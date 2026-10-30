// SPDX-License-Identifier: Apache-2.0

//! The backend-agnostic types and traits of a bounded datagram backend
//! (`quantstratum-docs: karyos/design/sockets-backend.md`, sections 3.1 to
//! 3.7, after `karyos/design/backend-contract.md`).
//!
//! A backend moves datagrams and reports evidence; the driver owns
//! publication identity, lane order, flow control and guard state. TX work
//! is claimed into a private [`TxFrame`], committed to a bounded FIFO queue
//! that fixes one [`Authority`] and one [`RouteId`], and exposed only by
//! [`TxBackend::flush`] after exactly one [`SenderGate`] check. Every
//! candidate of a flush is reported once in a caller owned [`TxReport`],
//! which a filling call refuses while it still holds entries.
//!
//! No item of this module performs a system call.

#![forbid(unsafe_code)]

// The handle table, the slot pool, the queue table and the ledger: the
// building blocks of the sockets endpoint.
pub(crate) mod handles;
mod lease_ledger;
pub(crate) mod ledger;
mod pool;
mod queues;

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::ops::ControlFlow;

use karyos_sys::log_buffer::{LeaseCopyError, ReadLease};
use thiserror::Error;

pub use lease_ledger::{LeaseLedger, LeaseLedgerCounters, ResetDrain};

/// Entries one [`TxReport`] holds, and so the most candidates one flush,
/// cancellation, close, reset or retirement call reports.
pub const TX_REPORT_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------
// 3.1 Budget
// ---------------------------------------------------------------------------

/// Work allowed for one call. Every attempt consumes `ops`, including an
/// attempt that returns `WouldBlock`, `EINTR` or a dropped datagram.
///
/// A zero budget makes no progress and changes no state. `bytes` counts
/// UDP payload bytes (Karyos frame bytes), not IP or UDP headers. An op is
/// one system call for sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    datagrams: u32,
    bytes: u64,
    ops: u32,
}

impl Budget {
    /// A budget of `datagrams` datagrams, `bytes` payload bytes and `ops`
    /// backend operations.
    #[inline]
    #[must_use]
    pub const fn new(datagrams: u32, bytes: u64, ops: u32) -> Self {
        Self {
            datagrams,
            bytes,
            ops,
        }
    }

    /// Datagrams allowed.
    #[inline]
    #[must_use]
    pub const fn datagrams(self) -> u32 {
        self.datagrams
    }

    /// Payload bytes allowed.
    #[inline]
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Backend operations (system calls for sockets) allowed.
    #[inline]
    #[must_use]
    pub const fn ops(self) -> u32 {
        self.ops
    }
}

/// What a call consumed; never more than its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Spent {
    /// Datagrams consumed, delivered and dropped alike.
    pub datagrams: u32,
    /// Payload bytes consumed.
    pub bytes: u64,
    /// Backend operations consumed, unsuccessful attempts included.
    pub ops: u32,
}

// ---------------------------------------------------------------------------
// 3.2 Identities and tokens
// ---------------------------------------------------------------------------

/// One opened endpoint, unique for the driver's life. The driver allocates
/// it from a checked counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceId(NonZeroU32);

impl InstanceId {
    /// The first instance of a driver.
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// Wraps an instance number.
    #[inline]
    #[must_use]
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Returns the instance number.
    #[inline]
    #[must_use]
    pub const fn get(self) -> NonZeroU32 {
        self.0
    }

    /// Returns the next instance identity.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::InstanceExhausted`] when the counter cannot
    /// advance; an identity is never reused.
    #[inline]
    pub const fn next(self) -> Result<Self, OpenError> {
        match self.0.checked_add(1) {
            Some(next) => Ok(Self(next)),
            None => Err(OpenError::InstanceExhausted),
        }
    }
}

/// Incremented on every reopen. For sockets it is also the capability epoch
/// (ambiguity A-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackendEpoch(NonZeroU32);

impl BackendEpoch {
    /// The epoch of a newly opened instance.
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// Wraps an epoch number.
    #[inline]
    #[must_use]
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    /// Returns the epoch number.
    #[inline]
    #[must_use]
    pub const fn get(self) -> NonZeroU32 {
        self.0
    }

    /// Returns the epoch a `reopen` moves to.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::EpochExhausted`] when the epoch cannot advance.
    #[inline]
    pub const fn next(self) -> Result<Self, OpenError> {
        match self.0.checked_add(1) {
            Some(next) => Ok(Self(next)),
            None => Err(OpenError::EpochExhausted),
        }
    }
}

/// The common submission identity of backend-contract.md: instance, epoch,
/// pool slot and slot generation. The four fields together are never
/// reused within the driver's life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubmissionId {
    instance: InstanceId,
    epoch: BackendEpoch,
    slot: u32,
    generation: NonZeroU64,
}

impl SubmissionId {
    /// Builds the identity of one claim of `slot`.
    #[inline]
    #[must_use]
    pub(crate) const fn new(
        instance: InstanceId,
        epoch: BackendEpoch,
        slot: u32,
        generation: NonZeroU64,
    ) -> Self {
        Self {
            instance,
            epoch,
            slot,
            generation,
        }
    }

    /// The endpoint instance.
    #[inline]
    #[must_use]
    pub const fn instance(self) -> InstanceId {
        self.instance
    }

    /// The backend epoch of the claim.
    #[inline]
    #[must_use]
    pub const fn epoch(self) -> BackendEpoch {
        self.epoch
    }

    /// The pool slot.
    #[inline]
    #[must_use]
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// The slot generation of the claim: 1 on the slot's first claim, one
    /// more on each later claim.
    #[inline]
    #[must_use]
    pub const fn generation(self) -> NonZeroU64 {
        self.generation
    }
}

/// Returned by a successful commit. It names a pending item; it is not
/// evidence that the item was ever submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxTicket(SubmissionId);

impl TxTicket {
    /// The ticket of the pending item `id`.
    #[inline]
    #[must_use]
    pub(crate) const fn new(id: SubmissionId) -> Self {
        Self(id)
    }

    /// The submission identity the ticket names.
    #[inline]
    #[must_use]
    pub const fn id(self) -> SubmissionId {
        self.0
    }
}

/// Opaque driver correlation, carried back in every report and event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SenderToken(u64);

impl SenderToken {
    /// Wraps a driver correlation value.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the correlation value.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Opaque driver key for the sender gate: one publication incarnation's
/// guard binding and local session epoch, or one unguarded control class.
///
/// The driver allocates it from a checked counter that never restarts; a
/// value is never reused for the driver's life, and exhaustion is a
/// terminal driver error. A queue's authority is fixed when it opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Authority(NonZeroU64);

impl Authority {
    /// The first authority of a driver.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Wraps an authority value.
    #[inline]
    #[must_use]
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// Returns the authority value.
    #[inline]
    #[must_use]
    pub const fn get(self) -> NonZeroU64 {
        self.0
    }

    /// Returns the next authority of the driver's counter, or `None` once
    /// it is exhausted.
    #[inline]
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// A route handle. The epoch ties it to one socket; the generation detects
/// reuse of the index within the instance. Every use compares all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteId {
    epoch: BackendEpoch,
    index: u16,
    generation: NonZeroU32,
}

impl RouteId {
    /// Builds a route handle; a backend issues it at `add_route`.
    #[inline]
    #[must_use]
    pub const fn new(epoch: BackendEpoch, index: u16, generation: NonZeroU32) -> Self {
        Self {
            epoch,
            index,
            generation,
        }
    }

    /// The backend epoch the handle was issued in.
    #[inline]
    #[must_use]
    pub const fn epoch(self) -> BackendEpoch {
        self.epoch
    }

    /// The route table index.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u16 {
        self.index
    }

    /// The per instance route generation.
    #[inline]
    #[must_use]
    pub const fn generation(self) -> NonZeroU32 {
        self.generation
    }
}

/// A TX queue handle. The epoch ties it to one socket; the generation
/// detects reuse of the index within the instance. Every use compares all
/// three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxQueueId {
    epoch: BackendEpoch,
    index: u16,
    generation: NonZeroU32,
}

impl TxQueueId {
    /// Builds a queue handle; a backend issues it at `open_queue`.
    #[inline]
    #[must_use]
    pub const fn new(epoch: BackendEpoch, index: u16, generation: NonZeroU32) -> Self {
        Self {
            epoch,
            index,
            generation,
        }
    }

    /// The backend epoch the handle was issued in.
    #[inline]
    #[must_use]
    pub const fn epoch(self) -> BackendEpoch {
        self.epoch
    }

    /// The queue table index.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u16 {
        self.index
    }

    /// The per instance queue generation.
    #[inline]
    #[must_use]
    pub const fn generation(self) -> NonZeroU32 {
        self.generation
    }
}

/// The receiving path of an endpoint (redundant paths, SPEC.md §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathId(u16);

impl PathId {
    /// Wraps a path number.
    #[inline]
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the path number.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// 3.3 TX: queues, claim, frame and commit
// ---------------------------------------------------------------------------

/// The configuration of one bounded FIFO TX queue. It fixes one authority
/// and one route, so every batch holds one incarnation, guard state and
/// route by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxQueueConfig {
    /// The sender gate key of every item of the queue.
    pub authority: Authority,
    /// The single destination of every item of the queue.
    pub route: RouteId,
    /// Claimed plus pending frames this queue may hold.
    pub max_pending: NonZeroU16,
}

/// A claimed, private TX frame. It borrows its backend, so only one frame
/// is claimed at a time per endpoint and no call can reach the pool while
/// it exists. Dropping it returns the slot to Free and the charge to the
/// queue; it cannot send anything.
pub trait TxFrame: Sized {
    /// Writable bytes granted by `claim_tx`; at most the datagram limit.
    fn capacity(&self) -> usize;

    /// The private frame. The kernel cannot access it in this state. Stale
    /// content from an earlier use may remain.
    fn bytes_mut(&mut self) -> &mut [u8];

    /// Moves the first `commit.len` bytes to the queue. On success the item
    /// is Pending at the queue tail and its bytes are immutable.
    ///
    /// # Errors
    ///
    /// Returns [`CommitRejected`] with the same frame and its ownership
    /// when the endpoint is not active, the queue is unknown, the length is
    /// outside `1..=capacity` or an option is unsupported, checked in that
    /// order.
    fn commit(self, commit: Commit) -> Result<TxTicket, CommitRejected<Self>>;
}

/// What a commit hands to the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commit {
    /// The initialized length returned by the encoder; 1 to capacity.
    pub len: usize,
    /// The driver correlation carried back in the item's report entry.
    pub token: SenderToken,
    /// Per datagram options.
    pub options: TxOptions,
}

/// Per datagram options. The baseline accepts only [`TxOptions::none`];
/// launch time or other offloads are added by their own designs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOptions {
    _private: (),
}

impl TxOptions {
    /// No per datagram option.
    #[inline]
    #[must_use]
    pub const fn none() -> Self {
        Self { _private: () }
    }

    /// Whether no option is set. Always true in the baseline.
    #[inline]
    #[must_use]
    pub const fn is_none(self) -> bool {
        true
    }
}

/// A rejected commit: the same frame, with its ownership, and the reason.
#[derive(Debug)]
pub struct CommitRejected<F> {
    /// The frame, unchanged and still claimed.
    pub frame: F,
    /// Why the commit was rejected.
    pub error: CommitError,
}

// ---------------------------------------------------------------------------
// 3.4 Flush, report and sender gate
// ---------------------------------------------------------------------------

/// The selection of one flush: a head prefix of one queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushRequest {
    /// The queue whose head prefix is offered.
    pub queue: TxQueueId,
    /// Clamped to [`TX_REPORT_CAPACITY`] and the endpoint's `max_batch`.
    pub max_datagrams: NonZeroU16,
    /// Payload bytes the exposure may reach, reserved before the call.
    pub max_bytes: u32,
}

/// The driver's sender gate. Monomorphized; called once per flush,
/// immediately before exposure. If it panics, the flush has changed no
/// state and sent nothing.
pub trait SenderGate {
    /// Decides how much of the candidate prefix may be exposed now.
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision;
}

/// The candidates one flush offers its gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exposure<'a> {
    /// The queue's authority.
    pub authority: Authority,
    /// The queue's route.
    pub route: RouteId,
    /// The backend epoch of the queue and route.
    pub epoch: BackendEpoch,
    /// Tokens of the queue's head prefix, in queue order.
    pub tokens: &'a [SenderToken],
    /// Lengths of the queue's head prefix, in queue order, in bytes.
    pub lengths: &'a [u16],
}

/// A gate's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Expose the first `count` candidates. A `count` above the number of
    /// candidates is a gate error: nothing is exposed.
    Permit {
        /// Candidates permitted, from the head.
        count: NonZeroU16,
    },
    /// Expose nothing. Items stay pending; nothing is cached.
    Deny,
}

/// The per candidate evidence of one call, filled by the backend before it
/// returns. Plain data, so filling it cannot unwind.
///
/// A call that fills a report refuses a report that is not empty, so unread
/// `Submitted` evidence cannot be overwritten. [`TxReport::pop_front`] is
/// the only way to empty it; there is no `clear`.
#[derive(Debug)]
pub struct TxReport {
    entries: [Option<TxEntry>; TX_REPORT_CAPACITY],
    head: usize,
    len: usize,
}

impl TxReport {
    /// An empty report.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; TX_REPORT_CAPACITY],
            head: 0,
            len: 0,
        }
    }

    /// Whether the report holds no entry.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Removes and returns the oldest entry. This is the only way to empty
    /// a report; there is no `clear`.
    pub fn pop_front(&mut self) -> Option<TxEntry> {
        let (Some(len), Some(next)) = (self.len.checked_sub(1), self.head.checked_add(1)) else {
            return None;
        };
        let entry = self.entries.get_mut(self.head).and_then(Option::take);
        debug_assert!(entry.is_some(), "a counted report entry is present");
        self.len = len;
        self.head = if len == 0 { 0 } else { next };
        entry
    }

    /// Starts filling the report: `None` when it still holds entries, which
    /// the calling operation turns into its `ReportNotEmpty` result before
    /// it calls a gate or the kernel and before it changes any state.
    pub(crate) fn writer(&mut self) -> Option<ReportWriter<'_>> {
        if self.is_empty() {
            self.head = 0;
            Some(ReportWriter { report: self })
        } else {
            None
        }
    }
}

impl Default for TxReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Appends entries to a report that was empty when the call started.
#[derive(Debug)]
pub(crate) struct ReportWriter<'a> {
    report: &'a mut TxReport,
}

impl ReportWriter<'_> {
    /// Entries the report can still take.
    pub(crate) fn remaining(&self) -> usize {
        // `head` is 0 while a writer exists: the free entries follow `len`.
        self.report
            .entries
            .get(self.report.len..)
            .map_or(0, <[Option<TxEntry>]>::len)
    }

    /// Appends `entry`, or gives it back when the report is full.
    pub(crate) fn push(&mut self, entry: TxEntry) -> Result<(), TxEntry> {
        // A writer exists only from an empty report, so `head` is 0 while
        // it fills and the next free entry is at `len`.
        let (Some(at), Some(len)) = (
            self.report.head.checked_add(self.report.len),
            self.report.len.checked_add(1),
        ) else {
            return Err(entry);
        };
        match self.report.entries.get_mut(at) {
            Some(free) => {
                *free = Some(entry);
                self.report.len = len;
                Ok(())
            }
            None => Err(entry),
        }
    }
}

/// The report of one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxEntry {
    /// The item's ticket.
    pub ticket: TxTicket,
    /// The item's driver correlation.
    pub token: SenderToken,
    /// The item's length in bytes.
    pub len: u16,
    /// What happened to the item.
    pub outcome: TxItemOutcome,
}

/// What one call established about one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxItemOutcome {
    /// Handed to the kernel. For sockets the storage was released when the
    /// call returned (`Release::AtSubmission`).
    Submitted {
        /// When the item's storage is released.
        release: Release,
    },
    /// Still pending, in place, under its original ticket.
    Pending {
        /// Why it was not submitted.
        cause: PendingCause,
    },
    /// Never exposed; the slot is free again.
    Returned {
        /// Why it was returned.
        reason: ReturnReason,
    },
    /// Exposure unproven. The item leaves its queue, is never retried and
    /// its slot is quarantined until reset. Sockets produce it only after a
    /// kernel result outside its documented range.
    Unknown,
}

/// When a submitted item's storage is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// At the submission itself: for copied sockets the kernel holds no
    /// reference once the send call returns (decision O-10).
    AtSubmission,
    /// By a later completion event of the backend.
    Deferred,
}

/// Why an item is still pending after a flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingCause {
    /// The gate denied the exposure.
    GateDenied,
    /// The kernel had no room (`EAGAIN`).
    WouldBlock,
    /// The kernel had no buffers (`ENOBUFS`, `ENOMEM`).
    NoBuffers,
    /// The call was interrupted (`EINTR`).
    Interrupted,
    /// `sendmmsg` accepted earlier items of the call and lost this item's
    /// error; the item was attempted and not accepted.
    ErrorLost,
    /// Behind the first unaccepted item; not attempted in this call.
    NotAttempted,
    /// A stale ICMP error was returned instead of a send.
    PeerError,
    /// The queue head failed with this error; the queue is faulted.
    Faulted(SendError),
    /// The flush stopped with [`FlushStop::Failed`] carrying this failure
    /// before handing off this item; only a reset returns it.
    ///
    /// - [`BackendFailure::Os`]: the send call failed in a way that ends
    ///   the half (`EBADF`, `ENOTSOCK`, `EFAULT`, `EINVAL`, section 4.7).
    ///   The half is stopped: every later flush returns the same
    ///   `Failed` with no gate check and no system call until the control
    ///   path resets the endpoint (3.10: a failure stops only that half).
    /// - [`BackendFailure::Invariant`]: the endpoint found its own queue
    ///   state broken before the exposure; the queue is faulted and needs a
    ///   reset (6.3, S-16).
    Failed(BackendFailure),
}

/// Why an item was returned without exposure: never handed to the
/// device, its slot free again and its frame the caller's, intact.
///
/// `#[non_exhaustive]` (karyos#770): the backend contract types have no
/// stable contract version yet (R-CORE-26), so a backend contract may add
/// reasons; a consumer handles a reason it does not know as any return,
/// never as an exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReturnReason {
    /// `cancel_pending`.
    Cancelled,
    /// `close_queue`.
    QueueClosed,
    /// `reset` or `retire`.
    Reset,
    /// A flush of a backend that resolves neighbours itself (a native
    /// backend in exclusive mode) found the item's next hop unresolved and
    /// returned it rather than hold it or send it unaddressed (R-CORE-44).
    /// The kernel resolves neighbours for sockets, which never return it.
    NeighbourUnresolved,
    /// As [`ReturnReason::NeighbourUnresolved`], with no room in the
    /// backend's neighbour table to start resolving the next hop
    /// (R-CORE-44).
    NeighbourTableFull,
}

/// The result of one flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushOutcome {
    /// Items submitted.
    pub submitted: u16,
    /// Payload bytes submitted.
    pub bytes: u32,
    /// Work consumed.
    pub spent: Spent,
    /// Why the flush stopped.
    pub stop: FlushStop,
}

/// Why a flush stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushStop {
    /// The permitted prefix was submitted; the queue may hold more.
    Exposed,
    /// `sendmmsg` accepted only the first `submitted` items of the
    /// permitted prefix and lost the error of the next one, which stays
    /// [`PendingCause::ErrorLost`] (4.3). The queue is not faulted; the next
    /// flush attempts that item again after a new gate check. Not in the
    /// 3.4 list of the design, which names no stop for a lost error:
    /// `Exposed` would claim the whole prefix was submitted.
    ErrorLost,
    /// The queue held no pending item.
    QueueEmpty,
    /// The gate denied the exposure.
    GateDenied,
    /// The head is longer than `max_bytes`; nothing was attempted.
    HeadExceedsBudget {
        /// The head item's length in bytes.
        head_len: u16,
    },
    /// The report still held entries; nothing was attempted.
    ReportNotEmpty,
    /// The gate permitted more items than it was offered.
    GateError {
        /// Items the gate permitted.
        permitted: u16,
        /// Items the flush offered.
        offered: u16,
    },
    /// A stale ICMP error was returned instead of a send.
    PeerError,
    /// The kernel had no room.
    WouldBlock,
    /// The kernel had no buffers.
    NoBuffers,
    /// The call was interrupted.
    Interrupted,
    /// The queue head failed with this error; the queue is faulted.
    Faulted(SendError),
    /// The queue could not be used.
    Queue(QueueError),
    /// The endpoint cannot continue; the control path must reset it.
    Failed(BackendFailure),
}

// ---------------------------------------------------------------------------
// 3.5 The common traits
// ---------------------------------------------------------------------------

/// The TX half of a backend endpoint. Every method takes `&mut self`; one
/// owning agent at a time.
pub trait TxBackend {
    /// The claimed frame type; it borrows the backend.
    type Frame<'a>: TxFrame
    where
        Self: 'a;

    /// Claims one Free slot of `len` writable bytes, charged to `queue`.
    ///
    /// # Errors
    ///
    /// Returns a [`ClaimError`], checked in this order: `NotActive`,
    /// `UnknownQueue`, `Empty`, `TooLarge`, `QueueFull`; then
    /// `IdentityExhausted` when no slot is free and slots were retired for
    /// generation overflow, `PoolExhausted` otherwise.
    fn claim_tx(&mut self, queue: TxQueueId, len: usize) -> Result<Self::Frame<'_>, ClaimError>;

    /// Offers a head prefix of one queue to `gate` once and exposes at most
    /// the permitted prefix once. Every candidate is reported in `report`
    /// exactly once before the call returns; a non-empty `report` is
    /// refused with [`FlushStop::ReportNotEmpty`] before the gate or the
    /// kernel is called.
    fn flush<G: SenderGate>(
        &mut self,
        request: FlushRequest,
        gate: &mut G,
        report: &mut TxReport,
    ) -> FlushOutcome;

    /// Reports completion events within `budget`. Copied sockets report
    /// none (decision O-10).
    fn poll_completions<H: CompletionHandler>(
        &mut self,
        budget: Budget,
        handler: &mut H,
    ) -> CompletionOutcome;

    /// Returns pending items of `queue` that were never exposed, up to the
    /// report capacity; call again while `more` is true.
    ///
    /// # Errors
    ///
    /// Returns a [`QueueError`]: `ReportNotEmpty` before any state change,
    /// `UnknownQueue` for a closed or stale handle, `NotActive` while the
    /// endpoint resets or is retired.
    fn cancel_pending(
        &mut self,
        queue: TxQueueId,
        report: &mut TxReport,
    ) -> Result<CancelOutcome, QueueError>;

    /// The optional borrowed-term TX operation (R-CORE-45; SPEC.md §16.6):
    /// queues the frames `lease` holds, as one datagram to `queue`'s route,
    /// instead of a frame the caller filled. A backend that borrows keeps
    /// the lease, in a [`LeaseLedger`], until it no longer references the
    /// bytes: through every pending, submitted, `Unknown` and reset state,
    /// released only when its contract proves access ended.
    ///
    /// The default stages, so every backend that does not borrow behaves
    /// exactly as before: it claims a frame of the lease's length, copies
    /// the frames into it ([`ReadLease::copy_to`], byte for byte what a
    /// copy read gives), commits it, and ends the lease once the commit is
    /// accepted.
    ///
    /// # Errors
    ///
    /// [`BorrowRejected`] with the lease, still held, and why: the claim,
    /// the copy or the commit failed. Nothing is queued then, and the
    /// claimed frame, if any, went back to its pool.
    fn submit_borrowed(
        &mut self,
        queue: TxQueueId,
        lease: ReadLease,
        token: SenderToken,
        options: TxOptions,
    ) -> Result<TxTicket, BorrowRejected> {
        let len = lease.len();
        let mut frame = match self.claim_tx(queue, len) {
            Ok(frame) => frame,
            Err(error) => {
                return Err(BorrowRejected {
                    lease,
                    error: BorrowError::Claim(error),
                });
            }
        };
        if let Err(error) = lease.copy_to(frame.bytes_mut()) {
            return Err(BorrowRejected {
                lease,
                error: BorrowError::Copy(error),
            });
        }
        match frame.commit(Commit {
            len,
            token,
            options,
        }) {
            // Staged: the frame holds the bytes, the lease ends here.
            Ok(ticket) => Ok(ticket),
            Err(rejected) => Err(BorrowRejected {
                lease,
                error: BorrowError::Commit(rejected.error),
            }),
        }
    }
}

/// A borrowed submission refused, with its lease, still held
/// ([`TxBackend::submit_borrowed`]).
#[derive(Debug)]
pub struct BorrowRejected {
    /// The lease, unchanged: the caller stages it, retries or drops it.
    pub lease: ReadLease,
    /// Why it was refused.
    pub error: BorrowError,
}

/// Why a borrowed submission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BorrowError {
    /// The staging frame could not be claimed.
    #[error("staging claim refused: {0}")]
    Claim(ClaimError),
    /// The lease could not be copied into the staging frame.
    #[error("lease copy refused: {0:?}")]
    Copy(LeaseCopyError),
    /// The staging frame's commit was rejected.
    #[error("staging commit rejected: {0}")]
    Commit(CommitError),
    /// The backend's ledger of borrowed leases is full.
    #[error("lease ledger full")]
    LedgerFull,
}

/// The RX half of a backend endpoint.
pub trait RxBackend {
    /// Receives within `budget`, lending each datagram to `handler` for the
    /// duration of one callback.
    fn poll_rx<H: RxHandler>(&mut self, budget: Budget, handler: &mut H) -> RxOutcome;
}

/// The driver's receiver of TX completion events.
pub trait CompletionHandler {
    /// Takes one event.
    fn event(&mut self, event: TxEvent);
}

/// One TX completion event, keyed by the full submission identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxEvent {
    /// The backend released the item's storage.
    Released {
        /// The submission.
        id: SubmissionId,
        /// Its driver correlation.
        token: SenderToken,
    },
    /// The interface reported the send result.
    SendResult {
        /// The submission.
        id: SubmissionId,
        /// Its driver correlation.
        token: SenderToken,
        /// Success, or the per datagram failure.
        result: Result<(), SendError>,
    },
    /// A timestamp of the submission.
    Timestamp {
        /// The submission.
        id: SubmissionId,
        /// Its driver correlation.
        token: SenderToken,
        /// The observation.
        observation: Observation,
    },
    /// An expected observation of the submission was lost.
    ObservationLost {
        /// The submission.
        id: SubmissionId,
        /// Its driver correlation.
        token: SenderToken,
    },
    /// An observation that no retained correlation names.
    Unmatched {
        /// The observation.
        observation: Observation,
    },
}

/// The result of one `poll_completions` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompletionOutcome {
    /// Events delivered to the handler.
    pub events: u32,
    /// Work consumed.
    pub spent: Spent,
}

/// The result of one cancellation or close call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelOutcome {
    /// Items returned in the report.
    pub returned: u16,
    /// Whether pending items remain; call again after emptying the report.
    pub more: bool,
}

// ---------------------------------------------------------------------------
// 3.6 Errors
// ---------------------------------------------------------------------------

/// Why `claim_tx` granted no frame.
///
/// Checked in this order (3.6), which is not the declaration order:
/// `NotActive`, `UnknownQueue`, `Empty`, `TooLarge`, `QueueFull`. If no
/// slot is free after that, the result is `IdentityExhausted` when only
/// slots retired for generation overflow keep the pool dry, and
/// `PoolExhausted` when a reset would free a quarantined slot. Quarantined
/// slots stay charged to their queue, so the pool runs dry only after
/// retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// `len` is 0.
    #[error("claim of 0 bytes")]
    Empty,
    /// `len` exceeds the datagram limit.
    #[error("claim of {len} bytes exceeds the datagram limit of {max}")]
    TooLarge {
        /// The requested length.
        len: usize,
        /// The datagram limit in bytes.
        max: u16,
    },
    /// The queue already holds `max_pending` claimed, pending and
    /// quarantined slots.
    #[error("queue is full at {max_pending} claimed and pending frames")]
    QueueFull {
        /// The queue's capacity.
        max_pending: u16,
    },
    /// No slot is free, but a reset would free a quarantined one.
    /// Reachable only after slot retirement.
    #[error("tx slot pool exhausted")]
    PoolExhausted,
    /// The queue is closed or the handle is stale.
    #[error("unknown tx queue")]
    UnknownQueue,
    /// The endpoint is resetting or retired.
    #[error("endpoint is not active")]
    NotActive,
    /// No slot is free, slots were retired for generation overflow and
    /// none is quarantined, so no reset frees one. A later release of a
    /// claimed or pending slot makes claims succeed again; the state is
    /// terminal only once every slot is retired (design 3.2 and 3.6).
    #[error("tx slot identities exhausted")]
    IdentityExhausted,
}

/// Why a commit was rejected; the frame comes back with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CommitError {
    /// The committed length is 0.
    #[error("commit of 0 bytes")]
    Empty,
    /// The committed length exceeds the claimed capacity.
    #[error("commit of {len} bytes exceeds the claimed capacity of {capacity}")]
    LengthExceedsClaim {
        /// The committed length.
        len: usize,
        /// The frame's capacity.
        capacity: usize,
    },
    /// An option the backend does not support.
    #[error("unsupported tx option")]
    UnsupportedOption,
    /// The queue is closed or the handle is stale.
    #[error("unknown tx queue")]
    UnknownQueue,
    /// The endpoint is resetting or retired.
    #[error("endpoint is not active")]
    NotActive,
}

/// A per datagram send failure; the datagram was not handed off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SendError {
    /// `EMSGSIZE`.
    #[error("datagram too large for the path")]
    MessageTooLarge,
    /// `ENETUNREACH`, `EHOSTUNREACH` or `ENETDOWN`.
    #[error("destination unreachable (os error {errno})")]
    Unreachable {
        /// Raw OS error number.
        errno: i32,
    },
    /// `EADDRNOTAVAIL`.
    #[error("local address unavailable")]
    AddressUnavailable,
    /// `EPERM` or `EACCES`.
    #[error("send denied (os error {errno})")]
    Denied {
        /// Raw OS error number.
        errno: i32,
    },
    /// Any other send error.
    #[error("send failed (os error {errno})")]
    Other {
        /// Raw OS error number.
        errno: i32,
    },
}

/// The endpoint cannot continue; the control path must reset it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BackendFailure {
    /// A system call failed in a way that ends the endpoint.
    #[error("{operation} failed with os error {errno}")]
    Os {
        /// The failing operation.
        operation: &'static str,
        /// Raw OS error number.
        errno: i32,
    },
    /// A kernel result outside its documented range, such as a `sendmmsg`
    /// count above the request or a short datagram send. The affected
    /// items are reported `Unknown`.
    #[error("{operation} returned a result outside its documented range")]
    Invariant {
        /// The operation whose result broke its contract.
        operation: &'static str,
    },
    /// The endpoint is resetting, reset or retired: the half makes no
    /// system call until the control path reopens it (section 7.3).
    #[error("endpoint is not active")]
    NotActive,
}

/// Why a queue operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QueueError {
    /// The queue is closed or the handle is stale.
    #[error("unknown tx queue")]
    UnknownQueue,
    /// Every queue entry of the endpoint is open.
    #[error("tx queue limit reached")]
    QueueLimit,
    /// The route is removed or the handle is stale.
    #[error("unknown route")]
    RouteUnknown,
    /// The route is in use.
    #[error("route in use")]
    RouteInUse,
    /// The queue's capacity would exceed the free slots: the sum of
    /// `max_pending` over open queues is at most `tx_slots`.
    #[error("queue of {requested} pending frames exceeds the {free} uncommitted tx slots")]
    OverCommitted {
        /// The requested `max_pending`.
        requested: u32,
        /// Slots not yet committed to an open queue.
        free: u32,
    },
    /// The report still held entries; nothing changed.
    #[error("tx report is not empty")]
    ReportNotEmpty,
    /// Queue generations are exhausted for the instance. Terminal.
    #[error("tx queue identities exhausted")]
    IdentityExhausted,
    /// The endpoint is resetting or retired.
    #[error("endpoint is not active")]
    NotActive,
    /// The queue was faulted by an invariant violation; only a reset
    /// clears it.
    #[error("tx queue needs an endpoint reset")]
    NeedsReset,
}

/// Why a route operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RouteError {
    /// Every route entry of the endpoint is in use.
    #[error("route limit reached")]
    RouteLimit,
    /// The route is removed or the handle is stale.
    #[error("unknown route")]
    Unknown,
    /// An open queue uses the route.
    #[error("route in use by an open queue")]
    InUse,
    /// The destination's address family differs from the socket's.
    #[error("destination address family does not match the socket")]
    FamilyMismatch,
    /// The destination is not supported.
    #[error("unsupported destination")]
    Unsupported,
    /// The datagram plus headers does not fit the measured route MTU.
    #[error(
        "datagram of {datagram} bytes plus {overhead} header bytes exceeds route mtu {route_mtu}"
    )]
    PathTooSmall {
        /// The datagram limit in bytes.
        datagram: u16,
        /// UDP and IP header bytes.
        overhead: u16,
        /// The measured route MTU in bytes.
        route_mtu: u32,
    },
    /// `require` includes a verified path MTU and none was measured.
    #[error("path mtu required but not measured")]
    PathUnverified,
    /// Route generations are exhausted for the instance. Terminal.
    #[error("route identities exhausted")]
    IdentityExhausted,
    /// The endpoint is resetting, reset or retired.
    #[error("endpoint is not active")]
    NotActive,
}

/// Why an endpoint could not open, reopen or retire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OpenError {
    /// A configuration value is outside its range.
    #[error("invalid configuration {field} = {value}")]
    InvalidConfig {
        /// The configuration field.
        field: &'static str,
        /// The rejected value.
        value: u64,
    },
    /// The configuration requires protection the backend cannot apply.
    #[error("protection profile unavailable")]
    ProtectionUnavailable,
    /// A required capability is not active.
    #[error("required capability {capability:?} is {state:?}")]
    RequiredCapability {
        /// The capability.
        capability: Capability,
        /// Its probed state.
        state: CapabilityState,
    },
    /// A system call failed.
    #[error("{operation} failed with os error {errno}")]
    Os {
        /// The failing operation.
        operation: &'static str,
        /// Raw OS error number.
        errno: i32,
    },
    /// Instance identities are exhausted.
    #[error("instance identities exhausted")]
    InstanceExhausted,
    /// The backend epoch cannot advance.
    #[error("backend epoch exhausted")]
    EpochExhausted,
    /// `reopen` or `retire` while pending items remain unreturned.
    #[error("reset incomplete: pending items remain")]
    ResetIncomplete,
    /// `reopen` of a retired endpoint: retirement is final.
    #[error("endpoint is retired")]
    Retired,
}

// ---------------------------------------------------------------------------
// 3.7 RX (the types the traits of 3.5 name)
// ---------------------------------------------------------------------------

/// The driver's receiver of lent datagrams.
pub trait RxHandler {
    /// Takes one datagram. The borrow ends when this returns. `Break` stops
    /// the poll.
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()>;

    /// Takes one dropped datagram.
    fn dropped(&mut self, drop: RxDrop);
}

/// One received datagram, lent for one callback. It has accessors only and
/// no constructor outside `karyos-io`; frame, session and protection
/// validation stays with the driver.
#[derive(Debug, Clone, Copy)]
pub struct RxDatagram<'a> {
    bytes: &'a [u8],
    source: SocketAddr,
    path: PathId,
    epoch: BackendEpoch,
    observation: Option<Observation>,
}

impl<'a> RxDatagram<'a> {
    /// Lends `bytes`, received from `source` on `path` in `epoch`.
    pub(crate) const fn new(
        bytes: &'a [u8],
        source: SocketAddr,
        path: PathId,
        epoch: BackendEpoch,
        observation: Option<Observation>,
    ) -> Self {
        Self {
            bytes,
            source,
            path,
            epoch,
            observation,
        }
    }

    /// The complete UDP payload.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The peer endpoint.
    #[inline]
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    /// The receiving path.
    #[inline]
    #[must_use]
    pub const fn path(&self) -> PathId {
        self.path
    }

    /// The backend (capability) epoch of the receiving endpoint.
    #[inline]
    #[must_use]
    pub const fn epoch(&self) -> BackendEpoch {
        self.epoch
    }

    /// The receive observation, when one was requested and taken.
    #[inline]
    #[must_use]
    pub const fn observation(&self) -> Option<Observation> {
        self.observation
    }
}

/// A datagram the backend dropped before the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxDrop {
    /// Why it was dropped.
    pub reason: RxDropReason,
    /// The peer endpoint, when known.
    pub source: Option<SocketAddr>,
}

/// Why the backend dropped a datagram. Backend drops cover only size and
/// address family (ambiguity A-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxDropReason {
    /// More than the datagram limit; `received` when the kernel says.
    Oversize {
        /// The datagram limit in bytes.
        limit: u16,
        /// The true length in bytes, when the kernel reports it.
        received: Option<usize>,
    },
    /// Source is not an IPv4 or IPv6 UDP endpoint.
    UnsupportedSource,
}

/// The result of one `poll_rx` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxOutcome {
    /// Datagrams lent to the handler.
    pub delivered: u32,
    /// Datagrams dropped.
    pub dropped: u32,
    /// Work consumed.
    pub spent: Spent,
    /// Why the poll stopped.
    pub stop: RxStop,
}

/// Why a poll stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxStop {
    /// No datagram was waiting.
    WouldBlock,
    /// The kernel had no buffers; transient, no reset.
    NoBuffers,
    /// The remaining budget does not admit a whole datagram.
    Budget,
    /// The handler returned `Break`.
    HandlerStopped,
    /// The call was interrupted.
    Interrupted,
    /// The half cannot continue; the control path must reset it. A sockets
    /// half is then stopped: every later poll returns the same `Failed`
    /// with no system call until the reset (3.10).
    Failed(BackendFailure),
}

/// An interval in one clock, as trace-clocks.md defines it:
/// `[time_ns - uncertainty_ns, time_ns + uncertainty_ns]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// Where the observation was taken.
    pub point: ObservationPoint,
    /// The clock domain.
    pub domain: ClockDomain,
    /// A new epoch is a new clock; times of two epochs never compare.
    pub epoch: ClockEpoch,
    /// The observed time in ns of the clock.
    pub time_ns: u64,
    /// The half-width of the interval in ns.
    pub uncertainty_ns: u64,
}

/// Where an observation was taken. A userspace observation is never a
/// kernel or wire time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationPoint {
    /// After a send call returned, in userspace.
    SendReturn,
    /// After a receive call returned, in userspace.
    RecvReturn,
    /// The kernel's TX stamp.
    KernelTx,
    /// The kernel's RX stamp.
    KernelRx,
    /// The NIC's TX stamp.
    HardwareTx,
    /// The NIC's RX stamp.
    HardwareRx,
}

/// The clock an observation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockDomain {
    /// The host's monotonic clock (`host_monotonic_ns`).
    HostMonotonic,
    /// The host's realtime clock.
    Realtime,
    /// International Atomic Time.
    Tai,
    /// A PTP hardware clock, by index.
    Phc(u32),
}

/// The epoch of an observation clock; a new epoch is a new clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockEpoch(u64);

impl ClockEpoch {
    /// Wraps an epoch number.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the epoch number.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Capability states (section 8.1), named by `OpenError::RequiredCapability`
// ---------------------------------------------------------------------------

/// A probed capability, one per capability state of the snapshot, plus the
/// per route path MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Don't fragment (`IP_MTU_DISCOVER`).
    DontFragment,
    /// TX batching (`sendmmsg`).
    TxBatch,
    /// RX batching (`recvmmsg`).
    RxBatch,
    /// UDP segmentation offload.
    Gso,
    /// UDP receive coalescing.
    Gro,
    /// Kernel TX and RX timestamps.
    KernelStamps,
    /// Hardware TX and RX timestamps.
    HardwareStamps,
    /// Busy polling.
    BusyPoll,
    /// Userspace observations around calls.
    UserObservations,
    /// The requested send buffer size.
    SendBuffer,
    /// The requested receive buffer size.
    RecvBuffer,
    /// A verified path MTU per route.
    PathMtu,
}

/// The probed state of one capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityState {
    /// In use.
    Active,
    /// Not active; its declared fallback is in use.
    Fallback(Reason),
    /// Not available.
    Unavailable(Reason),
    /// Not requested by the configuration.
    NotRequested,
}

/// Why a capability is not active. No probe result is published as proof
/// of absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The feature is not compiled in.
    NotBuilt,
    /// The platform lacks it.
    Platform,
    /// The system call library offers no API for it.
    LibraryApi,
    /// The call returned `ENOSYS`: the kernel or a seccomp filter refused
    /// it. Drives a fallback; never published as absence.
    Unsupported {
        /// Raw OS error number.
        errno: i32,
    },
    /// The call was denied.
    Denied {
        /// Raw OS error number.
        errno: i32,
    },
    /// The probe failed otherwise.
    ProbeFailed {
        /// Raw OS error number.
        errno: i32,
    },
    /// The effective value is below the request.
    BelowRequest {
        /// The effective value.
        effective: u32,
    },
    /// The path MTU could not be measured.
    Unverified,
}

#[cfg(test)]
mod tests;
