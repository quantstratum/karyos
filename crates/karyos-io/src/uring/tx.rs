// SPDX-License-Identifier: Apache-2.0

//! The `io_uring` TX half over the [`RingOps`] seam (`quantstratum-docs:
//! karyos/design/io-uring-backend.md` sections 3, 5, 7, 8 and 10): claim
//! and commit as the sockets backend does, a flush that publishes one
//! copied `SENDMSG` per permitted item, and completions that report the
//! send result and the release of each item as two events.
//!
//! **Ownership (SPEC.md §16.7, design 3.1).** A slot is Free, Claimed,
//! Pending, then Submitted from the push of its SQE until the completion
//! whose `user_data` names its generation; only then is it Free again. A
//! Submitted item is never re-pended, returned, cancelled into Free or
//! claimed: the seam refuses its bytes while the kernel owns it, and the
//! state machine releases the slot to the ledger only on its matching
//! completion. An item whose release evidence is lost (a CQ overflow, a
//! result outside the ABI, a closed queue) is Quarantined until reset.
//!
//! **Cancellation (design 10.1, 10.2).** [`UringTx::cancel_submitted`]
//! asks the kernel to cancel the Submitted items of one queue and
//! [`UringTx::reset`] cancels every operation of the ring; a cancel never
//! releases anything itself, only the target's own completion does. A
//! reset whose targets do not complete within its budgets stays
//! incomplete and reports the slots and bytes the kernel still owns
//! ([`UringTx::retained`]); nothing is freed under the kernel.
//!
//! No method of this module allocates after [`UringTx::open`].

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU64};

use super::ops::{
    CONTROL_SLOTS, CancelTarget, Cqe, EAGAIN, EBADR, EBUSY, EINTR, PushError, RingOps, UserData,
};
use crate::backend::handles::{HandleTable, IssueError};
use crate::backend::ledger::TxLedger;
use crate::backend::{
    BackendEpoch, BackendFailure, Budget, CancelOutcome, CapabilityState, ClaimError, Commit,
    CommitError, CommitRejected, CompletionHandler, CompletionOutcome, Exposure, FlushOutcome,
    FlushRequest, FlushStop, GateDecision, InstanceId, OpenError, PendingCause, QueueError,
    Release, ReportWriter, ReturnReason, RouteError, RouteId, SendError, SenderGate, SenderToken,
    Spent, SubmissionId, TX_REPORT_CAPACITY, TxBackend, TxEntry, TxEvent, TxFrame, TxItemOutcome,
    TxQueueConfig, TxQueueId, TxReport, TxTicket,
};

/// The end of a pending list.
const NO_SLOT: u32 = u32::MAX;
/// Candidates of one flush at most: one report's worth.
pub const URING_MAX_BATCH: u16 = 64;
const BATCH: usize = URING_MAX_BATCH as usize;
const _: () = assert!(BATCH <= TX_REPORT_CAPACITY);
/// Completions one reap copies out at most.
const REAP: usize = 64;
/// The operation named by a CQ overflow.
const OVERFLOW: &str = "uring_cq_overflow";
/// The operation named by enter failures.
const ENTER: &str = "io_uring_enter";

/// `NonZeroU16` from a literal of these constants; never zero.
const fn nz16(value: u16) -> NonZeroU16 {
    match NonZeroU16::new(value) {
        Some(value) => value,
        None => NonZeroU16::MIN,
    }
}

/// The default datagram limit, as the sockets backend's.
pub const DEFAULT_MAX_DATAGRAM: NonZeroU16 = nz16(1408);
/// The default TX slots (`T`, design 5.3).
pub const DEFAULT_TX_SLOTS: NonZeroU16 = nz16(256);
/// The default open queues.
pub const DEFAULT_MAX_QUEUES: NonZeroU16 = nz16(64);
/// The default routes.
pub const DEFAULT_MAX_ROUTES: NonZeroU16 = nz16(64);
/// The default flush batch (`B`, design 5.3).
pub const DEFAULT_MAX_BATCH: NonZeroU16 = nz16(32);

/// SQPOLL, only when explicitly configured (choice IU-2, design 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqPoll {
    /// The isolated CPU the kernel submission thread is pinned to.
    pub cpu: u32,
    /// Milliseconds the thread spins before it sleeps.
    pub idle_ms: u32,
}

/// The configuration of one `io_uring` TX half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UringTxConfig {
    /// The datagram limit in bytes; each slot holds one.
    pub max_datagram: NonZeroU16,
    /// Staging slots, which also bound the sends in flight (`T`).
    pub tx_slots: NonZeroU16,
    /// Open queues at most.
    pub max_queues: NonZeroU16,
    /// Routes at most.
    pub max_routes: NonZeroU16,
    /// Datagrams one flush exposes at most (`B`), 1 to
    /// [`URING_MAX_BATCH`].
    pub max_batch: NonZeroU16,
    /// SQPOLL; `None`, the default, submits through `io_uring_enter`.
    pub sqpoll: Option<SqPoll>,
}

impl Default for UringTxConfig {
    fn default() -> Self {
        Self {
            max_datagram: DEFAULT_MAX_DATAGRAM,
            tx_slots: DEFAULT_TX_SLOTS,
            max_queues: DEFAULT_MAX_QUEUES,
            max_routes: DEFAULT_MAX_ROUTES,
            max_batch: DEFAULT_MAX_BATCH,
            sqpoll: None,
        }
    }
}

impl UringTxConfig {
    /// Checks the ranges: `max_batch` at most [`URING_MAX_BATCH`] and the
    /// slot indices plus the control slots within the 16 bits of
    /// `user_data` (design 3.4).
    ///
    /// # Errors
    ///
    /// [`OpenError::InvalidConfig`] naming the field.
    pub fn validate(&self) -> Result<(), OpenError> {
        if self.max_batch.get() > URING_MAX_BATCH {
            return Err(OpenError::InvalidConfig {
                field: "max_batch",
                value: u64::from(self.max_batch.get()),
            });
        }
        if self.tx_slots.get().checked_add(CONTROL_SLOTS).is_none() {
            return Err(OpenError::InvalidConfig {
                field: "tx_slots",
                value: u64::from(self.tx_slots.get()),
            });
        }
        Ok(())
    }

    /// The SQ entries the ring needs: `B + K` rounded up to a power of
    /// two (design 5.1).
    #[must_use]
    pub fn sq_entries(&self) -> u32 {
        (u32::from(self.max_batch.get()) + u32::from(CONTROL_SLOTS)).next_power_of_two()
    }

    /// The CQ entries the ring needs: `T + K` rounded up to a power of two
    /// (design 5.1, copied sends), and never fewer than the SQ entries,
    /// which `IORING_SETUP_CQSIZE` refuses.
    #[must_use]
    pub fn cq_entries(&self) -> u32 {
        (u32::from(self.tx_slots.get()) + u32::from(CONTROL_SLOTS))
            .next_power_of_two()
            .max(self.sq_entries())
    }
}

/// The life of the half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Active,
    /// `reset` runs: pending items return, submitted ones are cancelled.
    Resetting,
    /// The reset finished; nothing the kernel owned remains.
    Closed,
}

/// Where one slot is (design 3.1 and 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Free,
    Claimed,
    Pending,
    /// Published to the kernel; released only by its completion.
    Submitted,
    /// Release evidence lost or the queue gone: kept until reset. The
    /// seam still tracks whether the kernel owns it.
    Quarantined,
}

#[derive(Debug, Clone, Copy)]
struct SlotMeta {
    phase: Phase,
    queue: Option<TxQueueId>,
    generation: Option<NonZeroU64>,
    token: SenderToken,
    len: u16,
    next: u32,
}

const FREE_META: SlotMeta = SlotMeta {
    phase: Phase::Free,
    queue: None,
    generation: None,
    token: SenderToken::new(0),
    len: 0,
    next: NO_SLOT,
};

/// The FIFO and fault of one open queue.
#[derive(Debug, Clone, Copy)]
struct Run {
    id: Option<TxQueueId>,
    head: u32,
    tail: u32,
    len: u16,
    /// An invariant fault; only a reset clears it.
    faulted: bool,
    /// `close_queue` started: no claim, commit or flush; it closes once
    /// its Submitted items completed.
    closing: bool,
}

const IDLE_RUN: Run = Run {
    id: None,
    head: NO_SLOT,
    tail: NO_SLOT,
    len: 0,
    faulted: false,
    closing: false,
};

/// One control slot for cancel operations (design 3.4).
#[derive(Debug, Clone, Copy)]
struct Control {
    /// The generation of the current or last operation; 0 before the
    /// first.
    generation: u64,
    in_flight: Option<CancelTarget>,
}

/// The counters of one TX half; every increment saturates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UringTxCounters {
    /// Completions of a send with `-EAGAIN`: the kernel did not park it
    /// (`uring_send_wouldblock`, design 3.5).
    pub send_wouldblock: u64,
    /// Sends the kernel reported not transmitted: `-EAGAIN`, `-ENOBUFS`,
    /// `-ENOMEM`, `-ECONNREFUSED`, `-ECANCELED` and `-EINTR`.
    pub known_not_transmitted: u64,
    /// Sends completed with `-ECANCELED`.
    pub cancelled: u64,
    /// Completions that named no operation in flight (stale or
    /// duplicated, design 3.4).
    pub stale_completions: u64,
    /// Results outside the ABI; the queue needs a reset.
    pub invariants: u64,
    /// CQ overflows (`uring_cq_overflow`, design 5.2).
    pub cq_overflow: u64,
    /// The difference between a ring cancel's count and the `-ECANCELED`
    /// completions after it (`uring_cancel_count_diff`, design 10.2).
    pub cancel_count_diff: u64,
    /// Enters that failed with `EINTR` or `EAGAIN`.
    pub enter_retries: u64,
}

/// Slots the kernel still owns and the bytes they hold: what a bounded
/// cancel and reap could not get back (design 10.2 and 10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Retained {
    /// Kernel owned slots.
    pub slots: u16,
    /// Their staging bytes.
    pub bytes: u64,
}

/// The result of one [`UringTx::cancel_submitted`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelSubmitted {
    /// Cancels published by this call.
    pub issued: u16,
    /// Submitted items of the queue that got no cancel in this call (no
    /// control slot or SQ entry was free): call again.
    pub more: bool,
}

/// The result of one [`UringTx::reset`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UringReset {
    /// Pending items returned with [`ReturnReason::Reset`].
    pub returned: u16,
    /// Pending, submitted or control operations remain: empty the report
    /// and call again. Nothing is freed meanwhile.
    pub more: bool,
    /// The report still held entries; nothing changed.
    pub report_not_empty: bool,
    /// What the kernel still owns after this call.
    pub retained: Retained,
}

/// The `io_uring` TX half: staging slots in the ring seam, queues, routes
/// and the ledger. One owning agent (SPEC.md §16.4).
#[derive(Debug)]
pub struct UringTx<R: RingOps> {
    instance: InstanceId,
    epoch: BackendEpoch,
    state: State,
    config: UringTxConfig,
    ring: R,
    ledger: TxLedger,
    slots: Box<[SlotMeta]>,
    runs: Box<[Run]>,
    routes: HandleTable<RouteId, SocketAddr>,
    control: [Control; CONTROL_SLOTS as usize],
    counters: UringTxCounters,
    failed: Option<BackendFailure>,
    /// The ring cancel of a reset: its count once it completed and the
    /// `-ECANCELED` completions seen since it was published.
    ring_cancel: Option<RingCancel>,
    sqpoll: CapabilityState,
    /// A deliberate mutant for the simulator's negative control: release
    /// each slot at its submission, as copied sockets do, instead of at its
    /// completion.
    #[cfg(any(test, feature = "test-hooks"))]
    release_at_submission: bool,
}

#[derive(Debug, Clone, Copy)]
struct RingCancel {
    count: Option<u32>,
    seen: u32,
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// What a send completion establishes (design 3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolution {
    Sent(Result<(), SendError>),
    /// A result outside the ABI: no send result, slot quarantined.
    Invariant,
}

const ENOMEM: i32 = 12;
const EBADF: i32 = 9;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const EMSGSIZE: i32 = 90;
const ENOTSOCK: i32 = 88;
const EOPNOTSUPP: i32 = 95;
const EPERM: i32 = 1;
const EACCES: i32 = 13;
const ENETDOWN: i32 = 100;
const ENETUNREACH: i32 = 101;
const ENOBUFS: i32 = 105;
const ECONNREFUSED: i32 = 111;
const EHOSTUNREACH: i32 = 113;
const EADDRNOTAVAIL: i32 = 99;
const ECANCELED: i32 = 125;

/// The table of design 3.5.
fn resolve(result: i32, len: u16) -> Resolution {
    if result >= 0 {
        return if u16::try_from(result) == Ok(len) {
            Resolution::Sent(Ok(()))
        } else {
            Resolution::Invariant
        };
    }
    let errno = result.checked_neg().unwrap_or(i32::MAX);
    let error = match errno {
        EMSGSIZE => SendError::MessageTooLarge,
        ENETUNREACH | EHOSTUNREACH | ENETDOWN => SendError::Unreachable { errno },
        EADDRNOTAVAIL => SendError::AddressUnavailable,
        EPERM | EACCES => SendError::Denied { errno },
        EAGAIN => SendError::WouldBlock,
        ENOBUFS | ENOMEM => SendError::NoBuffers,
        ECONNREFUSED => SendError::PeerRefused,
        ECANCELED => SendError::Cancelled,
        EBADF | ENOTSOCK | EINVAL | EFAULT | EOPNOTSUPP => return Resolution::Invariant,
        _ => SendError::Other { errno },
    };
    Resolution::Sent(Err(error))
}

/// Whether `error` means the kernel did not hand the datagram to the
/// network (design 3.5, "known not transmitted").
fn not_transmitted(error: SendError) -> bool {
    matches!(
        error,
        SendError::WouldBlock
            | SendError::NoBuffers
            | SendError::PeerRefused
            | SendError::Cancelled
            | SendError::Other { errno: EINTR }
    )
}

fn issue_queue(error: IssueError) -> QueueError {
    match error {
        IssueError::Full => QueueError::QueueLimit,
        IssueError::IdentityExhausted => QueueError::IdentityExhausted,
    }
}

impl<R: RingOps> UringTx<R> {
    /// Validates `config` against `ring` and allocates every table; no
    /// later call allocates. `sqpoll` is the state the ring was built
    /// with.
    ///
    /// # Errors
    ///
    /// [`OpenError::InvalidConfig`] for a value out of range or a ring
    /// whose slots differ from the configuration.
    pub fn open(
        config: UringTxConfig,
        instance: InstanceId,
        ring: R,
        sqpoll: CapabilityState,
    ) -> Result<Self, OpenError> {
        config.validate()?;
        if ring.slots() != config.tx_slots.get() || ring.slot_len() != config.max_datagram.get() {
            return Err(OpenError::InvalidConfig {
                field: "tx_slots",
                value: u64::from(ring.slots()),
            });
        }
        let epoch = BackendEpoch::FIRST;
        Ok(Self {
            instance,
            epoch,
            state: State::Active,
            config,
            ring,
            ledger: TxLedger::new(
                config.tx_slots,
                config.max_queues,
                config.max_datagram,
                epoch,
            ),
            slots: vec![FREE_META; usize::from(config.tx_slots.get())].into_boxed_slice(),
            runs: vec![IDLE_RUN; usize::from(config.max_queues.get())].into_boxed_slice(),
            routes: HandleTable::new(config.max_routes, epoch),
            control: [Control {
                generation: 0,
                in_flight: None,
            }; CONTROL_SLOTS as usize],
            counters: UringTxCounters::default(),
            failed: None,
            ring_cancel: None,
            sqpoll,
            #[cfg(any(test, feature = "test-hooks"))]
            release_at_submission: false,
        })
    }

    /// The ring seam, for its own diagnostics.
    #[must_use]
    pub fn ring(&self) -> &R {
        &self.ring
    }

    /// The ring seam, mutably: tests script completions through it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn ring_mut(&mut self) -> &mut R {
        &mut self.ring
    }

    /// Turns on the mutant that releases each slot at its submission
    /// instead of at its completion (the "release on enter return"
    /// negative control of design section 12). Never correct.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn inject_release_at_submission(&mut self) {
        self.release_at_submission = true;
    }

    /// Whether SQPOLL runs: `NotRequested` unless the configuration asked
    /// for it (IU-2).
    #[must_use]
    pub fn sqpoll(&self) -> CapabilityState {
        self.sqpoll
    }

    /// The half's counters.
    #[must_use]
    pub fn counters(&self) -> UringTxCounters {
        self.counters
    }

    /// The failure that stopped the half, if any.
    #[must_use]
    pub fn failure(&self) -> Option<BackendFailure> {
        self.failed
    }

    /// What the kernel owns now: the retained condition and its cost.
    #[must_use]
    pub fn retained(&self) -> Retained {
        let slots = self.ring.kernel_owned();
        Retained {
            slots,
            bytes: u64::from(slots).saturating_mul(u64::from(self.config.max_datagram.get())),
        }
    }

    /// Items Submitted and not yet completed.
    #[must_use]
    pub fn submitted(&self) -> usize {
        self.slots
            .iter()
            .filter(|meta| meta.phase == Phase::Submitted)
            .count()
    }

    /// Adds a route to `destination`.
    ///
    /// # Errors
    ///
    /// `NotActive`, `Unsupported` for an unspecified address or port 0,
    /// `RouteLimit`, `IdentityExhausted`.
    pub fn add_route(&mut self, destination: SocketAddr) -> Result<RouteId, RouteError> {
        if self.state != State::Active {
            return Err(RouteError::NotActive);
        }
        if destination.ip().is_unspecified() || destination.port() == 0 {
            return Err(RouteError::Unsupported);
        }
        self.routes
            .insert(destination)
            .map_err(|error| match error {
                IssueError::Full => RouteError::RouteLimit,
                IssueError::IdentityExhausted => RouteError::IdentityExhausted,
            })
    }

    /// Removes `route`.
    ///
    /// # Errors
    ///
    /// `NotActive`, `Unknown`, or `InUse` while an open queue names it.
    pub fn remove_route(&mut self, route: RouteId) -> Result<(), RouteError> {
        if self.state != State::Active {
            return Err(RouteError::NotActive);
        }
        if self.routes.get(route).is_none() {
            return Err(RouteError::Unknown);
        }
        if self
            .ledger
            .queues()
            .iter()
            .any(|(_, account)| account.route() == route)
        {
            return Err(RouteError::InUse);
        }
        self.routes.remove(route);
        Ok(())
    }

    /// Opens a bounded FIFO queue of one authority and one route.
    ///
    /// # Errors
    ///
    /// `NotActive`, `RouteUnknown`, then the ledger's `QueueLimit`,
    /// `OverCommitted` and `IdentityExhausted`.
    pub fn open_queue(&mut self, config: TxQueueConfig) -> Result<TxQueueId, QueueError> {
        if self.state != State::Active {
            return Err(QueueError::NotActive);
        }
        if self.routes.get(config.route).is_none() {
            return Err(QueueError::RouteUnknown);
        }
        let id = self.ledger.open_queue(config)?;
        match self.runs.get_mut(usize::from(id.index())) {
            Some(run) => {
                *run = Run {
                    id: Some(id),
                    ..IDLE_RUN
                };
                Ok(id)
            }
            None => {
                // The ledger issues indices below `max_queues`; undo.
                let _ = self.ledger.close_queue(id);
                Err(issue_queue(IssueError::Full))
            }
        }
    }

    /// Returns the pending items of `queue` with `QueueClosed` up to the
    /// report capacity and stops its claims, commits and flushes; once
    /// none is pending and every Submitted item has its terminal
    /// completion ([`TxBackend::poll_completions`]), closes it. Call while
    /// `more` is true.
    ///
    /// # Errors
    ///
    /// `ReportNotEmpty`, `NotActive`, `UnknownQueue`.
    pub fn close_queue(
        &mut self,
        queue: TxQueueId,
        report: &mut TxReport,
    ) -> Result<CancelOutcome, QueueError> {
        let Some(mut writer) = report.writer() else {
            return Err(QueueError::ReportNotEmpty);
        };
        if self.state != State::Active {
            return Err(QueueError::NotActive);
        }
        let index = self.run_index(queue).ok_or(QueueError::UnknownQueue)?;
        if let Some(run) = self.runs.get_mut(index) {
            run.closing = true;
        }
        let (returned, more) = self.return_pending(index, ReturnReason::QueueClosed, &mut writer);
        if more {
            return Ok(CancelOutcome { returned, more });
        }
        // Submitted items stay charged to the queue until their terminal
        // completions release them; the queue closes only after that, so
        // no slot is stranded by queue turnover.
        let in_flight = self
            .slots
            .iter()
            .any(|meta| meta.queue == Some(queue) && meta.phase == Phase::Submitted);
        if in_flight {
            return Ok(CancelOutcome {
                returned,
                more: true,
            });
        }
        self.ledger.close_queue(queue)?;
        if let Some(run) = self.runs.get_mut(index) {
            *run = IDLE_RUN;
        }
        Ok(CancelOutcome {
            returned,
            more: false,
        })
    }

    /// Asks the kernel to cancel the Submitted items of `queue` (design
    /// 10.1): one `ASYNC_CANCEL` per item, in the control slots. Nothing
    /// is released here; a target completing with `-ECANCELED` reports
    /// `SendResult(Err(Cancelled))` and `Released` from
    /// [`TxBackend::poll_completions`], and one already running completes
    /// as it does.
    ///
    /// # Errors
    ///
    /// `UnknownQueue`, or `NotActive` once the half is closed.
    pub fn cancel_submitted(&mut self, queue: TxQueueId) -> Result<CancelSubmitted, QueueError> {
        if self.state == State::Closed {
            return Err(QueueError::NotActive);
        }
        self.run_index(queue).ok_or(QueueError::UnknownQueue)?;
        let mut issued: u16 = 0;
        let mut more = false;
        for slot in 0..self.slots.len() {
            let Some(meta) = self.slots.get(slot).copied() else {
                break;
            };
            if meta.queue != Some(queue) || meta.phase != Phase::Submitted {
                continue;
            }
            let (Ok(index), Some(generation)) = (u16::try_from(slot), meta.generation) else {
                continue;
            };
            let target = CancelTarget::One(UserData::new(index, generation.get()));
            if self.already_cancelling(target) {
                continue;
            }
            if self.push_control(target).is_err() {
                more = true;
                break;
            }
            issued = issued.saturating_add(1);
        }
        if issued > 0 {
            let _ = self.enter_control();
        }
        Ok(CancelSubmitted { issued, more })
    }

    /// Resets the half (design 10.2): returns pending items with
    /// `ReturnReason::Reset` up to the report capacity, cancels every
    /// operation of the ring once, then reaps within `budget`, reporting
    /// completions to `handler`. Call until `more` is false; until then
    /// nothing the kernel may own is freed, and [`UringReset::retained`]
    /// says what it still owns. The first call stops claims, commits and
    /// flushes.
    pub fn reset<H: CompletionHandler>(
        &mut self,
        report: &mut TxReport,
        budget: Budget,
        handler: &mut H,
    ) -> UringReset {
        let Some(mut writer) = report.writer() else {
            return UringReset {
                returned: 0,
                more: self.state != State::Closed,
                report_not_empty: true,
                retained: self.retained(),
            };
        };
        if self.state == State::Closed {
            return UringReset {
                returned: 0,
                more: false,
                report_not_empty: false,
                retained: self.retained(),
            };
        }
        self.state = State::Resetting;
        let mut returned: u16 = 0;
        let mut pending = false;
        for index in 0..self.runs.len() {
            let (count, more) = self.return_pending(index, ReturnReason::Reset, &mut writer);
            returned = returned.saturating_add(count);
            pending |= more;
        }
        let kernel = self.ring.kernel_owned() > 0 || self.submitted() > 0;
        if kernel && self.ring_cancel.is_none() && self.push_control(CancelTarget::All).is_ok() {
            self.ring_cancel = Some(RingCancel {
                count: None,
                seen: 0,
            });
            let _ = self.enter_control();
        }
        self.reap(budget, handler);
        let busy = self.ring.kernel_owned() > 0
            || self.submitted() > 0
            || self
                .control
                .iter()
                .any(|control| control.in_flight.is_some());
        let more = pending || busy;
        if !more {
            self.finish_reset();
        }
        UringReset {
            returned,
            more,
            report_not_empty: false,
            retained: self.retained(),
        }
    }

    fn finish_reset(&mut self) {
        if let Some(cancel) = self.ring_cancel.take()
            && let Some(count) = cancel.count
            && count != cancel.seen
        {
            let diff = count.abs_diff(cancel.seen);
            self.counters.cancel_count_diff = self
                .counters
                .cancel_count_diff
                .saturating_add(u64::from(diff));
        }
        for meta in &mut *self.slots {
            if meta.phase == Phase::Quarantined {
                *meta = SlotMeta {
                    generation: meta.generation,
                    ..FREE_META
                };
            }
        }
        self.ledger.reset(self.epoch);
        self.runs.fill(IDLE_RUN);
        self.state = State::Closed;
    }

    /// The run of an open queue that is not closing: the one claims,
    /// commits and flushes use.
    fn open_run(&self, queue: TxQueueId) -> Option<usize> {
        let index = self.run_index(queue)?;
        (!self.runs.get(index)?.closing).then_some(index)
    }

    fn run_index(&self, queue: TxQueueId) -> Option<usize> {
        let index = usize::from(queue.index());
        let run = self.runs.get(index)?;
        (run.id == Some(queue)).then_some(index)
    }

    fn already_cancelling(&self, target: CancelTarget) -> bool {
        self.control
            .iter()
            .any(|control| control.in_flight == Some(target))
    }

    /// Publishes a cancel of `target` in a free control slot.
    fn push_control(&mut self, target: CancelTarget) -> Result<(), PushError> {
        let slots = self.config.tx_slots.get();
        let (index, control) = self
            .control
            .iter_mut()
            .enumerate()
            .find(|(_, control)| control.in_flight.is_none())
            .ok_or(PushError::Full)?;
        let generation = control.generation.checked_add(1).ok_or(PushError::Full)?;
        let index = u16::try_from(index)
            .ok()
            .and_then(|index| slots.checked_add(index))
            .ok_or(PushError::OutOfRange)?;
        self.ring
            .push_cancel(target, UserData::new(index, generation))?;
        control.generation = generation;
        control.in_flight = Some(target);
        Ok(())
    }

    /// One enter for control operations; a failure is counted and the
    /// next call enters again.
    fn enter_control(&mut self) -> Result<u32, i32> {
        match self.ring.enter() {
            Ok(consumed) => Ok(consumed),
            Err(errno) => {
                self.enter_failed(errno.0);
                Err(errno.0)
            }
        }
    }

    /// Records a failed enter: `EINTR` and `EAGAIN` retry, `EBUSY` and
    /// `EBADR` are the overflow invariant, anything else stops the half.
    fn enter_failed(&mut self, errno: i32) -> FlushStop {
        match errno {
            EINTR => {
                bump(&mut self.counters.enter_retries);
                FlushStop::Interrupted
            }
            EAGAIN => {
                bump(&mut self.counters.enter_retries);
                FlushStop::WouldBlock
            }
            EBUSY | EBADR => FlushStop::Failed(self.overflowed()),
            errno => {
                let failure = BackendFailure::Os {
                    operation: ENTER,
                    errno,
                };
                self.failed.get_or_insert(failure);
                FlushStop::Failed(failure)
            }
        }
    }

    /// A CQ overflow (design 5.2): every Submitted slot is quarantined, no
    /// release is inferred, and the half stops until reset.
    fn overflowed(&mut self) -> BackendFailure {
        let failure = BackendFailure::Invariant {
            operation: OVERFLOW,
        };
        if self.failed.is_none() {
            bump(&mut self.counters.cq_overflow);
        }
        self.failed.get_or_insert(failure);
        for slot in 0..self.slots.len() {
            self.quarantine_slot(slot);
        }
        failure
    }

    /// Quarantines a Submitted slot (and faults nothing else).
    fn quarantine_slot(&mut self, slot: usize) {
        let Some(meta) = self.slots.get_mut(slot) else {
            return;
        };
        if meta.phase != Phase::Submitted {
            return;
        }
        meta.phase = Phase::Quarantined;
        let charged = match (meta.queue, u32::try_from(slot)) {
            (Some(queue), Ok(slot)) => self.ledger.quarantine(queue, slot),
            _ => false,
        };
        if !charged {
            bump(&mut self.counters.invariants);
        }
    }

    /// A report entry or a ledger charge the endpoint's own state promised
    /// could not be written: the half stops until reset rather than go on
    /// with evidence missing.
    fn broken(&mut self, queue: Option<TxQueueId>) {
        self.fault(queue);
        self.failed.get_or_insert(BackendFailure::Invariant {
            operation: "uring_tx_state",
        });
    }

    fn fault(&mut self, queue: Option<TxQueueId>) {
        bump(&mut self.counters.invariants);
        if let Some(index) = queue.and_then(|queue| self.run_index(queue))
            && let Some(run) = self.runs.get_mut(index)
        {
            run.faulted = true;
        }
    }

    /// Takes pending items of run `index` off its FIFO and returns them
    /// with `reason` until the report is full; `more` when some remain.
    fn return_pending(
        &mut self,
        index: usize,
        reason: ReturnReason,
        writer: &mut ReportWriter<'_>,
    ) -> (u16, bool) {
        let mut returned: u16 = 0;
        loop {
            let Some(run) = self.runs.get(index).copied() else {
                return (returned, false);
            };
            if run.len == 0 {
                return (returned, false);
            }
            if writer.remaining() == 0 {
                return (returned, true);
            }
            let Some(queue) = run.id else {
                return (returned, false);
            };
            let Some((slot, meta)) = self.pop_head(index) else {
                return (returned, false);
            };
            let Some(entry) = self.entry(slot, meta, TxItemOutcome::Returned { reason }) else {
                return (returned, false);
            };
            if writer.push(entry).is_err() {
                self.broken(Some(queue));
            }
            if let Some(slot_meta) = self.slots.get_mut(slot as usize) {
                *slot_meta = SlotMeta {
                    generation: meta.generation,
                    ..FREE_META
                };
            }
            if !self.ledger.release_pending(queue, slot) {
                self.broken(Some(queue));
            }
            returned = returned.saturating_add(1);
        }
    }

    fn entry(&self, slot: u32, meta: SlotMeta, outcome: TxItemOutcome) -> Option<TxEntry> {
        Some(TxEntry {
            ticket: TxTicket::new(self.id(slot, meta)?),
            token: meta.token,
            len: meta.len,
            outcome,
        })
    }

    fn id(&self, slot: u32, meta: SlotMeta) -> Option<SubmissionId> {
        Some(SubmissionId::new(
            self.instance,
            self.epoch,
            slot,
            meta.generation?,
        ))
    }

    fn pop_head(&mut self, index: usize) -> Option<(u32, SlotMeta)> {
        let run = self.runs.get(index).copied()?;
        let slot = run.head;
        let meta = self.slots.get(slot as usize).copied()?;
        let len = run.len.checked_sub(1)?;
        let run = self.runs.get_mut(index)?;
        run.head = meta.next;
        run.len = len;
        if len == 0 {
            run.tail = NO_SLOT;
        }
        Some((slot, meta))
    }

    fn push_tail(&mut self, index: usize, slot: u32) -> bool {
        let Some(run) = self.runs.get(index).copied() else {
            return false;
        };
        let Some(len) = run.len.checked_add(1) else {
            return false;
        };
        if run.tail != NO_SLOT {
            match self.slots.get_mut(run.tail as usize) {
                Some(tail) => tail.next = slot,
                None => return false,
            }
        }
        let Some(run) = self.runs.get_mut(index) else {
            return false;
        };
        if run.head == NO_SLOT {
            run.head = slot;
        }
        run.tail = slot;
        run.len = len;
        true
    }

    /// Reaps up to `budget.datagrams` completions, entering first when
    /// the ring needs it, and reports them to `handler`.
    fn reap<H: CompletionHandler>(&mut self, budget: Budget, handler: &mut H) -> CompletionOutcome {
        let mut outcome = CompletionOutcome::default();
        if self.state == State::Closed {
            return outcome;
        }
        if budget.ops() > 0 && self.ring.needs_enter() {
            outcome.spent.ops = 1;
            let _ = self.enter_control();
        }
        let max = usize::try_from(budget.datagrams())
            .unwrap_or(REAP)
            .min(REAP);
        let mut cqes = [Cqe::EMPTY; REAP];
        let reaped = self.ring.reap(cqes.get_mut(..max).unwrap_or_default());
        for cqe in cqes.iter().take(reaped) {
            outcome.spent.datagrams = outcome.spent.datagrams.saturating_add(1);
            let events = self.complete(*cqe, handler);
            outcome.events = outcome.events.saturating_add(events);
        }
        if self.ring.cq_overflowed() {
            self.overflowed();
        }
        outcome
    }

    /// Handles one completion; returns the events delivered.
    fn complete<H: CompletionHandler>(&mut self, cqe: Cqe, handler: &mut H) -> u32 {
        let index = cqe.user_data.index();
        let slots = self.config.tx_slots.get();
        if index < slots {
            return self.complete_send(usize::from(index), cqe, handler);
        }
        let control = index
            .checked_sub(slots)
            .and_then(|control| self.control.get_mut(usize::from(control)));
        match control {
            Some(control)
                if control.in_flight.is_some()
                    && cqe.user_data.names(index, control.generation) =>
            {
                let target = control.in_flight.take();
                if target == Some(CancelTarget::All)
                    && let Some(cancel) = &mut self.ring_cancel
                {
                    cancel.count = u32::try_from(cqe.result).ok();
                }
            }
            _ => bump(&mut self.counters.stale_completions),
        }
        0
    }

    fn complete_send<H: CompletionHandler>(
        &mut self,
        slot: usize,
        cqe: Cqe,
        handler: &mut H,
    ) -> u32 {
        let Some(meta) = self.slots.get(slot).copied() else {
            return 0;
        };
        let matches = meta.generation.is_some_and(|generation| {
            u16::try_from(slot).is_ok_and(|index| cqe.user_data.names(index, generation.get()))
        });
        if !matches || !matches!(meta.phase, Phase::Submitted | Phase::Quarantined) {
            // Stale or duplicated: never touches the current occupant
            // (design 3.4); the queue that owns the slot needs a reset.
            bump(&mut self.counters.stale_completions);
            self.fault(meta.queue);
            return 0;
        }
        let (Ok(slot32), Some(queue)) = (u32::try_from(slot), meta.queue) else {
            return 0;
        };
        let Some(id) = self.id(slot32, meta) else {
            return 0;
        };
        if meta.phase == Phase::Quarantined {
            // Release evidence was lost earlier (overflow or closed
            // queue); the slot stays quarantined until reset.
            return 0;
        }
        match resolve(cqe.result, meta.len) {
            Resolution::Sent(result) => {
                if let Err(error) = result {
                    if not_transmitted(error) {
                        bump(&mut self.counters.known_not_transmitted);
                    }
                    match error {
                        SendError::WouldBlock => bump(&mut self.counters.send_wouldblock),
                        SendError::Cancelled => {
                            bump(&mut self.counters.cancelled);
                            if let Some(cancel) = &mut self.ring_cancel {
                                cancel.seen = cancel.seen.saturating_add(1);
                            }
                        }
                        _ => {}
                    }
                }
                handler.event(TxEvent::SendResult {
                    id,
                    token: meta.token,
                    result,
                });
                handler.event(TxEvent::Released {
                    id,
                    token: meta.token,
                });
                if let Some(slot_meta) = self.slots.get_mut(slot) {
                    *slot_meta = SlotMeta {
                        generation: meta.generation,
                        ..FREE_META
                    };
                }
                if !self.ledger.release_pending(queue, slot32) {
                    self.broken(Some(queue));
                }
                2
            }
            Resolution::Invariant => {
                self.quarantine_slot(slot);
                self.fault(Some(queue));
                0
            }
        }
    }
}

/// A claimed `io_uring` TX frame. Dropping it returns the slot.
#[derive(Debug)]
pub struct UringFrame<'a, R: RingOps> {
    tx: &'a mut UringTx<R>,
    queue: TxQueueId,
    slot: u32,
    len: usize,
    committed: bool,
}

impl<R: RingOps> TxFrame for UringFrame<'_, R> {
    fn capacity(&self) -> usize {
        self.len
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        u16::try_from(self.slot)
            .ok()
            .and_then(|slot| self.tx.ring.bytes_mut(slot))
            .and_then(|bytes| bytes.get_mut(..len))
            .unwrap_or_default()
    }

    fn commit(mut self, commit: Commit) -> Result<TxTicket, CommitRejected<Self>> {
        let active = self.tx.state == State::Active;
        if let Err(error) =
            self.tx
                .ledger
                .check_commit(active, self.queue, commit.len, self.len, commit.options)
        {
            return Err(CommitRejected { frame: self, error });
        }
        let Some(index) = self.tx.open_run(self.queue) else {
            return Err(CommitRejected {
                frame: self,
                error: CommitError::UnknownQueue,
            });
        };
        let (Ok(len), Some(meta)) = (
            u16::try_from(commit.len),
            self.tx.slots.get(self.slot as usize).copied(),
        ) else {
            let capacity = self.len;
            return Err(CommitRejected {
                frame: self,
                error: CommitError::LengthExceedsClaim {
                    len: commit.len,
                    capacity,
                },
            });
        };
        let Some(id) = self.tx.id(self.slot, meta) else {
            return Err(CommitRejected {
                frame: self,
                error: CommitError::UnknownQueue,
            });
        };
        if !self.tx.push_tail(index, self.slot) {
            return Err(CommitRejected {
                frame: self,
                error: CommitError::UnknownQueue,
            });
        }
        if !self.tx.ledger.pool_mut().commit(self.slot) {
            self.tx.broken(Some(self.queue));
        }
        if let Some(meta) = self.tx.slots.get_mut(self.slot as usize) {
            meta.phase = Phase::Pending;
            meta.token = commit.token;
            meta.len = len;
            meta.next = NO_SLOT;
        }
        self.committed = true;
        Ok(TxTicket::new(id))
    }
}

impl<R: RingOps> Drop for UringFrame<'_, R> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.tx.ledger.release_claim(self.queue, self.slot)
            && let Some(meta) = self.tx.slots.get_mut(self.slot as usize)
        {
            *meta = SlotMeta {
                generation: meta.generation,
                ..FREE_META
            };
        }
    }
}

impl<R: RingOps> TxBackend for UringTx<R> {
    type Frame<'a>
        = UringFrame<'a, R>
    where
        Self: 'a;

    fn claim_tx(&mut self, queue: TxQueueId, len: usize) -> Result<UringFrame<'_, R>, ClaimError> {
        let active = self.state == State::Active;
        if active && self.open_run(queue).is_none() {
            return Err(ClaimError::UnknownQueue);
        }
        let claimed = self.ledger.claim(active, queue, len)?;
        if let Some(meta) = self.slots.get_mut(claimed.slot as usize) {
            *meta = SlotMeta {
                phase: Phase::Claimed,
                queue: Some(queue),
                generation: Some(claimed.generation),
                ..FREE_META
            };
        }
        Ok(UringFrame {
            tx: self,
            queue,
            slot: claimed.slot,
            len,
            committed: false,
        })
    }

    /// Design 3.2: one gate check, then one copied `SENDMSG` per permitted
    /// item, each Submitted from its publication, then one enter. A failed
    /// enter changes no entry: published SQEs stay for the next enter.
    fn flush<G: SenderGate>(
        &mut self,
        request: FlushRequest,
        gate: &mut G,
        report: &mut TxReport,
    ) -> FlushOutcome {
        let mut outcome = FlushOutcome {
            submitted: 0,
            bytes: 0,
            spent: Spent::default(),
            stop: FlushStop::QueueEmpty,
        };
        let Some(mut writer) = report.writer() else {
            outcome.stop = FlushStop::ReportNotEmpty;
            return outcome;
        };
        if let Some(failure) = self.failed {
            outcome.stop = FlushStop::Failed(failure);
            return outcome;
        }
        if self.state != State::Active {
            outcome.stop = FlushStop::Queue(QueueError::NotActive);
            return outcome;
        }
        let Some(index) = self.open_run(request.queue) else {
            outcome.stop = FlushStop::Queue(QueueError::UnknownQueue);
            return outcome;
        };
        let Some(run) = self.runs.get(index).copied() else {
            outcome.stop = FlushStop::Queue(QueueError::UnknownQueue);
            return outcome;
        };
        if run.faulted {
            outcome.stop = FlushStop::Queue(QueueError::NeedsReset);
            return outcome;
        }
        if run.len == 0 {
            return outcome;
        }
        let Some(account) = self.ledger.queues().get(request.queue) else {
            outcome.stop = FlushStop::Queue(QueueError::UnknownQueue);
            return outcome;
        };
        let (authority, route) = (account.authority(), account.route());
        let Some(destination) = self.routes.get(route).copied() else {
            outcome.stop = FlushStop::Queue(QueueError::RouteUnknown);
            return outcome;
        };

        // Step 1: free SQ entries; one enter drains SQEs exposed earlier,
        // which exposes nothing new and needs no gate check.
        let mut free = self.ring.sq_free();
        if free == 0 && self.ring.needs_enter() {
            outcome.spent.ops = 1;
            if let Err(errno) = self.ring.enter() {
                outcome.stop = self.enter_failed(errno.0);
                return outcome;
            }
            free = self.ring.sq_free();
        }
        if free == 0 {
            // No SQ entry: the design's `SqFull`, reported as the
            // kernel having no room (FlushStop::WouldBlock).
            outcome.stop = FlushStop::WouldBlock;
            return outcome;
        }

        // The head prefix, clamped to the request, the batch, the SQ and
        // the byte budget.
        let limit = usize::from(request.max_datagrams.get())
            .min(usize::from(self.config.max_batch.get()))
            .min(free)
            .min(BATCH)
            .min(writer.remaining());
        let mut tokens = [SenderToken::new(0); BATCH];
        let mut lengths = [0_u16; BATCH];
        let mut slots = [NO_SLOT; BATCH];
        let mut offered: usize = 0;
        let mut bytes: u32 = 0;
        let mut cursor = run.head;
        while offered < limit && cursor != NO_SLOT {
            let Some(meta) = self.slots.get(cursor as usize).copied() else {
                break;
            };
            let Some(next) = bytes.checked_add(u32::from(meta.len)) else {
                break;
            };
            if next > request.max_bytes {
                break;
            }
            if let (Some(token), Some(len), Some(slot)) = (
                tokens.get_mut(offered),
                lengths.get_mut(offered),
                slots.get_mut(offered),
            ) {
                *token = meta.token;
                *len = meta.len;
                *slot = cursor;
            }
            bytes = next;
            offered = offered.saturating_add(1);
            cursor = meta.next;
        }
        if offered == 0 {
            let head_len = self.slots.get(run.head as usize).map_or(0, |meta| meta.len);
            outcome.stop = FlushStop::HeadExceedsBudget { head_len };
            return outcome;
        }
        let offered_u16 = u16::try_from(offered).unwrap_or(URING_MAX_BATCH);

        // Step 2: one gate check; a panic leaves no SQE written.
        let decision = gate.check(&Exposure {
            authority,
            route,
            epoch: self.epoch,
            tokens: tokens.get(..offered).unwrap_or_default(),
            lengths: lengths.get(..offered).unwrap_or_default(),
        });
        let permitted = match decision {
            GateDecision::Deny => {
                self.report_pending(&mut writer, &slots, 0, offered, PendingCause::GateDenied);
                outcome.stop = FlushStop::GateDenied;
                return outcome;
            }
            GateDecision::Permit { count } if count.get() > offered_u16 => {
                self.report_pending(&mut writer, &slots, 0, offered, PendingCause::GateDenied);
                outcome.stop = FlushStop::GateError {
                    permitted: count.get(),
                    offered: offered_u16,
                };
                return outcome;
            }
            GateDecision::Permit { count } => usize::from(count.get()),
        };

        // Steps 3 to 5: publish each permitted item; it is Submitted from
        // its publication. A refused push exposes nothing more.
        let mut exposed: usize = 0;
        for &slot in slots.iter().take(permitted) {
            let Some(meta) = self.slots.get(slot as usize).copied() else {
                break;
            };
            let (Ok(index16), Some(generation)) = (u16::try_from(slot), meta.generation) else {
                break;
            };
            let user_data = UserData::new(index16, generation.get());
            if self
                .ring
                .push_send(index16, meta.len, destination, user_data)
                .is_err()
            {
                break;
            }
            if self.pop_head(index).map(|(head, _)| head) != Some(slot) {
                // Published, but the FIFO disagrees: report it Submitted and
                // stop the half, never re-send it.
                self.broken(Some(request.queue));
            }
            if let Some(slot_meta) = self.slots.get_mut(slot as usize) {
                slot_meta.phase = Phase::Submitted;
                slot_meta.next = NO_SLOT;
            }
            #[cfg(any(test, feature = "test-hooks"))]
            if self.release_at_submission
                && let Some(slot_meta) = self.slots.get_mut(slot as usize)
            {
                *slot_meta = SlotMeta {
                    generation: meta.generation,
                    ..FREE_META
                };
                let _ = self.ledger.release_pending(request.queue, slot);
            }
            if let Some(entry) = self.entry(
                slot,
                meta,
                TxItemOutcome::Submitted {
                    release: Release::Deferred,
                },
            ) && writer.push(entry).is_err()
            {
                self.broken(Some(request.queue));
            }
            outcome.submitted = outcome.submitted.saturating_add(1);
            outcome.bytes = outcome.bytes.saturating_add(u32::from(meta.len));
            exposed = exposed.saturating_add(1);
        }
        self.report_pending(
            &mut writer,
            &slots,
            exposed,
            offered,
            PendingCause::NotAttempted,
        );
        outcome.spent.datagrams = u32::from(outcome.submitted);
        outcome.spent.bytes = u64::from(outcome.bytes);
        if exposed == 0 {
            outcome.stop = FlushStop::WouldBlock;
            return outcome;
        }

        // Step 6: one enter, unless SQPOLL submits on its own.
        outcome.stop = FlushStop::Exposed;
        if self.sqpoll != CapabilityState::Active || self.ring.needs_enter() {
            outcome.spent.ops = outcome.spent.ops.saturating_add(1);
            if let Err(errno) = self.ring.enter() {
                outcome.stop = self.enter_failed(errno.0);
            }
        }
        outcome
    }

    fn poll_completions<H: CompletionHandler>(
        &mut self,
        budget: Budget,
        handler: &mut H,
    ) -> CompletionOutcome {
        self.reap(budget, handler)
    }

    /// Returns only Pending items; Submitted ones are the kernel's until
    /// their completions ([`UringTx::cancel_submitted`]).
    fn cancel_pending(
        &mut self,
        queue: TxQueueId,
        report: &mut TxReport,
    ) -> Result<CancelOutcome, QueueError> {
        let Some(mut writer) = report.writer() else {
            return Err(QueueError::ReportNotEmpty);
        };
        if self.state != State::Active {
            return Err(QueueError::NotActive);
        }
        let index = self.run_index(queue).ok_or(QueueError::UnknownQueue)?;
        let (returned, more) = self.return_pending(index, ReturnReason::Cancelled, &mut writer);
        Ok(CancelOutcome { returned, more })
    }
}

impl<R: RingOps> UringTx<R> {
    /// Reports candidates `from..to` of `slots` Pending with `cause`.
    fn report_pending(
        &mut self,
        writer: &mut ReportWriter<'_>,
        slots: &[u32; BATCH],
        from: usize,
        to: usize,
        cause: PendingCause,
    ) {
        for &slot in slots.iter().take(to).skip(from) {
            let Some(meta) = self.slots.get(slot as usize).copied() else {
                continue;
            };
            if let Some(entry) = self.entry(slot, meta, TxItemOutcome::Pending { cause })
                && writer.push(entry).is_err()
            {
                self.broken(meta.queue);
            }
        }
    }
}

#[cfg(test)]
mod tests;
