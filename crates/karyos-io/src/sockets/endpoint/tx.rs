// SPDX-License-Identifier: Apache-2.0

//! The TX state of one endpoint: slot bytes, the pending FIFO of each queue,
//! routes, claim and commit, flush and the returns of cancellation, close
//! and reset (`quantstratum-docs: karyos/design/sockets-backend.md` 3.3,
//! 3.4, 3.8, 4.3, 4.7, section 6 and 7.2).
//!
//! Pending queues are intrusive lists threaded through slot metadata
//! indices, so no queue allocates (5.1). Every allocation happens in
//! [`TxCore::new`], on the control path.
//!
//! Positions, lengths and counts are checked (SPEC §14). Where the
//! endpoint finds its own state broken (a FIFO link to a slot of another
//! queue, a pending slot without a generation, a count that cannot move)
//! it never fabricates a value: the queue faults with an invariant
//! violation, which only a reset clears (6.3, S-16).

use std::num::NonZeroU64;
use std::sync::atomic::Ordering;

use super::config::{SOCKETS_MAX_BATCH, SOCKETS_MAX_BATCH_LEN, SocketsConfig};
use super::rx::count_up;
use super::{State, TX_DISCARDED_ON_DROP};
use crate::backend::handles::{HandleTable, IssueError};
use crate::backend::ledger::TxLedger;
use crate::backend::{
    BackendEpoch, BackendFailure, CancelOutcome, CapabilityState, ClaimError, Commit, CommitError,
    CommitRejected, Exposure, FlushOutcome, FlushRequest, FlushStop, GateDecision, InstanceId,
    OpenError, PendingCause, QueueError, Reason, Release, ReportWriter, ReturnReason, RouteError,
    RouteId, SendError, SenderGate, SenderToken, Spent, SubmissionId, TX_REPORT_CAPACITY, TxEntry,
    TxFrame, TxItemOutcome, TxQueueConfig, TxQueueId, TxReport, TxTicket,
};
use crate::sockets::ops::{Errno, RouteAddr, SendResult, SocketOps};

/// The end of a pending list.
const NO_SLOT: u32 = u32::MAX;
/// The stack arrays of one flush: at most this many candidates.
const BATCH: usize = SOCKETS_MAX_BATCH_LEN;
// Every candidate of one flush has a report entry.
const _: () = assert!(BATCH <= TX_REPORT_CAPACITY);
/// The operation named in send failures.
const SEND: &str = "send";
/// The operation named in invariant faults the endpoint finds in its own
/// queue state during a flush, before any exposure.
const FLUSH: &str = "flush";
/// UDP header bytes (4.5).
const UDP_HEADER: u16 = 8;
/// UDP and IPv4 header bytes without options (4.5); a constant sum, so an
/// overflow fails the build.
const IPV4_OVERHEAD: u16 = UDP_HEADER + 20;
/// UDP and IPv6 header bytes without extension headers (4.5).
const IPV6_OVERHEAD: u16 = UDP_HEADER + 40;

/// The result of `add_route`'s measurement, per route (3.8 and 4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInfo {
    /// The measured route MTU, or `None` when it could not be measured.
    pub route_mtu: Option<u32>,
    /// `Active` when measured, `Fallback(Unverified)` otherwise.
    pub path_mtu: CapabilityState,
}

#[derive(Debug, Clone)]
struct RouteEntry {
    address: RouteAddr,
    info: RouteInfo,
}

/// The metadata of one slot while it is pending.
#[derive(Debug, Clone, Copy)]
struct SlotMeta {
    /// The queue holding the slot; `None` unless Pending.
    queue: Option<TxQueueId>,
    generation: Option<NonZeroU64>,
    token: SenderToken,
    len: u16,
    /// The next pending slot of the same queue.
    next: u32,
    /// The item already has its terminal report (`Unknown`) but could not
    /// be taken off its FIFO; whatever later pops it quarantines it without
    /// a second report (at most one terminal report per ticket).
    terminal: bool,
}

const EMPTY_META: SlotMeta = SlotMeta {
    queue: None,
    generation: None,
    token: SenderToken::new(0),
    len: 0,
    next: NO_SLOT,
    terminal: false,
};

/// One pending item as a flush or a return reports it: everything its
/// report entry needs, read from the slot metadata once, so no entry is
/// built from a default.
#[derive(Debug, Clone, Copy)]
struct Item {
    slot: u32,
    ticket: TxTicket,
    token: SenderToken,
    len: u16,
    /// Reported `Unknown` already ([`SlotMeta::terminal`]).
    terminal: bool,
}

impl Item {
    fn entry(self, outcome: TxItemOutcome) -> TxEntry {
        TxEntry {
            ticket: self.ticket,
            token: self.token,
            len: self.len,
            outcome,
        }
    }
}

/// Why a queue is faulted (6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The head failed with a send error; `retry_queue` clears it.
    Send(SendError),
    /// A result outside the ABI, or the endpoint's own queue state found
    /// broken; only a reset clears it (S-16).
    Invariant,
}

/// The pending FIFO and fault state of one open queue.
#[derive(Debug, Clone, Copy)]
struct QueueRun {
    id: Option<TxQueueId>,
    head: u32,
    tail: u32,
    len: u16,
    fault: Option<Fault>,
    /// `close_queue` has started; the queue takes no new claim or commit.
    closing: bool,
}

const IDLE_RUN: QueueRun = QueueRun {
    id: None,
    head: NO_SLOT,
    tail: NO_SLOT,
    len: 0,
    fault: None,
    closing: false,
};

/// What a send result established about the permitted prefix.
#[derive(Debug, Clone, Copy)]
enum Next {
    /// Every permitted item was accepted.
    Done,
    /// Item `accepted` stays pending with `cause`; later items are
    /// `NotAttempted`.
    Pending {
        cause: PendingCause,
        stop: FlushStop,
        fault: Option<Fault>,
    },
    /// Items from `accepted` are `Unknown` and quarantined (6.3).
    Unknown,
}

/// The TX half's state; `SocketsTx` adds the socket.
#[derive(Debug)]
pub(super) struct TxCore {
    pub(super) instance: InstanceId,
    pub(super) epoch: BackendEpoch,
    pub(super) state: State,
    pub(super) config: SocketsConfig,
    bytes: Box<[u8]>,
    slots: Box<[SlotMeta]>,
    runs: Box<[QueueRun]>,
    ledger: TxLedger,
    routes: HandleTable<RouteId, RouteEntry>,
    peer_errors: u64,
    /// Counter increments that would have overflowed and were not applied.
    counter_overflows: u64,
    /// Whether each send of the epoch is one `sendmmsg` (4.3); `Spent::ops`
    /// counts by it.
    batched: bool,
    /// The failure that stopped the half (3.10): every later flush returns
    /// it with no gate check and no system call until `reset` and
    /// `reopen`.
    failed: Option<BackendFailure>,
    /// A test broke an invariant on purpose; the debug assertions of the
    /// release build guards stay quiet so the guards themselves run.
    #[cfg(test)]
    injected: bool,
    /// A head owner change [`Self::inject_after_send`] applies once the
    /// next send call has returned.
    #[cfg(test)]
    after_send: Option<(TxQueueId, Option<TxQueueId>)>,
}

impl TxCore {
    /// Allocates the pool, its metadata and the tables for a validated
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` for `tx_slots` when the pool size does not
    /// fit `usize`, which `validate` already rules out.
    pub(super) fn new(
        config: &SocketsConfig,
        instance: InstanceId,
        epoch: BackendEpoch,
        batched: bool,
    ) -> Result<Self, OpenError> {
        let slots = usize::from(config.tx_slots.get());
        let pool_bytes = slots
            .checked_mul(usize::from(config.max_datagram.get()))
            .ok_or(OpenError::InvalidConfig {
                field: "tx_slots",
                value: u64::from(config.tx_slots.get()),
            })?;
        Ok(Self {
            instance,
            epoch,
            state: State::Active,
            config: *config,
            bytes: vec![0; pool_bytes].into_boxed_slice(),
            slots: vec![EMPTY_META; slots].into_boxed_slice(),
            runs: vec![IDLE_RUN; usize::from(config.max_queues.get())].into_boxed_slice(),
            ledger: TxLedger::new(
                config.tx_slots,
                config.max_queues,
                config.max_datagram,
                epoch,
            ),
            routes: HandleTable::new(config.max_routes, epoch),
            peer_errors: 0,
            counter_overflows: 0,
            batched,
            failed: None,
            #[cfg(test)]
            injected: false,
            #[cfg(test)]
            after_send: None,
        })
    }

    /// Moves to the new epoch of `reopen`; the sizes are unchanged and a
    /// failure that stopped the half is cleared.
    pub(super) fn reopen(&mut self, config: &SocketsConfig, epoch: BackendEpoch, batched: bool) {
        self.epoch = epoch;
        self.config = *config;
        self.state = State::Active;
        self.batched = batched;
        self.failed = None;
    }

    fn active(&self) -> bool {
        self.state == State::Active
    }

    fn max_datagram(&self) -> u16 {
        self.config.max_datagram.get()
    }

    /// A release build guard found a broken invariant: debug builds assert,
    /// unless a test injected the fault to exercise the guard. The caller
    /// takes its typed path either way.
    fn broken(&self, invariant: &str) {
        debug_assert!(self.injected(), "broken invariant: {invariant}");
    }

    #[cfg(test)]
    fn injected(&self) -> bool {
        self.injected
    }

    #[cfg(not(test))]
    fn injected(&self) -> bool {
        false
    }

    /// `ECONNREFUSED` results of send calls (4.7).
    pub(super) fn peer_errors(&self) -> u64 {
        self.peer_errors
    }

    /// Counter increments that would have overflowed (`count_up`).
    pub(super) fn counter_overflows(&self) -> u64 {
        self.counter_overflows
    }

    /// Items on the FIFOs of every open queue, including items already
    /// reported `Unknown` that could not be taken off their FIFO. At most
    /// 1024 queues of `u16` counts, so the checked sum fits any `usize` of
    /// 32 bits or more; `None` if it did not, which every caller treats as
    /// "items remain", keeping `reset` and the drop check conservative.
    pub(super) fn pending_total(&self) -> Option<usize> {
        self.runs.iter().try_fold(0_usize, |total, run| {
            total.checked_add(usize::from(run.len))
        })
    }

    /// Marks `slot` terminal: reported `Unknown` while it stays on its
    /// FIFO, so it is quarantined, not reported again, when popped.
    fn mark_terminal(&mut self, slot: u32) {
        match self.meta_mut(slot) {
            Some(meta) => meta.terminal = true,
            None => self.broken("an exposed slot has metadata"),
        }
    }

    /// Whether `ticket` names an item that is pending now: same instance,
    /// epoch, slot and generation.
    pub(super) fn is_pending(&self, ticket: TxTicket) -> bool {
        let id = ticket.id();
        id.instance() == self.instance
            && id.epoch() == self.epoch
            && self.meta(id.slot()).is_some_and(|meta| {
                meta.queue.is_some() && !meta.terminal && meta.generation == Some(id.generation())
            })
    }

    fn meta(&self, slot: u32) -> Option<&SlotMeta> {
        usize::try_from(slot).ok().and_then(|at| self.slots.get(at))
    }

    fn meta_mut(&mut self, slot: u32) -> Option<&mut SlotMeta> {
        usize::try_from(slot)
            .ok()
            .and_then(|at| self.slots.get_mut(at))
    }

    fn run(&self, queue: TxQueueId) -> Option<&QueueRun> {
        self.runs
            .get(usize::from(queue.index()))
            .filter(|run| run.id == Some(queue))
    }

    fn run_mut(&mut self, queue: TxQueueId) -> Option<&mut QueueRun> {
        self.runs
            .get_mut(usize::from(queue.index()))
            .filter(|run| run.id == Some(queue))
    }

    fn closing(&self, queue: TxQueueId) -> bool {
        self.run(queue).is_some_and(|run| run.closing)
    }

    /// Faults `queue` with an invariant violation (6.3, S-16).
    fn fault_invariant(&mut self, queue: TxQueueId) {
        if let Some(run) = self.run_mut(queue) {
            run.fault = Some(Fault::Invariant);
        }
    }

    /// The byte range of `slot` in the pool, `len` bytes long.
    fn range(&self, slot: u32, len: usize) -> Option<std::ops::Range<usize>> {
        let start = usize::try_from(slot)
            .ok()?
            .checked_mul(usize::from(self.max_datagram()))?;
        Some(start..start.checked_add(len)?)
    }

    /// The bytes of a pending slot; `None` when the slot or length lies
    /// outside the pool, an invariant violation the caller faults on.
    fn slot_bytes(&self, slot: u32, len: usize) -> Option<&[u8]> {
        self.range(slot, len)
            .and_then(|range| self.bytes.get(range))
    }

    /// The writable bytes of a claimed slot; `None` when the slot or
    /// length lies outside the pool, an invariant violation the caller
    /// faults on. The ledger bounds both at claim.
    fn slot_bytes_mut(&mut self, slot: u32, len: usize) -> Option<&mut [u8]> {
        self.range(slot, len)
            .and_then(|range| self.bytes.get_mut(range))
    }

    /// The pending item at `slot` of `queue` and the next slot of the
    /// FIFO; `None` when the slot is not a pending slot of that queue with
    /// a generation.
    fn item(&self, queue: TxQueueId, slot: u32) -> Option<(Item, u32)> {
        let meta = self.meta(slot).filter(|meta| meta.queue == Some(queue))?;
        let generation = meta.generation?;
        let ticket = TxTicket::new(SubmissionId::new(
            self.instance,
            self.epoch,
            slot,
            generation,
        ));
        let item = Item {
            slot,
            ticket,
            token: meta.token,
            len: meta.len,
            terminal: meta.terminal,
        };
        Some((item, meta.next))
    }

    // -----------------------------------------------------------------
    // Routes (3.8, 4.5)
    // -----------------------------------------------------------------

    /// Adds a route to `destination`, checked in this order: `NotActive`
    /// (also for a half stopped by a failure, as the measurement is a
    /// system call), `Unsupported`, `FamilyMismatch`, `RouteLimit`; then
    /// the route MTU, which gives `PathTooSmall` or `PathUnverified`; then
    /// the generation counter (`IdentityExhausted`).
    pub(super) fn add_route<O: SocketOps>(
        &mut self,
        ops: &mut O,
        destination: std::net::SocketAddr,
    ) -> Result<RouteId, RouteError> {
        if !self.active() || self.failed.is_some() {
            return Err(RouteError::NotActive);
        }
        if destination.ip().is_unspecified() || destination.port() == 0 {
            return Err(RouteError::Unsupported);
        }
        if destination.is_ipv4() != self.config.local.is_ipv4() {
            return Err(RouteError::FamilyMismatch);
        }
        if !self.routes.has_free() {
            return Err(RouteError::RouteLimit);
        }
        let address = RouteAddr::new(destination);
        let info = match ops.route_mtu(&address) {
            Some(route_mtu) => {
                let overhead = if destination.is_ipv4() {
                    IPV4_OVERHEAD
                } else {
                    IPV6_OVERHEAD
                };
                let datagram = self.max_datagram();
                // Two `u16` values always sum within `u32`; an overflow
                // would mean the datagram cannot fit any path.
                let needed = u32::from(datagram).checked_add(u32::from(overhead));
                if needed.is_none_or(|needed| needed > route_mtu) {
                    return Err(RouteError::PathTooSmall {
                        datagram,
                        overhead,
                        route_mtu,
                    });
                }
                RouteInfo {
                    route_mtu: Some(route_mtu),
                    path_mtu: CapabilityState::Active,
                }
            }
            None if self
                .config
                .require
                .contains(crate::backend::Capability::PathMtu) =>
            {
                return Err(RouteError::PathUnverified);
            }
            None => RouteInfo {
                route_mtu: None,
                path_mtu: CapabilityState::Fallback(Reason::Unverified),
            },
        };
        self.routes
            .insert(RouteEntry { address, info })
            .map_err(|error| match error {
                IssueError::Full => RouteError::RouteLimit,
                IssueError::IdentityExhausted => RouteError::IdentityExhausted,
            })
    }

    /// Removes `route`: `NotActive`, `Unknown`, then `InUse` while an open
    /// queue names it.
    pub(super) fn remove_route(&mut self, route: RouteId) -> Result<(), RouteError> {
        if !self.active() {
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

    /// The measurement of `route`.
    pub(super) fn route_info(&self, route: RouteId) -> Result<RouteInfo, RouteError> {
        self.routes
            .get(route)
            .map(|entry| entry.info)
            .ok_or(RouteError::Unknown)
    }

    // -----------------------------------------------------------------
    // Queues (3.3, 3.8, 6.3, 7.2)
    // -----------------------------------------------------------------

    /// Opens a queue: `NotActive`, `RouteUnknown`, then the ledger's
    /// `QueueLimit`, `OverCommitted` and `IdentityExhausted`.
    pub(super) fn open_queue(&mut self, config: TxQueueConfig) -> Result<TxQueueId, QueueError> {
        if !self.active() {
            return Err(QueueError::NotActive);
        }
        if self.routes.get(config.route).is_none() {
            return Err(QueueError::RouteUnknown);
        }
        let queue = self.ledger.open_queue(config)?;
        if let Some(run) = self.runs.get_mut(usize::from(queue.index())) {
            *run = QueueRun {
                id: Some(queue),
                ..IDLE_RUN
            };
        }
        Ok(queue)
    }

    /// Clears a send fault; an invariant fault gives `NeedsReset`. A queue
    /// that `close_queue` is closing is `UnknownQueue`. It does not clear a
    /// failure that stopped the half; only a reset does.
    pub(super) fn retry_queue(&mut self, queue: TxQueueId) -> Result<(), QueueError> {
        if !self.active() {
            return Err(QueueError::NotActive);
        }
        let run = self
            .run_mut(queue)
            .filter(|run| !run.closing)
            .ok_or(QueueError::UnknownQueue)?;
        match run.fault {
            Some(Fault::Invariant) => Err(QueueError::NeedsReset),
            Some(Fault::Send(_)) | None => {
                run.fault = None;
                Ok(())
            }
        }
    }

    /// Checks a report, the state and the handle for `cancel_pending` and
    /// `close_queue`, in this order.
    fn check_return(&self, queue: TxQueueId, report: &TxReport) -> Result<(), QueueError> {
        if !report.is_empty() {
            return Err(QueueError::ReportNotEmpty);
        }
        if !self.active() {
            return Err(QueueError::NotActive);
        }
        if self.run(queue).is_none() {
            return Err(QueueError::UnknownQueue);
        }
        Ok(())
    }

    /// Returns pending items of `queue` with `Cancelled` (7.2).
    pub(super) fn cancel_pending(
        &mut self,
        queue: TxQueueId,
        report: &mut TxReport,
    ) -> Result<CancelOutcome, QueueError> {
        self.check_return(queue, report)?;
        if self.closing(queue) {
            return Err(QueueError::UnknownQueue);
        }
        let Some(mut writer) = report.writer() else {
            return Err(QueueError::ReportNotEmpty);
        };
        let mut returned: u16 = 0;
        self.drain(queue, &mut writer, ReturnReason::Cancelled, &mut returned);
        let more = self.run(queue).is_some_and(|run| run.len > 0);
        Ok(CancelOutcome { returned, more })
    }

    /// Returns pending items of `queue` with `QueueClosed`; once none
    /// remains, closes it (7.2). While `more` is true the queue takes no
    /// claim, commit or flush.
    pub(super) fn close_queue(
        &mut self,
        queue: TxQueueId,
        report: &mut TxReport,
    ) -> Result<CancelOutcome, QueueError> {
        self.check_return(queue, report)?;
        let Some(mut writer) = report.writer() else {
            return Err(QueueError::ReportNotEmpty);
        };
        if let Some(run) = self.run_mut(queue) {
            run.closing = true;
        }
        let mut returned: u16 = 0;
        self.drain(queue, &mut writer, ReturnReason::QueueClosed, &mut returned);
        let more = self.run(queue).is_some_and(|run| run.len > 0);
        if !more {
            self.ledger.close_queue(queue)?;
            if let Some(run) = self.runs.get_mut(usize::from(queue.index())) {
                *run = IDLE_RUN;
            }
        }
        Ok(CancelOutcome { returned, more })
    }

    /// Pops the head of `queue`'s FIFO and returns it; `None` for an empty
    /// queue.
    ///
    /// Release build guard (S1 review N3): the head's metadata must name
    /// `queue`, carry a generation, and the queue must count it. Otherwise
    /// nothing changes and `None` comes back, so no ledger call can
    /// release, quarantine or discharge a slot on the wrong queue. Every
    /// check runs before the first change.
    fn pop_head(&mut self, queue: TxQueueId) -> Option<Item> {
        let run = *self.run(queue)?;
        if run.head == NO_SLOT {
            return None;
        }
        let (Some((item, next)), Some(len)) = (self.item(queue, run.head), run.len.checked_sub(1))
        else {
            self.broken("a queue's head is a pending slot of that queue, counted by it");
            return None;
        };
        if let Some(meta) = self.meta_mut(item.slot) {
            meta.queue = None;
            meta.next = NO_SLOT;
        }
        if let Some(run) = self.run_mut(queue) {
            run.head = next;
            if next == NO_SLOT {
                run.tail = NO_SLOT;
            }
            run.len = len;
        }
        Some(item)
    }

    /// Pops `slot`, which must be the head of `queue`; `false` changes
    /// nothing.
    fn pop_expected(&mut self, queue: TxQueueId, slot: u32) -> bool {
        if self.run(queue).is_none_or(|run| run.head != slot) {
            self.broken("a flush candidate is still its queue's head");
            return false;
        }
        self.pop_head(queue).is_some()
    }

    /// Returns head items of `queue` with `reason` while the report has
    /// room, adding to `returned`; the slots are Free again. The count is
    /// checked before each pop, so an item is never returned uncounted.
    fn drain(
        &mut self,
        queue: TxQueueId,
        writer: &mut ReportWriter<'_>,
        reason: ReturnReason,
        returned: &mut u16,
    ) {
        while writer.remaining() > 0 {
            // At most `TX_REPORT_CAPACITY` entries per call, so the count
            // fits; on `None` the item simply stays pending.
            let Some(count) = returned.checked_add(1) else {
                break;
            };
            let Some(item) = self.pop_head(queue) else {
                break;
            };
            if item.terminal {
                // Reported `Unknown` by the flush that could not pop it:
                // quarantined now, with no second report.
                let quarantined = self.ledger.quarantine(queue, item.slot);
                debug_assert!(quarantined, "a terminal item was pending");
                continue;
            }
            let released = self.ledger.release_pending(queue, item.slot);
            debug_assert!(released, "a returned item was pending");
            push(writer, item.entry(TxItemOutcome::Returned { reason }));
            *returned = count;
        }
    }

    /// Returns pending items of every queue, in queue index order, with
    /// `Reset` (7.3 and 7.4). Returns the count and whether items remain.
    pub(super) fn drain_all(&mut self, writer: &mut ReportWriter<'_>) -> (u16, bool) {
        let mut returned: u16 = 0;
        for index in 0..self.runs.len() {
            let Some(queue) = self.runs.get(index).and_then(|run| run.id) else {
                continue;
            };
            self.drain(queue, writer, ReturnReason::Reset, &mut returned);
        }
        (returned, self.pending_total() != Some(0))
    }

    /// Reset step 3 (7.3), once nothing is pending: closes every queue,
    /// invalidates every route and frees quarantined slots. Queue and
    /// route handles issued afterwards carry the epoch `reopen` moves to;
    /// when the epoch cannot advance, `reopen` fails and no handle is
    /// issued again.
    ///
    /// Release build guard (S1 review N3): refuses, changing nothing and
    /// returning `false`, while any item is pending, so the ledger never
    /// frees occupied capacity. Under the invariants `drain_all` empties
    /// every queue first, so only an injected fault reaches it.
    pub(super) fn finish_reset(&mut self) -> bool {
        if self.pending_total() != Some(0) {
            self.broken("a reset returns every item first");
            return false;
        }
        let next = self.epoch.next().unwrap_or(self.epoch);
        self.ledger.reset(next);
        self.routes.clear(next);
        self.runs.iter_mut().for_each(|run| *run = IDLE_RUN);
        true
    }

    // -----------------------------------------------------------------
    // Claim and commit (3.3)
    // -----------------------------------------------------------------

    /// Claims one slot of `len` bytes for `queue` (3.6 order).
    pub(super) fn claim(
        &mut self,
        queue: TxQueueId,
        len: usize,
    ) -> Result<SocketsFrame<'_>, ClaimError> {
        let active = self.active();
        if active && self.closing(queue) {
            return Err(ClaimError::UnknownQueue);
        }
        let claimed = self.ledger.claim(active, queue, len)?;
        Ok(SocketsFrame {
            core: self,
            queue,
            slot: claimed.slot,
            generation: claimed.generation,
            capacity: len,
            done: false,
        })
    }

    // -----------------------------------------------------------------
    // Flush (3.4, section 6)
    // -----------------------------------------------------------------

    /// One gate check and at most one exposure of `request.queue`'s head
    /// prefix; the order of 6.3.
    pub(super) fn flush<O: SocketOps, G: SenderGate>(
        &mut self,
        ops: &mut O,
        request: FlushRequest,
        gate: &mut G,
        report: &mut TxReport,
    ) -> FlushOutcome {
        // Step 1: refuse a non-empty report; validate; select.
        if !report.is_empty() {
            return stopped(FlushStop::ReportNotEmpty);
        }
        if !self.active() {
            return stopped(FlushStop::Queue(QueueError::NotActive));
        }
        // A half stopped by a failure makes no gate check and no system
        // call until the reset (3.10).
        if let Some(failure) = self.failed {
            return stopped(FlushStop::Failed(failure));
        }
        let queue = request.queue;
        let Some(account) = self.ledger.queues().get(queue) else {
            return stopped(FlushStop::Queue(QueueError::UnknownQueue));
        };
        let (authority, route) = (account.authority(), account.route());
        let Some(run) = self.run(queue).copied() else {
            return stopped(FlushStop::Queue(QueueError::UnknownQueue));
        };
        if run.closing {
            return stopped(FlushStop::Queue(QueueError::UnknownQueue));
        }
        match run.fault {
            Some(Fault::Invariant) => return stopped(FlushStop::Queue(QueueError::NeedsReset)),
            Some(Fault::Send(error)) => return stopped(FlushStop::Faulted(error)),
            None => {}
        }
        let Some(address) = self.routes.get(route).map(|entry| &entry.address) else {
            return stopped(FlushStop::Queue(QueueError::RouteUnknown));
        };
        if run.head == NO_SLOT {
            return stopped(FlushStop::QueueEmpty);
        }
        // Clamped to `max_batch` and the stack arrays; `BATCH` is at most
        // `TX_REPORT_CAPACITY`, so every candidate has a report entry.
        let limit = request
            .max_datagrams
            .get()
            .min(self.config.max_batch.get())
            .min(SOCKETS_MAX_BATCH);
        let mut items: [Option<Item>; BATCH] = [None; BATCH];
        let mut tokens = [SenderToken::new(0); BATCH];
        let mut lengths = [0_u16; BATCH];
        let mut offered: u16 = 0;
        let mut offered_bytes: u32 = 0;
        let mut cursor = run.head;
        while offered < limit && cursor != NO_SLOT {
            // Release build guard (S1 review N3): the FIFO links only
            // pending slots of this queue. Nothing has changed yet, so a
            // broken link faults the queue before the gate is called.
            let Some((item, next)) = self.item(queue, cursor) else {
                self.broken("a queue's FIFO links only its own pending slots");
                self.fault_invariant(queue);
                return stopped(FlushStop::Failed(BackendFailure::Invariant {
                    operation: FLUSH,
                }));
            };
            // `max_bytes` is inclusive: a prefix of exactly `max_bytes`
            // bytes is offered.
            let Some(bytes) = offered_bytes
                .checked_add(u32::from(item.len))
                .filter(|bytes| *bytes <= request.max_bytes)
            else {
                if offered == 0 {
                    return stopped(FlushStop::HeadExceedsBudget { head_len: item.len });
                }
                break;
            };
            let at = usize::from(offered);
            let (Some(next_offered), Some(slot), Some(token), Some(len)) = (
                offered.checked_add(1),
                items.get_mut(at),
                tokens.get_mut(at),
                lengths.get_mut(at),
            ) else {
                // Unreachable: `offered < limit <= BATCH`.
                break;
            };
            *slot = Some(item);
            *token = item.token;
            *len = item.len;
            offered = next_offered;
            offered_bytes = bytes;
            cursor = next;
        }
        let offered_at = usize::from(offered);
        let (Some(offered_tokens), Some(offered_lengths)) =
            (tokens.get(..offered_at), lengths.get(..offered_at))
        else {
            // Unreachable: `offered <= BATCH`. Nothing has changed.
            self.broken("the offered prefix fits the stack arrays");
            self.fault_invariant(queue);
            return stopped(FlushStop::Failed(BackendFailure::Invariant {
                operation: FLUSH,
            }));
        };

        // Step 2: the gate. Nothing has changed yet, so a panic here leaves
        // the endpoint as it was.
        let decision = gate.check(&Exposure {
            authority,
            route,
            epoch: self.epoch,
            tokens: offered_tokens,
            lengths: offered_lengths,
        });
        let Some(mut writer) = report.writer() else {
            return stopped(FlushStop::ReportNotEmpty);
        };
        let permitted = match decision {
            GateDecision::Deny => {
                report_pending(&mut writer, &items, 0, offered_at, PendingCause::GateDenied);
                return stopped(FlushStop::GateDenied);
            }
            // A broken gate: nothing is exposed (6.1). Every candidate is
            // reported `Pending { GateDenied }`: no exposure was permitted
            // in a form the backend can act on, so the items wait at the
            // head as after a denial, and the stop names the gate error.
            GateDecision::Permit { count } if count.get() > offered => {
                report_pending(&mut writer, &items, 0, offered_at, PendingCause::GateDenied);
                return stopped(FlushStop::GateError {
                    permitted: count.get(),
                    offered,
                });
            }
            GateDecision::Permit { count } => count.get(),
        };
        let permitted_at = usize::from(permitted);

        // Step 3: one exposure of the permitted prefix. The bytes are
        // checked before the call; a slot outside the pool or a byte count
        // that cannot be summed is an invariant fault with nothing sent.
        let exposed = items
            .get(..permitted_at)
            .and_then(|prefix| {
                prefix
                    .iter()
                    .try_fold(0_u32, |sum, item| sum.checked_add(u32::from((*item)?.len)))
            })
            .map(|bytes| {
                let mut datagrams: [&[u8]; BATCH] = [&[]; BATCH];
                for (datagram, item) in datagrams
                    .iter_mut()
                    .zip(items.iter().copied())
                    .take(permitted_at)
                {
                    match item.and_then(|item| self.slot_bytes(item.slot, usize::from(item.len))) {
                        Some(slot_bytes) => *datagram = slot_bytes,
                        None => return None,
                    }
                }
                let prefix = datagrams.get(..permitted_at)?;
                Some((bytes, ops.send(address, prefix)))
            });
        let Some(Some((exposed_bytes, result))) = exposed else {
            self.broken("the permitted prefix lies in the pool");
            self.fault_invariant(queue);
            let failure = BackendFailure::Invariant { operation: FLUSH };
            report_pending(
                &mut writer,
                &items,
                0,
                offered_at,
                PendingCause::Failed(failure),
            );
            return stopped(FlushStop::Failed(failure));
        };
        #[cfg(test)]
        self.inject_after_send(queue);
        // A single send count outside `1..=permitted` comes only with a
        // result `classify` already takes as outside the ABI; the flush
        // then fails as an invariant violation and `ops` reports the most
        // calls the single send path makes for one exposure.
        let ops = self.send_ops(result, permitted);
        let spent = Spent {
            datagrams: u32::from(permitted),
            bytes: u64::from(exposed_bytes),
            ops: ops.unwrap_or(u32::from(permitted)),
        };

        // Steps 4 and 5: slot states, the queue head, then the report.
        let (mut accepted, mut next) = self.classify(result, permitted_at);
        if ops.is_none() {
            next = Next::Unknown;
        }
        let mut submitted: u16 = 0;
        let mut submitted_bytes: u32 = 0;
        for (at, item) in items.iter().copied().take(accepted).enumerate() {
            let counts = submitted
                .checked_add(1)
                .zip(item.and_then(|item| submitted_bytes.checked_add(u32::from(item.len))));
            // An accepted item that cannot be popped or counted would stay
            // pending and be sent again: it and every later candidate of
            // the exposure become `Unknown` instead (6.3).
            let (Some(item), Some((count, bytes))) = (item, counts) else {
                self.broken("an accepted item is counted");
                (accepted, next) = (at, Next::Unknown);
                break;
            };
            if !self.pop_expected(queue, item.slot) {
                (accepted, next) = (at, Next::Unknown);
                break;
            }
            let released = self.ledger.release_pending(queue, item.slot);
            debug_assert!(released, "a submitted item was pending");
            submitted = count;
            submitted_bytes = bytes;
            push(
                &mut writer,
                item.entry(TxItemOutcome::Submitted {
                    release: Release::AtSubmission,
                }),
            );
        }
        let stop = match next {
            Next::Done => FlushStop::Exposed,
            Next::Pending { cause, stop, fault } => {
                // The first unaccepted item carries the cause; the items
                // behind it were not attempted.
                let unaccepted = items.get(accepted..permitted_at).unwrap_or_default();
                for (at, item) in unaccepted.iter().flatten().enumerate() {
                    let cause = if at == 0 {
                        cause
                    } else {
                        PendingCause::NotAttempted
                    };
                    push(&mut writer, item.entry(TxItemOutcome::Pending { cause }));
                }
                if let (Some(fault), Some(run)) = (fault, self.run_mut(queue)) {
                    run.fault = Some(fault);
                }
                stop
            }
            Next::Unknown => {
                let unproven = items.get(accepted..permitted_at).unwrap_or_default();
                for item in unproven.iter().flatten() {
                    // A slot that cannot be popped stays on its FIFO,
                    // marked terminal: its queue is faulted below, so it
                    // is never exposed again, and whatever pops it later
                    // (a reset, a cancel or a close) quarantines it without
                    // a second terminal report.
                    if self.pop_expected(queue, item.slot) {
                        let quarantined = self.ledger.quarantine(queue, item.slot);
                        debug_assert!(quarantined, "an unknown item was pending");
                    } else {
                        self.mark_terminal(item.slot);
                    }
                    push(&mut writer, item.entry(TxItemOutcome::Unknown));
                }
                self.fault_invariant(queue);
                FlushStop::Failed(BackendFailure::Invariant { operation: SEND })
            }
        };
        // Candidates the gate trimmed stay pending behind the exposure.
        report_pending(
            &mut writer,
            &items,
            permitted_at,
            offered_at,
            PendingCause::GateDenied,
        );
        FlushOutcome {
            submitted,
            bytes: submitted_bytes,
            spent,
            stop,
        }
    }

    /// Backend operations of one exposure (4.3, 5.3), counted by the
    /// endpoint from the send path of the epoch, which
    /// [`SocketOps::send`] documents: one `sendmmsg` when batching is
    /// active; otherwise single sends, one call per accepted datagram plus
    /// the call that failed, as they stop at the first error. `None` for a
    /// count the single send path cannot give (zero, above the request, or
    /// a result outside the ABI past the request): an invariant violation
    /// of the socket.
    fn send_ops(&self, result: SendResult, permitted: u16) -> Option<u32> {
        if self.batched {
            return Some(1);
        }
        let after = |count: usize| u16::try_from(count).ok()?.checked_add(1);
        let calls = match result {
            SendResult::Sent { sent, error: None } => u16::try_from(sent).ok(),
            SendResult::Sent {
                sent,
                error: Some(_),
            } => after(sent),
            SendResult::Error(_) => Some(1),
            SendResult::OutOfAbi { proven } => after(proven),
        };
        calls
            .filter(|calls| (1..=permitted).contains(calls))
            .map(u32::from)
    }

    /// Maps a send result over `permitted` items to the accepted prefix and
    /// what follows it (4.3, 4.7 and 6.3).
    fn classify(&mut self, result: SendResult, permitted: usize) -> (usize, Next) {
        match result {
            // A count above the request, a zero count without an error and
            // an error after a complete batch are outside the ABI; a zero
            // count proves nothing about the items.
            SendResult::Sent { sent, .. } if sent > permitted => (0, Next::Unknown),
            SendResult::Sent {
                sent: 0,
                error: None,
            } => (0, Next::Unknown),
            SendResult::Sent { sent, error: None } if sent == permitted => (sent, Next::Done),
            SendResult::Sent {
                sent,
                error: Some(_),
            } if sent == permitted => (sent, Next::Unknown),
            // A partial `sendmmsg` that lost the error of item `sent`: the
            // stop names the lost error rather than `Exposed`, which would
            // claim the whole permitted prefix (3.4, 4.3).
            SendResult::Sent { sent, error: None } => (
                sent,
                Next::Pending {
                    cause: PendingCause::ErrorLost,
                    stop: FlushStop::ErrorLost,
                    fault: None,
                },
            ),
            SendResult::Sent {
                sent,
                error: Some(errno),
            } => (sent, self.classify_errno(errno)),
            SendResult::Error(errno) => (0, self.classify_errno(errno)),
            SendResult::OutOfAbi { proven } => (proven.min(permitted), Next::Unknown),
        }
    }

    /// The send column of 4.7 for the first unaccepted item. A `Failed`
    /// result stops the half (3.10).
    fn classify_errno(&mut self, errno: Errno) -> Next {
        let raw = errno.raw();
        let pending = |cause: PendingCause, stop: FlushStop| Next::Pending {
            cause,
            stop,
            fault: None,
        };
        let faulted = |error: SendError| Next::Pending {
            cause: PendingCause::Faulted(error),
            stop: FlushStop::Faulted(error),
            fault: Some(Fault::Send(error)),
        };
        match errno {
            Errno::AGAIN => pending(PendingCause::WouldBlock, FlushStop::WouldBlock),
            Errno::INTR => pending(PendingCause::Interrupted, FlushStop::Interrupted),
            Errno::NOBUFS | Errno::NOMEM => pending(PendingCause::NoBuffers, FlushStop::NoBuffers),
            Errno::CONNREFUSED => {
                count_up(&mut self.peer_errors, &mut self.counter_overflows);
                pending(PendingCause::PeerError, FlushStop::PeerError)
            }
            Errno::MSGSIZE => faulted(SendError::MessageTooLarge),
            Errno::NETUNREACH | Errno::HOSTUNREACH | Errno::NETDOWN => {
                faulted(SendError::Unreachable { errno: raw })
            }
            Errno::ADDRNOTAVAIL => faulted(SendError::AddressUnavailable),
            Errno::PERM | Errno::ACCES => faulted(SendError::Denied { errno: raw }),
            Errno::BADF | Errno::NOTSOCK | Errno::FAULT | Errno::INVAL => {
                let failure = BackendFailure::Os {
                    operation: SEND,
                    errno: raw,
                };
                self.failed = Some(failure);
                pending(PendingCause::Failed(failure), FlushStop::Failed(failure))
            }
            _ => faulted(SendError::Other { errno: raw }),
        }
    }

    // -----------------------------------------------------------------
    // Test-only fault injection (S1 review N3)
    // -----------------------------------------------------------------

    /// Rewrites the owner recorded in the metadata of `queue`'s head to
    /// `owner`, as a corrupted FIFO link would, and marks the core as
    /// carrying an injected fault so the release build guards run without
    /// their debug assertions. Returns the head slot.
    #[cfg(test)]
    pub(super) fn inject_head_owner(
        &mut self,
        queue: TxQueueId,
        owner: Option<TxQueueId>,
    ) -> Option<u32> {
        self.injected = true;
        let head = self.run(queue)?.head;
        self.meta_mut(head)?.queue = owner;
        Some(head)
    }

    /// Arms [`Self::inject_head_owner`] for `queue` to run right after the
    /// next send call returns, so the flush's pops after the call meet a
    /// corrupted head.
    #[cfg(test)]
    pub(super) fn inject_head_owner_after_send(
        &mut self,
        queue: TxQueueId,
        owner: Option<TxQueueId>,
    ) {
        self.injected = true;
        self.after_send = Some((queue, owner));
    }

    /// Applies the injection armed by
    /// [`Self::inject_head_owner_after_send`] for `queue`.
    #[cfg(test)]
    fn inject_after_send(&mut self, queue: TxQueueId) {
        if let Some((armed, owner)) = self.after_send.take() {
            if armed == queue {
                self.inject_head_owner(queue, owner);
            } else {
                self.after_send = Some((armed, owner));
            }
        }
    }

    /// Clears the injection mark of [`Self::inject_head_owner`].
    #[cfg(test)]
    pub(super) fn clear_injection(&mut self) {
        self.injected = false;
    }

    /// Sets the last generation of `slot`, so its next claim overflows the
    /// generation counter and retires the slot (3.2 Identity).
    #[cfg(test)]
    pub(super) fn set_slot_generation(&mut self, slot: u32, generation: u64) {
        self.ledger.pool_mut().set_last_generation(slot, generation);
    }
}

impl Drop for TxCore {
    /// Memory safe in every state; not a shutdown path (S-19). A drop
    /// outside unwinding with pending items is a driver bug: counted, and
    /// asserted in debug builds.
    fn drop(&mut self) {
        let pending = self.pending_total();
        if pending != Some(0) && !std::thread::panicking() {
            // `usize` fits `u64` on every supported target. The process
            // counter is checked; the documented choice for overflow is
            // that it keeps its value, as no process discards 2^64 items.
            // A total that cannot be counted adds nothing and asserts below.
            let discarded = pending.and_then(|pending| u64::try_from(pending).ok());
            let mut current = TX_DISCARDED_ON_DROP.load(Ordering::Relaxed);
            while let Some(total) = discarded.and_then(|discarded| current.checked_add(discarded)) {
                match TX_DISCARDED_ON_DROP.compare_exchange_weak(
                    current,
                    total,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => current = actual,
                }
            }
            match pending {
                Some(pending) => debug_assert!(
                    self.injected(),
                    "a sockets TX half dropped with {pending} pending items; use reset or retire"
                ),
                None => debug_assert!(
                    self.injected(),
                    "a sockets TX half dropped with uncountable pending items; use reset or retire"
                ),
            }
        }
    }
}

/// A flush that changed nothing.
const fn stopped(stop: FlushStop) -> FlushOutcome {
    FlushOutcome {
        submitted: 0,
        bytes: 0,
        spent: Spent {
            datagrams: 0,
            bytes: 0,
            ops: 0,
        },
        stop,
    }
}

/// Reports the candidates `items[from..to]` as still pending with `cause`.
fn report_pending(
    writer: &mut ReportWriter<'_>,
    items: &[Option<Item>; BATCH],
    from: usize,
    to: usize,
    cause: PendingCause,
) {
    for item in items.get(from..to).unwrap_or_default().iter().flatten() {
        push(writer, item.entry(TxItemOutcome::Pending { cause }));
    }
}

/// Appends an entry; every caller bounds its entries by the report's
/// capacity.
fn push(writer: &mut ReportWriter<'_>, entry: TxEntry) {
    let pushed = writer.push(entry);
    debug_assert!(pushed.is_ok(), "a report has room for every candidate");
}

/// A claimed, private TX frame of the sockets backend. It borrows its TX
/// half; dropping it frees the slot and the queue charge.
#[derive(Debug)]
pub struct SocketsFrame<'a> {
    core: &'a mut TxCore,
    queue: TxQueueId,
    slot: u32,
    generation: NonZeroU64,
    capacity: usize,
    done: bool,
}

impl SocketsFrame<'_> {
    /// The queue the frame is charged to.
    #[must_use]
    pub fn queue(&self) -> TxQueueId {
        self.queue
    }

    /// Widens the frame past the pool, as a corrupted claim would, and
    /// marks the core as carrying an injected fault.
    #[cfg(test)]
    pub(super) fn inject_capacity(&mut self, capacity: usize) {
        self.core.injected = true;
        self.capacity = capacity;
    }
}

impl TxFrame for SocketsFrame<'_> {
    fn capacity(&self) -> usize {
        self.capacity
    }

    /// The claimed bytes. A claim outside the pool is an invariant
    /// violation: the queue is faulted (`NeedsReset`), the frame gets no
    /// bytes, and its commit is rejected.
    fn bytes_mut(&mut self) -> &mut [u8] {
        if self.core.slot_bytes_mut(self.slot, self.capacity).is_none() {
            self.core.broken("a claimed slot lies in the pool");
            self.core.fault_invariant(self.queue);
            return &mut [];
        }
        self.core
            .slot_bytes_mut(self.slot, self.capacity)
            .unwrap_or_default()
    }

    /// Commits the frame to the tail of its queue's FIFO.
    ///
    /// The new FIFO length is checked before any change. The ledger bounds
    /// it by `max_pending`, so a queue without a FIFO entry or a length
    /// that cannot grow is an invariant violation: the queue is faulted
    /// (`NeedsReset`) and the commit is rejected with `UnknownQueue`,
    /// returning the frame.
    fn commit(mut self, commit: Commit) -> Result<TxTicket, CommitRejected<Self>> {
        let core = &mut *self.core;
        let (queue, slot) = (self.queue, self.slot);
        let checked = core.ledger.check_commit(
            core.active(),
            queue,
            commit.len,
            self.capacity,
            commit.options,
        );
        let checked = match checked {
            Err(CommitError::NotActive) => Err(CommitError::NotActive),
            _ if core.closing(queue) => Err(CommitError::UnknownQueue),
            other => other,
        };
        let run_len = core.run(queue).and_then(|run| run.len.checked_add(1));
        let in_pool = core.slot_bytes_mut(slot, self.capacity).is_some();
        let checked = match (checked, run_len, in_pool) {
            (Ok(()), None, _) => {
                core.broken("an open queue's FIFO length can grow");
                core.fault_invariant(queue);
                Err(CommitError::UnknownQueue)
            }
            (Ok(()), _, false) => {
                core.broken("a claimed slot lies in the pool");
                core.fault_invariant(queue);
                Err(CommitError::UnknownQueue)
            }
            (checked, _, _) => checked,
        };
        let len = u16::try_from(commit.len);
        let (Ok(()), Ok(len), Some(run_len)) = (checked, len, run_len) else {
            let error = checked.err().unwrap_or(CommitError::LengthExceedsClaim {
                len: commit.len,
                capacity: self.capacity,
            });
            return Err(CommitRejected { frame: self, error });
        };
        let committed = core.ledger.pool_mut().commit(slot);
        debug_assert!(committed, "a claimed slot commits");
        if let Some(meta) = core.meta_mut(slot) {
            *meta = SlotMeta {
                queue: Some(queue),
                generation: Some(self.generation),
                token: commit.token,
                len,
                next: NO_SLOT,
                terminal: false,
            };
        }
        let tail = core.run(queue).map_or(NO_SLOT, |run| run.tail);
        if let Some(previous) = core.meta_mut(tail) {
            previous.next = slot;
        }
        if let Some(run) = core.run_mut(queue) {
            if run.head == NO_SLOT {
                run.head = slot;
            }
            run.tail = slot;
            run.len = run_len;
        }
        let ticket = TxTicket::new(SubmissionId::new(
            core.instance,
            core.epoch,
            slot,
            self.generation,
        ));
        self.done = true;
        Ok(ticket)
    }
}

impl Drop for SocketsFrame<'_> {
    fn drop(&mut self) {
        if !self.done {
            let released = self.core.ledger.release_claim(self.queue, self.slot);
            debug_assert!(released, "a dropped frame held a claim");
        }
    }
}
