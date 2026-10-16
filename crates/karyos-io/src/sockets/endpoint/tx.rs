// SPDX-License-Identifier: Apache-2.0

//! The TX state of one endpoint: slot bytes, the pending FIFO of each queue,
//! routes, claim and commit, flush and the returns of cancellation, close
//! and reset (`quantstratum-docs: karyos/design/sockets-backend.md` 3.3,
//! 3.4, 3.8, 4.3, 4.7, section 6 and 7.2).
//!
//! Pending queues are intrusive lists threaded through slot metadata
//! indices, so no queue allocates (5.1). Every allocation happens in
//! [`TxCore::new`], on the control path.

use std::num::NonZeroU64;
use std::sync::atomic::Ordering;

use super::config::{SOCKETS_MAX_BATCH, SocketsConfig};
use super::{State, TX_DISCARDED_ON_DROP};
use crate::backend::handles::{HandleTable, IssueError};
use crate::backend::ledger::TxLedger;
use crate::backend::{
    BackendEpoch, BackendFailure, CancelOutcome, CapabilityState, ClaimError, Commit, CommitError,
    CommitRejected, Exposure, FlushOutcome, FlushRequest, FlushStop, GateDecision, InstanceId,
    PendingCause, QueueError, Reason, Release, ReportWriter, ReturnReason, RouteError, RouteId,
    SendError, SenderGate, SenderToken, Spent, SubmissionId, TX_REPORT_CAPACITY, TxEntry, TxFrame,
    TxItemOutcome, TxQueueConfig, TxQueueId, TxReport, TxTicket,
};
use crate::sockets::ops::{Errno, RouteAddr, SendResult, SocketOps};

/// The end of a pending list.
const NO_SLOT: u32 = u32::MAX;
/// The stack arrays of one flush: at most this many candidates.
const BATCH: usize = SOCKETS_MAX_BATCH as usize;
/// The operation named in send failures.
const SEND: &str = "send";
/// UDP header bytes (4.5).
const UDP_HEADER: u16 = 8;
/// IPv4 header bytes without options (4.5).
const IPV4_HEADER: u16 = 20;
/// IPv6 header bytes without extension headers (4.5).
const IPV6_HEADER: u16 = 40;

/// The result of `add_route`'s measurement, per route (3.8 and 4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInfo {
    /// The measured route MTU, or `None` when it could not be measured.
    pub route_mtu: Option<u32>,
    /// `Active` when measured, `Fallback(Unverified)` otherwise.
    pub path_mtu: CapabilityState,
}

#[derive(Debug, Clone, Copy)]
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
}

const EMPTY_META: SlotMeta = SlotMeta {
    queue: None,
    generation: None,
    token: SenderToken::new(0),
    len: 0,
    next: NO_SLOT,
};

/// Why a queue is faulted (6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The head failed with a send error; `retry_queue` clears it.
    Send(SendError),
    /// A result outside the ABI; only a reset clears it (S-16).
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
}

impl TxCore {
    /// Allocates the pool, its metadata and the tables for a validated
    /// configuration.
    pub(super) fn new(config: &SocketsConfig, instance: InstanceId, epoch: BackendEpoch) -> Self {
        let slots = usize::from(config.tx_slots.get());
        let pool_bytes = slots.saturating_mul(usize::from(config.max_datagram.get()));
        Self {
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
        }
    }

    /// Moves to the new epoch of `reopen`; the sizes are unchanged.
    pub(super) fn reopen(&mut self, config: &SocketsConfig, epoch: BackendEpoch) {
        self.epoch = epoch;
        self.config = *config;
        self.state = State::Active;
    }

    fn active(&self) -> bool {
        self.state == State::Active
    }

    fn max_datagram(&self) -> u16 {
        self.config.max_datagram.get()
    }

    /// `ECONNREFUSED` results of send calls (4.7).
    pub(super) fn peer_errors(&self) -> u64 {
        self.peer_errors
    }

    /// Pending items over every open queue.
    pub(super) fn pending_total(&self) -> usize {
        self.runs.iter().map(|run| usize::from(run.len)).sum()
    }

    /// Whether `ticket` names an item that is pending now: same instance,
    /// epoch, slot and generation.
    pub(super) fn is_pending(&self, ticket: TxTicket) -> bool {
        let id = ticket.id();
        id.instance() == self.instance
            && id.epoch() == self.epoch
            && self.meta(id.slot()).is_some_and(|meta| {
                meta.queue.is_some() && meta.generation == Some(id.generation())
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

    /// The byte range of `slot` in the pool, `len` bytes long.
    fn range(&self, slot: u32, len: usize) -> Option<std::ops::Range<usize>> {
        let start = usize::try_from(slot)
            .ok()?
            .checked_mul(usize::from(self.max_datagram()))?;
        Some(start..start.checked_add(len)?)
    }

    fn slot_bytes(&self, slot: u32, len: usize) -> &[u8] {
        self.range(slot, len)
            .and_then(|range| self.bytes.get(range))
            .unwrap_or_default()
    }

    fn slot_bytes_mut(&mut self, slot: u32, len: usize) -> &mut [u8] {
        match self.range(slot, len) {
            Some(range) => self.bytes.get_mut(range).unwrap_or_default(),
            None => Default::default(),
        }
    }

    fn ticket(&self, slot: u32) -> TxTicket {
        let generation = self
            .meta(slot)
            .and_then(|meta| meta.generation)
            .unwrap_or(NonZeroU64::MIN);
        TxTicket::new(SubmissionId::new(
            self.instance,
            self.epoch,
            slot,
            generation,
        ))
    }

    // -----------------------------------------------------------------
    // Routes (3.8, 4.5)
    // -----------------------------------------------------------------

    /// Adds a route to `destination`, checked in this order: `NotActive`,
    /// `Unsupported`, `FamilyMismatch`, `RouteLimit`; then the route MTU,
    /// which gives `PathTooSmall` or `PathUnverified`; then the generation
    /// counter (`IdentityExhausted`).
    pub(super) fn add_route<O: SocketOps>(
        &mut self,
        ops: &mut O,
        destination: std::net::SocketAddr,
    ) -> Result<RouteId, RouteError> {
        if !self.active() {
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
                let ip_header = if destination.is_ipv4() {
                    IPV4_HEADER
                } else {
                    IPV6_HEADER
                };
                let overhead = UDP_HEADER.saturating_add(ip_header);
                let datagram = self.max_datagram();
                let needed = u32::from(datagram).saturating_add(u32::from(overhead));
                if needed > route_mtu {
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

    /// Clears a send fault; an invariant fault gives `NeedsReset`.
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
        let returned = self.drain(queue, &mut writer, ReturnReason::Cancelled);
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
        let returned = self.drain(queue, &mut writer, ReturnReason::QueueClosed);
        let more = self.run(queue).is_some_and(|run| run.len > 0);
        if !more {
            self.ledger.close_queue(queue)?;
            if let Some(run) = self.runs.get_mut(usize::from(queue.index())) {
                *run = IDLE_RUN;
            }
        }
        Ok(CancelOutcome { returned, more })
    }

    /// Pops the head of `queue`'s FIFO and returns its slot.
    ///
    /// The slot's metadata names the queue that owns it; a head owned by
    /// another queue is never popped, so no ledger call can release,
    /// quarantine or discharge a slot on the wrong queue, in release builds
    /// as well (S1 review N3).
    fn pop_head(&mut self, queue: TxQueueId) -> Option<u32> {
        let head = self.run(queue)?.head;
        let meta = self.meta_mut(head)?;
        if meta.queue != Some(queue) {
            debug_assert!(false, "a queue's head is owned by that queue");
            return None;
        }
        let next = meta.next;
        meta.queue = None;
        meta.next = NO_SLOT;
        let run = self.run_mut(queue)?;
        run.head = next;
        if next == NO_SLOT {
            run.tail = NO_SLOT;
        }
        run.len = run.len.saturating_sub(1);
        Some(head)
    }

    /// Returns head items of `queue` with `reason` while the report has
    /// room; the slots are Free again.
    fn drain(
        &mut self,
        queue: TxQueueId,
        writer: &mut ReportWriter<'_>,
        reason: ReturnReason,
    ) -> u16 {
        let mut returned: u16 = 0;
        while writer.remaining() > 0 {
            let Some(slot) = self.pop_head(queue) else {
                break;
            };
            let entry = self.entry(slot, TxItemOutcome::Returned { reason });
            let released = self.ledger.release_pending(queue, slot);
            debug_assert!(released, "a returned item was pending");
            push(writer, entry);
            returned = returned.saturating_add(1);
        }
        returned
    }

    /// Returns pending items of every queue, in queue index order, with
    /// `Reset` (7.3 and 7.4). Returns the count and whether items remain.
    pub(super) fn drain_all(&mut self, writer: &mut ReportWriter<'_>) -> (u16, bool) {
        let mut returned: u16 = 0;
        for index in 0..self.runs.len() {
            let Some(queue) = self.runs.get(index).and_then(|run| run.id) else {
                continue;
            };
            returned = returned.saturating_add(self.drain(queue, writer, ReturnReason::Reset));
        }
        (returned, self.pending_total() > 0)
    }

    /// Reset step 3 (7.3), once nothing is pending: closes every queue,
    /// invalidates every route and frees quarantined slots. Queue and
    /// route handles issued afterwards carry the epoch `reopen` moves to;
    /// when the epoch cannot advance, `reopen` fails and no handle is
    /// issued again. Refuses, changing nothing and returning `false`, while
    /// any item is pending, so the ledger never frees occupied capacity.
    pub(super) fn finish_reset(&mut self) -> bool {
        if self.pending_total() > 0 {
            debug_assert!(false, "a reset returns every item first");
            return false;
        }
        let next = self.epoch.next().unwrap_or(self.epoch);
        self.ledger.reset(next);
        self.routes.clear(next);
        self.runs.iter_mut().for_each(|run| *run = IDLE_RUN);
        true
    }

    fn entry(&self, slot: u32, outcome: TxItemOutcome) -> TxEntry {
        let (token, len) = self
            .meta(slot)
            .map_or((SenderToken::new(0), 0), |meta| (meta.token, meta.len));
        TxEntry {
            ticket: self.ticket(slot),
            token,
            len,
            outcome,
        }
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
        let Some(account) = self.ledger.queues().get(request.queue) else {
            return stopped(FlushStop::Queue(QueueError::UnknownQueue));
        };
        let (authority, route) = (account.authority(), account.route());
        let Some(run) = self.run(request.queue).copied() else {
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
        let Some(address) = self.routes.get(route).map(|entry| entry.address) else {
            return stopped(FlushStop::Queue(QueueError::RouteUnknown));
        };
        if run.head == NO_SLOT {
            return stopped(FlushStop::QueueEmpty);
        }
        let limit = usize::from(request.max_datagrams.get())
            .min(usize::from(self.config.max_batch.get()))
            .min(TX_REPORT_CAPACITY)
            .min(BATCH);
        let mut slots = [NO_SLOT; BATCH];
        let mut tokens = [SenderToken::new(0); BATCH];
        let mut lengths = [0_u16; BATCH];
        let mut offered = 0_usize;
        let mut offered_bytes = 0_u32;
        let mut cursor = run.head;
        while offered < limit {
            let Some(meta) = self
                .meta(cursor)
                .filter(|meta| meta.queue == Some(request.queue))
            else {
                break;
            };
            let Some(bytes) = offered_bytes
                .checked_add(u32::from(meta.len))
                .filter(|bytes| *bytes <= request.max_bytes)
            else {
                if offered == 0 {
                    return stopped(FlushStop::HeadExceedsBudget { head_len: meta.len });
                }
                break;
            };
            if let (Some(slot), Some(token), Some(len)) = (
                slots.get_mut(offered),
                tokens.get_mut(offered),
                lengths.get_mut(offered),
            ) {
                *slot = cursor;
                *token = meta.token;
                *len = meta.len;
            }
            offered = offered.saturating_add(1);
            offered_bytes = bytes;
            cursor = meta.next;
        }
        let offered16 = u16::try_from(offered).unwrap_or(u16::MAX);

        // Step 2: the gate. Nothing has changed yet, so a panic here leaves
        // the endpoint as it was.
        let decision = gate.check(&Exposure {
            authority,
            route,
            epoch: self.epoch,
            tokens: tokens.get(..offered).unwrap_or_default(),
            lengths: lengths.get(..offered).unwrap_or_default(),
        });
        let Some(mut writer) = report.writer() else {
            return stopped(FlushStop::ReportNotEmpty);
        };
        let permitted = match decision {
            GateDecision::Deny => {
                self.report_pending(&mut writer, &slots, 0, offered, PendingCause::GateDenied);
                return stopped(FlushStop::GateDenied);
            }
            GateDecision::Permit { count } if usize::from(count.get()) > offered => {
                self.report_pending(&mut writer, &slots, 0, offered, PendingCause::GateDenied);
                return stopped(FlushStop::GateError {
                    permitted: count.get(),
                    offered: offered16,
                });
            }
            GateDecision::Permit { count } => usize::from(count.get()),
        };

        // Step 3: one exposure of the permitted prefix.
        let mut exposed_bytes = 0_u32;
        let result = {
            let mut datagrams: [&[u8]; BATCH] = [&[]; BATCH];
            for (at, datagram) in datagrams.iter_mut().enumerate().take(permitted) {
                let (slot, len) = (
                    slots.get(at).copied().unwrap_or(NO_SLOT),
                    lengths.get(at).copied().unwrap_or(0),
                );
                *datagram = self.slot_bytes(slot, usize::from(len));
                exposed_bytes = exposed_bytes.saturating_add(u32::from(len));
            }
            ops.send(&address, datagrams.get(..permitted).unwrap_or_default())
        };
        let spent = Spent {
            datagrams: u32::try_from(permitted).unwrap_or(u32::MAX),
            bytes: u64::from(exposed_bytes),
            ops: 1,
        };

        // Steps 4 and 5: slot states, the queue head, then the report.
        let (accepted, next) = self.classify(result, permitted);
        let mut submitted: u16 = 0;
        let mut submitted_bytes: u32 = 0;
        for _ in 0..accepted {
            let Some(slot) = self.pop_head(request.queue) else {
                break;
            };
            let entry = self.entry(
                slot,
                TxItemOutcome::Submitted {
                    release: Release::AtSubmission,
                },
            );
            let released = self.ledger.release_pending(request.queue, slot);
            debug_assert!(released, "a submitted item was pending");
            submitted = submitted.saturating_add(1);
            submitted_bytes = submitted_bytes.saturating_add(u32::from(entry.len));
            push(&mut writer, entry);
        }
        let stop = match next {
            Next::Done => FlushStop::Exposed,
            Next::Pending { cause, stop, fault } => {
                self.report_pending(
                    &mut writer,
                    &slots,
                    accepted,
                    accepted.saturating_add(1),
                    cause,
                );
                self.report_pending(
                    &mut writer,
                    &slots,
                    accepted.saturating_add(1),
                    permitted,
                    PendingCause::NotAttempted,
                );
                if let (Some(fault), Some(run)) = (fault, self.run_mut(request.queue)) {
                    run.fault = Some(fault);
                }
                stop
            }
            Next::Unknown => {
                for _ in accepted..permitted {
                    let Some(slot) = self.pop_head(request.queue) else {
                        break;
                    };
                    let entry = self.entry(slot, TxItemOutcome::Unknown);
                    let quarantined = self.ledger.quarantine(request.queue, slot);
                    debug_assert!(quarantined, "an unknown item was pending");
                    push(&mut writer, entry);
                }
                if let Some(run) = self.run_mut(request.queue) {
                    run.fault = Some(Fault::Invariant);
                }
                FlushStop::Failed(BackendFailure::Invariant { operation: SEND })
            }
        };
        // Candidates the gate trimmed stay pending behind the exposure.
        self.report_pending(
            &mut writer,
            &slots,
            permitted,
            offered,
            PendingCause::GateDenied,
        );
        FlushOutcome {
            submitted,
            bytes: submitted_bytes,
            spent,
            stop,
        }
    }

    /// Reports `slots[from..to]` as still pending with `cause`.
    fn report_pending(
        &self,
        writer: &mut ReportWriter<'_>,
        slots: &[u32; BATCH],
        from: usize,
        to: usize,
        cause: PendingCause,
    ) {
        for slot in slots.get(from..to).unwrap_or_default() {
            push(writer, self.entry(*slot, TxItemOutcome::Pending { cause }));
        }
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
            SendResult::Sent { sent, error: None } => (
                sent,
                Next::Pending {
                    cause: PendingCause::ErrorLost,
                    stop: FlushStop::Exposed,
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

    /// The send column of 4.7 for the first unaccepted item.
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
                self.peer_errors = self.peer_errors.saturating_add(1);
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
                pending(PendingCause::Failed(failure), FlushStop::Failed(failure))
            }
            _ => faulted(SendError::Other { errno: raw }),
        }
    }
}

impl Drop for TxCore {
    /// Memory safe in every state; not a shutdown path (S-19). A drop
    /// outside unwinding with pending items is a driver bug: counted, and
    /// asserted in debug builds.
    fn drop(&mut self) {
        let pending = self.pending_total();
        if pending > 0 && !std::thread::panicking() {
            TX_DISCARDED_ON_DROP.fetch_add(
                u64::try_from(pending).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            debug_assert!(
                pending == 0,
                "a sockets TX half dropped with {pending} pending items; use reset or retire"
            );
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
}

impl TxFrame for SocketsFrame<'_> {
    fn capacity(&self) -> usize {
        self.capacity
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.core.slot_bytes_mut(self.slot, self.capacity)
    }

    fn commit(mut self, commit: Commit) -> Result<TxTicket, CommitRejected<Self>> {
        let core = &mut *self.core;
        let checked = core.ledger.check_commit(
            core.active(),
            self.queue,
            commit.len,
            self.capacity,
            commit.options,
        );
        let checked = match checked {
            Err(CommitError::NotActive) => Err(CommitError::NotActive),
            _ if core.closing(self.queue) => Err(CommitError::UnknownQueue),
            other => other,
        };
        let len = u16::try_from(commit.len);
        let (Ok(()), Ok(len)) = (checked, len) else {
            let error = checked.err().unwrap_or(CommitError::LengthExceedsClaim {
                len: commit.len,
                capacity: self.capacity,
            });
            return Err(CommitRejected { frame: self, error });
        };
        let committed = core.ledger.pool_mut().commit(self.slot);
        debug_assert!(committed, "a claimed slot commits");
        let (queue, slot) = (self.queue, self.slot);
        if let Some(meta) = core.meta_mut(slot) {
            *meta = SlotMeta {
                queue: Some(queue),
                generation: Some(self.generation),
                token: commit.token,
                len,
                next: NO_SLOT,
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
            run.len = run.len.saturating_add(1);
        }
        self.done = true;
        Ok(self.core.ticket(slot))
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
