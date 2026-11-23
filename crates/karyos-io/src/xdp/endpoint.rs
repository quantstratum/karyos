// SPDX-License-Identifier: Apache-2.0

//! The AF_XDP copy-mode endpoint over the [`XskOps`] seam
//! (`quantstratum-docs: karyos/design/af-xdp-backend.md` sections 6 to 9
//! and 11): one socket, one queue of one interface, one owned UMEM.
//!
//! **TX (7).** `claim_tx` and `commit` as the sockets backend does, over
//! the shared ledger; the payload region of a frame starts after the
//! Ethernet, IP and UDP headers. A flush makes one gate check, writes the
//! headers and one descriptor per permitted item, publishes them with one
//! producer store (the exposure point), reports them `Submitted { release:
//! Deferred }` and kicks once, nonblocking, when the ring asks for it.
//!
//! **Completions (7.5).** Only [`Completion::Released`] of a Submitted
//! item releases it: the backend emits `TxEvent::Released` and no send
//! result, which AF_XDP does not give. Any other completion is the
//! invariant `xsk_completion`: nothing is released, every Submitted item
//! is quarantined and the endpoint stops until it is retired.
//!
//! **RX (8).** Descriptors are reaped one at a time within the budget;
//! each frame's headers are validated (8.2) and its UDP payload lent to
//! the handler, and the frame goes back to the fill ring when the lend
//! returns or unwinds. Wakeups are nonblocking (`recvfrom` with
//! `MSG_DONTWAIT`), never `poll(2)`.
//!
//! **Teardown (11.2, 11.3).** [`XdpEndpoint::retire`] returns Pending
//! items, reports every Submitted item that has not completed `Unknown`
//! (it may or may not have been sent), and then drops the socket core in
//! the order rings, socket, UMEM; [`Teardown`] counts what was released.
//!
//! Deferred, and not implemented: busy polling, NUMA placement, zero
//! copy and multi-buffer frames (owner item 3).

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU64};
use std::ops::ControlFlow;

use super::headers::{self, Addressing, Checked};
use super::ops::{Completion, RxDesc, XskOps};
use crate::backend::handles::{HandleTable, IssueError};
use crate::backend::ledger::TxLedger;
use crate::backend::{
    BackendEpoch, BackendFailure, Budget, CancelOutcome, ClaimError, Commit, CommitError,
    CommitRejected, CompletionHandler, CompletionOutcome, Exposure, FlushOutcome, FlushRequest,
    FlushStop, GateDecision, InstanceId, OpenError, PathId, PendingCause, QueueError, Release,
    ReportWriter, ReturnReason, RouteError, RouteId, RxBackend, RxDatagram, RxDrop, RxHandler,
    RxOutcome, RxStop, SenderGate, SenderToken, Spent, SubmissionId, TX_REPORT_CAPACITY, TxBackend,
    TxEntry, TxEvent, TxFrame, TxItemOutcome, TxQueueConfig, TxQueueId, TxReport, TxTicket,
};

const NO_SLOT: u32 = u32::MAX;
/// Candidates of one flush at most.
pub const XDP_MAX_BATCH: u16 = 64;
const BATCH: usize = XDP_MAX_BATCH as usize;
const _: () = assert!(BATCH <= TX_REPORT_CAPACITY);
const REAP: usize = 64;
const COMPLETION: &str = "xsk_completion";
const KICK: &str = "xsk_sendto";
/// `XDP_PACKET_HEADROOM`: bytes the kernel keeps before each RX packet.
pub const RX_HEADROOM: usize = 256;

/// The configuration of one endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpEndpointConfig {
    /// The endpoint's address and port; every route has its family.
    pub local: SocketAddr,
    /// The interface's MAC, from sysfs.
    pub local_mac: [u8; 6],
    /// The interface MTU, from sysfs.
    pub mtu: u32,
    /// The datagram limit in bytes.
    pub max_datagram: NonZeroU16,
    /// Open queues at most.
    pub max_queues: NonZeroU16,
    /// Routes at most.
    pub max_routes: NonZeroU16,
    /// Datagrams one flush exposes at most.
    pub max_batch: NonZeroU16,
    /// TTL or hop limit of sent datagrams.
    pub hop_limit: u8,
    /// The path of received datagrams.
    pub path: PathId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Free,
    Claimed,
    Pending,
    Submitted,
    Quarantined,
    /// Reported `Unknown` by `retire`; terminal.
    Reported,
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

#[derive(Debug, Clone, Copy)]
struct Run {
    id: Option<TxQueueId>,
    head: u32,
    tail: u32,
    len: u16,
}

const IDLE_RUN: Run = Run {
    id: None,
    head: NO_SLOT,
    tail: NO_SLOT,
    len: 0,
};

/// One route: the destination and its next hop MAC (design 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteEntry {
    addressing: Addressing,
}

/// The counters of one endpoint; every increment saturates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XdpCounters {
    /// Completions that named no Submitted frame.
    pub invalid_completions: u64,
    /// RX descriptors outside a Posted frame.
    pub invalid_rx: u64,
    /// Frames dropped by header validation.
    pub rx_dropped: u64,
    /// Kicks that returned `EBUSY` (`xdp_tx_dropped`).
    pub tx_dropped: u64,
    /// TX kicks.
    pub tx_kicks: u64,
    /// RX wakeups.
    pub rx_kicks: u64,
}

/// What [`XdpEndpoint::retire`] established (design 11.2 and 11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Teardown {
    /// Pending items were returned and more remain: empty the report and
    /// call again.
    More {
        /// Items returned by this call.
        returned: u16,
    },
    /// Done: the socket core is dropped.
    Complete {
        /// Items returned by this call.
        returned: u16,
        /// Submitted items without a completion, reported `Unknown`.
        unknown: u16,
        /// TX frames the kernel owned when the socket closed.
        kernel_owned_frames: u16,
    },
    /// The report still held entries; nothing changed.
    ReportNotEmpty,
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The AF_XDP copy-mode endpoint.
#[derive(Debug)]
pub struct XdpEndpoint<O: XskOps> {
    instance: InstanceId,
    epoch: BackendEpoch,
    config: XdpEndpointConfig,
    header: usize,
    xsk: Option<O>,
    ledger: TxLedger,
    slots: Box<[SlotMeta]>,
    runs: Box<[Run]>,
    routes: HandleTable<RouteId, RouteEntry>,
    counters: XdpCounters,
    failed: Option<BackendFailure>,
    /// `retire` has started: no claim, commit, flush, route or queue.
    retiring: bool,
}

impl<O: XskOps> XdpEndpoint<O> {
    /// Checks `config` against `xsk` (design 6.1: the datagram and its
    /// headers fit the MTU and the frame) and allocates every table.
    ///
    /// # Errors
    ///
    /// [`OpenError::InvalidConfig`] naming the field.
    pub fn open(
        config: XdpEndpointConfig,
        instance: InstanceId,
        xsk: O,
    ) -> Result<Self, OpenError> {
        let header = headers::header_len(&config.local);
        let datagram = usize::from(config.max_datagram.get());
        let frame = usize::try_from(xsk.frame_len()).unwrap_or(0);
        let mtu = usize::try_from(config.mtu).unwrap_or(0);
        let total = datagram.saturating_add(header);
        // The kernel reserves `XDP_PACKET_HEADROOM` before each RX frame
        // (design 6.1), so a frame holds `F - 256` bytes of packet.
        if total > frame.saturating_sub(RX_HEADROOM) || total > mtu.saturating_add(headers::ETH) {
            return Err(OpenError::InvalidConfig {
                field: "max_datagram",
                value: u64::from(config.max_datagram.get()),
            });
        }
        if config.max_batch.get() > XDP_MAX_BATCH {
            return Err(OpenError::InvalidConfig {
                field: "max_batch",
                value: u64::from(config.max_batch.get()),
            });
        }
        let tx_slots = NonZeroU16::new(xsk.tx_frames()).ok_or(OpenError::InvalidConfig {
            field: "tx_frames",
            value: 0,
        })?;
        let epoch = BackendEpoch::FIRST;
        Ok(Self {
            instance,
            epoch,
            config,
            header,
            ledger: TxLedger::new(tx_slots, config.max_queues, config.max_datagram, epoch),
            slots: vec![FREE_META; usize::from(tx_slots.get())].into_boxed_slice(),
            runs: vec![IDLE_RUN; usize::from(config.max_queues.get())].into_boxed_slice(),
            routes: HandleTable::new(config.max_routes, epoch),
            xsk: Some(xsk),
            counters: XdpCounters::default(),
            failed: None,
            retiring: false,
        })
    }

    /// The socket core, while it is open.
    #[must_use]
    pub fn xsk(&self) -> Option<&O> {
        self.xsk.as_ref()
    }

    /// The socket core, mutably: tests script the rings through it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn xsk_mut(&mut self) -> Option<&mut O> {
        self.xsk.as_mut()
    }

    /// The endpoint's counters.
    #[must_use]
    pub fn counters(&self) -> XdpCounters {
        self.counters
    }

    /// The failure that stopped the endpoint, if any.
    #[must_use]
    pub fn failure(&self) -> Option<BackendFailure> {
        self.failed
    }

    /// Items Submitted and not completed.
    #[must_use]
    pub fn submitted(&self) -> usize {
        self.slots
            .iter()
            .filter(|meta| meta.phase == Phase::Submitted)
            .count()
    }

    /// Adds a route to `destination` through the next hop MAC `next_hop`
    /// (resolved by the control path, design 7.2).
    ///
    /// # Errors
    ///
    /// `NotActive`, `Unsupported` (unspecified address or port 0),
    /// `FamilyMismatch`, `RouteLimit`, `IdentityExhausted`.
    pub fn add_route(
        &mut self,
        destination: SocketAddr,
        next_hop: [u8; 6],
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
        let addressing = Addressing {
            source_mac: self.config.local_mac,
            destination_mac: next_hop,
            source: self.config.local,
            destination,
            hop_limit: self.config.hop_limit,
        };
        self.routes
            .insert(RouteEntry { addressing })
            .map_err(|error| match error {
                IssueError::Full => RouteError::RouteLimit,
                IssueError::IdentityExhausted => RouteError::IdentityExhausted,
            })
    }

    /// Opens a bounded FIFO queue of one authority and one route.
    ///
    /// # Errors
    ///
    /// `NotActive`, `RouteUnknown`, then the ledger's errors.
    pub fn open_queue(&mut self, config: TxQueueConfig) -> Result<TxQueueId, QueueError> {
        if !self.active() {
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
                let _ = self.ledger.close_queue(id);
                Err(QueueError::QueueLimit)
            }
        }
    }

    /// Returns every Pending item with `ReturnReason::Reset`, reports every
    /// Submitted item without a completion `Unknown`, then closes the
    /// socket core (rings, socket, UMEM, in that order). Call while it
    /// returns [`Teardown::More`].
    pub fn retire(&mut self, report: &mut TxReport) -> Teardown {
        let Some(mut writer) = report.writer() else {
            return Teardown::ReportNotEmpty;
        };
        self.retiring = true;
        let mut returned: u16 = 0;
        for index in 0..self.runs.len() {
            let (count, more) = self.return_pending(index, ReturnReason::Reset, &mut writer);
            returned = returned.saturating_add(count);
            if more {
                return Teardown::More { returned };
            }
        }
        let mut unknown: u16 = 0;
        for slot in 0..self.slots.len() {
            let Some(meta) = self.slots.get(slot).copied() else {
                break;
            };
            // Submitted items without a completion, and items quarantined by
            // an invalid completion, end `Unknown` (11.2 step 5).
            if !matches!(meta.phase, Phase::Submitted | Phase::Quarantined) {
                continue;
            }
            if writer.remaining() == 0 {
                return Teardown::More { returned };
            }
            if let Some(entry) = u32::try_from(slot)
                .ok()
                .and_then(|slot| self.entry(slot, meta, TxItemOutcome::Unknown))
                && writer.push(entry).is_err()
            {
                return Teardown::More { returned };
            }
            if let Some(slot_meta) = self.slots.get_mut(slot) {
                slot_meta.phase = Phase::Reported;
            }
            unknown = unknown.saturating_add(1);
        }
        let kernel_owned_frames = self.xsk.as_ref().map_or(0, XskOps::tx_kernel_owned);
        // Rings, then socket, then UMEM: the declaration order of the core.
        self.xsk = None;
        self.failed = Some(BackendFailure::NotActive);
        Teardown::Complete {
            returned,
            unknown,
            kernel_owned_frames,
        }
    }

    /// Whether claims, commits, flushes, routes and queues are accepted.
    fn active(&self) -> bool {
        self.xsk.is_some() && self.failed.is_none() && !self.retiring
    }

    /// The endpoint's own state was found broken (a report entry or a
    /// ledger charge it promised): it stops until retired.
    fn broken(&mut self) {
        bump(&mut self.counters.invalid_completions);
        self.failed.get_or_insert(BackendFailure::Invariant {
            operation: "xdp_tx_state",
        });
    }

    fn run_index(&self, queue: TxQueueId) -> Option<usize> {
        let index = usize::from(queue.index());
        (self.runs.get(index)?.id == Some(queue)).then_some(index)
    }

    fn id(&self, slot: u32, meta: SlotMeta) -> Option<SubmissionId> {
        Some(SubmissionId::new(
            self.instance,
            self.epoch,
            slot,
            meta.generation?,
        ))
    }

    fn entry(&self, slot: u32, meta: SlotMeta, outcome: TxItemOutcome) -> Option<TxEntry> {
        Some(TxEntry {
            ticket: TxTicket::new(self.id(slot, meta)?),
            token: meta.token,
            len: meta.len,
            outcome,
        })
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
            let Some(queue) = run.id else {
                return (returned, false);
            };
            if run.len == 0 {
                return (returned, false);
            }
            if writer.remaining() == 0 {
                return (returned, true);
            }
            let Some((slot, meta)) = self.pop_head(index) else {
                return (returned, false);
            };
            if let Some(entry) = self.entry(slot, meta, TxItemOutcome::Returned { reason })
                && writer.push(entry).is_err()
            {
                self.broken();
            }
            if let Some(slot_meta) = self.slots.get_mut(slot as usize) {
                *slot_meta = SlotMeta {
                    generation: meta.generation,
                    ..FREE_META
                };
            }
            if !self.ledger.release_pending(queue, slot) {
                self.broken();
            }
            returned = returned.saturating_add(1);
        }
    }

    /// An invalid completion (7.5): every Submitted item is quarantined
    /// and the endpoint stops.
    fn completion_invariant(&mut self) -> BackendFailure {
        let failure = BackendFailure::Invariant {
            operation: COMPLETION,
        };
        bump(&mut self.counters.invalid_completions);
        for slot in 0..self.slots.len() {
            let Some(meta) = self.slots.get_mut(slot) else {
                break;
            };
            if meta.phase == Phase::Submitted {
                meta.phase = Phase::Quarantined;
                if let (Some(queue), Ok(slot)) = (meta.queue, u32::try_from(slot)) {
                    let _ = self.ledger.quarantine(queue, slot);
                }
            }
        }
        *self.failed.get_or_insert(failure)
    }

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
                self.broken();
            }
        }
    }
}

/// A claimed AF_XDP TX frame: its payload region. Dropping it returns the
/// frame.
#[derive(Debug)]
pub struct XdpFrame<'a, O: XskOps> {
    endpoint: &'a mut XdpEndpoint<O>,
    queue: TxQueueId,
    slot: u32,
    len: usize,
    committed: bool,
}

impl<O: XskOps> TxFrame for XdpFrame<'_, O> {
    fn capacity(&self) -> usize {
        self.len
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let (start, len) = (self.endpoint.header, self.len);
        let Some(xsk) = self.endpoint.xsk.as_mut() else {
            return &mut [];
        };
        u16::try_from(self.slot)
            .ok()
            .and_then(|slot| xsk.tx_frame_mut(slot))
            .and_then(|frame| frame.get_mut(start..start.checked_add(len)?))
            .unwrap_or_default()
    }

    fn commit(mut self, commit: Commit) -> Result<TxTicket, CommitRejected<Self>> {
        let active = self.endpoint.active();
        if let Err(error) = self.endpoint.ledger.check_commit(
            active,
            self.queue,
            commit.len,
            self.len,
            commit.options,
        ) {
            return Err(CommitRejected { frame: self, error });
        }
        let (Some(index), Ok(len), Some(meta)) = (
            self.endpoint.run_index(self.queue),
            u16::try_from(commit.len),
            self.endpoint.slots.get(self.slot as usize).copied(),
        ) else {
            return Err(CommitRejected {
                frame: self,
                error: CommitError::UnknownQueue,
            });
        };
        let Some(id) = self.endpoint.id(self.slot, meta) else {
            return Err(CommitRejected {
                frame: self,
                error: CommitError::UnknownQueue,
            });
        };
        if !self.endpoint.push_tail(index, self.slot) {
            return Err(CommitRejected {
                frame: self,
                error: CommitError::UnknownQueue,
            });
        }
        if !self.endpoint.ledger.pool_mut().commit(self.slot) {
            self.endpoint.broken();
        }
        if let Some(meta) = self.endpoint.slots.get_mut(self.slot as usize) {
            meta.phase = Phase::Pending;
            meta.token = commit.token;
            meta.len = len;
            meta.next = NO_SLOT;
        }
        self.committed = true;
        Ok(TxTicket::new(id))
    }
}

impl<O: XskOps> Drop for XdpFrame<'_, O> {
    fn drop(&mut self) {
        if !self.committed
            && self.endpoint.ledger.release_claim(self.queue, self.slot)
            && let Some(meta) = self.endpoint.slots.get_mut(self.slot as usize)
        {
            *meta = SlotMeta {
                generation: meta.generation,
                ..FREE_META
            };
        }
    }
}

impl<O: XskOps> TxBackend for XdpEndpoint<O> {
    type Frame<'a>
        = XdpFrame<'a, O>
    where
        Self: 'a;

    fn claim_tx(&mut self, queue: TxQueueId, len: usize) -> Result<XdpFrame<'_, O>, ClaimError> {
        let active = self.active();
        if active && self.run_index(queue).is_none() {
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
        Ok(XdpFrame {
            endpoint: self,
            queue,
            slot: claimed.slot,
            len,
            committed: false,
        })
    }

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
        let Some(index) = self.run_index(request.queue) else {
            outcome.stop = FlushStop::Queue(QueueError::UnknownQueue);
            return outcome;
        };
        let Some(run) = self.runs.get(index).copied() else {
            outcome.stop = FlushStop::Queue(QueueError::UnknownQueue);
            return outcome;
        };
        if run.len == 0 {
            return outcome;
        }
        let Some(account) = self.ledger.queues().get(request.queue) else {
            outcome.stop = FlushStop::Queue(QueueError::UnknownQueue);
            return outcome;
        };
        let (authority, route) = (account.authority(), account.route());
        let Some(addressing) = self.routes.get(route).map(|entry| entry.addressing) else {
            outcome.stop = FlushStop::Queue(QueueError::RouteUnknown);
            return outcome;
        };
        let free = self
            .xsk
            .as_mut()
            .map_or(0, |xsk| usize::try_from(xsk.tx_free()).unwrap_or(0));
        if free == 0 {
            // A full TX ring: the kernel has no room (design 7.3).
            outcome.stop = FlushStop::WouldBlock;
            return outcome;
        }
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
        let offered_u16 = u16::try_from(offered).unwrap_or(XDP_MAX_BATCH);
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
        // Step 3: headers and descriptors, invisible until the producer
        // store.
        let mut exposed: usize = 0;
        for &slot in slots.iter().take(permitted) {
            let Some(meta) = self.slots.get(slot as usize).copied() else {
                break;
            };
            let (Ok(frame), Some(xsk)) = (u16::try_from(slot), self.xsk.as_mut()) else {
                break;
            };
            let total = xsk.tx_frame_mut(frame).and_then(|bytes| {
                headers::write_headers(bytes, &addressing, usize::from(meta.len))
            });
            let Some(total) = total.and_then(|total| u32::try_from(total).ok()) else {
                break;
            };
            if !xsk.push_tx(frame, total) {
                break;
            }
            if self.pop_head(index).map(|(head, _)| head) != Some(slot) {
                // Written, but the FIFO disagrees: stop, never re-send.
                self.broken();
            }
            if let Some(slot_meta) = self.slots.get_mut(slot as usize) {
                slot_meta.phase = Phase::Submitted;
                slot_meta.next = NO_SLOT;
            }
            outcome.submitted = outcome.submitted.saturating_add(1);
            outcome.bytes = outcome.bytes.saturating_add(u32::from(meta.len));
            exposed = exposed.saturating_add(1);
        }
        if exposed == 0 {
            self.report_pending(&mut writer, &slots, 0, offered, PendingCause::NotAttempted);
            outcome.stop = FlushStop::WouldBlock;
            return outcome;
        }
        // Step 4: the exposure point.
        if let Some(xsk) = self.xsk.as_mut() {
            xsk.publish_tx();
        }
        // Step 5.
        for &slot in slots.iter().take(exposed) {
            if let Some(meta) = self.slots.get(slot as usize).copied()
                && let Some(entry) = self.entry(
                    slot,
                    meta,
                    TxItemOutcome::Submitted {
                        release: Release::Deferred,
                    },
                )
                && writer.push(entry).is_err()
            {
                self.broken();
            }
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
        // Step 6: one nonblocking kick when the ring asks for it.
        let (kicked, stop) = self.kick();
        outcome.spent.ops = u32::from(kicked);
        outcome.stop = stop.unwrap_or(FlushStop::Exposed);
        outcome
    }

    /// Only a completion naming a Submitted frame releases it; AF_XDP gives
    /// no send result. While items are Submitted, one nonblocking kick
    /// drives copy mode, which transmits only inside `sendto`.
    fn poll_completions<H: CompletionHandler>(
        &mut self,
        budget: Budget,
        handler: &mut H,
    ) -> CompletionOutcome {
        let mut outcome = CompletionOutcome::default();
        if self.xsk.is_none() {
            return outcome;
        }
        if self.submitted() > 0 && budget.ops() > 0 {
            let (kicked, _) = self.kick();
            outcome.spent.ops = u32::from(kicked);
        }
        let max = usize::try_from(budget.datagrams())
            .unwrap_or(REAP)
            .min(REAP);
        let mut completions = [Completion::EMPTY; REAP];
        let reaped = self.xsk.as_mut().map_or(0, |xsk| {
            xsk.reap_completions(completions.get_mut(..max).unwrap_or_default())
        });
        for completion in completions.iter().take(reaped) {
            outcome.spent.datagrams = outcome.spent.datagrams.saturating_add(1);
            let frame = match *completion {
                Completion::Released { frame } => frame,
                Completion::Invalid { .. } => {
                    self.completion_invariant();
                    continue;
                }
            };
            let slot = u32::from(frame);
            let Some(meta) = self.slots.get(usize::from(frame)).copied() else {
                self.completion_invariant();
                continue;
            };
            match meta.phase {
                Phase::Submitted => {}
                // Kernel ownership ended, but the release evidence was
                // invalidated earlier: no release is inferred.
                Phase::Quarantined | Phase::Reported => continue,
                Phase::Free | Phase::Claimed | Phase::Pending => {
                    self.completion_invariant();
                    continue;
                }
            }
            let (Some(id), Some(queue)) = (self.id(slot, meta), meta.queue) else {
                continue;
            };
            handler.event(TxEvent::Released {
                id,
                token: meta.token,
            });
            outcome.events = outcome.events.saturating_add(1);
            if let Some(slot_meta) = self.slots.get_mut(usize::from(frame)) {
                *slot_meta = SlotMeta {
                    generation: meta.generation,
                    ..FREE_META
                };
            }
            if !self.ledger.release_pending(queue, slot) {
                self.broken();
            }
        }
        outcome
    }

    fn cancel_pending(
        &mut self,
        queue: TxQueueId,
        report: &mut TxReport,
    ) -> Result<CancelOutcome, QueueError> {
        let Some(mut writer) = report.writer() else {
            return Err(QueueError::ReportNotEmpty);
        };
        if self.xsk.is_none() {
            return Err(QueueError::NotActive);
        }
        let index = self.run_index(queue).ok_or(QueueError::UnknownQueue)?;
        let (returned, more) = self.return_pending(index, ReturnReason::Cancelled, &mut writer);
        Ok(CancelOutcome { returned, more })
    }
}

impl<O: XskOps> XdpEndpoint<O> {
    /// One nonblocking TX kick when the ring asks for it (design 7.3
    /// step 6, 7.4): whether it kicked, and the stop it implies.
    fn kick(&mut self) -> (bool, Option<FlushStop>) {
        let Some(xsk) = self.xsk.as_mut() else {
            return (false, None);
        };
        if !xsk.tx_needs_wakeup() {
            return (false, None);
        }
        bump(&mut self.counters.tx_kicks);
        let stop = match xsk.kick_tx() {
            Ok(()) => None,
            Err(errno) => match errno.0 {
                11 => Some(FlushStop::WouldBlock),
                105 => Some(FlushStop::NoBuffers),
                4 => Some(FlushStop::Interrupted),
                16 => {
                    bump(&mut self.counters.tx_dropped);
                    None
                }
                errno => {
                    let failure = BackendFailure::Os {
                        operation: KICK,
                        errno,
                    };
                    Some(FlushStop::Failed(*self.failed.get_or_insert(failure)))
                }
            },
        };
        (true, stop)
    }
}

impl<O: XskOps> RxBackend for XdpEndpoint<O> {
    fn poll_rx<H: RxHandler>(&mut self, budget: Budget, handler: &mut H) -> RxOutcome {
        let mut outcome = RxOutcome {
            delivered: 0,
            dropped: 0,
            spent: Spent::default(),
            stop: RxStop::WouldBlock,
        };
        if let Some(failure) = self.failed {
            outcome.stop = RxStop::Failed(failure);
            return outcome;
        }
        let XdpEndpointConfig {
            local,
            local_mac,
            max_datagram,
            path,
            ..
        } = self.config;
        let epoch = self.epoch;
        let Some(xsk) = self.xsk.as_mut() else {
            outcome.stop = RxStop::Failed(BackendFailure::NotActive);
            return outcome;
        };
        // Admission before any ring work: a poll with no op left publishes
        // and kicks nothing.
        if budget.ops() == 0 {
            outcome.stop = RxStop::Budget;
            return outcome;
        }
        let mut one = [RxDesc::EMPTY; 1];
        loop {
            // A descriptor is taken only while its largest payload still
            // fits the byte allowance, so no delivery overruns it.
            let room = budget.bytes().saturating_sub(outcome.spent.bytes);
            if outcome.spent.datagrams >= budget.datagrams() || room < u64::from(max_datagram.get())
            {
                outcome.stop = RxStop::Budget;
                break;
            }
            if xsk.reap_rx(&mut one) == 0 {
                break;
            }
            let [desc] = one;
            outcome.spent.datagrams = outcome.spent.datagrams.saturating_add(1);
            let lent = xsk.lend_rx(desc, |frame| {
                match headers::validate(frame, local, local_mac, max_datagram.get()) {
                    Checked::Datagram {
                        offset,
                        len,
                        source,
                    } => {
                        let payload = frame
                            .get(offset..offset.saturating_add(len))
                            .unwrap_or_default();
                        let flow =
                            handler.datagram(RxDatagram::new(payload, source, path, epoch, None));
                        Some((len, flow))
                    }
                    Checked::Drop(reason, source) => {
                        handler.dropped(RxDrop { reason, source });
                        None
                    }
                }
            });
            match lent {
                None => bump(&mut self.counters.invalid_rx),
                Some(None) => {
                    bump(&mut self.counters.rx_dropped);
                    outcome.dropped = outcome.dropped.saturating_add(1);
                }
                Some(Some((len, flow))) => {
                    outcome.delivered = outcome.delivered.saturating_add(1);
                    outcome.spent.bytes = outcome
                        .spent
                        .bytes
                        .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
                    if matches!(flow, ControlFlow::Break(())) {
                        outcome.stop = RxStop::HandlerStopped;
                        break;
                    }
                }
            }
        }
        // The fill producer once per call; a nonblocking wakeup if asked.
        xsk.publish_fill();
        if xsk.fill_needs_wakeup() {
            bump(&mut self.counters.rx_kicks);
            outcome.spent.ops = outcome.spent.ops.saturating_add(1);
            let _ = xsk.kick_rx();
        }
        outcome
    }
}

#[cfg(test)]
mod tests;
