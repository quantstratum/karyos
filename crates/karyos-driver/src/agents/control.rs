// SPDX-License-Identifier: Apache-2.0

//! The control path between the agents (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §2.3 and §3, DN-4; phase 4b-1).
//!
//! - **Items.** The receiver agent owns every RX half. It hands the sender
//!   agent, which owns every TX half, two kinds of control through one
//!   bounded ring: controls to send (an RSP_SETUP challenge to a source)
//!   and controls it received for a local publication (RSP_SETUP CHALLENGE
//!   and SOLICIT, SM, RTTM REQUEST). A full ring drops the item and counts
//!   it per kind. An outgoing SM carries its image's slot ([`SmGuard`]); an
//!   RTTM REQUEST carries its path's report ([`ReportGuard`]), which the
//!   sender settles with the time read before the submitting call, or
//!   which reports not submitted when dropped unsettled.
//! - **Control TX.** The sender sends controls through a small cache of
//!   routes per endpoint, one control queue per destination, at most
//!   `control_routes` of them; a full cache reuses the least recently used
//!   entry. The cache belongs to one backend epoch of the endpoint: a reset
//!   reopens the endpoint at its next epoch, whose route and queue ids are
//!   all new, so the cache starts empty again. Any failed send evicts its
//!   entry. Controls pass an always-permit gate, private to this module:
//!   only [`ControlRoutes::send`] uses it, and that takes a typed
//!   [`Control`], so DATA can never pass it (the guard gate is phase 7,
//!   `guards-and-abort.md`).

use std::net::SocketAddr;
use std::num::NonZeroU16;

use karyos_io::backend::{
    Authority, BackendEpoch, Commit, Exposure, FlushRequest, GateDecision, RouteId, SenderGate,
    SenderToken, TxBackend, TxFrame, TxItemOutcome, TxOptions, TxQueueConfig, TxQueueId, TxReport,
};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::network::{Control, MAX_CONTROL_LENGTH};

use super::EndpointId;

/// The SM slot of one image (network-sessions.md S1: an SM slot per
/// binding): set while its SM waits in the control ring, cleared when the
/// sender drops the item after sending it.
#[derive(Debug, Default)]
pub struct SmSlot(std::sync::atomic::AtomicBool);

impl SmSlot {
    /// Whether the image's previous SM still waits.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// The guard an SM carries through the ring: its drop frees the slot.
#[derive(Debug)]
pub struct SmGuard(std::sync::Arc<SmSlot>);

impl SmGuard {
    /// Takes `slot` for one SM.
    #[must_use]
    pub fn take(slot: &std::sync::Arc<SmSlot>) -> Self {
        slot.0.store(true, std::sync::atomic::Ordering::Release);
        Self(std::sync::Arc::clone(slot))
    }
}

impl Drop for SmGuard {
    fn drop(&mut self) {
        (self.0)
            .0
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// The submission report of one control the receiver hands to the sender
/// (an RTTM REQUEST, RC-1; a NAK, RC-6): the sender reads the clock
/// immediately before the backend call, publishes it as sending, and then
/// whether the call submitted the control, did not, or left its exposure
/// unknown; the receiver collects the report. A reply proves the control
/// went out, so one that overtakes the final report settles from the
/// sending state. At most one control per slot is in flight: its owner
/// waits while the slot is waiting or sending.
#[derive(Debug, Default)]
pub struct ReportSlot {
    state: std::sync::atomic::AtomicU8,
    /// The time read before the submitting call; valid once `state` is
    /// `REPORT_SENDING` or later (published by its Release store).
    start: std::sync::atomic::AtomicU64,
}

/// No control in the ring and no report to collect.
const REPORT_IDLE: u8 = 0;
/// A control waits in the ring.
const REPORT_WAITING: u8 = 1;
/// The sender is in the backend call; `start` holds its start.
const REPORT_SENDING: u8 = 2;
/// The backend reported it submitted; `start` holds its start.
const REPORT_SUBMITTED: u8 = 3;
/// It was not submitted: refused, failed or dropped.
const REPORT_NOT_SUBMITTED: u8 = 4;
/// Its exposure is unknown (a backend result outside its documented
/// range); `start` holds its start.
const REPORT_UNCERTAIN: u8 = 5;

/// What a [`ReportSlot`] reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendReport {
    /// Submitted; the time read before the submitting call.
    Submitted(u64),
    /// Not submitted.
    NotSubmitted,
    /// Its exposure is unknown; the time read before the call.
    Uncertain(u64),
}

impl ReportSlot {
    /// Whether the slot's control is still with the sender: waiting in the
    /// ring or in its backend call.
    #[must_use]
    pub fn busy(&self) -> bool {
        matches!(
            self.state.load(std::sync::atomic::Ordering::Acquire),
            REPORT_WAITING | REPORT_SENDING
        )
    }

    /// Takes the final report of the last control, if the sender made one,
    /// and frees the slot. With `replied` (a reply to it arrived, proving
    /// it went out), a control still in its backend call reports submitted
    /// at its start; the slot then stays busy until the sender's final
    /// report, which a later collection clears.
    pub fn collect(&self, replied: bool) -> Option<SendReport> {
        use std::sync::atomic::Ordering;

        let report = match self.state.load(Ordering::Acquire) {
            REPORT_SENDING if replied => {
                return Some(SendReport::Submitted(self.start.load(Ordering::Relaxed)));
            }
            REPORT_SUBMITTED => SendReport::Submitted(self.start.load(Ordering::Relaxed)),
            REPORT_NOT_SUBMITTED => SendReport::NotSubmitted,
            REPORT_UNCERTAIN => SendReport::Uncertain(self.start.load(Ordering::Relaxed)),
            _ => return None,
        };
        self.state.store(REPORT_IDLE, Ordering::Relaxed);
        Some(report)
    }
}

/// The guard a control carries through the ring: the sender reports its
/// submission through it; dropped unreported, it reports not submitted.
#[derive(Debug)]
pub struct ReportGuard(Option<std::sync::Arc<ReportSlot>>);

impl ReportGuard {
    /// Takes `slot` for one control.
    #[must_use]
    pub fn take(slot: &std::sync::Arc<ReportSlot>) -> Self {
        slot.state
            .store(REPORT_WAITING, std::sync::atomic::Ordering::Release);
        Self(Some(std::sync::Arc::clone(slot)))
    }

    /// The sender enters the backend call; `start` was read immediately
    /// before it.
    pub fn sending(&mut self, start: u64) {
        use std::sync::atomic::Ordering;

        if let Some(slot) = &self.0 {
            slot.start.store(start, Ordering::Relaxed);
            slot.state.store(REPORT_SENDING, Ordering::Release);
        }
    }

    /// The backend reported the control submitted, at the start
    /// [`ReportGuard::sending`] published.
    pub fn submitted(mut self) {
        if let Some(slot) = self.0.take() {
            slot.state
                .store(REPORT_SUBMITTED, std::sync::atomic::Ordering::Release);
        }
    }

    /// The backend left the control's exposure unknown, at the start
    /// [`ReportGuard::sending`] published.
    pub fn uncertain(mut self) {
        if let Some(slot) = self.0.take() {
            slot.state
                .store(REPORT_UNCERTAIN, std::sync::atomic::Ordering::Release);
        }
    }
}

impl Drop for ReportGuard {
    fn drop(&mut self) {
        if let Some(slot) = self.0.take() {
            slot.state
                .store(REPORT_NOT_SUBMITTED, std::sync::atomic::Ordering::Release);
        }
    }
}

/// What an outgoing control carries back to the receiver.
#[derive(Debug)]
pub enum ItemGuard {
    /// An SM's slot, freed once the SM was sent.
    Sm(SmGuard),
    /// A control's submission report (an RTTM REQUEST, a NAK).
    Report(ReportGuard),
}

/// A control handed from the receiver agent to the sender agent.
#[derive(Debug)]
pub enum ControlItem {
    /// Send `control` on `endpoint` to `destination`.
    Outgoing {
        /// The endpoint to send on.
        endpoint: EndpointId,
        /// Where to.
        destination: SocketAddr,
        /// What.
        control: Control,
        /// An SM's slot or an RTTM REQUEST's report, settled once the
        /// control was sent.
        guard: Option<ItemGuard>,
    },
    /// `control` arrived on `endpoint` from `source`, for a local
    /// publication.
    Incoming {
        /// The endpoint it arrived on.
        endpoint: EndpointId,
        /// Its backend source.
        source: SocketAddr,
        /// What.
        control: Control,
        /// When the receiver took it from the backend.
        seen: u64,
    },
}

/// The gate of control traffic: every candidate is permitted.
#[derive(Debug, Clone, Copy, Default)]
struct ControlGate;

impl SenderGate for ControlGate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        match u16::try_from(candidate.tokens.len())
            .ok()
            .and_then(NonZeroU16::new)
        {
            Some(count) => GateDecision::Permit { count },
            None => GateDecision::Deny,
        }
    }
}

/// Why a control was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlSendError {
    /// The control did not encode.
    Encode,
    /// No route or queue could be set up for the destination.
    Route,
    /// The queue had no room for it.
    Claim,
    /// The kernel did not take it.
    Unsent,
    /// Its exposure is unknown: the backend reported a result outside its
    /// documented range (it may have left).
    Uncertain,
}

/// One cached control destination.
#[derive(Debug, Clone, Copy)]
struct Destination {
    address: SocketAddr,
    route: RouteId,
    queue: TxQueueId,
    used: u64,
}

/// The control routes of one endpoint's TX half, for one backend epoch.
#[derive(Debug)]
pub struct ControlRoutes {
    entries: Vec<Destination>,
    max: usize,
    /// The epoch the cached ids belong to.
    epoch: Option<BackendEpoch>,
    /// A logical clock for least-recently-used eviction.
    tick: u64,
    report: TxReport,
    /// Evicted entries whose queue still had frames in flight: closed again
    /// at the sender's next duty, once, before they count as failed (#838).
    lingering: Vec<Destination>,
    /// What this epoch refused or failed to close, until the sender takes
    /// it ([`ControlRoutes::take_refusal`]).
    refusal: ControlRefusal,
    /// Test only: the next closes to report in flight.
    #[cfg(test)]
    pub(crate) close_in_flight: u32,
}

/// What an endpoint's control routes hit in its current epoch (#838): a
/// route or queue refused for the endpoint's limit, and a close that did
/// not complete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControlRefusal {
    /// A route or queue was refused for the endpoint's limit.
    pub limited: bool,
    /// A live route or queue did not close.
    pub close_failed: bool,
}

/// How a control entry's close went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closed {
    Done,
    /// Its queue still has frames in flight.
    InFlight,
    Failed,
}

/// Datagrams one control queue holds: controls are sent at once.
const CONTROL_QUEUE_DEPTH: u16 = 4;

impl ControlRoutes {
    /// At most `max` cached destinations (at least 1); allocated here.
    #[must_use]
    pub fn new(max: usize) -> Self {
        let max = max.max(1);
        Self {
            entries: Vec::with_capacity(max),
            max,
            epoch: None,
            tick: 0,
            report: TxReport::new(),
            lingering: Vec::with_capacity(max),
            refusal: ControlRefusal::default(),
            #[cfg(test)]
            close_in_flight: 0,
        }
    }

    /// Forgets every cached destination without touching any half: for an
    /// endpoint handed back, or a half of a new epoch.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lingering.clear();
        self.epoch = None;
        self.refusal = ControlRefusal::default();
    }

    /// Test only: the entries evicted in flight, not closed yet.
    #[cfg(test)]
    pub(crate) fn lingering(&self) -> usize {
        self.lingering.len()
    }

    /// Test only: records `refusal` as this cache's, in `epoch`.
    #[cfg(test)]
    pub(crate) fn refuse(&mut self, epoch: BackendEpoch, refusal: ControlRefusal) {
        self.epoch = Some(epoch);
        self.refusal.limited |= refusal.limited;
        self.refusal.close_failed |= refusal.close_failed;
    }

    /// What this epoch's control routes refused or failed to close since
    /// the last call, which clears it, with that epoch.
    pub fn take_refusal(&mut self) -> Option<(BackendEpoch, ControlRefusal)> {
        let refusal = std::mem::take(&mut self.refusal);
        self.epoch
            .filter(|_| refusal != ControlRefusal::default())
            .map(|epoch| (epoch, refusal))
    }

    /// The cached destinations, oldest use first (tests).
    #[cfg(test)]
    pub(crate) fn cached(&self) -> Vec<SocketAddr> {
        let mut entries = self.entries.clone();
        entries.sort_by_key(|entry| entry.used);
        entries.iter().map(|entry| entry.address).collect()
    }

    /// Drops the entry of `queue` from `tx` and the cache.
    fn evict<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, queue: TxQueueId) {
        if let Some(index) = self.entries.iter().position(|entry| entry.queue == queue) {
            let old = self.entries.swap_remove(index);
            match self.close(tx, old) {
                Closed::Done => {}
                // Closed again at the next duty before it counts as
                // failed; the caller made room ([`ControlRoutes::queue`]).
                Closed::InFlight => self.lingering.push(old),
                Closed::Failed => self.refusal.close_failed = true,
            }
        }
    }

    /// Closes the entries evicted with frames in flight once more, at the
    /// sender's duty (each cycle, however many controls it sends): what
    /// still does not close has failed. A half of another epoch dropped
    /// them in its reset.
    pub fn close_lingering<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>) {
        if self.epoch != Some(tx.capabilities().epoch) {
            self.lingering.clear();
            return;
        }
        while let Some(old) = self.lingering.pop() {
            if self.close(tx, old) != Closed::Done {
                self.refusal.close_failed = true;
            }
        }
    }

    /// Closes again the entries evicted in flight that have closed since,
    /// keeping the others for the duty: none counts as failed here, so a
    /// burst of sends cannot use up their grace.
    fn reclose_closed<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>) {
        let mut index = 0;
        while let Some(old) = self.lingering.get(index).copied() {
            if self.close(tx, old) == Closed::Done {
                self.lingering.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }

    /// Closes `old`'s queue, then its route. A handle already gone counts
    /// as closed.
    fn close<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, old: Destination) -> Closed {
        use karyos_io::backend::{QueueError, RouteError};

        #[cfg(test)]
        if self.close_in_flight > 0 {
            self.close_in_flight -= 1;
            return Closed::InFlight;
        }
        loop {
            match tx.close_queue(old.queue, &mut self.report) {
                Ok(outcome) => {
                    let returned = outcome.returned;
                    while self.report.pop_front().is_some() {}
                    if !outcome.more {
                        break;
                    }
                    if returned == 0 {
                        return Closed::InFlight;
                    }
                }
                Err(QueueError::UnknownQueue) => break,
                Err(_) => return Closed::Failed,
            }
        }
        match tx.remove_route(old.route) {
            Ok(()) | Err(RouteError::Unknown) => Closed::Done,
            Err(_) => Closed::Failed,
        }
    }

    /// The control queue to `address` on `tx`, created on first use; the
    /// least recently used destination makes room when the cache is full.
    fn queue<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
    ) -> Result<TxQueueId, ControlSendError> {
        // A reset reopened the endpoint: the cached ids are of the old
        // epoch, and every one of them is dead.
        let epoch = tx.capabilities().epoch;
        if self.epoch != Some(epoch) {
            self.entries.clear();
            self.lingering.clear();
            self.epoch = Some(epoch);
            self.refusal = ControlRefusal::default();
        }
        // A u64 use clock does not wrap in practice; if it ever would, the
        // ages start over.
        self.tick = match self.tick.checked_add(1) {
            Some(tick) => tick,
            None => {
                for entry in &mut self.entries {
                    entry.used = 0;
                }
                1
            }
        };
        let tick = self.tick;
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.address == address)
        {
            entry.used = tick;
            return Ok(entry.queue);
        }
        if self.entries.len() >= self.max && self.lingering.len() >= self.lingering.capacity() {
            // Every evicted entry is still in flight: those that closed
            // since make room; with none, this send waits (refused, not a
            // failed close nor a limit).
            self.reclose_closed(tx);
            if self.lingering.len() >= self.lingering.capacity() {
                return Err(ControlSendError::Route);
            }
        }
        if self.entries.len() >= self.max
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|entry| entry.used)
                .map(|entry| entry.queue)
        {
            self.evict(tx, oldest);
        }
        let route = tx.add_route(address).map_err(|error| {
            if error == karyos_io::backend::RouteError::RouteLimit {
                self.refusal.limited = true;
            }
            ControlSendError::Route
        })?;
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::new(CONTROL_QUEUE_DEPTH).unwrap_or(NonZeroU16::MIN),
            })
            .map_err(|error| {
                if matches!(
                    error,
                    karyos_io::backend::QueueError::QueueLimit
                        | karyos_io::backend::QueueError::OverCommitted { .. }
                ) {
                    self.refusal.limited = true;
                }
                let _ = tx.remove_route(route);
                ControlSendError::Route
            })?;
        self.entries.push(Destination {
            address,
            route,
            queue,
            used: tick,
        });
        Ok(queue)
    }

    /// Encodes `control` and sends it on `tx` to `address`, now. It takes
    /// a typed [`Control`] only, so no DATA can take this path:
    ///
    /// ```compile_fail
    /// # use karyos_driver::agents::control::ControlRoutes;
    /// # use karyos_io::sockets::{OsSocket, endpoint::SocketsTx};
    /// fn send_data(routes: &mut ControlRoutes, tx: &mut SocketsTx<OsSocket>, batch: &[u8]) {
    ///     let to = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    ///     // A DATA batch is bytes, not a `Control`: this does not compile.
    ///     let _ = routes.send(tx, to, batch);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// The [`ControlSendError`] reason; nothing waits for a later cycle,
    /// and the destination's entry is evicted.
    pub fn send<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
        control: &Control,
    ) -> Result<(), ControlSendError> {
        let mut bytes = [0u8; MAX_CONTROL_LENGTH];
        let length = control
            .encode(&mut bytes)
            .map_err(|_| ControlSendError::Encode)?;
        let encoded = bytes.get(..length).ok_or(ControlSendError::Encode)?;
        let queue = self.queue(tx, address)?;
        let claimed = tx
            .claim_tx(queue, encoded.len())
            .ok()
            .and_then(|mut frame| {
                frame
                    .bytes_mut()
                    .get_mut(..encoded.len())?
                    .copy_from_slice(encoded);
                frame
                    .commit(Commit {
                        len: encoded.len(),
                        token: SenderToken::new(0),
                        options: TxOptions::none(),
                    })
                    .ok()
            });
        if claimed.is_none() {
            self.evict(tx, queue);
            return Err(ControlSendError::Claim);
        }
        let _ = tx.flush(
            FlushRequest {
                queue,
                max_datagrams: NonZeroU16::MIN,
                max_bytes: u32::MAX,
            },
            &mut ControlGate,
            &mut self.report,
        );
        let (mut sent, mut unknown) = (false, false);
        while let Some(entry) = self.report.pop_front() {
            sent |= matches!(entry.outcome, TxItemOutcome::Submitted { .. });
            unknown |= matches!(entry.outcome, TxItemOutcome::Unknown);
        }
        if sent {
            return Ok(());
        }
        // Not taken now: a control is not worth a retry; dropping the
        // queue drops it, so no stale control waits.
        self.evict(tx, queue);
        Err(if unknown {
            ControlSendError::Uncertain
        } else {
            ControlSendError::Unsent
        })
    }
}

/// One endpoint's control routes, kept by the sender in a table allocated
/// at creation (one per endpoint the agent can hold).
#[derive(Debug)]
pub struct RouteSlot {
    /// The endpoint it serves, `None` while free.
    pub endpoint: Option<EndpointId>,
    /// Its routes.
    pub routes: ControlRoutes,
}
