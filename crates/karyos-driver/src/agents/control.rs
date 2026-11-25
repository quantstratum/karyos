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
use std::sync::{Arc, Mutex};

use karyos_io::backend::{
    Authority, BackendEpoch, Commit, Exposure, FlushRequest, FlushStop, GateDecision, PendingCause,
    RouteId, SenderGate, SenderToken, TxBackend, TxFrame, TxItemOutcome, TxOptions, TxQueueConfig,
    TxQueueId, TxReport,
};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::network::{Control, MAX_CONTROL_LENGTH};

use karyos_protocol::protection::hmac_sha256::Domain;

use crate::wire_auth::{ENVELOPE_LEN, Proof, Sealer};

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
        /// The image's domain 4 sealer on an authenticated channel: the
        /// control then goes only sealed, never bare (ADR-0086 section 2);
        /// `None` on a trusted channel, whose controls go bare.
        seal: Option<SharedSealer>,
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
    /// The cache is full of routes still closing with frames in flight:
    /// an ANNOUNCE waits for the duty that closes them
    /// ([`ControlRoutes::send_or_wait`]); any other control is refused
    /// (#849).
    Blocked,
}

/// One cached control destination.
#[derive(Debug, Clone, Copy)]
struct Destination {
    address: SocketAddr,
    route: RouteId,
    queue: TxQueueId,
    used: u64,
    /// Evicted with frames in flight: it sends nothing more, keeps its
    /// place in the cache, and is closed again at each sender duty until it
    /// closes, fails with a close error, or outlives
    /// [`CONTROL_CLOSE_TIMEOUT`] (#849).
    closing: bool,
    /// The first duty that found it closing, still in flight.
    closing_since: Option<u64>,
    /// Opened for a reply to a REGISTER or a registrant's first SM, to an
    /// address the network chose (karyos#977, #942 item 7): such entries
    /// take at most half the cache and make room only among themselves,
    /// so a stream of new registrants never evicts a destination's route.
    transient: bool,
}

/// How long an evicted control route may stay in flight before it counts
/// as a failed close: the driver's one bound for closes in flight, with its
/// reason at [`super::CLOSE_IN_FLIGHT_TIMEOUT`].
pub use super::CLOSE_IN_FLIGHT_TIMEOUT as CONTROL_CLOSE_TIMEOUT;

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
    /// Controls refused while every cached route was closing, in order:
    /// sent before any later one, at the next send or duty (#838). At most
    /// one per destination and kind (and alias, for an ANNOUNCE): a later
    /// one replaces it in place, so the room allocated at creation for
    /// every such key is never exceeded and nothing waits forever.
    waiting: std::collections::VecDeque<(SocketAddr, Control)>,
    /// Controls dropped with the waiting queue full, or refused for
    /// another reason when their turn came.
    pub(crate) waits_dropped: u64,
    /// Evicted routes that outlived [`CONTROL_CLOSE_TIMEOUT`] in flight.
    pub(crate) close_timeouts: u64,
    /// A count above would have overflowed: it holds its last value.
    pub(crate) overflowed: bool,
    /// Entries at most, open and closing: twice the cache, allocated at
    /// creation.
    limit: usize,
    /// What this epoch refused or failed to close, until the sender takes
    /// it ([`ControlRoutes::take_refusal`]).
    refusal: ControlRefusal,
    /// Test only: the next closes to report in flight.
    #[cfg(test)]
    pub(crate) close_in_flight: u32,
    /// Test only: every close reports in flight while set.
    #[cfg(test)]
    pub(crate) hold_closes: bool,
}

/// What an endpoint's control routes hit in its current epoch (#838): a
/// route or queue refused for the endpoint's limit, and a close that did
/// not complete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControlRefusal {
    /// A route or queue was refused for the endpoint's limit.
    pub limited: bool,
    /// Live routes or queues that did not close, each counted.
    pub close_failed: u32,
}

/// How a control entry's close went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closed {
    Done,
    /// Its queue still has frames in flight.
    InFlight,
    Failed,
}

/// The default room in the waiting queue: one publication's ANNOUNCE to
/// each of its destinations.
const WAITING_EXTRA: usize = super::data::DEFAULT_MAX_DESTINATIONS;

/// What a waiting control is unique by, with its destination: its kind,
/// and an ANNOUNCE's alias (each publication announces itself).
fn wait_key(
    control: &Control,
) -> (
    karyos_protocol::network::ControlKind,
    Option<karyos_protocol::network::Alias>,
) {
    let alias = match control {
        Control::SetupAnnounce(announce) => Some(announce.alias),
        _ => None,
    };
    (control.kind(), alias)
}

/// Seals one encoded control: the `frames` bytes at the start of a buffer
/// with room for the envelope, returning the sealed length, or `None` when
/// it cannot be sealed (nothing is sent). A pairwise or sender control is
/// sealed by the session's [`Sealer`] (domains 4 and 1), a SETUP or an
/// RSP_SETUP by the channel's or pair's [`Proof`] (domains 5 and 6).
pub trait ControlSeal {
    /// The domain it seals in.
    fn domain(&self) -> Domain;
    /// Seals the control.
    fn seal_control(&mut self, buffer: &mut [u8], frames: usize) -> Option<usize>;
}

impl ControlSeal for Sealer {
    fn domain(&self) -> Domain {
        Sealer::domain(self)
    }

    fn seal_control(&mut self, buffer: &mut [u8], frames: usize) -> Option<usize> {
        self.seal(buffer, frames).ok()
    }
}

/// An image's session [`Sealer`], shared between the receiver agent, which
/// owns the image, and the sender agent, which seals and sends its
/// controls: a clone allocates nothing. A poisoned lock seals nothing, so
/// the control is not sent (fail closed).
#[derive(Clone)]
pub struct SharedSealer {
    sealer: Arc<Mutex<Sealer>>,
    domain: Domain,
}

impl core::fmt::Debug for SharedSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedSealer")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl SharedSealer {
    /// Shares `sealer`.
    #[must_use]
    pub fn new(sealer: Sealer) -> Self {
        let domain = sealer.domain();
        Self {
            sealer: Arc::new(Mutex::new(sealer)),
            domain,
        }
    }
}

impl ControlSeal for SharedSealer {
    fn domain(&self) -> Domain {
        self.domain
    }

    fn seal_control(&mut self, buffer: &mut [u8], frames: usize) -> Option<usize> {
        self.sealer.lock().ok()?.seal(buffer, frames).ok()
    }
}

impl ControlSeal for Proof {
    fn domain(&self) -> Domain {
        Proof::domain(self)
    }

    fn seal_control(&mut self, buffer: &mut [u8], frames: usize) -> Option<usize> {
        self.seal(buffer, frames).ok()
    }
}

/// Whether `control` belongs in `domain` (ADR-0086 section 7a): SETUP in
/// 5, RSP_SETUP in 6, the receiver's SM, NAK and RTTM in 4, the sender's
/// PATH_HB, ERR and RTTM in 1. ERR UNBOUND is prebinding and stays bare.
fn sealable_in(control: &Control, domain: Domain) -> bool {
    match control {
        Control::SetupAnnounce(_) | Control::SetupAnswer(_) => domain == Domain::SetupProof,
        Control::Challenge(_) | Control::Solicit(_) | Control::Register(_) => {
            domain == Domain::RspSetup
        }
        Control::Status(_) | Control::Nak(_) => domain == Domain::ReceiverToPublisher,
        Control::NakReply(_) | Control::Registration(_) | Control::PathHeartbeat(_) => {
            domain == Domain::Data
        }
        Control::Rttm(_) => matches!(domain, Domain::Data | Domain::ReceiverToPublisher),
        // ERR UNBOUND, and any kind this profile does not name.
        _ => false,
    }
}

/// Datagrams one control queue holds: controls are sent at once.
pub(crate) const CONTROL_QUEUE_DEPTH: u16 = 4;

impl ControlRoutes {
    /// At most `max` cached destinations (at least 1), and room for the
    /// ANNOUNCEs of one publication's destinations waiting; allocated
    /// here.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self::with_waiting(max, WAITING_EXTRA)
    }

    /// At most `max` cached destinations (at least 1), and room for
    /// `waiting` controls waiting, one per destination, kind and alias
    /// ([`ControlRoutes::send_or_wait`]); allocated here.
    #[must_use]
    pub fn with_waiting(max: usize, waiting: usize) -> Self {
        let max = max.max(1);
        Self {
            // At most `max` open entries, and as many closing.
            entries: Vec::with_capacity(max.saturating_mul(2)),
            max,
            epoch: None,
            tick: 0,
            report: TxReport::new(),
            waiting: std::collections::VecDeque::with_capacity(waiting.max(1)),
            waits_dropped: 0,
            close_timeouts: 0,
            overflowed: false,
            limit: max.saturating_mul(2),
            refusal: ControlRefusal::default(),
            #[cfg(test)]
            close_in_flight: 0,
            #[cfg(test)]
            hold_closes: false,
        }
    }

    /// Forgets every cached destination without touching any half: for an
    /// endpoint handed back, or a half of a new epoch.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.waiting.clear();
        self.epoch = None;
        self.refusal = ControlRefusal::default();
    }

    /// Counts a live route or queue that did not close in this epoch.
    fn close_failure(&mut self) {
        match self.refusal.close_failed.checked_add(1) {
            Some(failed) => self.refusal.close_failed = failed,
            None => self.overflowed = true,
        }
    }

    /// Drops the controls waiting, counted: their epoch is gone.
    fn drop_waiting(&mut self) {
        for _ in self.waiting.drain(..) {
            super::roles::bump(&mut self.waits_dropped, &mut self.overflowed);
        }
    }

    /// Test only: the entries evicted in flight, not closed yet.
    #[cfg(test)]
    pub(crate) fn lingering(&self) -> usize {
        self.entries.iter().filter(|entry| entry.closing).count()
    }

    /// Test only: the cache's entries, open and closing, and the capacity
    /// allocated for them.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> (usize, usize) {
        (self.entries.len(), self.entries.capacity())
    }

    /// Test only: the controls waiting.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// Test only: records `refusal` as this cache's, in `epoch`.
    #[cfg(test)]
    pub(crate) fn refuse(&mut self, epoch: BackendEpoch, refusal: ControlRefusal) {
        self.epoch = Some(epoch);
        self.refusal.limited |= refusal.limited;
        for _ in 0..refusal.close_failed {
            self.close_failure();
        }
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
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| !entry.closing)
            .copied()
            .collect();
        entries.sort_by_key(|entry| entry.used);
        entries.iter().map(|entry| entry.address).collect()
    }

    /// Drops the entry of `queue` from `tx` and the cache; one with frames
    /// in flight stays, closing, until the next duty.
    fn evict<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, queue: TxQueueId) {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.queue == queue && !entry.closing)
        else {
            return;
        };
        let Some(old) = self.entries.get(index).copied() else {
            return;
        };
        match self.close(tx, old) {
            Closed::Done => {
                self.entries.swap_remove(index);
            }
            Closed::InFlight => {
                // It keeps its place until the next duty closes it. The
                // cache never grows: open and closing together stay within
                // the capacity allocated at creation (`queue` refuses a new
                // destination as `Blocked` when full), and no route is ever
                // given up as failed to make room (QS-COORDINATOR on #849).
                if let Some(entry) = self.entries.iter_mut().find(|entry| entry.queue == queue) {
                    entry.closing = true;
                }
            }
            Closed::Failed => {
                self.entries.swap_remove(index);
                self.close_failure();
            }
        }
    }

    /// The sender's duty at `now`: closes again the entries evicted with
    /// frames in flight (each cycle, however many controls it sends). One
    /// that closes leaves the cache; a close error, or
    /// [`CONTROL_CLOSE_TIMEOUT`] in flight from the first duty that found
    /// it so, counts as a failed close; otherwise it keeps its place. Then
    /// the controls waiting go, in order. A half of another epoch dropped
    /// them all in its reset.
    pub fn close_lingering<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, now: u64) {
        if self.epoch != Some(tx.capabilities().epoch) {
            self.entries.clear();
            self.drop_waiting();
            return;
        }
        let mut index = 0;
        while let Some(old) = self.entries.get(index).copied() {
            if !old.closing {
                index += 1;
                continue;
            }
            match self.close(tx, old) {
                Closed::Done => {
                    self.entries.swap_remove(index);
                }
                Closed::Failed => {
                    self.close_failure();
                    self.entries.swap_remove(index);
                }
                Closed::InFlight => {
                    let since = match self.entries.get_mut(index) {
                        Some(entry) => *entry.closing_since.get_or_insert(now),
                        None => now,
                    };
                    let late = super::close_late(since, now);
                    if late {
                        super::roles::bump(&mut self.close_timeouts, &mut self.overflowed);
                        self.close_failure();
                        self.entries.swap_remove(index);
                    } else {
                        index += 1;
                    }
                }
            }
        }
        self.send_waiting(tx);
    }

    /// Closes again the closing entries that have closed since, keeping
    /// the others for the duty: none counts as failed here, so a burst of
    /// sends cannot use up their grace.
    fn reclose_closed<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>) {
        let mut index = 0;
        while let Some(old) = self.entries.get(index).copied() {
            if old.closing && self.close(tx, old) == Closed::Done {
                self.entries.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }

    /// Drops the ANNOUNCEs of `alias` waiting, to `destination` only when
    /// given: a destination removed, or the publication removed, announces
    /// nothing stale (#849).
    pub fn purge_announces(
        &mut self,
        alias: karyos_protocol::network::Alias,
        destination: Option<SocketAddr>,
    ) {
        self.waiting.retain(|(address, control)| {
            !(matches!(control, Control::SetupAnnounce(announce) if announce.alias == alias)
                && destination.is_none_or(|destination| destination == *address))
        });
    }

    /// Sends the controls waiting, in order, until one is blocked again.
    fn send_waiting<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>) {
        // Waiting since an epoch the endpoint has left: none goes out on
        // the new one; all are dropped, counted.
        if self
            .epoch
            .is_some_and(|epoch| epoch != tx.capabilities().epoch)
        {
            self.drop_waiting();
            return;
        }
        while let Some((address, control)) = self.waiting.pop_front() {
            match self.send_now(tx, address, &control, false) {
                Ok(()) => {}
                Err(ControlSendError::Blocked) => {
                    self.waiting.push_front((address, control));
                    return;
                }
                // Its turn came and it was refused otherwise: dropped,
                // counted.
                Err(_) => super::roles::bump(&mut self.waits_dropped, &mut self.overflowed),
            }
        }
    }

    /// Drops what `queue` holds unsent, under ordinary backpressure, while
    /// keeping the queue and its destination's route (karyos#977 review):
    /// the pending frames that were never exposed are cancelled in place,
    /// so no queue is closed or reopened and no queue handle is spent. A
    /// queue whose flush latched a fault never comes here: it is evicted
    /// (karyos#1016). A queue the backend refuses to cancel on (closed,
    /// stale, or the endpoint resetting) is evicted too.
    fn discard<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, queue: TxQueueId) {
        loop {
            match tx.cancel_pending(queue, &mut self.report) {
                Ok(outcome) => {
                    while self.report.pop_front().is_some() {}
                    if !outcome.more {
                        return;
                    }
                    if outcome.returned == 0 {
                        // Nothing more can be returned now: what remains
                        // was exposed, and is not a stale reply waiting.
                        return;
                    }
                }
                Err(_) => {
                    while self.report.pop_front().is_some() {}
                    self.evict(tx, queue);
                    return;
                }
            }
        }
    }

    /// Closes `old`'s queue, then its route. A handle already gone counts
    /// as closed.
    fn close<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, old: Destination) -> Closed {
        use karyos_io::backend::{QueueError, RouteError};

        #[cfg(test)]
        if self.hold_closes {
            return Closed::InFlight;
        }
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
        transient: bool,
    ) -> Result<TxQueueId, ControlSendError> {
        // A reset reopened the endpoint: the cached ids are of the old
        // epoch, and every one of them is dead.
        let epoch = tx.capabilities().epoch;
        if self.epoch != Some(epoch) {
            self.entries.clear();
            self.drop_waiting();
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
            .find(|entry| entry.address == address && !entry.closing)
        {
            entry.used = tick;
            // A route a destination's own control uses is no longer a
            // reply's: replies cannot evict it any more.
            entry.transient &= transient;
            return Ok(entry.queue);
        }
        // At most `max` open entries, and `limit` in all with those closing:
        // the capacity allocated at creation. With `max` open, the least
        // recently used makes room, closed or closing. Full, the closing
        // ones that closed since make room; with none, the control is
        // refused `Blocked` (neither a failed close nor a limit).
        let open = self.entries.iter().filter(|entry| !entry.closing).count();
        if transient {
            // A transient route makes room only among the transient ones,
            // which hold at most half the cache (karyos#977).
            let share = (self.max / 2).max(1);
            let held = self
                .entries
                .iter()
                .filter(|entry| !entry.closing && entry.transient)
                .count();
            if held >= share || open >= self.max {
                let oldest = self
                    .entries
                    .iter()
                    .filter(|entry| !entry.closing && entry.transient)
                    .min_by_key(|entry| entry.used)
                    .map(|entry| entry.queue)
                    .ok_or(ControlSendError::Blocked)?;
                self.evict(tx, oldest);
            }
        } else if open >= self.max
            && let Some(oldest) = self
                .entries
                .iter()
                .filter(|entry| !entry.closing)
                .min_by_key(|entry| entry.used)
                .map(|entry| entry.queue)
        {
            self.evict(tx, oldest);
        }
        if self.entries.len() >= self.limit {
            self.reclose_closed(tx);
            if self.entries.len() >= self.limit {
                return Err(ControlSendError::Blocked);
            }
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
                etf: None,
            })
            .map_err(|error| {
                if super::data::fanout::queue_limit(error) {
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
            closing: false,
            closing_since: None,
            transient,
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
    /// The controls waiting go first, so none to the same destination is
    /// overtaken: a receiver never sees a control before the ANNOUNCE it
    /// refers to (#847).
    ///
    /// # Errors
    ///
    /// The [`ControlSendError`] reason; nothing waits for a later cycle.
    /// `Blocked` while a control to `address` still waits; otherwise the
    /// destination's entry is evicted.
    pub fn send<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
        control: &Control,
    ) -> Result<(), ControlSendError> {
        self.send_waiting(tx);
        if self.waiting.iter().any(|(at, _)| *at == address) {
            return Err(ControlSendError::Blocked);
        }
        self.send_now(tx, address, control, false)
    }

    /// [`ControlRoutes::send`] of a reply to a REGISTER or to a
    /// registrant's first SM: its route, when it opens one, is transient
    /// (karyos#977). Transient routes hold at most half the cache, at
    /// least one, and make room only by evicting the least recently used
    /// transient route; with none to evict the reply is refused `Blocked`.
    ///
    /// # Errors
    ///
    /// As [`ControlRoutes::send`].
    pub fn send_reply<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
        control: &Control,
    ) -> Result<(), ControlSendError> {
        self.send_waiting(tx);
        if self.waiting.iter().any(|(at, _)| *at == address) {
            return Err(ControlSendError::Blocked);
        }
        self.send_now(tx, address, control, true)
    }

    /// [`ControlRoutes::send`], except that a control refused because
    /// every cached route is closing waits, in order behind those already
    /// waiting, and goes at the next send or duty (#838): every
    /// destination gets it. `Ok(false)` when it waits; one past the
    /// waiting queue's room is dropped and counted, `Blocked`.
    ///
    /// # Errors
    ///
    /// As [`ControlRoutes::send`].
    pub fn send_or_wait<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
        control: &Control,
    ) -> Result<bool, ControlSendError> {
        self.send_waiting(tx);
        let result = if self.waiting.is_empty() {
            self.send_now(tx, address, control, false)
        } else {
            Err(ControlSendError::Blocked)
        };
        match result {
            Ok(()) => Ok(true),
            Err(ControlSendError::Blocked) => {
                let key = wait_key(control);
                if let Some(slot) = self
                    .waiting
                    .iter_mut()
                    .find(|(at, waiting)| *at == address && wait_key(waiting) == key)
                {
                    // The latest replaces the earlier, in its place.
                    slot.1 = *control;
                    return Ok(false);
                }
                if self.waiting.len() < self.waiting.capacity() {
                    self.waiting.push_back((address, *control));
                    return Ok(false);
                }
                super::roles::bump(&mut self.waits_dropped, &mut self.overflowed);
                Err(ControlSendError::Blocked)
            }
            Err(error) => Err(error),
        }
    }

    /// [`ControlRoutes::send`] of a control on an authenticated channel:
    /// sealed by `seal` in the domain its kind belongs to (ADR-0086
    /// section 7a), encoded and sealed afresh at the send, so every
    /// transmission takes a fresh envelope sequence. A sealed control never
    /// waits for a later cycle; while another control to `address` waits
    /// it is refused `Blocked`, and one that cannot be sealed is refused
    /// `Encode` without anything being queued.
    ///
    /// # Errors
    ///
    /// As [`ControlRoutes::send`].
    pub fn send_sealed<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
        control: &Control,
        seal: &mut dyn ControlSeal,
    ) -> Result<(), ControlSendError> {
        self.send_waiting(tx);
        if self.waiting.iter().any(|(at, _)| *at == address) {
            return Err(ControlSendError::Blocked);
        }
        self.send_encoded(tx, address, control, false, Some(seal))
    }

    fn send_now<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
        control: &Control,
        transient: bool,
    ) -> Result<(), ControlSendError> {
        self.send_encoded(tx, address, control, transient, None)
    }

    fn send_encoded<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
        control: &Control,
        transient: bool,
        seal: Option<&mut dyn ControlSeal>,
    ) -> Result<(), ControlSendError> {
        let mut bytes = [0u8; MAX_CONTROL_LENGTH + ENVELOPE_LEN];
        let plain = bytes
            .get_mut(..MAX_CONTROL_LENGTH)
            .ok_or(ControlSendError::Encode)?;
        let mut length = control
            .encode(plain)
            .map_err(|_| ControlSendError::Encode)?;
        if let Some(seal) = seal {
            if !sealable_in(control, seal.domain()) {
                return Err(ControlSendError::Encode);
            }
            length = seal
                .seal_control(&mut bytes, length)
                .ok_or(ControlSendError::Encode)?;
        }
        let encoded = bytes.get(..length).ok_or(ControlSendError::Encode)?;
        // A reply that reuses a destination's own route (karyos#977
        // review): failing, it must not take that route with it.
        let protected = transient
            && self
                .entries
                .iter()
                .any(|entry| entry.address == address && !entry.closing && !entry.transient);
        let queue = self.queue(tx, address, transient)?;
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
            // Nothing was queued: a protected route stays as it was.
            if !protected {
                self.evict(tx, queue);
            }
            return Err(ControlSendError::Claim);
        }
        let flushed = tx.flush(
            FlushRequest {
                queue,
                max_datagrams: NonZeroU16::MIN,
                max_bytes: u32::MAX,
            },
            &mut ControlGate,
            &mut self.report,
        );
        // A send error latches a fault on the queue (an `EMSGSIZE`, say),
        // which a cancellation does not clear: the next control on it
        // would stop at the fault and be dropped (karyos#1016). Such a
        // queue is evicted even on a protected route; only ordinary
        // backpressure keeps the queue and cancels in place.
        let mut faulted = matches!(
            flushed.stop,
            FlushStop::Faulted(_) | FlushStop::Queue(_) | FlushStop::Failed(_)
        );
        let (mut sent, mut unknown) = (false, false);
        while let Some(entry) = self.report.pop_front() {
            sent |= matches!(entry.outcome, TxItemOutcome::Submitted { .. });
            unknown |= matches!(entry.outcome, TxItemOutcome::Unknown);
            faulted |= matches!(
                entry.outcome,
                TxItemOutcome::Pending {
                    cause: PendingCause::Faulted(_)
                }
            );
        }
        if sent {
            return Ok(());
        }
        // Not taken now: a control is not worth a retry. Under ordinary
        // backpressure a protected route keeps its queue and route, and
        // the unsent reply is cancelled in place; otherwise the queue is
        // evicted, so no stale control waits.
        if protected && !faulted {
            self.discard(tx, queue);
        } else {
            self.evict(tx, queue);
        }
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
