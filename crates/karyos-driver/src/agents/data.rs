// SPDX-License-Identifier: Apache-2.0

//! The sender agent's first sends (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §3.1 steps 8 and 11; phase 5c).
//!
//! An [`Outbound`] publication owns one [`SenderRead`] per lane, one TX
//! queue per lane toward the channel destination and a [`LaneSender`] over
//! them. Each cycle after establishment it stages, per lane, committed
//! frames read at the reader's cursor straight into claimed TX frames
//! (copy staging, S2), then serves the lanes under the data DRR. A head the
//! backend reports `Submitted` moves the reader's registered position: on
//! a reliable channel to the lesser of what was submitted and what every
//! bound receiver consumed (SPEC §4 flow control), on an unreliable one to
//! what was submitted.
//!
//! - **Gate.** Every flush passes `DataGate`, which permits every
//!   candidate until the guard gate of phase 7. It is private to this
//!   module, and only [`Outbound::serve`] uses it; control traffic has its
//!   own gate in [`super::control`].
//! - **Allocation.** The lane sender and the per-lane records are
//!   allocated when the publication is added. Queues and routes are opened
//!   on the first cycle of an endpoint epoch and handed to the lane sender
//!   with `reopen`, which allocates nothing.
//! - **Resets.** A new endpoint epoch drops what was staged and not
//!   submitted. A reliable lane rewinds its reader to the registered
//!   position, which is only ever a block boundary, and sends it again; an
//!   unreliable lane leaves the gap to the receiver's gap policy.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::sync::Arc;

use karyos_io::backend::{
    Authority, BackendEpoch, Commit, Exposure, GateDecision, SenderGate, SenderToken, TxBackend,
    TxFrame, TxOptions, TxQueueConfig, TxQueueId, TxReport, TxTicket,
};
use karyos_io::lanes::{LaneGate, LaneSender, Left, SenderFailure, Staged};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_protocol::network::{Alias, Lanes};
use karyos_sys::log_buffer::{LogBuffer, ReadError, ReadOrigin, ReadOutcome, SenderRead};
use karyos_sys::sizing::align_frame;

use super::{AgentError, AgentKind, EndpointId};

/// A publication's lane reader.
pub type LaneReader = SenderRead<Arc<LogBuffer>>;

/// Datagrams staged per lane queue at once.
const STAGED_PER_LANE: u16 = 8;

/// The gate of data traffic until phase 7: every candidate is permitted.
/// It records, per lane, the position each submitted head reached.
struct DataGate<'a> {
    lanes: &'a mut [LaneTrack],
}

impl SenderGate for DataGate<'_> {
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

impl LaneGate for DataGate<'_> {
    fn admits(&mut self, _lane: usize) -> bool {
        true
    }

    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        let Some(track) = self.lanes.get_mut(lane) else {
            return;
        };
        // Heads leave in staging order.
        match track.staged.pop_front() {
            Some((ticket, next)) if ticket == staged.ticket => match how {
                Left::Submitted => track.submitted = Some(next),
                Left::Returned | Left::Unknown => track.unsent = true,
            },
            _ => track.mismatched = true,
        }
    }
}

/// One lane's staged heads, in order, and what left.
#[derive(Debug)]
struct LaneTrack {
    /// Ticket and the stream position after it, per staged datagram.
    staged: VecDeque<(TxTicket, u64)>,
    /// The position the last submitted head reached, this call.
    submitted: Option<u64>,
    /// The highest position any submitted head reached: a reliable lane's
    /// registered position follows the receivers' consumption up to it,
    /// also in cycles that submit nothing.
    high: u64,
    /// A head was returned or of unknown exposure, this call.
    unsent: bool,
    /// A head left out of staging order, this call.
    mismatched: bool,
}

/// The counters of one outbound publication; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutboundCounters {
    /// Datagrams staged.
    pub staged: u64,
    /// Canonical PAD or ABORTED records staged.
    pub records: u64,
    /// Datagrams the backend submitted.
    pub submitted: u64,
    /// Calls in which a head was returned or of unknown exposure.
    pub unsent: u64,
    /// Calls in which a head left out of staging order: a broken
    /// invariant, counted.
    pub mismatched: u64,
    /// Read errors other than `Pending` (see the reader's counters).
    pub read_errors: u64,
    /// Queue setup failures (the partial open is closed again).
    pub queue_failures: u64,
    /// Route setup failures.
    pub route_failures: u64,
    /// Send faults reported for a lane's head.
    pub send_faults: u64,
    /// Invariant, sender or DRR failures.
    pub send_failures: u64,
    /// Committed datagrams the lane sender refused to record.
    pub staged_refused: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

impl OutboundCounters {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64, by: u64) {
        let value = field(self);
        match value.checked_add(by) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }
}

/// One publication's data path toward its channel destination.
#[derive(Debug)]
pub struct Outbound {
    endpoint: EndpointId,
    alias: Alias,
    destination: SocketAddr,
    readers: Vec<LaneReader>,
    reliable: bool,
    /// The largest datagram, the channel MTU.
    mtu: usize,
    sender: LaneSender,
    queues: Vec<TxQueueId>,
    tracks: Vec<LaneTrack>,
    /// The endpoint epoch its queues were opened in.
    opened: Option<BackendEpoch>,
    /// See [`Outbound::needs_reset`].
    needs_reset: bool,
    /// Report storage for closing queues (allocated at construction).
    report: TxReport,
    next_token: u64,
    counters: OutboundCounters,
}

/// Why an outbound publication was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundError {
    /// No reader, more than four, or quanta of another count.
    Lanes,
    /// The DRR refused the quanta for this MTU.
    Quanta,
    /// The MTU is zero or does not fit a datagram.
    Mtu,
}

impl Outbound {
    /// The data path of the publication `alias` on `endpoint` toward
    /// `destination`, reading `readers` (one per lane, in lane order) into
    /// datagrams of at most `mtu` bytes, served with `quanta`. Allocates
    /// everything its cycles use.
    ///
    /// # Errors
    ///
    /// [`OutboundError`].
    pub fn new(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        readers: Vec<LaneReader>,
        quanta: &Lanes<u64>,
        mtu: u32,
        reliable: bool,
    ) -> Result<Self, OutboundError> {
        let lanes = readers.len();
        if lanes == 0 || lanes != quanta.as_slice().len() {
            return Err(OutboundError::Lanes);
        }
        let max_charge = align_frame(mtu).map_err(|_| OutboundError::Mtu)?;
        let config = DrrConfig::new(quanta.as_slice(), u64::from(max_charge))
            .map_err(|_| OutboundError::Quanta)?;
        // Placeholders until the first cycle opens the real queues.
        let placeholder = TxQueueId::new(BackendEpoch::FIRST, u16::MAX, NonZeroU32::MAX);
        let queues = vec![placeholder; lanes];
        let bound = usize::from(STAGED_PER_LANE);
        let sender = LaneSender::new(config, &queues, bound).map_err(|_| OutboundError::Lanes)?;
        let tracks = (0..lanes)
            .map(|_| LaneTrack {
                staged: VecDeque::with_capacity(bound),
                submitted: None,
                high: 0,
                unsent: false,
                mismatched: false,
            })
            .collect();
        Ok(Self {
            endpoint,
            alias,
            destination,
            readers,
            reliable,
            mtu: usize::try_from(mtu).map_err(|_| OutboundError::Mtu)?,
            sender,
            queues,
            tracks,
            opened: None,
            needs_reset: false,
            report: TxReport::new(),
            next_token: 1,
            counters: OutboundCounters::default(),
        })
    }

    /// The endpoint it sends on.
    #[must_use]
    pub fn endpoint(&self) -> EndpointId {
        self.endpoint
    }

    /// Its alias.
    #[must_use]
    pub fn alias(&self) -> Alias {
        self.alias
    }

    /// Its channel destination.
    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> OutboundCounters {
        self.counters
    }

    /// The readers, in lane order.
    #[must_use]
    pub fn readers(&self) -> &[LaneReader] {
        &self.readers
    }

    /// Each lane's join point for an answer now: where its next read
    /// starts.
    #[must_use]
    pub fn joins(&self) -> Option<Lanes<u64>> {
        let mut joins = [0u64; 4];
        for (join, reader) in joins.iter_mut().zip(&self.readers) {
            *join = reader.position();
        }
        Lanes::new(joins.get(..self.readers.len())?).ok()
    }

    /// Opens the route and the lane queues on `tx` for its current epoch,
    /// once per epoch; a new epoch drops what the old one staged.
    fn open<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>) -> bool {
        let epoch = tx.capabilities().epoch;
        if self.opened == Some(epoch) {
            return true;
        }
        let Ok(route) = tx.add_route(self.destination) else {
            self.counters.bump(|c| &mut c.route_failures, 1);
            return false;
        };
        // All or nothing: a partial open is closed again, so a failing
        // endpoint does not leak a route and queues every cycle.
        for lane in 0..self.queues.len() {
            let opened = tx.open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::new(STAGED_PER_LANE).unwrap_or(NonZeroU16::MIN),
            });
            let Ok(opened) = opened else {
                self.counters.bump(|c| &mut c.queue_failures, 1);
                for queue in self.queues.iter().take(lane) {
                    let _ = tx.close_queue(*queue, &mut self.report);
                    while self.report.pop_front().is_some() {}
                }
                let _ = tx.remove_route(route);
                return false;
            };
            if let Some(queue) = self.queues.get_mut(lane) {
                *queue = opened;
            }
        }
        for (lane, queue) in self.queues.iter().enumerate() {
            self.sender.reopen(lane, *queue);
        }
        for track in &mut self.tracks {
            track.staged.clear();
        }
        // A reset returned what was staged and not submitted. A reliable
        // lane reads it again from its registered position (a block
        // boundary, never below the floor); an unreliable one leaves the
        // gap to the receiver's gap policy (LaneSender::reopen).
        if self.opened.is_some() && self.reliable {
            for reader in &mut self.readers {
                // A faulted reader cannot rewind: its lane is already ended
                // (C-9) and its reads keep failing.
                let _ = reader.rewind();
            }
        }
        self.opened = Some(epoch);
        self.needs_reset = false;
        true
    }

    /// One cycle: stage what each lane has committed, serve the lanes
    /// within `budget`, and move each reader's registered position.
    /// `consumption` gives, per lane, the least position every bound
    /// receiver consumed (a reliable channel's bound). Returns the work
    /// done.
    ///
    /// # Errors
    ///
    /// [`AgentError::CountOverflow`].
    pub fn serve<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        budget: Budget,
        consumption: Option<&[u64]>,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        if !self.open(tx) {
            return Ok(0);
        }
        let mut work = 0u32;
        for lane in 0..self.readers.len() {
            work = work
                .checked_add(self.stage(tx, lane)?)
                .ok_or(overflow.clone())?;
        }
        let report = self.sender.serve(
            tx,
            &mut DataGate {
                lanes: &mut self.tracks,
            },
            budget,
        );
        self.handle_failure(tx, report.failure);
        for (lane, (track, reader)) in self.tracks.iter_mut().zip(&mut self.readers).enumerate() {
            if std::mem::take(&mut track.unsent) {
                self.counters.bump(|c| &mut c.unsent, 1);
            }
            if std::mem::take(&mut track.mismatched) {
                self.counters.bump(|c| &mut c.mismatched, 1);
            }
            if let Some(submitted) = track.submitted.take() {
                self.counters.bump(|c| &mut c.submitted, 1);
                track.high = track.high.max(submitted);
            }
            let submitted = track.high;
            let target = if self.reliable {
                // No bound receiver: the registered position holds (SPEC §4:
                // never past what a required receiver consumed).
                match consumption.and_then(|positions| positions.get(lane)) {
                    Some(consumed) => submitted.min(*consumed),
                    None => continue,
                }
            } else {
                submitted
            };
            // Only a block boundary the reader returned is registered: the
            // registered position is always a valid restart after a reset.
            if let Some(boundary) = reader.boundary_at_or_below(target) {
                let _ = reader.sent(boundary);
            }
        }
        Ok(work)
    }

    /// The control path of a send failure (lane-sender.md, outcome
    /// table): a send fault is retried on its queue, which keeps its items;
    /// a queue that needs a reset, an invariant, a sender bug or an item of
    /// unknown exposure marks the publication as needing an endpoint reset,
    /// which the conductor reads ([`Outbound::needs_reset`]).
    fn handle_failure<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        failure: Option<SenderFailure>,
    ) {
        match failure {
            None => {}
            Some(SenderFailure::Backend { lane, .. }) => {
                self.counters.bump(|c| &mut c.send_faults, 1);
                let retried = self
                    .queues
                    .get(lane)
                    .is_some_and(|queue| tx.retry_queue(*queue).is_ok());
                if retried {
                    self.sender.retry(lane);
                } else {
                    self.needs_reset = true;
                }
            }
            Some(
                SenderFailure::Invariant { .. }
                | SenderFailure::Sender { .. }
                | SenderFailure::Drr(_),
            ) => {
                self.counters.bump(|c| &mut c.send_failures, 1);
                self.needs_reset = true;
            }
        }
        for lane in 0..self.queues.len() {
            // An item of unknown exposure waits for the control path: only
            // an endpoint reset resolves it.
            if self.sender.suspended(lane) == Some(true) {
                self.needs_reset = true;
                continue;
            }
            // A faulted queue the report did not name (the fault left the
            // head pending): retried the same way.
            if self.sender.needs_control(lane) == Some(true) {
                self.counters.bump(|c| &mut c.send_faults, 1);
                let retried = self
                    .queues
                    .get(lane)
                    .is_some_and(|queue| tx.retry_queue(*queue).is_ok());
                if retried {
                    self.sender.retry(lane);
                } else {
                    self.needs_reset = true;
                }
            }
        }
    }

    /// Whether the endpoint needs a reset before this publication can send
    /// again (a send fault that cannot be retried, an invariant, or an item
    /// of unknown exposure). A new endpoint epoch clears it.
    #[must_use]
    pub fn needs_reset(&self) -> bool {
        self.needs_reset
    }

    /// Stages `lane`'s committed frames, one datagram per claimed TX frame,
    /// until its queue is full or nothing more is committed.
    fn stage<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        lane: usize,
    ) -> Result<u32, AgentError> {
        let overflow = AgentError::CountOverflow(AgentKind::Sender);
        let mut staged = 0u32;
        let (Some(queue), Some(reader)) =
            (self.queues.get(lane).copied(), self.readers.get_mut(lane))
        else {
            return Ok(0);
        };
        while self
            .sender
            .pending(lane)
            .is_some_and(|pending| pending < usize::from(STAGED_PER_LANE))
        {
            let Ok(mut frame) = tx.claim_tx(queue, self.mtu) else {
                break;
            };
            let from = reader.position();
            let (len, next, record) =
                match reader.read_committed(from, ReadOrigin::Cursor, frame.bytes_mut()) {
                    Ok(ReadOutcome::Copied { len, next }) => (len, next, false),
                    Ok(ReadOutcome::Canonical { next, .. }) => (32, next, true),
                    // Dropping the unused frame frees its slot.
                    Ok(ReadOutcome::Pending) => break,
                    Err(ReadError::Retry) => break,
                    Err(_) => {
                        self.counters.bump(|c| &mut c.read_errors, 1);
                        break;
                    }
                };
            let token = SenderToken::new(self.next_token);
            self.next_token = self.next_token.checked_add(1).ok_or(overflow.clone())?;
            let Ok(ticket) = frame.commit(Commit {
                len,
                token,
                options: TxOptions::none(),
            }) else {
                // The cursor moved past a read that was not staged: a gap
                // the receiver closes by repair or by its gap policy.
                self.counters.bump(|c| &mut c.queue_failures, 1);
                break;
            };
            let charge = u32::try_from(len)
                .ok()
                .and_then(|len| align_frame(len).ok())
                .map(u64::from);
            let (Some(charge), Ok(len16)) = (charge, u16::try_from(len)) else {
                break;
            };
            // Unreachable: the lane's pending count was checked below its
            // bound and the charge is one aligned datagram of at most the
            // MTU. Counted if it ever happens; the committed item then
            // leaves unrecorded and shows as `mismatched`.
            if self
                .sender
                .staged(
                    lane,
                    Staged {
                        ticket,
                        charge,
                        len: len16,
                    },
                )
                .is_err()
            {
                self.counters.bump(|c| &mut c.staged_refused, 1);
                break;
            }
            if let Some(track) = self.tracks.get_mut(lane) {
                track.staged.push_back((ticket, next));
            }
            self.counters.bump(
                if record {
                    |c| &mut c.records
                } else {
                    |c| &mut c.staged
                },
                1,
            );
            staged = staged.checked_add(1).ok_or(overflow.clone())?;
        }
        Ok(staged)
    }
}

/// Test publications: real log buffers, one per lane, with their
/// publication and conductor handles, and the outbound path reading them.
#[cfg(test)]
pub(crate) mod testing {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test helpers, as ADR-0007 allows in tests"
    )]

    use std::net::SocketAddr;
    use std::sync::Arc;

    use karyos_protocol::frame::Lane;
    use karyos_protocol::network::{Alias, Lanes, TermParams};
    use karyos_sys::log_buffer::{
        Conductor, DEFAULT_CLAIM_DEADLINE, DEFAULT_CORRUPT_RETRIES, LogBuffer, LogBufferConfig,
        Publication, PublicationMode, Role, SenderRead,
    };
    use karyos_sys::sizing::TermLength;
    use karyos_sys::term::TermId;

    use super::{EndpointId, Outbound};

    /// The publishing side of a test publication.
    pub(crate) struct TestLog {
        pub(crate) lanes: Vec<Arc<LogBuffer>>,
        pub(crate) publications: Vec<Publication<Arc<LogBuffer>>>,
        pub(crate) conductors: Vec<Conductor<Arc<LogBuffer>>>,
    }

    /// A publication of `lanes` lanes with `term`, read for `alias` on
    /// `endpoint` toward `destination`; each lane's quantum is four MTUs.
    pub(crate) fn outbound(
        endpoint: EndpointId,
        alias: Alias,
        destination: SocketAddr,
        term: TermParams,
        lanes: u8,
        reliable: bool,
    ) -> (Box<Outbound>, TestLog) {
        let mut log = TestLog {
            lanes: Vec::new(),
            publications: Vec::new(),
            conductors: Vec::new(),
        };
        let mut readers = Vec::new();
        for lane in 0..lanes {
            let term_length = TermLength::try_new(term.term_length).unwrap();
            let buffer = Arc::new(
                LogBuffer::new(LogBufferConfig {
                    term_length,
                    spare_slots: 3,
                    max_subscribers: 2,
                    mtu: term.mtu,
                    max_reserved: term_length.get() / 8,
                    initial_term_id: TermId::new(term.initial_term_id.cast_unsigned()),
                    lane: Lane::try_new(lane).unwrap(),
                    session_id: alias.session_id,
                    stream_id: alias.stream_id,
                    publication: PublicationMode::Exclusive,
                    claim_deadline: DEFAULT_CLAIM_DEADLINE,
                    schedule_capacity: 0,
                })
                .unwrap(),
            );
            let mut conductor = buffer.conductor_owned().unwrap();
            // A required participant on every channel, with its L_send
            // reservation (S2 2.1).
            readers.push(
                SenderRead::new(
                    conductor.subscribe_as(Role::Required, true, 1).unwrap(),
                    DEFAULT_CORRUPT_RETRIES,
                )
                .unwrap(),
            );
            log.publications
                .push(buffer.publication_owned().unwrap().unwrap());
            log.conductors.push(conductor);
            log.lanes.push(buffer);
        }
        let quanta = vec![u64::from(term.mtu) * 4; usize::from(lanes)];
        let outbound = Outbound::new(
            endpoint,
            alias,
            destination,
            readers,
            &Lanes::new(&quanta).unwrap(),
            term.mtu,
            reliable,
        )
        .unwrap();
        (Box::new(outbound), log)
    }
}

#[cfg(test)]
mod tests;
