// SPDX-License-Identifier: Apache-2.0

//! The network work of each agent (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §3.1, §3.2 and phase 4b-1): the
//! establishment control path. No image is created yet (phase 4b-2).
//!
//! - **Receiver.** For each RX half it holds, the receiver reads up to
//!   `rx_datagrams` datagrams and classifies them. SETUP ANNOUNCE and
//!   ANSWER go to its session table ([`ReceiveSessions`]); a challenge to
//!   send, and every control for a sender session (RSP_SETUP CHALLENGE and
//!   SOLICIT, SM), go to the sender agent through the control ring
//!   ([`ControlItem`], DN-4). An accepted answer becomes an
//!   [`AgentEvent::CreateImage`] for the conductor, its slot reserved
//!   before the session table commits it. DATA waits for phase 5.
//! - **Sender.** It holds the publications it announces
//!   ([`SendSessions`]), their channel destinations and join points. Each
//!   cycle it sends the controls the receiver handed over, answers the
//!   challenges and solicits for its publications toward the channel
//!   destination (never a payload's address), and sends the announcements
//!   due.
//!
//! Every queue and table is allocated when the agents are created; drops
//! are counted.

use std::net::SocketAddr;
use std::ops::ControlFlow;

use karyos_io::backend::{Budget, RxBackend, RxDatagram, RxDrop, RxHandler};
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::network::{Alias, Control, Datagram, Lanes, classify};

use super::control::{ControlItem, ControlRoutes};
use super::ring::{self, Reservation, RingReceiver, RingSender};
use super::{AgentCommand, AgentConfig, AgentError, AgentEvent, AgentKind, EndpointId, Half};
use crate::sessions::OsNonces;
use crate::sessions::receive::{
    AnnounceOutcome, AnswerOutcome, BindingKey, ReceiveSessions, SessionConfigError,
};
use crate::sessions::send::{SendSessionError, SendSessions};

/// The receiver's counters; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceiverCounters {
    /// Datagrams read.
    pub datagrams: u64,
    /// Datagrams dropped by the backend.
    pub backend_drops: u64,
    /// Datagrams that did not decode.
    pub decode_errors: u64,
    /// Controls handed to the sender.
    pub forwarded: u64,
    /// RSP_SETUP challenges dropped with the control ring full.
    pub ring_full_rsp_setup: u64,
    /// Received CHALLENGEs dropped with the control ring full.
    pub ring_full_challenge: u64,
    /// Received SOLICITs dropped with the control ring full.
    pub ring_full_solicit: u64,
    /// Received SMs dropped with the control ring full.
    pub ring_full_status: u64,
    /// Challenges not sent: the trigger's source is not an answerable
    /// unicast endpoint (network-control-schemas.md §7.3).
    pub unanswerable_source: u64,
    /// Images asked of the conductor.
    pub create_image: u64,
    /// Data and controls this phase does not handle yet.
    pub unhandled: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

/// The sender's counters; checked, sticky on overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenderCounters {
    /// Controls sent.
    pub sent: u64,
    /// Controls not sent (encoding, route, queue or kernel).
    pub send_failures: u64,
    /// Controls for an endpoint whose TX half the sender does not hold.
    pub no_endpoint: u64,
    /// Answers the session table refused (see its counters).
    pub refused: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

fn bump(value: &mut u64, overflowed: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *overflowed = true,
    }
}

/// The receiver agent's network state.
#[derive(Debug)]
pub struct ReceiverRole {
    sessions: ReceiveSessions,
    nonces: OsNonces,
    to_sender: RingSender<ControlItem>,
    budget: Budget,
    counters: ReceiverCounters,
}

/// The sender agent's network state.
#[derive(Debug)]
pub struct SenderRole {
    sessions: SendSessions,
    from_receiver: RingReceiver<ControlItem>,
    /// Each publication's channel destination and join points.
    publications: Vec<(EndpointId, Alias, SocketAddr, Lanes<u64>)>,
    /// Control routes per endpoint.
    routes: Vec<(EndpointId, ControlRoutes)>,
    max_routes: usize,
    budget: u32,
    /// The announcements due this cycle (allocated at creation).
    due: Vec<(EndpointId, karyos_protocol::network::SetupAnnounce)>,
    counters: SenderCounters,
}

/// Both roles and the control ring between them, sized by `config`.
pub(super) fn roles(config: &AgentConfig) -> Result<(SenderRole, ReceiverRole), AgentError> {
    let capacity = std::num::NonZeroUsize::new(config.control_capacity).ok_or(
        AgentError::InvalidConfig("control_capacity must be at least 1"),
    )?;
    let (to_sender, from_receiver) = ring::ring(capacity);
    let mut boot_id = [0u64; 2];
    karyos_sys::random::fill_u64s(&mut boot_id)
        .map_err(|_| AgentError::InvalidConfig("no random source for receiver_boot_id"))?;
    // An all-zero draw is not a valid boot id; draw once more.
    if boot_id == [0, 0] {
        karyos_sys::random::fill_u64s(&mut boot_id)
            .map_err(|_| AgentError::InvalidConfig("no random source for receiver_boot_id"))?;
    }
    let sessions = ReceiveSessions::new(config.sessions, boot_id)
        .map_err(|SessionConfigError(reason)| AgentError::InvalidConfig(reason))?;
    let send = SendSessions::new(
        config.publications,
        config.setup_interval,
        config.answer_rate,
    )
    .map_err(|_| AgentError::InvalidConfig("invalid sender session configuration"))?;
    let datagrams = config.rx_datagrams;
    let bytes = u64::from(datagrams)
        .checked_mul(u64::from(karyos_io::sockets::endpoint::MAX_DATAGRAM))
        .ok_or(AgentError::InvalidConfig("rx_datagrams too large"))?;
    // One receive call per datagram, plus the one that finds none.
    let ops = datagrams
        .checked_add(1)
        .ok_or(AgentError::InvalidConfig("rx_datagrams too large"))?;
    Ok((
        SenderRole {
            sessions: send,
            from_receiver,
            publications: Vec::with_capacity(config.publications),
            routes: Vec::with_capacity(config.max_endpoints),
            max_routes: config.control_routes,
            budget: u32::try_from(config.control_capacity).unwrap_or(u32::MAX),
            due: Vec::with_capacity(config.publications),
            counters: SenderCounters::default(),
        },
        ReceiverRole {
            sessions,
            nonces: OsNonces,
            to_sender,
            budget: Budget::new(datagrams, bytes, ops),
            counters: ReceiverCounters::default(),
        },
    ))
}

impl ReceiverRole {
    /// The counters.
    #[must_use]
    pub fn counters(&self) -> ReceiverCounters {
        self.counters
    }

    /// One cycle: the session timers, then every held RX half.
    pub(super) fn duty<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        events: &RingSender<AgentEvent<O>>,
        now: u64,
    ) -> u32 {
        let mut work = self.sessions.timers(now);
        for (endpoint, half) in halves.iter_mut() {
            let Half::Rx(rx) = half else {
                continue;
            };
            let mut intake = Intake {
                endpoint: *endpoint,
                now,
                role: self,
                events,
                work: 0,
            };
            let budget = intake.role.budget;
            let _ = rx.poll_rx(budget, &mut intake);
            work += intake.work;
        }
        work
    }
}

/// The receiver's handler of one endpoint's datagrams.
struct Intake<'a, O: SocketOps> {
    endpoint: EndpointId,
    now: u64,
    role: &'a mut ReceiverRole,
    events: &'a RingSender<AgentEvent<O>>,
    work: u32,
}

impl<O: SocketOps> Intake<'_, O> {
    fn count(&mut self, field: fn(&mut ReceiverCounters) -> &mut u64) {
        let counters = &mut self.role.counters;
        let mut overflowed = counters.overflowed;
        bump(field(counters), &mut overflowed);
        counters.overflowed = overflowed;
    }

    /// Hands `item` to the sender; a full ring drops it, counted per kind
    /// so that a flood of one kind does not hide another.
    fn forward(&mut self, item: ControlItem) {
        let full: fn(&mut ReceiverCounters) -> &mut u64 = match item {
            ControlItem::Outgoing { .. } => |c| &mut c.ring_full_rsp_setup,
            ControlItem::Incoming {
                control: Control::Challenge(_),
                ..
            } => |c| &mut c.ring_full_challenge,
            ControlItem::Incoming {
                control: Control::Solicit(_),
                ..
            } => |c| &mut c.ring_full_solicit,
            ControlItem::Incoming { .. } => |c| &mut c.ring_full_status,
        };
        match self.role.to_sender.try_post(item) {
            Ok(()) => self.count(|c| &mut c.forwarded),
            Err(_) => self.count(full),
        }
    }

    fn control(&mut self, source: SocketAddr, control: Control) {
        let endpoint = self.endpoint;
        let now = self.now;
        match control {
            Control::SetupAnnounce(announce) => {
                let key = BindingKey {
                    endpoint,
                    source,
                    alias: announce.alias,
                };
                if let AnnounceOutcome::Challenge(challenge) =
                    self.role
                        .sessions
                        .announce(key, &announce, now, &mut self.role.nonces)
                {
                    // §7.3: an RSP_SETUP goes only to the trigger's validated
                    // source endpoint, through the socket it arrived on.
                    if answerable(source) {
                        self.forward(ControlItem::Outgoing {
                            endpoint,
                            destination: source,
                            control: Control::Challenge(challenge),
                        });
                    } else {
                        self.count(|c| &mut c.unanswerable_source);
                    }
                }
            }
            Control::SetupAnswer(answer) => {
                let key = BindingKey {
                    endpoint,
                    source,
                    alias: answer.alias,
                };
                let mut slot: Option<Reservation> = None;
                let events = self.events;
                let outcome = self.role.sessions.answer(key, &answer, now, || {
                    slot = events.reserve();
                    slot.is_some()
                });
                if let (
                    AnswerOutcome::CreateImage {
                        slot: session,
                        identity,
                        term,
                        joins,
                    },
                    Some(reservation),
                ) = (outcome, slot)
                {
                    let event = AgentEvent::CreateImage {
                        endpoint,
                        slot: session,
                        identity,
                        term,
                        joins,
                    };
                    // The event ring's consumer gone: the driver is
                    // stopping; nothing to undo.
                    let _ = events.post(reservation, event);
                    self.count(|c| &mut c.create_image);
                }
            }
            Control::Challenge(_) | Control::Solicit(_) | Control::Status(_) => {
                self.forward(ControlItem::Incoming {
                    endpoint,
                    source,
                    control,
                });
            }
            _ => self.count(|c| &mut c.unhandled),
        }
    }
}

impl<O: SocketOps> RxHandler for Intake<'_, O> {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        self.work += 1;
        self.count(|c| &mut c.datagrams);
        let source = datagram.source();
        match classify(datagram.bytes()) {
            Ok(Datagram::Control(control)) => self.control(source, control),
            Ok(Datagram::DataBatch(_) | Datagram::Heartbeat(_)) => {
                self.count(|c| &mut c.unhandled);
            }
            Err(_) => self.count(|c| &mut c.decode_errors),
        }
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _drop: RxDrop) {
        self.count(|c| &mut c.backend_drops);
    }
}

impl SenderRole {
    /// The counters.
    #[must_use]
    pub fn counters(&self) -> SenderCounters {
        self.counters
    }

    fn count(&mut self, field: fn(&mut SenderCounters) -> &mut u64) {
        let mut overflowed = self.counters.overflowed;
        bump(field(&mut self.counters), &mut overflowed);
        self.counters.overflowed = overflowed;
    }

    /// The sender's commands: `AddPublication`.
    pub(super) fn command<O: SocketOps>(
        &mut self,
        command: AgentCommand<O>,
    ) -> Option<(Reservation, AgentEvent<O>)> {
        let AgentCommand::AddPublication {
            reply,
            publication,
            destination,
            joins,
        } = command
        else {
            return None;
        };
        let event = match self.sessions.add(publication) {
            Ok(()) => {
                self.publications.push((
                    publication.endpoint,
                    publication.alias,
                    destination,
                    joins,
                ));
                AgentEvent::PublicationAdded {
                    endpoint: publication.endpoint,
                    alias: publication.alias,
                }
            }
            Err(SendSessionError::Full | SendSessionError::DuplicateAlias)
            | Err(SendSessionError::InvalidConfig) => AgentEvent::PublicationRefused {
                agent: AgentKind::Sender,
                endpoint: publication.endpoint,
                alias: publication.alias,
            },
        };
        Some((reply, event))
    }

    /// Sends `control` on `endpoint` to `destination`.
    fn send<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        destination: SocketAddr,
        control: &Control,
    ) {
        let tx = halves.iter_mut().find_map(|(held, half)| match half {
            Half::Tx(tx) if *held == endpoint => Some(tx),
            _ => None,
        });
        let Some(tx) = tx else {
            self.count(|c| &mut c.no_endpoint);
            return;
        };
        let max = self.max_routes;
        let routes = match self.routes.iter().position(|(held, _)| *held == endpoint) {
            Some(index) => index,
            None => {
                self.routes.push((endpoint, ControlRoutes::new(max)));
                self.routes.len() - 1
            }
        };
        let Some((_, routes)) = self.routes.get_mut(routes) else {
            return;
        };
        match routes.send(tx, destination, control) {
            Ok(()) => self.count(|c| &mut c.sent),
            Err(_) => self.count(|c| &mut c.send_failures),
        }
    }

    /// The publication's channel destination and join points.
    fn route_of(&self, endpoint: EndpointId, alias: Alias) -> Option<(SocketAddr, Lanes<u64>)> {
        self.publications
            .iter()
            .find(|(held, held_alias, ..)| *held == endpoint && *held_alias == alias)
            .map(|(_, _, destination, joins)| (*destination, *joins))
    }

    /// One cycle: the controls the receiver handed over, then the
    /// announcements due.
    pub(super) fn duty<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        now: u64,
    ) -> u32 {
        let mut work = 0u32;
        for _ in 0..self.budget {
            let Ok(Some(item)) = self.from_receiver.try_take() else {
                break;
            };
            work += 1;
            match item {
                ControlItem::Outgoing {
                    endpoint,
                    destination,
                    control,
                } => self.send(halves, endpoint, destination, &control),
                ControlItem::Incoming {
                    endpoint,
                    source,
                    control,
                } => self.incoming(halves, endpoint, source, now, control),
            }
        }
        let mut due = std::mem::take(&mut self.due);
        self.sessions
            .announce_due(now, |endpoint, announce| due.push((endpoint, announce)));
        for (endpoint, announce) in due.drain(..) {
            // An ANNOUNCE goes to the channel's configured destination
            // (§6.2).
            if let Some((destination, _)) = self.route_of(endpoint, announce.alias) {
                work += 1;
                self.send(
                    halves,
                    endpoint,
                    destination,
                    &Control::SetupAnnounce(announce),
                );
            }
        }
        // Its capacity stays for the next cycle.
        self.due = due;
        work
    }

    fn incoming<O: SocketOps>(
        &mut self,
        halves: &mut [(EndpointId, Half<O>)],
        endpoint: EndpointId,
        source: SocketAddr,
        now: u64,
        control: Control,
    ) {
        if let Some((destination, answer)) = self.answer_for(endpoint, source, now, control) {
            self.send(halves, endpoint, destination, &answer);
        }
    }

    /// The SETUP ANSWER to a received control, and where it goes: §7.3 and
    /// §6.2/§6.3, an ANSWER follows the channel's configured route (the
    /// unicast endpoint, or the group on multicast), never the trigger's
    /// source, so a spoofed CHALLENGE or SOLICIT cannot steer it.
    fn answer_for(
        &mut self,
        endpoint: EndpointId,
        source: SocketAddr,
        now: u64,
        control: Control,
    ) -> Option<(SocketAddr, Control)> {
        let (alias, answer) = match control {
            Control::Challenge(challenge) => {
                let Some((_, joins)) = self.route_of(endpoint, challenge.alias) else {
                    self.count(|c| &mut c.refused);
                    return None;
                };
                (
                    challenge.alias,
                    self.sessions
                        .challenge(endpoint, source, now, &challenge, |_| joins),
                )
            }
            Control::Solicit(solicit) => {
                let Some((_, joins)) = self.route_of(endpoint, solicit.alias) else {
                    self.count(|c| &mut c.refused);
                    return None;
                };
                (
                    solicit.alias,
                    self.sessions
                        .solicit(endpoint, source, now, &solicit, |_| joins),
                )
            }
            Control::Status(status) => {
                self.sessions.status(endpoint, &status);
                return None;
            }
            _ => return None,
        };
        match answer {
            Ok(answer) => self
                .route_of(endpoint, alias)
                .map(|(destination, _)| (destination, Control::SetupAnswer(answer))),
            Err(_) => {
                self.count(|c| &mut c.refused);
                None
            }
        }
    }
}

/// Whether an RSP_SETUP may answer `source` (network-control-schemas.md
/// §7.3): a unicast address with a nonzero port; never a multicast,
/// broadcast or unspecified address.
fn answerable(source: SocketAddr) -> bool {
    let ip = source.ip();
    let broadcast = match ip {
        std::net::IpAddr::V4(v4) => v4.is_broadcast(),
        std::net::IpAddr::V6(_) => false,
    };
    source.port() != 0 && !ip.is_multicast() && !ip.is_unspecified() && !broadcast
}

#[cfg(test)]
mod tests;
