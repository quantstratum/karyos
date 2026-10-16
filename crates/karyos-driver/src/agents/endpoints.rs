// SPDX-License-Identifier: Apache-2.0

//! The conductor's endpoint table (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §2.4 and §4.2, phase 3;
//! `sockets-backend.md` 3.10): the conductor opens each sockets endpoint,
//! splits it and hands the TX half to the sender agent and the RX half to
//! the receiver agent. Socket life changes only while the conductor holds
//! the joined endpoint:
//!
//! - **Open.** Both agents' command and reply slots are reserved before the
//!   socket is opened. [`EndpointEvent::Opened`] follows once both agents
//!   answered `Attached`.
//! - **Reset.** The conductor asks both agents for their halves, joins
//!   them, resets the endpoint (reporting each item it returns), reopens it
//!   with the next epoch, splits it and attaches the new halves;
//!   [`EndpointEvent::Reopened`] follows once both agents hold them again.
//! - **Retire.** The same hand back and join, then `retire` until complete:
//!   the socket closes and the entry leaves the table.
//! - **Failure.** When an agent refuses a half, or a command to one agent
//!   cannot be posted after the other's was, the entry is failing: it is
//!   not active, the half still with an agent is asked back and dropped
//!   (closing its descriptor), and one [`EndpointEvent::Failed`] reports it
//!   once both halves are accounted for; then the entry leaves the table.
//! - **Stop.** After the runner hands the agents back (DN-8),
//!   [`Endpoints::reclaim`] collects every half: held by the agents, in
//!   their unread commands, in unpolled answers and in the table. It joins
//!   and retires every endpoint whose two halves it finds and drops the
//!   rest, so every descriptor closes.
//!
//! Every step runs on the control path. The table holds at most the
//! agents' `max_endpoints` entries, allocated at creation. Reference
//! counting endpoints per stream and their lookup by local bind and family
//! (design §4.2) belong to phase 4, where streams use them.

use karyos_io::backend::{InstanceId, OpenError, TxEntry, TxReport};
use karyos_io::sockets::endpoint::{
    Retired, SocketsConfig, SocketsEndpoint, SocketsRx, SocketsTx, SplitFailure,
};
use karyos_io::sockets::ops::SocketOps;

use super::{
    AgentCommand, AgentConfig, AgentError, AgentEvent, AgentKind, AgentLink, AgentLinks,
    EndpointId, Half, NetworkAgents,
};

/// Why an endpoint operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// The table holds `max_endpoints` entries.
    #[error("the endpoint table is full")]
    TableFull,
    /// No entry of that id.
    #[error("unknown endpoint {0:?}")]
    Unknown(EndpointId),
    /// The endpoint is resetting, retiring, attaching or failing.
    #[error("endpoint {0:?} is busy")]
    Busy(EndpointId),
    /// Opening or reopening the socket failed.
    #[error("cannot open the endpoint: {0}")]
    Open(OpenError),
    /// Splitting the endpoint failed.
    #[error("cannot split the endpoint: {0}")]
    Split(SplitFailure),
    /// An agent's rings refused or failed.
    #[error(transparent)]
    Agent(AgentError),
    /// An agent refused a half (a broken invariant: the table is sized for
    /// the agents' capacity).
    #[error("the {0:?} agent refused a half")]
    Refused(AgentKind),
    /// The halves handed back did not join (a broken invariant).
    #[error("the endpoint's halves did not join")]
    Join,
    /// A reset or retirement did not finish within its bound.
    #[error("the endpoint did not drain")]
    Drain,
    /// Every endpoint identity was used.
    #[error("endpoint identities exhausted")]
    Exhausted,
}

/// What [`Endpoints::poll`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointEvent {
    /// Both halves are attached: the endpoint is active.
    Opened(EndpointId),
    /// A reset finished and both agents hold the new halves: the endpoint
    /// is active again, at its next epoch.
    Reopened {
        /// The endpoint.
        endpoint: EndpointId,
        /// TX items the reset returned.
        returned: u32,
    },
    /// A retirement finished: the socket is closed, the entry gone.
    Retired {
        /// The endpoint.
        endpoint: EndpointId,
        /// TX items the retirement returned.
        returned: u32,
    },
    /// One TX item a reset or retirement returned, never sent: its report
    /// entry, for the sender's outcome accounting (phase 7).
    Returned {
        /// The endpoint.
        endpoint: EndpointId,
        /// The item's report entry.
        entry: TxEntry,
    },
    /// The endpoint failed: both halves are closed and the entry is gone.
    Failed {
        /// The endpoint.
        endpoint: EndpointId,
        /// Why.
        error: EndpointError,
    },
}

/// What a hand back is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Reset,
    Retire,
}

/// An agent's answer to an `Attach`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Pending,
    Attached,
}

/// Where one half of a failing entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Its `Attach` was posted; no answer yet.
    Posted,
    /// The agent holds it: a `Detach` is due.
    Held,
    /// A `Detach` was posted; no answer yet.
    Detaching,
    /// Closed, refused, never posted or with a gone agent.
    Done,
}

/// An entry's state.
enum State<O: SocketOps> {
    /// Both halves were posted; waiting for both answers. `reopen` holds
    /// the items a reset returned, for its [`EndpointEvent::Reopened`].
    Attaching {
        sender: Answer,
        receiver: Answer,
        reopen: Option<u32>,
    },
    /// Both agents hold their halves.
    Active,
    /// Waiting for both halves to come back.
    Detaching {
        purpose: Purpose,
        tx: Option<SocketsTx<O>>,
        rx: Option<SocketsRx<O>>,
        sender: bool,
        receiver: bool,
    },
    /// Reopened and split, waiting for ring room to attach the halves.
    Split {
        tx: SocketsTx<O>,
        rx: SocketsRx<O>,
        returned: u32,
    },
    /// Bringing back and closing the halves after a failure.
    Failing {
        error: EndpointError,
        sender: Fate,
        receiver: Fate,
    },
}

struct Entry<O: SocketOps> {
    id: EndpointId,
    config: SocketsConfig,
    /// The bound local address of the current epoch.
    local: std::net::SocketAddr,
    state: State<O>,
}

/// The conductor's endpoint table.
pub struct Endpoints<O: SocketOps> {
    entries: Vec<Entry<O>>,
    max: usize,
    next: Option<InstanceId>,
    report: TxReport,
}

impl<O: SocketOps> std::fmt::Debug for Endpoints<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoints")
            .field("entries", &self.entries.len())
            .field("max", &self.max)
            .finish_non_exhaustive()
    }
}

/// Reset and retire calls one drain may take before it is abandoned: each
/// call returns up to a report's worth of items, and an endpoint holds at
/// most `MAX_TX_SLOTS` of them.
const MAX_DRAIN_CALLS: u32 = 4096;

/// The link of `agent`.
fn link_of<O: SocketOps>(links: &AgentLinks<O>, agent: AgentKind) -> &AgentLink<O> {
    match agent {
        AgentKind::Sender => &links.sender,
        AgentKind::Receiver => &links.receiver,
    }
}

impl<O: SocketOps> Endpoints<O> {
    /// A table sized for the agents of `config`: at most their
    /// `max_endpoints` endpoints, so no agent refuses a half for room.
    #[must_use]
    pub fn new(config: &AgentConfig) -> Self {
        let max = config.max_endpoints;
        Self {
            entries: Vec::with_capacity(max),
            max,
            next: Some(InstanceId::FIRST),
            report: TxReport::new(),
        }
    }

    /// The endpoints in the table, failing ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `endpoint` is active: both agents hold its halves.
    #[must_use]
    pub fn is_active(&self, endpoint: EndpointId) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.id == endpoint && matches!(entry.state, State::Active))
    }

    /// The bound local address of `endpoint` in its current epoch (a
    /// port 0 bind resolved by the kernel).
    #[must_use]
    pub fn local_address(&self, endpoint: EndpointId) -> Option<std::net::SocketAddr> {
        self.entries
            .iter()
            .find(|entry| entry.id == endpoint)
            .map(|entry| entry.local)
    }

    fn index(&self, endpoint: EndpointId) -> Result<usize, EndpointError> {
        self.entries
            .iter()
            .position(|entry| entry.id == endpoint)
            .ok_or(EndpointError::Unknown(endpoint))
    }

    /// Opens an endpoint over `ops`, splits it and attaches its halves to
    /// the agents; [`EndpointEvent::Opened`] follows once both answered.
    ///
    /// # Errors
    ///
    /// [`EndpointError::TableFull`], [`EndpointError::Agent`] when a ring
    /// has no room, [`EndpointError::Open`], [`EndpointError::Split`],
    /// [`EndpointError::Exhausted`]: nothing is left open or posted. An
    /// [`EndpointError::Agent`] after the sender's half was posted (the
    /// receiver gone) leaves a failing entry that brings that half back.
    pub fn open(
        &mut self,
        links: &AgentLinks<O>,
        config: SocketsConfig,
        ops: O,
    ) -> Result<EndpointId, EndpointError> {
        if self.entries.len() >= self.max {
            return Err(EndpointError::TableFull);
        }
        let to_sender = links.sender.prepare().map_err(EndpointError::Agent)?;
        let to_receiver = links.receiver.prepare().map_err(EndpointError::Agent)?;
        let instance = self.next.ok_or(EndpointError::Exhausted)?;
        let endpoint =
            SocketsEndpoint::open(&config, instance, ops).map_err(EndpointError::Open)?;
        let local = endpoint.capabilities().local;
        // The counter only moves forward: a later failure wastes the id.
        self.next = instance.next().ok();
        // A refused split drops the endpoint, which closes its socket.
        let (tx, rx) = endpoint
            .split()
            .map_err(|error| EndpointError::Split(error.error))?;
        let id = EndpointId(instance.get().get());
        // A failed sender commit drops both halves: nothing was posted.
        links
            .sender
            .commit(to_sender, |reply| AgentCommand::Attach {
                reply,
                endpoint: id,
                half: Half::Tx(Box::new(tx)),
            })
            .map_err(EndpointError::Agent)?;
        let state = match links
            .receiver
            .commit(to_receiver, |reply| AgentCommand::Attach {
                reply,
                endpoint: id,
                half: Half::Rx(Box::new(rx)),
            }) {
            Ok(()) => State::Attaching {
                sender: Answer::Pending,
                receiver: Answer::Pending,
                reopen: None,
            },
            Err(error) => {
                self.entries.push(Entry {
                    id,
                    config,
                    local,
                    state: State::Failing {
                        error: EndpointError::Agent(error.clone()),
                        sender: Fate::Posted,
                        receiver: Fate::Done,
                    },
                });
                return Err(EndpointError::Agent(error));
            }
        };
        self.entries.push(Entry {
            id,
            config,
            local,
            state,
        });
        Ok(id)
    }

    /// Resets an active endpoint: its halves come back, it is reset,
    /// reopened at its next epoch and attached again
    /// ([`EndpointEvent::Reopened`]).
    ///
    /// # Errors
    ///
    /// [`EndpointError::Unknown`], [`EndpointError::Busy`] unless active,
    /// [`EndpointError::Agent`] when a ring has no room (nothing posted).
    pub fn reset(
        &mut self,
        links: &AgentLinks<O>,
        endpoint: EndpointId,
    ) -> Result<(), EndpointError> {
        self.detach(links, endpoint, Purpose::Reset)
    }

    /// Retires an active endpoint: its halves come back and its socket
    /// closes ([`EndpointEvent::Retired`]).
    ///
    /// # Errors
    ///
    /// As [`Endpoints::reset`].
    pub fn retire(
        &mut self,
        links: &AgentLinks<O>,
        endpoint: EndpointId,
    ) -> Result<(), EndpointError> {
        self.detach(links, endpoint, Purpose::Retire)
    }

    fn detach(
        &mut self,
        links: &AgentLinks<O>,
        endpoint: EndpointId,
        purpose: Purpose,
    ) -> Result<(), EndpointError> {
        let index = self.index(endpoint)?;
        let entry = self
            .entries
            .get_mut(index)
            .ok_or(EndpointError::Unknown(endpoint))?;
        if !matches!(entry.state, State::Active) {
            return Err(EndpointError::Busy(endpoint));
        }
        let to_sender = links.sender.prepare().map_err(EndpointError::Agent)?;
        let to_receiver = links.receiver.prepare().map_err(EndpointError::Agent)?;
        // A failed sender commit posts nothing: the entry stays active.
        links
            .sender
            .commit(to_sender, |reply| AgentCommand::Detach { reply, endpoint })
            .map_err(EndpointError::Agent)?;
        // The receiver gone: its half never comes back; the join then
        // fails and the endpoint is reported failed.
        let receiver_gone = links
            .receiver
            .commit(to_receiver, |reply| AgentCommand::Detach {
                reply,
                endpoint,
            })
            .is_err();
        entry.state = State::Detaching {
            purpose,
            tx: None,
            rx: None,
            sender: false,
            receiver: receiver_gone,
        };
        Ok(())
    }

    /// Serves the agents' endpoint answers and advances every entry,
    /// reporting endpoint events to `on_event`; other agent events go to
    /// `other`.
    pub fn poll(
        &mut self,
        links: &AgentLinks<O>,
        mut on_event: impl FnMut(EndpointEvent),
        mut other: impl FnMut(AgentEvent<O>),
    ) {
        for link in [&links.sender, &links.receiver] {
            while let Some(event) = link.take_event() {
                if let Some(event) = self.answer(event) {
                    other(event);
                }
            }
        }
        // Backwards, so a removed entry never makes the loop skip another.
        for index in (0..self.entries.len()).rev() {
            self.advance(links, index, &mut on_event);
        }
    }

    /// Applies one agent answer; returns events that are not about an
    /// endpoint of this table.
    fn answer(&mut self, event: AgentEvent<O>) -> Option<AgentEvent<O>> {
        let (endpoint, agent) = match &event {
            AgentEvent::Attached { agent, endpoint }
            | AgentEvent::Refused {
                agent, endpoint, ..
            }
            | AgentEvent::Detached {
                agent, endpoint, ..
            } => (*endpoint, *agent),
            AgentEvent::Pong { .. }
            | AgentEvent::Stopped { .. }
            | AgentEvent::PublicationAdded { .. }
            | AgentEvent::PublicationRefused { .. }
            | AgentEvent::CreateImage { .. }
            | AgentEvent::Configured { .. }
            | AgentEvent::ImageInstalled { .. }
            | AgentEvent::ImageReleased { .. }
            | AgentEvent::Unsupported { .. } => return Some(event),
        };
        let Ok(index) = self.index(endpoint) else {
            // An answer for an endpoint already gone: dropped (a half in
            // it closes its descriptor).
            return None;
        };
        let entry = self.entries.get_mut(index)?;
        match (event, &mut entry.state) {
            (
                AgentEvent::Attached { .. },
                State::Attaching {
                    sender, receiver, ..
                },
            ) => {
                *match agent {
                    AgentKind::Sender => sender,
                    AgentKind::Receiver => receiver,
                } = Answer::Attached;
            }
            (
                AgentEvent::Refused { half, .. },
                State::Attaching {
                    sender, receiver, ..
                },
            ) => {
                // A broken invariant: the refused half is dropped, closing
                // it; the other is brought back and closed.
                drop(half);
                let fate = |answer| match answer {
                    Answer::Pending => Fate::Posted,
                    Answer::Attached => Fate::Held,
                };
                let (sender, receiver) = match agent {
                    AgentKind::Sender => (Fate::Done, fate(*receiver)),
                    AgentKind::Receiver => (fate(*sender), Fate::Done),
                };
                entry.state = State::Failing {
                    error: EndpointError::Refused(agent),
                    sender,
                    receiver,
                };
            }
            (
                event,
                State::Failing {
                    sender, receiver, ..
                },
            ) => {
                let fate = match agent {
                    AgentKind::Sender => sender,
                    AgentKind::Receiver => receiver,
                };
                // Any half in the answer is dropped here, closing it.
                *fate = match (event, *fate) {
                    (AgentEvent::Attached { .. }, Fate::Posted) => Fate::Held,
                    (AgentEvent::Refused { .. } | AgentEvent::Detached { .. }, _) => Fate::Done,
                    (_, unchanged) => unchanged,
                };
            }
            (
                AgentEvent::Detached { half, .. },
                State::Detaching {
                    tx,
                    rx,
                    sender,
                    receiver,
                    ..
                },
            ) => {
                match half {
                    Some(Half::Tx(half)) => *tx = Some(*half),
                    Some(Half::Rx(half)) => *rx = Some(*half),
                    None => {}
                }
                match agent {
                    AgentKind::Sender => *sender = true,
                    AgentKind::Receiver => *receiver = true,
                }
            }
            // An answer that does not fit the entry's state: dropped.
            _ => {}
        }
        None
    }

    /// Advances one entry whose answers are in: reports an attachment,
    /// finishes a hand back, attaches a split endpoint or settles a
    /// failure.
    fn advance(
        &mut self,
        links: &AgentLinks<O>,
        index: usize,
        on_event: &mut impl FnMut(EndpointEvent),
    ) {
        let Some(entry) = self.entries.get_mut(index) else {
            return;
        };
        let id = entry.id;
        match &mut entry.state {
            State::Attaching {
                sender: Answer::Attached,
                receiver: Answer::Attached,
                reopen,
            } => {
                let event = match reopen {
                    None => EndpointEvent::Opened(id),
                    Some(returned) => EndpointEvent::Reopened {
                        endpoint: id,
                        returned: *returned,
                    },
                };
                entry.state = State::Active;
                on_event(event);
            }
            State::Detaching {
                sender: true,
                receiver: true,
                ..
            } => self.finish(index, on_event),
            State::Split { .. } => self.attach_split(links, index, on_event),
            State::Failing {
                error,
                sender,
                receiver,
            } => {
                for (agent, fate) in [
                    (AgentKind::Sender, &mut *sender),
                    (AgentKind::Receiver, &mut *receiver),
                ] {
                    if *fate != Fate::Held {
                        continue;
                    }
                    let link = link_of(links, agent);
                    // No room yet: tried again on the next poll.
                    let Ok(prepared) = link.prepare() else {
                        continue;
                    };
                    *fate = match link.commit(prepared, |reply| AgentCommand::Detach {
                        reply,
                        endpoint: id,
                    }) {
                        Ok(()) => Fate::Detaching,
                        // The agent is gone: its half comes back at reclaim.
                        Err(_) => Fate::Done,
                    };
                }
                if *sender == Fate::Done && *receiver == Fate::Done {
                    let error = error.clone();
                    self.entries.swap_remove(index);
                    on_event(EndpointEvent::Failed {
                        endpoint: id,
                        error,
                    });
                }
            }
            State::Attaching { .. } | State::Active | State::Detaching { .. } => {}
        }
    }

    /// Both halves are back: join, then reset, reopen and split, or
    /// retire.
    fn finish(&mut self, index: usize, on_event: &mut impl FnMut(EndpointEvent)) {
        let Some(entry) = self.entries.get_mut(index) else {
            return;
        };
        let State::Detaching {
            purpose, tx, rx, ..
        } = std::mem::replace(&mut entry.state, State::Active)
        else {
            return;
        };
        let id = entry.id;
        let config = entry.config;
        let joined = match (tx, rx) {
            (Some(tx), Some(rx)) => SocketsEndpoint::join(tx, rx).ok(),
            // A missing half: what came back is dropped, closing it.
            _ => None,
        };
        let Some(mut endpoint) = joined else {
            self.entries.swap_remove(index);
            on_event(EndpointEvent::Failed {
                endpoint: id,
                error: EndpointError::Join,
            });
            return;
        };
        match purpose {
            Purpose::Reset => {
                let outcome = Self::drain_reset(&mut endpoint, &mut self.report, id, on_event)
                    .and_then(|returned| {
                        endpoint
                            .reopen(&config)
                            .map(|snapshot| (returned, snapshot.local))
                            .map_err(EndpointError::Open)
                    })
                    .and_then(|(returned, local)| {
                        endpoint
                            .split()
                            .map(|halves| (halves, returned, local))
                            .map_err(|error| EndpointError::Split(error.error))
                    });
                match outcome {
                    Ok(((tx, rx), returned, local)) => {
                        if let Some(entry) = self.entries.get_mut(index) {
                            entry.local = local;
                            entry.state = State::Split { tx, rx, returned };
                        }
                    }
                    Err(error) => {
                        self.entries.swap_remove(index);
                        on_event(EndpointEvent::Failed {
                            endpoint: id,
                            error,
                        });
                    }
                }
            }
            Purpose::Retire => {
                let retired = Self::drain_retire(&mut endpoint, &mut self.report, id, on_event);
                self.entries.swap_remove(index);
                on_event(match retired {
                    Ok(returned) => EndpointEvent::Retired {
                        endpoint: id,
                        returned,
                    },
                    Err(error) => EndpointEvent::Failed {
                        endpoint: id,
                        error,
                    },
                });
            }
        }
    }

    /// Attaches the halves of a reset endpoint once both rings have room.
    fn attach_split(
        &mut self,
        links: &AgentLinks<O>,
        index: usize,
        on_event: &mut impl FnMut(EndpointEvent),
    ) {
        let Some(entry) = self.entries.get_mut(index) else {
            return;
        };
        if !matches!(entry.state, State::Split { .. }) {
            return;
        }
        let (Ok(to_sender), Ok(to_receiver)) = (links.sender.prepare(), links.receiver.prepare())
        else {
            return;
        };
        let State::Split { tx, rx, returned } = std::mem::replace(&mut entry.state, State::Active)
        else {
            return;
        };
        let id = entry.id;
        if let Err(error) = links
            .sender
            .commit(to_sender, |reply| AgentCommand::Attach {
                reply,
                endpoint: id,
                half: Half::Tx(Box::new(tx)),
            })
        {
            // Nothing posted: the halves are dropped, closing them.
            drop(rx);
            self.entries.swap_remove(index);
            on_event(EndpointEvent::Failed {
                endpoint: id,
                error: EndpointError::Agent(error),
            });
            return;
        }
        entry.state = match links
            .receiver
            .commit(to_receiver, |reply| AgentCommand::Attach {
                reply,
                endpoint: id,
                half: Half::Rx(Box::new(rx)),
            }) {
            Ok(()) => State::Attaching {
                sender: Answer::Pending,
                receiver: Answer::Pending,
                reopen: Some(returned),
            },
            Err(error) => State::Failing {
                error: EndpointError::Agent(error),
                sender: Fate::Posted,
                receiver: Fate::Done,
            },
        };
    }

    /// Resets until the endpoint has returned every item, reporting each.
    fn drain_reset(
        endpoint: &mut SocketsEndpoint<O>,
        report: &mut TxReport,
        id: EndpointId,
        on_event: &mut impl FnMut(EndpointEvent),
    ) -> Result<u32, EndpointError> {
        let mut returned = 0u32;
        for _ in 0..MAX_DRAIN_CALLS {
            let outcome = endpoint.reset(report);
            returned = returned
                .checked_add(Self::report_returned(report, id, on_event))
                .ok_or(EndpointError::Drain)?;
            if !outcome.more && !outcome.report_not_empty {
                return Ok(returned);
            }
        }
        Err(EndpointError::Drain)
    }

    /// Retires until complete, reporting each returned item.
    fn drain_retire(
        endpoint: &mut SocketsEndpoint<O>,
        report: &mut TxReport,
        id: EndpointId,
        on_event: &mut impl FnMut(EndpointEvent),
    ) -> Result<u32, EndpointError> {
        let mut returned = 0u32;
        for _ in 0..MAX_DRAIN_CALLS {
            let outcome = endpoint.retire(report);
            returned = returned
                .checked_add(Self::report_returned(report, id, on_event))
                .ok_or(EndpointError::Drain)?;
            if matches!(outcome, Retired::Complete { .. }) {
                return Ok(returned);
            }
        }
        Err(EndpointError::Drain)
    }

    /// Empties `report`, reporting each entry; returns how many.
    fn report_returned(
        report: &mut TxReport,
        id: EndpointId,
        on_event: &mut impl FnMut(EndpointEvent),
    ) -> u32 {
        let mut count = 0u32;
        // At most a report's capacity per call: no overflow.
        while let Some(entry) = report.pop_front() {
            count += 1;
            on_event(EndpointEvent::Returned {
                endpoint: id,
                entry,
            });
        }
        count
    }

    /// After a stop (DN-8): collects every half, from the agents (held, and
    /// in commands they never read), from the answers still unread in the
    /// links and from the table; joins and retires every endpoint whose two
    /// halves it finds and drops the others, so every descriptor closes.
    /// Returned items are reported to `on_event`; returns how many endpoints
    /// retired cleanly.
    pub fn reclaim(
        &mut self,
        links: &AgentLinks<O>,
        agents: &mut NetworkAgents<O>,
        mut on_event: impl FnMut(EndpointEvent),
    ) -> usize {
        let mut halves = Vec::new();
        halves.extend(agents.sender.take_halves());
        halves.extend(agents.receiver.take_halves());
        halves.extend(agents.sender.take_unread_halves());
        halves.extend(agents.receiver.take_unread_halves());
        for link in [&links.sender, &links.receiver] {
            while let Some(event) = link.take_event() {
                match event {
                    AgentEvent::Refused { endpoint, half, .. }
                    | AgentEvent::Detached {
                        endpoint,
                        half: Some(half),
                        ..
                    } => halves.push((endpoint, half)),
                    _ => {}
                }
            }
        }
        let mut txs = Vec::with_capacity(halves.len());
        let mut rxs = Vec::with_capacity(halves.len());
        for (id, half) in halves {
            match half {
                Half::Tx(tx) => txs.push((id, *tx)),
                Half::Rx(rx) => rxs.push((id, *rx)),
            }
        }
        for entry in self.entries.drain(..) {
            match entry.state {
                State::Detaching { tx, rx, .. } => {
                    txs.extend(tx.map(|tx| (entry.id, tx)));
                    rxs.extend(rx.map(|rx| (entry.id, rx)));
                }
                State::Split { tx, rx, .. } => {
                    txs.push((entry.id, tx));
                    rxs.push((entry.id, rx));
                }
                State::Attaching { .. } | State::Active | State::Failing { .. } => {}
            }
        }
        // At most one per collected TX half: no overflow.
        let mut retired = 0usize;
        for (id, tx) in txs {
            let Some(position) = rxs.iter().position(|(other, _)| *other == id) else {
                continue;
            };
            let (_, rx) = rxs.swap_remove(position);
            if let Ok(mut endpoint) = SocketsEndpoint::join(tx, rx)
                && Self::drain_retire(&mut endpoint, &mut self.report, id, &mut on_event).is_ok()
            {
                retired += 1;
            }
        }
        retired
    }
}

#[cfg(test)]
mod tests;
