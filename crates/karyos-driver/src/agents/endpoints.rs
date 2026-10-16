// SPDX-License-Identifier: Apache-2.0

//! The conductor's endpoint table (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §2.4 and §4.2, phase 3;
//! `sockets-backend.md` 3.10): the conductor opens each sockets endpoint,
//! splits it and hands the TX half to the sender agent and the RX half to
//! the receiver agent. Socket life changes only while the conductor holds
//! the joined endpoint:
//!
//! - **Open.** Both agents' command and reply slots are reserved before the
//!   socket is opened, so an open either attaches both halves or leaves
//!   nothing behind.
//! - **Reset.** The conductor asks both agents for their halves, joins
//!   them, resets the endpoint (draining the items it returns), reopens it
//!   with the next epoch, splits it and attaches the new halves.
//! - **Retire.** The same hand back and join, then `retire` until complete:
//!   the socket closes and the entry leaves the table.
//! - **Stop.** After the runner hands the agents back (DN-8),
//!   [`Endpoints::reclaim`] takes their halves, joins and retires every
//!   endpoint, so every descriptor is closed.
//!
//! Every step runs on the control path; the table holds at most
//! `max_endpoints` entries, allocated at creation.

use karyos_io::backend::{InstanceId, OpenError, TxReport};
use karyos_io::sockets::endpoint::{
    Retired, SocketsConfig, SocketsEndpoint, SocketsRx, SocketsTx, SplitFailure,
};
use karyos_io::sockets::ops::SocketOps;

use super::{AgentCommand, AgentError, AgentEvent, AgentKind, AgentLinks, EndpointId, Half};

/// Why an endpoint operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// The table holds `max_endpoints` entries.
    #[error("the endpoint table is full")]
    TableFull,
    /// No entry of that id.
    #[error("unknown endpoint {0:?}")]
    Unknown(EndpointId),
    /// The endpoint is resetting, retiring or attaching.
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
    /// A reset finished: the endpoint is active again, at its next epoch.
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
    /// The endpoint failed and was retired; its socket is closed.
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

/// An entry's state.
enum State<O: SocketOps> {
    /// Both halves were posted; waiting for both answers.
    Attaching { sender: bool, receiver: bool },
    /// Both agents hold their halves.
    Active,
    /// Waiting for both halves to come back.
    Detaching {
        purpose: Purpose,
        tx: Option<SocketsTx<O>>,
        rx: Option<SocketsRx<O>>,
        answers: u8,
    },
    /// Reopened and split, waiting for ring room to attach the halves.
    Split {
        tx: SocketsTx<O>,
        rx: SocketsRx<O>,
        returned: u32,
    },
}

struct Entry<O: SocketOps> {
    id: EndpointId,
    config: SocketsConfig,
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

impl<O: SocketOps> Endpoints<O> {
    /// A table sized for the agents of `config`: at most their
    /// `max_endpoints` endpoints, so no agent refuses a half for room.
    #[must_use]
    pub fn new(config: &super::AgentConfig) -> Self {
        let max = config.max_endpoints;
        Self {
            entries: Vec::with_capacity(max),
            max,
            next: Some(InstanceId::FIRST),
            report: TxReport::new(),
        }
    }

    /// The endpoints in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `endpoint` is active.
    #[must_use]
    pub fn is_active(&self, endpoint: EndpointId) -> bool {
        self.entry(endpoint)
            .is_some_and(|entry| matches!(entry.state, State::Active))
    }

    fn entry(&self, endpoint: EndpointId) -> Option<&Entry<O>> {
        self.entries.iter().find(|entry| entry.id == endpoint)
    }

    fn index(&self, endpoint: EndpointId) -> Result<usize, EndpointError> {
        self.entries
            .iter()
            .position(|entry| entry.id == endpoint)
            .ok_or(EndpointError::Unknown(endpoint))
    }

    /// Opens an endpoint over `ops`, splits it and attaches its halves to
    /// the agents; [`EndpointEvent::Opened`] follows once both answered.
    /// On error nothing is left open or posted.
    ///
    /// # Errors
    ///
    /// [`EndpointError::TableFull`], [`EndpointError::Agent`] when a ring
    /// has no room, [`EndpointError::Open`], [`EndpointError::Split`],
    /// [`EndpointError::Exhausted`].
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
        // Nothing to undo if the identities run out later: the counter
        // only moves forward.
        self.next = instance.next().ok();
        // A refused split drops the endpoint, which closes its socket.
        let (tx, rx) = endpoint
            .split()
            .map_err(|error| EndpointError::Split(error.error))?;
        let id = EndpointId(instance.get().get());
        links
            .sender
            .commit(to_sender, |reply| AgentCommand::Attach {
                reply,
                endpoint: id,
                half: Half::Tx(Box::new(tx)),
            })
            .map_err(EndpointError::Agent)?;
        links
            .receiver
            .commit(to_receiver, |reply| AgentCommand::Attach {
                reply,
                endpoint: id,
                half: Half::Rx(Box::new(rx)),
            })
            .map_err(EndpointError::Agent)?;
        self.entries.push(Entry {
            id,
            config,
            state: State::Attaching {
                sender: false,
                receiver: false,
            },
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
        for (link, prepared) in [(&links.sender, to_sender), (&links.receiver, to_receiver)] {
            link.commit(prepared, |reply| AgentCommand::Detach { reply, endpoint })
                .map_err(EndpointError::Agent)?;
        }
        entry.state = State::Detaching {
            purpose,
            tx: None,
            rx: None,
            answers: 0,
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
                if let Some(event) = self.answer(event, &mut on_event) {
                    other(event);
                }
            }
        }
        // Entries split after a reset, waiting for ring room.
        for index in 0..self.entries.len() {
            self.attach_split(links, index, &mut on_event);
        }
    }

    /// Applies one agent answer; returns events that are not about an
    /// endpoint of this table.
    fn answer(
        &mut self,
        event: AgentEvent<O>,
        on_event: &mut impl FnMut(EndpointEvent),
    ) -> Option<AgentEvent<O>> {
        let (endpoint, agent) = match &event {
            AgentEvent::Attached { agent, endpoint }
            | AgentEvent::Refused {
                agent, endpoint, ..
            }
            | AgentEvent::Detached {
                agent, endpoint, ..
            } => (*endpoint, *agent),
            AgentEvent::Pong { .. } | AgentEvent::Stopped { .. } => return Some(event),
        };
        let Ok(index) = self.index(endpoint) else {
            // An answer for an endpoint already gone: drop it (a half in it
            // closes its descriptor).
            return None;
        };
        let entry = self.entries.get_mut(index)?;
        match (event, &mut entry.state) {
            (AgentEvent::Attached { .. }, State::Attaching { sender, receiver }) => {
                match agent {
                    AgentKind::Sender => *sender = true,
                    AgentKind::Receiver => *receiver = true,
                }
                if *sender && *receiver {
                    entry.state = State::Active;
                    on_event(EndpointEvent::Opened(endpoint));
                }
            }
            (AgentEvent::Refused { half, .. }, State::Attaching { .. }) => {
                // A broken invariant: the table is sized from the agents'
                // capacity and every id is new. The refused half is
                // dropped, closing its descriptor; the entry becomes active
                // so that `retire` brings the other half back and closes
                // it.
                drop(half);
                entry.state = State::Active;
                on_event(EndpointEvent::Failed {
                    endpoint,
                    error: EndpointError::Refused(agent),
                });
            }
            (
                AgentEvent::Detached { half, .. },
                State::Detaching {
                    tx, rx, answers, ..
                },
            ) => {
                match half {
                    Some(Half::Tx(half)) => *tx = Some(*half),
                    Some(Half::Rx(half)) => *rx = Some(*half),
                    None => {}
                }
                // Two answers at most: one per agent.
                *answers = answers.checked_add(1).unwrap_or(u8::MAX);
                if *answers >= 2 {
                    self.finish(index, on_event);
                }
            }
            // An answer that does not fit the entry's state: dropped.
            _ => {}
        }
        None
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
        let (Some(tx), Some(rx)) = (tx, rx) else {
            // A half was missing: what came back is dropped, closing it.
            self.entries.swap_remove(index);
            on_event(EndpointEvent::Failed {
                endpoint: id,
                error: EndpointError::Join,
            });
            return;
        };
        let Ok(mut endpoint) = SocketsEndpoint::join(tx, rx) else {
            self.entries.swap_remove(index);
            on_event(EndpointEvent::Failed {
                endpoint: id,
                error: EndpointError::Join,
            });
            return;
        };
        let failed = |error| EndpointEvent::Failed {
            endpoint: id,
            error,
        };
        match purpose {
            Purpose::Reset => {
                let outcome = Self::drain_reset(&mut endpoint, &mut self.report)
                    .and_then(|returned| {
                        endpoint
                            .reopen(&config)
                            .map(|_| returned)
                            .map_err(EndpointError::Open)
                    })
                    .and_then(|returned| {
                        endpoint
                            .split()
                            .map(|halves| (halves, returned))
                            .map_err(|error| EndpointError::Split(error.error))
                    });
                match outcome {
                    Ok(((tx, rx), returned)) => {
                        if let Some(entry) = self.entries.get_mut(index) {
                            entry.state = State::Split { tx, rx, returned };
                        }
                    }
                    Err(error) => {
                        self.entries.swap_remove(index);
                        on_event(failed(error));
                    }
                }
            }
            Purpose::Retire => {
                let retired = Self::drain_retire(&mut endpoint, &mut self.report);
                self.entries.swap_remove(index);
                match retired {
                    Ok(returned) => on_event(EndpointEvent::Retired {
                        endpoint: id,
                        returned,
                    }),
                    Err(error) => on_event(failed(error)),
                }
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
        let State::Split { tx, rx, returned } = std::mem::replace(
            &mut entry.state,
            State::Attaching {
                sender: false,
                receiver: false,
            },
        ) else {
            return;
        };
        let id = entry.id;
        let posted = links
            .sender
            .commit(to_sender, |reply| AgentCommand::Attach {
                reply,
                endpoint: id,
                half: Half::Tx(Box::new(tx)),
            })
            .and_then(|()| {
                links
                    .receiver
                    .commit(to_receiver, |reply| AgentCommand::Attach {
                        reply,
                        endpoint: id,
                        half: Half::Rx(Box::new(rx)),
                    })
            });
        match posted {
            Ok(()) => on_event(EndpointEvent::Reopened {
                endpoint: id,
                returned,
            }),
            Err(error) => {
                self.entries.swap_remove(index);
                on_event(EndpointEvent::Failed {
                    endpoint: id,
                    error: EndpointError::Agent(error),
                });
            }
        }
    }

    /// Resets until the endpoint has returned every item.
    fn drain_reset(
        endpoint: &mut SocketsEndpoint<O>,
        report: &mut TxReport,
    ) -> Result<u32, EndpointError> {
        let mut returned = 0u32;
        for _ in 0..MAX_DRAIN_CALLS {
            let outcome = endpoint.reset(report);
            returned = returned
                .checked_add(u32::from(outcome.returned))
                .ok_or(EndpointError::Drain)?;
            while report.pop_front().is_some() {}
            if !outcome.more && !outcome.report_not_empty {
                return Ok(returned);
            }
        }
        Err(EndpointError::Drain)
    }

    /// Retires until complete.
    fn drain_retire(
        endpoint: &mut SocketsEndpoint<O>,
        report: &mut TxReport,
    ) -> Result<u32, EndpointError> {
        let mut returned = 0u32;
        for _ in 0..MAX_DRAIN_CALLS {
            let outcome = endpoint.retire(report);
            while report.pop_front().is_some() {}
            match outcome {
                Retired::Complete { returned: last } => {
                    return returned
                        .checked_add(u32::from(last))
                        .ok_or(EndpointError::Drain);
                }
                Retired::More { returned: some } => {
                    returned = returned
                        .checked_add(u32::from(some))
                        .ok_or(EndpointError::Drain)?;
                }
                Retired::ReportNotEmpty | Retired::ResetIncomplete => {}
            }
        }
        Err(EndpointError::Drain)
    }

    /// After a stop (DN-8): joins the halves the agents handed back with
    /// [`super::SenderAgent::take_halves`] and
    /// [`super::ReceiverAgent::take_halves`] and retires every endpoint, so
    /// every descriptor closes. Returns how many endpoints retired cleanly;
    /// halves without a partner are dropped, which closes them too.
    pub fn reclaim(&mut self, halves: impl IntoIterator<Item = (EndpointId, Half<O>)>) -> usize {
        let mut txs = Vec::with_capacity(self.entries.len());
        let mut rxs = Vec::with_capacity(self.entries.len());
        for (id, half) in halves {
            match half {
                Half::Tx(tx) => txs.push((id, *tx)),
                Half::Rx(rx) => rxs.push((id, *rx)),
            }
        }
        // Halves held in the table itself (mid reset or retirement).
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
                State::Attaching { .. } | State::Active => {}
            }
        }
        // At most one per table entry: no overflow.
        let mut retired = 0usize;
        for (id, tx) in txs {
            let Some(position) = rxs.iter().position(|(other, _)| *other == id) else {
                continue;
            };
            let (_, rx) = rxs.swap_remove(position);
            if let Ok(mut endpoint) = SocketsEndpoint::join(tx, rx)
                && Self::drain_retire(&mut endpoint, &mut self.report).is_ok()
            {
                retired += 1;
            }
        }
        retired
    }
}

#[cfg(test)]
mod tests;
