// SPDX-License-Identifier: Apache-2.0

//! The network's half of the trace journals' glue (`quantstratum-docs:
//! karyos/design/trace-network.md` §4 and §5; P2.12 step 3, PR 3a): the
//! commands that hand hooks and journals to the agents, and their answers
//! queued for the conductor, which owns the journals' table entries.

use karyos_io::sockets::OsSocket;
use karyos_protocol::network::{Alias, Identity};
use karyos_protocol::trace_hook::{NetJournal, NetSide, PublicationIdentity};
use karyos_sys::frame::Lane;

use super::{Network, NetworkPublicationState};
use crate::agents::net_trace::{JournalFacts, TraceHook};
use crate::agents::{AgentCommand, AgentEvent, AgentLink, EndpointId};
use crate::sessions::receive::SlotRef;

/// The identity a trace journal names for the publication `identity`
/// sends under `alias` (§5).
#[must_use]
pub(crate) fn identity(identity: &Identity, alias: Alias) -> PublicationIdentity {
    PublicationIdentity {
        driver: identity.driver_id,
        registration: identity.registration_id,
        stream_id: alias.stream_id,
        session_id: alias.session_id,
        incarnation: identity.incarnation,
    }
}

/// What the conductor learns about network journals in a cycle.
#[derive(Debug)]
pub(crate) enum TraceEvent {
    /// An agent holds its new hook; the previous one was dropped here, on
    /// the control path.
    Set,
    /// Journal `number` starts at `start` (§5, the start fact).
    Opened {
        /// The journal number.
        number: u64,
        /// The start.
        start: u64,
    },
    /// The agent could not write the journal, which comes back.
    Refused {
        /// The journal.
        journal: NetJournal,
    },
    /// The agent closed journal `number`, with its facts, or without when
    /// it had no such journal.
    Closed {
        /// The journal number.
        number: u64,
        /// Its facts.
        facts: Option<JournalFacts>,
    },
    /// The publication `registration` became active: its sender journals
    /// can open.
    PublicationActive {
        /// The aggregate's registration.
        registration: u64,
    },
    /// The publication `registration` is gone from the sender.
    PublicationRemoved {
        /// The identity its journals named.
        traced: PublicationIdentity,
    },
}

impl TraceEvent {
    /// Hands the trace event `event` is to `trace`; any other event comes
    /// back.
    pub(crate) fn route(
        event: AgentEvent<OsSocket>,
        trace: impl FnOnce(Self),
    ) -> Option<AgentEvent<OsSocket>> {
        let traced = match event {
            AgentEvent::NetworkTraceSet { previous, .. } => {
                // The agent closed the journals the previous hook held; the
                // conductor counted them when it set the new one.
                drop(previous);
                Self::Set
            }
            AgentEvent::NetworkJournalOpened { number, start, .. } => {
                Self::Opened { number, start }
            }
            AgentEvent::NetworkJournalRefused { journal, .. } => Self::Refused { journal },
            AgentEvent::NetworkJournalClosed { number, facts, .. } => {
                Self::Closed { number, facts }
            }
            other => return Some(other),
        };
        trace(traced);
        None
    }
}

/// How a journal handed to an agent fared.
#[derive(Debug)]
pub(crate) enum Handed {
    /// Posted: the agent answers it.
    Posted,
    /// No room in the ring: the journal comes back.
    Busy(NetJournal),
    /// The agent is gone, and the journal with the command.
    Gone,
}

/// A traced object's lanes and where its journals go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Traced {
    /// The identity its journals name.
    pub(crate) publication: PublicationIdentity,
    /// The endpoint.
    pub(crate) endpoint: EndpointId,
    /// The alias the agent knows it by.
    pub(crate) alias: Alias,
    /// Its lane count.
    pub(crate) lanes: usize,
    /// The aggregate's registration on this driver; `0` for an unexposed
    /// image.
    pub(crate) registration: u64,
}

impl Network {
    fn link(&self, side: NetSide) -> &AgentLink<OsSocket> {
        match side {
            NetSide::Sender => &self.links.sender,
            NetSide::Receiver => &self.links.receiver,
        }
    }

    /// Hands `hook` to the agent of `side`; the hook comes back when the
    /// ring has no room. A gone agent drops it.
    pub(crate) fn post_trace_hook(
        &self,
        side: NetSide,
        hook: Option<TraceHook>,
    ) -> Result<(), Option<TraceHook>> {
        let link = self.link(side);
        let Ok(prepared) = link.prepare() else {
            return Err(hook);
        };
        let _ = link.commit(prepared, |reply| AgentCommand::SetNetworkTrace {
            reply,
            hook,
        });
        Ok(())
    }

    /// Hands `journal` to the agent of its side, for the publication
    /// `alias` on `endpoint`.
    pub(crate) fn post_open_journal(
        &self,
        endpoint: EndpointId,
        alias: Alias,
        journal: NetJournal,
    ) -> Handed {
        let link = self.link(journal.side);
        let Ok(prepared) = link.prepare() else {
            return Handed::Busy(journal);
        };
        match link.commit(prepared, |reply| AgentCommand::OpenNetworkJournal {
            reply,
            endpoint,
            alias,
            journal,
        }) {
            Ok(()) => Handed::Posted,
            Err(_) => Handed::Gone,
        }
    }

    /// Asks the agent of `side` to close journal `number`; `false` when
    /// the ring has no room or the agent is gone.
    pub(crate) fn post_close_journal(
        &self,
        side: NetSide,
        publication: PublicationIdentity,
        lane: Lane,
        number: u64,
    ) -> bool {
        self.link(side)
            .post(|reply| AgentCommand::CloseNetworkJournal {
                reply,
                publication,
                lane,
                number,
            })
            .is_ok()
    }

    /// The active publication `registration`, as its sender journals see
    /// it.
    #[must_use]
    pub(crate) fn traced_publication(&self, registration: u64) -> Option<Traced> {
        self.publications
            .iter()
            .find(|entry| {
                entry.registration == registration && entry.state == NetworkPublicationState::Active
            })
            .map(|entry| Traced {
                publication: entry.traced,
                endpoint: entry.endpoint,
                alias: entry.alias,
                lanes: usize::from(entry.lanes),
                registration: entry.registration,
            })
    }

    /// The registrations of the active publications.
    #[must_use]
    pub(crate) fn active_publications(&self) -> Vec<u64> {
        self.publications
            .iter()
            .filter(|entry| entry.state == NetworkPublicationState::Active)
            .map(|entry| entry.registration)
            .collect()
    }

    /// The installed image `slot`, as its receiver journals see it.
    #[must_use]
    pub(crate) fn traced_image(&self, slot: SlotRef) -> Option<Traced> {
        self.net_images
            .iter()
            .find(|image| image.slot == slot)
            .map(|image| Traced {
                publication: image.traced,
                endpoint: image.endpoint,
                alias: Alias {
                    session_id: image.traced.session_id,
                    stream_id: image.traced.stream_id,
                },
                lanes: image.lanes,
                registration: image.exposed.map_or(0, |handle| handle.registration()),
            })
    }

    /// The slots of the installed images.
    #[must_use]
    pub(crate) fn installed_images(&self) -> Vec<SlotRef> {
        self.net_images.iter().map(|image| image.slot).collect()
    }

    /// Takes the cycle's trace events; hand the buffer back with
    /// [`Network::return_trace_events`].
    pub(crate) fn take_trace_events(&mut self) -> Vec<TraceEvent> {
        core::mem::take(&mut self.trace_events)
    }

    /// Returns the buffer [`Network::take_trace_events`] took, emptied.
    pub(crate) fn return_trace_events(&mut self, mut events: Vec<TraceEvent>) {
        events.clear();
        self.trace_events = events;
    }
}
