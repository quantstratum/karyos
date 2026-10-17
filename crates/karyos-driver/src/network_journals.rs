// SPDX-License-Identifier: Apache-2.0

//! The network trace journals of the driver's sender and receiver agents
//! (`quantstratum-docs: karyos/design/trace-network.md` §4 and §5, NT-1,
//! NT-3 and NT-4).
//!
//! - **Hooks.** The application (or `karyosd`) sets one
//!   [`NetworkTraceHook`] per side, sender or receiver, on the control
//!   path. The conductor hands it to that side's agent, which calls it on
//!   the data path. Network journals exist only while their side has a
//!   hook; removing or replacing it closes its open journals, without
//!   facts (`Lost`), counted apart from refusals.
//! - **Creation.** One journal per lane of a publication incarnation on the
//!   sender, and of an image on the receiver, created on the control path
//!   only (ACS 15498): a heap journal of `network_journal_records` records
//!   charged to `max_network_journal_bytes`, in the trace mirror's table
//!   with the same mirror sequence as client journals (T7): per lane of a
//!   publication once the sender added it, and of an image once it is
//!   installed. Its writer goes to the agent, which hands it to the hook
//!   ([`NetworkTraceHook::open_journal`]); the driver keeps the drain, and
//!   the duty cycle mirrors it with the client journals. A journal the
//!   agent cannot take comes back, and is closed and counted as refused.
//! - **Refusal.** A journal over the budget, or that finds no free table
//!   entry, is not created and never reaches the hook: the mirror's header
//!   word 7, the driver counter and the publication's refused count rise
//!   (all three even when the header count cannot, ACS 15639). The refused
//!   counts live in a table of `max_trace_journals` publications, reserved
//!   at start; a publication's count is dropped when the agent forgets the
//!   publication (it closed, or its image retired). A refusal the full table
//!   cannot hold is counted as untracked, and every publication the table
//!   does not name then reports that count, so no refused journal is ever
//!   reported as none.
//! - **Facts.** The start (pickup start or image join) is the agent's
//!   answer to the journal (§5, ACS 15840); the boundary (pickup or commit
//!   boundary) and a receiver's first sealed gap come with its close.
//! - **Close.** A publication's journals close before the sender removes
//!   it; an image's when it retires, through the receiver, which also
//!   posts them unsolicited. The close names the journal number. The hook
//!   closes the writer ([`NetworkTraceHook::close_journal`]) and the driver
//!   drains the journal to its end, as for a client journal.

use crate::agents::net_trace::TraceHook;
use crate::embedded::StreamTerms;
use crate::net::trace::{Handed, TraceEvent, Traced};
use crate::sessions::receive::SlotRef;
use karyos_protocol::trace_hook::{
    HOST_MONOTONIC_PROVENANCE, NetJournal, NetSide, NetworkTraceHook, PublicationIdentity,
    TRACE_RECORD_WORDS,
};
use karyos_sys::frame::Lane;
use karyos_sys::record_journal::{JournalLayout, journal_block};
use karyos_sys::trace_mirror::{JournalKind, NetworkFacts, TimeNamespace};

use crate::embedded::EmbeddedDriver;
use crate::trace_journals::Observed;

/// A network journal the driver created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Open {
    side: NetSide,
    publication: PublicationIdentity,
    lane: Lane,
    journal: u64,
    /// A receiver journal's image.
    image: Option<SlotRef>,
    /// Whether its close is posted to the agent.
    close_posted: bool,
}

/// The hooks' state, the open network journals and the refused counts.
pub(crate) struct NetworkTracing {
    /// Whether the sender and the receiver have a hook.
    hooked: [bool; 2],
    /// A hook change not handed to its agent yet (its ring was full).
    pending: [Option<Option<TraceHook>>; 2],
    open: Vec<Open>,
    /// Refused journals per publication, for the in-process report (§5):
    /// at most its reserved capacity.
    refused: Vec<(PublicationIdentity, u64)>,
    /// Refusals of publications the full table could not hold.
    untracked: u64,
}

impl core::fmt::Debug for NetworkTracing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetworkTracing")
            .field("hooked", &self.hooked)
            .field("pending", &self.pending.each_ref().map(Option::is_some))
            .field("open", &self.open)
            .field("refused", &self.refused)
            .field("untracked", &self.untracked)
            .finish()
    }
}

const fn slot(side: NetSide) -> usize {
    match side {
        NetSide::Sender => 0,
        NetSide::Receiver => 1,
    }
}

impl NetworkTracing {
    /// No hooks, with room for the refused counts of `publications`
    /// publications (control path).
    pub(crate) fn new(publications: usize) -> Self {
        Self {
            hooked: [false, false],
            pending: [None, None],
            open: Vec::new(),
            refused: Vec::with_capacity(publications),
            untracked: 0,
        }
    }

    /// Whether journals of `side` can open now: its agent holds a hook.
    fn ready(&self, side: NetSide) -> bool {
        self.hooked.get(slot(side)).copied().unwrap_or(false)
            && self.pending.get(slot(side)).is_some_and(Option::is_none)
    }

    fn position(&self, journal: u64) -> Option<usize> {
        self.open.iter().position(|open| open.journal == journal)
    }

    fn find(&self, side: NetSide, publication: &PublicationIdentity, lane: Lane) -> Option<usize> {
        self.open
            .iter()
            .position(|open| (open.side, open.publication, open.lane) == (side, *publication, lane))
    }
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Sets the network trace hook of `side`, or removes it with `None`
    /// (control path). Its agent closes the journals the previous hook
    /// held, through it, without facts: each is `Lost`, and counted
    /// (`network trace journals unhooked`). A new hook gets a journal per
    /// lane of every publication or image already there.
    pub fn set_network_trace_hook(
        &mut self,
        side: NetSide,
        hook: Option<Box<dyn NetworkTraceHook>>,
    ) {
        for _ in self.network.open.iter().filter(|open| open.side == side) {
            self.counters
                .add(crate::counters::Event::NetworkTraceJournalsUnhooked, 1);
        }
        self.network.open.retain(|open| open.side != side);
        if let Some(hooked) = self.network.hooked.get_mut(slot(side)) {
            *hooked = hook.is_some();
        }
        if let Some(pending) = self.network.pending.get_mut(slot(side)) {
            *pending = Some(hook.map(TraceHook));
        }
        self.post_trace_hooks();
    }

    /// Hands each pending hook to its agent; a full ring keeps it for the
    /// next cycle. Without a network there is no agent: the hook drops.
    /// Once a new hook is handed over, every publication or image already
    /// there gets its journals.
    fn post_trace_hooks(&mut self) {
        for side in [NetSide::Sender, NetSide::Receiver] {
            let Some(hook) = self
                .network
                .pending
                .get_mut(slot(side))
                .and_then(Option::take)
            else {
                continue;
            };
            let Some(net) = &self.net else {
                continue;
            };
            if let Err(hook) = net.post_trace_hook(side, hook) {
                if let Some(pending) = self.network.pending.get_mut(slot(side)) {
                    *pending = Some(hook);
                }
                continue;
            }
            if !self.network.ready(side) {
                continue;
            }
            match side {
                NetSide::Sender => {
                    for registration in net.active_publications() {
                        self.open_publication_journals(registration);
                    }
                }
                NetSide::Receiver => {
                    for image in net.installed_images() {
                        self.open_image_journals(image);
                    }
                }
            }
        }
    }

    /// One cycle of the network journals' glue: pending hooks go to their
    /// agents, and the agents' answers are applied.
    pub(crate) fn serve_network_trace(&mut self) {
        self.post_trace_hooks();
        let Some(events) = self
            .net
            .as_mut()
            .map(crate::net::Network::take_trace_events)
        else {
            return;
        };
        let mut events = events;
        for event in events.drain(..) {
            self.apply_trace_event(event);
        }
        if let Some(net) = &mut self.net {
            net.return_trace_events(events);
        }
    }

    /// Applies one agent answer, or a publication's change.
    pub(crate) fn apply_trace_event(&mut self, event: TraceEvent) {
        match event {
            TraceEvent::Set => {}
            TraceEvent::Opened { number, start } => {
                let _ = self.trace_journals.update_network(number, |facts| {
                    facts.start = Some(start);
                });
            }
            TraceEvent::Refused { journal } => self.refuse_handed(journal),
            TraceEvent::Closed { number, facts } => {
                let Some(index) = self.network.position(number) else {
                    // Already closed: the unsolicited close of a retired
                    // image and the answer to the conductor's own.
                    return;
                };
                let open = self.network.open.swap_remove(index);
                if let Some(facts) = facts {
                    let receiver = open.side == NetSide::Receiver;
                    let _ = self.trace_journals.update_network(number, |recorded| {
                        recorded.boundary = Some(facts.boundary);
                        if receiver && recorded.first_gap.is_none() {
                            recorded.first_gap = facts.first_gap;
                        }
                    });
                }
            }
            TraceEvent::PublicationActive { registration } => {
                self.open_publication_journals(registration);
            }
            TraceEvent::PublicationRemoved { traced } => {
                self.forget_network_publication(&traced);
            }
        }
    }

    /// Opens a sender journal per lane of the active publication
    /// `registration`.
    fn open_publication_journals(&mut self, registration: u64) {
        let Some(traced) = self
            .net
            .as_ref()
            .and_then(|net| net.traced_publication(registration))
        else {
            return;
        };
        self.open_traced(NetSide::Sender, traced, None);
    }

    /// Opens a receiver journal per lane of the installed image `image`.
    pub(crate) fn open_image_journals(&mut self, image: SlotRef) {
        let Some(traced) = self.net.as_ref().and_then(|net| net.traced_image(image)) else {
            return;
        };
        self.open_traced(NetSide::Receiver, traced, Some(image));
    }

    fn open_traced(&mut self, side: NetSide, traced: Traced, image: Option<SlotRef>) {
        for lane in 0..traced.lanes {
            let Some(lane) = u8::try_from(lane)
                .ok()
                .and_then(|lane| Lane::try_new(lane).ok())
            else {
                return;
            };
            let Some(journal) = self.open_network_journal(
                side,
                traced.publication,
                lane,
                traced.registration,
                None,
            ) else {
                continue;
            };
            let number = journal.number;
            if let Some(index) = self.network.position(number)
                && let Some(open) = self.network.open.get_mut(index)
            {
                open.image = image;
            }
            let Some(net) = &self.net else {
                return;
            };
            match net.post_open_journal(traced.endpoint, traced.alias, journal) {
                Handed::Posted => {}
                Handed::Busy(journal) => self.refuse_handed(journal),
                // The journal dropped with the command: its writer closed,
                // with no start, so it is `Lost`.
                Handed::Gone => {
                    if let Some(index) = self.network.position(number) {
                        self.network.open.swap_remove(index);
                    }
                }
            }
        }
    }

    /// A journal no agent took: it closes (its writer drops, with no
    /// start, so it is `Lost`) and counts as refused (§5), so no trace of
    /// its publication is reported `Complete`.
    fn refuse_handed(&mut self, journal: NetJournal) {
        if let Some(index) = self.network.position(journal.number) {
            self.network.open.swap_remove(index);
        }
        let publication = journal.publication;
        drop(journal);
        self.refuse_network_journal(publication);
    }

    /// The sender journals of publication `registration` to close before
    /// its removal: `(lane, journal number)`, each marked posted.
    pub(crate) fn publication_journal_closes(&mut self, registration: u64) -> Vec<(Lane, u64)> {
        let driver = self.driver_id;
        self.network
            .open
            .iter_mut()
            .filter(|open| {
                open.side == NetSide::Sender
                    && !open.close_posted
                    && (open.publication.driver, open.publication.registration)
                        == (driver, registration)
            })
            .map(|open| {
                open.close_posted = true;
                (open.lane, open.journal)
            })
            .collect()
    }

    /// The image `image` retires: its receiver journals are closed by the
    /// receiver, which posts them unsolicited; the conductor asks for each
    /// too, so none waits on a dropped one. A close that finds no room
    /// leaves the journal `Lost`.
    pub(crate) fn close_image_journals(&mut self, image: SlotRef) {
        let Some(net) = &self.net else {
            return;
        };
        let mut lost = Vec::new();
        for open in self
            .network
            .open
            .iter_mut()
            .filter(|open| open.image == Some(image) && !open.close_posted)
        {
            open.close_posted = true;
            if !net.post_close_journal(open.side, open.publication, open.lane, open.journal) {
                lost.push(open.journal);
            }
        }
        for journal in lost {
            if let Some(index) = self.network.position(journal) {
                self.network.open.swap_remove(index);
            }
        }
    }

    /// Network journals of `publication` refused so far (§5): a report
    /// gives no trace of such a publication a final `Complete`.
    #[must_use]
    pub fn network_journals_refused(&self, publication: &PublicationIdentity) -> u64 {
        self.network
            .refused
            .iter()
            .find(|(refused, _)| refused == publication)
            .map_or(self.network.untracked, |(_, count)| *count)
    }

    /// Drops the refused count of `publication` (control path): it closed,
    /// or its image retired, so no report can still need it.
    pub(crate) fn forget_network_publication(&mut self, publication: &PublicationIdentity) {
        self.network
            .refused
            .retain(|(refused, _)| refused != publication);
    }

    /// Opens the network journal of `side` for `lane` of `publication`
    /// (control path): `registration` is the publication's on the sender,
    /// the image's on the receiver, and `start` the pickup start or the
    /// image join, if known. Returns the journal, for its agent; `None`
    /// without a hook for `side`, for a journal already open, or for a
    /// refused one, which is counted.
    pub(crate) fn open_network_journal(
        &mut self,
        side: NetSide,
        publication: PublicationIdentity,
        lane: Lane,
        registration: u64,
        start: Option<u64>,
    ) -> Option<NetJournal> {
        if !self.network.ready(side) || self.network.find(side, &publication, lane).is_some() {
            return None;
        }
        let layout = JournalLayout {
            capacity: self.config.network_journal_records,
            payload_words: TRACE_RECORD_WORDS,
            drop_ranges: karyos_sys::trace_mirror::MIRROR_RANGES,
        };
        let reserved = self.trace_journals.preflight_network(&layout);
        let journal = self.next_trace_number;
        let next = journal.checked_add(1);
        let block = match (&reserved, next) {
            (Ok(_), Some(_)) => journal_block(layout).ok(),
            _ => None,
        };
        let (Ok(reserved), Some(next), Some((writer, drain))) = (reserved, next, block) else {
            self.refuse_network_journal(publication);
            return None;
        };
        self.next_trace_number = next;
        let (kind, covers) = match side {
            NetSide::Sender => (JournalKind::NetworkSender, true),
            // Only a publication this driver sends has local `Publish`
            // records to cover (T5).
            NetSide::Receiver => (
                JournalKind::NetworkReceiver,
                publication.driver == self.driver_id,
            ),
        };
        let observed = Observed {
            kind,
            registration,
            stream: publication.registration,
            lane,
            incarnation: publication.incarnation,
            join: None,
            time_namespace: TimeNamespace::Same,
            provenance: HOST_MONOTONIC_PROVENANCE,
            network: Some(NetworkFacts {
                sender_driver: publication.driver,
                start,
                boundary: None,
                first_gap: None,
            }),
            covers,
        };
        self.trace_journals
            .insert(reserved, journal, 0, observed, drain);
        self.network.open.push(Open {
            side,
            publication,
            lane,
            journal,
            image: None,
            close_posted: false,
        });
        Some(NetJournal {
            side,
            publication,
            lane,
            number: journal,
            writer,
        })
    }

    /// Closes the network journal of `side` for `lane` of `publication`
    /// in the table (control path): records its `boundary` and a
    /// receiver's `first_gap`, if known; the writer's holder closes it, and
    /// the duty cycle drains it to its end. `false` for no such open
    /// journal.
    #[cfg(test)]
    pub(crate) fn close_network_journal(
        &mut self,
        side: NetSide,
        publication: &PublicationIdentity,
        lane: Lane,
        boundary: Option<u64>,
        first_gap: Option<u64>,
    ) -> bool {
        let Some(index) = self.network.find(side, publication, lane) else {
            return false;
        };
        let open = self.network.open.swap_remove(index);
        let receiver = side == NetSide::Receiver;
        self.trace_journals.update_network(open.journal, |facts| {
            facts.boundary = boundary.or(facts.boundary);
            if receiver && facts.first_gap.is_none() {
                facts.first_gap = first_gap;
            }
        });
        true
    }

    /// Records the start of the first sealed gap of the image of
    /// `publication` on `lane` (control path); a later gap changes
    /// nothing. `false` for no open receiver journal.
    #[cfg(test)]
    pub(crate) fn seal_network_gap(
        &mut self,
        publication: &PublicationIdentity,
        lane: Lane,
        gap: u64,
    ) -> bool {
        let Some(open) = self
            .network
            .find(NetSide::Receiver, publication, lane)
            .and_then(|index| self.network.open.get(index).copied())
        else {
            return false;
        };
        self.trace_journals.update_network(open.journal, |facts| {
            if facts.first_gap.is_none() {
                facts.first_gap = Some(gap);
            }
        })
    }

    /// Counts a refused network journal of `publication` in every place
    /// that reports it.
    fn refuse_network_journal(&mut self, publication: PublicationIdentity) {
        self.trace_journals.refuse_network(&self.counters);
        let network = &mut self.network;
        let index = network
            .refused
            .iter()
            .position(|(found, _)| *found == publication);
        let index = match index {
            Some(index) => Some(index),
            // Within the capacity reserved at start: no allocation.
            None if network.refused.len() < network.refused.capacity() => {
                network.refused.push((publication, 0));
                network.refused.len().checked_sub(1)
            }
            None => None,
        };
        let count = match index.and_then(|index| network.refused.get_mut(index)) {
            Some((_, count)) => count,
            None => &mut network.untracked,
        };
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self
                .counters
                .add(crate::counters::Event::CounterOverflows, 1),
        }
    }
}

#[cfg(test)]
mod tests;
