// SPDX-License-Identifier: Apache-2.0

//! The network trace journals of the driver's sender and receiver agents
//! (`quantstratum-docs: karyos/design/trace-network.md` §4 and §5, NT-1,
//! NT-3 and NT-4).
//!
//! - **Hooks.** The application (or `karyosd`) sets one
//!   [`NetworkTraceHook`] per side, sender or receiver, on the control
//!   path. Network journals exist only while their side has a hook;
//!   removing or replacing it closes its open journals.
//! - **Creation.** One journal per lane of a publication incarnation on the
//!   sender, and of an image on the receiver, created on the control path
//!   only (ACS 15498): a heap journal of `network_journal_records` records
//!   charged to `max_network_journal_bytes`, in the trace mirror's table
//!   with the same mirror sequence as client journals (T7). Its writer is
//!   handed to the hook ([`NetworkTraceHook::open_journal`]); the driver
//!   keeps the drain, and the duty cycle mirrors it with the client
//!   journals.
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
//! - **Facts.** The start (pickup start or image join) is written at
//!   creation; the boundary (pickup or commit boundary) at close; a
//!   receiver's first sealed gap when it is sealed or at close.
//! - **Close.** The hook closes the writer
//!   ([`NetworkTraceHook::close_journal`]) and the driver drains the
//!   journal to its end, as for a client journal.

use crate::embedded::StreamTerms;
use karyos_protocol::trace_hook::{
    HOST_MONOTONIC_PROVENANCE, NetJournal, NetSide, NetworkTraceHook, PublicationIdentity,
    TRACE_RECORD_WORDS,
};
use karyos_sys::frame::Lane;
use karyos_sys::record_journal::{JournalLayout, journal_block};
use karyos_sys::trace_mirror::{JournalKind, NetworkFacts, TimeNamespace};

use crate::embedded::EmbeddedDriver;
use crate::trace_journals::Observed;

/// A network journal the driver handed to a hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Open {
    side: NetSide,
    publication: PublicationIdentity,
    lane: Lane,
    journal: u64,
}

/// The hooks, the open network journals and the refused counts.
pub(crate) struct NetworkTracing {
    /// The sender's and the receiver's hook.
    hooks: [Option<Box<dyn NetworkTraceHook>>; 2],
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
            .field("sender_hook", &self.hooks[0].is_some())
            .field("receiver_hook", &self.hooks[1].is_some())
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
            hooks: [None, None],
            open: Vec::new(),
            refused: Vec::with_capacity(publications),
            untracked: 0,
        }
    }

    fn hook(&mut self, side: NetSide) -> Option<&mut Box<dyn NetworkTraceHook>> {
        self.hooks.get_mut(slot(side)).and_then(Option::as_mut)
    }

    fn find(&self, side: NetSide, publication: &PublicationIdentity, lane: Lane) -> Option<usize> {
        self.open
            .iter()
            .position(|open| (open.side, open.publication, open.lane) == (side, *publication, lane))
    }
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Sets the network trace hook of `side`, or removes it with `None`
    /// (control path). The journals the previous hook held are closed
    /// first, through it, without a boundary.
    pub fn set_network_trace_hook(
        &mut self,
        side: NetSide,
        hook: Option<Box<dyn NetworkTraceHook>>,
    ) {
        let open: Vec<Open> = self
            .network
            .open
            .iter()
            .copied()
            .filter(|open| open.side == side)
            .collect();
        for open in open {
            self.close_network_journal(side, &open.publication, open.lane, None, None);
        }
        if let Some(target) = self.network.hooks.get_mut(slot(side)) {
            *target = hook;
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "called by the agents in P2.12 step 3")
    )]
    pub(crate) fn forget_network_publication(&mut self, publication: &PublicationIdentity) {
        self.network
            .refused
            .retain(|(refused, _)| refused != publication);
    }

    /// Opens the network journal of `side` for `lane` of `publication`
    /// (control path): `registration` is the publication's on the sender,
    /// the image's on the receiver, and `start` the pickup start or the
    /// image join. Returns the journal number; `None` without a hook for
    /// `side`, for a journal already open, or for a refused one, which is
    /// counted.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "called by the agents in P2.12 step 3")
    )]
    pub(crate) fn open_network_journal(
        &mut self,
        side: NetSide,
        publication: PublicationIdentity,
        lane: Lane,
        registration: u64,
        start: Option<u64>,
    ) -> Option<u64> {
        if self.network.hook(side).is_none()
            || self.network.find(side, &publication, lane).is_some()
        {
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
        });
        if let Some(hook) = self.network.hook(side) {
            hook.open_journal(NetJournal {
                side,
                publication,
                lane,
                number: journal,
                writer,
            });
        }
        Some(journal)
    }

    /// Closes the network journal of `side` for `lane` of `publication`
    /// (control path): its publication closed or its image retired. Records
    /// its `boundary` and a receiver's `first_gap`, if known, then has the
    /// hook close the writer; the duty cycle drains it to its end. `false`
    /// for no such open journal.
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
        if let Some(hook) = self.network.hook(side) {
            hook.close_journal(side, publication, lane);
        }
        true
    }

    /// Records the start of the first sealed gap of the image of
    /// `publication` on `lane` (control path); a later gap changes
    /// nothing. `false` for no open receiver journal.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "called by the agents in P2.12 step 3")
    )]
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
