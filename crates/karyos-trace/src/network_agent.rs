// SPDX-License-Identifier: Apache-2.0

//! [`NetworkTraceAgent`], the [`NetworkTraceHook`] of `karyos-trace`
//! (`quantstratum-docs: karyos/design/trace-network.md` §2 and §3, NT-1 and
//! NT-2): it writes the `SenderPickup` and `ReceiverCommit` records of a
//! driver agent into the network journals the driver hands it.
//!
//! The application (or `karyosd`) builds one per driver agent with the
//! observing driver's `driver_id`, a clock and the most journals it holds
//! at once, and sets it with `EmbeddedDriver::set_network_trace_hook`. The
//! journal table is allocated then: a journal handed over takes a free
//! place on the control path ([`NetworkTraceHook::open_journal`]), and the
//! data-path calls only look it up, never allocate. A journal that finds
//! no place is closed at once and counted; an observation whose
//! publication and lane have no open journal on its side, as for a journal
//! the driver refused, is counted and dropped.

use karyos_protocol::frame::{Lane, TraceExtension};
use karyos_protocol::journal::{Append, Stamp};
use karyos_protocol::trace_hook::{
    NetCommit, NetJournal, NetPickup, NetSide, NetworkTraceHook, PublicationIdentity,
};

use crate::journal::{ObserverId, TraceWriter, trace_writer};
use crate::record::{NetworkPath, ObservedTime, Point, TraceIds, TraceRecord};
use crate::trace_clock::TraceClock;

/// One of the [`NetworkCounts`] counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkCounter {
    /// [`NetworkCounts::stored`].
    Stored,
    /// [`NetworkCounts::dropped`].
    Dropped,
    /// [`NetworkCounts::refused`].
    Refused,
    /// [`NetworkCounts::unjournaled`].
    Unjournaled,
    /// [`NetworkCounts::journals_refused`].
    JournalsRefused,
}

/// What a [`NetworkTraceAgent`]'s records did. Counters are checked: one
/// that would overflow keeps its value and the first such counter is
/// reported in `overflowed` (SPEC.md §14, ADR-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkCounts {
    /// Records stored in a journal.
    pub stored: u64,
    /// Records a full journal dropped (also counted in its drop ranges).
    pub dropped: u64,
    /// Records a journal refused (closed, exhausted, another collection
    /// clock).
    pub refused: u64,
    /// Observations with no open journal for their side, publication and
    /// lane: never recorded.
    pub unjournaled: u64,
    /// Journals the agent could not take: its table was full, or the
    /// journal's records were not trace records. Each was closed at once.
    pub journals_refused: u64,
    /// The first counter that would have overflowed; it stays set.
    pub overflowed: Option<NetworkCounter>,
}

impl NetworkCounts {
    fn count(&mut self, counter: NetworkCounter) {
        let value = match counter {
            NetworkCounter::Stored => &mut self.stored,
            NetworkCounter::Dropped => &mut self.dropped,
            NetworkCounter::Refused => &mut self.refused,
            NetworkCounter::Unjournaled => &mut self.unjournaled,
            NetworkCounter::JournalsRefused => &mut self.journals_refused,
        };
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => {
                self.overflowed.get_or_insert(counter);
            }
        }
    }
}

/// A journal the agent writes.
#[derive(Debug)]
struct Held {
    side: NetSide,
    publication: PublicationIdentity,
    lane: Lane,
    writer: TraceWriter,
}

/// The network trace hook of one driver agent.
#[derive(Debug)]
pub struct NetworkTraceAgent<C> {
    driver: [u64; 2],
    clock: C,
    /// The collection clock of every journal: the clock's domain.
    domain: u64,
    journals: Vec<Option<Held>>,
    counts: NetworkCounts,
}

impl<C: TraceClock> NetworkTraceAgent<C> {
    /// An agent of the driver `driver` (its `driver_id`, the observer of
    /// every journal it writes), stamping with `clock`, that holds at most
    /// `journals` journals at once (control path: the table is allocated
    /// here).
    #[must_use]
    pub fn new(driver: [u64; 2], mut clock: C, journals: usize) -> Self {
        let domain = clock.now().clock;
        let mut table = Vec::with_capacity(journals);
        table.resize_with(journals, || None);
        Self {
            driver,
            clock,
            domain,
            journals: table,
            counts: NetworkCounts::default(),
        }
    }

    /// What the records did so far.
    #[must_use]
    pub fn counts(&self) -> NetworkCounts {
        self.counts
    }

    /// The clock.
    #[must_use]
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Records the observation `build` makes from the current time into
    /// the open journal of `side`, `publication` and `lane`, found by a scan
    /// of the table, which allocates nothing; without one, counts it as
    /// unjournaled and takes no time.
    fn record(
        &mut self,
        side: NetSide,
        publication: &PublicationIdentity,
        lane: Lane,
        build: impl FnOnce(ObservedTime) -> TraceRecord,
    ) {
        let Some(writer) = self.journals.iter_mut().flatten().find_map(|held| {
            ((held.side, held.publication, held.lane) == (side, *publication, lane))
                .then_some(&mut held.writer)
        }) else {
            self.counts.count(NetworkCounter::Unjournaled);
            return;
        };
        let observed = self.clock.now();
        let collected = Stamp {
            time: observed.time,
            clock: observed.clock,
            epoch: observed.epoch,
        };
        let counter = match writer.record(&build(observed), collected) {
            Ok(Append::Stored { .. }) => NetworkCounter::Stored,
            Ok(Append::Dropped { .. }) => NetworkCounter::Dropped,
            Err(_) => NetworkCounter::Refused,
        };
        self.counts.count(counter);
    }
}

/// The record of a network observation: a network point never sets the
/// root flag (T6).
fn observation(
    point: Point,
    ext: &TraceExtension,
    publication: &PublicationIdentity,
    lane: Lane,
    position: u64,
    network: NetworkPath,
    observed: ObservedTime,
) -> TraceRecord {
    TraceRecord {
        point,
        publication: (*publication).into(),
        lane: lane.get(),
        position,
        ids: TraceIds::from(*ext),
        observed,
        subscriber: None,
        packet: None,
        network: Some(network),
        root: false,
    }
}

impl<C: TraceClock> NetworkTraceHook for NetworkTraceAgent<C> {
    fn open_journal(&mut self, journal: NetJournal) {
        let NetJournal {
            side,
            publication,
            lane,
            number,
            writer,
        } = journal;
        let observer = ObserverId {
            driver: self.driver,
            journal: number,
        };
        let free = self.journals.iter().position(Option::is_none);
        match (trace_writer(writer, observer, self.domain), free) {
            (Ok(writer), Some(index)) => {
                if let Some(slot) = self.journals.get_mut(index) {
                    *slot = Some(Held {
                        side,
                        publication,
                        lane,
                        writer,
                    });
                }
            }
            // Closed at once, so the driver drains it to its end.
            (Ok(mut writer), None) => {
                writer.close();
                self.counts.count(NetworkCounter::JournalsRefused);
            }
            // Not a trace journal: its writer is dropped, which closes it.
            (Err(_), _) => self.counts.count(NetworkCounter::JournalsRefused),
        }
    }

    fn close_journal(&mut self, side: NetSide, publication: &PublicationIdentity, lane: Lane) {
        let found = self.journals.iter_mut().find(|slot| {
            slot.as_ref().is_some_and(|held| {
                (held.side, held.publication, held.lane) == (side, *publication, lane)
            })
        });
        if let Some(slot) = found
            && let Some(mut held) = slot.take()
        {
            held.writer.close();
        }
    }

    fn on_sender_pickup(&mut self, ext: &TraceExtension, at: &NetPickup) {
        let path = NetworkPath {
            path: at.path,
            attempt: at.attempt,
        };
        self.record(NetSide::Sender, &at.publication, at.lane, |observed| {
            observation(
                Point::SenderPickup,
                ext,
                &at.publication,
                at.lane,
                at.position,
                path,
                observed,
            )
        });
    }

    fn on_receiver_commit(&mut self, ext: &TraceExtension, at: &NetCommit) {
        // A receiver cannot know the attempt: DATA carries none.
        let path = NetworkPath {
            path: at.path,
            attempt: 0,
        };
        self.record(NetSide::Receiver, &at.publication, at.lane, |observed| {
            observation(
                Point::ReceiverCommit,
                ext,
                &at.publication,
                at.lane,
                at.position,
                path,
                observed,
            )
        });
    }
}

#[cfg(test)]
mod tests;
