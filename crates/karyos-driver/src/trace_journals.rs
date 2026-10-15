// SPDX-License-Identifier: Apache-2.0

//! The client trace journals the driver consumes (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`, J1 to J4).
//!
//! - **Creation (J2).** `TraceJournal` asks for a journal of given sizes.
//!   The sizes are checked as `record_journal` checks them, and against
//!   what the trace mirror can hold ([`MAX_MIRROR_PAYLOAD`] payload words,
//!   [`MIRROR_RANGES`] drop ranges); the bytes of every journal the driver
//!   holds stay within `max_trace_journal_bytes`. A journal that finds no
//!   free table entry is refused with `TraceJournalsExhausted`; any refusal
//!   creates nothing. The driver assigns the journal number (a trace
//!   number, never reused) and answers with it and a hand-over key.
//! - **Consumption (J1).** Each duty cycle drains the journals into the
//!   trace mirror, at most `trace_drain_budget` records over all of them
//!   (the loss accounting is reread only when the journal's attempted count
//!   moved, it took a record, ended, showed a range in progress, or is on
//!   its final visit),
//!   from a cursor that rotates across the table: a cycle whose budget runs
//!   out at a journal starts the next cycle at the journal after it. The
//!   journal's memory is untrusted ([`JournalDrain`]): a violation records
//!   a `client protocol violation` error keyed by the client and the
//!   journal, stops draining it and marks its entry writer lost. Nothing
//!   panics.
//! - **Facts (J3).** The table entry carries the journal's client, state,
//!   final boundary (`CloseJournal`), last mirrored ring record and loss
//!   accounting. An entry becomes closed once its writer closed it and the
//!   driver drained it to its end. An ended entry is reused only once the
//!   ring retains no record of its journal.
//! - **A writer that is gone (J4).** When a remote client's journal grant
//!   ends (its `Detach`, its exit proof, or a grant never sent), the driver
//!   drains what is committed and marks the entry closed if the writer had
//!   closed it, writer lost otherwise. An in-process writer closes its
//!   journal when dropped.

use karyos_sys::record_journal::{Drained, JournalDrain, JournalLayout};
use karyos_sys::trace_mirror::{
    JournalEntry, JournalState, MAX_MIRROR_PAYLOAD, MIRROR_RANGES, TraceMirror, TraceMirrorReader,
};

use crate::counters::{DriverCounters, Event};
use crate::diagnostics::{Diagnostics, ErrorCode};

/// Why a journal was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Sizes the journal or the mirror cannot hold, or beyond the bytes
    /// budget.
    Resources,
    /// No free table entry.
    Exhausted,
}

/// A journal in the table.
#[derive(Debug)]
struct Held {
    entry: JournalEntry,
    /// `None` once the journal ended: drained to its close, faulted, or
    /// its writer gone.
    drain: Option<JournalDrain>,
    /// Bytes charged to `max_trace_journal_bytes` while `drain` lives.
    bytes: u64,
}

/// The journal table, the trace mirror and the drain cursor.
#[derive(Debug)]
pub(crate) struct TraceJournals {
    mirror: TraceMirror,
    slots: Vec<Option<Held>>,
    cursor: usize,
    bytes: u64,
    max_bytes: u64,
    budget: usize,
}

/// Bytes of a region's header stride (`karyos_sys::ipc::HEADER_STRIDE`).
const REGION_HEADER: usize = 128;

/// The bytes a journal of `layout` occupies: its whole region, header
/// included, also when it lives on the heap.
pub(crate) fn journal_bytes(layout: &JournalLayout) -> Option<u64> {
    layout
        .structure_bytes()?
        .checked_add(REGION_HEADER)
        .and_then(|bytes| u64::try_from(bytes).ok())
}

impl TraceJournals {
    /// The table over `mirror`, with the driver's limits.
    pub(crate) fn new(mirror: TraceMirror, max_bytes: u64, budget: usize) -> Self {
        let mut slots = Vec::with_capacity(mirror.entries());
        slots.resize_with(mirror.entries(), || None);
        Self {
            mirror,
            slots,
            cursor: 0,
            bytes: 0,
            max_bytes,
            budget,
        }
    }

    /// A reader of the trace mirror.
    pub(crate) fn reader(&self) -> TraceMirrorReader {
        self.mirror.reader()
    }

    /// The mirror's region, to grant it to tools; `None` on the heap.
    #[cfg(target_os = "linux")]
    pub(crate) fn region(&self) -> Option<&karyos_sys::ipc::Region> {
        self.mirror.region()
    }

    /// The region of journal `journal`, while the driver drains it.
    #[cfg(target_os = "linux")]
    pub(crate) fn journal_region(&self, journal: u64) -> Option<&karyos_sys::ipc::Region> {
        self.slots
            .iter()
            .flatten()
            .find(|held| held.entry.journal == journal)
            .and_then(|held| held.drain.as_ref())
            .and_then(JournalDrain::region)
    }

    /// Journals still open.
    pub(crate) fn open(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|held| held.entry.state == JournalState::Open)
            .count()
    }

    /// Checks a request for a journal of `layout` without changing
    /// anything: its sizes, the bytes budget and a free table entry.
    /// Returns the entry and the bytes it would charge.
    pub(crate) fn preflight(&self, layout: &JournalLayout) -> Result<(usize, u64), Refusal> {
        let bytes = journal_bytes(layout).ok_or(Refusal::Resources)?;
        let sizes = layout.validate().is_ok()
            && layout.payload_words <= MAX_MIRROR_PAYLOAD
            && layout.drop_ranges <= MIRROR_RANGES
            && self
                .bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= self.max_bytes);
        if !sizes {
            return Err(Refusal::Resources);
        }
        let oldest = self.mirror.bounds().first;
        let free = self.slots.iter().position(|slot| match slot {
            None => true,
            // Reused only once the ring retains no record of the journal.
            Some(held) => {
                held.drain.is_none()
                    && held.entry.state != JournalState::Open
                    && held.entry.last_record.is_none_or(|last| last < oldest)
            }
        });
        free.map(|index| (index, bytes)).ok_or(Refusal::Exhausted)
    }

    /// Opens `journal` of `client` in entry `index` (from
    /// [`TraceJournals::preflight`]) with its drain.
    /// `observed` is the subscription the journal observes, with its
    /// stream and join position, or `None` for a publisher-side journal.
    pub(crate) fn insert(
        &mut self,
        index: usize,
        journal: u64,
        client: u64,
        observed: Option<(u64, u64, Option<u64>)>,
        drain: JournalDrain,
        bytes: u64,
    ) {
        let layout = drain.layout();
        let mut entry = JournalEntry::open(
            journal,
            client,
            layout.payload_words as u64,
            layout.capacity as u64,
        );
        if let Some((subscription, stream, join)) = observed {
            entry.subscription = subscription;
            entry.stream = stream;
            entry.join = join;
        }
        if let Some(slot) = self.slots.get_mut(index) {
            self.mirror.write_entry(index, Some(&entry));
            self.bytes = self.bytes.saturating_add(bytes);
            *slot = Some(Held {
                entry,
                drain: Some(drain),
                bytes,
            });
        }
    }

    /// Records the final delivery boundary of `client`'s open journal
    /// `journal`; `false` (nothing changed) for a journal that is not an
    /// open journal of the client without a boundary.
    pub(crate) fn close(&mut self, client: u64, journal: u64, boundary: u64) -> bool {
        let found = self.slots.iter_mut().enumerate().find_map(|(index, slot)| {
            slot.as_mut()
                .filter(|held| {
                    held.entry.journal == journal
                        && held.entry.client == client
                        && held.entry.state == JournalState::Open
                        && held.entry.boundary.is_none()
                })
                .map(|held| (index, held))
        });
        let Some((index, held)) = found else {
            return false;
        };
        held.entry.boundary = Some(boundary);
        self.mirror.write_entry(index, Some(&held.entry));
        true
    }

    /// The writer of `journal` is gone (its grant ended): drains what is
    /// committed, then marks the entry closed if the writer closed it,
    /// writer lost otherwise.
    pub(crate) fn writer_gone(
        &mut self,
        journal: u64,
        diagnostics: &mut Diagnostics,
        counters: &mut DriverCounters,
    ) {
        let Some(index) = self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|held| held.entry.journal == journal && held.drain.is_some())
        }) else {
            return;
        };
        // Every committed record: at most the capacity is pending.
        let limit = self
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .and_then(|held| held.drain.as_ref())
            .map_or(0, |drain| drain.layout().capacity.saturating_add(1));
        // The final visit rereads the loss accounting whatever it took, so
        // a drop recorded after the last read reaches the entry for good.
        self.drain_one(index, limit, true, diagnostics, counters);
        if let Some(Some(held)) = self.slots.get_mut(index)
            && let Some(drain) = held.drain.take()
        {
            drop(drain);
            held.entry.state = JournalState::WriterLost;
            self.bytes = self.bytes.saturating_sub(held.bytes);
            self.mirror.write_entry(index, Some(&held.entry));
        }
    }

    /// One duty cycle's drain: at most the budget over every journal, from
    /// the rotating cursor. Returns the records mirrored.
    pub(crate) fn drain(
        &mut self,
        diagnostics: &mut Diagnostics,
        counters: &mut DriverCounters,
    ) -> u32 {
        let count = self.slots.len();
        if count == 0 {
            return 0;
        }
        let start = self.cursor % count;
        let mut left = self.budget;
        let mut next = (start + 1) % count;
        for step in 0..count {
            let index = (start + step) % count;
            let draining = self
                .slots
                .get(index)
                .and_then(Option::as_ref)
                .is_some_and(|held| held.drain.is_some());
            if !draining {
                continue;
            }
            let taken = self.drain_one(index, left, false, diagnostics, counters);
            left = left.saturating_sub(taken);
            if left == 0 {
                // The next cycle starts after the journal that used the
                // rest of the budget.
                next = (index + 1) % count;
                break;
            }
        }
        self.cursor = next;
        u32::try_from(self.budget - left).unwrap_or(u32::MAX)
    }

    /// Drains at most `limit` records of entry `index` into the mirror and
    /// refreshes its entry. Returns the records taken.
    fn drain_one(
        &mut self,
        index: usize,
        limit: usize,
        final_visit: bool,
        diagnostics: &mut Diagnostics,
        counters: &mut DriverCounters,
    ) -> usize {
        let Some(Some(held)) = self.slots.get_mut(index) else {
            return 0;
        };
        let Some(drain) = held.drain.as_mut() else {
            return 0;
        };
        let journal = held.entry.journal;
        let before = held.entry;
        let mut taken = 0usize;
        let mut ended = None;
        while taken < limit {
            match drain.take() {
                Drained::Record {
                    sequence, payload, ..
                } => {
                    taken += 1;
                    // The ring's sequences cannot be exhausted in practice;
                    // a record that could not be appended is not counted.
                    if let Some(appended) = self.mirror.append(journal, sequence, payload) {
                        held.entry.last_record = Some(appended.seq);
                        held.entry.mirrored = held.entry.mirrored.saturating_add(1);
                        counters.add(Event::TraceRecordsMirrored, 1);
                        if appended.overwrote.is_some() {
                            counters.add(Event::TraceMirrorOverwritten, 1);
                        }
                    }
                }
                Drained::Empty => break,
                Drained::Closed => {
                    ended = Some(JournalState::Closed);
                    break;
                }
                Drained::Violation(_) => {
                    ended = Some(JournalState::WriterLost);
                    break;
                }
            }
        }
        // Every append, stored or dropped, raises the attempted count, so
        // the loss accounting is reread only when that count moved since the
        // last read, this visit took a record or ended the journal, the last
        // read saw a range still being written, or this is the final visit:
        // an idle journal costs one load per cycle, not `MIRROR_RANGES`
        // seqlock reads (review of #131 and #135).
        let refresh = final_visit
            || taken > 0
            || ended.is_some()
            || held.entry.unstable > 0
            || drain.attempted() != Some(held.entry.attempted);
        match refresh.then(|| drain.losses()) {
            None => {}
            Some(Ok(losses)) => {
                let entry = &mut held.entry;
                entry.attempted = losses.attempted;
                entry.stored = losses.stored;
                entry.lost_before = losses.lost_before;
                entry.unstable = u64::try_from(losses.unstable).unwrap_or(u64::MAX);
                // The journal has at most MIRROR_RANGES drop ranges.
                entry.range_count = losses.ranges.len().min(MIRROR_RANGES);
                for (target, range) in entry.ranges.iter_mut().zip(losses.ranges) {
                    *target = *range;
                }
            }
            Some(Err(_)) => ended = Some(JournalState::WriterLost),
        }
        if let Some(state) = ended {
            if drain.fault().is_some() {
                counters.add(Event::TraceJournalFaults, 1);
                diagnostics.error(
                    counters,
                    ErrorCode::ClientProtocolViolation,
                    [held.entry.client, journal],
                    "trace journal broke its protocol; it is no longer drained",
                );
            }
            held.drain = None;
            held.entry.state = state;
            self.bytes = self.bytes.saturating_sub(held.bytes);
        }
        if held.entry != before {
            self.mirror.write_entry(index, Some(&held.entry));
        }
        taken
    }
}

#[cfg(test)]
mod tests;
