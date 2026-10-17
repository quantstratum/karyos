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
//! - **Facts (J3, T2, T4).** The table entry carries the journal's client,
//!   state, kind and observed registration with its stream and
//!   incarnation (from the driver's own record of the registration, so the
//!   entry alone names the publication), the subscription's join position
//!   for a subscriber journal, the time namespace word and the clock
//!   provenance word, the final boundary (`CloseJournal`), the last
//!   mirrored ring record and the loss accounting. An entry becomes closed
//!   once its writer closed it and the driver drained it to its end.
//! - **Mirror sequence (T7, ACS 13973).** Each journal the driver creates
//!   gets the next mirror sequence, from 1, in its entry and in its recycle
//!   log entry: a counter of its own, advanced only when a `TraceJournal`
//!   succeeds, so a tool can tell a journal it never saw from a gap, which
//!   the journal number (from the trace number space that
//!   `EmbeddedDriver::next_trace_number` also draws from) cannot.
//! - **Recycling (T5).** An ended entry is reused only once the ring
//!   retains no record of its journal. When a subscriber journal `S` ends,
//!   the driver notes every publisher journal `j` of `S`'s publication
//!   still in the table with its attempted count `A_j` and its stored count
//!   at that moment, read together with `losses` (for a journal already
//!   ended, its final counts). `S` is **covered** once, for every noted
//!   `j`, the drain released every record `j` had stored at that moment
//!   (so every record below `A_j` was consumed) or `j` ended (drained to its
//!   end), and the ring's oldest retained sequence is above the ring
//!   sequence of `j`'s last mirrored record when that drain condition was
//!   first seen. Reusing the entry of an `S` that is not covered first
//!   writes a recycle log entry (its publication, final state and
//!   boundary, and the noted `(j, A_j)` pairs), which is dropped once `S`
//!   is covered. An `S` with more noted journals than
//!   [`MAX_RECYCLE_PAIRS`] cannot be logged, and with the log full none
//!   can: such an entry is reused only once covered, and a `TraceJournal`
//!   that finds no other free entry is refused with
//!   `TraceJournalsExhausted`. Free entries are preferred, then ended
//!   entries that need no log entry. Coverage advances once per duty
//!   cycle, after the drain.
//! - **Network journals (`trace-network.md` §4 and §5, NT-3).** The
//!   driver's own journals of its sender and receiver agents (kinds 3 and
//!   4) share the table and the mirror sequence, but are charged to their
//!   own budget, `max_network_journal_bytes`, and live on the heap. A
//!   refused one creates nothing and raises header word 7 of the mirror.
//!   Their facts (the sender's `driver_id`, start, boundary and first gap)
//!   are written at creation and when they change, on the control path.
//!   A kind 3 entry, and a kind 4 entry of a publication this driver
//!   sends, is reused only once covered as a subscriber journal is, with
//!   no recycle log entry: it waits instead.
//! - **A writer that is gone (J4).** When a remote client's journal grant
//!   ends (its `Detach`, its exit proof, or a grant never sent), the driver
//!   drains what is committed and marks the entry closed if the writer had
//!   closed it, writer lost otherwise. An in-process writer closes its
//!   journal when dropped.

use karyos_sys::frame::Lane;
use karyos_sys::record_journal::{Drained, JournalDrain, JournalLayout};
use karyos_sys::trace_mirror::{
    JournalEntry, JournalKind, JournalState, MAX_MIRROR_PAYLOAD, MAX_RECYCLE_PAIRS, MIRROR_RANGES,
    NetworkFacts, NotedPublisher, RecycledJournal, TimeNamespace, TraceMirror, TraceMirrorReader,
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

/// What a journal observes, from the driver's own record of the
/// registration the `TraceJournal` named (T4), and the facts the driver
/// recorded when it created the journal (T2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observed {
    /// Subscriber or publisher journal.
    pub(crate) kind: JournalKind,
    /// The observed subscription or publication.
    pub(crate) registration: u64,
    /// Its publication's registration (the aggregate's).
    pub(crate) stream: u64,
    /// Its lane: journals pair within a lane.
    pub(crate) lane: Lane,
    /// The publication's incarnation.
    pub(crate) incarnation: u64,
    /// A subscription's join position; `None` for a publisher journal.
    pub(crate) join: Option<u64>,
    /// The client's time namespace against the driver's.
    pub(crate) time_namespace: TimeNamespace,
    /// The client's clock provenance word.
    pub(crate) provenance: u64,
    /// A network journal's facts; `None` for a client journal.
    pub(crate) network: Option<NetworkFacts>,
    /// Whether a network journal waits for T5 coverage before its entry is
    /// reused: a sender journal, or a receiver journal of a publication
    /// this driver sends.
    pub(crate) covers: bool,
}

/// A publisher journal noted when a subscriber journal ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Note {
    journal: u64,
    /// Its attempted count at that moment.
    attempted: u64,
    /// Its stored count read after that attempted count (`losses` reads
    /// the attempted count, then the head, both Acquire): once the drain
    /// has released this many records, every record below `attempted` was
    /// consumed. `u64::MAX` when its accounting could not be read (the
    /// journal then faults and the drain condition waits for its end).
    stored: u64,
    /// `Some` once the drain condition was first seen, with the ring
    /// sequence of the journal's last mirrored record at that point.
    drained: Option<Option<u64>>,
}

/// Whether every note's drain condition was seen and the ring no longer
/// retains a record at or below its mark: no `Publish` that could need the
/// subscriber journal is pending or retained.
fn covered(notes: &[Note], oldest: u64) -> bool {
    notes.iter().all(|note| {
        note.drained
            .is_some_and(|last| last.is_none_or(|last| last < oldest))
    })
}

/// A journal in the table.
#[derive(Debug)]
struct Held {
    entry: JournalEntry,
    /// `None` once the journal ended: drained to its close, faulted, or
    /// its writer gone.
    drain: Option<JournalDrain>,
    /// Bytes charged to its kind's budget while `drain` lives:
    /// `max_trace_journal_bytes` for a client journal,
    /// `max_network_journal_bytes` for a network journal.
    bytes: u64,
    /// For a subscriber journal, or a network journal that `covers`, that
    /// ended: the publisher journals noted at its end.
    notes: Option<Vec<Note>>,
    /// The buffer those notes are written into, reserved for every table
    /// entry when the journal is inserted, so noting allocates nothing on
    /// the drain path.
    spare: Vec<Note>,
    /// See [`Observed::covers`].
    covers: bool,
}

impl Held {
    /// Whether reusing this ended entry needs a recycle log entry: a
    /// subscriber journal not yet covered.
    fn needs_log(&self, oldest: u64) -> bool {
        self.notes
            .as_deref()
            .is_some_and(|notes| !covered(notes, oldest))
    }
}

/// The bytes held once a journal that charged `bytes` ends: `held` never
/// holds less than one journal's charge, so the difference is checked
/// (SPEC.md §14); if the accounting ever broke, the charge goes to zero
/// explicitly and one `counter overflows` is counted.
fn release(held: u64, bytes: u64, counters: &DriverCounters) -> u64 {
    held.checked_sub(bytes).unwrap_or_else(|| {
        counters.add(Event::CounterOverflows, 1);
        0
    })
}

/// Counts a refused network journal in the driver counters, and an
/// overflow when the mirror's header count could not rise (`header_rose`
/// false): the refusal is never silent (ACS 15639).
fn count_refusal(header_rose: bool, counters: &DriverCounters) {
    if !header_rose {
        counters.add(Event::CounterOverflows, 1);
    }
    counters.add(Event::NetworkTraceJournalsRefused, 1);
}

/// A table entry [`TraceJournals::preflight`] found for a new journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reserved {
    /// The table entry.
    index: usize,
    /// The bytes the journal charges.
    bytes: u64,
    /// The recycle log entry that reusing the table entry fills, if any.
    log: Option<usize>,
    /// The bytes held once the journal is charged (checked here).
    total: u64,
    /// The journal's sequence and the next one (checked here).
    sequence: (u64, u64),
    /// Charged to the network budget.
    network: bool,
}

impl Reserved {
    /// The bytes the journal charges.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// The journal table, the trace mirror and the drain cursor.
#[derive(Debug)]
pub(crate) struct TraceJournals {
    mirror: TraceMirror,
    slots: Vec<Option<Held>>,
    /// The notes of each recycle log entry the mirror shows, which decide
    /// when it is dropped.
    log: Vec<Option<Vec<Note>>>,
    /// Note buffers of dropped recycle log entries, kept for the next
    /// journals inserted, at most one per log entry.
    spares: Vec<Vec<Note>>,
    /// The drain progress of each journal [`TraceJournals::advance`]
    /// reads, reserved for every table entry at start.
    progress: Vec<(u64, Option<u64>, Option<u64>)>,
    cursor: usize,
    bytes: u64,
    max_bytes: u64,
    /// Bytes of the network journals held, within `max_net_bytes`.
    net_bytes: u64,
    max_net_bytes: u64,
    budget: usize,
    /// The mirror sequence of the next journal created (T7): its own
    /// counter, advanced only by [`TraceJournals::insert`], so the
    /// sequences of the journals the driver created are dense from 1.
    next_sequence: u64,
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
    pub(crate) fn new(
        mirror: TraceMirror,
        max_bytes: u64,
        max_net_bytes: u64,
        budget: usize,
    ) -> Self {
        let mut slots = Vec::with_capacity(mirror.entries());
        slots.resize_with(mirror.entries(), || None);
        let mut log = Vec::with_capacity(mirror.log_entries());
        log.resize_with(mirror.log_entries(), || None);
        let spares = Vec::with_capacity(mirror.log_entries());
        let progress = Vec::with_capacity(mirror.entries());
        Self {
            mirror,
            slots,
            log,
            spares,
            progress,
            cursor: 0,
            bytes: 0,
            max_bytes,
            net_bytes: 0,
            max_net_bytes,
            budget,
            next_sequence: 1,
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

    /// Client journals still open.
    pub(crate) fn open(&self) -> usize {
        self.open_where(false)
    }

    /// Network journals still open.
    pub(crate) fn network_open(&self) -> usize {
        self.open_where(true)
    }

    fn open_where(&self, network: bool) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|held| {
                held.entry.state == JournalState::Open && held.entry.kind.is_network() == network
            })
            .count()
    }

    /// Checks a request for a journal of `layout` without changing
    /// anything: its sizes, the bytes budget and a free table entry (see
    /// the module documentation, "Recycling"). Returns the entry, the
    /// bytes it would charge and the recycle log entry its reuse fills.
    pub(crate) fn preflight(&self, layout: &JournalLayout) -> Result<Reserved, Refusal> {
        self.preflight_for(layout, false)
    }

    /// [`TraceJournals::preflight`] for a network journal, against
    /// `max_network_journal_bytes`.
    pub(crate) fn preflight_network(&self, layout: &JournalLayout) -> Result<Reserved, Refusal> {
        self.preflight_for(layout, true)
    }

    fn preflight_for(&self, layout: &JournalLayout, network: bool) -> Result<Reserved, Refusal> {
        let bytes = journal_bytes(layout).ok_or(Refusal::Resources)?;
        let (held, max) = if network {
            (self.net_bytes, self.max_net_bytes)
        } else {
            (self.bytes, self.max_bytes)
        };
        let total = held.checked_add(bytes).filter(|total| *total <= max);
        let sizes = layout.validate().is_ok()
            && layout.payload_words <= MAX_MIRROR_PAYLOAD
            && layout.drop_ranges <= MIRROR_RANGES;
        let (true, Some(total)) = (sizes, total) else {
            return Err(Refusal::Resources);
        };
        // Exhaustion of a 64-bit count of created journals cannot happen;
        // it is checked all the same (SPEC.md §14) and refuses the journal.
        let next = self
            .next_sequence
            .checked_add(1)
            .ok_or(Refusal::Exhausted)?;
        let sequence = (self.next_sequence, next);
        let oldest = self.mirror.bounds().first;
        let free_log = self.log.iter().position(Option::is_none);
        // The best entry: a free one, then an ended one that needs no log
        // entry, then one that a free log entry can describe.
        let mut found: Option<(u8, Reserved)> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            let candidate = match slot {
                None => Some((0, None)),
                // Reused only once the ring retains no record of the
                // journal.
                Some(held)
                    if held.drain.is_none()
                        && held.entry.state != JournalState::Open
                        && held.entry.last_record.is_none_or(|last| last < oldest) =>
                {
                    match &held.notes {
                        // A network entry is never logged: it waits.
                        Some(notes) if held.covers && !covered(notes, oldest) => None,
                        Some(notes) if !covered(notes, oldest) => free_log
                            .filter(|_| notes.len() <= MAX_RECYCLE_PAIRS)
                            .map(|log| (2, Some(log))),
                        _ => Some((1, None)),
                    }
                }
                Some(_) => None,
            };
            if let Some((rank, log)) = candidate
                && found.is_none_or(|(best, _)| rank < best)
            {
                found = Some((
                    rank,
                    Reserved {
                        index,
                        bytes,
                        log,
                        total,
                        sequence,
                        network,
                    },
                ));
            }
        }
        found
            .map(|(_, reserved)| reserved)
            .ok_or(Refusal::Exhausted)
    }

    /// Opens `journal` of `client` in the entry `reserved` names (from
    /// [`TraceJournals::preflight`]) with its drain, observing `observed`.
    /// Reusing the entry of a subscriber journal that is not covered first
    /// writes its recycle log entry.
    pub(crate) fn insert(
        &mut self,
        reserved: Reserved,
        journal: u64,
        client: u64,
        observed: Observed,
        drain: JournalDrain,
    ) {
        let Reserved {
            index,
            bytes,
            log,
            total,
            sequence: (sequence, next_sequence),
            network,
        } = reserved;
        let layout = drain.layout();
        let mut entry = JournalEntry::open(
            journal,
            client,
            observed.kind,
            layout.payload_words as u64,
            layout.capacity as u64,
        );
        entry.registration = observed.registration;
        entry.stream = observed.stream;
        entry.lane = observed.lane;
        entry.incarnation = observed.incarnation;
        entry.join = observed.join;
        entry.time_namespace = observed.time_namespace;
        entry.provenance = observed.provenance;
        entry.network = observed.network;
        // Both checked by `preflight`, which nothing changed since.
        entry.sequence = sequence;
        self.next_sequence = next_sequence;
        // The high-water mark first (Release), then the log and the entry:
        // a tool reads it before the table and the log.
        self.mirror.assign_sequence(entry.sequence);
        let entries = self.slots.len();
        let Some(old) = self.slots.get_mut(index).map(Option::take) else {
            return;
        };
        let oldest = self.mirror.bounds().first;
        let logged = log.filter(|_| old.as_ref().is_some_and(|old| old.needs_log(oldest)));
        // The new journal's note buffer: the old journal's, else a dropped
        // log entry's, else a new one, reserved for every table entry
        // (control path).
        let mut spare = None;
        match (old, logged) {
            // The log entry before the table entry is reused, so a reader
            // of the table and then the log never misses the recycled
            // journal.
            (Some(old), Some(log)) if self.log.get(log).is_some() => {
                spare = Some(old.spare);
                let notes = old.notes.unwrap_or_default();
                let mut record = RecycledJournal {
                    journal: old.entry.journal,
                    stream: old.entry.stream,
                    lane: old.entry.lane,
                    incarnation: old.entry.incarnation,
                    state: old.entry.state,
                    boundary: old.entry.boundary,
                    pairs: [NotedPublisher::default(); MAX_RECYCLE_PAIRS],
                    pair_count: notes.len().min(MAX_RECYCLE_PAIRS),
                    sequence: old.entry.sequence,
                };
                for (pair, note) in record.pairs.iter_mut().zip(&notes) {
                    *pair = NotedPublisher {
                        journal: note.journal,
                        attempted: note.attempted,
                    };
                }
                self.mirror.write_log(log, Some(&record));
                if let Some(free) = self.log.get_mut(log) {
                    *free = Some(notes);
                }
            }
            (Some(old), _) => spare = Some(old.notes.unwrap_or(old.spare)),
            (None, _) => {}
        }
        let mut spare = spare
            .or_else(|| self.spares.pop())
            .filter(|spare| spare.capacity() >= entries)
            .unwrap_or_else(|| Vec::with_capacity(entries));
        spare.clear();
        self.mirror.write_entry(index, Some(&entry));
        if network {
            self.net_bytes = total;
        } else {
            self.bytes = total;
        }
        if let Some(slot) = self.slots.get_mut(index) {
            *slot = Some(Held {
                entry,
                drain: Some(drain),
                bytes,
                notes: None,
                spare,
                covers: observed.covers,
            });
        }
    }

    /// Counts a refused network journal in the mirror's header word 7 and
    /// in the driver counters; a header count that cannot rise is counted
    /// as an overflow, never silently (ACS 15639).
    pub(crate) fn refuse_network(&mut self, counters: &DriverCounters) {
        count_refusal(self.mirror.refuse_network_journal(), counters);
    }

    /// Whether a table entry still names a network journal of
    /// `publication`: until then its refused count may still be needed by
    /// a report (§5).
    #[must_use]
    pub(crate) fn names_network(
        &self,
        publication: &karyos_protocol::trace_hook::PublicationIdentity,
    ) -> bool {
        self.slots.iter().flatten().any(|held| {
            held.entry
                .network
                .is_some_and(|facts| facts.sender_driver == publication.driver)
                && (held.entry.stream, held.entry.incarnation)
                    == (publication.registration, publication.incarnation)
        })
    }

    /// Updates the facts of network journal `journal` with `update` and
    /// rewrites its entry; `false` (nothing changed) for a journal that is
    /// not a network journal in the table.
    pub(crate) fn update_network(
        &mut self,
        journal: u64,
        update: impl FnOnce(&mut NetworkFacts),
    ) -> bool {
        let found = self.slots.iter_mut().enumerate().find_map(|(index, slot)| {
            slot.as_mut()
                .filter(|held| held.entry.journal == journal)
                .map(|held| (index, held))
        });
        let Some((index, held)) = found else {
            return false;
        };
        let Some(facts) = held.entry.network.as_mut() else {
            return false;
        };
        update(facts);
        self.mirror.write_entry(index, Some(&held.entry))
    }

    /// The bytes held once `held`, which ended, releases its charge from
    /// its budget.
    fn release_held(&mut self, network: bool, bytes: u64, counters: &DriverCounters) {
        if network {
            self.net_bytes = release(self.net_bytes, bytes, counters);
        } else {
            self.bytes = release(self.bytes, bytes, counters);
        }
    }

    /// Subscriber journal `index` ended: notes every publisher journal of
    /// its publication still in the table with its attempted and stored
    /// counts, once. A publisher journal created later cannot hold a
    /// `Publish` the subscriber journal could be expected for.
    fn note_end(&mut self, index: usize) {
        let Some(Some(subscriber)) = self.slots.get(index) else {
            return;
        };
        let noted = subscriber.entry.kind == JournalKind::Subscriber || subscriber.covers;
        if !noted || subscriber.notes.is_some() {
            return;
        }
        let (stream, incarnation, lane) = (
            subscriber.entry.stream,
            subscriber.entry.incarnation,
            subscriber.entry.lane,
        );
        // Its buffer holds a note for every table entry: no allocation.
        let mut notes = match self.slots.get_mut(index) {
            Some(Some(subscriber)) => core::mem::take(&mut subscriber.spare),
            _ => return,
        };
        notes.clear();
        for held in self.slots.iter_mut().flatten().filter(|held| {
            held.entry.kind == JournalKind::Publisher
                && held.entry.stream == stream
                && held.entry.incarnation == incarnation
                && held.entry.lane == lane
        }) {
            let journal = held.entry.journal;
            let note = match held.drain.as_mut().map(JournalDrain::losses) {
                // Ended: its final counts; only the ring condition remains.
                None => Note {
                    journal,
                    attempted: held.entry.attempted,
                    stored: 0,
                    drained: Some(held.entry.last_record),
                },
                Some(Ok(losses)) => Note {
                    journal,
                    attempted: losses.attempted,
                    stored: losses.stored,
                    drained: None,
                },
                // The violation is sticky: the journal ends writer lost at
                // its next visit, which meets the drain condition.
                Some(Err(_)) => Note {
                    journal,
                    attempted: held.entry.attempted,
                    stored: u64::MAX,
                    drained: None,
                },
            };
            notes.push(note);
        }
        if let Some(Some(subscriber)) = self.slots.get_mut(index) {
            subscriber.notes = Some(notes);
        }
    }

    /// Advances every pending note's drain condition, then drops the
    /// recycle log entries whose subscriber journal is covered.
    fn advance(&mut self) {
        let pending = |notes: &[Note]| notes.iter().any(|note| note.drained.is_none());
        let any = self
            .slots
            .iter()
            .flatten()
            .filter_map(|held| held.notes.as_deref())
            .chain(self.log.iter().flatten().map(Vec::as_slice))
            .any(pending);
        if any {
            // Each journal still in the table: (number, released records
            // or `None` once ended, last mirrored ring record), into the
            // scratch reserved for every entry.
            self.progress.clear();
            self.progress
                .extend(self.slots.iter().flatten().map(|held| {
                    (
                        held.entry.journal,
                        held.drain.as_ref().map(JournalDrain::consumed),
                        held.entry.last_record,
                    )
                }));
            let progress = &self.progress;
            let notes = self
                .slots
                .iter_mut()
                .flatten()
                .filter_map(|held| held.notes.as_mut())
                .chain(self.log.iter_mut().flatten())
                .flatten()
                .filter(|note| note.drained.is_none());
            for note in notes {
                note.drained = match progress.iter().find(|seen| seen.0 == note.journal) {
                    // Reused: it ended, drained to its end, and the ring
                    // retains none of its records.
                    None => Some(None),
                    Some(&(_, None, last)) => Some(last),
                    Some(&(_, Some(consumed), last)) if consumed >= note.stored => Some(last),
                    Some(_) => None,
                };
            }
        }
        let oldest = self.mirror.bounds().first;
        for (index, slot) in self.log.iter_mut().enumerate() {
            if slot.as_deref().is_some_and(|notes| covered(notes, oldest)) {
                self.mirror.write_log(index, None);
                // Its buffer is kept for a later journal, not freed here.
                if let Some(notes) = slot.take()
                    && self.spares.len() < self.spares.capacity()
                {
                    self.spares.push(notes);
                }
            }
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
            .map(|drain| drain.layout().capacity);
        let limit = match limit.map(|capacity| (capacity, capacity.checked_add(1))) {
            None => 0,
            Some((_, Some(limit))) => limit,
            // A capacity of `usize::MAX` records cannot be mapped; checked
            // all the same (SPEC.md §14): the capacity bounds the drain.
            Some((capacity, None)) => {
                counters.add(Event::CounterOverflows, 1);
                capacity
            }
        };
        // The final visit rereads the loss accounting whatever it took, so
        // a drop recorded after the last read reaches the entry for good.
        self.drain_one(index, limit, true, diagnostics, counters);
        if let Some(Some(held)) = self.slots.get_mut(index)
            && let Some(drain) = held.drain.take()
        {
            drop(drain);
            held.entry.state = JournalState::WriterLost;
            let (network, bytes) = (held.entry.kind.is_network(), held.bytes);
            self.mirror.write_entry(index, Some(&held.entry));
            self.release_held(network, bytes, counters);
            self.note_end(index);
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
            // A drain takes at most what it was given.
            left = match left.checked_sub(taken) {
                Some(left) => left,
                None => {
                    counters.add(Event::CounterOverflows, 1);
                    0
                }
            };
            if left == 0 {
                // The next cycle starts after the journal that used the
                // rest of the budget.
                next = (index + 1) % count;
                break;
            }
        }
        self.cursor = next;
        self.advance();
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
                        // A count that does not fit keeps its last value.
                        match held.entry.mirrored.checked_add(1) {
                            Some(mirrored) => held.entry.mirrored = mirrored,
                            None => counters.add(Event::CounterOverflows, 1),
                        }
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
        let ended_now = ended.is_some();
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
        }
        let (network, bytes) = (held.entry.kind.is_network(), held.bytes);
        if held.entry != before {
            self.mirror.write_entry(index, Some(&held.entry));
        }
        if ended_now {
            self.release_held(network, bytes, counters);
            self.note_end(index);
        }
        taken
    }
}

/// The time namespace of the process `pidfd` proves against the driver's
/// (T2): the namespace files of both processes are compared by device and
/// inode. Unknown when either cannot be read (a kernel without time
/// namespaces, or a process the driver cannot inspect) or when the process
/// exited, since its pid may then name another process. Control path
/// only.
#[cfg(target_os = "linux")]
pub(crate) fn time_namespace_of(pidfd: &karyos_sys::ipc::PidFd) -> TimeNamespace {
    use std::os::unix::fs::MetadataExt;
    let own = std::fs::metadata("/proc/self/ns/time");
    let theirs = std::fs::metadata(format!("/proc/{}/ns/time", pidfd.pid()));
    // Alive after the read: the pid named the proven process throughout.
    if pidfd.exited().unwrap_or(true) {
        return TimeNamespace::Unknown;
    }
    match (own, theirs) {
        (Ok(own), Ok(theirs)) if (own.dev(), own.ino()) == (theirs.dev(), theirs.ino()) => {
            TimeNamespace::Same
        }
        (Ok(_), Ok(_)) => TimeNamespace::Different,
        _ => TimeNamespace::Unknown,
    }
}

#[cfg(test)]
mod tests;
