// SPDX-License-Identifier: Apache-2.0

//! The in-process trace report (`quantstratum-docs:
//! karyos/design/trace-data-path.md`, "Journals and the report", batch
//! p6b2). It is built here, not in the driver, so the SPEC.md §14 crate
//! graph stays unchanged (ACS 12439, on the owner decision ACS 11410):
//! whoever built the agents registers their collectors with the facts the
//! client handles know (a subscription's join position, and its delivery
//! boundary at its terminal close), drains them on the control path, and
//! reads per-stream latency histograms between `Publish` and
//! `SubscriberPoll` and each trace's attribution verdict, following
//! trace-attribution.md.
//!
//! A trace's expected set is the union, over its messages, of the
//! publishing journal and the subscription journals eligible for the
//! message: those that joined at or before its position and whose delivery
//! boundary passed it. Any journal still open could still be eligible: an
//! open publisher journal could publish another message of the trace, such
//! as a child. So the set is frozen, and a final `Complete` possible, only
//! once every journal registered in the report reached its terminal close
//! (coordinator decision ACS 12662 on trace-data-path.md, "Trace-wide
//! expected set"); until then a trace gets a provisional answer.
//! `Incomplete` is final as soon as it is reached.
//!
//! Automatic calibration: two [`ClockProvenance::StdMonotonic`] clocks with
//! the same epoch (one process start) share their source, and so do two
//! [`ClockProvenance::HostMonotonic`] clocks with the same epoch whose
//! journals are both in the driver's time namespace ([`JournalClock`];
//! `quantstratum-docs: karyos/design/trace-tool.md`, T2). A latency between
//! them uses offset 0, drift 0 and the sum of their declared resolutions,
//! valid over the times observed so far. An opaque clock gets no automatic
//! calibration, only those given to [`TraceReport::add_calibration`].
//!
//! **Sources (T1).** Each journal is read through a [`JournalSource`]: the
//! in-process [`TraceCollector`] (registered with
//! [`TraceReport::add_publisher`] and [`TraceReport::add_subscriber`]), or
//! any other source, such as a tool's reader of the driver's trace mirror
//! ([`TraceReport::add_publisher_source`] and
//! [`TraceReport::add_subscriber_source`]). A source's kind, publication
//! and join come from its registration, never from its records (T4). A
//! source in [`SourceState::Lost`] makes every trace it could be expected
//! in final `Incomplete`: a subscriber journal is then taken as expected
//! for every message of its publication from its join on.
//!
//! **Scope.** A source that starts after the journal's start
//! ([`JournalSource::start`], a tool's attach horizon) cannot show the
//! observations below its start. A message is out of the report's scope
//! when such a journal could hold its missing observation there: a
//! publisher journal while the message's `Publish` is missing, a
//! subscriber journal that could be expected for it and holds no poll of
//! it, in both cases at a position below the first position the source
//! delivered (every position while it delivered none). Messages
//! [`TraceReport::out_of_scope`] names are out of scope too. A trace with
//! any message out of scope gets [`TraceAnswer::OutOfScope`], never a
//! verdict. The position rule relies on a journal observing one
//! publication in position order; a message whose observations lie wholly
//! below every horizon is unknown to the report, which is why a reader
//! with horizons calls [`TraceReport::require_roots`] (T6): a trace is then
//! `Complete` only if a root-flagged `Publish` of it was observed. Single
//! messages can be declared out of scope with
//! [`TraceReport::out_of_scope_message`] (a tool's missed journals, T7).

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::attribution::{AttributionConfig, Attributor, Verdict, combine};
use crate::clocks::{Calibration, ClockKey, Observation, latency};
use crate::error::TraceError;
use crate::histogram::{Histogram, HistogramError};
use crate::journal::{Collected, ObserverId, TraceCollector};
use crate::record::{ObservedTime, Point, PublicationId};
use crate::source::{JournalSource, SourceState};
use crate::trace_clock::ClockProvenance;

/// A journal registered with a [`TraceReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JournalId(usize);

/// What the report can say about a trace now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceAnswer {
    /// Final: no further evidence changes it.
    Final(Verdict),
    /// No loss seen so far; not a verdict.
    Provisional,
    /// Some observation of the trace may lie where the report cannot see
    /// it (below a source's start, or in a publication range declared out
    /// of scope); not a verdict.
    OutOfScope,
    /// The report holds no observation of this trace.
    Unknown,
}

/// A publication as a journal's registration names it: the driver
/// instance, the stream registration and the incarnation
/// (`quantstratum-docs: karyos/design/trace-tool.md`, T4). A mapping
/// cutover keeps all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PublicationKey {
    /// The driver instance, two words.
    pub driver: [u64; 2],
    /// The stream's registration.
    pub registration: u64,
    /// The publication's incarnation.
    pub incarnation: u64,
}

impl From<PublicationId> for PublicationKey {
    fn from(publication: PublicationId) -> Self {
        Self {
            driver: publication.driver,
            registration: publication.registration,
            incarnation: publication.incarnation,
        }
    }
}

/// The clock of a registered journal: its provenance and whether its
/// process reads `CLOCK_MONOTONIC` in the driver's time namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalClock {
    /// Where the journal's times come from.
    pub provenance: ClockProvenance,
    /// The driver found the journal's process in its own time namespace;
    /// always true for an agent in the report's own process. Two
    /// [`ClockProvenance::HostMonotonic`] clocks are calibrated only when
    /// both are.
    pub driver_time_namespace: bool,
}

impl From<ClockProvenance> for JournalClock {
    /// A clock of an agent in this process.
    fn from(provenance: ClockProvenance) -> Self {
        Self {
            provenance,
            driver_time_namespace: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Publisher,
    Subscriber { join: u64 },
}

#[derive(Debug)]
struct Journal {
    source: Box<dyn JournalSource>,
    /// The source's first sequence.
    start: u64,
    observer: ObserverId,
    attributor: Attributor,
    kind: Kind,
    publication: PublicationKey,
    clock: JournalClock,
    /// The owner closed the handle (its writer is closed); for a
    /// subscription, with its final delivery boundary.
    owner_closed: bool,
    boundary: Option<u64>,
    /// The source is [`SourceState::Lost`].
    lost: bool,
    /// The collector reported `Closed`.
    drained: bool,
    /// The position of the first record of its publication the source
    /// delivered.
    first_position: Option<u64>,
    /// Final verdicts per trace, once terminally closed.
    finals: Option<BTreeMap<[u64; 2], Verdict>>,
    /// Traces that found the attributor's table full: final `Incomplete`.
    untracked: Vec<[u64; 2]>,
    /// Observed times per clock `(domain, epoch)`: lowest, highest, and the
    /// declared uncertainty.
    clocks: BTreeMap<(u64, u64), (u64, u64, u64)>,
}

impl Journal {
    fn terminal(&self) -> bool {
        self.finals.is_some()
    }

    /// For a subscription journal of `publication`, whether it is expected
    /// for a message at `position`: `Some` once decided. A lost journal is
    /// expected for every message from its join on.
    fn eligible(&self, publication: &PublicationKey, position: u64) -> Option<bool> {
        let Kind::Subscriber { join } = self.kind else {
            return Some(false);
        };
        if self.publication != *publication || join > position {
            return Some(false);
        }
        if self.lost {
            return Some(true);
        }
        self.boundary.map(|boundary| boundary > position)
    }

    /// Whether an observation at `position` may lie below the source's
    /// start, where the report cannot see it.
    fn unseen(&self, position: u64) -> bool {
        self.start > 0 && self.first_position.is_none_or(|first| position < first)
    }

    /// This journal's verdict for a trace: final, provisional, or absent.
    fn verdict(&self, trace_id: [u64; 2]) -> Option<Verdict> {
        if self.lost || self.untracked.contains(&trace_id) {
            return Some(Verdict::Incomplete);
        }
        match &self.finals {
            Some(finals) => finals.get(&trace_id).copied(),
            None => self.attributor.provisional(trace_id),
        }
    }

    fn observation(&self, observed: &ObservedTime) -> Observation {
        Observation {
            clock: ClockKey {
                observer: self.observer,
                domain: observed.clock,
                epoch: observed.epoch,
            },
            time: observed.time,
            uncertainty: observed.uncertainty,
        }
    }
}

/// One message of a trace, keyed by its publication, lane and position.
#[derive(Debug, Default)]
struct Message {
    /// The publication as its first record named it.
    publication: PublicationId,
    trace_id: [u64; 2],
    publish: Option<(JournalId, ObservedTime)>,
    /// Its `Publish` record carries the `root` flag.
    root: bool,
    polls: Vec<(JournalId, ObservedTime)>,
}

/// The key of a [`Message`]: the publication as T4 names it (so records
/// that differ only in the wire ids are one message), lane and position.
type MessageKey = (PublicationKey, u8, u64);

/// `[low - by, high + by]`, each end clamped to the axis end, written out
/// explicitly (ADR-0007 keeps `saturating_*` out of positions and counters).
#[expect(
    clippy::implicit_saturating_sub,
    reason = "ADR-0007 keeps saturating_* out of positions and counters; a window end clamped to the axis end is written out explicitly"
)]
fn widened(low: u64, high: u64, by: u64) -> (u64, u64) {
    let from = if by > low { 0 } else { low - by };
    let to = if by > u64::MAX - high {
        u64::MAX
    } else {
        high + by
    };
    (from, to)
}

/// `value - start`, or 0 below `start`: a sequence counted from a source's
/// start.
#[expect(
    clippy::implicit_saturating_sub,
    reason = "ADR-0007 keeps saturating_* out of positions and counters; a sequence below the start is written out explicitly as 0"
)]
fn from_start(value: u64, start: u64) -> u64 {
    if value > start { value - start } else { 0 }
}

/// `item` with its sequences counted from `start`, so the attributor reads
/// the source as a journal that begins there.
fn rebased(item: Collected, start: u64) -> Collected {
    if start == 0 {
        return item;
    }
    let gap = |gap: Option<(u64, u64)>| {
        gap.map(|(from, to)| (from_start(from, start), from_start(to, start)))
    };
    match item {
        Collected::Record {
            sequence,
            gap: before,
            record,
            collected,
        } => Collected::Record {
            sequence: from_start(sequence, start),
            gap: gap(before),
            record,
            collected,
        },
        Collected::Corrupt {
            sequence,
            gap: before,
            error,
        } => Collected::Corrupt {
            sequence: from_start(sequence, start),
            gap: gap(before),
            error,
        },
        other => other,
    }
}

/// Histogram parameters of [`TraceReport::latencies`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistogramConfig {
    /// Significant decimal digits.
    pub digits: u8,
    /// Highest trackable value, in `unit`.
    pub highest: u64,
    /// Unit of the recorded latencies, in clock units.
    pub unit: u64,
}

/// What [`TraceReport::summary`] says about one publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationSummary {
    /// The publication.
    pub publication: PublicationId,
    /// Messages of it the report holds an observation of.
    pub messages: u64,
    /// Traces with a message of it whose answer is a final `Complete`.
    pub complete: u64,
    /// Traces with a message of it whose answer is a final `Incomplete`.
    pub incomplete: u64,
    /// Traces with a message of it whose answer is provisional.
    pub provisional: u64,
    /// Traces with a message of it that are out of the report's scope.
    pub out_of_scope: u64,
}

/// A message the report holds, from [`TraceReport::messages`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldMessage {
    /// Its publication.
    pub publication: PublicationKey,
    /// Its lane.
    pub lane: u8,
    /// Its position.
    pub position: u64,
    /// The current answer of its trace.
    pub answer: TraceAnswer,
}

/// The report over a set of journals (control path).
#[derive(Debug)]
pub struct TraceReport {
    attribution: AttributionConfig,
    histogram: HistogramConfig,
    journals: Vec<Journal>,
    messages: HashMap<MessageKey, Message>,
    calibrations: Vec<Calibration>,
    /// Publications whose messages at or below a position (every message
    /// for `None`) are out of scope.
    excluded: Vec<(PublicationKey, Option<u64>)>,
    /// Single messages declared out of scope.
    excluded_messages: HashSet<MessageKey>,
    /// A trace can be `Complete` only with a root `Publish` observed (T6).
    roots_required: bool,
    /// Set when [`TraceReport::trace`] first returns a final answer: from
    /// then on the registered journals are frozen, so no later journal can
    /// widen an expected set a final answer was given for.
    frozen: Cell<bool>,
}

impl TraceReport {
    /// An empty report whose journals use `attribution` and whose latency
    /// histograms use `histogram`.
    #[must_use]
    pub fn new(attribution: AttributionConfig, histogram: HistogramConfig) -> Self {
        Self {
            attribution,
            histogram,
            journals: Vec::new(),
            messages: HashMap::new(),
            calibrations: Vec::new(),
            excluded: Vec::new(),
            excluded_messages: HashSet::new(),
            roots_required: false,
            frozen: Cell::new(false),
        }
    }

    fn add(
        &mut self,
        source: Box<dyn JournalSource>,
        clock: JournalClock,
        kind: Kind,
        publication: PublicationKey,
    ) -> Result<JournalId, TraceError> {
        if self.frozen.get() {
            return Err(TraceError::MembershipFrozen);
        }
        let id = JournalId(self.journals.len());
        self.journals.push(Journal {
            observer: source.observer(),
            start: source.start(),
            source,
            attributor: Attributor::new(self.attribution)?,
            kind,
            publication,
            clock,
            owner_closed: false,
            boundary: None,
            lost: false,
            drained: false,
            first_position: None,
            finals: None,
            untracked: Vec::new(),
            clocks: BTreeMap::new(),
        });
        Ok(id)
    }

    /// Registers the journal of a publication handle of `publication`,
    /// stamped by a clock of `provenance` in this process.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::MembershipFrozen`] once the report gave any
    /// final answer (coordinator decision ACS 12667), and
    /// [`TraceError::Attribution`] when the attributor's tables cannot be
    /// allocated.
    pub fn add_publisher(
        &mut self,
        collector: TraceCollector,
        provenance: ClockProvenance,
        publication: PublicationId,
    ) -> Result<JournalId, TraceError> {
        self.add_publisher_source(collector, provenance.into(), publication.into())
    }

    /// Registers the journal of a subscription of `publication` that joined
    /// at stream position `join`, stamped by a clock of `provenance` in
    /// this process.
    ///
    /// # Errors
    ///
    /// As [`TraceReport::add_publisher`].
    pub fn add_subscriber(
        &mut self,
        collector: TraceCollector,
        provenance: ClockProvenance,
        publication: PublicationId,
        join: u64,
    ) -> Result<JournalId, TraceError> {
        self.add_subscriber_source(collector, provenance.into(), publication.into(), join)
    }

    /// Registers a publisher journal of `publication` read through
    /// `source`, stamped by `clock` (T1). The publication comes from the
    /// journal's registration, never from its records (T4).
    ///
    /// # Errors
    ///
    /// As [`TraceReport::add_publisher`].
    pub fn add_publisher_source(
        &mut self,
        source: impl JournalSource + 'static,
        clock: JournalClock,
        publication: PublicationKey,
    ) -> Result<JournalId, TraceError> {
        self.add(Box::new(source), clock, Kind::Publisher, publication)
    }

    /// Registers a subscriber journal of `publication` that joined at
    /// stream position `join`, read through `source` and stamped by
    /// `clock` (T1). Publication and join come from the journal's
    /// registration, never from its records (T4).
    ///
    /// # Errors
    ///
    /// As [`TraceReport::add_publisher`].
    pub fn add_subscriber_source(
        &mut self,
        source: impl JournalSource + 'static,
        clock: JournalClock,
        publication: PublicationKey,
        join: u64,
    ) -> Result<JournalId, TraceError> {
        self.add(
            Box::new(source),
            clock,
            Kind::Subscriber { join },
            publication,
        )
    }

    /// Records the terminal close of a journal's handle, after its writer
    /// closed and every observation it will make was made. A subscription
    /// passes its final delivery boundary, which decides the messages it is
    /// expected for; a publication passes `None`. A source that knows its
    /// terminal state ([`JournalSource::state`]) needs no call.
    pub fn closed(&mut self, journal: JournalId, boundary: Option<u64>) {
        if let Some(journal) = self.journals.get_mut(journal.0) {
            journal.owner_closed = true;
            if matches!(journal.kind, Kind::Subscriber { .. }) {
                journal.boundary = boundary;
            }
        }
    }

    /// Declares the messages of `publication` at positions at or below
    /// `through`, or every message of it for `None`, out of the report's
    /// scope: a journal that could be expected for them may be invisible
    /// (a tool's recycle log, `quantstratum-docs:
    /// karyos/design/trace-tool.md`, T5). It never narrows: declarations
    /// accumulate.
    pub fn out_of_scope(&mut self, publication: PublicationKey, through: Option<u64>) {
        self.excluded.push((publication, through));
    }

    /// Declares the message of `publication` at `position` in `lane` out of
    /// the report's scope (a tool's missed journal, `quantstratum-docs:
    /// karyos/design/trace-tool.md`, T7). Declarations accumulate.
    pub fn out_of_scope_message(&mut self, publication: PublicationKey, lane: u8, position: u64) {
        self.excluded_messages.insert((publication, lane, position));
    }

    /// Requires an observed root for a final `Complete` (`quantstratum-docs:
    /// karyos/design/trace-tool.md`, "Trace horizon", T6): a trace that
    /// would be `Complete` but none of whose observed `Publish` records
    /// carries the `root` flag is out of scope. A reader whose sources start
    /// after their journals' start (a tool) needs it, since a trace's
    /// earlier messages may all lie below every horizon; a report that
    /// reads every journal from its start (in process) has no horizon and
    /// answers without it.
    pub fn require_roots(&mut self) {
        self.roots_required = true;
    }

    /// Adds an explicit calibration, for clocks the report cannot calibrate
    /// automatically.
    pub fn add_calibration(&mut self, calibration: Calibration) {
        self.calibrations.push(calibration);
    }

    /// Drains every journal: feeds its attributor, keeps its observations,
    /// and computes final verdicts for journals that reached their terminal
    /// close.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::NotClosed`] only if the attributor's close
    /// preconditions are broken, which this report never does.
    pub fn drain(&mut self) -> Result<(), TraceError> {
        for index in 0..self.journals.len() {
            self.drain_journal(index)?;
        }
        Ok(())
    }

    fn drain_journal(&mut self, index: usize) -> Result<(), TraceError> {
        let id = JournalId(index);
        let Some(journal) = self.journals.get_mut(index) else {
            return Ok(());
        };
        if journal.terminal() {
            return Ok(());
        }
        // The state before the records: a source returns `Closed` only
        // after every record it holds.
        match journal.source.state() {
            SourceState::Open => {}
            SourceState::Closed { boundary } => {
                journal.owner_closed = true;
                if matches!(journal.kind, Kind::Subscriber { .. }) {
                    journal.boundary = boundary;
                }
            }
            SourceState::Lost => {
                journal.owner_closed = true;
                journal.lost = true;
            }
        }
        let start = journal.start;
        loop {
            let item = rebased(journal.source.take(), start);
            if let crate::attribution::Observed::Untracked { trace_id } =
                journal.attributor.observe(&item)
            {
                journal.untracked.push(trace_id);
            }
            match item {
                Collected::Record { record, .. } => {
                    let observed = record.observed;
                    let clock = journal
                        .clocks
                        .entry((observed.clock, observed.epoch))
                        .or_insert((observed.time, observed.time, observed.uncertainty));
                    clock.0 = clock.0.min(observed.time);
                    clock.1 = clock.1.max(observed.time);
                    clock.2 = clock.2.max(observed.uncertainty);
                    if journal.first_position.is_none()
                        && PublicationKey::from(record.publication) == journal.publication
                    {
                        journal.first_position = Some(record.position);
                    }
                    let message = self
                        .messages
                        .entry((
                            PublicationKey::from(record.publication),
                            record.lane,
                            record.position,
                        ))
                        .or_insert_with(|| Message {
                            publication: record.publication,
                            ..Message::default()
                        });
                    message.trace_id = record.ids.trace_id;
                    match record.point {
                        Point::Publish => {
                            message.publish = Some((id, observed));
                            message.root = record.root;
                        }
                        Point::SubscriberPoll => message.polls.push((id, observed)),
                        _ => {}
                    }
                }
                Collected::Corrupt { .. } => {}
                Collected::Empty => break,
                Collected::Closed => {
                    journal.drained = true;
                    break;
                }
            }
        }
        let losses = journal.source.losses();
        let (attempted, stored) = (from_start(losses.attempted, start), losses.stored);
        journal.attributor.observe_snapshot(attempted, stored);
        if journal.drained && journal.owner_closed {
            let finals = journal.attributor.close(attempted)?.collect();
            journal.finals = Some(finals);
        }
        Ok(())
    }

    /// What the report can say about the trace `trace_id` now. A final
    /// answer freezes the registered journals: later registrations fail
    /// with [`TraceError::MembershipFrozen`].
    #[must_use]
    pub fn trace(&self, trace_id: [u64; 2]) -> TraceAnswer {
        let messages: Vec<_> = self
            .messages
            .iter()
            .filter(|(_, message)| message.trace_id == trace_id)
            .collect();
        self.answer(trace_id, &messages)
    }

    /// The answer for a trace with `messages`, freezing the registered
    /// journals on a final one.
    fn answer(&self, trace_id: [u64; 2], messages: &[(&MessageKey, &Message)]) -> TraceAnswer {
        let answer = self.decide(trace_id, messages);
        if matches!(answer, TraceAnswer::Final(_)) {
            self.frozen.set(true);
        }
        answer
    }

    /// Whether a message at `position` of `publication` could have an
    /// observation the report cannot see.
    fn out_of_reach(&self, publication: &PublicationKey, position: u64, message: &Message) -> bool {
        if self.excluded.iter().any(|(excluded, through)| {
            excluded == publication && through.is_none_or(|through| position <= through)
        }) {
            return true;
        }
        self.journals.iter().enumerate().any(|(index, journal)| {
            if journal.publication != *publication || !journal.unseen(position) {
                return false;
            }
            match journal.kind {
                Kind::Publisher => message.publish.is_none(),
                Kind::Subscriber { .. } => {
                    journal.eligible(publication, position) != Some(false)
                        && !message
                            .polls
                            .iter()
                            .any(|(JournalId(polled), _)| *polled == index)
                }
            }
        })
    }

    fn decide(&self, trace_id: [u64; 2], messages: &[(&MessageKey, &Message)]) -> TraceAnswer {
        if messages.is_empty() {
            return TraceAnswer::Unknown;
        }
        if messages.iter().any(|(key, message)| {
            let (publication, _lane, position) = key;
            self.excluded_messages.contains(*key)
                || self.out_of_reach(publication, *position, message)
        }) {
            return TraceAnswer::OutOfScope;
        }
        let mut expected: Vec<usize> = Vec::new();
        let mut decided = true;
        let mut publish_missing = false;
        // Per message: an eligible subscription journal, terminally closed
        // without this message's SubscriberPoll, makes the trace Incomplete,
        // even if the journal holds the trace for another message. So does
        // a missing Publish that a lost publisher journal could have held.
        let mut poll_missing = false;
        for ((publication, _lane, position), message) in messages {
            let publication = *publication;
            match message.publish {
                Some((JournalId(journal), _)) => expected.push(journal),
                None => publish_missing = true,
            }
            // Every publisher journal of this publication could hold the
            // missing Publish record until it is terminally closed.
            for (index, journal) in self.journals.iter().enumerate() {
                if journal.kind == Kind::Publisher && journal.publication == publication {
                    decided &= journal.terminal();
                    poll_missing |= journal.lost && message.publish.is_none();
                    continue;
                }
                match journal.eligible(&publication, *position) {
                    Some(true) => {
                        expected.push(index);
                        let polled = message
                            .polls
                            .iter()
                            .any(|(JournalId(journal), _)| *journal == index);
                        if journal.terminal() && !polled {
                            poll_missing = true;
                        }
                    }
                    Some(false) => {}
                    None => decided = false,
                }
            }
        }
        expected.sort_unstable();
        expected.dedup();
        let verdicts: Vec<(bool, Option<Verdict>)> = expected
            .iter()
            .filter_map(|index| self.journals.get(*index))
            .map(|journal| (journal.terminal(), journal.verdict(trace_id)))
            .collect();
        // Incomplete is final as soon as it is reached: a reported loss, or
        // a terminally closed expected journal without the trace.
        let incomplete = poll_missing
            || verdicts.iter().any(|(terminal, verdict)| {
                *verdict == Some(Verdict::Incomplete) || (*terminal && verdict.is_none())
            });
        if incomplete {
            return TraceAnswer::Final(Verdict::Incomplete);
        }
        let all_terminal = verdicts.iter().all(|(terminal, _)| *terminal);
        // Every registered journal, not only those already holding the
        // trace: an open one could still add a message of it.
        let registered_terminal = self.journals.iter().all(Journal::terminal);
        if !decided || !all_terminal || !registered_terminal {
            return TraceAnswer::Provisional;
        }
        if publish_missing {
            return TraceAnswer::Final(Verdict::Incomplete);
        }
        let verdict = combine(verdicts.into_iter().map(|(_, verdict)| verdict));
        // T6: Complete only from an observed root.
        if verdict == Verdict::Complete
            && self.roots_required
            && !messages.iter().any(|(_, message)| message.root)
        {
            return TraceAnswer::OutOfScope;
        }
        TraceAnswer::Final(verdict)
    }

    /// Every message the report holds, with the current answer of its
    /// trace (one answer per trace; a final one freezes the registered
    /// journals, as with [`TraceReport::trace`]). Records without a trace
    /// id are left out.
    #[must_use]
    pub fn messages(&self) -> Vec<HeldMessage> {
        let mut traces: HashMap<[u64; 2], Vec<(&MessageKey, &Message)>> = HashMap::new();
        for (key, message) in &self.messages {
            if message.trace_id != [0, 0] {
                traces
                    .entry(message.trace_id)
                    .or_default()
                    .push((key, message));
            }
        }
        let mut out = Vec::new();
        for (trace_id, messages) in &traces {
            let answer = self.answer(*trace_id, messages);
            out.extend(
                messages
                    .iter()
                    .map(|((publication, lane, position), _)| HeldMessage {
                        publication: *publication,
                        lane: *lane,
                        position: *position,
                        answer,
                    }),
            );
        }
        out
    }

    /// Per publication, the messages the report holds and the answers of
    /// the traces with a message of it, counted once per trace and
    /// publication. Records without a trace id count as messages only. A
    /// final answer freezes the registered journals, as with
    /// [`TraceReport::trace`].
    #[must_use]
    pub fn summary(&self) -> Vec<PublicationSummary> {
        let mut out: Vec<PublicationSummary> = Vec::new();
        let mut traces: HashMap<[u64; 2], Vec<(&MessageKey, &Message)>> = HashMap::new();
        for (key, message) in &self.messages {
            let index = summary_index(&mut out, message.publication);
            if let Some(summary) = out.get_mut(index) {
                summary.messages += 1;
            }
            if message.trace_id != [0, 0] {
                traces
                    .entry(message.trace_id)
                    .or_default()
                    .push((key, message));
            }
        }
        for (trace_id, messages) in &traces {
            let answer = self.answer(*trace_id, messages);
            let mut publications: Vec<PublicationId> = messages
                .iter()
                .map(|(_, message)| message.publication)
                .collect();
            publications.sort_unstable_by_key(publication_order);
            publications.dedup();
            for publication in publications {
                let index = summary_index(&mut out, publication);
                let Some(summary) = out.get_mut(index) else {
                    continue;
                };
                match answer {
                    TraceAnswer::Final(Verdict::Complete) => summary.complete += 1,
                    TraceAnswer::Final(Verdict::Incomplete) => summary.incomplete += 1,
                    TraceAnswer::Provisional => summary.provisional += 1,
                    TraceAnswer::OutOfScope => summary.out_of_scope += 1,
                    TraceAnswer::Unknown => {}
                }
            }
        }
        out.sort_unstable_by_key(|summary| publication_order(&summary.publication));
        out
    }

    /// The automatic calibrations between clocks that share their source
    /// (standard clocks of one process, host clocks in the driver's time
    /// namespace), over the times observed so far, with the explicit ones.
    fn calibrations(&self) -> Vec<Calibration> {
        let mut out = self.calibrations.clone();
        for from in self.journals.iter().filter(|j| j.kind == Kind::Publisher) {
            for to in self.journals.iter().filter(|j| j.kind != Kind::Publisher) {
                if !shared_source(from.clock, to.clock) {
                    continue;
                }
                for (&(domain, epoch), &(low, high, resolution)) in &from.clocks {
                    for (&(to_domain, to_epoch), &(_, _, to_resolution)) in &to.clocks {
                        if to_epoch != epoch {
                            continue;
                        }
                        // The interval widens to the axis ends, which only
                        // makes it larger: the conservative direction.
                        let Some(offset_uncertainty) = resolution.checked_add(to_resolution) else {
                            continue;
                        };
                        let (valid_from, valid_to) = widened(low, high, resolution);
                        out.push(Calibration {
                            from: ClockKey {
                                observer: from.observer,
                                domain,
                                epoch,
                            },
                            to: ClockKey {
                                observer: to.observer,
                                domain: to_domain,
                                epoch,
                            },
                            reference: low,
                            offset: 0,
                            offset_uncertainty,
                            drift: 0,
                            drift_uncertainty: 0,
                            valid_from,
                            valid_to,
                        });
                    }
                }
            }
        }
        out
    }

    /// Per-publication latency histograms between each message's `Publish`
    /// observation and each of its `SubscriberPoll` observations. A pair
    /// without a usable calibration is recorded as unavailable with its
    /// reason. The interval may have a negative lower bound: the `Publish`
    /// time is taken after the commit.
    ///
    /// # Errors
    ///
    /// Returns the histogram's errors for an invalid configuration.
    pub fn latencies(&self) -> Result<Vec<(PublicationId, Histogram)>, HistogramError> {
        let calibrations = self.calibrations();
        let mut out: Vec<(PublicationId, Histogram)> = Vec::new();
        for message in self.messages.values() {
            let publication = &message.publication;
            let Some((JournalId(from), published)) = message.publish else {
                continue;
            };
            let Some(from) = self.journals.get(from) else {
                continue;
            };
            let a = from.observation(&published);
            for (JournalId(to), polled) in &message.polls {
                let Some(to) = self.journals.get(*to) else {
                    continue;
                };
                let b = to.observation(polled);
                let index = match out.iter().position(|(p, _)| p == publication) {
                    Some(index) => index,
                    None => {
                        out.push((
                            *publication,
                            Histogram::new(
                                self.histogram.digits,
                                self.histogram.highest,
                                self.histogram.unit,
                            )?,
                        ));
                        out.len() - 1
                    }
                };
                if let Some((_, histogram)) = out.get_mut(index) {
                    histogram.record(latency(&a, &b, &calibrations))?;
                }
            }
        }
        Ok(out)
    }
}

/// Whether two journal clocks read one source, so that equal epochs can be
/// calibrated with zero offset.
fn shared_source(from: JournalClock, to: JournalClock) -> bool {
    match (from.provenance, to.provenance) {
        (ClockProvenance::StdMonotonic, ClockProvenance::StdMonotonic) => true,
        (ClockProvenance::HostMonotonic, ClockProvenance::HostMonotonic) => {
            from.driver_time_namespace && to.driver_time_namespace
        }
        _ => false,
    }
}

/// A total order of publications, for stable output.
fn publication_order(publication: &PublicationId) -> (u64, u64, u64, u64, i32, i32) {
    (
        publication.driver[0],
        publication.driver[1],
        publication.registration,
        publication.incarnation,
        publication.stream_id,
        publication.session_id,
    )
}

/// The index of `publication`'s summary in `out`, added empty if absent.
fn summary_index(out: &mut Vec<PublicationSummary>, publication: PublicationId) -> usize {
    if let Some(index) = out.iter().position(|s| s.publication == publication) {
        return index;
    }
    out.push(PublicationSummary {
        publication,
        messages: 0,
        complete: 0,
        incomplete: 0,
        provisional: 0,
        out_of_scope: 0,
    });
    out.len() - 1
}

#[cfg(test)]
mod tests;
