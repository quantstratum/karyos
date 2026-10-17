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
//!
//! **Network journals (`quantstratum-docs: karyos/design/trace-network.md`
//! §5).** A network sender or receiver journal
//! ([`TraceReport::add_network_source`]) observes one lane of one
//! publication with its facts: the pickup start or image join, at its close
//! the pickup or commit boundary, and a receiver's recorded gaps. Its
//! records name their own frame, so each is tied to the message with the
//! same publication, lane, trace id and `message_id`; it never creates a
//! message of its own. A fragment drained before its message's `Publish`
//! or `SubscriberPoll` is parked until one names the message's position:
//! at most [`MAX_PARKED`] fragments. An overflow is counted and puts every
//! trace of the publication that is not final then out of scope, its later
//! messages included (conservative). A fragment whose message can no
//! longer appear, once every publisher and subscriber journal of its
//! publication is terminal, is aged out and counted; the drain order of
//! the journals never changes a verdict. A network journal is expected for
//! a message at or above its start, below its boundary and outside its
//! recorded gaps, or whenever it holds a record of the message; one closed
//! without a boundary is lost, as a subscriber journal without its
//! boundary is. A publication with refused network journals
//! ([`TraceReport::network_refused`]) never has a final `Complete`.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::attribution::{AttributionConfig, Attributor, Verdict, combine};
use crate::clocks::{Calibration, ClockKey, Observation, latency};
use crate::error::TraceError;
use crate::histogram::{Histogram, HistogramError};
use crate::journal::{Collected, ObserverId, TraceCollector};
use crate::record::{NetworkPath, ObservedTime, Point, PublicationId};
use crate::source::{JournalSource, SourceState};
use crate::trace_clock::ClockProvenance;
use karyos_protocol::trace_hook::NetSide;

/// Network fragments a report parks while waiting for their message's
/// position (`trace-network.md` §5): past it, a fragment is counted and its
/// publication's non-final traces are out of scope.
pub const MAX_PARKED: usize = 4096;

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
    Subscriber {
        join: u64,
    },
    /// A network journal of one lane, expected from `start` on.
    Network {
        side: NetSide,
        lane: u8,
        start: u64,
    },
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
    /// subscription, with its final delivery boundary; for a network
    /// journal, its pickup or commit boundary.
    owner_closed: bool,
    boundary: Option<u64>,
    /// A network receiver journal's recorded gaps, `[from, to)`.
    gaps: Vec<(u64, u64)>,
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
    /// The terminal close of its handle, with `boundary`: a network
    /// journal without one has no decided membership, so it is lost.
    fn close(&mut self, boundary: Option<u64>) {
        self.owner_closed = true;
        match self.kind {
            Kind::Publisher => {}
            Kind::Subscriber { .. } => self.boundary = boundary,
            Kind::Network { .. } => {
                self.boundary = boundary;
                self.lost |= boundary.is_none();
            }
        }
    }

    fn terminal(&self) -> bool {
        self.finals.is_some()
    }

    /// For a subscription or network journal, whether it is expected for
    /// the message at `position` of `lane` of `publication`, given whether
    /// it `observed` the message: `Some` once decided. A lost journal is
    /// expected for every message from its join or start on; a network
    /// journal holding part of the message always is (§5).
    fn eligible(
        &self,
        publication: &PublicationKey,
        lane: u8,
        position: u64,
        observed: bool,
    ) -> Option<bool> {
        if self.publication != *publication {
            return Some(false);
        }
        let from = match self.kind {
            Kind::Publisher => return Some(false),
            Kind::Subscriber { join } => join,
            Kind::Network {
                lane: own, start, ..
            } => {
                if own != lane {
                    return Some(false);
                }
                if observed {
                    return Some(true);
                }
                if self
                    .gaps
                    .iter()
                    .any(|(gap_from, gap_to)| *gap_from <= position && position < *gap_to)
                {
                    return Some(false);
                }
                start
            }
        };
        if from > position {
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
    /// Network observations of its fragments: journal, point, frame
    /// position, path and time.
    network: Vec<NetworkObservation>,
}

impl Message {
    /// Whether journal `index` observed this message.
    fn observed_by(&self, index: usize) -> bool {
        self.polls
            .iter()
            .any(|(JournalId(journal), _)| *journal == index)
            || self
                .network
                .iter()
                .any(|observation| observation.journal.0 == index)
    }
}

/// One network observation of one fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkObservation {
    journal: JournalId,
    point: Point,
    /// The fragment's frame position.
    position: u64,
    path: NetworkPath,
    observed: ObservedTime,
}

/// The key a network record shares with its message: publication, lane,
/// trace id and `message_id`.
type FragmentKey = (PublicationKey, u8, [u64; 2], u64);

/// A fragment waiting for its message's position.
#[derive(Debug, Clone, Copy)]
struct Parked {
    key: FragmentKey,
    observation: NetworkObservation,
}

/// What became of the network fragments the report parked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParkedCounts {
    /// Fragments that found the parking area full.
    pub overflowed: u64,
    /// Fragments whose message can no longer appear: every publisher and
    /// subscriber journal of their publication was terminal.
    pub aged: u64,
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
    /// The message each fragment key names, once known.
    fragments: HashMap<FragmentKey, MessageKey>,
    /// Fragments waiting for their message's position (at most
    /// [`MAX_PARKED`]).
    parked: Vec<Parked>,
    parked_counts: ParkedCounts,
    /// Publications whose parking overflowed: their traces that were not
    /// final then, and every later message of them, are out of scope.
    parking_lost: Vec<PublicationKey>,
    /// Final answers of those traces, kept as they were.
    pinned: HashMap<[u64; 2], Verdict>,
    /// Publications with refused network journals: never `Complete`.
    refused: Vec<PublicationKey>,
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
            fragments: HashMap::new(),
            parked: Vec::new(),
            parked_counts: ParkedCounts::default(),
            parking_lost: Vec::new(),
            pinned: HashMap::new(),
            refused: Vec::new(),
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
            gaps: Vec::new(),
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

    /// Registers a network journal (`trace-network.md` §5) of `side` for
    /// `lane` of `publication`, read through `source` and stamped by
    /// `clock`: its records are expected from `start` on (the pickup start
    /// or the image join; from 0 when unknown). Its boundary comes with its
    /// close, and a receiver's gaps from [`TraceReport::network_gaps`].
    ///
    /// # Errors
    ///
    /// As [`TraceReport::add_publisher`].
    pub fn add_network_source(
        &mut self,
        source: impl JournalSource + 'static,
        clock: JournalClock,
        publication: PublicationKey,
        side: NetSide,
        lane: u8,
        start: Option<u64>,
    ) -> Result<JournalId, TraceError> {
        self.add(
            Box::new(source),
            clock,
            Kind::Network {
                side,
                lane,
                start: start.unwrap_or(0),
            },
            publication,
        )
    }

    /// [`TraceReport::add_network_source`] for an in-process collector.
    ///
    /// # Errors
    ///
    /// As [`TraceReport::add_publisher`].
    pub fn add_network(
        &mut self,
        collector: TraceCollector,
        provenance: ClockProvenance,
        publication: PublicationId,
        side: NetSide,
        lane: u8,
        start: Option<u64>,
    ) -> Result<JournalId, TraceError> {
        self.add_network_source(
            collector,
            provenance.into(),
            publication.into(),
            side,
            lane,
            start,
        )
    }

    /// Records the sealed gaps `[from, to)` of a network receiver journal's
    /// image, as far as known: frames in them are not expected. A gap list
    /// that overflowed passes the gaps it kept, and frames past the last of
    /// them stay expected, which is §5's in-process rule; passing no gaps
    /// is the tool's rule, where every frame at or after the first gap
    /// stays expected. Either way a frame lost to an unrecorded gap makes
    /// its trace `Incomplete`, never a false `Complete`.
    pub fn network_gaps(&mut self, journal: JournalId, gaps: &[(u64, u64)]) {
        if let Some(journal) = self.journals.get_mut(journal.0)
            && matches!(journal.kind, Kind::Network { .. })
        {
            journal.gaps.clear();
            journal.gaps.extend_from_slice(gaps);
        }
    }

    /// Records that `count` network journals of `publication` were refused
    /// (`trace-network.md` §5): no trace with a message of it is then a
    /// final `Complete`, since its network observations were never
    /// recorded.
    pub fn network_refused(&mut self, publication: PublicationKey, count: u64) {
        if count > 0 && !self.refused.contains(&publication) {
            self.refused.push(publication);
        }
    }

    /// What became of the parked network fragments.
    #[must_use]
    pub fn parked(&self) -> ParkedCounts {
        self.parked_counts
    }

    /// Records the terminal close of a journal's handle, after its writer
    /// closed and every observation it will make was made. A subscription
    /// passes its final delivery boundary, which decides the messages it is
    /// expected for, and a network journal its pickup or commit boundary;
    /// a publication passes `None`. A source that knows its terminal state
    /// ([`JournalSource::state`]) needs no call.
    pub fn closed(&mut self, journal: JournalId, boundary: Option<u64>) {
        if let Some(journal) = self.journals.get_mut(journal.0) {
            journal.close(boundary);
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
        self.age_parked();
        Ok(())
    }

    /// Ages out the parked fragments whose message can no longer appear:
    /// at least one publisher or subscriber journal of their publication
    /// is registered and all of them are terminal, so every record that
    /// could name the message was drained. Decided after every journal of
    /// the pass, so no drain order changes it.
    fn age_parked(&mut self) {
        let journals = &self.journals;
        let settled = |publication: &PublicationKey| {
            let mut clients = journals.iter().filter(|journal| {
                journal.publication == *publication
                    && matches!(journal.kind, Kind::Publisher | Kind::Subscriber { .. })
            });
            let mut any = false;
            let all = clients.all(|journal| {
                any = true;
                journal.terminal()
            });
            any && all
        };
        let before = self.parked.len();
        self.parked.retain(|parked| !settled(&parked.key.0));
        let aged = before
            .checked_sub(self.parked.len())
            .and_then(|aged| u64::try_from(aged).ok())
            .unwrap_or(0);
        if let Some(total) = self.parked_counts.aged.checked_add(aged) {
            self.parked_counts.aged = total;
        }
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
            SourceState::Closed { boundary } => journal.close(boundary),
            SourceState::Lost => {
                journal.owner_closed = true;
                journal.lost = true;
            }
        }
        let start = journal.start;
        // The publications whose fragments found the parking area full.
        let mut lost_parking: Vec<PublicationKey> = Vec::new();
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
                    let publication = PublicationKey::from(record.publication);
                    let fragment: FragmentKey = (
                        publication,
                        record.lane,
                        record.ids.trace_id,
                        record.ids.message_id,
                    );
                    // A network record names its own frame: it joins its
                    // message, or waits for it (§5), never creating one.
                    if matches!(record.point, Point::SenderPickup | Point::ReceiverCommit)
                        && let Some(path) = record.network
                    {
                        let observation = NetworkObservation {
                            journal: id,
                            point: record.point,
                            position: record.position,
                            path,
                            observed,
                        };
                        let known = self
                            .fragments
                            .get(&fragment)
                            .and_then(|key| self.messages.get_mut(key));
                        match known {
                            Some(message) => message.network.push(observation),
                            None if self.parked.len() < MAX_PARKED => self.parked.push(Parked {
                                key: fragment,
                                observation,
                            }),
                            None => {
                                count(&mut self.parked_counts.overflowed);
                                if !lost_parking.contains(&publication) {
                                    lost_parking.push(publication);
                                }
                            }
                        }
                        continue;
                    }
                    let key = (publication, record.lane, record.position);
                    let message = self.messages.entry(key).or_insert_with(|| Message {
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
                    // Both name the message's block: its fragments join it.
                    if matches!(record.point, Point::Publish | Point::SubscriberPoll) {
                        self.fragments.entry(fragment).or_insert(key);
                        let mut index = 0;
                        while let Some(parked) = self.parked.get(index) {
                            if parked.key == fragment {
                                let parked = self.parked.swap_remove(index);
                                message.network.push(parked.observation);
                            } else {
                                index += 1;
                            }
                        }
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
        for publication in lost_parking {
            self.lose_parking(publication);
        }
        Ok(())
    }

    /// The parking area overflowed for `publication`: its traces that are
    /// final keep their answer, and the others are out of scope from now
    /// on (§5).
    fn lose_parking(&mut self, publication: PublicationKey) {
        if self.parking_lost.contains(&publication) {
            return;
        }
        let mut traces: HashMap<[u64; 2], Vec<(&MessageKey, &Message)>> = HashMap::new();
        for (key, message) in &self.messages {
            if message.trace_id != [0, 0] {
                traces
                    .entry(message.trace_id)
                    .or_default()
                    .push((key, message));
            }
        }
        let pinned: Vec<([u64; 2], Verdict)> = traces
            .iter()
            .filter(|(_, messages)| messages.iter().any(|(key, _)| key.0 == publication))
            .filter_map(
                |(trace_id, messages)| match self.decide(*trace_id, messages) {
                    TraceAnswer::Final(verdict) => Some((*trace_id, verdict)),
                    _ => None,
                },
            )
            .collect();
        self.pinned.extend(pinned);
        self.parking_lost.push(publication);
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
    fn out_of_reach(
        &self,
        publication: &PublicationKey,
        lane: u8,
        position: u64,
        message: &Message,
    ) -> bool {
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
                Kind::Subscriber { .. } | Kind::Network { .. } => {
                    let observed = message.observed_by(index);
                    journal.eligible(publication, lane, position, observed) != Some(false)
                        && !observed
                }
            }
        })
    }

    fn decide(&self, trace_id: [u64; 2], messages: &[(&MessageKey, &Message)]) -> TraceAnswer {
        if messages.is_empty() {
            return TraceAnswer::Unknown;
        }
        if let Some(verdict) = self.pinned.get(&trace_id) {
            return TraceAnswer::Final(*verdict);
        }
        if messages.iter().any(|(key, message)| {
            let (publication, lane, position) = key;
            self.excluded_messages.contains(*key)
                || self.parking_lost.contains(publication)
                || self.out_of_reach(publication, *lane, *position, message)
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
        for ((publication, lane, position), message) in messages {
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
                let observed = message.observed_by(index);
                match journal.eligible(&publication, *lane, *position, observed) {
                    Some(true) => {
                        expected.push(index);
                        if journal.terminal() && !observed {
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
        // A refused network journal never recorded its observations (§5).
        if verdict == Verdict::Complete
            && messages
                .iter()
                .any(|((publication, _, _), _)| self.refused.contains(publication))
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

/// Adds one to a report count; a count that cannot rise keeps its value.
fn count(value: &mut u64) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
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
