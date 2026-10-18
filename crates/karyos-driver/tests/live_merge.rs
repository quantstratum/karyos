// SPDX-License-Identifier: Apache-2.0

//! The live merge over an embedded driver (SPEC.md §8.2; `quantstratum-docs:
//! karyos/design/archive-gap-analysis.md`, A6a). A stream is recorded
//! through a recording reader, and the frames read are fed into a replay
//! target (A5b), which a replay subscription reads at the recorded
//! positions; a live reader joins the stream at its head. The merge
//! delivers the replay below the live reader's position and the live
//! reader from it: no duplicate, no hole, and every disagreement typed.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use karyos_client::{
    ClientPublication, ClientSubscription, LiveMerge, MergeError, MergePoll, MessageLimit,
    OfferOutcome, Replay, ReplayStop,
};
use karyos_driver::recording::RecordingLease;
use karyos_driver::replay::{ReplayFeed, ReplayTargetConfig};
use karyos_driver::{EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_protocol::trace_hook::PublicationIdentity;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    LogBuffer, LogBufferConfig, LossPolicy, PublicationMode, ReadError, ReadOrigin, ReadOutcome,
    Role, SealReason, SenderRead, SkipReason,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

const SOURCE: i32 = 42;
const OTHER: i32 = 44;
const TARGET: i32 = 43;
const INITIAL_TERM_ID: i32 = 7;

fn stream(stream_id: i32, term_length: u32) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(term_length).unwrap(),
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(INITIAL_TERM_ID.cast_unsigned()),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// Message `sequence`, `length` bytes, its sequence in its first word.
fn message(sequence: u32, length: usize) -> Vec<u8> {
    let mut data = vec![u8::try_from(sequence % 251).unwrap(); length];
    data[..4].copy_from_slice(&sequence.to_le_bytes());
    data
}

fn sequence(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

/// What a recording reader read: whole frames, or a canonical record and
/// its extent.
#[derive(Debug, Clone)]
enum Run {
    Frames(u64, Vec<u8>),
    Fill(u64, Vec<u8>, u32),
}

impl Run {
    fn position(&self) -> u64 {
        match self {
            Self::Frames(position, _) | Self::Fill(position, _, _) => *position,
        }
    }
}

/// A recorded stream: its publication, a recording reader and the runs
/// it read so far.
struct Recorded {
    handle: StreamHandle,
    publication: ClientPublication,
    reader: SenderRead<Arc<LogBuffer<HeapTerms>>>,
    _lease: RecordingLease,
    runs: Vec<Run>,
    sent: u32,
    term_length: u32,
}

impl Recorded {
    fn new(driver: &mut EmbeddedDriver, stream_id: i32) -> Self {
        Self::with_terms(driver, stream_id, MIN_TERM_LENGTH)
    }

    fn with_terms(driver: &mut EmbeddedDriver, stream_id: i32, term_length: u32) -> Self {
        let handle = driver.add_stream(stream(stream_id, term_length)).unwrap();
        let (reader, lease) = driver
            .recording_reader(handle, Role::Required)
            .unwrap()
            .into_parts();
        Self {
            handle,
            publication: driver.publication(handle).unwrap(),
            reader,
            _lease: lease,
            runs: Vec::new(),
            sent: 0,
            term_length,
        }
    }

    /// Publishes `count` more messages of `length` bytes and records
    /// them as the recording reader reads them.
    fn publish(&mut self, driver: &mut EmbeddedDriver, count: u32, length: usize) {
        let target = self.sent + count;
        let mut out = vec![0u8; usize::try_from(self.term_length).unwrap()];
        let mut idle = 0;
        while (self.sent < target || idle < 4) && idle < 1000 {
            if self.sent < target
                && let OfferOutcome::Accepted { .. } =
                    self.publication.offer(&message(self.sent, length)).unwrap()
            {
                self.sent += 1;
            }
            driver.do_work().unwrap();
            let from = self.reader.position();
            match self
                .reader
                .read_committed(from, ReadOrigin::Cursor, &mut out)
            {
                Ok(ReadOutcome::Copied { len, next }) => {
                    self.runs.push(Run::Frames(from, out[..len].to_vec()));
                    self.reader.sent(next).unwrap();
                    idle = 0;
                }
                Ok(ReadOutcome::Canonical { next, .. }) => {
                    let extent = u32::try_from(next - from).unwrap();
                    self.runs.push(Run::Fill(from, out[..32].to_vec(), extent));
                    self.reader.sent(next).unwrap();
                    idle = 0;
                }
                Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => idle += 1,
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(self.sent, target);
    }

    fn end(&self) -> u64 {
        self.reader.position()
    }
}

/// Counts the stops of a replay.
#[derive(Clone, Default)]
struct Stops(Arc<AtomicUsize>);

impl ReplayStop for Stops {
    fn stop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

impl Stops {
    fn count(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

/// A replay target of `stream_id`'s recording in terms of `term_length`,
/// joined at `join`, its feed and its reader.
fn target(
    driver: &mut EmbeddedDriver,
    stream_id: i32,
    term_length: u32,
    join: u64,
) -> (
    karyos_driver::AggregateHandle,
    ReplayFeed<HeapTerms>,
    ClientSubscription,
) {
    let (handle, feed) = driver
        .replay_target(ReplayTargetConfig {
            stream_id: TARGET,
            session_id: 9,
            term_length,
            initial_term_id: INITIAL_TERM_ID,
            mtu: DEFAULT_MTU,
            join,
            lane: Lane::ZERO,
            source_stream_id: stream_id,
            source_session_id: 1,
        })
        .unwrap();
    let reader = driver
        .subscribe(handle.lane(Lane::ZERO).unwrap(), Role::Required)
        .unwrap();
    (handle, feed, reader)
}

/// A replay being fed: the runs left, and where it ends.
struct Feeding {
    handle: Option<karyos_driver::AggregateHandle>,
    feed: Option<ReplayFeed<HeapTerms>>,
    runs: std::collections::VecDeque<Run>,
    /// A range sealed as a gap in place of the runs it covers.
    gap: Option<(u64, u64)>,
    end: u64,
    /// The runs from here on wait.
    hold: Option<u64>,
}

impl Feeding {
    /// Feeds what the target takes, and seals it at `end` once every run
    /// was written.
    fn step(&mut self, driver: &mut EmbeddedDriver) {
        let Some(feed) = self.feed.as_mut() else {
            return;
        };
        while let Some(run) = self.runs.front() {
            if self.hold.is_some_and(|hold| run.position() >= hold) {
                return;
            }
            if let Some((from, to)) = self.gap.filter(|(from, _)| run.position() == *from) {
                if !feed.gap(from, to).unwrap() {
                    return;
                }
                // The runs the gap covers are not written.
                self.runs.retain(|run| run.position() >= to);
                self.gap = None;
                continue;
            }
            let taken = match run {
                Run::Frames(position, bytes) => feed.frames(*position, bytes).unwrap(),
                Run::Fill(position, record, extent) => {
                    feed.fill(*position, record, *extent).unwrap()
                }
            };
            if !taken {
                return;
            }
            self.runs.pop_front();
        }
        let (handle, feed) = (self.handle.take().unwrap(), self.feed.take().unwrap());
        driver.finish_replay(handle, feed, self.end).unwrap();
    }
}

/// A replay of `recorded`'s runs below `end`, sealed at `end`, as the
/// recording of `source`; the gap `gap`, if any, replaces the runs in it.
fn replay_of(
    driver: &mut EmbeddedDriver,
    recorded: &Recorded,
    stream_id: i32,
    end: u64,
    gap: Option<(u64, u64)>,
    source: PublicationIdentity,
    stops: &Stops,
) -> (Box<Replay>, Feeding) {
    replay_from(driver, recorded, stream_id, 0..end, gap, source, stops)
}

/// [`replay_of`] over `range`: joined at its start.
fn replay_from(
    driver: &mut EmbeddedDriver,
    recorded: &Recorded,
    stream_id: i32,
    range: std::ops::Range<u64>,
    gap: Option<(u64, u64)>,
    source: PublicationIdentity,
    stops: &Stops,
) -> (Box<Replay>, Feeding) {
    let (handle, feed, reader) = target(driver, stream_id, recorded.term_length, range.start);
    let end = range.end;
    let runs = recorded
        .runs
        .iter()
        .filter(|run| range.contains(&run.position()))
        .cloned()
        .collect();
    let replay = Replay::new(reader, source).with_stop(Box::new(stops.clone()));
    (
        Box::new(replay),
        Feeding {
            handle: Some(handle),
            feed: Some(feed),
            runs,
            gap,
            end,
            hold: None,
        },
    )
}

/// What a merge delivered: each message's sequence and position, the polls
/// and the failure that ended it, if any.
#[derive(Default)]
struct Merged {
    messages: Vec<(u32, u64, usize)>,
    polls: Vec<MergePoll>,
    failure: Option<MergeError>,
}

/// Polls `merge`, feeding the replay and running the driver, until `count`
/// messages came, it failed, or 2000 cycles passed.
fn run(
    driver: &mut EmbeddedDriver,
    merge: &mut LiveMerge,
    feeding: &mut Feeding,
    count: usize,
) -> Merged {
    let mut merged = Merged::default();
    for _ in 0..2000 {
        feeding.step(driver);
        driver.do_work().unwrap();
        let polled = merge.poll(
            |bytes, info| {
                merged
                    .messages
                    .push((sequence(bytes), info.position, bytes.len()));
            },
            MessageLimit::new(8),
        );
        match polled {
            Ok(poll) => merged.polls.push(poll),
            Err(failed) => {
                merged.polls.push(failed.poll);
                merged.failure = Some(failed.cause);
                return merged;
            }
        }
        if merged.messages.len() >= count {
            break;
        }
    }
    merged
}

/// A driver, a recorded source with `before` messages, then a live
/// reader joined at the head, then `after` more messages: returns the
/// driver, the recording, the live reader and its join position.
fn joined(
    before: u32,
    after: u32,
    live_role: Role,
) -> (EmbeddedDriver, Recorded, ClientSubscription, u64) {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut recorded = Recorded::new(&mut driver, SOURCE);
    recorded.publish(&mut driver, before, 1000);
    let live = driver.subscribe(recorded.handle, live_role).unwrap();
    let cutover = live.position();
    assert_eq!(cutover, recorded.end());
    recorded.publish(&mut driver, after, 1000);
    (driver, recorded, live, cutover)
}

/// The merge delivers every message once, in order: the replay's below
/// the cutover, the live reader's from it; the replay's duplicates past
/// the cutover are dropped; the replay stops at the cutover.
#[test]
fn a_merge_cuts_over_with_no_duplicate_and_no_hole() {
    // A required live reader holds its publisher back: a window past
    // the cutover is published.
    let (mut driver, recorded, live, cutover) = joined(100, 20, Role::Required);
    assert!(cutover > u64::from(MIN_TERM_LENGTH), "crosses a term");
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    // The whole recording: past the cutover too.
    let end = recorded.end();
    let (replay, mut feeding) =
        replay_of(&mut driver, &recorded, SOURCE, end, None, source, &stops);
    let mut merge = LiveMerge::new(live, source, replay);
    assert_eq!(merge.cutover(), cutover);
    let merged = run(&mut driver, &mut merge, &mut feeding, 120);
    assert_eq!(merged.failure, None);
    let sequences: Vec<u32> = merged
        .messages
        .iter()
        .map(|(sequence, ..)| *sequence)
        .collect();
    assert_eq!(sequences, (0..120).collect::<Vec<_>>());
    assert!(merged.messages.windows(2).all(|pair| pair[0].1 < pair[1].1));
    let cutovers: Vec<u64> = merged
        .polls
        .iter()
        .filter_map(|poll| poll.cutover)
        .collect();
    assert_eq!(cutovers, [cutover]);
    assert!(merge.is_live());
    assert_eq!(stops.count(), 1);
    drop(merge);
    assert_eq!(stops.count(), 1);
}

/// A replay that ends exactly at the cutover hands over to the live
/// reader there; one that ends below it fails, typed, and stops.
#[test]
fn a_replay_must_reach_the_cutover() {
    let (mut driver, recorded, live, cutover) = joined(60, 20, Role::Required);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let (replay, mut feeding) = replay_of(
        &mut driver,
        &recorded,
        SOURCE,
        cutover,
        None,
        source,
        &stops,
    );
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 80);
    assert_eq!(merged.failure, None);
    let sequences: Vec<u32> = merged
        .messages
        .iter()
        .map(|(sequence, ..)| *sequence)
        .collect();
    assert_eq!(sequences, (0..80).collect::<Vec<_>>());

    let (mut driver, recorded, live, cutover) = joined(60, 20, Role::Required);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let short = recorded.runs[40].position();
    let (replay, mut feeding) =
        replay_of(&mut driver, &recorded, SOURCE, short, None, source, &stops);
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 80);
    assert_eq!(
        merged.failure,
        Some(MergeError::ReplayShort {
            end: short,
            reason: SealReason::EndOfStream,
            cutover,
        })
    );
    assert!(
        merged
            .messages
            .iter()
            .all(|(_, position, _)| *position < short)
    );
    assert_eq!(stops.count(), 1);
    // Final: the next poll reports it again and delivers nothing.
    let again = merge.poll(|_, _| panic!("delivered"), MessageLimit::new(8));
    assert!(matches!(
        again,
        Err(failed) if matches!(failed.cause, MergeError::ReplayShort { .. })
    ));
    assert!(merge.failure().is_some());
}

/// A replay of another incarnation of the publication is an epoch change:
/// the merge fails before it delivers, and the replay stops at once.
#[test]
fn a_replay_of_another_incarnation_is_an_epoch_change() {
    let (mut driver, recorded, live, _) = joined(20, 0, Role::Required);
    let live_source = driver.trace_identity(recorded.handle).unwrap();
    let replayed = PublicationIdentity {
        incarnation: live_source.incarnation + 1,
        ..live_source
    };
    let stops = Stops::default();
    let end = recorded.end();
    let (replay, mut feeding) =
        replay_of(&mut driver, &recorded, SOURCE, end, None, replayed, &stops);
    let mut merge = LiveMerge::new(live, live_source, replay);
    assert_eq!(stops.count(), 1);
    let merged = run(&mut driver, &mut merge, &mut feeding, 1);
    assert_eq!(
        merged.failure,
        Some(MergeError::EpochChanged {
            replay: replayed,
            live: live_source,
        })
    );
    assert!(merged.messages.is_empty());
}

/// A replay of another log, under the live stream's identity, disagrees
/// with it at the cutover: the live reader's first message is not the
/// replay's there, and the merge fails, typed, instead of merging.
#[test]
fn a_replay_of_another_log_is_a_mismatch() {
    let mut driver = EmbeddedDriver::new().unwrap();
    // Two streams alike up to the cutover, then with other lengths.
    let mut replayed = Recorded::new(&mut driver, OTHER);
    let mut recorded = Recorded::new(&mut driver, SOURCE);
    replayed.publish(&mut driver, 30, 1000);
    recorded.publish(&mut driver, 30, 1000);
    assert_eq!(replayed.end(), recorded.end());
    let live = driver.subscribe(recorded.handle, Role::Required).unwrap();
    let cutover = live.position();
    replayed.publish(&mut driver, 10, 1000);
    recorded.publish(&mut driver, 10, 2000);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let end = replayed.end();
    let (replay, mut feeding) = replay_of(&mut driver, &replayed, OTHER, end, None, source, &stops);
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 40);
    assert_eq!(
        merged.failure,
        Some(MergeError::Mismatch {
            position: cutover,
            cutover,
        })
    );
    let sequences: Vec<u32> = merged
        .messages
        .iter()
        .map(|(sequence, ..)| *sequence)
        .collect();
    assert_eq!(sequences, (0..30).collect::<Vec<_>>());
    assert_eq!(stops.count(), 1);
    // The required live reader declined its first message: it is still
    // at the cutover, and delivers it next.
    let mut live = merge.into_live();
    assert_eq!(live.position(), cutover);
    let mut first = None;
    live.poll(
        |bytes, info| {
            first.get_or_insert((sequence(bytes), info.position, bytes.len()));
        },
        MessageLimit::new(1),
    )
    .unwrap();
    assert_eq!(first, Some((30, cutover, 2000)));
}

/// A gap in the recording below the cutover is reported as the replay's
/// local gap, and the merge goes on to the cutover and the live reader.
#[test]
fn a_gap_in_the_recording_is_reported_and_the_merge_goes_on() {
    let (mut driver, recorded, live, cutover) = joined(40, 10, Role::Required);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let (from, to) = (recorded.runs[10].position(), recorded.runs[15].position());
    let (replay, mut feeding) = replay_of(
        &mut driver,
        &recorded,
        SOURCE,
        cutover,
        Some((from, to)),
        source,
        &stops,
    );
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 45);
    assert_eq!(merged.failure, None);
    let skipped: Vec<_> = merged
        .polls
        .iter()
        .filter_map(|poll| poll.summary.skipped)
        .collect();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].position, from);
    assert_eq!(u64::from(skipped[0].extent), to - from);
    assert!(matches!(skipped[0].reason, SkipReason::LocalGap(_)));
    let positions: Vec<u64> = merged
        .messages
        .iter()
        .map(|(_, position, _)| *position)
        .collect();
    assert!(
        positions
            .iter()
            .all(|position| !(from..to).contains(position))
    );
    let sequences: Vec<u32> = merged
        .messages
        .iter()
        .map(|(sequence, ..)| *sequence)
        .collect();
    assert_eq!(sequences.last(), Some(&49));
}

/// An optional live reader lapped while the replay delivered below the
/// cutover fails the merge with the overrun's positions, never a silent
/// skip.
#[test]
fn a_lapped_live_reader_fails_the_merge() {
    let (mut driver, recorded, live, cutover) = joined(20, 300, Role::Optional);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let (replay, mut feeding) = replay_of(
        &mut driver,
        &recorded,
        SOURCE,
        cutover,
        None,
        source,
        &stops,
    );
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 400);
    let Some(MergeError::LiveOverrun(overrun)) = merged.failure else {
        panic!("{:?}", merged.failure);
    };
    assert_eq!(overrun.from, cutover);
    assert!(overrun.resume > cutover);
    let sequences: Vec<u32> = merged
        .messages
        .iter()
        .map(|(sequence, ..)| *sequence)
        .collect();
    assert_eq!(sequences, (0..20).collect::<Vec<_>>());
}

/// The live reader can be taken back at any time; the replay stops then,
/// and the live reader is still where the merge found it.
#[test]
fn the_live_reader_is_given_back() {
    let (mut driver, recorded, live, cutover) = joined(20, 5, Role::Required);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let (replay, _feeding) = replay_of(
        &mut driver,
        &recorded,
        SOURCE,
        cutover,
        None,
        source,
        &stops,
    );
    let merge = LiveMerge::new(live, source, replay);
    let live = merge.into_live();
    assert_eq!(stops.count(), 1);
    assert_eq!(live.position(), cutover);
}

/// Two streams recorded side by side, and a live reader of the second
/// joined after `live_count` messages of `live_length` bytes: returns the
/// driver, the first (replayed) stream after `replayed_count` messages of
/// `replayed_length` bytes, the live reader, its join position and the
/// second stream's identity.
fn other_log(
    replayed_count: u32,
    replayed_length: usize,
    live_count: u32,
    live_length: usize,
) -> (
    EmbeddedDriver,
    Recorded,
    ClientSubscription,
    u64,
    PublicationIdentity,
) {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut replayed = Recorded::new(&mut driver, OTHER);
    let mut recorded = Recorded::new(&mut driver, SOURCE);
    replayed.publish(&mut driver, replayed_count, replayed_length);
    recorded.publish(&mut driver, live_count, live_length);
    let live = driver.subscribe(recorded.handle, Role::Required).unwrap();
    let cutover = live.position();
    let source = driver.trace_identity(recorded.handle).unwrap();
    (driver, replayed, live, cutover, source)
}

/// A replay message that runs across the cutover belongs to another log:
/// it was delivered, and then the merge fails, typed.
#[test]
fn a_replay_message_across_the_cutover_is_a_mismatch() {
    // Messages of 1568 bytes on the live stream (two frames under the
    // mtu), 1056 in the replay: the cutover, after ten live messages,
    // falls inside the replay's fifteenth.
    let (mut driver, replayed, live, cutover, source) = other_log(20, 1000, 10, 1500);
    assert_eq!(cutover, 15_680);
    let stops = Stops::default();
    let end = replayed.end();
    let (replay, mut feeding) = replay_of(&mut driver, &replayed, OTHER, end, None, source, &stops);
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 20);
    assert_eq!(
        merged.failure,
        Some(MergeError::Mismatch {
            position: 14 * 1056,
            cutover,
        })
    );
    // The fifteenth would end past the cutover even unfragmented: it is
    // not delivered.
    assert_eq!(merged.messages.len(), 14);
}

/// Term padding in the replay over the cutover belongs to another log: the
/// merge fails, typed, rather than switch past it.
#[test]
fn term_padding_across_the_cutover_is_a_mismatch() {
    // Messages of 3104 bytes in the replay (three frames under the mtu),
    // so its first term ends in padding from 65_184; messages of 1056 on
    // the live stream, joined at 65_472.
    let (mut driver, replayed, live, cutover, source) = other_log(25, 3000, 62, 1000);
    assert_eq!(cutover, 65_472);
    let stops = Stops::default();
    let end = replayed.end();
    let (replay, mut feeding) = replay_of(&mut driver, &replayed, OTHER, end, None, source, &stops);
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 25);
    assert_eq!(
        merged.failure,
        Some(MergeError::Mismatch {
            position: 65_184,
            cutover,
        })
    );
    assert_eq!(merged.messages.len(), 21);
}

/// A replay that starts past the cutover would skip what lies between:
/// the merge fails, typed, before it delivers.
#[test]
fn a_replay_past_the_cutover_is_a_mismatch() {
    let (mut driver, recorded, live, cutover) = joined(20, 10, Role::Required);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let start = recorded.runs[25].position();
    assert!(start > cutover);
    let (replay, mut feeding) = replay_from(
        &mut driver,
        &recorded,
        SOURCE,
        start..recorded.end(),
        None,
        source,
        &stops,
    );
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 1);
    assert_eq!(
        merged.failure,
        Some(MergeError::Mismatch {
            position: start,
            cutover,
        })
    );
    assert!(merged.messages.is_empty());
}

/// A replay laid out in other terms disagrees with the live stream at the
/// cutover: the live reader's first message comes after term padding the
/// replay does not have, so the merge fails, typed.
#[test]
fn a_replay_in_other_terms_is_a_mismatch() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut replayed = Recorded::with_terms(&mut driver, OTHER, 2 * MIN_TERM_LENGTH);
    let mut recorded = Recorded::new(&mut driver, SOURCE);
    // 62 messages of 1056 bytes: the live stream's first term ends there,
    // in padding; the replay's goes on.
    replayed.publish(&mut driver, 62, 1000);
    recorded.publish(&mut driver, 62, 1000);
    let live = driver.subscribe(recorded.handle, Role::Required).unwrap();
    let cutover = live.position();
    assert_eq!(cutover, 65_472);
    replayed.publish(&mut driver, 5, 1000);
    recorded.publish(&mut driver, 5, 1000);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let end = replayed.end();
    let (replay, mut feeding) = replay_of(&mut driver, &replayed, OTHER, end, None, source, &stops);
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 67);
    assert_eq!(
        merged.failure,
        Some(MergeError::Mismatch {
            position: u64::from(MIN_TERM_LENGTH),
            cutover,
        })
    );
    assert_eq!(merged.messages.len(), 62);
}

/// Term padding at the cutover, with the replay's next term written later:
/// the replay steps over the padding and waits there, and the merge cuts
/// over once the next term's first message comes, checked against the
/// live reader's.
#[test]
fn term_padding_at_the_cutover_waits_for_the_next_term() {
    // 62 messages of 1056 bytes: the first term ends in padding from the
    // live reader's join at 65_472.
    let (mut driver, recorded, live, cutover) = joined(62, 5, Role::Required);
    assert_eq!(cutover, 65_472);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let end = recorded.end();
    let (replay, mut feeding) =
        replay_of(&mut driver, &recorded, SOURCE, end, None, source, &stops);
    feeding.hold = Some(u64::from(MIN_TERM_LENGTH));
    let mut merge = LiveMerge::new(live, source, replay);
    let waiting = run(&mut driver, &mut merge, &mut feeding, 63);
    assert_eq!(waiting.failure, None);
    assert_eq!(waiting.messages.len(), 62);
    assert!(!merge.is_live());
    feeding.hold = None;
    let rest = run(&mut driver, &mut merge, &mut feeding, 5);
    assert_eq!(rest.failure, None);
    let sequences: Vec<u32> = rest
        .messages
        .iter()
        .map(|(sequence, ..)| *sequence)
        .collect();
    assert_eq!(sequences, (62..67).collect::<Vec<_>>());
    assert_eq!(rest.messages[0].1, u64::from(MIN_TERM_LENGTH));
    let cutovers: Vec<u64> = rest.polls.iter().filter_map(|poll| poll.cutover).collect();
    assert_eq!(cutovers, [cutover]);
}

/// A live reader of another lane than 0 does not merge: the merge fails,
/// typed, and the replay stops.
#[test]
fn only_lane_zero_merges() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let recorded = Recorded::new(&mut driver, SOURCE);
    let lanes = driver
        .add_aggregate(karyos_driver::AggregateConfig {
            stream: stream(OTHER, MIN_TERM_LENGTH),
            quanta: vec![u64::from(karyos_sys::sizing::align_frame(DEFAULT_MTU).unwrap()); 3],
        })
        .unwrap();
    let lane = Lane::try_new(2).unwrap();
    let live = driver
        .subscribe(lanes.lane(lane).unwrap(), Role::Required)
        .unwrap();
    let source = driver.trace_identity(lanes.lane(lane).unwrap()).unwrap();
    let stops = Stops::default();
    let (replay, mut feeding) = replay_of(&mut driver, &recorded, SOURCE, 0, None, source, &stops);
    let mut merge = LiveMerge::new(live, source, replay);
    assert_eq!(stops.count(), 1);
    let merged = run(&mut driver, &mut merge, &mut feeding, 1);
    assert_eq!(
        merged.failure,
        Some(MergeError::Lane {
            live: Some(lane),
            replay: Some(Lane::ZERO),
        })
    );
}

/// A poll with a limit of 0 does nothing: not at the cutover, where the
/// replay's next frame would be looked at, nor once live, where the live
/// reader's first message would be checked and delivered.
#[test]
fn a_limit_of_zero_does_nothing() {
    let (mut driver, recorded, live, cutover) = joined(10, 5, Role::Required);
    let source = driver.trace_identity(recorded.handle).unwrap();
    let stops = Stops::default();
    let end = recorded.end();
    let (replay, mut feeding) =
        replay_of(&mut driver, &recorded, SOURCE, end, None, source, &stops);
    // The replay waits at the cutover for what follows it.
    feeding.hold = Some(cutover);
    let mut merge = LiveMerge::new(live, source, replay);
    let below = run(&mut driver, &mut merge, &mut feeding, 11);
    assert_eq!(below.messages.len(), 10);
    assert!(!merge.is_live());
    feeding.hold = None;
    for _ in 0..50 {
        feeding.step(&mut driver);
        driver.do_work().unwrap();
    }
    let zero = |merge: &mut LiveMerge| {
        merge
            .poll(|_, _| panic!("delivered"), MessageLimit::new(0))
            .unwrap()
    };
    assert_eq!(zero(&mut merge), MergePoll::default());
    assert!(!merge.is_live());
    // Cut over, with the live reader's first message still to check.
    let cut = merge
        .poll(|_, _| panic!("delivered"), MessageLimit::new(1))
        .unwrap();
    assert_eq!(cut.cutover, Some(cutover));
    assert_eq!(zero(&mut merge), MergePoll::default());
    let first = merge
        .poll(
            |_, info| assert_eq!(info.position, cutover),
            MessageLimit::new(1),
        )
        .unwrap();
    assert_eq!(first.summary.delivered, 1);
}

/// A fragmented replay message that runs across the cutover, though one
/// frame of it would not, is found once delivered: then the merge fails,
/// typed.
#[test]
fn a_fragmented_message_across_the_cutover_is_a_mismatch() {
    // 1500 bytes take two frames, 1568 bytes; one frame would end at
    // 1536, the live stream's cutover after three 512-byte frames.
    let (mut driver, replayed, live, cutover, source) = other_log(5, 1500, 3, 480);
    assert_eq!(cutover, 1536);
    let stops = Stops::default();
    let end = replayed.end();
    let (replay, mut feeding) = replay_of(&mut driver, &replayed, OTHER, end, None, source, &stops);
    let mut merge = LiveMerge::new(live, source, replay);
    let merged = run(&mut driver, &mut merge, &mut feeding, 5);
    assert_eq!(
        merged.failure,
        Some(MergeError::Mismatch {
            position: 0,
            cutover,
        })
    );
    assert_eq!(merged.messages.len(), 1);
}
