// SPDX-License-Identifier: Apache-2.0

//! A replay target over a heap driver: a stream's frames, read by a
//! recording reader, are written into the target at their positions and
//! read back by an aggregate subscription; the end seals as the replay
//! ended, a recorded gap reads as a local gap, and refusals are typed.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use karyos_client::aggregate::{AggregatePoll, LaneEnd};
use karyos_client::{ClientPublication, OfferOutcome};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    LogBufferConfig, LossPolicy, PublicationMode, ReadError, ReadOrigin, ReadOutcome, Role,
    SkipReason,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

use super::*;
use crate::embedded::{StreamConfig, StreamHandle};

const MESSAGE: usize = 1000;
const INITIAL_TERM_ID: i32 = 7;
const BUDGET: Budget = Budget {
    work: 64,
    bytes: 1 << 20,
};

fn source() -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 4,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(INITIAL_TERM_ID.cast_unsigned()),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 42,
            claim_deadline: 100,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// A driver whose recorded streams start at [`INITIAL_TERM_ID`], the
/// term id every replay target here is given, in place of a drawn one.
fn pinned() -> EmbeddedDriver {
    EmbeddedDriver::with_config(crate::embedded::DriverConfig {
        initial_term_id: Some(INITIAL_TERM_ID.cast_unsigned()),
        ..crate::embedded::DriverConfig::default()
    })
    .unwrap()
}

/// A target on another stream than the recorded one, as SPEC §8.2 has.
fn target(session_id: i32, join: u64) -> ReplayTargetConfig {
    ReplayTargetConfig {
        stream_id: 43,
        session_id,
        term_length: MIN_TERM_LENGTH,
        initial_term_id: INITIAL_TERM_ID,
        mtu: DEFAULT_MTU,
        join,
        lane: Lane::ZERO,
        source_stream_id: 42,
        source_session_id: 1,
    }
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

/// Publishes `count` messages, each holding its index, and records them
/// as a recording reader reads them; returns the runs and the end.
fn record(driver: &mut EmbeddedDriver<HeapTerms>, count: u32) -> (Vec<Run>, u64) {
    let (runs, end, _) = record_format(driver, count);
    (runs, end)
}

/// [`record`], with the recorded stream and the recording's format.
fn record_format(
    driver: &mut EmbeddedDriver<HeapTerms>,
    count: u32,
) -> (
    Vec<Run>,
    u64,
    (StreamHandle, crate::recording::RecordingFormat),
) {
    let handle = driver.add_stream(source()).unwrap();
    let recording = driver.recording_reader(handle, Role::Required).unwrap();
    let format = recording.format();
    let (mut reader, _lease) = recording.into_parts();
    let mut publication: ClientPublication = driver.publication(handle).unwrap();
    let mut runs = Vec::new();
    let mut out = vec![0u8; usize::try_from(MIN_TERM_LENGTH).unwrap()];
    let mut sent = 0;
    let mut idle = 0;
    while (sent < count || idle < 4) && idle < 1000 {
        if sent < count {
            let mut message = [0u8; MESSAGE];
            message[..4].copy_from_slice(&sent.to_le_bytes());
            if let OfferOutcome::Accepted { .. } = publication.offer(&message).unwrap() {
                sent += 1;
            }
        }
        driver.do_work().unwrap();
        let from = reader.position();
        match reader.read_committed(from, ReadOrigin::Cursor, &mut out) {
            Ok(ReadOutcome::Copied { len, next }) => {
                runs.push(Run::Frames(from, out[..len].to_vec()));
                reader.sent(next).unwrap();
                idle = 0;
            }
            Ok(ReadOutcome::Canonical { next, .. }) => {
                let extent = u32::try_from(next - from).unwrap();
                runs.push(Run::Fill(from, out[..32].to_vec(), extent));
                reader.sent(next).unwrap();
                idle = 0;
            }
            Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => idle += 1,
            Err(error) => panic!("{error:?}"),
        }
    }
    assert_eq!(sent, count);
    (runs, reader.position(), (handle, format))
}

/// Feeds `runs` into `feed` and polls `reader` as it goes; the runs in
/// `lost` are sealed as one gap instead, from the first's position to the
/// next run's. The driver runs after each write, or, when `eager`, only
/// after a write that found its term not ready. Returns how many writes
/// were not taken.
#[allow(clippy::too_many_arguments, reason = "a test's knobs")]
fn replay<T: StreamTerms>(
    driver: &mut EmbeddedDriver<T>,
    feed: &mut ReplayFeed<T>,
    reader: &mut karyos_client::aggregate::AggregateSubscription<T>,
    runs: &[Run],
    lost: Option<std::ops::Range<usize>>,
    eager: bool,
    seen: &mut Vec<u32>,
    polls: &mut Vec<AggregatePoll>,
) -> usize {
    let mut refused = 0;
    let mut index = 0;
    while index < runs.len() {
        let run = &runs[index];
        let mut tries = 0;
        loop {
            let (taken, next) = match &lost {
                Some(lost) if lost.start == index => {
                    let end = runs
                        .get(lost.end)
                        .map(Run::position)
                        .unwrap_or_else(|| panic!("a gap needs a next run"));
                    (feed.gap(run.position(), end).unwrap(), lost.end)
                }
                _ => {
                    let taken = match run {
                        Run::Frames(position, bytes) => feed.frames(*position, bytes).unwrap(),
                        Run::Fill(position, record, extent) => {
                            feed.fill(*position, record, *extent).unwrap()
                        }
                    };
                    (taken, index + 1)
                }
            };
            if !taken {
                refused += 1;
            }
            if !eager || !taken {
                driver.do_work().unwrap();
                polls.push(reader.poll(
                    |bytes, _, _| seen.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                    BUDGET,
                ));
            }
            if taken {
                index = next;
                break;
            }
            tries += 1;
            assert!(tries < 1000, "run {index} never taken");
        }
    }
    refused
}

/// Polls until the aggregate's terminal, at most 1000 polls.
fn until_terminal<T: StreamTerms>(
    driver: &mut EmbeddedDriver<T>,
    reader: &mut karyos_client::aggregate::AggregateSubscription<T>,
    seen: &mut Vec<u32>,
) -> AggregatePoll {
    for _ in 0..1000 {
        driver.do_work().unwrap();
        let poll = reader.poll(
            |bytes, _, _| seen.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            BUDGET,
        );
        if poll.terminal.is_some() {
            return poll;
        }
    }
    panic!("no terminal");
}

/// A stream recorded across terms (frames and the padding at each term's
/// end) replays at its positions, in order and whole, and ends at its end
/// with a clean EOS.
#[test]
fn a_replay_target_delivers_the_recording_at_its_positions() {
    let mut driver = pinned();
    let count = 200;
    let (runs, end) = record(&mut driver, count);
    assert!(end > 3 * u64::from(MIN_TERM_LENGTH), "crosses terms: {end}");
    assert!(runs.iter().any(|run| matches!(run, Run::Fill(..))));
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert_eq!(feed.position(), end);
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert_eq!(seen, (0..count).collect::<Vec<_>>());
    assert_eq!(
        terminal.lanes[0].end,
        Some(LaneEnd::Closed {
            position: end,
            reason: SealReason::EndOfStream
        })
    );
    assert!(terminal.terminal.unwrap().clean);
}

/// A replay target keeps the recording's `initial_term_id` from its
/// config, on a driver that draws one for each local publication: the
/// target is an image, never drawn. A recording made from that id
/// replays exactly.
#[test]
fn a_replay_target_keeps_the_recordings_initial_term_id() {
    const RECORDED: u32 = 0x1234_5678;
    let mut recorder = EmbeddedDriver::with_config(crate::embedded::DriverConfig {
        initial_term_id: Some(RECORDED),
        ..crate::embedded::DriverConfig::default()
    })
    .unwrap();
    let count = 200;
    let (runs, end) = record(&mut recorder, count);
    // No override: this driver draws.
    let mut driver = EmbeddedDriver::new().unwrap();
    let config = ReplayTargetConfig {
        initial_term_id: RECORDED.cast_signed(),
        ..target(2, 0)
    };
    let (handle, mut feed) = driver.replay_target(config).unwrap();
    let lane = driver.stream_ref(handle.lane(Lane::ZERO).unwrap()).unwrap();
    assert_eq!(lane.buffer.config().initial_term_id.get(), RECORDED);
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert_eq!(feed.position(), end);
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert_eq!(seen, (0..count).collect::<Vec<_>>());
    assert!(terminal.terminal.unwrap().clean);
}

/// A recording reader's format names the recorded lane as the driver
/// built it, with its drawn `initial_term_id`, so a host learns the id
/// there; a replay target built from that format replays the recording
/// exactly.
#[test]
fn a_recordings_format_carries_the_drawn_initial_term_id() {
    // No override: the recorded stream's id is drawn.
    let mut driver = EmbeddedDriver::new().unwrap();
    let count = 200;
    let (runs, end, (recorded, format)) = record_format(&mut driver, count);
    let buffer = *driver.stream_ref(recorded).unwrap().buffer.config();
    assert_eq!(
        format,
        crate::recording::RecordingFormat {
            lane: Lane::ZERO,
            initial_term_id: buffer.initial_term_id.get().cast_signed(),
            term_length: MIN_TERM_LENGTH,
            mtu: DEFAULT_MTU,
        }
    );
    let config = ReplayTargetConfig {
        term_length: format.term_length,
        initial_term_id: format.initial_term_id,
        mtu: format.mtu,
        lane: format.lane,
        ..target(2, 0)
    };
    let (handle, mut feed) = driver.replay_target(config).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert_eq!(feed.position(), end);
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert_eq!(seen, (0..count).collect::<Vec<_>>());
    assert!(terminal.terminal.unwrap().clean);
}

/// A replay joined inside the recording starts there: a subscriber reads
/// from the join on, at the recorded positions.
#[test]
fn a_replay_joins_at_its_first_position() {
    let mut driver = pinned();
    let (runs, end) = record(&mut driver, 100);
    let from = runs
        .iter()
        .position(|run| {
            run.position() > u64::from(MIN_TERM_LENGTH) && matches!(run, Run::Frames(..))
        })
        .unwrap();
    let join = runs[from].position();
    let (handle, mut feed) = driver.replay_target(target(2, join)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs[from..],
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert!(terminal.terminal.unwrap().clean);
    let first = seen[0];
    assert!(first > 0);
    assert_eq!(seen, (first..100).collect::<Vec<_>>());
}

/// A range the recording lost reads as a local gap; the replay still ends
/// with EndOfStream, but the reader saw a loss, so its EOS is not clean.
#[test]
fn a_recorded_gap_is_a_local_gap_and_the_end_is_not_clean() {
    let mut driver = pinned();
    let (runs, end) = record(&mut driver, 40);
    let lost = runs
        .iter()
        .position(|run| matches!(run, Run::Frames(..)) && run.position() > 0)
        .unwrap();
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        Some(lost..lost + 1),
        false,
        &mut seen,
        &mut polls,
    );
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    polls.push(terminal.clone());
    let skipped = polls.iter().find_map(|poll| poll.lanes[0].skipped).unwrap();
    assert_eq!(skipped.position, runs[lost].position());
    assert_eq!(
        skipped.reason,
        SkipReason::LocalGap(GapReason::RangeUnavailable)
    );
    assert_eq!(
        terminal.lanes[0].end,
        Some(LaneEnd::Closed {
            position: end,
            reason: SealReason::EndOfStream
        })
    );
    assert_eq!(terminal.lanes[0].first_loss, Some(runs[lost].position()));
    assert!(!terminal.terminal.unwrap().clean);
}

/// A replay that ends before its end seals ImageRetired: not clean.
#[test]
fn an_incomplete_replay_retires_its_target() {
    let mut driver = pinned();
    let (runs, end) = record(&mut driver, 20);
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    let half = runs.len() / 2;
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs[..half],
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert!(!driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert!(matches!(
        terminal.lanes[0].end,
        Some(LaneEnd::Closed {
            reason: SealReason::ImageRetired,
            ..
        })
    ));
    assert!(!terminal.terminal.unwrap().clean);
}

/// A lane other than 0, a key in use and a geometry an image cannot have
/// are refused when the target is made; a target finishes only once.
#[test]
fn replay_targets_are_refused_typed() {
    let mut driver = EmbeddedDriver::<HeapTerms>::new().unwrap();
    let _source = driver.add_stream(source()).unwrap();
    assert!(matches!(
        driver.replay_target(ReplayTargetConfig {
            lane: Lane::try_new(1).unwrap(),
            ..target(2, 0)
        }),
        Err(DriverError::ReplayLane { lane: 1 })
    ));
    assert!(matches!(
        driver.replay_target(ReplayTargetConfig {
            stream_id: 42,
            ..target(1, 0)
        }),
        Err(DriverError::DuplicateStream {
            stream_id: 42,
            session_id: 1
        })
    ));
    assert!(matches!(
        driver.replay_target(ReplayTargetConfig {
            term_length: 1000,
            ..target(2, 0)
        }),
        Err(DriverError::InvalidConfig)
    ));
    let (handle, feed) = driver.replay_target(target(2, 0)).unwrap();
    let (other, other_feed) = driver.replay_target(target(3, 0)).unwrap();
    // A feed with another target's handle is refused, and is then spent.
    assert!(matches!(
        driver.finish_replay(other, feed, 0),
        Err(DriverError::UnknownStream { .. })
    ));
    assert!(driver.finish_replay(other, other_feed, 0).unwrap());
    let _ = handle;
}

/// On an IPC driver the target's lane is a region of the driver's
/// instance, with a fresh id, so remote clients may fetch it as any image;
/// in process it reads as on the heap.
#[cfg(target_os = "linux")]
#[test]
fn an_ipc_drivers_replay_target_lives_in_a_region() {
    use karyos_sys::term_bytes::SharedTerms;

    use crate::admission::IpcConfig;
    use crate::clock::SystemClock;
    use crate::embedded::DriverConfig;

    let mut heap = pinned();
    let (runs, end) = record(&mut heap, 60);
    let dir = std::env::temp_dir().join(format!("karyos-a5b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let timeout = 5_000_000_000;
    let mut driver = EmbeddedDriver::<SharedTerms>::with_ipc(
        DriverConfig::default(),
        IpcConfig {
            dir: dir.clone(),
            max_pending_hellos: 2,
            hello_timeout: timeout,
            max_outbound_per_client: 8,
            fetch_deadline: timeout,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: crate::admission::DEFAULT_MAX_TOOLS,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap();
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let stream = handle.streams().next().unwrap();
    assert!(
        <SharedTerms as sealed::Create>::region(&driver.stream(stream).unwrap().buffer).is_some()
    );
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert_eq!(seen, (0..60).collect::<Vec<_>>());
    assert!(terminal.terminal.unwrap().clean);
    drop(reader);
    drop(driver);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fed without the driver running between writes, a run whose term is not
/// prepared yet is refused for now and taken once it is: frames, a fill
/// that opens the replay and a gap that crosses a term's end (sealed as
/// one local gap per term). Nothing is lost or written twice.
#[test]
fn a_term_not_ready_is_offered_again() {
    let mut driver = pinned();
    let count = 200;
    let (runs, end) = record(&mut driver, count);
    // Frames: everything, eagerly.
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    let refused = replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        None,
        true,
        &mut seen,
        &mut polls,
    );
    assert!(refused > 0, "no term was ever not ready");
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert_eq!(seen, (0..count).collect::<Vec<_>>());
    assert!(terminal.terminal.unwrap().clean);

    // A gap from the last frames of the second term, over its padding, to
    // the end of the third term's first frames: the third term is not
    // prepared when the gap comes.
    let fills: Vec<usize> = runs
        .iter()
        .enumerate()
        .filter_map(|(index, run)| matches!(run, Run::Fill(..)).then_some(index))
        .collect();
    let fill = fills[0];
    let lost = fills[1] - 1..fills[1] + 2;
    let (handle, mut feed) = driver.replay_target(target(3, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        Some(lost.clone()),
        true,
        &mut seen,
        &mut polls,
    );
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    // Sealed in two pieces, one per term; the lane's first loss is the
    // gap's start.
    assert_eq!(
        terminal.lanes[0].first_loss,
        Some(runs[lost.start].position())
    );
    assert!(!terminal.terminal.unwrap().clean);
    assert_eq!(
        seen.len(),
        usize::try_from(count).unwrap() - seen_lost(&runs, lost)
    );

    // A replay that opens at the padding of a term not prepared yet.
    let (handle, mut feed) = driver
        .replay_target(target(4, runs[fill].position()))
        .unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs[fill..],
        None,
        true,
        &mut seen,
        &mut polls,
    );
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    until_terminal(&mut driver, &mut reader, &mut seen);
    assert_eq!(seen.first().copied(), Some(first_index(&runs[fill + 1])));
}

/// The messages the runs of `lost` held.
fn seen_lost(runs: &[Run], lost: std::ops::Range<usize>) -> usize {
    runs[lost]
        .iter()
        .map(|run| match run {
            Run::Frames(_, bytes) => bytes.len().div_ceil(1056),
            Run::Fill(..) => 0,
        })
        .sum()
}

/// The index of the first message of a frames run.
fn first_index(run: &Run) -> u32 {
    let Run::Frames(_, bytes) = run else {
        panic!("frames");
    };
    // The payload follows the 32-byte header.
    u32::from_le_bytes(bytes[32..36].try_into().unwrap())
}

/// #374 review P2: a feed that wrote past the end it finishes at is
/// refused, typed, and its target retires; so does a dropped feed's, on
/// the driver's next duty; a frame of another source is refused.
#[test]
fn a_target_is_never_left_behind() {
    let mut driver = pinned();
    let (runs, _) = record(&mut driver, 40);
    let frames: Vec<&Run> = runs
        .iter()
        .filter(|run| matches!(run, Run::Frames(..)))
        .collect();
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    // The first run, then the third: the second is outstanding.
    for run in [frames[0], frames[2]] {
        let Run::Frames(position, bytes) = run else {
            unreachable!()
        };
        while !feed.frames(*position, bytes).unwrap() {
            driver.do_work().unwrap();
        }
    }
    let end = frames[1].position();
    assert!(matches!(
        driver.finish_replay(handle, feed, end),
        Err(DriverError::ReplayOutstanding { .. })
    ));
    let mut seen = Vec::new();
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert!(matches!(
        terminal.lanes[0].end,
        Some(LaneEnd::Closed {
            reason: SealReason::ImageRetired,
            ..
        })
    ));
    // Dropped unfinished: retired on the next duty.
    let (handle, feed) = driver.replay_target(target(3, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    drop(feed);
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert!(matches!(
        terminal.lanes[0].end,
        Some(LaneEnd::Closed {
            reason: SealReason::ImageRetired,
            ..
        })
    ));
    // Frames recorded from another session are refused before any write.
    let (handle, mut feed) = driver
        .replay_target(ReplayTargetConfig {
            source_session_id: 9,
            ..target(4, 0)
        })
        .unwrap();
    let Run::Frames(position, bytes) = frames[0] else {
        unreachable!()
    };
    assert!(matches!(
        feed.frames(*position, bytes),
        Err(ReplayFeedError::Invalid { .. })
    ));
    assert_eq!(feed.position(), 0);
    assert!(driver.finish_replay(handle, feed, 0).unwrap());
}

/// Joins the runs into runs of several frames: every stretch of frames
/// runs between two fills becomes one run, its frames at their offsets.
fn joined(runs: &[Run]) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    for run in runs {
        match (out.last_mut(), run) {
            (Some(Run::Frames(start, bytes)), Run::Frames(position, frame)) => {
                let offset = usize::try_from(position - *start).unwrap();
                bytes.resize(offset, 0);
                bytes.extend_from_slice(frame);
            }
            _ => out.push(run.clone()),
        }
    }
    out
}

/// #374 review P3 (M7): a run of several frames, as a recording reader may
/// read it, is written frame by frame at its positions, and its last frame
/// may omit its alignment padding.
#[test]
fn a_run_of_several_frames_is_written_whole() {
    let mut driver = pinned();
    let count = 120;
    let (runs, end) = record(&mut driver, count);
    let runs = joined(&runs);
    assert!(
        runs.iter()
            .any(|run| matches!(run, Run::Frames(_, bytes) if bytes.len() > 2 * 1056)),
        "no run of several frames"
    );
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert_eq!(feed.position(), end);
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert_eq!(seen, (0..count).collect::<Vec<_>>());
    assert!(terminal.terminal.unwrap().clean);
}

/// #374 review P3 (M6): a replay over more terms than the image has slots
/// goes on only because the feed cleans the terms its reader left.
#[test]
fn a_replay_longer_than_the_images_terms_cleans_as_it_goes() {
    let mut driver = pinned();
    let count = 400;
    let (runs, end) = record(&mut driver, count);
    assert!(
        end > 6 * u64::from(MIN_TERM_LENGTH),
        "over six terms: {end}"
    );
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    let terminal = until_terminal(&mut driver, &mut reader, &mut seen);
    assert_eq!(seen, (0..count).collect::<Vec<_>>());
    assert!(terminal.terminal.unwrap().clean);
}

/// #374 review P3: each message reads at the position it was recorded at,
/// and the target is freed only once its last reader drops.
#[test]
fn messages_read_at_their_recorded_positions_and_the_target_outlives_its_reader() {
    let mut driver = pinned();
    let count = 40;
    let (runs, end) = record(&mut driver, count);
    let recorded: Vec<(u32, u64)> = runs
        .iter()
        .filter(|run| matches!(run, Run::Frames(..)))
        .map(|run| (first_index(run), run.position()))
        .collect();
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let stream = handle.streams().next().unwrap();
    let mut reader = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    // A second reader, polled only at the end, for the positions.
    let mut late = driver.subscribe_aggregate(&handle, Role::Required).unwrap();
    let mut seen = Vec::new();
    let mut polls = Vec::new();
    replay(
        &mut driver,
        &mut feed,
        &mut reader,
        &runs,
        None,
        false,
        &mut seen,
        &mut polls,
    );
    assert!(driver.finish_replay(handle, feed, end).unwrap());
    // The gauges show the retiring target at once, before any duty.
    assert_eq!(counter(&driver, "streams retiring"), 1);
    until_terminal(&mut driver, &mut reader, &mut seen);
    let mut read = Vec::new();
    for _ in 0..1000 {
        driver.do_work().unwrap();
        let poll = late.poll(
            |bytes, _, info| {
                read.push((
                    u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                    info.position,
                ));
            },
            BUDGET,
        );
        if poll.terminal.is_some() {
            break;
        }
    }
    assert_eq!(read, recorded);
    // Retired, but read: kept until both readers drop.
    drop(reader);
    for _ in 0..4 {
        driver.do_work().unwrap();
    }
    assert!(driver.stream(stream).is_ok());
    drop(late);
    for _ in 0..4 {
        driver.do_work().unwrap();
    }
    assert!(matches!(
        driver.stream(stream),
        Err(DriverError::UnknownStream { .. })
    ));
}

/// #374 review P3: a frame whose header names another position than the
/// one it is fed at is refused, and so is a fill that is not a record of
/// its extent; nothing is written.
#[test]
fn frames_and_fills_are_checked_against_their_positions_and_extents() {
    let mut driver = pinned();
    let (runs, _) = record(&mut driver, 80);
    let (handle, mut feed) = driver.replay_target(target(2, 0)).unwrap();
    let Run::Frames(_, frame) = &runs[0] else {
        panic!("frames first");
    };
    assert!(matches!(
        feed.frames(1056, frame),
        Err(ReplayFeedError::Invalid { position: 1056, .. })
    ));
    let (fill, record, extent) = runs
        .iter()
        .find_map(|run| match run {
            Run::Fill(position, record, extent) => Some((*position, record.clone(), *extent)),
            Run::Frames(..) => None,
        })
        .unwrap();
    assert!(matches!(
        feed.fill(fill, &record, extent - 32),
        Err(ReplayFeedError::Invalid { .. })
    ));
    assert!(matches!(
        feed.fill(0, frame, 1056),
        Err(ReplayFeedError::Invalid { position: 0, .. })
    ));
    assert_eq!(feed.position(), 0);
    assert!(driver.finish_replay(handle, feed, 0).unwrap());
}

/// A driver counter by its label.
fn counter(driver: &EmbeddedDriver, label: &str) -> u64 {
    use karyos_sys::counters::CellRead;
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}
