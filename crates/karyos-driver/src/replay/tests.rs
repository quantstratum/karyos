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
use crate::embedded::StreamConfig;

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
    let handle = driver.add_stream(source()).unwrap();
    let (mut reader, _lease) = driver
        .recording_reader(handle, Role::Required)
        .unwrap()
        .into_parts();
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
    (runs, reader.position())
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
    let mut driver = EmbeddedDriver::new().unwrap();
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

/// A replay joined inside the recording starts there: a subscriber reads
/// from the join on, at the recorded positions.
#[test]
fn a_replay_joins_at_its_first_position() {
    let mut driver = EmbeddedDriver::new().unwrap();
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
    let mut driver = EmbeddedDriver::new().unwrap();
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
    let mut driver = EmbeddedDriver::new().unwrap();
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

    let mut heap = EmbeddedDriver::new().unwrap();
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
    let mut driver = EmbeddedDriver::new().unwrap();
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
    let mut driver = EmbeddedDriver::new().unwrap();
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
