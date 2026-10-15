// SPDX-License-Identifier: Apache-2.0

//! Rejoin policies of an overrun reader over an embedded driver
//! (`quantstratum-docs: karyos/design/rejoin-policies.md`, Tests; SPEC.md
//! §13 "Overrun without Archive"). Each test laps one optional reader.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::{Arc, Mutex};

use karyos_client::{
    ClientPublication, ClientSubscription, LinkStatus, MessageLimit, OfferOutcome, Overrun,
    RejoinOutcome, RejoinPolicy, ReplayFallbackReason, Secondary, SecondaryOutcome, SnapshotFailed,
    SnapshotSource,
};
use karyos_driver::{EmbeddedDriver, Reconfiguration, StreamConfig, StreamHandle};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

/// A stream with room for `subscribers` readers.
fn config(subscribers: u8) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: subscribers,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
        },
        allow_unconnected: true,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    }
}

fn message(sequence: u32) -> Vec<u8> {
    let mut data = vec![sequence as u8; 512];
    data[..4].copy_from_slice(&sequence.to_le_bytes());
    data
}

/// Offers `message(sequence)`, running the driver until it is accepted;
/// returns its position.
fn offer(driver: &mut EmbeddedDriver, publication: &mut ClientPublication, sequence: u32) -> u64 {
    for _ in 0..10_000 {
        if let OfferOutcome::Accepted { position, .. } =
            publication.offer(&message(sequence)).unwrap()
        {
            return position;
        }
        let _ = driver.do_work().unwrap();
    }
    panic!("offer never accepted");
}

/// Publishes until the lagging reader's data is reclaimed; returns the
/// positions published.
fn lap(driver: &mut EmbeddedDriver, publication: &mut ClientPublication) -> Vec<u64> {
    (0..300)
        .map(|sequence| {
            let position = offer(driver, publication, sequence);
            let _ = driver.do_work().unwrap();
            position
        })
        .collect()
}

/// A driver, a stream, its publication and one lagging optional reader
/// with `policy`, already lapped; returns the positions published.
fn lapped(
    policy: RejoinPolicy,
    subscribers: u8,
) -> (
    EmbeddedDriver,
    StreamHandle,
    ClientPublication,
    ClientSubscription,
    Vec<u64>,
) {
    let mut driver = EmbeddedDriver::new().unwrap();
    let stream = driver.add_stream(config(subscribers)).unwrap();
    let lagging = driver
        .subscribe(stream, Role::Optional)
        .unwrap()
        .with_rejoin(policy);
    let mut publication = driver.publication(stream).unwrap();
    let positions = lap(&mut driver, &mut publication);
    (driver, stream, publication, lagging, positions)
}

/// The first message delivered after the overrun, with its position.
fn next_message(
    driver: &mut EmbeddedDriver,
    publication: &mut ClientPublication,
    subscription: &mut ClientSubscription,
) -> u64 {
    let position = offer(driver, publication, 1000);
    let mut seen = None;
    let _ = subscription
        .poll(|_, info| seen = Some(info.position), MessageLimit::new(1))
        .unwrap();
    assert!(seen.unwrap() <= position);
    seen.unwrap()
}

/// A source that records each call and answers with `answer`.
#[derive(Clone)]
struct Recorder {
    calls: Arc<Mutex<Vec<Overrun>>>,
    answer: Answer,
}

#[derive(Clone, Copy)]
enum Answer {
    Rebuilt,
    Fails,
    Panics,
}

impl Recorder {
    fn new(answer: Answer) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            answer,
        }
    }

    fn calls(&self) -> Vec<Overrun> {
        self.calls.lock().unwrap().clone()
    }
}

impl SnapshotSource for Recorder {
    fn rebuild(&mut self, overrun: &Overrun) -> Result<(), SnapshotFailed> {
        self.calls.lock().unwrap().push(*overrun);
        match self.answer {
            Answer::Rebuilt => Ok(()),
            Answer::Fails => Err(SnapshotFailed),
            Answer::Panics => panic!("the snapshot source failed"),
        }
    }
}

#[test]
fn test_rejoin_at_head_overrun_reports_exact_range() {
    let (mut driver, _stream, mut publication, mut lagging, positions) =
        lapped(RejoinPolicy::RejoinAtHead, 4);
    let summary = lagging.poll(|_, _| {}, MessageLimit::new(10)).unwrap();
    assert_eq!(summary.delivered, 0);
    assert_eq!(summary.rejoin, Some(RejoinOutcome::ResumedAtHead));
    assert_eq!(summary.closed_by_overrun, None);
    let overrun = summary.overrun.unwrap();
    // The lost range starts at the reader's position and ends at the
    // retention floor; delivery resumes at the reserved head, the end of
    // the last message published (512 bytes plus a 32-byte header).
    let head = positions.last().unwrap() + 544;
    assert_eq!(overrun.from, 0);
    assert!(0 < overrun.lost_to && overrun.lost_to <= overrun.resume);
    assert_eq!(overrun.resume, head);
    let next = next_message(&mut driver, &mut publication, &mut lagging);
    assert_eq!(next, overrun.resume);
}

#[test]
fn test_rejoin_close_overrun_detaches_and_stays_closed() {
    let (mut driver, stream, mut publication, mut lagging, _) = lapped(RejoinPolicy::Close, 3);
    // Fill the optional readers' slot credit (`S - C`) and cells: no reader
    // is admitted beyond them.
    let mut others = Vec::new();
    while let Ok(other) = driver.subscribe(stream, Role::Optional) {
        others.push(other);
    }
    let summary = lagging
        .poll(|_, _| panic!("closed"), MessageLimit::new(10))
        .unwrap();
    let overrun = summary.overrun.unwrap();
    assert_eq!(summary.rejoin, Some(RejoinOutcome::Closed));
    assert_eq!(summary.closed_by_overrun, Some(overrun));
    assert!(lagging.is_closed_by_overrun());
    assert!(lagging.generation_link().is_none());
    // Its cell and credit are free: a new reader is admitted within the
    // credit limit, and only one.
    let _ = driver.do_work().unwrap();
    let _again = driver.subscribe(stream, Role::Optional).unwrap();
    assert!(driver.subscribe(stream, Role::Optional).is_err());
    // Every later poll reports the same closure, touching nothing.
    let _ = offer(&mut driver, &mut publication, 1000);
    for _ in 0..3 {
        let later = lagging
            .poll(|_, _| panic!("closed"), MessageLimit::new(10))
            .unwrap();
        assert_eq!(later.delivered, 0);
        assert_eq!(later.overrun, None);
        assert_eq!(later.rejoin, Some(RejoinOutcome::Closed));
        assert_eq!(later.closed_by_overrun, Some(overrun));
    }
}

#[test]
fn test_rejoin_snapshot_rebuilds_before_resume() {
    let recorder = Recorder::new(Answer::Rebuilt);
    let order = Arc::clone(&recorder.calls);
    let (mut driver, _stream, mut publication, mut lagging, _) =
        lapped(RejoinPolicy::Snapshot(Box::new(recorder.clone())), 4);
    let mut delivered_before_call = false;
    let summary = lagging
        .poll(
            |_, _| delivered_before_call |= order.lock().unwrap().is_empty(),
            MessageLimit::new(10),
        )
        .unwrap();
    assert!(
        !delivered_before_call,
        "a message reached the handler first"
    );
    let overrun = summary.overrun.unwrap();
    assert_eq!(summary.rejoin, Some(RejoinOutcome::SnapshotRebuilt));
    // Once, with the exact range, in the poll that observed the overrun.
    assert_eq!(recorder.calls(), vec![overrun]);
    let next = next_message(&mut driver, &mut publication, &mut lagging);
    assert_eq!(next, overrun.resume);
    assert_eq!(recorder.calls().len(), 1);
}

#[test]
fn test_rejoin_snapshot_failure_closes() {
    for answer in [Answer::Fails, Answer::Panics] {
        let recorder = Recorder::new(answer);
        let (_driver, _stream, _publication, mut lagging, _) =
            lapped(RejoinPolicy::Snapshot(Box::new(recorder.clone())), 4);
        let summary = lagging
            .poll(|_, _| panic!("closed"), MessageLimit::new(10))
            .unwrap();
        let overrun = summary.overrun.unwrap();
        assert_eq!(summary.rejoin, Some(RejoinOutcome::SnapshotFailed));
        assert_eq!(summary.closed_by_overrun, Some(overrun));
        assert_eq!(recorder.calls(), vec![overrun]);
        let later = lagging
            .poll(|_, _| panic!("closed"), MessageLimit::new(10))
            .unwrap();
        assert_eq!(later.rejoin, Some(RejoinOutcome::SnapshotFailed));
        assert_eq!(later.closed_by_overrun, Some(overrun));
    }
}

#[test]
fn test_rejoin_replay_falls_back_with_reason() {
    let cases: Vec<(Secondary, SecondaryOutcome, Option<Recorder>)> = vec![
        (
            Secondary::RejoinAtHead,
            SecondaryOutcome::ResumedAtHead,
            None,
        ),
        (Secondary::Close, SecondaryOutcome::Closed, None),
        {
            let recorder = Recorder::new(Answer::Rebuilt);
            (
                Secondary::Snapshot(Box::new(recorder.clone())),
                SecondaryOutcome::SnapshotRebuilt,
                Some(recorder),
            )
        },
        {
            let recorder = Recorder::new(Answer::Fails);
            (
                Secondary::Snapshot(Box::new(recorder.clone())),
                SecondaryOutcome::SnapshotFailed,
                Some(recorder),
            )
        },
        {
            let recorder = Recorder::new(Answer::Panics);
            (
                Secondary::Snapshot(Box::new(recorder.clone())),
                SecondaryOutcome::SnapshotFailed,
                Some(recorder),
            )
        },
    ];
    for (secondary, expected, recorder) in cases {
        let (_driver, _stream, _publication, mut lagging, _) =
            lapped(RejoinPolicy::Replay { secondary }, 4);
        let summary = lagging.poll(|_, _| {}, MessageLimit::new(10)).unwrap();
        let overrun = summary.overrun.unwrap();
        let outcome = RejoinOutcome::ReplayFallback {
            reason: ReplayFallbackReason::NoArchive,
            secondary: expected,
        };
        assert_eq!(summary.rejoin, Some(outcome));
        let closes = matches!(
            expected,
            SecondaryOutcome::Closed | SecondaryOutcome::SnapshotFailed
        );
        assert_eq!(summary.closed_by_overrun.is_some(), closes, "{expected:?}");
        assert_eq!(lagging.is_closed_by_overrun(), closes);
        if let Some(recorder) = recorder {
            assert_eq!(recorder.calls(), vec![overrun]);
        }
    }
}

#[test]
fn test_rejoin_close_during_cutover_releases_successor() {
    let (mut driver, stream, publication, mut lagging, _) = lapped(RejoinPolicy::Close, 4);
    drop(publication);
    let link = Arc::clone(lagging.generation_link().unwrap());
    let _ = driver
        .reconfigure_stream(
            stream,
            Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 3,
            },
        )
        .unwrap();
    // The cutover opens and reserves the lagging reader's successor cell.
    for _ in 0..1000 {
        if link.status() == LinkStatus::Offered {
            break;
        }
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(link.status(), LinkStatus::Offered);
    let summary = lagging
        .poll(|_, _| panic!("closed"), MessageLimit::new(10))
        .unwrap();
    assert_eq!(summary.rejoin, Some(RejoinOutcome::Closed));
    assert!(summary.closed_by_overrun.is_some());
    // The successor reservation was handed back and dropped, the link is
    // closed for good, and the handle no longer holds it.
    assert_eq!(link.status(), LinkStatus::Closed);
    assert!(lagging.generation_link().is_none());
    // The cutover settles without it: the predecessor is freed.
    for _ in 0..1000 {
        if driver.generations(stream).unwrap().len() == 1 {
            break;
        }
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(driver.generations(stream).unwrap().len(), 1);
    // A later cutover does not reach the closed subscription.
    let _ = driver
        .reconfigure_stream(
            stream,
            Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
            },
        )
        .unwrap();
    for _ in 0..100 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(link.status(), LinkStatus::Closed);
    let later = lagging
        .poll(|_, _| panic!("closed"), MessageLimit::new(10))
        .unwrap();
    assert_eq!(later.rejoin, Some(RejoinOutcome::Closed));
}
