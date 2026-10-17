// SPDX-License-Identifier: Apache-2.0

//! The receiver's unicast loss state (phase 6): detection, the immediate
//! NAK, the one-RTT retry anchored at submission, partial repair,
//! uncertain submissions (RC-6), exact reply correlation, RANGE_INVALID up
//! to the limit (RC-8), RANGE_UNAVAILABLE and GapCannotResume (RC-9).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cell::Cell;

use karyos_protocol::frame::Lane;
use karyos_protocol::network::{Alias, Identity, NakRange, NakReply, NakReplyReason, Receiver};

use super::*;

/// An RTT that tests set at will; it records the path asked.
struct FakeRtt {
    rtt: Cell<u64>,
    asked: Cell<Option<usize>>,
}

impl FakeRtt {
    fn new(rtt: u64) -> Self {
        Self {
            rtt: Cell::new(rtt),
            asked: Cell::new(None),
        }
    }
}

impl RttSource for FakeRtt {
    fn rtt_snapshot(&self, path: usize) -> u64 {
        self.asked.set(Some(path));
        self.rtt.get()
    }
}

fn alias() -> Alias {
    Alias {
        session_id: 5,
        stream_id: 6,
    }
}

fn identity() -> Identity {
    Identity {
        driver_id: [1, 2],
        registration_id: 3,
        incarnation: 1,
    }
}

fn receiver() -> Receiver {
    Receiver {
        receiver_boot_id: [7, 8],
        receiver_id: 9,
    }
}

fn image() -> ImageLoss {
    ImageLoss::new(LossConfig::default(), alias(), identity(), receiver(), 2, 1).unwrap()
}

fn hole(start: u64, length: u32) -> Option<Hole> {
    Some(Hole { start, length })
}

fn lane(index: u8) -> Lane {
    Lane::try_new(index).unwrap()
}

fn reply_to(nak: &Nak, reason: NakReplyReason) -> NakReply {
    NakReply::answering(nak, reason)
}

const WINDOW_END: u64 = 1 << 20;

#[test]
fn the_configuration_is_checked() {
    let zero = LossConfig {
        range_invalid_limit: 0,
    };
    assert_eq!(
        ImageLoss::new(zero, alias(), identity(), receiver(), 1, 0).err(),
        Some(LossConfigError::ZeroLimit)
    );
    for lanes in [0, 5] {
        assert_eq!(
            ImageLoss::new(
                LossConfig::default(),
                alias(),
                identity(),
                receiver(),
                lanes,
                0
            )
            .err(),
            Some(LossConfigError::LaneCount)
        );
    }
}

/// A detected hole's NAK is due at once, names the image and the hole,
/// and stays due until it is submitted.
#[test]
fn a_detected_hole_is_due_at_once() {
    let mut loss = image();
    assert_eq!(loss.due(lane(0), 0), None);
    loss.observe(lane(0), hole(4096, 256), 10);
    let nak = loss.due(lane(0), 10).unwrap();
    assert_eq!(
        (nak.alias, nak.identity, nak.receiver),
        (alias(), identity(), receiver())
    );
    assert_eq!(
        nak.range,
        NakRange {
            lane: lane(0),
            length: 256,
            start: 4096,
        }
    );
    loss.not_submitted(&nak);
    assert_eq!(loss.due(lane(0), 11), Some(nak));
    // Lanes are independent; one outside the image is ignored.
    assert_eq!(loss.due(lane(1), 11), None);
    loss.observe(lane(3), hole(0, 32), 11);
    assert_eq!(loss.due(lane(3), 11), None);
    let counters = loss.counters();
    assert_eq!((counters.detected, counters.not_submitted), (1, 1));
}

/// The retry is due when `age_ns(now, submitted_at) >= rtt`, with the RTT
/// copied at submission from the image's path: a later sample does not
/// move it.
#[test]
fn the_retry_waits_one_rtt_from_submission() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    loss.observe(lane(0), hole(0, 64), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 100, &rtt);
    assert_eq!(rtt.asked.get(), Some(1));
    rtt.rtt.set(50);
    assert_eq!(loss.due(lane(0), 1_099), None);
    let retry = loss.due(lane(0), 1_100).unwrap();
    assert_eq!(retry, nak);
    loss.submitted(&retry, 1_200, &rtt);
    assert_eq!(loss.due(lane(0), 1_249), None);
    assert!(loss.due(lane(0), 1_250).is_some());
    let counters = loss.counters();
    assert_eq!((counters.submitted, counters.retries), (2, 1));
}

/// A hole that disappears was repaired; one that shrinks inside itself is
/// the same hole and keeps its retry anchor; one elsewhere is a new
/// decision, due at once.
#[test]
fn repairs_partial_repairs_and_new_holes() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    // The front 64 bytes arrived: the remainder waits for the same retry.
    loss.observe(lane(0), hole(64, 64), 500);
    assert_eq!(loss.due(lane(0), 999), None);
    let retry = loss.due(lane(0), 1_000).unwrap();
    assert_eq!((retry.range.start, retry.range.length), (64, 64));
    // A hole elsewhere: a new decision, due at once.
    loss.observe(lane(0), hole(4096, 32), 1_001);
    assert_eq!(loss.due(lane(0), 1_001).unwrap().range.start, 4096);
    loss.observe(lane(0), None, 1_002);
    assert_eq!(loss.due(lane(0), 5_000), None);
    let counters = loss.counters();
    assert_eq!(
        (
            counters.detected,
            counters.partial_repairs,
            counters.repaired
        ),
        (2, 1, 1)
    );
}

/// A submission for an interval that is no longer the lane's hole records
/// nothing.
#[test]
fn a_stale_submission_records_nothing() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.observe(lane(0), hole(0, 64), 1);
    loss.submitted(&nak, 2, &rtt);
    // Still due: the NAK for the old interval was not this hole's.
    assert_eq!(loss.due(lane(0), 3).unwrap().range.length, 64);
    assert_eq!(loss.counters().submitted, 0);
}

/// Only an exact echo of the outstanding NAK counts.
#[test]
fn replies_must_echo_the_outstanding_nak() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    // Nothing outstanding yet.
    assert_eq!(
        loss.reply(&reply_to(&nak, NakReplyReason::RangeInvalid), WINDOW_END),
        ReplyOutcome::Unmatched
    );
    loss.submitted(&nak, 0, &rtt);
    let mut foreign = vec![];
    let mut other = nak;
    other.identity.incarnation = 2;
    foreign.push(other);
    let mut other = nak;
    other.receiver.receiver_id = 10;
    foreign.push(other);
    let mut other = nak;
    other.alias.session_id = 50;
    foreign.push(other);
    let mut other = nak;
    other.range.length = 96;
    foreign.push(other);
    let mut other = nak;
    other.range.start = 32;
    foreign.push(other);
    let mut other = nak;
    other.range.lane = lane(1);
    foreign.push(other);
    for other in &foreign {
        assert_eq!(
            loss.reply(&reply_to(other, NakReplyReason::RangeInvalid), WINDOW_END),
            ReplyOutcome::Unmatched,
            "{other:?}"
        );
    }
    assert_eq!(loss.counters().replies_unmatched, 7);
    assert_eq!(
        loss.reply(&reply_to(&nak, NakReplyReason::RangeInvalid), WINDOW_END),
        ReplyOutcome::StillDue
    );
}

/// RANGE_INVALID keeps the hole in its retry schedule; the limit's
/// consecutive reply for the same interval closes the image (RC-8), and a
/// new interval starts the count over.
#[test]
fn range_invalid_closes_at_the_limit() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let invalid = reply_to(&nak, NakReplyReason::RangeInvalid);
    for _ in 0..2 {
        assert_eq!(loss.reply(&invalid, WINDOW_END), ReplyOutcome::StillDue);
    }
    // The hole stays in its retry schedule.
    assert_eq!(loss.due(lane(0), 999), None);
    assert!(loss.due(lane(0), 1_000).is_some());
    // A partial repair is another interval: the count starts over.
    loss.observe(lane(0), hole(32, 96), 1_000);
    let nak = loss.due(lane(0), 1_000).unwrap();
    loss.submitted(&nak, 1_000, &rtt);
    let invalid = reply_to(&nak, NakReplyReason::RangeInvalid);
    for _ in 0..2 {
        assert_eq!(loss.reply(&invalid, WINDOW_END), ReplyOutcome::StillDue);
    }
    assert!(!loss.is_closed());
    // Another lane has a NAK due when the image closes.
    loss.observe(lane(1), hole(0, 32), 1_000);
    assert!(loss.due(lane(1), 1_000).is_some());
    assert_eq!(
        loss.reply(&invalid, WINDOW_END),
        ReplyOutcome::ProtocolFault {
            lane: lane(0),
            hole: Hole {
                start: 32,
                length: 96,
            },
        }
    );
    // Terminal: nothing is due, observations change nothing.
    assert!(loss.is_closed());
    assert_eq!(loss.due(lane(0), 10_000), None);
    assert_eq!(loss.due(lane(1), 10_000), None);
    let detected = loss.counters().detected;
    loss.observe(lane(1), hole(4096, 32), 10_000);
    loss.observe(lane(0), None, 10_000);
    let counters = loss.counters();
    assert_eq!((counters.detected, counters.repaired), (detected, 0));
    assert_eq!((counters.range_invalid, counters.protocol_faults), (5, 1));
}

/// RANGE_UNAVAILABLE makes the whole NAKed hole unrecoverable, even when
/// the lowest retained position lies inside it (RC-9): no suffix is
/// requested. Its end is the gap owner's.
#[test]
fn range_unavailable_makes_the_whole_hole_unrecoverable() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let unavailable = reply_to(
        &nak,
        NakReplyReason::RangeUnavailable {
            lowest_retained: 64,
        },
    );
    assert_eq!(
        loss.reply(&unavailable, WINDOW_END),
        ReplyOutcome::Unrecoverable {
            lane: lane(0),
            hole: Hole {
                start: 0,
                length: 128,
            },
            lowest_retained: 64,
        }
    );
    assert!(!loss.is_closed());
    // Never requested again, not even the retained suffix.
    assert_eq!(loss.due(lane(0), 100_000), None);
    loss.observe(lane(0), hole(64, 64), 100_000);
    assert_eq!(loss.due(lane(0), 100_000), None);
    // The gap owner skipped it: the next hole is a new decision.
    loss.observe(lane(0), None, 100_001);
    loss.observe(lane(0), hole(4096, 32), 100_002);
    assert!(loss.due(lane(0), 100_002).is_some());
    let counters = loss.counters();
    assert_eq!((counters.range_unavailable, counters.repaired), (1, 0));
}

/// A lowest retained position at or beyond the end of the receive window
/// closes the image with GapCannotResume, whatever the skip policy.
#[test]
fn a_floor_beyond_the_window_cannot_resume() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let beyond = reply_to(
        &nak,
        NakReplyReason::RangeUnavailable {
            lowest_retained: WINDOW_END,
        },
    );
    assert_eq!(
        loss.reply(&beyond, WINDOW_END),
        ReplyOutcome::GapCannotResume {
            lane: lane(0),
            hole: Hole {
                start: 0,
                length: 128,
            },
            lowest_retained: WINDOW_END,
        }
    );
    assert!(loss.is_closed());
    assert_eq!(loss.due(lane(1), 1), None);
    // A late reply after the close is unmatched.
    assert_eq!(loss.reply(&beyond, WINDOW_END), ReplyOutcome::Unmatched);
    assert_eq!(loss.counters().gap_cannot_resume, 1);
}

/// RC-6: an uncertain NAK counts as submitted when reported; a second one
/// while it is unresolved is a route fault, and nothing more is due until
/// the backend resolves it.
#[test]
fn one_unresolved_uncertain_nak_per_image() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    loss.observe(lane(0), hole(0, 64), 0);
    loss.observe(lane(1), hole(0, 64), 0);
    let first = loss.due(lane(0), 0).unwrap();
    loss.uncertain(&first, 10, &rtt).unwrap();
    // Its retry is due one RTT after the report, from new storage.
    assert_eq!(loss.due(lane(0), 1_009), None);
    assert!(loss.due(lane(0), 1_010).is_some());
    let second = loss.due(lane(1), 20).unwrap();
    assert_eq!(loss.uncertain(&second, 20, &rtt), Err(RouteFault));
    assert_eq!(loss.due(lane(0), 5_000), None);
    assert_eq!(loss.due(lane(1), 5_000), None);
    loss.uncertain_resolved();
    assert!(loss.due(lane(1), 5_000).is_some());
    let counters = loss.counters();
    assert_eq!((counters.uncertain, counters.route_faults), (1, 1));
}

/// A hole no NAK can name (misaligned) is counted and never sent.
#[test]
fn an_unnameable_hole_is_counted() {
    let mut loss = image();
    loss.observe(lane(0), hole(16, 64), 0);
    assert_eq!(loss.due(lane(0), 0), None);
    loss.observe(lane(1), hole(0, 48), 0);
    assert_eq!(loss.due(lane(1), 0), None);
    assert_eq!(loss.counters().unnameable, 2);
}
