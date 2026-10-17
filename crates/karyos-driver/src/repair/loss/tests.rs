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
    /// The image's path (1 in these tests) has the set RTT; any other path
    /// a far larger one, so a wrong path shows in the retry timing.
    fn rtt_snapshot(&self, path: usize) -> u64 {
        self.asked.set(Some(path));
        if path == 1 {
            self.rtt.get()
        } else {
            self.rtt.get() * 1_000
        }
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
    let _ = loss.observe(lane(0), hole(4096, 256), 10);
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
    let _ = loss.observe(lane(3), hole(0, 32), 11);
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
    let _ = loss.observe(lane(0), hole(0, 64), 0);
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
    let _ = loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    // The front 64 bytes arrived: the remainder waits for the same retry.
    let _ = loss.observe(lane(0), hole(64, 64), 500);
    assert_eq!(loss.due(lane(0), 999), None);
    let retry = loss.due(lane(0), 1_000).unwrap();
    assert_eq!((retry.range.start, retry.range.length), (64, 64));
    // A hole elsewhere: a new decision, due at once.
    let _ = loss.observe(lane(0), hole(4096, 32), 1_001);
    assert_eq!(loss.due(lane(0), 1_001).unwrap().range.start, 4096);
    let _ = loss.observe(lane(0), None, 1_002);
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
    let _ = loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    let _ = loss.observe(lane(0), hole(0, 64), 1);
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
    let _ = loss.observe(lane(0), hole(0, 128), 0);
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
    let _ = loss.observe(lane(0), hole(0, 128), 0);
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
    let _ = loss.observe(lane(0), hole(32, 96), 1_000);
    let nak = loss.due(lane(0), 1_000).unwrap();
    loss.submitted(&nak, 1_000, &rtt);
    let invalid = reply_to(&nak, NakReplyReason::RangeInvalid);
    for _ in 0..2 {
        assert_eq!(loss.reply(&invalid, WINDOW_END), ReplyOutcome::StillDue);
    }
    assert!(!loss.is_closed());
    // Another lane has a NAK due when the image closes.
    let _ = loss.observe(lane(1), hole(0, 32), 1_000);
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
    let _ = loss.observe(lane(1), hole(4096, 32), 10_000);
    let _ = loss.observe(lane(0), None, 10_000);
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
    let _ = loss.observe(lane(0), hole(0, 128), 0);
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
    let _ = loss.observe(lane(0), hole(64, 64), 100_000);
    assert_eq!(loss.due(lane(0), 100_000), None);
    // The gap owner skipped it: the next hole is a new decision.
    let _ = loss.observe(lane(0), None, 100_001);
    let _ = loss.observe(lane(0), hole(4096, 32), 100_002);
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
    let _ = loss.observe(lane(0), hole(0, 128), 0);
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
    let _ = loss.observe(lane(0), hole(0, 64), 0);
    let _ = loss.observe(lane(1), hole(0, 64), 0);
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
    let _ = loss.observe(lane(0), hole(16, 64), 0);
    assert_eq!(loss.due(lane(0), 0), None);
    let _ = loss.observe(lane(1), hole(0, 48), 0);
    assert_eq!(loss.due(lane(1), 0), None);
    assert_eq!(loss.counters().unnameable, 2);
}

/// #278 review P2 (RC-9, ACS 15712): late data splits a NAKed hole; the
/// remainder beyond the split is the same decision, and once
/// RANGE_UNAVAILABLE answered the span it is unrecoverable at once,
/// never NAKed again.
#[test]
fn a_split_hole_stays_one_decision_and_is_unrecoverable_whole() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 1024), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    // Late original data fills [256, 512): the first hole is [0, 256).
    let _ = loss.observe(lane(0), hole(0, 256), 10);
    let unavailable = reply_to(
        &nak,
        NakReplyReason::RangeUnavailable {
            lowest_retained: 2048,
        },
    );
    assert!(matches!(
        loss.reply(&unavailable, WINDOW_END),
        ReplyOutcome::Unrecoverable {
            hole: Hole {
                start: 0,
                length: 256
            },
            ..
        }
    ));
    // The gap owner skips [0, 256): the next hole is [512, 1024), inside
    // the span, unrecoverable at once.
    assert_eq!(
        loss.observe(lane(0), hole(512, 512), 20),
        Observation::Unrecoverable {
            lane: lane(0),
            hole: Hole {
                start: 512,
                length: 512,
            },
            lowest_retained: 2048,
        }
    );
    assert_eq!(loss.due(lane(0), 100_000), None);
    // A hole past the span is a new decision.
    let _ = loss.observe(lane(0), hole(4096, 32), 30);
    assert!(loss.due(lane(0), 30).is_some());
}

/// Without a reply, the split remainder keeps the decision's anchors: its
/// retry waits for the original RTT, it is not a new hole due at once.
#[test]
fn a_split_remainder_keeps_its_anchors() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 1024), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let _ = loss.observe(lane(0), hole(0, 256), 10);
    // [0, 256) arrives; [512, 1024) is still missing.
    let _ = loss.observe(lane(0), hole(512, 512), 20);
    assert_eq!(loss.due(lane(0), 999), None);
    assert_eq!(loss.due(lane(0), 1_000).unwrap().range.start, 512);
    assert_eq!(loss.counters().detected, 1);
}

/// A hole that shrinks from its end in AwaitRepair is the same hole.
#[test]
fn a_hole_shrinking_from_its_end_keeps_its_anchors() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let _ = loss.observe(lane(0), hole(0, 64), 10);
    assert_eq!(loss.due(lane(0), 999), None);
    assert_eq!(loss.due(lane(0), 1_000).unwrap().range.length, 64);
    assert_eq!(loss.counters().detected, 1);
}

/// RANGE_INVALID echoing the NAK of the larger interval, after a partial
/// repair, does not count toward the new interval's limit.
#[test]
fn a_stale_range_invalid_does_not_count() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let _ = loss.observe(lane(0), hole(64, 64), 10);
    let invalid = reply_to(&nak, NakReplyReason::RangeInvalid);
    for _ in 0..5 {
        assert_eq!(loss.reply(&invalid, WINDOW_END), ReplyOutcome::StillDue);
    }
    assert!(!loss.is_closed());
}

/// RANGE_INVALID counts start over on a new hole elsewhere.
#[test]
fn range_invalid_counts_start_over_on_a_new_hole() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let invalid = reply_to(&nak, NakReplyReason::RangeInvalid);
    for _ in 0..2 {
        assert_eq!(loss.reply(&invalid, WINDOW_END), ReplyOutcome::StillDue);
    }
    let _ = loss.observe(lane(0), hole(8192, 64), 10);
    let nak = loss.due(lane(0), 10).unwrap();
    loss.submitted(&nak, 10, &rtt);
    let invalid = reply_to(&nak, NakReplyReason::RangeInvalid);
    for _ in 0..2 {
        assert_eq!(loss.reply(&invalid, WINDOW_END), ReplyOutcome::StillDue);
    }
    assert!(!loss.is_closed());
}

/// A floor at or below the hole's start contradicts RANGE_UNAVAILABLE:
/// still unrecoverable, and counted.
#[test]
fn a_contradictory_floor_is_an_anomaly() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(256, 128), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let below = reply_to(
        &nak,
        NakReplyReason::RangeUnavailable {
            lowest_retained: 256,
        },
    );
    assert!(matches!(
        loss.reply(&below, WINDOW_END),
        ReplyOutcome::Unrecoverable { .. }
    ));
    assert_eq!(loss.counters().anomalies, 1);
}

/// The longest nameable hole is a whole maximal term; one longer, or an
/// empty one, is not, and each decision counts the fault once.
#[test]
fn nak_lengths_are_bounded() {
    let mut loss = image();
    let _ = loss.observe(lane(0), hole(0, MAX_NAK_LENGTH), 0);
    assert_eq!(loss.due(lane(0), 0).unwrap().range.length, MAX_NAK_LENGTH);
    let _ = loss.observe(lane(1), hole(0, MAX_NAK_LENGTH + 32), 0);
    assert_eq!(loss.due(lane(1), 0), None);
    assert_eq!(loss.due(lane(1), 1), None);
    assert_eq!(loss.counters().unnameable, 1);
    let _ = loss.observe(lane(1), None, 2);
    let _ = loss.observe(lane(1), hole(64, 0), 2);
    assert_eq!(loss.due(lane(1), 2), None);
    assert_eq!(loss.counters().unnameable, 2);
}

/// A clock stepped back behind a submission does not make the retry due.
#[test]
fn a_clock_stepped_back_does_not_retry() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 64), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 5_000, &rtt);
    assert_eq!(loss.due(lane(0), 4_000), None);
    assert!(loss.due(lane(0), 6_000).is_some());
}

/// Counters after each step: a first send is no retry.
#[test]
fn retries_count_only_second_sends() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 64), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    assert_eq!((loss.counters().submitted, loss.counters().retries), (1, 0));
    let nak = loss.due(lane(0), 1_000).unwrap();
    loss.submitted(&nak, 1_000, &rtt);
    assert_eq!((loss.counters().submitted, loss.counters().retries), (2, 1));
}

/// A reply on another lane after the image closed is unmatched.
#[test]
fn a_reply_after_the_close_is_unmatched() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 64), 0);
    let _ = loss.observe(lane(1), hole(0, 64), 0);
    let first = loss.due(lane(0), 0).unwrap();
    loss.submitted(&first, 0, &rtt);
    let second = loss.due(lane(1), 0).unwrap();
    loss.submitted(&second, 0, &rtt);
    let beyond = reply_to(
        &first,
        NakReplyReason::RangeUnavailable {
            lowest_retained: WINDOW_END,
        },
    );
    assert!(matches!(
        loss.reply(&beyond, WINDOW_END),
        ReplyOutcome::GapCannotResume { .. }
    ));
    assert_eq!(
        loss.reply(&reply_to(&second, NakReplyReason::RangeInvalid), WINDOW_END),
        ReplyOutcome::Unmatched
    );
}

/// The span is the decision's first NAK: retrying a fragment inside it
/// keeps it, so the far remainder is still the same decision.
#[test]
fn a_fragment_retry_keeps_the_span() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 1024), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let _ = loss.observe(lane(0), hole(0, 256), 10);
    let retry = loss.due(lane(0), 1_000).unwrap();
    assert_eq!(retry.range.length, 256);
    loss.submitted(&retry, 1_000, &rtt);
    let _ = loss.observe(lane(0), hole(512, 512), 1_010);
    assert_eq!(loss.due(lane(0), 1_010), None);
    assert_eq!(loss.counters().detected, 1);
}

/// #278 re-review P2: RANGE_UNAVAILABLE condemns only the range its reply
/// answered. A fragment of the span retried alone and refused leaves the
/// rest of the span the sender's to repair: it is NAKed again at once.
#[test]
fn only_the_answered_range_is_unrecoverable() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 1024), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let _ = loss.observe(lane(0), hole(0, 256), 10);
    let retry = loss.due(lane(0), 1_000).unwrap();
    assert_eq!(retry.range.length, 256);
    loss.submitted(&retry, 1_000, &rtt);
    let unavailable = reply_to(
        &retry,
        NakReplyReason::RangeUnavailable {
            lowest_retained: 128,
        },
    );
    assert!(matches!(
        loss.reply(&unavailable, WINDOW_END),
        ReplyOutcome::Unrecoverable { .. }
    ));
    // The gap owner resolves [0, 256); [512, 1024) is retained: due.
    assert_eq!(
        loss.observe(lane(0), hole(512, 512), 1_100),
        Observation::Nothing
    );
    let again = loss.due(lane(0), 1_100).unwrap();
    assert_eq!((again.range.start, again.range.length), (512, 512));
}

/// An unrecoverable hole that shrinks again is reported once: the gap
/// owner already has it.
#[test]
fn an_unrecoverable_hole_is_reported_once() {
    let mut loss = image();
    let rtt = FakeRtt::new(1_000);
    let _ = loss.observe(lane(0), hole(0, 1024), 0);
    let nak = loss.due(lane(0), 0).unwrap();
    loss.submitted(&nak, 0, &rtt);
    let _ = loss.observe(lane(0), hole(0, 256), 10);
    let unavailable = reply_to(
        &nak,
        NakReplyReason::RangeUnavailable {
            lowest_retained: 2048,
        },
    );
    let _ = loss.reply(&unavailable, WINDOW_END);
    assert!(matches!(
        loss.observe(lane(0), hole(512, 512), 20),
        Observation::Unrecoverable { .. }
    ));
    assert_eq!(
        loss.observe(lane(0), hole(768, 256), 30),
        Observation::Nothing
    );
    assert_eq!(loss.due(lane(0), 100_000), None);
}

/// The RttSource of RttProbes reads the asked path's estimate.
#[test]
fn rtt_probes_answer_for_the_asked_path() {
    use crate::rtt::{RttConfig, RttProbes};

    let config = RttConfig::default();
    let mut probes = RttProbes::new(config, 2).unwrap();
    let probe = probes.due(1, 0).unwrap();
    probes.submitted(probe, 0);
    let _ = probes.reply(1, probe.generation, probe.probe_id, 5_000_000);
    assert_eq!(probes.rtt_snapshot(1), probes.estimate(1));
    assert_eq!(probes.rtt_snapshot(0), config.rtt_initial);
    assert_ne!(probes.rtt_snapshot(1), probes.rtt_snapshot(0));
}
