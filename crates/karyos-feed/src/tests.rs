// SPDX-License-Identifier: Apache-2.0

//! The arbiter's tests, one per case of `quantstratum-docs:
//! karyos/design/feed-arbitration.md` section 8.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::num::NonZeroU64;

use super::*;

/// A test feed: a message is its epoch and sequence as two little-endian
/// words, then its payload; a message shorter than 16 bytes is outside the
/// sequence.
#[derive(Debug, Clone, Copy)]
struct TestFeed {
    modulus: Option<NonZeroU64>,
    start: Option<u64>,
}

impl FeedSequencer for TestFeed {
    fn identity(&self, message: &[u8]) -> Option<Identity> {
        let (head, _) = message.split_first_chunk::<16>()?;
        let (epoch, sequence) = head.split_at(8);
        Some(Identity {
            epoch: u64::from_le_bytes(epoch.try_into().ok()?),
            sequence: u64::from_le_bytes(sequence.try_into().ok()?),
        })
    }

    fn sequence_modulus(&self) -> Option<NonZeroU64> {
        self.modulus
    }

    fn epoch_start(&self, _epoch: u64) -> Option<u64> {
        self.start
    }
}

fn message(epoch: u64, sequence: u64, payload: &[u8]) -> Vec<u8> {
    [&epoch.to_le_bytes()[..], &sequence.to_le_bytes(), payload].concat()
}

/// What an arbiter released, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Out {
    Message(Line, u64, u64, Vec<u8>),
    Gap(u64, u64, u64),
    Jump(Line, u64),
    Epoch(u64, u64),
}

fn record(out: &mut Vec<Out>) -> impl FnMut(Event<'_>) + '_ {
    |event| {
        out.push(match event {
            Event::Message {
                line,
                identity,
                bytes,
            } => Out::Message(line, identity.epoch, identity.sequence, bytes.to_vec()),
            Event::Gap { epoch, from, count } => Out::Gap(epoch, from, count),
            Event::Jump { line, identity } => Out::Jump(line, identity.sequence),
            Event::EpochChange { from, to } => Out::Epoch(from, to),
        });
    }
}

const SKEW: u64 = 1_000;

fn arbiter_with(feed: TestFeed, capacity: usize, start: Start) -> Arbiter<TestFeed> {
    Arbiter::new(
        feed,
        ArbiterConfig {
            capacity,
            max_message_length: 64,
            skew_window: SKEW,
            start,
        },
    )
    .unwrap()
}

fn plain() -> Arbiter<TestFeed> {
    arbiter_with(
        TestFeed {
            modulus: None,
            start: None,
        },
        8,
        Start::AtFirst,
    )
}

/// The sequences of the delivered messages, in order.
fn sequences(out: &[Out]) -> Vec<u64> {
    out.iter()
        .filter_map(|out| match out {
            Out::Message(_, _, sequence, _) => Some(*sequence),
            _ => None,
        })
        .collect()
}

fn push(
    arbiter: &mut Arbiter<TestFeed>,
    out: &mut Vec<Out>,
    line: Line,
    epoch: u64,
    sequence: u64,
    now: u64,
) {
    arbiter.push(line, &message(epoch, sequence, b"p"), now, record(out));
}

/// Each line alternately ahead: every message once, in order, from the
/// line that brought it first, with no gap.
#[test]
fn each_line_alternately_ahead_delivers_each_message_once_in_order() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in 1..=40u64 {
        let (first, second) = if (sequence / 5) % 2 == 0 {
            (Line::A, Line::B)
        } else {
            (Line::B, Line::A)
        };
        push(&mut arbiter, &mut out, first, 1, sequence, sequence);
        push(&mut arbiter, &mut out, second, 1, sequence, sequence);
    }
    assert_eq!(sequences(&out), (1..=40).collect::<Vec<_>>());
    let counters = arbiter.counters();
    assert_eq!(counters.delivered, 40);
    assert_eq!(counters.wins_a + counters.wins_b, 40);
    assert!(counters.wins_a > 0 && counters.wins_b > 0);
    assert_eq!(counters.duplicates_a + counters.duplicates_b, 40);
    assert_eq!(counters.gaps, 0);
    // A line ahead by several messages: B runs three ahead, A catches up.
    let mut arbiter = plain();
    let mut out = Vec::new();
    push(&mut arbiter, &mut out, Line::A, 1, 1, 0);
    for sequence in 2..=4 {
        push(&mut arbiter, &mut out, Line::B, 1, sequence, 0);
    }
    for sequence in 2..=4 {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
    }
    assert_eq!(sequences(&out), vec![1, 2, 3, 4]);
}

/// A message missing from one line is repaired from the other without a
/// report.
#[test]
fn a_message_missing_from_one_line_is_repaired_silently() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in 1..=10 {
        if sequence != 4 {
            push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
        }
        if sequence != 7 {
            push(&mut arbiter, &mut out, Line::B, 1, sequence, 0);
        }
    }
    assert_eq!(sequences(&out), (1..=10).collect::<Vec<_>>());
    assert!(!out.iter().any(|out| matches!(out, Out::Gap(..))));
    assert_eq!(arbiter.counters().gaps, 0);
}

/// A message missing from both lines is a gap: once both lines passed it,
/// and, with one line silent, once the skew window expires.
#[test]
fn a_message_missing_from_both_lines_is_reported_as_a_gap() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in [1, 2, 3, 5, 6] {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
        push(&mut arbiter, &mut out, Line::B, 1, sequence, 0);
    }
    assert_eq!(
        out.iter()
            .filter(|out| matches!(out, Out::Gap(..)))
            .collect::<Vec<_>>(),
        vec![&Out::Gap(1, 4, 1)]
    );
    assert_eq!(sequences(&out), vec![1, 2, 3, 5, 6]);

    // B silent: the hole waits for the skew window, then is a gap.
    let mut arbiter = plain();
    let mut out = Vec::new();
    push(&mut arbiter, &mut out, Line::A, 1, 1, 0);
    push(&mut arbiter, &mut out, Line::A, 1, 3, 10);
    assert_eq!(sequences(&out), vec![1]);
    arbiter.poll(10 + SKEW - 1, record(&mut out));
    assert_eq!(sequences(&out), vec![1]);
    arbiter.poll(10 + SKEW, record(&mut out));
    assert_eq!(out.get(1), Some(&Out::Gap(1, 2, 1)));
    assert_eq!(sequences(&out), vec![1, 3]);
    assert_eq!(arbiter.counters().gap_messages, 1);
}

/// A session reset is an epoch change: no gap for the restarted sequence,
/// the held messages of the old epoch delivered first.
#[test]
fn a_session_reset_produces_no_false_gap() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in 1000..1005 {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
        push(&mut arbiter, &mut out, Line::B, 1, sequence, 0);
    }
    for sequence in 1..=3 {
        push(&mut arbiter, &mut out, Line::A, 2, sequence, 0);
        push(&mut arbiter, &mut out, Line::B, 2, sequence, 0);
    }
    assert!(!out.iter().any(|out| matches!(out, Out::Gap(..))));
    assert!(out.contains(&Out::Epoch(1, 2)));
    assert_eq!(sequences(&out), vec![1000, 1001, 1002, 1003, 1004, 1, 2, 3]);
    assert_eq!(arbiter.counters().jumps, 0);
}

/// A sequence wrap over the feed's modulus is an ordinary advance, never a
/// reset: no epoch change, no gap, no jump.
#[test]
fn a_sequence_wrap_is_not_read_as_a_reset() {
    let feed = TestFeed {
        modulus: NonZeroU64::new(1 << 16),
        start: None,
    };
    let mut arbiter = arbiter_with(feed, 8, Start::AtFirst);
    let mut out = Vec::new();
    let around: Vec<u64> = (65_530..65_536).chain(0..6).collect();
    for &sequence in &around {
        push(&mut arbiter, &mut out, Line::B, 7, sequence, 0);
        push(&mut arbiter, &mut out, Line::A, 7, sequence, 0);
    }
    assert_eq!(sequences(&out), around);
    assert!(
        !out.iter()
            .any(|out| matches!(out, Out::Gap(..) | Out::Epoch(..) | Out::Jump(..)))
    );
    // A hole across the wrap is repaired from the other line as anywhere.
    let mut arbiter = arbiter_with(feed, 8, Start::AtFirst);
    let mut out = Vec::new();
    for &sequence in &around {
        if sequence != 0 {
            push(&mut arbiter, &mut out, Line::A, 7, sequence, 0);
        }
        if sequence != 65_535 {
            push(&mut arbiter, &mut out, Line::B, 7, sequence, 0);
        }
    }
    assert_eq!(sequences(&out), around);
}

/// The window is strictly below half the space: an advance one short of
/// it is held, a message at it is a jump, reported and dropped, never a
/// reset.
#[test]
fn a_jump_at_the_window_is_not_an_advance() {
    let feed = TestFeed {
        modulus: NonZeroU64::new(64),
        start: None,
    };
    // modulus 64: the window is 31, half the space 32.
    let mut arbiter = arbiter_with(feed, 16, Start::AtFirst);
    let mut out = Vec::new();
    push(&mut arbiter, &mut out, Line::A, 1, 0, 0);
    // next is 1: 1 + 30 = 31 is the last advance, 1 + 31 = 32 a jump.
    push(&mut arbiter, &mut out, Line::A, 1, 32, 0);
    assert_eq!(out.last(), Some(&Out::Jump(Line::A, 32)));
    assert_eq!(arbiter.counters().jumps, 1);
    // The far side of the window behind next is a jump too, not a
    // duplicate: 1 - 31 = 34 (mod 64).
    push(&mut arbiter, &mut out, Line::B, 1, 34, 0);
    assert_eq!(out.last(), Some(&Out::Jump(Line::B, 34)));
    // 1 - 30 = 35 is behind inside the window, never delivered: late.
    push(&mut arbiter, &mut out, Line::B, 1, 35, 0);
    assert_eq!(arbiter.counters().jumps, 2);
    assert_eq!(arbiter.counters().late_b, 1);
    // 0, delivered, is a duplicate.
    push(&mut arbiter, &mut out, Line::B, 1, 0, 0);
    assert_eq!(arbiter.counters().duplicates_b, 1);
    // 31 is an advance beyond the buffer: the holes before it overflow.
    push(&mut arbiter, &mut out, Line::A, 1, 31, 0);
    assert_eq!(arbiter.position().map(|position| position.epoch), Some(1));
    assert!(arbiter.counters().buffer_overflows > 0);
    assert!(!out.iter().any(|out| matches!(out, Out::Epoch(..))));
}

/// An asymmetric epoch change: A reports epoch 2 while B still carries
/// epoch 1. The first epoch 2 message ends epoch 1; B's later epoch 1
/// messages are dropped and counted, never delivered after it.
#[test]
fn an_asymmetric_epoch_change_drops_the_lagging_lines_old_messages() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in 1..=3 {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
    }
    push(&mut arbiter, &mut out, Line::A, 2, 1, 0);
    // B lags: its epoch 1 messages arrive after the change.
    for sequence in 1..=5 {
        push(&mut arbiter, &mut out, Line::B, 1, sequence, 0);
    }
    push(&mut arbiter, &mut out, Line::B, 2, 1, 0);
    push(&mut arbiter, &mut out, Line::B, 2, 2, 0);
    let epoch_at = out.iter().position(|out| *out == Out::Epoch(1, 2)).unwrap();
    assert!(
        out.iter()
            .skip(epoch_at)
            .all(|out| !matches!(out, Out::Message(_, 1, ..)))
    );
    assert_eq!(sequences(&out), vec![1, 2, 3, 1, 2]);
    assert_eq!(arbiter.counters().stale_epoch, 5);
}

/// The lines are out of step at a reset: A moves to epoch 2 while it
/// still misses 3 of epoch 1, which the lagging B then brings. Epoch 1's
/// hole stays open, epoch 2's messages wait, and 3 is repaired from B
/// with no gap; B's epoch 1 messages after the close are stale.
#[test]
fn an_old_epoch_hole_is_repaired_from_the_lagging_line_after_a_reset() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in [1, 2, 4, 5] {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
    }
    push(&mut arbiter, &mut out, Line::A, 2, 1, 0);
    push(&mut arbiter, &mut out, Line::A, 2, 2, 0);
    assert_eq!(sequences(&out), vec![1, 2]);
    assert_eq!(arbiter.held(), 4);
    for sequence in 1..=5 {
        push(&mut arbiter, &mut out, Line::B, 1, sequence, 0);
    }
    push(&mut arbiter, &mut out, Line::B, 2, 1, 0);
    assert_eq!(sequences(&out), vec![1, 2, 3, 4, 5, 1, 2]);
    assert!(!out.iter().any(|out| matches!(out, Out::Gap(..))));
    let epoch_at = out.iter().position(|out| *out == Out::Epoch(1, 2)).unwrap();
    assert_eq!(epoch_at, 5);
    let counters = arbiter.counters();
    // B's 4 and 5 came after the close: stale. Its 1 and 2 were
    // duplicates while epoch 1 was open.
    assert_eq!(counters.stale_epoch, 2);
    assert_eq!(counters.duplicates_b, 3);

    // The same hole with B silent closes at the skew window: a gap.
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in [1, 2, 4] {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
    }
    push(&mut arbiter, &mut out, Line::A, 2, 1, 0);
    arbiter.poll(SKEW, record(&mut out));
    assert_eq!(
        out.iter().skip(2).cloned().collect::<Vec<_>>(),
        vec![
            Out::Gap(1, 3, 1),
            Out::Message(Line::A, 1, 4, message(1, 4, b"p")),
            Out::Epoch(1, 2),
            Out::Message(Line::A, 2, 1, message(2, 1, b"p")),
        ]
    );
}

/// A copy of a sequence declared lost is late, not a duplicate.
#[test]
fn a_copy_after_its_gap_is_late() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    push(&mut arbiter, &mut out, Line::A, 1, 1, 0);
    push(&mut arbiter, &mut out, Line::A, 1, 3, 0);
    arbiter.poll(SKEW, record(&mut out));
    assert!(out.contains(&Out::Gap(1, 2, 1)));
    push(&mut arbiter, &mut out, Line::B, 1, 2, SKEW);
    push(&mut arbiter, &mut out, Line::B, 1, 3, SKEW);
    let counters = arbiter.counters();
    assert_eq!((counters.late_b, counters.duplicates_b), (1, 1));
    assert_eq!(sequences(&out), vec![1, 3]);
}

/// The epoch's stated start: a new epoch whose first message is lost on
/// both lines reports it as a gap.
#[test]
fn an_epoch_start_makes_a_lost_first_message_a_gap() {
    let feed = TestFeed {
        modulus: None,
        start: Some(1),
    };
    let mut arbiter = arbiter_with(feed, 8, Start::AtFirst);
    let mut out = Vec::new();
    push(&mut arbiter, &mut out, Line::A, 1, 9, 0);
    push(&mut arbiter, &mut out, Line::A, 2, 2, 0);
    push(&mut arbiter, &mut out, Line::B, 2, 2, 0);
    assert!(out.contains(&Out::Gap(2, 1, 1)));
    assert_eq!(sequences(&out), vec![9, 2]);
}

/// A duplicate whose length differs from the first copy is counted as a
/// conflict, against a held copy and against a delivered one.
#[test]
fn a_duplicate_of_another_length_is_a_length_conflict() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    arbiter.push(Line::A, &message(1, 1, b"abc"), 0, record(&mut out));
    arbiter.push(Line::B, &message(1, 1, b"abcd"), 0, record(&mut out));
    // Held: 3 arrives before 2.
    arbiter.push(Line::A, &message(1, 3, b"x"), 0, record(&mut out));
    arbiter.push(Line::B, &message(1, 3, b"xy"), 0, record(&mut out));
    // Same length, other bytes: a duplicate only, not compared.
    arbiter.push(Line::B, &message(1, 1, b"zzz"), 0, record(&mut out));
    let counters = arbiter.counters();
    assert_eq!(counters.length_conflicts, 2);
    assert_eq!(counters.duplicates_b, 3);
    assert_eq!(
        out.first(),
        Some(&Out::Message(Line::A, 1, 1, message(1, 1, b"abc")))
    );
}

/// A consumer joining mid-stream holds until it resyncs at its snapshot's
/// position: older messages are discarded, later ones delivered in order.
#[test]
fn a_mid_stream_join_recovers_through_a_resync_at_a_stated_position() {
    let mut arbiter = arbiter_with(
        TestFeed {
            modulus: None,
            start: None,
        },
        8,
        Start::AwaitingResync,
    );
    let mut out = Vec::new();
    for sequence in 100..106 {
        push(&mut arbiter, &mut out, Line::A, 3, sequence, 0);
        push(&mut arbiter, &mut out, Line::B, 3, sequence, 0);
    }
    assert!(out.is_empty());
    assert_eq!(arbiter.held(), 6);
    // The snapshot includes everything up to 102.
    arbiter.resync(
        Identity {
            epoch: 3,
            sequence: 102,
        },
        0,
        record(&mut out),
    );
    assert_eq!(sequences(&out), vec![103, 104, 105]);
    assert_eq!(arbiter.counters().resync_discarded, 3);
    push(&mut arbiter, &mut out, Line::B, 3, 106, 0);
    assert_eq!(sequences(&out), vec![103, 104, 105, 106]);
}

/// A resync during an open hole is deterministic: held messages at or
/// before the position are discarded, those after it stay, and the hole
/// after the position is not declared a gap by the resync.
#[test]
fn a_resync_during_an_open_hole_releases_deterministically() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    push(&mut arbiter, &mut out, Line::A, 1, 1, 0);
    // 2 is missing; 3, 4 and 6 are held.
    for sequence in [3, 4, 6] {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
    }
    assert_eq!(arbiter.held(), 3);
    arbiter.resync(
        Identity {
            epoch: 1,
            sequence: 3,
        },
        0,
        record(&mut out),
    );
    // 3 is discarded; 4 is now next and delivered; 5 is an open hole.
    assert_eq!(sequences(&out), vec![1, 4]);
    assert_eq!(arbiter.counters().resync_discarded, 1);
    assert_eq!(arbiter.counters().gaps, 0);
    assert_eq!(arbiter.held(), 1);
    // The hole then follows the usual rules.
    arbiter.poll(SKEW, record(&mut out));
    assert_eq!(
        out.last(),
        Some(&Out::Message(Line::A, 1, 6, message(1, 6, b"p")))
    );
    assert!(out.contains(&Out::Gap(1, 5, 1)));
}

/// A resync into another epoch discards everything held.
#[test]
fn a_resync_into_another_epoch_discards_what_is_held() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    push(&mut arbiter, &mut out, Line::A, 1, 1, 0);
    push(&mut arbiter, &mut out, Line::A, 1, 3, 0);
    arbiter.resync(
        Identity {
            epoch: 2,
            sequence: 10,
        },
        0,
        record(&mut out),
    );
    assert_eq!(arbiter.held(), 0);
    assert_eq!(arbiter.counters().resync_discarded, 1);
    push(&mut arbiter, &mut out, Line::B, 2, 11, 0);
    assert_eq!(sequences(&out), vec![1, 11]);
}

/// The buffer overflows: a message beyond it ends the oldest holes, the
/// held messages before them delivered.
#[test]
fn buffer_overflow_declares_the_oldest_holes_lost() {
    let mut arbiter = arbiter_with(
        TestFeed {
            modulus: None,
            start: None,
        },
        4,
        Start::AtFirst,
    );
    let mut out = Vec::new();
    push(&mut arbiter, &mut out, Line::A, 1, 1, 0);
    push(&mut arbiter, &mut out, Line::A, 1, 3, 0);
    // next is 2; 2 + 4 = 6 does not fit: hole 2 goes, 3 is delivered, 6
    // waits at the far end of the buffer behind holes 4 and 5.
    push(&mut arbiter, &mut out, Line::A, 1, 6, 0);
    assert_eq!(sequences(&out), vec![1, 3]);
    assert!(out.contains(&Out::Gap(1, 2, 1)));
    assert_eq!(arbiter.counters().buffer_overflows, 1);
    assert_eq!(arbiter.held(), 1);
}

/// Unsequenced and oversized messages are counted, never delivered.
#[test]
fn unsequenced_and_oversized_messages_are_counted() {
    let mut arbiter = plain();
    let mut out = Vec::new();
    arbiter.push(Line::A, b"heartbeat", 0, record(&mut out));
    push(&mut arbiter, &mut out, Line::A, 1, 1, 0);
    // Too long to hold while ahead; deliverable when next.
    arbiter.push(Line::A, &message(1, 3, &[0; 64]), 0, record(&mut out));
    arbiter.push(Line::A, &message(1, 2, &[0; 64]), 0, record(&mut out));
    let counters = arbiter.counters();
    assert_eq!(counters.unsequenced, 1);
    assert_eq!(counters.oversized, 1);
    assert_eq!(sequences(&out), vec![1, 2]);
}

/// The settings are checked.
#[test]
fn the_configuration_is_checked() {
    let feed = TestFeed {
        modulus: None,
        start: None,
    };
    let config = |capacity| ArbiterConfig {
        capacity,
        max_message_length: 8,
        skew_window: 1,
        start: Start::AtFirst,
    };
    assert_eq!(
        Arbiter::new(feed, config(0)).err(),
        Some(ConfigError::Capacity)
    );
    assert_eq!(
        Arbiter::new(feed, config(6)).err(),
        Some(ConfigError::Capacity)
    );
    let small = TestFeed {
        modulus: NonZeroU64::new(16),
        start: None,
    };
    // modulus 16: window 7, so a capacity of 8 does not fit.
    assert_eq!(
        Arbiter::new(small, config(8)).err(),
        Some(ConfigError::CapacityAboveWindow)
    );
    assert!(Arbiter::new(small, config(4)).is_ok());
    let tiny = TestFeed {
        modulus: NonZeroU64::new(4),
        start: None,
    };
    assert_eq!(
        Arbiter::new(tiny, config(1)).err(),
        Some(ConfigError::Modulus)
    );
    // 5: window 2, a buffer of one.
    let five = TestFeed {
        modulus: NonZeroU64::new(5),
        start: None,
    };
    assert!(Arbiter::new(five, config(1)).is_ok());
}

/// While an old epoch's hole is open, a new-epoch message beyond the
/// second buffer, or a message of a third epoch, closes it at once: the
/// hole is a gap.
#[test]
fn an_open_old_epoch_closes_on_overflow_or_a_third_epoch() {
    // Overflow of the waiting buffer (capacity 8).
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in [1, 3] {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
    }
    push(&mut arbiter, &mut out, Line::A, 2, 1, 0);
    push(&mut arbiter, &mut out, Line::A, 2, 9, 0);
    assert!(out.contains(&Out::Gap(1, 2, 1)));
    assert!(out.contains(&Out::Epoch(1, 2)));
    assert_eq!(sequences(&out), vec![1, 3, 1]);
    assert_eq!(
        arbiter.position(),
        Some(Identity {
            epoch: 2,
            sequence: 2
        })
    );

    // A third epoch.
    let mut arbiter = plain();
    let mut out = Vec::new();
    for sequence in [1, 3] {
        push(&mut arbiter, &mut out, Line::A, 1, sequence, 0);
    }
    push(&mut arbiter, &mut out, Line::A, 2, 1, 0);
    push(&mut arbiter, &mut out, Line::A, 3, 1, 0);
    assert_eq!(
        out.iter().skip(1).cloned().collect::<Vec<_>>(),
        vec![
            Out::Gap(1, 2, 1),
            Out::Message(Line::A, 1, 3, message(1, 3, b"p")),
            Out::Epoch(1, 2),
            Out::Message(Line::A, 2, 1, message(2, 1, b"p")),
            Out::Epoch(2, 3),
            Out::Message(Line::A, 3, 1, message(3, 1, b"p")),
        ]
    );
}
