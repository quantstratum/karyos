// SPDX-License-Identifier: Apache-2.0

//! The skip policy against a receive owner (`quantstratum-docs:
//! karyos/design/gaps-and-unreliable-delivery.md`, "Required validation",
//! "Skip timing" and "Far window").

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::sync::Arc;

use super::*;
use crate::SysError;
use crate::frame::{Flags, FrameType, Word0};
use crate::log_buffer::{DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig, PublicationMode};
use crate::receive::{ImageParams, Item, ValidatedDatagram};
use crate::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use crate::term::TermId;

const SESSION: i32 = 3;
const STREAM: i32 = 4;
const INITIAL: u32 = 9;
const TERM: u64 = MIN_TERM_LENGTH as u64;
const MS: u64 = 1_000_000;

fn params() -> ImageParams {
    ImageParams::new(
        SESSION,
        STREAM,
        1,
        TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        DEFAULT_MTU,
    )
    .unwrap()
}

fn image() -> (Arc<LogBuffer>, ReceiveOwner) {
    image_from(0)
}

/// An image joined at `join`.
fn image_from(join: u64) -> (Arc<LogBuffer>, ReceiveOwner) {
    let buffer = Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 5,
            max_subscribers: 2,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(INITIAL),
            lane: Lane::ZERO,
            session_id: SESSION,
            stream_id: STREAM,
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Image {
                join,
                local_gaps: true,
            },
            schedule_capacity: 0,
        })
        .unwrap(),
    );
    let owner = ReceiveOwner::new(params(), vec![Arc::clone(&buffer)]).unwrap();
    (buffer, owner)
}

/// A 64-byte DATA frame of term `term` at `offset`.
fn data(term: u32, offset: u32, fill: u8) -> Vec<u8> {
    let flags = Flags::new(true, true, false, false, Lane::ZERO);
    let mut out = Vec::new();
    out.extend_from_slice(&Word0::new(64, flags, FrameType::Data).pack().to_le_bytes());
    out.extend_from_slice(&offset.cast_signed().to_le_bytes());
    out.extend_from_slice(&SESSION.to_le_bytes());
    out.extend_from_slice(&STREAM.to_le_bytes());
    out.extend_from_slice(&INITIAL.wrapping_add(term).to_le_bytes());
    out.extend_from_slice(&0i64.to_le_bytes());
    out.extend(std::iter::repeat_n(fill, 32));
    out
}

fn receive(owner: &mut ReceiveOwner, bytes: &[u8]) -> Result<Received, ReceiveError> {
    let datagram = ValidatedDatagram::parse(bytes, &params()).unwrap();
    let Some(Item::Frame(frame)) = datagram.items().next() else {
        panic!("no frame");
    };
    owner.receive(&frame)
}

fn policy_of(config: SkipConfig) -> SkipPolicy {
    SkipPolicy::new(config, 1).unwrap()
}

/// Frames at 0 and 128: a hole `[64, 128)`.
fn with_hole() -> (Arc<LogBuffer>, ReceiveOwner) {
    let (buffer, mut owner) = image();
    receive(&mut owner, &data(0, 0, 1)).unwrap();
    receive(&mut owner, &data(0, 128, 2)).unwrap();
    assert_eq!(owner.first_hole(Lane::ZERO).unwrap(), Some((64, 64)));
    (buffer, owner)
}

#[test]
fn an_unreliable_hole_is_sealed_at_the_reorder_deadline() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig::unreliable());
    assert_eq!(skip.duty(&mut owner, 0).unwrap().sealed, 0, "detected at 0");
    assert_eq!(skip.duty(&mut owner, MS - 1).unwrap().sealed, 0);
    let report = skip.duty(&mut owner, MS).unwrap();
    assert_eq!((report.sealed, report.sealed_bytes), (1, 64));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(192));
    assert_eq!(owner.first_hole(Lane::ZERO).unwrap(), None);
}

/// The deadline is the larger of the reorder interval and the skew window,
/// never their sum.
#[test]
fn the_deadline_is_the_larger_of_reorder_and_skew() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig {
        skew_window_ns: 3 * MS,
        ..SkipConfig::unreliable()
    });
    assert_eq!(skip.duty(&mut owner, 0).unwrap().sealed, 0);
    assert_eq!(skip.duty(&mut owner, 3 * MS - 1).unwrap().sealed, 0);
    assert_eq!(
        skip.duty(&mut owner, 3 * MS).unwrap().sealed,
        1,
        "not at 4 ms"
    );
}

/// A duplicate never restarts the deadline; a repair before it wins.
#[test]
fn a_duplicate_does_not_restart_and_a_repair_wins() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig::unreliable());
    let _ = skip.duty(&mut owner, 0).unwrap();
    let duplicate = receive(&mut owner, &data(0, 128, 2));
    assert_eq!(duplicate, Ok(Received::Duplicate));
    skip.arrived(Lane::ZERO, &duplicate, 128, MS / 2);
    assert_eq!(skip.duty(&mut owner, MS).unwrap().sealed, 1);

    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig::unreliable());
    let _ = skip.duty(&mut owner, 0).unwrap();
    let repaired = receive(&mut owner, &data(0, 64, 3));
    skip.arrived(Lane::ZERO, &repaired, 64, MS / 2);
    let report = skip.duty(&mut owner, MS).unwrap();
    assert_eq!(report.sealed, 0, "the real frame won");
    assert_eq!(owner.first_loss(Lane::ZERO), Some(None));
}

/// A zero interval seals at the first duty that sees the hole.
#[test]
fn a_zero_interval_seals_at_once() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig {
        reorder_timeout_ns: 0,
        ..SkipConfig::unreliable()
    });
    assert_eq!(skip.duty(&mut owner, 5).unwrap().sealed, 1);
}

/// A hole revealed after the episode began is a new detection, with its
/// own deadline.
#[test]
fn a_later_hole_is_a_new_detection() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig::unreliable());
    let _ = skip.duty(&mut owner, 0).unwrap();
    // A frame far above reveals a second hole [192, 320) at 0.5 ms.
    receive(&mut owner, &data(0, 320, 4)).unwrap();
    let report = skip.duty(&mut owner, MS).unwrap();
    assert_eq!(report.sealed, 1, "only the first hole is due");
    assert_eq!(owner.first_hole(Lane::ZERO).unwrap(), Some((192, 128)));
    assert_eq!(skip.duty(&mut owner, 2 * MS - 1).unwrap().sealed, 0);
    assert_eq!(skip.duty(&mut owner, 2 * MS).unwrap().sealed, 1);
}

/// GU-5: a reliable channel never seals on a timer; `close` closes on a
/// correlated `RANGE_UNAVAILABLE`, `skip` seals the whole hole.
#[test]
fn a_reliable_hole_closes_or_is_skipped_only_when_unrecoverable() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig::reliable());
    assert_eq!(skip.duty(&mut owner, 10_000 * MS).unwrap().sealed, 0);
    let report = skip
        .range_unavailable(&mut owner, Lane::ZERO, 128, 10_000 * MS)
        .unwrap();
    assert_eq!(
        report.close,
        Some(Close {
            lane: Lane::ZERO,
            cause: CloseCause::Unrecoverable,
            from: 64,
            to: 128
        })
    );
    assert_eq!(
        owner.first_hole(Lane::ZERO).unwrap(),
        Some((64, 64)),
        "no record"
    );
    assert_eq!(skip.counters(Lane::ZERO).unwrap().unrecoverable, 1);

    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig {
        on_unrecoverable: Unrecoverable::Skip,
        ..SkipConfig::reliable()
    });
    let report = skip
        .range_unavailable(&mut owner, Lane::ZERO, 96, 0)
        .unwrap();
    assert_eq!(
        (report.sealed, report.sealed_bytes),
        (1, 64),
        "the whole hole"
    );
    assert_eq!(report.close, None);
    assert_eq!(owner.first_loss(Lane::ZERO), Some(Some(64)));
}

/// GU-6: a lowest retained position beyond the window closes with
/// `GapCannotResume` under every policy.
#[test]
fn a_range_beyond_the_window_cannot_resume() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig {
        on_unrecoverable: Unrecoverable::Skip,
        ..SkipConfig::reliable()
    });
    let far = 3 * TERM;
    let report = skip
        .range_unavailable(&mut owner, Lane::ZERO, far, 0)
        .unwrap();
    assert_eq!(
        report
            .close
            .map(|close| (close.cause, close.from, close.to)),
        Some((CloseCause::GapCannotResume, 64, far))
    );
}

/// GU-6 on an unreliable channel: arrivals all `Ahead` for the far-window
/// timeout close the lane; a committed arrival in between restarts it.
#[test]
fn arrivals_all_ahead_close_an_unreliable_lane() {
    let (_buffer, mut owner) = image();
    receive(&mut owner, &data(0, 0, 1)).unwrap();
    let mut skip = policy_of(SkipConfig::unreliable());
    let ahead = Ok(Received::Ahead);
    skip.arrived(Lane::ZERO, &ahead, 5 * TERM, 0);
    skip.arrived(Lane::ZERO, &ahead, 4 * TERM, 500 * MS);
    assert_eq!(skip.duty(&mut owner, 999 * MS).unwrap().close, None);
    // A committed arrival restarts the clock.
    let committed = receive(&mut owner, &data(0, 64, 2));
    skip.arrived(Lane::ZERO, &committed, 64, 999 * MS);
    assert_eq!(skip.duty(&mut owner, 1000 * MS).unwrap().close, None);
    skip.arrived(Lane::ZERO, &ahead, 6 * TERM, 1000 * MS);
    assert_eq!(skip.duty(&mut owner, 1999 * MS).unwrap().close, None);
    let report = skip.duty(&mut owner, 2000 * MS).unwrap();
    assert_eq!(
        report.close,
        Some(Close {
            lane: Lane::ZERO,
            cause: CloseCause::GapCannotResume,
            from: 128,
            to: 6 * TERM
        })
    );
    // Closed: nothing more is reported or sealed.
    assert_eq!(
        skip.duty(&mut owner, 3000 * MS).unwrap(),
        SkipReport::default()
    );
    assert_eq!(skip.counters(Lane::ZERO).unwrap().gap_cannot_resume, 1);
}

#[test]
fn a_reorder_interval_above_one_second_is_refused() {
    assert_eq!(
        SkipPolicy::new(
            SkipConfig {
                reorder_timeout_ns: MAX_REORDER_TIMEOUT_NS + 1,
                ..SkipConfig::unreliable()
            },
            1
        )
        .err(),
        Some(SkipConfigError::ReorderTimeout(MAX_REORDER_TIMEOUT_NS + 1))
    );
}

/// GU-6 and RC-9 against a floor beyond the window: no far-window catch-up
/// under either policy. The lane closes with `GapCannotResume` and nothing
/// is sealed, not the near hole and not the rest of its term.
#[test]
fn a_floor_beyond_the_window_seals_nothing() {
    // Past the window, and outside the incarnation (a peer-reported floor).
    for (policy, floor) in [
        (Unrecoverable::Skip, 3 * TERM),
        (Unrecoverable::Close, 3 * TERM),
        (Unrecoverable::Skip, u64::MAX),
        (Unrecoverable::Close, u64::MAX),
    ] {
        let (_buffer, mut owner) = with_hole();
        let mut skip = policy_of(SkipConfig {
            on_unrecoverable: policy,
            ..SkipConfig::reliable()
        });
        let report = skip
            .range_unavailable(&mut owner, Lane::ZERO, floor, 0)
            .unwrap();
        assert_eq!((report.sealed, report.sealed_bytes), (0, 0));
        assert_eq!(
            report
                .close
                .map(|close| (close.cause, close.from, close.to)),
            Some((CloseCause::GapCannotResume, 64, floor))
        );
        assert_eq!(owner.first_hole(Lane::ZERO).unwrap(), Some((64, 64)));
        assert_eq!(owner.first_loss(Lane::ZERO), Some(None));
    }
}

/// Under `skip`, only holes that start below the floor are sealed, each
/// whole; a hole above the floor stays due.
#[test]
fn skip_seals_only_the_holes_below_the_floor() {
    let (_buffer, mut owner) = with_hole();
    // A second hole [192, 320) above a floor of 160.
    receive(&mut owner, &data(0, 320, 3)).unwrap();
    let mut skip = policy_of(SkipConfig {
        on_unrecoverable: Unrecoverable::Skip,
        ..SkipConfig::reliable()
    });
    let report = skip
        .range_unavailable(&mut owner, Lane::ZERO, 160, 0)
        .unwrap();
    assert_eq!((report.sealed, report.sealed_bytes), (1, 64));
    assert_eq!(owner.first_hole(Lane::ZERO).unwrap(), Some((192, 128)));
}

/// GU-11: a seal published before a later step failed is counted and
/// reported as `GapCommitted`, never as a plain failure, and the duty stops
/// there: the second hole is not sealed in that call.
#[test]
fn a_seal_committed_before_a_failure_is_reported_with_the_duty() {
    let (_buffer, mut owner) = with_hole();
    // A second hole [192, 320).
    receive(&mut owner, &data(0, 320, 3)).unwrap();
    let mut skip = policy_of(SkipConfig {
        reorder_timeout_ns: 0,
        ..SkipConfig::unreliable()
    });
    owner.fail_next_advance(Lane::ZERO, SysError::ResourcesUnavailable);
    let report = skip.duty(&mut owner, 5).unwrap();
    assert_eq!((report.sealed, report.sealed_bytes), (1, 64));
    assert_eq!(
        report.committed_failure,
        Some(ReceiveError::GapCommitted {
            lane: Lane::ZERO,
            position: 64,
            extent: 64,
            error: SysError::ResourcesUnavailable,
        })
    );
    assert_eq!(owner.gap_counters(Lane::ZERO).unwrap().gaps_sealed, 1);
    assert_eq!(owner.first_loss(Lane::ZERO), Some(Some(64)));
}

/// GU-11: close counters are per lane, and an increment that would
/// overflow keeps the value and sets the sticky flag.
#[test]
fn close_counters_are_per_lane_and_never_wrap() {
    let skip = policy_of(SkipConfig::unreliable());
    assert_eq!(skip.counters(Lane::ZERO), Some(SkipCounters::default()));
    assert_eq!(skip.counters(Lane::try_new(1).unwrap()), None);

    let mut counters = SkipCounters {
        gap_cannot_resume: u64::MAX,
        ..SkipCounters::default()
    };
    counters.count(CloseCause::GapCannotResume);
    assert_eq!(counters.gap_cannot_resume, u64::MAX);
    assert!(counters.overflowed);
    counters.count(CloseCause::Unrecoverable);
    assert_eq!(counters.unrecoverable, 1);
    assert!(counters.overflowed, "sticky");
}

/// A committed failure stops the whole duty: a hole due on another lane is
/// not sealed in that call.
#[test]
fn a_committed_failure_stops_the_other_lanes() {
    let lane_one = Lane::try_new(1).unwrap();
    let params = ImageParams::new(
        SESSION,
        STREAM,
        2,
        TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        DEFAULT_MTU,
    )
    .unwrap();
    let buffer = |lane: Lane| {
        let (plain, _) = image();
        Arc::new(
            LogBuffer::new(LogBufferConfig {
                lane,
                ..plain.config
            })
            .unwrap(),
        )
    };
    let mut owner = ReceiveOwner::new(params, vec![buffer(Lane::ZERO), buffer(lane_one)]).unwrap();
    // A hole [64, 128) on each lane.
    for lane in [Lane::ZERO, lane_one] {
        for (offset, fill) in [(0, 1), (128, 2)] {
            let mut bytes = data(0, offset, fill);
            let flags = Flags::new(true, true, false, false, lane);
            bytes[..8]
                .copy_from_slice(&Word0::new(64, flags, FrameType::Data).pack().to_le_bytes());
            let datagram = ValidatedDatagram::parse(&bytes, &params).unwrap();
            let Some(Item::Frame(frame)) = datagram.items().next() else {
                panic!("no frame");
            };
            owner.receive(&frame).unwrap();
        }
    }
    let mut skip = SkipPolicy::new(
        SkipConfig {
            reorder_timeout_ns: 0,
            ..SkipConfig::unreliable()
        },
        2,
    )
    .unwrap();
    owner.fail_next_advance(Lane::ZERO, SysError::ResourcesUnavailable);
    let report = skip.duty(&mut owner, 5).unwrap();
    assert!(report.committed_failure.is_some());
    assert_eq!(report.sealed, 1, "lane 1 not sealed in that call");
    assert_eq!(owner.first_hole(lane_one).unwrap(), Some((64, 64)));
    assert_eq!(owner.first_loss(lane_one), Some(None));
}

/// A gate that answers from a script, recording what it was asked.
#[derive(Default)]
struct Scripted {
    pending: bool,
    asked: Vec<(Lane, u64, u32, u64)>,
}

impl SealGate for Scripted {
    fn before_seal(&mut self, lane: Lane, position: u64, extent: u32, now: u64) -> GateAnswer {
        self.asked.push((lane, position, extent, now));
        if self.pending {
            GateAnswer::Pending
        } else {
            GateAnswer::Permit
        }
    }
}

/// A due hole whose gate answers Pending stays due and is posted: nothing
/// is sealed, a copy into it is late after the skip and not written, and
/// once the gate permits the hole is sealed whole and the post cleared.
#[test]
fn a_pending_gate_posts_the_hole_and_holds_its_seal() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig::unreliable());
    let mut gate = Scripted {
        pending: true,
        ..Scripted::default()
    };
    assert_eq!(skip.duty_gated(&mut owner, 0, &mut gate).unwrap().sealed, 0);
    assert!(gate.asked.is_empty(), "not due yet");
    let report = skip.duty_gated(&mut owner, MS, &mut gate).unwrap();
    assert_eq!((report.sealed, report.gated), (0, 1));
    assert_eq!(gate.asked, [(Lane::ZERO, 64, 64, MS)]);
    assert_eq!(owner.posted(Lane::ZERO), Some((64, 128)));
    assert_eq!(owner.first_hole(Lane::ZERO).unwrap(), Some((64, 64)));
    // A late copy into the posted hole is refused and counted.
    let late = receive(&mut owner, &data(0, 64, 9));
    assert_eq!(late, Ok(Received::LateAfterSkip));
    assert_eq!(owner.counters().frames_late_after_skip, 1);
    assert_eq!(owner.first_hole(Lane::ZERO).unwrap(), Some((64, 64)));
    // Still pending on the next duty: asked again, nothing sealed.
    let report = skip.duty_gated(&mut owner, 2 * MS, &mut gate).unwrap();
    assert_eq!((report.sealed, report.gated), (0, 1));
    // Permitted: the whole hole is sealed and the post cleared.
    gate.pending = false;
    let report = skip.duty_gated(&mut owner, 3 * MS, &mut gate).unwrap();
    assert_eq!(
        (report.sealed, report.sealed_bytes, report.gated),
        (1, 64, 0)
    );
    assert_eq!(owner.posted(Lane::ZERO), None);
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(192));
    // The lane commits again above the sealed hole.
    assert_eq!(
        receive(&mut owner, &data(0, 192, 4)),
        Ok(Received::Committed {
            position: 192,
            extent: 64
        })
    );
}

/// The ungated duty is the duty with a gate that always permits: the same
/// seals, nothing posted.
#[test]
fn the_ungated_duty_seals_as_before() {
    let (_buffer, mut gated_owner) = with_hole();
    let (_buffer2, mut owner) = with_hole();
    let mut gated = policy_of(SkipConfig::unreliable());
    let mut plain = policy_of(SkipConfig::unreliable());
    let mut gate = Scripted::default();
    for now in [0, MS] {
        let a = gated.duty_gated(&mut gated_owner, now, &mut gate).unwrap();
        let b = plain.duty(&mut owner, now).unwrap();
        assert_eq!(a, b);
    }
    assert_eq!(gate.asked, [(Lane::ZERO, 64, 64, MS)]);
    assert_eq!(owner.posted(Lane::ZERO), None);
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(192));
}

/// A reliable range proven unrecoverable under `skip` asks the gate too:
/// pending, it is posted and not sealed; permitted, it is sealed whole.
#[test]
fn an_unrecoverable_range_is_gated_too() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig {
        on_unrecoverable: Unrecoverable::Skip,
        ..SkipConfig::reliable()
    });
    let mut gate = Scripted {
        pending: true,
        ..Scripted::default()
    };
    let report = skip
        .range_unavailable_gated(&mut owner, Lane::ZERO, 96, 0, &mut gate)
        .unwrap();
    assert_eq!((report.sealed, report.gated, report.close), (0, 1, None));
    assert_eq!(owner.posted(Lane::ZERO), Some((64, 128)));
    // The unrecoverable range stays due: a later duty seals it once
    // permitted, with no new RANGE_UNAVAILABLE.
    gate.pending = false;
    let report = skip.duty_gated(&mut owner, 0, &mut gate).unwrap();
    assert_eq!((report.sealed, report.sealed_bytes), (1, 64));
    assert_eq!(owner.posted(Lane::ZERO), None);
    assert_eq!(owner.first_loss(Lane::ZERO), Some(Some(64)));
}

/// P2.12 step 3 PR 3b: `duty_observed` tells of each committed seal once,
/// with its lane, position and extent; a later duty with nothing due tells
/// nothing more.
#[test]
fn each_committed_seal_is_told_once() {
    let (_buffer, mut owner) = with_hole();
    // A second hole [192, 320).
    receive(&mut owner, &data(0, 320, 3)).unwrap();
    let mut skip = policy_of(SkipConfig {
        reorder_timeout_ns: 0,
        ..SkipConfig::unreliable()
    });
    let mut sealed = Vec::new();
    let report = skip
        .duty_observed(&mut owner, 5, &mut Ungated, |lane, position, extent| {
            sealed.push((lane, position, extent));
        })
        .unwrap();
    assert_eq!(report.sealed, 2);
    assert_eq!(sealed, [(Lane::ZERO, 64, 64), (Lane::ZERO, 192, 128)]);
    let report = skip
        .duty_observed(&mut owner, 6, &mut Ungated, |lane, position, extent| {
            sealed.push((lane, position, extent));
        })
        .unwrap();
    assert_eq!(report.sealed, 0);
    assert_eq!(sealed.len(), 2, "nothing more");
}

/// PR 3b: a seal published before a later step failed (GU-11) is told
/// once, as committed.
#[test]
fn a_seal_committed_before_a_failure_is_told() {
    let (_buffer, mut owner) = with_hole();
    receive(&mut owner, &data(0, 320, 3)).unwrap();
    let mut skip = policy_of(SkipConfig {
        reorder_timeout_ns: 0,
        ..SkipConfig::unreliable()
    });
    owner.fail_next_advance(Lane::ZERO, SysError::ResourcesUnavailable);
    let mut sealed = Vec::new();
    let report = skip
        .duty_observed(&mut owner, 5, &mut Ungated, |lane, position, extent| {
            sealed.push((lane, position, extent));
        })
        .unwrap();
    assert!(report.committed_failure.is_some());
    assert_eq!(sealed, [(Lane::ZERO, 64, 64)]);
}

/// PR 3b: a hole the gate holds (posted, not sealed) tells nothing, on
/// each duty it stays pending; once permitted, its seal is told once.
#[test]
fn a_held_seal_is_told_only_once_committed() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig::unreliable());
    let mut gate = Scripted {
        pending: true,
        ..Scripted::default()
    };
    let mut sealed = Vec::new();
    for now in [0, MS, 2 * MS] {
        let _ = skip
            .duty_observed(&mut owner, now, &mut gate, |lane, position, extent| {
                sealed.push((lane, position, extent));
            })
            .unwrap();
    }
    assert!(sealed.is_empty(), "posted, never sealed");
    gate.pending = false;
    for now in [3 * MS, 4 * MS] {
        let _ = skip
            .duty_observed(&mut owner, now, &mut gate, |lane, position, extent| {
                sealed.push((lane, position, extent));
            })
            .unwrap();
    }
    assert_eq!(sealed, [(Lane::ZERO, 64, 64)]);
}

/// PR 3b: an unrecoverable range sealed under `skip` is told too.
#[test]
fn an_unrecoverable_seal_is_told() {
    let (_buffer, mut owner) = with_hole();
    let mut skip = policy_of(SkipConfig {
        on_unrecoverable: Unrecoverable::Skip,
        ..SkipConfig::reliable()
    });
    let mut sealed = Vec::new();
    let report = skip
        .range_unavailable_observed(
            &mut owner,
            Lane::ZERO,
            160,
            0,
            &mut Ungated,
            |lane, position, extent| sealed.push((lane, position, extent)),
        )
        .unwrap();
    assert_eq!(report.sealed, 1);
    assert_eq!(sealed, [(Lane::ZERO, 64, 64)]);
}

/// A heartbeat's tail (SPEC §6, G1): frame `[0, 64)` received, the sender's
/// next position 192, so `[64, 192)` was lost with nothing after it.
fn with_tail() -> (Arc<LogBuffer>, ReceiveOwner, SkipPolicy) {
    let (buffer, mut owner) = image();
    receive(&mut owner, &data(0, 0, 1)).unwrap();
    let mut skip = policy_of(SkipConfig::unreliable());
    skip.revealed(Lane::ZERO, 192);
    (buffer, owner, skip)
}

/// What one duty sealed, each `(position, extent)`.
fn sealed_by(skip: &mut SkipPolicy, owner: &mut ReceiveOwner, now: u64) -> Vec<(u64, u32)> {
    let mut seals = Vec::new();
    let _ = skip
        .duty_observed(owner, now, &mut Ungated, |_, position, extent| {
            seals.push((position, extent));
        })
        .unwrap();
    seals
}

/// karyos#806: an unreliable tail no frame revealed is sealed from the
/// covered end to the heartbeat's mark, at the reorder deadline, with its
/// exact range.
#[test]
fn an_unreliable_tail_a_heartbeat_reveals_is_sealed_at_the_deadline() {
    let (_buffer, mut owner, mut skip) = with_tail();
    assert_eq!(
        owner.first_hole(Lane::ZERO).unwrap(),
        None,
        "no frame shows it"
    );
    assert!(
        sealed_by(&mut skip, &mut owner, 0).is_empty(),
        "detected at 0"
    );
    assert!(sealed_by(&mut skip, &mut owner, MS - 1).is_empty());
    assert_eq!(sealed_by(&mut skip, &mut owner, MS), [(64, 128)]);
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(192));
    assert!(sealed_by(&mut skip, &mut owner, 2 * MS).is_empty(), "once");
}

/// The tail's data arriving before the deadline leaves nothing to seal.
#[test]
fn a_tail_that_arrives_before_the_deadline_is_not_sealed() {
    let (_buffer, mut owner, mut skip) = with_tail();
    assert!(sealed_by(&mut skip, &mut owner, 0).is_empty());
    receive(&mut owner, &data(0, 64, 2)).unwrap();
    receive(&mut owner, &data(0, 128, 3)).unwrap();
    assert!(sealed_by(&mut skip, &mut owner, MS).is_empty());
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(192));
}

/// The same mark again neither restarts the deadline nor seals twice; a
/// higher one extends the open hole, detected when it opened.
#[test]
fn a_repeated_mark_is_idempotent_and_a_higher_one_extends_the_hole() {
    let (_buffer, mut owner, mut skip) = with_tail();
    assert!(sealed_by(&mut skip, &mut owner, 0).is_empty());
    skip.revealed(Lane::ZERO, 192);
    skip.revealed(Lane::ZERO, 128);
    skip.revealed(Lane::ZERO, 256);
    assert!(sealed_by(&mut skip, &mut owner, MS / 2).is_empty());
    assert_eq!(sealed_by(&mut skip, &mut owner, MS), [(64, 192)]);
    skip.revealed(Lane::ZERO, 256);
    assert!(sealed_by(&mut skip, &mut owner, 3 * MS).is_empty());
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(256));
}

/// An image that joined at 256 seals nothing before its join: a mark at
/// or below it is no tail, one above it a tail from the join.
#[test]
fn a_tail_never_reaches_below_the_join() {
    let (_buffer, mut owner) = image_from(256);
    let mut skip = policy_of(SkipConfig::unreliable());
    skip.revealed(Lane::ZERO, 256);
    assert!(sealed_by(&mut skip, &mut owner, 0).is_empty());
    assert!(sealed_by(&mut skip, &mut owner, 10 * MS).is_empty());
    skip.revealed(Lane::ZERO, 320);
    assert!(sealed_by(&mut skip, &mut owner, 11 * MS).is_empty());
    assert_eq!(sealed_by(&mut skip, &mut owner, 12 * MS), [(256, 64)]);
}

/// A reliable image NAKs its tail (the driver's business): the policy
/// never seals it.
#[test]
fn a_reliable_tail_is_never_sealed() {
    let (_buffer, mut owner) = image();
    receive(&mut owner, &data(0, 0, 1)).unwrap();
    let mut skip = policy_of(SkipConfig::reliable());
    skip.revealed(Lane::ZERO, 192);
    assert!(sealed_by(&mut skip, &mut owner, 0).is_empty());
    assert!(sealed_by(&mut skip, &mut owner, 10 * MS).is_empty());
}
