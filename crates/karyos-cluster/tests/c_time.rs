// SPDX-License-Identifier: Apache-2.0

//! Contract C-TIME's stamping function (ADR-0111, decisions 2 and 4;
//! quantstratum/karyos#744): `event_time = max(raw, watermark)`, the
//! watermark being the log's last entry's event time, or the snapshot's
//! session table log time when the log is empty after it.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use karyos_cluster::{DedupConfig, SessionTable, stamp};

#[test]
fn test_stamp_keeps_a_clock_ahead_of_the_watermark() {
    assert_eq!(stamp(2_000, 1_000), 2_000);
    assert_eq!(stamp(1, 0), 1);
    assert_eq!(stamp(u64::MAX, u64::MAX - 1), u64::MAX);
}

#[test]
fn test_stamp_clamps_a_clock_behind_the_watermark_to_it() {
    assert_eq!(stamp(1_000, 2_000), 2_000);
    assert_eq!(stamp(0, u64::MAX), u64::MAX);
    // A genuine repeat of the clock is the watermark too: the two cannot
    // be told apart.
    assert_eq!(stamp(2_000, 2_000), 2_000);
}

#[test]
fn test_stamp_never_steps_back_along_a_history() {
    // A leader change to a clock 10_000 behind, then a clock that catches
    // up: every stamp is at least the one before, and each clamped stamp
    // is exactly the watermark before it.
    let raws = [100, 200, 300, 0, 50, 150, 299, 300, 301, 400];
    let mut watermark = 0;
    for raw in raws {
        let stamped = stamp(raw, watermark);
        assert!(stamped >= watermark);
        if raw <= watermark {
            assert_eq!(stamped, watermark);
        } else {
            assert_eq!(stamped, raw);
        }
        watermark = stamped;
    }
    assert_eq!(watermark, 400);
}

/// A log written before C-TIME can go back: its largest event time
/// exceeds its last entry's. The snapshot's session table records that
/// largest time (its log time), and a stamp against it never steps back
/// from any earlier entry; it survives the sessions section's encoding.
#[test]
fn test_stamp_against_a_pre_c_time_snapshot_log_time_never_steps_back() {
    let times = [10, 50, 30];
    let mut sessions = SessionTable::new(DedupConfig::default()).unwrap();
    for time in times {
        sessions.observe(time);
    }
    let restored = SessionTable::decode(&sessions.encode()).unwrap();
    let watermark = restored.log_time();
    assert_eq!(watermark, 50);
    assert!(watermark > *times.last().unwrap());
    for raw in [0, 20, 30, 49, 50] {
        let stamped = stamp(raw, watermark);
        assert_eq!(stamped, 50);
        assert!(times.iter().all(|time| stamped >= *time));
    }
    assert_eq!(stamp(60, watermark), 60);
}
