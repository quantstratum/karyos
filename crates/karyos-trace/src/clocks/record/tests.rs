// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;
use crate::clocks::ClockKey;
use crate::clocks::utc::{Scale, Source, SyncState};
use crate::journal::ObserverId;

fn key(domain: u64) -> ClockKey {
    ClockKey {
        observer: ObserverId {
            driver: [1, 0],
            journal: 2,
        },
        domain,
        epoch: 4,
    }
}

fn calibration() -> Calibration {
    Calibration {
        from: key(3),
        to: key(5),
        reference: 10,
        offset: -4,
        offset_uncertainty: 2,
        drift: 7,
        drift_uncertainty: 1,
        valid_from: 0,
        valid_to: 100,
    }
}

fn utc() -> UtcReference {
    UtcReference {
        clock: key(5),
        source: Source::Gnss,
        sync_state: SyncState::Synchronised,
        bound: 100,
        valid_from: 0,
        valid_to: 100,
        tick_fs: 1_000_000,
        scale: Scale::Tai,
        origin: 0,
        origin_scale_ns: 2_000_000_000_000_000_000,
        leap_table: 69,
        transform_uncertainty_ns: 0,
    }
}

/// A journal of both types reads each as its own, and skips a type it
/// does not know.
#[test]
fn a_journal_of_both_record_types_reads_each_as_its_own() {
    let mut unknown = utc().encode().unwrap();
    unknown[0] = (unknown[0] & !0xff) | 7;
    let journal = [
        calibration().encode().unwrap(),
        utc().encode().unwrap(),
        unknown,
    ];
    let (records, skipped) = ClockRecord::decode_all(&journal).unwrap();
    assert_eq!(
        records,
        [
            ClockRecord::Calibration(calibration()),
            ClockRecord::UtcReference(utc())
        ]
    );
    assert_eq!(skipped, 1);
}

/// A refused record names its index and its type's error.
#[test]
fn a_refused_record_names_its_index() {
    let mut bad = utc().encode().unwrap();
    bad[13] = 0; // no leap table
    let journal = [calibration().encode().unwrap(), bad];
    assert_eq!(
        ClockRecord::decode_all(&journal).unwrap_err(),
        (
            1,
            ClockRecordError::UtcReference(UtcReferenceError::LeapTable)
        )
    );
}
