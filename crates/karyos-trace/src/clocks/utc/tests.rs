// SPDX-License-Identifier: Apache-2.0

//! ADR-0090's vectors U-1 to U-8, byte for byte, and the conversion.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;
use crate::clocks::Calibration;

/// The vectors' bytes, as design/trace-clocks.md publishes them.
const VECTORS: [(&str, &str); 8] = [
    (
        "U-1",
        "0200010100000000010000000000000000000000000000000200000000000000030000000000000004000000000000006400000000000000e803000000000000d00700000000000040420f00000000000100000000000000e8030000000000000000c84e676dc11b45000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "U-2",
        "0200020200000000010000000000000000000000000000000200000000000000030000000000000004000000000000006400000000000000e803000000000000d00700000000000040420f00000000000200000000000000e8030000000000000000c84e676dc11b45000000000000000000000000000000010000000000000000000000000000000000000000000000",
    ),
    (
        "U-3",
        "0200020200000000010000000000000000000000000000000200000000000000030000000000000004000000000000006400000000000000e803000000000000d00700000000000040420f00000000000300000000000000e8030000000000000000c84e676dc11b450000000000000000004f91944e0000010000000000000000000000000000000000000000000000",
    ),
    (
        "U-4",
        "0200010100000000010000000000000000000000000000000200000000000000030000000000000004000000000000006400000000000000e803000000000000d00700000000000040420f00000000000100000000000000e8030000000000000000c84e676dc11b00000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "U-5",
        "0200010100000000010000000000000000000000000000000200000000000000030000000000000004000000000000006400000000000000e803000000000000d00700000000000040420f00000000000100000000000000e8030000000000000000c84e676dc11b45000000000000000000000000000000000000000000000000000000000000000100000000000000",
    ),
    (
        "U-6",
        "0100000000000000010000000000000000000000000000000200000000000000030000000000000004000000000000006400000000000000e803000000000000d00700000000000040420f00000000000100000000000000e8030000000000000000c84e676dc11b45000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "U-7",
        "02000101000000000100000000000000000000000000000002000000000000000300000000000000040000000000000064000000000000000000000000000000005ed0b20000000040420f000000000001000000000000000000000000000000009e5b2e68ded61945000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "U-8",
        "0200020200000000010000000000000000000000000000000200000000000000030000000000000004000000000000006400000000000000e803000000000000d00700000000000040420f00000000000300000000000000e8030000000000000000c84e676dc11b450000000000000000004f91944e000001000000000000000080a7484a2700000000000000000000",
    ),
];

fn words(name: &str) -> [u64; UTC_REFERENCE_WORDS] {
    let hex = VECTORS.iter().find(|(n, _)| *n == name).unwrap().1;
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut out = [0u64; UTC_REFERENCE_WORDS];
    for (word, chunk) in out.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    out
}

fn u1() -> UtcReference {
    UtcReference {
        clock: ClockKey {
            observer: ObserverId {
                driver: [1, 0],
                journal: 2,
            },
            domain: 3,
            epoch: 4,
        },
        source: Source::Gnss,
        sync_state: SyncState::Synchronised,
        bound: 100,
        valid_from: 1000,
        valid_to: 2000,
        tick_fs: 1_000_000,
        scale: Scale::Tai,
        origin: 1000,
        origin_scale_ns: 2_000_000_000_000_000_000,
        leap_table: 69,
        transform_uncertainty_ns: 0,
    }
}

fn u2() -> UtcReference {
    UtcReference {
        source: Source::Ptp,
        sync_state: SyncState::Holdover,
        scale: Scale::UtcStepped,
        transform_uncertainty_ns: 1,
        ..u1()
    }
}

fn u3() -> UtcReference {
    UtcReference {
        scale: Scale::UtcSmeared {
            smear_ns: 86_400_000_000_000,
            after_ns: 0,
        },
        ..u2()
    }
}

fn u7() -> UtcReference {
    UtcReference {
        valid_from: 0,
        valid_to: 3_000_000_000,
        origin: 0,
        origin_scale_ns: 1_861_920_035_000_000_000,
        ..u1()
    }
}

#[test]
fn the_accepted_vectors_decode_and_encode_exactly() {
    let centred = UtcReference {
        scale: Scale::UtcSmeared {
            smear_ns: 86_400_000_000_000,
            after_ns: 43_200_000_000_000,
        },
        ..u2()
    };
    for (name, record) in [
        ("U-1", u1()),
        ("U-2", u2()),
        ("U-3", u3()),
        ("U-7", u7()),
        ("U-8", centred),
    ] {
        assert_eq!(UtcReference::decode(&words(name)), Ok(record), "{name}");
        assert_eq!(record.encode().unwrap(), words(name), "{name}");
    }
}

#[test]
fn the_refused_vectors_name_their_refusal() {
    assert_eq!(
        UtcReference::decode(&words("U-4")),
        Err(UtcReferenceError::LeapTable)
    );
    assert_eq!(
        UtcReference::decode(&words("U-5")),
        Err(UtcReferenceError::Reserved)
    );
    assert_eq!(
        UtcReference::decode(&words("U-6")),
        Err(UtcReferenceError::RecordType { value: 1 })
    );
    // U-6 is a valid calibration.
    assert!(Calibration::decode(&words("U-6")).is_ok());
    // A smear on a scale that has none, and word 10's high bits.
    let mut smear = words("U-1");
    smear[14] = 1;
    assert_eq!(UtcReference::decode(&smear), Err(UtcReferenceError::Smear));
    let mut high = words("U-1");
    high[10] |= 1 << 8;
    assert_eq!(
        UtcReference::decode(&high),
        Err(UtcReferenceError::Reserved)
    );
    let mut code = words("U-1");
    code[0] |= 5 << 16;
    assert!(matches!(
        UtcReference::decode(&code),
        Err(UtcReferenceError::Code {
            field: "source",
            ..
        })
    ));
}

#[test]
fn u7_crosses_the_leap_second_of_2017() {
    let record = u7();
    assert_eq!(record.utc(0), Some(1_861_919_999_000_000_000));
    assert_eq!(record.utc(1_500_000_000), None);
    assert_eq!(record.utc(2_000_000_000), Some(1_861_920_000_000_000_000));
    assert_eq!(record.utc(3_000_000_000), Some(1_861_920_001_000_000_000));
    // Outside the validity.
    assert_eq!(record.utc(3_000_000_001), None);
}

#[test]
fn the_bound_rounds_up_and_adds_the_transformation() {
    let record = UtcReference {
        bound: 3,
        tick_fs: 333_334,
        transform_uncertainty_ns: 5,
        ..u1()
    };
    // 3 * 333 334 fs = 1.000002 ns, rounded up to 2.
    assert_eq!(record.bound_ns(), Some(7));
    assert_eq!(
        UtcReference {
            bound: u64::MAX,
            tick_fs: u64::MAX,
            ..u1()
        }
        .bound_ns(),
        None
    );
}

/// A stepped clock repeats the second before a leap: no evidence there.
#[test]
fn a_stepped_reading_before_a_leap_is_ambiguous() {
    let leap = 1_861_920_000_000_000_000_u64;
    let record = UtcReference {
        valid_from: 0,
        valid_to: u64::MAX,
        origin: 0,
        origin_scale_ns: 0,
        ..u2()
    };
    assert_eq!(
        record.utc(leap - 1_000_000_001),
        Some(i128::from(leap) - 1_000_000_001)
    );
    assert_eq!(record.utc(leap - 1), None);
    assert_eq!(record.utc(leap), Some(i128::from(leap)));
}

/// A smear meets UTC at both ends, and a centred one maps its middle to
/// the leap.
#[test]
fn a_smear_meets_utc_at_both_ends() {
    let leap = 1_861_920_000_000_000_000_i128;
    let width = 86_400_000_000_000_i128;
    for after in [0, width / 2] {
        let record = UtcReference {
            valid_from: 0,
            valid_to: u64::MAX,
            origin: 0,
            origin_scale_ns: 0,
            scale: Scale::UtcSmeared {
                smear_ns: width as u64,
                after_ns: after as u64,
            },
            ..u2()
        };
        let start = leap - (width - after);
        let at = |r: i128| record.utc(u64::try_from(r).unwrap());
        assert_eq!(at(start - 1), Some(start - 1));
        assert_eq!(at(start), Some(start));
        assert_eq!(at(start + width), Some(start + width));
        // Monotone across the smear, outside the inserted second.
        let mut last = start;
        for step in 1..1000 {
            let r = start + width * step / 1000;
            if let Some(u) = at(r) {
                assert!(u >= last, "after {after} at {r}");
                last = u;
            }
        }
    }
}
