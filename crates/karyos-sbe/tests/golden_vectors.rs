// SPDX-License-Identifier: Apache-2.0

//! SBE 1.0 golden vectors (SPEC §13, "SBE interoperability"; karyos#646):
//! the codecs IronSBE generates from Real Logic's public example schemas
//! encode the reference tool's bytes exactly, version 0 and 1 (repeating
//! groups, a nested group, variable data, enums, a set, composites,
//! constants); [`karyos_sbe::decode_car`] reads both back in place; and a
//! schema version this build does not know is refused with a typed error,
//! never read as a known one. See `vectors/README.md` for the reference
//! tool, its version and how to reproduce the bytes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

mod common;

use karyos_sbe::car::v1::{BooleanType, BoostType, Model};
use karyos_sbe::{FrameError, car, decode_car};

#[test]
fn version_0_encodes_the_reference_tools_bytes() {
    let expected = common::vector(include_str!("vectors/car-v0.hex"));
    let mut buf = [0u8; 512];
    let len = encode_car!(car::v0, &mut buf, |_: &mut car::v0::CarEncoder<'_>| {});
    assert_eq!(len, 207);
    assert_eq!(&buf[..len], expected.as_slice());
}

#[test]
fn version_1_encodes_the_reference_tools_bytes() {
    let expected = common::vector(include_str!("vectors/car-v1.hex"));
    let mut buf = [0u8; 512];
    let len = encode_car!(car::v1, &mut buf, |car: &mut car::v1::CarEncoder<'_>| {
        car.set_uuid(&common::uuid()).set_cup_holder_count(5);
    });
    assert_eq!(len, 224);
    assert_eq!(&buf[..len], expected.as_slice());
}

/// Checks every field both versions share.
fn check_car(car: &car::v1::CarDecoder<'_>) {
    assert_eq!(car.serial_number(), 1234);
    assert_eq!(car.model_year(), 2013);
    assert_eq!(car.available(), BooleanType::T);
    assert_eq!(car.code(), Model::A);
    assert_eq!(car.discounted_model(), Model::C, "a constant field");
    assert_eq!(car.some_numbers(), common::some_numbers().as_slice());
    assert_eq!(car.vehicle_code(), b"abcdef");
    let extras = car.extras();
    assert!(!extras.is_sun_roof());
    assert!(extras.is_sports_pack());
    assert!(extras.is_cruise_control());
    let engine = car.engine();
    assert_eq!(engine.capacity(), 2000);
    assert_eq!(engine.num_cylinders(), 4);
    assert_eq!(engine.max_rpm(), 9000, "a constant member");
    assert_eq!(engine.manufacturer_code(), b"123");
    assert_eq!(engine.efficiency(), 35);
    assert_eq!(engine.booster_enabled(), BooleanType::T);
    assert_eq!(engine.booster().boost_type(), BoostType::NITROUS);
    assert_eq!(engine.booster().horse_power(), 200);
    let fuel: Vec<_> = car
        .fuel_figures()
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| (e.speed(), e.mpg(), e.usage_description().unwrap().to_vec()))
        .collect();
    assert_eq!(
        fuel,
        common::FUEL
            .iter()
            .map(|(s, m, u)| (*s, *m, u.to_vec()))
            .collect::<Vec<_>>()
    );
    let perf: Vec<_> = car
        .performance_figures()
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| {
            let accelerations: Vec<_> = e
                .acceleration()
                .unwrap()
                .map(|a| a.unwrap())
                .map(|a| (a.mph(), a.seconds()))
                .collect();
            (e.octane_rating(), accelerations)
        })
        .collect();
    assert_eq!(
        perf,
        common::PERFORMANCE
            .iter()
            .map(|(o, a)| (*o, a.to_vec()))
            .collect::<Vec<_>>()
    );
    assert_eq!(car.manufacturer().unwrap(), b"Honda");
    assert_eq!(car.model().unwrap(), b"Civic VTi");
    assert_eq!(car.activation_code().unwrap(), b"abcdef");
}

#[test]
fn both_versions_decode_in_place() {
    let v1 = common::vector(include_str!("vectors/car-v1.hex"));
    let car = decode_car(&v1).unwrap();
    assert_eq!(car.acting_version(), 1);
    check_car(&car);
    assert_eq!(car.uuid(), Some(common::uuid().as_slice()));
    assert_eq!(car.cup_holder_count(), Some(5));
    assert_eq!(car.encoded_length().unwrap(), v1.len());

    // A version 0 message: the fields version 1 added are absent.
    let v0 = common::vector(include_str!("vectors/car-v0.hex"));
    let car = decode_car(&v0).unwrap();
    assert_eq!(car.acting_version(), 0);
    check_car(&car);
    assert_eq!(car.uuid(), None);
    assert_eq!(car.cup_holder_count(), None);
    assert_eq!(car.encoded_length().unwrap(), v0.len());
}

/// The message header's `version` field, little-endian at byte 6.
fn with_version(frame: &[u8], version: u16) -> Vec<u8> {
    let mut frame = frame.to_vec();
    frame[6..8].copy_from_slice(&version.to_le_bytes());
    frame
}

#[test]
fn an_unknown_schema_version_is_refused_not_reinterpreted() {
    let v1 = common::vector(include_str!("vectors/car-v1.hex"));
    // The next version, the largest, and one whose block would still fit:
    // each is refused before any field is read, whatever its bytes say.
    for version in [2, 7, u16::MAX] {
        assert_eq!(
            decode_car(&with_version(&v1, version)).err(),
            Some(FrameError::UnknownVersion { version }),
            "version {version}"
        );
    }
    // The known versions of the same bytes still decode.
    assert!(decode_car(&with_version(&v1, 1)).is_ok());
}

#[test]
fn another_schema_or_template_and_a_short_frame_are_refused() {
    let v0 = common::vector(include_str!("vectors/car-v0.hex"));
    let mut other_schema = v0.clone();
    other_schema[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        decode_car(&other_schema).err(),
        Some(FrameError::UnknownSchema { schema_id: 2 })
    );
    let mut other_template = v0.clone();
    other_template[2..4].copy_from_slice(&9u16.to_le_bytes());
    assert_eq!(
        decode_car(&other_template).err(),
        Some(FrameError::UnknownTemplate { template_id: 9 })
    );
    assert_eq!(
        decode_car(&v0[..7]).err(),
        Some(FrameError::Truncated { length: 7 })
    );
    // A header that promises more than the frame holds.
    assert!(matches!(
        decode_car(&v0[..20]).err(),
        Some(FrameError::Decode(_))
    ));
}
