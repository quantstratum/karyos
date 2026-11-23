// SPDX-License-Identifier: Apache-2.0

//! Decoding in place allocates nothing (SPEC §13, "SBE interoperability";
//! karyos#646): framing a golden vector and reading every field, group
//! entry and variable field of it, over a counting global allocator.
//! Encoding into a caller's buffer allocates nothing either.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

mod common;

use karyos_sbe::{car, decode_car};
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Reads every part of `frame` as a `Car`; returns a checksum so nothing
/// is optimised away.
fn read_all(frame: &[u8]) -> u64 {
    let car = decode_car(frame).unwrap();
    let mut sum = car.serial_number() + u64::from(car.model_year());
    sum += u64::from(car.engine().capacity());
    sum += u64::from(car.engine().booster().horse_power());
    sum += car.some_numbers().len() as u64 + car.vehicle_code().len() as u64;
    for entry in car.fuel_figures().unwrap() {
        let entry = entry.unwrap();
        sum += u64::from(entry.speed()) + entry.usage_description().unwrap().len() as u64;
    }
    for entry in car.performance_figures().unwrap() {
        let entry = entry.unwrap();
        sum += u64::from(entry.octane_rating());
        for acceleration in entry.acceleration().unwrap() {
            sum += u64::from(acceleration.unwrap().mph());
        }
    }
    sum += car.manufacturer().unwrap().len() as u64;
    sum += car.model().unwrap().len() as u64;
    sum += car.activation_code().unwrap().len() as u64;
    sum += u64::from(car.cup_holder_count().unwrap_or(0));
    sum
}

#[test]
fn decoding_in_place_allocates_nothing() {
    for hex in [
        include_str!("vectors/car-v0.hex"),
        include_str!("vectors/car-v1.hex"),
    ] {
        let frame = common::vector(hex);
        let (sum, allocations) = count(|| read_all(&frame));
        assert!(sum > 0);
        assert_eq!(allocations, 0, "decoding allocated");
    }
}

#[test]
fn encoding_into_a_buffer_allocates_nothing() {
    let mut buf = [0u8; 512];
    let (len, allocations) = count(|| {
        encode_car!(car::v1, &mut buf, |car: &mut car::v1::CarEncoder<'_>| {
            car.set_uuid(&common::uuid()).set_cup_holder_count(5);
        })
    });
    assert_eq!(len, 224);
    assert_eq!(allocations, 0, "encoding allocated");
}
