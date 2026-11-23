// SPDX-License-Identifier: Apache-2.0

//! A steady cycle of the SBE feed adapter allocates nothing (karyos#647):
//! framing each message by its SBE header, reading its sequence in place,
//! arbitrating two lines with duplicates and a repaired hole, and decoding
//! each delivered message in place, over a counting global allocator.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

mod common;

use karyos_sbe::adapter::{SbeEvent, SbeFeed, SbeSchema, SbeSequence};
use karyos_sbe::feed::{ArbiterConfig, Identity, Line, Start};
use karyos_sbe::{CAR_SCHEMA_ID, CAR_SCHEMA_VERSION, decode_car};
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct BySerial;

impl SbeSequence for BySerial {
    fn identity(&self, _: &ironsbe_core::header::MessageHeader, frame: &[u8]) -> Option<Identity> {
        decode_car(frame).ok().map(|car| Identity {
            epoch: 1,
            sequence: car.serial_number(),
        })
    }

    fn complete(&self, _: &ironsbe_core::header::MessageHeader, frame: &[u8]) -> bool {
        decode_car(frame).is_ok()
    }
}

#[test]
fn a_steady_cycle_allocates_nothing() {
    let mut feed = SbeFeed::new(
        SbeSchema {
            schema_id: CAR_SCHEMA_ID,
            max_version: CAR_SCHEMA_VERSION,
        },
        BySerial,
        ArbiterConfig {
            capacity: 64,
            max_message_length: 512,
            skew_window: 1_000_000,
            start: Start::AtFirst,
        },
    )
    .unwrap();
    let base = common::vector(include_str!("vectors/car-v1.hex"));
    let frames: Vec<Vec<u8>> = (1..=200u64)
        .map(|sequence| {
            let mut frame = base.clone();
            frame[8..16].copy_from_slice(&sequence.to_le_bytes());
            frame
        })
        .collect();
    let (delivered, allocations) = count(|| {
        let mut delivered = 0u64;
        let mut sum = 0u64;
        for (at, frame) in frames.iter().enumerate() {
            let now = at as u64;
            // Line A skips every tenth message, which line B fills; B
            // brings every message after A, a duplicate otherwise.
            if at % 10 != 5 {
                feed.push(Line::A, frame, now, |event| {
                    if let SbeEvent::Message { frame, .. } = event {
                        delivered += 1;
                        sum += decode_car(frame).unwrap().serial_number();
                    }
                });
            }
            feed.push(Line::B, frame, now, |event| {
                if let SbeEvent::Message { frame, .. } = event {
                    delivered += 1;
                    sum += decode_car(frame).unwrap().serial_number();
                }
            });
        }
        assert!(sum > 0);
        delivered
    });
    assert_eq!(delivered, 200);
    assert_eq!(allocations, 0, "a steady cycle allocated");
    assert_eq!(feed.counters().refused, 0);
}
