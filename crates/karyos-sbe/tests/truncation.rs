// SPDX-License-Identifier: Apache-2.0

//! Truncation of an SBE frame (karyos#646, Codex review of #1197): a frame
//! cut anywhere, in the header, the fixed block, a repeating group, a
//! nested group or a variable data field, is refused by
//! [`karyos_sbe::decode_car`]; the whole frame is accepted. Both schema
//! versions, every strict prefix, and the same as a property.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

mod common;

use karyos_sbe::decode_car;
use proptest::prelude::*;

fn versions() -> [Vec<u8>; 2] {
    [
        common::vector(include_str!("vectors/car-v0.hex")),
        common::vector(include_str!("vectors/car-v1.hex")),
    ]
}

#[test]
fn every_strict_prefix_is_refused_and_the_whole_frame_accepted() {
    for frame in versions() {
        assert!(decode_car(&frame).is_ok(), "{} bytes", frame.len());
        for cut in 0..frame.len() {
            assert!(
                decode_car(&frame[..cut]).is_err(),
                "a frame of {} bytes cut at {cut} was accepted",
                frame.len()
            );
        }
    }
}

proptest! {
    #[test]
    fn a_cut_frame_is_refused(version in 0usize..2, cut in any::<prop::sample::Index>()) {
        let frames = versions();
        let frame = &frames[version];
        let cut = cut.index(frame.len());
        prop_assert!(decode_car(&frame[..cut]).is_err(), "cut at {}", cut);
        prop_assert!(decode_car(frame).is_ok());
    }
}
