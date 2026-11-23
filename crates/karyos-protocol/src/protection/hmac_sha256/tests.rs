// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::protection::{Protection, Rejection, Verdict};
use karyos_sys::alloc_count::count;
use proptest::prelude::*;

/// The `hmac_key` of `quantstratum-docs:
/// karyos/evaluations/wire-auth-profile-v1/results/envelope-vectors.json`.
const KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// The binding of those vectors.
const BINDING: Binding = Binding {
    domain: Domain::Data,
    party_epoch: 0,
    session_id: -2,
    stream_id: 1001,
    key_id: 0x0102_0304,
};

/// The `hmac-sha256-t16` cases of that file: datagram, inner bytes, sequence.
/// A second implementation (Python `hmac`) reproduced every one of them.
const VECTORS: [(&str, usize, u64); 4] = [
    (
        "300000000100200001100100feffffffe9030000040302018877665544332211cbd62ed5bbbc270f5004178ef12a139e",
        0,
        1234605616436508552,
    ),
    (
        "500000000100200001100100feffffffe9030000040302018977665544332211a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a571c41c683232eee160480dec8d62f110",
        32,
        1234605616436508553,
    ),
    (
        "700000000100200001100100feffffffe9030000040302018a7766554433221100070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b990289d63c94a78d551d7328e8c57fcc7",
        64,
        1234605616436508554,
    ),
    (
        "500500000100200001100100feffffffe9030000040302018b7766554433221105121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cddae7f4010e1b2835424f5c697683909daab7c4d1deebf805121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cddae7f4010e1b2835424f5c697683909daab7c4d1deebf805121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cddae7f4010e1b2835424f5c697683909daab7c4d1deebf805121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cddae7f4010e1b2835424f5c697683909daab7c4d1deebf805121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cddae7f4010e1b2835424f5c697683909daab7c4d1deebf805121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b984300253e7d8f423758d1fe353466f946",
        1312,
        1234605616436508555,
    ),
];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2).unwrap_or("00"), 16).unwrap_or(0))
        .collect()
}

fn profile() -> HmacSha256 {
    HmacSha256::new(&KEY, BINDING, 0).unwrap_or_else(|_| unreachable!())
}

fn sealed(frames: &[u8], seq: u64) -> Vec<u8> {
    let mut datagram = vec![0_u8; frames.len() + HEADER_LEN + TAG_LEN];
    if let Some(slot) = datagram.get_mut(..frames.len()) {
        slot.copy_from_slice(frames);
    }
    let total = profile().seal_with(&mut datagram, frames.len(), seq);
    assert_eq!(total, Ok(datagram.len()));
    datagram
}

#[test]
fn the_independent_vectors_open_and_reseal_byte_for_byte() {
    for (text, inner, seq) in VECTORS {
        let datagram = hex(text);
        let opened = profile().open_envelope(&datagram);
        assert_eq!(
            opened,
            Ok(Opened {
                start: HEADER_LEN,
                frames: inner,
                seq
            })
        );
        let frames = &datagram[HEADER_LEN..HEADER_LEN + inner];
        assert_eq!(sealed(frames, seq), datagram, "seal reproduces the vector");
    }
}

#[test]
fn seal_advances_the_sequence_and_refuses_exhaustion() {
    let profile = HmacSha256::new(&KEY, BINDING, u64::MAX - 1).unwrap_or_else(|_| unreachable!());
    let mut datagram = [0_u8; 64];
    assert_eq!(profile.seal(&mut datagram, 8), Ok(8 + HEADER_LEN + TAG_LEN));
    assert_eq!(profile.next_seq(), u64::MAX);
    let before = datagram;
    let refused = profile.seal(&mut datagram, 8);
    assert_eq!(refused.map_err(|error| error.needed), Err(usize::MAX));
    assert_eq!(datagram, before, "an exhausted seal writes nothing");
    assert_eq!(profile.next_seq(), u64::MAX);
}

#[test]
fn a_buffer_without_room_for_the_envelope_is_refused() {
    let mut datagram = [0_u8; 40];
    assert_eq!(
        profile().seal(&mut datagram, 8),
        Err(SealError {
            needed: 56,
            available: 40
        })
    );
}

#[test]
fn an_empty_key_is_refused() {
    assert_eq!(HmacSha256::new(&[], BINDING, 0).map(|_| ()), Err(EmptyKey));
}

/// One test per failure mode: each field mutation is rejected with its
/// reason, before the tag.
#[test]
fn every_field_mismatch_fails_closed_with_its_reason() {
    let good = sealed(&[9_u8; 24], 77);
    let cases: [(usize, u8, Rejection); 11] = [
        (0, 1, Rejection::Length),
        (4, 1, Rejection::Version),
        (5, 1, Rejection::Flags),
        (6, 1, Rejection::FrameType),
        (8, 1, Rejection::Profile),
        (9, 1, Rejection::TagLength),
        (10, 1, Rejection::Domain),
        (11, 1, Rejection::Epoch),
        (12, 1, Rejection::Binding),
        (16, 1, Rejection::Binding),
        (20, 1, Rejection::Key),
    ];
    for (at, flip, reason) in cases {
        let mut datagram = good.clone();
        datagram[at] ^= flip;
        assert_eq!(profile().open_envelope(&datagram), Err(reason), "byte {at}");
        assert_eq!(profile().open(&datagram), Verdict::Reject(reason));
    }
}

#[test]
fn sequence_frames_and_tag_are_covered_by_the_tag() {
    let good = sealed(&[9_u8; 24], 77);
    for at in (24..good.len()).chain([good.len() - 1]) {
        let mut datagram = good.clone();
        datagram[at] ^= 0x80;
        assert_eq!(
            profile().open_envelope(&datagram),
            Err(Rejection::Tag),
            "byte {at}"
        );
    }
}

#[test]
fn short_truncated_and_extended_datagrams_are_rejected() {
    let good = sealed(&[9_u8; 24], 77);
    assert_eq!(
        profile().open_envelope(&good[..HEADER_LEN + TAG_LEN - 1]),
        Err(Rejection::Short)
    );
    assert_eq!(
        profile().open_envelope(&good[..good.len() - 1]),
        Err(Rejection::Length)
    );
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(profile().open_envelope(&longer), Err(Rejection::Length));
    // A consistent truncation: the length is rewritten, so only the tag rejects.
    let mut cut = good[..good.len() - 1].to_vec();
    let length = i32::try_from(cut.len()).unwrap_or(0).to_le_bytes();
    cut[..4].copy_from_slice(&length);
    assert_eq!(profile().open_envelope(&cut), Err(Rejection::Tag));
}

#[test]
fn a_wrong_key_or_another_domain_key_does_not_verify() {
    let good = sealed(&[9_u8; 24], 77);
    let mut other = KEY;
    other[0] ^= 1;
    let wrong = HmacSha256::new(&other, BINDING, 0).unwrap_or_else(|_| unreachable!());
    assert_eq!(wrong.open_envelope(&good), Err(Rejection::Tag));
    let sm = Binding {
        domain: Domain::ReceiverToPublisher,
        ..BINDING
    };
    let sm = HmacSha256::new(&KEY, sm, 0).unwrap_or_else(|_| unreachable!());
    assert_eq!(sm.open_envelope(&good), Err(Rejection::Domain));
}

#[test]
fn seal_and_open_allocate_nothing() {
    let profile = profile();
    let mut datagram = [0_u8; 1408];
    let (_, seen) = count(|| {
        let total = profile.seal(&mut datagram, 1360).unwrap_or(0);
        let _ = profile.open(datagram.get(..total).unwrap_or_default());
    });
    assert_eq!(seen, 0);
}

proptest! {
    /// Any frames round trip, and any single bit flip is rejected.
    #[test]
    fn round_trip_and_bit_flips(frames in proptest::collection::vec(any::<u8>(), 0..1400), seq in any::<u64>(), bit in any::<usize>()) {
        let datagram = sealed(&frames, seq);
        prop_assert_eq!(
            profile().open_envelope(&datagram),
            Ok(Opened { start: HEADER_LEN, frames: frames.len(), seq })
        );
        let mut flipped = datagram.clone();
        let at = bit % (flipped.len() * 8);
        flipped[at / 8] ^= 1 << (at % 8);
        prop_assert!(profile().open_envelope(&flipped).is_err());
    }
}
