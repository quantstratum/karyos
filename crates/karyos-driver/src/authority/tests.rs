// SPDX-License-Identifier: Apache-2.0

use super::*;
use karyos_protocol::protection::Rejection;
use karyos_protocol::protection::signed::{
    OpenedSigned, SignedBinding, SignedDomain, open_signed, seal_signed,
};

/// `ed25519_seed` and `ed25519_public` of `quantstratum-docs:
/// karyos/evaluations/wire-auth-profile-v1/results/envelope-vectors.json`.
const SEED: [u8; 32] = [0x11; 32];
const PUBLIC: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

/// Its two `ed25519` cases: sequence and datagram. A second implementation
/// (OpenSSL) reproduced both.
const VECTORS: [(u64, &str); 2] = [
    (
        1_234_605_616_436_508_564,
        "a00000000100200004400200feffffffe90300000403020194776655443322115a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a23e1287f01810dc8de74cadaba317d27f7b92da8b85b6909759bfdbcca61786edf4917329b2bdd213aa43d2f13955fc9d1b7b93b4cd993536d05a5f9d0008101",
    ),
    (
        1_234_605_616_436_508_565,
        "a00000000100200004400200feffffffe903000004030201957766554433221100070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b98f422a41f16c05a7254dc52102721b284b7fd6f45fc03113679a85f7ae49c0f81f5ceffe7a0bcb2bd258ac2976a747460e46f365e7edbf942bfc4b01a92def0d",
    ),
];

const BINDING: SignedBinding = SignedBinding {
    domain: SignedDomain::Guard,
    party_epoch: 0,
    session_id: -2,
    stream_id: 1001,
    key_id: 0x0102_0304,
};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_vectors_verify_and_reseal_byte_for_byte() {
    let signer = Ed25519Signer::from_seed(&SEED);
    let public: [u8; 32] = hex(PUBLIC).try_into().unwrap();
    let verifier = Ed25519Verifier::from_bytes(&public).unwrap();
    assert_eq!(signer.verifier(), verifier);
    for (seq, text) in VECTORS {
        let datagram = hex(text);
        assert_eq!(
            open_signed(&datagram, &BINDING, &verifier),
            Ok(OpenedSigned {
                start: 32,
                body: 64,
                seq
            })
        );
        let mut out = vec![0_u8; datagram.len()];
        out[..64].copy_from_slice(&datagram[32..96]);
        assert_eq!(
            seal_signed(&mut out, 64, &BINDING, seq, &signer),
            Ok(datagram.len())
        );
        assert_eq!(out, datagram);
    }
}

#[test]
fn a_flipped_body_or_signature_bit_and_another_key_are_refused() {
    let verifier = Ed25519Signer::from_seed(&SEED).verifier();
    let good = hex(VECTORS[0].1);
    for at in 24..good.len() {
        for bit in [0x01_u8, 0x80] {
            let mut datagram = good.clone();
            datagram[at] ^= bit;
            assert_eq!(
                open_signed(&datagram, &BINDING, &verifier),
                Err(Rejection::Tag),
                "byte {at}"
            );
        }
    }
    let other = Ed25519Signer::from_seed(&[0x22; 32]).verifier();
    assert_eq!(open_signed(&good, &BINDING, &other), Err(Rejection::Tag));
}

#[test]
fn the_key_loader_refuses_non_canonical_and_small_order_keys() {
    // The identity point (small order), canonical encoding.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    assert_eq!(
        Ed25519Verifier::from_bytes(&identity),
        Err(AuthorityKeyError::WeakKey)
    );
    // y = p + 1, a non-canonical encoding of the identity point
    // (ADR-0086 evidence E-5, `strict-a`).
    let mut non_canonical = [0xFF_u8; 32];
    non_canonical[0] = 0xEE;
    non_canonical[31] = 0x7F;
    assert_eq!(
        Ed25519Verifier::from_bytes(&non_canonical),
        Err(AuthorityKeyError::NonCanonical)
    );
}

#[test]
fn a_signature_with_a_non_canonical_s_is_refused() {
    let signer = Ed25519Signer::from_seed(&SEED);
    let verifier = signer.verifier();
    let mut datagram = hex(VECTORS[0].1);
    // Add the group order L to S (bytes 32 to 63 of the signature), which
    // keeps the equation but makes S non-canonical.
    const L: [u8; 32] = [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let s = datagram.len() - 32;
    let mut carry = 0_u16;
    for (index, limb) in L.iter().enumerate() {
        let sum = u16::from(datagram[s + index]) + u16::from(*limb) + carry;
        datagram[s + index] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    assert_eq!(
        open_signed(&datagram, &BINDING, &verifier),
        Err(Rejection::Tag)
    );
}
