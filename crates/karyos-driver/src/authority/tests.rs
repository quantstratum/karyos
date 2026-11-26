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
        "a00000000100200004400200feffffffe90300000403020194776655443322115a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a23e1287f01810dc8de74cadaba317d27f7b92da8b85b6909759bfdbcca61786edf4917329b2bdd213aa43d2f13955fc9d1b7b93b4cd993536d05a5f9d0008101",
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

/// RFC 8032 section 7.1, TEST 1 to TEST 3 (gate H5): the authority signer
/// derives each public key and signature, and strict verification accepts
/// each signature and refuses it for another message.
#[test]
fn the_rfc_8032_vectors_sign_and_verify() {
    let cases = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];
    for (seed, public, message, signature) in cases {
        let signer = Ed25519Signer::from_seed(&hex(seed).try_into().unwrap());
        let public: [u8; KEY_LEN] = hex(public).try_into().unwrap();
        let verifier = Ed25519Verifier::from_bytes(&public).unwrap();
        assert_eq!(signer.verifier(), verifier);
        let message = hex(message);
        let signature: [u8; SIGNATURE_LEN] = hex(signature).try_into().unwrap();
        assert_eq!(signer.sign(&message), signature);
        assert!(verifier.verify(&message, &signature));
        let mut other = message.clone();
        other.push(0);
        assert!(!verifier.verify(&other, &signature));
    }
}
