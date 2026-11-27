// SPDX-License-Identifier: Apache-2.0

//! Gate H7, constant time, for the Ed25519 authority of the
//! `authenticated` class (ADR-0086 section 8), on the shared harness of
//! `karyos-protocol` (`protection::timing`, included as
//! [`crate::timing`]).
//!
//! Review: [`Ed25519Verifier::verify`] is `VerifyingKey::verify_strict` of
//! `ed25519-dalek` 3.0.0. Every input of a verification is public (key,
//! message, signature); the secret-dependent operation is the authority's
//! signing, [`Ed25519Signer::sign`], whose scalar multiplication by the
//! secret scalar uses `curve25519-dalek`'s constant-time fixed-base table
//! lookups (`subtle` conditional selection), and whose final equation
//! check compares with `subtle::ConstantTimeEq`.
//!
//! The statistical tests are `#[ignore]`d. Gated (`|t|` below 4.5): a
//! signature of a fixed against a random message, the one operation on a
//! secret. Measured and not gated, because every input is public:
//! `verify_strict` computes `[S]B - [k]A` with `curve25519-dalek`'s
//! variable-time double-base multiplication, whose running time depends on
//! `S` and on `k = H(R || A || M)`, so a fixed against a random message
//! differs by design (|t| from 127 to 393 on xaskar); invalid signatures whose
//! `S` differs in its first against its last byte (both still below `L`);
//! and a valid against an invalid signature. Such a difference reveals
//! only bytes the sender chose or anyone can compute. A run counts as H7 evidence only if, in that same
//! run, the harness's A/A control (`timing::tests::h7_identical_classes_give_no_signal`)
//! is below 4.5.
//!
//! Command, on an otherwise idle host (`KARYOS_H7_SAMPLES` sets the samples
//! per class; 200 000 suffices at about 50 µs per operation):
//! `KARYOS_H7_SAMPLES=200000 cargo test -p karyos-driver --release --lib -- --ignored h7_ --nocapture --test-threads=1`

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use std::hint::black_box;

use super::*;
use crate::timing::{self, Class, Report, compare};

/// The message length: a signed SESSION_ABORT, label and header included.
const MESSAGE: usize = 20 + 32 + 88;

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[0x09; KEY_LEN])
}

fn message(class: Class, rng: &mut timing::Rng) -> [u8; MESSAGE] {
    let mut message = [0x5A_u8; MESSAGE];
    if class == Class::B {
        rng.fill(&mut message);
    }
    message
}

fn sign_fixed_against_random(samples: usize) -> Report {
    let signer = signer();
    compare(
        "Ed25519 sign, fixed against random message",
        0x4861,
        samples,
        message,
        |_| {},
        |message| black_box(signer.sign(black_box(message))) != [0; SIGNATURE_LEN],
    )
}

fn verify_fixed_against_random(samples: usize) -> Report {
    let signer = signer();
    let verifier = signer.verifier();
    compare(
        "Ed25519 verify_strict, valid, fixed against random message",
        0x4862,
        samples,
        |class, rng| {
            let message = message(class, rng);
            (message, signer.sign(&message))
        },
        |_| {},
        |(message, signature)| verifier.verify(black_box(message), black_box(signature)),
    )
}

fn verify_invalid_first_against_last(samples: usize) -> Report {
    let signer = signer();
    let verifier = signer.verifier();
    let message = [0x5A_u8; MESSAGE];
    let good = signer.sign(&message);
    compare(
        "Ed25519 verify_strict, invalid S, first byte against last byte",
        0x4863,
        samples,
        |class, _| {
            let mut bad = good;
            // Bit 0 of byte 32 and of byte 62: `S` stays below `L`
            // (2^252 + ...), whose top byte 63 is 0x10.
            match class {
                Class::A => bad[32] ^= 1,
                Class::B => bad[62] ^= 1,
            }
            bad
        },
        |_| {},
        |bad| !verifier.verify(black_box(&message), black_box(bad)),
    )
}

fn valid_against_invalid(samples: usize) -> Report {
    let signer = signer();
    let verifier = signer.verifier();
    let message = [0x5A_u8; MESSAGE];
    let good = signer.sign(&message);
    compare(
        "Ed25519 verify_strict, valid against invalid",
        0x4864,
        samples,
        |class, _| {
            let mut signature = good;
            if class == Class::B {
                signature[40] ^= 1;
            }
            (class, signature)
        },
        |_| {},
        |(class, signature)| {
            verifier.verify(black_box(&message), signature) == (*class == Class::A)
        },
    )
}

/// The comparisons that need no signature per slot (a debug build signs
/// slowly; the ignored run covers the other one).
#[test]
fn h7_every_comparison_gives_each_class_its_result() {
    for report in [
        sign_fixed_against_random(20),
        verify_invalid_first_against_last(20),
        valid_against_invalid(20),
    ] {
        assert_eq!(report.t.len(), timing::CROPS + 1, "{}", report.name);
    }
}

#[test]
#[ignore = "statistical timing test: run on an idle host, see the module documentation"]
fn h7_ed25519_timing() {
    let samples = timing::samples();
    for report in [
        verify_fixed_against_random(samples),
        verify_invalid_first_against_last(samples),
        valid_against_invalid(samples),
    ] {
        report.print();
    }
    sign_fixed_against_random(samples).assert_constant_time();
}
