// SPDX-License-Identifier: Apache-2.0

use super::*;
use karyos_sys::alloc_count::count;

/// The first `ed25519` case of `quantstratum-docs:
/// karyos/evaluations/wire-auth-profile-v1/results/envelope-vectors.json`:
/// domain 2, 64 body bytes of `0x5a`, reproduced by a second
/// implementation. The signature itself is checked in `karyos-driver`,
/// which holds the Ed25519 implementation.
const VECTOR: &str = "a00000000100200004400200feffffffe90300000403020194776655443322115a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a23e1287f01810dc8de74cadaba317d27f7b92da8b85b6909759bfdbcca61786edf4917329b2bdd213aa43d2f13955fc9d1b7b93b4cd993536d05a5f9d0008101";
const SEQ: u64 = 1_234_605_616_436_508_564;

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

/// Accepts exactly the vector's message and signature.
struct Expect {
    message: Vec<u8>,
    signature: [u8; SIGNATURE_LEN],
}

impl Expect {
    fn of_vector() -> Self {
        let datagram = hex(VECTOR);
        let split = datagram.len() - SIGNATURE_LEN;
        let mut message = LABEL.to_vec();
        message.extend_from_slice(&datagram[..split]);
        Self {
            message,
            signature: datagram[split..].try_into().unwrap(),
        }
    }
}

impl AuthorityVerifier for Expect {
    fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        message == self.message.as_slice() && signature == &self.signature
    }
}

impl AuthoritySigner for Expect {
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        assert_eq!(message, self.message.as_slice(), "the signed message");
        self.signature
    }
}

#[test]
fn the_vector_opens_and_reseals_byte_for_byte() {
    let datagram = hex(VECTOR);
    assert_eq!(
        open_signed(&datagram, &BINDING, &Expect::of_vector()),
        Ok(OpenedSigned {
            start: HEADER_LEN,
            body: 64,
            seq: SEQ
        })
    );
    let mut out = vec![0_u8; datagram.len()];
    out[..64].copy_from_slice(&datagram[HEADER_LEN..HEADER_LEN + 64]);
    assert_eq!(
        seal_signed(&mut out, 64, &BINDING, SEQ, &Expect::of_vector()),
        Ok(datagram.len())
    );
    assert_eq!(out, datagram);
}

#[test]
fn every_field_mismatch_fails_closed_before_the_signature() {
    let good = hex(VECTOR);
    let cases: [(usize, Rejection); 11] = [
        (0, Rejection::Length),
        (4, Rejection::Version),
        (5, Rejection::Flags),
        (6, Rejection::FrameType),
        (8, Rejection::Profile),
        (9, Rejection::TagLength),
        (10, Rejection::Domain),
        (11, Rejection::Epoch),
        (12, Rejection::Binding),
        (16, Rejection::Binding),
        (20, Rejection::Key),
    ];
    for (at, reason) in cases {
        let mut datagram = good.clone();
        datagram[at] ^= 1;
        assert_eq!(
            open_signed(&datagram, &BINDING, &Expect::of_vector()),
            Err(reason),
            "byte {at}"
        );
    }
    let abort = SignedBinding {
        domain: SignedDomain::SessionAbort,
        ..BINDING
    };
    assert_eq!(
        open_signed(&good, &abort, &Expect::of_vector()),
        Err(Rejection::Domain)
    );
}

#[test]
fn any_other_byte_is_left_to_the_signature() {
    let good = hex(VECTOR);
    for at in 24..good.len() {
        let mut datagram = good.clone();
        datagram[at] ^= 0x80;
        assert_eq!(
            open_signed(&datagram, &BINDING, &Expect::of_vector()),
            Err(Rejection::Tag),
            "byte {at}"
        );
    }
}

#[test]
fn short_and_oversized_datagrams_are_refused() {
    let good = hex(VECTOR);
    assert_eq!(
        open_signed(&good[..95], &BINDING, &Expect::of_vector()),
        Err(Rejection::Short)
    );
    let mut big = vec![0_u8; 400];
    assert_eq!(
        seal_signed(
            &mut big,
            MAX_BODY_LEN + 1,
            &BINDING,
            1,
            &Expect::of_vector()
        ),
        Err(SealError {
            needed: MAX_BODY_LEN + 1,
            available: MAX_BODY_LEN
        })
    );
}

#[test]
fn opening_allocates_nothing() {
    let datagram = hex(VECTOR);
    let verifier = Expect::of_vector();
    let (_, seen) = count(|| {
        let _ = open_signed(&datagram, &BINDING, &verifier);
    });
    assert_eq!(seen, 0);
}
