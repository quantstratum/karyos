// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::network::{Alias, Control, Identity, Lanes, Receiver};
use proptest::prelude::*;

/// The golden vectors of `quantstratum-docs:
/// karyos/design/authenticated-control-schemas.md` section 9, derived blind
/// by an independent session and identical to a second encoding.
const POSITIVE: [(&str, &str); 5] = [
    (
        "P-1",
        "3800000001001100010000000000000000000000000000000a000000000000000b0000000000000009000000000000008813000000000000",
    ),
    (
        "P-2",
        "5800000001001100020000000000000000000000000000000a000000000000000b00000000000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b14200000000000000c8c7c6c5c4c3c2c1d8d7d6d5d4d3d2d10000000000000000",
    ),
    (
        "P-3",
        "5800000001001100030000000000000000000000000000000a000000000000000b00000000000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b14200000000000000c8c7c6c5c4c3c2c1d8d7d6d5d4d3d2d10600000000000000",
    ),
    (
        "P-4",
        "58000000010012000100000078563412e903000000000000efcdab89674523011032547698badcfe070000000000000001000000000000000a000000000000000b0000000000000003000000000000000100000000000000",
    ),
    (
        "P-5",
        "78000000010013000102000078563412e903000000000000efcdab89674523011032547698badcfe07000000000000000100000000000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b1420000000000000003000000000000000010000000000000002000000000000000000000000000000000000000000000",
    ),
];

/// The negative vectors of section 9 with their first error.
const NEGATIVE: [(&str, ControlError, &str); 11] = [
    (
        "N-1",
        ControlError::InvalidValue,
        "3800000001001100010000000000000000000000000000000a000000000000000b0000000000000008000000000000008813000000000000",
    ),
    (
        "N-2",
        ControlError::InvalidValue,
        "3800000001001100010000000000000000000000000000000a000000000000000b0000000000000001000000000000008813000000000000",
    ),
    (
        "N-3",
        ControlError::InvalidIdentity,
        "38000000010011000100000000000000000000000000000000000000000000000b0000000000000009000000000000008813000000000000",
    ),
    (
        "N-4",
        ControlError::InvalidValue,
        "58000000010012000100000078563412e903000000000000efcdab89674523011032547698badcfe070000000000000001000000000000000a000000000000000b0000000000000003000000000000000000000000000000",
    ),
    (
        "N-5",
        ControlError::InvalidValue,
        "5800000001001100020000000000000000000000000000000a000000000000000b00000000000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b14200000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "N-6",
        ControlError::InvalidPosition,
        "78000000010013000102000078563412e903000000000000efcdab89674523011032547698badcfe07000000000000000100000000000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b1420000000000000003000000000000000010000000000000000000000000000000000000000000000000000000000000",
    ),
    (
        "N-7",
        ControlError::InvalidIdentity,
        "58000000010012000100000078563412e903000000000000efcdab89674523011032547698badcfe070000000000000001000000000000000a00000000000000000000000000000003000000000000000100000000000000",
    ),
    (
        "N-8",
        ControlError::ReservedBits,
        "3800000001001100010000007856341200000000000000000a000000000000000b0000000000000009000000000000008813000000000000",
    ),
    (
        "N-9",
        ControlError::InvalidValue,
        "3800000001001100010000000000000000000000000000000a000000000000000b0000000000000009000000000000000000000000000000",
    ),
    (
        "N-10",
        ControlError::InvalidValue,
        "58000000010012000100000078563412e903000000000000efcdab89674523011032547698badcfe070000000000000001000000000000000a00000000000000000000000000000003000000000000000000000000000000",
    ),
    (
        "N-11",
        ControlError::InvalidValue,
        "3800000001001100010000000000000000000000000000000a000000000000000b00000000000000090000000000000081ee360000000000",
    ),
];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

const RECEIVER: Receiver = Receiver {
    receiver_boot_id: [0xA1A2_A3A4_A5A6_A7A8, 0xB1B2_B3B4_B5B6_B7B8],
    receiver_id: 0x42,
};
const NONCE: [u64; 2] = [0xC1C2_C3C4_C5C6_C7C8, 0xD1D2_D3D4_D5D6_D7D8];
const ALIAS: Alias = Alias {
    session_id: 0x1234_5678,
    stream_id: 1001,
};
const IDENTITY: Identity = Identity {
    driver_id: [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210],
    registration_id: 7,
    incarnation: 1,
};

fn expected() -> [AuthControl; 5] {
    [
        AuthControl::State(GuardState {
            authority_id: 0x0A,
            guard_id: 0x0B,
            word: GuardWord::from_raw(9).unwrap(),
            lifetime_ms: 5000,
        }),
        AuthControl::Challenge(StatusChallenge {
            authority_id: 0x0A,
            guard_id: 0x0B,
            receiver: RECEIVER,
            nonce: NONCE,
        }),
        AuthControl::Status(GuardStatus {
            authority_id: 0x0A,
            guard_id: 0x0B,
            receiver: RECEIVER,
            nonce: NONCE,
            word: GuardWord::from_raw(6).unwrap(),
        }),
        AuthControl::Abort(SessionAbort {
            alias: ALIAS,
            identity: IDENTITY,
            authority_id: 0x0A,
            guard_id: 0x0B,
            guard_epoch: 3,
            reason: GUARD_CLOSED,
        }),
        AuthControl::Ack(AbortAck {
            alias: ALIAS,
            identity: IDENTITY,
            receiver: RECEIVER,
            guard_epoch: 3,
            lanes: Lanes::new(&[
                AckLane {
                    delivered: 4096,
                    unresolved_end: 8192,
                },
                AckLane::default(),
            ])
            .unwrap(),
        }),
    ]
}

#[test]
fn the_positive_vectors_decode_and_encode_byte_for_byte() {
    for ((name, text), value) in POSITIVE.iter().zip(expected()) {
        let bytes = hex(text);
        assert_eq!(AuthControl::decode(&bytes), Ok(value), "{name}");
        let mut out = [0_u8; 160];
        let length = value.encode(&mut out).unwrap();
        assert_eq!(&out[..length], bytes.as_slice(), "{name}");
    }
}

#[test]
fn the_negative_vectors_give_their_first_error() {
    for (name, error, text) in NEGATIVE {
        assert_eq!(AuthControl::decode(&hex(text)), Err(error), "{name}");
    }
}

#[test]
fn the_trusted_decoder_still_gates_every_body() {
    for (name, text) in POSITIVE {
        let bytes = hex(text);
        assert!(
            matches!(Control::decode(&bytes), Err(ControlError::GatedType { .. })),
            "{name}"
        );
    }
}

#[test]
fn only_a_status_challenge_is_accepted_bare() {
    let challenge = hex(POSITIVE[1].1);
    assert!(decode_bare_status_challenge(&challenge).is_ok());
    for index in [0, 2, 3, 4] {
        assert!(matches!(
            decode_bare_status_challenge(&hex(POSITIVE[index].1)),
            Err(ControlError::GatedType { .. })
        ));
    }
}

#[test]
fn guard_words_follow_their_epoch() {
    assert_eq!(GuardWord::from_epoch(1).map(GuardWord::raw), Ok(2));
    assert_eq!(GuardWord::from_epoch(4).map(GuardWord::raw), Ok(9));
    assert!(GuardWord::from_epoch(4).unwrap().is_open());
    assert!(!GuardWord::from_epoch(3).unwrap().is_open());
    assert_eq!(GuardWord::from_epoch(0), Err(ControlError::InvalidValue));
    assert_eq!(
        GuardWord::from_epoch(1 << 63),
        Err(ControlError::InvalidValue)
    );
    assert_eq!(
        GuardWord::from_epoch((1 << 63) - 1).map(GuardWord::epoch),
        Ok((1 << 63) - 1)
    );
}

#[test]
fn an_abort_without_a_guard_is_valid_for_other_reasons() {
    let AuthControl::Abort(mut abort) = expected()[3] else {
        unreachable!()
    };
    abort.guard_id = 0;
    abort.reason = 2;
    let mut out = [0_u8; 88];
    assert_eq!(AuthControl::Abort(abort).encode(&mut out), Ok(88));
    abort.reason = GUARD_CLOSED;
    assert_eq!(
        AuthControl::Abort(abort).encode(&mut out),
        Err(ControlError::InvalidIdentity)
    );
}

#[test]
fn a_short_buffer_is_refused() {
    let mut out = [0_u8; 40];
    assert_eq!(
        expected()[0].encode(&mut out),
        Err(ControlError::BufferTooShort {
            required: 56,
            available: 40
        })
    );
}

proptest! {
    /// No input panics, and whatever decodes encodes back to the same bytes.
    #[test]
    fn decode_never_panics_and_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..160)) {
        if let Ok(value) = AuthControl::decode(&bytes) {
            let mut out = [0_u8; 160];
            let length = value.encode(&mut out).unwrap();
            prop_assert_eq!(&out[..length], bytes.as_slice());
        }
    }

    /// Every single-byte change of a positive vector either decodes to a
    /// different value or is rejected.
    #[test]
    fn mutations_never_decode_to_the_same_value(index in 0_usize..5, at in 0_usize..152, delta in 1_u8..=255) {
        let mut bytes = hex(POSITIVE[index].1);
        let at = at % bytes.len();
        bytes[at] = bytes[at].wrapping_add(delta);
        if let Ok(value) = AuthControl::decode(&bytes) {
            prop_assert_ne!(value, expected()[index]);
        }
    }
}
