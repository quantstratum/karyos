// SPDX-License-Identifier: Apache-2.0

//! SETUP variant 3 vectors (ADR-0114 section 6a): a literal two-lane ENC
//! ANSWER built by hand from the variant 2 vector V-SETUP-2 of
//! network-control-schemas.md section 5, and its mutations.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::super::{
    Alias, ChallengeBlock, Control, ControlError, Identity, Lanes, SetupAnswer, TermParams,
};
use super::*;

/// V-SETUP-2 with `variant = 3`, `frame_length = 128` and the epoch block
/// `key_epoch = 3`, `party_epoch = 0x0102` inserted at offset 104.
const V_SETUP_3: [[u8; 8]; 16] = [
    [0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00],
    [0x03, 0x02, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12],
    [0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01],
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE],
    [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x01, 0x00, 0xFE, 0xFF, 0xFF, 0xFF],
    [0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1],
    [0xB8, 0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1],
    [0xC8, 0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1],
    [0xD8, 0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1],
    [0x03, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00],
    [0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

fn expected() -> EncAnswer {
    EncAnswer {
        answer: SetupAnswer {
            alias: Alias {
                session_id: 0x1234_5678,
                stream_id: 1001,
            },
            identity: Identity {
                driver_id: [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210],
                registration_id: 7,
                incarnation: 1,
            },
            term: TermParams {
                term_length: 65536,
                initial_term_id: -2,
                mtu: 1408,
            },
            challenge: ChallengeBlock {
                receiver_boot_id: [0xA1A2_A3A4_A5A6_A7A8, 0xB1B2_B3B4_B5B6_B7B8],
                nonce: [0xC1C2_C3C4_C5C6_C7C8, 0xD1D2_D3D4_D5D6_D7D8],
            },
            joins: Lanes::new(&[200_704, 0]).unwrap(),
        },
        key_epoch: 3,
        party_epoch: 0x0102,
    }
}

#[test]
fn the_variant_3_vector_decodes_and_encodes_to_itself() {
    let bytes = V_SETUP_3.as_flattened();
    assert_eq!(EncAnswer::decode(bytes), Ok(expected()));
    assert_eq!(decode_setup(bytes), Ok(EncSetup::Answer(expected())));
    let mut out = [0xEE_u8; MAX_ENC_ANSWER_LENGTH];
    assert_eq!(expected().encode(&mut out), Ok(128));
    assert_eq!(&out[..128], bytes);
    assert_eq!(expected().encoded_length(), 128);
}

#[test]
fn the_sizes_are_112_plus_8n() {
    for lanes in 1..=4_usize {
        let mut answer = expected();
        answer.answer.joins = Lanes::new(&[0, 32, 64, 96][..lanes]).unwrap();
        let mut out = [0_u8; MAX_ENC_ANSWER_LENGTH];
        let length = answer.encode(&mut out).unwrap();
        assert_eq!(length, 112 + 8 * lanes);
        assert_eq!(EncAnswer::decode(&out[..length]), Ok(answer));
    }
    assert_eq!(MAX_ENC_ANSWER_LENGTH, 144);
}

#[test]
fn a_variant_2_answer_is_refused_on_an_encrypted_channel_and_variant_3_elsewhere() {
    // Variant 2 through the encrypted decoder.
    let mut answer = [0_u8; MAX_ENC_ANSWER_LENGTH];
    let length = expected().answer.encode(&mut answer).unwrap();
    assert_eq!(
        decode_setup(&answer[..length]),
        Err(ControlError::InvalidVariant)
    );
    assert_eq!(
        EncAnswer::decode(&answer[..length]),
        Err(ControlError::InvalidVariant)
    );
    // Variant 3 through the trusted decoder, the one every other channel
    // uses.
    assert_eq!(
        Control::decode(V_SETUP_3.as_flattened()),
        Err(ControlError::InvalidVariant)
    );
}

#[test]
fn the_epoch_block_is_validated() {
    let valid = V_SETUP_3.as_flattened().to_vec();
    let mutate = |at: usize, value: u8| {
        let mut bytes = valid.clone();
        bytes[at] = value;
        bytes
    };
    // key_epoch 0.
    let mut zero = valid.clone();
    zero[104..108].fill(0);
    assert_eq!(EncAnswer::decode(&zero), Err(ControlError::InvalidValue));
    // Reserved epoch bytes.
    assert_eq!(
        EncAnswer::decode(&mutate(110, 1)),
        Err(ControlError::ReservedBits)
    );
    assert_eq!(
        EncAnswer::decode(&mutate(111, 1)),
        Err(ControlError::ReservedBits)
    );
    // Any party_epoch is valid.
    let mut high = valid.clone();
    high[108..110].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(
        EncAnswer::decode(&high).map(|a| a.party_epoch),
        Ok(u16::MAX)
    );
    // Length and count.
    assert_eq!(
        EncAnswer::decode(&valid[..120]),
        Err(ControlError::Truncated)
    );
    let mut longer = valid.clone();
    longer.extend_from_slice(&[0; 8]);
    assert_eq!(
        EncAnswer::decode(&longer),
        Err(ControlError::InvalidGrouping)
    );
    assert_eq!(
        EncAnswer::decode(&mutate(9, 0)),
        Err(ControlError::InvalidCount)
    );
    assert_eq!(
        EncAnswer::decode(&mutate(9, 3)),
        Err(ControlError::InvalidLength)
    );
    // Another frame type.
    assert_eq!(
        decode_setup(&mutate(6, 7)),
        Err(ControlError::WrongKind { code: 7 })
    );
    // The body keeps the variant 2 checks: a zero nonce.
    let mut nonce = valid.clone();
    nonce[88..104].fill(0);
    assert!(EncAnswer::decode(&nonce).is_err());
    // key_epoch 0 never encodes, and a failed encode writes nothing.
    let mut out = [0xEE_u8; MAX_ENC_ANSWER_LENGTH];
    let mut answer = expected();
    answer.key_epoch = 0;
    assert_eq!(answer.encode(&mut out), Err(ControlError::InvalidValue));
    assert!(out.iter().all(|byte| *byte == 0xEE));
    assert!(matches!(
        expected().encode(&mut out[..127]),
        Err(ControlError::BufferTooShort { .. })
    ));
    assert!(out.iter().all(|byte| *byte == 0xEE));
}

#[test]
fn an_announce_decodes_through_the_encrypted_decoder() {
    let mut out = [0_u8; 72];
    let announce = super::super::SetupAnnounce {
        alias: expected().answer.alias,
        identity: expected().answer.identity,
        term: expected().answer.term,
        lane_count: 2,
    };
    let length = announce.encode(&mut out).unwrap();
    assert_eq!(
        decode_setup(&out[..length]),
        Ok(EncSetup::Announce(announce))
    );
}
