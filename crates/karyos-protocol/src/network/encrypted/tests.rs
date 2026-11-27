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

// Gate H5, part 2 (ADR-0114 "Hard gates", H5). Every expected value below
// was printed by `enc_vectors2.py`, a second implementation written from
// the frozen encodings only (Python `cryptography` and `hmac`), and is
// copied from its output `enc_vectors2-output.txt`; none comes from this
// implementation's output.
//
// The script encodes the ENC ANSWER from network-control-schemas.md 4.1
// with the field values of section 5.1 and V-SETUP-2 (`key_epoch` 3,
// `party_epoch` 0x0102) and seals it in domain 5 at `envelope_seq` 4,
// `IKM` = 00..1f, under the answer's own identity, alias and `key_epoch`.

/// The ENC ANSWER of [`expected`], as the script encodes it.
const PY_ENC_ANSWER: &str = "80000000010005000302000078563412e903000000000000efcdab89674523011032547698badcfe0700000000000000010000000000000000000100feffffff8005000000000000a8a7a6a5a4a3a2a1b8b7b6b5b4b3b2b1c8c7c6c5c4c3c2c1d8d7d6d5d4d3d2d1030000000201000000100300000000000000000000000000";
/// The domain 5 `info` of the answer's identity at `key_epoch` 3.
const PY_SETUP_INFO: &str = "6b6172796f732d776972652d656e632d763031007365747570000000030000000000efcdab89674523011032547698badcfe0700000000000000010000000000000010";
/// The domain 5 key.
const PY_SETUP_KEY: &str = "0314ad0ea1e27adae56ecdc1f494c477197f1b3854352f0b4866bb0c16156e8b";
/// The sealed datagram, 212 bytes.
const PY_ENC_ANSWER_SEALED: &str = "d40000000100210010100500030000000000000078563412e90300000400000000000000efcdab89674523011032547698badcfe07000000000000000100000000000000f8607b9e1082fb4bd01791dfe521533680e89ff389b2f269baf7eb24d47b7ee40c7718ab581f44ead2ad13326c21e2fb35af1c39216699f06ef1091f98ebc1d5417ac3a04ae11774f41549d6e071446f13363ef8f2a5a8509c0eba324b15e809a6bd4823e4f5171de37f5c78241440a052246b752a9e4e9703f50bfc7e45011bf79748f70ba247120ae75aaa7fda1d2d";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// Gate H5, SETUP variant 3 (ADR-0114 sections 6a and 9; manifest
/// section 7): the ENC ANSWER transcript of the independent script. The
/// encoder gives its plaintext byte for byte, the domain 5 profile seals
/// it to the script's datagram, and opening that datagram gives back an
/// ENC ANSWER whose `key_epoch` equals the envelope's.
#[test]
fn h5_the_enc_answer_transcript_in_domain_5_matches_the_independent_script() {
    use crate::protection::aes_gcm_siv::{
        AesGcmSiv, Domain, ENVELOPE_LEN, HEADER_LEN, KeyContext, PublicationIdentity, Salt,
    };
    let answer = expected();
    let mut plaintext = [0_u8; MAX_ENC_ANSWER_LENGTH];
    let length = answer.encode(&mut plaintext).unwrap();
    assert_eq!(plaintext[..length].to_vec(), unhex(PY_ENC_ANSWER));
    let mut driver_id = [0_u8; 16];
    driver_id[..8].copy_from_slice(&answer.answer.identity.driver_id[0].to_le_bytes());
    driver_id[8..].copy_from_slice(&answer.answer.identity.driver_id[1].to_le_bytes());
    let context = KeyContext {
        domain: Domain::Setup,
        key_epoch: answer.key_epoch,
        party_epoch: 0,
        session_id: answer.answer.alias.session_id,
        stream_id: answer.answer.alias.stream_id,
        publication: PublicationIdentity {
            driver_id,
            registration_id: answer.answer.identity.registration_id,
            incarnation: answer.answer.identity.incarnation,
        },
        receiver: None,
        salt: Salt::Empty,
    };
    let (info, info_len) = context.info();
    assert_eq!(info[..info_len].to_vec(), unhex(PY_SETUP_INFO));
    let ikm: Vec<u8> = (0_u8..32).collect();
    assert_eq!(context.derive(&ikm).to_vec(), unhex(PY_SETUP_KEY));
    let profile = AesGcmSiv::new(&ikm, context, &[]).unwrap();
    let mut datagram = vec![0_u8; length + ENVELOPE_LEN];
    datagram[..length].copy_from_slice(&plaintext[..length]);
    profile.set_next_seq(4);
    let total = profile.seal_next(&mut datagram, length).unwrap();
    assert_eq!(total, 212);
    assert_eq!(datagram, unhex(PY_ENC_ANSWER_SEALED));
    let mut received = unhex(PY_ENC_ANSWER_SEALED);
    let opened = profile.open_in_place(&mut received).unwrap();
    let frames = &received[HEADER_LEN..HEADER_LEN + opened.frames];
    assert_eq!(decode_setup(frames), Ok(EncSetup::Answer(answer)));
    assert_eq!(
        u32::from_le_bytes(received[12..16].try_into().unwrap()),
        answer.key_epoch,
        "the answer's key_epoch is the envelope's"
    );
}

/// The tracked output of the independent script (`tests/vectors`).
const PY2: &str = include_str!("../../../tests/vectors/enc_vectors2-output.txt");

/// Asserts that a line of `output` starting with `prefix` carries `value`
/// as one of its words, and returns how many lines start with `prefix`.
fn tracked(output: &str, prefix: &str, value: &str) -> usize {
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| line.starts_with(prefix))
        .collect();
    assert!(
        !lines.is_empty(),
        "no line {prefix:?} in the tracked output"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.split_whitespace().any(|word| word == value)),
        "{prefix:?}: {value} is not the tracked output"
    );
    lines.len()
}

/// How many lines of `output` start with `prefix`.
fn lines_of(output: &str, prefix: &str) -> usize {
    output
        .lines()
        .filter(|line| line.starts_with(prefix))
        .count()
}

/// Gate H5 provenance: the ENC ANSWER values embedded above are the
/// values the tracked output of `enc_vectors2.py` prints.
#[test]
fn h5_the_embedded_enc_answer_is_the_tracked_output() {
    tracked(PY2, "enc answer plaintext (128): ", PY_ENC_ANSWER);
    tracked(PY2, "enc answer setup info: ", PY_SETUP_INFO);
    tracked(PY2, "enc answer setup key: ", PY_SETUP_KEY);
    tracked(PY2, "enc answer sealed seq 4 (212): ", PY_ENC_ANSWER_SEALED);
    assert_eq!(lines_of(PY2, "enc answer "), 4);
}
