// SPDX-License-Identifier: Apache-2.0

// The runtime over a test-only template with a block, a group and two
// variable fields: round trips, every rule of the envelope, truncation at
// every boundary, and the bounds of groups and variable fields.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

/// Block: a u64 at 0, an i32 at 8, a bool at 12. A group of 6-byte
/// entries (at most 3), a bytes field (0 to 4) and a UTF-8 field (1 to 8).
const TEST: Template = Template {
    schema_id: 9,
    template_id: 7,
    version: 1,
    block_length: 13,
    max_length: 12 + 13 + 4 + 18 + 2 + 4 + 2 + 8,
};

#[derive(Debug, PartialEq, Eq)]
struct Message<'a> {
    id: u64,
    level: i32,
    flag: bool,
    entries: Vec<[u8; 6]>,
    blob: &'a [u8],
    name: &'a str,
}

fn encode(message: &Message<'_>, out: &mut [u8]) -> Result<usize, CodecError> {
    let mut encoder = Encoder::new(out, &TEST)?;
    encoder.u64(0, message.id)?;
    encoder.i32(8, message.level)?;
    encoder.bool(12, message.flag)?;
    encoder.group(
        "entries",
        6,
        3,
        message.entries.iter().map(|entry| &entry[..]),
    )?;
    encoder.bytes("blob", 0, 4, message.blob)?;
    encoder.bytes("name", 1, 8, message.name.as_bytes())?;
    encoder.finish()
}

fn decode(buf: &[u8]) -> Result<Message<'_>, CodecError> {
    let (block, mut decoder) = Decoder::new(buf, &TEST)?;
    let id = block.u64(0)?;
    let level = block.i32(8)?;
    let flag = block.bool("flag", 12)?;
    let group = decoder.group("entries", 6, 3)?;
    let entries = group
        .iter()
        .map(|entry| entry.bytes().try_into().unwrap())
        .collect();
    let blob = decoder.bytes("blob", 0, 4)?;
    let name = decoder.str("name", 1, 8)?;
    decoder.finish()?;
    Ok(Message {
        id,
        level,
        flag,
        entries,
        blob,
        name,
    })
}

fn sample() -> Message<'static> {
    Message {
        id: 0x0102_0304_0506_0708,
        level: -5,
        flag: true,
        entries: vec![[1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12]],
        blob: &[0xAA, 0xBB],
        name: "lane",
    }
}

#[test]
fn a_message_round_trips_with_its_exact_bytes() {
    let mut out = [0u8; 128];
    let length = encode(&sample(), &mut out).unwrap();
    assert_eq!(length, 12 + 13 + 4 + 12 + 2 + 2 + 2 + 4);
    let expected: Vec<u8> = [
        &[9, 0, 7, 0, 1, 0, 13, 0, 51, 0, 0, 0][..],
        &[8, 7, 6, 5, 4, 3, 2, 1, 0xFB, 0xFF, 0xFF, 0xFF, 1],
        &[6, 0, 2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        &[2, 0, 0xAA, 0xBB],
        &[4, 0, b'l', b'a', b'n', b'e'],
    ]
    .concat();
    assert_eq!(&out[..length], &expected[..]);
    assert_eq!(decode(&out[..length]).unwrap(), sample());
}

#[test]
fn every_truncation_is_refused() {
    let mut out = [0u8; 128];
    let length = encode(&sample(), &mut out).unwrap();
    for cut in 0..length {
        // A shorter input whose envelope still declares the full length.
        assert!(decode(&out[..cut]).is_err(), "cut at {cut}");
        // A shorter capacity never yields a message.
        let mut short = vec![0u8; cut];
        assert!(
            matches!(
                encode(&sample(), &mut short),
                Err(CodecError::Truncated { .. })
            ),
            "capacity {cut}"
        );
    }
}

#[test]
fn an_unfinished_encoding_is_never_a_message() {
    let mut out = [0u8; 128];
    {
        // An encoder abandoned before `finish`.
        let mut encoder = Encoder::new(&mut out, &TEST).unwrap();
        encoder.u64(0, 1).unwrap();
    }
    assert_eq!(&out[8..12], &[0, 0, 0, 0]);
    assert!(matches!(
        decode(&out[..ENVELOPE_LENGTH + 13]),
        Err(CodecError::MessageLength { declared: 0, .. })
    ));
}

#[test]
fn the_envelope_must_name_the_supported_tuple() {
    let mut out = [0u8; 128];
    let length = encode(&sample(), &mut out).unwrap();
    // Schema, template, version and block length, one at a time.
    for at in [0, 2, 4, 6] {
        let mut bad = out;
        bad[at] ^= 0x10;
        assert!(
            matches!(
                decode(&bad[..length]),
                Err(CodecError::UnsupportedSchema { .. })
            ),
            "byte {at}"
        );
    }
    // A declared length other than the input's, or above the maximum.
    let mut bad = out;
    bad[8] += 1;
    assert!(matches!(
        decode(&bad[..length]),
        Err(CodecError::MessageLength { .. })
    ));
    let mut long = out;
    long[8..12].copy_from_slice(&(TEST.max_length + 1).to_le_bytes());
    let declared = usize::try_from(TEST.max_length + 1).unwrap();
    let mut buf = vec![0u8; declared];
    buf[..length].copy_from_slice(&long[..length]);
    assert!(matches!(
        decode(&buf),
        Err(CodecError::MessageLength { .. })
    ));
}

#[test]
fn bytes_left_over_are_refused() {
    let mut out = [0u8; 128];
    let length = encode(&sample(), &mut out).unwrap();
    let mut longer = out[..length + 1].to_vec();
    longer[8..12].copy_from_slice(&u32::try_from(length + 1).unwrap().to_le_bytes());
    assert!(matches!(
        decode(&longer),
        Err(CodecError::MessageLength { .. })
    ));
}

#[test]
fn groups_and_variable_fields_keep_their_bounds() {
    let mut out = [0u8; 128];
    // Four entries: one over the group's maximum.
    let mut message = sample();
    message.entries = vec![[0; 6]; 4];
    assert!(matches!(
        encode(&message, &mut out),
        Err(CodecError::CountOverLimit {
            count: 4,
            max: 3,
            ..
        })
    ));
    // A blob over 4 bytes; an empty name.
    let mut message = sample();
    message.blob = &[0; 5];
    assert!(matches!(
        encode(&message, &mut out),
        Err(CodecError::LengthOutOfRange { field: "blob", .. })
    ));
    let mut message = sample();
    message.name = "";
    assert!(matches!(
        encode(&message, &mut out),
        Err(CodecError::LengthOutOfRange { field: "name", .. })
    ));
    // Decoding: a count over the maximum, another entry length, invalid
    // UTF-8 and an invalid boolean.
    let length = encode(&sample(), &mut out).unwrap();
    let group_at = ENVELOPE_LENGTH + 13;
    let mut bad = out;
    bad[group_at + 2] = 4;
    assert!(matches!(
        decode(&bad[..length]),
        Err(CodecError::CountOverLimit { .. })
    ));
    let mut bad = out;
    bad[group_at] = 5;
    assert!(matches!(
        decode(&bad[..length]),
        Err(CodecError::UnsupportedSchema { .. })
    ));
    let mut bad = out;
    bad[length - 1] = 0xFF;
    assert!(matches!(
        decode(&bad[..length]),
        Err(CodecError::InvalidUtf8 { field: "name" })
    ));
    let mut bad = out;
    bad[ENVELOPE_LENGTH + 12] = 2;
    assert!(matches!(
        decode(&bad[..length]),
        Err(CodecError::InvalidBool {
            field: "flag",
            value: 2
        })
    ));
}

#[test]
fn a_group_has_no_entry_past_its_count() {
    // A template whose group has entries of 0 bytes: two of them.
    let empty = Template {
        schema_id: 9,
        template_id: 8,
        version: 1,
        block_length: 0,
        max_length: 16,
    };
    let bytes = [9, 0, 8, 0, 1, 0, 0, 0, 16, 0, 0, 0, 0, 0, 2, 0];
    let (_, mut decoder) = Decoder::new(&bytes, &empty).unwrap();
    let group = decoder.group("empty", 0, 2).unwrap();
    decoder.finish().unwrap();
    assert_eq!(group.count(), 2);
    assert!(group.entry(1).is_some());
    assert!(group.entry(2).is_none());
    assert_eq!(group.iter().count(), 2);
}

#[test]
fn the_maximum_length_holds_both_ways() {
    let mut out = [0u8; 128];
    let length = encode(&sample(), &mut out).unwrap();
    let declared = u32::try_from(length).unwrap();
    // A template whose maximum is exactly this message, and one byte less.
    let exact = Template {
        max_length: declared,
        ..TEST
    };
    let short = Template {
        max_length: declared - 1,
        ..TEST
    };
    assert!(Decoder::new(&out[..length], &exact).is_ok());
    assert!(matches!(
        Decoder::new(&out[..length], &short),
        Err(CodecError::MessageLength { .. })
    ));
    let mut again = [0u8; 128];
    let mut encoder = Encoder::new(&mut again, &exact).unwrap();
    encoder
        .bytes("blob", 0, 64, &out[ENVELOPE_LENGTH..length])
        .unwrap();
    assert!(matches!(
        encoder.finish(),
        Err(CodecError::MessageLength { .. })
    ));
    let mut encoder = Encoder::new(&mut again, &exact).unwrap();
    encoder
        .bytes(
            "blob",
            0,
            64,
            &out[ENVELOPE_LENGTH..length - 2 - usize::from(TEST.block_length)],
        )
        .unwrap();
    assert_eq!(encoder.finish().unwrap(), length);
    assert_eq!(&again[8..12], &declared.to_le_bytes());
}

#[test]
fn a_short_buffer_loses_its_earlier_message() {
    let mut out = [0u8; 128];
    let length = encode(&sample(), &mut out).unwrap();
    // Room for the envelope but not the block.
    let mut short = out[..ENVELOPE_LENGTH + 4].to_vec();
    assert!(matches!(
        Encoder::new(&mut short, &TEST),
        Err(CodecError::Truncated { .. })
    ));
    assert_eq!(&short[8..12], &[0, 0, 0, 0]);
    assert!(length > short.len());
}

#[test]
fn bytes_left_over_report_the_declared_length() {
    // A block and group read, then the fields skipped: the message's
    // declared length and where decoding stopped.
    let mut out = [0u8; 128];
    let length = encode(&sample(), &mut out).unwrap();
    let (_, mut decoder) = Decoder::new(&out[..length], &TEST).unwrap();
    decoder.group("entries", 6, 3).unwrap();
    assert_eq!(
        decoder.finish(),
        Err(CodecError::MessageLength {
            declared: u32::try_from(length).unwrap(),
            actual: ENVELOPE_LENGTH + 13 + 4 + 12,
        })
    );
}

#[test]
fn an_encoder_starts_from_a_zeroed_block() {
    let mut out = [0xFFu8; 128];
    // An encoder that writes no field of its block.
    assert!(Encoder::new(&mut out, &TEST).is_ok());
    assert_eq!(&out[8..ENVELOPE_LENGTH + 13], &[0u8; 4 + 13][..]);
}
