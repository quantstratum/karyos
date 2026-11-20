// SPDX-License-Identifier: Apache-2.0

//! The golden vectors of schema 2 version 1, which QS-REVIEWER derived
//! from the text alone (quantstratum-docs#658, comment 6464022448, at
//! `5eb4cd78`), without this code. V1 to V10 are reproduced byte for
//! byte, encoding and decoding; M1 to M9 and F-1 to F-12 are refused as
//! stated. The three large vectors are built from their stated header
//! and pattern; their SHA-256 digests are checked in the pull request,
//! since the workspace admits no hash crate for a test.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    reason = "test vectors, as ADR-0007 allows in tests; one ignored test prints the large ones"
)]

use super::*;

/// `text`'s hex bytes, whitespace ignored.
fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// `n` bytes, byte i = i mod 256.
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 256) as u8).collect()
}

/// Encodes `envelope`, checks `expected`, and decodes it back.
fn valid(label: &str, envelope: Envelope<'_>, expected: &[u8]) {
    assert_eq!(envelope.to_vec().unwrap(), expected, "{label} encode");
    assert_eq!(Envelope::decode(expected), Ok(envelope), "{label} decode");
}

const V4_HEADER: &str = "02 00 03 00 01 00 20 00 32 00 00 00
    01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
    09 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00";

#[test]
fn test_schema_2_golden_valid_vectors_v1_to_v10() {
    valid(
        "V1",
        Envelope::Register {
            client: 0x0102_0304_0506_0708,
        },
        &hex("02 00 01 00 01 00 08 00 14 00 00 00 08 07 06 05 04 03 02 01"),
    );
    valid(
        "V2",
        Envelope::Close {
            client: 7,
            epoch: 42,
        },
        &hex("02 00 02 00 01 00 10 00 1c 00 00 00
              07 00 00 00 00 00 00 00 2a 00 00 00 00 00 00 00"),
    );
    valid(
        "V3",
        Envelope::Request {
            request: Request::new(0x1122_3344_5566_7788, 3, 9, 5),
            command: &[],
        },
        &hex("02 00 03 00 01 00 20 00 2e 00 00 00
              88 77 66 55 44 33 22 11 03 00 00 00 00 00 00 00
              09 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00"),
    );
    let mut v4 = hex(V4_HEADER);
    v4.extend(hex("04 00 70 69 6e 67"));
    valid(
        "V4",
        Envelope::Request {
            request: Request::new(1, 1, 9, 10),
            command: b"ping",
        },
        &v4,
    );
    let command = pattern(65535);
    let mut v5 = hex("02 00 03 00 01 00 20 00 2d 00 01 00
                      02 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff
                      ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff");
    v5.extend(&command);
    assert_eq!(v5.len(), 65581);
    assert_eq!(&v5[v5.len() - 4..], &hex("fb fc fd fe")[..]);
    valid(
        "V5",
        Envelope::Request {
            request: Request::new(2, u64::MAX, u64::MAX, u64::MAX),
            command: &command,
        },
        &v5,
    );
    valid(
        "V6",
        Envelope::Request {
            request: Request::new(5, 6, u64::MAX, 0),
            command: &[],
        },
        &hex("02 00 03 00 01 00 20 00 2e 00 00 00
              05 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00
              ff ff ff ff ff ff ff ff 00 00 00 00 00 00 00 00 00 00"),
    );
    valid(
        "V7",
        Envelope::TimerFired {
            timer: 5,
            deadline: 1_000_000_000,
        },
        &hex("02 00 04 00 01 00 10 00 1c 00 00 00
              05 00 00 00 00 00 00 00 00 ca 9a 3b 00 00 00 00"),
    );
    valid(
        "V8",
        Envelope::TimerFired {
            timer: 0,
            deadline: 0,
        },
        &hex("02 00 04 00 01 00 10 00 1c 00 00 00
              00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"),
    );
    valid(
        "V9",
        Envelope::Configuration(&[0x2a]),
        &hex("02 00 05 00 01 00 00 00 0f 00 00 00 01 00 2a"),
    );
    let configuration = pattern(4096);
    let mut v10 = hex("02 00 05 00 01 00 00 00 0e 10 00 00 00 10");
    v10.extend(&configuration);
    assert_eq!(v10.len(), 4110);
    assert_eq!(&v10[v10.len() - 4..], &hex("fc fd fe ff")[..]);
    valid("V10", Envelope::Configuration(&configuration), &v10);
}

fn out_of_range(field: &'static str) -> Result<Envelope<'static>, CodecError> {
    Err(CodecError::ValueOutOfRange { field })
}

#[test]
fn test_schema_2_golden_value_and_length_vectors_m1_to_m9() {
    for (label, bytes, field) in [
        (
            "M1",
            hex("02 00 01 00 01 00 08 00 14 00 00 00 00 00 00 00 00 00 00 00"),
            "client",
        ),
        (
            "M2",
            hex("02 00 02 00 01 00 10 00 1c 00 00 00
                 00 00 00 00 00 00 00 00 2a 00 00 00 00 00 00 00"),
            "client",
        ),
        (
            "M3",
            hex("02 00 02 00 01 00 10 00 1c 00 00 00
                 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"),
            "epoch",
        ),
        (
            "M4",
            hex("02 00 03 00 01 00 20 00 2e 00 00 00
                 00 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00
                 09 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00"),
            "client",
        ),
        (
            "M5",
            hex("02 00 03 00 01 00 20 00 2e 00 00 00
                 88 77 66 55 44 33 22 11 00 00 00 00 00 00 00 00
                 09 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00"),
            "epoch",
        ),
        (
            "M6",
            hex("02 00 03 00 01 00 20 00 32 00 00 00
                 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00
                 09 00 00 00 00 00 00 00 0b 00 00 00 00 00 00 00
                 04 00 70 69 6e 67"),
            "lowest_unanswered",
        ),
    ] {
        assert_eq!(Envelope::decode(&bytes), out_of_range(field), "{label}");
    }
    // The same rules on encoding.
    for (label, envelope, field) in [
        ("M1", Envelope::Register { client: 0 }, "client"),
        (
            "M2",
            Envelope::Close {
                client: 0,
                epoch: 42,
            },
            "client",
        ),
        (
            "M3",
            Envelope::Close {
                client: 7,
                epoch: 0,
            },
            "epoch",
        ),
        (
            "M6",
            Envelope::Request {
                request: Request::new(1, 1, 9, 11),
                command: b"ping",
            },
            "lowest_unanswered",
        ),
    ] {
        assert_eq!(
            envelope.to_vec(),
            Err(CodecError::ValueOutOfRange { field }),
            "{label}"
        );
    }
    // M7: an empty configuration.
    let m7 = hex("02 00 05 00 01 00 00 00 0e 00 00 00 00 00");
    assert_eq!(
        Envelope::decode(&m7),
        Err(CodecError::LengthOutOfRange {
            field: "configuration",
            length: 0,
            min: 1,
            max: 4096
        })
    );
    // M8: 4097 bytes, two faults on decoding; one on encoding.
    let long = pattern(4097);
    let mut m8 = hex("02 00 05 00 01 00 00 00 0f 10 00 00 01 10");
    m8.extend(&long);
    assert_eq!(m8.len(), 4111);
    assert_eq!(&m8[m8.len() - 4..], &hex("fd fe ff 00")[..]);
    assert!(
        matches!(
            Envelope::decode(&m8),
            Err(CodecError::LengthOutOfRange {
                field: "configuration",
                length: 4097,
                min: 1,
                max: 4096
            } | CodecError::MessageLength {
                declared: 4111,
                actual: 4111
            })
        ),
        "{:?}",
        Envelope::decode(&m8)
    );
    assert_eq!(
        Envelope::Configuration(&long).to_vec(),
        Err(CodecError::LengthOutOfRange {
            field: "configuration",
            length: 4097,
            min: 1,
            max: 4096
        })
    );
    // M9: a command of 65536 bytes, on encoding only.
    let command = vec![0; 65536];
    assert_eq!(
        Envelope::Request {
            request: Request::new(1, 1, 0, 0),
            command: &command,
        }
        .to_vec(),
        Err(CodecError::LengthOutOfRange {
            field: "command",
            length: 65536,
            min: 0,
            max: 65535
        })
    );
}

#[test]
fn test_schema_2_golden_framing_vectors_f1_to_f12() {
    let unsupported = |schema, template, version| {
        Err::<Envelope<'static>, _>(CodecError::UnsupportedSchema {
            schema,
            template,
            version,
        })
    };
    for (label, text, expected) in [
        (
            "F-1",
            "01 00 01 00 01 00 08 00 14 00 00 00 08 07 06 05 04 03 02 01",
            unsupported(1, 1, 1),
        ),
        (
            "F-2",
            "02 00 01 00 02 00 08 00 14 00 00 00 08 07 06 05 04 03 02 01",
            unsupported(2, 1, 2),
        ),
        (
            "F-3",
            "02 00 00 00 01 00 08 00 14 00 00 00 01 00 00 00 00 00 00 00",
            unsupported(2, 0, 1),
        ),
        (
            "F-4",
            "02 00 06 00 01 00 08 00 14 00 00 00 01 00 00 00 00 00 00 00",
            unsupported(2, 6, 1),
        ),
        (
            "F-5",
            "02 00 01 00 01 00 10 00 14 00 00 00 08 07 06 05 04 03 02 01",
            unsupported(2, 1, 1),
        ),
        (
            "F-6",
            "02 00 05 00 01 00 08 00 0f 00 00 00 01 00 2a",
            unsupported(2, 5, 1),
        ),
        (
            "F-7",
            "02 00 01 00 01 00 08 00 13 00 00 00 08 07 06 05 04 03 02 01",
            Err(CodecError::MessageLength {
                declared: 19,
                actual: 20,
            }),
        ),
        (
            "F-8",
            "02 00 01 00 01 00 08 00 00 00 00 00 08 07 06 05 04 03 02 01",
            Err(CodecError::MessageLength {
                declared: 0,
                actual: 20,
            }),
        ),
    ] {
        assert_eq!(Envelope::decode(&hex(text)), expected, "{label}");
    }
    assert!(matches!(
        Envelope::decode(&hex("02 00 01 00 01 00 08 00 14 00 00")),
        Err(CodecError::Truncated { .. })
    ));
    assert!(matches!(
        Envelope::decode(&hex("02 00 01 00 01 00 08 00 0c 00 00 00")),
        Err(CodecError::Truncated { .. } | CodecError::MessageLength { .. })
    ));
    let mut f11 = hex(V4_HEADER);
    f11.extend(hex("03 00 70 69 6e 67"));
    assert!(
        matches!(
            Envelope::decode(&f11),
            Err(CodecError::MessageLength { .. })
        ),
        "F-11"
    );
    let mut f12 = hex(V4_HEADER);
    f12.extend(hex("05 00 70 69 6e 67"));
    assert!(
        matches!(Envelope::decode(&f12), Err(CodecError::Truncated { .. })),
        "F-12"
    );
}

/// Prints the three large vectors' encodings in hex, for their SHA-256
/// against the reviewer's (`cargo test -- --ignored --nocapture`).
#[test]
#[ignore = "prints the large vectors for an external SHA-256"]
fn print_the_large_vectors() {
    let command = pattern(65535);
    let configuration = pattern(4096);
    for (label, bytes) in [
        (
            "V5",
            Envelope::Request {
                request: Request::new(2, u64::MAX, u64::MAX, u64::MAX),
                command: &command,
            }
            .to_vec()
            .unwrap(),
        ),
        (
            "V10",
            Envelope::Configuration(&configuration).to_vec().unwrap(),
        ),
    ] {
        let text: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        println!("{label} {text}");
    }
}

/// B-1, `SessionBounds` of the default profile: 64 sessions, 64 replies
/// of 8 KiB, 60 s.
const B1: &str = "05 00 01 00 01 00 14 00 20 00 00 00
    40 00 00 00 40 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00";

/// The golden vectors of schema 5 version 1, the core's own entries
/// (karyos#927): B-1 and B-2 are reproduced byte for byte, B-3 to B-12
/// refused as stated. Schema 2's vectors above are unchanged.
#[test]
fn test_schema_5_golden_vectors_b1_to_b12() {
    let b1 = SessionBounds::new(DedupConfig::default());
    assert_eq!(b1.to_vec().unwrap(), hex(B1), "B-1 encode");
    assert_eq!(SessionBounds::decode(&hex(B1)), Ok(b1), "B-1 decode");
    let b2 = SessionBounds::new(
        DedupConfig::default()
            .with_sessions(u32::MAX)
            .with_window(u32::MAX)
            .with_response_bytes(u32::MAX)
            .with_ttl(u64::MAX),
    );
    let b2_bytes = hex("05 00 01 00 01 00 14 00 20 00 00 00
        ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff");
    assert_eq!(b2.to_vec().unwrap(), b2_bytes, "B-2 encode");
    assert_eq!(SessionBounds::decode(&b2_bytes), Ok(b2), "B-2 decode");
    for (label, text, field) in [
        (
            "B-3",
            "05 00 01 00 01 00 14 00 20 00 00 00
             00 00 00 00 40 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00",
            "sessions",
        ),
        (
            "B-4",
            "05 00 01 00 01 00 14 00 20 00 00 00
             40 00 00 00 00 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00",
            "window",
        ),
        (
            "B-5",
            "05 00 01 00 01 00 14 00 20 00 00 00
             40 00 00 00 40 00 00 00 00 00 00 00 00 58 47 f8 0d 00 00 00",
            "response_bytes",
        ),
        (
            "B-6",
            "05 00 01 00 01 00 14 00 20 00 00 00
             40 00 00 00 40 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00",
            "ttl",
        ),
    ] {
        let refused = Err(CodecError::ValueOutOfRange { field });
        assert_eq!(SessionBounds::decode(&hex(text)), refused, "{label} decode");
    }
    // The same rules on encoding.
    for (label, config, field) in [
        ("B-3", DedupConfig::default().with_sessions(0), "sessions"),
        ("B-4", DedupConfig::default().with_window(0), "window"),
        (
            "B-5",
            DedupConfig::default().with_response_bytes(0),
            "response_bytes",
        ),
        ("B-6", DedupConfig::default().with_ttl(0), "ttl"),
    ] {
        assert_eq!(
            SessionBounds::new(config).to_vec(),
            Err(CodecError::ValueOutOfRange { field }),
            "{label} encode"
        );
    }
    let unsupported = |schema, template, version| {
        Err::<SessionBounds, _>(CodecError::UnsupportedSchema {
            schema,
            template,
            version,
        })
    };
    for (label, text, expected) in [
        (
            "B-7",
            "05 00 01 00 02 00 14 00 20 00 00 00
             40 00 00 00 40 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00",
            unsupported(5, 1, 2),
        ),
        (
            "B-8",
            "05 00 02 00 01 00 14 00 20 00 00 00
             40 00 00 00 40 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00",
            unsupported(5, 2, 1),
        ),
        (
            "B-9",
            "05 00 00 00 01 00 14 00 20 00 00 00
             40 00 00 00 40 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00",
            unsupported(5, 0, 1),
        ),
        (
            "B-10",
            "05 00 01 00 01 00 10 00 20 00 00 00
             40 00 00 00 40 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00",
            unsupported(5, 1, 1),
        ),
        (
            "B-11",
            "05 00 01 00 01 00 14 00 1f 00 00 00
             40 00 00 00 40 00 00 00 00 20 00 00 00 58 47 f8 0d 00 00 00",
            Err(CodecError::MessageLength {
                declared: 31,
                actual: 32,
            }),
        ),
        (
            "B-12",
            "02 00 01 00 01 00 08 00 14 00 00 00 08 07 06 05 04 03 02 01",
            unsupported(2, 1, 1),
        ),
    ] {
        assert_eq!(SessionBounds::decode(&hex(text)), expected, "{label}");
    }
    // Schema 2's decoder refuses B-1: the bounds are not a schema 2
    // template.
    assert_eq!(
        Envelope::decode(&hex(B1)),
        Err(CodecError::UnsupportedSchema {
            schema: 5,
            template: 1,
            version: 1
        })
    );
}
