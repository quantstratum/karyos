// SPDX-License-Identifier: Apache-2.0

// Schema 4: round trips, the cross-field rules, unknown tuples and every
// boundary; the querier against fake control streams, including an
// Archive that does not know schema 4.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::*;
use crate::control::ControlResponse;

fn position() -> DurablePosition {
    DurablePosition {
        recording_id: 42,
        start: 64,
        written: 4096,
        durable: 1024,
        state: DurableState::Recording,
        sync: DurableSync::PerSegment,
    }
}

fn answer(position: DurablePosition) -> DurableAnswer {
    DurableAnswer {
        correlation_id: 0x0102_0304_0506_0708,
        position,
    }
}

fn encoded(message: &DurabilityMessage) -> Vec<u8> {
    let mut out = vec![0u8; MAX_MESSAGE];
    let length = message.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

#[test]
fn test_durable_codec_messages_round_trip() {
    let query = DurabilityMessage::QueryDurable(QueryDurable {
        correlation_id: 7,
        recording_id: 42,
    });
    let bytes = encoded(&query);
    assert_eq!(bytes.len(), 28);
    assert_eq!(DurabilityMessage::decode(&bytes).unwrap(), query);
    for (state, durable) in [
        (DurableState::Recording, 1024),
        (DurableState::Recording, 64),
        (DurableState::Stopped, 4096),
    ] {
        for sync in [
            DurableSync::None,
            DurableSync::PerSegment,
            DurableSync::Every,
        ] {
            let message = DurabilityMessage::DurablePosition(answer(DurablePosition {
                durable,
                state,
                sync,
                ..position()
            }));
            let bytes = encoded(&message);
            assert_eq!(bytes.len(), 54);
            assert_eq!(DurabilityMessage::decode(&bytes).unwrap(), message);
        }
    }
}

/// The envelope and block of section 5, field by field.
#[test]
fn test_durable_codec_layout_is_the_notes() {
    let bytes = encoded(&DurabilityMessage::DurablePosition(answer(position())));
    // schema 4, template 2, version 1, block 42, length 54
    assert_eq!(&bytes[..12], &[4, 0, 2, 0, 1, 0, 42, 0, 54, 0, 0, 0]);
    assert_eq!(&bytes[12..20], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&bytes[20..28], &42u64.to_le_bytes());
    assert_eq!(&bytes[28..36], &64u64.to_le_bytes());
    assert_eq!(&bytes[36..44], &4096u64.to_le_bytes());
    assert_eq!(&bytes[44..52], &1024u64.to_le_bytes());
    assert_eq!(&bytes[52..], &[1, 1]);
    let query = encoded(&DurabilityMessage::QueryDurable(QueryDurable {
        correlation_id: 7,
        recording_id: 42,
    }));
    assert_eq!(&query[..12], &[4, 0, 1, 0, 1, 0, 16, 0, 28, 0, 0, 0]);
    // The correlation id where every request has it: bytes 12 to 19.
    assert_eq!(&query[12..20], &7u64.to_le_bytes());
}

#[test]
fn test_durable_codec_cross_field_rules_are_refused() {
    let broken = [
        DurablePosition {
            durable: 4097,
            ..position()
        },
        DurablePosition {
            durable: 63,
            ..position()
        },
        DurablePosition {
            state: DurableState::Stopped,
            ..position()
        },
    ];
    for position in broken {
        let mut out = vec![0u8; MAX_MESSAGE];
        assert_eq!(
            answer(position).encode(&mut out),
            Err(CodecError::ValueOutOfRange { field: "durable" })
        );
        // The same bytes written by hand are refused by the decoder.
        let mut bytes = encoded(&DurabilityMessage::DurablePosition(
            answer(self::position()),
        ));
        bytes[44..52].copy_from_slice(&position.durable.to_le_bytes());
        if position.state == DurableState::Stopped {
            bytes[52] = 2;
        }
        assert_eq!(
            DurabilityMessage::decode(&bytes),
            Err(CodecError::ValueOutOfRange { field: "durable" })
        );
    }
    let mut out = vec![0u8; MAX_MESSAGE];
    assert_eq!(
        QueryDurable {
            correlation_id: 1,
            recording_id: 0
        }
        .encode(&mut out),
        Err(CodecError::ValueOutOfRange {
            field: "recording_id"
        })
    );
    let mut bytes = encoded(&DurabilityMessage::DurablePosition(answer(position())));
    bytes[20..28].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(
        DurabilityMessage::decode(&bytes),
        Err(CodecError::ValueOutOfRange {
            field: "recording_id"
        })
    );
}

#[test]
fn test_durable_codec_enums_and_tuples_are_checked() {
    let good = encoded(&DurabilityMessage::DurablePosition(answer(position())));
    let mut state = good.clone();
    state[52] = 3;
    assert_eq!(
        DurabilityMessage::decode(&state),
        Err(CodecError::InvalidEnum {
            field: "state",
            value: 3
        })
    );
    let mut sync = good.clone();
    sync[53] = 3;
    assert_eq!(
        DurabilityMessage::decode(&sync),
        Err(CodecError::InvalidEnum {
            field: "sync_policy",
            value: 3
        })
    );
    // Schema 1's tuple, another version and an unknown template are not
    // schema 4's.
    for (offset, value) in [(0, 1u16), (4, 2), (2, 3)] {
        let mut bytes = good.clone();
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        assert!(matches!(
            DurabilityMessage::decode(&bytes),
            Err(CodecError::UnsupportedSchema { .. })
        ));
    }
    // A block length other than version 1's.
    let mut block = good.clone();
    block[6] = 41;
    assert!(matches!(
        DurabilityMessage::decode(&block),
        Err(CodecError::UnsupportedSchema { .. })
    ));
    // Every truncation, and a byte too many.
    for length in 0..good.len() {
        assert!(
            DurabilityMessage::decode(&good[..length]).is_err(),
            "{length}"
        );
    }
    let mut long = good.clone();
    long.push(0);
    assert!(DurabilityMessage::decode(&long).is_err());
}

#[test]
fn test_durable_position_covers_a_message_ending_at_or_below_it() {
    let position = position();
    assert!(position.covers(1024));
    assert!(position.covers(64));
    assert!(!position.covers(1025));
}

/// Control streams in memory: what the querier sends, and what the test
/// answers.
#[derive(Clone, Default)]
struct Wire {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    answers: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl ControlRequests for Wire {
    fn send(&mut self, message: &[u8]) -> bool {
        self.sent.lock().unwrap().push(message.to_vec());
        true
    }
}

impl ControlResponses for Wire {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let answer = self.answers.lock().unwrap().pop_front()?;
        out[..answer.len()].copy_from_slice(&answer);
        Some(answer.len())
    }
}

impl Wire {
    fn answer(&self, bytes: Vec<u8>) {
        self.answers.lock().unwrap().push_back(bytes);
    }

    fn respond(&self, correlation_id: u64, code: ResponseCode, message: &str) {
        let mut out = vec![0u8; MAX_ANSWER];
        let length = ControlMessage::ControlResponse(ControlResponse {
            correlation_id,
            id: 0,
            code,
            message,
        })
        .encode(&mut out)
        .unwrap();
        out.truncate(length);
        self.answer(out);
    }

    /// The correlation id of the last query sent.
    fn last_correlation(&self) -> u64 {
        let sent = self.sent.lock().unwrap();
        match DurabilityMessage::decode(sent.last().unwrap()).unwrap() {
            DurabilityMessage::QueryDurable(query) => query.correlation_id,
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn test_durable_query_answer_is_matched_by_correlation() {
    let wire = Wire::default();
    let mut query = DurableQuery::new(0x5155_4552, wire.clone(), wire.clone());
    assert_eq!(query.poll(), DurablePoll::Idle);
    query.ask(42);
    assert_eq!(query.poll(), DurablePoll::Pending);
    let correlation_id = wire.last_correlation();
    assert_eq!(correlation_id >> 32, 0x5155_4552);
    // Another requester's answer, then a signal-like response, are
    // skipped; this one's is taken.
    wire.answer(encoded(&DurabilityMessage::DurablePosition(
        DurableAnswer {
            correlation_id: correlation_id + 1,
            position: position(),
        },
    )));
    wire.respond(0, ResponseCode::Ok, "");
    wire.answer(encoded(&DurabilityMessage::DurablePosition(
        DurableAnswer {
            correlation_id,
            position: position(),
        },
    )));
    assert_eq!(query.poll(), DurablePoll::Done(position()));
    assert_eq!(query.poll(), DurablePoll::Idle);
}

#[test]
fn test_durable_query_refusals_are_typed() {
    let wire = Wire::default();
    let mut query = DurableQuery::new(1, wire.clone(), wire.clone());
    query.ask(9);
    assert_eq!(query.poll(), DurablePoll::Pending);
    wire.respond(
        wire.last_correlation(),
        ResponseCode::UnknownRecording,
        "no such recording",
    );
    assert_eq!(
        query.poll(),
        DurablePoll::Refused {
            code: ResponseCode::UnknownRecording,
            message: "no such recording".to_owned()
        }
    );
}

/// An Archive that does not know schema 4 answers its unknown tuple with
/// code 5; the querier reports that durable acknowledgement is
/// unsupported, never a durable position of 0.
#[test]
fn test_durable_query_an_archive_without_schema_4_is_unsupported() {
    let wire = Wire::default();
    let mut query = DurableQuery::new(1, wire.clone(), wire.clone());
    query.ask(9);
    assert_eq!(query.poll(), DurablePoll::Pending);
    wire.respond(
        wire.last_correlation(),
        ResponseCode::UnsupportedSchema,
        "unsupported schema 4",
    );
    assert_eq!(query.poll(), DurablePoll::Unsupported);
}

/// Hex bytes, whitespace ignored.
fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

const GOLDEN_QUERY: &str = "04 00 01 00 01 00 10 00 1c 00 00 00
    08 07 06 05 04 03 02 01
    2a 00 00 00 00 00 00 00";

const GOLDEN_RECORDING: &str = "04 00 02 00 01 00 2a 00 36 00 00 00
    08 07 06 05 04 03 02 01
    2a 00 00 00 00 00 00 00
    00 10 00 00 00 00 00 00
    00 00 03 00 00 00 00 00
    00 00 02 00 00 00 00 00
    01
    01";

const GOLDEN_STOPPED: &str = "04 00 02 00 01 00 2a 00 36 00 00 00
    07 00 00 00 00 00 00 00
    01 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00
    34 12 00 00 00 00 00 00
    34 12 00 00 00 00 00 00
    02
    00";

const GOLDEN_UNSUPPORTED: &str = "01 00 65 00 01 00 11 00 1f 00 00 00
    08 07 06 05 04 03 02 01
    00 00 00 00 00 00 00 00
    05
    00 00";

/// The golden vectors QS-REVIEWER derived from the note's text alone,
/// before this code existed (quantstratum-docs#598), reproduced byte for
/// byte, both ways.
#[test]
fn test_durable_codec_reproduces_the_golden_vectors() {
    let golden = [
        (
            GOLDEN_QUERY,
            DurabilityMessage::QueryDurable(QueryDurable {
                correlation_id: 0x0102_0304_0506_0708,
                recording_id: 42,
            }),
        ),
        (
            GOLDEN_RECORDING,
            DurabilityMessage::DurablePosition(DurableAnswer {
                correlation_id: 0x0102_0304_0506_0708,
                position: DurablePosition {
                    recording_id: 42,
                    start: 0x1000,
                    written: 0x3_0000,
                    durable: 0x2_0000,
                    state: DurableState::Recording,
                    sync: DurableSync::PerSegment,
                },
            }),
        ),
        (
            GOLDEN_STOPPED,
            DurabilityMessage::DurablePosition(DurableAnswer {
                correlation_id: 7,
                position: DurablePosition {
                    recording_id: 1,
                    start: 0,
                    written: 0x1234,
                    durable: 0x1234,
                    state: DurableState::Stopped,
                    sync: DurableSync::None,
                },
            }),
        ),
    ];
    for (text, message) in golden {
        let bytes = hex(text);
        assert_eq!(encoded(&message), bytes, "{message:?}");
        assert_eq!(DurabilityMessage::decode(&bytes).unwrap(), message);
    }
    // An Archive without schema 4 answers that query with code 5, and the
    // querier reads it as unsupported.
    let bytes = hex(GOLDEN_UNSUPPORTED);
    let ControlMessage::ControlResponse(response) = ControlMessage::decode(&bytes).unwrap() else {
        panic!("a response");
    };
    assert_eq!(
        (response.correlation_id, response.id, response.code),
        (0x0102_0304_0506_0708, 0, ResponseCode::UnsupportedSchema)
    );
    let wire = Wire::default();
    let mut query = DurableQuery::new(0x0102_0304, wire.clone(), wire.clone());
    // Its first correlation id is 0x0102030400000001: answer the golden
    // one's, with this querier's id.
    query.ask(42);
    assert_eq!(query.poll(), DurablePoll::Pending);
    let mut answer = bytes.clone();
    answer[12..20].copy_from_slice(&wire.last_correlation().to_le_bytes());
    wire.answer(answer);
    assert_eq!(query.poll(), DurablePoll::Unsupported);
}

/// The reviewer's mutation table of the recording vector.
#[test]
fn test_durable_codec_refuses_the_golden_mutations() {
    let golden = hex(GOLDEN_RECORDING);
    let mutated = |offset: usize, bytes: &[u8]| {
        let mut message = golden.clone();
        message[offset..offset + bytes.len()].copy_from_slice(bytes);
        DurabilityMessage::decode(&message)
    };
    let durable = CodecError::ValueOutOfRange { field: "durable" };
    assert_eq!(mutated(44, &0x4_0000u64.to_le_bytes()), Err(durable));
    assert_eq!(mutated(44, &0x0800u64.to_le_bytes()), Err(durable));
    assert_eq!(mutated(52, &[2]), Err(durable));
    for state in [0, 3] {
        assert_eq!(
            mutated(52, &[state]),
            Err(CodecError::InvalidEnum {
                field: "state",
                value: state.into()
            })
        );
    }
    assert_eq!(
        mutated(53, &[3]),
        Err(CodecError::InvalidEnum {
            field: "sync_policy",
            value: 3
        })
    );
    let recording = CodecError::ValueOutOfRange {
        field: "recording_id",
    };
    assert_eq!(mutated(20, &0u64.to_le_bytes()), Err(recording));
    let mut query = hex(GOLDEN_QUERY);
    query[20..28].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(DurabilityMessage::decode(&query), Err(recording));
    for (offset, value) in [(6, 41u16), (4, 2)] {
        assert!(matches!(
            mutated(offset, &value.to_le_bytes()),
            Err(CodecError::UnsupportedSchema { .. })
        ));
    }
    assert!(matches!(
        mutated(8, &0u32.to_le_bytes()),
        Err(CodecError::MessageLength { .. })
    ));
    assert!(matches!(
        DurabilityMessage::decode(&golden[..53]),
        Err(CodecError::MessageLength { .. })
    ));
    let mut long = golden.clone();
    long.push(0);
    long[8..12].copy_from_slice(&55u32.to_le_bytes());
    assert!(matches!(
        DurabilityMessage::decode(&long),
        Err(CodecError::MessageLength { .. })
    ));
}
