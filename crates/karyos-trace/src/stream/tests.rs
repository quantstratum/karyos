// SPDX-License-Identifier: Apache-2.0

//! The trace stream's golden vectors and round trips (ADR-0117,
//! Validation).

use super::*;

/// The bytes of `words`, little-endian.
fn bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn encoded(message: &StreamMessage) -> Vec<u8> {
    let mut out = [0u8; MAX_MESSAGE_BYTES];
    let length = message.encode(&mut out).unwrap();
    out[..length].to_vec()
}

fn self_message() -> StreamMessage {
    StreamMessage::DriverSelf(DriverSelf {
        namespace: 1,
        namespace_inode: 0x1000_0000_EFFF_FFFB,
        clock: [0, 0, 0, 5, 0x0123_4567_89AB_CDEF],
        granularity: 1000,
    })
}

/// The header word of each kind, and a self message byte for byte.
#[test]
fn the_self_message_matches_its_golden_vector() {
    let expected = concat!(
        "4b54525301010000",
        "0100000000000000",
        "fbffffef00000010",
        "0000000000000000",
        "0000000000000000",
        "0000000000000000",
        "0500000000000000",
        "efcdab8967452301",
        "e803000000000000",
    );
    let hex: String = encoded(&self_message())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(hex, expected);
    assert_eq!(
        StreamMessage::decode(&encoded(&self_message())).unwrap(),
        self_message()
    );
}

#[test]
fn facts_record_and_loss_match_their_golden_vectors() {
    let facts = StreamMessage::Facts(JournalFacts {
        journal: 7,
        generation: 2,
        kind: 1,
        time_namespace: 1,
        provenance: 2,
    });
    assert_eq!(
        encoded(&facts),
        bytes(&[0x0000_0201_5352_544B, 7, 2, 1, 1, 2])
    );
    let mut words = [0u64; RECORD_WORDS];
    for (index, word) in words.iter_mut().enumerate() {
        *word = 0x100 + index as u64;
    }
    let record = StreamMessage::Record(StreamRecord {
        journal: 7,
        generation: 2,
        sequence: 41,
        words,
    });
    let mut expected = vec![0x0000_0301_5352_544B, 7, 2, 41];
    expected.extend(words);
    assert_eq!(encoded(&record), bytes(&expected));
    assert_eq!(encoded(&record).len(), 232);
    let loss = StreamMessage::Loss(StreamLoss {
        journal: 0,
        first: 10,
        last: 19,
    });
    assert_eq!(encoded(&loss), bytes(&[0x0000_0401_5352_544B, 0, 10, 19]));
    for message in [facts, record, loss] {
        assert_eq!(StreamMessage::decode(&encoded(&message)).unwrap(), message);
        assert_eq!(encoded(&message).len(), message.length());
    }
}

/// The requirement message (kind 5), byte for byte.
#[test]
fn the_requirement_message_matches_its_golden_vector() {
    let requirement = StreamMessage::Requirement(TimeRequirement {
        domain: 5,
        max_divergence_ns: 1_000_000,
        max_granularity_ns: 1000,
    });
    assert_eq!(
        encoded(&requirement),
        bytes(&[0x0000_0501_5352_544B, 5, 1_000_000, 1000])
    );
    assert_eq!(
        StreamMessage::decode(&encoded(&requirement)).unwrap(),
        requirement
    );
    assert_eq!(
        StreamMessage::decode(&bytes(&[0x0000_0501_5352_544B, 5, 1])),
        Err(StreamError::Length { length: 24 })
    );
}

#[test]
fn a_malformed_message_is_refused() {
    let good = encoded(&self_message());
    // Truncated, not whole words, or one word too many.
    assert!(matches!(
        StreamMessage::decode(&good[..good.len() - 8]),
        Err(StreamError::Length { .. })
    ));
    assert!(matches!(
        StreamMessage::decode(&good[..good.len() - 1]),
        Err(StreamError::Length { .. })
    ));
    let mut long = good.clone();
    long.extend([0u8; 8]);
    assert!(matches!(
        StreamMessage::decode(&long),
        Err(StreamError::Length { .. })
    ));
    assert!(matches!(
        StreamMessage::decode(&[]),
        Err(StreamError::Length { .. })
    ));
    // Another magic, version, or a reserved header bit.
    for (byte, bit) in [(0, 1), (4, 2), (7, 1)] {
        let mut bad = good.clone();
        bad[byte] ^= bit;
        assert_eq!(StreamMessage::decode(&bad), Err(StreamError::Header));
    }
    let mut kind = good.clone();
    kind[5] = 9;
    assert_eq!(
        StreamMessage::decode(&kind),
        Err(StreamError::Kind { kind: 9 })
    );
    // Fields out of range, refused both ways.
    let zero_generation = StreamMessage::Facts(JournalFacts {
        journal: 7,
        generation: 0,
        kind: 1,
        time_namespace: 1,
        provenance: 2,
    });
    let mut out = [0u8; MAX_MESSAGE_BYTES];
    assert_eq!(zero_generation.encode(&mut out), Err(StreamError::Field));
    assert_eq!(
        StreamMessage::decode(&bytes(&[0x0000_0201_5352_544B, 7, 0, 1, 1, 2])),
        Err(StreamError::Field)
    );
    assert_eq!(
        StreamMessage::decode(&bytes(&[0x0000_0401_5352_544B, 3, 5, 4])),
        Err(StreamError::Field)
    );
    let record = bytes(
        &[0x0000_0301_5352_544B, 0, 1, 1]
            .into_iter()
            .chain([0; RECORD_WORDS])
            .collect::<Vec<_>>(),
    );
    assert_eq!(StreamMessage::decode(&record), Err(StreamError::Field));
    // A buffer shorter than the message.
    assert_eq!(
        self_message().encode(&mut [0u8; 71]),
        Err(StreamError::Short { need: 72, have: 71 })
    );
}
