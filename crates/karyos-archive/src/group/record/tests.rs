// SPDX-License-Identifier: Apache-2.0

// Recording group records: a golden vector per template, built byte by
// byte from the design note's tables; a sample of every template and enum
// value round trip; truncation at every boundary; every invalid field as
// a mutated vector; and arbitrary bytes that never panic.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use proptest::prelude::*;

use super::*;

fn lane(value: u8) -> Lane {
    Lane::try_new(value).unwrap()
}

fn encoded(record: &GroupRecord<'_>) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = record.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

/// A record built from the tables, independent of the encoder: the
/// envelope, the block, then the variable field when there is one.
fn vector(template: &Template, block: &[u8], value: Option<&[u8]>) -> Vec<u8> {
    assert_eq!(block.len(), usize::from(template.block_length));
    let length = 12 + block.len() + value.map_or(0, |value| 2 + value.len());
    let mut out = Vec::new();
    out.extend_from_slice(&template.schema_id.to_le_bytes());
    out.extend_from_slice(&template.template_id.to_le_bytes());
    out.extend_from_slice(&template.version.to_le_bytes());
    out.extend_from_slice(&template.block_length.to_le_bytes());
    out.extend_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    out.extend_from_slice(block);
    if let Some(value) = value {
        out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// A block written field by field at the tables' offsets.
struct Fields(Vec<u8>);

impl Fields {
    fn new(length: u16) -> Self {
        Self(vec![0; usize::from(length)])
    }
    fn u64(mut self, at: usize, value: u64) -> Self {
        self.0[at..at + 8].copy_from_slice(&value.to_le_bytes());
        self
    }
    fn u32(mut self, at: usize, value: u32) -> Self {
        self.0[at..at + 4].copy_from_slice(&value.to_le_bytes());
        self
    }
    fn i32(mut self, at: usize, value: i32) -> Self {
        self.0[at..at + 4].copy_from_slice(&value.to_le_bytes());
        self
    }
    fn u16(mut self, at: usize, value: u16) -> Self {
        self.0[at..at + 2].copy_from_slice(&value.to_le_bytes());
        self
    }
    fn u8(mut self, at: usize, value: u8) -> Self {
        self.0[at] = value;
        self
    }
}

/// Each template's golden vector and the record it decodes to.
fn goldens() -> Vec<(Vec<u8>, GroupRecord<'static>)> {
    vec![
        (
            vector(
                &JOURNAL_HEADER,
                &Fields::new(24)
                    .u64(0, 7)
                    .u64(8, 1)
                    .u32(16, 4096)
                    .u16(20, 1)
                    .u8(22, 1)
                    .u8(23, 2)
                    .0,
                Some(b"build 42"),
            ),
            GroupRecord::Header(JournalHeader {
                group_id: 7,
                first_group_seq: 1,
                inline_threshold: 4096,
                contract_version: 1,
                clock: Clock::HostMonotonic,
                capture: Capture::BestEffort,
                manifest: b"build 42",
            }),
        ),
        (
            vector(
                &MESSAGE_EVENT,
                &Fields::new(58)
                    .u64(0, 1)
                    .u64(8, 1_000)
                    .u64(16, 2)
                    .u64(24, 4096)
                    .u64(32, 0)
                    .u32(40, 3)
                    .u32(44, 64)
                    .i32(48, 10)
                    .i32(52, -3)
                    .u8(56, 1)
                    .u8(57, 1)
                    .0,
                Some(b"abc"),
            ),
            GroupRecord::Message(MessageEvent {
                group_seq: 1,
                logical_time: 1_000,
                incarnation: 2,
                position: 4096,
                extent: 64,
                stream_id: 10,
                session_id: -3,
                lane: lane(1),
                payload: Payload::Inline(b"abc"),
            }),
        ),
        (
            vector(
                &MESSAGE_EVENT,
                &Fields::new(58)
                    .u64(0, 2)
                    .u64(8, 2_000)
                    .u64(16, 2)
                    .u64(24, 8192)
                    .u64(32, 9)
                    .u32(40, 5000)
                    .u32(44, 5056)
                    .i32(48, 10)
                    .i32(52, 3)
                    .u8(56, 0)
                    .u8(57, 2)
                    .0,
                Some(b""),
            ),
            GroupRecord::Message(MessageEvent {
                group_seq: 2,
                logical_time: 2_000,
                incarnation: 2,
                position: 8192,
                extent: 5056,
                stream_id: 10,
                session_id: 3,
                lane: lane(0),
                payload: Payload::Reference {
                    recording_id: 9,
                    length: 5000,
                },
            }),
        ),
        (
            vector(
                &CONFLATED_EVENT,
                &Fields::new(45)
                    .u64(0, 3)
                    .u64(8, 3_000)
                    .u64(16, 11)
                    .u64(24, 640)
                    .u32(32, 5)
                    .i32(36, 20)
                    .i32(40, 4)
                    .u8(44, 2)
                    .0,
                Some(b"v"),
            ),
            GroupRecord::Conflated(ConflatedEvent {
                group_seq: 3,
                logical_time: 3_000,
                version: 11,
                key: 5,
                stream_id: 20,
                session_id: 4,
                freshness: Freshness::Stale { since: 640 },
                value: b"v",
            }),
        ),
        (
            vector(
                &TIMER_EVENT,
                &Fields::new(24).u64(0, 4).u64(8, 5_000).u64(16, 77).0,
                None,
            ),
            GroupRecord::Timer(TimerEvent {
                group_seq: 4,
                logical_time: 5_000,
                timer_id: 77,
            }),
        ),
        (
            vector(
                &LIFECYCLE_EVENT,
                &Fields::new(41)
                    .u64(0, 5)
                    .u64(8, 6_000)
                    .u64(16, 3)
                    .u64(24, 0)
                    .i32(32, 10)
                    .i32(36, 3)
                    .u8(40, 1)
                    .0,
                None,
            ),
            GroupRecord::Lifecycle(LifecycleEvent {
                group_seq: 5,
                logical_time: 6_000,
                incarnation: 3,
                position: 0,
                stream_id: 10,
                session_id: 3,
                kind: LifecycleKind::ImageAvailable,
            }),
        ),
        (
            vector(
                &EXTERNAL_EVENT,
                &Fields::new(20).u64(0, 6).u64(8, 7_000).u32(16, 0xBEEF).0,
                Some(b"fill"),
            ),
            GroupRecord::External(ExternalEvent {
                group_seq: 6,
                logical_time: 7_000,
                kind: 0xBEEF,
                value: b"fill",
            }),
        ),
        (
            vector(
                &OUTCOME_OBSERVATION,
                &Fields::new(31)
                    .u64(0, 6)
                    .u64(8, 1024)
                    .u32(16, 0)
                    .i32(20, 30)
                    .i32(24, 1)
                    .u8(28, 1)
                    .u8(29, 1)
                    .u8(30, 2)
                    .0,
                None,
            ),
            GroupRecord::Outcome(OutcomeObservation {
                group_seq: 6,
                index: 0,
                stream_id: 30,
                session_id: 1,
                operation: Operation::Offer,
                outcome: Outcome::Accepted {
                    lane: lane(2),
                    position: 1024,
                },
            }),
        ),
        (
            vector(
                &TIMER_OBSERVATION,
                &Fields::new(29)
                    .u64(0, 6)
                    .u64(8, 78)
                    .u64(16, 9_000)
                    .u32(24, 1)
                    .u8(28, 1)
                    .0,
                None,
            ),
            GroupRecord::TimerOperation(TimerObservation {
                group_seq: 6,
                index: 1,
                timer_id: 78,
                deadline: 9_000,
                action: TimerAction::Create,
            }),
        ),
        (
            vector(
                &EXTERNAL_OBSERVATION,
                &Fields::new(16).u64(0, 6).u32(8, 2).u32(12, 1).0,
                Some(b"ack"),
            ),
            GroupRecord::ExternalObservation(ExternalObservation {
                group_seq: 6,
                index: 2,
                kind: 1,
                value: b"ack",
            }),
        ),
        (
            vector(
                &EVENT_END,
                &Fields::new(13).u64(0, 6).u32(8, 3).u8(12, 1).0,
                None,
            ),
            GroupRecord::End(EventEnd {
                group_seq: 6,
                observations: 3,
                outcome: EndOutcome::Complete,
            }),
        ),
        (
            vector(
                &GAP_MARKER,
                &Fields::new(17).u64(0, 7).u64(8, 9).u8(16, 2).0,
                None,
            ),
            GroupRecord::Gap(GapMarker {
                from_seq: 7,
                to_seq: 9,
                reason: GapReason::RingFull,
            }),
        ),
    ]
}

#[test]
fn every_template_has_its_golden_vector() {
    for (bytes, record) in goldens() {
        assert_eq!(GroupRecord::decode(&bytes).unwrap(), record, "{record:?}");
        assert_eq!(encoded(&record), bytes, "{record:?}");
    }
}

/// One record of every template, every enum value among them.
fn samples() -> Vec<GroupRecord<'static>> {
    let mut samples: Vec<GroupRecord<'static>> =
        goldens().into_iter().map(|(_, record)| record).collect();
    samples.push(GroupRecord::Header(JournalHeader {
        group_id: u64::MAX,
        first_group_seq: u64::MAX,
        inline_threshold: 65_535,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        manifest: &[0xAB; MAX_MANIFEST],
    }));
    samples.push(GroupRecord::Message(MessageEvent {
        group_seq: u64::MAX,
        logical_time: u64::MAX,
        incarnation: u64::MAX,
        position: u64::MAX,
        extent: u32::MAX - 31,
        stream_id: i32::MIN,
        session_id: i32::MAX,
        lane: lane(3),
        payload: Payload::Inline(&[7; MAX_INLINE]),
    }));
    samples.push(GroupRecord::Message(MessageEvent {
        group_seq: 9,
        logical_time: 0,
        incarnation: 0,
        position: 0,
        extent: 32,
        stream_id: 0,
        session_id: 0,
        lane: lane(0),
        payload: Payload::Inline(b""),
    }));
    samples.push(GroupRecord::Conflated(ConflatedEvent {
        group_seq: 1,
        logical_time: 1,
        version: 1,
        key: u32::MAX,
        stream_id: 1,
        session_id: 1,
        freshness: Freshness::Fresh,
        value: b"",
    }));
    samples.push(GroupRecord::Conflated(ConflatedEvent {
        group_seq: 1,
        logical_time: 1,
        version: 1,
        key: 0,
        stream_id: 1,
        session_id: 1,
        freshness: Freshness::Stale { since: 0 },
        value: b"stale",
    }));
    for kind in [
        LifecycleKind::ImageUnavailable,
        LifecycleKind::SubscriptionEnded,
    ] {
        samples.push(GroupRecord::Lifecycle(LifecycleEvent {
            group_seq: 1,
            logical_time: 1,
            incarnation: 1,
            position: 1 << 40,
            stream_id: 1,
            session_id: 1,
            kind,
        }));
    }
    let outcomes = [
        (Operation::Offer, Outcome::BackPressured),
        (Operation::Offer, Outcome::AdminAction),
        (Operation::Offer, Outcome::NotConnected),
        (Operation::Offer, Outcome::Closed),
        (Operation::Offer, Outcome::Gated),
        (Operation::Offer, Outcome::RateLimited),
        (Operation::Offer, Outcome::Failed),
        (
            Operation::Claim,
            Outcome::Accepted {
                lane: lane(0),
                position: 0,
            },
        ),
        (
            Operation::Claim,
            Outcome::Aborted {
                lane: lane(3),
                position: u64::MAX,
            },
        ),
        (Operation::Claim, Outcome::Gated),
    ];
    for (index, (operation, outcome)) in (0u32..).zip(outcomes) {
        samples.push(GroupRecord::Outcome(OutcomeObservation {
            group_seq: 2,
            index,
            stream_id: -1,
            session_id: -2,
            operation,
            outcome,
        }));
    }
    samples.push(GroupRecord::TimerOperation(TimerObservation {
        group_seq: 2,
        index: u32::MAX,
        timer_id: u64::MAX,
        deadline: 0,
        action: TimerAction::Cancel,
    }));
    samples.push(GroupRecord::End(EventEnd {
        group_seq: 2,
        observations: 0,
        outcome: EndOutcome::Incomplete,
    }));
    for reason in [GapReason::BudgetExceeded, GapReason::PayloadUnavailable] {
        samples.push(GroupRecord::Gap(GapMarker {
            from_seq: 3,
            to_seq: 3,
            reason,
        }));
    }
    samples
}

#[test]
fn every_sample_round_trips() {
    for record in samples() {
        let bytes = encoded(&record);
        assert_eq!(GroupRecord::decode(&bytes).unwrap(), record);
    }
}

/// Every prefix of a valid record is refused, as is the record with a
/// trailing byte; an encoder given a buffer one byte short writes nothing
/// a decoder accepts.
#[test]
fn every_truncation_is_refused() {
    for record in samples() {
        let bytes = encoded(&record);
        for cut in 0..bytes.len() {
            assert!(
                GroupRecord::decode(&bytes[..cut]).is_err(),
                "{record:?} at {cut}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(GroupRecord::decode(&longer).is_err());
        let mut short = vec![0xFFu8; bytes.len() - 1];
        assert!(matches!(
            record.encode(&mut short),
            Err(CodecError::Truncated { .. })
        ));
        assert!(GroupRecord::decode(&short).is_err());
    }
}

#[test]
fn unsupported_tuples_are_refused() {
    let (bytes, _) = goldens().remove(0);
    for (at, value) in [(0, 1u16), (0, 2), (2, 7), (2, 30), (4, 2)] {
        let mut mutated = bytes.clone();
        mutated[at..at + 2].copy_from_slice(&value.to_le_bytes());
        assert!(
            matches!(
                GroupRecord::decode(&mutated),
                Err(CodecError::UnsupportedSchema { .. })
            ),
            "{at} = {value}"
        );
    }
}

/// The golden vector of `template_id`, with the block byte at `at` set to
/// `value`; or with the u64 at `at` set when `wide`.
fn mutated(template_id: u16, at: usize, value: u64, wide: bool) -> Vec<u8> {
    let (mut bytes, _) = goldens()
        .into_iter()
        .find(|(bytes, _)| bytes[2..4] == template_id.to_le_bytes())
        .unwrap();
    let at = 12 + at;
    if wide {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    } else {
        bytes[at] = u8::try_from(value).unwrap();
    }
    bytes
}

fn refused(bytes: &[u8]) -> CodecError {
    GroupRecord::decode(bytes).unwrap_err()
}

#[test]
fn every_invalid_field_is_refused() {
    let out_of_range = |field| CodecError::ValueOutOfRange { field };
    let invalid = |field, value| CodecError::InvalidEnum { field, value };
    // Header.
    assert_eq!(refused(&mutated(1, 0, 0, true)), out_of_range("group_id"));
    assert_eq!(
        refused(&mutated(1, 8, 0, true)),
        out_of_range("first_group_seq")
    );
    for value in [0u32, 65_536] {
        let mut threshold = mutated(1, 0, 7, true);
        threshold[12 + 16..12 + 20].copy_from_slice(&value.to_le_bytes());
        assert_eq!(refused(&threshold), out_of_range("inline_threshold"));
    }
    assert_eq!(
        refused(&mutated(1, 20, 2, false)),
        out_of_range("contract_version")
    );
    assert_eq!(refused(&mutated(1, 22, 0, false)), invalid("clock", 0));
    assert_eq!(refused(&mutated(1, 22, 2, false)), invalid("clock", 2));
    assert_eq!(refused(&mutated(1, 23, 3, false)), invalid("capture", 3));
    let empty = vector(
        &JOURNAL_HEADER,
        &Fields::new(24)
            .u64(0, 1)
            .u64(8, 1)
            .u32(16, 1)
            .u16(20, 1)
            .u8(22, 1)
            .u8(23, 1)
            .0,
        Some(b""),
    );
    assert!(matches!(
        refused(&empty),
        CodecError::LengthOutOfRange {
            field: "manifest",
            ..
        }
    ));
    // Message.
    assert_eq!(refused(&mutated(2, 0, 0, true)), out_of_range("group_seq"));
    assert_eq!(refused(&mutated(2, 56, 4, false)), out_of_range("lane"));
    assert_eq!(refused(&mutated(2, 57, 0, false)), invalid("payload", 0));
    assert_eq!(refused(&mutated(2, 57, 3, false)), invalid("payload", 3));
    // An inline payload naming a recording, or not of its length.
    assert_eq!(
        refused(&mutated(2, 32, 9, true)),
        out_of_range("recording_id")
    );
    let mut length = mutated(2, 0, 1, true);
    length[12 + 40] = 4;
    assert_eq!(refused(&length), out_of_range("length"));
    // A reference with no recording, or with a value.
    let (reference, _) = goldens().remove(2);
    let mut no_recording = reference.clone();
    no_recording[12 + 32..12 + 40].fill(0);
    assert_eq!(refused(&no_recording), out_of_range("recording_id"));
    let mut with_value = reference[..reference.len() - 2].to_vec();
    with_value.extend_from_slice(&1u16.to_le_bytes());
    with_value.push(0);
    let total = u32::try_from(with_value.len()).unwrap();
    with_value[8..12].copy_from_slice(&total.to_le_bytes());
    assert!(matches!(
        refused(&with_value),
        CodecError::LengthOutOfRange { field: "value", .. }
    ));
    // Extents: zero, unaligned, below the payload.
    for extent in [0u32, 48, 2048] {
        let mut bytes = reference.clone();
        bytes[12 + 44..12 + 48].copy_from_slice(&extent.to_le_bytes());
        assert_eq!(refused(&bytes), out_of_range("extent"), "{extent}");
    }
    // Conflated: freshness, and a fresh value with a gap start.
    assert_eq!(refused(&mutated(3, 44, 0, false)), invalid("freshness", 0));
    assert_eq!(
        refused(&mutated(3, 44, 1, false)),
        out_of_range("stale_since")
    );
    // Timer and lifecycle.
    assert_eq!(refused(&mutated(4, 16, 0, true)), out_of_range("timer_id"));
    assert_eq!(refused(&mutated(5, 40, 4, false)), invalid("kind", 4));
    // Outcomes: enums, an aborted offer, and a position or lane on an
    // outcome that has none.
    assert_eq!(refused(&mutated(11, 28, 3, false)), invalid("operation", 3));
    assert_eq!(refused(&mutated(11, 29, 10, false)), invalid("outcome", 10));
    assert_eq!(refused(&mutated(11, 29, 8, false)), out_of_range("outcome"));
    assert_eq!(
        refused(&mutated(11, 29, 2, false)),
        out_of_range("position")
    );
    let mut lane_only = mutated(11, 8, 0, true);
    lane_only[12 + 29] = 6;
    assert_eq!(refused(&lane_only), out_of_range("lane"));
    assert_eq!(refused(&mutated(11, 30, 4, false)), out_of_range("lane"));
    // Timer operation, end and gap.
    assert_eq!(refused(&mutated(12, 8, 0, true)), out_of_range("timer_id"));
    assert_eq!(refused(&mutated(12, 28, 3, false)), invalid("action", 3));
    assert_eq!(refused(&mutated(20, 12, 0, false)), invalid("outcome", 0));
    assert_eq!(refused(&mutated(21, 8, 6, true)), out_of_range("to_seq"));
    assert_eq!(refused(&mutated(21, 0, 0, true)), out_of_range("from_seq"));
    assert_eq!(refused(&mutated(21, 16, 4, false)), invalid("reason", 4));
}

/// What a decoder refuses, an encoder refuses to write.
#[test]
fn invalid_values_are_not_encoded() {
    let mut out = vec![0u8; MAX_RECORD];
    let bad: Vec<GroupRecord<'static>> = vec![
        GroupRecord::Header(JournalHeader {
            group_id: 1,
            first_group_seq: 1,
            inline_threshold: 0,
            contract_version: 1,
            clock: Clock::HostMonotonic,
            capture: Capture::Strict,
            manifest: b"m",
        }),
        GroupRecord::Message(MessageEvent {
            group_seq: 1,
            logical_time: 0,
            incarnation: 0,
            position: 0,
            extent: 32,
            stream_id: 0,
            session_id: 0,
            lane: lane(0),
            payload: Payload::Inline(&[0; 33]),
        }),
        GroupRecord::Message(MessageEvent {
            group_seq: 1,
            logical_time: 0,
            incarnation: 0,
            position: 0,
            extent: 64,
            stream_id: 0,
            session_id: 0,
            lane: lane(0),
            payload: Payload::Reference {
                recording_id: 0,
                length: 1,
            },
        }),
        GroupRecord::Outcome(OutcomeObservation {
            group_seq: 1,
            index: 0,
            stream_id: 0,
            session_id: 0,
            operation: Operation::Offer,
            outcome: Outcome::Aborted {
                lane: lane(0),
                position: 0,
            },
        }),
        GroupRecord::Gap(GapMarker {
            from_seq: 2,
            to_seq: 1,
            reason: GapReason::RingFull,
        }),
        GroupRecord::Timer(TimerEvent {
            group_seq: 0,
            logical_time: 0,
            timer_id: 1,
        }),
    ];
    for record in bad {
        assert!(record.encode(&mut out).is_err(), "{record:?}");
        // Nothing a decoder accepts is left behind.
        assert!(GroupRecord::decode(&out).is_err(), "{record:?}");
    }
}

#[test]
fn every_record_knows_its_role() {
    let roles: Vec<Role> = goldens().iter().map(|(_, record)| record.role()).collect();
    assert_eq!(
        roles,
        vec![
            Role::Header {
                capture: Capture::BestEffort,
                first_group_seq: 1
            },
            Role::Event(1),
            Role::Event(2),
            Role::Event(3),
            Role::Event(4),
            Role::Event(5),
            Role::Event(6),
            Role::Observation(6, 0),
            Role::Observation(6, 1),
            Role::Observation(6, 2),
            Role::End(EventEnd {
                group_seq: 6,
                observations: 3,
                outcome: EndOutcome::Complete
            }),
            Role::Gap(GapMarker {
                from_seq: 7,
                to_seq: 9,
                reason: GapReason::RingFull
            }),
        ]
    );
}

proptest! {
    #[test]
    fn message_events_round_trip(
        group_seq in 1u64..,
        logical_time in any::<u64>(),
        incarnation in any::<u64>(),
        position in any::<u64>(),
        stream_id in any::<i32>(),
        session_id in any::<i32>(),
        lane_value in 0u8..4,
        value in proptest::collection::vec(any::<u8>(), 0..512),
        recording in proptest::option::of((1u64.., any::<u32>())),
        pad in 0u32..64,
    ) {
        let payload = match recording {
            Some((recording_id, length)) => Payload::Reference { recording_id, length },
            None => Payload::Inline(&value),
        };
        let length = match payload {
            Payload::Inline(value) => u32::try_from(value.len()).unwrap(),
            Payload::Reference { length, .. } => length,
        };
        let extent = u64::from(length)
            .next_multiple_of(32)
            .max(32)
            .checked_add(u64::from(pad) * 32)
            .and_then(|extent| u32::try_from(extent).ok());
        prop_assume!(extent.is_some());
        let record = GroupRecord::Message(MessageEvent {
            group_seq,
            logical_time,
            incarnation,
            position,
            extent: extent.unwrap(),
            stream_id,
            session_id,
            lane: lane(lane_value),
            payload,
        });
        let bytes = encoded(&record);
        prop_assert_eq!(GroupRecord::decode(&bytes).unwrap(), record);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = GroupRecord::decode(&bytes);
    }

    #[test]
    fn arbitrary_blocks_of_every_template_never_panic(
        template in 0usize..11,
        block in proptest::collection::vec(any::<u8>(), 58),
        value in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        let templates = [
            JOURNAL_HEADER, MESSAGE_EVENT, CONFLATED_EVENT, TIMER_EVENT,
            LIFECYCLE_EVENT, EXTERNAL_EVENT, OUTCOME_OBSERVATION,
            TIMER_OBSERVATION, EXTERNAL_OBSERVATION, EVENT_END, GAP_MARKER,
        ];
        let template = templates[template];
        let block = &block[..usize::from(template.block_length)];
        let _ = GroupRecord::decode(&vector(&template, block, Some(&value)));
        let _ = GroupRecord::decode(&vector(&template, block, None));
    }
}
