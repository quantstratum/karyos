// SPDX-License-Identifier: Apache-2.0

// Recording group records: a golden vector per template, built byte by
// byte from the design note's tables with the schema, template and
// version written as literals; a sample of every template and enum value
// round trip; truncation at every boundary; every invalid field as a
// mutated vector; and arbitrary bytes that never panic.

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

/// A record built from the tables, independent of the code: schema 3,
/// `template` and version 1 as literals, the block, then each variable
/// field with its length prefix.
fn vector(template: u16, block: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let length = 12 + block.len() + fields.iter().map(|field| 2 + field.len()).sum::<usize>();
    let mut out = Vec::new();
    out.extend_from_slice(&3u16.to_le_bytes());
    out.extend_from_slice(&template.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&u16::try_from(block.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    out.extend_from_slice(block);
    for field in fields {
        out.extend_from_slice(&u16::try_from(field.len()).unwrap().to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// A block written field by field at the tables' offsets.
struct Fields(Vec<u8>);

impl Fields {
    fn new(length: usize) -> Self {
        Self(vec![0; length])
    }
    fn u64(mut self, at: usize, value: u64) -> Self {
        self.0[at..at + 8].copy_from_slice(&value.to_le_bytes());
        self
    }
    fn i64(mut self, at: usize, value: i64) -> Self {
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

const EXTENSION_BYTES: [u8; EXTENSION] = [0x5A; EXTENSION];

/// Each template's golden vector and the record it decodes to.
#[allow(clippy::too_many_lines, reason = "one vector per template")]
fn goldens() -> Vec<(Vec<u8>, GroupRecord<'static>)> {
    vec![
        (
            vector(
                1,
                &Fields::new(24)
                    .u64(0, 7)
                    .u64(8, 1)
                    .u32(16, 4096)
                    .u16(20, 1)
                    .u8(22, 1)
                    .u8(23, 2)
                    .0,
                &[b"build 42"],
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
                2,
                &Fields::new(67)
                    .u64(0, 1)
                    .u64(8, 1_000)
                    .u64(16, 2)
                    .u64(24, 4096)
                    .u64(32, 0)
                    .i64(40, 7)
                    .u32(48, 3)
                    .u32(52, 64)
                    .i32(56, 10)
                    .i32(60, -3)
                    .u8(64, 1)
                    .u8(65, 1)
                    .u8(66, 3)
                    .0,
                &[b"abc", &EXTENSION_BYTES],
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
                reserved_value: 7,
                end_of_stream: true,
                extension: Some(&EXTENSION_BYTES),
                payload: Payload::Inline(b"abc"),
            }),
        ),
        (
            vector(
                2,
                &Fields::new(67)
                    .u64(0, 2)
                    .u64(8, 2_000)
                    .u64(16, 2)
                    .u64(24, 8192)
                    .u64(32, 9)
                    .i64(40, -1)
                    .u32(48, 5000)
                    .u32(52, 5056)
                    .i32(56, 10)
                    .i32(60, 3)
                    .u8(64, 0)
                    .u8(65, 2)
                    .u8(66, 0)
                    .0,
                &[b"", b""],
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
                reserved_value: -1,
                end_of_stream: false,
                extension: None,
                payload: Payload::Reference {
                    recording_id: 9,
                    length: 5000,
                },
            }),
        ),
        (
            vector(
                3,
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
                &[b"v"],
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
                4,
                &Fields::new(24).u64(0, 4).u64(8, 5_000).u64(16, 77).0,
                &[],
            ),
            GroupRecord::Timer(TimerEvent {
                group_seq: 4,
                logical_time: 5_000,
                timer_id: 77,
            }),
        ),
        (
            vector(
                5,
                &Fields::new(43)
                    .u64(0, 5)
                    .u64(8, 6_000)
                    .u64(16, 3)
                    .u64(24, 128)
                    .i32(32, 10)
                    .i32(36, 3)
                    .u8(40, 3)
                    .u8(41, 2)
                    .u8(42, 2)
                    .0,
                &[],
            ),
            GroupRecord::Lifecycle(LifecycleEvent {
                group_seq: 5,
                logical_time: 6_000,
                incarnation: 3,
                position: 128,
                stream_id: 10,
                session_id: 3,
                lane: lane(2),
                kind: LifecycleKind::SubscriptionEnded(EndReason::Overrun),
            }),
        ),
        (
            vector(
                6,
                &Fields::new(20).u64(0, 6).u64(8, 7_000).u32(16, 0xBEEF).0,
                &[b"fill"],
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
                11,
                &Fields::new(59)
                    .u64(0, 6)
                    .u64(8, 1024)
                    .u64(16, 0)
                    .u64(24, 0)
                    .u32(32, 0)
                    .i32(36, 30)
                    .i32(40, 1)
                    .u16(44, 0)
                    .u16(46, 0)
                    .u8(48, 1)
                    .u8(49, 1)
                    .u8(50, 2)
                    .u32(51, 112)
                    .u32(55, 0x5f1c_09a2)
                    .0,
                &[],
            ),
            GroupRecord::Outcome(OutcomeObservation {
                group_seq: 6,
                index: 0,
                stream_id: 30,
                session_id: 1,
                operation: Operation::Offer,
                length: 112,
                crc32c: 0x5f1c_09a2,
                outcome: Outcome::Accepted {
                    lane: lane(2),
                    position: 1024,
                },
            }),
        ),
        (
            // MessageTooLarge { length: 70000, max: 65536 }: code 1, no
            // inner error, both fields.
            vector(
                11,
                &Fields::new(59)
                    .u64(0, 6)
                    .u64(8, 0)
                    .u64(16, 70_000)
                    .u64(24, 65_536)
                    .u32(32, 1)
                    .i32(36, 30)
                    .i32(40, 1)
                    .u16(44, 1)
                    .u16(46, 0)
                    .u8(48, 1)
                    .u8(49, 9)
                    .u8(50, 0)
                    .0,
                &[],
            ),
            GroupRecord::Outcome(OutcomeObservation {
                group_seq: 6,
                index: 1,
                stream_id: 30,
                session_id: 1,
                operation: Operation::Offer,
                length: 0,
                crc32c: 0,
                outcome: Outcome::Failed {
                    error: 1,
                    sub: 0,
                    detail: 70_000,
                    detail2: 65_536,
                },
            }),
        ),
        (
            vector(
                12,
                &Fields::new(29)
                    .u64(0, 6)
                    .u64(8, 78)
                    .u64(16, 9_000)
                    .u32(24, 2)
                    .u8(28, 1)
                    .0,
                &[],
            ),
            GroupRecord::TimerOperation(TimerObservation {
                group_seq: 6,
                index: 2,
                timer_id: 78,
                deadline: 9_000,
                action: TimerAction::Create,
            }),
        ),
        (
            vector(
                13,
                &Fields::new(16).u64(0, 6).u32(8, 3).u32(12, 1).0,
                &[b"ack"],
            ),
            GroupRecord::ExternalObservation(ExternalObservation {
                group_seq: 6,
                index: 3,
                kind: 1,
                value: b"ack",
            }),
        ),
        (
            vector(
                14,
                &Fields::new(72)
                    .u64(0, 6)
                    .u64(8, 2)
                    .u64(16, 1024)
                    .u64(24, 2048)
                    .u64(32, 3)
                    .u64(40, 0)
                    .u64(48, 0)
                    .u32(56, 4)
                    .i32(60, 30)
                    .i32(64, 1)
                    .u16(68, 0)
                    .u8(70, 1)
                    .u8(71, 2)
                    .0,
                &[],
            ),
            GroupRecord::Delivery(DeliveryObservation {
                group_seq: 6,
                index: 4,
                stream_id: 30,
                session_id: 1,
                kind: 1,
                lane: lane(2),
                receiver: 0,
                incarnation: 2,
                start: 1024,
                end: 2048,
                epoch: 3,
                reason: 0,
                lost: 0,
            }),
        ),
        (
            vector(20, &Fields::new(13).u64(0, 6).u32(8, 5).u8(12, 1).0, &[]),
            GroupRecord::End(EventEnd {
                group_seq: 6,
                observations: 5,
                outcome: EndOutcome::Complete,
            }),
        ),
        (
            vector(21, &Fields::new(17).u64(0, 7).u64(8, 9).u8(16, 2).0, &[]),
            GroupRecord::Gap(GapMarker {
                from_seq: 7,
                to_seq: 9,
                reason: GapReason::RingFull,
            }),
        ),
        // Conflation(ValueTooLarge { length: 300, max: 256 }): code 5, its
        // third variant, both fields of it.
        (
            vector(
                11,
                &Fields::new(59)
                    .u64(0, 8)
                    .u64(8, 0)
                    .u64(16, 300)
                    .u64(24, 256)
                    .u32(32, 0)
                    .i32(36, 40)
                    .i32(40, 2)
                    .u16(44, 5)
                    .u16(46, 3)
                    .u8(48, 1)
                    .u8(49, 9)
                    .u8(50, 0)
                    .0,
                &[],
            ),
            GroupRecord::Outcome(OutcomeObservation {
                group_seq: 8,
                index: 0,
                stream_id: 40,
                session_id: 2,
                operation: Operation::Offer,
                length: 0,
                crc32c: 0,
                outcome: Outcome::Failed {
                    error: 5,
                    sub: 3,
                    detail: 300,
                    detail2: 256,
                },
            }),
        ),
        // A7d: an overrun that `replay` resolved by falling back, the merge
        // failed; a skipped local gap; a payload not captured; a reference
        // its recording will never cover.
        (
            vector(
                7,
                &Fields::new(60)
                    .u64(0, 10)
                    .u64(8, 10_000)
                    .u64(16, 2)
                    .u64(24, 4096)
                    .u64(32, 8192)
                    .u64(40, 12_288)
                    .i32(48, 10)
                    .i32(52, 3)
                    .u8(56, 0)
                    .u8(57, 1)
                    .u8(58, 1)
                    .u8(59, 6)
                    .0,
                &[],
            ),
            GroupRecord::Loss(LossEvent {
                group_seq: 10,
                logical_time: 10_000,
                incarnation: 2,
                from: 4096,
                lost_to: 8192,
                resume: 12_288,
                stream_id: 10,
                session_id: 3,
                lane: lane(0),
                loss: Loss::Overrun {
                    outcome: OverrunOutcome::ResumedAtHead,
                    fallback: Some(FallbackReason::MergeFailed),
                },
            }),
        ),
        (
            vector(
                7,
                &Fields::new(60)
                    .u64(0, 11)
                    .u64(8, 11_000)
                    .u64(16, 2)
                    .u64(24, 12_288)
                    .u64(32, 12_544)
                    .u64(40, 12_544)
                    .i32(48, 10)
                    .i32(52, 3)
                    .u8(56, 1)
                    .u8(57, 2)
                    .u8(58, 0)
                    .u8(59, 8)
                    .0,
                &[],
            ),
            GroupRecord::Loss(LossEvent {
                group_seq: 11,
                logical_time: 11_000,
                incarnation: 2,
                from: 12_288,
                lost_to: 12_544,
                resume: 12_544,
                stream_id: 10,
                session_id: 3,
                lane: lane(1),
                loss: Loss::Skipped(SkipReason::LocalGap(LocalGapReason::RangeUnavailable)),
            }),
        ),
        (
            vector(
                2,
                &Fields::new(67)
                    .u64(0, 12)
                    .u64(8, 12_000)
                    .u64(16, 2)
                    .u64(24, 16_384)
                    .u64(32, 0)
                    .i64(40, 0)
                    .u32(48, 70_000)
                    .u32(52, 72_000)
                    .i32(56, 10)
                    .i32(60, 3)
                    .u8(64, 0)
                    .u8(65, 3)
                    .u8(66, 0)
                    .0,
                &[b"", b""],
            ),
            GroupRecord::Message(MessageEvent {
                group_seq: 12,
                logical_time: 12_000,
                incarnation: 2,
                position: 16_384,
                extent: 72_000,
                stream_id: 10,
                session_id: 3,
                lane: lane(0),
                reserved_value: 0,
                end_of_stream: false,
                extension: None,
                payload: Payload::Unavailable { length: 70_000 },
            }),
        ),
        (
            vector(22, &Fields::new(16).u64(0, 2).u64(8, 9).0, &[]),
            GroupRecord::Unavailable(ReferenceUnavailable {
                group_seq: 2,
                recording_id: 9,
            }),
        ),
        (
            vector(
                15,
                &Fields::new(28)
                    .u64(0, 6)
                    .u32(8, 3)
                    .u32(12, 8)
                    .u32(16, 1)
                    .i32(20, 30)
                    .i32(24, 1)
                    .0,
                &[],
            ),
            GroupRecord::Poll(DeliveryPoll {
                group_seq: 6,
                index: 3,
                max: 8,
                count: 1,
                stream_id: 30,
                session_id: 1,
            }),
        ),
        (
            vector(
                30,
                &Fields::new(40)
                    .u64(0, 12)
                    .u64(8, 3)
                    .u64(16, 4096)
                    .u64(24, 700)
                    .u32(32, 0xDEAD_BEEF)
                    .u32(36, 5)
                    .0,
                &[],
            ),
            GroupRecord::Checkpoint(CheckpointRecord {
                group_seq: 12,
                checkpoint_id: 3,
                position: 4096,
                length: 700,
                crc32c: 0xDEAD_BEEF,
                format: 5,
            }),
        ),
    ]
}

/// #382 review: a failure's encoding against the note's §5.1 table: the
/// `Option<u64>` of `ViewClosed::ImageRetired` (sub 4) present and absent,
/// and `Sys::Os`'s errno sign-extended (sub 13).
#[test]
fn failures_follow_the_table() {
    let failure = |error, sub, detail, detail2| {
        let record = GroupRecord::Outcome(OutcomeObservation {
            group_seq: 1,
            index: 0,
            stream_id: 1,
            session_id: 1,
            operation: Operation::Offer,
            length: 0,
            crc32c: 0,
            outcome: Outcome::Failed {
                error,
                sub,
                detail,
                detail2,
            },
        });
        let bytes = vector(
            11,
            &Fields::new(59)
                .u64(0, 1)
                .u64(16, detail)
                .u64(24, detail2)
                .i32(36, 1)
                .i32(40, 1)
                .u16(44, error)
                .u16(46, sub)
                .u8(48, 1)
                .u8(49, 9)
                .0,
            &[],
        );
        assert_eq!(GroupRecord::decode(&bytes).unwrap(), record);
        assert_eq!(encoded(&record), bytes);
    };
    // ImageRetired { since: Some(4096) } and { since: None }.
    failure(20, 4, 4096, 1);
    failure(20, 4, 0, 0);
    // Sys(Os { errno: -1 }): the i32, sign-extended.
    failure(11, 13, (-1i64).cast_unsigned(), 0);
}

#[test]
fn every_template_has_its_golden_vector() {
    for (bytes, record) in goldens() {
        assert_eq!(GroupRecord::decode(&bytes).unwrap(), record, "{record:?}");
        assert_eq!(encoded(&record), bytes, "{record:?}");
    }
}

/// One record of every template, every enum value among them.
#[allow(clippy::too_many_lines, reason = "one sample per value")]
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
        reserved_value: i64::MIN,
        end_of_stream: false,
        extension: Some(&EXTENSION_BYTES),
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
        reserved_value: 0,
        end_of_stream: true,
        extension: None,
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
        LifecycleKind::ImageAvailable,
        LifecycleKind::ImageUnavailable,
        LifecycleKind::SubscriptionEnded(EndReason::EndOfStream),
        LifecycleKind::SubscriptionEnded(EndReason::Revoked),
        LifecycleKind::SubscriptionEnded(EndReason::Closed),
    ] {
        samples.push(GroupRecord::Lifecycle(LifecycleEvent {
            group_seq: 1,
            logical_time: 1,
            incarnation: 1,
            position: 1 << 40,
            stream_id: 1,
            session_id: 1,
            lane: lane(1),
            kind,
        }));
    }
    let positioned = Outcome::Accepted {
        lane: lane(0),
        position: 0,
    };
    let aborted = Outcome::Aborted {
        lane: lane(3),
        position: u64::MAX,
    };
    let outcomes = [
        (Operation::Offer, Outcome::BackPressured),
        (Operation::Offer, Outcome::AdminAction),
        (Operation::Offer, Outcome::NotConnected),
        (Operation::Offer, Outcome::Closed),
        (Operation::Offer, Outcome::Gated),
        (Operation::Offer, Outcome::RateLimited),
        (
            Operation::Offer,
            Outcome::Failed {
                error: MAX_ERROR_CODE,
                sub: 0,
                detail: 0,
                detail2: 0,
            },
        ),
        (Operation::Claim, positioned),
        (Operation::Claim, aborted),
        (Operation::Claim, Outcome::Gated),
        (
            Operation::Claim,
            Outcome::Failed {
                error: 11,
                sub: 26,
                detail: u64::MAX,
                detail2: 1,
            },
        ),
        (Operation::Commit, positioned),
        (Operation::Commit, aborted),
    ];
    for (index, (operation, outcome)) in (0u32..).zip(outcomes) {
        samples.push(GroupRecord::Outcome(OutcomeObservation {
            group_seq: 2,
            index,
            stream_id: -1,
            session_id: -2,
            operation,
            length: 0,
            crc32c: 0,
            outcome,
        }));
    }
    for kind in [2, 3, 4, 5, 16, 17, 18, 19] {
        samples.push(GroupRecord::Delivery(DeliveryObservation {
            group_seq: 2,
            index: 1,
            stream_id: 1,
            session_id: 1,
            kind,
            lane: lane(3),
            // As the ring writes them: a receiver on range-side kinds, a
            // lost count on outcomes lost only.
            receiver: if kind >= 16 { u16::MAX } else { 0 },
            incarnation: u64::MAX,
            start: 1,
            end: 2,
            epoch: 3,
            reason: u64::MAX,
            lost: if kind == 19 { 4 } else { 0 },
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
    let loss = |loss| {
        GroupRecord::Loss(LossEvent {
            group_seq: u64::MAX,
            logical_time: u64::MAX,
            incarnation: u64::MAX,
            from: 0,
            lost_to: u64::MAX,
            resume: u64::MAX,
            stream_id: i32::MIN,
            session_id: i32::MAX,
            lane: lane(3),
            loss,
        })
    };
    let reasons = [
        None,
        Some(FallbackReason::NoArchive),
        Some(FallbackReason::NoRecording),
        Some(FallbackReason::RetentionShort),
        Some(FallbackReason::RecordingBehind),
        Some(FallbackReason::Refused),
        Some(FallbackReason::MergeFailed),
        Some(FallbackReason::Withdrawn),
    ];
    for outcome in [
        OverrunOutcome::ResumedAtHead,
        OverrunOutcome::SnapshotRebuilt,
        OverrunOutcome::SnapshotFailed,
        OverrunOutcome::Closed,
    ] {
        for fallback in reasons {
            samples.push(loss(Loss::Overrun { outcome, fallback }));
        }
    }
    for outcome in [OverrunOutcome::Replayed, OverrunOutcome::Replaying] {
        samples.push(loss(Loss::Overrun {
            outcome,
            fallback: None,
        }));
    }
    for reason in [
        SkipReason::MessageTooLarge,
        SkipReason::MissingEnd,
        SkipReason::Interrupted,
        SkipReason::Orphan,
        SkipReason::JoinedMidMessage,
        SkipReason::AfterLoss,
        SkipReason::LocalGap(LocalGapReason::ReorderExpired),
        SkipReason::LocalGap(LocalGapReason::RangeUnavailable),
    ] {
        samples.push(loss(Loss::Skipped(reason)));
    }
    samples.push(loss(Loss::Aborted));
    samples.push(GroupRecord::Unavailable(ReferenceUnavailable {
        group_seq: u64::MAX,
        recording_id: u64::MAX,
    }));
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
    for (at, value) in [(0, 1u16), (0, 2), (2, 8), (2, 15), (2, 23), (2, 30), (4, 2)] {
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

/// Golden vector `index`, with the `width`-byte field at block offset
/// `at` set to `value`.
fn mutated(index: usize, at: usize, value: u64, width: usize) -> Vec<u8> {
    let (mut bytes, _) = goldens().remove(index);
    let at = 12 + at;
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    bytes
}

fn refused(bytes: &[u8]) -> CodecError {
    GroupRecord::decode(bytes).unwrap_err()
}

// The goldens' indexes.
const HEADER: usize = 0;
const INLINE: usize = 1;
const REFERENCE: usize = 2;
const CONFLATED: usize = 3;
const TIMER: usize = 4;
const LIFECYCLE: usize = 5;
const ACCEPTED: usize = 7;
const FAILED: usize = 8;
const TIMER_OP: usize = 9;
const DELIVERY: usize = 11;
const END: usize = 12;
const GAP: usize = 13;
const NESTED: usize = 14;
const OVERRUN: usize = 15;
const SKIPPED: usize = 16;
const UNCAPTURED: usize = 17;
const UNAVAILABLE: usize = 18;
const POLL: usize = 19;

#[test]
#[allow(clippy::too_many_lines, reason = "one case per rule")]
fn every_invalid_field_is_refused() {
    let out_of_range = |field| CodecError::ValueOutOfRange { field };
    let invalid = |field, value| CodecError::InvalidEnum { field, value };
    // Header.
    assert_eq!(refused(&mutated(HEADER, 0, 0, 8)), out_of_range("group_id"));
    assert_eq!(
        refused(&mutated(HEADER, 8, 0, 8)),
        out_of_range("first_group_seq")
    );
    for value in [0u64, 65_536] {
        assert_eq!(
            refused(&mutated(HEADER, 16, value, 4)),
            out_of_range("inline_threshold")
        );
    }
    assert_eq!(
        refused(&mutated(HEADER, 20, 2, 2)),
        out_of_range("contract_version")
    );
    assert_eq!(refused(&mutated(HEADER, 22, 0, 1)), invalid("clock", 0));
    assert_eq!(refused(&mutated(HEADER, 22, 2, 1)), invalid("clock", 2));
    assert_eq!(refused(&mutated(HEADER, 23, 3, 1)), invalid("capture", 3));
    let empty = vector(
        1,
        &Fields::new(24)
            .u64(0, 1)
            .u64(8, 1)
            .u32(16, 1)
            .u16(20, 1)
            .u8(22, 1)
            .u8(23, 1)
            .0,
        &[b""],
    );
    assert!(matches!(
        refused(&empty),
        CodecError::LengthOutOfRange {
            field: "manifest",
            ..
        }
    ));
    // Message.
    assert_eq!(
        refused(&mutated(INLINE, 0, 0, 8)),
        out_of_range("group_seq")
    );
    assert_eq!(refused(&mutated(INLINE, 64, 4, 1)), out_of_range("lane"));
    assert_eq!(refused(&mutated(INLINE, 65, 0, 1)), invalid("payload", 0));
    assert_eq!(refused(&mutated(INLINE, 65, 4, 1)), invalid("payload", 4));
    assert_eq!(refused(&mutated(INLINE, 66, 4, 1)), out_of_range("flags"));
    // An inline payload naming a recording, or not of its length.
    assert_eq!(
        refused(&mutated(INLINE, 32, 9, 8)),
        out_of_range("recording_id")
    );
    assert_eq!(refused(&mutated(INLINE, 48, 4, 4)), out_of_range("length"));
    // The extension flag and the extension field disagree.
    assert!(matches!(
        refused(&mutated(INLINE, 66, 1, 1)),
        CodecError::LengthOutOfRange {
            field: "extension",
            ..
        }
    ));
    assert!(matches!(
        refused(&mutated(REFERENCE, 66, 2, 1)),
        CodecError::LengthOutOfRange {
            field: "extension",
            ..
        }
    ));
    // A reference with no recording, or with a value.
    assert_eq!(
        refused(&mutated(REFERENCE, 32, 0, 8)),
        out_of_range("recording_id")
    );
    let (reference, _) = goldens().remove(REFERENCE);
    let mut with_value = reference[..reference.len() - 4].to_vec();
    with_value.extend_from_slice(&1u16.to_le_bytes());
    with_value.push(0);
    with_value.extend_from_slice(&0u16.to_le_bytes());
    let total = u32::try_from(with_value.len()).unwrap();
    with_value[8..12].copy_from_slice(&total.to_le_bytes());
    assert!(matches!(
        refused(&with_value),
        CodecError::LengthOutOfRange { field: "value", .. }
    ));
    // Extents: zero, unaligned above the least, below the payload, and
    // the payload with no room for a frame header.
    for extent in [0u32, 5060, 2048, 5024] {
        assert_eq!(
            refused(&mutated(REFERENCE, 52, u64::from(extent), 4)),
            out_of_range("extent"),
            "{extent}"
        );
    }
    // Conflated: freshness, and a fresh value with a gap start.
    assert_eq!(
        refused(&mutated(CONFLATED, 44, 0, 1)),
        invalid("freshness", 0)
    );
    assert_eq!(
        refused(&mutated(CONFLATED, 44, 1, 1)),
        out_of_range("stale_since")
    );
    // Timer and lifecycle.
    assert_eq!(refused(&mutated(TIMER, 16, 0, 8)), out_of_range("timer_id"));
    assert_eq!(refused(&mutated(LIFECYCLE, 40, 4, 1)), invalid("kind", 4));
    assert_eq!(refused(&mutated(LIFECYCLE, 42, 5, 1)), invalid("reason", 5));
    assert_eq!(refused(&mutated(LIFECYCLE, 42, 0, 1)), invalid("reason", 0));
    let mut available = mutated(LIFECYCLE, 40, 1, 1);
    assert_eq!(refused(&available), out_of_range("reason"));
    available[12 + 42] = 0;
    available[12 + 41] = 4;
    assert_eq!(refused(&available), out_of_range("lane"));
    // Outcomes.
    assert_eq!(
        refused(&mutated(ACCEPTED, 48, 4, 1)),
        invalid("operation", 4)
    );
    assert_eq!(
        refused(&mutated(ACCEPTED, 49, 10, 1)),
        invalid("outcome", 10)
    );
    // An aborted offer; a commit that is neither accepted nor aborted.
    assert_eq!(
        refused(&mutated(ACCEPTED, 49, 8, 1)),
        out_of_range("outcome")
    );
    let mut commit = mutated(ACCEPTED, 48, 3, 1);
    commit[12 + 49] = 2;
    commit[12 + 8..12 + 16].fill(0);
    commit[12 + 50] = 0;
    assert_eq!(refused(&commit), out_of_range("outcome"));
    // A claim records no length or digest.
    let mut claim = mutated(ACCEPTED, 48, 2, 1);
    claim[12 + 51..12 + 59].fill(0);
    assert!(GroupRecord::decode(&claim).is_ok());
    for at in [51, 55] {
        let mut digested = claim.clone();
        digested[12 + at] = 1;
        assert_eq!(refused(&digested), out_of_range("length"), "{at}");
    }
    // A delivery poll presenting more than its maximum.
    assert_eq!(refused(&mutated(POLL, 16, 9, 4)), out_of_range("count"));
    assert!(GroupRecord::decode(&mutated(POLL, 16, 8, 4)).is_ok());
    // A position or a lane on an outcome that has none.
    assert_eq!(
        refused(&mutated(ACCEPTED, 49, 2, 1)),
        out_of_range("position")
    );
    let mut lane_only = mutated(ACCEPTED, 8, 0, 8);
    lane_only[12 + 49] = 6;
    assert_eq!(refused(&lane_only), out_of_range("lane"));
    assert_eq!(refused(&mutated(ACCEPTED, 50, 4, 1)), out_of_range("lane"));
    // An error, a sub-variant or a detail on an outcome that is no
    // failure; a failure with no error, an unknown one, or a sub-variant
    // its error does not have.
    for (at, width) in [(44, 2), (46, 2), (16, 8), (24, 8)] {
        assert_eq!(
            refused(&mutated(ACCEPTED, at, 1, width)),
            out_of_range("error"),
            "{at}"
        );
    }
    assert_eq!(refused(&mutated(FAILED, 44, 0, 2)), out_of_range("error"));
    assert_eq!(
        refused(&mutated(FAILED, 44, u64::from(MAX_ERROR_CODE) + 1, 2)),
        out_of_range("error")
    );
    // MessageTooLarge has no inner error; Conflation has seven.
    assert_eq!(refused(&mutated(FAILED, 46, 1, 2)), out_of_range("sub"));
    assert_eq!(refused(&mutated(NESTED, 46, 0, 2)), out_of_range("sub"));
    assert_eq!(refused(&mutated(NESTED, 46, 8, 2)), out_of_range("sub"));
    // Timer operation, delivery, end and gap.
    assert_eq!(
        refused(&mutated(TIMER_OP, 8, 0, 8)),
        out_of_range("timer_id")
    );
    assert_eq!(refused(&mutated(TIMER_OP, 28, 3, 1)), invalid("action", 3));
    for kind in [0u64, 6, 15, 20] {
        assert_eq!(
            refused(&mutated(DELIVERY, 70, kind, 1)),
            invalid("kind", kind)
        );
    }
    assert_eq!(refused(&mutated(DELIVERY, 71, 4, 1)), out_of_range("lane"));
    assert_eq!(refused(&mutated(END, 12, 0, 1)), invalid("outcome", 0));
    assert_eq!(refused(&mutated(GAP, 8, 6, 8)), out_of_range("to_seq"));
    assert_eq!(refused(&mutated(GAP, 0, 0, 8)), out_of_range("from_seq"));
    assert_eq!(refused(&mutated(GAP, 16, 4, 1)), invalid("reason", 4));
}

/// What a decoder refuses, an encoder refuses to write.
#[test]
fn invalid_values_are_not_encoded() {
    let mut out = vec![0u8; MAX_RECORD];
    let message = |extent, payload| {
        GroupRecord::Message(MessageEvent {
            group_seq: 1,
            logical_time: 0,
            incarnation: 0,
            position: 0,
            extent,
            stream_id: 0,
            session_id: 0,
            lane: lane(0),
            reserved_value: 0,
            end_of_stream: false,
            extension: None,
            payload,
        })
    };
    let outcome = |operation, outcome| {
        GroupRecord::Outcome(OutcomeObservation {
            group_seq: 1,
            index: 0,
            stream_id: 0,
            session_id: 0,
            operation,
            length: 0,
            crc32c: 0,
            outcome,
        })
    };
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
        message(32, Payload::Inline(&[0; 1])),
        message(
            64,
            Payload::Reference {
                recording_id: 0,
                length: 1,
            },
        ),
        outcome(
            Operation::Offer,
            Outcome::Aborted {
                lane: lane(0),
                position: 0,
            },
        ),
        outcome(Operation::Commit, Outcome::BackPressured),
        outcome(
            Operation::Commit,
            Outcome::Failed {
                error: 1,
                sub: 0,
                detail: 0,
                detail2: 0,
            },
        ),
        outcome(
            Operation::Offer,
            Outcome::Failed {
                error: 0,
                sub: 0,
                detail: 0,
                detail2: 0,
            },
        ),
        outcome(
            Operation::Offer,
            Outcome::Failed {
                error: 5,
                sub: 8,
                detail: 0,
                detail2: 0,
            },
        ),
        GroupRecord::Delivery(DeliveryObservation {
            group_seq: 1,
            index: 0,
            stream_id: 0,
            session_id: 0,
            kind: 6,
            lane: lane(0),
            receiver: 0,
            incarnation: 0,
            start: 0,
            end: 0,
            epoch: 0,
            reason: 0,
            lost: 0,
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
            Role::Observation(6, 3),
            Role::Delivery {
                group_seq: 6,
                index: 4,
                stream_id: 30,
                session_id: 1,
            },
            Role::End(EventEnd {
                group_seq: 6,
                observations: 5,
                outcome: EndOutcome::Complete
            }),
            Role::Gap(GapMarker {
                from_seq: 7,
                to_seq: 9,
                reason: GapReason::RingFull
            }),
            Role::Observation(8, 0),
            Role::Event(10),
            Role::Event(11),
            Role::Uncaptured(12),
            Role::Unavailable(2),
            Role::Poll {
                group_seq: 6,
                index: 3,
                count: 1,
                stream_id: 30,
                session_id: 1,
            },
            Role::Checkpoint {
                group_seq: 12,
                checkpoint_id: 3,
            },
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
        reserved_value in any::<i64>(),
        end_of_stream in any::<bool>(),
        traced in any::<bool>(),
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
            Payload::Reference { length, .. } | Payload::Unavailable { length } => length,
        };
        let extent = (u64::from(length) + 32)
            .next_multiple_of(32)
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
            reserved_value,
            end_of_stream,
            extension: traced.then_some(&EXTENSION_BYTES),
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
        template in 0usize..15,
        block in proptest::collection::vec(any::<u8>(), 72),
        value in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        let templates = [
            JOURNAL_HEADER, MESSAGE_EVENT, CONFLATED_EVENT, TIMER_EVENT,
            LIFECYCLE_EVENT, EXTERNAL_EVENT, OUTCOME_OBSERVATION,
            TIMER_OBSERVATION, EXTERNAL_OBSERVATION, DELIVERY_OBSERVATION,
            EVENT_END, GAP_MARKER, LOSS_EVENT, REFERENCE_UNAVAILABLE,
            DELIVERY_POLL,
        ];
        let template = templates[template];
        let block = &block[..usize::from(template.block_length)];
        let id = template.template_id;
        let _ = GroupRecord::decode(&vector(id, block, &[&value]));
        let _ = GroupRecord::decode(&vector(id, block, &[]));
        let _ = GroupRecord::decode(&vector(id, block, &[&value, &value]));
    }
}

/// #382 review P3: a delivery record holds only what the ring presents: a
/// receiver on a range-side kind, a lost count on outcomes lost.
#[test]
fn a_delivery_holds_only_what_the_ring_writes() {
    // Kind 1 (submitted) with a receiver, or with a lost count.
    assert_eq!(
        refused(&mutated(DELIVERY, 68, 1, 2)),
        CodecError::ValueOutOfRange { field: "receiver" }
    );
    assert_eq!(
        refused(&mutated(DELIVERY, 48, 1, 8)),
        CodecError::ValueOutOfRange { field: "lost" }
    );
    // A range (16) takes a receiver; only outcomes lost (19) a count.
    let mut range = mutated(DELIVERY, 70, 16, 1);
    range[12 + 68..12 + 70].copy_from_slice(&3u16.to_le_bytes());
    assert!(GroupRecord::decode(&range).is_ok());
    range[12 + 48] = 1;
    assert_eq!(
        refused(&range),
        CodecError::ValueOutOfRange { field: "lost" }
    );
}

/// #382 review P3: a field a variant does not have is 0 (the note's 5.1
/// table), and an `Option`'s flag is 0 or 1, its value 0 when absent.
#[test]
fn a_failure_holds_only_its_variants_fields() {
    let detail = CodecError::ValueOutOfRange { field: "detail" };
    let failure = |error: u16, sub: u16, first: u64, second: u64| {
        vector(
            11,
            &Fields::new(59)
                .u64(0, 1)
                .u64(16, first)
                .u64(24, second)
                .i32(36, 1)
                .i32(40, 1)
                .u16(44, error)
                .u16(46, sub)
                .u8(48, 1)
                .u8(49, 9)
                .0,
            &[],
        )
    };
    // EmptyMessage has no field; PositionsExhausted one; MessageTooLarge two.
    assert_eq!(refused(&failure(2, 0, 5, 0)), detail);
    assert_eq!(refused(&failure(3, 0, 5, 6)), detail);
    assert!(GroupRecord::decode(&failure(3, 0, 5, 0)).is_ok());
    assert!(GroupRecord::decode(&failure(1, 0, 5, 6)).is_ok());
    // Inner variants: Conflation::Closed none, Sys::Protocol none,
    // Conductor::InvalidChannel one.
    assert_eq!(refused(&failure(5, 5, 1, 0)), detail);
    assert_eq!(refused(&failure(11, 14, 1, 0)), detail);
    assert_eq!(refused(&failure(15, 10, 1, 2)), detail);
    // An Option: ViewClosed::ImageRetired and Attach::IncompatibleVersion.
    assert_eq!(refused(&failure(20, 4, 0, 2)), detail);
    assert_eq!(refused(&failure(20, 4, 7, 0)), detail);
    assert_eq!(refused(&failure(14, 2, 7, 0)), detail);
    assert!(GroupRecord::decode(&failure(14, 2, 7, 1)).is_ok());
    assert!(GroupRecord::decode(&failure(14, 2, 0, 0)).is_ok());
    // The encoder refuses the same.
    let mut out = vec![0u8; MAX_RECORD];
    let record = GroupRecord::Outcome(OutcomeObservation {
        group_seq: 1,
        index: 0,
        stream_id: 1,
        session_id: 1,
        operation: Operation::Offer,
        length: 0,
        crc32c: 0,
        outcome: Outcome::Failed {
            error: 2,
            sub: 0,
            detail: 5,
            detail2: 0,
        },
    });
    assert_eq!(record.encode(&mut out), Err(detail));
}

/// The A7d records' fields (`recording-group-gateway.md` section 10): a
/// loss event's kind, outcome, reason and positions, an unavailable
/// payload, and a reference unavailable's identifiers.
#[test]
fn every_invalid_a7d_field_is_refused() {
    let out_of_range = |field| CodecError::ValueOutOfRange { field };
    let invalid = |field, value| CodecError::InvalidEnum { field, value };
    // An overrun.
    assert_eq!(
        refused(&mutated(OVERRUN, 0, 0, 8)),
        out_of_range("group_seq")
    );
    assert_eq!(refused(&mutated(OVERRUN, 56, 4, 1)), out_of_range("lane"));
    for kind in [0u64, 4] {
        assert_eq!(
            refused(&mutated(OVERRUN, 57, kind, 1)),
            invalid("kind", kind)
        );
    }
    for outcome in [0u64, 7] {
        assert_eq!(
            refused(&mutated(OVERRUN, 58, outcome, 1)),
            invalid("outcome", outcome)
        );
    }
    assert_eq!(refused(&mutated(OVERRUN, 59, 8, 1)), invalid("reason", 8));
    // A replayed or replaying overrun did not fall back.
    for outcome in [5u64, 6] {
        assert_eq!(
            refused(&mutated(OVERRUN, 58, outcome, 1)),
            out_of_range("reason")
        );
    }
    assert_eq!(
        refused(&mutated(OVERRUN, 24, 8193, 8)),
        out_of_range("lost_to")
    );
    assert_eq!(
        refused(&mutated(OVERRUN, 40, 8191, 8)),
        out_of_range("resume")
    );
    // A skip: no outcome, a listed reason, and its end as its resume.
    assert_eq!(
        refused(&mutated(SKIPPED, 58, 1, 1)),
        out_of_range("outcome")
    );
    for reason in [0u64, 9] {
        assert_eq!(
            refused(&mutated(SKIPPED, 59, reason, 1)),
            invalid("reason", reason)
        );
    }
    assert_eq!(
        refused(&mutated(SKIPPED, 40, 12_800, 8)),
        out_of_range("resume")
    );
    // An abort: neither outcome nor reason.
    assert_eq!(refused(&mutated(SKIPPED, 57, 3, 1)), out_of_range("reason"));
    let mut aborted = mutated(SKIPPED, 57, 3, 1);
    aborted[12 + 59] = 0;
    assert!(matches!(
        GroupRecord::decode(&aborted).unwrap(),
        GroupRecord::Loss(LossEvent {
            loss: Loss::Aborted,
            ..
        })
    ));
    aborted[12 + 58] = 1;
    assert_eq!(refused(&aborted), out_of_range("outcome"));
    // An unavailable payload: no recording, no value, above MAX_INLINE.
    assert_eq!(
        refused(&mutated(UNCAPTURED, 32, 5, 8)),
        out_of_range("recording_id")
    );
    assert_eq!(
        refused(&mutated(UNCAPTURED, 48, 65_535, 4)),
        out_of_range("length")
    );
    let (bytes, _) = goldens().remove(UNCAPTURED);
    let valued = vector(2, &bytes[12..12 + 67], &[b"x", b""]);
    assert!(matches!(
        refused(&valued),
        CodecError::LengthOutOfRange { field: "value", .. }
    ));
    // A reference unavailable.
    assert_eq!(
        refused(&mutated(UNAVAILABLE, 0, 0, 8)),
        out_of_range("group_seq")
    );
    assert_eq!(
        refused(&mutated(UNAVAILABLE, 8, 0, 8)),
        out_of_range("recording_id")
    );
}

#[test]
fn invalid_a7d_values_are_not_encoded() {
    let mut out = vec![0u8; MAX_RECORD];
    let loss = |from, lost_to, resume, loss| {
        GroupRecord::Loss(LossEvent {
            group_seq: 1,
            logical_time: 0,
            incarnation: 0,
            from,
            lost_to,
            resume,
            stream_id: 0,
            session_id: 0,
            lane: lane(0),
            loss,
        })
    };
    let resumed = Loss::Overrun {
        outcome: OverrunOutcome::ResumedAtHead,
        fallback: None,
    };
    let cases = [
        (loss(2, 1, 3, resumed), "lost_to"),
        (loss(1, 3, 2, resumed), "resume"),
        (loss(1, 2, 3, Loss::Aborted), "resume"),
        (
            loss(
                1,
                2,
                3,
                Loss::Overrun {
                    outcome: OverrunOutcome::Replayed,
                    fallback: Some(FallbackReason::Refused),
                },
            ),
            "reason",
        ),
        (
            GroupRecord::Message(MessageEvent {
                group_seq: 1,
                logical_time: 0,
                incarnation: 0,
                position: 0,
                extent: 160,
                stream_id: 0,
                session_id: 0,
                lane: lane(0),
                reserved_value: 0,
                end_of_stream: false,
                extension: None,
                payload: Payload::Unavailable { length: 100 },
            }),
            "length",
        ),
        (
            GroupRecord::Unavailable(ReferenceUnavailable {
                group_seq: 0,
                recording_id: 9,
            }),
            "group_seq",
        ),
        (
            GroupRecord::Unavailable(ReferenceUnavailable {
                group_seq: 2,
                recording_id: 0,
            }),
            "recording_id",
        ),
    ];
    for (record, field) in cases {
        assert_eq!(
            record.encode(&mut out),
            Err(CodecError::ValueOutOfRange { field }),
            "{record:?}"
        );
    }
}

/// #405 review P3: each loss code against its table, written out as
/// literals: a swapped code fails here, whatever the round trips say.
#[test]
fn loss_codes_follow_the_tables() {
    let loss = |loss| {
        encoded(&GroupRecord::Loss(LossEvent {
            group_seq: 1,
            logical_time: 0,
            incarnation: 0,
            from: 0,
            lost_to: 0,
            resume: 0,
            stream_id: 0,
            session_id: 0,
            lane: lane(0),
            loss,
        }))
    };
    let codes = |bytes: Vec<u8>| (bytes[12 + 57], bytes[12 + 58], bytes[12 + 59]);
    let overruns = [
        (OverrunOutcome::ResumedAtHead, 1),
        (OverrunOutcome::SnapshotRebuilt, 2),
        (OverrunOutcome::SnapshotFailed, 3),
        (OverrunOutcome::Closed, 4),
        (OverrunOutcome::Replayed, 5),
        (OverrunOutcome::Replaying, 6),
    ];
    for (outcome, code) in overruns {
        let bytes = loss(Loss::Overrun {
            outcome,
            fallback: None,
        });
        assert_eq!(codes(bytes), (1, code, 0), "{outcome:?}");
    }
    let fallbacks = [
        (FallbackReason::NoArchive, 1),
        (FallbackReason::NoRecording, 2),
        (FallbackReason::RetentionShort, 3),
        (FallbackReason::RecordingBehind, 4),
        (FallbackReason::Refused, 5),
        (FallbackReason::MergeFailed, 6),
        (FallbackReason::Withdrawn, 7),
    ];
    for (reason, code) in fallbacks {
        let bytes = loss(Loss::Overrun {
            outcome: OverrunOutcome::Closed,
            fallback: Some(reason),
        });
        assert_eq!(codes(bytes), (1, 4, code), "{reason:?}");
    }
    let skips = [
        (SkipReason::MessageTooLarge, 1),
        (SkipReason::MissingEnd, 2),
        (SkipReason::Interrupted, 3),
        (SkipReason::Orphan, 4),
        (SkipReason::JoinedMidMessage, 5),
        (SkipReason::AfterLoss, 6),
        (SkipReason::LocalGap(LocalGapReason::ReorderExpired), 7),
        (SkipReason::LocalGap(LocalGapReason::RangeUnavailable), 8),
    ];
    for (reason, code) in skips {
        assert_eq!(
            codes(loss(Loss::Skipped(reason))),
            (2, 0, code),
            "{reason:?}"
        );
    }
    assert_eq!(codes(loss(Loss::Aborted)), (3, 0, 0));
}

/// A9-1: a checkpoint record names an event and an id, never 0, a length
/// of at least 1, and a range that ends within `u64`, unless its position
/// is a replay capture's `u64::MAX`; a refused one encodes nothing and
/// does not decode.
#[test]
fn a_checkpoint_record_refuses_what_names_nothing() {
    let valid = CheckpointRecord {
        group_seq: 1,
        checkpoint_id: 1,
        position: 0,
        length: 1,
        crc32c: 0,
        format: 0,
    };
    let capture = CheckpointRecord {
        position: u64::MAX,
        length: u64::MAX,
        ..valid
    };
    assert_eq!(capture.end(), None);
    let bytes = encoded(&GroupRecord::Checkpoint(capture));
    assert_eq!(
        GroupRecord::decode(&bytes).unwrap(),
        GroupRecord::Checkpoint(capture)
    );
    let refused = [
        (
            "group_seq",
            CheckpointRecord {
                group_seq: 0,
                ..valid
            },
        ),
        (
            "checkpoint_id",
            CheckpointRecord {
                checkpoint_id: 0,
                ..valid
            },
        ),
        ("length", CheckpointRecord { length: 0, ..valid }),
        (
            "position",
            CheckpointRecord {
                position: u64::MAX - 1,
                length: 2,
                ..valid
            },
        ),
    ];
    for (field, record) in refused {
        let mut out = vec![0u8; MAX_RECORD];
        assert_eq!(
            GroupRecord::Checkpoint(record).encode(&mut out),
            Err(CodecError::ValueOutOfRange { field })
        );
        let bytes = vector(
            30,
            &Fields::new(40)
                .u64(0, record.group_seq)
                .u64(8, record.checkpoint_id)
                .u64(16, record.position)
                .u64(24, record.length)
                .0,
            &[],
        );
        assert_eq!(
            GroupRecord::decode(&bytes),
            Err(CodecError::ValueOutOfRange { field })
        );
    }
}
