// SPDX-License-Identifier: Apache-2.0

//! Decoding, encoding and order-checking a recording group's records
//! allocate and free nothing, on success and on error paths (ADR-0036,
//! validation), over a counting global allocator.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_archive::group::order::OrderCheck;
use karyos_archive::group::record::{
    Capture, Clock, ConflatedEvent, EndOutcome, EventEnd, Freshness, GroupRecord, JournalHeader,
    MAX_RECORD, MessageEvent, Operation, Outcome, OutcomeObservation, Payload,
};
use karyos_sys::alloc_count::{CountingAllocator, count};
use karyos_sys::frame::Lane;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn journal() -> [GroupRecord<'static>; 5] {
    [
        GroupRecord::Header(JournalHeader {
            group_id: 1,
            first_group_seq: 1,
            inline_threshold: 4096,
            contract_version: 1,
            clock: Clock::HostMonotonic,
            capture: Capture::Strict,
            manifest: b"build",
        }),
        GroupRecord::Message(MessageEvent {
            group_seq: 1,
            logical_time: 10,
            incarnation: 1,
            position: 0,
            extent: 64,
            stream_id: 10,
            session_id: 3,
            lane: Lane::ZERO,
            reserved_value: 7,
            end_of_stream: false,
            extension: None,
            payload: Payload::Inline(b"payload"),
        }),
        GroupRecord::Outcome(OutcomeObservation {
            group_seq: 1,
            index: 0,
            stream_id: 20,
            session_id: 1,
            operation: Operation::Offer,
            length: 0,
            crc32c: 0,
            outcome: Outcome::BackPressured,
        }),
        GroupRecord::End(EventEnd {
            group_seq: 1,
            observations: 1,
            outcome: EndOutcome::Complete,
        }),
        GroupRecord::Conflated(ConflatedEvent {
            group_seq: 2,
            logical_time: 11,
            version: 4,
            key: 9,
            stream_id: 30,
            session_id: 2,
            freshness: Freshness::Stale { since: 128 },
            value: b"v",
        }),
    ]
}

#[test]
fn a_journal_is_encoded_decoded_and_checked_without_allocating() {
    let mut out = vec![0u8; MAX_RECORD];
    let mut check = OrderCheck::new();
    for record in journal() {
        let (length, allocations) = count(|| record.encode(&mut out).unwrap());
        assert_eq!(allocations, 0, "encode {record:?}");
        let (decoded, allocations) = count(|| GroupRecord::decode(&out[..length]).unwrap());
        assert_eq!(allocations, 0, "decode {record:?}");
        assert_eq!(decoded, record);
        let (pushed, allocations) = count(|| check.push(decoded.role()));
        assert_eq!(allocations, 0, "check {record:?}");
        pushed.unwrap();
        for cut in 0..length {
            let (refused, allocations) = count(|| GroupRecord::decode(&out[..cut]).is_err());
            assert!(refused);
            assert_eq!(allocations, 0, "truncated at {cut}");
        }
    }
    // A record out of order is refused without allocating.
    let (refused, allocations) = count(|| check.push(journal()[1].role()).is_err());
    assert!(refused);
    assert_eq!(allocations, 0);
}

/// A replay cursor allocates when it opens, then nothing per event
/// (recording-group-replay.md section 11), over a journal on disk.
#[test]
fn a_replay_cursor_steps_without_allocating() {
    use karyos_archive::disk::StdDisk;
    use karyos_archive::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
    use karyos_archive::group::prefix::{Coverage, recover};
    use karyos_archive::group::replay::{CursorConfig, ReplayConfig, ReplayCursor, Step};
    use karyos_archive::segment::SyncPolicy;

    struct Nothing;
    impl Coverage for Nothing {
        fn positions(&self, _recording_id: u64) -> Option<(u64, u64)> {
            None
        }
        fn ended(&self, _recording_id: u64) -> Option<u64> {
            None
        }
    }

    let dir = std::env::temp_dir().join(format!("karyos-replay-alloc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::PerSegment,
    };
    let records = journal();
    let GroupRecord::Header(header) = records[0] else {
        panic!("no header");
    };
    let mut out = vec![0u8; MAX_RECORD];
    let mut journal = GroupJournal::create(StdDisk, &dir, &header, config).unwrap();
    // Three copies of the event, as group_seq 1 to 3.
    for seq in 1..=3u64 {
        for record in &records[1..4] {
            let record = match *record {
                GroupRecord::Message(message) => GroupRecord::Message(MessageEvent {
                    group_seq: seq,
                    ..message
                }),
                GroupRecord::Outcome(outcome) => GroupRecord::Outcome(OutcomeObservation {
                    group_seq: seq,
                    ..outcome
                }),
                GroupRecord::End(end) => GroupRecord::End(EventEnd {
                    group_seq: seq,
                    ..end
                }),
                other => other,
            };
            let length = record.encode(&mut out).unwrap();
            let _ = journal.append(&out[..length]).unwrap();
        }
    }
    let _ = journal.close().unwrap();
    let mut journal = GroupJournal::recover(StdDisk, &dir, header.group_id, config)
        .unwrap()
        .journal;
    let recovery = recover(&mut journal, &Nothing, 8).unwrap();
    let replay = ReplayConfig {
        manifest: header.manifest,
        accept_manifest: false,
    };
    let room = CursorConfig {
        bytes: 4096,
        records: 8,
    };
    let mut cursor = ReplayCursor::open(journal, &recovery, &replay, room).unwrap();
    let mut seen = 0u64;
    loop {
        let (step, allocations) = count(|| match cursor.step().unwrap() {
            Step::Event(event) => Some(event.group_seq()),
            Step::Checkpoint(_) | Step::Stop(_) => None,
        });
        assert_eq!(allocations, 0, "a step allocated");
        match step {
            Some(seq) => {
                seen += 1;
                assert_eq!(seq, seen);
            }
            None => break,
        }
    }
    assert_eq!(seen, 3);
    drop(cursor);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A replayed dispatch allocates nothing per event (recording-group-
/// replay.md section 11): an inline message, its offer checked and
/// answered from the recording, with no capture.
#[test]
fn a_replay_gateway_dispatches_without_allocating() {
    use karyos_archive::disk::StdDisk;
    use karyos_archive::group::gateway::{
        Dispatched, Effects, Event, GroupGateway, Handler, MessagePayload, PublicationId,
    };
    use karyos_archive::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
    use karyos_archive::group::prefix::{Coverage, recover};
    use karyos_archive::group::record::CheckpointRecord;
    use karyos_archive::group::replay::gateway::{GatewayConfig, ReplayGateway};
    use karyos_archive::group::replay::{CursorConfig, ReplayConfig, ReplayCursor};
    use karyos_archive::segment::SyncPolicy;

    struct Nothing;
    impl Coverage for Nothing {
        fn positions(&self, _recording_id: u64) -> Option<(u64, u64)> {
            None
        }
        fn ended(&self, _recording_id: u64) -> Option<u64> {
            None
        }
    }

    let dir = std::env::temp_dir().join(format!(
        "karyos-replay-gateway-alloc-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::PerSegment,
    };
    let records = journal();
    let GroupRecord::Header(header) = records[0] else {
        panic!("no header");
    };
    let mut out = vec![0u8; MAX_RECORD];
    let mut journal = GroupJournal::create(StdDisk, &dir, &header, config).unwrap();
    for seq in 1..=3u64 {
        for record in &records[1..4] {
            let record = match *record {
                GroupRecord::Message(message) => GroupRecord::Message(MessageEvent {
                    group_seq: seq,
                    ..message
                }),
                // The offer of the message's payload, as the handler makes it.
                GroupRecord::Outcome(outcome) => GroupRecord::Outcome(OutcomeObservation {
                    group_seq: seq,
                    length: 7,
                    crc32c: karyos_archive::crc32c::crc32c(b"payload"),
                    ..outcome
                }),
                GroupRecord::End(end) => GroupRecord::End(EventEnd {
                    group_seq: seq,
                    ..end
                }),
                other => other,
            };
            let length = record.encode(&mut out).unwrap();
            let _ = journal.append(&out[..length]).unwrap();
        }
        // A checkpoint of each event (A9-2), compared in its dispatch.
        let checkpoint = GroupRecord::Checkpoint(CheckpointRecord {
            group_seq: seq,
            checkpoint_id: seq,
            position: 0,
            length: 5,
            crc32c: karyos_archive::crc32c::crc32c(b"state"),
            format: 1,
        });
        let length = checkpoint.encode(&mut out).unwrap();
        let _ = journal.append(&out[..length]).unwrap();
    }
    let _ = journal.close().unwrap();
    let mut journal = GroupJournal::recover(StdDisk, &dir, header.group_id, config)
        .unwrap()
        .journal;
    let recovery = recover(&mut journal, &Nothing, 8).unwrap();
    let replay = ReplayConfig {
        manifest: header.manifest,
        accept_manifest: false,
    };
    let room = CursorConfig {
        bytes: 4096,
        records: 8,
    };
    let cursor = ReplayCursor::open(journal, &recovery, &replay, room).unwrap();
    // The recorded offer is publication 0's: stream 20, session 1.
    let GroupRecord::Outcome(offer) = records[2] else {
        panic!("no offer");
    };
    let publications = [(offer.stream_id, offer.session_id)];
    let GroupRecord::Message(message) = records[1] else {
        panic!("no message");
    };
    let subscriptions = [(message.stream_id, message.session_id)];
    let mut gateway = ReplayGateway::new(
        cursor,
        &GatewayConfig {
            publications: &publications,
            subscriptions: &subscriptions,
            network: &[],
            conflated: &[],
            max_claim: 64,
            max_payload: 0,
            present_unavailable: false,
        },
        None,
    )
    .unwrap()
    .with_state(64)
    .unwrap();
    struct Offers;
    impl Handler for Offers {
        fn on_event(&mut self, event: &Event<'_>, effects: &mut dyn Effects) {
            if let Event::Message {
                payload: MessagePayload::Bytes(payload),
                ..
            } = event
            {
                let _ = effects.offer(PublicationId(0), payload);
            }
        }

        fn checkpoint(&mut self, out: &mut [u8]) -> Option<usize> {
            out.get_mut(..5)?.copy_from_slice(b"state");
            Some(5)
        }
    }
    let mut handler = Offers;
    let mut seen = 0u64;
    loop {
        let (dispatched, allocations) = count(|| gateway.dispatch(&mut handler));
        assert_eq!(allocations, 0, "a dispatch allocated");
        match dispatched.unwrap() {
            Dispatched::Event { group_seq } => {
                seen += 1;
                assert_eq!(group_seq, seen);
            }
            Dispatched::End => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(seen, 3);
    drop(gateway);
    std::fs::remove_dir_all(&dir).unwrap();
}
