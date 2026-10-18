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
