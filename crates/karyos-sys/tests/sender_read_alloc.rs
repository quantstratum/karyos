// SPDX-License-Identifier: Apache-2.0

//! The sender read path allocates and frees nothing (`quantstratum-docs:
//! karyos/design/network-sessions-sender.md` 2.5: "on the data path the
//! capability never allocates"), over a counting global allocator.

#![cfg(feature = "test-hooks")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_sys::alloc_count::{CountingAllocator, count};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, DEFAULT_CLAIM_DEADLINE, DEFAULT_CORRUPT_RETRIES, LogBuffer, LogBufferConfig,
    PublicationMode, ReadOrigin, ReadOutcome, Role, SenderRead,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn a_sender_read_allocates_nothing() {
    let buffer = LogBuffer::new(LogBufferConfig {
        term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        spare_slots: 3,
        max_subscribers: 2,
        mtu: DEFAULT_MTU,
        max_reserved: MIN_TERM_LENGTH / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 3,
        stream_id: 4,
        claim_deadline: DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Exclusive,
        schedule_capacity: 0,
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = SenderRead::new(
        conductor.subscribe_as(Role::Required, true, 1).unwrap(),
        DEFAULT_CORRUPT_RETRIES,
    )
    .unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    for i in 0..8u8 {
        let _ = publication
            .append(
                &vec![i; 100 + usize::from(i) * 700],
                AppendOptions::default(),
            )
            .unwrap();
    }
    let mut out = vec![0u8; DEFAULT_MTU as usize];
    let (reads, allocations) = count(|| {
        let mut reads = 0u32;
        loop {
            let from = reader.position();
            match reader.read_committed(from, ReadOrigin::Cursor, &mut out) {
                Ok(ReadOutcome::Copied { .. } | ReadOutcome::Canonical { .. }) => reads += 1,
                Ok(ReadOutcome::Pending) => break,
                Err(error) => panic!("{error:?}"),
            }
            reader.sent(reader.position()).unwrap();
        }
        reads
    });
    assert!(reads >= 8);
    assert_eq!(allocations, 0, "{allocations} allocations in {reads} reads");
}
