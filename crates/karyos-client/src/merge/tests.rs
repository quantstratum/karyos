// SPDX-License-Identifier: Apache-2.0

//! The merge over two log buffers holding the same messages at the same
//! positions, one read as the replay and one as the live stream: a poll
//! allocates nothing, nor frees, but the cutover's, which frees the
//! replay.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::sync::Arc;

use karyos_sys::log_buffer::{AppendOptions, LogBuffer, LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;

fn buffer() -> Arc<LogBuffer> {
    Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 2,
            max_subscribers: 2,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
        })
        .unwrap(),
    )
}

/// Appends messages `from..to`, each holding its index.
fn append(
    publication: &mut karyos_sys::log_buffer::Publication<Arc<LogBuffer>>,
    from: u32,
    to: u32,
) {
    for index in from..to {
        let mut message = [0u8; 100];
        message[..4].copy_from_slice(&index.to_le_bytes());
        let _ = publication
            .append(&message, AppendOptions::default())
            .unwrap();
    }
}

/// Every poll of a merge, on the replay and on the live reader, neither
/// allocates nor frees; the cutover's frees exactly what dropping a replay
/// frees.
#[test]
fn a_merge_poll_does_not_allocate() {
    let (replayed, live) = (buffer(), buffer());
    let mut conductor = replayed.conductor_owned().unwrap();
    let replay = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let mut replayed_publication = replayed.publication_owned().unwrap().unwrap();
    let mut live_publication = live.publication_owned().unwrap().unwrap();
    append(&mut replayed_publication, 0, 30);
    append(&mut live_publication, 0, 20);
    let reader = ClientSubscription::new(
        live.conductor_owned()
            .unwrap()
            .subscribe(Role::Required)
            .unwrap(),
    );
    append(&mut live_publication, 20, 30);
    let source = PublicationIdentity::default();
    // What dropping a replay costs, on a reader of the same buffer.
    let other = Box::new(Replay::new(
        ClientSubscription::new(conductor.subscribe(Role::Required).unwrap()),
        source,
    ));
    let ((), dropping) = karyos_sys::alloc_count::count(|| drop(other));
    let mut merge = LiveMerge::new(reader, source, Box::new(Replay::new(replay, source)));
    let mut seen = Vec::with_capacity(64);
    let mut cutovers = 0;
    for _ in 0..16 {
        let (polled, operations) = karyos_sys::alloc_count::count(|| {
            merge
                .poll(
                    |bytes, _| seen.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                    MessageLimit::new(4),
                )
                .ok()
        });
        if polled.unwrap().cutover.is_some() {
            cutovers += 1;
            assert_eq!(
                operations, dropping,
                "the cutover did more than free the replay"
            );
        } else {
            assert_eq!(operations, 0, "a poll allocated or freed");
        }
    }
    assert_eq!(seen, (0..30).collect::<Vec<_>>());
    assert_eq!(cutovers, 1);
}
