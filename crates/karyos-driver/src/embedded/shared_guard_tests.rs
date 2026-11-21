// SPDX-License-Identifier: Apache-2.0

//! Concurrent guarded streams share one outcome ring per incarnation
//! (ADR-0092; karyos#1102 (b)): `H` slots from the publisher slot count,
//! the ring created at the first guarded handle, one client per
//! incarnation, and the walker writing through the shared writer.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, ConcurrentOfferOutcome, LogBufferConfig, PublicationMode,
};
use karyos_sys::outcome_ring::Kind;
use karyos_sys::outcome_ring::shared::{SharedOutcomeReader, SharedRecord};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;
use karyos_client::ConsumedCell;

use crate::guard_streams::ShareClient;

fn concurrent(driver: &mut EmbeddedDriver, publishers: u8) -> StreamHandle {
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 6,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 16,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 9,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Concurrent {
                    publishers,
                    allow_non_lse: true,
                },
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
            conflation: None,
        })
        .unwrap()
}

/// A driver with a concurrent stream of `H = 2`, guarded with `C_m = 2`
/// and its guard open at epoch 2.
fn guarded() -> (EmbeddedDriver, StreamHandle, GuardHandle) {
    let mut driver = EmbeddedDriver::new().unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let handle = concurrent(&mut driver, 2);
    driver.guard_stream(handle, guard, 2, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    (driver, handle, guard)
}

/// Every record `reader` delivers, polling its slot's cell.
fn delivered(
    reader: &mut SharedOutcomeReader,
    slot: &crate::guard_streams::SharedSlot,
) -> Vec<(Kind, u64, u64)> {
    let mut seen = Vec::new();
    let _ = reader
        .poll(&*slot.ring, slot.cell.cell(), 64, |_, record| {
            if let SharedRecord::Delivered(record) = record {
                seen.push((record.kind, record.start, record.reason));
            }
        })
        .unwrap();
    seen
}

#[test]
fn slots_come_from_the_publisher_count_and_one_client_holds_them() {
    let (mut driver, handle, _) = guarded();
    let first = driver
        .attach_concurrent_guard(handle, ShareClient::InProcess)
        .unwrap();
    assert_eq!((first.slot, first.consumed), (0, 0));
    assert_eq!(first.binding.handles, 2);
    assert_eq!(first.binding.messages, 2);
    assert_eq!(first.binding.epoch, 2);
    // The ring's header, layout version 3: `H * C_m + C_r + H` slots.
    assert_eq!(
        karyos_sys::outcome_ring::shared::binding(&*first.ring, 64),
        Ok(first.binding)
    );
    assert_eq!(first.binding.capacity(), Some(2 * 2 + 1 + 2));
    // Another client is refused (ADR-0092 decision 2).
    assert_eq!(
        driver
            .attach_concurrent_guard(handle, ShareClient::Remote(7))
            .unwrap_err(),
        DriverError::Sys(karyos_sys::error::SysError::InvalidPublicationMode {
            reason: "GC-7-client"
        })
    );
    let second = driver
        .attach_concurrent_guard(handle, ShareClient::InProcess)
        .unwrap();
    assert_eq!(second.slot, 1);
    assert!(Arc::ptr_eq(&first.ring, &second.ring));
    // A detached slot is not issued again: the third handle is refused.
    driver.detach_concurrent_guard(handle, 0);
    assert_eq!(
        driver
            .attach_concurrent_guard(handle, ShareClient::InProcess)
            .unwrap_err(),
        DriverError::GuardHandleSlotsExhausted {
            stream: handle.stream,
            handles: 2,
        }
    );
}

#[test]
fn guarding_a_concurrent_stream_checks_its_slots_and_window() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let guard = driver.add_guard("orders").unwrap();
    let handle = concurrent(&mut driver, 2);
    // max_reserved is a sixteenth of a term: two handles of five do not
    // fit half a term, two of four do.
    assert_eq!(
        driver.guard_stream(handle, guard, 5, None),
        Err(DriverError::InvalidConfig)
    );
    driver.guard_stream(handle, guard, 4, None).unwrap();
    // The ring is created at the first guarded handle, under an open guard.
    assert!(matches!(
        driver.attach_concurrent_guard(handle, ShareClient::InProcess),
        Err(DriverError::GuardNotOpen { .. })
    ));
}

#[test]
fn the_walker_writes_every_handles_records_into_the_shared_ring() {
    let (mut driver, handle, guard) = guarded();
    let a = driver
        .attach_concurrent_guard(handle, ShareClient::InProcess)
        .unwrap();
    let b = driver
        .attach_concurrent_guard(handle, ShareClient::InProcess)
        .unwrap();
    let mut reader_a = SharedOutcomeReader::attach(&*a.ring, 1, 0, a.consumed).unwrap();
    let mut reader_b = SharedOutcomeReader::attach(&*b.ring, 1, 1, b.consumed).unwrap();
    let mut publisher = driver
        .stream(handle)
        .unwrap()
        .conductor
        .concurrent_publication()
        .unwrap()
        .unwrap();
    let mut positions = Vec::new();
    for _ in 0..3 {
        match publisher.offer(b"order", AppendOptions::default()).unwrap() {
            ConcurrentOfferOutcome::Appended { position } => positions.push(position),
            other => panic!("not appended: {other:?}"),
        }
    }
    assert!(reader_a.reserve(0, positions[0]));
    assert!(reader_b.reserve(0, positions[1]));
    assert!(reader_a.reserve(0, positions[2]));
    let _ = driver.do_work().unwrap();
    assert_eq!(
        delivered(&mut reader_a, &a),
        [
            (Kind::Submitted, positions[0], 0),
            (Kind::Submitted, positions[2], 0)
        ]
    );
    assert_eq!(
        delivered(&mut reader_b, &b),
        [(Kind::Submitted, positions[1], 0)]
    );
    // A guard close seals the incarnation: every handle reads `Ended`,
    // `GUARD_CLOSED`.
    driver.close_guard(guard, 2).unwrap();
    drop(publisher);
    for _ in 0..4 {
        let _ = driver.do_work().unwrap();
    }
    let ended = |seen: Vec<(Kind, u64, u64)>| {
        seen.iter()
            .any(|&(kind, _, reason)| kind == Kind::Ended && reason == 1)
    };
    assert!(ended(delivered(&mut reader_a, &a)));
    assert!(ended(delivered(&mut reader_b, &b)));
}

#[test]
fn a_detached_handle_leaves_the_room_minimum() {
    let (mut driver, handle, _) = guarded();
    let a = driver
        .attach_concurrent_guard(handle, ShareClient::InProcess)
        .unwrap();
    let b = driver
        .attach_concurrent_guard(handle, ShareClient::InProcess)
        .unwrap();
    let mut reader_a = SharedOutcomeReader::attach(&*a.ring, 1, 0, a.consumed).unwrap();
    // B never polls; detached, it holds no room back, so A reads past the
    // ring's ordinary bound without being faulted.
    driver.detach_concurrent_guard(handle, b.slot);
    let mut publisher = driver
        .stream(handle)
        .unwrap()
        .conductor
        .concurrent_publication()
        .unwrap()
        .unwrap();
    let mut read = 0;
    for _ in 0..12 {
        let ConcurrentOfferOutcome::Appended { position } =
            publisher.offer(b"order", AppendOptions::default()).unwrap()
        else {
            panic!("not appended");
        };
        assert!(reader_a.reserve(0, position));
        let _ = driver.do_work().unwrap();
        let seen = delivered(&mut reader_a, &a);
        assert_eq!(seen, [(Kind::Submitted, position, 0)]);
        read += seen.len();
    }
    assert_eq!(read, 12);
}

/// karyos#1102 (c): concurrent guarded handles from the driver. Each
/// reserves through its slot's reader, answers `BackPressured` at its own
/// quota, polls only its own records, and reads `Gated` and `Ended` after
/// the close; a dropped handle leaves the room minimum.
#[test]
fn concurrent_guarded_handles_keep_their_own_outcomes() {
    use karyos_client::ConcurrentOfferOutcome as Offer;

    let (mut driver, handle, guard) = guarded();
    let mut a = driver.concurrent_publication(handle).unwrap();
    let mut b = driver.concurrent_publication(handle).unwrap();
    assert_eq!(a.guard().unwrap().outstanding(), 0);
    let position = |outcome| match outcome {
        Offer::Accepted { position, .. } => position,
        other => panic!("not accepted: {other:?}"),
    };
    let a1 = position(a.offer(b"a1").unwrap());
    let b1 = position(b.offer(b"b1").unwrap());
    let a2 = position(a.offer(b"a2").unwrap());
    // C_m = 2: A's quota is full, B's is not.
    assert_eq!(a.offer(b"a3").unwrap(), Offer::BackPressured);
    assert_eq!(a.guard().unwrap().outstanding(), 2);
    let _ = driver.do_work().unwrap();
    let mut seen_a = Vec::new();
    let _ = a
        .poll_outcomes(16, |_, record| seen_a.push((record.kind, record.start)))
        .unwrap();
    assert_eq!(seen_a, [(Kind::Submitted, a1), (Kind::Submitted, a2)]);
    let mut seen_b = Vec::new();
    let _ = b
        .poll_outcomes(16, |_, record| seen_b.push((record.kind, record.start)))
        .unwrap();
    assert_eq!(seen_b, [(Kind::Submitted, b1)]);
    // Records read: A's quota is free again.
    assert_eq!(a.guard().unwrap().outstanding(), 0);
    let _ = position(a.offer(b"a3").unwrap());
    // A dropped handle is detached; the other keeps reading.
    drop(b);
    driver.close_guard(guard, 2).unwrap();
    assert_eq!(a.offer(b"late").unwrap(), Offer::Gated);
    let mut ended = false;
    for _ in 0..8 {
        let _ = driver.do_work().unwrap();
        let _ = a
            .poll_outcomes(16, |_, record| ended |= record.kind == Kind::Ended)
            .unwrap();
    }
    assert!(ended, "A reads the incarnation's Ended record");
}
