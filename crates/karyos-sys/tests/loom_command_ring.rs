// SPDX-License-Identifier: Apache-2.0

//! Loom model of `karyos_sys::command_ring` over the production
//! `RingWords`: a producer writes three records of different extents into a
//! 64-byte ring (the third needs a PAD and waits for room), retrying on
//! `Full`, while a consumer drains it. The consumer must receive exactly the
//! records written, in order, with every payload byte intact.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::command_ring::{RingError, RingRead, RingWords, TRAILER_WORDS};
use karyos_sys::sync::AtomicU64;
use loom::sync::Arc;
use loom::thread;

struct Ring {
    data: Vec<AtomicU64>,
    trailer: Vec<AtomicU64>,
}

impl Ring {
    fn words(&self) -> RingWords<'_> {
        RingWords::new(&self.data, &self.trailer, 32).unwrap()
    }
}

/// Type, position and payload length: 9 bytes (extent 24), 1 byte (extent
/// 16), then 17 bytes (extent 32) after a 24-byte PAD.
const RECORDS: [(u32, u64, usize); 3] = [(1, 0, 9), (2, 24, 1), (3, 64, 17)];

fn payload(type_id: u32, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| u8::try_from(type_id * 32 + u32::try_from(i).unwrap()).unwrap())
        .collect()
}

#[test]
fn records_arrive_once_in_order_and_intact() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(|| {
        let ring = Arc::new(Ring {
            data: (0..8).map(|_| AtomicU64::new(0)).collect(),
            trailer: (0..TRAILER_WORDS).map(|_| AtomicU64::new(0)).collect(),
        });
        let producer_ring = Arc::clone(&ring);
        let producer = thread::spawn(move || {
            let words = producer_ring.words();
            for (type_id, position, length) in RECORDS {
                loop {
                    match words.write(type_id, &payload(type_id, length)) {
                        Ok(written) => {
                            assert_eq!(written, position);
                            break;
                        }
                        Err(RingError::Full) => thread::yield_now(),
                        Err(other) => panic!("unexpected {other}"),
                    }
                }
            }
        });
        let words = ring.words();
        let mut out = vec![0u8; words.max_payload()];
        let mut received = 0;
        while received < RECORDS.len() {
            match words.read(&mut out).unwrap() {
                RingRead::Message {
                    position,
                    type_id,
                    length,
                } => {
                    let (expected_type, expected_position, expected_length) = RECORDS[received];
                    assert_eq!(
                        (type_id, position, length),
                        (expected_type, expected_position, expected_length)
                    );
                    assert_eq!(
                        &out[..length],
                        &payload(type_id, length)[..],
                        "corrupt payload"
                    );
                    received += 1;
                }
                RingRead::Pending => thread::yield_now(),
            }
        }
        producer.join().unwrap();
        assert_eq!(words.read(&mut out).unwrap(), RingRead::Pending);
    });
}
