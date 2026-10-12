// SPDX-License-Identifier: Apache-2.0

//! Loom models of `karyos_sys::broadcast` over the production
//! `BroadcastWords`. A writer sends three records through a small area,
//! overwriting the first, while a reader receives concurrently. Every
//! message the reader accepts must be exactly the record written at its
//! position (type, position, length and every payload byte), in order; a
//! reader overrun during its copy must report a lap that moves forward,
//! never mixed data. After the joins, a quiescent read of a known record
//! must succeed.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::broadcast::{BroadcastWords, Receive, TRAILER_WORDS};
use karyos_sys::sync::AtomicU64;
use loom::sync::Arc;
use loom::thread;

struct Buffer {
    data: Vec<AtomicU64>,
    trailer: Vec<AtomicU64>,
    max_extent: u64,
}

impl Buffer {
    fn new(data_words: usize, max_extent: u64) -> Arc<Self> {
        Arc::new(Self {
            data: (0..data_words).map(|_| AtomicU64::new(0)).collect(),
            trailer: (0..TRAILER_WORDS).map(|_| AtomicU64::new(0)).collect(),
            max_extent,
        })
    }

    fn words(&self) -> BroadcastWords<'_> {
        BroadcastWords::new(&self.data, &self.trailer, self.max_extent).unwrap()
    }
}

/// A record: type, position and payload length.
type Record = (u32, u64, usize);

fn payload(type_id: u32, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| u8::try_from(type_id * 32 + u32::try_from(i).unwrap()).unwrap())
        .collect()
}

fn run(data_words: usize, max_extent: u64, records: &'static [Record]) {
    let buffer = Buffer::new(data_words, max_extent);
    let writer_buffer = Arc::clone(&buffer);
    let writer = thread::spawn(move || {
        let words = writer_buffer.words();
        for &(type_id, position, length) in records {
            let written = words.transmit(type_id, &payload(type_id, length)).unwrap();
            assert_eq!(written, position);
        }
    });
    let reader_buffer = Arc::clone(&buffer);
    let reader = thread::spawn(move || {
        let words = reader_buffer.words();
        let mut cursor = 0;
        let mut last = 0;
        let mut out = vec![0u8; words.max_payload()];
        for _ in 0..records.len() {
            match words.receive(&mut cursor, &mut out).unwrap() {
                Receive::Message {
                    position,
                    type_id,
                    length,
                } => {
                    let &(_, expected_position, expected_length) = records
                        .iter()
                        .find(|record| record.0 == type_id)
                        .expect("unknown record type");
                    assert_eq!(position, expected_position, "wrong position");
                    assert_eq!(length, expected_length, "wrong length");
                    assert_eq!(&out[..length], &payload(type_id, length)[..], "mixed copy");
                    assert!(type_id > last, "out of order: {type_id} after {last}");
                    last = type_id;
                }
                Receive::Lapped {
                    lost_from,
                    rejoined_at,
                } => assert!(rejoined_at > lost_from, "lap {lost_from} -> {rejoined_at}"),
                Receive::Pending => {}
            }
        }
    });
    writer.join().unwrap();
    reader.join().unwrap();

    // Quiescent: a reader at the last record's position must receive it.
    let words = buffer.words();
    let &(type_id, position, length) = records.last().unwrap();
    let mut cursor = position;
    let mut out = vec![0u8; words.max_payload()];
    assert_eq!(
        words.receive(&mut cursor, &mut out).unwrap(),
        Receive::Message {
            position,
            type_id,
            length,
        }
    );
    assert_eq!(&out[..length], &payload(type_id, length)[..]);
}

fn builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder
}

/// 32-byte area, three 16-byte records: the third overwrites the first.
#[test]
fn fixed_records_are_never_mixed() {
    static RECORDS: [Record; 3] = [(1, 0, 8), (2, 16, 8), (3, 32, 8)];
    builder().check(|| run(4, 16, &RECORDS));
}

/// 64-byte area with variable extents: 9-byte payload (extent 24), 1-byte
/// payload (extent 16), then a 17-byte payload (extent 32) that needs a
/// 24-byte PAD and overwrites the first record from offset 0.
#[test]
fn variable_records_and_padding_are_never_mixed() {
    static RECORDS: [Record; 3] = [(1, 0, 9), (2, 24, 1), (3, 64, 17)];
    builder().check(|| run(8, 32, &RECORDS));
}
