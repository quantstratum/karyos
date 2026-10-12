// SPDX-License-Identifier: Apache-2.0

//! Loom model of `karyos_sys::broadcast` over the production
//! `BroadcastWords`: a writer sends three 16-byte records through a 32-byte
//! area, overwriting the first, while a reader receives concurrently. Every
//! message the reader accepts must carry its own payload, in order; a
//! reader overrun during its copy must report a lap, never mixed data.
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
}

impl Buffer {
    fn words(&self) -> BroadcastWords<'_> {
        BroadcastWords::new(&self.data, &self.trailer, 16).unwrap()
    }
}

fn payload(type_id: u32) -> [u8; 8] {
    [u8::try_from(type_id).unwrap(); 8]
}

#[test]
fn accepted_messages_are_never_mixed() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(|| {
        let buffer = Arc::new(Buffer {
            data: (0..4).map(|_| AtomicU64::new(0)).collect(),
            trailer: (0..TRAILER_WORDS).map(|_| AtomicU64::new(0)).collect(),
        });
        let writer_buffer = Arc::clone(&buffer);
        let writer = thread::spawn(move || {
            let words = writer_buffer.words();
            for type_id in 1..=3 {
                words.transmit(type_id, &payload(type_id)).unwrap();
            }
        });
        let reader_buffer = Arc::clone(&buffer);
        let reader = thread::spawn(move || {
            let words = reader_buffer.words();
            let mut cursor = 0;
            let mut last = 0;
            let mut out = [0u8; 8];
            for _ in 0..3 {
                match words.receive(&mut cursor, &mut out).unwrap() {
                    Receive::Message {
                        type_id, length, ..
                    } => {
                        assert_eq!(length, 8);
                        assert_eq!(out, payload(type_id), "mixed copy for {type_id}");
                        assert!(type_id > last, "out of order: {type_id} after {last}");
                        last = type_id;
                    }
                    Receive::Lapped {
                        lost_from,
                        rejoined_at,
                    } => assert!(rejoined_at > lost_from),
                    Receive::Pending => {}
                }
            }
        });
        writer.join().unwrap();
        reader.join().unwrap();
    });
}
