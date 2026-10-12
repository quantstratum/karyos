// SPDX-License-Identifier: Apache-2.0

//! Loom models of the conflation seqlock of `karyos_sys::conflation`, over
//! the production `SlotWords`: a writer writes two values into one slot
//! while a reader on its own thread reads it. A copy the reader accepts must
//! be one complete write: its version, its length and its bytes all from
//! the same write, never parts of two. Once the writer has finished, a read
//! returns the last value.
//!
//! The two models change the length between writes; in the second, the
//! later value is empty, so the length word is the only body word the later
//! write stores and the only witness that can reject a torn copy.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::conflation::{SlotRead, SlotWords};
use karyos_sys::sync::AtomicU64;
use loom::sync::Arc;
use loom::thread;

/// Version, length and two value words.
const WORDS: usize = 4;

/// Writes `first` (version 2) then `second` (version 4) while a reader
/// reads once; checks every accepted copy against the write of its version.
fn model(first: &'static [u8], second: &'static [u8]) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let words: Arc<Vec<AtomicU64>> = Arc::new((0..WORDS).map(|_| AtomicU64::new(0)).collect());
        let writer = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                let slot = SlotWords::new(&words).unwrap();
                assert_eq!(slot.write(first), Ok(2));
                assert_eq!(slot.write(second), Ok(4));
            })
        };
        let reader = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                let slot = SlotWords::new(&words).unwrap();
                let mut out = [0xEEu8; 16];
                match slot.read(&mut out) {
                    SlotRead::Value { version, length } => {
                        let expected = match version {
                            2 => first,
                            4 => second,
                            other => panic!("unexpected version {other}"),
                        };
                        assert_eq!(length, expected.len(), "version {version}");
                        assert_eq!(&out[..length], expected, "version {version}");
                    }
                    SlotRead::Empty | SlotRead::Unstable => {}
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();

        let slot = SlotWords::new(&words).unwrap();
        let mut last = [0u8; 16];
        assert_eq!(
            slot.read(&mut last),
            SlotRead::Value {
                version: 4,
                length: second.len()
            }
        );
        assert_eq!(&last[..second.len()], second);
    });
}

#[test]
fn accepted_copies_are_one_complete_write() {
    model(&[0x11; 16], &[0x22; 8]);
}

#[test]
fn an_empty_later_value_is_witnessed_by_the_length() {
    model(&[0x11; 16], &[]);
}
