// SPDX-License-Identifier: Apache-2.0

//! Loom model of the production fresh slot ([`FreshSlotWords`], GU-8): one
//! seqlock covers the value version, the value and the two freshness words.
//! The writer writes a value, marks the slot stale (a freshness-only
//! write), then writes a second value; a reader's accepted copy is always
//! one of the three states the writer produced, never a mix: the value
//! matches its version, the freshness matches the step, and a
//! freshness-only write never changes the value version.
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test model, as ADR-0007 allows in tests"
)]

use karyos_sys::conflation::{FreshRead, FreshSlotWords};
use karyos_sys::freshness::{STALE, SlotFreshness};
use karyos_sys::sync::AtomicU64;
use loom::sync::Arc;
use loom::thread;

const STALE_AT_8: SlotFreshness = SlotFreshness {
    loss_applied: 1 | STALE,
    stale_since: 8,
};

#[test]
fn a_reader_sees_value_and_freshness_coherent() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(|| {
        // The five header words and two value words.
        let words: Arc<Vec<AtomicU64>> = Arc::new((0..7).map(|_| AtomicU64::new(0)).collect());
        let writer = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                let slot = FreshSlotWords::new(&words).unwrap();
                assert_eq!(slot.write(b"first"), Ok(2));
                slot.set_freshness(STALE_AT_8).unwrap();
                assert_eq!(slot.write(b"second!!"), Ok(4));
            })
        };
        let reader = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                let slot = FreshSlotWords::new(&words).unwrap();
                let mut out = [0u8; 16];
                match slot.read(&mut out) {
                    FreshRead::Empty | FreshRead::Unstable => {}
                    FreshRead::Value {
                        version,
                        length,
                        freshness,
                    } => match version {
                        // Before or after the freshness-only write.
                        2 => {
                            assert_eq!(&out[..length], b"first", "torn value");
                            assert!(
                                freshness == SlotFreshness::default() || freshness == STALE_AT_8,
                                "torn freshness"
                            );
                        }
                        4 => {
                            assert_eq!(&out[..length], b"second!!", "torn value");
                            assert_eq!(freshness, STALE_AT_8, "a value write lost the freshness");
                        }
                        other => panic!("unexpected version {other}"),
                    },
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();
    });
}
