// SPDX-License-Identifier: Apache-2.0

//! Loom model of the production fresh slot ([`FreshSlotWords`], GU-8): one
//! seqlock covers the value version, the value and the two freshness words.
//!
//! The writer writes a value, two freshness-only updates, then a second
//! value. A reader's accepted copy is always a state the writer produced:
//! the value matches its version, the two freshness words come from the
//! same write (never one word of each), and a freshness-only write never
//! changes the value version. The control stores the freshness words
//! outside the seqlock and must fail.
//!
//! The conflation table's other slot model, `loom_conflation.rs`, covers
//! [`SlotWords`](karyos_sys::conflation::SlotWords), which the record
//! journal still uses.
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test model, as ADR-0007 allows in tests"
)]

use karyos_sys::conflation::{FreshRead, FreshSlotWords};
use karyos_sys::freshness::{STALE, SlotFreshness};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

/// The two freshness writes; a mix of their words is torn.
const FIRST: SlotFreshness = SlotFreshness {
    loss_applied: 1 | STALE,
    stale_since: 8,
};
const SECOND: SlotFreshness = SlotFreshness {
    loss_applied: 2 | STALE,
    stale_since: 4,
};

fn model(inside_seqlock: bool) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        // The five header words and two value words: both values span
        // both words.
        let words: Arc<Vec<AtomicU64>> = Arc::new((0..7).map(|_| AtomicU64::new(0)).collect());
        let writer = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                let slot = FreshSlotWords::new(&words).unwrap();
                assert_eq!(slot.write(b"first value!"), Ok(2));
                for freshness in [FIRST, SECOND] {
                    if inside_seqlock {
                        slot.set_freshness(freshness).unwrap();
                    } else {
                        // Control: the freshness words without the seqlock.
                        words[3].store(freshness.loss_applied, Ordering::Relaxed);
                        words[4].store(freshness.stale_since, Ordering::Relaxed);
                    }
                }
                assert_eq!(slot.write(b"second value!!!"), Ok(4));
            })
        };
        let reader = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                let slot = FreshSlotWords::new(&words).unwrap();
                let mut out = [0u8; 16];
                if let FreshRead::Value {
                    version,
                    length,
                    freshness,
                } = slot.read(&mut out)
                {
                    assert!(
                        [SlotFreshness::default(), FIRST, SECOND].contains(&freshness),
                        "torn freshness"
                    );
                    match version {
                        2 => assert_eq!(&out[..length], b"first value!", "torn value"),
                        4 => {
                            assert_eq!(&out[..length], b"second value!!!", "torn value");
                            assert_eq!(freshness, SECOND, "a value write lost the freshness");
                        }
                        other => panic!("unexpected version {other}"),
                    }
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();
    });
}

#[test]
fn a_reader_sees_value_and_freshness_coherent() {
    model(true);
}

#[test]
#[should_panic(expected = "torn freshness")]
fn control_freshness_outside_the_seqlock_is_torn() {
    model(false);
}
