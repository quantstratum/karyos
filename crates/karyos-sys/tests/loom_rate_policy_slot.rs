// SPDX-License-Identifier: Apache-2.0

//! Loom model of a published rate policy (`karyos_sys::rate_policy_slot`;
//! R-CORE-21, karyos#740), over the production slot: the driver publishes
//! two policies while a handle reads. Every read the handle accepts is one
//! whole publication, its version paired with its own policy, so a handle
//! never applies a policy half written.
//!
//! Run with `make loom`. It runs in under a second: one read against both
//! publications, explored up to two preemptions. Removing the reader's
//! second sequence check makes it fail with a torn policy.

#![cfg(loom)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test model, as ADR-0007 allows in tests"
)]

use karyos_sys::rate_limit::{Rate, RatePolicy};
use karyos_sys::rate_policy_slot::{OUTCOME_SLOT, SLOT_WORDS, SlotRead, publish, try_read};
use karyos_sys::sync::AtomicU64;
use loom::sync::Arc;
use loom::thread;

fn policy(rate: u64, burst: u64, bytes: Option<(u64, u64)>) -> RatePolicy {
    RatePolicy {
        messages: Rate {
            per_second: rate,
            burst,
        },
        bytes: bytes.map(|(per_second, burst)| Rate { per_second, burst }),
    }
}

#[test]
fn a_handle_never_reads_a_policy_half_written() {
    let published = [
        (1, policy(100, 10, Some((10_000, 2_000)))),
        (2, policy(50, 5, None)),
    ];
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let words: Arc<Vec<AtomicU64>> = Arc::new(
            (0..OUTCOME_SLOT + SLOT_WORDS)
                .map(|_| AtomicU64::new(0))
                .collect(),
        );
        let driver = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                for (version, policy) in published {
                    publish(&words, OUTCOME_SLOT, version, &policy);
                }
            })
        };
        // One read against both publications: with two preemptions it
        // meets each interleaving with either write, the second's over the
        // first's fields included.
        let view: &[AtomicU64] = &words;
        match try_read(&view, OUTCOME_SLOT) {
            SlotRead::Unpublished | SlotRead::Busy => {}
            SlotRead::Policy { version, policy } => {
                assert!(
                    published.contains(&(version, policy)),
                    "torn policy: {version} {policy:?}"
                );
            }
        }
        driver.join().unwrap();
        let view: &[AtomicU64] = &words;
        assert_eq!(
            try_read(&view, OUTCOME_SLOT),
            SlotRead::Policy {
                version: 2,
                policy: published[1].1
            }
        );
    });
}
