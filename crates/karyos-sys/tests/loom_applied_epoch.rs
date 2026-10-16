// SPDX-License-Identifier: Apache-2.0

//! Loom model of a sender's applied guard epoch
//! (`karyos_sys::applied_epoch`; `quantstratum-docs:
//! karyos/design/guards-and-abort.md`, "The sender gate and applied
//! epoch"), over the production cell.
//!
//! The sender publishes two applied epochs, each with the last positions
//! it submitted under the epoch before; the guard's owner reads
//! concurrently, retrying on a torn read. Every read it accepts must be
//! one whole publication (or the initial cell): the positions it reports
//! for an applied epoch are those published with that epoch, so an owner
//! that sees a sender applied for close epoch `c` also sees every position
//! the sender submitted before applying it.
//!
//! Negative controls, each of which must fail with "torn applied epoch":
//! the even sequence stored Relaxed (nothing publishes the fields), the
//! fields stored before the odd sequence with no fence, and the in-flight
//! count stored after the even sequence, outside the lock (DN-7).
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test model, as ADR-0007 allows in tests"
)]

use karyos_sys::applied_epoch::{Applied, AppliedEpoch, WriterControl};
use loom::sync::Arc;
use loom::thread;

const PUBLISHED: [Applied; 2] = [
    Applied {
        epoch: 3,
        positions: [64, 32, 0, 0],
        in_flight: 2,
    },
    Applied {
        epoch: 5,
        positions: [128, 96, 0, 0],
        in_flight: 0,
    },
];

fn model(control: WriterControl) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let cell = Arc::new(AppliedEpoch::with_control(control));
        let sender = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                for applied in PUBLISHED {
                    cell.publish(applied);
                }
            })
        };
        // The owner: a bounded number of attempts, each accepted read
        // checked whole.
        for _ in 0..3 {
            if let Some(read) = cell.try_read() {
                let initial = read.epoch == 0 && read.positions == [0; 4] && read.in_flight == 0;
                assert!(
                    initial || PUBLISHED.contains(&read),
                    "torn applied epoch: {read:?}"
                );
            }
            thread::yield_now();
        }
        sender.join().unwrap();
        assert_eq!(cell.try_read(), Some(PUBLISHED[1]));
    });
}

#[test]
fn the_owner_reads_whole_publications() {
    model(WriterControl::None);
}

#[test]
#[should_panic(expected = "torn applied epoch")]
fn control_a_relaxed_publishing_store() {
    model(WriterControl::RelaxedRelease);
}

#[test]
#[should_panic(expected = "torn applied epoch")]
fn control_the_fields_before_the_sequence() {
    model(WriterControl::FieldsBeforeSequence);
}

#[test]
#[should_panic(expected = "torn applied epoch")]
fn control_the_in_flight_count_outside_the_sequence() {
    model(WriterControl::InFlightOutsideSequence);
}
