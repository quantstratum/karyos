// SPDX-License-Identifier: Apache-2.0

//! Loom model of a guarded network lane's submission frontier
//! (`karyos_sys::submission_frontier`; `quantstratum-docs:
//! karyos/design/guards-and-abort.md`, "Trusted sockets in Phase 2"), over
//! the production cell.
//!
//! The gate publishes two frontiers, the second with a hole below its
//! `resolved`, then finishes the lane; the conductor supersedes the lane
//! at the same time, the final word's other writer. The walker reads
//! concurrently. Every read must hold:
//!
//! - a `resolved` comes with every hole published with or before it;
//! - a final word the gate wrote comes with the gate's last publication;
//! - no field is lower than in an earlier read;
//! - exactly one of the two final writers wins, and the word stays its.
//!
//! Negative controls, each of which must fail with its message:
//! `resolved` stored Relaxed ("a hole below resolved unseen"), the gate's
//! final word stored Relaxed ("a final word without its publication"),
//! and a final word stored without a compare-exchange ("two final
//! writers").
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test model, as ADR-0007 allows in tests"
)]

use karyos_sys::frame::Lane;
use karyos_sys::submission_frontier::{Final, Frontier, SubmissionFrontier, WriterControl};
use loom::sync::Arc;
use loom::thread;

const PUBLISHED: [Frontier; 2] = [
    Frontier {
        resolved: 64,
        unknown_hi: 0,
        staged_hi: 96,
    },
    Frontier {
        resolved: 160,
        unknown_hi: 128,
        staged_hi: 192,
    },
];
const GUARD_CLOSED: u64 = 1;
const DRIVER_SHUTDOWN: u64 = 5;

fn checked(read: (Final, Frontier), earlier: Frontier) -> Frontier {
    let (state, frontier) = read;
    if frontier.resolved >= PUBLISHED[1].resolved {
        assert!(
            frontier.unknown_hi >= PUBLISHED[1].unknown_hi,
            "a hole below resolved unseen: {frontier:?}"
        );
    }
    if state
        == (Final::Finished {
            reason: GUARD_CLOSED,
        })
    {
        assert_eq!(
            frontier, PUBLISHED[1],
            "a final word without its publication"
        );
    }
    assert!(
        frontier.resolved >= earlier.resolved
            && frontier.unknown_hi >= earlier.unknown_hi
            && frontier.staged_hi >= earlier.staged_hi,
        "a field went down: {frontier:?} after {earlier:?}"
    );
    frontier
}

fn model(control: WriterControl) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let cell = Arc::new(SubmissionFrontier::with_control(control));
        let gate = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                for frontier in PUBLISHED {
                    cell.publish(Lane::ZERO, frontier);
                }
                cell.finish(Lane::ZERO, GUARD_CLOSED).unwrap()
            })
        };
        let conductor = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || cell.supersede(Lane::ZERO, DRIVER_SHUTDOWN).unwrap())
        };
        let mut earlier = Frontier::default();
        for _ in 0..2 {
            earlier = checked(cell.read(Lane::ZERO), earlier);
            thread::yield_now();
        }
        let finished = gate.join().unwrap();
        let superseded = conductor.join().unwrap();
        assert!(finished != superseded, "two final writers");
        let (state, frontier) = cell.read(Lane::ZERO);
        let _ = checked((state, frontier), earlier);
        let expected = if finished {
            Final::Finished {
                reason: GUARD_CLOSED,
            }
        } else {
            Final::Superseded {
                reason: DRIVER_SHUTDOWN,
            }
        };
        assert_eq!(state, expected, "two final writers");
        assert_eq!(frontier, PUBLISHED[1]);
    });
}

#[test]
fn the_walker_reads_holes_and_finals_with_their_frontier() {
    model(WriterControl::None);
}

#[test]
#[should_panic(expected = "a hole below resolved unseen")]
fn control_a_relaxed_resolved() {
    model(WriterControl::RelaxedResolved);
}

#[test]
#[should_panic(expected = "a final word without its publication")]
fn control_a_relaxed_final_word() {
    model(WriterControl::RelaxedFinal);
}

#[test]
#[should_panic(expected = "two final writers")]
fn control_an_unchecked_final_word() {
    model(WriterControl::UncheckedFinal);
}
