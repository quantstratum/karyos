// SPDX-License-Identifier: Apache-2.0

//! Loom models of the span walk of the concurrent commit-deadline abort
//! (`quantstratum-docs: karyos/design/concurrent-deadline.md`, batch c2), over the production
//! helpers of `karyos_sys::publication`:
//!
//! - the walk racing two writers' marks over a span of two boundaries
//!   (frozen bound after the second): each boundary is owned by exactly one
//!   party; a writer that marked keeps its block (also one that marks and
//!   commits before the walk's first compare-exchange fails, which then
//!   stores nothing); the final `ABORTED` never covers a marked block; a
//!   writer whose mark fails finds the exact marker or the span's
//!   `ABORTED`, never a word that reads as a reserved one;
//! - the walk against a reader: the marker is never read as terminal, and
//!   a reader that sees the span's `ABORTED` sees every marker of it.
//!
//! Negative controls must fail: the walk storing `ABORTED` before marking,
//! a terminal store after a lost first compare-exchange, a marker equal to
//! a valid reserved word, and a walk passing a non-zero word.
//!
//! Exploration: default Loom bounds; the walk and two writers, or the walk
//! and one reader.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::publication::{
    ABORTING_MARKER, commit_block, end_span, mark_block, observe_block, reserved_extent,
    take_span_word,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

/// Two 32-byte boundaries; the span's frozen bound is their end.
const TERM: u32 = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Walk {
    Production,
    StoreFirst,
    StoreAfterLostFirst,
    PassNonZero,
    MarkerIsReserved,
}

fn reserved() -> Word0 {
    Word0::new(
        -32,
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

fn committed() -> Word0 {
    Word0::new(
        32,
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

fn aborted(extent: u32) -> Word0 {
    Word0::new(
        extent as i32,
        Flags::new(false, false, false, false, Lane::ZERO),
        FrameType::Aborted,
    )
}

/// Takes one boundary: the production helper, or a control marker equal
/// to a valid reserved word.
fn take(word: &AtomicU64, walk: Walk) -> bool {
    match walk {
        Walk::MarkerIsReserved => word
            .compare_exchange(
                0,
                reserved().pack().to_le(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok(),
        _ => take_span_word(word).is_ok(),
    }
}

/// The span walk from boundary 0 up to the frozen bound. Returns the
/// boundaries it owns and the extent of the `ABORTED` it stored.
fn walk(words: &[AtomicU64; 2], walk: Walk) -> ([bool; 2], Option<u32>) {
    if walk == Walk::StoreFirst {
        end_span(&words[0], aborted(TERM));
        let owned = [false, take(&words[1], walk)];
        return (owned, Some(TERM));
    }
    if !take(&words[0], walk) {
        if walk == Walk::StoreAfterLostFirst {
            end_span(&words[0], aborted(TERM));
            return ([false, false], Some(TERM));
        }
        // A writer marked first: no span, nothing stored.
        return ([false, false], None);
    }
    let second = take(&words[1], walk);
    let end = if second || walk == Walk::PassNonZero {
        TERM
    } else {
        32
    };
    end_span(&words[0], aborted(end));
    ([true, second], Some(end))
}

/// A writer of the one-boundary block at `index`: marks, then commits.
/// Returns whether it marked.
fn writer(words: &[AtomicU64; 2], index: usize) -> bool {
    let word = &words[index];
    if mark_block(word, reserved()) {
        assert!(
            commit_block(word, reserved(), committed()),
            "a marked block lost its commit to the walk"
        );
        return true;
    }
    // Nothing written; the word is the walk's.
    let found = observe_block(word);
    let offset = 32 * index as u32;
    assert!(
        reserved_extent(found, offset, TERM, TERM, Lane::ZERO).is_none(),
        "the marker reads as a reserved word"
    );
    assert!(
        found == ABORTING_MARKER.pack()
            || (index == 0 && found == aborted(32).pack())
            || (index == 0 && found == aborted(TERM).pack()),
        "a failed mark found a foreign word"
    );
    false
}

fn race_model(variant: Walk) {
    loom::model(move || {
        let words = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        let writers: Vec<_> = (0..2)
            .map(|index| {
                let words = Arc::clone(&words);
                thread::spawn(move || writer(&words, index))
            })
            .collect();
        let (owned, stored) = walk(&words, variant);
        let marked: Vec<bool> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        for index in 0..2 {
            assert!(
                !(owned[index] && marked[index]),
                "a boundary owned by the walk and a writer"
            );
        }
        if marked[0] {
            assert_eq!(
                observe_block(&words[0]),
                committed().pack(),
                "a marked block lost to the walk"
            );
        }
        if let Some(extent) = stored {
            for (index, marked) in marked.iter().enumerate() {
                assert!(
                    !(*marked && 32 * (index as u32) < extent),
                    "ABORTED covers a marked block"
                );
            }
        }
    });
}

#[test]
fn the_span_walk_and_writers_own_disjoint_boundaries() {
    race_model(Walk::Production);
}

#[test]
#[should_panic(expected = "ABORTED covers a marked block")]
fn control_storing_aborted_before_marking_fails() {
    race_model(Walk::StoreFirst);
}

#[test]
#[should_panic(expected = "a marked block lost")]
fn control_a_store_after_a_lost_first_take_fails() {
    race_model(Walk::StoreAfterLostFirst);
}

#[test]
#[should_panic(expected = "the marker reads as a reserved word")]
fn control_a_marker_equal_to_a_reserved_word_fails() {
    race_model(Walk::MarkerIsReserved);
}

#[test]
#[should_panic(expected = "ABORTED covers a marked block")]
fn control_passing_a_non_zero_word_fails() {
    race_model(Walk::PassNonZero);
}

fn reader_model(variant: Walk) {
    loom::model(move || {
        let words = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        let reader = {
            let words = Arc::clone(&words);
            thread::spawn(move || {
                let first = observe_block(&words[0]);
                if first as u32 as i32 > 0 {
                    // Terminal: only the span's ABORTED, with every marker
                    // of it placed before.
                    assert_eq!(first, aborted(TERM).pack(), "marker read as terminal");
                    assert_eq!(
                        u64::from_le(words[1].load(Ordering::Relaxed)),
                        ABORTING_MARKER.pack(),
                        "aborted span published before its markers"
                    );
                }
            })
        };
        let _ = walk(&words, variant);
        reader.join().unwrap();
    });
}

#[test]
fn the_marker_is_never_terminal_to_a_reader() {
    reader_model(Walk::Production);
}

#[test]
#[should_panic(expected = "aborted span published before its markers")]
fn control_a_reader_sees_aborted_before_the_markers() {
    reader_model(Walk::StoreFirst);
}
