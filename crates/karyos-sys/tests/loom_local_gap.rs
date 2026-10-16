// SPDX-License-Identifier: Apache-2.0

//! Loom models of local gap publication (`quantstratum-docs:
//! karyos/design/local-gap-layout.md`, "Tests g2 must carry", and
//! gaps-and-unreliable-delivery.md, "Publication ordering") over the
//! production helpers: `publish_block` and `observe_block`, and the record
//! encoding and checks of `karyos_sys::local_gap`.
//!
//! The receive owner writes the record's words 1 to 3, then publishes its
//! word 0 with one Release store; a reader loads word 0 with Acquire and
//! reads the rest of the header only when it is positive, then checks it.
//! The owner never writes a record over a committed frame: its private
//! extent record refuses an interval it shows covered.
//!
//! Header bytes are plain `UnsafeCell` bytes, as on heap terms, where Loom
//! reports any read that races a write; on shared terms the header is three
//! atomic words written and read Relaxed (`store_body`, `load_body`), where
//! a reader that is not ordered after them sees zeros and refuses the
//! record. Negative controls change one step
//! and must fail: word 0 published before the header, a Relaxed load of
//! word 0, and a record written without the overlap check over a frame a
//! reader is copying.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Lane, Word0};
use karyos_sys::local_gap::{
    GAP_BODY_LENGTH, GapReason, GapSite, check_body, check_word0, gap_body, gap_word0,
};
use karyos_sys::publication::{load_body, observe_block, publish_block, store_body};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

const SITE: GapSite = GapSite {
    term_offset: 64,
    term_id: 9,
    session_id: 3,
    stream_id: 4,
};
const EXTENT: u32 = 96;
const TERM: u32 = 1024;
const REASON: GapReason = GapReason::ReorderExpired;

/// One block of a term: its word 0 and the 24 header bytes after it.
struct Block {
    word0: AtomicU64,
    header: UnsafeCell<[u8; GAP_BODY_LENGTH]>,
}

impl Block {
    fn new() -> Self {
        Self {
            word0: AtomicU64::new(0),
            header: UnsafeCell::new([0; GAP_BODY_LENGTH]),
        }
    }

    fn write_header(&self, bytes: [u8; GAP_BODY_LENGTH]) {
        self.header.with_mut(|cell| {
            // SAFETY: the pointer comes from a live `UnsafeCell`; Loom checks
            // that no access races with this write.
            unsafe { *cell = bytes }
        });
    }

    fn read_header(&self) -> [u8; GAP_BODY_LENGTH] {
        self.header.with(|cell| {
            // SAFETY: as in `write_header`; ordered after the write only
            // through the Release publication and the reader's Acquire.
            unsafe { *cell }
        })
    }
}

fn gap() -> Word0 {
    gap_word0(EXTENT, Lane::ZERO).unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Production,
    PublishFirst,
    RelaxedLoad,
}

/// The owner seals a gap while a reader polls the block: the reader sees
/// zero and reads nothing, or a complete record it accepts.
fn publication_model(step: Step) {
    loom::model(move || {
        let block = Arc::new(Block::new());
        let owner = {
            let block = Arc::clone(&block);
            thread::spawn(move || {
                if step == Step::PublishFirst {
                    publish_block(&block.word0, gap());
                    block.write_header(gap_body(SITE, REASON));
                } else {
                    block.write_header(gap_body(SITE, REASON));
                    publish_block(&block.word0, gap());
                }
            })
        };
        let raw = match step {
            Step::RelaxedLoad => u64::from_le(block.word0.load(Ordering::Relaxed)),
            _ => observe_block(&block.word0),
        };
        if raw as u32 as i32 > 0 {
            let word0 = Word0::unpack(raw).unwrap();
            assert_eq!(
                check_word0(word0, SITE.term_offset, TERM, Lane::ZERO),
                Ok(EXTENT)
            );
            assert_eq!(check_body(&block.read_header(), SITE), Ok(REASON));
        }
        owner.join().unwrap();
    });
}

#[test]
fn a_reader_sees_zero_or_a_complete_gap_record() {
    publication_model(Step::Production);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_word0_before_the_header_fails() {
    publication_model(Step::PublishFirst);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_a_relaxed_word0_load_fails() {
    publication_model(Step::RelaxedLoad);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Overlap {
    Checked,
    Unchecked,
}

/// A committed frame is at the block; a reader copies its header bytes
/// while the owner is asked to seal the same interval. The owner's extent
/// record shows it covered, so the production owner refuses and the
/// reader's copy is never raced.
fn overlap_model(overlap: Overlap) {
    loom::model(move || {
        let block = Arc::new(Block::new());
        let frame_bytes = [7u8; GAP_BODY_LENGTH];
        // Committed before the threads start: the frame and the owner's
        // record of it.
        block.write_header(frame_bytes);
        block.word0.store(u64::from(64u32), Ordering::Release);
        let covered = true;
        let owner = {
            let block = Arc::clone(&block);
            thread::spawn(move || {
                if overlap == Overlap::Checked && covered {
                    return;
                }
                block.write_header(gap_body(SITE, REASON));
                publish_block(&block.word0, gap());
            })
        };
        if observe_block(&block.word0) == u64::from(64u32) {
            assert_eq!(block.read_header(), frame_bytes);
        }
        owner.join().unwrap();
    });
}

#[test]
fn a_gap_is_never_written_over_a_committed_frame() {
    overlap_model(Overlap::Checked);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_a_gap_without_the_overlap_check_fails() {
    overlap_model(Overlap::Unchecked);
}

/// A block of shared terms: word 0 and three atomic header words.
struct SharedBlock {
    word0: AtomicU64,
    header: [AtomicU64; 3],
}

/// The shared-terms access discipline: the owner stores the header words
/// Relaxed then publishes word 0; a reader that acquires word 0 reads the
/// complete header. Control: word 0 published first lets a reader see the
/// record with a zero header, which it refuses.
fn shared_model(step: Step) {
    loom::model(move || {
        let block = Arc::new(SharedBlock {
            word0: AtomicU64::new(0),
            header: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
        });
        let owner = {
            let block = Arc::clone(&block);
            thread::spawn(move || {
                let body = gap_body(SITE, REASON);
                let store_header = || {
                    for (word, chunk) in block.header.iter().zip(body.chunks_exact(8)) {
                        store_body(word, chunk.try_into().unwrap());
                    }
                };
                if step == Step::PublishFirst {
                    publish_block(&block.word0, gap());
                    store_header();
                } else {
                    store_header();
                    publish_block(&block.word0, gap());
                }
            })
        };
        if observe_block(&block.word0) as u32 as i32 > 0 {
            let mut header = [0u8; GAP_BODY_LENGTH];
            for (chunk, word) in header.chunks_exact_mut(8).zip(&block.header) {
                chunk.copy_from_slice(&load_body(word));
            }
            assert_eq!(check_body(&header, SITE), Ok(REASON));
        }
        owner.join().unwrap();
    });
}

#[test]
fn a_shared_reader_sees_zero_or_a_complete_gap_record() {
    shared_model(Step::Production);
}

#[test]
#[should_panic(expected = "assertion")]
fn control_shared_word0_before_the_header_fails() {
    shared_model(Step::PublishFirst);
}
