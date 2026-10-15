// SPDX-License-Identifier: Apache-2.0

//! Loom models of receive publication (`quantstratum-docs: karyos/design/receive-publication.md`,
//! batch r4) over the production helpers of `karyos_sys::publication`.
//!
//! The receive owner writes a frame's body, then publishes its word 0 with
//! one Release store (`publish_block`); a reader loads word 0 with Acquire
//! (`observe_block`) and reads the body only when it is positive. In an
//! image every fragment is its own publication, so the reader also loads an
//! interior fragment's word 0 with Acquire. Duplicates from several paths
//! reach a single owner through a queue, and only the owner writes.
//!
//! Bodies are plain `UnsafeCell` bytes, as on heap terms: Loom reports any
//! read that races a write. Negative controls change one production step
//! and must fail: word 0 published before the body, an interior word 0
//! loaded Relaxed, and two writers without a single owner.
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::publication::{observe_block, publish_block};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::cell::UnsafeCell;
use loom::sync::{Arc, Mutex};
use loom::thread;

fn fragment(begin: bool, end: bool) -> Word0 {
    Word0::new(
        40,
        Flags::new(begin, end, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

/// One frame: its word 0 and a two-word body.
struct Frame {
    word0: AtomicU64,
    body: UnsafeCell<[u64; 2]>,
}

impl Frame {
    fn new() -> Self {
        Self {
            word0: AtomicU64::new(0),
            body: UnsafeCell::new([0; 2]),
        }
    }

    fn write_body(&self, body: [u64; 2]) {
        self.body.with_mut(|cell| {
            // SAFETY: the pointer comes from a live `UnsafeCell`; Loom checks
            // that no access races with this write.
            unsafe { *cell = body }
        });
    }

    fn read_body(&self) -> [u64; 2] {
        self.body.with(|cell| {
            // SAFETY: as in `write_body`; ordered after the write only
            // through the Release publication and the reader's Acquire.
            unsafe { *cell }
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    Production,
    PublicationBeforeBody,
}

fn reader_model(order: Order) {
    loom::model(move || {
        let frame = Arc::new(Frame::new());
        let word0 = fragment(true, true);
        let owner = {
            let frame = Arc::clone(&frame);
            thread::spawn(move || {
                if order == Order::PublicationBeforeBody {
                    publish_block(&frame.word0, word0);
                    frame.write_body([7, 8]);
                } else {
                    frame.write_body([7, 8]);
                    publish_block(&frame.word0, word0);
                }
            })
        };
        // The reader sees zero and reads nothing else, or a positive
        // length and the complete body.
        if observe_block(&frame.word0) == word0.pack() {
            assert_eq!(frame.read_body(), [7, 8]);
        }
        owner.join().unwrap();
    });
}

#[test]
fn a_reader_sees_zero_or_a_complete_frame() {
    reader_model(Order::Production);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_publication_before_the_body_fails() {
    reader_model(Order::PublicationBeforeBody);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Interior {
    Acquire,
    Relaxed,
}

fn fragments_model(interior: Interior) {
    loom::model(move || {
        let first = Arc::new(Frame::new());
        let second = Arc::new(Frame::new());
        let (begin, end) = (fragment(true, false), fragment(false, true));
        let owner = {
            let (first, second) = (Arc::clone(&first), Arc::clone(&second));
            thread::spawn(move || {
                first.write_body([1, 2]);
                publish_block(&first.word0, begin);
                second.write_body([3, 4]);
                publish_block(&second.word0, end);
            })
        };
        // The image reader: BEGIN with Acquire, then the interior fragment's
        // own word 0, which in an image is a separate publication.
        if observe_block(&first.word0) == begin.pack() {
            let interior = match interior {
                Interior::Acquire => observe_block(&second.word0),
                Interior::Relaxed => u64::from_le(second.word0.load(Ordering::Relaxed)),
            };
            if interior == end.pack() {
                assert_eq!(first.read_body(), [1, 2]);
                assert_eq!(second.read_body(), [3, 4]);
            }
        }
        owner.join().unwrap();
    });
}

#[test]
fn fragments_published_separately_are_read_complete() {
    fragments_model(Interior::Acquire);
}

#[test]
#[should_panic(expected = "Concurrent read and write accesses")]
fn control_a_relaxed_interior_load_fails() {
    fragments_model(Interior::Relaxed);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Writers {
    SingleOwner,
    TwoWithoutOwner,
}

/// The receive owner's step for one arrival: a destination whose word 0 is
/// committed is compared and never written; otherwise the body is written
/// and word 0 published. Only the owner calls it.
fn commit_or_compare(frame: &Frame, body: [u64; 2], word0: Word0) -> bool {
    if observe_block(&frame.word0) != 0 {
        return frame.read_body() == body;
    }
    frame.write_body(body);
    publish_block(&frame.word0, word0);
    true
}

fn duplicates_model(writers: Writers) {
    loom::model(move || {
        let frame = Arc::new(Frame::new());
        let word0 = fragment(true, true);
        match writers {
            Writers::SingleOwner => {
                // Two paths deliver the same frame to the owner's queue.
                let queue = Arc::new(Mutex::new(Vec::<[u64; 2]>::with_capacity(2)));
                let paths: Vec<_> = (0..2)
                    .map(|_| {
                        let queue = Arc::clone(&queue);
                        thread::spawn(move || queue.lock().unwrap().push([5, 6]))
                    })
                    .collect();
                let owner = {
                    let (frame, queue) = (Arc::clone(&frame), Arc::clone(&queue));
                    thread::spawn(move || {
                        let mut handled = 0;
                        while handled < 2 {
                            let next = queue.lock().unwrap().pop();
                            match next {
                                Some(body) => {
                                    assert!(commit_or_compare(&frame, body, word0));
                                    handled += 1;
                                }
                                None => thread::yield_now(),
                            }
                        }
                    })
                };
                if observe_block(&frame.word0) == word0.pack() {
                    // Committed once, and never changed afterwards.
                    assert_eq!(frame.read_body(), [5, 6]);
                }
                for path in paths {
                    path.join().unwrap();
                }
                owner.join().unwrap();
            }
            Writers::TwoWithoutOwner => {
                // The arbitration removed: two path threads call the copy
                // and publish step directly, with different bodies.
                let threads: Vec<_> = [[5, 6], [9, 9]]
                    .into_iter()
                    .map(|body| {
                        let frame = Arc::clone(&frame);
                        thread::spawn(move || {
                            commit_or_compare(&frame, body, word0);
                        })
                    })
                    .collect();
                for thread in threads {
                    thread.join().unwrap();
                }
            }
        }
        assert_eq!(observe_block(&frame.word0), word0.pack());
    });
}

#[test]
fn duplicate_paths_are_committed_once_by_the_owner() {
    duplicates_model(Writers::SingleOwner);
}

#[test]
#[should_panic(expected = "Concurrent write accesses")]
fn control_two_writers_without_an_owner_fail() {
    duplicates_model(Writers::TwoWithoutOwner);
}
