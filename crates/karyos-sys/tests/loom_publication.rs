// SPDX-License-Identifier: Apache-2.0

//! Loom model of block publication with the production ordering helpers of
//! `karyos_sys::publication`: a writer fills a two-fragment block (plain
//! payload, interior word 0) and publishes its first word 0; a reader that
//! observes the block committed must see the interior word and the payload,
//! with Loom checking that every plain access is ordered. A second model
//! does the same for shared terms, whose payload is moved only as `Relaxed`
//! atomic words (`quantstratum-docs: karyos/design/shared-payload-access.md`).
//!
//! Run with `make loom`.

#![cfg(loom)]

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::publication::{
    load_body, load_interior, observe_block, publish_block, store_body, store_interior,
};
use karyos_sys::sync::AtomicU64;
use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::thread;

const PAYLOAD: [u64; 2] = [0x1111, 0x2222];

struct Block {
    first: AtomicU64,
    interior: AtomicU64,
    payload: UnsafeCell<[u64; 2]>,
}

fn first_word() -> Word0 {
    Word0::new(
        48,
        Flags::new(true, false, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

fn interior_word() -> Word0 {
    Word0::new(
        40,
        Flags::new(false, true, false, false, Lane::ZERO),
        FrameType::Data,
    )
}

#[test]
fn published_block_is_fully_visible() {
    loom::model(|| {
        let block = Arc::new(Block {
            first: AtomicU64::new(0),
            interior: AtomicU64::new(0),
            payload: UnsafeCell::new([0; 2]),
        });
        let writer = {
            let block = Arc::clone(&block);
            thread::spawn(move || {
                block.payload.with_mut(|payload| {
                    // SAFETY: the pointer comes from a live `UnsafeCell`; Loom
                    // checks that no access races with this write.
                    unsafe { *payload = PAYLOAD }
                });
                store_interior(&block.interior, interior_word());
                publish_block(&block.first, first_word());
            })
        };

        let observed = observe_block(&block.first);
        if observed != 0 {
            assert_eq!(observed, first_word().pack());
            assert_eq!(load_interior(&block.interior), interior_word().pack());
            let payload = block.payload.with(|payload| {
                // SAFETY: as above; the read is ordered after the writer's
                // write only through the Release/Acquire pair under test.
                unsafe { *payload }
            });
            assert_eq!(payload, PAYLOAD);
        }
        writer.join().unwrap();
    });
}

/// Shared terms: body words are `Relaxed` atomics, so only the
/// Release/Acquire pair on the first word 0 makes them visible.
#[test]
fn published_shared_block_is_fully_visible() {
    const BODY: [[u8; 8]; 2] = [[0x11; 8], [0x22; 8]];
    loom::model(|| {
        let first = Arc::new(AtomicU64::new(0));
        let body = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
        let writer = {
            let first = Arc::clone(&first);
            let body = Arc::clone(&body);
            thread::spawn(move || {
                for (word, bytes) in body.iter().zip(BODY) {
                    store_body(word, bytes);
                }
                publish_block(&first, first_word());
            })
        };

        if observe_block(&first) != 0 {
            for (word, bytes) in body.iter().zip(BODY) {
                assert_eq!(load_body(word), bytes);
            }
        }
        writer.join().unwrap();
    });
}
