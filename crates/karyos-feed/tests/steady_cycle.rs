// SPDX-License-Identifier: Apache-2.0

//! A steady arbitration cycle allocates nothing (`quantstratum-docs:
//! karyos/design/feed-arbitration.md` section 3; karyos#659): pushes from
//! both lines, with duplicates, a line ahead, a held message and a
//! repaired hole, counted with the workspace's counting allocator.

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use std::num::NonZeroU64;

use karyos_feed::{Arbiter, ArbiterConfig, Event, FeedSequencer, Identity, Line, Start};
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Feed;

impl FeedSequencer for Feed {
    fn identity(&self, message: &[u8]) -> Option<Identity> {
        let (head, _) = message.split_first_chunk::<16>()?;
        let (epoch, sequence) = head.split_at(8);
        Some(Identity {
            epoch: u64::from_le_bytes(epoch.try_into().ok()?),
            sequence: u64::from_le_bytes(sequence.try_into().ok()?),
        })
    }

    fn sequence_modulus(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(1 << 20)
    }
}

#[test]
fn a_steady_cycle_allocates_nothing() {
    let mut arbiter = Arbiter::new(
        Feed,
        ArbiterConfig {
            capacity: 64,
            max_message_length: 128,
            skew_window: 1_000_000,
            start: Start::AtFirst,
        },
    )
    .unwrap();
    // Messages built before counting; the sequence wraps inside the run.
    let base = (1u64 << 20) - 500;
    let messages: Vec<[u8; 48]> = (0..1000u64)
        .map(|offset| {
            let mut message = [0u8; 48];
            message[..8].copy_from_slice(&1u64.to_le_bytes());
            message[8..16].copy_from_slice(&((base + offset) % (1 << 20)).to_le_bytes());
            message
        })
        .collect();
    let mut delivered = 0u64;
    let mut gaps = 0u64;
    let mut emit = |event: Event<'_>| match event {
        Event::Message { .. } => delivered += 1,
        Event::Gap { .. } => gaps += 1,
        _ => {}
    };
    let ((), allocations) = count(|| {
        for (index, message) in messages.iter().enumerate() {
            let now = u64::try_from(index).unwrap();
            // A runs one ahead, so B's copy is a duplicate; every tenth
            // message is missing on A and repaired from B; every
            // seventh arrives on B before its predecessor, so it is held.
            if index % 10 != 3 {
                arbiter.push(Line::A, message, now, &mut emit);
            }
            if index % 7 == 0
                && let Some(next) = messages.get(index + 1)
            {
                arbiter.push(Line::B, next, now, &mut emit);
            }
            arbiter.push(Line::B, message, now, &mut emit);
        }
    });
    assert_eq!(allocations, 0);
    assert_eq!(delivered, 1000);
    assert_eq!(gaps, 0);
    let counters = arbiter.counters();
    assert!(counters.reordered > 0 && counters.wins_b > 0);
}
