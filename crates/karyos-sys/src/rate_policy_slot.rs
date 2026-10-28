// SPDX-License-Identifier: Apache-2.0

//! A published rate policy and its version (R-CORE-21; `quantstratum-docs:
//! karyos/design/guards-and-abort.md`, Rate limit transitions): the driver
//! writes the policy of a guarded stream, the handles and the sender gate
//! read it on their slow path and apply a newer version to their own
//! buckets.
//!
//! The slot is [`SLOT_WORDS`] words: the sequence, the version, the
//! message rate and burst, the byte rate and burst, and a flag that bytes
//! are limited. A version of 0 means no policy was published. In an
//! outcome ring it occupies header words [`OUTCOME_SLOT`] onwards, which
//! layout version 2 reserved as zero (`crate::outcome_ring`), so a ring
//! that publishes nothing reads as "no policy".
//!
//! The slot is a sequence lock with a single writer, the driver, as
//! [`crate::applied_epoch`]:
//!
//! - **Writer.** Stores the sequence odd (Relaxed), a Release fence, the
//!   fields (Relaxed), then the sequence even with Release.
//! - **Reader.** Loads the sequence with Acquire (odd: in progress, try
//!   again), the fields (Relaxed), an Acquire fence, and the sequence
//!   again (Relaxed). Equal sequences mean one whole publication; anything
//!   else is a torn read, which the reader answers by trying again later.
//!   A reader never applies a policy it did not read whole.

use crate::load_words::LoadWords;
use crate::rate_limit::{Rate, RatePolicy};
use crate::sync::{AtomicU64, Ordering, fence};

/// The words of one slot.
pub const SLOT_WORDS: usize = 7;
/// The first header word of an outcome ring that holds the slot.
pub const OUTCOME_SLOT: usize = 6;

/// The slot's sequence word, from its start: a reader that skips an
/// unchanged slot compares it alone, with one Acquire load.
pub const SEQUENCE: usize = 0;
const VERSION: usize = 1;
const MESSAGES_RATE: usize = 2;
const MESSAGES_BURST: usize = 3;
const BYTES_RATE: usize = 4;
const BYTES_BURST: usize = 5;
const BYTES_LIMITED: usize = 6;

/// What one read of a slot found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRead {
    /// No policy was published (version 0).
    Unpublished,
    /// The policy of `version`, read whole.
    Policy {
        /// Its version, from 1.
        version: u64,
        /// The policy.
        policy: RatePolicy,
    },
    /// A publication was in progress or the read was torn: try again later.
    Busy,
}

/// The driver: publishes `policy` as `version` into the slot at `start` of
/// `words`. Single writer only. Nothing happens for a slot past the end.
pub fn publish(words: &[AtomicU64], start: usize, version: u64, policy: &RatePolicy) {
    let Some(slot) = start
        .checked_add(SLOT_WORDS)
        .and_then(|end| words.get(start..end))
    else {
        return;
    };
    let Some(sequence) = slot.get(SEQUENCE) else {
        return;
    };
    let before = sequence.load(Ordering::Relaxed);
    sequence.store(before.wrapping_add(1), Ordering::Relaxed);
    fence(Ordering::Release);
    let bytes = policy.bytes.unwrap_or(Rate {
        per_second: 0,
        burst: 0,
    });
    for (at, value) in [
        (VERSION, version),
        (MESSAGES_RATE, policy.messages.per_second),
        (MESSAGES_BURST, policy.messages.burst),
        (BYTES_RATE, bytes.per_second),
        (BYTES_BURST, bytes.burst),
        (BYTES_LIMITED, u64::from(policy.bytes.is_some())),
    ] {
        if let Some(word) = slot.get(at) {
            word.store(value, Ordering::Relaxed);
        }
    }
    sequence.store(before.wrapping_add(2), Ordering::Release);
}

/// A handle or a gate: one attempt to read the slot at `start` of `words`.
/// A slot past the end reads as [`SlotRead::Unpublished`].
#[must_use]
pub fn try_read(words: &(impl LoadWords + ?Sized), start: usize) -> SlotRead {
    try_read_sequenced(words, start).0
}

/// [`try_read`], with the sequence word the read validated: `Some` for a
/// read whole (a policy, or a slot with none published yet), `None` for a
/// busy read or a slot past the end. A reader that skips unchanged slots
/// keeps this sequence, never one loaded after the read, which a
/// publication completed in between would make newer than what it read.
#[must_use]
pub fn try_read_sequenced(
    words: &(impl LoadWords + ?Sized),
    start: usize,
) -> (SlotRead, Option<u64>) {
    let at = |offset: usize| start.checked_add(offset);
    let (Some(first), Some(_)) = (
        at(SEQUENCE).and_then(|index| words.load_acquire(index)),
        at(BYTES_LIMITED).and_then(|index| words.load(index)),
    ) else {
        return (SlotRead::Unpublished, None);
    };
    if first % 2 == 1 {
        return (SlotRead::Busy, None);
    }
    let field = |offset: usize| at(offset).and_then(|index| words.load(index)).unwrap_or(0);
    let version = field(VERSION);
    let messages = Rate {
        per_second: field(MESSAGES_RATE),
        burst: field(MESSAGES_BURST),
    };
    let bytes = Rate {
        per_second: field(BYTES_RATE),
        burst: field(BYTES_BURST),
    };
    let limited = field(BYTES_LIMITED);
    fence(Ordering::Acquire);
    let second = at(SEQUENCE)
        .and_then(|index| words.load(index))
        .unwrap_or(first.wrapping_add(1));
    if first != second {
        return (SlotRead::Busy, None);
    }
    if version == 0 {
        return (SlotRead::Unpublished, Some(first));
    }
    (
        SlotRead::Policy {
            version,
            policy: RatePolicy {
                messages,
                bytes: (limited != 0).then_some(bytes),
            },
        },
        Some(first),
    )
}

#[cfg(all(test, not(loom)))]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    fn policy(rate: u64, burst: u64, bytes: Option<(u64, u64)>) -> RatePolicy {
        RatePolicy {
            messages: Rate {
                per_second: rate,
                burst,
            },
            bytes: bytes.map(|(per_second, burst)| Rate { per_second, burst }),
        }
    }

    /// Zero words are no policy; each publication reads back whole, with
    /// its version, with and without a byte limit; an odd sequence is busy.
    #[test]
    fn a_slot_reads_back_what_was_published() {
        let words: Vec<AtomicU64> = (0..16).map(|_| AtomicU64::new(0)).collect();
        let view: &[AtomicU64] = &words;
        assert_eq!(try_read(&view, OUTCOME_SLOT), SlotRead::Unpublished);
        let first = policy(100, 10, Some((10_000, 2_000)));
        publish(&words, OUTCOME_SLOT, 1, &first);
        assert_eq!(
            try_read(&view, OUTCOME_SLOT),
            SlotRead::Policy {
                version: 1,
                policy: first
            }
        );
        let second = policy(50, 5, None);
        publish(&words, OUTCOME_SLOT, 2, &second);
        assert_eq!(
            try_read(&view, OUTCOME_SLOT),
            SlotRead::Policy {
                version: 2,
                policy: second
            }
        );
        words[OUTCOME_SLOT].fetch_add(1, Ordering::Relaxed);
        assert_eq!(try_read(&view, OUTCOME_SLOT), SlotRead::Busy);
        // Past the end: nothing published, nothing written.
        assert_eq!(try_read(&view, 12), SlotRead::Unpublished);
        publish(&words, 12, 3, &second);
    }
}
