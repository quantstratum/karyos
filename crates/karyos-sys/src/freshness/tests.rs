// SPDX-License-Identifier: Apache-2.0

//! The loss barrier, single-threaded: layout, the ring-full rule,
//! retirement bounds, classification and the terminal cell. The ordering
//! is checked by `tests/loom_barrier.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

fn words(ring: usize) -> Vec<AtomicU64> {
    (0..barrier_words(ring).unwrap())
        .map(|_| AtomicU64::new(0))
        .collect()
}

fn classify(words: &[AtomicU64], ring: usize, slot: SlotFreshness, position: u64) -> Freshness {
    let snapshot = BarrierSnapshot::take(&words, ring).unwrap();
    snapshot.classify(&words, slot, position)
}

fn fresh_through(applied: u64) -> SlotFreshness {
    SlotFreshness {
        loss_applied: applied,
        stale_since: 0,
    }
}

#[test]
fn the_layout_is_a_header_and_three_words_per_record() {
    assert_eq!(barrier_words(MIN_RING), Some(3 + 3 * MIN_RING));
    assert_eq!(barrier_words(DEFAULT_RING), Some(3 + 3 * 16));
    assert_eq!(barrier_words(1), None);
    assert_eq!(barrier_words(0), None);
    assert_eq!(barrier_words(usize::MAX), None);
    let w = words(4);
    assert!(BarrierWords::new(&w, 4).is_ok());
    assert_eq!(
        BarrierWords::new(&w, 3).unwrap_err(),
        FreshnessError::InvalidLayout
    );
}

/// GU-9: a value is stale after a gap whenever it lies below the gap's
/// end, inside the gap or before it (the lost range may have held a newer
/// update of its key); a gap wholly above it does not touch it.
#[test]
fn a_committed_gap_makes_every_older_value_stale() {
    let w = words(4);
    let barrier = BarrierWords::new(&w, 4).unwrap();
    assert_eq!(classify(&w, 4, fresh_through(0), 2), Freshness::Fresh);
    assert_eq!(barrier.append_loss(8, 16), Ok(1));
    assert_eq!(
        classify(&w, 4, fresh_through(0), 2),
        Freshness::Stale { since: 8 },
        "a value before the gap"
    );
    assert_eq!(
        classify(&w, 4, fresh_through(0), 10),
        Freshness::Stale { since: 8 },
        "a value inside the gap"
    );
    assert_eq!(
        classify(&w, 4, fresh_through(0), 16),
        Freshness::Fresh,
        "a replacement at the end restores (half-open)"
    );
}

/// `since` is the lowest start among the unapplied gaps that end above the
/// value, whatever order they were committed in.
#[test]
fn stale_since_is_the_lowest_covering_start() {
    let w = words(4);
    let barrier = BarrierWords::new(&w, 4).unwrap();
    assert_eq!(barrier.append_loss(24, 32), Ok(1));
    assert_eq!(barrier.append_loss(8, 16), Ok(2));
    assert_eq!(
        classify(&w, 4, fresh_through(0), 2),
        Freshness::Stale { since: 8 }
    );
    assert_eq!(
        classify(&w, 4, fresh_through(0), 20),
        Freshness::Stale { since: 24 },
        "only the gap ending above it"
    );
    assert_eq!(
        classify(&w, 4, fresh_through(1), 20),
        Freshness::Fresh,
        "the applied gap is the slot's business"
    );
    assert_eq!(classify(&w, 4, fresh_through(2), 2), Freshness::Fresh);
}

/// A stale slot reports its own start, whatever the records say.
#[test]
fn a_stale_slot_reports_its_start() {
    let w = words(4);
    let barrier = BarrierWords::new(&w, 4).unwrap();
    barrier.append_loss(8, 16).unwrap();
    let stale = SlotFreshness {
        loss_applied: 1 | STALE,
        stale_since: 8,
    };
    assert_eq!(classify(&w, 4, stale, 100), Freshness::Stale { since: 8 });
    // An unapplied gap starting lower lowers it.
    barrier.append_loss(2, 4).unwrap();
    let later = SlotFreshness {
        loss_applied: 1 | STALE,
        stale_since: 8,
    };
    assert_eq!(classify(&w, 4, later, 3), Freshness::Stale { since: 2 });
}

/// The ring-full rule: no record is overwritten before it retires.
#[test]
fn a_full_ring_refuses_a_loss_until_a_retirement() {
    let w = words(2);
    let barrier = BarrierWords::new(&w, 2).unwrap();
    barrier.append_loss(0, 8).unwrap();
    barrier.append_loss(8, 16).unwrap();
    let before: Vec<u64> = w.iter().map(|w| w.load(Ordering::Relaxed)).collect();
    assert_eq!(
        barrier.append_loss(16, 24),
        Err(FreshnessError::RingFull { ring: 2 })
    );
    let after: Vec<u64> = w.iter().map(|w| w.load(Ordering::Relaxed)).collect();
    assert_eq!(before, after, "nothing stored");
    barrier.retire_through(1).unwrap();
    assert_eq!(barrier.append_loss(16, 24), Ok(3));
}

/// A slot that missed a retired record, or one reconciled past the
/// snapshot, is an incoherent pair: retry.
#[test]
fn an_incoherent_slot_is_retried() {
    let w = words(4);
    let barrier = BarrierWords::new(&w, 4).unwrap();
    barrier.append_loss(8, 16).unwrap();
    barrier.retire_through(1).unwrap();
    assert_eq!(classify(&w, 4, fresh_through(0), 10), Freshness::Retry);
    assert_eq!(classify(&w, 4, fresh_through(2), 10), Freshness::Retry);
    assert_eq!(classify(&w, 4, fresh_through(1), 10), Freshness::Fresh);
}

/// A record overwritten under the reader (its sequence word changed) is
/// missing history: retry, never Fresh.
#[test]
fn an_overwritten_record_is_retried() {
    let w = words(2);
    let barrier = BarrierWords::new(&w, 2).unwrap();
    barrier.append_loss(8, 16).unwrap();
    let snapshot = BarrierSnapshot::take(&w.as_slice(), 2).unwrap();
    // Record 1 (index 1) rewritten as loss 3, outside the protocol.
    w[3 + 3].store(3, Ordering::Relaxed);
    // The version is unchanged, so only the sequence check catches it.
    assert_eq!(
        snapshot.classify(&w.as_slice(), fresh_through(0), 10),
        Freshness::Retry
    );
}

/// A barrier write between the snapshot and the classification is seen by
/// the revalidation; a write in progress and a malformed view are typed.
#[test]
fn a_snapshot_is_revalidated_and_its_failures_are_typed() {
    let w = words(4);
    let barrier = BarrierWords::new(&w, 4).unwrap();
    let snapshot = BarrierSnapshot::take(&w.as_slice(), 4).unwrap();
    barrier.append_loss(8, 16).unwrap();
    assert_eq!(
        snapshot.classify(&w.as_slice(), fresh_through(0), 100),
        Freshness::Retry
    );
    w[0].store(5, Ordering::Relaxed);
    assert_eq!(
        BarrierSnapshot::take(&w.as_slice(), 4),
        Err(FreshnessError::Busy)
    );
    for ring in [0, 1, 3] {
        assert_eq!(
            BarrierSnapshot::take(&w.as_slice(), ring),
            Err(FreshnessError::InvalidLayout),
            "ring {ring}"
        );
    }
}

#[test]
fn retirement_stays_within_the_appended_losses() {
    let w = words(4);
    let barrier = BarrierWords::new(&w, 4).unwrap();
    barrier.append_loss(8, 16).unwrap();
    barrier.append_loss(16, 24).unwrap();
    assert_eq!(
        barrier.retire_through(3),
        Err(FreshnessError::InvalidRetirement {
            seq: 3,
            retired: 0,
            newest: 2
        })
    );
    barrier.retire_through(2).unwrap();
    assert_eq!(
        barrier.retire_through(1),
        Err(FreshnessError::InvalidRetirement {
            seq: 1,
            retired: 2,
            newest: 2
        })
    );
    let version = w[0].load(Ordering::Relaxed);
    barrier.retire_through(2).unwrap();
    assert_eq!(
        w[0].load(Ordering::Relaxed),
        version,
        "a no-op writes nothing"
    );
}

#[test]
fn an_empty_interval_and_an_exhausted_sequence_are_refused() {
    let w = words(4);
    let barrier = BarrierWords::new(&w, 4).unwrap();
    assert_eq!(
        barrier.append_loss(8, 8),
        Err(FreshnessError::InvalidInterval { start: 8, end: 8 })
    );
    w[0].store(u64::MAX - 1, Ordering::Relaxed);
    assert_eq!(barrier.append_loss(8, 16), Err(FreshnessError::Exhausted));
    assert_eq!(barrier.loss_seq(), 0, "nothing stored");
    // The sequence never reaches the slots' stale flag.
    w[0].store(0, Ordering::Relaxed);
    w[1].store(STALE - 1, Ordering::Relaxed);
    w[2].store(STALE - 1, Ordering::Relaxed);
    assert_eq!(barrier.append_loss(8, 16), Err(FreshnessError::Exhausted));
    assert_eq!(barrier.loss_seq(), STALE - 1);
}

#[test]
fn the_terminal_cell_is_one_shot() {
    let w: Vec<AtomicU64> = (0..TERMINAL_WORDS).map(|_| AtomicU64::new(0)).collect();
    let cell = TerminalCell::new(&w).unwrap();
    assert_eq!(TerminalCell::read(&w.as_slice()), None);
    let terminal = Terminal {
        start: 8,
        end: 16,
        reason: 2,
    };
    assert!(cell.publish(terminal));
    assert_eq!(TerminalCell::read(&w.as_slice()), Some(terminal));
    assert!(!cell.publish(Terminal {
        start: 0,
        end: 1,
        reason: 3
    }));
    assert_eq!(TerminalCell::read(&w.as_slice()), Some(terminal));
    assert!(TerminalCell::new(&w[..3]).is_err());
    // A claimed cell (a publisher mid-body) reads as unpublished and
    // refuses a second publisher.
    let w: Vec<AtomicU64> = (0..TERMINAL_WORDS).map(|_| AtomicU64::new(0)).collect();
    w[0].store(1, Ordering::Relaxed);
    let cell = TerminalCell::new(&w).unwrap();
    assert_eq!(TerminalCell::read(&w.as_slice()), None);
    assert!(!cell.publish(terminal));
}

fn mailbox_words() -> Vec<AtomicU64> {
    (0..MAILBOX_WORDS).map(|_| AtomicU64::new(0)).collect()
}

#[test]
fn a_mailbox_holds_one_request_until_it_is_acknowledged() {
    let w = mailbox_words();
    let mailbox = BarrierMailbox::new(&w).unwrap();
    assert!(BarrierMailbox::new(&w[..4]).is_err());
    assert_eq!(mailbox.pending(), None);
    let first = mailbox.post(8, 16).unwrap();
    assert_eq!(first, 1);
    assert!(!mailbox.is_acknowledged(first));
    // One request at a time: the second waits for the first's ack.
    assert_eq!(mailbox.post(24, 32), Err(FreshnessError::Busy));
    assert_eq!(
        mailbox.pending(),
        Some(SealRequest {
            request: first,
            start: 8,
            end: 16
        })
    );
    mailbox.acknowledge(first).unwrap();
    assert!(mailbox.is_acknowledged(first));
    assert_eq!(mailbox.pending(), None);
    let second = mailbox.post(24, 32).unwrap();
    assert_eq!(second, 2);
    assert!(!mailbox.is_acknowledged(second));
    assert_eq!(
        mailbox.pending(),
        Some(SealRequest {
            request: second,
            start: 24,
            end: 32
        })
    );
}

#[test]
fn a_mailbox_refuses_what_it_cannot_hold() {
    let w = mailbox_words();
    let mailbox = BarrierMailbox::new(&w).unwrap();
    assert_eq!(
        mailbox.post(8, 8),
        Err(FreshnessError::InvalidInterval { start: 8, end: 8 })
    );
    assert_eq!(mailbox.pending(), None, "nothing stored");
    // Only the outstanding request is acknowledged, once.
    assert_eq!(
        mailbox.acknowledge(1),
        Err(FreshnessError::UnknownRequest { request: 1 })
    );
    let request = mailbox.post(8, 16).unwrap();
    assert_eq!(
        mailbox.acknowledge(request + 1),
        Err(FreshnessError::UnknownRequest {
            request: request + 1
        })
    );
    mailbox.acknowledge(request).unwrap();
    assert_eq!(
        mailbox.acknowledge(request),
        Err(FreshnessError::UnknownRequest { request })
    );
    // An exhausted request number stores nothing.
    w[0].store(u64::MAX, Ordering::Relaxed);
    w[3].store(u64::MAX, Ordering::Relaxed);
    assert_eq!(mailbox.post(8, 16), Err(FreshnessError::Exhausted));
    assert_eq!(w[1].load(Ordering::Relaxed), 8);
    assert_eq!(w[2].load(Ordering::Relaxed), 16);
    assert_eq!(mailbox.pending(), None);
}

#[test]
fn a_mailbox_knows_when_its_feeder_attached() {
    let w = mailbox_words();
    let mailbox = BarrierMailbox::new(&w).unwrap();
    assert!(!mailbox.is_attached());
    mailbox.attach();
    assert!(mailbox.is_attached());
    // Attaching writes only the feeder's word.
    assert_eq!(w[4].load(Ordering::Relaxed), 1);
    assert!(w[..4].iter().all(|word| word.load(Ordering::Relaxed) == 0));
}
