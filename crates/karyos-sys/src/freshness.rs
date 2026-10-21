// SPDX-License-Identifier: Apache-2.0

//! The loss barrier of a conflation view (`quantstratum-docs:
//! karyos/design/gaps-and-unreliable-delivery.md`, "One-lane conflation
//! freshness", GU-8): a table-level record of committed gaps, so that a
//! reader classifies a value Stale as soon as a gap that covers it is
//! committed, before the writer has reconciled that value's slot.
//!
//! The barrier is a header and a ring of `G` loss records over atomic
//! words, under one fence-based seqlock (the protocol of the slots of
//! [`conflation`](crate::conflation)):
//!
//! ```text
//! [version, loss_seq, retired_through, record 0 .. record G-1]
//! record = [seq, start, end]   // the gap [start, end), loss number seq
//! ```
//!
//! Loss `seq` lives in record `seq % G`. The single writer (the view's
//! feeder) follows this order, which the Loom model
//! `tests/loom_freshness.rs` checks with a negative control for each step:
//!
//! 1. [`BarrierWords::append_loss`] publishes the record and the new
//!    `loss_seq` (Release), before the receive owner commits the gap.
//! 2. It reconciles every slot through that sequence: a freshness-only
//!    write of the slot's [`SlotFreshness`] words
//!    ([`FreshSlotWords::set_freshness`](crate::conflation::FreshSlotWords::set_freshness)),
//!    which advances the slot's sequence but not its value version.
//! 3. Only then [`BarrierWords::retire_through`] retires the record. The
//!    rule is this order: a slot seqlock's Release fence precedes the
//!    retirement, so a reader that sees the retirement sees the slot's
//!    reconciliation (or its odd version, and retries).
//!
//! A record is never overwritten before it retires: `append_loss` refuses
//! with [`FreshnessError::RingFull`] while `G` records are unretired, so
//! every slot's applied sequence is at least `retired_through`, which is at
//! least `loss_seq - G`, and every record a reader needs is retained.
//!
//! A reader takes a [`BarrierSnapshot`] (an Acquire load of the version),
//! copies the slot, then [`BarrierSnapshot::classify`] reads the records it
//! needs and revalidates the version: a changed barrier, a slot reconciled
//! past the snapshot or a missing record yields [`Freshness::Retry`], never
//! Fresh.
//!
//! A value at `position` is stale after a gap `[start, end)` whenever
//! `position < end` (GU-9): the lost range may have held a newer update of
//! its key, and only a replacement that begins at or after `end` restores
//! it. A gap above the value's position does not touch it.

use crate::load_words::LoadWords;
use crate::sync::{AtomicU64, Ordering, fence};

/// The default number of loss records per view (GU-8).
pub const DEFAULT_RING: usize = 16;
/// The fewest loss records a barrier holds.
pub const MIN_RING: usize = 2;
/// Bit 63 of a slot's applied loss sequence: the slot is stale.
pub const STALE: u64 = 1 << 63;

/// Word index of the barrier version.
const VERSION: usize = 0;
/// Word index of the newest loss sequence.
const LOSS_SEQ: usize = 1;
/// Word index of the sequence retired through.
const RETIRED: usize = 2;
/// Header words before the first record.
const HEADER_WORDS: usize = 3;
/// Words per loss record: `[seq, start, end]`.
const RECORD_WORDS: usize = 3;

/// Errors of the loss barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FreshnessError {
    /// The words do not hold a barrier of the requested ring size.
    #[error("invalid loss barrier layout")]
    InvalidLayout,
    /// `G` records are unretired: the loss waits for a retirement.
    #[error("loss ring full ({ring} records unretired)")]
    RingFull {
        /// The ring size.
        ring: usize,
    },
    /// The loss sequence would reach [`STALE`] (bit 63, which a slot's
    /// applied sequence uses as its stale flag) or the barrier version
    /// would overflow.
    #[error("loss barrier sequence exhausted")]
    Exhausted,
    /// A barrier write is in progress: take the snapshot again.
    #[error("loss barrier write in progress")]
    Busy,
    /// An empty or reversed interval.
    #[error("invalid loss interval [{start}, {end})")]
    InvalidInterval {
        /// The interval start.
        start: u64,
        /// The interval end.
        end: u64,
    },
    /// A retirement outside `retired_through..=loss_seq`.
    #[error("cannot retire through {seq}: retired {retired}, newest {newest}")]
    InvalidRetirement {
        /// The requested sequence.
        seq: u64,
        /// Already retired through.
        retired: u64,
        /// The newest loss sequence.
        newest: u64,
    },
    /// An acknowledgement of a request that is not the outstanding one.
    #[error("seal request {request} is not outstanding")]
    UnknownRequest {
        /// The acknowledged request number.
        request: u64,
    },
}

/// The number of words of a barrier with `ring` records; `None` below
/// [`MIN_RING`] or past the address space.
#[must_use]
pub fn barrier_words(ring: usize) -> Option<usize> {
    if ring < MIN_RING {
        return None;
    }
    ring.checked_mul(RECORD_WORDS)?.checked_add(HEADER_WORDS)
}

/// A slot's freshness words, copied with the slot under its seqlock
/// (GU-8): the loss sequence the slot is reconciled through, with
/// [`STALE`] set while the slot is stale, and the earliest still
/// unrepaired gap start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlotFreshness {
    /// The applied loss sequence, [`STALE`] set while stale.
    pub loss_applied: u64,
    /// The earliest unrepaired gap start; meaningful while stale.
    pub stale_since: u64,
}

impl SlotFreshness {
    /// The loss sequence the slot is reconciled through.
    #[must_use]
    pub fn applied(&self) -> u64 {
        self.loss_applied & !STALE
    }

    /// Whether the slot is stale.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.loss_applied & STALE != 0
    }
}

/// A value's freshness, as a reader reports it with the copied value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// No committed gap is known to cover the value.
    Fresh,
    /// A committed gap covers the value; `since` is its start.
    Stale {
        /// The start of the earliest gap that made the value stale.
        since: u64,
    },
    /// The barrier changed, the slot is newer than the snapshot or a
    /// needed record is gone: copy the slot again.
    Retry,
}

/// The barrier over a view's words: the single writer's operations.
///
/// Correct results require that only the view's single writer calls
/// [`BarrierWords::append_loss`] and [`BarrierWords::retire_through`], in
/// the order of the module documentation. Memory safety never depends on
/// it: every access is atomic and bounds-checked.
#[derive(Debug, Clone, Copy)]
pub struct BarrierWords<'a> {
    words: &'a [AtomicU64],
    ring: usize,
}

impl<'a> BarrierWords<'a> {
    /// Wraps the words of a barrier with `ring` records.
    ///
    /// # Errors
    ///
    /// [`FreshnessError::InvalidLayout`] unless `words` holds exactly
    /// [`barrier_words`]`(ring)` words.
    pub fn new(words: &'a [AtomicU64], ring: usize) -> Result<Self, FreshnessError> {
        if barrier_words(ring) != Some(words.len()) {
            return Err(FreshnessError::InvalidLayout);
        }
        Ok(Self { words, ring })
    }

    /// The ring size `G`.
    #[must_use]
    pub fn ring(&self) -> usize {
        self.ring
    }

    fn word(&self, index: usize) -> Result<&'a AtomicU64, FreshnessError> {
        self.words.get(index).ok_or(FreshnessError::InvalidLayout)
    }

    /// The newest loss sequence (the writer's own word: Relaxed).
    #[must_use]
    pub fn loss_seq(&self) -> u64 {
        self.word(LOSS_SEQ)
            .map_or(0, |word| word.load(Ordering::Relaxed))
    }

    /// The sequence retired through (the writer's own word: Relaxed).
    #[must_use]
    pub fn retired_through(&self) -> u64 {
        self.word(RETIRED)
            .map_or(0, |word| word.load(Ordering::Relaxed))
    }

    /// Appends the loss of `[start, end)` and publishes it (step 1). Returns
    /// its sequence; the caller reconciles every slot through it, then
    /// retires it.
    ///
    /// # Errors
    ///
    /// [`FreshnessError::InvalidInterval`] for an empty interval,
    /// [`FreshnessError::RingFull`] while `G` records are unretired (the
    /// gap is not committed yet; retry after a retirement) and
    /// [`FreshnessError::Exhausted`]. Nothing is stored on error.
    pub fn append_loss(&self, start: u64, end: u64) -> Result<u64, FreshnessError> {
        if start >= end {
            return Err(FreshnessError::InvalidInterval { start, end });
        }
        let newest = self.loss_seq();
        let retired = self.retired_through();
        let unretired = newest
            .checked_sub(retired)
            .ok_or(FreshnessError::InvalidLayout)?;
        if u64::try_from(self.ring).is_ok_and(|ring| unretired >= ring) {
            return Err(FreshnessError::RingFull { ring: self.ring });
        }
        // The sequence stays below the slots' stale flag.
        let seq = newest
            .checked_add(1)
            .filter(|&seq| seq < STALE)
            .ok_or(FreshnessError::Exhausted)?;
        let record = self.record_index(seq)?;
        let (Some(start_at), Some(end_at)) = (record.checked_add(1), record.checked_add(2)) else {
            return Err(FreshnessError::InvalidLayout);
        };
        self.write(&[
            (record, seq),
            (start_at, start),
            (end_at, end),
            (LOSS_SEQ, seq),
        ])?;
        Ok(seq)
    }

    /// Retires every record through `seq` (step 3): only after every slot
    /// was reconciled through it.
    ///
    /// # Errors
    ///
    /// [`FreshnessError::InvalidRetirement`] outside
    /// `retired_through..=loss_seq`, [`FreshnessError::Exhausted`].
    pub fn retire_through(&self, seq: u64) -> Result<(), FreshnessError> {
        let newest = self.loss_seq();
        let retired = self.retired_through();
        if seq < retired || seq > newest {
            return Err(FreshnessError::InvalidRetirement {
                seq,
                retired,
                newest,
            });
        }
        if seq == retired {
            return Ok(());
        }
        self.write(&[(RETIRED, seq)])
    }

    /// The first word of the record of loss `seq`.
    fn record_index(&self, seq: u64) -> Result<usize, FreshnessError> {
        record_index(seq, self.ring)
    }

    /// One seqlock write of `values`, as the slot writer does: the odd
    /// version (Relaxed), a Release fence, the words (Relaxed), the next
    /// even version (Release).
    fn write(&self, values: &[(usize, u64)]) -> Result<(), FreshnessError> {
        let version = self.word(VERSION)?;
        // Only this writer stores the version, so it is even here.
        let current = version.load(Ordering::Relaxed);
        let (Some(odd), Some(even)) = (current.checked_add(1), current.checked_add(2)) else {
            return Err(FreshnessError::Exhausted);
        };
        // Check every index before the first store.
        for &(index, _) in values {
            self.word(index)?;
        }
        version.store(odd, Ordering::Relaxed);
        fence(Ordering::Release);
        for &(index, value) in values {
            self.word(index)?.store(value, Ordering::Relaxed);
        }
        version.store(even, Ordering::Release);
        Ok(())
    }
}

/// The first word of the record of loss `seq` in a ring of `ring` records.
fn record_index(seq: u64, ring: usize) -> Result<usize, FreshnessError> {
    let ring_words = u64::try_from(ring).map_err(|_| FreshnessError::InvalidLayout)?;
    let slot = seq
        .checked_rem(ring_words)
        .and_then(|slot| usize::try_from(slot).ok())
        .ok_or(FreshnessError::InvalidLayout)?;
    slot.checked_mul(RECORD_WORDS)
        .and_then(|offset| offset.checked_add(HEADER_WORDS))
        .ok_or(FreshnessError::InvalidLayout)
}

/// A reader's barrier snapshot: taken before the slot copy, checked after
/// it by [`BarrierSnapshot::classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarrierSnapshot {
    version: u64,
    loss_seq: u64,
    retired_through: u64,
    ring: usize,
}

impl BarrierSnapshot {
    /// Takes the snapshot of a barrier of `ring` records (an Acquire load
    /// of the version, then the header words).
    ///
    /// # Errors
    ///
    /// [`FreshnessError::InvalidLayout`] unless `words` holds exactly
    /// [`barrier_words`]`(ring)` words; [`FreshnessError::Busy`] while the
    /// writer is mid-write (take it again).
    pub fn take<W: LoadWords>(words: &W, ring: usize) -> Result<Self, FreshnessError> {
        if barrier_words(ring) != Some(words.len()) {
            return Err(FreshnessError::InvalidLayout);
        }
        let header = |index| words.load(index).ok_or(FreshnessError::InvalidLayout);
        let version = words
            .load_acquire(VERSION)
            .ok_or(FreshnessError::InvalidLayout)?;
        if version % 2 == 1 {
            return Err(FreshnessError::Busy);
        }
        Ok(Self {
            version,
            loss_seq: header(LOSS_SEQ)?,
            retired_through: header(RETIRED)?,
            ring,
        })
    }

    /// The barrier version the snapshot was taken at.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The newest loss sequence seen.
    #[must_use]
    pub fn loss_seq(&self) -> u64 {
        self.loss_seq
    }

    /// The sequence retired through, as seen.
    #[must_use]
    pub fn retired_through(&self) -> u64 {
        self.retired_through
    }

    /// Classifies the value at `position` whose slot freshness words
    /// `slot` were copied after [`BarrierSnapshot::take`]: reads the
    /// records the slot has not applied, then revalidates the barrier
    /// version. `words` are the barrier the snapshot was taken from.
    #[must_use]
    pub fn classify<W: LoadWords>(
        &self,
        words: &W,
        slot: SlotFreshness,
        position: u64,
    ) -> Freshness {
        let classified = self.classify_unchecked(words, slot, position);
        fence(Ordering::Acquire);
        if words.load(VERSION) != Some(self.version) {
            // The barrier changed while the slot or the records were read.
            return Freshness::Retry;
        }
        classified
    }

    fn classify_unchecked<W: LoadWords>(
        &self,
        words: &W,
        slot: SlotFreshness,
        position: u64,
    ) -> Freshness {
        let applied = slot.applied();
        // A slot reconciled past this snapshot, or one that missed a
        // retired record: an incoherent pair, copy again.
        if applied > self.loss_seq || applied < self.retired_through {
            return Freshness::Retry;
        }
        // The slot's own stale start, then the records `applied + 1 ..=
        // loss_seq`: the value is stale since the lowest start among them
        // and the unapplied gaps that end above it.
        let mut since = slot.is_stale().then_some(slot.stale_since);
        let mut seq = applied;
        while seq < self.loss_seq {
            let Some(next) = seq.checked_add(1) else {
                return Freshness::Retry;
            };
            seq = next;
            let Ok(record) = record_index(seq, self.ring) else {
                return Freshness::Retry;
            };
            let (Some(found), Some(start), Some(end)) = (
                words.load(record),
                record.checked_add(1).and_then(|at| words.load(at)),
                record.checked_add(2).and_then(|at| words.load(at)),
            ) else {
                return Freshness::Retry;
            };
            if found != seq {
                // Overwritten: the history this slot needs is gone.
                return Freshness::Retry;
            }
            if position < end {
                since = Some(since.map_or(start, |since| since.min(start)));
            }
        }
        match since {
            Some(since) => Freshness::Stale { since },
            None => Freshness::Fresh,
        }
    }
}

/// The one-shot terminal invalidation cell of a view (GU-8): published
/// once, after its body, when a full ring or an exhausted sequence leaves
/// no other way to mark retained values stale.
///
/// Words: `[state, start, end, reason]`; the state is 0 (empty), 1
/// (claimed, body being written) or 2 (published).
#[derive(Debug, Clone, Copy)]
pub struct TerminalCell<'a> {
    words: &'a [AtomicU64],
}

/// Words of a [`TerminalCell`].
pub const TERMINAL_WORDS: usize = 4;
/// Terminal close reason: the receive owner's seal waited past its bound
/// for the feeder's acknowledgement (conflated-network-images.md (c)).
pub const TERMINAL_BARRIER_TIMEOUT: u64 = 1;
/// Terminal close reason: the loss sequence or a slot's versions are
/// exhausted (GU-11).
pub const TERMINAL_FRESHNESS_EXHAUSTED: u64 = 2;
/// Terminal close reason: a loss below the feeder's frontier, which breaks
/// the invariant the readers' classification rests on.
pub const TERMINAL_BELOW_FRONTIER: u64 = 3;
/// Terminal close reason: the view's image retired, so no value of it
/// changes again (conflated-network-images.md (a)). Published with an
/// empty interval: it marks no value stale.
pub const TERMINAL_IMAGE_RETIRED: u64 = 4;
/// Terminal close reason: the view's feeder could not read on (its
/// subscription failed): the view closes, the image stays.
pub const TERMINAL_FEEDER_LOST: u64 = 5;

/// A terminal cell's states.
const EMPTY: u64 = 0;
const CLAIMED: u64 = 1;
const PUBLISHED: u64 = 2;

/// A published terminal invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terminal {
    /// The unresolved interval's start.
    pub start: u64,
    /// The unresolved interval's end.
    pub end: u64,
    /// The close reason code.
    pub reason: u64,
}

impl<'a> TerminalCell<'a> {
    /// Wraps the cell's [`TERMINAL_WORDS`] words.
    ///
    /// # Errors
    ///
    /// [`FreshnessError::InvalidLayout`] for any other length.
    pub fn new(words: &'a [AtomicU64]) -> Result<Self, FreshnessError> {
        if words.len() != TERMINAL_WORDS {
            return Err(FreshnessError::InvalidLayout);
        }
        Ok(Self { words })
    }

    /// Publishes the terminal invalidation: claims the cell (0 to 1), stores
    /// the body (Relaxed), then publishes it (2, Release). Returns `false`,
    /// storing nothing, if the cell was already claimed: it is one-shot,
    /// even against a second publisher.
    #[must_use]
    pub fn publish(&self, terminal: Terminal) -> bool {
        let [state, start, end, reason] = self.words else {
            return false;
        };
        if state
            .compare_exchange(EMPTY, CLAIMED, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        start.store(terminal.start, Ordering::Relaxed);
        end.store(terminal.end, Ordering::Relaxed);
        reason.store(terminal.reason, Ordering::Relaxed);
        state.store(PUBLISHED, Ordering::Release);
        true
    }

    /// The published invalidation, read only after the publication's
    /// Acquire; `None` while empty or claimed.
    #[must_use]
    pub fn read<W: LoadWords>(words: &W) -> Option<Terminal> {
        if words.load_acquire(0)? != PUBLISHED {
            return None;
        }
        Some(Terminal {
            start: words.load(1)?,
            end: words.load(2)?,
            reason: words.load(3)?,
        })
    }
}

/// Words of a [`BarrierMailbox`]: `[request, start, end, ack, attached]`.
pub const MAILBOX_WORDS: usize = 5;
/// Mailbox word indexes.
const REQUEST: usize = 0;
const REQUEST_START: usize = 1;
const REQUEST_END: usize = 2;
const ACK: usize = 3;
const ATTACHED: usize = 4;

/// One lane image's seal mailbox between its receive owner and its view's
/// feeder (`quantstratum-docs: karyos/design/conflated-network-images.md`,
/// (b); GU-8's reviewed bounded handshake).
///
/// The owner posts the interval it intends to seal
/// ([`BarrierMailbox::post`]) and seals only after it reads the
/// acknowledgement ([`BarrierMailbox::is_acknowledged`], Acquire). The
/// feeder takes the request ([`BarrierMailbox::pending`], Acquire), appends
/// the loss to its barrier and publishes it, and only then acknowledges
/// ([`BarrierMailbox::acknowledge`], Release): an owner that sees the
/// acknowledgement sees the barrier record. One request is outstanding at a
/// time, so the mailbox is fixed size. Each side writes only its own words:
/// the owner `request`, `start` and `end`; the feeder `ack` and `attached`.
///
/// While the feeder is not attached ([`BarrierMailbox::is_attached`]), no
/// view exists to protect: the owner seals at once, and the feeder, which
/// catches up from the image log after [`BarrierMailbox::attach`], meets
/// the committed gap itself and appends it before it publishes any value
/// past it. The Loom model `tests/loom_barrier_mailbox.rs` checks the
/// handshake together with the barrier, a slot and the terminal cell.
#[derive(Debug, Clone, Copy)]
pub struct BarrierMailbox<'a> {
    words: &'a [AtomicU64],
}

/// A posted seal request, as the feeder reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealRequest {
    /// The request number, to acknowledge.
    pub request: u64,
    /// The interval's start.
    pub start: u64,
    /// The interval's end.
    pub end: u64,
}

impl<'a> BarrierMailbox<'a> {
    /// Wraps the mailbox's [`MAILBOX_WORDS`] words.
    ///
    /// # Errors
    ///
    /// [`FreshnessError::InvalidLayout`] for any other length.
    pub fn new(words: &'a [AtomicU64]) -> Result<Self, FreshnessError> {
        if words.len() != MAILBOX_WORDS {
            return Err(FreshnessError::InvalidLayout);
        }
        Ok(Self { words })
    }

    fn word(&self, index: usize) -> Result<&'a AtomicU64, FreshnessError> {
        self.words.get(index).ok_or(FreshnessError::InvalidLayout)
    }

    /// Owner: whether the feeder is attached (Acquire). Until it is, the
    /// owner seals without the mailbox.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.word(ATTACHED)
            .is_ok_and(|word| word.load(Ordering::Acquire) != 0)
    }

    /// Owner: posts the interval `[start, end)` it intends to seal: the
    /// interval (Relaxed), then the next request number (Release). Returns
    /// the request number, to wait for with
    /// [`BarrierMailbox::is_acknowledged`].
    ///
    /// # Errors
    ///
    /// [`FreshnessError::InvalidInterval`] for an empty interval,
    /// [`FreshnessError::Busy`] while the previous request is not
    /// acknowledged, [`FreshnessError::Exhausted`]. Nothing is stored on
    /// error.
    pub fn post(&self, start: u64, end: u64) -> Result<u64, FreshnessError> {
        if start >= end {
            return Err(FreshnessError::InvalidInterval { start, end });
        }
        let request = self.word(REQUEST)?;
        // The owner's own word: Relaxed.
        let current = request.load(Ordering::Relaxed);
        // Acquire: the feeder's reads of the previous interval happen
        // before the stores below overwrite it.
        if self.word(ACK)?.load(Ordering::Acquire) != current {
            return Err(FreshnessError::Busy);
        }
        let next = current.checked_add(1).ok_or(FreshnessError::Exhausted)?;
        self.word(REQUEST_START)?.store(start, Ordering::Relaxed);
        self.word(REQUEST_END)?.store(end, Ordering::Relaxed);
        request.store(next, Ordering::Release);
        Ok(next)
    }

    /// Owner: whether the feeder acknowledged `request` (Acquire): its
    /// barrier then holds the interval, and the owner may seal.
    #[must_use]
    pub fn is_acknowledged(&self, request: u64) -> bool {
        self.word(ACK)
            .is_ok_and(|word| word.load(Ordering::Acquire) == request)
    }

    /// Feeder: marks the feeder attached (Release), before it catches up
    /// from the image log.
    pub fn attach(&self) {
        if let Ok(word) = self.word(ATTACHED) {
            word.store(1, Ordering::Release);
        }
    }

    /// Feeder: the outstanding request, if any (an Acquire load of the
    /// request number, then the interval).
    #[must_use]
    pub fn pending(&self) -> Option<SealRequest> {
        let request = self.word(REQUEST).ok()?.load(Ordering::Acquire);
        // The feeder's own word: Relaxed.
        if self.word(ACK).ok()?.load(Ordering::Relaxed) == request {
            return None;
        }
        Some(SealRequest {
            request,
            start: self.word(REQUEST_START).ok()?.load(Ordering::Relaxed),
            end: self.word(REQUEST_END).ok()?.load(Ordering::Relaxed),
        })
    }

    /// Feeder: acknowledges `request` (Release), only after its barrier
    /// published the interval ([`BarrierWords::append_loss`]).
    ///
    /// # Errors
    ///
    /// [`FreshnessError::UnknownRequest`] unless `request` is the
    /// outstanding request; nothing is stored then.
    pub fn acknowledge(&self, request: u64) -> Result<(), FreshnessError> {
        let current = self.word(REQUEST)?.load(Ordering::Acquire);
        let ack = self.word(ACK)?;
        if request != current || request == ack.load(Ordering::Relaxed) {
            return Err(FreshnessError::UnknownRequest { request });
        }
        ack.store(request, Ordering::Release);
        Ok(())
    }
}

/// Words of a [`FreshnessLink`]: a mailbox, then a terminal cell.
pub const LINK_WORDS: usize = MAILBOX_WORDS + TERMINAL_WORDS;

/// The words a lane image's receive owner and its conflated view share
/// (`quantstratum-docs: karyos/design/conflated-network-images.md`, (b)
/// and (c)): the seal mailbox and the view's terminal cell, in one heap
/// allocation both hold. The receive owner allocates it when it installs
/// the image (control path) and hands a clone to the conductor, which
/// builds the view's table over the same terminal cell, so the owner can
/// publish the fail-safe without being a second table writer.
#[derive(Debug, Clone)]
pub struct FreshnessLink {
    words: std::sync::Arc<[AtomicU64]>,
}

impl FreshnessLink {
    /// Allocates a zeroed link: no request, nothing acknowledged, no
    /// feeder attached, an empty terminal cell.
    #[must_use]
    pub fn new() -> Self {
        Self {
            words: (0..LINK_WORDS).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// The seal mailbox.
    ///
    /// # Errors
    ///
    /// None in practice: the layout is fixed at allocation.
    pub fn mailbox(&self) -> Result<BarrierMailbox<'_>, FreshnessError> {
        BarrierMailbox::new(
            self.words
                .get(..MAILBOX_WORDS)
                .ok_or(FreshnessError::InvalidLayout)?,
        )
    }

    /// The view's terminal cell words, for [`TerminalCell::new`] and
    /// [`TerminalCell::read`].
    #[must_use]
    pub fn terminal_words(&self) -> &[AtomicU64] {
        self.words.get(MAILBOX_WORDS..).unwrap_or(&[])
    }

    /// The view's terminal cell.
    ///
    /// # Errors
    ///
    /// None in practice: the layout is fixed at allocation.
    pub fn terminal(&self) -> Result<TerminalCell<'_>, FreshnessError> {
        TerminalCell::new(self.terminal_words())
    }
}

impl Default for FreshnessLink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(loom)))]
mod tests;
