// SPDX-License-Identifier: Apache-2.0

//! The orderings of block publication (SPEC.md §4, publish and read), as
//! small helpers over one word 0 each. `term_memory` uses them on real term
//! memory; the Loom model uses the same helpers on model atomics, so the model
//! checks the production orderings.
//!
//! Values are stored little-endian so the bytes in memory match the wire
//! layout on every target.

use crate::frame::{Flags, FrameType, Lane, PROTOCOL_VERSION, Word0};
use crate::sync::{AtomicU64, Ordering, fence};

/// Stores an interior fragment's word 0. It becomes visible to readers
/// through the `Release` of the block's first word 0, so `Relaxed` suffices.
#[inline]
pub fn store_interior(word: &AtomicU64, word0: Word0) {
    word.store(word0.pack().to_le(), Ordering::Relaxed);
}

/// Publishes a block by storing its first word 0 with `Release`, after every
/// other byte and interior word 0 of the block has been written.
#[inline]
pub fn publish_block(first: &AtomicU64, word0: Word0) {
    first.store(word0.pack().to_le(), Ordering::Release);
}

/// Loads a block's first word 0 with `Acquire`; if it is committed, every
/// write made before its publication is visible afterwards.
#[inline]
#[must_use]
pub fn observe_block(first: &AtomicU64) -> u64 {
    u64::from_le(first.load(Ordering::Acquire))
}

/// Loads an interior fragment's word 0 after [`observe_block`] saw the
/// block committed.
#[inline]
#[must_use]
pub fn load_interior(word: &AtomicU64) -> u64 {
    u64::from_le(word.load(Ordering::Relaxed))
}

/// Stores eight body bytes (header words 1 to 3, extension or payload) of a
/// block on shared terms, which are written only as atomic words. Like an
/// interior word 0 they become visible through the block's `Release`
/// publication, so `Relaxed` suffices. Bytes keep their memory order, as a
/// plain copy would.
#[inline]
pub fn store_body(word: &AtomicU64, bytes: [u8; 8]) {
    word.store(u64::from_ne_bytes(bytes), Ordering::Relaxed);
}

/// Loads eight body bytes of a block on shared terms after
/// [`observe_block`] saw it committed.
#[inline]
#[must_use]
pub fn load_body(word: &AtomicU64) -> [u8; 8] {
    word.load(Ordering::Relaxed).to_ne_bytes()
}

/// Clears a location that may have held a word 0, during exclusive cleaning.
/// The `Release` publication of `FREE` afterwards orders it before any later
/// use of the slot.
#[inline]
pub fn clear_word(word: &AtomicU64) {
    word.store(0, Ordering::Relaxed);
}

/// Marks a claimed block: compare-exchanges its first word 0 from 0 to the
/// `reserved` value, a negative length (SPEC.md §4, claims). It is the
/// claim's first write to the block; it fails only if the block was already
/// aborted, and then nothing else may be written.
#[inline]
pub fn mark_block(first: &AtomicU64, reserved: Word0) -> bool {
    first
        .compare_exchange(
            0,
            reserved.pack().to_le(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Commits a marked block: compare-exchanges its first word 0 from
/// `reserved` to the final `committed` word 0. Its `Release` publishes the
/// block like [`publish_block`]. Fails if an abort won.
#[inline]
pub fn commit_block(first: &AtomicU64, reserved: Word0, committed: Word0) -> bool {
    first
        .compare_exchange(
            reserved.pack().to_le(),
            committed.pack().to_le(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Aborts a marked block: compare-exchanges its first word 0 from
/// `reserved` to the `aborted` word 0 stating the reserved extent. Fails if
/// a commit won (or another abort did).
#[inline]
pub fn abort_block(first: &AtomicU64, reserved: Word0, aborted: Word0) -> bool {
    first
        .compare_exchange(
            reserved.pack().to_le(),
            aborted.pack().to_le(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Writes the claim record (`quantstratum-docs: karyos/design/claim-deadline.md`) as a seqlock
/// of atomic words: the serial goes odd, a Release fence orders it before
/// the record store, and the next even serial is stored with Release. Only
/// the publication writes it.
#[inline]
pub fn write_claim_record(serial: &AtomicU64, record: &AtomicU64, value: u64) {
    let current = serial.load(Ordering::Relaxed);
    serial.store(current.wrapping_add(1), Ordering::Relaxed);
    fence(Ordering::Release);
    record.store(value, Ordering::Relaxed);
    serial.store(current.wrapping_add(2), Ordering::Release);
}

/// Invalidates the claim record on behalf of a writer that can make no
/// further access (`quantstratum-docs: karyos/design/ipc-data-path.md`,
/// Ending a registration): the writer may have died with the serial odd,
/// so this does not wait for an even snapshot. It stores an empty record
/// under an odd serial and then the next even serial with Release, so no
/// reader takes the torn contents.
#[inline]
pub fn invalidate_claim_record(serial: &AtomicU64, record: &AtomicU64) {
    let odd = serial.load(Ordering::Relaxed) | 1;
    serial.store(odd, Ordering::Relaxed);
    fence(Ordering::Release);
    record.store(0, Ordering::Relaxed);
    serial.store(odd.wrapping_add(1), Ordering::Release);
}

/// Reads a consistent claim record: `(serial, record)` when both serial
/// loads are equal and even, `None` while the publication rewrites it.
#[inline]
#[must_use]
pub fn read_claim_record(serial: &AtomicU64, record: &AtomicU64) -> Option<(u64, u64)> {
    let first = serial.load(Ordering::Acquire);
    let value = record.load(Ordering::Relaxed);
    fence(Ordering::Acquire);
    let second = serial.load(Ordering::Relaxed);
    (first == second && first.is_multiple_of(2)).then_some((first, value))
}

/// Whether `raw` (as loaded, little-endian) is a valid reserved word of a
/// claim of `extent` bytes on `lane`: protocol version, no reserved flag
/// bits, type DATA, BEGIN and END, the lane, and a length of minus the
/// extent. EOS and EXT are the claim's choice.
#[must_use]
fn is_reserved_claim(raw: u64, extent: u32, lane: Lane) -> bool {
    let Ok(word) = Word0::unpack(u64::from_le(raw)) else {
        return false;
    };
    let flags = word.flags();
    word.version() == PROTOCOL_VERSION
        && word.frame_type_code() == FrameType::Data.code()
        && flags.begin()
        && flags.end()
        && flags.lane() == lane
        && i64::from(word.frame_length()) == -i64::from(extent)
}

/// The commit-deadline abort of one claimed block
/// (`quantstratum-docs: karyos/design/claim-deadline.md`): at most two compare-exchanges on its
/// first word 0, and no other access. From 0 (the writer has not marked)
/// to `aborted`; if that fails because the writer marked, or the word was
/// already a valid reserved word of `extent` on `lane`, from exactly that
/// observed word to `aborted`. Returns whether this call won the abort.
#[inline]
pub fn deadline_abort(first: &AtomicU64, extent: u32, lane: Lane, aborted: Word0) -> bool {
    let target = aborted.pack().to_le();
    let mut current = first.load(Ordering::Acquire);
    if current == 0 {
        match first.compare_exchange(0, target, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(found) => current = found,
        }
    }
    is_reserved_claim(current, extent, lane)
        && first
            .compare_exchange(current, target, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

/// A publisher slot in use (`quantstratum-docs: karyos/design/concurrent-publication.md`). A
/// free slot holds 0 (never used) or `t_close + 1`.
pub const PUBLISHER_HELD: u64 = 1 << 63;

/// Frees a publisher slot after its holder's last access, recording the
/// active term count at close (`t_close`). The Release orders every access
/// of the holder before the conductor's Acquire in
/// [`acquire_publisher_slot`].
#[inline]
pub fn release_publisher_slot(word: &AtomicU64, t_close: u32) {
    word.store(u64::from(t_close) + 1, Ordering::Release);
}

/// Takes a free publisher slot for a new holder: `None` when it is held,
/// otherwise `Some` of the previous holder's `t_close` (`None` for a
/// never-used slot). Only the conductor issues slots, so the store needs
/// no compare-exchange.
#[inline]
pub fn acquire_publisher_slot(word: &AtomicU64) -> Option<Option<u32>> {
    let value = word.load(Ordering::Acquire);
    if value & PUBLISHER_HELD != 0 {
        return None;
    }
    word.store(PUBLISHER_HELD | value, Ordering::Relaxed);
    Some(value.checked_sub(1).map(|t_close| t_close as u32))
}

/// The first term count a reissued publisher slot may reserve in: the
/// active count `active`, unless the previous holder closed in the still
/// active term `t_close` after a crossing in it (`crossed`, evaluated only
/// then), in which case `t_close + 1`.
#[inline]
#[must_use]
pub fn reissue_from(previous: Option<u32>, active: u32, crossed: impl FnOnce() -> bool) -> u32 {
    match previous {
        Some(t_close) if active <= t_close && crossed() => t_close.wrapping_add(1),
        _ => active,
    }
}

/// The aborting marker of the span walk (`quantstratum-docs: karyos/design/concurrent-deadline.md`):
/// type `ABORTED`, length `-32`, no flags. No reserved word equals it
/// (those are `DATA` or `PAD`), and readers wait at it as at any negative
/// word.
pub const ABORTING_MARKER: Word0 = Word0::new(-32, Flags::NONE, FrameType::Aborted);

/// Takes one 32-byte boundary of a zero span for the span walk: compare-
/// exchanges it from 0 to [`ABORTING_MARKER`]. Fails with the word found
/// (decoded) when a writer marked or committed there first; the walk then
/// stores nothing there.
#[inline]
pub fn take_span_word(word: &AtomicU64) -> Result<(), u64> {
    word.compare_exchange(
        0,
        ABORTING_MARKER.pack().to_le(),
        Ordering::AcqRel,
        Ordering::Acquire,
    )
    .map(|_| ())
    .map_err(u64::from_le)
}

/// Ends a span walk: stores the `ABORTED` word covering the owned span over
/// the marker at its start with `Release`, after every marker of the span.
#[inline]
pub fn end_span(first: &AtomicU64, aborted: Word0) {
    publish_block(first, aborted);
}

/// The extent of a concurrent block's valid reserved word `raw` (decoded)
/// at `offset` (`quantstratum-docs: karyos/design/concurrent-deadline.md`, aborting a marked
/// block): protocol version, no reserved flag bits, type `DATA` with BEGIN
/// (a message or claim) or a `PAD` without flags ending exactly at the
/// term end, the buffer's lane, and a negative length that is a multiple of
/// 32, at most `max_reserved` and fits in the term from `offset`. `None`
/// for anything else, the aborting marker included.
#[must_use]
pub fn reserved_extent(
    raw: u64,
    offset: u32,
    term_length: u32,
    max_reserved: u32,
    lane: Lane,
) -> Option<u32> {
    let word = Word0::unpack(raw).ok()?;
    let length = word.frame_length();
    if word.version() != PROTOCOL_VERSION || length >= 0 {
        return None;
    }
    let extent = length.unsigned_abs();
    let flags = word.flags();
    let fits = extent.is_multiple_of(32)
        && extent <= max_reserved
        && offset < term_length
        && extent <= term_length - offset;
    let shape = match FrameType::try_from_code(word.frame_type_code()) {
        Ok(FrameType::Data) => flags.begin() && flags.lane() == lane,
        Ok(FrameType::Pad) => {
            flags == Flags::new(false, false, false, false, lane) && extent == term_length - offset
        }
        _ => false,
    };
    (fits && shape).then_some(extent)
}

/// The seal word once sealed (`quantstratum-docs: karyos/design/publication-seal.md`).
pub const SEAL_SEALED: u64 = 1 << 63;
/// The seal word's mark of a known seal position, held in the bits below.
pub const SEAL_POSITIONED: u64 = 1 << 62;

/// Seals (conductor): writes `SEAL_SEALED`, then a zero `limit`. A
/// publisher whose Acquire load of the limit reads that zero then observes
/// the seal.
///
/// The issuer takes the publication, then reads the seal; the conductor
/// writes the seal, then reads whether it was taken. Every one of these
/// four accesses is a read-modify-write, so each reads the latest value of
/// its word: if the issuer's read misses the seal, the seal write reads
/// from it and synchronizes with it, and the conductor then sees the take
/// (`quantstratum-docs: karyos/design/publication-seal.md`, issuance).
#[inline]
pub fn seal(seal: &AtomicU64, limit: &AtomicU64) {
    let _ = seal.swap(SEAL_SEALED, Ordering::AcqRel);
    limit.store(0, Ordering::Release);
}

/// A publisher's check after an attempt that was not granted: whether the
/// buffer is sealed.
#[inline]
pub fn observe_seal(seal: &AtomicU64) -> bool {
    seal.load(Ordering::Acquire) != 0
}

/// Takes the exclusive publication once (issuer), then the issuer reads
/// the seal with [`issuer_sees_seal`].
#[inline]
pub fn take_publication(taken: &AtomicU64) -> bool {
    taken
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// The issuer's read of the seal after [`take_publication`], a
/// read-modify-write that changes nothing (see [`seal`]).
#[inline]
pub fn issuer_sees_seal(seal: &AtomicU64) -> bool {
    seal.fetch_or(0, Ordering::AcqRel) != 0
}

/// The conductor's read, after [`seal`], of whether the exclusive
/// publication was ever taken: a read-modify-write that changes nothing
/// (see [`seal`]).
#[inline]
pub fn publication_taken(taken: &AtomicU64) -> bool {
    taken.fetch_or(0, Ordering::AcqRel) != 0
}

/// Announces the exclusive publication's release after its last
/// reservation (its last `reserved_head` store).
#[inline]
pub fn release_publication(released: &AtomicU64) {
    released.store(1, Ordering::Release);
}

/// Whether the exclusive publication released: the Acquire orders every
/// reservation it was granted before the conductor's head read.
#[inline]
pub fn publication_released(released: &AtomicU64) -> bool {
    released.load(Ordering::Acquire) != 0
}

/// Whether a publisher slot is free (conductor): the Acquire orders every
/// reservation of its last holder before the conductor's head read.
/// Concurrent handles are issued by the conductor itself, so no issuance
/// races this load.
#[inline]
pub fn publisher_slot_free(word: &AtomicU64) -> bool {
    word.load(Ordering::Acquire) & PUBLISHER_HELD == 0
}

/// The bit of `active_count` that stops rotation once a concurrent buffer
/// is fenced (`quantstratum-docs: karyos/design/mapping-generations.md`). Every reader of the
/// count truncates it to 32 bits, and every rotation advances it with a
/// compare-exchange from an exact count, which fails once the bit is set.
pub const ROTATION_FENCE: u64 = 1 << 63;

/// Stops rotation (conductor): sets [`ROTATION_FENCE`] and returns the
/// active term count. A read-modify-write, so a rotation's
/// compare-exchange either precedes it (and the count returned is the
/// rotated one) or fails.
#[inline]
pub fn fence_rotation(active_count: &AtomicU64) -> u32 {
    active_count.fetch_or(ROTATION_FENCE, Ordering::AcqRel) as u32
}

/// The term count of an `active_count` value, without the fence bit.
#[inline]
pub fn active_term_count(raw: u64) -> u32 {
    raw as u32
}

/// Closes the active term's tail (conductor): adds `term_length`, so every
/// later `fetch_add` lands past the end, and returns the old tail. Its
/// offset is the end of every reservation granted in that term, since each
/// is a `fetch_add` earlier in the tail's modification order. A
/// publisher's `fetch_add` that reads from this one synchronizes with the
/// conductor and sees the seal and the zero limit stored before it.
#[inline]
pub fn fence_tail(tail: &AtomicU64, term_length: u32) -> u64 {
    tail.fetch_add(u64::from(term_length), Ordering::AcqRel)
}

/// Writes the seal position (conductor), once every publisher released.
/// A swap, like every write to the seal word, so that the issuer's
/// read-modify-write in [`issuer_sees_seal`] is ordered with all of them.
#[inline]
pub fn position_seal(seal: &AtomicU64, position: u64) {
    let _ = seal.swap(
        SEAL_SEALED | SEAL_POSITIONED | (position & (SEAL_POSITIONED - 1)),
        Ordering::AcqRel,
    );
}
