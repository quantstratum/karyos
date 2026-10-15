// SPDX-License-Identifier: Apache-2.0

//! The receive owner of an image (`quantstratum-docs: karyos/design/receive-publication.md`,
//! batch r2): the only writer of every lane of an image, which commits frames
//! validated by [`ValidatedDatagram::parse`](crate::receive::ValidatedDatagram::parse)
//! one by one.
//!
//! Per lane it keeps a term window `{r, r + 1}` (the term of the rebuild
//! position and the next one), standing write loans on the terms it writes,
//! and a private extent record: two bitmaps per term (`covered` and
//! `starts`, one bit per 32-byte unit). The record, never the term memory,
//! decides what is committed, so a frame that overlaps or differs from a
//! committed one is never written and a word 0 left from an earlier use of a
//! slot is never taken for a committed frame. Copies for the trailing term
//! `r - 1` are compared under a transient read loan and never written.
//!
//! Every check happens before the first write; the write itself (body, then
//! word 0 with one Release store) cannot fail.

use core::marker::PhantomData;
use core::sync::atomic::Ordering;
use std::sync::Arc;

use super::{LogBuffer, Lookup, PublicationMode};
use crate::error::SysError;
use crate::frame::{FRAME_ALIGNMENT, Lane};
use crate::loan::{LoanOutcome, Rotation, release_loan, rotate_to, take_loan};
use crate::publication::{active_term_count, observe_block, publish_block, take_publication};
use crate::receive::{ImageParams, ValidatedFrame};
use crate::term::{TERM_COUNT_LIMIT, TermCount};
use crate::term_bytes::{HeapTerms, TermBytes};

/// Bits per bitmap word.
const WORD_BITS: usize = 64;
/// Bitmap words a duty cycle clears per lane: bounded cleaning work.
const CLEAN_CHUNK_WORDS: usize = 1024;
/// Bitmap sets per lane: the trailing term, the window and one spare
/// (owner decision D2).
const SETS: usize = 4;
/// Registry cell of the owner's transient read loan on the trailing term;
/// cells 0 and 1 hold the write loans, by term parity.
const READ_CELL: usize = 2;
/// Bytes compared per read of committed bytes.
const COMPARE_CHUNK: usize = 256;

/// What [`ReceiveOwner::receive`] did with a frame that broke no protocol
/// rule. Only `Committed` changed the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// Written and published with one Release store of its word 0.
    Committed {
        /// Stream position of the frame in its lane.
        position: u64,
        /// The extent it occupies.
        extent: u32,
    },
    /// Equal, byte for byte, to the committed frame at its destination.
    Duplicate,
    /// Its term is no longer held by the image, or it starts below the join
    /// point: dropped without comparison.
    Late,
    /// Its term is beyond the window `{r, r + 1}`: dropped.
    Ahead,
    /// Its term is not prepared yet, or no clean bitmap set is free for
    /// it: dropped, to be repaired like a loss.
    NotReady,
}

/// A frame the owner refused because it breaks a protocol rule, or an
/// internal failure. The image is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiveError {
    /// The frame differs from, or overlaps, a committed frame.
    #[error(
        "frame at position {position} (extent {extent}) of lane {lane:?} conflicts with a committed frame"
    )]
    Conflict {
        /// The frame's lane.
        lane: Lane,
        /// The frame's position.
        position: u64,
        /// The frame's extent.
        extent: u32,
    },
    /// The frame was validated against other image parameters.
    #[error("the frame was validated for another image")]
    Foreign,
    /// The image's shared state is not what the owner wrote: a protocol
    /// error of another party, or a defect.
    #[error(transparent)]
    Sys(#[from] SysError),
}

/// Lifetime counters of a receive owner, over all lanes. A counter that
/// would overflow keeps its value and increments `overflows` instead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiveCounters {
    /// Frames committed.
    pub frames_committed: u64,
    /// Extent bytes committed.
    pub bytes_committed: u64,
    /// Exact duplicates.
    pub frames_duplicate: u64,
    /// Frames dropped as late.
    pub frames_late: u64,
    /// Frames dropped as ahead of the window.
    pub frames_ahead: u64,
    /// Frames dropped as not ready.
    pub frames_not_ready: u64,
    /// Frames refused as conflicting.
    pub frames_conflicting: u64,
    /// Times the next term was not prepared by the conductor.
    pub cleaner_lag: u64,
    /// Increments not applied because a counter would overflow.
    pub overflows: u64,
}

impl ReceiveCounters {
    fn bump(counter: &mut u64, overflows: &mut u64, by: u64) {
        match counter.checked_add(by) {
            Some(value) => *counter = value,
            None => *overflows = overflows.saturating_add(1),
        }
    }
}

/// The single writer of an image: every lane, one per [`LogBuffer`] in
/// [`PublicationMode::Image`]. `Send` but not `Sync`, and every method that
/// touches the image takes `&mut self`, so no two receive operations on one
/// image ever run at once.
#[derive(Debug)]
pub struct ReceiveOwner<T: TermBytes = HeapTerms> {
    params: ImageParams,
    lanes: Vec<LaneOwner<T>>,
    counters: ReceiveCounters,
    _not_sync: PhantomData<core::cell::Cell<()>>,
}

impl<T: TermBytes> ReceiveOwner<T> {
    /// The owner of the image whose lanes are `lanes`, lane `i` at index
    /// `i`, for frames validated against `params`. Takes each lane's owner
    /// flag; an image has one owner for its whole life.
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidPublicationMode`] when a buffer is not an image,
    /// does not match `params` or its lane index, or already has an owner.
    pub fn new(params: ImageParams, lanes: Vec<Arc<LogBuffer<T>>>) -> Result<Self, SysError> {
        let invalid = |reason| SysError::InvalidPublicationMode { reason };
        if lanes.len() != usize::from(params.lanes()) {
            return Err(invalid("the lane count differs from the image parameters"));
        }
        for (index, buffer) in lanes.iter().enumerate() {
            let config = &buffer.config;
            if !matches!(config.publication, PublicationMode::Image { .. }) {
                return Err(invalid("a receive owner needs image buffers"));
            }
            if usize::from(config.lane.get()) != index
                || config.session_id != params.session_id()
                || config.stream_id != params.stream_id()
                || config.term_length != params.term_length()
                || config.mtu != params.mtu()
            {
                return Err(invalid(
                    "an image buffer does not match the image parameters",
                ));
            }
        }
        let mut owners = Vec::with_capacity(lanes.len());
        for buffer in lanes {
            if !take_publication(buffer.publication_taken()) {
                return Err(invalid("the image already has a receive owner"));
            }
            owners.push(LaneOwner::new(buffer));
        }
        Ok(Self {
            params,
            lanes: owners,
            counters: ReceiveCounters::default(),
            _not_sync: PhantomData,
        })
    }

    /// Classifies `frame` against the lane's window and extent record and,
    /// if it is new, writes and publishes it.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::Conflict`] for a frame that differs from or overlaps a
    /// committed one, [`ReceiveError::Foreign`] for a frame validated for
    /// other parameters, [`ReceiveError::Sys`] for a corrupt shared state.
    /// The image is unchanged in every error case.
    pub fn receive(&mut self, frame: &ValidatedFrame<'_>) -> Result<Received, ReceiveError> {
        if frame.params() != &self.params {
            return Err(ReceiveError::Foreign);
        }
        let lane = self
            .lanes
            .get_mut(usize::from(frame.lane().get()))
            .ok_or(ReceiveError::Foreign)?;
        let result = lane.receive(frame);
        let counters = &mut self.counters;
        let overflows = &mut counters.overflows;
        match result {
            Ok(Received::Committed { extent, .. }) => {
                ReceiveCounters::bump(&mut counters.frames_committed, overflows, 1);
                ReceiveCounters::bump(&mut counters.bytes_committed, overflows, u64::from(extent));
            }
            Ok(Received::Duplicate) => {
                ReceiveCounters::bump(&mut counters.frames_duplicate, overflows, 1);
            }
            Ok(Received::Late) => ReceiveCounters::bump(&mut counters.frames_late, overflows, 1),
            Ok(Received::Ahead) => ReceiveCounters::bump(&mut counters.frames_ahead, overflows, 1),
            Ok(Received::NotReady) => {
                ReceiveCounters::bump(&mut counters.frames_not_ready, overflows, 1);
            }
            Err(ReceiveError::Conflict { .. }) => {
                ReceiveCounters::bump(&mut counters.frames_conflicting, overflows, 1);
            }
            Err(_) => {}
        }
        if lane.lagged {
            lane.lagged = false;
            ReceiveCounters::bump(&mut counters.cleaner_lag, overflows, 1);
        }
        result
    }

    /// Bounded background work: clears released bitmap sets, at most
    /// `CLEAN_CHUNK_WORDS` words per lane. Returns whether work remains.
    pub fn duty(&mut self) -> bool {
        let mut remaining = false;
        for lane in &mut self.lanes {
            remaining |= lane.clean_chunk();
        }
        remaining
    }

    /// The rebuild position of `lane`: the end of its contiguous committed
    /// prefix, also published in the image (Release).
    #[must_use]
    pub fn rebuild_position(&self, lane: Lane) -> Option<u64> {
        self.lanes.get(usize::from(lane.get())).map(|l| l.rebuild)
    }

    /// The highest committed end of `lane`, the high-water mark that loss
    /// detection compares the rebuild position against.
    #[must_use]
    pub fn high_water(&self, lane: Lane) -> Option<u64> {
        self.lanes.get(usize::from(lane.get())).map(|l| l.high)
    }

    /// The owner's lifetime counters.
    #[must_use]
    pub fn counters(&self) -> ReceiveCounters {
        self.counters
    }
}

impl<T: TermBytes> Drop for ReceiveOwner<T> {
    fn drop(&mut self) {
        for lane in &mut self.lanes {
            lane.release_all();
        }
    }
}

/// The extent record of one term incarnation.
#[derive(Debug)]
struct Set {
    term: Option<TermCount>,
    covered: Vec<u64>,
    starts: Vec<u64>,
    /// Released and not yet fully zeroed: never used until clean.
    dirty: bool,
    cursor: usize,
}

/// The owner's state for one lane.
#[derive(Debug)]
struct LaneOwner<T: TermBytes> {
    buffer: Arc<LogBuffer<T>>,
    units: usize,
    join: u64,
    rebuild: u64,
    high: u64,
    sets: [Set; SETS],
    /// Standing write loans, by term parity: the term and its slot.
    loans: [Option<(TermCount, u8)>; 2],
    /// Set when the last receive found the next term unprepared.
    lagged: bool,
}

impl<T: TermBytes> LaneOwner<T> {
    fn new(buffer: Arc<LogBuffer<T>>) -> Self {
        let units = (buffer.term_length / FRAME_ALIGNMENT) as usize;
        let words = units.div_ceil(WORD_BITS);
        let join = buffer.join();
        let set = || Set {
            term: None,
            covered: vec![0; words],
            starts: vec![0; words],
            dirty: false,
            cursor: 0,
        };
        Self {
            buffer,
            units,
            join,
            rebuild: join,
            high: join,
            sets: [set(), set(), set(), set()],
            loans: [None, None],
            lagged: false,
        }
    }

    fn receive(&mut self, frame: &ValidatedFrame<'_>) -> Result<Received, ReceiveError> {
        let buffer = Arc::clone(&self.buffer);
        let Ok(count) = frame.term_id().count_from(buffer.initial_term_id) else {
            // Not a term of this incarnation's first 2^31.
            return Ok(Received::Late);
        };
        let start = buffer.position(count, frame.term_offset());
        if start < self.join {
            return Ok(Received::Late);
        }
        let (r, _) = self.split_end(self.rebuild)?;
        let (c, rr) = (count.get(), r.get());
        if c > rr.saturating_add(1) {
            return Ok(Received::Ahead);
        }
        if c.saturating_add(1) < rr {
            return Ok(Received::Late);
        }
        let unit = (frame.term_offset() / FRAME_ALIGNMENT) as usize;
        let units = (frame.extent() / FRAME_ALIGNMENT) as usize;
        let conflict = || ReceiveError::Conflict {
            lane: frame.lane(),
            position: start,
            extent: frame.extent(),
        };

        if c.saturating_add(1) == rr {
            // The trailing term: every unit from the join point up is
            // covered, so a copy is a duplicate or a conflict, never new.
            let Some(index) = self.set_of(count) else {
                return Ok(Received::Late);
            };
            let set = self.set(index)?;
            if !bit(&set.starts, unit) {
                return Err(conflict());
            }
            return match self.compare_trailing(count, frame)? {
                Some(true) => Ok(Received::Duplicate),
                Some(false) => Err(conflict()),
                None => Ok(Received::Late),
            };
        }

        let index = match self.set_of(count) {
            Some(index) => index,
            None => match self.assign_set(count) {
                Some(index) => index,
                None => return Ok(Received::NotReady),
            },
        };
        if bit(&self.set(index)?.starts, unit) {
            // Written by this owner in this term incarnation, so its write
            // loan is held.
            let slot = self.held_slot(count).ok_or(SysError::CorruptTerm {
                offset: frame.term_offset(),
                reason: "committed frame without its write loan",
            })?;
            return if equal(&buffer, slot, frame) {
                Ok(Received::Duplicate)
            } else {
                Err(conflict())
            };
        }
        if any_set(&self.set(index)?.covered, unit, units) {
            return Err(conflict());
        }
        let Some(slot) = self.write_loan(count)? else {
            return Ok(Received::NotReady);
        };
        write(&buffer, slot, frame);
        let set = self.set_mut(index)?;
        set_bit(&mut set.starts, unit);
        set_range(&mut set.covered, unit, units);
        let end = start + u64::from(frame.extent());
        self.high = self.high.max(end);
        if start == self.rebuild {
            self.advance()?;
        }
        Ok(Received::Committed {
            position: start,
            extent: frame.extent(),
        })
    }

    /// [`LogBuffer::split`], except that the end of the incarnation's last
    /// term, which no term count names, is the end of that term: once the
    /// last term is complete the window stays on it, every later copy is
    /// compared there, and nothing new is ever written.
    fn split_end(&self, position: u64) -> Result<(TermCount, u32), SysError> {
        let term_length = self.buffer.term_length;
        if position == u64::from(TERM_COUNT_LIMIT) * u64::from(term_length) {
            return Ok((TermCount::try_new(TERM_COUNT_LIMIT - 1)?, term_length));
        }
        self.buffer.split(position)
    }

    fn set(&self, index: usize) -> Result<&Set, SysError> {
        self.sets.get(index).ok_or(SysError::ResourcesUnavailable)
    }

    fn set_mut(&mut self, index: usize) -> Result<&mut Set, SysError> {
        self.sets
            .get_mut(index)
            .ok_or(SysError::ResourcesUnavailable)
    }

    fn loan(&mut self, parity: usize) -> Result<&mut Option<(TermCount, u8)>, SysError> {
        self.loans
            .get_mut(parity)
            .ok_or(SysError::ResourcesUnavailable)
    }

    fn set_of(&self, count: TermCount) -> Option<usize> {
        self.sets.iter().position(|set| set.term == Some(count))
    }

    fn assign_set(&mut self, count: TermCount) -> Option<usize> {
        let (index, set) = self
            .sets
            .iter_mut()
            .enumerate()
            .find(|(_, set)| set.term.is_none() && !set.dirty)?;
        set.term = Some(count);
        Some(index)
    }

    fn held_slot(&self, count: TermCount) -> Option<u8> {
        match self.loans.get((count.get() & 1) as usize) {
            Some(Some((held, slot))) if *held == count => Some(*slot),
            _ => None,
        }
    }

    /// The slot of `count` under a standing write loan, activating every
    /// term up to it first. `None` when the term is not prepared or the
    /// loan is refused: nothing was written.
    fn write_loan(&mut self, count: TermCount) -> Result<Option<u8>, SysError> {
        if let Some(slot) = self.held_slot(count) {
            return Ok(Some(slot));
        }
        let parity = (count.get() & 1) as usize;
        let buffer = Arc::clone(&self.buffer);
        if self.loan(parity)?.take().is_some() {
            // A loan on an older term of the same parity, left behind by a
            // window move: its accesses ended with the last receive.
            release_loan(&buffer.cell(parity)?.loan);
        }
        if !self.activate_through(count)? {
            self.lagged = true;
            return Ok(None);
        }
        let Lookup::Slot(slot) = buffer.lookup(count)? else {
            self.lagged = true;
            return Ok(None);
        };
        let cell = buffer.cell(parity)?;
        match take_loan(
            &cell.loan,
            &cell.revoked,
            buffer.descriptor(slot)?,
            buffer.target(slot, count)?,
        )? {
            LoanOutcome::Granted => {
                *self.loan(parity)? = Some((count, slot));
                Ok(Some(slot))
            }
            _ => Ok(None),
        }
    }

    /// Activates, in order, every term after the active one up to `count`,
    /// as rotation step 2 does. `false` when a term is not prepared.
    fn activate_through(&self, count: TermCount) -> Result<bool, SysError> {
        let buffer = &*self.buffer;
        // The window spans two terms past a rebuild position that may sit
        // at the start of a term not yet activated: at most three steps.
        for _ in 0..4 {
            let active = TermCount::try_new(active_term_count(
                buffer.active_count().load(Ordering::Acquire),
            ))?;
            if active >= count {
                return Ok(true);
            }
            let next = active.next()?;
            let Lookup::Slot(slot) = buffer.lookup(next)? else {
                return Ok(false);
            };
            match rotate_to(
                buffer.descriptor(slot)?,
                buffer.active_count(),
                buffer.initial_term_id.advanced_by(next),
                buffer.generation,
                next,
            )? {
                Rotation::Completed | Rotation::Superseded => {}
                Rotation::NotReady => return Ok(false),
            }
        }
        Ok(false)
    }

    /// Compares a copy for the trailing term under a transient read loan.
    /// `None` when the term is no longer held.
    fn compare_trailing(
        &self,
        count: TermCount,
        frame: &ValidatedFrame<'_>,
    ) -> Result<Option<bool>, SysError> {
        let buffer = &*self.buffer;
        let Lookup::Slot(slot) = buffer.lookup(count)? else {
            return Ok(None);
        };
        let cell = buffer.cell(READ_CELL)?;
        match take_loan(
            &cell.loan,
            &cell.revoked,
            buffer.descriptor(slot)?,
            buffer.target(slot, count)?,
        )? {
            LoanOutcome::Granted => {}
            _ => return Ok(None),
        }
        let same = equal(buffer, slot, frame);
        release_loan(&cell.loan);
        Ok(Some(same))
    }

    /// Advances the rebuild position over every covered unit from it,
    /// publishes it, and moves the window when it crosses a term end.
    fn advance(&mut self) -> Result<(), SysError> {
        let buffer = Arc::clone(&self.buffer);
        // At most the two window terms can be crossed in one advance.
        for _ in 0..3 {
            let (count, offset) = self.split_end(self.rebuild)?;
            let Some(index) = self.set_of(count) else {
                break;
            };
            let unit = (offset / FRAME_ALIGNMENT) as usize;
            let end = first_zero(&self.set(index)?.covered, unit, self.units);
            if end == unit {
                break;
            }
            self.rebuild = buffer.position(count, 0) + (end as u64) * u64::from(FRAME_ALIGNMENT);
            if end < self.units {
                break;
            }
        }
        // Every frame below the rebuild position was published (Release)
        // before this store.
        buffer
            .reserved_head()
            .store(self.rebuild, Ordering::Release);
        let (r, _) = self.split_end(self.rebuild)?;
        for parity in 0..2 {
            let loan = self.loan(parity)?;
            if let Some((held, _)) = *loan
                && held < r
            {
                *loan = None;
                release_loan(&buffer.cell(parity)?.loan);
            }
        }
        for set in &mut self.sets {
            if let Some(term) = set.term
                && term.get().saturating_add(1) < r.get()
            {
                set.term = None;
                set.dirty = true;
                set.cursor = 0;
            }
        }
        Ok(())
    }

    /// Clears a chunk of released sets; returns whether work remains.
    fn clean_chunk(&mut self) -> bool {
        let mut budget = CLEAN_CHUNK_WORDS;
        for set in &mut self.sets {
            if !set.dirty {
                continue;
            }
            let words = set.covered.len();
            let end = (set.cursor + budget).min(words);
            for bits in [&mut set.covered, &mut set.starts] {
                if let Some(range) = bits.get_mut(set.cursor..end) {
                    range.fill(0);
                }
            }
            budget -= end - set.cursor;
            set.cursor = end;
            if set.cursor == words {
                set.dirty = false;
                set.cursor = 0;
            }
            if budget == 0 {
                break;
            }
        }
        self.sets.iter().any(|set| set.dirty)
    }

    fn release_all(&mut self) {
        for (parity, loan) in self.loans.iter_mut().enumerate() {
            if loan.take().is_some()
                && let Ok(cell) = self.buffer.cell(parity)
            {
                release_loan(&cell.loan);
            }
        }
    }
}

/// Writes the frame's body after word 0, then publishes its image word 0.
fn write<T: TermBytes>(buffer: &LogBuffer<T>, slot: u8, frame: &ValidatedFrame<'_>) {
    let offset = frame.term_offset();
    // SAFETY: the owner holds the write loan on `slot`'s current term; the
    // range starts 8 bytes into the frame, a multiple of 8, and lies inside
    // the frame's extent, which the owner's record shows uncovered, so it
    // holds no word 0 of this term and was never written in this
    // incarnation (its bytes read zero after cleaning); no reader reaches
    // it before the Release publication below.
    unsafe { buffer.regions.write_bytes(slot, offset + 8, frame.body()) };
    // SAFETY: write loan held; `offset` is the start of this frame.
    let word0 = unsafe { buffer.regions.word0(slot, offset) };
    publish_block(word0, frame.image_word0());
}

/// Whether the committed frame at the frame's destination equals it: its
/// image word 0 and every body byte.
fn equal<T: TermBytes>(buffer: &LogBuffer<T>, slot: u8, frame: &ValidatedFrame<'_>) -> bool {
    let offset = frame.term_offset();
    // SAFETY: the caller holds a loan on `slot`'s current term and `offset`
    // is the start of a frame the owner committed there.
    let word0 = unsafe { buffer.regions.word0(slot, offset) };
    if observe_block(word0) != frame.image_word0().pack() {
        return false;
    }
    let body = frame.body();
    let mut chunk = [0u8; COMPARE_CHUNK];
    for (index, expected) in body.chunks(COMPARE_CHUNK).enumerate() {
        let Some(out) = chunk.get_mut(..expected.len()) else {
            return false;
        };
        let at = offset + 8 + (index * COMPARE_CHUNK) as u32;
        // SAFETY: loan held; `at` is a multiple of 8 inside the committed
        // frame (same image word 0, so the same length), after its word 0
        // and holding no other; the Acquire load above saw it published.
        unsafe { buffer.regions.read_bytes(slot, at, out) };
        if out != expected {
            return false;
        }
    }
    true
}

fn bit(bits: &[u64], index: usize) -> bool {
    bits.get(index / WORD_BITS)
        .is_some_and(|word| word & (1 << (index % WORD_BITS)) != 0)
}

fn set_bit(bits: &mut [u64], index: usize) {
    if let Some(word) = bits.get_mut(index / WORD_BITS) {
        *word |= 1 << (index % WORD_BITS);
    }
}

/// The mask of bits `[from, to)` of one word, `0 <= from < to <= 64`.
fn mask(from: usize, to: usize) -> u64 {
    let high = if to == WORD_BITS {
        u64::MAX
    } else {
        (1u64 << to) - 1
    };
    high & !((1u64 << from) - 1)
}

/// Calls `each(word index, mask)` for the words of `[start, start + len)`.
fn words_of(start: usize, len: usize, mut each: impl FnMut(usize, u64) -> bool) -> bool {
    let end = start + len;
    let mut at = start;
    while at < end {
        let word = at / WORD_BITS;
        let to = (end - word * WORD_BITS).min(WORD_BITS);
        if each(word, mask(at % WORD_BITS, to)) {
            return true;
        }
        at = (word + 1) * WORD_BITS;
    }
    false
}

/// Whether any bit of `[start, start + len)` is set.
fn any_set(bits: &[u64], start: usize, len: usize) -> bool {
    words_of(start, len, |word, mask| {
        bits.get(word).is_some_and(|value| value & mask != 0)
    })
}

fn set_range(bits: &mut [u64], start: usize, len: usize) {
    words_of(start, len, |word, mask| {
        if let Some(value) = bits.get_mut(word) {
            *value |= mask;
        }
        false
    });
}

/// The first clear bit at or after `start` and below `limit`, or `limit`:
/// a scan of whole words.
fn first_zero(bits: &[u64], start: usize, limit: usize) -> usize {
    let mut at = start;
    while at < limit {
        let word = at / WORD_BITS;
        let value = bits.get(word).copied().unwrap_or(0) | ((1u64 << (at % WORD_BITS)) - 1);
        if value != u64::MAX {
            return (word * WORD_BITS + value.trailing_ones() as usize).min(limit);
        }
        at = (word + 1) * WORD_BITS;
    }
    limit
}

#[cfg(test)]
mod tests;
