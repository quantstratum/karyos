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
use crate::publication::{
    active_term_count, observe_block, publish_block, release_publication, take_publication,
};
use crate::receive::{ImageParams, ValidatedFrame};
use crate::term::{TERM_COUNT_LIMIT, TermCount};
use crate::term_bytes::{HeapTerms, TermBytes};

/// Bits per bitmap word.
const WORD_BITS: usize = 64;
/// Bitmap word indexes a duty cycle clears per lane, in every bitmap of a
/// set: bounded cleaning work. A set has three bitmaps (`covered`, `starts`,
/// `gap_starts`), so a duty clears up to 3072 words, 1.5 times the two
/// bitmaps' 2048, and a set is clean in as many duty cycles as before
/// (`quantstratum-docs: karyos/design/local-gap-layout.md`).
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
    /// It overlaps a local gap record still retained and no committed real
    /// frame (`quantstratum-docs: karyos/design/gaps-and-unreliable-delivery.md`,
    /// GU-7): it arrived after its range was sealed as lost, is counted and
    /// is not written. A sealed interval is never reopened. A frame
    /// overlapping an interval posted for sealing
    /// ([`ReceiveOwner::post_seal`]) is refused the same way: posting is
    /// the point of no return (conflated-network-images.md (b)).
    LateAfterSkip,
}

/// A frame the owner refused because it breaks a protocol rule, or an
/// internal failure. The image is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    /// A local gap was asked of an image without the `LOCAL_GAPS`
    /// capability.
    #[error("the image may not hold local gaps")]
    NoLocalGaps,
    /// A local gap interval that is not a positive multiple of 32 bytes
    /// starting on a 32-byte boundary inside one term.
    #[error("invalid local gap at position {position} (extent {extent}) of lane {lane:?}")]
    InvalidGap {
        /// The lane.
        lane: Lane,
        /// The interval's position.
        position: u64,
        /// The interval's extent.
        extent: u32,
    },
    /// The image's shared state is not what the owner wrote: a protocol
    /// error of another party, or a defect.
    #[error(transparent)]
    Sys(#[from] SysError),
    /// The local gap record was published, then the owner failed to move
    /// its positions (`quantstratum-docs:
    /// karyos/design/gaps-and-unreliable-delivery.md`, GU-11): the record
    /// stands and the caller never seals the interval again.
    #[error(
        "local gap at position {position} (extent {extent}) of lane {lane:?} committed, then: {error}"
    )]
    GapCommitted {
        /// The lane.
        lane: Lane,
        /// The interval's position.
        position: u64,
        /// The interval's extent.
        extent: u32,
        /// What failed after the record was published.
        error: SysError,
    },
}

/// One lane's local gap counters (GU-11). Increments are checked: one that
/// would overflow keeps its value and sets `overflowed`, which stays set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GapCounters {
    /// Local gap records sealed.
    pub gaps_sealed: u64,
    /// Bytes they cover.
    pub gap_bytes: u64,
    /// Records sealed because the unreliable reorder interval expired.
    pub reorder_expired: u64,
    /// Records sealed after a correlated `RANGE_UNAVAILABLE` under `skip`.
    pub range_unavailable_skips: u64,
    /// Late copies dropped after their range was sealed (GU-7).
    pub late_after_skip: u64,
    /// An increment did not apply because it would have overflowed.
    pub overflowed: bool,
}

impl GapCounters {
    fn add(&mut self, field: fn(&mut Self) -> &mut u64, by: u64) {
        let value = field(self);
        match value.checked_add(by) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }

    fn sealed(&mut self, extent: u32, reason: crate::local_gap::GapReason) {
        self.add(|c| &mut c.gaps_sealed, 1);
        self.add(|c| &mut c.gap_bytes, u64::from(extent));
        match reason {
            crate::local_gap::GapReason::ReorderExpired => {
                self.add(|c| &mut c.reorder_expired, 1);
            }
            crate::local_gap::GapReason::RangeUnavailable => {
                self.add(|c| &mut c.range_unavailable_skips, 1);
            }
        }
    }
}

/// A receive owner counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceiveCounter {
    /// [`ReceiveCounters::frames_committed`].
    FramesCommitted,
    /// [`ReceiveCounters::bytes_committed`].
    BytesCommitted,
    /// [`ReceiveCounters::frames_duplicate`].
    FramesDuplicate,
    /// [`ReceiveCounters::frames_late`].
    FramesLate,
    /// [`ReceiveCounters::frames_ahead`].
    FramesAhead,
    /// [`ReceiveCounters::frames_not_ready`].
    FramesNotReady,
    /// [`ReceiveCounters::frames_conflicting`].
    FramesConflicting,
    /// [`ReceiveCounters::cleaner_lag`].
    CleanerLag,
    /// [`ReceiveCounters::frames_late_after_skip`].
    FramesLateAfterSkip,
}

/// Lifetime counters of a receive owner, over all lanes. Increments are
/// checked: a counter that would overflow keeps its value, never wraps or
/// saturates, and the first such counter is reported in `overflowed`
/// (SPEC.md §14, ADR-0007). An overflow never changes what `receive`
/// returns: the frame's outcome stands.
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
    /// Frames dropped because they arrived after their range was sealed as
    /// a local gap (GU-7).
    pub frames_late_after_skip: u64,
    /// The first counter whose increment was not applied because it would
    /// have overflowed; it stays set.
    pub overflowed: Option<ReceiveCounter>,
}

impl ReceiveCounters {
    fn bump(&mut self, counter: ReceiveCounter, by: u64) {
        let value = match counter {
            ReceiveCounter::FramesCommitted => &mut self.frames_committed,
            ReceiveCounter::BytesCommitted => &mut self.bytes_committed,
            ReceiveCounter::FramesDuplicate => &mut self.frames_duplicate,
            ReceiveCounter::FramesLate => &mut self.frames_late,
            ReceiveCounter::FramesAhead => &mut self.frames_ahead,
            ReceiveCounter::FramesNotReady => &mut self.frames_not_ready,
            ReceiveCounter::FramesConflicting => &mut self.frames_conflicting,
            ReceiveCounter::CleanerLag => &mut self.cleaner_lag,
            ReceiveCounter::FramesLateAfterSkip => &mut self.frames_late_after_skip,
        };
        match value.checked_add(by) {
            Some(next) => *value = next,
            None => {
                self.overflowed.get_or_insert(counter);
            }
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
        match result {
            Ok(Received::Committed { extent, .. }) => {
                counters.bump(ReceiveCounter::FramesCommitted, 1);
                counters.bump(ReceiveCounter::BytesCommitted, u64::from(extent));
            }
            Ok(Received::Duplicate) => counters.bump(ReceiveCounter::FramesDuplicate, 1),
            Ok(Received::Late) => counters.bump(ReceiveCounter::FramesLate, 1),
            Ok(Received::Ahead) => counters.bump(ReceiveCounter::FramesAhead, 1),
            Ok(Received::NotReady) => counters.bump(ReceiveCounter::FramesNotReady, 1),
            Ok(Received::LateAfterSkip) => {
                counters.bump(ReceiveCounter::FramesLateAfterSkip, 1);
                lane.gaps.add(|c| &mut c.late_after_skip, 1);
            }
            Err(ReceiveError::Conflict { .. }) => {
                counters.bump(ReceiveCounter::FramesConflicting, 1);
            }
            Err(_) => {}
        }
        if lane.lagged {
            lane.lagged = false;
            counters.bump(ReceiveCounter::CleanerLag, 1);
        }
        result
    }

    /// Seals `[position, position + extent)` of `lane` as a local gap
    /// (`quantstratum-docs: karyos/design/local-gap-layout.md`): writes the
    /// record's header after its word 0, then publishes word 0 with one
    /// Release store, marks the interval covered and advances the rebuild
    /// position across it. The interval must lie in one term of the window
    /// and overlap no committed frame; this primitive never narrows it, so
    /// the caller rechecks its extent maps first (the skip policy's
    /// business, not decided here).
    ///
    /// # Errors
    ///
    /// [`ReceiveError::NoLocalGaps`] for an image without the capability,
    /// [`ReceiveError::InvalidGap`] for an interval outside one term or not
    /// 32-aligned, [`ReceiveError::Conflict`] for an interval overlapping a
    /// committed frame, [`ReceiveError::Foreign`] for a lane the image does
    /// not have, [`ReceiveError::Sys`] for a corrupt shared state. No record
    /// is written and no position moves in every error case and for `Late`,
    /// `Ahead` and `NotReady`; as for `receive`, a `NotReady` attempt may
    /// already have activated terms up to the interval's (`write_loan`).
    pub fn seal_gap(
        &mut self,
        lane: Lane,
        position: u64,
        extent: u32,
        reason: crate::local_gap::GapReason,
    ) -> Result<Received, ReceiveError> {
        let owner = self
            .lanes
            .get_mut(usize::from(lane.get()))
            .ok_or(ReceiveError::Foreign)?;
        let result = owner.seal_gap(lane, position, extent, reason);
        if owner.lagged {
            owner.lagged = false;
            self.counters.bump(ReceiveCounter::CleanerLag, 1);
        }
        result
    }

    /// Posts `[position, position + extent)` of `lane` for sealing
    /// (`quantstratum-docs: karyos/design/conflated-network-images.md`,
    /// (b)): from now on a frame overlapping it is not committed and reads
    /// [`Received::LateAfterSkip`], so the interval is sealed whole once its
    /// seal gate permits, and a value in it is never both marked stale and
    /// delivered. A lane holds one posted interval; a new post replaces it,
    /// and the seal of an interval overlapping it clears it.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::Foreign`] for a lane the image does not have,
    /// [`ReceiveError::InvalidGap`] for an empty interval or one past the
    /// position range. Nothing is posted on error.
    pub fn post_seal(
        &mut self,
        lane: Lane,
        position: u64,
        extent: u32,
    ) -> Result<(), ReceiveError> {
        let owner = self
            .lanes
            .get_mut(usize::from(lane.get()))
            .ok_or(ReceiveError::Foreign)?;
        let invalid = ReceiveError::InvalidGap {
            lane,
            position,
            extent,
        };
        let end = position
            .checked_add(u64::from(extent))
            .filter(|_| extent > 0)
            .ok_or(invalid)?;
        owner.posted = Some((position, end));
        Ok(())
    }

    /// The interval of `lane` posted for sealing and not sealed yet, as
    /// `[start, end)`; `None` for a lane without one or one the image does
    /// not have.
    #[must_use]
    pub fn posted(&self, lane: Lane) -> Option<(u64, u64)> {
        self.lanes.get(usize::from(lane.get()))?.posted
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

    /// What `lane` reports as consumed (SPEC §4): its published head (the
    /// rebuild position as last stored, which the fence pair of
    /// [`LogBuffer::required_position`] orders), lowered to the least
    /// required subscriber's position when the image has one, so a stopped
    /// required subscriber holds a reliable sender. Optional subscribers
    /// bound nothing. The head, not the owner's local rebuild position: a
    /// rebuild move whose store did not happen (an error path) is never
    /// reported.
    #[must_use]
    pub fn consumption(&self, lane: Lane) -> Option<u64> {
        let owner = self.lanes.get(usize::from(lane.get()))?;
        // Only this thread stores the image's head.
        let head = owner.buffer.reserved_head().load(Ordering::Relaxed);
        Some(
            owner
                .buffer
                .required_position()
                .map_or(head, |required| required.min(head)),
        )
    }

    /// Test hook (feature `test-hooks`): stores `position` as `lane`'s
    /// published head, as a rebuild move whose store raced or failed would
    /// leave it, so dependent crates can check what consumption reports.
    /// Returns whether the lane exists.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn set_published_head(&self, lane: Lane, position: u64) -> bool {
        let Some(owner) = self.lanes.get(usize::from(lane.get())) else {
            return false;
        };
        owner
            .buffer
            .reserved_head()
            .store(position, Ordering::Release);
        true
    }

    /// The covered end of `lane`: the highest end of any covered extent,
    /// a real frame or a local gap, which loss detection compares the
    /// rebuild position against.
    #[must_use]
    pub fn high_water(&self, lane: Lane) -> Option<u64> {
        self.lanes.get(usize::from(lane.get())).map(|l| l.high)
    }

    /// The first hole of `lane` above its resolved prefix, as `(position,
    /// extent)`: up to the start of the next covered extent, within one
    /// term (GU-4). `None` while nothing above the prefix is covered.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::Foreign`] for a lane the image does not have,
    /// [`ReceiveError::Sys`] for a corrupt owner state.
    pub fn first_hole(&self, lane: Lane) -> Result<Option<(u64, u32)>, ReceiveError> {
        let owner = self
            .lanes
            .get(usize::from(lane.get()))
            .ok_or(ReceiveError::Foreign)?;
        Ok(owner.first_hole()?)
    }

    /// The tail hole of `lane` a sender's heartbeat at `mark` reveals, as
    /// `(position, extent)`: from the resolved prefix to `mark`, within the
    /// prefix's term, when nothing above the prefix is covered
    /// (`quantstratum-docs: karyos/SPEC.md` §6, G1). `None` when the prefix
    /// reaches `mark` or a covered extent lies above it
    /// ([`ReceiveOwner::first_hole`] names that hole). A reliable image
    /// NAKs it, an unreliable one seals it at its deadline.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::Foreign`] for a lane the image does not have,
    /// [`ReceiveError::Sys`] for a position outside the incarnation.
    pub fn heartbeat_tail(
        &self,
        lane: Lane,
        mark: u64,
    ) -> Result<Option<(u64, u32)>, ReceiveError> {
        let owner = self
            .lanes
            .get(usize::from(lane.get()))
            .ok_or(ReceiveError::Foreign)?;
        Ok(owner.heartbeat_tail(mark)?)
    }

    /// Whether `position` of `lane` lies in the window `{r, r + 1}` of
    /// terms, `r` the term of the resolved prefix (GU-6: a position beyond
    /// it cannot be resumed). A position outside the incarnation, which a
    /// peer may report, is outside the window.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::Foreign`] for a lane the image does not have.
    pub fn within_window(&self, lane: Lane, position: u64) -> Result<bool, ReceiveError> {
        let owner = self
            .lanes
            .get(usize::from(lane.get()))
            .ok_or(ReceiveError::Foreign)?;
        let (r, _) = owner.split_end(owner.rebuild)?;
        let Ok((count, _)) = owner.buffer.split(position) else {
            return Ok(false);
        };
        Ok(count.get() <= r.get().saturating_add(1))
    }

    /// The received high-water mark of `lane` (`quantstratum-docs:
    /// karyos/design/gaps-and-unreliable-delivery.md`, GU-1): the highest
    /// end of a real committed frame. A sealed gap never moves it.
    #[must_use]
    pub fn received_high_water(&self, lane: Lane) -> Option<u64> {
        self.lanes.get(usize::from(lane.get())).map(|l| l.received)
    }

    /// Makes the next advance of `lane`'s resolved prefix fail with
    /// `error`.
    #[cfg(test)]
    pub(crate) fn fail_next_advance(&mut self, lane: Lane, error: SysError) {
        if let Some(owner) = self.lanes.get_mut(usize::from(lane.get())) {
            owner.fail_advance = Some(error);
        }
    }

    /// The local gap counters of `lane` (GU-11).
    #[must_use]
    pub fn gap_counters(&self, lane: Lane) -> Option<GapCounters> {
        self.lanes.get(usize::from(lane.get())).map(|l| l.gaps)
    }

    /// The first loss of `lane` (GU-1): the start of its lowest local gap,
    /// `None` while none was sealed. The contiguous received prefix is the
    /// rebuild position while it is `None`, and this position afterwards.
    #[must_use]
    pub fn first_loss(&self, lane: Lane) -> Option<Option<u64>> {
        self.lanes
            .get(usize::from(lane.get()))
            .map(|l| l.first_loss)
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
            // The owner is the image's only publication: its release, after
            // its last commit, lets the conductor position a seal there,
            // as a local publication's drop does (publication-seal.md).
            release_publication(lane.buffer.exclusive_released());
        }
    }
}

/// The extent record of one term incarnation.
#[derive(Debug)]
struct Set {
    term: Option<TermCount>,
    covered: Vec<u64>,
    starts: Vec<u64>,
    /// The starts of local gap records: kept apart from `starts`, which
    /// marks real frames only, so a late copy can tell a real overlap from
    /// one with a local gap alone.
    gap_starts: Vec<u64>,
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
    /// The resolved prefix (GU-1): advances across real frames and local
    /// gap records.
    rebuild: u64,
    /// The covered end: the highest end of any covered extent, real or gap.
    high: u64,
    /// The received high-water mark: the highest end of a real committed
    /// frame; a gap record never moves it (GU-1).
    received: u64,
    /// The start of the lane's lowest local gap, never cleared within the
    /// incarnation (GU-1).
    first_loss: Option<u64>,
    /// Local gap counters (GU-11).
    gaps: GapCounters,
    sets: [Set; SETS],
    /// Standing write loans, by term parity: the term and its slot.
    loans: [Option<(TermCount, u8)>; 2],
    /// Set when the last receive found the next term unprepared.
    lagged: bool,
    /// The interval `[start, end)` posted for sealing and not sealed yet:
    /// no frame overlapping it is committed.
    posted: Option<(u64, u64)>,
    /// Returned by the next `advance`: tests reproduce a failure after a
    /// gap record was published.
    #[cfg(test)]
    fail_advance: Option<SysError>,
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
            gap_starts: vec![0; words],
            dirty: false,
            cursor: 0,
        };
        Self {
            buffer,
            units,
            join,
            rebuild: join,
            high: join,
            received: join,
            first_loss: None,
            gaps: GapCounters::default(),
            sets: [set(), set(), set(), set()],
            loans: [None, None],
            lagged: false,
            posted: None,
            #[cfg(test)]
            fail_advance: None,
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
            let starts = bit(&self.set(index)?.starts, unit);
            // Whether the term is still held decides first: a copy of a
            // reclaimed term is late whatever it would have been.
            return match self.compare_trailing(count, frame, starts)? {
                Some(true) => Ok(Received::Duplicate),
                // Every unit of the trailing term is covered: a copy that
                // meets no real frame lies in gaps alone (GU-7).
                Some(false) if !overlaps_real(self.set(index)?, unit, units) => {
                    Ok(Received::LateAfterSkip)
                }
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
            // A real overlap is classified first, as a conflict; an overlap
            // with retained gap records alone is late after the skip (GU-7).
            return if overlaps_real(self.set(index)?, unit, units) {
                Err(conflict())
            } else {
                Ok(Received::LateAfterSkip)
            };
        }
        // Posting is the point of no return: the posted interval is sealed
        // whole, so nothing lands in it.
        let end = start
            .checked_add(u64::from(frame.extent()))
            .ok_or_else(conflict)?;
        if self
            .posted
            .is_some_and(|(from, to)| start < to && from < end)
        {
            return Ok(Received::LateAfterSkip);
        }
        let Some(slot) = self.write_loan(count)? else {
            return Ok(Received::NotReady);
        };
        write(&buffer, slot, frame);
        let set = self.set_mut(index)?;
        set_bit(&mut set.starts, unit);
        set_range(&mut set.covered, unit, units);
        self.high = self.high.max(end);
        self.received = self.received.max(end);
        if start == self.rebuild {
            self.advance()?;
        }
        Ok(Received::Committed {
            position: start,
            extent: frame.extent(),
        })
    }

    fn seal_gap(
        &mut self,
        lane: Lane,
        position: u64,
        extent: u32,
        reason: crate::local_gap::GapReason,
    ) -> Result<Received, ReceiveError> {
        use crate::local_gap::{GapSite, gap_body, gap_word0};
        let buffer = Arc::clone(&self.buffer);
        if !buffer.local_gaps() {
            return Err(ReceiveError::NoLocalGaps);
        }
        let invalid = ReceiveError::InvalidGap {
            lane,
            position,
            extent,
        };
        let (count, offset) = buffer.split(position)?;
        let word0 = gap_word0(extent, lane).ok_or(invalid)?;
        if !offset.is_multiple_of(FRAME_ALIGNMENT)
            || offset
                .checked_add(extent)
                .is_none_or(|end| end > buffer.term_length)
        {
            return Err(invalid);
        }
        if position < self.join {
            return Ok(Received::Late);
        }
        let (r, _) = self.split_end(self.rebuild)?;
        let (c, rr) = (count.get(), r.get());
        if c > rr.saturating_add(1) {
            return Ok(Received::Ahead);
        }
        // The trailing term is covered from the join point up: nothing is
        // left to seal there.
        if c < rr {
            return Ok(Received::Late);
        }
        let index = match self.set_of(count) {
            Some(index) => index,
            None => match self.assign_set(count) {
                Some(index) => index,
                None => return Ok(Received::NotReady),
            },
        };
        let (Ok(unit), Ok(units)) = (
            usize::try_from(offset / FRAME_ALIGNMENT),
            usize::try_from(extent / FRAME_ALIGNMENT),
        ) else {
            return Err(invalid);
        };
        // Both fit: the interval was checked to end inside the term.
        let (Some(header), Some(end)) = (
            offset.checked_add(8),
            position.checked_add(u64::from(extent)),
        ) else {
            return Err(invalid);
        };
        if any_set(&self.set(index)?.covered, unit, units) {
            return Err(ReceiveError::Conflict {
                lane,
                position,
                extent,
            });
        }
        let Some(slot) = self.write_loan(count)? else {
            return Ok(Received::NotReady);
        };
        let site = GapSite {
            term_offset: offset,
            term_id: buffer
                .initial_term_id
                .advanced_by(count)
                .get()
                .cast_signed(),
            session_id: buffer.config.session_id,
            stream_id: buffer.config.stream_id,
        };
        // Borrowed before the publication: nothing after it may fail before
        // the record is in the owner's maps.
        let set = self.set_mut(index)?;
        // SAFETY: the owner holds the write loan on `slot`'s current term;
        // the 24 bytes start 8 bytes into the record, a multiple of 8, and
        // lie inside its extent (at least 32), which the owner's record
        // shows uncovered, so they hold no word 0 of this term and were
        // never written in this incarnation; no reader reaches them before
        // the Release publication below.
        unsafe {
            buffer
                .regions
                .write_bytes(slot, header, &gap_body(site, reason))
        };
        // SAFETY: write loan held; `offset` is the start of this record.
        let first = unsafe { buffer.regions.word0(slot, offset) };
        publish_block(first, word0);
        set_bit(&mut set.gap_starts, unit);
        set_range(&mut set.covered, unit, units);
        self.high = self.high.max(end);
        self.first_loss = Some(
            self.first_loss
                .map_or(position, |first| first.min(position)),
        );
        self.gaps.sealed(extent, reason);
        // A seal from the posted interval's start on releases what it
        // covers; what lies above stays posted.
        if let Some((from, to)) = self.posted
            && position <= from
            && from < end
        {
            self.posted = (end < to).then_some((end, to));
        }
        // The record is published: a failure from here on is reported as
        // committed, so the caller never seals the interval again.
        if position == self.rebuild
            && let Err(error) = self.advance()
        {
            return Err(ReceiveError::GapCommitted {
                lane,
                position,
                extent,
                error,
            });
        }
        Ok(Received::Committed { position, extent })
    }

    /// The first hole above the resolved prefix: from it to the start of
    /// the next covered extent, within its term (`quantstratum-docs:
    /// karyos/design/gaps-and-unreliable-delivery.md`, GU-4). `None` while
    /// nothing above the prefix is covered.
    fn first_hole(&self) -> Result<Option<(u64, u32)>, SysError> {
        if self.rebuild >= self.high {
            return Ok(None);
        }
        let (count, offset) = self.buffer.split(self.rebuild)?;
        let term_length = self.buffer.term_length;
        let unit = (offset / FRAME_ALIGNMENT) as usize;
        let end = match self.set_of(count) {
            // A term with nothing received is a hole to its end.
            None => self.units,
            Some(index) => first_one(&self.set(index)?.covered, unit, self.units),
        };
        let end_offset = u32::try_from(end)
            .ok()
            .and_then(|end| end.checked_mul(FRAME_ALIGNMENT))
            .filter(|end| *end <= term_length && *end > offset)
            .ok_or(SysError::CorruptTerm {
                offset,
                reason: "hole extent",
            })?;
        Ok(Some((self.rebuild, end_offset - offset)))
    }

    /// The tail hole a heartbeat at `mark` reveals: from the resolved
    /// prefix to `mark`, within the prefix's term, while nothing above the
    /// prefix is covered. The prefix starts at the join point and never
    /// moves below it, so neither does the hole.
    fn heartbeat_tail(&self, mark: u64) -> Result<Option<(u64, u32)>, SysError> {
        if self.high > self.rebuild || mark <= self.rebuild {
            return Ok(None);
        }
        let (_, offset) = self.buffer.split(self.rebuild)?;
        // Both fit: `offset` is inside the term, so the room is at most
        // `term_length`.
        let room = self.buffer.term_length - offset;
        let extent = u32::try_from(mark - self.rebuild).map_or(room, |extent| extent.min(room));
        Ok(Some((self.rebuild, extent)))
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

    /// Compares a copy for the trailing term under a transient read loan:
    /// equal only if a committed frame starts where it does (`starts`) and
    /// matches it. `None` when the term is no longer held.
    fn compare_trailing(
        &self,
        count: TermCount,
        frame: &ValidatedFrame<'_>,
        starts: bool,
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
        let same = starts && equal(buffer, slot, frame);
        release_loan(&cell.loan);
        Ok(Some(same))
    }

    /// Advances the rebuild position over every covered unit from it,
    /// publishes it, and moves the window when it crosses a term end.
    fn advance(&mut self) -> Result<(), SysError> {
        #[cfg(test)]
        if let Some(error) = self.fail_advance.take() {
            return Err(error);
        }
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
            for bits in [&mut set.covered, &mut set.starts, &mut set.gap_starts] {
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

/// Whether `[unit, unit + units)` meets a committed real frame of `set`. A
/// covered unit belongs to the record that starts at the nearest start bit
/// at or below it, a real frame (`starts`) or a local gap (`gap_starts`):
/// the range meets a real frame if the record covering its first unit is
/// one, or if a real frame starts inside it. Both searches are word-wise.
fn overlaps_real(set: &Set, unit: usize, units: usize) -> bool {
    if bit(&set.covered, unit) {
        // The record covering `unit`: the highest start at or below it,
        // inside the covered run (above its highest uncovered unit).
        let start = last_one(unit, |word| {
            word_at(&set.starts, word) | word_at(&set.gap_starts, word)
        });
        let uncovered = last_one(unit, |word| !word_at(&set.covered, word));
        match start {
            Some(start) if uncovered.is_none_or(|below| below < start) => {
                if bit(&set.starts, start) {
                    return true;
                }
            }
            // A covered unit with no start below it in its run: a broken
            // map; treat it as real, the conservative answer.
            _ => return true,
        }
    }
    // No start lies past the map: stop the search at its end.
    let Some(map_end) = set.starts.len().checked_mul(WORD_BITS) else {
        // A map too large to address: the conservative answer.
        return true;
    };
    let end = unit
        .checked_add(units)
        .map_or(map_end, |end| end.min(map_end));
    // A range starting past the map meets no start.
    end.checked_sub(unit)
        .is_some_and(|len| any_set(&set.starts, unit, len))
}

/// Word `index` of `bits`; zero past its end.
fn word_at(bits: &[u64], index: usize) -> u64 {
    bits.get(index).copied().unwrap_or(0)
}

/// The highest set bit at or below `at` of the bitmap whose words
/// `word(index)` gives, scanning down whole words.
fn last_one(at: usize, word: impl Fn(usize) -> u64) -> Option<usize> {
    let mut index = at / WORD_BITS;
    let mut value = word(index) & mask(0, at % WORD_BITS + 1);
    loop {
        if value != 0 {
            // `value` is non-zero: `ilog2` is its highest set bit, below 64.
            let bit = usize::try_from(value.ilog2()).ok()?;
            return index.checked_mul(WORD_BITS)?.checked_add(bit);
        }
        index = index.checked_sub(1)?;
        value = word(index);
    }
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

/// The first set bit at or after `start`, or `limit`.
fn first_one(bits: &[u64], start: usize, limit: usize) -> usize {
    let mut at = start;
    while at < limit {
        let word = at / WORD_BITS;
        let value = bits.get(word).copied().unwrap_or(0) & !((1u64 << (at % WORD_BITS)) - 1);
        if value != 0 {
            return (word * WORD_BITS + value.trailing_zeros() as usize).min(limit);
        }
        at = (word + 1) * WORD_BITS;
    }
    limit
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
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod heap_tests {
    use super::*;

    type Terms = HeapTerms;

    fn new_image(config: crate::log_buffer::LogBufferConfig) -> Result<LogBuffer<Terms>, SysError> {
        LogBuffer::new(config)
    }

    include!("receive_owner/tests.rs");
    include!("receive_owner/frame_reader_tests.rs");
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod shared_tests {
    use super::*;
    use crate::term_bytes::SharedTerms;

    type Terms = SharedTerms;

    fn new_image(config: crate::log_buffer::LogBufferConfig) -> Result<LogBuffer<Terms>, SysError> {
        LogBuffer::new_shared(config)
    }

    include!("receive_owner/tests.rs");
    include!("receive_owner/frame_reader_tests.rs");
}
