// SPDX-License-Identifier: Apache-2.0

//! The commit-deadline abort of concurrent publication
//! (`quantstratum-docs: karyos/design/concurrent-deadline.md`, batch c2): the frontier, the
//! look-ahead, one timer per stuck point and the span walk with aborting
//! markers, under fixed per-call budgets.
//!
//! Every persisted continuation keeps term counts, slots and offsets only,
//! never a reference, and revalidates the slot's descriptor before any word
//! access. The conductor holds no loan: a term is inspectable while its slot
//! holds it `ACTIVE` or `RECLAIMING`, and only this conductor moves a slot
//! on to `CLEANING`, dropping this state for the slot first
//! ([`ConcurrentDeadlines::forget_slot`]).

use super::{DeadlineReport, LayoutError, LogBuffer, Lookup, SysError, TermBytes, corrupt};
use crate::frame::{FRAME_ALIGNMENT, Flags, FrameType, PROTOCOL_VERSION, Word0};
use crate::publication::{
    ABORTING_MARKER, abort_block, end_span, load_interior, observe_block, reserved_extent,
    take_span_word,
};
use crate::sizing::align_frame;
use crate::slot::{Descriptor, SlotState};
use crate::term::TermCount;
use core::sync::atomic::Ordering;

/// Compare-exchanges of the span walk per call (`W`, failed ones included).
pub(super) const WALK_BUDGET: u32 = 16;
/// Word reads of the frontier scan and look-ahead per call (`S`).
pub(super) const SCAN_BUDGET: u32 = 64;

/// A position as a term count and an offset in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Point {
    count: TermCount,
    offset: u32,
}

/// A marked block being timed.
#[derive(Debug, Clone, Copy)]
struct Marked {
    count: TermCount,
    slot: u8,
    offset: u32,
    reserved: Word0,
    extent: u32,
    first_seen: u64,
}

/// The zero span at the frontier: timed until it expires, then walked.
#[derive(Debug, Clone, Copy)]
struct Span {
    count: TermCount,
    slot: u8,
    start: u32,
    /// The admitted head of the term at the first observation, kept for
    /// the whole walk.
    bound: u32,
    first_seen: u64,
    /// Once the walk owns `start`: the next boundary to take.
    next: Option<u32>,
}

/// A terminal fragmented `DATA` block whose fragments are being walked.
#[derive(Debug, Clone, Copy)]
struct Fragments {
    count: TermCount,
    slot: u8,
    start: u32,
    /// Its first word 0, re-loaded and compared on resumption.
    first: u64,
    next: u32,
}

/// What one scanned block is.
enum Scanned {
    Zero,
    Marker,
    Reserved {
        reserved: Word0,
        extent: u32,
    },
    Terminal {
        extent: u32,
    },
    /// A fragment walk ran out of budget.
    Partial,
}

/// Where a scan stopped.
enum Stop {
    /// Out of budget, or at the admitted head.
    Done,
    /// At a marked block at the frontier: the look-ahead continues.
    Marked { after: Point },
}

/// The conductor's concurrent deadline state.
#[derive(Debug)]
pub(super) struct ConcurrentDeadlines {
    frontier: Point,
    lookahead: Point,
    fragments: Option<Fragments>,
    /// Marked blocks, `P + S` entries reserved at issue: step 1 leaves at
    /// most `P` (each confirmed reserved at its read, at most one per
    /// writer, whose later block is reserved only after its earlier one
    /// completed) and one scan adds at most `S`, one per read.
    marked: Vec<Marked>,
    limit: usize,
    span: Option<Span>,
    walk_budget: u32,
    scan_budget: u32,
}

/// The clock, read at most once and only when needed.
struct Now<'a> {
    clock: &'a mut dyn FnMut() -> u64,
    value: Option<u64>,
}

impl Now<'_> {
    fn get(&mut self) -> u64 {
        *self.value.get_or_insert_with(|| (self.clock)())
    }
}

impl ConcurrentDeadlines {
    pub(super) fn new(publishers: usize) -> Self {
        Self {
            frontier: Point {
                count: TermCount::ZERO,
                offset: 0,
            },
            lookahead: Point {
                count: TermCount::ZERO,
                offset: 0,
            },
            fragments: None,
            marked: Vec::with_capacity(publishers + SCAN_BUDGET as usize),
            limit: publishers + SCAN_BUDGET as usize,
            span: None,
            walk_budget: WALK_BUDGET,
            scan_budget: SCAN_BUDGET,
        }
    }

    /// Test hook: smaller budgets.
    #[cfg(test)]
    pub(super) fn set_budgets(&mut self, walk: u32, scan: u32) {
        assert!(walk >= 1 && (2..=SCAN_BUDGET).contains(&scan));
        self.walk_budget = walk;
        self.scan_budget = scan;
    }

    /// Drops every observation and walk of `slot`'s term: the conductor is
    /// about to move the slot to `CLEANING`.
    pub(super) fn forget_slot(&mut self, slot: u8) {
        self.marked.retain(|marked| marked.slot != slot);
        if self.span.is_some_and(|span| span.slot == slot) {
            self.span = None;
        }
        if self.fragments.is_some_and(|walk| walk.slot == slot) {
            self.fragments = None;
        }
    }

    /// One service call: serve expired marked blocks, advance the span
    /// walk, then scan (`quantstratum-docs: karyos/design/concurrent-deadline.md`, Work per
    /// call and bounds). Effects are counted in `report` as they complete.
    pub(super) fn service<T: TermBytes>(
        &mut self,
        buffer: &LogBuffer<T>,
        clock: &mut dyn FnMut() -> u64,
        report: &mut DeadlineReport,
        after_marked: &mut dyn FnMut(),
    ) -> Result<(), SysError> {
        // The clock of points already observed below the admitted head.
        let mut now = Now { clock, value: None };
        self.serve_marked(buffer, &mut now, report)?;
        after_marked();
        self.walk(buffer, &mut now, report)?;
        // New observations are dated by a clock read after the head
        // snapshot of the scan.
        let mut scan_now = Now {
            clock: now.clock,
            value: None,
        };
        self.scan(buffer, &mut scan_now)
    }

    /// Whether an observation or a span walk remains.
    pub(super) fn waiting(&self) -> bool {
        !self.marked.is_empty() || self.span.is_some()
    }

    /// Step 1: every marked observation, at most one compare-exchange each.
    fn serve_marked<T: TermBytes>(
        &mut self,
        buffer: &LogBuffer<T>,
        now: &mut Now<'_>,
        report: &mut DeadlineReport,
    ) -> Result<(), SysError> {
        let deadline = buffer.config.claim_deadline;
        let mut index = 0;
        while let Some(marked) = self.marked.get_mut(index) {
            if !holds(buffer, marked.slot, marked.count)? {
                self.marked.swap_remove(index);
                continue;
            }
            // SAFETY: see `word`; `offset` is the block's first frame start.
            let word = unsafe { word(buffer, marked.slot, marked.offset) };
            let found = observe_block(word);
            if found != marked.reserved.pack() {
                if found as u32 as i32 <= 0 {
                    return Err(corrupt(marked.offset, "marked block changed"));
                }
                // Committed or aborted: no longer stuck; resolved if it
                // had expired.
                let now = now.get();
                if marked
                    .first_seen
                    .checked_add(deadline)
                    .is_some_and(|expiry| now >= expiry)
                {
                    bump(&mut report.resolved)?;
                }
                self.marked.swap_remove(index);
                continue;
            }
            let expired = timer(&mut marked.first_seen, now.get(), deadline, report)?;
            if !expired {
                index += 1;
                continue;
            }
            let extent = marked.extent;
            if abort_block(word, marked.reserved, aborted(buffer, extent)) {
                count_abort(report, extent)?;
            } else {
                bump(&mut report.resolved)?;
            }
            self.marked.swap_remove(index);
        }
        Ok(())
    }

    /// Step 2: the zero span at the frontier, at most `W` compare-exchanges.
    fn walk<T: TermBytes>(
        &mut self,
        buffer: &LogBuffer<T>,
        now: &mut Now<'_>,
        report: &mut DeadlineReport,
    ) -> Result<(), SysError> {
        let Some(mut span) = self.span else {
            return Ok(());
        };
        if !holds(buffer, span.slot, span.count)? {
            self.span = None;
            return Ok(());
        }
        let mut budget = self.walk_budget;
        if span.next.is_none() {
            let expired = timer(
                &mut span.first_seen,
                now.get(),
                buffer.config.claim_deadline,
                report,
            )?;
            if !expired {
                self.span = Some(span);
                return Ok(());
            }
            budget -= 1;
            // SAFETY: see `word`; `start` is a frame start (the frontier).
            let first = unsafe { word(buffer, span.slot, span.start) };
            match take_span_word(first) {
                Ok(()) => span.next = Some(span.start + FRAME_ALIGNMENT),
                Err(found) => {
                    // The writer marked or committed first: no span, nothing
                    // stored; an expired mark is served now with the span's
                    // first observation.
                    self.span = None;
                    return self.serve_lost_start(buffer, span, found, report);
                }
            }
        }
        let mut end = None;
        while let Some(next) = span.next {
            if next >= span.bound {
                end = Some(span.bound);
                break;
            }
            if budget == 0 {
                break;
            }
            budget -= 1;
            // SAFETY: see `word`; a 32-byte boundary of the owned span
            // below its frozen bound.
            match take_span_word(unsafe { word(buffer, span.slot, next) }) {
                Ok(()) => span.next = Some(next + FRAME_ALIGNMENT),
                Err(_) => {
                    end = Some(next);
                    break;
                }
            }
        }
        match end {
            Some(end) => {
                let extent = end - span.start;
                // SAFETY: as above; the span's start holds the marker this
                // walk placed.
                end_span(
                    unsafe { word(buffer, span.slot, span.start) },
                    aborted(buffer, extent),
                );
                count_abort(report, extent)?;
                self.span = None;
            }
            None => self.span = Some(span),
        }
        Ok(())
    }

    /// The span's first compare-exchange lost to `found`: a mark served as
    /// an expired marked block, or a terminal word already resolved.
    fn serve_lost_start<T: TermBytes>(
        &mut self,
        buffer: &LogBuffer<T>,
        span: Span,
        found: u64,
        report: &mut DeadlineReport,
    ) -> Result<(), SysError> {
        if found as u32 as i32 > 0 {
            bump(&mut report.resolved)?;
            return Ok(());
        }
        let extent = reserved_extent(
            found,
            span.start,
            buffer.term_length,
            buffer.config.max_reserved,
            buffer.config.lane,
        )
        .ok_or_else(|| corrupt(span.start, "reserved word"))?;
        let reserved = Word0::unpack(found).map_err(|_| corrupt(span.start, "reserved word"))?;
        // SAFETY: see `word`; the span's start, a frame start.
        let first = unsafe { word(buffer, span.slot, span.start) };
        if abort_block(first, reserved, aborted(buffer, extent)) {
            count_abort(report, extent)?;
        } else {
            bump(&mut report.resolved)?;
        }
        Ok(())
    }

    /// Step 3: the frontier, then the look-ahead, at most `S` word reads.
    fn scan<T: TermBytes>(
        &mut self,
        buffer: &LogBuffer<T>,
        now: &mut Now<'_>,
    ) -> Result<(), SysError> {
        let head = buffer.conductor_head()?;
        // The look-ahead passed only terminal blocks, which stay terminal,
        // and marked ones, each observed and still reserved at step 1 of
        // this call unless dropped there as terminal: the first block
        // between the frontier and the look-ahead that may be
        // non-terminal is the lowest remaining observation. The frontier
        // moves there without reading the region again.
        if self.frontier < self.lookahead {
            let (frontier, lookahead) = (self.frontier, self.lookahead);
            let next = self
                .marked
                .iter()
                .map(|marked| Point {
                    count: marked.count,
                    offset: marked.offset,
                })
                .filter(|point| frontier <= *point && *point < lookahead)
                .min()
                .unwrap_or(lookahead);
            self.frontier = next;
            if next.count != frontier.count {
                self.drop_before(next);
            }
        }
        let mut reads = 0;
        let stop = self.scan_frontier(buffer, head, now, &mut reads)?;
        if self.lookahead < self.frontier {
            self.lookahead = self.frontier;
        }
        if let Stop::Marked { after } = stop {
            if self.lookahead < after {
                self.lookahead = after;
            }
            self.scan_lookahead(buffer, head, now, &mut reads)?;
        }
        Ok(())
    }

    fn scan_frontier<T: TermBytes>(
        &mut self,
        buffer: &LogBuffer<T>,
        head: u64,
        now: &mut Now<'_>,
        reads: &mut u32,
    ) -> Result<Stop, SysError> {
        loop {
            let Some((point, slot)) = settle(buffer, self.frontier)? else {
                return Ok(Stop::Done);
            };
            if point != self.frontier {
                self.frontier = point;
                self.drop_before(point);
            }
            let bound = bound(buffer, head, point.count);
            if point.offset >= bound || *reads >= self.scan_budget {
                return Ok(Stop::Done);
            }
            // A marked block step 1 of this call just found still reserved:
            // its observation is the evidence, so the scan spends no read
            // on it and the look-ahead keeps the whole budget.
            if let Some(marked) = self
                .marked
                .iter()
                .find(|marked| (marked.count, marked.offset) == (point.count, point.offset))
            {
                return Ok(Stop::Marked {
                    after: Point {
                        count: point.count,
                        offset: point.offset + marked.extent,
                    },
                });
            }
            let at_span = self
                .span
                .filter(|span| span.count == point.count && span.start == point.offset);
            match self.scan_block(buffer, point, slot, reads)? {
                Scanned::Zero => {
                    if at_span.is_none() {
                        // A new zero span: only the frontier's is timed.
                        self.span = Some(Span {
                            count: point.count,
                            slot,
                            start: point.offset,
                            bound,
                            first_seen: now.get(),
                            next: None,
                        });
                    }
                    return Ok(Stop::Done);
                }
                Scanned::Marker => {
                    if at_span.is_some_and(|span| span.next.is_some()) {
                        return Ok(Stop::Done);
                    }
                    return Err(corrupt(point.offset, "aborting marker"));
                }
                Scanned::Reserved { reserved, extent } => {
                    // A zero span that became a mark keeps its timer.
                    let first_seen = match at_span {
                        Some(span) => {
                            self.span = None;
                            Some(span.first_seen)
                        }
                        None => None,
                    };
                    self.observe(point, slot, reserved, extent, first_seen, now);
                    return Ok(Stop::Marked {
                        after: Point {
                            count: point.count,
                            offset: point.offset + extent,
                        },
                    });
                }
                Scanned::Terminal { extent } => {
                    if at_span.is_some() {
                        self.span = None;
                    }
                    self.marked.retain(|marked| {
                        (marked.count, marked.offset) != (point.count, point.offset)
                    });
                    self.frontier.offset += extent;
                }
                Scanned::Partial => return Ok(Stop::Done),
            }
        }
    }

    fn scan_lookahead<T: TermBytes>(
        &mut self,
        buffer: &LogBuffer<T>,
        head: u64,
        now: &mut Now<'_>,
        reads: &mut u32,
    ) -> Result<(), SysError> {
        loop {
            let Some((point, slot)) = settle(buffer, self.lookahead)? else {
                return Ok(());
            };
            self.lookahead = point;
            if point.offset >= bound(buffer, head, point.count) || *reads >= self.scan_budget {
                return Ok(());
            }
            match self.scan_block(buffer, point, slot, reads)? {
                // Its extent is unknown: the look-ahead waits here.
                Scanned::Zero | Scanned::Partial => return Ok(()),
                Scanned::Marker => return Err(corrupt(point.offset, "aborting marker")),
                Scanned::Reserved { reserved, extent } => {
                    if !self.observe(point, slot, reserved, extent, None, now) {
                        return Ok(());
                    }
                    self.lookahead.offset += extent;
                }
                Scanned::Terminal { extent } => self.lookahead.offset += extent,
            }
        }
    }

    /// Keeps a marked block's observation, adding it with `first_seen` (or
    /// the scan's clock) if new. `false` when no entry is free, which a
    /// buffer with at most `P` outstanding blocks never reaches.
    fn observe(
        &mut self,
        point: Point,
        slot: u8,
        reserved: Word0,
        extent: u32,
        first_seen: Option<u64>,
        now: &mut Now<'_>,
    ) -> bool {
        if let Some(marked) = self
            .marked
            .iter_mut()
            .find(|marked| (marked.count, marked.offset) == (point.count, point.offset))
        {
            if let Some(first_seen) = first_seen {
                marked.first_seen = first_seen;
            }
            return true;
        }
        if self.marked.len() >= self.limit {
            return false;
        }
        let first_seen = first_seen.unwrap_or_else(|| now.get());
        self.marked.push(Marked {
            count: point.count,
            slot,
            offset: point.offset,
            reserved,
            extent,
            first_seen,
        });
        true
    }

    /// Drops state of terms before `point`'s, which the frontier passed.
    fn drop_before(&mut self, point: Point) {
        self.marked.retain(|marked| marked.count >= point.count);
        if self.span.is_some_and(|span| span.count < point.count) {
            self.span = None;
        }
        if self.lookahead < point {
            self.lookahead = point;
        }
    }

    /// Reads the block at `point`: one read for its first word 0 and one
    /// per interior word 0 of a terminal `DATA` block, within the budget.
    fn scan_block<T: TermBytes>(
        &mut self,
        buffer: &LogBuffer<T>,
        point: Point,
        slot: u8,
        reads: &mut u32,
    ) -> Result<Scanned, SysError> {
        let term_length = buffer.term_length;
        let start = point.offset;
        *reads += 1;
        // SAFETY: see `word`; a block start reached by the scan.
        let raw = observe_block(unsafe { word(buffer, slot, start) });
        if raw == 0 {
            return Ok(Scanned::Zero);
        }
        if raw == ABORTING_MARKER.pack() {
            return Ok(Scanned::Marker);
        }
        if raw as u32 as i32 <= 0 {
            let extent = reserved_extent(
                raw,
                start,
                term_length,
                buffer.config.max_reserved,
                buffer.config.lane,
            )
            .ok_or_else(|| corrupt(start, "reserved word"))?;
            let reserved = Word0::unpack(raw).map_err(|_| corrupt(start, "reserved word"))?;
            return Ok(Scanned::Reserved { reserved, extent });
        }
        let first = Word0::unpack(raw).map_err(|_| corrupt(start, "reserved flags"))?;
        if first.version() != PROTOCOL_VERSION {
            return Err(corrupt(start, "version"));
        }
        let length = first.frame_length().unsigned_abs();
        match FrameType::try_from_code(first.frame_type_code()) {
            Ok(FrameType::Pad) if length == term_length - start => {
                return Ok(Scanned::Terminal { extent: length });
            }
            Ok(FrameType::Aborted)
                if first.flags().lane() == buffer.config.lane
                    && length.is_multiple_of(FRAME_ALIGNMENT)
                    && length <= term_length - start =>
            {
                return Ok(Scanned::Terminal { extent: length });
            }
            Ok(FrameType::Data) if first.flags().begin() => {}
            _ => return Err(corrupt(start, "terminal word")),
        }
        // A resumed walk continues only over the same terminal word, just
        // re-loaded with Acquire.
        let (mut offset, mut word0) = match self.fragments {
            Some(walk) if walk.count == point.count && walk.start == start && walk.first == raw => {
                if *reads >= self.scan_budget {
                    return Ok(Scanned::Partial);
                }
                *reads += 1;
                // SAFETY: see `word`; an interior frame start of the
                // terminal block, published by its commit.
                let interior = load_interior(unsafe { word(buffer, slot, walk.next) });
                (
                    walk.next,
                    Word0::unpack(interior).map_err(|_| corrupt(walk.next, "reserved flags"))?,
                )
            }
            _ => (start, first),
        };
        loop {
            let flags = word0.flags();
            if word0.frame_type_code() != FrameType::Data.code()
                || flags.begin() != (offset == start)
            {
                return Err(corrupt(offset, "fragment"));
            }
            let frame_length = u32::try_from(word0.frame_length())
                .ok()
                .filter(|length| *length >= flags.header_length())
                .ok_or_else(|| corrupt(offset, "fragment length"))?;
            let reserved = align_frame(frame_length)?;
            if reserved > term_length - offset {
                return Err(corrupt(offset, "frame past term end"));
            }
            offset += reserved;
            if flags.end() {
                self.fragments = None;
                return Ok(Scanned::Terminal {
                    extent: offset - start,
                });
            }
            if offset == term_length {
                return Err(corrupt(offset, "block without END"));
            }
            if *reads >= self.scan_budget {
                self.fragments = Some(Fragments {
                    count: point.count,
                    slot,
                    start,
                    first: raw,
                    next: offset,
                });
                return Ok(Scanned::Partial);
            }
            *reads += 1;
            // SAFETY: as above.
            let interior = load_interior(unsafe { word(buffer, slot, offset) });
            word0 = Word0::unpack(interior).map_err(|_| corrupt(offset, "reserved flags"))?;
        }
    }
}

/// The timer of one stuck point (claim-deadline.md): a clock going back
/// re-anchors and is counted, an unrepresentable expiry is counted, and
/// equality expires.
fn timer(
    first_seen: &mut u64,
    now: u64,
    deadline: u64,
    report: &mut DeadlineReport,
) -> Result<bool, SysError> {
    if now < *first_seen {
        *first_seen = now;
        bump(&mut report.clock_went_back)?;
        return Ok(false);
    }
    match first_seen.checked_add(deadline) {
        Some(expiry) => Ok(now >= expiry),
        None => {
            bump(&mut report.unrepresentable)?;
            Ok(false)
        }
    }
}

/// Counts one outcome (at most `P + 1` per call, so never overflowing).
fn bump(count: &mut u32) -> Result<(), SysError> {
    *count = count.checked_add(1).ok_or(LayoutError::LengthOverflow {
        value: u64::from(*count),
    })?;
    Ok(())
}

/// Counts one abort of `extent` bytes.
fn count_abort(report: &mut DeadlineReport, extent: u32) -> Result<(), SysError> {
    bump(&mut report.aborted)?;
    report.aborted_bytes =
        report
            .aborted_bytes
            .checked_add(u64::from(extent))
            .ok_or(LayoutError::LengthOverflow {
                value: report.aborted_bytes,
            })?;
    Ok(())
}

/// The `ABORTED` word of `extent` bytes on the buffer's lane.
fn aborted<T: TermBytes>(buffer: &LogBuffer<T>, extent: u32) -> Word0 {
    Word0::new(
        extent as i32,
        Flags::new(false, false, false, false, buffer.config.lane),
        FrameType::Aborted,
    )
}

/// The admitted head offset of term `count`: the term end once the head
/// passed it, the head's offset in the head's term, 0 for later terms.
fn bound<T: TermBytes>(buffer: &LogBuffer<T>, head: u64, count: TermCount) -> u32 {
    let base = buffer.position(count, 0);
    let term_length = buffer.term_length;
    if head <= base {
        0
    } else if head - base >= u64::from(term_length) {
        term_length
    } else {
        (head - base) as u32
    }
}

/// Whether `slot` still holds term `count` inspectable: `ACTIVE` or
/// `RECLAIMING` with that term id.
fn holds<T: TermBytes>(
    buffer: &LogBuffer<T>,
    slot: u8,
    count: TermCount,
) -> Result<bool, SysError> {
    let found = Descriptor::decode(buffer.descriptor(slot)?.load(Ordering::Acquire))?;
    Ok(
        matches!(found.state(), SlotState::Active | SlotState::Reclaiming)
            && found.term_id() == buffer.initial_term_id.advanced_by(count),
    )
}

/// The slot holding term `count` inspectable: the table hint, else a scan
/// of the descriptors (a quarantined term's hint may have been reused).
fn find_slot<T: TermBytes>(
    buffer: &LogBuffer<T>,
    count: TermCount,
) -> Result<Option<u8>, SysError> {
    if let Lookup::Slot(slot) = buffer.lookup(count)?
        && holds(buffer, slot, count)?
    {
        return Ok(Some(slot));
    }
    for slot in 0..buffer.slots {
        if holds(buffer, slot, count)? {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// Settles a scan position: at the end of a term the active count has
/// passed, the next term; in a term no longer inspectable, the start of the
/// oldest later inspectable one. `None` when nothing is inspectable yet.
fn settle<T: TermBytes>(
    buffer: &LogBuffer<T>,
    mut point: Point,
) -> Result<Option<(Point, u8)>, SysError> {
    let active = buffer.active_count.load(Ordering::Acquire);
    loop {
        if point.offset >= buffer.term_length && u64::from(point.count.get()) < active {
            point = Point {
                count: point.count.next()?,
                offset: 0,
            };
        }
        if let Some(slot) = find_slot(buffer, point.count)? {
            return Ok(Some((point, slot)));
        }
        // Gone (or never inspected): the oldest later inspectable term.
        let mut oldest = None::<TermCount>;
        for slot in 0..buffer.slots {
            let found = Descriptor::decode(buffer.descriptor(slot)?.load(Ordering::Acquire))?;
            if !matches!(found.state(), SlotState::Active | SlotState::Reclaiming) {
                continue;
            }
            let count = found.term_id().count_from(buffer.initial_term_id)?;
            if count > point.count && oldest.is_none_or(|oldest| count < oldest) {
                oldest = Some(count);
            }
        }
        let Some(count) = oldest else {
            return Ok(None);
        };
        point = Point { count, offset: 0 };
    }
}

/// The word 0 location at `offset` of `slot`.
///
/// # Safety
///
/// `slot` was just validated by [`holds`] (or [`find_slot`]) to hold an
/// inspectable term, so only this conductor can move it to `CLEANING`, and
/// not during the caller's use; `offset` is a 32-byte boundary below the
/// term length that no party accesses non-atomically in this incarnation:
/// a frame start reached by the scan, or a boundary of a zero span owned or
/// being taken by the walk, whose writers fail their mark before any write.
unsafe fn word<T: TermBytes>(
    buffer: &LogBuffer<T>,
    slot: u8,
    offset: u32,
) -> &core::sync::atomic::AtomicU64 {
    // SAFETY: the caller's contract is the conductor case of `word0`.
    unsafe { buffer.regions.word0(slot, offset) }
}
