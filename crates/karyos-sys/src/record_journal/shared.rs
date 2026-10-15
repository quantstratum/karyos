// SPDX-License-Identifier: Apache-2.0

//! A journal in one block of words, the structure of a trace journal region
//! (`quantstratum-docs: karyos/design/trace-journal-region.md`), and the
//! driver's drain of it.
//!
//! **Layout** (words of the structure, after the region header):
//!
//! | Words | Content |
//! | --- | --- |
//! | 0 to 15 | Geometry: [`JOURNAL_MAGIC`], capacity, payload words, drop ranges; the rest zero |
//! | 16 to 79 | The journal's control words (`head`, `consumed`, `attempted`, closed flag, writer words, watermark) |
//! | 80 on | The drop ranges, [`RANGE_WORDS`] each, padded to a 128-byte stride |
//! | then | The records, `1 + payload` words each, padded to a 128-byte stride |
//!
//! The driver writes the geometry at creation; the client writes the
//! records and the writer words, the driver only `consumed`.
//!
//! **Draining untrusted memory.** A client writes the whole region, so the
//! driver's [`JournalDrain`] trusts nothing it reads there: it keeps its own
//! copies of the geometry, of `consumed` (it never reads the shared word
//! back) and of the next sequence it accepts, and checks each read against
//! them: the geometry words must keep their values, `head` must stay within
//! `consumed..=consumed + capacity`, sequences must increase, and every drop
//! range must have `first <= last`. A violation is sticky: the drain
//! reports it from then on and copies nothing more. Nothing in it panics.

use std::sync::Arc;

use super::owned::{Backing, JournalWriter, Losses, Region};
use super::{
    CONSUMED, CONTROL_WORDS, DropRange, HEAD, JournalError, JournalWords, RANGE_WORDS, STRIDE,
};
use crate::atomic_view::{HeapWords, WORD_BYTES};
use crate::sync::{AtomicU64, Ordering};

/// The first geometry word of a journal block: "KYjrnl" and a format.
pub const JOURNAL_MAGIC: u64 = u64::from_le_bytes(*b"KYjrnl01");
/// Layout version of a journal region's structure.
pub const JOURNAL_LAYOUT_VERSION: u64 = 1;
/// Words of the geometry stride.
const GEOMETRY_WORDS: usize = STRIDE;

/// Rounds `words` up to a whole stride; `None` on overflow.
const fn stride_round(words: usize) -> Option<usize> {
    match words.checked_add(STRIDE - 1) {
        Some(padded) => Some(padded / STRIDE * STRIDE),
        None => None,
    }
}

/// The sizes of a journal: `capacity` records (a power of two) of
/// `payload_words` words, with `drop_ranges` drop-range entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalLayout {
    /// Records, a nonzero power of two.
    pub capacity: usize,
    /// Payload words per record, nonzero.
    pub payload_words: usize,
    /// Drop-range entries, nonzero.
    pub drop_ranges: usize,
}

impl JournalLayout {
    /// Checks the sizes as [`super::record_journal`] does, and that the
    /// structure's size fits.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvalidConfig`].
    pub fn validate(&self) -> Result<(), JournalError> {
        let valid = self.capacity > 0
            && self.capacity.is_power_of_two()
            && self.payload_words > 0
            && self.drop_ranges > 0
            && self.structure_bytes().is_some();
        if valid {
            Ok(())
        } else {
            Err(JournalError::InvalidConfig)
        }
    }

    const fn ranges_offset() -> usize {
        GEOMETRY_WORDS + CONTROL_WORDS
    }

    fn records_offset(&self) -> Option<usize> {
        let ranges = stride_round(self.drop_ranges.checked_mul(RANGE_WORDS)?)?;
        Self::ranges_offset().checked_add(ranges)
    }

    fn record_words(&self) -> Option<usize> {
        self.capacity
            .checked_mul(self.payload_words.checked_add(1)?)
    }

    /// Words of the structure; `None` on overflow.
    #[must_use]
    pub fn structure_words(&self) -> Option<usize> {
        self.records_offset()?
            .checked_add(stride_round(self.record_words()?)?)
    }

    /// Bytes of the structure, a multiple of 128; `None` on overflow or
    /// beyond `isize::MAX`.
    #[must_use]
    pub fn structure_bytes(&self) -> Option<usize> {
        self.structure_words()?
            .checked_mul(WORD_BYTES)
            .filter(|bytes| isize::try_from(*bytes).is_ok())
    }

    fn geometry(&self) -> [u64; 4] {
        [
            JOURNAL_MAGIC,
            self.capacity as u64,
            self.payload_words as u64,
            self.drop_ranges as u64,
        ]
    }

    /// Writes the geometry words of a fresh block.
    fn stamp(&self, block: &[AtomicU64]) {
        for (word, value) in block.iter().zip(self.geometry()) {
            word.store(value, Ordering::Release);
        }
    }

    /// Whether the geometry words of `block` still hold this layout.
    fn matches(&self, block: &[AtomicU64]) -> bool {
        self.geometry().iter().enumerate().all(|(index, value)| {
            block
                .get(index)
                .is_some_and(|word| word.load(Ordering::Acquire) == *value)
        })
    }

    /// The journal words of `block`, which holds exactly this structure.
    pub(super) fn words<'a>(&self, block: &'a [AtomicU64]) -> Option<JournalWords<'a>> {
        if Some(block.len()) != self.structure_words() {
            return None;
        }
        let control = block.get(GEOMETRY_WORDS..Self::ranges_offset())?;
        let ranges_end = Self::ranges_offset().checked_add(self.drop_ranges * RANGE_WORDS)?;
        let ranges = block.get(Self::ranges_offset()..ranges_end)?;
        let start = self.records_offset()?;
        let records = block.get(start..start.checked_add(self.record_words()?)?)?;
        JournalWords::new(records, control, ranges, self.payload_words).ok()
    }
}

/// What a client's journal did wrong. The driver stops draining it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// The geometry words changed, so the record length or capacity no
    /// longer matches the journal's.
    Layout,
    /// `head` went backwards or past `consumed + capacity`.
    Head,
    /// A record's sequence did not increase.
    Sequence,
    /// A drop range ends before it starts.
    Range,
}

/// What [`JournalDrain::take`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Drained<'a> {
    /// A record, copied and released to the writer.
    Record {
        /// Its sequence.
        sequence: u64,
        /// Sequences `[from, to)` before it that were never stored, if any.
        gap: Option<(u64, u64)>,
        /// Its payload, in the drain's buffer.
        payload: &'a [u64],
    },
    /// Nothing is waiting; the journal is open.
    Empty,
    /// The writer closed the journal and every record was taken.
    Closed,
    /// The journal broke its protocol; nothing more is copied.
    Violation(Violation),
}

/// The driver's consumer of a client journal: it treats the journal's
/// memory as untrusted (see the module documentation).
#[derive(Debug)]
pub struct JournalDrain {
    region: Arc<Region>,
    layout: JournalLayout,
    /// The driver's own count of released records.
    consumed: u64,
    /// The lowest sequence the next record may carry.
    expected: u64,
    payload: Box<[u64]>,
    ranges: Box<[DropRange]>,
    fault: Option<Violation>,
}

impl JournalDrain {
    fn new(region: Arc<Region>, layout: JournalLayout) -> Self {
        Self {
            region,
            layout,
            consumed: 0,
            expected: 0,
            payload: vec![0; layout.payload_words].into_boxed_slice(),
            ranges: vec![DropRange::default(); layout.drop_ranges].into_boxed_slice(),
            fault: None,
        }
    }

    /// The journal's sizes, as the driver created it.
    #[must_use]
    pub fn layout(&self) -> JournalLayout {
        self.layout
    }

    /// Records released to the writer.
    #[must_use]
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// The journal's attempted count (one Acquire load), for deciding
    /// whether its loss accounting changed; `None` when the journal cannot
    /// be read. The value is untrusted, like every word of the journal:
    /// it only selects a reread, which `losses` validates.
    #[must_use]
    pub fn attempted(&self) -> Option<u64> {
        Self::words(&self.region, &self.layout).map(|words| words.attempted())
    }

    /// The violation that stopped the drain, if any.
    #[must_use]
    pub fn fault(&self) -> Option<Violation> {
        self.fault
    }

    /// The journal region, to pass its descriptor; `None` on the heap.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn region(&self) -> Option<&crate::ipc::Region> {
        match &self.region.backing {
            Backing::Mapped(region) => Some(region),
            _ => None,
        }
    }

    /// The journal words, if the geometry still holds the layout.
    fn words<'a>(region: &'a Region, layout: &JournalLayout) -> Option<JournalWords<'a>> {
        region
            .block()
            .filter(|block| layout.matches(block))
            .and_then(|block| layout.words(block))
    }

    /// Copies and releases the oldest record, after checking the journal's
    /// words against the driver's own state.
    pub fn take(&mut self) -> Drained<'_> {
        let consumed = self.consumed;
        let expected = self.expected;
        let capacity = self.layout.capacity as u64;
        let outcome = match (self.fault, Self::words(&self.region, &self.layout)) {
            (Some(violation), _) => Err(violation),
            (None, None) => Err(Violation::Layout),
            (None, Some(words)) => {
                Self::copy(&words, consumed, expected, capacity, &mut self.payload)
            }
        };
        match outcome {
            Ok(Step::Empty) => Drained::Empty,
            Ok(Step::Closed) => Drained::Closed,
            Ok(Step::Record { sequence }) => {
                self.consumed = consumed + 1;
                self.expected = sequence + 1;
                Drained::Record {
                    sequence,
                    gap: (sequence != expected).then_some((expected, sequence)),
                    payload: &self.payload,
                }
            }
            Err(violation) => {
                self.fault = Some(violation);
                Drained::Violation(violation)
            }
        }
    }

    /// One checked copy at the driver's `consumed`; releases the slot.
    fn copy(
        words: &JournalWords<'_>,
        consumed: u64,
        expected: u64,
        capacity: u64,
        out: &mut [u64],
    ) -> Result<Step, Violation> {
        let within = |head: u64| {
            head.checked_sub(consumed)
                .is_some_and(|pending| pending <= capacity)
        };
        let mut head = words.load(HEAD, Ordering::Acquire);
        if !within(head) {
            return Err(Violation::Head);
        }
        if head == consumed {
            if !words.is_closed() {
                return Ok(Step::Empty);
            }
            // Closed (Acquire) after the writer's last record: reload.
            head = words.load(HEAD, Ordering::Acquire);
            if !within(head) {
                return Err(Violation::Head);
            }
            if head == consumed {
                return Ok(Step::Closed);
            }
        }
        let slot = words.record(consumed).ok_or(Violation::Layout)?;
        let sequence = slot.first().map_or(0, |word| word.load(Ordering::Relaxed));
        for (value, word) in out.iter_mut().zip(slot.iter().skip(1)) {
            *value = word.load(Ordering::Relaxed);
        }
        if sequence < expected || sequence == u64::MAX {
            return Err(Violation::Sequence);
        }
        // `consumed < head`, so this cannot overflow.
        words.store(CONSUMED, consumed + 1, Ordering::Release);
        Ok(Step::Record { sequence })
    }

    /// The loss accounting at a fresh horizon (see [`JournalWords::losses`]),
    /// checked: a drop range that ends before it starts, or a stored count
    /// below what was released, is a violation.
    ///
    /// # Errors
    ///
    /// Returns the violation, sticky as for [`JournalDrain::take`].
    pub fn losses(&mut self) -> Result<Losses<'_>, Violation> {
        let consumed = self.consumed;
        if let Some(violation) = self.fault {
            return Err(violation);
        }
        // The buffer holds every drop range by construction.
        let snapshot = match Self::words(&self.region, &self.layout) {
            Some(words) => words
                .losses(&mut self.ranges)
                .map_err(|_| Violation::Layout),
            None => Err(Violation::Layout),
        };
        let checked = snapshot.and_then(|snapshot| {
            let ranges = self.ranges.get(..snapshot.ranges).unwrap_or(&[]);
            if ranges.iter().any(|range| range.first > range.last) {
                Err(Violation::Range)
            } else if snapshot.stored < consumed {
                Err(Violation::Head)
            } else {
                Ok(snapshot)
            }
        });
        match checked {
            Ok(snapshot) => Ok(Losses {
                attempted: snapshot.attempted,
                stored: snapshot.stored,
                ranges: self.ranges.get(..snapshot.ranges).unwrap_or(&[]),
                unstable: snapshot.unstable,
                lost_before: snapshot.lost_before,
            }),
            Err(violation) => {
                self.fault = Some(violation);
                Err(violation)
            }
        }
    }

    /// Whether the writer closed the journal; `false` once faulted.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.fault.is_none()
            && Self::words(&self.region, &self.layout).is_some_and(|words| words.is_closed())
    }

    /// Test only: the journal's words, to break its protocol as a hostile
    /// client would.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use]
    pub fn hostile_words(&self) -> &[AtomicU64] {
        self.region.block().unwrap_or(&[])
    }
}

/// One checked step of a drain.
enum Step {
    Empty,
    Closed,
    Record { sequence: u64 },
}

fn writer(region: &Arc<Region>) -> JournalWriter {
    JournalWriter {
        region: Arc::clone(region),
        guard: None,
    }
}

fn region(backing: Backing, layout: JournalLayout) -> Arc<Region> {
    Arc::new(Region {
        backing,
        record_words: layout.payload_words + 1,
        capacity: layout.capacity,
        range_count: layout.drop_ranges,
        payload_words: layout.payload_words,
    })
}

/// A journal of `layout` in one heap block (an in-process client of the
/// driver): its only writer and the driver's drain (control path).
///
/// # Errors
///
/// Returns [`JournalError::InvalidConfig`] for invalid sizes.
pub fn journal_block(layout: JournalLayout) -> Result<(JournalWriter, JournalDrain), JournalError> {
    layout.validate()?;
    let words = layout
        .structure_words()
        .ok_or(JournalError::InvalidConfig)?;
    let heap = HeapWords::zeroed(words).map_err(|_| JournalError::InvalidConfig)?;
    layout.stamp(heap.words().as_slice());
    let region = region(Backing::Block(heap), layout);
    region.words()?;
    Ok((writer(&region), JournalDrain::new(region, layout)))
}

/// Creates a journal region of `layout` (driver side): kind `Journal`,
/// size seals only, the geometry stamped; returns the driver's drain, whose
/// region carries the descriptor to fetch.
///
/// # Errors
///
/// Returns [`crate::SysError::InvalidRegion`] for invalid sizes, and the
/// errors of [`crate::ipc::Region::create`].
#[cfg(target_os = "linux")]
pub fn journal_region(
    instance: u128,
    id: u64,
    layout: JournalLayout,
) -> Result<JournalDrain, crate::SysError> {
    let invalid = crate::SysError::InvalidRegion { address: 0, len: 0 };
    layout.validate().map_err(|_| invalid)?;
    let structure_length = layout.structure_bytes().ok_or(invalid)?;
    let mapped = crate::ipc::Region::create(crate::ipc::RegionRecord {
        instance,
        region: id,
        kind: crate::ipc::RegionKind::Journal,
        generation: 0,
        layout: JOURNAL_LAYOUT_VERSION,
        structure_length,
    })?;
    layout.stamp(mapped.structure().as_slice());
    let region = region(Backing::Mapped(mapped), layout);
    region.words().map_err(|_| invalid)?;
    Ok(JournalDrain::new(region, layout))
}

/// The writer of a journal region the client attached (client side): the
/// region must be a `Journal` of this layout version, whose structure and
/// geometry words hold `layout`.
///
/// # Errors
///
/// Returns [`crate::SysError::InvalidRegion`] when the region does not
/// hold `layout`.
#[cfg(target_os = "linux")]
pub fn attach_journal(
    mapped: crate::ipc::Region,
    layout: JournalLayout,
) -> Result<JournalWriter, crate::SysError> {
    let record = mapped.record();
    let invalid = crate::SysError::InvalidRegion {
        address: 0,
        len: record.structure_length,
    };
    let valid = record.kind == crate::ipc::RegionKind::Journal
        && record.layout == JOURNAL_LAYOUT_VERSION
        && record.generation == 0
        && layout.validate().is_ok()
        && layout.structure_bytes() == Some(record.structure_length)
        && layout.matches(mapped.structure().as_slice());
    if !valid {
        return Err(invalid);
    }
    let region = region(Backing::Mapped(mapped), layout);
    region.words().map_err(|_| invalid)?;
    Ok(writer(&region))
}

#[cfg(test)]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]
mod tests {
    use super::*;
    use crate::record_journal::{Append, Stamp};

    const LAYOUT: JournalLayout = JournalLayout {
        capacity: 4,
        payload_words: 3,
        drop_ranges: 2,
    };

    fn stamp(time: u64) -> Stamp {
        Stamp {
            time,
            clock: 1,
            epoch: 1,
        }
    }

    /// A drained record: its sequence, its gap and its first payload word.
    type Seen = (u64, Option<(u64, u64)>, u64);

    fn drain_all(drain: &mut JournalDrain) -> (Vec<Seen>, Drained<'_>) {
        let mut seen = Vec::new();
        while let Drained::Record {
            sequence,
            gap,
            payload,
        } = drain.take()
        {
            seen.push((sequence, gap, payload[0]));
        }
        let last = drain.take();
        (seen, last)
    }

    #[test]
    fn the_layout_is_stride_aligned_and_checked() {
        // Geometry 16, control 64, ranges 2 * 8 = 16, records 4 * 4 = 16.
        assert_eq!(LAYOUT.structure_words(), Some(16 + 64 + 16 + 16));
        assert_eq!(LAYOUT.structure_bytes().unwrap() % 128, 0);
        for bad in [
            JournalLayout {
                capacity: 3,
                ..LAYOUT
            },
            JournalLayout {
                payload_words: 0,
                ..LAYOUT
            },
            JournalLayout {
                drop_ranges: 0,
                ..LAYOUT
            },
            JournalLayout {
                capacity: 1 << 62,
                payload_words: 4,
                drop_ranges: 1,
            },
        ] {
            assert!(journal_block(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_drain_takes_records_and_reports_gaps_and_drops() {
        let (mut writer, mut drain) = journal_block(LAYOUT).unwrap();
        for value in 0..6u64 {
            let appended = writer.append(&[value, 0, 0], stamp(value)).unwrap();
            // Four fit; the fifth and sixth are dropped.
            assert_eq!(
                matches!(appended, Append::Stored { .. }),
                value < 4,
                "{value}"
            );
        }
        let (seen, last) = drain_all(&mut drain);
        assert_eq!(last, Drained::Empty);
        assert_eq!(
            seen,
            vec![(0, None, 0), (1, None, 1), (2, None, 2), (3, None, 3)]
        );
        // Room again: the next record shows the dropped ones as a gap.
        writer.append(&[9, 0, 0], stamp(9)).unwrap();
        let (seen, _) = drain_all(&mut drain);
        assert_eq!(seen, vec![(6, Some((4, 6)), 9)]);
        let losses = drain.losses().unwrap();
        assert_eq!((losses.attempted, losses.stored), (7, 5));
        assert_eq!(losses.ranges.len(), 1);
        assert_eq!((losses.ranges[0].first, losses.ranges[0].last), (4, 5));
        drop(writer);
        assert!(drain.is_closed());
        assert_eq!(drain.take(), Drained::Closed);
        assert_eq!(drain.consumed(), 5);
    }

    #[test]
    fn a_hostile_head_is_a_violation_and_sticks() {
        let (mut writer, mut drain) = journal_block(LAYOUT).unwrap();
        writer.append(&[1, 2, 3], stamp(1)).unwrap();
        let words = drain.hostile_words();
        // `head` past `consumed + capacity`.
        words[GEOMETRY_WORDS + HEAD].store(9, Ordering::Release);
        assert_eq!(drain.take(), Drained::Violation(Violation::Head));
        // Sticky, also once the word looks right again.
        drain.hostile_words()[GEOMETRY_WORDS + HEAD].store(1, Ordering::Release);
        assert_eq!(drain.take(), Drained::Violation(Violation::Head));
        assert_eq!(drain.losses().err(), Some(Violation::Head));
        assert!(!drain.is_closed());
        assert_eq!(drain.fault(), Some(Violation::Head));
    }

    #[test]
    fn a_repeated_sequence_or_a_changed_length_is_a_violation() {
        let (mut writer, mut drain) = journal_block(LAYOUT).unwrap();
        writer.append(&[1, 0, 0], stamp(1)).unwrap();
        writer.append(&[2, 0, 0], stamp(2)).unwrap();
        assert!(matches!(drain.take(), Drained::Record { sequence: 0, .. }));
        // The second record claims the first one's sequence.
        let records = LAYOUT.records_offset().unwrap();
        drain.hostile_words()[records + 4].store(0, Ordering::Relaxed);
        assert_eq!(drain.take(), Drained::Violation(Violation::Sequence));

        let (mut writer, mut drain) = journal_block(LAYOUT).unwrap();
        writer.append(&[1, 0, 0], stamp(1)).unwrap();
        // The payload length word no longer matches the journal's.
        drain.hostile_words()[2].store(5, Ordering::Release);
        assert_eq!(drain.take(), Drained::Violation(Violation::Layout));
    }

    #[test]
    fn a_backwards_range_is_a_violation() {
        let (mut writer, mut drain) = journal_block(LAYOUT).unwrap();
        for value in 0..5u64 {
            writer.append(&[value, 0, 0], stamp(value)).unwrap();
        }
        // Range entry 0 (version, length, first, last, ...) covers 4..=4;
        // make its last sequence 2.
        let ranges = JournalLayout::ranges_offset();
        drain.hostile_words()[ranges + 3].store(2, Ordering::Relaxed);
        assert_eq!(drain.losses().err(), Some(Violation::Range));
    }

    #[test]
    fn the_writer_appends_through_the_block_api_as_on_the_heap() {
        let (mut writer, _drain) = journal_block(LAYOUT).unwrap();
        assert_eq!((writer.capacity(), writer.payload_words()), (4, 3));
        assert!(matches!(
            writer.append(&[1, 2], stamp(1)),
            Err(JournalError::PayloadLength { .. })
        ));
    }
}
