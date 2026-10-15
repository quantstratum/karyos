// SPDX-License-Identifier: Apache-2.0

//! The words of a log buffer and their layout (`quantstratum-docs: karyos/design/ipc-log-buffer.md`).
//!
//! Every word that more than one party touches lives in one [`Backing`]:
//! heap memory of this process, or a shared [`crate::ipc::Region`]. The
//! [`Layout`] places each section on a 128-byte stride. Control words are
//! reached through *overlays*: `#[repr(C)]` types made only of `AtomicU64`
//! ([`Line`], [`Cell`], [`Control`]), whose size, alignment and field
//! offsets are asserted at compile time. A section pointer is derived once,
//! after its bounds are checked against the backing, and turned into a
//! reference only by an accessor that borrows the owner of the backing.

use core::mem::{align_of, offset_of, size_of};
use core::ptr::NonNull;
use core::sync::atomic::AtomicU64;

use crate::atomic_view::{HeapWords, WORD_BYTES};
use crate::error::SysError;

/// Words of one 128-byte stride.
pub(crate) const LINE_WORDS: usize = 16;
/// Words of the configuration block: four strides.
pub(crate) const CONFIG_WORDS: usize = 4 * LINE_WORDS;

/// A type made only of `AtomicU64`, laid over backing words.
///
/// # Safety
///
/// An implementor is `#[repr(C)]`, consists only of `AtomicU64` fields
/// (directly, in arrays, or in other `Overlay` types), has no padding, has
/// the alignment of `AtomicU64`, and its size is `WORDS * 8` bytes. Every
/// bit pattern of its words is then a valid value, and every byte of it is
/// part of an `AtomicU64`.
pub(crate) unsafe trait Overlay: Sized {
    /// Its size in words.
    const WORDS: usize;
}

/// One control word alone on a 128-byte stride. The padding words are
/// never accessed.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct Line {
    pub(crate) word: AtomicU64,
    _padding: [AtomicU64; LINE_WORDS - 1],
}

/// One registry cell (SPEC.md §4 participants), alone on its stride.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct Cell {
    pub(crate) loan: AtomicU64,
    pub(crate) revoked: AtomicU64,
    pub(crate) position: AtomicU64,
    pub(crate) state: AtomicU64,
    /// The export id of the grant that registered it (IPC), 0 otherwise.
    pub(crate) registration: AtomicU64,
    _padding: [AtomicU64; LINE_WORDS - 5],
}

/// One concurrent publisher slot, alone on its stride.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct PublisherSlot {
    /// The slot word (`quantstratum-docs: karyos/design/concurrent-publication.md`).
    pub(crate) word: AtomicU64,
    /// The export id of the grant that registered it (IPC), 0 otherwise.
    pub(crate) registration: AtomicU64,
    /// The term count the registered handle starts from (IPC).
    pub(crate) from: AtomicU64,
    _padding: [AtomicU64; LINE_WORDS - 3],
}

/// The single control words, each on its own stride.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct Control {
    pub(crate) active_count: Line,
    pub(crate) reserved_head: Line,
    pub(crate) limit: Line,
    pub(crate) floor: Line,
    pub(crate) seal: Line,
    pub(crate) publication_taken: Line,
    pub(crate) exclusive_released: Line,
    pub(crate) publication_registration: Line,
    pub(crate) claim_record: Line,
    pub(crate) claim_serial: Line,
}

// SAFETY: `#[repr(C)]`, only `AtomicU64` fields, no padding (asserted below).
unsafe impl Overlay for AtomicU64 {
    const WORDS: usize = 1;
}
// SAFETY: as above.
unsafe impl Overlay for Line {
    const WORDS: usize = LINE_WORDS;
}
// SAFETY: as above.
unsafe impl Overlay for Cell {
    const WORDS: usize = LINE_WORDS;
}
// SAFETY: as above.
unsafe impl Overlay for PublisherSlot {
    const WORDS: usize = LINE_WORDS;
}
// SAFETY: as above.
unsafe impl Overlay for Control {
    const WORDS: usize = 10 * LINE_WORDS;
}

const _: () = {
    assert!(size_of::<Line>() == Line::WORDS * WORD_BYTES);
    assert!(size_of::<Cell>() == Cell::WORDS * WORD_BYTES);
    assert!(size_of::<Control>() == Control::WORDS * WORD_BYTES);
    assert!(size_of::<PublisherSlot>() == PublisherSlot::WORDS * WORD_BYTES);
    assert!(align_of::<PublisherSlot>() == align_of::<AtomicU64>());
    assert!(offset_of!(PublisherSlot, registration) == 8);
    assert!(offset_of!(PublisherSlot, from) == 16);
    assert!(align_of::<Line>() == align_of::<AtomicU64>());
    assert!(align_of::<Cell>() == align_of::<AtomicU64>());
    assert!(align_of::<Control>() == align_of::<AtomicU64>());
    assert!(offset_of!(Line, word) == 0);
    assert!(offset_of!(Cell, loan) == 0);
    assert!(offset_of!(Cell, revoked) == 8);
    assert!(offset_of!(Cell, position) == 16);
    assert!(offset_of!(Cell, state) == 24);
    assert!(offset_of!(Cell, registration) == 32);
    assert!(offset_of!(Control, reserved_head) == 128);
    assert!(offset_of!(Control, claim_serial) == 9 * 128);
};

/// Where a buffer's words live.
#[derive(Debug)]
pub enum Backing {
    /// Heap memory of this process.
    Heap(HeapWords),
    /// A shared region (Linux).
    #[cfg(target_os = "linux")]
    Region(crate::ipc::Region),
}

impl Backing {
    /// The first word and the number of words.
    fn words(&self) -> (NonNull<AtomicU64>, usize) {
        match self {
            Self::Heap(words) => (words.base(), words.count()),
            #[cfg(target_os = "linux")]
            Self::Region(region) => {
                let words = region.structure().as_slice();
                (NonNull::from(words).cast(), words.len())
            }
        }
    }

    /// The word at `index`, if in bounds.
    pub(crate) fn word(&self, index: usize) -> Option<&AtomicU64> {
        let (base, count) = self.words();
        if index >= count {
            return None;
        }
        // SAFETY: `index < count`: the pointer stays inside the backing's
        // live words.
        let word = unsafe { base.add(index) };
        // SAFETY: the word is an initialized `AtomicU64` of the backing,
        // which `self` owns and the reference borrows; accessed only
        // atomically.
        Some(unsafe { word.as_ref() })
    }

    /// A pointer to `count` overlays of type `V` from word `index`, after
    /// checking that they lie inside the backing. The pointer stays valid
    /// while the backing lives; it is turned into a reference only by an
    /// accessor that borrows the backing's owner.
    pub(crate) fn overlays<V: Overlay>(
        &self,
        index: usize,
        count: usize,
    ) -> Result<NonNull<[V]>, SysError> {
        let (base, words) = self.words();
        let end = count
            .checked_mul(V::WORDS)
            .and_then(|len| index.checked_add(len))
            .filter(|end| *end <= words)
            .ok_or(SysError::InvalidRegion {
                address: 0,
                len: words.saturating_mul(WORD_BYTES),
            })?;
        let _ = end;
        // SAFETY: `index <= end <= words`, so the pointer stays inside (or
        // one past, for an empty section) the backing's words.
        let first = unsafe { base.add(index) };
        Ok(NonNull::slice_from_raw_parts(first.cast::<V>(), count))
    }
}

/// The word index of each section of a buffer's backing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    pub(crate) config: usize,
    pub(crate) control: usize,
    pub(crate) descriptors: usize,
    pub(crate) table: usize,
    pub(crate) tails: usize,
    pub(crate) cells: usize,
    pub(crate) publishers: usize,
    pub(crate) terms: usize,
    pub(crate) slots: usize,
    pub(crate) cell_count: usize,
    pub(crate) publisher_count: usize,
    pub(crate) term_words: usize,
    /// Words of the whole backing: a multiple of [`LINE_WORDS`].
    pub(crate) total: usize,
}

fn line_up(words: usize) -> Option<usize> {
    words
        .checked_add(LINE_WORDS - 1)
        .map(|w| w / LINE_WORDS * LINE_WORDS)
}

impl Layout {
    /// The layout of a buffer with `slots` slots, `cells` registry cells,
    /// `publishers` publisher slots and, when `terms_in_backing`, `slots`
    /// terms of `term_length` bytes. Checked arithmetic throughout.
    pub(crate) fn new(
        slots: u8,
        cells: usize,
        publishers: usize,
        term_length: u32,
        terms_in_backing: bool,
    ) -> Result<Self, SysError> {
        let overflow = SysError::InvalidRegion { address: 0, len: 0 };
        let slots = usize::from(slots);
        let term_words = if terms_in_backing {
            (term_length as usize)
                .checked_mul(slots)
                .map(|bytes| bytes / WORD_BYTES)
                .ok_or(overflow)?
        } else {
            0
        };
        let config = 0;
        let control = config + CONFIG_WORDS;
        let next = |start: usize, words: Option<usize>| {
            words
                .and_then(|words| start.checked_add(words))
                .and_then(line_up)
                .ok_or(overflow)
        };
        let descriptors = next(control, Some(Control::WORDS))?;
        let table = next(descriptors, slots.checked_mul(LINE_WORDS))?;
        let tails = next(table, Some(slots))?;
        let cells_at = next(tails, slots.checked_mul(LINE_WORDS))?;
        let publishers_at = next(cells_at, cells.checked_mul(Cell::WORDS))?;
        let terms = next(publishers_at, publishers.checked_mul(LINE_WORDS))?;
        let total = next(terms, Some(term_words))?;
        Ok(Self {
            config,
            control,
            descriptors,
            table,
            tails,
            cells: cells_at,
            publishers: publishers_at,
            terms,
            slots,
            cell_count: cells,
            publisher_count: publishers,
            term_words,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_start_on_strides_and_do_not_overlap() {
        let layout = Layout::new(9, 5, 3, 64 * 1024, true).unwrap();
        let starts = [
            layout.config,
            layout.control,
            layout.descriptors,
            layout.table,
            layout.tails,
            layout.cells,
            layout.publishers,
            layout.terms,
            layout.total,
        ];
        assert!(starts.iter().all(|start| start % LINE_WORDS == 0));
        assert!(starts.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(layout.control - layout.config, CONFIG_WORDS);
        assert!(layout.table - layout.descriptors >= 9 * LINE_WORDS);
        assert!(layout.cells - layout.tails >= 9 * LINE_WORDS);
        assert!(layout.publishers - layout.cells >= 5 * LINE_WORDS);
        assert!(layout.terms - layout.publishers >= 3 * LINE_WORDS);
        assert_eq!(layout.total - layout.terms, 9 * 64 * 1024 / 8);
        let local = Layout::new(9, 5, 0, 64 * 1024, false).unwrap();
        assert_eq!(local.term_words, 0);
        assert_eq!(local.total, local.terms);
    }

    #[test]
    fn overlays_are_bounds_checked() {
        let backing = Backing::Heap(HeapWords::zeroed(64).unwrap());
        assert!(backing.overlays::<Line>(0, 4).is_ok());
        assert!(backing.overlays::<Line>(16, 3).is_ok());
        assert!(backing.overlays::<Line>(16, 4).is_err());
        assert!(backing.overlays::<Line>(64, 0).is_ok());
        assert!(backing.overlays::<Line>(65, 0).is_err());
        assert!(backing.overlays::<Line>(0, usize::MAX).is_err());
        assert!(backing.word(63).is_some());
        assert!(backing.word(64).is_none());
    }
}
