// SPDX-License-Identifier: Apache-2.0

//! The words of a guard binding (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, "The binding across processes"):
//! the guard words, a handle's outcome ring and its consumed cell. Each
//! lives on the heap for an in-process driver, or in a shared region in
//! IPC mode (Linux), which admission grants to a client.

use std::fmt;

use karyos_client::{ConsumedCell, HeapWords};
use karyos_sys::load_words::LoadWords;
use karyos_sys::sync::AtomicU64;

/// The bytes of a region of `length` words, header included, as
/// [`Words::region`] sizes it; `None` on overflow.
#[cfg(target_os = "linux")]
pub(crate) fn region_bytes(length: usize) -> Option<u64> {
    let stride = karyos_sys::ipc::HEADER_STRIDE;
    let structure = length
        .max(1)
        .checked_mul(core::mem::size_of::<u64>())?
        .checked_next_multiple_of(stride)?;
    u64::try_from(structure.checked_add(stride)?).ok()
}

/// Words the driver writes, or whose cell its client writes.
pub(crate) enum Words {
    /// A heap allocation of the driver's process.
    Heap(HeapWords),
    /// A shared region (Linux).
    #[cfg(target_os = "linux")]
    Region(karyos_sys::ipc::Region),
}

impl fmt::Debug for Words {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Heap(_) => f.write_str("Words::Heap"),
            #[cfg(target_os = "linux")]
            Self::Region(region) => write!(f, "Words::Region({:?})", region.record()),
        }
    }
}

impl Words {
    /// `length` zeroed words on the heap, at least one.
    pub(crate) fn heap(length: usize) -> Self {
        Self::Heap(HeapWords::zeroed(length.max(1)))
    }

    /// At least `length` zeroed words in a new region named `region` of
    /// driver instance `instance`. A driver-only region carries the
    /// `F_SEAL_FUTURE_WRITE` seal, so every later mapping is read-only; a
    /// shared one only the size seals, for a cell its client writes.
    ///
    /// # Errors
    ///
    /// The region's errors.
    #[cfg(target_os = "linux")]
    pub(crate) fn region(
        instance: u128,
        region: u64,
        kind: karyos_sys::ipc::RegionKind,
        layout: u64,
        length: usize,
        driver_only: bool,
    ) -> Result<Self, karyos_sys::error::SysError> {
        use karyos_sys::ipc::{HEADER_STRIDE, Region, RegionRecord};
        // The structure is a nonzero multiple of the header stride.
        let structure_length = length
            .max(1)
            .checked_mul(core::mem::size_of::<u64>())
            .and_then(|bytes| bytes.checked_next_multiple_of(HEADER_STRIDE))
            .ok_or(karyos_sys::error::SysError::InvalidRegion { address: 0, len: 0 })?;
        let record = RegionRecord {
            instance,
            region,
            kind,
            generation: 0,
            layout,
            structure_length,
        };
        let mapped = if driver_only {
            Region::create_driver_only(record)?
        } else {
            Region::create(record)?
        };
        Ok(Self::Region(mapped))
    }

    /// The words, for the driver's stores and the walker's.
    pub(crate) fn words(&self) -> &[AtomicU64] {
        match self {
            Self::Heap(heap) => heap.words(),
            #[cfg(target_os = "linux")]
            Self::Region(region) => region.structure().as_slice(),
        }
    }

    /// The shared region, to grant; `None` on the heap.
    #[cfg(target_os = "linux")]
    pub(crate) const fn shared(&self) -> Option<&karyos_sys::ipc::Region> {
        match self {
            Self::Heap(_) => None,
            Self::Region(region) => Some(region),
        }
    }
}

impl LoadWords for Words {
    fn len(&self) -> usize {
        self.words().len()
    }

    fn load(&self, index: usize) -> Option<u64> {
        self.words().load(index)
    }

    fn load_acquire(&self, index: usize) -> Option<u64> {
        self.words().load_acquire(index)
    }
}

/// A consumed cell is word 0 of its words.
impl ConsumedCell for Words {
    fn cell(&self) -> &AtomicU64 {
        // Every store holds at least one word: both constructors round
        // the length up to 1.
        self.words()
            .first()
            .unwrap_or_else(|| unreachable!("a consumed cell holds a word"))
    }
}

/// One word of shared words, seen as word 0: a guard's word in the guard
/// words, for a reader that reads word 0, such as the sender's guard gate.
#[derive(Debug)]
pub(crate) struct WordAt {
    words: std::sync::Arc<Words>,
    index: usize,
}

impl WordAt {
    /// Word `index` of `words`.
    pub(crate) const fn new(words: std::sync::Arc<Words>, index: usize) -> Self {
        Self { words, index }
    }
}

impl LoadWords for WordAt {
    fn len(&self) -> usize {
        usize::from(self.index < self.words.len())
    }

    fn load(&self, index: usize) -> Option<u64> {
        if index == 0 {
            self.words.load(self.index)
        } else {
            None
        }
    }

    fn load_acquire(&self, index: usize) -> Option<u64> {
        if index == 0 {
            self.words.load_acquire(self.index)
        } else {
            None
        }
    }
}
