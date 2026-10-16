// SPDX-License-Identifier: Apache-2.0

//! Loads of 64-bit words by index: what the reader of a shared structure
//! needs, so that one reader works over writable words and over a mapping
//! without write access (`quantstratum-docs:
//! karyos/design/conflation-end-to-end.md`, Cross-process views, and
//! observability-and-tools.md, Read-only views).
//!
//! Over writable words, [`LoadWords::load_acquire`] is an `Acquire` load;
//! over [`ReadOnlyWords`](crate::atomic_view::ReadOnlyWords) it is a
//! `Relaxed` load followed by an `Acquire` fence, the strongest ordering
//! read-only memory allows. Both synchronize with a `Release` store of the
//! value read, so a reader written against this trait keeps its ordering
//! argument in both cases.

use crate::sync::{AtomicU64, Ordering};

/// Loads of the words of a shared structure, by index.
pub trait LoadWords {
    /// The number of words.
    fn len(&self) -> usize;

    /// Whether there is no word.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Loads word `index` (`Relaxed`); `None` past the end.
    fn load(&self, index: usize) -> Option<u64>;

    /// Loads word `index` with acquire semantics; `None` past the end.
    fn load_acquire(&self, index: usize) -> Option<u64>;
}

impl LoadWords for &[AtomicU64] {
    #[inline]
    fn len(&self) -> usize {
        <[AtomicU64]>::len(self)
    }

    #[inline]
    fn load(&self, index: usize) -> Option<u64> {
        self.get(index).map(|word| word.load(Ordering::Relaxed))
    }

    #[inline]
    fn load_acquire(&self, index: usize) -> Option<u64> {
        self.get(index).map(|word| word.load(Ordering::Acquire))
    }
}

#[cfg(not(loom))]
impl LoadWords for crate::atomic_view::ReadOnlyWords<'_> {
    #[inline]
    fn len(&self) -> usize {
        crate::atomic_view::ReadOnlyWords::len(self)
    }

    #[inline]
    fn load(&self, index: usize) -> Option<u64> {
        crate::atomic_view::ReadOnlyWords::load(self, index)
    }

    #[inline]
    fn load_acquire(&self, index: usize) -> Option<u64> {
        crate::atomic_view::ReadOnlyWords::load_acquire(self, index)
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use crate::atomic_view::{HeapWords, ReadOnlyWords};
    use crate::broadcast::{BroadcastReader, BroadcastWords, Receive, TRAILER_WORDS};
    use crate::conflation::{SlotRead, SlotWords, read_slot};

    /// A slot read through a load-only view finds what the writable view
    /// finds: empty, then each written value with its version.
    #[test]
    fn a_slot_reads_the_same_through_a_read_only_view() {
        let heap = HeapWords::zeroed(2 + 4).unwrap();
        let slot = SlotWords::new(heap.words().as_slice()).unwrap();
        let read_only = ReadOnlyWords::of(heap.words());
        let mut out = [0u8; 32];
        let mut expected = [0u8; 32];
        assert_eq!(read_slot(&read_only, &mut out), SlotRead::Empty);
        for value in [b"first".as_slice(), b"a longer value"] {
            let version = slot.write(value).unwrap();
            let found = read_slot(&read_only, &mut out);
            assert_eq!(found, slot.read(&mut expected));
            assert_eq!(
                found,
                SlotRead::Value {
                    version,
                    length: value.len()
                }
            );
            assert_eq!(out.get(..value.len()), Some(value));
        }
        // Too few words for a slot reads as unstable, never a panic.
        let short = HeapWords::zeroed(1).unwrap();
        assert_eq!(
            read_slot(&ReadOnlyWords::of(short.words()), &mut out),
            SlotRead::Unstable
        );
    }

    /// A broadcast buffer read through a load-only view delivers what its
    /// writer transmitted, then pending, and reports the writer's close.
    #[test]
    fn a_broadcast_buffer_reads_the_same_through_a_read_only_view() {
        let data = HeapWords::zeroed(32).unwrap();
        let trailer = HeapWords::zeroed(TRAILER_WORDS).unwrap();
        let writer =
            BroadcastWords::new(data.words().as_slice(), trailer.words().as_slice(), 64).unwrap();
        let reader = BroadcastReader::new(
            ReadOnlyWords::of(data.words()),
            ReadOnlyWords::of(trailer.words()),
            64,
        )
        .unwrap();
        let mut cursor = reader.tail();
        let mut out = vec![0u8; reader.max_payload()];
        for (type_id, payload) in [(1, b"one".as_slice()), (2, b"second message")] {
            let position = writer.transmit(type_id, payload).unwrap();
            assert_eq!(
                reader.receive(&mut cursor, &mut out).unwrap(),
                Receive::Message {
                    position,
                    type_id,
                    length: payload.len()
                }
            );
            assert_eq!(out.get(..payload.len()), Some(payload));
        }
        assert_eq!(
            reader.receive(&mut cursor, &mut out).unwrap(),
            Receive::Pending
        );
        assert_eq!(reader.tail(), writer.tail());
        assert!(!reader.is_closed());
        writer.close();
        assert!(reader.is_closed());
    }
}
