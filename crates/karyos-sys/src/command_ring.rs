// SPDX-License-Identifier: Apache-2.0

//! Single-producer single-consumer command ring (ADR-0047): one per client
//! registration, written by the client and drained by the driver conductor.
//!
//! The data area is `capacity` bytes, a power of two. Positions are
//! monotonic `u64` byte positions computed with checked arithmetic. Records
//! use the broadcast buffer's format: a header word (true length in bytes
//! including the header in the low 32 bits, message type in the high 32
//! bits) followed by payload words; the extent is the length rounded up to 8
//! bytes; a record never wraps, and the producer pads the end of the area
//! with a [`PAD_TYPE`] record whose length and extent fill it exactly.
//!
//! The producer loads `head` (Acquire), checks for room, stores the record
//! words (Relaxed) and then `tail` (Release). The consumer loads `tail`
//! (Acquire), validates and copies one record into private storage, and then
//! stores `head` (Release). The producer never writes words the consumer
//! has not released, so no copy needs revalidation.
//!
//! The producer is a client and is not trusted: the consumer checks every
//! header and position before using it, and a malformed one closes the ring
//! for good. Every word is accessed only atomically.
//!
//! [`RingWords`] holds the protocol over any atomic words (also checked with
//! Loom); [`command_ring`] builds the owned, safe API over heap memory.

use crate::broadcast::{HEADER_LENGTH, PAD_TYPE};
use crate::sync::{AtomicU64, Ordering};

/// Smallest capacity of an owned ring, in bytes.
pub const MIN_CAPACITY: usize = 1024;
/// Words of the trailer: `tail` and `head`, each on its own 128-byte stride;
/// the consumer-written closed flag shares the head's stride.
pub const TRAILER_WORDS: usize = 2 * STRIDE;

/// Bytes of a command ring region's structure for `capacity` bytes of data
/// (R-CORE-34): the size it is created with, after the region header.
/// `None` for a capacity it refuses.
#[must_use]
pub fn structure_length(capacity: usize) -> Option<usize> {
    crate::cnc_store::ring_structure_length(capacity, MIN_CAPACITY, TRAILER_WORDS)
}

const STRIDE: usize = 16;
const TAIL: usize = 0;
const HEAD: usize = STRIDE;
const CLOSED: usize = HEAD + 1;
/// The client heartbeat: a producer-written word on the tail's stride
/// (quantstratum-docs: `karyos/design/required-participant-loss.md`).
const HEARTBEAT: usize = TAIL + 1;

/// Errors of the command ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RingError {
    /// The message type is reserved.
    #[error("message type {type_id:#x} is reserved")]
    ReservedType {
        /// The rejected type.
        type_id: u32,
    },
    /// The record would exceed the maximum record extent.
    #[error("message of {length} bytes exceeds the maximum of {max}")]
    MessageTooLarge {
        /// Payload length.
        length: usize,
        /// Largest payload accepted.
        max: usize,
    },
    /// Not enough released room; retry after the consumer drains.
    #[error("command ring full")]
    Full,
    /// The ring is closed: positions were exhausted or the consumer found a
    /// malformed record. Nothing more is written or read.
    #[error("command ring closed")]
    Closed,
    /// The consumer found a malformed header or position; the ring is now
    /// closed.
    #[error("malformed command ring record at position {position}")]
    Malformed {
        /// The consumer's position.
        position: u64,
    },
    /// Capacity is not a power of two of at least two words, or the record
    /// limit does not fit it.
    #[error("invalid command ring geometry")]
    InvalidGeometry,
    /// The caller's buffer cannot hold the largest payload.
    #[error("buffer of {available} bytes is shorter than the required {required}")]
    BufferTooShort {
        /// Bytes available.
        available: usize,
        /// Bytes required.
        required: usize,
    },
}

/// What a read found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingRead {
    /// Nothing new.
    Pending,
    /// A record was copied.
    Message {
        /// Its position.
        position: u64,
        /// Its type.
        type_id: u32,
        /// Payload bytes copied into the caller's buffer.
        length: usize,
    },
}

/// The words of one command ring.
#[derive(Debug, Clone, Copy)]
pub struct RingWords<'a> {
    data: &'a [AtomicU64],
    trailer: &'a [AtomicU64],
    capacity: u64,
    max_extent: u64,
}

const fn align8(value: u64) -> Option<u64> {
    match value.checked_add(7) {
        Some(sum) => Some(sum & !7),
        None => None,
    }
}

impl<'a> RingWords<'a> {
    /// Wraps the data words and the trailer. `max_extent` bounds a record's
    /// extent in bytes (header included).
    ///
    /// # Errors
    ///
    /// Returns [`RingError::InvalidGeometry`] unless the data area is a power
    /// of two of at least 2 words, the trailer has [`TRAILER_WORDS`] words,
    /// and `max_extent` is a multiple of 8 between 16 and half the
    /// capacity. Padding is always shorter than the record that needs it, so
    /// a padding record plus a record of at most half the capacity always fit
    /// in the area: a record can neither overlap its own padding nor wait
    /// forever for room.
    pub fn new(
        data: &'a [AtomicU64],
        trailer: &'a [AtomicU64],
        max_extent: u64,
    ) -> Result<Self, RingError> {
        let capacity = u64::try_from(data.len())
            .ok()
            .and_then(|words| words.checked_mul(8))
            .ok_or(RingError::InvalidGeometry)?;
        let valid = data.len() >= 2
            && capacity.is_power_of_two()
            && trailer.len() >= TRAILER_WORDS
            && max_extent.is_multiple_of(8)
            && (16..=capacity / 2).contains(&max_extent);
        if !valid {
            return Err(RingError::InvalidGeometry);
        }
        Ok(Self {
            data,
            trailer,
            capacity,
            max_extent,
        })
    }

    /// Largest payload in bytes.
    #[must_use]
    pub fn max_payload(&self) -> usize {
        usize::try_from(self.max_extent - u64::from(HEADER_LENGTH)).unwrap_or(0)
    }

    fn trailer(&self, index: usize) -> Option<&'a AtomicU64> {
        self.trailer.get(index)
    }

    fn word_at(&self, position: u64) -> Option<&'a AtomicU64> {
        let offset = position & (self.capacity - 1);
        self.data.get(usize::try_from(offset / 8).ok()?)
    }

    /// Whether the ring is closed (Acquire).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.trailer(CLOSED)
            .is_none_or(|word| word.load(Ordering::Acquire) != 0)
    }

    /// Advances the client heartbeat by one (Release), returning the new
    /// value. Only the single producer calls this. The heartbeat is a
    /// counter, never a time: each side samples it with its own clock.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::Closed`] once the counter would wrap; the
    /// ring is closed then, since a heartbeat never repeats a value.
    pub fn beat(&self) -> Result<u64, RingError> {
        let word = self.trailer(HEARTBEAT).ok_or(RingError::Closed)?;
        let Some(next) = word.load(Ordering::Relaxed).checked_add(1) else {
            self.close();
            return Err(RingError::Closed);
        };
        word.store(next, Ordering::Release);
        Ok(next)
    }

    /// The client heartbeat (Acquire), as last advanced by the producer.
    #[must_use]
    pub fn heartbeat(&self) -> u64 {
        self.trailer(HEARTBEAT)
            .map_or(0, |word| word.load(Ordering::Acquire))
    }

    /// Closes the ring for good (Release). The consumer calls this when it
    /// stops serving the producer; later writes fail with
    /// [`RingError::Closed`].
    pub fn close(&self) {
        if let Some(word) = self.trailer(CLOSED) {
            word.store(1, Ordering::Release);
        }
    }

    /// Writes one record. Only the single producer calls this.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::ReservedType`], [`RingError::MessageTooLarge`],
    /// [`RingError::Full`] and [`RingError::Closed`]. On error no record or
    /// position is written; position exhaustion or an impossible `head`
    /// sets the persistent closed flag.
    pub fn write(&self, type_id: u32, payload: &[u8]) -> Result<u64, RingError> {
        if self.is_closed() {
            return Err(RingError::Closed);
        }
        if type_id == PAD_TYPE {
            return Err(RingError::ReservedType { type_id });
        }
        let too_large = RingError::MessageTooLarge {
            length: payload.len(),
            max: self.max_payload(),
        };
        let length = u64::try_from(payload.len())
            .ok()
            .and_then(|length| length.checked_add(u64::from(HEADER_LENGTH)))
            .filter(|&length| length <= u64::from(u32::MAX))
            .ok_or(too_large)?;
        let extent = align8(length)
            .filter(|&extent| extent <= self.max_extent)
            .ok_or(too_large)?;
        let (Some(tail_word), Some(head_word)) = (self.trailer(TAIL), self.trailer(HEAD)) else {
            return Err(RingError::InvalidGeometry);
        };
        let tail = tail_word.load(Ordering::Relaxed);
        let head = head_word.load(Ordering::Acquire);
        // Misaligned positions, or a head ahead of the tail or more than a
        // capacity behind it, are impossible in a correct ring: close for
        // good before any store.
        let Some(used) = tail.checked_sub(head).filter(|&used| {
            used <= self.capacity && head.is_multiple_of(8) && tail.is_multiple_of(8)
        }) else {
            self.close();
            return Err(RingError::Closed);
        };
        let to_end = self.capacity - (tail & (self.capacity - 1));
        let padding = if extent > to_end { to_end } else { 0 };
        let Some((start, new_tail)) = tail
            .checked_add(padding)
            .and_then(|start| Some((start, start.checked_add(extent)?)))
        else {
            self.close();
            return Err(RingError::Closed);
        };
        if padding + extent > self.capacity - used {
            return Err(RingError::Full);
        }
        let store = |position: u64, value: u64| {
            if let Some(word) = self.word_at(position) {
                word.store(value, Ordering::Relaxed);
            }
        };
        if padding > 0 {
            store(tail, (u64::from(PAD_TYPE) << 32) | padding);
        }
        store(start, (u64::from(type_id) << 32) | length);
        for (index, chunk) in payload.chunks(8).enumerate() {
            let mut bytes = [0u8; 8];
            if let Some(prefix) = bytes.get_mut(..chunk.len()) {
                prefix.copy_from_slice(chunk);
            }
            let offset = (index as u64 + 1) * 8;
            store(start + offset, u64::from_le_bytes(bytes));
        }
        tail_word.store(new_tail, Ordering::Release);
        Ok(start)
    }

    /// Reads at most one record into `out`, stepping over at most one
    /// padding record. Only the single consumer calls this.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::BufferTooShort`] when `out` cannot hold the
    /// largest payload, [`RingError::Closed`] on a closed ring, and
    /// [`RingError::Malformed`] when the producer wrote an invalid header or
    /// tail, which closes the ring.
    pub fn read(&self, out: &mut [u8]) -> Result<RingRead, RingError> {
        if out.len() < self.max_payload() {
            return Err(RingError::BufferTooShort {
                available: out.len(),
                required: self.max_payload(),
            });
        }
        if self.is_closed() {
            return Err(RingError::Closed);
        }
        let (Some(tail_word), Some(head_word)) = (self.trailer(TAIL), self.trailer(HEAD)) else {
            return Err(RingError::InvalidGeometry);
        };
        for _ in 0..2 {
            let head = head_word.load(Ordering::Relaxed);
            let tail = tail_word.load(Ordering::Acquire);
            let malformed = || {
                self.close();
                Err(RingError::Malformed { position: head })
            };
            // Positions are record boundaries: multiples of 8, the tail at
            // most a capacity ahead of the head. Checked before anything
            // else, including the empty case.
            let Some(available) = tail.checked_sub(head).filter(|&a| {
                a <= self.capacity && head.is_multiple_of(8) && tail.is_multiple_of(8)
            }) else {
                return malformed();
            };
            if available == 0 {
                return Ok(RingRead::Pending);
            }
            let header = self.word_at(head).map_or(0, |w| w.load(Ordering::Relaxed));
            let length = header & u64::from(u32::MAX);
            let type_id = u32::try_from(header >> 32).unwrap_or(PAD_TYPE);
            let to_end = self.capacity - (head & (self.capacity - 1));
            let fits = |extent: u64| {
                if type_id == PAD_TYPE {
                    extent == to_end && length == to_end
                } else {
                    extent <= self.max_extent.min(to_end)
                }
            };
            let Some(extent) = align8(length)
                .filter(|&e| length >= u64::from(HEADER_LENGTH) && fits(e) && e <= available)
            else {
                return malformed();
            };
            let copied = if type_id == PAD_TYPE {
                0
            } else {
                let Some(n) = length
                    .checked_sub(u64::from(HEADER_LENGTH))
                    .and_then(|n| usize::try_from(n).ok())
                else {
                    return malformed();
                };
                self.copy_payload(head, out.get_mut(..n).unwrap_or(&mut []));
                n
            };
            head_word.store(head + extent, Ordering::Release);
            if type_id != PAD_TYPE {
                return Ok(RingRead::Message {
                    position: head,
                    type_id,
                    length: copied,
                });
            }
        }
        Ok(RingRead::Pending)
    }

    fn copy_payload(&self, position: u64, out: &mut [u8]) {
        for (index, chunk) in out.chunks_mut(8).enumerate() {
            let offset = (index as u64 + 1) * 8;
            let word = self
                .word_at(position + offset)
                .map_or(0, |w| w.load(Ordering::Relaxed));
            let bytes = word.to_le_bytes();
            chunk.copy_from_slice(bytes.get(..chunk.len()).unwrap_or(&[]));
        }
    }
}

#[cfg(all(test, not(loom)))]
impl RingWords<'_> {
    /// Test only: overwrites a data word as a faulty producer would.
    fn corrupt(&self, position: u64, value: u64) {
        if let Some(word) = self.word_at(position) {
            word.store(value, Ordering::Relaxed);
        }
    }

    /// Test only: sets the tail and the head as a faulty party would.
    fn set_positions(&self, tail: u64, head: u64) {
        for (index, value) in [(TAIL, tail), (HEAD, head)] {
            if let Some(word) = self.trailer(index) {
                word.store(value, Ordering::Relaxed);
            }
        }
    }

    /// Test only: moves an empty ring's positions to `position`.
    fn seed(&self, position: u64) {
        for index in [TAIL, HEAD] {
            if let Some(word) = self.trailer(index) {
                word.store(position, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(not(loom))]
pub use owned::{RingConsumer, RingMessage, RingProducer, command_ring};

#[cfg(not(loom))]
mod owned {
    use std::sync::Arc;

    use super::{MIN_CAPACITY, RingError, RingRead, RingWords, TRAILER_WORDS};
    use crate::cnc_store::RingStore;
    #[cfg(target_os = "linux")]
    use crate::error::SysError;

    /// A validated store always forms valid ring words.
    #[cfg(target_os = "linux")]
    fn invalid_store() -> SysError {
        SysError::InvalidRegion { address: 0, len: 0 }
    }

    #[derive(Debug)]
    struct Region(RingStore);

    impl Region {
        fn words(&self) -> Result<RingWords<'_>, RingError> {
            RingWords::new(self.0.data(), self.0.trailer(), self.0.max_extent())
        }
    }

    /// Creates a ring of `capacity` bytes (control path) and its only
    /// producer and consumer. The largest record extent is `capacity / 8`.
    ///
    /// # Errors
    ///
    /// Returns [`RingError::InvalidGeometry`] unless `capacity` is a power of
    /// two of at least [`MIN_CAPACITY`].
    pub fn command_ring(capacity: usize) -> Result<(RingProducer, RingConsumer), RingError> {
        let store = RingStore::heap(capacity, MIN_CAPACITY, TRAILER_WORDS)
            .ok_or(RingError::InvalidGeometry)?;
        let region = Arc::new(Region(store));
        Ok((
            RingProducer::over(Arc::clone(&region))?,
            RingConsumer::over(region)?,
        ))
    }

    /// The ring's only producer (not `Clone`).
    #[derive(Debug)]
    pub struct RingProducer {
        region: Arc<Region>,
    }

    impl RingProducer {
        fn over(region: Arc<Region>) -> Result<Self, RingError> {
            region.words()?;
            Ok(Self { region })
        }

        /// The producer of a ring in an attached region (client side,
        /// `quantstratum-docs: karyos/design/ipc-cnc-regions.md`). The driver keeps the consumer.
        ///
        /// # Errors
        ///
        /// Returns [`SysError::InvalidRegion`] unless the region is a command
        /// ring of this layout whose configuration line describes a valid
        /// ring that fills it exactly.
        #[cfg(target_os = "linux")]
        pub fn attach(region: crate::ipc::Region) -> Result<Self, SysError> {
            let store = RingStore::attach(
                region,
                crate::ipc::RegionKind::CommandRing,
                MIN_CAPACITY,
                TRAILER_WORDS,
            )?;
            Self::over(Arc::new(Region(store))).map_err(|_| invalid_store())
        }

        /// Writes one record; returns its position.
        ///
        /// # Errors
        ///
        /// As [`RingWords::write`].
        pub fn write(&mut self, type_id: u32, payload: &[u8]) -> Result<u64, RingError> {
            self.region.words()?.write(type_id, payload)
        }

        /// Largest payload in bytes.
        #[must_use]
        pub fn max_payload(&self) -> usize {
            self.region.words().map_or(0, |words| words.max_payload())
        }

        /// Whether the ring is closed.
        #[must_use]
        pub fn is_closed(&self) -> bool {
            self.region.words().is_ok_and(|words| words.is_closed())
        }

        /// Advances the client heartbeat; see [`RingWords::beat`].
        ///
        /// # Errors
        ///
        /// As [`RingWords::beat`].
        pub fn beat(&mut self) -> Result<u64, RingError> {
            self.region.words()?.beat()
        }

        #[cfg(test)]
        pub(super) fn words_for_test(&self) -> Result<RingWords<'_>, RingError> {
            self.region.words()
        }
    }

    /// A record read by the consumer; the payload borrows its copy buffer.
    #[derive(Debug, PartialEq, Eq)]
    pub struct RingMessage<'a> {
        /// Its position.
        pub position: u64,
        /// Its type.
        pub type_id: u32,
        /// Its payload, valid until the next read.
        pub payload: &'a [u8],
    }

    /// The ring's only consumer (not `Clone`), with a private copy buffer.
    #[derive(Debug)]
    pub struct RingConsumer {
        region: Arc<Region>,
        scratch: Box<[u8]>,
    }

    impl RingConsumer {
        /// The client heartbeat; see [`RingWords::heartbeat`].
        #[must_use]
        pub fn heartbeat(&self) -> u64 {
            self.region.words().map_or(0, |words| words.heartbeat())
        }

        fn over(region: Arc<Region>) -> Result<Self, RingError> {
            let max = region.words()?.max_payload();
            Ok(Self {
                region,
                scratch: vec![0u8; max].into_boxed_slice(),
            })
        }

        /// Creates a ring of `capacity` bytes in a new shared region (driver
        /// side, `quantstratum-docs: karyos/design/ipc-cnc-regions.md`) and returns its consumer.
        /// The client attaches the producer through [`RingConsumer::region`].
        ///
        /// # Errors
        ///
        /// Returns [`SysError::InvalidRegion`] unless `capacity` is a power
        /// of two of at least [`MIN_CAPACITY`], and the errors of
        /// [`crate::ipc::Region::create`].
        #[cfg(target_os = "linux")]
        pub fn create_in(instance: u128, region: u64, capacity: usize) -> Result<Self, SysError> {
            let store = RingStore::create_in(
                instance,
                region,
                crate::ipc::RegionKind::CommandRing,
                capacity,
                MIN_CAPACITY,
                TRAILER_WORDS,
            )?;
            Self::over(Arc::new(Region(store))).map_err(|_| invalid_store())
        }

        /// The shared region, to pass its descriptor; `None` on the heap.
        #[cfg(target_os = "linux")]
        #[must_use]
        pub fn region(&self) -> Option<&crate::ipc::Region> {
            self.region.0.region()
        }

        /// Closes the ring for good, so the producer sees it; see
        /// [`RingWords::close`].
        pub fn close(&mut self) {
            if let Ok(words) = self.region.words() {
                words.close();
            }
        }

        /// Reads at most one record; `Ok(None)` when nothing is pending.
        ///
        /// # Errors
        ///
        /// As [`RingWords::read`].
        pub fn read(&mut self) -> Result<Option<RingMessage<'_>>, RingError> {
            let words = self.region.words()?;
            Ok(match words.read(&mut self.scratch)? {
                RingRead::Pending => None,
                RingRead::Message {
                    position,
                    type_id,
                    length,
                } => Some(RingMessage {
                    position,
                    type_id,
                    payload: self.scratch.get(..length).unwrap_or(&[]),
                }),
            })
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::broadcast::PAD_TYPE;

    fn message(sequence: u32, length: usize) -> Vec<u8> {
        (0..length).map(|i| (i as u8) ^ (sequence as u8)).collect()
    }

    #[test]
    fn fifo_lengths_padding_and_full() {
        let (mut producer, mut consumer) = command_ring(1024).unwrap();
        assert_eq!(producer.max_payload(), 120);
        for (sequence, length) in [(1u32, 0usize), (2, 1), (3, 7), (4, 8), (5, 9), (6, 120)] {
            producer
                .write(sequence, &message(sequence, length))
                .unwrap();
        }
        for (sequence, length) in [(1u32, 0usize), (2, 1), (3, 7), (4, 8), (5, 9), (6, 120)] {
            let read = consumer.read().unwrap().unwrap();
            assert_eq!(
                (read.type_id, read.payload),
                (sequence, &message(sequence, length)[..])
            );
        }
        assert_eq!(consumer.read().unwrap(), None);

        // 100-byte payloads (extent 112): fill until Full, drain, repeat
        // across many wraps with padding.
        let mut next_write = 0u32;
        let mut next_read = 0u32;
        while next_read < 200 {
            match producer.write(next_write, &message(next_write, 100)) {
                Ok(_) => next_write += 1,
                Err(RingError::Full) => {
                    let read = consumer.read().unwrap().unwrap();
                    assert_eq!(read.type_id, next_read);
                    assert_eq!(read.payload, &message(next_read, 100)[..]);
                    next_read += 1;
                }
                Err(other) => panic!("unexpected {other}"),
            }
        }
        assert_eq!(
            producer.write(PAD_TYPE, b"x"),
            Err(RingError::ReservedType { type_id: PAD_TYPE })
        );
        assert!(matches!(
            producer.write(1, &[0; 121]),
            Err(RingError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn a_malformed_header_closes_the_ring() {
        let (mut producer, mut consumer) = command_ring(1024).unwrap();
        let position = producer.write(1, b"ok").unwrap();
        let words = producer.words_for_test().unwrap();
        // A faulty producer rewrites the header with a length past the tail.
        words.corrupt(position, (1u64 << 32) | 4000);
        assert_eq!(consumer.read(), Err(RingError::Malformed { position }));
        assert!(producer.is_closed());
        assert_eq!(consumer.read(), Err(RingError::Closed));
        assert_eq!(producer.write(1, b"x"), Err(RingError::Closed));
    }

    #[test]
    fn misaligned_or_impossible_positions_close_the_ring() {
        // A misaligned tail: rejected before delivery or any head advance.
        let (producer, mut consumer) = command_ring(1024).unwrap();
        let words = producer.words_for_test().unwrap();
        words.corrupt(0, (7u64 << 32) | 8);
        words.set_positions(9, 0);
        assert_eq!(consumer.read(), Err(RingError::Malformed { position: 0 }));
        assert!(producer.is_closed());

        // A head ahead of the tail: the producer closes the ring for good,
        // and restoring the head does not reopen it.
        let (mut producer, _consumer) = command_ring(1024).unwrap();
        let words = producer.words_for_test().unwrap();
        words.set_positions(0, 8);
        assert_eq!(producer.write(1, b"x"), Err(RingError::Closed));
        let words = producer.words_for_test().unwrap();
        words.set_positions(0, 0);
        assert_eq!(producer.write(1, b"x"), Err(RingError::Closed));
        assert!(producer.is_closed());

        // A misaligned tail: the producer writes nothing and closes.
        let (mut producer, _consumer) = command_ring(1024).unwrap();
        producer.words_for_test().unwrap().set_positions(9, 0);
        assert_eq!(producer.write(1, b"x"), Err(RingError::Closed));
        assert!(producer.is_closed());
    }

    #[test]
    fn a_record_larger_than_half_the_ring_is_rejected_at_creation() {
        let data: Vec<AtomicU64> = (0..8).map(|_| AtomicU64::new(0)).collect();
        let trailer: Vec<AtomicU64> = (0..TRAILER_WORDS).map(|_| AtomicU64::new(0)).collect();
        // 64-byte ring: a 64-byte record could need 48 bytes of padding and
        // then never fit.
        assert_eq!(
            RingWords::new(&data, &trailer, 64).err(),
            Some(RingError::InvalidGeometry)
        );
        let words = RingWords::new(&data, &trailer, 32).unwrap();
        let mut out = [0u8; 24];
        // Extents 24 and 16 leave the tail at offset 40, 24 bytes before
        // the end; drain both.
        words.write(1, &[1; 16]).unwrap();
        words.write(2, &[2; 8]).unwrap();
        for _ in 0..2 {
            assert!(matches!(words.read(&mut out), Ok(RingRead::Message { .. })));
        }
        // The largest record (extent 32) needs 24 bytes of padding, and the
        // two still fit in the empty ring.
        assert_eq!(words.write(3, &[3; 24]), Ok(64));
        assert_eq!(
            words.read(&mut out),
            Ok(RingRead::Message {
                position: 64,
                type_id: 3,
                length: 24
            })
        );
    }

    #[test]
    fn position_exhaustion_closes_the_ring() {
        let (mut producer, mut consumer) = command_ring(1024).unwrap();
        producer.words_for_test().unwrap().seed(u64::MAX - 15);
        assert_eq!(producer.write(1, &[0; 17]), Err(RingError::Closed));
        assert!(producer.is_closed());
        assert_eq!(producer.write(1, &[]), Err(RingError::Closed));
        assert_eq!(consumer.read(), Err(RingError::Closed));
    }

    #[test]
    fn concurrent_producer_and_consumer() {
        let (mut producer, mut consumer) = command_ring(1024).unwrap();
        let total = if cfg!(miri) { 200u32 } else { 50_000 };
        std::thread::scope(|scope| {
            scope.spawn(move || {
                for sequence in 0..total {
                    let data = message(sequence, (sequence % 113) as usize);
                    while producer.write(sequence, &data) == Err(RingError::Full) {
                        std::thread::yield_now();
                    }
                }
            });
            scope.spawn(move || {
                let mut next = 0;
                while next < total {
                    match consumer.read().unwrap() {
                        Some(read) => {
                            assert_eq!(read.type_id, next);
                            assert_eq!(read.payload, &message(next, (next % 113) as usize)[..]);
                            next += 1;
                        }
                        None => std::thread::yield_now(),
                    }
                }
            });
        });
    }

    #[test]
    fn the_heartbeat_counts_and_leaves_the_records_alone() {
        let (mut producer, mut consumer) = command_ring(1024).unwrap();
        assert_eq!(consumer.heartbeat(), 0);
        producer.write(1, b"x").unwrap();
        assert_eq!(producer.beat(), Ok(1));
        assert_eq!(producer.beat(), Ok(2));
        assert_eq!(consumer.heartbeat(), 2);
        let read = consumer.read().unwrap().unwrap();
        assert_eq!((read.type_id, read.payload), (1, &b"x"[..]));
        // A wrapped counter would repeat a value: the ring closes instead.
        let words = producer.words_for_test().unwrap();
        words
            .trailer(HEARTBEAT)
            .unwrap()
            .store(u64::MAX, Ordering::Relaxed);
        assert_eq!(producer.beat(), Err(RingError::Closed));
        assert!(producer.is_closed());
    }
}

/// Consumer properties over untrusted producer memory (issue #121, the
/// control protocol harness standing in for fuzzing, #11 option B), in the
/// style of the frame parser's: whatever words and positions a faulty or
/// hostile client stores, the consumer never panics or reads outside the
/// data area, every record it delivers satisfies the producer's framing
/// rules, and it closes the ring rather than stall; a well-formed ring
/// delivers exactly what was written, in order.
#[cfg(all(test, not(loom)))]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod properties {
    use std::collections::VecDeque;

    use proptest::prelude::*;

    use super::*;

    /// A ring of `2^log_words` data words and its trailer.
    struct Memory {
        data: Vec<AtomicU64>,
        trailer: Vec<AtomicU64>,
        max_extent: u64,
    }

    impl Memory {
        fn new(log_words: u32, extent_words: u64) -> Self {
            let words = 1usize << log_words;
            let capacity = words as u64 * 8;
            // A multiple of 8 between 16 and half the capacity.
            let max_extent = (extent_words * 8).clamp(16, capacity / 2);
            Self {
                data: (0..words).map(|_| AtomicU64::new(0)).collect(),
                trailer: (0..TRAILER_WORDS).map(|_| AtomicU64::new(0)).collect(),
                max_extent,
            }
        }

        fn words(&self) -> RingWords<'_> {
            RingWords::new(&self.data, &self.trailer, self.max_extent).unwrap()
        }
    }

    /// Geometry: 4 to 128 data words, and the record limit in words.
    fn geometry() -> impl Strategy<Value = (u32, u64)> {
        (2u32..=7, 2u64..=64)
    }

    /// A data word as a hostile producer might store it: often a header with
    /// a plausible length (or the padding type), sometimes anything.
    fn hostile_word() -> impl Strategy<Value = u64> {
        prop_oneof![
            2 => any::<u64>(),
            1 => (any::<u32>(), 0u64..=1100).prop_map(|(type_id, length)| {
                (u64::from(type_id) << 32) | length
            }),
            1 => (0u64..=1100).prop_map(|length| (u64::from(PAD_TYPE) << 32) | length),
            6 => (0u32..=4, 8u64..=64).prop_map(|(type_id, length)| {
                (u64::from(type_id) << 32) | length
            }),
            1 => Just(0u64),
        ]
    }

    /// A position: from the start, anywhere, or near the end of the `u64`
    /// range.
    fn base() -> impl Strategy<Value = u64> {
        prop_oneof![0u64..=4096, any::<u64>(), (u64::MAX - 4096)..=u64::MAX]
    }

    fn load(words: &RingWords<'_>, position: u64) -> u64 {
        words.word_at(position).unwrap().load(Ordering::Relaxed)
    }

    fn positions(words: &RingWords<'_>) -> (u64, u64) {
        let tail = words.trailer(TAIL).unwrap().load(Ordering::Relaxed);
        let head = words.trailer(HEAD).unwrap().load(Ordering::Relaxed);
        (tail, head)
    }

    /// One record the consumer delivered.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Delivered {
        position: u64,
        type_id: u32,
        payload: Vec<u8>,
    }

    /// How draining ended.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum End {
        /// Every published byte was consumed.
        Drained,
        /// The consumer found a malformed record or position.
        Malformed,
    }

    /// Reads until the ring is drained or closed, checking every step
    /// against the framing rules; returns what was delivered and how it
    /// ended. Each read either consumes at least 8 bytes or ends, so the
    /// loop is bounded by the published bytes.
    fn drain(words: &RingWords<'_>) -> Result<(Vec<Delivered>, End), TestCaseError> {
        let capacity = words.capacity;
        let max_payload = words.max_payload();
        let mut out = vec![0u8; max_payload];
        let mut delivered = Vec::new();
        let (tail, start) = positions(words);
        let limit = tail.wrapping_sub(start).min(capacity) / 8 + 3;
        for _ in 0..limit {
            let (tail, head) = positions(words);
            match words.read(&mut out) {
                Ok(RingRead::Message {
                    position,
                    type_id,
                    length,
                }) => {
                    let (_, after) = positions(words);
                    let extent = align8(length as u64 + 8).unwrap();
                    prop_assert_ne!(type_id, PAD_TYPE);
                    prop_assert!(length <= max_payload);
                    prop_assert!(extent <= words.max_extent);
                    prop_assert!(position >= head && position.is_multiple_of(8));
                    prop_assert_eq!(position + extent, after);
                    prop_assert!(after <= tail);
                    // A record never wraps around the end of the area.
                    prop_assert!((position & (capacity - 1)) + extent <= capacity);
                    // The header names the record, and the payload is the
                    // words after it.
                    prop_assert_eq!(
                        load(words, position),
                        (u64::from(type_id) << 32) | (length as u64 + 8)
                    );
                    let expected: Vec<u8> = (0..extent / 8 - 1)
                        .flat_map(|index| load(words, position + 8 + index * 8).to_le_bytes())
                        .take(length)
                        .collect();
                    prop_assert_eq!(&out[..length], &expected[..]);
                    // Anything between the old head and the record is one
                    // padding record that reaches the end of the area.
                    if position != head {
                        prop_assert_eq!(position & (capacity - 1), 0);
                        prop_assert_eq!(load(words, head) >> 32, u64::from(PAD_TYPE));
                    }
                    delivered.push(Delivered {
                        position,
                        type_id,
                        payload: expected,
                    });
                }
                Ok(RingRead::Pending) => {
                    let (_, after) = positions(words);
                    prop_assert!(head <= after && after <= tail);
                    if after == tail {
                        return Ok((delivered, End::Drained));
                    }
                    // Only stepping over padding leaves bytes pending.
                    prop_assert!(after > head);
                }
                Err(RingError::Malformed { position }) => {
                    let (_, after) = positions(words);
                    prop_assert_eq!(position, after);
                    prop_assert!(words.is_closed());
                    prop_assert_eq!(words.read(&mut out), Err(RingError::Closed));
                    return Ok((delivered, End::Malformed));
                }
                Err(other) => prop_assert!(false, "unexpected read error {other:?}"),
            }
        }
        Err(TestCaseError::fail(
            "the consumer neither drained nor closed the ring",
        ))
    }

    /// One producer step of a model run.
    #[derive(Debug, Clone)]
    enum Step {
        Write { type_id: u32, payload: Vec<u8> },
        Read,
    }

    /// A write (mostly small payloads, sometimes past any limit, sometimes
    /// of the reserved type) or, with weight `reads` against 4, a read.
    fn step(reads: u32) -> impl Strategy<Value = Step> {
        let payload = prop_oneof![0usize..=24, 0usize..=520]
            .prop_flat_map(|length| prop::collection::vec(any::<u8>(), length));
        prop_oneof![
            4 => (
                prop_oneof![8 => 0u32..=8, 4 => any::<u32>(), 1 => Just(PAD_TYPE)],
                payload,
            )
                .prop_map(|(type_id, payload)| Step::Write { type_id, payload }),
            reads => Just(Step::Read),
        ]
    }

    /// Runs `steps` against a ring whose positions start at `seed`, checking
    /// writes and reads against a FIFO model; returns the records written
    /// and not yet read, with their positions.
    fn run(
        words: &RingWords<'_>,
        seed: u64,
        steps: &[Step],
    ) -> Result<VecDeque<Delivered>, TestCaseError> {
        words.seed(seed);
        let max_payload = words.max_payload();
        let mut out = vec![0u8; max_payload];
        let mut model: VecDeque<Delivered> = VecDeque::new();
        for step in steps {
            match step {
                Step::Write { type_id, payload } => match words.write(*type_id, payload) {
                    Ok(position) => {
                        prop_assert_ne!(*type_id, PAD_TYPE);
                        prop_assert!(payload.len() <= max_payload);
                        model.push_back(Delivered {
                            position,
                            type_id: *type_id,
                            payload: payload.clone(),
                        });
                    }
                    Err(RingError::ReservedType { type_id: rejected }) => {
                        prop_assert_eq!(rejected, PAD_TYPE);
                        prop_assert_eq!(*type_id, PAD_TYPE);
                    }
                    Err(RingError::MessageTooLarge { length, max }) => {
                        prop_assert_eq!(length, payload.len());
                        prop_assert_eq!(max, max_payload);
                        prop_assert!(payload.len() > max_payload);
                    }
                    // Any record within the limit fits an empty ring.
                    Err(RingError::Full) => prop_assert!(!model.is_empty()),
                    Err(other) => prop_assert!(false, "unexpected write error {other:?}"),
                },
                Step::Read => match words.read(&mut out) {
                    Ok(RingRead::Message {
                        position,
                        type_id,
                        length,
                    }) => {
                        let expected = model.pop_front();
                        prop_assert_eq!(
                            Some(Delivered {
                                position,
                                type_id,
                                payload: out[..length].to_vec(),
                            }),
                            expected
                        );
                    }
                    Ok(RingRead::Pending) => prop_assert!(model.is_empty()),
                    Err(other) => prop_assert!(false, "unexpected read error {other:?}"),
                },
            }
        }
        Ok(model)
    }

    proptest! {
        #![proptest_config(crate::receive::tests_config())]

        /// Arbitrary data words and positions: no panic, no read outside
        /// the area, only well-framed records delivered, and the consumer
        /// either drains the published bytes or closes the ring.
        #[test]
        fn a_consumer_survives_any_producer_memory(
            ((log_words, extent_words), contents) in geometry().prop_flat_map(|geometry| {
                (Just(geometry), prop::collection::vec(hostile_word(), 1usize << geometry.0))
            }),
            head in prop_oneof![3 => base().prop_map(|position| position & !7), 1 => base()],
            // Mostly whole words up to the capacity (taken modulo the word
            // count), sometimes any distance.
            published in prop_oneof![6 => (0u64..=128).prop_map(Ok), 2 => any::<u64>().prop_map(Err)],
        ) {
            let memory = Memory::new(log_words, extent_words);
            let words = memory.words();
            for (word, value) in memory.data.iter().zip(&contents) {
                word.store(*value, Ordering::Relaxed);
            }
            let published = published
                .map_or_else(|raw| raw, |count| count % (words.capacity / 8 + 1) * 8);
            let tail = head.wrapping_add(published);
            words.set_positions(tail, head);
            let valid = tail >= head
                && tail - head <= words.capacity
                && head.is_multiple_of(8)
                && tail.is_multiple_of(8);
            let (_, end) = drain(&words)?;
            // Impossible positions are refused before anything is read.
            if !valid {
                prop_assert_eq!(end, End::Malformed);
            }
        }

        /// A correct producer and consumer, interleaved from any starting
        /// position: every record is delivered once, in order, unchanged.
        #[test]
        fn written_records_are_read_back_in_order(
            (log_words, extent_words) in geometry(),
            seed in base().prop_map(|position| position.min(u64::MAX - (1 << 20)) & !7),
            steps in prop::collection::vec(step(2), 1..64),
        ) {
            let memory = Memory::new(log_words, extent_words);
            let words = memory.words();
            let pending = run(&words, seed, &steps)?;
            let (delivered, end) = drain(&words)?;
            prop_assert_eq!(end, End::Drained);
            prop_assert_eq!(delivered, Vec::from(pending));
        }

        /// A well-formed ring with one data word overwritten: records that
        /// end before the overwritten word are delivered unchanged, the rest
        /// only as well-framed records, and a word outside the published
        /// bytes changes nothing.
        #[test]
        fn one_corrupted_word_only_affects_what_follows_it(
            (log_words, extent_words) in geometry(),
            seed in base().prop_map(|position| position.min(u64::MAX - (1 << 20)) & !7),
            steps in prop::collection::vec(step(1), 1..64),
            index in any::<prop::sample::Index>(),
            corruption in prop_oneof![
                hostile_word().prop_map(|value| (value, true)),
                (0u32..64).prop_map(|bit| (1u64 << bit, false)),
            ],
        ) {
            let memory = Memory::new(log_words, extent_words);
            let words = memory.words();
            let pending = run(&words, seed, &steps)?;
            let (tail, head) = positions(&words);
            let capacity = words.capacity;
            let offset = index.index(memory.data.len()) as u64 * 8;
            let original = load(&words, offset);
            let (value, replace) = corruption;
            let value = if replace { value } else { original ^ value };
            words.corrupt(offset, value);
            // The stream position of the overwritten word, if published.
            let corrupted = head + (offset.wrapping_sub(head) & (capacity - 1));
            let (delivered, end) = drain(&words)?;
            if corrupted >= tail || value == original {
                prop_assert_eq!(end, End::Drained);
                prop_assert_eq!(delivered, Vec::from(pending));
            } else {
                let intact: Vec<Delivered> = pending
                    .into_iter()
                    .take_while(|record| {
                        record.position + align8(record.payload.len() as u64 + 8).unwrap()
                            <= corrupted
                    })
                    .collect();
                prop_assert!(delivered.len() >= intact.len());
                prop_assert_eq!(&delivered[..intact.len()], &intact[..]);
            }
        }
    }
}
