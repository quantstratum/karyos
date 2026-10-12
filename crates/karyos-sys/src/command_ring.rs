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

const STRIDE: usize = 16;
const TAIL: usize = 0;
const HEAD: usize = STRIDE;
const CLOSED: usize = HEAD + 1;

/// Errors of the command ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
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
    use crate::atomic_view::HeapWords;

    #[derive(Debug)]
    struct Region {
        data: HeapWords,
        trailer: HeapWords,
        max_extent: u64,
    }

    impl Region {
        fn words(&self) -> Result<RingWords<'_>, RingError> {
            RingWords::new(
                self.data.words().as_slice(),
                self.trailer.words().as_slice(),
                self.max_extent,
            )
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
        if capacity < MIN_CAPACITY || !capacity.is_power_of_two() {
            return Err(RingError::InvalidGeometry);
        }
        let data = HeapWords::zeroed(capacity / 8).map_err(|_| RingError::InvalidGeometry)?;
        let trailer = HeapWords::zeroed(TRAILER_WORDS).map_err(|_| RingError::InvalidGeometry)?;
        let max_extent = u64::try_from(capacity / 8).map_err(|_| RingError::InvalidGeometry)?;
        let region = Arc::new(Region {
            data,
            trailer,
            max_extent,
        });
        let max = region.words()?.max_payload();
        Ok((
            RingProducer {
                region: Arc::clone(&region),
            },
            RingConsumer {
                region,
                scratch: vec![0u8; max].into_boxed_slice(),
            },
        ))
    }

    /// The ring's only producer (not `Clone`).
    #[derive(Debug)]
    pub struct RingProducer {
        region: Arc<Region>,
    }

    impl RingProducer {
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
}
