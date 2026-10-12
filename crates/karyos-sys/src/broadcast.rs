// SPDX-License-Identifier: Apache-2.0

//! Broadcast buffer (SPEC.md §3, CnC file): one writer, any number of
//! readers that never back-pressure it. A slow reader is lapped and told so.
//!
//! The data area is `capacity` bytes, a power of two. Positions are
//! monotonic `u64` byte positions computed with checked arithmetic. A record
//! is a header word (true length in bytes including the header in the low
//! 32 bits, message type in the high 32 bits) followed by payload words; its
//! extent is the length rounded up to 8 bytes. A record never wraps: the
//! writer pads the end of the area with a [`PAD_TYPE`] record when needed.
//!
//! The writer stores `tail_intent` (Relaxed), issues a Release fence, writes
//! the record words (Relaxed), stores `latest` (Relaxed) and then `tail`
//! (Release). A reader loads `tail` (Acquire), copies the record (Relaxed)
//! into private storage, issues an Acquire fence and loads `tail_intent`
//! (Relaxed). The copy is used only if `tail_intent - cursor <= capacity`:
//! any overwrite of the copied words that the reader could have observed
//! makes this check fail, while an unchanged, coherent old copy may be
//! accepted.
//!
//! Every word is accessed only atomically, so a lapped reader copies stale or
//! mixed values and discards them, never a data race.
//!
//! [`BroadcastWords`] holds the protocol over any atomic words (also checked
//! with Loom); [`broadcast`] builds the owned, safe API over heap memory.

use crate::sync::{AtomicU64, Ordering, fence};

/// Message type of a padding record; not available to applications.
pub const PAD_TYPE: u32 = u32::MAX;
/// Bytes of a record header.
pub const HEADER_LENGTH: u32 = 8;
/// Smallest capacity of an owned buffer, in bytes.
pub const MIN_CAPACITY: usize = 1024;
/// Words of the trailer: `tail_intent`, `tail` and `latest`, each on its own
/// 128-byte stride.
pub const TRAILER_WORDS: usize = 3 * STRIDE;

const STRIDE: usize = 16;
const TAIL_INTENT: usize = 0;
const TAIL: usize = STRIDE;
const LATEST: usize = 2 * STRIDE;
/// Written only by the writer, so it shares the intent's stride.
const CLOSED: usize = TAIL_INTENT + 1;

/// Errors of the broadcast buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BroadcastError {
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
    /// Positions would exceed `u64::MAX`. The buffer is closed for good:
    /// this and every later transmit fail without writing.
    #[error("broadcast positions exhausted; the buffer is closed")]
    PositionsExhausted,
    /// Capacity is not a power of two of at least the minimum, or the
    /// record limit does not fit it.
    #[error("invalid broadcast geometry")]
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

/// What a receive found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receive {
    /// Nothing new.
    Pending,
    /// The reader was overrun; records from `lost_from` up to the rejoin
    /// position were not delivered.
    Lapped {
        /// The cursor when the lap was detected.
        lost_from: u64,
        /// The position the reader rejoined at.
        rejoined_at: u64,
    },
    /// A validated message was copied.
    Message {
        /// Its position.
        position: u64,
        /// Its type.
        type_id: u32,
        /// Payload bytes copied into the caller's buffer.
        length: usize,
    },
}

/// The words of one broadcast buffer.
#[derive(Debug, Clone, Copy)]
pub struct BroadcastWords<'a> {
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

impl<'a> BroadcastWords<'a> {
    /// Wraps the data words and the trailer. `max_extent` bounds a record's
    /// extent in bytes (header included).
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastError::InvalidGeometry`] unless the data area is a
    /// power of two of at least 2 words, the trailer has
    /// [`TRAILER_WORDS`] words, and `max_extent` is a multiple of 8 between
    /// 16 and the capacity.
    pub fn new(
        data: &'a [AtomicU64],
        trailer: &'a [AtomicU64],
        max_extent: u64,
    ) -> Result<Self, BroadcastError> {
        let capacity = u64::try_from(data.len())
            .ok()
            .and_then(|words| words.checked_mul(8))
            .ok_or(BroadcastError::InvalidGeometry)?;
        let valid = data.len() >= 2
            && capacity.is_power_of_two()
            && trailer.len() >= TRAILER_WORDS
            && max_extent.is_multiple_of(8)
            && (16..=capacity).contains(&max_extent);
        if !valid {
            return Err(BroadcastError::InvalidGeometry);
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

    /// Whether position exhaustion has closed the buffer (Acquire). Readers
    /// can still drain what was committed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.trailer(CLOSED)
            .is_some_and(|word| word.load(Ordering::Acquire) != 0)
    }

    /// The committed tail (Acquire): where a new reader starts.
    #[must_use]
    pub fn tail(&self) -> u64 {
        self.trailer(TAIL)
            .map_or(0, |word| word.load(Ordering::Acquire))
    }

    /// Writes one message. Only the single writer calls this.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastError::ReservedType`],
    /// [`BroadcastError::MessageTooLarge`] and
    /// [`BroadcastError::PositionsExhausted`]; nothing is written on error.
    /// Exhaustion closes the buffer: every later transmit fails too.
    pub fn transmit(&self, type_id: u32, payload: &[u8]) -> Result<u64, BroadcastError> {
        if self.is_closed() {
            return Err(BroadcastError::PositionsExhausted);
        }
        if type_id == PAD_TYPE {
            return Err(BroadcastError::ReservedType { type_id });
        }
        let too_large = BroadcastError::MessageTooLarge {
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
        let (Some(intent), Some(tail_word), Some(latest)) = (
            self.trailer(TAIL_INTENT),
            self.trailer(TAIL),
            self.trailer(LATEST),
        ) else {
            return Err(BroadcastError::InvalidGeometry);
        };
        let tail = tail_word.load(Ordering::Relaxed);
        let to_end = self.capacity - (tail & (self.capacity - 1));
        let padding = if extent > to_end { to_end } else { 0 };
        let Some((start, new_tail)) = tail
            .checked_add(padding)
            .and_then(|start| Some((start, start.checked_add(extent)?)))
        else {
            if let Some(closed) = self.trailer(CLOSED) {
                closed.store(1, Ordering::Release);
            }
            return Err(BroadcastError::PositionsExhausted);
        };

        intent.store(new_tail, Ordering::Relaxed);
        fence(Ordering::Release);
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
        latest.store(start, Ordering::Relaxed);
        tail_word.store(new_tail, Ordering::Release);
        Ok(start)
    }

    /// Receives at most one message into `out`, stepping over at most one
    /// padding record. `cursor` is the reader's private position; it never
    /// moves backward.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastError::BufferTooShort`] when `out` cannot hold the
    /// largest payload; the cursor is unchanged.
    pub fn receive(&self, cursor: &mut u64, out: &mut [u8]) -> Result<Receive, BroadcastError> {
        if out.len() < self.max_payload() {
            return Err(BroadcastError::BufferTooShort {
                available: out.len(),
                required: self.max_payload(),
            });
        }
        for _ in 0..2 {
            let tail = self.tail();
            if tail <= *cursor {
                return Ok(Receive::Pending);
            }
            if tail - *cursor > self.capacity {
                return Ok(self.rejoin(cursor));
            }
            let position = *cursor;
            let header = self
                .word_at(position)
                .map_or(0, |w| w.load(Ordering::Relaxed));
            let length = header & u64::from(u32::MAX);
            let type_id = u32::try_from(header >> 32).unwrap_or(PAD_TYPE);
            let to_end = self.capacity - (position & (self.capacity - 1));
            // Checked before any copy: a lapped header can hold arbitrary
            // bits. A PAD fills exactly the rest of the area; a record fits
            // both the record limit and the rest of the area.
            let fits = |extent: u64| {
                if type_id == PAD_TYPE {
                    extent == to_end
                } else {
                    extent <= self.max_extent.min(to_end)
                }
            };
            let extent = align8(length)
                .filter(|&e| length >= u64::from(HEADER_LENGTH) && fits(e))
                .filter(|&e| position.checked_add(e).is_some_and(|end| end <= tail));
            let payload_length = length.saturating_sub(u64::from(HEADER_LENGTH));
            let copied = match (extent, usize::try_from(payload_length)) {
                (Some(_), Ok(n)) if type_id != PAD_TYPE => {
                    self.copy_payload(position, out.get_mut(..n).unwrap_or(&mut []));
                    n
                }
                _ => 0,
            };
            fence(Ordering::Acquire);
            let intent = self
                .trailer(TAIL_INTENT)
                .map_or(u64::MAX, |word| word.load(Ordering::Relaxed));
            let overwritten = intent
                .checked_sub(position)
                .is_none_or(|distance| distance > self.capacity);
            let Some(extent) = extent.filter(|_| !overwritten) else {
                // Overwritten during the copy, or a malformed header: treat
                // as a lap and rejoin.
                return Ok(self.rejoin(cursor));
            };
            *cursor = position + extent;
            if type_id != PAD_TYPE {
                return Ok(Receive::Message {
                    position,
                    type_id,
                    length: copied,
                });
            }
        }
        Ok(Receive::Pending)
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

    /// Moves a lapped reader forward. `latest` (the start of the most
    /// recently written non-PAD record) is only a candidate: it is used if
    /// it lies in `[intent - capacity, tail)` for a fresh Acquire load of
    /// `tail` and a later load of `tail_intent`, so it is committed and not
    /// yet overwritten. Otherwise the reader moves to that `tail`, or to the
    /// intent if the fresh `tail` is still at or behind the cursor (a
    /// Relaxed observation of an overwrite does not make the newer `tail`
    /// visible). Every position used is a record boundary, and the cursor
    /// never moves backward.
    fn rejoin(&self, cursor: &mut u64) -> Receive {
        let lost_from = *cursor;
        let tail = self.tail();
        let latest = self
            .trailer(LATEST)
            .map_or(tail, |word| word.load(Ordering::Relaxed));
        let intent = self
            .trailer(TAIL_INTENT)
            .map_or(tail, |word| word.load(Ordering::Relaxed))
            .max(tail);
        let floor = intent.saturating_sub(self.capacity);
        let mut target = if (floor..tail).contains(&latest) {
            latest
        } else {
            tail
        };
        if target <= *cursor {
            target = intent;
        }
        *cursor = target.max(*cursor);
        Receive::Lapped {
            lost_from,
            rejoined_at: *cursor,
        }
    }
}

#[cfg(all(test, not(loom)))]
impl BroadcastWords<'_> {
    /// Test only: moves an empty buffer's positions to `position`, a
    /// multiple of 8.
    fn seed(&self, position: u64) {
        for index in [TAIL_INTENT, TAIL, LATEST] {
            if let Some(word) = self.trailer(index) {
                word.store(position, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(not(loom))]
pub use owned::{BroadcastReceiver, BroadcastTransmitter, broadcast};

#[cfg(not(loom))]
mod owned {
    use std::sync::Arc;

    use super::{BroadcastError, BroadcastWords, MIN_CAPACITY, Receive, TRAILER_WORDS};
    use crate::atomic_view::HeapWords;

    #[derive(Debug)]
    struct Region {
        data: HeapWords,
        trailer: HeapWords,
        max_extent: u64,
    }

    impl Region {
        fn words(&self) -> Result<BroadcastWords<'_>, BroadcastError> {
            BroadcastWords::new(
                self.data.words().as_slice(),
                self.trailer.words().as_slice(),
                self.max_extent,
            )
        }
    }

    /// Creates a buffer of `capacity` bytes (control path) and its only
    /// transmitter. The largest record extent is `capacity / 8`.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastError::InvalidGeometry`] unless `capacity` is a
    /// power of two of at least [`MIN_CAPACITY`].
    pub fn broadcast(capacity: usize) -> Result<BroadcastTransmitter, BroadcastError> {
        if capacity < MIN_CAPACITY || !capacity.is_power_of_two() {
            return Err(BroadcastError::InvalidGeometry);
        }
        let data = HeapWords::zeroed(capacity / 8).map_err(|_| BroadcastError::InvalidGeometry)?;
        let trailer =
            HeapWords::zeroed(TRAILER_WORDS).map_err(|_| BroadcastError::InvalidGeometry)?;
        let max_extent =
            u64::try_from(capacity / 8).map_err(|_| BroadcastError::InvalidGeometry)?;
        let region = Arc::new(Region {
            data,
            trailer,
            max_extent,
        });
        region.words()?;
        Ok(BroadcastTransmitter { region })
    }

    /// The buffer's only writer (not `Clone`).
    #[derive(Debug)]
    pub struct BroadcastTransmitter {
        region: Arc<Region>,
    }

    impl BroadcastTransmitter {
        /// Writes one message; returns its position.
        ///
        /// # Errors
        ///
        /// As [`BroadcastWords::transmit`].
        pub fn transmit(&mut self, type_id: u32, payload: &[u8]) -> Result<u64, BroadcastError> {
            self.region.words()?.transmit(type_id, payload)
        }

        /// Largest payload in bytes.
        #[must_use]
        pub fn max_payload(&self) -> usize {
            self.region.words().map_or(0, |words| words.max_payload())
        }

        /// Whether position exhaustion has closed the buffer.
        #[must_use]
        pub fn is_closed(&self) -> bool {
            self.region.words().map_or(true, |words| words.is_closed())
        }

        #[cfg(test)]
        pub(super) fn seed(&self, position: u64) {
            if let Ok(words) = self.region.words() {
                words.seed(position);
            }
        }

        /// A new reader starting at the committed tail (control path:
        /// allocates its copy buffer).
        #[must_use]
        pub fn receiver(&self) -> BroadcastReceiver {
            let (cursor, max) = self
                .region
                .words()
                .map_or((0, 0), |words| (words.tail(), words.max_payload()));
            BroadcastReceiver {
                region: Arc::clone(&self.region),
                cursor,
                scratch: vec![0u8; max].into_boxed_slice(),
            }
        }
    }

    /// A reader with a private cursor and copy buffer.
    #[derive(Debug)]
    pub struct BroadcastReceiver {
        region: Arc<Region>,
        cursor: u64,
        scratch: Box<[u8]>,
    }

    /// A received item; a message's payload borrows the receiver's copy.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Received<'a> {
        /// Nothing new.
        Pending,
        /// Overrun; see [`Receive::Lapped`].
        Lapped {
            /// The cursor when the lap was detected.
            lost_from: u64,
            /// The position the reader rejoined at.
            rejoined_at: u64,
        },
        /// A validated message.
        Message {
            /// Its position.
            position: u64,
            /// Its type.
            type_id: u32,
            /// Its payload, valid until the next receive.
            payload: &'a [u8],
        },
    }

    impl BroadcastReceiver {
        /// The next position this reader reads.
        #[must_use]
        pub fn position(&self) -> u64 {
            self.cursor
        }

        /// Receives at most one message.
        #[must_use]
        pub fn receive(&mut self) -> Received<'_> {
            let Ok(words) = self.region.words() else {
                return Received::Pending;
            };
            match words.receive(&mut self.cursor, &mut self.scratch) {
                Ok(Receive::Message {
                    position,
                    type_id,
                    length,
                }) => Received::Message {
                    position,
                    type_id,
                    payload: self.scratch.get(..length).unwrap_or(&[]),
                },
                Ok(Receive::Lapped {
                    lost_from,
                    rejoined_at,
                }) => Received::Lapped {
                    lost_from,
                    rejoined_at,
                },
                // The scratch is sized for the largest payload at creation.
                Ok(Receive::Pending) | Err(_) => Received::Pending,
            }
        }
    }
}

#[cfg(not(loom))]
pub use owned::Received;

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    fn message(sequence: u32, length: usize) -> Vec<u8> {
        (0..length).map(|i| (i as u8) ^ (sequence as u8)).collect()
    }

    #[test]
    fn geometry_and_payload_lengths() {
        assert!(broadcast(512).is_err());
        assert!(broadcast(1536).is_err());
        let mut tx = broadcast(1024).unwrap();
        assert_eq!(tx.max_payload(), 120);
        let mut rx = tx.receiver();
        for (sequence, length) in [(1u32, 1usize), (2, 7), (3, 8), (4, 9), (5, 0), (6, 120)] {
            let position = tx.transmit(sequence, &message(sequence, length)).unwrap();
            let Received::Message {
                position: got,
                type_id,
                payload,
            } = rx.receive()
            else {
                panic!("expected message {sequence}");
            };
            assert_eq!((got, type_id), (position, sequence));
            assert_eq!(payload, &message(sequence, length)[..]);
        }
        assert_eq!(rx.receive(), Received::Pending);
        // Payload 1 has length 9 and extent 16.
        assert_eq!(rx.position(), 16 + 16 + 16 + 24 + 8 + 128);
        assert_eq!(
            tx.transmit(1, &[0; 121]),
            Err(BroadcastError::MessageTooLarge {
                length: 121,
                max: 120
            })
        );
        assert_eq!(
            tx.transmit(PAD_TYPE, b"x"),
            Err(BroadcastError::ReservedType { type_id: PAD_TYPE })
        );
    }

    #[test]
    fn padding_at_the_end_and_wrapping() {
        let mut tx = broadcast(1024).unwrap();
        let mut rx = tx.receiver();
        // 100-byte payloads: extent 112, so the ninth record pads 128 bytes.
        for sequence in 0..40u32 {
            tx.transmit(sequence, &message(sequence, 100)).unwrap();
            let Received::Message {
                type_id, payload, ..
            } = rx.receive()
            else {
                panic!("expected message {sequence}");
            };
            assert_eq!(type_id, sequence);
            assert_eq!(payload, &message(sequence, 100)[..]);
        }
    }

    #[test]
    fn position_exhaustion_closes_the_buffer() {
        let mut tx = broadcast(1024).unwrap();
        tx.seed(u64::MAX - 15);
        let mut rx = tx.receiver();
        // A 17-byte payload needs PAD 16 + extent 32: exhausted.
        assert_eq!(
            tx.transmit(1, &[0; 17]),
            Err(BroadcastError::PositionsExhausted)
        );
        assert!(tx.is_closed());
        // A record that would still fit is refused too: closed for good.
        assert_eq!(tx.transmit(2, &[]), Err(BroadcastError::PositionsExhausted));
        assert_eq!(rx.receive(), Received::Pending);
    }

    #[test]
    fn a_slow_reader_is_lapped_and_rejoins_at_latest() {
        let mut tx = broadcast(1024).unwrap();
        let mut rx = tx.receiver();
        for sequence in 0..20u32 {
            tx.transmit(sequence, &message(sequence, 100)).unwrap();
        }
        let Received::Lapped {
            lost_from,
            rejoined_at,
        } = rx.receive()
        else {
            panic!("expected a lap");
        };
        assert_eq!(lost_from, 0);
        assert!(rejoined_at > lost_from);
        // Rejoined at the latest record: it is delivered next.
        let Received::Message { type_id, .. } = rx.receive() else {
            panic!("expected the latest message");
        };
        assert_eq!(type_id, 19);
        assert_eq!(rx.receive(), Received::Pending);
    }

    #[test]
    fn concurrent_writer_and_lapping_readers() {
        let mut tx = broadcast(1024).unwrap();
        let readers: Vec<_> = (0..2).map(|_| tx.receiver()).collect();
        let total = if cfg!(miri) { 200u32 } else { 50_000 };
        std::thread::scope(|scope| {
            for mut rx in readers {
                scope.spawn(move || {
                    let mut last = None;
                    loop {
                        match rx.receive() {
                            Received::Message {
                                type_id, payload, ..
                            } => {
                                assert!(last.is_none_or(|l| type_id > l));
                                let length = (type_id % 113) as usize;
                                assert_eq!(payload, &message(type_id, length)[..]);
                                last = Some(type_id);
                                if type_id == total - 1 {
                                    break;
                                }
                            }
                            Received::Lapped { .. } | Received::Pending => {
                                std::thread::yield_now();
                            }
                        }
                    }
                });
            }
            scope.spawn(move || {
                for sequence in 0..total {
                    let length = (sequence % 113) as usize;
                    tx.transmit(sequence, &message(sequence, length)).unwrap();
                }
            });
        });
    }
}
