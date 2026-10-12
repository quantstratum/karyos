// SPDX-License-Identifier: Apache-2.0

//! One term in heap memory, written by one exclusive writer and read
//! concurrently by any number of readers in the same process.
//!
//! Scope: a single term that is never reused, rotated or cleaned, so no loans
//! are needed yet. The writer computes every header location, fragment extent
//! and decision word itself from [`FragmentPlan`]; callers supply only typed
//! fields, an optional opaque trace extension and the payload, never header
//! bytes that affect geometry.
//!
//! Access rules that make concurrent use sound:
//!
//! - Every header word 0 is accessed only atomically. Interior fragments'
//!   words are stored `Relaxed` before the first fragment's word is stored
//!   with `Release`; readers load the first word with `Acquire` and interior
//!   words `Relaxed` afterwards. No plain access ever touches a word 0.
//! - All other bytes are accessed only with plain copies. The writer writes
//!   only bytes at or after its private tail, which no reader reaches until the
//!   block's first word 0 is published; after publication it never writes
//!   them again. Readers copy only bytes of published blocks, so their plain
//!   reads happen after the writer's plain writes.
//! - No slice or reference covering the term's bytes is ever created; the
//!   memory is reached only through raw pointers derived from the owning
//!   allocation, and atomic views of single words.

use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::error::{LayoutError, SysError};
use crate::frame::{
    EXTENSION_LENGTH, FRAME_ALIGNMENT, Flags, FrameType, HEADER_LENGTH, Lane, PROTOCOL_VERSION,
    Word0,
};
use crate::sizing::{FragmentPlan, TermLength, align_frame};

/// Alignment of a term allocation.
const TERM_ALIGNMENT: usize = 4096;

/// The fields that every frame of the term carries, written by the writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameIdentity {
    /// The lane whose bank holds the term.
    pub lane: Lane,
    /// Compact wire alias of the publication incarnation.
    pub session_id: i32,
    /// Application-chosen stream.
    pub stream_id: i32,
    /// The term's id.
    pub term_id: i32,
}

/// One heap-allocated term.
#[derive(Debug)]
pub struct TermMemory {
    base: NonNull<u8>,
    length: TermLength,
    identity: FrameIdentity,
    writer_taken: AtomicBool,
}

// SAFETY: the allocation is owned by `TermMemory` and freed only in `drop`.
// All shared access goes through `ExclusiveWriter` and `CommittedReader`,
// which follow the access rules in the module documentation: atomic access
// to every word 0 and plain access to other bytes only when ordered by those
// atomics. No thread-affine state exists.
unsafe impl Send for TermMemory {}
// SAFETY: see the `Send` impl.
unsafe impl Sync for TermMemory {}

impl TermMemory {
    /// Allocates a zeroed term.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] when the allocation fails.
    pub fn new(length: TermLength, identity: FrameIdentity) -> Result<Self, SysError> {
        let len = length.get() as usize;
        let layout = Layout::from_size_align(len, TERM_ALIGNMENT)
            .map_err(|_| SysError::InvalidRegion { address: 0, len })?;
        // SAFETY: `layout` has a non-zero size (a term is at least 64 KiB).
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let base = NonNull::new(raw).ok_or(SysError::InvalidRegion { address: 0, len })?;
        Ok(Self {
            base,
            length,
            identity,
            writer_taken: AtomicBool::new(false),
        })
    }

    /// The term length.
    #[inline]
    #[must_use]
    pub fn length(&self) -> TermLength {
        self.length
    }

    /// Takes the term's only writer. Returns `None` once a writer has been
    /// taken, even if that writer was dropped or forgotten: the right to write
    /// is never reissued.
    ///
    /// # Errors
    ///
    /// Returns layout errors for an invalid `mtu` or `max_reserved`; the
    /// writer is not taken in that case.
    pub fn writer(
        &self,
        mtu: u32,
        max_reserved: u32,
    ) -> Result<Option<ExclusiveWriter<'_>>, SysError> {
        let plan = FragmentPlan::new(mtu, Flags::NONE)?;
        let max_message_length = plan.max_message_length(max_reserved, self.length)?;
        if self
            .writer_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(None);
        }
        Ok(Some(ExclusiveWriter {
            memory: self,
            tail: 0,
            mtu,
            max_reserved,
            max_message_length,
        }))
    }

    /// A reader that walks the term from its start.
    #[must_use]
    pub fn reader(&self) -> CommittedReader<'_> {
        CommittedReader {
            memory: self,
            offset: 0,
        }
    }

    /// The atomic word 0 at `offset`.
    ///
    /// Callers pass only offsets of frame starts that the writer computed
    /// (multiples of 32 below the term length); those locations are accessed
    /// only through this function.
    fn word0(&self, offset: u32) -> &AtomicU64 {
        debug_assert!(offset.is_multiple_of(FRAME_ALIGNMENT) && offset < self.length.get());
        // SAFETY: `offset` is a multiple of 32 inside the live allocation, so
        // the pointer is valid and 8-byte aligned for the lifetime of `&self`.
        // Every access to this location goes through an `AtomicU64` (module
        // rules), so no non-atomic access races with it.
        let pointer = unsafe { self.base.as_ptr().add(offset as usize) };
        // SAFETY: as above: valid, aligned, accessed only atomically while
        // the returned reference lives.
        unsafe { AtomicU64::from_ptr(pointer.cast::<u64>()) }
    }

    /// Plain copy of `bytes` into the term at `offset`.
    ///
    /// Only the writer calls this, for bytes in its own unpublished range,
    /// never for a word 0.
    fn write_plain(&self, offset: u32, bytes: &[u8]) {
        debug_assert!(offset as usize + bytes.len() <= self.length.get() as usize);
        // SAFETY: the destination lies inside the allocation (checked by the
        // writer's geometry), is not a word 0, and is not read by anyone until
        // a later Release publication; the source is a distinct slice.
        let destination = unsafe { self.base.as_ptr().add(offset as usize) };
        // SAFETY: see above; the two regions cannot overlap because the
        // source is caller memory outside the term allocation.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
    }

    /// Plain copy of `out.len()` bytes from the term at `offset`.
    ///
    /// Only readers call this, for non-word-0 bytes of a block whose first
    /// word 0 they loaded with Acquire.
    fn read_plain(&self, offset: u32, out: &mut [u8]) {
        debug_assert!(offset as usize + out.len() <= self.length.get() as usize);
        // SAFETY: the source lies inside the allocation and belongs to a
        // published block, which the writer never writes again; the reads
        // happen after the writer's writes through the Acquire load.
        let source = unsafe { self.base.as_ptr().add(offset as usize) };
        // SAFETY: see above; `out` is caller memory outside the allocation.
        unsafe { core::ptr::copy_nonoverlapping(source, out.as_mut_ptr(), out.len()) };
    }
}

impl Drop for TermMemory {
    fn drop(&mut self) {
        let len = self.length.get() as usize;
        if let Ok(layout) = Layout::from_size_align(len, TERM_ALIGNMENT) {
            // SAFETY: `base` came from `alloc_zeroed` with this same layout and
            // is freed once; no writer or reader outlives `self`.
            unsafe { std::alloc::dealloc(self.base.as_ptr(), layout) };
        }
    }
}

/// Options for one append.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteOptions {
    /// Set EOS on the last fragment.
    pub end_of_stream: bool,
    /// Application value written in every fragment's header.
    pub reserved_value: i64,
    /// Opaque, already encoded trace extension written after every
    /// fragment's header; its presence sets EXT.
    pub extension: Option<[u8; EXTENSION_LENGTH as usize]>,
}

/// Result of an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a full term must be rotated"]
pub enum WriteOutcome {
    /// The message was published as one block.
    Appended {
        /// Term offset of the block.
        offset: u32,
        /// Bytes the block occupies.
        reserved: u32,
    },
    /// The block did not fit; the rest of the term was published as PAD.
    TermFull,
}

/// The term's only writer.
#[derive(Debug)]
pub struct ExclusiveWriter<'a> {
    memory: &'a TermMemory,
    tail: u32,
    mtu: u32,
    max_reserved: u32,
    max_message_length: u32,
}

impl ExclusiveWriter<'_> {
    /// Current tail offset.
    #[inline]
    #[must_use]
    pub fn tail(&self) -> u32 {
        self.tail
    }

    /// Appends one message block and publishes it.
    ///
    /// Every input is validated before any byte is written. Fragment
    /// headers, extensions and payload are written first; interior word 0
    /// values are stored `Relaxed`; the first fragment's word 0 is stored
    /// last with `Release`. After that store the tail advances; nothing after
    /// the publication can fail.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::EmptyMessage`] for an empty payload and layout
    /// errors when the message is too large; the term is unchanged.
    pub fn append(
        &mut self,
        payload: &[u8],
        options: WriteOptions,
    ) -> Result<WriteOutcome, SysError> {
        if payload.is_empty() {
            return Err(SysError::EmptyMessage);
        }
        let term_length = self.memory.length.get();
        if self.tail == term_length {
            return Ok(WriteOutcome::TermFull);
        }
        let ext = options.extension.is_some();
        let lane = self.memory.identity.lane;
        let plan = FragmentPlan::new(self.mtu, Flags::new(false, false, false, ext, lane))?;
        let length = u32::try_from(payload.len()).map_err(|_| LayoutError::LengthOverflow {
            value: payload.len() as u64,
        })?;
        let max = if ext {
            plan.max_message_length(self.max_reserved, self.memory.length)?
        } else {
            self.max_message_length
        };
        FragmentPlan::check_message(length, max)?;
        let reserved = plan.reserved(length)?;
        let remaining = term_length - self.tail;
        if reserved > remaining {
            self.publish_pad(remaining);
            return Ok(WriteOutcome::TermFull);
        }

        let start = self.tail;
        let fragments = plan.fragments(length);
        let chunk = plan.payload_per_fragment() as usize;
        let mut offset = start;
        let mut rest = payload;
        let mut first = None;
        for index in 0..fragments {
            let (body, next) = rest.split_at(chunk.min(rest.len()));
            rest = next;
            let last = index + 1 == fragments;
            let flags = Flags::new(index == 0, last, last && options.end_of_stream, ext, lane);
            let header_length = flags.header_length();
            // Bounded by the MTU, so the conversions cannot fail.
            let frame_length = header_length + body.len() as u32;
            let word0 = Word0::new(frame_length as i32, flags, FrameType::Data);
            self.write_header_tail(offset, options.reserved_value);
            if let Some(extension) = &options.extension {
                self.memory.write_plain(offset + HEADER_LENGTH, extension);
            }
            self.memory.write_plain(offset + header_length, body);
            if index == 0 {
                first = Some(word0);
            } else {
                self.memory
                    .word0(offset)
                    .store(word0.pack().to_le(), Ordering::Relaxed);
            }
            // Alignment padding is already zero: the term is never reused.
            offset += align_frame(frame_length).unwrap_or(frame_length);
        }
        if let Some(word0) = first {
            self.memory
                .word0(start)
                .store(word0.pack().to_le(), Ordering::Release);
        }
        self.tail = start + reserved;
        Ok(WriteOutcome::Appended {
            offset: start,
            reserved,
        })
    }

    /// Publishes one PAD frame covering `[tail, term end)` and closes the term.
    fn publish_pad(&mut self, extent: u32) {
        let offset = self.tail;
        let flags = Flags::new(false, false, false, false, self.memory.identity.lane);
        self.write_header_tail(offset, 0);
        self.memory.word0(offset).store(
            Word0::new(extent as i32, flags, FrameType::Pad)
                .pack()
                .to_le(),
            Ordering::Release,
        );
        self.tail = self.memory.length.get();
    }

    /// Writes header bytes 8..32 (term offset, identity, reserved value).
    fn write_header_tail(&self, offset: u32, reserved_value: i64) {
        let identity = self.memory.identity;
        let mut bytes = [0u8; 24];
        let fields: [&[u8]; 5] = [
            &(offset as i32).to_le_bytes(),
            &identity.session_id.to_le_bytes(),
            &identity.stream_id.to_le_bytes(),
            &identity.term_id.to_le_bytes(),
            &reserved_value.to_le_bytes(),
        ];
        let mut at = 0;
        for field in fields {
            if let Some(slot) = bytes.get_mut(at..at + field.len()) {
                slot.copy_from_slice(field);
            }
            at += field.len();
        }
        self.memory.write_plain(offset + 8, &bytes);
    }
}

/// What a reader found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// A message was copied into the caller's buffer.
    Message {
        /// Term offset of the block.
        offset: u32,
        /// Bytes copied (the message length).
        length: u32,
        /// Whether the last fragment carries EOS.
        end_of_stream: bool,
        /// Reserved value of the first fragment.
        reserved_value: i64,
    },
    /// Nothing published at the reader's position yet.
    Pending,
    /// The term ended.
    End,
}

/// Walks published blocks from the term start; any number may exist.
#[derive(Debug)]
pub struct CommittedReader<'a> {
    memory: &'a TermMemory,
    offset: u32,
}

impl CommittedReader<'_> {
    /// The position of the next read.
    #[inline]
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Copies the next published message into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::BufferTooShort`] when `out` cannot hold the
    /// message (the position does not advance) and [`SysError::CorruptTerm`]
    /// when the published geometry is inconsistent.
    pub fn poll(&mut self, out: &mut [u8]) -> Result<ReadOutcome, SysError> {
        let term_length = self.memory.length.get();
        if self.offset == term_length {
            return Ok(ReadOutcome::End);
        }
        let start = self.offset;
        let first = u64::from_le(self.memory.word0(start).load(Ordering::Acquire));
        let signed = first as u32 as i32;
        if signed <= 0 {
            return Ok(ReadOutcome::Pending);
        }
        let word0 = Word0::unpack(first).map_err(|_| corrupt(start, "reserved flags"))?;
        if word0.version() != PROTOCOL_VERSION {
            return Err(corrupt(start, "version"));
        }
        match FrameType::try_from_code(word0.frame_type_code()) {
            Ok(FrameType::Pad) => {
                if signed as u32 != term_length - start {
                    return Err(corrupt(start, "pad extent"));
                }
                self.offset = term_length;
                Ok(ReadOutcome::End)
            }
            Ok(FrameType::Data) => self.read_block(start, word0, out),
            _ => Err(corrupt(start, "frame type")),
        }
    }

    fn read_block(
        &mut self,
        start: u32,
        first: Word0,
        out: &mut [u8],
    ) -> Result<ReadOutcome, SysError> {
        let term_length = self.memory.length.get();
        // First pass: walk the geometry from the atomic words only.
        let mut offset = start;
        let mut word0 = first;
        let mut length: u32 = 0;
        let end_of_stream;
        loop {
            let flags = word0.flags();
            if flags.begin() != (offset == start) {
                return Err(corrupt(offset, "BEGIN placement"));
            }
            let frame_length = u32::try_from(word0.frame_length())
                .map_err(|_| corrupt(offset, "uncommitted fragment"))?;
            let header_length = flags.header_length();
            if frame_length < header_length {
                return Err(corrupt(offset, "frame shorter than header"));
            }
            let reserved = align_frame(frame_length)?;
            if reserved > term_length - offset {
                return Err(corrupt(offset, "frame past term end"));
            }
            length = length
                .checked_add(frame_length - header_length)
                .ok_or_else(|| corrupt(offset, "length overflow"))?;
            offset += reserved;
            if flags.end() {
                end_of_stream = flags.eos();
                break;
            }
            if offset == term_length {
                return Err(corrupt(offset, "block without END"));
            }
            word0 = Word0::unpack(u64::from_le(
                self.memory.word0(offset).load(Ordering::Relaxed),
            ))
            .map_err(|_| corrupt(offset, "reserved flags"))?;
            if word0.frame_type_code() != FrameType::Data.code() {
                return Err(corrupt(offset, "interior frame type"));
            }
        }
        let end = offset;
        if out.len() < length as usize {
            return Err(SysError::BufferTooShort {
                required: length as usize,
                available: out.len(),
            });
        }
        // Second pass: copy payloads (never word 0 bytes).
        let mut reserved_value = [0u8; 8];
        self.memory.read_plain(start + 24, &mut reserved_value);
        let mut offset = start;
        let mut written = 0usize;
        while offset < end {
            let word0 = Word0::unpack(u64::from_le(
                self.memory.word0(offset).load(Ordering::Relaxed),
            ))
            .map_err(|_| corrupt(offset, "reserved flags"))?;
            let header_length = word0.flags().header_length();
            let frame_length = word0.frame_length() as u32;
            let payload = (frame_length - header_length) as usize;
            if let Some(target) = out.get_mut(written..written + payload) {
                self.memory.read_plain(offset + header_length, target);
            }
            written += payload;
            offset += align_frame(frame_length)?;
        }
        self.offset = end;
        Ok(ReadOutcome::Message {
            offset: start,
            length,
            end_of_stream,
            reserved_value: i64::from_le_bytes(reserved_value),
        })
    }
}

fn corrupt(offset: u32, reason: &'static str) -> SysError {
    SysError::CorruptTerm { offset, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH};

    const IDENTITY: FrameIdentity = FrameIdentity {
        lane: Lane::ZERO,
        session_id: 5,
        stream_id: 6,
        term_id: 7,
    };

    fn term() -> TermMemory {
        TermMemory::new(TermLength::try_new(MIN_TERM_LENGTH).unwrap(), IDENTITY).unwrap()
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed))
            .collect()
    }

    fn read(reader: &mut CommittedReader<'_>) -> (ReadOutcome, Vec<u8>) {
        let mut out = vec![0u8; 8192];
        let outcome = reader.poll(&mut out).unwrap();
        if let ReadOutcome::Message { length, .. } = outcome {
            out.truncate(length as usize);
        } else {
            out.clear();
        }
        (outcome, out)
    }

    #[test]
    fn append_then_read() {
        let term = term();
        let mut writer = term
            .writer(DEFAULT_MTU, MIN_TERM_LENGTH / 8)
            .unwrap()
            .unwrap();
        let mut reader = term.reader();
        assert_eq!(read(&mut reader).0, ReadOutcome::Pending);
        let data = payload(100, 1);
        let options = WriteOptions {
            end_of_stream: true,
            reserved_value: -9,
            extension: None,
        };
        assert_eq!(
            writer.append(&data, options).unwrap(),
            WriteOutcome::Appended {
                offset: 0,
                reserved: 160
            }
        );
        let (outcome, bytes) = read(&mut reader);
        assert_eq!(
            outcome,
            ReadOutcome::Message {
                offset: 0,
                length: 100,
                end_of_stream: true,
                reserved_value: -9,
            }
        );
        assert_eq!(bytes, data);
        assert_eq!(read(&mut reader).0, ReadOutcome::Pending);
    }

    #[test]
    fn fragmented_and_traced_messages() {
        let term = term();
        let mut writer = term
            .writer(DEFAULT_MTU, MIN_TERM_LENGTH / 8)
            .unwrap()
            .unwrap();
        let mut reader = term.reader();
        let plain = payload(8000, 2);
        assert_eq!(
            writer.append(&plain, WriteOptions::default()).unwrap(),
            WriteOutcome::Appended {
                offset: 0,
                reserved: 8192
            }
        );
        let traced = payload(3000, 3);
        let options = WriteOptions {
            extension: Some([0x5A; 64]),
            ..WriteOptions::default()
        };
        let _ = writer.append(&traced, options).unwrap();
        assert_eq!(read(&mut reader).1, plain);
        assert_eq!(read(&mut reader).1, traced);
    }

    #[test]
    fn rejected_appends_change_nothing() {
        let term = term();
        let mut writer = term
            .writer(DEFAULT_MTU, MIN_TERM_LENGTH / 8)
            .unwrap()
            .unwrap();
        assert_eq!(
            writer.append(&[], WriteOptions::default()),
            Err(SysError::EmptyMessage)
        );
        assert!(matches!(
            writer.append(&payload(8001, 0), WriteOptions::default()),
            Err(SysError::Layout(LayoutError::MessageTooLarge { .. }))
        ));
        assert_eq!(writer.tail(), 0);
        assert_eq!(read(&mut term.reader()).0, ReadOutcome::Pending);
    }

    #[test]
    fn full_term_publishes_pad_and_ends() {
        let term = term();
        let mut writer = term
            .writer(DEFAULT_MTU, MIN_TERM_LENGTH / 8)
            .unwrap()
            .unwrap();
        let data = payload(5000, 4);
        let mut appended = 0;
        while let WriteOutcome::Appended { .. } =
            writer.append(&data, WriteOptions::default()).unwrap()
        {
            appended += 1;
        }
        assert_eq!(
            writer.append(&data, WriteOptions::default()),
            Ok(WriteOutcome::TermFull)
        );
        let mut reader = term.reader();
        for _ in 0..appended {
            assert_eq!(read(&mut reader).1, data);
        }
        assert_eq!(read(&mut reader).0, ReadOutcome::End);
        assert_eq!(read(&mut reader).0, ReadOutcome::End);
    }

    #[test]
    fn the_writer_is_issued_once() {
        let term = term();
        assert!(term.writer(32, 64).is_err());
        // The writer has no Drop impl, so dropping it and forgetting it are
        // the same: either way the right to write is not reissued.
        {
            let writer = term.writer(DEFAULT_MTU, MIN_TERM_LENGTH / 8).unwrap();
            assert!(writer.is_some());
        }
        assert!(
            term.writer(DEFAULT_MTU, MIN_TERM_LENGTH / 8)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn short_buffers_do_not_advance() {
        let term = term();
        let mut writer = term
            .writer(DEFAULT_MTU, MIN_TERM_LENGTH / 8)
            .unwrap()
            .unwrap();
        let _ = writer
            .append(&payload(300, 5), WriteOptions::default())
            .unwrap();
        let mut reader = term.reader();
        let mut small = [0u8; 299];
        assert_eq!(
            reader.poll(&mut small),
            Err(SysError::BufferTooShort {
                required: 300,
                available: 299
            })
        );
        assert_eq!(reader.offset(), 0);
        assert_eq!(read(&mut reader).1, payload(300, 5));
    }

    /// One writer thread and two reader threads; under Miri this checks the
    /// access rules for data races.
    #[test]
    fn concurrent_writer_and_readers() {
        let count: u32 = if cfg!(miri) { 12 } else { 400 };
        let term = term();
        std::thread::scope(|scope| {
            let mut writer = term
                .writer(DEFAULT_MTU, MIN_TERM_LENGTH / 8)
                .unwrap()
                .unwrap();
            scope.spawn(move || {
                for sequence in 0..count {
                    let len = 40 + (sequence as usize * 37) % 2500;
                    let mut data = payload(len, sequence as u8);
                    data[..4].copy_from_slice(&sequence.to_le_bytes());
                    match writer.append(&data, WriteOptions::default()).unwrap() {
                        WriteOutcome::Appended { .. } => {}
                        WriteOutcome::TermFull => break,
                    }
                }
                // Close the term so readers terminate.
                while writer
                    .append(&payload(2600, 0), WriteOptions::default())
                    .unwrap()
                    != WriteOutcome::TermFull
                {}
            });
            for _ in 0..2 {
                scope.spawn(|| {
                    let mut reader = term.reader();
                    let mut expected = 0u32;
                    let mut out = vec![0u8; 8192];
                    loop {
                        match reader.poll(&mut out).unwrap() {
                            ReadOutcome::Message { length, .. } => {
                                let sequence = u32::from_le_bytes(out[..4].try_into().unwrap());
                                if length as usize != 2600 {
                                    assert_eq!(sequence, expected);
                                    let len = 40 + (sequence as usize * 37) % 2500;
                                    let mut data = payload(len, sequence as u8);
                                    data[..4].copy_from_slice(&sequence.to_le_bytes());
                                    assert_eq!(&out[..length as usize], &data[..]);
                                    expected += 1;
                                }
                            }
                            ReadOutcome::Pending => std::thread::yield_now(),
                            ReadOutcome::End => break,
                        }
                    }
                });
            }
        });
    }
}
