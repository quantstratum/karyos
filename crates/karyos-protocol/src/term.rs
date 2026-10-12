// SPDX-License-Identifier: Apache-2.0

//! Sequential flyweights over one term held in a byte slice: an appender
//! that writes whole message blocks at its tail and a scanner that walks
//! committed blocks from the term start (SPEC.md §4, publish and read).
//!
//! This is foundational storage logic, not the concurrent appender nor the
//! IPC mode. It works on `&mut [u8]` and `&[u8]`, so Rust's borrow rules
//! provide the exclusion that the shared-memory version will provide with
//! loans and atomics. Header locations come only from the appender's tail or
//! the scanner's walk, never from caller-chosen offsets. The scanner follows
//! the publisher-log rule: the first fragment's word 0 is the decision word of
//! the whole block, so interior fragments are read only once that word is
//! committed.
//!
//! These helpers read and write plain bytes. They must never be placed over a
//! live term that other threads or processes access concurrently: that needs
//! atomic decision-word reads and capability-scoped plain ranges, which are a
//! separate, later layer.

use crate::error::ProtocolError;
use crate::frame::{
    EXTENSION_LENGTH, FRAME_ALIGNMENT, Flags, FrameHeader, FrameType, HEADER_LENGTH, Lane,
    PROTOCOL_VERSION, TraceExtension, Word0,
};
use crate::sizing::{FragmentPlan, TermLength, align_frame};

/// The header fields every frame of one term carries. A term belongs to one
/// lane's bank, so its lane is part of the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TermIdentity {
    /// The lane whose bank holds the term.
    pub lane: Lane,
    /// Compact wire alias of the publication incarnation.
    pub session_id: i32,
    /// Application-chosen stream.
    pub stream_id: i32,
    /// The term's id.
    pub term_id: i32,
}

/// Per-message options for [`TermAppender::append`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppendOptions {
    /// Set EOS on the last fragment.
    pub end_of_stream: bool,
    /// Trace extension written after every fragment's header.
    pub extension: Option<TraceExtension>,
    /// Application value in every fragment's header.
    pub reserved_value: i64,
}

/// Result of an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a full term must be rotated"]
pub enum AppendOutcome {
    /// The message was written as one block.
    Appended {
        /// Term offset of the block's first fragment.
        offset: u32,
        /// Bytes the block occupies.
        reserved: u32,
    },
    /// The block did not fit: the rest of the term was padded (if any space
    /// remained) and nothing else can be appended to this term.
    TermFull,
}

/// Writes whole message blocks at the tail of a term it borrows exclusively.
#[derive(Debug)]
pub struct TermAppender<'a> {
    term: &'a mut [u8],
    term_length: u32,
    tail: u32,
    identity: TermIdentity,
    mtu: u32,
    max_reserved: u32,
    max_message_length: u32,
}

impl<'a> TermAppender<'a> {
    /// Starts appending at offset 0 of `term`, which it first zero-fills:
    /// constructing an appender resets the term, so stale frames from earlier
    /// use can never be scanned after a shorter new append.
    ///
    /// `max_reserved` bounds the bytes one message may reserve (at most
    /// `term_length / 8`); the message limit is derived from it for messages
    /// without the trace extension.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BufferTooShort`] when `term` is not exactly
    /// `term_length` bytes, and the errors of [`FragmentPlan::new`] and
    /// [`FragmentPlan::max_message_length`].
    pub fn new(
        term: &'a mut [u8],
        term_length: TermLength,
        identity: TermIdentity,
        mtu: u32,
        max_reserved: u32,
    ) -> Result<Self, ProtocolError> {
        let length = term_length.get();
        if term.len() != length as usize {
            return Err(ProtocolError::BufferTooShort {
                required: length as usize,
                available: term.len(),
            });
        }
        let plan = FragmentPlan::new(mtu, Flags::NONE)?;
        let max_message_length = plan.max_message_length(max_reserved, term_length)?;
        term.fill(0);
        Ok(Self {
            term,
            term_length: length,
            tail: 0,
            identity,
            mtu,
            max_reserved,
            max_message_length,
        })
    }

    /// Current tail offset.
    #[inline]
    #[must_use]
    pub fn tail(&self) -> u32 {
        self.tail
    }

    /// Largest message without the trace extension.
    #[inline]
    #[must_use]
    pub fn max_message_length(&self) -> u32 {
        self.max_message_length
    }

    /// Appends `payload` as one message block.
    ///
    /// The block is never split across terms: if it does not fit, the rest
    /// of the term is filled with one PAD frame and [`AppendOutcome::TermFull`]
    /// is returned. As in the publisher's log, every interior fragment is
    /// complete before the first fragment's word 0 is written.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EmptyMessage`] for an empty payload (a
    /// header-only DATA frame is a heartbeat, not an application message),
    /// [`ProtocolError::MessageTooLarge`] above the message limit (with the
    /// extension the limit is recomputed for its header) and arithmetic
    /// errors from sizing. Every error is detected before anything is
    /// written; the tail and the term are then unchanged.
    pub fn append(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<AppendOutcome, ProtocolError> {
        if payload.is_empty() {
            return Err(ProtocolError::EmptyMessage);
        }
        let ext = options.extension.is_some();
        let lane = self.identity.lane;
        let fragment_flags = Flags::new(false, false, false, ext, lane);
        let plan = FragmentPlan::new(self.mtu, fragment_flags)?;
        let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::LengthOverflow {
            value: payload.len() as u64,
        })?;
        let max = if ext {
            plan.max_message_length(self.max_reserved, TermLength::try_new(self.term_length)?)?
        } else {
            self.max_message_length
        };
        // Encode the extension once, up front, so an invalid one fails before
        // any byte of the term is written.
        let extension = match options.extension {
            Some(extension) => {
                let mut bytes = [0u8; EXTENSION_LENGTH as usize];
                extension.encode(&mut bytes)?;
                Some(bytes)
            }
            None => None,
        };
        FragmentPlan::check_message(length, max)?;
        let reserved = plan.reserved(length)?;
        let end = self
            .tail
            .checked_add(reserved)
            .ok_or(ProtocolError::LengthOverflow {
                value: u64::from(reserved),
            })?;
        if end > self.term_length {
            self.pad_to_end()?;
            return Ok(AppendOutcome::TermFull);
        }

        let start = self.tail;
        let fragments = plan.fragments(length);
        let chunk = plan.payload_per_fragment() as usize;
        let mut offset = start;
        let mut first_word0 = None;
        let mut rest = payload;
        for index in 0..fragments {
            let (body, next) = rest.split_at(chunk.min(rest.len()));
            rest = next;
            let last = index + 1 == fragments;
            let flags = Flags::new(index == 0, last, last && options.end_of_stream, ext, lane);
            let header_length = flags.header_length();
            let frame_length = header_length + body.len() as u32;
            let word0 = Word0::new(frame_length as i32, flags, FrameType::Data);
            let header = FrameHeader {
                word0,
                term_offset: offset as i32,
                session_id: self.identity.session_id,
                stream_id: self.identity.stream_id,
                term_id: self.identity.term_id,
                reserved_value: options.reserved_value,
            };
            let frame_reserved = align_frame(frame_length)?;
            let region = slice_mut(self.term, offset, frame_reserved)?;
            region.fill(0);
            let mut header_bytes = [0u8; HEADER_LENGTH as usize];
            header.encode(&mut header_bytes)?;
            // Bytes 0..8 are word 0. Interior fragments get theirs now; the
            // first fragment's word 0 is the decision word and is written
            // only after the whole block (it is never published early).
            let from = if index == 0 { 8 } else { 0 };
            region
                .get_mut(from..HEADER_LENGTH as usize)
                .ok_or(ProtocolError::BufferTooShort {
                    required: HEADER_LENGTH as usize,
                    available: 0,
                })?
                .copy_from_slice(header_bytes.get(from..).unwrap_or(&[]));
            if let Some(bytes) = &extension {
                tail_mut(region, HEADER_LENGTH)?
                    .get_mut(..bytes.len())
                    .ok_or(ProtocolError::BufferTooShort {
                        required: bytes.len(),
                        available: 0,
                    })?
                    .copy_from_slice(bytes);
            }
            tail_mut(region, header_length)?
                .get_mut(..body.len())
                .ok_or(ProtocolError::BufferTooShort {
                    required: body.len(),
                    available: 0,
                })?
                .copy_from_slice(body);
            if index == 0 {
                first_word0 = Some(word0);
            }
            offset += frame_reserved;
        }
        if let Some(word0) = first_word0 {
            slice_mut(self.term, start, 8)?.copy_from_slice(&word0.pack().to_le_bytes());
        }
        self.tail = end;
        Ok(AppendOutcome::Appended {
            offset: start,
            reserved,
        })
    }

    /// Fills `[tail, term_length)` with one PAD frame whose length states the
    /// extent, then closes the term.
    fn pad_to_end(&mut self) -> Result<(), ProtocolError> {
        let extent = self.term_length - self.tail;
        if extent > 0 {
            let pad_flags = Flags::new(false, false, false, false, self.identity.lane);
            let header = FrameHeader {
                word0: Word0::new(extent as i32, pad_flags, FrameType::Pad),
                term_offset: self.tail as i32,
                session_id: self.identity.session_id,
                stream_id: self.identity.stream_id,
                term_id: self.identity.term_id,
                reserved_value: 0,
            };
            let region = slice_mut(self.term, self.tail, HEADER_LENGTH)?;
            header.encode(region)?;
        }
        self.tail = self.term_length;
        Ok(())
    }
}

/// One committed message block found by the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageBlock<'a> {
    block: &'a [u8],
    offset: u32,
    length: u32,
    lane: Lane,
    end_of_stream: bool,
    reserved_value: i64,
}

impl<'a> MessageBlock<'a> {
    /// Term offset of the first fragment.
    #[inline]
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Bytes the block occupies.
    #[inline]
    #[must_use]
    pub fn reserved(&self) -> u32 {
        self.block.len() as u32
    }

    /// Logical message length (sum of fragment payloads).
    #[inline]
    #[must_use]
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Lane of the message.
    #[inline]
    #[must_use]
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// Whether the last fragment carries EOS.
    #[inline]
    #[must_use]
    pub fn end_of_stream(&self) -> bool {
        self.end_of_stream
    }

    /// Application value of the first fragment.
    #[inline]
    #[must_use]
    pub fn reserved_value(&self) -> i64 {
        self.reserved_value
    }

    /// The payload of each fragment, in order. The block was validated when
    /// it was scanned.
    #[must_use]
    pub fn fragments(&self) -> Fragments<'a> {
        Fragments { rest: self.block }
    }

    /// Copies the whole message into `out`, returning the bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BufferTooShort`] when `out` is too small.
    pub fn copy_to(&self, out: &mut [u8]) -> Result<usize, ProtocolError> {
        let mut written = 0usize;
        let available = out.len();
        for fragment in self.fragments() {
            let end = written + fragment.len();
            out.get_mut(written..end)
                .ok_or(ProtocolError::BufferTooShort {
                    required: self.length as usize,
                    available,
                })?
                .copy_from_slice(fragment);
            written = end;
        }
        Ok(written)
    }
}

/// Iterator over the fragment payloads of a validated block.
#[derive(Debug, Clone)]
pub struct Fragments<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Fragments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let header = FrameHeader::decode(self.rest).ok()?;
        let frame_length = u32::try_from(header.word0.frame_length()).ok()?;
        let header_length = header.word0.flags().header_length();
        let reserved = align_frame(frame_length).ok()? as usize;
        let payload = self
            .rest
            .get(header_length as usize..frame_length as usize)?;
        self.rest = self.rest.get(reserved..).unwrap_or(&[]);
        Some(payload)
    }
}

/// What the scanner found at its position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanItem<'a> {
    /// A committed message block.
    Message(MessageBlock<'a>),
    /// A committed header-only DATA frame: a heartbeat observation, not an
    /// application message.
    Heartbeat {
        /// Term offset of the frame.
        offset: u32,
    },
    /// An aborted extent, skipped without reading past its word 0.
    Aborted {
        /// Term offset of the extent.
        offset: u32,
        /// Bytes skipped.
        extent: u32,
    },
    /// Nothing committed yet at the position (word 0 is zero or a negative
    /// marker); scan again later from the same position.
    Pending,
    /// The term ended (a PAD frame, or the term length was reached).
    End,
}

/// Walks committed blocks of one term from its start.
#[derive(Debug, Clone)]
pub struct TermScanner<'a> {
    term: &'a [u8],
    term_length: u32,
    offset: u32,
    identity: TermIdentity,
}

impl<'a> TermScanner<'a> {
    /// Scans `term` from offset 0.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BufferTooShort`] when `term` is not exactly
    /// `term_length` bytes.
    pub fn new(
        term: &'a [u8],
        term_length: TermLength,
        identity: TermIdentity,
    ) -> Result<Self, ProtocolError> {
        let length = term_length.get();
        if term.len() != length as usize {
            return Err(ProtocolError::BufferTooShort {
                required: length as usize,
                available: term.len(),
            });
        }
        Ok(Self {
            term,
            term_length: length,
            offset: 0,
            identity,
        })
    }

    /// The position the next call reads from.
    #[inline]
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Reads the item at the current position and advances past it.
    ///
    /// An error is terminal for this scanner: the position does not advance
    /// and no resynchronization is attempted. Resynchronizing after an
    /// interruption (a new BEGIN, PAD or ABORTED inside a block) belongs to
    /// the receiver and assembler layers.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidFrame`] when the bytes at the position
    /// violate the frame rules.
    pub fn next_item(&mut self) -> Result<ScanItem<'a>, ProtocolError> {
        if self.offset == self.term_length {
            return Ok(ScanItem::End);
        }
        let offset = self.offset;
        let raw = u64::from_le_bytes(read8(self.term, offset)?);
        // Classify the signed length before looking at anything else: zero is
        // unwritten and negative values (down to i32::MIN) are in-progress
        // markers whose other bits carry no meaning.
        let signed = raw as u32 as i32;
        let Ok(length) = u32::try_from(signed) else {
            return Ok(ScanItem::Pending);
        };
        if length == 0 {
            return Ok(ScanItem::Pending);
        }
        let word0 = Word0::unpack(raw).map_err(|_| invalid(offset, "reserved flag bits set"))?;
        let remaining = self.term_length - offset;
        match FrameType::try_from_code(word0.frame_type_code()) {
            Ok(FrameType::Aborted) => {
                // Only word 0 of an aborted block may be read.
                if word0.version() != PROTOCOL_VERSION {
                    return Err(ProtocolError::UnsupportedVersion {
                        version: word0.version(),
                    });
                }
                if !length.is_multiple_of(FRAME_ALIGNMENT) || length > remaining {
                    return Err(invalid(offset, "aborted extent out of bounds"));
                }
                self.offset += length;
                Ok(ScanItem::Aborted {
                    offset,
                    extent: length,
                })
            }
            Ok(FrameType::Pad) => {
                if length != remaining {
                    return Err(invalid(offset, "pad does not end at the term end"));
                }
                self.check_header(offset, FrameType::Pad)?;
                self.offset = self.term_length;
                Ok(ScanItem::End)
            }
            Ok(FrameType::Data) => {
                // Full validation first; a heartbeat is then a validated block
                // with no payload.
                let block = self.scan_block(offset)?;
                self.offset += block.reserved();
                if block.length() == 0 {
                    return Ok(ScanItem::Heartbeat { offset });
                }
                Ok(ScanItem::Message(block))
            }
            _ => Err(invalid(offset, "frame type not allowed in a term")),
        }
    }

    /// Validates every fragment of the block whose decision word at `start`
    /// is committed.
    fn scan_block(&self, start: u32) -> Result<MessageBlock<'a>, ProtocolError> {
        let mut offset = start;
        let mut length: u32 = 0;
        let mut first: Option<FrameHeader> = None;
        let mut first_extension: Option<&[u8]> = None;
        let end_of_stream;
        loop {
            if first.is_some() {
                // An interior fragment: classify its word 0 before reading the
                // rest of its header, so an interruption (an ABORTED or PAD
                // record, or an uncommitted word) never reads further.
                let word0 = Word0::unpack(u64::from_le_bytes(read8(self.term, offset)?))
                    .map_err(|_| invalid(offset, "reserved flag bits set"))?;
                if word0.frame_length() <= 0 || word0.frame_type_code() != FrameType::Data.code() {
                    return Err(invalid(offset, "block interrupted before END"));
                }
            }
            let header = self.check_header(offset, FrameType::Data)?;
            let flags = header.word0.flags();
            if flags.begin() != first.is_none() {
                return Err(invalid(offset, "BEGIN flag out of place"));
            }
            if flags.eos() && !flags.end() {
                return Err(invalid(offset, "EOS on a fragment that is not the last"));
            }
            if let Some(first) = first
                && flags.ext() != first.word0.flags().ext()
            {
                return Err(invalid(offset, "fragments disagree on the extension"));
            }
            let frame_length = u32::try_from(header.word0.frame_length())
                .map_err(|_| invalid(offset, "interior fragment not complete"))?;
            let header_length = flags.header_length();
            if frame_length < header_length {
                return Err(invalid(offset, "frame shorter than its header"));
            }
            let reserved = align_frame(frame_length)?;
            if reserved > self.term_length - offset {
                return Err(invalid(offset, "frame extends past the term"));
            }
            if flags.ext() {
                let ext = slice(self.term, offset + HEADER_LENGTH, EXTENSION_LENGTH)?;
                TraceExtension::decode(ext).map_err(|_| invalid(offset, "invalid extension"))?;
                // Every fragment of a traced message carries the same,
                // immutable extension.
                match first_extension {
                    None => first_extension = Some(ext),
                    Some(first) if first != ext => {
                        return Err(invalid(offset, "fragments disagree on the trace extension"));
                    }
                    Some(_) => {}
                }
            }
            length = length
                .checked_add(frame_length - header_length)
                .ok_or_else(|| invalid(offset, "message length overflow"))?;
            if first.is_none() {
                first = Some(header);
            }
            offset += reserved;
            if flags.end() {
                end_of_stream = flags.eos();
                break;
            }
            if offset == self.term_length {
                return Err(invalid(offset, "block ends without END"));
            }
        }
        let Some(first) = first else {
            return Err(invalid(start, "empty block"));
        };
        let block = slice(self.term, start, offset - start)?;
        Ok(MessageBlock {
            block,
            offset: start,
            length,
            lane: first.word0.flags().lane(),
            end_of_stream,
            reserved_value: first.reserved_value,
        })
    }

    fn check_header(&self, offset: u32, expected: FrameType) -> Result<FrameHeader, ProtocolError> {
        let header = FrameHeader::decode(slice(self.term, offset, HEADER_LENGTH)?)
            .map_err(|_| invalid(offset, "reserved flag bits set"))?;
        if header.word0.version() != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                version: header.word0.version(),
            });
        }
        if header.word0.frame_type_code() != expected.code() {
            return Err(invalid(offset, "unexpected frame type inside a block"));
        }
        if header.word0.flags().lane() != self.identity.lane {
            return Err(invalid(offset, "frame lane does not match the term's lane"));
        }
        if header.term_offset != offset as i32
            || header.term_id != self.identity.term_id
            || header.session_id != self.identity.session_id
            || header.stream_id != self.identity.stream_id
        {
            return Err(invalid(offset, "header identity does not match the term"));
        }
        Ok(header)
    }
}

fn invalid(offset: u32, reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidFrame { offset, reason }
}

fn read8(bytes: &[u8], offset: u32) -> Result<[u8; 8], ProtocolError> {
    let mut out = [0u8; 8];
    out.copy_from_slice(slice(bytes, offset, 8)?);
    Ok(out)
}

fn slice(bytes: &[u8], offset: u32, length: u32) -> Result<&[u8], ProtocolError> {
    let start = offset as usize;
    let end = start
        .checked_add(length as usize)
        .ok_or(ProtocolError::LengthOverflow {
            value: u64::from(length),
        })?;
    bytes.get(start..end).ok_or(ProtocolError::BufferTooShort {
        required: end,
        available: bytes.len(),
    })
}

fn slice_mut(bytes: &mut [u8], offset: u32, length: u32) -> Result<&mut [u8], ProtocolError> {
    let available = bytes.len();
    let start = offset as usize;
    let end = start
        .checked_add(length as usize)
        .ok_or(ProtocolError::LengthOverflow {
            value: u64::from(length),
        })?;
    bytes
        .get_mut(start..end)
        .ok_or(ProtocolError::BufferTooShort {
            required: end,
            available,
        })
}

fn tail_mut(bytes: &mut [u8], from: u32) -> Result<&mut [u8], ProtocolError> {
    let available = bytes.len();
    bytes
        .get_mut(from as usize..)
        .ok_or(ProtocolError::BufferTooShort {
            required: from as usize,
            available,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sizing::DEFAULT_MTU;

    const TERM: u32 = 64 * 1024;
    const IDENTITY: TermIdentity = TermIdentity {
        lane: Lane::ZERO,
        session_id: -7,
        stream_id: 1001,
        term_id: 0x1234_5678,
    };

    fn term_length() -> TermLength {
        TermLength::try_new(TERM).unwrap()
    }

    fn appender(term: &mut [u8]) -> TermAppender<'_> {
        TermAppender::new(term, term_length(), IDENTITY, DEFAULT_MTU, TERM / 8).unwrap()
    }

    fn scanner(term: &[u8]) -> TermScanner<'_> {
        TermScanner::new(term, term_length(), IDENTITY).unwrap()
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn message(item: ScanItem<'_>) -> MessageBlock<'_> {
        match item {
            ScanItem::Message(block) => block,
            other => panic!("expected a message, found {other:?}"),
        }
    }

    fn contents(block: &MessageBlock<'_>) -> Vec<u8> {
        let mut out = vec![0; block.length() as usize];
        assert_eq!(block.copy_to(&mut out).unwrap(), out.len());
        out
    }

    fn put_word0(term: &mut [u8], offset: u32, word: Word0) {
        let at = offset as usize;
        term[at..at + 8].copy_from_slice(&word.pack().to_le_bytes());
    }

    #[test]
    fn single_message_round_trip_then_pending() {
        let mut term = vec![0u8; TERM as usize];
        let data = payload(100, 1);
        let outcome = appender(&mut term)
            .append(&data, AppendOptions::default())
            .unwrap();
        assert_eq!(
            outcome,
            AppendOutcome::Appended {
                offset: 0,
                reserved: 160
            }
        );
        let mut scan = scanner(&term);
        let block = message(scan.next_item().unwrap());
        assert_eq!(
            (block.offset(), block.reserved(), block.length()),
            (0, 160, 100)
        );
        assert_eq!(contents(&block), data);
        assert_eq!(scan.next_item(), Ok(ScanItem::Pending));
        assert_eq!(scan.offset(), 160);
    }

    #[test]
    fn spec_sized_message_fragments_and_reassembles() {
        let mut term = vec![0u8; TERM as usize];
        let data = payload(8000, 2);
        let mut app = appender(&mut term);
        assert_eq!(app.max_message_length(), 8000);
        assert_eq!(
            app.append(&data, AppendOptions::default()),
            Ok(AppendOutcome::Appended {
                offset: 0,
                reserved: 8192
            })
        );
        assert_eq!(
            app.append(&payload(8001, 2), AppendOptions::default()),
            Err(ProtocolError::MessageTooLarge {
                length: 8001,
                max: 8000
            })
        );
        let block = message(scanner(&term).next_item().unwrap());
        assert_eq!(block.fragments().count(), 6);
        assert_eq!(contents(&block), data);
    }

    #[test]
    fn empty_messages_are_rejected_and_header_only_data_is_a_heartbeat() {
        let mut term = vec![0u8; TERM as usize];
        {
            let mut app = appender(&mut term);
            assert_eq!(
                app.append(&[], AppendOptions::default()),
                Err(ProtocolError::EmptyMessage)
            );
            assert_eq!(app.tail(), 0);
        }
        assert!(term.iter().all(|b| *b == 0));

        let heartbeat = FrameHeader {
            word0: Word0::new(
                32,
                Flags::new(true, true, false, false, Lane::ZERO),
                FrameType::Data,
            ),
            term_offset: 0,
            session_id: IDENTITY.session_id,
            stream_id: IDENTITY.stream_id,
            term_id: IDENTITY.term_id,
            reserved_value: 0,
        };
        heartbeat.encode(&mut term).unwrap();
        let mut scan = scanner(&term);
        assert_eq!(scan.next_item(), Ok(ScanItem::Heartbeat { offset: 0 }));
        assert_eq!(scan.offset(), 32);
    }

    #[test]
    fn end_of_stream_and_reserved_value() {
        let mut term = vec![0u8; TERM as usize];
        let options = AppendOptions {
            end_of_stream: true,
            extension: None,
            reserved_value: -1,
        };
        let _ = appender(&mut term)
            .append(&payload(3000, 9), options)
            .unwrap();
        let block = message(scanner(&term).next_item().unwrap());
        assert!(block.end_of_stream());
        assert_eq!(block.reserved_value(), -1);
        let flags: Vec<u8> = [0usize, 1408, 2816].iter().map(|at| term[at + 5]).collect();
        assert_eq!(flags, vec![0x01, 0x00, 0x02 | 0x04]);
    }

    #[test]
    fn markers_with_junk_are_pending_and_payload_headers_are_never_read() {
        let mut term = vec![0u8; TERM as usize];
        // A negative marker whose other bits are junk, including reserved
        // flag bits, and i32::MIN.
        term[..8].copy_from_slice(&0xFFFF_FFFF_8000_0000u64.to_le_bytes());
        assert_eq!(scanner(&term).next_item(), Ok(ScanItem::Pending));
        term[..8].copy_from_slice(&0xC0C0_C0C0_FFFF_FFE0u64.to_le_bytes());
        assert_eq!(scanner(&term).next_item(), Ok(ScanItem::Pending));

        // A payload that contains a valid-looking aligned header is data.
        let mut term = vec![0u8; TERM as usize];
        let mut fake = vec![0u8; 96];
        FrameHeader {
            word0: Word0::new(
                64,
                Flags::new(true, true, false, false, Lane::ZERO),
                FrameType::Pad,
            ),
            term_offset: 64,
            session_id: IDENTITY.session_id,
            stream_id: IDENTITY.stream_id,
            term_id: IDENTITY.term_id,
            reserved_value: 0,
        }
        .encode(&mut fake[32..])
        .unwrap();
        let _ = appender(&mut term)
            .append(&fake, AppendOptions::default())
            .unwrap();
        let mut scan = scanner(&term);
        assert_eq!(contents(&message(scan.next_item().unwrap())), fake);
        assert_eq!(scan.next_item(), Ok(ScanItem::Pending));
    }

    #[test]
    fn extension_messages_respect_the_configured_budget() {
        let mut term = vec![0u8; TERM as usize];
        let mut app =
            TermAppender::new(&mut term, term_length(), IDENTITY, DEFAULT_MTU, 128).unwrap();
        let traced = AppendOptions {
            extension: Some(TraceExtension::default()),
            ..AppendOptions::default()
        };
        // 96-byte header + 64 bytes reserves 160 > 128.
        assert_eq!(
            app.append(&payload(64, 1), traced),
            Err(ProtocolError::MessageTooLarge {
                length: 64,
                max: 32
            })
        );
        assert_eq!(app.append(&payload(32, 1), traced).map(|_| ()), Ok(()));
    }

    #[test]
    fn invalid_extension_fails_before_writing() {
        let mut term = vec![0u8; TERM as usize];
        {
            let mut app = appender(&mut term);
            let options = AppendOptions {
                extension: Some(TraceExtension {
                    extension_flags: 1,
                    ..TraceExtension::default()
                }),
                ..AppendOptions::default()
            };
            assert!(app.append(&payload(3000, 1), options).is_err());
            assert_eq!(app.tail(), 0);
        }
        assert!(term.iter().all(|b| *b == 0));
    }

    #[test]
    fn traced_fragments_must_agree() {
        let mut base = vec![0u8; TERM as usize];
        let options = AppendOptions {
            extension: Some(TraceExtension {
                message_id: 99,
                ..TraceExtension::default()
            }),
            ..AppendOptions::default()
        };
        let _ = appender(&mut base)
            .append(&payload(3000, 2), options)
            .unwrap();
        assert!(matches!(
            scanner(&base).next_item(),
            Ok(ScanItem::Message(_))
        ));
        // Second fragment without EXT, or with another message id.
        let mut cleared = base.clone();
        cleared[1408 + 5] &= !0x08;
        assert!(scanner(&cleared).next_item().is_err());
        let mut changed = base.clone();
        changed[1408 + 32 + 40] = 100;
        assert!(scanner(&changed).next_item().is_err());
    }

    #[test]
    fn invalid_extension_on_a_full_term_does_not_pad() {
        let mut term = vec![0u8; TERM as usize];
        let mut app = appender(&mut term);
        let filler = payload(8000, 3);
        while app.tail() + 8192 <= TERM - 4096 {
            let _ = app.append(&filler, AppendOptions::default()).unwrap();
        }
        let tail = app.tail();
        let options = AppendOptions {
            extension: Some(TraceExtension {
                extension_flags: 1,
                ..TraceExtension::default()
            }),
            ..AppendOptions::default()
        };
        assert!(app.append(&payload(7000, 3), options).is_err());
        assert_eq!(app.tail(), tail);
    }

    #[test]
    fn extension_messages_round_trip() {
        let mut term = vec![0u8; TERM as usize];
        let extension = TraceExtension {
            message_id: 99,
            ..TraceExtension::default()
        };
        let data = payload(3000, 3);
        let options = AppendOptions {
            extension: Some(extension),
            ..AppendOptions::default()
        };
        let _ = appender(&mut term).append(&data, options).unwrap();
        let block = message(scanner(&term).next_item().unwrap());
        assert_eq!(block.fragments().count(), 3);
        assert_eq!(contents(&block), data);
    }

    #[test]
    fn full_term_is_padded_and_ends_the_scan() {
        let mut term = vec![0u8; TERM as usize];
        let data = payload(5000, 4);
        let mut app = appender(&mut term);
        let mut appended = 0;
        while let AppendOutcome::Appended { .. } =
            app.append(&data, AppendOptions::default()).unwrap()
        {
            appended += 1;
        }
        assert_eq!(app.tail(), TERM);
        assert_eq!(
            app.append(&data, AppendOptions::default()),
            Ok(AppendOutcome::TermFull)
        );
        let mut scan = scanner(&term);
        for _ in 0..appended {
            assert_eq!(contents(&message(scan.next_item().unwrap())), data);
        }
        assert_eq!(scan.next_item(), Ok(ScanItem::End));
        assert_eq!(scan.next_item(), Ok(ScanItem::End));
    }

    #[test]
    fn uncommitted_decision_word_hides_committed_looking_interior_fragments() {
        let mut term = vec![0u8; TERM as usize];
        let _ = appender(&mut term)
            .append(&payload(4000, 5), AppendOptions::default())
            .unwrap();
        // Interior fragment word 0 is positive, but the block's decision word
        // is not committed yet.
        term[..8].fill(0);
        assert_eq!(scanner(&term).next_item(), Ok(ScanItem::Pending));
        put_word0(
            &mut term,
            0,
            Word0::new(-4096, Flags::NONE, FrameType::Data),
        );
        assert_eq!(scanner(&term).next_item(), Ok(ScanItem::Pending));
    }

    #[test]
    fn aborted_block_is_skipped_reading_only_word0() {
        let mut term = vec![0u8; TERM as usize];
        let mut app = appender(&mut term);
        let first = app
            .append(&payload(3000, 6), AppendOptions::default())
            .unwrap();
        let second = payload(200, 7);
        let _ = app.append(&second, AppendOptions::default()).unwrap();
        let AppendOutcome::Appended { reserved, .. } = first else {
            panic!("first append failed");
        };
        // Garbage after word 0 must not be read.
        term[8..reserved as usize].fill(0xFF);
        put_word0(
            &mut term,
            0,
            Word0::new(reserved as i32, Flags::NONE, FrameType::Aborted),
        );
        let mut scan = scanner(&term);
        assert_eq!(
            scan.next_item(),
            Ok(ScanItem::Aborted {
                offset: 0,
                extent: reserved
            })
        );
        assert_eq!(contents(&message(scan.next_item().unwrap())), second);
    }

    #[test]
    fn malformed_frames_are_rejected_without_advancing() {
        let base = {
            let mut term = vec![0u8; TERM as usize];
            let _ = appender(&mut term)
                .append(&payload(3000, 8), AppendOptions::default())
                .unwrap();
            term
        };
        type Corruption = Box<dyn Fn(&mut Vec<u8>)>;
        let corruptions: Vec<(&str, Corruption)> = vec![
            ("version", Box::new(|t| t[4] = 9)),
            ("reserved flags", Box::new(|t| t[5] |= 0x40)),
            (
                "type in term",
                Box::new(|t| t[6] = FrameType::Nak.code() as u8),
            ),
            ("term offset", Box::new(|t| t[8] = 32)),
            ("session", Box::new(|t| t[12] ^= 1)),
            ("stream", Box::new(|t| t[16] ^= 1)),
            ("term id", Box::new(|t| t[20] ^= 1)),
            ("short frame", Box::new(|t| t[0] = 8)),
            ("missing BEGIN", Box::new(|t| t[5] &= !0x01)),
            ("interior BEGIN", Box::new(|t| t[1408 + 5] |= 0x01)),
            ("interior lane", Box::new(|t| t[1408 + 5] |= 0x10)),
            ("first lane", Box::new(|t| t[5] |= 0x10)),
            ("interior extension", Box::new(|t| t[1408 + 5] |= 0x08)),
            ("early EOS", Box::new(|t| t[1408 + 5] |= 0x04)),
            (
                "aborted interruption",
                Box::new(|t| {
                    t[1408..1408 + 8].copy_from_slice(
                        &Word0::new(1408, Flags::NONE, FrameType::Aborted)
                            .pack()
                            .to_le_bytes(),
                    );
                    t[1408 + 8..2816].fill(0xFF);
                }),
            ),
            (
                "aborted version",
                Box::new(|t| {
                    t[..8].copy_from_slice(
                        &Word0::new(4192, Flags::NONE, FrameType::Aborted)
                            .pack()
                            .to_le_bytes(),
                    );
                    t[4] = 2;
                }),
            ),
            (
                "interior incomplete",
                Box::new(|t| t[1408..1408 + 4].copy_from_slice(&(-1i32).to_le_bytes())),
            ),
            (
                "missing END",
                Box::new(|t| {
                    t[2816 + 5] &= !0x02;
                    t[2816..2820].copy_from_slice(&1376i32.to_le_bytes());
                }),
            ),
            (
                "past term end",
                Box::new(|t| t[0..4].copy_from_slice(&(TERM as i32 + 32).to_le_bytes())),
            ),
        ];
        for (name, corrupt) in corruptions {
            let mut term = base.clone();
            corrupt(&mut term);
            let mut scan = scanner(&term);
            assert!(scan.next_item().is_err(), "{name} was accepted");
            assert_eq!(scan.offset(), 0, "{name} advanced");
        }
    }

    #[test]
    fn bad_pad_and_aborted_extents_are_rejected() {
        let mut term = vec![0u8; TERM as usize];
        put_word0(&mut term, 0, Word0::new(64, Flags::NONE, FrameType::Pad));
        assert!(scanner(&term).next_item().is_err());
        put_word0(
            &mut term,
            0,
            Word0::new(48, Flags::NONE, FrameType::Aborted),
        );
        assert!(scanner(&term).next_item().is_err());
        put_word0(
            &mut term,
            0,
            Word0::new(TERM as i32 + 32, Flags::NONE, FrameType::Aborted),
        );
        assert!(scanner(&term).next_item().is_err());
    }

    #[test]
    fn heartbeats_are_fully_validated() {
        let mut term = vec![0u8; TERM as usize];
        // A 96-byte header-only frame with EXT but an invalid (all-zero)
        // extension is rejected, not reported as a heartbeat.
        let at = (TERM - 64) as usize;
        let header = FrameHeader {
            word0: Word0::new(
                96,
                Flags::new(true, true, false, true, Lane::ZERO),
                FrameType::Data,
            ),
            term_offset: at as i32,
            session_id: IDENTITY.session_id,
            stream_id: IDENTITY.stream_id,
            term_id: IDENTITY.term_id,
            reserved_value: 0,
        };
        // Reach the offset by an aborted extent covering the start.
        term[..8].copy_from_slice(
            &Word0::new(at as i32, Flags::NONE, FrameType::Aborted)
                .pack()
                .to_le_bytes(),
        );
        header.encode(&mut term[at..]).unwrap();
        let mut scan = scanner(&term);
        assert!(matches!(scan.next_item(), Ok(ScanItem::Aborted { .. })));
        assert!(scan.next_item().is_err());
        assert_eq!(scan.offset() as usize, at);

        // A valid traced heartbeat is reported as a heartbeat.
        let mut term = vec![0u8; TERM as usize];
        let traced = FrameHeader {
            term_offset: 0,
            ..header
        };
        traced.encode(&mut term).unwrap();
        TraceExtension::default().encode(&mut term[32..]).unwrap();
        let mut scan = scanner(&term);
        assert_eq!(scan.next_item(), Ok(ScanItem::Heartbeat { offset: 0 }));
        assert_eq!(scan.offset(), 96);
    }

    #[test]
    fn a_new_appender_resets_the_term() {
        let mut term = vec![0u8; TERM as usize];
        let _ = appender(&mut term)
            .append(&payload(5000, 1), AppendOptions::default())
            .unwrap();
        let short = payload(10, 2);
        let _ = appender(&mut term)
            .append(&short, AppendOptions::default())
            .unwrap();
        let mut scan = scanner(&term);
        assert_eq!(contents(&message(scan.next_item().unwrap())), short);
        assert_eq!(scan.next_item(), Ok(ScanItem::Pending));
    }

    #[test]
    fn wrong_buffer_lengths_are_rejected() {
        let mut short = vec![0u8; TERM as usize - 1];
        assert!(
            TermAppender::new(&mut short, term_length(), IDENTITY, DEFAULT_MTU, TERM / 8).is_err()
        );
        assert!(TermScanner::new(&short, term_length(), IDENTITY).is_err());
        let mut term = vec![0u8; TERM as usize];
        assert!(
            TermAppender::new(&mut term, term_length(), IDENTITY, DEFAULT_MTU, TERM / 4).is_err()
        );
    }

    /// Randomized append and scan with a fixed-seed generator: the scanner
    /// returns exactly the appended sequence, then the term end.
    #[test]
    fn randomized_sequences_round_trip() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..20 {
            let mut term = vec![0u8; TERM as usize];
            let mut appended = Vec::new();
            {
                let mut app = appender(&mut term);
                loop {
                    let len = (next() % 8000) as usize + 1;
                    let data = payload(len, round as u8);
                    let ext = next() % 4 == 0;
                    let options = AppendOptions {
                        extension: ext.then_some(TraceExtension::default()),
                        ..AppendOptions::default()
                    };
                    match app.append(&data, options) {
                        Ok(AppendOutcome::Appended { .. }) => appended.push(data),
                        Ok(AppendOutcome::TermFull) => break,
                        Err(ProtocolError::MessageTooLarge { .. }) => {}
                        Err(err) => panic!("append failed: {err}"),
                    }
                }
            }
            let mut scan = scanner(&term);
            for expected in &appended {
                assert_eq!(&contents(&message(scan.next_item().unwrap())), expected);
            }
            assert_eq!(scan.next_item(), Ok(ScanItem::End));
        }
    }
}
