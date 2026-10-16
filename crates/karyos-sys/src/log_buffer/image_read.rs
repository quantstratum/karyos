// SPDX-License-Identifier: Apache-2.0

//! The read mode of an image (`quantstratum-docs: karyos/design/receive-publication.md`,
//! "Fragments are published one by one", batch r3).
//!
//! In a publisher's log one Release store publishes a whole block, so a
//! reader that sees the first fragment sees them all. In an image every
//! fragment is published by its own word 0, as it arrived. This first pass
//! therefore loads every fragment's word 0 with Acquire, waits on an
//! incomplete message, and checks the message structure that the receive
//! owner cannot check frame by frame. A malformed structure is skipped and
//! reported, never `CorruptTerm`: the image holds what a remote peer sent.

use super::{FRAME_ALIGNMENT, SkipReason, SubscriptionContext, Validated, corrupt};
use crate::error::SysError;
use crate::frame::{FrameType, PROTOCOL_VERSION, Word0};
use crate::local_gap::{GAP_BODY_LENGTH, GapSite, LOCAL_GAP_TYPE, check_body, check_word0};
use crate::publication::observe_block;
use crate::sizing::align_frame;
use crate::term_bytes::TermBytes;

/// What a committed block of an image is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// A wire frame type.
    Frame(FrameType),
    /// A local gap record of an image with the `LOCAL_GAPS` capability.
    LocalGap,
}

/// One committed frame of the walk.
pub(super) struct Frame {
    pub(super) word0: Word0,
    pub(super) kind: Kind,
    /// Aligned extent of the frame in the term.
    pub(super) reserved: u32,
}

impl Frame {
    /// Whether it is a DATA frame.
    pub(super) fn data(&self) -> bool {
        self.kind == Kind::Frame(FrameType::Data)
    }
}

impl<T: TermBytes> SubscriptionContext<'_, T> {
    /// The first pass over the frame at `start` of an image, under the
    /// caller's read loan.
    pub(super) fn validate_image_block(&self, slot: u8, start: u32) -> Result<Validated, SysError> {
        let buffer = self.buffer;
        let term_length = buffer.term_length;
        let Some(first) = self.frame(slot, start)? else {
            return Ok(Validated::Pending);
        };
        let flags = first.word0.flags();
        match first.kind {
            Kind::LocalGap => {
                return self.local_gap(slot, self.cursor.position, start, first.reserved);
            }
            Kind::Frame(FrameType::Pad) => {
                if first.reserved != term_length - start {
                    return Err(corrupt(start, "pad extent"));
                }
                return Ok(Validated::Pad);
            }
            Kind::Frame(FrameType::Aborted) => {
                if flags.lane() != buffer.config.lane {
                    return Err(corrupt(start, "aborted lane"));
                }
                return Ok(Validated::Aborted {
                    extent: first.reserved,
                });
            }
            _ if !flags.begin() => return self.orphan_run(slot, start, usize::MAX),
            _ => {}
        }
        let max_reserved = buffer.config.max_reserved;
        let max_length = buffer.max_message_length;
        let mut offset = start;
        let mut frame = first;
        let mut reserved: u32 = 0;
        let mut length: u32 = 0;
        // Every iteration moves `offset` forward by a positive extent
        // inside the term, so the walk ends.
        loop {
            let header_length = frame.word0.flags().header_length();
            let frame_length = frame.word0.frame_length().cast_unsigned();
            reserved = reserved.saturating_add(frame.reserved);
            length = length.saturating_add(frame_length.saturating_sub(header_length));
            offset += frame.reserved;
            if reserved > max_reserved || length > max_length {
                return Ok(Validated::Skip {
                    extent: offset - start,
                    reason: SkipReason::MessageTooLarge,
                });
            }
            if frame.word0.flags().end() {
                return Ok(Validated::Block(super::Block {
                    end: offset,
                    length,
                    end_of_stream: frame.word0.flags().eos(),
                    ext: flags.ext(),
                }));
            }
            if offset == term_length {
                return Ok(Validated::Skip {
                    extent: term_length - start,
                    reason: SkipReason::MissingEnd,
                });
            }
            let Some(next) = self.frame(slot, offset)? else {
                // A fragment not yet received: the message is incomplete.
                return Ok(Validated::Pending);
            };
            if !next.data() || next.word0.flags().begin() {
                return Ok(Validated::Skip {
                    extent: offset - start,
                    reason: SkipReason::Interrupted,
                });
            }
            frame = next;
        }
    }

    /// Skips the committed run of DATA frames without BEGIN at `start`, up
    /// to the next BEGIN, ABORTED, PAD or uncommitted frame, or after
    /// `limit` frames (a frame reader's bounded skip step; the rest of the
    /// run is the next step).
    pub(super) fn orphan_run(
        &self,
        slot: u8,
        start: u32,
        limit: usize,
    ) -> Result<Validated, SysError> {
        let term_length = self.buffer.term_length;
        let mut offset = start;
        let mut walked = 0usize;
        while offset < term_length && walked < limit {
            walked += 1;
            match self.frame(slot, offset)? {
                Some(frame) if frame.data() && !frame.word0.flags().begin() => {
                    offset += frame.reserved;
                }
                _ => break,
            }
        }
        let reason = self.cursor.resync.run_reason();
        Ok(Validated::Skip {
            extent: offset - start,
            reason,
        })
    }

    /// The committed frame at `offset`, its word 0 loaded with Acquire (each
    /// is its own publication in an image), or `None` when not published
    /// yet. Its extent is checked against the term end.
    pub(super) fn frame(&self, slot: u8, offset: u32) -> Result<Option<Frame>, SysError> {
        let term_length = self.buffer.term_length;
        // SAFETY: the caller holds a read loan for this slot's term; `offset`
        // is a frame start of the walk (`start` or the end of a committed
        // frame), a 32-byte boundary below the term end.
        let raw = observe_block(unsafe { self.buffer.regions.word0(slot, offset) });
        let signed = raw as u32 as i32;
        if signed <= 0 {
            return Ok(None);
        }
        let word0 = Word0::unpack(raw).map_err(|_| corrupt(offset, "reserved flags"))?;
        if word0.version() != PROTOCOL_VERSION {
            return Err(corrupt(offset, "version"));
        }
        if word0.frame_type_code() == LOCAL_GAP_TYPE && self.buffer.local_gaps() {
            let reserved = check_word0(word0, offset, term_length, self.buffer.config.lane)
                .map_err(|reason| corrupt(offset, reason))?;
            return Ok(Some(Frame {
                word0,
                kind: Kind::LocalGap,
                reserved,
            }));
        }
        // Without the capability a local gap type is an unknown type.
        let frame_type = FrameType::try_from_code(word0.frame_type_code())
            .map_err(|_| corrupt(offset, "frame type"))?;
        let length = signed.cast_unsigned();
        let reserved = match frame_type {
            // The receive owner stores the logical extent of a record.
            FrameType::Pad | FrameType::Aborted if length.is_multiple_of(FRAME_ALIGNMENT) => length,
            FrameType::Data if length >= word0.flags().header_length() => {
                align_frame(length).map_err(|_| corrupt(offset, "frame length"))?
            }
            _ => return Err(corrupt(offset, "frame length")),
        };
        if reserved > term_length - offset {
            return Err(corrupt(offset, "frame past term end"));
        }
        Ok(Some(Frame {
            word0,
            kind: Kind::Frame(frame_type),
            reserved,
        }))
    }

    /// The local gap record at `start` of `extent` bytes, whose word 0
    /// [`Self::frame`] loaded with Acquire and checked: its header is
    /// checked against the read position and the image, and the interval
    /// is skipped without reading it.
    pub(super) fn local_gap(
        &self,
        slot: u8,
        position: u64,
        start: u32,
        extent: u32,
    ) -> Result<Validated, SysError> {
        let buffer = self.buffer;
        let (count, offset) = buffer.split(position)?;
        if offset != start {
            return Err(corrupt(start, "local gap position"));
        }
        let header = start
            .checked_add(8)
            .ok_or_else(|| corrupt(start, "local gap position"))?;
        let mut body = [0u8; GAP_BODY_LENGTH];
        // SAFETY: the caller holds a read loan for this slot's term;
        // `header`, `start + 8`, is a multiple of 8 and the 24 bytes after word 0 lie inside
        // the record (its extent is at least 32, checked by `check_word0`),
        // with no other word 0; `frame` loaded this record's word 0 with
        // Acquire, and the owner stored these bytes before its Release.
        unsafe { buffer.regions.read_bytes(slot, header, &mut body) };
        let site = GapSite {
            term_offset: start,
            term_id: buffer
                .initial_term_id
                .advanced_by(count)
                .get()
                .cast_signed(),
            session_id: buffer.config.session_id,
            stream_id: buffer.config.stream_id,
        };
        let reason = check_body(&body, site).map_err(|reason| corrupt(start, reason))?;
        Ok(Validated::Skip {
            extent,
            reason: SkipReason::LocalGap(reason),
        })
    }
}
