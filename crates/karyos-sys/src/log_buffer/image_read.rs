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
use crate::publication::observe_block;
use crate::sizing::align_frame;
use crate::term_bytes::TermBytes;

/// One committed frame of the walk.
struct Frame {
    word0: Word0,
    frame_type: FrameType,
    /// Aligned extent of the frame in the term.
    reserved: u32,
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
        match first.frame_type {
            FrameType::Pad => {
                if first.reserved != term_length - start {
                    return Err(corrupt(start, "pad extent"));
                }
                return Ok(Validated::Pad);
            }
            FrameType::Aborted => {
                if flags.lane() != buffer.config.lane {
                    return Err(corrupt(start, "aborted lane"));
                }
                return Ok(Validated::Aborted {
                    extent: first.reserved,
                });
            }
            _ if !flags.begin() => return self.orphan_run(slot, start),
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
            if next.frame_type != FrameType::Data || next.word0.flags().begin() {
                return Ok(Validated::Skip {
                    extent: offset - start,
                    reason: SkipReason::Interrupted,
                });
            }
            frame = next;
        }
    }

    /// Skips the committed run of DATA frames without BEGIN at `start`, up
    /// to the next BEGIN, ABORTED, PAD or uncommitted frame.
    fn orphan_run(&self, slot: u8, start: u32) -> Result<Validated, SysError> {
        let term_length = self.buffer.term_length;
        let mut offset = start;
        while offset < term_length {
            match self.frame(slot, offset)? {
                Some(frame)
                    if frame.frame_type == FrameType::Data && !frame.word0.flags().begin() =>
                {
                    offset += frame.reserved;
                }
                _ => break,
            }
        }
        let reason = if self.cursor.joining {
            SkipReason::JoinedMidMessage
        } else {
            SkipReason::Orphan
        };
        Ok(Validated::Skip {
            extent: offset - start,
            reason,
        })
    }

    /// The committed frame at `offset`, its word 0 loaded with Acquire (each
    /// is its own publication in an image), or `None` when not published
    /// yet. Its extent is checked against the term end.
    fn frame(&self, slot: u8, offset: u32) -> Result<Option<Frame>, SysError> {
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
            frame_type,
            reserved,
        }))
    }
}
