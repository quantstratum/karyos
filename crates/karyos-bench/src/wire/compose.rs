// SPDX-License-Identifier: Apache-2.0

//! Composition of the datagrams of one message of a workload shape
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.3,
//! "Frames").
//!
//! Until the sender read capability of P2.5 S2 exists, the frames of a
//! shape are appended to a term through [`TermAppender`] and read back
//! through [`TermScanner`], the encoding production uses; results carry
//! the label [`COMPOSED_LABEL`]. That is done once per shape, as a
//! template. Every message then copies the template and writes its
//! sequence number into the `reserved_value` of each frame header, so the
//! composition of a message costs one copy and allocates nothing after
//! the template is built; it precedes the timed send stage.

use std::ops::Range;

use karyos_protocol::frame::{
    Flags, FrameHeader, FrameType, HEADER_LENGTH, Lane, TraceExtension, Word0,
};
use karyos_protocol::sizing::{TermLength, align_frame};
use karyos_protocol::term::{
    AppendOptions, AppendOutcome, ScanItem, TermAppender, TermIdentity, TermScanner,
};

use crate::manifest::{MtuRule, Shape, Size, w6_datagrams};
use crate::workloads::BenchError;

/// The label every result composed this way carries.
pub const COMPOSED_LABEL: &str = "composed sender path";

/// The term the templates are composed in: 64 KiB, the smallest term,
/// whose eighth (8 KiB) holds the largest message of every shape (W7).
const TERM: u32 = 64 * 1024;

/// The fixed identity of the composed frames (`static binding`).
pub const IDENTITY: TermIdentity = TermIdentity {
    lane: Lane::ZERO,
    session_id: 1,
    stream_id: 1,
    term_id: 0,
};

/// The byte offset of `reserved_value` in a frame header.
const RESERVED_VALUE: usize = 24;

/// A `u32` length as `usize`, checked (SPEC §14: no `as` conversions).
fn to_usize(value: u32) -> Result<usize, BenchError> {
    usize::try_from(value).map_err(|_| BenchError(format!("length {value} exceeds usize")))
}

/// The frame length of a header-only DATA frame (W2): the 32-byte header.
const HEARTBEAT_LENGTH: i32 = 32;

/// The datagrams of one message of a shape, built once and stamped per
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// The shape.
    pub shape: Shape,
    /// Its size at the point.
    pub size: Size,
    /// The datagram bytes, back to back.
    bytes: Vec<u8>,
    /// Each datagram's range in `bytes`.
    datagrams: Vec<Range<usize>>,
    /// The offset of each frame header in `bytes`, to stamp.
    headers: Vec<usize>,
}

impl Template {
    /// Composes the template of `shape` for a profile whose DATA envelope
    /// is `envelope` bytes, at the point's `e_max` under `rule`. The
    /// payload `L` follows `e_max` for every profile (manifest 2.0 6.1),
    /// while the frame budget, and so the W6 datagram count, follows the
    /// profile's own envelope: `trusted` (0) composes W6 in 5 datagrams
    /// even where a larger envelope needs 6.
    ///
    /// # Errors
    ///
    /// An envelope above `e_max`, the size errors of the manifest model,
    /// W8 (no size formula here), and any encoding error, which would be
    /// a defect.
    pub fn new(shape: Shape, e_max: u32, envelope: u32, rule: MtuRule) -> Result<Self, BenchError> {
        if envelope > e_max {
            return Err(BenchError(format!(
                "envelope {envelope} above E_max {e_max}"
            )));
        }
        let size = shape
            .size(e_max, rule)
            .map_err(|error| BenchError(format!("{shape}: {error}")))?;
        let mut term = vec![0_u8; to_usize(TERM)?];
        let term_length =
            TermLength::try_new(TERM).map_err(|error| BenchError(format!("term: {error}")))?;
        let mut blocks: Vec<Range<usize>> = Vec::new();
        if shape == Shape::W2 {
            // A header-only DATA frame: a heartbeat, not a message.
            let heartbeat = FrameHeader {
                word0: Word0::new(
                    HEARTBEAT_LENGTH,
                    Flags::new(true, true, false, false, Lane::ZERO),
                    FrameType::Data,
                ),
                term_offset: 0,
                session_id: IDENTITY.session_id,
                stream_id: IDENTITY.stream_id,
                term_id: IDENTITY.term_id,
                reserved_value: 0,
            };
            heartbeat
                .encode(&mut term)
                .map_err(|error| BenchError(format!("heartbeat: {error}")))?;
        } else {
            // The frames fill the budget the rule leaves for them: under
            // `CountsEnvelope` the envelope comes out of the MTU.
            let budget = rule
                .frame_budget(size.mtu, envelope)
                .map_err(|error| BenchError(format!("{shape}: {error}")))?;
            let mut appender =
                TermAppender::new(&mut term, term_length, IDENTITY, budget, TERM / 8)
                    .map_err(|error| BenchError(format!("appender: {error}")))?;
            let payload = vec![0x5a_u8; to_usize(size.payload)?];
            let options = AppendOptions {
                extension: size.ext.then(TraceExtension::default),
                ..AppendOptions::default()
            };
            for _ in 0..size.frames_per_datagram {
                match appender.append(&payload, options) {
                    Ok(AppendOutcome::Appended { .. }) => {}
                    Ok(AppendOutcome::TermFull) => {
                        return Err(BenchError(format!("{shape}: template term full")));
                    }
                    Err(error) => return Err(BenchError(format!("{shape}: {error}"))),
                }
            }
        }
        let mut scanner = TermScanner::new(&term, term_length, IDENTITY)
            .map_err(|error| BenchError(format!("scanner: {error}")))?;
        loop {
            match scanner.next_item() {
                Ok(ScanItem::Message(block)) => {
                    let start = to_usize(block.offset())?;
                    let end = start
                        .checked_add(to_usize(block.reserved())?)
                        .ok_or_else(|| BenchError(format!("{shape}: block end overflow")))?;
                    blocks.push(start..end);
                }
                Ok(ScanItem::Heartbeat { offset }) => {
                    let start = to_usize(offset)?;
                    let end = start
                        .checked_add(to_usize(HEADER_LENGTH)?)
                        .ok_or_else(|| BenchError(format!("{shape}: heartbeat end overflow")))?;
                    blocks.push(start..end);
                }
                Ok(ScanItem::End | ScanItem::Pending) => break,
                Ok(ScanItem::Aborted { .. }) => {
                    return Err(BenchError(format!("{shape}: aborted block in template")));
                }
                Err(error) => return Err(BenchError(format!("{shape}: {error}"))),
            }
        }
        // Frame boundaries inside the blocks.
        let mut frames: Vec<Range<usize>> = Vec::new();
        for block in &blocks {
            let mut at = block.start;
            while at < block.end {
                let header = term
                    .get(at..)
                    .ok_or_else(|| BenchError(format!("{shape}: frame past the term")))
                    .and_then(|rest| {
                        FrameHeader::decode(rest)
                            .map_err(|error| BenchError(format!("{shape}: {error}")))
                    })?;
                let length = u32::try_from(header.word0.frame_length())
                    .map_err(|_| BenchError(format!("{shape}: negative frame length")))?;
                let reserved = to_usize(
                    align_frame(length).map_err(|error| BenchError(format!("{shape}: {error}")))?,
                )?;
                let next = at
                    .checked_add(reserved)
                    .filter(|next| *next > at)
                    .ok_or_else(|| BenchError(format!("{shape}: frame end overflow")))?;
                frames.push(at..next);
                at = next;
            }
        }
        // Datagrams: W5 packs every frame into one; W6 sends each fragment
        // in its own; every other shape is one frame per datagram.
        let groups: Vec<Vec<Range<usize>>> = if shape == Shape::W5 {
            vec![frames]
        } else {
            frames.into_iter().map(|frame| vec![frame]).collect()
        };
        let mut bytes = Vec::new();
        let mut datagrams = Vec::new();
        let mut headers = Vec::new();
        for group in groups {
            let start = bytes.len();
            for frame in group {
                headers.push(bytes.len());
                let slice = term
                    .get(frame)
                    .ok_or_else(|| BenchError(format!("{shape}: frame out of range")))?;
                bytes.extend_from_slice(slice);
            }
            datagrams.push(start..bytes.len());
        }
        // W6 takes the count of the profile's envelope (manifest 2.0 6.1).
        let expected = if shape == Shape::W6 {
            to_usize(
                w6_datagrams(envelope, rule)
                    .map_err(|error| BenchError(format!("{shape}: {error}")))?,
            )?
        } else {
            to_usize(size.datagrams_per_message)?
        };
        if datagrams.len() != expected {
            return Err(BenchError(format!(
                "{shape}: {} datagrams composed, {expected} expected",
                datagrams.len()
            )));
        }
        Ok(Self {
            shape,
            size,
            bytes,
            datagrams,
            headers,
        })
    }

    /// The number of datagrams of one message.
    #[must_use]
    pub fn datagrams(&self) -> usize {
        self.datagrams.len()
    }

    /// The frame headers of one message.
    #[must_use]
    pub fn frames(&self) -> usize {
        self.headers.len()
    }

    /// The bytes of one message, all datagrams back to back.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the template has no bytes; never true for a composed one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Writes message `sequence` into `out`, which must be [`Self::len`]
    /// bytes long: the template, with `sequence` in every frame's
    /// `reserved_value`. Allocates nothing.
    ///
    /// # Errors
    ///
    /// A buffer of the wrong length.
    pub fn stamp(&self, sequence: u64, out: &mut [u8]) -> Result<(), BenchError> {
        if out.len() != self.bytes.len() {
            return Err(BenchError(format!(
                "stamp buffer of {} bytes, {} needed",
                out.len(),
                self.bytes.len()
            )));
        }
        out.copy_from_slice(&self.bytes);
        let value = sequence.to_le_bytes();
        for &header in &self.headers {
            let field = header
                .checked_add(RESERVED_VALUE)
                .and_then(|start| out.get_mut(start..start.checked_add(8)?))
                .ok_or_else(|| BenchError("frame header outside the message".into()))?;
            field.copy_from_slice(&value);
        }
        Ok(())
    }

    /// Datagram `index` of a stamped message `bytes`.
    #[must_use]
    pub fn datagram<'b>(&self, bytes: &'b [u8], index: usize) -> Option<&'b [u8]> {
        bytes.get(self.datagrams.get(index)?.clone())
    }
}

/// The sequence number a received frame carries in `reserved_value`.
#[must_use]
pub fn sequence_of(frame: &[u8]) -> Option<u64> {
    let field = frame.get(RESERVED_VALUE..RESERVED_VALUE.checked_add(8)?)?;
    let mut value = [0_u8; 8];
    value.copy_from_slice(field);
    Some(u64::from_le_bytes(value))
}

#[cfg(test)]
mod tests;
