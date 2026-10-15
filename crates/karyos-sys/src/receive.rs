// SPDX-License-Identifier: Apache-2.0

//! Validation of a received data datagram before anything is written into an
//! image (`quantstratum-docs: karyos/design/receive-publication.md`, stage 1).
//!
//! [`ValidatedDatagram::parse`] accepts a whole datagram or rejects it: a
//! datagram with one bad frame yields no frame at all (SPEC.md 7.2). It checks
//! everything that needs no image state: the MTU, every frame's header, its
//! length against the datagram and the term, the trace extension, and the
//! canonical PAD and ABORTED records. The term window, duplicates and
//! overlaps are checked later by the receive owner, against its own state.
//!
//! Only [`ValidatedFrame`], for DATA with a payload, PAD and ABORTED, can be
//! written into an image; it is built here and nowhere else. A header-only
//! DATA frame is a [`Heartbeat`], a control observation that no image write
//! accepts.

use crate::frame::{
    EXTENSION_LENGTH, ExtensionFault, FRAME_ALIGNMENT, Flags, FrameType, HEADER_LENGTH, Lane,
    PROTOCOL_VERSION, Word0, check_extension,
};
use crate::sizing::{FragmentPlan, TermLength, align_frame};
use crate::term::TermId;

/// Why a datagram was rejected. `offset` is the byte offset of the offending
/// frame in the datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The image parameters are invalid.
    #[error("invalid image parameters: {reason}")]
    InvalidParams {
        /// What is wrong.
        reason: &'static str,
    },
    /// The datagram holds no byte.
    #[error("empty datagram")]
    Empty,
    /// The datagram is longer than the image's MTU.
    #[error("datagram of {length} bytes exceeds the mtu of {mtu}")]
    TooLong {
        /// The datagram length.
        length: usize,
        /// The image's MTU.
        mtu: u32,
    },
    /// Fewer than 32 bytes remain where a frame header must start.
    #[error("truncated header at offset {offset}")]
    Truncated {
        /// Offset of the frame.
        offset: usize,
    },
    /// Word 0 carries another protocol version.
    #[error("unsupported version {version} at offset {offset}")]
    Version {
        /// Offset of the frame.
        offset: usize,
        /// The version byte.
        version: u8,
    },
    /// Reserved flag bits are set.
    #[error("reserved flag bits {flags:#04x} at offset {offset}")]
    ReservedFlags {
        /// Offset of the frame.
        offset: usize,
        /// The flags byte.
        flags: u8,
    },
    /// The frame type is not DATA, PAD or ABORTED: an undefined code, or a
    /// control frame, which belongs to a control datagram.
    #[error("frame type {code:#06x} at offset {offset} is not a data frame type")]
    FrameType {
        /// Offset of the frame.
        offset: usize,
        /// The type code.
        code: u16,
    },
    /// `session_id` is not the image's.
    #[error("session {session_id} at offset {offset} is not the image's")]
    Session {
        /// Offset of the frame.
        offset: usize,
        /// The session id found.
        session_id: i32,
    },
    /// `stream_id` is not the image's.
    #[error("stream {stream_id} at offset {offset} is not the image's")]
    Stream {
        /// Offset of the frame.
        offset: usize,
        /// The stream id found.
        stream_id: i32,
    },
    /// The lane is not one of the image's lanes.
    #[error("lane {lane} at offset {offset} is not one of the image's lanes")]
    Lane {
        /// Offset of the frame.
        offset: usize,
        /// The lane found.
        lane: u8,
    },
    /// `term_offset` is negative, not a multiple of 32 or not below the term
    /// length.
    #[error("term offset {term_offset} at offset {offset} is invalid")]
    TermOffset {
        /// Offset of the frame.
        offset: usize,
        /// The term offset found.
        term_offset: i32,
    },
    /// `frame_length` is impossible for the frame's type.
    #[error("frame length {frame_length} at offset {offset} is invalid for its type")]
    FrameLength {
        /// Offset of the frame.
        offset: usize,
        /// The frame length found.
        frame_length: i32,
    },
    /// The frame runs past the end of the datagram.
    #[error("frame of {frame_length} bytes at offset {offset} runs past the datagram")]
    PastDatagram {
        /// Offset of the frame.
        offset: usize,
        /// The frame length.
        frame_length: u32,
    },
    /// The frame's reserved extent runs past the end of its term.
    #[error("frame at offset {offset} runs past the end of its term")]
    PastTermEnd {
        /// Offset of the frame.
        offset: usize,
    },
    /// The trace extension is invalid.
    #[error("invalid trace extension at offset {offset}: {fault:?}")]
    Extension {
        /// Offset of the frame.
        offset: usize,
        /// What is wrong.
        fault: ExtensionFault,
    },
    /// A PAD or ABORTED record carries a flag other than its lane.
    #[error("record flags {flags:#04x} at offset {offset} carry more than the lane")]
    RecordFlags {
        /// Offset of the frame.
        offset: usize,
        /// The flags byte.
        flags: u8,
    },
    /// A PAD or ABORTED extent is not positive, not a multiple of 32, or
    /// does not fit the term (a PAD extent must end exactly at its end).
    #[error("record extent {extent} at offset {offset} is invalid")]
    Extent {
        /// Offset of the frame.
        offset: usize,
        /// The extent found in `reserved_value`.
        extent: i64,
    },
}

/// The fixed parameters of an image that a datagram is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageParams {
    session_id: i32,
    stream_id: i32,
    lanes: u8,
    term_length: TermLength,
    mtu: u32,
}

impl ImageParams {
    /// The parameters of an image: its session alias and stream, its lane
    /// count, its term length and its MTU (bytes of frames per datagram).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidParams`] for a lane count outside `1..=4`
    /// or an MTU that leaves no room for a header and one payload byte.
    pub fn new(
        session_id: i32,
        stream_id: i32,
        lanes: u8,
        term_length: TermLength,
        mtu: u32,
    ) -> Result<Self, ParseError> {
        if lanes == 0 || lanes > Lane::COUNT {
            return Err(ParseError::InvalidParams {
                reason: "lane count outside 1..=4",
            });
        }
        if FragmentPlan::new(mtu, Flags::NONE).is_err() {
            return Err(ParseError::InvalidParams {
                reason: "mtu leaves no room for a header and one payload byte",
            });
        }
        Ok(Self {
            session_id,
            stream_id,
            lanes,
            term_length,
            mtu,
        })
    }

    /// The image's session alias.
    #[inline]
    #[must_use]
    pub const fn session_id(&self) -> i32 {
        self.session_id
    }

    /// The image's stream id.
    #[inline]
    #[must_use]
    pub const fn stream_id(&self) -> i32 {
        self.stream_id
    }

    /// The image's lane count.
    #[inline]
    #[must_use]
    pub const fn lanes(&self) -> u8 {
        self.lanes
    }

    /// The image's term length.
    #[inline]
    #[must_use]
    pub const fn term_length(&self) -> TermLength {
        self.term_length
    }

    /// The image's MTU.
    #[inline]
    #[must_use]
    pub const fn mtu(&self) -> u32 {
        self.mtu
    }
}

/// A datagram whose every frame passed stage 1 validation.
#[derive(Debug, Clone, Copy)]
pub struct ValidatedDatagram<'a> {
    bytes: &'a [u8],
    params: ImageParams,
}

impl<'a> ValidatedDatagram<'a> {
    /// Validates every frame of `bytes` against `params`.
    ///
    /// # Errors
    ///
    /// Returns the first [`ParseError`] found; nothing of the datagram may
    /// then be used.
    pub fn parse(bytes: &'a [u8], params: &ImageParams) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(ParseError::Empty);
        }
        if bytes.len() > params.mtu as usize {
            return Err(ParseError::TooLong {
                length: bytes.len(),
                mtu: params.mtu,
            });
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let (_, next) = decode(bytes, offset, params)?;
            offset = next;
        }
        Ok(Self {
            bytes,
            params: *params,
        })
    }

    /// The datagram's items, in order.
    #[must_use]
    pub fn items(&self) -> Items<'a> {
        Items {
            bytes: self.bytes,
            params: self.params,
            offset: 0,
        }
    }

    /// The datagram's length in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false: an empty datagram is rejected.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Iterator over the items of a [`ValidatedDatagram`].
///
/// It decodes with the same function that validated the datagram, over the
/// same bytes, so it yields exactly the items that [`ValidatedDatagram::parse`]
/// accepted.
#[derive(Debug, Clone)]
pub struct Items<'a> {
    bytes: &'a [u8],
    params: ImageParams,
    offset: usize,
}

impl<'a> Iterator for Items<'a> {
    type Item = Item<'a>;

    fn next(&mut self) -> Option<Item<'a>> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        match decode(self.bytes, self.offset, &self.params) {
            Ok((item, next)) => {
                self.offset = next;
                Some(item)
            }
            // Unreachable for a validated datagram; stop rather than panic.
            Err(_) => {
                self.offset = self.bytes.len();
                None
            }
        }
    }
}

/// One item of a validated datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item<'a> {
    /// A frame that can be written into an image.
    Frame(ValidatedFrame<'a>),
    /// A header-only DATA frame: a control observation, never written.
    Heartbeat(Heartbeat),
}

/// The type of a [`ValidatedFrame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// DATA with at least one payload byte.
    Data,
    /// A PAD record: its extent ends at the term end.
    Pad,
    /// An ABORTED record.
    Aborted,
}

/// A frame that passed stage 1 and can be offered to an image's receive
/// owner. Built only by [`ValidatedDatagram::parse`]; its fields are private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedFrame<'a> {
    params: ImageParams,
    kind: FrameKind,
    lane: Lane,
    term_id: TermId,
    term_offset: u32,
    extent: u32,
    image_word0: Word0,
    wire: &'a [u8],
}

impl<'a> ValidatedFrame<'a> {
    /// The image parameters the frame was validated against; a receive
    /// owner accepts it only for an image with exactly these.
    pub(crate) const fn params(&self) -> &ImageParams {
        &self.params
    }

    /// The frame's type.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    /// The frame's lane.
    #[inline]
    #[must_use]
    pub const fn lane(&self) -> Lane {
        self.lane
    }

    /// The frame's term id.
    #[inline]
    #[must_use]
    pub const fn term_id(&self) -> TermId {
        self.term_id
    }

    /// The frame's offset in its term: a multiple of 32 below the term
    /// length.
    #[inline]
    #[must_use]
    pub const fn term_offset(&self) -> u32 {
        self.term_offset
    }

    /// The extent the frame occupies in the term: the aligned frame length
    /// for DATA, the stated extent for PAD and ABORTED. It ends at or before
    /// the term end.
    #[inline]
    #[must_use]
    pub const fn extent(&self) -> u32 {
        self.extent
    }

    /// The word 0 to store in the image: the wire word 0 for DATA, and a
    /// word stating the logical extent for PAD and ABORTED (SPEC.md §4).
    #[inline]
    #[must_use]
    pub const fn image_word0(&self) -> Word0 {
        self.image_word0
    }

    /// The bytes to write into the image after word 0: header bytes 8 to 31,
    /// then, for DATA, the extension and the payload up to `frame_length`.
    /// Alignment padding is not included.
    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        self.wire.get(8..).unwrap_or_default()
    }
}

/// A header-only DATA frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    lane: Lane,
    term_id: TermId,
    term_offset: u32,
    flags: Flags,
}

impl Heartbeat {
    /// The heartbeat's lane.
    #[inline]
    #[must_use]
    pub const fn lane(&self) -> Lane {
        self.lane
    }

    /// The term id it names.
    #[inline]
    #[must_use]
    pub const fn term_id(&self) -> TermId {
        self.term_id
    }

    /// The term offset it names.
    #[inline]
    #[must_use]
    pub const fn term_offset(&self) -> u32 {
        self.term_offset
    }

    /// Its flags.
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> Flags {
        self.flags
    }
}

/// Little-endian read of `N` bytes at `at` of `bytes`.
fn read<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// Decodes and validates the frame at `offset`, returning it and the offset
/// of the next frame.
fn decode<'a>(
    bytes: &'a [u8],
    offset: usize,
    params: &ImageParams,
) -> Result<(Item<'a>, usize), ParseError> {
    let truncated = ParseError::Truncated { offset };
    let header: [u8; HEADER_LENGTH as usize] = read(bytes, offset).ok_or(truncated)?;
    let field = |at: usize| -> Result<[u8; 4], ParseError> {
        header
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .ok_or(truncated)
    };
    let raw_word0 = u64::from_le_bytes(read(&header, 0).ok_or(truncated)?);
    let word0 = Word0::unpack(raw_word0).map_err(|_| ParseError::ReservedFlags {
        offset,
        flags: (raw_word0 >> 40) as u8,
    })?;
    if word0.version() != PROTOCOL_VERSION {
        return Err(ParseError::Version {
            offset,
            version: word0.version(),
        });
    }
    let code = word0.frame_type_code();
    let frame_type = match FrameType::try_from_code(code) {
        Ok(t @ (FrameType::Data | FrameType::Pad | FrameType::Aborted)) => t,
        _ => return Err(ParseError::FrameType { offset, code }),
    };
    let term_offset = i32::from_le_bytes(field(8)?);
    let session_id = i32::from_le_bytes(field(12)?);
    let stream_id = i32::from_le_bytes(field(16)?);
    let term_id = TermId::new(u32::from_le_bytes(field(20)?));
    let reserved_value = i64::from_le_bytes(read(&header, 24).ok_or(truncated)?);
    if session_id != params.session_id {
        return Err(ParseError::Session { offset, session_id });
    }
    if stream_id != params.stream_id {
        return Err(ParseError::Stream { offset, stream_id });
    }
    let flags = word0.flags();
    let lane = flags.lane();
    if lane.get() >= params.lanes {
        return Err(ParseError::Lane {
            offset,
            lane: lane.get(),
        });
    }
    let term_length = params.term_length.get();
    let term_offset_u32 = u32::try_from(term_offset)
        .ok()
        .filter(|t| t % FRAME_ALIGNMENT == 0 && *t < term_length)
        .ok_or(ParseError::TermOffset {
            offset,
            term_offset,
        })?;
    let room = term_length - term_offset_u32;
    let remaining = bytes.len() - offset;
    let frame_length = word0.frame_length();
    let bad_length = ParseError::FrameLength {
        offset,
        frame_length,
    };

    if frame_type == FrameType::Data {
        let length = u32::try_from(frame_length).map_err(|_| bad_length)?;
        let header_length = flags.header_length();
        if length < header_length {
            return Err(bad_length);
        }
        if length as usize > remaining {
            return Err(ParseError::PastDatagram {
                offset,
                frame_length: length,
            });
        }
        let reserved = align_frame(length).map_err(|_| bad_length)?;
        if reserved > room {
            return Err(ParseError::PastTermEnd { offset });
        }
        let start = offset + HEADER_LENGTH as usize;
        if flags.ext() {
            let extension: [u8; EXTENSION_LENGTH as usize] = read(bytes, start).ok_or(truncated)?;
            check_extension(&extension).map_err(|fault| ParseError::Extension { offset, fault })?;
        }
        let next = offset + reserved as usize;
        if length == header_length {
            let heartbeat = Heartbeat {
                lane,
                term_id,
                term_offset: term_offset_u32,
                flags,
            };
            return Ok((Item::Heartbeat(heartbeat), next));
        }
        let wire = bytes
            .get(offset..offset + length as usize)
            .ok_or(truncated)?;
        let frame = ValidatedFrame {
            params: *params,
            kind: FrameKind::Data,
            lane,
            term_id,
            term_offset: term_offset_u32,
            extent: reserved,
            image_word0: word0,
            wire,
        };
        return Ok((Item::Frame(frame), next));
    }

    // PAD and ABORTED travel as canonical 32-byte records.
    if frame_length != HEADER_LENGTH as i32 {
        return Err(bad_length);
    }
    if flags.get() != Flags::new(false, false, false, false, lane).get() {
        return Err(ParseError::RecordFlags {
            offset,
            flags: flags.get(),
        });
    }
    let bad_extent = ParseError::Extent {
        offset,
        extent: reserved_value,
    };
    let extent = u32::try_from(reserved_value)
        .ok()
        .filter(|e| *e > 0 && e % FRAME_ALIGNMENT == 0 && *e <= room)
        .ok_or(bad_extent)?;
    let kind = if frame_type == FrameType::Pad {
        if extent != room {
            return Err(bad_extent);
        }
        FrameKind::Pad
    } else {
        FrameKind::Aborted
    };
    let extent_i32 = i32::try_from(extent).map_err(|_| bad_extent)?;
    let wire = bytes
        .get(offset..offset + HEADER_LENGTH as usize)
        .ok_or(truncated)?;
    let frame = ValidatedFrame {
        params: *params,
        kind,
        lane,
        term_id,
        term_offset: term_offset_u32,
        extent,
        image_word0: Word0::new(extent_i32, flags, frame_type),
        wire,
    };
    Ok((Item::Frame(frame), offset + HEADER_LENGTH as usize))
}

/// Property test settings shared by the receive tests: under Miri, fewer
/// cases and no failure file (Miri's isolation forbids the file system
/// access that persistence needs).
#[cfg(test)]
pub(crate) fn tests_config() -> proptest::test_runner::Config {
    if cfg!(miri) {
        proptest::test_runner::Config {
            cases: 8,
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        }
    } else {
        proptest::test_runner::Config::default()
    }
}

#[cfg(test)]
mod tests;
