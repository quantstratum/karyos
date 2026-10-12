// SPDX-License-Identifier: Apache-2.0

//! Frame header, word 0, flags, frame types and the trace extension
//! (SPEC.md §4 frame header, §5 frame types). All multi-byte fields are
//! little-endian.

use crate::error::ProtocolError;

/// Length of the base frame header in bytes.
pub const HEADER_LENGTH: u32 = 32;
/// Length of the trace extension in bytes.
pub const EXTENSION_LENGTH: u32 = 64;
/// Alignment of every frame in a term, in bytes.
pub const FRAME_ALIGNMENT: u32 = 32;
/// Protocol version written in word 0.
pub const PROTOCOL_VERSION: u8 = 1;
/// Version of the trace extension layout.
pub const EXTENSION_VERSION: u8 = 1;

const FLAG_BEGIN: u8 = 0x01;
const FLAG_END: u8 = 0x02;
const FLAG_EOS: u8 = 0x04;
const FLAG_EXT: u8 = 0x08;
const LANE_SHIFT: u8 = 4;
const LANE_MASK: u8 = 0x30;
const RESERVED_FLAGS: u8 = 0xC0;

/// The flags byte: BEGIN, END, EOS, EXT and the lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flags(u8);

impl Flags {
    /// No flags, lane 0.
    pub const NONE: Self = Self(0);

    /// Validates a raw flags byte.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ReservedFlags`] when bit 6 or 7 is set.
    #[inline]
    pub const fn try_new(raw: u8) -> Result<Self, ProtocolError> {
        if raw & RESERVED_FLAGS == 0 {
            Ok(Self(raw))
        } else {
            Err(ProtocolError::ReservedFlags { flags: raw })
        }
    }

    /// Builds flags from their parts.
    #[inline]
    #[must_use]
    pub const fn new(begin: bool, end: bool, eos: bool, ext: bool, lane: Lane) -> Self {
        let mut raw = lane.get() << LANE_SHIFT;
        if begin {
            raw |= FLAG_BEGIN;
        }
        if end {
            raw |= FLAG_END;
        }
        if eos {
            raw |= FLAG_EOS;
        }
        if ext {
            raw |= FLAG_EXT;
        }
        Self(raw)
    }

    /// The raw byte.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// First fragment of a message.
    #[inline]
    #[must_use]
    pub const fn begin(self) -> bool {
        self.0 & FLAG_BEGIN != 0
    }

    /// Last fragment of a message.
    #[inline]
    #[must_use]
    pub const fn end(self) -> bool {
        self.0 & FLAG_END != 0
    }

    /// End of stream.
    #[inline]
    #[must_use]
    pub const fn eos(self) -> bool {
        self.0 & FLAG_EOS != 0
    }

    /// A 64-byte trace extension follows the header.
    #[inline]
    #[must_use]
    pub const fn ext(self) -> bool {
        self.0 & FLAG_EXT != 0
    }

    /// The lane, 0 (most urgent) to 3.
    #[inline]
    #[must_use]
    pub const fn lane(self) -> Lane {
        Lane((self.0 & LANE_MASK) >> LANE_SHIFT)
    }

    /// Header length for these flags: 32, or 96 with the extension.
    #[inline]
    #[must_use]
    pub const fn header_length(self) -> u32 {
        if self.ext() {
            HEADER_LENGTH + EXTENSION_LENGTH
        } else {
            HEADER_LENGTH
        }
    }
}

/// A priority lane, 0 to 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Lane(u8);

impl Lane {
    /// Number of lanes.
    pub const COUNT: u8 = 4;

    /// Validates a lane.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidLane`] when `lane >= 4`.
    #[inline]
    pub const fn try_new(lane: u8) -> Result<Self, ProtocolError> {
        if lane < Self::COUNT {
            Ok(Self(lane))
        } else {
            Err(ProtocolError::InvalidLane { lane })
        }
    }

    /// The lane number.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Frame types with their stable wire codes (SPEC.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FrameType {
    /// Fills the end of a term.
    Pad = 0x00,
    /// Payload; header-only DATA is a heartbeat.
    Data = 0x01,
    /// Retransmission request.
    Nak = 0x02,
    /// Status message.
    Sm = 0x03,
    /// Protocol error.
    Err = 0x04,
    /// Session setup.
    Setup = 0x05,
    /// Round-trip time measurement.
    Rttm = 0x06,
    /// Request for SETUP with a challenge.
    RspSetup = 0x07,
    /// Canonical record of an aborted extent.
    Aborted = 0x08,
    /// Per-path heartbeat.
    PathHb = 0x10,
    /// Guard and limit state.
    Guard = 0x11,
    /// Terminal abort of a publication incarnation.
    SessionAbort = 0x12,
    /// Acknowledgement of a session abort.
    SessionAbortAck = 0x13,
}

impl FrameType {
    /// Decodes a wire code.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnknownFrameType`] for an undefined code.
    #[inline]
    pub const fn try_from_code(code: u16) -> Result<Self, ProtocolError> {
        Ok(match code {
            0x00 => Self::Pad,
            0x01 => Self::Data,
            0x02 => Self::Nak,
            0x03 => Self::Sm,
            0x04 => Self::Err,
            0x05 => Self::Setup,
            0x06 => Self::Rttm,
            0x07 => Self::RspSetup,
            0x08 => Self::Aborted,
            0x10 => Self::PathHb,
            0x11 => Self::Guard,
            0x12 => Self::SessionAbort,
            0x13 => Self::SessionAbortAck,
            _ => return Err(ProtocolError::UnknownFrameType { code }),
        })
    }

    /// The wire code.
    #[inline]
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }
}

/// Word 0 of a frame header: `frame_length`, version, flags and type packed
/// into one little-endian 64-bit word, the unit of every atomic access to a
/// header (SPEC.md §4).
///
/// `frame_length` is signed: positive means committed, zero means not yet
/// written, and negative values are the reserved and aborting markers of the
/// commit-or-abort protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Word0 {
    frame_length: i32,
    version: u8,
    flags: Flags,
    frame_type: u16,
}

impl Word0 {
    /// Builds a word 0 for the current protocol version.
    #[inline]
    #[must_use]
    pub const fn new(frame_length: i32, flags: Flags, frame_type: FrameType) -> Self {
        Self {
            frame_length,
            version: PROTOCOL_VERSION,
            flags,
            frame_type: frame_type.code(),
        }
    }

    /// The signed frame length.
    #[inline]
    #[must_use]
    pub const fn frame_length(self) -> i32 {
        self.frame_length
    }

    /// The version byte.
    #[inline]
    #[must_use]
    pub const fn version(self) -> u8 {
        self.version
    }

    /// The flags.
    #[inline]
    #[must_use]
    pub const fn flags(self) -> Flags {
        self.flags
    }

    /// The raw type code; validate with [`FrameType::try_from_code`].
    #[inline]
    #[must_use]
    pub const fn frame_type_code(self) -> u16 {
        self.frame_type
    }

    /// Packs into the 64-bit value stored atomically (bytes 0..8 of the
    /// header, little-endian).
    #[inline]
    #[must_use]
    pub const fn pack(self) -> u64 {
        (self.frame_length as u32 as u64)
            | ((self.version as u64) << 32)
            | ((self.flags.get() as u64) << 40)
            | ((self.frame_type as u64) << 48)
    }

    /// Unpacks a 64-bit word 0, validating the flags. The type code and
    /// version are returned as found; callers validate them.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ReservedFlags`] for reserved flag bits.
    #[inline]
    pub const fn unpack(raw: u64) -> Result<Self, ProtocolError> {
        let flags = match Flags::try_new((raw >> 40) as u8) {
            Ok(flags) => flags,
            Err(err) => return Err(err),
        };
        Ok(Self {
            frame_length: raw as u32 as i32,
            version: (raw >> 32) as u8,
            flags,
            frame_type: (raw >> 48) as u16,
        })
    }
}

/// The 32-byte base frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    /// Word 0.
    pub word0: Word0,
    /// Offset of this frame in its term.
    pub term_offset: i32,
    /// Compact wire alias of the publication incarnation.
    pub session_id: i32,
    /// Application-chosen stream.
    pub stream_id: i32,
    /// Term this frame belongs to.
    pub term_id: i32,
    /// Free for the application; extent of PAD and ABORTED records.
    pub reserved_value: i64,
}

impl FrameHeader {
    /// Writes the header into the first 32 bytes of `out`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BufferTooShort`] when `out` is shorter than
    /// 32 bytes.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), ProtocolError> {
        let out = prefix_mut(out, HEADER_LENGTH as usize)?;
        write(out, 0, &self.word0.pack().to_le_bytes())?;
        write(out, 8, &self.term_offset.to_le_bytes())?;
        write(out, 12, &self.session_id.to_le_bytes())?;
        write(out, 16, &self.stream_id.to_le_bytes())?;
        write(out, 20, &self.term_id.to_le_bytes())?;
        write(out, 24, &self.reserved_value.to_le_bytes())
    }

    /// Reads a header from the first 32 bytes of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BufferTooShort`] for a short buffer and
    /// [`ProtocolError::ReservedFlags`] for reserved flag bits. The version
    /// and frame type are returned as found.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes = prefix(bytes, HEADER_LENGTH as usize)?;
        Ok(Self {
            word0: Word0::unpack(u64::from_le_bytes(read(bytes, 0)?))?,
            term_offset: i32::from_le_bytes(read(bytes, 8)?),
            session_id: i32::from_le_bytes(read(bytes, 12)?),
            stream_id: i32::from_le_bytes(read(bytes, 16)?),
            term_id: i32::from_le_bytes(read(bytes, 20)?),
            reserved_value: i64::from_le_bytes(read(bytes, 24)?),
        })
    }
}

/// The 64-byte trace extension that follows the header when `EXT` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TraceExtension {
    /// Defined feature bits; none are defined in version 1.
    pub extension_flags: u16,
    /// Trace id as two little-endian words.
    pub trace_id: [u64; 2],
    /// Current causal span; zero when unused.
    pub span_id: u64,
    /// Parent span; zero when absent.
    pub parent_span_id: u64,
    /// Logical message identity shared by its fragments.
    pub message_id: u64,
}

/// Extension feature bits defined by version 1 (none).
const DEFINED_EXTENSION_FLAGS: u16 = 0;

impl TraceExtension {
    /// Writes the extension into the first 64 bytes of `out`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BufferTooShort`] for a short buffer and
    /// [`ProtocolError::InvalidExtension`] for undefined feature bits.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), ProtocolError> {
        if self.extension_flags & !DEFINED_EXTENSION_FLAGS != 0 {
            return Err(ProtocolError::InvalidExtension {
                reason: "undefined extension flags",
            });
        }
        let out = prefix_mut(out, EXTENSION_LENGTH as usize)?;
        write(out, 0, &[EXTENSION_VERSION, 0])?;
        write(out, 2, &self.extension_flags.to_le_bytes())?;
        write(out, 4, &EXTENSION_LENGTH.to_le_bytes())?;
        write(out, 8, &self.trace_id[0].to_le_bytes())?;
        write(out, 16, &self.trace_id[1].to_le_bytes())?;
        write(out, 24, &self.span_id.to_le_bytes())?;
        write(out, 32, &self.parent_span_id.to_le_bytes())?;
        write(out, 40, &self.message_id.to_le_bytes())?;
        write(out, 48, &[0; 16])
    }

    /// Reads and validates an extension from the first 64 bytes of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BufferTooShort`] for a short buffer,
    /// [`ProtocolError::UnsupportedVersion`] for another layout version and
    /// [`ProtocolError::InvalidExtension`] for a non-zero reserved byte, a
    /// wrong length or undefined feature bits.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes = prefix(bytes, EXTENSION_LENGTH as usize)?;
        let [version, reserved] = read::<2>(bytes, 0)?;
        if version != EXTENSION_VERSION {
            return Err(ProtocolError::UnsupportedVersion { version });
        }
        if reserved != 0 || read::<16>(bytes, 48)? != [0; 16] {
            return Err(ProtocolError::InvalidExtension {
                reason: "reserved bytes are not zero",
            });
        }
        let extension_flags = u16::from_le_bytes(read(bytes, 2)?);
        if extension_flags & !DEFINED_EXTENSION_FLAGS != 0 {
            return Err(ProtocolError::InvalidExtension {
                reason: "undefined extension flags",
            });
        }
        if u32::from_le_bytes(read(bytes, 4)?) != EXTENSION_LENGTH {
            return Err(ProtocolError::InvalidExtension {
                reason: "extension length is not 64",
            });
        }
        Ok(Self {
            extension_flags,
            trace_id: [
                u64::from_le_bytes(read(bytes, 8)?),
                u64::from_le_bytes(read(bytes, 16)?),
            ],
            span_id: u64::from_le_bytes(read(bytes, 24)?),
            parent_span_id: u64::from_le_bytes(read(bytes, 32)?),
            message_id: u64::from_le_bytes(read(bytes, 40)?),
        })
    }
}

fn prefix(bytes: &[u8], required: usize) -> Result<&[u8], ProtocolError> {
    bytes.get(..required).ok_or(ProtocolError::BufferTooShort {
        required,
        available: bytes.len(),
    })
}

fn prefix_mut(bytes: &mut [u8], required: usize) -> Result<&mut [u8], ProtocolError> {
    let available = bytes.len();
    bytes
        .get_mut(..required)
        .ok_or(ProtocolError::BufferTooShort {
            required,
            available,
        })
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolError> {
    let end = offset.checked_add(N).ok_or(ProtocolError::LengthOverflow {
        value: offset as u64,
    })?;
    let slice = bytes
        .get(offset..end)
        .ok_or(ProtocolError::BufferTooShort {
            required: end,
            available: bytes.len(),
        })?;
    let mut out = [0; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn write(out: &mut [u8], offset: usize, value: &[u8]) -> Result<(), ProtocolError> {
    let available = out.len();
    let end = offset
        .checked_add(value.len())
        .ok_or(ProtocolError::LengthOverflow {
            value: offset as u64,
        })?;
    out.get_mut(offset..end)
        .ok_or(ProtocolError::BufferTooShort {
            required: end,
            available,
        })?
        .copy_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_layout_and_reserved_bits() {
        let flags = Flags::new(true, false, true, true, Lane::try_new(3).unwrap());
        assert_eq!(flags.get(), 0b0011_1101);
        assert!(flags.begin() && !flags.end() && flags.eos() && flags.ext());
        assert_eq!(flags.lane().get(), 3);
        assert_eq!(flags.header_length(), 96);
        assert_eq!(Flags::NONE.header_length(), 32);
        assert_eq!(
            Flags::try_new(0x40),
            Err(ProtocolError::ReservedFlags { flags: 0x40 })
        );
        assert!(Lane::try_new(4).is_err());
    }

    #[test]
    fn frame_type_codes_are_stable() {
        let all = [
            (FrameType::Pad, 0x00),
            (FrameType::Data, 0x01),
            (FrameType::Nak, 0x02),
            (FrameType::Sm, 0x03),
            (FrameType::Err, 0x04),
            (FrameType::Setup, 0x05),
            (FrameType::Rttm, 0x06),
            (FrameType::RspSetup, 0x07),
            (FrameType::Aborted, 0x08),
            (FrameType::PathHb, 0x10),
            (FrameType::Guard, 0x11),
            (FrameType::SessionAbort, 0x12),
            (FrameType::SessionAbortAck, 0x13),
        ];
        for (frame_type, code) in all {
            assert_eq!(frame_type.code(), code);
            assert_eq!(FrameType::try_from_code(code), Ok(frame_type));
        }
        assert!(FrameType::try_from_code(0x09).is_err());
        assert!(FrameType::try_from_code(0x14).is_err());
    }

    #[test]
    fn word0_packs_little_endian_and_keeps_negative_lengths() {
        let flags = Flags::new(true, true, false, false, Lane::try_new(1).unwrap());
        let word = Word0::new(1408, flags, FrameType::Data);
        assert_eq!(word.pack(), 0x0001_1301_0000_0580);
        assert_eq!(
            word.pack().to_le_bytes(),
            [0x80, 0x05, 0, 0, 0x01, 0x13, 0x01, 0x00]
        );
        assert_eq!(Word0::unpack(word.pack()), Ok(word));

        let reserved = Word0::new(-8192, Flags::NONE, FrameType::Data);
        assert_eq!(
            Word0::unpack(reserved.pack()).unwrap().frame_length(),
            -8192
        );
    }

    /// Binary vector: a committed single-fragment DATA frame header.
    #[test]
    fn header_binary_vector() {
        let header = FrameHeader {
            word0: Word0::new(
                40,
                Flags::new(true, true, false, false, Lane::default()),
                FrameType::Data,
            ),
            term_offset: 0x40,
            session_id: -2,
            stream_id: 1001,
            term_id: 0x7FFF_FFFF,
            reserved_value: 0x0102_0304_0506_0708,
        };
        let expected: [u8; 32] = [
            0x28, 0x00, 0x00, 0x00, 0x01, 0x03, 0x01, 0x00, // word 0
            0x40, 0x00, 0x00, 0x00, // term_offset
            0xFE, 0xFF, 0xFF, 0xFF, // session_id
            0xE9, 0x03, 0x00, 0x00, // stream_id
            0xFF, 0xFF, 0xFF, 0x7F, // term_id
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // reserved_value
        ];
        let mut out = [0u8; 32];
        header.encode(&mut out).unwrap();
        assert_eq!(out, expected);
        assert_eq!(FrameHeader::decode(&expected), Ok(header));
        assert_eq!(
            FrameHeader::decode(&expected[..31]),
            Err(ProtocolError::BufferTooShort {
                required: 32,
                available: 31
            })
        );
    }

    #[test]
    fn extension_round_trip_and_validation() {
        let ext = TraceExtension {
            extension_flags: 0,
            trace_id: [1, 2],
            span_id: 3,
            parent_span_id: 4,
            message_id: 5,
        };
        let mut out = [0xAAu8; 64];
        ext.encode(&mut out).unwrap();
        assert_eq!(&out[..8], &[1, 0, 0, 0, 64, 0, 0, 0]);
        assert_eq!(&out[48..], &[0; 16]);
        assert_eq!(TraceExtension::decode(&out), Ok(ext));

        let mut bad = out;
        bad[0] = 2;
        assert_eq!(
            TraceExtension::decode(&bad),
            Err(ProtocolError::UnsupportedVersion { version: 2 })
        );
        let mut bad = out;
        bad[63] = 1;
        assert!(TraceExtension::decode(&bad).is_err());
        let mut bad = out;
        bad[2] = 1;
        assert!(TraceExtension::decode(&bad).is_err());
        let mut bad = out;
        bad[4] = 65;
        assert!(TraceExtension::decode(&bad).is_err());
    }
}
