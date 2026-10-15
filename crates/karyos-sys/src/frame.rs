// SPDX-License-Identifier: Apache-2.0

//! The decision word (word 0), flags, lanes and frame types, plus the header
//! constants (SPEC.md §4 frame header, §5 frame types). These are memory
//! protocol facts: the writer and reader of a term compute geometry from
//! them. `karyos-protocol` re-exports them and adds the header codecs.

use crate::error::LayoutError;

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
/// Extension feature bits defined by version 1 (none).
pub const DEFINED_EXTENSION_FLAGS: u16 = 0;

/// Why a trace extension's fixed fields are invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionFault {
    /// `extension_version` is not [`EXTENSION_VERSION`].
    Version,
    /// The reserved byte at offset 1 or a byte of 48 to 63 is not zero.
    Reserved,
    /// A feature bit outside [`DEFINED_EXTENSION_FLAGS`] is set.
    Flags,
    /// `extension_length` is not [`EXTENSION_LENGTH`].
    Length,
}

/// Checks the fixed fields of a trace extension (SPEC.md §4): its version,
/// the reserved byte at offset 1, the feature bits, `extension_length` and
/// the reserved bytes 48 to 63. The identity fields are not interpreted.
///
/// # Errors
///
/// Returns the first [`ExtensionFault`] found.
pub fn check_extension(bytes: &[u8; EXTENSION_LENGTH as usize]) -> Result<(), ExtensionFault> {
    let [version, reserved, flags_lo, flags_hi, l0, l1, l2, l3, ..] = *bytes;
    if version != EXTENSION_VERSION {
        return Err(ExtensionFault::Version);
    }
    if reserved != 0
        || bytes
            .get(48..)
            .is_none_or(|tail| tail.iter().any(|b| *b != 0))
    {
        return Err(ExtensionFault::Reserved);
    }
    if u16::from_le_bytes([flags_lo, flags_hi]) & !DEFINED_EXTENSION_FLAGS != 0 {
        return Err(ExtensionFault::Flags);
    }
    if u32::from_le_bytes([l0, l1, l2, l3]) != EXTENSION_LENGTH {
        return Err(ExtensionFault::Length);
    }
    Ok(())
}

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
    /// Returns [`LayoutError::ReservedFlags`] when bit 6 or 7 is set.
    #[inline]
    pub const fn try_new(raw: u8) -> Result<Self, LayoutError> {
        if raw & RESERVED_FLAGS == 0 {
            Ok(Self(raw))
        } else {
            Err(LayoutError::ReservedFlags { flags: raw })
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
    /// Lane 0, the most urgent.
    pub const ZERO: Self = Self(0);

    /// Validates a lane.
    ///
    /// # Errors
    ///
    /// Returns [`LayoutError::InvalidLane`] when `lane >= 4`.
    #[inline]
    pub const fn try_new(lane: u8) -> Result<Self, LayoutError> {
        if lane < Self::COUNT {
            Ok(Self(lane))
        } else {
            Err(LayoutError::InvalidLane { lane })
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
///
/// Control frames share only word 0 with data frames; a type code here does
/// not imply that its frame body is the 32-byte header layout (`FrameHeader`
/// in `karyos-protocol`).
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
    /// Returns [`LayoutError::UnknownFrameType`] for an undefined code.
    #[inline]
    pub const fn try_from_code(code: u16) -> Result<Self, LayoutError> {
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
            _ => return Err(LayoutError::UnknownFrameType { code }),
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
    /// Returns [`LayoutError::ReservedFlags`] for reserved flag bits.
    #[inline]
    pub const fn unpack(raw: u64) -> Result<Self, LayoutError> {
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
            Err(LayoutError::ReservedFlags { flags: 0x40 })
        );
        assert!(Lane::try_new(4).is_err());
    }

    #[test]
    fn every_lane_round_trips_through_flags() {
        for lane in 0..Lane::COUNT {
            let flags = Flags::new(false, false, false, false, Lane::try_new(lane).unwrap());
            assert_eq!(flags.get(), lane << 4);
            assert_eq!(Flags::try_new(flags.get()).unwrap().lane().get(), lane);
        }
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
}
