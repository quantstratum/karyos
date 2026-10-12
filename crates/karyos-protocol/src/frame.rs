// SPDX-License-Identifier: Apache-2.0

//! Frame header and trace extension codecs (SPEC.md §4 frame header). All
//! multi-byte fields are little-endian. The decision word, flags, lanes,
//! frame types and header constants live in `karyos_sys::frame` and are
//! re-exported here.

pub use karyos_sys::frame::{
    EXTENSION_LENGTH, FRAME_ALIGNMENT, Flags, FrameType, HEADER_LENGTH, Lane, PROTOCOL_VERSION,
    Word0,
};

use crate::error::ProtocolError;

/// Version of the trace extension layout.
pub const EXTENSION_VERSION: u8 = 1;

/// The 32-byte base frame header.
///
/// In a term, a committed DATA or PAD frame is fully visible once its word 0
/// is loaded with Acquire. An ABORTED block is not: only its word 0 is
/// meaningful and the rest of its extent may be uninitialised or still being
/// written, so a reader must not decode a full header there (SPEC.md §4). On
/// the wire, PAD and ABORTED both travel as canonical 32-byte records whose
/// extent is `reserved_value`.
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
    /// This is a raw decode: it checks only the buffer length and the
    /// reserved flag bits. Admitting a committed or received frame also needs
    /// version, type, `EXT`, length and canonical PAD/ABORTED validation,
    /// which belong to the readers and receivers that use this decoder.
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
    fn encoding_leaves_the_rest_of_the_buffer_untouched() {
        let header = FrameHeader {
            word0: Word0::new(0, Flags::NONE, FrameType::Pad),
            term_offset: 0,
            session_id: 0,
            stream_id: 0,
            term_id: 0,
            reserved_value: 0,
        };
        let mut out = [0xEEu8; 40];
        header.encode(&mut out).unwrap();
        assert!(out[..32].iter().all(|b| *b == 0 || *b == 1));
        assert_eq!(&out[32..], &[0xEE; 8]);

        let mut ext_out = [0xEEu8; 70];
        TraceExtension::default().encode(&mut ext_out).unwrap();
        assert_eq!(&ext_out[64..], &[0xEE; 6]);
        assert!(TraceExtension::default().encode(&mut [0u8; 63]).is_err());
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

    /// Binary vector: a full extension with distinct multi-byte identifiers,
    /// so swapped fields cannot round-trip unnoticed.
    #[test]
    fn extension_binary_vector() {
        let ext = TraceExtension {
            extension_flags: 0,
            trace_id: [0x1112_1314_1516_1718, 0x2122_2324_2526_2728],
            span_id: 0x3132_3334_3536_3738,
            parent_span_id: 0x4142_4344_4546_4748,
            message_id: 0x5152_5354_5556_5758,
        };
        let mut expected = [0u8; 64];
        expected[..8].copy_from_slice(&[1, 0, 0, 0, 64, 0, 0, 0]);
        expected[8..16].copy_from_slice(&[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);
        expected[16..24].copy_from_slice(&[0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21]);
        expected[24..32].copy_from_slice(&[0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31]);
        expected[32..40].copy_from_slice(&[0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41]);
        expected[40..48].copy_from_slice(&[0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51]);
        let mut out = [0xAAu8; 64];
        ext.encode(&mut out).unwrap();
        assert_eq!(out, expected);
        assert_eq!(TraceExtension::decode(&expected), Ok(ext));
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
