// SPDX-License-Identifier: Apache-2.0

//! Errors of the `karyos-protocol` crate.

use thiserror::Error;

/// Errors raised while validating frame layouts and sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// A buffer is shorter than the structure being read or written.
    #[error("buffer of {available} bytes is shorter than the required {required}")]
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
    /// Reserved flag bits 6 and 7 are set.
    #[error("frame flags {flags:#04x} set reserved bits")]
    ReservedFlags {
        /// The flags byte.
        flags: u8,
    },
    /// A lane number is outside `0..4`.
    #[error("lane {lane} is outside 0..4")]
    InvalidLane {
        /// The rejected lane.
        lane: u8,
    },
    /// A frame type code is not defined.
    #[error("unknown frame type {code:#06x}")]
    UnknownFrameType {
        /// The type code.
        code: u16,
    },
    /// A frame or extension carries a version this implementation does not
    /// support.
    #[error("unsupported version {version}")]
    UnsupportedVersion {
        /// The version found.
        version: u8,
    },
    /// The trace extension is malformed.
    #[error("invalid trace extension: {reason}")]
    InvalidExtension {
        /// Which check failed.
        reason: &'static str,
    },
    /// A term length is not a power of two between 64 KiB and 1 GiB.
    #[error("term length {value} is not a power of two in 65536..=1073741824")]
    InvalidTermLength {
        /// The rejected value.
        value: u32,
    },
    /// An MTU leaves no room for the header and one payload byte.
    #[error("mtu {value} leaves no payload room after a {header_length}-byte header")]
    InvalidMtu {
        /// The rejected MTU.
        value: u32,
        /// The effective header length.
        header_length: u32,
    },
    /// An application message must carry at least one byte.
    #[error("empty application message; header-only DATA is a heartbeat")]
    EmptyMessage,
    /// A frame in a term violates the frame rules.
    #[error("invalid frame at term offset {offset}: {reason}")]
    InvalidFrame {
        /// Term offset of the offending frame.
        offset: u32,
        /// Which rule failed.
        reason: &'static str,
    },
    /// A length computation overflowed.
    #[error("length arithmetic overflowed for {value}")]
    LengthOverflow {
        /// The value that could not be processed.
        value: u64,
    },
    /// A message is longer than the configured maximum.
    #[error("message of {length} bytes exceeds the maximum of {max}")]
    MessageTooLarge {
        /// The message length.
        length: u32,
        /// The maximum message length.
        max: u32,
    },
    /// A maximum reserved length is out of range for the term.
    #[error(
        "max reserved length {value} must be at least one fragment and at most term_length / 8 = {limit}"
    )]
    InvalidMaxReservedLength {
        /// The rejected value.
        value: u32,
        /// `term_length / 8`.
        limit: u32,
    },
}
