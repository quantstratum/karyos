// SPDX-License-Identifier: Apache-2.0

//! Errors of the `karyos-protocol` crate.

use thiserror::Error;

/// Errors raised while validating frame layouts and sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// A frame layout or sizing rule from `karyos_sys` failed.
    #[error(transparent)]
    Layout(#[from] karyos_sys::error::LayoutError),
    /// A buffer is shorter than the structure being read or written.
    #[error("buffer of {available} bytes is shorter than the required {required}")]
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
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
}
