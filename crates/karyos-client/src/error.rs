// SPDX-License-Identifier: Apache-2.0

//! Errors of the client API.

use karyos_sys::conflation::ConflationError;
use karyos_sys::error::{LayoutError, SysError};
use thiserror::Error;

/// Errors returned by publications and subscriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClientError {
    /// The message exceeds the publication's maximum message length.
    #[error("message of {length} bytes exceeds the maximum of {max}")]
    MessageTooLarge {
        /// The message length.
        length: u32,
        /// The maximum message length.
        max: u32,
    },
    /// An application message must carry at least one byte.
    #[error("empty application message")]
    EmptyMessage,
    /// A mapping starting at `base` could report a stream position at or
    /// above `2^63` (`quantstratum-docs: karyos/design/mapping-generations.md`).
    #[error("a mapping starting at {base} exceeds the stream position range")]
    PositionsExhausted {
        /// The rejected base.
        base: u64,
    },
    /// A conflated publication rejected its key or value size.
    #[error(transparent)]
    Conflation(#[from] ConflationError),
    /// A lower layer failed.
    #[error(transparent)]
    Sys(SysError),
}

impl From<SysError> for ClientError {
    fn from(error: SysError) -> Self {
        match error {
            SysError::EmptyMessage => Self::EmptyMessage,
            SysError::Layout(LayoutError::MessageTooLarge { length, max }) => {
                Self::MessageTooLarge { length, max }
            }
            other => Self::Sys(other),
        }
    }
}
