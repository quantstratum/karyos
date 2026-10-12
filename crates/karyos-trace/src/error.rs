// SPDX-License-Identifier: Apache-2.0

//! Errors of the trace crate.

use karyos_protocol::journal::JournalError;
use thiserror::Error;

/// Errors of trace records and trace journals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TraceError {
    /// The record layout version is not supported.
    #[error("unsupported trace record version {version}")]
    Version {
        /// The version found.
        version: u8,
    },
    /// The observation point code is unknown.
    #[error("unknown observation point {code}")]
    UnknownPoint {
        /// The code found.
        code: u8,
    },
    /// Reserved bits are set.
    #[error("reserved trace record bits are set")]
    ReservedBits,
    /// The lane is out of range.
    #[error("lane {lane} is out of range")]
    Lane {
        /// The lane found.
        lane: u8,
    },
    /// Subscriber identity is missing on a subscriber poll, zero, or present
    /// on another point.
    #[error("subscriber identity does not match the observation point")]
    Subscriber,
    /// Packet context is missing on a packet-level point, has a zero token,
    /// or is present on a point that is not packet level.
    #[error("packet identity does not match the observation point")]
    Packet,
    /// The collection stamp uses another clock than the journal's declared
    /// collection clock, or an epoch below the last accepted one; nothing
    /// was appended.
    #[error("collection stamp does not follow the journal's collection clock")]
    CollectionClock,
    /// An attribution table size is zero.
    #[error("invalid attribution configuration")]
    Attribution,
    /// Final verdicts were requested before the journal's terminal close was
    /// observed.
    #[error("the journal has not been observed closed")]
    NotClosed,
    /// The underlying journal failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}
