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
    /// Packet identity is zero or present on a point that is not packet
    /// level.
    #[error("packet identity does not match the observation point")]
    Packet,
    /// The underlying journal failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}
