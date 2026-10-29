// SPDX-License-Identifier: Apache-2.0

//! Errors of the trace crate.

use karyos_protocol::journal::JournalError;
use thiserror::Error;

/// Errors of trace records and trace journals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
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
    /// Network path context is missing on `SenderPickup` or
    /// `ReceiverCommit` in layout version 3, carries an attempt on
    /// `ReceiverCommit`, comes with a packet token, or is present on
    /// another point or in an older version.
    #[error("network path does not match the observation point")]
    NetworkPath,
    /// An application point's id is zero.
    #[error("an application point's id is zero")]
    PointId,
    /// An application observation's metadata is out of bounds: more than
    /// four values, an unknown type, a tag that is not graphic ASCII
    /// zero-padded, a value past the count, or a reserved bit set.
    #[error("application point metadata is invalid")]
    Metadata,
    /// An application point recorded into a journal of another client than
    /// the one that registered it; nothing was appended.
    #[error("the trace point belongs to another client than the journal")]
    ForeignPoint,
    /// The `root` flag is set on a point other than `Publish`.
    #[error("the root flag is set on a point other than Publish")]
    Root,
    /// The collection stamp uses another clock than the journal's declared
    /// collection clock, or an epoch below the last accepted one; nothing
    /// was appended.
    #[error("collection stamp does not follow the journal's collection clock")]
    CollectionClock,
    /// An attribution table size is zero or cannot be allocated.
    #[error("invalid attribution configuration")]
    Attribution,
    /// Final verdicts were requested before the journal's terminal close was
    /// observed.
    #[error("the journal has not been observed closed")]
    NotClosed,
    /// The report already gave a final answer: its journals are frozen and
    /// no journal can be added.
    #[error("the trace report already gave a final answer; no journal can be added")]
    MembershipFrozen,
    /// The underlying journal failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}
