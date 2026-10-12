// SPDX-License-Identifier: Apache-2.0

//! Errors of the driver.

use karyos_client::ClientError;
use karyos_sys::error::SysError;
use thiserror::Error;

/// Errors returned by the embedded driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DriverError {
    /// The stream handle does not name a stream of this driver.
    #[error("unknown stream {index}")]
    UnknownStream {
        /// The handle's index.
        index: usize,
    },
    /// A stream with the same wire stream id and session already exists.
    #[error("stream {stream_id} session {session_id} already exists")]
    DuplicateStream {
        /// Wire stream id.
        stream_id: i32,
        /// Session alias.
        session_id: i32,
    },
    /// A control-channel limit or size is invalid.
    #[error("invalid driver configuration")]
    InvalidConfig,
    /// `max_clients` clients are admitted.
    #[error("too many clients")]
    TooManyClients,
    /// Client identities are exhausted.
    #[error("client identities exhausted")]
    ClientIdsExhausted,
    /// The driver is in its terminal state: its broadcast buffer is closed.
    #[error("the driver is in its terminal state")]
    Terminal,
    /// The process has used every driver identity.
    #[error("driver identities exhausted")]
    DriverIdsExhausted,
    /// The stream's publication has already been taken.
    #[error("the stream's publication has already been taken")]
    PublicationTaken,
    /// A client-level error.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// A lower layer failed.
    #[error(transparent)]
    Sys(#[from] SysError),
}
