// SPDX-License-Identifier: Apache-2.0

//! Public facade: re-exports the client, Archive and Cluster APIs and defines
//! `karyos::Error`.
//!
//! Implemented so far: the client API (publications, subscriptions and the
//! client conductor) and the error type aggregating client errors. The Archive and Cluster APIs do not exist yet.

pub use karyos_client::{
    Aborted, ClaimOutcome, ClientClaim, ClientConductor, ClientError, ClientPublication,
    ClientSubscription, CommitOutcome, Completion, ConductorError, ConductorPoll, MessageInfo,
    MessageLimit, OfferOutcome, Outcome, Overrun, PollError, PollSummary,
};

/// Every error of the public Karyos API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A client error.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// A poll failed after possibly delivering messages.
    #[error(transparent)]
    Poll(#[from] PollError),
    /// A client conductor request could not be submitted.
    #[error(transparent)]
    Conductor(#[from] ConductorError),
}
