// SPDX-License-Identifier: Apache-2.0

//! Public facade: re-exports the client, Archive and Cluster APIs and defines
//! `karyos::Error`.
//!
//! Implemented so far: the client API (publications, subscriptions and the
//! client conductor), the SPEC §10 [`Client`] facade that names channels by
//! URI, and the error type aggregating client errors. The Archive and
//! Cluster APIs do not exist yet.

pub use karyos_client::{
    Aborted, ClaimOutcome, Client, ClientClaim, ClientConductor, ClientError, ClientPublication,
    ClientSubscription, CommitOutcome, Completion, ConductorError, ConductorPoll, Connection,
    Context, ContextBuilder, IdleStrategy, ImageStop, MessageInfo, MessageLimit, OfferOutcome,
    Outcome, Overrun, PollError, PollSummary, StreamId, Subscription, SubscriptionError,
    SubscriptionPoll,
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
    /// A client conductor request could not be submitted (the low-level
    /// API; the facade reports it as `ClientError::Conductor`).
    #[error(transparent)]
    Conductor(#[from] ConductorError),
    /// A facade subscription's poll failed or the subscription is closed.
    #[error(transparent)]
    Subscription(#[from] SubscriptionError),
}
