// SPDX-License-Identifier: Apache-2.0

//! Public facade: the SPEC §10 client API, the Archive and Cluster APIs,
//! and `karyos::Error`.
//!
//! Start at [`Client`]: a [`Context`] names the driver, and the client
//! adds publications and subscriptions by channel URI. A [`Publication`]
//! offers or claims with `Result<Accepted, OfferError>`; a
//! [`Subscription`] polls its stream or the images of a network channel.
//!
//! [`embedded`] holds the low-level API the driver, the benchmarks and
//! the simulator use: the client conductor and the per-lane handles with
//! their outcome enums. The Archive and Cluster APIs do not exist yet.

pub use karyos_client::{
    Accepted, Claim, Client, ClientError, Connection, Context, ContextBuilder, IdleStrategy,
    ImageStop, Lane, MessageInfo, MessageLength, MessageLimit, OfferError, PollError, PollSummary,
    Publication, StreamId, Subscription, SubscriptionError, SubscriptionPoll,
};

/// The low-level client API: the conductor and the per-lane handles with
/// their outcome enums, for embedded use and the tools built on them.
pub mod embedded {
    pub use karyos_client::{
        Aborted, ClaimOutcome, ClientClaim, ClientConductor, ClientPublication, ClientSubscription,
        CommitOutcome, Completion, ConductorError, ConductorPoll, OfferOutcome, Outcome, Overrun,
    };
}

use embedded::ConductorError;

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
