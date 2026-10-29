// SPDX-License-Identifier: Apache-2.0

//! Public facade: the SPEC §10 client API, the Archive and Cluster APIs,
//! and `karyos::Error`.
//!
//! Start at [`Client`]: a [`Context`] names the driver, and the client
//! adds publications and subscriptions by channel URI. A [`Publication`]
//! offers or claims with `Result<Accepted, OfferError>`; a
//! [`Subscription`] polls its stream or the images of a network channel.
//!
//! The shape of SPEC §10, against [`Error`]:
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> Result<(), karyos::Error> {
//! use karyos::{
//!     Client, Context, IdleStrategy, Lane, MessageLength, MessageLimit, OfferError, StreamId,
//! };
//!
//! let ctx = Context::builder()
//!     .dir("/dev/shm/karyos")
//!     .idle_strategy(IdleStrategy::BusySpin)
//!     .build()?;
//! let mut client = Client::connect(ctx)?;
//!
//! // Publish
//! let mut orders = client.add_exclusive_publication("karyos:ipc?lanes=2", StreamId::new(1001))?;
//! let encoded = [0u8; 64];
//! let lane = Lane::try_new(1).expect("a lane below Lane::COUNT");
//! match orders.offer_on(lane, &encoded) {
//!     Ok(accepted) => { /* lane and position, accepted locally */ }
//!     Err(OfferError::BackPressured) => { /* retry or drop */ }
//!     Err(OfferError::Gated) => { /* kill switch is closed */ }
//!     Err(e) => return Err(e.into()),
//! }
//!
//! // Encode in place; dropping an uncommitted claim aborts its block
//! let mut claim = orders.try_claim(MessageLength::try_new(64)?)?;
//! claim.payload().copy_from_slice(&encoded);
//! let accepted = claim.commit()?;
//!
//! // Subscribe
//! let mut md = client.add_subscription("karyos:ipc", StreamId::new(2001))?;
//! md.poll(|payload, _info| drop(payload), MessageLimit::new(16))?;
//! # let _ = accepted;
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! [`embedded`] holds the low-level API the driver, the benchmarks and
//! the simulator use: the client conductor and the per-lane handles with
//! their outcome enums. The Archive and Cluster APIs do not exist yet.
//!
//! # Versions
//!
//! [`CORE_VERSION`] is the core release this facade was built from, and
//! [`PROTOCOL_VERSION`] the admission protocol version its client
//! announces to a driver (R-CORE-33, karyos#752). They are the values the
//! C ABI publishes as `KARYOS_PROTOCOL_VERSION` and a `libkaryos`
//! package's manifest as `core_version` and `protocol_version`, readable
//! at run time without the C ABI:
//!
//! ```
//! let release: &str = karyos::CORE_VERSION;
//! let protocol: u64 = karyos::PROTOCOL_VERSION;
//! assert!(!release.is_empty() && protocol > 0);
//! ```

/// The core release this facade was built from: the workspace version,
/// such as `0.1.0-alpha.2` (R-CORE-33, karyos#752).
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use karyos_client::PROTOCOL_VERSION;
pub use karyos_client::{
    Accepted, Claim, Client, ClientError, ConflatedBudget, ConflatedLimits, ConflatedOptions,
    ConflatedSubscription, ConflatedValue, Connection, Context, ContextBuilder, Freshness,
    IdleStrategy, ImageChange, ImageEnd, ImageStop, Lane, MessageInfo, MessageLength, MessageLimit,
    NetworkAdmission, OfferError, OfferOptions, PollError, PollSummary, Publication,
    PublicationRoles, ReceiverIdentity, RejoinPolicy, SealReason, Secondary, SnapshotSource,
    Strategy, StreamId, SubscriberRole, Subscription, SubscriptionError, SubscriptionOptions,
    SubscriptionPoll, ViewClosed,
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
#[non_exhaustive]
pub enum Error {
    /// A client error.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// An offer, a claim or a commit was not accepted.
    #[error(transparent)]
    Offer(#[from] OfferError),
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
