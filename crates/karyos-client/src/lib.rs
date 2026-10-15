// SPDX-License-Identifier: Apache-2.0

//! Publications, subscriptions, the client conductor, conflation and lanes.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! embedded-mode publication and subscription API over one lane's log buffer
//! (copy delivery), a bounded client view over the keyed conflation table,
//! and the client conductor that requests capabilities from the driver.
//! The driver feeder, lanes beyond one and IPC attachment do not exist yet.

pub mod concurrent;
pub mod conductor;
pub mod conflated_subscription;
pub mod error;
pub mod generation;
#[cfg(target_os = "linux")]
pub mod ipc;
pub mod link;
pub mod publication;
pub mod subscription;
pub mod trace;

pub use concurrent::{
    ClientConcurrentClaim, ClientConcurrentPublication, ConcurrentClaimOutcome,
    ConcurrentOfferOutcome,
};
pub use conductor::{
    ClientConductor, Completion, ConductorError, ConductorPoll, DEFAULT_DRIVER_TIMEOUT,
    DEFAULT_HEARTBEAT_INTERVAL, EVENT_QUEUE, Fetchable, Outcome, Request,
};
pub use conflated_subscription::ConflatedSubscription;
pub use error::ClientError;
pub use generation::{GenerationLink, LinkStatus, Successor};
pub use publication::{ClaimOutcome, ClientClaim, ClientPublication, CommitOutcome, OfferOutcome};
pub use subscription::{
    Aborted, ClientSubscription, InvalidExtensions, MessageInfo, MessageLimit, Overrun, PollError,
    PollSummary, Skipped,
};
pub use trace::TraceDecision;
