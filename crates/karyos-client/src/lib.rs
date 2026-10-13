// SPDX-License-Identifier: Apache-2.0

//! Publications, subscriptions, the client conductor, conflation and lanes.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! embedded-mode publication and subscription API over one lane's log buffer
//! (copy delivery), and the client conductor that requests them from the
//! driver through the command ring and the broadcast buffer. Conflation,
//! lanes beyond one and IPC attachment do not exist yet.

pub mod concurrent;
pub mod conductor;
pub mod error;
pub mod link;
pub mod publication;
pub mod subscription;

pub use concurrent::{
    ClientConcurrentClaim, ClientConcurrentPublication, ConcurrentClaimOutcome,
    ConcurrentOfferOutcome,
};
pub use conductor::{ClientConductor, Completion, ConductorError, ConductorPoll, Outcome};
pub use error::ClientError;
pub use publication::{ClaimOutcome, ClientClaim, ClientPublication, CommitOutcome, OfferOutcome};
pub use subscription::{
    Aborted, ClientSubscription, MessageInfo, MessageLimit, Overrun, PollError, PollSummary,
};
