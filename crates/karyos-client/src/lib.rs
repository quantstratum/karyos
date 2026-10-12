// SPDX-License-Identifier: Apache-2.0

//! Publications, subscriptions, the client conductor, conflation and lanes.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! embedded-mode publication and subscription API over one lane's log buffer
//! (copy delivery). The client conductor, conflation, lanes beyond one and
//! IPC attachment do not exist yet.

pub mod error;
pub mod publication;
pub mod subscription;

pub use error::ClientError;
pub use publication::{ClientPublication, OfferOutcome};
pub use subscription::{ClientSubscription, MessageInfo, PollSummary};
