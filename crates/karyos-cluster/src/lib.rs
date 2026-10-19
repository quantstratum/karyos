// SPDX-License-Identifier: Apache-2.0

//! Consensus module, service container, snapshots and guards.
//!
//! The planned scope is `quantstratum-docs: karyos/SPEC.md` §14.
//! Implemented so far (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C4): the durable Raft log and
//! its term and vote store, core neutral, over the Archive's segment
//! store ([`log`], [`hard_state`]); C7a's client deduplication, the
//! replicated session table ([`dedup`]); and C8a's snapshot store, typed
//! sections published by a manifest ([`snapshot`]). The consensus core,
//! the service container and guards do not exist yet.

pub mod dedup;
mod file;
pub mod hard_state;
pub mod log;
pub mod mark;
pub mod snapshot;

pub use dedup::{DecodeError, DedupConfig, Outcome, Registered, Request, SessionTable};
pub use hard_state::HardState;
pub use log::{ChainProblem, Corruption, Entry, LogError, Opened, RaftLog};
