// SPDX-License-Identifier: Apache-2.0

//! Consensus module, service container, snapshots and guards.
//!
//! The planned scope is `quantstratum-docs: karyos/SPEC.md` §14.
//! Implemented so far (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C4): the durable Raft log and
//! its term and vote store, core neutral, over the Archive's segment
//! store ([`log`], [`hard_state`]); C7a's client deduplication, the
//! replicated session table ([`dedup`]); and C8a's snapshot store, typed
//! sections published by a manifest ([`snapshot`]); and C10's service
//! container, a [`service::ClusteredService`] fed committed entries
//! ([`service`]); and the custom Raft core's state machine of ADR-0105
//! ([`consensus`]), not yet driven over the log. The guards do not exist
//! yet.
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

pub mod consensus;
pub mod dedup;
mod file;
pub mod hard_state;
pub mod log;
pub mod mark;
pub mod service;
pub mod snapshot;

pub use dedup::{DecodeError, DedupConfig, Outcome, Registered, Request, SessionTable};
pub use hard_state::HardState;
pub use log::{
    ChainProblem, Corruption, Entry, EntryAnswer, EntrySlot, LogError, Opened, RaftLog, SlotAnswer,
};
