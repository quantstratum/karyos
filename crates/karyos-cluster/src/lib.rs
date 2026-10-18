// SPDX-License-Identifier: Apache-2.0

//! Consensus module, service container, snapshots and guards.
//!
//! The planned scope is `quantstratum-docs: karyos/SPEC.md` §14.
//! Implemented so far (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C4): the durable Raft log and
//! its term and vote store, core neutral, over the Archive's segment
//! store ([`log`], [`hard_state`]). The consensus core, the service
//! container, snapshots and guards do not exist yet.

mod file;
pub mod hard_state;
pub mod log;
pub mod mark;

pub use hard_state::HardState;
pub use log::{ChainProblem, Corruption, Entry, LogError, Opened, RaftLog};
