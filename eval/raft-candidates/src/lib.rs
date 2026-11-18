// SPDX-License-Identifier: Apache-2.0

//! The adapters of ADR-0043's Raft candidates behind the C5 harness's
//! [`ConsensusCore`](karyos_sim::harness::core::ConsensusCore)
//! (quantstratum-docs: karyos/design/cluster-gap-analysis.md §6, C5;
//! plan issue 060, karyos#678).
//!
//! **Evaluation only.** This crate is its own workspace, unpublished, and
//! no crate of the core depends on it (quantstratum-docs:
//! karyos/reviews/dependency-admission-raft-candidates-evaluation.md,
//! conditions 1 to 3; `make shipped-graph-check` in the core's
//! `make pre-push`). Nothing here selects a core.
//!
//! - [`executor`]: the bounded, manually pumped executor behind
//!   `openraft-rt`'s runtime abstraction (owner item 33).
//! - [`openraft_core`]: `openraft` 0.10.0-alpha.37, default features off,
//!   on that executor.
//! - [`raft_rs`]: `raft` 0.7.0 (TiKV's raft-rs), its `RawNode` driven by
//!   the harness's node.
//! - [`process`]: the same cores in real processes: C4's log on real
//!   files, UDP between processes, the monotonic clock.
//! - [`variant`]: which build of a candidate ran, baseline or patched,
//!   with its patch record.

pub mod executor;
pub mod openraft_core;
pub mod process;
pub mod raft_rs;
pub mod variant;
