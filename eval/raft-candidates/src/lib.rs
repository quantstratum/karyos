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
//! - [`openraft_wire`]: the bytes of its messages between processes.
//! - [`raft_rs`]: `raft` 0.7.0 (TiKV's raft-rs), its `RawNode` driven by
//!   the harness's node.
//! - [`process`]: the same cores in real processes: C4's log on real
//!   files, UDP between processes, the monotonic clock, serving the
//!   harness test service to client processes.
//! - [`record`]: what those processes report, stamped from the host
//!   monotonic clock, and its merge for the harness checks.
//! - [`v2`]: C5 version 2's frozen W2 in-flight byte case.
//! - [`variant`]: which build of a candidate ran, baseline or patched,
//!   with its patch record.

pub mod custom_wire;
pub mod executor;
pub mod openraft_core;
pub mod openraft_wire;
pub mod process;
pub mod raft_rs;
pub mod record;
pub mod v2;
pub mod variant;
