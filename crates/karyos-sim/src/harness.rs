// SPDX-License-Identifier: Apache-2.0

//! The evaluation harness of the Raft cores (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C5; ADR-0043, Harness and
//! Workloads), over the multi-node host (C1), the crashing disk (C2), the
//! linearizability checker (C3) and the Raft log (C4).
//!
//! - [`core`]: [`core::ConsensusCore`], the caller-driven trait a core's
//!   adapter implements, its neutral [`core::Ready`], and
//!   [`core::drive`], the only place that orders persistence before the
//!   messages that depend on it.
//! - [`node`]: a server node (a core, C4's log over a simulated disk, the
//!   deterministic test service) and a scripted client node, over one wire
//!   type, with the [`node::Recorder`] they report to.
//! - [`check`]: the recorded history through C3, and the safety checks.
//!
//! The workloads and a reference core follow in a later step.

pub mod check;
pub mod core;
pub mod node;
