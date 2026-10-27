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
//! - [`delivery`]: the `ClusteredService` delivery path (C10): a server
//!   node over a service container and a client with a session, apart
//!   from the C5 nodes.
//! - [`node`]: a server node (a core, C4's log over a simulated disk, the
//!   deterministic test service) and a scripted client node, over one wire
//!   type, with the [`node::Recorder`] they report to.
//! - [`check`]: the recorded history through C3, and the safety checks.
//! - [`reference`](mod@reference): a harness fixture core with a fixed leader and no
//!   elections.
//! - [`workloads`]: ADR-0043's workloads as generators of cases, a runner
//!   and pass predicates, safety and liveness reported apart.
//! - [`membership`]: the phase 5 membership scenarios a fixed leader can
//!   run (quantstratum-docs: karyos/design/phase-5-cluster-scenarios.md,
//!   P5-S1).
//! - [`standby`]: a standby cluster, its feed, fencing and promotion
//!   (the same document, P5-S2).

pub mod check;
pub mod core;
pub mod delivery;
pub mod membership;
pub mod node;
pub mod reference;
pub mod standby;
pub mod workloads;
