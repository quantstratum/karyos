// SPDX-License-Identifier: Apache-2.0

//! Deterministic simulator, including the backend ring models.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far
//! (`quantstratum-docs: karyos/design/simulator-and-bench.md`, s1): a seeded, single-threaded
//! scheduler on virtual time that drives the embedded driver one API call
//! per step, with suspended actors (also inside a claim), forgotten
//! claims, dropped handles, stream removal and cutovers, clients whose
//! heartbeat stops (also while their reader holds a loan) until the
//! driver may time them out under the stream's loss policy, conflated
//! streams read through their keyed view, and an oracle that checks every
//! delivery. Timed transmission on virtual time (P2.11 T1) runs in
//! `tests/timed.rs`, over the scripted sockets of karyos-io's test hooks.
//! Suspensions and drops are logical, inside one
//! process: they are not evidence for real process pause, crash or restart,
//! which belongs to IPC. The network, the backend ring models, the disk
//! model, the Archive and the Cluster do not exist yet.

pub mod clock;
pub mod oracle;
pub mod payload;
pub mod publisher;
pub mod rng;
pub mod scenarios;
pub mod sim;

pub use clock::SimClock;
pub use rng::Rng;
pub use sim::{Failure, Faults, Report, Scenario, StreamPlan, run};
