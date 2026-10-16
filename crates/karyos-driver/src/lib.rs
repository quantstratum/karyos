// SPDX-License-Identifier: Apache-2.0

//! Driver conductor, sender, receiver, flow control and path arbitration.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! embedded driver, which owns one log buffer and its conductor per stream in
//! the application's process, admits clients and serves their commands, and
//! runs conductor duty when the application calls
//! [`EmbeddedDriver::do_work`]. The media driver process, the network
//! sender and receiver, and agent threads do not exist yet.

#[cfg(target_os = "linux")]
pub mod admission;
pub mod agents;
mod client_counters;
pub mod clock;
mod commands;
pub mod counters;
pub mod diagnostics;
pub mod embedded;
pub mod error;
mod generations;
pub mod guard_ack;
pub mod guard_gate;
mod guard_streams;
pub mod guards;
mod ledger;
pub mod paths;
mod positions;
mod remote_generations;
pub mod rtt;
pub mod schedule;
pub mod sessions;
pub mod timed_gate;
mod trace_journals;

#[cfg(target_os = "linux")]
pub use admission::{DEFAULT_MAX_TOOLS, IpcConfig};
pub use clock::{MonotonicClock, SystemClock};
pub use embedded::{
    AggregateConfig, AggregateHandle, DriverConfig, EmbeddedDriver, FIRST_INCARNATION,
    StreamConfig, StreamHandle, StreamState,
};
pub use error::{DriverError, WalkerUnavailable};
pub use generations::{GenerationInfo, Reconfiguration};
pub use guards::{Audit, AuditOutcome, AuditRecord, GuardHandle, GuardRate, RateScope, Requester};
pub use karyos_client::ConflatedSubscription;
pub use karyos_sys::log_buffer::{LossPolicy, SealReason, SealState};
