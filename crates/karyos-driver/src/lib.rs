// SPDX-License-Identifier: Apache-2.0

//! Driver conductor, sender, receiver, flow control and path arbitration.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! embedded driver, which owns one log buffer and its conductor per stream in
//! the application's process, admits clients and serves their commands, and
//! runs conductor duty when the application calls
//! [`EmbeddedDriver::do_work`]. The media driver process, the network
//! sender and receiver, and agent threads do not exist yet.
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

#[cfg(target_os = "linux")]
pub mod admission;
pub mod agents;
pub mod authority;
mod capabilities;
mod client_counters;
pub mod clock;
mod commands;
pub mod counters;
pub mod diagnostics;
pub mod embedded;
pub mod error;
mod generations;
pub mod grant_audit;
pub mod guard_ack;
pub mod guard_gate;
mod guard_streams;
pub mod guards;
mod ledger;
pub mod membership;
pub mod net;
mod network_journals;
pub mod paths;
mod positions;
pub mod recording;
mod remote_generations;
pub mod repair;
pub mod replay;
pub mod rtt;
pub mod schedule;
pub mod sessions;
pub(crate) mod shared_words;
#[cfg(target_os = "linux")]
pub mod sizing;
pub mod sm_schedule;
pub mod spin;
pub mod timed_gate;
mod trace_journals;

#[cfg(test)]
pub(crate) mod test_ports;

/// The lib tests count allocations where a test arms the counter (the
/// trace drain path); unarmed, it is the system allocator.
#[cfg(test)]
#[global_allocator]
static ALLOCATOR: karyos_sys::alloc_count::CountingAllocator =
    karyos_sys::alloc_count::CountingAllocator;

#[cfg(target_os = "linux")]
pub use admission::{DEFAULT_MAX_TOOLS, IpcConfig, MAX_PROBES_PER_STEP};
pub use clock::{MonotonicClock, SystemClock};
pub use embedded::{
    AggregateConfig, AggregateHandle, DriverConfig, EmbeddedDriver, FIRST_INCARNATION,
    FailedReason, NotReadyReason, Readiness, StreamConfig, StreamHandle, StreamState,
    stream_lane_bytes,
};
pub use error::{DriverError, EndpointLimit, TimedNetworkUnsupported, WalkerUnavailable};
pub use generations::{GenerationInfo, Reconfiguration};
pub use guards::{
    Audit, AuditOutcome, AuditRecord, GuardHandle, GuardRate, LaneRefusal, RateAuthority,
    RateChangeError, RateScope, Requester,
};
pub use karyos_client::ConflatedSubscription;
pub use karyos_sys::log_buffer::{LossPolicy, SealReason, SealState};
