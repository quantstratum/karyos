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
mod client_counters;
pub mod clock;
mod commands;
pub mod counters;
pub mod diagnostics;
pub mod embedded;
pub mod error;
mod generations;
mod ledger;
mod positions;
mod remote_generations;

#[cfg(target_os = "linux")]
pub use admission::{DEFAULT_MAX_TOOLS, IpcConfig};
pub use clock::{MonotonicClock, SystemClock};
pub use embedded::{
    DriverConfig, EmbeddedDriver, FIRST_INCARNATION, StreamConfig, StreamHandle, StreamState,
};
pub use error::DriverError;
pub use generations::{GenerationInfo, Reconfiguration};
pub use karyos_client::ConflatedSubscription;
pub use karyos_sys::log_buffer::{LossPolicy, SealState};
