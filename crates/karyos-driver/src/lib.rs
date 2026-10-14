// SPDX-License-Identifier: Apache-2.0

//! Driver conductor, sender, receiver, flow control and path arbitration.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! embedded driver, which owns one log buffer and its conductor per stream in
//! the application's process, admits clients and serves their commands, and
//! runs conductor duty when the application calls
//! [`EmbeddedDriver::do_work`]. The media driver process, the network
//! sender and receiver, and agent threads do not exist yet.

pub mod clock;
mod commands;
pub mod counters;
pub mod embedded;
pub mod error;
mod generations;

pub use clock::{MonotonicClock, SystemClock};
pub use embedded::{DriverConfig, EmbeddedDriver, StreamConfig, StreamHandle, StreamState};
pub use error::DriverError;
pub use generations::{GenerationInfo, Reconfiguration};
pub use karyos_sys::log_buffer::SealState;
