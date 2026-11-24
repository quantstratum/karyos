// SPDX-License-Identifier: Apache-2.0

//! The per-host management agent (SPEC.md §11 "Agent", ADR-0055;
//! quantstratum-docs: karyos/design/management-agent-gap-analysis.md, M6a).
//!
//! - **What it is.** A library the `karyos-agent` binary (M7) and the
//!   exporter (M8) build on. It attaches to each configured driver as a
//!   tool (`karyos_client::tool::attach_tool`), maps the CnC read-only
//!   and never touches the data path; each attach counts against the
//!   driver's `max_tools`.
//! - **The model.** Per driver: its instance and whether it is attached,
//!   closed or unavailable; one sampling pass of the driver counters
//!   (counters by key, and per stream lane the limit, head, floor,
//!   headroom and each subscriber's lag, consistent or marked mixed); the
//!   client counters; and followers of the error log, the loss report and
//!   the guard audit ring, each with its cursor, the newest records up to
//!   a bound, and the records delivered and overwritten (a lapped cursor
//!   reports what it lost).
//! - **API v1.** [`api`] defines what the agent reports, as Rust types;
//!   [`json`] writes them as JSON, by hand (owner item 51, interim 3), and
//!   `server` serves them on a local Unix socket to the uids of a role
//!   table (interims 1 and 2; M7).
//! - **Trace latencies** (M6c): per publication lane, the observed
//!   latencies between `Publish` and `SubscriberPoll` within a bounded
//!   window of the agent's time, from a follower of the driver's trace
//!   mirror whose memory is bounded by [`WindowConfig`]; never trace
//!   verdicts (quantstratum-docs: karyos/design/agent-trace-window.md).
//! - **Exporter** (M8): [`exporter`] renders the view in the Prometheus
//!   text format and answers `GET /metrics` on a loopback address only;
//!   the `karyos-exporter` binary runs it as its own process (owner item
//!   51, interim 4).
//! - **Archive catalog** (M11): for a driver given an Archive,
//!   [`catalog`] lists its recordings over the Archive's control streams
//!   on a thread of its own, as a full IPC client of that driver; off by
//!   default.
//! - **Clocks and rate limits** (R-CORE-40, karyos#741): `clocks DIR`
//!   reads the clocks of the trace journals the agent follows and the
//!   calibrations it can see, each without a valid calibration unavailable
//!   with its reason; `rate-limits DIR` reads each network publication's
//!   rate limiters, policy, version and refusals from the driver's counter
//!   cells. Until karyos#118 produces calibrations, a clocks view
//!   legitimately shows no cross-host calibration.
//! - **Not yet.** An endpoint's capability gauges read as one group in
//!   the view (M6b's `karyos_client::capabilities` reads them).
//! - **Operations journal** (M10b): [`journal`] keeps the agent's guard
//!   operations as an Archive recording (owner item 51(7) of the
//!   2026-10-21 decisions, interim; the gap analysis's new owner item 7).
//! - **Crate graph** (owner item 52): it depends on `karyos-archive`,
//!   `karyos-client`, `karyos-sys` and `karyos-trace`, never on the driver
//!   or the tools; neither the driver, the client nor the Archive depends
//!   on it.
//!
//! The attach is Linux only, as the tool attach is; [`api`] builds
//! everywhere.
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "the attach that evaluates the rules is Linux only"
    )
)]
pub mod alerts;
pub mod api;
pub mod catalog;
pub mod cli;
pub mod exporter;
pub mod journal;
pub mod json;
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the attach that uses it is Linux only")
)]
mod model;
pub mod registry;
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the attach that uses it is Linux only")
)]
mod resources;
pub mod retention;
pub mod trace_export;
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the attach that uses it is Linux only")
)]
mod trace_window;

pub use trace_window::WindowConfig;

#[cfg(target_os = "linux")]
mod agent;
#[cfg(target_os = "linux")]
pub mod archive_retention;
#[cfg(target_os = "linux")]
pub mod operations;
#[cfg(target_os = "linux")]
pub mod preview;
#[cfg(target_os = "linux")]
pub mod server;

#[cfg(target_os = "linux")]
pub use agent::{Agent, AgentConfig, DEFAULT_ATTACH_TIMEOUT, DEFAULT_HISTORY, Requester};
