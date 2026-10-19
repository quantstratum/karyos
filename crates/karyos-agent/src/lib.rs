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
//! - **API v1.** [`api`] defines what the agent reports, as Rust types; no
//!   transport and no encoding yet (M7, owner items 1 and 3).
//! - **Not yet.** Trace latency histograms over a bounded window (M6c)
//!   and an endpoint's capability gauges read as one group (M6b).
//! - **Crate graph** (owner item 52): it depends on `karyos-client` and
//!   `karyos-sys`; neither the driver nor the client depends on it.
//!
//! The attach is Linux only, as the tool attach is; [`api`] builds
//! everywhere.

pub mod api;
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the attach that uses it is Linux only")
)]
mod model;

#[cfg(target_os = "linux")]
mod agent;

#[cfg(target_os = "linux")]
pub use agent::{Agent, AgentConfig, DEFAULT_ATTACH_TIMEOUT, DEFAULT_HISTORY};
