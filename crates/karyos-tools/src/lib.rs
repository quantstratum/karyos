// SPDX-License-Identifier: Apache-2.0

//! The `karyosd` daemon and the operational binaries.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14.
//! Implemented so far: `karyosd` (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Binaries), whose logic lives
//! here so that it can be tested: its command line ([`args`]), its duty
//! cycle loop and orderly shutdown ([`daemon`]) and its idle strategy
//! ([`idle`]); `karyos-stat` ([`stat`]) and `karyos-errors` ([`errors`]),
//! which attach as tools, with their shared command line
//! ([`args::parse_tool`]); and `karyos-trace` (`quantstratum-docs:
//! karyos/design/trace-tool.md`), whose command line, mirror reader,
//! output and run loop live in [`trace`]; and `karyos-replay diff`, with
//! its alias `karyos-tools replay diff` (`quantstratum-docs:
//! karyos/design/recording-group-replay.md` section 10,
//! `karyos/design/archive-host.md` H5), which compares two recording group
//! journals ([`replay`]); and `karyos-catalog list`
//! (`karyos/design/archive-host.md`, H4 and H4b), which lists an archive
//! directory's catalog read only, or a running Archive's recordings over
//! its control streams ([`catalog`]).
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

pub mod archive;
pub mod archive_signer;
pub mod args;
pub mod calibrate;
pub mod capability_log;
pub mod catalog;
pub mod catalog_export;
pub mod catalog_verify;
pub mod compat;
pub mod config;
pub mod daemon;
#[cfg(target_os = "linux")]
pub mod daemon_archive;
#[cfg(target_os = "linux")]
pub mod daemon_replica;
#[cfg(target_os = "linux")]
pub mod daemon_replication;
pub mod daemon_trace;
pub mod errors;
pub mod idle;
#[cfg(target_os = "linux")]
pub mod probe;
pub mod replay;
pub mod replay_live;
pub mod stat;
pub mod trace;
pub mod versions;
