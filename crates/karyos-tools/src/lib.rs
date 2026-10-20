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
//! output and run loop live in [`trace`]; and `karyos-tools replay diff`
//! (`quantstratum-docs: karyos/design/recording-group-replay.md` section
//! 10), which compares two recording group journals ([`replay`]).

pub mod archive;
pub mod args;
pub mod capability_log;
pub mod daemon;
pub mod errors;
pub mod idle;
pub mod replay;
pub mod stat;
pub mod trace;
