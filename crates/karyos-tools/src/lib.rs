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
//! ([`args::parse_tool`]).

pub mod args;
pub mod daemon;
pub mod errors;
pub mod idle;
pub mod stat;
