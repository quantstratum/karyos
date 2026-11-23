// SPDX-License-Identifier: Apache-2.0

//! SBE 1.0 integration for Karyos (SPEC §10.1; ADR-0052; karyos#631).
//!
//! The SBE framing and the client feed adapters live here and only here:
//! the adapters plug into [`karyos_feed`]'s A/B arbitration, so this crate
//! depends on `karyos-feed` and never the reverse. IronSBE, admitted for
//! this crate alone (quantstratum-docs:
//! karyos/reviews/dependency-admission-ironsbe.md), enters through it with
//! its codec crates only: its transport, server and client never reach the
//! Karyos data plane, since Karyos is the transport (SPEC §18, X17).
//! `make sbe-graph-check` keeps both rules. The framing arrives with
//! karyos#646 and the adapters with karyos#647; this crate holds neither
//! yet.
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

#![forbid(unsafe_code)]

/// The feed arbitration the SBE adapters plug into (SPEC §7.2).
pub use karyos_feed as feed;
