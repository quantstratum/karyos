// SPDX-License-Identifier: Apache-2.0

//! Frame layouts, flyweights and channel URI parsing.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! frame header, word 0, flags, frame types and trace extension encodings,
//! term length, MTU and message sizing (SPEC.md §4 and §5); and sequential
//! flyweights that append message blocks to, and scan them from, a term held
//! in a byte slice; and the client command and driver response messages of
//! the CnC structures (`cnc`); and re-exports of the bounded record journal
//! (`journal`) and the host clock (`host_clock`) of `karyos-sys`; and the
//! data-path tracing hook that `karyos-trace` implements (`trace_hook`).
//! Concurrent shared-memory access and URI parsing do not exist yet.

pub mod admission;
pub mod cnc;
pub mod error;
pub mod frame;
pub mod host_clock;
pub mod journal;
pub mod sizing;
pub mod term;
pub mod trace_hook;

pub use error::{LayoutError, ProtocolError};
