// SPDX-License-Identifier: Apache-2.0

//! Frame layouts, flyweights and channel URI parsing.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! frame header, word 0, flags, frame types and trace extension encodings,
//! and term length, MTU and message sizing (SPEC.md §4 and §5). Flyweights
//! over live terms and URI parsing do not exist yet.

pub mod error;
pub mod frame;
pub mod sizing;

pub use error::ProtocolError;
