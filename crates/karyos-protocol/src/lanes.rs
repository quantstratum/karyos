// SPDX-License-Identifier: Apache-2.0

//! Priority lanes (SPEC.md §7.4, ADR-0020): the scheduling logic shared by
//! the network sender and the aggregate subscriber (`quantstratum-docs:
//! karyos/design/aggregate-lanes.md`).
//!
//! Implemented so far: [`drr`], the persistent deficit round robin state
//! machine, which knows nothing of sockets, terms or backends; a caller
//! supplies the lanes through [`drr::LaneSource`].

pub mod drr;
