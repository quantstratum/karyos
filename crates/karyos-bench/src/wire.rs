// SPDX-License-Identifier: Apache-2.0

//! The wire workloads of manifest 6.1 over the sockets backend
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.3).
//!
//! - [`compose`]: the datagrams of one message of each shape, composed
//!   through the term appender and scanner.
//! - [`load`]: the R1, R2 and R3 loads.

pub mod compose;
pub mod load;
