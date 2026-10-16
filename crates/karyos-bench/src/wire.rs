// SPDX-License-Identifier: Apache-2.0

//! The wire workloads of manifest 6.1 over the sockets backend
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.3).
//!
//! - [`compose`]: the datagrams of one message of each shape, composed
//!   through the term appender and scanner.
//! - [`load`]: the R1, R2 and R3 loads.
//! - [`stage`]: the send and receive stages of one run over loopback.
//! - [`process`]: each role in its own process.
//! - [`profile`]: the protection profile a configuration names.

pub mod compose;
pub mod load;
pub mod process;
pub mod profile;
pub mod stage;
