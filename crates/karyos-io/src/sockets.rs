// SPDX-License-Identifier: Apache-2.0

//! The portable UDP sockets backend (`quantstratum-docs:
//! karyos/design/sockets-backend.md`).
//!
//! Implemented so far: the [`ops::SocketOps`] seam of section 3.9, the only
//! place that will perform socket system calls, and its scripted test
//! double (feature `test-hooks`). The endpoint, `rustix` on Linux and
//! `std::net` on macOS come in later batches.

#![forbid(unsafe_code)]

pub mod ops;
#[cfg(any(test, feature = "test-hooks"))]
pub mod scripted;
