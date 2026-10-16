// SPDX-License-Identifier: Apache-2.0

//! The portable UDP sockets backend (`quantstratum-docs:
//! karyos/design/sockets-backend.md`).
//!
//! Implemented so far: the [`ops::SocketOps`] seam of section 3.9, the only
//! place that performs socket system calls, its scripted test double
//! (feature `test-hooks`), the endpoint state machine over the seam
//! ([`endpoint`]) and, on Linux, the `rustix` implementation of the seam
//! (`linux`). `std::net` on macOS comes in a later batch.

#![forbid(unsafe_code)]

pub mod endpoint;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod ops;
#[cfg(any(test, feature = "test-hooks"))]
pub mod scripted;
