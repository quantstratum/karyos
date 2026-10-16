// SPDX-License-Identifier: Apache-2.0

//! The portable UDP sockets backend (`quantstratum-docs:
//! karyos/design/sockets-backend.md`).
//!
//! Implemented so far: the [`ops::SocketOps`] seam of section 3.9, the only
//! place that performs socket system calls, its scripted test double
//! (feature `test-hooks`), the endpoint state machine over the seam
//! ([`endpoint`]) and the platform implementations of the seam,
//! [`OsSocket`]: `rustix` on Linux (`linux`) and `std::net` on macOS
//! (`portable`), decisions O-1 and O-2.

#![forbid(unsafe_code)]

pub mod endpoint;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod ops;
#[cfg(target_os = "macos")]
pub mod portable;
#[cfg(any(test, feature = "test-hooks"))]
pub mod scripted;

/// The [`ops::SocketOps`] of this platform (3.9): `rustix` on Linux.
#[cfg(target_os = "linux")]
pub type OsSocket = linux::LinuxSocket;

/// The [`ops::SocketOps`] of this platform (3.9): `std::net` on macOS.
#[cfg(target_os = "macos")]
pub type OsSocket = portable::PortableSocket;

/// The sockets endpoint over the operating system's sockets (3.8).
pub type SocketsBackend = endpoint::SocketsEndpoint<OsSocket>;
