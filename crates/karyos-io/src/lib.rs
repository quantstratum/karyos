// SPDX-License-Identifier: Apache-2.0

//! Backend traits, the sockets backend, hardware timestamps and timed transmission; the `uring` and `xdp` features add the other backends.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14.
//! Implemented so far: the backend-agnostic types and traits of
//! `karyos/design/sockets-backend.md` sections 3.1 to 3.7 ([`backend`]),
//! and the sockets system call seam with its scripted test double
//! ([`sockets`]). No module of this crate performs a system call yet.

pub mod backend;
pub mod sockets;
