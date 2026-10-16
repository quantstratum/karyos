// SPDX-License-Identifier: Apache-2.0

//! Backend traits, the sockets backend, hardware timestamps and timed transmission; the `uring` and `xdp` features add the other backends.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14.
//! Implemented so far: the backend-agnostic types and traits of
//! `karyos/design/sockets-backend.md` sections 3.1 to 3.7 ([`backend`]),
//! the sockets system call seam with its scripted test double and the
//! sockets endpoint state machine over that seam ([`sockets`]). No module
//! of this crate performs a socket system call yet.

/// Counts this test binary's allocations, for the data calls that must not
/// allocate (`karyos_sys::alloc_count`).
#[cfg(test)]
#[global_allocator]
static ALLOCATOR: karyos_sys::alloc_count::CountingAllocator =
    karyos_sys::alloc_count::CountingAllocator;

pub mod backend;
pub mod sockets;
