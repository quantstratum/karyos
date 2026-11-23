// SPDX-License-Identifier: Apache-2.0

//! Backend traits, the sockets backend, hardware timestamps and timed transmission; the `uring` and `xdp` features add the other backends.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14.
//! Implemented so far: the backend-agnostic types and traits of
//! `karyos/design/sockets-backend.md` sections 3.1 to 3.7 ([`backend`]),
//! the sockets system call seam with its scripted test double, the sockets
//! endpoint state machine over that seam and its implementations over
//! `rustix` on Linux and `std::net` on macOS ([`sockets`]).
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

/// Counts this test binary's allocations, for the data calls that must not
/// allocate (`karyos_sys::alloc_count`).
#[cfg(test)]
#[global_allocator]
static ALLOCATOR: karyos_sys::alloc_count::CountingAllocator =
    karyos_sys::alloc_count::CountingAllocator;

pub mod backend;
pub mod lanes;
pub mod sockets;
#[cfg(any(feature = "uring", feature = "test-hooks", test))]
pub mod uring;
