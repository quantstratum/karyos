// SPDX-License-Identifier: Apache-2.0

//! The host clock of `karyos-sys` (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Timestamps"), re-exported for
//! crates that depend on `karyos-protocol` only, such as `karyos-trace`,
//! whose `HostMonotonic` trace clock reads it (`quantstratum-docs:
//! karyos/design/trace-tool.md`, T2).

pub use karyos_sys::host_clock::host_monotonic_ns;
