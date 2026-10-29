// SPDX-License-Identifier: Apache-2.0

//! The C ABI version (R-CORE-33, karyos#729; `quantstratum-docs:
//! karyos/design/versions.md`): the single source of `libkaryos`'s
//! version, which `karyos-ffi` exports as `karyos_abi_version` and its
//! header as `KARYOS_ABI_VERSION_*`, and the tools report with the other
//! contract versions. Kept here, beside the admission version, so a tool
//! reports it without depending on the C ABI crate. Owner item 48's rule
//! applies: additive growth increments the patch; a binding requires the
//! exact `0.y` line and a library patch at least its header's.

/// The C ABI version's major number.
pub const C_ABI_MAJOR: u32 = 0;
/// The C ABI version's minor number.
pub const C_ABI_MINOR: u32 = 1;
/// The C ABI version's patch number.
pub const C_ABI_PATCH: u32 = 5;
