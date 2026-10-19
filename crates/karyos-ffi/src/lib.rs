// SPDX-License-Identifier: Apache-2.0

//! The C ABI of Karyos (quantstratum-docs: karyos/SPEC.md §10.2, ADR-0053,
//! ADR-0067; karyos/design/ffi-gap-analysis.md).
//!
//! The crate has no public Rust API: its interface is the C symbols
//! `include/karyos.h` declares. `unsafe` is denied in the crate and
//! expected only in the boundary module `abi`, which turns each pointer and
//! length into a checked safe value before the safe modules see it.
//!
//! Built so far (F1): the ABI version, the status codes and their text, the
//! bounded handle tables and the panic boundary. Objects come with F2
//! onward.

#![deny(unsafe_code)]

#[expect(
    unsafe_code,
    reason = "the C ABI boundary: exported symbols and raw pointer arguments (ADR-0053)"
)]
mod abi;
mod boundary;
#[expect(dead_code, reason = "the handle kinds get their tables from F2 on")]
mod handles;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "most codes and the error mapping are used from F2 on"
    )
)]
mod status;

#[cfg(test)]
mod header;
