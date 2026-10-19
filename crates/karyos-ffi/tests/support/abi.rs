// SPDX-License-Identifier: Apache-2.0

//! The exported symbols, declared as C declares them, and safe wrappers the
//! tests call. This module is the only `unsafe` of the tests (SPEC.md
//! §10.2, §14): `make lint-sync` checks that it and `src/abi.rs` are the
//! only modules that expect `unsafe_code`.

#![expect(
    unsafe_code,
    reason = "calls the C ABI through its exported symbols, as C does (ADR-0053)"
)]

use core::ffi::{CStr, c_char};

unsafe extern "C" {
    fn karyos_abi_version(major: *mut u32, minor: *mut u32, patch: *mut u32) -> i32;
    safe fn karyos_status_message(status: i32) -> *const c_char;
}

/// `karyos_abi_version` with valid out-parameters: the status and the
/// version.
pub fn abi_version() -> (i32, [u32; 3]) {
    let mut version = [u32::MAX; 3];
    let [major, minor, patch] = &mut version;
    // SAFETY: each pointer is a live, aligned, writable `u32`.
    let status = unsafe { karyos_abi_version(major, minor, patch) };
    (status, version)
}

/// `karyos_abi_version` with a null `minor`: the status and what was
/// written.
pub fn abi_version_null_minor() -> (i32, [u32; 2]) {
    let mut written = [u32::MAX; 2];
    let [major, patch] = &mut written;
    // SAFETY: a null pointer is allowed; the others are live, aligned and
    // writable.
    let status = unsafe { karyos_abi_version(major, core::ptr::null_mut(), patch) };
    (status, written)
}

/// `karyos_abi_version` with a misaligned `major`: the status and what was
/// written.
pub fn abi_version_misaligned_major() -> (i32, [u32; 2]) {
    let mut bytes = [0_u8; 8];
    let mut written = [u32::MAX; 2];
    let [minor, patch] = &mut written;
    // An address one byte past an aligned `u32` slot is misaligned, and
    // the function checks alignment before writing.
    let base = bytes.as_mut_ptr();
    let misaligned = base.wrapping_add(base.align_offset(4) + 1).cast::<u32>();
    // SAFETY: the function refuses the misaligned pointer before any use;
    // the others are live, aligned and writable.
    let status = unsafe { karyos_abi_version(misaligned, minor, patch) };
    (status, written)
}

/// `karyos_abi_version` with the out-parameters marked in `null` passed as
/// null: the status, and each value written (`None` for a null or
/// untouched one).
pub fn abi_version_with(null: [bool; 3]) -> (i32, [Option<u32>; 3]) {
    let mut values = [u32::MAX; 3];
    let [major, minor, patch] = &mut values;
    let pointer = |value: &mut u32, null: bool| {
        if null {
            core::ptr::null_mut()
        } else {
            core::ptr::from_mut(value)
        }
    };
    let [major_null, minor_null, patch_null] = null;
    let (major, minor, patch) = (
        pointer(major, major_null),
        pointer(minor, minor_null),
        pointer(patch, patch_null),
    );
    // SAFETY: each pointer is null or a live, aligned, writable `u32`.
    let status = unsafe { karyos_abi_version(major, minor, patch) };
    let written = |value: u32, null: bool| (!null && value != u32::MAX).then_some(value);
    let [major, minor, patch] = values;
    (
        status,
        [
            written(major, major_null),
            written(minor, minor_null),
            written(patch, patch_null),
        ],
    )
}

/// `karyos_status_message` as a string.
pub fn status_message(status: i32) -> String {
    let text = karyos_status_message(status);
    assert!(!text.is_null());
    // SAFETY: the function returns a NUL-terminated static string.
    let text = unsafe { CStr::from_ptr(text) };
    text.to_string_lossy().into_owned()
}
