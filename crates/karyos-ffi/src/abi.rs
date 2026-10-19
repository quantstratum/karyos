// SPDX-License-Identifier: Apache-2.0

//! The boundary: every exported symbol, and the only `unsafe` of the crate
//! (SPEC.md §10.2; ADR-0053). Each function catches unwinding, checks each
//! pointer (null, alignment) before any use and hands safe values to the
//! safe modules. `include/karyos.h` declares every symbol; a test checks
//! the two agree.

use core::ffi::c_char;
use std::panic::catch_unwind;

use crate::boundary::{forget_payload, guard};
use crate::status::{Status, UNKNOWN_CODE};

/// The ABI version's major number (`KARYOS_ABI_VERSION_MAJOR`).
pub(crate) const ABI_VERSION_MAJOR: u32 = 0;
/// The ABI version's minor number (`KARYOS_ABI_VERSION_MINOR`).
pub(crate) const ABI_VERSION_MINOR: u32 = 1;
/// The ABI version's patch number (`KARYOS_ABI_VERSION_PATCH`).
pub(crate) const ABI_VERSION_PATCH: u32 = 0;

/// Whether `out` can take a `T`: not null and aligned. It cannot tell a
/// dangling pointer; the caller's contract excludes one.
fn writable<T>(out: *mut T) -> bool {
    !out.is_null() && out.is_aligned()
}

/// Writes the ABI version this library implements through `major`, `minor`
/// and `patch`. Call it before any other function: a different major is
/// incompatible.
///
/// Returns `KARYOS_OK`, or `KARYOS_E_INVALID_ARGUMENT`, with nothing
/// written, when a pointer is null or misaligned.
///
/// # Safety
///
/// Each pointer is null or points to a `uint32_t` the caller may write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_abi_version(
    major: *mut u32,
    minor: *mut u32,
    patch: *mut u32,
) -> i32 {
    guard(|| {
        if !(writable(major) && writable(minor) && writable(patch)) {
            return Status::InvalidArgument;
        }
        // SAFETY: `major` is non-null and aligned (checked above), and the
        // caller's contract makes it point to a writable `uint32_t`.
        unsafe { major.write(ABI_VERSION_MAJOR) };
        // SAFETY: as for `major`.
        unsafe { minor.write(ABI_VERSION_MINOR) };
        // SAFETY: as for `major`.
        unsafe { patch.write(ABI_VERSION_PATCH) };
        Status::Ok
    })
}

/// The static text of `status`: a NUL-terminated string that lives as long
/// as the library and is never freed. A code that is no status gets a
/// fixed text.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_status_message(status: i32) -> *const c_char {
    match catch_unwind(|| Status::from_code(status).map_or(UNKNOWN_CODE, Status::message)) {
        Ok(text) => text.as_ptr(),
        Err(payload) => {
            forget_payload(payload);
            UNKNOWN_CODE.as_ptr()
        }
    }
}
