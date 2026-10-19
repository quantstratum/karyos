// SPDX-License-Identifier: Apache-2.0

//! The boundary: every exported symbol, and the only `unsafe` of the crate
//! (SPEC.md §10.2; ADR-0053). Each function catches unwinding, checks each
//! pointer (null, alignment) before any use and hands safe values to the
//! safe modules. `include/karyos.h` declares every symbol; a test checks
//! the two agree.

use core::ffi::{CStr, c_char};
use std::panic::catch_unwind;
use std::path::PathBuf;

use crate::api::client;
use crate::boundary::{drop_payload, guard};
use crate::handles::Handle;
use crate::status::{Failure, Status, UNKNOWN_CODE};

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

/// Whether `input` can give a `T`: not null and aligned.
fn readable<T>(input: *const T) -> bool {
    !input.is_null() && input.is_aligned()
}

/// `karyos_client_options`: a client's options, copied by
/// `karyos_client_connect`. `size` comes first and is
/// `sizeof(karyos_client_options)` of the header the caller was built
/// with; `karyos_client_options_init` fills it and the defaults.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    /// The struct's size in bytes.
    pub size: u32,
    /// `KARYOS_IDLE_BUSY_SPIN`, `KARYOS_IDLE_YIELD` or `KARYOS_IDLE_SLEEP`.
    pub idle_strategy: u32,
    /// The driver's directory, NUL-terminated UTF-8; null for none.
    pub dir: *const c_char,
    /// The sleep of `KARYOS_IDLE_SLEEP`, in nanoseconds.
    pub idle_sleep_ns: u64,
    /// The longest wait of a control call, in nanoseconds; not 0.
    pub timeout_ns: u64,
    /// The most requests in flight; not 0.
    pub max_pending: u32,
    /// The most images a network subscription attaches; not 0.
    pub max_images: u32,
}

/// `karyos_detail`: what a failed control call adds to its status.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Detail {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// Zero.
    pub reserved: u32,
    /// A code the status defines, such as the driver's refusal code.
    pub code: u64,
    /// A value the status defines, such as a length, a version or `errno`.
    pub value: u64,
}

/// The size of `T` as the `size` field states it.
fn size_of_u32<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
}

/// Writes `failure`'s detail through `detail`, when it is an aligned
/// `karyos_detail` whose `size` covers this version's struct; otherwise
/// writes nothing.
///
/// # Safety
///
/// `detail` is null or points to a writable `karyos_detail` whose `size`
/// field the caller set.
unsafe fn write_detail(detail: *mut Detail, failure: Failure) {
    if !writable(detail) {
        return;
    }
    // SAFETY: `detail` is non-null and aligned, and points to a
    // `karyos_detail` (the caller's contract), whose first field is the
    // `uint32_t` size.
    let size = unsafe { detail.cast::<u32>().read() };
    if size < size_of_u32::<Detail>() {
        return;
    }
    let written = Detail {
        size,
        reserved: 0,
        code: failure.code,
        value: failure.value,
    };
    // SAFETY: as above; the caller's struct is at least this version's.
    unsafe { detail.write(written) };
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
            drop_payload(payload);
            UNKNOWN_CODE.as_ptr()
        }
    }
}

/// Fills `options` with the defaults: no directory, `KARYOS_IDLE_YIELD`,
/// the default timeout and bounds, and `size`.
///
/// Returns `KARYOS_OK`, or `KARYOS_E_INVALID_ARGUMENT` for a null or
/// misaligned pointer.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_client_options`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_options_init(options: *mut ClientOptions) -> i32 {
    guard(|| {
        if !writable(options) {
            return Status::InvalidArgument;
        }
        let defaults = client::Options::defaults();
        let filled = ClientOptions {
            size: size_of_u32::<ClientOptions>(),
            idle_strategy: defaults.idle_strategy,
            dir: core::ptr::null(),
            idle_sleep_ns: defaults.idle_sleep_ns,
            timeout_ns: defaults.timeout_ns,
            max_pending: defaults.max_pending,
            max_images: defaults.max_images,
        };
        // SAFETY: `options` is non-null and aligned, and the caller's
        // contract makes it a writable `karyos_client_options`.
        unsafe { options.write(filled) };
        Status::Ok
    })
}

/// Attaches a client to the driver whose admission socket is in
/// `options->dir`, and writes its handle through `client`. The options
/// are copied; nothing the caller passes is kept or consumed.
///
/// On failure nothing is opened, and `detail`, when not null and its
/// `size` covers `karyos_detail`, receives the failure's detail:
/// `KARYOS_E_INCOMPATIBLE_DRIVER` carries the driver's protocol version
/// in `value` when it admitted the client at another one (0 when it
/// refused it), `KARYOS_E_REFUSED` and `KARYOS_E_ADMISSION_REFUSED` the
/// driver's code. `KARYOS_E_UNSUPPORTED` on platforms without a
/// cross-process client (not Linux).
///
/// # Safety
///
/// `options` points to a readable `karyos_client_options` whose `size` is
/// set, and its `dir` is null or a NUL-terminated string; `client` points
/// to a writable `uint64_t`; `detail` is null or points to a writable
/// `karyos_detail` whose `size` is set. A null or misaligned `options` or
/// `client` returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_connect(
    options: *const ClientOptions,
    client: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !(readable(options) && writable(client)) {
            return Status::InvalidArgument;
        }
        // SAFETY: `options` is non-null and aligned, and points to a
        // `karyos_client_options` (the caller's contract), whose first
        // field is the `uint32_t` size.
        let size = unsafe { options.cast::<u32>().read() };
        if size < size_of_u32::<ClientOptions>() {
            return Status::InvalidArgument;
        }
        // SAFETY: as above; its size covers this version's struct.
        let raw = unsafe { options.read() };
        let dir = if raw.dir.is_null() {
            None
        } else {
            // SAFETY: a non-null `dir` is NUL-terminated (the caller's
            // contract) and only read here, while the call lasts.
            let dir = unsafe { CStr::from_ptr(raw.dir) };
            match dir.to_str() {
                Ok(dir) => Some(PathBuf::from(dir)),
                Err(_) => return Status::InvalidArgument,
            }
        };
        let options = client::Options {
            dir,
            idle_strategy: raw.idle_strategy,
            idle_sleep_ns: raw.idle_sleep_ns,
            timeout_ns: raw.timeout_ns,
            max_pending: raw.max_pending,
            max_images: raw.max_images,
        };
        match client::connect(&options) {
            Ok(handle) => {
                // SAFETY: `client` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { client.write(handle.raw()) };
                Status::Ok
            }
            Err(failure) => {
                // SAFETY: the caller's contract on `detail`.
                unsafe { write_detail(detail, failure) };
                failure.status
            }
        }
    })
}

/// Serves `client` once without waiting: completions, driver events, the
/// images of network subscriptions. Writes 1 through `served` when
/// anything was served, else 0. Call it regularly.
///
/// # Safety
///
/// `served` points to a writable `uint32_t`; null or misaligned returns
/// `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_poll(client: u64, served: *mut u32) -> i32 {
    guard(|| {
        if !writable(served) {
            return Status::InvalidArgument;
        }
        match client::poll(Handle::from_raw(client)) {
            Ok(any) => {
                // SAFETY: `served` is non-null and aligned, and the
                // caller's contract makes it a writable `uint32_t`.
                unsafe { served.write(u32::from(any)) };
                Status::Ok
            }
            Err(status) => status,
        }
    })
}

/// Closes `client`; the driver releases what it granted it. A closed
/// handle answers `KARYOS_E_CLOSED`, a handle in use `KARYOS_E_BUSY` or
/// `KARYOS_E_REENTRANT` (nothing is closed then).
#[unsafe(no_mangle)]
pub extern "C" fn karyos_client_close(client: u64) -> i32 {
    guard(|| match client::close(Handle::from_raw(client)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

#[cfg(test)]
mod tests;
