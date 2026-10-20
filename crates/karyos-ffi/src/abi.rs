// SPDX-License-Identifier: Apache-2.0

//! The boundary: every exported symbol, and the only `unsafe` of the crate
//! (SPEC.md §10.2; ADR-0053). Each function catches unwinding, checks each
//! pointer (null, alignment) before any use and hands safe values to the
//! safe modules. `include/karyos.h` declares every symbol; a test checks
//! the two agree.

use core::ffi::{CStr, c_char, c_void};
use std::panic::catch_unwind;
use std::path::PathBuf;

use crate::api;
use crate::api::client;
use crate::api::driver;
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

/// The size of `karyos_client_options` in ABI 0.1.0: the smallest a
/// caller built against any 0.y header passes. A later minor version adds
/// fields after it, and an older caller's smaller struct still connects,
/// with the defaults for what it lacks (SPEC.md §13, ABI compatibility).
const CLIENT_OPTIONS_SIZE_0_1: u32 = 40;
/// The size of `karyos_detail` in ABI 0.1.0, likewise.
const DETAIL_SIZE_0_1: u32 = 24;

/// The size of `T` as the `size` field states it.
fn size_of_u32<T>() -> u32 {
    u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
}

/// `karyos_accepted`: where an accepted message went.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Accepted {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// The lane the message was appended to.
    pub lane: u32,
    /// The message's position in that lane.
    pub position: u64,
}

/// The size of `karyos_accepted` in ABI 0.1.0.
const ACCEPTED_SIZE_0_1: u32 = 16;

/// Writes the value `fill` builds from the caller's `size` through `out`,
/// a caller's growing struct, when it is aligned and its `size` is at
/// least `min` (the struct's size in ABI 0.1.0): the prefix both versions
/// know, so an older caller's smaller struct gets its fields and a newer
/// one's later fields are left alone. Otherwise writes nothing.
///
/// # Safety
///
/// `out` is null or points to a writable struct whose first field is the
/// `uint32_t` size the caller set, and which is at least that size.
unsafe fn write_sized<T>(out: *mut T, min: u32, fill: impl FnOnce(u32) -> T) {
    if !writable(out) {
        return;
    }
    // SAFETY: `out` is non-null and aligned, and points to the caller's
    // struct (its contract), whose first field is the `uint32_t` size.
    let size = unsafe { out.cast::<u32>().read() };
    if size < min {
        return;
    }
    let written = fill(size);
    let length = prefix(size, size_of_u32::<T>());
    // SAFETY: the caller's struct is at least `size` writable bytes (its
    // contract), `length` is at most `size` and at most the size of
    // `written`, a local that does not overlap it.
    unsafe {
        core::ptr::copy_nonoverlapping((&raw const written).cast::<u8>(), out.cast::<u8>(), length);
    };
}

/// Writes `failure`'s detail through `detail` (see [`write_sized`]).
///
/// # Safety
///
/// As [`write_sized`].
unsafe fn write_detail(detail: *mut Detail, failure: Failure) {
    // SAFETY: the caller's contract, passed on.
    unsafe {
        write_sized(detail, DETAIL_SIZE_0_1, |size| Detail {
            size,
            reserved: 0,
            code: failure.code,
            value: failure.value,
        });
    };
}

/// Writes `accepted` through `out` (see [`write_sized`]).
///
/// # Safety
///
/// As [`write_sized`].
unsafe fn write_accepted(out: *mut Accepted, placed: api::publication::Placed) {
    // SAFETY: the caller's contract, passed on.
    unsafe {
        write_sized(out, ACCEPTED_SIZE_0_1, |size| Accepted {
            size,
            lane: u32::from(placed.lane.get()),
            position: placed.position,
        });
    };
}

/// A NUL-terminated UTF-8 string the caller passes, read during the call.
///
/// # Safety
///
/// `text` is null or a NUL-terminated string that lives through the call.
unsafe fn read_str<'a>(text: *const c_char) -> Result<&'a str, Status> {
    if text.is_null() {
        return Err(Status::InvalidArgument);
    }
    // SAFETY: non-null and NUL-terminated (the caller's contract), and
    // used only during the call.
    let text = unsafe { CStr::from_ptr(text) };
    text.to_str().map_err(|_| Status::InvalidArgument)
}

/// The bytes of a growing struct both sides know: the smaller of the
/// caller's `size` and this version's.
fn prefix(size: u32, ours: u32) -> usize {
    usize::try_from(size.min(ours)).unwrap_or(0)
}

/// Reads a growing struct the caller passes at `input`: the prefix both
/// versions know copied over `defaults`, so the fields an older caller's
/// struct lacks keep their defaults.
///
/// # Errors
///
/// [`Status::InvalidArgument`] for a null or misaligned `input`, or a
/// `size` below `min`.
///
/// # Safety
///
/// `input` is null or points to a readable struct whose first field is
/// the `uint32_t` size the caller set, and which is at least that size.
/// `T` must be valid for every bit pattern (integers and raw pointers
/// only: no `bool`, enum or reference), since its bytes come from the
/// caller: `DriverOptions` and `StreamOptions` are.
unsafe fn read_sized<T: Copy>(input: *const T, min: u32, defaults: T) -> Result<T, Status> {
    if !readable(input) {
        return Err(Status::InvalidArgument);
    }
    // SAFETY: `input` is non-null and aligned, and points to the caller's
    // struct (its contract), whose first field is the `uint32_t` size.
    let size = unsafe { input.cast::<u32>().read() };
    if size < min {
        return Err(Status::InvalidArgument);
    }
    let mut read = defaults;
    let length = prefix(size, size_of_u32::<T>());
    // SAFETY: the caller's struct is at least `size` readable bytes (its
    // contract), `length` is at most `size` and at most the size of
    // `read`, a local that does not overlap it.
    unsafe {
        core::ptr::copy_nonoverlapping(input.cast::<u8>(), (&raw mut read).cast::<u8>(), length);
    };
    Ok(read)
}

/// `karyos_client_options` with the defaults and this version's size.
fn default_options() -> ClientOptions {
    let defaults = client::Options::defaults();
    ClientOptions {
        size: size_of_u32::<ClientOptions>(),
        idle_strategy: defaults.idle_strategy,
        dir: core::ptr::null(),
        idle_sleep_ns: defaults.idle_sleep_ns,
        timeout_ns: defaults.timeout_ns,
        max_pending: defaults.max_pending,
        max_images: defaults.max_images,
    }
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
        let filled = default_options();
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
        if size < CLIENT_OPTIONS_SIZE_0_1 {
            return Status::InvalidArgument;
        }
        // Fields an older caller's struct lacks keep their defaults.
        let mut raw = default_options();
        let length = prefix(size, size_of_u32::<ClientOptions>());
        // SAFETY: the caller's struct is at least `size` readable bytes
        // (its contract), `length` is at most `size` and at most the size
        // of `raw`, a local that does not overlap it; every field of 0.1.0
        // lies within it (`size` is at least that version's), so `dir` is
        // copied whole.
        unsafe {
            core::ptr::copy_nonoverlapping(
                options.cast::<u8>(),
                (&raw mut raw).cast::<u8>(),
                length,
            );
        };
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

/// Adds the exclusive publication of `stream_id` on the channel `uri`
/// (`karyos:ipc` or `karyos:udp`) to `client`, and writes its handle
/// through `publication`. A control call: it waits for the driver up to
/// the client's timeout, and holds the client handle meanwhile
/// (`KARYOS_E_BUSY` to another thread). On failure nothing is opened and
/// `detail` (may be null) receives the failure's detail.
///
/// # Safety
///
/// `uri` is a NUL-terminated string; `publication` points to a writable
/// `uint64_t`; `detail` is null or a `karyos_detail` whose `size` is set.
/// A null `uri` or `publication` returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_add_publication(
    client: u64,
    uri: *const c_char,
    stream_id: i32,
    publication: *mut u64,
    detail: *mut Detail,
) -> i32 {
    // SAFETY: the caller's contract, passed on.
    guard(|| unsafe { add_publication(client, uri, stream_id, false, publication, detail) })
}

/// Adds a concurrent publication handle of `stream_id` on the channel
/// `uri` to `client`, and writes its handle through `publication`. The
/// stream must be a `karyos:ipc` stream the driver configures for
/// concurrent publishers; the handle has lane 0 only, and the offer and
/// claim calls of an exclusive publication apply to it. A control call,
/// as `karyos_client_add_publication`; on failure nothing is opened and
/// `detail` (may be null) receives the failure's detail.
///
/// # Safety
///
/// As `karyos_client_add_publication`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_add_concurrent_publication(
    client: u64,
    uri: *const c_char,
    stream_id: i32,
    publication: *mut u64,
    detail: *mut Detail,
) -> i32 {
    // SAFETY: the caller's contract, passed on.
    guard(|| unsafe { add_publication(client, uri, stream_id, true, publication, detail) })
}

/// The body of both add calls.
///
/// # Safety
///
/// As `karyos_client_add_publication`.
unsafe fn add_publication(
    client: u64,
    uri: *const c_char,
    stream_id: i32,
    concurrent: bool,
    publication: *mut u64,
    detail: *mut Detail,
) -> Status {
    if !writable(publication) {
        return Status::InvalidArgument;
    }
    // SAFETY: the caller's contract on `uri`.
    let uri = match unsafe { read_str(uri) } {
        Ok(uri) => uri,
        Err(status) => return status,
    };
    match api::publication::add(Handle::from_raw(client), uri, stream_id, concurrent) {
        Ok(handle) => {
            // SAFETY: `publication` is non-null and aligned, and the
            // caller's contract makes it a writable `uint64_t`.
            unsafe { publication.write(handle.raw()) };
            Status::Ok
        }
        Err(failure) => {
            // SAFETY: the caller's contract on `detail`.
            unsafe { write_detail(detail, failure) };
            failure.status
        }
    }
}

/// Offers `length` bytes at `data` on `lane` of `publication`, copied into
/// the term before it returns. On `KARYOS_OK`, `accepted` (may be null)
/// receives the lane and position. A data-path call: it never waits.
///
/// # Safety
///
/// `data` points to `length` readable bytes (it may be null when `length`
/// is 0); `accepted` is null or a `karyos_accepted` whose `size` is set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_publication_offer(
    publication: u64,
    lane: u32,
    data: *const u8,
    length: usize,
    accepted: *mut Accepted,
) -> i32 {
    guard(|| {
        let payload: &[u8] = if length == 0 {
            &[]
        } else if data.is_null() || isize::try_from(length).is_err() {
            return Status::InvalidArgument;
        } else {
            // SAFETY: `data` is non-null and points to `length` readable
            // bytes (the caller's contract), `length` fits an `isize`, and
            // the slice is used only during the call.
            unsafe { core::slice::from_raw_parts(data, length) }
        };
        match api::publication::offer(Handle::from_raw(publication), lane, payload) {
            Ok(done) => {
                // SAFETY: the caller's contract on `accepted`.
                unsafe { write_accepted(accepted, done) };
                Status::Ok
            }
            Err(failure) => failure.status,
        }
    })
}

/// Offers `length` bytes at `data` on the timed `lane` of `publication`,
/// with its requested not-before time `tx_time` in the lane's clock domain
/// (`karyos_clock_now` reads it), copied into the term before it returns.
/// The lane's handle checks the time first, before anything is reserved;
/// on a network route the driver's sender holds the message until its
/// time. On `KARYOS_OK`, `accepted` (may be null) receives the lane and
/// position. A data-path call: it never waits.
///
/// # Safety
///
/// As [`karyos_publication_offer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_publication_offer_at(
    publication: u64,
    lane: u32,
    data: *const u8,
    length: usize,
    tx_time: u64,
    accepted: *mut Accepted,
) -> i32 {
    guard(|| {
        let payload: &[u8] = if length == 0 {
            &[]
        } else if data.is_null() || isize::try_from(length).is_err() {
            return Status::InvalidArgument;
        } else {
            // SAFETY: `data` is non-null and points to `length` readable
            // bytes (the caller's contract), `length` fits an `isize`, and
            // the slice is used only during the call.
            unsafe { core::slice::from_raw_parts(data, length) }
        };
        match api::publication::offer_at(Handle::from_raw(publication), lane, payload, tx_time) {
            Ok(done) => {
                // SAFETY: the caller's contract on `accepted`.
                unsafe { write_accepted(accepted, done) };
                Status::Ok
            }
            Err(failure) => failure.status,
        }
    })
}

/// `KARYOS_CLOCK_MONOTONIC`: the host's monotonic clock, a timed lane's
/// default domain.
pub(crate) const CLOCK_MONOTONIC: u32 = 0;
/// `KARYOS_CLOCK_TAI`: the host's `CLOCK_TAI`, Linux only.
pub(crate) const CLOCK_TAI: u32 = 1;

/// Writes the current time of `domain` (`KARYOS_CLOCK_*`) through `now`:
/// the time `karyos_publication_offer_at` expects for a lane of that
/// domain. Callers use it on every platform rather than read the clocks
/// themselves: on Linux it equals `CLOCK_MONOTONIC` or `CLOCK_TAI`, but on
/// macOS the monotonic domain has a per-process origin, so a value means
/// something only within this process (an embedded driver). A data-path
/// call: it never waits and takes no handle.
///
/// # Safety
///
/// `now` points to a writable `uint64_t`; null or misaligned returns
/// `KARYOS_E_INVALID_ARGUMENT`, as does an unknown domain, and nothing is
/// written then. A domain this platform cannot read returns
/// `KARYOS_E_UNSUPPORTED`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_clock_now(domain: u32, now: *mut u64) -> i32 {
    guard(|| {
        if !writable(now) {
            return Status::InvalidArgument;
        }
        match api::clock::now(domain) {
            Ok(time) => {
                // SAFETY: `now` is non-null and aligned, and the caller's
                // contract makes it a writable `uint64_t`.
                unsafe { now.write(time) };
                Status::Ok
            }
            Err(failure) => failure.status,
        }
    })
}

/// Stages a claim of `length` bytes on `lane` of `publication`: writes its
/// handle through `claim` and, through `buffer`, a pointer to `length`
/// zeroed bytes the caller fills. The pointer stays valid until
/// `karyos_claim_commit` releases the claim, `karyos_claim_abort`, or the
/// close of the publication or of its client; it never points into a term
/// or a shared mapping.
/// One claim per publication: another before it is released returns
/// `KARYOS_E_CLAIM_OUTSTANDING`. Nothing reaches the term before the
/// commit.
///
/// # Safety
///
/// `claim` points to a writable `uint64_t` and `buffer` to a writable
/// `uint8_t *`; a null or misaligned one returns
/// `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_publication_claim(
    publication: u64,
    lane: u32,
    length: u32,
    claim: *mut u64,
    buffer: *mut *mut u8,
) -> i32 {
    guard(|| {
        if !(writable(claim) && writable(buffer)) {
            return Status::InvalidArgument;
        }
        match api::publication::claim(Handle::from_raw(publication), lane, length) {
            Ok((handle, staged)) => {
                // SAFETY: `claim` is non-null and aligned, and the caller's
                // contract makes it a writable `uint64_t`.
                unsafe { claim.write(handle.raw()) };
                // SAFETY: as for `claim`, a writable `uint8_t *`.
                unsafe { buffer.write(staged) };
                Status::Ok
            }
            Err(failure) => failure.status,
        }
    })
}

/// Commits `claim`: claims `length` in the term, copies the staged bytes
/// and commits, in one call. On `KARYOS_OK`, `accepted` (may be null)
/// receives the lane and position, and the claim is released. A data-path
/// outcome that can clear (`KARYOS_E_BACK_PRESSURED`,
/// `KARYOS_E_NOT_CONNECTED`, `KARYOS_E_ADMIN_ACTION`,
/// `KARYOS_E_RATE_LIMITED`, `KARYOS_E_GATED`) keeps the claim staged and
/// its buffer valid, to retry or abort; any other failure releases it.
///
/// # Safety
///
/// `accepted` is null or a `karyos_accepted` whose `size` is set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_claim_commit(claim: u64, accepted: *mut Accepted) -> i32 {
    guard(|| match api::publication::commit(Handle::from_raw(claim)) {
        Ok(done) => {
            // SAFETY: the caller's contract on `accepted`.
            unsafe { write_accepted(accepted, done) };
            Status::Ok
        }
        Err(failure) => failure.status,
    })
}

/// Aborts `claim`: nothing reaches the term, and its buffer is released.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_claim_abort(claim: u64) -> i32 {
    guard(|| match api::publication::abort(Handle::from_raw(claim)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

/// Closes `publication` through its client, with its outstanding claim.
/// It needs the client handle too: while that is in use
/// (`KARYOS_E_BUSY`, `KARYOS_E_REENTRANT`) nothing is closed.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_publication_close(publication: u64) -> i32 {
    guard(
        || match api::publication::close(Handle::from_raw(publication)) {
            Ok(()) => Status::Ok,
            Err(status) => status,
        },
    )
}

// The outcome streams of guarded publications (F7a-2; quantstratum-docs:
// karyos/design/ffi-gap-analysis.md §6, guards-and-abort.md G5).

/// `KARYOS_OUTCOME_SUBMITTED`: handed to the backend under an open guard.
pub(crate) const OUTCOME_SUBMITTED: u32 = 1;
/// `KARYOS_OUTCOME_CONFIRMED_CANCELLED`: a pending backend operation whose
/// cancellation the backend established.
pub(crate) const OUTCOME_CONFIRMED_CANCELLED: u32 = 2;
/// `KARYOS_OUTCOME_UNKNOWN`: the backend could not establish whether the
/// operation was handed off.
pub(crate) const OUTCOME_UNKNOWN: u32 = 3;
/// `KARYOS_OUTCOME_REJECTED`: refused at the gate under a closed or changed
/// guard.
pub(crate) const OUTCOME_REJECTED: u32 = 4;
/// `KARYOS_OUTCOME_ABORTED`: aborted before submission.
pub(crate) const OUTCOME_ABORTED: u32 = 5;
/// `KARYOS_OUTCOME_RANGE`: a receiver's delivered prefix and unresolved
/// range.
pub(crate) const OUTCOME_RANGE: u32 = 16;
/// `KARYOS_OUTCOME_INTERRUPTED`: a required receiver that did not
/// acknowledge an abort.
pub(crate) const OUTCOME_INTERRUPTED: u32 = 17;
/// `KARYOS_OUTCOME_ENDED`: the summary that ends an incarnation's records.
pub(crate) const OUTCOME_ENDED: u32 = 18;
/// `KARYOS_OUTCOME_OUTCOMES_LOST`: the final record of a faulted client.
pub(crate) const OUTCOME_OUTCOMES_LOST: u32 = 19;

/// `karyos_outcome`: one outcome record, handed to the handler for the
/// call only. `size` is this version's `sizeof(karyos_outcome)`: a handler
/// built against an older header reads only the fields it knows.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Outcome {
    /// The struct's size in bytes, set by the library.
    pub size: u32,
    /// A `KARYOS_OUTCOME_*` kind; a newer library may add kinds.
    pub kind: u32,
    /// The lane, 0 to 3.
    pub lane: u32,
    /// The receiver index, for range kinds; 0 otherwise.
    pub receiver: u32,
    /// The record's sequence.
    pub sequence: u64,
    /// The incarnation.
    pub incarnation: u64,
    /// Message start position, or a receiver's contiguous delivered prefix.
    pub start: u64,
    /// Message end position, or the unresolved range end.
    pub end: u64,
    /// The guard epoch at the decision, or of the abort.
    pub epoch: u64,
    /// The reason, for rejected, aborted and range kinds.
    pub reason: u64,
    /// The lost count, for `KARYOS_OUTCOME_OUTCOMES_LOST` only.
    pub lost: u64,
}

/// `karyos_outcome_handler`: called once per record with the caller's
/// `context` and the record, valid only during the call. It must return
/// normally.
pub type OutcomeHandler = Option<unsafe extern "C" fn(*mut c_void, *const Outcome)>;

/// The `KARYOS_OUTCOME_*` code of `kind`.
fn outcome_kind(kind: karyos_sys::outcome_ring::Kind) -> u32 {
    use karyos_sys::outcome_ring::Kind;
    match kind {
        Kind::Submitted => OUTCOME_SUBMITTED,
        Kind::ConfirmedCancelled => OUTCOME_CONFIRMED_CANCELLED,
        Kind::Unknown => OUTCOME_UNKNOWN,
        Kind::Rejected => OUTCOME_REJECTED,
        Kind::Aborted => OUTCOME_ABORTED,
        Kind::Range => OUTCOME_RANGE,
        Kind::Interrupted => OUTCOME_INTERRUPTED,
        Kind::Ended => OUTCOME_ENDED,
        Kind::OutcomesLost => OUTCOME_OUTCOMES_LOST,
    }
}

/// `record`, of `sequence`, as the C ABI hands it to a handler.
fn outcome(sequence: u64, record: &karyos_sys::outcome_ring::Record) -> Outcome {
    Outcome {
        size: size_of_u32::<Outcome>(),
        kind: outcome_kind(record.kind),
        lane: u32::from(record.lane),
        receiver: u32::from(record.receiver),
        sequence,
        incarnation: record.incarnation,
        start: record.start,
        end: record.end,
        epoch: record.epoch,
        reason: record.reason,
        lost: record.lost,
    }
}

/// Delivers at most `limit` outcome records of `lane` of `publication` to
/// `handler`, in sequence order, and writes how many through `delivered`
/// (may be null), also on failure: a failed poll's status follows the
/// records delivered before it. A `limit` of 0 delivers nothing. A
/// data-path call: it never waits and never allocates.
///
/// A lane that is not guarded has no records: 0 with `KARYOS_OK`, as has
/// lane 0 of a concurrent handle, which is never guarded; a lane the
/// publication does not configure returns `KARYOS_E_INVALID_LANE`. After
/// the driver's final `KARYOS_OUTCOME_OUTCOMES_LOST` record the stream has
/// ended: later polls deliver 0 with `KARYOS_OK`, and offers and claims
/// return `KARYOS_E_OUTCOMES_LOST`. The handler runs while the publication
/// is held: from it, offering, claiming, polling or closing this
/// publication, or closing its client, returns `KARYOS_E_REENTRANT`.
///
/// A binding stops a poll after a failed handler with the bounded poll of
/// ADR-0067: a `limit` of 1 in a loop, and no call after the failure. The
/// failed record is consumed; the ones after it stay undelivered.
///
/// # Safety
///
/// `handler` is null or a function of the `karyos_outcome_handler`
/// signature that returns normally; `context` is passed to it untouched;
/// `delivered` is null or points to a writable `uint32_t`. A null
/// `handler` returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_publication_poll_outcomes(
    publication: u64,
    lane: u32,
    handler: OutcomeHandler,
    context: *mut c_void,
    limit: u32,
    delivered: *mut u32,
) -> i32 {
    guard(|| {
        let Some(handler) = handler else {
            return Status::InvalidArgument;
        };
        if !delivered.is_null() && !delivered.is_aligned() {
            return Status::InvalidArgument;
        }
        let mut call = |sequence: u64, record: &karyos_sys::outcome_ring::Record| {
            let outcome = outcome(sequence, record);
            // SAFETY: `handler` has the handler's signature and returns
            // normally (the caller's contract); `outcome` outlives the
            // call, which only reads it.
            unsafe { handler(context, &raw const outcome) };
        };
        let (status, count) =
            match api::outcomes::poll(Handle::from_raw(publication), lane, limit, &mut call) {
                Ok(count) => (Status::Ok, count),
                Err((failure, count)) => (failure.status, count),
            };
        if !delivered.is_null() {
            // SAFETY: `delivered` is non-null and aligned, and the caller's
            // contract makes it a writable `uint32_t`.
            unsafe { delivered.write(count) };
        }
        status
    })
}

// Subscriptions and their poll (F4; quantstratum-docs:
// karyos/design/ffi-gap-analysis.md §4.4, ADR-0067).

/// `KARYOS_MESSAGE_END_OF_STREAM`: the message ends its stream.
pub(crate) const MESSAGE_END_OF_STREAM: u32 = 1;
/// `KARYOS_MESSAGE_TRACED`: the message carries a trace extension.
pub(crate) const MESSAGE_TRACED: u32 = 2;

/// `karyos_message_info`: what the poll knows of a message, handed to the
/// handler for the call only. `size` is this version's
/// `sizeof(karyos_message_info)`: a handler built against an older header
/// reads only the fields it knows.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MessageInfo {
    /// The struct's size in bytes, set by the library.
    pub size: u32,
    /// The message's lane.
    pub lane: u32,
    /// The message's stream position.
    pub position: u64,
    /// The publisher's reserved value.
    pub reserved_value: i64,
    /// The bytes from the message to the next one.
    pub extent: u32,
    /// The image's session id; the stream's for a `karyos:ipc` one.
    pub session_id: i32,
    /// `KARYOS_MESSAGE_*` bits.
    pub flags: u32,
    /// Zero.
    pub reserved: u32,
}

/// `karyos_image_change`: an image of a network subscription attached or
/// retired.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageChange {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// The image's session id.
    pub session_id: i32,
    /// The image's attach id.
    pub image_id: u64,
    /// The image's lane.
    pub lane: u32,
    /// 1 when it was attached, 0 when it was retired.
    pub available: u32,
}

/// The size of `karyos_image_change` in ABI 0.1.0.
const IMAGE_CHANGE_SIZE_0_1: u32 = 24;

/// `karyos_message_handler`: called once per message with the caller's
/// `context`, the message's `length` bytes at `data` (a private copy, valid
/// only during the call) and its `info`. It must return normally.
pub type MessageHandler =
    Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *const MessageInfo)>;

/// `info` as the C ABI hands it to a handler.
fn message_info(info: &karyos_client::MessageInfo) -> MessageInfo {
    let mut flags = 0;
    if info.end_of_stream {
        flags |= MESSAGE_END_OF_STREAM;
    }
    if info.extension.is_some() {
        flags |= MESSAGE_TRACED;
    }
    MessageInfo {
        size: size_of_u32::<MessageInfo>(),
        lane: u32::from(info.lane.get()),
        position: info.position,
        reserved_value: info.reserved_value,
        extent: info.extent,
        session_id: info.session_id,
        flags,
        reserved: 0,
    }
}

/// Adds the subscription of `stream_id` on the channel `uri` (`karyos:ipc`
/// or `karyos:udp`) to `client`, with its private copy buffer, and writes
/// its handle through `subscription`. A control call: it waits for the
/// driver up to the client's timeout, and holds the client handle
/// meanwhile (`KARYOS_E_BUSY` to another thread). On failure nothing is
/// opened and `detail` (may be null) receives the failure's detail.
///
/// # Safety
///
/// `uri` is a NUL-terminated string; `subscription` points to a writable
/// `uint64_t`; `detail` is null or a `karyos_detail` whose `size` is set.
/// A null `uri` or `subscription` returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_add_subscription(
    client: u64,
    uri: *const c_char,
    stream_id: i32,
    subscription: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(subscription) {
            return Status::InvalidArgument;
        }
        // SAFETY: the caller's contract on `uri`.
        let uri = match unsafe { read_str(uri) } {
            Ok(uri) => uri,
            Err(status) => return status,
        };
        match api::subscription::add(Handle::from_raw(client), uri, stream_id) {
            Ok(handle) => {
                // SAFETY: `subscription` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { subscription.write(handle.raw()) };
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

/// `KARYOS_ROLE_REQUIRED`: the reader bounds its publisher and is never
/// lapped (SPEC.md §4); the role `karyos_client_add_subscription` takes.
pub(crate) const ROLE_REQUIRED: u32 = 0;
/// `KARYOS_ROLE_OPTIONAL`: the reader does not bound its publisher and may
/// be lapped.
pub(crate) const ROLE_OPTIONAL: u32 = 1;
/// `KARYOS_ROLE_OBSERVER`: as optional, and it only copies.
pub(crate) const ROLE_OBSERVER: u32 = 2;
/// `KARYOS_REJOIN_AT_HEAD`: after an overrun, delivery continues at the
/// head; the policy `karyos_client_add_subscription` takes.
pub(crate) const REJOIN_AT_HEAD: u32 = 0;
/// `KARYOS_REJOIN_CLOSE`: an overrun closes the subscription, whose polls
/// then return `KARYOS_E_CLOSED_BY_OVERRUN`.
pub(crate) const REJOIN_CLOSE: u32 = 1;

/// `karyos_subscription_options`: a subscription's role and rejoin policy
/// (`quantstratum-docs: karyos/design/rejoin-policies.md`), read by
/// `karyos_client_add_subscription_with`. Only integers: the library reads
/// it by prefix from the caller's bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubscriptionOptions {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// `KARYOS_ROLE_*`.
    pub role: u32,
    /// `KARYOS_REJOIN_*`.
    pub rejoin: u32,
    /// Zero.
    pub reserved: u32,
}

/// The size of `karyos_subscription_options` in ABI 0.1.0, the smallest a
/// caller passes.
const SUBSCRIPTION_OPTIONS_SIZE_0_1: u32 = 16;

/// `karyos_subscription_options` with the defaults (a required reader that
/// rejoins at the head) and this version's size.
fn default_subscription_options() -> SubscriptionOptions {
    SubscriptionOptions {
        size: size_of_u32::<SubscriptionOptions>(),
        role: ROLE_REQUIRED,
        rejoin: REJOIN_AT_HEAD,
        reserved: 0,
    }
}

/// The client options of `options`: an unknown role or policy, or a
/// nonzero `reserved`, is [`Status::InvalidArgument`].
fn subscription_options(
    options: SubscriptionOptions,
) -> Result<karyos_client::SubscriptionOptions, Status> {
    use karyos_client::{RejoinPolicy, SubscriberRole};
    if options.reserved != 0 {
        return Err(Status::InvalidArgument);
    }
    let role = match options.role {
        ROLE_REQUIRED => SubscriberRole::Required,
        ROLE_OPTIONAL => SubscriberRole::Optional,
        ROLE_OBSERVER => SubscriberRole::Observer,
        _ => return Err(Status::InvalidArgument),
    };
    let rejoin = match options.rejoin {
        REJOIN_AT_HEAD => RejoinPolicy::RejoinAtHead,
        REJOIN_CLOSE => RejoinPolicy::Close,
        _ => return Err(Status::InvalidArgument),
    };
    Ok(karyos_client::SubscriptionOptions::new(role, rejoin))
}

/// Fills `options` with the defaults (`KARYOS_ROLE_REQUIRED`,
/// `KARYOS_REJOIN_AT_HEAD`) and its size.
///
/// Returns `KARYOS_OK`, or `KARYOS_E_INVALID_ARGUMENT` for a null or
/// misaligned pointer.
///
/// # Safety
///
/// `options` is null or points to a writable
/// `karyos_subscription_options`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_subscription_options_init(
    options: *mut SubscriptionOptions,
) -> i32 {
    guard(|| {
        if !writable(options) {
            return Status::InvalidArgument;
        }
        // SAFETY: `options` is non-null and aligned, and the caller's
        // contract makes it a writable `karyos_subscription_options`.
        unsafe { options.write(default_subscription_options()) };
        Status::Ok
    })
}

/// As `karyos_client_add_subscription`, with the reader's role and rejoin
/// policy from `options` (filled by `karyos_subscription_options_init`).
/// Each image of a `karyos:udp` subscription takes the role and the policy.
/// The options are copied; a struct from an older header of the same major
/// version is read by its prefix. A null `options`, a `size` below that of
/// ABI 0.1.0, an unknown role or policy, or a nonzero `reserved` returns
/// `KARYOS_E_INVALID_ARGUMENT` and opens nothing.
///
/// # Safety
///
/// As `karyos_client_add_subscription`; `options` is null or points to a
/// readable `karyos_subscription_options` of at least its `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_add_subscription_with(
    client: u64,
    uri: *const c_char,
    stream_id: i32,
    options: *const SubscriptionOptions,
    subscription: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(subscription) {
            return Status::InvalidArgument;
        }
        // SAFETY: the caller's contract on `options`; `SubscriptionOptions`
        // holds integers only, valid for every bit pattern.
        let read = unsafe {
            read_sized(
                options,
                SUBSCRIPTION_OPTIONS_SIZE_0_1,
                default_subscription_options(),
            )
        };
        let options = match read.and_then(subscription_options) {
            Ok(options) => options,
            Err(status) => return status,
        };
        // SAFETY: the caller's contract on `uri`.
        let uri = match unsafe { read_str(uri) } {
            Ok(uri) => uri,
            Err(status) => return status,
        };
        match api::subscription::add_with(Handle::from_raw(client), uri, stream_id, options) {
            Ok(handle) => {
                // SAFETY: `subscription` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { subscription.write(handle.raw()) };
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

/// Delivers at most `limit` messages of `subscription` to `handler`, each
/// copied first, and writes how many through `delivered` (may be null),
/// also on failure: a failed poll's status follows the messages delivered
/// before it. A `limit` of 0 delivers nothing. A data-path call: it never
/// waits, and allocates only when a newly adopted image or mapping has a
/// larger message than any before (`KARYOS_E_SYSTEM` when it cannot,
/// before anything of that round is delivered: the count covers earlier
/// rounds). The handler runs while the subscription
/// is held: from it, polling or closing this subscription, or closing its
/// client, returns `KARYOS_E_REENTRANT`.
///
/// A binding stops a poll after a failed handler with the bounded poll of
/// ADR-0067: a `limit` of 1 in a loop, and no call after the failure. The
/// failed message is acknowledged; the ones after it stay undelivered.
///
/// # Safety
///
/// `handler` is null or a function of the `karyos_message_handler`
/// signature that returns normally; `context` is passed to it untouched;
/// `delivered` is null or points to a writable `uint32_t`. A null
/// `handler` returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_subscription_poll(
    subscription: u64,
    handler: MessageHandler,
    context: *mut c_void,
    limit: u32,
    delivered: *mut u32,
) -> i32 {
    guard(|| {
        let Some(handler) = handler else {
            return Status::InvalidArgument;
        };
        if !delivered.is_null() && !delivered.is_aligned() {
            return Status::InvalidArgument;
        }
        let mut call = |bytes: &[u8], info: &karyos_client::MessageInfo| {
            let info = message_info(info);
            // SAFETY: `handler` has the handler's signature and returns
            // normally (the caller's contract); `bytes` and `info` outlive
            // the call, which only reads them.
            unsafe { handler(context, bytes.as_ptr(), bytes.len(), &raw const info) };
        };
        let (status, count) =
            match api::subscription::poll(Handle::from_raw(subscription), limit, &mut call) {
                Ok(count) => (Status::Ok, count),
                Err((failure, count)) => (failure.status, count),
            };
        if !delivered.is_null() {
            // SAFETY: `delivered` is non-null and aligned, and the caller's
            // contract makes it a writable `uint32_t`.
            unsafe { delivered.write(count) };
        }
        status
    })
}

/// Takes the oldest queued image change of `subscription` into `change`
/// and writes 1 through `has`, or writes 0 through `has` when none is
/// queued (a `karyos:ipc` subscription has none). The queue is bounded:
/// `karyos_subscription_image_changes_lost` counts what a full queue
/// dropped.
///
/// A null or misaligned `change` or `has`, or a `change` whose `size` is
/// below this ABI's first `karyos_image_change`, returns
/// `KARYOS_E_INVALID_ARGUMENT` and takes nothing from the queue.
///
/// # Safety
///
/// `change` points to a writable `karyos_image_change` whose `size` is set;
/// `has` points to a writable `uint32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_subscription_next_image_change(
    subscription: u64,
    change: *mut ImageChange,
    has: *mut u32,
) -> i32 {
    guard(|| {
        if !(writable(has) && writable(change)) {
            return Status::InvalidArgument;
        }
        // Checked before the change is taken, so a struct that cannot hold
        // it never loses one.
        // SAFETY: `change` is non-null and aligned, and the caller's
        // contract makes it a `karyos_image_change` whose first field is
        // the `uint32_t` size it set.
        if unsafe { change.cast::<u32>().read() } < IMAGE_CHANGE_SIZE_0_1 {
            return Status::InvalidArgument;
        }
        match api::subscription::next_image_change(Handle::from_raw(subscription)) {
            Ok(next) => {
                if let Some(next) = next {
                    // SAFETY: the caller's contract on `change`.
                    unsafe {
                        write_sized(change, IMAGE_CHANGE_SIZE_0_1, |size| ImageChange {
                            size,
                            session_id: next.session_id,
                            image_id: next.image_id,
                            lane: u32::from(next.lane.get()),
                            available: u32::from(next.available),
                        });
                    };
                }
                // SAFETY: `has` is non-null and aligned, and the caller's
                // contract makes it a writable `uint32_t`.
                unsafe { has.write(u32::from(next.is_some())) };
                Status::Ok
            }
            Err(status) => status,
        }
    })
}

/// Writes through `lost` the image changes `subscription`'s full queue
/// dropped.
///
/// # Safety
///
/// `lost` points to a writable `uint64_t`; a null or misaligned one
/// returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_subscription_image_changes_lost(
    subscription: u64,
    lost: *mut u64,
) -> i32 {
    guard(|| {
        if !writable(lost) {
            return Status::InvalidArgument;
        }
        match api::subscription::image_changes_lost(Handle::from_raw(subscription)) {
            Ok(count) => {
                // SAFETY: `lost` is non-null and aligned, and the caller's
                // contract makes it a writable `uint64_t`.
                unsafe { lost.write(count) };
                Status::Ok
            }
            Err(status) => status,
        }
    })
}

/// Closes `subscription` through its client. It needs the client handle
/// too: while that is in use (`KARYOS_E_BUSY`, `KARYOS_E_REENTRANT`)
/// nothing is closed.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_subscription_close(subscription: u64) -> i32 {
    guard(
        || match api::subscription::close(Handle::from_raw(subscription)) {
            Ok(()) => Status::Ok,
            Err(status) => status,
        },
    )
}

/// `karyos_driver_options`: an embedded driver's options, copied by
/// `karyos_driver_create`. `size` comes first; every setting it does not
/// carry is the driver's default.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverOptions {
    /// The struct's size in bytes.
    pub size: u32,
    /// Clients admitted at once.
    pub max_clients: u32,
    /// Streams configured at once.
    pub max_streams: u32,
    /// Pending requests per client.
    pub max_pending_per_client: u32,
    /// Bytes of each client's command ring, a power of two.
    pub ring_capacity: u32,
    /// Bytes of the broadcast buffer.
    pub broadcast_capacity: u32,
    /// Cells of the counters region.
    pub counters_capacity: u32,
    /// Zero; anything else is refused (a later minor may use it).
    pub reserved: u32,
    /// How often the driver advances its heartbeat, in nanoseconds.
    pub heartbeat_interval_ns: u64,
    /// How long a client's heartbeat may stay unchanged, in nanoseconds.
    pub client_liveness_timeout_ns: u64,
    /// How long a handle has to move to a successor mapping, in
    /// nanoseconds.
    pub cutover_deadline_ns: u64,
}

/// The size of `karyos_driver_options` in the first ABI version that has
/// it: the smallest a caller passes (as `CLIENT_OPTIONS_SIZE_0_1`).
const DRIVER_OPTIONS_SIZE_0_1: u32 = 56;

/// `karyos_driver_options` with the driver's defaults and this version's
/// size.
fn default_driver_options() -> DriverOptions {
    let defaults = driver::Options::defaults();
    DriverOptions {
        size: size_of_u32::<DriverOptions>(),
        max_clients: defaults.max_clients,
        max_streams: defaults.max_streams,
        max_pending_per_client: defaults.max_pending_per_client,
        ring_capacity: defaults.ring_capacity,
        broadcast_capacity: defaults.broadcast_capacity,
        counters_capacity: defaults.counters_capacity,
        reserved: 0,
        heartbeat_interval_ns: defaults.heartbeat_interval_ns,
        client_liveness_timeout_ns: defaults.client_liveness_timeout_ns,
        cutover_deadline_ns: defaults.cutover_deadline_ns,
    }
}

/// Fills `options` with the driver's defaults and `size`.
///
/// Returns `KARYOS_OK`, or `KARYOS_E_INVALID_ARGUMENT` for a null or
/// misaligned pointer.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_driver_options`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_options_init(options: *mut DriverOptions) -> i32 {
    guard(|| {
        if !writable(options) {
            return Status::InvalidArgument;
        }
        let filled = default_driver_options();
        // SAFETY: `options` is non-null and aligned, and the caller's
        // contract makes it a writable `karyos_driver_options`.
        unsafe { options.write(filled) };
        Status::Ok
    })
}

/// Creates an embedded driver, driven by its caller
/// (`karyos_driver_do_work`) until `karyos_driver_start` gives it a
/// thread, and writes its handle through `driver`. The options are copied.
///
/// On failure nothing is created, and `detail`, when not null and its
/// `size` covers `karyos_detail`, receives the failure's detail
/// (`KARYOS_E_SYSTEM`: an `errno`, or the descriptors needed in `code` and
/// the soft limit in `value`).
///
/// # Safety
///
/// `options` points to a readable `karyos_driver_options` whose `size` is
/// set; `driver` points to a writable `uint64_t`; `detail` is null or
/// points to a writable `karyos_detail` whose `size` is set. A null or
/// misaligned `options` or `driver`, or a `size` below the first
/// version's, returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_create(
    options: *const DriverOptions,
    driver: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(driver) {
            return Status::InvalidArgument;
        }
        // SAFETY: the caller's contract on `options`.
        let raw =
            match unsafe { read_sized(options, DRIVER_OPTIONS_SIZE_0_1, default_driver_options()) }
            {
                Ok(raw) => raw,
                Err(status) => return status,
            };
        // A later minor may give it a meaning: refused, not ignored.
        if raw.reserved != 0 {
            return Status::InvalidArgument;
        }
        let options = driver::Options {
            max_clients: raw.max_clients,
            max_streams: raw.max_streams,
            max_pending_per_client: raw.max_pending_per_client,
            ring_capacity: raw.ring_capacity,
            broadcast_capacity: raw.broadcast_capacity,
            counters_capacity: raw.counters_capacity,
            heartbeat_interval_ns: raw.heartbeat_interval_ns,
            client_liveness_timeout_ns: raw.client_liveness_timeout_ns,
            cutover_deadline_ns: raw.cutover_deadline_ns,
        };
        match driver::create(&options) {
            Ok(handle) => {
                // SAFETY: `driver` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { driver.write(handle.raw()) };
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

/// Runs one duty cycle of `driver` and writes its work count through
/// `work`. `KARYOS_E_BUSY` while the driver runs on its own thread.
///
/// # Safety
///
/// `work` points to a writable `uint32_t`; null or misaligned returns
/// `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_do_work(driver: u64, work: *mut u32) -> i32 {
    guard(|| {
        if !writable(work) {
            return Status::InvalidArgument;
        }
        match driver::do_work(Handle::from_raw(driver)) {
            Ok(count) => {
                // SAFETY: `work` is non-null and aligned, and the caller's
                // contract makes it a writable `uint32_t`.
                unsafe { work.write(count) };
                Status::Ok
            }
            Err(failure) => failure.status,
        }
    })
}

/// Moves `driver` to a thread of its own, which runs its duty cycle and,
/// when one did no work, idles by `idle_strategy` (`KARYOS_IDLE_*`;
/// `idle_sleep_ns` for `KARYOS_IDLE_SLEEP`) until `karyos_driver_stop` or
/// the close. `KARYOS_E_BUSY` when it already runs on one.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_driver_start(driver: u64, idle_strategy: u32, idle_sleep_ns: u64) -> i32 {
    guard(|| {
        let idle = driver::Idle {
            strategy: idle_strategy,
            sleep_ns: idle_sleep_ns,
        };
        match driver::start(Handle::from_raw(driver), idle) {
            Ok(()) => Status::Ok,
            Err(failure) => failure.status,
        }
    })
}

/// Stops `driver`'s thread and gives the driver back to its caller.
/// `KARYOS_E_BUSY` when it does not run on one; `KARYOS_E_INTERNAL` when a
/// panic on its thread poisoned it.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_driver_stop(driver: u64) -> i32 {
    guard(|| match driver::stop(Handle::from_raw(driver)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

/// `karyos_stream_options`: a stream's options, copied by
/// `karyos_driver_add_stream`: the fields of the Rust `StreamConfig` and
/// its log buffer, without conflation. `size` comes first.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StreamOptions {
    /// The struct's size in bytes.
    pub size: u32,
    /// The wire stream id.
    pub stream_id: i32,
    /// Bytes of each term, a power of two.
    pub term_length: u32,
    /// The largest frame, header included.
    pub mtu: u32,
    /// The most bytes one claim reserves.
    pub max_reserved: u32,
    /// Term slots beyond the three in use.
    pub spare_slots: u32,
    /// Subscribers at once.
    pub max_subscribers: u32,
    /// The session alias.
    pub session_id: i32,
    /// The first term's id.
    pub initial_term_id: u32,
    /// The lane; 0 in this version.
    pub lane: u32,
    /// `KARYOS_PUBLICATION_*`; exclusive in this version.
    pub publication_mode: u32,
    /// Offers allowed with no subscriber attached: 0 or 1.
    pub allow_unconnected: u32,
    /// Entries of the stream's schedule ring; 0 for none.
    pub schedule_capacity: u32,
    /// `KARYOS_LOSS_*`: what a lost required subscriber does.
    pub on_required_loss: u32,
    /// How long a claim may stay open, in nanoseconds.
    pub claim_deadline_ns: u64,
}

/// The size of `karyos_stream_options` in the first ABI version that has
/// it (as `CLIENT_OPTIONS_SIZE_0_1`).
const STREAM_OPTIONS_SIZE_0_1: u32 = 64;

/// `karyos_stream_options` with the defaults and this version's size.
fn default_stream_options() -> StreamOptions {
    let defaults = driver::StreamOptions::defaults();
    StreamOptions {
        size: size_of_u32::<StreamOptions>(),
        stream_id: defaults.stream_id,
        term_length: defaults.term_length,
        mtu: defaults.mtu,
        max_reserved: defaults.max_reserved,
        spare_slots: defaults.spare_slots,
        max_subscribers: defaults.max_subscribers,
        session_id: defaults.session_id,
        initial_term_id: defaults.initial_term_id,
        lane: defaults.lane,
        publication_mode: defaults.publication_mode,
        allow_unconnected: defaults.allow_unconnected,
        schedule_capacity: defaults.schedule_capacity,
        on_required_loss: defaults.on_required_loss,
        claim_deadline_ns: defaults.claim_deadline_ns,
    }
}

/// Fills `options` with a stream's defaults (stream id 0, the smallest
/// term) and `size`.
///
/// Returns `KARYOS_OK`, or `KARYOS_E_INVALID_ARGUMENT` for a null or
/// misaligned pointer.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_stream_options`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_stream_options_init(options: *mut StreamOptions) -> i32 {
    guard(|| {
        if !writable(options) {
            return Status::InvalidArgument;
        }
        let filled = default_stream_options();
        // SAFETY: `options` is non-null and aligned, and the caller's
        // contract makes it a writable `karyos_stream_options`.
        unsafe { options.write(filled) };
        Status::Ok
    })
}

/// Adds a stream to `driver`, which lives until
/// `karyos_driver_remove_stream` or the driver's close. The options are
/// copied. On failure nothing is added, and `detail` receives the
/// failure's detail (a duplicate stream id: `KARYOS_E_INVALID_ARGUMENT`
/// with the stream id in `code` and the session id in `value`).
///
/// # Safety
///
/// `options` points to a readable `karyos_stream_options` whose `size` is
/// set; `detail` is null or a `karyos_detail` whose `size` is set. A null
/// or misaligned `options`, or a `size` below the first version's,
/// returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_add_stream(
    driver: u64,
    options: *const StreamOptions,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        // SAFETY: the caller's contract on `options`.
        let raw =
            match unsafe { read_sized(options, STREAM_OPTIONS_SIZE_0_1, default_stream_options()) }
            {
                Ok(raw) => raw,
                Err(status) => return status,
            };
        let options = driver::StreamOptions {
            stream_id: raw.stream_id,
            term_length: raw.term_length,
            mtu: raw.mtu,
            max_reserved: raw.max_reserved,
            spare_slots: raw.spare_slots,
            max_subscribers: raw.max_subscribers,
            session_id: raw.session_id,
            initial_term_id: raw.initial_term_id,
            lane: raw.lane,
            publication_mode: raw.publication_mode,
            allow_unconnected: raw.allow_unconnected,
            schedule_capacity: raw.schedule_capacity,
            on_required_loss: raw.on_required_loss,
            claim_deadline_ns: raw.claim_deadline_ns,
        };
        match driver::add_stream(Handle::from_raw(driver), &options) {
            Ok(()) => Status::Ok,
            Err(failure) => {
                // SAFETY: the caller's contract on `detail`.
                unsafe { write_detail(detail, failure) };
                failure.status
            }
        }
    })
}

/// Removes `driver`'s stream `stream_id`: its publication closes, and its
/// subscribers read up to its seal. `KARYOS_E_INVALID_ARGUMENT` for a
/// stream id the driver does not have.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_driver_remove_stream(driver: u64, stream_id: i32) -> i32 {
    guard(
        || match driver::remove_stream(Handle::from_raw(driver), stream_id) {
            Ok(()) => Status::Ok,
            Err(failure) => failure.status,
        },
    )
}

/// Opens a client of `driver` in this process and writes its handle
/// through `client`. The client follows its driver: `KARYOS_E_INTERNAL`
/// once the driver is poisoned, `KARYOS_E_CLOSED` once it is closed.
///
/// On failure nothing is opened, and `detail` receives the failure's
/// detail as for `karyos_client_connect`.
///
/// # Safety
///
/// `client` points to a writable `uint64_t`; `detail` is null or points to
/// a writable `karyos_detail` whose `size` is set. A null or misaligned
/// `client` returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_connect(
    driver: u64,
    client: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(client) {
            return Status::InvalidArgument;
        }
        match client::connect_embedded(Handle::from_raw(driver)) {
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

/// Closes `driver`, stopping its thread first. Its clients stay open, to
/// be closed, and answer `KARYOS_E_CLOSED` meanwhile. A handle in use
/// answers `KARYOS_E_BUSY` or `KARYOS_E_REENTRANT` (nothing is closed
/// then).
#[unsafe(no_mangle)]
pub extern "C" fn karyos_driver_close(driver: u64) -> i32 {
    guard(|| match driver::close(Handle::from_raw(driver)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

#[cfg(test)]
mod tests;
