// SPDX-License-Identifier: Apache-2.0

//! The boundary: every exported symbol, and the only `unsafe` of the crate
//! (SPEC.md §10.2; ADR-0053). Each function catches unwinding, checks each
//! pointer (null, alignment) before any use and hands safe values to the
//! safe modules. `include/karyos.h` declares every symbol; a test checks
//! the two agree. The test kit's fault hook (`test_hooks`, feature
//! `test-hooks`) is declared apart, in `include/karyos_test_hooks.h`.

use core::ffi::{CStr, c_char, c_void};
use std::panic::catch_unwind;
use std::path::PathBuf;

use crate::api;

/// The conformance test kit's fault hook, never in a product build.
#[cfg(feature = "test-hooks")]
mod test_hooks;
use crate::api::client;
use crate::api::driver;
use crate::boundary::{drop_payload, guard};
use crate::handles::Handle;
use crate::status::{Failure, Status, UNKNOWN_CODE};

/// The ABI version's major number (`KARYOS_ABI_VERSION_MAJOR`), from its
/// single source in `karyos-protocol` (karyos#729); the header test checks
/// the header's.
pub(crate) const ABI_VERSION_MAJOR: u32 = karyos_protocol::versions::C_ABI_MAJOR;
/// The ABI version's minor number (`KARYOS_ABI_VERSION_MINOR`).
pub(crate) const ABI_VERSION_MINOR: u32 = karyos_protocol::versions::C_ABI_MINOR;
/// The ABI version's patch number (`KARYOS_ABI_VERSION_PATCH`).
pub(crate) const ABI_VERSION_PATCH: u32 = karyos_protocol::versions::C_ABI_PATCH;

/// Whether `out` can take a `T`: not null and aligned. It cannot tell a
/// dangling pointer; the caller's contract excludes one.
fn writable<T>(out: *mut T) -> bool {
    !out.is_null() && out.is_aligned()
}

/// Whether `input` can give a `T`: not null and aligned.
fn readable<T>(input: *const T) -> bool {
    !input.is_null() && input.is_aligned()
}

/// Whether `sized` can be a caller's growing struct: not null, and aligned
/// for its leading `uint32_t` size. Its other bytes are copied bytewise,
/// so the struct need not have this version's alignment: an older
/// header's struct may have a smaller one (the first
/// `karyos_subscription_options` is four `uint32_t`, aligned to 4).
fn sized_struct<T>(sized: *const T) -> bool {
    !sized.is_null() && sized.cast::<u32>().is_aligned()
}

/// A client's options, copied by karyos_client_connect. Fill it with
/// karyos_client_options_init, which sets size and the defaults, then set
/// dir. Zero timeout_ns, max_pending or max_images are invalid. A struct
/// from an older header of the same major version is accepted: the fields
/// it lacks take their defaults. A size below that of ABI 0.1.0 is
/// KARYOS_E_INVALID_ARGUMENT.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    /// The struct's size in bytes.
    pub size: u32,
    /// KARYOS_IDLE_BUSY_SPIN, KARYOS_IDLE_YIELD, KARYOS_IDLE_SLEEP or
    /// KARYOS_IDLE_YIELD_THEN_SLEEP (the default).
    pub idle_strategy: u32,
    /// The driver's directory, NUL-terminated UTF-8.
    pub dir: *const c_char,
    /// The sleep of KARYOS_IDLE_SLEEP, in nanoseconds.
    pub idle_sleep_ns: u64,
    /// The longest wait of a control call, in nanoseconds.
    pub timeout_ns: u64,
    /// The most requests in flight.
    pub max_pending: u32,
    /// The most images a network subscription attaches.
    pub max_images: u32,
}

/// What a failed control call adds to its status. The caller sets size to
/// sizeof(karyos_detail) of the header it was built with; the library
/// writes the fields both versions know. A size below that of ABI 0.1.0,
/// or a null pointer, receives nothing. Untouched on success.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Detail {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// Zero.
    pub reserved: u32,
    /// A code the status defines, such as the driver's refusal code (with
    /// KARYOS_E_REFUSED, possibly a code this header does not list).
    pub code: u64,
    /// A value the status defines, such as a length, a version or errno.
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

/// A legacy `_init`: `init` called with the 0.1.0 `size` as the `size_t`
/// the sized inits take, or `KARYOS_E_UNSUPPORTED` where a `size_t`
/// cannot hold it (none of this crate's targets).
fn init_0_1(size: u32, init: impl FnOnce(usize) -> i32) -> i32 {
    usize::try_from(size).map_or(Status::Unsupported.code(), init)
}

/// Where an accepted message went. The caller sets size to
/// sizeof(karyos_accepted); the rule of karyos_detail applies.
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
    if !sized_struct(out) {
        return;
    }
    // SAFETY: `out` is non-null and aligned for its `uint32_t` size, and points to the caller's
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

/// Writes the first `min(size, size_of::<T>())` bytes of `filled` through
/// `out`, with its leading `uint32_t` size set to that length: a sized
/// `_init` (owner item 48's option A, interim). The caller's bytes past
/// the length are not touched.
///
/// Returns [`Status::InvalidArgument`], with nothing written, for a null or
/// misaligned `out` or a `size` below `min`; [`Status::Internal`], with
/// nothing written, for a `T` past what its `uint32_t` size holds (no
/// struct of this crate).
///
/// # Safety
///
/// `out` is null or points to `size` writable bytes, and `T` is a
/// `#[repr(C)]` struct whose first field is the `uint32_t` size.
unsafe fn init_sized<T>(out: *mut T, size: usize, min: u32, filled: T) -> Status {
    // A `min` no `size_t` holds is past any struct the caller has.
    if !sized_struct(out) || !usize::try_from(min).is_ok_and(|min| size >= min) {
        return Status::InvalidArgument;
    }
    let length = size.min(size_of::<T>());
    // At most this version's struct, whose size its `uint32_t` field holds.
    let Ok(written) = u32::try_from(length) else {
        return Status::Internal;
    };
    let mut filled = filled;
    // SAFETY: `filled` is a `#[repr(C)]` local whose first field is the
    // `uint32_t` size.
    unsafe { (&raw mut filled).cast::<u32>().write(written) };
    // SAFETY: the caller's struct is at least `size` writable bytes (its
    // contract), `length` is at most `size` and at most the size of
    // `filled`, a local that does not overlap it.
    unsafe {
        core::ptr::copy_nonoverlapping((&raw const filled).cast::<u8>(), out.cast::<u8>(), length);
    };
    Status::Ok
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
    if !sized_struct(input) {
        return Err(Status::InvalidArgument);
    }
    // SAFETY: `input` is non-null and aligned for its `uint32_t` size, and points to the caller's
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

/// Writes the ABI version this library implements. Returns KARYOS_OK, or
/// KARYOS_E_INVALID_ARGUMENT with nothing written when a pointer is null or
/// misaligned.
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

/// The static text of a status code; a fixed text for a code that is none.
/// Never freed.
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

/// As `karyos_client_options_init_sized` with the size of `karyos_client_options` in ABI 0.1.0, the
/// first: the symbol a binary built against an older header calls, which
/// writes no field that header lacks (owner item 48's option A, interim).
/// A caller built against this header calls the header's `static inline`
/// `karyos_client_options_init`, which passes its own `sizeof`.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_client_options` of at least that
/// size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_options_init(options: *mut ClientOptions) -> i32 {
    init_0_1(CLIENT_OPTIONS_SIZE_0_1, |size| {
        // SAFETY: the caller's contract on `options`, of at least the 0.1.0
        // size.
        unsafe { karyos_client_options_init_sized(options, size) }
    })
}

/// Fills options with the defaults and its size; the idle strategy is
/// KARYOS_IDLE_YIELD_THEN_SLEEP. KARYOS_E_INVALID_ARGUMENT for a null or
/// misaligned pointer.
///
/// # Safety
///
/// `options` is null or points to `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_options_init_sized(
    options: *mut ClientOptions,
    size: usize,
) -> i32 {
    guard(|| {
        let filled = default_options();
        // SAFETY: the caller's contract on `options` and `size`.
        unsafe { init_sized(options, size, CLIENT_OPTIONS_SIZE_0_1, filled) }
    })
}

/// Attaches a client to the driver whose admission socket is in
/// options->dir and writes its handle. The options are copied; a failed
/// connect opens nothing and fills detail (may be null).
/// KARYOS_E_INCOMPATIBLE_DRIVER carries the driver's protocol version in
/// detail->value when it admitted the client at another one, or when its
/// refusal states it; 0 when a refusing driver states none (0.1.0-alpha.2
/// and earlier). KARYOS_E_UNSUPPORTED where no cross-process client exists
/// (not Linux).
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

/// Serves the client once without waiting; writes 1 to served when
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

/// Closes the client; the driver releases what it granted it. Nothing is
/// closed when the handle is in use (KARYOS_E_BUSY, KARYOS_E_REENTRANT).
#[unsafe(no_mangle)]
pub extern "C" fn karyos_client_close(client: u64) -> i32 {
    guard(|| match client::close(Handle::from_raw(client)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

/// Adds the exclusive publication of stream_id on the channel uri
/// (karyos:ipc or karyos:udp) to the client and writes its handle. A
/// karyos:udp channel needs a driver that runs its network: an embedded
/// one created with KARYOS_NETWORK_ON, or karyosd --network on; otherwise
/// it is refused (KARYOS_E_UNSUPPORTED_CHANNEL). A
/// control call: it waits for the driver up to the client's timeout and
/// holds the client handle meanwhile. A failure opens nothing and fills
/// detail (may be null). A guarded stream's publication binds its guard
/// and outcome stream (karyos_publication_poll_outcomes) for a client of a
/// driver in another process; an embedded driver's client is refused one
/// with KARYOS_E_REFUSED, detail code 6 (invalid publication mode). A
/// karyos:udp publication whose lanes are above the driver's
/// max_stream_bytes (karyos_driver_options or karyosd --max-stream-bytes)
/// is KARYOS_E_REFUSED,
/// detail code 24 with the lane's bytes in value; no retry of the same
/// uri succeeds. A karyos:udp publication its endpoint cannot hold
/// (karyos#859) is KARYOS_E_REFUSED, detail code 4 (resources
/// unavailable), with detail.value = limit << 56 | capacity << 32 |
/// needed: limit 1 for TX slots, 2 for queues, 3 for routes; capacity the
/// endpoint's (24 bits, saturated); needed what it would take with this
/// publication. A retry can succeed once a removal on that endpoint has
/// ended, which frees its room. A channel
/// the driver does not serve (CnC code 13) is
/// KARYOS_E_UNSUPPORTED_CHANNEL, with 0 in detail.code and the driver's
/// detail in detail.value, the stream id.
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

/// Adds a concurrent publication handle of stream_id on the karyos:ipc
/// channel uri to the client and writes its handle. The driver must
/// configure the stream for concurrent publishers; the handle has lane 0
/// only, and the offer and claim calls apply to it. A control call, as
/// karyos_client_add_publication.
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

/// Offers length bytes at data on the lane, copied before it returns; data
/// may be null when length is 0. On KARYOS_OK, accepted (may be null)
/// receives the lane and position. KARYOS_E_INVALID_SCHEDULE on a timed
/// lane, which takes karyos_publication_offer_at only. Never waits.
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

/// Per-offer options of karyos_publication_offer_with. Fill it with
/// karyos_offer_options_init (reserved_value 0, what
/// karyos_publication_offer sends), then set reserved_value. The size rule
/// of karyos_driver_options applies.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OfferOptions {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// Zero; anything else is KARYOS_E_INVALID_ARGUMENT.
    pub reserved: u32,
    /// The value every fragment's header carries, which subscribers read as
    /// karyos_message_info.reserved_value. On a conflated stream it is the
    /// message's key, in 0..keys of the stream's table; see
    /// karyos_publication_offer_with.
    pub reserved_value: i64,
}

/// The size of `karyos_offer_options` in ABI 0.1.0, the smallest a caller
/// passes.
const OFFER_OPTIONS_SIZE_0_1: u32 = 16;

/// `karyos_offer_options` with the defaults (a reserved value of 0) and
/// this version's size.
fn default_offer_options() -> OfferOptions {
    OfferOptions {
        size: size_of_u32::<OfferOptions>(),
        reserved: 0,
        reserved_value: 0,
    }
}

/// As `karyos_offer_options_init_sized` with the size of `karyos_offer_options` in ABI 0.1.0, the
/// first: the symbol a binary built against an older header calls, which
/// writes no field that header lacks (owner item 48's option A, interim).
/// A caller built against this header calls the header's `static inline`
/// `karyos_offer_options_init`, which passes its own `sizeof`.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_offer_options` of at least that
/// size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_offer_options_init(options: *mut OfferOptions) -> i32 {
    init_0_1(OFFER_OPTIONS_SIZE_0_1, |size| {
        // SAFETY: the caller's contract on `options`, of at least the 0.1.0
        // size.
        unsafe { karyos_offer_options_init_sized(options, size) }
    })
}

/// Fills options with the defaults and its size. KARYOS_E_INVALID_ARGUMENT
/// for a null or misaligned pointer.
///
/// # Safety
///
/// `options` is null or points to `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_offer_options_init_sized(
    options: *mut OfferOptions,
    size: usize,
) -> i32 {
    guard(|| {
        let filled = default_offer_options();
        // SAFETY: the caller's contract on `options` and `size`.
        unsafe { init_sized(options, size, OFFER_OPTIONS_SIZE_0_1, filled) }
    })
}

/// As karyos_publication_offer, with options: the reserved value every
/// fragment's header carries. A null options, a size below that of ABI
/// 0.1.0, or a nonzero reserved returns KARYOS_E_INVALID_ARGUMENT, and a
/// timed lane KARYOS_E_INVALID_SCHEDULE.
///
/// On a conflated stream the driver is authoritative: a key outside the
/// table never enters the conflated view, and the driver counts it as a
/// rejected key. Every publication also refuses such a key, or a value
/// larger than the capacity, before it appends: KARYOS_E_CONFLATION, with
/// nothing reserved. The table's shape comes with the log buffer the
/// publication writes to, for a client of a driver in this process or in
/// another. Conflation is a view over the log, not a filter on it: an
/// appended message reaches the stream's subscribers whatever its key.
///
/// # Safety
///
/// As [`karyos_publication_offer`]; `options` is null or points to a
/// readable `karyos_offer_options` of at least its `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_publication_offer_with(
    publication: u64,
    lane: u32,
    data: *const u8,
    length: usize,
    options: *const OfferOptions,
    accepted: *mut Accepted,
) -> i32 {
    guard(|| {
        // SAFETY: the caller's contract on `options`; `OfferOptions` holds
        // integers only, valid for every bit pattern.
        let options =
            match unsafe { read_sized(options, OFFER_OPTIONS_SIZE_0_1, default_offer_options()) } {
                Ok(options) if options.reserved == 0 => {
                    karyos_client::OfferOptions::new().with_reserved_value(options.reserved_value)
                }
                Ok(_) => return Status::InvalidArgument,
                Err(status) => return status,
            };
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
        match api::publication::offer_with(Handle::from_raw(publication), lane, payload, options) {
            Ok(done) => {
                // SAFETY: the caller's contract on `accepted`.
                unsafe { write_accepted(accepted, done) };
                Status::Ok
            }
            Err(failure) => failure.status,
        }
    })
}

/// Offers length bytes at data on the timed lane with its requested
/// not-before time tx_time in the lane's clock domain (karyos_clock_now
/// reads it), copied before it returns; data may be null when length is 0.
/// The lane's handle checks the time before anything is reserved; the
/// driver's sender holds the message until its time, and local readers
/// read it at its commit. A timed lane is a network publication's: a
/// driver's stream is never timed (karyos_stream_options).
/// KARYOS_E_INVALID_SCHEDULE for a lane that is not timed, a time below the
/// lane's last, one past the horizon or an overflowing deadline. On
/// KARYOS_OK, accepted (may be null) receives the lane and position. Never
/// waits.
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

/// Writes the current time of domain (KARYOS_CLOCK_*): the time
/// karyos_publication_offer_at expects for a lane of that domain. Use it on
/// every platform rather than read the clocks: on macOS the monotonic
/// domain has a per-process origin, meaningful only within this process.
/// KARYOS_E_INVALID_ARGUMENT for an unknown domain or a null or misaligned
/// now (nothing is written); KARYOS_E_UNSUPPORTED for a domain this
/// platform cannot read (KARYOS_CLOCK_TAI off Linux). Never waits.
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

/// Stages a claim of length bytes on the lane: writes its handle and a
/// pointer to length zeroed bytes to fill. The pointer is valid until the
/// commit releases the claim, its abort, or the close of the publication or
/// of its client, and never points into a term or a shared mapping. One
/// claim per publication (KARYOS_E_CLAIM_OUTSTANDING). A claim on a timed
/// lane is staged, and its commit answers KARYOS_E_INVALID_SCHEDULE.
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

/// Commits the claim: claims in the term, copies the staged bytes and
/// commits, in one call. KARYOS_OK releases the claim and fills accepted
/// (may be null). KARYOS_E_BACK_PRESSURED, KARYOS_E_NOT_CONNECTED,
/// KARYOS_E_ADMIN_ACTION, KARYOS_E_RATE_LIMITED and KARYOS_E_GATED keep it
/// staged and its buffer valid, to retry or abort; any other failure
/// releases it, such as KARYOS_E_INVALID_SCHEDULE on a timed lane.
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

/// Aborts the claim: nothing reaches the term.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_claim_abort(claim: u64) -> i32 {
    guard(|| match api::publication::abort(Handle::from_raw(claim)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

/// Closes the publication, with its outstanding claim, and releases it to
/// its client, at once or at the client's next call while another call
/// holds the client (Threads, above).
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

/// One outcome record of a guarded publication, valid during the handler's
/// call. size is the library's sizeof(karyos_outcome): read only the fields
/// it covers.
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

/// Called once per outcome record with the caller's context and the
/// record, valid only during the call. It must return normally.
pub type OutcomeHandler =
    Option<unsafe extern "C" fn(context: *mut c_void, outcome: *const Outcome)>;

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

/// Delivers at most limit outcome records of the publication's lane to
/// handler, in sequence order, and writes their count through delivered
/// (may be null), also when it fails: a failed poll's status follows the
/// records delivered before it. Never waits and never allocates. A lane
/// that is not guarded, and lane 0 of a concurrent handle, deliver 0; a
/// lane the publication does not configure returns KARYOS_E_INVALID_LANE.
/// After the final KARYOS_OUTCOME_OUTCOMES_LOST record, polls deliver 0
/// and offers and claims return KARYOS_E_OUTCOMES_LOST. From the handler,
/// offering, claiming, polling or closing this publication, or closing its
/// client, returns KARYOS_E_REENTRANT. To stop after a failed handler
/// (ADR-0067), poll with a limit of 1 in a loop and stop calling.
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

/// What the poll knows of a message, valid during the handler's call. size
/// is the library's sizeof(karyos_message_info): read only the fields it
/// covers.
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
    /// The bytes the message takes in the stream, its frames and their
    /// alignment: its frames end at position + extent (a pad, an abort or
    /// a gap may follow before the next message).
    pub extent: u32,
    /// The image's session id; the stream's for a `karyos:ipc` one.
    pub session_id: i32,
    /// `KARYOS_MESSAGE_*` bits.
    pub flags: u32,
    /// Zero.
    pub reserved: u32,
}

/// An image of a network subscription attached (available 1) or retired.
/// A retired image's end follows: a KARYOS_END_* code (defined with
/// karyos_subscription_end), its seal position and the raw seal reason.
/// KARYOS_END_END_OF_STREAM is a clean end, KARYOS_END_IMAGE_RETIRED one
/// without (its publisher timed out, or a lane lost a frame on the way);
/// KARYOS_END_NONE for an attached image, and for one released unsealed
/// when its client closed. Set size to sizeof(karyos_image_change): a
/// caller built against the first version sets 24 and gets no end fields,
/// one built with them sets at least KARYOS_IMAGE_CHANGE_SIZE_ENDS, and one
/// built with the join loss fields (ADR-0100) at least
/// KARYOS_IMAGE_CHANGE_SIZE_JOIN_LOSS. A change with join_loss_to above
/// join_loss_from reports an attach that started above its lane's join:
/// the range [join_loss_from, join_loss_to) was not delivered to it.
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
    /// A retired image's end, a `KARYOS_END_*` code: `KARYOS_END_NONE` for
    /// an attached image, and for one released unsealed.
    pub end_reason: u32,
    /// Zero.
    pub reserved: u32,
    /// 0 with no end, for a seal not positioned yet, and for a seal at
    /// position 0: 0 alone does not tell them apart.
    pub end_position: u64,
    /// The seal's raw reason code; 0 with no end.
    pub seal_code: u64,
    /// An attach's join loss (ADR-0100): the lane's join; 0 with none.
    pub join_loss_from: u64,
    /// Where that attach started; 0 with none, so `join_loss_to` above
    /// `join_loss_from` marks a loss.
    pub join_loss_to: u64,
}

/// The size of `karyos_image_change` in ABI 0.1.0.
const IMAGE_CHANGE_SIZE_0_1: u32 = 24;

/// The size of `karyos_image_change` with its end fields
/// (`KARYOS_IMAGE_CHANGE_SIZE_ENDS`): the header's, checked by its tests;
/// the library writes by the caller's size and needs no constant.
#[cfg(test)]
pub(crate) const IMAGE_CHANGE_SIZE_ENDS: u32 = 48;

/// The size of `karyos_image_change` with its join loss fields
/// (`KARYOS_IMAGE_CHANGE_SIZE_JOIN_LOSS`, ADR-0100), checked as
/// [`IMAGE_CHANGE_SIZE_ENDS`] is.
#[cfg(test)]
pub(crate) const IMAGE_CHANGE_SIZE_JOIN_LOSS: u32 = 64;

/// Called once per message with the caller's context, the message's length
/// bytes at data (a private copy, never a term or a shared mapping, valid
/// only during the call) and its info. It must return normally.
pub type MessageHandler = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        data: *const u8,
        length: usize,
        info: *const MessageInfo,
    ),
>;

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

/// Adds the subscription of stream_id on the channel uri (karyos:ipc or
/// karyos:udp) to the client and writes its handle; karyos:udp needs a
/// driver that runs its network, as for karyos_client_add_publication. A
/// control call: it
/// waits for the driver up to the client's timeout and holds the client
/// handle meanwhile. A failure opens nothing and fills detail (may be
/// null).
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
/// `KARYOS_REJOIN_ARCHIVE`: an overrun's gap is recovered from the Archive
/// the options name, then merged back into the live stream (F9b).
pub(crate) const REJOIN_ARCHIVE: u32 = 2;

/// A subscription's role and rejoin policy, read by
/// karyos_client_add_subscription_with. Fill it with
/// karyos_subscription_options_init (KARYOS_ROLE_REQUIRED,
/// KARYOS_REJOIN_AT_HEAD: what karyos_client_add_subscription takes), then
/// set the fields. The size rule of karyos_driver_options applies.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubscriptionOptions {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// KARYOS_ROLE_*.
    pub role: u32,
    /// KARYOS_REJOIN_*.
    pub rejoin: u32,
    /// Zero; anything else is KARYOS_E_INVALID_ARGUMENT.
    pub reserved: u32,
    /// For KARYOS_REJOIN_ARCHIVE, and 0 for any other policy: the Archive
    /// handle, of the same client; the rejoin's requester id, at most
    /// UINT32_MAX, or 0 for one the library assigns (a caller that
    /// chooses one keeps it unique among the Archive's requesters); the
    /// stream replays are asked onto; and the policy after a failed merge,
    /// KARYOS_REJOIN_AT_HEAD or KARYOS_REJOIN_CLOSE. The library assigns
    /// the Archive handle's own client_id plus 1, then plus 2 and up, one
    /// per rejoin (KARYOS_E_INVALID_ARGUMENT past UINT32_MAX): space the
    /// client_ids of Archive handles that share an Archive so their ranges
    /// do not meet.
    pub archive: u64,
    /// For `KARYOS_REJOIN_ARCHIVE`: the rejoin's requester id, at most
    /// `UINT32_MAX`, or 0 for one the library assigns; 0 otherwise.
    pub archive_client_id: u64,
    /// For `KARYOS_REJOIN_ARCHIVE`: the stream replays are asked onto; 0
    /// otherwise.
    pub replay_stream_id: i32,
    /// For `KARYOS_REJOIN_ARCHIVE`: `KARYOS_REJOIN_AT_HEAD` or
    /// `KARYOS_REJOIN_CLOSE`, the policy after a failed merge; 0
    /// otherwise.
    pub secondary: u32,
}

/// The size of `karyos_subscription_options` in ABI 0.1.0, the smallest a
/// caller passes.
const SUBSCRIPTION_OPTIONS_SIZE_0_1: u32 = 16;

/// The size with the Archive rejoin's fields (F9b).
const SUBSCRIPTION_OPTIONS_SIZE_ARCHIVE: u32 = 40;

/// `karyos_subscription_options` with the defaults (a required reader that
/// rejoins at the head) and this version's size.
fn default_subscription_options() -> SubscriptionOptions {
    SubscriptionOptions {
        size: size_of_u32::<SubscriptionOptions>(),
        role: ROLE_REQUIRED,
        rejoin: REJOIN_AT_HEAD,
        reserved: 0,
        archive: 0,
        archive_client_id: 0,
        replay_stream_id: 0,
        secondary: 0,
    }
}

/// The client options of `options`, and the Archive rejoin it asks for:
/// an unknown role, policy or secondary, a nonzero `reserved`, a size
/// between the two layouts, an Archive rejoin in the smaller one, or an
/// Archive field set for another policy is [`Status::InvalidArgument`].
fn subscription_options(
    options: SubscriptionOptions,
) -> Result<
    (
        karyos_client::SubscriptionOptions,
        Option<api::subscription::ArchiveRejoin>,
    ),
    Status,
> {
    use karyos_client::{RejoinPolicy, SubscriberRole};
    if options.reserved != 0
        || (options.size > SUBSCRIPTION_OPTIONS_SIZE_0_1
            && options.size < SUBSCRIPTION_OPTIONS_SIZE_ARCHIVE)
    {
        return Err(Status::InvalidArgument);
    }
    let role = match options.role {
        ROLE_REQUIRED => SubscriberRole::Required,
        ROLE_OPTIONAL => SubscriberRole::Optional,
        ROLE_OBSERVER => SubscriberRole::Observer,
        _ => return Err(Status::InvalidArgument),
    };
    let archive_fields = options.archive != 0
        || options.archive_client_id != 0
        || options.replay_stream_id != 0
        || options.secondary != 0;
    let (rejoin, archive) = match options.rejoin {
        REJOIN_AT_HEAD | REJOIN_CLOSE if archive_fields => {
            return Err(Status::InvalidArgument);
        }
        REJOIN_AT_HEAD => (RejoinPolicy::RejoinAtHead, None),
        REJOIN_CLOSE => (RejoinPolicy::Close, None),
        REJOIN_ARCHIVE if options.size >= SUBSCRIPTION_OPTIONS_SIZE_ARCHIVE => {
            let close_on_failure = match options.secondary {
                REJOIN_AT_HEAD => false,
                REJOIN_CLOSE => true,
                _ => return Err(Status::InvalidArgument),
            };
            // The live reader's own policy is set aside while it rejoins.
            let archive = api::subscription::ArchiveRejoin {
                archive: Handle::from_raw(options.archive),
                client_id: options.archive_client_id,
                replay_stream_id: options.replay_stream_id,
                close_on_failure,
            };
            (RejoinPolicy::RejoinAtHead, Some(archive))
        }
        _ => return Err(Status::InvalidArgument),
    };
    Ok((
        karyos_client::SubscriptionOptions::new(role, rejoin),
        archive,
    ))
}

/// As `karyos_subscription_options_init_sized` with the size of `karyos_subscription_options` in ABI 0.1.0, the
/// first: the symbol a binary built against an older header calls, which
/// writes no field that header lacks (owner item 48's option A, interim).
/// A caller built against this header calls the header's `static inline`
/// `karyos_subscription_options_init`, which passes its own `sizeof`.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_subscription_options` of at least that
/// size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_subscription_options_init(
    options: *mut SubscriptionOptions,
) -> i32 {
    init_0_1(SUBSCRIPTION_OPTIONS_SIZE_0_1, |size| {
        // SAFETY: the caller's contract on `options`, of at least the 0.1.0
        // size.
        unsafe { karyos_subscription_options_init_sized(options, size) }
    })
}

/// Fills options with the defaults and its size. KARYOS_E_INVALID_ARGUMENT
/// for a null or misaligned pointer.
///
/// # Safety
///
/// `options` is null or points to `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_subscription_options_init_sized(
    options: *mut SubscriptionOptions,
    size: usize,
) -> i32 {
    guard(|| {
        let filled = default_subscription_options();
        // SAFETY: the caller's contract on `options` and `size`.
        unsafe { init_sized(options, size, SUBSCRIPTION_OPTIONS_SIZE_0_1, filled) }
    })
}

/// As karyos_client_add_subscription, with the reader's role and rejoin
/// policy; each image of a karyos:udp subscription takes both. A null
/// options, a size below that of ABI 0.1.0 (16) or between it and that of
/// the Archive fields (40), an unknown role or policy, or a nonzero
/// reserved returns KARYOS_E_INVALID_ARGUMENT and opens nothing.
///
/// KARYOS_REJOIN_ARCHIVE recovers an overrun's gap from the Archive handle
/// and merges it back into the live stream. The Archive handle lends only
/// its control streams and an id: the rejoin takes its own request
/// publication and response subscription, which the subscription owns. A
/// rejoin's Archive streams are released by their drop when the
/// subscription closes, and closing the Archive handle leaves the rejoin
/// working. Each rejoin takes one of the request stream's publisher slots
/// (KARYOS_E_REFUSED when none is free). While a gap is recovered, keep
/// calling karyos_client_poll, so the replay target's grant completes;
/// karyos_subscription_rejoin_state tells the recovery and a failed merge.
/// A network subscription is KARYOS_E_UNSUPPORTED_CHANNEL; one that names
/// no publication to recover, an Archive of another client, an Archive
/// field set for another policy, or another secondary is
/// KARYOS_E_INVALID_ARGUMENT. Nothing stays open on failure.
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
        let (options, archive) = match read.and_then(subscription_options) {
            Ok(options) => options,
            Err(status) => return status,
        };
        // SAFETY: the caller's contract on `uri`.
        let uri = match unsafe { read_str(uri) } {
            Ok(uri) => uri,
            Err(status) => return status,
        };
        match api::subscription::add_rejoining(
            Handle::from_raw(client),
            uri,
            stream_id,
            options,
            archive,
        ) {
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

/// `KARYOS_STRATEGY_MIN`: the slowest live receiver bounds the sender
/// (owner item 7, karyos#637); a channel's `fc=min`, or no `fc`.
pub(crate) const STRATEGY_MIN: u32 = 0;
/// `KARYOS_STRATEGY_MAX`: the fastest live receiver bounds it (`fc=max`).
pub(crate) const STRATEGY_MAX: u32 = 1;
/// `KARYOS_STRATEGY_TAGGED`: the receivers of a tagged group bound it
/// (`fc=tagged:<group>`).
pub(crate) const STRATEGY_TAGGED: u32 = 2;

/// The `count` words at `words`: empty for a count of 0, whatever the
/// pointer; [`Status::InvalidArgument`] for a null or misaligned pointer
/// with a count, or a byte length past `isize::MAX`.
///
/// # Safety
///
/// With a nonzero `count`, `words` points to `count` readable `uint64_t`,
/// unchanged during the call.
unsafe fn read_words<'a>(words: *const u64, count: usize) -> Result<&'a [u64], Status> {
    if count == 0 {
        return Ok(&[]);
    }
    if !readable(words)
        || count
            .checked_mul(8)
            .is_none_or(|bytes| isize::try_from(bytes).is_err())
    {
        return Err(Status::InvalidArgument);
    }
    // SAFETY: non-null and aligned, `count` readable words below
    // `isize::MAX` bytes (the caller's contract and the checks above), used
    // only during the call.
    Ok(unsafe { std::slice::from_raw_parts(words, count) })
}

/// As karyos_client_add_publication on a karyos:udp channel, whose
/// receivers have configured roles (ABI 0.1.2): strategy is a
/// KARYOS_STRATEGY_* and must be the channel's fc (KARYOS_STRATEGY_MIN
/// without one), or the driver refuses with KARYOS_E_REFUSED, detail code
/// 17; tagged_group is the group of KARYOS_STRATEGY_TAGGED and 0 for the
/// others. required holds required_count required receiver ids, and tags
/// tag_count pairs of words, a receiver id and its tag (either may be null
/// with a count of 0). An unknown strategy, a group that does not match
/// it, a receiver id or tag of 0, a repeated receiver id, a null list with
/// a count, or roles the command ring's largest record cannot carry is
/// KARYOS_E_INVALID_ARGUMENT; more required, or more tagged, receivers
/// than the driver's membership holds is KARYOS_E_REFUSED, detail code 18;
/// a karyos:ipc URI is
/// KARYOS_E_UNSUPPORTED_CHANNEL. Nothing is opened on failure.
///
/// # Safety
///
/// As `karyos_client_add_publication`; with a nonzero count, `required`
/// points to `required_count` readable `uint64_t` and `tags` to `2 *
/// tag_count`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_add_publication_with_roles(
    client: u64,
    uri: *const c_char,
    stream_id: i32,
    strategy: u32,
    tagged_group: u64,
    required: *const u64,
    required_count: usize,
    tags: *const u64,
    tag_count: usize,
    publication: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(publication) {
            return Status::InvalidArgument;
        }
        let strategy = match (strategy, tagged_group) {
            (STRATEGY_MIN, 0) => karyos_client::Strategy::Min,
            (STRATEGY_MAX, 0) => karyos_client::Strategy::Max,
            (STRATEGY_TAGGED, group) if group != 0 => karyos_client::Strategy::Tagged(group),
            _ => return Status::InvalidArgument,
        };
        let Some(tag_words) = tag_count.checked_mul(2) else {
            return Status::InvalidArgument;
        };
        // SAFETY: the caller's contract on `required` and `tags`.
        let lists = unsafe { read_words(required, required_count) }
            .and_then(|required| Ok((required, unsafe { read_words(tags, tag_words) }?)));
        let (required, tags) = match lists {
            Ok(lists) => lists,
            Err(status) => return status,
        };
        let roles = karyos_client::PublicationRoles {
            strategy,
            required: required.to_vec(),
            tags: tags
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&[id, tag]| (id, tag))
                .collect(),
        };
        if !roles.is_well_formed() {
            return Status::InvalidArgument;
        }
        // SAFETY: the caller's contract on `uri`.
        let uri = match unsafe { read_str(uri) } {
            Ok(uri) => uri,
            Err(status) => return status,
        };
        match api::publication::add_with_roles(Handle::from_raw(client), uri, stream_id, &roles) {
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
    })
}

/// As karyos_client_add_subscription_with on a karyos:udp channel, whose
/// images name a configured receiver identity (ABI 0.1.2): receiver_id
/// (nonzero) in every RB block and group_tag in their status messages,
/// what a publication's required receiver ids and tagged group name. A
/// receiver_id of 0, or an Archive rejoin in options, is
/// KARYOS_E_INVALID_ARGUMENT; a karyos:ipc URI is
/// KARYOS_E_UNSUPPORTED_CHANNEL; another identity on the same endpoint and
/// stream is KARYOS_E_REFUSED, detail code 15. Nothing stays open on
/// failure.
///
/// # Safety
///
/// As `karyos_client_add_subscription_with`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_add_subscription_as(
    client: u64,
    uri: *const c_char,
    stream_id: i32,
    options: *const SubscriptionOptions,
    receiver_id: u64,
    group_tag: u64,
    subscription: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(subscription) {
            return Status::InvalidArgument;
        }
        let Some(receiver_id) = core::num::NonZeroU64::new(receiver_id) else {
            return Status::InvalidArgument;
        };
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
            Ok((options, None)) => options,
            Ok((_, Some(_))) => return Status::InvalidArgument,
            Err(status) => return status,
        };
        // SAFETY: the caller's contract on `uri`.
        let uri = match unsafe { read_str(uri) } {
            Ok(uri) => uri,
            Err(status) => return status,
        };
        let identity = karyos_client::ReceiverIdentity {
            receiver_id,
            group_tag,
        };
        match api::subscription::add_as(Handle::from_raw(client), uri, stream_id, options, identity)
        {
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

/// `KARYOS_ADMISSION_UNKNOWN`: no admission state reported yet, or a
/// publication that is not a network one (karyos#637).
pub(crate) const ADMISSION_UNKNOWN: u32 = 0;
/// `KARYOS_ADMISSION_OPEN`.
pub(crate) const ADMISSION_OPEN: u32 = 1;
/// `KARYOS_ADMISSION_NOT_JOINED`.
pub(crate) const ADMISSION_NOT_JOINED: u32 = 2;
/// `KARYOS_ADMISSION_LOST_REQUIRED`.
pub(crate) const ADMISSION_LOST_REQUIRED: u32 = 3;

/// Writes the admission state of a network publication through admission,
/// a KARYOS_ADMISSION_* (ABI 0.1.2): the last state its sender observed, as
/// its client last heard it, not a list of transitions. Offers keep their
/// outcomes: under not joined and lost required they answer
/// KARYOS_E_BACK_PRESSURED once the window is full. A null admission is
/// KARYOS_E_INVALID_ARGUMENT.
///
/// # Safety
///
/// `admission` points to a writable `uint32_t`; a null one returns
/// `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_publication_network_admission(
    publication: u64,
    admission: *mut u32,
) -> i32 {
    guard(|| {
        if !writable(admission) {
            return Status::InvalidArgument;
        }
        match api::publication::network_admission(Handle::from_raw(publication)) {
            Ok(state) => {
                let code = match state {
                    None => ADMISSION_UNKNOWN,
                    Some(karyos_client::NetworkAdmission::Open) => ADMISSION_OPEN,
                    Some(karyos_client::NetworkAdmission::NotJoined) => ADMISSION_NOT_JOINED,
                    Some(karyos_client::NetworkAdmission::LostRequired) => ADMISSION_LOST_REQUIRED,
                    Some(_) => ADMISSION_UNKNOWN,
                };
                // SAFETY: `admission` is non-null and aligned, and the
                // caller's contract makes it a writable `uint32_t`.
                unsafe { admission.write(code) };
                Status::Ok
            }
            Err(status) => status,
        }
    })
}

/// `KARYOS_MERGE_NONE`: no merge failed.
pub(crate) const MERGE_NONE: u32 = 0;
/// `KARYOS_MERGE_OTHER`: a failure a newer library knows and this ABI
/// version names no code for.
pub(crate) const MERGE_OTHER: u32 = 255;

/// The `KARYOS_MERGE_*` code of a merge failure: 1 an epoch change, 2 a
/// replay that ended short, 3 a mismatch at the cutover, 4 another lane,
/// 5 the replay overrun, 6 the replay revoked, 7 the replay's failure, 8
/// the live reader overrun, 9 the live reader's failure.
pub(crate) fn merge_code(error: &karyos_client::MergeError) -> u32 {
    use karyos_client::MergeError;
    match error {
        MergeError::EpochChanged { .. } => 1,
        MergeError::ReplayShort { .. } => 2,
        MergeError::Mismatch { .. } => 3,
        MergeError::Lane { .. } => 4,
        MergeError::ReplayOverrun(_) => 5,
        MergeError::ReplayRevoked { .. } => 6,
        MergeError::Replay(_) => 7,
        MergeError::LiveOverrun(_) => 8,
        MergeError::Live(_) => 9,
        _ => MERGE_OTHER,
    }
}

/// Where a subscription's Archive rejoin stands. size is the caller's
/// sizeof(karyos_subscription_rejoin); the rule of karyos_detail applies.
/// recovering is 1 while a gap is asked for or merged; merge_failure is
/// the last failed merge's KARYOS_MERGE_* code.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubscriptionRejoin {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// 1 while a gap is asked for or merged, 0 otherwise.
    pub recovering: u32,
    /// The last merge failure's `KARYOS_MERGE_*` code.
    pub merge_failure: u32,
    /// Zero.
    pub reserved: u32,
}

/// The size of `karyos_subscription_rejoin` in its first version.
const SUBSCRIPTION_REJOIN_SIZE_0_1: u32 = 16;

/// Writes where the subscription's Archive rejoin stands. A subscription
/// that does not rejoin from an Archive reads 0 and KARYOS_MERGE_NONE.
/// Never waits. A null or misaligned state, or a size below 16, is
/// KARYOS_E_INVALID_ARGUMENT with nothing written.
///
/// # Safety
///
/// `state` points to a writable `karyos_subscription_rejoin` whose `size`
/// is set; a null or misaligned one, or a `size` below 16, returns
/// `KARYOS_E_INVALID_ARGUMENT` with nothing written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_subscription_rejoin_state(
    subscription: u64,
    state: *mut SubscriptionRejoin,
) -> i32 {
    guard(|| {
        if !writable(state) {
            return Status::InvalidArgument;
        }
        // SAFETY: `state` is non-null and aligned, and points to the
        // caller's struct (its contract), whose first field is the size.
        if unsafe { state.cast::<u32>().read() } < SUBSCRIPTION_REJOIN_SIZE_0_1 {
            return Status::InvalidArgument;
        }
        let (recovering, failure) =
            match api::subscription::rejoin_state(Handle::from_raw(subscription)) {
                Ok(Some((recovering, failure))) => (recovering, failure),
                Ok(None) => (false, None),
                Err(status) => return status,
            };
        // SAFETY: the caller's contract on `state`, whose size was read
        // above.
        unsafe { write_rejoin_state(state, recovering, failure.as_ref()) };
        Status::Ok
    })
}

/// Writes `recovering` and `failure` through `state` by its size: the
/// sized write of `karyos_subscription_rejoin_state`, apart so that it
/// runs under Miri with no driver.
///
/// # Safety
///
/// `state` is non-null, aligned and points to a writable
/// `karyos_subscription_rejoin` of at least its `size` bytes.
unsafe fn write_rejoin_state(
    state: *mut SubscriptionRejoin,
    recovering: bool,
    failure: Option<&karyos_client::MergeError>,
) {
    // The caller's size stays, as every sized output's does.
    let filled = |size| SubscriptionRejoin {
        size,
        recovering: u32::from(recovering),
        merge_failure: failure.map_or(MERGE_NONE, merge_code),
        reserved: 0,
    };
    // SAFETY: the caller's contract on `state`.
    unsafe { write_sized(state, SUBSCRIPTION_REJOIN_SIZE_0_1, filled) };
}

/// Delivers at most limit messages to handler, each from a private copy,
/// and writes their count through delivered (may be null), also when it
/// fails: a failed poll's status follows the messages delivered before it.
/// Never waits; it allocates only when a newly attached image or mapping
/// has a larger message than any before (KARYOS_E_SYSTEM when it cannot,
/// before anything of that round is delivered: the count covers earlier
/// rounds). From the handler, polling or closing this subscription, or
/// closing its client, returns KARYOS_E_REENTRANT. A karyos:ipc
/// subscription's end is its poll's status, after the messages before it,
/// and every later poll's: KARYOS_E_CLOSED_BY_OVERRUN once its rejoin
/// policy closed it, KARYOS_E_CLOSED once its stream's seal is reached or
/// it was revoked with its client. An overrun it rejoined after, an aborted
/// block or a skip is KARYOS_OK and the next poll goes on. A karyos:udp
/// subscription's images end one by one (image changes report them): its
/// poll answers KARYOS_OK. To stop
/// after a failed handler (ADR-0067), poll with a limit of 1 in a loop and
/// stop calling: the failed message is acknowledged, the later ones are
/// not delivered.
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

/// Takes the oldest queued image change into change and sets has to 1, or
/// sets has to 0 when none is queued. The queue is bounded. change points
/// to a karyos_image_change whose size is set: a null one, or one smaller
/// than this version's first, returns KARYOS_E_INVALID_ARGUMENT and takes
/// nothing.
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
                    // SAFETY: the caller's contract on `change`, whose
                    // size was read above.
                    unsafe { write_image_change(change, &next) };
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

/// Writes `next` through `change` by its size: the sized write of
/// `karyos_subscription_next_image_change`, apart so that it runs under
/// Miri with no driver. A 24-byte struct takes no end fields.
///
/// # Safety
///
/// `change` is non-null, aligned and points to a writable
/// `karyos_image_change` of at least its `size` bytes.
unsafe fn write_image_change(change: *mut ImageChange, next: &karyos_client::ImageChange) {
    let ended = next.end.map(|end| api::subscription::End::Sealed {
        reason: end.reason,
        position: end.position.unwrap_or(0),
    });
    let (end_reason, end_position, seal_code) = end_fields(ended);
    // The caller's size stays, as every sized output's does.
    let filled = |size| ImageChange {
        size,
        session_id: next.session_id,
        image_id: next.image_id,
        lane: u32::from(next.lane.get()),
        available: u32::from(next.available),
        end_reason,
        reserved: 0,
        end_position,
        seal_code,
        join_loss_from: next.join_loss.map_or(0, |loss| loss.from),
        join_loss_to: next.join_loss.map_or(0, |loss| loss.to),
    };
    // SAFETY: the caller's contract on `change`.
    unsafe { write_sized(change, IMAGE_CHANGE_SIZE_0_1, filled) };
}

/// Writes the image changes a full queue dropped through lost.
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

/// Closes the subscription and releases it to its client, at once or at
/// the client's next call while another call holds the client (Threads,
/// above).
#[unsafe(no_mangle)]
pub extern "C" fn karyos_subscription_close(subscription: u64) -> i32 {
    guard(
        || match api::subscription::close(Handle::from_raw(subscription)) {
            Ok(()) => Status::Ok,
            Err(status) => status,
        },
    )
}

/// An embedded driver's options, copied by karyos_driver_create. Fill it
/// with karyos_driver_options_init, which sets size and the driver's
/// defaults; every setting it does not carry is the driver's default. A
/// struct from an older header of the same major version is accepted: the
/// fields it lacks take their defaults. A size below that of its first
/// version is KARYOS_E_INVALID_ARGUMENT.
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
    /// Zero; anything else is KARYOS_E_INVALID_ARGUMENT.
    pub reserved: u32,
    /// How often the driver advances its heartbeat, in nanoseconds.
    pub heartbeat_interval_ns: u64,
    /// How long a client's heartbeat may stay unchanged, in nanoseconds.
    pub client_liveness_timeout_ns: u64,
    /// How long a handle has to move to a successor mapping, in ns.
    pub cutover_deadline_ns: u64,
    /// How long the host has to call karyos_driver_startup_complete, in
    /// ns (ABI 0.1.3). Nonzero; the default, and an older struct's, is
    /// 30 s.
    pub startup_timeout_ns: u64,
    /// KARYOS_NETWORK_OFF or KARYOS_NETWORK_ON (ABI 0.1.4); off for an
    /// older struct. Any other value is KARYOS_E_INVALID_ARGUMENT.
    pub network: u32,
    /// Must be zero; a later version may give it a meaning.
    pub reserved0: u32,
    /// The most bytes one stream lane may take, its log buffer region plus
    /// its conflation table's (ABI 0.1.5). 0, the default and an older
    /// struct's, sets no cap. A stream above it is refused by
    /// karyos_driver_add_stream, and a client's karyos:udp publication by
    /// KARYOS_E_REFUSED, detail code 24.
    pub max_stream_bytes: u64,
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
        startup_timeout_ns: defaults.startup_timeout_ns,
        // The driver's default, as every other field.
        network: if defaults.network {
            driver::NETWORK_ON
        } else {
            driver::NETWORK_OFF
        },
        reserved0: 0,
        max_stream_bytes: defaults.max_stream_bytes,
    }
}

/// As `karyos_driver_options_init_sized` with the size of `karyos_driver_options` in ABI 0.1.0, the
/// first: the symbol a binary built against an older header calls, which
/// writes no field that header lacks (owner item 48's option A, interim).
/// A caller built against this header calls the header's `static inline`
/// `karyos_driver_options_init`, which passes its own `sizeof`.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_driver_options` of at least that
/// size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_options_init(options: *mut DriverOptions) -> i32 {
    init_0_1(DRIVER_OPTIONS_SIZE_0_1, |size| {
        // SAFETY: the caller's contract on `options`, of at least the 0.1.0
        // size.
        unsafe { karyos_driver_options_init_sized(options, size) }
    })
}

/// Fills options with the driver's defaults and its size.
/// KARYOS_E_INVALID_ARGUMENT for a null or misaligned pointer.
///
/// # Safety
///
/// `options` is null or points to `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_options_init_sized(
    options: *mut DriverOptions,
    size: usize,
) -> i32 {
    guard(|| {
        let filled = default_driver_options();
        // SAFETY: the caller's contract on `options` and `size`.
        unsafe { init_sized(options, size, DRIVER_OPTIONS_SIZE_0_1, filled) }
    })
}

/// Creates an embedded driver and writes its handle. Its caller drives it
/// with karyos_driver_do_work until karyos_driver_start gives it a thread.
/// A failed create creates nothing and fills detail (may be null):
/// KARYOS_E_SYSTEM carries errno in value, or the descriptors needed in
/// code and the soft limit in value.
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
        // A later minor may give them a meaning: refused, not ignored.
        if raw.reserved != 0 || raw.reserved0 != 0 {
            return Status::InvalidArgument;
        }
        let network = match raw.network {
            driver::NETWORK_OFF => false,
            driver::NETWORK_ON => true,
            _ => return Status::InvalidArgument,
        };
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
            startup_timeout_ns: raw.startup_timeout_ns,
            network,
            max_stream_bytes: raw.max_stream_bytes,
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

/// Runs one duty cycle and writes its work count. KARYOS_E_BUSY while the
/// driver runs on its own thread; KARYOS_E_INTERNAL once a panic poisoned
/// it.
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

/// Gives the driver a thread of its own, which runs its duty cycle and
/// idles by idle_strategy (KARYOS_IDLE_*; idle_sleep_ns for
/// KARYOS_IDLE_SLEEP) after a cycle without work. The agents' default is
/// KARYOS_IDLE_YIELD_THEN_SLEEP. KARYOS_E_BUSY when it already has one.
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

/// Stops the driver's thread and gives the driver back to its caller.
/// KARYOS_E_BUSY when it has none; KARYOS_E_INTERNAL when a panic on it
/// poisoned the driver.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_driver_stop(driver: u64) -> i32 {
    guard(|| match driver::stop(Handle::from_raw(driver)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

/// Declares the host's startup complete (R-CORE-35): its streams and
/// whatever else it needs before serving exist. Writes 1 through complete,
/// or 0 when startup_timeout_ns had already passed: the readiness is then
/// FAILED for good. It works with or without karyos_driver_start.
///
/// # Safety
///
/// `complete` points to a writable `uint32_t`; null or misaligned returns
/// `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_startup_complete(driver: u64, complete: *mut u32) -> i32 {
    guard(|| {
        if !writable(complete) {
            return Status::InvalidArgument;
        }
        match driver::startup_complete(Handle::from_raw(driver)) {
            Ok(done) => {
                // SAFETY: `complete` is non-null and aligned, and the
                // caller's contract makes it a writable `uint32_t`.
                unsafe { complete.write(u32::from(done)) };
                Status::Ok
            }
            Err(status) => status,
        }
    })
}

/// A driver's readiness, written by karyos_driver_readiness. The caller
/// sets size to sizeof(karyos_readiness); a size below that of ABI 0.1.3
/// is KARYOS_E_INVALID_ARGUMENT, and a larger one gets the fields this
/// version knows.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReadinessOut {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// KARYOS_READINESS_*.
    pub state: u32,
    /// KARYOS_READINESS_REASON_*.
    pub reason: u32,
    /// Written as zero.
    pub reserved: u32,
    /// Nanoseconds since the driver was created, on its clock.
    pub uptime_ns: u64,
}

/// The size of `karyos_readiness` in ABI 0.1.3, its first version.
const READINESS_SIZE_0_1_3: u32 = 24;

/// Writes the driver's readiness, its reason and its uptime (R-CORE-35).
/// It reads the driver's state and clock, and touches no data path. A host
/// that never calls karyos_driver_startup_complete reads
/// KARYOS_READINESS_FAILED once startup_timeout_ns (30 s by default) has
/// passed. KARYOS_E_INVALID_ARGUMENT for a null or misaligned out, or a
/// size below that of ABI 0.1.3.
///
/// # Safety
///
/// `out` points to a writable `karyos_readiness` whose `size` is set. A
/// null or misaligned `out`, or a `size` below ABI 0.1.3's, returns
/// `KARYOS_E_INVALID_ARGUMENT` with nothing written; a larger `size` gets
/// the fields this version knows.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_readiness(driver: u64, out: *mut ReadinessOut) -> i32 {
    guard(|| {
        if !sized_struct(out) {
            return Status::InvalidArgument;
        }
        // SAFETY: `out` is non-null and aligned for its `uint32_t` size,
        // and points to the caller's struct (its contract), whose first
        // field is the `uint32_t` size.
        if unsafe { out.cast::<u32>().read() } < READINESS_SIZE_0_1_3 {
            return Status::InvalidArgument;
        }
        match driver::readiness(Handle::from_raw(driver)) {
            Ok((readiness, uptime_ns)) => {
                let (state, reason) = readiness.wire();
                let narrow = |code: u64| u32::try_from(code).unwrap_or(u32::MAX);
                // SAFETY: the caller's contract on `out`.
                unsafe {
                    write_sized(out, READINESS_SIZE_0_1_3, |size| ReadinessOut {
                        size,
                        state: narrow(state),
                        reason: narrow(reason),
                        reserved: 0,
                        uptime_ns,
                    });
                };
                Status::Ok
            }
            Err(status) => status,
        }
    })
}

/// A stream's options, copied by karyos_driver_add_stream: the driver's
/// stream configuration and its conflation table. Fill it with
/// karyos_stream_options_init, then set stream_id. This version takes lane
/// 0 only (KARYOS_E_INVALID_LANE otherwise); the driver checks the sizes.
/// The size rule of karyos_driver_options applies, with three layouts: 64
/// bytes up to claim_deadline_ns (an exclusive stream with no conflation
/// table), 80 bytes with the conflation fields, and 88 bytes with
/// publishers. A size between two layouts, or a nonzero reserved, is
/// KARYOS_E_INVALID_ARGUMENT.
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
    /// The lane: 0.
    pub lane: u32,
    /// KARYOS_PUBLICATION_*.
    pub publication_mode: u32,
    /// Offers allowed with no subscriber attached: 0 or 1. It applies to
    /// every publication of the stream, exclusive or concurrent, an
    /// in-process or a remote client's.
    pub allow_unconnected: u32,
    /// Entries of a schedule ring, which would make the lane timed
    /// (karyos_publication_offer_at). Must be 0: karyos_driver_add_stream
    /// refuses any other value with KARYOS_E_INVALID_ARGUMENT, since a
    /// driver's stream has no sender to release the ring, which would take
    /// its capacity of timed offers and then back pressure for good. A
    /// timed lane is a network publication's: a driver configures timed
    /// network streams (karyosd --timed-network), and a client's network
    /// publication of such a stream is timed.
    pub schedule_capacity: u32,
    /// KARYOS_LOSS_*: what a lost required subscriber does.
    pub on_required_loss: u32,
    /// How long a claim may stay open, in nanoseconds.
    pub claim_deadline_ns: u64,
    /// The stream's conflation table (from 80 bytes): its keys, its largest
    /// value and its update journal, in bytes. All three 0 for none; a
    /// partial set, or a table the driver cannot build, is
    /// KARYOS_E_INVALID_ARGUMENT. An offer's reserved value is its key.
    pub conflation_keys: u32,
    /// The largest value of the table, in bytes.
    pub conflation_value_capacity: u32,
    /// Bytes of the table's update journal.
    pub conflation_journal_capacity: u64,
    /// Concurrent handles at once (from 88 bytes): 1 to 255 with
    /// KARYOS_PUBLICATION_CONCURRENT, 0 with KARYOS_PUBLICATION_EXCLUSIVE;
    /// anything else is KARYOS_E_INVALID_ARGUMENT. Each publisher, like
    /// each optional or observer reader, takes one spare-slot credit for the
    /// stream's life, and one spare slot is kept for cleaning: publishers +
    /// optional and observer readers <= spare_slots - 1 (an exclusive
    /// stream counts 1 publisher). Past it the stream is refused
    /// (KARYOS_E_RESOURCES_UNAVAILABLE), or later the reader is. With the
    /// default 3 spare slots, 2 publishers leave room for no optional
    /// reader: raise spare_slots for a concurrent stream that also has
    /// optional readers, such as an Archive's request stream. A concurrent
    /// handle's offer needs a connected subscriber (KARYOS_E_NOT_CONNECTED
    /// otherwise) unless the stream allows unconnected offers. Each handle
    /// reserves with one atomic fetch_add: on an aarch64 CPU without LSE
    /// atomics, as detected at run time (not the build's target features),
    /// the driver refuses a concurrent stream, its default.
    pub publishers: u32,
    /// Zero.
    pub reserved: u32,
}

/// The smallest size of `karyos_stream_options` accepted: that of the
/// first ABI version that has it (as `CLIENT_OPTIONS_SIZE_0_1`), with no
/// conflation fields. Such a caller's stream has no conflation table.
const STREAM_OPTIONS_SIZE_0_1: u32 = 64;

/// The size of `karyos_stream_options` with its conflation fields (F7b-2b).
/// A size between [`STREAM_OPTIONS_SIZE_0_1`] and this one comes from no
/// header, and could cut a field: it is refused.
const STREAM_OPTIONS_SIZE_CONFLATION: u32 = 80;

/// The size of `karyos_stream_options` with its publishers field. A size
/// between [`STREAM_OPTIONS_SIZE_CONFLATION`] and this one comes from no
/// header either: it is refused.
const STREAM_OPTIONS_SIZE_CONCURRENT: u32 = 88;

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
        conflation_keys: defaults.conflation_keys,
        conflation_value_capacity: defaults.conflation_value_capacity,
        conflation_journal_capacity: defaults.conflation_journal_capacity,
        publishers: defaults.publishers,
        reserved: 0,
    }
}

/// As `karyos_stream_options_init_sized` with the size of `karyos_stream_options` in ABI 0.1.0, the
/// first: the symbol a binary built against an older header calls, which
/// writes no field that header lacks (owner item 48's option A, interim).
/// A caller built against this header calls the header's `static inline`
/// `karyos_stream_options_init`, which passes its own `sizeof`.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_stream_options` of at least that
/// size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_stream_options_init(options: *mut StreamOptions) -> i32 {
    init_0_1(STREAM_OPTIONS_SIZE_0_1, |size| {
        // SAFETY: the caller's contract on `options`, of at least the 0.1.0
        // size.
        unsafe { karyos_stream_options_init_sized(options, size) }
    })
}

/// Fills options with a stream's defaults (stream id 0, the smallest term)
/// and its size. KARYOS_E_INVALID_ARGUMENT for a null or misaligned
/// pointer.
///
/// # Safety
///
/// `options` is null or points to `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_stream_options_init_sized(
    options: *mut StreamOptions,
    size: usize,
) -> i32 {
    guard(|| {
        let filled = default_stream_options();
        // SAFETY: the caller's contract on `options` and `size`.
        unsafe { init_sized(options, size, STREAM_OPTIONS_SIZE_0_1, filled) }
    })
}

/// Adds a stream to the driver, until karyos_driver_remove_stream or the
/// driver's close. A failure adds nothing and fills detail (may be null): a
/// duplicate stream id is KARYOS_E_INVALID_ARGUMENT with the stream id in
/// code and the session id in value. A stream above the driver's
/// max_stream_bytes is KARYOS_E_INVALID_ARGUMENT with the stream's bytes
/// in code and the cap in value.
///
/// # Safety
///
/// `options` points to a readable `karyos_stream_options` whose `size` is
/// set; `detail` is null or a `karyos_detail` whose `size` is set. A null
/// or misaligned `options`, a `size` below the first version's (64), a
/// `size` between two layouts (64, 80 and 88), or a nonzero `reserved`,
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
        // The copy above went only to a local; a size no header produces is
        // refused before anything is used.
        let between = |low: u32, high: u32| raw.size > low && raw.size < high;
        if between(STREAM_OPTIONS_SIZE_0_1, STREAM_OPTIONS_SIZE_CONFLATION)
            || between(
                STREAM_OPTIONS_SIZE_CONFLATION,
                STREAM_OPTIONS_SIZE_CONCURRENT,
            )
            || raw.reserved != 0
        {
            return Status::InvalidArgument;
        }
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
            conflation_keys: raw.conflation_keys,
            conflation_value_capacity: raw.conflation_value_capacity,
            conflation_journal_capacity: raw.conflation_journal_capacity,
            publishers: raw.publishers,
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

/// Removes the driver's stream: its publication closes, and its subscribers
/// read up to its seal. KARYOS_E_INVALID_ARGUMENT for a stream id the
/// driver does not have.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_driver_remove_stream(driver: u64, stream_id: i32) -> i32 {
    guard(
        || match driver::remove_stream(Handle::from_raw(driver), stream_id) {
            Ok(()) => Status::Ok,
            Err(failure) => failure.status,
        },
    )
}

/// Called once per delivered key with the caller's context, the key, its
/// latest value's length bytes at data (the reader's private copy, never
/// the shared table, valid only during the call), the value's version and
/// its freshness (KARYOS_FRESH, or the start of the gap that made it
/// stale). It must return normally.
pub type ConflatedHandler = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        key: u32,
        data: *const u8,
        length: usize,
        version: u64,
        freshness: u64,
    ),
>;

/// Subscribes to the conflation table of the driver's stream and writes
/// the conflated subscription's handle. The view follows its driver: once
/// the driver is closed it answers KARYOS_E_CLOSED, and is still closed
/// with karyos_conflated_close. KARYOS_E_INVALID_ARGUMENT for a stream id
/// the driver does not have, KARYOS_E_CONFLATION for a stream without a
/// table, KARYOS_E_CLOSED for a stream being removed or a closed driver; a
/// failure opens nothing.
///
/// # Safety
///
/// `conflated` points to a writable `uint64_t`; a null or misaligned one
/// returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_driver_subscribe_conflated(
    driver: u64,
    stream_id: i32,
    conflated: *mut u64,
) -> i32 {
    guard(|| {
        if !writable(conflated) {
            return Status::InvalidArgument;
        }
        match api::conflated::subscribe(Handle::from_raw(driver), stream_id) {
            Ok(handle) => {
                // SAFETY: `conflated` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { conflated.write(handle.raw()) };
                Status::Ok
            }
            Err(failure) => failure.status,
        }
    })
}

/// Adds a view of the conflation table of the karyos:ipc stream stream_id
/// to the client and writes its handle. A client attached to a driver in
/// another process takes it; a client of a driver in this process is
/// refused by its driver (KARYOS_E_REFUSED): take that view with
/// karyos_driver_subscribe_conflated. The view is the client's: closing the
/// client closes it, and its handle then answers KARYOS_E_CLOSED. There is
/// no options struct: its poll reads with the default retries, its table
/// must be within the default limits (2^20 keys, 64 KiB values, a 64 MiB
/// journal), and the key budget is each poll's. A control call: it waits
/// for the driver up to the client's timeout and holds the client handle
/// meanwhile. A failure opens nothing and fills detail (may be null);
/// another channel is KARYOS_E_UNSUPPORTED_CHANNEL.
///
/// # Safety
///
/// `uri` is a NUL-terminated string; `conflated` points to a writable
/// `uint64_t`; `detail` is null or a `karyos_detail` whose `size` is set.
/// A null `uri` or `conflated` returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_add_conflated_subscription(
    client: u64,
    uri: *const c_char,
    stream_id: i32,
    conflated: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(conflated) {
            return Status::InvalidArgument;
        }
        // SAFETY: the caller's contract on `uri`.
        let uri = match unsafe { read_str(uri) } {
            Ok(uri) => uri,
            Err(status) => return status,
        };
        match api::conflated::add(Handle::from_raw(client), uri, stream_id) {
            Ok(handle) => {
                // SAFETY: `conflated` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { conflated.write(handle.raw()) };
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

/// Delivers the latest value of at most key_budget changed keys to handler
/// and writes how many through delivered (may be null), also on failure.
/// Intermediate versions may be skipped; a key_budget of 0 delivers
/// nothing. A data-path call: it never waits and never allocates. Once the
/// table published a terminal invalidation the view is closed: that poll
/// and every later one return KARYOS_E_CLOSED. From the handler, polling
/// or closing this view returns KARYOS_E_REENTRANT.
///
/// # Safety
///
/// `handler` is null or a function of the `karyos_conflated_handler`
/// signature that returns normally; `context` is passed to it untouched;
/// `delivered` is null or points to a writable `uint32_t`. A null
/// `handler` returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_conflated_poll(
    conflated: u64,
    handler: ConflatedHandler,
    context: *mut c_void,
    key_budget: u32,
    delivered: *mut u32,
) -> i32 {
    guard(|| {
        let Some(handler) = handler else {
            return Status::InvalidArgument;
        };
        if !delivered.is_null() && !delivered.is_aligned() {
            return Status::InvalidArgument;
        }
        let mut call = |key: u32, value: &[u8], version: u64, freshness: u64| {
            // SAFETY: `handler` has the handler's signature and returns
            // normally (the caller's contract); `value` outlives the call,
            // which only reads it.
            unsafe {
                handler(
                    context,
                    key,
                    value.as_ptr(),
                    value.len(),
                    version,
                    freshness,
                )
            };
        };
        let (status, count) =
            match api::conflated::poll(Handle::from_raw(conflated), key_budget, &mut call) {
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

/// Closes the conflated subscription. A client's view is released to its
/// client, at once or at the client's next call while another call holds
/// the client (Threads, above).
#[unsafe(no_mangle)]
pub extern "C" fn karyos_conflated_close(conflated: u64) -> i32 {
    guard(
        || match api::conflated::close(Handle::from_raw(conflated)) {
            Ok(()) => Status::Ok,
            Err(status) => status,
        },
    )
}

/// Opens a client of the driver in this process and writes its handle. The
/// client follows its driver: KARYOS_E_INTERNAL once the driver is
/// poisoned, KARYOS_E_CLOSED once it is closed. A failed connect opens
/// nothing and fills detail (may be null).
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

/// Closes the driver, stopping its thread first. Its clients stay open,
/// answer KARYOS_E_CLOSED, and are closed with karyos_client_close. A
/// handle in use answers KARYOS_E_BUSY or KARYOS_E_REENTRANT, and nothing
/// is closed.
#[unsafe(no_mangle)]
pub extern "C" fn karyos_driver_close(driver: u64) -> i32 {
    guard(|| match driver::close(Handle::from_raw(driver)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

// Archive connections and their catalog listing (F9a; quantstratum-docs:
// karyos/design/ffi-archive.md).

/// `KARYOS_RECORDING_RECORDING`: the recording still records.
pub(crate) const RECORDING_RECORDING: u32 = 0;
/// `KARYOS_RECORDING_STOPPED`: the recording stopped.
pub(crate) const RECORDING_STOPPED: u32 = 1;

/// The size of the first `karyos_archive_options`.
const ARCHIVE_OPTIONS_SIZE_0_1: u32 = 32;

/// The control streams of an Archive and how a connection to it waits.
/// size is the caller's sizeof(karyos_archive_options); the library reads
/// the fields it knows of a newer struct, and the defaults past an older
/// one. reserved must be 0. client_id is this requester's id, at most
/// UINT32_MAX and unique among the Archive's requesters. deadline_ns is how
/// long a listing waits; 0 for the client's timeout.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArchiveOptions {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// Must be 0.
    pub reserved: u32,
    /// The Archive's request stream.
    pub requests: i32,
    /// The Archive's response stream.
    pub responses: i32,
    /// This requester's id, at most `UINT32_MAX`, unique among the
    /// Archive's requesters.
    pub client_id: u64,
    /// How long a listing waits, in nanoseconds; 0 for the client's
    /// timeout.
    pub deadline_ns: u64,
}

/// One recording of a listing, valid only during the handler call. size is
/// this version's sizeof(karyos_recording): a handler built against an
/// older header reads only the fields it knows. state is a
/// KARYOS_RECORDING_* value; stop_reason a KARYOS_STOP_* reason when
/// stopped, 0 while it records; incomplete 1 when the recording lost
/// ranges. start_time_ns is in nanoseconds since the Archive agent
/// started. position is the position written so far, or where it stopped.
/// channel holds channel_length bytes, not NUL-terminated.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Recording {
    /// The struct's size in bytes, set by the library.
    pub size: u32,
    /// `KARYOS_RECORDING_RECORDING` or `KARYOS_RECORDING_STOPPED`.
    pub state: u32,
    /// A `KARYOS_STOP_*` reason when stopped; 0 while it records.
    pub stop_reason: u32,
    /// 1 when the recording lost ranges, 0 otherwise.
    pub incomplete: u32,
    /// The recorded stream.
    pub stream_id: i32,
    /// The recorded session.
    pub session_id: i32,
    /// The recording's id, never 0.
    pub id: u64,
    /// Its first position.
    pub start: u64,
    /// When it started, in nanoseconds since the Archive agent started.
    pub start_time_ns: u64,
    /// The position written so far, or where it stopped.
    pub position: u64,
    /// The channel's bytes, not NUL-terminated, valid during the call.
    pub channel: *const c_char,
    /// The channel's length in bytes.
    pub channel_length: usize,
}

/// Called once per recording with the caller's context and the recording,
/// valid only during the call. It must return normally.
pub type RecordingHandler =
    Option<unsafe extern "C" fn(context: *mut c_void, recording: *const Recording)>;

/// The `KARYOS_STOP_*` code of `reason`; `None` for a reason a later
/// Archive version decodes, which has no code here (owner item 41).
pub(crate) fn stop_reason(reason: karyos_archive::catalog::StopReason) -> Option<u32> {
    use karyos_archive::catalog::{FailKind, StopReason};
    Some(match reason {
        StopReason::Normal => 1,
        StopReason::Recovered => 2,
        StopReason::Empty => 3,
        StopReason::Lapped => 4,
        StopReason::Stopped => 5,
        StopReason::Shutdown => 6,
        StopReason::Failed(FailKind::Source) => 7,
        StopReason::Failed(FailKind::RequiredLapped) => 8,
        StopReason::Failed(FailKind::Invalid) => 9,
        _ => return None,
    })
}

/// Whether the C ABI can state `listed`: [`recording`] converts it.
pub(crate) fn expressible(listed: &karyos_archive::client::list::ListedRecording) -> bool {
    recording(listed).is_some()
}

/// `listed` as the C ABI hands it to a handler; its channel borrows
/// `listed`'s. `None` for a state or stop reason a later Archive version
/// decodes, which has no code here (owner item 41).
fn recording(listed: &karyos_archive::client::list::ListedRecording) -> Option<Recording> {
    use karyos_archive::control::RecordingState;
    let (state, stop, incomplete, position) = match listed.state {
        RecordingState::Recording {
            written,
            incomplete,
        } => (RECORDING_RECORDING, 0, incomplete, written),
        RecordingState::Stopped(stop) => (
            RECORDING_STOPPED,
            stop_reason(stop.reason)?,
            stop.incomplete,
            stop.position,
        ),
        _ => return None,
    };
    Some(Recording {
        size: size_of_u32::<Recording>(),
        state,
        stop_reason: stop,
        incomplete: u32::from(incomplete),
        stream_id: listed.stream_id,
        session_id: listed.session_id,
        id: listed.recording_id,
        start: listed.start,
        start_time_ns: listed.start_time_ns,
        position,
        channel: listed.channel.as_ptr().cast::<c_char>(),
        channel_length: listed.channel.len(),
    })
}

/// Opens a connection of the client to the Archive whose control streams
/// options names, and writes its handle: a concurrent publication on its
/// request stream and an optional subscription on its response stream,
/// both the client's. Closing the client closes it. A control call: it
/// waits for the driver up to the client's timeout. A failed connect opens
/// nothing and fills detail (may be null); a client_id above UINT32_MAX or
/// a nonzero reserved is KARYOS_E_INVALID_ARGUMENT.
///
/// # Safety
///
/// `options` points to a readable `karyos_archive_options` whose `size` is
/// set; `archive` points to a writable `uint64_t`; `detail` is null or a
/// `karyos_detail` whose `size` is set. A null or misaligned `options` or
/// `archive`, or a `size` below the first version's (32), returns
/// `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_archive_connect(
    client: u64,
    options: *const ArchiveOptions,
    archive: *mut u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(archive) {
            return Status::InvalidArgument;
        }
        let defaults = ArchiveOptions {
            size: size_of_u32::<ArchiveOptions>(),
            reserved: 0,
            requests: 0,
            responses: 0,
            client_id: 0,
            deadline_ns: 0,
        };
        // SAFETY: the caller's contract on `options`.
        let raw = match unsafe { read_sized(options, ARCHIVE_OPTIONS_SIZE_0_1, defaults) } {
            Ok(raw) => raw,
            Err(status) => return status,
        };
        if raw.reserved != 0 {
            return Status::InvalidArgument;
        }
        let options = api::archive::Options {
            requests: raw.requests,
            responses: raw.responses,
            client_id: raw.client_id,
            deadline_ns: raw.deadline_ns,
        };
        match api::archive::connect(Handle::from_raw(client), options) {
            Ok(handle) => {
                // SAFETY: `archive` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { archive.write(handle.raw()) };
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

/// Lists the recordings of the Archive's catalog whose id is above
/// after_id, at most limit, handing each to handler in id order, and
/// writes how many through delivered (may be null), also on failure. Fewer
/// than limit means the catalog has no more; the next page starts after
/// the last id delivered. A limit of 0 delivers nothing. A control call: it
/// waits for the whole page up to the connection's deadline, then hands it
/// over. A page that does not arrive in time is KARYOS_E_TIMEOUT with
/// nothing delivered; an Archive's refusal is KARYOS_E_REFUSED with its
/// response code in detail's code (1 an error, 2 an unknown recording, 3
/// an unknown replay, 4 an invalid request, 5 an unsupported schema). From
/// the handler, any call on the connection or its client returns
/// KARYOS_E_REENTRANT; another thread's returns KARYOS_E_BUSY.
///
/// # Safety
///
/// `handler` is null or a function of the `karyos_recording_handler`
/// signature that returns normally; `context` is passed to it untouched;
/// `delivered` is null or points to a writable `uint32_t`; `detail` is
/// null or a `karyos_detail` whose `size` is set. A null `handler`
/// returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_archive_list(
    archive: u64,
    after_id: u64,
    limit: u32,
    handler: RecordingHandler,
    context: *mut c_void,
    delivered: *mut u32,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        let Some(handler) = handler else {
            return Status::InvalidArgument;
        };
        if !delivered.is_null() && !delivered.is_aligned() {
            return Status::InvalidArgument;
        }
        let mut call = |listed: &karyos_archive::client::list::ListedRecording| {
            // `api::archive::list` refuses a page holding a recording the C
            // ABI cannot state, before delivering any, and refuses the call
            // if this conversion still fails.
            let Some(recording) = recording(listed) else {
                return false;
            };
            // SAFETY: `handler` has the handler's signature and returns
            // normally (the caller's contract); `recording` and the
            // channel it points into outlive the call, which only reads
            // them.
            unsafe { handler(context, &raw const recording) };
            true
        };
        let (status, count) =
            match api::archive::list(Handle::from_raw(archive), after_id, limit, &mut call) {
                Ok(count) => (Status::Ok, count),
                Err(failure) => {
                    // SAFETY: the caller's contract on `detail`.
                    unsafe { write_detail(detail, failure) };
                    (failure.status, 0)
                }
            };
        if !delivered.is_null() {
            // SAFETY: `delivered` is non-null and aligned, and the caller's
            // contract makes it a writable `uint32_t`.
            unsafe { delivered.write(count) };
        }
        status
    })
}

/// Closes the Archive connection: its two streams are removed from its
/// client, at once or at the client's next call while another call holds
/// the client (Threads, above).
#[unsafe(no_mangle)]
pub extern "C" fn karyos_archive_close(archive: u64) -> i32 {
    guard(|| match api::archive::close(Handle::from_raw(archive)) {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

// Archive replays and how a subscription ended (F9c, B6; quantstratum-docs:
// karyos/design/archive-replay-control.md).

/// `KARYOS_REPLAY_FULL`: as fast as the target takes it.
pub(crate) const REPLAY_FULL: u32 = 1;
/// `KARYOS_REPLAY_AS_RECORDED`: at the recorded pace.
pub(crate) const REPLAY_AS_RECORDED: u32 = 2;
/// `KARYOS_REPLAY_SCALED`: the recorded pace scaled by `scale_ppm`.
pub(crate) const REPLAY_SCALED: u32 = 3;

/// The size of the first `karyos_replay_options`.
const REPLAY_OPTIONS_SIZE_0_1: u32 = 48;

/// What to replay, and where. Set size to sizeof(karyos_replay_options);
/// karyos_replay_options_init fills it and the defaults (the whole
/// recording from position 0 at full rate over karyos:ipc). The rule of
/// karyos_detail applies to its size.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReplayOptions {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// KARYOS_REPLAY_FULL, _AS_RECORDED or _SCALED.
    pub rate: u32,
    /// For KARYOS_REPLAY_SCALED, 1 to 100000000; 0 otherwise.
    pub scale_ppm: u32,
    /// The target stream.
    pub target_stream_id: i32,
    /// The recording, never 0.
    pub recording_id: u64,
    /// The first position replayed.
    pub position: u64,
    /// Bytes; UINT64_MAX to the recording's end.
    pub length: u64,
    /// NUL-terminated UTF-8 of 1 to 1024 bytes, read during the call; NULL
    /// for karyos:ipc.
    pub target_channel: *const c_char,
}

/// The defaults of `karyos_replay_options`: the whole recording from 0 at
/// full rate onto stream 0 over `karyos:ipc`.
fn default_replay_options() -> ReplayOptions {
    ReplayOptions {
        size: size_of_u32::<ReplayOptions>(),
        rate: REPLAY_FULL,
        scale_ppm: 0,
        target_stream_id: 0,
        recording_id: 0,
        position: 0,
        length: u64::MAX,
        target_channel: core::ptr::null(),
    }
}

/// As `karyos_replay_options_init_sized` with the size of `karyos_replay_options` in ABI 0.1.0, the
/// first: the symbol a binary built against an older header calls, which
/// writes no field that header lacks (owner item 48's option A, interim).
/// A caller built against this header calls the header's `static inline`
/// `karyos_replay_options_init`, which passes its own `sizeof`.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_replay_options` of at least that
/// size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_replay_options_init(options: *mut ReplayOptions) -> i32 {
    init_0_1(REPLAY_OPTIONS_SIZE_0_1, |size| {
        // SAFETY: the caller's contract on `options`, of at least the 0.1.0
        // size.
        unsafe { karyos_replay_options_init_sized(options, size) }
    })
}

/// Fills options with the defaults and its size.
///
/// # Safety
///
/// `options` is null or points to `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_replay_options_init_sized(
    options: *mut ReplayOptions,
    size: usize,
) -> i32 {
    guard(|| {
        let filled = default_replay_options();
        // SAFETY: the caller's contract on `options` and `size`.
        unsafe { init_sized(options, size, REPLAY_OPTIONS_SIZE_0_1, filled) }
    })
}

/// The replay spec `raw` asks for; its channel is read during the call.
///
/// # Safety
///
/// `raw.target_channel` is null or a NUL-terminated string.
unsafe fn replay_spec(
    raw: &ReplayOptions,
) -> Result<karyos_archive::client::replay::ReplaySpec, Status> {
    use karyos_archive::control::{MAX_CHANNEL, MAX_SCALE_PPM, ReplayRate};
    let rate = match (raw.rate, raw.scale_ppm) {
        (REPLAY_FULL, 0) => ReplayRate::Full,
        (REPLAY_AS_RECORDED, 0) => ReplayRate::AsRecorded,
        (REPLAY_SCALED, ppm) if (1..=MAX_SCALE_PPM).contains(&ppm) => ReplayRate::Scaled { ppm },
        _ => return Err(Status::InvalidArgument),
    };
    if raw.recording_id == 0 {
        return Err(Status::InvalidArgument);
    }
    let mut spec = karyos_archive::client::replay::ReplaySpec::new(
        raw.recording_id,
        raw.position,
        raw.target_stream_id,
    );
    spec.length = raw.length;
    spec.rate = rate;
    if !raw.target_channel.is_null() {
        // SAFETY: the caller's contract on the channel.
        let channel = unsafe { read_str(raw.target_channel) }?;
        if channel.is_empty() || channel.len() > MAX_CHANNEL {
            return Err(Status::InvalidArgument);
        }
        channel.clone_into(&mut spec.target_channel);
    }
    Ok(spec)
}

/// Starts a replay on the Archive connection of what options names, and
/// writes its id and its target's session id. The target is a replay
/// target at options' target_stream_id and that session, exclusive to its
/// first reader: karyos_client_add_replay_subscription takes it. A
/// replay's end is its target's seal, which karyos_subscription_end_state reads;
/// no answer tells the requester.
///
/// A control call (Threads, above): it serves the client and waits for the
/// Archive's answer up to the connection's deadline, holding the client,
/// then the Archive handle. From a subscription's poll handler, which
/// holds only its subscription, it is allowed but blocks that poll up to
/// the deadline, so avoid it. The connection's first replay call opens
/// control streams of its own, with the next requester id the connection
/// hands out: a host with no publisher left on its request stream refuses
/// it (KARYOS_E_REFUSED).
///
/// An Archive's refusal is KARYOS_E_REFUSED with its response code in
/// detail's code (as karyos_archive_list's); no answer in time is
/// KARYOS_E_TIMEOUT, and a replay its late answer started is stopped; 16
/// of the connection's requests waiting is KARYOS_E_BUSY, as a held handle
/// is (poll the client and call again). A recording_id of 0, a rate and
/// scale_ppm that do not match, or a channel that is not UTF-8 of 1 to
/// 1024 bytes is KARYOS_E_INVALID_ARGUMENT.
///
/// # Safety
///
/// `options` points to a readable `karyos_replay_options` whose `size` is
/// set and whose `target_channel` is null or NUL-terminated; `replay_id`
/// points to a writable `uint64_t` and `session_id` to a writable
/// `int32_t`; `detail` is null or a `karyos_detail` whose `size` is set. A
/// null or misaligned `options`, `replay_id` or `session_id`, or a `size`
/// below the first version's (48), returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_archive_replay(
    archive: u64,
    options: *const ReplayOptions,
    replay_id: *mut u64,
    session_id: *mut i32,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if !writable(replay_id) || !writable(session_id) {
            return Status::InvalidArgument;
        }
        // SAFETY: the caller's contract on `options`.
        let raw =
            match unsafe { read_sized(options, REPLAY_OPTIONS_SIZE_0_1, default_replay_options()) }
            {
                Ok(raw) => raw,
                Err(status) => return status,
            };
        // SAFETY: the caller's contract on the channel.
        let spec = match unsafe { replay_spec(&raw) } {
            Ok(spec) => spec,
            Err(status) => return status,
        };
        match api::archive::replay(Handle::from_raw(archive), &spec) {
            Ok((id, session)) => {
                // SAFETY: `replay_id` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { replay_id.write(id) };
                // SAFETY: `session_id` is non-null and aligned, and the
                // caller's contract makes it a writable `int32_t`.
                unsafe { session_id.write(session) };
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

/// Stops the replay; its target seals as an image retired. A control call,
/// as karyos_archive_replay: a replay the Archive does not run (ended, or
/// never started) is KARYOS_E_REFUSED with code 3 (an unknown replay) in
/// detail.
///
/// # Safety
///
/// `detail` is null or a `karyos_detail` whose `size` is set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_archive_stop_replay(
    archive: u64,
    replay_id: u64,
    detail: *mut Detail,
) -> i32 {
    guard(|| {
        if replay_id == 0 {
            return Status::InvalidArgument;
        }
        match api::archive::stop_replay(Handle::from_raw(archive), replay_id) {
            Ok(()) => Status::Ok,
            Err(failure) => {
                // SAFETY: the caller's contract on `detail`.
                unsafe { write_detail(detail, failure) };
                failure.status
            }
        }
    })
}

/// The size of the first `karyos_replay_subscription_options`.
const REPLAY_SUBSCRIPTION_OPTIONS_SIZE_0_1: u32 = 8;

/// A replay subscription's options: at ABI 0.1 only its size and a
/// reserved word, so later fields grow it without a new function. Set size
/// to sizeof(karyos_replay_subscription_options);
/// karyos_replay_subscription_options_init fills it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReplaySubscriptionOptions {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// Must be 0.
    pub reserved: u32,
}

/// As `karyos_replay_subscription_options_init_sized` with the size of `karyos_replay_subscription_options` in ABI 0.1.0, the
/// first: the symbol a binary built against an older header calls, which
/// writes no field that header lacks (owner item 48's option A, interim).
/// A caller built against this header calls the header's `static inline`
/// `karyos_replay_subscription_options_init`, which passes its own `sizeof`.
///
/// # Safety
///
/// `options` is null or points to a writable `karyos_replay_subscription_options` of at least that
/// size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_replay_subscription_options_init(
    options: *mut ReplaySubscriptionOptions,
) -> i32 {
    init_0_1(REPLAY_SUBSCRIPTION_OPTIONS_SIZE_0_1, |size| {
        // SAFETY: the caller's contract on `options`, of at least the 0.1.0
        // size.
        unsafe { karyos_replay_subscription_options_init_sized(options, size) }
    })
}

/// Fills options with the defaults and its size.
///
/// # Safety
///
/// `options` is null or points to `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_replay_subscription_options_init_sized(
    options: *mut ReplaySubscriptionOptions,
    size: usize,
) -> i32 {
    guard(|| {
        let filled = ReplaySubscriptionOptions {
            size: size_of_u32::<ReplaySubscriptionOptions>(),
            reserved: 0,
        };
        // SAFETY: the caller's contract on `options` and `size`.
        unsafe { init_sized(options, size, REPLAY_SUBSCRIPTION_OPTIONS_SIZE_0_1, filled) }
    })
}

/// Adds the subscription of the replay target at stream_id and session_id
/// (as karyos_archive_replay named them) to the client and writes its
/// handle. KARYOS_E_NOT_CONNECTED until the target's grant: a
/// karyos_client_poll completes it, in both driver modes (a started
/// embedded driver never polls a client), and the caller then calls
/// again. One target is asked for at a time per client: asking for
/// another withdraws the one asked for before. options may be NULL for the
/// defaults. The subscription is the client's and polls as any other. A
/// control call: it holds the client handle.
///
/// # Safety
///
/// `options` is null (the defaults) or points to a readable
/// `karyos_replay_subscription_options` whose `size` is set (at least 8,
/// `reserved` 0); `subscription` points to a writable `uint64_t`.
/// Anything else returns `KARYOS_E_INVALID_ARGUMENT`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_client_add_replay_subscription(
    client: u64,
    stream_id: i32,
    session_id: i32,
    options: *const ReplaySubscriptionOptions,
    subscription: *mut u64,
) -> i32 {
    guard(|| {
        if !writable(subscription) {
            return Status::InvalidArgument;
        }
        if !options.is_null() {
            let defaults = ReplaySubscriptionOptions {
                size: size_of_u32::<ReplaySubscriptionOptions>(),
                reserved: 0,
            };
            // SAFETY: the caller's contract on `options`.
            match unsafe { read_sized(options, REPLAY_SUBSCRIPTION_OPTIONS_SIZE_0_1, defaults) } {
                Ok(raw) if raw.reserved == 0 => {}
                Ok(_) => return Status::InvalidArgument,
                Err(status) => return status,
            }
        }
        match api::subscription::add_replay(Handle::from_raw(client), stream_id, session_id) {
            Ok(handle) => {
                // SAFETY: `subscription` is non-null and aligned, and the
                // caller's contract makes it a writable `uint64_t`.
                unsafe { subscription.write(handle.raw()) };
                Status::Ok
            }
            Err(failure) => failure.status,
        }
    })
}

/// `KARYOS_END_NONE`: the subscription has not ended.
pub(crate) const END_NONE: u32 = 0;
/// `KARYOS_END_END_OF_STREAM`: its stream ended cleanly (a replay that
/// reached its end, a remote publication's EOS).
pub(crate) const END_END_OF_STREAM: u32 = 1;
/// `KARYOS_END_IMAGE_RETIRED`: its image retired without a complete end
/// (a stopped or failed replay).
pub(crate) const END_IMAGE_RETIRED: u32 = 2;
/// `KARYOS_END_STREAM_REMOVED`: its stream was removed.
pub(crate) const END_STREAM_REMOVED: u32 = 3;
/// `KARYOS_END_REVOKED`: revoked with its client's loss.
pub(crate) const END_REVOKED: u32 = 4;
/// `KARYOS_END_CLOSED_BY_OVERRUN`: closed by its rejoin policy.
pub(crate) const END_CLOSED_BY_OVERRUN: u32 = 5;
/// `KARYOS_END_OTHER`: any other end, a reason a later core adds
/// included; `seal_code` keeps the raw seal reason.
pub(crate) const END_OTHER: u32 = 255;

/// The size of the first `karyos_subscription_end`.
const SUBSCRIPTION_END_SIZE_0_1: u32 = 24;

/// How a subscription ended. Set size to sizeof(karyos_subscription_end);
/// the rule of karyos_detail applies.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubscriptionEnd {
    /// The struct's size in bytes, set by the caller.
    pub size: u32,
    /// A KARYOS_END_* code.
    pub reason: u32,
    /// The seal's position, a revoked reader's position, or an overrun's
    /// first position not delivered; 0 while it has not ended.
    pub position: u64,
    /// The seal's raw reason code for a sealed end; 0 otherwise.
    pub seal_code: u64,
}

/// The `KARYOS_END_*` code, position and seal code of `end`.
pub(crate) fn end_fields(end: Option<api::subscription::End>) -> (u32, u64, u64) {
    use api::subscription::End;
    use karyos_sys::log_buffer::SealReason;
    match end {
        None => (END_NONE, 0, 0),
        Some(End::Sealed { reason, position }) => {
            let code = match reason {
                SealReason::EndOfStream => END_END_OF_STREAM,
                SealReason::ImageRetired => END_IMAGE_RETIRED,
                SealReason::StreamRemoved => END_STREAM_REMOVED,
                _ => END_OTHER,
            };
            (code, position, reason.code())
        }
        Some(End::Revoked { position }) => (END_REVOKED, position, 0),
        Some(End::ClosedByOverrun { position }) => (END_CLOSED_BY_OVERRUN, position, 0),
    }
}

/// Writes how the subscription ended: KARYOS_END_NONE while it has not,
/// else the end a poll saw when it answered KARYOS_E_CLOSED or
/// KARYOS_E_CLOSED_BY_OVERRUN. A stream that ends cleanly also flags its
/// last message KARYOS_MESSAGE_END_OF_STREAM; this call gives the reason
/// and position of every end, one no message carries (an image retired)
/// included. A network subscription outlives its images, whose ends its
/// image changes report, and reads KARYOS_END_NONE. A data-path call: it
/// never waits. A size below 24 is KARYOS_E_INVALID_ARGUMENT.
///
/// # Safety
///
/// `end` points to a writable `karyos_subscription_end` whose `size` is
/// set; a null or misaligned one, or a `size` below 24, returns
/// `KARYOS_E_INVALID_ARGUMENT` with nothing written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn karyos_subscription_end_state(
    subscription: u64,
    end: *mut SubscriptionEnd,
) -> i32 {
    guard(|| {
        if !writable(end) {
            return Status::InvalidArgument;
        }
        // SAFETY: `end` is non-null and aligned, and points to the caller's
        // struct (its contract), whose first field is the size.
        if unsafe { end.cast::<u32>().read() } < SUBSCRIPTION_END_SIZE_0_1 {
            return Status::InvalidArgument;
        }
        let fields = match api::subscription::end(Handle::from_raw(subscription)) {
            Ok(ended) => end_fields(ended),
            Err(status) => return status,
        };
        // SAFETY: the caller's contract on `end`, whose size was read above.
        unsafe { write_subscription_end(end, fields) };
        Status::Ok
    })
}

/// Writes `fields` through `end` by its size: the sized write of
/// `karyos_subscription_end_state`, apart so that it runs under Miri with no
/// driver.
///
/// # Safety
///
/// `end` is non-null, aligned and points to a writable
/// `karyos_subscription_end` of at least its `size` bytes.
unsafe fn write_subscription_end(
    end: *mut SubscriptionEnd,
    (reason, position, seal_code): (u32, u64, u64),
) {
    // The caller's size stays, as every sized output's does.
    let filled = |size| SubscriptionEnd {
        size,
        reason,
        position,
        seal_code,
    };
    // SAFETY: the caller's contract on `end`.
    unsafe { write_sized(end, SUBSCRIPTION_END_SIZE_0_1, filled) };
}

#[cfg(test)]
mod tests;
