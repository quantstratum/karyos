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
unsafe fn write_accepted(out: *mut Accepted, accepted: karyos_client::Accepted) {
    // SAFETY: the caller's contract, passed on.
    unsafe {
        write_sized(out, ACCEPTED_SIZE_0_1, |size| Accepted {
            size,
            lane: u32::from(accepted.lane().get()),
            position: accepted.position(),
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
    guard(|| {
        if !writable(publication) {
            return Status::InvalidArgument;
        }
        // SAFETY: the caller's contract on `uri`.
        let uri = match unsafe { read_str(uri) } {
            Ok(uri) => uri,
            Err(status) => return status,
        };
        match api::publication::add(Handle::from_raw(client), uri, stream_id) {
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

#[cfg(test)]
mod tests;
