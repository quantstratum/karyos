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

/// `karyos_client_options`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    pub size: u32,
    pub idle_strategy: u32,
    pub dir: *const c_char,
    pub idle_sleep_ns: u64,
    pub timeout_ns: u64,
    pub max_pending: u32,
    pub max_images: u32,
}

/// `karyos_driver_options`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverOptions {
    pub size: u32,
    pub max_clients: u32,
    pub max_streams: u32,
    pub max_pending_per_client: u32,
    pub ring_capacity: u32,
    pub broadcast_capacity: u32,
    pub counters_capacity: u32,
    pub reserved: u32,
    pub heartbeat_interval_ns: u64,
    pub client_liveness_timeout_ns: u64,
    pub cutover_deadline_ns: u64,
}

/// `karyos_stream_options`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StreamOptions {
    pub size: u32,
    pub stream_id: i32,
    pub term_length: u32,
    pub mtu: u32,
    pub max_reserved: u32,
    pub spare_slots: u32,
    pub max_subscribers: u32,
    pub session_id: i32,
    pub initial_term_id: u32,
    pub lane: u32,
    pub publication_mode: u32,
    pub allow_unconnected: u32,
    pub schedule_capacity: u32,
    pub on_required_loss: u32,
    pub claim_deadline_ns: u64,
}

/// `karyos_detail`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Detail {
    pub size: u32,
    pub reserved: u32,
    pub code: u64,
    pub value: u64,
}

/// `karyos_outcome`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Outcome {
    pub size: u32,
    pub kind: u32,
    pub lane: u32,
    pub receiver: u32,
    pub sequence: u64,
    pub incarnation: u64,
    pub start: u64,
    pub end: u64,
    pub epoch: u64,
    pub reason: u64,
    pub lost: u64,
}

/// `karyos_outcome_handler`.
type OutcomeHandler = unsafe extern "C" fn(*mut core::ffi::c_void, *const Outcome);

unsafe extern "C" {
    fn karyos_abi_version(major: *mut u32, minor: *mut u32, patch: *mut u32) -> i32;
    safe fn karyos_status_message(status: i32) -> *const c_char;
    fn karyos_client_options_init(options: *mut ClientOptions) -> i32;
    fn karyos_client_connect(
        options: *const ClientOptions,
        client: *mut u64,
        detail: *mut Detail,
    ) -> i32;
    fn karyos_client_poll(client: u64, served: *mut u32) -> i32;
    safe fn karyos_client_close(client: u64) -> i32;
    fn karyos_driver_options_init(options: *mut DriverOptions) -> i32;
    fn karyos_driver_create(
        options: *const DriverOptions,
        driver: *mut u64,
        detail: *mut Detail,
    ) -> i32;
    fn karyos_driver_do_work(driver: u64, work: *mut u32) -> i32;
    safe fn karyos_driver_start(driver: u64, idle_strategy: u32, idle_sleep_ns: u64) -> i32;
    safe fn karyos_driver_stop(driver: u64) -> i32;
    fn karyos_driver_connect(driver: u64, client: *mut u64, detail: *mut Detail) -> i32;
    safe fn karyos_driver_close(driver: u64) -> i32;
    fn karyos_stream_options_init(options: *mut StreamOptions) -> i32;
    fn karyos_driver_add_stream(
        driver: u64,
        options: *const StreamOptions,
        detail: *mut Detail,
    ) -> i32;
    safe fn karyos_driver_remove_stream(driver: u64, stream_id: i32) -> i32;
    fn karyos_client_add_publication(
        client: u64,
        uri: *const c_char,
        stream_id: i32,
        publication: *mut u64,
        detail: *mut Detail,
    ) -> i32;
    fn karyos_publication_offer(
        publication: u64,
        lane: u32,
        data: *const u8,
        length: usize,
        accepted: *mut core::ffi::c_void,
    ) -> i32;
    fn karyos_publication_poll_outcomes(
        publication: u64,
        lane: u32,
        handler: Option<OutcomeHandler>,
        context: *mut core::ffi::c_void,
        limit: u32,
        delivered: *mut u32,
    ) -> i32;
    safe fn karyos_publication_close(publication: u64) -> i32;
}

/// `karyos_stream_options_init` with `stream_id` set: the status and the
/// options.
pub fn stream_options(stream_id: i32) -> (i32, StreamOptions) {
    let mut options = core::mem::MaybeUninit::<StreamOptions>::zeroed();
    // SAFETY: a live, aligned, writable `StreamOptions`.
    let status = unsafe { karyos_stream_options_init(options.as_mut_ptr()) };
    // SAFETY: zeroed, then written in full on success; every field is an
    // integer, so the zeroes are a value too.
    let mut options = unsafe { options.assume_init() };
    options.stream_id = stream_id;
    (status, options)
}

/// `karyos_driver_add_stream`: the status and the detail.
pub fn driver_add_stream(driver: u64, options: &StreamOptions) -> (i32, Detail) {
    let mut detail = Detail {
        size: u32::try_from(size_of::<Detail>()).unwrap_or(u32::MAX),
        ..Detail::default()
    };
    // SAFETY: live, aligned pointers.
    let status = unsafe { karyos_driver_add_stream(driver, options, &mut detail) };
    (status, detail)
}

/// `karyos_driver_remove_stream`.
pub fn driver_remove_stream(driver: u64, stream_id: i32) -> i32 {
    karyos_driver_remove_stream(driver, stream_id)
}

/// `karyos_client_add_publication` of `stream_id` on `karyos:ipc`: the
/// status and the handle.
pub fn client_add_ipc_publication(client: u64, stream_id: i32) -> (i32, u64) {
    let mut publication = 0;
    // SAFETY: a static C string and a live, aligned `u64`; a null detail
    // is allowed.
    let status = unsafe {
        karyos_client_add_publication(
            client,
            c"karyos:ipc".as_ptr(),
            stream_id,
            &mut publication,
            core::ptr::null_mut(),
        )
    };
    (status, publication)
}

/// `karyos_publication_offer` of `data` on lane 0, without the accepted
/// position.
pub fn publication_offer(publication: u64, data: &[u8]) -> i32 {
    // SAFETY: `data` is live for the call; a null `accepted` is allowed.
    unsafe {
        karyos_publication_offer(
            publication,
            0,
            data.as_ptr(),
            data.len(),
            core::ptr::null_mut(),
        )
    }
}

/// `karyos_driver_options_init`: the status and the options.
pub fn driver_options() -> (i32, DriverOptions) {
    let mut options = core::mem::MaybeUninit::<DriverOptions>::zeroed();
    // SAFETY: a live, aligned, writable `DriverOptions`.
    let status = unsafe { karyos_driver_options_init(options.as_mut_ptr()) };
    // SAFETY: zeroed, then written in full on success; every field is an
    // integer, so the zeroes are a value too.
    (status, unsafe { options.assume_init() })
}

/// `karyos_driver_create` of `options`: the status, the handle and the
/// detail.
pub fn driver_create_with(options: &DriverOptions) -> (i32, u64, Detail) {
    let mut driver = 0;
    let mut detail = Detail {
        size: u32::try_from(size_of::<Detail>()).unwrap_or(u32::MAX),
        ..Detail::default()
    };
    // SAFETY: live, aligned pointers.
    let status = unsafe { karyos_driver_create(options, &mut driver, &mut detail) };
    (status, driver, detail)
}

/// `karyos_driver_create` with the defaults: the status and the handle.
pub fn driver_create() -> (i32, u64) {
    let (status, options) = driver_options();
    assert_eq!(status, 0);
    let (status, driver, _) = driver_create_with(&options);
    (status, driver)
}

/// `karyos_driver_do_work`: the status and the work count.
pub fn driver_do_work(driver: u64) -> (i32, u32) {
    let mut work = u32::MAX;
    // SAFETY: a live, aligned `u32`.
    let status = unsafe { karyos_driver_do_work(driver, &mut work) };
    (status, work)
}

/// `karyos_driver_start`.
pub fn driver_start(driver: u64, idle_strategy: u32, idle_sleep_ns: u64) -> i32 {
    karyos_driver_start(driver, idle_strategy, idle_sleep_ns)
}

/// `karyos_driver_stop`.
pub fn driver_stop(driver: u64) -> i32 {
    karyos_driver_stop(driver)
}

/// `karyos_driver_connect`: the status and the client handle.
pub fn driver_connect(driver: u64) -> (i32, u64) {
    let mut client = 0;
    // SAFETY: a live, aligned `u64`; a null detail is allowed.
    let status = unsafe { karyos_driver_connect(driver, &mut client, core::ptr::null_mut()) };
    (status, client)
}

/// `karyos_driver_close`.
pub fn driver_close(driver: u64) -> i32 {
    karyos_driver_close(driver)
}

/// `karyos_client_connect` to the driver in `dir`, with the defaults
/// otherwise: the status, the handle and the detail.
pub fn client_connect(dir: &CStr) -> (i32, u64, Detail) {
    let mut options = core::mem::MaybeUninit::<ClientOptions>::zeroed();
    // SAFETY: a live, aligned, writable `ClientOptions`.
    let status = unsafe { karyos_client_options_init(options.as_mut_ptr()) };
    assert_eq!(status, 0);
    // SAFETY: `karyos_client_options_init` wrote every field.
    let mut options = unsafe { options.assume_init() };
    options.dir = dir.as_ptr();
    options.timeout_ns = 5_000_000_000;
    let mut client = 0;
    let mut detail = Detail {
        size: u32::try_from(size_of::<Detail>()).unwrap_or(u32::MAX),
        ..Detail::default()
    };
    // SAFETY: live, aligned pointers; `dir` outlives the call.
    let status = unsafe { karyos_client_connect(&options, &mut client, &mut detail) };
    (status, client, detail)
}

/// `karyos_client_poll`: the status and `served`.
pub fn client_poll(client: u64) -> (i32, u32) {
    let mut served = u32::MAX;
    // SAFETY: a live, aligned `u32`.
    let status = unsafe { karyos_client_poll(client, &mut served) };
    (status, served)
}

/// `karyos_client_close`.
pub fn client_close(client: u64) -> i32 {
    karyos_client_close(client)
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

/// Appends each record to the `Vec<Outcome>` at `context`.
unsafe extern "C" fn collect(context: *mut core::ffi::c_void, outcome: *const Outcome) {
    // SAFETY: the library hands a live `Outcome` for the call.
    let outcome = unsafe { *outcome };
    // SAFETY: `publication_poll_outcomes` passes a live `Vec<Outcome>`.
    unsafe { (*context.cast::<Vec<Outcome>>()).push(outcome) };
}

/// `karyos_publication_poll_outcomes` of `lane`: the status, the count
/// written and the records handed to the handler.
pub fn publication_poll_outcomes(
    publication: u64,
    lane: u32,
    limit: u32,
) -> (i32, u32, Vec<Outcome>) {
    let mut records = Vec::new();
    let mut delivered = u32::MAX;
    // SAFETY: `collect` returns normally and reads the live `records`;
    // `delivered` is a live, aligned `u32`.
    let status = unsafe {
        karyos_publication_poll_outcomes(
            publication,
            lane,
            Some(collect),
            core::ptr::from_mut(&mut records).cast(),
            limit,
            &mut delivered,
        )
    };
    (status, delivered, records)
}

/// `karyos_publication_close`.
pub fn publication_close(publication: u64) -> i32 {
    karyos_publication_close(publication)
}
