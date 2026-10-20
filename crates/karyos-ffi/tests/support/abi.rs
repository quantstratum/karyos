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

/// `karyos_accepted`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Accepted {
    pub size: u32,
    pub lane: u32,
    pub position: u64,
}

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
    fn karyos_publication_claim(
        publication: u64,
        lane: u32,
        length: u32,
        claim: *mut u64,
        buffer: *mut *mut u8,
    ) -> i32;
    fn karyos_claim_commit(claim: u64, accepted: *mut core::ffi::c_void) -> i32;
    safe fn karyos_claim_abort(claim: u64) -> i32;
    safe fn karyos_publication_close(publication: u64) -> i32;
}

/// The byte every part of a [`SizedStruct`] the caller did not set holds:
/// its tail past this header's struct, and for an output struct every field
/// but its size.
pub const SENTINEL: u8 = 0xA5;

/// A caller's `T` as a header of another minor version lays it out: its
/// size field says `size`, which may be below or above `size_of::<T>()`,
/// and it lies in `size_of::<T>()` plus at least sixteen bytes of
/// 8-aligned memory. The first `size_of::<T>()` bytes hold `value` (or the
/// sentinel, for an output), and every byte past them holds the sentinel,
/// so a library that reads or writes past its own prefix is seen.
#[derive(Debug)]
pub struct SizedStruct<T> {
    words: Vec<u64>,
    _of: core::marker::PhantomData<T>,
}

impl<T: Copy> SizedStruct<T> {
    /// `value`, or the sentinel for an output, with size field `size`.
    /// `T` must have no padding bytes, as every struct of this module.
    pub fn new(value: Option<&T>, size: u32) -> Self {
        // A `u32` size plus sixteen fits a `usize` on every target the
        // library supports.
        let bytes =
            usize::try_from(size).map_or(size_of::<T>(), |size| size.max(size_of::<T>())) + 16;
        let mut words = vec![u64::from_ne_bytes([SENTINEL; 8]); bytes.div_ceil(8)];
        let base = words.as_mut_ptr().cast::<u8>();
        if let Some(value) = value {
            // SAFETY: `words` holds at least `size_of::<T>()` bytes and is
            // 8-aligned, which covers `T`'s alignment (a C struct of
            // integers and pointers); `value` does not overlap it. `T` has
            // no padding bytes, so every byte read is initialized: each
            // struct of this module lays its fields out in size order
            // with no gap (callers pass only those).
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::from_ref(value).cast::<u8>(),
                    base,
                    size_of::<T>(),
                );
            }
        }
        // SAFETY: the size is the struct's first field, a `u32` at offset
        // 0 of the aligned words.
        unsafe { base.cast::<u32>().write(size) };
        Self {
            words,
            _of: core::marker::PhantomData,
        }
    }

    /// The struct, for an input.
    pub fn as_ptr(&self) -> *const T {
        self.words.as_ptr().cast()
    }

    /// The struct, for an output.
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.words.as_mut_ptr().cast()
    }

    /// Every byte.
    fn bytes(&self) -> Vec<u8> {
        self.words
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .collect()
    }

    /// Sets byte `offset` to `byte`, as a library's write would: for the
    /// runner's self-test.
    pub fn poke(&mut self, offset: usize, byte: u8) {
        if let Some(word) = self.words.get_mut(offset / 8) {
            let mut bytes = word.to_ne_bytes();
            if let Some(slot) = bytes.get_mut(offset % 8) {
                *slot = byte;
            }
            *word = u64::from_ne_bytes(bytes);
        }
    }

    /// Whether every byte past this header's struct still holds the
    /// sentinel.
    pub fn tail_intact(&self) -> bool {
        self.bytes()
            .get(size_of::<T>()..)
            .is_some_and(|tail| tail.iter().all(|byte| *byte == SENTINEL))
    }

    /// The `N` bytes at `offset` within this header's struct, unless they
    /// still hold the sentinel: the field was not written.
    pub fn written<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        let field: [u8; N] = self
            .bytes()
            .get(offset..offset.checked_add(N)?)?
            .try_into()
            .ok()?;
        (field != [SENTINEL; N]).then_some(field)
    }
}

/// A `karyos_accepted` of size `size` filled with the sentinel.
pub fn accepted(size: u32) -> SizedStruct<Accepted> {
    SizedStruct::new(None, size)
}

/// `karyos_accepted`'s lane and position, when the library wrote them.
pub fn accepted_fields(accepted: &SizedStruct<Accepted>) -> Option<(u32, u64)> {
    let lane = accepted.written::<4>(4)?;
    let position = accepted.written::<8>(8)?;
    Some((u32::from_ne_bytes(lane), u64::from_ne_bytes(position)))
}

/// `karyos_detail`'s code and value, when the library wrote them.
pub fn detail_fields(detail: &SizedStruct<Detail>) -> Option<(u64, u64)> {
    let code = detail.written::<8>(8)?;
    let value = detail.written::<8>(16)?;
    Some((u64::from_ne_bytes(code), u64::from_ne_bytes(value)))
}

/// `karyos_driver_create` with `options` sized as `size`: the status and
/// the handle.
pub fn driver_create_sized(options: &DriverOptions, size: u32) -> (i32, u64) {
    let options = SizedStruct::new(Some(options), size);
    let mut driver = 0;
    // SAFETY: a struct of at least `size` readable bytes and a live,
    // aligned `u64`; a null detail is allowed.
    let status =
        unsafe { karyos_driver_create(options.as_ptr(), &mut driver, core::ptr::null_mut()) };
    (status, driver)
}

/// `karyos_driver_add_stream` with `options` sized as `size`.
pub fn driver_add_stream_sized(driver: u64, options: &StreamOptions, size: u32) -> i32 {
    let options = SizedStruct::new(Some(options), size);
    // SAFETY: a struct of at least `size` readable bytes; a null detail is
    // allowed.
    unsafe { karyos_driver_add_stream(driver, options.as_ptr(), core::ptr::null_mut()) }
}

/// `karyos_client_connect` with the default options sized as `size` and no
/// directory: the status.
pub fn client_connect_sized(size: u32) -> i32 {
    let mut options = core::mem::MaybeUninit::<ClientOptions>::zeroed();
    // SAFETY: a live, aligned, writable `ClientOptions`.
    let status = unsafe { karyos_client_options_init(options.as_mut_ptr()) };
    assert_eq!(status, 0);
    // SAFETY: `karyos_client_options_init` wrote every field.
    let options = SizedStruct::new(Some(&unsafe { options.assume_init() }), size);
    let mut client = 0;
    // SAFETY: a struct of at least `size` readable bytes whose `dir` is
    // null, and a live, aligned `u64`; a null detail is allowed.
    unsafe { karyos_client_connect(options.as_ptr(), &mut client, core::ptr::null_mut()) }
}

/// `karyos_client_add_publication` of `stream_id` on `uri`, with a detail
/// sized as `detail_size`: the status, the handle and the detail.
pub fn client_add_publication(
    client: u64,
    uri: &CStr,
    stream_id: i32,
    detail_size: u32,
) -> (i32, u64, SizedStruct<Detail>) {
    let mut publication = 0;
    let mut detail = SizedStruct::<Detail>::new(None, detail_size);
    // SAFETY: a live C string, a live, aligned `u64` and a detail of at
    // least `detail_size` writable bytes.
    let status = unsafe {
        karyos_client_add_publication(
            client,
            uri.as_ptr(),
            stream_id,
            &mut publication,
            detail.as_mut_ptr(),
        )
    };
    (status, publication, detail)
}

/// `karyos_publication_offer` of `data` on `lane`, with an accepted sized
/// as `accepted_size`: the status and the accepted.
pub fn publication_offer_on(
    publication: u64,
    lane: u32,
    data: &[u8],
    accepted_size: u32,
) -> (i32, SizedStruct<Accepted>) {
    let mut accepted = accepted(accepted_size);
    // SAFETY: `data` is live for the call; `accepted` holds at least
    // `accepted_size` writable bytes.
    let status = unsafe {
        karyos_publication_offer(
            publication,
            lane,
            data.as_ptr(),
            data.len(),
            accepted.as_mut_ptr().cast(),
        )
    };
    (status, accepted)
}

/// `karyos_publication_claim` of `length` bytes on `lane`: the status and
/// the claim's handle.
pub fn publication_claim(publication: u64, lane: u32, length: u32) -> (i32, u64) {
    let mut claim = 0;
    let mut buffer = core::ptr::null_mut();
    // SAFETY: a live, aligned `u64` and pointer.
    let status =
        unsafe { karyos_publication_claim(publication, lane, length, &mut claim, &mut buffer) };
    (status, claim)
}

/// `karyos_claim_commit`, with an accepted sized as `accepted_size`: the
/// status and the accepted.
pub fn claim_commit(claim: u64, accepted_size: u32) -> (i32, SizedStruct<Accepted>) {
    let mut accepted = accepted(accepted_size);
    // SAFETY: `accepted` holds at least `accepted_size` writable bytes.
    let status = unsafe { karyos_claim_commit(claim, accepted.as_mut_ptr().cast()) };
    (status, accepted)
}

/// `karyos_claim_abort`.
pub fn claim_abort(claim: u64) -> i32 {
    karyos_claim_abort(claim)
}

/// `karyos_publication_close`.
pub fn publication_close(publication: u64) -> i32 {
    karyos_publication_close(publication)
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
