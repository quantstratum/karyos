// SPDX-License-Identifier: Apache-2.0

//! The exported client functions over an embedded driver's conductor, so
//! they run under Miri and on macOS (quantstratum-docs:
//! karyos/design/ffi-gap-analysis.md §4.7).

use karyos_client::{Client, Context};
use karyos_driver::EmbeddedDriver;

use super::*;

/// Options from `karyos_client_options_init`.
fn defaults() -> ClientOptions {
    let mut options = core::mem::MaybeUninit::<ClientOptions>::zeroed();
    // SAFETY: a live, aligned, writable `ClientOptions`.
    let status = unsafe { karyos_client_options_init(options.as_mut_ptr()) };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_client_options_init` wrote every field.
    unsafe { options.assume_init() }
}

/// `karyos_client_connect` of `options`: the status, the handle written
/// and the detail.
fn connect(options: &ClientOptions) -> (i32, u64, Detail) {
    let mut client = u64::MAX;
    let mut detail = Detail {
        size: size_of_u32::<Detail>(),
        reserved: 7,
        code: 7,
        value: 7,
    };
    // SAFETY: live, aligned pointers; `options.dir` is null or a C string
    // the caller keeps alive.
    let status = unsafe { karyos_client_connect(options, &mut client, &mut detail) };
    (status, client, detail)
}

/// `karyos_client_poll` of `client`: the status and `served`.
fn poll(client: u64) -> (i32, u32) {
    let mut served = u32::MAX;
    // SAFETY: a live, aligned `u32`.
    let status = unsafe { karyos_client_poll(client, &mut served) };
    (status, served)
}

#[test]
fn options_init_fills_the_defaults_and_the_size() {
    let options = defaults();
    assert_eq!(options.size, size_of_u32::<ClientOptions>());
    assert_eq!(options.idle_strategy, client::IDLE_YIELD);
    assert!(options.dir.is_null());
    assert_eq!(options.timeout_ns, 10_000_000_000);
    assert_eq!(options.max_pending, 64);
    assert_eq!(options.max_images, 8);
    // SAFETY: a null pointer is refused before any use.
    let status = unsafe { karyos_client_options_init(core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
}

#[test]
fn connect_refuses_bad_arguments_and_writes_nothing() {
    let options = defaults();
    let mut client = u64::MAX;
    // SAFETY: null pointers are refused before any use.
    let null_options =
        unsafe { karyos_client_connect(core::ptr::null(), &mut client, core::ptr::null_mut()) };
    assert_eq!(null_options, Status::InvalidArgument.code());
    // SAFETY: as above.
    let null_client =
        unsafe { karyos_client_connect(&options, core::ptr::null_mut(), core::ptr::null_mut()) };
    assert_eq!(null_client, Status::InvalidArgument.code());
    assert_eq!(client, u64::MAX);

    let short = ClientOptions {
        size: options.size - 1,
        ..options
    };
    assert_eq!(connect(&short).0, Status::InvalidArgument.code());

    let not_utf8 = c"\xff\xfe";
    let bad_dir = ClientOptions {
        dir: not_utf8.as_ptr(),
        ..options
    };
    assert_eq!(connect(&bad_dir).0, Status::InvalidArgument.code());

    let bad_idle = ClientOptions {
        idle_strategy: 9,
        ..options
    };
    assert_eq!(connect(&bad_idle).0, Status::InvalidArgument.code());
}

#[test]
fn an_invalid_context_is_refused_with_its_detail_cleared() {
    let zero_timeout = ClientOptions {
        timeout_ns: 0,
        ..defaults()
    };
    let (status, client, detail) = connect(&zero_timeout);
    assert_eq!(status, Status::InvalidContext.code());
    assert_eq!(client, u64::MAX);
    assert_eq!((detail.reserved, detail.code, detail.value), (0, 0, 0));
    assert_eq!(detail.size, size_of_u32::<Detail>());
    // A detail too short for this version is left alone.
    let mut short = Detail {
        size: 4,
        reserved: 7,
        code: 7,
        value: 7,
    };
    let mut handle = 0;
    // SAFETY: live, aligned pointers.
    let status = unsafe { karyos_client_connect(&zero_timeout, &mut handle, &mut short) };
    assert_eq!(status, Status::InvalidContext.code());
    assert_eq!((short.code, short.value), (7, 7));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn connect_is_unsupported_without_a_cross_process_client() {
    let dir = c"/nonexistent/karyos";
    let options = ClientOptions {
        dir: dir.as_ptr(),
        ..defaults()
    };
    assert_eq!(connect(&options).0, Status::Unsupported.code());
}

#[test]
fn a_client_handle_is_served_and_closed_once() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let conductor = driver.connect().unwrap();
    let context = Context::builder().build().unwrap();
    let handle = client::insert_embedded(Client::with_conductor(conductor, context)).unwrap();
    let raw = handle.raw();

    // An idle client serves nothing: `served` is written as 0. A 1 needs
    // a completion or an event, which F3 and F4's calls bring.
    for _ in 0..4 {
        assert_eq!(poll(raw), (Status::Ok.code(), 0));
    }
    // SAFETY: a null `served` is refused before any use.
    let null_served = unsafe { karyos_client_poll(raw, core::ptr::null_mut()) };
    assert_eq!(null_served, Status::InvalidArgument.code());
    assert_eq!(poll(0).0, Status::InvalidHandle.code());

    assert_eq!(karyos_client_close(raw), Status::Ok.code());
    assert_eq!(karyos_client_close(raw), Status::Closed.code());
    assert_eq!(poll(raw), (Status::Closed.code(), u32::MAX));
    let _ = driver.do_work().unwrap();
}

#[test]
fn the_0_1_sizes_are_this_version_s() {
    // Today's structs are the first released ones; a field added later
    // goes after them and leaves these constants alone.
    assert_eq!(CLIENT_OPTIONS_SIZE_0_1, size_of_u32::<ClientOptions>());
    assert_eq!(DETAIL_SIZE_0_1, size_of_u32::<Detail>());
}

#[test]
fn a_struct_from_a_newer_header_is_read_and_written_by_its_prefix() {
    /// Options with one field more, as a later minor version may add.
    #[repr(C)]
    struct Newer {
        options: ClientOptions,
        later: u64,
    }
    let newer = Newer {
        options: ClientOptions {
            size: size_of_u32::<Newer>(),
            timeout_ns: 0,
            ..defaults()
        },
        later: 7,
    };
    #[repr(C)]
    struct NewerDetail {
        detail: Detail,
        later: u64,
    }
    let mut detail = NewerDetail {
        detail: Detail {
            size: size_of_u32::<NewerDetail>(),
            reserved: 7,
            code: 7,
            value: 7,
        },
        later: 9,
    };
    let mut client = u64::MAX;
    // SAFETY: live, aligned structs at least as large as their `size`.
    let status = unsafe {
        karyos_client_connect(
            core::ptr::from_ref(&newer).cast(),
            &mut client,
            core::ptr::from_mut(&mut detail).cast(),
        )
    };
    // The prefix was read: its zero timeout is refused.
    assert_eq!(status, Status::InvalidContext.code());
    assert_eq!((detail.detail.code, detail.detail.value), (0, 0));
    // The newer field is left alone, and the caller's size kept.
    assert_eq!(detail.later, 9);
    assert_eq!(detail.detail.size, size_of_u32::<NewerDetail>());
    assert_eq!(newer.later, 7);
}
