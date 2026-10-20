// SPDX-License-Identifier: Apache-2.0

//! Conflated subscriptions over the C ABI (F7b-2b): the stream options'
//! conflation fields and their sizes, `karyos_driver_subscribe_conflated`,
//! `karyos_conflated_poll` and `karyos_conflated_close`.

use super::*;

/// A stream of a C driver with a conflation table of 4 keys.
const KEYED: i32 = 1020;

/// A stream of a C driver without a conflation table.
const PLAIN: i32 = 1021;

/// `karyos_stream_options` of `stream_id` from `karyos_stream_options_init`.
fn stream_options_of(stream_id: i32) -> StreamOptions {
    let mut stream = core::mem::MaybeUninit::<StreamOptions>::zeroed();
    // SAFETY: a live, aligned, writable `StreamOptions`.
    let status = unsafe { karyos_stream_options_init(stream.as_mut_ptr()) };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_stream_options_init` wrote every field.
    let mut stream = unsafe { stream.assume_init() };
    stream.stream_id = stream_id;
    stream
}

/// `options` with a table of 4 keys, values of at most 64 bytes and a
/// journal of 4096 bytes.
fn with_table(options: StreamOptions) -> StreamOptions {
    StreamOptions {
        conflation_keys: 4,
        conflation_value_capacity: 64,
        conflation_journal_capacity: 4096,
        ..options
    }
}

/// `karyos_driver_add_stream` of `options`.
fn add_stream(driver: u64, options: &StreamOptions) -> i32 {
    // SAFETY: live, aligned pointers of their stated sizes; no detail.
    unsafe { karyos_driver_add_stream(driver, options, core::ptr::null_mut()) }
}

/// A C driver in the invoker mode.
fn c_driver() -> u64 {
    let mut options = core::mem::MaybeUninit::<DriverOptions>::zeroed();
    // SAFETY: a live, aligned, writable `DriverOptions`.
    let status = unsafe { karyos_driver_options_init(options.as_mut_ptr()) };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_driver_options_init` wrote every field.
    let options = unsafe { options.assume_init() };
    let mut driver = 0;
    // SAFETY: live, aligned pointers; no detail.
    let status = unsafe { karyos_driver_create(&options, &mut driver, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    driver
}

/// `karyos_driver_subscribe_conflated` of `stream_id`.
fn subscribe(driver: u64, stream_id: i32) -> (i32, u64) {
    let mut conflated = 0;
    // SAFETY: a live, aligned `u64`.
    let status = unsafe { karyos_driver_subscribe_conflated(driver, stream_id, &mut conflated) };
    (status, conflated)
}

/// What a conflated handler saw: each key with its value, version and
/// freshness.
#[derive(Default)]
struct Values(Vec<(u32, Vec<u8>, u64, u64)>);

/// A `karyos_conflated_handler` that records into its `Values`.
///
/// # Safety
///
/// `context` is a live `Values`; `data` holds `length` bytes during the
/// call.
unsafe extern "C" fn record_value(
    context: *mut c_void,
    key: u32,
    data: *const u8,
    length: usize,
    version: u64,
    freshness: u64,
) {
    // SAFETY: the function's contract.
    let values = unsafe { &mut *context.cast::<Values>() };
    // SAFETY: as above.
    let bytes = unsafe { core::slice::from_raw_parts(data, length) };
    values.0.push((key, bytes.to_vec(), version, freshness));
}

/// `karyos_conflated_poll` of at most `key_budget` keys into `values`.
fn poll_values(conflated: u64, values: &mut Values, key_budget: u32) -> (i32, u32) {
    let mut delivered = u32::MAX;
    // SAFETY: a handler of the signature that returns normally, its live
    // context, and a live, aligned `u32`.
    let status = unsafe {
        karyos_conflated_poll(
            conflated,
            Some(record_value),
            (&raw mut *values).cast(),
            key_budget,
            &mut delivered,
        )
    };
    (status, delivered)
}

/// The conflation fields are read when the struct has them: 64 bytes is
/// the first layout, with no table; a size between it and 80 is refused
/// before anything is used; 80 and more are read by their 80-byte prefix.
/// No driver: the size checks come first, and an accepted size reaches the
/// handle check (a Miri test of the stream options' prefix read).
#[test]
fn stream_options_take_two_layouts_and_nothing_between() {
    assert_eq!(
        size_of_u32::<StreamOptions>(),
        STREAM_OPTIONS_SIZE_CONFLATION
    );
    let options = stream_options_of(KEYED);
    assert_eq!(options.size, STREAM_OPTIONS_SIZE_CONFLATION);
    assert_eq!(
        (
            options.conflation_keys,
            options.conflation_value_capacity,
            options.conflation_journal_capacity
        ),
        (0, 0, 0)
    );
    /// `karyos_stream_options` of a newer header: one more field.
    #[repr(C)]
    struct Newer {
        options: StreamOptions,
        later: u64,
    }
    let newer = Newer {
        options: StreamOptions {
            size: size_of_u32::<Newer>(),
            ..with_table(options)
        },
        later: u64::MAX,
    };
    let sized = |size: u32| {
        let given = Newer {
            options: StreamOptions {
                size,
                ..newer.options
            },
            later: u64::MAX,
        };
        // SAFETY: `given` is live and at least `size` bytes; no detail.
        unsafe { karyos_driver_add_stream(0, (&raw const given).cast(), core::ptr::null_mut()) }
    };
    for refused in [60, 65, 72, 76, 79] {
        assert_eq!(sized(refused), Status::InvalidArgument.code(), "{refused}");
    }
    for accepted in [64, 80, size_of_u32::<Newer>()] {
        assert_eq!(sized(accepted), Status::InvalidHandle.code(), "{accepted}");
    }
}

/// The subscribe and poll arguments are checked before any handle is
/// looked up; a handle of another kind is refused (no driver).
#[test]
fn conflated_calls_check_their_arguments() {
    // SAFETY: a null out-pointer, the case under test.
    let status = unsafe { karyos_driver_subscribe_conflated(0, KEYED, core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!(subscribe(0, KEYED).0, Status::InvalidHandle.code());
    let mut delivered = 0u32;
    // SAFETY: a null handler, the case under test.
    let status =
        unsafe { karyos_conflated_poll(0, None, core::ptr::null_mut(), 1, &mut delivered) };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut values = Values::default();
    let mut words = [0u32; 2];
    // SAFETY: a misaligned `delivered`, the case under test.
    let status = unsafe {
        karyos_conflated_poll(
            0,
            Some(record_value),
            (&raw mut values).cast(),
            1,
            words.as_mut_ptr().cast::<u8>().wrapping_add(1).cast(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!(
        poll_values(0, &mut values, 1),
        (Status::InvalidHandle.code(), 0)
    );
    assert_eq!(karyos_conflated_close(0), Status::InvalidHandle.code());
    assert!(values.0.is_empty());
}

/// A partial table adds no stream; subscribing needs a stream with a
/// table; a view delivers each changed key's latest value, from a copy,
/// Fresh; and it follows its driver's close.
#[test]
fn a_conflated_view_delivers_each_keys_latest_value() {
    let driver = c_driver();
    let partial = StreamOptions {
        conflation_journal_capacity: 0,
        ..with_table(stream_options_of(KEYED))
    };
    assert_eq!(add_stream(driver, &partial), Status::InvalidArgument.code());
    let keyed = StreamOptions {
        allow_unconnected: 1,
        ..with_table(stream_options_of(KEYED))
    };
    assert_eq!(add_stream(driver, &keyed), Status::Ok.code());
    assert_eq!(
        add_stream(driver, &stream_options_of(PLAIN)),
        Status::Ok.code()
    );
    assert_eq!(subscribe(driver, PLAIN).0, Status::Conflation.code());
    assert_eq!(subscribe(driver, 9999).0, Status::InvalidArgument.code());
    let (status, view) = subscribe(driver, KEYED);
    assert_eq!(status, Status::Ok.code());
    let mut values = Values::default();
    assert_eq!(poll_values(view, &mut values, 8), (Status::Ok.code(), 0));
    assert_eq!(
        karyos_driver_start(driver, client::IDLE_YIELD, 0),
        Status::Ok.code()
    );
    let mut client = 0;
    // SAFETY: a live, aligned `u64`; no detail.
    let status = unsafe { karyos_driver_connect(driver, &mut client, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    let (status, publication) = add_publication_of(client, KEYED);
    assert_eq!(status, Status::Ok.code());
    let start = std::time::Instant::now();
    for (key, value) in [(1, b"a"), (1, b"b"), (2, b"c")] {
        let options = OfferOptions {
            reserved_value: key,
            ..offer_defaults()
        };
        loop {
            // SAFETY: `options` is live and its stated size.
            let (status, _) = unsafe { offer_with(publication, value, &options) };
            if status == Status::Ok.code() {
                break;
            }
            assert_eq!(status, Status::NotConnected.code());
            assert!(start.elapsed() < std::time::Duration::from_secs(3600));
            std::thread::yield_now();
        }
    }
    // The feeder copies the log into the table on the driver's thread;
    // the view sees key 1's latest value and key 2's.
    let latest = |values: &Values, key: u32| {
        values
            .0
            .iter()
            .rev()
            .find(|seen| seen.0 == key)
            .map(|seen| seen.1.clone())
    };
    while latest(&values, 1).as_deref() != Some(b"b") || latest(&values, 2).is_none() {
        assert!(start.elapsed() < std::time::Duration::from_secs(3600));
        let (status, delivered) = poll_values(view, &mut values, 8);
        assert_eq!(status, Status::Ok.code());
        assert!(delivered <= 8);
        std::thread::yield_now();
    }
    assert_eq!(latest(&values, 2).as_deref(), Some(b"c".as_slice()));
    assert!(values.0.iter().all(|seen| seen.3 == api::conflated::FRESH));
    assert!(values.0.iter().all(|seen| seen.0 < 4));
    // A key's versions only grow.
    let versions: Vec<u64> = values
        .0
        .iter()
        .filter(|seen| seen.0 == 1)
        .map(|seen| seen.2)
        .collect();
    assert!(versions.windows(2).all(|pair| pair.first() < pair.last()));
    // A budget of 0 delivers nothing.
    assert_eq!(poll_values(view, &mut values, 0).1, 0);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(karyos_driver_close(driver), Status::Ok.code());
    // The view follows its driver's close, and is closed by its handle.
    assert_eq!(
        poll_values(view, &mut values, 8),
        (Status::Closed.code(), 0)
    );
    assert_eq!(karyos_conflated_close(view), Status::Ok.code());
    assert_eq!(karyos_conflated_close(view), Status::Closed.code());
}
