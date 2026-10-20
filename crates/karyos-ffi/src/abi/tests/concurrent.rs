// SPDX-License-Identifier: Apache-2.0

//! Concurrent streams of a C driver (F7a-1 follow-up): the stream options'
//! `KARYOS_PUBLICATION_CONCURRENT` and `publishers`, and concurrent
//! handles on such a stream through the C ABI only.

use super::*;

/// A concurrent stream of a C driver.
const SHARED: i32 = 1030;

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

/// `options` as a concurrent stream of `publishers` handles.
fn concurrent(options: StreamOptions, publishers: u32) -> StreamOptions {
    StreamOptions {
        publication_mode: api::driver::PUBLICATION_CONCURRENT,
        publishers,
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

/// The mode and `publishers` agree or the stream is refused: exclusive
/// takes 0, concurrent 1 to 255, and an unknown mode nothing. Nothing is
/// added on refusal.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_stream_mode_takes_only_its_publishers() {
    let driver = c_driver();
    let exclusive = stream_options_of(SHARED);
    for refused in [
        StreamOptions {
            publishers: 2,
            ..exclusive
        },
        concurrent(exclusive, 0),
        concurrent(exclusive, 256),
        StreamOptions {
            publication_mode: 2,
            ..exclusive
        },
    ] {
        assert_eq!(
            add_stream(driver, &refused),
            Status::InvalidArgument.code(),
            "{refused:?}"
        );
    }
    // Each concurrent publisher takes one spare slot of the stream's term
    // ring, which keeps one for cleaning: with the default 3 spare slots
    // at most 2 publishers fit, and 3 is refused as unavailable resources.
    assert_eq!(exclusive.spare_slots, 3);
    assert_eq!(
        add_stream(driver, &concurrent(exclusive, 3)),
        Status::ResourcesUnavailable.code()
    );
    // One more spare slot fits a third publisher (another stream id: a
    // removed stream's id stays taken while it retires).
    let roomier = StreamOptions {
        stream_id: SHARED + 1,
        spare_slots: 4,
        ..concurrent(exclusive, 3)
    };
    assert_eq!(add_stream(driver, &roomier), Status::Ok.code());
    // Nothing was added by a refusal: the stream id is still free.
    assert_eq!(
        add_stream(driver, &concurrent(exclusive, 2)),
        Status::Ok.code()
    );
    assert_eq!(karyos_driver_close(driver), Status::Ok.code());
}

/// On a C driver's concurrent stream of two publishers, a C client takes
/// two concurrent handles, a third is refused, an exclusive one too; both
/// offer on lane 0 and lane 1 is invalid; closing one frees its slot.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_c_driver_s_concurrent_stream_takes_its_publishers() {
    let driver = c_driver();
    let shared = concurrent(stream_options_of(SHARED), 2);
    assert_eq!(add_stream(driver, &shared), Status::Ok.code());
    assert_eq!(
        karyos_driver_start(driver, client::IDLE_YIELD, 0),
        Status::Ok.code()
    );
    let mut client = 0;
    // SAFETY: a live, aligned `u64`; no detail.
    let status = unsafe { karyos_driver_connect(driver, &mut client, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    // A concurrent handle offers to a connected stream: a reader joins.
    let (status, _reading) = add_subscription_of(client, SHARED);
    assert_eq!(status, Status::Ok.code());
    let (status, first) = add_concurrent_of(client, SHARED);
    assert_eq!(status, Status::Ok.code());
    let (status, second) = add_concurrent_of(client, SHARED);
    assert_eq!(status, Status::Ok.code());
    assert_ne!(add_concurrent_of(client, SHARED).0, Status::Ok.code());
    assert_ne!(add_publication_of(client, SHARED).0, Status::Ok.code());
    for publication in [first, second] {
        assert_eq!(offer(publication, b"shared").0, Status::Ok.code());
    }
    // SAFETY: a live payload of 1 byte, no out-parameter.
    let other_lane =
        unsafe { karyos_publication_offer(first, 1, b"x".as_ptr(), 1, core::ptr::null_mut()) };
    assert_eq!(other_lane, Status::InvalidLane.code());
    assert_eq!(karyos_publication_close(first), Status::Ok.code());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let third = loop {
        let (status, third) = add_concurrent_of(client, SHARED);
        if status == Status::Ok.code() {
            break third;
        }
        assert!(std::time::Instant::now() < deadline, "slot never freed");
        idle();
    };
    assert_eq!(offer(third, b"again").0, Status::Ok.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(karyos_driver_close(driver), Status::Ok.code());
}
