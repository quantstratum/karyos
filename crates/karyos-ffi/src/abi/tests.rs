// SPDX-License-Identifier: Apache-2.0

//! The exported client functions over an embedded driver's conductor, so
//! they run under Miri and on macOS (quantstratum-docs:
//! karyos/design/ffi-gap-analysis.md §4.7).

use karyos_client::{Client, Context};
use karyos_driver::EmbeddedDriver;

use super::*;

/// A client context whose control calls wait long enough for a driver
/// thread under Miri, whose clock runs fast against its slow execution.
fn test_context() -> Context {
    Context::builder()
        .timeout(std::time::Duration::from_secs(3600))
        .build()
        .unwrap()
}

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

/// The options' last fields are read: a zero bound there is refused, so a
/// copy that stops short of them (keeping their defaults) fails here.
#[test]
fn connect_reads_the_options_to_their_last_field() {
    for options in [
        ClientOptions {
            max_images: 0,
            ..defaults()
        },
        ClientOptions {
            max_pending: 0,
            ..defaults()
        },
    ] {
        assert_eq!(connect(&options).0, Status::InvalidContext.code());
    }
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
    let context = test_context();
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

/// An embedded driver on its own thread, with the heap stream 1001, until
/// dropped; control calls need it served while they wait.
struct Driven {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Driven {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

/// The one-lane heap stream of the publication tests.
const STREAM: i32 = 1001;

/// A one-lane heap stream of `stream_id` that accepts offers with no
/// subscriber.
fn stream_config(stream_id: i32) -> karyos_driver::StreamConfig {
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;
    karyos_driver::StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: karyos_driver::LossPolicy::Hold,
        conflation: None,
    }
}

/// A stream whose offers are refused while no subscriber is connected.
const STREAM_UNCONNECTED: i32 = 1002;

/// A driven driver with the streams, and two conductors of it. Its clients
/// are timed out only after an hour without a heartbeat: under Miri, a
/// client a test has not used yet would otherwise be retired first.
fn driven() -> (
    Driven,
    karyos_client::ClientConductor,
    karyos_client::ClientConductor,
) {
    let mut driver = EmbeddedDriver::with_config(karyos_driver::DriverConfig {
        client_liveness_timeout: 3_600_000_000_000,
        ..karyos_driver::DriverConfig::default()
    })
    .unwrap();
    let _ = driver.add_stream(stream_config(STREAM)).unwrap();
    let mut unconnected = karyos_driver::StreamConfig {
        allow_unconnected: false,
        ..stream_config(STREAM_UNCONNECTED)
    };
    unconnected.buffer.stream_id = STREAM_UNCONNECTED;
    let _ = driver.add_stream(unconnected).unwrap();
    let ours = driver.connect().unwrap();
    let theirs = driver.connect().unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        while !flag.load(std::sync::atomic::Ordering::Acquire) {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
    });
    (
        Driven {
            stop,
            thread: Some(thread),
        },
        ours,
        theirs,
    )
}

/// A `karyos_accepted` of this version, filled with a marker.
fn accepted() -> Accepted {
    Accepted {
        size: size_of_u32::<Accepted>(),
        lane: u32::MAX,
        position: u64::MAX,
    }
}

/// `karyos_client_add_publication` of the stream on `karyos:ipc`.
fn add_publication(client: u64) -> (i32, u64) {
    add_publication_of(client, STREAM)
}

/// `karyos_client_add_publication` of `stream` on `karyos:ipc`.
fn add_publication_of(client: u64, stream: i32) -> (i32, u64) {
    let mut publication = 0;
    // SAFETY: a C string literal, a live `u64`, no detail.
    let status = unsafe {
        karyos_client_add_publication(
            client,
            c"karyos:ipc".as_ptr(),
            stream,
            &mut publication,
            core::ptr::null_mut(),
        )
    };
    (status, publication)
}

/// `karyos_publication_offer` of `payload` on lane 0.
fn offer(publication: u64, payload: &[u8]) -> (i32, Accepted) {
    let mut done = accepted();
    // SAFETY: `payload` is live for the call; `done` is a live
    // `karyos_accepted` with its size.
    let status = unsafe {
        karyos_publication_offer(publication, 0, payload.as_ptr(), payload.len(), &mut done)
    };
    (status, done)
}

/// `karyos_publication_claim`: the status, the claim and the buffer.
fn claim(publication: u64, lane: u32, length: u32) -> (i32, u64, *mut u8) {
    let (mut claim, mut buffer) = (0, core::ptr::null_mut());
    // SAFETY: live, aligned out-parameters.
    let status =
        unsafe { karyos_publication_claim(publication, lane, length, &mut claim, &mut buffer) };
    (status, claim, buffer)
}

/// Writes `bytes` into a claim's staged buffer, as a C caller does.
///
/// # Safety
///
/// `buffer` holds at least `bytes.len()` bytes of an outstanding claim.
unsafe fn fill(buffer: *mut u8, bytes: &[u8]) {
    // SAFETY: the caller's contract; nothing else refers to the bytes
    // while the slice lives.
    let staged = unsafe { core::slice::from_raw_parts_mut(buffer, bytes.len()) };
    staged.copy_from_slice(bytes);
}

/// `karyos_claim_commit`: the status and where the message went.
fn commit(claim: u64) -> (i32, Accepted) {
    let mut done = accepted();
    // SAFETY: a live `karyos_accepted` with its size.
    let status = unsafe { karyos_claim_commit(claim, &mut done) };
    (status, done)
}

/// Reads up to `count` messages of `subscription`, serving `client`.
fn read(
    client: &mut Client<karyos_client::ClientConductor>,
    subscription: &mut karyos_client::Subscription<karyos_sys::term_bytes::HeapTerms>,
    count: usize,
) -> Vec<Vec<u8>> {
    let mut seen = Vec::new();
    let start = std::time::Instant::now();
    while seen.len() < count {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3600),
            "{seen:?}"
        );
        let _ = client.poll();
        let _ = subscription.poll(
            |bytes, _| seen.push(bytes.to_vec()),
            karyos_client::MessageLimit::new(16),
        );
        std::thread::yield_now();
    }
    seen
}

#[test]
fn a_publication_offers_and_commits_staged_claims() {
    let (_driven, ours, theirs) = driven();
    let context = test_context();
    let client = client::insert_embedded(Client::with_conductor(ours, context.clone()))
        .unwrap()
        .raw();
    let mut subscriber = Client::with_conductor(theirs, context);
    let mut reading = subscriber
        .add_subscription("karyos:ipc", karyos_client::StreamId::new(STREAM))
        .unwrap();
    let (status, publication) = add_publication(client);
    assert_eq!(status, Status::Ok.code());

    // An offer copies the bytes; a null pointer is refused unless empty.
    let (status, offered) = offer(publication, b"hello");
    assert_eq!(status, Status::Ok.code());
    assert_eq!(offered.lane, 0);
    // SAFETY: a null pointer with a nonzero length is refused before use.
    let null = unsafe {
        karyos_publication_offer(publication, 0, core::ptr::null(), 3, core::ptr::null_mut())
    };
    assert_eq!(null, Status::InvalidArgument.code());
    // SAFETY: an empty payload is never read.
    let empty = unsafe {
        karyos_publication_offer(publication, 0, core::ptr::null(), 0, core::ptr::null_mut())
    };
    assert_eq!(empty, Status::EmptyMessage.code());

    // A staged claim: written by the caller, reaching the term only at the
    // commit, and one at a time.
    let (status, staged, buffer) = claim(publication, 0, 5);
    assert_eq!(status, Status::Ok.code());
    assert!(!buffer.is_null());
    // SAFETY: the buffer holds the 5 claimed bytes until the commit.
    unsafe { fill(buffer, b"world") };
    assert_eq!(claim(publication, 0, 1).0, Status::ClaimOutstanding.code());
    let (status, committed) = commit(staged);
    assert_eq!(status, Status::Ok.code());
    assert!(committed.position > offered.position);
    assert_eq!(commit(staged).0, Status::Closed.code());
    assert_eq!(karyos_claim_abort(staged), Status::Closed.code());

    // An aborted claim leaves nothing, and frees the publication's claim.
    let (status, aborted, _) = claim(publication, 0, 4);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(karyos_claim_abort(aborted), Status::Ok.code());
    assert_eq!(commit(aborted).0, Status::Closed.code());

    // The lane's largest message is the bound of the staged buffer: a
    // claim of exactly it is staged, one byte more is refused with the
    // length and the bound.
    let max = crate::api::publication::lane_max(
        crate::handles::Handle::from_raw(publication),
        karyos_sys::frame::Lane::ZERO,
    )
    .unwrap();
    let (status, largest, _) = claim(publication, 0, max);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(karyos_claim_abort(largest), Status::Ok.code());
    assert_eq!(
        claim(publication, 0, max + 1).0,
        Status::MessageTooLarge.code()
    );
    let refused =
        crate::api::publication::claim(crate::handles::Handle::from_raw(publication), 0, max + 1)
            .map(|_| ());
    assert_eq!(
        refused,
        Err(crate::status::Failure::with(
            Status::MessageTooLarge,
            u64::from(max + 1),
            u64::from(max)
        ))
    );

    // A new claim starts zeroed, whatever the last one held.
    let (status, dirty, buffer) = claim(publication, 0, 4);
    assert_eq!(status, Status::Ok.code());
    // SAFETY: the buffer holds the 4 claimed bytes until the abort.
    unsafe { fill(buffer, b"xxxx") };
    assert_eq!(karyos_claim_abort(dirty), Status::Ok.code());
    let (status, fresh, buffer) = claim(publication, 0, 4);
    assert_eq!(status, Status::Ok.code());
    // SAFETY: the buffer holds the 4 claimed bytes until the abort, and
    // nothing writes them meanwhile.
    let zeroed = unsafe { core::slice::from_raw_parts(buffer, 4) }.to_vec();
    assert_eq!(zeroed, [0; 4]);
    assert_eq!(karyos_claim_abort(fresh), Status::Ok.code());

    // Refused claims.
    assert_eq!(claim(publication, 9, 4).0, Status::InvalidLane.code());
    assert_eq!(claim(publication, 300, 4).0, Status::InvalidLane.code());
    assert_eq!(claim(publication, 0, 0).0, Status::EmptyMessage.code());
    assert_eq!(
        claim(publication, 0, u32::MAX).0,
        Status::MessageTooLarge.code()
    );

    assert_eq!(
        read(&mut subscriber, &mut reading, 2),
        [b"hello".to_vec(), b"world".to_vec()]
    );

    // A publication closes once; a closed one refuses everything.
    assert_eq!(karyos_publication_close(publication), Status::Ok.code());
    assert_eq!(karyos_publication_close(publication), Status::Closed.code());
    assert_eq!(offer(publication, b"x").0, Status::Closed.code());
    assert_eq!(claim(publication, 0, 1).0, Status::Closed.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

#[test]
fn closing_a_client_closes_its_publications_and_their_claims() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (status, publication) = add_publication(client);
    assert_eq!(status, Status::Ok.code());
    let (status, staged, _) = claim(publication, 0, 3);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(offer(publication, b"x").0, Status::Closed.code());
    assert_eq!(commit(staged).0, Status::Closed.code());
    assert_eq!(karyos_publication_close(publication), Status::Closed.code());
    // A closed client adds nothing.
    assert_eq!(add_publication(client).0, Status::Closed.code());
}

#[test]
fn add_publication_refuses_bad_arguments() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let mut publication = 0;
    // SAFETY: a null URI is refused before any use.
    let null_uri = unsafe {
        karyos_client_add_publication(
            client,
            core::ptr::null(),
            STREAM,
            &mut publication,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(null_uri, Status::InvalidArgument.code());
    // SAFETY: a null out-parameter is refused before any use.
    let null_out = unsafe {
        karyos_client_add_publication(
            client,
            c"karyos:ipc".as_ptr(),
            STREAM,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(null_out, Status::InvalidArgument.code());
    let mut detail = Detail {
        size: size_of_u32::<Detail>(),
        reserved: 0,
        code: 0,
        value: 0,
    };
    // SAFETY: live pointers and a C string literal.
    let bad_uri = unsafe {
        karyos_client_add_publication(
            client,
            c"no-such-scheme:".as_ptr(),
            STREAM,
            &mut publication,
            &mut detail,
        )
    };
    assert_eq!(bad_uri, Status::InvalidChannel.code());
    assert_eq!(publication, 0);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

#[test]
fn a_commit_that_finds_no_subscriber_keeps_its_claim_staged() {
    let (_driven, ours, theirs) = driven();
    let context = test_context();
    let client = client::insert_embedded(Client::with_conductor(ours, context.clone()))
        .unwrap()
        .raw();
    let (status, publication) = add_publication_of(client, STREAM_UNCONNECTED);
    assert_eq!(status, Status::Ok.code());
    let (status, staged, buffer) = claim(publication, 0, 3);
    assert_eq!(status, Status::Ok.code());
    // SAFETY: the buffer holds the 3 claimed bytes until the claim is
    // released.
    unsafe { fill(buffer, b"abc") };
    // No subscriber: the commit is refused, and the claim stays staged.
    assert_eq!(commit(staged).0, Status::NotConnected.code());
    assert_eq!(claim(publication, 0, 1).0, Status::ClaimOutstanding.code());
    // A subscriber connects; the same claim, with its bytes, commits.
    let mut subscriber = Client::with_conductor(theirs, context);
    let mut reading = subscriber
        .add_subscription(
            "karyos:ipc",
            karyos_client::StreamId::new(STREAM_UNCONNECTED),
        )
        .unwrap();
    let start = std::time::Instant::now();
    loop {
        assert!(start.elapsed() < std::time::Duration::from_secs(3600));
        let (status, _) = commit(staged);
        if status == Status::Ok.code() {
            break;
        }
        assert_eq!(status, Status::NotConnected.code());
        let _ = subscriber.poll();
        std::thread::yield_now();
    }
    assert_eq!(read(&mut subscriber, &mut reading, 1), [b"abc".to_vec()]);
    assert_eq!(commit(staged).0, Status::Closed.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

// F5: the growing structs of the driver are read to their last field.

#[test]
fn a_driver_options_struct_is_read_to_its_last_field() {
    let mut given = default_driver_options();
    given.max_clients = 3;
    given.cutover_deadline_ns = 123_456;
    // SAFETY: a live, aligned `DriverOptions` whose size is set.
    let read = unsafe { read_sized(&given, DRIVER_OPTIONS_SIZE_0_1, default_driver_options()) };
    let read = read.unwrap();
    assert_eq!((read.max_clients, read.cutover_deadline_ns), (3, 123_456));
    // A struct below the first size is refused.
    given.size = DRIVER_OPTIONS_SIZE_0_1 - 1;
    // SAFETY: as above.
    let refused = unsafe { read_sized(&given, DRIVER_OPTIONS_SIZE_0_1, default_driver_options()) };
    assert_eq!(refused.map(|_| ()), Err(Status::InvalidArgument));
}

#[test]
fn a_stream_options_struct_is_read_to_its_last_field() {
    let mut given = default_stream_options();
    given.stream_id = 77;
    given.claim_deadline_ns = 654_321;
    // SAFETY: a live, aligned `StreamOptions` whose size is set.
    let read = unsafe { read_sized(&given, STREAM_OPTIONS_SIZE_0_1, default_stream_options()) };
    let read = read.unwrap();
    assert_eq!((read.stream_id, read.claim_deadline_ns), (77, 654_321));
}

#[test]
fn an_older_structs_missing_tail_keeps_the_defaults() {
    /// A first version of a growing struct, and a later one with a field
    /// more.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct Later {
        size: u32,
        first: u32,
        added: u64,
    }
    let older = Later {
        size: 8,
        first: 5,
        added: 99,
    };
    let defaults = Later {
        size: 16,
        first: 0,
        added: 7,
    };
    // SAFETY: a live, aligned `Later`; the function reads only its first
    // `size` bytes.
    let read = unsafe { read_sized(&older, 8, defaults) }.unwrap();
    assert_eq!((read.size, read.first, read.added), (8, 5, 7));
    // A null struct is refused.
    // SAFETY: a null pointer is refused before any use.
    let null = unsafe { read_sized(core::ptr::null::<Later>(), 8, defaults) };
    assert_eq!(null.map(|_| ()), Err(Status::InvalidArgument));
}

// Subscriptions and their poll (F4).

/// `karyos_client_add_subscription` of `stream` on `karyos:ipc`.
fn add_subscription_of(client: u64, stream: i32) -> (i32, u64) {
    let mut subscription = 0;
    // SAFETY: a C string literal, a live `u64`, no detail.
    let status = unsafe {
        karyos_client_add_subscription(
            client,
            c"karyos:ipc".as_ptr(),
            stream,
            &mut subscription,
            core::ptr::null_mut(),
        )
    };
    (status, subscription)
}

/// What a test handler saw and did, through its context.
#[derive(Default)]
struct Seen {
    messages: Vec<Vec<u8>>,
    infos: Vec<MessageInfo>,
    data: Vec<usize>,
    /// The subscription and client the handler reenters, when nonzero.
    reenter: (u64, u64),
    reentered: Vec<i32>,
    /// The message number at which the handler "fails", as a binding's
    /// handler that throws: 0 for none.
    fail_at: usize,
    failed: bool,
}

/// A `karyos_message_handler` that records into its `Seen`.
///
/// # Safety
///
/// `context` is a live `Seen`; `data` holds `length` bytes and `info` a
/// `karyos_message_info`, both during the call.
unsafe extern "C" fn record(
    context: *mut c_void,
    data: *const u8,
    length: usize,
    info: *const MessageInfo,
) {
    // SAFETY: the function's contract.
    let seen = unsafe { &mut *context.cast::<Seen>() };
    // SAFETY: as above.
    let bytes = unsafe { core::slice::from_raw_parts(data, length) };
    seen.messages.push(bytes.to_vec());
    // SAFETY: as above.
    seen.infos.push(unsafe { info.read() });
    seen.data.push(data as usize);
    let (subscription, client) = seen.reenter;
    if subscription != 0 {
        let mut delivered = 0;
        // SAFETY: a live `uint32_t`, and this very handler.
        seen.reentered.push(unsafe {
            karyos_subscription_poll(
                subscription,
                Some(record),
                core::ptr::null_mut(),
                1,
                &mut delivered,
            )
        });
        seen.reentered.push(karyos_subscription_close(subscription));
        seen.reentered.push(karyos_client_close(client));
    }
    if seen.fail_at == seen.messages.len() {
        seen.failed = true;
    }
}

/// `karyos_subscription_poll` with [`record`] into `seen`.
fn poll_into(subscription: u64, seen: &mut Seen, limit: u32) -> (i32, u32) {
    let mut delivered = u32::MAX;
    // SAFETY: `record` has the handler's signature; `seen` is a live
    // `Seen` for the call; `delivered` is a live `uint32_t`.
    let status = unsafe {
        karyos_subscription_poll(
            subscription,
            Some(record),
            (&raw mut *seen).cast(),
            limit,
            &mut delivered,
        )
    };
    (status, delivered)
}

/// Polls with `limit` until `seen` holds `count` messages.
fn poll_until(subscription: u64, client: u64, seen: &mut Seen, limit: u32, count: usize) {
    let start = std::time::Instant::now();
    while seen.messages.len() < count {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3600),
            "{}",
            seen.messages.len()
        );
        let _ = poll(client);
        let (status, delivered) = poll_into(subscription, seen, limit);
        assert_eq!(status, Status::Ok.code());
        assert!(delivered <= limit);
        std::thread::yield_now();
    }
}

#[test]
fn a_subscription_delivers_each_message_from_its_private_copy() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (status, subscription) = add_subscription_of(client, STREAM);
    assert_eq!(status, Status::Ok.code());
    // The copy is the stream's largest message, allocated at the add.
    let copy = api::subscription::copy_length(Handle::from_raw(subscription)).unwrap();
    assert!(copy >= 8000, "{copy}");
    let (status, publication) = add_publication(client);
    assert_eq!(status, Status::Ok.code());
    let largest = vec![7u8; copy];
    for payload in [&b"one"[..], &b"two"[..], &largest[..]] {
        assert_eq!(offer(publication, payload).0, Status::Ok.code());
    }
    let mut seen = Seen::default();
    poll_until(subscription, client, &mut seen, 2, 3);
    assert_eq!(seen.messages, [b"one".to_vec(), b"two".to_vec(), largest]);
    // Every message came from the one private copy, which never grew.
    assert!(seen.data.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        api::subscription::copy_length(Handle::from_raw(subscription)),
        Some(copy)
    );
    let info = seen.infos[1];
    assert_eq!(info.size, size_of_u32::<MessageInfo>());
    assert_eq!((info.lane, info.session_id, info.flags), (0, 1, 0));
    assert!(info.position > seen.infos[0].position);
    assert!(info.extent >= 32);
    // A limit of 0 delivers nothing; a stale handle is closed.
    assert_eq!(
        poll_into(subscription, &mut seen, 0),
        (Status::Ok.code(), 0)
    );
    assert_eq!(karyos_subscription_close(subscription), Status::Ok.code());
    assert_eq!(
        poll_into(subscription, &mut seen, 1).0,
        Status::Closed.code()
    );
    assert_eq!(
        karyos_subscription_close(subscription),
        Status::Closed.code()
    );
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// ADR-0067: a binding stops a poll after a failed handler with the
/// bounded poll, a limit of 1 in a loop and no call after the failure.
/// The failed message is acknowledged; the ones after it stay undelivered
/// and are the next poll's.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn the_bounded_poll_stops_after_a_failed_handler() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (_, subscription) = add_subscription_of(client, STREAM);
    let (_, publication) = add_publication(client);
    for payload in [b"m1", b"m2", b"m3", b"m4"] {
        assert_eq!(offer(publication, payload).0, Status::Ok.code());
    }
    let mut seen = Seen {
        fail_at: 2,
        ..Seen::default()
    };
    // The binding's loop: one message per call, until a handler fails.
    let start = std::time::Instant::now();
    while !seen.failed {
        assert!(start.elapsed() < std::time::Duration::from_secs(3600));
        let _ = poll(client);
        let (status, delivered) = poll_into(subscription, &mut seen, 1);
        assert_eq!(status, Status::Ok.code());
        assert!(delivered <= 1);
    }
    assert_eq!(seen.messages, [b"m1".to_vec(), b"m2".to_vec()]);
    // Resumed later: m2 was acknowledged, m3 is next.
    let mut after = Seen::default();
    poll_until(subscription, client, &mut after, 1, 1);
    assert_eq!(after.messages, [b"m3".to_vec()]);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// From its handler, polling or closing the subscription, or closing its
/// client, answers REENTRANT and closes nothing: the subscription and the
/// client's publication still work afterwards.
#[test]
fn a_handler_that_reenters_its_subscription_is_refused() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (_, subscription) = add_subscription_of(client, STREAM);
    let (_, publication) = add_publication(client);
    assert_eq!(offer(publication, b"first").0, Status::Ok.code());
    let mut seen = Seen {
        reenter: (subscription, client),
        ..Seen::default()
    };
    poll_until(subscription, client, &mut seen, 1, 1);
    assert_eq!(seen.reentered, [Status::Reentrant.code(); 3]);
    // Nothing was closed.
    assert_eq!(offer(publication, b"second").0, Status::Ok.code());
    let mut after = Seen::default();
    poll_until(subscription, client, &mut after, 4, 1);
    assert_eq!(after.messages, [b"second".to_vec()]);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    // The client's close closed its subscription and its publication.
    assert_eq!(
        poll_into(subscription, &mut after, 1).0,
        Status::Closed.code()
    );
    assert_eq!(offer(publication, b"x").0, Status::Closed.code());
}

/// A handler that holds its subscription on one thread makes another
/// thread's poll answer BUSY, and the client's close answer BUSY with
/// nothing closed; both work once it returns.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_subscription_held_by_another_thread_is_busy() {
    use std::sync::{Arc, Barrier};

    struct Hold {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }
    unsafe extern "C" fn holding(
        context: *mut c_void,
        _data: *const u8,
        _length: usize,
        _info: *const MessageInfo,
    ) {
        // SAFETY: the context is a live `Hold` for the call.
        let hold = unsafe { &*context.cast::<Hold>() };
        let _ = hold.entered.wait();
        let _ = hold.release.wait();
    }

    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (_, subscription) = add_subscription_of(client, STREAM);
    let (_, publication) = add_publication(client);
    assert_eq!(offer(publication, b"held").0, Status::Ok.code());
    let (entered, release) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
    let holder = {
        let mut hold = Hold {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        };
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            loop {
                assert!(start.elapsed() < std::time::Duration::from_secs(3600));
                let _ = poll(client);
                let mut delivered = 0;
                // SAFETY: `hold` has the handler's signature, `hold` the
                // context it reads, `delivered` a live `uint32_t`.
                let status = unsafe {
                    karyos_subscription_poll(
                        subscription,
                        Some(holding),
                        (&raw mut hold).cast(),
                        1,
                        &mut delivered,
                    )
                };
                assert_eq!(status, Status::Ok.code());
                if delivered == 1 {
                    return;
                }
                std::thread::yield_now();
            }
        })
    };
    let _ = entered.wait();
    let mut seen = Seen::default();
    assert_eq!(poll_into(subscription, &mut seen, 1).0, Status::Busy.code());
    assert_eq!(karyos_client_close(client), Status::Busy.code());
    let _ = release.wait();
    holder.join().unwrap();
    assert_eq!(poll_into(subscription, &mut seen, 1).0, Status::Ok.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A `karyos:ipc` subscription has no image change; arguments are checked
/// before anything else.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn image_changes_and_bad_arguments() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (_, subscription) = add_subscription_of(client, STREAM);
    let mut change = ImageChange {
        size: size_of_u32::<ImageChange>(),
        session_id: 0,
        image_id: 0,
        lane: 0,
        available: 0,
    };
    let (mut has, mut lost) = (u32::MAX, u64::MAX);
    // SAFETY: live, aligned out-parameters.
    let status =
        unsafe { karyos_subscription_next_image_change(subscription, &mut change, &mut has) };
    assert_eq!((status, has), (Status::Ok.code(), 0));
    // SAFETY: a live `uint64_t`.
    let status = unsafe { karyos_subscription_image_changes_lost(subscription, &mut lost) };
    assert_eq!((status, lost), (Status::Ok.code(), 0));
    // Each block: a null pointer is refused before any use; the other
    // pointers are live.
    // SAFETY: as stated.
    let status = unsafe {
        karyos_subscription_next_image_change(subscription, &mut change, core::ptr::null_mut())
    };
    assert_eq!(status, Status::InvalidArgument.code());
    // SAFETY: as above.
    let status =
        unsafe { karyos_subscription_image_changes_lost(subscription, core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
    // SAFETY: as above.
    let status = unsafe {
        karyos_subscription_poll(
            subscription,
            None,
            core::ptr::null_mut(),
            1,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut added = 0;
    // SAFETY: as above.
    let status = unsafe {
        karyos_client_add_subscription(
            client,
            core::ptr::null(),
            STREAM,
            &mut added,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    // SAFETY: as above.
    let status = unsafe {
        karyos_client_add_subscription(
            client,
            c"karyos:ipc".as_ptr(),
            STREAM,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    // A handle of another kind, and a stream that does not exist.
    assert_eq!(
        poll_into(client, &mut Seen::default(), 1).0,
        Status::InvalidHandle.code()
    );
    assert_ne!(add_subscription_of(client, 9999).0, Status::Ok.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A copy that cannot grow answers SYSTEM before anything is delivered:
/// nothing is acknowledged, and the next poll delivers the message, with
/// the copy grown to the stream's largest message.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_copy_that_cannot_grow_delivers_nothing_and_loses_nothing() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (_, subscription) = add_subscription_of(client, STREAM);
    let handle = Handle::from_raw(subscription);
    let largest = api::subscription::copy_length(handle).unwrap();
    let (_, publication) = add_publication(client);
    assert_eq!(offer(publication, b"kept").0, Status::Ok.code());
    api::subscription::empty_copy(handle);
    api::subscription::REFUSE_GROWTH.with(|refuse| refuse.set(true));
    let mut seen = Seen::default();
    let start = std::time::Instant::now();
    // The message reaches the subscription; every poll fails before it.
    for _ in 0..64 {
        assert!(start.elapsed() < std::time::Duration::from_secs(3600));
        let _ = poll(client);
        assert_eq!(
            poll_into(subscription, &mut seen, 8),
            (Status::System.code(), 0)
        );
        std::thread::yield_now();
    }
    api::subscription::REFUSE_GROWTH.with(|refuse| refuse.set(false));
    assert!(seen.messages.is_empty());
    poll_until(subscription, client, &mut seen, 8, 1);
    assert_eq!(seen.messages, [b"kept".to_vec()]);
    assert_eq!(api::subscription::copy_length(handle), Some(largest));
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A driven driver with a network (Shared threading) and `N` conductors.
fn driven_network<const N: usize>() -> (Driven, [karyos_client::ClientConductor; N]) {
    let mut driver = EmbeddedDriver::with_config(karyos_driver::DriverConfig {
        client_liveness_timeout: 3_600_000_000_000,
        network: Some(karyos_driver::net::NetworkConfig {
            threading: karyos_driver::agents::ThreadingMode::Shared,
            ..karyos_driver::net::NetworkConfig::default()
        }),
        ..karyos_driver::DriverConfig::default()
    })
    .unwrap();
    let conductors = core::array::from_fn(|_| driver.connect().unwrap());
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        while !flag.load(std::sync::atomic::Ordering::Acquire) {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
    });
    (
        Driven {
            stop,
            thread: Some(thread),
        },
        conductors,
    )
}

/// DESIGN's sizing rule for the copy: a network subscription starts with
/// no image and a copy of 0; its first image grows the copy to that
/// image's largest message, a second image of a larger term grows it once
/// more, and a message of exactly the largest length is delivered.
#[test]
#[cfg_attr(miri, ignore = "UDP sockets")]
fn a_network_subscription_grows_its_copy_with_a_larger_image() {
    // The subscriber on one driver, the two publishers on another.
    let (_reading, [ours]) = driven_network::<1>();
    let (_writing, [small, large]) = driven_network::<2>();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let uri = std::ffi::CString::new(format!("karyos:udp?endpoint=127.0.0.1:{port}")).unwrap();
    let mut subscription = 0;
    // SAFETY: a live C string, a live `u64`, no detail.
    let status = unsafe {
        karyos_client_add_subscription(
            client,
            uri.as_ptr(),
            8,
            &mut subscription,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::Ok.code());
    let handle = Handle::from_raw(subscription);
    assert_eq!(api::subscription::copy_length(handle), Some(0));
    let publish = |conductor, term: u32| {
        let mut publisher = Client::with_conductor(conductor, test_context());
        let publication = publisher
            .add_exclusive_publication(
                &format!(
                    "karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1|term-length={term}"
                ),
                karyos_client::StreamId::new(8),
            )
            .unwrap();
        (publisher, publication)
    };
    let (mut first, mut one) = publish(small, 65536);
    let mut seen = Seen::default();
    // Polls until the copy reaches `length`, offering `payload` on `on`.
    let grow_to = |seen: &mut Seen,
                   on: &mut karyos_client::Publication<karyos_sys::term_bytes::HeapTerms>,
                   publisher: &mut Client<karyos_client::ClientConductor>,
                   payload: &[u8]| {
        let start = std::time::Instant::now();
        let before = seen.messages.len();
        while seen.messages.len() == before {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(60),
                "nothing"
            );
            let _ = (publisher.poll(), poll(client));
            let _ = on.offer(payload);
            let (status, _) = poll_into(subscription, seen, 1);
            assert_eq!(status, Status::Ok.code());
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    };
    let small_max = one
        .max_message_length(karyos_sys::frame::Lane::ZERO)
        .unwrap() as usize;
    grow_to(&mut seen, &mut one, &mut first, b"small");
    assert_eq!(api::subscription::copy_length(handle), Some(small_max));
    // DESIGN's P2-1 on #503: the first image's change is queued. A null or
    // too small `change` is refused and takes nothing; a valid one gets it.
    let mut has = u32::MAX;
    // SAFETY: a null `change` is refused before any use; `has` is live.
    let status = unsafe {
        karyos_subscription_next_image_change(subscription, core::ptr::null_mut(), &mut has)
    };
    assert_eq!((status, has), (Status::InvalidArgument.code(), u32::MAX));
    let mut change = ImageChange {
        size: IMAGE_CHANGE_SIZE_0_1 - 1,
        session_id: 0,
        image_id: 0,
        lane: u32::MAX,
        available: 0,
    };
    // SAFETY: live, aligned out-parameters.
    let status =
        unsafe { karyos_subscription_next_image_change(subscription, &mut change, &mut has) };
    assert_eq!((status, has), (Status::InvalidArgument.code(), u32::MAX));
    change.size = size_of_u32::<ImageChange>();
    // SAFETY: as above.
    let status =
        unsafe { karyos_subscription_next_image_change(subscription, &mut change, &mut has) };
    assert_eq!((status, has), (Status::Ok.code(), 1));
    assert_eq!((change.available, change.lane), (1, 0));
    assert_ne!(change.image_id, 0);
    let (mut second, mut two) = publish(large, 262_144);
    let large_max = two
        .max_message_length(karyos_sys::frame::Lane::ZERO)
        .unwrap() as usize;
    assert!(large_max > small_max);
    let largest = vec![5u8; large_max];
    let start = std::time::Instant::now();
    while !seen
        .messages
        .iter()
        .any(|message| message.len() == large_max)
    {
        assert!(
            start.elapsed() < std::time::Duration::from_secs(60),
            "no large"
        );
        grow_to(&mut seen, &mut two, &mut second, &largest);
    }
    assert_eq!(api::subscription::copy_length(handle), Some(large_max));
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A panic inside the poll, while it holds the subscription, returns
/// INTERNAL instead of unwinding into the caller, and poisons the handle:
/// every later poll answers INTERNAL, and its close still ends it.
#[test]
fn a_panic_in_the_poll_poisons_the_subscription() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (_, subscription) = add_subscription_of(client, STREAM);
    let (_, publication) = add_publication(client);
    assert_eq!(offer(publication, b"boom").0, Status::Ok.code());
    let mut seen = Seen::default();
    api::subscription::PANIC_IN_POLL.with(|panics| panics.set(true));
    let start = std::time::Instant::now();
    let status = loop {
        assert!(start.elapsed() < std::time::Duration::from_secs(3600));
        let _ = poll(client);
        let (status, _) = poll_into(subscription, &mut seen, 1);
        if status != Status::Ok.code() {
            break status;
        }
        std::thread::yield_now();
    };
    api::subscription::PANIC_IN_POLL.with(|panics| panics.set(false));
    assert_eq!(status, Status::Internal.code());
    assert!(seen.messages.is_empty());
    assert_eq!(
        poll_into(subscription, &mut seen, 1).0,
        Status::Internal.code()
    );
    assert_eq!(karyos_subscription_close(subscription), Status::Ok.code());
    assert_eq!(
        poll_into(subscription, &mut seen, 1).0,
        Status::Closed.code()
    );
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// The size of `change` is read and checked before the handle is looked up,
/// so with no driver: a null or too small `change` is refused with
/// INVALID_ARGUMENT and `has` untouched; a full one passes the check and
/// meets the handle's own failure. It runs under Miri, for the read of the
/// caller's `size`.
#[test]
fn next_image_change_checks_its_struct_before_its_handle() {
    let stale = Handle::from_raw(0).raw();
    let mut has = u32::MAX;
    // SAFETY: a null `change` is refused before any use; `has` is live.
    let status =
        unsafe { karyos_subscription_next_image_change(stale, core::ptr::null_mut(), &mut has) };
    assert_eq!((status, has), (Status::InvalidArgument.code(), u32::MAX));
    let mut change = ImageChange {
        size: IMAGE_CHANGE_SIZE_0_1 - 1,
        session_id: 7,
        image_id: 7,
        lane: 7,
        available: 7,
    };
    // SAFETY: live, aligned out-parameters.
    let status = unsafe { karyos_subscription_next_image_change(stale, &mut change, &mut has) };
    assert_eq!((status, has), (Status::InvalidArgument.code(), u32::MAX));
    change.size = size_of_u32::<ImageChange>();
    // SAFETY: as above.
    let status = unsafe { karyos_subscription_next_image_change(stale, &mut change, &mut has) };
    assert_eq!(status, Status::InvalidHandle.code());
    // Nothing was written: the handle failed after the check.
    assert_eq!((has, change.image_id), (u32::MAX, 7));
}
