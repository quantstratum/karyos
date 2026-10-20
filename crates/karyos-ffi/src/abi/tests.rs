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
