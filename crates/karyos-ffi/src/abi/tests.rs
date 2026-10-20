// SPDX-License-Identifier: Apache-2.0

//! The exported client functions over an embedded driver's conductor, so
//! they run under Miri and on macOS (quantstratum-docs:
//! karyos/design/ffi-gap-analysis.md §4.7).

use karyos_client::{Client, Context};
use karyos_driver::EmbeddedDriver;

use super::*;

/// A client context whose control calls wait long enough for a driver
/// thread under Miri, whose clock runs fast against its slow execution.
/// Under Miri its waits sleep: a thread that sleeps is not interpreted,
/// while one that yields spins through the interpreter.
fn test_context() -> Context {
    let builder = Context::builder().timeout(std::time::Duration::from_secs(3600));
    #[cfg(miri)]
    let builder = builder.idle_strategy(karyos_client::IdleStrategy::Sleep(
        std::time::Duration::from_millis(1),
    ));
    builder.build().unwrap()
}

/// Waits a little in a test's loop: a millisecond's sleep under Miri, so
/// the interpreter runs the thread that has work instead of the one that
/// waits (the Miri profile, MIRI.md); a yield natively.
fn idle() {
    #[cfg(miri)]
    std::thread::sleep(std::time::Duration::from_millis(1));
    #[cfg(not(miri))]
    std::thread::yield_now();
}

/// Options from `karyos_client_options_init`.
fn defaults() -> ClientOptions {
    let mut options = core::mem::MaybeUninit::<ClientOptions>::zeroed();
    // SAFETY: a live, aligned, writable `ClientOptions`.
    let status = unsafe {
        karyos_client_options_init_sized(options.as_mut_ptr(), size_of::<ClientOptions>())
    };
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
    // ADR-0066: the agents' default.
    assert_eq!(options.idle_strategy, client::IDLE_YIELD_THEN_SLEEP);
    assert!(options.dir.is_null());
    assert_eq!(options.timeout_ns, 10_000_000_000);
    assert_eq!(options.max_pending, 64);
    assert_eq!(options.max_images, 8);
    // SAFETY: a null pointer is refused before any use.
    let status = unsafe {
        karyos_client_options_init_sized(core::ptr::null_mut(), size_of::<ClientOptions>())
    };
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

    for unknown in [4, 9] {
        let bad_idle = ClientOptions {
            idle_strategy: unknown,
            ..options
        };
        assert_eq!(connect(&bad_idle).0, Status::InvalidArgument.code());
    }
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

/// A stream shared by two concurrent publication handles.
const STREAM_CONCURRENT: i32 = 1003;

/// A timed stream: a schedule ring of four entries, the default settings.
const STREAM_TIMED: i32 = 1004;

/// A stream with a keyed conflation table of 4 keys (F7b-2a): an offer's
/// reserved value is its key.
const STREAM_CONFLATED: i32 = 1005;

/// [`STREAM_CONFLATED`]'s table on a stream of two concurrent publication
/// handles.
const STREAM_CONFLATED_CONCURRENT: i32 = 1006;

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
    let mut shared = stream_config(STREAM_CONCURRENT);
    shared.buffer.publication = karyos_sys::log_buffer::PublicationMode::Concurrent {
        publishers: 2,
        allow_non_lse: true,
    };
    let _ = driver.add_stream(shared).unwrap();
    let mut conflated = stream_config(STREAM_CONFLATED);
    conflated.conflation = Some(karyos_sys::conflation::ConflationConfig {
        keys: 4,
        value_capacity: 64,
        journal_capacity: 4096,
    });
    let mut shared_conflated = stream_config(STREAM_CONFLATED_CONCURRENT);
    shared_conflated.buffer.publication = shared.buffer.publication;
    shared_conflated.conflation = conflated.conflation;
    let _ = driver.add_stream(conflated).unwrap();
    let _ = driver.add_stream(shared_conflated).unwrap();
    let mut timed = stream_config(STREAM_TIMED);
    timed.buffer.schedule_capacity = 4;
    let _ = driver.add_stream(timed).unwrap();
    let ours = driver.connect().unwrap();
    let theirs = driver.connect().unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        while !flag.load(std::sync::atomic::Ordering::Acquire) {
            let work = driver.do_work().unwrap();
            if work == 0 {
                idle();
            }
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

/// `karyos_client_add_concurrent_publication` of the shared stream.
fn add_concurrent(client: u64) -> (i32, u64) {
    add_concurrent_of(client, STREAM_CONCURRENT)
}

/// `karyos_client_add_concurrent_publication` of `stream`.
fn add_concurrent_of(client: u64, stream: i32) -> (i32, u64) {
    let mut publication = 0;
    // SAFETY: a C string literal, a live `u64`, no detail.
    let status = unsafe {
        karyos_client_add_concurrent_publication(
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

/// `karyos_publication_offer_at` of `payload` on lane 0 at `tx_time`.
fn offer_at(publication: u64, payload: &[u8], tx_time: u64) -> (i32, Accepted) {
    let mut done = accepted();
    // SAFETY: `payload` is live for the call; `done` is a live
    // `karyos_accepted` with its size.
    let status = unsafe {
        karyos_publication_offer_at(
            publication,
            0,
            payload.as_ptr(),
            payload.len(),
            tx_time,
            &mut done,
        )
    };
    (status, done)
}

/// `karyos_clock_now` of `domain`: the status and the time written, the
/// marker `u64::MAX` when nothing was.
fn clock_now(domain: u32) -> (i32, u64) {
    let mut now = u64::MAX;
    // SAFETY: a live, aligned `u64`.
    let status = unsafe { karyos_clock_now(domain, &mut now) };
    (status, now)
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
        idle();
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
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
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
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
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
        idle();
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

#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn concurrent_handles_share_a_stream_on_lane_0() {
    let (_driven, ours, theirs) = driven();
    let context = test_context();
    let client = client::insert_embedded(Client::with_conductor(ours, context.clone()))
        .unwrap()
        .raw();
    let mut subscriber = Client::with_conductor(theirs, context);
    let mut reading = subscriber
        .add_subscription(
            "karyos:ipc",
            karyos_client::StreamId::new(STREAM_CONCURRENT),
        )
        .unwrap();
    let (status, first) = add_concurrent(client);
    assert_eq!(status, Status::Ok.code());
    let (status, second) = add_concurrent(client);
    assert_eq!(status, Status::Ok.code());
    // The stream takes two publishers; an exclusive one is refused too.
    assert_ne!(add_concurrent(client).0, Status::Ok.code());
    assert_ne!(
        add_publication_of(client, STREAM_CONCURRENT).0,
        Status::Ok.code()
    );
    // A concurrent handle of an exclusive stream is refused.
    assert_ne!(add_concurrent_of_exclusive(client), Status::Ok.code());

    // Offers and staged commits from both handles, on lane 0 only.
    let (status, offered) = offer(first, b"one");
    assert_eq!(status, Status::Ok.code());
    assert_eq!(offered.lane, 0);
    assert_eq!(offer(second, b"two").0, Status::Ok.code());
    let (status, staged, buffer) = claim(second, 0, 5);
    assert_eq!(status, Status::Ok.code());
    // SAFETY: the claim's buffer holds 5 bytes.
    unsafe { fill(buffer, b"three") };
    let (status, committed) = commit(staged);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(committed.lane, 0);
    assert!(committed.position > offered.position);
    // SAFETY: a live payload of 1 byte, no out-parameter.
    let other_lane =
        unsafe { karyos_publication_offer(first, 1, b"x".as_ptr(), 1, core::ptr::null_mut()) };
    assert_eq!(other_lane, Status::InvalidLane.code());
    assert_eq!(claim(first, 1, 1).0, Status::InvalidLane.code());
    // The claim bound is the handle's message limit, at max and max + 1.
    let max = crate::api::publication::lane_max(
        crate::handles::Handle::from_raw(first),
        karyos_sys::frame::Lane::ZERO,
    )
    .unwrap();
    let (status, at_max, _) = claim(first, 0, max);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(karyos_claim_abort(at_max), Status::Ok.code());
    assert_eq!(claim(first, 0, max + 1).0, Status::MessageTooLarge.code());
    assert_eq!(
        read(&mut subscriber, &mut reading, 3),
        [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );

    // Closing a handle frees its publisher slot.
    assert_eq!(karyos_publication_close(first), Status::Ok.code());
    let (status, third) = add_concurrent(client);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(offer(third, b"four").0, Status::Ok.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(offer(second, b"x").0, Status::Closed.code());
}

/// `karyos_client_add_concurrent_publication` of the exclusive stream.
fn add_concurrent_of_exclusive(client: u64) -> i32 {
    let mut publication = 0;
    // SAFETY: a C string literal, a live `u64`, no detail.
    unsafe {
        karyos_client_add_concurrent_publication(
            client,
            c"karyos:ipc".as_ptr(),
            STREAM,
            &mut publication,
            core::ptr::null_mut(),
        )
    }
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
        idle();
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
    // A `karyos:ipc` subscription has no image changes: `has` and `lost`
    // are written as 0 and `change` is left alone (the Miri path of both
    // writes, MIRI.md).
    let mut change = ImageChange {
        size: size_of_u32::<ImageChange>(),
        session_id: 7,
        image_id: 7,
        lane: 7,
        available: 7,
    };
    let (mut has, mut lost) = (u32::MAX, u64::MAX);
    // SAFETY: live, aligned out-parameters.
    let status =
        unsafe { karyos_subscription_next_image_change(subscription, &mut change, &mut has) };
    assert_eq!((status, has, change.image_id), (Status::Ok.code(), 0, 7));
    // SAFETY: a live, aligned `u64`.
    let status = unsafe { karyos_subscription_image_changes_lost(subscription, &mut lost) };
    assert_eq!((status, lost), (Status::Ok.code(), 0));
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
                idle();
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
        idle();
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
            let work = driver.do_work().unwrap();
            if work == 0 {
                idle();
            }
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
    let port = test_port();
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
        idle();
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

/// F7a-3 (quantstratum-docs: karyos/design/ffi-gap-analysis.md §6): the
/// monotonic clock reads, never backwards; an unknown domain and a null or
/// misaligned out-pointer are refused and nothing is written.
#[test]
fn the_clock_reads_the_monotonic_domain_and_refuses_bad_arguments() {
    let (status, first) = clock_now(CLOCK_MONOTONIC);
    assert_eq!(status, Status::Ok.code());
    let (status, second) = clock_now(CLOCK_MONOTONIC);
    assert_eq!(status, Status::Ok.code());
    assert!(second >= first);
    assert_eq!(clock_now(7), (Status::InvalidArgument.code(), u64::MAX));
    // SAFETY: a null pointer, which the call refuses before any write.
    let status = unsafe { karyos_clock_now(CLOCK_MONOTONIC, core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut words = [0u64; 2];
    let misaligned = words
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(1)
        .cast::<u64>();
    // SAFETY: a misaligned pointer, which the call refuses before any
    // write.
    let status = unsafe { karyos_clock_now(CLOCK_MONOTONIC, misaligned) };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!(words, [0, 0]);
}

/// F7a-3: `CLOCK_TAI` is a platform capability: read on Linux when the
/// kernel serves it, `KARYOS_E_UNSUPPORTED` otherwise (never a bad
/// schedule), with nothing written.
#[test]
#[cfg_attr(miri, ignore = "Miri's isolation reads no CLOCK_TAI")]
fn the_tai_clock_is_read_where_the_platform_has_it() {
    let (status, now) = clock_now(CLOCK_TAI);
    #[cfg(target_os = "linux")]
    let served = karyos_sys::host_clock::host_tai_ns().is_some();
    #[cfg(not(target_os = "linux"))]
    let served = false;
    if served {
        assert_eq!(status, Status::Ok.code());
        assert_ne!(now, u64::MAX);
    } else {
        assert_eq!((status, now), (Status::Unsupported.code(), u64::MAX));
    }
}

/// F7a-3: a timed offer's arguments are checked as an offer's, before the
/// handle: a null payload of a length is refused, and a handle that is
/// none answers its status with nothing written.
#[test]
fn a_timed_offer_checks_its_arguments_first() {
    let mut done = accepted();
    // SAFETY: a null payload of a length, refused before any read.
    let status = unsafe { karyos_publication_offer_at(1, 0, core::ptr::null(), 4, 0, &mut done) };
    assert_eq!(status, Status::InvalidArgument.code());
    let (status, done) = offer_at(u64::MAX, b"x", 0);
    assert_eq!(status, Status::InvalidHandle.code());
    assert_eq!((done.lane, done.position), (u32::MAX, u64::MAX));
}

/// F7a-3: a timed lane granted over the in-process command ring (T-x2)
/// takes a timed offer, delivered; a plain offer, a time below the lane's
/// last or past its horizon, a lane that is not timed and a concurrent
/// handle are refused with `KARYOS_E_INVALID_SCHEDULE`, and an unconfigured
/// lane with `KARYOS_E_INVALID_LANE`.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_timed_lane_takes_a_timed_offer() {
    let (_driven, ours, theirs) = driven();
    let context = test_context();
    let client = client::insert_embedded(Client::with_conductor(ours, context.clone()))
        .unwrap()
        .raw();
    let mut subscriber = Client::with_conductor(theirs, context);
    let mut reading = subscriber
        .add_subscription("karyos:ipc", karyos_client::StreamId::new(STREAM_TIMED))
        .unwrap();
    let (status, publication) = add_publication_of(client, STREAM_TIMED);
    assert_eq!(status, Status::Ok.code());
    let (status, now) = clock_now(CLOCK_MONOTONIC);
    assert_eq!(status, Status::Ok.code());
    let (status, done) = offer_at(publication, b"timed", now);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(done.lane, 0);
    let schedule = Status::InvalidSchedule.code();
    assert_eq!(offer(publication, b"plain").0, schedule);
    assert_eq!(offer_at(publication, b"back", now - 1).0, schedule);
    assert_eq!(
        offer_at(publication, b"far", now + 60_000_000_000).0,
        schedule
    );
    let mut ignored = accepted();
    // SAFETY: a live payload and `karyos_accepted`.
    let status =
        unsafe { karyos_publication_offer_at(publication, 1, b"x".as_ptr(), 1, now, &mut ignored) };
    assert_eq!(status, Status::InvalidLane.code());
    // A lane that is not timed, and a concurrent handle.
    let (status, plain) = add_publication(client);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(offer_at(plain, b"x", now).0, schedule);
    let (status, concurrent) = add_concurrent(client);
    assert_eq!(status, Status::Ok.code());
    assert_eq!(offer_at(concurrent, b"x", now).0, schedule);
    assert_eq!(read(&mut subscriber, &mut reading, 1), [b"timed".to_vec()]);
}

mod archive;
mod concurrent;
mod conflated;
mod outcomes;
mod rejoin;
mod replay;
mod threads;

// Subscription options (F7b).

/// Options from `karyos_subscription_options_init`.
fn subscription_defaults() -> SubscriptionOptions {
    let mut options = core::mem::MaybeUninit::<SubscriptionOptions>::zeroed();
    // SAFETY: a live, aligned, writable `SubscriptionOptions`.
    let status = unsafe {
        karyos_subscription_options_init_sized(
            options.as_mut_ptr(),
            size_of::<SubscriptionOptions>(),
        )
    };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_subscription_options_init` wrote every field.
    unsafe { options.assume_init() }
}

/// `karyos_client_add_subscription_with` of `stream` on `karyos:ipc`: the
/// status and the handle written (`u64::MAX` when none was).
///
/// # Safety
///
/// `options` is null or a readable struct of at least its `size` bytes.
unsafe fn add_subscription_with(
    client: u64,
    stream: i32,
    options: *const SubscriptionOptions,
) -> (i32, u64) {
    let mut subscription = u64::MAX;
    // SAFETY: a C string literal, a live `u64`, no detail; `options` per
    // the function's contract.
    let status = unsafe {
        karyos_client_add_subscription_with(
            client,
            c"karyos:ipc".as_ptr(),
            stream,
            options,
            &mut subscription,
            core::ptr::null_mut(),
        )
    };
    (status, subscription)
}

#[test]
fn subscription_options_init_fills_the_defaults_and_the_size() {
    let options = subscription_defaults();
    assert_eq!(options.size, size_of_u32::<SubscriptionOptions>());
    assert_eq!(options.size, SUBSCRIPTION_OPTIONS_SIZE_ARCHIVE);
    assert_eq!(
        (options.role, options.rejoin, options.reserved),
        (ROLE_REQUIRED, REJOIN_AT_HEAD, 0)
    );
    assert_eq!(
        (
            options.archive,
            options.archive_client_id,
            options.replay_stream_id,
            options.secondary
        ),
        (0, 0, 0, 0)
    );
    // SAFETY: a null pointer is refused before any use.
    let status = unsafe {
        karyos_subscription_options_init_sized(
            core::ptr::null_mut(),
            size_of::<SubscriptionOptions>(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
}

/// Guard words after a caller's struct: an init that writes past the
/// caller's size overwrites them.
const CANARY: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// The first (ABI 0.1.0) `karyos_subscription_options`, as an older header
/// declared it: 16 bytes, then guard words.
#[repr(C)]
struct OlderSubscriptionOptions {
    size: u32,
    role: u32,
    rejoin: u32,
    reserved: u32,
    canaries: [u64; 3],
}

/// An older header's 16-byte struct, filled through the exported
/// `karyos_subscription_options_init` an older binary calls (owner item
/// 48, F-48: it wrote the current 40 bytes) and through the sized init:
/// 16 bytes at most, the size set to 16, the guard words intact.
#[test]
fn an_older_headers_subscription_options_are_filled_within_their_size() {
    for sized in [false, true] {
        let mut older = OlderSubscriptionOptions {
            size: 0,
            role: 9,
            rejoin: 9,
            reserved: 9,
            canaries: [CANARY; 3],
        };
        let options = (&raw mut older).cast::<SubscriptionOptions>();
        let status = if sized {
            // SAFETY: `older` is 16 writable bytes and more.
            unsafe { karyos_subscription_options_init_sized(options, 16) }
        } else {
            // SAFETY: `older` is the 0.1.0 size and more.
            unsafe { karyos_subscription_options_init(options) }
        };
        assert_eq!(status, Status::Ok.code());
        assert_eq!(older.size, SUBSCRIPTION_OPTIONS_SIZE_0_1);
        assert_eq!(
            (older.role, older.rejoin, older.reserved),
            (ROLE_REQUIRED, REJOIN_AT_HEAD, 0)
        );
        assert_eq!(older.canaries, [CANARY; 3], "nothing written past 16 bytes");
    }
    // A size below the first version's writes nothing.
    let mut older = OlderSubscriptionOptions {
        size: 7,
        role: 9,
        rejoin: 9,
        reserved: 9,
        canaries: [CANARY; 3],
    };
    // SAFETY: a live local of more than the size given.
    let status = unsafe {
        karyos_subscription_options_init_sized(
            (&raw mut older).cast(),
            usize::try_from(SUBSCRIPTION_OPTIONS_SIZE_0_1 - 4).unwrap(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!((older.size, older.role), (7, 9));
}

/// The sized init with this header's size fills every field, and the
/// struct an older binary's init filled is read by its 16 bytes only, at
/// an address that is 4 mod 8 as an older header's struct may be. The
/// options are accepted (the client is looked up next: no client 0).
#[test]
fn a_16_byte_struct_is_read_by_its_size() {
    let mut options = core::mem::MaybeUninit::<SubscriptionOptions>::zeroed();
    // SAFETY: a live, aligned, writable `SubscriptionOptions`.
    let status = unsafe {
        karyos_subscription_options_init_sized(
            options.as_mut_ptr(),
            size_of::<SubscriptionOptions>(),
        )
    };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: the sized init wrote every field.
    let full = unsafe { options.assume_init() };
    assert_eq!(full.size, SUBSCRIPTION_OPTIONS_SIZE_ARCHIVE);
    // An older header's struct is 4-aligned and may land at an address
    // that is 4 mod 8, where this version's 8-aligned struct cannot: the
    // 16 bytes start at whichever of the first two words sits there, so a
    // check of this version's alignment would refuse them.
    let mut words = [0_u32; 6];
    let at = usize::from(words.as_ptr().addr() % 8 == 0);
    let small = (&raw mut words[at]).cast::<SubscriptionOptions>();
    assert_eq!(small.addr() % 8, 4);
    // SAFETY: `words` holds the 0.1.0 size from `at` on.
    let status = unsafe { karyos_subscription_options_init(small) };
    assert_eq!(status, Status::Ok.code());
    assert_eq!(words[at], SUBSCRIPTION_OPTIONS_SIZE_0_1);
    // SAFETY: the struct is 16 bytes at `small`, of its stated size.
    let (status, subscription) = unsafe { add_subscription_with(0, STREAM, small) };
    assert_eq!(
        status,
        Status::InvalidHandle.code(),
        "the options were accepted"
    );
    assert_eq!(subscription, u64::MAX);
}

/// The grown `karyos_stream_options`: an older binary's 64- or 80-byte
/// struct is filled within its size, the legacy symbol fills the 0.1.0
/// 64 bytes, and this header's size fills them all.
#[test]
fn an_older_headers_stream_options_are_filled_within_their_size() {
    #[repr(C, align(8))]
    struct Room([u8; 120]);
    let ours = size_of_u32::<StreamOptions>();
    for (size, legacy) in [
        (STREAM_OPTIONS_SIZE_0_1, false),
        (STREAM_OPTIONS_SIZE_CONFLATION, false),
        (STREAM_OPTIONS_SIZE_CONCURRENT, false),
        (STREAM_OPTIONS_SIZE_CONFLATION, true),
    ] {
        let mut room = Room([0xa5; 120]);
        let options = (&raw mut room).cast::<StreamOptions>();
        let status = if legacy {
            // SAFETY: `room` is more than the 0.1.0 size.
            unsafe { karyos_stream_options_init(options) }
        } else {
            // SAFETY: `room` is more than `size` writable bytes.
            unsafe { karyos_stream_options_init_sized(options, usize::try_from(size).unwrap()) }
        };
        assert_eq!(status, Status::Ok.code());
        let written = if legacy {
            STREAM_OPTIONS_SIZE_0_1
        } else {
            size.min(ours)
        };
        let bytes = &room.0;
        assert_eq!(
            u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            written
        );
        let past = usize::try_from(written).unwrap();
        assert!(
            bytes[past..].iter().all(|byte| *byte == 0xa5),
            "nothing written past {written} bytes"
        );
    }
}

/// Bad options are refused before the client is looked up: nothing is
/// opened and the out-parameter is not written.
#[test]
fn add_with_refuses_bad_options_and_opens_nothing() {
    let refused = |options: *const SubscriptionOptions| {
        // SAFETY: null, or a live local of its stated size.
        let (status, subscription) = unsafe { add_subscription_with(0, STREAM, options) };
        assert_eq!(status, Status::InvalidArgument.code());
        assert_eq!(subscription, u64::MAX, "nothing written");
    };
    refused(core::ptr::null());
    let short = SubscriptionOptions {
        size: SUBSCRIPTION_OPTIONS_SIZE_0_1 - 4,
        ..subscription_defaults()
    };
    refused(&short);
    for options in [
        SubscriptionOptions {
            role: 3,
            ..subscription_defaults()
        },
        SubscriptionOptions {
            rejoin: 3,
            ..subscription_defaults()
        },
        SubscriptionOptions {
            reserved: 1,
            ..subscription_defaults()
        },
        // A size between the two layouts.
        SubscriptionOptions {
            size: SUBSCRIPTION_OPTIONS_SIZE_ARCHIVE - 8,
            ..subscription_defaults()
        },
        // The Archive rejoin in the smaller layout.
        SubscriptionOptions {
            size: SUBSCRIPTION_OPTIONS_SIZE_0_1,
            rejoin: REJOIN_ARCHIVE,
            ..subscription_defaults()
        },
        // An Archive field for another policy.
        SubscriptionOptions {
            archive: 7,
            ..subscription_defaults()
        },
        SubscriptionOptions {
            rejoin: REJOIN_CLOSE,
            replay_stream_id: 9,
            ..subscription_defaults()
        },
        // A secondary that is not a fallback policy.
        SubscriptionOptions {
            rejoin: REJOIN_ARCHIVE,
            archive: 7,
            secondary: REJOIN_ARCHIVE,
            ..subscription_defaults()
        },
    ] {
        refused(&options);
    }
    // The ABI's role codes are the wire's (karyos_protocol::cnc).
    let role = |code| {
        subscription_options(SubscriptionOptions {
            role: code,
            ..subscription_defaults()
        })
        .map(|options| options.0.role)
    };
    assert_eq!(
        role(ROLE_REQUIRED),
        Ok(karyos_client::SubscriberRole::Required)
    );
    assert_eq!(
        role(ROLE_OPTIONAL),
        Ok(karyos_client::SubscriberRole::Optional)
    );
    assert_eq!(
        role(ROLE_OBSERVER),
        Ok(karyos_client::SubscriberRole::Observer)
    );
}

/// An optional reader under `KARYOS_REJOIN_CLOSE`, added from a struct of
/// a newer header (read by its prefix), does not hold its publisher back;
/// lapped, its poll answers CLOSED_BY_OVERRUN, and so does every later
/// one. The one driver test of F7b under Miri: it reaches the options'
/// prefix read, the add's out-parameter and the poll's stop status.
#[test]
fn an_optional_reader_under_close_is_closed_by_its_overrun() {
    /// `karyos_subscription_options` of a newer header: one more field.
    #[repr(C)]
    struct Newer {
        options: SubscriptionOptions,
        later: u64,
    }
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let newer = Newer {
        options: SubscriptionOptions {
            size: size_of_u32::<Newer>(),
            role: ROLE_OPTIONAL,
            rejoin: REJOIN_CLOSE,
            ..subscription_defaults()
        },
        later: u64::MAX,
    };
    // SAFETY: `newer` is live and its stated size.
    let (status, subscription) =
        unsafe { add_subscription_with(client, STREAM, (&raw const newer).cast()) };
    assert_eq!(status, Status::Ok.code());
    assert_ne!(subscription, u64::MAX);
    let (_, publication) = add_publication(client);
    // Four terms of the largest messages, none read: the publisher's limit
    // moves on without the optional reader.
    let message = vec![7u8; 8000];
    let terms = karyos_sys::sizing::MIN_TERM_LENGTH as usize * 4;
    let start = std::time::Instant::now();
    for _ in 0..terms / message.len() {
        while offer(publication, &message).0 != Status::Ok.code() {
            assert!(start.elapsed() < std::time::Duration::from_secs(3600));
            std::thread::yield_now();
        }
    }
    let mut seen = Seen::default();
    let (status, delivered) = poll_into(subscription, &mut seen, 64);
    assert_eq!(status, Status::ClosedByOverrun.code(), "{delivered}");
    assert_eq!(
        poll_into(subscription, &mut seen, 64),
        (Status::ClosedByOverrun.code(), 0),
        "sticky"
    );
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A `karyos:ipc` subscription's stream sealed (the driver removed it):
/// the poll delivers what came before, then answers CLOSED, and so does
/// every later poll.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_sealed_stream_closes_its_subscription() {
    const SEALED: i32 = 1010;
    let mut options = core::mem::MaybeUninit::<DriverOptions>::zeroed();
    // SAFETY: a live, aligned, writable `DriverOptions`.
    let status = unsafe {
        karyos_driver_options_init_sized(options.as_mut_ptr(), size_of::<DriverOptions>())
    };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_driver_options_init` wrote every field.
    let options = unsafe { options.assume_init() };
    let mut driver = 0;
    // SAFETY: live, aligned pointers; no detail.
    let status = unsafe { karyos_driver_create(&options, &mut driver, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    let mut stream = core::mem::MaybeUninit::<StreamOptions>::zeroed();
    // SAFETY: a live, aligned, writable `StreamOptions`.
    let status = unsafe {
        karyos_stream_options_init_sized(stream.as_mut_ptr(), size_of::<StreamOptions>())
    };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_stream_options_init` wrote every field.
    let mut stream = unsafe { stream.assume_init() };
    stream.stream_id = SEALED;
    // SAFETY: live, aligned pointers; no detail.
    let status = unsafe { karyos_driver_add_stream(driver, &stream, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    assert_eq!(
        karyos_driver_start(driver, client::IDLE_YIELD, 0),
        Status::Ok.code()
    );
    let mut client = 0;
    // SAFETY: a live, aligned `u64`; no detail.
    let status = unsafe { karyos_driver_connect(driver, &mut client, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    let (status, subscription) = add_subscription_of(client, SEALED);
    assert_eq!(status, Status::Ok.code());
    let (status, publication) = add_publication_of(client, SEALED);
    assert_eq!(status, Status::Ok.code());
    let start = std::time::Instant::now();
    while offer(publication, b"last").0 != Status::Ok.code() {
        assert!(start.elapsed() < std::time::Duration::from_secs(60));
        std::thread::yield_now();
    }
    assert_eq!(
        karyos_driver_remove_stream(driver, SEALED),
        Status::Ok.code()
    );
    // The live publication's next attempt finds the stream closed and
    // releases it, which completes the seal (EmbeddedDriver::remove_stream).
    assert_ne!(offer(publication, b"after").0, Status::Ok.code());
    let mut seen = Seen::default();
    let status = loop {
        assert!(start.elapsed() < std::time::Duration::from_secs(60));
        let _ = poll(client);
        let (status, _) = poll_into(subscription, &mut seen, 8);
        if status != Status::Ok.code() {
            break status;
        }
        std::thread::yield_now();
    };
    assert_eq!(status, Status::Closed.code());
    assert_eq!(seen.messages, [b"last".to_vec()]);
    assert_eq!(
        poll_into(subscription, &mut seen, 8),
        (Status::Closed.code(), 0),
        "sticky"
    );
    // How it ended (F9c): the stream's removal, at its seal.
    let (status, end) = replay::subscription_end(subscription);
    assert_eq!(status, Status::Ok.code());
    assert_eq!((end.reason, end.seal_code), (END_STREAM_REMOVED, 3));
    assert!(end.position > 0);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(karyos_driver_close(driver), Status::Ok.code());
}

// Offer options (F7b-2a).

/// Options from `karyos_offer_options_init`.
fn offer_defaults() -> OfferOptions {
    let mut options = core::mem::MaybeUninit::<OfferOptions>::zeroed();
    // SAFETY: a live, aligned, writable `OfferOptions`.
    let status =
        unsafe { karyos_offer_options_init_sized(options.as_mut_ptr(), size_of::<OfferOptions>()) };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_offer_options_init` wrote every field.
    unsafe { options.assume_init() }
}

/// `karyos_publication_offer_with` of `payload` on lane 0 with `options`.
///
/// # Safety
///
/// `options` is null or a readable struct of at least its `size` bytes.
unsafe fn offer_with(
    publication: u64,
    payload: &[u8],
    options: *const OfferOptions,
) -> (i32, Accepted) {
    let mut done = accepted();
    // SAFETY: `payload` is live for the call, `done` is a live
    // `karyos_accepted` with its size; `options` per the contract.
    let status = unsafe {
        karyos_publication_offer_with(
            publication,
            0,
            payload.as_ptr(),
            payload.len(),
            options,
            &mut done,
        )
    };
    (status, done)
}

#[test]
fn offer_options_init_fills_the_defaults_and_the_size() {
    let options = offer_defaults();
    assert_eq!(options.size, size_of_u32::<OfferOptions>());
    assert_eq!(options.size, OFFER_OPTIONS_SIZE_0_1);
    assert_eq!((options.reserved, options.reserved_value), (0, 0));
    // SAFETY: a null pointer is refused before any use.
    let status = unsafe {
        karyos_offer_options_init_sized(core::ptr::null_mut(), size_of::<OfferOptions>())
    };
    assert_eq!(status, Status::InvalidArgument.code());
}

/// Bad options, then a null payload, are refused before the handle is
/// looked up, with nothing written to `accepted`; a newer header's options
/// and a payload reach the handle check. No driver: a Miri test of the
/// options read and the payload slice.
#[test]
fn offer_with_refuses_bad_options() {
    let refused = |options: *const OfferOptions| {
        // SAFETY: null, or a live local of its stated size.
        let (status, done) = unsafe { offer_with(0, b"x", options) };
        assert_eq!(status, Status::InvalidArgument.code());
        assert_eq!((done.lane, done.position), (u32::MAX, u64::MAX));
    };
    refused(core::ptr::null());
    refused(&OfferOptions {
        size: OFFER_OPTIONS_SIZE_0_1 - 8,
        ..offer_defaults()
    });
    refused(&OfferOptions {
        reserved: 1,
        ..offer_defaults()
    });
    // A null payload of nonzero length is refused after the options.
    let mut done = accepted();
    // SAFETY: a null payload, as the case under test; live options and
    // accepted of their sizes.
    let status = unsafe {
        karyos_publication_offer_with(0, 0, core::ptr::null(), 1, &offer_defaults(), &mut done)
    };
    assert_eq!(status, Status::InvalidArgument.code());
    /// `karyos_offer_options` of a newer header: one more field.
    #[repr(C)]
    struct Newer {
        options: OfferOptions,
        later: u64,
    }
    // Options of a newer header, read by their prefix, and a payload
    // borrowed for the call reach the handle check.
    let newer = Newer {
        options: OfferOptions {
            size: size_of_u32::<Newer>(),
            ..offer_defaults()
        },
        later: u64::MAX,
    };
    // SAFETY: `newer` is live and its stated size.
    let (status, done) = unsafe { offer_with(0, b"payload", (&raw const newer).cast()) };
    assert_eq!(status, Status::InvalidHandle.code());
    assert_eq!((done.lane, done.position), (u32::MAX, u64::MAX));
}

/// A reserved value reaches every subscriber's message info; the options
/// come from a newer header's larger struct, read by its prefix. On a
/// conflated stream the value is the key: a key outside the table is
/// CONFLATION, with nothing reserved.
#[test]
fn an_offer_carries_its_reserved_value() {
    /// `karyos_offer_options` of a newer header: one more field.
    #[repr(C)]
    struct Newer {
        options: OfferOptions,
        later: u64,
    }
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
    let newer = Newer {
        options: OfferOptions {
            size: size_of_u32::<Newer>(),
            reserved: 0,
            reserved_value: -42,
        },
        later: u64::MAX,
    };
    let start = std::time::Instant::now();
    let (status, done) = loop {
        // SAFETY: `newer` is live and its stated size.
        let (status, done) =
            unsafe { offer_with(publication, b"valued", (&raw const newer).cast()) };
        if status != Status::NotConnected.code() {
            break (status, done);
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(3600));
        std::thread::yield_now();
    };
    assert_eq!(status, Status::Ok.code());
    assert_eq!(done.lane, 0);
    let mut values = Vec::new();
    while values.is_empty() {
        assert!(start.elapsed() < std::time::Duration::from_secs(3600));
        let _ = subscriber.poll();
        let _ = reading.poll(
            |bytes, info| values.push((bytes.to_vec(), info.reserved_value)),
            karyos_client::MessageLimit::new(4),
        );
        std::thread::yield_now();
    }
    assert_eq!(values, [(b"valued".to_vec(), -42)]);
    // A conflated stream's key: 0..4.
    let (status, keyed) = add_publication_of(client, STREAM_CONFLATED);
    assert_eq!(status, Status::Ok.code());
    let outside = OfferOptions {
        reserved_value: 4,
        ..offer_defaults()
    };
    // SAFETY: `outside` is live and its stated size.
    let (status, done) = unsafe { offer_with(keyed, b"v", &outside) };
    assert_eq!(status, Status::Conflation.code());
    assert_eq!((done.lane, done.position), (u32::MAX, u64::MAX));
    // Nothing was appended: the first key inside the table starts the log.
    let inside = OfferOptions {
        reserved_value: 3,
        ..offer_defaults()
    };
    let (status, first) = loop {
        // SAFETY: `inside` is live and its stated size.
        let (status, first) = unsafe { offer_with(keyed, b"v", &inside) };
        if status != Status::NotConnected.code() && status != Status::BackPressured.code() {
            break (status, first);
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(3600));
        std::thread::yield_now();
    };
    assert_eq!(status, Status::Ok.code());
    assert_eq!((first.lane, first.position), (0, 0));
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A concurrent handle granted on a conflated stream checks its key as
/// the exclusive one does, before it appends.
#[test]
fn a_concurrent_offer_refuses_a_key_outside_its_table() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (status, keyed) = add_concurrent_of(client, STREAM_CONFLATED_CONCURRENT);
    assert_eq!(status, Status::Ok.code());
    let outside = OfferOptions {
        reserved_value: 4,
        ..offer_defaults()
    };
    // SAFETY: `outside` is live and its stated size.
    let (status, done) = unsafe { offer_with(keyed, b"v", &outside) };
    assert_eq!(status, Status::Conflation.code());
    assert_eq!((done.lane, done.position), (u32::MAX, u64::MAX));
    let inside = OfferOptions {
        reserved_value: 0,
        ..offer_defaults()
    };
    // SAFETY: `inside` is live and its stated size.
    let (status, first) = unsafe { offer_with(keyed, b"v", &inside) };
    assert_eq!(status, Status::Ok.code());
    assert_eq!((first.lane, first.position), (0, 0));
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// A loopback UDP port no socket holds now, picked below every ephemeral
/// range (Linux 32768 to 60999, macOS 49152 to 65535), so no bind to port
/// 0 can take it before the driver binds it (karyos#520). As karyos-driver's
/// `test_ports`: a process starts at its own offset and walks the range,
/// skipping ports it cannot bind. Owner item 26 (an `endpoint=host:0`
/// subscription that reports its port) would remove the race.
fn test_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    const FIRST: u32 = 20_000;
    const COUNT: u32 = 12_000;
    let start = std::process::id().wrapping_mul(2_654_435_761) % COUNT;
    loop {
        let taken = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(taken < COUNT, "no free test port left in the range");
        let port = u16::try_from(FIRST + (start + taken) % COUNT).unwrap();
        if std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}
