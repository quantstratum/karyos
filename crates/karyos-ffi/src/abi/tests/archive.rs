// SPDX-License-Identifier: Apache-2.0

//! Archive connections over the C ABI (F9a): `karyos_archive_list` and
//! `karyos_archive_close` driverless, over an in-memory Archive, so they
//! run under Miri (quantstratum-docs: karyos/design/ffi-archive.md §4);
//! `karyos_archive_connect`'s argument checks.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use karyos_archive::catalog::{SourceIncarnation, Stop, StopReason};
use karyos_archive::control::{
    ControlMessage, ControlResponse, RecordingDescriptor, RecordingState, ResponseCode,
};
use karyos_archive::segment::Geometry;
use karyos_sys::sizing::MIN_TERM_LENGTH;

use super::*;
use crate::api::archive::{MemoryRequests, MemoryResponses, insert_memory};

type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

/// The `(from_id, max_count)` of each listing an Archive was sent.
type Asked = Arc<Mutex<Vec<(u64, u32)>>>;

/// How an in-memory Archive answers a listing.
#[derive(Clone, Copy)]
enum Answer {
    /// The catalog's recordings from the requested id on.
    Catalog,
    /// A refusal with this code.
    Refuse(ResponseCode),
    /// Nothing.
    Silent,
}

/// The recordings of the in-memory catalog: ids 1 to 3.
const CATALOG: u64 = 3;

fn descriptor<'a>(correlation_id: u64, recording_id: u64) -> RecordingDescriptor<'a> {
    let state = if recording_id == 1 {
        RecordingState::Recording {
            written: 64,
            incomplete: true,
        }
    } else {
        RecordingState::Stopped(Stop {
            position: 100 * recording_id,
            time_ns: 2,
            reason: StopReason::Stopped,
            incomplete: false,
            closed_utc_ns: None,
        })
    };
    RecordingDescriptor {
        correlation_id,
        recording_id,
        start: 0,
        start_time_ns: 10 * recording_id,
        state,
        geometry: Geometry::new(MIN_TERM_LENGTH, 4 * u64::from(MIN_TERM_LENGTH)).unwrap(),
        source: SourceIncarnation {
            driver: [1, 2],
            registration: recording_id,
            incarnation: 1,
        },
        stream_id: 10,
        session_id: 1,
        channel: "karyos:ipc",
    }
}

fn push(answers: &Queue, message: &ControlMessage<'_>) {
    let mut out = vec![0; 4096];
    let length = message.encode(&mut out).unwrap();
    out.truncate(length);
    answers.lock().unwrap().push_back(out);
}

/// An Archive handle over an in-memory Archive that answers `answer`, and
/// the `(from_id, max_count)` of each listing it was sent.
fn archive(answer: Answer, deadline: Duration) -> (u64, Asked) {
    let answers = Queue::default();
    let asked = Asked::default();
    let requests = {
        let answers = Arc::clone(&answers);
        let asked = Arc::clone(&asked);
        MemoryRequests(Box::new(move |bytes| {
            let ControlMessage::ListRecordings(list) = ControlMessage::decode(bytes).unwrap()
            else {
                panic!("not a listing");
            };
            asked.lock().unwrap().push((list.from_id, list.max_count));
            let correlation_id = list.correlation_id;
            match answer {
                Answer::Catalog => {
                    let last = CATALOG.min(list.from_id + u64::from(list.max_count) - 1);
                    for id in list.from_id..=last {
                        push(
                            &answers,
                            &ControlMessage::RecordingDescriptor(descriptor(correlation_id, id)),
                        );
                    }
                    let count = (list.from_id..=last).count();
                    push(
                        &answers,
                        &ControlMessage::ControlResponse(ControlResponse {
                            correlation_id,
                            id: u64::try_from(count).unwrap(),
                            code: ResponseCode::Ok,
                            message: "",
                        }),
                    );
                }
                Answer::Refuse(code) => push(
                    &answers,
                    &ControlMessage::ControlResponse(ControlResponse {
                        correlation_id,
                        id: 0,
                        code,
                        message: "no",
                    }),
                ),
                Answer::Silent => {}
            }
            true
        }))
    };
    let responses = MemoryResponses(Box::new(move |out| {
        let message = answers.lock().unwrap().pop_front()?;
        out[..message.len()].copy_from_slice(&message);
        Some(message.len())
    }));
    let handle = insert_memory(requests, responses, deadline).unwrap();
    (handle.raw(), asked)
}

/// What a test's handler saw of each recording.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    id: u64,
    state: u32,
    stop_reason: u32,
    incomplete: u32,
    position: u64,
    start_time_ns: u64,
    channel: Vec<u8>,
}

unsafe extern "C" fn collect(context: *mut c_void, recording: *const Recording) {
    // SAFETY: the tests pass a `Vec<Seen>` as the context.
    let seen = unsafe { &mut *context.cast::<Vec<Seen>>() };
    // SAFETY: the library passes a live recording.
    let recording = unsafe { &*recording };
    assert_eq!(recording.size, size_of_u32::<Recording>());
    // SAFETY: the library's channel pointer holds `channel_length` bytes
    // during the call.
    let channel = unsafe {
        core::slice::from_raw_parts(recording.channel.cast::<u8>(), recording.channel_length)
    };
    seen.push(Seen {
        id: recording.id,
        state: recording.state,
        stop_reason: recording.stop_reason,
        incomplete: recording.incomplete,
        position: recording.position,
        start_time_ns: recording.start_time_ns,
        channel: channel.to_vec(),
    });
}

fn detail() -> Detail {
    Detail {
        size: size_of_u32::<Detail>(),
        reserved: 0,
        code: 7,
        value: 7,
    }
}

/// `karyos_archive_list` into a `Vec<Seen>`: the status, the count written
/// and what was seen.
fn list(archive: u64, after_id: u64, limit: u32, detail: &mut Detail) -> (i32, u32, Vec<Seen>) {
    let mut seen = Vec::<Seen>::new();
    let mut delivered = u32::MAX;
    // SAFETY: `collect` matches the handler's signature and its context
    // is `seen`; live, aligned out-pointers.
    let status = unsafe {
        karyos_archive_list(
            archive,
            after_id,
            limit,
            Some(collect),
            (&raw mut seen).cast(),
            &mut delivered,
            detail,
        )
    };
    (status, delivered, seen)
}

#[test]
fn a_listing_pages_through_the_catalog_after_an_id() {
    let (archive, asked) = archive(Answer::Catalog, Duration::from_secs(3600));
    let (status, delivered, seen) = list(archive, 0, 2, &mut detail());
    assert_eq!(status, Status::Ok.code());
    assert_eq!(delivered, 2);
    assert_eq!(
        seen,
        [
            Seen {
                id: 1,
                state: RECORDING_RECORDING,
                stop_reason: 0,
                incomplete: 1,
                position: 64,
                start_time_ns: 10,
                channel: b"karyos:ipc".to_vec(),
            },
            Seen {
                id: 2,
                state: RECORDING_STOPPED,
                stop_reason: stop_reason(StopReason::Stopped).unwrap(),
                incomplete: 0,
                position: 200,
                start_time_ns: 20,
                channel: b"karyos:ipc".to_vec(),
            },
        ]
    );
    // The next page starts after the last id: fewer than the limit ends
    // the catalog.
    let (status, delivered, seen) = list(archive, 2, 2, &mut detail());
    assert_eq!((status, delivered), (Status::Ok.code(), 1));
    assert_eq!(seen.iter().map(|seen| seen.id).collect::<Vec<_>>(), [3]);
    // Each listing asked the Archive for at most its limit, from
    // after_id + 1; a short page is followed by an empty one, as the
    // Archive may end a page early.
    assert_eq!(*asked.lock().unwrap(), [(1, 2), (3, 2), (4, 1)]);
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
    assert_eq!(karyos_archive_close(archive), Status::Closed.code());
}

#[test]
fn a_listing_asks_nothing_for_no_limit_or_past_the_last_id() {
    let (archive, asked) = archive(Answer::Catalog, Duration::from_secs(3600));
    assert_eq!(
        list(archive, 0, 0, &mut detail()),
        (Status::Ok.code(), 0, Vec::new())
    );
    assert_eq!(
        list(archive, u64::MAX, 4, &mut detail()),
        (Status::Ok.code(), 0, Vec::new())
    );
    assert!(asked.lock().unwrap().is_empty());
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
}

#[test]
fn an_archive_refusal_carries_its_response_code() {
    for (code, wire) in [
        (ResponseCode::Error, 1),
        (ResponseCode::UnknownRecording, 2),
        (ResponseCode::InvalidRequest, 4),
    ] {
        let (archive, _) = archive(Answer::Refuse(code), Duration::from_secs(3600));
        let mut detail = detail();
        let (status, delivered, seen) = list(archive, 0, 2, &mut detail);
        assert_eq!((status, delivered), (Status::Refused.code(), 0));
        assert!(seen.is_empty());
        assert_eq!(detail.code, wire);
        assert_eq!(karyos_archive_close(archive), Status::Ok.code());
    }
}

#[test]
fn a_page_that_does_not_arrive_in_time_delivers_nothing() {
    let (archive, asked) = archive(Answer::Silent, Duration::from_millis(1));
    let (status, delivered, seen) = list(archive, 0, 2, &mut detail());
    assert_eq!((status, delivered), (Status::Timeout.code(), 0));
    assert!(seen.is_empty());
    assert_eq!(*asked.lock().unwrap(), [(1, 2)]);
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
}

#[test]
fn a_listing_refuses_a_null_handler_and_misaligned_count() {
    let (archive, asked) = archive(Answer::Catalog, Duration::from_secs(3600));
    // SAFETY: a null handler, refused before anything is read.
    let status = unsafe {
        karyos_archive_list(
            archive,
            0,
            2,
            None,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut words = [0u32; 2];
    // SAFETY: a misaligned `delivered`, refused before it is written.
    let status = unsafe {
        karyos_archive_list(
            archive,
            0,
            2,
            Some(collect),
            core::ptr::null_mut(),
            words.as_mut_ptr().cast::<u8>().wrapping_add(1).cast(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    assert!(asked.lock().unwrap().is_empty());
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
}

/// A handler that lists and closes its own Archive, whose handle is its
/// context, and records both statuses in the next two words.
unsafe extern "C" fn reenter(context: *mut c_void, _recording: *const Recording) {
    // SAFETY: the test passes a live `[u64; 3]`.
    let words = unsafe { &mut *context.cast::<[u64; 3]>() };
    let archive = words[0];
    let (status, _, _) = list(archive, 0, 1, &mut detail());
    words[1] = u64::from(status.unsigned_abs());
    words[2] = u64::from(karyos_archive_close(archive).unsigned_abs());
}

#[test]
fn a_handler_cannot_reenter_its_archive() {
    let (archive, _) = archive(Answer::Catalog, Duration::from_secs(3600));
    let mut words = [archive, 0, 0];
    let mut delivered = 0;
    // SAFETY: `reenter` matches the handler's signature and its context is
    // `words`; a live, aligned `delivered`.
    let status = unsafe {
        karyos_archive_list(
            archive,
            0,
            1,
            Some(reenter),
            (&raw mut words).cast(),
            &mut delivered,
            core::ptr::null_mut(),
        )
    };
    assert_eq!((status, delivered), (Status::Ok.code(), 1));
    let reentrant = u64::from(Status::Reentrant.code().unsigned_abs());
    assert_eq!(words[1..], [reentrant, reentrant]);
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
}

pub(super) fn archive_options() -> ArchiveOptions {
    ArchiveOptions {
        size: size_of_u32::<ArchiveOptions>(),
        reserved: 0,
        requests: 100,
        responses: 101,
        client_id: 1,
        deadline_ns: 0,
    }
}

#[test]
fn a_connect_refuses_bad_options_before_its_client() {
    let mut archive = 7;
    for options in [
        ArchiveOptions {
            reserved: 1,
            ..archive_options()
        },
        ArchiveOptions {
            size: 31,
            ..archive_options()
        },
    ] {
        // SAFETY: live, aligned pointers of their stated sizes; no detail.
        let status =
            unsafe { karyos_archive_connect(1, &options, &mut archive, core::ptr::null_mut()) };
        assert_eq!(status, Status::InvalidArgument.code());
    }
    // SAFETY: a null `archive`, refused before anything is read.
    let status = unsafe {
        karyos_archive_connect(
            1,
            &archive_options(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    // SAFETY: a null `options`, refused before anything is read.
    let status = unsafe {
        karyos_archive_connect(1, core::ptr::null(), &mut archive, core::ptr::null_mut())
    };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!(archive, 7);
}

#[test]
fn a_connect_refuses_a_client_id_past_32_bits() {
    let options = ArchiveOptions {
        client_id: u64::from(u32::MAX) + 1,
        ..archive_options()
    };
    let mut archive = 7;
    // SAFETY: live, aligned pointers of their stated sizes; no detail.
    let status =
        unsafe { karyos_archive_connect(1, &options, &mut archive, core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!(archive, 7);
}

/// The control streams of the embedded Archive.
pub(super) const REQUESTS: i32 = 1030;
pub(super) const RESPONSES: i32 = 1031;
/// A data stream beside them, whose subscriptions rejoin (F9b).
pub(super) const DATA: i32 = 1032;

/// A driven driver with an Archive's control streams, whose Archive side
/// answers each listing from the in-memory catalog until dropped, and a
/// conductor for the client.
fn served_archive() -> (Driven, Driven, karyos_client::ClientConductor) {
    served_archive_with(2)
}

/// As [`served_archive`], with `publishers` request publishers and the
/// data stream [`DATA`].
pub(super) fn served_archive_with(
    publishers: u8,
) -> (Driven, Driven, karyos_client::ClientConductor) {
    use karyos_client::{MessageLimit, OfferOutcome};
    use karyos_sys::log_buffer::{PublicationMode, Role};
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut driver = EmbeddedDriver::with_config(karyos_driver::DriverConfig {
        client_liveness_timeout: 3_600_000_000_000,
        ..karyos_driver::DriverConfig::default()
    })
    .unwrap();
    let mut requests = stream_config(REQUESTS);
    requests.buffer.spare_slots = 6;
    requests.buffer.publication = PublicationMode::Concurrent {
        publishers,
        allow_non_lse: true,
    };
    let requests = driver.add_stream(requests).unwrap();
    let mut responses = stream_config(RESPONSES);
    responses.buffer.spare_slots = 6;
    let responses = driver.add_stream(responses).unwrap();
    // Room for the rejoins' optional readers.
    let mut data = stream_config(DATA);
    data.buffer.spare_slots = 6;
    let _ = driver.add_stream(data).unwrap();
    let mut reader = driver.subscribe(requests, Role::Required).unwrap();
    let mut answers = driver.publication(responses).unwrap();
    let conductor = patient(driver.connect().unwrap());

    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let driver_thread = std::thread::spawn(move || {
        while !flag.load(Ordering::Acquire) {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
    });
    let served = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&served);
    let archive_thread = std::thread::spawn(move || {
        let queue = Queue::default();
        let mut asked = Vec::new();
        while !flag.load(Ordering::Acquire) {
            let _ = reader.poll(|bytes, _| asked.push(bytes.to_vec()), MessageLimit::new(1));
            for request in asked.drain(..) {
                let ControlMessage::ListRecordings(list) =
                    ControlMessage::decode(&request).unwrap()
                else {
                    panic!("not a listing");
                };
                let last = CATALOG.min(list.from_id + u64::from(list.max_count) - 1);
                for id in list.from_id..=last {
                    push(
                        &queue,
                        &ControlMessage::RecordingDescriptor(descriptor(list.correlation_id, id)),
                    );
                }
                push(
                    &queue,
                    &ControlMessage::ControlResponse(ControlResponse {
                        correlation_id: list.correlation_id,
                        id: u64::try_from((list.from_id..=last).count()).unwrap(),
                        code: ResponseCode::Ok,
                        message: "",
                    }),
                );
            }
            let next = queue.lock().unwrap().pop_front();
            if let Some(answer) = next {
                while !matches!(
                    answers.offer(&answer).unwrap(),
                    OfferOutcome::Accepted { .. }
                ) {
                    std::thread::yield_now();
                }
            }
            std::thread::yield_now();
        }
    });
    (
        Driven {
            stop,
            thread: Some(driver_thread),
        },
        Driven {
            stop: served,
            thread: Some(archive_thread),
        },
        conductor,
    )
}

/// A client of an embedded driver connects to an Archive over its control
/// streams, pages through its catalog, and its close closes the
/// connection.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_client_lists_an_archive_and_its_close_closes_the_connection() {
    // Dropped in reverse: the Archive side stops before its driver.
    let (_driven, _archive, conductor) = served_archive();
    let client = client::insert_embedded(Client::with_conductor(conductor, test_context()))
        .unwrap()
        .raw();
    let options = ArchiveOptions {
        requests: REQUESTS,
        responses: RESPONSES,
        ..archive_options()
    };
    let mut archive = 0;
    // SAFETY: live, aligned pointers of their stated sizes; no detail.
    let status =
        unsafe { karyos_archive_connect(client, &options, &mut archive, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    let (status, delivered, seen) = list(archive, 0, 2, &mut detail());
    assert_eq!((status, delivered), (Status::Ok.code(), 2));
    assert_eq!(seen.iter().map(|seen| seen.id).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(seen[1].channel, b"karyos:ipc");
    let (status, delivered, seen) = list(archive, 2, 2, &mut detail());
    assert_eq!((status, delivered), (Status::Ok.code(), 1));
    assert_eq!(seen[0].id, 3);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    let (status, delivered, _) = list(archive, 0, 2, &mut detail());
    assert_eq!((status, delivered), (Status::Closed.code(), 0));
    assert_eq!(karyos_archive_close(archive), Status::Closed.code());
}

/// Closing a connection removes its streams from its client, which
/// connects again with the same id.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_closed_connection_leaves_its_client_open() {
    let (_driven, _archive, conductor) = served_archive();
    let client = client::insert_embedded(Client::with_conductor(conductor, test_context()))
        .unwrap()
        .raw();
    let options = ArchiveOptions {
        requests: REQUESTS,
        responses: RESPONSES,
        ..archive_options()
    };
    for _ in 0..3 {
        let mut archive = 0;
        // SAFETY: live, aligned pointers of their stated sizes; no detail.
        let status = unsafe {
            karyos_archive_connect(client, &options, &mut archive, core::ptr::null_mut())
        };
        assert_eq!(status, Status::Ok.code());
        let (status, delivered, _) = list(archive, 0, 4, &mut detail());
        assert_eq!((status, delivered), (Status::Ok.code(), 3));
        assert_eq!(karyos_archive_close(archive), Status::Ok.code());
    }
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// An Archive connection has no thread affinity (`karyos.h`, "Threads"):
/// one made on a thread lists on another and closes on a third.
#[test]
fn a_connection_moves_between_threads() {
    let (archive, asked) =
        std::thread::spawn(|| archive(Answer::Catalog, Duration::from_secs(3600)))
            .join()
            .unwrap();
    std::thread::spawn(move || {
        let (status, delivered, _) = list(archive, 0, 3, &mut detail());
        assert_eq!((status, delivered), (Status::Ok.code(), 3));
    })
    .join()
    .unwrap();
    assert_eq!(*asked.lock().unwrap(), [(1, 3)]);
    std::thread::spawn(move || assert_eq!(karyos_archive_close(archive), Status::Ok.code()))
        .join()
        .unwrap();
}
