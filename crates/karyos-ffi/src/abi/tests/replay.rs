// SPDX-License-Identifier: Apache-2.0

//! Archive replays over the C ABI (F9c, B6; quantstratum-docs:
//! karyos/design/archive-replay-control.md): `karyos_archive_replay` and
//! `karyos_archive_stop_replay` driverless, over an in-memory Archive, so
//! they run under Miri; their argument checks; `karyos_subscription_end_state`'s
//! sized write; and, natively, a replay through a real Archive read with
//! `karyos_client_add_replay_subscription` to its target's seal.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use karyos_archive::control::{ControlMessage, ControlResponse, ResponseCode};

use super::*;
use crate::api::archive::{MemoryRequests, MemoryResponses, insert_memory_replaying};

type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

/// How an in-memory Archive answers a replay request or a stop.
#[derive(Clone, Copy)]
enum Answer {
    /// `Ok`, a replay's id 42 or a stop's 0.
    Ok,
    /// A refusal with this code.
    Refuse(ResponseCode),
    /// Nothing.
    Silent,
}

/// The id the in-memory Archive gives a replay: its target's session is
/// its low 32 bits, 9.
const REPLAY_ID: u64 = (5 << 32) | 9;

fn push(answers: &Queue, message: &ControlMessage<'_>) {
    let mut out = vec![0; 4096];
    let length = message.encode(&mut out).unwrap();
    out.truncate(length);
    answers.lock().unwrap().push_back(out);
}

/// What the in-memory Archive was asked: a replay's recording and target
/// stream, or a stop's replay id.
#[derive(Debug, PartialEq, Eq)]
enum Asked {
    Replay {
        recording_id: u64,
        target_stream_id: i32,
        channel: String,
    },
    Stop(u64),
}

/// An Archive handle whose replayer runs over an in-memory Archive that
/// answers `answer`, and what it was asked. Its listing side answers
/// nothing.
fn archive(answer: Answer, deadline: Duration) -> (u64, Arc<Mutex<Vec<Asked>>>) {
    let answers = Queue::default();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let requests = {
        let answers = Arc::clone(&answers);
        let asked = Arc::clone(&asked);
        MemoryRequests(Box::new(move |bytes| {
            let (correlation_id, id) = match ControlMessage::decode(bytes).unwrap() {
                ControlMessage::Replay(replay) => {
                    asked.lock().unwrap().push(Asked::Replay {
                        recording_id: replay.recording_id,
                        target_stream_id: replay.target_stream_id,
                        channel: replay.target_channel.to_owned(),
                    });
                    (replay.correlation_id, REPLAY_ID)
                }
                ControlMessage::StopReplay(stop) => {
                    asked.lock().unwrap().push(Asked::Stop(stop.replay_id));
                    (stop.correlation_id, 0)
                }
                other => panic!("unexpected {other:?}"),
            };
            let (code, id) = match answer {
                Answer::Ok => (ResponseCode::Ok, id),
                Answer::Refuse(code) => (code, 0),
                Answer::Silent => return true,
            };
            push(
                &answers,
                &ControlMessage::ControlResponse(ControlResponse {
                    correlation_id,
                    id,
                    code,
                    message: if code == ResponseCode::Ok { "" } else { "no" },
                }),
            );
            true
        }))
    };
    let responses = MemoryResponses(Box::new(move |out| {
        let message = answers.lock().unwrap().pop_front()?;
        out[..message.len()].copy_from_slice(&message);
        Some(message.len())
    }));
    let silent = (
        MemoryRequests(Box::new(|_| true)),
        MemoryResponses(Box::new(|_| None)),
    );
    let handle = insert_memory_replaying(silent, (requests, responses), deadline).unwrap();
    (handle.raw(), asked)
}

/// Options from `karyos_replay_options_init`, for recording 3 onto
/// stream 1041.
fn options() -> ReplayOptions {
    let mut options = core::mem::MaybeUninit::<ReplayOptions>::zeroed();
    // SAFETY: a live, aligned, writable `ReplayOptions`.
    let status = unsafe {
        karyos_replay_options_init_sized(options.as_mut_ptr(), size_of_u32::<ReplayOptions>())
    };
    assert_eq!(status, Status::Ok.code());
    // SAFETY: `karyos_replay_options_init` wrote every field.
    let mut options = unsafe { options.assume_init() };
    options.recording_id = 3;
    options.target_stream_id = 1041;
    options
}

fn detail() -> Detail {
    Detail {
        size: size_of_u32::<Detail>(),
        reserved: 0,
        code: 7,
        value: 7,
    }
}

/// `karyos_archive_replay`: the status, the replay id and the session id.
fn replay(archive: u64, options: &ReplayOptions, detail: &mut Detail) -> (i32, u64, i32) {
    let (mut replay_id, mut session_id) = (u64::MAX, i32::MIN);
    // SAFETY: live, aligned pointers of their stated sizes; the options'
    // channel is null or a live C string.
    let status =
        unsafe { karyos_archive_replay(archive, options, &mut replay_id, &mut session_id, detail) };
    (status, replay_id, session_id)
}

/// `karyos_archive_stop_replay`.
fn stop(archive: u64, replay_id: u64, detail: &mut Detail) -> i32 {
    // SAFETY: a live detail of its stated size.
    unsafe { karyos_archive_stop_replay(archive, replay_id, detail) }
}

/// `karyos_subscription_end_state`: the status and what it wrote.
pub(super) fn subscription_end(subscription: u64) -> (i32, SubscriptionEnd) {
    let mut end = SubscriptionEnd {
        size: size_of_u32::<SubscriptionEnd>(),
        reason: 7,
        position: 7,
        seal_code: 7,
    };
    // SAFETY: a live, aligned struct of its stated size.
    let status = unsafe { karyos_subscription_end_state(subscription, &mut end) };
    (status, end)
}

/// A replay is started and stopped on an in-memory Archive; the id, the
/// session and what was asked come back as the C ABI writes them.
#[test]
fn a_replay_is_started_and_stopped_driverless() {
    let (archive, asked) = archive(Answer::Ok, Duration::from_secs(5));
    let mut detail = detail();
    let channel = c"karyos:ipc?alias=replay";
    let named = ReplayOptions {
        target_channel: channel.as_ptr(),
        ..options()
    };
    assert_eq!(
        replay(archive, &named, &mut detail),
        (Status::Ok.code(), REPLAY_ID, 9)
    );
    assert_eq!(stop(archive, REPLAY_ID, &mut detail), Status::Ok.code());
    assert_eq!(
        *asked.lock().unwrap(),
        [
            Asked::Replay {
                recording_id: 3,
                target_stream_id: 1041,
                channel: "karyos:ipc?alias=replay".to_owned(),
            },
            Asked::Stop(REPLAY_ID),
        ]
    );
    // A null channel is karyos:ipc.
    assert_eq!(
        replay(archive, &options(), &mut detail).0,
        Status::Ok.code()
    );
    assert!(matches!(
        &asked.lock().unwrap()[2],
        Asked::Replay { channel, .. } if channel == "karyos:ipc"
    ));
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
}

/// A refusal carries the Archive's response code in the detail; no answer
/// in time is a timeout.
#[test]
fn a_refused_or_unanswered_replay_reports_why() {
    let (refusing, _) = archive(
        Answer::Refuse(ResponseCode::UnknownRecording),
        Duration::from_secs(5),
    );
    let mut refused = detail();
    assert_eq!(
        replay(refusing, &options(), &mut refused).0,
        Status::Refused.code()
    );
    assert_eq!(refused.code, 2);
    assert_eq!(karyos_archive_close(refusing), Status::Ok.code());
    let (unknown, _) = archive(
        Answer::Refuse(ResponseCode::UnknownReplay),
        Duration::from_secs(5),
    );
    let mut refused = detail();
    assert_eq!(stop(unknown, 44, &mut refused), Status::Refused.code());
    assert_eq!(refused.code, 3);
    assert_eq!(karyos_archive_close(unknown), Status::Ok.code());
    let (silent, asked) = archive(Answer::Silent, Duration::from_millis(20));
    let mut unanswered = detail();
    assert_eq!(
        replay(silent, &options(), &mut unanswered).0,
        Status::Timeout.code()
    );
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert_eq!(karyos_archive_close(silent), Status::Ok.code());
}

/// Every argument is checked before the handle: the out-pointers, the
/// options' size, the rate and scale, the recording and the channel.
#[test]
fn a_replay_checks_its_arguments_before_its_handle() {
    let invalid = Status::InvalidArgument.code();
    let mut detail = detail();
    let (mut replay_id, mut session_id) = (0u64, 0i32);
    let good = options();
    let call = |options: *const ReplayOptions, replay_id: *mut u64, session_id: *mut i32| {
        let mut detail = Detail {
            size: size_of_u32::<Detail>(),
            reserved: 0,
            code: 0,
            value: 0,
        };
        // SAFETY: live, aligned pointers of their stated sizes, or null
        // where the check is of null.
        unsafe { karyos_archive_replay(0, options, replay_id, session_id, &mut detail) }
    };
    assert_eq!(call(&good, core::ptr::null_mut(), &mut session_id), invalid);
    assert_eq!(call(&good, &mut replay_id, core::ptr::null_mut()), invalid);
    assert_eq!(
        call(core::ptr::null(), &mut replay_id, &mut session_id),
        invalid
    );
    let channel_long = std::ffi::CString::new("c".repeat(1025)).unwrap();
    let not_utf8 = [0xFFu8, 0];
    for bad in [
        ReplayOptions { size: 40, ..good },
        ReplayOptions {
            recording_id: 0,
            ..good
        },
        ReplayOptions { rate: 0, ..good },
        ReplayOptions { rate: 9, ..good },
        ReplayOptions {
            scale_ppm: 5,
            ..good
        },
        ReplayOptions {
            rate: REPLAY_AS_RECORDED,
            scale_ppm: 5,
            ..good
        },
        ReplayOptions {
            rate: REPLAY_SCALED,
            scale_ppm: 0,
            ..good
        },
        ReplayOptions {
            rate: REPLAY_SCALED,
            scale_ppm: 100_000_001,
            ..good
        },
        ReplayOptions {
            target_channel: c"".as_ptr(),
            ..good
        },
        ReplayOptions {
            target_channel: channel_long.as_ptr(),
            ..good
        },
        ReplayOptions {
            target_channel: not_utf8.as_ptr().cast(),
            ..good
        },
    ] {
        assert_eq!(replay(0, &bad, &mut detail).0, invalid);
    }
    // Good options reach the handle.
    for fine in [
        good,
        ReplayOptions {
            rate: REPLAY_AS_RECORDED,
            ..good
        },
        ReplayOptions {
            rate: REPLAY_SCALED,
            scale_ppm: 1,
            ..good
        },
    ] {
        assert_eq!(
            replay(0, &fine, &mut detail).0,
            Status::InvalidHandle.code()
        );
    }
    assert_eq!(stop(0, 0, &mut detail), invalid);
    assert_eq!(stop(0, 5, &mut detail), Status::InvalidHandle.code());
}

/// The options' init fills the defaults and the size; a replay
/// subscription's options are refused with a nonzero reserved word or too
/// small a size, and checked before the client.
#[test]
fn the_replay_options_are_initialized_and_checked() {
    let options = options();
    assert_eq!(options.size, 48);
    assert_eq!(options.size, size_of_u32::<ReplayOptions>());
    assert_eq!(
        (
            options.rate,
            options.scale_ppm,
            options.position,
            options.length
        ),
        (REPLAY_FULL, 0, 0, u64::MAX)
    );
    assert!(options.target_channel.is_null());
    // SAFETY: a null pointer is the check.
    let status = unsafe {
        karyos_replay_options_init_sized(core::ptr::null_mut(), size_of_u32::<ReplayOptions>())
    };
    assert_eq!(status, Status::InvalidArgument.code());
    // SAFETY: a null pointer is the check.
    let status = unsafe {
        karyos_replay_subscription_options_init_sized(
            core::ptr::null_mut(),
            size_of_u32::<ReplaySubscriptionOptions>(),
        )
    };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut sub = ReplaySubscriptionOptions {
        size: 0,
        reserved: 7,
    };
    // SAFETY: a live, aligned struct.
    let status = unsafe {
        karyos_replay_subscription_options_init_sized(
            &mut sub,
            size_of_u32::<ReplaySubscriptionOptions>(),
        )
    };
    assert_eq!((status, sub.size, sub.reserved), (Status::Ok.code(), 8, 0));
    let mut subscription = 0;
    let add = |options: *const ReplaySubscriptionOptions, out: *mut u64| {
        // SAFETY: null, or live and aligned pointers of their stated
        // sizes.
        unsafe { karyos_client_add_replay_subscription(0, 1041, 9, options, out) }
    };
    let invalid = Status::InvalidArgument.code();
    assert_eq!(add(core::ptr::null(), core::ptr::null_mut()), invalid);
    let reserved = ReplaySubscriptionOptions { reserved: 1, ..sub };
    assert_eq!(add(&reserved, &mut subscription), invalid);
    let small = ReplaySubscriptionOptions { size: 4, ..sub };
    assert_eq!(add(&small, &mut subscription), invalid);
    // Null options are the defaults: the client handle is checked next.
    let invalid_handle = Status::InvalidHandle.code();
    assert_eq!(add(core::ptr::null(), &mut subscription), invalid_handle);
    assert_eq!(add(&sub, &mut subscription), invalid_handle);
}

/// `karyos_subscription_end_state` checks its struct before the handle, and its
/// write is by the caller's size: a newer struct keeps its tail, and each
/// end has its code, position and seal code.
#[test]
fn the_subscription_end_is_written_by_the_callers_size() {
    use crate::api::subscription::End;
    use karyos_sys::log_buffer::SealReason;
    let invalid = Status::InvalidArgument.code();
    // SAFETY: a null pointer is the check.
    let status = unsafe { karyos_subscription_end_state(0, core::ptr::null_mut()) };
    assert_eq!(status, invalid);
    let mut short = SubscriptionEnd {
        size: 16,
        reason: 7,
        position: 7,
        seal_code: 7,
    };
    // SAFETY: a live, aligned struct of its stated size.
    let status = unsafe { karyos_subscription_end_state(0, &mut short) };
    assert_eq!(status, invalid);
    assert_eq!((short.reason, short.position), (7, 7));
    assert_eq!(subscription_end(0).0, Status::InvalidHandle.code());
    // A struct of a newer header, 8 bytes longer: its tail stays.
    #[repr(C)]
    struct Newer {
        end: SubscriptionEnd,
        tail: u64,
    }
    let mut newer = Newer {
        end: SubscriptionEnd {
            size: 32,
            reason: 7,
            position: 7,
            seal_code: 7,
        },
        tail: 0xA5A5,
    };
    let sealed = Some(End::Sealed {
        reason: SealReason::EndOfStream,
        position: 4096,
    });
    // SAFETY: `newer` is live, aligned and 32 bytes, its size.
    unsafe { write_subscription_end(&raw mut newer.end, end_fields(sealed)) };
    assert_eq!(
        (
            newer.end.size,
            newer.end.reason,
            newer.end.position,
            newer.end.seal_code,
            newer.tail
        ),
        (32, END_END_OF_STREAM, 4096, 8, 0xA5A5)
    );
    for (end, fields) in [
        (None, (END_NONE, 0, 0)),
        (
            Some(End::Sealed {
                reason: SealReason::ImageRetired,
                position: 10,
            }),
            (END_IMAGE_RETIRED, 10, 7),
        ),
        (
            Some(End::Sealed {
                reason: SealReason::StreamRemoved,
                position: 11,
            }),
            (END_STREAM_REMOVED, 11, 3),
        ),
        (
            Some(End::Sealed {
                reason: SealReason::GuardClosed,
                position: 12,
            }),
            (END_OTHER, 12, 5),
        ),
        (Some(End::Revoked { position: 13 }), (END_REVOKED, 13, 0)),
        (
            Some(End::ClosedByOverrun { position: 14 }),
            (END_CLOSED_BY_OVERRUN, 14, 0),
        ),
    ] {
        assert_eq!(end_fields(end), fields);
    }
}

/// Through a real Archive (karyos-tools' `DriverHost`, which holds a
/// replay until its target's first reader): a replay of the whole
/// recording, started with `karyos_archive_replay`, is read with
/// `karyos_client_add_replay_subscription` to `KARYOS_E_CLOSED`, every
/// message at its position, and `karyos_subscription_end_state` reads a clean
/// end of stream at the replay's end. A replay at a millionth of the
/// recorded pace, stopped with `karyos_archive_stop_replay`, ends as an
/// image retired; stopping it again is refused as an unknown replay.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_replay_through_a_real_archive_ends_at_its_targets_seal() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use karyos_archive::agent::{AgentConfig, ArchiveHandle};
    use karyos_archive::control::{self};
    use karyos_archive::disk::StdDisk;
    use karyos_archive::recorder::Mode;
    use karyos_archive::segment::SyncPolicy;
    use karyos_archive::server::{ControlServer, MAX_REQUEST};
    use karyos_client::{ConcurrentOfferOutcome, MessageLimit, OfferOutcome};
    use karyos_sys::log_buffer::{PublicationMode, Role};
    use karyos_tools::archive::DriverHost;

    use super::archive::{DATA, REQUESTS, RESPONSES, archive_options};
    use super::rejoin::real;

    /// Removes the directory when the test ends, a failing one included.
    struct Removed(std::path::PathBuf);
    impl Drop for Removed {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const TARGET: i32 = 1041;
    let dir = std::env::temp_dir().join(format!("karyos-ffi-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _removed = Removed(dir.clone());
    let mut driver = EmbeddedDriver::with_config(karyos_driver::DriverConfig {
        client_liveness_timeout: 3_600_000_000_000,
        ..karyos_driver::DriverConfig::default()
    })
    .unwrap();
    let roomy = |stream_id| {
        let mut config = stream_config(stream_id);
        config.buffer.spare_slots = 6;
        config.buffer.max_subscribers = 8;
        config
    };
    let data = driver.add_stream(roomy(DATA)).unwrap();
    let mut shared = roomy(REQUESTS);
    shared.buffer.publication = PublicationMode::Concurrent {
        publishers: 4,
        allow_non_lse: true,
    };
    let requests = driver.add_stream(shared).unwrap();
    let responses = driver.add_stream(roomy(RESPONSES)).unwrap();
    let mut asking = driver.concurrent_publication(requests).unwrap();
    let mut answers = driver.subscribe(responses, Role::Required).unwrap();
    let reading = real::Reading(driver.subscribe(requests, Role::Required).unwrap());
    let writing = real::Writing(driver.publication(responses).unwrap());
    let mut publication = driver.publication(data).unwrap();
    let conductor = driver.connect().unwrap();
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let mut server = ControlServer::new(
        agent,
        // A short linger: an ended replay's target seals soon after.
        DriverHost::new(driver).with_replay_linger(Duration::from_millis(50)),
        reading,
        writing,
    );
    let cycle = |server: &mut ControlServer<
        DriverHost<karyos_sys::term_bytes::HeapTerms>,
        real::Reading,
        real::Writing,
    >| {
        let _ = server.host_mut().driver_mut().do_work().unwrap();
        let _ = server.duty();
        let _ = server.host_mut().finish_ended();
    };

    // Record the data stream from its start.
    let start = control::StartRecording {
        correlation_id: 1,
        stream_id: DATA,
        session_id: 1,
        mode: Mode::Required,
        sync_policy: SyncPolicy::PerSegment,
        segment_length: 0,
        channel: "karyos:ipc",
    };
    let mut out = vec![0u8; MAX_REQUEST];
    let length = ControlMessage::StartRecording(start)
        .encode(&mut out)
        .unwrap();
    while !matches!(
        asking.offer(&out[..length]),
        Ok(ConcurrentOfferOutcome::Accepted { .. })
    ) {
        cycle(&mut server);
    }
    let begun = Instant::now();
    let mut started = None;
    while started.is_none() {
        assert!(begun.elapsed() < Duration::from_secs(20), "no answer");
        cycle(&mut server);
        let _ = answers.poll(
            |bytes, _| {
                if let Ok(ControlMessage::ControlResponse(response)) = ControlMessage::decode(bytes)
                    && response.correlation_id == 1
                {
                    started = Some((response.code, response.id));
                }
            },
            MessageLimit::new(16),
        );
    }
    let (code, recording_id) = started.unwrap();
    assert_eq!(code, ResponseCode::Ok);
    drop(answers);
    drop(asking);

    // Two batches 5 ms apart, each recorded before the next: a replay at a
    // millionth of the recorded pace holds the second for about 5 000 s.
    let mut sent: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut end = 0;
    for batch in 0..2u8 {
        if batch > 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        let goal = sent.len() + 6;
        let begun = Instant::now();
        while sent.len() < goal {
            assert!(begun.elapsed() < Duration::from_secs(20), "not published");
            let sequence = u32::try_from(sent.len()).unwrap();
            let length = [100usize, 1400, 3000][sent.len() % 3];
            let mut message = vec![u8::try_from(sequence % 251).unwrap(); length];
            message[..4].copy_from_slice(&sequence.to_le_bytes());
            if let Ok(OfferOutcome::Accepted { position, .. }) = publication.offer(&message) {
                sent.push((position, message));
            }
            cycle(&mut server);
        }
        let (last, message) = sent.last().unwrap();
        let published = *last + u64::try_from(message.len()).unwrap();
        let begun = Instant::now();
        while server.agent().describe(recording_id).unwrap().end < published {
            assert!(begun.elapsed() < Duration::from_secs(20), "not recorded");
            cycle(&mut server);
        }
        end = server.agent().describe(recording_id).unwrap().end;
    }

    // The C calls, which wait for the driver and the Archive, on a thread
    // of their own while this one runs the driver, the server and the host.
    let working = AtomicBool::new(true);
    let outcome = std::thread::scope(|scope| {
        let caller = scope.spawn(|| {
            let done = |result| {
                working.store(false, Ordering::Release);
                result
            };
            let client = client::insert_embedded(Client::with_conductor(conductor, test_context()))
                .unwrap()
                .raw();
            let connect = ArchiveOptions {
                requests: REQUESTS,
                responses: RESPONSES,
                client_id: 7,
                ..archive_options()
            };
            let mut archive = 0;
            // SAFETY: live, aligned pointers of their stated sizes.
            let status = unsafe {
                karyos_archive_connect(client, &connect, &mut archive, core::ptr::null_mut())
            };
            assert_eq!(status, Status::Ok.code());
            let read_to_end = |options: &ReplayOptions, stop_after: Option<usize>| {
                let mut detail = detail();
                let (status, replay_id, session_id) = replay(archive, options, &mut detail);
                assert_eq!(status, Status::Ok.code(), "{}", detail.code);
                assert_eq!(
                    session_id,
                    karyos_archive::server::replay_session_id(replay_id)
                );
                let mut subscription = 0;
                let begun = Instant::now();
                loop {
                    assert!(begun.elapsed() < Duration::from_secs(20), "no grant");
                    let _ = poll(client);
                    // SAFETY: a live, aligned `uint64_t`; default options.
                    let status = unsafe {
                        karyos_client_add_replay_subscription(
                            client,
                            TARGET,
                            session_id,
                            core::ptr::null(),
                            &mut subscription,
                        )
                    };
                    if status == Status::Ok.code() {
                        break;
                    }
                    assert_eq!(status, Status::NotConnected.code());
                }
                assert_eq!(subscription_end(subscription).1.reason, END_NONE);
                let mut seen = Seen::default();
                let mut stopped = false;
                let begun = Instant::now();
                let status = loop {
                    assert!(begun.elapsed() < Duration::from_secs(30), "no end");
                    let _ = poll(client);
                    let (status, _) = poll_into(subscription, &mut seen, 64);
                    if status != Status::Ok.code() {
                        break status;
                    }
                    if !stopped && stop_after.is_some_and(|count| seen.messages.len() >= count) {
                        assert_eq!(stop(archive, replay_id, &mut detail), Status::Ok.code());
                        stopped = true;
                    }
                    std::thread::yield_now();
                };
                let (end_status, read) = subscription_end(subscription);
                assert_eq!(end_status, Status::Ok.code());
                assert_eq!(karyos_subscription_close(subscription), Status::Ok.code());
                (status, seen, read, replay_id)
            };
            let whole = ReplayOptions {
                recording_id,
                target_stream_id: TARGET,
                ..options()
            };
            let complete = read_to_end(&whole, None);
            let slow = ReplayOptions {
                rate: REPLAY_SCALED,
                scale_ppm: 1,
                ..whole
            };
            let stopped = read_to_end(&slow, Some(1));
            let mut detail = detail();
            let again = stop(archive, stopped.3, &mut detail);
            let again_code = detail.code;
            assert_eq!(karyos_archive_close(archive), Status::Ok.code());
            assert_eq!(karyos_client_close(client), Status::Ok.code());
            done((complete, stopped, again, again_code))
        });
        while working.load(Ordering::Acquire) && !caller.is_finished() {
            cycle(&mut server);
            std::thread::yield_now();
        }
        caller.join().unwrap()
    });
    let ((status, seen, read, _), (stopped_status, stopped_seen, stopped_read, _), again, code) =
        outcome;
    assert_eq!(status, Status::Closed.code());
    let delivered: Vec<(u64, Vec<u8>)> = seen
        .infos
        .iter()
        .map(|info| info.position)
        .zip(seen.messages)
        .collect();
    assert!(delivered == sent, "every message, at its position");
    assert_eq!(
        (read.reason, read.position, read.seal_code),
        (END_END_OF_STREAM, end, 8)
    );
    assert_eq!(stopped_status, Status::Closed.code());
    assert!(stopped_seen.messages.len() < sent.len());
    assert_eq!(
        (stopped_read.reason, stopped_read.seal_code),
        (END_IMAGE_RETIRED, 7)
    );
    assert_eq!((again, code), (Status::Refused.code(), 3));
    drop(publication);
    let _ = server.shutdown_into_host();
}
