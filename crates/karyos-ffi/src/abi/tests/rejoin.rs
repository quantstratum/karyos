// SPDX-License-Identifier: Apache-2.0

//! The Archive-backed rejoin over the C ABI (F9b; quantstratum-docs:
//! karyos/design/ffi-archive.md): `KARYOS_REJOIN_ARCHIVE` in the
//! subscription options, `karyos_subscription_rejoin_state`, and that a
//! rejoin's Archive streams leave nothing open on failure or at close.

use super::archive::{DATA, REQUESTS, RESPONSES, archive_options, served_archive_with};
use super::*;

/// An embedded client of `conductor`, and its Archive handle over the
/// fake Archive's control streams.
fn client_and_archive(conductor: karyos_client::ClientConductor) -> (u64, u64) {
    let client = client::insert_embedded(Client::with_conductor(conductor, test_context()))
        .unwrap()
        .raw();
    let options = ArchiveOptions {
        requests: REQUESTS,
        responses: RESPONSES,
        client_id: 7,
        ..archive_options()
    };
    let mut archive = 0;
    // SAFETY: live, aligned pointers of their stated sizes; no detail.
    let status =
        unsafe { karyos_archive_connect(client, &options, &mut archive, core::ptr::null_mut()) };
    assert_eq!(status, Status::Ok.code());
    (client, archive)
}

/// Options that rejoin from `archive`.
fn rejoining(archive: u64) -> SubscriptionOptions {
    SubscriptionOptions {
        role: ROLE_OPTIONAL,
        rejoin: REJOIN_ARCHIVE,
        archive,
        replay_stream_id: 1040,
        secondary: REJOIN_AT_HEAD,
        ..subscription_defaults()
    }
}

/// `karyos_client_add_subscription_with` of [`DATA`] with `options`.
fn add(client: u64, options: &SubscriptionOptions) -> (i32, u64) {
    // SAFETY: `options` is live and its stated size.
    unsafe { add_subscription_with(client, DATA, options) }
}

/// `karyos_subscription_rejoin_state`: the status and what it wrote.
fn state(subscription: u64) -> (i32, SubscriptionRejoin) {
    let mut state = SubscriptionRejoin {
        size: size_of_u32::<SubscriptionRejoin>(),
        recovering: 7,
        merge_failure: 7,
        reserved: 7,
    };
    // SAFETY: a live, aligned struct of its stated size.
    let status = unsafe { karyos_subscription_rejoin_state(subscription, &mut state) };
    (status, state)
}

/// A subscription added with `KARYOS_REJOIN_ARCHIVE` delivers the live
/// stream as any other, and reads not recovering with no failure; a
/// subscription that does not rejoin reads the same.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_rejoining_subscription_reads_live_and_reports_its_state() {
    let (_driven, _archive, conductor) = served_archive_with(2);
    let (client, archive) = client_and_archive(conductor);
    let (status, subscription) = add(client, &rejoining(archive));
    assert_eq!(status, Status::Ok.code());
    let (status, plain) = add(client, &subscription_defaults());
    assert_eq!(status, Status::Ok.code());
    for handle in [subscription, plain] {
        let (status, read) = state(handle);
        assert_eq!(status, Status::Ok.code());
        assert_eq!(
            (
                read.size,
                read.recovering,
                read.merge_failure,
                read.reserved
            ),
            (16, 0, MERGE_NONE, 0)
        );
    }
    let (_, publication) = add_publication_of(client, DATA);
    assert_eq!(offer(publication, b"live").0, Status::Ok.code());
    let mut seen = Seen::default();
    poll_until(subscription, client, &mut seen, 4, 1);
    assert_eq!(seen.messages, [b"live".to_vec()]);
    // The Archive handle is only a factory: closing it leaves the rejoin.
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
    assert_eq!(offer(publication, b"after").0, Status::Ok.code());
    let mut after = Seen::default();
    poll_until(subscription, client, &mut after, 4, 1);
    assert_eq!(after.messages, [b"after".to_vec()]);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(state(subscription).0, Status::Closed.code());
}

/// A rejoin takes one request publisher of its own and releases it at its
/// subscription's close: with two publishers, the Archive handle's and
/// one, a second rejoin is refused until the first closes, then takes its
/// slot. A refused rejoin leaves its subscription removed: repeated
/// refusals never use up the stream's subscriber slots.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_rejoin_holds_one_publisher_slot_and_releases_it_at_close() {
    let (_driven, _archive, conductor) = served_archive_with(2);
    let (client, archive) = client_and_archive(conductor);
    let (status, first) = add(client, &rejoining(archive));
    assert_eq!(status, Status::Ok.code());
    // More refusals than the stream has subscriber slots (4).
    for _ in 0..6 {
        let (status, refused) = add(client, &rejoining(archive));
        assert_eq!(status, Status::Refused.code());
        assert_eq!(refused, u64::MAX, "nothing written");
    }
    assert_eq!(karyos_subscription_close(first), Status::Ok.code());
    let (status, second) = add(client, &rejoining(archive));
    assert_eq!(status, Status::Ok.code());
    let (status, plain) = add(client, &subscription_defaults());
    assert_eq!(status, Status::Ok.code(), "a subscriber slot is still free");
    assert_ne!(second, plain);
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// The Archive must be the client's own, a chosen id must fit 32 bits,
/// and the handle must be an Archive's; nothing is opened otherwise.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_rejoin_checks_its_archive_and_its_id() {
    let (_driven, _archive, conductor) = served_archive_with(4);
    let (client, archive) = client_and_archive(conductor);
    // A client of another driver: its Archive is not ours.
    let (_other_driven, _other_archive, other_conductor) = served_archive_with(2);
    let (other_client, other_archive) = client_and_archive(other_conductor);
    for (options, expected) in [
        (rejoining(other_archive), Status::InvalidArgument),
        (
            SubscriptionOptions {
                archive_client_id: u64::from(u32::MAX) + 1,
                ..rejoining(archive)
            },
            Status::InvalidArgument,
        ),
        (rejoining(0), Status::InvalidHandle),
        (rejoining(client), Status::InvalidHandle),
    ] {
        let (status, subscription) = add(client, &options);
        assert_eq!(status, expected.code());
        assert_eq!(subscription, u64::MAX, "nothing written");
    }
    // A chosen id is the caller's; 0 takes one of the library's.
    for client_id in [9, 0] {
        let (status, _) = add(
            client,
            &SubscriptionOptions {
                archive_client_id: client_id,
                ..rejoining(archive)
            },
        );
        assert_eq!(status, Status::Ok.code(), "id {client_id}");
    }
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    assert_eq!(karyos_client_close(other_client), Status::Ok.code());
}

/// The state's sized write, with no driver (the MIRI row): a struct of a
/// newer header keeps its tail, and a failure is written as its code.
#[test]
fn the_rejoin_state_is_written_by_the_callers_size() {
    /// A struct of a newer header: one more field, which stays untouched.
    #[repr(C)]
    struct Newer {
        state: SubscriptionRejoin,
        later: u64,
    }
    let mut newer = Newer {
        state: SubscriptionRejoin {
            size: size_of_u32::<Newer>(),
            recovering: 7,
            merge_failure: 7,
            reserved: 7,
        },
        later: u64::MAX,
    };
    let failure = karyos_client::MergeError::Live(karyos_client::ClientError::Timeout);
    // SAFETY: `newer` is live, aligned and its stated size.
    unsafe { write_rejoin_state((&raw mut newer).cast(), true, Some(&failure)) };
    assert_eq!(
        (
            newer.state.size,
            newer.state.recovering,
            newer.state.merge_failure,
            newer.state.reserved
        ),
        (size_of_u32::<Newer>(), 1, 9, 0),
        "the caller's size stays"
    );
    assert_eq!(newer.later, u64::MAX);
    let mut exact = SubscriptionRejoin {
        size: 16,
        recovering: 7,
        merge_failure: 7,
        reserved: 7,
    };
    // SAFETY: `exact` is live, aligned and its stated size.
    unsafe { write_rejoin_state(&mut exact, false, None) };
    assert_eq!((exact.recovering, exact.merge_failure), (0, MERGE_NONE));
    // The arguments are checked before the handle: a null or short struct
    // is refused with nothing written, whatever the handle.
    // SAFETY: a null pointer, refused before any use.
    let status = unsafe { karyos_subscription_rejoin_state(0, core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut short = SubscriptionRejoin {
        size: 12,
        recovering: 7,
        merge_failure: 7,
        reserved: 7,
    };
    // SAFETY: a live struct; its size is below the first version's.
    let status = unsafe { karyos_subscription_rejoin_state(0, &mut short) };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!((short.recovering, short.merge_failure), (7, 7));
    assert_eq!(state(0).0, Status::InvalidHandle.code());
}

/// The state's arguments are checked first, and its struct is written by
/// the caller's size, for a subscription that does not rejoin.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn the_rejoin_state_checks_its_arguments_and_writes_by_size() {
    let (_driven, ours, _theirs) = driven();
    let client = client::insert_embedded(Client::with_conductor(ours, test_context()))
        .unwrap()
        .raw();
    let (status, subscription) = add_subscription_of(client, STREAM);
    assert_eq!(status, Status::Ok.code());
    // SAFETY: a null pointer, refused before any use.
    let status = unsafe { karyos_subscription_rejoin_state(subscription, core::ptr::null_mut()) };
    assert_eq!(status, Status::InvalidArgument.code());
    let mut short = SubscriptionRejoin {
        size: 12,
        recovering: 7,
        merge_failure: 7,
        reserved: 7,
    };
    // SAFETY: a live struct; its size is below the first version's.
    let status = unsafe { karyos_subscription_rejoin_state(subscription, &mut short) };
    assert_eq!(status, Status::InvalidArgument.code());
    assert_eq!((short.recovering, short.merge_failure), (7, 7));
    /// A struct of a newer header: one more field, which stays untouched.
    #[repr(C)]
    struct Newer {
        state: SubscriptionRejoin,
        later: u64,
    }
    let mut newer = Newer {
        state: SubscriptionRejoin {
            size: size_of_u32::<Newer>(),
            recovering: 7,
            merge_failure: 7,
            reserved: 7,
        },
        later: u64::MAX,
    };
    // SAFETY: `newer` is live and its stated size.
    let status = unsafe { karyos_subscription_rejoin_state(subscription, (&raw mut newer).cast()) };
    assert_eq!(status, Status::Ok.code());
    assert_eq!(
        (
            newer.state.size,
            newer.state.recovering,
            newer.state.merge_failure
        ),
        (size_of_u32::<Newer>(), 0, MERGE_NONE),
        "the caller's size stays"
    );
    assert_eq!(newer.later, u64::MAX);
    assert_eq!(state(0).0, Status::InvalidHandle.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
}

/// Each merge failure has its code, and one this ABI version does not
/// name is `KARYOS_MERGE_OTHER`'s through the match's wildcard.
#[test]
fn each_merge_failure_has_its_code() {
    use karyos_client::{ClientError, MergeError, Overrun};
    assert_eq!(
        merge_code(&MergeError::ReplayOverrun(Overrun::new(0, 1, 1))),
        5
    );
    assert_eq!(merge_code(&MergeError::Replay(ClientError::Timeout)), 7);
    assert_eq!(
        merge_code(&MergeError::LiveOverrun(Overrun::new(0, 1, 1))),
        8
    );
    assert_eq!(merge_code(&MergeError::Live(ClientError::Timeout)), 9);
}

/// The Archive's control streams as a real Archive's server reads and
/// writes them (#549).
pub(super) mod real {
    use karyos_archive::server::{RequestSource, ResponseSink};
    use karyos_client::{ClientPublication, ClientSubscription, MessageLimit, OfferOutcome};

    /// The request stream as the server reads it.
    pub(crate) struct Reading(pub(crate) ClientSubscription);

    impl RequestSource for Reading {
        fn next(&mut self, out: &mut [u8]) -> Option<usize> {
            let mut length = None;
            let _ = self.0.poll(
                |bytes, _| {
                    if let Some(into) = out.get_mut(..bytes.len()) {
                        into.copy_from_slice(bytes);
                        length = Some(bytes.len());
                    }
                },
                MessageLimit::new(1),
            );
            length
        }
    }

    /// The response stream as the server writes it.
    pub(crate) struct Writing(pub(crate) ClientPublication);

    impl ResponseSink for Writing {
        fn send(&mut self, message: &[u8]) -> bool {
            matches!(self.0.offer(message), Ok(OfferOutcome::Accepted { .. }))
        }
    }
}

/// A lapped subscription added with `KARYOS_REJOIN_ARCHIVE` recovers its
/// gap through a real Archive (#549): the production host (karyos-tools'
/// `DriverHost`, which holds a replay until its target's first reader),
/// the control server and an agent on a temporary directory. The stream
/// is recorded from its start; the optional reader, never polled, is
/// lapped by five terms; then, polled through the C ABI with
/// `karyos_client_poll`, it reports the recovery
/// (`karyos_subscription_rejoin_state`), ends it with no merge failure,
/// and delivers every message once, in order, byte-exact, at its
/// position.
#[test]
#[cfg_attr(miri, ignore = "driver integration; covered natively")]
fn a_lapped_subscription_recovers_its_gap_through_a_real_archive() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use karyos_archive::agent::{AgentConfig, ArchiveHandle};
    use karyos_archive::control::{self, ControlMessage, ResponseCode};
    use karyos_archive::disk::StdDisk;
    use karyos_archive::recorder::Mode;
    use karyos_archive::segment::SyncPolicy;
    use karyos_archive::server::{ControlServer, MAX_REQUEST};
    use karyos_client::{ConcurrentOfferOutcome, MessageLimit, OfferOutcome};
    use karyos_sys::log_buffer::{PublicationMode, Role};
    use karyos_sys::sizing::MIN_TERM_LENGTH;
    use karyos_tools::archive::DriverHost;

    /// Removes the directory when the test ends, a failing one included.
    struct Removed(std::path::PathBuf);
    impl Drop for Removed {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let dir = std::env::temp_dir().join(format!("karyos-ffi-rejoin-{}", std::process::id()));
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
    // The test's own requester, to start the recording.
    let mut asking = driver.concurrent_publication(requests).unwrap();
    let mut answers = driver.subscribe(responses, Role::Required).unwrap();
    let reading = real::Reading(driver.subscribe(requests, Role::Required).unwrap());
    let writing = real::Writing(driver.publication(responses).unwrap());
    let mut publication = driver.publication(data).unwrap();
    let conductor = driver.connect().unwrap();
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let mut server = ControlServer::new(agent, DriverHost::new(driver), reading, writing);
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
                    started = Some(response.code);
                }
            },
            MessageLimit::new(16),
        );
    }
    assert_eq!(started, Some(ResponseCode::Ok));
    drop(answers);
    drop(asking);

    // The C client, its Archive handle and the rejoining subscription:
    // control calls that wait for the driver, which this thread runs.
    let (client, archive, subscription) = std::thread::scope(|scope| {
        let adding = scope.spawn(move || {
            let (client, archive) = client_and_archive(conductor);
            let (status, subscription) = add(client, &rejoining(archive));
            assert_eq!(status, Status::Ok.code());
            (client, archive, subscription)
        });
        while !adding.is_finished() {
            cycle(&mut server);
        }
        adding.join().unwrap()
    });

    // Lap the subscription, which is not polled: five terms of messages
    // of several sizes, some fragmented, each with its sequence first.
    let mut sent: Vec<(u64, Vec<u8>)> = Vec::new();
    let goal = 5 * u64::from(MIN_TERM_LENGTH);
    let begun = Instant::now();
    while sent.last().is_none_or(|(position, _)| *position < goal) {
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

    // Poll through the C ABI on a thread of its own, while this one runs
    // the driver, the server and the host.
    let polling = AtomicBool::new(true);
    let (seen, recovered) = std::thread::scope(|scope| {
        let poller = scope.spawn(|| {
            let mut seen = Seen::default();
            let mut recovered = false;
            let begun = Instant::now();
            loop {
                assert!(
                    begun.elapsed() < Duration::from_secs(60),
                    "{} of {}, recovered {recovered}",
                    seen.messages.len(),
                    sent.len()
                );
                let _ = poll(client);
                let (status, _) = poll_into(subscription, &mut seen, 64);
                assert_eq!(status, Status::Ok.code());
                let (status, read) = state(subscription);
                assert_eq!(status, Status::Ok.code());
                assert_eq!(read.merge_failure, MERGE_NONE, "a failed merge");
                recovered |= read.recovering == 1;
                if seen.messages.len() >= sent.len() && read.recovering == 0 {
                    polling.store(false, Ordering::Release);
                    return (seen, recovered);
                }
                std::thread::yield_now();
            }
        });
        while polling.load(Ordering::Acquire) && !poller.is_finished() {
            cycle(&mut server);
            std::thread::yield_now();
        }
        poller.join().unwrap()
    });
    assert!(recovered, "the subscription was never lapped");
    let delivered: Vec<(u64, Vec<u8>)> = seen
        .infos
        .iter()
        .map(|info| info.position)
        .zip(seen.messages)
        .collect();
    assert!(
        delivered == sent,
        "every message once, in order, byte-exact, at its position"
    );
    assert_eq!(karyos_archive_close(archive), Status::Ok.code());
    assert_eq!(karyos_client_close(client), Status::Ok.code());
    drop(publication);
    let _ = server.shutdown_into_host();
}
