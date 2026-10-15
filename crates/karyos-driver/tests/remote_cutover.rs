// SPDX-License-Identifier: Apache-2.0

//! Cutovers with remote participants, over real sockets, descriptors and
//! regions (Linux; `quantstratum-docs: karyos/design/ipc-data-path.md`,
//! Generations across processes): the client's control path fetches and
//! prepares each successor, and its handle moves when it reaches the seal,
//! with no allocation and no free in the data calls, which this binary
//! counts with its global allocator.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_client::ipc::{RemoteClient, attach};
use karyos_client::{
    ConcurrentOfferOutcome, Fetchable, LinkStatus, MessageLimit, OfferOutcome, Outcome,
};
use karyos_driver::{
    DriverConfig, EmbeddedDriver, IpcConfig, LossPolicy, Reconfiguration, StreamConfig,
    StreamHandle, SystemClock,
};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::alloc_count::{CountingAllocator, count};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

type IpcDriver = EmbeddedDriver<SharedTerms>;

const KEY: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-cut-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A driver on the system clock, with a cutover deadline of `deadline_ns`.
fn driver(dir: &Path, deadline_ns: u64) -> IpcDriver {
    driver_with(dir, deadline_ns, 16)
}

/// As [`driver`], with at most `max_exports` grants per client.
fn driver_with(dir: &Path, deadline_ns: u64, max_exports: usize) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig {
            cutover_deadline: deadline_ns,
            ..DriverConfig::default()
        },
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 2,
            hello_timeout: 5_000_000_000,
            max_outbound_per_client: 8,
            fetch_deadline: 5_000_000_000,
            max_exports_per_client: max_exports,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

fn stream_config(publication: PublicationMode) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication,
        },
        allow_unconnected: false,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

fn reconfigure(driver: &mut IpcDriver, stream: StreamHandle) {
    let _ = driver
        .reconfigure_stream(
            stream,
            Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 5,
            },
        )
        .unwrap();
}

/// Serves the driver while `client` runs on another thread; returns its
/// result once it finished.
fn serve_while<R: Send>(driver: &mut IpcDriver, client: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(client);
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "client stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap()
    })
}

/// Attaches a remote client, requests one grant with `request` and takes
/// it with `take`, while the driver runs.
fn remote_grant<H: Send>(
    driver: &mut IpcDriver,
    dir: &Path,
    request: impl FnOnce(&mut RemoteClient) + Send,
    take: impl FnOnce(&RemoteClient, &Fetchable) -> H + Send,
) -> (RemoteClient, H) {
    let dir = dir.to_path_buf();
    serve_while(driver, move || {
        let mut client = attach(&dir, Duration::from_secs(5), 16).unwrap();
        request(&mut client);
        let mut fetchable = None;
        let start = Instant::now();
        while fetchable.is_none() {
            assert!(start.elapsed() < Duration::from_secs(5), "no grant");
            let _ = client.poll(usize::MAX, |completion| {
                if let Outcome::Fetchable(grant) = completion.outcome {
                    fetchable = Some(grant);
                }
            });
        }
        let handle = take(&client, &fetchable.unwrap());
        (client, handle)
    })
}

fn counter(driver: &IpcDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            karyos_sys::counters::CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

/// Runs the driver until `done`, within a bound.
fn serve_until(driver: &mut IpcDriver, mut done: impl FnMut(&IpcDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(10), "never happened");
        let _ = driver.do_work().unwrap();
        std::thread::sleep(Duration::from_micros(200));
    }
}

/// A remote subscription moves to its successor: the client's poll fetches
/// and prepares it, the subscription's poll crosses the seal and delivers
/// the message published on the successor at its stream position, and no
/// subscription poll allocates or frees. The moved predecessor's grant is
/// detached and the predecessor freed.
#[test]
fn a_remote_subscription_moves_without_allocating() {
    let dir = dir("subscriber");
    let mut driver = driver(&dir, 5_000_000_000);
    let stream = driver
        .add_stream(stream_config(PublicationMode::Exclusive))
        .unwrap();
    let (client, mut subscription) = remote_grant(
        &mut driver,
        &dir,
        |client| {
            let _ = client
                .add_subscription(KEY, SubscriberRole::Required)
                .unwrap();
        },
        |client, fetchable| client.take_subscription(fetchable).unwrap(),
    );
    let mut publication = driver.publication(stream).unwrap();
    assert!(matches!(
        publication.offer(b"before").unwrap(),
        OfferOutcome::Accepted { position: 0, .. }
    ));
    reconfigure(&mut driver, stream);
    let mut client = client;
    let (after, seen, operations) = serve_while(&mut driver, || {
        let mut after = None;
        let mut seen = [None::<u64>; 2];
        let mut operations = 0;
        let start = Instant::now();
        while seen[1].is_none() {
            assert!(start.elapsed() < Duration::from_secs(10), "never moved");
            let _ = client.poll(usize::MAX, |_| {});
            if after.is_none()
                && let OfferOutcome::Accepted { position, .. } =
                    publication.offer(b"after").unwrap()
            {
                after = Some(position);
            }
            let (polled, made) = count(|| {
                subscription
                    .poll(
                        |bytes, info| {
                            let at = usize::from(bytes == b"after");
                            seen[at] = Some(info.position);
                        },
                        MessageLimit::new(8),
                    )
                    .is_ok()
            });
            assert!(polled);
            operations += made;
            std::thread::sleep(Duration::from_micros(100));
        }
        // The next control-path poll drops the retired predecessor.
        let _ = client.poll(usize::MAX, |_| {});
        (after, seen, operations)
    });
    assert_eq!(operations, 0, "a subscription poll allocated or freed");
    assert_eq!(seen[0], Some(0));
    assert_eq!(seen[1], after);
    assert!(after.unwrap() > 0);
    assert_eq!(counter(&driver, "grants fenced"), 0);
    // The predecessor's grant is detached, and the predecessor freed.
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 1 && driver.generations(stream).unwrap().len() == 1
    });
    drop(subscription);
    drop(client);
}

/// A remote exclusive publication moves to its successor without
/// allocating in its offers; an in-process subscriber reads both sides.
#[test]
fn a_remote_publication_moves_without_allocating() {
    let dir = dir("publisher");
    let mut driver = driver(&dir, 5_000_000_000);
    let stream = driver
        .add_stream(stream_config(PublicationMode::Exclusive))
        .unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let (client, mut publication) = remote_grant(
        &mut driver,
        &dir,
        |client| {
            let _ = client.add_publication(KEY, false).unwrap();
        },
        |client, fetchable| client.take_publication(fetchable).unwrap(),
    );
    assert!(matches!(
        publication.offer(b"before").unwrap(),
        OfferOutcome::Accepted { position: 0, .. }
    ));
    reconfigure(&mut driver, stream);
    let mut client = client;
    let (after, operations) = serve_while(&mut driver, || {
        let mut operations = 0;
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(10), "never moved");
            let _ = client.poll(usize::MAX, |_| {});
            let (offered, made) = count(|| publication.offer(b"after"));
            operations += made;
            if let OfferOutcome::Accepted { position, .. } = offered.unwrap() {
                let _ = client.poll(usize::MAX, |_| {});
                return (position, operations);
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    });
    assert_eq!(operations, 0, "an offer allocated or freed");
    assert!(after > 0);
    let mut seen = Vec::new();
    serve_until(&mut driver, |_| {
        let _ = subscription.poll(
            |bytes, info| seen.push((info.position, bytes.to_vec())),
            MessageLimit::new(8),
        );
        seen.len() == 2
    });
    assert_eq!(
        seen,
        vec![(0, b"before".to_vec()), (after, b"after".to_vec())]
    );
    assert_eq!(counter(&driver, "grants fenced"), 0);
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 1
    });
    drop(publication);
    drop(client);
}

/// A remote concurrent publication moves to its successor without
/// allocating in its offers.
#[test]
fn a_remote_concurrent_publication_moves_without_allocating() {
    let dir = dir("concurrent");
    let mut driver = driver(&dir, 5_000_000_000);
    let stream = driver
        .add_stream(stream_config(PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: true,
        }))
        .unwrap();
    let mut subscription = driver.subscribe(stream, Role::Required).unwrap();
    let (client, mut publication) = remote_grant(
        &mut driver,
        &dir,
        |client| {
            let _ = client.add_concurrent_publication(KEY, false).unwrap();
        },
        |client, fetchable| client.take_concurrent_publication(fetchable).unwrap(),
    );
    assert!(matches!(
        publication.offer(b"before").unwrap(),
        ConcurrentOfferOutcome::Accepted { position: 0, .. }
    ));
    reconfigure(&mut driver, stream);
    let mut client = client;
    let (after, operations) = serve_while(&mut driver, || {
        let mut operations = 0;
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(10), "never moved");
            let _ = client.poll(usize::MAX, |_| {});
            let (offered, made) = count(|| publication.offer(b"after"));
            operations += made;
            if let ConcurrentOfferOutcome::Accepted { position, .. } = offered.unwrap() {
                let _ = client.poll(usize::MAX, |_| {});
                return (position, operations);
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    });
    assert_eq!(operations, 0, "an offer allocated or freed");
    let mut seen = Vec::new();
    serve_until(&mut driver, |_| {
        let _ = subscription.poll(
            |bytes, info| seen.push((info.position, bytes.to_vec())),
            MessageLimit::new(8),
        );
        seen.len() == 2
    });
    assert_eq!(
        seen,
        vec![(0, b"before".to_vec()), (after, b"after".to_vec())]
    );
    assert_eq!(counter(&driver, "grants fenced"), 0);
    drop(publication);
    drop(client);
}

/// A subscriber whose client fetched and staged its successor, then paused
/// past the deadline: the fence wins, the handle's activation fails and it
/// reports the end; the fetched successor stays charged until its
/// `Detach`, sent by the client's next poll, and the old grant until the
/// handle is dropped.
#[test]
fn a_staged_successor_fenced_while_paused_fails_to_activate() {
    let dir = dir("paused");
    let mut driver = driver(&dir, 50_000_000);
    let stream = driver
        .add_stream(stream_config(PublicationMode::Exclusive))
        .unwrap();
    let (mut client, mut subscription) = remote_grant(
        &mut driver,
        &dir,
        |client| {
            let _ = client
                .add_subscription(KEY, SubscriberRole::Required)
                .unwrap();
        },
        |client, fetchable| client.take_subscription(fetchable).unwrap(),
    );
    let link = std::sync::Arc::clone(subscription.generation_link().unwrap());
    reconfigure(&mut driver, stream);
    // The control path stages the successor; the handle does not poll.
    let mut client = serve_while(&mut driver, move || {
        let start = Instant::now();
        while link.status() != LinkStatus::Offered {
            assert!(start.elapsed() < Duration::from_secs(10), "never staged");
            let _ = client.poll(usize::MAX, |_| {});
            std::thread::sleep(Duration::from_micros(100));
        }
        client
    });
    // Paused past the deadline: the driver fences the sent successor.
    serve_until(&mut driver, |driver| counter(driver, "grants fenced") == 1);
    let summary = subscription
        .poll(|_, _| panic!("nothing to deliver"), MessageLimit::new(8))
        .unwrap();
    assert!(summary.closed.is_some(), "{summary:?}");
    assert_eq!(
        subscription.generation_link().unwrap().status(),
        LinkStatus::Closed
    );
    // Both grants are charged until their Detach.
    assert_eq!(counter(&driver, "grants detached"), 0);
    let _ = client.poll(usize::MAX, |_| {});
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 1
    });
    drop(subscription);
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 2
    });
    drop(client);
}

/// The counts above are meaningful: in this binary the counter sees an
/// allocation and its free.
#[test]
fn the_counting_allocator_counts_in_this_binary() {
    let ((), operations) = count(|| drop(std::hint::black_box(vec![0u8; 64])));
    assert_eq!(operations, 2);
}

/// A final seal carries no successor mark: a remote publication and a
/// remote subscription close at once at `remove_stream`, without waiting
/// for any event from their client's control path.
#[test]
fn remote_handles_close_at_once_at_a_final_seal() {
    let dir = dir("final");
    let mut driver = driver(&dir, 5_000_000_000);
    let stream = driver
        .add_stream(stream_config(PublicationMode::Exclusive))
        .unwrap();
    let path = dir.clone();
    let (client, mut publication, mut subscription) = serve_while(&mut driver, move || {
        let mut client = attach(&path, Duration::from_secs(5), 16).unwrap();
        let publishing = client.add_publication(KEY, false).unwrap();
        let _ = client
            .add_subscription(KEY, SubscriberRole::Required)
            .unwrap();
        let mut grants = Vec::new();
        let start = Instant::now();
        while grants.len() < 2 {
            assert!(start.elapsed() < Duration::from_secs(5), "no grants");
            let _ = client.poll(usize::MAX, |completion| {
                if let Outcome::Fetchable(grant) = completion.outcome {
                    grants.push((completion.sequence, grant));
                }
            });
        }
        let (mut publication, mut subscription) = (None, None);
        for (sequence, grant) in grants {
            if sequence == publishing {
                publication = Some(client.take_publication(&grant).unwrap());
            } else {
                subscription = Some(client.take_subscription(&grant).unwrap());
            }
        }
        (client, publication.unwrap(), subscription.unwrap())
    });
    assert!(matches!(
        publication.offer(b"last").unwrap(),
        OfferOutcome::Accepted { position: 0, .. }
    ));
    driver.remove_stream(stream).unwrap();
    // The publication's next attempt sees the final seal and ends.
    assert_eq!(publication.offer(b"late").unwrap(), OfferOutcome::Closed);
    drop(publication);
    // The subscription reads the backlog, then the end, once the driver
    // positions the seal; its client is never polled.
    let mut seen = Vec::new();
    let mut closed = None;
    serve_until(&mut driver, |_| {
        let summary = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
            .unwrap();
        closed = summary.closed;
        closed.is_some()
    });
    assert_eq!(seen, vec![b"last".to_vec()]);
    assert_eq!(
        subscription.generation_link().unwrap().status(),
        LinkStatus::Current
    );
    drop(subscription);
    drop(client);
}

/// A client whose control path hears `Fenced` while the successor it staged
/// is still offered, before its handle polls: the control path closes the
/// link and drops the successor (unmapped, then detached), and the handle
/// then reports the end at the seal.
#[test]
fn a_fence_heard_while_the_successor_is_offered_closes_the_link() {
    let dir = dir("fenced-offered");
    let mut driver = driver(&dir, 50_000_000);
    let stream = driver
        .add_stream(stream_config(PublicationMode::Exclusive))
        .unwrap();
    let (client, mut subscription) = remote_grant(
        &mut driver,
        &dir,
        |client| {
            let _ = client
                .add_subscription(KEY, SubscriberRole::Required)
                .unwrap();
        },
        |client, fetchable| client.take_subscription(fetchable).unwrap(),
    );
    let link = std::sync::Arc::clone(subscription.generation_link().unwrap());
    reconfigure(&mut driver, stream);
    let staged = std::sync::Arc::clone(&link);
    let mut client = serve_while(&mut driver, move || {
        let mut client = client;
        let start = Instant::now();
        while staged.status() != LinkStatus::Offered {
            assert!(start.elapsed() < Duration::from_secs(10), "never staged");
            let _ = client.poll(usize::MAX, |_| {});
            std::thread::sleep(Duration::from_micros(100));
        }
        client
    });
    serve_until(&mut driver, |driver| counter(driver, "grants fenced") == 1);
    // The control path hears the fence first.
    let start = Instant::now();
    while link.status() != LinkStatus::Closed {
        assert!(start.elapsed() < Duration::from_secs(10), "never closed");
        let _ = client.poll(usize::MAX, |_| {});
    }
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 1
    });
    let summary = subscription
        .poll(|_, _| panic!("nothing to deliver"), MessageLimit::new(8))
        .unwrap();
    assert!(summary.closed.is_some(), "{summary:?}");
    drop(subscription);
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 2
    });
    drop(client);
}

/// A client at its export bound gets no successor: the driver reserves
/// nothing and sends `Fenced` at once, with no `SuccessorReady`; the
/// control path closes the link and the handle ends at the seal.
#[test]
fn a_client_at_its_export_bound_is_fenced_at_once() {
    let dir = dir("bound");
    let mut driver = driver_with(&dir, 5_000_000_000, 1);
    let stream = driver
        .add_stream(stream_config(PublicationMode::Exclusive))
        .unwrap();
    let (mut client, mut subscription) = remote_grant(
        &mut driver,
        &dir,
        |client| {
            let _ = client
                .add_subscription(KEY, SubscriberRole::Required)
                .unwrap();
        },
        |client, fetchable| client.take_subscription(fetchable).unwrap(),
    );
    let link = std::sync::Arc::clone(subscription.generation_link().unwrap());
    reconfigure(&mut driver, stream);
    let start = Instant::now();
    while link.status() != LinkStatus::Closed {
        assert!(start.elapsed() < Duration::from_secs(10), "never fenced");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |_| {});
    }
    assert_eq!(counter(&driver, "grants reserved"), 1);
    let mut closed = None;
    serve_until(&mut driver, |_| {
        closed = subscription
            .poll(|_, _| panic!("nothing to deliver"), MessageLimit::new(8))
            .unwrap()
            .closed;
        closed.is_some()
    });
    drop(subscription);
    drop(client);
}
