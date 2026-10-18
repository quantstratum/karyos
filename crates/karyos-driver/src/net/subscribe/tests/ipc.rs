// SPDX-License-Identifier: Apache-2.0

//! Network streams on IPC drivers (network-shared-terms n3 and n4): a
//! driver A, heap or IPC, publishes on loopback; an IPC driver B
//! subscribes, installs each image in shared regions and exposes it as an
//! aggregate, which an in-process subscriber reads and a remote client
//! fetches. On an IPC A, the publication's lanes are A's regions.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use karyos_client::ipc::{AttachError, RemoteClient, attach};
use karyos_client::{MessageLimit, OfferOutcome, Outcome};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{Role, SealReason};
use karyos_sys::sizing::{MIN_TERM_LENGTH, TermLength};
use karyos_sys::term_bytes::SharedTerms;

use super::{ANY_PORT, BUDGET, aggregate, channel, driver};
use crate::admission::IpcConfig;
use crate::agents::ThreadingMode;
use crate::clock::SystemClock;
use crate::embedded::{AggregateHandle, DriverConfig, EmbeddedDriver, StreamTerms};
use crate::error::DriverError;
use crate::net::{NetworkConfig, NetworkSubscription};

type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("karyos-n3-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    TempDir(dir)
}

/// A test's directory, removed when the test ends, passed or not.
struct TempDir(PathBuf);

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An IPC driver with a network, on the system clock, timeouts of 5 s.
fn ipc_driver(dir: &Path) -> IpcDriver {
    let timeout = 5_000_000_000;
    EmbeddedDriver::with_ipc(
        DriverConfig {
            network: Some(NetworkConfig {
                threading: ThreadingMode::Shared,
                ..NetworkConfig::default()
            }),
            ..DriverConfig::default()
        },
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 2,
            hello_timeout: timeout,
            max_outbound_per_client: 8,
            fetch_deadline: timeout,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: crate::admission::DEFAULT_MAX_TOOLS,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Runs both drivers until `done`.
fn pump<P: StreamTerms>(
    a: &mut EmbeddedDriver<P>,
    b: &mut IpcDriver,
    mut done: impl FnMut(&mut IpcDriver) -> bool,
) {
    let start = Instant::now();
    while !done(b) {
        assert!(start.elapsed() < Duration::from_secs(20), "not reached");
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        std::thread::sleep(Duration::from_micros(100));
    }
}

/// A's publication of `lanes` lanes and B's image of it, exposed.
fn exposed<P: StreamTerms>(
    a: &mut EmbeddedDriver<P>,
    b: &mut IpcDriver,
    lanes: usize,
) -> (AggregateHandle, AggregateHandle, NetworkSubscription) {
    let subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = b.network_subscription_address(10).unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 3, lanes), &channel(address))
        .unwrap();
    let mut image = None;
    pump(a, b, |b| {
        image = b.exposed_network_image(10, 3);
        image.is_some()
    });
    (publication, image.unwrap(), subscription)
}

/// Offers `count` numbered messages on lane `lane` of `publication`,
/// running both drivers while the publisher is held.
fn offer<P: StreamTerms>(
    a: &mut EmbeddedDriver<P>,
    b: &mut IpcDriver,
    publication: &AggregateHandle,
    lane: u8,
    count: u32,
) {
    let mut handle = a
        .publication(publication.lane(Lane::try_new(lane).unwrap()).unwrap())
        .unwrap();
    let mut sent = 0u32;
    pump(a, b, |_| {
        while sent < count {
            let mut payload = [0u8; 600];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match handle.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        sent == count
    });
}

/// An IPC driver's image: each lane is a shared region of the driver's
/// instance, with fresh increasing ids; an in-process subscriber of the
/// exposed aggregate reads every lane's exact sequence; and the image
/// refuses a cutover (`ImageCutover`, N-4a).
#[test]
fn an_ipc_drivers_image_lives_in_regions_and_is_read_in_process() {
    let dir = dir("in-process");
    let (mut a, mut b) = (driver(ThreadingMode::Shared), ipc_driver(&dir));
    let (publication, image, _subscription) = exposed(&mut a, &mut b, 2);
    let instance = b.instance().unwrap();
    let mut ids = Vec::new();
    for stream in image.streams() {
        let lane = b.stream_ref(stream).unwrap();
        let record = lane.buffer.region().unwrap().record();
        assert_eq!((record.instance, record.generation), (instance, 0));
        ids.push(record.region);
    }
    assert_eq!(ids.len(), 2);
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{ids:?}");
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    offer(&mut a, &mut b, &publication, 0, 40);
    offer(&mut a, &mut b, &publication, 1, 10);
    let mut seen = [0u32; 2];
    pump(&mut a, &mut b, |_| {
        let _ = reader.poll(
            |bytes, lane, _| {
                let lane = usize::from(lane.get());
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen[lane], "lane {lane} in order");
                seen[lane] += 1;
            },
            BUDGET,
        );
        seen == [40, 10]
    });
    let reconfiguration = crate::generations::Reconfiguration {
        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
        spare_slots: 5,
    };
    assert!(matches!(
        b.reconfigure_aggregate(&image, reconfiguration),
        Err(DriverError::ImageCutover { .. })
    ));
    // A lane of this two-lane image names the image as the reason, before
    // the aggregate-lane refusal any other aggregate's lane gets.
    assert!(matches!(
        b.reconfigure_stream(image.lane(Lane::ZERO).unwrap(), reconfiguration),
        Err(DriverError::ImageCutover { .. })
    ));
    drop(reader);
    let _ = (a.close_network(), b.close_network());
}

/// Two IPC drivers over the network (network-shared-terms n4): A's
/// network publication, made by the public call, has its lanes in A's
/// regions; B subscribes by the public call, and an in-process subscriber
/// of B's image reads every lane's exact sequence.
#[test]
fn an_ipc_drivers_publication_lives_in_regions_and_reaches_an_ipc_image() {
    let (a_dir, b_dir) = (dir("pair-a"), dir("pair-b"));
    let (mut a, mut b) = (ipc_driver(&a_dir), ipc_driver(&b_dir));
    let (publication, image, _subscription) = exposed(&mut a, &mut b, 2);
    let instance = a.instance().unwrap();
    for stream in publication.streams() {
        let lane = a.stream_ref(stream).unwrap();
        let record = lane.buffer.region().unwrap().record();
        assert_eq!(record.instance, instance);
    }
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    offer(&mut a, &mut b, &publication, 0, 40);
    offer(&mut a, &mut b, &publication, 1, 10);
    let mut seen = [0u32; 2];
    pump(&mut a, &mut b, |_| {
        let _ = reader.poll(
            |bytes, lane, _| {
                let lane = usize::from(lane.get());
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen[lane], "lane {lane} in order");
                seen[lane] += 1;
            },
            BUDGET,
        );
        seen == [40, 10]
    });
    drop(reader);
    let _ = (a.close_network(), b.close_network());
}

/// E5 on shared terms (network-shared-terms n4): between two IPC drivers,
/// a steady network cycle on either side allocates nothing, so the
/// sender's staging and NAK reads and the receive owner's writes into
/// regions allocate nothing either.
#[test]
fn a_steady_ipc_network_cycle_allocates_nothing() {
    use karyos_sys::alloc_count::count;

    let ((), made) = count(|| drop(std::hint::black_box(vec![0_u8; 8])));
    assert!(made > 0, "the counting allocator counts in this binary");
    let (a_dir, b_dir) = (dir("alloc-a"), dir("alloc-b"));
    let (mut a, mut b) = (ipc_driver(&a_dir), ipc_driver(&b_dir));
    let (publication, image, _subscription) = exposed(&mut a, &mut b, 1);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // Warm up: every buffer the path keeps is sized by real traffic.
    let (mut sent, mut seen) = (0u32, 0u32);
    pump(&mut a, &mut b, |_| {
        while sent < 128 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        seen == 128
    });
    // Then traffic keeps flowing while only the network cycles are counted.
    let mut work = [0u64; 2];
    for _ in 0..2_000 {
        while sent < 384 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let ((units, error), made) = count(|| a.serve_network());
        assert!(error.is_none());
        assert_eq!(made, 0, "publisher: {units} units allocated");
        work[0] += u64::from(units);
        let ((units, error), made) = count(|| b.serve_network());
        assert!(error.is_none());
        assert_eq!(made, 0, "subscriber: {units} units allocated");
        work[1] += u64::from(units);
        let _ = (a.do_work().unwrap(), b.do_work().unwrap());
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        if seen == 384 {
            break;
        }
        std::thread::sleep(Duration::from_micros(50));
    }
    assert_eq!(seen, 384);
    assert!(
        work[0] > 0 && work[1] > 0,
        "counted cycles did work: {work:?}"
    );
    drop(reader);
    let _ = (a.close_network(), b.close_network());
}

/// Attaches a remote client to `b` while both drivers run.
fn attach_running<P: StreamTerms>(
    a: &mut EmbeddedDriver<P>,
    b: &mut IpcDriver,
    dir: &Path,
) -> Result<RemoteClient, AttachError> {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| attach(dir, Duration::from_secs(5), 16));
        while !handle.is_finished() {
            let _ = a.do_work().unwrap();
            let _ = b.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap()
    })
}

/// A remote client subscribes to an IPC driver's image by its stream key,
/// fetches its lane (a manifest and the lane's region), reads the exact
/// sequence the remote publisher sent, and, once the subscription is
/// removed, reports closed at the image's seal, `ImageRetired`.
#[test]
fn a_remote_client_fetches_an_image_and_closes_at_its_retirement() {
    let dir = dir("remote");
    let (mut a, mut b) = (driver(ThreadingMode::Shared), ipc_driver(&dir));
    let (publication, _image, subscription) = exposed(&mut a, &mut b, 1);
    let mut client = attach_running(&mut a, &mut b, &dir).unwrap();
    let subscribed = Arc::new(AtomicBool::new(false));
    let retired = Arc::new(AtomicBool::new(false));
    let (client_subscribed, client_retired) = (Arc::clone(&subscribed), Arc::clone(&retired));
    let count = 30u32;
    std::thread::scope(|scope| {
        let reader = scope.spawn(move || {
            let key = StreamKey {
                stream_id: 10,
                session_id: 3,
            };
            let _ = client
                .add_subscription(key, SubscriberRole::Required)
                .unwrap();
            let mut fetchable = None;
            let start = Instant::now();
            while fetchable.is_none() {
                assert!(start.elapsed() < Duration::from_secs(10), "no completion");
                let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                    Outcome::Fetchable(grant) => fetchable = Some(grant),
                    other => panic!("expected a fetchable grant, got {other:?}"),
                });
            }
            let mut subscription = client.take_subscription(&fetchable.unwrap()).unwrap();
            client_subscribed.store(true, Ordering::Release);
            let mut seen = 0u32;
            let mut closed = None;
            let start = Instant::now();
            while closed.is_none() {
                assert!(start.elapsed() < Duration::from_secs(20), "never closed");
                let summary = subscription
                    .poll(
                        |payload, _| {
                            let index = u32::from_le_bytes(payload[..4].try_into().unwrap());
                            assert_eq!(index, seen, "in order");
                            seen += 1;
                        },
                        MessageLimit::new(64),
                    )
                    .unwrap();
                if seen == count {
                    client_retired.store(true, Ordering::Release);
                }
                if summary.closed.is_some() {
                    closed = summary.close_reason;
                }
            }
            drop(subscription);
            drop(client);
            (seen, closed)
        });
        let start = Instant::now();
        while !subscribed.load(Ordering::Acquire) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "never subscribed"
            );
            let _ = a.do_work().unwrap();
            let _ = b.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        offer(&mut a, &mut b, &publication, 0, count);
        while !retired.load(Ordering::Acquire) {
            assert!(start.elapsed() < Duration::from_secs(20), "never read");
            let _ = a.do_work().unwrap();
            let _ = b.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        // Every message read: the image retires and seals.
        assert!(b.unsubscribe_network(subscription).unwrap());
        while !reader.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "client stuck");
            let _ = a.do_work().unwrap();
            let _ = b.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        let (seen, closed) = reader.join().unwrap();
        assert_eq!(seen, count);
        assert_eq!(closed, Some(SealReason::ImageRetired));
    });
    let _ = (a.close_network(), b.close_network());
}
