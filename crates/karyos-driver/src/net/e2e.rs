// SPDX-License-Identifier: Apache-2.0

//! The end-to-end matrix of the network wiring (W4, ACS 15962): embedded
//! drivers in one process over loopback, one publishing (W2), the others
//! subscribing to its images (W3).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use karyos_client::OfferOutcome;
use karyos_client::aggregate::{AggregateSubscription, LaneEnd};
use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role, SealReason};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

use crate::agents::{AgentConfig, ThreadingMode};
use crate::embedded::{
    AggregateConfig, AggregateHandle, DriverConfig, EmbeddedDriver, StreamConfig,
};
use crate::net::NetworkConfig;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const MS: u64 = 1_000_000;

/// Agent settings that retire a silent image within 100 ms.
fn fast_agents() -> AgentConfig {
    AgentConfig {
        sm_interval: 5 * MS,
        image_liveness_timeout: 100 * MS,
        idle_image_timeout: 100 * MS,
        ..AgentConfig::default()
    }
}

/// A driver with the default liveness: an image held at its window by a
/// stalled subscriber sees only stationary heartbeats, which keep it for
/// `idle_image_timeout`, so the fast settings would retire it under load.
fn driver(threading: ThreadingMode) -> EmbeddedDriver {
    driver_with(threading, AgentConfig::default())
}

/// A driver whose silent images retire within 100 ms.
fn fast_driver(threading: ThreadingMode) -> EmbeddedDriver {
    driver_with(threading, fast_agents())
}

fn driver_with(threading: ThreadingMode, agents: AgentConfig) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading,
            agents,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

fn aggregate(stream_id: i32, session_id: i32, lanes: usize) -> AggregateConfig {
    AggregateConfig {
        stream: StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id,
                stream_id,
                claim_deadline: 100,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        },
        quanta: vec![u64::from(DEFAULT_MTU) * 4; lanes],
    }
}

fn channel(address: SocketAddr, reliable: bool) -> UdpConfig {
    UdpConfig {
        destination: Destination::Unicast(address),
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable,
        flow_control: None,
        security: Security::Trusted,
    }
}

fn free_address() -> SocketAddr {
    UdpSocket::bind(SocketAddr::new(LOOPBACK, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Runs every driver until `done`, at most about four seconds.
fn pump(
    drivers: &mut [&mut EmbeddedDriver],
    mut done: impl FnMut(&mut [&mut EmbeddedDriver]) -> bool,
) {
    for _ in 0..40_000 {
        for driver in drivers.iter_mut() {
            let _ = driver.do_work().unwrap();
        }
        if done(drivers) {
            return;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let counters: Vec<String> = drivers
        .iter()
        .map(|driver| driver.net.as_ref().unwrap().agent_counters())
        .collect();
    panic!("not reached: {counters:?}");
}

const BUDGET: Budget = Budget {
    work: 256,
    bytes: 1 << 22,
};

/// A publication on `a` and B's subscription of it, with B's image found.
fn connected(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    reliable: bool,
    stream_id: i32,
) -> (AggregateHandle, AggregateHandle) {
    let address = free_address();
    let _ = b
        .add_network_subscription(stream_id, &channel(address, reliable))
        .unwrap();
    let publication = a
        .add_network_publication(aggregate(stream_id, 3, 1), &channel(address, reliable))
        .unwrap();
    let mut image = None;
    pump(&mut [a, b], |drivers| {
        image = drivers[1].network_image(stream_id, 3);
        image.is_some()
    });
    (publication, image.unwrap())
}

/// Offers `count` numbered messages on lane 0 of `publication` while
/// reading `reader` on `b`, until every one arrived in order.
fn exchange(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    publication: &AggregateHandle,
    reader: &mut AggregateSubscription<HeapTerms>,
    count: u32,
) {
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    exchange_on(a, b, &mut lane, reader, 0..count);
}

/// [`exchange`] of the messages numbered `range` on `lane`.
fn exchange_on(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    lane: &mut karyos_client::ClientPublication<HeapTerms>,
    reader: &mut AggregateSubscription<HeapTerms>,
    range: core::ops::Range<u32>,
) {
    exchange_from(a, b, lane, reader, range.start, range);
}

/// [`exchange_on`] whose messages from `range.start` up to `sent` were
/// already offered.
fn exchange_from(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    lane: &mut karyos_client::ClientPublication<HeapTerms>,
    reader: &mut AggregateSubscription<HeapTerms>,
    sent: u32,
    range: core::ops::Range<u32>,
) {
    let count = range.end;
    let (mut sent, mut seen) = (sent, range.start);
    pump(&mut [a, b], |_| {
        while sent < count {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == count
    });
}

/// E1: reliable and unreliable channels both deliver in order across terms,
/// in every threading mode.
#[test]
fn both_channel_kinds_deliver_across_terms() {
    for mode in [ThreadingMode::Shared, ThreadingMode::Dedicated] {
        for reliable in [true, false] {
            let (mut a, mut b) = (driver(mode), driver(mode));
            let (publication, image) = connected(&mut a, &mut b, reliable, 10);
            let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
            exchange(&mut a, &mut b, &publication, &mut reader, 256);
        }
    }
}

/// E1, SPEC §6 flow control: on either channel kind the sender is bound by
/// the receiver's window, so a stalled required subscriber of the image
/// holds the publisher; once it reads, the publisher goes on. Reliability
/// changes recovery (NAKs), not the window.
#[test]
fn a_stalled_receiver_holds_either_channel_at_its_window() {
    for reliable in [true, false] {
        let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
        let (publication, image) = connected(&mut a, &mut b, reliable, 10);
        let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
        let mut lane = a
            .publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap();
        let offer = |lane: &mut karyos_client::ClientPublication<HeapTerms>| {
            matches!(
                lane.offer(&[7u8; 1000]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        };
        let mut accepted = 0u32;
        let mut pressed = false;
        for _ in 0..4000 {
            if offer(&mut lane) {
                accepted += 1;
            } else {
                pressed = true;
            }
            let _ = a.do_work().unwrap();
            let _ = b.do_work().unwrap();
        }
        assert!(
            pressed,
            "reliable {reliable}: never held ({accepted} accepted)"
        );
        assert!(
            accepted < 1024,
            "reliable {reliable}: {accepted} accepted while stalled"
        );
        // The subscriber reads: the window reopens and the publisher goes on.
        let held = accepted;
        pump(&mut [&mut a, &mut b], |_| {
            let _ = reader.poll(|_, _, _| {}, BUDGET);
            if offer(&mut lane) {
                accepted += 1;
            }
            accepted > held + 256
        });
    }
}

/// E4: a publication that goes silent retires its image at liveness; the
/// reader sees the image's seal, and the image is reclaimed once it drops.
#[test]
fn a_silent_publication_retires_its_image_at_liveness() {
    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Optional).unwrap();
    a.remove_aggregate(&publication).unwrap();
    let mut end = None;
    pump(&mut [&mut a, &mut b], |_| {
        let poll = reader.poll(|_, _, _| {}, BUDGET);
        end = poll.lanes.first().and_then(|lane| lane.end);
        end.is_some()
    });
    assert!(
        matches!(
            end,
            Some(LaneEnd::Closed {
                reason: SealReason::ImageRetired,
                ..
            })
        ),
        "{end:?}"
    );
    drop(reader);
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].net.as_ref().unwrap().image_count() == 0
    });
}

/// E4: closing a subscriber's network with an image installed is clean,
/// and a receiver panic on one driver leaves the other unaffected (DN-9).
#[test]
fn closing_and_failing_one_side_leaves_the_other_clean() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _ = connected(&mut a, &mut b, true, 10);
    let shutdown = b.close_network().unwrap();
    assert!(shutdown.agents_stopped);
    assert!(shutdown.failures.is_empty() && shutdown.late.is_empty());
    assert!(shutdown.endpoints_retired >= 1);
    for _ in 0..100 {
        let _ = a.do_work().unwrap();
    }
    let mut c = driver(ThreadingMode::Shared);
    let _ = connected(&mut a, &mut c, true, 11);
    c.net
        .as_ref()
        .unwrap()
        .links()
        .receiver
        .post(|_reply| crate::agents::AgentCommand::Panic)
        .unwrap();
    assert!(c.do_work().is_err());
    for _ in 0..100 {
        let _ = a.do_work().unwrap();
    }
    // A still serves: a fresh subscriber of a new publication reads it.
    let mut d = driver(ThreadingMode::Shared);
    let (publication, image) = connected(&mut a, &mut d, true, 12);
    let mut reader = d.subscribe_aggregate(&image, Role::Required).unwrap();
    exchange(&mut a, &mut d, &publication, &mut reader, 32);
}

/// E5: in steady state, a network cycle on either side allocates nothing.
#[test]
fn a_steady_network_cycle_allocates_nothing() {
    use karyos_sys::alloc_count::count;

    let ((), made) = count(|| drop(std::hint::black_box(vec![0_u8; 8])));
    assert!(made > 0, "the counting allocator counts in this binary");
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // Warm up: every buffer the path keeps is sized by real traffic.
    exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..128);
    // Then traffic keeps flowing while only the network cycles are counted:
    // the client's offers and polls, and the streams' duty, stay outside.
    let (mut sent, mut seen, mut work) = (128u32, 128u32, [0u64; 2]);
    for _ in 0..2_000 {
        while sent < 384 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        for (side, driver) in [&mut a, &mut b].into_iter().enumerate() {
            let ((units, error), made) = count(|| driver.serve_network());
            assert!(error.is_none());
            assert_eq!(made, 0, "side {side}: {units} units allocated");
            work[side] += u64::from(units);
        }
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
}

/// E2: a send fault that needs an endpoint reset, end to end: the sender
/// requests it (#270), the endpoint table resets and reopens the endpoint,
/// the reliable lane resends from its registered position, and the
/// subscriber gets every message exactly once, in order.
#[test]
fn an_endpoint_reset_loses_nothing_on_a_reliable_channel() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..64);
    // The subscriber holds: its consumption, and so the sender's
    // registered position, stays at 64 while 16 more are sent and
    // committed.
    let committed =
        |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().receiver_counters().unwrap();
    let before = committed(&b).data_committed;
    let mut sent = 64u32;
    pump(&mut [&mut a, &mut b], |drivers| {
        while sent < 80 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        committed(drivers[1]).data_committed >= before + 16
    });
    let dropped = committed(&b).data_dropped;
    let (endpoint, alias) = a
        .net
        .as_ref()
        .unwrap()
        .publication_route(publication.registration())
        .unwrap();
    a.net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
        .unwrap();
    // The reset reopens the endpoint and the reliable lane rewinds to its
    // registered position: what it already sent arrives again, and the
    // receiver drops those copies as duplicates.
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].net.as_ref().unwrap().reopened() >= 1
            && committed(drivers[1]).data_dropped > dropped
    });
    // The subscriber still reads every message exactly once, in order, and
    // traffic after the reset flows.
    exchange_from(&mut a, &mut b, &mut lane, &mut reader, sent, 64..320);
}

/// E3, Linux: one multicast publication reaches two subscribing drivers
/// on one group, each through its own image. Both sides use the default
/// interface, so the group's route decides; where the host has no
/// multicast route or cannot join (a minimal container network), the test
/// is skipped, and says so on the process's stderr, which the harness does
/// not capture, so the gate output shows it.
#[cfg(target_os = "linux")]
#[test]
fn a_multicast_publication_reaches_every_subscriber() {
    use std::io::Write as _;

    let skip = |why: &str| {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED a_multicast_publication_reaches_every_subscriber: {why}"
        );
    };
    // Probe the host with plain sockets first: only a host that cannot
    // carry loopback multicast skips; after a good probe, any driver
    // failure fails the test.
    if let Err(why) = multicast_probe() {
        skip(&why);
        return;
    }
    let port = free_address().port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 1)), port);
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b, mut c) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    for subscriber in [&mut b, &mut c] {
        let _ = subscriber.add_network_subscription(10, &channel).unwrap();
    }
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel)
        .unwrap();
    let mut images = (None, None);
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        images = (
            drivers[1].network_image(10, 3),
            drivers[2].network_image(10, 3),
        );
        images.0.is_some() && images.1.is_some()
    });
    let (Some(first), Some(second)) = images else {
        unreachable!("pumped until both exist");
    };
    let mut readers = [
        b.subscribe_aggregate(&first, Role::Required).unwrap(),
        c.subscribe_aggregate(&second, Role::Required).unwrap(),
    ];
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, [0u32; 2]);
    pump(&mut [&mut a, &mut b, &mut c], |_| {
        while sent < 128 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        for (reader, seen) in readers.iter_mut().zip(seen.iter_mut()) {
            let _ = reader.poll(
                |bytes, _, _| {
                    let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    assert_eq!(index, *seen, "in order, exactly once");
                    *seen += 1;
                },
                BUDGET,
            );
        }
        seen == [128, 128]
    });
}

/// Whether this host carries IPv4 multicast on its default route back to
/// itself: a group joined on one plain socket receives what another sends.
#[cfg(target_os = "linux")]
fn multicast_probe() -> Result<(), String> {
    let group = Ipv4Addr::new(239, 255, 0, 2);
    let receiver = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .map_err(|error| format!("probe bind: {error}"))?;
    receiver
        .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
        .map_err(|error| format!("probe join: {error}"))?;
    receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| format!("probe timeout: {error}"))?;
    let port = receiver
        .local_addr()
        .map_err(|error| format!("probe address: {error}"))?
        .port();
    let sender = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .map_err(|error| format!("probe sender: {error}"))?;
    sender
        .send_to(b"probe", SocketAddr::new(IpAddr::V4(group), port))
        .map_err(|error| format!("probe send: {error}"))?;
    let mut buffer = [0u8; 8];
    match receiver.recv(&mut buffer) {
        Ok(5) if &buffer[..5] == b"probe" => Ok(()),
        Ok(_) => Err("probe received something else".into()),
        Err(error) => Err(format!("no loopback multicast: {error}")),
    }
}

/// E1 on two lanes: each lane delivers its own messages in order, on both
/// channel kinds.
#[test]
fn two_lanes_deliver_in_order_on_either_kind() {
    for reliable in [true, false] {
        let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
        let address = free_address();
        let _ = b
            .add_network_subscription(10, &channel(address, reliable))
            .unwrap();
        let publication = a
            .add_network_publication(aggregate(10, 3, 2), &channel(address, reliable))
            .unwrap();
        let mut image = None;
        pump(&mut [&mut a, &mut b], |drivers| {
            image = drivers[1].network_image(10, 3);
            image.is_some()
        });
        let mut reader = b
            .subscribe_aggregate(&image.unwrap(), Role::Required)
            .unwrap();
        let mut lanes = [
            a.publication(publication.lane(Lane::ZERO).unwrap())
                .unwrap(),
            a.publication(publication.lane(Lane::try_new(1).unwrap()).unwrap())
                .unwrap(),
        ];
        let (mut sent, mut seen) = ([0u32; 2], [0u32; 2]);
        pump(&mut [&mut a, &mut b], |_| {
            for (lane, publication) in lanes.iter_mut().enumerate() {
                while sent[lane] < 96 {
                    let mut payload = [0u8; 1000];
                    payload[..4].copy_from_slice(&sent[lane].to_le_bytes());
                    match publication.offer(&payload).unwrap() {
                        OfferOutcome::Accepted { .. } => sent[lane] += 1,
                        _ => break,
                    }
                }
            }
            let _ = reader.poll(
                |bytes, lane, _| {
                    let lane = usize::from(lane.get());
                    let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    assert_eq!(index, seen[lane], "lane {lane} in order");
                    seen[lane] += 1;
                },
                BUDGET,
            );
            seen == [96, 96]
        });
    }
}

mod netem;
