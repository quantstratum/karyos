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

/// MC-1, the "required receiver precedence" row: a live required
/// receiver bounds the sender under every strategy. On one multicast group
/// B (receiver 77) stalls its subscriber and C reads everything. Under
/// `max` with no required receiver, the sender follows C and is not held;
/// with B required it is held at B's window, under `max` and under a
/// `tagged` group that C alone is in. The channel is unreliable, so only the
/// strategy limit bounds the sender (no retention hold). Linux, after the
/// multicast probe.
#[cfg(target_os = "linux")]
#[test]
fn a_required_receiver_bounds_every_strategy() {
    use std::io::Write as _;

    use crate::membership::{PublicationRoles, ReceiverIdentity, Strategy};

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED a_required_receiver_bounds_every_strategy: {why}"
        );
        return;
    }
    let identity = |id: u64, group_tag: u64| ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(id).unwrap(),
        group_tag,
    };
    let cases = [
        ("max", Strategy::Max, Vec::new(), Vec::new(), None, false),
        (
            "max, B required",
            Strategy::Max,
            vec![77],
            Vec::new(),
            None,
            true,
        ),
        (
            "tagged C, B required",
            Strategy::Tagged(9),
            vec![77],
            vec![(88, 9)],
            Some(identity(88, 9)),
            true,
        ),
    ];
    for (name, strategy, required, tags, c_identity, held) in cases {
        let port = free_address().port();
        let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 3)), port);
        let channel = UdpConfig {
            destination: Destination::Multicast { group, ttl: None },
            interface: None,
            paths: Vec::new(),
            reliable: false,
            flow_control: None,
            security: Security::Trusted,
        };
        let (mut a, mut b, mut c) = (
            driver(ThreadingMode::Shared),
            driver(ThreadingMode::Shared),
            driver(ThreadingMode::Shared),
        );
        let _ = b
            .add_network_subscription_as(10, &channel, identity(77, 0))
            .unwrap();
        let _ = match c_identity {
            Some(identity) => c.add_network_subscription_as(10, &channel, identity),
            None => c.add_network_subscription(10, &channel),
        }
        .unwrap();
        let publication = a
            .add_network_publication_with_roles(
                aggregate(10, 3, 1),
                &channel,
                PublicationRoles {
                    strategy,
                    required,
                    tags,
                },
            )
            .unwrap();
        let mut images = (None, None);
        pump(&mut [&mut a, &mut b, &mut c], |drivers| {
            images = (
                drivers[1].network_image(10, 3),
                drivers[2].network_image(10, 3),
            );
            images.0.is_some() && images.1.is_some()
        });
        let (Some(stalled), Some(fast)) = images else {
            unreachable!("pumped until both exist");
        };
        // B's subscriber never reads; C's reads everything.
        let _stalled = b.subscribe_aggregate(&stalled, Role::Required).unwrap();
        let mut reader = c.subscribe_aggregate(&fast, Role::Required).unwrap();
        let mut lane = a
            .publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap();
        let (mut accepted, mut delivered) = (0u32, 0u32);
        for _ in 0..4000 {
            if matches!(
                lane.offer(&[7u8; 1000]).unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                accepted += 1;
            }
            let _ = a.do_work().unwrap();
            let _ = b.do_work().unwrap();
            let _ = c.do_work().unwrap();
            let _ = reader.poll(|_, _, _| delivered += 1, BUDGET);
        }
        if held {
            assert!(
                accepted < 1024,
                "{name}: {accepted} accepted while B stalls"
            );
            // Held at B's window, not before any send: B joined as the
            // required receiver (one that never joins holds every first
            // send).
            assert!(delivered > 0, "{name}: nothing sent");
        } else {
            assert!(
                accepted >= 1024,
                "{name}: held at {accepted} with no required receiver"
            );
        }
    }
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

/// The shared agents of `driver`.
fn shared(
    driver: &mut EmbeddedDriver,
) -> &mut crate::agents::NetworkAgents<karyos_io::sockets::OsSocket> {
    match &mut driver.net.as_mut().unwrap().agents {
        super::Agents::Shared(agents) => agents,
        _ => panic!("not shared"),
    }
}

/// A driver clock that never moves.
#[derive(Debug)]
struct Frozen;

impl crate::clock::MonotonicClock for Frozen {
    fn now(&mut self) -> u64 {
        0
    }
}

/// The network keeps its own time base (`host_monotonic_ns`) in the
/// shared mode, whatever the driver's injectable clock says (here frozen
/// at 0). A NAK left unanswered is asked again one RTT after its
/// submission, which compares the NAK's start (the role clock) with the
/// cycle's `now`; an RTTM round trip yields a sample, which needs the
/// probe's issue, its start and the reply's arrival on one clock.
#[test]
fn the_network_keeps_its_own_clock() {
    let frozen = || {
        EmbeddedDriver::with_clock(
            DriverConfig {
                network: Some(NetworkConfig {
                    threading: ThreadingMode::Shared,
                    ..NetworkConfig::default()
                }),
                ..DriverConfig::default()
            },
            Box::new(Frozen),
        )
        .unwrap()
    };
    let (mut a, mut b) = (frozen(), frozen());
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // The second DATA datagram is lost, and the sender never repairs.
    shared(&mut b).receiver.drop_data(&[1]);
    shared(&mut a).sender.ignore_naks();
    let mut sent = 0u32;
    pump(&mut [&mut a, &mut b], |drivers| {
        while sent < 8
            && matches!(
                lane.offer(&[7u8; 1000]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = reader.poll(|_, _, _| {}, BUDGET);
        drivers[1]
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .is_some_and(|counters| counters.nak_retries >= 1 && counters.rttm_samples >= 1)
    });
}

/// mc-w2 in the shared mode with a frozen driver clock (ACS 16142): a
/// multicast image's cycles run on the network's own time base, so a hole
/// the sender never repairs is asked again cycle after cycle; each NAK's
/// copy reaches the other subscriber's control group, where it passes
/// validation. Linux only, after the loopback multicast probe, like
/// `a_multicast_publication_reaches_every_subscriber`.
#[cfg(target_os = "linux")]
#[test]
fn multicast_cycles_run_on_the_network_clock() {
    use std::io::Write as _;

    use crate::net::{ControlGroup, MAX_CONTROL_GROUPS};

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED multicast_cycles_run_on_the_network_clock: {why}"
        );
        return;
    }
    let group = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(239, 255, 0, 3)),
        free_address().port(),
    );
    let control = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(239, 255, 0, 4)),
        free_address().port(),
    );
    let mut table = [None; MAX_CONTROL_GROUPS];
    table[0] = Some(ControlGroup {
        data_group: group,
        interface: None,
        control_group: control,
    });
    let frozen = || {
        EmbeddedDriver::with_clock(
            DriverConfig {
                network: Some(NetworkConfig {
                    threading: ThreadingMode::Shared,
                    nak_control_groups: table,
                    ..NetworkConfig::default()
                }),
                ..DriverConfig::default()
            },
            Box::new(Frozen),
        )
        .unwrap()
    };
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b, mut c) = (frozen(), frozen(), frozen());
    for subscriber in [&mut b, &mut c] {
        let _ = subscriber.add_network_subscription(10, &channel).unwrap();
    }
    assert_eq!(b.network_control_join_failures(), 0);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel)
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some() && drivers[2].network_image(10, 3).is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // B loses the second DATA datagram; the sender never repairs.
    shared(&mut b).receiver.drop_data(&[1]);
    shared(&mut a).sender.ignore_naks();
    let mut sent = 0u32;
    let counters =
        |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().receiver_counters().unwrap();
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        while sent < 8
            && matches!(
                lane.offer(&[7u8; 1000]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = reader.poll(|_, _, _| {}, BUDGET);
        let (b, c) = (counters(&*drivers[1]), counters(&*drivers[2]));
        b.nak_cycles >= 2 && b.naks >= 2 && c.group_naks >= 1
    });
    let b = counters(&b);
    assert!(b.group_nak_copies >= 2, "{b:?}");
}

mod netem;

/// The table of the conflated views below: four keys of 16 bytes.
const VIEW: karyos_sys::conflation::ConflationConfig = karyos_sys::conflation::ConflationConfig {
    keys: 4,
    value_capacity: 16,
    journal_capacity: 1024,
};

/// Offers `value` under `key` on `lane`, pumping both drivers until it is
/// accepted.
fn offer_keyed(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    lane: &mut karyos_client::ClientPublication<HeapTerms>,
    key: i64,
    value: u8,
) {
    let options = karyos_sys::log_buffer::AppendOptions {
        reserved_value: key,
        ..karyos_sys::log_buffer::AppendOptions::default()
    };
    pump(&mut [a, b], |_| {
        matches!(
            lane.offer_with(&[value; 16], options).unwrap(),
            OfferOutcome::Accepted { .. }
        )
    });
}

/// Polls `reader` while pumping both drivers until `done` holds for the
/// latest `(value, freshness)` of each key.
fn view_until(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    reader: &mut karyos_sys::conflation::ConflationReader,
    latest: &mut [Option<(u8, karyos_sys::freshness::Freshness)>; 4],
    mut done: impl FnMut(&[Option<(u8, karyos_sys::freshness::Freshness)>; 4]) -> bool,
) {
    let budget = karyos_sys::conflation::Budget {
        keys: 16,
        retries: 4,
    };
    pump(&mut [a, b], |_| {
        let _ = reader.poll_changed(budget, |key, _, value, freshness| {
            latest[key as usize] = Some((value[0], freshness));
        });
        done(latest)
    });
}

/// C4 (conflated-network-images.md (a)): a conflated subscription's image
/// gets a view fed from its lane; its values read Fresh.
#[test]
fn a_conflated_network_view_reads_its_values_fresh() {
    use karyos_sys::freshness::Freshness;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let address = free_address();
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(address, false), Lane::ZERO, VIEW)
        .unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    assert_eq!(b.network_view_counters().built, 1);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    for key in 0..4 {
        offer_keyed(&mut a, &mut b, &mut lane, key, 10 + key as u8);
    }
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        (0..4).all(|key| latest[key] == Some((10 + key as u8, Freshness::Fresh)))
    });
}

/// C4, GU-9 end to end: on an unreliable channel a lost update makes every
/// key Stale since the gap's start once the receiver seals it, through the
/// view's mailbox (the feeder acknowledges after recording the loss); an
/// update past the gap restores its own key, Fresh.
#[test]
fn a_lost_update_stales_the_view_until_replaced() {
    use karyos_sys::freshness::Freshness;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let address = free_address();
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(address, false), Lane::ZERO, VIEW)
        .unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    for key in 0..4 {
        offer_keyed(&mut a, &mut b, &mut lane, key, 10 + key as u8);
    }
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest.iter().all(Option::is_some)
    });
    // The next DATA datagram, key 1's update, is lost; key 2's arrives.
    b.net.as_mut().unwrap().drop_receiver_data(&[0]);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    offer_keyed(&mut a, &mut b, &mut lane, 2, 22);
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0].is_some_and(|(_, freshness)| freshness != Freshness::Fresh)
            && latest[2] == Some((22, Freshness::Fresh))
    });
    let since = match latest[0] {
        Some((10, Freshness::Stale { since })) => since,
        other => panic!("{other:?}"),
    };
    assert_eq!(latest[1], Some((11, Freshness::Stale { since })));
    assert_eq!(latest[3], Some((13, Freshness::Stale { since })));
    // A replacement of key 1 past the gap is Fresh; key 0 stays Stale.
    offer_keyed(&mut a, &mut b, &mut lane, 1, 31);
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[1] == Some((31, Freshness::Fresh))
    });
    assert_eq!(latest[0], Some((10, Freshness::Stale { since })));
    let views = b.network_view_counters();
    assert!(views.acked >= 1, "{views:?}");
    let counters = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(
        counters.barrier_acks >= 1 && counters.gaps_sealed >= 1,
        "{counters:?}"
    );
    assert_eq!(counters.barrier_timeouts, 0);
}

/// C4, design (c): once the view's terminal cell is published (here by the
/// receive owner's side of the link), the conductor closes the feeder on
/// its next duty, and the reader delivers nothing more and reports it.
#[test]
fn a_published_terminal_cell_closes_the_network_view() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let address = free_address();
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(address, false), Lane::ZERO, VIEW)
        .unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    let terminal = karyos_sys::freshness::Terminal {
        start: 0,
        end: 64,
        reason: karyos_sys::freshness::TERMINAL_BARRIER_TIMEOUT,
    };
    assert!(link.terminal().unwrap().publish(terminal));
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().closed_terminal == 1
    });
    let budget = karyos_sys::conflation::Budget {
        keys: 16,
        retries: 4,
    };
    let mut delivered = 0;
    let report = reader.poll_changed(budget, |_, _, _, _| delivered += 1);
    assert_eq!((delivered, report.terminal), (0, Some(terminal)));
    assert!(
        b.network_view_link(&image, Lane::ZERO).is_none(),
        "feeder closed"
    );
}
