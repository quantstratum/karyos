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
    AggregateConfig, AggregateHandle, DriverConfig, EmbeddedDriver, StreamConfig, StreamTerms,
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
        sender_heartbeat_interval: 20 * MS,
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

/// A loopback address for a subscription to bind on any port: the kernel
/// picks it at the bind, and [`bound`] reads it back, so no other process
/// can take it in between.
const ANY_PORT: SocketAddr = SocketAddr::new(LOOPBACK, 0);

/// The address `driver`'s network subscription of `stream_id` is bound
/// to.
fn bound<T: StreamTerms>(driver: &EmbeddedDriver<T>, stream_id: i32) -> SocketAddr {
    driver.network_subscription_address(stream_id).unwrap()
}

/// A loopback socket nobody reads, for a publication with no receiver to
/// send to: held while the test runs, so no other process takes its port.
fn silent() -> UdpSocket {
    UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).unwrap()
}

/// A port for a multicast group, free a moment ago: a group's port is
/// named before any bind, so it cannot be read back from one.
fn free_port() -> u16 {
    silent().local_addr().unwrap().port()
}

/// Runs every driver until `done`, at most about four seconds.
fn pump<T: StreamTerms>(
    drivers: &mut [&mut EmbeddedDriver<T>],
    mut done: impl FnMut(&mut [&mut EmbeddedDriver<T>]) -> bool,
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
fn connected<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    reliable: bool,
    stream_id: i32,
) -> (AggregateHandle, AggregateHandle) {
    let _ = b
        .add_network_subscription(stream_id, &channel(ANY_PORT, reliable))
        .unwrap();
    let address = bound(b, stream_id);
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
fn exchange<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    publication: &AggregateHandle,
    reader: &mut AggregateSubscription<T>,
    count: u32,
) {
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    exchange_on(a, b, &mut lane, reader, 0..count);
}

/// [`exchange`] of the messages numbered `range` on `lane`.
fn exchange_on<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    lane: &mut karyos_client::ClientPublication<T>,
    reader: &mut AggregateSubscription<T>,
    range: core::ops::Range<u32>,
) {
    exchange_from(a, b, lane, reader, range.start, range);
}

/// [`exchange_on`] whose messages from `range.start` up to `sent` were
/// already offered.
fn exchange_from<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    lane: &mut karyos_client::ClientPublication<T>,
    reader: &mut AggregateSubscription<T>,
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
/// Its driver's network stops, which sends no EOS and lingers for nothing
/// (driver-network-agents.md §7); a removal would end it at its EOS.
#[test]
fn a_silent_publication_retires_its_image_at_liveness() {
    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let (_publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Optional).unwrap();
    let _ = a.close_network();
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
    let port = free_port();
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

/// SPEC §13 phase 2, alias collision, on one multicast group: two
/// publisher drivers use the same `session_id` and stream on one group.
/// The subscribing driver's receiver keeps two images, keyed by source
/// endpoint, and commits each source's frames into its own image: every
/// frame of both publishers commits and none is refused. The driver
/// exposes one aggregate per alias (interim D2, `add_image_aggregate`), so
/// one image is exposed and the other is driven unexposed; the exposed
/// one delivers only its own publisher's messages, every one, in order,
/// and nothing of the other publisher crosses into it. Linux, after the
/// loopback multicast probe, like `a_multicast_publication_reaches_every_subscriber`.
#[cfg(target_os = "linux")]
#[test]
fn colliding_aliases_on_one_multicast_group_keep_two_images_apart() {
    use std::io::Write as _;

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED colliding_aliases_on_one_multicast_group_keep_two_images_apart: {why}"
        );
        return;
    }
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 5)), free_port());
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a1, mut a2, mut b) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    let _ = b.add_network_subscription(10, &channel).unwrap();
    // The same stream and session on both: one alias, two sources.
    let publications = [
        a1.add_network_publication(aggregate(10, 3, 1), &channel)
            .unwrap(),
        a2.add_network_publication(aggregate(10, 3, 1), &channel)
            .unwrap(),
    ];
    // Two images installed: one exposed, the other driven unexposed.
    let mut image = None;
    pump(&mut [&mut a1, &mut a2, &mut b], |drivers| {
        image = drivers[2].network_image(10, 3);
        image.is_some() && drivers[2].network_images_unexposed() == 1
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lanes = [
        a1.publication(publications[0].lane(Lane::ZERO).unwrap())
            .unwrap(),
        a2.publication(publications[1].lane(Lane::ZERO).unwrap())
            .unwrap(),
    ];
    // Publisher p's message i is tagged (p, i).
    let count = 64u32;
    let mut sent = [0u32; 2];
    let mut seen: Vec<(u8, u32)> = Vec::new();
    let mut offer = |lanes: &mut [karyos_client::ClientPublication<HeapTerms>; 2]| {
        for (publisher, lane) in lanes.iter_mut().enumerate() {
            while sent[publisher] < count {
                let mut payload = [0u8; 1000];
                payload[0] = u8::try_from(publisher + 1).unwrap();
                payload[1..5].copy_from_slice(&sent[publisher].to_le_bytes());
                match lane.offer(&payload).unwrap() {
                    OfferOutcome::Accepted { .. } => sent[publisher] += 1,
                    _ => break,
                }
            }
        }
        sent
    };
    pump(&mut [&mut a1, &mut a2, &mut b], |drivers| {
        let sent = offer(&mut lanes);
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
                seen.push((bytes[0], index));
            },
            BUDGET,
        );
        // Every frame of both publishers is committed, each into its own
        // image (1000-byte messages are one frame each).
        let committed = drivers[2]
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .unwrap()
            .data_committed;
        sent == [count, count] && seen.len() >= 64 && committed >= 2 * u64::from(count)
    });
    // A while more: nothing else reaches the exposed image.
    for _ in 0..200 {
        let _ = a1.do_work().unwrap();
        let _ = a2.do_work().unwrap();
        let _ = b.do_work().unwrap();
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
                seen.push((bytes[0], index));
            },
            BUDGET,
        );
    }
    let owner = seen[0].0;
    let expected: Vec<(u8, u32)> = (0..count).map(|i| (owner, i)).collect();
    assert_eq!(
        seen, expected,
        "a frame of the other publisher crossed, or one was lost"
    );
    let counters = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(counters.create_image, 2, "{counters:?}");
    assert_eq!(counters.data_refused, 0, "{counters:?}");
}

/// MC-1, the "required receiver precedence" row: a live required
/// receiver bounds the sender under every strategy. On one multicast group
/// B (receiver 77) stalls its subscriber and C reads everything. Under
/// `max` with no required receiver, the sender follows C and is not held;
/// with B required it is held at B's window, under `max` and under a
/// `tagged` group that C alone is in: in every cycle its sent frontier
/// (`sent_high`) is at most B's position plus the window B advertises
/// (SPEC §13), and it is held only where one more maximum frame would
/// pass it. B's position is its image's join, since its subscriber never
/// reads. Two mechanisms hold the sender at that one point: the strategy
/// limit with B's precedence, and, on this unreliable channel too, the
/// retention of a joined required member, which keeps the log's registered
/// position at B's consumption so the publisher meets back pressure half
/// a term past it. B's window is also half a term, so this test cannot
/// tell them apart; `membership/tests.rs`
/// (`edges_are_checked_sums_and_required_members_bound_every_strategy`)
/// checks the limit alone. Linux, after the multicast probe.
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
        let port = free_port();
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
        // B's position plus its window: the stalled subscriber stays at
        // the image's join, and B advertises half a term (the receiver's
        // window rule, `agents/roles.rs`).
        let image_lane = b.stream_ref(stalled.lane(Lane::ZERO).unwrap()).unwrap();
        let config = image_lane.buffer.config();
        let PublicationMode::Image { join, .. } = config.publication else {
            panic!("{name}: not an image");
        };
        let window = (config.term_length.get() / 2).min(karyos_protocol::network::MAX_WINDOW)
            & !(karyos_sys::frame::FRAME_ALIGNMENT - 1);
        let bound = join + u64::from(window);
        let (mut accepted, mut delivered, mut sent) = (0u32, 0u32, 0u64);
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
            sent = shared(&mut a).sender.sent_high(0, 0).unwrap();
            if held {
                assert!(
                    sent <= bound,
                    "{name}: sent {sent} past B's position {join} plus its window {window}"
                );
            }
        }
        if held {
            assert!(
                accepted < 1024,
                "{name}: {accepted} accepted while B stalls"
            );
            // Held at B's window, not before it: a first send needs a whole
            // maximum frame to fit below the edge, and one more would pass
            // it.
            assert!(
                sent + u64::from(DEFAULT_MTU) > bound,
                "{name}: held at {sent}, short of B's bound {bound}"
            );
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
        let _ = b
            .add_network_subscription(10, &channel(ANY_PORT, reliable))
            .unwrap();
        let address = bound(&b, 10);
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
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 3)), free_port());
    let control = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 4)), free_port());
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

mod linger;

mod netem;

mod trace;

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
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
        .unwrap();
    let address = bound(&b, 10);
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
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
        .unwrap();
    let address = bound(&b, 10);
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
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
        .unwrap();
    let address = bound(&b, 10);
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

/// Subscribes B to a conflated view of `config` and connects A's one-lane
/// publication, pumping until B has its image.
fn conflated_pair(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    config: karyos_sys::conflation::ConflationConfig,
) -> (
    crate::embedded::AggregateHandle,
    crate::embedded::AggregateHandle,
    crate::net::NetworkSubscription,
) {
    let subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, config)
        .unwrap();
    let address = bound(b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [a, b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    (publication, image.unwrap(), subscription)
}

/// C4 follow-up: a view whose table cannot be built is counted with its
/// cause; the image is served without one.
#[test]
fn an_unbuildable_view_is_counted_with_its_cause() {
    use crate::net::ViewBuildFailure;
    use karyos_sys::conflation::ConflationError;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let config = karyos_sys::conflation::ConflationConfig { keys: 0, ..VIEW };
    let (_publication, image, _subscription) = conflated_pair(&mut a, &mut b, config);
    let views = b.network_view_counters();
    assert_eq!(
        (views.built, views.unbuilt_failed, views.unbuilt_unexposed),
        (0, 1, 0),
        "{views:?}"
    );
    assert_eq!(
        views.last_build_failure,
        Some(ViewBuildFailure::Table(ConflationError::InvalidConfig))
    );
    assert!(b.network_view_reader(&image, Lane::ZERO).is_none());
}

/// C4 follow-up: a gap the receiver seals before the view attaches (the
/// gate then seals as without a feeder) is met in the poll and recorded
/// there, so every key read so far is Stale since its start.
#[test]
fn a_gap_sealed_before_the_attach_stales_the_view() {
    use karyos_sys::freshness::Freshness;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    b.net.as_mut().unwrap().defer_view_attach();
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0] == Some((10, Freshness::Fresh))
    });
    b.net.as_mut().unwrap().drop_receiver_data(&[0]);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    offer_keyed(&mut a, &mut b, &mut lane, 2, 22);
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[2] == Some((22, Freshness::Fresh))
    });
    assert!(
        matches!(latest[0], Some((10, Freshness::Stale { .. }))),
        "{latest:?}"
    );
    b.attach_network_views();
    let views = b.network_view_counters();
    assert!(views.caught_up >= 1, "{views:?}");
    assert_eq!(views.acked, 0, "{views:?}");
}

/// C4 follow-up, driver-level BehindFrontier: a seal request below the
/// feeder's frontier publishes the terminal cell (reason below frontier)
/// and is never acknowledged.
#[test]
fn a_seal_request_below_the_frontier_closes_the_view() {
    use karyos_sys::freshness::{Freshness, TERMINAL_BELOW_FRONTIER};

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 11);
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[1] == Some((11, Freshness::Fresh))
    });
    let request = link.mailbox().unwrap().post(0, 1).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().closed_terminal == 1
    });
    assert!(!link.mailbox().unwrap().is_acknowledged(request));
    let terminal = karyos_sys::freshness::TerminalCell::read(&link.terminal_words()).unwrap();
    assert_eq!(terminal.reason, TERMINAL_BELOW_FRONTIER);
}

/// Reads `reader` while pumping both drivers until it delivered `count`
/// messages in all, checking that its lane stays open.
fn read_until(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    reader: &mut AggregateSubscription<HeapTerms>,
    read: &mut u32,
    count: u32,
) {
    pump(&mut [a, b], |_| {
        let poll = reader.poll(|_, _, _| *read += 1, BUDGET);
        assert!(
            poll.lanes.iter().all(|lane| lane.end.is_none()),
            "the image lane closed: {:?}",
            poll.lanes.first().and_then(|lane| lane.end)
        );
        *read >= count
    });
}

/// #330 review: exhausted versions close only the network view, with
/// reason 2 over every position; the image lane stays open, and another
/// subscriber of it still receives.
#[test]
fn an_exhausted_network_view_closes_alone() {
    use karyos_sys::freshness::{Freshness, TERMINAL_FRESHNESS_EXHAUSTED, TerminalCell};

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut other = b.subscribe_aggregate(&image, Role::Optional).unwrap();
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0] == Some((10, Freshness::Fresh))
    });
    // Key 1's next write exhausts its versions.
    b.seed_network_view_version(&image, Lane::ZERO, 1, u64::MAX - 1);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().closed_terminal == 1
    });
    let terminal = TerminalCell::read(&link.terminal_words()).unwrap();
    assert_eq!(
        (terminal.start, terminal.end, terminal.reason),
        (0, u64::MAX, TERMINAL_FRESHNESS_EXHAUSTED)
    );
    assert_eq!(
        b.seal_state(image.lane(Lane::ZERO).unwrap()).unwrap(),
        karyos_sys::log_buffer::SealState::Active,
        "the image lane is not sealed"
    );
    assert_eq!(b.network_view_counters().feeders_lost, 0);
    // The image lane goes on: a later message reaches the other reader.
    offer_keyed(&mut a, &mut b, &mut lane, 2, 22);
    let mut read = 0;
    read_until(&mut a, &mut b, &mut other, &mut read, 3);
}

/// #330 review: a feeder that cannot read on closes only its network view,
/// with reason 5 over every position, and is counted; the image lane stays
/// open, and another subscriber of it still receives.
#[test]
fn a_lost_feeder_closes_only_its_view() {
    use karyos_sys::freshness::{TERMINAL_FEEDER_LOST, TerminalCell};

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut other = b.subscribe_aggregate(&image, Role::Optional).unwrap();
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    b.fail_network_view_polls(&image, Lane::ZERO);
    pump(&mut [&mut a, &mut b], |drivers| {
        let views = drivers[1].network_view_counters();
        views.feeders_lost == 1 && views.closed_terminal == 1
    });
    let terminal = TerminalCell::read(&link.terminal_words()).unwrap();
    assert_eq!(
        (terminal.start, terminal.end, terminal.reason),
        (0, u64::MAX, TERMINAL_FEEDER_LOST)
    );
    assert_eq!(
        b.seal_state(image.lane(Lane::ZERO).unwrap()).unwrap(),
        karyos_sys::log_buffer::SealState::Active,
        "the image lane is not sealed"
    );
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    let mut read = 0;
    read_until(&mut a, &mut b, &mut other, &mut read, 2);
}

/// C4 follow-up, docs#119 (a): a retiring image closes its view with the
/// image-retired terminal reason, which the reader reports.
#[test]
fn a_retired_image_closes_its_view_as_retired() {
    use karyos_sys::freshness::TERMINAL_IMAGE_RETIRED;

    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    drop(lane);
    a.remove_aggregate(&publication).unwrap();
    let budget = karyos_sys::conflation::Budget {
        keys: 16,
        retries: 4,
    };
    let mut terminal = None;
    pump(&mut [&mut a, &mut b], |_| {
        terminal = reader.poll_changed(budget, |_, _, _, _| {}).terminal;
        terminal.is_some()
    });
    assert_eq!(terminal.map(|t| t.reason), Some(TERMINAL_IMAGE_RETIRED));
    let views = b.network_view_counters();
    assert_eq!(
        (views.closed_retired, views.closed_terminal),
        (1, 0),
        "{views:?}"
    );
}

/// Offers numbered messages on `lane` up to `until`, runs A and B once and
/// reads B's `reader`, checking order (T9).
#[cfg(target_os = "linux")]
fn offer_and_read(
    [a, b]: [&mut EmbeddedDriver; 2],
    lane: &mut karyos_client::ClientPublication<HeapTerms>,
    reader: &mut AggregateSubscription<HeapTerms>,
    (sent, seen): (&mut u32, &mut u32),
    until: u32,
) {
    while *sent < until {
        let mut payload = [0u8; 1000];
        payload[..4].copy_from_slice(&sent.to_le_bytes());
        match lane.offer(&payload).unwrap() {
            OfferOutcome::Accepted { .. } => *sent += 1,
            _ => break,
        }
    }
    let _ = a.do_work().unwrap();
    let _ = b.do_work().unwrap();
    let _ = reader.poll(
        |bytes, _, _| {
            let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            assert_eq!(index, *seen, "B in order, exactly once");
            *seen += 1;
        },
        BUDGET,
    );
}

/// T9 (contract-traceability-phase-2.md, "Retention floor"), end to end on
/// a reliable multicast publication with B required (receiver 77) and C
/// optional. While the sender holds NAKs back, C loses a datagram and the
/// sender, bound by B alone, sends `total` messages, B reading them all;
/// then NAKs flow. Returns C's closes `(unrecoverable, cannot_resume)`, and
/// with `repair_b`, checks that B's own hole above the floor is repaired.
/// `None` without multicast on this host.
#[cfg(target_os = "linux")]
fn optional_receiver_closes(total: u32, repair_b: bool) -> Option<(u64, u64)> {
    use std::io::Write as _;

    use crate::membership::{PublicationRoles, ReceiverIdentity, Strategy};

    if let Err(why) = multicast_probe() {
        let _ = writeln!(std::io::stderr(), "SKIPPED T9 retention floor: {why}");
        return None;
    }
    let port = free_port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 4)), port);
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
    let required = ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(77).unwrap(),
        group_tag: 0,
    };
    let _ = b
        .add_network_subscription_as(10, &channel, required)
        .unwrap();
    let _ = c.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication_with_roles(
            aggregate(10, 3, 1),
            &channel,
            PublicationRoles {
                strategy: Strategy::Max,
                required: vec![77],
                tags: Vec::new(),
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
    let (Some(on_b), Some(_on_c)) = images else {
        unreachable!("pumped until both exist");
    };
    let mut reader = b.subscribe_aggregate(&on_b, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // The sender holds NAKs back; C loses its third DATA datagram.
    a.net.as_mut().unwrap().sender_ignores_naks(true);
    c.net.as_mut().unwrap().drop_receiver_data(&[2]);
    let (mut sent, mut seen) = (0u32, 0u32);
    for _ in 0..40_000 {
        offer_and_read(
            [&mut a, &mut b],
            &mut lane,
            &mut reader,
            (&mut sent, &mut seen),
            total,
        );
        let _ = c.do_work().unwrap();
        if seen == total {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(seen, total, "B is required and reads everything");
    // NAKs flow again: C's hole is below the floor.
    a.net.as_mut().unwrap().sender_ignores_naks(false);
    let closes = |c: &EmbeddedDriver| {
        c.net.as_ref().unwrap().receiver_counters().map(|counters| {
            (
                counters.images_closed_unrecoverable,
                counters.images_closed_cannot_resume,
            )
        })
    };
    for _ in 0..40_000 {
        offer_and_read(
            [&mut a, &mut b],
            &mut lane,
            &mut reader,
            (&mut sent, &mut seen),
            total,
        );
        let _ = c.do_work().unwrap();
        if closes(&c).is_some_and(|(unrecoverable, cannot)| unrecoverable + cannot >= 1) {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let on_c = c.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(on_c.naks >= 1, "{on_c:?}");
    if repair_b {
        // The sender answered C's NAK below its floor (RANGE_UNAVAILABLE).
        let sender = a.net.as_ref().unwrap().sender_counters().unwrap();
        assert!(sender.naks >= 1 && sender.nak_replies >= 1, "{sender:?}");
        // A hole above the floor, B's, is repaired.
        b.net.as_mut().unwrap().drop_receiver_data(&[1]);
        let more = total + 8;
        for _ in 0..40_000 {
            offer_and_read(
                [&mut a, &mut b],
                &mut lane,
                &mut reader,
                (&mut sent, &mut seen),
                more,
            );
            if seen == more {
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        assert_eq!(seen, more, "B's lost datagram was repaired");
        let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
        assert!(receiver.naks >= 1, "{receiver:?}");
        assert_eq!(receiver.images_closed_unrecoverable, 0);
    }
    closes(&c)
}

/// T9: a term and a half, so the floor, bound by B alone, passes C's hole
/// but stays inside C's window `{r, r + 1}`. C's NAK below the floor is
/// answered RANGE_UNAVAILABLE and C's image closes as unrecoverable
/// (`on_unrecoverable = close`); B's own hole above the floor is repaired.
#[cfg(target_os = "linux")]
#[test]
fn an_optional_receivers_hole_below_the_floor_is_unrecoverable() {
    if let Some(closes) = optional_receiver_closes(MIN_TERM_LENGTH * 3 / 2 / 1000, true) {
        assert_eq!(closes, (1, 0), "C closed as unrecoverable");
    }
}

/// T9, the expected other outcome (GU-6): three terms, so the floor is
/// beyond C's window when its NAK flows. There is no far-window catch-up,
/// so C's image closes as GapCannotResume, not as unrecoverable.
#[cfg(target_os = "linux")]
#[test]
fn an_optional_receivers_hole_past_its_window_cannot_resume() {
    if let Some(closes) = optional_receiver_closes(3 * (MIN_TERM_LENGTH / 1000) + 8, false) {
        assert_eq!(closes, (0, 1), "C closed as GapCannotResume");
    }
}

/// rp-w4b2c: a publication over two paths reaches a subscription over the
/// same two paths, with the isolated-paths switch assumed on both drivers
/// (owner item 12 keeps it off on real sockets): every message once, in
/// order, though each path carries a copy. The second path is loopback,
/// which some hosts cannot carry multicast on; the founding path alone
/// then delivers, and the test still checks exactly-once order. Linux,
/// after the multicast probe.
#[cfg(target_os = "linux")]
#[test]
fn a_two_path_publication_reaches_a_two_path_subscription() {
    use std::io::Write as _;

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED a_two_path_publication_reaches_a_two_path_subscription: {why}"
        );
        return;
    }
    let port = free_port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 3)), port);
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ],
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    for side in [&mut a, &mut b] {
        side.net.as_mut().unwrap().assume_isolated_paths();
    }
    let _ = b.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 4, 1), &channel)
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 4);
        image.is_some()
    });
    let Some(image) = image else {
        unreachable!("pumped until it exists");
    };
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    pump(&mut [&mut a, &mut b], |_| {
        while sent < 128 {
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
        seen == 128
    });
    // Path 2 carries the stream too (#343 review): the receiver's SMs reach
    // the sender on path 2's endpoint, so path 2 is bound, published and
    // live end to end. A host whose loopback cannot join the group on path 2
    // exercises the founding path only, and says so.
    if b.network_path_counters().1 > 0 {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED path 2 of a_two_path_publication_reaches_a_two_path_subscription: its join failed on this host"
        );
        return;
    }
    let registration = publication.registration();
    pump(&mut [&mut a, &mut b], |drivers| {
        let bound = drivers[0]
            .net
            .as_ref()
            .unwrap()
            .publication_path_bindings(registration);
        bound.len() == 2 && bound.iter().all(|bound| *bound > 0)
    });
}

/// SPEC.md §15 "Guarded session abort", the trusted half
/// (guards-and-abort.md "Trusted sockets in Phase 2", O-11 and GC-6): a
/// guard close on a trusted socket channel is local. Messages written but
/// not sent before it never leave and are recorded `Aborted`; the sender
/// then sends nothing, no
/// DATA, repair, control, `SESSION_ABORT` or EOS; the close
/// acknowledgement names the last position submitted under the old epoch;
/// and the remote image ends at its liveness timeout with the messages
/// submitted before the close, and nothing after. A single-path sender
/// has no idle DATA heartbeat yet (gap G1), so none is checked here. The
/// reconnection half waits for a reopened network publication to bind a
/// fresh incarnation.
#[test]
fn a_guard_close_on_a_trusted_channel_ends_the_remote_image_at_liveness() {
    use karyos_sys::guard::Closed;
    use karyos_sys::outcome_ring::Kind;

    use crate::guard_ack::SenderAck;
    use crate::net::NetworkGuard;

    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let guard = a.add_guard("trusted").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, 1);
    // The sender's reservation and the guard's walker.
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_guarded_network_publication(
            config,
            &channel(address, true),
            NetworkGuard {
                guard,
                messages: 4,
                rate: None,
            },
        )
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Optional)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let message = |index: u32| {
        let mut payload = [0u8; 100];
        payload[..4].copy_from_slice(&index.to_le_bytes());
        payload
    };
    // Ten messages submitted and delivered under the open guard, each a
    // 160-byte frame.
    let mut kinds = Vec::new();
    let (mut sent, mut seen) = (0u32, 0u32);
    pump(&mut [&mut a, &mut b], |_| {
        let _ = lane
            .poll_outcomes(64, |_, record| kinds.push(record.kind))
            .unwrap();
        if sent < 10
            && matches!(
                lane.offer(&message(sent)).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = reader.poll(
            |bytes, _, _| {
                assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), seen);
                seen += 1;
            },
            BUDGET,
        );
        seen == 10 && kinds.len() == 10
    });
    assert!(
        kinds.iter().all(|kind| *kind == Kind::Submitted),
        "{kinds:?}"
    );
    // Three more written, then the close before any cycle runs: no gate
    // ever sees them open.
    for index in 10..13 {
        assert!(matches!(
            lane.offer(&message(index)).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    let Closed::Now { epoch } = a.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    assert_eq!(lane.offer(&message(13)).unwrap(), OfferOutcome::Gated);
    let mut ended = Vec::new();
    pump(&mut [&mut a, &mut b], |drivers| {
        let _ = lane
            .poll_outcomes(64, |_, record| ended.push((record.kind, record.reason)))
            .unwrap();
        drivers[0]
            .close_guard_ack(guard, epoch)
            .unwrap()
            .effective()
            == Some(true)
            && ended.last().is_some_and(|(kind, _)| *kind == Kind::Ended)
    });
    // The three never left: each is `Aborted` by the close, then `Ended`
    // (records from the sender gate's submissions, not at commit).
    let closed = (Kind::Aborted, crate::guard_streams::REASON_GUARD_CLOSED);
    assert_eq!(
        ended,
        [
            closed,
            closed,
            closed,
            (Kind::Ended, crate::guard_streams::REASON_GUARD_CLOSED)
        ]
    );
    let ack = a.close_guard_ack(guard, epoch).unwrap();
    let [(_, SenderAck::Applied { positions, .. })] = ack.senders[..] else {
        panic!("{ack:?}");
    };
    assert_eq!(positions[0], 10 * 160, "the last position submitted");
    // From here the sender is silent.
    let quiet = (
        shared(&mut a).sender.outbound_counters(0).unwrap(),
        shared(&mut a).sender.counters(),
    );
    let mut end = None;
    pump(&mut [&mut a, &mut b], |_| {
        let poll = reader.poll(|_, _, _| panic!("a message after the close"), BUDGET);
        end = poll.lanes.first().and_then(|lane| lane.end);
        end.is_some()
    });
    assert_eq!(
        end,
        Some(LaneEnd::Closed {
            position: 10 * 160,
            reason: SealReason::ImageRetired,
        })
    );
    drop(reader);
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].net.as_ref().unwrap().image_count() == 0
    });
    let (outbound, sender) = (
        shared(&mut a).sender.outbound_counters(0).unwrap(),
        shared(&mut a).sender.counters(),
    );
    assert_eq!(
        (outbound.staged, outbound.submitted, outbound.records),
        (quiet.0.staged, quiet.0.submitted, quiet.0.records),
        "no DATA after the close"
    );
    assert_eq!(sender.sent, quiet.1.sent, "no control after the close");
    assert_eq!((sender.eos_sent, sender.repairs), (0, 0));
    let received = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(received.data_committed, 10);
    assert_eq!(
        (received.images_retired, received.images_closed_eos),
        (1, 0),
        "ended at liveness, not by an EOS"
    );
}

/// #381 review P1: on a dedicated runner a receiver failure leaves the
/// sender's thread, and its gates, running. The driver must not end their
/// lanes: a message the sender submits after the failure is recorded
/// `Submitted`, never `Aborted`.
#[test]
fn a_receiver_failure_on_a_dedicated_runner_leaves_the_gates_deciding() {
    use karyos_sys::outcome_ring::Kind;

    use crate::net::NetworkGuard;

    let (mut a, mut b) = (
        driver(ThreadingMode::Dedicated),
        driver(ThreadingMode::Shared),
    );
    let guard = a.add_guard("dedicated").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, 1);
    // The sender's reservation and the guard's walker.
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_guarded_network_publication(
            config,
            &channel(address, true),
            NetworkGuard {
                guard,
                messages: 4,
                rate: None,
            },
        )
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Optional)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // Connected: two messages delivered and recorded.
    let (mut sent, mut seen, mut kinds) = (0u8, 0u32, Vec::new());
    pump(&mut [&mut a, &mut b], |_| {
        if sent < 2
            && matches!(
                lane.offer(&[sent; 100]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = lane
            .poll_outcomes(8, |_, record| kinds.push(record.kind))
            .unwrap();
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        seen == 2 && kinds.len() == 2
    });
    a.net
        .as_ref()
        .unwrap()
        .links()
        .receiver
        .post(|_reply| crate::agents::AgentCommand::Panic)
        .unwrap();
    let mut failed = false;
    for _ in 0..40_000 {
        if a.do_work().is_err() {
            failed = true;
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(failed, "the receiver failed");
    // Two more, after the failure: the sender's gate submits them.
    for _ in 0..40_000 {
        if sent < 4
            && matches!(
                lane.offer(&[sent; 100]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = a.do_work();
        let _ = b.do_work().unwrap();
        let _ = lane
            .poll_outcomes(8, |_, record| kinds.push(record.kind))
            .unwrap();
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        if kinds.len() == 4 && seen == 4 {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!((sent, seen), (4, 4), "sent after the failure");
    assert_eq!(kinds, [Kind::Submitted; 4]);
}

/// SPEC §6 (G1): a tail lost on the wire is revealed only by the idle
/// sender's heartbeat. The last three DATA datagrams of a reliable lane
/// are dropped at B's intake and the publisher goes idle: nothing else
/// shows the hole, so the heartbeat at the lane's next position raises
/// the image's mark, B NAKs the tail, the repair arrives, and every
/// message is delivered, in order, with the image still live.
#[test]
fn an_idle_heartbeat_reveals_a_lost_tail() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    // The next three DATA datagrams, the whole tail, are lost.
    b.net.as_mut().unwrap().drop_receiver_data(&[0, 1, 2]);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    for index in 0..3u32 {
        let mut payload = [0u8; 1000];
        payload[..4].copy_from_slice(&index.to_le_bytes());
        assert!(matches!(
            lane.offer(&payload).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    let mut seen = 0u32;
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == 3
    });
    let sender = a.net.as_ref().unwrap().sender_counters().unwrap();
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(sender.heartbeats_sent >= 1, "{sender:?}");
    assert!(receiver.naks >= 1, "{receiver:?}");
    assert!(b.network_image(10, 3).is_some(), "the image is still live");
}

/// G2: a publication whose `initial_term_id` is just below `u32::MAX`
/// (the test override) crosses the term id wrap: its messages arrive in
/// order across it.
#[test]
fn a_publication_crosses_the_term_id_wrap() {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.stream_defaults.initial_term_id = Some(u32::MAX - 1);
    let mut a = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let mut b = driver(ThreadingMode::Shared);
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let lane = a.stream_ref(publication.lane(Lane::ZERO).unwrap()).unwrap();
    assert_eq!(lane.config.initial_term_id.get(), u32::MAX - 1);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    // About four 64 KiB terms: term ids MAX - 1, MAX, 0 and 1.
    exchange(&mut a, &mut b, &publication, &mut reader, 256);
}
