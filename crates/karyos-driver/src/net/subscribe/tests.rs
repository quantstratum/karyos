// SPDX-License-Identifier: Apache-2.0

//! Two embedded drivers over loopback: one publishes on the network (W2),
//! the other subscribes and reads the image as a stream (W3).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use karyos_client::OfferOutcome;
use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use crate::agents::ThreadingMode;
use crate::embedded::{AggregateConfig, DriverConfig, EmbeddedDriver, StreamConfig};
use crate::net::NetworkConfig;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn driver(threading: ThreadingMode) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading,
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

fn channel(address: SocketAddr) -> UdpConfig {
    UdpConfig {
        destination: Destination::Unicast(address),
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// A loopback address with a port free a moment ago.
fn free_address() -> SocketAddr {
    UdpSocket::bind(SocketAddr::new(LOOPBACK, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Runs both drivers until `done`.
fn pump(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    mut done: impl FnMut(&mut EmbeddedDriver, &mut EmbeddedDriver) -> bool,
) {
    for _ in 0..20_000 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        if done(a, b) {
            return;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    panic!("not reached");
}

const BUDGET: Budget = Budget {
    work: 256,
    bytes: 1 << 22,
};

/// W3: a publication of driver A reaches a subscriber of driver B through
/// B's image, on both lanes, over more terms than one (so B drives the
/// image's term preparation), in order, in every threading mode.
#[test]
fn messages_reach_a_subscriber_of_the_image() {
    for mode in [ThreadingMode::Shared, ThreadingMode::Dedicated] {
        let mut a = driver(mode);
        let mut b = driver(mode);
        let address = free_address();
        let _subscription = b.add_network_subscription(10, &channel(address)).unwrap();
        let publication = a
            .add_network_publication(aggregate(10, 3, 2), &channel(address))
            .unwrap();
        let mut image = None;
        pump(&mut a, &mut b, |_, b| {
            image = b.network_image(10, 3);
            image.is_some()
        });
        let image = image.unwrap();
        let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
        let mut lanes = [
            a.publication(publication.lane(Lane::ZERO).unwrap())
                .unwrap(),
            a.publication(publication.lane(Lane::try_new(1).unwrap()).unwrap())
                .unwrap(),
        ];
        // About four 64 KiB terms on lane 0.
        let messages: u32 = 256;
        let mut sent = [0u32; 2];
        let mut seen = [0u32; 2];
        pump(&mut a, &mut b, |_, _| {
            for (lane, publication) in lanes.iter_mut().enumerate() {
                let count = if lane == 0 { messages } else { 16 };
                while sent[lane] < count {
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
                    assert_eq!(index, seen[lane], "{mode:?}: lane {lane} in order");
                    seen[lane] += 1;
                },
                BUDGET,
            );
            seen == [messages, 16]
        });
        drop(reader);
        drop(lanes);
        let _ = (a.close_network(), b.close_network());
    }
}

/// Removing the subscription retires its image: the image's streams are
/// sealed and leave, and the image table reclaims the image once its
/// subscriber is gone.
#[test]
fn a_removed_subscription_retires_and_reclaims_its_image() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let address = free_address();
    let subscription = b.add_network_subscription(10, &channel(address)).unwrap();
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    let mut image = None;
    pump(&mut a, &mut b, |_, b| {
        image = b.network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Optional)
        .unwrap();
    assert!(b.remove_network_subscription(subscription).unwrap());
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_none());
    // The subscriber sees the image's seal, not a local removal, and no
    // clean end.
    let mut ended = None;
    pump(&mut a, &mut b, |_, _| {
        let poll = reader.poll(|_, _, _| {}, BUDGET);
        ended = poll
            .terminal
            .zip(poll.lanes.first().and_then(|lane| lane.end));
        ended.is_some()
    });
    let (terminal, end) = ended.unwrap();
    assert!(
        matches!(
            end,
            karyos_client::aggregate::LaneEnd::Closed {
                reason: karyos_sys::log_buffer::SealReason::ImageRetired,
                ..
            }
        ),
        "{end:?}"
    );
    assert!(!terminal.clean);
    // The subscriber still holds the image's lanes: not reclaimed yet.
    for _ in 0..50 {
        let _ = b.do_work().unwrap();
    }
    assert_eq!(b.net.as_ref().unwrap().image_count(), 1);
    drop(reader);
    pump(&mut a, &mut b, |_, b| {
        b.net.as_ref().unwrap().image_count() == 0
    });
}

/// Interim keying (ACS 15937): a second image with an alias in use is not
/// exposed, and is counted; the first stays exposed.
#[test]
fn a_second_image_of_one_alias_is_counted_not_exposed() {
    let mut a = driver(ThreadingMode::Shared);
    let mut c = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let address = free_address();
    let subscription = b.add_network_subscription(10, &channel(address)).unwrap();
    let _first = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    let second = c
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |_, b| {
        let _ = c.do_work().unwrap();
        b.network_images_unexposed() == 1
    });
    assert!(b.network_image(10, 3).is_some());
    // The unexposed image is still fed past its first term: its terms are
    // prepared by the network, so the reliable publisher is never held.
    let mut lane = c.publication(second.lane(Lane::ZERO).unwrap()).unwrap();
    let mut accepted = 0u32;
    pump(&mut a, &mut b, |_, _| {
        let _ = c.do_work().unwrap();
        while accepted < 256 {
            match lane.offer(&[5u8; 1000]).unwrap() {
                OfferOutcome::Accepted { .. } => accepted += 1,
                _ => break,
            }
        }
        accepted == 256
    });
    // Removing the subscription retires both images; the unexposed one
    // drops its conductors, so both are reclaimed.
    assert!(b.remove_network_subscription(subscription).unwrap());
    pump(&mut a, &mut b, |_, b| {
        let _ = c.do_work().unwrap();
        b.net.as_ref().unwrap().image_count() == 0
    });
}

/// #283 P2: two subscriptions of one endpoint and stream share the
/// receiver's entry; removing one leaves the image, removing the last
/// retires it.
#[test]
fn subscriptions_of_one_key_are_counted() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let address = free_address();
    let first = b.add_network_subscription(10, &channel(address)).unwrap();
    let second = b.add_network_subscription(10, &channel(address)).unwrap();
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_some());
    assert!(b.remove_network_subscription(first).unwrap());
    for _ in 0..200 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
    }
    assert!(b.network_image(10, 3).is_some(), "the other still holds it");
    assert!(b.remove_network_subscription(second).unwrap());
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_none());
    assert!(!b.remove_network_subscription(second).unwrap(), "gone");
}

/// ACS 16071: a second subscription of one endpoint and stream with
/// another reliability is refused, not given the first's; the refusal
/// holds nothing, and once the first goes the other reliability is
/// accepted.
#[test]
fn a_subscription_with_another_reliability_is_refused() {
    let mut b = driver(ThreadingMode::Shared);
    let address = free_address();
    let reliable = channel(address);
    let unreliable = UdpConfig {
        reliable: false,
        ..channel(address)
    };
    let first = b.add_network_subscription(10, &reliable).unwrap();
    assert_eq!(
        b.add_network_subscription(10, &unreliable),
        Err(crate::DriverError::ReliabilityMismatch)
    );
    // The same reliability shares the entry.
    let second = b.add_network_subscription(10, &reliable).unwrap();
    assert!(b.remove_network_subscription(first).unwrap());
    assert!(b.remove_network_subscription(second).unwrap());
    // The endpoint retires over a few cycles; then it opens again.
    let mut added = false;
    for _ in 0..500 {
        let _ = b.do_work().unwrap();
        if b.add_network_subscription(10, &unreliable).is_ok() {
            added = true;
            break;
        }
    }
    assert!(
        added,
        "the other reliability is accepted once the first is gone"
    );
}

/// W5b B5: the conductor mirrors the receiver's subscription table, so a
/// new key beyond it is refused at once; a key already held still shares
/// its entry, and the receiver never refuses one the mirror admitted.
#[test]
fn the_receivers_subscription_table_is_mirrored() {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.subscriptions = 1;
    let mut b = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let address = free_address();
    let first = b.add_network_subscription(10, &channel(address)).unwrap();
    let shared = b.add_network_subscription(10, &channel(address)).unwrap();
    assert_eq!(
        b.add_network_subscription(11, &channel(address)),
        Err(crate::error::DriverError::NetworkSubscriptionsFull)
    );
    for _ in 0..50 {
        let _ = b.do_work().unwrap();
    }
    assert_eq!(b.network_subscription_refusals(), 0);
    // Removing every handle of the key frees its entry.
    assert!(b.remove_network_subscription(first).unwrap());
    assert!(b.remove_network_subscription(shared).unwrap());
    let _other = b.add_network_subscription(11, &channel(address)).unwrap();
    for _ in 0..50 {
        let _ = b.do_work().unwrap();
    }
    assert_eq!(b.network_subscription_refusals(), 0);
}

/// A free port, for a multicast group endpoint.
fn free_port() -> u16 {
    free_address().port()
}

/// RC-15 interim table (ACS 16103): an invalid control group table is
/// refused when the network starts.
#[test]
fn an_invalid_control_group_table_is_refused() {
    use crate::error::DriverError;
    use crate::net::{ControlGroup, MAX_CONTROL_GROUPS};

    let mut table = [None; MAX_CONTROL_GROUPS];
    table[0] = Some(ControlGroup {
        data_group: SocketAddr::from(([239, 7, 7, 1], 4000)),
        interface: None,
        control_group: SocketAddr::from(([10, 0, 0, 1], 4001)),
    });
    let refused = EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            nak_control_groups: table,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    });
    assert!(matches!(refused, Err(DriverError::InvalidConfig)));
}

/// RC-15: a reliable multicast subscription whose data group has a table
/// entry also holds an endpoint joined to the control group, or counts a
/// failed join and runs without peer input; it is accepted either way. An
/// unreliable one joins nothing, and removing the last handle releases
/// the control group endpoint.
#[test]
fn a_multicast_subscription_joins_its_control_group() {
    use crate::net::{ControlGroup, MAX_CONTROL_GROUPS};

    let data_group = SocketAddr::from(([239, 7, 7, 1], free_port()));
    let other_group = SocketAddr::from(([239, 7, 8, 1], free_port()));
    let mut table = [None; MAX_CONTROL_GROUPS];
    table[0] = Some(ControlGroup {
        data_group,
        interface: None,
        control_group: SocketAddr::from(([239, 7, 7, 2], free_port())),
    });
    table[1] = Some(ControlGroup {
        data_group: other_group,
        interface: None,
        control_group: SocketAddr::from(([239, 7, 8, 2], free_port())),
    });
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            nak_control_groups: table,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap();
    let multicast = |group, reliable| UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        reliable,
        ..channel(group)
    };
    let before = driver.network_held_endpoints();
    // A host without multicast on its default interface cannot join the
    // data group either: nothing to check there.
    let Ok(reliable) = driver.add_network_subscription(6, &multicast(data_group, true)) else {
        return;
    };
    let failed = driver.network_control_join_failures();
    let held = driver.network_held_endpoints();
    // The receiver's entry is multicast: its images time NAKs by cycle.
    for _ in 0..20 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(
        driver.net.as_ref().unwrap().receiver_multicast(reliable),
        Some(true)
    );
    assert_eq!(held, before + 2 - usize::try_from(failed).unwrap());
    // Its own data group, whose table entry it does not join.
    let unreliable = driver
        .add_network_subscription(7, &multicast(other_group, false))
        .unwrap();
    assert_eq!(driver.network_held_endpoints(), held + 1);
    assert_eq!(driver.network_control_join_failures(), failed);
    assert!(driver.remove_network_subscription(unreliable).unwrap());
    assert!(driver.remove_network_subscription(reliable).unwrap());
    assert_eq!(driver.network_held_endpoints(), before);
}

/// A unicast subscription's receiver entry is not multicast.
#[test]
fn a_unicast_subscription_is_not_multicast() {
    let mut driver = driver(ThreadingMode::Shared);
    let subscription = driver
        .add_network_subscription(9, &channel(free_address()))
        .unwrap();
    for _ in 0..20 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(
        driver
            .net
            .as_ref()
            .unwrap()
            .receiver_multicast(subscription),
        Some(false)
    );
}

/// Redundant paths (owner item 12): while the backend cannot isolate path
/// sockets, a channel with `paths` is refused and counted, and nothing is
/// held.
#[test]
fn a_channel_with_paths_is_refused_until_paths_are_isolated() {
    let mut driver = driver(ThreadingMode::Shared);
    let group = SocketAddr::from(([239, 7, 9, 1], free_port()));
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(LOOPBACK),
        ],
        ..channel(group)
    };
    assert_eq!(
        driver.add_network_subscription(6, &channel),
        Err(crate::error::DriverError::UnsupportedChannel)
    );
    assert_eq!(driver.network_path_counters(), (1, 0));
    assert_eq!(driver.network_held_endpoints(), 0);
}

/// rp-w1: with isolated paths (assumed here), a multicast subscription
/// with two paths holds one endpoint per path, each joined to the group on
/// its interface and with its own receiver entry; a path whose join fails
/// is counted and the subscription keeps the others. Removal releases
/// every path's endpoint.
#[test]
fn a_subscription_holds_an_endpoint_per_path() {
    let mut driver = driver(ThreadingMode::Shared);
    driver.net.as_mut().unwrap().assume_isolated_paths();
    let group = SocketAddr::from(([239, 7, 9, 2], free_port()));
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(LOOPBACK),
        ],
        ..channel(group)
    };
    // A host without multicast on its default interface cannot join the
    // first path either: nothing to check there.
    let Ok(subscription) = driver.add_network_subscription(6, &channel) else {
        return;
    };
    let (refused, failed) = driver.network_path_counters();
    assert_eq!(refused, 0);
    assert_eq!(
        driver.network_held_endpoints(),
        2 - usize::try_from(failed).unwrap()
    );
    assert!(driver.remove_network_subscription(subscription).unwrap());
    assert_eq!(driver.network_held_endpoints(), 0);
}

/// Unicast `paths` need a destination per path (owner item 11): refused.
#[test]
fn unicast_paths_are_refused() {
    let mut driver = driver(ThreadingMode::Shared);
    driver.net.as_mut().unwrap().assume_isolated_paths();
    let address = free_address();
    let channel = UdpConfig {
        interface: None,
        paths: vec![Interface::Address(LOOPBACK), Interface::Address(LOOPBACK)],
        ..channel(address)
    };
    assert_eq!(
        driver.add_network_subscription(6, &channel),
        Err(crate::error::DriverError::UnsupportedChannel)
    );
}

/// #294 tests: an unsubscription the receiver's full ring refuses waits,
/// and is posted once the ring has room, keeping its buffer.
#[test]
fn an_unsubscription_waits_for_room_in_the_ring() {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.command_capacity = 2;
    let mut b = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let address = free_address();
    // Its endpoint and its subscription fill the ring until the next
    // cycle.
    let first = b.add_network_subscription(10, &channel(address)).unwrap();
    let net = b.net.as_mut().unwrap();
    net.remove_subscription_later(first);
    assert_eq!(net.pending_unsubscribes(), 1, "the full ring refused it");
    let capacity = net.pending_unsubscribe_capacity();
    for _ in 0..50 {
        let _ = b.do_work().unwrap();
    }
    let net = b.net.as_ref().unwrap();
    assert_eq!(net.pending_unsubscribes(), 0);
    assert_eq!(
        net.pending_unsubscribe_capacity(),
        capacity,
        "the buffer is kept"
    );
    assert_eq!(net.subscription_count(), 0);
}
