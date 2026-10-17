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

/// MC-1: subscriptions sharing a receiver entry must agree on its
/// identity: another receiver id, another group tag, none where the first
/// has one, and one where the first has none are each refused, with the
/// endpoint released; the same identity shares the entry.
#[test]
fn a_subscription_with_another_identity_is_refused() {
    use crate::membership::ReceiverIdentity;

    let identity = |id: u64, group_tag: u64| ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(id).unwrap(),
        group_tag,
    };
    let mut b = driver(ThreadingMode::Shared);
    let address = free_address();
    let first = b
        .add_network_subscription_as(10, &channel(address), identity(77, 5))
        .unwrap();
    for other in [identity(78, 5), identity(77, 6)] {
        assert_eq!(
            b.add_network_subscription_as(10, &channel(address), other),
            Err(crate::DriverError::ReceiverIdentityMismatch)
        );
    }
    assert_eq!(
        b.add_network_subscription(10, &channel(address)),
        Err(crate::DriverError::ReceiverIdentityMismatch),
        "none where the first has one"
    );
    let second = b
        .add_network_subscription_as(10, &channel(address), identity(77, 5))
        .unwrap();
    // Another stream, derived identity: one where it has none is refused.
    let derived = b.add_network_subscription(11, &channel(address)).unwrap();
    assert_eq!(
        b.add_network_subscription_as(11, &channel(address), identity(77, 5)),
        Err(crate::DriverError::ReceiverIdentityMismatch)
    );
    for subscription in [first, second, derived] {
        assert!(b.remove_network_subscription(subscription).unwrap());
    }
}

/// C3: subscriptions sharing a receiver entry agree on its conflated
/// lane: another lane, none where the first has one, or one where the
/// first has none, is refused; the same lane shares the entry.
#[test]
fn a_subscription_with_another_conflated_lane_is_refused() {
    use karyos_sys::frame::Lane;

    const CONFIG: karyos_sys::conflation::ConflationConfig =
        karyos_sys::conflation::ConflationConfig {
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
        };
    let lane1 = Lane::try_new(1).unwrap();
    let mut b = driver(ThreadingMode::Shared);
    let address = free_address();
    let first = b
        .add_network_subscription_conflated(10, &channel(address), Lane::ZERO, CONFIG)
        .unwrap();
    assert_eq!(
        b.add_network_subscription_conflated(10, &channel(address), lane1, CONFIG),
        Err(crate::DriverError::ConflationMismatch)
    );
    assert_eq!(
        b.add_network_subscription(10, &channel(address)),
        Err(crate::DriverError::ConflationMismatch),
        "none where the first has one"
    );
    let other = karyos_sys::conflation::ConflationConfig {
        value_capacity: 16,
        ..CONFIG
    };
    assert_eq!(
        b.add_network_subscription_conflated(10, &channel(address), Lane::ZERO, other),
        Err(crate::DriverError::ConflationMismatch),
        "the same lane with another table"
    );
    let second = b
        .add_network_subscription_conflated(10, &channel(address), Lane::ZERO, CONFIG)
        .unwrap();
    let plain = b.add_network_subscription(11, &channel(address)).unwrap();
    assert_eq!(
        b.add_network_subscription_conflated(11, &channel(address), Lane::ZERO, CONFIG),
        Err(crate::DriverError::ConflationMismatch),
        "one where the first has none"
    );
    for subscription in [first, second, plain] {
        assert!(b.remove_network_subscription(subscription).unwrap());
    }
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
    use crate::error::DriverError;

    // The group ports are free when picked, but a parallel test can bind
    // one before the driver does: an endpoint that cannot bind is a fresh
    // attempt with fresh ports, never a failure.
    for _ in 0..8 {
        match control_group_attempt() {
            Ok(_) => return,
            Err(DriverError::NetworkEndpoint) => {}
            Err(error) => panic!("{error:?}"),
        }
    }
    panic!("no free group ports in 8 attempts");
}

/// One attempt of [`a_multicast_subscription_joins_its_control_group`]:
/// `Ok(false)` when the host cannot join the data group at all.
fn control_group_attempt() -> Result<bool, crate::error::DriverError> {
    use crate::error::DriverError;
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
    let reliable = match driver.add_network_subscription(6, &multicast(data_group, true)) {
        Ok(reliable) => reliable,
        Err(DriverError::NetworkEndpoint) => return Err(DriverError::NetworkEndpoint),
        Err(_) => return Ok(false),
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
    let unreliable = driver.add_network_subscription(7, &multicast(other_group, false))?;
    assert_eq!(driver.network_held_endpoints(), held + 1);
    assert_eq!(driver.network_control_join_failures(), failed);
    assert!(driver.remove_network_subscription(unreliable).unwrap());
    assert!(driver.remove_network_subscription(reliable).unwrap());
    assert_eq!(driver.network_held_endpoints(), before);
    Ok(true)
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
    if failed > 0 {
        // The later path cannot join here (macOS std sockets bind no two
        // sockets to one port, and loopback may refuse the membership):
        // only its failure was exercised.
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED the second path of a_subscription_holds_an_endpoint_per_path: its join failed on this host"
        );
        assert_eq!(driver.network_held_endpoints(), 1);
        assert!(driver.remove_network_subscription(subscription).unwrap());
        assert_eq!(driver.network_held_endpoints(), 0);
        return;
    }
    assert_eq!(driver.network_held_endpoints(), 2);
    assert!(driver.remove_network_subscription(subscription).unwrap());
    assert_eq!(driver.network_held_endpoints(), 0);
}

/// #304 with rp-w1: every path of a subscription with a configured
/// identity carries it, so the receiver entry of each later path names the
/// same identity as the first path's.
#[test]
fn every_path_of_a_subscription_carries_its_identity() {
    let identity = |id: u64, group_tag: u64| crate::membership::ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(id).unwrap(),
        group_tag,
    };
    let mut driver = driver(ThreadingMode::Shared);
    driver.net.as_mut().unwrap().assume_isolated_paths();
    let group = SocketAddr::from(([239, 7, 9, 3], free_port()));
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(LOOPBACK),
        ],
        ..channel(group)
    };
    // As above: a host without multicast has nothing to check.
    let Ok(subscription) = driver.add_network_subscription_as(6, &channel, identity(77, 5)) else {
        return;
    };
    for _ in 0..4 {
        let _ = driver.do_work().unwrap();
    }
    let identities = driver.net.as_ref().unwrap().path_identities(6);
    assert_eq!(identities.len(), driver.network_held_endpoints());
    assert!(!identities.is_empty());
    assert!(
        identities.iter().all(|held| *held == Some(identity(77, 5))),
        "{identities:?}"
    );
    assert!(driver.remove_network_subscription(subscription).unwrap());
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

/// #307 review P3: unicast with a single path is refused too.
#[test]
fn a_unicast_channel_with_one_path_is_refused() {
    let mut driver = driver(ThreadingMode::Shared);
    driver.net.as_mut().unwrap().assume_isolated_paths();
    let channel = UdpConfig {
        interface: None,
        paths: vec![Interface::Address(LOOPBACK)],
        ..channel(free_address())
    };
    assert_eq!(
        driver.add_network_subscription(6, &channel),
        Err(crate::error::DriverError::UnsupportedChannel)
    );
}

/// The multicast channel of `group` with `paths` (isolation assumed).
fn path_channel(group: SocketAddr, paths: Vec<Interface>) -> UdpConfig {
    UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths,
        ..channel(group)
    }
}

/// #307 review P2-4: a second handle of a key must ask for the same
/// paths; other paths would be dropped unseen, so they are refused and
/// counted.
#[test]
fn a_shared_key_with_other_paths_is_refused() {
    let mut driver = driver(ThreadingMode::Shared);
    driver.net.as_mut().unwrap().assume_isolated_paths();
    let group = SocketAddr::from(([239, 7, 9, 3], free_port()));
    let any = Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let Ok(_first) = driver.add_network_subscription(6, &path_channel(group, vec![any.clone()]))
    else {
        return;
    };
    let refused = driver.network_path_counters().0;
    assert_eq!(
        driver.add_network_subscription(
            6,
            &path_channel(group, vec![any.clone(), Interface::Address(LOOPBACK)])
        ),
        Err(crate::error::DriverError::UnsupportedChannel)
    );
    assert_eq!(driver.network_path_counters().0, refused + 1);
    // The same paths share the key.
    assert!(
        driver
            .add_network_subscription(6, &path_channel(group, vec![any]))
            .is_ok()
    );
}

/// A subscription table entry of `stream_id` on endpoint `first`, with
/// later paths on `later` (tests of the table's rules).
fn entry(first: u32, stream_id: i32, later: &[u32]) -> crate::net::NetSubscription {
    let mut paths = [None; crate::net::LATER_PATHS];
    for (slot, path) in paths.iter_mut().zip(later) {
        *slot = Some(crate::agents::EndpointId(*path));
    }
    crate::net::NetSubscription {
        endpoint: crate::agents::EndpointId(first),
        stream_id,
        reliable: true,
        control: None,
        later: paths,
        later_routes: [None; crate::net::LATER_PATHS],
        identity: None,
        conflated: None,
        users: 1,
    }
}

/// #307 review P2-2: an entry serves its stream on its first path and on
/// each later one, and nothing else.
#[test]
fn an_entry_serves_its_stream_on_every_path() {
    use crate::agents::EndpointId;

    let held = entry(1, 6, &[2, 3]);
    for endpoint in [1, 2, 3] {
        assert!(held.serves(EndpointId(endpoint), 6), "{endpoint}");
    }
    assert!(!held.serves(EndpointId(4), 6));
    assert!(!held.serves(EndpointId(2), 7));
    assert_eq!(held.entries(), Some(3));
}

/// #307 review P2-1: the mirror of the receiver's table counts each
/// path's entry: with room for 4, two subscriptions of 2 paths fill it,
/// and a third key is refused.
#[test]
fn the_mirror_counts_every_paths_entry() {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.subscriptions = 4;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let net = driver.net.as_mut().unwrap();
    net.subscriptions.push(entry(100, 6, &[101]));
    net.subscriptions.push(entry(102, 7, &[103]));
    assert_eq!(
        driver.add_network_subscription(8, &channel(free_address())),
        Err(crate::error::DriverError::NetworkSubscriptionsFull)
    );
}

/// #307 review P2-2: a first path on an endpoint another subscription of
/// the stream holds as a later path would share its receiver entry:
/// refused, and nothing is left held.
#[test]
fn a_first_path_never_shares_a_later_paths_entry() {
    let mut driver = driver(ThreadingMode::Shared);
    let address = free_address();
    // Open the endpoint as an ordinary subscription of another stream, then
    // make it a later path of stream 6 in the table.
    let other = driver
        .add_network_subscription(9, &channel(address))
        .unwrap();
    let endpoint = other.endpoint();
    let net = driver.net.as_mut().unwrap();
    net.subscriptions.push(entry(200, 6, &[endpoint.0]));
    let held = driver.network_held_endpoints();
    assert_eq!(
        driver.add_network_subscription(6, &channel(address)),
        Err(crate::error::DriverError::UnsupportedChannel)
    );
    assert_eq!(driver.network_held_endpoints(), held);
}

/// #312 review: a later path on the same endpoint as the subscription's
/// own first path (`paths=[any, any]`) would share its receiver entry: it
/// is skipped and counted, and only one endpoint is held.
#[test]
fn a_later_path_aliasing_the_first_is_skipped() {
    let mut driver = driver(ThreadingMode::Shared);
    driver.net.as_mut().unwrap().assume_isolated_paths();
    let group = SocketAddr::from(([239, 7, 9, 5], free_port()));
    let any = Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let Ok(_subscription) =
        driver.add_network_subscription(6, &path_channel(group, vec![any.clone(), any]))
    else {
        return;
    };
    assert_eq!(driver.network_path_counters().1, 1);
    assert_eq!(driver.network_held_endpoints(), 1);
}

/// #312 review: a new key's later paths count toward the mirror's room:
/// with one entry held and room for two, a key with a later path does not
/// fit, though its first path alone would.
#[test]
fn a_new_keys_later_paths_need_room() {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.subscriptions = 2;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    driver.net.as_mut().unwrap().assume_isolated_paths();
    driver
        .net
        .as_mut()
        .unwrap()
        .subscriptions
        .push(entry(300, 9, &[]));
    let group = SocketAddr::from(([239, 7, 9, 6], free_port()));
    let any = Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let refused = driver.add_network_subscription(
        6,
        &path_channel(group, vec![any, Interface::Address(LOOPBACK)]),
    );
    // A host that cannot join the first path refuses it earlier.
    if !matches!(refused, Err(crate::error::DriverError::NetworkEndpoint)) {
        assert_eq!(
            refused,
            Err(crate::error::DriverError::NetworkSubscriptionsFull)
        );
    }
}
