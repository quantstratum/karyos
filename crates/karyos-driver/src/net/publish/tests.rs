// SPDX-License-Identifier: Apache-2.0

//! Network publications: posted to the agents, announced, refused and
//! removed.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_protocol::network::{Control, Datagram, classify};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use crate::agents::ThreadingMode;
use crate::embedded::{
    AggregateConfig, AggregateHandle, DriverConfig, EmbeddedDriver, StreamConfig,
};
use crate::error::DriverError;
use crate::net::{NetworkConfig, NetworkPublicationState};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn driver() -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

fn aggregate(stream_id: i32, lanes: usize) -> AggregateConfig {
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
                session_id: 1,
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

fn channel(destination: Destination) -> UdpConfig {
    UdpConfig {
        destination,
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// A receiving socket on loopback that the test reads.
fn receiver() -> UdpSocket {
    let socket = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(1)))
        .unwrap();
    socket
}

/// Runs duty cycles until `done`.
fn until(driver: &mut EmbeddedDriver, mut done: impl FnMut(&mut EmbeddedDriver) -> bool) {
    for _ in 0..3000 {
        let _ = driver.do_work().unwrap();
        if done(driver) {
            return;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    panic!("not reached");
}

/// W2: a network publication reaches the sender agent, which takes it and
/// announces it to the channel destination with the aggregate's identity
/// and lanes.
#[test]
fn a_network_publication_is_announced_to_its_destination() {
    let mut driver = driver();
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let handle = driver
        .add_network_publication(aggregate(10, 2), &channel(destination))
        .unwrap();
    assert!(driver.network_publication_state(&handle).is_some());
    let mut buffer = [0u8; 2048];
    let mut announce = None;
    until(&mut driver, |_| {
        if let Ok(len) = socket.recv(&mut buffer)
            && let Ok(Datagram::Control(Control::SetupAnnounce(found))) = classify(&buffer[..len])
        {
            announce = Some(found);
        }
        announce.is_some()
    });
    let announce = announce.unwrap();
    assert_eq!(
        (announce.alias.stream_id, announce.alias.session_id),
        (10, 1)
    );
    assert_eq!(announce.identity.driver_id, driver.driver_id());
    assert_eq!(announce.term.mtu, DEFAULT_MTU);
    assert_eq!(
        driver.network_publication_state(&handle),
        Some(NetworkPublicationState::Active)
    );
}

/// Publications bound to one address share a send endpoint, and removing
/// them hands their data paths back and retires it once the last is gone.
#[test]
fn publications_share_and_release_a_send_endpoint() {
    let mut driver = driver();
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let first = driver
        .add_network_publication(aggregate(10, 1), &channel(destination.clone()))
        .unwrap();
    let second = driver
        .add_network_publication(aggregate(11, 1), &channel(destination))
        .unwrap();
    until(&mut driver, |driver| {
        [&first, &second].iter().all(|handle| {
            driver.network_publication_state(handle) == Some(NetworkPublicationState::Active)
        })
    });
    assert_eq!(driver.net.as_ref().unwrap().send_endpoints(), 1);
    driver.remove_aggregate(&first).unwrap();
    assert_eq!(
        driver.network_publication_state(&first),
        Some(NetworkPublicationState::Removing)
    );
    until(&mut driver, |driver| {
        driver.network_publication_state(&first).is_none()
    });
    assert_eq!(
        driver.net.as_ref().unwrap().send_endpoints(),
        1,
        "still held"
    );
    driver.remove_aggregate(&second).unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&second).is_none()
            && driver.net.as_ref().unwrap().send_endpoints() == 0
    });
}

/// What this step does not wire is refused before any stream exists, and a
/// driver without a network refuses every network publication.
#[test]
fn unsupported_channels_are_refused_before_any_stream() {
    let mut driver = driver();
    let multi = Destination::MultiDestination {
        destinations: vec![SocketAddr::new(LOOPBACK, 40_000)],
        control: None,
        mode: karyos_protocol::channel::ControlMode::Manual,
    };
    assert_eq!(
        driver.add_network_publication(aggregate(10, 1), &channel(multi)),
        Err(DriverError::UnsupportedChannel)
    );
    let mut named = channel(Destination::Unicast(SocketAddr::new(LOOPBACK, 40_000)));
    named.interface = Some(Interface::Name("lo".into()));
    assert_eq!(
        driver.add_network_publication(aggregate(10, 1), &named),
        Err(DriverError::UnsupportedChannel)
    );
    // Nothing was configured: the stream key is still free.
    assert!(driver.add_aggregate(aggregate(10, 1)).is_ok());
    let mut plain = EmbeddedDriver::new().unwrap();
    assert_eq!(
        plain.add_network_publication(
            aggregate(12, 1),
            &channel(Destination::Unicast(SocketAddr::new(LOOPBACK, 40_000)))
        ),
        Err(DriverError::NetworkUnavailable)
    );
}

/// A network publication cannot be reconfigured: its sender readers would
/// stay on the old mapping.
#[test]
fn a_network_publication_refuses_a_cutover() {
    let mut driver = driver();
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let handle = driver
        .add_network_publication(aggregate(10, 1), &channel(destination))
        .unwrap();
    let refused = driver.reconfigure_aggregate(
        &handle,
        crate::generations::Reconfiguration {
            term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
            spare_slots: 3,
        },
    );
    assert!(
        matches!(refused, Err(DriverError::NetworkCutover { stream: id }) if id == handle.registration()),
        "{refused:?}"
    );
}

/// The network publications and stale aliases held at once are bounded by
/// `AgentConfig::publications`: a publication beyond it is refused, and
/// removals never overflow the stale-alias queue.
#[test]
fn network_publications_are_bounded() {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.publications = 2;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let first = driver
        .add_network_publication(aggregate(10, 1), &channel(destination.clone()))
        .unwrap();
    let second = driver
        .add_network_publication(aggregate(11, 1), &channel(destination.clone()))
        .unwrap();
    assert_eq!(
        driver.add_network_publication(aggregate(12, 1), &channel(destination.clone())),
        Err(DriverError::NetworkPublicationsFull)
    );
    for handle in [&first, &second] {
        driver.remove_aggregate(handle).unwrap();
    }
    until(&mut driver, |driver| {
        [&first, &second]
            .iter()
            .all(|handle| driver.network_publication_state(handle).is_none())
    });
    assert_eq!(driver.net.as_ref().unwrap().stale_overflows(), 0);
    assert!(
        driver
            .add_network_publication(aggregate(13, 1), &channel(destination))
            .is_ok()
    );
}

/// #279 P1: a key whose old publication is still being removed is
/// refused, leaving nothing behind; once the old one is gone the key is
/// accepted, and the new publication is tracked and removed as any other.
/// The old streams stay until the sender's removal ends
/// (driver-network-agents.md §7), so the key is still held locally.
#[test]
fn a_key_still_being_removed_is_refused_until_it_is_gone() {
    let mut driver = driver();
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let other = driver
        .add_network_publication(aggregate(11, 1), &channel(destination.clone()))
        .unwrap();
    let old = driver
        .add_network_publication(aggregate(10, 1), &channel(destination.clone()))
        .unwrap();
    until(&mut driver, |driver| {
        [&other, &old].iter().all(|handle| {
            driver.network_publication_state(handle) == Some(NetworkPublicationState::Active)
        })
    });
    driver.remove_aggregate(&other).unwrap();
    driver.remove_aggregate(&old).unwrap();
    // The streams stay while the removal lingers: the key is held.
    driver.free_retired_streams();
    let users = driver.net.as_ref().unwrap().send_endpoint_users();
    assert!(matches!(
        driver.add_network_publication(aggregate(10, 1), &channel(destination.clone())),
        Err(DriverError::DuplicateStream { .. })
    ));
    assert_eq!(
        driver.net.as_ref().unwrap().send_endpoint_users(),
        users,
        "the refused attempt released its endpoint"
    );
    until(&mut driver, |driver| {
        driver.network_publication_state(&old).is_none()
            && driver.network_publication_state(&other).is_none()
    });
    // The removal ended: the next cycle frees the old streams.
    driver.free_retired_streams();
    let new = driver
        .add_network_publication(aggregate(10, 1), &channel(destination))
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&new) == Some(NetworkPublicationState::Active)
    });
    // A single-lane publication goes with its stream too.
    driver.remove_stream(new.lane(Lane::ZERO).unwrap()).unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&new).is_none()
            && driver.net.as_ref().unwrap().send_endpoints() == 0
    });
}

/// A publication the sender refuses (its table full) releases its endpoint
/// and leaves its alias stale, so the receiver forgets it; re-adding the
/// key before that removal is posted drops it from the queue.
#[test]
fn a_refused_publication_releases_its_endpoint_and_alias() {
    use karyos_protocol::network::{Alias, Identity, TermParams};

    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.publications = 2;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    // One entry of the sender's table the conductor does not track.
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let foreign = Alias {
        session_id: 99,
        stream_id: 99,
    };
    let endpoint = crate::agents::EndpointId(999);
    let (outbound, _log) = crate::agents::data::testing::outbound(
        endpoint,
        foreign,
        socket.local_addr().unwrap(),
        term,
        1,
        false,
    );
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|reply| crate::agents::AgentCommand::AddPublication {
            reply,
            publication: crate::sessions::send::Publication {
                endpoint,
                alias: foreign,
                identity: Identity {
                    driver_id: [0, 0],
                    registration_id: 999,
                    incarnation: 1,
                },
                term,
                lane_count: 1,
            },
            outbound,
            guard: None,
            roles: None,
        })
        .unwrap();
    let first = driver
        .add_network_publication(aggregate(10, 1), &channel(destination.clone()))
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&first) == Some(NetworkPublicationState::Active)
    });
    let refused = driver
        .add_network_publication(aggregate(11, 1), &channel(destination.clone()))
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&refused) == Some(NetworkPublicationState::Refused)
    });
    let net = driver.net.as_ref().unwrap();
    assert_eq!(
        net.send_endpoint_users(),
        1,
        "the refusal released its endpoint"
    );
    assert_eq!(net.stale_queued(), 1, "its alias is stale");
    // Re-adding the key before the stale alias is posted supersedes it.
    driver.remove_aggregate(&refused).unwrap();
    driver.free_retired_streams();
    assert_eq!(driver.network_publication_state(&refused), None);
    let again = driver
        .add_network_publication(aggregate(11, 1), &channel(destination))
        .unwrap();
    assert_eq!(driver.net.as_ref().unwrap().stale_queued(), 0);
    assert!(driver.network_publication_state(&again).is_some());
}

/// A guard named `name`, open at epoch 2.
fn open_guard(driver: &mut EmbeddedDriver, name: &str) -> crate::guards::GuardHandle {
    let guard = driver.add_guard(name).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1).unwrap(), 2);
    guard
}

/// A guarded network publication registers its sender gate with the
/// guard's owner: a close becomes effective at it once the sender applied
/// it, and its removal deregisters it.
#[test]
fn a_guarded_network_publication_takes_part_in_the_close_acknowledgement() {
    use karyos_sys::guard::Closed;

    use crate::net::NetworkGuard;

    let mut driver = driver();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    // Spare slots for the sender's reservation and the guard's walker.
    let mut config = aggregate(10, 2);
    config.stream.buffer.spare_slots = 4;
    let handle = driver
        .add_guarded_network_publication(
            config,
            &channel(destination),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        )
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    until(&mut driver, |driver| {
        driver.close_guard_ack(guard, epoch).unwrap().effective() == Some(true)
    });
    assert_eq!(
        driver.close_guard_ack(guard, epoch).unwrap().senders.len(),
        1
    );
    // Removed: its gate leaves the acknowledgement.
    driver.remove_aggregate(&handle).unwrap();
    until(&mut driver, |driver| {
        driver
            .close_guard_ack(guard, epoch)
            .unwrap()
            .senders
            .is_empty()
    });
}

/// A guard the lanes refuse leaves nothing configured: no aggregate, no
/// guard sender.
#[test]
fn a_refused_guard_leaves_nothing() {
    use karyos_sys::guard::Closed;

    use crate::net::NetworkGuard;

    let mut driver = driver();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let refused = driver.add_guarded_network_publication(
        aggregate(10, 1),
        &channel(destination.clone()),
        NetworkGuard {
            guard,
            messages: 0,
            rate: None,
        },
    );
    assert!(matches!(refused, Err(DriverError::InvalidConfig)));
    // The key is free again once the rolled-back streams are freed, and no
    // sender was registered.
    driver.free_retired_streams();
    let handle = driver
        .add_network_publication(aggregate(10, 1), &channel(destination))
        .unwrap();
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    assert!(
        driver
            .close_guard_ack(guard, epoch)
            .unwrap()
            .senders
            .is_empty()
    );
    driver.remove_aggregate(&handle).unwrap();
}

/// A guarded network publication needs a spare slot for its walker beyond
/// the sender's reservation: short of one, it says so.
#[test]
fn a_guarded_publication_short_of_spare_slots_says_so() {
    use crate::net::NetworkGuard;

    let mut driver = driver();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let refused = driver.add_guarded_network_publication(
        aggregate(10, 1),
        &channel(destination),
        NetworkGuard {
            guard,
            messages: 2,
            rate: None,
        },
    );
    assert!(matches!(
        refused,
        Err(DriverError::GuardWalkerUnavailable { .. })
    ));
}

/// A guarded publication refused after its guard sender was registered
/// (here, a full publication table) deregisters it: nothing waits on it.
#[test]
fn a_guarded_publication_refused_late_deregisters_its_sender() {
    use karyos_sys::guard::Closed;

    use crate::net::NetworkGuard;

    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.publications = 1;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let first = driver
        .add_network_publication(aggregate(10, 1), &channel(destination.clone()))
        .unwrap();
    let mut config = aggregate(11, 1);
    config.stream.buffer.spare_slots = 4;
    assert_eq!(
        driver
            .add_guarded_network_publication(
                config,
                &channel(destination),
                NetworkGuard {
                    guard,
                    messages: 2,
                    rate: None,
                },
            )
            .map(|_| ()),
        Err(DriverError::NetworkPublicationsFull)
    );
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    assert!(
        driver
            .close_guard_ack(guard, epoch)
            .unwrap()
            .senders
            .is_empty()
    );
    driver.remove_aggregate(&first).unwrap();
}

/// A guarded publication the sender refuses (its table is full) releases
/// its guard sender with its endpoint: nothing waits on it.
#[test]
fn a_guarded_publication_the_sender_refuses_releases_its_guard_sender() {
    use karyos_protocol::network::{Alias, Identity, TermParams};
    use karyos_sys::guard::Closed;

    use crate::net::NetworkGuard;

    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.publications = 1;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    // The sender's only entry, which the conductor does not track.
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let foreign = Alias {
        session_id: 99,
        stream_id: 99,
    };
    let endpoint = crate::agents::EndpointId(999);
    let (outbound, _log) = crate::agents::data::testing::outbound(
        endpoint,
        foreign,
        socket.local_addr().unwrap(),
        term,
        1,
        false,
    );
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|reply| crate::agents::AgentCommand::AddPublication {
            reply,
            publication: crate::sessions::send::Publication {
                endpoint,
                alias: foreign,
                identity: Identity {
                    driver_id: [0, 0],
                    registration_id: 999,
                    incarnation: 1,
                },
                term,
                lane_count: 1,
            },
            outbound,
            guard: None,
            roles: None,
        })
        .unwrap();
    let mut config = aggregate(11, 1);
    config.stream.buffer.spare_slots = 4;
    let refused = driver
        .add_guarded_network_publication(
            config,
            &channel(destination),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        )
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&refused) == Some(NetworkPublicationState::Refused)
    });
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    assert!(
        driver
            .close_guard_ack(guard, epoch)
            .unwrap()
            .senders
            .is_empty()
    );
}

/// A guarded publication of two lanes, with spare slots for the sender's
/// reservation and the walker.
fn guarded_pair(
    driver: &mut EmbeddedDriver,
    guard: crate::guards::GuardHandle,
    destination: Destination,
) -> Result<crate::embedded::AggregateHandle, DriverError> {
    let mut config = aggregate(10, 2);
    config.stream.buffer.spare_slots = 4;
    driver.add_guarded_network_publication(
        config,
        &channel(destination),
        crate::net::NetworkGuard {
            guard,
            messages: 2,
            rate: None,
        },
    )
}

/// #303 review P2: closing the network deregisters the guard sender of a
/// guarded publication it still tracks, so a guard close afterwards waits
/// on no sender.
#[test]
fn closing_the_network_releases_its_guard_senders() {
    use karyos_sys::guard::Closed;

    let mut driver = driver();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let handle = guarded_pair(&mut driver, guard, destination).unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    let shutdown = driver.close_network().unwrap();
    assert_eq!(shutdown.guard_senders_released, 1);
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    assert!(
        driver
            .close_guard_ack(guard, epoch)
            .unwrap()
            .senders
            .is_empty()
    );
}

/// #303 review P2: a failed agent (DN-9) never answers again, so the
/// guard senders of the publications it held are deregistered at once.
#[test]
fn a_failed_agent_releases_its_guard_senders() {
    use karyos_sys::guard::Closed;

    let mut driver = driver();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let handle = guarded_pair(&mut driver, guard, destination).unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::Panic)
        .unwrap();
    assert!(matches!(
        driver.do_work(),
        Err(DriverError::NetworkAgent { .. })
    ));
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    assert!(
        driver
            .close_guard_ack(guard, epoch)
            .unwrap()
            .senders
            .is_empty()
    );
    assert_eq!(driver.net.as_ref().unwrap().guard_release_counts(), (0, 0));
}

/// #303 review P3: a guard that lane 1 refuses after lane 0 was guarded
/// leaves nothing: both lanes' streams roll back with the aggregate (the
/// key is free again) and no guard sender was registered.
#[test]
fn a_partial_walker_failure_leaves_nothing() {
    use karyos_sys::guard::Closed;

    let mut driver = driver();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    driver.guard_lane_fault = Some(1);
    assert!(matches!(
        guarded_pair(&mut driver, guard, destination.clone()),
        Err(DriverError::GuardWalkerUnavailable { .. })
    ));
    driver.guard_lane_fault = None;
    driver.free_retired_streams();
    let handle = guarded_pair(&mut driver, guard, destination).unwrap();
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    assert_eq!(
        driver.close_guard_ack(guard, epoch).unwrap().senders.len(),
        1,
        "only the second publication's sender"
    );
    driver.remove_aggregate(&handle).unwrap();
}

/// rp-w4b2c: a channel with `paths` is refused, and counted, while the
/// sockets cannot be isolated per path (owner item 12), as subscriptions
/// are; nothing is held.
#[test]
fn a_publication_with_paths_is_refused_until_paths_are_isolated() {
    let mut driver = driver();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 7, 9, 21)), free_port());
    let channel = UdpConfig {
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(LOOPBACK),
        ],
        ..channel(Destination::Multicast { group, ttl: None })
    };
    assert_eq!(
        driver.add_network_publication(aggregate(10, 1), &channel),
        Err(DriverError::UnsupportedChannel)
    );
    assert_eq!(driver.network_path_counters(), (1, 0));
    assert_eq!(driver.net.as_ref().unwrap().send_endpoints(), 0);
    // Nothing was configured: the stream key is still free.
    assert!(driver.add_aggregate(aggregate(10, 1)).is_ok());
}

/// rp-w4b2c: with isolated paths (assumed here), a multicast publication
/// with two paths holds one send endpoint per path and becomes active; its
/// removal releases both. Unicast `paths` stay refused (owner item 11).
#[test]
fn a_publication_holds_a_send_endpoint_per_path() {
    let mut driver = driver();
    driver.net.as_mut().unwrap().assume_isolated_paths();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 7, 9, 22)), free_port());
    let paths = vec![
        Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Interface::Address(LOOPBACK),
    ];
    let routed = UdpConfig {
        interface: None,
        paths: paths.clone(),
        ..channel(Destination::Multicast { group, ttl: None })
    };
    let handle = driver
        .add_network_publication(aggregate(10, 1), &routed)
        .unwrap();
    assert_eq!(driver.net.as_ref().unwrap().send_endpoints(), 2);
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    driver.remove_aggregate(&handle).unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle).is_none()
            && driver.net.as_ref().unwrap().send_endpoints() == 0
    });
    let unicast = UdpConfig {
        interface: None,
        paths,
        ..channel(Destination::Unicast(SocketAddr::new(LOOPBACK, free_port())))
    };
    assert_eq!(
        driver.add_network_publication(aggregate(11, 1), &unicast),
        Err(DriverError::UnsupportedChannel)
    );
}

/// A port no socket holds now, for a group or destination of a test.
fn free_port() -> u16 {
    UdpSocket::bind(SocketAddr::new(LOOPBACK, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A driver whose agents hold `publications` sessions and `commands` ring
/// entries, with isolated paths assumed (rp-w4b2c follow-ups, #343 review).
fn paths_driver(publications: usize, commands: usize) -> EmbeddedDriver {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.publications = publications;
    network.agents.command_capacity = commands;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    driver.net.as_mut().unwrap().assume_isolated_paths();
    driver
}

/// A two-path multicast channel on a free group.
fn two_paths(last: u8) -> UdpConfig {
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 7, 9, last)), free_port());
    UdpConfig {
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(LOOPBACK),
        ],
        ..channel(Destination::Multicast { group, ttl: None })
    }
}

/// #343 review: each path's alias takes room in the network table, so a
/// two-path publication does not fit a table of one; nothing is held.
#[test]
fn a_two_path_publication_needs_room_for_each_path() {
    let mut driver = paths_driver(1, 64);
    assert_eq!(
        driver.add_network_publication(aggregate(10, 1), &two_paths(30)),
        Err(DriverError::NetworkPublicationsFull)
    );
    until(&mut driver, |driver| {
        driver.net.as_ref().unwrap().send_endpoints() == 0
    });
    assert!(driver.add_aggregate(aggregate(10, 1)).is_ok());
}

/// #343 review: a two-path publication the sender refuses (its session
/// table has room for one path only) releases both paths' endpoints and
/// leaves both aliases stale.
#[test]
fn a_refused_two_path_publication_releases_every_path() {
    use karyos_protocol::network::{Alias, Identity, TermParams};

    let mut driver = paths_driver(2, 64);
    // One session of the sender's table the conductor does not track.
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let foreign = Alias {
        session_id: 99,
        stream_id: 99,
    };
    let endpoint = crate::agents::EndpointId(999);
    let socket = receiver();
    let (outbound, _log) = crate::agents::data::testing::outbound(
        endpoint,
        foreign,
        socket.local_addr().unwrap(),
        term,
        1,
        false,
    );
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|reply| crate::agents::AgentCommand::AddPublication {
            reply,
            publication: crate::sessions::send::Publication {
                endpoint,
                alias: foreign,
                identity: Identity {
                    driver_id: [0, 0],
                    registration_id: 999,
                    incarnation: 1,
                },
                term,
                lane_count: 1,
            },
            outbound,
            guard: None,
            roles: None,
        })
        .unwrap();
    let refused = driver
        .add_network_publication(aggregate(10, 1), &two_paths(31))
        .unwrap();
    assert_eq!(driver.net.as_ref().unwrap().send_endpoints(), 2);
    until(&mut driver, |driver| {
        driver.network_publication_state(&refused) == Some(NetworkPublicationState::Refused)
            && driver.net.as_ref().unwrap().send_endpoints() == 0
    });
}

/// Opens the send endpoints of `channel`'s paths with a first publication
/// (stream 20), so a later one on the same binds posts no endpoint command;
/// then leaves `room` free entries in `link`'s ring.
fn leave_room(
    driver: &mut EmbeddedDriver,
    channel: &UdpConfig,
    receiver: bool,
    room: usize,
) -> AggregateHandle {
    let first = driver
        .add_network_publication(aggregate(20, 1), channel)
        .unwrap();
    until(driver, |driver| {
        driver.network_publication_state(&first) == Some(NetworkPublicationState::Active)
    });
    let ping = |driver: &EmbeddedDriver| {
        let links = driver.net.as_ref().unwrap().links();
        let link = if receiver {
            &links.receiver
        } else {
            &links.sender
        };
        link.ping(1).is_ok()
    };
    let mut capacity = 0usize;
    while ping(driver) {
        capacity += 1;
    }
    for _ in 0..20 {
        let _ = driver.do_work().unwrap();
    }
    for _ in 0..capacity - room {
        assert!(ping(driver));
    }
    first
}

/// #343 review: a failed post leaves nothing held. With room for one
/// receiver command, the second path's alias cannot be posted: the first
/// path's alias is queued stale, and the new publication holds nothing.
#[test]
fn a_failed_alias_post_stales_the_paths_already_published() {
    let mut driver = paths_driver(8, 64);
    let channel = two_paths(32);
    let _first = leave_room(&mut driver, &channel, true, 1);
    assert_eq!(
        driver.add_network_publication(aggregate(10, 1), &channel),
        Err(DriverError::NetworkBusy)
    );
    assert_eq!(driver.net.as_ref().unwrap().stale_queued(), 1);
}

/// #343 review: with the sender's ring full, the publication cannot be
/// posted: both paths' aliases are queued stale.
#[test]
fn a_failed_sender_post_stales_every_paths_alias() {
    let mut driver = paths_driver(8, 64);
    let channel = two_paths(33);
    let _first = leave_room(&mut driver, &channel, false, 0);
    assert_eq!(
        driver.add_network_publication(aggregate(10, 1), &channel),
        Err(DriverError::NetworkBusy)
    );
    assert_eq!(driver.net.as_ref().unwrap().stale_queued(), 2);
}

/// #343 review: every path's alias is published at the receiver while the
/// publication lives, and queued stale and removed with it.
#[test]
fn every_paths_alias_is_published_and_removed() {
    let mut driver = paths_driver(8, 64);
    let handle = driver
        .add_network_publication(aggregate(10, 1), &two_paths(34))
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    let net = driver.net.as_ref().unwrap();
    let paths = net.publication_paths(handle.registration());
    let (_, alias) = net.publication_route(handle.registration()).unwrap();
    assert_eq!(paths.len(), 2);
    assert!(
        paths
            .iter()
            .all(|path| net.receiver_published(*path, alias))
    );
    driver.remove_aggregate(&handle).unwrap();
    until(&mut driver, |driver| {
        let net = driver.net.as_ref().unwrap();
        driver.network_publication_state(&handle).is_none()
            && paths
                .iter()
                .all(|path| !net.receiver_published(*path, alias))
    });
}

/// A guarded network publication sealed by a guard close takes its fresh
/// incarnation after the reopen as a new publication identity on the wire,
/// every lane at once (guards-and-abort.md, On the network). The first
/// call removes the old session and refuses, typed and retryable, with the
/// quarantine's end; the old session is removed before anything is added;
/// once its alias's quarantine has passed, the next call swaps in every
/// lane and posts the sender again: a SETUP announces incarnation 2, and
/// its sender gate is registered again, so a later close waits on it.
#[test]
fn a_reopened_guarded_network_publication_takes_a_fresh_incarnation() {
    use karyos_sys::guard::Closed;
    use karyos_sys::log_buffer::SealReason;

    use crate::agents::AgentConfig;
    use crate::net::NetworkGuard;
    use crate::sessions::receive::SessionConfig;

    const QUARANTINE: u64 = 50_000_000;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            agents: AgentConfig {
                sessions: SessionConfig {
                    alias_quarantine: QUARANTINE,
                    ..SessionConfig::default()
                },
                ..AgentConfig::default()
            },
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let mut config = aggregate(10, 2);
    config.stream.buffer.spare_slots = 4;
    let handle = driver
        .add_guarded_network_publication(
            config,
            &channel(destination),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        )
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    let lanes = [Lane::ZERO, Lane::try_new(1).unwrap()].map(|lane| handle.lane(lane).unwrap());
    let publications = lanes.map(|lane| driver.publication(lane).unwrap());
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    // The sealed incarnation releases, and its seals are positioned.
    drop(publications);
    until(&mut driver, |driver| {
        lanes
            .iter()
            .all(|lane| driver.seal_reason(*lane) == Ok(Some(SealReason::GuardClosed)))
    });
    let epoch = driver.reopen_guard(guard, epoch, epoch).unwrap();
    // The first call past the seal positioning starts the removal and
    // refuses with the quarantine's estimated end.
    let mut first = None;
    until(&mut driver, |driver| match driver.publication(lanes[1]) {
        Err(DriverError::GuardSealed { .. }) => false,
        other => {
            first = Some(other.map(drop));
            true
        }
    });
    let started = driver.net.as_ref().unwrap().now();
    let Some(Err(DriverError::QuarantinedAlias { stream, until_ns })) = first else {
        panic!("{first:?}");
    };
    assert_eq!(stream, handle.registration() + 1);
    assert!(
        until_ns >= started && until_ns - started <= QUARANTINE,
        "{until_ns}"
    );
    assert_eq!(
        driver.network_publication_state(&handle),
        Some(NetworkPublicationState::Reincarnating)
    );
    // Nothing is swapped yet, on either lane.
    for lane in lanes {
        assert_eq!(driver.trace_identity(lane).unwrap().incarnation, 1);
    }
    // Refused, with the same error on the other lane, until the quarantine
    // from the old session's removal has passed.
    let mut refusals = 0u32;
    let mut taken = None;
    until(&mut driver, |driver| match driver.publication(lanes[0]) {
        Err(DriverError::QuarantinedAlias { .. }) => {
            refusals += 1;
            false
        }
        other => {
            taken = Some(other);
            true
        }
    });
    let taken = taken.unwrap().unwrap();
    assert!(refusals > 0);
    assert!(driver.net.as_ref().unwrap().now() - started >= QUARANTINE);
    for lane in lanes {
        assert_eq!(driver.trace_identity(lane).unwrap().incarnation, 2);
    }
    // The other lane is taken on the same incarnation, with no refusal.
    let other = driver.publication(lanes[1]).unwrap();
    // A SETUP announces the new incarnation, under the same alias.
    let mut buffer = [0u8; 2048];
    let mut announce = None;
    until(&mut driver, |_| {
        if let Ok(len) = socket.recv(&mut buffer)
            && let Ok(Datagram::Control(Control::SetupAnnounce(found))) = classify(&buffer[..len])
            && found.identity.incarnation == 2
        {
            announce = Some(found);
        }
        announce.is_some()
    });
    let announce = announce.unwrap();
    assert_eq!(
        (announce.alias.stream_id, announce.alias.session_id),
        (10, 1)
    );
    assert_eq!(announce.identity.registration_id, handle.registration());
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    // The new incarnation's sender gate takes part in the next close.
    drop((taken, other));
    let Closed::Now { epoch } = driver.close_guard(guard, epoch).unwrap() else {
        panic!("not closed");
    };
    until(&mut driver, |driver| {
        driver.close_guard_ack(guard, epoch).unwrap().effective() == Some(true)
    });
    assert_eq!(
        driver.close_guard_ack(guard, epoch).unwrap().senders.len(),
        1
    );
}

/// A driver whose aliases are quarantined for `quarantine` ns and whose
/// sender holds at most `publications`.
fn reincarnating_driver(quarantine: u64, publications: usize) -> EmbeddedDriver {
    use crate::agents::AgentConfig;
    use crate::sessions::receive::SessionConfig;

    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            agents: AgentConfig {
                publications,
                sessions: SessionConfig {
                    alias_quarantine: quarantine,
                    ..SessionConfig::default()
                },
                ..AgentConfig::default()
            },
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// A guarded one-lane network publication on `driver`, closed by its
/// guard, reopened, and refused once with `QuarantinedAlias` (its old
/// session's removal posted): its handle, guard, open epoch, lane and
/// receiving socket.
fn waiting_reincarnation(
    driver: &mut EmbeddedDriver,
) -> (
    AggregateHandle,
    crate::guards::GuardHandle,
    u64,
    crate::embedded::StreamHandle,
    UdpSocket,
) {
    use karyos_sys::guard::Closed;
    use karyos_sys::log_buffer::SealReason;

    use crate::net::NetworkGuard;

    let guard = open_guard(driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let mut config = aggregate(10, 1);
    config.stream.buffer.spare_slots = 4;
    let handle = driver
        .add_guarded_network_publication(
            config,
            &channel(destination),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        )
        .unwrap();
    until(driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    let lane = handle.lane(Lane::ZERO).unwrap();
    let publication = driver.publication(lane).unwrap();
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    drop(publication);
    until(driver, |driver| {
        driver.seal_reason(lane) == Ok(Some(SealReason::GuardClosed))
    });
    let epoch = driver.reopen_guard(guard, epoch, epoch).unwrap();
    let mut first = None;
    until(driver, |driver| match driver.publication(lane) {
        Err(DriverError::GuardSealed { .. }) => false,
        other => {
            first = Some(other.map(drop));
            true
        }
    });
    assert!(
        matches!(first, Some(Err(DriverError::QuarantinedAlias { .. }))),
        "{first:?}"
    );
    (handle, guard, epoch, lane, socket)
}

/// #396 review P2: a network close while the reincarnation waits adds no
/// sender, so the lane is refused, typed, and stays sealed at its first
/// incarnation: no offer is accepted that no sender reads.
#[test]
fn a_network_close_mid_reincarnation_leaves_the_lane_sealed() {
    use karyos_sys::log_buffer::SealReason;

    let mut driver = reincarnating_driver(50_000_000, 64);
    let (_handle, _guard, _epoch, lane, _socket) = waiting_reincarnation(&mut driver);
    let _ = driver.close_network().unwrap();
    std::thread::sleep(Duration::from_millis(60));
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
        assert_eq!(
            driver.publication(lane).map(drop),
            Err(DriverError::NetworkUnavailable)
        );
    }
    assert_eq!(driver.trace_identity(lane).unwrap().incarnation, 1);
    assert_eq!(driver.seal_reason(lane), Ok(Some(SealReason::GuardClosed)));
}

/// #396 review P2: an agent failure while the reincarnation waits adds no
/// sender either: the lane is refused with the failure and stays sealed.
#[test]
fn an_agent_failure_mid_reincarnation_leaves_the_lane_sealed() {
    use karyos_sys::log_buffer::SealReason;

    let mut driver = reincarnating_driver(50_000_000, 64);
    let (_handle, _guard, _epoch, lane, _socket) = waiting_reincarnation(&mut driver);
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::Panic)
        .unwrap();
    assert!(matches!(
        driver.do_work(),
        Err(DriverError::NetworkAgent { .. })
    ));
    std::thread::sleep(Duration::from_millis(60));
    for _ in 0..3 {
        let _ = driver.do_work();
        assert!(
            matches!(
                driver.publication(lane),
                Err(DriverError::NetworkAgent { .. })
            ),
            "refused with the failure"
        );
    }
    assert_eq!(driver.trace_identity(lane).unwrap().incarnation, 1);
    assert_eq!(driver.seal_reason(lane), Ok(Some(SealReason::GuardClosed)));
}

/// A reincarnation past its quarantine whose lanes are swapped
/// (`AwaitingSender`) and whose sender add was refused: the receiver's
/// ring is full, so its alias cannot be published.
fn awaiting_sender(
    driver: &mut EmbeddedDriver,
) -> (AggregateHandle, crate::embedded::StreamHandle, UdpSocket) {
    let (handle, _guard, _epoch, lane, socket) = waiting_reincarnation(driver);
    until(driver, |driver| {
        matches!(
            driver
                .net
                .as_ref()
                .unwrap()
                .reincarnation(handle.registration()),
            Ok(Some(crate::net::ReincarnationPhase::Ready {
                swapped: false
            }))
        )
    });
    while driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .receiver
        .ping(1)
        .is_ok()
    {}
    assert_eq!(
        driver.publication(lane).map(drop),
        Err(DriverError::NetworkBusy)
    );
    assert_eq!(
        driver.stream_ref(lane).unwrap().network,
        crate::embedded::NetworkLane::AwaitingSender
    );
    assert_eq!(driver.trace_identity(lane).unwrap().incarnation, 2);
    (handle, lane, socket)
}

/// #396 review P2: a lane swapped to its next incarnation whose sender
/// add was refused stays refused once the network closed: no handle, so
/// no offer is accepted and no record written for a sender that will
/// never read it.
#[test]
fn an_awaiting_sender_lane_is_refused_once_the_network_closed() {
    let mut driver = reincarnating_driver(20_000_000, 64);
    let (_handle, lane, _socket) = awaiting_sender(&mut driver);
    let _ = driver.close_network().unwrap();
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
        assert_eq!(
            driver.publication(lane).map(drop),
            Err(DriverError::NetworkUnavailable)
        );
    }
}

/// #396 re-check P2: an agent failure after the swap ends the
/// reincarnation's record, so only the failed network refuses the lane,
/// with the failure.
#[test]
fn an_awaiting_sender_lane_is_refused_once_an_agent_failed() {
    let mut driver = reincarnating_driver(20_000_000, 64);
    let (_handle, lane, _socket) = awaiting_sender(&mut driver);
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::Panic)
        .unwrap();
    assert!(matches!(
        driver.do_work(),
        Err(DriverError::NetworkAgent { .. })
    ));
    for _ in 0..3 {
        let _ = driver.do_work();
        let taken = driver.publication(lane).map(drop);
        assert!(
            matches!(taken, Err(DriverError::NetworkAgent { .. })),
            "{taken:?}"
        );
    }
}

/// #396 re-check: a refused add after the swap is posted again by a later
/// call once the ring has room, and the lane is sending.
#[test]
fn a_refused_add_after_the_swap_is_retried() {
    let mut driver = reincarnating_driver(20_000_000, 64);
    let (handle, lane, _socket) = awaiting_sender(&mut driver);
    let mut taken = None;
    until(&mut driver, |driver| match driver.publication(lane) {
        Err(DriverError::NetworkBusy) => false,
        other => {
            taken = Some(other.map(drop));
            true
        }
    });
    assert_eq!(taken, Some(Ok(())));
    assert_eq!(
        driver.stream_ref(lane).unwrap().network,
        crate::embedded::NetworkLane::Sending
    );
    let net = driver.net.as_ref().unwrap();
    assert!(net.reincarnation(handle.registration()).unwrap().is_none());
}

/// #396 re-check: a closed or failed network refuses only lanes that
/// would reincarnate: a network lane its guard never sealed still issues.
#[test]
fn a_live_network_lane_still_issues_after_a_close_or_a_failure() {
    for fail in [false, true] {
        let mut driver = reincarnating_driver(20_000_000, 64);
        let socket = receiver();
        let destination = Destination::Unicast(socket.local_addr().unwrap());
        let handle = driver
            .add_network_publication(aggregate(10, 1), &channel(destination))
            .unwrap();
        until(&mut driver, |driver| {
            driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
        });
        if fail {
            driver
                .net
                .as_ref()
                .unwrap()
                .links()
                .sender
                .post(|_reply| crate::agents::AgentCommand::Panic)
                .unwrap();
            assert!(driver.do_work().is_err());
        } else {
            let _ = driver.close_network().unwrap();
        }
        let lane = handle.lane(Lane::ZERO).unwrap();
        assert_eq!(driver.publication(lane).map(drop), Ok(()), "{fail}");
    }
}

/// #396 re-check: a reincarnation's record and its extra endpoint hold
/// end with the publication's removal, an agent failure or a close in
/// the middle of the wait.
#[test]
fn a_reincarnation_ends_with_a_removal_a_failure_or_a_close() {
    for how in 0..3 {
        let mut driver = reincarnating_driver(10_000_000_000, 64);
        let (handle, _guard, _epoch, _lane, _socket) = waiting_reincarnation(&mut driver);
        let registration = handle.registration();
        let net = driver.net.as_ref().unwrap();
        assert!(net.reincarnation(registration).unwrap().is_some());
        match how {
            0 => {
                driver.remove_aggregate(&handle).unwrap();
                let net = driver.net.as_ref().unwrap();
                assert!(net.reincarnation(registration).unwrap().is_none());
                until(&mut driver, |driver| {
                    driver.net.as_ref().unwrap().send_endpoints() == 0
                });
            }
            1 => {
                driver
                    .net
                    .as_ref()
                    .unwrap()
                    .links()
                    .sender
                    .post(|_reply| crate::agents::AgentCommand::Panic)
                    .unwrap();
                assert!(driver.do_work().is_err());
                let net = driver.net.as_ref().unwrap();
                assert!(net.reincarnation(registration).unwrap().is_none());
            }
            _ => {
                let _ = driver.close_network().unwrap();
                assert!(driver.net.is_none());
            }
        }
    }
}

/// #396 re-check P3: a reincarnation's room is counted once while its
/// old session is still being removed: the entry and the record are one
/// publication, so another one is admitted beside it.
#[test]
fn a_reincarnating_publication_takes_its_room_once() {
    let mut driver = reincarnating_driver(10_000_000_000, 2);
    let (handle, _guard, _epoch, _lane, socket) = waiting_reincarnation(&mut driver);
    // No duty since: the old session is still being removed.
    assert!(
        driver
            .net
            .as_ref()
            .unwrap()
            .is_network_aggregate(handle.registration())
    );
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let other = driver.add_network_publication(aggregate(11, 1), &channel(destination));
    assert!(other.is_ok(), "{other:?}");
}

/// #396 review P2: the quarantine runs from the old session's removal,
/// not from when it was posted. The removal is held back (no duty runs
/// for longer than the quarantine), so the swap still waits a full
/// quarantine once the removal ends.
#[test]
fn the_quarantine_runs_from_the_removal_not_the_post() {
    const QUARANTINE: u64 = 100_000_000;
    let mut driver = reincarnating_driver(QUARANTINE, 64);
    let (handle, _guard, _epoch, lane, _socket) = waiting_reincarnation(&mut driver);
    // No duty: the removal posted stays unanswered past the quarantine.
    std::thread::sleep(Duration::from_millis(150));
    let resumed = driver.net.as_ref().unwrap().now();
    let mut taken = None;
    until(&mut driver, |driver| match driver.publication(lane) {
        Err(DriverError::QuarantinedAlias { .. }) => false,
        other => {
            taken = Some(other.map(drop));
            true
        }
    });
    assert_eq!(taken, Some(Ok(())));
    let waited = driver.net.as_ref().unwrap().now() - resumed;
    assert!(
        waited >= QUARANTINE,
        "swapped {waited} ns after the removal"
    );
    assert_eq!(driver.trace_identity(lane).unwrap().incarnation, 2);
    let _ = handle;
}

/// #396 review P3: a guard closed again while the reincarnation waits is
/// reported as not open, not as a quarantine.
#[test]
fn a_guard_closed_again_while_waiting_is_not_open() {
    let mut driver = reincarnating_driver(10_000_000_000, 64);
    let (_handle, guard, epoch, lane, _socket) = waiting_reincarnation(&mut driver);
    let _ = driver.close_guard(guard, epoch).unwrap();
    assert!(matches!(
        driver.publication(lane),
        Err(DriverError::GuardNotOpen { .. })
    ));
}

/// #396 review P3: a reincarnating publication keeps its room in the
/// sender's table: another publication cannot take it during the wait.
#[test]
fn a_reincarnating_publication_keeps_its_room() {
    let mut driver = reincarnating_driver(10_000_000_000, 1);
    let (handle, _guard, _epoch, _lane, socket) = waiting_reincarnation(&mut driver);
    until(&mut driver, |driver| {
        !driver
            .net
            .as_ref()
            .unwrap()
            .is_network_aggregate(handle.registration())
    });
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let other = driver.add_network_publication(aggregate(11, 1), &channel(destination));
    assert!(
        matches!(other, Err(DriverError::NetworkPublicationsFull)),
        "{other:?}"
    );
}

/// A reincarnation ends with its publication: removing the aggregate while
/// it waits out the quarantine adds nothing, and its send endpoint retires.
#[test]
fn a_removed_reincarnating_publication_adds_nothing() {
    use karyos_sys::guard::Closed;
    use karyos_sys::log_buffer::SealReason;

    use crate::net::NetworkGuard;

    let mut driver = driver();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let mut config = aggregate(10, 1);
    config.stream.buffer.spare_slots = 4;
    let handle = driver
        .add_guarded_network_publication(
            config,
            &channel(destination),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        )
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    let lane = handle.lane(Lane::ZERO).unwrap();
    let publication = driver.publication(lane).unwrap();
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    drop(publication);
    until(&mut driver, |driver| {
        driver.seal_reason(lane) == Ok(Some(SealReason::GuardClosed))
    });
    let _ = driver.reopen_guard(guard, epoch, epoch).unwrap();
    until(&mut driver, |driver| {
        matches!(
            driver.publication(lane),
            Err(DriverError::QuarantinedAlias { .. })
        )
    });
    // Its old session's removal ends, and the default 10 s quarantine
    // holds the next incarnation back.
    until(&mut driver, |driver| {
        let net = driver.net.as_ref().unwrap();
        !net.is_network_aggregate(handle.registration())
    });
    let net = driver.net.as_ref().unwrap();
    assert!(matches!(
        net.reincarnation(handle.registration()),
        Ok(Some(crate::net::ReincarnationPhase::Waiting { .. }))
    ));
    // The extra hold keeps the endpoint open between incarnations.
    assert_eq!(net.send_endpoints(), 1);
    driver.remove_aggregate(&handle).unwrap();
    assert_eq!(driver.network_publication_state(&handle), None);
    until(&mut driver, |driver| {
        driver.net.as_ref().unwrap().send_endpoints() == 0
    });
}

/// Records plan v2: a network close supersedes a guarded publication's
/// gate, which never runs again. What it never staged never left: each
/// message is `Aborted` with `DRIVER_SHUTDOWN`, not `Submitted` at commit.
#[test]
fn a_network_close_aborts_what_the_gate_never_staged() {
    use karyos_client::OfferOutcome;
    use karyos_sys::outcome_ring::Kind;

    use crate::guard_streams::REASON_DRIVER_SHUTDOWN;
    use crate::net::NetworkGuard;

    let mut driver = driver();
    let guard = open_guard(&mut driver, "net");
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    // Spare slots for the sender's reservation and the guard's walker.
    let mut config = aggregate(10, 1);
    config.stream.buffer.spare_slots = 4;
    let handle = driver
        .add_guarded_network_publication(
            config,
            &channel(destination),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        )
        .unwrap();
    let mut lane = driver
        .publication(handle.lane(Lane::ZERO).unwrap())
        .unwrap();
    for value in [b"a", b"b"] {
        assert!(matches!(
            lane.offer(value).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    // Before any sender cycle: the gate never staged them.
    let _ = driver.close_network().unwrap();
    let mut records = Vec::new();
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
        let _ = lane
            .poll_outcomes(8, |_, record| records.push((record.kind, record.reason)))
            .unwrap();
    }
    let aborted = (Kind::Aborted, REASON_DRIVER_SHUTDOWN);
    assert_eq!(records, [aborted, aborted]);
}

/// SPEC §4 (initial state) and §5: each network publication draws its
/// `initial_term_id` on the control path, shared by its lanes, and its
/// SETUP announces it. Two draws differ (a 2^-32 equality is retried
/// once).
#[test]
fn network_publications_draw_their_initial_term_ids() {
    let announced = |stream_id: i32| {
        let mut driver = driver();
        let socket = receiver();
        let destination = Destination::Unicast(socket.local_addr().unwrap());
        let handle = driver
            .add_network_publication(aggregate(stream_id, 2), &channel(destination))
            .unwrap();
        let drawn: Vec<u32> = handle
            .streams()
            .map(|stream| {
                driver
                    .stream_ref(stream)
                    .unwrap()
                    .config
                    .initial_term_id
                    .get()
            })
            .collect();
        assert_eq!(drawn.len(), 2);
        assert_eq!(drawn[0], drawn[1], "every lane shares it");
        let mut buffer = [0u8; 2048];
        let mut announce = None;
        until(&mut driver, |_| {
            if let Ok(len) = socket.recv(&mut buffer)
                && let Ok(Datagram::Control(Control::SetupAnnounce(found))) =
                    classify(&buffer[..len])
            {
                announce = Some(found);
            }
            announce.is_some()
        });
        let announced = announce.unwrap().term.initial_term_id.cast_unsigned();
        assert_eq!(announced, drawn[0], "SETUP carries it");
        announced
    };
    let first = announced(10);
    let second = announced(11);
    let second = if second == first {
        announced(12)
    } else {
        second
    };
    assert_ne!(first, second);
}

/// #396 re-check P3: a publication the sender refused cannot reincarnate:
/// the call names the lane it was made on, not the aggregate's
/// registration (lane 1 of two here).
#[test]
fn a_refused_publication_names_the_lane_it_cannot_reincarnate() {
    use karyos_protocol::network::{Alias, Identity, TermParams};
    use karyos_sys::guard::Closed;
    use karyos_sys::log_buffer::SealReason;

    use crate::net::NetworkGuard;

    // The sender's one table entry is taken by a publication the
    // conductor does not track, so the guarded add is refused.
    let mut driver = reincarnating_driver(50_000_000, 1);
    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let foreign = Alias {
        session_id: 99,
        stream_id: 99,
    };
    let endpoint = crate::agents::EndpointId(999);
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let (outbound, _log) = crate::agents::data::testing::outbound(
        endpoint,
        foreign,
        socket.local_addr().unwrap(),
        term,
        1,
        false,
    );
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|reply| crate::agents::AgentCommand::AddPublication {
            reply,
            publication: crate::sessions::send::Publication {
                endpoint,
                alias: foreign,
                identity: Identity {
                    driver_id: [0, 0],
                    registration_id: 999,
                    incarnation: 1,
                },
                term,
                lane_count: 1,
            },
            outbound,
            guard: None,
            roles: None,
        })
        .unwrap();
    let guard = open_guard(&mut driver, "net");
    let mut config = aggregate(10, 2);
    config.stream.buffer.spare_slots = 4;
    let handle = driver
        .add_guarded_network_publication(
            config,
            &channel(destination),
            NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        )
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Refused)
    });
    let lanes = [Lane::ZERO, Lane::try_new(1).unwrap()].map(|lane| handle.lane(lane).unwrap());
    let publications = lanes.map(|lane| driver.publication(lane).unwrap());
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    drop(publications);
    until(&mut driver, |driver| {
        lanes
            .iter()
            .all(|lane| driver.seal_reason(*lane) == Ok(Some(SealReason::GuardClosed)))
    });
    let _ = driver.reopen_guard(guard, epoch, epoch).unwrap();
    let mut refused = None;
    until(&mut driver, |driver| match driver.publication(lanes[1]) {
        Err(DriverError::GuardSealed { .. }) => false,
        other => {
            refused = Some(other.map(drop));
            true
        }
    });
    assert_eq!(
        refused,
        Some(Err(DriverError::UnknownStream {
            stream: handle.registration() + 1
        }))
    );
}

/// P2.11 PR1: what a timed network publication's software route does
/// not support yet is refused, typed, before anything is configured.
#[test]
fn a_timed_network_publication_refuses_what_it_does_not_support() {
    use karyos_client::schedule::{ClockDomain, ScheduleOptions};
    use karyos_protocol::channel::Interface;

    use crate::error::TimedNetworkUnsupported as Unsupported;

    let socket = receiver();
    let destination = Destination::Unicast(socket.local_addr().unwrap());
    let unreliable = UdpConfig {
        reliable: false,
        ..channel(destination.clone())
    };
    let routed = UdpConfig {
        destination: Destination::Multicast {
            group: "239.255.0.9:4000".parse().unwrap(),
            ttl: None,
        },
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Interface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ],
        ..unreliable.clone()
    };
    let tai = ScheduleOptions {
        domain: ClockDomain::Tai,
        ..ScheduleOptions::default()
    };
    let cancel = ScheduleOptions {
        cancel_on_deadline: true,
        ..ScheduleOptions::default()
    };
    let cases = vec![
        (unreliable.clone(), cancel, Unsupported::CancelOnDeadline),
        // Refused before anything platform-specific: on every platform.
        (unreliable.clone(), tai, Unsupported::TaiDomain),
        (routed, ScheduleOptions::default(), Unsupported::Routed),
        (
            unreliable.clone(),
            ScheduleOptions {
                max_horizon: crate::agents::AgentConfig::default().image_liveness_timeout,
                ..ScheduleOptions::default()
            },
            Unsupported::HorizonPastLiveness,
        ),
    ];
    let mut driver = driver();
    for (channel, options, reason) in cases {
        let mut config = aggregate(10, 1);
        config.stream.buffer.schedule_capacity = 4;
        let refused = driver.add_timed_network_publication(config, &channel, None, options);
        assert_eq!(
            refused.map(drop),
            Err(DriverError::TimedNetworkUnsupported { reason }),
            "{reason:?}"
        );
        // Nothing was configured: the key is free.
        driver.free_retired_streams();
        assert!(driver.streams.is_empty(), "{reason:?}");
    }
    // A timed add of lanes with no ring is refused too.
    let refused = driver.add_timed_network_publication(
        aggregate(10, 1),
        &unreliable,
        None,
        ScheduleOptions::default(),
    );
    assert_eq!(refused.map(drop), Err(DriverError::InvalidConfig));
    // Once added, a lane's settings are its sender's: they do not change.
    let mut config = aggregate(10, 1);
    config.stream.buffer.schedule_capacity = 4;
    let handle = driver
        .add_timed_network_publication(config, &unreliable, None, ScheduleOptions::default())
        .unwrap();
    assert_eq!(
        driver.schedule_stream(handle.lane(Lane::ZERO).unwrap(), ScheduleOptions::default()),
        Err(DriverError::InvalidConfig)
    );
}

/// #404 review P1: a timed guarded network publication of two lanes,
/// closed by its guard and reopened, reincarnates both lanes on lane 0's
/// call. Lane 1's settings stay its sender's: a change is refused (no
/// way past the add's refusals), and its counter cells are the same.
#[test]
fn a_reincarnated_timed_lane_keeps_its_settings_and_counters() {
    use karyos_client::schedule::ScheduleOptions;
    use karyos_sys::guard::Closed;
    use karyos_sys::log_buffer::SealReason;

    use crate::net::NetworkGuard;

    let mut driver = reincarnating_driver(20_000_000, 64);
    let guard = open_guard(&mut driver, "timed");
    let socket = receiver();
    let unreliable = UdpConfig {
        reliable: false,
        ..channel(Destination::Unicast(socket.local_addr().unwrap()))
    };
    let mut config = aggregate(10, 2);
    config.stream.buffer.spare_slots = 4;
    config.stream.buffer.schedule_capacity = 4;
    let handle = driver
        .add_timed_network_publication(
            config,
            &unreliable,
            Some(NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            }),
            ScheduleOptions::default(),
        )
        .unwrap();
    until(&mut driver, |driver| {
        driver.network_publication_state(&handle) == Some(NetworkPublicationState::Active)
    });
    let lanes = [Lane::ZERO, Lane::try_new(1).unwrap()].map(|lane| handle.lane(lane).unwrap());
    let cells = driver.timed_counters(lanes[1]).unwrap().unwrap();
    let publications = lanes.map(|lane| driver.publication(lane).unwrap());
    let Closed::Now { epoch } = driver.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    drop(publications);
    until(&mut driver, |driver| {
        lanes
            .iter()
            .all(|lane| driver.seal_reason(*lane) == Ok(Some(SealReason::GuardClosed)))
    });
    let _ = driver.reopen_guard(guard, epoch, epoch).unwrap();
    let mut taken = None;
    until(&mut driver, |driver| match driver.publication(lanes[0]) {
        Err(DriverError::GuardSealed { .. } | DriverError::QuarantinedAlias { .. }) => false,
        other => {
            taken = Some(other.map(drop));
            true
        }
    });
    assert_eq!(taken, Some(Ok(())));
    assert_eq!(driver.trace_identity(lanes[1]).unwrap().incarnation, 2);
    let cancel = ScheduleOptions {
        cancel_on_deadline: true,
        ..ScheduleOptions::default()
    };
    assert_eq!(
        driver.schedule_stream(lanes[1], cancel),
        Err(DriverError::InvalidConfig)
    );
    let kept = driver.timed_counters(lanes[1]).unwrap().unwrap();
    assert!(std::sync::Arc::ptr_eq(&cells, &kept), "one set of counters");
}
