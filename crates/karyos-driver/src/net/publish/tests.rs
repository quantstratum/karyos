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

/// #279 P1: a key freed locally while its old publication is still being
/// removed is refused (`NetworkBusy`), leaving nothing behind; once the
/// old one is gone the key is accepted, and the new publication is
/// tracked and removed as any other.
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
    // The streams free before the sender answers: the key is free locally.
    driver.free_retired_streams();
    let users = driver.net.as_ref().unwrap().send_endpoint_users();
    assert_eq!(
        driver.add_network_publication(aggregate(10, 1), &channel(destination.clone())),
        Err(DriverError::NetworkBusy)
    );
    assert_eq!(
        driver.net.as_ref().unwrap().send_endpoint_users(),
        users,
        "the refused attempt released its endpoint"
    );
    until(&mut driver, |driver| {
        driver.network_publication_state(&old).is_none()
            && driver.network_publication_state(&other).is_none()
    });
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
