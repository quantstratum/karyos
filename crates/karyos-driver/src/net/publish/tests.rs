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
use crate::embedded::{AggregateConfig, DriverConfig, EmbeddedDriver, StreamConfig};
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
