// SPDX-License-Identifier: Apache-2.0

//! Dynamic registration's sender side on loopback (karyos#644 step 3a;
//! `quantstratum-docs: karyos/design/multi-destination-unicast.md` 3.2):
//! a `control-mode=dynamic` publication binds its `control` endpoint and
//! answers a REGISTER from an allowed source with one SETUP ANNOUNCE to
//! that source, and nothing to a source outside its allowlist. The first
//! tests register from a raw socket; the later ones from a Karyos
//! receiver's `control-mode=dynamic` subscription (step 3b), which
//! registers, is challenged, binds and receives, and reads the ERR of a
//! full table.

use std::net::{IpAddr, SocketAddr, UdpSocket};

use karyos_protocol::channel::{ControlMode, Destination, Interface, Security, UdpConfig};
use karyos_protocol::network::{Control, MAX_CONTROL_LENGTH, Receiver, RspRegister};

use karyos_sys::log_buffer::Role;

use super::{LOOPBACK, aggregate, driver, driver_with, exchange, free_port, pump};
use crate::agents::AgentConfig;
use crate::agents::ThreadingMode;
use crate::embedded::{AggregateHandle, EmbeddedDriver};
use crate::error::DriverError;
use crate::sessions::register::{AddressRange, RegistrationAllowlist};

/// A dynamic channel registering at `control`.
fn dynamic(control: SocketAddr) -> UdpConfig {
    UdpConfig {
        retransmit_window: None,
        destination: Destination::MultiDestination {
            destinations: Vec::new(),
            control: Some(control),
            mode: ControlMode::Dynamic,
        },
        interface: None,
        paths: Vec::new(),
        reliable: false,
        flow_control: None,
        security: Security::Trusted,
    }
}

fn allowlist(network: [u8; 4], prefix: u8) -> RegistrationAllowlist {
    let range = AddressRange::new(IpAddr::from(network), prefix).unwrap();
    RegistrationAllowlist::new(&[range]).unwrap()
}

/// A registrant's socket on loopback, never blocking.
fn registrant() -> UdpSocket {
    let socket = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

fn register(socket: &UdpSocket, control: SocketAddr, stream_id: i32) {
    let control_frame = Control::Register(RspRegister {
        stream_id,
        receiver: Receiver {
            receiver_boot_id: [7, 7],
            receiver_id: 1,
        },
    });
    let mut out = [0u8; MAX_CONTROL_LENGTH];
    let length = control_frame.encode(&mut out).unwrap();
    socket.send_to(&out[..length], control).unwrap();
}

/// The next control datagram `socket` holds, decoded; `None` when none is
/// queued.
fn received(socket: &UdpSocket) -> Option<(SocketAddr, Control)> {
    let mut buf = [0u8; 2048];
    match socket.recv_from(&mut buf) {
        Ok((length, from)) => Some((from, Control::decode(&buf[..length]).unwrap())),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(error) => panic!("{error}"),
    }
}

/// An allowed REGISTER gets one SETUP ANNOUNCE of its stream from the
/// control endpoint; a REGISTER from outside the allowlist gets nothing.
/// Ordered with no sleep: both REGISTERs reach one endpoint from one
/// socket, the refused one first, so any reply to it would be queued
/// before the ANNOUNCE of the admitted one.
#[test]
fn a_registrant_is_announced_only_inside_the_allowlist() {
    let mut a = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let channel = dynamic(control);
    let _outside = a
        .add_dynamic_network_publication(aggregate(10, 3, 1), &channel, allowlist([10, 0, 0, 0], 8))
        .unwrap();
    let _inside = a
        .add_dynamic_network_publication(
            aggregate(11, 4, 1),
            &channel,
            allowlist([127, 0, 0, 0], 8),
        )
        .unwrap();
    let socket = registrant();
    let mut announced = None;
    let mut polls = 0u32;
    pump(&mut [&mut a], |_| {
        // Both REGISTERs go together, again every thousand polls until
        // one is answered, as a receiver repeats them at its interval: the
        // first may arrive before both publications are live.
        if polls.is_multiple_of(1000) {
            register(&socket, control, 10);
            register(&socket, control, 11);
        }
        polls += 1;
        announced = received(&socket);
        announced.is_some()
    });
    let (from, reply) = announced.unwrap();
    assert_eq!(from, control);
    let Control::SetupAnnounce(setup) = reply else {
        panic!("{reply:?}");
    };
    assert_eq!(setup.alias.stream_id, 11);
    // Anything else queued is another ANNOUNCE of stream 11 (a retried
    // REGISTER), never one of stream 10.
    while let Some((_, other)) = received(&socket) {
        assert!(
            matches!(other, Control::SetupAnnounce(setup) if setup.alias.stream_id == 11),
            "{other:?}"
        );
    }
}

/// A second dynamic publication of one stream on one control endpoint is
/// refused with a typed error; another stream on that endpoint is not.
#[test]
fn a_second_dynamic_publication_of_a_stream_is_a_typed_error() {
    let mut a = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let channel = dynamic(control);
    let lan = || allowlist([127, 0, 0, 0], 8);
    let _first = a
        .add_dynamic_network_publication(aggregate(10, 3, 1), &channel, lan())
        .unwrap();
    assert!(matches!(
        a.add_dynamic_network_publication(aggregate(10, 5, 1), &channel, lan()),
        Err(DriverError::DynamicPublicationExists { stream_id: 10 })
    ));
    assert!(
        a.add_dynamic_network_publication(aggregate(11, 6, 1), &channel, lan())
            .is_ok()
    );
}

/// What a dynamic publication does not take: listed destinations, an
/// interface, or an allowlist on another channel. The public calls carry no
/// allowlist and still refuse dynamic mode.
#[test]
fn what_a_dynamic_publication_does_not_take_is_refused() {
    let mut a = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let lan = || allowlist([127, 0, 0, 0], 8);
    let mut listed = dynamic(control);
    listed.destination = Destination::MultiDestination {
        destinations: vec![SocketAddr::new(LOOPBACK, free_port())],
        control: Some(control),
        mode: ControlMode::Dynamic,
    };
    assert!(matches!(
        a.add_dynamic_network_publication(aggregate(10, 3, 1), &listed, lan()),
        Err(DriverError::UnsupportedChannel)
    ));
    let mut bound = dynamic(control);
    bound.interface = Some(Interface::Address(LOOPBACK));
    assert!(matches!(
        a.add_dynamic_network_publication(aggregate(10, 3, 1), &bound, lan()),
        Err(DriverError::UnsupportedChannel)
    ));
    let unicast = super::channel(SocketAddr::new(LOOPBACK, free_port()), false);
    assert!(matches!(
        a.add_dynamic_network_publication(aggregate(10, 3, 1), &unicast, lan()),
        Err(DriverError::InvalidConfig)
    ));
    assert!(matches!(
        a.add_network_publication(aggregate(10, 3, 1), &dynamic(control)),
        Err(DriverError::DynamicRegistrationUnsupported)
    ));
}

/// `dynamic(control)` as a Karyos receiver subscribes to it: reliable, and
/// bound on loopback.
fn subscribed(control: SocketAddr) -> UdpConfig {
    UdpConfig {
        interface: Some(Interface::Address(LOOPBACK)),
        reliable: true,
        ..dynamic(control)
    }
}

/// `dynamic(control)`, reliable, as its publication serves it.
fn reliable(control: SocketAddr) -> UdpConfig {
    UdpConfig {
        reliable: true,
        ..dynamic(control)
    }
}

/// `driver`'s registration counters at its sender.
fn registrations(driver: &EmbeddedDriver) -> crate::sessions::register::RegistrationCounters {
    driver
        .net
        .as_ref()
        .unwrap()
        .registration_counters()
        .unwrap()
}

/// `driver`'s receiver counters.
fn receiver(driver: &EmbeddedDriver) -> crate::agents::roles::ReceiverCounters {
    driver.net.as_ref().unwrap().receiver_counters().unwrap()
}

/// Pumps `a` and `b` until `b` has an image of `stream_id` (session 3).
fn image_of(a: &mut EmbeddedDriver, b: &mut EmbeddedDriver, stream_id: i32) -> AggregateHandle {
    let mut image = None;
    pump(&mut [a, b], |drivers| {
        image = drivers[1].network_image(stream_id, 3);
        image.is_some()
    });
    image.unwrap()
}

/// A Karyos receiver's dynamic subscription registers at `control`, is
/// announced, CHALLENGEs, binds and receives every message in order: the
/// whole exchange of design 3.2 between two drivers.
#[test]
fn a_dynamic_subscription_registers_binds_and_receives() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let publication = a
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
        )
        .unwrap();
    let _subscription = b
        .add_dynamic_network_subscription(10, &subscribed(control), None)
        .unwrap();
    let image = image_of(&mut a, &mut b, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    exchange(&mut a, &mut b, &publication, &mut reader, 64);
    assert!(receiver(&b).registers_sent >= 1);
    let counters = registrations(&a);
    assert!(counters.registered >= 1, "{counters:?}");
    assert!(counters.challenged >= 1, "{counters:?}");
}

/// A Karyos receiver outside a publication's allowlist gets nothing: its
/// REGISTERs are dropped with no reply, while the same receiver's
/// subscription of another stream on that endpoint, whose allowlist names
/// it, binds. Ordered with no sleep: the pump ends only once the sender
/// counted the refused REGISTER and the admitted stream's image exists.
#[test]
fn a_dynamic_subscription_outside_the_allowlist_gets_nothing() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let _outside = a
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &reliable(control),
            allowlist([10, 0, 0, 0], 8),
        )
        .unwrap();
    let _inside = a
        .add_dynamic_network_publication(
            aggregate(11, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
        )
        .unwrap();
    let _refused = b
        .add_dynamic_network_subscription(10, &subscribed(control), None)
        .unwrap();
    let _admitted = b
        .add_dynamic_network_subscription(11, &subscribed(control), None)
        .unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        registrations(drivers[0]).dropped_not_allowed >= 1
            && drivers[1].network_image(11, 3).is_some()
    });
    assert!(b.network_image(10, 3).is_none());
    // Nothing was announced to it: the only registration is stream 11's.
    let counters = registrations(&a);
    assert_eq!(counters.refused_full, 0, "{counters:?}");
    assert!(counters.registered >= 1, "{counters:?}");
}

/// A REGISTER finding the destination table full is answered ERR
/// REGISTRATION, which the receiver reads; the joined destination keeps
/// receiving. A publication of `max_destinations` 1: B joins, then C
/// registers.
#[test]
fn a_full_table_answers_err_and_keeps_its_destination() {
    let agents = AgentConfig {
        max_destinations: 1,
        ..AgentConfig::default()
    };
    let mut a = driver_with(ThreadingMode::Shared, agents);
    let mut b = driver(ThreadingMode::Shared);
    let mut c = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let publication = a
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
        )
        .unwrap();
    let _joined = b
        .add_dynamic_network_subscription(10, &subscribed(control), None)
        .unwrap();
    let image = image_of(&mut a, &mut b, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(karyos_sys::frame::Lane::ZERO).unwrap())
        .unwrap();
    super::exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..16);
    let _refused = c
        .add_dynamic_network_subscription(10, &subscribed(control), None)
        .unwrap();
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        receiver(drivers[2]).registration_refusals >= 1
    });
    assert!(c.network_image(10, 3).is_none());
    assert!(registrations(&a).refused_full >= 1);
    super::exchange_on(&mut a, &mut b, &mut lane, &mut reader, 16..32);
}

/// The public subscription calls refuse dynamic mode, as the publication
/// calls do, until the rest of karyos#644 lands.
#[test]
fn the_public_subscription_calls_refuse_dynamic_mode() {
    let mut b = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    assert!(matches!(
        b.add_network_subscription(10, &subscribed(control)),
        Err(DriverError::DynamicRegistrationUnsupported)
    ));
}
