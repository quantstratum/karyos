// SPDX-License-Identifier: Apache-2.0

//! Dynamic registration's sender side on loopback (karyos#644 step 3a;
//! `quantstratum-docs: karyos/design/multi-destination-unicast.md` 3.2):
//! a `control-mode=dynamic` publication binds its `control` endpoint and
//! answers a REGISTER from an allowed source with one SETUP ANNOUNCE to
//! that source, and nothing to a source outside its allowlist. The
//! receiver side is not here, so a raw socket registers.

use std::net::{IpAddr, SocketAddr, UdpSocket};

use karyos_protocol::channel::{ControlMode, Destination, Interface, Security, UdpConfig};
use karyos_protocol::network::{Control, MAX_CONTROL_LENGTH, Receiver, RspRegister};

use super::{LOOPBACK, aggregate, driver, free_port, pump};
use crate::agents::ThreadingMode;
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
