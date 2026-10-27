// SPDX-License-Identifier: Apache-2.0

//! Multi-destination unicast end to end, the manual-mode first sends
//! (`quantstratum-docs: karyos/design/multi-destination-unicast.md`;
//! ADR-0056, ADR-0082; karyos#630): one publication sends every datagram
//! over unicast to each configured destination, each with its own
//! establishment, SMs and image, on loopback with no multicast at all. A
//! required destination bounds the sender. Dynamic registration and, in
//! this step, reliable channels are refused.
//!
//! No test here claims isolation between destinations: until the next step
//! removes a slow optional destination (MD-7), one that stops consuming
//! holds the others.

use std::net::SocketAddr;

use karyos_client::OfferOutcome;
use karyos_protocol::channel::{
    ControlMode, Destination, FlowControl, Interface, Security, UdpConfig,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::Role;

use super::{ANY_PORT, BUDGET, LOOPBACK, aggregate, bound, channel, driver, pump};
use crate::agents::ThreadingMode;
use crate::embedded::EmbeddedDriver;
use crate::error::DriverError;
use crate::membership::{PublicationRoles, Strategy};

/// A manual multi-destination channel to `destinations`.
fn destinations(destinations: &[SocketAddr], reliable: bool) -> UdpConfig {
    UdpConfig {
        destination: Destination::MultiDestination {
            destinations: destinations.to_vec(),
            control: None,
            mode: ControlMode::Manual,
        },
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// Receivers on their own drivers, each subscribed to stream 10 on any
/// port, with the addresses they bound.
fn receivers(count: usize) -> (Vec<EmbeddedDriver>, Vec<SocketAddr>) {
    let mut drivers = Vec::with_capacity(count);
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let mut receiver = driver(ThreadingMode::Shared);
        let _ = receiver
            .add_network_subscription(10, &channel(ANY_PORT, false))
            .unwrap();
        addresses.push(bound(&receiver, 10));
        drivers.push(receiver);
    }
    (drivers, addresses)
}

/// One publication reaches three unicast destinations, each through its
/// own image, every message once and in order.
#[test]
fn a_publication_reaches_every_destination_through_its_own_image() {
    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers(3);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &destinations(&addresses, false))
        .unwrap();
    let mut images = vec![None; receivers.len()];
    {
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |drivers| {
            for (image, receiver) in images.iter_mut().zip(drivers.iter().skip(1)) {
                *image = receiver.network_image(10, 3);
            }
            images.iter().all(Option::is_some)
        });
    }
    let mut readers: Vec<_> = receivers
        .iter_mut()
        .zip(&images)
        .map(|(receiver, image)| {
            receiver
                .subscribe_aggregate(image.as_ref().unwrap(), Role::Required)
                .unwrap()
        })
        .collect();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, vec![0u32; receivers.len()]);
    let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
        .chain(receivers.iter_mut())
        .collect();
    pump(&mut all, |_| {
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
        seen.iter().all(|seen| *seen == 128)
    });
}

/// A required destination bounds the sender: under `fc=max`, with the
/// required receiver's subscriber stopped, the publisher is back
/// pressured once that receiver's window is used, while the optional
/// receiver keeps consuming.
#[test]
fn a_required_destination_bounds_the_sender() {
    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers(2);
    let mut channel = destinations(&addresses, false);
    channel.flow_control = Some(FlowControl::Max);
    let publication = a
        .add_network_publication_with_destinations(
            aggregate(10, 3, 1),
            &channel,
            Some(PublicationRoles {
                strategy: Strategy::Max,
                required: Vec::new(),
                tags: Vec::new(),
            }),
            &addresses[..1],
        )
        .unwrap();
    let mut images = vec![None; receivers.len()];
    {
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |drivers| {
            for (image, receiver) in images.iter_mut().zip(drivers.iter().skip(1)) {
                *image = receiver.network_image(10, 3);
            }
            images.iter().all(Option::is_some)
        });
    }
    // The required receiver's subscriber never polls: its consumption
    // stays at its join.
    let _stalled = receivers[0]
        .subscribe_aggregate(images[0].as_ref().unwrap(), Role::Required)
        .unwrap();
    let mut optional = receivers[1]
        .subscribe_aggregate(images[1].as_ref().unwrap(), Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut accepted = 0u64;
    let mut pressured = false;
    let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
        .chain(receivers.iter_mut())
        .collect();
    pump(&mut all, |_| {
        match lane.offer(&[7u8; 1000]).unwrap() {
            OfferOutcome::Accepted { .. } => accepted += 1,
            OfferOutcome::BackPressured => pressured = true,
            _ => {}
        }
        let _ = optional.poll(|_, _, _| {}, BUDGET);
        pressured && accepted > 0
    });
    // Bounded: far fewer than a stream's worth were accepted.
    assert!(accepted < 1024, "accepted {accepted}");
}

/// What this step refuses: dynamic registration (a typed error), a
/// reliable channel with destinations, `control` with a manual set, a
/// destination named twice, and a required destination that is not one.
#[test]
fn what_manual_mode_does_not_take_yet_is_refused() {
    let mut a = driver(ThreadingMode::Shared);
    let one: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let two: SocketAddr = "127.0.0.1:40002".parse().unwrap();
    let mut dynamic = destinations(&[one], false);
    dynamic.destination = Destination::MultiDestination {
        destinations: Vec::new(),
        control: Some(two),
        mode: ControlMode::Dynamic,
    };
    assert!(matches!(
        a.add_network_publication(aggregate(10, 3, 1), &dynamic),
        Err(DriverError::DynamicRegistrationUnsupported)
    ));
    assert!(matches!(
        a.add_network_publication(aggregate(10, 3, 1), &destinations(&[one, two], true)),
        Err(DriverError::UnsupportedChannel)
    ));
    let mut controlled = destinations(&[one], false);
    controlled.destination = Destination::MultiDestination {
        destinations: vec![one],
        control: Some(two),
        mode: ControlMode::Manual,
    };
    assert!(matches!(
        a.add_network_publication(aggregate(10, 3, 1), &controlled),
        Err(DriverError::UnsupportedChannel)
    ));
    assert!(matches!(
        a.add_network_publication(aggregate(10, 3, 1), &destinations(&[one, one], false)),
        Err(DriverError::UnsupportedChannel)
    ));
    assert!(matches!(
        a.add_network_publication_with_destinations(
            aggregate(10, 3, 1),
            &destinations(&[one], false),
            None,
            &[two],
        ),
        Err(DriverError::InvalidConfig)
    ));
    // A required destination on a channel without destinations.
    assert!(matches!(
        a.add_network_publication_with_destinations(
            aggregate(10, 3, 1),
            &channel(one, false),
            None,
            &[one],
        ),
        Err(DriverError::InvalidConfig)
    ));
}
