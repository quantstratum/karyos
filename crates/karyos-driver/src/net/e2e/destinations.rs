// SPDX-License-Identifier: Apache-2.0

//! Multi-destination unicast end to end, the manual-mode first sends
//! (`quantstratum-docs: karyos/design/multi-destination-unicast.md`;
//! ADR-0056, ADR-0082; karyos#630): one publication sends every datagram
//! over unicast to each configured destination, each with its own
//! establishment, SMs and image, on loopback with no multicast at all. A
//! required destination bounds the sender, a slow optional one is removed
//! without stalling the others (MD-7), and a retransmission goes only to
//! the destination that asked (MD-8). Dynamic registration is refused.

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
    receivers_on(count, false)
}

/// [`receivers`] on reliable or unreliable subscriptions.
fn receivers_on(count: usize, reliable: bool) -> (Vec<EmbeddedDriver>, Vec<SocketAddr>) {
    let mut drivers = Vec::with_capacity(count);
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let mut receiver = driver(ThreadingMode::Shared);
        let _ = receiver
            .add_network_subscription(10, &channel(ANY_PORT, reliable))
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

/// What manual mode refuses: dynamic registration (a typed error),
/// `control` with a manual set, a destination named twice, and a required
/// destination that is not one.
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

/// Connects `receivers` to a publication on `a` with `channel`, returning
/// the publication and each receiver's image.
fn connect(
    a: &mut EmbeddedDriver,
    receivers: &mut [EmbeddedDriver],
    channel: &UdpConfig,
    required: &[SocketAddr],
    roles: Option<PublicationRoles>,
) -> (
    crate::embedded::AggregateHandle,
    Vec<crate::embedded::AggregateHandle>,
) {
    let publication = a
        .add_network_publication_with_destinations(aggregate(10, 3, 1), channel, roles, required)
        .unwrap();
    let mut images = vec![None; receivers.len()];
    let mut all: Vec<&mut EmbeddedDriver> =
        std::iter::once(a).chain(receivers.iter_mut()).collect();
    pump(&mut all, |drivers| {
        for (image, receiver) in images.iter_mut().zip(drivers.iter().skip(1)) {
            *image = receiver.network_image(10, 3);
        }
        images.iter().all(Option::is_some)
    });
    (
        publication,
        images.into_iter().map(Option::unwrap).collect(),
    )
}

/// MD-7: under `fc=max`, an optional destination whose receiver stops
/// (its driver no longer runs: no SM, no read) fills its queue and is
/// removed, reported as slow, while the other destination receives every
/// message without a stall.
#[test]
fn a_slow_optional_destination_is_removed_without_stalling_the_others() {
    use crate::agents::data::RemovalReason;

    let mut a = driver(ThreadingMode::Shared);
    // Reliable, so a datagram the live receiver's socket drops is
    // repaired: the test is about the removal, not about loopback loss.
    let (mut receivers, addresses) = receivers_on(2, true);
    let mut channel = destinations(&addresses, true);
    channel.flow_control = Some(FlowControl::Max);
    let roles = PublicationRoles {
        strategy: Strategy::Max,
        required: Vec::new(),
        tags: Vec::new(),
    };
    let (publication, images) = connect(&mut a, &mut receivers, &channel, &[], Some(roles));
    let mut live = receivers.pop().unwrap();
    let _frozen = receivers.pop().unwrap();
    let mut reader = live
        .subscribe_aggregate(&images[1], Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    pump(&mut [&mut a, &mut live], |_| {
        while sent < 512 {
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
        seen == 512
    });
    let mut removed = Vec::new();
    pump(&mut [&mut a, &mut live], |drivers| {
        removed = drivers[0].network_removed_destinations(&publication);
        !removed.is_empty()
    });
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert_eq!(removed[0].destination, addresses[0]);
    assert_eq!(removed[0].reason, RemovalReason::Slow);
}

/// MD-8: on a reliable channel, a datagram one destination lost is
/// repaired to that destination only.
#[test]
fn a_retransmission_reaches_only_the_requester() {
    let mut a = driver(ThreadingMode::Shared);
    let mut receivers = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..2 {
        let mut receiver = driver(ThreadingMode::Shared);
        let _ = receiver
            .add_network_subscription(10, &channel(ANY_PORT, true))
            .unwrap();
        addresses.push(bound(&receiver, 10));
        receivers.push(receiver);
    }
    let (publication, images) = connect(
        &mut a,
        &mut receivers,
        &destinations(&addresses, true),
        &[],
        None,
    );
    // The first receiver loses its second DATA datagram.
    super::shared(&mut receivers[0]).receiver.drop_data(&[1]);
    let mut readers: Vec<_> = receivers
        .iter_mut()
        .zip(&images)
        .map(|(receiver, image)| receiver.subscribe_aggregate(image, Role::Required).unwrap())
        .collect();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, [0u32; 2]);
    let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
        .chain(receivers.iter_mut())
        .collect();
    pump(&mut all, |_| {
        while sent < 16 {
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
        seen == [16, 16]
    });
    let counters = super::shared(&mut a).sender.destination_counters(0);
    let repairs = |address: SocketAddr| {
        counters
            .iter()
            .find(|(held, _)| *held == address)
            .map(|(_, counters)| counters.repairs)
            .unwrap()
    };
    assert!(repairs(addresses[0]) >= 1, "{counters:?}");
    assert_eq!(repairs(addresses[1]), 0, "{counters:?}");
}
