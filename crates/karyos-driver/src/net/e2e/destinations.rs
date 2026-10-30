// SPDX-License-Identifier: Apache-2.0

//! Multi-destination unicast end to end, the manual-mode first sends
//! (`quantstratum-docs: karyos/design/multi-destination-unicast.md`;
//! ADR-0056, ADR-0082; karyos#630): one publication sends every datagram
//! over unicast to each configured destination, each with its own
//! establishment, SMs and image, on loopback with no multicast at all. A
//! required destination bounds the sender, a slow optional one is removed
//! without stalling the others (MD-7), and a retransmission goes only to
//! the destination that asked (MD-8). Dynamic registration is refused.

use std::net::{SocketAddr, UdpSocket};

use karyos_client::OfferOutcome;
use karyos_client::aggregate::LaneEnd;
use karyos_protocol::channel::{
    ControlMode, Destination, FlowControl, Interface, Security, UdpConfig,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{Role, SealReason};

use super::{ANY_PORT, BUDGET, LOOPBACK, aggregate, bound, channel, driver, driver_with, pump};
use crate::agents::ThreadingMode;
use crate::embedded::EmbeddedDriver;
use crate::error::DriverError;
use crate::membership::{PublicationRoles, Strategy};

/// A manual multi-destination channel to `destinations`.
pub(super) fn destinations(destinations: &[SocketAddr], reliable: bool) -> UdpConfig {
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

/// Loopback addresses no receiver can bind while this is held: each is
/// the ephemeral port of a socket kept open (karyos#900). A fixed port
/// can be one a receiver drew from the same ephemeral range, which turns
/// an expected `Added` into `Present`.
struct Reserved {
    sockets: Vec<UdpSocket>,
}

impl Reserved {
    /// `count` reserved loopback ports.
    fn new(count: usize) -> Self {
        let sockets = (0..count)
            .map(|_| UdpSocket::bind(SocketAddr::from((LOOPBACK, 0))).unwrap())
            .collect();
        Self { sockets }
    }

    /// The `index`th reserved address.
    fn at(&self, index: usize) -> SocketAddr {
        self.sockets[index].local_addr().unwrap()
    }
}

/// Receivers on their own drivers, each subscribed to stream 10 on any
/// port, with the addresses they bound.
fn receivers(count: usize) -> (Vec<EmbeddedDriver>, Vec<SocketAddr>) {
    receivers_on(count, false)
}

/// [`receivers`] on reliable or unreliable subscriptions.
pub(super) fn receivers_on(count: usize, reliable: bool) -> (Vec<EmbeddedDriver>, Vec<SocketAddr>) {
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

/// karyos#900: a reserved address is never one a receiver bound, and no
/// receiver can bind it while it is held.
#[test]
fn a_reserved_destination_is_never_a_receivers_port() {
    let (_receivers, addresses) = receivers(4);
    let reserved = Reserved::new(8);
    for index in 0..8 {
        let address = reserved.at(index);
        assert!(!addresses.contains(&address), "{address} is a receiver's");
        assert!(UdpSocket::bind(address).is_err(), "{address} is free");
    }
    let (_late, late) = receivers(4);
    for index in 0..8 {
        assert!(!late.contains(&reserved.at(index)));
    }
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
    // The removed destination no longer keeps the lane from draining: the
    // publication's EOS reaches the remaining one, whose image ends there.
    // The handle is released first, so the seal is positioned.
    drop(lane);
    a.remove_aggregate(&publication).unwrap();
    let mut end = None;
    pump(&mut [&mut a, &mut live], |_| {
        let poll = reader.poll(|_, _, _| seen += 1, BUDGET);
        if poll.terminal.is_some() {
            end = Some(poll.lanes[0].end);
        }
        end.is_some()
    });
    assert!(
        matches!(
            end,
            Some(Some(LaneEnd::Closed {
                reason: SealReason::EndOfStream,
                ..
            }))
        ),
        "{end:?}"
    );
}

/// MD-7 under `min` (no `fc`): a destination whose receiver stops bounds
/// the others until its liveness expiry and is never removed as slow
/// (design 4.5).
#[test]
fn under_min_a_stopped_destination_bounds_and_is_not_removed() {
    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers_on(2, true);
    let channel = destinations(&addresses, true);
    let (publication, images) = connect(&mut a, &mut receivers, &channel, &[], None);
    let mut live = receivers.pop().unwrap();
    let _frozen = receivers.pop().unwrap();
    let mut reader = live
        .subscribe_aggregate(&images[1], Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut sent = 0u32;
    for _ in 0..3_000 {
        while sent < 512 {
            let payload = [0u8; 1000];
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = a.do_work().unwrap();
        let _ = live.do_work().unwrap();
        let _ = reader.poll(|_, _, _| {}, BUDGET);
    }
    let removed = a.network_removed_destinations(&publication);
    assert!(removed.is_empty(), "{removed:?}");
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

/// Pumps `a` and `receivers` until the sender answered one destination
/// change of `publication`, which it returns.
fn answer(
    a: &mut EmbeddedDriver,
    receivers: &mut [EmbeddedDriver],
    publication: &crate::embedded::AggregateHandle,
) -> (SocketAddr, crate::agents::data::DestinationChange) {
    let mut answers = Vec::new();
    let mut all: Vec<&mut EmbeddedDriver> =
        std::iter::once(a).chain(receivers.iter_mut()).collect();
    pump(&mut all, |drivers| {
        answers = drivers[0].take_network_destination_changes(publication);
        !answers.is_empty()
    });
    answers[0]
}

/// MD-3, MD-14: an optional destination moves by a removal and an
/// addition at run time. The new one gets its own image and the messages
/// from its join; the removed one is reported as removed by command and
/// cannot come back before its quarantine.
#[test]
fn an_optional_destination_moves_by_removal_and_addition() {
    use crate::agents::data::{DestinationChange, RemovalReason};

    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers(3);
    let (publication, _) = {
        let (listed, _) = receivers.split_at_mut(2);
        connect(
            &mut a,
            listed,
            &destinations(&addresses[..2], false),
            &[],
            None,
        )
    };
    a.remove_network_destination(&publication, addresses[0])
        .unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (addresses[0], DestinationChange::Removed)
    );
    a.add_network_destination(&publication, addresses[2])
        .unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (addresses[2], DestinationChange::Added)
    );
    // Back at once: still quarantined.
    a.add_network_destination(&publication, addresses[0])
        .unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (addresses[0], DestinationChange::Quarantined)
    );
    // The new destination gets its own image, and messages.
    let mut image = None;
    {
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |drivers| {
            image = drivers[3].network_image(10, 3);
            image.is_some()
        });
    }
    let mut reader = receivers[2]
        .subscribe_aggregate(image.as_ref().unwrap(), Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
        .chain(receivers.iter_mut())
        .collect();
    pump(&mut all, |_| {
        while sent < 64 {
            match lane.offer(&sent.to_le_bytes()).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        seen == 64
    });
    let removed = a.network_removed_destinations(&publication);
    assert!(
        removed
            .iter()
            .any(|removal| removal.destination == addresses[0]
                && removal.reason == RemovalReason::Command),
        "{removed:?}"
    );
}

/// ADR-0082: a required destination is fixed at creation. It is never
/// removed or added at run time, and a restart of its receiver (a new boot
/// at the same endpoint) is rejected: the old member is lost and the
/// publication's admission is `LostRequired`.
#[test]
fn a_required_destination_neither_moves_nor_restarts() {
    use crate::agents::data::DestinationChange;
    use karyos_protocol::cnc::NetworkAdmission;

    let mut a = super::fast_driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers(2);
    let (publication, _) = connect(
        &mut a,
        &mut receivers,
        &destinations(&addresses, false),
        &addresses[..1],
        None,
    );
    a.remove_network_destination(&publication, addresses[0])
        .unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (addresses[0], DestinationChange::Required)
    );
    a.add_network_destination(&publication, addresses[0])
        .unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (addresses[0], DestinationChange::Required)
    );
    // The required receiver restarts at the same endpoint: a new driver,
    // a new boot id.
    let old = receivers.remove(0);
    drop(old);
    let mut restarted = super::fast_driver(ThreadingMode::Shared);
    let _ = restarted
        .add_network_subscription(10, &channel(addresses[0], false))
        .unwrap();
    assert_eq!(bound(&restarted, 10), addresses[0], "the same endpoint");
    receivers.insert(0, restarted);
    let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
        .chain(receivers.iter_mut())
        .collect();
    pump(&mut all, |drivers| {
        drivers[0].network_publication_admission(&publication)
            == Some(NetworkAdmission::LostRequired)
    });
    // The restarted receiver is never readmitted in its place.
    for _ in 0..2_000 {
        for driver in all.iter_mut() {
            let _ = driver.do_work().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_micros(100));
    }
    assert_eq!(
        all[0].network_publication_admission(&publication),
        Some(NetworkAdmission::LostRequired)
    );
}

/// Design 3.7: a removed destination is reported and retired, as a
/// removed publication is: its queues and route close at the next duty
/// and its slot is freed then. Twenty moves of an
/// optional destination never answer `Full`, never fail to open, and leave
/// the publication with its two destinations; the removal history keeps
/// the newest sixteen and counts the rest.
#[test]
fn twenty_moves_neither_fill_the_table_nor_leak() {
    use crate::agents::data::DestinationChange;

    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers(1);
    // Destinations nobody listens on: routed and opened, never live.
    let reserved = Reserved::new(21);
    let moving = |index: u16| reserved.at(usize::from(index));
    let (publication, _) = connect(
        &mut a,
        &mut receivers,
        &destinations(&[addresses[0], moving(0)], false),
        &[],
        None,
    );
    for index in 0..20u16 {
        a.remove_network_destination(&publication, moving(index))
            .unwrap();
        assert_eq!(
            answer(&mut a, &mut receivers, &publication),
            (moving(index), DestinationChange::Removed)
        );
        let retired = u64::from(index) + 1;
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |drivers| {
            super::shared(drivers[0])
                .sender
                .outbound_counters(0)
                .unwrap()
                .destinations_retired
                == retired
        });
        a.add_network_destination(&publication, moving(index + 1))
            .unwrap();
        assert_eq!(
            answer(&mut a, &mut receivers, &publication),
            (moving(index + 1), DestinationChange::Added)
        );
    }
    let sender = &super::shared(&mut a).sender;
    let destinations: Vec<SocketAddr> = sender
        .destination_counters(0)
        .into_iter()
        .map(|(address, _)| address)
        .collect();
    assert_eq!(destinations, [addresses[0], moving(20)]);
    let counters = sender.outbound_counters(0).unwrap();
    assert_eq!(counters.destinations_retired, 20);
    assert_eq!(
        (counters.route_failures, counters.queue_failures),
        (0, 0),
        "{counters:?}"
    );
    assert_eq!(a.network_removed_destinations(&publication).len(), 16);
    assert_eq!(a.network_removals_overwritten(&publication), 4);
}

/// Plan 157, point 2: a move at `MAX_DESTINATIONS` answers `Full` while
/// the removed destination holds its slot, and once its removal shows in
/// `network_removed_destinations` (it is reported in the cycle of the
/// removal, which hands its route and queues to the close list), the move
/// retried is added. It checks the public contract end to end in both
/// threading modes; the cycle order it relies on is guarded by the sender
/// test `a_move_right_after_the_report_is_added_in_the_cycle_order`, and
/// the bound by the unit churn test.
#[test]
fn a_move_at_capacity_waits_for_the_removal_to_retire() {
    move_at_capacity(ThreadingMode::Shared);
    move_at_capacity(ThreadingMode::Dedicated);
}

/// [`a_move_at_capacity_waits_for_the_removal_to_retire`] in `threading`.
fn move_at_capacity(threading: ThreadingMode) {
    use crate::agents::data::{DestinationChange, MAX_DESTINATIONS};

    let mut a = driver(threading);
    let (mut receivers, addresses) = receivers(1);
    // Index 0 is unused; the move goes to the last.
    let reserved = Reserved::new(MAX_DESTINATIONS + 1);
    let at = |index: usize| reserved.at(index);
    let (publication, _) = connect(
        &mut a,
        &mut receivers,
        &destinations(&addresses, false),
        &[],
        None,
    );
    for index in 1..MAX_DESTINATIONS {
        a.add_network_destination(&publication, at(index)).unwrap();
        assert_eq!(
            answer(&mut a, &mut receivers, &publication),
            (at(index), DestinationChange::Added)
        );
    }
    a.remove_network_destination(&publication, at(1)).unwrap();
    a.add_network_destination(&publication, at(MAX_DESTINATIONS))
        .unwrap();
    let mut answers = Vec::new();
    {
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |drivers| {
            answers.extend(drivers[0].take_network_destination_changes(&publication));
            answers.len() == 2
        });
    }
    let changes: Vec<DestinationChange> = answers.iter().map(|(_, change)| *change).collect();
    match threading {
        // One thread serves the two commands back to back, before the
        // removal is reported.
        ThreadingMode::Shared => assert_eq!(
            changes,
            [DestinationChange::Removed, DestinationChange::Full],
            "the slot is held until the removal retires"
        ),
        // The sender's thread may report, retire and close the removal
        // between the two posts: either answer, then the end state below.
        _ => assert!(
            matches!(
                changes.as_slice(),
                [
                    DestinationChange::Removed,
                    DestinationChange::Full | DestinationChange::Added
                ]
            ),
            "{changes:?}"
        ),
    }
    let added_early = changes.last() == Some(&DestinationChange::Added);
    // The public signal: once the removal shows, a retried move is added.
    let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
        .chain(receivers.iter_mut())
        .collect();
    pump(&mut all, |drivers| {
        drivers[0]
            .network_removed_destinations(&publication)
            .iter()
            .any(|removal| removal.destination == at(1))
    });
    let expected = if added_early {
        DestinationChange::Present
    } else {
        DestinationChange::Added
    };
    a.add_network_destination(&publication, at(MAX_DESTINATIONS))
        .unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (at(MAX_DESTINATIONS), expected)
    );
}

/// Design 3.7, MD-8: a destination removed and added back after its
/// quarantine is a fresh one: nothing of its old repair path, jobs or
/// counts, reaches the receiver's new incarnation.
#[test]
fn a_destination_added_back_starts_with_a_fresh_repair_path() {
    use crate::agents::data::DestinationChange;

    // Images retire within 100 ms: the quarantine is that short too.
    let mut a = super::fast_driver(ThreadingMode::Shared);
    let mut receivers: Vec<EmbeddedDriver> = (0..2)
        .map(|_| super::fast_driver(ThreadingMode::Shared))
        .collect();
    let addresses: Vec<SocketAddr> = receivers
        .iter_mut()
        .map(|receiver| {
            let _ = receiver
                .add_network_subscription(10, &channel(ANY_PORT, true))
                .unwrap();
            bound(receiver, 10)
        })
        .collect();
    let (publication, images) = connect(
        &mut a,
        &mut receivers,
        &destinations(&addresses, true),
        &[],
        None,
    );
    // The first receiver loses a datagram, which is repaired to it.
    super::shared(&mut receivers[0]).receiver.drop_data(&[1]);
    let mut reader = receivers[0]
        .subscribe_aggregate(&images[0], Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    let repairs = |driver: &mut EmbeddedDriver| {
        super::shared(driver)
            .sender
            .destination_counters(0)
            .into_iter()
            .find(|(address, _)| *address == addresses[0])
            .map(|(_, counters)| counters.repairs)
    };
    {
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
            let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
            seen == 16
        });
    }
    assert!(repairs(&mut a).unwrap() >= 1);
    a.remove_network_destination(&publication, addresses[0])
        .unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (addresses[0], DestinationChange::Removed)
    );
    // Added back once its quarantine has passed.
    let mut added = None;
    for _ in 0..200 {
        a.add_network_destination(&publication, addresses[0])
            .unwrap();
        let (_, outcome) = answer(&mut a, &mut receivers, &publication);
        if outcome == DestinationChange::Added {
            added = Some(outcome);
            break;
        }
        assert_eq!(outcome, DestinationChange::Quarantined);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(added, Some(DestinationChange::Added));
    assert_eq!(repairs(&mut a), Some(0), "a fresh repair path");
}

/// MD-8: each destination's repair cap is the job table's share for
/// `MAX_DESTINATIONS`, so a reliable publication grown to sixteen
/// destinations at run time never holds more jobs than its table.
#[test]
fn additions_never_overcommit_the_repair_job_table() {
    use crate::agents::data::{DestinationChange, MAX_DESTINATIONS};
    use crate::repair::jobs::JobsConfig;

    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers_on(1, true);
    let (publication, _) = connect(
        &mut a,
        &mut receivers,
        &destinations(&addresses, true),
        &[],
        None,
    );
    let table = JobsConfig::default().repair_jobs;
    let reserved = Reserved::new(MAX_DESTINATIONS);
    for port in 0..u16::try_from(MAX_DESTINATIONS).unwrap() {
        a.add_network_destination(&publication, reserved.at(usize::from(port)))
            .unwrap();
        let (_, outcome) = answer(&mut a, &mut receivers, &publication);
        let capacity = super::shared(&mut a).sender.fanout_job_capacity(0);
        assert!(capacity <= table, "{capacity} jobs over a table of {table}");
        if usize::from(port) + 1 < MAX_DESTINATIONS {
            assert_eq!(outcome, DestinationChange::Added);
        } else {
            assert_eq!(outcome, DestinationChange::Full);
        }
    }
    assert_eq!(super::shared(&mut a).sender.fanout_job_capacity(0), table);
}

/// MD-15: a destination added at run time joins at the cursor when it goes
/// live, so its sent frontier never holds the publication's below it: one
/// added after the traffic, with nothing of its own to send, does not keep
/// the publication from its EOS, which reaches both receivers.
#[test]
fn a_late_destination_does_not_hold_the_eos() {
    use crate::agents::data::DestinationChange;

    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers(2);
    let (publication, images) = {
        let (first, _) = receivers.split_at_mut(1);
        connect(
            &mut a,
            first,
            &destinations(&addresses[..1], false),
            &[],
            None,
        )
    };
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut first = receivers[0]
        .subscribe_aggregate(&images[0], Role::Required)
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    {
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |_| {
            while sent < 8 {
                match lane.offer(&sent.to_le_bytes()).unwrap() {
                    OfferOutcome::Accepted { .. } => sent += 1,
                    _ => break,
                }
            }
            let _ = first.poll(|_, _, _| seen += 1, BUDGET);
            seen == 8
        });
    }
    a.add_network_destination(&publication, addresses[1])
        .unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (addresses[1], DestinationChange::Added)
    );
    let mut image = None;
    {
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |drivers| {
            image = drivers[2].network_image(10, 3);
            image.is_some()
        });
    }
    let mut second = receivers[1]
        .subscribe_aggregate(image.as_ref().unwrap(), Role::Required)
        .unwrap();
    drop(lane);
    a.remove_aggregate(&publication).unwrap();
    let mut ends = [None, None];
    let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
        .chain(receivers.iter_mut())
        .collect();
    pump(&mut all, |_| {
        for (reader, end) in [&mut first, &mut second].into_iter().zip(&mut ends) {
            let poll = reader.poll(|_, _, _| {}, BUDGET);
            if poll.terminal.is_some() {
                *end = Some(poll.lanes[0].end);
            }
        }
        ends.iter().all(Option::is_some)
    });
    for end in ends {
        assert!(
            matches!(
                end,
                Some(Some(LaneEnd::Closed {
                    reason: SealReason::EndOfStream,
                    ..
                }))
            ),
            "{end:?}"
        );
    }
}

/// Review N1: the address family is the publication's, kept when every
/// destination has been removed, so an addition still answers `Added`, and
/// one of another family `Unknown`.
#[test]
fn an_addition_after_every_destination_removed_is_still_taken() {
    use crate::agents::data::DestinationChange;

    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers(1);
    let reserved = Reserved::new(2);
    let lone = reserved.at(0);
    let (publication, _) = connect(
        &mut a,
        &mut receivers,
        &destinations(&[addresses[0], lone], false),
        &[],
        None,
    );
    for gone in [addresses[0], lone] {
        a.remove_network_destination(&publication, gone).unwrap();
        assert_eq!(
            answer(&mut a, &mut receivers, &publication),
            (gone, DestinationChange::Removed)
        );
    }
    // No destination is left: the publication is not served, so its
    // removed targets retire only once one is added and served again.
    let next = reserved.at(1);
    a.add_network_destination(&publication, next).unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (next, DestinationChange::Added)
    );
    // Of another family, so no IPv4 receiver can hold it.
    let v6: SocketAddr = "[::1]:43002".parse().unwrap();
    a.add_network_destination(&publication, v6).unwrap();
    assert_eq!(
        answer(&mut a, &mut receivers, &publication),
        (v6, DestinationChange::Unknown)
    );
}

/// MD-12, review N3: an endpoint reset is not a send fault of any
/// destination. Three resets, each reopening the endpoint between rounds
/// of traffic, remove no optional destination, the idle one included.
#[test]
fn endpoint_resets_remove_no_optional_destination() {
    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers(1);
    let reserved = Reserved::new(1);
    let idle = reserved.at(0);
    let (publication, images) = connect(
        &mut a,
        &mut receivers,
        &destinations(&[addresses[0], idle], false),
        &[],
        None,
    );
    let (endpoint, alias) = a
        .net
        .as_ref()
        .unwrap()
        .publication_route(publication.registration())
        .unwrap();
    let mut reader = receivers[0]
        .subscribe_aggregate(&images[0], Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    for (reset, until) in (0..=3u64).zip([16u32, 32, 48, 64]) {
        if reset > 0 {
            a.net
                .as_ref()
                .unwrap()
                .links()
                .sender
                .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
                .unwrap();
        }
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |drivers| {
            while sent < until {
                match lane.offer(&sent.to_le_bytes()).unwrap() {
                    OfferOutcome::Accepted { .. } => sent += 1,
                    _ => break,
                }
            }
            let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
            drivers[0].net.as_ref().unwrap().reopened() >= reset && seen >= until
        });
    }
    assert!(a.network_removed_destinations(&publication).is_empty());
    let destinations: Vec<SocketAddr> = super::shared(&mut a)
        .sender
        .destination_counters(0)
        .into_iter()
        .map(|(address, _)| address)
        .collect();
    assert_eq!(destinations, [addresses[0], idle]);
    // Review B3 of #829: the resets' refused opens are not limits.
    let counters = super::shared(&mut a).sender.outbound_counters(0).unwrap();
    assert_eq!(counters.endpoint_limits, 0, "{counters:?}");
}

/// MD-20 (karyos#802): a reliable publication whose endpoint resets three
/// times between rounds of traffic catches each destination up by its own
/// repair path instead of resending everything to all of them: both
/// receivers still get every message, in order and exactly once, and no
/// destination is removed.
#[test]
fn a_reliable_reset_catches_each_destination_up_in_order() {
    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers_on(2, true);
    let (publication, images) = connect(
        &mut a,
        &mut receivers,
        &destinations(&addresses, true),
        &[],
        None,
    );
    let (endpoint, alias) = a
        .net
        .as_ref()
        .unwrap()
        .publication_route(publication.registration())
        .unwrap();
    let mut second = receivers.pop().unwrap();
    let mut first = receivers.pop().unwrap();
    let mut readers = [
        first
            .subscribe_aggregate(&images[0], Role::Required)
            .unwrap(),
        second
            .subscribe_aggregate(&images[1], Role::Required)
            .unwrap(),
    ];
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut sent = 0u32;
    let mut seen = [0u32; 2];
    for (reset, until) in (0..=3u64).zip([64u32, 128, 192, 256]) {
        if reset > 0 {
            a.net
                .as_ref()
                .unwrap()
                .links()
                .sender
                .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
                .unwrap();
        }
        pump(&mut [&mut a, &mut first, &mut second], |drivers| {
            while sent < until {
                match lane.offer(&sent.to_le_bytes()).unwrap() {
                    OfferOutcome::Accepted { .. } => sent += 1,
                    _ => break,
                }
            }
            for (reader, count) in readers.iter_mut().zip(seen.iter_mut()) {
                let _ = reader.poll(
                    |bytes, _, _| {
                        let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                        assert_eq!(index, *count, "in order, exactly once");
                        *count += 1;
                    },
                    BUDGET,
                );
            }
            drivers[0].net.as_ref().unwrap().reopened() >= reset
                && seen.iter().all(|count| *count >= until)
        });
    }
    assert_eq!(seen, [256, 256]);
    assert!(a.network_removed_destinations(&publication).is_empty());
    // That nothing below a reset's position goes twice to a destination
    // that had it is shown frame by frame at driver level
    // (`agents::data::tests::a_reset_resends_only_what_each_destination_lacks`):
    // here receivers drop copies, and the per-destination repair counts
    // also carry NAK repairs for loopback loss, so no count would tell it.
}

/// karyos#859: an idle multi-destination publication sends each
/// destination its idle DATA heartbeats, which are image evidence, not path
/// evidence (RP-2). Whether each destination's subscriber keeps its path
/// through `KARYOS_IDLE_SECS` (default 25) idle seconds, or loses it at
/// `path_liveness_timeout` and binds it again by SOLICIT: a measurement.
#[test]
#[ignore = "a measurement: KARYOS_IDLE_SECS idle seconds"]
#[allow(
    clippy::print_stdout,
    reason = "a measurement printed to the job's log"
)]
fn m859_an_idle_multi_destination_publication_keeps_its_paths() {
    use std::time::{Duration, Instant};

    let secs = std::env::var("KARYOS_IDLE_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(25u64);
    let mut a = driver(ThreadingMode::Shared);
    let (mut receivers, addresses) = receivers_on(2, true);
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &destinations(&addresses, true))
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
    let start = Instant::now();
    let mut next = Duration::from_secs(5);
    while start.elapsed() < Duration::from_secs(secs) {
        let _ = a.do_work().unwrap();
        for receiver in &mut receivers {
            let _ = receiver.do_work().unwrap();
        }
        if start.elapsed() >= next {
            next += Duration::from_secs(5);
            for (index, receiver) in receivers.iter().enumerate() {
                let counters = receiver.net.as_ref().unwrap().receiver_counters().unwrap();
                println!(
                    "idle_destinations {:>3} s receiver {index}: paths_bound {} data_unbound {} path_heartbeats {} heartbeats {} stationary {} images {}",
                    start.elapsed().as_secs(),
                    counters.paths_bound,
                    counters.data_unbound,
                    counters.path_heartbeats,
                    counters.heartbeats,
                    counters.heartbeats_stationary,
                    receiver.net.as_ref().unwrap().image_count(),
                );
            }
        }
        std::thread::sleep(Duration::from_micros(100));
    }
}

/// karyos#859: an idle multi-destination publication sends each live
/// destination a PATH_HB, so each subscriber keeps its path through three
/// `path_liveness_timeout`s (1 s here) and binds nothing again. Without it
/// each path was lost at the timeout and bound again by SOLICIT.
#[test]
fn an_idle_multi_destination_publication_keeps_each_path() {
    use std::time::{Duration, Instant};

    let mut agents = crate::agents::AgentConfig::default();
    agents.sessions.path_liveness_timeout = 1_000_000_000;
    let mut a = driver(ThreadingMode::Shared);
    let mut receivers = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..2 {
        let mut receiver = driver_with(ThreadingMode::Shared, agents);
        let _ = receiver
            .add_network_subscription(10, &channel(ANY_PORT, true))
            .unwrap();
        addresses.push(bound(&receiver, 10));
        receivers.push(receiver);
    }
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &destinations(&addresses, true))
        .unwrap();
    {
        let mut all: Vec<&mut EmbeddedDriver> = std::iter::once(&mut a)
            .chain(receivers.iter_mut())
            .collect();
        pump(&mut all, |drivers| {
            drivers
                .iter()
                .skip(1)
                .all(|receiver| receiver.network_image(10, 3).is_some())
        });
    }
    let bound_before: Vec<u64> = receivers
        .iter()
        .map(|receiver| {
            receiver
                .net
                .as_ref()
                .unwrap()
                .receiver_counters()
                .unwrap()
                .paths_bound
        })
        .collect();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        let _ = a.do_work().unwrap();
        for receiver in &mut receivers {
            let _ = receiver.do_work().unwrap();
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    for (receiver, before) in receivers.iter().zip(bound_before) {
        let counters = receiver.net.as_ref().unwrap().receiver_counters().unwrap();
        assert_eq!(
            counters.paths_bound, before,
            "a path bound again: {counters:?}"
        );
        assert_eq!(counters.data_unbound, 0, "a path lost: {counters:?}");
        assert!(counters.path_heartbeats > 0);
    }
}
