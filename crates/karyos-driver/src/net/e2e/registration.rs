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
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &channel,
            allowlist([10, 0, 0, 0], 8),
            None,
        )
        .unwrap();
    let _inside = a
        .add_dynamic_network_publication(
            aggregate(11, 4, 1),
            &channel,
            allowlist([127, 0, 0, 0], 8),
            None,
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
        .add_dynamic_network_publication(aggregate(10, 3, 1), &channel, lan(), None)
        .unwrap();
    assert!(matches!(
        a.add_dynamic_network_publication(aggregate(10, 5, 1), &channel, lan(), None),
        Err(DriverError::DynamicPublicationExists { stream_id: 10 })
    ));
    assert!(
        a.add_dynamic_network_publication(aggregate(11, 6, 1), &channel, lan(), None)
            .is_ok()
    );
}

/// What a dynamic publication does not take: listed destinations, an
/// interface, or an allowlist on another channel. A call that carries no
/// allowlist refuses dynamic mode, and no allowlist is empty: a missing
/// allowlist is a refusal, never a permissive default (ADR-0082).
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
        a.add_dynamic_network_publication(aggregate(10, 3, 1), &listed, lan(), None),
        Err(DriverError::UnsupportedChannel)
    ));
    let mut bound = dynamic(control);
    bound.interface = Some(Interface::Address(LOOPBACK));
    assert!(matches!(
        a.add_dynamic_network_publication(aggregate(10, 3, 1), &bound, lan(), None),
        Err(DriverError::UnsupportedChannel)
    ));
    let unicast = super::channel(SocketAddr::new(LOOPBACK, free_port()), false);
    assert!(matches!(
        a.add_dynamic_network_publication(aggregate(10, 3, 1), &unicast, lan(), None),
        Err(DriverError::UnsupportedChannel)
    ));
    for refused in [
        a.add_network_publication(aggregate(10, 3, 1), &dynamic(control)),
        a.add_network_publication_with_roles(
            aggregate(10, 3, 1),
            &dynamic(control),
            crate::membership::PublicationRoles {
                strategy: crate::membership::Strategy::Min,
                required: Vec::new(),
                tags: Vec::new(),
            },
        ),
        a.add_network_publication_with_destinations(
            aggregate(10, 3, 1),
            &dynamic(control),
            None,
            &[],
        ),
    ] {
        assert!(matches!(
            refused,
            Err(DriverError::DynamicRegistrationUnsupported)
        ));
    }
    assert_eq!(
        RegistrationAllowlist::new(&[]),
        Err(crate::sessions::register::RegistrationConfigError::EmptyAllowlist)
    );
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

/// The configured identity of receiver `receiver_id`.
fn as_receiver(receiver_id: u64) -> crate::membership::ReceiverIdentity {
    crate::membership::ReceiverIdentity {
        receiver_id: std::num::NonZeroU64::new(receiver_id).unwrap(),
        group_tag: 0,
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
            None,
        )
        .unwrap();
    let _subscription = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
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
            None,
        )
        .unwrap();
    let _inside = a
        .add_dynamic_network_publication(
            aggregate(11, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
            None,
        )
        .unwrap();
    let _refused = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    let _admitted = b
        .add_dynamic_network_subscription(11, &subscribed(control), as_receiver(1))
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
            None,
        )
        .unwrap();
    let _joined = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    let image = image_of(&mut a, &mut b, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(karyos_sys::frame::Lane::ZERO).unwrap())
        .unwrap();
    super::exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..16);
    assert_eq!(occupancy(&mut a, 10), 1, "B alone before C registers");
    let _refused = c
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(2))
        .unwrap();
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        receiver(drivers[2]).registration_refusals >= 1
    });
    assert!(c.network_image(10, 3).is_none());
    assert!(registrations(&a).refused_full >= 1);
    // The ERR leaves the table as it was (SPEC §13 "Multi-destination
    // isolation", karyos#645): the same one occupied entry, no pending
    // entry left by C's REGISTER, and by the lifecycle counters one
    // destination joined, none refused at a first SM, none removed.
    assert_eq!(occupancy(&mut a, 10), 1, "C's REGISTER left an entry");
    let counters = sender(&a);
    assert_eq!(counters.registrants_joined, 1);
    assert_eq!(counters.registrants_refused, 0);
    assert_eq!(counters.registrants_timed_out, 0);
    super::exchange_on(&mut a, &mut b, &mut lane, &mut reader, 16..32);
}

/// A subscription call that carries no receiver identity refuses dynamic
/// mode, and the dynamic call refuses a channel that is not dynamic.
#[test]
fn a_dynamic_subscription_needs_its_identity_and_a_dynamic_channel() {
    let mut b = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    assert!(matches!(
        b.add_network_subscription(10, &subscribed(control)),
        Err(DriverError::DynamicRegistrationUnsupported)
    ));
    assert!(matches!(
        b.add_network_subscription_as(10, &subscribed(control), as_receiver(1)),
        Err(DriverError::DynamicRegistrationUnsupported)
    ));
    let unicast = super::channel(SocketAddr::new(LOOPBACK, free_port()), true);
    assert!(matches!(
        b.add_dynamic_network_subscription(10, &unicast, as_receiver(1)),
        Err(DriverError::UnsupportedChannel)
    ));
}

/// The entries `driver`'s first publication, of `stream_id`, occupies:
/// its destinations plus its pending registrations.
fn occupancy(driver: &mut EmbeddedDriver, stream_id: i32) -> usize {
    let sender = &super::shared(driver).sender;
    sender.destination_counters(0).len() + sender.pending_registrations(stream_id)
}

/// `driver`'s sender counters.
fn sender(driver: &EmbeddedDriver) -> crate::agents::roles::SenderCounters {
    driver.net.as_ref().unwrap().sender_counters().unwrap()
}

/// MD-17 between drivers: a publication of `max_destinations` 2 with
/// required receiver 42. Optional receiver 1 joins and takes the one
/// optional slot; optional receiver 2 is answered ERR; receiver 42 still
/// joins in its reserved slot, which opens admission, and receives.
#[test]
fn a_required_receiver_joins_after_optional_registrants_fill_their_quota() {
    use crate::membership::{PublicationRoles, Strategy};

    let agents = AgentConfig {
        max_destinations: 2,
        ..AgentConfig::default()
    };
    let mut a = driver_with(ThreadingMode::Shared, agents);
    let (mut b, mut c, mut d) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    let control = SocketAddr::new(LOOPBACK, free_port());
    let roles = PublicationRoles {
        strategy: Strategy::Min,
        required: vec![42],
        tags: Vec::new(),
    };
    let publication = a
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
            Some(roles),
        )
        .unwrap();
    let _optional = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_image(10, 3).is_some()
    });
    let _refused = c
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(2))
        .unwrap();
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        receiver(drivers[2]).registration_refusals >= 1
    });
    let _required = d
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(42))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b, &mut c, &mut d], |drivers| {
        image = drivers[3].network_image(10, 3);
        image.is_some()
    });
    let mut reader = d
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(karyos_sys::frame::Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    pump(&mut [&mut a, &mut b, &mut c, &mut d], |_| {
        while sent < 16 {
            let payload = sent.to_le_bytes();
            match lane.offer(&payload).unwrap() {
                karyos_client::OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                assert_eq!(bytes[..4], seen.to_le_bytes(), "in order, exactly once");
                seen += 1;
            },
            super::BUDGET,
        );
        seen == 16
    });
    assert!(c.network_image(10, 3).is_none());
    assert_eq!(sender(&a).registrants_joined, 2);
}

/// Design 3.2 step 4 between drivers: receiver 1's driver goes and a new
/// one (a new boot id) registers with the same `receiver_id` from another
/// port. Its first SM retires the old destination (reason `restarted`)
/// and the new one binds.
#[test]
fn a_restarted_receiver_replaces_its_old_destination() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let _publication = a
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
            None,
        )
        .unwrap();
    let _first = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    let _ = image_of(&mut a, &mut b, 10);
    drop(b);
    let mut restarted = driver(ThreadingMode::Shared);
    let _again = restarted
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    let _ = image_of(&mut a, &mut restarted, 10);
    pump(&mut [&mut a], |drivers| {
        sender(drivers[0]).registrants_restarted >= 1
    });
    assert_eq!(sender(&a).registrants_joined, 2);
}

/// MD-19 between drivers: receiver 1 unsubscribes and subscribes again in
/// the same driver, so the same receiver block registers from a new port.
/// Once its old destination has been quiet for `destination_move_quiet`
/// its membership moves there (reason `moved`) and it receives again. The
/// receiver keeps a retired incarnation out for `alias_quarantine`
/// (network-sessions.md, "Fresh establishment"), 1 ms here so that the
/// same incarnation can be set up again at the new port.
#[test]
fn a_receiver_back_at_a_new_port_moves_after_the_quiet_time() {
    let mut a = driver(ThreadingMode::Shared);
    let mut quick = AgentConfig::default();
    quick.sessions.alias_quarantine = 1_000_000;
    let mut b = driver_with(ThreadingMode::Shared, quick);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let publication = a
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
            None,
        )
        .unwrap();
    let first = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    let _ = image_of(&mut a, &mut b, 10);
    b.remove_network_subscription(first).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        receiver(drivers[1]).images_retired >= 1
    });
    let _again = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    let image = image_of(&mut a, &mut b, 10);
    pump(&mut [&mut a], |drivers| {
        sender(drivers[0]).registrants_moved >= 1
    });
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(karyos_sys::frame::Lane::ZERO).unwrap())
        .unwrap();
    super::exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..16);
    assert_eq!(sender(&a).registrants_restarted, 0);
}

/// Every public publication and subscription call refuses a
/// `control-mode=dynamic` channel with
/// [`DriverError::DynamicRegistrationUnsupported`]: dynamic mode stays
/// unreachable from outside the crate until the registration defects
/// reported on karyos#644 are fixed.
#[test]
fn every_public_call_refuses_dynamic_mode() {
    use karyos_client::schedule::{ScheduleClock, ScheduleOptions};
    use karyos_sys::conflation::ConflationConfig;
    use karyos_sys::frame::Lane;

    let mut a = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let channel = dynamic(control);
    let guard = a.add_guard("dynamic").unwrap();
    let options = ScheduleOptions::default();
    let clock = ScheduleClock::host(options.domain).unwrap();
    // Valid for each call, so that only the channel is refused: spare
    // slots for a guard, a schedule ring for a timed lane.
    let config = || {
        let mut config = aggregate(10, 3, 1);
        config.stream.buffer.spare_slots = 4;
        config.stream.buffer.schedule_capacity = 4;
        config
    };
    let publications = [
        a.add_network_publication(config(), &channel),
        a.add_network_publication_with_roles(
            config(),
            &channel,
            crate::membership::PublicationRoles {
                strategy: crate::membership::Strategy::Min,
                required: Vec::new(),
                tags: Vec::new(),
            },
        ),
        a.add_network_publication_with_destinations(config(), &channel, None, &[]),
        a.add_guarded_network_publication(
            config(),
            &channel,
            crate::net::NetworkGuard {
                guard,
                messages: 2,
                rate: None,
            },
        ),
        a.add_timed_network_publication(config(), &channel, None, options),
        a.add_timed_network_publication_with_clock(config(), &channel, None, options, clock),
    ];
    for (call, refused) in publications.into_iter().enumerate() {
        assert!(
            matches!(refused, Err(DriverError::DynamicRegistrationUnsupported)),
            "publication call {call}: {refused:?}"
        );
    }
    let mut b = driver(ThreadingMode::Shared);
    let subscribed = subscribed(control);
    let subscriptions = [
        b.add_network_subscription(10, &subscribed),
        b.add_network_subscription_as(10, &subscribed, as_receiver(1)),
        b.add_network_subscription_conflated(
            10,
            &subscribed,
            Lane::ZERO,
            ConflationConfig {
                keys: 4,
                value_capacity: 8,
                journal_capacity: 1024,
                refresh: false,
            },
        ),
    ];
    for refused in subscriptions {
        assert!(
            matches!(refused, Err(DriverError::DynamicRegistrationUnsupported)),
            "{:?}",
            refused.err()
        );
    }
}

/// Subscriptions of streams `10..10 + count` on one driver, all
/// registering at one `control` address, with their publisher started
/// three seconds later (karyos#941 item 1): each binds. The three seconds
/// are the scenario, long past the REGISTER burst of every key; the end is
/// synchronised on the images, with no sleep.
fn subscriptions_bind_with_their_publisher_started_later(count: i32) {
    use crate::sessions::register::RegistrationState;

    let streams = 10..10 + count;
    let agents = AgentConfig {
        receiver_bindings: 128,
        ..AgentConfig::default()
    };
    let mut a = driver_with(ThreadingMode::Shared, agents);
    let mut b = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let subscriptions: Vec<_> = streams
        .clone()
        .map(|stream| {
            b.add_dynamic_network_subscription(stream, &subscribed(control), as_receiver(1))
                .unwrap()
        })
        .collect();
    let start = std::time::Instant::now();
    pump(&mut [&mut b], |_| {
        start.elapsed() >= std::time::Duration::from_secs(3)
    });
    // Nothing answered: each shows it is still registering, and backed
    // off from ten REGISTERs a second per key.
    for subscription in &subscriptions {
        assert_eq!(
            b.network_registration_state(*subscription),
            Some(RegistrationState::Registering)
        );
    }
    let sent = receiver(&b).registers_sent;
    let keys = u64::try_from(count).unwrap();
    assert!(sent < keys * 30, "{sent} REGISTERs in 3 s");
    let _publications: Vec<_> = streams
        .clone()
        .map(|stream| {
            a.add_dynamic_network_publication(
                aggregate(stream, 3, 1),
                &reliable(control),
                allowlist([127, 0, 0, 0], 8),
                None,
            )
            .unwrap()
        })
        .collect();
    pump(&mut [&mut a, &mut b], |drivers| {
        streams
            .clone()
            .all(|stream| drivers[1].network_image(stream, 3).is_some())
    });
    pump(&mut [&mut a, &mut b], |drivers| {
        subscriptions.iter().all(|subscription| {
            drivers[1].network_registration_state(*subscription) == Some(RegistrationState::Bound)
        })
    });
}

/// karyos#941 item 1, as the issue reproduced it: three dynamic
/// subscriptions to one control address bind when their publisher starts
/// after them. Their REGISTERs no longer spend the bucket the CHALLENGE
/// answering the publisher's ANNOUNCE needs, at the receiver or at the
/// sender.
#[test]
fn three_dynamic_subscriptions_to_one_control_bind_with_their_publisher_started_later() {
    subscriptions_bind_with_their_publisher_started_later(3);
}

/// [`three_dynamic_subscriptions_to_one_control_bind_with_their_publisher_started_later`]
/// with five, the other count the issue reproduced.
#[test]
fn five_dynamic_subscriptions_to_one_control_bind_with_their_publisher_started_later() {
    subscriptions_bind_with_their_publisher_started_later(5);
}

/// karyos#941 item 2: `receiver_bindings` below `max_destinations` is
/// refused at driver start, where a required receiver id could be kept
/// out by a table full of optional bindings (the issue's case,
/// `max_destinations` 3 and `receiver_bindings` 2).
#[test]
fn receiver_bindings_below_max_destinations_are_refused_at_start() {
    let refused = EmbeddedDriver::with_config(crate::embedded::DriverConfig {
        network: Some(crate::net::NetworkConfig {
            threading: ThreadingMode::Shared,
            agents: AgentConfig {
                max_destinations: 3,
                receiver_bindings: 2,
                ..AgentConfig::default()
            },
            ..crate::net::NetworkConfig::default()
        }),
        ..crate::embedded::DriverConfig::default()
    });
    assert!(refused.is_err());
    let equal = AgentConfig {
        max_destinations: 3,
        receiver_bindings: 3,
        ..AgentConfig::default()
    };
    let _ = driver_with(ThreadingMode::Shared, equal);
}

/// karyos#941 item 2: a driver's dynamic publications together take at
/// most `receiver_bindings` destinations, `max_destinations` each; one
/// more is refused naming both numbers.
#[test]
fn dynamic_publications_beyond_receiver_bindings_are_refused() {
    let agents = AgentConfig {
        max_destinations: 3,
        receiver_bindings: 7,
        ..AgentConfig::default()
    };
    let mut a = driver_with(ThreadingMode::Shared, agents);
    let control = SocketAddr::new(LOOPBACK, free_port());
    for stream in [10, 11] {
        assert!(
            a.add_dynamic_network_publication(
                aggregate(stream, 3, 1),
                &dynamic(control),
                allowlist([127, 0, 0, 0], 8),
                None,
            )
            .is_ok()
        );
    }
    assert_eq!(
        a.add_dynamic_network_publication(
            aggregate(12, 3, 1),
            &dynamic(control),
            allowlist([127, 0, 0, 0], 8),
            None,
        )
        .err(),
        Some(DriverError::ReceiverBindings { needed: 9, held: 7 })
    );
}

/// karyos#941 item 2 between drivers: a publication of `max_destinations`
/// 3 with required receiver 42, on a sender with three bindings, one held
/// by a static publication's receiver. Optional receiver 1 joins; optional
/// receiver 2 is announced but gets no ANSWER, since the one free binding
/// is kept for 42, so it keeps registering and installs no image. Receiver
/// 42 then joins and receives. Before the fix receiver 2 took the binding
/// and 42 was answered, believed itself bound and stopped registering
/// while the sender dropped its SMs.
#[test]
fn a_required_receiver_joins_with_the_other_bindings_taken() {
    use crate::membership::{PublicationRoles, Strategy};
    use crate::sessions::register::RegistrationState;

    let agents = AgentConfig {
        max_destinations: 3,
        receiver_bindings: 3,
        ..AgentConfig::default()
    };
    let mut a = driver_with(ThreadingMode::Shared, agents);
    let (mut s, mut b, mut c, mut d) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    let _static = super::connected(&mut a, &mut s, true, 20);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let roles = PublicationRoles {
        strategy: Strategy::Min,
        required: vec![42],
        tags: Vec::new(),
    };
    let publication = a
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
            Some(roles),
        )
        .unwrap();
    let _optional = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    pump(&mut [&mut a, &mut s, &mut b], |drivers| {
        drivers[2].network_image(10, 3).is_some()
    });
    let kept_out = c
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(2))
        .unwrap();
    // It keeps registering past its first exchanges, where an answered
    // receiver stops.
    pump(&mut [&mut a, &mut s, &mut b, &mut c], |drivers| {
        receiver(drivers[3]).registers_sent >= 4
    });
    assert!(c.network_image(10, 3).is_none());
    assert_eq!(
        c.network_registration_state(kept_out),
        Some(RegistrationState::Announced)
    );
    let required = d
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(42))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut s, &mut b, &mut c, &mut d], |drivers| {
        image = drivers[4].network_image(10, 3);
        image.is_some()
    });
    let mut reader = d
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(karyos_sys::frame::Lane::ZERO).unwrap())
        .unwrap();
    super::exchange_on(&mut a, &mut d, &mut lane, &mut reader, 0..16);
    assert_eq!(
        d.network_registration_state(required),
        Some(RegistrationState::Bound)
    );
    assert!(c.network_image(10, 3).is_none());
    assert_eq!(sender(&a).registrants_joined, 2);
    assert_eq!(sender(&a).bindings_full, 0);
    assert!(sender(&a).challenges_unbound >= 1);
}

/// karyos#941 item 3 between drivers: a refused dynamic subscription is
/// visible to its application. On a full table its state is `Refused` and
/// the documented CnC cell `registration refusals received` counts the
/// ERR; the joined receiver's state is `Bound`; a subscription outside the
/// allowlist, which gets no reply at all, stays `Registering` while its
/// `registers sent` cell grows.
#[test]
fn a_refused_dynamic_subscription_shows_it_in_its_state_and_the_cnc() {
    use crate::sessions::register::RegistrationState;

    let agents = AgentConfig {
        max_destinations: 1,
        ..AgentConfig::default()
    };
    let mut a = driver_with(ThreadingMode::Shared, agents);
    let (mut b, mut c) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let control = SocketAddr::new(LOOPBACK, free_port());
    let _publication = a
        .add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &reliable(control),
            allowlist([127, 0, 0, 0], 8),
            None,
        )
        .unwrap();
    let _outside = a
        .add_dynamic_network_publication(
            aggregate(11, 3, 1),
            &reliable(control),
            allowlist([10, 0, 0, 0], 8),
            None,
        )
        .unwrap();
    let joined = b
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
        .unwrap();
    let _ = image_of(&mut a, &mut b, 10);
    let refused = c
        .add_dynamic_network_subscription(10, &subscribed(control), as_receiver(2))
        .unwrap();
    let silent = c
        .add_dynamic_network_subscription(11, &subscribed(control), as_receiver(2))
        .unwrap();
    let cell = |driver: &EmbeddedDriver, label| super::cells(driver, label)[0].0;
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        cell(drivers[2], "registration refusals received") >= 1
            && cell(drivers[2], "registers sent") >= 3
            && registrations(drivers[0]).dropped_not_allowed >= 1
    });
    assert_eq!(
        b.network_registration_state(joined),
        Some(RegistrationState::Bound)
    );
    assert_eq!(
        c.network_registration_state(refused),
        Some(RegistrationState::Refused)
    );
    assert_eq!(
        c.network_registration_state(silent),
        Some(RegistrationState::Registering)
    );
    assert_eq!(
        cell(&c, "registration refusals received"),
        receiver(&c).registration_refusals
    );
    // A subscription that does not register has no state.
    let plain = b
        .add_network_subscription(12, &super::channel(super::ANY_PORT, true))
        .unwrap();
    assert_eq!(b.network_registration_state(plain), None);
}

/// An allowlist with no range of `control`'s address family admits no
/// registrant, since step 1 drops every REGISTER of the other family: it
/// is refused at creation, naming `control` (karyos#941 item 7).
#[test]
fn an_allowlist_with_no_range_of_the_control_family_is_refused() {
    use crate::sessions::register::RegistrationConfigError;

    let mut a = driver(ThreadingMode::Shared);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let v6 = AddressRange::new(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]), 128).unwrap();
    let refused = a.add_dynamic_network_publication(
        aggregate(10, 3, 1),
        &dynamic(control),
        RegistrationAllowlist::new(&[v6]).unwrap(),
        None,
    );
    assert_eq!(
        refused.err(),
        Some(DriverError::Registration(
            RegistrationConfigError::AllowlistFamily { control }
        ))
    );
    // One range of the family is enough, beside one of the other.
    let v4 = AddressRange::new(IpAddr::from([127, 0, 0, 0]), 8).unwrap();
    assert!(
        a.add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &dynamic(control),
            RegistrationAllowlist::new(&[v6, v4]).unwrap(),
            None,
        )
        .is_ok()
    );
}

/// Required receiver ids above `max_destinations` are refused with the
/// registration error that names them (karyos#941 item 7; karyos#943
/// M55), not a bare `InvalidConfig`; a repeated one is invalid roles.
#[test]
fn required_ids_the_publication_cannot_hold_are_refused_naming_them() {
    use crate::membership::{PublicationRoles, Strategy};
    use crate::sessions::register::RegistrationConfigError;

    let agents = AgentConfig {
        max_destinations: 2,
        ..AgentConfig::default()
    };
    let mut a = driver_with(ThreadingMode::Shared, agents);
    let control = SocketAddr::new(LOOPBACK, free_port());
    let mut add = |required: Vec<u64>| {
        let roles = PublicationRoles {
            strategy: Strategy::Min,
            required,
            tags: Vec::new(),
        };
        a.add_dynamic_network_publication(
            aggregate(10, 3, 1),
            &dynamic(control),
            allowlist([127, 0, 0, 0], 8),
            Some(roles),
        )
        .err()
    };
    assert_eq!(
        add(vec![41, 42, 43]),
        Some(DriverError::Registration(
            RegistrationConfigError::TooManyRequired {
                required: 3,
                max_destinations: 2,
            }
        ))
    );
    // A repeated id is invalid roles before any registration exists.
    assert_eq!(add(vec![42, 42]), Some(DriverError::InvalidRoles));
    // As many as `max_destinations` is admitted.
    assert_eq!(add(vec![41, 42]), None);
}

/// A hand-built dynamic channel skips the URI parser: a `control` with a
/// zero port, or an unspecified, multicast or broadcast address, is
/// refused naming it, where every REGISTER would count unsent for ever
/// (karyos#941 item 7).
#[test]
fn a_dynamic_subscription_refuses_a_control_no_register_can_reach() {
    let mut b = driver(ThreadingMode::Shared);
    let port = free_port();
    for control in [
        SocketAddr::new(LOOPBACK, 0),
        SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port),
        SocketAddr::new(IpAddr::from([224, 0, 0, 1]), port),
        SocketAddr::new(IpAddr::from([255, 255, 255, 255]), port),
    ] {
        assert_eq!(
            b.add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
                .err(),
            Some(DriverError::InvalidRegistrationControl { control }),
            "{control}"
        );
    }
    let control = SocketAddr::new(LOOPBACK, port);
    assert!(
        b.add_dynamic_network_subscription(10, &subscribed(control), as_receiver(1))
            .is_ok()
    );
}
