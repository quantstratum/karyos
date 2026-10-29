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

/// A loopback address for a subscription to bind on any port: the kernel
/// picks it at the bind, and [`bound`] reads it back, so no other process
/// can take it in between.
const ANY_PORT: SocketAddr = SocketAddr::new(LOOPBACK, 0);

/// The address `driver`'s network subscription of `stream_id` is bound
/// to.
fn bound(driver: &EmbeddedDriver, stream_id: i32) -> SocketAddr {
    driver.network_subscription_address(stream_id).unwrap()
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
        let _subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
        let address = bound(&b, 10);
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
    let subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
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

/// Two publishers of one alias on different sources (`quantstratum-docs:
/// karyos/design/per-source-images.md`, D2-1): both images are exposed,
/// each named by its registration with its own source; the alias resolves
/// to the oldest; each image's reader gets only its publisher's messages,
/// in order; removing the subscription retires and reclaims both.
#[test]
fn two_images_of_one_alias_are_both_exposed_and_read() {
    let mut a = driver(ThreadingMode::Shared);
    let mut c = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let publications = [
        a.add_network_publication(aggregate(10, 3, 1), &channel(address))
            .unwrap(),
        c.add_network_publication(aggregate(10, 3, 1), &channel(address))
            .unwrap(),
    ];
    pump(&mut a, &mut b, |_, b| {
        let _ = c.do_work().unwrap();
        b.network_images(10).len() == 2
    });
    assert_eq!(b.network_images_unexposed(), 0);
    let images = b.network_images(10);
    assert_ne!(images[0].1, images[1].1, "two sources");
    assert!(images[0].0.registration() < images[1].0.registration());
    assert_eq!(b.network_image(10, 3), Some(images[0].0), "the oldest");
    let mut readers = [images[0].0, images[1].0]
        .map(|image| b.subscribe_aggregate(&image, Role::Required).unwrap());
    // Which publisher an image is from is learnt from its first message.
    let mut lanes = [
        a.publication(publications[0].lane(Lane::ZERO).unwrap())
            .unwrap(),
        c.publication(publications[1].lane(Lane::ZERO).unwrap())
            .unwrap(),
    ];
    let messages = 64u32;
    let mut sent = [0u32; 2];
    let mut seen: [Vec<(u8, u32)>; 2] = [Vec::new(), Vec::new()];
    pump(&mut a, &mut b, |_, _| {
        let _ = c.do_work().unwrap();
        for (publisher, lane) in lanes.iter_mut().enumerate() {
            while sent[publisher] < messages {
                let mut payload = [0u8; 100];
                payload[0] = u8::try_from(publisher).unwrap();
                payload[1..5].copy_from_slice(&sent[publisher].to_le_bytes());
                match lane.offer(&payload).unwrap() {
                    OfferOutcome::Accepted { .. } => sent[publisher] += 1,
                    _ => break,
                }
            }
        }
        for (image, reader) in readers.iter_mut().enumerate() {
            let _ = reader.poll(
                |bytes, _, _| {
                    let index = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
                    seen[image].push((bytes[0], index));
                },
                BUDGET,
            );
        }
        seen.iter().all(|seen| seen.len() == 64)
    });
    let mut publishers = [seen[0][0].0, seen[1][0].0];
    for (image, seen) in seen.iter().enumerate() {
        let publisher = publishers[image];
        let expect: Vec<(u8, u32)> = (0..messages).map(|index| (publisher, index)).collect();
        assert_eq!(seen, &expect, "image {image}: only its publisher, in order");
    }
    publishers.sort_unstable();
    assert_eq!(publishers, [0, 1]);
    drop(readers);
    drop(lanes);
    assert!(b.remove_network_subscription(subscription).unwrap());
    pump(&mut a, &mut b, |_, b| {
        let _ = c.do_work().unwrap();
        b.net.as_ref().unwrap().image_count() == 0
    });
}

/// A local stream and an image of its key coexist, in either order
/// (karyos#490; per-source-images.md, D2-1 and D2-4): the image is exposed
/// beside a local stream of its key, a local stream may be added over a
/// live image's key, and key lookups take the local stream while the alias
/// path of a network subscription takes the image.
#[test]
fn a_local_key_and_an_image_alias_coexist() {
    use karyos_protocol::cnc::StreamKey;
    let key = StreamKey {
        stream_id: 10,
        session_id: 3,
    };
    // A key names the local stream; the image is there by registration.
    let lookups = |b: &EmbeddedDriver| {
        let local = b.find_stream(key, Some(Lane::ZERO)).unwrap();
        let image = b.network_image(10, 3).unwrap().registration();
        (
            b.streams[local].source.is_none(),
            b.streams
                .iter()
                .any(|stream| stream.id == image && stream.source.is_some()),
        )
    };
    // A local stream first: the image of its key is exposed beside it.
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let _local = b.add_aggregate(aggregate(10, 3, 1)).unwrap();
    let _subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_some());
    assert_eq!(b.network_images_unexposed(), 0);
    assert_eq!(lookups(&b), (true, true));
    // An image first: a local stream of its key is added beside it.
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let _subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_some());
    let _local = b.add_aggregate(aggregate(10, 3, 1)).unwrap();
    assert_eq!(lookups(&b), (true, true));
    // Two local streams of one key are still refused.
    assert!(matches!(
        b.add_aggregate(aggregate(10, 3, 1)),
        Err(crate::error::DriverError::DuplicateStream {
            stream_id: 10,
            session_id: 3
        })
    ));
}

/// DESIGN's P2 on #493: a client holding a network subscription of a
/// stream id and asking for that stream's key by `AddSubscription` gets the
/// local stream, never the loopback image of the same key: a key names the
/// local stream for every client, and images attach by registration.
#[test]
fn a_key_names_the_local_stream_for_a_network_subscriber_too() {
    use karyos_client::Outcome;
    use karyos_protocol::cnc::{StreamKey, SubscriberRole};
    let mut b = driver(ThreadingMode::Shared);
    let mut client = b.connect().unwrap();
    let port = free_port();
    let address = SocketAddr::new(LOOPBACK, port);
    let complete =
        |b: &mut EmbeddedDriver, client: &mut karyos_client::ClientConductor, sequence| {
            let mut outcome = None;
            for _ in 0..20_000 {
                let _ = b.do_work().unwrap();
                let _ = client.poll(usize::MAX, |completion| {
                    if completion.sequence == sequence {
                        outcome = Some(completion.outcome);
                    }
                });
                if outcome.is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_micros(100));
            }
            outcome.unwrap()
        };
    // The client's network subscription of stream 10.
    let sequence = client
        .add_network_subscription(
            &format!("karyos:udp?endpoint={address}"),
            10,
            SubscriberRole::Required,
        )
        .unwrap();
    assert!(matches!(
        complete(&mut b, &mut client, sequence),
        Outcome::NetworkSubscription { .. }
    ));
    // The driver's own network publication of (10, 3) to it: its loopback
    // image shares the key.
    let publication = b
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    for _ in 0..20_000 {
        let _ = b.do_work().unwrap();
        let _ = client.poll(usize::MAX, |_| {});
        if b.network_image(10, 3).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let image = b.network_image(10, 3).unwrap().registration();
    let leases = |b: &EmbeddedDriver, id: u64| {
        b.streams
            .iter()
            .find(|stream| stream.id == id)
            .unwrap()
            .leases
            .live()
    };
    let local = publication.registration();
    let (local_before, image_before) = (leases(&b, local), leases(&b, image));
    // The same client asks for the key.
    let key = StreamKey {
        stream_id: 10,
        session_id: 3,
    };
    let sequence = client
        .add_subscription(key, SubscriberRole::Required)
        .unwrap();
    // Held while the leases are read: the handle owns its lease.
    let granted = complete(&mut b, &mut client, sequence);
    assert!(matches!(granted, Outcome::Subscription(_)));
    assert_eq!(leases(&b, local), local_before + 1, "the local stream");
    assert_eq!(leases(&b, image), image_before, "not the image");
    drop(granted);
}

/// An image the stream table has no room for is installed, fed and
/// counted, not exposed; the first stays exposed.
#[test]
fn an_image_without_room_is_counted_not_exposed() {
    let mut a = driver(ThreadingMode::Shared);
    let mut c = driver(ThreadingMode::Shared);
    let mut b = EmbeddedDriver::with_config(DriverConfig {
        max_streams: 1,
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap();
    let subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
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
    assert_eq!(b.network_images(10).len(), 1);
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

/// A replay target has no source (per-source-images.md, D2-1): it is
/// refused over a live image's key, as over any stream's, and an image
/// over a replay target's key stays unexposed and counted.
#[test]
fn a_replay_target_and_an_image_never_share_a_key() {
    use crate::replay::ReplayTargetConfig;
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH};

    let target = |stream_id, session_id| ReplayTargetConfig {
        stream_id,
        session_id,
        term_length: MIN_TERM_LENGTH,
        initial_term_id: 7,
        mtu: DEFAULT_MTU,
        join: 0,
        lane: Lane::ZERO,
        source_stream_id: 42,
        source_session_id: 1,
    };
    // An image first: a replay target of its key is refused.
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let _subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_some());
    assert!(matches!(
        b.replay_target(target(10, 3)),
        Err(crate::error::DriverError::DuplicateStream {
            stream_id: 10,
            session_id: 3
        })
    ));
    // A replay target first: the image of its key is not exposed.
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let _target = b.replay_target(target(10, 3)).unwrap();
    let _subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |_, b| b.network_images_unexposed() == 1);
    assert!(b.network_images(10).is_empty());
}

/// #283 P2: two subscriptions of one endpoint and stream share the
/// receiver's entry; removing one leaves the image, removing the last
/// retires it.
#[test]
fn subscriptions_of_one_key_are_counted() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let first = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let second = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
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
    let address = ANY_PORT;
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
    let first = b
        .add_network_subscription_as(10, &channel(ANY_PORT), identity(77, 5))
        .unwrap();
    for other in [identity(78, 5), identity(77, 6)] {
        assert_eq!(
            b.add_network_subscription_as(10, &channel(ANY_PORT), other),
            Err(crate::DriverError::ReceiverIdentityMismatch)
        );
    }
    assert_eq!(
        b.add_network_subscription(10, &channel(ANY_PORT)),
        Err(crate::DriverError::ReceiverIdentityMismatch),
        "none where the first has one"
    );
    let second = b
        .add_network_subscription_as(10, &channel(ANY_PORT), identity(77, 5))
        .unwrap();
    // Another stream, derived identity: one where it has none is refused.
    let derived = b.add_network_subscription(11, &channel(ANY_PORT)).unwrap();
    assert_eq!(
        b.add_network_subscription_as(11, &channel(ANY_PORT), identity(77, 5)),
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
            refresh: false,
        };
    let lane1 = Lane::try_new(1).unwrap();
    let mut b = driver(ThreadingMode::Shared);
    let first = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT), Lane::ZERO, CONFIG)
        .unwrap();
    assert_eq!(
        b.add_network_subscription_conflated(10, &channel(ANY_PORT), lane1, CONFIG),
        Err(crate::DriverError::ConflationMismatch)
    );
    assert_eq!(
        b.add_network_subscription(10, &channel(ANY_PORT)),
        Err(crate::DriverError::ConflationMismatch),
        "none where the first has one"
    );
    let other = karyos_sys::conflation::ConflationConfig {
        value_capacity: 16,
        ..CONFIG
    };
    assert_eq!(
        b.add_network_subscription_conflated(10, &channel(ANY_PORT), Lane::ZERO, other),
        Err(crate::DriverError::ConflationMismatch),
        "the same lane with another table"
    );
    let second = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT), Lane::ZERO, CONFIG)
        .unwrap();
    let plain = b.add_network_subscription(11, &channel(ANY_PORT)).unwrap();
    assert_eq!(
        b.add_network_subscription_conflated(11, &channel(ANY_PORT), Lane::ZERO, CONFIG),
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
    let first = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let shared = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    assert_eq!(
        b.add_network_subscription(11, &channel(ANY_PORT)),
        Err(crate::error::DriverError::NetworkSubscriptionsFull)
    );
    for _ in 0..50 {
        let _ = b.do_work().unwrap();
    }
    assert_eq!(b.network_subscription_refusals(), 0);
    // Removing every handle of the key frees its entry.
    assert!(b.remove_network_subscription(first).unwrap());
    assert!(b.remove_network_subscription(shared).unwrap());
    let _other = b.add_network_subscription(11, &channel(ANY_PORT)).unwrap();
    for _ in 0..50 {
        let _ = b.do_work().unwrap();
    }
    assert_eq!(b.network_subscription_refusals(), 0);
}

/// A free port, for a multicast group endpoint, outside the ephemeral
/// range (karyos#520, [`crate::test_ports`]).
fn free_port() -> u16 {
    crate::test_ports::test_port()
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
        .add_network_subscription(9, &channel(ANY_PORT))
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
    let address = ANY_PORT;
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
    // Its endpoint and its subscription fill the ring until the next
    // cycle.
    let first = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
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
        ..channel(ANY_PORT)
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

/// C4 follow-up: an image on any path of a conflated subscription finds
/// its view's lane and table, the later paths' included.
#[test]
fn every_path_of_a_conflated_subscription_finds_its_view() {
    use karyos_sys::frame::Lane;

    const CONFIG: karyos_sys::conflation::ConflationConfig =
        karyos_sys::conflation::ConflationConfig {
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
            refresh: false,
        };
    let mut driver = driver(ThreadingMode::Shared);
    driver.net.as_mut().unwrap().assume_isolated_paths();
    let group = SocketAddr::from(([239, 7, 9, 3], free_port()));
    let any = Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let channel = path_channel(group, vec![any, Interface::Address(LOOPBACK)]);
    // As above: a host without multicast has nothing to check.
    let Ok(subscription) =
        driver.add_network_subscription_conflated(6, &channel, Lane::ZERO, CONFIG)
    else {
        return;
    };
    let net = driver.net.as_ref().unwrap();
    let endpoints = net.subscription_endpoints(6);
    // Linux joins the later path; elsewhere it may fail (std sockets bind
    // no two sockets to one port), and only the first path is checked.
    #[cfg(target_os = "linux")]
    assert_eq!(endpoints.len(), 2, "both paths joined");
    #[cfg(not(target_os = "linux"))]
    if driver.network_path_counters().1 == 0 {
        assert_eq!(endpoints.len(), 2, "both paths joined");
    }
    for endpoint in endpoints {
        assert_eq!(net.conflation_of(endpoint, 6), Some((Lane::ZERO, CONFIG)));
    }
    assert!(driver.remove_network_subscription(subscription).unwrap());
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
        driver.add_network_subscription(8, &channel(ANY_PORT)),
        Err(crate::error::DriverError::NetworkSubscriptionsFull)
    );
}

/// #307 review P2-2: a first path on an endpoint another subscription of
/// the stream holds as a later path would share its receiver entry:
/// refused, and nothing is left held.
#[test]
fn a_first_path_never_shares_a_later_paths_entry() {
    let mut driver = driver(ThreadingMode::Shared);
    // Open the endpoint as an ordinary subscription of another stream, then
    // make it a later path of stream 6 in the table.
    let other = driver
        .add_network_subscription(9, &channel(ANY_PORT))
        .unwrap();
    let endpoint = other.endpoint();
    let net = driver.net.as_mut().unwrap();
    net.subscriptions.push(entry(200, 6, &[endpoint.0]));
    let held = driver.network_held_endpoints();
    assert_eq!(
        driver.add_network_subscription(6, &channel(ANY_PORT)),
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

/// N-4a (network streams over shared terms, resolution 2): an exposed
/// image's lanes follow the remote sender's geometry and the receive
/// owner writes the mapping it was given, so neither the aggregate nor
/// one of its lanes may be reconfigured, and the image stays at its first
/// generation.
/// Before this refusal `reconfigure_aggregate` returned
/// `Ok(Generation(1))`: the lane was sealed for a cutover while the
/// receiver kept writing the old mapping.
#[test]
fn reconfiguring_an_exposed_image_is_refused() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let _subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    let mut image = None;
    pump(&mut a, &mut b, |_, b| {
        image = b.network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    let lane = image.lane(Lane::ZERO).unwrap();
    // A reconfiguration any local stream of this geometry accepts.
    let reconfiguration = crate::generations::Reconfiguration {
        term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
        spare_slots: 5,
    };
    let refused = b.reconfigure_aggregate(&image, reconfiguration);
    assert!(
        matches!(refused, Err(crate::error::DriverError::ImageCutover { .. })),
        "{refused:?}"
    );
    let refused = b.reconfigure_stream(lane, reconfiguration);
    assert!(
        matches!(refused, Err(crate::error::DriverError::ImageCutover { .. })),
        "{refused:?}"
    );
    let generations = b.generations(lane).unwrap();
    assert_eq!(generations.len(), 1, "{generations:?}");
    assert_eq!(
        generations[0].generation,
        karyos_sys::term::Generation::default()
    );
    let _ = (a.close_network(), b.close_network());
}

/// A driver of `spare_slots` image spares, on the shared threading mode.
fn image_driver(spare_slots: u8) -> EmbeddedDriver {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.images.spare_slots = spare_slots;
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// A remote client of `driver`, admitted with its export ledger.
fn remote_client(driver: &mut EmbeddedDriver) -> (u64, karyos_sys::command_ring::RingProducer) {
    let (producer, consumer) = karyos_sys::command_ring::command_ring(1024).unwrap();
    let link = std::sync::Arc::new(karyos_client::link::ClientLink::new());
    let client = driver
        .admit(
            consumer,
            link,
            Some(crate::ledger::Ledger::new(4, 4, 1 << 30)),
        )
        .unwrap();
    (client, producer)
}

/// Writes an `AddSubscription` of `role` on lane 0 of `(stream_id,
/// session_id)`.
fn add_remote_subscription(
    producer: &mut karyos_sys::command_ring::RingProducer,
    sequence: u64,
    (stream_id, session_id): (i32, i32),
    role: karyos_protocol::cnc::SubscriberRole,
) {
    use karyos_protocol::cnc::{Command, MAX_COMMAND_LENGTH, StreamKey};
    let command = Command::AddSubscription {
        sequence,
        stream: StreamKey {
            stream_id,
            session_id,
        },
        lane: Lane::ZERO,
        role,
    };
    let mut bytes = [0u8; MAX_COMMAND_LENGTH];
    let length = command.encode(&mut bytes).unwrap();
    producer.write(command.type_id(), &bytes[..length]).unwrap();
}

/// The grants of remote client `client`.
fn grants(driver: &EmbeddedDriver, client: u64) -> usize {
    driver
        .ledger(client)
        .map_or(0, |ledger| ledger.grants().len())
}

/// An image lane's spare-slot credits (SPEC.md §4, "Admission reserves
/// the worst case": the reservations never exceed `S - C`) are shared by
/// its receive owner, which holds `L = 3` of them, and every optional or
/// observer reader, which takes one. With the template's default five
/// spares (`C = 1`), one optional reader fits per lane, whoever asks: a
/// second one is refused with `ResourcesUnavailable`, from the same
/// client, from another client or in process, while required readers
/// take no credit. One more spare slot admits one more optional reader. A
/// local stream with the same five spares and its one publisher credit
/// admits three.
#[test]
fn an_image_lane_admits_as_many_optional_readers_as_its_spare_credits() {
    use karyos_protocol::cnc::SubscriberRole;
    let image = (10, 3);
    let run = |spare_slots: u8, check: &mut dyn FnMut(&mut EmbeddedDriver)| {
        let mut a = driver(ThreadingMode::Shared);
        let mut b = image_driver(spare_slots);
        let _subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
        let address = bound(&b, 10);
        let _publication = a
            .add_network_publication(aggregate(10, 3, 1), &channel(address))
            .unwrap();
        pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_some());
        check(&mut b);
        let _ = (a.close_network(), b.close_network());
    };
    let serve = |driver: &mut EmbeddedDriver| {
        for _ in 0..20 {
            let _ = driver.do_work().unwrap();
        }
    };
    // Two optional readers from one remote client: the second is refused.
    run(5, &mut |b| {
        let (client, mut producer) = remote_client(b);
        add_remote_subscription(&mut producer, 1, image, SubscriberRole::Optional);
        add_remote_subscription(&mut producer, 2, image, SubscriberRole::Optional);
        serve(b);
        assert_eq!(grants(b, client), 1, "one client");
    });
    // One optional reader from each of two remote clients: the same.
    run(5, &mut |b| {
        let (first, mut first_producer) = remote_client(b);
        let (second, mut second_producer) = remote_client(b);
        add_remote_subscription(&mut first_producer, 1, image, SubscriberRole::Optional);
        serve(b);
        add_remote_subscription(&mut second_producer, 1, image, SubscriberRole::Optional);
        serve(b);
        assert_eq!((grants(b, first), grants(b, second)), (1, 0), "two clients");
    });
    // In process: the same credit.
    run(5, &mut |b| {
        let handle = b.network_image(10, 3).unwrap();
        let _first = b.subscribe_aggregate(&handle, Role::Optional).unwrap();
        let second = b.subscribe_aggregate(&handle, Role::Optional);
        assert!(second.is_err(), "in process");
    });
    // Required readers take no credit.
    run(5, &mut |b| {
        let (client, mut producer) = remote_client(b);
        for sequence in 1..=3 {
            add_remote_subscription(&mut producer, sequence, image, SubscriberRole::Required);
        }
        serve(b);
        assert_eq!(grants(b, client), 3, "required");
    });
    // One more spare slot, one more optional reader.
    run(6, &mut |b| {
        let (client, mut producer) = remote_client(b);
        for sequence in 1..=3 {
            add_remote_subscription(&mut producer, sequence, image, SubscriberRole::Optional);
        }
        serve(b);
        assert_eq!(grants(b, client), 2, "six spares");
    });
    // A local stream of five spares: its publisher holds one credit.
    let mut local = image_driver(5);
    let mut config = aggregate(20, 1, 1).stream;
    config.buffer.spare_slots = 5;
    let _stream = local.add_stream(config).unwrap();
    let (client, mut producer) = remote_client(&mut local);
    for sequence in 1..=4 {
        add_remote_subscription(&mut producer, sequence, (20, 1), SubscriberRole::Optional);
    }
    serve(&mut local);
    assert_eq!(grants(&local, client), 3, "local stream");
}

/// A driver clock the test moves.
#[derive(Debug, Clone, Default)]
struct ManualClock(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl crate::clock::MonotonicClock for ManualClock {
    fn now(&mut self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Resolution 8 (network streams over shared terms): a remote client's
/// liveness retirement (`serve_liveness`, then `stop_serving`) ends its
/// image grants whose descriptor never left, with its registrations, at
/// once. A grant already sent may still be mapped by a process that only
/// stopped, so it stays charged and pins the retired image's storage
/// until the client's exit proof (its close flag), which ends it; only
/// then is the image reclaimed. The export ledger does not depend on the
/// backing, so a heap driver stands for the IPC driver that grants images
/// from step n3.
#[test]
fn a_liveness_retirement_ends_unsent_image_grants_and_the_exit_proof_the_rest() {
    use karyos_protocol::cnc::{Command, MAX_COMMAND_LENGTH, StreamKey, SubscriberRole};
    let clock = ManualClock::default();
    let mut a = driver(ThreadingMode::Shared);
    let mut b = EmbeddedDriver::with_clock(
        DriverConfig {
            network: Some(NetworkConfig {
                threading: ThreadingMode::Shared,
                ..NetworkConfig::default()
            }),
            heartbeat_interval: 10,
            client_liveness_timeout: 100,
            ..DriverConfig::default()
        },
        Box::new(clock.clone()),
    )
    .unwrap();
    let subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let _publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_some());
    let registrations = b.registrations.len();
    // A remote client, admitted with its export ledger.
    let (mut producer, consumer) = karyos_sys::command_ring::command_ring(1024).unwrap();
    let link = std::sync::Arc::new(karyos_client::link::ClientLink::new());
    let client = b
        .admit(
            consumer,
            std::sync::Arc::clone(&link),
            Some(crate::ledger::Ledger::new(4, 4, 1 << 30)),
        )
        .unwrap();
    for sequence in 1..=2 {
        let command = Command::AddSubscription {
            sequence,
            stream: StreamKey {
                stream_id: 10,
                session_id: 3,
            },
            lane: Lane::ZERO,
            role: SubscriberRole::Required,
        };
        let mut bytes = [0u8; MAX_COMMAND_LENGTH];
        let length = command.encode(&mut bytes).unwrap();
        producer.write(command.type_id(), &bytes[..length]).unwrap();
    }
    pump(&mut a, &mut b, |_, b| {
        b.ledger(client)
            .is_some_and(|ledger| ledger.grants().len() == 2)
    });
    let grants = b.ledger(client).unwrap().grants().to_vec();
    let image_stream = grants[0].stream;
    assert!(grants.iter().all(|grant| grant.stream == image_stream));
    assert!(grants.iter().all(|grant| !grant.sent));
    // The first grant's descriptor left; the second is still held.
    b.ledger_mut(client).unwrap().mark_sent(grants[0].export);
    // The client stops beating: its liveness timeout passes.
    clock.0.store(100, std::sync::atomic::Ordering::Relaxed);
    pump(&mut a, &mut b, |_, b| {
        b.ledger(client)
            .is_some_and(|ledger| ledger.grants().len() == 1)
    });
    let left = b.ledger(client).unwrap().grants().to_vec();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].export, grants[0].export, "the sent grant is kept");
    assert_eq!(b.registrations.len(), registrations, "its registrations go");
    // The image retires; the sent grant keeps its stream and storage.
    assert!(b.remove_network_subscription(subscription).unwrap());
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_none());
    for _ in 0..50 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
    }
    assert!(b.streams.iter().any(|stream| stream.id == image_stream));
    assert_eq!(b.net.as_ref().unwrap().image_count(), 1);
    assert!(
        b.net.as_ref().unwrap().image_charge() > 0,
        "the sent grant keeps the image's storage charged"
    );
    // The exit proof ends the sent grant: the stream frees and the image
    // is reclaimed.
    link.mark_closed();
    pump(&mut a, &mut b, |_, b| {
        b.net.as_ref().unwrap().image_count() == 0
    });
    assert_eq!(b.net.as_ref().unwrap().image_charge(), 0);
    assert!(b.ledger(client).is_none());
    assert!(b.streams.iter().all(|stream| stream.id != image_stream));
    let _ = (a.close_network(), b.close_network());
}

/// Network streams' terminal bound (network-sessions.md, Liveness and
/// terminal transitions): EOS on each lane's last message names its bound,
/// the image closes cleanly once both lanes' complete prefixes reach it,
/// and the subscriber reads every message, the EOS one marked, then a clean
/// terminal: every lane closed at `EndOfStream`.
#[test]
fn eos_on_every_lane_ends_the_image_cleanly_after_the_last_message() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let _subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 2), &channel(address))
        .unwrap();
    let mut image = None;
    pump(&mut a, &mut b, |_, b| {
        image = b.network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lanes = [
        a.publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap(),
        a.publication(publication.lane(Lane::try_new(1).unwrap()).unwrap())
            .unwrap(),
    ];
    let eos = karyos_sys::log_buffer::AppendOptions {
        end_of_stream: true,
        ..karyos_sys::log_buffer::AppendOptions::default()
    };
    // Two messages on lane 0, the second the end; one on lane 1.
    let mut offered = [0u8; 2];
    let plan: [&[(u8, bool)]; 2] = [&[(1, false), (2, true)], &[(3, true)]];
    let mut seen = Vec::new();
    let mut terminal = None;
    pump(&mut a, &mut b, |_, _| {
        for (lane, publication) in lanes.iter_mut().enumerate() {
            while let Some(&(fill, end)) = plan[lane].get(usize::from(offered[lane])) {
                let options = if end {
                    eos
                } else {
                    karyos_sys::log_buffer::AppendOptions::default()
                };
                match publication.offer_with(&[fill; 300], options).unwrap() {
                    OfferOutcome::Accepted { .. } => offered[lane] += 1,
                    _ => break,
                }
            }
        }
        let poll = reader.poll(
            |bytes, lane, info| seen.push((lane.get(), bytes[0], info.end_of_stream)),
            BUDGET,
        );
        if poll.terminal.is_some() {
            terminal = Some(poll);
        }
        terminal.is_some()
    });
    let poll = terminal.unwrap();
    seen.sort_unstable();
    assert_eq!(seen, [(0, 1, false), (0, 2, true), (1, 3, true)]);
    assert!(poll.terminal.unwrap().clean, "{poll:?}");
    for lane in &poll.lanes {
        assert!(
            matches!(
                lane.end,
                Some(karyos_client::aggregate::LaneEnd::Closed {
                    reason: karyos_sys::log_buffer::SealReason::EndOfStream,
                    ..
                })
            ),
            "{lane:?}"
        );
    }
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(
        (receiver.eos_bounds, receiver.images_closed_eos),
        (2, 1),
        "{receiver:?}"
    );
    drop(lanes);
    let _ = (a.close_network(), b.close_network());
}

#[cfg(target_os = "linux")]
mod ipc;

/// Writes `command` to a remote client's ring.
fn write_command(
    producer: &mut karyos_sys::command_ring::RingProducer,
    command: karyos_protocol::cnc::Command,
) {
    let mut bytes = [0u8; karyos_protocol::cnc::MAX_COMMAND_LENGTH];
    let length = command.encode(&mut bytes).unwrap();
    producer.write(command.type_id(), &bytes[..length]).unwrap();
}

/// The responses `observer` has not read yet.
fn responses(
    observer: &mut karyos_sys::broadcast::BroadcastReceiver,
) -> Vec<karyos_protocol::cnc::Response> {
    let mut out = Vec::new();
    while let karyos_sys::broadcast::Received::Message {
        type_id, payload, ..
    } = observer.receive()
    {
        if let Ok(response) = karyos_protocol::cnc::Response::decode(type_id, payload) {
            out.push(response);
        }
    }
    out
}

/// Every message the driver broadcast that `observer` has not read, as
/// text: responses and events (a closed image's `PublicationClosed`).
fn broadcast(observer: &mut karyos_sys::broadcast::BroadcastReceiver) -> Vec<String> {
    let mut out = Vec::new();
    while let karyos_sys::broadcast::Received::Message {
        type_id, payload, ..
    } = observer.receive()
    {
        if let Ok(response) = karyos_protocol::cnc::Response::decode(type_id, payload) {
            out.push(format!("{response:?}"));
        } else if let Ok(event) = karyos_protocol::cnc::Event::decode(type_id, payload) {
            out.push(format!("{event:?}"));
        } else {
            out.push(format!("type {type_id:#x}"));
        }
    }
    out
}

/// Binding commands to images (`quantstratum-docs:
/// karyos/design/per-source-images.md`, D2-2 and D2-3): with two images
/// of one alias, `AddSubscription` by the alias grants the oldest and
/// `AddImageSubscription` grants the image it names. A local stream's
/// registration, a network publication's, a lane the image lacks and a
/// retiring image are `UnknownStream`, the image registration its detail.
#[test]
fn commands_bind_by_alias_to_the_oldest_image_and_by_registration_to_one() {
    use karyos_protocol::cnc::{Command, ErrorCode, Response, SubscriberRole};

    let mut a = driver(ThreadingMode::Shared);
    let mut c = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let subscription = b.add_network_subscription(10, &channel(ANY_PORT)).unwrap();
    let address = bound(&b, 10);
    let _first = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    let _second = c
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |_, b| {
        let _ = c.do_work().unwrap();
        b.network_images(10).len() == 2
    });
    // Oldest is the lowest aggregate registration, as `find_stream`
    // takes it, whatever order the images are listed in.
    let mut images: Vec<_> = b
        .network_images(10)
        .into_iter()
        .map(|(image, _)| image)
        .collect();
    images.sort_by_key(crate::embedded::AggregateHandle::registration);
    let [oldest, newest] = images[..] else {
        panic!("two images");
    };
    let local = b.add_aggregate(aggregate(20, 1, 1)).unwrap();
    // A publication with no receiver sends to a socket the test holds.
    let silent = UdpSocket::bind(ANY_PORT).unwrap();
    let publication = b
        .add_network_publication(aggregate(30, 1, 1), &channel(silent.local_addr().unwrap()))
        .unwrap();
    let mut observer = b.broadcast.receiver();
    let (client, mut producer) = remote_client(&mut b);
    // Both publishers stay driven, so neither image goes stale or misses
    // a repair while the commands are served.
    let serve = |a: &mut EmbeddedDriver, c: &mut EmbeddedDriver, b: &mut EmbeddedDriver| {
        for _ in 0..20 {
            let _ = (a.do_work().unwrap(), c.do_work().unwrap());
            let _ = b.do_work().unwrap();
        }
    };
    let image_subscription = |sequence, image, lane| Command::AddImageSubscription {
        sequence,
        image,
        lane: Lane::try_new(lane).unwrap(),
        role: SubscriberRole::Required,
    };
    let live = |b: &EmbeddedDriver| {
        let mut live: Vec<u64> = b
            .network_images(10)
            .iter()
            .map(|(image, _)| image.registration())
            .collect();
        live.sort_unstable();
        live
    };
    assert_eq!(
        live(&b),
        [oldest.registration(), newest.registration()],
        "both images live before the commands"
    );
    add_remote_subscription(&mut producer, 1, (10, 3), SubscriberRole::Required);
    write_command(
        &mut producer,
        image_subscription(2, newest.registration(), 0),
    );
    serve(&mut a, &mut c, &mut b);
    let streams: Vec<u64> = b
        .ledger(client)
        .unwrap()
        .grants()
        .iter()
        .map(|grant| grant.stream)
        .collect();
    // What the driver said while the commands ran (a closed image names
    // its reason there) and the images still live: if the alias missed the
    // oldest, these say why (the test has failed so, rarely, under load).
    let said = broadcast(&mut observer);
    assert_eq!(
        streams,
        [oldest.registration(), newest.registration()],
        "the alias reaches the oldest, the registration its image; live after the \
         commands: {:?}; the driver said: {said:?}",
        live(&b)
    );
    // None of these is an image's live lane.
    let refused = [
        (3, local.registration(), 0),
        (4, publication.registration(), 0),
        (5, newest.registration(), 1),
    ];
    for (sequence, image, lane) in refused {
        write_command(&mut producer, image_subscription(sequence, image, lane));
    }
    serve(&mut a, &mut c, &mut b);
    let mut events = b.broadcast.receiver();
    assert!(b.remove_network_subscription(subscription).unwrap());
    pump(&mut a, &mut b, |_, b| b.network_image(10, 3).is_none());
    // Each image's retirement closes its lane naming the image (D2-3).
    let mut closed = Vec::new();
    while let karyos_sys::broadcast::Received::Message {
        type_id, payload, ..
    } = events.receive()
    {
        if let Ok(karyos_protocol::cnc::Event::PublicationClosed { stream, image, .. }) =
            karyos_protocol::cnc::Event::decode(type_id, payload)
        {
            closed.push((stream.stream_id, image));
        }
    }
    closed.sort_unstable();
    assert_eq!(
        closed,
        [(10, oldest.registration()), (10, newest.registration())]
    );
    write_command(
        &mut producer,
        image_subscription(6, oldest.registration(), 0),
    );
    serve(&mut a, &mut c, &mut b);
    assert_eq!(grants(&b, client), 2, "nothing more granted");
    let errors: Vec<(u64, ErrorCode, u64)> = responses(&mut observer)
        .into_iter()
        .filter_map(|response| match response {
            Response::Error {
                request,
                code,
                detail,
            } => Some((request.sequence, code, detail)),
            _ => None,
        })
        .collect();
    assert_eq!(
        errors,
        [
            (3, ErrorCode::UnknownStream, local.registration()),
            (4, ErrorCode::UnknownStream, publication.registration()),
            (5, ErrorCode::UnknownStream, newest.registration()),
            (6, ErrorCode::UnknownStream, oldest.registration()),
        ]
    );
}

/// A client conductor of the subscribing driver (per-source-images.md,
/// D2-3 and D2-5): a network subscription by URI hears two
/// `ImageAvailable` events for two images of one alias, each naming its
/// image registration and its source, and a plain `add_subscription` by
/// the alias still attaches the oldest image.
#[test]
fn a_conductor_hears_each_image_and_attaches_by_alias_to_the_oldest() {
    use karyos_client::Outcome;
    use karyos_protocol::cnc::{Event, StreamKey, SubscriberRole};

    let mut a = driver(ThreadingMode::Shared);
    let mut c = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let address = SocketAddr::new(LOOPBACK, free_port());
    let mut client = b.connect().unwrap();
    let uri = format!("karyos:udp?endpoint={address}");
    let subscribed = client
        .add_network_subscription(&uri, 10, SubscriberRole::Required)
        .unwrap();
    let _first = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    let _second = c
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    let mut heard = Vec::new();
    let mut outcomes = Vec::new();
    pump(&mut a, &mut b, |_, _| {
        let _ = c.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| outcomes.push(completion));
        for event in client.take_events() {
            if let Event::ImageAvailable {
                stream,
                image,
                source,
                ..
            } = event
            {
                heard.push((stream, image, source));
            }
        }
        heard.len() == 2
    });
    assert!(
        outcomes
            .iter()
            .any(|completion| completion.sequence == subscribed
                && matches!(completion.outcome, Outcome::NetworkSubscription { .. }))
    );
    let alias = StreamKey {
        stream_id: 10,
        session_id: 3,
    };
    heard.sort_unstable_by_key(|(_, image, _)| *image);
    let images: Vec<_> = b
        .network_images(10)
        .into_iter()
        .map(|(handle, source)| (alias, handle.registration(), source))
        .collect();
    assert_eq!(heard, images, "each image with its registration and source");
    let attach = client
        .add_subscription(alias, SubscriberRole::Required)
        .unwrap();
    pump(&mut a, &mut b, |_, _| {
        let _ = c.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| outcomes.push(completion));
        outcomes
            .iter()
            .any(|completion| completion.sequence == attach)
    });
    let completion = outcomes
        .iter()
        .find(|completion| completion.sequence == attach)
        .unwrap();
    assert!(matches!(completion.outcome, Outcome::Subscription(_)));
    let oldest = images[0].1;
    assert_eq!(
        b.registrations
            .last()
            .map(crate::commands::Registration::stream),
        Some(oldest),
        "the alias attaches the oldest image"
    );
}

/// Stages of the driver thread of a facade test.
const PUBLISH: u8 = 1;
const REMOVE: u8 = 2;
const STOP: u8 = 3;

/// An in-process facade over driver `b`, which a driver thread serves with
/// a publisher `a`: one image of stream 10 per `PUBLISH`, retired at
/// `REMOVE`. The thread publishes `b`'s registration count.
struct FacadeRig {
    client: karyos_client::Client<karyos_client::ClientConductor>,
    reading: Option<karyos_client::Subscription<karyos_sys::term_bytes::HeapTerms>>,
    stage: std::sync::Arc<std::sync::atomic::AtomicU8>,
    registrations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    thread: std::thread::JoinHandle<EmbeddedDriver>,
}

impl FacadeRig {
    fn new() -> Self {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

        use karyos_client::{Client, Context, IdleStrategy};
        use karyos_protocol::cnc::StreamId;

        let port = free_port();
        let stage = Arc::new(AtomicU8::new(0));
        let registrations = Arc::new(AtomicUsize::new(0));
        let (send, receive) = std::sync::mpsc::channel();
        let driving = Arc::clone(&stage);
        let counting = Arc::clone(&registrations);
        let thread = std::thread::spawn(move || {
            let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
            send.send(b.connect().unwrap()).unwrap();
            let destination = SocketAddr::new(LOOPBACK, port);
            let mut publication = None;
            loop {
                match driving.load(Ordering::Acquire) {
                    PUBLISH if publication.is_none() => {
                        publication = Some(
                            a.add_network_publication(aggregate(10, 3, 1), &channel(destination))
                                .unwrap(),
                        );
                    }
                    REMOVE => {
                        if let Some(publication) = publication.take() {
                            a.remove_aggregate(&publication).unwrap();
                        }
                    }
                    STOP => break,
                    _ => {}
                }
                let _ = a.do_work().unwrap();
                let _ = b.do_work().unwrap();
                counting.store(b.registrations.len(), Ordering::Release);
                std::thread::sleep(Duration::from_micros(50));
            }
            for _ in 0..50 {
                let _ = b.do_work().unwrap();
            }
            let _ = (a.close_network(), b.close_network());
            b
        });
        let context = Context::builder()
            .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let mut client = Client::with_conductor(receive.recv().unwrap(), context);
        let reading = client
            .add_subscription(
                &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
                StreamId::new(10),
            )
            .unwrap();
        Self {
            client,
            reading: Some(reading),
            stage,
            registrations,
            thread,
        }
    }

    fn stage(&self, stage: u8) {
        self.stage
            .store(stage, std::sync::atomic::Ordering::Release);
    }

    fn registrations(&self) -> usize {
        self.registrations
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Serves the client, and reads its subscription when `read`, until
    /// `done`.
    fn until(&mut self, read: bool, done: &dyn Fn(&Self) -> bool) {
        let start = std::time::Instant::now();
        while !done(self) {
            assert!(start.elapsed() < Duration::from_secs(20), "not reached");
            self.service(read);
        }
    }

    fn service(&mut self, read: bool) {
        let _ = self.client.poll();
        if read && let Some(reading) = self.reading.as_mut() {
            let _ = reading.poll(|_, _| {}, karyos_client::MessageLimit::new(64));
        }
        std::thread::sleep(Duration::from_micros(100));
    }

    /// Serves the client a while, so it releases what was let go of, then
    /// stops the driver thread and asserts that `b` forgot every
    /// registration by the command, none swept.
    fn ends_with_none_swept(mut self) {
        for _ in 0..100 {
            self.service(false);
        }
        self.stage(STOP);
        let b = self.thread.join().unwrap();
        assert!(b.registrations.is_empty(), "the registration was removed");
        assert_eq!(
            b.counters.value(crate::counters::Event::RegistrationsSwept),
            0,
            "removed by the command, not swept"
        );
        drop((self.reading, self.client));
    }
}

/// The client facade releases a retired image's handle with
/// `RemoveSubscription` (`Connection::release_subscription`), so the driver
/// forgets its registration by the command, not by sweeping a dropped
/// handle: an in-process facade reads one image, the image retires, and
/// the driver ends with no registration and none swept.
#[test]
fn the_facade_removes_a_retired_images_subscription() {
    let mut rig = FacadeRig::new();
    rig.stage(PUBLISH);
    rig.until(true, &|rig| {
        rig.reading.as_ref().is_some_and(|r| r.image_count() == 1)
    });
    rig.stage(REMOVE);
    rig.until(true, &|rig| {
        rig.reading.as_ref().is_some_and(|r| r.image_count() == 0)
    });
    rig.ends_with_none_swept();
}

/// An image that retires before its subscription ever polled it is
/// released by the client at `ImageUnavailable`, with `RemoveSubscription`,
/// not dropped: the subscription is never read, so the handle is still in
/// the inbox when the image retires.
#[test]
fn the_facade_removes_an_image_retired_before_it_was_read() {
    let mut rig = FacadeRig::new();
    rig.stage(PUBLISH);
    rig.until(false, &|rig| rig.registrations() == 1);
    // The attach's answer reaches the inbox at the client's next services.
    for _ in 0..100 {
        rig.service(false);
    }
    rig.stage(REMOVE);
    rig.until(false, &|rig| rig.registrations() == 0);
    rig.ends_with_none_swept();
}

/// Dropping a network subscription that still reads an image releases the
/// image's handle with `RemoveSubscription`, not by dropping it.
#[test]
fn a_dropped_network_subscription_removes_its_images() {
    let mut rig = FacadeRig::new();
    rig.stage(PUBLISH);
    rig.until(true, &|rig| {
        rig.reading.as_ref().is_some_and(|r| r.image_count() == 1)
    });
    drop(rig.reading.take());
    rig.until(false, &|rig| rig.registrations() == 0);
    rig.ends_with_none_swept();
}
