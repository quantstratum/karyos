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

/// A loopback address with a port free a moment ago.
fn free_address() -> SocketAddr {
    UdpSocket::bind(SocketAddr::new(LOOPBACK, 0))
        .unwrap()
        .local_addr()
        .unwrap()
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
        let address = free_address();
        let _subscription = b.add_network_subscription(10, &channel(address)).unwrap();
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
    let address = free_address();
    let subscription = b.add_network_subscription(10, &channel(address)).unwrap();
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

/// Interim keying (ACS 15937): a second image with an alias in use is not
/// exposed, and is counted; the first stays exposed.
#[test]
fn a_second_image_of_one_alias_is_counted_not_exposed() {
    let mut a = driver(ThreadingMode::Shared);
    let mut c = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let address = free_address();
    let subscription = b.add_network_subscription(10, &channel(address)).unwrap();
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
    assert!(b.network_image(10, 3).is_some());
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

/// #283 P2: two subscriptions of one endpoint and stream share the
/// receiver's entry; removing one leaves the image, removing the last
/// retires it.
#[test]
fn subscriptions_of_one_key_are_counted() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = driver(ThreadingMode::Shared);
    let address = free_address();
    let first = b.add_network_subscription(10, &channel(address)).unwrap();
    let second = b.add_network_subscription(10, &channel(address)).unwrap();
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
