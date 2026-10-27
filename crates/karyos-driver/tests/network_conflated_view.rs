// SPDX-License-Identifier: Apache-2.0

//! A conflated view of a network image through the public API only (owner
//! decisions of 2026-10-21, item 7: "receiver-side conflated
//! subscriptions"; karyos#637): a `karyos:udp` subscription with a
//! conflated lane, its image's view read with `subscribe_conflated` on the
//! image's lane stream, each value with its freshness. The `karyos:ipc`
//! path is `tests/conflated_view.rs`'s, unchanged.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use karyos_client::{Freshness, OfferOutcome};
use karyos_driver::agents::ThreadingMode;
use karyos_driver::net::NetworkConfig;
use karyos_driver::{AggregateConfig, DriverConfig, EmbeddedDriver, StreamConfig};
use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_sys::conflation::ConflationConfig;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{AppendOptions, LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

const VIEW: ConflationConfig = ConflationConfig {
    keys: 4,
    value_capacity: 16,
    journal_capacity: 1024,
    refresh: false,
};

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

fn channel(address: SocketAddr) -> UdpConfig {
    UdpConfig {
        destination: Destination::Unicast(address),
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable: false,
        flow_control: None,
        security: Security::Trusted,
    }
}

fn aggregate(stream_id: i32, session_id: i32) -> AggregateConfig {
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
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        },
        quanta: vec![u64::from(DEFAULT_MTU) * 4],
    }
}

/// Runs both drivers until `done`, at most five seconds.
fn pump(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    mut done: impl FnMut(&mut EmbeddedDriver) -> bool,
) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        if done(b) {
            return;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    panic!("not reached");
}

/// Owner item 7, karyos#637: a conflated subscription works on a
/// `karyos:udp` channel through the public API. Its image's view holds
/// each key's latest value, read `Fresh`; a later update replaces it.
#[test]
fn a_conflated_network_subscription_reads_its_view() {
    let (mut a, mut b) = (driver(), driver());
    let _subscription = b
        .add_network_subscription_conflated(
            10,
            &channel(SocketAddr::new(LOOPBACK, 0)),
            Lane::ZERO,
            VIEW,
        )
        .unwrap();
    let address = b.network_subscription_address(10).unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 3), &channel(address))
        .unwrap();
    let mut image = None;
    pump(&mut a, &mut b, |b| {
        image = b.network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    let mut view = b
        .subscribe_conflated(image.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut latest: [Option<(u8, Freshness)>; 4] = [None; 4];
    for (key, value) in [(0i64, 10u8), (2, 20), (0, 11)] {
        let options = AppendOptions {
            reserved_value: key,
            ..AppendOptions::default()
        };
        let mut offered = false;
        pump(&mut a, &mut b, |_| {
            if !offered {
                offered = matches!(
                    lane.offer_with(&[value; 16], options).unwrap(),
                    OfferOutcome::Accepted { .. }
                );
            }
            let _ = view
                .poll_changed(|key, found| {
                    latest[key as usize] = Some((found.payload()[0], found.freshness()));
                })
                .unwrap();
            latest[usize::try_from(key).unwrap()].is_some_and(|(seen, _)| seen == value)
        });
    }
    assert_eq!(
        latest,
        [
            Some((11, Freshness::Fresh)),
            None,
            Some((20, Freshness::Fresh)),
            None
        ]
    );
    // The view's counts are the driver's own.
    assert_eq!(b.network_view_counters().built, 1);
}
