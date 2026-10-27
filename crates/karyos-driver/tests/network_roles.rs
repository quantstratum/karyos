// SPDX-License-Identifier: Apache-2.0

//! The public roles and tags configuration of a network publication
//! (owner decisions of 2026-10-21, item 7; karyos#637), through the public
//! API only: the channel's `fc` is the one source of the strategy, typed
//! roles must name the same one, `max` and `tagged:<group>` are granted,
//! and what stays unsupported (`tagged:0`) is refused, never run as `min`.
//! A receiver's identity is configured with
//! `add_network_subscription_as`. The bound each strategy puts on the
//! sender is asserted over multicast by `net/e2e.rs`,
//! `a_required_receiver_bounds_every_strategy` (Linux).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use karyos_driver::agents::ThreadingMode;
use karyos_driver::membership::{PublicationRoles, ReceiverIdentity, Strategy};
use karyos_driver::net::NetworkConfig;
use karyos_driver::{AggregateConfig, DriverConfig, DriverError, EmbeddedDriver, StreamConfig};
use karyos_protocol::channel::{ChannelConfig, Media, UdpConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

/// A network-enabled driver whose agents run only in the test's cycles.
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

fn aggregate(stream_id: i32) -> AggregateConfig {
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

/// A multicast channel on the loopback interface with `fc`, as a URI
/// parses it.
fn channel(fc: &str) -> UdpConfig {
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let fc = if fc.is_empty() {
        String::new()
    } else {
        format!("|fc={fc}")
    };
    let uri = format!("karyos:udp?group=239.255.0.11:{port}|interface=127.0.0.1{fc}");
    match ChannelConfig::parse(&uri).unwrap().media {
        Media::Udp(channel) => channel,
        _ => panic!("not udp: {uri}"),
    }
}

fn roles(strategy: Strategy) -> PublicationRoles {
    PublicationRoles {
        strategy,
        required: vec![77],
        tags: vec![(88, 9)],
    }
}

/// `fc=max` and `fc=tagged:<group>` are granted, with or without typed
/// roles that name the same strategy; `fc=min` and no `fc` are `min`.
#[test]
fn every_strategy_is_requested_by_its_fc() {
    let mut driver = driver();
    for (stream_id, fc) in [(10, "max"), (11, "tagged:9"), (12, "min"), (13, "")] {
        driver
            .add_network_publication(aggregate(stream_id), &channel(fc))
            .unwrap_or_else(|error| panic!("fc={fc}: {error}"));
    }
    for (stream_id, fc, strategy) in [
        (20, "max", Strategy::Max),
        (21, "tagged:9", Strategy::Tagged(9)),
        (22, "min", Strategy::Min),
        (23, "", Strategy::Min),
    ] {
        driver
            .add_network_publication_with_roles(aggregate(stream_id), &channel(fc), roles(strategy))
            .unwrap_or_else(|error| panic!("fc={fc}: {error}"));
    }
}

/// Roles that name another strategy than the channel's `fc` are refused,
/// whichever way round, never resolved by precedence.
#[test]
fn roles_that_contradict_the_fc_are_refused() {
    let mut driver = driver();
    for (stream_id, fc, strategy) in [
        (30, "max", Strategy::Min),
        (31, "", Strategy::Max),
        (32, "min", Strategy::Tagged(9)),
        (33, "tagged:9", Strategy::Tagged(8)),
        (34, "tagged:9", Strategy::Max),
    ] {
        assert_eq!(
            driver
                .add_network_publication_with_roles(
                    aggregate(stream_id),
                    &channel(fc),
                    roles(strategy)
                )
                .err(),
            Some(DriverError::StrategyConflict),
            "fc={fc} with {strategy:?}"
        );
    }
}

/// What stays unsupported is refused with a typed error, never run as
/// `min`: a tagged group of 0 names no group.
#[test]
fn a_tagged_group_of_zero_is_refused() {
    let mut driver = driver();
    assert_eq!(
        driver
            .add_network_publication(aggregate(40), &channel("tagged:0"))
            .err(),
        Some(DriverError::UnsupportedChannel)
    );
    assert_eq!(
        driver
            .add_network_publication_with_roles(
                aggregate(41),
                &channel("tagged:0"),
                roles(Strategy::Tagged(0))
            )
            .err(),
        Some(DriverError::UnsupportedChannel)
    );
}

/// A subscription names its receiver identity through the public API.
#[test]
fn a_subscription_takes_its_receiver_identity() {
    let mut driver = driver();
    let identity = ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(77).unwrap(),
        group_tag: 9,
    };
    driver
        .add_network_subscription_as(50, &channel("max"), identity)
        .unwrap();
}
