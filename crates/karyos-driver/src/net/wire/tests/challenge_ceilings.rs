// SPDX-License-Identifier: Apache-2.0

//! H8 R5-04 (EST-13, BUD-4): ADR-0086 section 6 bounds the challenge
//! table at 256 pending challenges per driver and 8 per source address.
//! The conductor refuses a protected channel, typed and before anything
//! exists, on a driver whose configuration asks for more; at the ceilings
//! it is admitted and establishes, and a trusted channel is unaffected.
//! The table at the ceilings is exercised in
//! `sessions/receive/tests.rs`
//! (`an_authenticated_challenge_table_holds_the_profile_ceilings_exactly`).

use super::*;

use crate::sessions::receive::{
    AUTH_MAX_PENDING_CHALLENGES, AUTH_MAX_PENDING_PER_SOURCE, SessionConfig,
};

/// A keyed driver whose challenge table is `pending` globally and
/// `per_source` per source address, with room for both (`max_images` and
/// the control ring above them).
fn keyed_table(files: &[(&str, &str)], pending: usize, per_source: usize) -> (EmbeddedDriver, Mem) {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.subscriptions = 64;
    network.agents.sessions = SessionConfig {
        max_images: pending.max(64),
        max_pending_challenges: pending,
        max_pending_per_source: per_source,
        ..network.agents.sessions
    };
    let units = pending.max(64) * usize::from(network.agents.sessions.max_paths) + pending + 32;
    network.agents.control_capacity = network.agents.control_capacity.max(units);
    network.agents.session_command_capacity = network
        .agents
        .session_command_capacity
        .max(3 * pending.max(64));
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let (keys, state) = dirs(files);
    let report = driver
        .start_wire_keys_at(Box::new(keys.clone()) as Dir, Box::new(state) as Dir, wall)
        .unwrap();
    assert!(!report.alarm(), "{report:?}");
    (driver, keys)
}

/// A driver configured above either ceiling (257 pending, or 9 per
/// source) refuses an authenticated subscription and publication with
/// [`AuthRefusal::ChallengeCeiling`]; nothing is created, and the same
/// driver still admits a trusted channel.
#[test]
fn a_challenge_table_above_the_profile_ceilings_refuses_a_protected_channel() {
    for (pending, per_source) in [
        (AUTH_MAX_PENDING_CHALLENGES + 1, AUTH_MAX_PENDING_PER_SOURCE),
        (AUTH_MAX_PENDING_CHALLENGES, AUTH_MAX_PENDING_PER_SOURCE + 1),
    ] {
        let (mut subscriber, _) = keyed_table(&borrowed(&subscriber_files()), pending, per_source);
        let security = Security::Authenticated(auth(None));
        assert_eq!(
            subscriber
                .add_network_subscription_as(
                    STREAM,
                    &udp(Destination::Unicast(ANY_PORT), security),
                    identity(RECEIVER),
                )
                .unwrap_err(),
            refused(AuthRefusal::ChallengeCeiling),
            "{pending}/{per_source}"
        );
        assert_eq!(roles(&subscriber).1, (0, 0, 0));
        assert!(subscriber.network_subscription_address(STREAM).is_none());

        let (mut publisher, _) = keyed_table(&borrowed(&publisher_files()), pending, per_source);
        assert_eq!(
            publisher
                .add_network_publication(
                    aggregate(STREAM),
                    &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
                )
                .unwrap_err(),
            refused(AuthRefusal::ChallengeCeiling)
        );
        assert_eq!(publisher.net.as_ref().unwrap().publication_count(), 0);
        assert_eq!(roles(&publisher).0, (0, 0, 0));

        // A trusted channel has no such ceiling.
        subscriber
            .add_network_subscription(
                STREAM,
                &udp(Destination::Unicast(ANY_PORT), Security::Trusted),
            )
            .unwrap();
    }
}

/// At exactly the ceilings (256 pending, 8 per source) an authenticated
/// channel is admitted through production admission and establishes.
#[test]
fn a_challenge_table_at_the_profile_ceilings_admits_and_establishes() {
    let (mut subscriber, _) = keyed_table(
        &borrowed(&subscriber_files()),
        AUTH_MAX_PENDING_CHALLENGES,
        AUTH_MAX_PENDING_PER_SOURCE,
    );
    let security = Security::Authenticated(auth(None));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (mut publisher, _) = keyed_table(
        &borrowed(&publisher_files()),
        AUTH_MAX_PENDING_CHALLENGES,
        AUTH_MAX_PENDING_PER_SOURCE,
    );
    let handle = publisher
        .add_network_publication(aggregate(STREAM), &udp(Destination::Unicast(to), security))
        .unwrap();
    let registration = handle.registration();
    assert!(pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        drivers[0]
            .net
            .as_ref()
            .unwrap()
            .publication_established(registration)
            && !drivers[1].network_images(STREAM).is_empty()
    }));
}
