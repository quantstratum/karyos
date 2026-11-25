// SPDX-License-Identifier: Apache-2.0

//! H8 invariants of the authenticated class (karyos#648) through the
//! production paths: the drivers' admission, the conductor's key duty and
//! both agents on loopback. Each test names the invariant it proves (the
//! `INV-` id of the round 4 invariant list).

use super::*;

/// [`established`], also returning the publication's handle and the
/// subscription.
fn established_with_handles() -> (
    EmbeddedDriver,
    EmbeddedDriver,
    crate::embedded::AggregateHandle,
    crate::net::NetworkSubscription,
) {
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let security = Security::Authenticated(auth(Some(authority(control()))));
    let subscription = subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (mut publisher, _) = keyed(&borrowed(&publisher_files()));
    let handle = publisher
        .add_network_publication(aggregate(STREAM), &udp(Destination::Unicast(to), security))
        .unwrap();
    let registration = handle.registration();
    let up = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        drivers[0]
            .net
            .as_ref()
            .unwrap()
            .publication_established(registration)
            && roles(drivers[0]).0 == (1, 1, 0)
            && roles(drivers[1]).1.1 == 1
    });
    assert!(up, "{:?} {:?}", roles(&publisher), roles(&subscriber));
    (publisher, subscriber, handle, subscription)
}

/// INV-EXP-1 (manifest 4.4 and 5; wire-key-files.md 2.3): a key file is
/// used only inside its validity. Once the wall clock passes the channel
/// and pairwise files' `not_after`, the conductor's next key tick, with no
/// reload and no file change, withdraws the publication's session sealer
/// and every image's sealer on both drivers, and no new authenticated
/// admission is taken under the expired keys.
#[test]
fn inv_an_expired_key_withdraws_every_authenticated_path_at_the_next_tick() {
    let (mut publisher, _, mut subscriber, _) = established();
    // 2027-01-30T00:00:00Z, the test files' `not_after`, plus one second;
    // short of the next reload is not needed: the tick re-reads validity.
    let not_after: i64 = 1_801_267_200;
    advance(not_after + 1 - wall());
    let withdrawn = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        roles(drivers[0]).0.1 == 0 && {
            let (_, images, withdrawn) = roles(drivers[1]).1;
            images == withdrawn
        }
    });
    assert!(
        withdrawn,
        "still live past not_after: {:?} {:?}",
        roles(&publisher),
        roles(&subscriber)
    );
    let security = Security::Authenticated(auth(None));
    assert_eq!(
        publisher
            .add_network_publication(
                aggregate(STREAM + 1),
                &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
            )
            .unwrap_err(),
        refused(AuthRefusal::ChannelKey)
    );
}

/// INV-ADM-10 (ADR-0086 section 8; H8 finding 8's retention rule applied
/// to the sender): removing an authenticated publication drops what its
/// admission bound in the sender role (its SETUP proof, domain 1
/// prototype, pairwise verifiers, boot id table and abort signer). Key
/// material is not retained past the publication it was admitted for.
#[test]
#[ignore = "H8 invariant: a removed authenticated publication keeps its keys in the sender role, fix pending"]
fn inv_a_removed_authenticated_publication_drops_its_keys() {
    let (mut publisher, mut subscriber, handle, _subscription) = established_with_handles();
    publisher.remove_aggregate(&handle).unwrap();
    let gone = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        drivers[0].net.as_ref().unwrap().publication_count() == 0 && roles(drivers[0]).0.1 == 0
    });
    assert!(gone, "never removed: {:?}", roles(&publisher));
    for _ in 0..50 {
        let _ = publisher.do_work().unwrap();
    }
    assert_eq!(
        roles(&publisher).0.0,
        0,
        "the removed publication's keys are still held"
    );
}

/// INV-ADM-11 (bind_auth.rs `Unbind`; H8 round 2 precondition): removing
/// an authenticated subscription drops its keys, its abort scope and its
/// control peer reservation in the receiver role.
#[test]
fn inv_a_removed_authenticated_subscription_drops_its_keys() {
    let (mut publisher, mut subscriber, _handle, subscription) = established_with_handles();
    assert!(
        subscriber
            .remove_network_subscription(subscription)
            .unwrap()
    );
    let gone = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        roles(drivers[1]).1.0 == 0
    });
    assert!(gone, "still bound: {:?}", roles(&subscriber));
}

/// INV-RST-2 (ADR-0086 section 7, "Snapshot rollback and clones"; SPEC.md
/// section 4): every driver start draws a fresh random `driver_id`, so a
/// restarted publisher's publication identities, and with them its domain
/// 1 and 4 keys, are new.
#[test]
fn inv_each_driver_start_draws_a_fresh_driver_id() {
    let first = driver_with(4);
    let second = driver_with(4);
    assert_ne!(first.driver_id(), [0, 0]);
    assert_ne!(first.driver_id(), second.driver_id());
}
