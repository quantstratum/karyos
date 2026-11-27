// SPDX-License-Identifier: Apache-2.0

//! H8 round 4 (karyos#648): invariants raised to proofs through
//! production admission and the guard authority's real STATUS
//! transmission on loopback. Each test names its `INV-` id.

use super::*;

/// A word of guard 11 closed at odd `epoch`.
fn closed_word(epoch: u64) -> Arc<karyos_client::HeapWords> {
    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(
        karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open: false }).unwrap(),
        karyos_sys::sync::Ordering::Release,
    );
    word
}

/// INV-RST-5 (ADR-0107 d7), end to end: the authority's committed epoch
/// survives its restart. Before, it opens the publication through real
/// STATUS transmission and commits epoch 2. A restarted authority over the
/// same commit directory whose guard word was restored below that epoch
/// signs and sends no STATUS: every challenge it gets is refused.
#[test]
fn inv_r4_a_restarted_authority_never_signs_below_its_committed_epoch() {
    let (marks, commits) = (Mem::default(), Mem::default());
    let control = SocketAddr::new(LOOPBACK, crate::test_ports::test_port());
    let guard = ChannelAuthority {
        follower_id: 66,
        ..authority(control)
    };
    let (mut authority_driver, _) = keyed(&borrowed(&authority_files()));
    authority_driver
        .start_guard_state(
            Box::new(Mem::default()) as Dir,
            Box::new(commits.clone()) as Dir,
        )
        .unwrap();
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let security = Security::Authenticated(auth(Some(guard)));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (mut publisher, _) = keyed(&borrowed(&guarded_files()));
    publisher
        .start_guard_state(
            Box::new(marks.clone()) as Dir,
            Box::new(Mem::default()) as Dir,
        )
        .unwrap();
    let handle = publisher
        .add_network_publication(aggregate(STREAM), &udp(Destination::Unicast(to), security))
        .unwrap();
    let registration = handle.registration();
    let from = {
        let net = publisher.net.as_ref().unwrap();
        net.endpoint_address(net.publication_paths(registration)[0])
            .unwrap()
    };
    let guards = |word: Arc<karyos_client::HeapWords>| {
        vec![crate::guard_authority::AuthorityGuard {
            guard_id: 11,
            word: word as Arc<dyn karyos_client::SharedWords>,
            lifetime_ms: 5_000,
            receivers: vec![(66, from)],
        }]
    };
    authority_driver
        .start_guard_authority(10, guards(open_word(2)), &[control])
        .unwrap();
    let opened = pump(
        &mut [&mut publisher, &mut subscriber, &mut authority_driver],
        |drivers| {
            drivers[0]
                .net
                .as_ref()
                .unwrap()
                .publication_established(registration)
        },
    );
    assert!(opened, "the original authority opens it");
    assert!(
        authority_driver
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .unwrap()
            .guard_statuses_sent
            >= 1
    );
    drop(authority_driver);
    // Restarted over the same commits, its word restored below them.
    let (mut restarted, _) = keyed(&borrowed(&authority_files()));
    restarted
        .start_guard_state(
            Box::new(Mem::default()) as Dir,
            Box::new(commits.clone()) as Dir,
        )
        .unwrap();
    if restarted
        .start_guard_authority(10, guards(closed_word(1)), &[control])
        .is_err()
    {
        // Refused at load: it signs nothing at all.
        return;
    }
    let refused = pump(
        &mut [&mut publisher, &mut subscriber, &mut restarted],
        |drivers| {
            drivers[2]
                .net
                .as_ref()
                .unwrap()
                .receiver_counters()
                .unwrap()
                .guard_challenges_refused
                > 0
        },
    );
    assert!(refused, "a challenge reached the restarted authority");
    assert_eq!(
        restarted
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .unwrap()
            .guard_statuses_sent,
        0,
        "nothing signed below the committed epoch"
    );
}
