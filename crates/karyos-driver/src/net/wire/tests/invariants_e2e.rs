// SPDX-License-Identifier: Apache-2.0

//! H8 invariants once proven only at unit level, raised to end-to-end
//! proofs through production admission, the conductor's key duty and both
//! agents on loopback (karyos#648). Each test names its `INV-` id in the
//! round 4 invariant list.

use super::*;

/// A driver over `keys` and `state` (kept by the caller), started at the
/// test wall clock.
fn started(keys: &Mem, state: &Mem) -> EmbeddedDriver {
    let mut driver = driver_with(64);
    driver
        .start_wire_keys_at(
            Box::new(keys.clone()) as Dir,
            Box::new(state.clone()) as Dir,
            wall,
        )
        .unwrap();
    driver
}

/// An established pair whose publisher's key and state directories are
/// both returned: publisher, its keys, its state, subscriber, its keys.
fn established_with_state() -> (EmbeddedDriver, Mem, Mem, EmbeddedDriver, Mem) {
    let (mut subscriber, sub_keys) = keyed(&borrowed(&subscriber_files()));
    let security = Security::Authenticated(auth(Some(authority(control()))));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (keys, state) = dirs(&borrowed(&publisher_files()));
    let mut publisher = started(&keys, &state);
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
    (publisher, keys, state, subscriber, sub_keys)
}

/// Whether both roles of the pair have withdrawn every authenticated path.
fn withdrawn(drivers: &[&mut EmbeddedDriver]) -> bool {
    roles(drivers[0]).0.1 == 0 && {
        let (_, images, withdrawn) = roles(drivers[1]).1;
        images == withdrawn
    }
}

/// A new authenticated publication of `stream` on `driver`, refused or not.
fn admit(driver: &mut EmbeddedDriver, stream: i32) -> Result<(), DriverError> {
    let security = Security::Authenticated(auth(None));
    driver
        .add_network_publication(
            aggregate(stream),
            &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
        )
        .map(|_| ())
}

/// INV-REV-1 (WK 2.4), end to end: a revocation withdraws the session on
/// both drivers, survives the removal of the revoked list and a driver
/// restart over the same key and state directories: the revoked key is
/// never admitted again.
#[test]
fn inv_e2e_a_revocation_is_durable_across_a_cleared_list_and_a_restart() {
    let (mut publisher, keys, state, mut subscriber, sub_keys) = established_with_state();
    for dir in [&keys, &sub_keys] {
        dir.put("revoked", "3-1\n9-1\n");
    }
    advance(RELOAD_INTERVAL_S);
    assert!(pump(&mut [&mut publisher, &mut subscriber], |d| withdrawn(
        d
    )));
    keys.files.lock().unwrap().remove("revoked");
    advance(RELOAD_INTERVAL_S);
    for _ in 0..50 {
        let _ = publisher.do_work().unwrap();
    }
    assert_eq!(
        admit(&mut publisher, STREAM + 1),
        Err(refused(AuthRefusal::ChannelKey))
    );
    drop(publisher);
    let mut restarted = started(&keys, &state);
    assert_eq!(
        admit(&mut restarted, STREAM + 1),
        Err(refused(AuthRefusal::ChannelKey)),
        "the durable record keeps it revoked"
    );
}

/// INV-REV-7 (WK 2.4), end to end: an admitted key file whose bytes change
/// under its name disables the key for good: the live session is withdrawn
/// on both roles, and restoring the original bytes does not re-admit it.
#[test]
fn inv_e2e_a_changed_key_file_withdraws_the_session_for_good() {
    let (mut publisher, keys, _state, mut subscriber, _) = established_with_state();
    let changed = channel_key(3, STREAM).replacen("secret=03", "secret=99", 1);
    keys.put("3-1.key", &changed);
    advance(RELOAD_INTERVAL_S);
    assert!(
        pump(&mut [&mut publisher, &mut subscriber], |d| roles(d[0]).0.1
            == 0),
        "{:?}",
        roles(&publisher)
    );
    keys.put("3-1.key", &channel_key(3, STREAM));
    advance(RELOAD_INTERVAL_S);
    for _ in 0..50 {
        let _ = publisher.do_work().unwrap();
    }
    assert_eq!(
        admit(&mut publisher, STREAM + 1),
        Err(refused(AuthRefusal::ChannelKey))
    );
    assert_eq!(roles(&publisher).0.1, 0);
}

/// INV-KSF-2 (WK 2.4), end to end: a revoked list that does not validate
/// disables every authenticated path on both drivers and refuses admission.
#[test]
fn inv_e2e_a_malformed_revoked_list_disables_every_path() {
    let (mut publisher, keys, _state, mut subscriber, sub_keys) = established_with_state();
    for dir in [&keys, &sub_keys] {
        dir.put("revoked", "*\n");
    }
    advance(RELOAD_INTERVAL_S);
    assert!(
        pump(&mut [&mut publisher, &mut subscriber], |d| withdrawn(d)),
        "{:?} {:?}",
        roles(&publisher),
        roles(&subscriber)
    );
    assert_eq!(
        admit(&mut publisher, STREAM + 1),
        Err(refused(AuthRefusal::KeyStoreDisabled))
    );
}

/// INV-KSF-3 (WK 2.6), end to end: a state commit that fails disables
/// every key, so the live session is withdrawn and admission refused, and
/// once commits succeed again the store admits again.
#[test]
fn inv_e2e_a_failed_state_commit_disables_every_path_until_one_succeeds() {
    let (mut publisher, keys, state, mut subscriber, _) = established_with_state();
    *state.fail_writes.lock().unwrap() = true;
    // A new file needs a commit to be admitted.
    keys.put("4-1.key", &channel_key(4, STREAM + 1));
    advance(RELOAD_INTERVAL_S);
    assert!(
        pump(&mut [&mut publisher, &mut subscriber], |d| roles(d[0]).0.1
            == 0),
        "{:?}",
        roles(&publisher)
    );
    assert_eq!(
        admit(&mut publisher, STREAM + 1),
        Err(refused(AuthRefusal::KeyStoreDisabled))
    );
    *state.fail_writes.lock().unwrap() = false;
    advance(RELOAD_INTERVAL_S);
    for _ in 0..50 {
        let _ = publisher.do_work().unwrap();
    }
    assert!(publisher.wire_key_counters().unwrap().failures >= 1);
    assert_eq!(admit(&mut publisher, STREAM + 1), Ok(()));
}

/// INV-KSF-5 and INV-REV-6 (H8 N1), end to end: after a store outage
/// withdraws the session, the recovered store does not revive it: the
/// withdrawn session sealer and the images' sealers stay withdrawn (no
/// window or sealer of that establishment returns), while the recovered
/// store admits new channels again (the test is not vacuous).
#[test]
fn inv_e2e_a_recovered_store_does_not_revive_the_withdrawn_session() {
    let (mut publisher, keys, _state, mut subscriber, sub_keys) = established_with_state();
    for dir in [&keys, &sub_keys] {
        *dir.fail_list.lock().unwrap() = true;
    }
    advance(RELOAD_INTERVAL_S);
    assert!(pump(&mut [&mut publisher, &mut subscriber], |d| withdrawn(
        d
    )));
    let images = roles(&subscriber).1.1;
    for dir in [&keys, &sub_keys] {
        *dir.fail_list.lock().unwrap() = false;
    }
    advance(RELOAD_INTERVAL_S);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut revived = false;
    while std::time::Instant::now() < deadline && !revived {
        let _ = publisher.do_work().unwrap();
        let _ = subscriber.do_work().unwrap();
        let (_, now, still) = roles(&subscriber).1;
        revived = roles(&publisher).0.1 != 0 || (now == images && still < images);
        std::thread::sleep(Duration::from_micros(200));
    }
    assert!(!revived, "{:?} {:?}", roles(&publisher), roles(&subscriber));
    assert_eq!(
        admit(&mut publisher, STREAM + 1),
        Ok(()),
        "the store recovered"
    );
}

/// INV-KSF-6 (WK 2.6), end to end: a driver whose state directory was
/// never initialised does not start its store, and every authenticated
/// admission is then refused, typed.
#[test]
fn inv_e2e_an_uninitialised_state_starts_no_store_and_admits_nothing() {
    let (keys, state) = (Mem::default(), Mem::default());
    for (name, text) in publisher_files() {
        keys.put(name, &text);
    }
    let mut driver = driver_with(64);
    assert!(matches!(
        driver.start_wire_keys_at(Box::new(keys) as Dir, Box::new(state) as Dir, wall),
        Err(DriverError::KeyStoreStart(_))
    ));
    assert_eq!(
        admit(&mut driver, STREAM),
        Err(refused(AuthRefusal::NoKeyStore))
    );
}

/// INV-KSF-8 (WK 2.2), end to end: a key whose secret another key already
/// uses is never admitted: a channel naming it is refused, typed, while
/// the original key still admits.
#[test]
fn inv_e2e_a_reused_secret_is_refused_at_admission() {
    let mut files = publisher_files();
    files.push((
        "4-1.key",
        channel_key(3, STREAM + 1).replacen("key_id=3", "key_id=4", 1),
    ));
    let (mut driver, _) = keyed_allowing_alarm(&borrowed(&files));
    let security = Security::Authenticated(AuthenticatedChannel {
        channel_key_id: 4,
        ..auth(None)
    });
    assert_eq!(
        driver
            .add_network_publication(
                aggregate(STREAM + 1),
                &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
            )
            .map(|_| ()),
        Err(refused(AuthRefusal::ChannelKey))
    );
    assert_eq!(
        admit(&mut driver, STREAM),
        Ok(()),
        "the original key admits"
    );
}

/// [`keyed`] without its no-alarm assertion: a refused file is reported.
fn keyed_allowing_alarm(files: &[(&str, &str)]) -> (EmbeddedDriver, Mem) {
    let (keys, state) = dirs(files);
    (started(&keys, &state), keys)
}
