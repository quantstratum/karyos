// SPDX-License-Identifier: Apache-2.0

//! ADR-0114 section 10: the signal, the fence, what a change stops, and
//! when the fence releases.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_protocol::protection::aes_gcm_siv::{
    Domain, EncRejection, KeyContext, MAX_PLAINTEXT, PublicationIdentity, Salt,
};

use super::super::{
    ChannelKeys, EncKeyError, EncOpener, EncSealer, EncSendError, MAX_SEALED, OpenRate,
    open_bootstrap,
};
use super::*;
use crate::wire_keys::{KEY_LEN, KeyFile, parse};

fn channel() -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| "11".to_owned()).collect();
    parse(
        "3-1.key",
        format!(
            "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=6\n"
        )
        .as_bytes(),
    )
    .unwrap()
}

fn keys() -> ChannelKeys {
    ChannelKeys::new(&[&channel()]).unwrap()
}

fn clock() -> u64 {
    1_000
}

fn context(domain: Domain, driver: u8) -> KeyContext {
    KeyContext {
        domain,
        key_epoch: 1,
        party_epoch: 0,
        session_id: 9,
        stream_id: 6,
        publication: PublicationIdentity {
            driver_id: [driver; 16],
            registration_id: 7,
            incarnation: 1,
        },
        receiver: None,
        salt: match domain {
            Domain::Sender => Salt::Challenge {
                receiver_boot_id: [2; 16],
                nonce: [3; 16],
            },
            _ => Salt::Empty,
        },
    }
}

/// One DATA frame header, 32 bytes, sealed into a fresh datagram.
fn sealed(sealer: &mut EncSealer) -> Result<Vec<u8>, EncSendError> {
    let mut bytes = vec![0_u8; MAX_SEALED];
    bytes[..4].copy_from_slice(&32_i32.to_le_bytes());
    bytes[4] = 1;
    bytes[6] = 1;
    let length = sealer.seal(&mut bytes, 32)?;
    bytes.truncate(length);
    Ok(bytes)
}

fn injected() -> (VmGenerationWatch, SignalInjector) {
    let (signal, injector) = InjectedSignal::new();
    (VmGenerationWatch::new(Box::new(signal)), injector)
}

/// Where the platform gives no signal, the deployment rule alone applies:
/// the watch says so, and no amount of time moves the generation (the
/// trigger is the signal, never a timer).
#[test]
fn without_a_signal_nothing_ever_closes() {
    let mut watch = VmGenerationWatch::platform();
    assert_eq!(watch.state(), SignalState::Unavailable);
    for now in [0, POLL_INTERVAL_NS, 3_600 * 1_000_000_000, u64::MAX] {
        assert_eq!(watch.poll(now), 0);
    }
    assert!(!quiesced());
    assert_eq!(generation_changes(), 0);
}

/// An injected signal is read at most once per interval, and only a
/// change moves the generation; it never moves back.
#[test]
fn only_the_signal_moves_the_generation() {
    let (mut watch, injector) = injected();
    assert_eq!(watch.state(), SignalState::Available);
    assert_eq!(watch.poll(0), 0);
    assert_eq!(watch.poll(10 * POLL_INTERVAL_NS), 0, "no change");
    injector.change();
    assert_eq!(
        watch.poll(10 * POLL_INTERVAL_NS + 1),
        0,
        "read again only after the interval"
    );
    assert_eq!(watch.poll(11 * POLL_INTERVAL_NS), 1);
    assert_eq!(watch.poll(u64::MAX), 1);
    // Another watch of the process sees it without its own signal.
    assert_eq!(VmGenerationWatch::new(Box::new(NoSignal)).poll(0), 1);
}

/// Section 10 steps 1 and 2 and the nonce invariant of section 5: after
/// the change, a sealer of every domain made before it seals nothing and
/// writes nothing, its envelope sequence does not move, an opener opens
/// nothing (a datagram sealed before the change included) and moves no
/// window, and while the fence is held no key is derived and no bootstrap
/// datagram opens. After the release the old keys stay dead.
#[test]
fn a_change_stops_every_key_made_before_it() {
    let (mut watch, injector) = injected();
    register();
    let keys = keys();
    let mut data = EncSealer::new(&keys, None, context(Domain::Sender, 1), clock).unwrap();
    let mut setup = EncSealer::new(&keys, None, context(Domain::Setup, 1), clock).unwrap();
    let mut opener = EncOpener::new(&keys, None, context(Domain::Sender, 1), 0).unwrap();
    let mut rate = OpenRate::default();
    let mut out = [0_u8; MAX_PLAINTEXT];
    let first = sealed(&mut data).unwrap();
    let pending = sealed(&mut data).unwrap();
    assert!(
        opener
            .open(&first, &mut out, &mut rate, 1_000, |_| Ok(()))
            .is_ok()
    );
    let mut announce = vec![0_u8; MAX_SEALED];
    let announce_len = setup.seal(&mut announce, 32).unwrap();
    announce.truncate(announce_len);
    let next_seq = (data.key().next_seq(), setup.key().next_seq());
    let window = opener.current_window();

    injector.change();
    assert_eq!(watch.poll(POLL_INTERVAL_NS), 1);
    assert!(quiesced(), "held until the registered role redraws");

    let check_old = |data: &mut EncSealer, setup: &mut EncSealer, opener: &mut EncOpener| {
        let mut bytes = vec![0xA5_u8; MAX_SEALED];
        assert_eq!(data.seal(&mut bytes, 32), Err(EncSendError::VmGeneration));
        assert_eq!(setup.seal(&mut bytes, 32), Err(EncSendError::VmGeneration));
        assert!(bytes.iter().all(|byte| *byte == 0xA5), "nothing written");
        assert_eq!((data.key().next_seq(), setup.key().next_seq()), next_seq);
        let mut out = [0_u8; MAX_PLAINTEXT];
        let mut rate = OpenRate::default();
        assert_eq!(
            opener
                .open(&pending, &mut out, &mut rate, 1_000, |_| Ok(()))
                .err(),
            Some(EncRejection::VmGeneration)
        );
        assert_eq!(opener.current_window(), window);
        assert_eq!(opener.resync(1, 1, 1_000), Err(EncRejection::VmGeneration));
        assert_eq!(opener.epochs(), (1, 0));
    };
    check_old(&mut data, &mut setup, &mut opener);
    // While held: no key for any context, the same one included.
    for domain in [Domain::Sender, Domain::Setup] {
        assert_eq!(
            EncSealer::new(&keys, None, context(domain, 1), clock).err(),
            Some(EncKeyError::VmGeneration)
        );
    }
    assert_eq!(
        EncOpener::new(&keys, None, context(Domain::Sender, 1), 0).err(),
        Some(EncKeyError::VmGeneration)
    );
    assert_eq!(
        open_bootstrap(
            &keys,
            None,
            None,
            &announce,
            &mut out,
            &mut rate,
            1_000,
            |_, _| { Ok(()) }
        )
        .err(),
        Some(EncRejection::VmGeneration)
    );

    // The role redrew: keys are made again, and the old ones stay dead.
    redrawn(1);
    assert!(!quiesced());
    check_old(&mut data, &mut setup, &mut opener);
    let mut fresh = EncSealer::new(&keys, None, context(Domain::Sender, 2), clock).unwrap();
    assert!(sealed(&mut fresh).is_ok());
}

/// The fence releases only once every registered role redrew for the
/// current generation: a stale report changes nothing, and a role
/// registered while it is held starts fresh and counts as redrawn.
#[test]
fn the_fence_releases_once_every_registered_role_redrew() {
    let (mut watch, injector) = injected();
    register();
    register();
    injector.change();
    assert_eq!(watch.poll(0), 1);
    assert!(quiesced());
    redrawn(1);
    assert!(quiesced(), "one of two");
    redrawn(0);
    assert!(quiesced(), "a stale report");
    register();
    assert!(
        quiesced(),
        "a new role counts as redrawn, the second has not"
    );
    redrawn(1);
    assert!(!quiesced());
    // A second change waits for all three.
    injector.change();
    assert_eq!(watch.poll(POLL_INTERVAL_NS), 2);
    redrawn(2);
    redrawn(2);
    assert!(quiesced());
    redrawn(2);
    assert!(!quiesced());
}

/// The successor of a `driver_id` in a generation is drawn once and is
/// the same for every caller, so the embedded driver and its sender role
/// agree; it is never zero nor the old id, and each id has its own. A
/// generation that has not happened has none.
#[test]
fn a_driver_id_has_one_successor_per_generation() {
    let (mut watch, injector) = injected();
    let old = [5, 6];
    assert_eq!(successor(old, 1), None, "no change yet");
    injector.change();
    assert_eq!(watch.poll(0), 1);
    let new = successor(old, 1).unwrap();
    assert_ne!(new, old);
    assert_ne!(new, [0, 0]);
    assert_eq!(successor(old, 1), Some(new));
    assert_eq!(successor(old, 2), None, "not yet");
    let other = successor([7, 8], 1).unwrap();
    assert_ne!(other, new);
}

/// Across repeated changes the table stays bounded: an entry goes once
/// [`KEEP_GENERATIONS`] newer generations exist, and a caller that far
/// behind gets nothing (fail closed) instead of a fresh draw that would
/// disagree with the callers that stepped in time.
#[test]
fn the_successor_table_stays_bounded() {
    let (mut watch, injector) = injected();
    let mut driver = [5, 6];
    let mut first = None;
    for generation in 1..=200_u64 {
        injector.change();
        assert_eq!(watch.poll(generation * POLL_INTERVAL_NS), generation);
        // Two drivers of the process step each time.
        driver = successor(driver, generation).unwrap();
        let _ = successor([generation, 1], generation).unwrap();
        first.get_or_insert(driver);
        assert!(successors_held() <= 2 * usize::try_from(KEEP_GENERATIONS).unwrap());
    }
    assert!(successors_held() <= MAX_SUCCESSORS);
    assert_eq!(successor([5, 6], 1), None, "pruned: fail closed");
    // A caller one step behind within the kept window still agrees.
    let held = successor([200, 1], 200).unwrap();
    assert_eq!(successor([200, 1], 200), Some(held));
}

/// Full, the table refuses a new successor (fail closed).
#[test]
fn a_full_successor_table_refuses() {
    let (mut watch, injector) = injected();
    injector.change();
    assert_eq!(watch.poll(0), 1);
    for id in 1..=u64::try_from(MAX_SUCCESSORS).unwrap() {
        assert!(successor([id, 9], 1).is_some());
    }
    assert_eq!(successor([0, 9], 1), None);
    assert!(successor([1, 9], 1).is_some(), "held entries still answer");
}
