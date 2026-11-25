// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::wire_keys::parse;

fn channel_file(epoch: u32, fill: u8) -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch={epoch}\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=1001\n"
    );
    parse(&format!("3-{epoch}.key"), text.as_bytes()).unwrap()
}

fn pairwise_file(epoch: u32, receiver_id: u64, fill: u8) -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch={epoch}\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nreceiver_id={receiver_id}\npublisher_id=5\n"
    );
    parse(&format!("9-{epoch}.key"), text.as_bytes()).unwrap()
}

const ALIAS: Alias = Alias {
    session_id: 41,
    stream_id: 1001,
};

const IDENTITY: Identity = Identity {
    driver_id: [0x1111, 0x2222],
    registration_id: 1,
    incarnation: 1,
};

const BOOT: [u64; 2] = [0xb0, 0x07];

const NOW: i64 = 1_796_083_200;

fn sender(boot: [u64; 2], nonce: [u64; 2]) -> Party {
    Party::Sender {
        identity: IDENTITY,
        lane_count: 1,
        receiver_boot_id: boot,
        nonce,
    }
}

fn receiver(boot: [u64; 2]) -> Party {
    Party::Receiver {
        identity: IDENTITY,
        receiver_boot_id: boot,
        receiver_id: 66,
    }
}

/// Seals `frames` and returns the datagram.
fn sealed(sealer: &mut Sealer, frames: &[u8]) -> Vec<u8> {
    let mut buf = vec![0_u8; 256];
    buf[..frames.len()].copy_from_slice(frames);
    let len = sealer.seal(&mut buf, frames.len()).unwrap();
    buf.truncate(len);
    buf
}

#[test]
fn a_sealed_datagram_opens_once_and_only_under_its_own_party() {
    let file = channel_file(1, 0x11);
    let party = sender(BOOT, [1, 2]);
    let mut sealer = Sealer::new(&file, party, ALIAS).unwrap();
    let mut verifier = Verifier::new([&file], party, ALIAS).unwrap();
    let datagram = sealed(&mut sealer, b"frames");
    let opened = verifier.open(&datagram, NOW).unwrap();
    assert_eq!(
        &datagram[opened.start..opened.start + opened.frames],
        b"frames"
    );
    // The same bytes again: the window refuses them.
    assert_eq!(
        verifier.open(&datagram, NOW),
        Err(Refusal::Replay(Replay::Duplicate))
    );
    // A receiver restart (new boot id) or a new nonce derives another
    // key: the datagram fails its tag and moves no window.
    for other in [sender([0xb1, 0x07], [1, 2]), sender(BOOT, [1, 3])] {
        let mut fresh = Verifier::new([&file], other, ALIAS).unwrap();
        assert_eq!(
            fresh.open(&datagram, NOW),
            Err(Refusal::Envelope(Rejection::Tag))
        );
        let mut again = Sealer::new(&file, other, ALIAS).unwrap();
        assert!(fresh.open(&sealed(&mut again, b"x"), NOW).is_ok());
    }
    // A sender restart is a new identity, and so a new key.
    let restarted = Party::Sender {
        identity: Identity {
            driver_id: [0x3333, 0x2222],
            ..IDENTITY
        },
        lane_count: 1,
        receiver_boot_id: BOOT,
        nonce: [1, 2],
    };
    let mut other = Verifier::new([&file], restarted, ALIAS).unwrap();
    assert_eq!(
        other.open(&datagram, NOW),
        Err(Refusal::Envelope(Rejection::Tag))
    );
}

#[test]
fn a_forged_or_altered_datagram_moves_no_window() {
    let file = channel_file(1, 0x11);
    let party = sender(BOOT, [1, 2]);
    let mut sealer = Sealer::new(&file, party, ALIAS).unwrap();
    let mut verifier = Verifier::new([&file], party, ALIAS).unwrap();
    let first = sealed(&mut sealer, b"one");
    // A far-ahead sequence with a bad tag must not slide the window past
    // the genuine datagram.
    let mut forged = first.clone();
    forged[24..32].copy_from_slice(&5000_u64.to_le_bytes());
    assert_eq!(
        verifier.open(&forged, NOW),
        Err(Refusal::Envelope(Rejection::Tag))
    );
    let mut flipped = first.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(
        verifier.open(&flipped, NOW),
        Err(Refusal::Envelope(Rejection::Tag))
    );
    assert!(verifier.open(&first, NOW).is_ok());
    // Wrong key id, short datagram.
    let mut other_key = first.clone();
    other_key[20..24].copy_from_slice(&4_u32.to_le_bytes());
    assert_eq!(
        verifier.open(&other_key, NOW),
        Err(Refusal::Envelope(Rejection::Key))
    );
    assert_eq!(
        verifier.open(&first[..10], NOW),
        Err(Refusal::Envelope(Rejection::Short))
    );
    // A domain 4 datagram is never a domain 1 one.
    let pair = pairwise_file(1, 66, 0x22);
    let mut rcv = Sealer::new(&pair, receiver(BOOT), ALIAS).unwrap();
    let sm = sealed(&mut rcv, b"sm");
    assert!(matches!(verifier.open(&sm, NOW), Err(Refusal::Envelope(_))));
}

#[test]
fn keys_must_fit_their_party() {
    let channel = channel_file(1, 0x11);
    let pair = pairwise_file(1, 66, 0x22);
    let other_pair = pairwise_file(1, 67, 0x23);
    assert_eq!(
        Sealer::new(&pair, sender(BOOT, [1, 2]), ALIAS).unwrap_err(),
        KeyError::Purpose
    );
    assert_eq!(
        Sealer::new(&channel, receiver(BOOT), ALIAS).unwrap_err(),
        KeyError::Purpose
    );
    assert_eq!(
        Sealer::new(&other_pair, receiver(BOOT), ALIAS).unwrap_err(),
        KeyError::Scope
    );
    let none: [&KeyFile; 0] = [];
    assert_eq!(
        Verifier::new(none, receiver(BOOT), ALIAS).unwrap_err(),
        KeyError::NoKey
    );
    let (a, b, c) = (
        pairwise_file(1, 66, 1),
        pairwise_file(2, 66, 2),
        pairwise_file(3, 66, 3),
    );
    assert_eq!(
        Verifier::new([&a, &b, &c], receiver(BOOT), ALIAS).unwrap_err(),
        KeyError::NoKey
    );
    assert_eq!(
        Verifier::new([&a, &a], receiver(BOOT), ALIAS).unwrap_err(),
        KeyError::Mixed
    );
    assert_eq!(
        Proof::new(
            ProofKind::RspSetup { receiver_id: 67 },
            ALIAS,
            Some(&a),
            [&a],
            1
        )
        .unwrap_err(),
        KeyError::Scope
    );
}

#[test]
fn the_overlap_verifies_both_file_epochs_and_a_reload_keeps_their_windows() {
    let (old, new) = (pairwise_file(1, 66, 0x31), pairwise_file(2, 66, 0x32));
    let party = receiver(BOOT);
    let mut old_sealer = Sealer::new(&old, party, ALIAS).unwrap();
    let mut new_sealer = Sealer::new(&new, party, ALIAS).unwrap();
    let mut verifier = Verifier::new([&old, &new], party, ALIAS).unwrap();
    let under_old = sealed(&mut old_sealer, b"a");
    let under_new = sealed(&mut new_sealer, b"b");
    assert!(verifier.open(&under_old, NOW).is_ok());
    assert!(verifier.open(&under_new, NOW).is_ok());
    // A reload with the same two files keeps both windows.
    verifier.refresh([&old, &new]).unwrap();
    assert_eq!(
        verifier.open(&under_old, NOW),
        Err(Refusal::Replay(Replay::Duplicate))
    );
    // The old file epoch retires: its datagrams no longer open, and the
    // new one's window survives.
    verifier.refresh([&new]).unwrap();
    assert!(matches!(
        verifier.open(&sealed(&mut old_sealer, b"c"), NOW),
        Err(Refusal::Envelope(_))
    ));
    assert_eq!(
        verifier.open(&under_new, NOW),
        Err(Refusal::Replay(Replay::Duplicate))
    );
    // Another key id is refused and changes nothing.
    let other = channel_file(1, 1);
    assert!(verifier.refresh([&other]).is_err());
    assert!(verifier.open(&sealed(&mut new_sealer, b"d"), NOW).is_ok());
}

#[test]
fn the_sender_moves_epoch_at_75_percent_and_refuses_at_the_limit() {
    let file = channel_file(1, 0x11);
    let party = sender(BOOT, [1, 2]);
    let mut verifier = Verifier::new([&file], party, ALIAS).unwrap();
    // Just below the threshold: epoch 0, then 1 from sequence 0.
    let mut sealer = Sealer::at_seq(&file, party, ALIAS, 0, ROTATE_AT - 1);
    let last_old = sealed(&mut sealer, b"old");
    assert_eq!(sealer.party_epoch(), 0);
    let first_new = sealed(&mut sealer, b"new");
    assert_eq!(sealer.party_epoch(), 1);
    assert_eq!(first_new[11], 1);
    assert_eq!(u64::from_le_bytes(first_new[24..32].try_into().unwrap()), 0);
    assert!(verifier.open(&last_old, NOW).is_ok());
    assert!(verifier.open(&first_new, NOW).is_ok());
    // The previous epoch still opens during the overlap; epoch 2 is now
    // the one derived ahead.
    let mut straggler = Sealer::at_seq(&file, party, ALIAS, 0, ROTATE_AT - 3);
    assert!(verifier.open(&sealed(&mut straggler, b"late"), NOW).is_ok());
    let mut two = Sealer::at_seq(&file, party, ALIAS, 2, 0);
    assert!(verifier.open(&sealed(&mut two, b"two"), NOW).is_ok());
    // Epoch 0 is now two behind and refused.
    assert_eq!(
        verifier.open(&sealed(&mut straggler, b"later"), NOW),
        Err(Refusal::Envelope(Rejection::Epoch))
    );
    // The last in-band epoch cannot move on: the sender stops.
    let mut last = Sealer::at_seq(&file, party, ALIAS, u8::MAX, ROTATE_AT);
    let mut buf = [0_u8; 128];
    assert_eq!(last.seal(&mut buf, 4), Err(SealFailure::Exhausted));
    assert_eq!(last.party_epoch(), u8::MAX);
    // A buffer too small fails without using a sequence.
    let mut small = Sealer::new(&file, party, ALIAS).unwrap();
    let mut tiny = [0_u8; 40];
    assert!(matches!(
        small.seal(&mut tiny, 4),
        Err(SealFailure::Buffer(_))
    ));
    let first = sealed(&mut small, b"ok");
    assert_eq!(u64::from_le_bytes(first[24..32].try_into().unwrap()), 0);
}

#[test]
fn proofs_bind_their_domain_and_report_the_file_epoch() {
    let (old, new) = (channel_file(1, 0x41), channel_file(2, 0x42));
    let publisher = Proof::new(ProofKind::Setup, ALIAS, Some(&new), [&old, &new], 2).unwrap();
    let mut buf = vec![0_u8; 128];
    buf[..5].copy_from_slice(b"setup");
    let len = publisher.seal(&mut buf, 5).unwrap();
    let receiver_side = Proof::new(ProofKind::Setup, ALIAS, None, [&old, &new], 2).unwrap();
    let proved = receiver_side.verify(&buf[..len]).unwrap();
    assert_eq!((proved.file_epoch, proved.current), (2, true));
    // Under the previous epoch's key it verifies, but not as current.
    let stale = Proof::new(ProofKind::Setup, ALIAS, Some(&old), [&old], 1).unwrap();
    let len = stale.seal(&mut buf, 5).unwrap();
    let proved = receiver_side.verify(&buf[..len]).unwrap();
    assert_eq!((proved.file_epoch, proved.current), (1, false));
    // No window: the same bytes verify again; freshness is the
    // transcript's.
    assert!(receiver_side.verify(&buf[..len]).is_ok());
    // An RSP_SETUP key never verifies a SETUP proof.
    let pair = pairwise_file(2, 66, 0x42);
    let rsp = Proof::new(
        ProofKind::RspSetup { receiver_id: 66 },
        ALIAS,
        Some(&pair),
        [&pair],
        2,
    )
    .unwrap();
    let len = rsp.seal(&mut buf, 5).unwrap();
    assert!(receiver_side.verify(&buf[..len]).is_err());
    // A verify-only proof cannot seal.
    assert_eq!(receiver_side.seal(&mut buf, 5), Err(SealFailure::Exhausted));
}

fn proved(file_epoch: u32, current: bool) -> Proved {
    Proved {
        opened: Opened {
            start: HEADER_LEN,
            frames: 0,
            seq: 0,
        },
        file_epoch,
        current,
    }
}

#[test]
fn the_publisher_rule_never_rebinds_a_retired_boot_id() {
    let mut table = BootTable::new(2);
    let (b0, b1, b2) = ([1, 0], [2, 0], [3, 0]);
    assert_eq!(table.decide(66, b0, &proved(1, true)), BootDecision::Bind);
    assert_eq!(table.decide(66, b0, &proved(1, true)), BootDecision::Bound);
    // The receiver restarted: B1 binds and B0 retires for good.
    assert_eq!(table.decide(66, b1, &proved(1, true)), BootDecision::Bind);
    assert_eq!(
        table.decide(66, b0, &proved(1, true)),
        BootDecision::Retired
    );
    // Under the previous file epoch's key nothing binds or changes.
    assert_eq!(
        table.decide(66, b2, &proved(0, false)),
        BootDecision::PreviousEpoch
    );
    assert_eq!(
        table.decide(67, b2, &proved(0, false)),
        BootDecision::PreviousEpoch
    );
    assert_eq!(table.decide(66, b1, &proved(1, true)), BootDecision::Bound);
    // A new file epoch keeps the old epoch's retired ids until it stops
    // verifying.
    assert_eq!(table.decide(66, b2, &proved(2, true)), BootDecision::Bind);
    assert_eq!(
        table.decide(66, b0, &proved(2, true)),
        BootDecision::Retired
    );
    assert_eq!(
        table.decide(66, b1, &proved(2, true)),
        BootDecision::Retired
    );
    // Forgetting another receiver's old epoch touches nothing here.
    table.forget_before(67, 2);
    assert_eq!(
        table.decide(66, b0, &proved(2, true)),
        BootDecision::Retired
    );
    table.forget_before(66, 2);
    assert_eq!(table.decide(66, b0, &proved(2, true)), BootDecision::Bind);
    // The table of receivers is sized at admission.
    assert_eq!(table.decide(67, b0, &proved(2, true)), BootDecision::Bind);
    assert_eq!(table.decide(68, b0, &proved(2, true)), BootDecision::Full);
}

#[test]
fn a_full_retired_list_refuses_new_boot_ids_until_the_next_file_epoch() {
    let mut table = BootTable::new(1);
    for boot in 0..=u64::try_from(MAX_RETIRED_BOOTS).unwrap() {
        assert_eq!(
            table.decide(66, [boot, 1], &proved(1, true)),
            BootDecision::Bind
        );
    }
    let fresh = [99, 1];
    assert_eq!(
        table.decide(66, fresh, &proved(1, true)),
        BootDecision::Full
    );
    // The bound one still answers.
    let bound = [u64::try_from(MAX_RETIRED_BOOTS).unwrap(), 1];
    assert_eq!(
        table.decide(66, bound, &proved(1, true)),
        BootDecision::Bound
    );
    assert_eq!(
        table.decide(66, fresh, &proved(2, true)),
        BootDecision::Bind
    );
}

#[test]
fn a_verify_only_side_never_takes_the_retiring_key_for_the_current_one() {
    // Only the retiring file epoch 1 is loaded, but the lineage's current
    // one is 2: an RSP_SETUP under 1 verifies and must not bind.
    let old = pairwise_file(1, 66, 0x51);
    let kind = ProofKind::RspSetup { receiver_id: 66 };
    let receiver_side = Proof::new(kind, ALIAS, Some(&old), [&old], 1).unwrap();
    let mut buf = vec![0_u8; 128];
    let len = receiver_side.seal(&mut buf, 3).unwrap();
    let publisher = Proof::new(kind, ALIAS, None, [&old], 2).unwrap();
    let proved = publisher.verify(&buf[..len]).unwrap();
    assert_eq!((proved.file_epoch, proved.current), (1, false));
    let mut table = BootTable::new(1);
    assert_eq!(table.decide(66, BOOT, &proved), BootDecision::PreviousEpoch);
}

#[test]
fn the_previous_in_band_epoch_stops_verifying_after_its_overlap() {
    let file = channel_file(1, 0x11);
    let party = sender(BOOT, [1, 2]);
    let mut verifier = Verifier::new([&file], party, ALIAS).unwrap();
    let mut old = Sealer::at_seq(&file, party, ALIAS, 0, 100);
    let mut new = Sealer::at_seq(&file, party, ALIAS, 1, 0);
    let early = sealed(&mut old, b"a");
    let at_edge = sealed(&mut old, b"b");
    let too_late = sealed(&mut old, b"c");
    // The move to epoch 1 at NOW starts the overlap.
    assert!(verifier.open(&sealed(&mut new, b"n"), NOW).is_ok());
    assert!(verifier.open(&early, NOW).is_ok());
    assert!(verifier.open(&at_edge, NOW + IN_BAND_OVERLAP_S - 1).is_ok());
    // From the deadline on, epoch 0 is gone even within its window.
    assert_eq!(
        verifier.open(&too_late, NOW + IN_BAND_OVERLAP_S),
        Err(Refusal::Envelope(Rejection::Epoch))
    );
    // The current epoch still verifies.
    assert!(
        verifier
            .open(&sealed(&mut new, b"m"), NOW + IN_BAND_OVERLAP_S)
            .is_ok()
    );
}

#[test]
fn a_reload_with_no_key_left_clears_every_key() {
    let pair = pairwise_file(1, 66, 0x61);
    let party = receiver(BOOT);
    let mut sealer = Sealer::new(&pair, party, ALIAS).unwrap();
    let mut verifier = Verifier::new([&pair], party, ALIAS).unwrap();
    let datagram = sealed(&mut sealer, b"sm");
    let none: [&KeyFile; 0] = [];
    verifier.refresh(none).unwrap();
    assert_eq!(
        verifier.open(&datagram, NOW),
        Err(Refusal::Envelope(Rejection::Epoch))
    );
    assert_eq!(
        verifier.open(&sealed(&mut sealer, b"sm2"), NOW),
        Err(Refusal::Envelope(Rejection::Epoch))
    );
}

/// A checked datagram that its caller refuses (for its inner frames) and
/// never commits consumes no sequence and moves no epoch: the same
/// sequence still opens, and a next-epoch datagram checked only does not
/// start the old epoch's overlap.
#[test]
fn a_check_without_a_commit_changes_nothing() {
    let file = channel_file(1, 0x11);
    let party = sender(BOOT, [1, 2]);
    let mut verifier = Verifier::new([&file], party, ALIAS).unwrap();
    let mut old = Sealer::at_seq(&file, party, ALIAS, 0, 7);
    let mut new = Sealer::at_seq(&file, party, ALIAS, 1, 0);
    let first = sealed(&mut old, b"a");
    let late = sealed(&mut old, b"b");
    let checked = verifier.check(&first, NOW).unwrap();
    assert_eq!(checked.opened().seq, 7);
    // Checked again: nothing was recorded.
    let again = verifier.check(&first, NOW).unwrap();
    assert_eq!(verifier.commit(again, NOW).unwrap().seq, 7);
    // Now recorded: a duplicate.
    assert_eq!(
        verifier.check(&first, NOW),
        Err(Refusal::Replay(Replay::Duplicate))
    );
    // A stale check of the same datagram cannot commit twice.
    assert_eq!(
        verifier.commit(checked, NOW),
        Err(Refusal::Replay(Replay::Duplicate))
    );
    // The next epoch, checked and never committed: epoch 0 stays current,
    // so it still verifies long after an overlap would have ended.
    let moved = sealed(&mut new, b"n");
    let _ = verifier.check(&moved, NOW).unwrap();
    assert!(verifier.open(&late, NOW + IN_BAND_OVERLAP_S + 1).is_ok());
    // Committed, the move happens and starts the overlap from then.
    let checked = verifier.check(&moved, NOW + IN_BAND_OVERLAP_S + 1).unwrap();
    assert!(
        verifier
            .commit(checked, NOW + IN_BAND_OVERLAP_S + 1)
            .is_ok()
    );
    let past = sealed(&mut old, b"c");
    assert_eq!(
        verifier.open(&past, NOW + 2 * IN_BAND_OVERLAP_S + 1),
        Err(Refusal::Envelope(Rejection::Epoch))
    );
}
