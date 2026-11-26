// SPDX-License-Identifier: Apache-2.0

//! The receive order, the accounting and the downgrade refusals of
//! ADR-0114 sections 6 to 9 (quantstratum/karyos#650 and #651).

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::cell::Cell;

use karyos_protocol::network::encrypted::EncAnswer;
use karyos_protocol::network::{Alias, ChallengeBlock, Identity, Lanes, SetupAnswer, TermParams};

use super::*;
use crate::wire_keys::parse;

thread_local! {
    /// The test clock, per test thread.
    static NOW: Cell<u64> = const { Cell::new(1_000 * SECOND_NS) };
}

fn clock() -> u64 {
    NOW.with(Cell::get)
}

fn set_now(now: u64) {
    NOW.with(|cell| cell.set(now));
}

fn channel_file(epoch: u32, fill: u8) -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch={epoch}\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=6\n"
    );
    parse(&format!("3-{epoch}.key"), text.as_bytes()).unwrap()
}

fn pairwise_file(receiver_id: u64, epoch: u32, fill: u8) -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch={epoch}\npurpose=pairwise\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nreceiver_id={receiver_id}\npublisher_id=5\n"
    );
    parse(&format!("9-{epoch}.key"), text.as_bytes()).unwrap()
}

fn keys() -> ChannelKeys {
    ChannelKeys::new(&[&channel_file(1, 0x11)]).unwrap()
}

fn pairs(fill: u8) -> PairwiseFiles {
    PairwiseFiles::new(&[&pairwise_file(66, 1, fill)]).unwrap()
}

const PUBLICATION: PublicationIdentity = PublicationIdentity {
    driver_id: [1; 16],
    registration_id: 7,
    incarnation: 1,
};
const RECEIVER: ReceiverIdentity = ReceiverIdentity {
    receiver_boot_id: [2; 16],
    receiver_id: 66,
};
const SALT: Salt = Salt::Challenge {
    receiver_boot_id: [2; 16],
    nonce: [3; 16],
};

fn context(domain: Domain) -> KeyContext {
    KeyContext {
        domain,
        key_epoch: 1,
        party_epoch: 0,
        session_id: 9,
        stream_id: 6,
        publication: PUBLICATION,
        receiver: domain.is_receiver().then_some(RECEIVER),
        salt: if domain.is_bootstrap() {
            Salt::Empty
        } else {
            SALT
        },
    }
}

/// A 32-byte inner frame of `frame_type`.
fn frame(frame_type: u16) -> [u8; 32] {
    let mut out = [7_u8; 32];
    out[..4].copy_from_slice(&32_i32.to_le_bytes());
    out[4] = 1;
    out[5] = 0;
    out[6..8].copy_from_slice(&frame_type.to_le_bytes());
    out
}

fn seal(sealer: &mut EncSealer, frames: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; MAX_SEALED];
    bytes[..frames.len()].copy_from_slice(frames);
    let length = sealer.seal(&mut bytes, frames.len()).unwrap();
    bytes.truncate(length);
    bytes
}

fn sender() -> EncSealer {
    EncSealer::new(&keys(), None, context(Domain::Sender), clock).unwrap()
}

fn opener() -> EncOpener {
    EncOpener::new(&keys(), None, context(Domain::Sender), clock()).unwrap()
}

fn open(
    opener: &mut EncOpener,
    channel: &mut EncChannel,
    datagram: &[u8],
) -> Result<Accepted, EncRejection> {
    let mut out = [0_u8; MAX_PLAINTEXT];
    let result = opener.open(datagram, &mut out, &mut channel.rate, clock(), |_| Ok(()));
    if let Err(reason) = result {
        channel.rejections.bump(reason);
        assert!(out.iter().all(|byte| *byte == 0), "nothing released");
    }
    result
}

const DATA: u16 = 0x01;

/// Every reason has its own counter.
#[test]
fn every_rejection_reason_has_its_own_counter() {
    use EncRejection as R;
    let all = [
        R::Short,
        R::Length,
        R::TooLong,
        R::Version,
        R::Flags,
        R::Reserved,
        R::FrameType,
        R::BareFrame,
        R::WrongClass,
        R::MixedClass,
        R::PlaintextSetup,
        R::Profile,
        R::TagLength,
        R::Domain,
        R::Epoch,
        R::Binding,
        R::Party,
        R::SequenceCap,
        R::Duplicate,
        R::TooOld,
        R::Tag,
        R::Pairwise,
        R::Unexpected,
        R::InnerRejected,
        R::OpenRate,
        R::KeyAge,
        R::RetiredBoot,
        R::RetiredParty,
        R::ResyncRefused,
        R::BeforeJoin,
        R::VmGeneration,
        R::Withdrawn,
    ];
    assert_eq!(all.len(), ENC_REASONS);
    let mut seen = [false; ENC_REASONS];
    for reason in all {
        assert!(!seen[reason_index(reason)]);
        seen[reason_index(reason)] = true;
    }
    let mut counters = EncRejections::default();
    counters.counts[reason_index(R::Tag)] = u64::MAX;
    counters.bump(R::Tag);
    assert_eq!(counters.get(R::Tag), u64::MAX, "saturating");
    assert_eq!(counters.get(R::Epoch), 0);
}

/// Section 9, "Downgrade": each attack shape on an `encrypted` channel is
/// refused before any key is tried, with its own reason.
#[test]
fn every_downgrade_shape_has_its_own_reason() {
    let mut sealer = sender();
    let valid = seal(&mut sealer, &frame(DATA));
    // Envelope stripped: a bare frame of each SPEC.md section 5 type.
    for code in [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x08, 0x10, 0x11, 0x12, 0x13,
    ] {
        assert_eq!(header(&frame(code)), Err(EncRejection::BareFrame), "{code}");
    }
    // A plaintext SETUP or a bare RSP_SETUP.
    for code in [0x05, 0x07] {
        assert_eq!(header(&frame(code)), Err(EncRejection::PlaintextSetup));
    }
    // An authenticated envelope as the outer frame.
    let mut wrong = valid.clone();
    wrong[6..8].copy_from_slice(&0x20_u16.to_le_bytes());
    assert_eq!(header(&wrong), Err(EncRejection::WrongClass));
    // Bytes after the tag.
    let mut trailing = valid.clone();
    trailing.extend_from_slice(&frame(DATA));
    assert_eq!(header(&trailing), Err(EncRejection::MixedClass));
    // Another profile, the reserved ones included.
    for profile in [0, 1, 4, 17, 18, 255] {
        let mut other = valid.clone();
        other[8] = profile;
        assert_eq!(header(&other), Err(EncRejection::Profile), "{profile}");
    }
    // Longer than 1408 bytes.
    let mut long = valid.clone();
    long.resize(MAX_DATAGRAM + 1, 0);
    let length = i32::try_from(long.len()).unwrap();
    long[..4].copy_from_slice(&length.to_le_bytes());
    assert_eq!(header(&long), Err(EncRejection::TooLong));
    // An unknown domain.
    let mut domain = valid.clone();
    domain[10] = 2;
    assert_eq!(header(&domain), Err(EncRejection::Domain));
    assert!(header(&valid).is_ok());
}

/// Section 9: mixed classes inside, and a forbidden frame after an allowed
/// one, reject the whole datagram after the tag verifies; nothing is
/// marked and a retry is refused the same way.
#[test]
fn a_forbidden_inner_frame_rejects_the_whole_datagram() {
    let mut sealer = sender();
    let mut opener = opener();
    let mut channel = EncChannel::default();
    for (inner, reason) in [
        (
            [frame(DATA), frame(0x21)].concat(),
            EncRejection::MixedClass,
        ),
        (
            [frame(DATA), frame(0x20)].concat(),
            EncRejection::MixedClass,
        ),
        (
            [frame(DATA), frame(0x03)].concat(),
            EncRejection::InnerRejected,
        ),
        (
            [frame(DATA), frame(0x11)].concat(),
            EncRejection::InnerRejected,
        ),
        (frame(0x07).to_vec(), EncRejection::InnerRejected),
    ] {
        let datagram = seal(&mut sealer, &inner);
        for _ in 0..2 {
            assert_eq!(open(&mut opener, &mut channel, &datagram), Err(reason));
        }
        assert_eq!(opener.current_window().highest(), None, "nothing marked");
    }
    // The domain matrix of section 9.
    assert!(check_matrix(Domain::Receiver, &[frame(0x03), frame(0x02)].concat()).is_ok());
    assert_eq!(
        check_matrix(Domain::Receiver, &frame(DATA)),
        Err(EncRejection::InnerRejected)
    );
    assert_eq!(
        check_matrix(Domain::Receiver, &frame(0x13)),
        Err(EncRejection::InnerRejected),
        "SESSION_ABORT_ACK stays refused until its body is fixed"
    );
    assert_eq!(
        check_matrix(Domain::Setup, &[frame(0x05), frame(0x05)].concat()),
        Err(EncRejection::InnerRejected),
        "one frame only"
    );
    assert!(check_matrix(Domain::RspSetup, &frame(0x07)).is_ok());
    assert_eq!(
        check_matrix(Domain::Sender, &[]),
        Err(EncRejection::InnerRejected)
    );
}

/// Section 8: a datagram is accepted once; a tampered or forged one is
/// refused with nothing marked and no plaintext released.
#[test]
fn a_tampered_or_replayed_datagram_changes_nothing() {
    let mut sealer = sender();
    let mut opener = opener();
    let mut channel = EncChannel::default();
    let first = seal(&mut sealer, &frame(DATA));
    let accepted = open(&mut opener, &mut channel, &first).unwrap();
    assert_eq!(accepted.frames, 32);
    assert!(!accepted.promoted);
    assert_eq!(
        open(&mut opener, &mut channel, &first),
        Err(EncRejection::Duplicate)
    );
    let window = opener.current_window();
    let mut tampered = seal(&mut sealer, &frame(DATA));
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        open(&mut opener, &mut channel, &tampered),
        Err(EncRejection::Tag)
    );
    // Forged under another channel key.
    let other = ChannelKeys::new(&[&channel_file(1, 0x99)]).unwrap();
    let mut forger = EncSealer::new(&other, None, context(Domain::Sender), clock).unwrap();
    // Past the sequences the genuine sender used: the tag, not the
    // window, refuses it.
    seal(&mut forger, &frame(DATA));
    seal(&mut forger, &frame(DATA));
    let forged = seal(&mut forger, &frame(DATA));
    assert_eq!(
        open(&mut opener, &mut channel, &forged),
        Err(EncRejection::Tag)
    );
    assert_eq!(opener.current_window(), window);
    assert_eq!(channel.rejections.get(EncRejection::Tag), 2);
    assert_eq!(channel.rejections.get(EncRejection::Duplicate), 1);
}

/// Section 6, "Accounting before every open": `envelope_seq` at the cap is
/// dropped before the open and before any charge.
#[test]
fn a_sequence_at_the_cap_is_dropped_before_the_open() {
    let mut sealer = sender();
    let mut opener = opener();
    let mut channel = EncChannel::default();
    let mut capped = seal(&mut sealer, &frame(DATA));
    capped[28..36].copy_from_slice(&DATA_SEQ_CAP.to_le_bytes());
    assert_eq!(
        open(&mut opener, &mut channel, &capped),
        Err(EncRejection::SequenceCap)
    );
    assert_eq!(channel.rate.charged(KeyKind::Committed), 0, "not charged");
    assert_eq!(channel.rate.charged(KeyKind::Scratch), 0);
    // Bootstrap keys cap at 2^30.
    let keys = keys();
    let mut setup = EncSealer::new(&keys, None, context(Domain::Setup), clock).unwrap();
    let mut capped = seal(&mut setup, &frame(0x05));
    capped[28..36].copy_from_slice(&BOOTSTRAP_SEQ_CAP.to_le_bytes());
    let mut out = [0_u8; MAX_PLAINTEXT];
    let mut rate = OpenRate::default();
    assert_eq!(
        open_bootstrap(
            &keys,
            None,
            None,
            &capped,
            &mut out,
            &mut rate,
            clock(),
            |_, _| Ok(())
        )
        .map(|_| ()),
        Err(EncRejection::SequenceCap)
    );
    assert_eq!(rate, OpenRate::default());
}

/// Section 6: the two fixed rate counters of a channel. A charge over a
/// limit is refused, with no state change, until the next one-second
/// interval, which restarts both; the counters are independent.
#[test]
fn the_open_rate_is_refused_over_its_limit_until_the_next_second() {
    let mut sealer = sender();
    let mut opener = opener();
    let mut channel = EncChannel::default();
    let first = seal(&mut sealer, &frame(DATA));
    let second = clock() / SECOND_NS;
    channel.rate = OpenRate {
        interval: second,
        committed: COMMITTED_OPENS_PER_S,
        scratch: 0,
    };
    assert_eq!(
        open(&mut opener, &mut channel, &first),
        Err(EncRejection::OpenRate)
    );
    assert_eq!(opener.current_window().highest(), None);
    assert_eq!(channel.rejections.get(EncRejection::OpenRate), 1);
    // The scratch counter is separate.
    assert_eq!(channel.rate.charge(KeyKind::Scratch, clock()), Ok(()));
    // Still refused later in the same second.
    set_now(clock() + SECOND_NS - 1 - clock() % SECOND_NS);
    assert_eq!(
        open(&mut opener, &mut channel, &first),
        Err(EncRejection::OpenRate)
    );
    // The next interval restarts both counters.
    set_now((second + 1) * SECOND_NS);
    assert!(open(&mut opener, &mut channel, &first).is_ok());
    assert_eq!(channel.rate.charged(KeyKind::Committed), 1);
    assert_eq!(channel.rate.charged(KeyKind::Scratch), 0);
    // The scratch limit.
    let mut rate = OpenRate {
        interval: second + 1,
        committed: 0,
        scratch: SCRATCH_OPENS_PER_S,
    };
    assert_eq!(
        rate.charge(KeyKind::Scratch, clock()),
        Err(EncRejection::OpenRate)
    );
    assert_eq!(rate.charge(KeyKind::Committed, clock()), Ok(()));
    assert_eq!(core::mem::size_of::<OpenRate>(), 16, "fixed size");
}

/// Section 6: a committed key past 3660 s from its commit is not used, nor
/// a scratch key whose predecessor has passed that age.
#[test]
fn a_key_past_its_age_is_not_used() {
    let start = clock();
    let mut sealer = sender();
    let mut opener = opener();
    let mut channel = EncChannel::default();
    let first = seal(&mut sealer, &frame(DATA));
    set_now(start + KEY_AGE_NS);
    assert!(
        open(&mut opener, &mut channel, &first).is_ok(),
        "at the age"
    );
    let second = seal(&mut sealer, &frame(DATA));
    set_now(start + KEY_AGE_NS + 1);
    assert_eq!(
        open(&mut opener, &mut channel, &second),
        Err(EncRejection::KeyAge)
    );
    // The next epoch, whose predecessor is too old: refused too.
    let mut next = context(Domain::Sender);
    next.party_epoch = 1;
    let mut rolled = EncSealer::new(&keys(), None, next, clock).unwrap();
    let third = seal(&mut rolled, &frame(DATA));
    assert_eq!(
        open(&mut opener, &mut channel, &third),
        Err(EncRejection::KeyAge)
    );
    assert_eq!(opener.epochs(), (1, 0), "no promotion");
    assert_eq!(channel.rejections.get(EncRejection::KeyAge), 2);
}

/// Sections 5 and 6: the sender rolls to the next `party_epoch` at its age
/// budget; the receiver tries the next epoch in scratch, commits it only
/// on a fully accepted datagram, keeps the previous for exactly 10 s, and
/// refuses an epoch more than one ahead.
#[test]
fn epochs_roll_without_interruption() {
    let start = clock();
    let mut sealer = sender();
    let mut opener = opener();
    let mut channel = EncChannel::default();
    let old = seal(&mut sealer, &frame(DATA));
    let old_late = seal(&mut sealer, &frame(DATA));
    assert!(open(&mut opener, &mut channel, &old).is_ok());
    set_now(start + SEND_AGE_NS);
    let new = seal(&mut sealer, &frame(DATA));
    assert_eq!(sealer.context().party_epoch, 1, "rolled at the age budget");
    assert_eq!(sealer.key().next_seq(), 1, "a new counter from 0");
    // A next-epoch datagram refused for its inner frames commits nothing.
    let bad = seal(&mut sealer, &[frame(DATA), frame(0x02)].concat());
    assert_eq!(
        open(&mut opener, &mut channel, &bad),
        Err(EncRejection::InnerRejected)
    );
    assert_eq!(opener.epochs(), (1, 0));
    let accepted = open(&mut opener, &mut channel, &new).unwrap();
    assert!(accepted.promoted);
    assert_eq!(opener.epochs(), (1, 1));
    assert_eq!(channel.rate.charged(KeyKind::Scratch), 2);
    // The previous epoch for 10 s after the promotion.
    set_now(start + SEND_AGE_NS + EPOCH_OVERLAP_NS - 1);
    assert!(open(&mut opener, &mut channel, &old_late).is_ok());
    let late = {
        let mut previous = EncSealer::new(&keys(), None, context(Domain::Sender), clock).unwrap();
        for _ in 0..3 {
            seal(&mut previous, &frame(DATA));
        }
        seal(&mut previous, &frame(DATA))
    };
    set_now(start + SEND_AGE_NS + EPOCH_OVERLAP_NS);
    assert_eq!(
        open(&mut opener, &mut channel, &late),
        Err(EncRejection::Epoch)
    );
    // Two epochs ahead.
    let mut ahead = context(Domain::Sender);
    ahead.party_epoch = 3;
    let mut far = EncSealer::new(&keys(), None, ahead, clock).unwrap();
    assert_eq!(
        open(&mut opener, &mut channel, &seal(&mut far, &frame(DATA))),
        Err(EncRejection::Epoch)
    );
}

/// Section 6: a new file epoch is the next epoch at `party_epoch` 0.
#[test]
fn a_new_file_epoch_is_accepted_as_the_next_epoch() {
    let both = ChannelKeys::new(&[&channel_file(1, 0x11), &channel_file(2, 0x22)]).unwrap();
    assert_eq!(both.current_epoch(), 2);
    let mut opener = EncOpener::new(&both, None, context(Domain::Sender), clock()).unwrap();
    let mut next = context(Domain::Sender);
    next.key_epoch = 2;
    let mut sealer = EncSealer::new(&both, None, next, clock).unwrap();
    let mut channel = EncChannel::default();
    let accepted = open(&mut opener, &mut channel, &seal(&mut sealer, &frame(DATA))).unwrap();
    assert!(accepted.promoted);
    assert_eq!(opener.epochs(), (2, 0));
    assert!(matches!(
        ChannelKeys::new(&[&channel_file(1, 0x11), &channel_file(1, 0x22)]),
        Err(EncKeyError::Files)
    ));
}

/// Section 4: a domain 4 datagram with a valid outer tag and a wrong
/// pairwise trailer commits, promotes and marks nothing.
#[test]
fn a_wrong_pairwise_trailer_commits_nothing() {
    let keys = keys();
    let ours = pairs(0x22);
    let theirs = pairs(0x55);
    let mut opener =
        EncOpener::new(&keys, Some(&ours), context(Domain::Receiver), clock()).unwrap();
    let mut genuine = EncSealer::new(&keys, Some(&ours), context(Domain::Receiver), clock).unwrap();
    let mut forger =
        EncSealer::new(&keys, Some(&theirs), context(Domain::Receiver), clock).unwrap();
    let mut channel = EncChannel::default();
    let sm = frame(0x03);
    assert_eq!(
        open(&mut opener, &mut channel, &seal(&mut forger, &sm)),
        Err(EncRejection::Pairwise)
    );
    // The forger's next epoch: no promotion either.
    let mut next = context(Domain::Receiver);
    next.party_epoch = 1;
    let mut forger_next = EncSealer::new(&keys, Some(&theirs), next, clock).unwrap();
    assert_eq!(
        open(&mut opener, &mut channel, &seal(&mut forger_next, &sm)),
        Err(EncRejection::Pairwise)
    );
    assert_eq!(opener.epochs(), (1, 0));
    assert_eq!(opener.current_window().highest(), None);
    assert!(open(&mut opener, &mut channel, &seal(&mut genuine, &sm)).is_ok());
    assert_eq!(channel.rejections.get(EncRejection::Pairwise), 2);
    // A receiver domain without a pairwise file cannot be keyed.
    assert!(matches!(
        EncSealer::new(&keys, None, context(Domain::Receiver), clock),
        Err(EncKeyError::Receiver)
    ));
    assert!(matches!(
        EncSealer::new(&keys, Some(&pairs_of(67)), context(Domain::Receiver), clock),
        Err(EncKeyError::Receiver)
    ));
}

fn pairs_of(receiver_id: u64) -> PairwiseFiles {
    PairwiseFiles::new(&[&pairwise_file(receiver_id, 1, 0x22)]).unwrap()
}

/// Sections 4 and 7: bootstrap datagrams open under a scratch derivation
/// from their header; an RSP_SETUP forged by a group holder without the
/// pairwise key is refused; one under the previous file epoch verifies but
/// is not current.
#[test]
fn bootstrap_datagrams_open_under_scratch_keys() {
    let keys = keys();
    let mut rate = OpenRate::default();
    let mut out = [0_u8; MAX_PLAINTEXT];
    let mut setup = EncSealer::new(&keys, None, context(Domain::Setup), clock).unwrap();
    let datagram = seal(&mut setup, &frame(0x05));
    let opened = open_bootstrap(
        &keys,
        None,
        None,
        &datagram,
        &mut out,
        &mut rate,
        clock(),
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(opened.header.publication, Some(PUBLICATION));
    assert!(opened.current_epoch);
    assert_eq!(rate.charged(KeyKind::Scratch), 1);
    // RSP_SETUP: the publisher verifies under its own identity and the
    // receiver's pairwise file.
    let ours = pairs(0x22);
    let mut rsp = EncSealer::new(&keys, Some(&ours), context(Domain::RspSetup), clock).unwrap();
    let challenge = seal(&mut rsp, &frame(0x07));
    let run = |files: &PairwiseFiles, bytes: &[u8], rate: &mut OpenRate| {
        let mut out = [0_u8; MAX_PLAINTEXT];
        open_bootstrap(
            &keys,
            Some(files),
            Some(PUBLICATION),
            bytes,
            &mut out,
            rate,
            clock(),
            |_, _| Ok(()),
        )
        .map(|opened| opened.header.receiver)
    };
    assert_eq!(run(&ours, &challenge, &mut rate), Ok(Some(RECEIVER)));
    let mut forger =
        EncSealer::new(&keys, Some(&pairs(0x55)), context(Domain::RspSetup), clock).unwrap();
    assert_eq!(
        run(&ours, &seal(&mut forger, &frame(0x07)), &mut rate),
        Err(EncRejection::Pairwise)
    );
    // A receiver the configuration names no pairwise file for.
    assert_eq!(
        run(&pairs_of(67), &challenge, &mut rate),
        Err(EncRejection::Pairwise)
    );
    // The previous file epoch verifies but is not current.
    let both = ChannelKeys::new(&[&channel_file(1, 0x11), &channel_file(2, 0x22)]).unwrap();
    let opened = open_bootstrap(
        &both,
        None,
        None,
        &datagram,
        &mut out,
        &mut rate,
        clock(),
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(!opened.current_epoch);
    // A bootstrap key with a nonzero party epoch.
    let mut bad = datagram.clone();
    bad[16] = 1;
    assert_eq!(
        open_bootstrap(
            &keys,
            None,
            None,
            &bad,
            &mut out,
            &mut rate,
            clock(),
            |_, _| Ok(())
        )
        .map(|_| ()),
        Err(EncRejection::Epoch)
    );
}

/// Section 6: at most 100 seals per second of one bootstrap key.
#[test]
fn a_bootstrap_key_seals_at_most_100_per_second() {
    let mut setup = EncSealer::new(&keys(), None, context(Domain::Setup), clock).unwrap();
    let mut bytes = [0_u8; MAX_SEALED];
    for _ in 0..BOOTSTRAP_SEALS_PER_S {
        bytes[..32].copy_from_slice(&frame(0x05));
        setup.seal(&mut bytes, 32).unwrap();
    }
    bytes[..32].copy_from_slice(&frame(0x05));
    assert_eq!(setup.seal(&mut bytes, 32), Err(EncSendError::Rate));
    assert_eq!(setup.key().next_seq(), u64::from(BOOTSTRAP_SEALS_PER_S));
    set_now(clock() + SECOND_NS);
    assert!(setup.seal(&mut bytes, 32).is_ok());
}

/// Section 7: retired boot ids are refused, and a full table refuses new
/// ones until the next file epoch.
#[test]
fn retired_boot_ids_are_refused_and_a_full_table_fails_closed() {
    let mut retired = RetiredBoots::default();
    let boot = |n: u8| ReceiverIdentity {
        receiver_boot_id: [n; 16],
        receiver_id: 66,
    };
    for n in 0..u8::try_from(RETIRED_BOOTS).unwrap() {
        retired.retire(&boot(n), 1).unwrap();
    }
    assert!(retired.contains(&boot(0)));
    assert!(!retired.has_room());
    assert_eq!(
        retired.retire(&boot(200), 1),
        Err(EncRejection::RetiredBoot)
    );
    retired.expire(2);
    assert!(retired.has_room());
    assert!(!retired.contains(&boot(0)));
}

fn enc_answer(key_epoch: u32, party_epoch: u16) -> EncAnswer {
    EncAnswer {
        answer: SetupAnswer {
            alias: Alias {
                session_id: 9,
                stream_id: 6,
            },
            identity: Identity {
                driver_id: [1, 1],
                registration_id: 7,
                incarnation: 1,
            },
            term: TermParams {
                term_length: 65_536,
                initial_term_id: 0,
                mtu: 1408,
            },
            challenge: ChallengeBlock {
                receiver_boot_id: [2, 2],
                nonce: [4, 4],
            },
            joins: Lanes::new(&[0]).unwrap(),
        },
        key_epoch,
        party_epoch,
    }
}

/// Section 6b: a bound receiver that missed an epoch resynchronises from a
/// current answer to a new context with an empty window, keeps the old one
/// for the overlap, and refuses a delayed answer from the file overlap, a
/// regressing epoch pair, and another identity or term.
#[test]
fn a_bound_receiver_resynchronises_and_refuses_a_delayed_answer() {
    let start = clock();
    let both = ChannelKeys::new(&[&channel_file(1, 0x11), &channel_file(2, 0x22)]).unwrap();
    let bound = enc_answer(1, 0);
    let (identity, term) = (bound.answer.identity, bound.answer.term);
    let mut opener = EncOpener::new(&both, None, context(Domain::Sender), start).unwrap();
    let mut channel = EncChannel::default();
    // The sender moved two epochs on: the receiver cannot follow.
    let mut ahead = context(Domain::Sender);
    ahead.key_epoch = 2;
    ahead.party_epoch = 2;
    let mut sealer = EncSealer::new(&both, None, ahead, clock).unwrap();
    let missed = seal(&mut sealer, &frame(DATA));
    assert_eq!(
        open(&mut opener, &mut channel, &missed),
        Err(EncRejection::Epoch)
    );
    let old = {
        let mut previous = EncSealer::new(&both, None, context(Domain::Sender), clock).unwrap();
        seal(&mut previous, &frame(DATA))
    };
    // A delayed answer from the overlap: verified under the previous file
    // epoch only.
    assert_eq!(
        check_resync((&identity, &term), opener.epochs(), 2, &enc_answer(1, 1), 1),
        Err(EncRejection::ResyncRefused)
    );
    // Another identity, other terms, a lower pair.
    let mut other = enc_answer(2, 2);
    other.answer.identity.incarnation = 2;
    assert_eq!(
        check_resync((&identity, &term), opener.epochs(), 2, &other, 2),
        Err(EncRejection::ResyncRefused)
    );
    let mut terms = enc_answer(2, 2);
    terms.answer.term.mtu = 1024;
    assert_eq!(
        check_resync((&identity, &term), opener.epochs(), 2, &terms, 2),
        Err(EncRejection::ResyncRefused)
    );
    assert_eq!(
        check_resync((&identity, &term), (2, 3), 2, &enc_answer(2, 2), 2),
        Err(EncRejection::ResyncRefused)
    );
    assert_eq!(opener.resync(1, 0, clock()), Ok(()), "same pair: no change");
    // The current answer.
    let current = enc_answer(2, 2);
    assert_eq!(
        check_resync((&identity, &term), opener.epochs(), 2, &current, 2),
        Ok(())
    );
    opener.resync(2, 2, start).unwrap();
    assert_eq!(opener.epochs(), (2, 2));
    assert_eq!(opener.current_window().highest(), None, "an empty window");
    assert_eq!(opener.context().salt, SALT, "the unicast salt stays");
    assert!(open(&mut opener, &mut channel, &missed).is_ok());
    // The previous context for the overlap only.
    assert!(open(&mut opener, &mut channel, &old).is_ok());
    assert_eq!(
        opener.resync(1, 5, start),
        Err(EncRejection::ResyncRefused),
        "never backward"
    );
}

/// The seal and open paths allocate nothing.
#[test]
fn sealing_and_opening_allocate_nothing() {
    let keys = keys();
    let ours = pairs(0x22);
    let mut sealer = EncSealer::new(&keys, Some(&ours), context(Domain::Receiver), clock).unwrap();
    let mut opener =
        EncOpener::new(&keys, Some(&ours), context(Domain::Receiver), clock()).unwrap();
    let mut rate = OpenRate::default();
    let mut bytes = [0_u8; MAX_SEALED];
    let mut out = [0_u8; MAX_PLAINTEXT];
    let now = clock();
    let (result, allocations) = karyos_sys::alloc_count::count_allocations(|| {
        bytes[..32].copy_from_slice(&frame(0x03));
        let length = sealer.seal(&mut bytes, 32).unwrap();
        opener
            .open(&bytes[..length], &mut out, &mut rate, now, |_| Ok(()))
            .map(|accepted| accepted.frames)
    });
    assert_eq!(result, Ok(32));
    assert_eq!(allocations, 0);
    // The scratch derivation of the next epoch, and its commit.
    let mut next = context(Domain::Receiver);
    next.party_epoch = 1;
    let mut rolled = EncSealer::new(&keys, Some(&ours), next, clock).unwrap();
    bytes[..32].copy_from_slice(&frame(0x03));
    let length = rolled.seal(&mut bytes, 32).unwrap();
    let (result, allocations) = karyos_sys::alloc_count::count_allocations(|| {
        opener
            .open(&bytes[..length], &mut out, &mut rate, now, |_| Ok(()))
            .map(|accepted| accepted.promoted)
    });
    assert_eq!(result, Ok(true));
    assert_eq!(allocations, 0);
}

/// H8 finding 4: a withdrawn sealer erases its key in place and never
/// seals again, not even after a roll, which it refuses too.
#[test]
fn a_withdrawn_sealer_never_seals_again_even_after_a_roll() {
    let mut sealer = sender();
    let _ = seal(&mut sealer, &frame(DATA));
    sealer.withdraw();
    assert!(sealer.is_withdrawn());
    assert_eq!(sealer.key().context().domain, Domain::Setup, "replaced");
    sealer.roll_now();
    let mut bytes = vec![0_u8; MAX_SEALED];
    bytes[..32].copy_from_slice(&frame(DATA));
    assert!(matches!(
        sealer.seal(&mut bytes, 32),
        Err(EncSendError::Withdrawn)
    ));
    assert!(!DatagramSeal::can_seal(&sealer));
}

/// H8 finding 4: a withdrawn opener opens nothing, under its current
/// epoch or the next, and refuses a resynchronisation.
#[test]
fn a_withdrawn_opener_never_opens_again() {
    let mut sealer = sender();
    let mut opener = opener();
    let mut channel = EncChannel::default();
    assert!(open(&mut opener, &mut channel, &seal(&mut sealer, &frame(DATA))).is_ok());
    let current = seal(&mut sealer, &frame(DATA));
    sealer.roll_now();
    let next = seal(&mut sealer, &frame(DATA));
    opener.withdraw();
    assert!(opener.is_withdrawn());
    assert_eq!(
        open(&mut opener, &mut channel, &current),
        Err(EncRejection::Withdrawn)
    );
    assert_eq!(
        open(&mut opener, &mut channel, &next),
        Err(EncRejection::Withdrawn)
    );
    assert_eq!(channel.rejections.get(EncRejection::Withdrawn), 2);
    assert_eq!(
        channel.rejections.get(EncRejection::Epoch),
        0,
        "its own counter"
    );
    assert_eq!(
        opener.resync(1, 5, clock()),
        Err(EncRejection::ResyncRefused)
    );
}

/// H8 finding 4: applying a key set that no longer names the key epoch
/// in use (revoked, expired, or the store disabled) withdraws the sealer
/// and the opener; a receiver-domain sealer is withdrawn once its
/// pairwise file is gone; an unchanged set changes nothing.
#[test]
fn a_revoked_key_withdraws_the_sealer_and_the_opener() {
    use crate::wire_auth::FixedKeys;

    let mut sealer = sender();
    let mut opener = opener();
    let same = FixedKeys {
        files: vec![channel_file(1, 0x11)],
    };
    sealer.apply_keys(&same);
    opener.apply_keys(&same);
    assert!(!sealer.is_withdrawn() && !opener.is_withdrawn());
    let mut channel = EncChannel::default();
    assert!(open(&mut opener, &mut channel, &seal(&mut sealer, &frame(DATA))).is_ok());
    sealer.apply_keys(&FixedKeys::default());
    opener.apply_keys(&FixedKeys::default());
    assert!(sealer.is_withdrawn() && opener.is_withdrawn());
    let mut receiver = EncSealer::new(
        &keys(),
        Some(&pairs(0x22)),
        context(Domain::Receiver),
        clock,
    )
    .unwrap();
    receiver.apply_keys(&same);
    assert!(receiver.is_withdrawn(), "its pairwise file is gone");
}

/// H8 finding 4: the erase is infallible whatever domain is current: a
/// bootstrap (domain 5) and a domain 6 sealer both overwrite their key in
/// place with the zero key under the checked bootstrap context, its
/// counters from 0, and seal nothing again.
#[test]
fn withdraw_erases_under_a_bootstrap_or_domain_6_context() {
    let mut setup = EncSealer::new(&keys(), None, context(Domain::Setup), clock).unwrap();
    let _ = seal(&mut setup, &frame(0x0E));
    let mut rsp = EncSealer::new(
        &keys(),
        Some(&pairs(0x22)),
        context(Domain::RspSetup),
        clock,
    )
    .unwrap();
    let _ = seal(&mut rsp, &frame(0x0E));
    for sealer in [&mut setup, &mut rsp] {
        assert_eq!(sealer.key().next_seq(), 1);
        sealer.withdraw();
        let erased = sealer.key().context();
        assert_eq!(
            (erased.domain, erased.receiver, erased.salt),
            (Domain::Setup, None, Salt::Empty)
        );
        assert_eq!(sealer.key().next_seq(), 0, "overwritten in place");
        let mut bytes = vec![0_u8; MAX_SEALED];
        assert!(matches!(
            sealer.seal(&mut bytes, 32),
            Err(EncSendError::Withdrawn)
        ));
    }
}

/// A key set holding `files`.
fn set(files: Vec<KeyFile>) -> crate::wire_auth::FixedKeys {
    crate::wire_auth::FixedKeys { files }
}

/// H8 finding 4 with ADR-0114 section 6: once an opener has promoted (its
/// spare used, its previous epoch held), revoking the previous epoch's
/// file erases that slot in place and keeps it as the spare, so the next
/// promotion still finds a slot and constructs no key.
#[test]
fn a_revoked_previous_epoch_keeps_its_slot_as_the_spare() {
    let both = ChannelKeys::new(&[&channel_file(1, 0x11), &channel_file(2, 0x22)]).unwrap();
    let mut opener = EncOpener::new(&both, None, context(Domain::Sender), clock()).unwrap();
    let mut next = context(Domain::Sender);
    next.key_epoch = 2;
    let mut sealer = EncSealer::new(&both, None, next, clock).unwrap();
    let mut channel = EncChannel::default();
    assert!(
        open(&mut opener, &mut channel, &seal(&mut sealer, &frame(DATA)))
            .unwrap()
            .promoted
    );
    assert!(opener.previous.is_some() && opener.spare.is_none());
    // Epoch 1 revoked: the previous slot is erased and becomes the spare.
    opener.apply_keys(&set(vec![channel_file(2, 0x22)]));
    assert!(!opener.is_withdrawn());
    assert!(opener.previous.is_none());
    let spare = opener.spare.as_ref().expect("recycled, not dropped");
    assert_eq!(spare.context(), &opener.erase, "erased in place");
    // The next epoch still promotes, from the recycled slot.
    sealer.roll_now();
    let accepted = open(&mut opener, &mut channel, &seal(&mut sealer, &frame(DATA))).unwrap();
    assert!(accepted.promoted);
    assert_eq!(opener.epochs(), (2, 1));
    assert!(opener.previous.is_some(), "the overlap is kept");
}

/// ADR-0114 section 6 rotation: a file epoch newly admitted by the key
/// set moves a live sealer to `(new, 0)` at its next datagram, under a key
/// whose context names the new epoch (its sequence restarts, no nonce is
/// reused), and a live opener that admitted it too accepts that datagram
/// as its next epoch and promotes, keeping the old epoch for exactly the
/// 10 s overlap. A file of another class or purpose is never admitted.
#[test]
fn a_rotation_moves_live_sealers_and_openers_to_the_new_epoch() {
    let start = clock();
    let mut sealer = sender();
    let mut opener = opener();
    let mut channel = EncChannel::default();
    let first = seal(&mut sealer, &frame(DATA));
    let old_late = seal(&mut sealer, &frame(DATA));
    assert!(open(&mut opener, &mut channel, &first).is_ok());
    let old_context = *sealer.context();
    let old_seq = sealer.key().next_seq();
    // Epoch 2 admitted and signing; epoch 1 still verifies (the overlap).
    let rotated = set(vec![channel_file(1, 0x11), channel_file(2, 0x22)]);
    sealer.apply_keys(&rotated);
    opener.apply_keys(&rotated);
    assert!(!sealer.is_withdrawn() && !opener.is_withdrawn());
    assert_eq!(
        (sealer.context().key_epoch, sealer.context().party_epoch),
        (2, 0)
    );
    assert_eq!(sealer.key().next_seq(), 0, "a new key, its counter from 0");
    assert_ne!(*sealer.context(), old_context, "never the old key's nonces");
    assert_eq!(old_seq, 2);
    let new = seal(&mut sealer, &frame(DATA));
    let accepted = open(&mut opener, &mut channel, &new).unwrap();
    assert!(accepted.promoted);
    assert_eq!(opener.epochs(), (2, 0));
    // The previous epoch for exactly 10 s after the promotion.
    set_now(start + EPOCH_OVERLAP_NS - 1);
    assert!(open(&mut opener, &mut channel, &old_late).is_ok());
    let mut stale = EncSealer::new(&keys(), None, context(Domain::Sender), clock).unwrap();
    for _ in 0..4 {
        let _ = seal(&mut stale, &frame(DATA));
    }
    set_now(start + EPOCH_OVERLAP_NS);
    assert_eq!(
        open(&mut opener, &mut channel, &seal(&mut stale, &frame(DATA))),
        Err(EncRejection::Epoch)
    );
    // Applying the same set again changes nothing.
    sealer.apply_keys(&rotated);
    assert_eq!(sealer.key().next_seq(), 1);
    // Wrong purpose: a pairwise file of the channel's key id is ignored.
    let mut keys = keys();
    let mut wrong = pairwise_file(66, 3, 0x33);
    wrong.key_id = 3;
    assert!(!keys.admit(&set(vec![channel_file(1, 0x11), wrong])));
    assert_eq!(keys.current_epoch(), 1);
}

/// Rotation on the receiver side of a domain 4 key: a new pairwise epoch
/// of the receiver the sealer serves is admitted with the channel epoch,
/// and the domain 4 sealer moves to the new key epoch and keeps sealing
/// with its trailer; an unrelated receiver's file is not admitted.
#[test]
fn a_rotation_admits_the_served_receivers_pairwise_epoch() {
    let mut receiver = EncSealer::new(
        &keys(),
        Some(&pairs(0x22)),
        context(Domain::Receiver),
        clock,
    )
    .unwrap();
    let rotated = set(vec![
        channel_file(1, 0x11),
        channel_file(2, 0x22),
        pairwise_file(66, 1, 0x22),
        pairwise_file(66, 2, 0x44),
    ]);
    receiver.apply_keys(&rotated);
    assert!(!receiver.is_withdrawn());
    assert_eq!(receiver.context().key_epoch, 2);
    assert_eq!(
        receiver.pairwise.as_ref().unwrap().epochs_of(66),
        [Some(2), Some(1)]
    );
    assert!(!seal(&mut receiver, &frame(DATA)).is_empty());
    let mut files = pairs(0x22);
    let mut other = pairwise_file(77, 1, 0x55);
    other.key_id = 9;
    assert!(!files.admit(&set(vec![other])));
    assert_eq!(files.epochs_of(77), [None, None]);
}

/// [`identity_of`] inverts [`publication_of`].
#[test]
fn identity_of_inverts_publication_of() {
    let identity = karyos_protocol::network::Identity {
        driver_id: [0x0102_0304_0506_0708, 0x1112_1314_1516_1718],
        registration_id: 7,
        incarnation: 9,
    };
    assert_eq!(identity_of(&publication_of(&identity)), identity);
}
