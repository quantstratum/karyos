// SPDX-License-Identifier: Apache-2.0

//! The receive side of ADR-0114 section 9 at the receiver role: the
//! downgrade refusals and `enc_unexpected` (quantstratum/karyos#651).

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::net::SocketAddr;

use karyos_protocol::network::{Alias, Control, Identity, SetupAnnounce, TermParams};
use karyos_protocol::protection::aes_gcm_siv::{EncRejection, KeyContext, Salt};

use super::super::super::AgentConfig;
use super::super::super::chain::session_rings;
use super::*;
use crate::wire_enc::{ChannelKeys, EncOpener, EncRejections, EncSealer, MAX_SEALED};
use crate::wire_keys::{KEY_LEN, parse};

fn channel(fill: u8) -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    parse(
        "3-1.key",
        format!(
            "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=6\n"
        )
        .as_bytes(),
    )
    .unwrap()
}

fn pairwise() -> KeyFile {
    parse(
        "9-1.key",
        b"format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=1\npurpose=pairwise\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=2222222222222222222222222222222222222222222222222222222222222222\nreceiver_id=66\npublisher_id=5\n",
    )
    .unwrap()
}

const ALIAS: Alias = Alias {
    session_id: 5,
    stream_id: 6,
};
const IDENTITY: Identity = Identity {
    driver_id: [1, 2],
    registration_id: 3,
    incarnation: 1,
};

fn announce() -> Control {
    Control::SetupAnnounce(SetupAnnounce {
        alias: ALIAS,
        identity: IDENTITY,
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 0,
            mtu: 1408,
        },
        lane_count: 1,
    })
}

fn encoded(control: &Control) -> Vec<u8> {
    let mut bytes = vec![0_u8; 256];
    let length = control.encode(&mut bytes).unwrap();
    bytes.truncate(length);
    bytes
}

/// A receiver role with an encrypted subscription to stream 6 on endpoint
/// 1, and a way to inject datagrams.
struct Rig {
    role: super::super::ReceiverRole,
    sessions: super::super::SessionEnd,
    source: SocketAddr,
}

fn rig() -> Rig {
    let (_, mut role) = super::super::roles(&AgentConfig::default()).unwrap();
    role.enc.subscribe(
        SubscriptionEnc::new(EndpointId(1), 6, &[&channel(0x11)], &[&pairwise()], 66).unwrap(),
    );
    let (sessions, _link) = session_rings(std::num::NonZeroUsize::new(4).unwrap());
    Rig {
        role,
        sessions,
        source: "10.0.0.2:4000".parse().unwrap(),
    }
}

impl Rig {
    fn inject(&mut self, bytes: &[u8]) {
        self.role
            .inject_datagram(&self.sessions, EndpointId(1), self.source, bytes, 1_000);
    }

    fn rejections(&self) -> EncRejections {
        self.role.enc.rejections(EndpointId(1), 6).unwrap()
    }
}

fn setup_sealer(fill: u8) -> EncSealer {
    let keys = ChannelKeys::new(&[&channel(fill)]).unwrap();
    EncSealer::new(
        &keys,
        None,
        KeyContext {
            domain: Domain::Setup,
            key_epoch: 1,
            party_epoch: 0,
            session_id: ALIAS.session_id,
            stream_id: ALIAS.stream_id,
            publication: publication_of(&IDENTITY),
            receiver: None,
            salt: Salt::Empty,
        },
        monotonic_ns,
    )
    .unwrap()
}

fn sealed(sealer: &mut EncSealer, control: &Control) -> Vec<u8> {
    let mut bytes = vec![0_u8; MAX_SEALED];
    let length = control.encode(&mut bytes).unwrap();
    let sealed = sealer.seal(&mut bytes, length).unwrap();
    bytes.truncate(sealed);
    bytes
}

/// Section 9 and SPEC.md section 13 "Encrypted control and downgrade": on
/// an encrypted stream, the envelope stripped, an authenticated envelope
/// and a plaintext SETUP are each dropped and advance their own counter; a
/// plaintext SETUP occupies no challenge entry; the stream never falls
/// back to trusted, during establishment included.
#[test]
fn each_downgrade_shape_is_dropped_and_counted_on_its_own() {
    let mut rig = rig();
    let counters = rig.role.counters;
    // A plaintext SETUP ANNOUNCE: no challenge.
    rig.inject(&encoded(&announce()));
    assert_eq!(rig.rejections().get(EncRejection::PlaintextSetup), 1);
    assert!(rig.role.posted_challenges().is_empty());
    // A bare DATA frame (the envelope stripped).
    let mut data = [0_u8; 64];
    data[..4].copy_from_slice(&64_i32.to_le_bytes());
    data[4] = 1;
    data[6..8].copy_from_slice(&1_u16.to_le_bytes());
    data[12..16].copy_from_slice(&ALIAS.session_id.to_le_bytes());
    data[16..20].copy_from_slice(&ALIAS.stream_id.to_le_bytes());
    rig.inject(&data);
    assert_eq!(rig.rejections().get(EncRejection::BareFrame), 1);
    // An authenticated envelope as the outer frame.
    let mut wrong = data;
    wrong[6..8].copy_from_slice(&0x20_u16.to_le_bytes());
    rig.inject(&wrong);
    assert_eq!(rig.rejections().get(EncRejection::WrongClass), 1);
    // Each reason moved by one, and nothing else of the role but the
    // datagram count.
    assert_eq!(rig.rejections().total(), 3);
    let mut after = rig.role.counters;
    after.datagrams = counters.datagrams;
    assert_eq!(after, counters, "a refusal changes nothing but its counter");
    assert!(rig.role.posted_challenges().is_empty());
    assert_eq!(rig.role.enc.unattributed, EncRejections::default());
}

/// Section 9: an envelope with an inner `0x21` (mixed classes) and one
/// forged under another channel key are dropped and counted after the
/// tag, never parsed.
#[test]
fn a_mixed_or_forged_envelope_is_dropped_and_counted() {
    let mut rig = rig();
    let mut forger = setup_sealer(0x99);
    rig.inject(&sealed(&mut forger, &announce()));
    assert_eq!(rig.rejections().get(EncRejection::Tag), 1);
    // Bytes after the tag.
    let mut genuine = setup_sealer(0x11);
    let mut trailing = sealed(&mut genuine, &announce());
    trailing.extend_from_slice(&[0; 32]);
    rig.inject(&trailing);
    assert_eq!(rig.rejections().get(EncRejection::MixedClass), 1);
    assert!(rig.role.posted_challenges().is_empty());
}

/// Section 9: an outer `0x21` on a stream that is not encrypted is dropped
/// and counted (`enc_unexpected`), and never reaches the trusted path.
#[test]
fn an_envelope_on_a_stream_that_is_not_encrypted_is_unexpected() {
    let mut rig = rig();
    let counters = rig.role.counters;
    let mut sealer = setup_sealer(0x11);
    let mut bytes = sealed(&mut sealer, &announce());
    bytes[24..28].copy_from_slice(&7_i32.to_le_bytes());
    rig.inject(&bytes);
    assert_eq!(rig.role.enc.unattributed.get(EncRejection::Unexpected), 1);
    assert_eq!(rig.rejections().total(), 0);
    let mut after = rig.role.counters;
    after.datagrams = counters.datagrams;
    assert_eq!(after, counters);
}

/// A verified ANNOUNCE takes the encrypted path (here no trusted
/// subscription exists, so it sets nothing up) and names its publication
/// as the target of its alias (H8-02): a SOLICIT on that alias is keyed in
/// domain 6 under it, and a CHALLENGE to it shares that one key. A SOLICIT
/// with no verified target is refused, never sent bare
/// (`a_solicit_goes_sealed_in_domain_6_with_its_trailer`).
#[test]
fn a_verified_announce_passes_and_a_solicit_is_never_bare() {
    let mut rig = rig();
    let mut sealer = setup_sealer(0x11);
    rig.inject(&sealed(&mut sealer, &announce()));
    assert_eq!(rig.rejections().total(), 0);
    let (sessions, _link) = session_rings(std::num::NonZeroUsize::new(4).unwrap());
    let mut intake = Intake {
        endpoint: EndpointId(1),
        now: 1_000,
        role: &mut rig.role,
        sessions: &sessions,
        work: 0,
    };
    let solicit = Control::Solicit(karyos_protocol::network::RspSolicit {
        alias: ALIAS,
        challenge: karyos_protocol::network::ChallengeBlock {
            receiver_boot_id: [7, 8],
            nonce: [9, 9],
        },
    });
    let mut seal = intake.enc_rsp_seal(EndpointId(1), &solicit).unwrap();
    let mut buffer = [0_u8; 256];
    assert!(seal.seal_control(&mut buffer, 56).is_some());
    // A CHALLENGE is sealed in domain 6 with the pairwise trailer, under
    // one sealer per target.
    let challenge = Control::Challenge(karyos_protocol::network::RspChallenge {
        alias: ALIAS,
        identity: IDENTITY,
        challenge: karyos_protocol::network::ChallengeBlock {
            receiver_boot_id: [7, 8],
            nonce: [9, 9],
        },
    });
    let mut seal = intake.enc_rsp_seal(EndpointId(1), &challenge).unwrap();
    assert_eq!(seal.domain(), ControlDomain::RspSetup);
    let length = challenge.encode(&mut buffer).unwrap();
    let sealed = seal.seal_control(&mut buffer, length).unwrap();
    assert_eq!(sealed, length + 84 + 20);
    let again = intake.enc_rsp_seal(EndpointId(1), &challenge).unwrap();
    assert_eq!(intake.role.enc.rsp.len(), 1);
    drop(again);
    // A stream that is not encrypted has no encrypted sealer.
    let mut other = challenge;
    if let Control::Challenge(c) = &mut other {
        c.alias.stream_id = 7;
    }
    assert!(intake.enc_rsp_seal(EndpointId(1), &other).is_none());
}

/// The envelopes of a local encrypted publication go to the sender
/// undecoded; a bare control for it is refused, never parsed.
#[test]
fn a_local_encrypted_publication_takes_only_envelopes() {
    let mut rig = rig();
    let published = Alias {
        session_id: 11,
        stream_id: 12,
    };
    rig.role.enc.publish(EndpointId(1), published);
    let mut nak = [0_u8; 96];
    nak[..4].copy_from_slice(&96_i32.to_le_bytes());
    nak[4] = 1;
    nak[6..8].copy_from_slice(&2_u16.to_le_bytes());
    nak[12..16].copy_from_slice(&11_i32.to_le_bytes());
    nak[16..20].copy_from_slice(&12_i32.to_le_bytes());
    rig.inject(&nak);
    assert_eq!(rig.role.enc.unattributed.get(EncRejection::BareFrame), 1);
    let mut sealer = setup_sealer(0x11);
    let mut envelope = sealed(&mut sealer, &announce());
    envelope[20..24].copy_from_slice(&11_i32.to_le_bytes());
    envelope[24..28].copy_from_slice(&12_i32.to_le_bytes());
    rig.inject(&envelope);
    assert_eq!(
        rig.role.enc.unattributed.total(),
        1,
        "forwarded, not counted"
    );
}

fn two_epochs() -> ChannelKeys {
    let mut second = channel(0x55);
    second.file_epoch = 2;
    ChannelKeys::new(&[&channel(0x11), &second]).unwrap()
}

fn term() -> TermParams {
    TermParams {
        term_length: 65_536,
        initial_term_id: 0,
        mtu: 1408,
    }
}

const BOOT: [u64; 2] = [7, 8];
const NONCE: [u64; 2] = [9, 9];

/// A role holding one bound encrypted image at epoch pair (1, 0), on a
/// subscription that holds file epochs 1 and 2 (2 current).
fn bound() -> super::super::ReceiverRole {
    let (_, mut role) = super::super::roles(&AgentConfig::default()).unwrap();
    let mut second = channel(0x55);
    second.file_epoch = 2;
    let subscription = SubscriptionEnc::new(
        EndpointId(1),
        6,
        &[&channel(0x11), &second],
        &[&pairwise()],
        66,
    )
    .unwrap();
    let opener = EncOpener::new(
        &two_epochs(),
        None,
        KeyContext {
            domain: Domain::Sender,
            key_epoch: 1,
            party_epoch: 0,
            session_id: ALIAS.session_id,
            stream_id: ALIAS.stream_id,
            publication: publication_of(&IDENTITY),
            receiver: None,
            salt: Salt::Challenge {
                receiver_boot_id: id128(BOOT),
                nonce: id128([1, 1]),
            },
        },
        0,
    )
    .unwrap();
    role.enc.subscribe(subscription);
    role.enc.images.push(ImageEnc {
        slot: SlotRef {
            slot: 0,
            generation: 1,
        },
        endpoint: EndpointId(1),
        alias: ALIAS,
        identity: IDENTITY,
        term: term(),
        opener,
        resync: Some((NONCE, 1_000)),
    });
    role
}

fn enc_answer(key_epoch: u32, party_epoch: u16, nonce: [u64; 2]) -> EncAnswer {
    EncAnswer {
        answer: karyos_protocol::network::SetupAnswer {
            alias: ALIAS,
            identity: IDENTITY,
            term: term(),
            challenge: ChallengeBlock {
                receiver_boot_id: BOOT,
                nonce,
            },
            joins: karyos_protocol::network::Lanes::new(&[1 << 20]).unwrap(),
        },
        key_epoch,
        party_epoch,
    }
}

/// Section 6b at the role: the answer that echoes the outstanding
/// challenge under the current file epoch moves the binding to its pair,
/// with an empty window and the salt kept; the challenge is consumed, so
/// the same answer again is refused.
#[test]
fn a_current_answer_to_the_resync_challenge_moves_the_binding() {
    let mut role = bound();
    let answer = enc_answer(2, 3, NONCE);
    assert_eq!(role.enc.resync(0, &answer, 2, true, BOOT, 1_500), Ok(()));
    let image = &role.enc.images[0];
    assert_eq!(image.opener.epochs(), (2, 3));
    assert_eq!(image.opener.current_window().highest(), None);
    assert_eq!(
        image.opener.context().salt,
        Salt::Challenge {
            receiver_boot_id: id128(BOOT),
            nonce: id128([1, 1]),
        },
        "the unicast salt of the establishment stays; join points are ignored"
    );
    assert!(image.resync.is_none(), "consumed");
    assert_eq!(
        role.enc.resync(0, &answer, 2, true, BOOT, 1_600),
        Err(EncRejection::ResyncRefused)
    );
}

/// Section 6b step 5: a delayed answer that verifies only under the
/// previous file epoch, in its overlap, is refused and changes nothing but
/// the consumed challenge.
#[test]
fn a_delayed_answer_from_the_overlap_is_refused() {
    let mut role = bound();
    assert_eq!(
        role.enc
            .resync(0, &enc_answer(1, 4, NONCE), 1, false, BOOT, 1_500),
        Err(EncRejection::ResyncRefused)
    );
    assert_eq!(role.enc.images[0].opener.epochs(), (1, 0));
}

/// Section 6b step 3: another nonce, another boot id, an expired
/// challenge, a lower pair, another identity or term parameters, or a
/// `key_epoch` other than the envelope's: each refused.
#[test]
fn every_other_answer_for_the_bound_identity_is_refused() {
    let refused = |answer: EncAnswer, envelope: u32, now: u64| {
        let mut role = bound();
        let result = role.enc.resync(0, &answer, envelope, true, BOOT, now);
        assert_eq!(role.enc.images[0].opener.epochs(), (1, 0));
        result
    };
    assert_eq!(
        refused(enc_answer(2, 0, [5, 5]), 2, 1_500),
        Err(EncRejection::ResyncRefused)
    );
    let mut boot = enc_answer(2, 0, NONCE);
    boot.answer.challenge.receiver_boot_id = [3, 3];
    assert_eq!(refused(boot, 2, 1_500), Err(EncRejection::ResyncRefused));
    assert_eq!(
        refused(
            enc_answer(2, 0, NONCE),
            2,
            1_000 + RESYNC_CHALLENGE_TIMEOUT_NS + 1
        ),
        Err(EncRejection::ResyncRefused)
    );
    let mut terms = enc_answer(2, 0, NONCE);
    terms.answer.term.mtu = 1024;
    assert_eq!(refused(terms, 2, 1_500), Err(EncRejection::ResyncRefused));
    assert_eq!(
        refused(enc_answer(2, 0, NONCE), 1, 1_500),
        Err(EncRejection::ResyncRefused)
    );
    let mut role = bound();
    role.enc.images[0].opener.resync(2, 5, 0).unwrap();
    assert_eq!(
        role.enc
            .resync(0, &enc_answer(2, 4, NONCE), 2, true, BOOT, 1_500),
        Err(EncRejection::ResyncRefused),
        "never backward"
    );
}

/// Section 6b step 1 and the domain matrix: a SOLICIT of an encrypted
/// subscription goes sealed in domain 6 with its pairwise trailer, under
/// the bound image's publication key, or under the publication the DATA
/// that caused it named; the publication opens it with the receiver's
/// pairwise file.
#[test]
fn a_solicit_goes_sealed_in_domain_6_with_its_trailer() {
    use crate::wire_enc::{OpenRate, PairwiseFiles, open_bootstrap};
    use karyos_protocol::network::RspSolicit;

    let opens = |bytes: &[u8], publication| {
        let mut out = [0_u8; MAX_PLAINTEXT];
        let mut rate = OpenRate::default();
        let files = PairwiseFiles::new(&[&pairwise()]).unwrap();
        let keys = ChannelKeys::new(&[&channel(0x11)]).unwrap();
        open_bootstrap(
            &keys,
            Some(&files),
            Some(publication),
            bytes,
            &mut out,
            &mut rate,
            0,
            |_, _| Ok(()),
        )
        .map(|opened| {
            (
                opened.header.domain,
                karyos_protocol::network::classify(&out[..opened.frames]).is_ok(),
            )
        })
    };
    let solicit = |alias: Alias| {
        Control::Solicit(RspSolicit {
            alias,
            challenge: ChallengeBlock {
                receiver_boot_id: [7, 8],
                nonce: [9, 9],
            },
        })
    };
    let seal_with = |role: &mut super::super::ReceiverRole, control: &Control| {
        let (sessions, _link) = session_rings(std::num::NonZeroUsize::new(4).unwrap());
        let mut intake = Intake {
            endpoint: EndpointId(1),
            now: 1_000,
            role,
            sessions: &sessions,
            work: 0,
        };
        let mut seal = intake.enc_rsp_seal(EndpointId(1), control).unwrap();
        let mut buffer = [0_u8; 256];
        let length = control.encode(&mut buffer).unwrap();
        seal.seal_control(&mut buffer, length)
            .map(|sealed| buffer[..sealed].to_vec())
    };
    // A bound image's SOLICIT (resynchronisation).
    let mut role = rig().role;
    let other = bound();
    let image = &other.enc.images[0];
    role.enc.images.push(ImageEnc {
        slot: image.slot,
        endpoint: image.endpoint,
        alias: image.alias,
        identity: image.identity,
        term: image.term,
        opener: EncOpener::new(
            &ChannelKeys::new(&[&channel(0x11)]).unwrap(),
            None,
            *image.opener.context(),
            0,
        )
        .unwrap(),
        resync: None,
    });
    let bytes = seal_with(&mut role, &solicit(ALIAS)).unwrap();
    assert_eq!(bytes.len(), 56 + 84 + 20, "header, trailer and tag");
    assert_eq!(
        opens(&bytes, publication_of(&IDENTITY)),
        Ok((Domain::RspSetup, true))
    );
    // An unbound alias whose DATA named its publication.
    let mut role = rig().role;
    let unbound = Alias {
        session_id: 77,
        stream_id: 6,
    };
    role.enc
        .verified
        .push((EndpointId(1), unbound, publication_of(&IDENTITY)));
    let bytes = seal_with(&mut role, &solicit(unbound)).unwrap();
    assert_eq!(
        opens(&bytes, publication_of(&IDENTITY)),
        Ok((Domain::RspSetup, true))
    );
    // With no target known it is refused, never sent bare.
    let mut role = rig().role;
    assert_eq!(seal_with(&mut role, &solicit(unbound)), None);
}

fn second_epoch() -> KeyFile {
    let mut second = channel(0x55);
    second.file_epoch = 2;
    second
}

/// The envelope sequence of a sealed control.
fn sequence_of(sealer: &mut SharedSealer) -> u64 {
    use crate::agents::control::ControlSeal;

    let mut bytes = vec![0_u8; MAX_SEALED];
    let length = announce().encode(&mut bytes).unwrap();
    let sealed = sealer.seal_control(&mut bytes, length).unwrap();
    crate::wire_enc::header(&bytes[..sealed]).unwrap().seq
}

/// H8 finding 4 and ADR-0114 nonces: dropping a file a domain 6 sealer
/// does not use (here the previous channel epoch) leaves the sealer as it
/// is, so the next SOLICIT continues its sequence; nothing is rebuilt.
#[test]
fn an_unrelated_dropped_file_keeps_the_rsp_sequence() {
    use crate::wire_auth::FixedKeys;

    let (_, mut role): (_, super::super::ReceiverRole) =
        super::super::roles(&AgentConfig::default()).unwrap();
    role.enc.subscribe(
        SubscriptionEnc::new(
            EndpointId(1),
            6,
            &[&channel(0x11), &second_epoch()],
            &[&pairwise()],
            66,
        )
        .unwrap(),
    );
    let target = publication_of(&IDENTITY);
    let mut sealer = role
        .enc
        .rsp_sealer(0, target, ALIAS, [4; 16], true)
        .unwrap();
    assert_eq!(sequence_of(&mut sealer), 0);
    role.enc.apply_keys(&FixedKeys {
        files: vec![second_epoch(), pairwise()],
    });
    let mut again = role
        .enc
        .rsp_sealer(0, target, ALIAS, [4; 16], true)
        .unwrap();
    assert_eq!(sequence_of(&mut again), 1, "the sequence continues");
    assert_eq!(role.enc.rsp.len(), 1);
}

/// H8 finding 4 and ADR-0114 nonces: a domain 6 sealer whose own pairwise
/// file was dropped is withdrawn and kept as a tombstone: the same target
/// and boot id get it again, which seals nothing, and it is never rebuilt
/// with its sequence restarted under the same key and party.
#[test]
fn a_withdrawn_rsp_sealer_is_never_rebuilt() {
    use crate::agents::control::ControlSeal;
    use crate::wire_auth::FixedKeys;

    let (_, mut role): (_, super::super::ReceiverRole) =
        super::super::roles(&AgentConfig::default()).unwrap();
    role.enc.subscribe(
        SubscriptionEnc::new(EndpointId(1), 6, &[&channel(0x11)], &[&pairwise()], 66).unwrap(),
    );
    let target = publication_of(&IDENTITY);
    let mut sealer = role
        .enc
        .rsp_sealer(0, target, ALIAS, [4; 16], true)
        .unwrap();
    assert_eq!(sequence_of(&mut sealer), 0);
    role.enc.apply_keys(&FixedKeys {
        files: vec![channel(0x11)],
    });
    for _ in 0..2 {
        let mut again = role
            .enc
            .rsp_sealer(0, target, ALIAS, [4; 16], true)
            .unwrap();
        let mut bytes = vec![0_u8; MAX_SEALED];
        let length = announce().encode(&mut bytes).unwrap();
        assert!(again.seal_control(&mut bytes, length).is_none());
    }
    assert_eq!(role.enc.rsp.len(), 1, "no rebuild");
}

/// A receive role whose VM generation signal the test changes.
fn watched(
    role: &mut super::super::ReceiverRole,
) -> crate::wire_enc::vm_generation::SignalInjector {
    let (signal, injector) = crate::wire_enc::vm_generation::InjectedSignal::new();
    role.enc.watch(VmGenerationWatch::new(Box::new(signal)));
    injector
}

fn session_end() -> super::super::SessionEnd {
    session_rings(std::num::NonZeroUsize::new(4).unwrap()).0
}

const AFTER: u64 = crate::wire_enc::vm_generation::POLL_INTERVAL_NS;

/// ADR-0114 section 10 at the receive role: until the signal changes
/// nothing closes; the first duty after it drops every image's domain 1
/// keys, every pending answer, target, domain 6 sealer and scratch slot,
/// draws a fresh `receiver_boot_id` and reports the role redrawn, which
/// releases the fence. The subscription stays encrypted.
#[test]
fn a_vm_generation_change_closes_every_image_and_redraws_the_boot_id() {
    let mut role = bound();
    let sessions = session_end();
    role.enc
        .verified
        .push((EndpointId(1), ALIAS, publication_of(&IDENTITY)));
    role.enc
        .answers
        .push((EndpointId(1), ALIAS, enc_answer(2, 0, NONCE)));
    let injector = watched(&mut role);
    let old = role.boot_id();
    role.on_generation_change(&sessions, 0);
    assert_eq!(role.enc_generation(), 0);
    assert_eq!(role.enc_images(), 1);
    injector.change();
    role.on_generation_change(&sessions, AFTER);
    assert_eq!(role.enc_generation(), 1);
    assert_eq!(role.enc_images(), 0);
    assert!(role.enc.answers.is_empty() && role.enc.verified.is_empty());
    let subscription = &role.enc.subscriptions[0];
    assert!(role.enc.rsp.is_empty() && subscription.bootstrap.is_none());
    assert_ne!(role.boot_id(), old);
    assert_ne!(role.boot_id(), [0, 0]);
    assert!(!crate::wire_enc::quiesced(), "the only role redrew");
    // No resynchronisation can move a binding that no longer exists.
    assert_eq!(
        role.enc
            .resync(0, &enc_answer(2, 3, NONCE), 2, true, BOOT, 1_500),
        Err(EncRejection::ResyncRefused)
    );
}

/// While the fence is held (another role has not redrawn), an envelope
/// is dropped and counted (`enc_vm_generation`) before anything opens it,
/// and the stream still refuses a bare SETUP: closing never downgrades it.
#[test]
fn while_the_fence_is_held_every_envelope_is_dropped_and_counted() {
    let mut rig = rig();
    let sessions = session_end();
    let mut sealer = setup_sealer(0x11);
    let announce_sealed = sealed(&mut sealer, &announce());
    let injector = watched(&mut rig.role);
    crate::wire_enc::vm_generation::register();
    injector.change();
    rig.role.on_generation_change(&sessions, AFTER);
    assert!(crate::wire_enc::quiesced());
    rig.inject(&announce_sealed);
    assert_eq!(rig.rejections().get(EncRejection::VmGeneration), 1);
    assert_eq!(rig.rejections().total(), 1, "refused for that reason only");
    rig.inject(&encoded(&announce()));
    assert_eq!(rig.rejections().get(EncRejection::PlaintextSetup), 1);
}

/// Where the platform gives no signal, a role's encrypted images stay
/// until the deployment rule ends the process: no timer closes them.
#[test]
fn without_a_signal_no_image_closes() {
    let mut role = bound();
    let sessions = session_end();
    let old = role.boot_id();
    role.enc.watch(VmGenerationWatch::platform());
    for now in [0, 1_000_000_000, 3_600_000_000_000] {
        role.on_generation_change(&sessions, now);
    }
    assert_eq!(role.enc_generation(), 0);
    assert_eq!(role.enc_images(), 1);
    assert_eq!(role.boot_id(), old);
}

/// ADR-0114 section 7, "Retired publication identities": while a retired
/// full identity is inside its `alias_quarantine`, its encrypted traffic is
/// dropped and counted (`enc_retired_party`) before any derivation, and
/// nothing else counts it; once the quarantine has passed, the same
/// identity's SETUP opens again.
#[test]
fn a_retired_identity_is_dropped_for_its_quarantine_without_a_derivation() {
    let mut rig = rig();
    let mut sealer = setup_sealer(0x11);
    let first = sealed(&mut sealer, &announce());
    let second = sealed(&mut sealer, &announce());
    let quarantine = crate::sessions::receive::SessionConfig::default().alias_quarantine;
    rig.role.sessions.quarantine_for_test(IDENTITY, 1_000);
    rig.inject(&first);
    let rejections = rig.rejections();
    assert_eq!(rejections.get(EncRejection::RetiredParty), 1);
    assert_eq!(rejections.total(), 1, "nothing else counts it");
    // Past the quarantine the identity is no longer retired.
    rig.role.inject_datagram(
        &rig.sessions,
        EndpointId(1),
        rig.source,
        &second,
        1_000 + quarantine,
    );
    let rejections = rig.rejections();
    assert_eq!(rejections.get(EncRejection::RetiredParty), 1);
    assert_eq!(rejections.total(), 1);
}

/// Gate H10 (manifest section 7 and section 2.1, the R4 flood; ADR-0114
/// sections 6 and 8, "Accounting before every open"): a flood of domain 5
/// SETUP ANNOUNCEs forged under another channel key (invalid tags) goes
/// through the receiver role's real receive path allocating nothing; each
/// is dropped and counted (`enc_tag`) after one scratch open, makes no
/// challenge entry, and changes nothing of the role but its datagram
/// count. The domain 1 flood on an established image is
/// `an_invalid_tag_flood_on_an_encrypted_image_allocates_nothing` (images
/// tests).
#[test]
fn an_invalid_tag_setup_flood_allocates_nothing_and_changes_nothing() {
    const FLOOD: usize = 2_000;

    let mut rig = rig();
    // At most 100 bootstrap seals a second: the ANNOUNCEs cycle.
    let mut forger = setup_sealer(0x99);
    let announces: Vec<Vec<u8>> = (0..50).map(|_| sealed(&mut forger, &announce())).collect();
    // One first: the scratch slot is made once, ahead of the flood.
    rig.inject(&announces[0]);
    let counters = rig.role.counters;
    let before = rig.rejections();
    let ((), allocations) = karyos_sys::alloc_count::count_allocations(|| {
        for bytes in announces.iter().cycle().take(FLOOD) {
            rig.inject(bytes);
        }
    });
    assert_eq!(allocations, 0, "the flood allocates nothing");
    let after = rig.rejections();
    let flooded = u64::try_from(FLOOD).unwrap();
    assert_eq!(
        after.get(EncRejection::Tag),
        before.get(EncRejection::Tag) + flooded,
        "{after:?}"
    );
    assert_eq!(after.total(), before.total() + flooded, "{after:?}");
    assert!(rig.role.posted_challenges().is_empty(), "no challenge");
    let mut moved = rig.role.counters;
    moved.datagrams = counters.datagrams;
    assert_eq!(moved, counters, "nothing but the datagram count");
    assert_eq!(rig.role.enc.unattributed, EncRejections::default());
}

fn challenge_of(identity: Identity) -> Control {
    challenge_on(identity, ALIAS)
}

fn challenge_on(identity: Identity, alias: Alias) -> Control {
    Control::Challenge(karyos_protocol::network::RspChallenge {
        alias,
        identity,
        challenge: ChallengeBlock {
            receiver_boot_id: [7, 8],
            nonce: [9, 9],
        },
    })
}

/// The sealer `enc_rsp_seal` gives `control` on endpoint 1 of `rig`.
fn rsp_seal_of(rig: &mut Rig, control: &Control) -> SharedSealer {
    let mut intake = Intake {
        endpoint: EndpointId(1),
        now: 1_000,
        role: &mut rig.role,
        sessions: &rig.sessions,
        work: 0,
    };
    intake.enc_rsp_seal(EndpointId(1), control).unwrap()
}

/// H8-01: a subscription removed and made again within one receiver boot
/// gets the domain 6 sealer the role made for that key before, so its
/// sequence continues: the same (key, nonce) is never sealed twice.
#[test]
fn a_recreated_subscription_continues_its_rsp_sequence() {
    let mut rig = rig();
    let mut announcer = setup_sealer(0x11);
    rig.inject(&sealed(&mut announcer, &announce()));
    let challenge = challenge_of(IDENTITY);
    assert_eq!(sequence_of(&mut rsp_seal_of(&mut rig, &challenge)), 0);
    for replace in [false, true] {
        if !replace {
            rig.role.enc.unsubscribe(EndpointId(1), 6);
        }
        rig.role.enc.subscribe(
            SubscriptionEnc::new(EndpointId(1), 6, &[&channel(0x11)], &[&pairwise()], 66).unwrap(),
        );
        rig.inject(&sealed(&mut announcer, &announce()));
    }
    assert_eq!(
        sequence_of(&mut rsp_seal_of(&mut rig, &challenge)),
        1,
        "the sequence continues across the subscription's replacement"
    );
    assert_eq!(rig.role.enc.rsp.len(), 1);
}

/// H8-02: domain 1 headers no verified datagram backs (forged, under
/// another key, each naming a fresh publication on a fresh alias) record no
/// target and make no domain 6 sealer, however many; the SOLICITs they
/// could cause are refused. A legitimate publication's verified ANNOUNCE is
/// then still challenged, sealed in domain 6.
#[test]
fn forged_headers_take_no_rsp_slot_and_a_verified_target_is_still_challenged() {
    use karyos_protocol::network::RspSolicit;

    let mut rig = rig();
    let forged_keys = ChannelKeys::new(&[&channel(0x99)]).unwrap();
    let mut buffer = [0_u8; 512];
    for n in 0..=u64::try_from(RSP_SEALERS).unwrap() {
        let session_id = 100 + i32::try_from(n).unwrap();
        let alias = Alias {
            session_id,
            stream_id: 6,
        };
        let publication = PublicationIdentity {
            driver_id: [9; 16],
            registration_id: 10 + n,
            incarnation: 1,
        };
        let mut forger = EncSealer::new(
            &forged_keys,
            None,
            KeyContext {
                domain: Domain::Sender,
                key_epoch: 1,
                party_epoch: 0,
                session_id,
                stream_id: 6,
                publication,
                receiver: None,
                salt: Salt::Challenge {
                    receiver_boot_id: [1; 16],
                    nonce: [2; 16],
                },
            },
            monotonic_ns,
        )
        .unwrap();
        rig.inject(&sealed(&mut forger, &announce()));
        let solicit = Control::Solicit(RspSolicit {
            alias,
            challenge: ChallengeBlock {
                receiver_boot_id: [7, 8],
                nonce: [9, 9],
            },
        });
        let length = solicit.encode(&mut buffer).unwrap();
        assert_eq!(
            rsp_seal_of(&mut rig, &solicit).seal_control(&mut buffer, length),
            None
        );
    }
    assert!(rig.role.enc.rsp.is_empty(), "no persistent sealer");
    assert!(rig.role.enc.verified.is_empty(), "no persistent target");
    // A CHALLENGE to an identity no verified datagram named is refused too.
    let mut stranger = IDENTITY;
    stranger.registration_id = 99;
    let challenge = challenge_of(stranger);
    let length = challenge.encode(&mut buffer).unwrap();
    assert_eq!(
        rsp_seal_of(&mut rig, &challenge).seal_control(&mut buffer, length),
        None
    );
    rig.inject(&sealed(&mut setup_sealer(0x11), &announce()));
    let challenge = challenge_of(IDENTITY);
    let length = challenge.encode(&mut buffer).unwrap();
    assert!(
        rsp_seal_of(&mut rig, &challenge)
            .seal_control(&mut buffer, length)
            .is_some(),
        "the legitimate target is challenged"
    );
}

/// H8-08 (section 6b): an answer that echoes the outstanding challenge
/// but is refused for any later reason (another term, an envelope under
/// another file epoch, one verified only under the previous file epoch, a
/// lower pair) consumes nothing and moves nothing: the legitimate answer
/// still resynchronises.
#[test]
fn a_refused_resync_answer_leaves_the_challenge_to_the_legitimate_one() {
    let mut terms = enc_answer(2, 3, NONCE);
    terms.answer.term.mtu = 1024;
    let mut identity = enc_answer(2, 3, NONCE);
    identity.answer.identity.incarnation = 2;
    let refusals = [
        (terms, 2, true),
        (identity, 2, true),
        (enc_answer(2, 3, NONCE), 1, true),
        (enc_answer(2, 3, NONCE), 2, false),
        (enc_answer(1, 0, NONCE), 1, true),
    ];
    for (answer, envelope, current) in refusals {
        let mut role = bound();
        if answer.key_epoch == 1 {
            role.enc.images[0].opener.resync(1, 4, 0).unwrap();
        }
        let before = role.enc.images[0].opener.epochs();
        assert_eq!(
            role.enc.resync(0, &answer, envelope, current, BOOT, 1_500),
            Err(EncRejection::ResyncRefused)
        );
        assert_eq!(role.enc.images[0].opener.epochs(), before, "nothing moved");
        assert_eq!(
            role.enc.images[0].resync,
            Some((NONCE, 1_000)),
            "not consumed"
        );
        assert_eq!(
            role.enc
                .resync(0, &enc_answer(2, 5, NONCE), 2, true, BOOT, 1_600),
            Ok(())
        );
        assert_eq!(role.enc.images[0].opener.epochs(), (2, 5));
        assert!(
            role.enc.images[0].resync.is_none(),
            "consumed with the move"
        );
    }
}

/// H8-09 (section 10 step 2): a VM generation change withdraws every
/// domain 6 sealer through its shared object, so a clone a queued control
/// holds is erased with it, before the role reports itself redrawn.
#[test]
fn a_vm_generation_change_withdraws_every_queued_rsp_sealer() {
    let mut role = bound();
    let queued = role
        .enc
        .rsp_sealer(0, publication_of(&IDENTITY), ALIAS, [4; 16], true)
        .unwrap();
    assert!(!queued.is_withdrawn());
    let sessions = session_end();
    let injector = watched(&mut role);
    injector.change();
    role.on_generation_change(&sessions, AFTER);
    assert_eq!(role.enc_generation(), 1);
    assert!(queued.is_withdrawn(), "the queued clone is erased");
    assert!(
        role.enc.rsp.is_empty(),
        "the table is free under the new boot"
    );
}

/// One step of [`no_sealer_repeats_a_key_and_nonce_within_a_boot`].
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Seals the CHALLENGE to target 0 or 1 in domain 6.
    Challenge(u8),
    /// Establishes an image: a fresh nonce, its domain 4 sealer.
    Establish,
    /// Seals with the domain 4 sealer of image `n` (modulo the count).
    Control(u8),
    /// Rolls the `party_epoch` of image `n`'s domain 4 sealer, or of
    /// target `n`'s domain 6 sealer.
    RollD4(u8),
    RollD6(u8),
    /// Rotates the channel file: epoch 2 admitted and signing.
    RotateFile,
    /// Moves both targets to the other alias (H8-10): each announces on
    /// it, and the CHALLENGEs that follow are on it.
    Alias,
    /// Replaces the subscription with a new one of the same files.
    Replace,
    /// Removes the subscription, then makes it again.
    RemoveRecreate,
}

fn step() -> impl proptest::strategy::Strategy<Value = Step> {
    use proptest::prelude::*;
    prop_oneof![
        (0_u8..2).prop_map(Step::Challenge),
        Just(Step::Establish),
        any::<u8>().prop_map(Step::Control),
        any::<u8>().prop_map(Step::RollD4),
        (0_u8..2).prop_map(Step::RollD6),
        Just(Step::RotateFile),
        Just(Step::Alias),
        Just(Step::Replace),
        Just(Step::RemoveRecreate),
    ]
}

fn run_steps(steps: &[Step]) -> Vec<crate::wire_enc::SealedRecord> {
    use crate::wire_auth::FixedKeys;

    let mut rig = rig();
    let identities = [IDENTITY, {
        let mut other = IDENTITY;
        other.registration_id = 4;
        other
    }];
    let aliases = [ALIAS, ALIAS_2];
    let mut on = 0_usize;
    for identity in identities {
        rig.inject(&announce_under(identity));
    }
    let mut controls: Vec<SharedSealer> = Vec::new();
    let mut buffer = [0_u8; 512];
    let frames = 64;
    crate::wire_enc::record_seals();
    for step in steps {
        match *step {
            Step::Challenge(target) => {
                let challenge = challenge_on(identities[usize::from(target)], aliases[on]);
                let _ = rsp_seal_of(&mut rig, &challenge).seal_control(&mut buffer, frames);
            }
            Step::Alias => {
                on = 1 - on;
                for identity in identities {
                    rig.inject(&announce_on(identity, aliases[on]));
                }
            }
            Step::Establish => {
                let Some(nonce) = rig.role.nonces.nonce() else {
                    continue;
                };
                rig.role
                    .enc
                    .answers
                    .push((EndpointId(1), ALIAS, enc_answer(1, 0, nonce)));
                let key = BindingKey {
                    endpoint: EndpointId(1),
                    source: rig.source,
                    alias: ALIAS,
                };
                let slot = SlotRef {
                    slot: controls.len().try_into().unwrap(),
                    generation: 1,
                };
                if let Ok(Some(sealer)) = rig.role.enc_keys(&key, IDENTITY, slot, 66, nonce, 1_000)
                {
                    controls.push(sealer);
                }
            }
            Step::Control(n) | Step::RollD4(n) if !controls.is_empty() => {
                let at = usize::from(n) % controls.len();
                if matches!(step, Step::RollD4(_)) {
                    controls[at].roll_for_test();
                } else {
                    let _ = controls[at].seal_control(&mut buffer, frames);
                }
            }
            Step::Control(_) | Step::RollD4(_) => {}
            Step::RollD6(target) => {
                let challenge = challenge_on(identities[usize::from(target)], aliases[on]);
                rsp_seal_of(&mut rig, &challenge).roll_for_test();
            }
            Step::RotateFile => {
                rig.role.enc.apply_keys(&FixedKeys {
                    files: vec![channel(0x11), second_epoch(), pairwise()],
                });
                for control in &mut controls {
                    control.apply_keys(&FixedKeys {
                        files: vec![channel(0x11), second_epoch(), pairwise()],
                    });
                }
            }
            Step::Replace | Step::RemoveRecreate => {
                if matches!(step, Step::RemoveRecreate) {
                    rig.role.enc.unsubscribe(EndpointId(1), 6);
                }
                rig.role.enc.subscribe(
                    SubscriptionEnc::new(EndpointId(1), 6, &[&channel(0x11)], &[&pairwise()], 66)
                        .unwrap(),
                );
                for identity in identities {
                    rig.inject(&announce_on(identity, aliases[on]));
                }
            }
        }
    }
    crate::wire_enc::take_seals()
}

/// The derivation inputs of a recorded seal's key (H8-10): its context
/// with the selectors `session_id` and `stream_id` cleared, which enter
/// no HKDF input. Every rig file of a key id has one secret per epoch, so
/// equal inputs mean one derived key.
fn derivation(context: &KeyContext) -> KeyContext {
    KeyContext {
        session_id: 0,
        stream_id: 0,
        ..*context
    }
}

/// A verified domain 5 ANNOUNCE of `identity`, under its own key.
fn announce_under(identity: Identity) -> Vec<u8> {
    announce_on(identity, ALIAS)
}

/// A second alias of the rig's stream.
const ALIAS_2: Alias = Alias {
    session_id: 9,
    stream_id: 6,
};

/// A verified domain 5 ANNOUNCE of `identity` on `alias`.
fn announce_on(identity: Identity, alias: Alias) -> Vec<u8> {
    let keys = ChannelKeys::new(&[&channel(0x11)]).unwrap();
    let mut sealer = EncSealer::new(
        &keys,
        None,
        KeyContext {
            domain: Domain::Setup,
            key_epoch: 1,
            party_epoch: 0,
            session_id: alias.session_id,
            stream_id: alias.stream_id,
            publication: publication_of(&identity),
            receiver: None,
            salt: Salt::Empty,
        },
        monotonic_ns,
    )
    .unwrap();
    let mut control = announce();
    if let Control::SetupAnnounce(setup) = &mut control {
        setup.identity = identity;
        setup.alias = alias;
    }
    sealed(&mut sealer, &control)
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

    /// H8-01, H8-10 and ADR-0114 section 6: within one receiver boot,
    /// across any sequence of subscription replacements, removals and
    /// re-creations, alias changes, `party_epoch` rolls, file epoch
    /// rotations and seals in domains 4 and 6, no two seals share the
    /// derivation inputs of their key (the context less its selectors)
    /// and an envelope sequence, so no (key, nonce) pair is ever used
    /// twice.
    #[test]
    fn no_sealer_repeats_a_key_and_nonce_within_a_boot(
        steps in proptest::collection::vec(step(), 1..48)
    ) {
        // The receiver's own sealers: domains 4 and 6.
        let seals: Vec<_> = run_steps(&steps)
            .into_iter()
            .filter(|record| record.context.domain.is_receiver())
            .collect();
        for (at, record) in seals.iter().enumerate() {
            for other in &seals[..at] {
                proptest::prop_assert!(
                    !(derivation(&other.context) == derivation(&record.context)
                        && other.seq == record.seq),
                    "(key, nonce) reused: {:?} seq {}",
                    record.context,
                    record.seq
                );
            }
        }
    }
}

/// The header of `control` sealed by `seal`.
fn sealed_head(seal: &mut SharedSealer, control: &Control) -> crate::wire_enc::Header {
    let mut bytes = vec![0_u8; MAX_SEALED];
    let length = control.encode(&mut bytes).unwrap();
    let sealed = seal.seal_control(&mut bytes, length).unwrap();
    crate::wire_enc::header(&bytes[..sealed]).unwrap()
}

/// H8-14 (with H8-10; ADR-0114 sections 4, 5 and 7): `session_id` and
/// `stream_id` are selectors, never HKDF inputs, so a publication's domain
/// 6 key is one key on every alias, with one sequence, and no alias owns
/// it. A channel key holder that announces the target's identity on its
/// own alias first gets its CHALLENGE sealed there; the genuine
/// publication's verified ANNOUNCE on its alias then still gets its
/// CHALLENGE sealed, its header naming that alias, its sequence continuing
/// the key's one counter (never 0 again), and it opens under the target's
/// key; the attacker's alias pins nothing.
#[test]
fn a_forged_first_alias_never_pins_the_target() {
    let mut rig = rig();
    rig.inject(&announce_on(IDENTITY, ALIAS_2));
    let forged = sealed_head(
        &mut rsp_seal_of(&mut rig, &challenge_on(IDENTITY, ALIAS_2)),
        &challenge_on(IDENTITY, ALIAS_2),
    );
    assert_eq!((forged.session_id, forged.seq), (ALIAS_2.session_id, 0));
    rig.inject(&announce_on(IDENTITY, ALIAS));
    assert_eq!(rig.rejections().total(), 0, "both announces verified");
    let genuine = challenge_on(IDENTITY, ALIAS);
    let mut seal = rsp_seal_of(&mut rig, &genuine);
    let mut bytes = vec![0_u8; MAX_SEALED];
    let length = genuine.encode(&mut bytes).unwrap();
    let sealed = seal
        .seal_control(&mut bytes, length)
        .expect("the genuine alias is challenged");
    let head = crate::wire_enc::header(&bytes[..sealed]).unwrap();
    assert_eq!(
        (head.session_id, head.stream_id, head.seq),
        (ALIAS.session_id, ALIAS.stream_id, 1),
        "its alias, the key's one sequence"
    );
    // It opens under the target's domain 6 key with the receiver's
    // pairwise trailer, the publication's alias in its header.
    let mut out = [0_u8; MAX_PLAINTEXT];
    let opened = crate::wire_enc::open_bootstrap(
        &ChannelKeys::new(&[&channel(0x11)]).unwrap(),
        Some(&crate::wire_enc::PairwiseFiles::new(&[&pairwise()]).unwrap()),
        Some(publication_of(&IDENTITY)),
        &bytes[..sealed],
        &mut out,
        &mut crate::wire_enc::OpenRate::default(),
        0,
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(matches!(
        karyos_protocol::network::classify(&out[..opened.frames]),
        Ok(karyos_protocol::network::Datagram::Control(control)) if control == genuine
    ));
    assert_eq!(rig.role.enc.rsp.len(), 1, "one entry, one counter");
    // Either alias continues the same counter.
    let again = sealed_head(
        &mut rsp_seal_of(&mut rig, &challenge_on(IDENTITY, ALIAS_2)),
        &challenge_on(IDENTITY, ALIAS_2),
    );
    assert_eq!(again.seq, 2);
}

/// A publication of the rig's driver, registration `n`.
fn target(n: u64) -> PublicationIdentity {
    PublicationIdentity {
        driver_id: [5; 16],
        registration_id: 100 + n,
        incarnation: 1,
    }
}

/// A role whose one subscription holds channel epoch 1, with every domain
/// 6 entry of the table made, one target each, each having sealed once.
fn full_rsp_table() -> super::super::ReceiverRole {
    let (_, mut role) = super::super::roles(&AgentConfig::default()).unwrap();
    role.enc.subscribe(
        SubscriptionEnc::new(EndpointId(1), 6, &[&channel(0x11)], &[&pairwise()], 66).unwrap(),
    );
    for n in 0..u64::try_from(RSP_SEALERS).unwrap() {
        let mut sealer = role
            .enc
            .rsp_sealer(0, target(n), ALIAS, [4; 16], true)
            .unwrap();
        assert_eq!(sequence_of(&mut sealer), 0);
    }
    let over = u64::try_from(RSP_SEALERS).unwrap();
    assert!(
        role.enc
            .rsp_sealer(0, target(over), ALIAS, [4; 16], true)
            .is_none(),
        "full"
    );
    role
}

/// H8-11: once the root file epoch every entry sealed under stops
/// verifying, its withdrawn entries are reclaimed, so turnover past 64
/// targets within one boot keeps challenging: 64 more targets, and the
/// first ones again, get sealers under the successor epoch, sequence 0
/// under a new key. No sealer is made again under the reclaimed epoch.
#[test]
fn rsp_entries_are_reclaimed_once_their_root_stops_verifying() {
    use crate::wire_auth::FixedKeys;

    let mut role = full_rsp_table();
    role.enc.apply_keys(&FixedKeys {
        files: vec![second_epoch(), pairwise()],
    });
    assert!(role.enc.rsp.is_empty(), "every expired entry is reclaimed");
    assert_eq!(role.enc.floors, vec![(3, 1)]);
    for n in 0..2 * u64::try_from(RSP_SEALERS).unwrap() {
        let sealer = role.enc.rsp_sealer(0, target(n), ALIAS, [4; 16], true);
        if n < u64::try_from(RSP_SEALERS).unwrap() {
            let mut sealer = sealer.unwrap();
            let mut bytes = vec![0_u8; MAX_SEALED];
            let length = announce().encode(&mut bytes).unwrap();
            let sealed = sealer.seal_control(&mut bytes, length).unwrap();
            let head = crate::wire_enc::header(&bytes[..sealed]).unwrap();
            assert_eq!((head.key_epoch, head.seq), (2, 0), "a new key");
        } else {
            assert!(sealer.is_none(), "bounded at {RSP_SEALERS}");
        }
    }
    // A floor at epoch 1: should epoch 1 verify again, no sealer of key id
    // 3 is made under it in this boot.
    role.enc.rsp.clear();
    role.enc.subscriptions[0].keys = ChannelKeys::new(&[&channel(0x11)]).unwrap();
    assert!(
        role.enc
            .rsp_sealer(0, target(0), ALIAS, [4; 16], true)
            .is_none()
    );
}

/// H8-11: an entry whose key is still live, or which is withdrawn while a
/// file it sealed under still verifies (a tombstone), is never reclaimed:
/// the table stays full and refuses a new target (fail closed).
#[test]
fn a_still_derivable_rsp_entry_is_never_reclaimed() {
    use crate::wire_auth::FixedKeys;

    let mut role = full_rsp_table();
    // Every target is current (a verified SETUP named it), so at the
    // rotation every sealer moves to epoch 2 and stays live.
    for n in 0..u64::try_from(RSP_SEALERS).unwrap() {
        role.enc.verified.push((EndpointId(1), ALIAS, target(n)));
    }
    role.enc.apply_keys(&FixedKeys {
        files: vec![channel(0x11), second_epoch(), pairwise()],
    });
    assert_eq!(role.enc.rsp.len(), RSP_SEALERS);
    let over = u64::try_from(RSP_SEALERS).unwrap();
    assert!(
        role.enc
            .rsp_sealer(0, target(over), ALIAS, [4; 16], true)
            .is_none()
    );
    // The pairwise file goes: every sealer is withdrawn, but both channel
    // epochs still verify.
    role.enc.apply_keys(&FixedKeys {
        files: vec![channel(0x11), second_epoch()],
    });
    assert_eq!(role.enc.rsp.len(), RSP_SEALERS, "tombstones stay");
    assert!(role.enc.floors.is_empty());
    // Epoch 1 goes, epoch 2 stays: they sealed under 2, which verifies.
    role.enc.apply_keys(&FixedKeys {
        files: vec![second_epoch()],
    });
    assert_eq!(role.enc.rsp.len(), RSP_SEALERS);
}

/// An ANNOUNCE of `IDENTITY` on `ALIAS` sealed in domain 5 under channel
/// file epoch `epoch` (1 is fill 0x11, 2 is fill 0x55).
fn announce_at(epoch: u32) -> Vec<u8> {
    let file = if epoch == 1 {
        channel(0x11)
    } else {
        second_epoch()
    };
    let keys = ChannelKeys::new(&[&file]).unwrap();
    let mut sealer = EncSealer::new(
        &keys,
        None,
        KeyContext {
            domain: Domain::Setup,
            key_epoch: epoch,
            party_epoch: 0,
            session_id: ALIAS.session_id,
            stream_id: ALIAS.stream_id,
            publication: publication_of(&IDENTITY),
            receiver: None,
            salt: Salt::Empty,
        },
        monotonic_ns,
    )
    .unwrap();
    sealed(&mut sealer, &announce())
}

/// The view of a successor's activation: `signing` the channel epoch that
/// signs, `verifying` the ones that verify, with the pairwise file.
fn view(signing: u32, verifying: &[u32]) -> crate::wire_auth::SplitKeys {
    let file = |epoch: u32| {
        if epoch == 1 {
            channel(0x11)
        } else {
            second_epoch()
        }
    };
    let mut files: Vec<KeyFile> = verifying.iter().map(|epoch| file(*epoch)).collect();
    files.push(pairwise());
    crate::wire_auth::SplitKeys {
        signing: Some(file(signing)),
        verifying: files,
        current: verifying.iter().copied().max(),
    }
}

/// H8-12 (section 7, wire-key-files.md 2.3): the active binding epoch is
/// the signing one, not the highest that verifies. With both channel
/// epochs loaded, before the successor's activation (it verifies early,
/// its predecessor signs) a SETUP under the predecessor, which every party
/// still sends under, establishes, and so does one under the successor;
/// at activation (the successor signs) the retired predecessor binds
/// nothing and the successor establishes; after the predecessor stops
/// verifying, likewise.
#[test]
fn establishment_binds_through_the_signing_epoch_around_activation() {
    for (phase, view, binds) in [
        ("before", view(1, &[1, 2]), [true, true]),
        ("at", view(2, &[1, 2]), [false, true]),
        ("after", view(2, &[2]), [false, true]),
    ] {
        for (epoch, binds) in [1, 2].into_iter().zip(binds) {
            let (_, mut role): (_, super::super::ReceiverRole) =
                super::super::roles(&AgentConfig::default()).unwrap();
            role.enc.subscribe(
                SubscriptionEnc::new(
                    EndpointId(1),
                    6,
                    &[&channel(0x11), &second_epoch()],
                    &[&pairwise()],
                    66,
                )
                .unwrap(),
            );
            role.enc.apply_keys(&view);
            let (sessions, _link) = session_rings(std::num::NonZeroUsize::new(4).unwrap());
            let source: SocketAddr = "10.0.0.2:4000".parse().unwrap();
            role.inject_datagram(&sessions, EndpointId(1), source, &announce_at(epoch), 1_000);
            let rejections = role.enc.rejections(EndpointId(1), 6).unwrap();
            assert_eq!(
                role.enc.verified.len(),
                usize::from(binds),
                "{phase} activation, epoch {epoch}: {rejections:?}"
            );
            if binds {
                assert_eq!(rejections.total(), 0, "{phase}, {epoch}");
            }
        }
    }
}

/// H8-12 (section 6b): with both epochs loaded, a resynchronisation
/// answer under the signing epoch (or the successor already) moves the
/// binding before the successor's activation and at it; one under a
/// retired predecessor never does. (After the predecessor stops verifying
/// an image still bound under it is withdrawn, and re-establishes.)
#[test]
fn resync_binds_through_the_signing_epoch_around_activation() {
    for (phase, view, binds) in [
        ("before", view(1, &[1, 2]), [true, true]),
        ("at", view(2, &[1, 2]), [false, true]),
    ] {
        for (epoch, binds) in [1, 2].into_iter().zip(binds) {
            let mut role = bound();
            role.enc.apply_keys(&view);
            let result = role
                .enc
                .resync(0, &enc_answer(epoch, 3, NONCE), epoch, true, BOOT, 1_500);
            if binds {
                assert_eq!(result, Ok(()), "{phase} activation, epoch {epoch}");
                assert_eq!(role.enc.images[0].opener.epochs(), (epoch, 3));
            } else {
                assert_eq!(result, Err(EncRejection::ResyncRefused), "{phase}, {epoch}");
                assert_eq!(role.enc.images[0].opener.epochs(), (1, 0));
            }
        }
    }
}

/// H8-11: with normal overlapping rotation (the successor admitted and
/// signing while the predecessor still verifies), an entry whose target is
/// gone is not advanced to the successor: it stays withdrawn under epoch 1,
/// only as that epoch's nonce history. A target that comes back verified
/// gets the successor's key from sequence 0 (a key never used); once epoch
/// 1 stops verifying the other 63 entries are reclaimed, so turnover goes
/// past 64 targets within one boot, still bounded at 64.
#[test]
fn rsp_turnover_passes_64_targets_across_an_overlapping_rotation() {
    use crate::agents::control::ControlSeal;
    use crate::wire_auth::FixedKeys;

    let all = u64::try_from(RSP_SEALERS).unwrap();
    let mut role = full_rsp_table();
    role.enc.apply_keys(&FixedKeys {
        files: vec![channel(0x11), second_epoch(), pairwise()],
    });
    assert_eq!(role.enc.rsp.len(), RSP_SEALERS);
    assert!(
        role.enc
            .rsp
            .iter()
            .all(|entry| entry.sealer.key_epoch().is_none() && entry.high_epoch == 1),
        "no entry of a gone target advanced"
    );
    // Target 0 comes back: the successor's key, from sequence 0.
    let mut back = role
        .enc
        .rsp_sealer(0, target(0), ALIAS, [4; 16], true)
        .unwrap();
    let head = sealed_head(&mut back, &announce());
    assert_eq!((head.key_epoch, head.seq), (2, 0));
    assert!(
        role.enc
            .rsp_sealer(0, target(all), ALIAS, [4; 16], true)
            .is_none(),
        "full while epoch 1 verifies (fail closed)"
    );
    // Epoch 1 stops verifying: its 63 histories go, target 0's live
    // epoch 2 entry stays.
    role.enc.apply_keys(&FixedKeys {
        files: vec![second_epoch(), pairwise()],
    });
    assert_eq!(role.enc.rsp.len(), 1);
    for n in all..2 * all {
        let sealer = role.enc.rsp_sealer(0, target(n), ALIAS, [4; 16], true);
        if n < 2 * all - 1 {
            let head = sealed_head(&mut sealer.unwrap(), &announce());
            assert_eq!((head.key_epoch, head.seq), (2, 0), "target {n}");
        } else {
            assert!(sealer.is_none(), "bounded at {RSP_SEALERS}");
        }
    }
    let head = sealed_head(
        &mut role
            .enc
            .rsp_sealer(0, target(0), ALIAS, [4; 16], true)
            .unwrap(),
        &announce(),
    );
    assert_eq!((head.key_epoch, head.seq), (2, 1), "target 0 continues");
}

/// H8-18 (section 10): a role whose last subscription went keeps its
/// domain 6 sealers for the boot (H8-01) and stays registered with the
/// fence; a VM generation change still withdraws them, a queued clone
/// included, redraws its boot id and reports it, so the fence releases.
#[test]
fn a_role_without_subscriptions_still_closes_its_rsp_sealers_on_a_generation_change() {
    let mut rig = rig();
    let sessions = session_end();
    rig.inject(&announce_on(IDENTITY, ALIAS));
    let queued = rsp_seal_of(&mut rig, &challenge_of(IDENTITY));
    assert!(!queued.is_withdrawn());
    let injector = watched(&mut rig.role);
    rig.role.enc.unsubscribe(EndpointId(1), 6);
    assert!(rig.role.enc.subscriptions.is_empty());
    assert_eq!(rig.role.enc.rsp.len(), 1, "kept for the boot");
    let old = rig.role.boot_id();
    injector.change();
    rig.role.on_generation_change(&sessions, AFTER);
    assert!(queued.is_withdrawn(), "the shared key is withdrawn");
    assert!(rig.role.enc.rsp.is_empty());
    assert_eq!(rig.role.enc_generation(), 1, "reported redrawn");
    assert_ne!(rig.role.boot_id(), old);
    assert!(!crate::wire_enc::quiesced(), "the fence released");
}

/// H8-17 (section 7, wire-key-files.md 2.3): once the successor has been
/// seen to sign, a backward wall-clock step that selects the predecessor
/// to sign again (both still verify) never lets it bind again: no SETUP
/// under it establishes and no resynchronisation answer under it moves a
/// binding; the successor still does both.
#[test]
fn a_backward_clock_step_never_lets_the_predecessor_bind_again() {
    for (epoch, binds) in [(1, false), (2, true)] {
        let (_, mut role): (_, super::super::ReceiverRole) =
            super::super::roles(&AgentConfig::default()).unwrap();
        role.enc.subscribe(
            SubscriptionEnc::new(
                EndpointId(1),
                6,
                &[&channel(0x11), &second_epoch()],
                &[&pairwise()],
                66,
            )
            .unwrap(),
        );
        for signing in [1, 2, 1] {
            role.enc.apply_keys(&view(signing, &[1, 2]));
        }
        let (sessions, _link) = session_rings(std::num::NonZeroUsize::new(4).unwrap());
        let source: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        role.inject_datagram(&sessions, EndpointId(1), source, &announce_at(epoch), 1_000);
        assert_eq!(role.enc.verified.len(), usize::from(binds), "epoch {epoch}");
        let mut role = bound();
        for signing in [1, 2, 1] {
            role.enc.apply_keys(&view(signing, &[1, 2]));
        }
        let result = role
            .enc
            .resync(0, &enc_answer(epoch, 3, NONCE), epoch, true, BOOT, 1_500);
        assert_eq!(result.is_ok(), binds, "resync under epoch {epoch}");
    }
}

/// H8-16 (section 6b): the previous epoch's key a resynchronisation kept
/// for the 10 s overlap is erased by role maintenance once the overlap
/// has passed, with no further promotion and no root retired.
#[test]
fn role_maintenance_erases_the_previous_key_after_its_overlap() {
    let mut role = bound();
    let sessions = session_end();
    role.enc.images[0].opener.resync(1, 3, 1_500).unwrap();
    assert!(role.enc.images[0].opener.has_previous());
    let deadline = 1_500 + crate::wire_enc::EPOCH_OVERLAP_NS;
    role.on_generation_change(&sessions, deadline - 1);
    assert!(
        role.enc.images[0].opener.has_previous(),
        "within the overlap"
    );
    role.on_generation_change(&sessions, deadline);
    assert!(
        !role.enc.images[0].opener.has_previous(),
        "erased at its end"
    );
    assert_eq!(role.enc.images[0].opener.epochs(), (1, 3));
}
