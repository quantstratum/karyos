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
/// subscription exists, so it sets nothing up). A SOLICIT whose target
/// publication is not known (no binding, no DATA naming one) cannot be
/// keyed in domain 6 and is refused, never sent bare.
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
    assert_eq!(seal.seal_control(&mut buffer, 56), None);
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
    assert_eq!(intake.role.enc.subscriptions[0].rsp.len(), 1);
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
        .targets
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
