// SPDX-License-Identifier: Apache-2.0

//! The publisher side of ADR-0114 sections 4, 6a and 7.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::cell::Cell;

use karyos_protocol::frame::Lane;
use karyos_protocol::network::encrypted::{EncSetup, decode_setup};
use karyos_protocol::network::{
    ChallengeBlock, LaneStatus, Lanes, Nak, NakRange, RspChallenge, StatusMessage, TermParams,
};
use karyos_protocol::protection::aes_gcm_siv::{EncRejection, MAX_PLAINTEXT};

use super::*;
use crate::wire_enc::open_bootstrap;
use crate::wire_enc::{EncOpener, MAX_SEALED, OpenRate, SECOND_NS};
use crate::wire_keys::{KEY_LEN, parse};

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(5 * SECOND_NS) };
}

fn clock() -> u64 {
    NOW.with(Cell::get)
}

fn file(text: String, name: &str) -> KeyFile {
    parse(name, text.as_bytes()).unwrap()
}

fn channel(epoch: u32, fill: u8) -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    file(
        format!(
            "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch={epoch}\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=6\n"
        ),
        &format!("3-{epoch}.key"),
    )
}

fn pairwise(fill: u8) -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    file(
        format!(
            "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=1\npurpose=pairwise\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nreceiver_id=66\npublisher_id=5\n"
        ),
        "9-1.key",
    )
}

const ALIAS: Alias = Alias {
    session_id: 9,
    stream_id: 6,
};
const IDENTITY: Identity = Identity {
    driver_id: [1, 1],
    registration_id: 7,
    incarnation: 1,
};

fn publication() -> PublicationEnc {
    PublicationEnc::new(
        EndpointId(1),
        ALIAS,
        IDENTITY,
        &[&channel(1, 0x11)],
        &[&pairwise(0x22)],
        clock,
    )
    .unwrap()
}

/// One receiver start: its block and its keys.
struct Peer {
    boot: u64,
    receiver: ReceiverIdentity,
    rsp: EncSealer,
    nonce: [u64; 2],
}

fn peer(boot: u64, pairwise_fill: u8, key_epoch: u32, keys: &ChannelKeys) -> Peer {
    let receiver = ReceiverIdentity {
        receiver_boot_id: id128([boot, boot]),
        receiver_id: 66,
    };
    let files = PairwiseFiles::new(&[&pairwise(pairwise_fill)]).unwrap();
    let rsp = EncSealer::new(
        keys,
        Some(&files),
        KeyContext {
            domain: Domain::RspSetup,
            key_epoch,
            party_epoch: 0,
            session_id: ALIAS.session_id,
            stream_id: ALIAS.stream_id,
            publication: publication_of(&IDENTITY),
            receiver: Some(receiver),
            salt: Salt::Empty,
        },
        clock,
    )
    .unwrap();
    Peer {
        boot,
        receiver,
        rsp,
        nonce: [boot + 100, boot + 100],
    }
}

impl Peer {
    fn challenge(&mut self) -> Vec<u8> {
        let control = Control::Challenge(RspChallenge {
            alias: ALIAS,
            identity: IDENTITY,
            challenge: ChallengeBlock {
                receiver_boot_id: [self.boot, self.boot],
                nonce: self.nonce,
            },
        });
        seal_control(&mut self.rsp, &control)
    }

    fn data_keys(&self) -> (EncSealer, PairwiseFiles) {
        let files = PairwiseFiles::new(&[&pairwise(0x22)]).unwrap();
        let keys = ChannelKeys::new(&[&channel(1, 0x11)]).unwrap();
        let sealer = EncSealer::new(
            &keys,
            Some(&files),
            KeyContext {
                domain: Domain::Receiver,
                key_epoch: 1,
                party_epoch: 0,
                session_id: ALIAS.session_id,
                stream_id: ALIAS.stream_id,
                publication: publication_of(&IDENTITY),
                receiver: Some(self.receiver),
                salt: Salt::Challenge {
                    receiver_boot_id: self.receiver.receiver_boot_id,
                    nonce: id128(self.nonce),
                },
            },
            clock,
        )
        .unwrap();
        (sealer, files)
    }

    fn nak(&self) -> Control {
        let boot = self.boot;
        Control::Nak(Nak {
            alias: ALIAS,
            identity: IDENTITY,
            receiver: Receiver {
                receiver_boot_id: [boot, boot],
                receiver_id: 66,
            },
            range: NakRange {
                lane: Lane::ZERO,
                length: 32,
                start: 0,
            },
        })
    }
}

fn seal_control(sealer: &mut EncSealer, control: &Control) -> Vec<u8> {
    let mut bytes = vec![0_u8; MAX_SEALED];
    let length = control.encode(&mut bytes).unwrap();
    let sealed = sealer.seal(&mut bytes, length).unwrap();
    bytes.truncate(sealed);
    bytes
}

fn open(publication: &mut PublicationEnc, bytes: &[u8]) -> Result<EncOpened, EncRejection> {
    let mut out = [0_u8; MAX_PLAINTEXT];
    publication.open(bytes, &mut out)
}

fn keys() -> ChannelKeys {
    ChannelKeys::new(&[&channel(1, 0x11)]).unwrap()
}

/// Section 7, "Pairwise proof first": an RSP_SETUP forged by a group
/// holder binds nothing and is counted; the genuine one binds once, and a
/// repeat neither re-derives nor rebinds.
#[test]
fn an_rsp_setup_binds_only_with_its_pairwise_proof() {
    let mut publication = publication();
    let mut forger = peer(5, 0x55, 1, &keys());
    assert_eq!(
        open(&mut publication, &forger.challenge()),
        Err(EncRejection::Pairwise)
    );
    assert_eq!(publication.bound_receiver(), None);
    assert_eq!(
        publication.channel.rejections.get(EncRejection::Pairwise),
        1
    );
    let mut genuine = peer(5, 0x22, 1, &keys());
    let Ok(EncOpened::RspSetup(_, establishing)) = open(&mut publication, &genuine.challenge())
    else {
        panic!()
    };
    assert!(establishing.bind);
    assert_eq!(publication.bound_receiver(), Some(genuine.receiver));
    let Ok(EncOpened::RspSetup(_, again)) = open(&mut publication, &genuine.challenge()) else {
        panic!()
    };
    assert!(!again.bind);
    // Its NAK opens under the committed domain 4 key; a forged one with a
    // valid outer tag and a wrong trailer is refused.
    let (mut sealer, _) = genuine.data_keys();
    let nak = genuine.nak();
    assert_eq!(
        open(&mut publication, &seal_control(&mut sealer, &nak)),
        Ok(EncOpened::Receiver(nak))
    );
    let theirs = PairwiseFiles::new(&[&pairwise(0x55)]).unwrap();
    let mut context = *sealer.context();
    context.party_epoch = 0;
    let mut forged = EncSealer::new(&keys(), Some(&theirs), context, clock).unwrap();
    // Past the genuine sequence: the trailer, not the window, refuses it.
    seal_control(&mut forged, &nak);
    assert_eq!(
        open(&mut publication, &seal_control(&mut forged, &nak)),
        Err(EncRejection::Pairwise)
    );
}

/// Section 7: an old RSP_SETUP followed by its old NAKs, replayed after
/// the receiver restarted, changes no binding and moves no window.
#[test]
fn an_old_rsp_setup_and_its_naks_replayed_after_a_restart_change_nothing() {
    let mut publication = publication();
    let mut first = peer(5, 0x22, 1, &keys());
    let old_challenge = first.challenge();
    assert!(open(&mut publication, &old_challenge).is_ok());
    let (mut old_sealer, _) = first.data_keys();
    let old_nak = seal_control(&mut old_sealer, &first.nak());
    assert!(open(&mut publication, &old_nak).is_ok());
    // The receiver restarts with a new boot id.
    let mut second = peer(6, 0x22, 1, &keys());
    let Ok(EncOpened::RspSetup(_, establishing)) = open(&mut publication, &second.challenge())
    else {
        panic!()
    };
    assert!(establishing.bind);
    for replay in [&old_challenge, &old_nak] {
        assert_eq!(
            open(&mut publication, replay),
            Err(EncRejection::RetiredBoot)
        );
    }
    assert_eq!(publication.bound_receiver(), Some(second.receiver));
    let (mut sealer, _) = second.data_keys();
    assert!(open(&mut publication, &seal_control(&mut sealer, &second.nak())).is_ok());
}

/// Section 7: an RSP_SETUP that verifies only under the previous file
/// epoch never creates a binding.
#[test]
fn an_rsp_setup_under_the_previous_file_epoch_binds_nothing() {
    let mut publication = PublicationEnc::new(
        EndpointId(1),
        ALIAS,
        IDENTITY,
        &[&channel(1, 0x11), &channel(2, 0x33)],
        &[&pairwise(0x22)],
        clock,
    )
    .unwrap();
    let both = ChannelKeys::new(&[&channel(1, 0x11), &channel(2, 0x33)]).unwrap();
    let mut old = peer(5, 0x22, 1, &both);
    assert_eq!(
        open(&mut publication, &old.challenge()),
        Err(EncRejection::Epoch)
    );
    assert_eq!(publication.bound_receiver(), None);
    let mut current = peer(5, 0x22, 2, &both);
    assert!(open(&mut publication, &current.challenge()).is_ok());
}

/// Section 6a: every answer is an ENC ANSWER in domain 5 stating the
/// sender's epochs; the session sealer's DATA opens under the receiver's
/// domain 1 opener started at those epochs.
#[test]
fn the_answer_is_variant_3_and_the_session_opens_at_its_epochs() {
    let mut publication = publication();
    let mut receiver = peer(5, 0x22, 1, &keys());
    let Ok(EncOpened::RspSetup(_, establishing)) = open(&mut publication, &receiver.challenge())
    else {
        panic!()
    };
    let answer = SetupAnswer {
        alias: ALIAS,
        identity: IDENTITY,
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 0,
            mtu: 1408,
        },
        challenge: ChallengeBlock {
            receiver_boot_id: [5, 5],
            nonce: receiver.nonce,
        },
        joins: Lanes::new(&[0]).unwrap(),
    };
    let mut bytes = [0_u8; MAX_SEALED];
    let length = publication.seal_answer(answer, None, &mut bytes).unwrap();
    let mut out = [0_u8; MAX_PLAINTEXT];
    let mut rate = OpenRate::default();
    let opened = open_bootstrap(
        &keys(),
        None,
        None,
        &bytes[..length],
        &mut out,
        &mut rate,
        clock(),
        |_, _| Ok(()),
    )
    .unwrap();
    let Ok(EncSetup::Answer(enc)) = decode_setup(&out[..opened.frames]) else {
        panic!()
    };
    assert_eq!((enc.key_epoch, enc.party_epoch), (1, 0));
    assert_eq!(enc.answer, answer);
    // The session's DATA.
    let mut sealer = publication.data_sealer(&establishing).unwrap();
    let mut opener = EncOpener::new(&keys(), None, *sealer.context(), clock()).unwrap();
    let mut data = [0_u8; MAX_SEALED];
    data[..32].copy_from_slice(&{
        let mut frame = [0_u8; 32];
        frame[..4].copy_from_slice(&32_i32.to_le_bytes());
        frame[4] = 1;
        frame[6] = 1;
        frame
    });
    let length = sealer.seal(&mut data, 32).unwrap();
    assert!(
        opener
            .open(&data[..length], &mut out, &mut rate, clock(), |_| Ok(()))
            .is_ok()
    );
    let _ = &mut receiver;
}

/// The ANNOUNCE is sealed in domain 5 under the publication's own key and
/// opens under a scratch derivation from its header.
#[test]
fn the_announce_is_sealed_in_domain_5() {
    let mut publication = publication();
    let announce = Control::SetupAnnounce(karyos_protocol::network::SetupAnnounce {
        alias: ALIAS,
        identity: IDENTITY,
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 0,
            mtu: 1408,
        },
        lane_count: 1,
    });
    let mut bytes = [0_u8; MAX_SEALED];
    let length = announce.encode(&mut bytes).unwrap();
    let sealed = publication.seal_announce(&mut bytes, length).unwrap();
    assert_eq!(sealed, length + 84);
    let mut out = [0_u8; MAX_PLAINTEXT];
    let mut rate = OpenRate::default();
    let opened = open_bootstrap(
        &keys(),
        None,
        None,
        &bytes[..sealed],
        &mut out,
        &mut rate,
        clock(),
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(opened.header.publication, Some(publication_of(&IDENTITY)));
    assert!(matches!(
        decode_setup(&out[..opened.frames]),
        Ok(EncSetup::Announce(_))
    ));
}

/// The sender role routes an encrypted envelope to its publication's keys
/// before anything decodes it: a forged RSP_SETUP is refused and counted
/// on that publication, and one for no encrypted publication is counted
/// unattributed. Neither reaches the trusted path.
#[test]
fn the_sender_role_opens_an_envelope_only_under_its_publication_keys() {
    let (mut sender, _): (super::super::SenderRole, super::super::ReceiverRole) =
        super::super::roles(&crate::agents::AgentConfig::default()).unwrap();
    sender.enc.publish(publication());
    let mut forger = peer(5, 0x55, 1, &keys());
    assert!(
        sender
            .open_sealed_for(EndpointId(1), &forger.challenge())
            .is_none()
    );
    assert_eq!(
        sender
            .enc
            .rejections(EndpointId(1), ALIAS)
            .unwrap()
            .get(EncRejection::Pairwise),
        1
    );
    let mut other = peer(5, 0x22, 1, &keys());
    let mut bytes = other.challenge();
    bytes[24..28].copy_from_slice(&7_i32.to_le_bytes());
    assert!(sender.open_sealed_for(EndpointId(1), &bytes).is_none());
    assert_eq!(sender.enc.unattributed.get(EncRejection::Binding), 1);
    // A genuine CHALLENGE verifies; with no outbound to key it installs
    // nothing and is not answered.
    assert!(
        sender
            .open_sealed_for(EndpointId(1), &other.challenge())
            .is_none()
    );
}

/// ADR-0114 section 10 at the send role. The first duty after the signal
/// drops the publication's keys and binding and gives it the fresh
/// `driver_id` the fence's table holds for the old one. While the fence is
/// held it opens nothing (an RSP_SETUP and a NAK sealed before the change
/// included, counted `enc_vm_generation`) and seals no SETUP, so none goes
/// bare. Once released, its domain 5 keys are made under the new identity,
/// and a receiver under a new boot id binds it again: nothing of the old
/// binding, retired boot ids and tombstones included, blocks it, and the
/// old identity's controls never verify again.
#[test]
fn a_vm_generation_change_redraws_the_publication_and_it_binds_again() {
    use crate::wire_enc::vm_generation;

    let (mut sender, _): (super::super::SenderRole, super::super::ReceiverRole) =
        super::super::roles(&crate::agents::AgentConfig::default()).unwrap();
    sender.enc.publish(publication());
    let mut receiver = peer(5, 0x22, 1, &keys());
    let Ok(EncOpened::RspSetup(_, establishing)) =
        open(&mut sender.enc.publications[0], &receiver.challenge())
    else {
        panic!()
    };
    let (mut naks, _) = receiver.data_keys();
    let nak = seal_control(&mut naks, &receiver.nak());
    let later = receiver.challenge();
    let (signal, injector) = vm_generation::InjectedSignal::new();
    sender.enc.watch(VmGenerationWatch::new(Box::new(signal)));
    // A second role, the receiver's, holds the fence until it redraws.
    vm_generation::register();
    sender.on_generation_change(0);
    assert_eq!(sender.enc_identity(EndpointId(1), ALIAS), Some(IDENTITY));

    injector.change();
    sender.on_generation_change(vm_generation::POLL_INTERVAL_NS);
    assert_eq!(sender.enc_generation(), 1);
    let fresh = sender.enc_identity(EndpointId(1), ALIAS).unwrap();
    assert_eq!(
        Some(fresh.driver_id),
        vm_generation::successor(IDENTITY.driver_id, 1),
        "the id the embedded driver takes too"
    );
    assert_eq!(
        (fresh.registration_id, fresh.incarnation),
        (IDENTITY.registration_id, IDENTITY.incarnation)
    );
    let publication = &mut sender.enc.publications[0];
    assert!(publication.bound_receiver().is_none());
    assert!(publication.setup.is_none() && publication.bootstrap.is_none());
    let mut bytes = [0_u8; MAX_SEALED];
    assert_eq!(publication.seal_announce(&mut bytes, 32), None);
    assert_eq!(open(publication, &nak), Err(EncRejection::VmGeneration));
    assert_eq!(open(publication, &later), Err(EncRejection::VmGeneration));
    assert_eq!(
        publication
            .channel
            .rejections
            .get(EncRejection::VmGeneration),
        2
    );

    // The receiver's role redraws: the fence releases and the next duty
    // keys the publication under its new identity.
    vm_generation::redrawn(1);
    sender.on_generation_change(2 * vm_generation::POLL_INTERVAL_NS);
    let publication = &mut sender.enc.publications[0];
    assert!(publication.seal_announce(&mut bytes, 32).is_some());
    let session = publication.data_sealer(&establishing).unwrap();
    assert_eq!(session.context().publication, publication_of(&fresh));
    assert_ne!(session.context().publication, publication_of(&IDENTITY));
    // The old identity's controls select keys that no longer exist.
    assert!(open(publication, &later).is_err());
    assert!(open(publication, &nak).is_err());
    // A receiver under a new boot id challenges the new identity and binds.
    let mut again = fresh_peer(6, fresh);
    let Ok(EncOpened::RspSetup(_, rebound)) = open(publication, &again.challenge()) else {
        panic!()
    };
    assert!(rebound.bind);
    assert_eq!(publication.bound_receiver(), Some(again.receiver));
}

/// A receiver start that challenges the publication under `identity`.
fn fresh_peer(boot: u64, identity: Identity) -> FreshPeer {
    let receiver = ReceiverIdentity {
        receiver_boot_id: id128([boot, boot]),
        receiver_id: 66,
    };
    let files = PairwiseFiles::new(&[&pairwise(0x22)]).unwrap();
    let rsp = EncSealer::new(
        &keys(),
        Some(&files),
        KeyContext {
            domain: Domain::RspSetup,
            key_epoch: 1,
            party_epoch: 0,
            session_id: ALIAS.session_id,
            stream_id: ALIAS.stream_id,
            publication: publication_of(&identity),
            receiver: Some(receiver),
            salt: Salt::Empty,
        },
        clock,
    )
    .unwrap();
    FreshPeer {
        boot,
        identity,
        receiver,
        rsp,
    }
}

struct FreshPeer {
    boot: u64,
    identity: Identity,
    receiver: ReceiverIdentity,
    rsp: EncSealer,
}

impl FreshPeer {
    fn challenge(&mut self) -> Vec<u8> {
        let control = Control::Challenge(RspChallenge {
            alias: ALIAS,
            identity: self.identity,
            challenge: ChallengeBlock {
                receiver_boot_id: [self.boot, self.boot],
                nonce: [self.boot + 200, self.boot + 200],
            },
        });
        seal_control(&mut self.rsp, &control)
    }
}

impl Peer {
    /// The receiver's SM for this publication.
    fn sm(&self) -> Control {
        let boot = self.boot;
        Control::Status(StatusMessage {
            alias: ALIAS,
            identity: IDENTITY,
            receiver: Receiver {
                receiver_boot_id: [boot, boot],
                receiver_id: 66,
            },
            group_tag: 0,
            lanes: Lanes::new(&[LaneStatus {
                consumption: 4096,
                window: 65_536,
            }])
            .unwrap(),
        })
    }
}

/// A pairwise file of `receiver_id`.
fn pairwise_of(receiver_id: u64, fill: u8) -> KeyFile {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    file(
        format!(
            "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=1\npurpose=pairwise\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nreceiver_id={receiver_id}\npublisher_id=5\n"
        ),
        "9-1.key",
    )
}

/// Gate H3 (manifest section 7 and table 2.2; ADR-0114 section 4, "a
/// group holder cannot impersonate a named receiver", and section 7,
/// "Pairwise proof first"): another receiver holding the channel key
/// forges the bound receiver's SM and NAK. Under the bound receiver's
/// identity with its own pairwise secret the outer tag verifies and the
/// trailer refuses them (`enc_pairwise`); under its own identity, with
/// its own valid trailer, no binding names it (`enc_party`). Neither
/// changes the binding nor marks the window: the genuine receiver's SM and
/// NAK at its next sequences, below the forged ones, still open.
#[test]
fn another_receivers_forged_sm_and_nak_change_nothing_at_the_publisher() {
    let mut publication = publication();
    let mut genuine = peer(5, 0x22, 1, &keys());
    assert!(open(&mut publication, &genuine.challenge()).is_ok());
    let bound = publication.bound_receiver();
    assert_eq!(bound, Some(genuine.receiver));
    let (mut sealer, _) = genuine.data_keys();
    let (sm, nak) = (genuine.sm(), genuine.nak());
    // The bound receiver's identity, the forger's own pairwise secret.
    let theirs = PairwiseFiles::new(&[&pairwise(0x55)]).unwrap();
    let mut forged = EncSealer::new(&keys(), Some(&theirs), *sealer.context(), clock).unwrap();
    for _ in 0..4 {
        let _ = seal_control(&mut forged, &sm);
    }
    // Its own identity (receiver 67) and its own valid pairwise file.
    let other = ReceiverIdentity {
        receiver_boot_id: id128([6, 6]),
        receiver_id: 67,
    };
    let own_files = PairwiseFiles::new(&[&pairwise_of(67, 0x66)]).unwrap();
    let mut own_context = *sealer.context();
    own_context.receiver = Some(other);
    own_context.salt = Salt::Challenge {
        receiver_boot_id: other.receiver_boot_id,
        nonce: id128(genuine.nonce),
    };
    let mut own = EncSealer::new(&keys(), Some(&own_files), own_context, clock).unwrap();
    for control in [sm, nak] {
        assert_eq!(
            open(&mut publication, &seal_control(&mut forged, &control)),
            Err(EncRejection::Pairwise)
        );
        assert_eq!(
            open(&mut publication, &seal_control(&mut own, &control)),
            Err(EncRejection::Party)
        );
    }
    let rejections = publication.channel.rejections;
    assert_eq!(rejections.get(EncRejection::Pairwise), 2);
    assert_eq!(rejections.get(EncRejection::Party), 2);
    assert_eq!(rejections.total(), 4);
    assert_eq!(publication.bound_receiver(), bound, "the binding stays");
    // The genuine SM and NAK at sequences 0 and 1: the window never moved.
    for control in [sm, nak] {
        assert_eq!(
            open(&mut publication, &seal_control(&mut sealer, &control)),
            Ok(EncOpened::Receiver(control))
        );
    }
}

/// ADR-0114 "Validation", "a receiver that misses a whole epoch and
/// catches up by establishment" (section 6, "Discovery for a fresh
/// receiver"; gate H4, old epoch after a roll): the session's domain 1
/// sealer moves two epochs on, so the receiver's opener refuses its DATA
/// (`enc_epoch`). The receiver restarts and establishes afresh; the ENC
/// ANSWER states the epochs of the session it binds, and an opener started
/// at the stated pair opens that session's DATA.
#[test]
fn a_receiver_that_missed_a_whole_epoch_catches_up_by_establishment() {
    let mut publication = publication();
    let mut first = peer(5, 0x22, 1, &keys());
    let Ok(EncOpened::RspSetup(_, establishing)) = open(&mut publication, &first.challenge())
    else {
        panic!()
    };
    let mut session = publication.data_sealer(&establishing).unwrap();
    let mut stale = EncOpener::new(&keys(), None, *session.context(), clock()).unwrap();
    session.roll_now();
    session.roll_now();
    let data = |sealer: &mut EncSealer| {
        let mut bytes = vec![0_u8; MAX_SEALED];
        bytes[..4].copy_from_slice(&32_i32.to_le_bytes());
        bytes[4] = 1;
        bytes[6] = 1;
        let length = sealer.seal(&mut bytes, 32).unwrap();
        bytes.truncate(length);
        bytes
    };
    let mut rate = OpenRate::default();
    let mut out = [0_u8; MAX_PLAINTEXT];
    assert_eq!(
        stale
            .open(
                &data(&mut session),
                &mut out,
                &mut rate,
                clock(),
                |_| Ok(())
            )
            .map(|_| ()),
        Err(EncRejection::Epoch),
        "a whole epoch missed"
    );
    // A fresh establishment under a new boot id.
    let mut second = peer(6, 0x22, 1, &keys());
    let Ok(EncOpened::RspSetup(_, again)) = open(&mut publication, &second.challenge()) else {
        panic!()
    };
    assert!(again.bind);
    let mut fresh = publication.data_sealer(&again).unwrap();
    let _ = data(&mut fresh);
    let answer = SetupAnswer {
        alias: ALIAS,
        identity: IDENTITY,
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 0,
            mtu: 1408,
        },
        challenge: ChallengeBlock {
            receiver_boot_id: [6, 6],
            nonce: second.nonce,
        },
        joins: Lanes::new(&[0]).unwrap(),
    };
    let mut bytes = [0_u8; MAX_SEALED];
    let length = publication
        .seal_answer(
            answer,
            Some((fresh.context().key_epoch, fresh.context().party_epoch)),
            &mut bytes,
        )
        .unwrap();
    let opened = open_bootstrap(
        &keys(),
        None,
        None,
        &bytes[..length],
        &mut out,
        &mut rate,
        clock(),
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(opened.current_epoch);
    let Ok(EncSetup::Answer(enc)) = decode_setup(&out[..opened.frames]) else {
        panic!()
    };
    assert_eq!(
        (enc.key_epoch, enc.party_epoch),
        (fresh.context().key_epoch, fresh.context().party_epoch)
    );
    let mut stated = *fresh.context();
    (stated.key_epoch, stated.party_epoch) = (enc.key_epoch, enc.party_epoch);
    let mut caught_up = EncOpener::new(&keys(), None, stated, clock()).unwrap();
    assert!(
        caught_up
            .open(&data(&mut fresh), &mut out, &mut rate, clock(), |_| Ok(()))
            .is_ok()
    );
    let _ = &mut first;
}

fn plain_answer() -> SetupAnswer {
    SetupAnswer {
        alias: ALIAS,
        identity: IDENTITY,
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 0,
            mtu: 1408,
        },
        challenge: ChallengeBlock {
            receiver_boot_id: [5, 5],
            nonce: [7, 7],
        },
        joins: Lanes::new(&[0]).unwrap(),
    }
}

/// H8-06: while a successor file epoch only verifies (its predecessor
/// still signs), the ENC ANSWER is sealed under the signing epoch and its
/// epoch block states the domain 5 sealer's actual epoch, so body and
/// envelope agree; a session sealer at another key epoch refuses the
/// answer instead of sending one that disagrees.
#[test]
fn an_enc_answer_states_and_seals_the_signing_epoch() {
    use crate::wire_auth::SplitKeys;

    let mut publication = publication();
    publication.apply_keys(&SplitKeys {
        signing: Some(channel(1, 0x11)),
        verifying: vec![channel(1, 0x11), channel(2, 0x33), pairwise(0x22)],
        current: Some(2),
    });
    let mut bytes = [0_u8; MAX_SEALED];
    let length = publication
        .seal_answer(plain_answer(), Some((1, 4)), &mut bytes)
        .unwrap();
    let both = ChannelKeys::new(&[&channel(1, 0x11), &channel(2, 0x33)]).unwrap();
    let mut out = [0_u8; MAX_PLAINTEXT];
    let mut rate = OpenRate::default();
    let opened = open_bootstrap(
        &both,
        None,
        None,
        &bytes[..length],
        &mut out,
        &mut rate,
        clock(),
        |_, _| Ok(()),
    )
    .unwrap();
    let Ok(EncSetup::Answer(enc)) = decode_setup(&out[..opened.frames]) else {
        panic!()
    };
    assert_eq!(opened.header.key_epoch, 1, "sealed under the signing epoch");
    assert_eq!((enc.key_epoch, enc.party_epoch), (1, 4));
    assert_eq!(
        publication.seal_answer(plain_answer(), Some((2, 0)), &mut bytes),
        None,
        "never an answer whose epochs disagree"
    );
}

/// H8-07 (section 7): the retired boot ids of a file epoch are kept while
/// that epoch verifies, through the overlap, and expire in the key update
/// path once it stops verifying, so a full table takes new boot ids again.
#[test]
fn retired_boot_ids_expire_once_their_file_epoch_stops_verifying() {
    use crate::wire_auth::FixedKeys;
    use crate::wire_enc::RETIRED_BOOTS;

    let mut publication = publication();
    let receiver = |boot: u64| ReceiverIdentity {
        receiver_boot_id: id128([boot, boot]),
        receiver_id: 66,
    };
    for boot in 1..=u64::try_from(RETIRED_BOOTS).unwrap() {
        publication.retired.retire(&receiver(boot), 1).unwrap();
    }
    assert!(!publication.retired.has_room());
    publication.apply_keys(&FixedKeys {
        files: vec![channel(1, 0x11), channel(2, 0x33), pairwise(0x22)],
    });
    assert!(!publication.retired.has_room(), "kept through the overlap");
    assert!(publication.retired.contains(&receiver(1)));
    publication.apply_keys(&FixedKeys {
        files: vec![channel(2, 0x33), pairwise(0x22)],
    });
    assert!(publication.retired.has_room(), "expired with their epoch");
    assert!(!publication.retired.contains(&receiver(1)));
}

/// The view of a successor's activation at the publisher: `signing` the
/// channel epoch that signs, `verifying` the ones that verify.
fn activation(signing: u32, verifying: &[u32]) -> crate::wire_auth::SplitKeys {
    let fill = |epoch: u32| if epoch == 1 { 0x11 } else { 0x33 };
    let mut files: Vec<KeyFile> = verifying
        .iter()
        .map(|epoch| channel(*epoch, fill(*epoch)))
        .collect();
    files.push(pairwise(0x22));
    crate::wire_auth::SplitKeys {
        signing: Some(channel(signing, fill(signing))),
        verifying: files,
        current: verifying.iter().copied().max(),
    }
}

/// H8-12 (section 7, wire-key-files.md 2.3): with both channel epochs
/// loaded, an RSP_SETUP under the signing epoch binds before the
/// successor's activation (the predecessor signs, the successor verifies
/// early), as does one under the successor; at and after activation the
/// retired predecessor binds nothing and the successor binds. The answer
/// to a binding is sealed under, and states, the signing epoch.
#[test]
fn an_rsp_setup_binds_through_the_signing_epoch_around_activation() {
    for (phase, view, binds) in [
        ("before", activation(1, &[1, 2]), [true, true]),
        ("at", activation(2, &[1, 2]), [false, true]),
        ("after", activation(2, &[2]), [false, true]),
    ] {
        for (epoch, binds) in [1, 2].into_iter().zip(binds) {
            let mut publication = PublicationEnc::new(
                EndpointId(1),
                ALIAS,
                IDENTITY,
                &[&channel(1, 0x11), &channel(2, 0x33)],
                &[&pairwise(0x22)],
                clock,
            )
            .unwrap();
            publication.sign_with(1).unwrap();
            // The views come in order: the predecessor stops verifying
            // only after the successor signs.
            if phase == "after" {
                publication.apply_keys(&activation(2, &[1, 2]));
            }
            publication.apply_keys(&view);
            let both = ChannelKeys::new(&[&channel(1, 0x11), &channel(2, 0x33)]).unwrap();
            let mut receiver = peer(5, 0x22, epoch, &both);
            let opened = open(&mut publication, &receiver.challenge());
            if binds {
                assert!(
                    matches!(
                        opened,
                        Ok(EncOpened::RspSetup(_, EncEstablishing { bind: true, .. }))
                    ),
                    "{phase} activation, epoch {epoch}: {opened:?}"
                );
                let signing = if phase == "before" { 1 } else { 2 };
                let mut bytes = [0_u8; MAX_SEALED];
                let length = publication
                    .seal_answer(plain_answer(), None, &mut bytes)
                    .unwrap();
                assert_eq!(
                    crate::wire_enc::header(&bytes[..length]).unwrap().key_epoch,
                    signing,
                    "{phase}: the answer goes under the signing epoch"
                );
            } else {
                assert_eq!(opened, Err(EncRejection::Epoch), "{phase}, {epoch}");
                assert_eq!(publication.bound_receiver(), None);
            }
        }
    }
}

/// H8-05: the publication's domain 6 scratch slot, which holds the last
/// RSP_SETUP's key with its receiver's pairwise HMAC states, is erased in
/// place by a key set that rotates or retires the pairwise file; the next
/// RSP_SETUP re-keys it and still binds.
#[test]
fn the_domain_6_scratch_slot_keeps_no_retired_pairwise_key() {
    use crate::wire_auth::FixedKeys;

    let mut publication = publication();
    let mut receiver = peer(5, 0x22, 1, &keys());
    assert!(open(&mut publication, &receiver.challenge()).is_ok());
    assert_eq!(
        publication.bootstrap.as_ref().unwrap().pairwise_epochs(),
        [Some(1), None]
    );
    publication.apply_keys(&FixedKeys {
        files: vec![channel(1, 0x11), pairwise(0x22)],
    });
    assert_eq!(
        publication.bootstrap.as_ref().unwrap().pairwise_epochs(),
        [None, None],
        "erased in place"
    );
    let mut again = peer(6, 0x22, 1, &keys());
    assert!(open(&mut publication, &again.challenge()).is_ok());
}

/// H8-15 (sections 8 and 9): the publication-specific checks of a
/// receiver control run inside the domain 4 open, before its sequence is
/// marked or an epoch promoted. With the receiver's next `party_epoch`
/// (whose first accepted datagram would promote), a correctly sealed
/// two-lane SM for this one-lane publication, and a one-lane SM from a
/// source that is not a destination of the publication, are refused and
/// counted and change nothing: no epoch moves, and the very datagram from
/// the destination still opens (its sequence was never marked) and
/// promotes.
#[test]
fn a_refused_domain_4_control_marks_nothing_and_promotes_nothing() {
    let (mut sender, _): (super::super::SenderRole, super::super::ReceiverRole) =
        super::super::roles(&crate::agents::AgentConfig::default()).unwrap();
    let destination: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let stranger: SocketAddr = "10.0.0.7:5000".parse().unwrap();
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 0,
        mtu: 1408,
    };
    let (mut path, _log) =
        crate::agents::data::testing::outbound(EndpointId(1), ALIAS, destination, term, 1, false);
    path.set_destinations(
        crate::agents::data::DEFAULT_MAX_DESTINATIONS,
        &[destination],
        &[],
        Some(true),
    )
    .unwrap();
    sender.publications.push(path);
    sender.enc.publish(publication());
    let mut receiver = peer(5, 0x22, 1, &keys());
    assert!(open(&mut sender.enc.publications[0], &receiver.challenge()).is_ok());
    let (mut sealer, _) = receiver.data_keys();
    sealer.roll_now();
    let lane = LaneStatus {
        consumption: 4096,
        window: 65_536,
    };
    let mut two_lanes = receiver.sm();
    if let Control::Status(status) = &mut two_lanes {
        status.lanes = Lanes::new(&[lane, lane]).unwrap();
    }
    let two_lanes = seal_control(&mut sealer, &two_lanes);
    assert!(
        sender
            .open_sealed_from(EndpointId(1), destination, &two_lanes)
            .is_none()
    );
    let one_lane = seal_control(&mut sealer, &receiver.sm());
    assert!(
        sender
            .open_sealed_from(EndpointId(1), stranger, &one_lane)
            .is_none()
    );
    let publication = &sender.enc.publications[0];
    assert_eq!(publication.bound_epochs(), Some((1, 0)), "nothing promoted");
    assert_eq!(
        publication
            .channel
            .rejections
            .get(EncRejection::InnerRejected),
        2
    );
    assert_eq!(
        sender
            .open_sealed_from(EndpointId(1), destination, &one_lane)
            .map(|(control, _)| control),
        Some(receiver.sm()),
        "its sequence was never marked"
    );
    assert_eq!(sender.enc.publications[0].bound_epochs(), Some((1, 1)));
}

/// H8-16 (section 6b): the bound receiver's previous domain 4 key, kept
/// for the 10 s overlap after a promotion, is erased by the sender role's
/// maintenance once the overlap has passed, with no further promotion and
/// no root retired.
#[test]
fn sender_maintenance_erases_the_previous_receiver_key_after_its_overlap() {
    use crate::wire_enc::EPOCH_OVERLAP_NS;

    let (mut sender, _): (super::super::SenderRole, super::super::ReceiverRole) =
        super::super::roles(&crate::agents::AgentConfig::default()).unwrap();
    sender.enc.publish(publication());
    let mut receiver = peer(5, 0x22, 1, &keys());
    assert!(open(&mut sender.enc.publications[0], &receiver.challenge()).is_ok());
    let (mut sealer, _) = receiver.data_keys();
    sealer.roll_now();
    let nak = seal_control(&mut sealer, &receiver.nak());
    assert!(open(&mut sender.enc.publications[0], &nak).is_ok());
    assert!(sender.enc.publications[0].bound_has_previous());
    let start = clock();
    NOW.with(|now| now.set(start + EPOCH_OVERLAP_NS - 1));
    sender.on_generation_change(0);
    assert!(
        sender.enc.publications[0].bound_has_previous(),
        "within the overlap"
    );
    NOW.with(|now| now.set(start + EPOCH_OVERLAP_NS));
    sender.on_generation_change(0);
    assert!(
        !sender.enc.publications[0].bound_has_previous(),
        "erased at its end"
    );
    assert_eq!(sender.enc.publications[0].bound_epochs(), Some((1, 1)));
    NOW.with(|now| now.set(start));
}

/// H8-15 (sections 8 and 9): a NAK and an RTTM REQUEST are bound to their
/// receiver inside the domain 4 open, and an SM to the publication's
/// incarnation. Under the receiver's next `party_epoch`, a captured NAK
/// and RTTM REQUEST injected from a source no binding names, and an SM
/// naming another incarnation, are refused and change nothing: no epoch
/// moves, and the very NAK and REQUEST from the bound source still open.
#[test]
fn a_next_epoch_nak_or_rttm_from_an_unbound_source_marks_nothing() {
    use karyos_protocol::network::{Rttm, RttmKind};

    let (mut sender, _): (super::super::SenderRole, super::super::ReceiverRole) =
        super::super::roles(&crate::agents::AgentConfig::default()).unwrap();
    let destination: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let stranger: SocketAddr = "10.0.0.7:5000".parse().unwrap();
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 0,
        mtu: 1408,
    };
    let (mut path, _log) =
        crate::agents::data::testing::outbound(EndpointId(1), ALIAS, destination, term, 1, true);
    path.enable_repair(
        &crate::agents::repair::RepairConfig::default(),
        term.term_length,
        IDENTITY,
    )
    .unwrap();
    sender.publications.push(path);
    sender.enc.publish(publication());
    sender.bind(EndpointId(1), destination, &plain_answer(), None, clock());
    let mut receiver = peer(5, 0x22, 1, &keys());
    assert!(open(&mut sender.enc.publications[0], &receiver.challenge()).is_ok());
    let (mut sealer, _) = receiver.data_keys();
    sealer.roll_now();
    let rttm = Control::Rttm(Rttm {
        alias: ALIAS,
        identity: IDENTITY,
        receiver: Receiver {
            receiver_boot_id: [5, 5],
            receiver_id: 66,
        },
        probe_id: 1,
        kind: RttmKind::Request,
    });
    let mut other = receiver.sm();
    if let Control::Status(status) = &mut other {
        status.identity.incarnation = 2;
    }
    let nak = seal_control(&mut sealer, &receiver.nak());
    let request = seal_control(&mut sealer, &rttm);
    let other = seal_control(&mut sealer, &other);
    for bytes in [&nak, &request] {
        assert!(
            sender
                .open_sealed_from(EndpointId(1), stranger, bytes)
                .is_none()
        );
    }
    assert!(
        sender
            .open_sealed_from(EndpointId(1), destination, &other)
            .is_none()
    );
    let publication = &sender.enc.publications[0];
    assert_eq!(publication.bound_epochs(), Some((1, 0)), "nothing promoted");
    assert_eq!(
        publication
            .channel
            .rejections
            .get(EncRejection::InnerRejected),
        3
    );
    for (bytes, control) in [(&nak, receiver.nak()), (&request, rttm)] {
        assert_eq!(
            sender
                .open_sealed_from(EndpointId(1), destination, bytes)
                .map(|(control, _)| control),
            Some(control),
            "its sequence was never marked"
        );
    }
    assert_eq!(sender.enc.publications[0].bound_epochs(), Some((1, 1)));
}

/// H8-17 (section 7): the activation floor is the sender role's, per
/// channel key id, not the publication's. Once the successor has been seen
/// to sign, a backward clock step that selects the predecessor again and a
/// publication made again under it, as admission makes one, never let an
/// RSP_SETUP under the predecessor bind; one under the successor binds.
#[test]
fn a_recreated_publication_keeps_the_activation_floor() {
    for (epoch, binds) in [(1, false), (2, true)] {
        let (mut sender, _): (super::super::SenderRole, super::super::ReceiverRole) =
            super::super::roles(&crate::agents::AgentConfig::default()).unwrap();
        let made = |signing: u32| {
            let mut publication = PublicationEnc::new(
                EndpointId(1),
                ALIAS,
                IDENTITY,
                &[&channel(1, 0x11), &channel(2, 0x33)],
                &[&pairwise(0x22)],
                clock,
            )
            .unwrap();
            publication.sign_with(signing).unwrap();
            publication
        };
        sender.enc.publish(made(1));
        sender.enc.apply_keys(&activation(2, &[1, 2]));
        // The clock steps back; the publication is made again under the
        // predecessor's view.
        sender.enc.unpublish(EndpointId(1), ALIAS);
        sender.enc.publish(made(1));
        assert_eq!(sender.enc.activation.floor(3), Some(2));
        sender.enc.apply_keys(&activation(1, &[1, 2]));
        let both = ChannelKeys::new(&[&channel(1, 0x11), &channel(2, 0x33)]).unwrap();
        let mut receiver = peer(5, 0x22, epoch, &both);
        let opened = open(&mut sender.enc.publications[0], &receiver.challenge());
        if binds {
            assert!(
                matches!(
                    opened,
                    Ok(EncOpened::RspSetup(_, EncEstablishing { bind: true, .. }))
                ),
                "epoch {epoch}: {opened:?}"
            );
        } else {
            assert_eq!(opened, Err(EncRejection::Epoch), "epoch {epoch}");
            assert_eq!(sender.enc.publications[0].bound_receiver(), None);
        }
    }
}

/// H8-19 (section 10): a sender role registered with the fence keeps
/// maintaining once its last encrypted publication is removed. Two roles
/// watch the same VM; one removes its last publication; the change the
/// other observes is reported redrawn by both, so the fence releases.
#[test]
fn a_sender_without_publications_still_releases_the_fence() {
    use crate::wire_enc::vm_generation;

    let mut senders: Vec<super::super::SenderRole> = (0..2)
        .map(|_| {
            super::super::roles(&crate::agents::AgentConfig::default())
                .unwrap()
                .0
        })
        .collect();
    let mut injectors = Vec::new();
    for sender in &mut senders {
        sender.enc.publish(publication());
        let (signal, injector) = vm_generation::InjectedSignal::new();
        sender.enc.watch(VmGenerationWatch::new(Box::new(signal)));
        sender.on_generation_change(0);
        injectors.push(injector);
    }
    senders[0].enc.unpublish(EndpointId(1), ALIAS);
    assert!(senders[0].enc.publications.is_empty());
    // The other role observes the change first.
    injectors[1].change();
    for sender in senders.iter_mut().rev() {
        sender.on_generation_change(vm_generation::POLL_INTERVAL_NS);
    }
    let current = vm_generation::generation();
    assert!(current > 0);
    assert_eq!(senders[0].enc_generation(), current, "reported redrawn");
    assert_eq!(senders[1].enc_generation(), current);
    assert!(!vm_generation::quiesced(), "the fence released");
}
