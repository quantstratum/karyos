// SPDX-License-Identifier: Apache-2.0

//! H8 invariants of the authenticated class (karyos#648), each through
//! both network agents on loopback: the roles, rings and duties the
//! driver runs, with the bindings posted by hand rather than through
//! production admission. Each test names the invariant it proves (the
//! `INV-` id of the round 4 invariant list).

use super::*;

/// A SETUP ANNOUNCE of the rig's publication sealed in domain 5 under
/// `channel`'s SETUP proof.
fn sealed_announce(channel: &crate::wire_keys::KeyFile) -> Vec<u8> {
    use crate::wire_auth::{ENVELOPE_LEN, Proof, ProofKind};
    use karyos_protocol::network::Control;

    let proof = Proof::new(
        ProofKind::Setup,
        alias(),
        Some(channel),
        [channel],
        channel.file_epoch,
    )
    .unwrap();
    let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
    let length = Control::SetupAnnounce(announce(65_536))
        .encode(&mut bytes)
        .unwrap();
    let length = proof.seal(&mut bytes, length).unwrap();
    bytes.truncate(length);
    bytes
}

/// INV-EST-2 (ADR-0086 section 7a, open point 12): on an authenticated
/// subscription a SETUP ANNOUNCE takes a challenge entry only after it
/// verifies under the SETUP proof key. One sealed under another secret of
/// the same `key_id` is refused, counted, creates no challenge and sends
/// nothing; the genuine one then challenges (the test is not vacuous).
#[test]
fn inv_a_forged_setup_announce_takes_no_challenge() {
    let (mut rig, b, channel) = authenticated_rig();
    // Only the receiver runs: its subscription is in place, and no genuine
    // ANNOUNCE is sent.
    rig.sender_stopped = true;
    rig.round(true);
    let mut forged = auth_keys(77).0;
    if let crate::wire_keys::Material::Secret(secret) = &mut forged.material {
        secret[0] ^= 0xff;
    }
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let sessions = rig.agents.receiver.role.session_counters();
    let before = rig.agents.receiver.counters();
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_datagram(
        &receiver.sessions,
        b,
        source,
        &sealed_announce(&forged),
        rig.now,
    );
    only_changed(
        before,
        rig.agents.receiver.counters(),
        |c| &mut c.auth_rejected,
        1,
    );
    assert_eq!(
        rig.agents.receiver.role.session_counters(),
        sessions,
        "no challenge entry"
    );
    assert!(
        rig.agents.sender.role.take_control().is_none(),
        "no CHALLENGE"
    );
    let receiver = &mut rig.agents.receiver;
    receiver.role.inject_datagram(
        &receiver.sessions,
        b,
        source,
        &sealed_announce(&channel),
        rig.now,
    );
    assert_ne!(
        rig.agents.receiver.role.session_counters(),
        sessions,
        "the genuine ANNOUNCE takes an entry"
    );
}

/// INV-EST-3 (ADR-0086 section 7, domains 5 and 6): a SETUP ANSWER binds
/// only to the receiver's current challenge entry. An ANSWER that verifies
/// under the channel's SETUP proof but names a nonce the receiver never
/// issued (a replayed ANSWER of an earlier challenge) installs no image
/// and binds no path.
#[test]
fn inv_a_stale_authenticated_answer_installs_nothing() {
    use crate::wire_auth::{ENVELOPE_LEN, Proof, ProofKind};
    use karyos_protocol::network::{ChallengeBlock, Control, SetupAnswer};

    let (mut rig, b, channel) = authenticated_rig();
    rig.sender_stopped = true;
    rig.round(true);
    let boot = rig.agents.receiver.role.boot_id();
    let answer = Control::SetupAnswer(SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: term(65_536),
        challenge: ChallengeBlock {
            receiver_boot_id: boot,
            nonce: [0x5eed, 0xf00d],
        },
        joins: Lanes::new(&[0, 0]).unwrap(),
    });
    let proof = Proof::new(
        ProofKind::Setup,
        alias(),
        Some(&channel),
        [&channel],
        channel.file_epoch,
    )
    .unwrap();
    let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
    let length = answer.encode(&mut bytes).unwrap();
    let length = proof.seal(&mut bytes, length).unwrap();
    bytes.truncate(length);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let before = rig.agents.receiver.counters();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &bytes, rig.now);
    for _ in 0..50 {
        rig.round(true);
    }
    let after = rig.agents.receiver.counters();
    assert_eq!(after.auth_rejected, before.auth_rejected, "it verified");
    assert_eq!(after.paths_bound, before.paths_bound, "{after:?}");
    assert_eq!(rig.agents.receiver.role.auth_state().1, 0, "no image");
    assert!(
        rig.events
            .iter()
            .all(|event| !matches!(event, ImageEvent::Installed { .. })),
        "{:?}",
        rig.events
    );
}

/// INV-KEY-6 (ADR-0086 sections 2 and 7a; H8 finding 4): once the channel
/// signing key is withdrawn (revoked, expired, or the store disabled), an
/// authenticated publication announces nothing at all: its SETUP proof
/// cannot seal, and nothing falls back to a bare ANNOUNCE. No image is
/// installed.
#[test]
fn inv_a_withdrawn_channel_key_never_announces_bare() {
    let (mut rig, _b, _channel) = authenticated_rig();
    rig.agents
        .sender
        .role
        .apply_keys(&crate::wire_auth::FixedKeys::default());
    for _ in 0..300 {
        rig.round(true);
    }
    let receiver = rig.agents.receiver.counters();
    let sender = rig.agents.sender.role.counters();
    assert_eq!(receiver.auth_bare, 0, "nothing bare arrived: {receiver:?}");
    assert!(sender.seal_failures > 0, "it tried, sealed: {sender:?}");
    assert_eq!(rig.agents.receiver.role.auth_state().1, 0, "no image");
    assert_eq!(
        rig.agents.sender.role.auth_state().1,
        0,
        "no session sealer"
    );
}

/// INV-KEY-7 (ADR-0086 section 7a, open point 11): RSP_SETUP is always
/// authenticated on an authenticated channel. With its pairwise signing
/// key withdrawn (the channel key still valid, so the ANNOUNCE verifies),
/// the subscription's CHALLENGE cannot seal and is never sent bare: the
/// publisher sees no bare RSP_SETUP and binds nothing.
#[test]
fn inv_a_withdrawn_pairwise_key_never_challenges_bare() {
    let (mut rig, _b, channel) = authenticated_rig();
    rig.agents
        .receiver
        .role
        .apply_keys(&crate::wire_auth::FixedKeys {
            files: vec![channel],
        });
    for _ in 0..300 {
        rig.round(true);
    }
    let sender = rig.agents.sender.role.counters();
    assert_eq!(sender.auth_bare, 0, "no bare RSP_SETUP: {sender:?}");
    assert!(
        sender.seal_failures > 0,
        "the CHALLENGE was tried and failed to seal: {sender:?}"
    );
    assert_eq!(rig.agents.sender.role.auth_state().1, 0, "nothing bound");
    assert_eq!(rig.agents.receiver.role.auth_state().1, 0, "no image");
}

/// INV-ADM-9 (ADR-0086 section 7a; the comment at the ANNOUNCE loop:
/// "sealed now (domain 5) or not at all"): a publication whose outbound
/// requires authentication sends no bare SETUP even when the sender role
/// holds no key binding for it. Here the binding never reached the sender
/// (as it would not after a lost or refused `Authenticate`): every
/// ANNOUNCE must be held back, never sent bare.
#[test]
#[ignore = "H8 invariant: an auth-required outbound without its sender binding announces bare, fix pending"]
fn inv_an_auth_required_publication_without_its_binding_sends_nothing_bare() {
    use crate::agents::roles::receive_auth::SubscriptionAuth;

    let (mut rig, b) = Rig::new(Setup {
        auth: true,
        reliable: true,
        identity: Some(identity_77(0)),
        ..Setup::default()
    });
    let (channel, pairwise) = auth_keys(77);
    let a = rig.publisher;
    rig.agents.receiver.role.authenticate_published(a, alias());
    rig.agents.receiver.role.authenticate_subscription(
        SubscriptionAuth::new(b, alias(), &channel, &pairwise, 77).unwrap(),
    );
    for _ in 0..300 {
        rig.round(true);
    }
    let receiver = rig.agents.receiver.counters();
    assert_eq!(
        receiver.auth_bare, 0,
        "a bare ANNOUNCE of an authenticated publication arrived: {receiver:?}"
    );
}

/// INV-ABT-6 (H8 finding 2; ADR-0086 section 6): an applied abort makes
/// the image terminal to every sender datagram, heartbeats included: a
/// valid heartbeat envelope opened under the image's key after the abort
/// moves nothing (no liveness, no terminal bound) and is counted.
#[test]
fn inv_a_sealed_heartbeat_after_an_abort_moves_nothing() {
    use crate::authority::Ed25519Signer;
    use crate::signed_control::Authority;
    use crate::wire_auth::Sealer;
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let (mut rig, b) = Rig::new(Setup {
        reliable: true,
        ..Setup::default()
    });
    let slot = established(&mut rig);
    rig.sender_stopped = true;
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let receiver_id = rig.agents.receiver.role.receiver_of(slot).receiver_id;
    let (channel, pairwise) = auth_keys(receiver_id);
    rig.agents.receiver.role.trust_authorities(
        vec![Authority::of(
            10,
            Ed25519Signer::from_seed(&[9; 32]).verifier(),
            10,
            &[11],
            true,
        )],
        rig.now,
    );
    rig.agents.receiver.role.permit_abort(
        b,
        alias().stream_id,
        crate::agents::roles::AbortScope {
            authority_id: 10,
            guard_id: 11,
        },
    );
    let (sender, _) = rig
        .agents
        .receiver
        .role
        .authenticate_image(slot, &channel, &pairwise, auth_wall)
        .unwrap();
    let mut sealer = Sealer::new(&channel, sender, alias()).unwrap();
    let heartbeat = sealed(&mut sealer, &eos_heartbeat(0, 0));
    let inject = |rig: &mut Rig, bytes: &[u8]| {
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, bytes, rig.now);
        rig.agents.receiver.counters()
    };
    let after = inject(&mut rig, &signed_abort(10, 11, GUARD_CLOSED));
    assert_eq!(after.abort_acks_sent, 1, "{after:?}");
    let before = after;
    let after = inject(&mut rig, &heartbeat);
    assert_eq!(after.data_after_abort, before.data_after_abort + 1);
    assert_eq!(
        (after.eos_bounds, after.data_committed, after.auth_rejected),
        (
            before.eos_bounds,
            before.data_committed,
            before.auth_rejected
        ),
        "{after:?}"
    );
}

/// INV-ABT-7 (ADR-0086 sections 6 and 7, domain 3): an abort applies at
/// most once per incarnation. After the guarding authority's abort is
/// applied, a second, different SESSION_ABORT of the same incarnation (a
/// digest cache miss) changes nothing: no second close, no second ACK.
#[test]
fn inv_a_second_abort_of_an_aborted_incarnation_changes_nothing() {
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let scope = crate::agents::roles::AbortScope {
        authority_id: 10,
        guard_id: 11,
    };
    let (mut rig, b, _slot) = abort_rig(Some(scope));
    let first = inject_abort(&mut rig, b, &signed_abort(10, 11, GUARD_CLOSED));
    assert_eq!(first.abort_acks_sent, 1, "{first:?}");
    let after = inject_abort(&mut rig, b, &signed_abort(10, 0, 2));
    assert_eq!(
        (
            after.abort_acks_sent,
            after.abort_acks_resent,
            after.images_closed_aborted
        ),
        (
            first.abort_acks_sent,
            first.abort_acks_resent,
            first.images_closed_aborted.max(1)
        ),
        "{after:?}"
    );
    assert_eq!(after.aborts_refused, first.aborts_refused + 1, "{after:?}");
}

/// INV-RST-1 (ADR-0086 section 7, "Snapshot rollback and clones"): every
/// start of the receive side draws a fresh, nonzero `receiver_boot_id`, so
/// no domain 4 key or window of an earlier start is reused.
#[test]
fn inv_each_start_draws_a_fresh_receiver_boot_id() {
    let (first, _) = Rig::new(Setup::default());
    let (second, _) = Rig::new(Setup::default());
    let (one, two) = (
        first.agents.receiver.role.boot_id(),
        second.agents.receiver.role.boot_id(),
    );
    assert_ne!(one, [0, 0]);
    assert_ne!(two, [0, 0]);
    assert_ne!(one, two, "a fresh boot id per start");
}
