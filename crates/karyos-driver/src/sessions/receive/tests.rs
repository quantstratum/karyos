// SPDX-License-Identifier: Apache-2.0

//! The receive session table (network-sessions.md "Fresh establishment",
//! S1, S5): challenge lifecycle, answers, installation, bound keys,
//! retirement and quarantine, capacity and timers.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_protocol::network::{Lanes, SetupAnnounce, SetupAnswer};

use super::*;

const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000 * MS;
const BOOT: [u64; 2] = [7, 8];

/// Nonces 1, 2, 3, ...; `fail` makes the next draw fail.
#[derive(Default)]
struct Counter {
    next: u64,
    fail: bool,
}

impl NonceSource for Counter {
    fn nonce(&mut self) -> Option<[u64; 2]> {
        if std::mem::take(&mut self.fail) {
            return None;
        }
        self.next += 1;
        Some([self.next, 0])
    }
}

fn key(port: u16) -> BindingKey {
    BindingKey {
        endpoint: EndpointId(1),
        source: SocketAddr::from(([10, 0, 0, 1], port)),
        alias: Alias {
            session_id: 5,
            stream_id: 6,
        },
    }
}

fn identity(incarnation: u64) -> Identity {
    Identity {
        driver_id: [1, 2],
        registration_id: 3,
        incarnation,
    }
}

fn term() -> TermParams {
    TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    }
}

fn announce(incarnation: u64) -> SetupAnnounce {
    SetupAnnounce {
        alias: key(1).alias,
        identity: identity(incarnation),
        term: term(),
        lane_count: 2,
    }
}

fn answer(incarnation: u64, nonce: [u64; 2]) -> SetupAnswer {
    SetupAnswer {
        alias: key(1).alias,
        identity: identity(incarnation),
        term: term(),
        challenge: ChallengeBlock {
            receiver_boot_id: BOOT,
            nonce,
        },
        joins: Lanes::new(&[0, 0]).unwrap(),
    }
}

fn table(config: SessionConfig) -> ReceiveSessions {
    ReceiveSessions::new(config, BOOT).unwrap()
}

fn challenged(outcome: AnnounceOutcome) -> RspChallenge {
    match outcome {
        AnnounceOutcome::Challenge(challenge) => challenge,
        AnnounceOutcome::Dropped(reason) => panic!("dropped: {reason:?}"),
    }
}

fn accepted(outcome: AnswerOutcome) -> SlotRef {
    match outcome {
        AnswerOutcome::CreateImage { slot, .. } => slot,
        AnswerOutcome::PathBound { .. } => panic!("bound as a path"),
        AnswerOutcome::Dropped(reason) => panic!("dropped: {reason:?}"),
    }
}

/// The happy path: announce, challenge, answer, `ImageReady`, bound.
#[test]
fn an_answered_challenge_installs_one_image() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let challenge = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces));
    assert_eq!(challenge.challenge.receiver_boot_id, BOOT);
    assert_eq!(challenge.identity, identity(1));
    let pending = accepted(sessions.answer(
        key(1),
        &answer(1, challenge.challenge.nonce),
        10 * MS,
        || true,
    ));
    assert_eq!(
        sessions.lookup(&key(1)),
        None,
        "not bound before installation"
    );
    let ReadyOutcome::Installed(slot) = sessions.image_ready(pending, 20 * MS) else {
        panic!("not installed");
    };
    assert_eq!(
        slot.generation,
        pending.generation + 1,
        "the generation moved"
    );
    assert_eq!(sessions.lookup(&key(1)), Some(slot));
    assert!(sessions.is_active(slot));
    assert!(!sessions.is_active(pending), "the old reference is stale");
    assert_eq!(sessions.counters().installed, 1);
}

/// An identical announcement resends the same challenge without extending
/// its expiry; another one, or one after expiry, replaces it, and the old
/// nonce no longer answers.
#[test]
fn a_challenge_is_resent_replaced_and_expires() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let first = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces));
    let again = challenged(sessions.announce(key(1), &announce(1), 900 * MS, &mut nonces));
    assert_eq!(first, again, "resent, same nonce");
    assert_eq!(sessions.counters().challenge_resends, 1);
    // The resend did not extend the expiry.
    assert_eq!(
        sessions.answer(key(1), &answer(1, first.challenge.nonce), SECOND, || true),
        AnswerOutcome::Dropped(Ignored::Expired)
    );
    // After expiry, the identical announcement gets a fresh challenge.
    let fresh = challenged(sessions.announce(key(1), &announce(1), SECOND, &mut nonces));
    assert_ne!(fresh.challenge.nonce, first.challenge.nonce);
    // Another identity replaces it too; the replaced nonce is dead.
    let other = challenged(sessions.announce(key(1), &announce(2), SECOND + MS, &mut nonces));
    assert_eq!(
        sessions.answer(
            key(1),
            &answer(2, fresh.challenge.nonce),
            SECOND + 2 * MS,
            || true
        ),
        AnswerOutcome::Dropped(Ignored::Mismatch)
    );
    accepted(sessions.answer(
        key(1),
        &answer(2, other.challenge.nonce),
        SECOND + 3 * MS,
        || true,
    ));
}

/// Every field of the answer must match: identity, term parameters, lane
/// count, boot id, nonce and key.
#[test]
fn a_mismatched_answer_is_dropped() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let challenge = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces));
    let nonce = challenge.challenge.nonce;
    let mut wrong_term = answer(1, nonce);
    wrong_term.term.mtu = 1400;
    let mut wrong_lanes = answer(1, nonce);
    wrong_lanes.joins = Lanes::new(&[0]).unwrap();
    let mut wrong_boot = answer(1, nonce);
    wrong_boot.challenge.receiver_boot_id = [9, 9];
    for wrong in [
        answer(2, nonce),
        answer(1, [99, 0]),
        wrong_term,
        wrong_lanes,
        wrong_boot,
    ] {
        assert_eq!(
            sessions.answer(key(1), &wrong, MS, || true),
            AnswerOutcome::Dropped(Ignored::Mismatch)
        );
    }
    assert_eq!(
        sessions.answer(key(2), &answer(1, nonce), MS, || true),
        AnswerOutcome::Dropped(Ignored::NoChallenge),
        "another source key"
    );
    accepted(sessions.answer(key(1), &answer(1, nonce), MS, || true));
}

/// The command chain is reserved only for a valid answer; without credit
/// the challenge stays pending. A consumed challenge cannot answer twice.
#[test]
fn an_answer_needs_the_command_chain_and_counts_once() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let nonce = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces))
        .challenge
        .nonce;
    let mut reserved = 0;
    assert_eq!(
        sessions.answer(key(1), &answer(2, nonce), MS, || {
            reserved += 1;
            true
        }),
        AnswerOutcome::Dropped(Ignored::Mismatch)
    );
    assert_eq!(reserved, 0, "no reservation for an invalid answer");
    assert_eq!(
        sessions.answer(key(1), &answer(1, nonce), MS, || false),
        AnswerOutcome::Dropped(Ignored::NoCommandCredit)
    );
    let pending = accepted(sessions.answer(key(1), &answer(1, nonce), 2 * MS, || true));
    assert_eq!(
        sessions.answer(key(1), &answer(1, nonce), 3 * MS, || true),
        AnswerOutcome::Dropped(Ignored::AlreadyAnswered)
    );
    // An identical announcement resends; a different one waits for the
    // conductor.
    challenged(sessions.announce(key(1), &announce(1), 60 * MS, &mut nonces));
    assert_eq!(
        sessions.announce(key(1), &announce(2), 61 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::AwaitingInstallation)
    );
    // An answered challenge survives the timers past its expiry, until
    // the conductor replies; a late `ImageReady` releases it.
    assert_eq!(sessions.timers(2 * SECOND), 0);
    assert_eq!(
        sessions.image_ready(pending, 2 * SECOND),
        ReadyOutcome::Release(pending)
    );
    assert_eq!(sessions.lookup(&key(1)), None);
}

/// `ImageRefused` removes the challenge and its token.
#[test]
fn a_refused_image_removes_the_challenge() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let nonce = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces))
        .challenge
        .nonce;
    let pending = accepted(sessions.answer(key(1), &answer(1, nonce), MS, || true));
    sessions.image_refused(pending);
    assert_eq!(
        sessions.answer(key(1), &answer(1, nonce), 2 * MS, || true),
        AnswerOutcome::Dropped(Ignored::NoChallenge)
    );
    assert_eq!(
        sessions.image_ready(pending, 3 * MS),
        ReadyOutcome::Release(pending)
    );
}

/// A bound key ignores SETUP for its identity and rejects another identity;
/// neither creates a challenge.
#[test]
fn a_bound_key_ignores_and_rejects_setups() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let nonce = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces))
        .challenge
        .nonce;
    let pending = accepted(sessions.answer(key(1), &answer(1, nonce), MS, || true));
    sessions.image_ready(pending, 2 * MS);
    assert_eq!(
        sessions.announce(key(1), &announce(1), 3 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::BoundSameIdentity)
    );
    assert_eq!(
        sessions.announce(key(1), &announce(2), 3 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::BoundOtherIdentity)
    );
    assert_eq!(sessions.counters().challenges, 1);
}

/// Retirement unbinds at once; the identity is quarantined for
/// `alias_quarantine`, under any alias; the slot stays charged until both
/// the quarantine passed and the storage was reclaimed.
#[test]
fn a_retired_identity_is_quarantined() {
    let config = SessionConfig {
        max_images: 1,
        max_pending_challenges: 1,
        max_pending_per_source: 1,
        ..SessionConfig::default()
    };
    let mut sessions = table(config);
    let mut nonces = Counter::default();
    let nonce = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces))
        .challenge
        .nonce;
    let pending = accepted(sessions.answer(key(1), &answer(1, nonce), MS, || true));
    let ReadyOutcome::Installed(slot) = sessions.image_ready(pending, 2 * MS) else {
        panic!("not installed");
    };
    assert!(sessions.retire(slot, SECOND));
    assert_eq!(sessions.lookup(&key(1)), None);
    // The same identity from another source key, during the quarantine.
    assert_eq!(
        sessions.announce(key(2), &announce(1), 2 * SECOND, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::Quarantined)
    );
    // Another identity: the only slot is still charged by the tombstone.
    assert_eq!(
        sessions.announce(key(2), &announce(2), 2 * SECOND, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::TableFull)
    );
    // The quarantine passes, but the storage is not reclaimed yet.
    assert_eq!(sessions.timers(12 * SECOND), 0);
    sessions.storage_reclaimed(slot);
    assert_eq!(sessions.timers(12 * SECOND), 1);
    challenged(sessions.announce(key(2), &announce(1), 12 * SECOND, &mut nonces));
}

/// Pending challenges are bounded globally and per source address; the
/// table is swept for expired challenges before an announcement is
/// refused.
#[test]
fn pending_challenges_are_bounded() {
    let config = SessionConfig {
        max_images: 8,
        max_pending_challenges: 3,
        max_pending_per_source: 2,
        ..SessionConfig::default()
    };
    let mut sessions = table(config);
    let mut nonces = Counter::default();
    let from = |ip: u8, port: u16| BindingKey {
        source: SocketAddr::from(([10, 0, 0, ip], port)),
        ..key(port)
    };
    challenged(sessions.announce(from(1, 1), &announce(1), 0, &mut nonces));
    challenged(sessions.announce(from(1, 2), &announce(2), 0, &mut nonces));
    assert_eq!(
        sessions.announce(from(1, 3), &announce(3), 0, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::ChallengeCapacity),
        "per source"
    );
    challenged(sessions.announce(from(2, 3), &announce(3), 0, &mut nonces));
    assert_eq!(
        sessions.announce(from(3, 4), &announce(4), 0, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::ChallengeCapacity),
        "global"
    );
    // After the timeout, the expired challenges make room without a timer.
    challenged(sessions.announce(from(3, 4), &announce(4), SECOND, &mut nonces));
    assert_eq!(sessions.counters().challenges_expired, 3);
}

/// Timers free expired challenges up to their budget, never an answered
/// one.
#[test]
fn timers_respect_their_budget() {
    let config = SessionConfig {
        timer_actions: 2,
        ..SessionConfig::default()
    };
    let mut sessions = table(config);
    let mut nonces = Counter::default();
    for port in 1..=3 {
        let mut ann = announce(u64::from(port));
        ann.alias.session_id = i32::from(port);
        let mut key = key(port);
        key.alias.session_id = i32::from(port);
        key.source = SocketAddr::from(([10, 0, 0, u8::try_from(port).unwrap()], port));
        challenged(sessions.announce(key, &ann, 0, &mut nonces));
    }
    assert_eq!(sessions.timers(SECOND - 1), 0);
    assert_eq!(sessions.timers(SECOND), 2);
    assert_eq!(sessions.timers(SECOND), 1);
}

/// A failed nonce draw drops the announcement and creates nothing.
#[test]
fn no_nonce_no_challenge() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter {
        fail: true,
        ..Counter::default()
    };
    assert_eq!(
        sessions.announce(key(1), &announce(1), 0, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::NoNonce)
    );
    challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces));
}

/// An exhausted slot generation retires the slot for good.
#[test]
fn an_exhausted_generation_retires_the_slot() {
    let config = SessionConfig {
        max_images: 1,
        max_pending_challenges: 1,
        max_pending_per_source: 1,
        ..SessionConfig::default()
    };
    let mut sessions = table(config);
    sessions.slots[0].generation = u32::MAX;
    let mut nonces = Counter::default();
    let nonce = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces))
        .challenge
        .nonce;
    let pending = accepted(sessions.answer(key(1), &answer(1, nonce), MS, || true));
    assert_eq!(
        sessions.image_ready(pending, 2 * MS),
        ReadyOutcome::Release(pending)
    );
    assert_eq!(sessions.counters().slots_exhausted, 1);
    assert_eq!(
        sessions.announce(key(2), &announce(2), 3 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::TableFull)
    );
}

/// S5 relations are validated, and the boot id is not zero.
#[test]
fn the_configuration_is_checked() {
    for config in [
        SessionConfig {
            max_images: 0,
            ..SessionConfig::default()
        },
        SessionConfig {
            max_pending_challenges: 65,
            ..SessionConfig::default()
        },
        SessionConfig {
            max_pending_per_source: 17,
            ..SessionConfig::default()
        },
        SessionConfig {
            setup_challenge_timeout: 0,
            ..SessionConfig::default()
        },
        SessionConfig {
            timer_actions: 0,
            ..SessionConfig::default()
        },
    ] {
        assert!(ReceiveSessions::new(config, BOOT).is_err());
    }
    assert!(ReceiveSessions::new(SessionConfig::default(), [0, 0]).is_err());
}

/// Puts a challenge for `identity(incarnation)` under `key` straight into
/// a free slot, as a race that passed the announcement checks would.
fn inject(
    sessions: &mut ReceiveSessions,
    key: BindingKey,
    incarnation: u64,
    nonce: [u64; 2],
    answered: bool,
) -> SlotRef {
    let index = sessions
        .slots
        .iter()
        .position(|slot| slot.state == State::Free)
        .unwrap();
    let slot = &mut sessions.slots[index];
    slot.state = State::Challenged {
        key,
        identity: identity(incarnation),
        term: term(),
        lane_count: 2,
        nonce,
        created_at: 0,
        last_sent: 0,
        answered,
        path_of: None,
        joins: answered.then(|| Lanes::new(&[0, 0]).unwrap()),
    };
    SlotRef {
        slot: u32::try_from(index).unwrap(),
        generation: slot.generation,
    }
}

fn other_key() -> BindingKey {
    BindingKey {
        alias: Alias {
            session_id: 50,
            stream_id: 6,
        },
        ..key(2)
    }
}

/// Installs `identity(1)` on `key(1)`.
fn install_on_key_one(sessions: &mut ReceiveSessions, nonces: &mut Counter) -> SlotRef {
    let nonce = challenged(sessions.announce(key(1), &announce(1), 0, nonces))
        .challenge
        .nonce;
    let pending = accepted(sessions.answer(key(1), &answer(1, nonce), MS, || true));
    let ReadyOutcome::Installed(bound) = sessions.image_ready(pending, MS) else {
        panic!("not installed");
    };
    bound
}

/// Review P1 scenario A: X is active on K1; a delayed SETUP for X under K2
/// is refused at the announcement. A K2 challenge that got in before (a
/// race) still cannot install X: after K1 retires, the answer and
/// `ImageReady` both see the quarantine.
#[test]
fn an_old_challenge_cannot_bypass_the_quarantine() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let bound = install_on_key_one(&mut sessions, &mut nonces);
    let other_announce = SetupAnnounce {
        alias: other_key().alias,
        ..announce(1)
    };
    assert_eq!(
        sessions.announce(other_key(), &other_announce, 2 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::DuplicateIdentity)
    );
    inject(&mut sessions, other_key(), 1, [77, 0], false);
    sessions.retire(bound, 3 * MS);
    let late_answer = SetupAnswer {
        alias: other_key().alias,
        ..answer(1, [77, 0])
    };
    assert_eq!(
        sessions.answer(other_key(), &late_answer, 4 * MS, || true),
        AnswerOutcome::Dropped(Ignored::Quarantined)
    );
    // Answered before the retirement, installed after it: released.
    let answered = inject(&mut sessions, key(3), 1, [78, 0], true);
    assert_eq!(
        sessions.image_ready(answered, 5 * MS),
        ReadyOutcome::Release(answered)
    );
    assert_eq!(sessions.counters().installed, 1);
}

/// Review P1 scenario B: one identity from two source ports installs one
/// image. The second key is refused at the announcement; a raced challenge
/// is refused at the answer and at `ImageReady`.
#[test]
fn one_identity_installs_one_image() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces));
    assert_eq!(
        sessions.announce(key(2), &announce(1), 0, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::DuplicateIdentity)
    );

    let mut sessions = table(SessionConfig::default());
    install_on_key_one(&mut sessions, &mut nonces);
    inject(&mut sessions, key(2), 1, [79, 0], false);
    let raced_answer = SetupAnswer {
        alias: key(2).alias,
        ..answer(1, [79, 0])
    };
    assert_eq!(
        sessions.answer(key(2), &raced_answer, 2 * MS, || true),
        AnswerOutcome::Dropped(Ignored::DuplicateIdentity)
    );
    let answered = inject(&mut sessions, key(3), 1, [80, 0], true);
    assert_eq!(
        sessions.image_ready(answered, 3 * MS),
        ReadyOutcome::Release(answered)
    );
    assert_eq!(sessions.counters().installed, 1);
}

/// The per-source bound counts an IPv4-mapped IPv6 source as its IPv4
/// address.
#[test]
fn ipv4_mapped_sources_share_a_budget() {
    let config = SessionConfig {
        max_pending_per_source: 1,
        ..SessionConfig::default()
    };
    let mut sessions = table(config);
    let mut nonces = Counter::default();
    challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces));
    let mapped = BindingKey {
        source: "[::ffff:10.0.0.1]:2".parse().unwrap(),
        ..key(2)
    };
    assert_eq!(
        sessions.announce(mapped, &announce(2), 0, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::ChallengeCapacity)
    );
}

/// A control whose alias differs from its key's is dropped.
#[test]
fn an_alias_mismatch_is_dropped() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let mut wrong = announce(1);
    wrong.alias.session_id = 99;
    assert_eq!(
        sessions.announce(key(1), &wrong, 0, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::AliasMismatch)
    );
    let nonce = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces))
        .challenge
        .nonce;
    let mut wrong = answer(1, nonce);
    wrong.alias.session_id = 99;
    assert_eq!(
        sessions.answer(key(1), &wrong, MS, || true),
        AnswerOutcome::Dropped(Ignored::AliasMismatch)
    );
}

/// Conductor replies carry the installed generation; one for the
/// challenge's generation is ignored and counted.
#[test]
fn a_stale_reclaim_is_counted() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let nonce = challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces))
        .challenge
        .nonce;
    let pending = accepted(sessions.answer(key(1), &answer(1, nonce), MS, || true));
    let ReadyOutcome::Installed(slot) = sessions.image_ready(pending, MS) else {
        panic!("not installed");
    };
    sessions.retire(slot, MS);
    sessions.storage_reclaimed(pending);
    assert_eq!(sessions.counters().stale_commands, 1);
    sessions.storage_reclaimed(slot);
    assert_eq!(sessions.timers(20 * SECOND), 1);
}

/// Review of #235, P1-3: identical announcements resend the challenge at
/// most once per `challenge_resend_interval` (50 ms).
#[test]
fn resends_are_held_off() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces));
    let mut sent = 0;
    for step in 1..=200u64 {
        // 200 identical announcements within 25 ms.
        if let AnnounceOutcome::Challenge(_) =
            sessions.announce(key(1), &announce(1), step * 125_000, &mut nonces)
        {
            sent += 1;
        }
    }
    assert_eq!(sent, 0);
    challenged(sessions.announce(key(1), &announce(1), 50 * MS, &mut nonces));
    assert_eq!(
        sessions.announce(key(1), &announce(1), 60 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::ResendHoldoff)
    );
}

/// RP-1, hooks 2 and 3: a later path of an active image (another source,
/// the image's alias, term parameters and lane count) gets a path
/// challenge; its answer binds the path, creates no image and reserves no
/// conductor chain. The first path was bound at installation, and
/// retirement clears both.
#[test]
fn a_later_path_binds_without_an_image() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let image = install_on_key_one(&mut sessions, &mut nonces);
    assert_eq!(sessions.paths().live(image), 1);
    assert_eq!(sessions.paths().lookup(key(1)), Some((image, 0)));
    assert_eq!(sessions.counters().path_bind_failed, 0);
    let nonce = challenged(sessions.announce(key(2), &announce(1), 2 * MS, &mut nonces))
        .challenge
        .nonce;
    let mut reserved = false;
    assert_eq!(
        sessions.answer(key(2), &answer(1, nonce), 3 * MS, || {
            reserved = true;
            true
        }),
        AnswerOutcome::PathBound { image, path: 1 }
    );
    assert!(!reserved, "a path reserves no chain");
    assert_eq!(sessions.paths().live(image), 2);
    assert_eq!(sessions.paths().lookup(key(2)), Some((image, 1)));
    assert_eq!(sessions.counters().installed, 1);
    assert_eq!(sessions.counters().paths_bound, 1);
    // The bound path's key announcing again: bound, as for the first path.
    assert_eq!(
        sessions.announce(key(2), &announce(1), 4 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::BoundSameIdentity)
    );
    assert!(sessions.retire(image, 5 * MS));
    assert_eq!(sessions.paths().live(image), 0);
    assert_eq!(sessions.paths().lookup(key(2)), None);
}

/// Hook 1 keeps every refusal it had (ACS 15540): an identity challenged
/// or answered under another key is refused as before; so are another
/// identity on a bound path's key, an active identity with other term
/// parameters or lane count, and a full image.
#[test]
fn a_later_path_keeps_the_refusals() {
    let mut nonces = Counter::default();
    // Challenged elsewhere.
    let mut sessions = table(SessionConfig::default());
    challenged(sessions.announce(key(1), &announce(1), 0, &mut nonces));
    assert_eq!(
        sessions.announce(key(2), &announce(1), 0, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::DuplicateIdentity)
    );
    // Answered elsewhere.
    let mut sessions = table(SessionConfig::default());
    inject(&mut sessions, key(1), 1, [90, 0], true);
    assert_eq!(
        sessions.announce(key(2), &announce(1), 0, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::DuplicateIdentity)
    );
    // Another identity on a bound path's key.
    let mut sessions = table(SessionConfig::default());
    let image = install_on_key_one(&mut sessions, &mut nonces);
    let nonce = challenged(sessions.announce(key(2), &announce(1), 2 * MS, &mut nonces))
        .challenge
        .nonce;
    assert_eq!(
        sessions.answer(key(2), &answer(1, nonce), 3 * MS, || true),
        AnswerOutcome::PathBound { image, path: 1 }
    );
    assert_eq!(
        sessions.announce(key(2), &announce(2), 4 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::BoundOtherIdentity)
    );
    // Other term parameters, or another lane count, for the active image.
    let other_term = SetupAnnounce {
        term: TermParams {
            mtu: 1200,
            ..term()
        },
        ..announce(1)
    };
    let other_lanes = SetupAnnounce {
        lane_count: 1,
        ..announce(1)
    };
    for other in [other_term, other_lanes] {
        assert_eq!(
            sessions.announce(key(3), &other, 5 * MS, &mut nonces),
            AnnounceOutcome::Dropped(Ignored::DuplicateIdentity)
        );
    }
    // A full image: `max_paths` 2, both bound.
    let mut sessions = table(SessionConfig {
        max_paths: 2,
        ..SessionConfig::default()
    });
    let image = install_on_key_one(&mut sessions, &mut nonces);
    let nonce = challenged(sessions.announce(key(2), &announce(1), 2 * MS, &mut nonces))
        .challenge
        .nonce;
    assert_eq!(
        sessions.answer(key(2), &answer(1, nonce), 3 * MS, || true),
        AnswerOutcome::PathBound { image, path: 1 }
    );
    assert_eq!(
        sessions.announce(key(3), &announce(1), 4 * MS, &mut nonces),
        AnnounceOutcome::Dropped(Ignored::PathsFull)
    );
    assert_eq!(sessions.counters().installed, 1);
}

/// A path challenge whose image retired before its answer binds nothing:
/// the quarantine refuses it, and no image is created.
#[test]
fn a_path_answer_after_retirement_binds_nothing() {
    let mut sessions = table(SessionConfig::default());
    let mut nonces = Counter::default();
    let image = install_on_key_one(&mut sessions, &mut nonces);
    let nonce = challenged(sessions.announce(key(2), &announce(1), 2 * MS, &mut nonces))
        .challenge
        .nonce;
    assert!(sessions.retire(image, 3 * MS));
    assert_eq!(
        sessions.answer(key(2), &answer(1, nonce), 4 * MS, || true),
        AnswerOutcome::Dropped(Ignored::Quarantined)
    );
    assert_eq!(sessions.paths().lookup(key(2)), None);
    assert_eq!(sessions.counters().paths_bound, 0);
}

#[test]
fn the_path_settings_are_validated() {
    for (max_paths, timeout) in [(0, 1), (super::super::paths::MAX_PATHS + 1, 1), (4, 0)] {
        assert!(
            ReceiveSessions::new(
                SessionConfig {
                    max_paths,
                    path_liveness_timeout: timeout,
                    ..SessionConfig::default()
                },
                BOOT
            )
            .is_err()
        );
    }
}

/// An installed image whose first path cannot be bound (no recorded
/// joins: a broken invariant) is still installed, and the failure is
/// counted (s-88 review, P3).
#[test]
fn a_failed_first_binding_is_counted() {
    let mut sessions = table(SessionConfig::default());
    let pending = inject(&mut sessions, key(1), 1, [91, 0], true);
    if let Some(slot) = sessions
        .slots
        .get_mut(usize::try_from(pending.slot).unwrap())
        && let State::Challenged { joins, .. } = &mut slot.state
    {
        *joins = None;
    }
    let ReadyOutcome::Installed(image) = sessions.image_ready(pending, MS) else {
        panic!("not installed");
    };
    assert!(sessions.is_active(image));
    assert_eq!(sessions.paths().live(image), 0);
    assert_eq!(sessions.counters().path_bind_failed, 1);
}
