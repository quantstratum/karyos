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
    challenged(sessions.announce(key(1), &announce(1), 4 * MS, &mut nonces));
    assert_eq!(
        sessions.announce(key(1), &announce(2), 5 * MS, &mut nonces),
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
