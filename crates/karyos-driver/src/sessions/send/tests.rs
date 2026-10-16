// SPDX-License-Identifier: Apache-2.0

//! The sender's SETUP side: announce cadence until the first SM, answers
//! to challenges and solicits, and every drop.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_protocol::network::{ChallengeBlock, LaneStatus, Receiver};

use super::*;

const MS: u64 = 1_000_000;
const INTERVAL: u64 = 100 * MS;

fn alias(session_id: i32) -> Alias {
    Alias {
        session_id,
        stream_id: 6,
    }
}

fn identity(incarnation: u64) -> Identity {
    Identity {
        driver_id: [1, 2],
        registration_id: 3,
        incarnation,
    }
}

fn publication(session_id: i32) -> Publication {
    Publication {
        endpoint: EndpointId(1),
        alias: alias(session_id),
        identity: identity(1),
        term: TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        },
        lane_count: 2,
    }
}

fn joins(_: &Publication) -> Lanes<u64> {
    Lanes::new(&[64, 128]).unwrap()
}

fn block() -> ChallengeBlock {
    ChallengeBlock {
        receiver_boot_id: [7, 8],
        nonce: [42, 0],
    }
}

fn sm(session_id: i32, incarnation: u64) -> StatusMessage {
    StatusMessage {
        alias: alias(session_id),
        identity: identity(incarnation),
        receiver: Receiver {
            receiver_boot_id: [7, 8],
            receiver_id: 1,
        },
        group_tag: 0,
        lanes: Lanes::new(&[LaneStatus::default(), LaneStatus::default()]).unwrap(),
    }
}

fn due(sessions: &mut SendSessions, now: u64) -> Vec<(EndpointId, SetupAnnounce)> {
    let mut out = Vec::new();
    sessions.announce_due(now, |endpoint, announce| out.push((endpoint, announce)));
    out
}

/// A publication announces at once, then every interval, and stops at its
/// first SM for its identity (an SM for another identity does not count).
#[test]
fn announcements_repeat_until_the_first_sm() {
    let mut sessions = SendSessions::new(4, INTERVAL).unwrap();
    sessions.add(publication(5)).unwrap();
    let first = due(&mut sessions, 0);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].1.identity, identity(1));
    assert_eq!(first[0].1.lane_count, 2);
    assert!(due(&mut sessions, INTERVAL - 1).is_empty());
    assert_eq!(due(&mut sessions, INTERVAL).len(), 1);
    assert!(
        !sessions.status(EndpointId(1), &sm(5, 2)),
        "another identity"
    );
    assert!(
        !sessions.status(EndpointId(2), &sm(5, 1)),
        "another endpoint"
    );
    assert!(sessions.status(EndpointId(1), &sm(5, 1)));
    assert!(
        !sessions.status(EndpointId(1), &sm(5, 1)),
        "established once"
    );
    assert!(sessions.is_established(EndpointId(1), alias(5)));
    assert!(due(&mut sessions, 10 * INTERVAL).is_empty());
    assert_eq!(sessions.counters().announces, 2);
    assert_eq!(sessions.counters().established, 1);
}

/// A challenge naming our identity is answered with the echoed challenge
/// and the current joins; another identity, alias or endpoint is dropped.
#[test]
fn a_challenge_is_answered_only_for_our_identity() {
    let mut sessions = SendSessions::new(4, INTERVAL).unwrap();
    sessions.add(publication(5)).unwrap();
    let challenge = RspChallenge {
        alias: alias(5),
        identity: identity(1),
        challenge: block(),
    };
    let answer = sessions
        .challenge(EndpointId(1), &challenge, joins)
        .unwrap();
    assert_eq!(answer.challenge, block());
    assert_eq!(answer.identity, identity(1));
    assert_eq!(answer.joins.as_slice(), [64, 128]);
    let stale = RspChallenge {
        identity: identity(2),
        ..challenge
    };
    assert_eq!(
        sessions.challenge(EndpointId(1), &stale, joins),
        Err(SendIgnored::WrongIdentity)
    );
    let other = RspChallenge {
        alias: alias(6),
        ..challenge
    };
    assert_eq!(
        sessions.challenge(EndpointId(1), &other, joins),
        Err(SendIgnored::UnknownAlias)
    );
    assert_eq!(
        sessions.challenge(EndpointId(2), &challenge, joins),
        Err(SendIgnored::UnknownAlias),
        "another channel"
    );
    assert_eq!(sessions.counters().answers, 1);
    assert_eq!(sessions.counters().dropped, 3);
}

/// A solicit is answered by alias on its endpoint, after establishment too
/// (a late multicast receiver or a restarted unicast one).
#[test]
fn a_solicit_is_answered_by_alias() {
    let mut sessions = SendSessions::new(4, INTERVAL).unwrap();
    sessions.add(publication(5)).unwrap();
    sessions.status(EndpointId(1), &sm(5, 1));
    let solicit = RspSolicit {
        alias: alias(5),
        challenge: block(),
    };
    let answer = sessions.solicit(EndpointId(1), &solicit, joins).unwrap();
    assert_eq!(answer.identity, identity(1));
    assert_eq!(
        sessions.solicit(
            EndpointId(1),
            &RspSolicit {
                alias: alias(6),
                ..solicit
            },
            joins
        ),
        Err(SendIgnored::UnknownAlias)
    );
    // Joins that do not cover the lanes are never sent.
    assert_eq!(
        sessions.solicit(EndpointId(1), &solicit, |_| Lanes::new(&[0]).unwrap()),
        Err(SendIgnored::Joins)
    );
}

/// The table is bounded, an alias is unique per endpoint, and a removed
/// publication no longer answers.
#[test]
fn the_table_is_bounded_and_aliases_unique() {
    assert_eq!(
        SendSessions::new(0, INTERVAL).unwrap_err(),
        SendSessionError::InvalidConfig
    );
    assert_eq!(
        SendSessions::new(1, 0).unwrap_err(),
        SendSessionError::InvalidConfig
    );
    let mut sessions = SendSessions::new(1, INTERVAL).unwrap();
    sessions.add(publication(5)).unwrap();
    assert_eq!(
        sessions.add(publication(5)),
        Err(SendSessionError::DuplicateAlias)
    );
    assert_eq!(sessions.add(publication(6)), Err(SendSessionError::Full));
    let mut bad = publication(7);
    bad.lane_count = 5;
    assert_eq!(sessions.add(bad), Err(SendSessionError::InvalidConfig));
    assert!(sessions.remove(EndpointId(1), alias(5)));
    assert!(!sessions.remove(EndpointId(1), alias(5)));
    let solicit = RspSolicit {
        alias: alias(5),
        challenge: block(),
    };
    assert_eq!(
        sessions.solicit(EndpointId(1), &solicit, joins),
        Err(SendIgnored::UnknownAlias)
    );
    sessions.add(publication(6)).unwrap();
}
