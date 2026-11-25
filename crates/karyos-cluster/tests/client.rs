// SPDX-License-Identifier: Apache-2.0

//! The Cluster client's failover (karyos#720), against the cluster's
//! replicated deduplication (`SessionTable`, one table standing for every
//! replica's): a leader change with no duplicate application, a lower
//! generation refused once a higher one is seen (S5), an unknown outcome
//! reported and never resent on its own, the advertised window held to,
//! an expiry reaching the caller typed, and nothing allocated after
//! registration.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_cluster::client::{Answer, ClusterClient, Event, Reply, SubmitError};
use karyos_cluster::dedup::{DedupConfig, Outcome, Request, SessionTable};
use karyos_sys::alloc_count::{CountingAllocator, count_allocations};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const OLD: u64 = 1;
const NEW: u64 = 2;

fn config(window: u32) -> DedupConfig {
    DedupConfig::default()
        .with_sessions(4)
        .with_window(window)
        .with_response_bytes(64)
        .with_ttl(1_000_000_000)
}

/// A table and a client registered on it, sending to the old leader.
fn registered(window: u32) -> (SessionTable, ClusterClient) {
    let mut table = SessionTable::new(config(window)).unwrap();
    let session = table.register(9, 1, 0).unwrap();
    let mut client = ClusterClient::new(9, Some(OLD));
    client.registered(session, 1);
    (table, client)
}

fn events(call: impl FnOnce(&mut dyn FnMut(Event))) -> Vec<Event> {
    let mut out = Vec::new();
    call(&mut |event| out.push(event));
    out
}

/// The answer, as the client reads it, to `request` applied on `table`;
/// `applied` counts how often the command ran.
fn apply(table: &mut SessionTable, request: Request, at: u64, applied: &mut u32) -> Answer {
    match table.request(request, at, |reply| {
        *applied += 1;
        reply[0] = 1;
        Some(1)
    }) {
        Outcome::Applied(_) => Answer::Applied,
        Outcome::Retained(_) => Answer::Retained,
        Outcome::Duplicate => Answer::Duplicate,
        Outcome::ReplyTooLarge => Answer::ReplyTooLarge,
        Outcome::SessionExpired => Answer::SessionExpired,
        Outcome::WindowFull => Answer::WindowFull,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_leader_change_reports_unknown_and_a_retry_is_not_applied_twice() {
    let (mut table, mut client) = registered(4);
    let mut applied = 0;
    let (to, request) = client.submit().unwrap();
    assert_eq!((to, request.sequence), (OLD, 0));
    // The old leader applies it; its reply is lost; the leader changes.
    let _ = apply(&mut table, request, 10, &mut applied);
    let seen = events(|sink| client.leader_changed(Some(NEW), 2, sink));
    assert_eq!(
        seen,
        vec![Event::Unknown {
            client: 9,
            sequence: 0
        }]
    );
    // Nothing was resent on its own; the caller retries: the same request,
    // to the new leader, answered from the kept reply.
    let (to, again) = client.retry(0).unwrap();
    assert_eq!((to, again.sequence, again.epoch), (NEW, 0, request.epoch));
    let answer = apply(&mut table, again, 20, &mut applied);
    assert_eq!(answer, Answer::Retained);
    assert_eq!(applied, 1, "applied twice");
    let seen = events(|sink| client.replied(0, 2, Reply::Outcome(answer), sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 0,
            answer: Answer::Retained
        }]
    );
}

#[test]
fn a_redirect_resends_the_same_request_to_the_leader_it_names() {
    let (_, mut client) = registered(4);
    let (_, request) = client.submit().unwrap();
    let seen = events(|sink| client.replied(0, 1, Reply::Redirect { leader: Some(NEW) }, sink));
    assert_eq!(seen, vec![Event::Resend { to: NEW, request }]);
    assert_eq!(client.leader(), Some(NEW));
}

/// S5 (phase-5 cluster scenarios): a client that has seen generation 2
/// rejects every generation 1 reply, of any kind, and a generation 1
/// leader's announcement.
#[test]
fn a_client_that_saw_generation_2_refuses_every_generation_1_reply() {
    let (_, mut client) = registered(4);
    let _ = client.submit().unwrap();
    let _ = client.submit().unwrap();
    let seen = events(|sink| client.replied(0, 2, Reply::Outcome(Answer::Applied), sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 0,
            answer: Answer::Applied
        }]
    );
    for reply in [
        Reply::Outcome(Answer::Applied),
        Reply::Outcome(Answer::Retained),
        Reply::Outcome(Answer::SessionExpired),
        Reply::Redirect { leader: Some(OLD) },
    ] {
        let seen = events(|sink| client.replied(1, 1, reply, sink));
        assert_eq!(
            seen,
            vec![Event::StaleGeneration {
                generation: 1,
                highest: 2
            }],
            "{reply:?}"
        );
    }
    let seen = events(|sink| client.leader_changed(Some(OLD), 1, sink));
    assert_eq!(
        seen,
        vec![Event::StaleGeneration {
            generation: 1,
            highest: 2
        }]
    );
    // Request 1 is still outstanding, the leader unchanged.
    assert_eq!(client.lowest_unanswered(), 1);
    assert_eq!(client.leader(), Some(OLD));
}

#[test]
fn a_timed_out_request_is_unknown_and_never_resent_on_its_own() {
    let (_, mut client) = registered(4);
    let _ = client.submit().unwrap();
    let seen = events(|sink| client.timed_out(0, sink));
    assert_eq!(
        seen,
        vec![Event::Unknown {
            client: 9,
            sequence: 0
        }]
    );
    // Once: a second timeout, or a leader change, reports it no more.
    assert!(events(|sink| client.timed_out(0, sink)).is_empty());
    assert!(events(|sink| client.leader_changed(Some(NEW), 1, sink)).is_empty());
    // It holds its place in the window until retried or abandoned.
    assert_eq!(client.lowest_unanswered(), 0);
    client.abandon(0);
    assert_eq!(client.lowest_unanswered(), 1);
}

#[test]
fn the_advertised_window_is_read_and_held_to() {
    let (mut table, mut client) = registered(2);
    assert_eq!(client.bounds().map(|bounds| bounds.window), Some(2));
    let mut applied = 0;
    let (_, first) = client.submit().unwrap();
    let (_, second) = client.submit().unwrap();
    assert_eq!(client.submit(), Err(SubmitError::WindowFull { window: 2 }));
    // The cluster's own window, full of unacknowledged replies, refuses a
    // third request typed: the client reports it busy, not applied.
    let _ = apply(&mut table, first, 1, &mut applied);
    let _ = apply(&mut table, second, 2, &mut applied);
    let third = Request::new(9, first.epoch, 2, 0);
    let answer = apply(&mut table, third, 3, &mut applied);
    assert_eq!(answer, Answer::WindowFull);
    let seen = events(|sink| client.replied(1, 1, Reply::Outcome(answer), sink));
    assert_eq!(seen, vec![Event::Busy { sequence: 1 }]);
    assert_eq!(applied, 2);
}

#[test]
fn an_expired_session_reaches_the_caller_typed() {
    let (_, mut client) = registered(4);
    let _ = client.submit().unwrap();
    let (_, request) = client.submit().unwrap();
    let seen = events(|sink| client.replied(1, 1, Reply::Outcome(Answer::SessionExpired), sink));
    assert_eq!(
        seen,
        vec![
            Event::Unknown {
                client: 9,
                sequence: 0
            },
            Event::Unknown {
                client: 9,
                sequence: 1
            },
            Event::Expired {
                client: 9,
                epoch: request.epoch
            },
        ]
    );
    assert_eq!(client.submit(), Err(SubmitError::NotRegistered));
}

/// After registration, the failover path allocates nothing: submits,
/// redirects, leader changes, timeouts, retries and outcomes.
#[test]
fn the_failover_path_allocates_nothing_after_registration() {
    let (_, mut client) = registered(8);
    let mut seen = 0u64;
    let ((), allocations) = count_allocations(|| {
        for round in 0..100u64 {
            let mut sink = |_: Event| seen += 1;
            let (_, request) = client.submit().unwrap();
            client.replied(
                request.sequence,
                1,
                Reply::Redirect { leader: Some(NEW) },
                &mut sink,
            );
            client.leader_changed(Some(OLD), 1, &mut sink);
            client.timed_out(request.sequence, &mut sink);
            let _ = client.retry(request.sequence).unwrap();
            let answer = if round % 2 == 0 {
                Answer::Applied
            } else {
                Answer::Retained
            };
            client.replied(request.sequence, 1, Reply::Outcome(answer), &mut sink);
        }
    });
    assert_eq!(allocations, 0);
    assert!(seen >= 300);
}
