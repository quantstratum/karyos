// SPDX-License-Identifier: Apache-2.0

//! The Cluster client's failover (karyos#720), against the cluster's
//! replicated deduplication (`SessionTable`, one table standing for every
//! replica's): a leader change with no duplicate application, a lower
//! generation refused once a higher one is seen (S5), an unknown outcome
//! reported and never resent on its own, answers and timers of older
//! attempts ignored, registrations ordered by epoch, the advertised window
//! held to, an expiry reaching the caller typed, and nothing allocated
//! after registration.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_cluster::client::{
    Accepted, Answer, ClusterClient, Event, Key, RegisterError, Reply, Send, Stamp, SubmitError,
};
use karyos_cluster::cluster_identity::ClusterId;
use karyos_cluster::dedup::{DedupConfig, Outcome, Registered, Request, SessionTable};
use karyos_sys::alloc_count::{CountingAllocator, count_allocations};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const OLD: u64 = 1;
const NEW: u64 = 2;
/// The live cluster's identity.
const LIVE: ClusterId = ClusterId([0x11; 32]);
/// Its standby's.
const STANDBY: ClusterId = ClusterId([0x22; 32]);
/// A rebuild's: no live client accepts it (ADR-0123 decision 2).
const REBUILD: ClusterId = ClusterId([0x33; 32]);

/// A stamp of the live cluster in `generation`.
const fn live(generation: u64) -> Stamp {
    Stamp {
        cluster: LIVE,
        generation,
    }
}

fn config(window: u32) -> DedupConfig {
    DedupConfig::default()
        .with_sessions(4)
        .with_window(window)
        .with_response_bytes(64)
        .with_ttl(1_000_000_000)
}

fn events(call: impl FnOnce(&mut dyn FnMut(Event))) -> Vec<Event> {
    let mut out = Vec::new();
    call(&mut |event| out.push(event));
    out
}

/// A table, its session for client 9, and a client registered on it,
/// sending to the old leader.
fn registered(window: u32) -> (SessionTable, Registered, ClusterClient) {
    let mut table = SessionTable::new(config(window)).unwrap();
    let session = table.register(9, 1, 0).unwrap();
    let mut client = ClusterClient::new(9, Some(OLD), Accepted::only(LIVE));
    assert!(events(|sink| client.registered(session, live(1), sink).unwrap()).is_empty());
    (table, session, client)
}

/// The answer, as the client reads it, to `request` applied on `table`;
/// `applied` counts how often the command ran.
fn apply(table: &mut SessionTable, request: Request, at: u64, applied: &mut u32) -> Answer {
    match table.request(request, b"op", at, |reply| {
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
        Outcome::PayloadMismatch => Answer::PayloadMismatch,
        Outcome::OutOfOrder { expected } => Answer::OutOfOrder { expected },
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_leader_change_reports_unknown_and_a_retry_is_not_applied_twice() {
    let (mut table, _, mut client) = registered(4);
    let mut applied = 0;
    let first = client.submit().unwrap();
    assert_eq!(
        (first.to, first.request.sequence, first.key.attempt),
        (OLD, 0, 0)
    );
    // The old leader applies it; its reply is lost; the leader changes.
    let _ = apply(&mut table, first.request, 10, &mut applied);
    let seen = events(|sink| client.leader_changed(Some(NEW), live(2), sink));
    assert_eq!(
        seen,
        vec![Event::Unknown {
            client: 9,
            sequence: 0
        }]
    );
    // Nothing was resent on its own; the caller retries: the same request,
    // a new attempt, to the new leader, answered from the kept reply.
    let again = client.retry(0).unwrap();
    assert_eq!(
        (again.to, again.request, again.key.attempt),
        (NEW, first.request, 1)
    );
    let answer = apply(&mut table, again.request, 20, &mut applied);
    assert_eq!(answer, Answer::Retained);
    assert_eq!(applied, 1, "applied twice");
    let seen = events(|sink| client.replied(again.key, live(2), Reply::Outcome(answer), sink));
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
    let (_, _, mut client) = registered(4);
    let sent = client.submit().unwrap();
    let seen = events(|sink| {
        client.replied(
            sent.key,
            live(1),
            Reply::Redirect { leader: Some(NEW) },
            sink,
        )
    });
    let resent = Send {
        cluster: LIVE,
        to: NEW,
        request: sent.request,
        key: Key {
            attempt: 1,
            ..sent.key
        },
    };
    assert_eq!(seen, vec![Event::Resend(resent)]);
    assert_eq!(client.leader(), Some(NEW));
    // A redirect naming no leader: not taken, waiting for one, nothing sent.
    let seen =
        events(|sink| client.replied(resent.key, live(1), Reply::Redirect { leader: None }, sink));
    assert_eq!(seen, vec![Event::NoLeader { sequence: 0 }]);
    assert_eq!(client.retry(0), Err(SubmitError::NoLeader));
}

/// A redirect, a busy or out-of-order refusal, or a timer, of an attempt a
/// newer one overtook, or of a request already unknown, steers nothing.
#[test]
fn an_older_attempt_or_an_unknown_request_is_not_steered() {
    let (_, _, mut client) = registered(4);
    let first = client.submit().unwrap();
    let second = client.retry(0).unwrap();
    for reply in [
        Reply::Redirect { leader: Some(NEW) },
        Reply::Outcome(Answer::WindowFull),
        Reply::Outcome(Answer::OutOfOrder { expected: 0 }),
    ] {
        assert!(
            events(|sink| client.replied(first.key, live(1), reply, sink)).is_empty(),
            "{reply:?}"
        );
    }
    assert!(events(|sink| client.timed_out(first.key, sink)).is_empty());
    assert_eq!(client.leader(), Some(OLD));
    // The current attempt times out: unknown, and a redirect after that is
    // not followed by a resend.
    let seen = events(|sink| client.timed_out(second.key, sink));
    assert_eq!(
        seen,
        vec![Event::Unknown {
            client: 9,
            sequence: 0
        }]
    );
    let redirect = Reply::Redirect { leader: Some(NEW) };
    assert!(events(|sink| client.replied(second.key, live(1), redirect, sink)).is_empty());
    // An outcome of any attempt still settles it.
    let seen =
        events(|sink| client.replied(first.key, live(1), Reply::Outcome(Answer::Applied), sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 0,
            answer: Answer::Applied
        }]
    );
}

/// S5 (phase-5 cluster scenarios): a client that has seen generation 2
/// rejects every generation 1 reply, of any kind, and a generation 1
/// leader's announcement.
#[test]
fn a_client_that_saw_generation_2_refuses_every_generation_1_reply() {
    let (_, _, mut client) = registered(4);
    let first = client.submit().unwrap();
    let second = client.submit().unwrap();
    let seen =
        events(|sink| client.replied(first.key, live(2), Reply::Outcome(Answer::Applied), sink));
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
        let seen = events(|sink| client.replied(second.key, live(1), reply, sink));
        assert_eq!(
            seen,
            vec![Event::StaleGeneration {
                generation: 1,
                highest: 2
            }],
            "{reply:?}"
        );
    }
    let seen = events(|sink| client.leader_changed(Some(OLD), live(1), sink));
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

/// An answer that names no outstanding request, or another session,
/// raises no generation: only a correlated answer does.
#[test]
fn an_uncorrelated_answer_raises_no_generation() {
    let (_, _, mut client) = registered(4);
    let sent = client.submit().unwrap();
    let stray = Key {
        sequence: 7,
        ..sent.key
    };
    let other = Key {
        epoch: sent.key.epoch + 1,
        ..sent.key
    };
    for key in [stray, other] {
        assert!(
            events(|sink| client.replied(key, live(9), Reply::Outcome(Answer::Applied), sink))
                .is_empty()
        );
    }
    assert_eq!(client.generation(), 1);
    assert_eq!(client.lowest_unanswered(), 0);
}

#[test]
fn a_timed_out_request_is_unknown_and_never_resent_on_its_own() {
    let (_, _, mut client) = registered(4);
    let sent = client.submit().unwrap();
    let seen = events(|sink| client.timed_out(sent.key, sink));
    assert_eq!(
        seen,
        vec![Event::Unknown {
            client: 9,
            sequence: 0
        }]
    );
    // Once: a second timeout, or a leader change, reports it no more.
    assert!(events(|sink| client.timed_out(sent.key, sink)).is_empty());
    assert!(events(|sink| client.leader_changed(Some(NEW), live(1), sink)).is_empty());
    // It holds its place in the window until it has an outcome.
    assert_eq!(client.lowest_unanswered(), 0);
    let again = client.retry(0).unwrap();
    let seen =
        events(|sink| client.replied(again.key, live(1), Reply::Outcome(Answer::Duplicate), sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 0,
            answer: Answer::Duplicate
        }]
    );
    assert_eq!(client.lowest_unanswered(), 1);
}

#[test]
fn registrations_are_ordered_by_epoch() {
    let (mut table, session, mut client) = registered(4);
    let _ = client.submit().unwrap();
    // The same session again: nothing changes.
    assert!(events(|sink| client.registered(session, live(1), sink).unwrap()).is_empty());
    assert_eq!(client.lowest_unanswered(), 0);
    let newer = table.register(9, 2, 1).unwrap();
    assert!(newer.epoch > session.epoch);
    // A newer one replaces it: the outstanding request is unknown.
    let seen = events(|sink| client.registered(newer, live(1), sink).unwrap());
    assert_eq!(
        seen,
        vec![Event::Unknown {
            client: 9,
            sequence: 0
        }]
    );
    let sent = client.submit().unwrap();
    assert_eq!((sent.key.epoch, sent.request.sequence), (newer.epoch, 0));
    // The older one, arriving late, is refused.
    assert_eq!(
        events(|sink| {
            assert_eq!(
                client.registered(session, live(1), sink),
                Err(RegisterError::Stale {
                    epoch: session.epoch,
                    held: newer.epoch
                })
            );
        }),
        vec![]
    );
}

#[test]
fn the_advertised_window_is_read_and_held_to() {
    let (mut table, _, mut client) = registered(2);
    assert_eq!(client.bounds().map(|bounds| bounds.window), Some(2));
    let mut applied = 0;
    let first = client.submit().unwrap();
    let second = client.submit().unwrap();
    assert_eq!(client.submit(), Err(SubmitError::WindowFull { window: 2 }));
    // Both applied; the client settles the first but its next request
    // still advertises 0 as the lowest unanswered (a stale advert): the
    // cluster's window, full of replies it must keep, refuses it typed and
    // the client reports it busy, not applied.
    let _ = apply(&mut table, first.request, 1, &mut applied);
    let _ = apply(&mut table, second.request, 2, &mut applied);
    let seen =
        events(|sink| client.replied(first.key, live(1), Reply::Outcome(Answer::Applied), sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 0,
            answer: Answer::Applied
        }]
    );
    let third = client.submit().unwrap();
    let stale = Request::new(9, third.key.epoch, third.request.sequence, 0);
    let answer = apply(&mut table, stale, 3, &mut applied);
    assert_eq!(answer, Answer::WindowFull);
    let seen = events(|sink| client.replied(third.key, live(1), Reply::Outcome(answer), sink));
    assert_eq!(seen, vec![Event::Busy { sequence: 2 }]);
    assert_eq!(applied, 2);
    // Sent as the client builds it, with its real lowest unanswered, the
    // retry is taken.
    let again = client.retry(2).unwrap();
    assert_eq!(
        apply(&mut table, again.request, 4, &mut applied),
        Answer::Applied
    );
}

/// Sequences 0 and 1 delivered in reverse, under a log of an earlier
/// build (sessions take sequences in order): the cluster refuses 1 typed,
/// the client keeps it outstanding, and once 0 is applied a retry of 1 is.
#[test]
fn an_out_of_order_refusal_reaches_the_caller_typed_and_is_retried() {
    let (mut table, _, mut client) = registered(4);
    table.set_exact(false);
    let mut applied = 0;
    let first = client.submit().unwrap();
    let second = client.submit().unwrap();
    let answer = apply(&mut table, second.request, 1, &mut applied);
    assert_eq!(answer, Answer::OutOfOrder { expected: 0 });
    let seen = events(|sink| client.replied(second.key, live(1), Reply::Outcome(answer), sink));
    assert_eq!(
        seen,
        vec![Event::OutOfOrder {
            sequence: 1,
            expected: 0
        }]
    );
    let answer = apply(&mut table, first.request, 2, &mut applied);
    let seen = events(|sink| client.replied(first.key, live(1), Reply::Outcome(answer), sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 0,
            answer: Answer::Applied
        }]
    );
    let again = client.retry(1).unwrap();
    let answer = apply(&mut table, again.request, 3, &mut applied);
    let seen = events(|sink| client.replied(again.key, live(1), Reply::Outcome(answer), sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 1,
            answer: Answer::Applied
        }]
    );
    assert_eq!(applied, 2);
    assert_eq!(client.lowest_unanswered(), 2);
}

#[test]
fn an_expired_session_reaches_the_caller_typed() {
    let (_, _, mut client) = registered(4);
    let _ = client.submit().unwrap();
    let second = client.submit().unwrap();
    let reply = Reply::Outcome(Answer::SessionExpired);
    let seen = events(|sink| client.replied(second.key, live(1), reply, sink));
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
                epoch: second.key.epoch
            },
        ]
    );
    assert_eq!(client.submit(), Err(SubmitError::NotRegistered));
}

/// After registration, the failover path allocates nothing: submits,
/// redirects, leader changes, timeouts, retries and outcomes.
#[test]
fn the_failover_path_allocates_nothing_after_registration() {
    let (_, _, mut client) = registered(8);
    let mut seen = 0u64;
    let ((), allocations) = count_allocations(|| {
        for round in 0..100u64 {
            let mut sink = |_: Event| seen += 1;
            let sent = client.submit().unwrap();
            client.replied(
                sent.key,
                live(1),
                Reply::Redirect { leader: Some(NEW) },
                &mut sink,
            );
            client.leader_changed(Some(OLD), live(1), &mut sink);
            let again = client.retry(sent.request.sequence).unwrap();
            client.timed_out(again.key, &mut sink);
            let again = client.retry(sent.request.sequence).unwrap();
            let answer = if round % 2 == 0 {
                Answer::Applied
            } else {
                Answer::Retained
            };
            client.replied(again.key, live(1), Reply::Outcome(answer), &mut sink);
        }
    });
    assert_eq!(allocations, 0);
    assert!(seen >= 400);
}

/// A newer session with a larger window: the buffer is reserved to the
/// whole new window, so filling it allocates nothing.
#[test]
fn a_larger_window_on_a_new_session_is_reserved_whole() {
    let (_, _, mut client) = registered(8);
    for _ in 0..8 {
        let _ = client.submit().unwrap();
    }
    let mut wider = SessionTable::new(config(16)).unwrap();
    let session = wider.register(9, 2, 0).unwrap();
    let mut unknown = 0;
    client
        .registered(session, live(1), &mut |_| unknown += 1)
        .unwrap();
    assert_eq!(unknown, 8);
    let ((), allocations) = count_allocations(|| {
        for _ in 0..16 {
            let _ = client.submit().unwrap();
        }
    });
    assert_eq!(allocations, 0);
    assert_eq!(client.submit(), Err(SubmitError::WindowFull { window: 16 }));
}

/// Under the exact identity, sequences delivered in reverse both apply,
/// once each; a retry carrying another command is refused as a mismatch
/// and reaches the caller as its outcome.
#[test]
fn reverse_delivery_applies_under_the_exact_identity_and_a_mismatch_is_typed() {
    let (mut table, _, mut client) = registered(4);
    let mut applied = 0;
    let first = client.submit().unwrap();
    let second = client.submit().unwrap();
    for sent in [second, first] {
        let answer = apply(&mut table, sent.request, 1, &mut applied);
        let seen = events(|sink| client.replied(sent.key, live(1), Reply::Outcome(answer), sink));
        assert_eq!(
            seen,
            vec![Event::Completed {
                sequence: sent.request.sequence,
                answer: Answer::Applied
            }]
        );
    }
    assert_eq!(applied, 2);
    let third = client.submit().unwrap();
    let _ = apply(&mut table, third.request, 2, &mut applied);
    let again = client.retry(third.request.sequence).unwrap();
    let outcome = table.request(again.request, b"another", 3, |_| Some(0));
    assert_eq!(outcome, Outcome::PayloadMismatch);
    let reply = Reply::Outcome(Answer::PayloadMismatch);
    let seen = events(|sink| client.replied(again.key, live(1), reply, sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 2,
            answer: Answer::PayloadMismatch
        }]
    );
    assert_eq!(applied, 3);
}

/// ADR-0123 decision 4: a registration from a cluster the client does not
/// accept opens no session, and an answer or announcement from one is
/// refused, whatever generation it claims, changing nothing.
#[test]
fn a_foreign_cluster_is_refused_at_registration_and_after() {
    let mut table = SessionTable::new(config(4)).unwrap();
    let session = table.register(9, 1, 0).unwrap();
    let mut client = ClusterClient::new(9, Some(OLD), Accepted::only(LIVE));
    let rebuild = Stamp {
        cluster: REBUILD,
        generation: 9,
    };
    let seen = events(|sink| {
        assert_eq!(
            client.registered(session, rebuild, sink),
            Err(RegisterError::ForeignCluster { received: REBUILD })
        );
    });
    assert_eq!(seen, vec![Event::ForeignCluster { received: REBUILD }]);
    assert_eq!(client.submit(), Err(SubmitError::NotRegistered));
    assert_eq!(client.generation(), 0);

    let (_, _, mut client) = registered(4);
    let sent = client.submit().unwrap();
    assert_eq!(sent.cluster, LIVE);
    let reply = Reply::Outcome(Answer::Applied);
    let seen = events(|sink| client.replied(sent.key, rebuild, reply, sink));
    assert_eq!(seen, vec![Event::ForeignCluster { received: REBUILD }]);
    let seen = events(|sink| client.leader_changed(Some(NEW), rebuild, sink));
    assert_eq!(seen, vec![Event::ForeignCluster { received: REBUILD }]);
    // Nothing changed: the generation, the leader, the request.
    assert_eq!(client.generation(), 1);
    assert_eq!(client.leader(), Some(OLD));
    let seen = events(|sink| client.replied(sent.key, live(1), reply, sink));
    assert_eq!(
        seen,
        vec![Event::Completed {
            sequence: 0,
            answer: Answer::Applied
        }]
    );
}

/// ADR-0123 decision 6: a client accepting the primary and its standby
/// follows the promoted standby by its higher generation, then refuses the
/// old primary as stale; an identity it was not given is refused whatever
/// generation it claims.
#[test]
fn failover_to_the_standby_follows_one_generation_mark() {
    let accepted = Accepted {
        primary: LIVE,
        standby: Some(STANDBY),
    };
    let mut table = SessionTable::new(config(4)).unwrap();
    let session = table.register(9, 1, 0).unwrap();
    let mut client = ClusterClient::new(9, Some(OLD), accepted);
    assert!(events(|sink| client.registered(session, live(1), sink).unwrap()).is_empty());
    let promoted = Stamp {
        cluster: STANDBY,
        generation: 2,
    };
    let seen = events(|sink| client.leader_changed(Some(NEW), promoted, sink));
    assert!(
        seen.iter()
            .all(|event| matches!(event, Event::Unknown { .. }))
    );
    assert_eq!(client.generation(), 2);
    let standby = SessionTable::new(config(4))
        .unwrap()
        .register(9, 3, 0)
        .unwrap();
    assert!(events(|sink| client.registered(standby, promoted, sink).unwrap()).is_empty());
    let sent = client.submit().unwrap();
    assert_eq!(sent.cluster, STANDBY);
    let seen = events(|sink| client.leader_changed(Some(OLD), live(1), sink));
    assert_eq!(
        seen,
        vec![Event::StaleGeneration {
            generation: 1,
            highest: 2
        }]
    );
    let rebuild = Stamp {
        cluster: REBUILD,
        generation: 99,
    };
    let seen = events(|sink| client.leader_changed(Some(OLD), rebuild, sink));
    assert_eq!(seen, vec![Event::ForeignCluster { received: REBUILD }]);
    assert_eq!(client.generation(), 2);
    assert_eq!(client.leader(), Some(NEW));
}

/// Codex review of karyos#1283: after a failover to the standby, a delayed
/// registration of the old primary's generation is stale: it changes neither
/// the session nor the identity requests name.
#[test]
fn a_stale_registration_changes_nothing() {
    let accepted = Accepted {
        primary: LIVE,
        standby: Some(STANDBY),
    };
    let mut table = SessionTable::new(config(4)).unwrap();
    let session = table.register(9, 1, 0).unwrap();
    let mut client = ClusterClient::new(9, Some(OLD), accepted);
    assert!(events(|sink| client.registered(session, live(1), sink).unwrap()).is_empty());
    let promoted = Stamp {
        cluster: STANDBY,
        generation: 2,
    };
    let standby = SessionTable::new(config(4)).unwrap().register(9, 3, 0).unwrap();
    let _ = events(|sink| client.leader_changed(Some(NEW), promoted, sink));
    assert!(events(|sink| client.registered(standby, promoted, sink).unwrap()).is_empty());
    let late = SessionTable::new(config(4)).unwrap().register(9, 7, 0).unwrap();
    let seen = events(|sink| {
        assert_eq!(
            client.registered(late, live(1), sink),
            Err(RegisterError::StaleGeneration {
                generation: 1,
                highest: 2
            })
        );
    });
    assert_eq!(
        seen,
        vec![Event::StaleGeneration {
            generation: 1,
            highest: 2
        }]
    );
    let sent = client.submit().unwrap();
    assert_eq!((sent.cluster, sent.key.epoch), (STANDBY, 3));
}
