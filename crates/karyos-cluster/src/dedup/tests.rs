// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

/// 4 sessions, 3 replies of 8 bytes, a TTL of 100.
fn small() -> DedupConfig {
    DedupConfig::default()
        .with_sessions(4)
        .with_window(3)
        .with_response_bytes(8)
        .with_ttl(100)
}

fn table() -> SessionTable {
    SessionTable::new(small()).unwrap()
}

/// A command whose reply is `reply`, counting its runs.
fn command<'a>(runs: &'a mut u32, reply: &'a [u8]) -> impl FnOnce(&mut [u8]) -> Option<usize> + 'a {
    move |buffer| {
        *runs += 1;
        buffer.get_mut(..reply.len())?.copy_from_slice(reply);
        Some(reply.len())
    }
}

fn run(
    table: &mut SessionTable,
    request: Request,
    time: u64,
    reply: &[u8],
) -> (Outcome<'static>, u32) {
    let mut runs = 0;
    let outcome = match table.request(request, time, command(&mut runs, reply)) {
        Outcome::Applied(bytes) => Outcome::Applied(leak(bytes)),
        Outcome::Retained(bytes) => Outcome::Retained(leak(bytes)),
        other => owned(other),
    };
    (outcome, runs)
}

fn leak(bytes: &[u8]) -> &'static [u8] {
    Box::leak(bytes.to_vec().into_boxed_slice())
}

fn owned(outcome: Outcome<'_>) -> Outcome<'static> {
    match outcome {
        Outcome::Duplicate => Outcome::Duplicate,
        Outcome::ReplyTooLarge => Outcome::ReplyTooLarge,
        Outcome::SessionExpired => Outcome::SessionExpired,
        Outcome::WindowFull => Outcome::WindowFull,
        Outcome::OutOfOrder { expected } => Outcome::OutOfOrder { expected },
        Outcome::Applied(_) | Outcome::Retained(_) => unreachable!(),
    }
}

#[test]
fn the_defaults_are_the_proposal() {
    let config = DedupConfig::default();
    assert_eq!(
        (
            config.sessions,
            config.window,
            config.response_bytes,
            config.ttl
        ),
        (1024, 64, 8192, 60_000_000_000)
    );
}

#[test]
fn a_zero_bound_or_an_overflow_is_refused() {
    assert_eq!(
        SessionTable::new(small().with_sessions(0)),
        Err(ConfigError::Zero("sessions"))
    );
    assert_eq!(
        SessionTable::new(small().with_window(0)),
        Err(ConfigError::Zero("window"))
    );
    assert_eq!(
        SessionTable::new(small().with_response_bytes(0)),
        Err(ConfigError::Zero("response_bytes"))
    );
    assert_eq!(
        SessionTable::new(small().with_ttl(0)),
        Err(ConfigError::Zero("ttl"))
    );
    #[cfg(target_pointer_width = "64")]
    assert_eq!(
        SessionTable::new(
            small()
                .with_sessions(u32::MAX)
                .with_window(u32::MAX)
                .with_response_bytes(u32::MAX)
        ),
        Err(ConfigError::TooLarge)
    );
}

#[test]
fn registration_advertises_the_bounds() {
    let mut table = table();
    assert_eq!(
        table.register(7, 1, 10),
        Ok(Registered {
            epoch: 1,
            config: small()
        })
    );
    assert_eq!(table.live_sessions(), 1);
}

#[test]
fn a_new_request_runs_once_and_a_retry_gets_its_reply() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 0, 0), 1, b"one");
    assert_eq!((outcome, runs), (Outcome::Applied(b"one"), 1));
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 0, 0), 2, b"other");
    assert_eq!((outcome, runs), (Outcome::Retained(b"one"), 0));
}

#[test]
fn an_acknowledged_reply_is_dropped_and_its_retry_is_a_duplicate() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    run(&mut table, Request::new(7, 1, 0, 0), 1, b"a");
    run(&mut table, Request::new(7, 1, 1, 0), 2, b"b");
    // The client saw reply 0.
    let (outcome, _) = run(&mut table, Request::new(7, 1, 2, 1), 3, b"c");
    assert_eq!(outcome, Outcome::Applied(b"c"));
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 0, 1), 4, b"x");
    assert_eq!((outcome, runs), (Outcome::Duplicate, 0));
    let (outcome, _) = run(&mut table, Request::new(7, 1, 1, 1), 5, b"x");
    assert_eq!(outcome, Outcome::Retained(b"b"));
}

#[test]
fn a_full_window_refuses_until_the_client_acknowledges() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    for sequence in 0..3 {
        let (outcome, _) = run(&mut table, Request::new(7, 1, sequence, 0), 1, b"r");
        assert_eq!(outcome, Outcome::Applied(b"r"));
    }
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 3, 0), 2, b"r");
    assert_eq!((outcome, runs), (Outcome::WindowFull, 0));
    // The refused request is retried with an acknowledgement.
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 3, 1), 3, b"s");
    assert_eq!((outcome, runs), (Outcome::Applied(b"s"), 1));
    // The window wraps: sequence 3 took sequence 0's slot.
    let (outcome, _) = run(&mut table, Request::new(7, 1, 3, 1), 4, b"x");
    assert_eq!(outcome, Outcome::Retained(b"s"));
    let (outcome, _) = run(&mut table, Request::new(7, 1, 1, 1), 4, b"x");
    assert_eq!(outcome, Outcome::Retained(b"r"));
}

#[test]
fn a_sequence_past_the_next_is_out_of_order() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 1, 0), 1, b"r");
    assert_eq!((outcome, runs), (Outcome::OutOfOrder { expected: 0 }, 0));
}

#[test]
fn an_acknowledgement_past_the_applied_ones_stops_at_them() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    run(&mut table, Request::new(7, 1, 0, 0), 1, b"a");
    // A claim to have seen replies 0..9 drops only the applied ones.
    let (outcome, _) = run(&mut table, Request::new(7, 1, 1, 9), 2, b"b");
    assert_eq!(outcome, Outcome::Applied(b"b"));
    let (outcome, _) = run(&mut table, Request::new(7, 1, 1, 9), 3, b"x");
    assert_eq!(outcome, Outcome::Duplicate);
}

#[test]
fn a_reply_that_does_not_fit_is_recorded_and_not_run_again() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    let mut runs = 0;
    let outcome = table.request(Request::new(7, 1, 0, 0), 1, |_| {
        runs += 1;
        None
    });
    assert_eq!(outcome, Outcome::ReplyTooLarge);
    // A length past the buffer is the same.
    let outcome = table.request(Request::new(7, 1, 1, 0), 1, |_| {
        runs += 1;
        Some(9)
    });
    assert_eq!(outcome, Outcome::ReplyTooLarge);
    assert_eq!(runs, 2);
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 0, 0), 2, b"r");
    assert_eq!((outcome, runs), (Outcome::ReplyTooLarge, 0));
    // A reply of exactly the bound fits.
    let (outcome, _) = run(&mut table, Request::new(7, 1, 2, 0), 3, b"12345678");
    assert_eq!(outcome, Outcome::Applied(b"12345678"));
}

#[test]
fn a_session_expires_at_its_ttl_in_log_time() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    run(&mut table, Request::new(7, 1, 0, 0), 50, b"a");
    // Activity at 50: still live at 149, which renews it to 249.
    let (outcome, _) = run(&mut table, Request::new(7, 1, 0, 0), 149, b"x");
    assert_eq!(outcome, Outcome::Retained(b"a"));
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 0, 0), 249, b"x");
    assert_eq!((outcome, runs), (Outcome::SessionExpired, 0));
    assert_eq!(table.live_sessions(), 0);
}

#[test]
fn any_entry_advances_log_time_and_it_never_goes_back() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    // Another client's entry at 100 expires client 7 (last active at 0).
    table.register(8, 2, 100).unwrap();
    // A new leader's clock behind: log time stays at 100.
    let (outcome, _) = run(&mut table, Request::new(7, 1, 0, 0), 20, b"x");
    assert_eq!(outcome, Outcome::SessionExpired);
    assert_eq!(table.log_time(), 100);
}

#[test]
fn a_duplicate_or_retained_request_renews_the_session() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    run(&mut table, Request::new(7, 1, 0, 0), 0, b"a");
    for time in [90, 180, 270] {
        let (outcome, _) = run(&mut table, Request::new(7, 1, 0, 0), time, b"x");
        assert_eq!(outcome, Outcome::Retained(b"a"));
    }
}

#[test]
fn a_full_table_refuses_and_never_evicts_a_live_session() {
    let mut table = table();
    // Client c registers at index c + 1, its epoch.
    for client in 0..4 {
        table.register(client, client + 1, 0).unwrap();
    }
    assert_eq!(
        table.register(9, 5, 10),
        Err(RegisterError::SessionsExhausted)
    );
    for client in 0..4 {
        let (outcome, _) = run(&mut table, Request::new(client, client + 1, 0, 0), 10, b"r");
        assert_eq!(outcome, Outcome::Applied(b"r"));
    }
    // An expired session's slot is free again.
    for client in 1..4 {
        run(&mut table, Request::new(client, client + 1, 1, 0), 60, b"r");
    }
    assert_eq!(table.register(9, 6, 110).map(|done| done.epoch), Ok(6));
    let (outcome, _) = run(&mut table, Request::new(0, 1, 0, 0), 110, b"x");
    assert_eq!(outcome, Outcome::SessionExpired);
}

#[test]
fn registrations_follow_log_order() {
    let mut table = table();
    table.register(7, 5, 0).unwrap();
    for index in [3, 5] {
        assert_eq!(
            table.register(8, index, 0),
            Err(RegisterError::NotAfter { index, last: 5 })
        );
    }
    assert_eq!(table.live_sessions(), 1);
}

#[test]
fn each_registration_opens_its_own_session() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    run(&mut table, Request::new(7, 1, 0, 0), 1, b"a");
    // A duplicate of the registration, applied later: another session,
    // under its own epoch; the first keeps its replies.
    assert_eq!(table.register(7, 2, 2).map(|done| done.epoch), Ok(2));
    assert_eq!(table.live_sessions(), 2);
    let (outcome, _) = run(&mut table, Request::new(7, 1, 0, 0), 3, b"x");
    assert_eq!(outcome, Outcome::Retained(b"a"));
    let (outcome, runs) = run(&mut table, Request::new(7, 2, 0, 0), 4, b"b");
    assert_eq!((outcome, runs), (Outcome::Applied(b"b"), 1));
    // An epoch never registered.
    let (outcome, _) = run(&mut table, Request::new(7, 9, 0, 0), 5, b"x");
    assert_eq!(outcome, Outcome::SessionExpired);
}

/// REVIEWER-02's F1 on #458: a late duplicate of a registration, applied
/// after its session expired, must not revive it, so a late duplicate of
/// its first request never runs again.
#[test]
fn a_late_duplicate_registration_never_revives_an_expired_session() {
    let mut table = table();
    let epoch = table.register(7, 1, 0).unwrap().epoch;
    let (outcome, runs) = run(&mut table, Request::new(7, epoch, 0, 0), 1, b"a");
    assert_eq!((outcome, runs), (Outcome::Applied(b"a"), 1));
    // The duplicate registration, past the TTL: a new session, epoch 2.
    assert_eq!(table.register(7, 2, 500).map(|done| done.epoch), Ok(2));
    let (outcome, runs) = run(&mut table, Request::new(7, epoch, 0, 0), 501, b"x");
    assert_eq!((outcome, runs), (Outcome::SessionExpired, 0));
}

/// REVIEWER-02's F2 on #458: a stale request carrying an older lowest
/// unanswered never moves the base back.
#[test]
fn a_stale_acknowledgement_never_moves_the_base_back() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    for (sequence, reply) in [(0, b"a"), (1, b"b"), (2, b"c")] {
        run(&mut table, Request::new(7, 1, sequence, 0), 1, reply);
    }
    // The client saw replies 0 and 1; sequence 3 takes sequence 0's slot.
    let (outcome, _) = run(&mut table, Request::new(7, 1, 3, 2), 2, b"d");
    assert_eq!(outcome, Outcome::Applied(b"d"));
    // A late duplicate of request 0, with its old acknowledgement.
    let (outcome, runs) = run(&mut table, Request::new(7, 1, 0, 0), 3, b"x");
    assert_eq!((outcome, runs), (Outcome::Duplicate, 0));
    let (outcome, _) = run(&mut table, Request::new(7, 1, 0, 0), 4, b"x");
    assert_eq!(outcome, Outcome::Duplicate);
}

#[test]
fn a_closed_session_frees_its_slot() {
    let mut table = table();
    table.register(7, 1, 0).unwrap();
    assert!(!table.close(7, 2, 1));
    assert!(table.close(7, 1, 1));
    assert!(!table.close(7, 1, 1));
    assert_eq!(table.live_sessions(), 0);
    let (outcome, _) = run(&mut table, Request::new(7, 1, 0, 0), 2, b"x");
    assert_eq!(outcome, Outcome::SessionExpired);
}

#[test]
fn replicas_applying_the_same_entries_hold_the_same_table() {
    // Client 7 holds epoch 1, client 8 epoch 2.
    let entries = [
        (7, 0, 0, 1),
        (8, 0, 0, 2),
        (7, 1, 0, 3),
        (7, 1, 1, 200),
        (8, 0, 0, 201),
    ];
    let mut replicas = [table(), table()];
    for replica in &mut replicas {
        replica.register(7, 1, 0).unwrap();
        replica.register(8, 2, 0).unwrap();
        for (client, sequence, seen, time) in entries {
            let epoch = if client == 7 { 1 } else { 2 };
            run(
                replica,
                Request::new(client, epoch, sequence, seen),
                time,
                b"r",
            );
        }
    }
    assert_eq!(replicas[0], replicas[1]);
}
