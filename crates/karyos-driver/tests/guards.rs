// SPDX-License-Identifier: Apache-2.0

//! Guarded local streams in the embedded driver (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, Admission and Local streams; P2.10
//! G-d1b): the binding to the open epoch, the walker's final records, the
//! reservation bound, the close's seal and the refusals.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use karyos_client::{
    ClaimOutcome, ClientError, ClientPublication, ClientSubscription, CommitOutcome, MessageLimit,
    OfferOutcome,
};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, GuardRate, RateScope, Reconfiguration, SealState,
    StreamConfig, StreamHandle, WalkerUnavailable,
};
use karyos_sys::frame::Lane;
use karyos_sys::guard::Closed;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::log_buffer::{Role, SealReason};
use karyos_sys::outcome_ring::{Kind, Record};
use karyos_sys::rate_limit::{Rate, RatePolicy, RatePolicyError};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

fn stream(
    driver: &mut EmbeddedDriver,
    stream_id: i32,
    publication: PublicationMode,
    allow_unconnected: bool,
) -> StreamHandle {
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 6,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication,
                schedule_capacity: 0,
            },
            allow_unconnected,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
            conflation: None,
        })
        .unwrap()
}

/// A driver with one guarded exclusive stream, `C_m` messages, and the
/// guard reopened at epoch 2.
fn guarded(messages: u64) -> (EmbeddedDriver, StreamHandle, karyos_driver::GuardHandle) {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(handle, guard, messages, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    (driver, handle, guard)
}

fn outcomes(publication: &mut ClientPublication) -> Vec<Record> {
    let mut records = Vec::new();
    let _ = publication
        .poll_outcomes(64, |_, record| records.push(record))
        .unwrap();
    records
}

#[test]
fn a_guarded_handle_gets_one_submitted_record_per_message() {
    let (mut driver, handle, _guard) = guarded(4);
    let mut publication = driver.publication(handle).unwrap();
    let mut accepted = Vec::new();
    for value in [b"a", b"b", b"c"] {
        match publication.offer(value).unwrap() {
            OfferOutcome::Accepted { position, .. } => accepted.push(position),
            other => panic!("not accepted: {other:?}"),
        }
    }
    let _ = driver.do_work().unwrap();
    let records = outcomes(&mut publication);
    assert_eq!(records.len(), 3);
    for (record, position) in records.iter().zip(&accepted) {
        assert_eq!(record.kind, Kind::Submitted);
        assert_eq!(record.start, *position);
        assert!(record.end > record.start);
        assert_eq!(record.epoch, 2, "bound to the open epoch");
    }
    assert_eq!(publication.guard().unwrap().outstanding(), 0);
}

#[test]
fn reservations_bound_the_publisher_until_the_walker_records_them() {
    let (mut driver, handle, _guard) = guarded(2);
    let mut publication = driver.publication(handle).unwrap();
    for value in [b"a", b"b"] {
        assert!(matches!(
            publication.offer(value).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert_eq!(
        publication.offer(b"c").unwrap(),
        OfferOutcome::BackPressured
    );
    let _ = driver.do_work().unwrap();
    assert_eq!(outcomes(&mut publication).len(), 2);
    assert!(matches!(
        publication.offer(b"c").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
}

/// A close seals the stream with `GuardClosed`: the handle is `Gated`, an
/// outstanding claim loses to the abort and gets `Aborted` with the guard
/// close reason, and the walker's last pass writes `Ended`.
#[test]
fn a_close_gates_the_handle_and_ends_its_outcomes() {
    let (mut driver, handle, guard) = guarded(4);
    let mut publication = driver.publication(handle).unwrap();
    assert!(matches!(
        publication.offer(b"a").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let ClaimOutcome::Claimed(mut claim) = publication.try_claim(8).unwrap() else {
        panic!("not claimed");
    };
    claim.payload().copy_from_slice(b"pending!");
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    assert!(matches!(claim.commit(), CommitOutcome::Aborted { .. }));
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(publication.offer(b"b").unwrap(), OfferOutcome::Gated);
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    let records = outcomes(&mut publication);
    let kinds: Vec<Kind> = records.iter().map(|record| record.kind).collect();
    assert_eq!(
        kinds,
        [Kind::Submitted, Kind::Aborted, Kind::Ended],
        "{records:?}"
    );
    assert_eq!(records[1].reason, 1, "AbortReason::GUARD_CLOSED");
    assert_eq!(records[2].reason, 1);
    assert_eq!(publication.guard().unwrap().outstanding(), 0);
    // The sealed incarnation is final; after a reopen the next handle gets
    // a fresh one (G-d2).
    drop(publication);
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    assert!(driver.publication(handle).is_ok());
}

#[test]
fn a_handle_is_issued_only_under_an_open_guard() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(handle, guard, 4, None).unwrap();
    assert!(matches!(
        driver.publication(handle),
        Err(DriverError::GuardNotOpen { guard: 1 })
    ));
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    assert!(driver.publication(handle).is_ok());
}

#[test]
fn guarding_is_refused_where_it_cannot_hold() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let guard = driver.add_guard("orders").unwrap();
    // GC-7: concurrent publications are not guarded.
    let concurrent = stream(
        &mut driver,
        3,
        PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: true,
        },
        true,
    );
    assert_eq!(
        driver.guard_stream(concurrent, guard, 4, None),
        Err(DriverError::InvalidPublicationMode)
    );
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    assert_eq!(
        driver.guard_stream(handle, guard, 0, None),
        Err(DriverError::InvalidConfig)
    );
    // max_reserved is an eighth of a term: five do not fit half a term.
    assert_eq!(
        driver.guard_stream(handle, guard, 5, None),
        Err(DriverError::InvalidConfig)
    );
    driver.guard_stream(handle, guard, 4, None).unwrap();
    assert_eq!(
        driver.guard_stream(handle, guard, 4, None),
        Err(DriverError::InvalidConfig)
    );
    // A guarded stream is not reconfigured (G-d2).
    assert_eq!(
        driver.reconfigure_stream(
            handle,
            Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 6,
            }
        ),
        Err(DriverError::InvalidConfig)
    );
    // A stream with an issued handle is not guarded after the fact.
    let late = stream(&mut driver, 4, PublicationMode::Exclusive, true);
    let _publication = driver.publication(late).unwrap();
    assert_eq!(
        driver.guard_stream(late, guard, 4, None),
        Err(DriverError::InvalidConfig)
    );
}

/// The walker reads for the driver, not for an application: a guarded
/// stream that refuses unconnected offers is still not connected.
#[test]
fn the_walker_does_not_connect_the_stream() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, false);
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(handle, guard, 4, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut publication = driver.publication(handle).unwrap();
    assert_eq!(publication.offer(b"a").unwrap(), OfferOutcome::NotConnected);
    assert!(!matches!(
        publication.offer(b"a"),
        Err(ClientError::OutcomesLost)
    ));
}

/// The driver walks every duty cycle, so the walker's hold on the floor
/// never stalls a publisher that reads its outcomes: many terms go by.
#[test]
fn the_walker_keeps_up_across_many_terms() {
    let (mut driver, handle, _guard) = guarded(4);
    let mut publication = driver.publication(handle).unwrap();
    let payload = vec![7u8; 1000];
    let total = 4 * MIN_TERM_LENGTH as usize / payload.len();
    let mut accepted = 0;
    let mut recorded = 0;
    let mut rounds = 0;
    while accepted < total {
        rounds += 1;
        assert!(rounds < 50 * total, "the publisher stalled at {accepted}");
        match publication.offer(&payload).unwrap() {
            OfferOutcome::Accepted { .. } => accepted += 1,
            OfferOutcome::BackPressured | OfferOutcome::AdminAction => {}
            other => panic!("unexpected {other:?}"),
        }
        let _ = driver.do_work().unwrap();
        recorded += outcomes(&mut publication).len();
    }
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    recorded += outcomes(&mut publication).len();
    assert_eq!(recorded, total, "one final record per message");
    assert_eq!(publication.guard().unwrap().outstanding(), 0);
}

fn read(subscription: &mut ClientSubscription) -> (Vec<Vec<u8>>, Option<SealReason>) {
    let mut seen = Vec::new();
    loop {
        let summary = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
            .unwrap();
        if summary.delivered == 0 && summary.aborted.is_none() {
            return (seen, summary.close_reason);
        }
    }
}

/// G-d2 (guards-and-abort.md, The fresh incarnation): after a close and a
/// reopen, the next handle publishes into a fresh incarnation that starts
/// at the seal position, with the next incarnation number; the old
/// subscriber reads to `GuardClosed`, and a new subscription reads only
/// the fresh incarnation.
#[test]
fn a_reopen_gives_the_next_handle_a_fresh_incarnation() {
    let (mut driver, handle, guard) = guarded(4);
    let mut old_reader = driver.subscribe(handle, Role::Optional).unwrap();
    let mut publication = driver.publication(handle).unwrap();
    let OfferOutcome::Accepted {
        position: first, ..
    } = publication.offer(b"one").unwrap()
    else {
        panic!("not accepted");
    };
    assert_eq!(driver.trace_identity(handle).unwrap().incarnation, 1);
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    assert_eq!(publication.offer(b"two").unwrap(), OfferOutcome::Gated);
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    let old: Vec<Kind> = outcomes(&mut publication).iter().map(|r| r.kind).collect();
    assert_eq!(old, [Kind::Submitted, Kind::Ended]);
    let (seen, closed) = read(&mut old_reader);
    assert_eq!(seen, [b"one".to_vec()]);
    assert_eq!(closed, Some(SealReason::GuardClosed));
    // Still closed: no fresh incarnation, nothing created.
    assert!(matches!(
        driver.publication(handle),
        Err(DriverError::GuardNotOpen { .. })
    ));
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let mut fresh = driver.publication(handle).unwrap();
    assert_eq!(driver.trace_identity(handle).unwrap().incarnation, 2);
    // The replaced incarnation's identity stays readable while it retires.
    assert_eq!(driver.trace_identity_at(handle, 1).unwrap().incarnation, 1);
    assert!(driver.trace_identity_at(handle, 3).is_err());
    let mut new_reader = driver.subscribe(handle, Role::Optional).unwrap();
    let OfferOutcome::Accepted { position, .. } = fresh.offer(b"three").unwrap() else {
        panic!("not accepted");
    };
    assert!(
        position > first,
        "positions continue: {position} after {first}"
    );
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    let records = outcomes(&mut fresh);
    assert_eq!(records.len(), 1);
    assert_eq!(
        (records[0].kind, records[0].incarnation),
        (Kind::Submitted, 2)
    );
    assert_eq!(records[0].epoch, 4);
    assert_eq!(records[0].start, position);
    let (seen, closed) = read(&mut new_reader);
    assert_eq!(seen, [b"three".to_vec()]);
    assert_eq!(closed, None);
    // The old handle stays gated, the old reader stays at its end.
    assert_eq!(publication.offer(b"four").unwrap(), OfferOutcome::Gated);
    assert_eq!(read(&mut old_reader).1, Some(SealReason::GuardClosed));
}

/// The fresh incarnation waits for the sealed one's publication to
/// release: before that the seal has no position.
#[test]
fn a_fresh_incarnation_waits_for_the_old_handle_to_release() {
    let (mut driver, handle, guard) = guarded(4);
    let publication = driver.publication(handle).unwrap();
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let _ = driver.do_work().unwrap();
    assert!(matches!(
        driver.publication(handle),
        Err(DriverError::GuardSealed { .. })
    ));
    drop(publication);
    let _ = driver.do_work().unwrap();
    assert!(driver.publication(handle).is_ok());
}

/// Review of #207, P2: a block its writer aborted is `WRITER_ABORTED` (6)
/// even when the guard closes before the walker reaches it; only the
/// blocks the close aborted are `GUARD_CLOSED` (1).
#[test]
fn a_writer_abort_keeps_its_reason_across_a_close() {
    let (mut driver, handle, guard) = guarded(4);
    let mut publication = driver.publication(handle).unwrap();
    let ClaimOutcome::Claimed(claim) = publication.try_claim(8).unwrap() else {
        panic!("not claimed");
    };
    // The writer drops its claim: its own abort.
    drop(claim);
    assert!(matches!(
        publication.offer(b"after").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::Gated);
    for _ in 0..3 {
        let _ = driver.do_work().unwrap();
    }
    let records = outcomes(&mut publication);
    let kinds: Vec<(Kind, u64)> = records.iter().map(|r| (r.kind, r.reason)).collect();
    assert_eq!(
        kinds,
        [(Kind::Aborted, 6), (Kind::Submitted, 0), (Kind::Ended, 1)],
        "{records:?}"
    );
}

/// Review of #209 (M4, and the fresh start): nothing is created while the
/// guard is closed, and the fresh incarnation starts exactly at the seal
/// position.
#[test]
fn the_fresh_incarnation_starts_at_the_seal_and_only_when_open() {
    let (mut driver, handle, guard) = guarded(4);
    let mut publication = driver.publication(handle).unwrap();
    for value in [b"a", b"b"] {
        assert!(matches!(
            publication.offer(value).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    drop(publication);
    let _ = driver.do_work().unwrap();
    let seal = match driver.seal_state(handle).unwrap() {
        SealState::Positioned { position } | SealState::Retired { position } => position,
        other => panic!("not positioned: {other:?}"),
    };
    for _ in 0..2 {
        assert!(matches!(
            driver.publication(handle),
            Err(DriverError::GuardNotOpen { .. })
        ));
        assert_eq!(driver.trace_identity(handle).unwrap().incarnation, 1);
    }
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let mut fresh = driver.publication(handle).unwrap();
    assert_eq!(driver.trace_identity(handle).unwrap().incarnation, 2);
    let OfferOutcome::Accepted { position, .. } = fresh.offer(b"c").unwrap() else {
        panic!("not accepted");
    };
    assert_eq!(position, seal, "the fresh incarnation starts at the seal");
    // Coordinator decision (ACS 15320): incarnation 2's seal is an absolute
    // stream position too, where incarnation 3 starts.
    assert_eq!(driver.close_guard(guard, 4), Ok(Closed::Now { epoch: 5 }));
    drop(fresh);
    let _ = driver.do_work().unwrap();
    let second = match driver.seal_state(handle).unwrap() {
        SealState::Positioned { position } | SealState::Retired { position } => position,
        other => panic!("not positioned: {other:?}"),
    };
    assert!(second > seal, "{second} after {seal}");
    assert_eq!(driver.reopen_guard(guard, 5, 5), Ok(6));
    let mut third = driver.publication(handle).unwrap();
    assert_eq!(driver.trace_identity(handle).unwrap().incarnation, 3);
    let OfferOutcome::Accepted { position, .. } = third.offer(b"d").unwrap() else {
        panic!("not accepted");
    };
    assert_eq!(position, second, "incarnation 3 starts at 2's seal");
}

/// Review of #209 (M5): with a walker budget of one block, the old readers
/// can pass the seal before the replaced walker reached it; the replaced
/// incarnation is kept until its walker wrote `Ended`.
#[test]
fn a_replaced_incarnation_is_kept_until_its_walker_ended() {
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        guard_walker_budget: 1,
        ..DriverConfig::default()
    })
    .unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(handle, guard, 4, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut publication = driver.publication(handle).unwrap();
    for value in [b"a", b"b", b"c"] {
        assert!(matches!(
            publication.offer(value).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::Gated);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let _fresh = driver.publication(handle).unwrap();
    // One block per cycle: Submitted three times, then Ended.
    let mut kinds = Vec::new();
    for _ in 0..8 {
        let _ = driver.do_work().unwrap();
        kinds.extend(outcomes(&mut publication).iter().map(|r| r.kind));
    }
    assert_eq!(
        kinds,
        [
            Kind::Submitted,
            Kind::Submitted,
            Kind::Submitted,
            Kind::Ended
        ]
    );
}

/// Review of #209, P2-1: a removed stream creates nothing; it stays at its
/// incarnation and refuses as a retiring stream.
#[test]
fn a_removed_guarded_stream_creates_no_incarnation() {
    let (mut driver, handle, guard) = guarded(4);
    let publication = driver.publication(handle).unwrap();
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    drop(publication);
    let _ = driver.do_work().unwrap();
    driver.remove_stream(handle).unwrap();
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    assert!(matches!(
        driver.publication(handle),
        Err(DriverError::StreamRetiring { .. })
    ));
    assert_eq!(driver.trace_identity(handle).unwrap().incarnation, 1);
}

/// ACS 15298: the walker holds one spare-slot credit for the stream's life,
/// and `guard_stream` names what it lacks. With 6 spare slots, 5 credits
/// are allowed: the exclusive publication's and 4 optional readers' use
/// them all, so the walker gets none; once a reader leaves, it does.
#[test]
fn guard_stream_names_the_walkers_missing_credit() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    let mut readers: Vec<_> = (0..4)
        .map(|_| driver.subscribe(handle, Role::Optional).unwrap())
        .collect();
    let stream_id = match driver.guard_stream(handle, guard, 4, None) {
        Err(DriverError::GuardWalkerUnavailable {
            stream,
            reason: WalkerUnavailable::NoSpareCredit,
        }) => stream,
        other => panic!("expected no spare credit, got {other:?}"),
    };
    assert_eq!(
        DriverError::GuardWalkerUnavailable {
            stream: stream_id,
            reason: WalkerUnavailable::NoSpareCredit,
        }
        .to_string(),
        format!("stream {stream_id}'s guard walker is unavailable: no spare-slot credit")
    );
    drop(readers.pop());
    let _ = driver.do_work().unwrap();
    driver.guard_stream(handle, guard, 4, None).unwrap();
}

/// A full cell table is told apart from a missing credit: required readers
/// take cells but no credit.
#[test]
fn guard_stream_names_the_walkers_missing_cell() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    let _readers: Vec<_> = (0..4)
        .map(|_| driver.subscribe(handle, Role::Required).unwrap())
        .collect();
    assert!(matches!(
        driver.guard_stream(handle, guard, 4, None),
        Err(DriverError::GuardWalkerUnavailable {
            reason: WalkerUnavailable::NoReaderCell,
            ..
        })
    ));
    assert_eq!(
        WalkerUnavailable::NoReaderCell.to_string(),
        "no reader cell"
    );
}

fn per_second(messages: u64, burst: u64, bytes: Option<(u64, u64)>) -> GuardRate {
    GuardRate::publication(RatePolicy {
        messages: Rate {
            per_second: messages,
            burst,
        },
        bytes: bytes.map(|(per_second, burst)| Rate { per_second, burst }),
    })
}

/// G-e3 (GC-5): only the publication scope is supported, and a policy is
/// validated against the stream's largest frame; nothing is guarded on a
/// refusal.
#[test]
fn guard_stream_validates_its_rate_limit() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    for scope in [
        RateScope::Strategy,
        RateScope::Account,
        RateScope::Destination,
    ] {
        let rate = GuardRate::scoped(scope, per_second(10, 1, None).policy);
        assert_eq!(
            driver.guard_stream(handle, guard, 4, Some(rate)),
            Err(DriverError::RateScopeUnsupported { scope })
        );
    }
    assert_eq!(
        driver.guard_stream(handle, guard, 4, Some(per_second(0, 1, None))),
        Err(DriverError::InvalidRatePolicy(RatePolicyError::Zero))
    );
    // The bound is the MTU, which no datagram exceeds: a byte burst of 64
    // cannot hold it, one byte short of the MTU neither.
    assert!(matches!(
        driver.guard_stream(handle, guard, 4, Some(per_second(10, 1, Some((1000, 64))))),
        Err(DriverError::InvalidRatePolicy(
            RatePolicyError::BurstBelowFrame { burst: 64, .. }
        ))
    ));
    let frame = u64::from(DEFAULT_MTU);
    assert!(matches!(
        driver.guard_stream(handle, guard, 4, Some(per_second(10, 2, Some((frame, frame - 1))))),
        Err(DriverError::InvalidRatePolicy(
            RatePolicyError::BurstBelowFrame { frame: f, .. }
        )) if f == frame
    ));
    driver
        .guard_stream(
            handle,
            guard,
            4,
            Some(per_second(10, 2, Some((frame, frame)))),
        )
        .unwrap();
}

/// Every handle bound to a rate-limited guard carries the copy, a fresh
/// incarnation's too: past the burst it refuses early and appends nothing.
#[test]
fn a_rate_limited_handle_refuses_past_its_burst() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    // One message a second: no refill during the test.
    driver
        .guard_stream(handle, guard, 4, Some(per_second(1, 2, None)))
        .unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut publication = driver.publication(handle).unwrap();
    for value in [b"a", b"b"] {
        assert!(matches!(
            publication.offer(value).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert_eq!(publication.offer(b"c").unwrap(), OfferOutcome::RateLimited);
    assert!(matches!(
        publication.try_claim(8).unwrap(),
        ClaimOutcome::RateLimited
    ));
    let _ = driver.do_work().unwrap();
    assert_eq!(
        outcomes(&mut publication).len(),
        2,
        "two messages, two records"
    );
    assert_eq!(driver.close_guard(guard, 2), Ok(Closed::Now { epoch: 3 }));
    drop(publication);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
    let mut fresh = driver.publication(handle).unwrap();
    assert_eq!(fresh.guard().unwrap().rate_tokens(), Some(2));
    for value in [b"d", b"e"] {
        assert!(matches!(
            fresh.offer(value).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    assert_eq!(fresh.offer(b"f").unwrap(), OfferOutcome::RateLimited);
}

/// R-CORE-21: a guarded stream's rate policy changes by version (compare
/// and set). The safety path takes only a tightening that keeps the
/// control reserve; an administrator takes any valid policy above it.
/// Every call is audited with the versions before and after, and a
/// refusal changes nothing.
#[test]
fn a_rate_policy_changes_by_version_under_its_authority() {
    use karyos_driver::{AuditOutcome, RateAuthority, RateChangeError};
    use karyos_protocol::cnc::ErrorCode;

    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    let reserve = Rate {
        per_second: 5,
        burst: 2,
    };
    // A reserve the policy itself crosses is refused when guarding.
    assert_eq!(
        driver.guard_stream(
            handle,
            guard,
            4,
            Some(per_second(4, 2, None).with_reserve(reserve))
        ),
        Err(DriverError::RateChange(RateChangeError::ReserveCrossed))
    );
    driver
        .guard_stream(
            handle,
            guard,
            4,
            Some(per_second(100, 10, None).with_reserve(reserve)),
        )
        .unwrap();
    let safety = |operation| (RateAuthority::Safety, operation);
    let admin = |operation| (RateAuthority::Administrator, operation);
    let change = |driver: &mut EmbeddedDriver, expected, policy: GuardRate, by| {
        driver.change_rate_policy(handle, expected, policy.policy, by)
    };
    // Version 1 at guarding; a tightening on the safety path makes 2.
    assert_eq!(
        change(&mut driver, 1, per_second(50, 10, None), safety(1)),
        Ok(2)
    );
    // A stale version is refused.
    assert_eq!(
        change(&mut driver, 1, per_second(40, 10, None), safety(2)),
        Err(DriverError::RateChange(RateChangeError::VersionMismatch {
            expected: 1,
            current: 2
        }))
    );
    // A loosening, or a mixed change, is not the safety path's.
    assert_eq!(
        change(&mut driver, 2, per_second(60, 10, None), safety(3)),
        Err(DriverError::RateChange(RateChangeError::NotATightening))
    );
    assert_eq!(
        change(&mut driver, 2, per_second(40, 20, None), safety(4)),
        Err(DriverError::RateChange(RateChangeError::NotATightening))
    );
    // A tightening below the reserve is refused whatever the authority.
    assert_eq!(
        change(&mut driver, 2, per_second(4, 10, None), safety(5)),
        Err(DriverError::RateChange(RateChangeError::ReserveCrossed))
    );
    assert_eq!(
        change(&mut driver, 2, per_second(50, 1, None), admin(6)),
        Err(DriverError::RateChange(RateChangeError::ReserveCrossed))
    );
    // An administrator loosens; an unchanged policy keeps the version.
    assert_eq!(
        change(&mut driver, 2, per_second(200, 20, None), admin(7)),
        Ok(3)
    );
    assert_eq!(
        change(&mut driver, 3, per_second(200, 20, None), safety(8)),
        Ok(3)
    );
    // A policy the stream refuses is refused, audited with its own code.
    assert!(matches!(
        change(&mut driver, 3, per_second(0, 0, None), admin(9)),
        Err(DriverError::InvalidRatePolicy(_))
    ));
    let audit: Vec<_> = driver
        .guard_audit()
        .records
        .iter()
        .map(|record| {
            (
                record.operation,
                record.before,
                record.after,
                record.outcome,
            )
        })
        .collect();
    let refused = |code| AuditOutcome::Refused(code);
    let changed = |authority| AuditOutcome::RateChanged { authority };
    let unchanged = |authority| AuditOutcome::RateUnchanged { authority };
    assert_eq!(
        audit,
        [
            (1, 1, 2, changed(RateAuthority::Safety)),
            (2, 2, 2, refused(ErrorCode::RateVersionMismatch)),
            (3, 2, 2, refused(ErrorCode::RateNotATightening)),
            (4, 2, 2, refused(ErrorCode::RateNotATightening)),
            (5, 2, 2, refused(ErrorCode::RateReserveCrossed)),
            (6, 2, 2, refused(ErrorCode::RateReserveCrossed)),
            (7, 2, 3, changed(RateAuthority::Administrator)),
            (8, 3, 3, unchanged(RateAuthority::Safety)),
            (9, 3, 3, refused(ErrorCode::RateInvalidPolicy)),
        ]
    );
    // A stream guarded without a rate has none to change.
    let other = stream(&mut driver, 3, PublicationMode::Exclusive, true);
    driver.guard_stream(other, guard, 4, None).unwrap();
    assert_eq!(
        driver.change_rate_policy(other, 0, per_second(1, 1, None).policy, admin(10)),
        Err(DriverError::RateChange(RateChangeError::NoRate))
    );
}

/// R-CORE-21: a change binds the handles already issued: a spent handle
/// reads the published policy on its slow path and earns at the new rate.
#[test]
fn a_rate_policy_change_reaches_an_issued_handle() {
    use karyos_driver::RateAuthority;

    let mut driver = EmbeddedDriver::new().unwrap();
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    let guard = driver.add_guard("orders").unwrap();
    // One message a second, a burst of one: no refill between the offers.
    driver
        .guard_stream(handle, guard, 4, Some(per_second(1, 1, None)))
        .unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    let mut publication = driver.publication(handle).unwrap();
    assert!(matches!(
        publication.offer(b"a").unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert_eq!(publication.offer(b"b").unwrap(), OfferOutcome::RateLimited);
    // A million a second: the handle earns a token within microseconds.
    assert_eq!(
        driver.change_rate_policy(
            handle,
            1,
            per_second(1_000_000, 1, None).policy,
            (RateAuthority::Administrator, 1),
        ),
        Ok(2)
    );
    let start = std::time::Instant::now();
    let accepted = loop {
        match publication.offer(b"b").unwrap() {
            OfferOutcome::Accepted { .. } => break true,
            OfferOutcome::RateLimited if start.elapsed().as_millis() < 500 => {}
            _ => break false,
        }
    };
    assert!(accepted, "the handle applied the new policy");
}

/// R-CORE-21, review B3 of #814: a per-stream change on a lane of an
/// aggregate of several lanes changes every lane, so the lanes' versions
/// never part and the aggregate's next change is served. A call refused
/// before its policy is weighed, an aggregate with an unguarded lane, is
/// audited too.
#[test]
fn a_change_on_one_lane_changes_its_aggregate() {
    use karyos_driver::{AggregateConfig, AuditOutcome, RateAuthority, RateChangeError};
    use karyos_protocol::cnc::ErrorCode;

    let mut driver = EmbeddedDriver::new().unwrap();
    let config = |stream_id| AggregateConfig {
        stream: StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 6,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
            conflation: None,
        },
        quanta: vec![u64::from(DEFAULT_MTU) * 4; 2],
    };
    let lane = |aggregate: &karyos_driver::AggregateHandle, lane| {
        aggregate.lane(Lane::try_new(lane).unwrap()).unwrap()
    };
    let aggregate = driver.add_aggregate(config(2)).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    for number in 0..2 {
        driver
            .guard_stream(
                lane(&aggregate, number),
                guard,
                4,
                Some(per_second(100, 10, None)),
            )
            .unwrap();
    }
    let admin = |operation| (RateAuthority::Administrator, operation);
    assert_eq!(
        driver.change_rate_policy(
            lane(&aggregate, 1),
            1,
            per_second(50, 10, None).policy,
            admin(1)
        ),
        Ok(2)
    );
    assert_eq!(
        driver.change_aggregate_rate_policy(
            &aggregate,
            2,
            per_second(40, 10, None).policy,
            admin(2)
        ),
        Ok(3)
    );
    // Review N2 of #814: lane 1 of another aggregate is not guarded; its
    // guarded lane still changes, alone, on the safety path too.
    let partial = driver.add_aggregate(config(3)).unwrap();
    driver
        .guard_stream(lane(&partial, 0), guard, 4, Some(per_second(100, 10, None)))
        .unwrap();
    let safety = |operation| (RateAuthority::Safety, operation);
    assert_eq!(
        driver.change_rate_policy(
            lane(&partial, 0),
            1,
            per_second(40, 10, None).policy,
            safety(3)
        ),
        Ok(2)
    );
    assert_eq!(
        driver.change_aggregate_rate_policy(
            &partial,
            2,
            per_second(30, 10, None).policy,
            safety(4)
        ),
        Ok(3)
    );
    let last = *driver.guard_audit().records.last().unwrap();
    assert_eq!(
        (last.operation, last.before, last.after, last.outcome),
        (
            4,
            2,
            3,
            AuditOutcome::RateChanged {
                authority: RateAuthority::Safety
            }
        )
    );
    // An aggregate with no guarded lane has no rate to change.
    let bare = driver.add_aggregate(config(4)).unwrap();
    assert_eq!(
        driver.change_aggregate_rate_policy(&bare, 0, per_second(30, 10, None).policy, safety(5)),
        Err(DriverError::RateChange(RateChangeError::NoRate))
    );
    let _ = ErrorCode::RateNotSet;
}

/// Review N1 of #814: an aggregate change is weighed on each guarded lane
/// with its own policy and reserve, and taken by all of them or none. A
/// safety change that tightens lane 0 but loosens lane 1 is refused for
/// both, and audited for each guard.
#[test]
fn an_aggregate_change_is_weighed_on_every_lane() {
    use karyos_driver::{AggregateConfig, AuditOutcome, RateAuthority, RateChangeError};
    use karyos_protocol::cnc::ErrorCode;

    let mut driver = EmbeddedDriver::new().unwrap();
    let mut stream = StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        conflation: None,
    };
    stream.buffer.stream_id = 2;
    let aggregate = driver
        .add_aggregate(AggregateConfig {
            stream,
            quanta: vec![u64::from(DEFAULT_MTU) * 4; 2],
        })
        .unwrap();
    let lane = |number| aggregate.lane(Lane::try_new(number).unwrap()).unwrap();
    let (a, b) = (
        driver.add_guard("a").unwrap(),
        driver.add_guard("b").unwrap(),
    );
    let reserve = Rate {
        per_second: 10,
        burst: 2,
    };
    driver
        .guard_stream(lane(0), a, 4, Some(per_second(100, 10, None)))
        .unwrap();
    driver
        .guard_stream(
            lane(1),
            b,
            4,
            Some(per_second(20, 10, None).with_reserve(reserve)),
        )
        .unwrap();
    let safety = |operation| (RateAuthority::Safety, operation);
    let admin = |operation| (RateAuthority::Administrator, operation);
    assert_eq!(
        driver.change_aggregate_rate_policy(
            &aggregate,
            1,
            per_second(50, 10, None).policy,
            safety(1)
        ),
        Err(DriverError::RateChange(RateChangeError::NotATightening))
    );
    // Lane 1's reserve is weighed too, under any authority.
    assert_eq!(
        driver.change_aggregate_rate_policy(
            &aggregate,
            1,
            per_second(5, 10, None).policy,
            admin(2)
        ),
        Err(DriverError::RateChange(RateChangeError::ReserveCrossed))
    );
    // Nothing changed: both lanes are still at version 1.
    assert_eq!(
        driver.change_aggregate_rate_policy(
            &aggregate,
            1,
            per_second(15, 10, None).policy,
            safety(3)
        ),
        Ok(2)
    );
    let audit: Vec<_> = driver
        .guard_audit()
        .records
        .iter()
        .map(|record| {
            (
                record.operation,
                record.guard,
                record.before,
                record.after,
                record.outcome,
            )
        })
        .collect();
    let refused = AuditOutcome::Refused;
    let changed = AuditOutcome::RateChanged {
        authority: RateAuthority::Safety,
    };
    let (a, b) = (a.id(), b.id());
    assert_eq!(
        audit[audit.len() - 6..],
        [
            (1, a, 1, 1, refused(ErrorCode::RateNotATightening)),
            (1, b, 1, 1, refused(ErrorCode::RateNotATightening)),
            (2, a, 1, 1, refused(ErrorCode::RateReserveCrossed)),
            (2, b, 1, 1, refused(ErrorCode::RateReserveCrossed)),
            (3, a, 1, 2, changed),
            (3, b, 1, 2, changed),
        ]
    );
}
