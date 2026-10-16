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
    DriverConfig, DriverError, EmbeddedDriver, Reconfiguration, SealState, StreamConfig,
    StreamHandle, WalkerUnavailable,
};
use karyos_sys::frame::Lane;
use karyos_sys::guard::Closed;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::log_buffer::{Role, SealReason};
use karyos_sys::outcome_ring::{Kind, Record};
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
    driver.guard_stream(handle, guard, messages).unwrap();
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
    driver.guard_stream(handle, guard, 4).unwrap();
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
        driver.guard_stream(concurrent, guard, 4),
        Err(DriverError::InvalidPublicationMode)
    );
    let handle = stream(&mut driver, 2, PublicationMode::Exclusive, true);
    assert_eq!(
        driver.guard_stream(handle, guard, 0),
        Err(DriverError::InvalidConfig)
    );
    // max_reserved is an eighth of a term: five do not fit half a term.
    assert_eq!(
        driver.guard_stream(handle, guard, 5),
        Err(DriverError::InvalidConfig)
    );
    driver.guard_stream(handle, guard, 4).unwrap();
    assert_eq!(
        driver.guard_stream(handle, guard, 4),
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
        driver.guard_stream(late, guard, 4),
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
    driver.guard_stream(handle, guard, 4).unwrap();
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
    driver.guard_stream(handle, guard, 4).unwrap();
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
    let stream_id = match driver.guard_stream(handle, guard, 4) {
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
    driver.guard_stream(handle, guard, 4).unwrap();
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
        driver.guard_stream(handle, guard, 4),
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
