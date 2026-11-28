// SPDX-License-Identifier: Apache-2.0

//! ADR-0126 at the opener and the pool: arrival order, the full table,
//! cancellation, leases, the re-check at completion and the open rate.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::cell::Cell;

use karyos_protocol::protection::aes_gcm_siv::{
    Domain, EncRejection, KeyContext, MAX_PLAINTEXT, PublicationIdentity, Salt,
};
use karyos_sys::alloc_count::count_allocations;

use super::super::{
    COMMITTED_OPENS_PER_S, ChannelKeys, EncOpener, EncSealer, KEY_AGE_NS, KeyKind, MAX_SEALED,
    OpenRate, Prepared, SECOND_NS, Ticket,
};
use super::{
    Done, EncVerifyConfig, MAX_ENC_VERIFIERS, MAX_ENC_VERIFY_SLOTS, Outcome, VerifyPool,
    enc_verify_inline_fallbacks,
};
use crate::wire_keys::{KEY_LEN, parse};

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(1_000 * SECOND_NS) };
}

fn clock() -> u64 {
    NOW.with(Cell::get)
}

fn set_now(now: u64) {
    NOW.with(|cell| cell.set(now));
}

fn keys(fill: u8) -> ChannelKeys {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=6\n"
    );
    ChannelKeys::new(&[&parse("3-1.key", text.as_bytes()).unwrap()]).unwrap()
}

fn context() -> KeyContext {
    KeyContext {
        domain: Domain::Sender,
        key_epoch: 1,
        party_epoch: 0,
        session_id: 9,
        stream_id: 6,
        publication: PublicationIdentity {
            driver_id: [1; 16],
            registration_id: 7,
            incarnation: 1,
        },
        receiver: None,
        salt: Salt::Challenge {
            receiver_boot_id: [2; 16],
            nonce: [3; 16],
        },
    }
}

/// One 32-byte DATA frame whose body is `body`.
fn frame(body: u8) -> [u8; 32] {
    let mut out = [body; 32];
    out[..4].copy_from_slice(&32_i32.to_le_bytes());
    out[4] = 1;
    out[5] = 0;
    out[6..8].copy_from_slice(&1_u16.to_le_bytes());
    out
}

/// The next datagram of `sealer`, one DATA frame of `body`.
fn seal(sealer: &mut EncSealer, body: u8) -> Vec<u8> {
    let mut bytes = vec![0_u8; MAX_SEALED];
    bytes[..32].copy_from_slice(&frame(body));
    let length = sealer.seal(&mut bytes, 32).unwrap();
    bytes.truncate(length);
    bytes
}

/// `count` datagrams sealed under the channel key of `fill`, the `i`th
/// one DATA frame of body `i`: genuine under 0x11, forged under any
/// other.
fn sealed(fill: u8, count: usize) -> Vec<Vec<u8>> {
    let mut sealer = EncSealer::new(&keys(fill), None, context(), clock).unwrap();
    (0..count)
        .map(|i| seal(&mut sealer, u8::try_from(i % 251).unwrap()))
        .collect()
}

fn opener() -> EncOpener {
    EncOpener::new(&keys(0x11), None, context(), clock()).unwrap()
}

type Job = (u32, Ticket);

fn pool(slots: u16, verifiers: u16, spawn: bool) -> VerifyPool<Job> {
    VerifyPool::new(EncVerifyConfig { verifiers, slots }, spawn).unwrap()
}

/// Prepares `bytes` and dispatches it as job `tag`.
fn dispatch(
    pool: &mut VerifyPool<Job>,
    opener: &mut EncOpener,
    rate: &mut OpenRate,
    bytes: &[u8],
    tag: u32,
) -> Result<(), EncRejection> {
    match opener.prepare(bytes, rate, clock())? {
        Prepared::Dispatch(ticket, lease) => pool
            .dispatch(bytes, lease, (tag, ticket))
            .map_err(|_| EncRejection::VerifyBusy),
        Prepared::Inline => panic!("a committed key is dispatched"),
    }
}

/// Re-checks and commits a consumed job, as a role does; its tag.
fn finish(opener: &mut EncOpener, done: Done<Job>) -> Result<u32, EncRejection> {
    let Done {
        context: (tag, ticket),
        outcome,
        lease,
        header,
        len,
    } = done;
    let opened = match outcome {
        Outcome::Verified(opened) => opened,
        Outcome::Failed(reason) => return Err(reason),
        Outcome::Cancelled => return Err(EncRejection::Withdrawn),
    };
    let lease = lease.unwrap();
    let pending = opener.complete(&ticket, &lease, &opened, (&header, len), clock())?;
    drop(lease);
    opener.commit(pending).map(|_| tag)
}

#[test]
fn a_verifier_pool_config_is_validated() {
    assert_eq!(EncVerifyConfig::default().verifiers, 0, "off by default");
    assert_eq!(EncVerifyConfig::default().validate(), Ok(()));
    let config = |verifiers, slots| EncVerifyConfig { verifiers, slots };
    assert_eq!(
        config(MAX_ENC_VERIFIERS, MAX_ENC_VERIFY_SLOTS).validate(),
        Ok(())
    );
    assert!(config(MAX_ENC_VERIFIERS + 1, 64).validate().is_err());
    assert!(config(2, 0).validate().is_err());
    assert!(config(2, MAX_ENC_VERIFY_SLOTS + 1).validate().is_err());
}

/// Decision 4: results are consumed in arrival order; a delayed first job
/// holds back the later ones, done or not, and nothing allocates.
#[test]
fn a_delayed_first_job_holds_back_the_later_ones() {
    let mut opener = opener();
    let mut rate = OpenRate::default();
    let mut pool = pool(8, 0, false);
    let datagrams = sealed(0x11, 3);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let ((), allocations) = count_allocations(|| {
        for (tag, bytes) in (0_u32..).zip(&datagrams) {
            dispatch(&mut pool, &mut opener, &mut rate, bytes, tag).unwrap();
        }
        // The later two are verified; the first is not yet.
        assert!(pool.verify_at(1));
        assert!(pool.verify_at(2));
        assert!(pool.take(&mut plain).is_none(), "the first holds them back");
        assert_eq!(pool.in_flight(), 3);
        assert!(pool.verify_at(0));
        for expected in 0..3 {
            let done = pool.take(&mut plain).unwrap();
            assert_eq!(finish(&mut opener, done), Ok(expected));
            assert_eq!(&plain[..32], &frame(u8::try_from(expected).unwrap()));
        }
        assert!(pool.take(&mut plain).is_none());
    });
    assert_eq!(allocations, 0, "dispatch, verification and consumption");
    assert_eq!(opener.leases(), 0);
}

/// Decision 4: with no free slot the datagram is dropped before dispatch,
/// its lease returned; a freed slot takes the next one. Nothing
/// allocates.
#[test]
fn a_full_slot_table_drops_before_dispatch() {
    let mut opener = opener();
    let mut rate = OpenRate::default();
    let mut pool = pool(2, 0, false);
    let datagrams = sealed(0x11, 4);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let ((), allocations) = count_allocations(|| {
        dispatch(&mut pool, &mut opener, &mut rate, &datagrams[0], 0).unwrap();
        dispatch(&mut pool, &mut opener, &mut rate, &datagrams[1], 1).unwrap();
        assert_eq!(opener.leases(), 2);
        assert_eq!(
            dispatch(&mut pool, &mut opener, &mut rate, &datagrams[2], 2),
            Err(EncRejection::VerifyBusy)
        );
        assert_eq!(opener.leases(), 2, "the refused job's lease is back");
        let done = pool.take_waiting(&mut plain).unwrap();
        assert_eq!(finish(&mut opener, done), Ok(0));
        dispatch(&mut pool, &mut opener, &mut rate, &datagrams[3], 3).unwrap();
        for expected in [1, 3] {
            let done = pool.take_waiting(&mut plain).unwrap();
            assert_eq!(finish(&mut opener, done), Ok(expected));
        }
    });
    assert_eq!(allocations, 0);
    assert_eq!(opener.leases(), 0);
    // The dropped one was never marked: it still verifies.
    let mut out = [0_u8; MAX_PLAINTEXT];
    assert!(
        opener
            .open(&datagrams[2], &mut out, &mut rate, clock(), |_| Ok(()))
            .is_ok()
    );
}

/// Decision 5: a cancelled job and a job whose opener is withdrawn before
/// a verifier starts it end cancelled, are never opened, and return their
/// leases; a running one finishes. Nothing allocates.
#[test]
fn cancelled_and_withdrawn_jobs_end_cancelled() {
    let mut opener = opener();
    let mut rate = OpenRate::default();
    let mut pool = pool(8, 0, false);
    let datagrams = sealed(0x11, 4);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let ((), allocations) = count_allocations(|| {
        for (tag, bytes) in (0_u32..).zip(&datagrams) {
            dispatch(&mut pool, &mut opener, &mut rate, bytes, tag).unwrap();
        }
        assert!(pool.verify_at(0), "already done before the cancel");
        assert_eq!(pool.cancel_where(|(tag, _)| *tag == 1), 1);
        assert_eq!(
            pool.cancel_where(|(tag, _)| *tag == 0),
            0,
            "done: not cancelled"
        );
        assert!(!pool.verify_at(1), "a cancelled job is never run");
        let done = pool.take(&mut plain).unwrap();
        assert_eq!(finish(&mut opener, done), Ok(0));
        let done = pool.take(&mut plain).unwrap();
        assert_eq!(done.outcome, Outcome::Cancelled);
        drop(done);
    });
    assert_eq!(allocations, 0);
    // Withdrawn while two are queued: the verifier reads the mark first.
    let key = opener.current_key();
    opener.withdraw();
    assert_eq!(opener.leases(), 2);
    let held = key.upgrade().expect("held by the queued jobs' leases");
    assert_eq!(
        held.context(),
        &context(),
        "not erased while a lease is out"
    );
    drop(held);
    assert!(pool.verify_one());
    assert!(pool.verify_one());
    for _ in 0..2 {
        let done = pool.take(&mut plain).unwrap();
        assert_eq!(done.outcome, Outcome::Cancelled);
    }
    assert_eq!(opener.leases(), 0);
    assert!(
        key.upgrade().is_none(),
        "erased once the last lease returned"
    );
}

/// Decision 5: every lease returns exactly once, whatever the outcome:
/// committed, refused by the open, refused at the re-check, cancelled,
/// dropped before dispatch, and still in flight when the pool stops.
#[test]
fn leases_return_exactly_once_on_every_path() {
    let mut opener = opener();
    let mut rate = OpenRate::default();
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let genuine = sealed(0x11, 4);
    let forged = sealed(0x99, 1);
    {
        let mut pool = pool(3, 2, true);
        dispatch(&mut pool, &mut opener, &mut rate, &genuine[0], 0).unwrap();
        dispatch(&mut pool, &mut opener, &mut rate, &forged[0], 1).unwrap();
        dispatch(&mut pool, &mut opener, &mut rate, &genuine[0], 2).unwrap();
        assert_eq!(
            dispatch(&mut pool, &mut opener, &mut rate, &genuine[1], 3),
            Err(EncRejection::VerifyBusy)
        );
        assert_eq!(opener.leases(), 3);
        let done = pool.take_waiting(&mut plain).unwrap();
        assert_eq!(finish(&mut opener, done), Ok(0));
        let done = pool.take_waiting(&mut plain).unwrap();
        assert_eq!(finish(&mut opener, done), Err(EncRejection::Tag));
        // A second copy of a committed sequence: refused at the re-check.
        let done = pool.take_waiting(&mut plain).unwrap();
        assert_eq!(finish(&mut opener, done), Err(EncRejection::Duplicate));
        assert_eq!(opener.leases(), 0);
        dispatch(&mut pool, &mut opener, &mut rate, &genuine[2], 4).unwrap();
        dispatch(&mut pool, &mut opener, &mut rate, &genuine[3], 5).unwrap();
        let _ = pool.cancel_where(|_| true);
        assert_eq!(opener.leases(), 2);
        // Dropped with both in flight.
    }
    assert_eq!(opener.leases(), 0, "the stopped pool returned every lease");
    // Never committed: both still verify.
    let mut out = [0_u8; MAX_PLAINTEXT];
    for bytes in &genuine[2..] {
        assert!(
            opener
                .open(bytes, &mut out, &mut rate, clock(), |_| Ok(()))
                .is_ok()
        );
    }
}

/// Decision 3: a withdrawal while a verified result waits refuses it and
/// commits nothing; the key it held is erased only once its lease
/// returns. A promotion while a job is in flight keeps its key as the
/// previous epoch's, so it still commits there.
#[test]
fn a_change_while_a_job_is_in_flight_is_checked_again() {
    let mut rate = OpenRate::default();
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let datagrams = sealed(0x11, 2);
    let mut pool = pool(4, 0, false);
    let mut opener = opener();
    dispatch(&mut pool, &mut opener, &mut rate, &datagrams[0], 0).unwrap();
    assert!(pool.verify_one());
    let key = opener.current_key();
    opener.withdraw();
    assert!(key.upgrade().is_some(), "held by the verified job's lease");
    let done = pool.take(&mut plain).unwrap();
    assert_eq!(finish(&mut opener, done), Err(EncRejection::Withdrawn));
    assert_eq!(opener.leases(), 0);
    assert!(key.upgrade().is_none(), "erased at zero");

    // A promotion in flight: the job's key becomes the previous epoch's.
    let mut opener = fresh_opener();
    let mut sealer = EncSealer::new(&keys(0x11), None, context(), clock).unwrap();
    let first = seal(&mut sealer, 1);
    sealer.roll_now();
    let next = seal(&mut sealer, 2);
    dispatch(&mut pool, &mut opener, &mut rate, &first, 7).unwrap();
    let mut out = [0_u8; MAX_PLAINTEXT];
    assert!(
        opener
            .open(&next, &mut out, &mut rate, clock(), |_| Ok(()))
            .unwrap()
            .promoted
    );
    let done = pool.take_waiting(&mut plain).unwrap();
    assert_eq!(finish(&mut opener, done), Ok(7));
    assert_eq!(opener.leases(), 0);
}

/// [`opener`], where a binding shadows it.
fn fresh_opener() -> EncOpener {
    opener()
}

/// Decisions 2 and 3 at the age boundary: a job dispatched at the last
/// nanosecond of its key's age is refused when it completes after it,
/// and one dispatched after it is refused before its open.
#[test]
fn a_key_past_its_age_at_completion_is_refused() {
    let start = clock();
    let mut opener = opener();
    let mut rate = OpenRate::default();
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let mut pool = pool(4, 0, false);
    let datagrams = sealed(0x11, 3);
    set_now(start + KEY_AGE_NS);
    dispatch(&mut pool, &mut opener, &mut rate, &datagrams[0], 0).unwrap();
    dispatch(&mut pool, &mut opener, &mut rate, &datagrams[1], 1).unwrap();
    let done = pool.take_waiting(&mut plain).unwrap();
    assert_eq!(finish(&mut opener, done), Ok(0), "within its age");
    set_now(start + KEY_AGE_NS + 1);
    let done = pool.take_waiting(&mut plain).unwrap();
    assert_eq!(finish(&mut opener, done), Err(EncRejection::KeyAge));
    assert_eq!(
        dispatch(&mut pool, &mut opener, &mut rate, &datagrams[2], 2),
        Err(EncRejection::KeyAge)
    );
    assert_eq!(opener.leases(), 0);
    set_now(start);
}

/// Decision 2: the open rate is charged on the role thread before
/// dispatch, so the channel's aggregate limit is one count whatever the
/// verifier count: a flood with `COMMITTED_OPENS_PER_S - 100` already
/// charged dispatches exactly 100 opens while the verifiers run, and the
/// rest is refused before any open; the next second starts again.
#[test]
fn the_open_rate_is_one_aggregate_count_under_a_concurrent_flood() {
    let mut opener = opener();
    let mut pool = pool(128, 3, true);
    assert_eq!(pool.verifiers(), 3);
    let forged = sealed(0x99, 1_000);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let mut rate = OpenRate {
        interval: clock() / SECOND_NS,
        committed: COMMITTED_OPENS_PER_S - 100,
        ..OpenRate::default()
    };
    let (mut dispatched, mut over, mut refused) = (0, 0, 0);
    for (tag, bytes) in (0_u32..).zip(&forged) {
        match dispatch(&mut pool, &mut opener, &mut rate, bytes, tag) {
            Ok(()) => dispatched += 1,
            Err(EncRejection::OpenRate) => over += 1,
            Err(EncRejection::VerifyBusy) => panic!("128 slots hold every dispatched job"),
            Err(other) => panic!("{other:?}"),
        }
        // Consume what the verifiers finished, as the role does.
        while let Some(done) = pool.take(&mut plain) {
            assert_eq!(finish(&mut opener, done), Err(EncRejection::Tag));
            refused += 1;
        }
    }
    while let Some(done) = pool.take_waiting(&mut plain) {
        assert_eq!(finish(&mut opener, done), Err(EncRejection::Tag));
        refused += 1;
    }
    assert_eq!((dispatched, over, refused), (100, 900, 100));
    assert_eq!(rate.charged(KeyKind::Committed), COMMITTED_OPENS_PER_S);
    assert_eq!(opener.leases(), 0);
    set_now(clock() + SECOND_NS);
    dispatch(&mut pool, &mut opener, &mut rate, &forged[0], 0).unwrap();
    assert_eq!(rate.charged(KeyKind::Committed), 1, "the next second");
    let done = pool.take_waiting(&mut plain).unwrap();
    assert_eq!(finish(&mut opener, done), Err(EncRejection::Tag));
    set_now(clock() - SECOND_NS);
}

/// Review of #1298, finding 2: a verifier that starts after one that
/// failed parks on its own index and is woken by each dispatch, so the
/// role never runs a job itself; with no verifier started there is no
/// pool and the role opens inline, counted.
#[test]
fn a_verifier_started_after_a_failed_one_is_woken() {
    let mut opener = opener();
    let mut rate = OpenRate::default();
    let config = EncVerifyConfig {
        verifiers: 3,
        slots: 4,
    };
    let mut pool = VerifyPool::<Job>::start(config, true, |me| me != 2).unwrap();
    assert_eq!(pool.verifiers(), 1);
    let datagrams = sealed(0x11, 16);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let deadline = || std::time::Instant::now() + std::time::Duration::from_secs(5);
    for (tag, bytes) in (0_u32..).zip(&datagrams) {
        let until = deadline();
        while !pool.shared.sleeping[2].load(core::sync::atomic::Ordering::SeqCst) {
            assert!(std::time::Instant::now() < until, "the verifier parks");
            std::thread::yield_now();
        }
        dispatch(&mut pool, &mut opener, &mut rate, bytes, tag).unwrap();
        let until = deadline();
        let done = loop {
            if let Some(done) = pool.take(&mut plain) {
                break done;
            }
            assert!(
                std::time::Instant::now() < until,
                "job {tag}: the parked verifier was never woken"
            );
            std::thread::yield_now();
        };
        assert_eq!(finish(&mut opener, done), Ok(tag));
    }
    assert_eq!(opener.leases(), 0);
    let before = enc_verify_inline_fallbacks();
    assert!(VerifyPool::<Job>::start(config, true, |_| true).is_none());
    assert!(enc_verify_inline_fallbacks() > before);
}

/// Review of #1298, finding 3: every slot's mutex is set up with the
/// pool, so the first dispatch into each cold slot, its verification and
/// its consumption allocate nothing (a lazily boxed pthread mutex on
/// macOS would allocate at its first lock).
#[test]
fn every_cold_slot_is_used_without_allocating() {
    let mut opener = opener();
    let mut rate = OpenRate::default();
    let mut pool = pool(64, 0, false);
    let datagrams = sealed(0x11, 64);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let ((), allocations) = count_allocations(|| {
        for (tag, bytes) in (0_u32..).zip(&datagrams) {
            dispatch(&mut pool, &mut opener, &mut rate, bytes, tag).unwrap();
        }
        for expected in 0..64 {
            let done = pool.take_waiting(&mut plain).unwrap();
            assert_eq!(finish(&mut opener, done), Ok(expected));
        }
    });
    assert_eq!(allocations, 0, "64 cold slots");
    assert_eq!(opener.leases(), 0);
}
