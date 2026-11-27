// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use karyos_protocol::network::Receiver;
use karyos_protocol::network::authenticated::{GuardState, GuardStatus, GuardWord};

use super::*;
use crate::wire_keys::store::{FileError, Files};

const MS: u64 = 1_000_000;

const RECEIVER: Receiver = Receiver {
    receiver_boot_id: [7, 8],
    receiver_id: 66,
};

/// Marks in memory; `fail` makes every commit fail, `unreadable` every
/// read.
#[derive(Debug, Default)]
pub(crate) struct Marks {
    pub(crate) held: HashMap<u64, u64>,
    pub(crate) latched: HashSet<u64>,
    pub(crate) fail: bool,
    pub(crate) unreadable: bool,
}

impl MarkStore for Marks {
    fn load(&self, guard_id: u64) -> Result<u64, MarkError> {
        if self.unreadable {
            return Err(MarkError::Unreadable);
        }
        Ok(self.held.get(&guard_id).copied().unwrap_or(0))
    }

    fn latched(&self, guard_id: u64) -> Result<bool, MarkError> {
        if self.unreadable {
            return Err(MarkError::Unreadable);
        }
        Ok(self.latched.contains(&guard_id))
    }

    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), MarkError> {
        if self.fail {
            return Err(MarkError::Commit);
        }
        let held = self.held.entry(guard_id).or_insert(0);
        *held = (*held).max(epoch);
        Ok(())
    }

    fn latch(&mut self, guard_id: u64) -> Result<(), MarkError> {
        if self.fail {
            return Err(MarkError::Commit);
        }
        self.latched.insert(guard_id);
        Ok(())
    }
}

struct Counter(u64);

impl crate::sessions::NonceSource for Counter {
    fn nonce(&mut self) -> Option<[u64; 2]> {
        self.0 += 1;
        Some([self.0, 1])
    }
}

fn status(nonce: [u64; 2], epoch: u64) -> GuardStatus {
    GuardStatus {
        authority_id: 10,
        guard_id: 11,
        receiver: RECEIVER,
        nonce,
        word: GuardWord::from_epoch(epoch).unwrap(),
    }
}

fn state(epoch: u64, lifetime_ms: u32) -> GuardState {
    GuardState {
        authority_id: 10,
        guard_id: 11,
        word: GuardWord::from_epoch(epoch).unwrap(),
        lifetime_ms,
    }
}

/// A guard recovered open at `epoch` (even) at time 0.
fn recovered(epoch: u64, marks: &mut Marks, nonces: &mut Counter) -> RemoteGuard {
    let mut guard = RemoteGuard::new(10, 11, marks.load(11).unwrap());
    let challenge = guard.challenge(RECEIVER, 0, nonces).unwrap();
    guard
        .on_status(&status(challenge.nonce, epoch), RECEIVER, MS, marks)
        .unwrap();
    guard
}

/// ADR-0086 section 7, design 4.1 and 4.4: until recovery completes
/// nothing opens: a verified `Open` STATE is discarded without raising the
/// floor or persisting anything.
#[test]
fn recovery_not_completed_means_no_open() {
    let mut marks = Marks::default();
    let mut guard = RemoteGuard::new(10, 11, 0);
    assert!(!guard.is_open(0));
    assert_eq!(
        guard.on_state(&state(8, 5_000), 0, &mut marks),
        Err(GuardRefusal::Recovering)
    );
    assert_eq!((guard.floor(), guard.phase(0)), (0, Phase::Recovering));
    assert!(marks.held.is_empty(), "nothing persisted");
    assert!(guard.round_due(0));
}

/// Design 4.4 step 3: a STATUS at or above the durable mark completes
/// recovery, its epoch persisted as the floor before it opens; one equal
/// to the mark completes it too.
#[test]
fn a_status_at_or_above_the_mark_completes_recovery() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    marks.held.insert(11, 4);
    let mut guard = RemoteGuard::load(10, 11, &marks);
    assert_eq!(guard.floor(), 4);
    let challenge = guard.challenge(RECEIVER, 0, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(&status(challenge.nonce, 4), RECEIVER, MS, &mut marks),
        Ok(GuardChange::Applied(Phase::Open {
            epoch: 4,
            until: MS + DEFAULT_LIFETIME_NS
        }))
    );
    assert!(guard.is_open(2 * MS));
    let mut higher = RemoteGuard::new(10, 11, 4);
    let challenge = higher.challenge(RECEIVER, 0, &mut nonces).unwrap();
    assert!(
        higher
            .on_status(&status(challenge.nonce, 6), RECEIVER, MS, &mut marks)
            .is_ok()
    );
    assert_eq!(marks.held[&11], 6, "persisted");
}

/// Design 4.4 step 3 and the rollback latch of 4.5: a STATUS below the
/// durable mark latches the guard closed; neither a later higher `Open`
/// STATE nor a later STATUS under the same guard opens it.
#[test]
fn a_status_below_the_mark_latches_closed() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    marks.held.insert(11, 6);
    let mut guard = RemoteGuard::load(10, 11, &marks);
    let challenge = guard.challenge(RECEIVER, 0, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(&status(challenge.nonce, 4), RECEIVER, MS, &mut marks),
        Err(GuardRefusal::Latched)
    );
    assert_eq!(guard.phase(MS), Phase::Latched);
    assert_eq!(
        guard.on_state(&state(10, 5_000), MS, &mut marks),
        Err(GuardRefusal::Latched)
    );
    assert!(guard.challenge(RECEIVER, MS, &mut nonces).is_none());
    assert!(!guard.round_due(10 * DEFAULT_LIFETIME_NS));
    assert!(!guard.is_open(MS));
    assert_eq!(marks.held[&11], 6, "the mark never moves down");
}

/// Design 4.3: a STATUS for an expired, replaced or consumed nonce, an
/// unknown nonce, another receiver or another guard is refused by its
/// reason and changes nothing: a delayed STATUS never opens, and the floor
/// never moves for it.
#[test]
fn stale_unknown_or_misdirected_statuses_change_nothing() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    let mut guard = RemoteGuard::new(10, 11, 2);
    // Expired: answered after the challenge timeout.
    let first = guard.challenge(RECEIVER, 0, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(
            &status(first.nonce, 8),
            RECEIVER,
            CHALLENGE_TIMEOUT_NS,
            &mut marks
        ),
        Err(GuardRefusal::StaleNonce)
    );
    // Replaced: a new round replaces the old nonce.
    let old = guard
        .challenge(RECEIVER, 2 * CHALLENGE_TIMEOUT_NS, &mut nonces)
        .unwrap();
    let now = 2 * CHALLENGE_TIMEOUT_NS + MS;
    let current = guard.challenge(RECEIVER, now, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(&status(old.nonce, 8), RECEIVER, now, &mut marks),
        Err(GuardRefusal::StaleNonce)
    );
    assert_eq!(
        guard.on_status(&status([99, 99], 8), RECEIVER, now, &mut marks),
        Err(GuardRefusal::UnknownNonce)
    );
    let other = Receiver {
        receiver_boot_id: [1, 1],
        ..RECEIVER
    };
    let mut misdirected = status(current.nonce, 8);
    misdirected.receiver = other;
    assert_eq!(
        guard.on_status(&misdirected, RECEIVER, now, &mut marks),
        Err(GuardRefusal::WrongReceiver)
    );
    let mut wrong_guard = status(current.nonce, 8);
    wrong_guard.guard_id = 12;
    assert_eq!(
        guard.on_status(&wrong_guard, RECEIVER, now, &mut marks),
        Err(GuardRefusal::WrongGuard)
    );
    assert_eq!((guard.floor(), guard.phase(now)), (2, Phase::Recovering));
    assert!(marks.held.is_empty());
    // Accepted once; its repeat finds the nonce consumed.
    assert!(
        guard
            .on_status(&status(current.nonce, 8), RECEIVER, now, &mut marks)
            .is_ok()
    );
    assert_eq!(
        guard.on_status(&status(current.nonce, 8), RECEIVER, now, &mut marks),
        Err(GuardRefusal::StaleNonce)
    );
    assert_eq!(guard.refusals(GuardRefusal::StaleNonce), 3);
}

/// Design 4.1: after recovery a STATE at or below the floor is refused; a
/// `Closed` one above it closes at once and raises the floor; an `Open`
/// one above it raises the floor but opens only on its confirming STATUS,
/// for the STATE's lifetime.
#[test]
fn states_after_recovery_need_an_epoch_above_the_floor() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    let mut guard = recovered(2, &mut marks, &mut nonces);
    assert_eq!(
        guard.on_state(&state(2, 5_000), 2 * MS, &mut marks),
        Err(GuardRefusal::Stale)
    );
    assert_eq!(
        guard.on_state(&state(3, 5_000), 2 * MS, &mut marks),
        Ok(GuardChange::Applied(Phase::Closed))
    );
    assert_eq!((guard.floor(), marks.held[&11]), (3, 3));
    assert_eq!(
        guard.on_state(&state(4, 2_000), 3 * MS, &mut marks),
        Ok(GuardChange::ConfirmationDue)
    );
    assert!(
        !guard.is_open(3 * MS),
        "an Open STATE never opens by itself"
    );
    assert_eq!(guard.floor(), 4);
    assert!(guard.round_due(3 * MS));
    let challenge = guard.challenge(RECEIVER, 3 * MS, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(&status(challenge.nonce, 4), RECEIVER, 4 * MS, &mut marks),
        Ok(GuardChange::Applied(Phase::Open {
            epoch: 4,
            until: 4 * MS + 2_000 * MS
        }))
    );
}

/// Design 4.4: a confirmation round keeps an `Open` past one lifetime;
/// with the authority silent it closes one lifetime after the last
/// confirmation.
#[test]
fn an_open_lives_only_by_its_confirmations() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    let mut guard = recovered(2, &mut marks, &mut nonces);
    let half = MS + DEFAULT_LIFETIME_NS / 2;
    assert!(!guard.round_due(half - 1));
    assert!(guard.round_due(half));
    let challenge = guard.challenge(RECEIVER, half, &mut nonces).unwrap();
    guard
        .on_status(&status(challenge.nonce, 2), RECEIVER, half + MS, &mut marks)
        .unwrap();
    assert!(
        guard.is_open(MS + DEFAULT_LIFETIME_NS + MS),
        "kept past one lifetime"
    );
    // Silent from now on.
    let last = half + MS;
    assert!(guard.is_open(last + DEFAULT_LIFETIME_NS - 1));
    assert!(!guard.is_open(last + DEFAULT_LIFETIME_NS));
}

/// Design 4.4 (PR #1286 review): an `Open` confirmed for a STATE's
/// nondefault lifetime keeps that lifetime once its confirmation clears
/// the pending STATE: the renewal round falls due half of it in, each
/// renewal extends the `Open` by it, and with the authority silent the
/// guard lapses one such lifetime after the last confirmation, never the
/// 5 s default.
#[test]
fn a_confirmed_lifetime_governs_its_renewals_and_expiry() {
    const LIFETIME: u64 = 1_000 * MS;
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    let mut guard = recovered(2, &mut marks, &mut nonces);
    assert_eq!(
        guard.on_state(&state(4, 1_000), 2 * MS, &mut marks),
        Ok(GuardChange::ConfirmationDue)
    );
    let challenge = guard.challenge(RECEIVER, 2 * MS, &mut nonces).unwrap();
    let confirmed = 3 * MS;
    assert_eq!(
        guard.on_status(&status(challenge.nonce, 4), RECEIVER, confirmed, &mut marks),
        Ok(GuardChange::Applied(Phase::Open {
            epoch: 4,
            until: confirmed + LIFETIME
        }))
    );
    // The renewal falls due half the confirmed lifetime in.
    let half = confirmed + LIFETIME / 2;
    assert!(!guard.round_due(half - 1));
    assert!(guard.round_due(half));
    let challenge = guard.challenge(RECEIVER, half, &mut nonces).unwrap();
    let renewed = half + MS;
    assert_eq!(
        guard.on_status(&status(challenge.nonce, 4), RECEIVER, renewed, &mut marks),
        Ok(GuardChange::Applied(Phase::Open {
            epoch: 4,
            until: renewed + LIFETIME
        })),
        "a renewal extends by the confirmed lifetime"
    );
    // Silent from now on: closed one confirmed lifetime later.
    assert!(guard.is_open(renewed + LIFETIME - 1));
    assert!(!guard.is_open(renewed + LIFETIME));
    assert_ne!(
        guard.word(renewed + LIFETIME),
        guard.word(renewed),
        "the gates read it closed"
    );
}

/// ADR-0086 section 7: a replay after a restart is refused by the durable
/// epoch: the old STATE at the persisted floor, and the old STATUS for a
/// nonce of the previous start.
#[test]
fn a_replay_after_a_restart_is_refused_by_the_epoch() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    let mut before = recovered(2, &mut marks, &mut nonces);
    let challenge = before.challenge(RECEIVER, 2 * MS, &mut nonces).unwrap();
    let old_status = status(challenge.nonce, 4);
    assert!(
        before
            .on_state(&state(4, 5_000), 2 * MS, &mut marks)
            .is_ok()
    );
    // Restart: the mark is 4, the guard recovers closed.
    let mut after = RemoteGuard::load(10, 11, &marks);
    assert_eq!(after.floor(), 4);
    assert_eq!(
        after.on_status(&old_status, RECEIVER, 3 * MS, &mut marks),
        Err(GuardRefusal::UnknownNonce)
    );
    let fresh = after.challenge(RECEIVER, 3 * MS, &mut nonces).unwrap();
    assert!(
        after
            .on_status(&status(fresh.nonce, 5), RECEIVER, 4 * MS, &mut marks)
            .is_ok()
    );
    assert_eq!(
        after.on_state(&state(4, 5_000), 5 * MS, &mut marks),
        Err(GuardRefusal::Stale)
    );
    assert!(!after.is_open(5 * MS));
}

/// ADR-0086 section 7: the mark is persisted before acting: a failed
/// commit opens nothing, and an unreadable mark leaves the guard latched.
#[test]
fn a_failed_mark_commit_opens_nothing() {
    let mut nonces = Counter(0);
    let mut marks = Marks {
        fail: true,
        ..Marks::default()
    };
    let mut guard = RemoteGuard::new(10, 11, 0);
    let challenge = guard.challenge(RECEIVER, 0, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(&status(challenge.nonce, 2), RECEIVER, MS, &mut marks),
        Err(GuardRefusal::Persist)
    );
    assert!(!guard.is_open(MS));
    let files = MemoryFiles::default();
    files
        .0
        .borrow_mut()
        .insert("guard-11".to_owned(), b"garbage\n".to_vec());
    let unreadable = GuardMarks::new(files);
    assert_eq!(
        RemoteGuard::load(10, 11, &unreadable).phase(0),
        Phase::Latched
    );
}

/// A directory in memory.
#[derive(Debug, Default)]
pub(crate) struct MemoryFiles(RefCell<HashMap<String, Vec<u8>>>);

impl Files for MemoryFiles {
    fn names(&self) -> Result<Vec<String>, FileError> {
        Ok(self.0.borrow().keys().cloned().collect())
    }

    fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, FileError> {
        let files = self.0.borrow();
        let bytes = files.get(name).ok_or(FileError::NotFound)?;
        let target = buf.get_mut(..bytes.len()).ok_or(FileError::Refused)?;
        target.copy_from_slice(bytes);
        Ok(bytes.len())
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), FileError> {
        self.0.borrow_mut().insert(name.to_owned(), bytes.to_vec());
        Ok(())
    }

    fn lock(&self) -> Result<(), FileError> {
        Ok(())
    }
}

/// The durable marks round-trip through their file and are only raised.
#[test]
fn guard_marks_persist_and_only_rise() {
    let mut marks = GuardMarks::new(MemoryFiles::default());
    assert_eq!(marks.load(11), Ok(0));
    marks.persist(11, 6).unwrap();
    marks.persist(11, 4).unwrap();
    assert_eq!(marks.load(11), Ok(6));
    assert_eq!(marks.load(12), Ok(0));
}

/// Finding 3 of the H8 review (design 4.1, ADR-0086 section 7): a
/// verified higher `Closed` STATE whose mark cannot be persisted still
/// raises the floor in memory and retires the outstanding round, so once
/// the store is writable again neither the old round's still-live `Open`
/// STATUS nor a fresh one at the old floor reopens; only a fresh STATUS
/// meeting the raised floor, persisted first, does.
#[test]
fn a_close_that_cannot_be_persisted_never_lets_the_old_floor_reopen() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    let mut guard = recovered(2, &mut marks, &mut nonces);
    // A renewal round is outstanding when the authority closes.
    let renewal = guard.challenge(RECEIVER, 2 * MS, &mut nonces).unwrap();
    marks.fail = true;
    assert_eq!(
        guard.on_state(&state(3, 5_000), 2 * MS, &mut marks),
        Err(GuardRefusal::Persist)
    );
    assert!(!guard.is_open(2 * MS));
    assert_eq!(guard.floor(), 3, "the floor rose in memory");
    assert_eq!(marks.held[&11], 2, "but is not durable yet");
    // The store is writable again.
    marks.fail = false;
    assert_eq!(
        guard.on_status(&status(renewal.nonce, 2), RECEIVER, 3 * MS, &mut marks),
        Err(GuardRefusal::StaleNonce),
        "the old round was retired"
    );
    let fresh = guard.challenge(RECEIVER, 3 * MS, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(&status(fresh.nonce, 2), RECEIVER, 4 * MS, &mut marks),
        Err(GuardRefusal::Stale)
    );
    assert!(!guard.is_open(4 * MS));
    assert_eq!(marks.held[&11], 2);
    // An `Open` STATE that cannot be persisted closes the same way and
    // only makes a confirmation due; its STATUS persists, then opens.
    marks.fail = true;
    assert_eq!(
        guard.on_state(&state(4, 5_000), 5 * MS, &mut marks),
        Err(GuardRefusal::Persist)
    );
    assert!(guard.round_due(5 * MS));
    marks.fail = false;
    let confirm = guard.challenge(RECEIVER, 5 * MS, &mut nonces).unwrap();
    assert!(matches!(
        guard.on_status(&status(confirm.nonce, 4), RECEIVER, 6 * MS, &mut marks),
        Ok(GuardChange::Applied(Phase::Open { epoch: 4, .. }))
    ));
    assert_eq!(marks.held[&11], 4, "durable before it opened");
}

/// Finding 3: a verified STATUS whose epoch cannot be persisted raises the
/// floor in memory; a lower one later is refused, not opened.
#[test]
fn a_status_that_cannot_be_persisted_still_raises_the_floor() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    let mut guard = recovered(2, &mut marks, &mut nonces);
    let first = guard.challenge(RECEIVER, 2 * MS, &mut nonces).unwrap();
    marks.fail = true;
    assert_eq!(
        guard.on_status(&status(first.nonce, 3), RECEIVER, 3 * MS, &mut marks),
        Err(GuardRefusal::Persist)
    );
    assert_eq!((guard.floor(), guard.phase(3 * MS)), (3, Phase::Closed));
    marks.fail = false;
    let second = guard.challenge(RECEIVER, 4 * MS, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(&status(second.nonce, 2), RECEIVER, 5 * MS, &mut marks),
        Err(GuardRefusal::Stale)
    );
    assert!(!guard.is_open(5 * MS));
}

/// Finding 9 of the H8 review (ADR-0107 decision 6, design 4.4 step 3):
/// the rollback latch is durable: after a restart the same guard id loads
/// latched, through its mark file; another configured guard id does not.
#[test]
fn the_rollback_latch_survives_a_restart() {
    let mut nonces = Counter(0);
    let mut marks = GuardMarks::new(MemoryFiles::default());
    marks.persist(11, 6).unwrap();
    let mut guard = RemoteGuard::load(10, 11, &marks);
    let challenge = guard.challenge(RECEIVER, 0, &mut nonces).unwrap();
    assert_eq!(
        guard.on_status(&status(challenge.nonce, 4), RECEIVER, MS, &mut marks),
        Err(GuardRefusal::Latched)
    );
    assert_eq!(marks.latched(11), Ok(true));
    assert_eq!(marks.load(11), Ok(6), "the epoch is kept");
    // Restart.
    let mut after = RemoteGuard::load(10, 11, &marks);
    assert_eq!((after.phase(0), after.floor()), (Phase::Latched, 6));
    assert!(after.challenge(RECEIVER, 0, &mut nonces).is_none());
    // A later raise keeps the latch.
    marks.persist(11, 8).unwrap();
    assert_eq!(marks.latched(11), Ok(true));
    // Only another configured guard id starts afresh.
    assert_eq!(
        RemoteGuard::load(10, 12, &marks).phase(0),
        Phase::Recovering
    );
}

/// Finding 9: a latch that cannot be stored still latches in memory,
/// counted as a persist failure too.
#[test]
fn a_latch_that_cannot_be_stored_still_latches() {
    let mut nonces = Counter(0);
    let mut marks = Marks::default();
    marks.held.insert(11, 6);
    let mut guard = RemoteGuard::load(10, 11, &marks);
    let challenge = guard.challenge(RECEIVER, 0, &mut nonces).unwrap();
    marks.fail = true;
    assert_eq!(
        guard.on_status(&status(challenge.nonce, 4), RECEIVER, MS, &mut marks),
        Err(GuardRefusal::Latched)
    );
    assert_eq!(guard.phase(MS), Phase::Latched);
    assert_eq!(guard.refusals(GuardRefusal::Persist), 1);
}

/// Finding 9: the mark file format is versioned and parsed fail closed:
/// v1 (epoch only) reads unlatched; v2 carries the latch; an unknown
/// version or a malformed field loads latched, and no commit overwrites a
/// mark it cannot read.
#[test]
fn the_mark_format_is_versioned_and_fails_closed() {
    let files = MemoryFiles::default();
    let put = |name: &str, text: &str| {
        files
            .0
            .borrow_mut()
            .insert(name.to_owned(), text.as_bytes().to_vec());
    };
    put("guard-1", "karyos-guard-mark-v1\nepoch=4\n");
    put("guard-2", "karyos-guard-mark-v2\nepoch=4\nlatched=1\n");
    put("guard-3", "karyos-guard-mark-v3\nepoch=4\nlatched=0\n");
    put("guard-4", "karyos-guard-mark-v2\nepoch=4\nlatched=2\n");
    put("guard-5", "karyos-guard-mark-v2\nepoch=4\n");
    put("guard-6", "karyos-guard-mark-v2\nepoch=+4\nlatched=0\n");
    let mut marks = GuardMarks::new(files);
    assert_eq!((marks.load(1), marks.latched(1)), (Ok(4), Ok(false)));
    assert_eq!(RemoteGuard::load(10, 1, &marks).phase(0), Phase::Recovering);
    assert_eq!((marks.load(2), marks.latched(2)), (Ok(4), Ok(true)));
    assert_eq!(RemoteGuard::load(10, 2, &marks).phase(0), Phase::Latched);
    for guard_id in 3..=6 {
        assert_eq!(marks.latched(guard_id), Err(MarkError::Unreadable));
        assert_eq!(
            RemoteGuard::load(10, guard_id, &marks).phase(0),
            Phase::Latched
        );
        assert_eq!(marks.persist(guard_id, 9), Err(MarkError::Unreadable));
        assert_eq!(marks.latch(guard_id), Err(MarkError::Unreadable));
    }
    // A v1 mark is rewritten as v2 on its next raise.
    marks.persist(1, 6).unwrap();
    assert_eq!((marks.load(1), marks.latched(1)), (Ok(6), Ok(false)));
    // The authority's committed epochs are named apart.
    let authority = GuardMarks::authority(MemoryFiles::default());
    assert_eq!(authority.name(11).as_str(), "authority-guard-11");
}
