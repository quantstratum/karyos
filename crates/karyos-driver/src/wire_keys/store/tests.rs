// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;

use super::*;
use crate::wire_keys::KEY_LEN;

/// An in-memory directory whose reads can be refused and whose commits can
/// fail.
#[derive(Default)]
struct Mem {
    files: RefCell<BTreeMap<String, Vec<u8>>>,
    refused: RefCell<BTreeSet<String>>,
    fail_writes: Cell<bool>,
    fail_list: Cell<bool>,
    /// The handle holding the exclusive lock, as `flock` on one descriptor.
    holder: Cell<Option<usize>>,
}

/// One open descriptor: clones share it, as a moved `SecureDir` does, and
/// the lock it holds is released when the last clone drops.
struct Handle {
    id: usize,
    mem: Rc<Mem>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.mem.holder.get() == Some(self.id) {
            self.mem.holder.set(None);
        }
    }
}

#[derive(Clone)]
struct Dir(Rc<Mem>, Rc<Handle>);

impl Default for Dir {
    fn default() -> Self {
        Self::over(Rc::default())
    }
}

impl Dir {
    fn over(mem: Rc<Mem>) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let handle = Rc::new(Handle {
            id,
            mem: Rc::clone(&mem),
        });
        Self(mem, handle)
    }
    /// The same directory through a second descriptor.
    fn reopen(&self) -> Self {
        Self::over(Rc::clone(&self.0))
    }
    fn put(&self, name: &str, bytes: &[u8]) {
        self.0
            .files
            .borrow_mut()
            .insert(name.to_owned(), bytes.to_vec());
    }
    fn remove(&self, name: &str) {
        self.0.files.borrow_mut().remove(name);
    }
    fn get(&self, name: &str) -> Vec<u8> {
        self.0.files.borrow()[name].clone()
    }
}

impl Files for Dir {
    fn names(&self) -> Result<Vec<String>, FileError> {
        if self.0.fail_list.get() {
            return Err(FileError::Refused);
        }
        Ok(self.0.files.borrow().keys().cloned().collect())
    }

    fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, FileError> {
        if self.0.refused.borrow().contains(name) {
            return Err(FileError::Refused);
        }
        let files = self.0.files.borrow();
        let bytes = files.get(name).ok_or(FileError::NotFound)?;
        if bytes.len() >= buf.len() {
            return Err(FileError::Refused);
        }
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), FileError> {
        if self.0.fail_writes.get() {
            return Err(FileError::Refused);
        }
        self.put(name, bytes);
        Ok(())
    }

    fn lock(&self) -> Result<(), FileError> {
        match self.0.holder.get() {
            Some(id) if id != self.1.id => Err(FileError::Refused),
            _ => {
                self.0.holder.set(Some(self.1.id));
                Ok(())
            }
        }
    }
}

const NOV_01: i64 = 1_793_491_200;
const DEC_01: i64 = 1_796_083_200;
const JAN_01: i64 = 1_798_761_600;
const JAN_30: i64 = 1_801_267_200;
const DAY: i64 = 86_400;

/// A canonical channel key file (design section 2.2).
fn channel(key_id: u32, epoch: u32, not_before: &str, not_after: &str, fill: u8) -> String {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    format!(
        "format=karyos-wire-key-v1\nkey_id={key_id}\nfile_epoch={epoch}\npurpose=channel\nprofile_id=1\nnot_before={not_before}T00:00:00Z\nnot_after={not_after}T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=1001\n"
    )
}

fn first() -> String {
    channel(3, 1, "2026-11-01", "2027-01-30", 0x11)
}

fn second() -> String {
    channel(3, 2, "2027-01-01", "2027-03-01", 0x22)
}

type Store = KeyStore<Dir, Dir>;

fn fresh() -> (Dir, Dir) {
    let (keys, state) = (Dir::default(), Dir::default());
    Store::initialise(&state, Zeroizing::new([7; KEY_LEN])).unwrap();
    (keys, state)
}

fn epochs(store: &Store) -> Vec<KeyRef> {
    store.loaded().map(|f| (f.key_id, f.file_epoch)).collect()
}

fn reasons(report: &Report) -> Vec<(u32, u32, Reason)> {
    report
        .events
        .iter()
        .map(|e| (e.key_id, e.file_epoch, e.reason))
        .collect()
}

fn committed(state: &Dir) -> KeyState {
    KeyState::decode(&state.get(STATE)).unwrap()
}

#[test]
fn start_fails_closed_without_a_good_state() {
    let (keys, state) = (Dir::default(), Dir::default());
    assert_eq!(
        Store::start(keys.clone(), state.clone(), DEC_01).unwrap_err(),
        StoreError::NotInitialised
    );
    Store::initialise(&state, Zeroizing::new([7; KEY_LEN])).unwrap();
    assert_eq!(
        Store::initialise(&state, Zeroizing::new([7; KEY_LEN])),
        Err(StoreError::AlreadyInitialised)
    );
    let mut bytes = state.get(STATE);
    bytes[0] ^= 1;
    state.put(STATE, &bytes);
    assert!(matches!(
        Store::start(keys.clone(), state.clone(), DEC_01).unwrap_err(),
        StoreError::State(_)
    ));
    state.0.refused.borrow_mut().insert(STATE.to_owned());
    assert_eq!(
        Store::start(keys, state.clone(), DEC_01).unwrap_err(),
        StoreError::Unreadable
    );
    // A state with no fingerprint key does not start either.
    let lone = Dir::default();
    lone.put(STATE, KeyState::default().encode().unwrap().as_bytes());
    assert_eq!(
        Store::start(Dir::default(), lone.clone(), DEC_01).unwrap_err(),
        StoreError::NotInitialised
    );
    assert_eq!(
        Store::initialise(&lone, Zeroizing::new([7; KEY_LEN])),
        Err(StoreError::AlreadyInitialised)
    );
}

#[test]
fn a_key_is_admitted_committed_and_used() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    keys.put("notes.txt", b"ignored");
    let (store, report) = Store::start(keys, state.clone(), DEC_01).unwrap();
    assert!(!report.alarm(), "{report:?}");
    assert_eq!(epochs(&store), [(3, 1)]);
    assert_eq!(store.signing_key(3, DEC_01).unwrap().file_epoch, 1);
    assert!(store.signing_key(4, DEC_01).is_none());
    assert!(store.signing_key(3, NOV_01 - 1).is_none());
    assert_eq!(store.verify_keys(3, NOV_01 - SKEW_S).count(), 1);
    assert_eq!(store.verify_keys(3, NOV_01 - SKEW_S - 1).count(), 0);
    let durable = committed(&state);
    assert_eq!(durable, *store.state());
    assert_eq!(
        durable.lineages[&3],
        Lineage {
            highest: 1,
            predecessor: None
        }
    );
    assert!(durable.admitted[&(3, 1)].secret.is_some());
}

#[test]
fn a_revocation_is_immediate_durable_and_never_revived() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    keys.put(REVOKED, b"3-1\n");
    assert!(!store.reload(DEC_01).alarm());
    assert!(epochs(&store).is_empty());
    assert!(committed(&state).tombstones.contains(&(3, 1)));
    // Removing the line, or the list, revives nothing, nor does a restart.
    keys.put(REVOKED, b"");
    store.reload(DEC_01);
    keys.remove(REVOKED);
    store.reload(DEC_01);
    assert!(epochs(&store).is_empty());
    let (store, _) = Store::start(keys, state, DEC_01).unwrap();
    assert!(epochs(&store).is_empty());
}

#[test]
fn a_revoked_list_that_does_not_validate_disables_every_key() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    for bad in [
        &b"3-2\n3-1\n"[..],
        b"3-1\n3-1\n",
        b"3-1",
        b"03-1\n",
        b"*\n",
        b"\n",
    ] {
        keys.put(REVOKED, bad);
        let report = store.reload(DEC_01);
        assert_eq!(reasons(&report), [(0, 0, Reason::RevokedList)]);
        assert!(store.is_disabled() && epochs(&store).is_empty());
        assert!(store.signing_key(3, DEC_01).is_none());
        assert_eq!(store.verify_keys(3, DEC_01).count(), 0);
    }
    keys.0.refused.borrow_mut().insert(REVOKED.to_owned());
    assert_eq!(
        reasons(&store.reload(DEC_01)),
        [(0, 0, Reason::RevokedList)]
    );
    // At startup too: no key loads before the list validates.
    let (started, report) = Store::start(keys.clone(), state, DEC_01).unwrap();
    assert!(started.is_disabled() && report.alarm());
    // A good list brings back what it does not revoke.
    keys.0.refused.borrow_mut().clear();
    keys.put(REVOKED, b"2-1\n");
    assert!(!store.reload(DEC_01).alarm());
    assert_eq!(epochs(&store), [(3, 1)]);
}

#[test]
fn a_changed_file_disables_its_key_for_good() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    keys.put(
        "3-1.key",
        channel(3, 1, "2026-11-01", "2027-01-30", 0x99).as_bytes(),
    );
    assert_eq!(reasons(&store.reload(DEC_01)), [(3, 1, Reason::Changed)]);
    assert!(epochs(&store).is_empty());
    assert!(committed(&state).disabled.contains(&(3, 1)));
    // The original bytes do not re-admit it, before or after a restart.
    keys.put("3-1.key", first().as_bytes());
    store.reload(DEC_01);
    assert!(epochs(&store).is_empty());
    let (store, _) = Store::start(keys, state, DEC_01).unwrap();
    assert!(epochs(&store).is_empty());
}

#[test]
fn an_admitted_file_that_turns_bad_is_disabled() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    // A permission change is seen on the next reload.
    keys.0.refused.borrow_mut().insert("3-1.key".to_owned());
    assert_eq!(reasons(&store.reload(DEC_01)), [(3, 1, Reason::Refused)]);
    assert!(committed(&state).disabled.contains(&(3, 1)));
    keys.0.refused.borrow_mut().clear();
    store.reload(DEC_01);
    assert!(epochs(&store).is_empty());
}

#[test]
fn a_never_admitted_bad_file_is_only_absent() {
    let (keys, state) = fresh();
    keys.put(
        "3-1.key",
        first()
            .replace("purpose=channel", "purpose=other")
            .as_bytes(),
    );
    keys.put(
        "4-1.key",
        channel(4, 1, "2026-11-01", "2027-01-30", 4).as_bytes(),
    );
    keys.0.refused.borrow_mut().insert("4-1.key".to_owned());
    let (mut store, report) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    assert_eq!(
        reasons(&report),
        [
            (3, 1, Reason::Malformed(KeyFileError::Value { line: 4 })),
            (4, 1, Reason::Refused)
        ]
    );
    assert!(epochs(&store).is_empty());
    assert!(committed(&state).disabled.is_empty());
    // Fixed, they load: nothing was marked.
    keys.put("3-1.key", first().as_bytes());
    keys.0.refused.borrow_mut().clear();
    assert!(!store.reload(DEC_01).alarm());
    assert_eq!(epochs(&store), [(3, 1), (4, 1)]);
}

#[test]
fn epochs_only_move_forward() {
    let (keys, state) = fresh();
    keys.put("3-2.key", second().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state, DEC_01).unwrap();
    keys.put("3-1.key", first().as_bytes());
    assert_eq!(
        reasons(&store.reload(DEC_01)),
        [(3, 1, Reason::EpochBackward)]
    );
    assert_eq!(epochs(&store), [(3, 2)]);
}

#[test]
fn deletion_and_expiry_remove_a_key_at_once() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state, DEC_01).unwrap();
    store.reload(JAN_30 + SKEW_S);
    assert_eq!(epochs(&store), [(3, 1)]);
    store.reload(JAN_30 + SKEW_S + 1);
    assert!(epochs(&store).is_empty());
    store.reload(DEC_01);
    assert_eq!(epochs(&store), [(3, 1)]);
    keys.remove("3-1.key");
    store.reload(DEC_01);
    assert!(epochs(&store).is_empty());
    // A never-admitted key already expired is refused and counted.
    keys.put(
        "4-1.key",
        channel(4, 1, "2026-11-01", "2027-01-30", 4).as_bytes(),
    );
    assert_eq!(
        reasons(&store.reload(JAN_30 + DAY)),
        [(4, 1, Reason::Expired)]
    );
}

#[test]
fn a_rollover_overlaps_for_a_day_then_retires_for_good() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    keys.put("3-2.key", second().as_bytes());
    assert!(!store.reload(DEC_01).alarm());
    let deadline = JAN_01 + DAY - SKEW_S;
    assert_eq!(
        committed(&state).lineages[&3],
        Lineage {
            highest: 2,
            predecessor: Some((1, deadline))
        }
    );
    // Signing moves to E2 exactly at its `not_before`.
    assert_eq!(store.signing_key(3, JAN_01 - 1).unwrap().file_epoch, 1);
    assert_eq!(store.signing_key(3, JAN_01).unwrap().file_epoch, 2);
    // Both verify from `nb2 - 60 s` until the deadline.
    let verify = |store: &Store, now| -> Vec<u32> {
        store.verify_keys(3, now).map(|f| f.file_epoch).collect()
    };
    assert_eq!(verify(&store, JAN_01 - SKEW_S - 1), [1]);
    assert_eq!(verify(&store, JAN_01 - SKEW_S), [1, 2]);
    assert_eq!(verify(&store, deadline - 1), [1, 2]);
    assert_eq!(verify(&store, deadline), [2]);
    // Past the deadline the reload retires E1, durably.
    store.reload(deadline);
    assert_eq!(epochs(&store), [(3, 2)]);
    assert!(committed(&state).retired.contains(&(3, 1)));
    // A clock moved back, a deleted E2 and a restart revive nothing.
    store.reload(DEC_01);
    keys.remove("3-2.key");
    store.reload(DEC_01);
    assert!(epochs(&store).is_empty());
    let (store, _) = Store::start(keys, state, DEC_01).unwrap();
    assert!(epochs(&store).is_empty());
}

#[test]
fn a_third_epoch_retires_the_oldest_at_once() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    keys.put("3-2.key", second().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    assert_eq!(epochs(&store), [(3, 1), (3, 2)]);
    keys.put(
        "3-3.key",
        channel(3, 3, "2027-01-15", "2027-03-01", 0x33).as_bytes(),
    );
    store.reload(DEC_01);
    assert_eq!(epochs(&store), [(3, 2), (3, 3)]);
    let durable = committed(&state);
    assert!(durable.retired.contains(&(3, 1)));
    assert_eq!(durable.lineages[&3].predecessor.unwrap().0, 2);
}

#[test]
fn a_failed_commit_disables_every_key_until_one_succeeds() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    state.0.fail_writes.set(true);
    keys.put(
        "4-1.key",
        channel(4, 1, "2026-11-01", "2027-01-30", 4).as_bytes(),
    );
    assert_eq!(reasons(&store.reload(DEC_01)), [(0, 0, Reason::Commit)]);
    assert!(store.is_disabled() && epochs(&store).is_empty());
    assert!(!committed(&state).admitted.contains_key(&(4, 1)));
    // Still failing: the uncommitted admission is never used.
    assert_eq!(reasons(&store.reload(DEC_01)), [(0, 0, Reason::Commit)]);
    assert!(epochs(&store).is_empty());
    state.0.fail_writes.set(false);
    assert!(!store.reload(DEC_01).alarm());
    assert_eq!(epochs(&store), [(3, 1), (4, 1)]);
    assert!(committed(&state).admitted.contains_key(&(4, 1)));
}

#[test]
fn an_unlistable_directory_or_a_full_state_disables_every_key() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    keys.0.fail_list.set(true);
    assert_eq!(reasons(&store.reload(DEC_01)), [(0, 0, Reason::Directory)]);
    assert!(store.is_disabled() && store.signing_key(3, DEC_01).is_none());
    keys.0.fail_list.set(false);
    store.reload(DEC_01);
    assert_eq!(epochs(&store), [(3, 1)]);
    // A state one admission short of its bound.
    let mut full = committed(&state);
    for epoch in 1..=u32::try_from(MAX_ENTRIES).unwrap() {
        full.tombstones.insert((9, epoch));
    }
    full.tombstones.remove(&(9, 1));
    full.lineages.clear();
    full.admitted.clear();
    state.put(STATE, full.encode().unwrap().as_bytes());
    let (mut store, report) = Store::start(keys, state, DEC_01).unwrap();
    assert_eq!(reasons(&report), [(0, 0, Reason::StateFull)]);
    assert!(store.is_disabled() && epochs(&store).is_empty());
    assert!(store.reload(DEC_01).alarm());
}

#[test]
fn the_revoked_list_parser_follows_the_format() {
    assert_eq!(parse_revoked(b""), Some(vec![]));
    assert_eq!(
        parse_revoked(b"1-1\n1-2\n2-1\n"),
        Some(vec![(1, 1), (1, 2), (2, 1)])
    );
    for bad in [
        &b"1-2\n1-1\n"[..],
        b"1-1\n1-1\n",
        b"1-1",
        b"1-0\n",
        b"1-1 \n",
        b"1-1\r\n",
    ] {
        assert_eq!(parse_revoked(bad), None, "{bad:?}");
    }
}

#[test]
fn a_secret_reused_by_another_key_is_refused() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    // Same reload: a second key with the first one's secret.
    keys.put(
        "5-1.key",
        channel(5, 1, "2026-11-01", "2027-01-30", 0x11).as_bytes(),
    );
    let (mut store, report) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    assert_eq!(reasons(&report), [(5, 1, Reason::ReusedSecret)]);
    assert_eq!(epochs(&store), [(3, 1)]);
    // A later epoch of the same key_id reusing it is refused too.
    keys.remove("5-1.key");
    keys.put(
        "3-2.key",
        channel(3, 2, "2027-01-01", "2027-03-01", 0x11).as_bytes(),
    );
    assert_eq!(
        reasons(&store.reload(DEC_01)),
        [(3, 2, Reason::ReusedSecret)]
    );
    // After a restart, against the durable record alone: the original
    // key is gone and revoked, and its secret still cannot come back.
    keys.remove("3-2.key");
    keys.remove("3-1.key");
    keys.put(REVOKED, b"3-1\n");
    store.reload(DEC_01);
    drop(store);
    keys.put(
        "6-1.key",
        channel(6, 1, "2026-11-01", "2027-01-30", 0x11).as_bytes(),
    );
    let (store, report) = Store::start(keys, state.clone(), DEC_01).unwrap();
    assert_eq!(reasons(&report), [(6, 1, Reason::ReusedSecret)]);
    assert!(epochs(&store).is_empty());
    assert!(!committed(&state).admitted.contains_key(&(6, 1)));
}

#[test]
fn a_predecessor_stops_signing_at_the_successor_not_before_whatever_happens_to_it() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    keys.put("3-2.key", second().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    let deadline = JAN_01 + DAY - SKEW_S;
    // E2 deleted after its `not_before`: E1 does not take over signing,
    // though it still verifies until the deadline.
    keys.remove("3-2.key");
    store.reload(JAN_01);
    assert_eq!(epochs(&store), [(3, 1)]);
    assert!(store.signing_key(3, JAN_01).is_none());
    assert_eq!(store.signing_key(3, JAN_01 - 1).unwrap().file_epoch, 1);
    assert_eq!(store.verify_keys(3, JAN_01).count(), 1);
    // At the deadline, before any reload retires it, it neither signs nor
    // verifies.
    assert!(store.signing_key(3, deadline).is_none());
    assert_eq!(store.verify_keys(3, deadline).count(), 0);
    // A revoked E2 does not hand signing back either, nor does a restart.
    keys.put("3-2.key", second().as_bytes());
    keys.put(REVOKED, b"3-2\n");
    store.reload(JAN_01);
    assert!(store.signing_key(3, JAN_01 + 1).is_none());
    drop(store);
    let (store, _) = Store::start(keys, state, JAN_01).unwrap();
    assert!(store.signing_key(3, JAN_01).is_none());
    assert_eq!(store.signing_key(3, JAN_01 - 1).unwrap().file_epoch, 1);
}

#[test]
fn a_successor_admitted_past_the_deadline_retires_its_predecessor_at_once() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (mut store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    let deadline = JAN_01 + DAY - SKEW_S;
    // E2 first appears after its overlap has already ended.
    keys.put("3-2.key", second().as_bytes());
    assert!(!store.reload(deadline + 1).alarm());
    assert_eq!(epochs(&store), [(3, 2)]);
    let durable = committed(&state);
    assert!(durable.retired.contains(&(3, 1)));
    assert!(durable.admitted.contains_key(&(3, 2)));
    // A restart with the clock rolled back does not load E1 again.
    drop(store);
    let (store, _) = Store::start(keys, state, DEC_01).unwrap();
    assert!(epochs(&store).iter().all(|key| *key != (3, 1)));
    assert!(store.signing_key(3, DEC_01).is_none());
}

#[test]
fn a_second_store_cannot_work_from_the_same_state() {
    let (keys, state) = fresh();
    keys.put("3-1.key", first().as_bytes());
    let (store, _) = Store::start(keys.clone(), state.clone(), DEC_01).unwrap();
    let other = state.reopen();
    assert_eq!(
        Store::start(keys.clone(), other.clone(), DEC_01).unwrap_err(),
        StoreError::Locked
    );
    assert_eq!(
        Store::initialise(&other, Zeroizing::new([7; KEY_LEN])),
        Err(StoreError::Locked)
    );
    // Once the first store drops, the lock is free.
    drop(store);
    drop(state);
    let (store, report) = Store::start(keys, other, DEC_01).unwrap();
    assert!(!report.alarm());
    assert_eq!(epochs(&store), [(3, 1)]);
}

/// karyos#1067: the state directory's lock, through `Files::lock` on a
/// `SecureDir`, is never refused while other threads spawn children: a
/// child's fork-to-exec window holds a closed handle's lock for a moment,
/// and `SecureDir::lock_exclusive` outlasts it.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(miri, ignore = "host syscalls")]
fn the_state_directory_lock_is_never_refused_by_a_spawn() {
    use karyos_sys::secure_dir::{SecureDir, effective_uid};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let base = std::env::temp_dir().join(format!("karyos-wire-keys-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("state")).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(base.join("state"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let spawners: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::process::Command::new("true").status();
                }
            })
        })
        .collect();
    let (mut refused, mut tries) = (0u32, 0u32);
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(2) {
        let dir =
            SecureDir::open_beneath(&base, std::path::Path::new("state"), effective_uid()).unwrap();
        if Files::lock(&dir).is_err() {
            refused += 1;
        }
        tries += 1;
    }
    stop.store(true, Ordering::Relaxed);
    for spawner in spawners {
        spawner.join().unwrap();
    }
    assert!(tries > 0);
    assert_eq!(refused, 0, "{refused} of {tries} locks refused");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_pairwise_file_reusing_a_channel_secret_is_refused() {
    // wire-key-files.md 2.7: a pairwise file with the same `secret` as the
    // channel file, refused at admission as a reused secret.
    let (keys, state) = fresh();
    keys.put(
        "3-3.key",
        channel(3, 3, "2026-11-01", "2027-01-30", 0x11).as_bytes(),
    );
    let secret: String = (0..KEY_LEN).map(|_| "11").collect();
    keys.put(
        "16909060-3.key",
        format!(
            "format=karyos-wire-key-v1\nkey_id=16909060\nfile_epoch=3\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nreceiver_id=66\npublisher_id=5\n"
        )
        .as_bytes(),
    );
    let (store, report) = Store::start(keys, state, DEC_01).unwrap();
    assert_eq!(reasons(&report), [(16_909_060, 3, Reason::ReusedSecret)]);
    assert_eq!(epochs(&store), [(3, 3)]);
}

#[test]
fn a_secret_reused_across_classes_is_refused() {
    // wire-key-files.md 2.7: the `profile_id=1` channel file and the same
    // secret as a `profile_id=16` file, presented as `4-3.key`.
    let (keys, state) = fresh();
    let authenticated = channel(3, 3, "2026-11-01", "2027-01-30", 0x11);
    keys.put("3-3.key", authenticated.as_bytes());
    keys.put(
        "4-3.key",
        authenticated
            .replace("key_id=3", "key_id=4")
            .replace("profile_id=1", "profile_id=16")
            .as_bytes(),
    );
    let (store, report) = Store::start(keys, state, DEC_01).unwrap();
    assert_eq!(reasons(&report), [(4, 3, Reason::ReusedSecret)]);
    assert_eq!(epochs(&store), [(3, 3)]);
}
