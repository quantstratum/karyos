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
}

#[derive(Clone, Default)]
struct Dir(Rc<Mem>);

impl Dir {
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
