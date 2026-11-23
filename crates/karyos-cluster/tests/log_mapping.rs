// SPDX-License-Identifier: Apache-2.0

//! R-CORE-8 (karyos#745): the public mapping between the log's entries
//! and the positions of the recording that holds them, in both
//! directions, with each case that has no answer a value:
//!
//! - a replay driven through the mapping gives the live order;
//! - past the durable prefix, "not yet";
//! - a position inside a frame, "not an entry";
//! - a purged prefix, "purged", in both directions;
//! - after a snapshot install, "below the snapshot" and "another epoch";
//! - the identities hold across a reopen.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use karyos_archive::disk::StdDisk;
use karyos_archive::segment::Geometry;
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_cluster::{Entry, EntryAnswer, EntrySlot, HardState, RaftLog, SlotAnswer};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("karyos-r8-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 4 KiB segments: entries of a few hundred bytes span segments.
fn small() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

fn entry(index: u64, term: u64) -> Entry {
    Entry {
        index,
        term,
        event_time: index * 1_000,
        payload: vec![u8::try_from(index % 251).unwrap(); 300],
    }
}

/// A log of entries 1 to `last`, synced, committed through `commit`.
fn log(dir: &Path, last: u64, commit: u64) -> RaftLog<StdDisk> {
    let mut log = RaftLog::create(StdDisk, dir, small(), 1).unwrap();
    let batch: Vec<Entry> = (1..=last).map(|index| entry(index, 1)).collect();
    let _ = log.append(&batch).unwrap();
    let _ = log.sync().unwrap();
    log.save_hard_state(HardState {
        current_term: 1,
        voted_for: None,
        commit: Some(commit),
    })
    .unwrap();
    log
}

fn recorded(log: &RaftLog<StdDisk>, index: u64) -> EntrySlot {
    match log.slot_of(index) {
        EntryAnswer::Recorded(slot) => slot,
        other => panic!("entry {index}: {other:?}"),
    }
}

/// Walks the recording from `slot` through the mapping, reading each
/// entry: the replay.
fn replay(log: &mut RaftLog<StdDisk>, mut slot: EntrySlot) -> Vec<Entry> {
    let mut read = Vec::new();
    loop {
        read.push(log.read_slot(&slot).unwrap());
        let Some(next) = slot.next_position() else {
            break;
        };
        match log.entry_at(slot.epoch, next) {
            SlotAnswer::Entry(found) => slot = found,
            SlotAnswer::NotYet { .. } => break,
            other => panic!("at {next}: {other:?}"),
        }
    }
    read
}

#[test]
fn a_replay_through_the_mapping_gives_the_live_order() {
    let dir = TempDir::new("replay");
    let mut log = log(&dir.0, 30, 30);
    let live: Vec<Entry> = (1..=30).map(|index| entry(index, 1)).collect();
    let first = recorded(&log, 1);
    assert_eq!(first.index, 1);
    assert_eq!(
        log.entry_at(first.epoch, first.position),
        SlotAnswer::Entry(first)
    );
    assert_eq!(replay(&mut log, first), live);
    // From the middle, the rest in order.
    let middle = recorded(&log, 12);
    assert_eq!(replay(&mut log, middle), live[11..].to_vec());
    // The identities hold across a reopen.
    let held = recorded(&log, 17);
    drop(log);
    let mut log = RaftLog::open(StdDisk, &dir.0, small()).unwrap().log;
    assert_eq!(log.slot_of(17), EntryAnswer::Recorded(held));
    assert_eq!(
        log.entry_at(held.epoch, held.position),
        SlotAnswer::Entry(held)
    );
    assert_eq!(log.read_slot(&held).unwrap(), live[16]);
}

#[test]
fn past_the_durable_prefix_the_answer_is_not_yet() {
    let dir = TempDir::new("not-yet");
    let mut log = log(&dir.0, 10, 10);
    let _ = log.append(&[entry(11, 1), entry(12, 1)]).unwrap();
    // Written, not synced, and never written: nothing promised.
    for index in [11, 12, 13, u64::MAX] {
        assert_eq!(
            log.slot_of(index),
            EntryAnswer::NotYet { durable: Some(10) },
            "{index}"
        );
    }
    let last = recorded(&log, 10);
    let end = last.next_position().unwrap();
    assert_eq!(
        log.entry_at(last.epoch, end),
        SlotAnswer::NotYet { durable: Some(10) }
    );
    assert_eq!(
        log.entry_at(last.epoch, u64::MAX),
        SlotAnswer::NotYet { durable: Some(10) }
    );
    // An empty log answers not yet for everything.
    let empty = TempDir::new("empty");
    let fresh = RaftLog::create(StdDisk, &empty.0, small(), 1).unwrap();
    assert_eq!(fresh.slot_of(1), EntryAnswer::NotYet { durable: None });
    assert_eq!(
        fresh.entry_at(fresh.epoch(), 0),
        SlotAnswer::NotYet { durable: None }
    );
}

#[test]
fn a_position_inside_a_frame_is_not_an_entry() {
    let dir = TempDir::new("inside");
    let log = log(&dir.0, 5, 5);
    let slot = recorded(&log, 3);
    for inside in [slot.position + 1, slot.position + slot.length - 1] {
        assert_eq!(
            log.entry_at(slot.epoch, inside),
            SlotAnswer::NotAnEntry { within: 3 }
        );
    }
}

#[test]
fn a_purged_prefix_answers_purged_both_ways() {
    let dir = TempDir::new("purged");
    let mut log = log(&dir.0, 40, 40);
    let below = recorded(&log, 2);
    let first = log.purge_prefix(30).unwrap();
    assert_eq!(log.slot_of(2), EntryAnswer::Purged { first });
    let SlotAnswer::Purged { start } = log.entry_at(below.epoch, below.position) else {
        panic!("{:?}", log.entry_at(below.epoch, below.position));
    };
    assert!(start > below.position);
    // What is kept still maps, and replays in order.
    let kept = recorded(&log, first);
    let live: Vec<Entry> = (first..=40).map(|index| entry(index, 1)).collect();
    assert_eq!(replay(&mut log, kept), live);
}

#[test]
fn after_an_install_the_snapshot_holds_what_the_log_no_longer_does() {
    let dir = TempDir::new("install");
    let snapshots_dir = TempDir::new("install-snapshots");
    let mut log = log(&dir.0, 10, 5);
    let before = recorded(&log, 3);
    let mut snapshots = SnapshotStore::open(
        StdDisk,
        &snapshots_dir.0,
        small(),
        SnapshotConfig::default(),
    )
    .unwrap()
    .store;
    let _ = snapshots
        .write(20, 2, &[Section::new(SectionKind::Service, 1, b"state")])
        .unwrap();
    log.install(20, 2, &snapshots).unwrap();
    assert_ne!(log.epoch(), before.epoch, "an install starts an epoch");
    for index in [3, 20] {
        assert_eq!(log.slot_of(index), EntryAnswer::BelowSnapshot { base: 20 });
    }
    assert_eq!(
        log.entry_at(before.epoch, before.position),
        SlotAnswer::OtherEpoch { epoch: log.epoch() }
    );
    // The next entries map in the new epoch, from the same positions.
    let _ = log.append(&[entry(21, 2), entry(22, 2)]).unwrap();
    let _ = log.sync().unwrap();
    let next = recorded(&log, 21);
    assert_eq!(next.epoch, log.epoch());
    assert_eq!(replay(&mut log, next), vec![entry(21, 2), entry(22, 2)]);
    // A slot of the old epoch no longer reads.
    assert!(log.read_slot(&before).is_err());
}
