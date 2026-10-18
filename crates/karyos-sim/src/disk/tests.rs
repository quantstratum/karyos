// SPDX-License-Identifier: Apache-2.0

// The disk model: what each survival mode keeps of pending data and
// names, torn writes at sector granularity, failed flushes, the crash
// budget, and one seed giving one outcome.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

const DIR: &str = "/d";

fn path(name: &str) -> PathBuf {
    Path::new(DIR).join(name)
}

/// The bytes of `name` on `disk`, or `None` when it has no such name.
fn contents(disk: &mut SimDisk, name: &str) -> Option<Vec<u8>> {
    let file = disk.open_read(&path(name)).ok()?;
    let len = usize::try_from(disk.len(&file).unwrap()).unwrap();
    let mut bytes = vec![0; len];
    disk.read_at(&file, 0, &mut bytes).unwrap();
    Some(bytes)
}

#[test]
fn reads_see_what_is_pending_and_a_crash_keeps_what_was_synced() {
    let mut disk = SimDisk::new();
    let file = disk.create(&path("a")).unwrap();
    disk.write_at(&file, 0, b"durable").unwrap();
    disk.sync(&file).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    disk.write_at(&file, 7, b" pending").unwrap();
    assert_eq!(contents(&mut disk, "a").unwrap(), b"durable pending");
    let mut synced = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut synced, "a").unwrap(), b"durable");
    let mut everything = disk.after_crash(Survives::Everything).unwrap();
    assert_eq!(contents(&mut everything, "a").unwrap(), b"durable pending");
}

/// A name not synced is lost with its directory, even with its data
/// synced; a rename and a removal not synced are undone.
#[test]
fn names_are_durable_only_by_their_directory() {
    let mut disk = SimDisk::new();
    let file = disk.create(&path("new")).unwrap();
    disk.write_at(&file, 0, b"x").unwrap();
    disk.sync(&file).unwrap();
    let mut synced = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut synced, "new"), None);
    disk.sync_dir(Path::new(DIR)).unwrap();
    disk.rename(&path("new"), &path("renamed")).unwrap();
    let kept = disk.create(&path("kept")).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    disk.remove(&path("kept")).unwrap();
    let _ = kept;
    let mut synced = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut synced, "renamed").unwrap(), b"x");
    assert!(contents(&mut synced, "kept").is_some());
    let mut live = disk.clone();
    assert_eq!(contents(&mut live, "kept"), None);
    assert_eq!(
        synced.list(Path::new(DIR)).unwrap(),
        ["kept".to_owned(), "renamed".to_owned()]
    );
}

/// A `set_len` not synced is undone by a crash that keeps only the
/// synced state: a truncation can be lost.
#[test]
fn a_set_len_is_data_made_durable_by_sync() {
    let mut disk = SimDisk::new();
    let file = disk.create(&path("a")).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    disk.write_at(&file, 0, b"0123456789").unwrap();
    disk.sync(&file).unwrap();
    disk.set_len(&file, 4).unwrap();
    assert_eq!(contents(&mut disk, "a").unwrap(), b"0123");
    let mut synced = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut synced, "a").unwrap(), b"0123456789");
}

/// A seeded subset can keep a later write without an earlier one, and a
/// torn write keeps whole sectors only; one seed gives one outcome.
#[test]
fn seeded_crashes_reorder_and_tear_deterministically() {
    let mut disk = SimDisk::new();
    let file = disk.create(&path("a")).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    for block in 0..8u8 {
        disk.write_at(&file, u64::from(block) * 4, &[block + 1; 4])
            .unwrap();
    }
    let big = vec![9u8; 3 * 512 + 100];
    disk.write_at(&file, 4096, &big).unwrap();
    let mut reordered = false;
    for seed in 0..32 {
        let mut crashed = disk.after_crash(Survives::Subset { seed }).unwrap();
        let bytes = contents(&mut crashed, "a").unwrap_or_default();
        let kept: Vec<bool> = (0..8)
            .map(|block| bytes.get(block * 4) == Some(&(u8::try_from(block).unwrap() + 1)))
            .collect();
        if kept.windows(2).any(|pair| !pair[0] && pair[1]) {
            reordered = true;
        }
        let again = disk.after_crash(Survives::Subset { seed }).unwrap();
        assert_eq!(crashed.trace(), again.trace(), "seed {seed}");
        let mut torn = disk.after_crash(Survives::Torn { seed }).unwrap();
        let bytes = contents(&mut torn, "a").unwrap();
        let written = bytes
            .get(4096..)
            .map_or(0, |tail| tail.iter().take_while(|byte| **byte == 9).count());
        assert!(
            written % 512 == 0 || written == big.len(),
            "seed {seed}: {written} bytes kept"
        );
    }
    assert!(
        reordered,
        "no seed kept a later write without an earlier one"
    );
}

/// A planned flush failure makes nothing durable, and is traced.
#[test]
fn a_failed_flush_makes_nothing_durable() {
    let mut disk = SimDisk::new().with_failed_syncs([2]);
    let file = disk.create(&path("a")).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    disk.write_at(&file, 0, b"lost").unwrap();
    assert!(disk.sync(&file).is_err());
    assert!(disk.trace().contains(&Decision::FailedSync { sync: 2 }));
    let mut synced = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut synced, "a").unwrap(), b"");
    // The next flush works, and the writes were still pending.
    disk.sync(&file).unwrap();
    let mut synced = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut synced, "a").unwrap(), b"lost");
}

/// The budget's next operation crashes the disk, and every later one
/// fails too; a crash is traced with its operation.
#[test]
fn the_budget_crashes_the_disk() {
    let mut disk = SimDisk::with_budget(2);
    let file = disk.create(&path("a")).unwrap();
    disk.write_at(&file, 0, b"x").unwrap();
    assert!(disk.sync(&file).is_err());
    assert!(disk.has_crashed());
    assert!(disk.write_at(&file, 1, b"y").is_err());
    assert_eq!(disk.used(), 3);
    assert_eq!(
        disk.trace(),
        [Decision::Crash {
            op: 3,
            call: "sync"
        }]
    );
    // A restart works again.
    let mut restarted = disk.after_crash(Survives::Everything).unwrap();
    assert_eq!(contents(&mut restarted, "a").unwrap(), b"x");
}
