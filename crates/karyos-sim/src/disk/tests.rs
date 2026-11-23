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
/// synced; a rename synced by its directory is kept, and a removal not
/// synced is undone.
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

/// A planned flush failure makes nothing durable, and is traced. By
/// default it drops the file's pending writes (fsyncgate): a later flush
/// succeeds without them. The optimistic model keeps them pending.
#[test]
fn a_failed_flush_makes_nothing_durable() {
    for optimistic in [false, true] {
        let disk = SimDisk::new().with_failed_syncs([2]);
        let mut disk = if optimistic {
            disk.with_optimistic_flushes()
        } else {
            disk
        };
        let file = disk.create(&path("a")).unwrap();
        disk.sync_dir(Path::new(DIR)).unwrap();
        disk.write_at(&file, 0, b"lost").unwrap();
        assert!(disk.sync(&file).is_err());
        assert!(disk.trace().contains(&Decision::FailedSync { sync: 2 }));
        let mut synced = disk.after_crash(Survives::Synced).unwrap();
        assert_eq!(contents(&mut synced, "a").unwrap(), b"");
        disk.sync(&file).unwrap();
        let mut synced = disk.after_crash(Survives::Synced).unwrap();
        let wanted: &[u8] = if optimistic { b"lost" } else { b"" };
        assert_eq!(
            contents(&mut synced, "a").unwrap(),
            wanted,
            "optimistic {optimistic}"
        );
    }
}

/// A failed directory flush makes no name durable: by default its
/// pending names are dropped, and a later flush succeeds without them.
#[test]
fn a_failed_directory_flush_makes_no_name_durable() {
    let mut disk = SimDisk::new().with_failed_syncs([1]);
    let _ = disk.create(&path("a")).unwrap();
    assert!(disk.sync_dir(Path::new(DIR)).is_err());
    let mut synced = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut synced, "a"), None);
    disk.sync_dir(Path::new(DIR)).unwrap();
    let mut synced = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut synced, "a"), None);
}

/// A tear ends at a whole-sector boundary of the disk, not of the write:
/// a write from byte 100 to 1700 over 512-byte sectors can keep 412, 924
/// or 1436 bytes, or none; a fixed seed tears some write in part.
#[test]
fn a_tear_ends_at_a_sector_of_the_disk() {
    let mut disk = SimDisk::new();
    let file = disk.create(&path("a")).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    for at in 0..4u64 {
        disk.write_at(&file, 100 + at * 4096, &[9u8; 1600]).unwrap();
    }
    let mut partial = 0;
    for seed in 0..8 {
        let mut torn = disk.after_crash(Survives::Torn { seed }).unwrap();
        let bytes = contents(&mut torn, "a").unwrap_or_default();
        for at in 0..4usize {
            let start = 100 + at * 4096;
            let kept = bytes
                .get(start..)
                .map_or(0, |tail| tail.iter().take_while(|byte| **byte == 9).count())
                .min(1600);
            assert!(
                [0, 412, 924, 1436, 1600].contains(&kept),
                "seed {seed}, write {at}: {kept} bytes kept"
            );
            if kept != 0 && kept != 1600 {
                partial += 1;
            }
        }
    }
    assert!(partial > 0, "no seed tore a write in part");
    // A smaller sector tears at its own boundaries.
    let mut small = SimDisk::new().with_sector(100);
    let file = small.create(&path("b")).unwrap();
    small.sync_dir(Path::new(DIR)).unwrap();
    small.write_at(&file, 50, &[9u8; 300]).unwrap();
    for seed in 0..8 {
        let mut torn = small.after_crash(Survives::Torn { seed }).unwrap();
        let bytes = contents(&mut torn, "b").unwrap_or_default();
        let kept = bytes
            .get(50..)
            .map_or(0, |tail| tail.iter().take_while(|byte| **byte == 9).count());
        assert!(
            [0, 50, 150, 250, 300].contains(&kept),
            "seed {seed}: {kept}"
        );
    }
}

/// Two seeds give two outcomes: the seed decides, not the call order.
#[test]
fn different_seeds_give_different_traces() {
    let mut disk = SimDisk::new();
    let file = disk.create(&path("a")).unwrap();
    for block in 0..16u64 {
        disk.write_at(&file, block * 8, &[1; 8]).unwrap();
    }
    let first = disk
        .after_crash(Survives::Subset { seed: 0 })
        .unwrap()
        .trace();
    let differs =
        (1..8).any(|seed| disk.after_crash(Survives::Subset { seed }).unwrap().trace() != first);
    assert!(differs, "every seed gave one trace");
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

/// Torn's seed decides too: two seeds tear the same writes differently.
#[test]
fn different_seeds_tear_differently() {
    let mut disk = SimDisk::new().with_sector(16);
    let file = disk.create(&path("a")).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    for block in 0..8u64 {
        disk.write_at(&file, block * 128, &[1; 128]).unwrap();
    }
    let first = disk
        .after_crash(Survives::Torn { seed: 0 })
        .unwrap()
        .trace();
    let differs =
        (1..8).any(|seed| disk.after_crash(Survives::Torn { seed }).unwrap().trace() != first);
    assert!(differs, "every seed tore alike");
}

/// A write within one sector is atomic under Torn: whole or dropped,
/// never in part, whatever the seed.
#[test]
fn a_write_within_one_sector_is_never_torn_in_part() {
    let mut disk = SimDisk::new();
    let file = disk.create(&path("a")).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    disk.write_at(&file, 100, &[9u8; 300]).unwrap();
    let (mut whole, mut dropped) = (0, 0);
    for seed in 0..64 {
        let mut torn = disk.after_crash(Survives::Torn { seed }).unwrap();
        let bytes = contents(&mut torn, "a").unwrap_or_default();
        let kept = bytes
            .get(100..)
            .map_or(0, |tail| tail.iter().take_while(|byte| **byte == 9).count());
        match kept {
            300 => whole += 1,
            0 => dropped += 1,
            kept => panic!("seed {seed}: {kept} of 300 bytes kept"),
        }
    }
    assert!(whole > 0 && dropped > 0, "{whole} whole, {dropped} dropped");
}

/// karyos#976: a disk that lies about syncs acknowledges them, and a crash
/// loses what they acknowledged; a sync of a file it does not have fails as
/// an honest disk's does; the disk the crash leaves is honest.
#[cfg(feature = "test-hooks")]
#[test]
fn a_disk_that_lies_about_syncs_loses_them_at_a_crash() {
    let mut disk = SimDisk::new().lying_about_syncs();
    let file = disk.create(&path("a")).unwrap();
    disk.sync_dir(Path::new(DIR)).unwrap();
    disk.write_at(&file, 0, b"acknowledged").unwrap();
    disk.sync(&file).unwrap();
    let missing = SimFile {
        inode: u64::MAX,
        writable: true,
    };
    assert_eq!(
        disk.sync(&missing).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let mut after = disk.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut after, "a").unwrap(), b"");
    let file = after.open(&path("a")).unwrap();
    after.write_at(&file, 0, b"kept").unwrap();
    after.sync(&file).unwrap();
    let mut again = after.after_crash(Survives::Synced).unwrap();
    assert_eq!(contents(&mut again, "a").unwrap(), b"kept");
}
