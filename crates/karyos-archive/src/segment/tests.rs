// SPDX-License-Identifier: Apache-2.0

// The A2 gate: torn-write and restart tests. A workload runs on a disk that
// crashes after every possible amount of work; for each crash, under both
// crash models, recovery must keep at least what was reported durable,
// read back exactly the stream up to its written position, and continue.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use proptest::prelude::*;

use super::fault::{FaultDisk, Survives};
use super::*;

const DIR: &str = "/archive";
const RECORDING: u64 = 7;

fn geometry() -> Geometry {
    Geometry::new(64, 128).unwrap()
}

/// The recorded stream: byte `i` of the recording.
fn stream(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from((index * 7 + 3) % 251).unwrap())
        .collect()
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Append(usize),
    Sync,
    Tick(u64),
}

/// What a workload reported before it stopped.
#[derive(Debug, Clone, Copy)]
struct Reported {
    created: bool,
    durable: u64,
}

/// Runs `steps` from `start` on `disk` until done or crashed.
fn run(
    disk: FaultDisk,
    steps: &[Step],
    policy: SyncPolicy,
    start: u64,
    skip_index_sync: bool,
) -> Reported {
    let dir = Path::new(DIR);
    let Ok(mut store) = SegmentStore::create(disk, dir, RECORDING, geometry(), policy, start)
    else {
        return Reported {
            created: false,
            durable: start,
        };
    };
    store.skip_index_sync = skip_index_sync;
    let total: usize = steps
        .iter()
        .map(|step| match step {
            Step::Append(length) => *length,
            _ => 0,
        })
        .sum();
    let bytes = stream(total);
    let mut reported = Reported {
        created: true,
        durable: store.durable(),
    };
    let mut position = start;
    for step in steps {
        let result = match *step {
            Step::Append(length) => {
                let from = usize::try_from(position - start).unwrap();
                match store.append(position, &bytes[from..from + length]) {
                    Ok(written) => {
                        position = written;
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            Step::Sync => store.sync().map(drop),
            Step::Tick(now) => store.tick(now).map(drop),
        };
        // What the store claims, failures included: a claim made before a
        // failure must hold too.
        reported.durable = store.durable();
        if result.is_err() {
            return reported;
        }
    }
    let durable = store.durable();
    if let Ok(closed) = store.close() {
        reported.durable = closed;
    } else {
        reported.durable = durable;
    }
    reported
}

/// Recovers what `crashed` left under `survives` and checks the gate's
/// properties; `Err` names the first one that fails.
fn check(
    crashed: &FaultDisk,
    survives: Survives,
    reported: Reported,
    policy: SyncPolicy,
    start: u64,
    total: usize,
) -> Result<(), String> {
    let disk = crashed.after_crash(survives);
    let dir = Path::new(DIR);
    let recovered = match SegmentStore::recover(disk, dir, RECORDING, geometry(), policy) {
        Ok(recovered) => recovered,
        Err(SegmentError::NotFound { .. }) if !reported.created => return Ok(()),
        Err(error) => return Err(format!("recovery failed: {error}")),
    };
    let mut store = recovered.store;
    if store.start() != start {
        return Err(format!("start {} != {start}", store.start()));
    }
    let written = store.written();
    if written < reported.durable {
        return Err(format!(
            "written {written} below the reported durable {}",
            reported.durable
        ));
    }
    let bytes = stream(total);
    let kept = usize::try_from(written - start).unwrap();
    if kept > total {
        return Err(format!("written {written} beyond the stream"));
    }
    let mut read = vec![0u8; kept];
    store
        .read(start, &mut read)
        .map_err(|error| error.to_string())?;
    if read != bytes[..kept] {
        return Err("the kept bytes differ from the stream".to_owned());
    }
    if store.durable() != written {
        return Err("recovery left something not durable".to_owned());
    }
    // Restart and continue: the rest of the stream, then every byte back.
    store
        .append(written, &bytes[kept..])
        .map_err(|error| error.to_string())?;
    let mut all = vec![0u8; total];
    store
        .read(start, &mut all)
        .map_err(|error| error.to_string())?;
    if all != bytes {
        return Err("the continued stream differs".to_owned());
    }
    Ok(())
}

/// Crashes the workload after every amount of work from zero to all of it
/// and checks both crash models; returns the failures.
fn crash_everywhere(
    steps: &[Step],
    policy: SyncPolicy,
    start: u64,
    skip_index_sync: bool,
) -> Vec<String> {
    let total: usize = steps
        .iter()
        .map(|step| match step {
            Step::Append(length) => *length,
            _ => 0,
        })
        .sum();
    let free = FaultDisk::default();
    let _ = run(free.clone(), steps, policy, start, skip_index_sync);
    let mut failures = Vec::new();
    for budget in 0..=free.used() {
        let disk = FaultDisk::with_budget(budget);
        let reported = run(disk.clone(), steps, policy, start, skip_index_sync);
        for survives in [Survives::Everything, Survives::Synced, Survives::TornData] {
            if let Err(failure) = check(&disk, survives, reported, policy, start, total) {
                failures.push(format!("budget {budget}, {survives:?}: {failure}"));
            }
        }
    }
    failures
}

/// The workload: appends across three segments (one starting mid
/// segment), explicit syncs, and an append that spans a roll.
fn workload() -> Vec<Step> {
    vec![
        Step::Append(50),
        Step::Append(100),
        Step::Sync,
        Step::Append(30),
        Step::Append(120),
        Step::Tick(5),
        Step::Append(10),
        Step::Sync,
        Step::Append(90),
    ]
}

/// The gate: for every crash point and both crash models, recovery keeps
/// at least the reported durable position, reads the stream back exactly
/// and continues it.
#[test]
fn every_crash_point_recovers_the_durable_prefix() {
    for (policy, start) in [
        (SyncPolicy::PerSegment, 0),
        (SyncPolicy::PerSegment, 200),
        (SyncPolicy::None, 0),
        (SyncPolicy::Every { interval_ns: 1 }, 64),
    ] {
        let failures = crash_everywhere(&workload(), policy, start, false);
        assert!(
            failures.is_empty(),
            "{policy:?} from {start}: {failures:#?}"
        );
    }
}

/// Negative control: without the index sync, a crash that keeps only what
/// was synced loses writes reported durable, and the gate sees it.
#[test]
fn an_unsynced_index_fails_the_gate() {
    let failures = crash_everywhere(&workload(), SyncPolicy::PerSegment, 0, true);
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("Synced") && failure.contains("below the reported")),
        "{failures:#?}"
    );
}

/// A crash between a segment's creation and its directory sync loses the
/// segment under the synced model; recovery keeps the previous one whole.
#[test]
fn a_crash_mid_roll_keeps_the_previous_segment() {
    let steps = [Step::Append(128), Step::Sync, Step::Append(1)];
    let free = FaultDisk::default();
    let _ = run(free.clone(), &steps, SyncPolicy::PerSegment, 0, false);
    // Every crash inside the roll's creation of segment 128.
    for budget in 0..=free.used() {
        let disk = FaultDisk::with_budget(budget);
        let reported = run(disk.clone(), &steps, SyncPolicy::PerSegment, 0, false);
        if !disk.has_crashed() {
            continue;
        }
        let recovered = SegmentStore::recover(
            disk.after_crash(Survives::Synced),
            Path::new(DIR),
            RECORDING,
            geometry(),
            SyncPolicy::PerSegment,
        );
        let Ok(recovered) = recovered else {
            assert!(!reported.created, "budget {budget}");
            continue;
        };
        assert!(
            recovered.store.written() >= reported.durable,
            "budget {budget}"
        );
        assert!(recovered.store.written() <= 129, "budget {budget}");
    }
}

/// An empty last segment (a header and no entry) is kept as the open one.
#[test]
fn an_empty_last_segment_recovers() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut store = SegmentStore::create(
        disk.clone(),
        dir,
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    store.append(0, &stream(128)).unwrap();
    // Roll by hand: the segment at 128 exists with its header only.
    store.roll(128).unwrap();
    assert_eq!(store.close().unwrap(), 128);
    let recovered =
        SegmentStore::recover(disk, dir, RECORDING, geometry(), SyncPolicy::PerSegment).unwrap();
    assert_eq!(recovered.cut, None);
    assert_eq!(recovered.store.written(), 128);
}

/// A torn last entry is cut and reported; the data before it is kept.
#[test]
fn a_torn_entry_is_cut_and_reported() {
    let free = FaultDisk::default();
    let steps = [Step::Append(40), Step::Append(40)];
    let _ = run(free.clone(), &steps, SyncPolicy::None, 0, false);
    let used = free.used();
    // The last write is the second entry: stop 5 bytes into it.
    let disk = FaultDisk::with_budget(used - 27);
    let _ = run(disk.clone(), &steps, SyncPolicy::None, 0, false);
    let recovered = SegmentStore::recover(
        disk.after_crash(Survives::Everything),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::None,
    )
    .unwrap();
    assert_eq!(
        recovered.cut,
        Some(Cut {
            position: 40,
            reason: CutReason::TornEntry
        })
    );
    assert_eq!(recovered.store.written(), 40);
}

/// Appends are contiguous; a bad position changes nothing.
#[test]
fn appends_are_contiguous() {
    let mut store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::None,
        10,
    )
    .unwrap();
    assert!(matches!(
        store.append(11, &[1]),
        Err(SegmentError::NotContiguous {
            expected: 10,
            got: 11
        })
    ));
    assert_eq!(store.append(10, &[1, 2]).unwrap(), 12);
    let mut out = [0u8; 2];
    store.read(10, &mut out).unwrap();
    assert_eq!(out, [1, 2]);
    assert!(store.read(9, &mut out).is_err());
    assert!(store.read(11, &mut out).is_err());
}

/// An existing recording is not created again.
#[test]
fn an_existing_recording_is_refused() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let _store = SegmentStore::create(
        disk.clone(),
        dir,
        RECORDING,
        geometry(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    assert!(matches!(
        SegmentStore::create(disk, dir, RECORDING, geometry(), SyncPolicy::None, 0),
        Err(SegmentError::Exists {
            recording: RECORDING
        })
    ));
}

/// The geometry is checked.
#[test]
fn the_geometry_is_checked() {
    assert!(Geometry::new(0, 128).is_err());
    assert!(Geometry::new(64, 0).is_err());
    assert!(Geometry::new(64, 100).is_err());
    assert!(Geometry::new(64, 1 << 33).is_err());
    let default = Geometry::with_default_length(1 << 16).unwrap();
    assert_eq!(default.segment_length(), DEFAULT_SEGMENT_LENGTH);
    let large = Geometry::with_default_length(1 << 30).unwrap();
    assert_eq!(large.segment_length(), 1 << 30);
}

/// The every-interval policy syncs when its interval passed, not before.
#[test]
fn the_interval_policy_syncs_on_time() {
    let mut store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::Every { interval_ns: 100 },
        0,
    )
    .unwrap();
    store.append(0, &[1; 10]).unwrap();
    assert_eq!(store.tick(50).unwrap(), 0);
    assert_eq!(store.tick(100).unwrap(), 10);
    store.append(10, &[2; 10]).unwrap();
    assert_eq!(store.tick(150).unwrap(), 10);
    assert_eq!(store.tick(200).unwrap(), 20);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Random workloads crashed at a random point keep the gate's
    /// properties under both models.
    #[test]
    fn random_workloads_recover(
        appends in prop::collection::vec((1usize..300, any::<bool>()), 1..6),
        start in 0u64..300,
        at in 0.0f64..=1.0,
    ) {
        let mut steps = Vec::new();
        for (length, sync) in appends {
            steps.push(Step::Append(length));
            if sync {
                steps.push(Step::Sync);
            }
        }
        let total: usize = steps.iter().map(|step| match step {
            Step::Append(length) => *length,
            _ => 0,
        }).sum();
        let free = FaultDisk::default();
        let _ = run(free.clone(), &steps, SyncPolicy::PerSegment, start, false);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
        let budget = (free.used() as f64 * at) as u64;
        let disk = FaultDisk::with_budget(budget);
        let reported = run(disk.clone(), &steps, SyncPolicy::PerSegment, start, false);
        for survives in [Survives::Everything, Survives::Synced, Survives::TornData] {
            let result = check(&disk, survives, reported, SyncPolicy::PerSegment, start, total);
            prop_assert!(result.is_ok(), "{survives:?}: {result:?}");
        }
    }
}

/// A temporary directory removed when dropped, a failing test included.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "karyos-archive-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The real disk: a recording written, closed, recovered and read back.
#[test]
fn a_recording_survives_a_close_on_disk() {
    let temp = TempDir::new("close");
    let dir = temp.0.clone();
    let geometry = Geometry::new(4096, 8192).unwrap();
    let bytes = stream(20_000);
    let mut store =
        SegmentStore::create(StdDisk, &dir, 3, geometry, SyncPolicy::PerSegment, 100).unwrap();
    for chunk in bytes.chunks(3000) {
        store.append(store.written(), chunk).unwrap();
    }
    assert_eq!(store.close().unwrap(), 20_100);
    let recovered =
        SegmentStore::recover(StdDisk, &dir, 3, geometry, SyncPolicy::PerSegment).unwrap();
    assert_eq!(recovered.cut, None);
    let mut store = recovered.store;
    let mut read = vec![0u8; bytes.len()];
    store.read(100, &mut read).unwrap();
    assert_eq!(read, bytes);
}

/// The cost of a sync on the real disk (`F_FULLFSYNC` on Apple targets,
/// `fdatasync` on Linux), beside a write: run by hand with `--ignored
/// --nocapture`; the numbers go in the PR, a bench workload follows.
#[test]
#[ignore = "a measurement, run by hand"]
#[allow(clippy::print_stderr, reason = "a measurement reports its numbers")]
fn measure_the_sync_cost() {
    let temp = TempDir::new("sync");
    let dir = temp.0.clone();
    let geometry = Geometry::new(1 << 16, 1 << 26).unwrap();
    let mut store = SegmentStore::create(StdDisk, &dir, 1, geometry, SyncPolicy::None, 0).unwrap();
    let chunk = stream(4096);
    let rounds = 200u32;
    let mut write = std::time::Duration::ZERO;
    let mut sync = std::time::Duration::ZERO;
    for _ in 0..rounds {
        let begin = std::time::Instant::now();
        store.append(store.written(), &chunk).unwrap();
        let written = std::time::Instant::now();
        store.sync().unwrap();
        write += written - begin;
        sync += written.elapsed();
    }
    eprintln!(
        "4 KiB append: {:?} mean; sync (data then index): {:?} mean, over {rounds}",
        write / rounds,
        sync / rounds
    );
}

/// #339 review P1: a valid header naming another geometry is a typed
/// error, and recovery removes nothing.
#[test]
fn a_geometry_mismatch_is_refused_and_removes_nothing() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut store = SegmentStore::create(
        disk.clone(),
        dir,
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    store.append(0, &stream(300)).unwrap();
    store.close().unwrap();
    let mut raw = disk.clone();
    let before = raw.list(dir).unwrap().len();
    let other = Geometry::new(64, 256).unwrap();
    assert!(matches!(
        SegmentStore::recover(disk.clone(), dir, RECORDING, other, SyncPolicy::PerSegment),
        Err(SegmentError::BadHeader {
            problem: HeaderProblem::Mismatch,
            ..
        })
    ));
    assert_eq!(raw.list(dir).unwrap().len(), before, "nothing removed");
    // With its own geometry it recovers whole.
    let recovered =
        SegmentStore::recover(disk, dir, RECORDING, geometry(), SyncPolicy::PerSegment).unwrap();
    assert_eq!(recovered.store.written(), 300);
}

/// Writes `bytes` over the index header of the segment at `base`.
fn overwrite_header(disk: &FaultDisk, base: u64, bytes: &[u8]) {
    let mut raw = disk.clone();
    let index = raw
        .open(&Path::new(DIR).join(index_name(RECORDING, base)))
        .unwrap();
    raw.write_at(&index, 0, bytes).unwrap();
}

/// #339 review P1: a torn header before the last segment, another version
/// under a valid CRC, and a start outside the segment are typed errors;
/// only the last segment's torn header is a segment being created.
#[test]
fn bad_headers_are_typed_errors() {
    let written = |disk: &FaultDisk| {
        let mut store = SegmentStore::create(
            disk.clone(),
            Path::new(DIR),
            RECORDING,
            geometry(),
            SyncPolicy::PerSegment,
            0,
        )
        .unwrap();
        store.append(0, &stream(300)).unwrap();
        store.close().unwrap();
    };
    let recover = |disk: &FaultDisk| {
        SegmentStore::recover(
            disk.clone(),
            Path::new(DIR),
            RECORDING,
            geometry(),
            SyncPolicy::PerSegment,
        )
    };
    // A torn first header, with later segments and data behind it:
    // corruption, not a new start.
    let disk = FaultDisk::default();
    written(&disk);
    overwrite_header(&disk, 0, &[0xFF; 8]);
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 0,
            problem: HeaderProblem::Corrupt
        })
    ));
    // A torn header on the last segment that holds data: corruption too,
    // and its files stay.
    let disk = FaultDisk::default();
    written(&disk);
    overwrite_header(&disk, 256, &[0xFF; 8]);
    let mut raw = disk.clone();
    let before = raw.list(Path::new(DIR)).unwrap().len();
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 256,
            problem: HeaderProblem::Corrupt
        })
    ));
    assert_eq!(raw.list(Path::new(DIR)).unwrap().len(), before);
    // The same with entries but no data behind the torn header: the
    // entries alone make it corruption.
    let disk = FaultDisk::default();
    written(&disk);
    let mut raw = disk.clone();
    let data = raw
        .open(&Path::new(DIR).join(data_name(RECORDING, 256)))
        .unwrap();
    raw.truncate(&data, 0).unwrap();
    overwrite_header(&disk, 256, &[0xFF; 8]);
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 256,
            problem: HeaderProblem::Corrupt
        })
    ));
    assert_eq!(raw.list(Path::new(DIR)).unwrap().len(), before);
    // A zeroed header on the last segment with data behind it: the header
    // was durable before the data, so it is corruption, and no cut hides
    // it (the previous segment ends at its base).
    let disk = FaultDisk::default();
    written(&disk);
    overwrite_header(&disk, 256, &[0u8; 48]);
    let mut raw = disk.clone();
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 256,
            problem: HeaderProblem::Corrupt
        })
    ));
    assert_eq!(raw.list(Path::new(DIR)).unwrap().len(), before);
    // The last index gone while its data file holds data.
    let disk = FaultDisk::default();
    written(&disk);
    let mut raw = disk.clone();
    raw.remove(&Path::new(DIR).join(index_name(RECORDING, 256)))
        .unwrap();
    let kept = raw.list(Path::new(DIR)).unwrap().len();
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 256,
            problem: HeaderProblem::Incomplete
        })
    ));
    assert_eq!(raw.list(Path::new(DIR)).unwrap().len(), kept);
    // A missing (zeroed) header before the last segment, with data behind
    // it: corruption.
    let disk = FaultDisk::default();
    written(&disk);
    overwrite_header(&disk, 128, &[0u8; 48]);
    let mut raw = disk.clone();
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 128,
            problem: HeaderProblem::Corrupt
        })
    ));
    assert_eq!(raw.list(Path::new(DIR)).unwrap().len(), before);
    // A missing header before the last segment with nothing behind it is
    // still never a segment being created.
    let disk = FaultDisk::default();
    written(&disk);
    let mut raw = disk.clone();
    for name in [data_name(RECORDING, 128), index_name(RECORDING, 128)] {
        let file = raw.open(&Path::new(DIR).join(name)).unwrap();
        raw.truncate(&file, 0).unwrap();
    }
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 128,
            problem: HeaderProblem::Incomplete
        })
    ));
    assert_eq!(raw.list(Path::new(DIR)).unwrap().len(), before);
    // An index whose data file is gone.
    let disk = FaultDisk::default();
    written(&disk);
    let mut raw = disk.clone();
    raw.remove(&Path::new(DIR).join(data_name(RECORDING, 128)))
        .unwrap();
    let before = raw.list(Path::new(DIR)).unwrap().len();
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 128,
            problem: HeaderProblem::Incomplete
        })
    ));
    assert_eq!(raw.list(Path::new(DIR)).unwrap().len(), before);
    // Another version under a valid CRC.
    let disk = FaultDisk::default();
    written(&disk);
    let mut header = Header {
        recording: RECORDING,
        base: 128,
        start: 128,
        segment_length: 128,
        term_length: 64,
    }
    .encode();
    header[4..8].copy_from_slice(&2u32.to_le_bytes());
    let crc = crc32c(&header[..44]);
    header[44..].copy_from_slice(&crc.to_le_bytes());
    overwrite_header(&disk, 128, &header);
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 128,
            problem: HeaderProblem::Foreign
        })
    ));
    // A start outside its segment.
    let disk = FaultDisk::default();
    written(&disk);
    let header = Header {
        recording: RECORDING,
        base: 128,
        start: 500,
        segment_length: 128,
        term_length: 64,
    }
    .encode();
    overwrite_header(&disk, 128, &header);
    assert!(matches!(
        recover(&disk),
        Err(SegmentError::BadHeader {
            base: 128,
            problem: HeaderProblem::OutOfRange
        })
    ));
    // The last segment's zeroed header with nothing behind it: being
    // created, removed, and the recording ends where the previous segment
    // does.
    let disk = FaultDisk::default();
    {
        let mut store = SegmentStore::create(
            disk.clone(),
            Path::new(DIR),
            RECORDING,
            geometry(),
            SyncPolicy::PerSegment,
            0,
        )
        .unwrap();
        store.append(0, &stream(256)).unwrap();
        store.roll(256).unwrap();
        store.close().unwrap();
    }
    overwrite_header(&disk, 256, &[0u8; 48]);
    let recovered = recover(&disk).unwrap();
    assert_eq!(recovered.store.written(), 256);
    assert_eq!(recovered.dropped_segments, 1);
}

/// #339 review P2: the interval policy does not sync at a roll; its next
/// tick syncs the finished segment and the open one.
#[test]
fn the_interval_policy_syncs_a_roll_at_its_tick() {
    let mut store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::Every { interval_ns: 100 },
        0,
    )
    .unwrap();
    store.append(0, &stream(200)).unwrap();
    assert_eq!(store.durable(), 0, "no sync on the write path");
    assert_eq!(store.finished.len(), 1);
    assert_eq!(store.tick(100).unwrap(), 200);
    assert!(store.finished.is_empty());
}

/// #339 review P3: a store under the interval policy that is never ticked
/// keeps at most `MAX_FINISHED` finished segments open; the roll past
/// them syncs them inline.
#[test]
fn the_interval_policy_bounds_the_finished_segments() {
    let mut store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::Every { interval_ns: 100 },
        0,
    )
    .unwrap();
    let length = u64::try_from(MAX_FINISHED).unwrap() * 128;
    store
        .append(0, &stream(usize::try_from(length).unwrap() + 1))
        .unwrap();
    assert_eq!(store.finished.len(), MAX_FINISHED);
    assert_eq!(store.durable(), 0, "no sync up to the cap");
    store.append(length + 1, &stream(128)).unwrap();
    assert!(store.finished.len() <= MAX_FINISHED);
    assert!(store.durable() > length, "the roll past the cap synced");
}

/// #339 review P3: an explicit sync restarts the interval at the next
/// tick.
#[test]
fn an_explicit_sync_restarts_the_interval() {
    let mut store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::Every { interval_ns: 100 },
        0,
    )
    .unwrap();
    store.append(0, &[1; 10]).unwrap();
    assert_eq!(store.sync().unwrap(), 10);
    assert_eq!(store.tick(500).unwrap(), 10);
    store.append(10, &[2; 10]).unwrap();
    assert_eq!(
        store.tick(550).unwrap(),
        10,
        "within the restarted interval"
    );
    assert_eq!(store.tick(600).unwrap(), 20);
}

/// #339 review P2: a data range torn under a valid entry (its bytes
/// changed, the file long enough) and a short data file are both cut at
/// that entry, never read back.
#[test]
fn a_torn_range_under_a_valid_entry_is_cut() {
    for short in [false, true] {
        let disk = FaultDisk::default();
        let dir = Path::new(DIR);
        let mut store = SegmentStore::create(
            disk.clone(),
            dir,
            RECORDING,
            geometry(),
            SyncPolicy::None,
            0,
        )
        .unwrap();
        store.append(0, &stream(40)).unwrap();
        store.append(40, &stream(80)[40..]).unwrap();
        drop(store);
        let mut raw = disk.clone();
        let data = raw.open(&dir.join(data_name(RECORDING, 0))).unwrap();
        if short {
            raw.truncate(&data, 60).unwrap();
        } else {
            raw.write_at(&data, 50, &[0xEE; 4]).unwrap();
        }
        let recovered =
            SegmentStore::recover(disk, dir, RECORDING, geometry(), SyncPolicy::None).unwrap();
        assert_eq!(
            recovered.cut,
            Some(Cut {
                position: 40,
                reason: CutReason::DataChecksum
            }),
            "short {short}"
        );
        assert_eq!(recovered.store.written(), 40);
    }
}
