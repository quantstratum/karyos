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

use std::io;
use std::path::Path;

use proptest::prelude::*;

use super::*;
use crate::fault::{FaultDisk, Survives};

const DIR: &str = "/archive";
const RECORDING: u64 = 7;

fn geometry() -> Geometry {
    Geometry::new(64, 128).unwrap()
}

/// Recovers through [`SegmentStore::recover`], checking it against
/// [`SegmentStore::verify`] first: verify leaves every byte, name and
/// sync of the disk as it was, and recover then does exactly what its
/// plan said, or refuses with the same error and changes nothing.
fn recover_checked(
    disk: FaultDisk,
    dir: &Path,
    recording: u64,
    geometry: Geometry,
    policy: SyncPolicy,
) -> Result<Recovered<FaultDisk>, SegmentError> {
    let before = disk.snapshot();
    let plan = SegmentStore::verify(disk.clone(), dir, recording, geometry);
    assert_eq!(disk.snapshot(), before, "verify changed the disk");
    let recovered = SegmentStore::recover(disk.clone(), dir, recording, geometry, policy);
    let mut probe = disk.clone();
    let exists = |probe: &mut FaultDisk, name: String| probe.open(&dir.join(name)).is_ok();
    match (&plan, &recovered) {
        (Ok(plan), Ok(recovered)) => {
            let kept = plan.kept.expect("a kept segment");
            assert_eq!(plan.cut, recovered.cut);
            assert_eq!(
                plan.dropped.len(),
                usize::try_from(recovered.dropped_segments).unwrap()
            );
            assert_eq!(
                (kept.start, kept.written, kept.written),
                (
                    recovered.store.start(),
                    recovered.store.written(),
                    recovered.store.durable()
                )
            );
            let data = probe
                .open(&dir.join(data_name(recording, kept.base)))
                .unwrap();
            let index = probe
                .open(&dir.join(index_name(recording, kept.base)))
                .unwrap();
            assert!(probe.len(&data).unwrap() <= kept.written - kept.base);
            // The kept index ends at its last kept entry, cut or not.
            let entries_end = entry_offset(kept.entries).unwrap();
            assert_eq!(probe.len(&index).unwrap(), entries_end);
            assert!(kept.index_length.is_none_or(|length| length == entries_end));
        }
        (Ok(plan), Err(SegmentError::NotFound { .. })) => assert!(plan.kept.is_none()),
        (Err(planned), Err(refused)) => {
            assert_eq!(planned.to_string(), refused.to_string());
            assert_eq!(disk.snapshot(), before, "a refusal changed the disk");
        }
        (plan, recovered) => panic!(
            "verify {plan:?} disagrees with recover {:?}",
            recovered.as_ref().map(|recovered| recovered.cut)
        ),
    }
    if let Ok(plan) = &plan {
        for dropped in &plan.dropped {
            assert!(!exists(&mut probe, data_name(recording, dropped.base)));
            assert!(!exists(&mut probe, index_name(recording, dropped.base)));
        }
    }
    recovered
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
    /// Truncates to the start plus this many bytes.
    Truncate(u64),
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
            Step::Truncate(offset) => store.truncate(start + offset).map(|_| {
                position = start + offset;
            }),
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
    let recovered = match recover_checked(disk, dir, RECORDING, geometry(), policy) {
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
        let recovered = recover_checked(
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
        recover_checked(disk, dir, RECORDING, geometry(), SyncPolicy::PerSegment).unwrap();
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
    let recovered = recover_checked(
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
        recover_checked(disk.clone(), dir, RECORDING, other, SyncPolicy::PerSegment),
        Err(SegmentError::BadHeader {
            problem: HeaderProblem::Mismatch,
            ..
        })
    ));
    assert_eq!(raw.list(dir).unwrap().len(), before, "nothing removed");
    // With its own geometry it recovers whole.
    let recovered =
        recover_checked(disk, dir, RECORDING, geometry(), SyncPolicy::PerSegment).unwrap();
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
        recover_checked(
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
    raw.set_len(&data, 0).unwrap();
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
        raw.set_len(&file, 0).unwrap();
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
    header[4..8].copy_from_slice(&3u32.to_le_bytes());
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

/// The creation gap: a last segment with a valid index header, no entry
/// and no data file is a creation cut short (the data file's directory
/// entry did not survive the crash, the index's did). Recovery removes it,
/// as `verify` reports first, and the recording ends where the previous
/// segment does.
#[test]
fn a_last_segment_without_its_data_file_is_a_creation_cut_short() {
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
    let mut raw = disk.clone();
    raw.remove(&Path::new(DIR).join(data_name(RECORDING, 256)))
        .unwrap();
    let plan = SegmentStore::verify(disk.clone(), Path::new(DIR), RECORDING, geometry()).unwrap();
    assert_eq!(
        plan.dropped,
        [DroppedSegment {
            base: 256,
            reason: DropReason::CreationGap
        }]
    );
    assert_eq!(plan.cut, None);
    assert_eq!(
        plan.kept.map(|kept| (kept.base, kept.written)),
        Some((128, 256))
    );
    let recovered = recover_checked(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
    )
    .unwrap();
    assert_eq!(recovered.store.written(), 256);
    assert_eq!(recovered.dropped_segments, 1);
    assert!(
        raw.open(&Path::new(DIR).join(index_name(RECORDING, 256)))
            .is_err()
    );
}

/// A disk that refuses every open for writing, to show a scan opens only
/// for reading; everything else goes to the disk it wraps.
struct NoWritableOpen<D>(D);

impl<D: Disk> Disk for NoWritableOpen<D> {
    type File = D::File;

    fn create(&mut self, path: &Path) -> io::Result<Self::File> {
        self.0.create(path)
    }

    fn open(&mut self, _path: &Path) -> io::Result<Self::File> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "opened for writing",
        ))
    }

    fn open_read(&mut self, path: &Path) -> io::Result<Self::File> {
        self.0.open_read(path)
    }

    fn write_at(&mut self, file: &Self::File, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.write_at(file, offset, bytes)
    }

    fn read_at(&mut self, file: &Self::File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_at(file, offset, buf)
    }

    fn len(&mut self, file: &Self::File) -> io::Result<u64> {
        self.0.len(file)
    }

    fn set_len(&mut self, file: &Self::File, len: u64) -> io::Result<()> {
        self.0.set_len(file, len)
    }

    fn sync(&mut self, file: &Self::File) -> io::Result<()> {
        self.0.sync(file)
    }

    fn sync_dir(&mut self, dir: &Path) -> io::Result<()> {
        self.0.sync_dir(dir)
    }

    fn list(&mut self, dir: &Path) -> io::Result<Vec<String>> {
        self.0.list(dir)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.0.remove(path)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        self.0.rename(from, to)
    }
}

/// #427 review P2-2: `verify` runs over a read-only disk
/// (`disk::ReadOnly`) and never opens a file for writing: its plan there
/// is the one it reports over the writable disk, and the disk is as it
/// was.
#[test]
fn verify_opens_only_for_reading() {
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
        store.append(0, &stream(300)).unwrap();
        store.close().unwrap();
    }
    // A torn entry on the last segment: the plan cuts its index.
    let mut raw = disk.clone();
    let index = raw
        .open(&Path::new(DIR).join(index_name(RECORDING, 256)))
        .unwrap();
    let length = raw.len(&index).unwrap();
    raw.set_len(&index, length - 1).unwrap();
    let before = disk.snapshot();
    let planned =
        SegmentStore::verify(disk.clone(), Path::new(DIR), RECORDING, geometry()).unwrap();
    let read_only = SegmentStore::verify(
        NoWritableOpen(crate::disk::ReadOnly(disk.clone())),
        Path::new(DIR),
        RECORDING,
        geometry(),
    )
    .unwrap();
    assert_eq!(read_only, planned);
    assert!(planned.cut.is_some());
    assert_eq!(disk.snapshot(), before);
}

/// #427 review P2-1: a last segment whose data file is gone but whose
/// index holds entries is no creation: it is refused, typed, and the disk
/// stays byte for byte as it was.
#[test]
fn a_last_segment_with_entries_and_no_data_file_is_refused() {
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
        store.append(0, &stream(300)).unwrap();
        store.close().unwrap();
    }
    let mut raw = disk.clone();
    raw.remove(&Path::new(DIR).join(data_name(RECORDING, 256)))
        .unwrap();
    let before = disk.snapshot();
    assert!(matches!(
        recover_checked(
            disk.clone(),
            Path::new(DIR),
            RECORDING,
            geometry(),
            SyncPolicy::PerSegment,
        ),
        Err(SegmentError::BadHeader {
            base: 256,
            problem: HeaderProblem::Incomplete
        })
    ));
    assert_eq!(disk.snapshot(), before);
}

/// #427 review P3: a creation gap that does not start where the recording
/// ends (the segment before it is gone) cuts the recording at its end as
/// `NotContiguous`, and the gap is removed.
#[test]
fn a_creation_gap_after_a_missing_segment_cuts_at_the_recording_end() {
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
        store.append(0, &stream(384)).unwrap();
        store.close().unwrap();
    }
    let mut raw = disk.clone();
    for name in [data_name(RECORDING, 128), index_name(RECORDING, 128)] {
        raw.remove(&Path::new(DIR).join(name)).unwrap();
    }
    raw.remove(&Path::new(DIR).join(data_name(RECORDING, 256)))
        .unwrap();
    let index = raw
        .open(&Path::new(DIR).join(index_name(RECORDING, 256)))
        .unwrap();
    raw.set_len(&index, HEADER).unwrap();
    let plan = SegmentStore::verify(disk.clone(), Path::new(DIR), RECORDING, geometry()).unwrap();
    assert_eq!(
        plan.cut,
        Some(Cut {
            position: 128,
            reason: CutReason::NotContiguous
        })
    );
    assert_eq!(
        plan.dropped,
        [DroppedSegment {
            base: 256,
            reason: DropReason::CreationGap
        }]
    );
    let recovered = recover_checked(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
    )
    .unwrap();
    assert_eq!(recovered.store.written(), 128);
    assert_eq!(recovered.cut, plan.cut);
}

/// The same state before the last segment is never a creation: a middle
/// segment with a valid header, no entry and no data file lost its data
/// file, and recovery refuses it and removes nothing.
#[test]
fn a_middle_segment_without_its_data_file_is_refused() {
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
        store.append(0, &stream(384)).unwrap();
        store.close().unwrap();
    }
    let mut raw = disk.clone();
    raw.remove(&Path::new(DIR).join(data_name(RECORDING, 128)))
        .unwrap();
    let index = raw
        .open(&Path::new(DIR).join(index_name(RECORDING, 128)))
        .unwrap();
    raw.set_len(&index, HEADER).unwrap();
    let before = disk.snapshot();
    assert!(matches!(
        recover_checked(
            disk.clone(),
            Path::new(DIR),
            RECORDING,
            geometry(),
            SyncPolicy::PerSegment,
        ),
        Err(SegmentError::BadHeader {
            base: 128,
            problem: HeaderProblem::Incomplete
        })
    ));
    assert_eq!(disk.snapshot(), before);
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
            raw.set_len(&data, 60).unwrap();
        } else {
            raw.write_at(&data, 50, &[0xEE; 4]).unwrap();
        }
        let recovered =
            recover_checked(disk, dir, RECORDING, geometry(), SyncPolicy::None).unwrap();
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

/// A piece of a recording, for the workloads with fills and gaps.
#[derive(Debug, Clone, Copy)]
enum Piece {
    /// `n` stream bytes.
    Data(usize),
    /// A fill of this extent.
    Fill(u32),
    /// A lost range of this length.
    Gap(u64),
    /// A sync.
    Sync,
}

/// The canonical record a fill at `position` stores.
fn fill_record(position: u64) -> [u8; FILL_RECORD] {
    let mut record = [0u8; FILL_RECORD];
    record[..8].copy_from_slice(&position.to_le_bytes());
    record[8] = 0xAB;
    record
}

/// Appends `piece` from `position` (the written one), or its rest from
/// `position` when a crash cut it there; returns the new written position.
fn apply_piece<D: Disk>(
    store: &mut SegmentStore<D>,
    piece_start: u64,
    piece: Piece,
    position: u64,
) -> Result<u64, SegmentError> {
    match piece {
        Piece::Data(length) => {
            let from = usize::try_from(position - piece_start).unwrap();
            let bytes = piece_bytes(piece_start, length);
            store.append(position, &bytes[from..])
        }
        Piece::Fill(extent) => store.append_fill(position, &fill_record(piece_start), extent),
        Piece::Gap(length) => store.append_gap(position, piece_start + length),
        Piece::Sync => store.sync(),
    }
}

/// The bytes of a data piece at `start`.
fn piece_bytes(start: u64, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from((start as usize + index * 13 + 1) % 253).unwrap())
        .collect()
}

/// Each piece with its start position.
fn layout(start: u64, pieces: &[Piece]) -> Vec<(u64, Piece)> {
    let mut position = start;
    pieces
        .iter()
        .map(|&piece| {
            let at = position;
            position += match piece {
                Piece::Data(length) => length as u64,
                Piece::Fill(extent) => u64::from(extent),
                Piece::Gap(length) => length,
                Piece::Sync => 0,
            };
            (at, piece)
        })
        .collect()
}

/// Runs `pieces` on `disk`; returns whether the store was created and the
/// last durable position reported.
fn run_pieces(disk: FaultDisk, pieces: &[Piece], start: u64) -> Reported {
    let dir = Path::new(DIR);
    let Ok(mut store) = SegmentStore::create(
        disk,
        dir,
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        start,
    ) else {
        return Reported {
            created: false,
            durable: start,
        };
    };
    let mut reported = Reported {
        created: true,
        durable: store.durable(),
    };
    for (at, piece) in layout(start, pieces) {
        match apply_piece(&mut store, at, piece, at) {
            Ok(_) => reported.durable = store.durable(),
            Err(_) => return reported,
        }
    }
    if let Ok(durable) = store.close() {
        reported.durable = durable;
    }
    reported
}

/// Checks a recovery of `pieces` against the gate, then continues it.
fn check_pieces(
    crashed: &FaultDisk,
    survives: Survives,
    reported: Reported,
    pieces: &[Piece],
    start: u64,
) -> Result<(), String> {
    let recovered = match recover_checked(
        crashed.after_crash(survives),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
    ) {
        Ok(recovered) => recovered,
        Err(SegmentError::NotFound { .. }) if !reported.created => return Ok(()),
        Err(error) => return Err(format!("recovery failed: {error}")),
    };
    let mut store = recovered.store;
    let written = store.written();
    if written < reported.durable {
        return Err(format!(
            "written {written} below durable {}",
            reported.durable
        ));
    }
    let pieces = layout(start, pieces);
    // Every whole or partly kept piece reads back as written.
    for &(at, piece) in &pieces {
        let end = at
            + match piece {
                Piece::Data(length) => length as u64,
                Piece::Fill(extent) => u64::from(extent),
                Piece::Gap(length) => length,
                Piece::Sync => 0,
            };
        let kept = end.min(written);
        if kept <= at {
            continue;
        }
        let mut read = vec![0u8; usize::try_from(kept - at).unwrap()];
        match piece {
            Piece::Data(length) => {
                store
                    .read(at, &mut read)
                    .map_err(|error| error.to_string())?;
                if read != piece_bytes(at, length)[..read.len()] {
                    return Err(format!("data at {at} differs"));
                }
            }
            Piece::Fill(_) => {
                if kept != end {
                    return Err(format!("fill at {at} kept in part"));
                }
                store
                    .read(at, &mut read)
                    .map_err(|error| error.to_string())?;
                if read[..FILL_RECORD] != fill_record(at)
                    || read[FILL_RECORD..].iter().any(|b| *b != 0)
                {
                    return Err(format!("fill at {at} differs"));
                }
            }
            Piece::Gap(_) => {
                if !matches!(store.read(at, &mut read), Err(SegmentError::Gap { .. })) {
                    return Err(format!("gap at {at} was readable"));
                }
            }
            Piece::Sync => {}
        }
    }
    // Restart and continue: the rest of the cut piece, then every later one.
    let mut position = written;
    for &(at, piece) in &pieces {
        let end = at
            + match piece {
                Piece::Data(length) => length as u64,
                Piece::Fill(extent) => u64::from(extent),
                Piece::Gap(length) => length,
                Piece::Sync => 0,
            };
        if end <= position && !matches!(piece, Piece::Sync) {
            continue;
        }
        if matches!(piece, Piece::Sync) {
            continue;
        }
        position =
            apply_piece(&mut store, at, piece, position).map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// A workload of data, fills (padding to a term end) and gaps, crossing
/// segments; one gap spans a roll.
fn pieces() -> Vec<Piece> {
    vec![
        Piece::Data(40),
        Piece::Fill(24 + 64),
        Piece::Sync,
        Piece::Data(30),
        Piece::Gap(150),
        Piece::Data(20),
        Piece::Sync,
        Piece::Fill(32),
        Piece::Data(10),
    ]
}

/// A4: fills and gaps keep the gate's properties at every crash point.
#[test]
fn every_crash_point_keeps_fills_and_gaps() {
    let free = FaultDisk::default();
    let _ = run_pieces(free.clone(), &pieces(), 0);
    let mut failures = Vec::new();
    for budget in 0..=free.used() {
        let disk = FaultDisk::with_budget(budget);
        let reported = run_pieces(disk.clone(), &pieces(), 0);
        for survives in [Survives::Everything, Survives::Synced, Survives::TornData] {
            if let Err(failure) = check_pieces(&disk, survives, reported, &pieces(), 0) {
                failures.push(format!("budget {budget}, {survives:?}: {failure}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A fill must hold its record and fit its segment; a gap is refused to
/// reads and reported by `gaps`.
#[test]
fn fills_and_gaps_are_checked() {
    let mut store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    assert!(matches!(
        store.append_fill(0, &fill_record(0), 31),
        Err(SegmentError::InvalidFill { extent: 31 })
    ));
    assert!(matches!(
        store.append_fill(0, &fill_record(0), 129),
        Err(SegmentError::InvalidFill { extent: 129 })
    ));
    assert_eq!(store.append_fill(0, &fill_record(0), 64).unwrap(), 64);
    assert_eq!(store.append_gap(64, 100).unwrap(), 100);
    assert_eq!(store.append_gap(100, 300).unwrap(), 300);
    assert_eq!(store.gaps(), [(64, 300)]);
    let mut out = [0u8; 8];
    assert!(matches!(
        store.read(90, &mut out),
        Err(SegmentError::Gap { from: 64, to: 300 })
    ));
    let mut fill = [1u8; 64];
    store.read(0, &mut fill).unwrap();
    assert_eq!(fill[..FILL_RECORD], fill_record(0));
}

/// An index entry of an unknown kind is refused at recovery, not cut.
#[test]
fn an_unknown_entry_kind_is_refused() {
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
    store.append(0, &[1; 10]).unwrap();
    drop(store);
    let entry = Entry {
        start: 10,
        length: 4,
        data_crc: 0,
        kind: EntryKind::Gap,
        time_ns: 0,
    };
    let mut bytes = entry.encode();
    bytes[16] = 9;
    let crc = crc32c(&bytes[..28]);
    bytes[28..].copy_from_slice(&crc.to_le_bytes());
    let mut raw = disk.clone();
    let index = raw.open(&dir.join(index_name(RECORDING, 0))).unwrap();
    raw.write_at(&index, HEADER + ENTRY, &bytes).unwrap();
    assert!(matches!(
        recover_checked(disk, dir, RECORDING, geometry(), SyncPolicy::None),
        Err(SegmentError::UnknownEntryKind {
            position: 10,
            kind: 9
        })
    ));
}

/// #341 review P3: a fill's extent lies in the data file before its entry
/// is written; a data file shorter than the extent is cut at the fill.
#[test]
fn a_fill_whose_extent_is_not_in_the_file_is_cut() {
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
    store.append(0, &[1; 10]).unwrap();
    store.append_fill(10, &fill_record(10), 64).unwrap();
    store.close().unwrap();
    // The record is whole, but the extent's end is not in the file.
    let mut raw = disk.clone();
    let data = raw.open(&dir.join(data_name(RECORDING, 0))).unwrap();
    raw.set_len(&data, 10 + 40).unwrap();
    let recovered =
        recover_checked(disk, dir, RECORDING, geometry(), SyncPolicy::PerSegment).unwrap();
    assert_eq!(recovered.store.written(), 10);
    assert_eq!(
        recovered.cut,
        Some(Cut {
            position: 10,
            reason: CutReason::DataChecksum
        })
    );
}

/// #341 review P3: a store records at most `MAX_GAPS` lost ranges; one
/// more is refused before anything is written, and one that joins the
/// last still fits.
#[test]
fn the_gaps_are_bounded() {
    let mut store = SegmentStore::create(
        FaultDisk::default(),
        Path::new(DIR),
        RECORDING,
        Geometry::new(64, 64 * 1024).unwrap(),
        SyncPolicy::None,
        0,
    )
    .unwrap();
    let mut position = 0;
    for _ in 0..MAX_GAPS {
        position = store.append(position, &[1]).unwrap();
        position = store.append_gap(position, position + 1).unwrap();
    }
    assert_eq!(store.gaps().len(), MAX_GAPS);
    assert!(store.gap_fits(), "joining the last gap still fits");
    position = store.append_gap(position, position + 1).unwrap();
    position = store.append(position, &[1]).unwrap();
    assert!(!store.gap_fits());
    assert!(matches!(
        store.append_gap(position, position + 1),
        Err(SegmentError::TooManyGaps)
    ));
    assert_eq!(store.written(), position, "nothing was written");
    assert!(store.append(position, &[1]).is_ok(), "the store is whole");
}

/// #341 review P3: an index holding more lost ranges than a store records
/// (only a crafted one can) is refused at recovery.
#[test]
fn an_index_with_too_many_gaps_is_refused() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let geometry = Geometry::new(64, 64 * 1024).unwrap();
    let mut store =
        SegmentStore::create(disk.clone(), dir, RECORDING, geometry, SyncPolicy::None, 0).unwrap();
    let mut position = 0;
    for _ in 0..MAX_GAPS {
        position = store.append(position, &[1]).unwrap();
        position = store.append_gap(position, position + 1).unwrap();
    }
    position = store.append(position, &[1]).unwrap();
    drop(store);
    // One more gap entry after the last, as no store writes it.
    let entries = u64::try_from(2 * MAX_GAPS + 1).unwrap();
    let entry = Entry {
        start: position,
        length: 1,
        data_crc: 0,
        kind: EntryKind::Gap,
        time_ns: 0,
    };
    let mut raw = disk.clone();
    let index = raw.open(&dir.join(index_name(RECORDING, 0))).unwrap();
    raw.write_at(&index, HEADER + entries * ENTRY, &entry.encode())
        .unwrap();
    assert!(matches!(
        recover_checked(disk, dir, RECORDING, geometry, SyncPolicy::None),
        Err(SegmentError::TooManyGaps)
    ));
}

/// The truncation gate: appends, truncations inside a segment, at a
/// segment's end and back to the start, each followed by more appends. At
/// every crash point and under the three crash models, recovery keeps at
/// least what was reported durable (a truncation lowers it), reads the
/// stream back exactly, and continues.
#[test]
fn every_crash_point_survives_a_truncation() {
    let steps = [
        Step::Append(50),
        Step::Append(100),
        Step::Sync,
        Step::Append(30),
        // Inside the third segment, at the end of a write.
        Step::Truncate(150),
        Step::Append(40),
        Step::Append(90),
        // At the end of the first segment: a write ends there.
        Step::Truncate(128),
        Step::Append(20),
        // Back to the start.
        Step::Truncate(0),
        Step::Append(70),
    ];
    for (policy, start) in [
        (SyncPolicy::PerSegment, 0),
        (SyncPolicy::None, 0),
        (SyncPolicy::Every { interval_ns: 1 }, 0),
    ] {
        let failures = crash_everywhere(&steps, policy, start, false);
        assert!(
            failures.is_empty(),
            "{policy:?} from {start}: {failures:#?}"
        );
    }
}

/// Once `truncate` returns, a crash recovers exactly to its position,
/// whatever survives.
#[test]
fn a_truncation_holds_once_it_returns() {
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
    let bytes = stream(300);
    store.append(0, &bytes[..100]).unwrap();
    store.append(100, &bytes[100..300]).unwrap();
    assert_eq!(store.truncate(100).unwrap(), 100);
    assert_eq!((store.written(), store.durable()), (100, 100));
    // No stale byte lingers past the written position.
    let mut files = disk.clone();
    let data = files.open(&dir.join(data_name(RECORDING, 0))).unwrap();
    assert_eq!(files.len(&data).unwrap(), 100);
    let mut beyond = [0u8; 1];
    assert!(matches!(
        store.read(100, &mut beyond),
        Err(SegmentError::OutOfRange { .. })
    ));
    for survives in [Survives::Everything, Survives::Synced, Survives::TornData] {
        let recovered = recover_checked(
            disk.after_crash(survives),
            dir,
            RECORDING,
            geometry(),
            SyncPolicy::None,
        )
        .unwrap();
        assert_eq!(recovered.store.written(), 100, "{survives:?}");
        assert_eq!(recovered.cut, None, "{survives:?}");
        assert_eq!(recovered.dropped_segments, 0, "{survives:?}");
    }
}

/// A position outside the recording, or inside a write, is refused with
/// nothing changed; truncating to the written position changes nothing.
#[test]
fn an_invalid_truncation_changes_nothing() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut store =
        SegmentStore::create(disk, dir, RECORDING, geometry(), SyncPolicy::None, 10).unwrap();
    let bytes = stream(100);
    store.append(10, &bytes[..40]).unwrap();
    store.append(50, &bytes[40..100]).unwrap();
    for position in [9, 111, 30, 64 + 10] {
        assert!(
            matches!(
                store.truncate(position),
                Err(SegmentError::InvalidTruncate { .. })
            ),
            "{position}"
        );
        assert_eq!(store.written(), 110);
    }
    assert_eq!(store.truncate(110).unwrap(), 110);
    store.append(110, &bytes[..1]).unwrap();
    assert_eq!(store.truncate(10).unwrap(), 10);
    assert_eq!(store.written(), 10);
}

/// The truncation's terminator never decodes as an entry: its own CRC
/// fails, so recovery cuts there.
#[test]
fn the_terminator_is_never_an_entry() {
    assert_eq!(Entry::decode(&[0u8; 32]), None);
}

/// A truncation to a segment's end keeps that segment whole, also when the
/// next segment was never created (nothing written past the end).
#[test]
fn a_truncation_to_a_segment_end_keeps_it() {
    let disk = FaultDisk::default();
    let dir = Path::new(DIR);
    let mut store =
        SegmentStore::create(disk, dir, RECORDING, geometry(), SyncPolicy::None, 0).unwrap();
    let bytes = stream(200);
    store.append(0, &bytes[..128]).unwrap();
    assert_eq!(store.truncate(128).unwrap(), 128);
    store.append(128, &bytes[128..200]).unwrap();
    assert_eq!(store.truncate(128).unwrap(), 128);
    store.append(128, &bytes[128..200]).unwrap();
    let mut all = vec![0u8; 200];
    store.read(0, &mut all).unwrap();
    assert_eq!(all, bytes);
}

/// A clock read before the last sync (it stepped back) is no interval: the
/// interval policy does not sync on it.
#[test]
fn a_backward_clock_does_not_sync() {
    let dir = Path::new(DIR);
    let mut store = SegmentStore::create(
        FaultDisk::default(),
        dir,
        RECORDING,
        geometry(),
        SyncPolicy::Every { interval_ns: 10 },
        0,
    )
    .unwrap();
    let bytes = stream(20);
    store.append(0, &bytes[..10]).unwrap();
    assert_eq!(store.tick(100).unwrap(), 10);
    store.append(10, &bytes[10..20]).unwrap();
    assert_eq!(store.tick(50).unwrap(), 10, "no sync on a backward step");
    assert_eq!(store.tick(110).unwrap(), 20);
}
