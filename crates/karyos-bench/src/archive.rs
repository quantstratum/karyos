// SPDX-License-Identifier: Apache-2.0

//! The Archive's write and sync cost over a real disk (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A2; ACS 16739 and 16990).
//!
//! - `archive-append` appends `message` bytes per iteration to a segment
//!   store that never syncs: the write path alone.
//! - `archive-sync` appends and then syncs each time: data, then index, as
//!   a durable position needs. It is a `required` recording's worst case.
//!
//! Disk use: a run writes `(warmup + iterations) × message` bytes of data,
//! plus a 32-byte index entry per append and a 48-byte header per
//! segment; `archive-append` at 64 KiB and 100 000 iterations writes about
//! 7 GB. Choose `--iterations` for the disk measured.
//!
//! The store lives in a fresh directory under the system's temporary
//! directory, or under `KARYOS_BENCH_DIR` to measure a chosen disk, and is
//! removed when the run ends, a panic included. Segments are four terms
//! long, so a run crosses rolls and pays their creation syncs. A record
//! names the directory, its filesystem, the sync policy and whether syncs
//! are `F_FULLFSYNC` (Apple targets): disks differ per host, so these
//! results are compared only under the same host and filesystem, and no
//! gate reads them.

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::workloads::{
    BenchError, Config, Measurement, Workload, error, histogram, record, resolution,
};
use karyos_archive::disk::StdDisk;
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};

/// Where an archive run wrote, and how it synced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveRun {
    /// The directory the segments were written in, through
    /// [`crate::env::clean`]: no quote or backslash, so the history line
    /// needs no escaping.
    pub dir: String,
    /// Its filesystem, where the host says (`unknown` otherwise), cleaned
    /// the same way.
    pub filesystem: String,
    /// The store's sync policy, and for `archive-sync` the explicit sync
    /// after every append.
    pub policy: &'static str,
    /// Whether a sync is `F_FULLFSYNC` (Apple targets), else `fdatasync`.
    pub full_fsync: bool,
}

/// The run's directory, removed when dropped.
struct RunDir(PathBuf);

impl RunDir {
    fn new() -> Result<Self, BenchError> {
        let base =
            std::env::var_os("KARYOS_BENCH_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let path = base.join(format!("karyos-bench-archive-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path).map_err(|cause| error("clear the run dir", cause))?;
        }
        std::fs::create_dir_all(&path).map_err(|cause| error("create the run dir", cause))?;
        Ok(Self(path))
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The filesystem of `dir`, as the host's tools name it.
fn filesystem(dir: &Path) -> String {
    let path = dir.to_string_lossy();
    let found = if cfg!(target_os = "linux") {
        crate::env::command("stat", &["-f", "-c", "%T", &path])
    } else {
        // `df -P` names the mount point; `mount` lists its type.
        crate::env::command("df", &["-P", &path])
            .and_then(|df| {
                df.lines()
                    .nth(1)?
                    .split_whitespace()
                    .last()
                    .map(str::to_owned)
            })
            .and_then(|mount_point| {
                let marker = format!(" on {mount_point} (");
                crate::env::command("mount", &[])?.lines().find_map(|line| {
                    let rest = line.split_once(&marker)?.1;
                    rest.split([',', ')']).next().map(str::to_owned)
                })
            })
    };
    found.map_or_else(|| "unknown".to_owned(), |name| crate::env::clean(&name))
}

/// Runs `archive-append` or `archive-sync`.
///
/// # Errors
///
/// A segment store or directory error, or a configuration it cannot run.
pub fn run(config: Config) -> Result<Measurement, BenchError> {
    let sync = match config.workload {
        Workload::ArchiveAppend => false,
        Workload::ArchiveSync => true,
        other => {
            return Err(BenchError(format!(
                "{} is not an archive workload",
                other.name()
            )));
        }
    };
    let segment = u64::from(config.term_length)
        .checked_mul(4)
        .ok_or_else(|| BenchError("segment length overflows".into()))?;
    let geometry =
        Geometry::new(config.term_length, segment).map_err(|cause| error("geometry", cause))?;
    let dir = RunDir::new()?;
    let policy = if sync {
        SyncPolicy::PerSegment
    } else {
        SyncPolicy::None
    };
    let mut store = SegmentStore::create(StdDisk, &dir.0, 1, geometry, policy, 0)
        .map_err(|cause| error("create the store", cause))?;
    let payload = vec![0x5Au8; config.message];
    let resolution = resolution();
    let mut position = 0u64;
    let mut latency = histogram()?;
    let total = config
        .warmup
        .checked_add(config.iterations)
        .ok_or_else(|| BenchError("iterations overflow".into()))?;
    let mut measured_since = None;
    for iteration in 0..total {
        if iteration == config.warmup {
            measured_since = Some(Instant::now());
        }
        let start = Instant::now();
        position = store
            .append(position, &payload)
            .map_err(|cause| error("append", cause))?;
        if sync {
            store.sync().map_err(|cause| error("sync", cause))?;
        }
        let elapsed = start.elapsed().as_nanos();
        if iteration >= config.warmup {
            record(&mut latency, elapsed, resolution)?;
        }
    }
    let seconds = measured_since.map_or(0.0, |since: Instant| since.elapsed().as_secs_f64());
    store.close().map_err(|cause| error("close", cause))?;
    let rate = config.iterations as f64 / seconds.max(f64::MIN_POSITIVE);
    let archive = ArchiveRun {
        filesystem: filesystem(&dir.0),
        dir: crate::env::clean(&dir.0.to_string_lossy()),
        policy: if sync { "sync-every-append" } else { "none" },
        full_fsync: sync && cfg!(target_vendor = "apple"),
    };
    Ok(Measurement {
        config,
        latency: Some(latency),
        producer_lateness: None,
        rate,
        resolution,
        cleaned_slots_per_second: None,
        term_rotations_per_second: None,
        archive: Some(archive),
    })
}
