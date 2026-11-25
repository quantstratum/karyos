// SPDX-License-Identifier: Apache-2.0

//! `karyos-backup`: a Cluster node's backup to remote storage, its check,
//! and a rebuild from it (`karyos_cluster::backup`; karyos#717). See
//! [`HELP`].
//!
//! Remote storage here is a directory ([`DirStore`]): one file per object,
//! named by its key, written whole then renamed into place. It is what the
//! documented procedure runs against and what an operator copies to or
//! from object storage with their own tooling, setting the retention and
//! object lock SPEC §8.4 asks for there (this store keeps neither); the S3
//! client (`karyos-tiering`) implements the same `ObjectStore` for an
//! Archive's tiering. Every command runs on the control path, against a
//! stopped node's directories or a copy taken while it was stopped.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::Digest;
use karyos_archive::integrity::copies::Enforcement;
use karyos_archive::integrity::tiering::{ObjectKey, ObjectStore};
use karyos_archive::segment::Geometry;
use karyos_cluster::RaftLog;
use karyos_cluster::backup::{self, Report, Target};
use karyos_cluster::snapshot::{SnapshotConfig, SnapshotStore};

/// The command's help.
pub const HELP: &str = "\
karyos-backup: a Cluster node's backup to remote storage, and a rebuild from it

usage:
  karyos-backup export  --log <dir> --snapshots <dir> --geometry <term>,<segment> --cluster <hex64> --remote <dir> [--retain-until-ns <ns>]
  karyos-backup verify  --cluster <hex64> --remote <dir>
  karyos-backup rebuild --log <dir> --snapshots <dir> --geometry <term>,<segment> --cluster <hex64> --remote <dir>

export   copies the node's latest snapshot and its committed log after it,
         every object read back and checked, the manifest last
verify   checks every object of an export against its manifest, changing
         nothing
rebuild  rebuilds a node from an export into the given directories, which
         exist and are empty, every object checked before anything is
         written

--geometry is the node's log geometry: its term length and segment length,
in bytes. --cluster names the cluster in the objects' keys: 64 hex digits.
";

/// Remote storage in a directory: one file per object.
#[derive(Debug, Clone)]
pub struct DirStore {
    root: PathBuf,
}

impl DirStore {
    /// The store in `root`, which exists.
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    fn path(&self, key: &ObjectKey) -> PathBuf {
        self.root.join(key.name().replace('/', "_"))
    }
}

impl ObjectStore for DirStore {
    fn put(&mut self, key: &ObjectKey, bytes: &[u8], _: u64) -> io::Result<Enforcement> {
        let path = self.path(key);
        let temporary = path.with_extension("partial");
        std::fs::write(&temporary, bytes)?;
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(&temporary, &path)?;
        Ok(Enforcement::Unsupported)
    }

    fn get(&mut self, key: &ObjectKey) -> io::Result<Vec<u8>> {
        std::fs::read(self.path(key))
    }
}

/// The options of one command.
#[derive(Debug, Default)]
struct Options {
    log: Option<PathBuf>,
    snapshots: Option<PathBuf>,
    geometry: Option<Geometry>,
    cluster: Option<Digest>,
    remote: Option<PathBuf>,
    retain_until_ns: u64,
}

fn digest(text: &str) -> Option<Digest> {
    if text.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (at, slot) in digest.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(at * 2..at * 2 + 2)?, 16).ok()?;
    }
    Some(digest)
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        retain_until_ns: u64::MAX,
        ..Options::default()
    };
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--log" => options.log = Some(PathBuf::from(value)),
            "--snapshots" => options.snapshots = Some(PathBuf::from(value)),
            "--remote" => options.remote = Some(PathBuf::from(value)),
            "--cluster" => {
                options.cluster = Some(digest(value).ok_or("--cluster takes 64 hex digits")?);
            }
            "--geometry" => {
                let (term, segment) = value
                    .split_once(',')
                    .ok_or("--geometry takes <term>,<segment>")?;
                let term = term.parse().map_err(|_| "bad term length")?;
                let segment = segment.parse().map_err(|_| "bad segment length")?;
                options.geometry =
                    Some(Geometry::new(term, segment).map_err(|error| error.to_string())?);
            }
            "--retain-until-ns" => {
                options.retain_until_ns = value.parse().map_err(|_| "bad --retain-until-ns")?;
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(options)
}

fn report(command: &str, report: &Report) -> String {
    let mut out = format!(
        "{command} base={}:{} top={}:{} entries={} objects={}\n",
        report.base.0, report.base.1, report.top.0, report.top.1, report.entries, report.objects
    );
    for item in report.not_included {
        let _ = writeln!(out, "not included: {item}");
    }
    out
}

/// Runs `karyos-backup <args>`: what to print, or the error.
///
/// # Errors
///
/// A usage error or the command's error, as text.
pub fn run(args: &[String]) -> Result<String, String> {
    let Some(command) = args.first() else {
        return Err(HELP.to_owned());
    };
    let options = parse(args.get(1..).unwrap_or(&[]))?;
    let cluster = options.cluster.ok_or("--cluster is required")?;
    let mut remote = DirStore::new(options.remote.as_deref().ok_or("--remote is required")?);
    match command.as_str() {
        "verify" => {
            let manifest =
                backup::verify(&mut remote, cluster).map_err(|error| error.to_string())?;
            Ok(format!(
                "verify base={}:{} top={}:{} objects={} ok\n",
                manifest.base.0,
                manifest.base.1,
                manifest.top.0,
                manifest.top.1,
                manifest.objects.len() + 1
            ))
        }
        "export" | "rebuild" => {
            let log = options.log.ok_or("--log is required")?;
            let snapshots = options.snapshots.ok_or("--snapshots is required")?;
            let geometry = options.geometry.ok_or("--geometry is required")?;
            if command == "rebuild" {
                let done = backup::rebuild(
                    &mut remote,
                    cluster,
                    &Target {
                        disk: &StdDisk,
                        log: &log,
                        snapshots: &snapshots,
                        geometry,
                    },
                )
                .map_err(|error| error.to_string())?;
                return Ok(report("rebuild", &done));
            }
            let store =
                SnapshotStore::open(StdDisk, &snapshots, geometry, SnapshotConfig::default())
                    .map_err(|error| error.to_string())?
                    .store;
            let mut node = RaftLog::open_with(StdDisk, &log, geometry, Some(&store))
                .map_err(|error| error.to_string())?
                .log;
            let done = backup::export(
                &store,
                &mut node,
                &mut remote,
                cluster,
                options.retain_until_ns,
            )
            .map_err(|error| error.to_string())?;
            Ok(report("export", &done))
        }
        _ => Err(format!("unknown command {command}\n{HELP}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cluster_id_is_64_hex_digits() {
        assert_eq!(digest(&"0a".repeat(32)), Some([10; 32]));
        assert_eq!(digest("0a"), None);
        assert_eq!(digest(&"zz".repeat(32)), None);
    }

    #[test]
    fn a_command_without_its_flags_is_refused() {
        assert!(run(&[]).is_err());
        assert!(
            run(&["export".to_owned()])
                .unwrap_err()
                .contains("--cluster")
        );
        let args: Vec<String> = ["verify", "--cluster", &"00".repeat(32), "--bogus", "x"]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect();
        assert!(run(&args).unwrap_err().contains("--bogus"));
    }
}
