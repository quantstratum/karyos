// SPDX-License-Identifier: Apache-2.0

//! `karyos-backup`: a Cluster node's backup to remote storage, its check,
//! and a rebuild from it (`karyos_cluster::backup`; karyos#717). See
//! [`HELP`].
//!
//! Remote storage here is a directory ([`DirStore`]): one file per object,
//! named by its key, written whole under a name of its own then renamed
//! into place, the directory synced after. It is what the documented
//! procedure runs against and what an operator copies to or from object
//! storage with their own tooling, setting the retention and object lock
//! SPEC §8.4 asks for there: this store enforces neither, and says so in
//! every export's report (`--require-retention` refuses it). The S3 client
//! (`karyos-tiering`) implements the same `ObjectStore` for an Archive's
//! tiering. Every command runs on the control path and holds an exclusive
//! lock on each directory it uses, so two runs never share one. An export
//! copies the stopped node's directories to a working copy first and opens
//! that, so the node's own are never changed.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::Digest;
use karyos_archive::integrity::copies::Enforcement;
use karyos_archive::integrity::tiering::{ObjectKey, ObjectStore};
use karyos_archive::segment::Geometry;
use karyos_cluster::RaftLog;
use karyos_cluster::backup::{self, Report, Retention, Target};
use karyos_cluster::snapshot::{SnapshotConfig, SnapshotStore};

/// The command's help.
pub const HELP: &str = "\
karyos-backup: a Cluster node's backup to remote storage, and a rebuild from it

usage:
  karyos-backup export  --log <dir> --snapshots <dir> --geometry <term>,<segment> --cluster <hex64> --remote <dir> [--retain-until-ns <ns>] [--require-retention]
  karyos-backup verify  --cluster <hex64> --remote <dir>
  karyos-backup rebuild --log <dir> --snapshots <dir> --geometry <term>,<segment> --cluster <hex64> --remote <dir>

export   copies a stopped node's directories to a working copy, then copies
         its latest snapshot and its committed log after it to the remote,
         every object read back and checked, the manifest last; the node's
         own directories are only read
verify   checks every object of an export against its manifest, changing
         nothing
rebuild  rebuilds a node from an export into the given directories, which
         exist and are empty, every object checked before anything is
         written; a rebuild that fails after that leaves them partly
         written, to be emptied before another

Each command locks every directory it uses: a second run on one of them is
refused while the first holds it.

--geometry is the node's log geometry: its term length and segment length,
in bytes. --cluster names the cluster in the objects' keys: 64 hex digits.
The remote directory enforces no retention: an export reports
retention=Unsupported, and --require-retention refuses it. Retention and
object lock are set where the export is copied to.
";

/// Remote storage in a directory: one file per object.
#[derive(Debug, Clone)]
pub struct DirStore {
    root: PathBuf,
}

/// Each put's temporary name is its own.
static PUTS: AtomicU64 = AtomicU64::new(0);

impl DirStore {
    /// The store in `root`, which exists.
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    fn name(key: &ObjectKey) -> String {
        key.name().replace('/', "_")
    }
}

impl ObjectStore for DirStore {
    fn put(&mut self, key: &ObjectKey, bytes: &[u8], _: u64) -> io::Result<Enforcement> {
        let name = Self::name(key);
        let temporary = self.root.join(format!(
            ".{name}.{}.{}.partial",
            std::process::id(),
            PUTS.fetch_add(1, Ordering::Relaxed)
        ));
        let written = (|| {
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            io::Write::write_all(&mut file, bytes)?;
            file.sync_all()
        })();
        if let Err(error) = written {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        fs::rename(&temporary, self.root.join(name))?;
        File::open(&self.root)?.sync_all()?;
        Ok(Enforcement::Unsupported)
    }

    fn get(&mut self, key: &ObjectKey) -> io::Result<Vec<u8>> {
        fs::read(self.root.join(Self::name(key)))
    }
}

/// An exclusive lock on directory `dir`, held while the file lives.
///
/// # Errors
///
/// When `dir` cannot be opened, or another run holds it.
fn lock(dir: &Path) -> Result<File, String> {
    let file = File::open(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    file.try_lock()
        .map_err(|_| format!("{} is in use by another run", dir.display()))?;
    Ok(file)
}

/// A working copy of a node's directories, removed when dropped.
struct WorkCopy(PathBuf);

impl WorkCopy {
    fn new() -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path =
            std::env::temp_dir().join(format!("karyos-backup-work-{}-{nanos}", std::process::id()));
        fs::create_dir(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for WorkCopy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Copies directory `from` into `to`, which does not exist, recursively.
fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            let _ = fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
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
    require_retention: bool,
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
        if flag == "--require-retention" {
            options.require_retention = true;
            continue;
        }
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
    if command == "export" {
        let _ = writeln!(out, "retention={:?}", report.retention);
    }
    if let (Some(identity), Some(nonce)) = (report.identity, report.nonce) {
        let source = identity.isolated_from.map_or([0; 32], |source| source.0);
        let _ = writeln!(
            out,
            "identity={} isolated_from={} nonce={}",
            hex(&identity.identity.0),
            hex(&source),
            hex(&nonce)
        );
    }
    for item in report.not_included {
        let _ = writeln!(out, "not included: {item}");
    }
    out
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// A rebuild identity's nonce: 32 bytes from the operating system's
/// random source (ADR-0123 decision 2), fresh for every rebuild.
fn nonce() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut nonce = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut nonce))
        .map_err(|error| format!("reading the rebuild nonce from /dev/urandom: {error}"))?;
    Ok(nonce)
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
    let root = options.remote.as_deref().ok_or("--remote is required")?;
    let _remote_lock = lock(root)?;
    let mut remote = DirStore::new(root);
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
            let _locks = (lock(&log)?, lock(&snapshots)?);
            if command == "rebuild" {
                let done = backup::rebuild(
                    &mut remote,
                    cluster,
                    &Target {
                        disk: &StdDisk,
                        log: &log,
                        snapshots: &snapshots,
                        geometry,
                        nonce: nonce()?,
                    },
                )
                .map_err(|error| error.to_string())?;
                return Ok(report("rebuild", &done));
            }
            // The node's directories are only read: their recovery runs on
            // the working copy.
            let work = WorkCopy::new()?;
            let (work_log, work_snapshots) = (work.0.join("log"), work.0.join("snapshots"));
            copy_dir(&log, &work_log)
                .map_err(|error| format!("copying {}: {error}", log.display()))?;
            copy_dir(&snapshots, &work_snapshots)
                .map_err(|error| format!("copying {}: {error}", snapshots.display()))?;
            let store = SnapshotStore::open(
                StdDisk,
                &work_snapshots,
                geometry,
                SnapshotConfig::default(),
            )
            .map_err(|error| error.to_string())?
            .store;
            let mut node = RaftLog::open_with(StdDisk, &work_log, geometry, Some(&store))
                .map_err(|error| error.to_string())?
                .log;
            let mut retention = Retention::until(options.retain_until_ns);
            if options.require_retention {
                retention = retention.required();
            }
            let done = backup::export(&store, &mut node, &mut remote, cluster, retention)
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

    #[test]
    fn a_locked_directory_is_refused_until_released() {
        let dir = std::env::temp_dir().join(format!("karyos-backup-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let held = lock(&dir).unwrap();
        assert!(lock(&dir).unwrap_err().contains("in use"));
        drop(held);
        drop(lock(&dir).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_put_leaves_only_its_object_and_replaces_none_of_another() {
        let dir = std::env::temp_dir().join(format!("karyos-backup-put-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let mut store = DirStore::new(&dir);
        let key = |start| ObjectKey {
            archive: [1; 32],
            recording: 1,
            start,
            end: start + 1,
            kind: karyos_archive::integrity::tiering::ObjectKind::Range,
        };
        assert_eq!(
            store.put(&key(1), b"one", 0).unwrap(),
            Enforcement::Unsupported
        );
        assert_eq!(
            store.put(&key(2), b"two", 0).unwrap(),
            Enforcement::Unsupported
        );
        assert_eq!(store.get(&key(1)).unwrap(), b"one");
        assert_eq!(store.get(&key(2)).unwrap(), b"two");
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            2,
            "a temporary file was left"
        );
        assert_eq!(
            store.get(&key(3)).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
