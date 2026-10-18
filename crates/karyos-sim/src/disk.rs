// SPDX-License-Identifier: Apache-2.0

//! A disk for the simulator (`quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md`, C2): `karyos-archive`'s
//! [`Disk`], with crashes, writes not yet flushed, kept in any order, torn
//! writes and failed flushes, all decided by a seed.
//!
//! - **What is durable.** Each file holds its durable bytes and its pending
//!   data operations, in order: writes and `set_len`. [`Disk::sync`] makes
//!   them durable. Each directory holds its durable names and its pending
//!   name operations: creations, renames and removals. [`Disk::sync_dir`]
//!   makes those durable. Reads see everything, durable or not, as a page
//!   cache does.
//! - **A crash.** After [`SimDisk::with_budget`] operations, the next one
//!   fails, and so does every later one. [`SimDisk::after_crash`] gives
//!   the disk a restart finds, by [`Survives`]: only what was durable,
//!   everything, any seeded subset of the pending operations, or all of
//!   them with seeded writes torn to a sector prefix. A subset keeps a
//!   later write without an earlier one: writeback in another order. Data
//!   and names are chosen apart, as a file system orders them, and a name
//!   operation whose file was not kept, or whose name is gone, does
//!   nothing.
//! - **A failed flush.** [`SimDisk::with_failed_syncs`] makes chosen
//!   `sync` and `sync_dir` calls, counted from 1, fail with nothing made
//!   durable. Their pending operations stay pending.
//! - **Determinism.** One seed gives one outcome: the state is in ordered
//!   maps, every count is checked integer arithmetic, and every fault
//!   decision is appended to a [`Decision`] trace a test can print or
//!   compare.
//!
//! It is single-threaded, as the simulator is: clones share one disk.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use karyos_archive::disk::Disk;

use crate::rng::Rng;

#[cfg(test)]
mod tests;

/// The unit a torn write keeps a prefix of.
pub const SECTOR: u64 = 512;

/// What a restart finds of the operations pending at a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Survives {
    /// Only what a sync made durable.
    Synced,
    /// Every operation, as if the cache reached the disk.
    Everything,
    /// Each pending operation kept or lost by the seed.
    Subset {
        /// The seed.
        seed: u64,
    },
    /// Every pending operation kept, each write torn by the seed to a
    /// prefix of whole sectors, or kept whole.
    Torn {
        /// The seed.
        seed: u64,
    },
}

/// One fault decision, in the order made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Operation `op` (counted from 1), a `call`, found the budget spent.
    Crash {
        /// The operation's number.
        op: u64,
        /// The call.
        call: &'static str,
    },
    /// Flush number `sync` failed as planned.
    FailedSync {
        /// The flush's number, `sync` and `sync_dir` counted together.
        sync: u64,
    },
    /// A file's pending data operation, at a restart.
    Data {
        /// The file.
        inode: u64,
        /// Its index among the file's pending operations.
        index: usize,
        /// What the restart found of it.
        fate: Fate,
    },
    /// A directory's pending name operation, at a restart.
    Name {
        /// The directory.
        dir: PathBuf,
        /// Its index among the directory's pending operations.
        index: usize,
        /// Whether the restart found it.
        kept: bool,
    },
}

/// What a restart found of one pending data operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Applied whole.
    Kept,
    /// Lost.
    Dropped,
    /// A write applied up to `kept` of its bytes.
    Torn {
        /// The bytes kept, whole sectors.
        kept: u64,
    },
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crash { op, call } => write!(f, "crash at operation {op} ({call})"),
            Self::FailedSync { sync } => write!(f, "flush {sync} failed"),
            Self::Data { inode, index, fate } => {
                write!(f, "file {inode}, pending {index}: {fate:?}")
            }
            Self::Name { dir, index, kept } => write!(
                f,
                "directory {}, pending {index}: {}",
                dir.display(),
                if *kept { "kept" } else { "dropped" }
            ),
        }
    }
}

/// A file's pending data operation.
#[derive(Debug, Clone)]
enum DataOp {
    Write { offset: u64, bytes: Vec<u8> },
    SetLen(u64),
}

/// A directory's pending name operation, by file name.
#[derive(Debug, Clone)]
enum NameOp {
    Link { name: String, inode: u64 },
    Rename { from: String, to: String },
    Remove { name: String },
}

#[derive(Debug, Clone, Default)]
struct File {
    durable: Vec<u8>,
    pending: Vec<DataOp>,
}

#[derive(Debug, Clone, Default)]
struct Dir {
    durable: BTreeMap<String, u64>,
    pending: Vec<NameOp>,
}

#[derive(Debug, Default)]
struct State {
    files: BTreeMap<u64, File>,
    dirs: BTreeMap<PathBuf, Dir>,
    next_inode: u64,
    /// Operations so far.
    ops: u64,
    /// Operations allowed before the crash.
    budget: Option<u64>,
    crashed: bool,
    /// Flushes so far.
    syncs: u64,
    /// The flushes that fail.
    failing: BTreeSet<u64>,
    trace: Vec<Decision>,
}

/// An open file: its inode, and whether it was opened for writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimFile {
    inode: u64,
    writable: bool,
}

/// The simulator's disk. Clones share it.
#[derive(Debug, Clone, Default)]
pub struct SimDisk(Rc<RefCell<State>>);

fn error(kind: io::ErrorKind, what: &str) -> io::Error {
    io::Error::new(kind, what.to_owned())
}

fn crashed() -> io::Error {
    error(io::ErrorKind::Other, "the simulated disk crashed")
}

/// `bytes` with `op` applied.
fn apply(bytes: &mut Vec<u8>, op: &DataOp) -> io::Result<()> {
    let too_large = || error(io::ErrorKind::InvalidInput, "a file past usize");
    match op {
        DataOp::Write {
            offset,
            bytes: data,
        } => {
            let start = usize::try_from(*offset).map_err(|_| too_large())?;
            let end = start.checked_add(data.len()).ok_or_else(too_large)?;
            if bytes.len() < end {
                bytes.resize(end, 0);
            }
            if let Some(target) = bytes.get_mut(start..end) {
                target.copy_from_slice(data);
            }
        }
        DataOp::SetLen(len) => {
            bytes.resize(usize::try_from(*len).map_err(|_| too_large())?, 0);
        }
    }
    Ok(())
}

/// `names` with `op` applied; one whose name is gone does nothing.
fn apply_name(names: &mut BTreeMap<String, u64>, op: &NameOp) {
    match op {
        NameOp::Link { name, inode } => {
            let _ = names.insert(name.clone(), *inode);
        }
        NameOp::Rename { from, to } => {
            if let Some(inode) = names.remove(from) {
                let _ = names.insert(to.clone(), inode);
            }
        }
        NameOp::Remove { name } => {
            let _ = names.remove(name);
        }
    }
}

/// A path's directory and file name.
fn split(path: &Path) -> io::Result<(PathBuf, String)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| error(io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    Ok((dir.to_path_buf(), name.to_owned()))
}

impl File {
    fn live(&self) -> io::Result<Vec<u8>> {
        let mut bytes = self.durable.clone();
        for op in &self.pending {
            apply(&mut bytes, op)?;
        }
        Ok(bytes)
    }
}

impl Dir {
    fn live(&self) -> BTreeMap<String, u64> {
        let mut names = self.durable.clone();
        for op in &self.pending {
            apply_name(&mut names, op);
        }
        names
    }
}

impl SimDisk {
    /// A disk that never crashes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A disk whose operation `budget + 1` crashes it.
    #[must_use]
    pub fn with_budget(budget: u64) -> Self {
        let disk = Self::default();
        disk.0.borrow_mut().budget = Some(budget);
        disk
    }

    /// Makes the flushes numbered in `syncs` (from 1, `sync` and
    /// `sync_dir` together) fail, with nothing made durable.
    #[must_use]
    pub fn with_failed_syncs(self, syncs: impl IntoIterator<Item = u64>) -> Self {
        self.0.borrow_mut().failing.extend(syncs);
        self
    }

    /// The operations made so far.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.0.borrow().ops
    }

    /// Whether the budget was spent.
    #[must_use]
    pub fn has_crashed(&self) -> bool {
        self.0.borrow().crashed
    }

    /// The fault decisions so far.
    #[must_use]
    pub fn trace(&self) -> Vec<Decision> {
        self.0.borrow().trace.clone()
    }

    /// The disk a restart finds after a crash now, by `survives`: a new,
    /// working disk, whose trace continues this one's.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] for a file grown past `usize`.
    pub fn after_crash(&self, survives: Survives) -> io::Result<Self> {
        let state = self.0.borrow();
        let mut rng = Rng::new(match survives {
            Survives::Subset { seed } | Survives::Torn { seed } => seed,
            Survives::Synced | Survives::Everything => 0,
        });
        let mut trace = state.trace.clone();
        let mut files = BTreeMap::new();
        for (inode, file) in &state.files {
            let mut bytes = file.durable.clone();
            for (index, op) in file.pending.iter().enumerate() {
                let fate = match survives {
                    Survives::Synced => Fate::Dropped,
                    Survives::Everything => Fate::Kept,
                    Survives::Subset { .. } => {
                        if rng.chance(1, 2) {
                            Fate::Kept
                        } else {
                            Fate::Dropped
                        }
                    }
                    Survives::Torn { .. } => match op {
                        DataOp::Write { bytes: data, .. } if rng.chance(1, 2) => {
                            let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
                            let sectors = length / SECTOR;
                            let kept = rng
                                .below(sectors.checked_add(1).unwrap_or(sectors))
                                .checked_mul(SECTOR)
                                .unwrap_or(0);
                            Fate::Torn { kept }
                        }
                        _ => Fate::Kept,
                    },
                };
                match (fate, op) {
                    (Fate::Kept, op) => apply(&mut bytes, op)?,
                    (
                        Fate::Torn { kept },
                        DataOp::Write {
                            offset,
                            bytes: data,
                        },
                    ) => {
                        let kept = usize::try_from(kept).unwrap_or(usize::MAX).min(data.len());
                        let prefix = DataOp::Write {
                            offset: *offset,
                            bytes: data.get(..kept).unwrap_or_default().to_vec(),
                        };
                        apply(&mut bytes, &prefix)?;
                    }
                    _ => {}
                }
                if !matches!(survives, Survives::Synced | Survives::Everything) {
                    trace.push(Decision::Data {
                        inode: *inode,
                        index,
                        fate,
                    });
                }
            }
            let _ = files.insert(
                *inode,
                File {
                    durable: bytes,
                    pending: Vec::new(),
                },
            );
        }
        let mut dirs = BTreeMap::new();
        for (path, dir) in &state.dirs {
            let mut names = dir.durable.clone();
            for (index, op) in dir.pending.iter().enumerate() {
                let kept = match survives {
                    Survives::Synced => false,
                    Survives::Everything | Survives::Torn { .. } => true,
                    Survives::Subset { .. } => rng.chance(1, 2),
                };
                if kept {
                    apply_name(&mut names, op);
                }
                if matches!(survives, Survives::Subset { .. }) {
                    trace.push(Decision::Name {
                        dir: path.clone(),
                        index,
                        kept,
                    });
                }
            }
            let _ = dirs.insert(
                path.clone(),
                Dir {
                    durable: names,
                    pending: Vec::new(),
                },
            );
        }
        Ok(Self(Rc::new(RefCell::new(State {
            files,
            dirs,
            next_inode: state.next_inode,
            trace,
            ..State::default()
        }))))
    }

    /// Counts one operation; fails it once the budget is spent.
    fn step(&self, call: &'static str) -> io::Result<std::cell::RefMut<'_, State>> {
        let mut state = self.0.borrow_mut();
        if state.crashed {
            return Err(crashed());
        }
        let op = state.ops.checked_add(1).ok_or_else(crashed)?;
        state.ops = op;
        if state.budget.is_some_and(|budget| op > budget) {
            state.crashed = true;
            state.trace.push(Decision::Crash { op, call });
            return Err(crashed());
        }
        Ok(state)
    }

    /// Counts a flush; fails it if planned.
    fn flush(state: &mut State) -> io::Result<()> {
        let sync = state.syncs.checked_add(1).ok_or_else(crashed)?;
        state.syncs = sync;
        if state.failing.contains(&sync) {
            state.trace.push(Decision::FailedSync { sync });
            return Err(error(io::ErrorKind::Other, "a simulated flush failure"));
        }
        Ok(())
    }

    fn resolve(state: &State, path: &Path) -> io::Result<u64> {
        let (dir, name) = split(path)?;
        state
            .dirs
            .get(&dir)
            .and_then(|dir| dir.live().get(&name).copied())
            .ok_or_else(|| error(io::ErrorKind::NotFound, "no such file"))
    }

    fn file<'a>(state: &'a mut State, file: &SimFile) -> io::Result<&'a mut File> {
        state
            .files
            .get_mut(&file.inode)
            .ok_or_else(|| error(io::ErrorKind::NotFound, "no such file"))
    }
}

impl Disk for SimDisk {
    type File = SimFile;

    fn create(&mut self, path: &Path) -> io::Result<SimFile> {
        let mut state = self.step("create")?;
        if let Ok(inode) = Self::resolve(&state, path) {
            Self::file(
                &mut state,
                &SimFile {
                    inode,
                    writable: true,
                },
            )?
            .pending
            .push(DataOp::SetLen(0));
            return Ok(SimFile {
                inode,
                writable: true,
            });
        }
        let (dir, name) = split(path)?;
        let inode = state.next_inode;
        state.next_inode = inode.checked_add(1).ok_or_else(crashed)?;
        let _ = state.files.insert(inode, File::default());
        state
            .dirs
            .entry(dir)
            .or_default()
            .pending
            .push(NameOp::Link { name, inode });
        Ok(SimFile {
            inode,
            writable: true,
        })
    }

    fn open(&mut self, path: &Path) -> io::Result<SimFile> {
        let state = self.step("open")?;
        Ok(SimFile {
            inode: Self::resolve(&state, path)?,
            writable: true,
        })
    }

    fn open_read(&mut self, path: &Path) -> io::Result<SimFile> {
        let state = self.step("open_read")?;
        Ok(SimFile {
            inode: Self::resolve(&state, path)?,
            writable: false,
        })
    }

    fn write_at(&mut self, file: &SimFile, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.step("write_at")?;
        if !file.writable {
            return Err(error(io::ErrorKind::PermissionDenied, "opened for reading"));
        }
        Self::file(&mut state, file)?.pending.push(DataOp::Write {
            offset,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }

    fn read_at(&mut self, file: &SimFile, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut state = self.step("read_at")?;
        let live = Self::file(&mut state, file)?.live()?;
        let eof = || error(io::ErrorKind::UnexpectedEof, "read past the end");
        let start = usize::try_from(offset).map_err(|_| eof())?;
        let end = start.checked_add(buf.len()).ok_or_else(eof)?;
        buf.copy_from_slice(live.get(start..end).ok_or_else(eof)?);
        Ok(())
    }

    fn len(&mut self, file: &SimFile) -> io::Result<u64> {
        let mut state = self.step("len")?;
        let live = Self::file(&mut state, file)?.live()?;
        u64::try_from(live.len()).map_err(|_| crashed())
    }

    fn set_len(&mut self, file: &SimFile, len: u64) -> io::Result<()> {
        let mut state = self.step("set_len")?;
        if !file.writable {
            return Err(error(io::ErrorKind::PermissionDenied, "opened for reading"));
        }
        Self::file(&mut state, file)?
            .pending
            .push(DataOp::SetLen(len));
        Ok(())
    }

    fn sync(&mut self, file: &SimFile) -> io::Result<()> {
        let mut state = self.step("sync")?;
        Self::flush(&mut state)?;
        let entry = Self::file(&mut state, file)?;
        entry.durable = entry.live()?;
        entry.pending.clear();
        Ok(())
    }

    fn sync_dir(&mut self, dir: &Path) -> io::Result<()> {
        let mut state = self.step("sync_dir")?;
        Self::flush(&mut state)?;
        if let Some(entry) = state.dirs.get_mut(dir) {
            entry.durable = entry.live();
            entry.pending.clear();
        }
        Ok(())
    }

    fn list(&mut self, dir: &Path) -> io::Result<Vec<String>> {
        let state = self.step("list")?;
        Ok(state
            .dirs
            .get(dir)
            .map(|dir| dir.live().into_keys().collect())
            .unwrap_or_default())
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        let mut state = self.step("remove")?;
        let _ = Self::resolve(&state, path)?;
        let (dir, name) = split(path)?;
        state
            .dirs
            .entry(dir)
            .or_default()
            .pending
            .push(NameOp::Remove { name });
        Ok(())
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        let mut state = self.step("rename")?;
        let _ = Self::resolve(&state, from)?;
        let ((dir, from), (to_dir, to)) = (split(from)?, split(to)?);
        if dir != to_dir {
            return Err(error(
                io::ErrorKind::Unsupported,
                "a rename across directories",
            ));
        }
        state
            .dirs
            .entry(dir)
            .or_default()
            .pending
            .push(NameOp::Rename { from, to });
        Ok(())
    }
}
