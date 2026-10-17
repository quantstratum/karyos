// SPDX-License-Identifier: Apache-2.0

//! A disk in memory that crashes after a budget of work, for the
//! torn-write and restart tests: every creation, sync, truncation and
//! removal costs one unit and every written byte one, so a crash can fall
//! between any two operations or inside any write.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use super::disk::Disk;

/// One file: what the process sees, and what survives a crash.
#[derive(Debug, Clone, Default)]
struct File {
    data: Vec<u8>,
    synced: Vec<u8>,
    /// Its directory entry is durable.
    linked: bool,
}

/// The files, the budget and the crash.
#[derive(Debug, Default)]
struct Fs {
    files: BTreeMap<PathBuf, File>,
    budget: Option<u64>,
    crashed: bool,
    used: u64,
}

/// What survives a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Survives {
    /// Every operation applied before the crash, the torn write included:
    /// the disk persisted all of it.
    Everything,
    /// Only what a sync made durable: unsynced data is lost, and so is a
    /// file whose directory entry was not synced.
    Synced,
    /// Writeback in another order: every index byte written survives, but
    /// a data file keeps only what was synced. An entry can then outlive
    /// the data it covers.
    TornData,
}

/// A shared handle on the in-memory disk.
#[derive(Debug, Clone, Default)]
pub(super) struct FaultDisk(Rc<RefCell<Fs>>);

fn crashed() -> io::Error {
    io::Error::other("crashed")
}

impl FaultDisk {
    /// A disk that crashes once `budget` units are spent.
    pub(super) fn with_budget(budget: u64) -> Self {
        let disk = Self::default();
        disk.0.borrow_mut().budget = Some(budget);
        disk
    }

    /// Units spent so far.
    pub(super) fn used(&self) -> u64 {
        self.0.borrow().used
    }

    /// Whether the budget ran out.
    pub(super) fn has_crashed(&self) -> bool {
        self.0.borrow().crashed
    }

    /// The disk a restart finds after the crash, under `survives`.
    pub(super) fn after_crash(&self, survives: Survives) -> Self {
        let fs = self.0.borrow();
        let files = fs
            .files
            .iter()
            .filter(|(_, file)| survives != Survives::Synced || file.linked)
            .map(|(path, file)| {
                let data_file = path.extension().is_some_and(|extension| extension == "seg");
                let data = match survives {
                    Survives::Everything => file.data.clone(),
                    Survives::Synced => file.synced.clone(),
                    Survives::TornData if data_file => file.synced.clone(),
                    Survives::TornData => file.data.clone(),
                };
                let file = File {
                    synced: data.clone(),
                    data,
                    linked: true,
                };
                (path.clone(), file)
            })
            .collect();
        Self(Rc::new(RefCell::new(Fs {
            files,
            ..Fs::default()
        })))
    }

    /// Spends `cost` units: `Ok(cost)` when they fit, else the units left
    /// (the crash happens there).
    fn spend(fs: &mut Fs, cost: u64) -> Result<u64, u64> {
        let Some(budget) = fs.budget else {
            fs.used = fs.used.saturating_add(cost);
            return Ok(cost);
        };
        let left = budget.saturating_sub(fs.used);
        if cost <= left {
            fs.used = fs.used.saturating_add(cost);
            Ok(cost)
        } else {
            fs.used = budget;
            fs.crashed = true;
            Err(left)
        }
    }

    /// Spends one unit for an operation that applies whole or not at all.
    fn step(&self) -> io::Result<std::cell::RefMut<'_, Fs>> {
        let mut fs = self.0.borrow_mut();
        if fs.crashed {
            return Err(crashed());
        }
        if Self::spend(&mut fs, 1).is_err() {
            return Err(crashed());
        }
        Ok(fs)
    }

    fn file<'a>(fs: &'a mut Fs, path: &Path) -> io::Result<&'a mut File> {
        fs.files
            .get_mut(path)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}

impl Disk for FaultDisk {
    type File = PathBuf;

    fn create(&mut self, path: &Path) -> io::Result<PathBuf> {
        let mut fs = self.step()?;
        fs.files.insert(path.to_path_buf(), File::default());
        Ok(path.to_path_buf())
    }

    fn open(&mut self, path: &Path) -> io::Result<PathBuf> {
        let mut fs = self.0.borrow_mut();
        if fs.crashed {
            return Err(crashed());
        }
        Self::file(&mut fs, path)?;
        Ok(path.to_path_buf())
    }

    fn write_at(&mut self, file: &PathBuf, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let mut fs = self.0.borrow_mut();
        if fs.crashed {
            return Err(crashed());
        }
        let cost = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        let (applied, result) = match Self::spend(&mut fs, cost) {
            Ok(_) => (bytes.len(), Ok(())),
            Err(left) => (
                usize::try_from(left).map_err(io::Error::other)?,
                Err(crashed()),
            ),
        };
        let target = Self::file(&mut fs, file)?;
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(applied)
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        if target.data.len() < end {
            target.data.resize(end, 0);
        }
        if let (Some(slot), Some(source)) = (target.data.get_mut(start..end), bytes.get(..applied))
        {
            slot.copy_from_slice(source);
        }
        result
    }

    fn read_at(&mut self, file: &PathBuf, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut fs = self.0.borrow_mut();
        if fs.crashed {
            return Err(crashed());
        }
        let source = Self::file(&mut fs, file)?;
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        let bytes = source
            .data
            .get(start..end)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        buf.copy_from_slice(bytes);
        Ok(())
    }

    fn len(&mut self, file: &PathBuf) -> io::Result<u64> {
        let mut fs = self.0.borrow_mut();
        if fs.crashed {
            return Err(crashed());
        }
        u64::try_from(Self::file(&mut fs, file)?.data.len()).map_err(io::Error::other)
    }

    fn truncate(&mut self, file: &PathBuf, len: u64) -> io::Result<()> {
        let mut fs = self.step()?;
        let len = usize::try_from(len).map_err(io::Error::other)?;
        Self::file(&mut fs, file)?.data.truncate(len);
        Ok(())
    }

    fn sync(&mut self, file: &PathBuf) -> io::Result<()> {
        let mut fs = self.step()?;
        let target = Self::file(&mut fs, file)?;
        target.synced = target.data.clone();
        Ok(())
    }

    fn sync_dir(&mut self, dir: &Path) -> io::Result<()> {
        let mut fs = self.step()?;
        for (path, file) in &mut fs.files {
            if path.parent() == Some(dir) {
                file.linked = true;
            }
        }
        Ok(())
    }

    fn list(&mut self, dir: &Path) -> io::Result<Vec<String>> {
        let fs = self.0.borrow();
        if fs.crashed {
            return Err(crashed());
        }
        Ok(fs
            .files
            .keys()
            .filter(|path| path.parent() == Some(dir))
            .filter_map(|path| path.file_name()?.to_str().map(str::to_owned))
            .collect())
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        let mut fs = self.step()?;
        fs.files
            .remove(path)
            .map(drop)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}
