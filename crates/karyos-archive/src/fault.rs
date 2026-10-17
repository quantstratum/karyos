// SPDX-License-Identifier: Apache-2.0

//! A disk in memory that crashes after a budget of work, for the
//! torn-write and restart tests: every creation, sync, truncation, rename
//! and removal costs one unit and every written byte one, so a crash can
//! fall between any two operations or inside any write.
//!
//! Files are inodes; a directory maps names to inodes twice, as the
//! process sees it and as it would survive a crash (updated by
//! [`Disk::sync_dir`]), so a creation, a removal or a rename is durable
//! only once its directory is synced.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::disk::Disk;

/// One inode: what the process sees, and what survives a crash.
#[derive(Debug, Clone, Default)]
struct Inode {
    data: Vec<u8>,
    synced: Vec<u8>,
}

/// The inodes, both views of the names, the budget and the crash.
#[derive(Debug, Default)]
struct Fs {
    inodes: Vec<Inode>,
    names: BTreeMap<PathBuf, usize>,
    durable_names: BTreeMap<PathBuf, usize>,
    budget: Option<u64>,
    crashed: bool,
    used: u64,
}

/// What survives a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Survives {
    /// Every operation applied before the crash, the torn write included:
    /// the disk persisted all of it.
    Everything,
    /// Only what a sync made durable, as Linux promises: unsynced data is
    /// lost, and so is a name whose directory was not synced since.
    Synced,
    /// Writeback in another order: every name and every index byte
    /// written survive, but a segment's data file keeps only what was
    /// synced. An entry can then outlive the data it covers.
    TornData,
}

/// A shared handle on the in-memory disk.
#[derive(Debug, Clone, Default)]
pub(crate) struct FaultDisk(Rc<RefCell<Fs>>);

fn crashed() -> io::Error {
    io::Error::other("crashed")
}

fn not_found() -> io::Error {
    io::Error::from(io::ErrorKind::NotFound)
}

impl FaultDisk {
    /// A disk that crashes once `budget` units are spent.
    pub(crate) fn with_budget(budget: u64) -> Self {
        let disk = Self::default();
        disk.0.borrow_mut().budget = Some(budget);
        disk
    }

    /// Units spent so far.
    pub(crate) fn used(&self) -> u64 {
        self.0.borrow().used
    }

    /// Whether the budget ran out.
    pub(crate) fn has_crashed(&self) -> bool {
        self.0.borrow().crashed
    }

    /// The disk a restart finds after the crash, under `survives`.
    pub(crate) fn after_crash(&self, survives: Survives) -> Self {
        let fs = self.0.borrow();
        let names = match survives {
            Survives::Everything | Survives::TornData => &fs.names,
            Survives::Synced => &fs.durable_names,
        };
        let mut restarted = Fs::default();
        for (path, &inode) in names {
            let Some(old) = fs.inodes.get(inode) else {
                continue;
            };
            let data_file = path.extension().is_some_and(|extension| extension == "seg");
            let data = match survives {
                Survives::Everything => old.data.clone(),
                Survives::Synced => old.synced.clone(),
                Survives::TornData if data_file => old.synced.clone(),
                Survives::TornData => old.data.clone(),
            };
            restarted.inodes.push(Inode {
                synced: data.clone(),
                data,
            });
            let index = restarted.inodes.len() - 1;
            restarted.names.insert(path.clone(), index);
            restarted.durable_names.insert(path.clone(), index);
        }
        Self(Rc::new(RefCell::new(restarted)))
    }

    /// Spends `cost` units: `Ok(())` when they fit, else the units left
    /// (the crash happens there).
    fn spend(fs: &mut Fs, cost: u64) -> Result<(), u64> {
        let Some(budget) = fs.budget else {
            fs.used = fs.used.saturating_add(cost);
            return Ok(());
        };
        let left = budget.saturating_sub(fs.used);
        if cost <= left {
            fs.used = fs.used.saturating_add(cost);
            Ok(())
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

    /// A live view, for an operation that costs nothing.
    fn view(&self) -> io::Result<std::cell::RefMut<'_, Fs>> {
        let fs = self.0.borrow_mut();
        if fs.crashed {
            return Err(crashed());
        }
        Ok(fs)
    }

    fn inode<'a>(fs: &'a mut Fs, path: &Path) -> io::Result<&'a mut Inode> {
        let index = *fs.names.get(path).ok_or_else(not_found)?;
        fs.inodes.get_mut(index).ok_or_else(not_found)
    }
}

impl Disk for FaultDisk {
    type File = PathBuf;

    fn create(&mut self, path: &Path) -> io::Result<PathBuf> {
        let mut fs = self.step()?;
        fs.inodes.push(Inode::default());
        let index = fs.inodes.len() - 1;
        fs.names.insert(path.to_path_buf(), index);
        Ok(path.to_path_buf())
    }

    fn open(&mut self, path: &Path) -> io::Result<PathBuf> {
        let mut fs = self.view()?;
        Self::inode(&mut fs, path)?;
        Ok(path.to_path_buf())
    }

    fn open_read(&mut self, path: &Path) -> io::Result<PathBuf> {
        self.open(path)
    }

    fn write_at(&mut self, file: &PathBuf, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let mut fs = self.view()?;
        let cost = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        let (applied, result) = match Self::spend(&mut fs, cost) {
            Ok(()) => (bytes.len(), Ok(())),
            Err(left) => (
                usize::try_from(left).map_err(io::Error::other)?,
                Err(crashed()),
            ),
        };
        let target = Self::inode(&mut fs, file)?;
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
        let mut fs = self.view()?;
        let source = Self::inode(&mut fs, file)?;
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
        let mut fs = self.view()?;
        u64::try_from(Self::inode(&mut fs, file)?.data.len()).map_err(io::Error::other)
    }

    fn set_len(&mut self, file: &PathBuf, len: u64) -> io::Result<()> {
        let mut fs = self.step()?;
        let len = usize::try_from(len).map_err(io::Error::other)?;
        Self::inode(&mut fs, file)?.data.resize(len, 0);
        Ok(())
    }

    fn sync(&mut self, file: &PathBuf) -> io::Result<()> {
        let mut fs = self.step()?;
        let target = Self::inode(&mut fs, file)?;
        target.synced = target.data.clone();
        Ok(())
    }

    fn sync_dir(&mut self, dir: &Path) -> io::Result<()> {
        let mut fs = self.step()?;
        let Fs {
            names,
            durable_names,
            ..
        } = &mut *fs;
        durable_names.retain(|path, _| path.parent() != Some(dir));
        for (path, &inode) in names.iter() {
            if path.parent() == Some(dir) {
                durable_names.insert(path.clone(), inode);
            }
        }
        Ok(())
    }

    fn list(&mut self, dir: &Path) -> io::Result<Vec<String>> {
        let fs = self.view()?;
        Ok(fs
            .names
            .keys()
            .filter(|path| path.parent() == Some(dir))
            .filter_map(|path| path.file_name()?.to_str().map(str::to_owned))
            .collect())
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        let mut fs = self.step()?;
        fs.names.remove(path).map(drop).ok_or_else(not_found)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        let mut fs = self.step()?;
        let inode = fs.names.remove(from).ok_or_else(not_found)?;
        fs.names.insert(to.to_path_buf(), inode);
        Ok(())
    }
}
