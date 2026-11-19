// SPDX-License-Identifier: Apache-2.0

//! An append-only file of fixed-length entries, for the integrity
//! evidence that lives beside the journal: the key registry's entries and
//! the signed heads (karyos#663), the anchors (karyos#664). Each entry's
//! digest is chained in the integrity journal, so the file holds the
//! bytes and the journal holds the proof.
//!
//! An append writes one entry at the end and syncs it. Opening keeps the
//! whole entries and cuts a partial tail, which is what a crash during an
//! append leaves; deciding whether a whole entry is sound is the reader's
//! job, through the chain.

use std::path::Path;

use super::journal::IntegrityError;
use crate::disk::Disk;

/// An append-only file of `N`-byte entries.
#[derive(Debug)]
pub struct Ledger<D: Disk, const N: usize> {
    disk: D,
    file: D::File,
    /// The archive directory the ledger is in.
    dir: std::path::PathBuf,
    entries: Vec<[u8; N]>,
    poisoned: bool,
}

impl<D: Disk, const N: usize> Ledger<D, N> {
    /// The entry length, as a file offset.
    const LENGTH: u64 = N as u64;

    /// Opens the ledger at `path` in `dir`, creating it empty if it does
    /// not exist, and cuts a partial tail.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Io`] for the operating system's error.
    pub fn open(mut disk: D, dir: &Path, name: &str) -> Result<Self, IntegrityError> {
        let path = dir.join(name);
        let file = super::journal::open_locked(&mut disk, dir, &path)?;
        let length = disk.len(&file)?;
        let whole = length
            .checked_div(Self::LENGTH)
            .ok_or(IntegrityError::Overflow)?;
        let mut entries = Vec::new();
        for index in 0..whole {
            let offset = index
                .checked_mul(Self::LENGTH)
                .ok_or(IntegrityError::Overflow)?;
            let mut entry = [0u8; N];
            disk.read_at(&file, offset, &mut entry)?;
            entries.push(entry);
        }
        let keep = whole
            .checked_mul(Self::LENGTH)
            .ok_or(IntegrityError::Overflow)?;
        if keep != length {
            disk.set_len(&file, keep)?;
            disk.sync(&file)?;
        }
        Ok(Self {
            disk,
            file,
            dir: dir.to_path_buf(),
            entries,
            poisoned: false,
        })
    }

    /// The archive directory the ledger is in: the journal it belongs to
    /// is the one in the same directory.
    #[must_use]
    #[inline]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The entries, oldest first.
    #[must_use]
    #[inline]
    pub fn entries(&self) -> &[[u8; N]] {
        &self.entries
    }

    /// Appends `entry` and syncs it.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::StaleLedger`] when the file holds entries this
    /// handle does not, with nothing written; [`IntegrityError::Io`],
    /// after which the ledger is poisoned until reopened;
    /// [`IntegrityError::Poisoned`] after such a failure.
    pub fn append(&mut self, entry: [u8; N]) -> Result<(), IntegrityError> {
        if self.poisoned {
            return Err(IntegrityError::Poisoned);
        }
        let count = u64::try_from(self.entries.len()).map_err(|_| IntegrityError::Overflow)?;
        let offset = count
            .checked_mul(Self::LENGTH)
            .ok_or(IntegrityError::Overflow)?;
        // Compare and swap on the file length: a handle that does not hold
        // every entry on disk would overwrite one.
        if self.disk.len(&self.file)? != offset {
            return Err(IntegrityError::StaleLedger);
        }
        let written = self
            .disk
            .write_at(&self.file, offset, &entry)
            .and_then(|()| self.disk.sync(&self.file));
        if let Err(error) = written {
            self.poisoned = true;
            return Err(error.into());
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Cuts the ledger to its first `keep` entries and syncs it: how a
    /// reader drops a suffix the chain never recorded before anything is
    /// appended after it.
    ///
    /// # Errors
    ///
    /// As [`Ledger::append`]: [`IntegrityError::StaleLedger`] when the file
    /// holds entries this handle does not, with nothing cut.
    pub fn truncate(&mut self, keep: usize) -> Result<(), IntegrityError> {
        if self.poisoned {
            return Err(IntegrityError::Poisoned);
        }
        let held = u64::try_from(self.entries.len())
            .ok()
            .and_then(|held| held.checked_mul(Self::LENGTH))
            .ok_or(IntegrityError::Overflow)?;
        if self.disk.len(&self.file)? != held {
            return Err(IntegrityError::StaleLedger);
        }
        if keep >= self.entries.len() {
            return Ok(());
        }
        let count = u64::try_from(keep).map_err(|_| IntegrityError::Overflow)?;
        let length = count
            .checked_mul(Self::LENGTH)
            .ok_or(IntegrityError::Overflow)?;
        let cut = self
            .disk
            .set_len(&self.file, length)
            .and_then(|()| self.disk.sync(&self.file));
        if let Err(error) = cut {
            self.poisoned = true;
            return Err(error.into());
        }
        self.entries.truncate(keep);
        Ok(())
    }
}
