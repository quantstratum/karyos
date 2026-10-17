// SPDX-License-Identifier: Apache-2.0

//! The file operations of the Archive's stores, behind a trait so that the
//! torn-write and restart tests can crash them at any point.

use std::io;
use std::path::Path;

/// The file operations of the Archive's stores.
pub trait Disk {
    /// An open file.
    type File: core::fmt::Debug;

    /// Creates `path` empty, replacing any file there, and opens it.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn create(&mut self, path: &Path) -> io::Result<Self::File>;

    /// Opens the existing `path` for reading and writing.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn open(&mut self, path: &Path) -> io::Result<Self::File>;

    /// Writes all of `bytes` at `offset`, extending the file as needed.
    ///
    /// # Errors
    ///
    /// The operating system's error; part of `bytes` may have been written.
    fn write_at(&mut self, file: &Self::File, offset: u64, bytes: &[u8]) -> io::Result<()>;

    /// Reads exactly `buf.len()` bytes at `offset`.
    ///
    /// # Errors
    ///
    /// The operating system's error, or [`io::ErrorKind::UnexpectedEof`]
    /// past the end of the file.
    fn read_at(&mut self, file: &Self::File, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// The length of the file.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn len(&mut self, file: &Self::File) -> io::Result<u64>;

    /// Sets the file's length to `len` bytes: shortened, or extended with
    /// zeros.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn set_len(&mut self, file: &Self::File, len: u64) -> io::Result<()>;

    /// Makes the file's data durable. On Apple targets the standard library
    /// issues `F_FULLFSYNC`, since `fsync` there does not reach stable
    /// storage; on Linux, `fdatasync`.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn sync(&mut self, file: &Self::File) -> io::Result<()>;

    /// Makes the entries of `dir` durable: a file created there survives a
    /// crash only after this (Linux). Elsewhere it does nothing, and a new
    /// file's entry is made durable with its first `F_FULLFSYNC`.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn sync_dir(&mut self, dir: &Path) -> io::Result<()>;

    /// The names of the files in `dir`.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn list(&mut self, dir: &Path) -> io::Result<Vec<String>>;

    /// Removes `path`.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn remove(&mut self, path: &Path) -> io::Result<()>;

    /// Renames `from` to `to`, replacing `to` atomically. The new name is
    /// durable only after [`Disk::sync_dir`].
    ///
    /// # Errors
    ///
    /// The operating system's error.
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;
}

/// The operating system's files, through the standard library.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdDisk;

impl Disk for StdDisk {
    type File = std::fs::File;

    fn create(&mut self, path: &Path) -> io::Result<Self::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    }

    fn open(&mut self, path: &Path) -> io::Result<Self::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
    }

    fn write_at(&mut self, file: &Self::File, offset: u64, bytes: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt as _;
        file.write_all_at(bytes, offset)
    }

    fn read_at(&mut self, file: &Self::File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt as _;
        file.read_exact_at(buf, offset)
    }

    fn len(&mut self, file: &Self::File) -> io::Result<u64> {
        Ok(file.metadata()?.len())
    }

    fn set_len(&mut self, file: &Self::File, len: u64) -> io::Result<()> {
        file.set_len(len)
    }

    fn sync(&mut self, file: &Self::File) -> io::Result<()> {
        file.sync_data()
    }

    fn sync_dir(&mut self, dir: &Path) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            std::fs::File::open(dir)?.sync_all()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = dir;
            Ok(())
        }
    }

    fn list(&mut self, dir: &Path) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            if let Some(name) = entry?.file_name().to_str() {
                names.push(name.to_owned());
            }
        }
        Ok(names)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }
}
