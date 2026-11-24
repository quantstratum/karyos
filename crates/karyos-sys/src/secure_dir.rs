// SPDX-License-Identifier: Apache-2.0

//! A directory opened once by descriptor, and the small files read and
//! written under it, for the wire authentication key directory and the
//! durable key state (`quantstratum-docs: karyos/design/wire-key-files.md`
//! sections 2.1 and 2.6; quantstratum/karyos#648).
//!
//! The path is walked from `/` one component at a time, each opened with
//! `O_DIRECTORY | O_NOFOLLOW` under its parent's descriptor and checked
//! with `fstat` on that descriptor, so no component is checked by path and
//! then used by path. The directory's descriptor is then kept, and the path
//! is never resolved again. Every call goes through `rustix`'s safe
//! wrappers.

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Component, Path};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, fsync, openat, renameat, unlinkat};
use rustix::io::Errno;
use thiserror::Error;

/// Why a directory or a file under it is refused. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SecureDirError {
    /// The path is not absolute, or names `..`, `.` or a prefix.
    #[error("the directory path is not a plain absolute path")]
    Path,
    /// A symbolic link in the path, or the file is one.
    #[error("symbolic link refused")]
    Symlink,
    /// A component that is not a directory, or a file that is not regular.
    #[error("wrong file type")]
    FileType,
    /// Owned by someone other than root (ancestors only) or the service
    /// identity.
    #[error("wrong owner")]
    Owner,
    /// Writable by group or others (a directory), or granting any
    /// permission to group or others (a file).
    #[error("permissions too wide")]
    Mode,
    /// Larger than the caller's limit, by `fstat` or by the read itself.
    #[error("file too large")]
    TooLarge,
    /// The file does not exist.
    #[error("no such file")]
    NotFound,
    /// A name that is empty, holds `/` or NUL, or is `.` or `..`.
    #[error("bad file name")]
    Name,
    /// A system call failed.
    #[error("{operation} failed with OS error {errno}")]
    Os {
        /// The failing operation.
        operation: &'static str,
        /// Raw OS error number.
        errno: i32,
    },
}

fn os(operation: &'static str) -> impl Fn(Errno) -> SecureDirError {
    move |errno| match errno {
        Errno::LOOP => SecureDirError::Symlink,
        Errno::NOENT => SecureDirError::NotFound,
        _ => SecureDirError::Os {
            operation,
            errno: errno.raw_os_error(),
        },
    }
}

/// The effective user of this process: the service identity the key
/// directory and its files must belong to.
#[must_use]
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A directory opened once by descriptor and checked (design section 2.1).
#[derive(Debug)]
pub struct SecureDir {
    fd: OwnedFd,
    owner: u32,
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn open_dir(parent: impl AsFd, name: &str) -> Result<(OwnedFd, Stat), SecureDirError> {
    let fd = openat(&parent, name, DIR_FLAGS, Mode::empty()).map_err(|errno| match errno {
        // `O_NOFOLLOW | O_DIRECTORY` on a symbolic link answers `ENOTDIR`
        // on Linux, as a plain file does. The link is refused either way;
        // `fstatat` only names the reason.
        Errno::NOTDIR => match rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {
                SecureDirError::Symlink
            }
            _ => SecureDirError::FileType,
        },
        other => os("openat")(other),
    })?;
    let stat = fstat(&fd).map_err(os("fstat"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(SecureDirError::FileType);
    }
    Ok((fd, stat))
}

impl SecureDir {
    /// Opens the absolute directory `path` for the service identity
    /// `owner`. Every ancestor must be owned by root or `owner` and not be
    /// writable by group or others; the directory itself must be owned by
    /// `owner` with `mode & 0o022 == 0`. A symbolic link anywhere fails.
    ///
    /// # Errors
    ///
    /// The first [`SecureDirError`] that applies.
    pub fn open(path: &Path, owner: u32) -> Result<Self, SecureDirError> {
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(SecureDirError::Path);
        }
        let (root, stat) = open_dir(rustix::fs::CWD, "/")?;
        Self::walk(root, &stat, components, owner)
    }

    /// Opens `relative` beneath `base`, checking `base` and each component
    /// as [`SecureDir::open`] checks the ancestors and the directory: the
    /// same walk, started below `/` so that tests do not depend on the
    /// host's ancestors.
    ///
    /// # Errors
    ///
    /// As [`SecureDir::open`].
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn open_beneath(base: &Path, relative: &Path, owner: u32) -> Result<Self, SecureDirError> {
        let fd = rustix::fs::open(base, DIR_FLAGS, Mode::empty()).map_err(os("open"))?;
        let stat = fstat(&fd).map_err(os("fstat"))?;
        Self::walk(fd, &stat, relative.components(), owner)
    }

    fn walk<'a>(
        mut fd: OwnedFd,
        stat: &Stat,
        components: impl Iterator<Item = Component<'a>>,
        owner: u32,
    ) -> Result<Self, SecureDirError> {
        let mut last = *stat;
        for component in components {
            let Component::Normal(name) = component else {
                return Err(SecureDirError::Path);
            };
            let name = name.to_str().ok_or(SecureDirError::Path)?;
            check_ancestor(&last, owner)?;
            let (next, stat) = open_dir(&fd, name)?;
            fd = next;
            last = stat;
        }
        if last.st_uid != owner {
            return Err(SecureDirError::Owner);
        }
        if last.st_mode & 0o022 != 0 {
            return Err(SecureDirError::Mode);
        }
        Ok(Self { fd, owner })
    }

    /// The names of the directory's entries, `.` and `..` left out.
    ///
    /// # Errors
    ///
    /// [`SecureDirError::Os`] when the directory cannot be read.
    pub fn names(&self) -> Result<Vec<String>, SecureDirError> {
        let dir = rustix::fs::Dir::read_from(&self.fd).map_err(os("readdir"))?;
        let mut names = Vec::new();
        for entry in dir {
            let entry = entry.map_err(os("readdir"))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            // A name that is not UTF-8 is no key file; it is skipped.
            if let Ok(name) = core::str::from_utf8(name) {
                names.push(name.to_owned());
            }
        }
        Ok(names)
    }

    /// Reads the file `name` into `buf` and returns its length. The file is
    /// opened `O_NOFOLLOW | O_NONBLOCK` and checked by `fstat` on its
    /// descriptor: a regular file owned by the service identity, with
    /// `mode & 0o077 == 0`, at most `buf.len() - 1` bytes. The read stops
    /// when `buf` is full whatever `fstat` said, so a file that grows during
    /// the read is refused (a 4096-byte limit reads into 4097 bytes). The
    /// caller erases `buf` on every exit.
    ///
    /// # Errors
    ///
    /// The first [`SecureDirError`] that applies.
    pub fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, SecureDirError> {
        check_name(name)?;
        let limit = buf.len().saturating_sub(1);
        let fd = openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(os("openat"))?;
        let stat = fstat(&fd).map_err(os("fstat"))?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => {}
            FileType::Symlink => return Err(SecureDirError::Symlink),
            _ => return Err(SecureDirError::FileType),
        }
        if stat.st_uid != self.owner {
            return Err(SecureDirError::Owner);
        }
        if stat.st_mode & 0o077 != 0 {
            return Err(SecureDirError::Mode);
        }
        if !usize::try_from(stat.st_size).is_ok_and(|size| size <= limit) {
            return Err(SecureDirError::TooLarge);
        }
        let mut filled = 0;
        while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            match rustix::io::read(&fd, rest) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(Errno::INTR) => {}
                Err(errno) => return Err(os("read")(errno)),
            }
        }
        if filled > limit {
            return Err(SecureDirError::TooLarge);
        }
        Ok(filled)
    }

    /// Replaces the file `name` with `bytes`, durably: a temporary file is
    /// written with mode `0600`, `fsync`ed, renamed into place, and the
    /// directory is `fsync`ed (design section 2.6, "Commit").
    ///
    /// # Errors
    ///
    /// [`SecureDirError::Os`] when a step fails; `name` then still holds
    /// its previous bytes or the new ones, never a mix.
    pub fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), SecureDirError> {
        check_name(name)?;
        let temp = format!(".{name}.tmp");
        match unlinkat(&self.fd, temp.as_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(errno) => return Err(os("unlinkat")(errno)),
        }
        let fd = openat(
            &self.fd,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(os("openat"))?;
        let mut written = 0;
        while let Some(rest) = bytes.get(written..).filter(|rest| !rest.is_empty()) {
            match rustix::io::write(&fd, rest) {
                Ok(0) => return Err(os("write")(Errno::IO)),
                Ok(count) => written += count,
                Err(Errno::INTR) => {}
                Err(errno) => return Err(os("write")(errno)),
            }
        }
        fsync(&fd).map_err(os("fsync"))?;
        drop(fd);
        renameat(&self.fd, temp.as_str(), &self.fd, name).map_err(os("renameat"))?;
        fsync(&self.fd).map_err(os("fsync"))
    }
}

fn check_ancestor(stat: &Stat, owner: u32) -> Result<(), SecureDirError> {
    if stat.st_uid != 0 && stat.st_uid != owner {
        return Err(SecureDirError::Owner);
    }
    if stat.st_mode & 0o022 != 0 {
        return Err(SecureDirError::Mode);
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), SecureDirError> {
    if name.is_empty() || name == "." || name == ".." || name.bytes().any(|b| b == b'/' || b == 0) {
        return Err(SecureDirError::Name);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
