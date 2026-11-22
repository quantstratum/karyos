// SPDX-License-Identifier: Apache-2.0

//! File system queries for hosts of the driver (Linux): the free space
//! of the file system that holds a path, which `karyosd` checks before it
//! starts an Archive recording (`quantstratum-docs:
//! karyos/design/archive-host.md`, H3, `--archive-min-free`), and the
//! immutable attribute of a sealed segment (SPEC.md §8.4, "Immutability
//! enforcement"; karyos#958).

use std::path::Path;

use crate::error::SysError;

/// The bytes available to an unprivileged user on the file system that
/// holds `path` (`statvfs`: available blocks times the fragment size).
///
/// # Errors
///
/// [`SysError::Os`] when `statvfs` fails, for example for a path that
/// does not exist, and with `EOVERFLOW` when the product does not fit a
/// `u64`.
pub fn free_bytes(path: &Path) -> Result<u64, SysError> {
    let stat = rustix::fs::statvfs(path).map_err(|errno| SysError::Os {
        operation: "statvfs",
        errno: errno.raw_os_error(),
    })?;
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or(SysError::Os {
            operation: "statvfs",
            errno: rustix::io::Errno::OVERFLOW.raw_os_error(),
        })
}

/// What setting or clearing a file's immutable attribute came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum Immutability {
    /// The attribute is now as asked.
    Applied,
    /// The platform or the file system has no immutable attribute.
    Unsupported,
    /// The attribute exists but this process may not change it (on Linux,
    /// it needs `CAP_LINUX_IMMUTABLE`).
    NotPermitted,
}

/// Sets (`immutable`) or clears the immutable attribute of the file at
/// `path`: on Linux `FS_IOC_SETFLAGS` with `FS_IMMUTABLE_FL`, through
/// `rustix`'s safe wrapper, so no `unsafe` is added (karyos#958). An
/// immutable file can be neither written, renamed nor removed until the
/// attribute is cleared. A file system without it answers
/// [`Immutability::Unsupported`].
///
/// # Errors
///
/// [`SysError::Os`] when the file cannot be opened or its flags read or
/// written for another reason than missing support or permission, and
/// (`EINVAL`) for a path that is not a regular file: it is opened without
/// blocking (a FIFO would otherwise wait for a writer) and checked with
/// `fstat` before any `ioctl` reaches it (karyos#958 review).
pub fn set_immutable(path: &Path, immutable: bool) -> Result<Immutability, SysError> {
    use rustix::fs::{FileType, IFlags, Mode, OFlags, fstat, ioctl_getflags, ioctl_setflags, open};
    use rustix::io::Errno;

    let os = |operation: &'static str| {
        move |errno: Errno| SysError::Os {
            operation,
            errno: errno.raw_os_error(),
        }
    };
    let file = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(os("open"))?;
    let stat = fstat(&file).map_err(os("fstat"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(os("not a regular file")(Errno::INVAL));
    }
    let unsupported =
        |errno: Errno| matches!(errno, Errno::NOTTY | Errno::OPNOTSUPP | Errno::INVAL);
    let flags = match ioctl_getflags(&file) {
        Ok(flags) => flags,
        Err(errno) if unsupported(errno) => return Ok(Immutability::Unsupported),
        Err(errno) => return Err(os("ioctl(FS_IOC_GETFLAGS)")(errno)),
    };
    let wanted = if immutable {
        flags | IFlags::IMMUTABLE
    } else {
        flags & !IFlags::IMMUTABLE
    };
    if wanted == flags {
        return Ok(Immutability::Applied);
    }
    match ioctl_setflags(&file, wanted) {
        Ok(()) => Ok(Immutability::Applied),
        Err(errno) if unsupported(errno) => Ok(Immutability::Unsupported),
        Err(Errno::PERM | Errno::ACCESS) => Ok(Immutability::NotPermitted),
        Err(errno) => Err(os("ioctl(FS_IOC_SETFLAGS)")(errno)),
    }
}

/// Whether the regular file at `path` carries the immutable attribute
/// (`FS_IOC_GETFLAGS`, `FS_IMMUTABLE_FL`), read through `rustix`'s safe
/// wrapper as [`set_immutable`] reads it: `None` where the file system
/// has no such attribute. `karyos-catalog verify` reports it per copy
/// (karyos#1087).
///
/// # Errors
///
/// [`SysError::Os`] when the file cannot be opened or its flags read for
/// another reason than missing support, and (`EINVAL`) for a path that is
/// not a regular file.
pub fn is_immutable(path: &Path) -> Result<Option<bool>, SysError> {
    use rustix::fs::{FileType, IFlags, Mode, OFlags, fstat, ioctl_getflags, open};
    use rustix::io::Errno;

    let os = |operation: &'static str| {
        move |errno: Errno| SysError::Os {
            operation,
            errno: errno.raw_os_error(),
        }
    };
    let file = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(os("open"))?;
    let stat = fstat(&file).map_err(os("fstat"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(os("not a regular file")(Errno::INVAL));
    }
    match ioctl_getflags(&file) {
        Ok(flags) => Ok(Some(flags.contains(IFlags::IMMUTABLE))),
        Err(Errno::NOTTY | Errno::OPNOTSUPP | Errno::INVAL) => Ok(None),
        Err(errno) => Err(os("ioctl(FS_IOC_GETFLAGS)")(errno)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    /// A directory that exists has some free space reported (a test host
    /// with a full disk would fail other tests first); a path that does
    /// not exist is an OS error, never zero. Miri cannot call `statvfs`
    /// (karyos#924).
    #[cfg(not(miri))]
    #[test]
    #[cfg_attr(miri, ignore = "host syscalls")]
    fn the_free_space_of_a_path_is_read() {
        let dir = std::env::temp_dir();
        assert!(free_bytes(&dir).unwrap() > 0);
        let missing = dir.join("karyos-fs-no-such-dir/x");
        assert!(matches!(
            free_bytes(&missing),
            Err(SysError::Os {
                operation: "statvfs",
                ..
            })
        ));
    }

    /// The attribute is set and cleared where this process may; a file
    /// made immutable refuses writes and removal until released. Without
    /// support or `CAP_LINUX_IMMUTABLE` the typed answer says so.
    #[test]
    #[cfg_attr(miri, ignore = "host syscalls")]
    fn the_immutable_attribute_is_set_and_released_or_reported() {
        let dir = std::env::temp_dir().join(format!("karyos-immutable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealed.seg");
        std::fs::write(&path, b"sealed").unwrap();
        match set_immutable(&path, true).unwrap() {
            Immutability::Applied => {
                assert!(
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .is_err()
                );
                assert!(std::fs::remove_file(&path).is_err());
                assert_eq!(set_immutable(&path, false).unwrap(), Immutability::Applied);
                std::fs::remove_file(&path).unwrap();
            }
            other => {
                assert!(matches!(
                    other,
                    Immutability::Unsupported | Immutability::NotPermitted
                ));
                // Clearing an attribute never set changes nothing.
                let _ = set_immutable(&path, false).unwrap();
            }
        }
        assert!(set_immutable(&dir.join("missing"), true).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// karyos#958 review: a path that is not a regular file is refused
    /// before any ioctl, and a FIFO does not block the open waiting for a
    /// writer.
    #[test]
    #[cfg_attr(miri, ignore = "host syscalls")]
    fn a_fifo_is_refused_without_blocking() {
        let dir =
            std::env::temp_dir().join(format!("karyos-immutable-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        // The open runs on its own thread with a bound: a missing
        // O_NONBLOCK makes this fail on the timeout instead of hanging.
        let (sender, outcome) = std::sync::mpsc::channel();
        let path = fifo.clone();
        let _ = std::thread::spawn(move || {
            let _ = sender.send(set_immutable(&path, true));
        });
        let refused = outcome
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert!(matches!(
            refused,
            Err(SysError::Os {
                operation: "not a regular file",
                ..
            })
        ));
        assert!(matches!(
            set_immutable(&dir, true),
            Err(SysError::Os {
                operation: "not a regular file",
                ..
            })
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A plain file reads as not immutable, or as no attribute where the
    /// file system has none; a directory is refused (karyos#1087).
    #[cfg(not(miri))]
    #[test]
    #[cfg_attr(miri, ignore = "host syscalls")]
    fn the_immutable_attribute_of_a_file_is_read() {
        let dir = std::env::temp_dir().join(format!("karyos-fs-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plain");
        std::fs::write(&path, b"x").unwrap();
        assert!(matches!(is_immutable(&path).unwrap(), Some(false) | None));
        assert!(is_immutable(&dir).is_err());
        assert!(is_immutable(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
