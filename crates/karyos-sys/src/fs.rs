// SPDX-License-Identifier: Apache-2.0

//! File system queries for hosts of the driver (Linux): the free space
//! of the file system that holds a path, which `karyosd` checks before it
//! starts an Archive recording (`quantstratum-docs:
//! karyos/design/archive-host.md`, H3, `--archive-min-free`).

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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    /// A directory that exists has some free space reported (a test host
    /// with a full disk would fail other tests first); a path that does
    /// not exist is an OS error, never zero.
    #[test]
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
}
