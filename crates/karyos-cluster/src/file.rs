// SPDX-License-Identifier: Apache-2.0

//! Small records kept whole in their own file, replaced atomically through
//! the [`Disk`] trait: written to a temporary file, synced, renamed over
//! the record and its directory synced. A crash leaves the old record or
//! the new one, never a mix; a record that is torn anyway (a disk that
//! lies) is refused by its CRC when it is read.

use std::io;
use std::path::Path;

use karyos_archive::disk::Disk;

/// Replaces `dir/name` with `bytes`: `dir/name.tmp` is written and synced,
/// renamed over `name`, then `dir` is synced. Durable on return.
///
/// # Errors
///
/// The disk's error at any step; the record is then the old one or the
/// new one, and the caller cannot tell which until it reads it back.
pub(crate) fn replace<D: Disk>(
    disk: &mut D,
    dir: &Path,
    name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let target = dir.join(name);
    let temporary = dir.join(format!("{name}.tmp"));
    let file = disk.create(&temporary)?;
    disk.write_at(&file, 0, bytes)?;
    disk.sync(&file)?;
    drop(file);
    disk.rename(&temporary, &target)?;
    disk.sync_dir(dir)
}

/// A record file as read.
#[derive(Debug)]
pub(crate) enum Read {
    /// No such file.
    Missing,
    /// Its bytes: no more than the record's length.
    Bytes(Vec<u8>),
    /// Longer than the record: its length, nothing read.
    TooLong(u64),
}

/// The bytes of `dir/name`, read only up to `record` bytes.
///
/// # Errors
///
/// The disk's error other than a missing file.
pub(crate) fn read<D: Disk>(
    disk: &mut D,
    dir: &Path,
    name: &str,
    record: usize,
) -> io::Result<Read> {
    let file = match disk.open_read(&dir.join(name)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Read::Missing),
        Err(error) => return Err(error),
    };
    let length = disk.len(&file)?;
    let Some(fits) = usize::try_from(length).ok().filter(|fits| *fits <= record) else {
        return Ok(Read::TooLong(length));
    };
    let mut bytes = vec![0u8; fits];
    disk.read_at(&file, 0, &mut bytes)?;
    Ok(Read::Bytes(bytes))
}
