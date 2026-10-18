// SPDX-License-Identifier: Apache-2.0

//! What the log needs to know of A2's index files before and after A2's
//! recovery: the start of the last whole write. A2's format is documented
//! in `karyos_archive::segment` (a 48-byte header, then 32-byte entries:
//! the start at 0, the length at 8, the kind at 16, the entry's own
//! CRC-32C of bytes 0..28 at 28); an entry whose own CRC fails is not a
//! whole write and is skipped.

use std::io;
use std::path::Path;

use karyos_archive::crc32c::crc32c;
use karyos_archive::disk::Disk;

const HEADER: u64 = 48;
const ENTRY: u64 = 32;

/// The start of the last whole write the index files of `recording` in
/// `dir` record, if any.
///
/// # Errors
///
/// The disk's errors.
pub(crate) fn last_write_start<D: Disk>(
    disk: &mut D,
    dir: &Path,
    recording: u64,
) -> io::Result<Option<u64>> {
    let prefix = format!("{recording:016x}-");
    let mut last = None;
    for name in disk.list(dir)? {
        if !(name.starts_with(&prefix) && name.ends_with(".idx")) {
            continue;
        }
        let file = disk.open_read(&dir.join(&name))?;
        let length = disk.len(&file)?;
        let mut at = HEADER;
        while let Some(end) = at.checked_add(ENTRY).filter(|end| *end <= length) {
            let mut slot = [0u8; 32];
            disk.read_at(&file, at, &mut slot)?;
            if let Some(start) = whole_write(&slot) {
                last = Some(last.map_or(start, |last: u64| last.max(start)));
            }
            at = end;
        }
    }
    Ok(last)
}

/// The start of the write an index entry records, if it is whole: its own
/// CRC holds and it covers bytes.
fn whole_write(slot: &[u8; 32]) -> Option<u64> {
    let (body, crc) = slot.split_at(28);
    let crc = u32::from_le_bytes(crc.try_into().ok()?);
    let start = u64::from_le_bytes(body.get(..8)?.try_into().ok()?);
    let length = u32::from_le_bytes(body.get(8..12)?.try_into().ok()?);
    (crc == crc32c(body) && length > 0).then_some(start)
}
