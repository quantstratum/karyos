// SPDX-License-Identifier: Apache-2.0

//! The log's durable watermark: the last index [`crate::RaftLog::sync`]
//! reported durable, so a recovery can tell a crash's loss (above it) from
//! corruption (below it).
//!
//! The file holds two 32-byte slots, little endian, written in place:
//!
//! | Bytes | Field |
//! | --- | --- |
//! | 0..4 | magic `KRDM` |
//! | 4..12 | sequence |
//! | 12 | 1 when an index is set, else 0 |
//! | 13..21 | the durable last index (0 when unset) |
//! | 21..28 | zero |
//! | 28..32 | CRC-32C of bytes 0..28 |
//!
//! A new mark goes into the older slot, with the next sequence, then the
//! file is synced: a torn write leaves the other slot, an older mark, which
//! is still safe. The newest valid slot is the mark; with none valid, the
//! mark is unset (the first index minus one), the conservative choice.

use std::io;
use std::path::Path;

use karyos_archive::crc32c::crc32c;
use karyos_archive::disk::Disk;

/// The watermark's file.
pub const MARK_FILE: &str = "durable-mark";
/// One slot's length.
pub const SLOT_LEN: usize = 32;
/// The file's length: two slots.
pub const MARK_LEN: usize = 64;
/// The second slot's offset.
const SLOT_OFFSET: u64 = 32;
const MAGIC: [u8; 4] = *b"KRDM";

/// One slot's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// Its sequence: the newest valid slot is the mark.
    pub sequence: u64,
    /// The durable last index it records, `None` before the first entry.
    pub durable: Option<u64>,
}

impl Slot {
    /// The slot's bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; SLOT_LEN] {
        let mut bytes = [0u8; SLOT_LEN];
        let (body, crc) = bytes.split_at_mut(28);
        let (magic, rest) = body.split_at_mut(4);
        magic.copy_from_slice(&MAGIC);
        let (sequence, rest) = rest.split_at_mut(8);
        sequence.copy_from_slice(&self.sequence.to_le_bytes());
        let (flag, rest) = rest.split_at_mut(1);
        flag.copy_from_slice(&[u8::from(self.durable.is_some())]);
        let (index, _) = rest.split_at_mut(8);
        index.copy_from_slice(&self.durable.unwrap_or(0).to_le_bytes());
        let sum = crc32c(body);
        crc.copy_from_slice(&sum.to_le_bytes());
        bytes
    }

    /// The slot in `bytes`, if it is one this version wrote whole.
    #[must_use]
    pub fn decode(bytes: &[u8; SLOT_LEN]) -> Option<Self> {
        let (body, crc) = bytes.split_first_chunk::<28>()?;
        let crc: [u8; 4] = crc.try_into().ok()?;
        if u32::from_le_bytes(crc) != crc32c(body) {
            return None;
        }
        let (magic, rest) = body.split_first_chunk::<4>()?;
        let (sequence, rest) = rest.split_first_chunk::<8>()?;
        let (flag, rest) = rest.split_first_chunk::<1>()?;
        let (index, reserved) = rest.split_first_chunk::<8>()?;
        if *magic != MAGIC || reserved.iter().any(|byte| *byte != 0) {
            return None;
        }
        let index = u64::from_le_bytes(*index);
        let durable = match flag {
            [1] => Some(index),
            [0] if index == 0 => None,
            _ => return None,
        };
        Some(Self {
            sequence: u64::from_le_bytes(*sequence),
            durable,
        })
    }
}

/// The newest valid slot of the file's bytes, and which slot it is.
#[must_use]
pub fn newest(bytes: &[u8]) -> Option<(usize, Slot)> {
    let (first, rest) = bytes.split_first_chunk::<SLOT_LEN>()?;
    let second = rest.first_chunk::<SLOT_LEN>();
    let slots = [Slot::decode(first), second.and_then(Slot::decode)];
    slots
        .into_iter()
        .enumerate()
        .filter_map(|(at, slot)| slot.map(|slot| (at, slot)))
        .max_by_key(|(_, slot)| slot.sequence)
}

/// Writes `slot` at slot `at` (0 or 1) of the open file, then syncs it.
///
/// # Errors
///
/// The disk's errors.
pub(crate) fn write<D: Disk>(
    disk: &mut D,
    file: &D::File,
    at: usize,
    slot: Slot,
) -> io::Result<()> {
    let offset = if at == 0 { 0 } else { SLOT_OFFSET };
    disk.write_at(file, offset, &slot.encode())?;
    disk.sync(file)
}

/// Creates the file with an unset mark in slot 0, durable with its name on
/// return.
///
/// # Errors
///
/// The disk's errors.
pub(crate) fn create<D: Disk>(disk: &mut D, dir: &Path) -> io::Result<D::File> {
    let file = disk.create(&dir.join(MARK_FILE))?;
    let mut bytes = [0u8; MARK_LEN];
    if let Some(first) = bytes.first_chunk_mut::<SLOT_LEN>() {
        *first = Slot {
            sequence: 1,
            durable: None,
        }
        .encode();
    }
    disk.write_at(&file, 0, &bytes)?;
    disk.sync(&file)?;
    disk.sync_dir(dir)?;
    Ok(file)
}
