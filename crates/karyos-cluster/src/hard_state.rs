// SPDX-License-Identifier: Apache-2.0

//! The durable term and vote of a Raft node (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C4): one fixed-size record in
//! its own file, replaced atomically: written to a temporary file,
//! synced, renamed over the record, and its directory synced.
//!
//! The record, little endian, 44 bytes:
//!
//! | Bytes | Field |
//! | --- | --- |
//! | 0..4 | magic `KRHS` |
//! | 4..8 | version, 1 |
//! | 8..16 | `current_term` |
//! | 16 | 1 when `voted_for` is set, else 0 |
//! | 17..25 | `voted_for` (0 when unset) |
//! | 25 | 1 when `commit` is set, else 0 |
//! | 26..34 | `commit` (0 when unset) |
//! | 34..40 | zero |
//! | 40..44 | CRC-32C of bytes 0..40 |
//!
//! A record of another length, magic, version or CRC, a flag other than
//! 0 or 1, a value under an unset flag, or a nonzero reserved byte is
//! refused: never defaulted.

use std::fmt;

use karyos_archive::crc32c::crc32c;

/// The file of the record.
pub const HARD_STATE_FILE: &str = "hard-state";
/// The record's length.
pub const HARD_STATE_LEN: usize = 44;
const MAGIC: [u8; 4] = *b"KRHS";
const VERSION: u32 = 1;

/// A node's durable term, vote and, optionally, commit index.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HardState {
    /// The latest term the node has seen.
    pub current_term: u64,
    /// The node it voted for in `current_term`, if any.
    pub voted_for: Option<u64>,
    /// A commit index the node chose to keep; never above the log's
    /// durable last index.
    pub commit: Option<u64>,
}

/// Why a stored record is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardStateProblem {
    /// Not [`HARD_STATE_LEN`] bytes: torn or foreign.
    Length(usize),
    /// Another magic or version.
    Foreign,
    /// The CRC does not match: torn or damaged.
    Checksum,
    /// A flag, an unset value or a reserved byte is not as written.
    Malformed,
}

impl fmt::Display for HardStateProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(length) => {
                write!(f, "{length} bytes, not {HARD_STATE_LEN}")
            }
            Self::Foreign => f.write_str("another magic or version"),
            Self::Checksum => f.write_str("its CRC does not match"),
            Self::Malformed => f.write_str("a flag or a reserved byte is malformed"),
        }
    }
}

impl HardState {
    /// The record of this state.
    #[must_use]
    pub fn encode(&self) -> [u8; HARD_STATE_LEN] {
        let mut bytes = [0u8; HARD_STATE_LEN];
        let put = |bytes: &mut [u8; HARD_STATE_LEN], at: usize, value: &[u8]| {
            if let Some(slot) = bytes.get_mut(at..at + value.len()) {
                slot.copy_from_slice(value);
            }
        };
        put(&mut bytes, 0, &MAGIC);
        put(&mut bytes, 4, &VERSION.to_le_bytes());
        put(&mut bytes, 8, &self.current_term.to_le_bytes());
        put(&mut bytes, 16, &[u8::from(self.voted_for.is_some())]);
        put(&mut bytes, 17, &self.voted_for.unwrap_or(0).to_le_bytes());
        put(&mut bytes, 25, &[u8::from(self.commit.is_some())]);
        put(&mut bytes, 26, &self.commit.unwrap_or(0).to_le_bytes());
        let crc = crc32c(bytes.get(..40).unwrap_or(&[]));
        put(&mut bytes, 40, &crc.to_le_bytes());
        bytes
    }

    /// Decodes a stored record.
    ///
    /// # Errors
    ///
    /// The [`HardStateProblem`] of a record that is not one this version
    /// wrote whole.
    pub fn decode(bytes: &[u8]) -> Result<Self, HardStateProblem> {
        let record: &[u8; HARD_STATE_LEN] = bytes
            .try_into()
            .map_err(|_| HardStateProblem::Length(bytes.len()))?;
        let field = |at: usize| -> [u8; 8] {
            let mut word = [0u8; 8];
            if let Some(slice) = record.get(at..at + 8) {
                word.copy_from_slice(slice);
            }
            word
        };
        let mut crc = [0u8; 4];
        let mut version = [0u8; 4];
        crc.copy_from_slice(record.get(40..44).unwrap_or(&[0; 4]));
        version.copy_from_slice(record.get(4..8).unwrap_or(&[0; 4]));
        if crc32c(record.get(..40).unwrap_or(&[])) != u32::from_le_bytes(crc) {
            return Err(HardStateProblem::Checksum);
        }
        if record.get(..4) != Some(&MAGIC[..]) || u32::from_le_bytes(version) != VERSION {
            return Err(HardStateProblem::Foreign);
        }
        let optional = |flag: usize, at: usize| -> Result<Option<u64>, HardStateProblem> {
            let value = u64::from_le_bytes(field(at));
            match record.get(flag) {
                Some(1) => Ok(Some(value)),
                Some(0) if value == 0 => Ok(None),
                _ => Err(HardStateProblem::Malformed),
            }
        };
        if record
            .get(34..40)
            .is_none_or(|reserved| reserved.iter().any(|byte| *byte != 0))
        {
            return Err(HardStateProblem::Malformed);
        }
        Ok(Self {
            current_term: u64::from_le_bytes(field(8)),
            voted_for: optional(16, 17)?,
            commit: optional(25, 26)?,
        })
    }
}
