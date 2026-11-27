// SPDX-License-Identifier: Apache-2.0

//! A node's durable cluster identity (quantstratum-docs:
//! karyos/adr/0123-cluster-identity.md, decision 1): 32 bytes that tell
//! one cluster from another, written once when the node's state is
//! created, in its own file next to the hard state, and never rewritten.
//!
//! The record, little endian, 80 bytes:
//!
//! | Bytes | Field |
//! | --- | --- |
//! | 0..4 | magic `KRCI` |
//! | 4..8 | version, 1 |
//! | 8..40 | the identity |
//! | 40 | flags: bit 0 `isolated`, every other bit zero |
//! | 41..44 | zero |
//! | 44..76 | the source identity: all zero unless `isolated` |
//! | 76..80 | CRC-32C of bytes 0..76 |
//!
//! A record of another length, magic, version or CRC, an unknown flag, a
//! nonzero reserved byte, or a source identity that contradicts the flag
//! is refused: never defaulted.

use std::fmt;
use std::io;
use std::path::Path;

use karyos_archive::crc32c::crc32c;
use karyos_archive::disk::Disk;

use crate::file;

/// The file of the record.
pub const CLUSTER_IDENTITY_FILE: &str = "cluster-identity";
/// The record's length.
pub const CLUSTER_IDENTITY_LEN: usize = 80;
const MAGIC: [u8; 4] = *b"KRCI";
const VERSION: u32 = 1;
const ISOLATED: u8 = 1;
const BODY: usize = 76;

/// A cluster's 32-byte identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClusterId(pub [u8; 32]);

impl fmt::Debug for ClusterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClusterId(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// A node's identity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityRecord {
    /// The cluster this node belongs to.
    pub identity: ClusterId,
    /// For an isolated rebuild, the identity of the cluster it was rebuilt
    /// from: its external effects stay off and it is never promoted
    /// (ADR-0123 decision 5).
    pub isolated_from: Option<ClusterId>,
}

/// Why a stored record is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProblem {
    /// Not [`CLUSTER_IDENTITY_LEN`] bytes: torn or foreign.
    Length(u64),
    /// Another magic or version.
    Foreign,
    /// The CRC does not match: torn or damaged.
    Checksum,
    /// An unknown flag, a nonzero reserved byte, or a source identity
    /// that contradicts the flag.
    Malformed,
}

impl fmt::Display for IdentityProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(length) => write!(f, "{length} bytes, not {CLUSTER_IDENTITY_LEN}"),
            Self::Foreign => f.write_str("another magic or version"),
            Self::Checksum => f.write_str("its CRC does not match"),
            Self::Malformed => f.write_str("a flag, a reserved byte or the source is malformed"),
        }
    }
}

/// Why the record cannot be loaded or created.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The disk failed.
    #[error("the cluster identity's disk failed: {0}")]
    Io(#[from] io::Error),
    /// The stored record is refused.
    #[error("the cluster identity record is refused: {0}")]
    Refused(IdentityProblem),
    /// The directory holds a node's state but no identity record: the
    /// node does not start (ADR-0123 decision 1).
    #[error("the node's state has no cluster identity record: it does not start")]
    Missing,
    /// A record is already stored: the identity is written once.
    #[error("a cluster identity is already stored: it is written once")]
    Exists,
}

/// `value` at `at` in `bytes`; nothing if it does not fit.
fn put(bytes: &mut [u8; CLUSTER_IDENTITY_LEN], at: usize, value: &[u8]) {
    if let Some(slot) = at
        .checked_add(value.len())
        .and_then(|end| bytes.get_mut(at..end))
    {
        slot.copy_from_slice(value);
    }
}

/// The `N` bytes at `at`.
fn take<const N: usize>(bytes: &[u8; CLUSTER_IDENTITY_LEN], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

impl IdentityRecord {
    /// The record of this identity.
    #[must_use]
    pub fn encode(&self) -> [u8; CLUSTER_IDENTITY_LEN] {
        let mut bytes = [0u8; CLUSTER_IDENTITY_LEN];
        put(&mut bytes, 0, &MAGIC);
        put(&mut bytes, 4, &VERSION.to_le_bytes());
        put(&mut bytes, 8, &self.identity.0);
        if let Some(source) = self.isolated_from {
            put(&mut bytes, 40, &[ISOLATED]);
            put(&mut bytes, 44, &source.0);
        }
        let crc = bytes
            .split_first_chunk::<BODY>()
            .map_or(0, |(body, _)| crc32c(body));
        put(&mut bytes, BODY, &crc.to_le_bytes());
        bytes
    }

    /// Decodes a stored record.
    ///
    /// # Errors
    ///
    /// The [`IdentityProblem`] of a record that is not one this version
    /// wrote whole.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityProblem> {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let record: &[u8; CLUSTER_IDENTITY_LEN] = bytes
            .try_into()
            .map_err(|_| IdentityProblem::Length(length))?;
        let (body, _) = record
            .split_first_chunk::<BODY>()
            .ok_or(IdentityProblem::Length(length))?;
        if take::<4>(record, BODY) != Some(crc32c(body).to_le_bytes()) {
            return Err(IdentityProblem::Checksum);
        }
        if take::<4>(record, 0) != Some(MAGIC)
            || take::<4>(record, 4) != Some(VERSION.to_le_bytes())
        {
            return Err(IdentityProblem::Foreign);
        }
        let malformed = IdentityProblem::Malformed;
        if take::<3>(record, 41) != Some([0; 3]) {
            return Err(malformed);
        }
        let identity = take::<32>(record, 8).ok_or(malformed)?;
        let source = take::<32>(record, 44).ok_or(malformed)?;
        let isolated_from = match take::<1>(record, 40).ok_or(malformed)? {
            [ISOLATED] if source != identity && source != [0; 32] => Some(ClusterId(source)),
            [0] if source == [0; 32] => None,
            _ => return Err(malformed),
        };
        Ok(Self {
            identity: ClusterId(identity),
            isolated_from,
        })
    }

    /// Whether this node is an isolated rebuild.
    #[must_use]
    pub const fn isolated(&self) -> bool {
        self.isolated_from.is_some()
    }

    /// The record stored in `dir`, or nothing when there is none.
    ///
    /// # Errors
    ///
    /// The disk's error, or the stored record's refusal.
    pub fn load<D: Disk>(disk: &mut D, dir: &Path) -> Result<Option<Self>, IdentityError> {
        match file::read(disk, dir, CLUSTER_IDENTITY_FILE, CLUSTER_IDENTITY_LEN)? {
            file::Read::Missing => Ok(None),
            file::Read::TooLong(length) => {
                Err(IdentityError::Refused(IdentityProblem::Length(length)))
            }
            file::Read::Bytes(bytes) => Self::decode(&bytes)
                .map(Some)
                .map_err(IdentityError::Refused),
        }
    }

    /// The record a node opening `dir` starts under (ADR-0123 decision
    /// 1): the stored one; or, for a node with no state yet (`fresh`),
    /// `create`d, its identity given by the bootstrap or the operator.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Missing`] for a node with state and no record:
    /// it does not start under a default; else as [`Self::load`] and
    /// [`Self::create`].
    pub fn open<D: Disk>(
        disk: &mut D,
        dir: &Path,
        fresh: bool,
        create: impl FnOnce() -> Self,
    ) -> Result<Self, IdentityError> {
        match Self::load(disk, dir)? {
            Some(record) => Ok(record),
            None if fresh => {
                let record = create();
                record.create(disk, dir)?;
                Ok(record)
            }
            None => Err(IdentityError::Missing),
        }
    }

    /// Stores this record in `dir`, durably, when none is stored yet.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Exists`] when a record is already stored, whole or
    /// not: the identity is written once; else the disk's error.
    pub fn create<D: Disk>(&self, disk: &mut D, dir: &Path) -> Result<(), IdentityError> {
        if !matches!(
            file::read(disk, dir, CLUSTER_IDENTITY_FILE, CLUSTER_IDENTITY_LEN)?,
            file::Read::Missing
        ) {
            return Err(IdentityError::Exists);
        }
        file::replace(disk, dir, CLUSTER_IDENTITY_FILE, &self.encode())?;
        Ok(())
    }
}

/// The identity of a rebuild of `source` whose log reaches `(index,
/// term)` (ADR-0123 decision 2): SHA-256 over a domain string, the source
/// identity, the top index and term, and the caller's random `nonce`.
#[cfg(feature = "backup")]
#[must_use]
pub fn rebuild_identity(source: ClusterId, index: u64, term: u64, nonce: [u8; 32]) -> ClusterId {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"karyos cluster rebuild v1");
    hash.update(source.0);
    hash.update(index.to_le_bytes());
    hash.update(term.to_le_bytes());
    hash.update(nonce);
    ClusterId(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live() -> IdentityRecord {
        IdentityRecord {
            identity: ClusterId([7; 32]),
            isolated_from: None,
        }
    }

    fn isolated() -> IdentityRecord {
        IdentityRecord {
            identity: ClusterId([9; 32]),
            isolated_from: Some(ClusterId([7; 32])),
        }
    }

    /// Recomputes the CRC of a record changed in place.
    fn resealed(mut bytes: [u8; CLUSTER_IDENTITY_LEN]) -> [u8; CLUSTER_IDENTITY_LEN] {
        let crc = crc32c(&bytes[..BODY]);
        bytes[BODY..].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    #[test]
    fn a_record_round_trips() {
        for record in [live(), isolated()] {
            assert_eq!(IdentityRecord::decode(&record.encode()), Ok(record));
        }
        assert!(isolated().isolated());
        assert!(!live().isolated());
    }

    #[test]
    fn a_record_not_written_whole_is_refused() {
        let bytes = live().encode();
        assert_eq!(
            IdentityRecord::decode(&bytes[..79]),
            Err(IdentityProblem::Length(79))
        );
        let mut torn = bytes;
        torn[20] ^= 1;
        assert_eq!(
            IdentityRecord::decode(&torn),
            Err(IdentityProblem::Checksum)
        );
        let mut magic = bytes;
        magic[0] = b'X';
        assert_eq!(
            IdentityRecord::decode(&resealed(magic)),
            Err(IdentityProblem::Foreign)
        );
        let mut version = bytes;
        version[4] = 2;
        assert_eq!(
            IdentityRecord::decode(&resealed(version)),
            Err(IdentityProblem::Foreign)
        );
    }

    #[test]
    fn a_malformed_flag_reserved_byte_or_source_is_refused() {
        let bytes = live().encode();
        let mut flag = bytes;
        flag[40] = 2;
        let mut reserved = bytes;
        reserved[42] = 1;
        // A source identity under an unset flag.
        let mut stray = bytes;
        stray[50] = 1;
        // The flag with no source.
        let mut sourceless = bytes;
        sourceless[40] = ISOLATED;
        // A rebuild that kept its source's identity.
        let mut kept = isolated().encode();
        kept[44..76].copy_from_slice(&[9; 32]);
        for case in [flag, reserved, stray, sourceless, kept] {
            assert_eq!(
                IdentityRecord::decode(&resealed(case)),
                Err(IdentityProblem::Malformed)
            );
        }
    }

    #[test]
    fn the_identity_is_written_once_and_read_back() {
        use karyos_archive::disk::StdDisk;
        let dir =
            std::env::temp_dir().join(format!("karyos-cluster-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut disk = StdDisk;
        assert_eq!(IdentityRecord::load(&mut disk, &dir).unwrap(), None);
        live().create(&mut disk, &dir).unwrap();
        assert_eq!(IdentityRecord::load(&mut disk, &dir).unwrap(), Some(live()));
        assert!(matches!(
            isolated().create(&mut disk, &dir),
            Err(IdentityError::Exists)
        ));
        assert_eq!(IdentityRecord::load(&mut disk, &dir).unwrap(), Some(live()));
        // A torn record is refused, never defaulted, and never replaced.
        std::fs::write(dir.join(CLUSTER_IDENTITY_FILE), &live().encode()[..40]).unwrap();
        assert!(matches!(
            IdentityRecord::load(&mut disk, &dir),
            Err(IdentityError::Refused(IdentityProblem::Length(40)))
        ));
        assert!(matches!(
            live().create(&mut disk, &dir),
            Err(IdentityError::Exists)
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_node_with_state_and_no_identity_does_not_start() {
        use karyos_archive::disk::StdDisk;
        let dir = std::env::temp_dir().join(format!(
            "karyos-cluster-identity-open-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut disk = StdDisk;
        assert!(matches!(
            IdentityRecord::open(&mut disk, &dir, false, live),
            Err(IdentityError::Missing)
        ));
        assert_eq!(
            IdentityRecord::open(&mut disk, &dir, true, live).unwrap(),
            live()
        );
        // Opened again, the stored record wins over a new one.
        assert_eq!(
            IdentityRecord::open(&mut disk, &dir, true, isolated).unwrap(),
            live()
        );
        assert_eq!(
            IdentityRecord::open(&mut disk, &dir, false, isolated).unwrap(),
            live()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "backup")]
    #[test]
    fn two_rebuilds_of_one_export_take_two_identities() {
        let source = ClusterId([7; 32]);
        let first = rebuild_identity(source, 40, 3, [1; 32]);
        let second = rebuild_identity(source, 40, 3, [2; 32]);
        assert_ne!(first, second);
        assert_ne!(first, source);
        assert_eq!(first, rebuild_identity(source, 40, 3, [1; 32]));
        assert_ne!(first, rebuild_identity(source, 41, 3, [1; 32]));
    }

    /// The derivation's vector (ADR-0123 decision 2): SHA-256 over the
    /// 25-byte domain, the source, the index and term little endian, and
    /// the nonce, 105 bytes in all; computed independently.
    #[cfg(feature = "backup")]
    #[test]
    fn the_rebuild_identity_matches_its_vector() {
        let identity = rebuild_identity(ClusterId([7; 32]), 290, 3, [1; 32]);
        let expected: [u8; 32] = [
            0x7f, 0x50, 0x72, 0x3a, 0x28, 0xe7, 0x57, 0x59, 0xe8, 0x85, 0x39, 0x82, 0x56, 0xc5,
            0x1d, 0xc5, 0x9c, 0xb0, 0x7f, 0x87, 0x7f, 0x32, 0x55, 0x18, 0xf9, 0x33, 0xea, 0x85,
            0xbe, 0x65, 0x50, 0xef,
        ];
        assert_eq!(identity, ClusterId(expected));
    }
}
