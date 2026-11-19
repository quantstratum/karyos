// SPDX-License-Identifier: Apache-2.0

//! The trust bootstrap, the key registry and signed chain heads
//! (quantstratum-docs: karyos/SPEC.md §8.4, "Trust bootstrap", "Signed
//! heads and custody" and "Key registry"; ADR-0051 items 3, 4 and 6;
//! karyos#663).
//!
//! # Trust starts outside the export
//!
//! A key registry kept inside the integrity journal cannot authenticate
//! itself. A verifier therefore starts from a [`TrustRoot`] it is given
//! independently: the Archive's identity and the public keys of the
//! archival root or key authority. Every registry entry carries an
//! endorsement signature by one of those authority keys, so a registry
//! written by whoever controls the Archive host proves nothing unless the
//! authority endorsed it.
//!
//! # The archival key is not a wire key
//!
//! Heads are signed with Ed25519 (RFC 8032) over [`ChainHead::signed_bytes`],
//! which begin with a domain tag of the archival head purpose and carry the
//! Archive identity, the journal identity, the counter and the record
//! digest. The separation is structural: the only thing a
//! [`super::signing::HeadSigner`] can be asked to sign is a [`ChainHead`],
//! the only bytes a head is verified over are its signed bytes, and the
//! endorsement uses a different domain tag again. A signature made for any
//! other purpose, a wire key's included, does not verify as a head.
//! Verification uses `verify_strict`, as the admission record requires.
//!
//! # The private key stays off the Archive host
//!
//! Nothing outside tests holds a private key: the Archive asks a
//! [`super::signing::HeadSigner`] run by the operator on another host or in
//! a key service. The only signer Karyos ships is the test signer of the
//! tests, whose heads carry [`Custody::NoSeparation`].

use ed25519_dalek::{Signature, VerifyingKey};

use super::journal::{IntegrityError, IntegrityJournal};
use super::ledger::Ledger;
use super::{DIGEST_LENGTH, Digest, digest};
use crate::disk::Disk;

/// The length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// The format version of the signed head bytes and of the registry entry.
pub const TRUST_VERSION: u16 = 1;

/// The domain tag of a chain head's signed bytes: the archival head
/// purpose, separate from every wire key's.
pub const HEAD_DOMAIN: &[u8] = b"karyos/archive/signed-head/v1\0";

/// The domain tag of a registry entry's endorsement by the authority.
pub const ENDORSEMENT_DOMAIN: &[u8] = b"karyos/archive/key-endorsement/v1\0";

/// The encoded length of a signed head, in bytes.
pub const SIGNED_HEAD_LENGTH: usize = 184;

/// The encoded length of a key registry entry, in bytes.
pub const REGISTRY_ENTRY_LENGTH: usize = 184;

/// The length of a registry entry's bytes before its endorsement.
const ENDORSED_LENGTH: usize = REGISTRY_ENTRY_LENGTH - SIGNATURE_LENGTH;

/// A signature algorithm. The values are stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Algorithm {
    /// Ed25519 (RFC 8032), verified strictly.
    Ed25519 = 1,
}

/// How the custody of a signing key is known. The values are stable on
/// disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Custody {
    /// The operator declares the key is held off the Archive host.
    Declared = 1,
    /// Custody off the Archive host is evidenced externally.
    ExternallyEvidenced = 2,
    /// The key is on the Archive host: a test signer. Never custody.
    NoSeparation = 3,
}

impl Custody {
    /// The custody of an on-disk value.
    #[must_use]
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Declared,
            2 => Self::ExternallyEvidenced,
            3 => Self::NoSeparation,
            _ => return None,
        })
    }

    /// Whether the label claims the key is held apart from the Archive
    /// host. [`Custody::NoSeparation`] never does.
    #[must_use]
    #[inline]
    pub const fn is_separated(self) -> bool {
        !matches!(self, Self::NoSeparation)
    }

    /// The weaker of two labels: a head is only as separated as both its
    /// signer's label and its key's registration say.
    #[must_use]
    #[inline]
    pub const fn weaker(self, other: Self) -> Self {
        match (self, other) {
            (Self::NoSeparation, _) | (_, Self::NoSeparation) => Self::NoSeparation,
            (Self::Declared, _) | (_, Self::Declared) => Self::Declared,
            (Self::ExternallyEvidenced, Self::ExternallyEvidenced) => Self::ExternallyEvidenced,
        }
    }
}

/// The key id of a public key: its SHA-256.
#[must_use]
pub fn key_id(public: &[u8; PUBLIC_KEY_LENGTH]) -> Digest {
    digest(public)
}

/// What a verifier is given outside the export: the Archive's identity
/// and the public keys of the archival root or key authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    /// The Archive's identity.
    pub archive_id: Digest,
    /// The authority's public keys.
    pub authorities: Vec<[u8; PUBLIC_KEY_LENGTH]>,
}

impl TrustRoot {
    /// Whether one of the authority keys signed `message`.
    fn endorses(&self, message: &[u8], signature: &[u8; SIGNATURE_LENGTH]) -> bool {
        let signature = Signature::from_bytes(signature);
        self.authorities.iter().any(|public| {
            VerifyingKey::from_bytes(public)
                .is_ok_and(|key| key.verify_strict(message, &signature).is_ok())
        })
    }
}

/// The head of a chain, as it is signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainHead {
    /// The Archive's identity.
    pub archive_id: Digest,
    /// The journal's identity within the Archive.
    pub journal_id: u64,
    /// The counter of the head record.
    pub counter: u64,
    /// The record digest of the head record.
    pub digest: Digest,
}

/// The length of a head's signed bytes, after the domain tag.
const HEAD_FIELDS_LENGTH: usize = 2 + 1 + DIGEST_LENGTH + 8 + 8 + DIGEST_LENGTH;

/// The length of a head's signed bytes.
const HEAD_BYTES_LENGTH: usize = HEAD_DOMAIN.len() + HEAD_FIELDS_LENGTH;

/// The length of a registry entry's endorsement bytes.
const ENDORSEMENT_BYTES_LENGTH: usize = ENDORSEMENT_DOMAIN.len() + DIGEST_LENGTH + ENDORSED_LENGTH;

impl ChainHead {
    /// The canonical signed bytes, version 1, under the custody the signer
    /// declares: the archival head domain tag, then the version `u16`, the
    /// custody code `u8`, the Archive id, the journal id `u64`, the counter
    /// `u64` and the record digest, little-endian. The custody is signed so
    /// that a head's declared custody cannot be changed after signing.
    #[must_use]
    pub fn signed_bytes(&self, custody: Custody) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEAD_BYTES_LENGTH);
        bytes.extend_from_slice(HEAD_DOMAIN);
        bytes.extend_from_slice(&TRUST_VERSION.to_le_bytes());
        bytes.push(custody as u8);
        bytes.extend_from_slice(&self.archive_id);
        bytes.extend_from_slice(&self.journal_id.to_le_bytes());
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes
    }
}

/// A chain head with its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedHead {
    /// The head.
    pub head: ChainHead,
    /// The signing key's id.
    pub key_id: Digest,
    /// The custody the signer declared, covered by the signature.
    pub custody: Custody,
    /// The Ed25519 signature over the head's signed bytes under `custody`.
    pub signature: [u8; SIGNATURE_LENGTH],
}

/// Why trust evidence could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TrustDecodeError {
    /// A version this code does not read.
    #[error("trust record version {version} is not supported")]
    Version {
        /// The version.
        version: u16,
    },
    /// An unknown custody, algorithm or action code.
    #[error("trust record field {field} has unknown value {value}")]
    Unknown {
        /// The field.
        field: &'static str,
        /// The value.
        value: u8,
    },
    /// A reserved field is not zero.
    #[error("a trust record's reserved field is not zero")]
    Reserved,
}

/// Fixed-offset writer over an array.
struct Put<'a>(&'a mut [u8]);

impl Put<'_> {
    fn bytes<const N: usize>(&mut self, value: [u8; N]) {
        let rest = core::mem::take(&mut self.0);
        if let Some((head, rest)) = rest.split_first_chunk_mut::<N>() {
            *head = value;
            self.0 = rest;
        }
    }
}

/// Fixed-offset reader over an array whose length the caller fixed.
struct Take<'a>(&'a [u8]);

impl Take<'_> {
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        match self.0.split_first_chunk::<N>() {
            Some((head, rest)) => {
                self.0 = rest;
                *head
            }
            None => [0; N],
        }
    }
    fn u8(&mut self) -> u8 {
        let [value] = self.bytes::<1>();
        value
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.bytes())
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.bytes())
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.bytes())
    }
}

const _: () = {
    // version, custody, reserved, archive, journal, counter, digest, key,
    // signature.
    assert!(2 + 1 + 1 + 4 + 32 + 8 + 8 + 32 + 32 + 64 == SIGNED_HEAD_LENGTH);
    // version, action, algorithm, custody, reserved, sequence, key, public,
    // effective, evidence, endorsement.
    assert!(2 + 1 + 1 + 1 + 3 + 8 + 32 + 32 + 8 + 32 + 64 == REGISTRY_ENTRY_LENGTH);
};

impl SignedHead {
    /// The encoded signed head, version 1, little-endian at fixed offsets.
    #[must_use]
    pub fn encode(&self) -> [u8; SIGNED_HEAD_LENGTH] {
        let mut out = [0u8; SIGNED_HEAD_LENGTH];
        let mut put = Put(&mut out);
        put.bytes(TRUST_VERSION.to_le_bytes());
        put.bytes([self.custody as u8, 0]);
        put.bytes(0u32.to_le_bytes());
        put.bytes(self.head.archive_id);
        put.bytes(self.head.journal_id.to_le_bytes());
        put.bytes(self.head.counter.to_le_bytes());
        put.bytes(self.head.digest);
        put.bytes(self.key_id);
        put.bytes(self.signature);
        out
    }

    /// Reads an encoded signed head.
    ///
    /// # Errors
    ///
    /// [`TrustDecodeError`] for an unknown version or custody, or a
    /// reserved field that is not zero.
    pub fn decode(bytes: &[u8; SIGNED_HEAD_LENGTH]) -> Result<Self, TrustDecodeError> {
        let mut take = Take(bytes);
        let version = take.u16();
        if version != TRUST_VERSION {
            return Err(TrustDecodeError::Version { version });
        }
        let custody = take.u8();
        let custody = Custody::from_u8(custody).ok_or(TrustDecodeError::Unknown {
            field: "custody",
            value: custody,
        })?;
        if take.u8() != 0 || take.u32() != 0 {
            return Err(TrustDecodeError::Reserved);
        }
        let head = ChainHead {
            archive_id: take.bytes(),
            journal_id: take.u64(),
            counter: take.u64(),
            digest: take.bytes(),
        };
        Ok(Self {
            head,
            key_id: take.bytes(),
            custody,
            signature: take.bytes(),
        })
    }
}

/// What a registry entry does. The values are stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum RegistryAction {
    /// Registers a key, valid for heads from `effective` on.
    Register = 1,
    /// Retires a key: no head from `effective` on may use it.
    Retire = 2,
    /// Revokes a key from the cutoff `effective`, backed by independent
    /// evidence.
    Revoke = 3,
}

/// One entry of the key registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryEntry {
    /// What it does.
    pub action: RegistryAction,
    /// The algorithm of the key.
    pub algorithm: Algorithm,
    /// The custody class of the key.
    pub custody: Custody,
    /// The entry's sequence in the registry: 0, then one more each time.
    pub sequence: u64,
    /// The key id.
    pub key_id: Digest,
    /// The public key; zero for a retirement or a revocation.
    pub public: [u8; PUBLIC_KEY_LENGTH],
    /// The chain counter from which the entry takes effect.
    pub effective: u64,
    /// For a revocation, the digest of the independent evidence of its
    /// cutoff (an anchor or an operator record); zero otherwise.
    pub evidence: Digest,
    /// The authority's signature over the endorsement bytes.
    pub endorsement: [u8; SIGNATURE_LENGTH],
}

impl RegistryEntry {
    fn fields(&self) -> [u8; ENDORSED_LENGTH] {
        let mut out = [0u8; ENDORSED_LENGTH];
        let mut put = Put(&mut out);
        put.bytes(TRUST_VERSION.to_le_bytes());
        put.bytes([
            self.action as u8,
            self.algorithm as u8,
            self.custody as u8,
            0,
            0,
            0,
        ]);
        put.bytes(self.sequence.to_le_bytes());
        put.bytes(self.key_id);
        put.bytes(self.public);
        put.bytes(self.effective.to_le_bytes());
        put.bytes(self.evidence);
        out
    }

    /// The bytes the authority signs: the endorsement domain tag, the
    /// Archive id, then the entry's fields.
    #[must_use]
    pub fn endorsement_bytes(&self, archive_id: &Digest) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENDORSEMENT_BYTES_LENGTH);
        bytes.extend_from_slice(ENDORSEMENT_DOMAIN);
        bytes.extend_from_slice(archive_id);
        bytes.extend_from_slice(&self.fields());
        bytes
    }

    /// The encoded entry, version 1, little-endian at fixed offsets; its
    /// SHA-256 is what the integrity journal chains.
    #[must_use]
    pub fn encode(&self) -> [u8; REGISTRY_ENTRY_LENGTH] {
        let mut out = [0u8; REGISTRY_ENTRY_LENGTH];
        let mut put = Put(&mut out);
        put.bytes(self.fields());
        put.bytes(self.endorsement);
        out
    }

    /// Reads an encoded entry.
    ///
    /// # Errors
    ///
    /// [`TrustDecodeError`] for an unknown version, action, algorithm or
    /// custody, or a reserved field that is not zero.
    pub fn decode(bytes: &[u8; REGISTRY_ENTRY_LENGTH]) -> Result<Self, TrustDecodeError> {
        let mut take = Take(bytes);
        let version = take.u16();
        if version != TRUST_VERSION {
            return Err(TrustDecodeError::Version { version });
        }
        let unknown = |field, value| TrustDecodeError::Unknown { field, value };
        let action = match take.u8() {
            1 => RegistryAction::Register,
            2 => RegistryAction::Retire,
            3 => RegistryAction::Revoke,
            value => return Err(unknown("action", value)),
        };
        let algorithm = match take.u8() {
            1 => Algorithm::Ed25519,
            value => return Err(unknown("algorithm", value)),
        };
        let custody = take.u8();
        let custody = Custody::from_u8(custody).ok_or(unknown("custody", custody))?;
        if take.bytes::<3>() != [0; 3] {
            return Err(TrustDecodeError::Reserved);
        }
        Ok(Self {
            action,
            algorithm,
            custody,
            sequence: take.u64(),
            key_id: take.bytes(),
            public: take.bytes(),
            effective: take.u64(),
            evidence: take.bytes(),
            endorsement: take.bytes(),
        })
    }
}

/// Why a registry entry was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// The authority did not endorse the entry.
    #[error("registry entry {sequence} is not endorsed by the trust root")]
    NotEndorsed {
        /// The entry's sequence.
        sequence: u64,
    },
    /// The entry's sequence does not follow the registry's.
    #[error("registry entry {found} where {expected} was expected")]
    Sequence {
        /// The sequence expected.
        expected: u64,
        /// The sequence found.
        found: u64,
    },
    /// A registration whose key id is not the SHA-256 of its public key,
    /// or whose public key is not a valid Ed25519 key.
    #[error("registry entry {sequence} registers an invalid key")]
    InvalidKey {
        /// The entry's sequence.
        sequence: u64,
    },
    /// A key registered twice.
    #[error("registry entry {sequence} registers a key already registered")]
    Duplicate {
        /// The entry's sequence.
        sequence: u64,
    },
    /// A retirement or revocation of a key never registered.
    #[error("registry entry {sequence} names an unregistered key")]
    UnknownKey {
        /// The entry's sequence.
        sequence: u64,
    },
    /// A revocation without independent evidence of its cutoff.
    #[error("registry entry {sequence} revokes without evidence")]
    NoEvidence {
        /// The entry's sequence.
        sequence: u64,
    },
    /// An entry that would take effect before the chain position it is
    /// recorded at: a key must be registered before its first use, and
    /// no entry is backdated.
    #[error("registry entry {sequence} takes effect at {effective}, before chain record {next}")]
    Backdated {
        /// The entry's sequence.
        sequence: u64,
        /// Its effective counter.
        effective: u64,
        /// The chain's next counter.
        next: u64,
    },
    /// The integrity journal chains a registry entry whose bytes are not
    /// in the registry's ledger, or differ from them.
    #[error("registry entry {sequence} is chained but missing from the ledger")]
    Missing {
        /// The entry's sequence.
        sequence: u64,
    },
    /// A ledger entry that cannot be decoded although the journal chains
    /// it.
    #[error("registry entry at ledger index {index} cannot be decoded")]
    Malformed {
        /// The entry's index in the ledger.
        index: u64,
    },
    /// The registry appending is not the state the journal last committed:
    /// another handle appended since, or this one is behind.
    #[error("registry entry {sequence} appended from a stale registry")]
    Stale {
        /// The entry's sequence.
        sequence: u64,
    },
    /// The sequence space is exhausted.
    #[error("registry sequence overflow")]
    Overflow,
}

/// The state of one registered key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyState {
    /// The public key.
    pub public: [u8; PUBLIC_KEY_LENGTH],
    /// Its algorithm.
    pub algorithm: Algorithm,
    /// Its custody class.
    pub custody: Custody,
    /// The first counter it may sign.
    pub valid_from: u64,
    /// The counter from which it is retired.
    pub retired_from: Option<u64>,
    /// The revocation cutoff and the digest of its evidence.
    pub revoked_from: Option<(u64, Digest)>,
}

/// The key registry, rebuilt from its entries under a trust root.
#[derive(Debug, Clone)]
pub struct KeyRegistry {
    trust: TrustRoot,
    next_sequence: u64,
    /// A digest of every entry applied, in order: equal only for the same
    /// registry contents.
    identity: Digest,
    keys: std::collections::BTreeMap<Digest, KeyState>,
}

impl KeyRegistry {
    /// An empty registry under `trust`.
    #[must_use]
    pub const fn new(trust: TrustRoot) -> Self {
        Self {
            trust,
            next_sequence: 0,
            identity: EMPTY_REGISTRY,
            keys: std::collections::BTreeMap::new(),
        }
    }

    /// Rebuilds the registry under `trust` from the entries the integrity
    /// journal chains, in chain order, reading their bytes from `ledger`.
    ///
    /// A ledger entry is part of the registry only once its digest is
    /// chained as a key registry record: an entry written before a crash
    /// or a failed journal append that never committed is skipped, and an
    /// unchained suffix is cut from the ledger before anything else is
    /// appended (SPEC.md §8.4, "Key registry": every update has journal
    /// provenance).
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Registry`] with [`RegistryError::Missing`] when
    /// the journal chains an entry the ledger does not hold,
    /// [`IntegrityError::Poisoned`] for a journal handle an earlier append
    /// poisoned, [`IntegrityError::ForeignLedger`] for a ledger of another
    /// archive directory and [`IntegrityError::StaleJournal`] for a view
    /// behind the file, before anything is read or cut;
    /// [`RegistryError::Malformed`] when a chained entry cannot be read,
    /// [`RegistryError::Backdated`] for a registration effective before
    /// the chain record that registers it, as on append, or the refusal
    /// of [`KeyRegistry::apply`] for a chained entry;
    /// otherwise the journal's or the ledger's error.
    pub fn open<D: Disk>(
        trust: TrustRoot,
        journal: &mut IntegrityJournal<D>,
        ledger: &mut Ledger<D, REGISTRY_ENTRY_LENGTH>,
    ) -> Result<Self, IntegrityError> {
        // A poisoned handle reads only the records it knows of: a record
        // whose sync failed may still be on disk, and its ledger entry
        // must not be cut. Reopen the journal first.
        if journal.is_poisoned() {
            return Err(IntegrityError::Poisoned);
        }
        // Only the journal's own ledger: another journal's evidence would be
        // cut as orphans.
        if ledger.dir() != journal.dir() {
            return Err(IntegrityError::ForeignLedger);
        }
        // A view behind the file would cut a committed entry as an orphan.
        if !journal.is_current()? {
            return Err(IntegrityError::StaleJournal);
        }
        let chained: Vec<(u64, u64, Digest)> = journal
            .records()?
            .into_iter()
            .filter(|record| record.kind == super::SealKind::KeyRegistry)
            .map(|record| (record.counter, record.start, record.content))
            .collect();
        let mut registry = Self::new(trust);
        let mut next = chained.iter().peekable();
        let mut committed = 0usize;
        for (index, bytes) in ledger.entries().iter().enumerate() {
            let Some(&&(counter, sequence, content)) = next.peek() else {
                break;
            };
            if digest(bytes) != content {
                // Written, never chained: an append that did not commit.
                continue;
            }
            let entry = RegistryEntry::decode(bytes).map_err(|_| RegistryError::Malformed {
                index: u64::try_from(index).unwrap_or(u64::MAX),
            })?;
            if entry.sequence != sequence {
                return Err(RegistryError::Missing { sequence }.into());
            }
            check_timing(&entry, counter)?;
            registry.apply(&entry)?;
            let _ = next.next();
            committed = index.saturating_add(1);
        }
        if let Some(&(_, sequence, _)) = next.next() {
            return Err(RegistryError::Missing { sequence }.into());
        }
        ledger.truncate(committed)?;
        Ok(registry)
    }

    /// The trust root.
    #[must_use]
    #[inline]
    pub const fn trust(&self) -> &TrustRoot {
        &self.trust
    }

    /// A digest of the registry's contents: every entry applied, in order.
    /// Two registries with the same identity hold the same entries.
    #[must_use]
    #[inline]
    pub const fn identity(&self) -> Digest {
        self.identity
    }

    /// The sequence the next entry must carry.
    #[must_use]
    #[inline]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// A key's state.
    #[must_use]
    pub fn key(&self, key_id: &Digest) -> Option<&KeyState> {
        self.keys.get(key_id)
    }

    /// Applies the next entry.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] for an entry the authority did not endorse, out
    /// of sequence, registering an invalid or duplicate key, naming an
    /// unknown key, or revoking without evidence. Nothing changes on an
    /// error.
    pub fn apply(&mut self, entry: &RegistryEntry) -> Result<(), RegistryError> {
        let sequence = entry.sequence;
        if sequence != self.next_sequence {
            return Err(RegistryError::Sequence {
                expected: self.next_sequence,
                found: sequence,
            });
        }
        if !self.trust.endorses(
            &entry.endorsement_bytes(&self.trust.archive_id),
            &entry.endorsement,
        ) {
            return Err(RegistryError::NotEndorsed { sequence });
        }
        let next = sequence.checked_add(1).ok_or(RegistryError::Overflow)?;
        match entry.action {
            RegistryAction::Register => {
                if key_id(&entry.public) != entry.key_id
                    || VerifyingKey::from_bytes(&entry.public).is_err()
                {
                    return Err(RegistryError::InvalidKey { sequence });
                }
                if self.keys.contains_key(&entry.key_id) {
                    return Err(RegistryError::Duplicate { sequence });
                }
                self.keys.insert(
                    entry.key_id,
                    KeyState {
                        public: entry.public,
                        algorithm: entry.algorithm,
                        custody: entry.custody,
                        valid_from: entry.effective,
                        retired_from: None,
                        revoked_from: None,
                    },
                );
            }
            RegistryAction::Retire => {
                let state = self
                    .keys
                    .get_mut(&entry.key_id)
                    .ok_or(RegistryError::UnknownKey { sequence })?;
                // A later entry never relaxes an earlier restriction.
                state.retired_from = Some(
                    state
                        .retired_from
                        .map_or(entry.effective, |retired| retired.min(entry.effective)),
                );
            }
            RegistryAction::Revoke => {
                if entry.evidence == [0; DIGEST_LENGTH] {
                    return Err(RegistryError::NoEvidence { sequence });
                }
                let state = self
                    .keys
                    .get_mut(&entry.key_id)
                    .ok_or(RegistryError::UnknownKey { sequence })?;
                // The earliest evidenced cutoff stands, with its evidence:
                // a later revocation never makes a head valid again.
                state.revoked_from = Some(match state.revoked_from {
                    Some((cutoff, evidence)) if cutoff <= entry.effective => (cutoff, evidence),
                    _ => (entry.effective, entry.evidence),
                });
            }
        }
        self.next_sequence = next;
        self.identity = extend_identity(&self.identity, &digest(&entry.encode()));
        Ok(())
    }

    /// Applies `entry` and records it: its bytes in `ledger`, its digest
    /// chained in `journal` as a key registry record. The entry may not
    /// take effect before the chain record that registers it.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Registry`] for an entry [`KeyRegistry::apply`]
    /// refuses or one that is backdated, with nothing written; otherwise
    /// the ledger's or the journal's error.
    pub fn append<D: Disk>(
        &mut self,
        entry: &RegistryEntry,
        journal: &mut IntegrityJournal<D>,
        ledger: &mut Ledger<D, REGISTRY_ENTRY_LENGTH>,
    ) -> Result<(), IntegrityError> {
        // Nothing is written to the ledger for a journal that cannot chain
        // it: its record count is unknown until it is reopened.
        if journal.is_poisoned() {
            return Err(IntegrityError::Poisoned);
        }
        if ledger.dir() != journal.dir() {
            return Err(IntegrityError::ForeignLedger);
        }
        // Compare and swap on the whole history: only a registry that
        // applied exactly the entries the journal chains, in order, may
        // append, so a stale or divergent handle cannot commit.
        if journal.key_registry_identity() != self.identity {
            return Err(RegistryError::Stale {
                sequence: entry.sequence,
            }
            .into());
        }
        check_timing(entry, journal.next_counter())?;
        let mut applied = self.clone();
        applied.apply(entry)?;
        let bytes = entry.encode();
        ledger.append(bytes)?;
        journal.record_key_registry(&entry.key_id, entry.sequence, &bytes)?;
        *self = applied;
        Ok(())
    }

    /// Whether `key_id` may be dropped from the registry: never while one
    /// of `retained` (the signed heads still kept) was signed with it.
    #[must_use]
    pub fn may_drop<'a>(
        &self,
        key_id: &Digest,
        retained: impl IntoIterator<Item = &'a SignedHead>,
    ) -> bool {
        !retained.into_iter().any(|head| &head.key_id == key_id)
    }

    /// Verifies `signed` under this registry and its trust root.
    /// `pre_revocation_anchor` is the counter covered by an anchor proved
    /// to predate the key's revocation, if the caller has one (karyos#664).
    #[must_use]
    pub fn verify(&self, signed: &SignedHead, pre_revocation_anchor: Option<u64>) -> HeadVerdict {
        use HeadReason as R;
        let head = &signed.head;
        if head.archive_id != self.trust.archive_id {
            return HeadVerdict::Invalid(R::WrongArchive);
        }
        let Some(state) = self.keys.get(&signed.key_id) else {
            return HeadVerdict::Invalid(R::UnknownKey);
        };
        if head.counter < state.valid_from {
            return HeadVerdict::Invalid(R::KeyNotYetValid);
        }
        let valid_signature = VerifyingKey::from_bytes(&state.public).is_ok_and(|key| {
            key.verify_strict(
                &head.signed_bytes(signed.custody),
                &Signature::from_bytes(&signed.signature),
            )
            .is_ok()
        });
        if !valid_signature {
            return HeadVerdict::Invalid(R::BadSignature);
        }
        if state
            .retired_from
            .is_some_and(|retired| head.counter >= retired)
        {
            return HeadVerdict::Invalid(R::KeyRetired);
        }
        let custody = state.custody.weaker(signed.custody);
        if let Some((cutoff, _)) = state.revoked_from {
            if head.counter >= cutoff {
                return HeadVerdict::Invalid(R::SignedAfterRevocation);
            }
            let proved = pre_revocation_anchor.is_some_and(|anchored| anchored >= head.counter);
            if !proved {
                return HeadVerdict::NotTrustedEvidence(R::NoPreRevocationAnchor);
            }
        }
        HeadVerdict::Trusted { custody }
    }
}

/// The identity of a registry with no entries.
pub const EMPTY_REGISTRY: Digest = [0; DIGEST_LENGTH];

/// The identity of a registry history `identity` extended by the entry
/// whose canonical bytes have digest `entry_digest`: the SHA-256 of both.
#[must_use]
pub fn extend_identity(identity: &Digest, entry_digest: &Digest) -> Digest {
    let mut chained = [0u8; 2 * DIGEST_LENGTH];
    let (left, right) = chained.split_at_mut(DIGEST_LENGTH);
    left.copy_from_slice(identity);
    right.copy_from_slice(entry_digest);
    digest(&chained)
}

/// Refuses `entry` if it would take effect before `counter`, the chain
/// position of the record that registers it: a key is registered before
/// its first use. A revocation's cutoff is the independently evidenced
/// compromise point, which is often discovered after the records it
/// affects, and a retirement only narrows the key's validity, so neither
/// is refused as backdated. The same check applies on append and on
/// replay.
fn check_timing(entry: &RegistryEntry, counter: u64) -> Result<(), RegistryError> {
    if entry.action == RegistryAction::Register && entry.effective < counter {
        return Err(RegistryError::Backdated {
            sequence: entry.sequence,
            effective: entry.effective,
            next: counter,
        });
    }
    Ok(())
}

/// Why a head is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HeadReason {
    /// The head names another Archive.
    WrongArchive,
    /// The key is not in the registry.
    UnknownKey,
    /// The head precedes the key's registration: used before registered.
    KeyNotYetValid,
    /// The signature does not verify over the head's signed bytes.
    BadSignature,
    /// The key was retired before the head.
    KeyRetired,
    /// The head is at or past the key's revocation cutoff.
    SignedAfterRevocation,
    /// The head precedes the revocation, but no anchor proves it was
    /// signed before.
    NoPreRevocationAnchor,
}

/// A head's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeadVerdict {
    /// Trusted evidence, with the custody label to report. A label of
    /// [`Custody::NoSeparation`] is reported as "no custody separation".
    Trusted {
        /// The custody of the head.
        custody: Custody,
    },
    /// Not invalid, but not trusted evidence either.
    NotTrustedEvidence(HeadReason),
    /// Invalid.
    Invalid(HeadReason),
}
