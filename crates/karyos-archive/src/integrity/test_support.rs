// SPDX-License-Identifier: Apache-2.0

//! Test helpers shared by the integrity tests after karyos#663: a chain
//! with signed heads under a registry the test authority endorsed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};

use super::journal::IntegrityJournal;
use super::trust::{
    Algorithm, ChainHead, Custody, KeyRegistry, RegistryAction, RegistryEntry, SignedHead,
    TrustRoot, key_id,
};
use super::{Digest, SealRecord};
use crate::fault::FaultDisk;

pub(crate) const DIR: &str = "/archive";
pub(crate) const ARCHIVE: Digest = [7; 32];
pub(crate) const JOURNAL: u64 = 1;

pub(crate) fn authority() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

pub(crate) fn archival_key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

pub(crate) fn trust() -> TrustRoot {
    TrustRoot {
        archive_id: ARCHIVE,
        authorities: vec![authority().verifying_key().to_bytes()],
    }
}

/// A registry with the archival key registered from counter 0.
pub(crate) fn registry() -> KeyRegistry {
    let key = archival_key();
    let mut entry = RegistryEntry {
        action: RegistryAction::Register,
        algorithm: Algorithm::Ed25519,
        custody: Custody::Declared,
        sequence: 0,
        key_id: key_id(&key.verifying_key().to_bytes()),
        public: key.verifying_key().to_bytes(),
        effective: 0,
        evidence: [0; 32],
        endorsement: [0; 64],
    };
    entry.endorsement = authority()
        .sign(&entry.endorsement_bytes(&ARCHIVE))
        .to_bytes();
    let mut registry = KeyRegistry::new(trust());
    registry.apply(&entry).unwrap();
    registry
}

/// Signs the head at `record` with the archival key.
pub(crate) fn sign(record: &SealRecord) -> SignedHead {
    let head = ChainHead {
        archive_id: ARCHIVE,
        journal_id: JOURNAL,
        counter: record.counter,
        digest: record.digest(),
    };
    let key = archival_key();
    SignedHead {
        head,
        key_id: key_id(&key.verifying_key().to_bytes()),
        custody: Custody::NoSeparation,
        signature: key
            .sign(&head.signed_bytes(Custody::NoSeparation))
            .to_bytes(),
    }
}

/// A journal of `count` sealed ranges of recording 3, and its records.
pub(crate) fn chain(count: u64) -> (IntegrityJournal<FaultDisk>, Vec<SealRecord>) {
    let mut journal = IntegrityJournal::open(FaultDisk::default(), Path::new(DIR))
        .unwrap()
        .journal;
    for index in 0..count {
        let bytes = index.to_le_bytes();
        journal.seal_segment(3, index * 8, &bytes, false).unwrap();
    }
    let records = journal.records().unwrap();
    (journal, records)
}
