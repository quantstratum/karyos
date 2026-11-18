// SPDX-License-Identifier: Apache-2.0

//! Tests of the trust bootstrap, the key registry, signed heads and the
//! signing backlog (karyos#663). The only signer here is the test signer,
//! on this host, so every key it registers is labelled
//! [`Custody::NoSeparation`] unless a test says otherwise on purpose.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::num::{NonZeroU64, NonZeroUsize};
use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use proptest::prelude::*;

use super::journal::{IntegrityError, IntegrityJournal};
use super::ledger::Ledger;
use super::sealer::{SealSource, Sealer, run};
use super::signing::{
    BacklogPolicy, HeadSigner, HeadSigning, HeadStore, Offered, PollError, SignerUnavailable,
    SigningConfig, SigningConfigError,
};
use super::trust::*;
use super::{Digest, digest};
use crate::fault::{FaultDisk, Survives};

const DIR: &str = "/archive";
const ARCHIVE: Digest = [7; 32];
const JOURNAL: u64 = 1;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> [u8; PUBLIC_KEY_LENGTH] {
    key.verifying_key().to_bytes()
}

/// The authority, held outside the Archive.
fn authority() -> SigningKey {
    key(1)
}

fn trust() -> TrustRoot {
    TrustRoot {
        archive_id: ARCHIVE,
        authorities: vec![public(&authority())],
    }
}

/// A signer on this host, for tests only.
struct TestSigner {
    key: SigningKey,
    custody: Custody,
    available: bool,
}

impl TestSigner {
    fn new(seed: u8) -> Self {
        Self {
            key: key(seed),
            custody: Custody::NoSeparation,
            available: true,
        }
    }
}

impl HeadSigner for TestSigner {
    fn key_id(&self) -> Digest {
        key_id(&public(&self.key))
    }
    fn custody(&self) -> Custody {
        self.custody
    }
    fn sign(&mut self, head: &ChainHead) -> Result<[u8; SIGNATURE_LENGTH], SignerUnavailable> {
        if !self.available {
            return Err(SignerUnavailable);
        }
        Ok(self.key.sign(&head.signed_bytes(self.custody)).to_bytes())
    }
}

/// An entry endorsed by `by`.
fn entry(
    by: &SigningKey,
    sequence: u64,
    action: RegistryAction,
    of: &SigningKey,
    custody: Custody,
    effective: u64,
    evidence: Digest,
) -> RegistryEntry {
    let mut entry = RegistryEntry {
        action,
        algorithm: Algorithm::Ed25519,
        custody,
        sequence,
        key_id: key_id(&public(of)),
        public: if action == RegistryAction::Register {
            public(of)
        } else {
            [0; 32]
        },
        effective,
        evidence,
        endorsement: [0; 64],
    };
    entry.endorsement = by.sign(&entry.endorsement_bytes(&ARCHIVE)).to_bytes();
    entry
}

fn register(of: &SigningKey, custody: Custody, effective: u64) -> RegistryEntry {
    entry(
        &authority(),
        0,
        RegistryAction::Register,
        of,
        custody,
        effective,
        [0; 32],
    )
}

/// A chain of 128 seals of recording 3, the same every time.
fn seals() -> Vec<super::SealRecord> {
    let mut journal = IntegrityJournal::open(FaultDisk::default(), Path::new(DIR))
        .unwrap()
        .journal;
    for index in 0..128u64 {
        journal.seal_segment(3, index * 4, b"seal", false).unwrap();
    }
    journal.records().unwrap()
}

/// The head of [`seals`] at `counter`.
fn head(counter: u64) -> ChainHead {
    ChainHead {
        archive_id: ARCHIVE,
        journal_id: JOURNAL,
        counter,
        digest: seals()[usize::try_from(counter).unwrap()].digest(),
    }
}

fn signed(signer: &mut TestSigner, head: ChainHead) -> SignedHead {
    SignedHead {
        head,
        key_id: signer.key_id(),
        custody: signer.custody(),
        signature: signer.sign(&head).unwrap(),
    }
}

/// A registry with the test signer's key registered from counter 0.
/// A store of signed heads in memory, which can be made to fail.
#[derive(Default)]
struct Store {
    heads: Vec<SignedHead>,
    failing: bool,
}

impl HeadStore for Store {
    fn record(&mut self, signed: &SignedHead) -> Result<(), IntegrityError> {
        if self.failing {
            return Err(IntegrityError::Poisoned);
        }
        self.heads.push(*signed);
        Ok(())
    }
}

fn registry_with(signer: &TestSigner) -> KeyRegistry {
    let mut registry = KeyRegistry::new(trust());
    registry
        .apply(&register(&signer.key, Custody::NoSeparation, 0))
        .unwrap();
    registry
}

#[test]
fn the_signed_bytes_are_canonical_and_versioned() {
    let bytes = head(5).signed_bytes(Custody::NoSeparation);
    assert!(bytes.starts_with(HEAD_DOMAIN));
    let fields = &bytes[HEAD_DOMAIN.len()..];
    assert_eq!(&fields[..2], &TRUST_VERSION.to_le_bytes());
    assert_eq!(fields[2], Custody::NoSeparation as u8);
    assert_eq!(&fields[3..35], &ARCHIVE);
    assert_eq!(&fields[35..43], &JOURNAL.to_le_bytes());
    assert_eq!(&fields[43..51], &5u64.to_le_bytes());
    assert_eq!(&fields[51..], &head(5).digest);
    assert_eq!(head(5).signed_bytes(Custody::NoSeparation), bytes);
    assert_ne!(head(5).signed_bytes(Custody::ExternallyEvidenced), bytes);
}

#[test]
fn a_signature_from_one_journal_or_archive_does_not_verify_as_another() {
    let mut signer = TestSigner::new(9);
    let registry = registry_with(&signer);
    let good = signed(&mut signer, head(3));
    assert!(matches!(
        registry.verify(&good, None),
        HeadVerdict::Trusted { .. }
    ));
    let mut other_journal = good;
    other_journal.head.journal_id = 2;
    assert_eq!(
        registry.verify(&other_journal, None),
        HeadVerdict::Invalid(HeadReason::BadSignature)
    );
    let mut other_archive = good;
    other_archive.head.archive_id = [8; 32];
    assert_eq!(
        registry.verify(&other_archive, None),
        HeadVerdict::Invalid(HeadReason::WrongArchive)
    );
    // A registry trusted for the other Archive refuses it as well.
    let mut elsewhere = KeyRegistry::new(TrustRoot {
        archive_id: [8; 32],
        ..trust()
    });
    assert!(
        elsewhere
            .apply(&register(&signer.key, Custody::NoSeparation, 0))
            .is_err()
    );
}

#[test]
fn a_registry_the_authority_did_not_endorse_establishes_no_trust() {
    let signer = TestSigner::new(9);
    let mut registry = KeyRegistry::new(trust());
    // Whoever controls the Archive host endorses its own key.
    let forged = entry(
        &signer.key,
        0,
        RegistryAction::Register,
        &signer.key,
        Custody::ExternallyEvidenced,
        0,
        [0; 32],
    );
    assert_eq!(
        registry.apply(&forged),
        Err(RegistryError::NotEndorsed { sequence: 0 })
    );
    assert_eq!(registry.key(&signer.key_id()), None);
}

#[test]
fn a_key_is_refused_if_used_before_it_is_registered() {
    let mut signer = TestSigner::new(9);
    let mut registry = KeyRegistry::new(trust());
    registry
        .apply(&register(&signer.key, Custody::NoSeparation, 10))
        .unwrap();
    assert_eq!(
        registry.verify(&signed(&mut signer, head(9)), None),
        HeadVerdict::Invalid(HeadReason::KeyNotYetValid)
    );
    assert!(matches!(
        registry.verify(&signed(&mut signer, head(10)), None),
        HeadVerdict::Trusted { .. }
    ));
    let mut unknown = TestSigner::new(10);
    assert_eq!(
        registry.verify(&signed(&mut unknown, head(11)), None),
        HeadVerdict::Invalid(HeadReason::UnknownKey)
    );
}

#[test]
fn a_registration_cannot_be_backdated_and_is_chained_in_the_journal() {
    let disk = FaultDisk::default();
    let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut ledger =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk, Path::new(DIR), "keys").unwrap();
    journal
        .seal_segment(3, 0, b"before the key", false)
        .unwrap();
    let signer = TestSigner::new(9);
    let mut registry = KeyRegistry::new(trust());
    let backdated = register(&signer.key, Custody::NoSeparation, 0);
    assert!(matches!(
        registry.append(&backdated, &mut journal, &mut ledger),
        Err(IntegrityError::Registry(RegistryError::Backdated {
            next: 1,
            ..
        }))
    ));
    assert!(ledger.entries().is_empty());
    let entry = register(&signer.key, Custody::NoSeparation, 1);
    registry.append(&entry, &mut journal, &mut ledger).unwrap();
    let record = journal.records().unwrap()[1];
    assert_eq!(record.kind, super::SealKind::KeyRegistry);
    assert_eq!(record.content, digest(&ledger.entries()[0]));
    assert_eq!(RegistryEntry::decode(&ledger.entries()[0]), Ok(entry));
}

#[test]
fn a_key_is_retained_while_a_signed_head_needs_it() {
    let mut signer = TestSigner::new(9);
    let registry = registry_with(&signer);
    let kept = [signed(&mut signer, head(4))];
    assert!(!registry.may_drop(&signer.key_id(), &kept));
    assert!(registry.may_drop(&signer.key_id(), &[]));
}

#[test]
fn a_test_signer_is_labelled_no_custody_separation_whatever_the_registry_says() {
    let mut signer = TestSigner::new(9);
    let mut registry = KeyRegistry::new(trust());
    // Even a registration that claims custody cannot lift the test label.
    registry
        .apply(&register(&signer.key, Custody::ExternallyEvidenced, 0))
        .unwrap();
    let verdict = registry.verify(&signed(&mut signer, head(1)), None);
    assert_eq!(
        verdict,
        HeadVerdict::Trusted {
            custody: Custody::NoSeparation
        }
    );
    assert!(!Custody::NoSeparation.is_separated());
    assert_eq!(
        Custody::Declared.weaker(Custody::ExternallyEvidenced),
        Custody::Declared
    );
}

#[test]
fn a_head_signed_after_revocation_is_invalid() {
    let mut signer = TestSigner::new(9);
    let mut registry = registry_with(&signer);
    let evidence = digest(b"anchor before the compromise");
    registry
        .apply(&entry(
            &authority(),
            1,
            RegistryAction::Revoke,
            &signer.key,
            Custody::NoSeparation,
            20,
            evidence,
        ))
        .unwrap();
    assert_eq!(
        registry.verify(&signed(&mut signer, head(20)), Some(30)),
        HeadVerdict::Invalid(HeadReason::SignedAfterRevocation)
    );
}

#[test]
fn a_pre_revocation_head_needs_a_proved_pre_revocation_anchor() {
    let mut signer = TestSigner::new(9);
    let mut registry = registry_with(&signer);
    registry
        .apply(&entry(
            &authority(),
            1,
            RegistryAction::Revoke,
            &signer.key,
            Custody::NoSeparation,
            20,
            digest(b"evidence"),
        ))
        .unwrap();
    let before = signed(&mut signer, head(12));
    // Not invalid, and not trusted evidence either.
    assert_eq!(
        registry.verify(&before, None),
        HeadVerdict::NotTrustedEvidence(HeadReason::NoPreRevocationAnchor)
    );
    assert_eq!(
        registry.verify(&before, Some(11)),
        HeadVerdict::NotTrustedEvidence(HeadReason::NoPreRevocationAnchor)
    );
    assert!(matches!(
        registry.verify(&before, Some(12)),
        HeadVerdict::Trusted { .. }
    ));
}

#[test]
fn a_revocation_without_independent_evidence_is_refused() {
    let signer = TestSigner::new(9);
    let mut registry = registry_with(&signer);
    let unproved = entry(
        &authority(),
        1,
        RegistryAction::Revoke,
        &signer.key,
        Custody::NoSeparation,
        20,
        [0; 32],
    );
    assert_eq!(
        registry.apply(&unproved),
        Err(RegistryError::NoEvidence { sequence: 1 })
    );
}

#[test]
fn a_retired_key_signs_nothing_from_its_retirement() {
    let mut signer = TestSigner::new(9);
    let mut registry = registry_with(&signer);
    registry
        .apply(&entry(
            &authority(),
            1,
            RegistryAction::Retire,
            &signer.key,
            Custody::NoSeparation,
            8,
            [0; 32],
        ))
        .unwrap();
    assert!(matches!(
        registry.verify(&signed(&mut signer, head(7)), None),
        HeadVerdict::Trusted { .. }
    ));
    assert_eq!(
        registry.verify(&signed(&mut signer, head(8)), None),
        HeadVerdict::Invalid(HeadReason::KeyRetired)
    );
}

#[test]
fn the_archival_key_signature_over_any_other_purpose_is_refused() {
    let signer = TestSigner::new(9);
    let registry = registry_with(&signer);
    // The same fields under another purpose's tag, as a wire key's would.
    let mut wire = b"karyos/wire/guard/v1\0".to_vec();
    wire.extend_from_slice(&head(2).signed_bytes(Custody::NoSeparation)[HEAD_DOMAIN.len()..]);
    let forged = SignedHead {
        head: head(2),
        key_id: signer.key_id(),
        custody: Custody::NoSeparation,
        signature: signer.key.sign(&wire).to_bytes(),
    };
    assert_eq!(
        registry.verify(&forged, None),
        HeadVerdict::Invalid(HeadReason::BadSignature)
    );
    // An endorsement signature is not a head signature either.
    let endorsement = register(&signer.key, Custody::NoSeparation, 0).endorsement;
    let reused = SignedHead {
        signature: endorsement,
        ..forged
    };
    assert_eq!(
        registry.verify(&reused, None),
        HeadVerdict::Invalid(HeadReason::BadSignature)
    );
}

#[test]
fn an_unconfigured_anchor_interval_is_refused() {
    assert_eq!(
        SigningConfig::new(None, BacklogPolicy::Coalesce),
        Err(SigningConfigError::AnchorIntervalUnset)
    );
    assert_eq!(
        SigningConfig::new(Some(0), BacklogPolicy::Coalesce),
        Err(SigningConfigError::AnchorIntervalZero)
    );
}

#[test]
fn a_passed_anchor_interval_raises_the_alarm() {
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signing = HeadSigning::new(config, JOURNAL, 0);
    let mut signer = TestSigner::new(9);
    let mut store = Store::default();
    assert_eq!(signing.offer(head(0), 0), Offered::Queued);
    assert!(
        !signing
            .status(1_000, 1, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    assert!(
        signing
            .status(1_001, 1, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    assert_eq!(
        signing
            .poll(
                &mut signer,
                &mut store,
                &registry_with(&TestSigner::new(9)),
                &seals(),
                1_001
            )
            .unwrap(),
        1
    );
    assert!(
        !signing
            .status(1_500, 1, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    // Nothing new sealed: no lag, no alarm, however long it is.
    assert!(
        !signing
            .status(9_000, 1, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    assert!(
        signing
            .status(9_000, 2, &registry_with(&TestSigner::new(9)))
            .alarm
    );
}

#[test]
fn during_a_signer_outage_sealing_continues_the_backlog_stays_bounded_and_the_lag_is_reported() {
    let mut journal = IntegrityJournal::open(FaultDisk::default(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut sealer = Sealer::new(NonZeroU64::new(100).unwrap());
    sealer.track(3, SealSource::Segments, 0).unwrap();
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signing = HeadSigning::new(config, JOURNAL, 0);
    let mut signer = TestSigner::new(9);
    let mut store = Store::default();
    signer.available = false;
    let bytes = vec![5u8; 64 * 50];
    for round in 1..=50u64 {
        let now = round * 100;
        sealer.written(3, round * 64, now - 100).unwrap();
        // The data path: sealing completes with the signer unavailable.
        let sealed = run(&mut sealer, &mut journal, now, |_, start, end| {
            Ok(bytes[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()].to_vec())
        })
        .unwrap();
        assert_eq!(sealed, 1);
        let counter = journal.next_counter() - 1;
        let _ = signing.offer(
            ChainHead {
                archive_id: ARCHIVE,
                journal_id: JOURNAL,
                counter,
                digest: journal.head(),
            },
            now,
        );
        assert_eq!(
            signing
                .poll(
                    &mut signer,
                    &mut store,
                    &registry_with(&TestSigner::new(9)),
                    &journal.records().unwrap(),
                    now
                )
                .unwrap(),
            0
        );
        let status = signing.status(
            now,
            journal.next_counter(),
            &registry_with(&TestSigner::new(9)),
        );
        assert!(status.pending <= 1, "round {round}");
        // Reported before the first signed head.
        assert_eq!(status.last_signed, None);
        assert_eq!(status.coverage_lag_records, round);
        // The oldest uncovered record was offered in the first round.
        assert_eq!(status.coverage_lag_ns, now - 100);
    }
    assert!(
        signing
            .status(5_000, 50, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    assert_eq!(
        signing
            .status(5_000, 50, &registry_with(&TestSigner::new(9)))
            .coalesced,
        49
    );
    signer.available = true;
    assert_eq!(
        signing
            .poll(
                &mut signer,
                &mut store,
                &registry_with(&TestSigner::new(9)),
                &journal.records().unwrap(),
                5_100
            )
            .unwrap(),
        1
    );
    assert_eq!(store.heads, signing.signed());
    let status = signing.status(
        5_100,
        journal.next_counter(),
        &registry_with(&TestSigner::new(9)),
    );
    assert_eq!((status.coverage_lag_records, status.alarm), (0, false));
    let registry = registry_with(&signer);
    assert!(matches!(
        registry.verify(&signing.signed()[0], None),
        HeadVerdict::Trusted { .. }
    ));
    assert_eq!(signing.signed()[0].head.digest, journal.head());
}

#[test]
fn a_refusing_backlog_refuses_visibly_once_full() {
    let config = SigningConfig::new(
        Some(1_000),
        BacklogPolicy::Refuse {
            capacity: NonZeroUsize::new(2).unwrap(),
        },
    )
    .unwrap();
    let mut signing = HeadSigning::new(config, JOURNAL, 0);
    assert_eq!(signing.offer(head(0), 0), Offered::Queued);
    assert_eq!(signing.offer(head(1), 0), Offered::Queued);
    assert_eq!(signing.offer(head(2), 0), Offered::Refused);
    let status = signing.status(10, 3, &registry_with(&TestSigner::new(9)));
    assert_eq!((status.pending, status.refused), (2, 1));
}

#[test]
fn signed_heads_and_registry_entries_round_trip() {
    let mut signer = TestSigner::new(9);
    let head = signed(&mut signer, head(42));
    assert_eq!(SignedHead::decode(&head.encode()), Ok(head));
    let entry = register(&signer.key, Custody::Declared, 3);
    assert_eq!(RegistryEntry::decode(&entry.encode()), Ok(entry));
    let mut bad = entry.encode();
    bad[2] = 9;
    assert_eq!(
        RegistryEntry::decode(&bad),
        Err(TrustDecodeError::Unknown {
            field: "action",
            value: 9
        })
    );
}

proptest! {
    /// Decoding arbitrary bytes never panics.
    #[test]
    fn decoding_arbitrary_trust_records_is_total(
        bytes in proptest::collection::vec(any::<u8>(), SIGNED_HEAD_LENGTH..=SIGNED_HEAD_LENGTH),
    ) {
        let array: [u8; SIGNED_HEAD_LENGTH] = bytes.clone().try_into().unwrap();
        if let Ok(head) = SignedHead::decode(&array) {
            prop_assert_eq!(head.encode(), array);
        }
        let _ = RegistryEntry::decode(&array);
    }
}

#[test]
fn a_custody_label_changed_after_signing_breaks_the_signature() {
    let mut signer = TestSigner::new(9);
    let mut registry = KeyRegistry::new(trust());
    registry
        .apply(&register(&signer.key, Custody::ExternallyEvidenced, 0))
        .unwrap();
    let mut upgraded = signed(&mut signer, head(1));
    upgraded.custody = Custody::ExternallyEvidenced;
    assert_eq!(
        registry.verify(&upgraded, None),
        HeadVerdict::Invalid(HeadReason::BadSignature)
    );
}

#[test]
fn an_endorsed_revocation_may_record_a_cutoff_before_its_append() {
    let disk = FaultDisk::default();
    let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut ledger =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk, Path::new(DIR), "keys").unwrap();
    let signer = TestSigner::new(9);
    let mut registry = KeyRegistry::new(trust());
    registry
        .append(
            &register(&signer.key, Custody::NoSeparation, 0),
            &mut journal,
            &mut ledger,
        )
        .unwrap();
    let mut start = 0u64;
    for _ in 0..10 {
        journal.seal_segment(3, start, b"seal", false).unwrap();
        start += 4;
    }
    let revoke = entry(
        &authority(),
        1,
        RegistryAction::Revoke,
        &signer.key,
        Custody::NoSeparation,
        5,
        digest(b"compromise evidence at counter 5"),
    );
    registry.append(&revoke, &mut journal, &mut ledger).unwrap();
    assert_eq!(
        registry.key(&signer.key_id()).unwrap().revoked_from,
        Some((5, digest(b"compromise evidence at counter 5")))
    );
}

#[test]
fn a_later_lifecycle_entry_never_relaxes_an_earlier_cutoff() {
    let mut signer = TestSigner::new(9);
    let mut registry = registry_with(&signer);
    let first = digest(b"first evidence");
    for (sequence, cutoff, evidence) in [(1, 10, first), (2, 20, digest(b"second"))] {
        registry
            .apply(&entry(
                &authority(),
                sequence,
                RegistryAction::Revoke,
                &signer.key,
                Custody::NoSeparation,
                cutoff,
                evidence,
            ))
            .unwrap();
    }
    assert_eq!(
        registry.key(&signer.key_id()).unwrap().revoked_from,
        Some((10, first))
    );
    assert_eq!(
        registry.verify(&signed(&mut signer, head(15)), Some(30)),
        HeadVerdict::Invalid(HeadReason::SignedAfterRevocation)
    );
    // An earlier cutoff tightens it.
    registry
        .apply(&entry(
            &authority(),
            3,
            RegistryAction::Revoke,
            &signer.key,
            Custody::NoSeparation,
            4,
            digest(b"third"),
        ))
        .unwrap();
    assert_eq!(
        registry.key(&signer.key_id()).unwrap().revoked_from,
        Some((4, digest(b"third")))
    );
    for (sequence, retired) in [(4, 8), (5, 12)] {
        registry
            .apply(&entry(
                &authority(),
                sequence,
                RegistryAction::Retire,
                &signer.key,
                Custody::NoSeparation,
                retired,
                [0; 32],
            ))
            .unwrap();
    }
    assert_eq!(
        registry.key(&signer.key_id()).unwrap().retired_from,
        Some(8)
    );
}

#[test]
fn a_registry_entry_whose_journal_append_never_committed_is_not_replayed() {
    let disk = FaultDisk::default();
    let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut ledger =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk.clone(), Path::new(DIR), "keys").unwrap();
    let first = TestSigner::new(9);
    let mut registry = KeyRegistry::new(trust());
    registry
        .append(
            &register(&first.key, Custody::NoSeparation, 0),
            &mut journal,
            &mut ledger,
        )
        .unwrap();
    // The crash point: the ledger entry is synced, the journal record is
    // not written.
    let orphan = TestSigner::new(10);
    let uncommitted = entry(
        &authority(),
        1,
        RegistryAction::Register,
        &orphan.key,
        Custody::NoSeparation,
        1,
        [0; 32],
    );
    ledger.append(uncommitted.encode()).unwrap();

    let restarted = disk.after_crash(Survives::Synced);
    let mut journal = IntegrityJournal::open(restarted.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut ledger =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(restarted.clone(), Path::new(DIR), "keys")
            .unwrap();
    assert_eq!(ledger.entries().len(), 2);
    let mut registry = KeyRegistry::open(trust(), &mut journal, &mut ledger).unwrap();
    assert!(registry.key(&first.key_id()).is_some());
    assert!(registry.key(&orphan.key_id()).is_none());
    assert_eq!(registry.next_sequence(), 1);
    // The unchained suffix is cut before anything is appended after it.
    assert_eq!(ledger.entries().len(), 1);
    registry
        .append(&uncommitted, &mut journal, &mut ledger)
        .unwrap();

    let again = restarted.after_crash(Survives::Synced);
    let mut journal = IntegrityJournal::open(again.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut ledger =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(again, Path::new(DIR), "keys").unwrap();
    let registry = KeyRegistry::open(trust(), &mut journal, &mut ledger).unwrap();
    assert!(registry.key(&orphan.key_id()).is_some());
    assert_eq!(registry.next_sequence(), 2);
}

#[test]
fn a_chained_registry_entry_missing_from_the_ledger_is_refused() {
    let disk = FaultDisk::default();
    let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut ledger =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk.clone(), Path::new(DIR), "keys").unwrap();
    let signer = TestSigner::new(9);
    KeyRegistry::new(trust())
        .append(
            &register(&signer.key, Custody::NoSeparation, 0),
            &mut journal,
            &mut ledger,
        )
        .unwrap();
    let mut empty =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk, Path::new(DIR), "other").unwrap();
    assert!(matches!(
        KeyRegistry::open(trust(), &mut journal, &mut empty),
        Err(IntegrityError::Registry(RegistryError::Missing {
            sequence: 0
        }))
    ));
}

/// A journal of one seal and the head at that seal.
fn one_seal() -> (Vec<super::SealRecord>, ChainHead) {
    (seals()[..1].to_vec(), head(0))
}

#[test]
fn a_signed_head_counts_only_once_it_is_recorded_durably() {
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signing = HeadSigning::new(config, JOURNAL, 0);
    let mut signer = TestSigner::new(9);
    let mut failing = Store {
        failing: true,
        ..Store::default()
    };
    let (records, sealed) = one_seal();
    let _ = signing.offer(sealed, 0);
    assert!(
        signing
            .poll(
                &mut signer,
                &mut failing,
                &registry_with(&TestSigner::new(9)),
                &seals(),
                10
            )
            .is_err()
    );
    let status = signing.status(10, 1, &registry_with(&TestSigner::new(9)));
    assert_eq!((status.pending, status.last_signed), (1, None));
    assert!(signing.signed().is_empty());

    let disk = FaultDisk::default();
    let mut heads =
        Ledger::<_, SIGNED_HEAD_LENGTH>::open(disk.clone(), Path::new(DIR), "heads").unwrap();
    assert_eq!(
        signing
            .poll(
                &mut signer,
                &mut heads,
                &registry_with(&TestSigner::new(9)),
                &seals(),
                20
            )
            .unwrap(),
        1
    );
    let restarted = disk.after_crash(Survives::Synced);
    let heads = Ledger::<_, SIGNED_HEAD_LENGTH>::open(restarted, Path::new(DIR), "heads").unwrap();
    let registry = registry_with(&signer);
    let resumed = HeadSigning::resume(config, 30, heads.entries(), &registry, JOURNAL, &records);
    assert_eq!(resumed.signed(), signing.signed());
    let status = resumed.status(30, 1, &registry_with(&TestSigner::new(9)));
    assert_eq!((status.last_signed, status.discarded), (Some(0), 0));
}

#[test]
fn a_recovered_head_that_does_not_verify_covers_nothing() {
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signer = TestSigner::new(9);
    let registry = registry_with(&signer);
    let (records, sealed) = one_seal();
    let good = signed(&mut signer, sealed);
    let mut forged_signature = good;
    forged_signature.signature[0] ^= 1;
    let mut other_counter = good;
    other_counter.head.counter = 5;
    let mut other_journal = good;
    other_journal.head.journal_id = JOURNAL + 1;
    let stored: Vec<[u8; SIGNED_HEAD_LENGTH]> = [forged_signature, other_counter, other_journal]
        .iter()
        .map(SignedHead::encode)
        .collect();
    let resumed = HeadSigning::resume(config, 0, &stored, &registry, JOURNAL, &records);
    let status = resumed.status(0, 1, &registry_with(&TestSigner::new(9)));
    assert_eq!((status.last_signed, status.discarded), (None, 3));
    assert_eq!(status.coverage_lag_records, 1);
    assert!(status.alarm);
}

#[test]
fn a_restart_keeps_uncovered_records_overdue_until_coverage_advances() {
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signer = TestSigner::new(9);
    let registry = registry_with(&signer);
    let (records, sealed) = one_seal();
    let mut resumed = HeadSigning::resume(config, 5_000, &[], &registry, JOURNAL, &records);
    // The signer was out before the restart: the alarm stays raised.
    assert!(
        resumed
            .status(5_000, 1, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    let _ = resumed.offer(sealed, 5_000);
    assert!(
        resumed
            .status(5_001, 1, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    let mut store = Store::default();
    assert_eq!(
        resumed
            .poll(
                &mut signer,
                &mut store,
                &registry_with(&TestSigner::new(9)),
                &seals(),
                5_002
            )
            .unwrap(),
        1
    );
    assert!(
        !resumed
            .status(5_002, 1, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    // Nothing uncovered at the restart: no alarm.
    let covered = HeadSigning::resume(
        config,
        0,
        &[signed(&mut signer, sealed).encode()],
        &registry,
        JOURNAL,
        &records,
    );
    assert!(
        !covered
            .status(0, 1, &registry_with(&TestSigner::new(9)))
            .alarm
    );
}

#[test]
fn replay_refuses_a_registration_effective_before_its_chain_record() {
    let disk = FaultDisk::default();
    let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut ledger =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk, Path::new(DIR), "keys").unwrap();
    for start in 0..11u64 {
        journal.seal_segment(3, start * 4, b"seal", false).unwrap();
    }
    // Endorsed effective at 5, but first chained at counter 11: append
    // refuses it, so it is written past append, as a tampered host would.
    let signer = TestSigner::new(9);
    let early = register(&signer.key, Custody::NoSeparation, 5);
    let bytes = early.encode();
    ledger.append(bytes).unwrap();
    journal
        .record_key_registry(&signer.key_id(), 0, &bytes)
        .unwrap();
    assert!(matches!(
        KeyRegistry::open(trust(), &mut journal, &mut ledger),
        Err(IntegrityError::Registry(RegistryError::Backdated {
            effective: 5,
            next: 11,
            ..
        }))
    ));
}

#[test]
fn signing_an_old_head_does_not_hide_newer_records_left_uncovered() {
    let config = SigningConfig::new(
        Some(1_000),
        BacklogPolicy::Refuse {
            capacity: NonZeroUsize::new(1).unwrap(),
        },
    )
    .unwrap();
    let mut signing = HeadSigning::new(config, JOURNAL, 0);
    let mut signer = TestSigner::new(9);
    let mut store = Store::default();
    signer.available = false;
    assert_eq!(signing.offer(head(0), 0), Offered::Queued);
    assert_eq!(signing.offer(head(1), 100), Offered::Refused);
    signer.available = true;
    assert_eq!(
        signing
            .poll(
                &mut signer,
                &mut store,
                &registry_with(&TestSigner::new(9)),
                &seals(),
                1_500
            )
            .unwrap(),
        1
    );
    // Record 1 has waited since 100, longer than the interval.
    let status = signing.status(1_500, 2, &registry_with(&TestSigner::new(9)));
    assert_eq!(status.coverage_lag_records, 1);
    assert_eq!(status.coverage_lag_ns, 1_400);
    assert!(status.alarm);
    // A later head covers it, and its age is that of record 1.
    assert_eq!(signing.offer(head(2), 1_600), Offered::Queued);
    assert_eq!(
        signing
            .status(1_600, 3, &registry_with(&TestSigner::new(9)))
            .coverage_lag_ns,
        1_500
    );
    assert_eq!(
        signing
            .poll(
                &mut signer,
                &mut store,
                &registry_with(&TestSigner::new(9)),
                &seals(),
                1_700
            )
            .unwrap(),
        1
    );
    assert!(
        !signing
            .status(1_700, 3, &registry_with(&TestSigner::new(9)))
            .alarm
    );
}

#[test]
fn a_signature_from_a_key_the_registry_does_not_trust_covers_nothing() {
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signing = HeadSigning::new(config, JOURNAL, 0);
    let registry = registry_with(&TestSigner::new(9));
    // A valid Ed25519 key, never registered.
    let mut unregistered = TestSigner::new(10);
    let mut store = Store::default();
    let (_, sealed) = one_seal();
    let _ = signing.offer(sealed, 0);
    assert!(matches!(
        signing.poll(&mut unregistered, &mut store, &registry, &seals(), 10),
        Err(PollError::Untrusted {
            counter: 0,
            verdict: HeadVerdict::Invalid(HeadReason::UnknownKey)
        })
    ));
    assert!(store.heads.is_empty());
    let status = signing.status(2_000, 1, &registry_with(&TestSigner::new(9)));
    assert_eq!((status.pending, status.last_signed), (1, None));
    assert!(status.alarm);
}

#[test]
fn a_restart_stays_overdue_until_coverage_reaches_the_records_present_then() {
    let config = SigningConfig::new(
        Some(1_000),
        BacklogPolicy::Refuse {
            capacity: NonZeroUsize::new(1).unwrap(),
        },
    )
    .unwrap();
    let mut signer = TestSigner::new(9);
    let registry = registry_with(&signer);
    let records = seals()[..2].to_vec();
    let at = |counter: u64| head(counter);
    let mut resumed = HeadSigning::resume(config, 5_000, &[], &registry, JOURNAL, &records);
    let mut store = Store::default();
    assert_eq!(resumed.offer(at(0), 5_000), Offered::Queued);
    assert_eq!(resumed.offer(at(1), 5_000), Offered::Refused);
    assert_eq!(
        resumed
            .poll(&mut signer, &mut store, &registry, &seals(), 5_001)
            .unwrap(),
        1
    );
    // Record 1 was uncovered at the restart and still is.
    assert!(
        resumed
            .status(5_002, 2, &registry_with(&TestSigner::new(9)))
            .alarm
    );
    assert_eq!(resumed.offer(at(1), 5_003), Offered::Queued);
    assert_eq!(
        resumed
            .poll(&mut signer, &mut store, &registry, &seals(), 5_004)
            .unwrap(),
        1
    );
    assert!(
        !resumed
            .status(5_004, 2, &registry_with(&TestSigner::new(9)))
            .alarm
    );
}

#[test]
fn a_poisoned_journal_never_rebuilds_the_registry_or_cuts_its_ledger() {
    let probe = FaultDisk::default();
    IntegrityJournal::open(probe.clone(), Path::new(DIR)).unwrap();
    // The journal disk fails the registry record's write.
    let journal_disk = FaultDisk::with_budget(probe.used());
    let mut journal = IntegrityJournal::open(journal_disk, Path::new(DIR))
        .unwrap()
        .journal;
    let mut ledger =
        Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(FaultDisk::default(), Path::new(DIR), "keys")
            .unwrap();
    let signer = TestSigner::new(9);
    assert!(
        KeyRegistry::new(trust())
            .append(
                &register(&signer.key, Custody::NoSeparation, 0),
                &mut journal,
                &mut ledger,
            )
            .is_err()
    );
    assert!(journal.is_poisoned());
    assert!(matches!(
        KeyRegistry::open(trust(), &mut journal, &mut ledger),
        Err(IntegrityError::Poisoned)
    ));
    assert_eq!(ledger.entries().len(), 1);
    // Nor does an append write the ledger before the journal refuses it.
    let other = TestSigner::new(10);
    assert!(matches!(
        KeyRegistry::new(trust()).append(
            &register(&other.key, Custody::NoSeparation, 0),
            &mut journal,
            &mut ledger,
        ),
        Err(IntegrityError::Poisoned)
    ));
    assert_eq!(ledger.entries().len(), 1);
}

#[test]
fn a_head_of_another_journal_or_record_is_never_signed_or_credited() {
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let registry = registry_with(&TestSigner::new(9));
    let mut signer = TestSigner::new(9);
    let mut store = Store::default();
    let records = seals();
    let mut other_journal = head(3);
    other_journal.journal_id = JOURNAL + 1;
    let mut other_record = head(3);
    other_record.digest = digest(b"not this chain's record");
    for foreign in [other_journal, other_record] {
        let mut signing = HeadSigning::new(config, JOURNAL, 0);
        let _ = signing.offer(foreign, 0);
        assert!(matches!(
            signing.poll(&mut signer, &mut store, &registry, &records, 10),
            Err(PollError::NotInChain { counter: 3 })
        ));
        let status = signing.status(10, 4, &registry);
        assert_eq!(
            (status.last_signed, status.pending, status.discarded),
            (None, 0, 1)
        );
        assert!(store.heads.is_empty());
    }
}

#[test]
fn a_retrospective_revocation_withdraws_the_coverage_it_invalidates() {
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signer = TestSigner::new(9);
    let mut registry = registry_with(&signer);
    let mut store = Store::default();
    let records = seals();
    let mut signing = HeadSigning::new(config, JOURNAL, 0);
    let _ = signing.offer(head(5), 0);
    assert_eq!(
        signing
            .poll(&mut signer, &mut store, &registry, &records, 10)
            .unwrap(),
        1
    );
    assert!(!signing.status(20, 6, &registry).alarm);
    registry
        .apply(&entry(
            &authority(),
            1,
            RegistryAction::Revoke,
            &signer.key,
            Custody::NoSeparation,
            2,
            digest(b"compromised at 2"),
        ))
        .unwrap();
    // Status alone already stops crediting the revoked head.
    let status = signing.status(20, 6, &registry);
    assert_eq!(status.last_signed, None);
    assert!(status.alarm);
    // Revalidation drops it, and the records it covered stay overdue.
    signing.revalidate(&registry);
    let status = signing.status(20, 6, &registry);
    assert_eq!((status.last_signed, status.discarded), (None, 1));
    assert!(status.alarm);
}
