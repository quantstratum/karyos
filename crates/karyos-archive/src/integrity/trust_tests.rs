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
    BacklogPolicy, HeadSigner, HeadSigning, Offered, SignerUnavailable, SigningConfig,
    SigningConfigError,
};
use super::trust::*;
use super::{Digest, digest};
use crate::fault::FaultDisk;

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
        Ok(self.key.sign(&head.signed_bytes()).to_bytes())
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

fn head(counter: u64) -> ChainHead {
    ChainHead {
        archive_id: ARCHIVE,
        journal_id: JOURNAL,
        counter,
        digest: digest(&counter.to_le_bytes()),
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
fn registry_with(signer: &TestSigner) -> KeyRegistry {
    let mut registry = KeyRegistry::new(trust());
    registry
        .apply(&register(&signer.key, Custody::NoSeparation, 0))
        .unwrap();
    registry
}

#[test]
fn the_signed_bytes_are_canonical_and_versioned() {
    let bytes = head(5).signed_bytes();
    assert!(bytes.starts_with(HEAD_DOMAIN));
    let fields = &bytes[HEAD_DOMAIN.len()..];
    assert_eq!(&fields[..2], &TRUST_VERSION.to_le_bytes());
    assert_eq!(&fields[2..34], &ARCHIVE);
    assert_eq!(&fields[34..42], &JOURNAL.to_le_bytes());
    assert_eq!(&fields[42..50], &5u64.to_le_bytes());
    assert_eq!(&fields[50..], &head(5).digest);
    assert_eq!(head(5).signed_bytes(), bytes);
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
    wire.extend_from_slice(&head(2).signed_bytes()[HEAD_DOMAIN.len()..]);
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
    let mut signing = HeadSigning::new(config, 0);
    let mut signer = TestSigner::new(9);
    assert_eq!(signing.offer(head(0)), Offered::Queued);
    assert!(!signing.status(1_000, 1).alarm);
    assert!(signing.status(1_001, 1).alarm);
    assert_eq!(signing.poll(&mut signer, 1_001), 1);
    assert!(!signing.status(1_500, 1).alarm);
    // Nothing new sealed: no lag, no alarm, however long it is.
    assert!(!signing.status(9_000, 1).alarm);
    assert!(signing.status(9_000, 2).alarm);
}

#[test]
fn during_a_signer_outage_sealing_continues_the_backlog_stays_bounded_and_the_lag_is_reported() {
    let mut journal = IntegrityJournal::open(FaultDisk::default(), Path::new(DIR))
        .unwrap()
        .journal;
    let mut sealer = Sealer::new(NonZeroU64::new(100).unwrap());
    sealer.track(3, SealSource::Segments, 0).unwrap();
    let config = SigningConfig::new(Some(1_000), BacklogPolicy::Coalesce).unwrap();
    let mut signing = HeadSigning::new(config, 0);
    let mut signer = TestSigner::new(9);
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
        let _ = signing.offer(ChainHead {
            archive_id: ARCHIVE,
            journal_id: JOURNAL,
            counter,
            digest: journal.head(),
        });
        assert_eq!(signing.poll(&mut signer, now), 0);
        let status = signing.status(now, journal.next_counter());
        assert!(status.pending <= 1, "round {round}");
        // Reported before the first signed head.
        assert_eq!(status.last_signed, None);
        assert_eq!(status.coverage_lag_records, round);
        assert_eq!(status.coverage_lag_ns, now);
    }
    assert!(signing.status(5_000, 50).alarm);
    assert_eq!(signing.status(5_000, 50).coalesced, 49);
    signer.available = true;
    assert_eq!(signing.poll(&mut signer, 5_100), 1);
    let status = signing.status(5_100, journal.next_counter());
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
    let mut signing = HeadSigning::new(config, 0);
    assert_eq!(signing.offer(head(0)), Offered::Queued);
    assert_eq!(signing.offer(head(1)), Offered::Queued);
    assert_eq!(signing.offer(head(2)), Offered::Refused);
    let status = signing.status(10, 3);
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
