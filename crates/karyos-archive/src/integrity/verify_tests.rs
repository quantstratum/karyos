// SPDX-License-Identifier: Apache-2.0

//! Tests of the verifier's per-range outcomes (karyos#665): one per
//! outcome, one per reason that must never become `beyond_anchor`, the
//! statements, the C-EXTRACT mapping, the separation from time evidence,
//! co-occurring outcomes and the scrub.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::num::NonZeroU64;
use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};

use super::anchor::{Anchor, AnchorEvidence, AnchorKind, Externality};

/// Stores that hold exactly the anchors listed.
#[derive(Debug)]
struct Held<'a>(&'a [Anchor]);

impl AnchorEvidence for Held<'_> {
    fn confirms(&self, anchor: &Anchor) -> bool {
        self.0.contains(anchor)
    }
}
use super::journal::IntegrityJournal;
use super::ledger::Ledger;
use super::test_support::*;
use super::trust::*;
use super::verify::*;
use super::{SealRecord, digest};
use crate::fault::FaultDisk;

const OPERATOR: [u8; 32] = [21; 32];

/// The bytes of range `index` of recording 3.
fn range(index: u64) -> Vec<u8> {
    (index * 1_000).to_le_bytes().to_vec()
}

/// A chain: record 0 registers the archival key, records 1 to 6 seal six
/// ranges of recording 3, eight bytes each.
struct Scenario {
    journal: IntegrityJournal<FaultDisk>,
    keys: Vec<[u8; REGISTRY_ENTRY_LENGTH]>,
    heads: Vec<[u8; SIGNED_HEAD_LENGTH]>,
    anchors: Vec<Anchor>,
    trust: Option<TrustRoot>,
    written: Vec<(u64, u64)>,
}

fn registration() -> RegistryEntry {
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
    entry
}

impl Scenario {
    fn new() -> Self {
        let disk = FaultDisk::default();
        let mut journal = IntegrityJournal::open(disk.clone(), Path::new(DIR))
            .unwrap()
            .journal;
        let mut ledger =
            Ledger::<_, REGISTRY_ENTRY_LENGTH>::open(disk, Path::new(DIR), KEYS_FILE).unwrap();
        KeyRegistry::new(trust())
            .append(&registration(), &mut journal, &mut ledger)
            .unwrap();
        for index in 0..6 {
            journal
                .seal_segment(3, index * 8, &range(index), false)
                .unwrap();
        }
        let mut scenario = Self {
            journal,
            keys: ledger.entries().to_vec(),
            heads: Vec::new(),
            anchors: Vec::new(),
            trust: Some(trust()),
            written: vec![(3, 48)],
        };
        scenario.sign_head();
        scenario.anchor(4);
        scenario
    }

    fn records(&mut self) -> Vec<SealRecord> {
        self.journal.records().unwrap()
    }

    /// Signs the current head.
    fn sign_head(&mut self) {
        let records = self.records();
        self.heads.push(sign(records.last().unwrap()).encode());
    }

    /// Anchors the head at `counter` with the operator.
    fn anchor(&mut self, counter: usize) {
        let records = self.records();
        let external = u64::try_from(self.anchors.len()).unwrap();
        self.anchors.push(Anchor {
            kind: AnchorKind::OperatorExport,
            location: OPERATOR,
            external_counter: external,
            receipt: [0; 32],
            signed: sign(&records[counter]),
        });
    }

    fn verify_with(&mut self, read: impl FnMut(u64, u64, u64) -> RangeBytes) -> Verification {
        let records = self.records();
        let externality = Externality {
            local_archive: ARCHIVE,
            ..Externality::default()
        };
        let evidence = Evidence {
            records: &records,
            journal_fault: None,
            journal_id: JOURNAL,
            trust: self.trust.as_ref(),
            registry: &self.keys,
            heads: &self.heads,
            anchors: &self.anchors,
            anchor_faults: 0,
            stores: &Held(&self.anchors),
            externality: &externality,
            written: &self.written,
        };
        verify(&evidence, read)
    }

    fn verify(&mut self) -> Verification {
        self.verify_with(|_, start, _| RangeBytes::Bytes(range(start / 8)))
    }
}

fn outcomes(verification: &Verification) -> Vec<Outcome> {
    verification
        .ranges
        .iter()
        .map(|range| range.outcome)
        .collect()
}

fn never_beyond_anchor(verification: &Verification) {
    assert!(
        verification
            .ranges
            .iter()
            .all(|range| range.outcome != Outcome::BeyondAnchor),
        "{verification:?}"
    );
}

#[test]
fn verified_and_beyond_anchor_are_reached_and_co_occur() {
    let verification = Scenario::new().verify();
    use Outcome::*;
    assert_eq!(
        outcomes(&verification),
        [
            Verified,
            Verified,
            Verified,
            Verified,
            BeyondAnchor,
            BeyondAnchor
        ]
    );
    assert_eq!(verification.ranges[0].reasons, []);
    assert_eq!(verification.ranges[4].reasons, [Reason::NoAnchor]);
    assert_eq!(
        verification.coverage,
        Coverage {
            records: 7,
            signed_through: Some(6),
            anchored_through: Some(4),
        }
    );
}

#[test]
fn unsealed_is_reached_beside_sealed_ranges() {
    let mut scenario = Scenario::new();
    scenario.written = vec![(3, 60), (5, 10)];
    let verification = scenario.verify();
    let unsealed: Vec<_> = verification
        .ranges
        .iter()
        .filter(|range| range.outcome == Outcome::Unsealed)
        .map(|range| (range.recording, range.start, range.end))
        .collect();
    assert_eq!(unsealed, [(3, 48, 60), (5, 0, 10)]);
    assert_eq!(verification.ranges[0].outcome, Outcome::Verified);
}

#[test]
fn purged_needs_an_authenticated_purge_record_and_says_it_proves_no_absence() {
    let mut scenario = Scenario::new();
    scenario
        .journal
        .record_purge(3, 0, 16, digest(b"segment"))
        .unwrap();
    // Not yet covered by a signed head: not authenticated.
    let verification = scenario.verify();
    assert_eq!(verification.ranges[0].outcome, Outcome::Inconsistent);
    assert_eq!(
        verification.ranges[0].reasons,
        [Reason::UnauthenticatedPurge]
    );
    assert_eq!(verification.ranges[0].first_inconsistent, Some(7));
    scenario.sign_head();
    let verification = scenario.verify();
    assert_eq!(
        outcomes(&verification)[..3],
        [Outcome::Purged, Outcome::Purged, Outcome::Verified]
    );
    assert_eq!(Outcome::Purged.statement(), Some(PURGED_STATEMENT));
    assert!(PURGED_STATEMENT.contains("proves nothing about whether the payload bytes are absent"));
}

#[test]
fn an_altered_byte_is_inconsistent_with_proved_corruption_and_names_the_record() {
    let mut scenario = Scenario::new();
    let verification = scenario.verify_with(|_, start, _| {
        let mut bytes = range(start / 8);
        if start == 16 {
            bytes[0] ^= 1;
        }
        RangeBytes::Bytes(bytes)
    });
    let altered = &verification.ranges[2];
    assert_eq!(altered.outcome, Outcome::Inconsistent);
    assert_eq!(altered.reasons, [Reason::Corruption]);
    assert_eq!(altered.first_inconsistent, Some(3));
    assert_eq!(verification.ranges[1].outcome, Outcome::Verified);
}

#[test]
fn a_broken_chain_names_its_first_inconsistent_record() {
    let mut scenario = Scenario::new();
    let mut records = scenario.records();
    records.remove(3);
    let externality = Externality::default();
    let trust = trust();
    let evidence = Evidence {
        records: &records,
        journal_fault: None,
        journal_id: JOURNAL,
        trust: Some(&trust),
        registry: &scenario.keys,
        heads: &scenario.heads,
        anchors: &[],
        anchor_faults: 0,
        stores: &Held(&[]),
        externality: &externality,
        written: &[],
    };
    let verification = verify(&evidence, |_, start, _| RangeBytes::Bytes(range(start / 8)));
    let broken: Vec<_> = verification
        .ranges
        .iter()
        .filter(|range| range.first_inconsistent == Some(3))
        .map(|range| range.counter)
        .collect();
    assert_eq!(broken, [Some(4), Some(5), Some(6)]);
    never_beyond_anchor(&verification);
}

#[test]
fn missing_trust_is_untrusted_evidence_distinct_from_corruption() {
    let mut scenario = Scenario::new();
    scenario.trust = None;
    let verification = scenario.verify();
    for range in &verification.ranges {
        assert_eq!(range.outcome, Outcome::Inconsistent);
        assert!(range.reasons.contains(&Reason::UntrustedEvidence));
        assert!(!range.reasons.contains(&Reason::Corruption));
    }
    never_beyond_anchor(&verification);
}

#[test]
fn an_unknown_key_never_yields_beyond_anchor() {
    let mut scenario = Scenario::new();
    scenario.anchors.clear();
    let records = scenario.records();
    let stranger = SigningKey::from_bytes(&[33; 32]);
    let head = ChainHead {
        archive_id: ARCHIVE,
        journal_id: JOURNAL,
        counter: 6,
        digest: records[6].digest(),
    };
    scenario.heads = vec![
        SignedHead {
            head,
            key_id: key_id(&stranger.verifying_key().to_bytes()),
            custody: Custody::Declared,
            signature: stranger
                .sign(&head.signed_bytes(Custody::Declared))
                .to_bytes(),
        }
        .encode(),
    ];
    let verification = scenario.verify();
    for range in &verification.ranges {
        assert!(range.reasons.contains(&Reason::UnknownKey));
    }
    never_beyond_anchor(&verification);
}

#[test]
fn an_unknown_algorithm_never_yields_beyond_anchor() {
    let disk = FaultDisk::default();
    let mut journal = IntegrityJournal::open(disk, Path::new(DIR))
        .unwrap()
        .journal;
    let mut entry = registration().encode();
    entry[3] = 9;
    journal
        .record_key_registry(&registration().key_id, 0, &entry)
        .unwrap();
    for index in 0..6 {
        journal
            .seal_segment(3, index * 8, &range(index), false)
            .unwrap();
    }
    let records = journal.records().unwrap();
    let heads = [sign(&records[6]).encode()];
    let trust = trust();
    let externality = Externality::default();
    let verification = verify(
        &Evidence {
            records: &records,
            journal_fault: None,
            journal_id: JOURNAL,
            trust: Some(&trust),
            registry: &[entry],
            heads: &heads,
            anchors: &[],
            anchor_faults: 0,
            stores: &Held(&[]),
            externality: &externality,
            written: &[],
        },
        |_, start, _| RangeBytes::Bytes(range(start / 8)),
    );
    for range in &verification.ranges {
        assert!(range.reasons.contains(&Reason::UnknownAlgorithm));
    }
    never_beyond_anchor(&verification);
}

#[test]
fn malformed_or_missing_evidence_never_yields_beyond_anchor() {
    let mut malformed = Scenario::new();
    malformed.anchors.clear();
    malformed.heads[0][0] = 0xFF;
    let verification = malformed.verify();
    for range in &verification.ranges {
        assert!(range.reasons.contains(&Reason::MalformedEvidence));
    }
    never_beyond_anchor(&verification);
    // A registry entry that is not chained is malformed evidence too.
    let mut unchained = Scenario::new();
    unchained.keys[0][100] ^= 1;
    never_beyond_anchor(&unchained.verify());
    let mut missing = Scenario::new();
    missing.anchors.clear();
    missing.heads.clear();
    let verification = missing.verify();
    for range in &verification.ranges {
        assert_eq!(range.reasons, [Reason::MissingEvidence]);
    }
    never_beyond_anchor(&verification);
}

#[test]
fn conflicting_anchors_never_yield_beyond_anchor() {
    let mut scenario = Scenario::new();
    let records = scenario.records();
    let mut other = sign(&records[5]);
    other.head.digest = digest(b"another head");
    let key = archival_key();
    other.signature = key.sign(&other.head.signed_bytes(other.custody)).to_bytes();
    scenario.anchors.push(Anchor {
        kind: AnchorKind::ReplicaJournal,
        location: [22; 32],
        external_counter: 0,
        receipt: [0; 32],
        signed: other,
    });
    let verification = scenario.verify();
    for range in &verification.ranges {
        assert_eq!(range.outcome, Outcome::Inconsistent);
        assert!(range.reasons.contains(&Reason::ConflictingAnchors));
    }
}

#[test]
fn an_index_shortened_below_a_seal_is_inconsistent() {
    let mut scenario = Scenario::new();
    let verification = scenario.verify_with(|_, start, _| {
        if start >= 32 {
            RangeBytes::Missing
        } else {
            RangeBytes::Bytes(range(start / 8))
        }
    });
    assert_eq!(verification.ranges[3].outcome, Outcome::Verified);
    assert_eq!(verification.ranges[4].reasons, [Reason::ShortenedIndex]);
    assert_eq!(verification.ranges[4].first_inconsistent, Some(5));
}

#[test]
fn only_verified_carries_a_tamper_evidence_statement() {
    use Outcome::*;
    for outcome in [Verified, BeyondAnchor, Unsealed, Purged, Inconsistent] {
        let tamper = outcome
            .statement()
            .is_some_and(|text| text.starts_with("tamper evident"));
        assert_eq!(tamper, outcome == Verified, "{outcome:?}");
        // C-EXTRACT: unverifiable is everything but verified.
        assert_eq!(outcome.is_unverifiable(), outcome != Verified);
    }
}

#[test]
fn integrity_and_time_evidence_stay_apart() {
    let verification = Scenario::new().verify();
    assert_eq!(verification.time, TimeEvidence::NotEvaluated);
    use Outcome::*;
    for outcome in [Verified, BeyondAnchor, Unsealed, Purged, Inconsistent] {
        assert!(!["met", "not_met", "no_evidence"].contains(&outcome.name()));
    }
}

#[test]
fn a_scheduled_scrub_raises_an_event_on_a_mismatch() {
    let mut scenario = Scenario::new();
    let mut scrub = Scrub::new(NonZeroU64::new(1_000).unwrap(), 500);
    assert_eq!(scrub.poll(499, || panic!("not due")), None);
    let clean = scrub.poll(500, || scenario.verify()).unwrap();
    assert!(clean.is_empty());
    assert_eq!(scrub.next_ns(), 1_500);
    let events = scrub
        .poll(1_500, || {
            scenario.verify_with(|_, start, _| {
                let mut bytes = range(start / 8);
                if start == 8 {
                    bytes[1] ^= 1;
                }
                RangeBytes::Bytes(bytes)
            })
        })
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].at_ns, 1_500);
    assert!(matches!(
        &events[0].finding,
        ScrubFinding::Range(range) if range.counter == Some(2)
    ));
}

/// Verifies `records` in place of the scenario's chain.
fn verify_records(
    scenario: &Scenario,
    records: &[SealRecord],
    journal_fault: Option<super::Inconsistency>,
    stores: &dyn AnchorEvidence,
) -> Verification {
    let externality = Externality {
        local_archive: ARCHIVE,
        ..Externality::default()
    };
    let evidence = Evidence {
        records,
        journal_fault,
        journal_id: JOURNAL,
        trust: scenario.trust.as_ref(),
        registry: &scenario.keys,
        heads: &scenario.heads,
        anchors: &scenario.anchors,
        anchor_faults: 0,
        stores,
        externality: &externality,
        written: &scenario.written,
    };
    verify(&evidence, |_, start, _| RangeBytes::Bytes(range(start / 8)))
}

#[test]
fn a_registry_commitment_missing_from_the_ledger_verifies_nothing() {
    let mut scenario = Scenario::new();
    let key = archival_key();
    let mut revoke = RegistryEntry {
        action: RegistryAction::Retire,
        sequence: 1,
        effective: 2,
        ..registration()
    };
    revoke.endorsement = authority()
        .sign(&revoke.endorsement_bytes(&ARCHIVE))
        .to_bytes();
    // The journal commits the retirement; the ledger supplied lacks it.
    scenario
        .journal
        .record_key_registry(
            &key_id(&key.verifying_key().to_bytes()),
            1,
            &revoke.encode(),
        )
        .unwrap();
    let verification = scenario.verify();
    assert!(
        verification
            .ranges
            .iter()
            .all(|range| range.outcome != Outcome::Verified),
        "{verification:?}"
    );
    assert!(
        verification.ranges[0]
            .reasons
            .contains(&Reason::MalformedEvidence)
    );
}

#[test]
fn a_record_rejected_at_its_position_is_never_verified() {
    let mut scenario = Scenario::new();
    let mut records = scenario.records();
    // A copy of range record 2 after the last record: its counter repeats.
    records.push(records[2]);
    let held = scenario.anchors.clone();
    let verification = verify_records(&scenario, &records, None, &Held(&held));
    assert_eq!(verification.journal_break, Some(7));
    let last = verification.ranges.last().unwrap();
    assert_eq!(last.counter, Some(2));
    assert_eq!(last.outcome, Outcome::Inconsistent);
    assert_eq!(last.first_inconsistent, Some(7));
}

#[test]
fn a_journal_fault_no_range_reaches_is_reported_and_scrubbed() {
    let mut scenario = Scenario::new();
    let records = scenario.records();
    let fault = super::Inconsistency::CounterGap {
        expected: 7,
        found: 0,
    };
    let held = scenario.anchors.clone();
    let verification = verify_records(&scenario, &records, Some(fault), &Held(&held));
    assert_eq!(verification.journal_break, Some(7));
    let mut scrub = Scrub::new(NonZeroU64::new(1_000).unwrap(), 0);
    let events = scrub.poll(0, || verification.clone()).unwrap();
    assert_eq!(
        events[0].finding,
        ScrubFinding::Journal {
            first_inconsistent: 7
        }
    );
}

/// Stores that also prove they held every anchor before any revocation.
#[derive(Debug)]
struct Predating<'a>(&'a [Anchor]);

impl AnchorEvidence for Predating<'_> {
    fn confirms(&self, anchor: &Anchor) -> bool {
        self.0.contains(anchor)
    }

    fn held_before_revocation_of(&self, _anchor: &Anchor, _key_id: &super::Digest) -> bool {
        true
    }
}

#[test]
fn a_revoked_keys_head_needs_an_anchor_proved_to_predate_the_revocation() {
    let mut scenario = Scenario::new();
    let key = archival_key();
    let mut revoke = RegistryEntry {
        action: RegistryAction::Revoke,
        sequence: 1,
        effective: 100,
        evidence: digest(b"compromised later"),
        ..registration()
    };
    revoke.endorsement = authority()
        .sign(&revoke.endorsement_bytes(&ARCHIVE))
        .to_bytes();
    let bytes = revoke.encode();
    scenario
        .journal
        .record_key_registry(&key_id(&key.verifying_key().to_bytes()), 1, &bytes)
        .unwrap();
    scenario.keys.push(bytes);
    scenario.anchor(6);
    let records = scenario.records();
    let held = scenario.anchors.clone();
    // An anchor that merely exists today proves no ordering.
    let unproved = verify_records(&scenario, &records, None, &Held(&held));
    assert_eq!(unproved.coverage.signed_through, None);
    assert!(
        unproved
            .ranges
            .iter()
            .all(|range| range.outcome != Outcome::Verified)
    );
    let proved = verify_records(&scenario, &records, None, &Predating(&held));
    assert_eq!(proved.coverage.signed_through, Some(6));
}

#[test]
fn offline_replay_refuses_a_registration_effective_before_its_commitment() {
    let mut journal = IntegrityJournal::open(FaultDisk::default(), Path::new(DIR))
        .unwrap()
        .journal;
    for index in 0..6 {
        journal
            .seal_segment(3, index * 8, &range(index), false)
            .unwrap();
    }
    // Endorsed effective at 0, first committed at counter 6.
    let entry = registration().encode();
    journal
        .record_key_registry(
            &key_id(&archival_key().verifying_key().to_bytes()),
            0,
            &entry,
        )
        .unwrap();
    let records = journal.records().unwrap();
    let heads = [sign(&records[5]).encode()];
    let trust = trust();
    let externality = Externality::default();
    let verification = verify(
        &Evidence {
            records: &records,
            journal_fault: None,
            journal_id: JOURNAL,
            trust: Some(&trust),
            registry: &[entry],
            heads: &heads,
            anchors: &[],
            anchor_faults: 0,
            stores: &Held(&[]),
            externality: &externality,
            written: &[],
        },
        |_, start, _| RangeBytes::Bytes(range(start / 8)),
    );
    assert_eq!(verification.coverage.signed_through, None);
    assert!(
        verification
            .ranges
            .iter()
            .all(|range| range.reasons.contains(&Reason::MalformedEvidence)),
        "{verification:?}"
    );
}

#[test]
fn a_malformed_anchor_entry_is_malformed_evidence_not_an_absent_anchor() {
    let scenario = Scenario::new();
    let mut scenario = scenario;
    let records = scenario.records();
    let held = scenario.anchors.clone();
    let externality = Externality {
        local_archive: ARCHIVE,
        ..Externality::default()
    };
    let evidence = Evidence {
        records: &records,
        journal_fault: None,
        journal_id: JOURNAL,
        trust: scenario.trust.as_ref(),
        registry: &scenario.keys,
        heads: &scenario.heads,
        anchors: &[],
        anchor_faults: 1,
        stores: &Held(&held),
        externality: &externality,
        written: &scenario.written,
    };
    let verification = verify(&evidence, |_, start, _| RangeBytes::Bytes(range(start / 8)));
    assert!(
        verification
            .ranges
            .iter()
            .all(|range| range.outcome == Outcome::Inconsistent
                && range.reasons.contains(&Reason::MalformedEvidence)),
        "{verification:?}"
    );
}

#[test]
fn purges_are_matched_to_every_range_they_cover() {
    let mut scenario = Scenario::new();
    let records = scenario.records();
    // Two purges of recording 3: [0, 16) then [0, 32), after the seals.
    scenario
        .journal
        .record_purge(3, 0, 16, records[1].content)
        .unwrap();
    scenario
        .journal
        .record_purge(3, 0, 32, records[3].content)
        .unwrap();
    scenario.sign_head();
    let verification = scenario.verify();
    let purged: Vec<u64> = verification
        .ranges
        .iter()
        .filter(|range| range.outcome == Outcome::Purged)
        .map(|range| range.start)
        .collect();
    assert_eq!(purged, [0, 8, 16, 24], "{verification:?}");
}
