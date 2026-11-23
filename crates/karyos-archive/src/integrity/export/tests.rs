// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;

/// The golden vectors of design/archive-export.md section 8, derived
/// blind by another session (quantstratum-docs#979).
const VECTORS: &str = include_str!("vectors.txt");

fn vector(name: &str) -> Vec<u8> {
    let hex = VECTORS
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

/// X-1 and X-2 encode exactly and decode back.
#[test]
fn x1_and_x2_encode_and_decode_exactly() {
    let id = [7u8; 32];
    assert_eq!(encode(&id, 0, &[]), vector("X-1"));
    let mut policy = Vec::new();
    policy.extend_from_slice(&1u64.to_le_bytes());
    policy.extend_from_slice(&1u64.to_le_bytes());
    policy.extend_from_slice(&3_600_000_000_000u64.to_le_bytes());
    policy.extend_from_slice(&1u32.to_le_bytes());
    policy.extend_from_slice(&[0, 1, 0, 0]);
    let sections = [Section {
        kind: SectionKind::Policies,
        journal: 0,
        count: 1,
        body: policy,
    }];
    assert_eq!(encode(&id, 0, &sections), vector("X-2"));
    let decoded = decode(&vector("X-2")).unwrap();
    assert_eq!(decoded.archive_id, id);
    assert_eq!(decoded.sections, sections);
    assert!(decode(&vector("X-1")).unwrap().sections.is_empty());
}

/// X-3 is refused `Magic`, X-4 `Length`.
#[test]
fn x3_and_x4_are_refused() {
    assert_eq!(decode(&vector("X-3")), Err(ExportError::Magic));
    assert_eq!(
        decode(&vector("X-4")),
        Err(ExportError::Length { section: 0 })
    );
}

/// X-5 to X-12, whole exports, are well formed containers: each decodes,
/// in the design's order, and encodes back to the same bytes.
#[test]
fn x5_to_x12_decode_and_reencode_exactly() {
    for name in ["X-5", "X-6", "X-7", "X-8", "X-9", "X-10", "X-11", "X-12"] {
        let bytes = vector(name);
        let decoded = decode(&bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            encode(
                &decoded.archive_id,
                decoded.created_utc_ns,
                &decoded.sections
            ),
            bytes,
            "{name}"
        );
    }
}

/// The refusals of design section 6, each typed.
#[test]
fn every_refusal_is_typed() {
    let id = [7u8; 32];
    let with = |sections: &[Section]| encode(&id, 0, sections);
    let journal = |role: u16, journal: u64| Section {
        kind: SectionKind::Journal,
        journal,
        count: 1,
        body: {
            let mut row = vec![0u8; 24];
            row[..2].copy_from_slice(&role.to_le_bytes());
            row
        },
    };
    // A damaged byte: the trailer.
    let mut damaged = vector("X-2");
    damaged[70] ^= 1;
    assert_eq!(decode(&damaged), Err(ExportError::Trailer));
    assert_eq!(decode(&[0u8; 50]), Err(ExportError::Trailer));
    // The version, with the trailer recomputed.
    let mut bytes = vector("X-1");
    bytes[8] = 2;
    let resealed = |mut bytes: Vec<u8>| {
        let end = bytes.len() - 32;
        let trailer: [u8; 32] = Sha256::digest(&bytes[..end]).into();
        bytes[end..].copy_from_slice(&trailer);
        bytes
    };
    assert_eq!(decode(&resealed(bytes)), Err(ExportError::Version(2)));
    let mut bytes = vector("X-1");
    bytes[10] = 1;
    assert_eq!(
        decode(&resealed(bytes)),
        Err(ExportError::Reserved { section: None })
    );
    // An unknown kind.
    let mut bytes = vector("X-2");
    bytes[64] = 13;
    assert_eq!(
        decode(&resealed(bytes)),
        Err(ExportError::Kind {
            section: 0,
            kind: 13
        })
    );
    let mut bytes = vector("X-2");
    bytes[66] = 2;
    assert_eq!(
        decode(&resealed(bytes)),
        Err(ExportError::SectionVersion {
            section: 0,
            version: 2
        })
    );
    // Order: the Archive's journal first, groups before the rest, the rest
    // ascending and once.
    assert_eq!(
        decode(&with(&[journal(2, 2)])),
        Err(ExportError::Order { section: 0 })
    );
    let policies = Section {
        kind: SectionKind::Policies,
        journal: 0,
        count: 0,
        body: Vec::new(),
    };
    assert_eq!(
        decode(&with(&[policies.clone(), journal(1, 1)])),
        Err(ExportError::Order { section: 1 })
    );
    assert_eq!(
        decode(&with(&[policies.clone(), policies])),
        Err(ExportError::Order { section: 1 })
    );
    // #1180 review: a journal's group appears once.
    assert_eq!(
        decode(&with(&[journal(1, 1), journal(3, 1)])),
        Err(ExportError::Order { section: 1 })
    );
    // #1180 review: a chunk's padding is zero.
    let mut chunk = frames_chunk(7, 0, &[1, 2, 3]);
    assert_eq!(chunk.len(), 32);
    chunk[31] = 9;
    let frames = Section {
        kind: SectionKind::Frames,
        journal: 0,
        count: 1,
        body: chunk,
    };
    assert_eq!(
        decode(&with(&[frames])),
        Err(ExportError::Length { section: 0 })
    );
    // A count that does not match.
    let mut bytes = vector("X-1");
    bytes[12] = 1;
    assert_eq!(
        decode(&resealed(bytes)),
        Err(ExportError::Count {
            declared: 1,
            found: 0
        })
    );
}

mod offline {
    use super::super::offline::{OfflineError, OfflineTrust, PolicyFinding, Role, verify_export};
    use super::vector;
    use crate::integrity::anchor::{Anchor, AnchorEvidence, Externality};
    use crate::integrity::test_key::TestKey;
    use crate::integrity::time::{Requirement, Verdict};
    use crate::integrity::trust::TrustRoot;
    use crate::integrity::verify::Outcome;

    /// The trusted operator store `0x0A`: it confirms its anchors, and
    /// proves they were held before a revocation when `before` is set.
    #[derive(Debug)]
    struct Store {
        before: bool,
    }

    impl AnchorEvidence for Store {
        fn confirms(&self, anchor: &Anchor) -> bool {
            anchor.location == [0x0A; 32]
        }

        fn held_before_revocation_of(&self, anchor: &Anchor, _key_id: &[u8; 32]) -> bool {
            self.before && self.confirms(anchor)
        }
    }

    fn run(name: &str, before: bool) -> Result<super::super::offline::OfflineReport, OfflineError> {
        let trust = TrustRoot {
            archive_id: [7; 32],
            authorities: vec![TestKey::from_seed([1; 32]).public()],
        };
        let externality = Externality {
            local_archive: [7; 32],
            local_locations: std::collections::BTreeSet::new(),
            anchored_by_this: std::collections::BTreeSet::new(),
        };
        let store = Store { before };
        verify_export(
            &vector(name),
            &OfflineTrust {
                trust: &trust,
                journals: &[(1, Role::Archive), (2, Role::TimeEvidence)],
                stores: &store,
                externality: &externality,
                requirement: Some(Requirement {
                    max_divergence_ns: 1_000_000_000,
                    max_granularity_ns: 1_000_000_000,
                }),
            },
        )
    }

    fn outcomes(report: &super::super::offline::OfflineReport) -> Vec<(u64, u64, u64, Outcome)> {
        report.journals[0]
            .2
            .ranges
            .iter()
            .map(|range| (range.recording, range.start, range.end, range.outcome))
            .collect()
    }

    /// X-5: a later revocation counts after the anchored run, so the
    /// range is `verified` only with the store's pre-revocation proof.
    #[test]
    fn x5_needs_the_pre_revocation_proof() {
        let with = run("X-5", true).unwrap();
        assert_eq!(outcomes(&with), [(7, 0, 64, Outcome::Verified)]);
        let without = run("X-5", false).unwrap();
        assert_eq!(outcomes(&without)[0].3, Outcome::Inconsistent);
    }

    /// X-6 omits a sealed time evidence entry, X-9 a revocation's row:
    /// both `Incomplete`.
    #[test]
    fn x6_and_x9_are_incomplete() {
        for name in ["X-6", "X-9"] {
            assert!(
                matches!(run(name, true), Err(OfflineError::Incomplete { .. })),
                "{name}: {:?}",
                run(name, true)
            );
        }
    }

    /// X-7: recording 7's policy is proven through its recording binding;
    /// recording 8, bound only by a class, is unproven. X-10: a binding
    /// sealed after the anchored run is ignored.
    #[test]
    fn x7_and_x10_prove_policies_only_through_recording_bindings() {
        let proven = PolicyFinding::Proven {
            policy: 1,
            version: 1,
        };
        assert_eq!(
            run("X-7", true).unwrap().policies,
            [(7, proven), (8, PolicyFinding::Unproven)]
        );
        let ten = run("X-10", true).unwrap().policies;
        assert_eq!(ten[0], (7, proven));
    }

    /// X-8: the range after the last anchor is `beyond_anchor`.
    #[test]
    fn x8_has_a_range_beyond_the_anchor() {
        let report = run("X-8", true).unwrap();
        let ranges = outcomes(&report);
        assert!(
            ranges.contains(&(7, 0, 64, Outcome::Verified)),
            "{ranges:?}"
        );
        assert!(
            ranges.contains(&(7, 64, 128, Outcome::BeyondAnchor)),
            "{ranges:?}"
        );
    }

    /// X-11, an empty time store, and X-12, the only counting entry citing
    /// records the export does not carry: `no_evidence`.
    #[test]
    fn x11_and_x12_have_no_time_evidence() {
        for name in ["X-11", "X-12"] {
            let report = run(name, true).unwrap();
            assert_eq!(report.time, [(7, Verdict::NoEvidence)], "{name}");
        }
    }

    /// #1183 review P1: an entries journal is read from the
    /// `TimeEvidence` section, so its ranges verify.
    #[test]
    fn an_entries_journal_verifies_against_its_store() {
        let report = run("X-12", true).unwrap();
        let (_, role, entries) = &report.journals[1];
        assert_eq!(*role, Role::TimeEvidence);
        let first = entries
            .ranges
            .iter()
            .find(|range| range.start == 0)
            .unwrap();
        assert_eq!(first.outcome, Outcome::Verified, "{:?}", entries.ranges);
    }

    /// #1183 review P1: a record after the chain breaks never counts,
    /// whatever counter it declares. A binding seal appended to X-7 with a
    /// counter inside the anchored run breaks the chain; read by declared
    /// counter it would demand a row (or, with one, bind recording 8), but
    /// only the verified prefix counts, so recording 8 stays unproven and
    /// no row is asked for.
    #[test]
    fn a_broken_suffix_never_proves_a_policy() {
        use super::super::{SectionKind, decode, encode};
        use crate::integrity::{SealKind, SealRecord, digest};
        let mut export = decode(&vector("X-7")).unwrap();
        let mut binding = [0u8; 64];
        binding[0] = 2;
        binding[1] = 1;
        binding[8..16].copy_from_slice(&1u64.to_le_bytes());
        binding[16..24].copy_from_slice(&8u64.to_le_bytes());
        let forged = SealRecord {
            kind: SealKind::Catalog,
            counter: 3,
            subject: u64::MAX,
            start: 9,
            end: 9,
            content: digest(&binding),
            previous: [0; 32],
        };
        for section in &mut export.sections {
            match section.kind {
                SectionKind::Seals if section.journal == 1 => {
                    section.body.extend_from_slice(&forged.encode());
                    section.count += 1;
                }
                _ => {}
            }
        }
        let bytes = encode(&export.archive_id, 0, &export.sections);
        let trust = TrustRoot {
            archive_id: [7; 32],
            authorities: vec![TestKey::from_seed([1; 32]).public()],
        };
        let externality = Externality {
            local_archive: [7; 32],
            local_locations: std::collections::BTreeSet::new(),
            anchored_by_this: std::collections::BTreeSet::new(),
        };
        let report = verify_export(
            &bytes,
            &OfflineTrust {
                trust: &trust,
                journals: &[(1, Role::Archive)],
                stores: &Store { before: true },
                externality: &externality,
                requirement: None,
            },
        )
        .unwrap();
        assert!(report.journals[0].2.journal_break.is_some());
        assert_eq!(report.policies[1], (8, PolicyFinding::Unproven));
    }

    /// #1183 review P2: entries with no journal to prove them are
    /// `Incomplete`.
    #[test]
    fn entries_without_their_journal_are_incomplete() {
        use super::super::{SectionKind, decode, encode};
        let mut export = decode(&vector("X-12")).unwrap();
        export
            .sections
            .retain(|section| !(section.kind.per_journal() && section.journal == 2));
        let bytes = encode(&export.archive_id, 0, &export.sections);
        let trust = TrustRoot {
            archive_id: [7; 32],
            authorities: vec![TestKey::from_seed([1; 32]).public()],
        };
        let externality = Externality {
            local_archive: [7; 32],
            local_locations: std::collections::BTreeSet::new(),
            anchored_by_this: std::collections::BTreeSet::new(),
        };
        let _ = SectionKind::TimeEvidence;
        assert!(matches!(
            verify_export(
                &bytes,
                &OfflineTrust {
                    trust: &trust,
                    journals: &[(1, Role::Archive)],
                    stores: &Store { before: true },
                    externality: &externality,
                    requirement: None,
                },
            ),
            Err(OfflineError::Incomplete { .. })
        ));
    }

    /// #1183 review P2: entries wholly outside the exported interval never
    /// change its verdict.
    #[test]
    fn entries_outside_the_interval_are_ignored() {
        use super::super::offline::{ManifestRow, time_verdict};
        use crate::integrity::time::{Source, SyncState};
        use crate::integrity::time_evidence::Entry;
        let inside = Entry {
            source: Source::Gnss,
            sync_state: SyncState::Synchronised,
            clock: [1, 0, 2, 3, 4],
            recording: 7,
            start: 0,
            end: 64,
            min_time: 1000,
            max_time: 2000,
            granularity: 1,
            bound_min_ns: 150,
            bound_max_ns: 160,
            calibration: [0xAA; 32],
            utc_reference: [0xBB; 32],
            tick_fs: 1_000_000,
        };
        let outside = Entry {
            start: 64,
            end: 128,
            bound_min_ns: 10_000_000_000,
            bound_max_ns: 10_000_000_000,
            ..inside
        };
        let row = ManifestRow {
            recording: 7,
            start: 0,
            end: 64,
        };
        let requirement = Requirement {
            max_divergence_ns: 1000,
            max_granularity_ns: 1000,
        };
        let clocks = [[0xAA; 32], [0xBB; 32]];
        assert_eq!(
            time_verdict(&row, &[inside, outside], &clocks, &requirement),
            Verdict::Met
        );
    }
}

/// The exporter's assembly reproduces the blind vectors X-5 to X-12 byte
/// for byte from their inputs (design section 8), built with the Archive's
/// own record types.
mod assembly {
    use super::super::assemble::{ExportContents, JournalExport, RecordingExport, assemble};
    use super::vector;
    use crate::integrity::anchor::{Anchor, AnchorKind};
    use crate::integrity::test_key::TestKey;
    use crate::integrity::time::{Source, SyncState};
    use crate::integrity::time_evidence::Entry;
    use crate::integrity::trust::{
        Algorithm, ChainHead, Custody, RegistryAction, RegistryEntry, SignedHead, key_id,
    };
    use crate::integrity::{GENESIS, SealKind, SealRecord, digest};

    const ARCHIVE: [u8; 32] = [7; 32];

    fn authority() -> TestKey {
        TestKey::from_seed([1; 32])
    }

    fn archival() -> TestKey {
        TestKey::from_seed([9; 32])
    }

    /// A registry entry, endorsed by the authority.
    fn entry(
        action: RegistryAction,
        sequence: u64,
        key: &TestKey,
        effective: u64,
        evidence: [u8; 32],
    ) -> RegistryEntry {
        let register = action == RegistryAction::Register;
        let mut entry = RegistryEntry {
            action,
            algorithm: Algorithm::Ed25519,
            custody: Custody::Declared,
            sequence,
            key_id: key_id(&key.public()),
            public: if register { key.public() } else { [0; 32] },
            effective,
            evidence,
            endorsement: [0; 64],
        };
        entry.endorsement = authority().sign_bytes(&entry.endorsement_bytes(&ARCHIVE));
        entry
    }

    /// What a record seals, before its counter and link.
    enum Seal {
        Registry(RegistryEntry),
        Range(SealKind, u64, u64, Vec<u8>),
        Policy(u64, u64, [u8; 30]),
        Binding(u64, [u8; 64]),
    }

    fn chain(seals: &[Seal]) -> Vec<SealRecord> {
        let mut records: Vec<SealRecord> = Vec::new();
        for (counter, seal) in (0u64..).zip(seals) {
            let (kind, subject, start, end, content) = match seal {
                Seal::Registry(entry) => (
                    SealKind::KeyRegistry,
                    u64::from_le_bytes(*entry.key_id.first_chunk::<8>().unwrap()),
                    entry.sequence,
                    entry.sequence,
                    digest(&entry.encode()),
                ),
                Seal::Range(kind, subject, start, bytes) => (
                    *kind,
                    *subject,
                    *start,
                    start + bytes.len() as u64,
                    digest(bytes),
                ),
                Seal::Policy(policy, version, canonical) => (
                    SealKind::Policy,
                    *policy,
                    *version,
                    *version,
                    digest(canonical),
                ),
                Seal::Binding(sequence, row) => (
                    SealKind::Catalog,
                    u64::MAX,
                    *sequence,
                    *sequence,
                    digest(row),
                ),
            };
            let previous = records.last().map_or(GENESIS, SealRecord::digest);
            records.push(SealRecord {
                kind,
                counter,
                subject,
                start,
                end,
                content,
                previous,
            });
        }
        records
    }

    fn head(journal: u64, records: &[SealRecord], counter: usize) -> SignedHead {
        let head = ChainHead {
            archive_id: ARCHIVE,
            journal_id: journal,
            counter: counter as u64,
            digest: records[counter].digest(),
        };
        SignedHead {
            head,
            key_id: key_id(&archival().public()),
            custody: Custody::Declared,
            signature: archival().sign_bytes(&head.signed_bytes(Custody::Declared)),
        }
    }

    fn anchor(signed: SignedHead) -> Anchor {
        Anchor {
            kind: AnchorKind::OperatorExport,
            location: [0x0A; 32],
            external_counter: 1,
            receipt: [0x0B; 32],
            signed,
        }
    }

    fn recording(id: u64, session: i32, start: u64, bytes: Vec<u8>) -> RecordingExport {
        RecordingExport {
            recording: id,
            start,
            segment_length: 4096,
            stream_id: 10,
            session_id: session,
            initial_term_id: 0,
            mtu: 1408,
            bytes,
        }
    }

    fn r0() -> RegistryEntry {
        entry(RegistryAction::Register, 0, &archival(), 0, [0; 32])
    }

    fn r1() -> RegistryEntry {
        entry(RegistryAction::Revoke, 1, &archival(), 2, [0x0C; 32])
    }

    fn e1() -> Entry {
        Entry {
            source: Source::Gnss,
            sync_state: SyncState::Synchronised,
            clock: [1, 0, 2, 3, 4],
            recording: 7,
            start: 0,
            end: 64,
            min_time: 1000,
            max_time: 2000,
            granularity: 1,
            bound_min_ns: 150,
            bound_max_ns: 160,
            calibration: [0xAA; 32],
            utc_reference: [0xBB; 32],
            tick_fs: 1_000_000,
        }
    }

    fn e2() -> Entry {
        Entry {
            min_time: 1500,
            ..e1()
        }
    }

    fn archive_journal(
        seals: &[Seal],
        heads: &[usize],
        anchors: &[usize],
        registry: Vec<RegistryEntry>,
    ) -> JournalExport {
        let records = chain(seals);
        JournalExport {
            id: 1,
            role: 1,
            heads: heads.iter().map(|at| head(1, &records, *at)).collect(),
            anchors: anchors
                .iter()
                .map(|at| anchor(head(1, &records, *at)))
                .collect(),
            records,
            registry,
        }
    }

    fn sevens() -> Vec<u8> {
        vec![7; 64]
    }

    fn x5(with_r1: bool) -> ExportContents {
        let registry = if with_r1 {
            vec![r0(), r1()]
        } else {
            vec![r0()]
        };
        ExportContents {
            archive_id: ARCHIVE,
            journals: vec![archive_journal(
                &[
                    Seal::Registry(r0()),
                    Seal::Range(SealKind::OpenSegment, 7, 0, sevens()),
                    Seal::Registry(r1()),
                ],
                &[1],
                &[1],
                registry,
            )],
            recordings: vec![recording(7, 3, 0, sevens())],
            ..ExportContents::default()
        }
    }

    fn base_journal() -> Vec<Seal> {
        vec![
            Seal::Registry(r0()),
            Seal::Range(SealKind::OpenSegment, 7, 0, sevens()),
        ]
    }

    fn x6(
        entries: &[Entry],
        carried: Vec<Entry>,
        heads: &[usize],
        anchors: &[usize],
    ) -> ExportContents {
        let mut seals = vec![Seal::Registry(r0())];
        let mut at = 0u64;
        for entry in entries {
            let bytes = entry.encode().unwrap().to_vec();
            seals.push(Seal::Range(SealKind::OpenSegment, 1, at, bytes));
            at += 200;
        }
        let records = chain(&seals);
        let entries_journal = JournalExport {
            id: 2,
            role: 2,
            heads: heads.iter().map(|at| head(2, &records, *at)).collect(),
            anchors: anchors
                .iter()
                .map(|at| anchor(head(2, &records, *at)))
                .collect(),
            records,
            registry: vec![r0()],
        };
        ExportContents {
            archive_id: ARCHIVE,
            journals: vec![
                archive_journal(&base_journal(), &[1], &[1], vec![r0()]),
                entries_journal,
            ],
            recordings: vec![recording(7, 3, 0, sevens())],
            time_evidence: Some((2, carried)),
            ..ExportContents::default()
        }
    }

    fn p1() -> [u8; 30] {
        let mut canonical = [0u8; 30];
        let fields: Vec<u8> = 1u64
            .to_le_bytes()
            .into_iter()
            .chain(1u64.to_le_bytes())
            .chain(3_600_000_000_000u64.to_le_bytes())
            .chain(1u32.to_le_bytes())
            .chain([0, 1])
            .collect();
        canonical.copy_from_slice(&fields);
        canonical
    }

    fn binding(
        selector: u8,
        policy: u64,
        recording: u64,
        stream_id: i32,
        channel: [u8; 32],
    ) -> [u8; 64] {
        let mut row = [0u8; 64];
        row[0] = 2;
        row[1] = selector;
        row[8..16].copy_from_slice(&policy.to_le_bytes());
        row[16..24].copy_from_slice(&recording.to_le_bytes());
        row[24..28].copy_from_slice(&stream_id.to_le_bytes());
        row[32..].copy_from_slice(&channel);
        row
    }

    fn x7(extra: bool) -> ExportContents {
        let b0 = binding(1, 1, 7, 0, [0; 32]);
        let b1 = binding(2, 1, 0, 10, digest(b"karyos:ipc"));
        let mut seals = base_journal();
        seals.push(Seal::Policy(1, 1, p1()));
        seals.push(Seal::Binding(0, b0));
        seals.push(Seal::Binding(1, b1));
        seals.push(Seal::Range(SealKind::OpenSegment, 8, 0, vec![8; 64]));
        if extra {
            seals.push(Seal::Binding(2, binding(1, 2, 7, 0, [0; 32])));
        }
        ExportContents {
            archive_id: ARCHIVE,
            journals: vec![archive_journal(&seals, &[5], &[5], vec![r0()])],
            recordings: vec![
                recording(7, 3, 0, sevens()),
                recording(8, 4, 0, vec![8; 64]),
            ],
            policies: vec![p1()],
            bindings: vec![b0, b1],
            ..ExportContents::default()
        }
    }

    fn x8() -> ExportContents {
        let key = TestKey::from_seed([0x0D; 32]);
        let r2 = entry(RegistryAction::Register, 1, &key, 3, [0; 32]);
        let mut seals = base_journal();
        seals.push(Seal::Range(SealKind::OpenSegment, 9, 0, vec![9; 8]));
        seals.push(Seal::Registry(r2));
        seals.push(Seal::Range(SealKind::OpenSegment, 7, 64, vec![0x17; 64]));
        let mut bytes = sevens();
        bytes.extend_from_slice(&[0x17; 64]);
        ExportContents {
            archive_id: ARCHIVE,
            journals: vec![archive_journal(&seals, &[1, 4], &[1], vec![r0(), r2])],
            recordings: vec![recording(7, 3, 0, bytes)],
            ..ExportContents::default()
        }
    }

    fn check(name: &str, contents: &ExportContents) {
        let built = assemble(contents).unwrap();
        let expected = vector(name);
        let first = built.iter().zip(&expected).position(|(a, b)| a != b);
        assert!(
            built == expected,
            "{name}: lengths {} vs {}, first difference at {first:?}",
            built.len(),
            expected.len()
        );
    }

    /// #1189 review P2: a range ending past `u64::MAX` is refused, typed.
    #[test]
    fn an_overflowing_range_is_refused() {
        use super::super::assemble::AssembleError;
        let contents = ExportContents {
            archive_id: ARCHIVE,
            recordings: vec![recording(7, 3, u64::MAX, vec![1])],
            ..ExportContents::default()
        };
        assert_eq!(
            assemble(&contents),
            Err(AssembleError::RangeOverflow { recording: 7 })
        );
    }

    #[test]
    fn the_assembly_reproduces_x5_to_x12() {
        check("X-5", &x5(true));
        check("X-6", &x6(&[e1(), e2()], vec![e1()], &[], &[]));
        check("X-7", &x7(false));
        check("X-8", &x8());
        check("X-9", &x5(false));
        check("X-10", &x7(true));
        check("X-11", &x6(&[], Vec::new(), &[], &[]));
        check("X-12", &x6(&[e1(), e2()], vec![e1(), e2()], &[1, 2], &[1]));
    }
}
