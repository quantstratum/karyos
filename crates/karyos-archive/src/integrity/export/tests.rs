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
}
