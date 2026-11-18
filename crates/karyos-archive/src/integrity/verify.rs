// SPDX-License-Identifier: Apache-2.0

//! The verifier and its per-range integrity outcomes (quantstratum-docs:
//! karyos/SPEC.md §8.4, "Verification"; ADR-0051 item 8; karyos#665).
//!
//! [`verify`] recomputes each sealed range's digest, walks the chain,
//! checks the key registry and the signed heads under an external
//! [`TrustRoot`], and compares the chain with its anchors. Every range gets
//! exactly one [`Outcome`], with explicit [`Reason`]s and the
//! [`Coverage`] of signatures and anchors:
//!
//! - `verified`: sealed, chain and signatures valid, at or below an
//!   external anchor. Only this outcome carries a tamper-evidence
//!   statement ([`Outcome::statement`]).
//! - `beyond_anchor`: a valid, signed chain after the last external
//!   anchor. Missing trust, an unknown key or algorithm, malformed or
//!   missing evidence and conflicting anchors never yield it.
//! - `unsealed`: written, with no seal yet.
//! - `purged`: removed by a purge record that a trusted signed head
//!   covers; it never proves that payload bytes are absent.
//! - `inconsistent`: the first inconsistent record is named. Missing trust
//!   is `inconsistent` with [`Reason::UntrustedEvidence`], which a reader
//!   tells apart from [`Reason::Corruption`], proved corruption.
//!
//! An index shortened by media damage below a seal reads back as missing
//! bytes and is `inconsistent` with [`Reason::ShortenedIndex`].
//!
//! The integrity outcome is reported apart from time evidence
//! ([`Verification::time`]): the integrity path never yields a time
//! verdict. C-EXTRACT's "unverifiable" is [`Outcome::is_unverifiable`].

use std::num::NonZeroU64;

use super::anchor::{AnchorReport, Externality, check_anchors};
use super::trust::{
    HeadReason, HeadVerdict, KeyRegistry, REGISTRY_ENTRY_LENGTH, RegistryEntry, SIGNED_HEAD_LENGTH,
    SignedHead, TrustDecodeError, TrustRoot,
};
use super::{ChainCheck, Inconsistency, SealKind, SealRecord, digest, verify_range};

/// A range's integrity outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Outcome {
    /// Sealed, chain and signatures valid, at or below an external anchor.
    Verified,
    /// A valid, signed chain after the last external anchor.
    BeyondAnchor,
    /// Written, not yet sealed.
    Unsealed,
    /// Removed by an authenticated purge record.
    Purged,
    /// Inconsistent: see the reasons and the first inconsistent record.
    Inconsistent,
}

/// The tamper-evidence statement of `verified`.
pub const VERIFIED_STATEMENT: &str = "tamper evident: sealed, chained, signed under the external trust and at or below an external anchor";

/// The statement every `purged` range carries.
pub const PURGED_STATEMENT: &str = "purged by an authenticated purge record; this proves nothing about whether the payload bytes are absent";

impl Outcome {
    /// The outcome's name in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::BeyondAnchor => "beyond_anchor",
            Self::Unsealed => "unsealed",
            Self::Purged => "purged",
            Self::Inconsistent => "inconsistent",
        }
    }

    /// The statement the outcome supports: a tamper-evidence statement for
    /// `verified` only, the purge caveat for `purged`, nothing otherwise.
    #[must_use]
    pub const fn statement(self) -> Option<&'static str> {
        match self {
            Self::Verified => Some(VERIFIED_STATEMENT),
            Self::Purged => Some(PURGED_STATEMENT),
            Self::BeyondAnchor | Self::Unsealed | Self::Inconsistent => None,
        }
    }

    /// C-EXTRACT's "unverifiable" (Venue Kit): every outcome other than
    /// `verified`.
    #[must_use]
    pub const fn is_unverifiable(self) -> bool {
        !matches!(self, Self::Verified)
    }
}

/// Why a range has its outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// No trust root was supplied: missing trust, not proved corruption.
    UntrustedEvidence,
    /// A head names a key the registry does not hold.
    UnknownKey,
    /// The registry names an algorithm this verifier does not know.
    UnknownAlgorithm,
    /// Evidence does not decode, is not chained, or the authority did not
    /// endorse it.
    MalformedEvidence,
    /// No trusted signed head covers the record.
    MissingEvidence,
    /// The anchors conflict with each other or with the chain.
    ConflictingAnchors,
    /// Proved corruption: the chain or a digest does not match.
    Corruption,
    /// The bytes below a seal are gone: an index shortened by media damage.
    ShortenedIndex,
    /// The purge record is not covered by a trusted signed head.
    UnauthenticatedPurge,
    /// No external anchor covers the record (a stated absence).
    NoAnchor,
}

impl Reason {
    /// The reason's name in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UntrustedEvidence => "untrusted_evidence",
            Self::UnknownKey => "unknown_key",
            Self::UnknownAlgorithm => "unknown_algorithm",
            Self::MalformedEvidence => "malformed_evidence",
            Self::MissingEvidence => "missing_evidence",
            Self::ConflictingAnchors => "conflicting_anchors",
            Self::Corruption => "corruption",
            Self::ShortenedIndex => "shortened_index",
            Self::UnauthenticatedPurge => "unauthenticated_purge",
            Self::NoAnchor => "no_anchor",
        }
    }
}

/// How far signatures and anchors reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    /// The records in the chain.
    pub records: u64,
    /// The highest position a trusted signed head covers.
    pub signed_through: Option<u64>,
    /// The highest position a trusted, consistent external anchor covers.
    pub anchored_through: Option<u64>,
}

/// One range's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeReport {
    /// The recording.
    pub recording: u64,
    /// The range's start.
    pub start: u64,
    /// Its end, exclusive.
    pub end: u64,
    /// The seal record's counter, if the range is sealed.
    pub counter: Option<u64>,
    /// The outcome.
    pub outcome: Outcome,
    /// The reasons, empty for a plain `verified`.
    pub reasons: Vec<Reason>,
    /// For `inconsistent`, the first inconsistent record's counter.
    pub first_inconsistent: Option<u64>,
}

/// Time evidence, which this verifier does not evaluate: its verdicts
/// (`met`, `not_met`, `no_evidence`) belong to the time evidence path and
/// never come from integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeEvidence {
    /// Not evaluated by the integrity verifier.
    NotEvaluated,
}

/// What [`verify`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// Each range, in chain order, then the unsealed tails.
    pub ranges: Vec<RangeReport>,
    /// The coverage of signatures and anchors.
    pub coverage: Coverage,
    /// The anchor comparison.
    pub anchors: AnchorReport,
    /// Time evidence, kept apart from integrity.
    pub time: TimeEvidence,
}

/// The bytes of a sealed range, as the store returns them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeBytes {
    /// The bytes.
    Bytes(Vec<u8>),
    /// Gone: the store's index or data ends below the seal.
    Missing,
}

/// The evidence a verifier reads.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// The chain's records, as read.
    pub records: &'a [SealRecord],
    /// A record that did not decode, after `records`.
    pub journal_fault: Option<Inconsistency>,
    /// The journal's identity.
    pub journal_id: u64,
    /// The trust supplied outside the export; `None` when there is none.
    pub trust: Option<&'a TrustRoot>,
    /// The key registry's entries, as stored.
    pub registry: &'a [[u8; REGISTRY_ENTRY_LENGTH]],
    /// The signed heads, as stored.
    pub heads: &'a [[u8; SIGNED_HEAD_LENGTH]],
    /// The anchors gathered from their stores.
    pub anchors: &'a [super::anchor::Anchor],
    /// What counts as external.
    pub externality: &'a Externality,
    /// Each recording's written end, for the unsealed tails.
    pub written: &'a [(u64, u64)],
}

/// The registry rebuilt from its entries, and what went wrong doing so.
fn rebuild_registry(
    trust: &TrustRoot,
    entries: &[[u8; REGISTRY_ENTRY_LENGTH]],
    records: &[SealRecord],
) -> (KeyRegistry, Vec<Reason>) {
    let mut registry = KeyRegistry::new(trust.clone());
    let mut reasons = Vec::new();
    let mut chained = records
        .iter()
        .filter(|record| record.kind == SealKind::KeyRegistry)
        .map(|record| record.content);
    for bytes in entries {
        if chained.next() != Some(digest(bytes)) {
            reasons.push(Reason::MalformedEvidence);
            break;
        }
        match RegistryEntry::decode(bytes) {
            Ok(entry) => {
                if registry.apply(&entry).is_err() {
                    reasons.push(Reason::MalformedEvidence);
                    break;
                }
            }
            Err(TrustDecodeError::Unknown {
                field: "algorithm", ..
            }) => {
                reasons.push(Reason::UnknownAlgorithm);
                break;
            }
            Err(_) => {
                reasons.push(Reason::MalformedEvidence);
                break;
            }
        }
    }
    (registry, reasons)
}

fn push_unique(reasons: &mut Vec<Reason>, reason: Reason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

/// Verifies `evidence`, reading each sealed range through `read`
/// (recording, start, end).
#[must_use]
pub fn verify(
    evidence: &Evidence<'_>,
    mut read: impl FnMut(u64, u64, u64) -> RangeBytes,
) -> Verification {
    let records = evidence.records;
    let records_len = u64::try_from(records.len()).unwrap_or(u64::MAX);
    // The chain: where it first breaks, if it does.
    let mut check = ChainCheck::new();
    let mut chain_break: Option<u64> = None;
    for record in records {
        if check.accept(record).is_err() {
            chain_break = Some(check.next_counter());
            break;
        }
    }
    if chain_break.is_none() && evidence.journal_fault.is_some() {
        chain_break = Some(records_len);
    }
    // Trust, the registry and the heads.
    let mut global: Vec<Reason> = Vec::new();
    let (registry, registry_reasons) = match evidence.trust {
        Some(trust) => {
            let (registry, reasons) = rebuild_registry(trust, evidence.registry, records);
            (Some(registry), reasons)
        }
        None => (None, vec![Reason::UntrustedEvidence]),
    };
    global.extend(registry_reasons);
    let anchors = match &registry {
        Some(registry) => check_anchors(
            records,
            evidence.journal_id,
            evidence.anchors,
            registry,
            evidence.externality,
        ),
        None => AnchorReport {
            anchored_through: None,
            kinds: std::collections::BTreeSet::new(),
            findings: Vec::new(),
            absent: Some(super::anchor::Absence::NoTrustedAnchor),
        },
    };
    if anchors.is_conflicting() {
        push_unique(&mut global, Reason::ConflictingAnchors);
    }
    let mut signed_through: Option<u64> = None;
    if let Some(registry) = &registry {
        for bytes in evidence.heads {
            let Ok(signed) = SignedHead::decode(bytes) else {
                push_unique(&mut global, Reason::MalformedEvidence);
                continue;
            };
            if signed.head.journal_id != evidence.journal_id {
                push_unique(&mut global, Reason::MalformedEvidence);
                continue;
            }
            match registry.verify(&signed, anchors.anchored_through) {
                HeadVerdict::Trusted { .. } => {
                    let counter = signed.head.counter;
                    let matches = usize::try_from(counter)
                        .ok()
                        .and_then(|index| records.get(index))
                        .is_some_and(|record| record.digest() == signed.head.digest);
                    if matches {
                        signed_through =
                            Some(signed_through.map_or(counter, |through| through.max(counter)));
                    } else {
                        push_unique(&mut global, Reason::Corruption);
                    }
                }
                HeadVerdict::Invalid(HeadReason::UnknownKey)
                | HeadVerdict::NotTrustedEvidence(HeadReason::UnknownKey) => {
                    push_unique(&mut global, Reason::UnknownKey);
                }
                HeadVerdict::Invalid(_) | HeadVerdict::NotTrustedEvidence(_) => {
                    push_unique(&mut global, Reason::MalformedEvidence);
                }
            }
        }
    }
    let coverage = Coverage {
        records: records_len,
        signed_through,
        anchored_through: anchors.anchored_through,
    };
    let signed = |counter: u64| signed_through.is_some_and(|through| counter <= through);
    let mut ranges = Vec::new();
    let mut sealed_ends: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    for record in records {
        if !record.kind.is_range() {
            continue;
        }
        let counter = record.counter;
        let mut report = RangeReport {
            recording: record.subject,
            start: record.start,
            end: record.end,
            counter: Some(counter),
            outcome: Outcome::Inconsistent,
            reasons: Vec::new(),
            first_inconsistent: None,
        };
        if let Some(broken) = chain_break.filter(|broken| *broken <= counter) {
            report.reasons.push(Reason::Corruption);
            report.first_inconsistent = Some(broken);
            ranges.push(report);
            continue;
        }
        sealed_ends.insert(record.subject, record.end);
        // A later purge record covering this range.
        let purge = records.iter().find(|purge| {
            purge.kind == SealKind::Purge
                && purge.counter > counter
                && purge.subject == record.subject
                && purge.start <= record.start
                && purge.end >= record.end
                && chain_break.is_none_or(|broken| purge.counter < broken)
        });
        if let Some(purge) = purge {
            if signed(purge.counter) && !global.contains(&Reason::ConflictingAnchors) {
                report.outcome = Outcome::Purged;
            } else {
                report.reasons.push(Reason::UnauthenticatedPurge);
                report.first_inconsistent = Some(purge.counter);
            }
            ranges.push(report);
            continue;
        }
        match read(record.subject, record.start, record.end) {
            RangeBytes::Missing => {
                report.reasons.push(Reason::ShortenedIndex);
                report.first_inconsistent = Some(counter);
                ranges.push(report);
                continue;
            }
            RangeBytes::Bytes(bytes) => {
                if verify_range(record, &bytes).is_err() {
                    report.reasons.push(Reason::Corruption);
                    report.first_inconsistent = Some(counter);
                    ranges.push(report);
                    continue;
                }
            }
        }
        report.reasons.extend(global.iter().copied());
        if !report.reasons.is_empty() {
            if !signed(counter) {
                push_unique(&mut report.reasons, Reason::MissingEvidence);
            }
            report.first_inconsistent = Some(counter);
        } else if !signed(counter) {
            report.reasons.push(Reason::MissingEvidence);
            report.first_inconsistent = Some(counter);
        } else if anchors
            .anchored_through
            .is_some_and(|through| counter <= through)
        {
            report.outcome = Outcome::Verified;
        } else {
            report.outcome = Outcome::BeyondAnchor;
            report.reasons.push(Reason::NoAnchor);
        }
        ranges.push(report);
    }
    for &(recording, written) in evidence.written {
        let start = sealed_ends.get(&recording).copied().unwrap_or(0);
        if written > start {
            ranges.push(RangeReport {
                recording,
                start,
                end: written,
                counter: None,
                outcome: Outcome::Unsealed,
                reasons: Vec::new(),
                first_inconsistent: None,
            });
        }
    }
    Verification {
        ranges,
        coverage,
        anchors,
        time: TimeEvidence::NotEvaluated,
    }
}

/// A mismatch a scrub found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubEvent {
    /// When the scrub ran, in ns.
    pub at_ns: u64,
    /// The inconsistent range.
    pub range: RangeReport,
}

/// The scrub: reverifies sealed copies every `interval_ns` and raises an
/// event for every inconsistent range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scrub {
    interval_ns: NonZeroU64,
    next_ns: u64,
}

impl Scrub {
    /// A scrub every `interval_ns`, first due at `first_ns`.
    #[must_use]
    pub const fn new(interval_ns: NonZeroU64, first_ns: u64) -> Self {
        Self {
            interval_ns,
            next_ns: first_ns,
        }
    }

    /// When the next scrub is due, in ns.
    #[must_use]
    #[inline]
    pub const fn next_ns(&self) -> u64 {
        self.next_ns
    }

    /// Runs `verify` if a scrub is due at `now_ns`, returning its events;
    /// `None` when none was due.
    pub fn poll(
        &mut self,
        now_ns: u64,
        verify: impl FnOnce() -> Verification,
    ) -> Option<Vec<ScrubEvent>> {
        if now_ns < self.next_ns {
            return None;
        }
        // Saturating by definition: a next time the clock never reaches
        // means no further scrub.
        self.next_ns = now_ns.saturating_add(self.interval_ns.get());
        let verification = verify();
        Some(
            verification
                .ranges
                .into_iter()
                .filter(|range| range.outcome == Outcome::Inconsistent)
                .map(|range| ScrubEvent {
                    at_ns: now_ns,
                    range,
                })
                .collect(),
        )
    }
}
