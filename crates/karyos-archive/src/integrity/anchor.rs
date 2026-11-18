// SPDX-License-Identifier: Apache-2.0

//! External anchors of the integrity chain (quantstratum-docs:
//! karyos/SPEC.md §8.4, "External anchors"; ADR-0051 item 7; karyos#664).
//!
//! A chain signed on one host cannot by itself detect truncation after its
//! last signed head, a rollback to an earlier head, or a privileged user
//! who re-signs. An [`Anchor`] is a signed head stored where the Archive
//! host cannot rewrite it, with a receipt from that store and the store's
//! own monotonic counter, kept off the host so a rollback of the chain
//! cannot be hidden by rolling the anchor record back too.
//!
//! [`check_anchors`] compares a chain with its anchors and reports, never
//! resolves: an anchor that is not external, untrusted or of a deferred
//! kind carries its reason; two anchors that disagree about one position
//! are equivocation; a chain shorter than an anchored head is truncation;
//! a chain whose record at an anchored position differs is a rollback; a
//! store counter that goes back while the head goes forward, or the other
//! way, is a counter rollback. An anchor proves only the prefix it covers:
//! [`AnchorReport::anchored_through`] is the highest anchored position,
//! and records after it are beyond the anchor. No anchor at all is an
//! absence with its reason ([`AnchorReport::absent`]), neither a pass nor
//! a failure.
//!
//! The kinds of the first release are a replica Archive's journal, a
//! Cluster log entry, an operator anchor exported by `karyos-catalog` and
//! object storage under a retention lock. The RFC 3161 time-stamp kind is
//! deferred: no RFC 3161 client is admitted under ADR-0070, so an anchor
//! of that kind is refused with [`AnchorReason::KindDeferred`].

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::Path;

use super::journal::IntegrityError;
use super::ledger::Ledger;
use crate::disk::Disk;

use super::trust::{
    ChainHead, HeadReason, HeadVerdict, KeyRegistry, SIGNED_HEAD_LENGTH, SignedHead,
    TrustDecodeError,
};
use super::{Digest, SealRecord};

/// The encoded length of an anchor, in bytes.
pub const ANCHOR_LENGTH: usize = 264;

/// The anchor format version.
pub const ANCHOR_VERSION: u16 = 1;

/// Where an anchor is kept. The values are stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum AnchorKind {
    /// The integrity journal of a replica Archive the host cannot rewrite.
    ReplicaJournal = 1,
    /// A Cluster log entry.
    ClusterLog = 2,
    /// An anchor exported by `karyos-catalog` and held by the operator.
    OperatorExport = 3,
    /// Object storage under a retention lock.
    ObjectLock = 4,
    /// An RFC 3161 time-stamp token: deferred, no client is admitted.
    Rfc3161 = 5,
}

impl AnchorKind {
    /// The kind of an on-disk value.
    #[must_use]
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::ReplicaJournal,
            2 => Self::ClusterLog,
            3 => Self::OperatorExport,
            4 => Self::ObjectLock,
            5 => Self::Rfc3161,
            _ => return None,
        })
    }
}

/// A signed head kept outside the Archive host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    /// The kind of store.
    pub kind: AnchorKind,
    /// The store's identity: the replica Archive's id, the cluster's, the
    /// operator's or the bucket's.
    pub location: Digest,
    /// The store's own monotonic counter for this anchor, kept off host.
    pub external_counter: u64,
    /// The digest of the store's receipt or checkpoint for it.
    pub receipt: Digest,
    /// The anchored head.
    pub signed: SignedHead,
}

impl Anchor {
    /// The encoded anchor, version 1, little-endian at fixed offsets:
    /// version `u16`, kind `u8`, five reserved zero bytes, location,
    /// external counter `u64`, receipt, then the signed head.
    #[must_use]
    pub fn encode(&self) -> [u8; ANCHOR_LENGTH] {
        let mut out = [0u8; ANCHOR_LENGTH];
        let fields = [
            &ANCHOR_VERSION.to_le_bytes()[..],
            &[self.kind as u8, 0, 0, 0, 0, 0],
            &self.location,
            &self.external_counter.to_le_bytes(),
            &self.receipt,
            &self.signed.encode(),
        ];
        for (slot, byte) in out.iter_mut().zip(fields.into_iter().flatten()) {
            *slot = *byte;
        }
        out
    }

    /// Reads an encoded anchor.
    ///
    /// # Errors
    ///
    /// [`TrustDecodeError`] for an unknown version or kind, a reserved
    /// byte that is not zero, or a signed head that does not decode.
    pub fn decode(bytes: &[u8; ANCHOR_LENGTH]) -> Result<Self, TrustDecodeError> {
        let reserved = TrustDecodeError::Reserved;
        let (version, rest) = bytes.split_first_chunk::<2>().ok_or(reserved)?;
        let version = u16::from_le_bytes(*version);
        if version != ANCHOR_VERSION {
            return Err(TrustDecodeError::Version { version });
        }
        let (&[kind, zeros @ ..], rest) = rest.split_first_chunk::<6>().ok_or(reserved)?;
        let kind = AnchorKind::from_u8(kind).ok_or(TrustDecodeError::Unknown {
            field: "anchor kind",
            value: kind,
        })?;
        if zeros != [0; 5] {
            return Err(reserved);
        }
        let (location, rest) = rest.split_first_chunk::<32>().ok_or(reserved)?;
        let (counter, rest) = rest.split_first_chunk::<8>().ok_or(reserved)?;
        let (receipt, rest) = rest.split_first_chunk::<32>().ok_or(reserved)?;
        let (signed, _) = rest
            .split_first_chunk::<SIGNED_HEAD_LENGTH>()
            .ok_or(reserved)?;
        Ok(Self {
            kind,
            location: *location,
            external_counter: u64::from_le_bytes(*counter),
            receipt: *receipt,
            signed: SignedHead::decode(signed)?,
        })
    }
}

const _: () = assert!(2 + 6 + 32 + 8 + 32 + SIGNED_HEAD_LENGTH == ANCHOR_LENGTH);

/// What counts as external for one Archive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Externality {
    /// This Archive's identity: an anchor stored here anchors nothing.
    pub local_archive: Digest,
    /// Stores on this host or rewritable from it, such as a local replica.
    pub local_locations: BTreeSet<Digest>,
    /// Archives whose journals this Archive anchors: a replica journal
    /// among them is a circular pair and anchors nothing.
    pub anchored_by_this: BTreeSet<Digest>,
}

/// Why an anchor does not count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnchorReason {
    /// Stored in this Archive.
    NotExternal,
    /// Stored on this host or rewritable from it: a local replica.
    LocalReplica,
    /// A replica Archive this Archive anchors in turn: a circular pair.
    Circular,
    /// A kind whose client is not admitted (RFC 3161).
    KindDeferred,
    /// The anchored head is for another journal.
    WrongJournal,
    /// The anchored head is not trusted evidence.
    Head(HeadReason),
}

impl Externality {
    /// Whether `anchor` is stored outside this Archive's reach.
    ///
    /// # Errors
    ///
    /// The [`AnchorReason`] it does not count.
    pub fn check(&self, anchor: &Anchor) -> Result<(), AnchorReason> {
        if anchor.kind == AnchorKind::Rfc3161 {
            return Err(AnchorReason::KindDeferred);
        }
        if anchor.location == self.local_archive {
            return Err(AnchorReason::NotExternal);
        }
        if self.local_locations.contains(&anchor.location) {
            return Err(AnchorReason::LocalReplica);
        }
        if anchor.kind == AnchorKind::ReplicaJournal
            && self.anchored_by_this.contains(&anchor.location)
        {
            return Err(AnchorReason::Circular);
        }
        Ok(())
    }
}

/// One thing [`check_anchors`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorFinding {
    /// The anchor at `index` does not count.
    Untrusted {
        /// The anchor's index in the list checked.
        index: usize,
        /// Why.
        reason: AnchorReason,
    },
    /// Two trusted anchors name different heads for one position.
    Equivocation {
        /// The position.
        counter: u64,
    },
    /// The chain ends before an anchored head: it was truncated.
    Truncated {
        /// The anchored position.
        anchored: u64,
        /// The chain's record count.
        records: u64,
    },
    /// The chain's record at an anchored position is not the anchored
    /// one: it was rolled back and rewritten.
    Rollback {
        /// The position.
        counter: u64,
    },
    /// A store's counter and the heads it anchors move in opposite
    /// directions: one of its anchors was rolled back.
    CounterRollback {
        /// The store.
        location: Digest,
    },
}

/// Why no anchor covers the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Absence {
    /// No anchor was supplied.
    NoAnchor,
    /// Anchors were supplied, but none counts.
    NoTrustedAnchor,
}

/// What [`check_anchors`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReport {
    /// The highest position a trusted, consistent anchor covers: records
    /// up to it are anchored, records after it are beyond the anchor.
    pub anchored_through: Option<u64>,
    /// The kinds of the anchors that counted.
    pub kinds: BTreeSet<AnchorKind>,
    /// Every finding, in the order found.
    pub findings: Vec<AnchorFinding>,
    /// Why nothing is anchored, when nothing is.
    pub absent: Option<Absence>,
}

impl AnchorReport {
    /// Whether a finding shows tampering or equivocation, as opposed to
    /// anchors that merely do not count.
    #[must_use]
    pub fn is_conflicting(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| !matches!(finding, AnchorFinding::Untrusted { .. }))
    }
}

/// Compares `records`, the chain of journal `journal_id`, with `anchors`.
/// Each anchor's head is verified under `registry` (a head whose key was
/// later revoked counts only when an earlier trusted anchor covers it).
#[must_use]
pub fn check_anchors(
    records: &[SealRecord],
    journal_id: u64,
    anchors: &[Anchor],
    registry: &KeyRegistry,
    externality: &Externality,
) -> AnchorReport {
    let mut report = AnchorReport {
        anchored_through: None,
        kinds: BTreeSet::new(),
        findings: Vec::new(),
        absent: None,
    };
    if anchors.is_empty() {
        report.absent = Some(Absence::NoAnchor);
        return report;
    }
    let mut trusted: Vec<&Anchor> = Vec::new();
    for (index, anchor) in anchors.iter().enumerate() {
        let reason = externality.check(anchor).err().or_else(|| {
            (anchor.signed.head.journal_id != journal_id).then_some(AnchorReason::WrongJournal)
        });
        let reason = reason.or_else(|| match registry.verify(&anchor.signed, None) {
            HeadVerdict::Trusted { .. } => None,
            HeadVerdict::NotTrustedEvidence(reason) | HeadVerdict::Invalid(reason) => {
                Some(AnchorReason::Head(reason))
            }
        });
        match reason {
            Some(reason) => report
                .findings
                .push(AnchorFinding::Untrusted { index, reason }),
            None => trusted.push(anchor),
        }
    }
    // Equivocation: two heads for one position. Neither counts.
    let mut by_counter: BTreeMap<u64, Digest> = BTreeMap::new();
    let mut equivocal = BTreeSet::new();
    for anchor in &trusted {
        let head = &anchor.signed.head;
        match by_counter.get(&head.counter) {
            Some(digest) if *digest != head.digest => {
                if equivocal.insert(head.counter) {
                    report.findings.push(AnchorFinding::Equivocation {
                        counter: head.counter,
                    });
                }
            }
            Some(_) => {}
            None => {
                by_counter.insert(head.counter, head.digest);
            }
        }
    }
    // Counter rollback: per store, the external counter and the head
    // counter must rise together.
    let mut by_location: BTreeMap<Digest, Vec<(u64, u64)>> = BTreeMap::new();
    for anchor in &trusted {
        by_location
            .entry(anchor.location)
            .or_default()
            .push((anchor.external_counter, anchor.signed.head.counter));
    }
    for (location, mut pairs) in by_location {
        pairs.sort_unstable();
        let rolled_back = pairs.windows(2).any(|pair| match pair {
            [(external_a, head_a), (external_b, head_b)] => {
                external_a == external_b || head_b < head_a
            }
            _ => false,
        });
        if rolled_back {
            report
                .findings
                .push(AnchorFinding::CounterRollback { location });
        }
    }
    let records_len = u64::try_from(records.len()).unwrap_or(u64::MAX);
    for anchor in trusted {
        let head = &anchor.signed.head;
        if equivocal.contains(&head.counter) {
            continue;
        }
        let Some(record) = usize::try_from(head.counter)
            .ok()
            .and_then(|index| records.get(index))
        else {
            report.findings.push(AnchorFinding::Truncated {
                anchored: head.counter,
                records: records_len,
            });
            continue;
        };
        if record.digest() != head.digest {
            report.findings.push(AnchorFinding::Rollback {
                counter: head.counter,
            });
            continue;
        }
        report.kinds.insert(anchor.kind);
        report.anchored_through = Some(
            report
                .anchored_through
                .map_or(head.counter, |through| through.max(head.counter)),
        );
    }
    if report.anchored_through.is_none() {
        report.absent = Some(Absence::NoTrustedAnchor);
    }
    report
}

/// Whether `later` extends `earlier`: `between` are the records after
/// `earlier`'s position up to and including `later`'s, and their counters
/// and links run from `earlier`'s digest to `later`'s. An anchor proved
/// this way extends an earlier one rather than merely existing.
#[must_use]
pub fn proves_ancestry(earlier: &ChainHead, later: &ChainHead, between: &[SealRecord]) -> bool {
    let mut expected = earlier.counter.checked_add(1);
    let mut head = earlier.digest;
    for record in between {
        if Some(record.counter) != expected || record.previous != head {
            return false;
        }
        head = record.digest();
        expected = record.counter.checked_add(1);
    }
    head == later.digest && expected == later.counter.checked_add(1)
}

/// What the policy requires of anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorPolicy {
    /// Kinds that must each anchor the chain.
    pub required_kinds: BTreeSet<AnchorKind>,
    /// The most records allowed past the last anchored position.
    pub max_unanchored_records: NonZeroU64,
}

/// A policy requirement the anchors miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyFinding {
    /// No trusted anchor of a required kind.
    MissingKind(AnchorKind),
    /// More records past the last anchor than the policy allows.
    IntervalExceeded {
        /// Records past the last anchored position.
        unanchored: u64,
    },
}

impl AnchorPolicy {
    /// Checks `report`, for a chain of `records` records, against the
    /// policy.
    #[must_use]
    pub fn check(&self, report: &AnchorReport, records: u64) -> Vec<PolicyFinding> {
        let mut findings: Vec<PolicyFinding> = self
            .required_kinds
            .difference(&report.kinds)
            .map(|kind| PolicyFinding::MissingKind(*kind))
            .collect();
        let covered = report
            .anchored_through
            .and_then(|through| through.checked_add(1))
            .unwrap_or(0);
        // Saturating by definition: a chain shorter than its anchors has
        // nothing unanchored (the truncation is a finding of its own).
        let unanchored = records.saturating_sub(covered);
        if unanchored > self.max_unanchored_records.get() {
            findings.push(PolicyFinding::IntervalExceeded { unanchored });
        }
        findings
    }
}

/// A store anchors are published to.
pub trait AnchorStore {
    /// The kind of store.
    fn kind(&self) -> AnchorKind;

    /// The store's identity.
    fn location(&self) -> Digest;

    /// Stores `signed`, returning the store's counter for it and the
    /// digest of its receipt.
    ///
    /// # Errors
    ///
    /// The store's error.
    fn publish(&mut self, signed: &SignedHead) -> std::io::Result<(u64, Digest)>;
}

/// Publishes the latest signed head to `store` once `every_records`
/// records have been signed past the last anchor, returning the anchor
/// published, if any. Everything a third party needs to check it is in
/// the anchor: the signed head, the store's counter and the receipt.
///
/// # Errors
///
/// The store's error; nothing is recorded as anchored then.
pub fn publish_due(
    store: &mut impl AnchorStore,
    last_anchored: Option<u64>,
    latest: Option<&SignedHead>,
    every_records: NonZeroU64,
) -> std::io::Result<Option<Anchor>> {
    let Some(latest) = latest else {
        return Ok(None);
    };
    let due = last_anchored.is_none_or(|anchored| {
        latest
            .head
            .counter
            .checked_sub(anchored)
            .is_some_and(|gap| gap >= every_records.get())
    });
    if !due {
        return Ok(None);
    }
    let (external_counter, receipt) = store.publish(latest)?;
    Ok(Some(Anchor {
        kind: store.kind(),
        location: store.location(),
        external_counter,
        receipt,
        signed: *latest,
    }))
}

/// An [`AnchorStore`] kept as a [`Ledger`] of encoded anchors in a
/// directory the Archive does not control: the operator's export
/// directory, or a mounted replica's. Its counter is the anchor's index
/// in the ledger and its receipt the digest of the bytes stored.
#[derive(Debug)]
pub struct LedgerAnchorStore<D: Disk> {
    kind: AnchorKind,
    location: Digest,
    ledger: Ledger<D, ANCHOR_LENGTH>,
}

impl<D: Disk> LedgerAnchorStore<D> {
    /// The anchor file in `dir`, the store `location` of kind `kind`.
    ///
    /// # Errors
    ///
    /// As [`Ledger::open`].
    pub fn open(
        disk: D,
        dir: &Path,
        kind: AnchorKind,
        location: Digest,
    ) -> Result<Self, IntegrityError> {
        Ok(Self {
            kind,
            location,
            ledger: Ledger::open(disk, dir, ANCHOR_FILE)?,
        })
    }

    /// The anchors stored, oldest first; one that does not decode is
    /// skipped, and the verifier reports what is missing.
    #[must_use]
    pub fn anchors(&self) -> Vec<Anchor> {
        self.ledger
            .entries()
            .iter()
            .filter_map(|bytes| Anchor::decode(bytes).ok())
            .collect()
    }
}

/// The anchor file's name in a store's directory.
pub const ANCHOR_FILE: &str = "anchors.kya";

impl<D: Disk> AnchorStore for LedgerAnchorStore<D> {
    fn kind(&self) -> AnchorKind {
        self.kind
    }

    fn location(&self) -> Digest {
        self.location
    }

    fn publish(&mut self, signed: &SignedHead) -> std::io::Result<(u64, Digest)> {
        let counter = u64::try_from(self.ledger.entries().len())
            .map_err(|_| std::io::Error::other("anchor counter overflow"))?;
        let anchor = Anchor {
            kind: self.kind,
            location: self.location,
            external_counter: counter,
            receipt: [0; 32],
            signed: *signed,
        };
        let bytes = anchor.encode();
        self.ledger.append(bytes).map_err(|error| match error {
            IntegrityError::Io(error) => error,
            other => std::io::Error::other(other.to_string()),
        })?;
        Ok((counter, super::digest(&bytes)))
    }
}
