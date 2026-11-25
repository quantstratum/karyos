// SPDX-License-Identifier: Apache-2.0

//! Retention policy, crash-safe purge and legal hold (quantstratum-docs:
//! karyos/SPEC.md §8.4, "Retention policy" and "Purge and legal hold";
//! ADR-0051 items 1 and 15; R-CORE-22; karyos#667).
//!
//! # Policy
//!
//! A [`RetentionPolicy`] states `retain_for` (a duration the operator
//! sets; no regulatory period is written in this code), `min_copies`,
//! `storage_tier` and `purge = manual | after_expiry`. Each version is
//! chained in the integrity journal ([`PolicyBook::record`]), so the policy
//! in force for a segment can be shown later. A policy binds to a
//! recording or to a recording class selected by channel and stream; a
//! recording's own binding wins.
//!
//! # Holds before purges
//!
//! Legal holds and recovery needs outrank purge targets: every purge
//! check looks at holds first. A hold is applied without waiting on the
//! operations journal ([`Retention::apply_hold`]): it inhibits at once and
//! is remembered in a local pending marker, and it is reported applied
//! only with the journal's evidence. A release needs that evidence and a
//! journal that records it, or it fails closed. At restart a pending
//! hold still inhibits, and when hold state cannot be read at all every
//! purge is inhibited until it can.
//!
//! # Purge
//!
//! A purge deletes through the existing crash-safe primitive,
//! [`SegmentStore::purge_before`]. It is refused, and the refusal is
//! journalled with its reason, unless it is authorised, no hold applies,
//! the retention has expired and the other verified copies satisfy
//! `min_copies`. An accepted purge journals its intent durably first,
//! deletes, then records the purge in the integrity journal with the
//! digest of the purged range's seals, and journals its completion. After a
//! crash, [`Retention::recover_purges`] rechecks authorisation, holds,
//! policy and copies before completing an outstanding intent, so an
//! earlier intent never overrides a later hold or policy change. A purge
//! never touches the key registry.
//!
//! `--archive-min-free` (default 1 GiB) stays: a free-space floor
//! complements retention and never proves it.

use std::collections::BTreeMap;
use std::io;
use std::num::NonZeroU32;

use sha2::{Digest as _, Sha256};

use super::copies::{CopyCatalog, ImmutabilityBackend};
use super::journal::{IntegrityError, IntegrityJournal};
use super::ledger::Ledger;
use super::{Digest, SealKind, SealRecord, digest};
use crate::disk::Disk;
use crate::segment::{SegmentError, SegmentStore};

/// The operations journal's file name in the archive directory.
pub const OPERATIONS_FILE: &str = "operations.kyo";

/// The pending holds' marker file name in the archive directory.
pub const PENDING_HOLDS_FILE: &str = "holds.kyp";

/// The encoded length of a pending hold marker: the recording `u64`,
/// then 1 for pending or 2 for resolved (evidenced or released).
pub const MARKER_LENGTH: usize = 16;

fn marker(recording: u64, resolved: bool) -> [u8; MARKER_LENGTH] {
    let mut out = [0u8; MARKER_LENGTH];
    let state: u64 = if resolved { 2 } else { 1 };
    for (slot, byte) in out.iter_mut().zip(
        recording
            .to_le_bytes()
            .into_iter()
            .chain(state.to_le_bytes()),
    ) {
        *slot = byte;
    }
    out
}

/// The encoded length of an operation record, in bytes.
pub const OPERATION_LENGTH: usize = 56;

/// When a purge may happen. The values are stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum PurgeMode {
    /// Only by an explicit operator request after expiry.
    Manual = 1,
    /// By the Archive's own schedule after expiry, or an operator request.
    AfterExpiry = 2,
}

/// A retention policy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// The policy's identity.
    pub policy: u64,
    /// Its version: each change is a new, higher version.
    pub version: u64,
    /// How long a range is kept after it closes, in ns. Set by the
    /// operator; nothing here defaults it.
    pub retain_for_ns: u64,
    /// The verified copies that must remain elsewhere before a local
    /// purge.
    pub min_copies: NonZeroU32,
    /// The storage tier, an operator-defined code.
    pub storage_tier: u8,
    /// When a purge may happen.
    pub purge: PurgeMode,
}

impl RetentionPolicy {
    /// The canonical bytes chained in the integrity journal, version 1:
    /// policy, version and `retain_for` `u64`s, `min_copies` `u32`, tier
    /// and purge mode, little-endian.
    #[must_use]
    pub fn canonical(&self) -> [u8; 30] {
        let mut out = [0u8; 30];
        let fields = [
            &self.policy.to_le_bytes()[..],
            &self.version.to_le_bytes(),
            &self.retain_for_ns.to_le_bytes(),
            &self.min_copies.get().to_le_bytes(),
            &[self.storage_tier, self.purge as u8],
        ];
        for (slot, byte) in out.iter_mut().zip(fields.into_iter().flatten()) {
            *slot = *byte;
        }
        out
    }
}

/// What a policy binds to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selector {
    /// One recording.
    Recording(u64),
    /// Every recording of a channel and stream.
    Class {
        /// The channel.
        channel: Vec<u8>,
        /// The stream id.
        stream_id: i32,
    },
}

/// Why a policy change was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// A version not above the policy's current one.
    #[error("policy {policy} version {version} does not follow version {current}")]
    Version {
        /// The policy.
        policy: u64,
        /// The version offered.
        version: u64,
        /// The current version.
        current: u64,
    },
    /// A binding to a policy never recorded.
    #[error("policy {policy} is not recorded")]
    Unknown {
        /// The policy.
        policy: u64,
    },
}

/// The policy book's file name in the archive directory.
pub const POLICIES_FILE: &str = "policies.kyl";

/// The encoded length of a policy book entry, in bytes.
pub const POLICY_ENTRY_LENGTH: usize = 64;

/// The integrity journal subject of the policy book's bindings, chained as
/// catalog changes with the entry's sequence as generation.
pub const POLICY_BOOK_SUBJECT: u64 = u64::MAX;

/// A binding's key: a recording, or a class by its channel's digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Recording(u64),
    Class(Digest, i32),
}

impl Key {
    fn of(selector: &Selector) -> Self {
        match selector {
            Selector::Recording(recording) => Self::Recording(*recording),
            Selector::Class { channel, stream_id } => Self::Class(digest(channel), *stream_id),
        }
    }
}

/// The policies in force and what they bind to, kept in a ledger whose
/// entries count only once the integrity journal chains them, so a
/// restart restores the effective state.
#[derive(Debug)]
pub struct PolicyBook<D: Disk> {
    ledger: Ledger<D, POLICY_ENTRY_LENGTH>,
    current: BTreeMap<u64, RetentionPolicy>,
    bindings: BTreeMap<Key, u64>,
}

impl<D: Disk> PolicyBook<D> {
    /// Opens the policy book of `dir`, restoring each policy version and
    /// binding that `journal` chains, in order. An entry stored before a
    /// crash or a failed journal append is not committed and is skipped.
    ///
    /// # Errors
    ///
    /// As [`Ledger::open`] and [`IntegrityJournal::records`];
    /// [`IntegrityError::Unrecorded`] when the journal chains a policy
    /// version or binding the ledger no longer holds, or holds damaged.
    pub fn open(
        disk: D,
        dir: &std::path::Path,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<Self, IntegrityError> {
        let ledger = Ledger::open(disk, dir, POLICIES_FILE)?;
        let records = journal.records()?;
        let chained = |kind: SealKind, subject: u64, start: u64, content: Digest| {
            records.iter().any(|record| {
                record.kind == kind
                    && record.subject == subject
                    && record.start == start
                    && record.content == content
            })
        };
        let mut book = Self {
            ledger,
            current: BTreeMap::new(),
            bindings: BTreeMap::new(),
        };
        let entries = book.ledger.entries().to_vec();
        // Every committed policy version and binding must still be in the
        // ledger, valid: a lost or damaged one could let an older, shorter
        // retention govern again, so it fails closed.
        let held: std::collections::BTreeSet<(u16, u64, u64, Digest)> = (0u64..)
            .zip(entries.iter())
            .filter_map(|(sequence, entry)| match decode_entry(entry)? {
                Entry::Policy(policy) => Some((
                    SealKind::Policy as u16,
                    policy.policy,
                    policy.version,
                    digest(&policy.canonical()),
                )),
                Entry::Binding(..) => Some((
                    SealKind::Catalog as u16,
                    POLICY_BOOK_SUBJECT,
                    sequence,
                    digest(entry),
                )),
            })
            .collect();
        for record in &records {
            let committed = record.kind == SealKind::Policy
                || (record.kind == SealKind::Catalog && record.subject == POLICY_BOOK_SUBJECT);
            if committed
                && !held.contains(&(
                    record.kind as u16,
                    record.subject,
                    record.start,
                    record.content,
                ))
            {
                return Err(IntegrityError::Unrecorded {
                    counter: record.counter,
                });
            }
        }
        for (sequence, entry) in (0u64..).zip(entries.iter()) {
            match decode_entry(entry) {
                Some(Entry::Policy(policy))
                    if book
                        .current
                        .get(&policy.policy)
                        .is_none_or(|current| policy.version > current.version)
                        && chained(
                            SealKind::Policy,
                            policy.policy,
                            policy.version,
                            digest(&policy.canonical()),
                        ) =>
                {
                    book.current.insert(policy.policy, policy);
                }
                Some(Entry::Binding(key, policy))
                    if book.current.contains_key(&policy)
                        && chained(
                            SealKind::Catalog,
                            POLICY_BOOK_SUBJECT,
                            sequence,
                            digest(entry),
                        ) =>
                {
                    book.bindings.insert(key, policy);
                }
                _ => {}
            }
        }
        Ok(book)
    }

    /// The version of `policy` in force, if one was recorded.
    #[must_use]
    pub fn current(&self, policy: u64) -> Option<RetentionPolicy> {
        self.current.get(&policy).copied()
    }

    /// Records the operator's configured `policy` when its terms differ
    /// from the version in force, as the next version (or as configured,
    /// when none was recorded); an unchanged one records nothing
    /// (karyos#1123). Returns the version purges are checked against: the
    /// one in force afterwards. The configured version number is only a
    /// starting point: the book's own order wins.
    ///
    /// # Errors
    ///
    /// As [`PolicyBook::record`]; [`IntegrityError::Policy`] when the next
    /// version would pass `u64::MAX`.
    pub fn record_configured(
        &mut self,
        policy: RetentionPolicy,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<RetentionPolicy, IntegrityError> {
        let next = match self.current(policy.policy) {
            Some(current)
                if RetentionPolicy {
                    version: current.version,
                    ..policy
                } == current =>
            {
                return Ok(current);
            }
            Some(current) => RetentionPolicy {
                version: current.version.checked_add(1).ok_or(PolicyError::Version {
                    policy: policy.policy,
                    version: current.version,
                    current: current.version,
                })?,
                ..policy
            },
            None => policy,
        };
        self.record(next, journal)?;
        Ok(next)
    }

    /// Records a new policy version: stored, then chained in `journal`,
    /// and only then in force.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Policy`] for a version that does not rise over the
    /// restored state, with nothing written; the ledger's or the journal's
    /// error.
    pub fn record(
        &mut self,
        policy: RetentionPolicy,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<SealRecord, IntegrityError> {
        if let Some(current) = self.current.get(&policy.policy)
            && policy.version <= current.version
        {
            return Err(PolicyError::Version {
                policy: policy.policy,
                version: policy.version,
                current: current.version,
            }
            .into());
        }
        let canonical = policy.canonical();
        let mut entry = [0u8; POLICY_ENTRY_LENGTH];
        for (slot, byte) in entry.iter_mut().zip(core::iter::once(1).chain(canonical)) {
            *slot = byte;
        }
        self.ledger.append(entry)?;
        let record = journal.record_policy_version(policy.policy, policy.version, &canonical)?;
        self.current.insert(policy.policy, policy);
        Ok(record)
    }

    /// Binds `selector` to `policy`: stored, then chained in `journal`.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Policy`] with [`PolicyError::Unknown`] for a
    /// policy never recorded; the ledger's or the journal's error.
    pub fn bind(
        &mut self,
        selector: &Selector,
        policy: u64,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<SealRecord, IntegrityError> {
        if !self.current.contains_key(&policy) {
            return Err(PolicyError::Unknown { policy }.into());
        }
        let key = Key::of(selector);
        let entry = encode_binding(key, policy);
        let sequence =
            u64::try_from(self.ledger.entries().len()).map_err(|_| IntegrityError::Overflow)?;
        self.ledger.append(entry)?;
        let record = journal.record_catalog_change(POLICY_BOOK_SUBJECT, sequence, &entry)?;
        self.bindings.insert(key, policy);
        Ok(record)
    }

    /// The policy in force for a recording of `channel` and `stream_id`:
    /// its own binding first, then its class's.
    #[must_use]
    pub fn resolve(
        &self,
        recording: u64,
        channel: &[u8],
        stream_id: i32,
    ) -> Option<&RetentionPolicy> {
        self.bindings
            .get(&Key::Recording(recording))
            .or_else(|| self.bindings.get(&Key::Class(digest(channel), stream_id)))
            .and_then(|policy| self.current.get(policy))
    }
}

/// A decoded policy book entry.
enum Entry {
    Policy(RetentionPolicy),
    Binding(Key, u64),
}

/// A binding entry: kind 2, the selector's tag at 1, the policy at 8, the
/// recording at 16 or the stream id at 24 and the channel digest at 32.
fn encode_binding(key: Key, policy: u64) -> [u8; POLICY_ENTRY_LENGTH] {
    let mut entry = [0u8; POLICY_ENTRY_LENGTH];
    let (tag, recording, stream_id, channel) = match key {
        Key::Recording(recording) => (1u8, recording, 0i32, [0u8; 32]),
        Key::Class(channel, stream_id) => (2u8, 0, stream_id, channel),
    };
    let fields: [&[u8]; 7] = [
        &[2, tag, 0, 0, 0, 0, 0, 0],
        &policy.to_le_bytes(),
        &recording.to_le_bytes(),
        &stream_id.to_le_bytes(),
        &[0; 4],
        &channel,
        &[],
    ];
    for (slot, byte) in entry.iter_mut().zip(fields.into_iter().flatten()) {
        *slot = *byte;
    }
    entry
}

fn decode_entry(entry: &[u8; POLICY_ENTRY_LENGTH]) -> Option<Entry> {
    let u64_at = |at: usize| {
        entry
            .get(at..)
            .and_then(|rest| rest.first_chunk::<8>())
            .map(|bytes| u64::from_le_bytes(*bytes))
    };
    match entry.first()? {
        1 => {
            let purge = match entry.get(30)? {
                1 => PurgeMode::Manual,
                2 => PurgeMode::AfterExpiry,
                _ => return None,
            };
            let min_copies = entry
                .get(25..)
                .and_then(|rest| rest.first_chunk::<4>())
                .map(|bytes| u32::from_le_bytes(*bytes))
                .and_then(NonZeroU32::new)?;
            Some(Entry::Policy(RetentionPolicy {
                policy: u64_at(1)?,
                version: u64_at(9)?,
                retain_for_ns: u64_at(17)?,
                min_copies,
                storage_tier: *entry.get(29)?,
                purge,
            }))
        }
        2 => {
            let policy = u64_at(8)?;
            let key = match entry.get(1)? {
                1 => Key::Recording(u64_at(16)?),
                2 => {
                    let stream_id = entry
                        .get(24..)
                        .and_then(|rest| rest.first_chunk::<4>())
                        .map(|bytes| i32::from_le_bytes(*bytes))?;
                    let channel = entry.get(32..)?.first_chunk::<32>().copied()?;
                    Key::Class(channel, stream_id)
                }
                _ => return None,
            };
            Some(Entry::Binding(key, policy))
        }
        _ => None,
    }
}

/// An operation the operations journal records. The kind values are
/// stable on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    /// A hold applied to a recording.
    HoldApplied {
        /// The recording.
        recording: u64,
    },
    /// A hold released.
    HoldReleased {
        /// The recording.
        recording: u64,
    },
    /// A purge's durable intent, before any deletion.
    PurgeIntent {
        /// The purge's id.
        id: u64,
        /// The recording.
        recording: u64,
        /// The first position kept.
        before: u64,
        /// The operator who asked.
        operator: u64,
        /// When the purged range closed, in ns.
        closed_ns: u64,
        /// Who started it, kept in the reason byte.
        source: PurgeSource,
        /// The recording's start when the intent was made: the purged
        /// range is `[from, before)`, recorded as such after a crash too.
        from: u64,
    },
    /// A purge refused, with its reason.
    PurgeRejected {
        /// The purge's id.
        id: u64,
        /// The recording.
        recording: u64,
        /// The reason's code ([`PurgeRefusal::code`]).
        reason: u8,
    },
    /// A purge completed.
    PurgeDone {
        /// The purge's id.
        id: u64,
    },
    /// An outstanding purge cancelled by recovery's recheck.
    PurgeCancelled {
        /// The purge's id.
        id: u64,
        /// The reason's code.
        reason: u8,
    },
    /// A writer closed the segment `[base, end)` of `recording` at
    /// `closed_ns` on the host's wall clock (ADR-0115): the agent's
    /// operations journal's expiry clock. Holds and intents ignore it.
    SegmentClosed {
        /// The recording.
        recording: u64,
        /// The segment's base.
        base: u64,
        /// Its end, exclusive.
        end: u64,
        /// When it closed, in ns of the host's wall clock.
        closed_ns: u64,
    },
}

impl Operation {
    /// The encoded record: kind, reason, six reserved zero bytes, then
    /// six `u64` fields, little-endian.
    #[must_use]
    pub fn encode(&self) -> [u8; OPERATION_LENGTH] {
        let (kind, reason, fields) = match *self {
            Self::HoldApplied { recording } => (1, 0, [recording, 0, 0, 0, 0, 0]),
            Self::HoldReleased { recording } => (2, 0, [recording, 0, 0, 0, 0, 0]),
            Self::PurgeIntent {
                id,
                recording,
                before,
                operator,
                closed_ns,
                source,
                from,
            } => (
                3,
                source as u8,
                [id, recording, before, operator, closed_ns, from],
            ),
            Self::PurgeRejected {
                id,
                recording,
                reason,
            } => (4, reason, [id, recording, 0, 0, 0, 0]),
            Self::PurgeDone { id } => (5, 0, [id, 0, 0, 0, 0, 0]),
            Self::PurgeCancelled { id, reason } => (6, reason, [id, 0, 0, 0, 0, 0]),
            Self::SegmentClosed {
                recording,
                base,
                end,
                closed_ns,
            } => (7, 0, [recording, base, end, closed_ns, 0, 0]),
        };
        let mut out = [0u8; OPERATION_LENGTH];
        let head = [kind, reason, 0, 0, 0, 0, 0, 0];
        let words = fields.iter().flat_map(|field| field.to_le_bytes());
        for (slot, byte) in out.iter_mut().zip(head.into_iter().chain(words)) {
            *slot = byte;
        }
        out
    }

    /// Reads an encoded record; `None` for an unknown kind.
    #[must_use]
    pub fn decode(bytes: &[u8; OPERATION_LENGTH]) -> Option<Self> {
        let word = |index: usize| {
            index
                .checked_mul(8)
                .and_then(|at| at.checked_add(8))
                .and_then(|at| bytes.get(at..))
                .and_then(|rest| rest.first_chunk::<8>())
                .map_or(0, |chunk| u64::from_le_bytes(*chunk))
        };
        let [kind, reason, ..] = *bytes;
        Some(match kind {
            1 => Self::HoldApplied { recording: word(0) },
            2 => Self::HoldReleased { recording: word(0) },
            3 => Self::PurgeIntent {
                id: word(0),
                recording: word(1),
                before: word(2),
                operator: word(3),
                closed_ns: word(4),
                from: word(5),
                source: match reason {
                    0 => PurgeSource::Operator,
                    1 => PurgeSource::Schedule,
                    _ => return None,
                },
            },
            4 => Self::PurgeRejected {
                id: word(0),
                recording: word(1),
                reason,
            },
            5 => Self::PurgeDone { id: word(0) },
            6 => Self::PurgeCancelled {
                id: word(0),
                reason,
            },
            7 => Self::SegmentClosed {
                recording: word(0),
                base: word(1),
                end: word(2),
                closed_ns: word(3),
            },
            _ => return None,
        })
    }
}

/// The operations journal: where holds and purges are recorded. It may
/// be unavailable; then risk-reducing actions proceed and risk-increasing
/// ones fail closed.
pub trait OperationsJournal {
    /// Appends `operation` durably, returning the digest of the record as
    /// evidence.
    ///
    /// # Errors
    ///
    /// The journal is unavailable or failed.
    fn append(&mut self, operation: &Operation) -> io::Result<Digest>;
}

impl<D: Disk> OperationsJournal for Ledger<D, OPERATION_LENGTH> {
    fn append(&mut self, operation: &Operation) -> io::Result<Digest> {
        let bytes = operation.encode();
        Ledger::append(self, bytes).map_err(|error| match error {
            IntegrityError::Io(error) => error,
            other => io::Error::other(other.to_string()),
        })?;
        Ok(digest(&bytes))
    }
}

/// A recording's hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hold {
    /// Requested, not yet evidenced by the operations journal: inhibits.
    Pending,
    /// Applied, with the journal record's digest as evidence: inhibits.
    Applied {
        /// The evidence.
        evidence: Digest,
    },
}

/// What applying a hold reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum HoldReport {
    /// Applied, with evidence.
    Applied {
        /// The evidence.
        evidence: Digest,
    },
    /// In force but not evidenced: the operations journal is unavailable.
    /// Its pending marker is durable, so it inhibits purge and survives
    /// restart; it is not reported applied.
    PendingNoEvidence,
    /// In force in this process only: neither the operations journal nor
    /// the pending marker recorded it, so it does not survive a restart.
    /// It inhibits purge here and is not reported applied.
    InMemoryOnly,
}

/// Why a hold could not be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReleaseError {
    /// The hold has no evidence of being applied: release fails closed.
    #[error("recording {recording}'s hold has no evidence; release fails closed")]
    NoEvidence {
        /// The recording.
        recording: u64,
    },
    /// The operations journal did not record the release: fails closed.
    #[error("the operations journal is unavailable; release fails closed")]
    JournalUnavailable,
    /// Hold state is unknown since restart.
    #[error("hold state is unknown; release fails closed")]
    Unknown,
    /// The journal holds the release but its resolving marker could not be
    /// written: the hold stays pending, and a retry completes the release.
    #[error("recording {recording}'s release is recorded but not yet resolved; retry")]
    Unconfirmed {
        /// The recording.
        recording: u64,
    },
}

impl ReleaseError {
    /// The reason's name in a control answer (ADR-0088): `no_evidence`
    /// and the rest, one per variant.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::NoEvidence { .. } => "no_evidence",
            Self::JournalUnavailable => "journal_unavailable",
            Self::Unknown => "holds_unknown",
            Self::Unconfirmed { .. } => "unconfirmed",
        }
    }
}

/// Who asks for a purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorisation {
    /// The operator.
    pub operator: u64,
    /// Whether the management path authorised the request (ADR-0055).
    pub authorised: bool,
}

/// Who started a purge: the policy's purge mode decides which may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PurgeSource {
    /// An operator, through the management path.
    Operator = 0,
    /// The Archive's own schedule.
    Schedule = 1,
}

/// A purge request: delete `recording`'s range before `before`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeRequest {
    /// The request's id.
    pub id: u64,
    /// The recording.
    pub recording: u64,
    /// The first position to keep.
    pub before: u64,
    /// Who asks.
    pub authorisation: Authorisation,
    /// When the range to purge closed, in ns of UTC.
    pub closed_ns: u64,
    /// Who started it.
    pub source: PurgeSource,
}

/// Why a purge is refused. Codes are stable in the operations journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PurgeRefusal {
    /// The request is not authorised.
    #[error("the purge is not authorised")]
    NotAuthorised,
    /// A legal hold applies.
    #[error("a legal hold applies")]
    LegalHold,
    /// Hold state cannot be evaluated: purge is inhibited.
    #[error("hold state is unknown; purge is inhibited")]
    HoldsUnknown,
    /// No policy is in force for the recording.
    #[error("no retention policy applies")]
    NoPolicy,
    /// The retention has not expired.
    #[error("retention runs until {expires_ns} ns")]
    NotExpired {
        /// When it expires.
        expires_ns: u64,
    },
    /// Too few verified copies elsewhere.
    #[error("{verified} verified copies elsewhere, {required} required")]
    BelowMinCopies {
        /// The verified copies elsewhere.
        verified: u64,
        /// The policy's `min_copies`.
        required: u32,
    },
    /// The operations journal could not record the intent: fails closed.
    #[error("the operations journal is unavailable; purge fails closed")]
    JournalUnavailable,
    /// The store given is another recording's.
    #[error("the store is recording {store}'s, the request is for {recording}")]
    WrongStore {
        /// The request's recording.
        recording: u64,
        /// The store's.
        store: u64,
    },
    /// The cutoff is not where a write starts, or not a position the
    /// store can purge to: the recording would begin inside a write, or
    /// the deletion would fail after its intent.
    #[error("the cutoff {before} is not a write start the store can purge to")]
    NotAWriteStart {
        /// The cutoff.
        before: u64,
    },
    /// The seals do not reach the cutoff.
    #[error("the cutoff {before} is past the sealed end {sealed}")]
    NotSealed {
        /// The cutoff.
        before: u64,
        /// Where the recording's seals end.
        sealed: u64,
    },
    /// Another purge with this id is outstanding.
    #[error("purge {id} is already outstanding")]
    DuplicateId {
        /// The id.
        id: u64,
    },
    /// The policy purges only on an operator's request; the schedule may
    /// not.
    #[error("the policy purges only on an operator's request")]
    ManualOnly,
    /// The cutoff falls inside a sealed range, which a purge would split.
    #[error("the cutoff {before} falls inside the range sealed by record {counter}")]
    SplitsSeal {
        /// The cutoff.
        before: u64,
        /// The seal record's counter.
        counter: u64,
    },
    /// The recording has no recorded close time (ADR-0093): it still
    /// records, or it stopped before close times were recorded.
    #[error("the recording has no recorded close time")]
    NoCloseTime,
    /// Segments of the recording are offloaded to object storage
    /// (ADR-0104, decision 5): no purge interval may intersect them, so
    /// the recording cannot be purged until they are restored.
    #[error("the recording's segments from {lowest} to {start} are offloaded")]
    Offloaded {
        /// The recording's lowest retained position, the offload floor.
        lowest: u64,
        /// Its local start, the end of the offloaded segments.
        start: u64,
    },
}

impl PurgeRefusal {
    /// The reason's name in a control answer (ADR-0088): `legal_hold`,
    /// `not_expired`, `below_min_copies` and the rest, one per variant.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::NotAuthorised => "not_authorised",
            Self::LegalHold => "legal_hold",
            Self::HoldsUnknown => "holds_unknown",
            Self::NoPolicy => "no_policy",
            Self::NotExpired { .. } => "not_expired",
            Self::BelowMinCopies { .. } => "below_min_copies",
            Self::JournalUnavailable => "journal_unavailable",
            Self::WrongStore { .. } => "wrong_store",
            Self::NotAWriteStart { .. } => "not_a_write_start",
            Self::NotSealed { .. } => "not_sealed",
            Self::DuplicateId { .. } => "duplicate_id",
            Self::ManualOnly => "manual_only",
            Self::SplitsSeal { .. } => "splits_seal",
            Self::NoCloseTime => "no_close_time",
            Self::Offloaded { .. } => "offloaded",
        }
    }

    /// The reason's code in the operations journal.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Self::NotAuthorised => 1,
            Self::LegalHold => 2,
            Self::HoldsUnknown => 3,
            Self::NoPolicy => 4,
            Self::NotExpired { .. } => 5,
            Self::BelowMinCopies { .. } => 6,
            Self::JournalUnavailable => 7,
            Self::WrongStore { .. } => 8,
            Self::SplitsSeal { .. } => 9,
            Self::NotAWriteStart { .. } => 10,
            Self::DuplicateId { .. } => 11,
            Self::ManualOnly => 12,
            Self::NotSealed { .. } => 13,
            Self::NoCloseTime => 14,
            Self::Offloaded { .. } => 15,
        }
    }
}

/// A purge's failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PurgeError {
    /// Refused before anything was deleted; `journalled` says whether the
    /// refusal reached the operations journal.
    #[error("purge refused: {refusal}")]
    Refused {
        /// Why.
        refusal: PurgeRefusal,
        /// Whether the refusal was journalled.
        journalled: bool,
    },
    /// The segment store failed.
    #[error("purge: {0}")]
    Store(#[from] SegmentError),
    /// The integrity journal failed.
    #[error("purge: {0}")]
    Integrity(#[from] IntegrityError),
    /// The operations journal failed after the deletion.
    #[error("purge: operations journal: {0}")]
    Operations(io::Error),
    /// A segment's immutability could not be released before its deletion
    /// (karyos#995): nothing was deleted, and the intent stays outstanding
    /// for [`Retention::recover_purges`].
    #[error("purge: releasing the immutability of {path}: {error}", path = path.display())]
    Release {
        /// The segment file.
        path: std::path::PathBuf,
        /// The backend's error.
        error: io::Error,
    },
}

/// The immutability backend a purge releases segments through.
struct Releaser(Box<dyn ImmutabilityBackend + Send>);

impl std::fmt::Debug for Releaser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Releaser")
    }
}

/// What a purge decision needs to know besides the request.
#[derive(Debug, Clone, Copy)]
pub struct PurgeContext<'a, D: Disk> {
    /// The policy in force, if any.
    pub policy: Option<&'a RetentionPolicy>,
    /// The copy catalog.
    pub copies: &'a CopyCatalog<D>,
    /// This Archive's location id, whose copy the purge removes.
    pub local: Digest,
    /// The current time, in ns of UTC.
    pub now_ns: u64,
}

/// Holds and intents rebuilt from the operations journal.
struct Rebuilt {
    holds: BTreeMap<u64, Hold>,
    intents: BTreeMap<u64, PurgeRequest>,
    froms: BTreeMap<u64, u64>,
    released: std::collections::BTreeSet<u64>,
}

/// Retention state: holds and the operations journal.
#[derive(Debug)]
pub struct Retention<J, D: Disk> {
    operations: J,
    pending: Ledger<D, MARKER_LENGTH>,
    holds: BTreeMap<u64, Hold>,
    holds_unknown: bool,
    intents: BTreeMap<u64, PurgeRequest>,
    /// Each outstanding intent's original start.
    froms: BTreeMap<u64, u64>,
    /// Recordings whose release the journal holds, though a pending
    /// marker may still reinstate their hold: a retry only resolves it.
    released: std::collections::BTreeSet<u64>,
    /// The backend a purge releases each segment's immutability through
    /// before deleting it; none releases nothing.
    immutability: Option<Releaser>,
}

impl<J: OperationsJournal, D: Disk> Retention<J, D> {
    /// Sets the backend a purge releases each segment's immutability
    /// through (karyos#995): only after every retention check passed and
    /// the intent is journalled, right before the deletion. Without it, a
    /// purge releases nothing, which suits a store whose segments were
    /// never made immutable.
    pub fn set_immutability(&mut self, backend: Box<dyn ImmutabilityBackend + Send>) {
        self.immutability = Some(Releaser(backend));
    }

    /// Rebuilds retention state at start from the operations journal's
    /// records (`None` when they cannot be read) and the pending markers.
    /// Unreadable hold state inhibits every purge until a later
    /// [`Retention::holds_readable`].
    #[must_use]
    pub fn recover(
        operations: J,
        records: Option<&[[u8; OPERATION_LENGTH]]>,
        pending: Ledger<D, MARKER_LENGTH>,
    ) -> Self {
        let mut state = Self {
            operations,
            pending,
            holds: BTreeMap::new(),
            holds_unknown: true,
            intents: BTreeMap::new(),
            froms: BTreeMap::new(),
            released: std::collections::BTreeSet::new(),
            immutability: None,
        };
        if let Some(records) = records {
            let _ = state.replay(records);
        }
        state.merge_pending();
        state
    }

    /// Rebuilds holds and intents from the operations journal's `records`.
    /// True when every record decoded; otherwise hold state becomes unknown,
    /// inhibiting every purge, and the holds already in force are kept.
    fn replay(&mut self, records: &[[u8; OPERATION_LENGTH]]) -> bool {
        let mut state = Self::rebuilt();
        for bytes in records {
            match Operation::decode(bytes) {
                Some(Operation::HoldApplied { recording }) => {
                    state.released.remove(&recording);
                    state.holds.insert(
                        recording,
                        Hold::Applied {
                            evidence: digest(bytes),
                        },
                    );
                }
                Some(Operation::HoldReleased { recording }) => {
                    state.holds.remove(&recording);
                    state.released.insert(recording);
                }
                Some(Operation::PurgeIntent {
                    id,
                    recording,
                    before,
                    operator,
                    closed_ns,
                    source,
                    from,
                }) => {
                    state.froms.entry(id).or_insert(from);
                    // A later intent never replaces an outstanding one.
                    state.intents.entry(id).or_insert(PurgeRequest {
                        id,
                        recording,
                        before,
                        authorisation: Authorisation {
                            operator,
                            authorised: false,
                        },
                        closed_ns,
                        source,
                    });
                }
                Some(Operation::PurgeDone { id } | Operation::PurgeCancelled { id, .. }) => {
                    state.intents.remove(&id);
                    state.froms.remove(&id);
                }
                Some(Operation::PurgeRejected { .. } | Operation::SegmentClosed { .. }) => {}
                None => {
                    self.holds_unknown = true;
                    return false;
                }
            }
        }
        // Holds applied in memory since the journal became unreadable stay
        // in force over what the journal says.
        for (recording, hold) in &self.holds {
            state.holds.entry(*recording).or_insert(*hold);
        }
        self.holds = state.holds;
        self.intents.extend(state.intents);
        self.froms.extend(state.froms);
        self.released.extend(state.released);
        self.holds_unknown = false;
        true
    }

    /// The holds and intents an empty journal shows.
    const fn rebuilt() -> Rebuilt {
        Rebuilt {
            holds: BTreeMap::new(),
            intents: BTreeMap::new(),
            froms: BTreeMap::new(),
            released: std::collections::BTreeSet::new(),
        }
    }

    /// Adds a pending hold for each recording whose last marker is pending.
    fn merge_pending(&mut self) {
        let state = self;
        // A recording whose last marker is pending, and which the journal
        // does not show applied, still inhibits: a hold the journal never
        // evidenced survives the restart.
        let mut last: BTreeMap<u64, bool> = BTreeMap::new();
        for bytes in state.pending.entries() {
            let (recording, rest) = bytes
                .split_first_chunk::<8>()
                .map_or((0, &[][..]), |(r, rest)| (u64::from_le_bytes(*r), rest));
            let resolved = rest.first() == Some(&2);
            last.insert(recording, resolved);
        }
        for (recording, resolved) in last {
            if !resolved {
                state.holds.entry(recording).or_insert(Hold::Pending);
            }
        }
    }

    /// Makes hold state readable again from the restored operations
    /// journal's `records`: they are replayed and the pending markers
    /// merged before purges are allowed. False, with purges still
    /// inhibited, when a record does not decode.
    #[must_use = "false when hold state is still unknown"]
    pub fn holds_readable(&mut self, records: &[[u8; OPERATION_LENGTH]]) -> bool {
        let replayed = self.replay(records);
        self.merge_pending();
        replayed
    }

    /// Whether the hold state could be read since the engine started:
    /// while it could not, every hold is unknown and every purge refused
    /// (`holds_unknown`). Read only (ADR-0101).
    #[must_use]
    pub const fn holds_known(&self) -> bool {
        !self.holds_unknown
    }

    /// `recording`'s hold as a retention state query reports it
    /// (ADR-0101): unknown while the hold state is; pending for a hold in
    /// force without evidence, an evidenced hold whose release the journal
    /// holds but whose resolving marker is not written yet included; held
    /// with evidence; else none. Read only.
    #[must_use]
    pub fn hold_state(&self, recording: u64) -> crate::control::HoldState {
        use crate::control::HoldState;
        if self.holds_unknown {
            return HoldState::Unknown;
        }
        match self.holds.get(&recording) {
            None => HoldState::None,
            Some(Hold::Pending) => HoldState::Pending,
            Some(Hold::Applied { .. }) => HoldState::Held,
        }
    }

    /// The hold on `recording`.
    #[must_use]
    pub fn hold(&self, recording: u64) -> Option<Hold> {
        self.holds.get(&recording).copied()
    }

    /// Records in the operations journal that a writer closed segment
    /// `[base, end)` of `recording` at `closed_ns` on the host's wall
    /// clock (ADR-0115), durably; the record's digest.
    ///
    /// # Errors
    ///
    /// The operations journal's.
    pub fn record_segment_close(
        &mut self,
        recording: u64,
        base: u64,
        end: u64,
        closed_ns: u64,
    ) -> io::Result<Digest> {
        self.operations.append(&Operation::SegmentClosed {
            recording,
            base,
            end,
            closed_ns,
        })
    }

    /// The purge intents outstanding.
    #[must_use]
    pub fn outstanding(&self) -> Vec<PurgeRequest> {
        self.intents.values().copied().collect()
    }

    /// Raises outstanding intent `id`'s close time to `closed_ns`, in
    /// memory, never lowering it: a resumed purge is rechecked against the
    /// close time the caller supplies (modification times for recordings,
    /// ADR-0093, decision 3; recorded closes for the journal, ADR-0115;
    /// karyos#1121 review). Unknown ids change nothing.
    pub fn raise_close_time(&mut self, id: u64, closed_ns: u64) {
        if let Some(intent) = self.intents.get_mut(&id) {
            intent.closed_ns = intent.closed_ns.max(closed_ns);
        }
    }

    /// Applies a hold on `recording`. It inhibits at once, never waiting
    /// on the operations journal; it is reported applied only with the
    /// journal's evidence. The pending marker is written first, so a
    /// hold the journal cannot record yet survives a restart.
    pub fn apply_hold(&mut self, recording: u64) -> HoldReport {
        let mut marked = true;
        if !matches!(self.holds.get(&recording), Some(Hold::Applied { .. })) {
            self.holds.insert(recording, Hold::Pending);
            // The hold is in force in memory either way; the marker is what
            // carries it across a restart.
            marked = self.pending.append(marker(recording, false)).is_ok();
        }
        if let Some(Hold::Applied { evidence }) = self.holds.get(&recording) {
            return HoldReport::Applied {
                evidence: *evidence,
            };
        }
        match self
            .operations
            .append(&Operation::HoldApplied { recording })
        {
            Ok(evidence) => {
                self.holds.insert(recording, Hold::Applied { evidence });
                // Best effort: if it is lost, the journal's record still
                // shows the hold applied at restart.
                let _ = self.pending.append(marker(recording, true));
                HoldReport::Applied { evidence }
            }
            Err(_) if marked => HoldReport::PendingNoEvidence,
            Err(_) => HoldReport::InMemoryOnly,
        }
    }

    /// Releases the hold on `recording`, only with evidence it was applied
    /// and a journal that records the release.
    ///
    /// # Errors
    ///
    /// [`ReleaseError`]; the hold stays in force on every error.
    pub fn release_hold(&mut self, recording: u64) -> Result<(), ReleaseError> {
        if self.holds_unknown {
            return Err(ReleaseError::Unknown);
        }
        // A release the journal already holds needs only its marker.
        if self.released.contains(&recording)
            && matches!(self.holds.get(&recording), Some(Hold::Pending))
        {
            return self.resolve_release(recording);
        }
        if !matches!(self.holds.get(&recording), Some(Hold::Applied { .. })) {
            return Err(ReleaseError::NoEvidence { recording });
        }
        // A pending marker first: a release whose record reaches the
        // journal but whose append reports a failure leaves this marker
        // last, so the restart keeps the hold. It fails closed.
        self.pending
            .append(marker(recording, false))
            .map_err(|_| ReleaseError::JournalUnavailable)?;
        self.operations
            .append(&Operation::HoldReleased { recording })
            .map_err(|_| ReleaseError::JournalUnavailable)?;
        self.released.insert(recording);
        self.holds.insert(recording, Hold::Pending);
        self.resolve_release(recording)
    }

    /// Writes the resolving marker of a release the journal holds; only
    /// then is the hold gone. Until it is written the hold stays pending,
    /// here and across a restart, and a retry completes it.
    fn resolve_release(&mut self, recording: u64) -> Result<(), ReleaseError> {
        self.pending
            .append(marker(recording, true))
            .map_err(|_| ReleaseError::Unconfirmed { recording })?;
        self.holds.remove(&recording);
        self.released.remove(&recording);
        Ok(())
    }

    /// Checks `request` without acting. Holds come first: they outrank
    /// purge targets.
    ///
    /// # Errors
    ///
    /// The [`PurgeRefusal`].
    /// `start` is the store's current start: copies need cover only
    /// `[start, before)`.
    pub fn check<D2: Disk>(
        &self,
        request: &PurgeRequest,
        context: &PurgeContext<'_, D2>,
        start: u64,
    ) -> Result<(), PurgeRefusal> {
        if self.holds_unknown {
            return Err(PurgeRefusal::HoldsUnknown);
        }
        if self.holds.contains_key(&request.recording) {
            return Err(PurgeRefusal::LegalHold);
        }
        if !request.authorisation.authorised {
            return Err(PurgeRefusal::NotAuthorised);
        }
        let policy = context.policy.ok_or(PurgeRefusal::NoPolicy)?;
        if policy.purge == PurgeMode::Manual && request.source == PurgeSource::Schedule {
            return Err(PurgeRefusal::ManualOnly);
        }
        let expires_ns = request.closed_ns.checked_add(policy.retain_for_ns).ok_or(
            PurgeRefusal::NotExpired {
                expires_ns: u64::MAX,
            },
        )?;
        if context.now_ns < expires_ns {
            return Err(PurgeRefusal::NotExpired { expires_ns });
        }
        let verified = context
            .copies
            .current()
            // A copy catalog that cannot answer counts nothing: fail closed.
            .map_err(|_| PurgeRefusal::JournalUnavailable)?
            .into_iter()
            .filter(|copy| {
                copy.location != context.local
                    && copy.recording == request.recording
                    && copy.state == super::copies::CopyState::Verified
                    && copy.start <= start
                    && copy.end >= request.before
            })
            .map(|copy| copy.location)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let verified = u64::try_from(verified).unwrap_or(u64::MAX);
        let required = policy.min_copies.get();
        if verified < u64::from(required) {
            return Err(PurgeRefusal::BelowMinCopies { verified, required });
        }
        Ok(())
    }

    /// Refuses `request` on an Archive with no purge configuration (no
    /// policy, no copy catalog; karyos#1093), journalling the refusal as
    /// [`Retention::purge`] would: holds first, as in
    /// [`Retention::check`], then `no_policy`. Never deletes.
    pub fn refuse_unconfigured(&mut self, request: &PurgeRequest) -> PurgeError {
        self.refuse_after_holds(request, PurgeRefusal::NoPolicy)
    }

    /// Refuses `request` with `last`, journalled, unless a refusal that
    /// comes first in [`Retention::check`] applies: a duplicate id, unknown
    /// holds, a hold, no authorisation. Never deletes. Used for what the
    /// check cannot see: no policy, no close time (ADR-0093).
    pub fn refuse_after_holds(&mut self, request: &PurgeRequest, last: PurgeRefusal) -> PurgeError {
        let refusal = self.first_refusal(request).unwrap_or(last);
        self.refuse(request, refusal)
    }

    /// Refuses `request`, journalled, when a refusal that comes first in
    /// [`Retention::check`] applies (a duplicate id, unknown holds, a hold,
    /// no authorisation); `None`, journalling nothing, otherwise. Run
    /// before anything that may fail on the recording's files, so a held
    /// recording is answered `legal_hold`, never a store error (karyos#1121
    /// review).
    pub fn refuse_early(&mut self, request: &PurgeRequest) -> Option<PurgeError> {
        let refusal = self.first_refusal(request)?;
        Some(self.refuse(request, refusal))
    }

    fn first_refusal(&self, request: &PurgeRequest) -> Option<PurgeRefusal> {
        if self.intents.contains_key(&request.id) {
            Some(PurgeRefusal::DuplicateId { id: request.id })
        } else if self.holds_unknown {
            Some(PurgeRefusal::HoldsUnknown)
        } else if self.holds.contains_key(&request.recording) {
            Some(PurgeRefusal::LegalHold)
        } else if !request.authorisation.authorised {
            Some(PurgeRefusal::NotAuthorised)
        } else {
            None
        }
    }

    fn refuse(&mut self, request: &PurgeRequest, refusal: PurgeRefusal) -> PurgeError {
        let journalled = self
            .operations
            .append(&Operation::PurgeRejected {
                id: request.id,
                recording: request.recording,
                reason: refusal.code(),
            })
            .is_ok();
        PurgeError::Refused {
            refusal,
            journalled,
        }
    }

    /// Purges `request`'s range from `store`: checked, its intent
    /// journalled, deleted through [`SegmentStore::purge_before`], recorded
    /// in `journal` with the digest of the purged range's seals, and its
    /// completion journalled. Returns the integrity journal's purge record.
    ///
    /// # Errors
    ///
    /// [`PurgeError::Refused`] before any deletion, the refusal journalled
    /// when the journal can take it; the store's or a journal's error
    /// after the intent, which [`Retention::recover_purges`] completes or
    /// cancels.
    pub fn purge<D2: Disk>(
        &mut self,
        request: &PurgeRequest,
        context: &PurgeContext<'_, D2>,
        store: &mut SegmentStore<D2>,
        journal: &mut IntegrityJournal<D2>,
    ) -> Result<SealRecord, PurgeError> {
        let checked = if request.recording != store.recording() {
            Err(PurgeRefusal::WrongStore {
                recording: request.recording,
                store: store.recording(),
            })
        } else if self.intents.contains_key(&request.id) {
            Err(PurgeRefusal::DuplicateId { id: request.id })
        } else {
            self.check(request, context, store.start())
                .and_then(|()| Self::not_offloaded(store))
                .and_then(|()| Self::boundaries(request, store, journal))
        };
        if let Err(refusal) = checked {
            return Err(self.refuse(request, refusal));
        }
        let intent = Operation::PurgeIntent {
            id: request.id,
            recording: request.recording,
            before: request.before,
            operator: request.authorisation.operator,
            closed_ns: request.closed_ns,
            source: request.source,
            from: store.lowest_retained(),
        };
        if self.operations.append(&intent).is_err() {
            return Err(PurgeError::Refused {
                refusal: PurgeRefusal::JournalUnavailable,
                journalled: false,
            });
        }
        self.intents.insert(request.id, *request);
        self.froms.insert(request.id, store.lowest_retained());
        self.complete(request, store, journal)
    }

    /// Refuses a purge of a recording with offloaded segments (ADR-0104,
    /// decision 5): every purge interval starts at the lowest retained
    /// position, the offload floor, so it intersects them whatever the
    /// cutoff.
    fn not_offloaded<D2: Disk>(store: &SegmentStore<D2>) -> Result<(), PurgeRefusal> {
        let (lowest, start) = (store.lowest_retained(), store.start());
        if lowest < start {
            return Err(PurgeRefusal::Offloaded { lowest, start });
        }
        Ok(())
    }

    /// The cutoff's boundaries, checked before any floor advances: it
    /// must start a write in the store and fall outside every sealed
    /// range. An index or journal that cannot be read refuses.
    fn boundaries<D2: Disk>(
        request: &PurgeRequest,
        store: &mut SegmentStore<D2>,
        journal: &mut IntegrityJournal<D2>,
    ) -> Result<(), PurgeRefusal> {
        // A recovered store reports nothing durable until it syncs, and
        // the primitive purges only below the durable position.
        store.sync().map_err(|_| PurgeRefusal::JournalUnavailable)?;
        if !store.can_purge_to(request.before)
            || !store
                .is_write_start(request.before)
                .map_err(|_| PurgeRefusal::JournalUnavailable)?
        {
            return Err(PurgeRefusal::NotAWriteStart {
                before: request.before,
            });
        }
        // The seals must reach the cutoff: purged bytes the chain never
        // sealed could neither be accounted for nor sealed later.
        let sealed = journal
            .sealed_end(request.recording)
            .unwrap_or(store.start());
        if request.before > sealed {
            return Err(PurgeRefusal::NotSealed {
                before: request.before,
                sealed,
            });
        }
        Self::cutoff_on_a_seal(request, journal)
    }

    /// Refuses a cutoff inside a sealed range: the purge would make part of
    /// it unreadable while its purge record covers none of it. An
    /// unreadable journal refuses as unavailable.
    fn cutoff_on_a_seal<D2: Disk>(
        request: &PurgeRequest,
        journal: &mut IntegrityJournal<D2>,
    ) -> Result<(), PurgeRefusal> {
        let records = journal
            .records()
            .map_err(|_| PurgeRefusal::JournalUnavailable)?;
        match records.iter().find(|record| {
            record.kind.is_range()
                && record.subject == request.recording
                && record.start < request.before
                && request.before < record.end
        }) {
            Some(record) => Err(PurgeRefusal::SplitsSeal {
                before: request.before,
                counter: record.counter,
            }),
            None => Ok(()),
        }
    }

    /// Deletes and records an intent already journalled.
    fn complete<D2: Disk>(
        &mut self,
        request: &PurgeRequest,
        store: &mut SegmentStore<D2>,
        journal: &mut IntegrityJournal<D2>,
    ) -> Result<SealRecord, PurgeError> {
        // The primitive purges only below the durable position, which a
        // recovered store reports as nothing until it syncs.
        store.sync()?;
        // The lowest retained position, never the local start: an
        // offloaded range is never counted purged (ADR-0104, decision 5).
        let start = store.lowest_retained();
        let records = journal.records()?;
        // The purge record may already be there: a crash after it.
        let existing = records.iter().find(|record| {
            record.kind == SealKind::Purge
                && record.subject == request.recording
                && record.end == request.before
        });
        let record = match existing {
            Some(record) => *record,
            None => {
                // The range the intent recorded, whatever the floor did
                // since: a crash after the deletion still records it whole.
                let first = self.froms.get(&request.id).copied().unwrap_or(start);
                let sealed = seals_digest(&records, request.recording, first, request.before);
                // A floor already past the cutoff deleted the range: only
                // the record is missing.
                if store.start() < request.before {
                    self.release(store, request.before)?;
                    store.purge_before(request.before)?;
                }
                journal.record_purge(request.recording, first, request.before, sealed)?
            }
        };
        if store.start() < request.before {
            self.release(store, request.before)?;
            store.purge_before(request.before)?;
        }
        // A crash inside the removal leaves segments below the floor: they
        // are released and removed before the purge is done (karyos#1121
        // review).
        let left = store.files_left_below_floor()?;
        if !left.is_empty() {
            if let Some(Releaser(backend)) = self.immutability.as_mut() {
                for (_, path, data) in &left {
                    if *data {
                        backend.release(path).map_err(|error| PurgeError::Release {
                            path: path.clone(),
                            error,
                        })?;
                    }
                }
            }
            let bases: Vec<u64> = left.iter().map(|(base, _, _)| *base).collect();
            store.remove_left_below_floor(&bases)?;
        }
        self.operations
            .append(&Operation::PurgeDone { id: request.id })
            .map_err(PurgeError::Operations)?;
        self.intents.remove(&request.id);
        self.froms.remove(&request.id);
        Ok(record)
    }

    /// Releases the immutability of every segment a purge below `before`
    /// removes, lowest first; the first failure stops it, before any
    /// deletion.
    fn release<D2: Disk>(
        &mut self,
        store: &SegmentStore<D2>,
        before: u64,
    ) -> Result<(), PurgeError> {
        let Some(Releaser(backend)) = self.immutability.as_mut() else {
            return Ok(());
        };
        for path in store.segment_files_below(before)? {
            backend
                .release(&path)
                .map_err(|error| PurgeError::Release { path, error })?;
        }
        Ok(())
    }

    /// Completes or cancels every outstanding purge intent after a crash.
    /// Each is rechecked first: `authorised` says whether its operator is
    /// still authorised, and holds, the policy and copies are evaluated
    /// as they are now. An intent whose floor already reached its cutoff
    /// is completed (recorded, and the files a crash left below the floor
    /// removed) only when the recheck passes; otherwise nothing more is
    /// deleted and it stays outstanding. One whose floor did not move that
    /// fails the recheck is cancelled with its reason, and nothing is
    /// deleted.
    ///
    /// # Errors
    ///
    /// The first store or journal error; outstanding intents stay.
    pub fn recover_purges<D2: Disk>(
        &mut self,
        context: &PurgeContext<'_, D2>,
        authorised: impl Fn(u64) -> bool,
        store: &mut SegmentStore<D2>,
        journal: &mut IntegrityJournal<D2>,
    ) -> Result<Vec<Result<SealRecord, PurgeRefusal>>, PurgeError> {
        let mut outcomes = Vec::new();
        for mut request in self.outstanding() {
            if request.recording != store.recording() {
                continue;
            }
            request.authorisation.authorised = authorised(request.authorisation.operator);
            // The completion shortcut takes the lowest retained position,
            // so an offloaded range below the start is never taken for a
            // purged one (ADR-0104, decision 5). Holds, the policy, its
            // expiry and the copies are rechecked first, over the intent's
            // original range: one that fails them now deletes nothing more,
            // the files left below the floor included, and stays
            // outstanding, never cancelled, since its floor already moved
            // (ADR-0113, point 8; karyos#702 review).
            if store.lowest_retained() >= request.before {
                let from = self
                    .froms
                    .get(&request.id)
                    .copied()
                    .unwrap_or_else(|| store.lowest_retained());
                match self.check(&request, context, from) {
                    Ok(()) => outcomes.push(Ok(self.complete(&request, store, journal)?)),
                    Err(refusal) => outcomes.push(Err(refusal)),
                }
                continue;
            }
            // The floor moves only after the same checks a fresh purge
            // passes, the boundaries included: a seal or a write may have
            // come to cover the cutoff since the intent.
            let checked = self
                .check(&request, context, store.start())
                .and_then(|()| Self::not_offloaded(store))
                .and_then(|()| Self::boundaries(&request, store, journal));
            match checked {
                Ok(()) => outcomes.push(Ok(self.complete(&request, store, journal)?)),
                Err(refusal) => {
                    // Cancelled only once recorded; otherwise it stays
                    // outstanding and inhibits nothing more than before.
                    if self
                        .operations
                        .append(&Operation::PurgeCancelled {
                            id: request.id,
                            reason: refusal.code(),
                        })
                        .is_ok()
                    {
                        self.intents.remove(&request.id);
                        self.froms.remove(&request.id);
                    }
                    outcomes.push(Err(refusal));
                }
            }
        }
        Ok(outcomes)
    }
}

/// The digest of a recording's seals of `[start, end)`: SHA-256 over the
/// content digests of its range records there, in chain order.
#[must_use]
pub fn seals_digest(records: &[SealRecord], recording: u64, start: u64, end: u64) -> Digest {
    let mut hasher = Sha256::new();
    for record in records {
        if record.kind.is_range()
            && record.subject == recording
            && record.start >= start
            && record.end <= end
        {
            hasher.update(record.content);
        }
    }
    hasher.finalize().into()
}

impl From<PolicyError> for IntegrityError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}
