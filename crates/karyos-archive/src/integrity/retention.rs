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

use super::copies::CopyCatalog;
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
pub const OPERATION_LENGTH: usize = 48;

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

/// The policies in force and what they bind to.
#[derive(Debug, Clone, Default)]
pub struct PolicyBook {
    current: BTreeMap<u64, RetentionPolicy>,
    bindings: BTreeMap<Selector, u64>,
}

impl PolicyBook {
    /// Records a new policy version, chaining it in `journal`.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Policy`] for a version that does not rise, with
    /// nothing written; the journal's error.
    pub fn record<D: Disk>(
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
        let record =
            journal.record_policy_version(policy.policy, policy.version, &policy.canonical())?;
        self.current.insert(policy.policy, policy);
        Ok(record)
    }

    /// Binds `selector` to `policy`.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Unknown`] for a policy never recorded.
    pub fn bind(&mut self, selector: Selector, policy: u64) -> Result<(), PolicyError> {
        if !self.current.contains_key(&policy) {
            return Err(PolicyError::Unknown { policy });
        }
        self.bindings.insert(selector, policy);
        Ok(())
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
        let class = Selector::Class {
            channel: channel.to_vec(),
            stream_id,
        };
        self.bindings
            .get(&Selector::Recording(recording))
            .or_else(|| self.bindings.get(&class))
            .and_then(|policy| self.current.get(policy))
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
}

impl Operation {
    /// The encoded record: kind, reason, six reserved zero bytes, then
    /// five `u64` fields, little-endian.
    #[must_use]
    pub fn encode(&self) -> [u8; OPERATION_LENGTH] {
        let (kind, reason, fields) = match *self {
            Self::HoldApplied { recording } => (1, 0, [recording, 0, 0, 0, 0]),
            Self::HoldReleased { recording } => (2, 0, [recording, 0, 0, 0, 0]),
            Self::PurgeIntent {
                id,
                recording,
                before,
                operator,
                closed_ns,
            } => (3, 0, [id, recording, before, operator, closed_ns]),
            Self::PurgeRejected {
                id,
                recording,
                reason,
            } => (4, reason, [id, recording, 0, 0, 0]),
            Self::PurgeDone { id } => (5, 0, [id, 0, 0, 0, 0]),
            Self::PurgeCancelled { id, reason } => (6, reason, [id, 0, 0, 0, 0]),
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
    /// It inhibits purge, survives restart, and is not reported applied.
    PendingNoEvidence,
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
}

/// Who asks for a purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorisation {
    /// The operator.
    pub operator: u64,
    /// Whether the management path authorised the request (ADR-0055).
    pub authorised: bool,
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
}

impl PurgeRefusal {
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

/// Retention state: holds and the operations journal.
#[derive(Debug)]
pub struct Retention<J, D: Disk> {
    operations: J,
    pending: Ledger<D, MARKER_LENGTH>,
    holds: BTreeMap<u64, Hold>,
    holds_unknown: bool,
    intents: BTreeMap<u64, PurgeRequest>,
}

impl<J: OperationsJournal, D: Disk> Retention<J, D> {
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
            holds_unknown: records.is_none(),
            intents: BTreeMap::new(),
        };
        for bytes in records.unwrap_or_default() {
            match Operation::decode(bytes) {
                Some(Operation::HoldApplied { recording }) => {
                    state.holds.insert(
                        recording,
                        Hold::Applied {
                            evidence: digest(bytes),
                        },
                    );
                }
                Some(Operation::HoldReleased { recording }) => {
                    state.holds.remove(&recording);
                }
                Some(Operation::PurgeIntent {
                    id,
                    recording,
                    before,
                    operator,
                    closed_ns,
                }) => {
                    state.intents.insert(
                        id,
                        PurgeRequest {
                            id,
                            recording,
                            before,
                            authorisation: Authorisation {
                                operator,
                                authorised: false,
                            },
                            closed_ns,
                        },
                    );
                }
                Some(Operation::PurgeDone { id } | Operation::PurgeCancelled { id, .. }) => {
                    state.intents.remove(&id);
                }
                Some(Operation::PurgeRejected { .. }) => {}
                None => state.holds_unknown = true,
            }
        }
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
        state
    }

    /// Marks hold state as readable again, once the operator restored the
    /// operations journal and recovery rebuilt it.
    pub const fn holds_readable(&mut self) {
        self.holds_unknown = false;
    }

    /// The hold on `recording`.
    #[must_use]
    pub fn hold(&self, recording: u64) -> Option<Hold> {
        self.holds.get(&recording).copied()
    }

    /// The purge intents outstanding.
    #[must_use]
    pub fn outstanding(&self) -> Vec<PurgeRequest> {
        self.intents.values().copied().collect()
    }

    /// Applies a hold on `recording`. It inhibits at once, never waiting
    /// on the operations journal; it is reported applied only with the
    /// journal's evidence. The pending marker is written first, so a
    /// hold the journal cannot record yet survives a restart.
    pub fn apply_hold(&mut self, recording: u64) -> HoldReport {
        if !matches!(self.holds.get(&recording), Some(Hold::Applied { .. })) {
            self.holds.insert(recording, Hold::Pending);
            // Best effort: the hold is in force in memory either way.
            let _ = self.pending.append(marker(recording, false));
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
            Err(_) => HoldReport::PendingNoEvidence,
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
        if !matches!(self.holds.get(&recording), Some(Hold::Applied { .. })) {
            return Err(ReleaseError::NoEvidence { recording });
        }
        self.operations
            .append(&Operation::HoldReleased { recording })
            .map_err(|_| ReleaseError::JournalUnavailable)?;
        self.holds.remove(&recording);
        // Best effort: a lost marker leaves an applied hold's last marker
        // resolved already, so nothing re-inhibits.
        let _ = self.pending.append(marker(recording, true));
        Ok(())
    }

    /// Checks `request` without acting. Holds come first: they outrank
    /// purge targets.
    ///
    /// # Errors
    ///
    /// The [`PurgeRefusal`].
    pub fn check<D2: Disk>(
        &self,
        request: &PurgeRequest,
        context: &PurgeContext<'_, D2>,
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
        let expires_ns = request.closed_ns.checked_add(policy.retain_for_ns).ok_or(
            PurgeRefusal::NotExpired {
                expires_ns: u64::MAX,
            },
        )?;
        if context.now_ns < expires_ns {
            return Err(PurgeRefusal::NotExpired { expires_ns });
        }
        let start = 0;
        let verified = context
            .copies
            .current()
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
        if let Err(refusal) = self.check(request, context) {
            return Err(self.refuse(request, refusal));
        }
        let intent = Operation::PurgeIntent {
            id: request.id,
            recording: request.recording,
            before: request.before,
            operator: request.authorisation.operator,
            closed_ns: request.closed_ns,
        };
        if self.operations.append(&intent).is_err() {
            return Err(PurgeError::Refused {
                refusal: PurgeRefusal::JournalUnavailable,
                journalled: false,
            });
        }
        self.intents.insert(request.id, *request);
        self.complete(request, store, journal)
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
        let start = store.start();
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
                let first = records
                    .iter()
                    .filter(|record| record.kind.is_range() && record.subject == request.recording)
                    .map(|record| record.start)
                    .min()
                    .unwrap_or(start)
                    .min(start);
                let sealed = seals_digest(&records, request.recording, first, request.before);
                store.purge_before(request.before)?;
                journal.record_purge(request.recording, first, request.before, sealed)?
            }
        };
        if store.start() < request.before {
            store.purge_before(request.before)?;
        }
        self.operations
            .append(&Operation::PurgeDone { id: request.id })
            .map_err(PurgeError::Operations)?;
        self.intents.remove(&request.id);
        Ok(record)
    }

    /// Completes or cancels every outstanding purge intent after a crash.
    /// Each is rechecked first: `authorised` says whether its operator is
    /// still authorised, and holds, the policy and copies are evaluated
    /// as they are now. An intent whose deletion already happened is only
    /// recorded; one that fails the recheck is cancelled with its reason,
    /// and nothing is deleted.
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
            if store.start() >= request.before {
                outcomes.push(Ok(self.complete(&request, store, journal)?));
                continue;
            }
            match self.check(&request, context) {
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
