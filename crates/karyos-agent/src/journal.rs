// SPDX-License-Identifier: Apache-2.0

//! The operations journal of the agent's guard operations (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M10 and its new owner
//! item 7, decided as item 51(7) of the 2026-10-21 owner decisions,
//! interim; not item 7 of those decisions): an Archive recording in the agent's journal directory, written
//! through the Archive's [`Recorder`] from a [`QueueSource`], and sealed by
//! the Archive's integrity journal (**Sealing**, below).
//!
//! - **One recording.** The directory's catalog holds the journal as one
//!   `required` recording on channel [`CHANNEL`]. The agent resumes the open
//!   one at start (recovering its store), or starts one when there is none.
//! - **Records.** Each operation is a request record before it is sent and
//!   an outcome record after it ([`Kind`]); each is one DATA frame
//!   ([`JournalRecord::encode`]).
//! - **Failure.** An append that fails leaves the journal unavailable until
//!   the agent restarts, and counts in [`Journal::failed_appends`]; the
//!   restart is the recovery, since [`Journal::open`] recovers the store
//!   and records the unknown interval. [`Journal::failed_at`] is when it
//!   first failed, for the alert raised at once. A close
//!   goes ahead without its record (failing toward safety); a reopen needs
//!   its request durable first ([`Journal::append_durable`]) and is refused
//!   otherwise (failing closed).
//! - **Unknown interval.** At start, a request with no outcome after it, or
//!   a tail recovery cut, means an operation may have taken effect without
//!   its record: the agent appends a [`Kind::UnknownInterval`] from the last
//!   record's time to now. The latest unknown interval stays open
//!   ([`Journal::gap`]), across restarts, until an administrator
//!   acknowledges it with a [`Kind::GapAcknowledged`] record naming it.
//! - **Sealing** (A10; karyos#985). The integrity journal lives in the
//!   operations journal's own directory, in this process: each durable
//!   append seals the recording up to its durable end
//!   ([`IntegrityJournal::seal_segment`]), so `karyos-catalog verify` of
//!   the directory reports its ranges. A seal that fails stops the sealing
//!   until the agent restarts, and counts in [`Journal::failed_seals`]; the
//!   journal itself goes on, its later ranges shown unsealed.
//! - **Verification** (karyos#702). [`Journal::verify`] runs the Archive's
//!   verifier over the directory's integrity journal and the recording, as
//!   `karyos-catalog verify` does without a trust file, and keeps each
//!   range's outcome and reasons under the verifier's own names, adjacent
//!   ranges with the same outcome and reasons merged into one. The agent
//!   holds no trust root for the journal: an intact sealed range is
//!   `inconsistent` with `untrusted_evidence` and `missing_evidence`, never
//!   `verified`, and a damaged one is `inconsistent` with `corruption` (or
//!   `shortened_index`), the range named. [`Journal::unsealed`] is true
//!   while a part of the recording has no seal.
//! - **Trust** (karyos#702). With `--journal-trust` ([`JournalTrust`]),
//!   the verification reads the directory's key registry and signed heads
//!   under that trust, as `karyos-catalog verify --trust` does: an intact
//!   range covered by a trusted head is no longer `untrusted_evidence`.
//! - **Retention** (ADR-0113). Legal holds and purges of the journal run
//!   through the Archive library's engine over this directory
//!   ([`retention`]); [`Integrity::purged`] lists each purged prefix with
//!   its purge evidence.
//! - **History** (R-CORE-14; karyos#725). [`Journal::history`] serves
//!   the durable records in pages, with a cursor a reader keeps across
//!   restarts, the retention floor, unknown intervals in place and a
//!   sequence a reader checks for gaps ([`history`]).
//! - **Encoding.** Sealing changed nothing in a record's layout
//!   ([`JournalRecord::encode`]): a journal written before it decodes as it
//!   did, and is sealed from its start at its next durable append.

pub mod history;
pub mod retention;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use karyos_archive::catalog::{
    Catalog, CatalogError, NewRecording, SourceIncarnation, StreamFormat,
};
use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::anchor::{Anchor, AnchorEvidence};
use karyos_archive::integrity::journal::{IntegrityJournal, read_records};
use karyos_archive::integrity::verify::{Evidence, RangeBytes, RangeReport, verify};
use karyos_archive::queue::{QueueConfig, QueueError, QueueSource};
use karyos_archive::recorder::{Mode, Recorder, RecorderError};
use karyos_archive::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};
use karyos_sys::frame::{FRAME_ALIGNMENT, FrameType, HEADER_LENGTH, Lane, Word0};

use crate::retention::RangeOutcome;
pub use history::{
    HISTORY_DEFAULT, HISTORY_MAX, HistoryCursor, HistoryPage, HistoryRecord, HistoryRefusal,
};
pub use retention::{JournalPolicy, JournalRetention, JournalTrust, Purged};

/// The journal recording's channel.
pub const CHANNEL: &[u8] = b"karyos:operations-journal";
/// The journal's term length: one record never comes near it.
const TERM_LENGTH: u32 = karyos_sys::sizing::MIN_TERM_LENGTH;
/// The longest reason a record keeps, in bytes.
pub const MAX_REASON: usize = 128;
/// The record layout's version.
const VERSION: u64 = 1;
/// The fixed words of a record before its reason.
const WORDS: usize = 11;
/// The most bytes one seal reads (karyos#1071).
const SEAL_CHUNK: u64 = 1 << 20;
/// How long a verification of the journal stands before the agent runs
/// the next (karyos#702): a minute.
pub const VERIFY_PERIOD_NS: u64 = 60_000_000_000;
/// The most ranges a verification keeps, adjacent ones with the same
/// outcome and reasons merged first.
pub const MAX_INTEGRITY_RANGES: usize = 16;
/// Bytes queued at most before the recorder takes them.
const MAX_QUEUED: u64 = 1 << 20;
/// The journal's largest frame: a term.
const MTU: core::num::NonZeroU32 = match core::num::NonZeroU32::new(TERM_LENGTH) {
    Some(mtu) => mtu,
    None => core::num::NonZeroU32::MIN,
};

/// An outcome record's code when the answer never came: the operation may
/// or may not have taken effect.
pub const UNKNOWN_OUTCOME: u64 = u64::MAX;

/// What a record says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A guard close, before it is sent.
    CloseRequest,
    /// What the close did.
    CloseOutcome,
    /// A guard reopen, before it is sent.
    ReopenRequest,
    /// What the reopen did.
    ReopenOutcome,
    /// Operations may have taken effect without their records between
    /// `expected` (the last record's time) and `time`.
    UnknownInterval,
    /// An administrator acknowledged the unknown interval recorded at
    /// position `expected`.
    GapAcknowledged,
    /// The agent stopped cleanly: [`Journal::stop`] wrote it durably, last.
    /// A start whose journal does not end with it records an unknown
    /// interval.
    AgentStopped,
    /// The agent started: [`Journal::open`] writes it durably, so every run
    /// leaves a record, and one that ends without [`Kind::AgentStopped`]
    /// shows, even when nothing else was written.
    AgentStarted,
    /// A legal hold on recording `guard`, before it is sent (M12).
    HoldRequest,
    /// What the hold did.
    HoldOutcome,
    /// A hold release on recording `guard`, before it is sent.
    ReleaseRequest,
    /// What the release did.
    ReleaseOutcome,
    /// A purge of recording `guard` below position `expected`, before it
    /// is sent.
    PurgeRequest,
    /// What the purge did.
    PurgeOutcome,
    /// A seal verification of recording `guard`, before it is sent.
    VerifyRequest,
    /// What the verification reported: `code` is 0 when it answered.
    VerifyOutcome,
    /// A rate policy change of stream `guard` (its stream word) from
    /// version `expected`, before it is sent (R-CORE-21, karyos#740).
    RateRequest,
    /// What the change did: the version after it in `word`, or the
    /// refusal's code in `code` and its detail in `word`.
    RateOutcome,
    /// A caller-chosen operation id's submit that was sent (R-CORE-18,
    /// karyos#738), after its request and outcome records: the operation
    /// (`parameters`: 1 a close, 2 a reopen), the guard, the epoch it
    /// acted at in `expected`, the operator, the relay and the reason; its
    /// outcome (`code` 0 and the guard word after it in `word`, a refusal's
    /// code and detail, or [`UNKNOWN_OUTCOME`]); and, after the relay
    /// word, the driver's directory and this host's boot identity
    /// ([`JournalRecord::target`], [`JournalRecord::boot`]). The agent
    /// rebuilds its retained outcomes and caller ids from these records
    /// only.
    Submitted,
    /// A product Cluster's admin command, before it is sent (R-CORE-41,
    /// karyos#772): the operation, the operator, the relay, the reason,
    /// the parameters' digest, and after the relay word the Cluster's name
    /// ([`JournalRecord::target`]), the command's name
    /// ([`JournalRecord::command`]) and an empty evidence.
    ClusterRequest,
    /// What the admin command came to: `code` 0 for sequenced, the log
    /// index in `word`, the term in `expected` and the product's evidence
    /// in [`JournalRecord::evidence`]; the product's refusal code; or
    /// [`UNKNOWN_OUTCOME`].
    ClusterOutcome,
    /// An admin command the agent refused before sending it: its
    /// [`crate::cluster_admin::RefusalCode`] in `code`.
    ClusterRefused,
    /// A marked operation entered the two-person flow (R-CORE-20,
    /// karyos#739, ADR-0112), durable before it is answered
    /// `pending_approval`: the operation id, the requester (`operator`,
    /// `relay`), the reason, the class in `parameters` (1 a guard reopen,
    /// 2 a Cluster command), the guard and the epoch it acts at
    /// (`guard`, `expected`) and the wait in nanoseconds (`word`); after
    /// the relay word the target (the driver's directory or the Cluster's
    /// name), the command's name, this host's boot, the parameter bytes
    /// and the target's instance ([`JournalRecord::bytes`],
    /// [`JournalRecord::instance`]). It consumes the preview's token and
    /// reserves the id.
    ApprovalRequested,
    /// A distinct principal approved the pending operation (`operator`
    /// and `relay` the approver's), durable before it is dispatched.
    ApprovalGranted,
    /// The requester withdrew the pending operation.
    ApprovalWithdrawn,
    /// The operation ended without being sent, its
    /// `approval::EndCode` in `code` and its text in `reason`:
    /// its deadline passed, the agent restarted while it was pending or
    /// before its dispatch, or at approval its target had changed, its
    /// Cluster was busy, its dispatch record could not be made durable or
    /// its driver was unavailable.
    ApprovalExpired,
}

impl Kind {
    const fn code(self) -> u64 {
        match self {
            Self::CloseRequest => 1,
            Self::CloseOutcome => 2,
            Self::ReopenRequest => 3,
            Self::ReopenOutcome => 4,
            Self::UnknownInterval => 5,
            Self::GapAcknowledged => 6,
            Self::AgentStopped => 7,
            Self::AgentStarted => 8,
            Self::HoldRequest => 9,
            Self::HoldOutcome => 10,
            Self::ReleaseRequest => 11,
            Self::ReleaseOutcome => 12,
            Self::PurgeRequest => 13,
            Self::PurgeOutcome => 14,
            Self::VerifyRequest => 15,
            Self::VerifyOutcome => 16,
            Self::RateRequest => 17,
            Self::RateOutcome => 18,
            Self::Submitted => 19,
            Self::ClusterRequest => 20,
            Self::ClusterOutcome => 21,
            Self::ClusterRefused => 22,
            Self::ApprovalRequested => 23,
            Self::ApprovalGranted => 24,
            Self::ApprovalWithdrawn => 25,
            Self::ApprovalExpired => 26,
        }
    }

    /// Its name in the journal's history (R-CORE-14; karyos#725).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CloseRequest => "close_request",
            Self::CloseOutcome => "close_outcome",
            Self::ReopenRequest => "reopen_request",
            Self::ReopenOutcome => "reopen_outcome",
            Self::UnknownInterval => "unknown_interval",
            Self::GapAcknowledged => "gap_acknowledged",
            Self::AgentStopped => "agent_stopped",
            Self::AgentStarted => "agent_started",
            Self::HoldRequest => "hold_request",
            Self::HoldOutcome => "hold_outcome",
            Self::ReleaseRequest => "release_request",
            Self::ReleaseOutcome => "release_outcome",
            Self::PurgeRequest => "purge_request",
            Self::PurgeOutcome => "purge_outcome",
            Self::VerifyRequest => "verify_request",
            Self::VerifyOutcome => "verify_outcome",
            Self::RateRequest => "rate_request",
            Self::RateOutcome => "rate_outcome",
            Self::Submitted => "submitted",
            Self::ClusterRequest => "cluster_request",
            Self::ClusterOutcome => "cluster_outcome",
            Self::ClusterRefused => "cluster_refused",
            Self::ApprovalRequested => "approval_requested",
            Self::ApprovalGranted => "approval_granted",
            Self::ApprovalWithdrawn => "approval_withdrawn",
            Self::ApprovalExpired => "approval_expired",
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::CloseRequest,
            2 => Self::CloseOutcome,
            3 => Self::ReopenRequest,
            4 => Self::ReopenOutcome,
            5 => Self::UnknownInterval,
            6 => Self::GapAcknowledged,
            7 => Self::AgentStopped,
            8 => Self::AgentStarted,
            9 => Self::HoldRequest,
            10 => Self::HoldOutcome,
            11 => Self::ReleaseRequest,
            12 => Self::ReleaseOutcome,
            13 => Self::PurgeRequest,
            14 => Self::PurgeOutcome,
            15 => Self::VerifyRequest,
            16 => Self::VerifyOutcome,
            17 => Self::RateRequest,
            18 => Self::RateOutcome,
            19 => Self::Submitted,
            20 => Self::ClusterRequest,
            21 => Self::ClusterOutcome,
            22 => Self::ClusterRefused,
            23 => Self::ApprovalRequested,
            24 => Self::ApprovalGranted,
            25 => Self::ApprovalWithdrawn,
            26 => Self::ApprovalExpired,
            _ => return None,
        })
    }

    const fn is_request(self) -> bool {
        matches!(
            self,
            Self::CloseRequest
                | Self::ReopenRequest
                | Self::HoldRequest
                | Self::ReleaseRequest
                | Self::PurgeRequest
                | Self::VerifyRequest
                | Self::RateRequest
                | Self::ClusterRequest
        )
    }

    /// Whether its record carries the Cluster fields after the relay word
    /// (karyos#772).
    pub(crate) const fn is_cluster(self) -> bool {
        matches!(
            self,
            Self::ClusterRequest | Self::ClusterOutcome | Self::ClusterRefused
        )
    }

    /// Whether its record establishes an operation id the agent rebuilds
    /// at start (karyos#738, karyos#739, karyos#772): a purge never
    /// removes one whose id is still retained.
    pub(crate) const fn establishes_id(self) -> bool {
        matches!(
            self,
            Self::ApprovalRequested | Self::Submitted | Self::ClusterRequest
        )
    }

    /// Whether it is one of the two-person flow's records (karyos#739),
    /// which carry the approval fields after the relay word.
    pub(crate) const fn is_approval(self) -> bool {
        matches!(
            self,
            Self::ApprovalRequested
                | Self::ApprovalGranted
                | Self::ApprovalWithdrawn
                | Self::ApprovalExpired
        )
    }
}

/// One journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalRecord {
    /// What it says.
    pub kind: Kind,
    /// Host `CLOCK_MONOTONIC` nanoseconds.
    pub time: u64,
    /// The guard id; 0 for an unknown interval or an acknowledgement.
    pub guard: u64,
    /// The epoch a reopen expects; the interval's start for an unknown
    /// interval; the acknowledged interval's position for an
    /// acknowledgement; else 0.
    pub expected: u64,
    /// The operation id.
    pub operation: u64,
    /// The operator's uid (the administrator's, for an acknowledgement).
    pub operator: u64,
    /// The command's parameters digest.
    pub parameters: u64,
    /// An outcome's control error code, 0 when it succeeded or for a
    /// request.
    pub code: u64,
    /// An outcome's guard word after it, else 0.
    pub word: u64,
    /// The operator's reason, at most [`MAX_REASON`] bytes.
    pub reason: Vec<u8>,
    /// The relay that carried the request for the operator, a remote
    /// control-plane component's configured relay id (karyos#708); 0 for
    /// a request made on the local socket, which no relay carried. The
    /// operator is then the authenticated requester, never the relay.
    pub relay: u64,
    /// A [`Kind::Submitted`] record's driver directory, or a Cluster
    /// record's Cluster name (karyos#772), as bytes; empty for every other
    /// kind.
    pub target: Vec<u8>,
    /// A [`Kind::Submitted`] record's host boot identity (Linux's
    /// `boot_id`), as bytes; empty for every other kind, or when unknown.
    pub boot: Vec<u8>,
    /// A Cluster record's command name (karyos#772); empty for every other
    /// kind.
    pub command: Vec<u8>,
    /// A [`Kind::ClusterOutcome`] record's evidence,
    /// `<algorithm>:<hex digest>`; empty when none was attached, and for
    /// every other kind.
    pub evidence: Vec<u8>,
    /// An approval record's parameter bytes, a Cluster command's
    /// (karyos#739); empty for every other kind.
    pub bytes: Vec<u8>,
    /// An approval record's target instance (karyos#739): the driver's, or
    /// the attach instance of the gateway that registered the Cluster; 0
    /// for every other kind.
    pub instance: u128,
}

impl JournalRecord {
    /// A record of `kind` at `time`, every other field zero.
    #[must_use]
    pub const fn new(kind: Kind, time: u64) -> Self {
        Self {
            kind,
            time,
            guard: 0,
            expected: 0,
            operation: 0,
            operator: 0,
            parameters: 0,
            code: 0,
            word: 0,
            reason: Vec::new(),
            relay: 0,
            target: Vec::new(),
            boot: Vec::new(),
            command: Vec::new(),
            evidence: Vec::new(),
            bytes: Vec::new(),
            instance: 0,
        }
    }

    /// The record's payload: eleven little-endian words (the layout's
    /// version, the kind, then the fields in declaration order, then the
    /// reason's length) and the reason, cut to [`MAX_REASON`] bytes; then,
    /// for a relayed request only, the relay as one more little-endian
    /// word (karyos#708). A [`Kind::Submitted`] record always has the relay
    /// word, then its target and boot, each after its length word; a
    /// Cluster record (karyos#772) the relay word, then its target, command
    /// and evidence the same way; an approval record (karyos#739) the relay
    /// word, then its target, command, boot, parameter bytes and instance
    /// (16 little-endian bytes) the same way. A record no relay carried is byte for byte what
    /// it was before relays, and a reader of the layout that stops at the
    /// reason reads either.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let reason = self.reason.get(..MAX_REASON).unwrap_or(&self.reason);
        let words = [
            VERSION,
            self.kind.code(),
            self.time,
            self.guard,
            self.expected,
            self.operation,
            self.operator,
            self.parameters,
            self.code,
            self.word,
            u64::try_from(reason.len()).unwrap_or(0),
        ];
        let mut out: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        out.extend_from_slice(reason);
        let instance = self.instance.to_le_bytes().to_vec();
        let fields: &[&Vec<u8>] = if self.kind == Kind::Submitted {
            // The relay word always, then the target and the boot, each
            // after its length word (karyos#738).
            &[&self.target, &self.boot]
        } else if self.kind.is_cluster() {
            &[&self.target, &self.command, &self.evidence]
        } else if self.kind.is_approval() {
            &[
                &self.target,
                &self.command,
                &self.boot,
                &self.bytes,
                &instance,
            ]
        } else {
            &[]
        };
        if !fields.is_empty() {
            out.extend_from_slice(&self.relay.to_le_bytes());
            for field in fields {
                out.extend_from_slice(&u64::try_from(field.len()).unwrap_or(0).to_le_bytes());
                out.extend_from_slice(field);
            }
        } else if self.relay != 0 {
            out.extend_from_slice(&self.relay.to_le_bytes());
        }
        out
    }

    /// The record of `payload`, if it is one of this layout.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let word = |index: usize| -> Option<u64> {
            let start = index.checked_mul(8)?;
            let bytes = payload.get(start..start.checked_add(8)?)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        };
        if word(0)? != VERSION {
            return None;
        }
        let length = usize::try_from(word(10)?).ok()?;
        let start = WORDS.checked_mul(8)?;
        let end = start.checked_add(length)?;
        let reason = payload.get(start..end)?;
        let kind = Kind::from_code(word(1)?)?;
        let tail = payload.get(end..)?;
        let mut target = Vec::new();
        let mut boot = Vec::new();
        let mut command = Vec::new();
        let mut evidence = Vec::new();
        let mut bytes = Vec::new();
        let mut instance = 0;
        let relay = if kind == Kind::Submitted || kind.is_cluster() || kind.is_approval() {
            // The relay word, then the fields by length.
            let (relay, mut rest) = tail.split_first_chunk::<8>()?;
            let mut field = || -> Option<Vec<u8>> {
                let (length, after) = rest.split_first_chunk::<8>()?;
                let length = usize::try_from(u64::from_le_bytes(*length)).ok()?;
                let bytes = after.get(..length)?;
                rest = after.get(length..)?;
                Some(bytes.to_vec())
            };
            target = field()?;
            if kind == Kind::Submitted {
                boot = field()?;
            } else if kind.is_approval() {
                command = field()?;
                boot = field()?;
                bytes = field()?;
                instance = u128::from_le_bytes(field()?.try_into().ok()?);
            } else {
                command = field()?;
                evidence = field()?;
            }
            if !rest.is_empty() {
                return None;
            }
            u64::from_le_bytes(*relay)
        } else {
            // The relay word, when one follows the reason; nothing else may.
            match tail {
                [] => 0,
                tail => u64::from_le_bytes(tail.try_into().ok()?),
            }
        };
        Some(Self {
            kind,
            time: word(2)?,
            guard: word(3)?,
            expected: word(4)?,
            operation: word(5)?,
            operator: word(6)?,
            parameters: word(7)?,
            code: word(8)?,
            word: word(9)?,
            reason: reason.to_vec(),
            relay,
            target,
            boot,
            command,
            evidence,
            bytes,
            instance,
        })
    }
}

/// Why the journal records an unknown interval: an administrator tells a
/// crash from a lost operation before acknowledging it. Carried in the
/// unknown-interval record's `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GapReason {
    /// The last record was a request with no outcome after it: the
    /// operation may have taken effect unrecorded.
    RequestWithoutOutcome,
    /// Recovery cut a torn tail: records after the cut are lost.
    TornTail,
    /// The last run did not end with [`Kind::AgentStopped`]: a crash, a
    /// kill, a signal stop (until karyos-agent catches signals, owner item
    /// 55) or a stop that could not be written. A close made while the
    /// journal was down then has no record at all.
    UncleanStop,
    /// The journal recording was stopped by another hand, and a new one
    /// begins.
    JournalReplaced,
    /// The journal could not be opened at the agent's start, so nothing
    /// of the run is recorded. Never written: the agent holds it in memory
    /// at [`UNOPENED_POSITION`], and its acknowledgement too.
    JournalUnavailableAtStart,
}

/// The position that names the unknown interval of a journal that could
/// not be opened ([`GapReason::JournalUnavailableAtStart`]): it has no
/// record, so no position in the journal.
pub const UNOPENED_POSITION: u64 = u64::MAX;

impl GapReason {
    /// The code an unknown-interval record carries.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::RequestWithoutOutcome => 1,
            Self::TornTail => 2,
            Self::UncleanStop => 3,
            Self::JournalReplaced => 4,
            Self::JournalUnavailableAtStart => 5,
        }
    }

    /// Its name, as the view and the history show it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RequestWithoutOutcome => "request_without_outcome",
            Self::TornTail => "torn_tail",
            Self::UncleanStop => "unclean_stop",
            Self::JournalReplaced => "journal_replaced",
            Self::JournalUnavailableAtStart => "journal_unavailable_at_start",
        }
    }

    /// The reason of `code`; an unknown one reads as an unclean stop, the
    /// most general.
    #[must_use]
    pub const fn from_code(code: u64) -> Self {
        match code {
            1 => Self::RequestWithoutOutcome,
            2 => Self::TornTail,
            4 => Self::JournalReplaced,
            5 => Self::JournalUnavailableAtStart,
            _ => Self::UncleanStop,
        }
    }
}

/// An unknown interval no administrator has acknowledged yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Gap {
    /// Its record's position in the journal.
    pub position: u64,
    /// Why it was recorded.
    pub reason: GapReason,
    /// The interval's start: the last record's time before it, 0 when
    /// none was readable.
    pub from: u64,
    /// The interval's end: the start of the agent that recorded it.
    pub to: u64,
}

/// Why the journal could not open or append.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The catalog's error.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// The store's error.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// The recorder's error.
    #[error(transparent)]
    Recorder(#[from] RecorderError),
    /// The queue's refusal.
    #[error(transparent)]
    Queue(#[from] QueueError),
    /// An earlier append failed: the journal stays unavailable until the
    /// agent restarts.
    #[error("the journal is unavailable")]
    Unavailable,
    /// The record was written but did not become durable.
    #[error("the journal record is not durable")]
    NotDurable,
    /// The segment the record would leave could not be closed first: its
    /// seal, the wall clock or its close entry failed (ADR-0115, point 1).
    /// Nothing was written; the next append tries the close again.
    #[error("the journal segment could not be closed")]
    NotClosed,
    /// No unknown interval is open, or another one is.
    #[error("no such unknown interval")]
    NoGap,
    /// The journal holds something that is not a frame at `position`.
    #[error("the journal is corrupt at {position}")]
    Corrupt {
        /// Where.
        position: u64,
    },
}

/// The operations journal (see the module).
#[derive(Debug)]
pub struct Journal {
    recorder: Option<JournalRecorder>,
    recording: u64,
    failed_appends: u64,
    /// Host time of the first failed append.
    failed_at: Option<u64>,
    gap: Option<Gap>,
    /// The integrity journal sealing the recording; `None` once a seal
    /// failed.
    integrity: Option<IntegrityJournal<StdDisk>>,
    failed_seals: u64,
    /// The bytes of one seal, reused.
    seal_buf: Vec<u8>,
    /// The most bytes one seal reads.
    seal_chunk: u64,
    /// The journal's directory, which a verification reads.
    dir: PathBuf,
    /// The last verification that could run.
    verification: Option<Integrity>,
    /// The retention settings (ADR-0113).
    settings: JournalRetention,
    /// The retention engine; `None` when its ledgers cannot be opened, the
    /// hold state then unreadable.
    retention: Option<retention::State>,
    /// A close entry failed: the retention ledger is poisoned until it is
    /// reopened, which the next rollover does first (ADR-0115, point 1).
    reopen_retention: bool,
    /// The records the open read, for tests.
    #[cfg(test)]
    pub(crate) scanned: Vec<JournalRecord>,
    /// The records the agent rebuilds its operation ids from, until taken
    /// ([`Journal::take_operations`]).
    operations: Vec<JournalRecord>,
    /// Where each record that establishes an operation id is, with that
    /// id, oldest first ([`Kind::establishes_id`]).
    id_records: Vec<(u64, u64)>,
}

/// The journal's recorder.
pub(crate) type JournalRecorder = Recorder<StdDisk, QueueSource>;

impl Journal {
    /// The [`Kind::Submitted`] and [`Kind::ClusterRequest`] records the
    /// open read, oldest first, taken once (karyos#738, karyos#772): the
    /// agent rebuilds its retained outcomes and caller ids from them. With
    /// them, the two-person flow's records and the dispatch records it
    /// follows (karyos#739): [`Kind::ReopenRequest`],
    /// [`Kind::ClusterOutcome`] and the four approval kinds.
    pub fn take_operations(&mut self) -> Vec<JournalRecord> {
        std::mem::take(&mut self.operations)
    }

    /// Opens the journal in `dir` at host time `now`, creating the
    /// directory if need be: resumes its open recording, or starts one,
    /// then records an unknown interval when the last run may have lost a
    /// record.
    ///
    /// # Errors
    ///
    /// [`JournalError`] when the directory's catalog or the recording
    /// cannot be opened, or the unknown interval cannot be recorded.
    pub fn open(dir: &Path, now: u64) -> Result<Self, JournalError> {
        Self::open_with(dir, now, JournalRetention::default())
    }

    /// [`Journal::open`] with the retention `settings` (ADR-0113): the
    /// engine is opened, the policy recorded and outstanding purges
    /// recovered before the first verification.
    ///
    /// # Errors
    ///
    /// As [`Journal::open`].
    pub fn open_with(
        dir: &Path,
        now: u64,
        settings: JournalRetention,
    ) -> Result<Self, JournalError> {
        let geometry = Geometry::with_default_length(TERM_LENGTH)?;
        Self::open_inner(dir, now, SEAL_CHUNK, geometry, settings)
    }

    /// [`Journal::open`] with seals of at most `seal_chunk` bytes.
    #[cfg(test)]
    pub(crate) fn open_chunked(
        dir: &Path,
        now: u64,
        seal_chunk: u64,
    ) -> Result<Self, JournalError> {
        let geometry = Geometry::with_default_length(TERM_LENGTH)?;
        Self::open_inner(dir, now, seal_chunk, geometry, JournalRetention::default())
    }

    /// Tests: [`Journal::open_with`] with segments of one term, so a test
    /// fills several.
    #[cfg(test)]
    pub(crate) fn open_small(
        dir: &Path,
        now: u64,
        settings: JournalRetention,
    ) -> Result<Self, JournalError> {
        let geometry = Geometry::new(TERM_LENGTH, u64::from(TERM_LENGTH))?;
        Self::open_inner(dir, now, SEAL_CHUNK, geometry, settings)
    }

    fn open_inner(
        dir: &Path,
        now: u64,
        seal_chunk: u64,
        geometry: Geometry,
        settings: JournalRetention,
    ) -> Result<Self, JournalError> {
        std::fs::create_dir_all(dir).map_err(CatalogError::Io)?;
        let mut catalog = Catalog::open(StdDisk, dir)?.catalog;
        let open = catalog
            .recordings()
            .iter()
            .rev()
            .find(|recording| recording.channel == CHANNEL)
            .map(|recording| (recording.id, recording.stop.is_none(), recording.geometry));
        let (recording, store, cut, earlier) = match open {
            Some((id, true, geometry)) => {
                let recovered =
                    SegmentStore::recover(StdDisk, dir, id, geometry, SyncPolicy::PerSegment)?;
                (id, recovered.store, recovered.cut.is_some(), false)
            }
            // A stopped journal is not this agent's to resume: a new one
            // starts, and what happened between them is not known.
            stopped => {
                let id = catalog.start(new_recording(geometry, now))?;
                let store =
                    SegmentStore::create(StdDisk, dir, id, geometry, SyncPolicy::PerSegment, 0)?;
                (id, store, false, stopped.is_some())
            }
        };
        let mut store = store;
        let scan = scan(&mut store)?;
        let source = QueueSource::new(
            QueueConfig::new(store.geometry(), 0, 0, MAX_QUEUED),
            store.written(),
        )?;
        let buffer = usize::try_from(TERM_LENGTH).map_err(|_| QueueError::Exhausted)?;
        let recorder = Recorder::new(store, source, Mode::Required, buffer, MAX_QUEUED)?;
        // An integrity journal that cannot be opened leaves the journal
        // unsealed, counted, never unavailable.
        let integrity = IntegrityJournal::open(StdDisk, dir)
            .ok()
            .map(|opened| opened.journal);
        let mut journal = Self {
            recorder: Some(recorder),
            recording,
            failed_appends: 0,
            failed_at: None,
            gap: scan.gap,
            failed_seals: u64::from(integrity.is_none()),
            integrity,
            seal_buf: Vec::new(),
            seal_chunk,
            dir: dir.to_path_buf(),
            verification: None,
            settings,
            retention: None,
            reopen_retention: false,
            #[cfg(test)]
            scanned: scan.all.clone(),
            operations: scan.operations,
            id_records: scan.id_records,
        };
        // The close times first: this start's records never land in a
        // segment already closed (ADR-0115, point 1).
        journal.open_retention();
        let last = scan.last.as_ref().map(|last| last.kind);
        let reason = if cut {
            Some(GapReason::TornTail)
        } else if earlier {
            Some(GapReason::JournalReplaced)
        } else if last.is_some_and(Kind::is_request) {
            Some(GapReason::RequestWithoutOutcome)
        } else if last.is_some_and(|kind| kind != Kind::AgentStopped) {
            Some(GapReason::UncleanStop)
        } else {
            // An empty journal, or one that ends with a clean stop.
            None
        };
        if let Some(reason) = reason {
            let mut record = JournalRecord::new(Kind::UnknownInterval, now);
            record.expected = scan.last.map_or(0, |last| last.time);
            record.code = reason.code();
            let position = journal.append_durable(&record, now)?;
            journal.gap = Some(Gap {
                position,
                reason,
                from: record.expected,
                to: now,
            });
        }
        // This run's first record: from here on, a run that does not end
        // with a clean stop is seen as one.
        let _ = journal.append_durable(&JournalRecord::new(Kind::AgentStarted, now), now)?;
        // Recovery before the first verification (ADR-0113, point 8).
        journal.recover_purges(now);
        journal.verify(now);
        Ok(journal)
    }

    /// The journal recording's id in its directory's catalog.
    #[must_use]
    pub const fn recording(&self) -> u64 {
        self.recording
    }

    /// Appends that failed since the agent started.
    #[must_use]
    pub const fn failed_appends(&self) -> u64 {
        self.failed_appends
    }

    /// Host time of the first append that failed, if one did.
    #[must_use]
    pub const fn failed_at(&self) -> Option<u64> {
        self.failed_at
    }

    /// Seals that failed (or an integrity journal that could not be
    /// opened) since the agent started: the journal's later ranges are
    /// unsealed.
    #[must_use]
    pub const fn failed_seals(&self) -> u64 {
        self.failed_seals
    }

    /// Whether a part of the recording has no seal (karyos#702): a seal
    /// failed, or the integrity journal could not be opened; records were
    /// written past the sealed end, until the next durable append seals
    /// them; or an append failed, and that end is no longer known.
    #[must_use]
    pub fn unsealed(&self) -> bool {
        let (Some(recorder), Some(integrity)) = (self.recorder.as_ref(), self.integrity.as_ref())
        else {
            return true;
        };
        let store = recorder.store();
        self.failed_seals > 0
            || integrity
                .sealed_end(self.recording)
                .unwrap_or(store.start())
                < store.written()
    }

    /// The last verification that could run (see the module).
    #[must_use]
    pub const fn integrity(&self) -> Option<&Integrity> {
        self.verification.as_ref()
    }

    /// Verifies the journal at host time `now` when the last verification
    /// is [`VERIFY_PERIOD_NS`] old, or none ran.
    pub fn verify_if_due(&mut self, now: u64) {
        let due = self
            .verification
            .as_ref()
            .is_none_or(|last| now.saturating_sub(last.at) >= VERIFY_PERIOD_NS);
        if due {
            self.verify(now);
        }
    }

    /// Verifies the journal's recording at host time `now` with the
    /// Archive's verifier (see the module); [`Journal::integrity`] then
    /// reports it. Nothing is kept when the journal is unavailable or its
    /// integrity journal cannot be read.
    pub fn verify(&mut self, now: u64) {
        self.verification = self.verified(now);
    }

    fn verified(&mut self, now: u64) -> Option<Integrity> {
        let recorder = self.recorder.as_mut()?;
        let (records, journal_fault) = read_records(&mut StdDisk, &self.dir).ok()?;
        let id = self.recording;
        let written = recorder.store().written();
        let trust = self.settings.trust.as_ref();
        let externality = trust
            .map(|trust| trust.externality.clone())
            .unwrap_or_default();
        let (keys, heads) = retention::trust_files(&self.dir, trust);
        let (anchors, anchor_stores, anchor_faults) =
            retention::anchor_stores(&self.settings.anchors);
        let evidence = Evidence {
            records: &records,
            journal_fault,
            journal_id: trust.map_or(0, |trust| trust.journal_id),
            trust: trust.map(|trust| &trust.root),
            registry: &keys,
            heads: &heads,
            anchors: &anchors,
            anchor_faults,
            stores: &anchor_stores,
            externality: &externality,
            written: &[(id, written)],
        };
        let verification = verify(&evidence, |recording, start, end| {
            // The journal's own ranges only, within what it wrote: a seal
            // is corrupt input, checked before anything is allocated.
            let Some(length) = end
                .checked_sub(start)
                .filter(|_| recording == id && end <= written)
                .and_then(|length| usize::try_from(length).ok())
            else {
                return RangeBytes::Missing;
            };
            let mut bytes = vec![0; length];
            match recorder.read(start, &mut bytes) {
                Ok(()) => RangeBytes::Bytes(bytes),
                Err(_) => RangeBytes::Missing,
            }
        });
        let mut integrity = Integrity::of(
            now,
            verification
                .ranges
                .iter()
                .filter(|report| report.recording == id),
        );
        integrity.purged = retention::purged_of(&records, id);
        Some(integrity)
    }

    /// Whether an append failed: the journal then refuses every append.
    #[must_use]
    pub const fn unavailable(&self) -> bool {
        self.recorder.is_none()
    }

    /// The unknown interval not acknowledged yet, if any.
    #[must_use]
    pub const fn gap(&self) -> Option<Gap> {
        self.gap
    }

    /// Appends `record` at host time `now`, written to the store but not
    /// necessarily durable; returns its position.
    ///
    /// # Errors
    ///
    /// [`JournalError`]; the journal is then unavailable, and the failure
    /// counted.
    pub fn append(&mut self, record: &JournalRecord, now: u64) -> Result<u64, JournalError> {
        self.write(record, now, false)
    }

    /// Appends `record` at host time `now` and makes it durable before it
    /// returns its position.
    ///
    /// # Errors
    ///
    /// As [`Journal::append`], and [`JournalError::NotDurable`].
    pub fn append_durable(
        &mut self,
        record: &JournalRecord,
        now: u64,
    ) -> Result<u64, JournalError> {
        self.write(record, now, true)
    }

    /// Records administrator `uid`'s acknowledgement of the open unknown
    /// interval at `position`, durably, and closes it.
    ///
    /// # Errors
    ///
    /// [`JournalError::NoGap`] when that interval is not the open one, and
    /// as [`Journal::append_durable`].
    pub fn acknowledge_gap(
        &mut self,
        position: u64,
        uid: u64,
        now: u64,
    ) -> Result<(), JournalError> {
        self.acknowledge_gap_relayed(position, uid, 0, now)
    }

    /// As [`Journal::acknowledge_gap`], for administrator `operator`
    /// whose request relay `relay` carried (0 for none; karyos#708).
    ///
    /// # Errors
    ///
    /// As [`Journal::acknowledge_gap`].
    pub fn acknowledge_gap_relayed(
        &mut self,
        position: u64,
        operator: u64,
        relay: u64,
        now: u64,
    ) -> Result<(), JournalError> {
        if self.gap.map(|gap| gap.position) != Some(position) {
            return Err(JournalError::NoGap);
        }
        let mut record = JournalRecord::new(Kind::GapAcknowledged, now);
        record.expected = position;
        record.operator = operator;
        record.relay = relay;
        let _ = self.append_durable(&record, now)?;
        self.gap = None;
        Ok(())
    }

    fn write(
        &mut self,
        record: &JournalRecord,
        now: u64,
        durable: bool,
    ) -> Result<u64, JournalError> {
        if self.recorder.is_none() {
            self.count_failure(now);
            return Err(JournalError::Unavailable);
        }
        // A segment left is closed, its time recorded, before this record
        // is written (ADR-0115, point 1). A close that could not be made
        // writes nothing and is tried again at the next append.
        if let Err(error) = self.close_before(record, now) {
            if !matches!(error, JournalError::NotClosed) {
                self.recorder = None;
            }
            self.count_failure(now);
            return Err(error);
        }
        let Some(recorder) = self.recorder.as_mut() else {
            self.count_failure(now);
            return Err(JournalError::Unavailable);
        };
        let result = (|| {
            let position = recorder.store().written();
            let end = recorder.source_mut().push(&record.encode())?;
            let _ = recorder.duty(now)?;
            if recorder.store().written() < end {
                return Err(JournalError::NotDurable);
            }
            if durable && recorder.sync()? < end {
                return Err(JournalError::NotDurable);
            }
            // A padding block may precede the frame: the record is where
            // its frame starts, the end less its aligned length.
            Ok(frame_start(end, record).unwrap_or(position))
        })();
        if result.is_err() {
            self.recorder = None;
            self.count_failure(now);
        } else {
            if let Ok(position) = result
                && record.kind.establishes_id()
            {
                self.id_records.push((position, record.operation));
            }
            self.after_write();
            if durable {
                self.seal();
            }
        }
        result
    }

    /// Seals the recording from where its seals end to its durable end.
    fn seal(&mut self) {
        let (Some(recorder), Some(integrity)) = (self.recorder.as_mut(), self.integrity.as_mut())
        else {
            return;
        };
        let start = integrity
            .sealed_end(self.recording)
            .unwrap_or(recorder.store().start());
        let end = recorder.store().durable();
        // At most `seal_chunk` bytes at a time: a journal from before
        // sealing is sealed in pieces, never read whole (karyos#1071).
        // A seal never crosses a segment boundary, so a purge may cut at
        // any boundary sealed (ADR-0113, point 7).
        let chunk = self.seal_chunk.max(1);
        let geometry = recorder.store().geometry();
        let sealed = (|| {
            let mut from = start;
            while from < end {
                let boundary = geometry
                    .base_of(from)
                    .saturating_add(geometry.segment_length());
                let to = end.min(from.saturating_add(chunk)).min(boundary);
                let length = usize::try_from(to.saturating_sub(from)).map_err(|_| ())?;
                self.seal_buf.resize(length, 0);
                recorder.read(from, &mut self.seal_buf).map_err(|_| ())?;
                integrity
                    .seal_segment(self.recording, from, &self.seal_buf, false)
                    .map_err(|_| ())?;
                from = to;
            }
            Ok::<(), ()>(())
        })();
        if sealed.is_err() {
            self.integrity = None;
            self.failed_seals = self.failed_seals.saturating_add(1);
        }
    }

    /// Records the agent's clean stop, durably, as its last record: the
    /// next start then records no unknown interval for this run. The one
    /// stop of the journal; a signal handler calls it once karyos-agent
    /// may catch signals (owner item 55).
    ///
    /// # Errors
    ///
    /// As [`Journal::append_durable`]: a journal already unavailable
    /// cannot record its stop, and the next start records the unclean
    /// stop, which is then exactly right.
    pub fn stop(&mut self, now: u64) -> Result<(), JournalError> {
        let _ = self.append_durable(&JournalRecord::new(Kind::AgentStopped, now), now)?;
        Ok(())
    }

    /// Tests: the seal buffer's capacity.
    #[cfg(test)]
    pub(crate) fn seal_capacity(&self) -> usize {
        self.seal_buf.capacity()
    }

    /// Tests: the recorder's store, to crash a purge part way.
    #[cfg(test)]
    pub(crate) fn store_mut(&mut self) -> &mut SegmentStore<StdDisk> {
        self.recorder
            .as_mut()
            .expect("an available journal")
            .store_mut()
    }

    /// Tests: the journal as an append failure leaves it.
    #[cfg(test)]
    pub(crate) fn break_recorder(&mut self) {
        self.recorder = None;
    }

    /// Tests: flips the byte at `position` of the recording's first
    /// segment on disk, as media damage would.
    #[cfg(test)]
    pub(crate) fn damage(&self, position: u64) {
        use std::io::{Read, Seek, SeekFrom, Write};

        let recorder = self.recorder.as_ref().expect("an available journal");
        let (data, _) = recorder.store().segment_paths(0);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(data)
            .expect("the segment opens");
        let mut byte = [0u8; 1];
        file.seek(SeekFrom::Start(position)).expect("seek");
        file.read_exact(&mut byte).expect("read");
        file.seek(SeekFrom::Start(position)).expect("seek");
        file.write_all(&[byte[0] ^ 0xff]).expect("write");
        file.sync_all().expect("sync");
    }

    fn count_failure(&mut self, now: u64) {
        self.failed_at.get_or_insert(now);
        // Checked: at its end the count keeps its value.
        if let Some(next) = self.failed_appends.checked_add(1) {
            self.failed_appends = next;
        }
    }
}

/// A verification of the journal's recording (karyos#702).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Integrity {
    /// When it ran: host `CLOCK_MONOTONIC` nanoseconds.
    pub at: u64,
    /// Each range's outcome and reasons, the verifier's names, in order;
    /// adjacent ranges with the same outcome and reasons are one, and at
    /// most [`MAX_INTEGRITY_RANGES`] are kept.
    pub ranges: Vec<RangeOutcome>,
    /// Whether ranges past [`MAX_INTEGRITY_RANGES`] were left out.
    pub truncated: bool,
    /// Each purged prefix the integrity journal chains, with its purge
    /// evidence (ADR-0113, point 8); the ranges above say whether that
    /// evidence is authenticated.
    pub purged: Vec<Purged>,
}

impl Integrity {
    fn of<'a>(at: u64, reports: impl Iterator<Item = &'a RangeReport>) -> Self {
        let mut ranges: Vec<RangeOutcome> = Vec::new();
        let mut truncated = false;
        for report in reports {
            let outcome = report.outcome.name();
            let reasons: Vec<String> = report
                .reasons
                .iter()
                .map(|reason| reason.name().to_owned())
                .collect();
            if let Some(last) = ranges.last_mut()
                && last.end == report.start
                && last.outcome == outcome
                && last.reasons == reasons
            {
                last.end = report.end;
                continue;
            }
            if ranges.len() == MAX_INTEGRITY_RANGES {
                truncated = true;
                break;
            }
            ranges.push(RangeOutcome {
                start: report.start,
                end: report.end,
                outcome: outcome.to_owned(),
                reasons,
            });
        }
        Self {
            at,
            ranges,
            truncated,
            purged: Vec::new(),
        }
    }
}

/// The anchor stores a verification of the journal reads: none.
#[derive(Debug)]
struct NoAnchors;

impl AnchorEvidence for NoAnchors {
    fn confirms(&self, _anchor: &Anchor) -> bool {
        false
    }
}

/// The catalog entry of a new journal recording.
fn new_recording(geometry: Geometry, now: u64) -> NewRecording<'static> {
    NewRecording {
        stream_id: 0,
        session_id: 0,
        channel: CHANNEL,
        start: 0,
        start_time_ns: now,
        geometry,
        policy: SyncPolicy::PerSegment,
        format: StreamFormat {
            lane: Lane::ZERO,
            initial_term_id: 0,
            mtu: MTU,
            source: SourceIncarnation {
                driver: [0, 0],
                registration: 0,
                incarnation: 0,
            },
        },
        required: true,
    }
}

/// Where the frame of `record` starts, given the position after it.
fn frame_start(end: u64, record: &JournalRecord) -> Option<u64> {
    let length = u64::try_from(record.encode().len())
        .ok()?
        .checked_add(u64::from(HEADER_LENGTH))?
        .checked_next_multiple_of(u64::from(FRAME_ALIGNMENT))?;
    end.checked_sub(length)
}

/// What a scan of the journal found.
#[derive(Debug, Default)]
struct Scan {
    /// The last record.
    last: Option<JournalRecord>,
    /// The latest unknown interval, unless an acknowledgement follows it.
    gap: Option<Gap>,
    /// Every record, for tests that read a journal back.
    #[cfg(test)]
    all: Vec<JournalRecord>,
    /// The [`Kind::Submitted`] and [`Kind::ClusterRequest`] records, oldest
    /// first: the agent's retained outcomes and caller ids are rebuilt from
    /// them (karyos#738, karyos#772).
    operations: Vec<JournalRecord>,
    /// Where each record that establishes an operation id is, with that
    /// id ([`Kind::establishes_id`]).
    id_records: Vec<(u64, u64)>,
}

/// Reads every frame of `store`, oldest first.
fn scan(store: &mut SegmentStore<StdDisk>) -> Result<Scan, JournalError> {
    let mut found = Scan::default();
    let mut position = store.start();
    let mut header = [0u8; HEADER_LENGTH as usize];
    let mut payload = Vec::new();
    while position < store.written() {
        store.read(position, &mut header)?;
        let corrupt = JournalError::Corrupt { position };
        let word0 = header
            .get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .and_then(|raw| Word0::unpack(raw).ok())
            .ok_or(JournalError::Corrupt { position })?;
        let extent = if word0.frame_type_code() == FrameType::Pad.code() {
            header
                .get(24..32)
                .and_then(|bytes| bytes.try_into().ok())
                .map(i64::from_le_bytes)
                .and_then(|extent| u64::try_from(extent).ok())
                .ok_or(corrupt)?
        } else {
            let length = u32::try_from(word0.frame_length())
                .ok()
                .filter(|length| *length >= HEADER_LENGTH)
                .ok_or(JournalError::Corrupt { position })?;
            let body = usize::try_from(length.abs_diff(HEADER_LENGTH))
                .map_err(|_| JournalError::Corrupt { position })?;
            payload.resize(body, 0);
            let at = position
                .checked_add(u64::from(HEADER_LENGTH))
                .ok_or(JournalError::Corrupt { position })?;
            store.read(at, &mut payload)?;
            if let Some(record) = JournalRecord::decode(&payload) {
                match record.kind {
                    Kind::UnknownInterval => {
                        found.gap = Some(Gap {
                            position,
                            reason: GapReason::from_code(record.code),
                            from: record.expected,
                            to: record.time,
                        });
                    }
                    Kind::GapAcknowledged
                        if found.gap.map(|gap| gap.position) == Some(record.expected) =>
                    {
                        found.gap = None;
                    }
                    _ => {}
                }
                #[cfg(test)]
                found.all.push(record.clone());
                if matches!(
                    record.kind,
                    Kind::Submitted
                        | Kind::ClusterRequest
                        | Kind::ClusterOutcome
                        | Kind::ReopenRequest
                ) || record.kind.is_approval()
                {
                    found.operations.push(record.clone());
                }
                if record.kind.establishes_id() {
                    found.id_records.push((position, record.operation));
                }
                found.last = Some(record);
            }
            u64::from(length)
                .checked_next_multiple_of(u64::from(FRAME_ALIGNMENT))
                .ok_or(JournalError::Corrupt { position })?
        };
        if extent == 0 {
            return Err(JournalError::Corrupt { position });
        }
        position = position
            .checked_add(extent)
            .ok_or(JournalError::Corrupt { position })?;
    }
    Ok(found)
}
