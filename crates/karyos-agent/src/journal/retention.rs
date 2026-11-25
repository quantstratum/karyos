// SPDX-License-Identifier: Apache-2.0

//! Retention, legal hold and purge of the operations journal (ADR-0113;
//! karyos#702).
//!
//! - **The engine.** The Archive library's [`Retention`], unchanged, over
//!   the journal's own directory: its operations ledger
//!   ([`OPERATIONS_FILE`]), its pending holds marker
//!   ([`PENDING_HOLDS_FILE`]) and its policy book ([`PolicyBook`], chained
//!   in the journal's integrity journal). No retention rule is
//!   reimplemented here.
//! - **One writer.** A purge, and the recovery of one, run through the
//!   journal recorder's own [`SegmentStore`], on the agent's polling
//!   thread: serialised with every append, seal and verification.
//! - **The policy.** `--journal-retention` ([`JournalPolicy`]), recorded
//!   as a policy version at start when it differs from the one in force.
//!   Without it no policy is in force and every purge is refused.
//! - **Copies.** Each `--journal-copy <location>=<dir>` is verified with
//!   the Archive's verifier before every purge decision; a copy that
//!   verifies over the candidate prefix is recorded `verified` in the
//!   journal's copy catalog for that prefix, and every other `verified`
//!   record is withdrawn, so the library's `min_copies` rule counts only
//!   copies verified now.
//! - **The expiry clock** (ADR-0115, superseding ADR-0113 point 5). When
//!   the writer closes a segment, its close time on the host's wall clock
//!   is recorded in the operations ledger ([`Operation::SegmentClosed`]) at
//!   the rollover, in order: the predecessor's last record and seal
//!   durable, the clock read, the entry synced, and only then the
//!   successor's first record written. A prefix expires once every
//!   segment's own close time plus `retain_for` has passed, so a clock
//!   stepped back never expires an older segment early; a prefix with a
//!   segment that has none (the current one, one closed before this
//!   change, a lost entry) never expires. File times are never read.
//!   Recovery rechecks expiry over an intent's whole original range.
//! - **Purges** fall on segment boundaries only, never inside the current
//!   segment; a `BEFORE` inside a segment is refused, never rounded.
//! - **Recovery** runs at open, before the journal's first verification,
//!   each outstanding intent's audit record made durable first; an intent
//!   it cannot reconcile stays outstanding (`purge_pending`) and refuses
//!   every further purge.

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use karyos_archive::control::HoldState;
use karyos_archive::disk::{ReadOnly, StdDisk};
use karyos_archive::integrity::anchor::Externality;
use karyos_archive::integrity::copies::{
    ArrivalProfile, CopyCatalog, CopyRecord, CopyState, Enforcement,
};
use karyos_archive::integrity::journal::{IntegrityJournal, read_records};
use karyos_archive::integrity::ledger::{Ledger, read_entries};
use karyos_archive::integrity::retention::{
    Authorisation, HoldReport, MARKER_LENGTH, OPERATION_LENGTH, OPERATIONS_FILE, Operation,
    PENDING_HOLDS_FILE, PolicyBook, PurgeContext, PurgeError, PurgeMode, PurgeRefusal,
    PurgeRequest, PurgeSource, Retention, RetentionPolicy, seals_digest,
};
use karyos_archive::integrity::trust::{
    HEADS_FILE, KEYS_FILE, PUBLIC_KEY_LENGTH, REGISTRY_ENTRY_LENGTH, SIGNED_HEAD_LENGTH, TrustRoot,
};
use karyos_archive::integrity::verify::{Evidence, Outcome, RangeBytes, Reason, verify};
use karyos_archive::integrity::{Digest, SealKind, digest};
use karyos_archive::segment::{SegmentStore, SyncPolicy, recorded_geometry};

use super::{Journal, JournalRecord, Kind, NoAnchors};
use crate::retention::RetentionReply;

#[cfg(test)]
mod tests;

/// The `guard` word of a retention record naming the journal itself, not
/// an Archive recording (ADR-0113, point 3).
pub const JOURNAL_SUBJECT: u64 = u64::MAX;
/// The journal policy's identity in its policy book.
const POLICY_ID: u64 = 1;
/// The wire code of a refusal (ADR-0088's `Refused`).
pub const REFUSED: u64 = 8;
/// The wire code of a failure (ADR-0088's `Error`).
const ERROR: u64 = 1;

/// The refusal while a hold is in force in memory only.
pub const HOLD_NOT_DURABLE: &str = "hold_not_durable";
/// The refusal while a purge intent is outstanding.
pub const PURGE_PENDING: &str = "purge_pending";
/// The refusal of a `BEFORE` that is not a segment boundary.
pub const INSIDE_SEGMENT: &str = "inside_segment";
/// The refusal of a `BEFORE` past the journal's current segment's start.
pub const CURRENT_SEGMENT: &str = "current_segment";
/// The refusal of a purge that would remove the record an operation id
/// still retained is rebuilt from (karyos#738, karyos#739 review).
pub const OPERATION_STATE_RETAINED: &str = "operation_state_retained";

/// The code an outcome record keeps in its `word` for refusal `name`: the
/// library's code for its own reasons, 101 on for the agent's.
#[must_use]
pub fn refusal_word(name: &str) -> u64 {
    const LIBRARY: [&str; 15] = [
        "not_authorised",
        "legal_hold",
        "holds_unknown",
        "no_policy",
        "not_expired",
        "below_min_copies",
        "journal_unavailable",
        "wrong_store",
        "splits_seal",
        "not_a_write_start",
        "duplicate_id",
        "manual_only",
        "not_sealed",
        "no_close_time",
        "offloaded",
    ];
    const AGENT: [&str; 5] = [
        HOLD_NOT_DURABLE,
        PURGE_PENDING,
        INSIDE_SEGMENT,
        CURRENT_SEGMENT,
        OPERATION_STATE_RETAINED,
    ];
    let at = |names: &[&str], base: u64| {
        (1u64..)
            .zip(names)
            .find(|(_, known)| **known == name)
            .map(|(code, _)| base.saturating_add(code))
    };
    at(&LIBRARY, 0).or_else(|| at(&AGENT, 100)).unwrap_or(0)
}

/// The journal's retention policy, `--journal-retention
/// retain_for=<duration>[,purge=manual|after_expiry][,min_copies=<n>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalPolicy {
    /// How long a prefix is kept after it closes, in nanoseconds.
    pub retain_for_ns: u64,
    /// When a purge may happen; the agent keeps no schedule, so either
    /// mode purges only on request once the prefix expired.
    pub purge: PurgeMode,
    /// The verified copies elsewhere a purge needs; 1 by default.
    pub min_copies: NonZeroU32,
}

impl JournalPolicy {
    /// The policy `value` states, or `None` for anything else: an unknown
    /// or repeated field, a zero or malformed duration, a zero copy count.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let (mut retain, mut purge, mut min_copies) = (None, None, None);
        for field in value.split(',') {
            let (key, value) = field.split_once('=')?;
            match key {
                "retain_for" if retain.is_none() => {
                    let duration = karyos_protocol::channel::parse_duration(value).ok()?;
                    if duration.is_zero() {
                        return None;
                    }
                    retain = Some(u64::try_from(duration.as_nanos()).ok()?);
                }
                "purge" if purge.is_none() => {
                    purge = Some(match value {
                        "manual" => PurgeMode::Manual,
                        "after_expiry" => PurgeMode::AfterExpiry,
                        _ => return None,
                    });
                }
                "min_copies" if min_copies.is_none() => {
                    min_copies = Some(value.parse::<NonZeroU32>().ok()?);
                }
                _ => return None,
            }
        }
        Some(Self {
            retain_for_ns: retain?,
            purge: purge.unwrap_or(PurgeMode::Manual),
            min_copies: min_copies.unwrap_or(NonZeroU32::MIN),
        })
    }

    const fn policy(self) -> RetentionPolicy {
        RetentionPolicy {
            policy: POLICY_ID,
            version: 1,
            retain_for_ns: self.retain_for_ns,
            min_copies: self.min_copies,
            storage_tier: 0,
            purge: self.purge,
        }
    }
}

/// The trust a verification of the journal, and of its copies, is given
/// (`--journal-trust <file>`): the file `karyos-catalog verify --trust`
/// reads, the same lines.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalTrust {
    /// The trust root: the archive identity and the authority keys.
    pub root: TrustRoot,
    /// What counts as external.
    pub externality: Externality,
    /// The journal's identity in its signed heads.
    pub journal_id: u64,
}

impl JournalTrust {
    /// Reads and parses the trust file at `path`.
    ///
    /// # Errors
    ///
    /// The file cannot be read, or [`JournalTrust::parse`]'s error.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(&text).map_err(|error| format!("{}: {error}", path.display()))
    }

    /// The trust `text` states: `archive HEX`, `authority HEX` (one or
    /// more), `journal N`, `time-journal N` (read, not used: the journal
    /// keeps no time evidence), `local HEX` and `anchors HEX`; `#`
    /// comments and blank lines ignored.
    ///
    /// # Errors
    ///
    /// The first malformed line, or a missing archive or authority.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut archive = None;
        let mut authorities: Vec<[u8; PUBLIC_KEY_LENGTH]> = Vec::new();
        let mut journal_id = 0u64;
        let mut externality = Externality::default();
        for (number, line) in (1usize..).zip(text.lines()) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = || format!("line {number}: {line}");
            let (key, value) = line.split_once(char::is_whitespace).ok_or_else(bad)?;
            let value = value.trim();
            match key {
                "archive" => archive = Some(hex32(value).ok_or_else(bad)?),
                "authority" => authorities.push(hex32(value).ok_or_else(bad)?),
                "journal" => journal_id = value.parse().map_err(|_| bad())?,
                "time-journal" => {
                    let _: u64 = value.parse().map_err(|_| bad())?;
                }
                "local" => {
                    let _ = externality
                        .local_locations
                        .insert(hex32(value).ok_or_else(bad)?);
                }
                "anchors" => {
                    let _ = externality
                        .anchored_by_this
                        .insert(hex32(value).ok_or_else(bad)?);
                }
                _ => return Err(bad()),
            }
        }
        let archive_id = archive.ok_or_else(|| "the trust file names no archive".to_owned())?;
        if authorities.is_empty() {
            return Err("the trust file names no authority".to_owned());
        }
        externality.local_archive = archive_id;
        Ok(Self {
            root: TrustRoot {
                archive_id,
                authorities,
            },
            externality,
            journal_id,
        })
    }
}

/// `--journal-anchors HEX=DIR`: the store's location and directory.
#[must_use]
pub fn parse_anchors(value: &str) -> Option<(Digest, PathBuf)> {
    let (location, dir) = value.split_once('=')?;
    if dir.is_empty() {
        return None;
    }
    Some((hex32(location)?, PathBuf::from(dir)))
}

/// The anchors of the stores `anchors` names, the stores themselves as
/// their evidence, and the count of entries that are not anchors: a store
/// that cannot be read counts as one, never as an empty store.
pub(super) fn anchor_stores(
    anchors: &[(Digest, PathBuf)],
) -> (
    Vec<karyos_archive::integrity::anchor::Anchor>,
    Vec<karyos_archive::integrity::anchor::StoredAnchors>,
    u64,
) {
    use karyos_archive::integrity::anchor::{ANCHOR_FILE, ANCHOR_LENGTH, StoredAnchors};
    let mut disk = ReadOnly(StdDisk);
    let (mut found, mut stores, mut faults) = (Vec::new(), Vec::new(), 0u64);
    for (location, dir) in anchors {
        let present = dir.join(ANCHOR_FILE).is_file();
        match read_entries::<_, ANCHOR_LENGTH>(&mut disk, dir, ANCHOR_FILE) {
            Ok(entries) if present => {
                let stored = StoredAnchors::new(*location, entries);
                found.extend(stored.anchors());
                faults = faults.saturating_add(stored.malformed());
                stores.push(stored);
            }
            _ => faults = faults.saturating_add(1),
        }
    }
    (found, stores, faults)
}

/// 64 hex digits, as 32 bytes.
fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The journal's retention settings (ADR-0113, point 4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalRetention {
    /// `--journal-retention`; `None`: no policy, no purge.
    pub policy: Option<JournalPolicy>,
    /// `--journal-copy <location>=<dir>`, one per location.
    pub copies: Vec<(String, PathBuf)>,
    /// `--journal-trust <file>`, parsed.
    pub trust: Option<JournalTrust>,
    /// `--journal-anchors HEX=DIR`: each operator export anchor store's
    /// location and directory, as `karyos-catalog verify --anchors`.
    pub anchors: Vec<(Digest, PathBuf)>,
}

impl JournalRetention {
    /// With `policy`.
    #[must_use]
    pub const fn with_policy(mut self, policy: Option<JournalPolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// With the copy `location` in `dir`.
    #[must_use]
    pub fn with_copy(mut self, location: String, dir: PathBuf) -> Self {
        self.copies.push((location, dir));
        self
    }

    /// With the anchor store at `location` in `dir`.
    #[must_use]
    pub fn with_anchors(mut self, location: Digest, dir: PathBuf) -> Self {
        self.anchors.push((location, dir));
        self
    }

    /// With `trust`.
    #[must_use]
    pub fn with_trust(mut self, trust: Option<JournalTrust>) -> Self {
        self.trust = trust;
        self
    }
}

/// A copy location's identity in the journal's copy catalog.
fn location(name: &str) -> Digest {
    digest(format!("karyos:journal-copy:{name}").as_bytes())
}

/// The journal's own location: the copy a purge removes.
fn local_location() -> Digest {
    digest(b"karyos:journal-local")
}

/// The disk of the engine's ledgers: the operating system's, and in tests
/// one that can be made to fail.
#[cfg(not(test))]
pub(super) type EngineDisk = StdDisk;
/// The disk of the engine's ledgers: the operating system's, and in tests
/// one that can be made to fail.
#[cfg(test)]
pub(super) type EngineDisk = fault::FaultDisk;

#[cfg(not(test))]
const fn engine_disk() -> EngineDisk {
    StdDisk
}

#[cfg(test)]
const fn engine_disk() -> EngineDisk {
    fault::FaultDisk
}

/// The engine: the library's, with its operations ledger as its journal.
type Engine = Retention<Ledger<EngineDisk, OPERATION_LENGTH>, EngineDisk>;

/// The journal's retention state.
#[derive(Debug)]
pub(super) struct State {
    engine: Engine,
    /// The policy in force: the configured one, as recorded.
    policy: Option<RetentionPolicy>,
    /// A hold in force in memory only: neither its marker nor its ledger
    /// record was written (`hold not durable`).
    undurable: bool,
    /// Each closed segment's recorded close time, by base (ADR-0115): the
    /// latest when one was recorded twice.
    closes: std::collections::BTreeMap<u64, u64>,
    /// The base of the next segment whose close is to be recorded.
    next_close: u64,
    /// Each outstanding intent's original start, by id, from the ledger.
    froms: std::collections::BTreeMap<u64, u64>,
    /// Tests: closes are not recorded, as when their entry is lost.
    #[cfg(test)]
    pub(super) skip_closes: bool,
}

/// A purged prefix of the journal, with its purge evidence (ADR-0113,
/// point 8).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Purged {
    /// The purged range's start.
    pub start: u64,
    /// Its end, exclusive.
    pub end: u64,
    /// The purge record's counter in the integrity journal.
    pub counter: u64,
    /// The digest of the purged range's seals, which the record chains.
    pub seals: Digest,
    /// The purge record's own digest.
    pub record: Digest,
}

/// The purged prefixes `records` chain for `recording`.
pub(super) fn purged_of(
    records: &[karyos_archive::integrity::SealRecord],
    recording: u64,
) -> Vec<Purged> {
    records
        .iter()
        .filter(|record| record.kind == SealKind::Purge && record.subject == recording)
        .map(|record| Purged {
            start: record.start,
            end: record.end,
            counter: record.counter,
            seals: record.content,
            record: record.digest(),
        })
        .collect()
}

/// The registry entries and signed heads of `dir`, read when `trust` is
/// given; none otherwise, or when they cannot be read.
pub(super) fn trust_files(
    dir: &Path,
    trust: Option<&JournalTrust>,
) -> (
    Vec<[u8; REGISTRY_ENTRY_LENGTH]>,
    Vec<[u8; SIGNED_HEAD_LENGTH]>,
) {
    if trust.is_none() {
        return (Vec::new(), Vec::new());
    }
    let mut disk = ReadOnly(StdDisk);
    (
        read_entries(&mut disk, dir, KEYS_FILE).unwrap_or_default(),
        read_entries(&mut disk, dir, HEADS_FILE).unwrap_or_default(),
    )
}

/// A refusal's reply.
fn refused(name: &str) -> RetentionReply {
    RetentionReply::Refused {
        code: REFUSED,
        reason: name.to_owned(),
    }
}

/// The reply of a purge's failure.
fn failed(error: &PurgeError) -> RetentionReply {
    match error {
        PurgeError::Refused { refusal, .. } => refused(refusal.name()),
        other => RetentionReply::Refused {
            code: ERROR,
            reason: other.to_string(),
        },
    }
}

/// Refuses `request` for the agent's reason `name`, journalled in the
/// engine as the library's `refusal`: a refusal the library ranks first
/// (a hold, unknown holds, no authorisation) answers instead.
fn refuse(
    engine: &mut Engine,
    request: &PurgeRequest,
    refusal: PurgeRefusal,
    name: &str,
) -> RetentionReply {
    match engine.refuse_after_holds(request, refusal) {
        PurgeError::Refused { refusal: first, .. } if first == refusal => refused(name),
        other => failed(&other),
    }
}

/// The configured copies that can count toward `min_copies` for the
/// journal in `live`, by canonical path (karyos#702 review): never the live
/// journal's directory itself, one location per directory (the first
/// named), and none that cannot be resolved. `None` when `live` cannot.
fn distinct_copies<'a>(
    live: &Path,
    copies: &'a [(String, PathBuf)],
) -> Option<Vec<(&'a str, PathBuf)>> {
    let live = std::fs::canonicalize(live).ok()?;
    let mut seen = BTreeSet::new();
    Some(
        copies
            .iter()
            .filter_map(|(name, dir)| {
                let canonical = std::fs::canonicalize(dir).ok()?;
                (canonical != live && seen.insert(canonical.clone()))
                    .then_some((name.as_str(), canonical))
            })
            .collect(),
    )
}

/// Whether the copy of the journal in `dir` verifies over `[start,
/// before)` of `recording`: its chain intact and holding the same seals
/// there as `ours`, its bytes matching them, and nothing but missing
/// trust or anchors against it.
fn copy_verifies(
    dir: &Path,
    recording: u64,
    (start, before): (u64, u64),
    ours: Digest,
    trust: Option<&JournalTrust>,
) -> bool {
    let mut disk = ReadOnly(StdDisk);
    let Ok((records, fault)) = read_records(&mut disk, dir) else {
        return false;
    };
    if fault.is_some()
        || start >= before
        || seals_digest(&records, recording, start, before) != ours
    {
        return false;
    }
    let Ok(Some(geometry)) = recorded_geometry(&mut disk, dir, recording) else {
        return false;
    };
    let Ok(mut store) = SegmentStore::open_verified(
        ReadOnly(StdDisk),
        dir,
        recording,
        geometry,
        SyncPolicy::None,
    ) else {
        return false;
    };
    let written = store.written();
    let (keys, heads) = trust_files(dir, trust);
    let externality = trust
        .map(|trust| trust.externality.clone())
        .unwrap_or_default();
    let evidence = Evidence {
        records: &records,
        journal_fault: None,
        journal_id: trust.map_or(0, |trust| trust.journal_id),
        trust: trust.map(|trust| &trust.root),
        registry: &keys,
        heads: &heads,
        anchors: &[],
        anchor_faults: 0,
        stores: &NoAnchors,
        externality: &externality,
        written: &[(recording, written)],
    };
    let verification = verify(&evidence, |id, from, to| {
        let Some(length) = to
            .checked_sub(from)
            .filter(|_| id == recording && to <= written)
            .and_then(|length| usize::try_from(length).ok())
        else {
            return RangeBytes::Missing;
        };
        let mut bytes = vec![0; length];
        match store.read(from, &mut bytes) {
            Ok(()) => RangeBytes::Bytes(bytes),
            Err(_) => RangeBytes::Missing,
        }
    });
    let mut covered = start;
    for range in verification
        .ranges
        .iter()
        .filter(|range| range.recording == recording && range.start < before && range.end > start)
    {
        let clean = matches!(range.outcome, Outcome::Verified | Outcome::BeyondAnchor)
            || (range.outcome == Outcome::Inconsistent
                && range.reasons.iter().all(|reason| {
                    matches!(
                        reason,
                        Reason::UntrustedEvidence | Reason::MissingEvidence | Reason::NoAnchor
                    )
                }));
        if range.start != covered || range.end > before || !clean {
            return false;
        }
        covered = range.end;
    }
    covered == before
}

/// The aligned length of `record`'s frame.
fn frame_length(record: &JournalRecord) -> u64 {
    u64::try_from(record.encode().len())
        .ok()
        .and_then(|length| length.checked_add(u64::from(karyos_sys::frame::HEADER_LENGTH)))
        .and_then(|length| {
            length.checked_next_multiple_of(u64::from(karyos_sys::frame::FRAME_ALIGNMENT))
        })
        .unwrap_or(u64::MAX)
}

/// Pads `recorder`'s recording to `target`, a term boundary past its
/// written end, the padding written at host time `now`: the next record
/// then starts there.
fn pad_to(
    recorder: &mut super::JournalRecorder,
    target: u64,
    now: u64,
) -> Result<(), super::JournalError> {
    while recorder.source_mut().tail() < target {
        let _ = recorder.source_mut().pad_term()?;
    }
    // One term at most per duty: as many duties as terms, and one more.
    let term = u64::from(recorder.store().geometry().term_length());
    let duties = target
        .saturating_sub(recorder.store().written())
        .div_ceil(term)
        .saturating_add(1);
    for _ in 0..duties {
        if recorder.store().written() >= target {
            break;
        }
        let _ = recorder.duty(now)?;
    }
    if recorder.store().written() < target {
        return Err(super::JournalError::NotDurable);
    }
    Ok(())
}

/// The wall clock, in nanoseconds since the Unix epoch.
fn wall_ns() -> Option<u64> {
    #[cfg(test)]
    if fault::clock_fails() {
        return None;
    }
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let now = u64::try_from(since.as_nanos()).ok()?;
    #[cfg(test)]
    let now = now.checked_add_signed(fault::clock_offset())?;
    Some(now)
}

impl Journal {
    /// Opens the retention engine over the journal's directory, with the
    /// segments' recorded close times, and records the configured policy
    /// (ADR-0113, points 1 and 4; ADR-0115): before this start's first
    /// append, so that append never lands in a segment already closed and
    /// a rollover it makes records its close. A ledger that cannot be
    /// opened leaves the hold state unreadable: every purge is then
    /// refused `holds_unknown`. [`Journal::recover_purges`] follows, once
    /// the start is journalled.
    pub(super) fn open_retention(&mut self) {
        let disk = engine_disk();
        let engine = (|| {
            let operations =
                Ledger::<EngineDisk, OPERATION_LENGTH>::open(disk, &self.dir, OPERATIONS_FILE)
                    .ok()?;
            let pending =
                Ledger::<EngineDisk, MARKER_LENGTH>::open(disk, &self.dir, PENDING_HOLDS_FILE)
                    .ok()?;
            let records = operations.entries().to_vec();
            let mut closes = std::collections::BTreeMap::new();
            let mut froms = std::collections::BTreeMap::new();
            for bytes in &records {
                match Operation::decode(bytes) {
                    Some(Operation::SegmentClosed {
                        recording,
                        base,
                        closed_ns,
                        ..
                    }) if recording == self.recording => {
                        let latest: &mut u64 = closes.entry(base).or_insert(closed_ns);
                        *latest = (*latest).max(closed_ns);
                    }
                    // Only this journal's intents: another recording's
                    // with the same id never narrows `from`.
                    Some(Operation::PurgeIntent {
                        id,
                        recording,
                        from,
                        ..
                    }) if recording == self.recording => {
                        let _ = froms.entry(id).or_insert(from);
                    }
                    _ => {}
                }
            }
            Some((
                Retention::recover(operations, Some(&records), pending),
                closes,
                froms,
            ))
        })();
        let policy = self.record_policy();
        // Segments closed before this start whose close was not recorded
        // keep no time: only closes from the current segment on are, and a
        // segment already closed is never closed again.
        let current = self.recorder.as_ref().map_or(0, |recorder| {
            let store = recorder.store();
            store.geometry().base_of(store.written().saturating_sub(1))
        });
        self.retention = engine.map(|(engine, closes, froms)| {
            let length = self
                .recorder
                .as_ref()
                .map_or(0, |recorder| recorder.store().geometry().segment_length());
            let next_close = closes.keys().next_back().map_or(current, |last: &u64| {
                current.max(last.saturating_add(length))
            });
            State {
                engine,
                policy,
                undurable: false,
                closes,
                next_close,
                froms,
                #[cfg(test)]
                skip_closes: false,
            }
        });
    }

    /// Records the configured policy as a policy version when it differs
    /// from the one in force; the one in force afterwards, or `None`
    /// without the option or when it cannot be recorded.
    fn record_policy(&mut self) -> Option<RetentionPolicy> {
        let configured = self.settings.policy?;
        let integrity = self.integrity.as_mut()?;
        let mut book = PolicyBook::open(StdDisk, &self.dir, integrity).ok()?;
        book.record_configured(configured.policy(), integrity).ok()
    }

    /// The journal's hold, as the view reports it: `none`, `pending`,
    /// `held`, `unknown`, or `not_durable` for a hold in memory only.
    #[must_use]
    pub fn hold(&self) -> &'static str {
        let Some(state) = self.retention.as_ref() else {
            return "unknown";
        };
        if state.undurable {
            return "not_durable";
        }
        match state.engine.hold_state(self.recording) {
            HoldState::None => "none",
            HoldState::Held => "held",
            HoldState::Pending => "pending",
            _ => "unknown",
        }
    }

    /// The policy in force for the journal.
    #[must_use]
    pub fn policy(&self) -> Option<RetentionPolicy> {
        self.retention.as_ref().and_then(|state| state.policy)
    }

    /// Whether a purge intent is outstanding (ADR-0113, point 8): every
    /// further purge is refused until it is reconciled.
    #[must_use]
    pub fn purge_pending(&self) -> bool {
        self.retention
            .as_ref()
            .is_some_and(|state| !state.engine.outstanding().is_empty())
    }

    /// Applies a legal hold on the journal: in force at once; reported
    /// `hold not durable` when neither its marker nor its ledger record
    /// could be written.
    pub(crate) fn hold_journal(&mut self) -> RetentionReply {
        let recording = self.recording;
        let Some(state) = self.retention.as_mut() else {
            return refused("holds_unknown");
        };
        match state.engine.apply_hold(recording) {
            HoldReport::Applied { .. } => {
                state.undurable = false;
                RetentionReply::Done { evidenced: true }
            }
            HoldReport::PendingNoEvidence => {
                state.undurable = false;
                RetentionReply::Done { evidenced: false }
            }
            HoldReport::InMemoryOnly => {
                state.undurable = true;
                RetentionReply::HoldNotDurable
            }
        }
    }

    /// Makes a hold held in memory only durable, when its marker or its
    /// record can now be written: run on every poll.
    pub fn retry_hold(&mut self) {
        let recording = self.recording;
        if let Some(state) = self.retention.as_mut().filter(|state| state.undurable) {
            state.undurable = state.engine.apply_hold(recording) == HoldReport::InMemoryOnly;
        }
    }

    /// Releases the journal's hold, with evidence it was applied.
    pub(crate) fn release_journal(&mut self) -> RetentionReply {
        let recording = self.recording;
        let Some(state) = self.retention.as_mut() else {
            return refused("holds_unknown");
        };
        match state.engine.release_hold(recording) {
            Ok(()) => RetentionReply::Done { evidenced: true },
            Err(error) => refused(error.name()),
        }
    }

    /// Records the copies that verify now over `[start, before)` as
    /// `verified` for it, and withdraws every other `verified` record of
    /// the journal: the catalog the decision reads, `None` when it cannot
    /// be opened or written, or the journal's own directory cannot be
    /// resolved. A copy is a directory other than the live journal's, by
    /// canonical path, and locations that resolve to the same directory
    /// count once ([`distinct_copies`]).
    fn verified_copies(&mut self, start: u64, before: u64) -> Option<CopyCatalog<StdDisk>> {
        let recording = self.recording;
        let copies = distinct_copies(&self.dir, &self.settings.copies)?;
        let integrity = self.integrity.as_mut()?;
        let mut catalog = CopyCatalog::open(StdDisk, &self.dir, integrity).ok()?;
        let records = integrity.records().ok()?;
        let ours = seals_digest(&records, recording, start, before);
        let trust = self.settings.trust.as_ref();
        let verified: BTreeSet<Digest> = copies
            .iter()
            .filter(|(_, dir)| copy_verifies(dir, recording, (start, before), ours, trust))
            .map(|(name, _)| location(name))
            .collect();
        let current = catalog.current().ok()?;
        let this = |copy: &CopyRecord| {
            copy.recording == recording && copy.start == start && copy.end == before
        };
        for copy in current
            .iter()
            .filter(|copy| copy.recording == recording && copy.state == CopyState::Verified)
        {
            if !(this(copy) && verified.contains(&copy.location)) {
                let withdrawn = CopyRecord {
                    state: CopyState::Unverified,
                    ..*copy
                };
                let _ = catalog.record(withdrawn, integrity).ok()?;
            }
        }
        for location in &verified {
            let known = current.iter().any(|copy| {
                this(copy) && copy.location == *location && copy.state == CopyState::Verified
            });
            if !known {
                let copy = CopyRecord {
                    sequence: 0,
                    recording,
                    start,
                    end: before,
                    location: *location,
                    digest: ours,
                    retain_until_ns: 0,
                    state: CopyState::Verified,
                    enforcement: Enforcement::Unsupported,
                    profile: ArrivalProfile::Local,
                };
                let _ = catalog.record(copy, integrity).ok()?;
            }
        }
        Some(catalog)
    }

    /// Whether `before` is a segment boundary of the journal and outside
    /// its current segment: `Err` with the refusal's name otherwise.
    fn boundary(&self, before: u64) -> Result<(), &'static str> {
        let Some(recorder) = self.recorder.as_ref() else {
            return Err("journal_unavailable");
        };
        let store = recorder.store();
        let geometry = store.geometry();
        if before == 0 || !before.is_multiple_of(geometry.segment_length()) {
            return Err(INSIDE_SEGMENT);
        }
        // The segment holding the last byte written is the current one.
        let current = geometry.base_of(store.written().saturating_sub(1));
        if before > current || before >= store.written() {
            return Err(CURRENT_SEGMENT);
        }
        Ok(())
    }

    /// When the prefix before `before` closed: the largest recorded close
    /// time of its segments, every one of which needs its own (ADR-0115,
    /// point 2); `None` when one has none.
    fn closed_ns(&self, before: u64) -> Option<u64> {
        let start = self.recorder.as_ref()?.store().start();
        self.closed_over(start, before)
    }

    /// The largest recorded close time of the segments of `[from,
    /// before)` (ADR-0115, point 2): every one needs its own; `None` when
    /// one has none.
    fn closed_over(&self, from: u64, before: u64) -> Option<u64> {
        let geometry = self.recorder.as_ref()?.store().geometry();
        let closes = &self.retention.as_ref()?.closes;
        let length = geometry.segment_length();
        let mut base = geometry.base_of(from);
        let mut latest = None;
        while base < before {
            let closed = *closes.get(&base)?;
            latest = Some(latest.map_or(closed, |latest: u64| latest.max(closed)));
            base = base.checked_add(length)?;
        }
        latest
    }

    /// Closes the segments the writer is about to leave, before
    /// `record` is written at host time `now` (ADR-0115, point 1): the
    /// predecessor's last record and seal durable, the wall clock read,
    /// the close entry synced, and only then may the record be written. A
    /// segment whose close is recorded stays closed: a record that would
    /// land in one, as at a start after a crash between the close entry
    /// and the successor's first record, goes to the next segment, after
    /// padding to it.
    ///
    /// # Errors
    ///
    /// [`super::JournalError::NotClosed`] when the seal, the wall clock or
    /// the close entry fails: nothing is written, the segment is not
    /// left, and the next append tries the close again. The recorder's
    /// errors: the journal then fails as for an append.
    pub(super) fn close_before(
        &mut self,
        record: &JournalRecord,
        now: u64,
    ) -> Result<(), super::JournalError> {
        let recording = self.recording;
        if self.reopen_retention && !self.reopen_retention_ledger() {
            return Err(super::JournalError::NotClosed);
        }
        let (Some(recorder), Some(state)) = (self.recorder.as_mut(), self.retention.as_ref())
        else {
            return Ok(());
        };
        let store = recorder.store();
        let geometry = store.geometry();
        let position = store.written();
        if position == 0 {
            return Ok(());
        }
        // Where the record's frame starts: a frame never crosses a term,
        // so one that does not fit begins the next.
        let term = u64::from(geometry.term_length());
        let frame = frame_length(record);
        let start = if position % term + frame > term {
            position.next_multiple_of(term)
        } else {
            position
        };
        if start < state.next_close {
            return pad_to(recorder, state.next_close, now);
        }
        let successor = geometry.base_of(start);
        if state.next_close >= successor {
            return Ok(());
        }
        let not_closed = Err(super::JournalError::NotClosed);
        let durable = recorder.sync()?;
        // A seal that failed is tried again over a reopened integrity
        // journal: the close needs the predecessor sealed.
        if self.integrity.is_none() {
            self.integrity = IntegrityJournal::open(StdDisk, &self.dir)
                .ok()
                .map(|opened| opened.journal);
        }
        self.seal();
        let floor = self
            .recorder
            .as_ref()
            .map_or(0, |recorder| recorder.store().start());
        let sealed = self
            .integrity
            .as_ref()
            .is_some_and(|integrity| integrity.sealed_end(recording).unwrap_or(floor) >= durable);
        #[cfg(test)]
        let sealed = sealed && !fault::seal_fails();
        if !sealed {
            return not_closed;
        }
        #[cfg(test)]
        if fault::crash_at() == fault::Crash::BeforeClose {
            return Err(super::JournalError::Unavailable);
        }
        let Some(closed_ns) = wall_ns() else {
            return not_closed;
        };
        let Some(state) = self.retention.as_mut() else {
            return Ok(());
        };
        let length = geometry.segment_length();
        while state.next_close < successor {
            let base = state.next_close;
            let end = base.saturating_add(length);
            #[cfg(test)]
            let skip = state.skip_closes;
            #[cfg(not(test))]
            let skip = false;
            // Tests: an entry lost, as after its write; never retried.
            if !skip {
                if state
                    .engine
                    .record_segment_close(recording, base, end, closed_ns)
                    .is_err()
                {
                    // Its ledger is poisoned: reopened at the next try.
                    self.reopen_retention = true;
                    return not_closed;
                }
                let _ = state.closes.insert(base, closed_ns);
            }
            state.next_close = end;
        }
        #[cfg(test)]
        if fault::crash_at() == fault::Crash::AfterClose {
            return Err(super::JournalError::Unavailable);
        }
        Ok(())
    }

    /// Reopens the retention engine after a close entry failed, keeping a
    /// hold held in memory only: whether it could.
    fn reopen_retention_ledger(&mut self) -> bool {
        let undurable = self.retention.take().is_some_and(|state| state.undurable);
        self.open_retention();
        match self.retention.as_mut() {
            Some(state) => {
                state.undurable = undurable;
                self.reopen_retention = false;
                true
            }
            None => false,
        }
    }

    /// After a write: a segment the writer left without its close being
    /// recorded first keeps no time, and is never closed later.
    pub(super) fn after_write(&mut self) {
        let (Some(recorder), Some(state)) = (self.recorder.as_ref(), self.retention.as_mut())
        else {
            return;
        };
        let store = recorder.store();
        let current = store.geometry().base_of(store.written().saturating_sub(1));
        state.next_close = state.next_close.max(current);
    }

    /// Purges the journal below `before` as purge `id` for `operator`
    /// (ADR-0113, point 7): refused, journalled with its reason, unless
    /// it is authorised, no hold applies, the prefix expired, the copies
    /// satisfy `min_copies`, and `before` is a segment boundary outside
    /// the current segment; otherwise the library's crash-safe purge
    /// through the recorder's own store. `now` is host monotonic time,
    /// for the verification that follows. Tests: no operation id is
    /// retained.
    #[cfg(test)]
    pub(crate) fn purge_journal(
        &mut self,
        id: u64,
        before: u64,
        authorisation: Authorisation,
        now: u64,
    ) -> RetentionReply {
        self.purge_journal_retaining(id, before, authorisation, now, &|_| false)
    }

    /// [`Journal::purge_journal`], refused `operation_state_retained` when
    /// the prefix holds a record an operation id is rebuilt from at start
    /// (its `ApprovalRequested`, `Submitted` or `ClusterRequest`) and
    /// `retained` says the id is still retained: pending, its outcome
    /// within its retention, or a tombstone. Purged, a restart would forget
    /// it, and a caller could reuse the id (karyos#739 review).
    pub(crate) fn purge_journal_retaining(
        &mut self,
        id: u64,
        before: u64,
        authorisation: Authorisation,
        now: u64,
        retained: &dyn Fn(u64) -> bool,
    ) -> RetentionReply {
        let request = PurgeRequest {
            id,
            recording: self.recording,
            before,
            authorisation,
            closed_ns: 0,
            source: PurgeSource::Operator,
        };
        let boundary = self.boundary(before);
        let closed = self.closed_ns(before);
        let holds_state = self
            .id_records
            .iter()
            .any(|&(position, operation)| position < before && retained(operation));
        let Some(state) = self.retention.as_mut() else {
            return refused("holds_unknown");
        };
        if state.undurable {
            return refuse(
                &mut state.engine,
                &request,
                PurgeRefusal::LegalHold,
                HOLD_NOT_DURABLE,
            );
        }
        if let Some(pending) = state.engine.outstanding().first() {
            let duplicate = PurgeRefusal::DuplicateId { id: pending.id };
            return refuse(&mut state.engine, &request, duplicate, PURGE_PENDING);
        }
        if let Some(refused) = state.engine.refuse_early(&request) {
            return failed(&refused);
        }
        if let Err(name) = boundary {
            let refusal = PurgeRefusal::NotAWriteStart { before };
            return refuse(&mut state.engine, &request, refusal, name);
        }
        // Journalled in the engine as not purgeable yet.
        if holds_state {
            let refusal = PurgeRefusal::NotExpired {
                expires_ns: u64::MAX,
            };
            return refuse(
                &mut state.engine,
                &request,
                refusal,
                OPERATION_STATE_RETAINED,
            );
        }
        let Some(policy) = state.policy else {
            let refusal = PurgeRefusal::NoPolicy;
            return refuse(&mut state.engine, &request, refusal, refusal.name());
        };
        // No recorded close, no expiry (ADR-0115, point 3).
        let Some(closed_ns) = closed else {
            let refusal = PurgeRefusal::NotExpired {
                expires_ns: u64::MAX,
            };
            return refuse(&mut state.engine, &request, refusal, refusal.name());
        };
        let request = PurgeRequest {
            closed_ns,
            ..request
        };
        let start = self
            .recorder
            .as_ref()
            .map_or(0, |recorder| recorder.store().start());
        let catalog = self.verified_copies(start, before);
        let Some(state) = self.retention.as_mut() else {
            return refused("holds_unknown");
        };
        let (Some(recorder), Some(integrity)) = (self.recorder.as_mut(), self.integrity.as_mut())
        else {
            let refusal = PurgeRefusal::JournalUnavailable;
            return refuse(&mut state.engine, &request, refusal, refusal.name());
        };
        let Some(catalog) = catalog else {
            let refusal = PurgeRefusal::BelowMinCopies {
                verified: 0,
                required: policy.min_copies.get(),
            };
            return refuse(&mut state.engine, &request, refusal, refusal.name());
        };
        let Some(now_ns) = wall_ns() else {
            let refusal = PurgeRefusal::NotExpired {
                expires_ns: u64::MAX,
            };
            return refuse(&mut state.engine, &request, refusal, refusal.name());
        };
        let context = PurgeContext {
            policy: Some(&policy),
            copies: &catalog,
            local: local_location(),
            now_ns,
        };
        let purged = state
            .engine
            .purge(&request, &context, recorder.store_mut(), integrity);
        let reply = match purged {
            Ok(_) => RetentionReply::Done { evidenced: true },
            Err(error) => failed(&error),
        };
        self.verify(now);
        reply
    }

    /// Completes or cancels each purge intent a crash left outstanding
    /// (ADR-0113, point 8), at open: each one's audit record made durable
    /// first, and only on segment boundaries outside the current segment.
    /// An intent it cannot reconcile stays outstanding.
    pub(super) fn recover_purges(&mut self, now: u64) {
        let Some(state) = self.retention.as_ref() else {
            return;
        };
        let outstanding = state.engine.outstanding();
        if outstanding.is_empty() {
            return;
        }
        let policy = state.policy;
        // Durable audit first (item 51).
        for intent in &outstanding {
            let mut record = JournalRecord::new(Kind::PurgeRequest, now);
            record.guard = JOURNAL_SUBJECT;
            record.expected = intent.before;
            record.operation = intent.id;
            record.operator = intent.authorisation.operator;
            record.reason = b"recovery".to_vec();
            if self.append_durable(&record, now).is_err() {
                return;
            }
        }
        let Some(lowest) = self
            .recorder
            .as_ref()
            .map(|recorder| recorder.store().lowest_retained())
        else {
            return;
        };
        // Expiry again over each intent's whole original range, each
        // segment's close entry kept until it completes (ADR-0115, point
        // 4): a missing entry or a range no longer expired leaves every
        // intent outstanding.
        let Some(now_ns) = wall_ns() else {
            return;
        };
        let retain = policy.map_or(u64::MAX, |policy| policy.retain_for_ns);
        for intent in outstanding
            .iter()
            .filter(|intent| intent.recording == self.recording)
        {
            let from = self
                .retention
                .as_ref()
                .and_then(|state| state.froms.get(&intent.id).copied())
                .unwrap_or(lowest);
            let expired = self
                .closed_over(from.min(lowest), intent.before)
                .and_then(|closed| closed.checked_add(retain))
                .is_some_and(|expires| now_ns >= expires);
            if !expired {
                return;
            }
        }
        // Every intent is rechecked, the floor already at its `BEFORE` or
        // not (ADR-0113, point 8): its close time over its whole original
        // range, and the copies verified again over the widest range.
        let mut range: Option<(u64, u64)> = None;
        let mut raised = Vec::new();
        for intent in outstanding
            .iter()
            .filter(|intent| intent.recording == self.recording)
        {
            // An intent whose floor is already at its `BEFORE` skips only
            // the boundary check: that is safe because the expiry loop
            // above rechecked its whole original range, from its recorded
            // `from` (`froms`), and its holds, policy and copies are
            // rechecked below like any other's.
            if lowest < intent.before && self.boundary(intent.before).is_err() {
                return;
            }
            let from = self
                .retention
                .as_ref()
                .and_then(|state| state.froms.get(&intent.id).copied())
                .unwrap_or(lowest)
                .min(lowest);
            // Without a recorded close the recheck never finds it expired.
            let closed = self.closed_over(from, intent.before).unwrap_or(u64::MAX);
            raised.push((intent.id, closed));
            range = Some(range.map_or((from, intent.before), |(low, high)| {
                (low.min(from), high.max(intent.before))
            }));
        }
        let catalog = match range {
            Some((low, high)) if low < high => self.verified_copies(low, high),
            _ => self
                .integrity
                .as_mut()
                .and_then(|integrity| CopyCatalog::open(StdDisk, &self.dir, integrity).ok()),
        };
        let Some(catalog) = catalog else {
            return;
        };
        let (Some(state), Some(recorder), Some(integrity)) = (
            self.retention.as_mut(),
            self.recorder.as_mut(),
            self.integrity.as_mut(),
        ) else {
            return;
        };
        for (id, closed) in raised {
            state.engine.raise_close_time(id, closed);
        }
        let context = PurgeContext {
            policy: policy.as_ref(),
            copies: &catalog,
            local: local_location(),
            now_ns,
        };
        // The control path authorised each intent (ADR-0088, decision 4).
        let outcomes =
            state
                .engine
                .recover_purges(&context, |_| true, recorder.store_mut(), integrity);
        // Each outcome is journalled after its durable request.
        if let Ok(outcomes) = outcomes {
            let recording = self.recording;
            for (intent, outcome) in outstanding
                .iter()
                .filter(|intent| intent.recording == recording)
                .zip(outcomes)
            {
                let mut record = JournalRecord::new(Kind::PurgeOutcome, now);
                record.guard = JOURNAL_SUBJECT;
                record.expected = intent.before;
                record.operation = intent.id;
                record.operator = intent.authorisation.operator;
                if let Err(refusal) = outcome {
                    record.code = REFUSED;
                    record.word = u64::from(refusal.code());
                }
                let _ = self.append(&record, now);
            }
        }
    }
}

/// The engine's disk in tests: the operating system's, failing every
/// write and sync while [`fault::fail`] is set on this thread.
#[cfg(test)]
pub(super) mod fault {
    use std::cell::Cell;
    use std::io;
    use std::path::Path;

    use karyos_archive::disk::{Disk, StdDisk};

    thread_local! {
        static SEAL_FAILS: Cell<bool> = const { Cell::new(false) };
        static CLOCK_FAILS: Cell<bool> = const { Cell::new(false) };
        static FAIL: Cell<bool> = const { Cell::new(false) };
        static OFFSET: Cell<i64> = const { Cell::new(0) };
        static CRASH: Cell<Crash> = const { Cell::new(Crash::None) };
    }

    /// Where a rollover stops, as a crash would.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Crash {
        /// Nowhere.
        None,
        /// Before the close entry.
        BeforeClose,
        /// After the close entry, before the successor's first record.
        AfterClose,
    }

    /// Makes a rollover's seal on this thread count as failed, or not.
    pub(crate) fn fail_seal(failing: bool) {
        SEAL_FAILS.with(|cell| cell.set(failing));
    }

    pub(crate) fn seal_fails() -> bool {
        SEAL_FAILS.with(Cell::get)
    }

    /// Makes this thread's wall clock unreadable, or readable again.
    pub(crate) fn fail_clock(failing: bool) {
        CLOCK_FAILS.with(|cell| cell.set(failing));
    }

    pub(crate) fn clock_fails() -> bool {
        CLOCK_FAILS.with(Cell::get)
    }

    /// Moves this thread's wall clock by `offset` nanoseconds.
    pub(crate) fn step_clock(offset: i64) {
        OFFSET.with(|cell| cell.set(offset));
    }

    pub(crate) fn clock_offset() -> i64 {
        OFFSET.with(Cell::get)
    }

    /// Makes the next rollover on this thread stop at `crash`.
    pub(crate) fn crash(crash: Crash) {
        CRASH.with(|cell| cell.set(crash));
    }

    pub(crate) fn crash_at() -> Crash {
        CRASH.with(Cell::get)
    }

    /// Makes the engine's ledgers fail on this thread, or work again.
    pub(crate) fn fail(failing: bool) {
        FAIL.with(|fail| fail.set(failing));
    }

    fn check() -> io::Result<()> {
        if FAIL.with(Cell::get) {
            return Err(io::Error::other("a failing disk"));
        }
        Ok(())
    }

    /// See the module.
    #[derive(Debug, Default, Clone, Copy)]
    pub(crate) struct FaultDisk;

    impl Disk for FaultDisk {
        type File = std::fs::File;

        fn create(&mut self, path: &Path) -> io::Result<Self::File> {
            check()?;
            StdDisk.create(path)
        }

        fn open(&mut self, path: &Path) -> io::Result<Self::File> {
            StdDisk.open(path)
        }

        fn open_read(&mut self, path: &Path) -> io::Result<Self::File> {
            StdDisk.open_read(path)
        }

        fn write_at(&mut self, file: &Self::File, offset: u64, bytes: &[u8]) -> io::Result<()> {
            check()?;
            StdDisk.write_at(file, offset, bytes)
        }

        fn read_at(&mut self, file: &Self::File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            StdDisk.read_at(file, offset, buf)
        }

        fn len(&mut self, file: &Self::File) -> io::Result<u64> {
            StdDisk.len(file)
        }

        fn set_len(&mut self, file: &Self::File, len: u64) -> io::Result<()> {
            check()?;
            StdDisk.set_len(file, len)
        }

        fn sync(&mut self, file: &Self::File) -> io::Result<()> {
            check()?;
            StdDisk.sync(file)
        }

        fn sync_dir(&mut self, dir: &Path) -> io::Result<()> {
            StdDisk.sync_dir(dir)
        }

        fn list(&mut self, dir: &Path) -> io::Result<Vec<String>> {
            StdDisk.list(dir)
        }

        fn remove(&mut self, path: &Path) -> io::Result<()> {
            StdDisk.remove(path)
        }

        fn modified(&mut self, path: &Path) -> io::Result<u64> {
            StdDisk.modified(path)
        }

        fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
            StdDisk.rename(from, to)
        }

        fn lock(&mut self, file: &Self::File) -> io::Result<()> {
            StdDisk.lock(file)
        }
    }
}
