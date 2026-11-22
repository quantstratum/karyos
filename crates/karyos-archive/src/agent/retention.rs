// SPDX-License-Identifier: Apache-2.0

//! The agent's retention backend (ADR-0088; karyos#967): holds, releases
//! and purges through the Archive's [`Retention`] engine, and seal
//! verification through [`verify::verify`], on the agent's thread, where
//! the segment stores, the integrity journal and the signed heads live.
//!
//! - **State.** The operations journal ([`OPERATIONS_FILE`]) and the
//!   pending-holds ledger ([`PENDING_HOLDS_FILE`]) in the archive
//!   directory, opened and replayed at start ([`Retention::recover`]).
//! - **Purge.** No policy and no copy catalog are configured in the agent
//!   yet (karyos#1093): a purge is refused before anything is deleted,
//!   holds first (`legal_hold`), else `no_policy`, the refusal journalled.
//! - **Verify.** The evidence is the integrity journal's records, the
//!   signed heads and the key registry with the trust root head signing
//!   was given, and the recording's written end. No anchors are gathered:
//!   the agent keeps none. Without an integrity journal there is nothing
//!   to verify and the answer is an error.

use std::path::Path;

use crate::catalog::Recording;
use crate::control::{self, IntegrityOutcome, NO_INCONSISTENT};
use crate::disk::Disk;
use crate::integrity::anchor::{Anchor, AnchorEvidence, Externality};
use crate::integrity::journal::IntegrityError;
use crate::integrity::ledger::{Ledger, read_entries};
use crate::integrity::retention::{
    Authorisation, HoldReport, MARKER_LENGTH, OPERATION_LENGTH, OPERATIONS_FILE,
    PENDING_HOLDS_FILE, PurgeContext, PurgeError, PurgeRefusal, PurgeRequest, PurgeSource,
    Retention, RetentionPolicy,
};
use crate::integrity::trust::{KEYS_FILE, REGISTRY_ENTRY_LENGTH};
use crate::integrity::verify::{self, Evidence, Outcome, RangeBytes, Reason};
use crate::segment::{SegmentStore, SyncPolicy};
use crate::server::RetentionAnswer;

use super::{State, read_store};

/// The agent's retention engine: the operations journal as its journal.
pub(super) type Engine<D> = Retention<Ledger<D, OPERATION_LENGTH>, D>;

/// A hold, a release or a purge, as posted to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Request {
    Hold(u64),
    Release(u64),
    Purge {
        recording: u64,
        before: u64,
        request_id: u64,
        operator: u64,
    },
}

/// A verification's answer: each range's outcome, or why it could not run.
pub type Verified = Result<Vec<control::RangeOutcome>, RetentionAnswer>;

/// Opens the retention engine of the archive in `dir`.
pub(super) fn open<D: Disk + Clone>(disk: &D, dir: &Path) -> Result<Engine<D>, IntegrityError> {
    let operations = Ledger::<D, OPERATION_LENGTH>::open(disk.clone(), dir, OPERATIONS_FILE)?;
    let pending = Ledger::<D, MARKER_LENGTH>::open(disk.clone(), dir, PENDING_HOLDS_FILE)?;
    let records = operations.entries().to_vec();
    Ok(Retention::recover(operations, Some(&records), pending))
}

/// The store anchors would be confirmed by: the agent keeps none.
#[derive(Debug)]
struct NoAnchors;

impl AnchorEvidence for NoAnchors {
    fn confirms(&self, _anchor: &Anchor) -> bool {
        false
    }
}

/// A [`Reason`]'s bit in a `RangeOutcome` (ADR-0088): the verifier's order.
const fn reason_bit(reason: Reason) -> u32 {
    let bit = match reason {
        Reason::UntrustedEvidence => 0,
        Reason::UnknownKey => 1,
        Reason::UnknownAlgorithm => 2,
        Reason::MalformedEvidence => 3,
        Reason::MissingEvidence => 4,
        Reason::ConflictingAnchors => 5,
        Reason::Corruption => 6,
        Reason::ShortenedIndex => 7,
        Reason::UnauthenticatedPurge => 8,
        Reason::NoAnchor => 9,
    };
    1 << bit
}

/// An [`Outcome`]'s wire outcome.
const fn outcome(outcome: Outcome) -> IntegrityOutcome {
    match outcome {
        Outcome::Verified => IntegrityOutcome::Verified,
        Outcome::BeyondAnchor => IntegrityOutcome::BeyondAnchor,
        Outcome::Unsealed => IntegrityOutcome::Unsealed,
        Outcome::Purged => IntegrityOutcome::Purged,
        Outcome::Inconsistent => IntegrityOutcome::Inconsistent,
    }
}

/// The wire range of `report`, its correlation id left for the server.
fn range(report: &verify::RangeReport) -> control::RangeOutcome {
    let outcome = outcome(report.outcome);
    control::RangeOutcome {
        correlation_id: 0,
        recording_id: report.recording,
        start: report.start,
        end: report.end,
        first_inconsistent: match outcome {
            IntegrityOutcome::Inconsistent => report.first_inconsistent.unwrap_or(NO_INCONSISTENT),
            _ => NO_INCONSISTENT,
        },
        reasons: report
            .reasons
            .iter()
            .fold(0, |bits, reason| bits | reason_bit(*reason)),
        outcome,
    }
}

/// The answer of a hold.
const fn held(report: HoldReport) -> RetentionAnswer {
    match report {
        HoldReport::Applied { .. } => RetentionAnswer::Done,
        HoldReport::PendingNoEvidence => RetentionAnswer::HeldWithoutEvidence,
        HoldReport::InMemoryOnly => RetentionAnswer::HeldInMemoryOnly,
    }
}

/// The answer of a refused or failed purge.
fn purge_failed(error: &PurgeError) -> RetentionAnswer {
    match error {
        PurgeError::Refused { refusal, .. } => RetentionAnswer::Refused(refusal.name().to_owned()),
        other => RetentionAnswer::Error(other.to_string()),
    }
}

impl<D: Disk + Clone> State<D> {
    /// Serves a hold, a release or a purge.
    pub(super) fn retain(&mut self, request: Request) -> RetentionAnswer {
        let recording = match request {
            Request::Hold(recording) | Request::Release(recording) => recording,
            Request::Purge { recording, .. } => recording,
        };
        if self.catalog.get(recording).is_none() {
            return RetentionAnswer::UnknownRecording;
        }
        match request {
            Request::Hold(recording) => held(self.retention.apply_hold(recording)),
            Request::Release(recording) => match self.retention.release_hold(recording) {
                Ok(()) => RetentionAnswer::Done,
                Err(error) => RetentionAnswer::Refused(error.name().to_owned()),
            },
            Request::Purge {
                recording,
                before,
                request_id,
                operator,
            } => {
                // The control path authorises (ADR-0088, decision 4).
                let request = PurgeRequest {
                    id: request_id,
                    recording,
                    before,
                    authorisation: Authorisation {
                        operator,
                        authorised: true,
                    },
                    closed_ns: 0,
                    source: PurgeSource::Operator,
                };
                match self.config.retention_policy {
                    Some(policy) => self.purge(request, &policy),
                    None => purge_failed(&self.retention.refuse_unconfigured(&request)),
                }
            }
        }
    }

    /// Runs `request` through [`Retention::purge`] under `policy`
    /// (karyos#1093): against the stopped recording's store reopened read
    /// only, the copy catalog counting the verified copies elsewhere. The
    /// range's
    /// close time is the stop's recorded `closed_utc_ns` (ADR-0093), raised
    /// by the newest modification time of the segments holding bytes below
    /// the cutoff; without a recorded one the purge is refused
    /// `no_close_time`, so a purge is never early.
    fn purge(&mut self, mut request: PurgeRequest, policy: &RetentionPolicy) -> RetentionAnswer {
        let error = |why: String| RetentionAnswer::Error(why);
        // The verification worker reads the recording's files: they are
        // never deleted under it (karyos#1124 review).
        if self.verifying.load(std::sync::atomic::Ordering::Acquire) == request.recording {
            return RetentionAnswer::Refused(VERIFICATION_RUNNING.to_owned());
        }
        if self.replays.reads(request.recording) {
            return error("a replay reads the recording; purge it once the replay ends".to_owned());
        }
        let Some(recording) = self.catalog.get(request.recording).cloned() else {
            return RetentionAnswer::UnknownRecording;
        };
        // ADR-0093: the close time is the one the stop recorded, chained in
        // the integrity journal; a recording that still records, or one
        // stopped before close times were recorded, has none.
        let Some(recorded) = recording.stop.and_then(|stop| stop.closed_utc_ns) else {
            return purge_failed(
                &self
                    .retention
                    .refuse_after_holds(&request, PurgeRefusal::NoCloseTime),
            );
        };
        // Holds first: a held recording is answered `legal_hold` even when
        // its files cannot be opened (karyos#1121 review).
        if let Some(refused) = self.retention.refuse_early(&request) {
            return purge_failed(&refused);
        }
        // Read only (karyos#1121 review): validation changes nothing, so a
        // refused purge never cuts a damaged tail, and segments a local
        // copy made immutable open. Only an approved purge releases and
        // deletes, and only the segments below its cutoff.
        let mut store = match open_stopped(&self.disk, &self.dir, &recording) {
            Ok(Some(store)) => store,
            Ok(None) => return error("the recording wrote no segment".to_owned()),
            Err(answer) => return answer,
        };
        // The cutoff is bounded before any file is listed (karyos#1121
        // review): one past the written end names segments that never
        // existed, as many as the request asks.
        if request.before > store.written() {
            return purge_failed(&self.retention.refuse_after_holds(
                &request,
                PurgeRefusal::NotAWriteStart {
                    before: request.before,
                },
            ));
        }
        request.closed_ns = match close_time(&self.disk, &store, request.before, recorded) {
            Ok(closed_ns) => closed_ns,
            Err(why) => return error(why.to_string()),
        };
        let Some(integrity) = self.integrity.as_mut() else {
            return error("no integrity journal: the Archive seals nothing".to_owned());
        };
        let Some((copies, local)) = integrity.copies.as_ref() else {
            return error("the copy catalog is unavailable".to_owned());
        };
        let Some(now_ns) = utc_now_ns() else {
            return error("the UTC time is unavailable".to_owned());
        };
        let context = PurgeContext {
            policy: Some(policy),
            copies,
            local: *local,
            now_ns,
        };
        match self
            .retention
            .purge(&request, &context, &mut store, &mut integrity.journal)
        {
            Ok(_) => RetentionAnswer::Done,
            Err(failed) => purge_failed(&failed),
        }
    }

    /// Reconciles the purge intents a crash left outstanding, at start and
    /// before any control request is served (karyos#1121 review), through
    /// [`Retention::recover_purges`] against each recording's stopped
    /// store, opened read only: an intent whose deletion already happened
    /// gets its integrity purge record and completes; an unfinished one is
    /// rechecked against the holds, the policy and the copies as they are
    /// now, then completed or cancelled. An intent that cannot be
    /// reconciled (no integrity journal or copy catalog, a store or
    /// journal error) stays outstanding until a later start.
    pub(super) fn reconcile_purges(&mut self) {
        let recordings: std::collections::BTreeSet<u64> = self
            .retention
            .outstanding()
            .iter()
            .map(|request| request.recording)
            .collect();
        if recordings.is_empty() {
            return;
        }
        let Some(now_ns) = utc_now_ns() else {
            return;
        };
        for id in recordings {
            let Some(recording) = self.catalog.get(id).cloned() else {
                continue;
            };
            let Ok(Some(mut store)) = open_stopped(&self.disk, &self.dir, &recording) else {
                continue;
            };
            // An unfinished intent is rechecked against the segments'
            // modification times as they are now, never only the close
            // time it saved (ADR-0093, decision 3).
            let recorded = recording
                .stop
                .and_then(|stop| stop.closed_utc_ns)
                .unwrap_or(0);
            for intent in self.retention.outstanding() {
                if intent.recording != id || store.start() >= intent.before {
                    continue;
                }
                if intent.before > store.written() {
                    continue;
                }
                let Ok(closed_ns) = close_time(&self.disk, &store, intent.before, recorded) else {
                    continue;
                };
                self.retention.raise_close_time(intent.id, closed_ns);
            }
            let Some(integrity) = self.integrity.as_mut() else {
                return;
            };
            let Some((copies, local)) = integrity.copies.as_ref() else {
                return;
            };
            let context = PurgeContext {
                policy: self.config.retention_policy.as_ref(),
                copies,
                local: *local,
                now_ns,
            };
            // The control path authorised each intent (ADR-0088, decision
            // 4). A failure leaves the intent outstanding.
            let _ = self.retention.recover_purges(
                &context,
                |_| true,
                &mut store,
                &mut integrity.journal,
            );
        }
    }

    /// Verifies `id`'s seals off the agent's thread (karyos#1111): the
    /// evidence is gathered here, then a worker reads the sealed ranges
    /// through a read-only view of the recording's store and answers
    /// `reply` itself, so a long verification never holds the recorders
    /// or the replays. One verification runs at a time; another is
    /// answered with an error to retry.
    pub(super) fn verify(&mut self, id: u64, reply: super::Reply<Verified>)
    where
        D: Send + 'static,
        D::File: Send,
    {
        let gathered = self.gather(id);
        let work = match gathered {
            Ok(work) => work,
            Err(answer) => {
                let _ = reply.send(Ok(Err(answer)));
                return;
            }
        };
        if self
            .verifying
            .compare_exchange(
                0,
                id,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            let _ = reply.send(Ok(Err(RetentionAnswer::Error(
                "a verification runs; retry once it answers".to_owned(),
            ))));
            return;
        }
        let verifying = std::sync::Arc::clone(&self.verifying);
        let (worker_reply, answer) = (reply.clone(), reply);
        let spawned = std::thread::Builder::new()
            .name(VERIFY_THREAD.to_owned())
            .spawn(move || {
                // Cleared on every exit, a panic's unwind included, so a
                // failed verification never blocks the next one.
                let _clear = Clear(verifying);
                let verified = work.run();
                let _ = worker_reply.send(Ok(verified));
            });
        if let Err(error) = spawned {
            self.verifying
                .store(0, std::sync::atomic::Ordering::Release);
            let _ = answer.send(Ok(Err(RetentionAnswer::Error(error.to_string()))));
        }
    }

    /// The evidence of a verification of `id`, read on the agent's thread.
    fn gather(&mut self, id: u64) -> Result<Verification<D>, RetentionAnswer> {
        let Some(recording) = self.catalog.get(id).cloned() else {
            return Err(RetentionAnswer::UnknownRecording);
        };
        let end = super::described(&recording, &self.active).end;
        let Some(integrity) = self.integrity.as_mut() else {
            return Err(RetentionAnswer::Error(
                "no integrity journal: the Archive seals nothing".to_owned(),
            ));
        };
        let records = integrity
            .journal
            .records()
            .map_err(|error| RetentionAnswer::Error(error.to_string()))?;
        let (trust, journal_id, heads) = match integrity.signing.as_ref() {
            Some(signing) => (
                Some(signing.trust.clone()),
                signing.journal_id,
                signing.heads.entries().to_vec(),
            ),
            None => (None, 0, Vec::new()),
        };
        let mut disk = self.disk.clone();
        let registry = if trust.is_some() {
            read_entries::<D, REGISTRY_ENTRY_LENGTH>(&mut disk, &self.dir, KEYS_FILE)
                .map_err(|error| RetentionAnswer::Error(error.to_string()))?
        } else {
            Vec::new()
        };
        Ok(Verification {
            disk: self.disk.clone(),
            dir: self.dir.clone(),
            recording,
            end,
            records,
            trust,
            journal_id,
            heads,
            registry,
        })
    }
}

/// A purge's close time before `before` (ADR-0093): `recorded`, raised by
/// the newest modification time of the segments holding bytes below the
/// cutoff, never lowered; a time that cannot be read adds nothing. The
/// caller bounds `before` by the written end first.
fn close_time<D: Disk + Clone>(
    disk: &D,
    store: &SegmentStore<D>,
    before: u64,
    recorded: u64,
) -> Result<u64, crate::segment::SegmentError> {
    let mut disk = disk.clone();
    let mut closed_ns = recorded;
    for file in store.segment_files_holding_below(before)? {
        if let Ok(at) = disk.modified(&file) {
            closed_ns = closed_ns.max(at);
        }
    }
    Ok(closed_ns)
}

/// The current UTC time in ns, if the clock reads past the epoch.
fn utc_now_ns() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|since| u64::try_from(since.as_nanos()).ok())
}

/// Clears the "verification runs" flag when dropped.
struct Clear(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl Drop for Clear {
    fn drop(&mut self) {
        self.0.store(0, std::sync::atomic::Ordering::Release);
    }
}

/// The refusal of a purge of a recording a verification reads: retried
/// once the verification answers. Not journalled: nothing was asked of the
/// retention engine.
pub const VERIFICATION_RUNNING: &str = "verification_running";

/// The name of the verification worker's thread.
pub(super) const VERIFY_THREAD: &str = "karyos-archive-verify";

/// A verification's evidence, owned, for its worker.
struct Verification<D: Disk> {
    disk: D,
    dir: std::path::PathBuf,
    recording: Recording,
    end: u64,
    records: Vec<crate::integrity::SealRecord>,
    trust: Option<crate::integrity::trust::TrustRoot>,
    journal_id: u64,
    heads: Vec<[u8; crate::integrity::trust::SIGNED_HEAD_LENGTH]>,
    registry: Vec<[u8; REGISTRY_ENTRY_LENGTH]>,
}

impl<D: Disk + Clone> Verification<D> {
    /// Verifies, reading the recording's sealed ranges through a read-only
    /// view of its store: every range the verifier reports, sealed ranges
    /// in chain order, then its unsealed tail. A recording that still
    /// records is read below its seals only, which are durable, so the
    /// view never reads what its recorder is writing.
    fn run(self) -> Verified {
        let id = self.recording.id;
        let mut store = open_stopped(&self.disk, &self.dir, &self.recording)?;
        let externality = Externality::default();
        let evidence = Evidence {
            records: &self.records,
            journal_fault: None,
            journal_id: self.journal_id,
            trust: self.trust.as_ref(),
            registry: &self.registry,
            heads: &self.heads,
            anchors: &[],
            anchor_faults: 0,
            stores: &NoAnchors,
            externality: &externality,
            written: &[(id, self.end)],
        };
        let verification = verify::verify(&evidence, |recording, start, end| {
            // Only this recording's ranges are reported: another's are
            // never read.
            if recording != id {
                return RangeBytes::Missing;
            }
            store
                .as_mut()
                .ok_or_else(|| std::io::Error::other("no segment"))
                .and_then(|store| read_store(store, start, end))
                .map_or(RangeBytes::Missing, RangeBytes::Bytes)
        });
        Ok(verification
            .ranges
            .iter()
            .filter(|report| report.recording == id)
            .map(range)
            .collect())
    }
}

/// Opens a stopped recording's store for reading, changing nothing; `None`
/// for a recording that wrote no segment.
fn open_stopped<D: Disk + Clone>(
    disk: &D,
    dir: &Path,
    recording: &Recording,
) -> Result<Option<SegmentStore<D>>, RetentionAnswer> {
    match SegmentStore::open_verified(
        disk.clone(),
        dir,
        recording.id,
        recording.geometry,
        SyncPolicy::None,
    ) {
        Ok(store) => Ok(Some(store)),
        Err(crate::segment::SegmentError::NotFound { .. }) => Ok(None),
        Err(error) => Err(RetentionAnswer::Error(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_names_are_the_adr_names() {
        use crate::integrity::retention::{PurgeRefusal, ReleaseError};
        let purges = [
            (PurgeRefusal::NotAuthorised, "not_authorised"),
            (PurgeRefusal::LegalHold, "legal_hold"),
            (PurgeRefusal::HoldsUnknown, "holds_unknown"),
            (PurgeRefusal::NoPolicy, "no_policy"),
            (PurgeRefusal::NotExpired { expires_ns: 1 }, "not_expired"),
            (
                PurgeRefusal::BelowMinCopies {
                    verified: 0,
                    required: 1,
                },
                "below_min_copies",
            ),
            (PurgeRefusal::JournalUnavailable, "journal_unavailable"),
            (
                PurgeRefusal::WrongStore {
                    recording: 1,
                    store: 2,
                },
                "wrong_store",
            ),
            (
                PurgeRefusal::NotAWriteStart { before: 1 },
                "not_a_write_start",
            ),
            (
                PurgeRefusal::NotSealed {
                    before: 1,
                    sealed: 0,
                },
                "not_sealed",
            ),
            (PurgeRefusal::DuplicateId { id: 1 }, "duplicate_id"),
            (PurgeRefusal::ManualOnly, "manual_only"),
            (
                PurgeRefusal::SplitsSeal {
                    before: 1,
                    counter: 0,
                },
                "splits_seal",
            ),
        ];
        for (refusal, name) in purges {
            assert_eq!(refusal.name(), name);
        }
        let releases = [
            (ReleaseError::NoEvidence { recording: 1 }, "no_evidence"),
            (ReleaseError::JournalUnavailable, "journal_unavailable"),
            (ReleaseError::Unknown, "holds_unknown"),
            (ReleaseError::Unconfirmed { recording: 1 }, "unconfirmed"),
        ];
        for (error, name) in releases {
            assert_eq!(error.name(), name);
        }
    }

    #[test]
    fn reason_bits_follow_the_verifier_order() {
        let reasons = [
            Reason::UntrustedEvidence,
            Reason::UnknownKey,
            Reason::UnknownAlgorithm,
            Reason::MalformedEvidence,
            Reason::MissingEvidence,
            Reason::ConflictingAnchors,
            Reason::Corruption,
            Reason::ShortenedIndex,
            Reason::UnauthenticatedPurge,
            Reason::NoAnchor,
        ];
        let mut all = 0;
        for (bit, reason) in reasons.into_iter().enumerate() {
            assert_eq!(reason_bit(reason), 1 << bit, "{}", reason.name());
            all |= reason_bit(reason);
        }
        assert_eq!(all, control::RANGE_REASONS);
    }
}
