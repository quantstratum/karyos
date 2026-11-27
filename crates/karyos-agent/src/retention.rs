// SPDX-License-Identifier: Apache-2.0

//! The Archive's retention operations through the agent (M12; karyos#701):
//! a legal hold, a hold release, a purge and a seal verification, each
//! journalled with its operator and parameters digest.
//!
//! The fail-closed rule of owner item 51 is asymmetric, and so is the code:
//!
//! - A **hold** only ever preserves data, so it is sent even when its
//!   request cannot be journalled; the failed append is counted by the
//!   journal, as an emergency guard close is.
//! - A **hold release** and a **purge** expose or destroy data, so each is
//!   sent only after its request is durably journalled; without that they
//!   answer [`RetentionAnswer::JournalUnavailable`] and nothing is sent.
//! - A **seal verification** reads; its request is journalled without
//!   waiting, like a hold.
//! - A request the role does **not allow** is never sent: its request and
//!   its outcome, refused `not_authorised`, are journalled without
//!   waiting ([`refuse_unauthorised`]), so every request and its outcome
//!   are in the journal (SPEC §13, Audited operations; karyos#719).
//!
//! The reserved recording name `journal` (ADR-0113) names the agent's own
//! operations journal instead: [`journal_command`] runs the same four
//! operations, with the same roles, answers and journalling, through the
//! Archive library's engine over the journal's directory
//! ([`crate::journal::retention`]), never an Archive.
//!
//! The Archive is reached through [`RetentionBackend`]. The agent adds no
//! verdict of its own: a refusal carries the Archive's code and reason, and
//! a verification carries each range's outcome and reasons as the
//! Archive's verifier named them.
//!
//! Role matrix (owner item 51, recorded here and enforced by the server):
//!
//! | Operation    | Viewer | Operator | Risk officer | Administrator |
//! |--------------|--------|----------|--------------|---------------|
//! | seal-verify  | yes    | yes      | yes          | yes           |
//! | legal-hold   | no     | yes      | yes          | yes           |
//! | hold-release | no     | no       | no           | yes           |
//! | purge        | no     | no       | no           | yes           |

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

pub use crate::journal::retention::JOURNAL_SUBJECT;
use crate::journal::retention::refusal_word;
use crate::journal::{Journal, JournalRecord, Kind, MAX_REASON, UNKNOWN_OUTCOME};

/// An Archive backend shared with the worker that calls it: every call
/// runs off the agent's polling thread, waited for at most a bound.
pub type SharedBackend = Arc<Mutex<Box<dyn RetentionBackend>>>;

/// `backend` shared for [`retention_command`].
#[must_use]
pub fn shared(backend: Box<dyn RetentionBackend>) -> SharedBackend {
    Arc::new(Mutex::new(backend))
}

/// What the Archive answered to a hold, a release or a purge.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionReply {
    /// Done. A hold is reported applied only with evidence (R-CORE-22):
    /// `evidenced` is false when the Archive applied it without being able
    /// to record it.
    Done {
        /// Whether the Archive recorded it.
        evidenced: bool,
    },
    /// Refused by the Archive, with its code and reason, verbatim.
    Refused {
        /// The Archive's refusal code.
        code: u64,
        /// Its reason.
        reason: String,
    },
    /// No answer: it may or may not have taken effect.
    NoAnswer,
    /// A hold of the journal in force in this process only: neither its
    /// marker nor its record could be written (ADR-0113, point 6).
    HoldNotDurable,
}

/// One range's integrity outcome, as the Archive's verifier reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeOutcome {
    /// The range's start.
    pub start: u64,
    /// Its end, exclusive.
    pub end: u64,
    /// The outcome's name: `verified`, `beyond_anchor`, `unsealed`,
    /// `purged` or `inconsistent`.
    pub outcome: String,
    /// The reasons' names.
    pub reasons: Vec<String>,
}

/// The Archive, as the agent's retention operations reach it.
pub trait RetentionBackend: Send + core::fmt::Debug {
    /// Applies a legal hold on `recording`.
    fn hold(&mut self, recording: u64, operation: u64, operator: u32) -> RetentionReply;
    /// Releases the legal hold on `recording`.
    fn release(&mut self, recording: u64, operation: u64, operator: u32) -> RetentionReply;
    /// Purges `recording` below `before`.
    fn purge(
        &mut self,
        recording: u64,
        before: u64,
        operation: u64,
        operator: u32,
    ) -> RetentionReply;
    /// Verifies `recording`'s seals: each range's outcome, or `None` when
    /// no answer came.
    fn verify(&mut self, recording: u64) -> Option<Vec<RangeOutcome>>;
}

/// A retention operation to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    /// A legal hold.
    Hold,
    /// A hold release.
    Release,
    /// A purge below `before`.
    Purge {
        /// The position the purge removes everything below.
        before: u64,
    },
    /// A seal verification.
    Verify,
}

impl Operation {
    const fn kinds(self) -> (Kind, Kind) {
        match self {
            Self::Hold => (Kind::HoldRequest, Kind::HoldOutcome),
            Self::Release => (Kind::ReleaseRequest, Kind::ReleaseOutcome),
            Self::Purge { .. } => (Kind::PurgeRequest, Kind::PurgeOutcome),
            Self::Verify => (Kind::VerifyRequest, Kind::VerifyOutcome),
        }
    }

    /// Whether it may expose or destroy data, so fails closed without a
    /// durable request record.
    #[must_use]
    pub const fn fails_closed(self) -> bool {
        matches!(self, Self::Release | Self::Purge { .. })
    }

    const fn before(self) -> u64 {
        match self {
            Self::Purge { before } => before,
            _ => 0,
        }
    }
}

/// What a retention operation came to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionAnswer {
    /// The Archive did it.
    Done {
        /// The operation id, as journalled.
        operation: u64,
        /// Whether the Archive recorded it (a hold applied without
        /// evidence is `false`).
        evidenced: bool,
    },
    /// The Archive refused it.
    Refused {
        /// The operation id.
        operation: u64,
        /// The Archive's refusal code.
        code: u64,
        /// Its reason.
        reason: String,
    },
    /// The verification's outcomes, verbatim.
    Verified {
        /// The operation id.
        operation: u64,
        /// Each range's outcome.
        ranges: Vec<RangeOutcome>,
    },
    /// A release or a purge with no durable request record: not sent.
    JournalUnavailable,
    /// The agent has no Archive to send it to.
    NoArchive,
    /// An earlier call to the Archive has not returned yet: not sent.
    Busy,
    /// Sent, and no answer came.
    NoAnswer {
        /// The operation id.
        operation: u64,
    },
    /// A hold of the journal in force in this process only (ADR-0113):
    /// it inhibits every purge of the journal until a later poll makes it
    /// durable, and a restart would lose it.
    HoldNotDurable {
        /// The operation id.
        operation: u64,
    },
}

/// One retention command.
#[derive(Debug, Clone, Copy)]
pub struct Command<'a> {
    /// The operation.
    pub operation: Operation,
    /// The recording.
    pub recording: u64,
    /// The operation id.
    pub id: u64,
    /// The operator: the local peer's uid, or a relayed principal's
    /// operator id.
    pub operator: u32,
    /// The relay that carried the request, 0 for none (karyos#708): the
    /// operator and the relay are journalled apart, as for every relayed
    /// operation.
    pub relay: u64,
    /// The reason, at most [`MAX_REASON`] bytes are kept.
    pub reason: &'a [u8],
}

impl Command<'_> {
    fn reason(&self) -> &[u8] {
        self.reason.get(..MAX_REASON).unwrap_or(self.reason)
    }

    fn record(&self, kind: Kind, now: u64) -> JournalRecord {
        let mut record = JournalRecord::new(kind, now);
        record.guard = self.recording;
        record.expected = self.operation.before();
        record.operation = self.id;
        record.operator = u64::from(self.operator);
        // The digest over the same words a guard operation's covers, the
        // record's kind telling the operations apart.
        record.parameters = karyos_protocol::cnc::guard_parameters(
            self.recording,
            self.operation.before(),
            self.id,
            u64::from(self.operator),
            self.reason(),
        );
        record.reason = self.reason().to_vec();
        record.relay = self.relay;
        record
    }
}

/// What the worker brings back.
enum Raw {
    Reply(RetentionReply),
    Ranges(Option<Vec<RangeOutcome>>),
}

/// Calls `backend` for `operation` on a worker, waiting at most `wait`:
/// `None` when no answer came in time, the call then finishing on its
/// own.
fn call(
    backend: &SharedBackend,
    operation: Operation,
    recording: u64,
    id: u64,
    operator: u32,
    wait: Duration,
) -> Option<Raw> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let backend = Arc::clone(backend);
    let spawned = std::thread::Builder::new()
        .name("karyos-agent-retention".to_owned())
        .spawn(move || {
            let Ok(mut backend) = backend.lock() else {
                return;
            };
            let raw = match operation {
                Operation::Verify => Raw::Ranges(backend.verify(recording)),
                Operation::Hold => Raw::Reply(backend.hold(recording, id, operator)),
                Operation::Release => Raw::Reply(backend.release(recording, id, operator)),
                Operation::Purge { before } => {
                    Raw::Reply(backend.purge(recording, before, id, operator))
                }
            };
            let _ = sender.send(raw);
        });
    spawned.ok()?;
    receiver.recv_timeout(wait).ok()
}

/// Makes `command` through `backend`, journalled in `journal` when there
/// is one, at host monotonic times from `now`. The Archive is called on a
/// worker and waited for at most `wait`, so a slow one never holds the
/// agent's polling thread; no answer in time is an unknown outcome.
pub fn retention_command(
    mut journal: Option<&mut Journal>,
    backend: Option<&SharedBackend>,
    command: &Command<'_>,
    wait: Duration,
    mut now: impl FnMut() -> u64,
) -> RetentionAnswer {
    let Some(backend) = backend else {
        return RetentionAnswer::NoArchive;
    };
    // A call still running holds the backend: refuse before journalling.
    if backend.try_lock().is_err() {
        return RetentionAnswer::Busy;
    }
    let (request, outcome) = command.operation.kinds();
    let record = command.record(request, now());
    if command.operation.fails_closed() {
        let durable = journal
            .as_deref_mut()
            .is_some_and(|journal| journal.append_durable(&record, record.time).is_ok());
        if !durable {
            return RetentionAnswer::JournalUnavailable;
        }
    } else if let Some(journal) = journal.as_deref_mut() {
        // Preserving or reading goes ahead: a failed append is counted.
        let _ = journal.append(&record, record.time);
    }
    let (id, recording, operator) = (command.id, command.recording, command.operator);
    let answer = match call(backend, command.operation, recording, id, operator, wait) {
        Some(Raw::Ranges(Some(ranges))) => RetentionAnswer::Verified {
            operation: id,
            ranges,
        },
        Some(Raw::Reply(answer)) => reply(id, answer),
        Some(Raw::Ranges(None)) | None => RetentionAnswer::NoAnswer { operation: id },
    };
    if let Some(journal) = journal {
        let record = outcome_record(command, outcome, &answer, now());
        let _ = journal.append(&record, record.time);
    }
    answer
}

/// Journals `command`, which its requester's role does not allow, as
/// refused `not_authorised` (karyos#719): its request record, then its
/// outcome record with the refusal, both without waiting. Nothing is
/// sent; a journal that cannot record them changes nothing else, the
/// answer being `forbidden` either way.
pub fn refuse_unauthorised(journal: Option<&mut Journal>, command: &Command<'_>, now: u64) {
    let Some(journal) = journal else {
        return;
    };
    let (request, outcome) = command.operation.kinds();
    let record = command.record(request, now);
    let _ = journal.append(&record, now);
    let mut record = command.record(outcome, now);
    record.code = crate::journal::retention::REFUSED;
    record.word = refusal_word("not_authorised");
    let _ = journal.append(&record, now);
}

/// The outcome record of `command` that came to `answer`.
fn outcome_record(
    command: &Command<'_>,
    outcome: Kind,
    answer: &RetentionAnswer,
    now: u64,
) -> JournalRecord {
    let mut record = command.record(outcome, now);
    match answer {
        RetentionAnswer::Done { evidenced, .. } => record.word = u64::from(*evidenced),
        RetentionAnswer::Refused { code, .. } => record.code = *code,
        RetentionAnswer::Verified { ranges, .. } => {
            record.word = u64::try_from(ranges.len()).unwrap_or(u64::MAX);
        }
        _ => record.code = UNKNOWN_OUTCOME,
    }
    record
}

/// Makes `command` on the agent's own operations journal (ADR-0113),
/// `command.recording` being [`JOURNAL_SUBJECT`]: journalled as
/// [`retention_command`] journals an Archive's, a release and a purge
/// only after their request is durable, and run through the journal's
/// retention engine on this thread. `authorised` is false for a purge the
/// requester's role does not allow: refused `not_authorised`, journalled.
/// `retained` says whether an operation id is still retained: a purge
/// that would remove the record it is rebuilt from is refused
/// `operation_state_retained`. A refusal's outcome record keeps the
/// reason's code in its `word` ([`refusal_word`]).
pub fn journal_command(
    journal: Option<&mut Journal>,
    command: &Command<'_>,
    (authorised, retained): (bool, &dyn Fn(u64) -> bool),
    mut now: impl FnMut() -> u64,
) -> RetentionAnswer {
    let Some(journal) = journal else {
        return RetentionAnswer::JournalUnavailable;
    };
    let (request, outcome) = command.operation.kinds();
    let record = command.record(request, now());
    if command.operation.fails_closed() {
        if journal.append_durable(&record, record.time).is_err() {
            return RetentionAnswer::JournalUnavailable;
        }
    } else {
        // Preserving or reading goes ahead: a failed append is counted.
        let _ = journal.append(&record, record.time);
    }
    let id = command.id;
    let answer = match command.operation {
        Operation::Hold => reply(id, journal.hold_journal()),
        Operation::Release => reply(id, journal.release_journal()),
        Operation::Purge { before } => {
            let authorisation = karyos_archive::integrity::retention::Authorisation {
                operator: u64::from(command.operator),
                authorised,
            };
            let purged =
                journal.purge_journal_retaining(id, before, authorisation, now(), retained);
            reply(id, purged)
        }
        Operation::Verify => {
            journal.verify(now());
            match journal.integrity() {
                Some(integrity) => RetentionAnswer::Verified {
                    operation: id,
                    ranges: integrity.ranges.clone(),
                },
                None => RetentionAnswer::NoAnswer { operation: id },
            }
        }
    };
    let mut record = outcome_record(command, outcome, &answer, now());
    if let RetentionAnswer::Refused { reason, .. } = &answer {
        record.word = refusal_word(reason);
    }
    let _ = journal.append(&record, record.time);
    answer
}

fn reply(operation: u64, reply: RetentionReply) -> RetentionAnswer {
    match reply {
        RetentionReply::Done { evidenced } => RetentionAnswer::Done {
            operation,
            evidenced,
        },
        RetentionReply::Refused { code, reason } => RetentionAnswer::Refused {
            operation,
            code,
            reason,
        },
        RetentionReply::NoAnswer => RetentionAnswer::NoAnswer { operation },
        RetentionReply::HoldNotDurable => RetentionAnswer::HoldNotDurable { operation },
    }
}

#[cfg(test)]
mod tests;
