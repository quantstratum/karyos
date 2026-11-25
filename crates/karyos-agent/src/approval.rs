// SPDX-License-Identifier: Apache-2.0

//! The pending approval outcome of a two-person policy (R-CORE-20,
//! karyos#739; quantstratum-docs: karyos/adr/0112-two-person-pending-approval.md).
//!
//! - **Which operations.** The classes `--two-person` marks
//!   ([`crate::two_person::TwoPersonClass`]); an unmarked operation behaves
//!   as before.
//! - **Every dispatch path is gated.** A marked guard reopen enters the
//!   flow only through `submit OPID TOKEN guard-reopen ...` after its
//!   preview; the direct `guard-reopen` is refused `two-person required`,
//!   unsent and unjournalled. A marked `cluster-command OPID ...` enters
//!   it itself, after the checks a direct command has (an unknown
//!   Cluster, an unregistered command, a role without its authority or a
//!   used id are refused and journalled as before).
//! - **The third outcome.** A request entering the flow performs nothing:
//!   it is answered `{"operation":N,"outcome":"pending_approval",
//!   "expires_in_ms":N}` once its [`Kind::ApprovalRequested`] record is
//!   durable, which also consumes the preview's token and reserves the id.
//!   Without a durable journal it is refused `journal unavailable`, and the
//!   token and the id stay as they were. The record binds the requester
//!   (operator and relay), the target (the driver's directory, instance
//!   and guard, or the Cluster's name and attach instance) and the
//!   parameters (the epoch, or the command's name and parameter bytes,
//!   and the reason).
//! - **Approval** (`approve OPID`): by a principal whose operator id
//!   differs from the requester's, relays not counting (else `same
//!   principal`), whose role may make the operation itself (else
//!   `forbidden`). The bound target is checked again: a driver that is a
//!   new instance, or a Cluster whose gateway attached again, ends the
//!   operation `target changed`, unsent and journalled. Then
//!   [`Kind::ApprovalGranted`] is made durable (else `journal
//!   unavailable`, still pending) and the operation is dispatched by the
//!   path a direct request takes: the guard at the bound epoch, which the
//!   driver checks with the transition; the Cluster command through its
//!   in-flight reservation, its durable kind 20 record and its gateway. A
//!   `busy` Cluster, a dispatch record that cannot be made durable or an
//!   unreachable driver ends the operation unsent, journalled, never
//!   retried silently. The core checks no state of a product command.
//! - **One transition at a time.** The agent serves one request at a
//!   time; the deadline is checked before any approval or withdrawal. A
//!   later approve is answered with the operation's state: its outcome
//!   (as its submit or `cluster-command` would have answered),
//!   `already approved`, `operation expired` or `not pending`.
//! - **Withdrawal** (`withdraw OPID`): by the requester's operator id only
//!   (else `not requester`), journalled [`Kind::ApprovalWithdrawn`],
//!   answered `{"operation":N,"outcome":"withdrawn"}`.
//! - **Expiry.** The deadline is the request record's time plus
//!   `--approval-wait`; past it the operation is expired, journalled
//!   [`Kind::ApprovalExpired`] when the agent next touches it or at its
//!   periodic sweep ([`crate::Agent::refresh`]).
//! - **Retries and retention.** While pending, the exact request again
//!   (the same id, operation, target, principal and parameters) is
//!   answered pending, with no token needed; the same id with anything
//!   different is `operation id conflict`. After the end, the outcome is
//!   retained for [`crate::preview::RETAINED`] from the record that ended
//!   it; past that, or from another boot, the id is a tombstone, answered
//!   `operation expired`.
//! - **Restarts** (`Approvals::rebuild`). A pending operation never
//!   survives a restart: it is journalled expired, "agent restarted". A
//!   granted one without its dispatch record (a `ReopenRequest`, or a kind
//!   20, of its id) was not sent: journalled ended "agent restarted before
//!   dispatch", never unknown. A dispatched one without an outcome is
//!   unknown. A restart after those changes nothing further.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::agent::Requester;
use crate::cluster_admin::ClusterAnswer;
use crate::journal::{JournalRecord, Kind, UNKNOWN_OUTCOME};
use crate::operations::GuardAnswer;
use crate::preview::RETAINED;

/// What a pending operation acts on, and at what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// A guard reopen.
    Guard {
        /// The driver's directory.
        dir: PathBuf,
        /// The driver instance previewed.
        instance: u128,
        /// The guard.
        guard: u64,
        /// The closed epoch it reopens.
        epoch: u64,
    },
    /// A product Cluster's admin command.
    Cluster {
        /// The Cluster's name.
        cluster: String,
        /// The attach instance of the gateway that registered it.
        instance: u64,
        /// The command's name.
        command: String,
        /// Its parameter bytes.
        parameters: Vec<u8>,
    },
}

/// A request in the flow: who asked for what, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) requester: Requester,
    pub(crate) target: Target,
    /// The reason, as journalled.
    pub(crate) reason: Vec<u8>,
}

impl Request {
    /// Whether `other` asks for the same operation: the instance and the
    /// epoch come from the preview, not from the request, and are not
    /// compared.
    fn same(&self, other: &Self) -> bool {
        let target = match (&self.target, &other.target) {
            (
                Target::Guard { dir, guard, .. },
                Target::Guard {
                    dir: other_dir,
                    guard: other_guard,
                    ..
                },
            ) => dir == other_dir && guard == other_guard,
            (
                Target::Cluster {
                    cluster,
                    command,
                    parameters,
                    ..
                },
                Target::Cluster {
                    cluster: other_cluster,
                    command: other_command,
                    parameters: other_parameters,
                    ..
                },
            ) => {
                cluster == other_cluster
                    && command == other_command
                    && parameters == other_parameters
            }
            _ => false,
        };
        target && self.requester == other.requester && self.reason == other.reason
    }
}

/// Why an operation ended without being sent, as an
/// [`Kind::ApprovalExpired`] record's `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndCode {
    /// Its deadline passed.
    Expired,
    /// The agent restarted while it was pending.
    Restarted,
    /// The agent restarted after its approval, before its dispatch.
    BeforeDispatch,
    /// At approval, its driver was a new instance, or its Cluster's
    /// gateway had attached again.
    TargetChanged,
    /// At approval, another command to its Cluster was in flight.
    Busy,
    /// At approval, its dispatch record could not be made durable.
    JournalUnavailable,
    /// At approval, its driver could not be reached.
    DriverUnavailable,
}

impl EndCode {
    /// Its record code.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Expired => 1,
            Self::Restarted => 2,
            Self::BeforeDispatch => 3,
            Self::TargetChanged => 4,
            Self::Busy => 5,
            Self::JournalUnavailable => 6,
            Self::DriverUnavailable => 7,
        }
    }

    /// The code of `code`; an unknown one reads as expired.
    const fn from_code(code: u64) -> Self {
        match code {
            2 => Self::Restarted,
            3 => Self::BeforeDispatch,
            4 => Self::TargetChanged,
            5 => Self::Busy,
            6 => Self::JournalUnavailable,
            7 => Self::DriverUnavailable,
            _ => Self::Expired,
        }
    }

    /// Its text, the record's reason.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Expired => "deadline passed",
            Self::Restarted => "agent restarted",
            Self::BeforeDispatch => "agent restarted before dispatch",
            Self::TargetChanged => "target changed",
            Self::Busy => "busy",
            Self::JournalUnavailable => "journal unavailable",
            Self::DriverUnavailable => "driver unavailable",
        }
    }

    /// The refusal a later request about it gets.
    pub(crate) const fn refusal(self) -> Refusal {
        match self {
            Self::Expired | Self::Restarted => Refusal::OperationExpired,
            Self::BeforeDispatch => Refusal::BeforeDispatch,
            Self::TargetChanged => Refusal::TargetChanged,
            Self::Busy => Refusal::Busy,
            Self::JournalUnavailable => Refusal::JournalUnavailable,
            Self::DriverUnavailable => Refusal::DriverUnavailable,
        }
    }
}

/// How an operation in the flow ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum End {
    /// A guard reopen sent: the driver's outcome.
    Guard(GuardAnswer),
    /// A Cluster command sent, or refused by the dispatch's own checks.
    Cluster(ClusterAnswer),
    /// Withdrawn by its requester.
    Withdrawn,
    /// Never sent.
    Unsent(EndCode),
}

/// Where an operation in the flow is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum State {
    /// Waiting for an approval until `deadline`, host monotonic
    /// nanoseconds.
    Pending { deadline: u64 },
    /// Approved, being sent.
    Granted,
    /// Ended by the record at `at`, host monotonic nanoseconds; `None` for
    /// one of another boot, a tombstone.
    Ended { end: End, at: Option<u64> },
}

/// A refusal of the flow's: nothing was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The approver is the requester, locally or through a relay.
    SamePrincipal,
    /// The approver's role may not make the operation.
    Forbidden,
    /// The bound target changed: the operation ended unsent.
    TargetChanged,
    /// The deadline passed, or the id is a tombstone.
    OperationExpired,
    /// The operation is approved and being sent.
    AlreadyApproved,
    /// The operation is not pending: withdrawn, or not in the flow.
    NotPending,
    /// No operation has this id.
    OperationIdUnknown,
    /// Only the requester withdraws.
    NotRequester,
    /// No durable record: nothing changed.
    JournalUnavailable,
    /// The id names another operation.
    OperationConflict,
    /// The agent restarted after the approval, before the dispatch.
    BeforeDispatch,
    /// Another command to the Cluster was in flight at the approval.
    Busy,
    /// The driver could not be reached at the approval.
    DriverUnavailable,
}

impl Refusal {
    /// Its error text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::SamePrincipal => "same principal",
            Self::Forbidden => "forbidden",
            Self::TargetChanged => "target changed",
            Self::OperationExpired => "operation expired",
            Self::AlreadyApproved => "already approved",
            Self::NotPending => "not pending",
            Self::OperationIdUnknown => "operation id unknown",
            Self::NotRequester => "not requester",
            Self::JournalUnavailable => "journal unavailable",
            Self::OperationConflict => "operation id conflict",
            Self::BeforeDispatch => "agent restarted before dispatch",
            Self::Busy => "busy",
            Self::DriverUnavailable => "driver unavailable",
        }
    }
}

/// The answer to a request that may enter the flow, to `approve` and to
/// `withdraw`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovalAnswer {
    /// Pending: nothing performed.
    Pending {
        /// The operation id.
        operation: u64,
        /// The time left until its deadline.
        expires_in_ms: u64,
    },
    /// Withdrawn by its requester.
    Withdrawn {
        /// The operation id.
        operation: u64,
    },
    /// A guard operation's answer, as a submit's.
    Guard(GuardAnswer),
    /// A Cluster command's answer, as a `cluster-command`'s.
    Cluster(ClusterAnswer),
    /// A submit's own refusal, before the flow.
    Submit(crate::preview::SubmitRefusal),
    /// The flow's refusal.
    Refused(Refusal),
}

/// Nanoseconds of `duration`, saturated.
pub(crate) fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// An operation in the flow.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) request: Request,
    pub(crate) state: State,
}

/// The operations in the flow, by id (karyos#739).
#[derive(Debug, Default)]
pub(crate) struct Approvals {
    by_id: HashMap<u64, Entry>,
}

impl Approvals {
    /// The operation `operation`.
    pub(crate) fn get(&self, operation: u64) -> Option<&Entry> {
        self.by_id.get(&operation)
    }

    /// Enters `request` as `operation`, pending until `deadline`.
    pub(crate) fn pend(&mut self, operation: u64, request: Request, deadline: u64) {
        let _ = self.by_id.insert(
            operation,
            Entry {
                request,
                state: State::Pending { deadline },
            },
        );
    }

    /// Sets `operation`'s state.
    pub(crate) fn set(&mut self, operation: u64, state: State) {
        if let Some(entry) = self.by_id.get_mut(&operation) {
            entry.state = state;
        }
    }

    /// The pending operations whose deadline is past at `now`.
    pub(crate) fn due(&self, now: u64) -> Vec<u64> {
        let mut due: Vec<u64> = self
            .by_id
            .iter()
            .filter(
                |(_, entry)| matches!(entry.state, State::Pending { deadline } if now >= deadline),
            )
            .map(|(id, _)| *id)
            .collect();
        due.sort_unstable();
        due
    }

    /// The ids in the flow: every one is used.
    pub(crate) fn ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.by_id.keys().copied()
    }

    /// The answer to `request` again under `operation` at `now`, if the
    /// id is in the flow: pending again while pending, the retained outcome
    /// after the end, or a conflict for anything different. `None` for an
    /// id not in the flow. Expiry is the caller's, first.
    pub(crate) fn retry(
        &self,
        operation: u64,
        request: &Request,
        now: u64,
    ) -> Option<ApprovalAnswer> {
        let entry = self.by_id.get(&operation)?;
        if !entry.request.same(request) {
            return Some(ApprovalAnswer::Refused(Refusal::OperationConflict));
        }
        Some(Self::state_answer(operation, &entry.state, now, true))
    }

    /// The answer an operation in `state` gives at `now` to a retry of
    /// its request (`retry`) or to an approve.
    pub(crate) fn state_answer(
        operation: u64,
        state: &State,
        now: u64,
        retry: bool,
    ) -> ApprovalAnswer {
        match state {
            State::Pending { deadline } if now < *deadline => ApprovalAnswer::Pending {
                operation,
                expires_in_ms: deadline.saturating_sub(now) / 1_000_000,
            },
            State::Pending { .. } => ApprovalAnswer::Refused(Refusal::OperationExpired),
            State::Granted => ApprovalAnswer::Refused(Refusal::AlreadyApproved),
            State::Ended { at, .. } if !live(*at, now) => {
                ApprovalAnswer::Refused(Refusal::OperationExpired)
            }
            State::Ended { end, .. } => match end {
                End::Guard(answer) => ApprovalAnswer::Guard(*answer),
                End::Cluster(answer) => ApprovalAnswer::Cluster(answer.clone()),
                End::Withdrawn if retry => ApprovalAnswer::Withdrawn { operation },
                End::Withdrawn => ApprovalAnswer::Refused(Refusal::NotPending),
                End::Unsent(code) => ApprovalAnswer::Refused(code.refusal()),
            },
        }
    }

    /// Rebuilds the flow from the journal's records, oldest first, at host
    /// time `now` on boot `boot` (ADR-0112 point 10), with the records a
    /// restart adds: an [`Kind::ApprovalExpired`] for each operation that
    /// was pending ("agent restarted") or granted without its dispatch
    /// record ("agent restarted before dispatch"). A granted operation
    /// with a dispatch record and no outcome is unknown. An ending record
    /// of another boot is a tombstone.
    pub(crate) fn rebuild(
        records: &[JournalRecord],
        (now, boot): (u64, &[u8]),
    ) -> (Self, Vec<JournalRecord>) {
        /// What a rebuild follows of one operation.
        struct Followed {
            entry: Entry,
            dispatched: bool,
            /// The boot of its latest approval record.
            boot: Vec<u8>,
        }
        let at = |time: u64, record_boot: &[u8]| {
            (!boot.is_empty() && record_boot == boot && time <= now).then_some(time)
        };
        let mut followed: HashMap<u64, Followed> = HashMap::new();
        for record in records {
            let operation = record.operation;
            if record.kind == Kind::ApprovalRequested {
                if let Some(request) = request_of(record) {
                    let deadline = record.time.saturating_add(record.word);
                    let _ = followed.insert(
                        operation,
                        Followed {
                            entry: Entry {
                                request,
                                state: State::Pending { deadline },
                            },
                            dispatched: false,
                            boot: record.boot.clone(),
                        },
                    );
                }
                continue;
            }
            let Some(op) = followed.get_mut(&operation) else {
                continue;
            };
            let granted = op.entry.state == State::Granted;
            match record.kind {
                Kind::ApprovalGranted if matches!(op.entry.state, State::Pending { .. }) => {
                    op.entry.state = State::Granted;
                    op.boot.clone_from(&record.boot);
                }
                Kind::ApprovalWithdrawn => {
                    op.entry.state = State::Ended {
                        end: End::Withdrawn,
                        at: at(record.time, &record.boot),
                    };
                }
                Kind::ApprovalExpired => {
                    op.entry.state = State::Ended {
                        end: End::Unsent(EndCode::from_code(record.code)),
                        at: at(record.time, &record.boot),
                    };
                }
                Kind::ReopenRequest | Kind::ClusterRequest if granted => op.dispatched = true,
                Kind::Submitted if granted => {
                    op.entry.state = State::Ended {
                        end: End::Guard(crate::preview::submitted_answer(record)),
                        at: at(record.time, &record.boot),
                    };
                }
                Kind::ClusterOutcome if granted && op.dispatched => {
                    op.entry.state = State::Ended {
                        end: End::Cluster(cluster_answer(record)),
                        at: at(record.time, &op.boot),
                    };
                }
                _ => {}
            }
        }
        let mut added = Vec::new();
        let mut approvals = Self::default();
        let mut ids: Vec<u64> = followed.keys().copied().collect();
        ids.sort_unstable();
        for operation in ids {
            let Some(op) = followed.remove(&operation) else {
                continue;
            };
            let mut entry = op.entry;
            let unsent = match entry.state {
                State::Pending { .. } => Some(EndCode::Restarted),
                State::Granted if !op.dispatched => Some(EndCode::BeforeDispatch),
                State::Granted => {
                    let end = match entry.request.target {
                        Target::Guard { .. } => End::Guard(GuardAnswer::NoAnswer { operation }),
                        Target::Cluster { .. } => End::Cluster(ClusterAnswer::NoAnswer {
                            operation,
                            journalled: false,
                        }),
                    };
                    entry.state = State::Ended {
                        end,
                        at: (op.boot.as_slice() == boot && !boot.is_empty()).then_some(now),
                    };
                    None
                }
                State::Ended { .. } => None,
            };
            if let Some(code) = unsent {
                added.push(ended_record(operation, code, (now, boot)));
                entry.state = State::Ended {
                    end: End::Unsent(code),
                    at: (!boot.is_empty()).then_some(now),
                };
            }
            let _ = approvals.by_id.insert(operation, entry);
        }
        (approvals, added)
    }
}

/// Whether an outcome ended at `at` is retained at `now`.
fn live(at: Option<u64>, now: u64) -> bool {
    at.is_some_and(|at| {
        now.checked_sub(at)
            .is_some_and(|age| age <= nanos(RETAINED))
    })
}

/// The request an [`Kind::ApprovalRequested`] record binds.
fn request_of(record: &JournalRecord) -> Option<Request> {
    let requester = Requester::relayed(u32::try_from(record.operator).ok()?, record.relay);
    let target = match record.parameters {
        1 => Target::Guard {
            dir: PathBuf::from(
                <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&record.target),
            ),
            instance: record.instance,
            guard: record.guard,
            epoch: record.expected,
        },
        2 => Target::Cluster {
            cluster: String::from_utf8(record.target.clone()).ok()?,
            instance: u64::try_from(record.instance).ok()?,
            command: String::from_utf8(record.command.clone()).ok()?,
            parameters: record.bytes.clone(),
        },
        _ => return None,
    };
    Some(Request {
        requester,
        target,
        reason: record.reason.clone(),
    })
}

/// The answer a [`Kind::ClusterOutcome`] record journals. The product's
/// reply bytes are not journalled: a sequenced outcome rebuilt at start
/// answers its index, term and evidence with an empty reply.
fn cluster_answer(record: &JournalRecord) -> ClusterAnswer {
    let operation = record.operation;
    if record.code == UNKNOWN_OUTCOME {
        ClusterAnswer::NoAnswer {
            operation,
            journalled: true,
        }
    } else if record.code == 0 {
        let evidence = std::str::from_utf8(&record.evidence)
            .ok()
            .and_then(|text| text.split_once(':'))
            .and_then(|(algorithm, digest)| {
                crate::cluster_admin::Evidence::new(algorithm, &unhex(digest)?)
            });
        ClusterAnswer::Sequenced {
            operation,
            index: record.word,
            term: record.expected,
            reply: Vec::new(),
            evidence,
            journalled: true,
        }
    } else {
        ClusterAnswer::Refused {
            operation,
            code: record.code,
            reason: String::new(),
            journalled: true,
        }
    }
}

/// The bytes of `text`, an even number of hex digits.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// The [`Kind::ApprovalRequested`] record of `request` as `operation`,
/// waiting `wait`, at `time` on `boot`.
pub(crate) fn requested_record(
    operation: u64,
    request: &Request,
    wait: Duration,
    (time, boot): (u64, &[u8]),
) -> JournalRecord {
    let mut record = JournalRecord::new(Kind::ApprovalRequested, time);
    record.operation = operation;
    record.operator = u64::from(request.requester.operator);
    record.relay = request.requester.relay;
    record.reason.clone_from(&request.reason);
    record.word = nanos(wait);
    record.boot = boot.to_vec();
    match &request.target {
        Target::Guard {
            dir,
            instance,
            guard,
            epoch,
        } => {
            record.parameters = 1;
            record.target = std::os::unix::ffi::OsStrExt::as_bytes(dir.as_os_str()).to_vec();
            record.instance = *instance;
            record.guard = *guard;
            record.expected = *epoch;
        }
        Target::Cluster {
            cluster,
            instance,
            command,
            parameters,
        } => {
            record.parameters = 2;
            record.target = cluster.as_bytes().to_vec();
            record.instance = u128::from(*instance);
            record.command = command.as_bytes().to_vec();
            record.bytes.clone_from(parameters);
        }
    }
    record
}

/// An [`Kind::ApprovalGranted`] or [`Kind::ApprovalWithdrawn`] record of
/// `operation` by `by`, at `time` on `boot`.
pub(crate) fn principal_record(
    kind: Kind,
    operation: u64,
    by: Requester,
    (time, boot): (u64, &[u8]),
) -> JournalRecord {
    let mut record = JournalRecord::new(kind, time);
    record.operation = operation;
    record.operator = u64::from(by.operator);
    record.relay = by.relay;
    record.boot = boot.to_vec();
    record
}

/// The [`Kind::ApprovalExpired`] record of `operation`, ended unsent for
/// `code`, at `time` on `boot`.
pub(crate) fn ended_record(
    operation: u64,
    code: EndCode,
    (time, boot): (u64, &[u8]),
) -> JournalRecord {
    let mut record = JournalRecord::new(Kind::ApprovalExpired, time);
    record.operation = operation;
    record.code = code.code();
    record.reason = code.text().as_bytes().to_vec();
    record.boot = boot.to_vec();
    record
}
