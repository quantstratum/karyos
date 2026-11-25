// SPDX-License-Identifier: Apache-2.0

//! Preview calls and caller-chosen operation ids (R-CORE-18, karyos#738;
//! quantstratum-docs: karyos/design/product-requirements-on-core.md).
//!
//! - **Preview.** `guard-close-preview DIR GUARD [REASON]` and
//!   `guard-reopen-preview DIR GUARD [REASON]` answer what the operation
//!   would do: the guard's state as the agent last saw it in the driver's
//!   guard audit, the epoch after, and a token. A field the agent cannot
//!   read is answered `"unavailable"`, never as a zero or a false
//!   (RR-CON-0008): a guard with no transition in the audit records the
//!   agent follows has no known state, and then no token either.
//! - **The token** is 128 random bits naming a preview the agent keeps in
//!   memory: the principal (the requester and the relay that carried it),
//!   the target (the driver's directory and instance, and the guard), the
//!   parameters (the operation, the epoch it acts at and the reason), and
//!   its expiry, [`PREVIEW_TTL`] after the preview. At most
//!   [`MAX_PREVIEWS`] are kept; past that the oldest is dropped.
//! - **Submit.** `submit OPID TOKEN guard-close|guard-reopen DIR GUARD
//!   [REASON]` performs exactly the previewed operation under the caller's
//!   operation id `OPID`. It is refused, with nothing sent, when the token
//!   is unknown, used or expired, or when its principal, its target or
//!   its parameters differ from the preview's, or when the driver is a new
//!   instance since. The epoch is checked by the driver itself, atomically
//!   with the transition (`GuardCloseAt` and `GuardReopen`): a guard that
//!   moved since the preview is refused there (`GuardNotOpenAt`,
//!   `GuardNotClosedAt`) and audited. A token is used up by the submit that
//!   sends it, whatever its outcome.
//! - **The operation id.** A submit journals and audits its request and
//!   outcome under `OPID`, as one operation: the preview itself leaves no
//!   record. An id is used up by its first submit that is sent, whatever
//!   came of it, and never takes a second operation:
//!   - **A retry** (the same id, operation, guard, principal and reason,
//!     with any token or none) is answered with the operation's retained
//!     outcome, unsent: its state, its refusal, or `no answer` for an
//!     unknown outcome, which is never retried as a new operation.
//!   - **A conflict** (the same id with any of those different) is refused
//!     `operation id conflict`, unsent.
//!   - **Expiry.** An outcome is retained for [`RETAINED`] after it was
//!     journalled; past that, the id is a tombstone: a retry is answered
//!     `operation expired`, distinct from a fresh operation and from a
//!     retained outcome, and is not sent either.
//!   - **Restarts.** With a journal, each sent submit is journalled as a
//!     `Submitted` record (its operation, driver directory, guard,
//!     principal, reason, epoch, full outcome and this host's boot
//!     identity), and the retained outcomes, tombstones and caller ids
//!     are rebuilt at start from those records only, so a restart keeps
//!     them: the agent's own ids of direct operations are not among them.
//!     A record of another boot (Linux's `boot_id`), whose monotonic time
//!     does not compare, is a tombstone. A submit that was not sent (no
//!     attach) is not journalled as one, and its id stays free. A journal
//!     that cannot be resumed (a new recording) starts with none, and
//!     records the unknown interval it opens with.
//!   - **Retries need no token.** `submit OPID - ...` names no token: it
//!     reaches a used id's retained outcome, and a fresh id without a
//!     token is `token unknown`.
//!   - **Id 0** is no operation id: refused as `operation id conflict`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use karyos_sys::guard::GuardState;

use crate::agent::Requester;

/// How long a submitted operation's outcome is retained for a retry
/// (karyos#738); past it the id is a tombstone.
pub const RETAINED: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a preview's token stays valid.
pub const PREVIEW_TTL: Duration = Duration::from_secs(60);

/// The previews the agent keeps at most.
pub const MAX_PREVIEWS: usize = 256;

/// The guard operation a preview is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreviewKind {
    /// `guard-close`.
    Close,
    /// `guard-reopen`.
    Reopen,
}

impl PreviewKind {
    /// Its request name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Close => "guard-close",
            Self::Reopen => "guard-reopen",
        }
    }
}

/// A preview's token: 128 random bits, written as 32 hex digits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Token([u8; 16]);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// A fresh token from the operating system's random source; `None`
    /// when it cannot be read.
    fn fresh() -> Option<Self> {
        use std::io::Read as _;
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut bytes))
            .ok()?;
        Some(Self(bytes))
    }

    /// The token written as `hex`, if it is 32 hex digits.
    #[must_use]
    pub fn parse(hex: &str) -> Option<Self> {
        if hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let digits = hex.get(index * 2..index * 2 + 2)?;
            *byte = u8::from_str_radix(digits, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// Its 32 hex digits.
    #[must_use]
    pub fn hex(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(32);
        for byte in self.0 {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }
}

/// What a preview binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bound {
    pub(crate) kind: PreviewKind,
    pub(crate) dir: PathBuf,
    pub(crate) guard: u64,
    pub(crate) requester: Requester,
    pub(crate) reason: Vec<u8>,
}

/// A kept preview.
#[derive(Debug, Clone)]
struct Kept {
    token: Token,
    bound: Bound,
    /// The driver instance it was taken of.
    instance: u128,
    /// The epoch the operation acts at: the open epoch a close replaces,
    /// or the closed one a reopen does.
    epoch: u64,
    expires: Instant,
}

/// What the agent saw of the guard for a preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) instance: u128,
    /// The guard's state from the latest transition the agent followed in
    /// its audit; `None` when it has none.
    pub(crate) state: Option<GuardState>,
}

/// A preview's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreviewAnswer {
    /// What the operation would do. `state` and `token` are `None` when
    /// unavailable; `epoch_after` is `None` when there is no change to
    /// make or the state is unavailable.
    Previewed {
        /// The operation.
        kind: PreviewKind,
        /// The guard.
        guard: u64,
        /// The driver instance.
        instance: u128,
        /// The guard's state as last seen.
        state: Option<GuardState>,
        /// The epoch after the operation.
        epoch_after: Option<u64>,
        /// The token a submit names, when there is a change to make.
        token: Option<Token>,
    },
    /// The directory is not one of the agent's drivers.
    UnknownDriver,
    /// The agent is not attached to that driver.
    Unattached,
}

/// Why a submit was refused; nothing was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubmitRefusal {
    /// No preview has this token: never issued, already used, or dropped.
    TokenUnknown,
    /// The preview expired.
    TokenExpired,
    /// Another principal previewed it.
    PrincipalMismatch,
    /// It was previewed for another operation, driver or guard.
    TargetMismatch,
    /// It was previewed with another reason.
    ParametersMismatch,
    /// The driver is a new instance since the preview.
    TargetChanged,
    /// The operation id was used for another operation, or is 0.
    OperationConflict,
    /// The operation id's retained outcome expired: a tombstone.
    OperationExpired,
}

impl SubmitRefusal {
    /// Its error text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::TokenUnknown => "token unknown",
            Self::TokenExpired => "token expired",
            Self::PrincipalMismatch => "principal mismatch",
            Self::TargetMismatch => "target mismatch",
            Self::ParametersMismatch => "parameters mismatch",
            Self::TargetChanged => "target changed",
            Self::OperationConflict => "operation id conflict",
            Self::OperationExpired => "operation expired",
        }
    }
}

/// The previews the agent keeps.
#[derive(Debug, Default)]
pub(crate) struct Previews {
    kept: Vec<Kept>,
}

impl Previews {
    /// Answers a preview of `bound` over what the agent `seen`, at `now`,
    /// keeping a token when there is a change to make.
    pub(crate) fn preview(&mut self, bound: Bound, seen: Seen, now: Instant) -> PreviewAnswer {
        self.expire(now);
        let (kind, guard) = (bound.kind, bound.guard);
        let change = seen.state.and_then(|state| match (kind, state.open) {
            (PreviewKind::Close, true) | (PreviewKind::Reopen, false) => {
                // Never past the guard's last epoch: a reopen there is
                // exhausted, so there is nothing to preview a token for.
                state
                    .epoch
                    .checked_add(1)
                    .filter(|after| *after <= karyos_sys::guard::MAX_EPOCH)
                    .map(|after| (state.epoch, after))
            }
            _ => None,
        });
        let token = change.and_then(|(epoch, _)| {
            let token = Token::fresh()?;
            if self.kept.len() >= MAX_PREVIEWS {
                let _ = self.kept.remove(0);
            }
            self.kept.push(Kept {
                token,
                bound,
                instance: seen.instance,
                epoch,
                expires: now + PREVIEW_TTL,
            });
            Some(token)
        });
        PreviewAnswer::Previewed {
            kind,
            guard,
            instance: seen.instance,
            state: seen.state,
            epoch_after: change.map(|(_, after)| after),
            token,
        }
    }

    /// The epoch to act at for a submit of `bound` with `token`, against
    /// the driver's current `instance`, at `now`; the preview is used up
    /// when it matches.
    ///
    /// # Errors
    ///
    /// The [`SubmitRefusal`] that names the first mismatch; a mismatched
    /// preview is kept for its own principal.
    pub(crate) fn take(
        &mut self,
        token: Token,
        bound: &Bound,
        instance: Option<u128>,
        now: Instant,
    ) -> Result<u64, SubmitRefusal> {
        let epoch = self.peek(token, bound, instance, now)?;
        self.remove(token);
        Ok(epoch)
    }

    /// As [`Previews::take`], but a matching preview is kept: the
    /// two-person flow uses it up only once its `ApprovalRequested` is
    /// durable (karyos#739). An expired preview, or one of a driver that
    /// is a new instance since, is dropped as by `take`.
    ///
    /// # Errors
    ///
    /// As [`Previews::take`].
    pub(crate) fn peek(
        &mut self,
        token: Token,
        bound: &Bound,
        instance: Option<u128>,
        now: Instant,
    ) -> Result<u64, SubmitRefusal> {
        let index = self
            .kept
            .iter()
            .position(|kept| kept.token == token)
            .ok_or(SubmitRefusal::TokenUnknown)?;
        let kept = self.kept.get(index).ok_or(SubmitRefusal::TokenUnknown)?;
        if now >= kept.expires {
            let _ = self.kept.remove(index);
            return Err(SubmitRefusal::TokenExpired);
        }
        let previewed = &kept.bound;
        if previewed.requester != bound.requester {
            return Err(SubmitRefusal::PrincipalMismatch);
        }
        if previewed.kind != bound.kind
            || previewed.dir != bound.dir
            || previewed.guard != bound.guard
        {
            return Err(SubmitRefusal::TargetMismatch);
        }
        if previewed.reason != bound.reason {
            return Err(SubmitRefusal::ParametersMismatch);
        }
        let epoch = kept.epoch;
        if instance != Some(kept.instance) {
            let _ = self.kept.remove(index);
            return Err(SubmitRefusal::TargetChanged);
        }
        Ok(epoch)
    }

    /// Drops the preview of `token`: used up.
    pub(crate) fn remove(&mut self, token: Token) {
        self.kept.retain(|kept| kept.token != token);
    }

    /// Drops the previews expired at `now`.
    fn expire(&mut self, now: Instant) {
        self.kept.retain(|kept| now < kept.expires);
    }
}

/// The state of `guard` from the newest record in `audit` that carries
/// its word, if any: every record of a known guard carries the word after
/// it (a refusal, the unchanged one); an unknown guard's carries 0.
pub(crate) fn last_state(audit: &[crate::api::GuardEntry], guard: u64) -> Option<GuardState> {
    audit
        .iter()
        .rev()
        .filter(|entry| entry.guard == guard && entry.after != 0)
        .find_map(|entry| karyos_sys::guard::decode(entry.after).ok())
}

/// What an operation id was used for: the operation, its target and its
/// principal, compared on a retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Used {
    pub(crate) kind: PreviewKind,
    /// The driver's directory, journalled with the id (karyos#738 review).
    pub(crate) dir: Option<PathBuf>,
    pub(crate) guard: u64,
    pub(crate) requester: Requester,
    pub(crate) reason: Vec<u8>,
}

impl Used {
    /// Whether `bound` asks for the same operation.
    fn same(&self, bound: &Bound) -> bool {
        self.kind == bound.kind
            && self.dir.as_ref() == Some(&bound.dir)
            && self.guard == bound.guard
            && self.requester == bound.requester
            && self.reason == bound.reason
    }
}

/// A used operation id's entry.
#[derive(Debug, Clone)]
struct Outcome {
    used: Used,
    answer: crate::operations::GuardAnswer,
    /// When it was journalled, host monotonic nanoseconds; `None` for one
    /// from before this host's boot, a tombstone.
    at: Option<u64>,
}

/// The outcomes of the operation ids used (karyos#738).
#[derive(Debug, Default)]
pub(crate) struct Outcomes {
    by_id: std::collections::HashMap<u64, Outcome>,
}

impl Outcomes {
    /// The answer to a submit of `bound` under `operation` at host time
    /// `now`, if the id was used: the retained outcome of a retry, or the
    /// refusal of a conflict or an expired id. `None` for a fresh id.
    pub(crate) fn answer(
        &self,
        operation: u64,
        bound: &Bound,
        now: u64,
    ) -> Option<Result<crate::operations::GuardAnswer, SubmitRefusal>> {
        if operation == 0 {
            return Some(Err(SubmitRefusal::OperationConflict));
        }
        let outcome = self.by_id.get(&operation)?;
        if !outcome.used.same(bound) {
            return Some(Err(SubmitRefusal::OperationConflict));
        }
        let retained = u64::try_from(RETAINED.as_nanos()).unwrap_or(u64::MAX);
        let live = outcome
            .at
            .is_some_and(|at| now.checked_sub(at).is_some_and(|age| age <= retained));
        Some(if live {
            Ok(outcome.answer)
        } else {
            Err(SubmitRefusal::OperationExpired)
        })
    }

    /// Records `operation`'s use for `used`, answered `answer` at `at`.
    pub(crate) fn record(
        &mut self,
        operation: u64,
        used: Used,
        answer: crate::operations::GuardAnswer,
        at: u64,
    ) {
        let _ = self.by_id.insert(
            operation,
            Outcome {
                used,
                answer,
                at: Some(at),
            },
        );
    }

    /// Rebuilds the outcomes from the journal's [`Kind::Submitted`]
    /// records, oldest first, at host time `now` on boot `boot`: only
    /// caller-chosen ids that were sent are there. A record of another
    /// boot (or of an unknown one) is a tombstone, as is one older than
    /// [`RETAINED`] when answered.
    ///
    /// [`Kind::Submitted`]: crate::journal::Kind::Submitted
    pub(crate) fn rebuild(
        records: &[crate::journal::JournalRecord],
        (now, boot): (u64, &[u8]),
    ) -> Self {
        use crate::journal::Kind;
        let mut outcomes = Self::default();
        for record in records
            .iter()
            .filter(|record| record.kind == Kind::Submitted)
        {
            let kind = if record.parameters == 2 {
                PreviewKind::Reopen
            } else {
                PreviewKind::Close
            };
            let operation = record.operation;
            let answer = submitted_answer(record);
            let used = Used {
                kind,
                dir: Some(PathBuf::from(
                    <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&record.target),
                )),
                guard: record.guard,
                requester: Requester::relayed(
                    u32::try_from(record.operator).unwrap_or(u32::MAX),
                    record.relay,
                ),
                reason: record.reason.clone(),
            };
            let same_boot = !boot.is_empty() && record.boot == boot;
            let _ = outcomes.by_id.insert(
                operation,
                Outcome {
                    used,
                    answer,
                    at: (same_boot && record.time <= now).then_some(record.time),
                },
            );
        }
        outcomes
    }

    /// The operation ids the outcomes hold: the caller ids used.
    pub(crate) fn ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.by_id.keys().copied()
    }
}

/// The outcome a [`crate::journal::Kind::Submitted`] record journals.
pub(crate) fn submitted_answer(
    record: &crate::journal::JournalRecord,
) -> crate::operations::GuardAnswer {
    use crate::journal::UNKNOWN_OUTCOME;
    use crate::operations::GuardAnswer;
    let operation = record.operation;
    if record.code == UNKNOWN_OUTCOME {
        GuardAnswer::NoAnswer { operation }
    } else if record.code == 0 {
        match karyos_sys::guard::decode(record.word) {
            Ok(state) => GuardAnswer::State {
                operation,
                guard: record.guard,
                state,
            },
            Err(_) => GuardAnswer::NoAnswer { operation },
        }
    } else {
        GuardAnswer::Refused {
            operation,
            code: record.code,
            detail: record.word,
        }
    }
}

/// This host's boot identity (Linux's `boot_id`), or empty when it cannot
/// be read: then no journalled outcome is taken for this boot's.
pub(crate) fn boot_id() -> Vec<u8> {
    std::fs::read("/proc/sys/kernel/random/boot_id")
        .map(|mut id| {
            while id.last().is_some_and(u8::is_ascii_whitespace) {
                let _ = id.pop();
            }
            id
        })
        .unwrap_or_default()
}

/// The [`crate::journal::Kind::Submitted`] record of a caller's operation
/// `operation` that was sent and answered `answer`, at `time` on `boot`.
pub(crate) fn submitted_record(
    operation: u64,
    used: &Used,
    (epoch, answer): (u64, crate::operations::GuardAnswer),
    (time, boot): (u64, &[u8]),
) -> crate::journal::JournalRecord {
    use crate::journal::{JournalRecord, Kind, UNKNOWN_OUTCOME};
    use crate::operations::GuardAnswer;
    let mut record = JournalRecord::new(Kind::Submitted, time);
    record.operation = operation;
    record.guard = used.guard;
    record.expected = epoch;
    record.parameters = match used.kind {
        PreviewKind::Close => 1,
        PreviewKind::Reopen => 2,
    };
    record.operator = u64::from(used.requester.operator);
    record.relay = used.requester.relay;
    record.reason = used.reason.clone();
    match answer {
        GuardAnswer::State { state, .. } => {
            record.word = karyos_sys::guard::encode(state).unwrap_or(0);
        }
        GuardAnswer::Refused { code, detail, .. } => {
            record.code = code;
            record.word = detail;
        }
        _ => record.code = UNKNOWN_OUTCOME,
    }
    record.target = used
        .dir
        .as_ref()
        .map(|dir| std::os::unix::ffi::OsStrExt::as_bytes(dir.as_os_str()).to_vec())
        .unwrap_or_default();
    record.boot = boot.to_vec();
    record
}

#[cfg(test)]
mod tests;
