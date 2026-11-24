// SPDX-License-Identifier: Apache-2.0

//! Audited guard operations through the agent (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M10b): an operator's
//! guard close or reopen, journalled, sent to the driver as an admitted
//! client acting for the operator's uid (M10a), its outcome journalled.
//!
//! - **Close.** Its request record is appended first; the close is sent
//!   whether the append worked or not (No A2: a close is never delayed by
//!   the journal), and a failed append counts in the journal.
//! - **Reopen.** Its request record must be durable first: without a
//!   journal, or when the append fails, the reopen is refused and never
//!   sent (it fails closed).
//! - **The driver.** The agent attaches as a client for the one command
//!   and leaves after it, so it holds no client slot between operations.
//!   No answer within the timeout is an unknown outcome, journalled as
//!   such ([`UNKNOWN_OUTCOME`]).
//! - **Rate change (R-CORE-21, karyos#740).** A rate policy change on a
//!   guarded stream: the safety path (a tightening) goes ahead whatever
//!   the journal does, as a close; an administrator's change needs its
//!   request durable first, as a reopen. Its records carry the stream in
//!   `guard`, the version it replaces in `expected` and the version after
//!   it in `word` (for a refusal, the refusal's detail).

use std::path::Path;
use std::time::{Duration, Instant};

use karyos_client::Outcome;
use karyos_client::ipc::{RemoteClient, attach};
use karyos_protocol::cnc::{RateAuthority, StreamKey};
use karyos_sys::guard::GuardState;
use karyos_sys::host_clock::host_monotonic_ns;
use karyos_sys::rate_limit::RatePolicy;

pub use crate::journal::UNKNOWN_OUTCOME;
use crate::journal::{Journal, JournalRecord, Kind, MAX_REASON};
/// Requests a one-command client may have pending.
const MAX_PENDING: usize = 4;

/// What a guard operation came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GuardAnswer {
    /// The driver answered with the guard's state after it.
    State {
        /// The operation id, as journalled and audited.
        operation: u64,
        /// The guard.
        guard: u64,
        /// Its state.
        state: GuardState,
    },
    /// The driver refused it with this control error code and detail.
    Refused {
        /// The operation id.
        operation: u64,
        /// The error code.
        code: u64,
        /// Its detail.
        detail: u64,
    },
    /// A reopen with no durable request record: not sent.
    JournalUnavailable,
    /// No configured driver has that directory.
    UnknownDriver,
    /// The agent could not attach to the driver: not sent.
    Unattached,
    /// Sent, and no answer came: it may or may not have taken effect.
    NoAnswer {
        /// The operation id.
        operation: u64,
    },
}

/// One guard command to make.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Command<'a> {
    pub(crate) dir: &'a Path,
    pub(crate) guard: u64,
    /// The transition, and the epoch it acts at.
    pub(crate) transition: Transition,
    pub(crate) operation: u64,
    /// The operator's uid: the peer that asked.
    pub(crate) operator: u32,
    /// The relay that carried the request, 0 for none (karyos#708).
    pub(crate) relay: u64,
    /// The reason, cut to [`MAX_REASON`] bytes once, by [`cut_reason`]:
    /// the digest, the driver and the journal all see the same bytes.
    pub(crate) reason: &'a [u8],
    pub(crate) timeout: Duration,
}

impl Command<'_> {
    fn record(&self, kind: Kind, now: u64) -> JournalRecord {
        let mut record = JournalRecord::new(kind, now);
        record.guard = self.guard;
        record.expected = self.transition.expected();
        record.operation = self.operation;
        record.operator = u64::from(self.operator);
        record.parameters = karyos_protocol::cnc::guard_parameters(
            self.guard,
            self.transition.expected(),
            self.operation,
            u64::from(self.operator),
            self.reason,
        );
        record.reason = self.reason.to_vec();
        record.relay = self.relay;
        record
    }
}

/// A guard command's transition (karyos#738).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transition {
    /// Close whatever the epoch.
    Close,
    /// Close only if open at this epoch: a previewed close, journalled as
    /// a close with the epoch in `expected`.
    CloseAt(u64),
    /// Reopen if closed at this epoch.
    Reopen(u64),
}

impl Transition {
    /// The epoch it acts at; 0 for a plain close.
    const fn expected(self) -> u64 {
        match self {
            Self::Close => 0,
            Self::CloseAt(epoch) | Self::Reopen(epoch) => epoch,
        }
    }
}

/// `reason` cut to the [`MAX_REASON`] bytes a journal record keeps.
pub(crate) fn cut_reason(reason: &[u8]) -> &[u8] {
    reason.get(..MAX_REASON).unwrap_or(reason)
}

/// Makes `command`, journalled in `journal` when there is one.
pub(crate) fn guard_command(journal: Option<&mut Journal>, command: &Command<'_>) -> GuardAnswer {
    let reopen = matches!(command.transition, Transition::Reopen(_));
    let (request, outcome) = if reopen {
        (Kind::ReopenRequest, Kind::ReopenOutcome)
    } else {
        (Kind::CloseRequest, Kind::CloseOutcome)
    };
    let mut journal = journal;
    let record = command.record(request, host_monotonic_ns());
    match (reopen, journal.as_deref_mut()) {
        // A reopen needs its record on disk before it is sent.
        (true, None) => return GuardAnswer::JournalUnavailable,
        (true, Some(journal)) => {
            if journal.append_durable(&record, record.time).is_err() {
                return GuardAnswer::JournalUnavailable;
            }
        }
        // A close goes ahead: a failed append is counted in the journal.
        (false, Some(journal)) => {
            let _ = journal.append(&record, record.time);
        }
        (false, None) => {}
    }
    let answer = send(command);
    if let Some(journal) = journal {
        let mut record = command.record(outcome, host_monotonic_ns());
        match answer {
            GuardAnswer::State { state, .. } => {
                record.word = karyos_sys::guard::encode(state).unwrap_or(0);
            }
            GuardAnswer::Refused { code, .. } => record.code = code,
            _ => record.code = UNKNOWN_OUTCOME,
        }
        let _ = journal.append(&record, record.time);
    }
    answer
}

/// Sends `command` as a one-command client and waits for its answer.
fn send(command: &Command<'_>) -> GuardAnswer {
    let Ok(mut client) = attach(command.dir, command.timeout, MAX_PENDING) else {
        return GuardAnswer::Unattached;
    };
    let operation = command.operation;
    let submitted = match command.transition {
        Transition::Close => client.guard_close(
            command.guard,
            operation,
            Some(command.operator),
            command.reason,
        ),
        Transition::CloseAt(expected) => client.guard_close_at(
            command.guard,
            expected,
            operation,
            Some(command.operator),
            command.reason,
        ),
        Transition::Reopen(expected) => client.guard_reopen(
            command.guard,
            expected,
            operation,
            Some(command.operator),
            command.reason,
        ),
    };
    let Ok(sequence) = submitted else {
        return GuardAnswer::Unattached;
    };
    match complete(&mut client, sequence, command.timeout) {
        Some(Outcome::GuardState { guard, state }) => GuardAnswer::State {
            operation,
            guard,
            state,
        },
        Some(Outcome::Refused { code, detail }) => GuardAnswer::Refused {
            operation,
            code: code.code(),
            detail,
        },
        _ => GuardAnswer::NoAnswer { operation },
    }
}

/// Polls `client` until request `sequence` completes or `timeout` passes.
fn complete(client: &mut RemoteClient, sequence: u64, timeout: Duration) -> Option<Outcome> {
    let start = Instant::now();
    loop {
        let mut found = None;
        let _ = client.poll(usize::MAX, |completion| {
            if completion.sequence == sequence {
                found = Some(completion.outcome);
            }
        });
        if found.is_some() {
            return found;
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// What a rate policy change came to (R-CORE-21, karyos#740).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateAnswer {
    /// The driver answered with the stream's policy version after it.
    State {
        /// The operation id, as journalled and audited.
        operation: u64,
        /// The stream.
        stream: StreamKey,
        /// Its policy version.
        version: u64,
    },
    /// The driver refused it with this control error code and detail
    /// (for `RateVersionMismatch`, the current version).
    Refused {
        /// The operation id.
        operation: u64,
        /// The error code.
        code: u64,
        /// Its detail.
        detail: u64,
    },
    /// An administrator's change with no durable request record: not
    /// sent.
    JournalUnavailable,
    /// No configured driver has that directory.
    UnknownDriver,
    /// The policy names a byte limit with a zero rate or burst: not sent.
    InvalidPolicy,
    /// The agent could not attach to the driver: not sent.
    Unattached,
    /// Sent, and no answer came: it may or may not have taken effect.
    NoAnswer {
        /// The operation id.
        operation: u64,
    },
}

/// A rate policy change as asked: the stream, the version it replaces,
/// the new policy and the authority it is asked under (R-CORE-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateChange {
    /// The guarded stream.
    pub stream: StreamKey,
    /// The policy version the change replaces.
    pub expected: u64,
    /// The new policy.
    pub policy: RatePolicy,
    /// The safety path or an administrator.
    pub authority: RateAuthority,
}

impl RateChange {
    /// A change of `stream` from version `expected` to `policy` under
    /// `authority`.
    #[must_use]
    pub const fn new(
        stream: StreamKey,
        expected: u64,
        policy: RatePolicy,
        authority: RateAuthority,
    ) -> Self {
        Self {
            stream,
            expected,
            policy,
            authority,
        }
    }
}

/// One rate policy change to make.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RateCommand<'a> {
    pub(crate) dir: &'a Path,
    pub(crate) stream: StreamKey,
    /// The policy version the change replaces.
    pub(crate) expected: u64,
    pub(crate) policy: RatePolicy,
    pub(crate) authority: RateAuthority,
    pub(crate) operation: u64,
    /// The operator's uid: the peer that asked.
    pub(crate) operator: u32,
    /// The relay that carried the request, 0 for none (karyos#708).
    pub(crate) relay: u64,
    /// The reason, cut by [`cut_reason`]. Journalled only: the command
    /// carries no reason, and its digest does not cover one.
    pub(crate) reason: &'a [u8],
    pub(crate) timeout: Duration,
}

/// The journal's word for `stream`: the stream id in the low half, the
/// session id in the high half, as the command's own digest has it.
#[must_use]
pub fn stream_word(stream: StreamKey) -> u64 {
    u64::from(stream.stream_id.cast_unsigned())
        | (u64::from(stream.session_id.cast_unsigned()) << 32)
}

impl RateCommand<'_> {
    fn record(&self, kind: Kind, now: u64) -> JournalRecord {
        let mut record = JournalRecord::new(kind, now);
        record.guard = stream_word(self.stream);
        record.expected = self.expected;
        record.operation = self.operation;
        record.operator = u64::from(self.operator);
        record.parameters = karyos_protocol::cnc::rate_parameters(
            self.stream,
            self.expected,
            self.authority,
            self.operation,
            u64::from(self.operator),
            &self.policy,
        );
        record.reason = self.reason.to_vec();
        record.relay = self.relay;
        record
    }
}

/// Makes `command`, journalled in `journal` when there is one: a request
/// record before it is sent, an outcome record (the version after it in
/// `word`, or the refusal's code) after.
///
/// The safety path only tightens, so it is never delayed by the journal,
/// as a guard close is not; an administrator's change may loosen, so its
/// request must be durable first, as a reopen's, or it is refused unsent.
pub(crate) fn rate_command(journal: Option<&mut Journal>, command: &RateCommand<'_>) -> RateAnswer {
    if command
        .policy
        .bytes
        .is_some_and(|bytes| bytes.per_second == 0 || bytes.burst == 0)
    {
        return RateAnswer::InvalidPolicy;
    }
    let mut journal = journal;
    let record = command.record(Kind::RateRequest, host_monotonic_ns());
    match (command.authority, journal.as_deref_mut()) {
        (RateAuthority::Administrator, None) => return RateAnswer::JournalUnavailable,
        (RateAuthority::Administrator, Some(journal)) => {
            if journal.append_durable(&record, record.time).is_err() {
                return RateAnswer::JournalUnavailable;
            }
        }
        (RateAuthority::Safety, Some(journal)) => {
            let _ = journal.append(&record, record.time);
        }
        (RateAuthority::Safety, None) => {}
    }
    let answer = send_rate(command);
    if let Some(journal) = journal {
        let mut record = command.record(Kind::RateOutcome, host_monotonic_ns());
        match answer {
            RateAnswer::State { version, .. } => record.word = version,
            RateAnswer::Refused { code, detail, .. } => {
                record.code = code;
                record.word = detail;
            }
            _ => record.code = UNKNOWN_OUTCOME,
        }
        let _ = journal.append(&record, record.time);
    }
    answer
}

/// Sends `command` as a one-command client and waits for its answer.
fn send_rate(command: &RateCommand<'_>) -> RateAnswer {
    let Ok(mut client) = attach(command.dir, command.timeout, MAX_PENDING) else {
        return RateAnswer::Unattached;
    };
    let operation = command.operation;
    let Ok(sequence) = client.rate_change(
        command.stream,
        command.expected,
        command.policy,
        command.authority,
        operation,
        Some(command.operator),
    ) else {
        return RateAnswer::Unattached;
    };
    match complete(&mut client, sequence, command.timeout) {
        Some(Outcome::RateState { stream, version }) => RateAnswer::State {
            operation,
            stream,
            version,
        },
        Some(Outcome::Refused { code, detail }) => RateAnswer::Refused {
            operation,
            code: code.code(),
            detail,
        },
        _ => RateAnswer::NoAnswer { operation },
    }
}
