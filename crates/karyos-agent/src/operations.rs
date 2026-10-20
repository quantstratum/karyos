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

use std::path::Path;
use std::time::{Duration, Instant};

use karyos_client::Outcome;
use karyos_client::ipc::{RemoteClient, attach};
use karyos_sys::guard::GuardState;
use karyos_sys::host_clock::host_monotonic_ns;

use crate::journal::{Journal, JournalRecord, Kind, MAX_REASON};

/// An outcome record's code when the driver's answer never came.
pub const UNKNOWN_OUTCOME: u64 = u64::MAX;
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
    /// `Some(expected)` for a reopen.
    pub(crate) reopen: Option<u64>,
    pub(crate) operation: u64,
    /// The operator's uid: the peer that asked.
    pub(crate) operator: u32,
    /// The reason, cut to [`MAX_REASON`] bytes once, by [`cut_reason`]:
    /// the digest, the driver and the journal all see the same bytes.
    pub(crate) reason: &'a [u8],
    pub(crate) timeout: Duration,
}

impl Command<'_> {
    fn record(&self, kind: Kind, now: u64) -> JournalRecord {
        let mut record = JournalRecord::new(kind, now);
        record.guard = self.guard;
        record.expected = self.reopen.unwrap_or(0);
        record.operation = self.operation;
        record.operator = u64::from(self.operator);
        record.parameters = karyos_protocol::cnc::guard_parameters(
            self.guard,
            self.reopen.unwrap_or(0),
            self.operation,
            u64::from(self.operator),
            self.reason,
        );
        record.reason = self.reason.to_vec();
        record
    }
}

/// `reason` cut to the [`MAX_REASON`] bytes a journal record keeps.
pub(crate) fn cut_reason(reason: &[u8]) -> &[u8] {
    reason.get(..MAX_REASON).unwrap_or(reason)
}

/// Makes `command`, journalled in `journal` when there is one.
pub(crate) fn guard_command(journal: Option<&mut Journal>, command: &Command<'_>) -> GuardAnswer {
    let (request, outcome) = match command.reopen {
        None => (Kind::CloseRequest, Kind::CloseOutcome),
        Some(_) => (Kind::ReopenRequest, Kind::ReopenOutcome),
    };
    let mut journal = journal;
    let record = command.record(request, host_monotonic_ns());
    match (command.reopen, journal.as_deref_mut()) {
        // A reopen needs its record on disk before it is sent.
        (Some(_), None) => return GuardAnswer::JournalUnavailable,
        (Some(_), Some(journal)) => {
            if journal.append_durable(&record, record.time).is_err() {
                return GuardAnswer::JournalUnavailable;
            }
        }
        // A close goes ahead: a failed append is counted in the journal.
        (None, Some(journal)) => {
            let _ = journal.append(&record, record.time);
        }
        (None, None) => {}
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
    let submitted = match command.reopen {
        None => client.guard_close(
            command.guard,
            operation,
            Some(command.operator),
            command.reason,
        ),
        Some(expected) => client.guard_reopen(
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
