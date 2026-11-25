// SPDX-License-Identifier: Apache-2.0

//! A product service's records in the operations journal (R-CORE-42;
//! karyos#773): the contract.
//!
//! - **Who.** A uid given the role `service` (or an administrator), on
//!   the local socket or through a relay, appends records; every other
//!   role is answered `forbidden`. The journal records the requester's
//!   operator id and the relay apart, as for every operation.
//! - **What.** A request record before the product sends a command and an
//!   outcome record after it, under one operation id the product chose:
//!   `journal-append request|outcome durable|ordinary OPID SERVICE COMMAND
//!   VALUE CORRELATION [REASON]`. `SERVICE` names the product service and
//!   `COMMAND` its command (at most [`MAX_NAME`] bytes each, of letters,
//!   digits, `.`, `_`, `-`, `@` and `:`); `VALUE` is the command's
//!   parameters digest (16 hex digits) for a request and the product's
//!   outcome code (a decimal number) for an outcome; `CORRELATION` is the
//!   product's reference to its own log entry (at most
//!   [`MAX_CORRELATION`] printable bytes without a space), which the
//!   history serves back as the record's `evidence`; `REASON` is the rest
//!   of the line. The agent checks the form only: no core code interprets
//!   a product's command, its digest, its code or its correlation, and it
//!   does not pair requests with outcomes; the history serves both under
//!   the operation id, and the product correlates them.
//! - **Durable or ordinary.** `durable` answers only once the record is
//!   durable, and a record that cannot be made durable is refused
//!   (`journal unavailable`): a fail-closed (risk-increasing) command is
//!   then never sent unrecorded. `ordinary` appends without waiting for
//!   durability, for a command that goes ahead when the journal cannot
//!   record it (a safety-reducing one); its answer says it is not durable
//!   yet.
//! - **Import after an outage.** A journal that could not record (it
//!   refused an append, or could not be opened) records an unknown
//!   interval at the agent's next start, which the view shows as the
//!   journal's gap with its alert until an administrator acknowledges it
//!   (`gap-ack`). The product then imports the records it kept, by
//!   operation id: `journal-import INTERVAL TIME request|outcome OPID
//!   SERVICE COMMAND VALUE CORRELATION [REASON]`, `INTERVAL` the unknown
//!   interval's position (an unknown interval the journal holds, refused
//!   otherwise) and `TIME` the product's own time of the original record,
//!   kept as given. An import is durable, and is its own record kind, so
//!   an imported record never reads as one made at the time. Importing
//!   does not close the gap: the interval stays visible until an
//!   administrator acknowledges it, having seen the imports.
//! - **Records.** [`Kind::ProductRequest`] and [`Kind::ProductOutcome`],
//!   and [`Kind::ProductRequestImported`] and
//!   [`Kind::ProductOutcomeImported`]; the history (R-CORE-14) serves them
//!   with their fields: `operation`, `operator`, `relay`, `target` (the
//!   service), `command`, `parameters` (a request's digest), `code` (an
//!   outcome's), `evidence` (the correlation), and, for an import,
//!   `expected` (the interval) and `word` (the product's time).

use crate::agent::Requester;
use crate::journal::{JournalRecord, Kind};

/// The longest service or command name, in bytes.
pub const MAX_NAME: usize = 32;
/// The longest correlation, in bytes.
pub const MAX_CORRELATION: usize = 64;

/// A record's phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    /// Before the command is sent.
    Request,
    /// After its answer.
    Outcome,
}

/// Where an imported record belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Import {
    /// The unknown interval's position.
    pub interval: u64,
    /// The product's own time of the original record, as given.
    pub time: u64,
}

/// One record a product service asks the journal to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProductAppend<'a> {
    /// Request or outcome.
    pub phase: Phase,
    /// Whether the answer waits for the record to be durable; an import
    /// always does.
    pub durable: bool,
    /// The operation id.
    pub operation: u64,
    /// The service's name.
    pub service: &'a str,
    /// The command's name.
    pub command: &'a str,
    /// A request's parameters digest, or an outcome's code.
    pub value: u64,
    /// The product's reference to its log entry.
    pub correlation: &'a str,
    /// The reason, possibly empty.
    pub reason: &'a str,
    /// Set for an import after an outage.
    pub import: Option<Import>,
}

impl ProductAppend<'_> {
    /// The record's kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match (self.phase, self.import.is_some()) {
            (Phase::Request, false) => Kind::ProductRequest,
            (Phase::Outcome, false) => Kind::ProductOutcome,
            (Phase::Request, true) => Kind::ProductRequestImported,
            (Phase::Outcome, true) => Kind::ProductOutcomeImported,
        }
    }

    /// Whether its answer waits for durability.
    #[must_use]
    pub const fn waits(&self) -> bool {
        self.durable || self.import.is_some()
    }

    /// The journal record for `requester` at host time `now`.
    #[must_use]
    pub fn record(&self, requester: Requester, now: u64) -> JournalRecord {
        let mut record = JournalRecord::new(self.kind(), now);
        record.operation = self.operation;
        record.operator = u64::from(requester.operator);
        record.relay = requester.relay;
        match self.phase {
            Phase::Request => record.parameters = self.value,
            Phase::Outcome => record.code = self.value,
        }
        record.target = self.service.as_bytes().to_vec();
        record.command = self.command.as_bytes().to_vec();
        record.evidence = self.correlation.as_bytes().to_vec();
        record.reason = self.reason.as_bytes().to_vec();
        if let Some(import) = self.import {
            record.expected = import.interval;
            record.word = import.time;
        }
        record
    }
}

/// How the agent answered a product's append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProductAnswer {
    /// Recorded at `position` of `recording`; `durable` when the answer
    /// waited for it.
    Journalled {
        /// The journal recording.
        recording: u64,
        /// The record's position.
        position: u64,
        /// Whether it is durable.
        durable: bool,
    },
    /// The journal could not record it (none configured, unavailable, or
    /// a durable append that could not be made durable): nothing is
    /// recorded, and a fail-closed command must not be sent.
    JournalUnavailable,
    /// An import names a position that is no unknown interval the
    /// journal holds.
    NotAnInterval {
        /// The position named.
        position: u64,
    },
}

/// Parses the arguments of `journal-append` (`import` `None`) or of
/// `journal-import` (the interval and time first); `None` when they do not
/// have the contract's form.
#[must_use]
pub fn parse(arguments: &str, import: bool) -> Option<ProductAppend<'_>> {
    let mut rest = arguments;
    let mut word = || -> Option<&str> {
        let (word, after) = rest.split_once(' ').unwrap_or((rest, ""));
        rest = after;
        (!word.is_empty()).then_some(word)
    };
    let number = |word: &str| -> Option<u64> {
        word.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| word.parse().ok())
            .flatten()
    };
    let import = if import {
        let interval = number(word()?)?;
        let time = number(word()?)?;
        Some(Import { interval, time })
    } else {
        None
    };
    let phase = match word()? {
        "request" => Phase::Request,
        "outcome" => Phase::Outcome,
        _ => return None,
    };
    let durable = if import.is_some() {
        true
    } else {
        match word()? {
            "durable" => true,
            "ordinary" => false,
            _ => return None,
        }
    };
    let operation = number(word()?)?;
    let name = |word: &str| -> bool {
        (1..=MAX_NAME).contains(&word.len())
            && word
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-@:".contains(&byte))
    };
    let service = word().filter(|word| name(word))?;
    let command = word().filter(|word| name(word))?;
    let value = word()?;
    let value = match phase {
        Phase::Request if value.len() == 16 && value.bytes().all(|b| b.is_ascii_hexdigit()) => {
            u64::from_str_radix(value, 16).ok()?
        }
        Phase::Request => return None,
        Phase::Outcome => number(value)?,
    };
    let correlation = word().filter(|word| {
        (1..=MAX_CORRELATION).contains(&word.len()) && word.bytes().all(|b| b.is_ascii_graphic())
    })?;
    Some(ProductAppend {
        phase,
        durable,
        operation,
        service,
        command,
        value,
        correlation,
        reason: rest,
        import,
    })
}

#[cfg(test)]
mod tests;
