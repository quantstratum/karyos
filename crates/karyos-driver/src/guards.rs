// SPDX-License-Identifier: Apache-2.0

//! Local guards (`quantstratum-docs: karyos/design/guards-and-abort.md`,
//! P2.10 batch 1): the registry of named guards, their transitions on the
//! control path, and the interim audit ring (G9 interim).
//!
//! - **Words.** Every guard's word (`karyos_sys::guard`) lives in one
//!   array of `max_guards` words, the guard region, and only the driver
//!   writes it, with Release. In IPC mode (Linux) the array is a
//!   driver-only region every guarded grant carries read-only
//!   (`quantstratum-docs: karyos/design/guards-and-abort.md`, "The binding
//!   across processes"); in process it is on the heap. A guard's word
//!   index is its position at `add`: guards are never removed, so an
//!   index is never reused while the driver lives, and the header of a
//!   live or late outcome ring never names another guard.
//! - **Authorization (G1).** A transition is authorized by the caller's
//!   process credentials on the control path: the in-process caller of
//!   the embedded API, or an admitted IPC client, whose uid admission
//!   proved equal to the driver's (`admission.rs`, `SO_PEERCRED` and the
//!   pidfd's pid). `NotAuthorized` stays reserved for a per-guard policy.
//! - **Audit (G9 interim).** Every transition, refusals included, appends
//!   one record before its response or return. Capture never delays or
//!   refuses a close: a full ring overwrites its oldest record and counts
//!   the overwritten records.
//! - **Tools (M4, `quantstratum-docs:
//!   karyos/design/management-agent-gap-analysis.md`).** Each record is
//!   also appended to the guard audit ring of `karyos_sys::diag`, a
//!   driver-only region a tool receives read-only, with the host
//!   `CLOCK_MONOTONIC` time beside the driver clock's. Each guard's word is
//!   a gauge labelled with the guard's name, participant kind
//!   `KIND_GUARD` and the guard id in `key2`, which `GuardCells` brings
//!   in line at every conductor duty cycle.

use std::collections::VecDeque;
use std::sync::Arc;

use crate::shared_words::Words;
use karyos_protocol::cnc::ErrorCode;
use karyos_sys::counters::{Counter, CounterKeys, KIND_GUARD};
use karyos_sys::diag::{GuardAudit, GuardAuditRecord};
use karyos_sys::guard::{self, Closed, GuardError, GuardState};

use crate::counters::{DriverCounters, Event, TYPE_GAUGE};
use crate::error::DriverError;

/// The longest guard name, in bytes.
pub const MAX_GUARD_NAME: usize = 64;

/// Names a guard of one driver. Guard ids start at 1 and are never reused
/// within the driver; the id is what `GuardClose` and `GuardReopen` carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardHandle {
    pub(crate) driver: u64,
    pub(crate) guard: u64,
}

impl GuardHandle {
    /// The guard id, as the control commands carry it.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.guard
    }
}

/// Who asked for a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requester {
    /// The in-process caller of the embedded API.
    InProcess,
    /// An admitted client, by client id.
    Client(u64),
    /// An operator, by uid, acting through an admitted client, such as the
    /// management agent (M10): the client says whom it acts for.
    Operator {
        /// The client id.
        client: u64,
        /// The operator's uid, as the client gave it.
        uid: u64,
    },
}

/// What a transition did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditOutcome {
    /// The guard closed at the word after.
    Closed,
    /// The guard was already closed: nothing changed.
    AlreadyClosed,
    /// The guard reopened at the word after.
    Reopened,
    /// The transition was refused with this code.
    Refused(ErrorCode),
    /// A guarded stream's rate policy changed (R-CORE-21): the record's
    /// `before` and `after` are the policy versions.
    RateChanged {
        /// Who changed it.
        authority: RateAuthority,
    },
    /// A rate policy change named the policy in force: nothing changed,
    /// and `before` equals `after` (R-CORE-21).
    RateUnchanged {
        /// Who asked.
        authority: RateAuthority,
    },
}

/// One record of the audit ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRecord {
    /// The driver's monotonic clock at the transition.
    pub time: u64,
    /// The guard id the requester named, known or not.
    pub guard: u64,
    /// The guard word before; 0 for an unknown guard.
    pub before: u64,
    /// The guard word after; equal to `before` unless it changed.
    pub after: u64,
    /// The requester's operation id (Audit A).
    pub operation: u64,
    /// Who asked.
    pub requester: Requester,
    /// What happened.
    pub outcome: AuditOutcome,
    /// The command's parameters digest
    /// (`karyos_protocol::cnc::guard_parameters`); 0 when none was given.
    pub parameters: u64,
}

/// A snapshot of the audit ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
    /// The retained records, oldest first.
    pub records: Vec<AuditRecord>,
    /// Records overwritten because the ring was full.
    pub overwritten: u64,
}

#[derive(Debug)]
struct Entry {
    name: String,
    id: u64,
    /// Its word's index in the guard words, never reused.
    index: usize,
    /// The epoch and driver clock time of the guard's latest closes,
    /// oldest first, at most [`CLOSE_HISTORY`].
    closes: VecDeque<(u64, u64)>,
}

/// Closes whose time a guard keeps for the effective-close
/// acknowledgement's overdue check.
pub const CLOSE_HISTORY: usize = 8;

/// The scope a rate limit applies to (`quantstratum-docs:
/// karyos/design/guards-and-abort.md`, Rate limits). Phase 2 supports the
/// publication scope only (GC-5); the others are refused at configuration
/// until their designs exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateScope {
    /// One publication's messages.
    Publication,
    /// A strategy's publications (not supported yet).
    Strategy,
    /// An account's publications (not supported yet).
    Account,
    /// A destination's traffic (not supported yet).
    Destination,
}

impl core::fmt::Display for RateScope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Publication => "publication",
            Self::Strategy => "strategy",
            Self::Account => "account",
            Self::Destination => "destination",
        })
    }
}

/// A guarded stream's rate limit: its scope, its token buckets and its
/// control reserve. Built with [`GuardRate::publication`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuardRate {
    /// What the limit applies to.
    pub scope: RateScope,
    /// The buckets' rates and bursts.
    pub policy: karyos_sys::rate_limit::RatePolicy,
    /// The least message rate and burst the publisher needs for its
    /// cancellations and resolutions (R-CORE-21): no tightening under
    /// [`RateAuthority::Safety`] goes below it. `None`: no floor.
    pub reserve: Option<karyos_sys::rate_limit::Rate>,
}

impl GuardRate {
    /// `policy` over the publication, with no reserve.
    #[must_use]
    pub const fn publication(policy: karyos_sys::rate_limit::RatePolicy) -> Self {
        Self::scoped(RateScope::Publication, policy)
    }

    /// `policy` over `scope`, with no reserve; only
    /// [`RateScope::Publication`] is supported yet.
    #[must_use]
    pub const fn scoped(scope: RateScope, policy: karyos_sys::rate_limit::RatePolicy) -> Self {
        Self {
            scope,
            policy,
            reserve: None,
        }
    }

    /// The same, with `reserve` as its control reserve.
    #[must_use]
    pub const fn with_reserve(mut self, reserve: karyos_sys::rate_limit::Rate) -> Self {
        self.reserve = Some(reserve);
        self
    }
}

/// Who changes a guarded stream's rate policy (R-CORE-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RateAuthority {
    /// The safety path (operators, risk officers): only a proven tightening
    /// that keeps the reserve.
    Safety,
    /// An administrator: any valid policy.
    Administrator,
}

/// Why one lane of an aggregate refused a rate policy change (R-CORE-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LaneRefusal {
    /// The change's own refusal on that lane.
    #[error(transparent)]
    Change(RateChangeError),
    /// The policy that lane refuses.
    #[error(transparent)]
    Invalid(karyos_sys::rate_limit::RatePolicyError),
}

impl LaneRefusal {
    /// The refusal of `error`, a rate change's, if it is one.
    pub(crate) fn of(error: &DriverError) -> Option<Self> {
        match error {
            DriverError::RateChange(change) => Some(Self::Change(*change)),
            DriverError::InvalidRatePolicy(invalid) => Some(Self::Invalid(*invalid)),
            _ => None,
        }
    }

    /// The error it stands for, without its lane.
    pub(crate) const fn error(self) -> DriverError {
        match self {
            Self::Change(change) => DriverError::RateChange(change),
            Self::Invalid(invalid) => DriverError::InvalidRatePolicy(invalid),
        }
    }
}

/// Why a rate policy change was refused (R-CORE-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RateChangeError {
    /// The stream's policy is at another version than the one expected.
    #[error("the rate policy is at version {current}, not {expected}")]
    VersionMismatch {
        /// The version the caller expected.
        expected: u64,
        /// The stream's version.
        current: u64,
    },
    /// The safety path takes only a provable tightening.
    #[error("the safety path takes only a tightening of the rate policy")]
    NotATightening,
    /// The policy goes below the stream's control reserve.
    #[error("the rate policy goes below the stream's control reserve")]
    ReserveCrossed,
    /// The stream has no rate policy to change.
    #[error("the stream has no rate policy")]
    NoRate,
}

/// The guard registry and audit ring of one driver.
#[derive(Debug)]
pub(crate) struct Guards {
    driver: u64,
    max: usize,
    /// Every guard's word, `max` of them: the guard region.
    words: Arc<Words>,
    entries: Vec<Entry>,
    next: u64,
    audit: VecDeque<AuditRecord>,
    audit_capacity: usize,
    overwritten: u64,
    /// The tools' copy of every record (M4).
    ring: GuardAudit,
    /// Records the ring took overwriting an older one, or dropped once its
    /// sequences were exhausted.
    ring_overwritten: u64,
    ring_dropped: u64,
}

impl Guards {
    /// The registry of at most `max` guards over `words`, which holds at
    /// least `max` words, zeroed.
    pub(crate) fn new(
        driver: u64,
        max: usize,
        words: Words,
        audit_capacity: usize,
        ring: GuardAudit,
    ) -> Self {
        Self {
            driver,
            max: max.min(words.words().len()),
            words: Arc::new(words),
            entries: Vec::with_capacity(max),
            next: 1,
            audit: VecDeque::with_capacity(audit_capacity),
            audit_capacity,
            overwritten: 0,
            ring,
            ring_overwritten: 0,
            ring_dropped: 0,
        }
    }

    /// The guard audit ring's shared region, for tools; `None` on the
    /// heap.
    #[cfg(target_os = "linux")]
    pub(crate) fn region(&self) -> Option<&karyos_sys::ipc::Region> {
        self.ring.region()
    }

    /// A reader of the tools' guard audit ring.
    pub(crate) fn ring_reader(&self) -> karyos_sys::diag::GuardAuditReader {
        self.ring.reader()
    }

    /// Each guard's id, in registry order.
    pub(crate) fn ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries.iter().map(|entry| entry.id)
    }

    /// Each guard's id, name and current word.
    fn words(&self) -> impl Iterator<Item = (u64, &str, u64)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.id, entry.name.as_str(), self.raw(entry)))
    }

    /// Adds a guard, created closed at epoch 1.
    pub(crate) fn add(&mut self, name: &str) -> Result<GuardHandle, DriverError> {
        if name.is_empty() || name.len() > MAX_GUARD_NAME {
            return Err(DriverError::InvalidConfig);
        }
        // The guard's word gauge is labelled with its name beside its
        // acknowledgement group (M4b), which readers pick by label: a name
        // equal to one of the group's labels would join the group.
        if crate::guard_ack::is_ack_label(name) {
            return Err(DriverError::InvalidConfig);
        }
        if self.entries.iter().any(|entry| entry.name == name) {
            return Err(DriverError::DuplicateGuard);
        }
        if self.entries.len() >= self.max {
            return Err(DriverError::TooManyGuards);
        }
        let id = self.next;
        let next = id.checked_add(1).ok_or(DriverError::GuardIdsExhausted)?;
        // The next unused word: guards are never removed, so an index is
        // never reused.
        let index = self.entries.len();
        let Some(cell) = self.words.words().get(index) else {
            return Err(DriverError::TooManyGuards);
        };
        cell.store(guard::created(), karyos_sys::sync::Ordering::Release);
        self.entries.push(Entry {
            name: name.to_owned(),
            id,
            index,
            closes: VecDeque::with_capacity(CLOSE_HISTORY),
        });
        self.next = next;
        Ok(GuardHandle {
            driver: self.driver,
            guard: id,
        })
    }

    /// The handle of the guard named `name`.
    pub(crate) fn find(&self, name: &str) -> Option<GuardHandle> {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| GuardHandle {
                driver: self.driver,
                guard: entry.id,
            })
    }

    fn entry(&self, id: u64) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    /// The handle of guard `id`, for a control command.
    pub(crate) fn by_id(&self, id: u64) -> Option<GuardHandle> {
        self.entry(id).map(|entry| GuardHandle {
            driver: self.driver,
            guard: entry.id,
        })
    }

    /// The driver clock time of the guard's close at `epoch`; for a close
    /// older than the [`CLOSE_HISTORY`] kept, the time of the oldest kept
    /// close after it, which happened no earlier (so an overdue check can
    /// only come late, never early). `None` if the guard never closed at or
    /// after `epoch`.
    pub(crate) fn closed_since(
        &self,
        handle: GuardHandle,
        epoch: u64,
    ) -> Result<Option<u64>, DriverError> {
        let entry = self.check(handle)?;
        Ok(entry
            .closes
            .iter()
            .find(|&&(closed, _)| closed >= epoch)
            .map(|&(_, time)| time))
    }

    fn check(&self, handle: GuardHandle) -> Result<&Entry, DriverError> {
        if handle.driver != self.driver {
            return Err(DriverError::UnknownGuard);
        }
        self.entry(handle.guard).ok_or(DriverError::UnknownGuard)
    }

    /// Records a rate policy change of a stream guarded by `handle`
    /// (R-CORE-21): from version `before` to `after` under `authority`, or
    /// refused with `error`. `parameters` is the authority's code (1
    /// safety, 2 administrator).
    pub(crate) fn audit_rate(
        &mut self,
        handle: GuardHandle,
        (before, after): (u64, u64),
        (operation, requester, authority): (u64, Requester, RateAuthority),
        result: Result<(), &DriverError>,
        time: u64,
    ) {
        let parameters = match authority {
            RateAuthority::Safety => 1,
            RateAuthority::Administrator => 2,
        };
        let outcome = match result {
            Ok(()) if before == after => AuditOutcome::RateUnchanged { authority },
            Ok(()) => AuditOutcome::RateChanged { authority },
            Err(error) => refused(error),
        };
        self.record(
            time,
            handle.guard,
            before,
            after,
            (operation, requester, parameters),
            outcome,
        );
    }

    /// The guard words and the guard's index in them, for the handles,
    /// gates and outcome rings bound to it.
    pub(crate) fn view(&self, handle: GuardHandle) -> Result<(Arc<Words>, usize), DriverError> {
        Ok((Arc::clone(&self.words), self.check(handle)?.index))
    }

    /// The guard words, to grant (`GuardRegion`).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn guard_words(&self) -> &Arc<Words> {
        &self.words
    }

    /// The guard's state.
    pub(crate) fn state(&self, handle: GuardHandle) -> Result<GuardState, DriverError> {
        let entry = self.check(handle)?;
        Ok(guard::load_in(&*self.words, entry.index)?)
    }

    fn raw(&self, entry: &Entry) -> u64 {
        self.cell(entry)
            .map_or(0, |cell| cell.load(karyos_sys::sync::Ordering::Relaxed))
    }

    /// The guard's word.
    fn cell(&self, entry: &Entry) -> Option<&karyos_sys::sync::AtomicU64> {
        self.words.words().get(entry.index)
    }

    /// Closes a guard and records the transition.
    pub(crate) fn close(
        &mut self,
        handle: GuardHandle,
        operation: u64,
        requester: Requester,
        parameters: u64,
        time: u64,
    ) -> Result<Closed, DriverError> {
        let checked = self.check(handle).map(|entry| {
            let before = self.raw(entry);
            let result = self
                .cell(entry)
                .ok_or(GuardError::Corrupt { word: before })
                .and_then(guard::close);
            (before, self.raw(entry), result)
        });
        let (before, after, result) = match checked {
            Ok(found) => found,
            Err(error) => {
                let id = handle.guard;
                let asked = (operation, requester, parameters);
                self.record(time, id, 0, 0, asked, refused(&error));
                return Err(error);
            }
        };
        if let Ok(Closed::Now { epoch }) = result
            && let Some(entry) = self
                .entries
                .iter_mut()
                .find(|entry| entry.id == handle.guard)
        {
            if entry.closes.len() >= CLOSE_HISTORY {
                let _ = entry.closes.pop_front();
            }
            entry.closes.push_back((epoch, time));
        }
        let outcome = match &result {
            Ok(Closed::Now { .. }) => AuditOutcome::Closed,
            Ok(Closed::Already { .. }) => AuditOutcome::AlreadyClosed,
            Err(error) => refused(&DriverError::Guard(*error)),
        };
        self.record(
            time,
            handle.guard,
            before,
            after,
            (operation, requester, parameters),
            outcome,
        );
        Ok(result?)
    }

    /// Reopens a guard closed at `expected` and records the transition.
    pub(crate) fn reopen(
        &mut self,
        handle: GuardHandle,
        expected: u64,
        operation: u64,
        requester: Requester,
        parameters: u64,
        time: u64,
    ) -> Result<u64, DriverError> {
        let checked = self.check(handle).map(|entry| {
            let before = self.raw(entry);
            let result = self
                .cell(entry)
                .ok_or(GuardError::Corrupt { word: before })
                .and_then(|cell| guard::reopen(cell, expected));
            (before, self.raw(entry), result)
        });
        let (before, after, result) = match checked {
            Ok(found) => found,
            Err(error) => {
                let id = handle.guard;
                let asked = (operation, requester, parameters);
                self.record(time, id, 0, 0, asked, refused(&error));
                return Err(error);
            }
        };
        let outcome = match &result {
            Ok(_) => AuditOutcome::Reopened,
            Err(error) => refused(&DriverError::Guard(*error)),
        };
        self.record(
            time,
            handle.guard,
            before,
            after,
            (operation, requester, parameters),
            outcome,
        );
        Ok(result?)
    }

    /// Records a transition; `asked` is the operation id, the requester and
    /// the parameters digest.
    fn record(
        &mut self,
        time: u64,
        guard: u64,
        before: u64,
        after: u64,
        asked: (u64, Requester, u64),
        outcome: AuditOutcome,
    ) {
        let (operation, requester, parameters) = asked;
        let (requester_kind, requester_id, operator) = match requester {
            Requester::InProcess => (0, 0, 0),
            Requester::Client(client) => (1, client, 0),
            Requester::Operator { client, uid } => (2, client, uid),
        };
        let (outcome_code, refusal) = match outcome {
            AuditOutcome::Closed => (1, 0),
            AuditOutcome::AlreadyClosed => (2, 0),
            AuditOutcome::Reopened => (3, 0),
            AuditOutcome::Refused(code) => (4, u16::try_from(code.code()).unwrap_or(u16::MAX)),
            AuditOutcome::RateChanged { .. } => (5, 0),
            AuditOutcome::RateUnchanged { .. } => (6, 0),
        };
        // A ring whose sequences are exhausted keeps what it has and counts
        // the record dropped; the driver's own audit below still records.
        let appended = self.ring.record(&GuardAuditRecord {
            time: karyos_sys::host_clock::host_monotonic_ns(),
            driver_time: time,
            guard,
            before,
            after,
            operation,
            requester_kind,
            requester: requester_id,
            outcome: outcome_code,
            refusal,
            operator,
            parameters,
        });
        let count = match appended {
            Some(appended) if appended.overwrote.is_some() => Some(&mut self.ring_overwritten),
            Some(_) => None,
            None => Some(&mut self.ring_dropped),
        };
        // Checked, never wrapped (SPEC.md section 14): at its end the
        // count keeps its value.
        if let Some(count) = count
            && let Some(next) = count.checked_add(1)
        {
            *count = next;
        }
        if self.audit_capacity == 0 {
            // Checked, never wrapped (SPEC.md section 14): at its end the
            // count keeps its value.
            if let Some(next) = self.overwritten.checked_add(1) {
                self.overwritten = next;
            }
            return;
        }
        if self.audit.len() >= self.audit_capacity {
            let _ = self.audit.pop_front();
            // Checked, never wrapped (SPEC.md section 14): at its end the
            // count keeps its value.
            if let Some(next) = self.overwritten.checked_add(1) {
                self.overwritten = next;
            }
        }
        self.audit.push_back(AuditRecord {
            time,
            guard,
            before,
            after,
            operation,
            requester,
            outcome,
            parameters,
        });
    }

    /// Tests: overwrites a guard's word, to reach states such as the last
    /// epoch or a corrupt word.
    #[cfg(test)]
    pub(crate) fn set_word(&self, handle: GuardHandle, word: u64) {
        if let Ok(entry) = self.check(handle)
            && let Some(cell) = self.cell(entry)
        {
            cell.store(word, karyos_sys::sync::Ordering::Release);
        }
    }

    /// A snapshot of the audit ring.
    pub(crate) fn audit(&self) -> Audit {
        Audit {
            records: self.audit.iter().copied().collect(),
            overwritten: self.overwritten,
        }
    }
}

/// Each guard's word as a gauge for tools (M4): labelled with the guard's
/// name, keyed by participant kind [`KIND_GUARD`] and the guard id. Guards
/// are never removed, so a gauge lives as long as the driver. One the
/// region has no room for is counted once in `counters unavailable` and
/// retried every [`GUARD_CELL_RETRY`] syncs, so a full region is not
/// scanned at every duty cycle.
#[derive(Debug, Default)]
pub(crate) struct GuardCells {
    /// Per guard in registry order: its id, its gauge, the word last
    /// stored, and whether a refused allocation was counted.
    cells: Vec<(u64, Option<Counter>, u64, bool)>,
    /// Syncs left before refused allocations are tried again.
    retry_in: u32,
    /// The ring's overwritten and dropped records already counted.
    ring_counted: (u64, u64),
}

impl Guards {
    /// The guard audit ring's records overwritten and dropped so far.
    pub(crate) fn ring_losses(&self) -> (u64, u64) {
        (self.ring_overwritten, self.ring_dropped)
    }
}

/// Syncs between two retries of a refused guard gauge allocation.
pub(crate) const GUARD_CELL_RETRY: u32 = 1024;

impl GuardCells {
    /// Brings the gauges in line with `guards` (control path, each
    /// conductor duty cycle): a new guard gets its gauge, a changed word
    /// is stored.
    pub(crate) fn sync(&mut self, guards: &Guards, counters: &mut DriverCounters) {
        // A refused allocation is retried only when the countdown ends.
        let retry = match self.retry_in.checked_sub(1) {
            Some(left) => {
                self.retry_in = left;
                false
            }
            None => true,
        };
        let mut refused = false;
        for (index, (id, name, word)) in guards.words().enumerate() {
            if self.cells.get(index).is_none() {
                self.cells.push((id, None, 0, false));
            }
            let Some((_, cell, stored, counted)) = self.cells.get_mut(index) else {
                continue;
            };
            if cell.is_none() && (retry || !*counted) {
                let keys = CounterKeys {
                    kind: KIND_GUARD,
                    participant: id,
                    ..CounterKeys::DRIVER
                };
                *cell = if *counted {
                    counters.retry_keyed(TYPE_GAUGE, name, keys)
                } else {
                    counters.allocate_keyed(TYPE_GAUGE, name, keys)
                };
                *counted = true;
                *stored = 0;
                refused |= cell.is_none();
            }
            if let Some(cell) = cell
                && *stored != word
            {
                cell.set(word);
                *stored = word;
            }
        }
        if refused {
            self.retry_in = GUARD_CELL_RETRY;
        }
        // The ring's losses since the last sync, into the driver's events.
        let (overwritten, dropped) = guards.ring_losses();
        let (counted_overwritten, counted_dropped) = self.ring_counted;
        if let Some(delta) = overwritten.checked_sub(counted_overwritten) {
            counters.add(Event::GuardAuditOverwritten, delta);
        }
        if let Some(delta) = dropped.checked_sub(counted_dropped) {
            counters.add(Event::GuardAuditDropped, delta);
        }
        self.ring_counted = (overwritten, dropped);
    }
}

/// The control code of a refused transition.
pub(crate) fn refused(error: &DriverError) -> AuditOutcome {
    AuditOutcome::Refused(error_code(error))
}

/// The `ErrorCode` a control command answers for a guard error.
pub(crate) fn error_code(error: &DriverError) -> ErrorCode {
    match error {
        DriverError::Guard(GuardError::NotClosedAt { .. }) => ErrorCode::GuardNotClosedAt,
        DriverError::Guard(GuardError::Exhausted) => ErrorCode::GuardExhausted,
        DriverError::RateChange(RateChangeError::VersionMismatch { .. }) => {
            ErrorCode::RateVersionMismatch
        }
        DriverError::RateChange(RateChangeError::NotATightening) => ErrorCode::RateNotATightening,
        DriverError::RateChange(RateChangeError::ReserveCrossed) => ErrorCode::RateReserveCrossed,
        DriverError::RateChange(RateChangeError::NoRate) => ErrorCode::RateNotSet,
        DriverError::InvalidRatePolicy(_) => ErrorCode::RateInvalidPolicy,
        // A lane's refusal has its own code.
        DriverError::RateChangeOnLane { refusal, .. } => error_code(&refusal.error()),
        // A lane of the call that is gone or retiring names no guard.
        DriverError::UnknownStream { .. } | DriverError::StreamRetiring { .. } => {
            ErrorCode::UnknownStream
        }
        // A corrupt word is a broken invariant, reported as unknown to
        // the requester; the guard stays closed.
        _ => ErrorCode::UnknownGuard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_are_named_closed_and_audited() {
        let mut guards = Guards::new(
            7,
            2,
            Words::heap(2),
            3,
            karyos_sys::diag::guard_audit(4).unwrap(),
        );
        let orders = guards.add("orders").unwrap();
        assert_eq!(orders.id(), 1);
        assert_eq!(guards.find("orders"), Some(orders));
        assert_eq!(guards.add("orders"), Err(DriverError::DuplicateGuard));
        assert_eq!(guards.add(""), Err(DriverError::InvalidConfig));
        let _ = guards.add("quotes").unwrap();
        assert_eq!(guards.add("third"), Err(DriverError::TooManyGuards));
        assert_eq!(
            guards.state(orders).unwrap(),
            GuardState {
                epoch: 1,
                open: false
            }
        );
        assert_eq!(
            guards.reopen(orders, 1, 10, Requester::InProcess, 0, 100),
            Ok(2)
        );
        assert_eq!(
            guards.reopen(orders, 1, 11, Requester::Client(4), 0, 101),
            Err(DriverError::Guard(GuardError::NotClosedAt {
                expected: 1,
                current: GuardState {
                    epoch: 2,
                    open: true
                }
            }))
        );
        assert_eq!(
            guards.close(orders, 12, Requester::Client(4), 0, 102),
            Ok(Closed::Now { epoch: 3 })
        );
        let foreign = GuardHandle {
            driver: 8,
            guard: 1,
        };
        assert_eq!(
            guards.close(foreign, 13, Requester::InProcess, 0, 103),
            Err(DriverError::UnknownGuard)
        );
        let audit = guards.audit();
        // Four transitions into three records: the oldest is overwritten.
        assert_eq!(audit.overwritten, 1);
        assert_eq!(
            audit.records,
            [
                AuditRecord {
                    time: 101,
                    guard: 1,
                    before: 5,
                    after: 5,
                    operation: 11,
                    requester: Requester::Client(4),
                    outcome: AuditOutcome::Refused(ErrorCode::GuardNotClosedAt),
                    parameters: 0,
                },
                AuditRecord {
                    time: 102,
                    guard: 1,
                    before: 5,
                    after: 6,
                    operation: 12,
                    requester: Requester::Client(4),
                    outcome: AuditOutcome::Closed,
                    parameters: 0,
                },
                AuditRecord {
                    time: 103,
                    guard: 1,
                    before: 0,
                    after: 0,
                    operation: 13,
                    requester: Requester::InProcess,
                    outcome: AuditOutcome::Refused(ErrorCode::UnknownGuard),
                    parameters: 0,
                },
            ]
        );
    }

    #[test]
    fn a_close_is_recorded_even_without_audit_room() {
        let mut guards = Guards::new(
            1,
            1,
            Words::heap(1),
            0,
            karyos_sys::diag::guard_audit(4).unwrap(),
        );
        let guard = guards.add("g").unwrap();
        assert_eq!(
            guards.close(guard, 1, Requester::InProcess, 0, 0),
            Ok(Closed::Already { epoch: 1 })
        );
        assert_eq!(guards.audit().overwritten, 1);
        assert!(guards.audit().records.is_empty());
    }

    /// A guard gauge the full region refused is counted once and tried
    /// again only every `GUARD_CELL_RETRY` syncs, not at every duty cycle;
    /// it appears once room is made and the countdown ends.
    #[test]
    fn a_refused_guard_gauge_is_retried_every_nth_sync() {
        use crate::counters::{Event, FIXED_COUNTERS};
        let mut counters = DriverCounters::with_capacity(FIXED_COUNTERS + 1).unwrap();
        let mut guards = Guards::new(
            1,
            2,
            Words::heap(2),
            2,
            karyos_sys::diag::guard_audit(2).unwrap(),
        );
        let _ = guards.add("kill").unwrap();
        // The one spare cell is taken.
        let taken = counters
            .allocate_keyed(TYPE_GAUGE, "taken", CounterKeys::DRIVER)
            .unwrap();
        let mut cells = GuardCells::default();
        cells.sync(&guards, &mut counters);
        assert_eq!(counters.value(Event::CountersUnavailable), 1);
        let gauges = |counters: &DriverCounters| {
            let reader = counters.reader();
            (0..reader.capacity())
                .filter(|&index| {
                    matches!(
                        reader.read(index),
                        karyos_sys::counters::CellRead::Allocated { metadata, .. }
                            if metadata.keys.kind == KIND_GUARD
                    )
                })
                .count()
        };
        counters.free(taken);
        for _ in 0..GUARD_CELL_RETRY {
            cells.sync(&guards, &mut counters);
            assert_eq!(gauges(&counters), 0, "retried before the countdown ended");
        }
        cells.sync(&guards, &mut counters);
        assert_eq!(gauges(&counters), 1);
        // Counted once: the retries add nothing.
        assert_eq!(counters.value(Event::CountersUnavailable), 1);
    }
}
