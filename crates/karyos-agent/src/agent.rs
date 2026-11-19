// SPDX-License-Identifier: Apache-2.0

//! The agent: one tool attach per configured driver, and the model it
//! keeps of each.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use karyos_client::tool::{RemoteTool, attach_tool};
use karyos_sys::counters::{CellRead, CountersReader, PassRead, read_pass};
use karyos_sys::host_clock::host_monotonic_ns;

use crate::alerts::{AckRead, AlertRules, Alerts};
use crate::api::{
    API_VERSION, AgentView, Alert, AlertKind, Counter, DriverState, DriverView, ErrorEntry,
    GapView, GuardEntry, JournalView, LossEntry, Sample,
};
use crate::catalog::{CatalogConfig, CatalogWatch};
use crate::journal::{Gap, GapReason, Journal, JournalError, UNOPENED_POSITION};
use crate::model::{self, Cell, Follower};
use crate::operations::{self, GuardAnswer};
use crate::registry::{self, JoinError, Kind, Registry};
use crate::trace_window::{TraceWindow, WindowConfig};

/// Attempts at a consistent sampling pass before the values are reported
/// as mixed, as `karyos-stat` makes.
const ATTEMPTS: usize = 8;

/// The default wait for each message of an attach.
pub const DEFAULT_ATTACH_TIMEOUT: Duration = Duration::from_secs(1);
/// The default records kept per diagnostic ring and driver.
pub const DEFAULT_HISTORY: usize = 256;

/// What the agent watches.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentConfig {
    /// The admission socket directories of the drivers, one per driver.
    pub drivers: Vec<PathBuf>,
    /// The wait for each message of an attach.
    pub attach_timeout: Duration,
    /// Records kept per diagnostic ring and driver; older ones are dropped
    /// from the view, still counted as delivered.
    pub history: usize,
    /// The trace latency window's bounds.
    pub trace: WindowConfig,
    /// The alert rules (M9).
    pub alerts: AlertRules,
    /// The operations journal's directory (M10b); `None` for none, and
    /// guard reopens are then refused.
    pub journal: Option<PathBuf>,
    /// The wait for a driver's answer to a guard operation (M10b).
    pub guard_timeout: Duration,
    /// The drivers whose Archive catalog the agent lists (M11), each a
    /// directory of `drivers`; none by default.
    pub archives: Vec<(PathBuf, CatalogConfig)>,
    /// The agent's own name (R-CORE-24), from its deployment's
    /// configuration; `None` by default.
    pub agent_id: Option<String>,
}

impl AgentConfig {
    /// Watching the drivers whose admission sockets are in `drivers`.
    #[must_use]
    pub fn new(drivers: Vec<PathBuf>) -> Self {
        Self {
            drivers,
            attach_timeout: DEFAULT_ATTACH_TIMEOUT,
            history: DEFAULT_HISTORY,
            trace: WindowConfig::default(),
            alerts: AlertRules::default(),
            journal: None,
            guard_timeout: DEFAULT_ATTACH_TIMEOUT,
            archives: Vec::new(),
            agent_id: None,
        }
    }

    /// With `id` as the agent's own name (R-CORE-24): what its deployment
    /// calls it, for example `namespace/pod`. The agent reports it and
    /// looks nothing up.
    #[must_use]
    pub fn with_agent_id(mut self, id: String) -> Self {
        // The same rule as `--agent-id`; an id outside it is not taken.
        self.agent_id = crate::api::valid_agent_id(&id).then_some(id);
        self
    }

    /// With the operations journal in `dir` (M10b).
    #[must_use]
    pub fn with_journal(mut self, dir: PathBuf) -> Self {
        self.journal = Some(dir);
        self
    }

    /// With the trace latency window `trace`.
    #[must_use]
    pub fn with_trace_window(mut self, trace: WindowConfig) -> Self {
        self.trace = trace;
        self
    }

    /// With `attach_timeout` for each message of an attach.
    #[must_use]
    pub fn with_attach_timeout(mut self, attach_timeout: Duration) -> Self {
        self.attach_timeout = attach_timeout;
        self
    }

    /// Keeping `history` records per ring and driver.
    #[must_use]
    pub fn with_history(mut self, history: usize) -> Self {
        self.history = history;
        self
    }

    /// With `alerts` as the alert rules.
    #[must_use]
    pub fn with_alerts(mut self, alerts: AlertRules) -> Self {
        self.alerts = alerts;
        self
    }

    /// Listing the Archive catalog of the driver in `dir` as `catalog`
    /// says (M11). A directory that is not one of the drivers lists
    /// nothing.
    #[must_use]
    pub fn with_archive(mut self, dir: PathBuf, catalog: CatalogConfig) -> Self {
        self.archives.push((dir, catalog));
        self
    }
}

/// One watched driver.
#[derive(Debug)]
struct Driver {
    dir: PathBuf,
    tool: Option<RemoteTool>,
    instance: Option<u128>,
    state: DriverState,
    sample: Option<Sample>,
    /// The driver counters' last values, for their `changed_ns`.
    changes: model::Changes,
    client_counters: Vec<Counter>,
    /// The client counters' last values.
    client_changes: model::Changes,
    errors: Follower<ErrorEntry>,
    losses: Follower<LossEntry>,
    guards: Follower<GuardEntry>,
    trace: Option<TraceWindow>,
    alerts: Alerts,
    catalog: Option<CatalogWatch>,
    attachment: crate::api::Attachment,
}

/// Who asked for an operation (karyos#708): the operator the journal and
/// the driver's audit name, and the relay that carried the request, kept
/// apart so that a relayed request never reads as the relay's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Requester {
    /// The operator: the local peer's uid, or a relayed principal's
    /// operator id from the agent's own principal table.
    pub operator: u32,
    /// The relay's configured id; 0 for a request on the local socket.
    pub relay: u64,
}

impl Requester {
    /// The local peer `uid`, which no relay carried.
    #[must_use]
    pub const fn local(uid: u32) -> Self {
        Self {
            operator: uid,
            relay: 0,
        }
    }

    /// Principal `operator`, whose request relay `relay` carried.
    #[must_use]
    pub const fn relayed(operator: u32, relay: u64) -> Self {
        Self { operator, relay }
    }
}

/// The agent. Each driver it is attached to counts one tool against the
/// driver's `max_tools`; a driver that exits releases it.
#[derive(Debug)]
pub struct Agent {
    config: AgentConfig,
    drivers: Vec<Driver>,
    /// The operations journal, once opened.
    journal: Option<Journal>,
    /// Why the configured journal could not be opened.
    journal_error: Option<String>,
    /// The unknown interval of a journal that could not be opened, until
    /// an administrator acknowledges it. Held in memory: nothing durable
    /// can record it or its acknowledgement.
    unopened_gap: Option<Gap>,
    /// The next guard operation's id.
    next_operation: u64,
    /// When it started (R-CORE-24).
    started_ns: u64,
    /// The join metadata registry (karyos#736), in memory.
    registry: Registry,
}

impl Agent {
    /// An agent for `config`, attached to nothing yet: the first
    /// [`Agent::refresh`] attaches.
    #[must_use]
    pub fn new(config: AgentConfig) -> Self {
        let drivers = config
            .drivers
            .iter()
            .map(|dir| Driver {
                dir: dir.clone(),
                tool: None,
                instance: None,
                state: DriverState::Unavailable {
                    reason: "not attached yet".to_owned(),
                },
                sample: None,
                changes: model::Changes::default(),
                client_counters: Vec::new(),
                client_changes: model::Changes::default(),
                errors: Follower::new(config.history),
                losses: Follower::new(config.history),
                guards: Follower::new(config.history),
                trace: None,
                alerts: Alerts::default(),
                // The catalog's own thread connects, off the refresh path.
                catalog: config
                    .archives
                    .iter()
                    .find(|(archive, _)| archive == dir)
                    .map(|(_, catalog)| CatalogWatch::start(dir.clone(), *catalog)),
                attachment: crate::api::Attachment::default(),
            })
            .collect();
        let start = host_monotonic_ns();
        let (journal, journal_error) = match config.journal.as_deref() {
            None => (None, None),
            Some(dir) => match Journal::open(dir, start) {
                Ok(journal) => (Some(journal), None),
                Err(error) => (None, Some(error.to_string())),
            },
        };
        let unopened_gap = journal_error.as_ref().map(|_| Gap {
            position: UNOPENED_POSITION,
            reason: GapReason::JournalUnavailableAtStart,
            from: 0,
            to: start,
        });
        Self {
            config,
            drivers,
            journal,
            journal_error,
            unopened_gap,
            // Ids from the agent's start time: unique across restarts.
            next_operation: host_monotonic_ns().max(1),
            started_ns: start,
            registry: Registry::new(start),
        }
    }

    /// Up to `count` closed trace buckets of the driver in `dir`, from
    /// `from` on (a bucket number and a lane), of the window run `epoch`
    /// when given, in a reply within [`crate::api::MAX_BUCKET_REPLY`] plus
    /// one lane (R-CORE-23).
    /// `Ok(Err(_))` is the window's own refusal; `Err(answer)` a driver
    /// unknown or with no trace window yet, answered as a guard
    /// operation's.
    pub fn trace_buckets(
        &self,
        dir: &Path,
        from: crate::api::BucketCursor,
        count: usize,
        epoch: Option<u64>,
    ) -> Result<Result<crate::api::BucketRead, crate::api::BucketRefusal>, GuardAnswer> {
        let driver = self
            .drivers
            .iter()
            .find(|driver| driver.dir == dir)
            .ok_or(GuardAnswer::UnknownDriver)?;
        let window = driver.trace.as_ref().ok_or(GuardAnswer::Unattached)?;
        Ok(window.buckets(from, count, epoch, crate::api::MAX_BUCKET_REPLY))
    }

    /// Up to `count` raw trace records of the driver in `dir`, from mirror
    /// sequence `from` on, for a cursor of driver instance `epoch` when
    /// given (R-CORE-13). Read from the attached driver's mirror at the
    /// call: the agent keeps no cursor. `Ok(Err(_))` is the export's own
    /// refusal; `Err(answer)` a driver unknown or not attached, answered as
    /// a guard operation's.
    pub fn trace_export(
        &self,
        dir: &Path,
        from: u64,
        count: usize,
        epoch: Option<u128>,
    ) -> Result<Result<crate::api::ExportPage, crate::api::ExportRefusal>, GuardAnswer> {
        let driver = self
            .drivers
            .iter()
            .find(|driver| driver.dir == dir)
            .ok_or(GuardAnswer::UnknownDriver)?;
        let (Some(tool), Some(instance)) = (driver.tool.as_ref(), driver.instance) else {
            return Err(GuardAnswer::Unattached);
        };
        Ok(crate::trace_export::export(
            tool.trace_mirror(),
            Some(tool.client_counters()),
            instance,
            from,
            count,
            epoch,
            crate::api::MAX_EXPORT_REPLY,
        ))
    }

    /// Closes guard `guard` of the driver in `dir` for operator `uid`
    /// with `reason`, journalled (M10b; see `operations`).
    pub fn guard_close(&mut self, dir: &Path, guard: u64, uid: u32, reason: &[u8]) -> GuardAnswer {
        self.guard_command(dir, guard, None, Requester::local(uid), reason)
    }

    /// As [`Agent::guard_close`], for `requester`, whom a relay may have
    /// carried (karyos#708): the journal records the relay and the
    /// requester apart.
    pub fn guard_close_for(
        &mut self,
        dir: &Path,
        guard: u64,
        requester: Requester,
        reason: &[u8],
    ) -> GuardAnswer {
        self.guard_command(dir, guard, None, requester, reason)
    }

    /// As [`Agent::guard_reopen`], for `requester` (karyos#708).
    pub fn guard_reopen_for(
        &mut self,
        dir: &Path,
        guard: u64,
        expected: u64,
        requester: Requester,
        reason: &[u8],
    ) -> GuardAnswer {
        self.guard_command(dir, guard, Some(expected), requester, reason)
    }

    /// Reopens guard `guard`, closed at `expected`, of the driver in `dir`
    /// for operator `uid`; refused unless its request is journalled
    /// durably first.
    pub fn guard_reopen(
        &mut self,
        dir: &Path,
        guard: u64,
        expected: u64,
        uid: u32,
        reason: &[u8],
    ) -> GuardAnswer {
        self.guard_command(dir, guard, Some(expected), Requester::local(uid), reason)
    }

    fn guard_command(
        &mut self,
        dir: &Path,
        guard: u64,
        reopen: Option<u64>,
        requester: Requester,
        reason: &[u8],
    ) -> GuardAnswer {
        if !self.drivers.iter().any(|driver| driver.dir == dir) {
            return GuardAnswer::UnknownDriver;
        }
        let operation = self.next_operation;
        // Checked: at their end the ids keep the last one.
        self.next_operation = operation.checked_add(1).unwrap_or(operation);
        let command = operations::Command {
            dir,
            guard,
            reopen,
            operation,
            operator: requester.operator,
            relay: requester.relay,
            // Cut once, so the digest covers what is journalled (DESIGN's
            // P2 on #487).
            reason: operations::cut_reason(reason),
            timeout: self.config.guard_timeout,
        };
        operations::guard_command(self.journal.as_mut(), &command)
    }

    /// Stops the agent's journal cleanly: its `agent stopped` record, durable
    /// and last, so the next start records no unknown interval for this
    /// run (karyos#490 follow-up, kind 7). The agent's one clean stop; the
    /// binary's signal handling calls it once karyos-agent may catch
    /// signals (owner item 55); until then a signal stop is an unclean one.
    ///
    /// # Errors
    ///
    /// The journal's: a journal that failed cannot record its stop, and
    /// the next start records the unclean stop.
    pub fn stop(&mut self) -> Result<(), JournalError> {
        match self.journal.as_mut() {
            Some(journal) => journal.stop(host_monotonic_ns()),
            None => Ok(()),
        }
    }

    /// Records administrator `uid`'s acknowledgement of the open unknown
    /// interval at `position` (M10b). That of a journal that could not be
    /// opened, at [`UNOPENED_POSITION`], is kept in memory only and
    /// logged at info on standard error with `uid` and the interval: the
    /// run has no journal to record it, and the next start raises it again
    /// if the journal still cannot be opened.
    ///
    /// # Errors
    ///
    /// [`JournalError::NoGap`] when there is no such interval open, and
    /// the journal's errors.
    pub fn acknowledge_gap(&mut self, position: u64, uid: u32) -> Result<(), JournalError> {
        self.acknowledge_gap_for(position, Requester::local(uid))
    }

    /// As [`Agent::acknowledge_gap`], for `requester` (karyos#708).
    ///
    /// # Errors
    ///
    /// As [`Agent::acknowledge_gap`].
    pub fn acknowledge_gap_for(
        &mut self,
        position: u64,
        requester: Requester,
    ) -> Result<(), JournalError> {
        let uid = requester.operator;
        match self.journal.as_mut() {
            Some(journal) => journal.acknowledge_gap_relayed(
                position,
                u64::from(uid),
                requester.relay,
                host_monotonic_ns(),
            ),
            None => match self.unopened_gap.take_if(|gap| gap.position == position) {
                // The one operator act nothing durable records: logged at
                // info on standard error, as the agent logs (DESIGN's P3 on
                // #498).
                Some(gap) => {
                    let _ = writeln!(
                        std::io::stderr(),
                        "karyos-agent: info: {} acknowledged the unknown interval of a \
                         journal that could not be opened, from {} to {}; held in memory only",
                        acknowledger(requester),
                        gap.from,
                        gap.to,
                    );
                    Ok(())
                }
                None => Err(JournalError::NoGap),
            },
        }
    }

    /// The journal's state, for the view.
    fn journal_view(&self) -> Option<JournalView> {
        self.config.journal.as_ref()?;
        let journal = self.journal.as_ref();
        let gap = journal.and_then(Journal::gap).or(self.unopened_gap);
        Some(JournalView {
            recording: journal.map(Journal::recording),
            unsealed: true,
            unavailable: journal.is_none_or(Journal::unavailable),
            error: self.journal_error.clone(),
            failed_appends: journal.map_or(0, Journal::failed_appends),
            gap: gap.map(|gap| GapView {
                position: gap.position,
                from: gap.from,
                to: gap.to,
                reason: match gap.reason {
                    GapReason::RequestWithoutOutcome => "request_without_outcome",
                    GapReason::TornTail => "torn_tail",
                    GapReason::JournalReplaced => "journal_replaced",
                    GapReason::JournalUnavailableAtStart => "journal_unavailable_at_start",
                    _ => "unclean_stop",
                },
            }),
            // An unknown interval stays an alert until it is acknowledged;
            // a journal that failed is one from its failure on, until the
            // restart that records it (DESIGN's P3 on #485).
            alerts: gap
                .map(|gap| Alert {
                    kind: AlertKind::JournalGap,
                    stream: 0,
                    lane: 0,
                    participant: gap.position,
                    value: gap.to.abs_diff(gap.from),
                    since: gap.to,
                })
                .into_iter()
                .chain(journal.and_then(Journal::failed_at).map(|since| Alert {
                    kind: AlertKind::JournalGap,
                    stream: 0,
                    lane: 0,
                    participant: u64::MAX,
                    value: journal.map_or(0, Journal::failed_appends),
                    since,
                }))
                .collect(),
        })
    }

    /// Attaches to every driver it is not attached to, reads every one it
    /// is, and notes those that exited. A driver it cannot attach to is
    /// reported unavailable with the reason; nothing here fails the agent.
    pub fn refresh(&mut self) {
        let (timeout, trace) = (self.config.attach_timeout, self.config.trace);
        for driver in &mut self.drivers {
            driver.refresh(timeout, trace, &self.config.alerts);
        }
    }

    /// The join registry's generation (karyos#736).
    #[must_use]
    pub const fn join_generation(&self) -> u64 {
        self.registry.generation()
    }

    /// The index of the driver in `dir`.
    fn driver_index(&self, dir: &Path) -> Result<usize, JoinError> {
        self.drivers
            .iter()
            .position(|driver| driver.dir == dir)
            .ok_or(JoinError::UnknownDriver)
    }

    /// Puts a new version of the driver in `dir`'s `kind` `key` with
    /// `attributes`, for `requester` (karyos#736): its operator, and its
    /// relay apart (karyos#708); its number.
    ///
    /// # Errors
    ///
    /// [`JoinError::UnknownDriver`], or the registry's refusal.
    pub fn join_put(
        &mut self,
        dir: &Path,
        kind: Kind,
        key: &str,
        attributes: &str,
        requester: Requester,
    ) -> Result<u64, JoinError> {
        let driver = self.driver_index(dir)?;
        self.registry
            .put_relayed(
                driver,
                kind,
                key,
                attributes,
                (requester.operator, requester.relay),
                host_monotonic_ns(),
            )
            .map_err(JoinError::Refused)
    }

    /// Ends the current version of the driver in `dir`'s `kind` `key`; its
    /// number.
    ///
    /// # Errors
    ///
    /// [`JoinError::UnknownDriver`], or the registry's refusal.
    pub fn join_retire(&mut self, dir: &Path, kind: Kind, key: &str) -> Result<u64, JoinError> {
        let driver = self.driver_index(dir)?;
        self.registry
            .retire(driver, kind, key, host_monotonic_ns())
            .map_err(JoinError::Refused)
    }

    /// The version of the driver in `dir`'s `kind` `key` in force at `at`
    /// (host `CLOCK_MONOTONIC` nanoseconds, now when `None`), with what
    /// the agent observes of the identity now.
    ///
    /// # Errors
    ///
    /// [`JoinError::UnknownDriver`], or a malformed key.
    pub fn join_get<'a>(
        &'a self,
        dir: &'a Path,
        kind: Kind,
        key: &'a str,
        at: Option<u64>,
    ) -> Result<registry::Read<'a>, JoinError> {
        let index = self.driver_index(dir)?;
        let driver = self.drivers.get(index).ok_or(JoinError::UnknownDriver)?;
        registry::check_key(kind, key).map_err(JoinError::Refused)?;
        Ok(registry::Read {
            generation: self.registry.generation(),
            since_ns: self.registry.since_ns(),
            dir,
            kind,
            key,
            at: at.unwrap_or_else(host_monotonic_ns),
            entry: self.registry.get(index, kind, key),
            presence: driver.presence(kind, key),
        })
    }

    /// A page of the driver in `dir`'s entries, after `after` when given.
    ///
    /// # Errors
    ///
    /// [`JoinError::UnknownDriver`], or a malformed or oversized cursor
    /// key, refused as [`Agent::join_get`] refuses it.
    pub fn join_list<'a>(
        &'a self,
        dir: &'a Path,
        after: Option<(Kind, &str)>,
    ) -> Result<registry::Page<'a>, JoinError> {
        let index = self.driver_index(dir)?;
        let driver = self.drivers.get(index).ok_or(JoinError::UnknownDriver)?;
        // A cursor is a key: refused as a get refuses it (karyos#893).
        if let Some((kind, key)) = after {
            registry::check_key(kind, key).map_err(JoinError::Refused)?;
        }
        let (entries, more) = self.registry.list(index, after);
        Ok(registry::Page {
            generation: self.registry.generation(),
            since_ns: self.registry.since_ns(),
            evicted: self.registry.evicted(),
            dir,
            entries: entries
                .into_iter()
                .map(|entry| (entry, driver.presence(entry.kind, &entry.key)))
                .collect(),
            more,
        })
    }

    /// What the agent knows, as API v1.
    #[must_use]
    pub fn view(&self) -> AgentView {
        AgentView {
            version: API_VERSION,
            drivers: self.drivers.iter().map(Driver::view).collect(),
            journal: self.journal_view(),
            agent: crate::api::AgentIdentity::new(
                self.config.agent_id.clone(),
                std::process::id(),
                self.started_ns,
            ),
        }
    }

    /// Its capabilities for a caller who may close guards (`close`),
    /// reopen them (`reopen`), acknowledge the journal's unknown interval
    /// (`acknowledge`) and write the join registry (`register`,
    /// karyos#736), in [`crate::api::CAPABILITIES`] order
    /// (R-CORE-24). What this deployment does not offer is `Unavailable`,
    /// whatever the role; what it offers but the role does not allow is
    /// `Forbidden`.
    #[must_use]
    pub fn capabilities(
        &self,
        close: bool,
        reopen: bool,
        acknowledge: bool,
        register: bool,
    ) -> Vec<crate::api::Capability> {
        use crate::api::{CAPABILITIES, Capability, CapabilityState};

        // Reopens need a journal that records; an acknowledgement also
        // serves the unknown interval of a journal that could not open.
        let (reopen_off, acknowledge_off) = match (&self.config.journal, &self.journal) {
            (None, _) => (Some("not_configured"), Some("not_configured")),
            // Could not open: only its unknown interval can be acknowledged.
            (Some(_), None) => (Some("journal_unavailable"), None),
            // Opened, then an append failed: it refuses every append.
            (Some(_), Some(journal)) if journal.unavailable() => {
                (Some("journal_unavailable"), Some("journal_unavailable"))
            }
            (Some(_), Some(_)) => (None, None),
        };
        let catalog = self.drivers.iter().any(|driver| driver.catalog.is_some());
        CAPABILITIES
            .iter()
            .map(|&name| {
                let (unavailable, permitted) = match name {
                    "guard-close" => (None, close),
                    "guard-reopen" => (reopen_off, reopen),
                    "gap-ack" => (acknowledge_off, acknowledge),
                    "catalog" => ((!catalog).then_some("not_configured"), true),
                    // Served to every role, always.
                    "view" | "trace-window" | "limits" | "trace-buckets" | "trace-export"
                    | "join-registry" => (None, true),
                    "join-put" => (None, register),
                    // A name added to CAPABILITIES must be classified here.
                    _ => (Some("not_configured"), true),
                };
                let state = match (unavailable, permitted) {
                    (Some(reason), _) => CapabilityState::Unavailable { reason },
                    (None, false) => CapabilityState::Forbidden { reason: "role" },
                    (None, true) => CapabilityState::Served,
                };
                Capability { name, state }
            })
            .collect()
    }
}

impl Driver {
    /// What the agent observes now of the identity `kind` `key` in this
    /// driver (karyos#736): for a trace point or an application counter,
    /// whether a client cell of that type and label exists and how many;
    /// for a stream, its publications in the last sample
    /// ([`stream_presence`], karyos#885); and nothing while not attached.
    fn presence(&self, kind: Kind, key: &str) -> registry::Presence {
        let types: &[u64] = match kind {
            Kind::Stream => {
                return stream_presence(self.tool.is_some(), self.sample.as_ref(), key);
            }
            Kind::Point => &[karyos_sys::counters::TYPE_TRACE_POINT],
            Kind::Counter => &[
                karyos_sys::counters::TYPE_APPLICATION_EVENT,
                karyos_sys::counters::TYPE_APPLICATION_GAUGE,
            ],
        };
        if self.tool.is_none() {
            return registry::Presence::default();
        }
        let holders = self
            .client_counters
            .iter()
            .filter(|counter| types.contains(&counter.type_id) && counter.label == key)
            .count();
        let holders = u64::try_from(holders).unwrap_or(u64::MAX);
        registry::Presence {
            present: Some(holders > 0),
            holders: Some(holders),
        }
    }

    fn refresh(&mut self, timeout: Duration, trace: WindowConfig, rules: &AlertRules) {
        if self.tool.is_none() {
            match attach_tool(&self.dir, timeout) {
                Ok(tool) => {
                    // A new instance is a new driver: its rings start over.
                    if self.instance != Some(tool.instance()) {
                        self.changes.restart();
                        self.client_changes.restart();
                        self.errors.restart();
                        self.losses.restart();
                        self.guards.restart();
                        self.alerts.restart();
                        self.trace = Some(TraceWindow::new(trace, driver_id(tool.instance())));
                    }
                    self.instance = Some(tool.instance());
                    self.state = DriverState::Attached;
                    self.tool = Some(tool);
                    self.attachment.since_ns = Some(host_monotonic_ns());
                    self.attachment.attaches = self.attachment.attaches.saturating_add(1);
                }
                Err(error) => {
                    // A closed driver stays reported closed until it is
                    // back.
                    if self.state != DriverState::Closed {
                        self.state = DriverState::Unavailable {
                            reason: error.to_string(),
                        };
                    }
                    // Nothing read: its lag alerts clear, a quiet refresh
                    // for its loss alert (M9).
                    self.alerts.detached(rules);
                    return;
                }
            }
        }
        let Some(tool) = self.tool.as_mut() else {
            return;
        };
        // Read first, so the last values of a driver that exits are kept.
        self.sample = Some(read_sample(tool.counters(), &mut self.changes));
        self.client_counters = model::counters(
            &read_cells(tool.client_counters()),
            host_monotonic_ns(),
            &mut self.client_changes,
        );
        read_rings(tool, &mut self.errors, &mut self.losses, &mut self.guards);
        if let Some(window) = self.trace.as_mut() {
            window.scan(tool.trace_mirror(), host_monotonic_ns());
        }
        // The rules see what this refresh read (M9).
        let losses = self.losses.feed();
        let reported = losses.delivered.checked_add(losses.overwritten);
        self.alerts.update(
            rules,
            self.sample.as_ref(),
            reported.unwrap_or(losses.delivered),
            host_monotonic_ns(),
        );
        let acks: Vec<AckRead> = karyos_client::guard_acks::guard_acks(tool.counters())
            .iter()
            .map(|ack| AckRead {
                guard: ack.guard,
                consistent: ack.consistent,
                epoch: ack.epoch,
                overdue: ack.overdue,
            })
            .collect();
        self.alerts.update_guard_acks(&acks, host_monotonic_ns());
        let ended = match tool.driver_closed() {
            Ok(false) => return,
            Ok(true) => {
                self.tool = None;
                self.state = DriverState::Closed;
                crate::api::AttachEndReason::DriverGone
            }
            Err(error) => {
                self.tool = None;
                self.state = DriverState::Unavailable {
                    reason: error.to_string(),
                };
                crate::api::AttachEndReason::Detached
            }
        };
        // The attach ended: stated, with the instance it was attached to
        // (R-CORE-24).
        if let Some(instance) = self.instance {
            self.attachment.previous = Some(crate::api::AttachEnd::new(
                instance,
                host_monotonic_ns(),
                ended,
            ));
        }
        self.attachment.since_ns = None;
        // The driver it was attached to went away: its catalog's session
        // ends now, not at its deadline (M11). An attach that fails later
        // does not signal, as the driver may be alive with its tool slots
        // taken.
        if let Some(catalog) = &self.catalog {
            catalog.driver_gone();
        }
    }

    fn view(&self) -> DriverView {
        let (latencies, trace) = self
            .trace
            .as_ref()
            .map(|window| window.view(host_monotonic_ns()))
            .unwrap_or_default();
        DriverView {
            dir: self.dir.clone(),
            state: self.state.clone(),
            instance: self.instance,
            sample: self.sample.clone(),
            client_counters: self.client_counters.clone(),
            errors: self.errors.feed(),
            losses: self.losses.feed(),
            guards: self.guards.feed(),
            latencies,
            trace,
            alerts: self.alerts.firing(),
            catalog: self.catalog.as_ref().map(CatalogWatch::view),
            attachment: self.attachment,
        }
    }
}

/// What `sample` shows of the stream whose wire id is `key` (karyos#885):
/// its holders are the publications of every lane with that wire id, a
/// client's `publication` cell each plus the lane's `embedded
/// publications` count, and it is present when it has at least one.
/// Nothing while not `attached`, before the agent's first sample or the
/// driver's first pass, or while `counters unavailable` is nonzero, since
/// a cell the driver could not allocate would undercount them and make a
/// shared stream look unshared; nothing either when the count overflows.
fn stream_presence(attached: bool, sample: Option<&Sample>, key: &str) -> registry::Presence {
    let (true, Some(sample)) = (attached, sample) else {
        return registry::Presence::default();
    };
    use karyos_sys::counters::{
        LABEL_EMBEDDED_PUBLICATIONS, LABEL_PUBLICATION, LABEL_STREAM_WIRE_ID, wire_stream_id,
    };

    let Ok(stream_id) = key.parse::<i32>() else {
        return registry::Presence::default();
    };
    let unavailable = sample.counters.iter().any(|counter| {
        counter.stream == 0 && counter.label == "counters unavailable" && counter.value > 0
    });
    if !sample.sampled || unavailable {
        return registry::Presence::default();
    }
    let lane_count = |lane: &crate::api::Counter, label: &str| -> Option<u64> {
        sample
            .counters
            .iter()
            .filter(|counter| {
                counter.label == label && counter.stream == lane.stream && counter.lane == lane.lane
            })
            .map(|counter| {
                if label == LABEL_PUBLICATION {
                    1
                } else {
                    counter.value
                }
            })
            .try_fold(0, u64::checked_add)
    };
    let holders = sample
        .counters
        .iter()
        .filter(|counter| {
            counter.label == LABEL_STREAM_WIRE_ID
                && wire_stream_id(counter.value) == Some(stream_id)
        })
        .map(|lane| {
            lane_count(lane, LABEL_PUBLICATION)?
                .checked_add(lane_count(lane, LABEL_EMBEDDED_PUBLICATIONS)?)
        })
        .try_fold(0_u64, |sum, lane| sum.checked_add(lane?));
    // A count past u64::MAX is no count: unknown, as for a missing cell.
    let Some(holders) = holders else {
        return registry::Presence::default();
    };
    registry::Presence {
        present: Some(holders > 0),
        holders: Some(holders),
    }
}

/// The `driver_id` words of a driver instance id, as the trace records
/// carry them.
fn driver_id(instance: u128) -> [u64; 2] {
    let [high, low] = [instance >> 64, instance & u128::from(u64::MAX)]
        .map(|half| u64::try_from(half).unwrap_or(0));
    [high, low]
}

/// Every allocated cell of `reader`.
fn read_cells(reader: &CountersReader) -> Vec<Cell> {
    (0..reader.capacity())
        .filter_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } => Some((metadata, value)),
            _ => None,
        })
        .collect()
}

/// One sampling pass of the driver counters.
fn read_sample(counters: &CountersReader, changes: &mut model::Changes) -> Sample {
    let epoch = (0..counters.capacity()).find(|&index| {
        matches!(counters.read(index), CellRead::Allocated { metadata, .. }
            if metadata.label() == b"positions epoch" && metadata.keys.stream == 0)
    });
    let read = read_pass(
        // No epoch cell: one read, consistent, as nothing can be mixed.
        || {
            epoch
                .and_then(|index| counters.load_value(index))
                .unwrap_or(0)
        },
        || read_cells(counters),
        ATTEMPTS,
    );
    let (consistent, cells) = match read {
        PassRead::Consistent(cells) => (true, cells),
        PassRead::Inconsistent(cells) => (false, cells),
    };
    model::sample(&cells, consistent, host_monotonic_ns(), changes)
}

/// Scans the three diagnostic rings from their followers' cursors.
fn read_rings(
    tool: &RemoteTool,
    errors: &mut Follower<ErrorEntry>,
    losses: &mut Follower<LossEntry>,
    guards: &mut Follower<GuardEntry>,
) {
    // The error log updates a repeated error's record in place (its
    // occurrences and last time), so the scan starts again from the oldest
    // record kept, as `karyos-errors` does: an earlier record comes back
    // updated, never as a new one.
    let next = errors.cursor;
    let start = errors.oldest().map_or(next, |oldest| oldest.seq.min(next));
    let mut cursor = start;
    let mut read = Vec::new();
    let scan = tool.error_log().scan(&mut cursor, |record| {
        read.push(ErrorEntry {
            seq: record.seq,
            first: record.first,
            last: record.last,
            occurrences: record.occurrences,
            code: record.code,
            source: record.source,
            key: record.key,
            message: record.message,
        });
    });
    // The boundary proved `start..proven` overwritten; only the part past
    // what was read before is a loss.
    let lost = start
        .checked_add(scan.overwritten)
        .and_then(|proven| proven.checked_sub(next))
        .unwrap_or(0);
    errors.cursor = cursor.max(next);
    let mut new = 0;
    for entry in read {
        if entry.seq >= next {
            new += 1;
            errors.push(entry);
        } else {
            errors.update(entry, |kept, read| kept.seq == read.seq);
        }
    }
    errors.count(new, lost);

    let mut cursor = losses.cursor;
    let mut kept = Vec::new();
    let scan = tool.loss_report().scan(&mut cursor, |seq, record| {
        kept.push(LossEntry {
            seq,
            time: record.time,
            kind: record.kind,
            reason: record.reason,
            lane: record.lane,
            stream_id: record.stream_id,
            stream_registration: record.stream_registration,
            from: record.from,
            to: record.to,
            participant: record.participant,
            client: record.client,
        });
    });
    losses.cursor = cursor;
    losses.count(scan.delivered, scan.overwritten);
    kept.into_iter().for_each(|entry| losses.push(entry));

    let mut cursor = guards.cursor;
    let mut kept = Vec::new();
    let scan = tool.guard_audit().scan(&mut cursor, |seq, record| {
        kept.push(GuardEntry {
            seq,
            time: record.time,
            guard: record.guard,
            before: record.before,
            after: record.after,
            operation: record.operation,
            requester_kind: record.requester_kind,
            requester: record.requester,
            outcome: record.outcome,
            refusal: record.refusal,
            operator: record.operator,
            parameters: record.parameters,
        });
    });
    guards.cursor = cursor;
    guards.count(scan.delivered, scan.overwritten);
    kept.into_iter().for_each(|entry| guards.push(entry));
}

/// Who acknowledged an unknown interval, as the agent logs it: `uid U`
/// for a local request, as before relays; `operator O relay R` for a
/// relayed one (karyos#708), so the log names the relay and never calls a
/// principal's operator id a uid.
fn acknowledger(requester: Requester) -> String {
    match requester.relay {
        0 => format!("uid {}", requester.operator),
        relay => format!("operator {} relay {relay}", requester.operator),
    }
}

#[cfg(test)]
mod tests;
