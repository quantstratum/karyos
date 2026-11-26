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
use crate::operations::{self, GuardAnswer, RateAnswer};
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
    /// The operation classes marked for two people (R-CORE-20, karyos#739,
    /// `--two-person`); none by default.
    pub two_person: Vec<crate::two_person::TwoPersonClass>,
    /// How long a marked operation waits for its approval
    /// (`--approval-wait`).
    pub approval_wait: Duration,
    /// The operations journal's retention policy, copies and trust
    /// (ADR-0113): no policy by default, so no purge.
    pub journal_retention: crate::journal::JournalRetention,
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
            two_person: Vec::new(),
            approval_wait: crate::two_person::DEFAULT_WAIT,
            journal_retention: crate::journal::JournalRetention::default(),
        }
    }

    /// With the operations journal's retention `settings` (ADR-0113).
    #[must_use]
    pub fn with_journal_retention(mut self, settings: crate::journal::JournalRetention) -> Self {
        self.journal_retention = settings;
        self
    }

    /// With `classes` marked for two people (R-CORE-20, karyos#739).
    #[must_use]
    pub fn with_two_person(mut self, classes: Vec<crate::two_person::TwoPersonClass>) -> Self {
        self.two_person = classes;
        self
    }

    /// With `wait` as the wait for an approval, at most
    /// [`crate::two_person::MAX_WAIT`] (karyos#739).
    #[must_use]
    pub fn with_approval_wait(mut self, wait: Duration) -> Self {
        self.approval_wait = wait.min(crate::two_person::MAX_WAIT);
        self
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

/// The driver gauge of its configured `max_trace_points_per_client`.
const TRACE_POINTS_PER_CLIENT: &str = "trace points per client";
/// The driver gauge of its configured
/// `max_trace_point_registrations_per_client`.
const TRACE_POINT_REGISTRATIONS_PER_CLIENT: &str = "trace point registrations per client";

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
    /// The trace mirror's `network_journals_refused` when the agent last
    /// attached to this driver (karyos#931).
    refused_at_attach: Option<u64>,
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
    /// The Archive's retention operations (M12), once one is attached.
    retention: Option<crate::retention::SharedBackend>,
    /// The rate policy versions rate changes were answered with
    /// (karyos#740), least recently answered first.
    rates: Vec<crate::api::RateView>,
    /// The guard previews whose tokens a submit may name (karyos#738).
    previews: crate::preview::Previews,
    /// The outcomes of the operation ids used, retained for retries and
    /// rebuilt from the journal at start (karyos#738).
    outcomes: crate::preview::Outcomes,
    /// Every operation id used, the agent's own and the ones callers chose,
    /// rebuilt from the journal at start (karyos#738): one accounting, so
    /// no two operations share an id.
    used_ids: std::collections::HashSet<u64>,
    /// This host's boot identity, journalled with each submit (karyos#738).
    boot: Vec<u8>,
    /// The product Clusters attached for admin commands (karyos#772).
    clusters: crate::cluster_admin::Clusters,
    /// The operations in the two-person flow, rebuilt from the journal at
    /// start (karyos#739).
    approvals: crate::approval::Approvals,
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
                refused_at_attach: None,
            })
            .collect();
        let start = host_monotonic_ns();
        let (mut journal, journal_error) = match config.journal.as_deref() {
            None => (None, None),
            Some(dir) => match Journal::open_with(dir, start, config.journal_retention.clone()) {
                Ok(mut journal) => {
                    // An earlier start that could not open the journal is
                    // an unknown interval, from its marker (karyos#773
                    // review); the marker goes once it is recorded.
                    let marker = crate::journal::outage_marker(dir);
                    if let Ok(text) = std::fs::read_to_string(&marker) {
                        let from = text.trim().parse().unwrap_or(0);
                        if journal.record_outage(from, start).is_ok() {
                            let _ = std::fs::remove_file(&marker);
                        }
                    }
                    (Some(journal), None)
                }
                Err(error) => {
                    // Best effort: a marker that cannot be written leaves
                    // the outage in memory only, for this run.
                    let marker = crate::journal::outage_marker(dir);
                    if !marker.exists() {
                        let _ = std::fs::write(&marker, start.to_string());
                    }
                    (None, Some(error.to_string()))
                }
            },
        };
        let operations = journal
            .as_mut()
            .map(Journal::take_operations)
            .unwrap_or_default();
        let boot = crate::preview::boot_id();
        let outcomes = crate::preview::Outcomes::rebuild(&operations, (start, &boot));
        // A pending operation never survives a restart, nor a granted one
        // without its dispatch record (karyos#739): their ends are
        // journalled now.
        let (approvals, ended) = crate::approval::Approvals::rebuild(&operations, (start, &boot));
        if let Some(journal) = journal.as_mut() {
            for record in &ended {
                let _ = journal.append_durable(record, record.time);
            }
        }
        // Only callers' ids: the agent's own direct ids are not journalled
        // as submits, and its allocator starts past them (karyos#738).
        // And the ids of every admin command sent to a Cluster (karyos#772).
        let used_ids = outcomes
            .ids()
            .chain(
                operations
                    .iter()
                    .filter(|record| record.kind == crate::journal::Kind::ClusterRequest)
                    .map(|record| record.operation),
            )
            .chain(approvals.ids())
            .collect();
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
            retention: None,
            rates: Vec::new(),
            previews: crate::preview::Previews::default(),
            outcomes,
            used_ids,
            boot,
            clusters: crate::cluster_admin::Clusters::default(),
            approvals,
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

    /// The clocks of the driver in `dir` (R-CORE-40, karyos#741): its
    /// local trace journals' clocks as the agent's trace window last saw
    /// them, with their domains, epochs and uncertainties, and the
    /// calibrations the agent can see. The agent reads no calibration
    /// source until karyos#118 produces one, so every clock's calibration
    /// is unavailable, `no_calibration`, and the list is empty with the
    /// reason `no_producer`: a clocks view may legitimately show no
    /// cross-host calibration until then. Read from the window the agent
    /// holds, never from a mapping: O(journals), within `max_journals`.
    ///
    /// # Errors
    ///
    /// [`GuardAnswer::UnknownDriver`] for a directory not configured, and
    /// [`GuardAnswer::Unattached`] before the agent has attached to it.
    pub fn clocks(&self, dir: &Path) -> Result<crate::api::ClocksRead, GuardAnswer> {
        /// The calibrations the agent can see: none until karyos#118.
        const CALIBRATIONS: &[karyos_trace::Calibration] = &[];
        let driver = self
            .drivers
            .iter()
            .find(|driver| driver.dir == dir)
            .ok_or(GuardAnswer::UnknownDriver)?;
        let (Some(window), Some(instance)) = (driver.trace.as_ref(), driver.instance) else {
            return Err(GuardAnswer::Unattached);
        };
        let (clocks, calibrations) = window.clocks(CALIBRATIONS);
        Ok(crate::api::ClocksRead {
            dir: driver.dir.clone(),
            read_ns: host_monotonic_ns(),
            driver: instance,
            clocks,
            calibrations,
            calibrations_unavailable: Some("no_producer"),
        })
    }

    /// The rate limiters of the driver in `dir` (R-CORE-40, karyos#741):
    /// per network publication, the policy in force, its version and each
    /// limiter's refusals, from the counter cells of the agent's last
    /// sampling pass, never from a mapping: O(cells), within the counters
    /// region.
    ///
    /// # Errors
    ///
    /// [`GuardAnswer::UnknownDriver`] for a directory not configured, and
    /// [`GuardAnswer::Unattached`] before a pass of it was read.
    pub fn rate_limits(&self, dir: &Path) -> Result<crate::api::RateLimitsRead, GuardAnswer> {
        let driver = self
            .drivers
            .iter()
            .find(|driver| driver.dir == dir)
            .ok_or(GuardAnswer::UnknownDriver)?;
        let sample = driver.sample.as_ref().ok_or(GuardAnswer::Unattached)?;
        Ok(crate::api::RateLimitsRead {
            dir: driver.dir.clone(),
            read_ns: sample.counters.first().map(|counter| counter.read_ns),
            publications: crate::resources::rate_limits(&sample.counters),
        })
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
            // The driver's copy of each point, never a client's cell
            // (karyos#869).
            Some(tool.counters()),
            instance,
            from,
            count,
            epoch,
            crate::api::MAX_EXPORT_REPLY,
        )
        .map(|mut page| {
            page.network_journals_refused.attach = driver.refused_at_attach;
            page
        }))
    }

    /// Attaches a product's Cluster as `name` for admin commands, with the
    /// commands its gateway registers (R-CORE-41, karyos#772; see
    /// [`crate::cluster_admin`]).
    ///
    /// # Errors
    ///
    /// [`crate::cluster_admin::AttachError`], with nothing attached.
    pub fn attach_cluster(
        &mut self,
        name: &str,
        gateway: Box<dyn crate::cluster_admin::ClusterGateway>,
    ) -> Result<(), crate::cluster_admin::AttachError> {
        self.clusters.attach(name, gateway)
    }

    /// Makes admin command `command` with `parameters` on the Cluster
    /// attached as `cluster`, under the caller's operation id `operation`,
    /// for `requester` with `clearance`: journalled before and after, or
    /// refused and journalled unsent (see [`crate::cluster_admin`]).
    pub fn cluster_command_for(
        &mut self,
        (cluster, command, parameters): (&str, &str, &[u8]),
        operation: u64,
        (requester, clearance): (Requester, crate::cluster_admin::Clearance),
        reason: &[u8],
    ) -> crate::cluster_admin::ClusterAnswer {
        // A marked command enters the approval flow, never this path
        // (karyos#739).
        if self.command_marked(cluster, command) {
            return crate::cluster_admin::ClusterAnswer::TwoPersonRequired;
        }
        let command = crate::cluster_admin::Command {
            cluster,
            command,
            parameters,
            operation,
            operator: requester.operator,
            relay: requester.relay,
            clearance,
            reason,
        };
        let used_ids = &mut self.used_ids;
        crate::cluster_admin::cluster_command(
            self.journal.as_mut(),
            &self.clusters,
            &command,
            (self.config.guard_timeout, |id, take| {
                if take {
                    !used_ids.insert(id)
                } else {
                    used_ids.contains(&id)
                }
            }),
            host_monotonic_ns,
        )
    }

    /// Attaches the Archive the retention operations go to (M12).
    pub fn set_retention(&mut self, backend: Box<dyn crate::retention::RetentionBackend>) {
        self.retention = Some(crate::retention::shared(backend));
    }

    /// Makes retention `operation` on `recording` for `requester`,
    /// journalled with its operator and relay under the fail-closed rule of
    /// [`crate::retention`].
    pub fn retention(
        &mut self,
        operation: crate::retention::Operation,
        recording: u64,
        requester: Requester,
        reason: &[u8],
    ) -> crate::retention::RetentionAnswer {
        // An id is taken only when the operation can be sent.
        let id = if self.retention.is_some() {
            self.allocate_operation()
        } else {
            self.next_operation
        };
        let command = crate::retention::Command {
            operation,
            recording,
            id,
            operator: requester.operator,
            relay: requester.relay,
            reason,
        };
        crate::retention::retention_command(
            self.journal.as_mut(),
            self.retention.as_ref(),
            &command,
            self.config.guard_timeout,
            host_monotonic_ns,
        )
    }

    /// Journals a guard close (`reopen_at` `None`) or a reopen at epoch
    /// `reopen_at` of `guard` in the driver in `dir` that `requester`'s
    /// role does not allow, refused `not_authorised`, and sends nothing
    /// (karyos#719; [`operations::refuse_unauthorised`]).
    pub fn guard_refused(
        &mut self,
        dir: &Path,
        guard: u64,
        reopen_at: Option<u64>,
        requester: Requester,
        reason: &[u8],
    ) {
        let operation = self.allocate_operation();
        let command = operations::Command {
            dir,
            guard,
            transition: reopen_at.map_or(
                operations::Transition::Close,
                operations::Transition::Reopen,
            ),
            instance: None,
            operation,
            operator: requester.operator,
            relay: requester.relay,
            reason: operations::cut_reason(reason),
            timeout: self.config.guard_timeout,
        };
        operations::refuse_unauthorised(self.journal.as_mut(), &command, host_monotonic_ns());
    }

    /// Journals a retention `operation` on Archive `recording` that
    /// `requester`'s role does not allow, refused `not_authorised`, and
    /// sends nothing (karyos#719; [`crate::retention::refuse_unauthorised`]).
    pub fn retention_refused(
        &mut self,
        operation: crate::retention::Operation,
        recording: u64,
        requester: Requester,
        reason: &[u8],
    ) {
        let id = self.allocate_operation();
        let command = crate::retention::Command {
            operation,
            recording,
            id,
            operator: requester.operator,
            relay: requester.relay,
            reason,
        };
        crate::retention::refuse_unauthorised(self.journal.as_mut(), &command, host_monotonic_ns());
    }

    /// Makes a retention `operation` on the agent's own operations journal
    /// for `requester` with `reason` (ADR-0113): the reserved recording
    /// name `journal`. `authorised` is false for a purge the requester's
    /// role does not allow, which is refused and journalled.
    pub fn journal_retention(
        &mut self,
        operation: crate::retention::Operation,
        requester: Requester,
        reason: &[u8],
        authorised: bool,
    ) -> crate::retention::RetentionAnswer {
        let id = self.allocate_operation();
        let command = crate::retention::Command {
            operation,
            recording: crate::retention::JOURNAL_SUBJECT,
            id,
            operator: requester.operator,
            relay: requester.relay,
            reason,
        };
        // Every id used is retained: pending, within its outcome's
        // retention, or a tombstone (karyos#738, karyos#739).
        let used = &self.used_ids;
        let retained = |operation: u64| used.contains(&operation);
        crate::retention::journal_command(
            self.journal.as_mut(),
            &command,
            (authorised, &retained),
            host_monotonic_ns,
        )
    }

    /// Closes guard `guard` of the driver in `dir` for operator `uid`
    /// with `reason`, journalled (M10b; see `operations`).
    pub fn guard_close(&mut self, dir: &Path, guard: u64, uid: u32, reason: &[u8]) -> GuardAnswer {
        self.guard_command(
            dir,
            guard,
            operations::Transition::Close,
            Requester::local(uid),
            reason,
            (None, None),
        )
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
        self.guard_command(
            dir,
            guard,
            operations::Transition::Close,
            requester,
            reason,
            (None, None),
        )
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
        if self.reopen_marked() {
            return GuardAnswer::TwoPersonRequired;
        }
        self.guard_command(
            dir,
            guard,
            operations::Transition::Reopen(expected),
            requester,
            reason,
            (None, None),
        )
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
        if self.reopen_marked() {
            return GuardAnswer::TwoPersonRequired;
        }
        self.guard_command(
            dir,
            guard,
            operations::Transition::Reopen(expected),
            Requester::local(uid),
            reason,
            (None, None),
        )
    }

    /// Previews guard operation `kind` on guard `guard` of the driver in
    /// `dir` for `requester` with `reason` (R-CORE-18, karyos#738; see
    /// [`crate::preview`]): the guard's state as last followed in the
    /// driver's audit, the epoch after, and a token a submit names.
    pub fn guard_preview_for(
        &mut self,
        kind: crate::preview::PreviewKind,
        dir: &Path,
        guard: u64,
        requester: Requester,
        reason: &[u8],
    ) -> crate::preview::PreviewAnswer {
        use crate::preview::{Bound, PreviewAnswer, Seen, last_state};
        let Some(driver) = self.drivers.iter().find(|driver| driver.dir == dir) else {
            return PreviewAnswer::UnknownDriver;
        };
        let (Some(_), Some(instance)) = (driver.tool.as_ref(), driver.instance) else {
            return PreviewAnswer::Unattached;
        };
        let audit = driver.guards.feed().records;
        let seen = Seen {
            instance,
            state: last_state(&audit, guard),
        };
        let bound = Bound {
            kind,
            dir: dir.to_path_buf(),
            guard,
            requester,
            reason: operations::cut_reason(reason).to_vec(),
        };
        self.previews
            .preview(bound, seen, std::time::Instant::now())
    }

    /// Submits the previewed operation `kind` named by `token`, under the
    /// caller's operation id `operation` (R-CORE-18, karyos#738; see
    /// [`crate::preview`]): sent only when the token's principal, target
    /// and parameters are this request's and the driver is the instance
    /// previewed, at the previewed epoch, which the driver checks with the
    /// transition.
    ///
    /// # Errors
    ///
    /// The [`crate::preview::SubmitRefusal`] that refused it, with nothing
    /// sent.
    pub fn guard_submit_for(
        &mut self,
        (operation, token): (u64, Option<crate::preview::Token>),
        kind: crate::preview::PreviewKind,
        dir: &Path,
        guard: u64,
        requester: Requester,
        reason: &[u8],
    ) -> Result<GuardAnswer, crate::preview::SubmitRefusal> {
        use crate::preview::{Bound, PreviewKind, SubmitRefusal, Used};
        // A marked reopen enters the approval flow ([`Agent::submit_for`]),
        // never this path (karyos#739).
        if kind == PreviewKind::Reopen && self.reopen_marked() {
            return Ok(GuardAnswer::TwoPersonRequired);
        }
        let instance = self
            .drivers
            .iter()
            .find(|driver| driver.dir == dir)
            .and_then(|driver| driver.instance);
        let bound = Bound {
            kind,
            dir: dir.to_path_buf(),
            guard,
            requester,
            reason: operations::cut_reason(reason).to_vec(),
        };
        // A used id: its retained outcome, or its refusal; never sent.
        if let Some(answer) = self.outcomes.answer(operation, &bound, host_monotonic_ns()) {
            return answer;
        }
        // An id the agent used for an operation of its own (karyos#738
        // review): a conflict, never sent.
        if self.used_ids.contains(&operation) {
            return Err(SubmitRefusal::OperationConflict);
        }
        // A fresh id needs its preview's token; a retry above needs none.
        let token = token.ok_or(SubmitRefusal::TokenUnknown)?;
        let epoch = self
            .previews
            .take(token, &bound, instance, std::time::Instant::now())?;
        let transition = match kind {
            PreviewKind::Close => operations::Transition::CloseAt(epoch),
            PreviewKind::Reopen => operations::Transition::Reopen(epoch),
        };
        let answer = self.guard_command(
            dir,
            guard,
            transition,
            requester,
            reason,
            (Some(operation), instance),
        );
        // Sent: the id is used up, whatever came of it.
        if matches!(
            answer,
            GuardAnswer::State { .. } | GuardAnswer::Refused { .. } | GuardAnswer::NoAnswer { .. }
        ) {
            let _ = self.used_ids.insert(operation);
            let used = Used {
                kind,
                dir: Some(bound.dir),
                guard,
                requester,
                reason: bound.reason,
            };
            let now = host_monotonic_ns();
            // Journalled as one submit, with the driver target, the full
            // outcome and the boot: what a restart rebuilds (karyos#738).
            if let Some(journal) = self.journal.as_mut() {
                let record = crate::preview::submitted_record(
                    operation,
                    &used,
                    (epoch, answer),
                    (now, &self.boot),
                );
                let _ = journal.append(&record, now);
            }
            self.outcomes.record(operation, used, answer, now);
        }
        Ok(answer)
    }

    /// Whether this deployment marks guard reopens for two people
    /// (karyos#739).
    fn reopen_marked(&self) -> bool {
        self.config
            .two_person
            .contains(&crate::two_person::TwoPersonClass::GuardReopen)
    }

    /// Whether this deployment marks `command` of Cluster `cluster` for two
    /// people (karyos#739).
    fn command_marked(&self, cluster: &str, command: &str) -> bool {
        self.config.two_person.iter().any(|class| {
            matches!(
                class,
                crate::two_person::TwoPersonClass::ClusterCommand {
                    cluster: marked,
                    command: name,
                } if marked == cluster && name == command
            )
        })
    }

    /// Detaches the Cluster attached as `name`; `false` when none is. An
    /// operation pending on it ends `target changed` at its approval, even
    /// after a new attach under the name (karyos#739).
    pub fn detach_cluster(&mut self, name: &str) -> bool {
        self.clusters.detach(name)
    }

    /// Submits a previewed guard operation as [`Agent::guard_submit_for`]
    /// does; a reopen this deployment marks for two people enters the
    /// approval flow instead (R-CORE-20, karyos#739; see
    /// [`crate::approval`]): it is answered pending once its request is
    /// journalled durably, which consumes the token and reserves the id,
    /// and nothing is sent.
    pub fn submit_for(
        &mut self,
        (operation, token): (u64, Option<crate::preview::Token>),
        kind: crate::preview::PreviewKind,
        dir: &Path,
        guard: u64,
        requester: Requester,
        reason: &[u8],
    ) -> crate::approval::ApprovalAnswer {
        use crate::approval::{ApprovalAnswer, Request, Target};
        use crate::preview::{Bound, PreviewKind, SubmitRefusal};
        if kind != PreviewKind::Reopen || !self.reopen_marked() {
            return match self.guard_submit_for(
                (operation, token),
                kind,
                dir,
                guard,
                requester,
                reason,
            ) {
                Ok(answer) => ApprovalAnswer::Guard(answer),
                Err(refusal) => ApprovalAnswer::Submit(refusal),
            };
        }
        let now = host_monotonic_ns();
        self.sweep_approvals(now);
        let mut request = Request {
            requester,
            target: Target::Guard {
                dir: dir.to_path_buf(),
                instance: 0,
                guard,
                epoch: 0,
            },
            reason: operations::cut_reason(reason).to_vec(),
        };
        // The exact request again: pending, or its retained outcome, with
        // no token needed (ADR-0112 point 9).
        if let Some(answer) = self.approvals.retry(operation, &request, now) {
            return answer;
        }
        let bound = Bound {
            kind,
            dir: dir.to_path_buf(),
            guard,
            requester,
            reason: request.reason.clone(),
        };
        if let Some(answer) = self.outcomes.answer(operation, &bound, now) {
            return match answer {
                Ok(answer) => ApprovalAnswer::Guard(answer),
                Err(refusal) => ApprovalAnswer::Submit(refusal),
            };
        }
        if self.used_ids.contains(&operation) {
            return ApprovalAnswer::Submit(SubmitRefusal::OperationConflict);
        }
        let Some(token) = token else {
            return ApprovalAnswer::Submit(SubmitRefusal::TokenUnknown);
        };
        let current = self
            .drivers
            .iter()
            .find(|driver| driver.dir == dir)
            .and_then(|driver| driver.instance);
        // Checked, not used up: the token goes with the durable record.
        let epoch = match self
            .previews
            .peek(token, &bound, current, std::time::Instant::now())
        {
            Ok(epoch) => epoch,
            Err(refusal) => return ApprovalAnswer::Submit(refusal),
        };
        let Some(current) = current else {
            return ApprovalAnswer::Submit(SubmitRefusal::TargetChanged);
        };
        request.target = Target::Guard {
            dir: dir.to_path_buf(),
            instance: current,
            guard,
            epoch,
        };
        self.pend(operation, request, now, Some(token))
    }

    /// Makes admin command `command` as [`Agent::cluster_command_for`]
    /// does; a command this deployment marks for two people enters the
    /// approval flow instead (R-CORE-20, karyos#739), after the checks a
    /// direct command has: answered pending once its request is journalled
    /// durably, which reserves the id, and nothing is sent.
    pub fn cluster_command_answer_for(
        &mut self,
        (cluster, command, parameters): (&str, &str, &[u8]),
        operation: u64,
        (requester, clearance): (Requester, crate::cluster_admin::Clearance),
        reason: &[u8],
    ) -> crate::approval::ApprovalAnswer {
        use crate::approval::{ApprovalAnswer, Request, Target};
        if !self.command_marked(cluster, command) {
            return ApprovalAnswer::Cluster(self.cluster_command_for(
                (cluster, command, parameters),
                operation,
                (requester, clearance),
                reason,
            ));
        }
        let now = host_monotonic_ns();
        self.sweep_approvals(now);
        let reason = operations::cut_reason(reason);
        let mut request = Request {
            requester,
            target: Target::Cluster {
                cluster: cluster.to_owned(),
                instance: 0,
                command: command.to_owned(),
                parameters: parameters.to_vec(),
            },
            reason: reason.to_vec(),
        };
        if let Some(answer) = self.approvals.retry(operation, &request, now) {
            return answer;
        }
        let checked = crate::cluster_admin::Command {
            cluster,
            command,
            parameters,
            operation,
            operator: requester.operator,
            relay: requester.relay,
            clearance,
            reason,
        };
        let used_ids = &self.used_ids;
        let mut clock = host_monotonic_ns;
        let instance = match crate::cluster_admin::check(
            self.journal.as_mut(),
            &self.clusters,
            &checked,
            &mut |id, _| used_ids.contains(&id),
            &mut clock,
        ) {
            Ok(attached) => attached.instance(),
            Err(answer) => return ApprovalAnswer::Cluster(answer),
        };
        if let Target::Cluster {
            instance: bound, ..
        } = &mut request.target
        {
            *bound = instance;
        }
        self.pend(operation, request, now, None)
    }

    /// Enters `request` as `operation` at `now`: pending once its
    /// `ApprovalRequested` is durable, which uses up `token` and reserves
    /// the id; refused `journal unavailable` otherwise, the token and the
    /// id as they were (karyos#739).
    fn pend(
        &mut self,
        operation: u64,
        request: crate::approval::Request,
        now: u64,
        token: Option<crate::preview::Token>,
    ) -> crate::approval::ApprovalAnswer {
        use crate::approval::{ApprovalAnswer, Refusal, nanos, requested_record};
        let wait = self.config.approval_wait;
        let record = requested_record(operation, &request, wait, (now, &self.boot));
        let durable = self
            .journal
            .as_mut()
            .is_some_and(|journal| journal.append_durable(&record, now).is_ok());
        if !durable {
            return ApprovalAnswer::Refused(Refusal::JournalUnavailable);
        }
        if let Some(token) = token {
            self.previews.remove(token);
        }
        let _ = self.used_ids.insert(operation);
        self.approvals
            .pend(operation, request, now.saturating_add(nanos(wait)));
        ApprovalAnswer::Pending {
            operation,
            expires_in_ms: u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Approves pending operation `operation` for `approver`, whose role
    /// may reopen guards (`may_reopen`) and grants `clearance` (R-CORE-20,
    /// karyos#739; see [`crate::approval`]): refused for the requester
    /// itself, a role that may not make the operation, an expired or ended
    /// operation; ended `target changed` for a target that changed;
    /// otherwise journalled durably and dispatched as a direct request is.
    pub fn approve_for(
        &mut self,
        operation: u64,
        approver: Requester,
        (may_reopen, clearance): (bool, crate::cluster_admin::Clearance),
    ) -> crate::approval::ApprovalAnswer {
        use crate::approval::{
            ApprovalAnswer, Approvals, End, EndCode, Refusal, State, Target, principal_record,
        };
        let now = host_monotonic_ns();
        // Expiry first (ADR-0112 point 5).
        self.sweep_approvals(now);
        let Some(entry) = self.approvals.get(operation) else {
            return ApprovalAnswer::Refused(if self.used_ids.contains(&operation) {
                Refusal::NotPending
            } else {
                Refusal::OperationIdUnknown
            });
        };
        if !matches!(entry.state, State::Pending { .. }) {
            // The role first: a completed operation's retained outcome is
            // only for a role that may approve it, never for any caller
            // that knows its id (karyos#739 review). A Cluster command
            // whose authority is not known now is refused.
            let allowed = match &entry.request.target {
                Target::Guard { .. } => may_reopen,
                Target::Cluster {
                    cluster, command, ..
                } => self
                    .clusters
                    .find(cluster)
                    .and_then(|attached| attached.authority(command))
                    .is_some_and(|authority| clearance.allows(authority)),
            };
            if !allowed {
                return ApprovalAnswer::Refused(Refusal::Forbidden);
            }
            return Approvals::state_answer(operation, &entry.state, now, false);
        }
        let request = entry.request.clone();
        if approver.operator == request.requester.operator {
            return ApprovalAnswer::Refused(Refusal::SamePrincipal);
        }
        let current = match &request.target {
            Target::Guard { dir, instance, .. } => {
                if !may_reopen {
                    return ApprovalAnswer::Refused(Refusal::Forbidden);
                }
                self.drivers
                    .iter()
                    .find(|driver| &driver.dir == dir)
                    .and_then(|driver| driver.instance)
                    == Some(*instance)
            }
            Target::Cluster {
                cluster,
                instance,
                command,
                ..
            } => {
                let attached = self.clusters.find(cluster);
                if attached
                    .and_then(|attached| attached.authority(command))
                    .is_some_and(|authority| !clearance.allows(authority))
                {
                    return ApprovalAnswer::Refused(Refusal::Forbidden);
                }
                attached.map(crate::cluster_admin::Attached::instance) == Some(*instance)
            }
        };
        if !current {
            self.end_unsent(operation, EndCode::TargetChanged, now);
            return ApprovalAnswer::Refused(Refusal::TargetChanged);
        }
        let record = principal_record(
            crate::journal::Kind::ApprovalGranted,
            operation,
            approver,
            (now, &self.boot),
        );
        let durable = self
            .journal
            .as_mut()
            .is_some_and(|journal| journal.append_durable(&record, now).is_ok());
        if !durable {
            return ApprovalAnswer::Refused(Refusal::JournalUnavailable);
        }
        self.approvals.set(operation, State::Granted);
        let requester = request.requester;
        let (end, answer) = match request.target {
            Target::Guard {
                dir,
                instance,
                guard,
                epoch,
            } => {
                let answer = self.guard_command(
                    &dir,
                    guard,
                    operations::Transition::Reopen(epoch),
                    requester,
                    &request.reason,
                    (Some(operation), Some(instance)),
                );
                let unsent = match answer {
                    GuardAnswer::State { .. }
                    | GuardAnswer::Refused { .. }
                    | GuardAnswer::NoAnswer { .. } => None,
                    GuardAnswer::InstanceChanged => Some(EndCode::TargetChanged),
                    GuardAnswer::JournalUnavailable => Some(EndCode::JournalUnavailable),
                    _ => Some(EndCode::DriverUnavailable),
                };
                if let Some(code) = unsent {
                    (End::Unsent(code), ApprovalAnswer::Refused(code.refusal()))
                } else {
                    let used = crate::preview::Used {
                        kind: crate::preview::PreviewKind::Reopen,
                        dir: Some(dir),
                        guard,
                        requester,
                        reason: request.reason,
                    };
                    let now = host_monotonic_ns();
                    // Its dispatch is journalled as a submit's: what a
                    // restart rebuilds (karyos#738).
                    if let Some(journal) = self.journal.as_mut() {
                        let record = crate::preview::submitted_record(
                            operation,
                            &used,
                            (epoch, answer),
                            (now, &self.boot),
                        );
                        let _ = journal.append(&record, now);
                    }
                    self.outcomes.record(operation, used, answer, now);
                    (End::Guard(answer), ApprovalAnswer::Guard(answer))
                }
            }
            Target::Cluster {
                cluster,
                command,
                parameters,
                ..
            } => {
                let checked = crate::cluster_admin::Command {
                    cluster: &cluster,
                    command: &command,
                    parameters: &parameters,
                    operation,
                    operator: requester.operator,
                    relay: requester.relay,
                    clearance,
                    reason: &request.reason,
                };
                // The id is reserved by the pending operation: free for
                // its own dispatch.
                let answer = crate::cluster_admin::cluster_command(
                    self.journal.as_mut(),
                    &self.clusters,
                    &checked,
                    (self.config.guard_timeout, |_, _| false),
                    host_monotonic_ns,
                );
                match answer {
                    crate::cluster_admin::ClusterAnswer::Busy => (
                        End::Unsent(EndCode::Busy),
                        ApprovalAnswer::Refused(Refusal::Busy),
                    ),
                    crate::cluster_admin::ClusterAnswer::JournalUnavailable => (
                        End::Unsent(EndCode::JournalUnavailable),
                        ApprovalAnswer::Refused(Refusal::JournalUnavailable),
                    ),
                    answer => (
                        End::Cluster(answer.clone()),
                        ApprovalAnswer::Cluster(answer),
                    ),
                }
            }
        };
        let now = host_monotonic_ns();
        match end {
            End::Unsent(code) => self.end_unsent(operation, code, now),
            end => self
                .approvals
                .set(operation, State::Ended { end, at: Some(now) }),
        }
        answer
    }

    /// Withdraws pending operation `operation` for `requester`: only its
    /// requester's operator id may (R-CORE-20, karyos#739).
    pub fn withdraw_for(
        &mut self,
        operation: u64,
        requester: Requester,
    ) -> crate::approval::ApprovalAnswer {
        use crate::approval::{ApprovalAnswer, Approvals, End, Refusal, State, principal_record};
        let now = host_monotonic_ns();
        self.sweep_approvals(now);
        let Some(entry) = self.approvals.get(operation) else {
            return ApprovalAnswer::Refused(if self.used_ids.contains(&operation) {
                Refusal::NotPending
            } else {
                Refusal::OperationIdUnknown
            });
        };
        if !matches!(entry.state, State::Pending { .. }) {
            return match Approvals::state_answer(operation, &entry.state, now, false) {
                expired @ ApprovalAnswer::Refused(Refusal::OperationExpired) => expired,
                _ => ApprovalAnswer::Refused(Refusal::NotPending),
            };
        }
        if entry.request.requester.operator != requester.operator {
            return ApprovalAnswer::Refused(Refusal::NotRequester);
        }
        let record = principal_record(
            crate::journal::Kind::ApprovalWithdrawn,
            operation,
            requester,
            (now, &self.boot),
        );
        let durable = self
            .journal
            .as_mut()
            .is_some_and(|journal| journal.append_durable(&record, now).is_ok());
        if !durable {
            return ApprovalAnswer::Refused(Refusal::JournalUnavailable);
        }
        self.approvals.set(
            operation,
            State::Ended {
                end: End::Withdrawn,
                at: Some(now),
            },
        );
        ApprovalAnswer::Withdrawn { operation }
    }

    /// Expires every pending operation whose deadline passed at `now`,
    /// journalled (karyos#739).
    fn sweep_approvals(&mut self, now: u64) {
        for operation in self.approvals.due(now) {
            self.end_unsent(operation, crate::approval::EndCode::Expired, now);
        }
    }

    /// Ends `operation` unsent for `code` at `now`, journalled. Nothing was
    /// sent, so it ends even when the record cannot be made durable.
    fn end_unsent(&mut self, operation: u64, code: crate::approval::EndCode, now: u64) {
        use crate::approval::{End, State, ended_record};
        if let Some(journal) = self.journal.as_mut() {
            let record = ended_record(operation, code, (now, &self.boot));
            let _ = journal.append_durable(&record, now);
        }
        self.approvals.set(
            operation,
            State::Ended {
                end: End::Unsent(code),
                at: Some(now),
            },
        );
    }

    /// The next operation id of the agent's own, skipping any a caller
    /// already used (karyos#738 review), and taken: no two operations share
    /// an id. Checked: at the end of the ids the last one is kept.
    fn allocate_operation(&mut self) -> u64 {
        loop {
            let id = self.next_operation;
            let Some(next) = id.checked_add(1) else {
                let _ = self.used_ids.insert(id);
                return id;
            };
            self.next_operation = next;
            if self.used_ids.insert(id) {
                return id;
            }
        }
    }

    fn guard_command(
        &mut self,
        dir: &Path,
        guard: u64,
        transition: operations::Transition,
        requester: Requester,
        reason: &[u8],
        (chosen, instance): (Option<u64>, Option<u128>),
    ) -> GuardAnswer {
        if !self.drivers.iter().any(|driver| driver.dir == dir) {
            return GuardAnswer::UnknownDriver;
        }
        let operation = match chosen {
            Some(operation) => operation,
            None => self.allocate_operation(),
        };
        let command = operations::Command {
            dir,
            guard,
            transition,
            instance,
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

    /// Makes rate policy `change` on a guarded stream of the driver in
    /// `dir`, for
    /// `requester` (R-CORE-21, karyos#740; see `operations`). The driver
    /// decides whether the safety path may take it; an administrator's
    /// change is refused unless its request is journalled durably first.
    /// A version the driver answers is kept for [`Agent::view`].
    pub fn rate_change_for(
        &mut self,
        dir: &Path,
        change: operations::RateChange,
        requester: Requester,
        reason: &[u8],
    ) -> RateAnswer {
        let operations::RateChange {
            stream,
            expected,
            policy,
            authority,
        } = change;
        if !self.drivers.iter().any(|driver| driver.dir == dir) {
            return RateAnswer::UnknownDriver;
        }
        let operation = self.allocate_operation();
        let command = operations::RateCommand {
            dir,
            stream,
            expected,
            policy,
            authority,
            operation,
            operator: requester.operator,
            relay: requester.relay,
            reason: operations::cut_reason(reason),
            timeout: self.config.guard_timeout,
        };
        let answer = operations::rate_command(self.journal.as_mut(), &command);
        if let RateAnswer::State {
            operation,
            stream,
            version,
        } = answer
        {
            self.note_rate(dir, stream, version, operation);
        }
        answer
    }

    /// Keeps `version` as stream `stream`'s, most recent last, within
    /// [`crate::api::MAX_RATE_VIEWS`].
    fn note_rate(
        &mut self,
        dir: &Path,
        stream: karyos_protocol::cnc::StreamKey,
        version: u64,
        operation: u64,
    ) {
        self.rates.retain(|rate| {
            !(rate.dir == dir
                && rate.stream_id == stream.stream_id
                && rate.session_id == stream.session_id)
        });
        if self.rates.len() >= crate::api::MAX_RATE_VIEWS && !self.rates.is_empty() {
            self.rates.remove(0);
        }
        self.rates.push(crate::api::RateView::new(
            dir.to_path_buf(),
            stream.stream_id,
            stream.session_id,
            version,
            operation,
        ));
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
            .map(|_| ())
    }

    /// As [`Agent::acknowledge_gap`], for `requester` (karyos#708): the
    /// interval acknowledged, as the view showed it (karyos#726). The
    /// acknowledgement says the interval was seen and nothing more: what
    /// happened in it stays unknown.
    ///
    /// # Errors
    ///
    /// As [`Agent::acknowledge_gap`].
    pub fn acknowledge_gap_for(
        &mut self,
        position: u64,
        requester: Requester,
    ) -> Result<GapView, JournalError> {
        let uid = requester.operator;
        match self.journal.as_mut() {
            Some(journal) => {
                let gap = journal
                    .gap()
                    .filter(|gap| gap.position == position)
                    .ok_or(JournalError::NoGap)?;
                journal.acknowledge_gap_relayed(
                    position,
                    u64::from(uid),
                    requester.relay,
                    host_monotonic_ns(),
                )?;
                Ok(gap_view(gap))
            }
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
                    Ok(gap_view(gap))
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
            unsealed: journal.is_none_or(Journal::unsealed),
            unavailable: journal.is_none_or(Journal::unavailable),
            error: self.journal_error.clone(),
            failed_appends: journal.map_or(0, Journal::failed_appends),
            gap: gap.map(gap_view),
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
            integrity: journal
                .and_then(Journal::integrity)
                .map(|integrity| integrity.ranges.clone()),
            integrity_truncated: journal
                .and_then(Journal::integrity)
                .is_some_and(|integrity| integrity.truncated),
            hold: journal.map(Journal::hold),
            policy: journal.and_then(Journal::policy),
            purged: journal
                .and_then(Journal::integrity)
                .map(|integrity| integrity.purged.clone())
                .unwrap_or_default(),
            purge_pending: journal.is_some_and(Journal::purge_pending),
            head: journal.and_then(Journal::head),
        })
    }

    /// Appends a product service's record to the operations journal for
    /// `requester` (R-CORE-42, karyos#773; [`crate::product`] states the
    /// contract): durably when `append` waits for it, refused when the
    /// journal cannot record it, and an import only when it names an
    /// unknown interval the journal holds. Nothing in it is interpreted.
    pub fn journal_append(
        &mut self,
        append: &crate::product::ProductAppend<'_>,
        requester: Requester,
    ) -> crate::product::ProductAnswer {
        use crate::product::ProductAnswer;

        let Some(journal) = self.journal.as_mut() else {
            return ProductAnswer::JournalUnavailable;
        };
        if let Some(import) = append.import
            && (import.recording != journal.recording()
                || !journal.holds_unknown_interval(import.interval))
        {
            // An unavailable journal holds nothing to name.
            if journal.unavailable() {
                return ProductAnswer::JournalUnavailable;
            }
            return ProductAnswer::NotAnInterval {
                recording: import.recording,
                position: import.interval,
            };
        }
        let now = host_monotonic_ns();
        let record = append.record(requester, now);
        let written = if append.waits() {
            journal.append_durable(&record, now)
        } else {
            journal.append(&record, now)
        };
        match written {
            Ok(position) => ProductAnswer::Journalled {
                recording: journal.recording(),
                position,
                durable: append.waits(),
            },
            Err(_) => ProductAnswer::JournalUnavailable,
        }
    }

    /// Makes every journal record already written durable before a view
    /// is taken, so the view's `journal.head` follows every record
    /// written before it (R-CORE-14; karyos#725; [`Journal::settle`]).
    pub fn settle_journal(&mut self) {
        if let Some(journal) = self.journal.as_mut() {
            journal.settle(host_monotonic_ns());
        }
    }

    /// A page of the operations journal's history (R-CORE-14;
    /// karyos#725): up to `count` records from `from`, or from the
    /// retention floor (see [`crate::journal::history`]).
    ///
    /// # Errors
    ///
    /// [`HistoryRefusal::NotConfigured`](crate::journal::HistoryRefusal)
    /// without a journal, and [`Journal::history`]'s refusals.
    pub fn journal_history(
        &mut self,
        from: Option<crate::journal::HistoryCursor>,
        count: usize,
    ) -> Result<crate::journal::HistoryPage, crate::journal::HistoryRefusal> {
        use crate::journal::HistoryRefusal;
        if self.config.journal.is_none() {
            return Err(HistoryRefusal::NotConfigured);
        }
        self.journal
            .as_mut()
            .ok_or(HistoryRefusal::Unavailable)?
            .history(from, count)
    }

    /// Attaches to every driver it is not attached to, reads every one it
    /// is, and notes those that exited. A driver it cannot attach to is
    /// reported unavailable with the reason; nothing here fails the agent.
    pub fn refresh(&mut self) {
        let (timeout, trace) = (self.config.attach_timeout, self.config.trace);
        for driver in &mut self.drivers {
            driver.refresh(timeout, trace, &self.config.alerts);
        }
        // The journal's integrity, again once its last verification is
        // old (karyos#702).
        // A journal hold in memory only becomes durable once it can
        // (ADR-0113, point 6).
        if let Some(journal) = self.journal.as_mut() {
            journal.retry_hold();
            journal.verify_if_due(host_monotonic_ns());
        }
        // The periodic sweep of the approvals past their deadline
        // (karyos#739).
        self.sweep_approvals(host_monotonic_ns());
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

    /// The `limits` dimensions (R-CORE-38) as this agent answers them:
    /// [`crate::server::LIMITS`], with `trace.points_per_client` and
    /// `trace.point_registrations_per_client` the attached drivers'
    /// configured bounds (karyos#868). Each driver publishes its bounds as
    /// the gauges `trace points per client` and `trace point registrations
    /// per client`; over several attached drivers the smallest is the
    /// bound, so a client within it is within every one. With no attached
    /// driver that publishes one, it is the driver's default.
    #[must_use]
    pub fn limits(&self) -> [crate::api::Limit; crate::server::LIMITS.len()] {
        let mut limits = crate::server::LIMITS;
        for (name, label) in [
            ("trace.points_per_client", TRACE_POINTS_PER_CLIENT),
            (
                "trace.point_registrations_per_client",
                TRACE_POINT_REGISTRATIONS_PER_CLIENT,
            ),
        ] {
            let configured = self
                .drivers
                .iter()
                .filter(|driver| driver.tool.is_some())
                .filter_map(|driver| driver.sample.as_ref())
                .filter_map(|sample| {
                    sample
                        .counters
                        .iter()
                        .find(|counter| {
                            counter.stream == 0
                                && counter.type_id == karyos_sys::counters::TYPE_GAUGE
                                && counter.label == label
                        })
                        .map(|counter| counter.value)
                })
                .min();
            if let Some(configured) = configured
                && let Some(limit) = limits.iter_mut().find(|limit| limit.name == name)
            {
                limit.bound = Some(configured);
            }
        }
        limits
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
            rates: self.rates.clone(),
        }
    }

    /// Its capabilities for a caller who may close guards (`close`),
    /// reopen them (`reopen`), acknowledge the journal's unknown interval
    /// (`acknowledge`), write the join registry (`register`,
    /// karyos#736) and append a product's records to the journal
    /// (`append`, karyos#773), in [`crate::api::CAPABILITIES`] order
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
        append: bool,
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
        // The history reads a journal that opened and can still be read.
        let history_off = match (&self.config.journal, &self.journal) {
            (None, _) => Some("not_configured"),
            (Some(_), Some(journal)) if journal.head().is_some() => None,
            (Some(_), _) => Some("journal_unavailable"),
        };
        let catalog = self.drivers.iter().any(|driver| driver.catalog.is_some());
        // The admin command clearance these flags name: an administrator
        // acknowledges, an operator or a risk officer closes (karyos#772).
        let clearance = if acknowledge {
            crate::cluster_admin::Clearance::Administrator
        } else if close {
            crate::cluster_admin::Clearance::Operator
        } else {
            crate::cluster_admin::Clearance::None
        };
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
                    | "join-registry" | "clocks" | "rate-limits" => (None, true),
                    "join-put" => (None, register),
                    // Every role reads the history the view summarises.
                    "journal-history" => (history_off, true),
                    // A product service's records need a journal that
                    // records (karyos#773).
                    "journal-append" => (history_off, append),
                    // The safety path is a closer's; an administrator's
                    // change needs the journal, which the answer reports.
                    "rate-change" => (None, close || acknowledge),
                    // A preview and its submit serve the operations they
                    // preview; a reopen's submit still needs the journal,
                    // which its answer reports (karyos#738).
                    "guard-preview" | "submit" => (None, close || reopen),
                    // Admin commands need a Cluster attached and a journal
                    // that records, and are offered to a role only when an
                    // attached Cluster registers a command it may make
                    // (karyos#772).
                    "cluster-command" => (
                        if self.clusters.is_empty() {
                            Some("not_configured")
                        } else {
                            reopen_off
                        },
                        self.clusters.any_allowed(clearance),
                    ),
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
                    self.refused_at_attach = self
                        .tool
                        .as_ref()
                        .map(|tool| tool.trace_mirror().network_journals_refused());
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

/// `gap` as the view and the answers show it.
fn gap_view(gap: Gap) -> GapView {
    GapView {
        position: gap.position,
        from: gap.from,
        to: gap.to,
        reason: gap.reason.name(),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod approval_tests;

#[cfg(test)]
mod product_tests;
