// SPDX-License-Identifier: Apache-2.0

//! The agent: one tool attach per configured driver, and the model it
//! keeps of each.

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
use crate::journal::{Journal, JournalError};
use crate::model::{self, Cell, Follower};
use crate::operations::{self, GuardAnswer};
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
        }
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
    client_counters: Vec<Counter>,
    errors: Follower<ErrorEntry>,
    losses: Follower<LossEntry>,
    guards: Follower<GuardEntry>,
    trace: Option<TraceWindow>,
    alerts: Alerts,
    catalog: Option<CatalogWatch>,
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
    /// The next guard operation's id.
    next_operation: u64,
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
                client_counters: Vec::new(),
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
            })
            .collect();
        let (journal, journal_error) = match config.journal.as_deref() {
            None => (None, None),
            Some(dir) => match Journal::open(dir, host_monotonic_ns()) {
                Ok(journal) => (Some(journal), None),
                Err(error) => (None, Some(error.to_string())),
            },
        };
        Self {
            config,
            drivers,
            journal,
            journal_error,
            // Ids from the agent's start time: unique across restarts.
            next_operation: host_monotonic_ns().max(1),
        }
    }

    /// Closes guard `guard` of the driver in `dir` for operator `uid`
    /// with `reason`, journalled (M10b; see `operations`).
    pub fn guard_close(&mut self, dir: &Path, guard: u64, uid: u32, reason: &[u8]) -> GuardAnswer {
        self.guard_command(dir, guard, None, uid, reason)
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
        self.guard_command(dir, guard, Some(expected), uid, reason)
    }

    fn guard_command(
        &mut self,
        dir: &Path,
        guard: u64,
        reopen: Option<u64>,
        uid: u32,
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
            operator: uid,
            // Cut once, so the digest covers what is journalled (DESIGN's
            // P2 on #487).
            reason: operations::cut_reason(reason),
            timeout: self.config.guard_timeout,
        };
        operations::guard_command(self.journal.as_mut(), &command)
    }

    /// Records administrator `uid`'s acknowledgement of the open unknown
    /// interval at `position` (M10b).
    ///
    /// # Errors
    ///
    /// [`JournalError::NoGap`] when there is no journal or that interval
    /// is not the open one, and the journal's errors.
    pub fn acknowledge_gap(&mut self, position: u64, uid: u32) -> Result<(), JournalError> {
        self.journal
            .as_mut()
            .ok_or(JournalError::NoGap)?
            .acknowledge_gap(position, u64::from(uid), host_monotonic_ns())
    }

    /// The journal's state, for the view.
    fn journal_view(&self) -> Option<JournalView> {
        self.config.journal.as_ref()?;
        let journal = self.journal.as_ref();
        let gap = journal.and_then(Journal::gap);
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

    /// What the agent knows, as API v1.
    #[must_use]
    pub fn view(&self) -> AgentView {
        AgentView {
            version: API_VERSION,
            drivers: self.drivers.iter().map(Driver::view).collect(),
            journal: self.journal_view(),
        }
    }
}

impl Driver {
    fn refresh(&mut self, timeout: Duration, trace: WindowConfig, rules: &AlertRules) {
        if self.tool.is_none() {
            match attach_tool(&self.dir, timeout) {
                Ok(tool) => {
                    // A new instance is a new driver: its rings start over.
                    if self.instance != Some(tool.instance()) {
                        self.errors.restart();
                        self.losses.restart();
                        self.guards.restart();
                        self.alerts.restart();
                        self.trace = Some(TraceWindow::new(trace, driver_id(tool.instance())));
                    }
                    self.instance = Some(tool.instance());
                    self.state = DriverState::Attached;
                    self.tool = Some(tool);
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
        self.sample = Some(read_sample(tool.counters()));
        self.client_counters = read_cells(tool.client_counters())
            .iter()
            .map(|(metadata, value)| model::counter(metadata, *value))
            .collect();
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
        match tool.driver_closed() {
            Ok(false) => return,
            Ok(true) => {
                self.tool = None;
                self.state = DriverState::Closed;
            }
            Err(error) => {
                self.tool = None;
                self.state = DriverState::Unavailable {
                    reason: error.to_string(),
                };
            }
        }
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
        }
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
fn read_sample(counters: &CountersReader) -> Sample {
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
    model::sample(&cells, consistent, host_monotonic_ns())
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
