// SPDX-License-Identifier: Apache-2.0

//! The agent: one tool attach per configured driver, and the model it
//! keeps of each.

use std::path::PathBuf;
use std::time::Duration;

use karyos_client::tool::{RemoteTool, attach_tool};
use karyos_sys::counters::{CellRead, CountersReader, PassRead, read_pass};
use karyos_sys::host_clock::host_monotonic_ns;

use crate::api::{
    API_VERSION, AgentView, Counter, DriverState, DriverView, ErrorEntry, GuardEntry, LossEntry,
    Sample,
};
use crate::model::{self, Cell, Follower};
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
        }
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
}

/// The agent. Each driver it is attached to counts one tool against the
/// driver's `max_tools`; a driver that exits releases it.
#[derive(Debug)]
pub struct Agent {
    config: AgentConfig,
    drivers: Vec<Driver>,
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
            })
            .collect();
        Self { config, drivers }
    }

    /// Attaches to every driver it is not attached to, reads every one it
    /// is, and notes those that exited. A driver it cannot attach to is
    /// reported unavailable with the reason; nothing here fails the agent.
    pub fn refresh(&mut self) {
        let (timeout, trace) = (self.config.attach_timeout, self.config.trace);
        for driver in &mut self.drivers {
            driver.refresh(timeout, trace);
        }
    }

    /// What the agent knows, as API v1.
    #[must_use]
    pub fn view(&self) -> AgentView {
        AgentView {
            version: API_VERSION,
            drivers: self.drivers.iter().map(Driver::view).collect(),
        }
    }
}

impl Driver {
    fn refresh(&mut self, timeout: Duration, trace: WindowConfig) {
        if self.tool.is_none() {
            match attach_tool(&self.dir, timeout) {
                Ok(tool) => {
                    // A new instance is a new driver: its rings start over.
                    if self.instance != Some(tool.instance()) {
                        self.errors.restart();
                        self.losses.restart();
                        self.guards.restart();
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
        match tool.driver_closed() {
            Ok(false) => {}
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
        });
    });
    guards.cursor = cursor;
    guards.count(scan.delivered, scan.overwritten);
    kept.into_iter().for_each(|entry| guards.push(entry));
}
