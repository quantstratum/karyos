// SPDX-License-Identifier: Apache-2.0

//! API v1: what the agent reports, as Rust types (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M6). No transport and
//! no encoding: M7 serves these over a local socket and M8 exposes them
//! to Prometheus. Every type is `#[non_exhaustive]`, so v1 can gain
//! fields; a change that removes or retypes one is a new version.

use std::path::PathBuf;

/// The version of these types.
pub const API_VERSION: u32 = 1;

/// Everything the agent knows, at one refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentView {
    /// [`API_VERSION`].
    pub version: u32,
    /// One entry per configured driver directory, in configuration order.
    pub drivers: Vec<DriverView>,
}

/// One configured driver.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DriverView {
    /// The driver's admission socket directory.
    pub dir: PathBuf,
    /// Whether the agent is attached.
    pub state: DriverState,
    /// The driver instance id of the last attach, if there was one.
    pub instance: Option<u128>,
    /// The driver counters, positions and lag of the last refresh.
    pub sample: Option<Sample>,
    /// The client counters of the last refresh.
    pub client_counters: Vec<Counter>,
    /// The error log's records the agent followed.
    pub errors: Feed<ErrorEntry>,
    /// The loss report's records the agent followed.
    pub losses: Feed<LossEntry>,
    /// The guard audit ring's records the agent followed.
    pub guards: Feed<GuardEntry>,
    /// Per publication lane, the observed latencies within the trace
    /// window (M6c): never trace verdicts.
    pub latencies: Vec<LaneLatency>,
    /// What the trace window counted.
    pub trace: TraceCounts,
}

/// Whether the agent is attached to a driver.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DriverState {
    /// Attached and the driver is running.
    Attached,
    /// The driver closed the connection: it exited. The agent released
    /// its tool slot and attaches again at a later refresh.
    Closed,
    /// No attach yet, or the last one failed.
    Unavailable {
        /// Why.
        reason: String,
    },
}

/// One sampling pass of the driver counters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Sample {
    /// The values come from one completed pass; when false they may mix
    /// passes, and the differences below may be implausible.
    pub consistent: bool,
    /// Whether the driver completed a sampling pass yet.
    pub sampled: bool,
    /// Host `CLOCK_MONOTONIC` nanoseconds since the pass, if known.
    pub age_ns: Option<u64>,
    /// Every allocated driver counter that is not a position, by key.
    pub counters: Vec<Counter>,
    /// Positions and lag per stream lane.
    pub lanes: Vec<Lane>,
}

/// One counter cell.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counter {
    /// Its label.
    pub label: String,
    /// Its type (`TYPE_EVENT` 1, `TYPE_GAUGE` 2, `TYPE_POSITION` 4,
    /// `TYPE_TIMESTAMP` 5).
    pub type_id: u64,
    /// The stream registration, 0 for driver-wide counters.
    pub stream: u64,
    /// The lane.
    pub lane: u8,
    /// The participant kind (`KIND_*`).
    pub kind: u8,
    /// The participant or client registration, 0 when none.
    pub participant: u64,
    /// Its value.
    pub value: u64,
}

/// One stream lane's positions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lane {
    /// The stream registration.
    pub stream: u64,
    /// The lane.
    pub lane: u8,
    /// The publisher limit.
    pub limit: Option<u64>,
    /// The head.
    pub head: Option<u64>,
    /// The retention floor.
    pub floor: Option<u64>,
    /// `limit - head`, signed; `None` when a position is missing or the
    /// difference does not fit.
    pub headroom: Option<i64>,
    /// Each subscriber's position and lag.
    pub subscribers: Vec<Subscriber>,
}

/// One subscriber of a stream lane.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Subscriber {
    /// Its registration.
    pub registration: u64,
    /// Its position cell's label.
    pub label: String,
    /// Its position.
    pub position: u64,
    /// `head - position`, signed; `None` when the head is missing or the
    /// difference does not fit.
    pub lag: Option<i64>,
}

/// The records of a diagnostic ring the agent followed: the newest at most
/// the configured history, oldest first, with what the agent missed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Feed<T> {
    /// The records kept.
    pub records: Vec<T>,
    /// Records read from the current driver instance.
    pub delivered: u64,
    /// Records the ring overwrote before the agent read them: a lapped
    /// cursor.
    pub overwritten: u64,
}

impl<T> Default for Feed<T> {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            delivered: 0,
            overwritten: 0,
        }
    }
}

/// One error log record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrorEntry {
    /// Its sequence in the ring.
    pub seq: u64,
    /// First occurrence, host `CLOCK_MONOTONIC` nanoseconds.
    pub first: u64,
    /// Last occurrence.
    pub last: u64,
    /// Occurrences.
    pub occurrences: u64,
    /// The error code.
    pub code: u32,
    /// The agent that reported it.
    pub source: u16,
    /// Its key: a stream or client registration, and a detail value.
    pub key: [u64; 2],
    /// The message.
    pub message: String,
}

/// One loss report record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LossEntry {
    /// Its sequence in the ring.
    pub seq: u64,
    /// Host `CLOCK_MONOTONIC` nanoseconds.
    pub time: u64,
    /// The loss kind.
    pub kind: u16,
    /// Its reason.
    pub reason: u16,
    /// The lane.
    pub lane: u8,
    /// The stream id.
    pub stream_id: u64,
    /// The stream registration of the publication's identity.
    pub stream_registration: u64,
    /// The lost range, from (inclusive).
    pub from: u64,
    /// The lost range, to (exclusive).
    pub to: u64,
    /// The reporting participant's registration, 0 for the driver.
    pub participant: u64,
    /// The reporting client's registration, 0 for the driver.
    pub client: u64,
}

/// One guard transition, refusals included.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuardEntry {
    /// Its sequence in the ring.
    pub seq: u64,
    /// Host `CLOCK_MONOTONIC` nanoseconds.
    pub time: u64,
    /// The guard id.
    pub guard: u64,
    /// The guard word before.
    pub before: u64,
    /// The guard word after.
    pub after: u64,
    /// The requester's operation id.
    pub operation: u64,
    /// 0 the in-process caller, 1 an admitted client.
    pub requester_kind: u8,
    /// The client id for a client, else 0.
    pub requester: u64,
    /// 1 closed, 2 already closed, 3 reopened, 4 refused.
    pub outcome: u8,
    /// The control error code of a refusal, else 0.
    pub refusal: u16,
}

/// One publication lane's latencies within the trace window: the pairs of
/// a message's `Publish` and each of its `SubscriberPoll`s the mirror
/// delivered, in nanoseconds. Not a trace verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaneLatency {
    /// The publication's stream registration.
    pub stream: u64,
    /// Its incarnation.
    pub incarnation: u64,
    /// The lane.
    pub lane: u8,
    /// Pairs with a latency interval.
    pub available: u64,
    /// Pairs whose clocks share no source: no interval.
    pub unavailable: u64,
    /// A count overflowed: the quantiles answer nothing.
    pub incomplete: bool,
    /// The median.
    pub p50: Option<QuantileBounds>,
    /// The 90th percentile.
    pub p90: Option<QuantileBounds>,
    /// The 99th percentile.
    pub p99: Option<QuantileBounds>,
    /// The 99.9th percentile.
    pub p999: Option<QuantileBounds>,
    /// The maximum.
    pub max: Option<QuantileBounds>,
}

/// Where a quantile lies: `[low, high]` nanoseconds; `None` is an
/// unbounded side (past the histogram's range).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct QuantileBounds {
    /// Lower bound.
    pub low: Option<i64>,
    /// Upper bound.
    pub high: Option<i64>,
}

/// What the trace window counted for one driver (since the agent's attach
/// to its instance), or holds now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct TraceCounts {
    /// Records scanned.
    pub records: u64,
    /// Records whose payload is not a trace record.
    pub malformed: u64,
    /// Records of a journal the agent never saw in the table.
    pub unknown_journal: u64,
    /// Records of network journals or points, not matched in this version.
    pub network_ignored: u64,
    /// Journals past the bound, whose records are not matched.
    pub journals_dropped: u64,
    /// Messages refused at the pending bound.
    pub pending_dropped: u64,
    /// Polls past the bound of one message.
    pub polls_dropped: u64,
    /// Pairs of lanes past the bound.
    pub lanes_dropped: u64,
    /// Messages that aged out of the window unmatched.
    pub aged_out: u64,
    /// Mirror records overwritten before the agent read them.
    pub mirror_overwritten: u64,
    /// Messages pending now.
    pub pending: u64,
}
