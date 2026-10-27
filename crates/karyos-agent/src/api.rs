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
    /// The operations journal, when one is configured (M10b).
    pub journal: Option<JournalView>,
}

/// The operations journal of the agent's guard operations (M10b; the
/// gap analysis's new owner item 7, decided as item 51(7) of the
/// 2026-10-21 owner decisions, interim; not item 7 of those decisions,
/// which is the public roles and tags surface).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalView {
    /// Its recording's id in the journal directory's catalog; `None` when
    /// it could not be opened.
    pub recording: Option<u64>,
    /// Always `true` until A10 seals the journal: its records carry no
    /// seal yet.
    pub unsealed: bool,
    /// Whether it refuses appends: it could not be opened, or an append
    /// failed. Closes still go ahead; reopens are refused.
    pub unavailable: bool,
    /// Why it could not be opened.
    pub error: Option<String>,
    /// Appends that failed since the agent started.
    pub failed_appends: u64,
    /// The unknown interval not acknowledged yet.
    pub gap: Option<GapView>,
    /// The journal's alerts: [`AlertKind::JournalGap`] while `gap` is open.
    pub alerts: Vec<Alert>,
}

/// An unknown interval in the journal: operations may have taken effect
/// without their records between `from` and `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GapView {
    /// Its record's position, which an acknowledgement names.
    pub position: u64,
    /// The last record's time before it (host `CLOCK_MONOTONIC`
    /// nanoseconds); 0 when none was readable.
    pub from: u64,
    /// The start of the agent that recorded it.
    pub to: u64,
    /// Why it was recorded: `request_without_outcome`, `torn_tail`,
    /// `unclean_stop`, `journal_replaced` or
    /// `journal_unavailable_at_start`, so an administrator tells a crash
    /// from a lost operation before acknowledging it. The last is held in
    /// memory at [`UNOPENED_POSITION`](crate::journal::UNOPENED_POSITION),
    /// never recorded.
    pub reason: &'static str,
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
    /// The alerts firing for this driver (M9).
    pub alerts: Vec<Alert>,
    /// The Archive catalog listed for this driver (M11); `None` unless the
    /// driver is configured with an Archive (`--archive`).
    pub catalog: Option<Catalog>,
}

/// The Archive catalog of a driver, as the agent last listed it over the
/// Archive control streams (SPEC §11; management-agent-gap-analysis.md,
/// M11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Catalog {
    /// The recordings of the last complete listing, in id order.
    pub recordings: Vec<CatalogRecording>,
    /// Recordings that listing found past the agent's bound, not kept.
    pub left_out: u64,
    /// Host `CLOCK_MONOTONIC` nanoseconds when that listing ended; `None`
    /// before the first.
    pub listed_at: Option<u64>,
    /// Complete listings so far.
    pub listings: u64,
    /// Attempts that failed so far: a connection, a grant, a refusal or a
    /// listing past its deadline.
    pub failures: u64,
    /// The last failure, until a listing completes.
    pub last_error: Option<String>,
}

/// One recording of a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CatalogRecording {
    /// The recording id, never 0.
    pub recording_id: u64,
    /// The recorded stream.
    pub stream_id: i32,
    /// The recorded session.
    pub session_id: i32,
    /// The recorded channel.
    pub channel: String,
    /// Its first position.
    pub start: u64,
    /// When it started, in the Archive host's nanoseconds.
    pub start_time_ns: u64,
    /// Whether it still records.
    pub recording: bool,
    /// The position written so far, or where it stopped.
    pub position: u64,
    /// When it stopped, in the Archive host's nanoseconds.
    pub stopped_ns: Option<u64>,
    /// Why it stopped: `normal`, `recovered`, `empty`, `lapped`, `stopped`,
    /// `shutdown`, or `failed_source`, `failed_required_lapped`,
    /// `failed_invalid`.
    pub stop_reason: Option<String>,
    /// It lost ranges (an async recording that lapped and resumed).
    pub incomplete: bool,
}

/// What an alert watches (SPEC §11, alerting; management-agent-gap-analysis.md,
/// M9). Replication lag and clock divergence come with the Cluster and the
/// Archive's retention work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlertKind {
    /// A subscriber's lag stayed at or above the rule's bound.
    Lag,
    /// The driver reported unrecoverable losses (its loss report grew).
    Loss,
    /// A guard's close is in effect and senders have not applied it past
    /// the driver's `guard_ack_timeout` (M4b's acknowledgements).
    GuardAck,
    /// The operations journal holds an unknown interval no administrator
    /// acknowledged (M10b): `participant` is its position, `value` its
    /// length in nanoseconds, `since` its end. Or the journal failed an
    /// append, so operations go unrecorded until the agent restarts:
    /// `participant` is `u64::MAX`, `value` the failed appends, `since` the
    /// first failure.
    JournalGap,
}

/// One alert firing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Alert {
    /// What it watches.
    pub kind: AlertKind,
    /// The stream registration (`Lag`); 0 for a driver-wide alert.
    pub stream: u64,
    /// The lane (`Lag`).
    pub lane: u8,
    /// The subscriber's registration (`Lag`) or the guard id
    /// (`GuardAck`); 0 when none.
    pub participant: u64,
    /// `Lag`: the lag in bytes at the last consistent sample. `Loss`: the
    /// loss records reported since it began firing, read or overwritten.
    /// `GuardAck`: the senders overdue at the last consistent read.
    pub value: u64,
    /// Host `CLOCK_MONOTONIC` nanoseconds of the refresh it began firing.
    pub since: u64,
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
    /// 0 the in-process caller, 1 an admitted client, 2 an operator
    /// through an admitted client (M10).
    pub requester_kind: u8,
    /// The client id for a client or an operator's client, else 0.
    pub requester: u64,
    /// 1 closed, 2 already closed, 3 reopened, 4 refused.
    pub outcome: u8,
    /// The control error code of a refusal, else 0.
    pub refusal: u16,
    /// The operator's uid (`requester_kind` 2), else 0 (M10).
    pub operator: u64,
    /// The command's parameters digest, 0 when none was given (M10).
    pub parameters: u64,
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
    /// Records of network journals, not matched in this version.
    pub network_ignored: u64,
    /// Records of other points (packet-level stamps) in publisher and
    /// subscriber journals, not matched.
    pub points_ignored: u64,
    /// A second `Publish` of a message already filed: ignored.
    pub duplicates: u64,
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
