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
    /// The agent itself (R-CORE-24; karyos#728).
    pub agent: AgentIdentity,
    /// The rate policy version of each guarded stream this agent changed,
    /// as the driver last answered it (R-CORE-21, karyos#740), at most
    /// [`MAX_RATE_VIEWS`], the least recently answered dropped first. It
    /// is what this agent observed, not a read of the driver.
    pub rates: Vec<RateView>,
}

/// The most streams [`AgentView::rates`] holds.
pub const MAX_RATE_VIEWS: usize = 256;

/// A guarded stream's rate policy version, as a rate change's answer
/// named it (R-CORE-21, karyos#740).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateView {
    /// The driver's directory.
    pub dir: std::path::PathBuf,
    /// The wire stream id.
    pub stream_id: i32,
    /// The session id.
    pub session_id: i32,
    /// The policy version.
    pub version: u64,
    /// The operation whose answer named it.
    pub operation: u64,
}

impl RateView {
    /// The version `version` of stream `stream_id`/`session_id` of the
    /// driver in `dir`, answered to `operation`.
    #[must_use]
    pub const fn new(
        dir: std::path::PathBuf,
        stream_id: i32,
        session_id: i32,
        version: u64,
        operation: u64,
    ) -> Self {
        Self {
            dir,
            stream_id,
            session_id,
            version,
            operation,
        }
    }
}

/// The longest name of a principal a relay carries requests for
/// (karyos#708), in bytes.
pub const MAX_PRINCIPAL: usize = 64;

/// Whether `name` is a valid principal name: 1 to [`MAX_PRINCIPAL`] bytes
/// of ASCII letters, digits, `.`, `_`, `-`, `@` and `:` (karyos#708).
#[must_use]
pub fn valid_principal(name: &str) -> bool {
    (1..=MAX_PRINCIPAL).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-@:".contains(&byte))
}

/// Whether `id` is an agent id `--agent-id` takes: 1 to 64 bytes of
/// letters, digits, `.`, `_`, `:`, `/` and `-` (R-CORE-24).
#[must_use]
pub fn valid_agent_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

/// The agent's own identity, distinct from the drivers it watches
/// (R-CORE-24; karyos#728).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentIdentity {
    /// The name its deployment gave it (`--agent-id`), taken from
    /// configuration only: the agent looks up no host or orchestrator
    /// name. `None` when none was given.
    pub id: Option<String>,
    /// Its process id.
    pub pid: u32,
    /// Host `CLOCK_MONOTONIC` nanoseconds when it started. With `pid` it
    /// identifies this incarnation of the agent: it is not a wall-clock
    /// time, is not comparable between hosts and does not survive a
    /// reboot.
    pub started_ns: u64,
}

impl AgentIdentity {
    /// The identity `id`, of process `pid`, started at `started_ns`.
    #[must_use]
    pub fn new(id: Option<String>, pid: u32, started_ns: u64) -> Self {
        Self {
            id,
            pid,
            started_ns,
        }
    }
}

/// A driver's attachment, as the agent states it (R-CORE-24).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attachment {
    /// Host `CLOCK_MONOTONIC` nanoseconds when the current attach began;
    /// `None` while detached.
    pub since_ns: Option<u64>,
    /// Attaches so far.
    pub attaches: u64,
    /// How the previous attach ended; `None` before any ended.
    pub previous: Option<AttachEnd>,
}

/// How an attach ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttachEnd {
    /// The driver instance it was attached to.
    pub instance: u128,
    /// Host `CLOCK_MONOTONIC` nanoseconds when it ended.
    pub ended_ns: u64,
    /// Why.
    pub reason: AttachEndReason,
}

impl AttachEnd {
    /// The end of the attach to `instance` at `ended_ns`, for `reason`.
    #[must_use]
    pub fn new(instance: u128, ended_ns: u64, reason: AttachEndReason) -> Self {
        Self {
            instance,
            ended_ns,
            reason,
        }
    }
}

/// Why an attach ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachEndReason {
    /// The driver closed (`"driver_gone"`).
    DriverGone,
    /// Reading the driver failed and the agent let it go (`"detached"`).
    Detached,
}

/// One capability of the agent, for the caller that asked (R-CORE-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capability {
    /// Its name, one of [`CAPABILITIES`].
    pub name: &'static str,
    /// Whether the caller is served it.
    pub state: CapabilityState,
}

/// Whether a capability is served to a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityState {
    /// Served.
    Served,
    /// Not available in this deployment, whatever the caller's role, for
    /// `reason`: `"not_configured"` or `"journal_unavailable"`.
    Unavailable {
        /// Why.
        reason: &'static str,
    },
    /// Available, but not for the caller's role (`"role"`).
    Forbidden {
        /// Why.
        reason: &'static str,
    },
}

/// The capability names of API v1, a closed list: a later agent may add
/// names, and a client ignores the ones it does not know.
pub const CAPABILITIES: [&str; 19] = [
    "view",
    "guard-close",
    "guard-reopen",
    "gap-ack",
    "catalog",
    "trace-window",
    "limits",
    "trace-buckets",
    "trace-export",
    "join-registry",
    "join-put",
    "rate-change",
    "guard-preview",
    "submit",
    "clocks",
    "rate-limits",
    "cluster-command",
    "journal-history",
    "journal-append",
];

/// The byte bound of a `trace-buckets` reply (R-CORE-23). A reply holds
/// whole lanes only, and always at least one, so a reader always
/// progresses: it is at most `MAX_BUCKET_REPLY` plus one lane's encoding,
/// [`MAX_LANE_REPLY`] at most. A bucket larger than the bound is paged by
/// lane; the first lane left out is named by `next`, a bucket number and a
/// lane index. A client sizes its buffer for
/// `MAX_BUCKET_REPLY + MAX_LANE_REPLY`.
pub const MAX_BUCKET_REPLY: usize = 1 << 20;
/// The largest encoding of one lane of a bucket: its header, at most
/// [`LANE_HEADER_REPLY`] bytes, and its histogram's four count arrays of
/// [`LANE_BUCKETS`] entries each (two sides, two signs), each entry
/// `[index,count],` at most 29 bytes (an index of 5 digits, a count of
/// 20): `LANE_HEADER_REPLY + 4 x LANE_BUCKETS x 29`, 2 870 932 bytes at
/// the trace window's 3 significant digits and 10 s highest magnitude.
pub const MAX_LANE_REPLY: usize = LANE_HEADER_REPLY + 4 * LANE_BUCKETS * 29;
/// The entries of one count array of a lane's histogram, at the trace
/// window's 3 significant digits and 10 s highest magnitude.
pub const LANE_BUCKETS: usize = 24_745;
/// The most bytes of a lane's encoding besides its count arrays.
pub const LANE_HEADER_REPLY: usize = 512;
/// Buckets one `trace-buckets` request asks for by default, and at most.
pub const BUCKETS_DEFAULT: usize = 6;
/// The most buckets one request may ask for.
pub const BUCKETS_MAX: usize = 60;

/// The byte bound of a `trace-export` reply (R-CORE-13), as
/// [`MAX_BUCKET_REPLY`]'s: whole records only, each counted with its
/// journal the first time one names it, and always at least the first
/// record, so a reply is at most `MAX_EXPORT_REPLY` plus one record and one
/// journal, [`MAX_RECORD_REPLY`] and [`MAX_JOURNAL_REPLY`] at most. A
/// record past it is left for the next read, named by `next`. A client
/// sizes its buffer for the sum.
pub const MAX_EXPORT_REPLY: usize = 1 << 20;
/// The largest encoding of one exported record: its fields, at most 128
/// bytes with their three numbers of up to 20 digits, and its payload of
/// at most `MAX_MIRROR_PAYLOAD` (27) words of up to 20 digits and a
/// separator each: `128 + 27 x 21`, 695 bytes.
pub const MAX_RECORD_REPLY: usize = 128 + karyos_sys::trace_mirror::MAX_MIRROR_PAYLOAD * 21;
/// The largest encoding of one exported journal: its fields, at most 1024
/// bytes, and its drop ranges, at most `MIRROR_RANGES` (8) of at most 192
/// bytes each (six numbers of up to 20 digits, their keys, 184 bytes):
/// `1024 + 8 x 192`, 2560 bytes.
pub const MAX_JOURNAL_REPLY: usize = 1024 + karyos_sys::trace_mirror::MIRROR_RANGES * 192;
/// The largest encoding of one exported application point (R-CORE-1):
/// its fields, at most 128 bytes, and a label of up to 64 bytes, each
/// possibly escaped to two (a point's label holds no control character):
/// 384 bytes with room to spare.
pub const MAX_POINT_REPLY: usize = 384;
/// Records one `trace-export` request asks for by default.
pub const EXPORT_DEFAULT: usize = 1024;
/// The most records one request may ask for: the work of one read.
pub const EXPORT_MAX: usize = 16_384;

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
    /// Whether a part of its recording has no seal (karyos#702): a seal
    /// failed or the integrity journal could not be opened, records wait
    /// past the sealed end for the next durable append, or the journal is
    /// unavailable; `false` when the Archive's sealing covers all it
    /// wrote. Kept in v1, now computed.
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
    /// Each range's integrity outcome at the journal's last verification
    /// (karyos#702, SPEC.md §8.4), with the outcome and reason names of
    /// the Archive's verifier, unchanged; adjacent ranges with the same
    /// outcome and reasons are one, at most
    /// [`MAX_INTEGRITY_RANGES`](crate::journal::MAX_INTEGRITY_RANGES).
    /// `None` when no verification could run.
    pub integrity: Option<Vec<crate::retention::RangeOutcome>>,
    /// Whether ranges past that bound were left out.
    pub integrity_truncated: bool,
    /// The journal's legal hold (ADR-0113): `none`, `pending`, `held`,
    /// `unknown` (its state cannot be read: every purge is refused) or
    /// `not_durable` (in force in memory only); `None` when the journal
    /// could not be opened.
    pub hold: Option<&'static str>,
    /// The journal's retention policy in force; `None` for none, when
    /// every purge is refused.
    pub policy: Option<karyos_archive::integrity::retention::RetentionPolicy>,
    /// Each purged prefix, with its purge evidence, from the last
    /// verification.
    pub purged: Vec<crate::journal::Purged>,
    /// Whether a purge intent is outstanding: every further purge is
    /// refused until it is reconciled.
    pub purge_pending: bool,
    /// The journal's recording and durable end when the view was taken
    /// (R-CORE-14; karyos#725): a reader that follows the history from
    /// here misses no record written after the view and sees none written
    /// before it again. `None` while the journal is unavailable.
    pub head: Option<crate::journal::HistoryCursor>,
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
    /// Its attachment: since when, how many, and how the previous one
    /// ended (R-CORE-24).
    pub attachment: Attachment,
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
    /// The Archive's retention state (ADR-0101; karyos#967), read after
    /// each listing; `None` unless the driver's Archive names a retention
    /// state stream (`--archive DIR=REQ,RESP,STATE`).
    pub retention: Option<RetentionView>,
}

/// An Archive's retention state as it last answered a retention state
/// query (ADR-0101): read only, from the Archive itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetentionView {
    /// Each recording's retention, in id order, at most the agent's bound.
    pub recordings: Vec<RecordingRetention>,
    /// The Archive's `--archive-min-free` floor in bytes; 0 for none.
    pub min_free_bytes: u64,
    /// Its file system's free bytes when it answered; `None` when it
    /// could not tell.
    pub free_bytes: Option<u64>,
    /// Host `CLOCK_MONOTONIC` nanoseconds when the answer ended; `None`
    /// before the first.
    pub read_at: Option<u64>,
    /// The last failure, until a query is answered: "retention state
    /// unsupported by this Archive" for an Archive without version 2.
    pub last_error: Option<String>,
}

/// One recording's retention, as its Archive answers it (ADR-0101).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordingRetention {
    /// The recording id, never 0.
    pub recording_id: u64,
    /// Its hold: `none`, `held` (applied with evidence), `pending` (in
    /// force without evidence) or `unknown` (the Archive could not read
    /// its hold state).
    pub hold: &'static str,
    /// When the hold was applied or received, UTC nanoseconds; `None`
    /// when not recorded.
    pub hold_since_ns: Option<u64>,
    /// Its recorded UTC close time; `None` while it records or without
    /// one.
    pub close_time_ns: Option<u64>,
    /// The earliest expiry its policy gives from that close time, a lower
    /// bound and never purge eligibility; `None` for none.
    pub earliest_expiry_ns: Option<u64>,
    /// The configured policy's identity and version; `None` for none.
    pub policy: Option<(u64, u64)>,
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
///
/// **Identity** (R-CORE-17). A counter's identity is its driver's
/// `instance` with its `cell_registration`, which a region never reuses;
/// a subscriber position's is the instance with its `cell_registration`;
/// a lane's is the instance with its `stream` and `lane`. Within one pass
/// each identity appears once, and two passes of one instance join on
/// it. The label, type and keys describe a datum but are not its
/// identity: a counter freed and allocated again under the same keys is
/// a new series, and two clients may allocate the same keys. A new
/// instance is a new series: nothing joins across it, and every
/// `changed_ns` starts again at `None`.
///
/// **Times.** Each counter carries `read_ns`, when the agent read it, and
/// `changed_ns`, an upper bound on when its value last changed. Each lane
/// carries `sampled_ns`, the driver's own sampling time of its positions.
/// A datum untouched for several passes reports this pass's `read_ns` and
/// the older `changed_ns`, never the pass time as its change. The
/// pass-level `consistent`, `sampled` and `age_ns` keep their meaning.
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
    /// `TYPE_TIMESTAMP` 5, and an application's `TYPE_APPLICATION_EVENT` 6
    /// and `TYPE_APPLICATION_GAUGE` 7, R-CORE-3).
    pub type_id: u64,
    /// The stream registration, 0 for driver-wide counters.
    pub stream: u64,
    /// The lane.
    pub lane: u8,
    /// The participant kind (`KIND_*`).
    pub kind: u8,
    /// The participant or client registration, 0 when none.
    pub participant: u64,
    /// The cell's registration: one allocation, never reused within the
    /// driver instance's region. With the instance, the datum's identity
    /// (R-CORE-17).
    pub cell_registration: u64,
    /// Its value.
    pub value: u64,
    /// Host `CLOCK_MONOTONIC` nanoseconds at which the agent read this
    /// cell: the end of the read of its pass (R-CORE-17).
    pub read_ns: u64,
    /// The `read_ns` of the first pass in which the agent saw this
    /// datum's value differ from its previous pass. It is an upper bound
    /// on the instant of the change: the change happened after the
    /// previous pass's `read_ns`, the earliest, and by this one, the
    /// latest. `None` until the agent has seen the datum change since it
    /// was allocated, or since the driver instance changed.
    pub changed_ns: Option<u64>,
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
    /// Host `CLOCK_MONOTONIC` nanoseconds at which the driver sampled the
    /// positions (its `positions sampled at` cell), if known: the time of
    /// every position of this lane (R-CORE-17).
    pub sampled_ns: Option<u64>,
}

/// One subscriber of a stream lane.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Subscriber {
    /// Its registration.
    pub registration: u64,
    /// Its position cell's registration: with the instance, the
    /// position's identity, which tells apart a subscriber's predecessor
    /// and current cells during a cutover (R-CORE-17).
    pub cell_registration: u64,
    /// Its position cell's label.
    pub label: String,
    /// Its position.
    pub position: u64,
    /// `head - position`, signed; `None` when the head is missing or the
    /// difference does not fit.
    pub lag: Option<i64>,
    /// As [`Counter::changed_ns`], for the position, at the lane's
    /// `sampled_ns` passes; in a pass that is not `consistent`, at the
    /// agent's read instead, as that pass may mix samples.
    pub changed_ns: Option<u64>,
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
    /// Closed buckets evicted, oldest first, to keep within the budget
    /// (R-CORE-23).
    pub buckets_evicted: u64,
    /// Closed buckets larger than the whole budget, never kept.
    pub buckets_over_budget: u64,
}

/// One closed slice of the trace window, a disjoint bucket (R-CORE-23):
/// no pair in it is in any other bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TraceBucket {
    /// Its slice number.
    pub number: u64,
    /// Its lanes in all; `lanes` is the part from `first_lane` on that
    /// this reply holds (R-CORE-23's paging by lane).
    pub lanes_total: usize,
    /// The index of the first lane of `lanes` among the bucket's.
    pub first_lane: usize,
    /// Its span of the agent's time, `[start_ns, end_ns)`.
    pub start_ns: u64,
    /// The end of its span.
    pub end_ns: u64,
    /// Each lane with pairs in it.
    pub lanes: Vec<BucketLane>,
    /// What was lost while it was current, on the bucket's first page
    /// (`first_lane` 0) only; `None` on a later page of it, so a reader
    /// never counts it twice.
    pub loss: Option<Loss>,
    /// It lost something, or a lane's count overflowed: no clean quantile.
    /// Stated on every page of the bucket.
    pub incomplete: bool,
}

/// One lane's histogram in a bucket, as mergeable counts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BucketLane {
    /// The publication's stream registration.
    pub stream: u64,
    /// Its incarnation.
    pub incarnation: u64,
    /// The lane.
    pub lane: u8,
    /// The histogram's counts (`karyos_trace::Histogram::from_counts`).
    pub counts: karyos_trace::HistogramCounts,
}

/// One dimension `limits` answers (R-CORE-38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// Its name in a request and in the answer.
    pub name: &'static str,
    /// The bound; `None` when the dimension has none.
    pub bound: Option<u64>,
    /// Whether a client may propose a value within the bound and have it
    /// applied to its request.
    pub negotiable: bool,
}

/// The loss counted while a slice was current: what its histograms miss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Loss {
    /// Messages refused at the pending bound.
    pub pending_dropped: u64,
    /// Polls past the bound of one message.
    pub polls_dropped: u64,
    /// Pairs of lanes past the bound.
    pub lanes_dropped: u64,
    /// Messages aged out unmatched.
    pub aged_out: u64,
    /// Mirror records overwritten unread.
    pub mirror_overwritten: u64,
    /// Records of journals past the bound.
    pub journals_dropped: u64,
    /// Records whose payload did not decode.
    pub malformed: u64,
    /// Records of a journal not (yet) in the table.
    pub unknown_journal: u64,
}

impl Loss {
    pub(crate) fn of(counts: &TraceCounts) -> Self {
        Self {
            pending_dropped: counts.pending_dropped,
            polls_dropped: counts.polls_dropped,
            lanes_dropped: counts.lanes_dropped,
            aged_out: counts.aged_out,
            mirror_overwritten: counts.mirror_overwritten,
            journals_dropped: counts.journals_dropped,
            malformed: counts.malformed,
            unknown_journal: counts.unknown_journal,
        }
    }

    pub(crate) fn since(self, start: Self) -> Self {
        let less = |now: u64, then: u64| now.saturating_sub(then);
        Self {
            pending_dropped: less(self.pending_dropped, start.pending_dropped),
            polls_dropped: less(self.polls_dropped, start.polls_dropped),
            lanes_dropped: less(self.lanes_dropped, start.lanes_dropped),
            aged_out: less(self.aged_out, start.aged_out),
            mirror_overwritten: less(self.mirror_overwritten, start.mirror_overwritten),
            journals_dropped: less(self.journals_dropped, start.journals_dropped),
            malformed: less(self.malformed, start.malformed),
            unknown_journal: less(self.unknown_journal, start.unknown_journal),
        }
    }

    /// Whether anything was lost.
    #[must_use]
    pub fn any(&self) -> bool {
        *self != Self::default()
    }
}

/// Why a bucket read is refused (R-CORE-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BucketRefusal {
    /// The reader's cursor belongs to another run of the window.
    EpochChanged {
        /// This run's epoch.
        epoch: u64,
        /// The oldest bucket number kept.
        oldest: u64,
    },
    /// The bucket is no longer kept.
    Expired {
        /// The oldest bucket number kept.
        oldest: u64,
    },
    /// The bucket was larger than the whole budget and never kept.
    OverBudget {
        /// Its number.
        number: u64,
    },
}

/// What a bucket read returns: the buckets from the asked number on, in
/// order, with no gap.
#[derive(Debug)]
#[non_exhaustive]
pub struct BucketRead {
    /// This run's epoch.
    pub epoch: u64,
    /// One slice's length, in ns.
    pub slice_ns: u64,
    /// The slice now current: buckets are the numbers below it.
    pub current: u64,
    /// The oldest bucket number kept.
    pub oldest: u64,
    /// The buckets, oldest first; the last may hold only part of its
    /// lanes, and the first starts at the lane asked for.
    pub buckets: Vec<TraceBucket>,
    /// Where the next read starts, when the reply stopped before every
    /// bucket asked for (the byte bound, or a bucket refused as over
    /// budget); `None` when every bucket asked for is here, whole.
    pub next: Option<BucketCursor>,
}

/// A position in the buckets: a bucket number and a lane index in it
/// (R-CORE-23). A bucket's first page starts at lane 0. Ordered by number,
/// then lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct BucketCursor {
    /// The bucket number.
    pub number: u64,
    /// The index of its first lane to read.
    pub lane: usize,
}

impl BucketCursor {
    /// Bucket `number` from its lane `lane`.
    #[must_use]
    pub const fn new(number: u64, lane: usize) -> Self {
        Self { number, lane }
    }
}

/// One raw trace record of the driver's mirror (R-CORE-13): its mirror
/// sequence, the journal it was drained from, its sequence there and its
/// payload words, whole.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportRecord {
    /// Its mirror ring sequence: the cursor.
    pub seq: u64,
    /// The journal it was drained from.
    pub journal: u64,
    /// Its sequence in that journal.
    pub sequence: u64,
    /// Its payload words (a `karyos-trace` record for a client journal).
    pub payload: Vec<u64>,
}

/// Mirror sequences `first..=last` an export never delivers, and why
/// (R-CORE-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportLoss {
    /// The first lost sequence.
    pub first: u64,
    /// The last lost sequence.
    pub last: u64,
    /// Why they were lost.
    pub reason: LossReason,
}

/// Why an export lost records (R-CORE-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LossReason {
    /// Overwritten in the ring before they were read.
    Overwritten,
    /// A record whose length passed the payload bound: never delivered
    /// cut.
    Malformed,
}

/// A journal a page's records name, as the table showed it when the page
/// was read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportJournal {
    /// In the table: its entry, with its clock provenance, time namespace
    /// and drop ranges.
    Live(Box<karyos_sys::trace_mirror::JournalEntry>),
    /// Recycled from the table, still in the recycle log.
    Recycled(Box<karyos_sys::trace_mirror::RecycledJournal>),
    /// In neither: recycled and gone from the log too, every entry having
    /// been read.
    Unknown {
        /// Its number.
        journal: u64,
    },
    /// Not read: a table or log entry stayed busy on every attempt while
    /// this page's first record was its journal's. Its records are
    /// delivered without calibration, counted in `unreadable_records`.
    Unreadable {
        /// Its number.
        journal: u64,
    },
}

/// An application trace point a page's records reference (R-CORE-1), as
/// the client counters region showed it when the page was read: its label
/// and client, or neither when no single live cell of the records' client
/// names the id (released, never seen, or claimed twice). Ids are never
/// reused within the instance, so an unnamed point is never another's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportPoint {
    /// The point id.
    pub id: u16,
    /// Its label, when named.
    pub label: Option<String>,
    /// The client that registered it, when named.
    pub client: Option<u64>,
}

/// One page of a trace export (R-CORE-13).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportPage {
    /// The driver instance the sequences belong to: the cursor's epoch.
    pub epoch: u128,
    /// The sequence asked for.
    pub from: u64,
    /// What was lost between `from` and the first record, or within the
    /// page, oldest first.
    pub lost: Vec<ExportLoss>,
    /// The records, in sequence order, with no duplicate.
    pub records: Vec<ExportRecord>,
    /// The sequence to ask for next.
    pub next: u64,
    /// The sequence the mirror will give its next record: `next` equal to
    /// it means the reader is up to date.
    pub head: u64,
    /// The journals the records name, by number.
    pub journals: Vec<ExportJournal>,
    /// The application points the records reference, by id (R-CORE-1).
    pub points: Vec<ExportPoint>,
    /// The records whose journal is `unknown` (recycled and gone from the
    /// log too): they are delivered, without their calibration.
    pub unknown_records: u64,
    /// The records whose journal is `unreadable`: delivered, without their
    /// calibration; a later read of the same records may name it.
    pub unreadable_records: u64,
    /// The mirror header's `network_journals_refused`
    /// (`trace-network.md` §4 and §5) when the agent attached to this
    /// driver instance, read before this page's journal table read and
    /// after it. `after - before` is only the increase observed during
    /// that read: a refusal before the attach, between pages or before
    /// `before` is not in it, so equal samples do not show complete
    /// coverage. A nonzero `attach`, or any rise since it seen in a page's
    /// samples, means a network journal may be missing, and no later
    /// trace is a final `Complete` for that attach (NT-4, karyos#931).
    pub network_journals_refused: RefusedReads,
}

/// Three reads of the mirror header's `network_journals_refused`
/// (karyos#931).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefusedReads {
    /// At the agent's attach to the driver instance; `None` when the agent
    /// has not recorded it (an export read outside an attached driver).
    pub attach: Option<u64>,
    /// Before the page's journal table read.
    pub before: u64,
    /// After the page's journal table read.
    pub after: u64,
}

/// Why an export read is refused (R-CORE-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportRefusal {
    /// The cursor belongs to another driver instance, whose sequences are
    /// not this one's: the reader starts again from 0.
    EpochChanged {
        /// This driver instance.
        epoch: u128,
    },
    /// The cursor is beyond the ring's next sequence: not this instance's
    /// sequences, or a reader's error. It is never served as caught up.
    Ahead {
        /// The ring's next sequence.
        next: u64,
    },
    /// The ring's bounds were being written on every attempt: retry.
    Busy,
}

/// What a `clocks DIR` read reports of one driver (R-CORE-40, karyos#741):
/// the clocks of the trace journals the agent follows in the driver's
/// trace mirror, and the calibrations the agent can see.
///
/// A clock without a valid calibration reads as unavailable with a reason,
/// never as a number, and no latency is derived here (`karyos_trace`'s
/// clocks module). Until karyos#118 produces calibrations, the agent sees
/// none: `calibrations` is empty with `calibrations_unavailable`
/// `"no_producer"`, and every clock's calibration is unavailable, which a
/// clocks view shows as "no cross-host calibration" rather than hiding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClocksRead {
    /// The driver's directory.
    pub dir: PathBuf,
    /// Host `CLOCK_MONOTONIC` nanoseconds of the agent's read.
    pub read_ns: u64,
    /// The driver instance whose journals these are.
    pub driver: u128,
    /// One per local trace journal the agent follows, by journal number:
    /// at most the trace window's `max_journals`. Network journals carry
    /// no clock of this host and are not listed.
    pub clocks: Vec<ClockState>,
    /// Every calibration the agent can see.
    pub calibrations: Vec<CalibrationView>,
    /// Why `calibrations` is empty when no source of them exists:
    /// `"no_producer"` until karyos#118; `None` when the agent reads a
    /// source, so an empty list then means none was published.
    pub calibrations_unavailable: Option<&'static str>,
}

/// One clock: a trace journal's clock as its records observed it
/// (`karyos_trace::ClockKey`: the journal's observer, the domain and the
/// calibration epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClockState {
    /// The journal number, the observer's within the driver instance.
    pub journal: u64,
    /// What the journal declared of its clock's origin: `"std_monotonic"`,
    /// `"host_monotonic"` or `"opaque"`.
    pub provenance: &'static str,
    /// Whether the driver found the journal's writer in its own time
    /// namespace.
    pub same_namespace: bool,
    /// The clock domain of its last record; `None` before any.
    pub domain: Option<u64>,
    /// The calibration epoch of its last record; `None` before any.
    pub epoch: Option<u64>,
    /// The time of its last record, in the clock's unit; `None` before any.
    pub time: Option<u64>,
    /// The largest uncertainty (half-width, the clock's unit) of its
    /// records in that epoch; `None` before any.
    pub uncertainty: Option<u64>,
    /// Whether a calibration from this clock holds at `time`.
    pub calibration: CalibrationState,
}

/// Whether a clock has a calibration valid at its last observed time
/// (R-CORE-40).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CalibrationState {
    /// `count` calibrations from the clock, each to another clock, hold at
    /// its last observed time.
    Valid {
        /// How many.
        count: usize,
    },
    /// None holds, for `reason`.
    Unavailable {
        /// Why.
        reason: CalibrationUnavailable,
    },
}

/// Why a clock has no valid calibration (R-CORE-40).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CalibrationUnavailable {
    /// No calibration from the clock (`"no_calibration"`): the state of
    /// every clock until karyos#118.
    NoCalibration,
    /// The clock has no observed time to check one against
    /// (`"not_observed"`).
    NotObserved,
    /// Every calibration from it ended before its last time (`"expired"`).
    Expired,
    /// None from it has started by its last time (`"not_yet_valid"`).
    NotYetValid,
    /// Two hold for one target clock (`"ambiguous"`): neither is used.
    Ambiguous,
}

impl CalibrationUnavailable {
    /// Its name in the API.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoCalibration => "no_calibration",
            Self::NotObserved => "not_observed",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// A calibration the agent can see, with its validity range and whether
/// it holds at its source clock's last observed time (R-CORE-40).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CalibrationView {
    /// The calibration, as `karyos_trace` defines it.
    pub calibration: karyos_trace::Calibration,
    /// Whether it holds: `"valid"`, `"expired"`, `"not_yet_valid"`, or
    /// `"not_observed"` when its source clock has no observed time.
    pub state: &'static str,
}

/// What a `rate-limits DIR` read reports of one driver (R-CORE-40,
/// karyos#741), from the agent's last sampling pass of its counters: the
/// rate limiters of its network publications' sender gates, where the
/// authoritative buckets live (R-CORE-21), with the policy in force, its
/// version and the refusals counted.
///
/// Each value is a counter cell the sender writes at the end of its duty
/// cycle; a pass reads each cell on its own, so a pass may mix two cycles.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimitsRead {
    /// The driver's directory.
    pub dir: PathBuf,
    /// Host `CLOCK_MONOTONIC` nanoseconds of the pass read; `None` when
    /// the pass had no counter.
    pub read_ns: Option<u64>,
    /// One per network publication with counter cells, by stream
    /// registration.
    pub publications: Vec<PublicationRates>,
}

/// A network publication's rate limiters (R-CORE-40).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublicationRates {
    /// The stream registration its cells are keyed by.
    pub registration: u64,
    /// The publication's own buckets, which its messages spend.
    pub publication: Limiter,
    /// The control bucket of its cancel and resolve traffic (R-CORE-21's
    /// control reserve).
    pub control: Limiter,
    /// The version of the published rate policy the gate applies; 0 for
    /// the policy it was built with, or for none; `None` when the driver
    /// publishes no such cell (one older than karyos#741).
    pub version: Option<u64>,
}

/// One rate limiter as the agent reads it (R-CORE-40).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limiter {
    /// The driver publishes no cell for it (one older than karyos#741):
    /// nothing is known (`"not_counted"`).
    Unknown,
    /// The gate has no such bucket (`"none"`): nothing is limited and
    /// nothing counted.
    None,
    /// The bucket in force and its refusals (`"limited"`).
    Limited {
        /// The policy in force.
        policy: karyos_sys::rate_limit::RatePolicy,
        /// The checks at which the bucket could not pay for what was due:
        /// a datagram or control frame that waits is counted at each check
        /// that holds it. 0 means it refused nothing; a limiter that
        /// counts nothing is [`Limiter::None`] or [`Limiter::Unknown`],
        /// never 0.
        refusals: u64,
    },
}
