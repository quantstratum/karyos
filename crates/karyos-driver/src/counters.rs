// SPDX-License-Identifier: Apache-2.0

//! Instrumentation of the embedded driver (a first part of SPEC.md §11, not
//! the full CnC observability or error log): client admission, command
//! service, the terminal state and stream lifecycle, in a counters region
//! that tools read through a [`CountersReader`].
//!
//! - **Event counters** ([`TYPE_EVENTS`]) are lifetime totals and only
//!   grow. An increment that would overflow leaves the counter unchanged
//!   (ADR-0007, no silent wrap or saturation) and adds one to `counter
//!   overflows`, which is how an overflow is reported; the command or event
//!   itself is unaffected. Only an overflow of `counter overflows` itself
//!   goes unrecorded.
//! - **Gauges** ([`TYPE_GAUGE`]) are current values. The driver refreshes
//!   them at the end of every duty cycle, also one that returns a stream's
//!   error (every stream still runs first), and after each control call
//!   that changes them, so a handle dropped by the application shows up at
//!   the next duty cycle.
//! - Each counter is read on its own; there is no atomic snapshot across
//!   counters.
//!
//! Counters, by label (the label is the counter's metadata):
//!
//! | Label | Type | Meaning |
//! | --- | --- | --- |
//! | `clients admitted` | event | clients admitted by `connect` |
//! | `clients retired` | event | admission slots released (close flag observed) |
//! | `clients faulty` | event | clients retired for a protocol violation, at the first retirement |
//! | `fetches abandoned at leave` | event | remote clients that left with a fetch outstanding (one it abandoned, or exports not detached): a clean leave, their exports charged until the exit proof (karyos#851) |
//! | `trace point ids exhausted` | event | trace point registrations refused because the instance assigned every id (R-CORE-1, karyos#722) |
//! | `trace points per client` | gauge | the configured `max_trace_points_per_client`, set at creation (karyos#868) |
//! | `trace point registrations per client` | gauge | the configured `max_trace_point_registrations_per_client`, set at creation (karyos#868) |
//! | `trace point copies dropped` | event | trace points registered without a driver-written copy because `max_trace_point_copies` were live (karyos#869) |
//! | `commands served` | event | commands decoded and executed or refused; malformed records are not commands |
//! | `commands refused` | event | served commands answered with an `Error` |
//! | `responses sent` | event | responses written to the broadcast buffer |
//! | `terminal` | gauge | 1 once the driver is in its terminal state |
//! | `streams active` | gauge | streams accepting new capabilities |
//! | `streams retiring` | gauge | streams removed but not yet freed |
//! | `streams freed` | event | streams freed |
//! | `registrations swept` | event | registrations forgotten because their capability was dropped |
//! | `counter overflows` | event | increments that would have overflowed and were not applied |
//! | `clients connected` | gauge | admission slots in use, including faulty clients awaiting producer detach |
//! | `hand-over entries held` | gauge | capabilities waiting to be taken |
//! | `stream leases live` | gauge | capability leases over all streams; forgotten handles stay counted |
//! | `streams removed` | event | streams that went from active to retiring, once each |
//! | `claims aborted at deadline` | event | claims and blocks a deadline call aborted (`DeadlineReport::aborted`) |
//! | `claim deadlines resolved` | event | expired points a deadline call found already terminal (`resolved`); repeats per call |
//! | `claim clock steps back` | event | timers a deadline call re-anchored (`clock_went_back`); repeats per call |
//! | `claim deadlines unrepresentable` | event | points whose expiry instant does not fit `u64` (`unrepresentable`); repeats per call |
//! | `claims waiting` | gauge | streams whose latest deadline call reported `waiting` |
//! | `positions epoch` | gauge | sampling pass sequence: odd while a pass writes the position cells |
//! | `positions sampled at` | timestamp | host `CLOCK_MONOTONIC` nanoseconds of the last completed pass |
//! | `counters unavailable` | event | counter allocations refused for lack of a free cell |
//! | `generations retired` | gauge | mappings retired but not yet reclaimed, over all streams |
//! | `slots quarantined` | gauge | slots in `RECLAIMING` with a live loan, over all streams and retained mappings |
//! | `spare reservations in use` | gauge | spare-slot credits in use as admission counts them (publisher credits plus subscriber credits), over all streams and retained mappings |
//! | `loans outstanding` | gauge | non-zero loan words, over all streams and retained mappings |
//! | `retirement pool exhausted` | event | reconfigurations refused because `max_retained_generations` predecessors are retained |
//! | `error events dropped` | event | error events lost before reaching the error log |
//! | `error records overwritten` | event | error log records overwritten |
//! | `loss records overwritten` | event | loss report records overwritten |
//! | `loss reports unverified` | event | `ReportLoss` records of a subscription that had already ended |
//! | `overruns rejoin at head` | event | reported overruns whose applied policy was `rejoin at head` |
//! | `overruns snapshot` | event | reported overruns whose applied policy was `snapshot`, whether it rebuilt or failed |
//! | `overruns close` | event | reported overruns whose applied policy was `close` |
//! | `replay fallbacks` | event | reported overruns whose `replay` policy fell back; each is also counted under its secondary |
//! | `trace records mirrored` | event | client trace journal records the driver copied into the trace mirror |
//! | `trace mirror overwritten` | event | trace mirror ring records overwritten (mirror loss, never journal loss) |
//! | `trace journals open` | gauge | client trace journals whose writer may still append |
//! | `trace journal faults` | event | client trace journals the driver stopped draining for a protocol violation |
//! | `driver pid` | gauge | the driver process's id in its own pid namespace, set at creation; a tool in another namespace knows it by another number |
//! | `driver started at` | timestamp | host `CLOCK_MONOTONIC` nanoseconds when the driver was created |
//! | `conductor duty at` | timestamp | host `CLOCK_MONOTONIC` nanoseconds of the last duty cycle, read at its end with the positions pass; 0 before the first |
//! | `capability fallback` | event | endpoint capabilities on a fallback, once per endpoint epoch (SPEC §16.8) |
//! | `capability missing` | event | endpoint opens and reopens refused for a required capability (SPEC §16.8) |
//! | `guard audit records overwritten` | event | guard audit ring records overwritten by newer ones |
//! | `guard audit records dropped` | event | guard audit ring records dropped once its sequences were exhausted |
//!
//! With a network, each endpoint's effective capabilities are gauges keyed
//! by participant kind endpoint and its instance id (`crate::capabilities`,
//! M3), written by the conductor.
//!
//! With a network, the agents' system counters are driver-wide event
//! cells (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`,
//! M2), allocated when the driver is created, before any agent starts.
//! Each is written only by the agent that counts it, with `set` (a swap,
//! as karyos-sys requires of value updates) of its own checked count at
//! the end of its duty cycle, in every threading
//! mode; the conductor frees them when the network closes and the agents
//! come back. Sender: `network controls sent`, `network control send
//! failures`, `naks received`, `status messages received`, `heartbeats
//! sent`, then the dynamic registrations' cells listed with
//! `agents::SENDER_CELLS`, ending with `sender counters overflowed`, a
//! gauge that is 1 once a sender or registration count saturated
//! (karyos#977). Receiver: `datagrams received`, `datagrams dropped by backend`,
//! `invalid frames received`, `status messages sent`, `images retired at
//! timeout`, and for `control-mode=dynamic` subscriptions (karyos#941)
//! `registers sent`, `registers unsent` (a rate, the control ring or a
//! missing identity refused one due) and `registration refusals received`
//! (ERR REGISTRATION `DESTINATIONS_FULL` from a `control` address). A
//! dynamic subscription whose REGISTERs are dropped with no reply (the
//! allowlist, a rate, quarantine) shows only `registers sent` growing.
//! Then `registers rate limited` (its per-`control` bucket held one
//! back), `setup not from control` and the gauge `receiver counters
//! overflowed` (karyos#977).
//! When no cell is free one is not allocated and `counters unavailable`
//! counts it.
//!
//! Each network publication and exposed image has its own cells (M2b),
//! keyed by its stream's registration (key0; lane, kind and participant
//! 0) and written the same way by its agent. Publication: `network frames
//! sent`, `network bytes sent`, `network retransmits`, `network naks
//! received`, `network admission` (a gauge) and `network rate policies
//! refused`. Image: `network naks sent`, `network losses`, `network
//! repaired`. They are allocated all or none with the publication, or
//! once the image is installed and exposed; when the region has no room
//! for the whole group, `counters unavailable` counts one and the stream
//! runs without cells, never retried. They are freed when the publication
//! is removed, the image retires or the network closes; cells still in
//! flight to the receiver at the close are left pending release, which
//! the allocator reuses. Size the region for 6 cells per network
//! publication and 3 per image on top of the rest.
//!
//! Position cells (`quantstratum-docs: karyos/design/observability-and-tools.md`,
//! "Per-stream positions") are allocated, set and released only inside a
//! sampling pass, between its odd and its even `positions epoch`, with the
//! layout version 2 key words: per stream lane `stream limit`, `stream
//! head` and `stream floor` (key0 the stream, key1 its lane), and per
//! attached subscriber cell `subscriber position generation G cell N` (key1
//! also kind subscriber, key2 its registration, 0 for an in-process
//! subscription without one); during a cutover a subscriber that has not
//! moved yet is sampled in its predecessor mapping. The region holds
//! `counters_capacity` cells; when none is free a cell is not allocated,
//! `counters unavailable` counts it once, tools show that position as
//! unavailable, and later passes retry.
//!
//! A conflated stream (`quantstratum-docs: karyos/design/conflation-end-to-end.md`,
//! Counters) has three event counters of its feeder, keyed by the stream
//! and its lane (participant kind none): `conflation updates written`
//! (messages written to the keyed table), `conflation keys rejected` (keys
//! outside the table) and `conflation values too large` (values longer
//! than a slot). They are allocated when the stream is added, outside any
//! sampling pass, and freed when the stream is freed. When no cell is free
//! one is not allocated, `counters unavailable` counts it, and it is not
//! retried.
//!
//! The cells are allocated once, when the driver is created. A reader
//! keeps the region alive after the driver is dropped; the driver's
//! counters then read as pending release with their last values, and
//! nothing reallocates them.

use karyos_sys::counters::{Counter, CountersManager, CountersReader, counters};

use crate::error::DriverError;

/// Type id of an event counter (only grows).
pub const TYPE_EVENTS: u64 = 1;
/// Type id of a gauge (current value).
pub const TYPE_GAUGE: u64 = 2;
/// Type id of a stream position in bytes, sampled by the driver.
pub const TYPE_POSITION: u64 = karyos_sys::counters::TYPE_POSITION;
/// Type id of an idle loop's spin time: lifetime host `CLOCK_MONOTONIC`
/// nanoseconds in busy-spin phases (`crate::spin`, cnc-primitives.md).
pub const TYPE_SPIN_TIME: u64 = 3;
/// Type id of a host `CLOCK_MONOTONIC` time in nanoseconds.
pub const TYPE_TIMESTAMP: u64 = karyos_sys::counters::TYPE_TIMESTAMP;

/// Counters the driver allocates, in cell order.
const LABELS: [(u64, &str); 78] = [
    (TYPE_EVENTS, "clients admitted"),
    (TYPE_EVENTS, "clients retired"),
    (TYPE_EVENTS, "clients faulty"),
    (TYPE_EVENTS, "commands served"),
    (TYPE_EVENTS, "commands refused"),
    (TYPE_EVENTS, "responses sent"),
    (TYPE_GAUGE, "terminal"),
    (TYPE_GAUGE, "streams active"),
    (TYPE_GAUGE, "streams retiring"),
    (TYPE_EVENTS, "streams freed"),
    (TYPE_EVENTS, "registrations swept"),
    (TYPE_EVENTS, "counter overflows"),
    (TYPE_GAUGE, "clients connected"),
    (TYPE_GAUGE, "hand-over entries held"),
    (TYPE_GAUGE, "stream leases live"),
    (TYPE_EVENTS, "streams removed"),
    (TYPE_EVENTS, "claims aborted at deadline"),
    (TYPE_EVENTS, "claim deadlines resolved"),
    (TYPE_EVENTS, "claim clock steps back"),
    (TYPE_EVENTS, "claim deadlines unrepresentable"),
    (TYPE_GAUGE, "claims waiting"),
    (TYPE_EVENTS, "clients timed out"),
    (TYPE_EVENTS, "participants revoked"),
    (TYPE_EVENTS, "required participants lost"),
    (TYPE_EVENTS, "required bounds withdrawn"),
    (TYPE_EVENTS, "events not sent"),
    (TYPE_EVENTS, "grants reserved"),
    (TYPE_EVENTS, "grants ended"),
    (TYPE_EVENTS, "grants exported"),
    (TYPE_EVENTS, "grants detached"),
    (TYPE_EVENTS, "grants fenced"),
    (TYPE_GAUGE, "positions epoch"),
    (TYPE_TIMESTAMP, "positions sampled at"),
    (TYPE_EVENTS, "counters unavailable"),
    (TYPE_GAUGE, "generations retired"),
    (TYPE_GAUGE, "slots quarantined"),
    (TYPE_GAUGE, "spare reservations in use"),
    (TYPE_GAUGE, "loans outstanding"),
    (TYPE_EVENTS, "retirement pool exhausted"),
    (TYPE_EVENTS, "error events dropped"),
    (TYPE_EVENTS, "error records overwritten"),
    (TYPE_EVENTS, "loss records overwritten"),
    (TYPE_EVENTS, "loss reports unverified"),
    (TYPE_EVENTS, "overruns rejoin at head"),
    (TYPE_EVENTS, "overruns snapshot"),
    (TYPE_EVENTS, "overruns close"),
    (TYPE_EVENTS, "replay fallbacks"),
    (TYPE_EVENTS, "trace records mirrored"),
    (TYPE_EVENTS, "trace mirror overwritten"),
    (TYPE_GAUGE, "trace journals open"),
    (TYPE_EVENTS, "trace journal faults"),
    (TYPE_EVENTS, "guard outcomes written"),
    (TYPE_EVENTS, "guard outcomes lost"),
    (TYPE_EVENTS, "guard walker budget exhausted"),
    (TYPE_GAUGE, "network trace journals open"),
    (TYPE_EVENTS, "network trace journals refused"),
    (TYPE_EVENTS, "network trace journals unhooked"),
    (TYPE_EVENTS, "replay targets not retired"),
    (TYPE_EVENTS, "overruns replayed"),
    (TYPE_GAUGE, "driver pid"),
    (TYPE_TIMESTAMP, "driver started at"),
    (TYPE_TIMESTAMP, "conductor duty at"),
    (TYPE_EVENTS, "capability fallback"),
    (TYPE_EVENTS, "capability missing"),
    (TYPE_EVENTS, "guard audit records overwritten"),
    (TYPE_EVENTS, "guard audit records dropped"),
    (TYPE_EVENTS, "schedule violations"),
    (TYPE_EVENTS, "schedule violations dropped"),
    (TYPE_EVENTS, "grants released at exit"),
    (TYPE_EVENTS, "fetches dropped at exit"),
    (TYPE_EVENTS, "admission messages dropped at exit"),
    (TYPE_EVENTS, "admission messages not sent at exit"),
    (TYPE_EVENTS, "clients closed before their exit"),
    (TYPE_EVENTS, "fetches abandoned at leave"),
    (TYPE_EVENTS, "trace point ids exhausted"),
    (TYPE_GAUGE, "trace points per client"),
    (TYPE_GAUGE, "trace point registrations per client"),
    (TYPE_EVENTS, "trace point copies dropped"),
];

/// The fixed counters, which every counters region must hold: the labels,
/// and the conductor loop's spin time cell (`crate::spin`), which its
/// loop's meter writes and so is held apart.
pub(crate) const FIXED_COUNTERS: usize = LABELS.len() + 1;

/// One of the driver's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    /// Clients admitted by `connect`.
    ClientsAdmitted,
    /// Admission slots released (the client's close flag was observed).
    ClientsRetired,
    /// Clients retired for a protocol violation, counted at the first
    /// retirement; their slot is released later and counted in
    /// `ClientsRetired`.
    ClientsFaulty,
    /// Commands decoded and executed or refused; malformed records are not
    /// commands and count in `ClientsFaulty` instead.
    CommandsServed,
    /// Served commands answered with an `Error`.
    CommandsRefused,
    /// Responses written to the broadcast buffer.
    ResponsesSent,
    /// 1 once the driver is in its terminal state.
    Terminal,
    /// Streams accepting new capabilities.
    StreamsActive,
    /// Streams removed but not yet freed.
    StreamsRetiring,
    /// Streams freed.
    StreamsFreed,
    /// Registrations forgotten because their capability was dropped.
    RegistrationsSwept,
    /// Increments that would have overflowed and were not applied.
    CounterOverflows,
    /// Admission slots in use, including retired faulty clients whose
    /// producer has not detached yet.
    ClientsConnected,
    HandOverHeld,
    /// Leases over all streams; a forgotten handle stays counted.
    LeasesLive,
    /// Streams that went from active to retiring; a repeated
    /// `remove_stream` is not counted again.
    StreamsRemoved,
    /// Deadline calls that won an abort.
    ClaimsAborted,
    /// Deadline calls that found an expired claim already terminal.
    ClaimDeadlinesResolved,
    /// Deadline calls that re-anchored a timer after the clock went back.
    ClaimClockStepsBack,
    /// Deadline calls whose expiry instant does not fit `u64`.
    ClaimDeadlinesUnrepresentable,
    /// Streams whose latest deadline call returned `Waiting`.
    ClaimsWaiting,
    /// Clients whose heartbeat stopped for the liveness timeout.
    ClientsTimedOut,
    /// Subscribers revoked because their client was lost.
    ParticipantsRevoked,
    /// Required subscribers among them (SPEC.md §4
    /// `required_participant_lost`).
    RequiredParticipantsLost,
    /// Revoked `hold` subscribers whose bound a later scan withdrew.
    RequiredBoundsWithdrawn,
    /// Driver events the broadcast buffer had no room for.
    EventsNotSent,
    /// Participants reserved for a remote client's grant.
    GrantsReserved,
    /// Grants whose registration the driver ended in a buffer.
    GrantsEnded,
    /// Grants whose fetch was sent whole.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "fetches are served only on Linux")
    )]
    GrantsExported,
    /// Grants a client ended with `Detach`.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "Detach is served only on Linux")
    )]
    GrantsDetached,
    /// Successor grants fenced at a cutover deadline.
    GrantsFenced,
    /// The sampling pass sequence: odd while a pass writes.
    PositionsEpoch,
    /// Host `CLOCK_MONOTONIC` nanoseconds of the last completed pass.
    PositionsSampledAt,
    /// Counter allocations refused for lack of a free cell.
    CountersUnavailable,
    /// Mappings retired but not yet reclaimed, over all streams.
    GenerationsRetired,
    /// Slots in `RECLAIMING` with a live loan.
    SlotsQuarantined,
    /// Spare-slot credits held by admitted subscribers.
    SpareReservationsInUse,
    /// Non-zero loan words.
    LoansOutstanding,
    /// Reconfigurations refused because the retirement pool is full.
    RetirementPoolExhausted,
    /// Error events lost before reaching the error log: today only when
    /// the log's sequences are exhausted; phase 2 also counts events the
    /// agents' bounded queue to the conductor drops.
    ErrorEventsDropped,
    /// Error log records overwritten.
    ErrorRecordsOverwritten,
    /// Loss report records overwritten.
    LossRecordsOverwritten,
    /// Loss reports recorded unverified: their subscription had already
    /// ended.
    LossReportsUnverified,
    /// Reported overruns whose applied policy was `rejoin at head`.
    OverrunsRejoinAtHead,
    /// Reported overruns whose applied policy was `snapshot`, rebuilt or
    /// failed.
    OverrunsSnapshot,
    /// Reported overruns whose applied policy was `close`.
    OverrunsClose,
    /// Reported overruns whose `replay` policy fell back to its secondary,
    /// which is also counted under its own policy.
    ReplayFallbacks,
    /// Client trace journal records copied into the trace mirror.
    TraceRecordsMirrored,
    /// Trace mirror ring records overwritten: mirror loss, never journal
    /// loss.
    TraceMirrorOverwritten,
    /// Client trace journals whose writer may still append.
    TraceJournalsOpen,
    /// Client trace journals no longer drained after a protocol violation.
    TraceJournalFaults,
    /// Final outcome records the guard walkers wrote into handle rings.
    GuardOutcomesWritten,
    /// Outcome records counted as lost (a faulted client, or a block no
    /// issued handle reserved).
    GuardOutcomesLost,
    /// Duty cycles in which a guard walker used its whole budget.
    GuardWalkerBudgetExhausted,
    /// Network trace journals whose agent may still append
    /// (`trace-network.md`, NT-3).
    NetworkTraceJournalsOpen,
    /// Network trace journals refused: over `max_network_journal_bytes`,
    /// no free table entry (`trace-network.md` §4), or not taken by their
    /// agent (no hook there, or its publication or image is gone).
    NetworkTraceJournalsRefused,
    /// Network trace journals closed without facts because their side's
    /// hook was replaced or removed: `Lost`, never refused.
    NetworkTraceJournalsUnhooked,
    /// Replay targets whose feed was dropped unfinished and whose retire
    /// then failed; such a target is no longer tracked.
    ReplayTargetsNotRetired,
    /// Reported overruns that `replay` recovered from a recording, merging
    /// back into the live stream.
    OverrunsReplayed,
    /// The driver process's id in the driver's own pid namespace (a tool
    /// in another namespace knows the process by another number), so a
    /// tool can tell which process it reads
    /// (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`,
    /// M1).
    DriverPid,
    /// Host `CLOCK_MONOTONIC` nanoseconds when the driver was created.
    DriverStartedAt,
    /// Host `CLOCK_MONOTONIC` nanoseconds of the last duty cycle, read at
    /// its end with the positions pass, 0 before the first: a tool's age
    /// of it grows while the conductor stalls.
    ConductorDutyAt,
    /// Endpoint capabilities running on a fallback, once per endpoint
    /// epoch (SPEC §16.8; `crate::capabilities`).
    CapabilityFallback,
    /// Endpoint opens and reopens refused because a required capability
    /// was not active (SPEC §16.8).
    CapabilityMissing,
    /// Guard audit ring records overwritten by newer ones (M4).
    GuardAuditOverwritten,
    /// Guard audit ring records dropped once its sequences were exhausted
    /// (M4).
    GuardAuditDropped,
    /// Timed lanes sealed with `ScheduleViolation`: their publisher breached
    /// the schedule ring's protocol (`quantstratum-docs:
    /// karyos/design/timed-tx.md`, section 11, TT-6).
    ScheduleViolations,
    /// Schedule violation reports dropped: past their bound, or naming a
    /// publication, lane or incarnation no longer live.
    ScheduleViolationsDropped,
    /// Grants whose descriptor left and that a remote client did not
    /// detach: its exit proof (or its `Leave`) ended them, after its queued
    /// messages were drained. A faulty client is retired without a drain,
    /// so its grants count here too. `GrantsDetached` counts a `Detach`
    /// (karyos#827).
    GrantsReleasedAtExit,
    /// `Fetch` messages found queued after a client's exit proof, or after
    /// a close before it: not served, since they would create state for a
    /// dead client. "Clients closed before their exit" tells the cases
    /// apart.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "admission is served only on Linux")
    )]
    FetchesDroppedAtExit,
    /// Other admission messages left after a client's exit proof: a
    /// `Detach` naming no detachable export, undecodable, carrying a
    /// descriptor, a receive error, or still queued at the drain's bound
    /// (counted once).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "admission is served only on Linux")
    )]
    AdmissionMessagesDroppedAtExit,
    /// Admission messages queued for a client when its exit was proven, or
    /// when its socket closed before it, dropped unsent.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "admission is served only on Linux")
    )]
    OutboundDroppedAtExit,
    /// Remote clients whose socket closed (end of file, `EPIPE` or
    /// `ECONNRESET`, the end of file confirmed by `POLLRDHUP`) before their
    /// exit proof: drained, then retired like a faulty client but not
    /// counted as one, since a dying process closes its socket first
    /// (karyos#827). One with no exit proof within `fetch_deadline` is
    /// then counted in `ClientsFaulty` as well.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "admission is served only on Linux")
    )]
    ClientsClosedBeforeExit,
    /// Remote clients that left with a fetch outstanding: a fetch whose
    /// reply they abandoned, or exports not detached. A clean leave, not a
    /// fault; what was exported stays charged until the exit proof
    /// (karyos#851). Last, so no other counter's id moves.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist on Linux only")
    )]
    FetchesAbandonedAtLeave,
    /// Trace point registrations refused with `TracePointIdsExhausted`:
    /// the instance assigned every id, which is never reused (R-CORE-1,
    /// karyos#722). Last, so no other counter's id moves.
    TracePointIdsExhausted,
    /// The driver's configured `max_trace_points_per_client`, set at
    /// creation, so a tool reports the bound this driver enforces
    /// (karyos#868). After the earlier counters, so none of their ids
    /// moves.
    TracePointsPerClient,
    /// The driver's configured `max_trace_point_registrations_per_client`,
    /// set at creation (karyos#868).
    TracePointRegistrationsPerClient,
    /// Trace points registered with no driver-written copy, because
    /// `max_trace_point_copies` copies were live (karyos#869).
    TracePointCopiesDropped,
}

/// The driver's counters region and its counter capabilities.
#[derive(Debug)]
pub(crate) struct DriverCounters {
    manager: CountersManager,
    reader: CountersReader,
    counters: Vec<Counter>,
    /// The conductor loop's spin time cell: fixed, kept here, written from
    /// the meter's shared word (`crate::spin`).
    spin: Counter,
}

impl DriverCounters {
    /// Allocates a region of exactly the fixed counters (control path).
    #[cfg(test)]
    pub(crate) fn new() -> Result<Self, DriverError> {
        Self::with_capacity(FIXED_COUNTERS)
    }

    /// Allocates a region of `capacity` cells and every fixed counter; the
    /// rest serve position cells (control path).
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::InvalidConfig`] when `capacity` cannot hold
    /// the fixed counters or cannot be allocated.
    pub(crate) fn with_capacity(capacity: usize) -> Result<Self, DriverError> {
        if capacity < FIXED_COUNTERS {
            return Err(DriverError::InvalidConfig);
        }
        let (manager, reader) = counters(capacity).map_err(|_| DriverError::InvalidConfig)?;
        Self::allocate(manager, reader)
    }

    /// Allocates the region in a shared region (IPC mode), with `capacity`
    /// cells.
    #[cfg(target_os = "linux")]
    pub(crate) fn new_in(
        instance: u128,
        region: u64,
        capacity: usize,
    ) -> Result<Self, DriverError> {
        if capacity < FIXED_COUNTERS {
            return Err(DriverError::InvalidConfig);
        }
        let (manager, reader) = karyos_sys::counters::counters_in(instance, region, capacity)?;
        Self::allocate(manager, reader)
    }

    fn allocate(mut manager: CountersManager, reader: CountersReader) -> Result<Self, DriverError> {
        let counters = LABELS
            .iter()
            .map(|&(type_id, label)| manager.allocate(type_id, label))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DriverError::InvalidConfig)?;
        let spin = manager
            .allocate(TYPE_SPIN_TIME, "conductor spin time")
            .map_err(|_| DriverError::InvalidConfig)?;
        Ok(Self {
            manager,
            reader,
            counters,
            spin,
        })
    }

    /// Sets the conductor loop's spin time (`crate::spin`).
    pub(crate) fn set_conductor_spin(&self, value: u64) {
        self.spin.set(value);
    }

    /// Allocates a keyed counter outside the fixed set (inside a sampling
    /// pass); `None`, counted in `counters unavailable`, when no cell is
    /// free.
    pub(crate) fn allocate_keyed(
        &mut self,
        type_id: u64,
        label: &str,
        keys: karyos_sys::counters::CounterKeys,
    ) -> Option<Counter> {
        match self.manager.allocate_keyed(type_id, label, keys) {
            Ok(counter) => Some(counter),
            Err(_) => {
                self.add(Event::CountersUnavailable, 1);
                None
            }
        }
    }

    /// Allocates a driver-written copy of a client's trace point (karyos#869):
    /// a cell of type id 8 with the point's `name` as its label, keyed to
    /// the client, published with its `id` as its value. Clients never
    /// write this region, so its value is the id the driver assigned.
    /// `None`, counted in `counters unavailable`, when no cell is free.
    pub(crate) fn allocate_point_name(
        &mut self,
        name: &str,
        keys: karyos_sys::counters::CounterKeys,
        id: u16,
    ) -> Option<Counter> {
        match self.manager.allocate_valued_where(
            karyos_sys::counters::TYPE_TRACE_POINT,
            name,
            keys,
            u64::from(id),
            |_| true,
        ) {
            Ok(counter) => Some(counter),
            Err(_) => {
                self.add(Event::CountersUnavailable, 1);
                None
            }
        }
    }

    /// Counts an allocation refused without scanning the region, because
    /// an earlier allocation in the same pass already found it full.
    pub(crate) fn count_unavailable(&self) {
        self.add(Event::CountersUnavailable, 1);
    }

    /// Allocates a keyed counter again after an earlier refusal that
    /// [`allocate_keyed`](Self::allocate_keyed) already counted; `None`,
    /// not counted again, when still no cell is free.
    pub(crate) fn retry_keyed(
        &mut self,
        type_id: u64,
        label: &str,
        keys: karyos_sys::counters::CounterKeys,
    ) -> Option<Counter> {
        self.manager.allocate_keyed(type_id, label, keys).ok()
    }

    /// Frees a keyed counter at once (inside a sampling pass).
    pub(crate) fn free(&mut self, counter: Counter) {
        // A refused free leaves the cell pending release, so it is not
        // reused while anything might still name it.
        let _ = self.manager.free(counter);
    }

    /// Begins a sampling pass with the odd `epoch`.
    pub(crate) fn begin_pass(&self, epoch: u64) {
        if let Some(counter) = self.counter(Event::PositionsEpoch) {
            counter.begin_pass(epoch);
        }
    }

    /// Ends a sampling pass with the even `epoch`.
    pub(crate) fn end_pass(&self, epoch: u64) {
        if let Some(counter) = self.counter(Event::PositionsEpoch) {
            counter.end_pass(epoch);
        }
    }

    fn counter(&self, event: Event) -> Option<&Counter> {
        self.counters.get(event as usize)
    }

    /// Adds `delta` to an event counter.
    pub(crate) fn add(&self, event: Event, delta: u64) {
        let Some(counter) = self.counter(event) else {
            return;
        };
        if counter.increment(delta).is_err()
            && let Some(overflows) = self.counter(Event::CounterOverflows)
        {
            // Overflowing the overflow counter itself leaves it at its last
            // value; nothing further can record it.
            let _ = overflows.increment(1);
        }
    }

    /// Adds `delta` to a keyed event counter, reporting an overflow as
    /// [`add`](Self::add) does.
    pub(crate) fn add_to(&self, counter: &Counter, delta: u64) {
        if counter.increment(delta).is_err()
            && let Some(overflows) = self.counter(Event::CounterOverflows)
        {
            let _ = overflows.increment(1);
        }
    }

    /// Sets a gauge.
    pub(crate) fn set(&self, event: Event, value: u64) {
        if let Some(counter) = self.counter(event) {
            counter.set(value);
        }
    }

    /// The shared region of the counters, in IPC mode.
    #[cfg(target_os = "linux")]
    pub(crate) fn region(&self) -> Option<&karyos_sys::ipc::Region> {
        self.reader.region()
    }

    /// A read-only view for tools.
    pub(crate) fn reader(&self) -> CountersReader {
        self.reader.clone()
    }

    /// An event's current value.
    #[cfg(test)]
    pub(crate) fn value(&self, event: Event) -> u64 {
        use karyos_sys::counters::CellRead;
        match self.reader.read(self.counter(event).unwrap().index()) {
            CellRead::Allocated { value, .. } => value,
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use karyos_sys::counters::CellRead;

    use super::*;

    /// `Event` discriminants index `LABELS`: every event names its own
    /// label.
    #[test]
    fn events_match_their_labels() {
        let counters = DriverCounters::new().unwrap();
        let events = [
            (Event::ClientsAdmitted, "clients admitted"),
            (Event::ClientsRetired, "clients retired"),
            (Event::ClientsFaulty, "clients faulty"),
            (Event::CommandsServed, "commands served"),
            (Event::CommandsRefused, "commands refused"),
            (Event::ResponsesSent, "responses sent"),
            (Event::Terminal, "terminal"),
            (Event::StreamsActive, "streams active"),
            (Event::StreamsRetiring, "streams retiring"),
            (Event::StreamsFreed, "streams freed"),
            (Event::RegistrationsSwept, "registrations swept"),
            (Event::CounterOverflows, "counter overflows"),
            (Event::ClientsConnected, "clients connected"),
            (Event::HandOverHeld, "hand-over entries held"),
            (Event::LeasesLive, "stream leases live"),
            (Event::StreamsRemoved, "streams removed"),
            (Event::ClaimsAborted, "claims aborted at deadline"),
            (Event::ClaimDeadlinesResolved, "claim deadlines resolved"),
            (Event::ClaimClockStepsBack, "claim clock steps back"),
            (
                Event::ClaimDeadlinesUnrepresentable,
                "claim deadlines unrepresentable",
            ),
            (Event::ClaimsWaiting, "claims waiting"),
            (Event::ClientsTimedOut, "clients timed out"),
            (Event::ParticipantsRevoked, "participants revoked"),
            (
                Event::RequiredParticipantsLost,
                "required participants lost",
            ),
            (Event::RequiredBoundsWithdrawn, "required bounds withdrawn"),
            (Event::EventsNotSent, "events not sent"),
            (Event::GrantsReserved, "grants reserved"),
            (Event::GrantsEnded, "grants ended"),
            (Event::GrantsExported, "grants exported"),
            (Event::GrantsDetached, "grants detached"),
            (Event::GrantsFenced, "grants fenced"),
            (Event::PositionsEpoch, "positions epoch"),
            (Event::PositionsSampledAt, "positions sampled at"),
            (Event::CountersUnavailable, "counters unavailable"),
            (Event::GenerationsRetired, "generations retired"),
            (Event::SlotsQuarantined, "slots quarantined"),
            (Event::SpareReservationsInUse, "spare reservations in use"),
            (Event::LoansOutstanding, "loans outstanding"),
            (Event::RetirementPoolExhausted, "retirement pool exhausted"),
            (Event::ErrorEventsDropped, "error events dropped"),
            (Event::ErrorRecordsOverwritten, "error records overwritten"),
            (Event::LossRecordsOverwritten, "loss records overwritten"),
            (Event::LossReportsUnverified, "loss reports unverified"),
            (Event::OverrunsRejoinAtHead, "overruns rejoin at head"),
            (Event::OverrunsSnapshot, "overruns snapshot"),
            (Event::OverrunsClose, "overruns close"),
            (Event::ReplayFallbacks, "replay fallbacks"),
            (Event::TraceRecordsMirrored, "trace records mirrored"),
            (Event::TraceMirrorOverwritten, "trace mirror overwritten"),
            (Event::TraceJournalsOpen, "trace journals open"),
            (Event::TraceJournalFaults, "trace journal faults"),
            (Event::GuardOutcomesWritten, "guard outcomes written"),
            (Event::GuardOutcomesLost, "guard outcomes lost"),
            (
                Event::GuardWalkerBudgetExhausted,
                "guard walker budget exhausted",
            ),
            (
                Event::NetworkTraceJournalsOpen,
                "network trace journals open",
            ),
            (
                Event::NetworkTraceJournalsRefused,
                "network trace journals refused",
            ),
            (
                Event::NetworkTraceJournalsUnhooked,
                "network trace journals unhooked",
            ),
            (Event::ReplayTargetsNotRetired, "replay targets not retired"),
            (Event::OverrunsReplayed, "overruns replayed"),
            (Event::DriverPid, "driver pid"),
            (Event::DriverStartedAt, "driver started at"),
            (Event::ConductorDutyAt, "conductor duty at"),
            (Event::CapabilityFallback, "capability fallback"),
            (Event::CapabilityMissing, "capability missing"),
            (
                Event::GuardAuditOverwritten,
                "guard audit records overwritten",
            ),
            (Event::GuardAuditDropped, "guard audit records dropped"),
            (Event::ScheduleViolations, "schedule violations"),
            (
                Event::ScheduleViolationsDropped,
                "schedule violations dropped",
            ),
            (Event::GrantsReleasedAtExit, "grants released at exit"),
            (Event::FetchesDroppedAtExit, "fetches dropped at exit"),
            (
                Event::AdmissionMessagesDroppedAtExit,
                "admission messages dropped at exit",
            ),
            (
                Event::OutboundDroppedAtExit,
                "admission messages not sent at exit",
            ),
            (
                Event::ClientsClosedBeforeExit,
                "clients closed before their exit",
            ),
            (Event::FetchesAbandonedAtLeave, "fetches abandoned at leave"),
            (Event::TracePointIdsExhausted, "trace point ids exhausted"),
            (Event::TracePointsPerClient, "trace points per client"),
            (
                Event::TracePointRegistrationsPerClient,
                "trace point registrations per client",
            ),
            (Event::TracePointCopiesDropped, "trace point copies dropped"),
        ];
        assert_eq!(events.len(), LABELS.len());
        let reader = counters.reader();
        for (event, label) in events {
            counters.add(event, 1);
            let index = counters.counter(event).unwrap().index();
            let CellRead::Allocated {
                metadata, value, ..
            } = reader.read(index)
            else {
                panic!("counter {label} not allocated");
            };
            assert_eq!(metadata.label(), label.as_bytes());
            assert_eq!(value, 1);
        }
    }

    #[test]
    fn an_overflow_is_recorded_not_wrapped() {
        let counters = DriverCounters::new().unwrap();
        counters.set(Event::CommandsServed, u64::MAX);
        counters.add(Event::CommandsServed, 1);
        let reader = counters.reader();
        let read = |event| match reader.read(counters.counter(event).unwrap().index()) {
            CellRead::Allocated { value, .. } => value,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(read(Event::CommandsServed), u64::MAX);
        assert_eq!(read(Event::CounterOverflows), 1);
    }
}
