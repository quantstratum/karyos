// SPDX-License-Identifier: Apache-2.0

//! Multicast receiver membership and flow control
//! (`quantstratum-docs: karyos/design/multicast-flow-control.md`; P2.7 A;
//! MC-1 to MC-9, ACS 15597, 15604 and 15610).
//!
//! [`Membership`] is one publication incarnation's receiver table. The
//! sender agent owns it and is its only writer (MC-1). It takes the SMs
//! that the session binding has already validated, and answers the
//! sender's questions: the per-lane submission edge, whether admission is
//! open, whether the publication is connected and what required
//! consumption bounds retention.
//!
//! - **Members.** A member is keyed by `receiver_id` and
//!   `receiver_boot_id` within the table's publication identity and alias;
//!   a new boot id is a new membership, never a continuation. Each slot has a
//!   private checked generation, raised at every reuse; queued work names
//!   it ([`MemberRef`]) and is rechecked with [`Membership::current`]. A
//!   slot whose generation is exhausted is retired for the incarnation.
//! - **Bindings** (MC-9, ACS 15636). Every SM arrives through a session
//!   binding ([`SmKey`]). A member records the `(endpoint, source)` pairs
//!   of its accepted SMs, at most `max_paths`, and stays one logical
//!   receiver whatever path carries its SM: a copy over a second path
//!   changes nothing more. A binding beyond `max_paths` is refused and
//!   counted; the SM still applies. [`Membership::binding_gone`] removes a
//!   binding, and only the removal of a member's last binding removes the
//!   member: an optional one expires and a required one is lost (M5). The
//!   sender calls it synchronously when its binding row is removed or
//!   reset, never from a queue, and before a reset that changes the
//!   receiver or its boot id (ACS 15647). A binding refused for
//!   `max_paths` is not recorded: the member can be removed while still
//!   reachable on it, until that path's next accepted SM.
//! - **Roles and tags** are configured ([`Roles`]): a packet cannot promote
//!   itself to required or choose its group. An SM whose `group_tag`
//!   differs from the receiver's configured tag (0 when none) is rejected
//!   whole (MC-2). The required set is fixed for the incarnation (owner
//!   decision M4): a required receiver has one membership, and a second
//!   boot id is refused.
//! - **Credit** (MC-5). A member's first SM is its join: it fixes each
//!   lane's window, which must lie in `min_window..=max_window`. A later SM
//!   with another window, a lower consumption (stale), a consumption above
//!   the lane's `sent_high` (MC-9) or an overflowing edge is rejected whole
//!   and counted; a rejected SM changes and refreshes nothing.
//! - **Liveness** (ACS 15604, 15610). An accepted SM is fresh when it
//!   advances consumption on a lane, or reports `sent_high` on every lane
//!   (caught up). A member is live while its last accepted SM is younger
//!   than `receiver_timeout` and its last fresh SM younger than
//!   `pause_timeout`, so a stationary member stays only until
//!   `pause_timeout`. Expiry is judged by `age_ns` at the time of the
//!   question, even before [`Membership::timers`] has reached the entry.
//! - **Limits.** A lane's edge is the strategy's extremum of the live
//!   members' `consumption + window` ([`Strategy`]), then the minimum
//!   with every live required member's edge. No strategy member gives
//!   [`Limit::NoReceiverWindow`] (MC-3); an unresolved required loss gives
//!   [`Limit::Held`]: no new first sends on any lane, and no drain (MC-7).
//! - **Admission and loss** (owner decision M5). Admission opens once every
//!   configured required receiver has joined; a lost required member stops
//!   it for the incarnation and keeps its last consumption in the
//!   retention bound. An expired optional member leaves a tombstone: its
//!   receiver, boot id and last consumption (ACS 15647). While the
//!   tombstone exists, an SM of that receiver rejoins only when it is fresh
//!   against it (it advances a lane with none lower, or it is caught up on
//!   every lane) or after a new [`Membership::expect`]; any other SM is
//!   rejected (`Expired`) and counted, so stationary SMs of a paused member
//!   cannot defeat `pause_timeout` by rejoining, and a delayed old SM
//!   cannot rejoin at a lower point. The tombstone is cleared after
//!   `receiver_timeout` without any SM of it, or when a new establishment
//!   ([`Membership::expect`]) or a configured required receiver needs its
//!   slot; an SM-driven optional join never takes another receiver's
//!   tombstone (ACS 15663). A rejoin is a new membership with a new
//!   generation and join point.
//!
//! The table, the role lists and the event queue are sized at
//! construction; the data calls do not allocate. Counters never wrap: a
//! count at its end keeps its value and sets the sticky `overflowed` flag
//! (SPEC.md section 14).

use std::net::SocketAddr;

use karyos_protocol::frame::Lane;
use karyos_protocol::network::{Alias, Identity, MAX_LANES, Receiver, StatusMessage};
pub use karyos_protocol::roles::{PublicationRoles, ReceiverIdentity, Roles, Strategy};
use karyos_sys::host_clock::age_ns;

use crate::agents::EndpointId;
use crate::paths::MAX_PATHS;
use crate::repair::admission::Requester;

/// The session binding an SM arrived through (ACS 15595, 15636): the
/// sender's key for an accepted SM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmKey {
    /// The endpoint it arrived on.
    pub endpoint: EndpointId,
    /// The publication's alias and stream.
    pub alias: Alias,
    /// Its source, normalized.
    pub source: SocketAddr,
    /// The publication incarnation.
    pub identity: Identity,
    /// The receiver, boot id included.
    pub receiver: Receiver,
}

/// A member's binding: where its SMs may come from.
type Binding = (EndpointId, SocketAddr);

/// The bindings a member holds: [`MAX_PATHS`].
const BINDINGS: usize = 16;

const _: () = assert!(MAX_PATHS == 16, "BINDINGS is MAX_PATHS");

/// The membership settings (MC-1, MC-5, MC-6; provisional and
/// configurable). Times are in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipConfig {
    /// Table entries, required members included (default 64).
    pub max_receivers: u16,
    /// Entries waiting for their first SM (default 16).
    pub max_pending: u16,
    /// Bindings per member, 1 to [`MAX_PATHS`] (default 4).
    pub max_paths: u8,
    /// The publication's lane count, 1 to 4.
    pub lane_count: u8,
    /// The strategy.
    pub strategy: Strategy,
    /// The least window a member may fix: the largest datagram.
    pub min_window: u32,
    /// The largest window a member may fix: the image capacity, at most
    /// half a term.
    pub max_window: u32,
    /// The receivers' SM interval (default 10 ms).
    pub sm_interval: u64,
    /// Expiry without an accepted or a fresh SM (default 5 s; at least ten
    /// `sm_interval`).
    pub receiver_timeout: u64,
    /// Expiry of a member whose SMs are stationary (default 60 s; at least
    /// `receiver_timeout`).
    pub pause_timeout: u64,
    /// Expiry of a pending entry, and the wait for the required set
    /// (default `receiver_timeout`).
    pub join_timeout: u64,
    /// Queued membership events (default 64).
    pub max_events: u16,
}

impl MembershipConfig {
    /// The defaults for a publication of `lane_count` lanes whose windows
    /// lie in `min_window..=max_window`.
    #[must_use]
    pub const fn new(lane_count: u8, min_window: u32, max_window: u32) -> Self {
        Self {
            max_receivers: DEFAULT_MAX_RECEIVERS,
            max_pending: 16,
            max_paths: 4,
            lane_count,
            strategy: Strategy::Min,
            min_window,
            max_window,
            sm_interval: 10_000_000,
            receiver_timeout: 5_000_000_000,
            pause_timeout: 60_000_000_000,
            join_timeout: 5_000_000_000,
            max_events: 64,
        }
    }

    /// Checks the settings, at configuration.
    ///
    /// # Errors
    ///
    /// See [`MembershipConfigError`].
    pub fn validate(&self) -> Result<(), MembershipConfigError> {
        if self.max_receivers == 0 || self.max_pending > self.max_receivers || self.max_events == 0
        {
            return Err(MembershipConfigError::Capacity);
        }
        if self.max_paths == 0 || self.max_paths > MAX_PATHS {
            return Err(MembershipConfigError::Paths);
        }
        if self.lane_count == 0 || usize::from(self.lane_count) > MAX_LANES {
            return Err(MembershipConfigError::Lanes);
        }
        if self.min_window == 0 || self.min_window > self.max_window {
            return Err(MembershipConfigError::Window);
        }
        let ten_intervals = self.sm_interval.checked_mul(10);
        if self.sm_interval == 0
            || self.join_timeout == 0
            || ten_intervals.is_none_or(|least| self.receiver_timeout < least)
            || self.pause_timeout < self.receiver_timeout
        {
            return Err(MembershipConfigError::Timeouts);
        }
        if self.strategy == Strategy::Tagged(0) {
            return Err(MembershipConfigError::Tag);
        }
        Ok(())
    }
}

/// Why a [`MembershipConfig`] or [`Roles`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipConfigError {
    /// No entry or event slot, or more pending entries than entries.
    #[error("no entry or event slot, or more pending entries than entries")]
    Capacity,
    /// `max_paths` is not 1 to [`MAX_PATHS`].
    #[error("max_paths is not 1 to {MAX_PATHS}")]
    Paths,
    /// The lane count is not 1 to 4.
    #[error("the lane count is not 1 to 4")]
    Lanes,
    /// `0 < min_window <= max_window` does not hold.
    #[error("0 < min_window <= max_window does not hold")]
    Window,
    /// A zero interval or join timeout, `receiver_timeout` below ten
    /// `sm_interval`, or `pause_timeout` below `receiver_timeout`.
    #[error(
        "a zero interval or join timeout, receiver_timeout below ten sm_interval, or pause_timeout below receiver_timeout"
    )]
    Timeouts,
    /// The tagged strategy names tag 0.
    #[error("the tagged strategy names tag 0")]
    Tag,
    /// A role list is longer than the table, names receiver 0 or tag 0, or
    /// names a receiver twice.
    #[error("a role list is longer than the table, names receiver or tag 0, or repeats a receiver")]
    Roles,
}

/// A membership: a slot and the generation it had then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberRef {
    /// The table slot.
    pub slot: u16,
    /// The slot's generation for this membership.
    pub generation: u64,
}

/// The result of [`Membership::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusOutcome {
    /// The SM was committed.
    Accepted {
        /// The membership it updated.
        member: MemberRef,
        /// Whether it was the membership's join.
        joined: bool,
        /// Whether it was fresh. Every accepted SM resets the
        /// `receiver_timeout` clock; a fresh one also resets the
        /// `pause_timeout` clock, which stationary SMs do not.
        fresh: bool,
    },
    /// The SM was rejected whole; it changed and refreshed nothing.
    Rejected(StatusRejected),
}

/// Why an SM (or an expected join) was rejected; each reason is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusRejected {
    /// Another publication incarnation or alias.
    Identity,
    /// The key's receiver, identity or alias is not the SM's.
    Key,
    /// Not exactly the publication's lane count.
    Lanes,
    /// The declared tag is not the configured one (MC-2).
    Tag,
    /// A join window outside `min_window..=max_window`.
    Window,
    /// A window other than the one fixed at the join (`sm_window_changed`).
    WindowChanged,
    /// A consumption below the last accepted one: reordered or replayed.
    Stale,
    /// A consumption above the lane's `sent_high`.
    Beyond,
    /// `consumption + window` overflows.
    Overflow,
    /// A second boot id for a required receiver (owner decision M4).
    BootChanged,
    /// A required member that is lost; its return needs a new incarnation.
    Lost,
    /// An SM of an expired optional member that is not fresh against its
    /// tombstone: stationary, or older.
    Expired,
    /// No slot left for a newcomer: nothing is evicted.
    TableFull,
    /// The pending limit is reached.
    PendingFull,
}

/// The result of [`Membership::binding_gone`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gone {
    /// No member holds that binding.
    Unknown,
    /// The member keeps another binding.
    Remaining,
    /// It was the last binding: a pending entry is removed, and an optional
    /// member leaves a tombstone.
    Removed,
    /// It was a required member's last binding: it is lost (M5).
    Lost,
}

/// A lane's submission edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// First sends may go up to, not including, this position.
    Edge(u64),
    /// No live strategy member on this lane (MC-3): no first sends.
    NoReceiverWindow,
    /// A required loss is unresolved: no first sends on any lane (MC-7).
    Held,
}

/// The application admission gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Every required member has joined and none is lost.
    Open,
    /// A configured required member has not joined yet.
    NotJoined,
    /// A required member is lost (owner decision M5): stopped for the
    /// incarnation.
    LostRequired,
}

/// A membership change, queued for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberEvent {
    /// A member joined at these per-lane consumption positions.
    Joined {
        /// The membership.
        member: MemberRef,
        /// The receiver.
        receiver: Receiver,
        /// Whether it is required.
        required: bool,
        /// The join points, lane 0 first.
        joins: [u64; MAX_LANES],
    },
    /// An optional member expired, leaving a tombstone.
    Expired {
        /// The membership.
        member: MemberRef,
        /// The receiver.
        receiver: Receiver,
        /// Its last accepted consumption.
        consumption: [u64; MAX_LANES],
    },
    /// A required member expired: admission stops.
    LostRequired {
        /// The membership.
        member: MemberRef,
        /// The receiver.
        receiver: Receiver,
        /// Its last accepted consumption, kept for retention.
        consumption: [u64; MAX_LANES],
    },
    /// A required receiver has not joined within `join_timeout`.
    NotJoined {
        /// The configured receiver id.
        receiver_id: u64,
    },
}

/// What the table counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MembershipCounters {
    /// SMs accepted.
    pub accepted: u64,
    /// Memberships joined.
    pub joins: u64,
    /// Accepted SMs that were fresh.
    pub fresh: u64,
    /// Accepted SMs that repeated a state not caught up (stationary).
    pub stationary: u64,
    /// Stationary SMs accepted while only `pause_timeout` kept the member:
    /// an operator's sign of a long pause.
    pub paused: u64,
    /// SMs of another incarnation or alias.
    pub identity: u64,
    /// SMs whose key did not match them.
    pub key: u64,
    /// Bindings refused beyond `max_paths`.
    pub paths_full: u64,
    /// Bindings removed by [`Membership::binding_gone`].
    pub bindings_gone: u64,
    /// Members removed with their last binding.
    pub unbound: u64,
    /// SMs with another lane count.
    pub lanes: u64,
    /// SMs whose tag was not the configured one.
    pub tag: u64,
    /// Joins with a window out of bounds.
    pub window: u64,
    /// SMs whose window changed (`sm_window_changed`).
    pub window_changed: u64,
    /// Stale SMs.
    pub stale: u64,
    /// SMs above `sent_high`.
    pub beyond: u64,
    /// SMs whose edge overflowed.
    pub overflow: u64,
    /// SMs or joins of a second boot of a required receiver.
    pub boot_changed: u64,
    /// SMs of a lost required member.
    pub lost_rejected: u64,
    /// SMs of an expired optional member refused by its tombstone.
    pub expired_rejected: u64,
    /// Tombstones cleared after `receiver_timeout` of silence or for
    /// another receiver's slot (not its own receiver's rejoin).
    pub tombstones_cleared: u64,
    /// Newcomers refused for a full table.
    pub table_full: u64,
    /// Expected joins refused for the pending limit.
    pub pending_full: u64,
    /// Slots retired at generation exhaustion.
    pub retired_slots: u64,
    /// Pending entries removed at `join_timeout`.
    pub join_expired: u64,
    /// Optional members expired.
    pub expired: u64,
    /// Required members lost.
    pub lost_required: u64,
    /// Required receivers reported not joined.
    pub not_joined: u64,
    /// `sent_high` updates below the current value, refused.
    pub sent_regressed: u64,
    /// Events not queued for a full queue.
    pub events_dropped: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
    /// An event was dropped (sticky): the report is incomplete.
    pub events_incomplete: bool,
}

impl MembershipCounters {
    fn bump(&mut self, field: impl FnOnce(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
}

/// An entry's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    /// Expected, waiting for its first SM.
    Pending,
    /// Joined.
    Active,
    /// A required member that expired: kept until the incarnation ends.
    LostRequired,
    /// An optional member that expired: its receiver and last consumption;
    /// `last_accepted` is when the last SM of it was seen.
    Tombstone,
}

/// One table entry.
#[derive(Debug, Clone, Copy)]
struct Entry {
    state: State,
    generation: u64,
    /// Generation exhausted: never used again.
    retired: bool,
    receiver: Receiver,
    bindings: [Option<Binding>; BINDINGS],
    required: bool,
    tag: u64,
    /// When a pending entry was expected.
    since: u64,
    /// The consumption of the joining SM, per lane.
    joins: [u64; MAX_LANES],
    consumption: [u64; MAX_LANES],
    windows: [u32; MAX_LANES],
    /// `consumption + window`, checked at acceptance.
    edges: [u64; MAX_LANES],
    last_accepted: u64,
    last_fresh: u64,
}

impl Entry {
    const FREE: Self = Self {
        state: State::Free,
        generation: 0,
        retired: false,
        receiver: Receiver {
            receiver_boot_id: [0, 0],
            receiver_id: 0,
        },
        bindings: [None; BINDINGS],
        required: false,
        tag: 0,
        since: 0,
        joins: [0; MAX_LANES],
        consumption: [0; MAX_LANES],
        windows: [0; MAX_LANES],
        edges: [0; MAX_LANES],
        last_accepted: 0,
        last_fresh: 0,
    };
}

/// One publication incarnation's receiver membership.
#[derive(Debug)]
pub struct Membership {
    config: MembershipConfig,
    identity: Identity,
    alias: Alias,
    entries: Vec<Entry>,
    required: Vec<u64>,
    /// Whether each required receiver has joined (parallel to `required`).
    required_joined: Vec<bool>,
    /// Whether each required receiver was reported not joined.
    required_reported: Vec<bool>,
    /// The required destinations of a multi-destination publication, by
    /// endpoint (MD-11, MD-17; karyos#630): a member whose binding source
    /// is one of them is required.
    required_sources: Vec<SocketAddr>,
    /// Whether each required destination has joined (parallel).
    required_sources_joined: Vec<bool>,
    /// Whether each one's missing join was counted (parallel).
    required_sources_reported: Vec<bool>,
    tags: Vec<(u64, u64)>,
    sent_high: [u64; MAX_LANES],
    created: u64,
    cursor: usize,
    events: Vec<MemberEvent>,
    counters: MembershipCounters,
}

/// Table entries of a publication's membership, required members
/// included (MC-1): the most required, and the most tagged, receivers
/// its roles can name.
pub const DEFAULT_MAX_RECEIVERS: u16 = 64;

/// Whether `roles` fit a membership of `max_receivers` entries: at most
/// that many required and that many tagged receivers, no `receiver_id` 0
/// or repeated in either list, and no tag 0.
///
/// The counts are checked first, before either list is read, so a list
/// longer than the table costs nothing (karyos#637). Each list is then
/// copied into a buffer of `max_receivers` entries and sorted: O(n log n),
/// and the buffer is on the stack up to [`DEFAULT_MAX_RECEIVERS`], the
/// bound of every command, so a command allocates nothing here.
///
/// # Errors
///
/// [`MembershipConfigError::Roles`] when they do not.
pub fn check_roles(roles: &Roles<'_>, max_receivers: u16) -> Result<(), MembershipConfigError> {
    let table = usize::from(max_receivers);
    if roles.required.len() > table || roles.tags.len() > table {
        return Err(MembershipConfigError::Roles);
    }
    let mut stack = [0u64; DEFAULT_MAX_RECEIVERS as usize];
    let mut heap = Vec::new();
    let scratch: &mut [u64] = if table <= stack.len() {
        &mut stack
    } else {
        // A configured table larger than any command's: once per
        // publication, on the control path.
        heap.resize(table, 0);
        &mut heap
    };
    if zero_or_repeated(roles.required.iter().copied(), scratch)
        || zero_or_repeated(roles.tags.iter().map(|&(id, _)| id), scratch)
        || roles.tags.iter().any(|&(_, tag)| tag == 0)
    {
        return Err(MembershipConfigError::Roles);
    }
    Ok(())
}

impl Membership {
    /// A table for the publication `identity` on `alias`, created at `now`.
    ///
    /// # Errors
    ///
    /// See [`MembershipConfigError`].
    pub fn new(
        config: MembershipConfig,
        identity: Identity,
        alias: Alias,
        roles: &Roles<'_>,
        now: u64,
    ) -> Result<Self, MembershipConfigError> {
        config.validate()?;
        let table = usize::from(config.max_receivers);
        check_roles(roles, config.max_receivers)?;
        let mut events = Vec::new();
        events.reserve_exact(usize::from(config.max_events));
        Ok(Self {
            config,
            identity,
            alias,
            entries: vec![Entry::FREE; table],
            required: roles.required.to_vec(),
            required_joined: vec![false; roles.required.len()],
            required_reported: vec![false; roles.required.len()],
            required_sources: Vec::new(),
            required_sources_joined: Vec::new(),
            required_sources_reported: Vec::new(),
            tags: roles.tags.to_vec(),
            sent_high: [0; MAX_LANES],
            created: now,
            cursor: 0,
            events,
            counters: MembershipCounters::default(),
        })
    }

    /// Makes the receivers at `sources` required, as a multi-destination
    /// publication names its required destinations by endpoint (control
    /// path, before the first SM; karyos#630). Their joins gate admission
    /// like configured required receiver ids.
    pub fn set_required_sources(&mut self, sources: &[SocketAddr]) {
        self.required_sources = sources.to_vec();
        self.required_sources_joined = vec![false; sources.len()];
        self.required_sources_reported = vec![false; sources.len()];
    }

    /// Whether an active member bound to `source` is live at `now`: a
    /// multi-destination publication's destination at that address gets
    /// copies (MD-16).
    #[must_use]
    pub fn live_at(&self, source: SocketAddr, now: u64) -> bool {
        self.member_at(source, now).is_some()
    }

    /// The edge of `lane` of the live active member bound to `source` at
    /// `now`: a destination's own edge (MD-1).
    #[must_use]
    pub fn edge_at(&self, source: SocketAddr, lane: Lane, now: u64) -> Option<u64> {
        self.member_at(source, now)?
            .edges
            .get(usize::from(lane.get()))
            .copied()
    }

    fn member_at(&self, source: SocketAddr, now: u64) -> Option<&Entry> {
        self.entries.iter().find(|entry| {
            entry.state == State::Active
                && self.live(entry, now)
                && entry
                    .bindings
                    .iter()
                    .flatten()
                    .any(|(_, bound)| *bound == source)
        })
    }

    /// Its settings.
    #[must_use]
    pub const fn config(&self) -> &MembershipConfig {
        &self.config
    }

    /// The tag configured for `receiver_id` (MC-2): 0 when none is.
    #[must_use]
    pub fn configured_tag(&self, receiver_id: u64) -> u64 {
        self.tags
            .iter()
            .find(|(id, _)| *id == receiver_id)
            .map_or(0, |(_, tag)| *tag)
    }

    /// The counters.
    #[must_use]
    pub const fn counters(&self) -> &MembershipCounters {
        &self.counters
    }

    /// Raises `lane`'s `sent_high`, the highest position ever submitted on
    /// any path (MC-9). Returns false, and counts, for a lower value or a
    /// lane outside the publication.
    pub fn advance_sent(&mut self, lane: Lane, sent_high: u64) -> bool {
        let at = usize::from(lane.get());
        let Some(high) = self
            .sent_high
            .get_mut(at)
            .filter(|_| at < usize::from(self.config.lane_count))
        else {
            self.counters.bump(|c| &mut c.sent_regressed);
            return false;
        };
        if sent_high < *high {
            self.counters.bump(|c| &mut c.sent_regressed);
            return false;
        }
        *high = sent_high;
        true
    }

    /// Expects the join of `key`'s receiver, from its session
    /// establishment: a pending entry holding that binding and the `joins`
    /// the SETUP answer gave it (lane 0 first), removed at `join_timeout`
    /// unless an SM joins it first. An existing entry is returned
    /// unchanged; a repeated SETUP extends nothing.
    ///
    /// # Errors
    ///
    /// [`StatusRejected::Identity`], [`StatusRejected::BootChanged`],
    /// [`StatusRejected::Lost`], [`StatusRejected::PendingFull`] or
    /// [`StatusRejected::TableFull`].
    pub fn expect(
        &mut self,
        key: &SmKey,
        joins: &[u64],
        now: u64,
    ) -> Result<MemberRef, StatusRejected> {
        if key.identity != self.identity || key.alias != self.alias {
            return Err(self.reject(StatusRejected::Identity));
        }
        let receiver = key.receiver;
        let required =
            self.is_required(receiver.receiver_id) || self.is_required_source(key.source);
        // A new establishment lifts the receiver's tombstone, once the
        // pending and table limits pass: the next SM joins.
        let mut lift = None;
        if let Some(slot) = self.find(receiver) {
            match self.entry(slot).map(|e| e.state) {
                Some(State::LostRequired) => return Err(self.reject(StatusRejected::Lost)),
                Some(State::Tombstone) => lift = Some(slot),
                _ => {
                    self.bind(slot, key);
                    return Ok(self.member_ref(slot));
                }
            }
        }
        if required && self.other_boot(receiver).is_some() {
            return Err(self.reject(StatusRejected::BootChanged));
        }
        let pending = self
            .entries
            .iter()
            .filter(|e| e.state == State::Pending)
            .count();
        if pending >= usize::from(self.config.max_pending) {
            return Err(self.reject(StatusRejected::PendingFull));
        }
        let slot = self
            .allocate(required, true, lift)
            .map_err(|reason| self.reject(reason))?;
        let tag = self.tag_of(receiver.receiver_id);
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.state = State::Pending;
            entry.receiver = receiver;
            entry.required = required;
            entry.tag = tag;
            entry.since = now;
            for (join, given) in entry.joins.iter_mut().zip(joins) {
                *join = *given;
            }
        }
        self.bind(slot, key);
        Ok(self.member_ref(slot))
    }

    /// Takes an SM that the session binding `key` has validated, at `now`
    /// (multicast-flow-control.md, "SM validation and liveness"). An
    /// accepted SM adds `key`'s binding to its member.
    pub fn status(&mut self, key: &SmKey, sm: &StatusMessage, now: u64) -> StatusOutcome {
        if key.receiver != sm.receiver || key.identity != sm.identity || key.alias != sm.alias {
            return StatusOutcome::Rejected(self.reject(StatusRejected::Key));
        }
        match self.try_status(sm, key.source, now) {
            Ok(outcome) => {
                if let StatusOutcome::Accepted { member, .. } = outcome {
                    self.bind(usize::from(member.slot), key);
                }
                outcome
            }
            Err(reason) => StatusOutcome::Rejected(self.reject(reason)),
        }
    }

    /// Removes the binding `key` that the sender expired or evicted (ACS
    /// 15633, 15636). Only a member's last binding removes it: a required
    /// member is then lost, as at its timeout (M5), and an optional one
    /// leaves a tombstone. The binding names no generation, so the sender
    /// must call this synchronously when its binding row is removed or
    /// reset, never from a queue, and before a reset that changes the
    /// receiver or its boot id (ACS 15647).
    pub fn binding_gone(&mut self, key: &SmKey, now: u64) -> Gone {
        let Some(slot) = self
            .find(key.receiver)
            .filter(|_| key.identity == self.identity && key.alias == self.alias)
        else {
            return Gone::Unknown;
        };
        let binding = (key.endpoint, key.source);
        let Some(entry) = self.entries.get_mut(slot) else {
            return Gone::Unknown;
        };
        let Some(held) = entry.bindings.iter_mut().find(|b| **b == Some(binding)) else {
            return Gone::Unknown;
        };
        *held = None;
        let remaining = entry.bindings.iter().any(Option::is_some);
        let state = entry.state;
        self.counters.bump(|c| &mut c.bindings_gone);
        if state == State::LostRequired {
            return Gone::Lost;
        }
        if remaining {
            return Gone::Remaining;
        }
        self.counters.bump(|c| &mut c.unbound);
        match state {
            State::Active => {
                let required = self.entry(slot).is_some_and(|e| e.required);
                self.expire(slot, now);
                if required { Gone::Lost } else { Gone::Removed }
            }
            _ => {
                self.free(slot);
                Gone::Removed
            }
        }
    }

    fn try_status(
        &mut self,
        sm: &StatusMessage,
        source: SocketAddr,
        now: u64,
    ) -> Result<StatusOutcome, StatusRejected> {
        if sm.identity != self.identity || sm.alias != self.alias {
            return Err(StatusRejected::Identity);
        }
        if sm.lanes.count() != self.config.lane_count {
            return Err(StatusRejected::Lanes);
        }
        let id = sm.receiver.receiver_id;
        if sm.group_tag != self.tag_of(id) {
            return Err(StatusRejected::Tag);
        }
        let required = self.is_required(id) || self.is_required_source(source);
        let mut found = self.find(sm.receiver);
        let mut tombstone = None;
        if let Some(slot) = found {
            let expired = self
                .entry(slot)
                .is_some_and(|e| e.state == State::Active && !self.live(e, now));
            if expired {
                self.expire(slot, now);
            }
            match self.entry(slot).map(|e| e.state) {
                Some(State::LostRequired) => return Err(StatusRejected::Lost),
                Some(State::Active | State::Pending) => {}
                Some(State::Tombstone) => {
                    found = None;
                    tombstone = Some(slot);
                }
                _ => found = None,
            }
        }
        if found.is_none() && required && self.other_boot(sm.receiver).is_some() {
            return Err(StatusRejected::BootChanged);
        }
        let joining =
            found.is_none_or(|slot| self.entry(slot).is_some_and(|e| e.state == State::Pending));
        let current = found.and_then(|slot| self.entry(slot)).copied();

        let lanes = usize::from(self.config.lane_count);
        let mut edges = [0; MAX_LANES];
        let mut consumption = [0; MAX_LANES];
        let mut windows = [0; MAX_LANES];
        let mut advanced = false;
        let mut caught_up = true;
        for (lane, status) in sm.lanes.as_slice().iter().enumerate().take(lanes) {
            let sent = self.sent_high.get(lane).copied().unwrap_or(0);
            if joining {
                if status.window < self.config.min_window || status.window > self.config.max_window
                {
                    return Err(StatusRejected::Window);
                }
            } else if let Some(entry) = current {
                if entry.windows.get(lane).copied() != Some(status.window) {
                    return Err(StatusRejected::WindowChanged);
                }
                let last = entry.consumption.get(lane).copied().unwrap_or(0);
                if status.consumption < last {
                    return Err(StatusRejected::Stale);
                }
                advanced |= status.consumption > last;
            }
            if status.consumption > sent {
                return Err(StatusRejected::Beyond);
            }
            caught_up &= status.consumption == sent;
            let edge = status
                .consumption
                .checked_add(u64::from(status.window))
                .ok_or(StatusRejected::Overflow)?;
            if let (Some(e), Some(c), Some(w)) = (
                edges.get_mut(lane),
                consumption.get_mut(lane),
                windows.get_mut(lane),
            ) {
                *e = edge;
                *c = status.consumption;
                *w = status.window;
            }
        }

        // The credit checks above come first, so a doubly bad SM is counted
        // for its credit fault; then the tombstone decides.
        let lift = match tombstone {
            Some(slot) => self.tombstone_admits(slot, sm, now)?,
            None => None,
        };
        // An SM-driven join takes a free slot, or its own tombstone's; only a
        // new establishment or a configured required receiver may take
        // another receiver's tombstone.
        let slot = match found {
            Some(slot) => slot,
            None => self.allocate(required, required, lift)?,
        };
        let fresh = joining || advanced || caught_up;
        let tag = self.tag_of(id);
        let timeout = self.config.receiver_timeout;
        let Some(entry) = self.entries.get_mut(slot) else {
            return Err(StatusRejected::TableFull);
        };
        let paused = !fresh && age_ns(now, entry.last_fresh) >= timeout;
        if joining {
            entry.state = State::Active;
            entry.receiver = sm.receiver;
            entry.required = required;
            entry.tag = tag;
            entry.windows = windows;
            // An expected entry keeps the joins its answer gave; a direct
            // join starts at its first SM.
            if current.is_none() {
                entry.joins = consumption;
            }
        }
        entry.consumption = consumption;
        entry.edges = edges;
        entry.last_accepted = now;
        if fresh {
            entry.last_fresh = now;
        }
        let member = self.member_ref(slot);
        self.counters.bump(|c| &mut c.accepted);
        if fresh {
            self.counters.bump(|c| &mut c.fresh);
        } else {
            self.counters.bump(|c| &mut c.stationary);
            if paused {
                self.counters.bump(|c| &mut c.paused);
            }
        }
        if joining {
            self.counters.bump(|c| &mut c.joins);
            if let Some(at) = self.required.iter().position(|r| *r == id)
                && let Some(joined) = self.required_joined.get_mut(at)
            {
                *joined = true;
            }
            if let Some(at) = self.required_sources.iter().position(|r| *r == source)
                && let Some(joined) = self.required_sources_joined.get_mut(at)
            {
                *joined = true;
            }
            self.event(MemberEvent::Joined {
                member,
                receiver: sm.receiver,
                required,
                joins: consumption,
            });
        }
        Ok(StatusOutcome::Accepted {
            member,
            joined: joining,
            fresh,
        })
    }

    /// Whether `member` still names its membership: queued work rechecks
    /// it before applying.
    #[must_use]
    pub fn current(&self, member: MemberRef) -> bool {
        self.entry(usize::from(member.slot)).is_some_and(|e| {
            matches!(
                e.state,
                State::Pending | State::Active | State::LostRequired
            ) && e.generation == member.generation
        })
    }

    /// What a NAK from `receiver` on `lane` is checked against at `now`
    /// (R4 step 2): a live member's join point, last accepted consumption
    /// and window; an expected entry's answered join point before its
    /// first SM; otherwise [`Requester::Unknown`].
    #[must_use]
    pub fn requester(&self, receiver: Receiver, lane: Lane, now: u64) -> Requester {
        let at = usize::from(lane.get());
        if at >= usize::from(self.config.lane_count) {
            return Requester::Unknown;
        }
        let Some(entry) = self.find(receiver).and_then(|slot| self.entry(slot)) else {
            return Requester::Unknown;
        };
        let join = entry.joins.get(at).copied();
        match entry.state {
            State::Active if self.live(entry, now) => match (
                join,
                entry.consumption.get(at).copied(),
                entry.windows.get(at).copied(),
            ) {
                (Some(join), Some(consumption), Some(window)) => Requester::Member {
                    join,
                    consumption,
                    window,
                },
                _ => Requester::Unknown,
            },
            State::Pending => join.map_or(Requester::Unknown, |join| Requester::Joined { join }),
            _ => Requester::Unknown,
        }
    }

    /// `lane`'s submission edge at `now`.
    #[must_use]
    pub fn limit(&self, lane: Lane, now: u64) -> Limit {
        if self.lost(now) {
            return Limit::Held;
        }
        let at = usize::from(lane.get());
        if at >= usize::from(self.config.lane_count) {
            return Limit::NoReceiverWindow;
        }
        let mut strategy: Option<u64> = None;
        let mut required: Option<u64> = None;
        for entry in self
            .entries
            .iter()
            .filter(|e| e.state == State::Active && self.live(e, now))
        {
            let Some(edge) = entry.edges.get(at).copied() else {
                continue;
            };
            let counts = match self.config.strategy {
                Strategy::Min | Strategy::Max => true,
                Strategy::Tagged(tag) => entry.tag == tag,
            };
            if counts {
                strategy = Some(match (self.config.strategy, strategy) {
                    (_, None) => edge,
                    (Strategy::Max, Some(best)) => best.max(edge),
                    (_, Some(best)) => best.min(edge),
                });
            }
            if entry.required {
                required = Some(required.map_or(edge, |least| least.min(edge)));
            }
        }
        match (strategy, required) {
            (None, _) => Limit::NoReceiverWindow,
            (Some(edge), None) => Limit::Edge(edge),
            (Some(edge), Some(least)) => Limit::Edge(edge.min(least)),
        }
    }

    /// The admission gate at `now`.
    #[must_use]
    pub fn admission(&self, now: u64) -> Admission {
        if self.lost(now) {
            Admission::LostRequired
        } else if self.required_joined.iter().all(|joined| *joined)
            && self.required_sources_joined.iter().all(|joined| *joined)
        {
            Admission::Open
        } else {
            Admission::NotJoined
        }
    }

    /// Whether a member of any role is live at `now`.
    #[must_use]
    pub fn connected(&self, now: u64) -> bool {
        self.entries
            .iter()
            .any(|e| e.state == State::Active && self.live(e, now))
    }

    /// The least consumption of `lane` over the required members, live,
    /// expired or lost: the retention bound they impose, or `None` when no
    /// required member has joined.
    #[must_use]
    pub fn retention(&self, lane: Lane) -> Option<u64> {
        let at = usize::from(lane.get());
        self.entries
            .iter()
            .filter(|e| e.required && matches!(e.state, State::Active | State::LostRequired))
            .filter_map(|e| e.consumption.get(at).copied())
            .min()
    }

    /// Runs at most `limit` timer actions at `now`: reports required
    /// receivers not joined within `join_timeout`, then scans entries from
    /// a persistent cursor, removing expired pending entries and optional
    /// members and marking expired required members lost. Each report and
    /// each entry visited is one action. Returns the actions taken.
    pub fn timers(&mut self, now: u64, limit: u32) -> u32 {
        let mut actions: u32 = 0;
        if age_ns(now, self.created) >= self.config.join_timeout {
            for at in 0..self.required.len() {
                if actions >= limit {
                    return actions;
                }
                let joined = self.required_joined.get(at).copied().unwrap_or(true);
                let reported = self.required_reported.get(at).copied().unwrap_or(true);
                if joined || reported {
                    continue;
                }
                if let Some(flag) = self.required_reported.get_mut(at) {
                    *flag = true;
                }
                let receiver_id = self.required.get(at).copied().unwrap_or(0);
                self.counters.bump(|c| &mut c.not_joined);
                self.event(MemberEvent::NotJoined { receiver_id });
                let Some(next) = actions.checked_add(1) else {
                    return actions;
                };
                actions = next;
            }
        }
        if age_ns(now, self.created) >= self.config.join_timeout {
            for at in 0..self.required_sources.len() {
                if actions >= limit {
                    return actions;
                }
                let joined = self
                    .required_sources_joined
                    .get(at)
                    .copied()
                    .unwrap_or(true);
                let reported = self
                    .required_sources_reported
                    .get(at)
                    .copied()
                    .unwrap_or(true);
                if joined || reported {
                    continue;
                }
                if let Some(flag) = self.required_sources_reported.get_mut(at) {
                    *flag = true;
                }
                self.counters.bump(|c| &mut c.not_joined);
                let Some(next) = actions.checked_add(1) else {
                    return actions;
                };
                actions = next;
            }
        }
        let slots = self.entries.len();
        for _ in 0..slots {
            let Some(next) = actions.checked_add(1).filter(|next| *next <= limit) else {
                break;
            };
            actions = next;
            let slot = self.cursor;
            self.cursor = slot.checked_add(1).filter(|n| *n < slots).unwrap_or(0);
            let Some(entry) = self.entry(slot).copied() else {
                continue;
            };
            match entry.state {
                State::Pending if age_ns(now, entry.since) >= self.config.join_timeout => {
                    self.free(slot);
                    self.counters.bump(|c| &mut c.join_expired);
                }
                State::Active if !self.live(&entry, now) => self.expire(slot, now),
                State::Tombstone
                    if age_ns(now, entry.last_accepted) >= self.config.receiver_timeout =>
                {
                    self.free(slot);
                    self.counters.bump(|c| &mut c.tombstones_cleared);
                }
                _ => {}
            }
        }
        actions
    }

    /// Hands each queued event to `report`, oldest first, and empties the
    /// queue.
    pub fn drain_events(&mut self, mut report: impl FnMut(MemberEvent)) {
        for event in self.events.drain(..) {
            report(event);
        }
    }

    /// Whether `entry` is live at `now` (ACS 15610).
    fn live(&self, entry: &Entry, now: u64) -> bool {
        age_ns(now, entry.last_accepted) < self.config.receiver_timeout
            && age_ns(now, entry.last_fresh) < self.config.pause_timeout
    }

    /// Whether a required loss is unresolved at `now`, swept or not.
    fn lost(&self, now: u64) -> bool {
        self.entries.iter().any(|e| {
            e.state == State::LostRequired
                || (e.required && e.state == State::Active && !self.live(e, now))
        })
    }

    /// Expires the active entry at `slot` at `now`: a required member is
    /// lost; an optional one leaves a tombstone.
    fn expire(&mut self, slot: usize, now: u64) {
        let Some(entry) = self.entry(slot).copied() else {
            return;
        };
        let member = self.member_ref(slot);
        if entry.required {
            if let Some(e) = self.entries.get_mut(slot) {
                e.state = State::LostRequired;
            }
            self.counters.bump(|c| &mut c.lost_required);
            self.event(MemberEvent::LostRequired {
                member,
                receiver: entry.receiver,
                consumption: entry.consumption,
            });
        } else {
            if let Some(e) = self.entries.get_mut(slot) {
                e.state = State::Tombstone;
                e.bindings = [None; BINDINGS];
                e.last_accepted = now;
            }
            self.counters.bump(|c| &mut c.expired);
            self.event(MemberEvent::Expired {
                member,
                receiver: entry.receiver,
                consumption: entry.consumption,
            });
        }
    }

    /// Whether the tombstone at `slot` lets `sm` rejoin at `now` (ACS
    /// 15647): `Some(slot)` to clear it once the SM is accepted, `None` when
    /// it was silent for `receiver_timeout` and is cleared already.
    ///
    /// # Errors
    ///
    /// [`StatusRejected::Expired`] for an SM that is not fresh against it;
    /// the tombstone notes that it was seen.
    fn tombstone_admits(
        &mut self,
        slot: usize,
        sm: &StatusMessage,
        now: u64,
    ) -> Result<Option<usize>, StatusRejected> {
        let Some(entry) = self.entry(slot).copied() else {
            return Ok(None);
        };
        if age_ns(now, entry.last_accepted) >= self.config.receiver_timeout {
            self.free(slot);
            self.counters.bump(|c| &mut c.tombstones_cleared);
            return Ok(None);
        }
        let mut lower = false;
        let mut advanced = false;
        let mut caught_up = true;
        for ((status, last), sent) in sm
            .lanes
            .as_slice()
            .iter()
            .zip(entry.consumption)
            .zip(self.sent_high)
        {
            lower |= status.consumption < last;
            advanced |= status.consumption > last;
            caught_up &= status.consumption == sent;
        }
        if caught_up || (advanced && !lower) {
            return Ok(Some(slot));
        }
        if let Some(e) = self.entries.get_mut(slot) {
            e.last_accepted = now;
        }
        Err(StatusRejected::Expired)
    }

    /// Takes a slot for a newcomer, raising its generation: `own` (the
    /// newcomer's own tombstone) if given, else a free one, else, when
    /// `tombstones` allows, the tombstone seen longest ago. A tombstone
    /// taken is cleared and counted. Optional newcomers leave room for
    /// every required receiver not yet in the table. Exhausted slots are
    /// retired and skipped.
    fn allocate(
        &mut self,
        required: bool,
        tombstones: bool,
        mut own: Option<usize>,
    ) -> Result<usize, StatusRejected> {
        let reserved = if required {
            0
        } else {
            self.required
                .iter()
                .filter(|id| {
                    !self
                        .entries
                        .iter()
                        .any(|e| e.state != State::Free && e.receiver.receiver_id == **id)
                })
                .count()
        };
        let usable = |slot: usize, e: &Entry, own: Option<usize>| {
            !e.retired
                && (e.state == State::Free
                    || (e.state == State::Tombstone && (tombstones || own == Some(slot))))
        };
        let mut free = self
            .entries
            .iter()
            .enumerate()
            .filter(|(slot, e)| usable(*slot, e, own))
            .count();
        while free > reserved {
            let slot = own
                .filter(|slot| self.entry(*slot).is_some_and(|e| usable(*slot, e, own)))
                .or_else(|| {
                    self.entries
                        .iter()
                        .position(|e| e.state == State::Free && !e.retired)
                })
                .or_else(|| {
                    self.entries
                        .iter()
                        .enumerate()
                        .filter(|(slot, e)| e.state == State::Tombstone && usable(*slot, e, own))
                        .min_by_key(|(_, e)| e.last_accepted)
                        .map(|(slot, _)| slot)
                });
            let Some(slot) = slot else {
                break;
            };
            if own != Some(slot)
                && self
                    .entry(slot)
                    .is_some_and(|e| e.state == State::Tombstone)
            {
                self.counters.bump(|c| &mut c.tombstones_cleared);
            }
            let Some(entry) = self.entries.get_mut(slot) else {
                break;
            };
            if let Some(next) = entry.generation.checked_add(1) {
                *entry = Entry {
                    generation: next,
                    ..Entry::FREE
                };
                entry.state = State::Pending;
                return Ok(slot);
            }
            *entry = Entry {
                retired: true,
                ..*entry
            };
            entry.state = State::Free;
            if own == Some(slot) {
                own = None;
            }
            self.counters.bump(|c| &mut c.retired_slots);
            let Some(left) = free.checked_sub(1) else {
                break;
            };
            free = left;
        }
        Err(StatusRejected::TableFull)
    }

    /// Adds `key`'s binding to the entry at `slot`, unless it holds it or
    /// already holds `max_paths`: then it is refused, counted and not
    /// recorded, so the member can be removed while still reachable on it
    /// until that path's next accepted SM.
    fn bind(&mut self, slot: usize, key: &SmKey) {
        let binding = (key.endpoint, key.source);
        let limit = usize::from(self.config.max_paths);
        let Some(entry) = self.entries.get_mut(slot) else {
            return;
        };
        if entry.bindings.contains(&Some(binding)) {
            return;
        }
        let free = entry.bindings.iter_mut().take(limit).find(|b| b.is_none());
        match free {
            Some(held) => *held = Some(binding),
            None => self.counters.bump(|c| &mut c.paths_full),
        }
    }

    fn free(&mut self, slot: usize) {
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.state = State::Free;
        }
    }

    fn entry(&self, slot: usize) -> Option<&Entry> {
        self.entries.get(slot)
    }

    fn member_ref(&self, slot: usize) -> MemberRef {
        MemberRef {
            slot: u16::try_from(slot).unwrap_or(u16::MAX),
            generation: self.entry(slot).map_or(0, |e| e.generation),
        }
    }

    /// The entry holding exactly `receiver`, in any state but free.
    fn find(&self, receiver: Receiver) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.state != State::Free && e.receiver == receiver)
    }

    /// An entry of `receiver`'s id with another boot id.
    fn other_boot(&self, receiver: Receiver) -> Option<usize> {
        self.entries.iter().position(|e| {
            e.state != State::Free
                && e.receiver.receiver_id == receiver.receiver_id
                && e.receiver.receiver_boot_id != receiver.receiver_boot_id
        })
    }

    fn is_required(&self, receiver_id: u64) -> bool {
        self.required.contains(&receiver_id)
    }

    fn is_required_source(&self, source: SocketAddr) -> bool {
        self.required_sources.contains(&source)
    }

    fn tag_of(&self, receiver_id: u64) -> u64 {
        self.tags
            .iter()
            .find(|(id, _)| *id == receiver_id)
            .map_or(0, |(_, tag)| *tag)
    }

    fn event(&mut self, event: MemberEvent) {
        if self.events.len() < usize::from(self.config.max_events) {
            self.events.push(event);
        } else {
            self.counters.events_incomplete = true;
            self.counters.bump(|c| &mut c.events_dropped);
        }
    }

    fn reject(&mut self, reason: StatusRejected) -> StatusRejected {
        self.counters.bump(|c| match reason {
            StatusRejected::Identity => &mut c.identity,
            StatusRejected::Key => &mut c.key,
            StatusRejected::Lanes => &mut c.lanes,
            StatusRejected::Tag => &mut c.tag,
            StatusRejected::Window => &mut c.window,
            StatusRejected::WindowChanged => &mut c.window_changed,
            StatusRejected::Stale => &mut c.stale,
            StatusRejected::Beyond => &mut c.beyond,
            StatusRejected::Overflow => &mut c.overflow,
            StatusRejected::BootChanged => &mut c.boot_changed,
            StatusRejected::Lost => &mut c.lost_rejected,
            StatusRejected::Expired => &mut c.expired_rejected,
            StatusRejected::TableFull => &mut c.table_full,
            StatusRejected::PendingFull => &mut c.pending_full,
        });
        reason
    }
}

/// Whether `ids` has a 0 or names an id twice.
/// Whether `ids` hold a 0 or a repeat, sorted in `scratch`, which holds
/// them all (the caller bounds their count first).
fn zero_or_repeated(ids: impl Iterator<Item = u64>, scratch: &mut [u64]) -> bool {
    let mut count = 0;
    for (slot, id) in scratch.iter_mut().zip(ids) {
        *slot = id;
        count += 1;
    }
    let Some(ids) = scratch.get_mut(..count) else {
        return true;
    };
    ids.sort_unstable();
    ids.first() == Some(&0) || ids.windows(2).any(|pair| matches!(pair, [a, b] if a == b))
}

#[cfg(test)]
mod tests;
