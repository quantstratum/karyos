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
//!   `receiver_boot_id` within the table's publication identity; a new
//!   boot id is a new membership, never a continuation. Each slot has a
//!   private checked generation, raised at every reuse; queued work names
//!   it ([`MemberRef`]) and is rechecked with [`Membership::current`]. A
//!   slot whose generation is exhausted is retired for the incarnation.
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
//!   retention bound. An expired optional member is removed; it can join
//!   again as a new membership with a new generation and join point.
//!
//! The table, the role lists and the event queue are sized at
//! construction; the data calls do not allocate. Counters never wrap: a
//! count at its end keeps its value and sets the sticky `overflowed` flag
//! (SPEC.md section 14).

use karyos_protocol::frame::Lane;
use karyos_protocol::network::{Identity, Receiver, StatusMessage};
use karyos_sys::host_clock::age_ns;

/// The most lanes a publication has.
pub const MAX_LANES: usize = 4;

/// How the optional contribution to a lane's edge is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// The slowest live member's edge (the default).
    Min,
    /// The fastest live member's edge: optional members may lose data.
    Max,
    /// The slowest live member configured with this tag (not 0).
    Tagged(u64),
}

/// The membership settings (MC-1, MC-5, MC-6; provisional and
/// configurable). Times are in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipConfig {
    /// Table entries, required members included (default 64).
    pub max_receivers: u16,
    /// Entries waiting for their first SM (default 16).
    pub max_pending: u16,
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
            max_receivers: 64,
            max_pending: 16,
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
pub enum MembershipConfigError {
    /// No entry or event slot, or more pending entries than entries.
    #[error("no entry or event slot, or more pending entries than entries")]
    Capacity,
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

/// The configured roles and tags of an incarnation.
#[derive(Debug, Clone, Copy, Default)]
pub struct Roles<'a> {
    /// The required `receiver_id`s.
    pub required: &'a [u64],
    /// `(receiver_id, tag)` pairs; a receiver absent here has tag 0.
    pub tags: &'a [(u64, u64)],
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
        /// Whether it refreshed liveness against `receiver_timeout`.
        fresh: bool,
    },
    /// The SM was rejected whole; it changed and refreshed nothing.
    Rejected(StatusRejected),
}

/// Why an SM (or an expected join) was rejected; each reason is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusRejected {
    /// Another publication incarnation.
    Identity,
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
    /// No slot left for a newcomer: nothing is evicted.
    TableFull,
    /// The pending limit is reached.
    PendingFull,
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
    /// An optional member expired and was removed.
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
    /// SMs of another incarnation.
    pub identity: u64,
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
}

/// One table entry.
#[derive(Debug, Clone, Copy)]
struct Entry {
    state: State,
    generation: u64,
    /// Generation exhausted: never used again.
    retired: bool,
    receiver: Receiver,
    required: bool,
    tag: u64,
    /// When a pending entry was expected.
    since: u64,
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
        required: false,
        tag: 0,
        since: 0,
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
    entries: Vec<Entry>,
    required: Vec<u64>,
    /// Whether each required receiver has joined (parallel to `required`).
    required_joined: Vec<bool>,
    /// Whether each required receiver was reported not joined.
    required_reported: Vec<bool>,
    tags: Vec<(u64, u64)>,
    sent_high: [u64; MAX_LANES],
    created: u64,
    cursor: usize,
    events: Vec<MemberEvent>,
    counters: MembershipCounters,
}

impl Membership {
    /// A table for `identity`, created at `now`.
    ///
    /// # Errors
    ///
    /// See [`MembershipConfigError`].
    pub fn new(
        config: MembershipConfig,
        identity: Identity,
        roles: &Roles<'_>,
        now: u64,
    ) -> Result<Self, MembershipConfigError> {
        config.validate()?;
        let table = usize::from(config.max_receivers);
        let tagged: Vec<u64> = roles.tags.iter().map(|(id, _)| *id).collect();
        if roles.required.len() > table
            || roles.tags.len() > table
            || zero_or_repeated(roles.required)
            || zero_or_repeated(&tagged)
            || roles.tags.iter().any(|(_, tag)| *tag == 0)
        {
            return Err(MembershipConfigError::Roles);
        }
        let mut events = Vec::new();
        events.reserve_exact(usize::from(config.max_events));
        Ok(Self {
            config,
            identity,
            entries: vec![Entry::FREE; table],
            required: roles.required.to_vec(),
            required_joined: vec![false; roles.required.len()],
            required_reported: vec![false; roles.required.len()],
            tags: roles.tags.to_vec(),
            sent_high: [0; MAX_LANES],
            created: now,
            cursor: 0,
            events,
            counters: MembershipCounters::default(),
        })
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

    /// Expects `receiver`'s join, from its session establishment: a pending
    /// entry, removed at `join_timeout` unless an SM joins it first. An
    /// existing entry is returned unchanged; a repeated SETUP extends
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`StatusRejected::BootChanged`], [`StatusRejected::Lost`],
    /// [`StatusRejected::PendingFull`] or [`StatusRejected::TableFull`].
    pub fn expect(&mut self, receiver: Receiver, now: u64) -> Result<MemberRef, StatusRejected> {
        let required = self.is_required(receiver.receiver_id);
        if let Some(slot) = self.find(receiver) {
            if self
                .entry(slot)
                .is_some_and(|e| e.state == State::LostRequired)
            {
                return Err(self.reject(StatusRejected::Lost));
            }
            return Ok(self.member_ref(slot));
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
        let slot = self.allocate(required)?;
        let tag = self.tag_of(receiver.receiver_id);
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.state = State::Pending;
            entry.receiver = receiver;
            entry.required = required;
            entry.tag = tag;
            entry.since = now;
        }
        Ok(self.member_ref(slot))
    }

    /// Takes an SM that the session binding has validated, at `now`
    /// (multicast-flow-control.md, "SM validation and liveness").
    pub fn status(&mut self, sm: &StatusMessage, now: u64) -> StatusOutcome {
        match self.try_status(sm, now) {
            Ok(outcome) => outcome,
            Err(reason) => StatusOutcome::Rejected(self.reject(reason)),
        }
    }

    fn try_status(
        &mut self,
        sm: &StatusMessage,
        now: u64,
    ) -> Result<StatusOutcome, StatusRejected> {
        if sm.identity != self.identity {
            return Err(StatusRejected::Identity);
        }
        if sm.lanes.count() != self.config.lane_count {
            return Err(StatusRejected::Lanes);
        }
        let id = sm.receiver.receiver_id;
        if sm.group_tag != self.tag_of(id) {
            return Err(StatusRejected::Tag);
        }
        let required = self.is_required(id);
        let mut found = self.find(sm.receiver);
        if let Some(slot) = found {
            let expired = self
                .entry(slot)
                .is_some_and(|e| e.state == State::Active && !self.live(e, now));
            if expired {
                self.expire(slot);
            }
            match self.entry(slot).map(|e| e.state) {
                Some(State::LostRequired) => return Err(StatusRejected::Lost),
                Some(State::Active | State::Pending) => {}
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

        let slot = match found {
            Some(slot) => slot,
            None => self.allocate(required)?,
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
        self.entry(usize::from(member.slot))
            .is_some_and(|e| e.state != State::Free && e.generation == member.generation)
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
        } else if self.required_joined.iter().all(|joined| *joined) {
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
                actions += 1;
            }
        }
        let slots = self.entries.len();
        let mut visited = 0;
        while actions < limit && visited < slots {
            let slot = self.cursor;
            self.cursor = if slot + 1 >= slots { 0 } else { slot + 1 };
            visited += 1;
            actions += 1;
            let Some(entry) = self.entry(slot).copied() else {
                continue;
            };
            match entry.state {
                State::Pending if age_ns(now, entry.since) >= self.config.join_timeout => {
                    self.free(slot);
                    self.counters.bump(|c| &mut c.join_expired);
                }
                State::Active if !self.live(&entry, now) => self.expire(slot),
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

    /// Expires the active entry at `slot`: a required member is lost, an
    /// optional one removed.
    fn expire(&mut self, slot: usize) {
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
            self.free(slot);
            self.counters.bump(|c| &mut c.expired);
            self.event(MemberEvent::Expired {
                member,
                receiver: entry.receiver,
                consumption: entry.consumption,
            });
        }
    }

    /// Takes a free slot for a newcomer, raising its generation; optional
    /// newcomers leave room for every required receiver not yet in the
    /// table. Exhausted slots are retired and skipped.
    fn allocate(&mut self, required: bool) -> Result<usize, StatusRejected> {
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
        let mut free = self
            .entries
            .iter()
            .filter(|e| e.state == State::Free && !e.retired)
            .count();
        while free > reserved {
            let Some(slot) = self
                .entries
                .iter()
                .position(|e| e.state == State::Free && !e.retired)
            else {
                break;
            };
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
            entry.retired = true;
            self.counters.bump(|c| &mut c.retired_slots);
            free -= 1;
        }
        Err(StatusRejected::TableFull)
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
            StatusRejected::Lanes => &mut c.lanes,
            StatusRejected::Tag => &mut c.tag,
            StatusRejected::Window => &mut c.window,
            StatusRejected::WindowChanged => &mut c.window_changed,
            StatusRejected::Stale => &mut c.stale,
            StatusRejected::Beyond => &mut c.beyond,
            StatusRejected::Overflow => &mut c.overflow,
            StatusRejected::BootChanged => &mut c.boot_changed,
            StatusRejected::Lost => &mut c.lost_rejected,
            StatusRejected::TableFull => &mut c.table_full,
            StatusRejected::PendingFull => &mut c.pending_full,
        });
        reason
    }
}

/// Whether `ids` has a 0 or names an id twice.
fn zero_or_repeated(ids: &[u64]) -> bool {
    ids.iter()
        .enumerate()
        .any(|(at, id)| *id == 0 || ids.iter().skip(at + 1).any(|other| other == id))
}

#[cfg(test)]
mod tests;
