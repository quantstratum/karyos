// SPDX-License-Identifier: Apache-2.0

//! The simulated network of the multi-node host (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C1): a message bus between
//! node ids, one link per direction, each with its own state, fault rates,
//! bounded in-flight queue and fault generator.
//!
//! **Generators.** Each link draws from its own SplitMix64 stream, seeded
//! by [`link_seed`] from the run's fault seed and the link's `(from, to)`,
//! so what happens on one link never changes the draws of another: a cut
//! of `0 -> 1` leaves the deliveries of `2 -> 3` as they were.
//!
//! **A send** is decided in this order, each draw written to the trace
//! with its value:
//!
//! 1. a link that is down drops the message, with no draw;
//! 2. on a lossy link, the loss draw (`below(1_000_000)`), lost when
//!    under `loss_ppm`;
//! 3. the delay draw (`between(min_delay, max_delay)`); the message is
//!    due at the later of `now + delay` and the link's last due time, so
//!    a link is FIFO and delay jitter never reorders it;
//! 4. on a lossy link, the reorder draw (`below(1_000_000)`): under
//!    `reorder_ppm`, the message overtakes the newest one in flight, taking
//!    its due time, which stays within `[now + min_delay, now +
//!    max_delay]`, and is delivered just before it. With no message in
//!    flight within those bounds, nothing is overtaken;
//! 5. on a lossy link, the duplicate draw (`below(1_000_000)`); a copy
//!    then takes its own delay draw, after its original.
//!
//! A message that finds its link's queue at `cap` is dropped as an
//! overflow, after its draws.
//!
//! **At delivery**, a message whose link is down when it falls due is
//! dropped as `LinkDown`: a partition also stops what was already in
//! flight.
//!
//! Links are kept in a `BTreeMap` and their queues in a `Vec`, so no hash
//! order reaches a decision.

use std::collections::BTreeMap;
use std::fmt::{self, Debug};

use crate::rng::Rng;

/// A node's id.
pub type NodeId = u32;

/// Draws are in parts per million.
const PPM: u64 = 1_000_000;

/// A link's fault rates, in parts per million.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkFaults {
    /// Messages lost.
    pub loss_ppm: u64,
    /// Messages that overtake the newest one in flight.
    pub reorder_ppm: u64,
    /// Messages sent twice.
    pub duplicate_ppm: u64,
}

/// What a link does with what it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Delivers everything, in order, after its delay.
    Up,
    /// Drops everything, also what is in flight when it falls due.
    Down,
    /// Delivers with these faults.
    Lossy(LinkFaults),
}

/// One direction between two nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkConfig {
    /// The state it starts in, and returns to at [`Net::heal`].
    pub state: LinkState,
    /// The shortest delay, in base time units: at least 1, since what a
    /// node sends in a step is delivered from the next one.
    pub min_delay: u64,
    /// The longest delay.
    pub max_delay: u64,
    /// Messages in flight at once; one more is dropped as an overflow.
    pub cap: usize,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            state: LinkState::Up,
            min_delay: 1,
            max_delay: 1,
            cap: 1024,
        }
    }
}

/// A link configuration the network refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkConfigError {
    /// `min_delay` is 0: a message cannot arrive in the step it is sent.
    ZeroDelay,
    /// `min_delay` is above `max_delay`.
    DelayRange {
        /// The shortest delay asked for.
        min: u64,
        /// The longest delay asked for.
        max: u64,
    },
    /// A fault rate is above 1_000_000 ppm.
    Rate {
        /// The rate asked for.
        ppm: u64,
    },
}

impl fmt::Display for LinkConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDelay => write!(f, "min_delay is 0; it must be at least 1"),
            Self::DelayRange { min, max } => {
                write!(f, "min_delay {min} is above max_delay {max}")
            }
            Self::Rate { ppm } => write!(f, "a rate of {ppm} ppm is above 1000000"),
        }
    }
}

impl std::error::Error for LinkConfigError {}

/// Checks a link state's rates.
fn validate_state(state: LinkState) -> Result<(), LinkConfigError> {
    if let LinkState::Lossy(faults) = state {
        for ppm in [faults.loss_ppm, faults.reorder_ppm, faults.duplicate_ppm] {
            if ppm > PPM {
                return Err(LinkConfigError::Rate { ppm });
            }
        }
    }
    Ok(())
}

/// Checks a link configuration: its delays and its state's rates.
///
/// # Errors
///
/// [`LinkConfigError`] for a delay of 0, a delay range upside down or a
/// rate out of bounds.
pub fn validate(config: LinkConfig) -> Result<(), LinkConfigError> {
    if config.min_delay == 0 {
        return Err(LinkConfigError::ZeroDelay);
    }
    if config.min_delay > config.max_delay {
        return Err(LinkConfigError::DelayRange {
            min: config.min_delay,
            max: config.max_delay,
        });
    }
    validate_state(config.state)
}

/// The seed of the link `from -> to`'s fault generator: the first output
/// of SplitMix64 seeded with `fault_seed ^ (from << 32 | to)`.
#[must_use]
pub fn link_seed(fault_seed: u64, from: NodeId, to: NodeId) -> u64 {
    let link = (u64::from(from) << 32) | u64::from(to);
    Rng::new(fault_seed ^ link).next_u64()
}

/// Why a message was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropReason {
    /// Its link was down (a partition or a cut), at its send or when it
    /// fell due.
    LinkDown,
    /// The loss draw lost it.
    Loss,
    /// Its link's queue was full.
    Overflow,
    /// It was due at a node that is down.
    NodeDown,
}

/// What the network counted, over every link.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetCounters {
    /// Messages sent.
    pub sent: u64,
    /// Dropped because the link was down.
    pub dropped_link_down: u64,
    /// Dropped by the loss draw.
    pub dropped_loss: u64,
    /// Dropped because the queue was full.
    pub dropped_overflow: u64,
    /// Dropped because the destination node was down.
    pub dropped_node_down: u64,
    /// Copies made by the duplicate draw.
    pub duplicated: u64,
    /// Messages that overtook the newest one in flight.
    pub reordered: u64,
    /// Messages delivered.
    pub delivered: u64,
}

/// A message in flight.
#[derive(Debug, Clone)]
struct InFlight<M> {
    due: u64,
    /// Orders messages due at the same time, in send order; one that
    /// overtakes another takes its order, and the other a new one.
    order: u64,
    id: u64,
    message: M,
}

#[derive(Debug, Clone)]
struct Link<M> {
    config: LinkConfig,
    state: LinkState,
    rng: Rng,
    /// The latest due time given on this link: what follows is not due
    /// before it.
    last_due: u64,
    queue: Vec<InFlight<M>>,
}

/// A message the network delivers now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery<M> {
    /// The sender.
    pub from: NodeId,
    /// The destination.
    pub to: NodeId,
    /// The message's id, in send order (a copy keeps its original's).
    pub id: u64,
    /// The message.
    pub message: M,
}

/// The network: links by `(from, to)` and the trace lines it produces.
#[derive(Debug)]
pub struct Net<M> {
    links: BTreeMap<(NodeId, NodeId), Link<M>>,
    default: LinkConfig,
    fault_seed: u64,
    next_id: u64,
    next_order: u64,
    counters: NetCounters,
    events: Vec<String>,
}

/// An arithmetic step of the network overflowed its integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetOverflow;

impl fmt::Display for NetOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a time, an id or a counter of the network overflowed")
    }
}

impl std::error::Error for NetOverflow {}

impl<M: Clone + Debug> Net<M> {
    /// A network whose links start as `default`, each drawing from its
    /// own stream of `fault_seed` ([`link_seed`]).
    ///
    /// # Errors
    ///
    /// [`LinkConfigError`] when `default` is invalid ([`validate`]).
    pub fn new(default: LinkConfig, fault_seed: u64) -> Result<Self, LinkConfigError> {
        validate(default)?;
        Ok(Self {
            links: BTreeMap::new(),
            default,
            fault_seed,
            next_id: 0,
            next_order: 0,
            counters: NetCounters::default(),
            events: vec![format!("links default {default:?}")],
        })
    }

    fn link(&mut self, from: NodeId, to: NodeId) -> &mut Link<M> {
        let (default, seed) = (self.default, link_seed(self.fault_seed, from, to));
        self.links.entry((from, to)).or_insert_with(|| Link {
            config: default,
            state: default.state,
            rng: Rng::new(seed),
            last_due: 0,
            queue: Vec::new(),
        })
    }

    /// Configures the link from `from` to `to`; its state becomes the
    /// configured one.
    ///
    /// # Errors
    ///
    /// [`LinkConfigError`] when `config` is invalid ([`validate`]); the
    /// link is unchanged.
    pub fn configure(
        &mut self,
        from: NodeId,
        to: NodeId,
        config: LinkConfig,
    ) -> Result<(), LinkConfigError> {
        validate(config)?;
        let link = self.link(from, to);
        link.config = config;
        link.state = config.state;
        self.events
            .push(format!("link {from}->{to} configured {config:?}"));
        Ok(())
    }

    /// Sets the link from `from` to `to` to `state`.
    ///
    /// # Errors
    ///
    /// [`LinkConfigError::Rate`] for a rate out of bounds; the link is
    /// unchanged.
    pub fn set_state(
        &mut self,
        from: NodeId,
        to: NodeId,
        state: LinkState,
    ) -> Result<(), LinkConfigError> {
        validate_state(state)?;
        self.link(from, to).state = state;
        self.events.push(format!("link {from}->{to} {state:?}"));
        Ok(())
    }

    /// Cuts one direction: from `from` to `to` only.
    pub fn cut(&mut self, from: NodeId, to: NodeId) {
        self.link(from, to).state = LinkState::Down;
        self.events.push(format!("link {from}->{to} Down"));
    }

    /// Cuts every link between `node` and every other node of `nodes`,
    /// both ways.
    pub fn isolate(&mut self, node: NodeId, nodes: &[NodeId]) {
        for &other in nodes.iter().filter(|other| **other != node) {
            self.cut(node, other);
            self.cut(other, node);
        }
    }

    /// Cuts every link between the two sides, both ways.
    pub fn split(&mut self, left: &[NodeId], right: &[NodeId]) {
        for &a in left {
            for &b in right {
                self.cut(a, b);
                self.cut(b, a);
            }
        }
    }

    /// Returns every link to its configured state.
    pub fn heal(&mut self) {
        for link in self.links.values_mut() {
            link.state = link.config.state;
        }
        self.events.push("heal".into());
    }

    /// The counters so far.
    #[must_use]
    pub fn counters(&self) -> NetCounters {
        self.counters
    }

    /// Messages in flight on the link from `from` to `to`.
    #[must_use]
    pub fn in_flight(&self, from: NodeId, to: NodeId) -> usize {
        self.links
            .get(&(from, to))
            .map_or(0, |link| link.queue.len())
    }

    /// Takes the trace lines written since the last call.
    pub fn take_events(&mut self) -> Vec<String> {
        std::mem::take(&mut self.events)
    }

    fn count(&mut self, field: fn(&mut NetCounters) -> &mut u64) -> Result<(), NetOverflow> {
        let value = field(&mut self.counters);
        *value = value.checked_add(1).ok_or(NetOverflow)?;
        Ok(())
    }

    fn drop_message(&mut self, id: u64, reason: DropReason) -> Result<(), NetOverflow> {
        self.events.push(format!("#{id} dropped {reason:?}"));
        self.count(match reason {
            DropReason::LinkDown => |c| &mut c.dropped_link_down,
            DropReason::Loss => |c| &mut c.dropped_loss,
            DropReason::Overflow => |c| &mut c.dropped_overflow,
            DropReason::NodeDown => |c| &mut c.dropped_node_down,
        })
    }

    /// One draw of `below(1_000_000)` on the link, traced: whether it is
    /// under `ppm`.
    fn draw(&mut self, from: NodeId, to: NodeId, id: u64, what: &str, ppm: u64) -> bool {
        let draw = self.link(from, to).rng.below(PPM);
        let hit = draw < ppm;
        self.events.push(format!("#{id} {what} draw {draw}: {hit}"));
        hit
    }

    /// Sends `message` from `from` to `to` at base time `now`; returns its
    /// id.
    ///
    /// # Errors
    ///
    /// [`NetOverflow`] when a time, an id or a counter overflows.
    pub fn send(
        &mut self,
        from: NodeId,
        to: NodeId,
        message: M,
        now: u64,
    ) -> Result<u64, NetOverflow> {
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(NetOverflow)?;
        self.count(|c| &mut c.sent)?;
        self.events
            .push(format!("#{id} sent {from}->{to} at {now}: {message:?}"));
        let link = self.link(from, to);
        let faults = match link.state {
            LinkState::Down => {
                self.drop_message(id, DropReason::LinkDown)?;
                return Ok(id);
            }
            LinkState::Up => None,
            LinkState::Lossy(faults) => Some(faults),
        };
        if let Some(faults) = faults
            && self.draw(from, to, id, "loss", faults.loss_ppm)
        {
            self.drop_message(id, DropReason::Loss)?;
            return Ok(id);
        }
        let due = self.delay(from, to, id, now, "delay")?;
        let overtake = match faults {
            Some(faults) => self.draw(from, to, id, "reorder", faults.reorder_ppm),
            None => false,
        };
        self.enqueue(from, to, id, message.clone(), now, due, overtake)?;
        if let Some(faults) = faults
            && self.draw(from, to, id, "duplicate", faults.duplicate_ppm)
        {
            self.count(|c| &mut c.duplicated)?;
            let due = self.delay(from, to, id, now, "copy delay")?;
            self.enqueue(from, to, id, message, now, due, false)?;
        }
        Ok(id)
    }

    /// The delay draw of a message sent at `now`, and its due time: no
    /// earlier than the link's last due time (FIFO).
    fn delay(
        &mut self,
        from: NodeId,
        to: NodeId,
        id: u64,
        now: u64,
        what: &str,
    ) -> Result<u64, NetOverflow> {
        let link = self.link(from, to);
        let delay = link
            .rng
            .between(link.config.min_delay, link.config.max_delay);
        let due = now
            .checked_add(delay)
            .ok_or(NetOverflow)?
            .max(link.last_due);
        self.events.push(format!("#{id} {what} draw {delay}"));
        Ok(due)
    }

    #[allow(clippy::too_many_arguments, reason = "one message's whole placement")]
    fn enqueue(
        &mut self,
        from: NodeId,
        to: NodeId,
        id: u64,
        message: M,
        now: u64,
        due: u64,
        overtake: bool,
    ) -> Result<(), NetOverflow> {
        let order = self.next_order;
        self.next_order = order.checked_add(1).ok_or(NetOverflow)?;
        let link = self.link(from, to);
        if link.queue.len() >= link.config.cap {
            return self.drop_message(id, DropReason::Overflow);
        }
        let earliest = now.checked_add(link.config.min_delay).ok_or(NetOverflow)?;
        let latest = now.checked_add(link.config.max_delay).ok_or(NetOverflow)?;
        // Overtaking the newest message in flight, if its due time is
        // within this message's bounds: it takes that place, and the
        // newest one is ordered after it.
        let newest = link
            .queue
            .iter_mut()
            .max_by_key(|flight| (flight.due, flight.order))
            .filter(|flight| (earliest..=latest).contains(&flight.due));
        let mut overtaken = None;
        let (due, order) = match newest {
            Some(newest) if overtake => {
                let place = (newest.due, newest.order);
                newest.order = order;
                overtaken = Some(newest.id);
                place
            }
            _ => {
                link.last_due = link.last_due.max(due);
                (due, order)
            }
        };
        link.queue.push(InFlight {
            due,
            order,
            id,
            message,
        });
        match overtaken {
            Some(other) => {
                self.count(|c| &mut c.reordered)?;
                self.events
                    .push(format!("#{id} overtakes #{other}, due at {due}"));
            }
            None if overtake => self
                .events
                .push(format!("#{id} has nothing to overtake, due at {due}")),
            None => self.events.push(format!("#{id} due at {due}")),
        }
        Ok(())
    }

    /// Takes every message due at base time `now` or earlier, in order of
    /// due time, then send order, then link. One whose link is down now is
    /// dropped as `LinkDown`, not returned.
    ///
    /// # Errors
    ///
    /// [`NetOverflow`] when a counter overflows.
    pub fn due(&mut self, now: u64) -> Result<Vec<Delivery<M>>, NetOverflow> {
        let mut due = Vec::new();
        for (&(from, to), link) in &mut self.links {
            let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut link.queue)
                .into_iter()
                .partition(|flight| flight.due <= now);
            link.queue = waiting;
            let down = link.state == LinkState::Down;
            due.extend(ready.into_iter().map(|flight| (flight, from, to, down)));
        }
        due.sort_by_key(|(flight, from, to, _)| (flight.due, flight.order, *from, *to));
        let mut deliveries = Vec::with_capacity(due.len());
        for (flight, from, to, down) in due {
            if down {
                self.drop_message(flight.id, DropReason::LinkDown)?;
            } else {
                deliveries.push(Delivery {
                    from,
                    to,
                    id: flight.id,
                    message: flight.message,
                });
            }
        }
        Ok(deliveries)
    }

    /// Records the delivery of `delivery` at base time `now`, or its drop
    /// at a node that is down.
    ///
    /// # Errors
    ///
    /// [`NetOverflow`] when a counter overflows.
    pub fn delivered(
        &mut self,
        delivery: &Delivery<M>,
        now: u64,
        up: bool,
    ) -> Result<(), NetOverflow> {
        if up {
            self.events.push(format!(
                "#{} delivered {}->{} at {now}",
                delivery.id, delivery.from, delivery.to
            ));
            self.count(|c| &mut c.delivered)
        } else {
            self.drop_message(delivery.id, DropReason::NodeDown)
        }
    }
}
