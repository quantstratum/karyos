// SPDX-License-Identifier: Apache-2.0

//! The simulated network of the multi-node host (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C1): a message bus between
//! node ids, one link per direction, each with its own state, fault rates
//! and bounded in-flight queue.
//!
//! Every decision on a sent message is drawn from the fault generator, in
//! this order, and each draw is written to the trace with its value:
//!
//! 1. a link that is down drops the message, with no draw;
//! 2. on a lossy link, the loss draw (`below(1_000_000)`), lost when
//!    under `loss_ppm`;
//! 3. the delay draw (`between(min_delay, max_delay)`);
//! 4. on a lossy link, the reorder draw (`below(1_000_000)`), which
//!    swaps the message's place with the newest one in flight when under
//!    `reorder_ppm`, so it is delivered just before it;
//! 5. on a lossy link, the duplicate draw (`below(1_000_000)`); a copy
//!    then takes its own delay draw.
//!
//! A message that finds its link's queue at `cap` is dropped as an
//! overflow, after its draws. Links are kept in a `BTreeMap` and their
//! queues in a `Vec`, so no hash order reaches a decision.

use std::collections::BTreeMap;
use std::fmt::Debug;

use crate::rng::Rng;

/// A node's id.
pub type NodeId = u32;

/// Draws are in parts per million.
const PPM: u64 = 1_000_000;

/// A link's fault rates, in parts per million, and its delays, in base
/// time units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkFaults {
    /// Messages lost.
    pub loss_ppm: u64,
    /// Messages placed before the newest one in flight.
    pub reorder_ppm: u64,
    /// Messages sent twice.
    pub duplicate_ppm: u64,
}

/// What a link does with what it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Delivers everything, after its delay.
    Up,
    /// Drops everything.
    Down,
    /// Delivers with these faults.
    Lossy(LinkFaults),
}

/// One direction between two nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkConfig {
    /// The state it starts in, and returns to at [`Net::heal`].
    pub state: LinkState,
    /// The shortest delay, in base time units.
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

/// Why a message was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropReason {
    /// Its link was down (a partition or a cut).
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
    /// Messages placed before the newest one in flight.
    pub reordered: u64,
    /// Messages delivered.
    pub delivered: u64,
}

/// A message in flight.
#[derive(Debug, Clone)]
struct InFlight<M> {
    due: u64,
    /// Orders messages due at the same time, in send order; a reordered
    /// message swaps it with the one it overtakes.
    order: u64,
    id: u64,
    message: M,
}

#[derive(Debug, Clone)]
struct Link<M> {
    config: LinkConfig,
    state: LinkState,
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

/// The network: links by `(from, to)`, a fault generator and the trace
/// lines it produces.
#[derive(Debug)]
pub struct Net<M> {
    links: BTreeMap<(NodeId, NodeId), Link<M>>,
    default: LinkConfig,
    rng: Rng,
    next_id: u64,
    next_order: u64,
    counters: NetCounters,
    events: Vec<String>,
}

/// An arithmetic step of the network overflowed its integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetOverflow;

impl<M: Clone + Debug> Net<M> {
    /// A network whose links start as `default`, drawing from `rng`.
    #[must_use]
    pub fn new(default: LinkConfig, rng: Rng) -> Self {
        Self {
            links: BTreeMap::new(),
            default,
            rng,
            next_id: 0,
            next_order: 0,
            counters: NetCounters::default(),
            events: Vec::new(),
        }
    }

    fn link(&mut self, from: NodeId, to: NodeId) -> &mut Link<M> {
        let default = self.default;
        self.links.entry((from, to)).or_insert_with(|| Link {
            config: default,
            state: default.state,
            queue: Vec::new(),
        })
    }

    /// Configures the link from `from` to `to`; its state becomes the
    /// configured one.
    pub fn configure(&mut self, from: NodeId, to: NodeId, config: LinkConfig) {
        let link = self.link(from, to);
        link.config = config;
        link.state = config.state;
    }

    /// Sets the link from `from` to `to` to `state`.
    pub fn set_state(&mut self, from: NodeId, to: NodeId, state: LinkState) {
        self.link(from, to).state = state;
        self.events.push(format!("link {from}->{to} {state:?}"));
    }

    /// Cuts one direction: from `from` to `to` only.
    pub fn cut(&mut self, from: NodeId, to: NodeId) {
        self.set_state(from, to, LinkState::Down);
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

    /// Sends `message` from `from` to `to` at base time `now`; returns its
    /// id.
    ///
    /// # Errors
    ///
    /// [`NetOverflow`] when a time or a counter overflows.
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
        let (state, config) = (link.state, link.config);
        let faults = match state {
            LinkState::Down => {
                self.drop_message(id, DropReason::LinkDown)?;
                return Ok(id);
            }
            LinkState::Up => None,
            LinkState::Lossy(faults) => Some(faults),
        };
        if let Some(faults) = faults {
            let draw = self.rng.below(PPM);
            let lost = draw < faults.loss_ppm;
            self.events.push(format!("#{id} loss draw {draw}: {lost}"));
            if lost {
                self.drop_message(id, DropReason::Loss)?;
                return Ok(id);
            }
        }
        let delay = self.rng.between(config.min_delay, config.max_delay);
        self.events.push(format!("#{id} delay draw {delay}"));
        let due = now.checked_add(delay).ok_or(NetOverflow)?;
        let reorder = match faults {
            Some(faults) => {
                let draw = self.rng.below(PPM);
                let reorder = draw < faults.reorder_ppm;
                self.events
                    .push(format!("#{id} reorder draw {draw}: {reorder}"));
                reorder
            }
            None => false,
        };
        self.enqueue(from, to, id, message.clone(), due, reorder)?;
        if let Some(faults) = faults {
            let draw = self.rng.below(PPM);
            let duplicate = draw < faults.duplicate_ppm;
            self.events
                .push(format!("#{id} duplicate draw {draw}: {duplicate}"));
            if duplicate {
                self.count(|c| &mut c.duplicated)?;
                let delay = self.rng.between(config.min_delay, config.max_delay);
                self.events.push(format!("#{id} copy delay draw {delay}"));
                let due = now.checked_add(delay).ok_or(NetOverflow)?;
                self.enqueue(from, to, id, message, due, false)?;
            }
        }
        Ok(id)
    }

    fn enqueue(
        &mut self,
        from: NodeId,
        to: NodeId,
        id: u64,
        message: M,
        due: u64,
        reorder: bool,
    ) -> Result<(), NetOverflow> {
        let order = self.next_order;
        self.next_order = order.checked_add(1).ok_or(NetOverflow)?;
        let link = self.link(from, to);
        if link.queue.len() >= link.config.cap {
            return self.drop_message(id, DropReason::Overflow);
        }
        // Overtakes the newest message in flight: it takes that message's
        // place and the newest one takes its own, so it is delivered just
        // before it.
        let mut overtaken = None;
        let newest = link
            .queue
            .iter_mut()
            .max_by_key(|flight| (flight.due, flight.order));
        let (due, order, reordered) = match newest {
            Some(newest) if reorder => {
                let place = (newest.due, newest.order);
                newest.due = due.max(newest.due);
                newest.order = order;
                overtaken = Some(format!(
                    "#{id} overtakes #{}, now due at {}",
                    newest.id, newest.due
                ));
                (place.0, place.1, true)
            }
            _ => (due, order, false),
        };
        link.queue.push(InFlight {
            due,
            order,
            id,
            message,
        });
        if reordered {
            self.count(|c| &mut c.reordered)?;
        }
        self.events.extend(overtaken);
        self.events.push(format!("#{id} due at {due}"));
        Ok(())
    }

    /// Takes every message due at base time `now` or earlier, in order of
    /// due time, then send order, then link.
    pub fn due(&mut self, now: u64) -> Vec<Delivery<M>> {
        let mut due = Vec::new();
        for (&(from, to), link) in &mut self.links {
            let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut link.queue)
                .into_iter()
                .partition(|flight| flight.due <= now);
            link.queue = waiting;
            due.extend(
                ready
                    .into_iter()
                    .map(|flight| (flight.due, flight.order, from, to, flight)),
            );
        }
        due.sort_by_key(|(due, order, from, to, _)| (*due, *order, *from, *to));
        due.into_iter()
            .map(|(_, _, from, to, flight)| Delivery {
                from,
                to,
                id: flight.id,
                message: flight.message,
            })
            .collect()
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
