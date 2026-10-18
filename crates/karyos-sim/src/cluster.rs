// SPDX-License-Identifier: Apache-2.0

//! The multi-node host (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C1): several [`Node`]s in
//! one seeded scheduler, each on its own [`NodeClock`], exchanging
//! messages over a [`Net`]. It stands beside the single-driver [`crate::sim`],
//! which it leaves unchanged.
//!
//! **Generators.** The run's seed drives two SplitMix64 streams: the
//! scheduler's, `Rng::new(seed)`, which orders the nodes' ticks, and the
//! network's, `Rng::new(fault_seed(seed))`, which draws every fault (see
//! [`crate::net`] for its order). A fault draw therefore never reshuffles
//! the nodes, and a scripted partition changes only the draws of the
//! messages it drops.
//!
//! **A step**, at each base time unit: the base clock advances by one;
//! every message due is delivered, in the network's order, to a node that
//! is up (one that is down drops it); then every node that is up ticks,
//! in an order drawn from the scheduler's generator. What a node sends is
//! sent at once, at the step's base time.
//!
//! **Crash and restart** are node events: a crashed node is neither
//! ticked nor delivered to, and [`Node::crash`] and [`Node::restart`] let
//! it decide what it keeps. What a crash loses from storage is C2's disk
//! model.
//!
//! **The trace** holds every step's events, every draw with its value,
//! and is digested as the single-driver simulator's is, so a seed
//! reproduces it byte for byte.

use std::fmt::Debug;

use crate::clock::SimClock;
use crate::net::{Delivery, LinkConfig, LinkConfigError, Net, NetOverflow, NodeId};
use crate::rng::Rng;
use crate::sim::Failure;

/// Parts per million of a clock's rate.
const PPM: i128 = 1_000_000;

/// The value the run's seed is mixed with for the network's generator:
/// "fault" in ASCII.
pub const FAULT_SPLIT: u64 = 0x0066_6175_6C74;

/// The network's seed of a run: the first output of SplitMix64 seeded
/// with `seed ^ FAULT_SPLIT`.
#[must_use]
pub fn fault_seed(seed: u64) -> u64 {
    Rng::new(seed ^ FAULT_SPLIT).next_u64()
}

/// A node's view of the shared base clock: `offset + base * (1_000_000 +
/// drift_ppm) / 1_000_000`, in integers. Monotonic, since the rate is
/// positive and the base never goes back.
#[derive(Debug, Clone)]
pub struct NodeClock {
    base: SimClock,
    offset: u64,
    drift_ppm: i64,
}

/// A clock's time does not fit in `u64`, or its rate is not positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockError;

impl NodeClock {
    /// A view of `base` starting at `offset`, running `drift_ppm` parts
    /// per million fast (or slow, when negative).
    ///
    /// # Errors
    ///
    /// [`ClockError`] for a drift of `-1_000_000` ppm or less: the clock
    /// would stop or run backwards.
    pub fn new(base: SimClock, offset: u64, drift_ppm: i64) -> Result<Self, ClockError> {
        if i128::from(drift_ppm) <= -PPM {
            return Err(ClockError);
        }
        Ok(Self {
            base,
            offset,
            drift_ppm,
        })
    }

    /// The node's time now.
    ///
    /// # Errors
    ///
    /// [`ClockError`] when it does not fit in `u64`.
    pub fn now(&self) -> Result<u64, ClockError> {
        let rate = PPM
            .checked_add(i128::from(self.drift_ppm))
            .ok_or(ClockError)?;
        let scaled = i128::from(self.base.get())
            .checked_mul(rate)
            .ok_or(ClockError)?
            .checked_div(PPM)
            .ok_or(ClockError)?;
        let local = scaled
            .checked_add(i128::from(self.offset))
            .ok_or(ClockError)?;
        u64::try_from(local).map_err(|_| ClockError)
    }
}

/// What a node sends: `(to, message)` pairs.
pub type Outbox<M> = Vec<(NodeId, M)>;

/// A simulated node: the cluster code of later batches plugs in here.
pub trait Node<M> {
    /// One scheduler step at the node's time `now`: timers fire here.
    fn tick(&mut self, now: u64, out: &mut Outbox<M>);

    /// `message` from `from` arrives at the node's time `now`.
    fn deliver(&mut self, from: NodeId, message: M, now: u64, out: &mut Outbox<M>);

    /// The node crashes: it is not ticked or delivered to until it
    /// restarts. What it keeps is its own (storage loss is C2's).
    fn crash(&mut self) {}

    /// The node restarts at its time `now`.
    fn restart(&mut self, _now: u64) {}
}

struct Slot<N> {
    node: N,
    clock: NodeClock,
    up: bool,
}

/// A run of several nodes.
pub struct ClusterSim<N, M> {
    name: &'static str,
    seed: u64,
    scheduler: Rng,
    base: SimClock,
    net: Net<M>,
    nodes: Vec<Slot<N>>,
    step: u64,
    trace: Vec<String>,
    digest: u64,
}

/// Steps kept in a failure's trace.
const FAILURE_TRACE: usize = 48;

impl<N: Node<M>, M: Clone + Debug> ClusterSim<N, M> {
    /// A run named `name` of `seed`, whose links start as `link`.
    ///
    /// # Errors
    ///
    /// [`LinkConfigError`] when `link` is invalid
    /// ([`crate::net::validate`]).
    pub fn new(name: &'static str, seed: u64, link: LinkConfig) -> Result<Self, LinkConfigError> {
        Ok(Self {
            name,
            seed,
            scheduler: Rng::new(seed),
            base: SimClock::default(),
            net: Net::new(link, Rng::new(fault_seed(seed)))?,
            nodes: Vec::new(),
            step: 0,
            trace: Vec::new(),
            digest: 0xCBF2_9CE4_8422_2325,
        })
    }

    /// Adds `node` on a clock of `offset` and `drift_ppm`; returns its id,
    /// in order from 0.
    ///
    /// # Errors
    ///
    /// The clock's refusal, and a failure when the ids run out.
    pub fn add_node(&mut self, node: N, offset: u64, drift_ppm: i64) -> Result<NodeId, Failure> {
        let clock = NodeClock::new(self.base.clone(), offset, drift_ppm)
            .map_err(|_| self.failure(format!("clock drift {drift_ppm} ppm")))?;
        let id = NodeId::try_from(self.nodes.len())
            .map_err(|_| self.failure("node ids exhausted".into()))?;
        self.nodes.push(Slot {
            node,
            clock,
            up: true,
        });
        Ok(id)
    }

    /// The node `id`.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&N> {
        self.slot(id).map(|slot| &slot.node)
    }

    fn slot(&self, id: NodeId) -> Option<&Slot<N>> {
        self.nodes.get(usize::try_from(id).ok()?)
    }

    fn slot_mut(&mut self, id: NodeId) -> Option<&mut Slot<N>> {
        self.nodes.get_mut(usize::try_from(id).ok()?)
    }

    /// Node ids, from 0.
    #[must_use]
    pub fn ids(&self) -> Vec<NodeId> {
        (0..self.nodes.len())
            .filter_map(|index| NodeId::try_from(index).ok())
            .collect()
    }

    /// The network, to configure links and partitions.
    pub fn net_mut(&mut self) -> &mut Net<M> {
        &mut self.net
    }

    /// The network.
    #[must_use]
    pub fn net(&self) -> &Net<M> {
        &self.net
    }

    /// The base time now.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.base.get()
    }

    /// The whole trace so far.
    #[must_use]
    pub fn trace(&self) -> &[String] {
        &self.trace
    }

    /// A digest of the whole trace: equal for equal seeds.
    #[must_use]
    pub fn digest(&self) -> u64 {
        self.digest
    }

    /// A failure of this run with `reason` and its last steps.
    #[must_use]
    pub fn failure(&self, reason: String) -> Failure {
        Failure {
            scenario: self.name,
            seed: self.seed,
            step: self.step,
            reason,
            trace: self
                .trace
                .iter()
                .rev()
                .take(FAILURE_TRACE)
                .rev()
                .cloned()
                .collect(),
        }
    }

    fn note(&mut self, event: String) {
        for byte in event.bytes().chain(self.step.to_le_bytes()) {
            self.digest ^= u64::from(byte);
            self.digest = self.digest.wrapping_mul(0x0000_0100_0000_01B3);
        }
        self.trace
            .push(format!("[{} t={}] {event}", self.step, self.base.get()));
    }

    /// Moves the network's events into the trace.
    fn absorb(&mut self) {
        for event in self.net.take_events() {
            self.note(event);
        }
    }

    fn overflow(&self, _: NetOverflow) -> Failure {
        self.failure("network arithmetic overflowed".into())
    }

    fn local(&self, id: NodeId) -> Result<u64, Failure> {
        self.slot(id)
            .ok_or_else(|| self.failure(format!("no node {id}")))?
            .clock
            .now()
            .map_err(|_| self.failure(format!("node {id}'s clock overflowed")))
    }

    /// Sends what `from` put in `out`.
    fn send_all(&mut self, from: NodeId, out: Outbox<M>) -> Result<(), Failure> {
        let now = self.base.get();
        for (to, message) in out {
            self.net
                .send(from, to, message, now)
                .map_err(|error| self.overflow(error))?;
            self.absorb();
        }
        Ok(())
    }

    /// Sends `message` from `from` to `to` now, as a test script does.
    ///
    /// # Errors
    ///
    /// A failure when the network's arithmetic overflows.
    pub fn send(&mut self, from: NodeId, to: NodeId, message: M) -> Result<u64, Failure> {
        let id = self
            .net
            .send(from, to, message, self.base.get())
            .map_err(|error| self.overflow(error))?;
        self.absorb();
        Ok(id)
    }

    /// Crashes `id`: no ticks, and messages due at it are dropped.
    pub fn crash(&mut self, id: NodeId) {
        if let Some(slot) = self.slot_mut(id) {
            slot.up = false;
            slot.node.crash();
        }
        self.note(format!("node {id} crashed"));
    }

    /// Restarts `id`.
    ///
    /// # Errors
    ///
    /// A failure when its clock overflows.
    pub fn restart(&mut self, id: NodeId) -> Result<(), Failure> {
        let now = self.local(id)?;
        if let Some(slot) = self.slot_mut(id) {
            slot.up = true;
            slot.node.restart(now);
        }
        self.note(format!("node {id} restarted at {now}"));
        Ok(())
    }

    /// Runs `steps` steps.
    ///
    /// # Errors
    ///
    /// The first failure.
    pub fn run_for(&mut self, steps: u64) -> Result<(), Failure> {
        for _ in 0..steps {
            self.step()?;
        }
        Ok(())
    }

    /// One step: the base clock advances by one, due messages are
    /// delivered, and the nodes that are up tick.
    ///
    /// # Errors
    ///
    /// A failure when a clock or the network overflows.
    pub fn step(&mut self) -> Result<(), Failure> {
        self.step = self
            .step
            .checked_add(1)
            .ok_or_else(|| self.failure("steps exhausted".into()))?;
        // Link changes made between steps (configure, partitions) first.
        self.absorb();
        self.base.advance(1);
        let now = self.base.get();
        for delivery in self.net.due(now) {
            self.deliver(delivery, now)?;
        }
        // The tick order: a draw per position, from the scheduler only.
        let mut order: Vec<NodeId> = self
            .ids()
            .into_iter()
            .filter(|id| self.slot(*id).is_some_and(|slot| slot.up))
            .collect();
        let mut ticked = Vec::with_capacity(order.len());
        while !order.is_empty() {
            let len = u64::try_from(order.len()).map_err(|_| self.failure("nodes".into()))?;
            let pick = self.scheduler.below(len);
            let index = usize::try_from(pick).map_err(|_| self.failure("pick".into()))?;
            if index < order.len() {
                ticked.push(order.remove(index));
            }
        }
        self.note(format!("tick order {ticked:?}"));
        for id in ticked {
            let local = self.local(id)?;
            let mut out = Vec::new();
            if let Some(slot) = self.slot_mut(id) {
                slot.node.tick(local, &mut out);
            }
            self.send_all(id, out)?;
        }
        Ok(())
    }

    fn deliver(&mut self, delivery: Delivery<M>, now: u64) -> Result<(), Failure> {
        let up = self.slot(delivery.to).is_some_and(|slot| slot.up);
        self.net
            .delivered(&delivery, now, up)
            .map_err(|error| self.overflow(error))?;
        self.absorb();
        if !up {
            return Ok(());
        }
        let local = self.local(delivery.to)?;
        let mut out = Vec::new();
        if let Some(slot) = self.slot_mut(delivery.to) {
            slot.node
                .deliver(delivery.from, delivery.message, local, &mut out);
        }
        self.send_all(delivery.to, out)
    }
}

/// The toy node's messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Echo {
    /// Asks for an echo of its number.
    Ping(u64),
    /// The echo.
    Pong(u64),
}

/// A toy node: its timer fires every `period` units of its own clock and
/// sends a numbered `Ping` to each peer; it answers every `Ping` with a
/// `Pong` and records whatever it receives.
#[derive(Debug, Clone, Default)]
pub struct EchoNode {
    /// Its timer's period, in its own time units; 0 never fires.
    pub period: u64,
    /// Where its timer's pings go.
    pub peers: Vec<NodeId>,
    /// Timer firings so far.
    pub ticks: u64,
    /// What it received: sender, message and its own time.
    pub received: Vec<(NodeId, Echo, u64)>,
    /// Restarts so far.
    pub restarts: u64,
    next: u64,
}

impl EchoNode {
    /// A node whose timer fires every `period` and pings `peers`.
    #[must_use]
    pub fn new(period: u64, peers: Vec<NodeId>) -> Self {
        Self {
            period,
            peers,
            next: period,
            ..Self::default()
        }
    }
}

impl Node<Echo> for EchoNode {
    fn tick(&mut self, now: u64, out: &mut Outbox<Echo>) {
        if self.period == 0 {
            return;
        }
        while self.next <= now {
            let (Some(ticks), Some(next)) = (
                self.ticks.checked_add(1),
                self.next.checked_add(self.period),
            ) else {
                return;
            };
            self.ticks = ticks;
            self.next = next;
            for &peer in &self.peers {
                out.push((peer, Echo::Ping(ticks)));
            }
        }
    }

    fn deliver(&mut self, from: NodeId, message: Echo, now: u64, out: &mut Outbox<Echo>) {
        self.received.push((from, message, now));
        if let Echo::Ping(number) = message {
            out.push((from, Echo::Pong(number)));
        }
    }

    fn restart(&mut self, _now: u64) {
        if let Some(restarts) = self.restarts.checked_add(1) {
            self.restarts = restarts;
        }
    }
}
