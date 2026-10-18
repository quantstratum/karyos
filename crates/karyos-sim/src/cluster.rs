// SPDX-License-Identifier: Apache-2.0

//! The multi-node host (quantstratum-docs:
//! karyos/design/cluster-gap-analysis.md §6, C1): several [`Node`]s in
//! one seeded scheduler, each on its own [`NodeClock`], exchanging
//! messages over a [`Net`]. It stands beside the single-driver [`crate::sim`],
//! which it leaves unchanged.
//!
//! **Generators.** The run's seed drives the scheduler's SplitMix64
//! stream, `Rng::new(seed)`, which only orders the nodes' ticks, and the
//! network's fault seed, [`fault_seed`]: each link draws from its own
//! stream of it ([`crate::net::link_seed`], and [`crate::net`] for the
//! draw order). A fault draw never reshuffles the nodes, and a scripted
//! cut changes no other link's draws.
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
//! **The trace** holds the setup (the links' default configuration, each
//! node's clock), every link change, crash and restart in the order made,
//! and every step's events with each draw's value. It is digested as the
//! single-driver simulator's is, so a seed reproduces it byte for byte.

use std::fmt::{self, Debug};

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

/// A node clock refused or overflowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    /// A drift of `-1_000_000` ppm or less: the clock would stop or run
    /// backwards.
    Drift {
        /// The drift asked for.
        drift_ppm: i64,
    },
    /// The node's time does not fit in `u64`.
    Overflow {
        /// The base time.
        base: u64,
        /// The clock's offset.
        offset: u64,
        /// The clock's drift.
        drift_ppm: i64,
    },
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Drift { drift_ppm } => {
                write!(f, "a drift of {drift_ppm} ppm would stop the clock")
            }
            Self::Overflow {
                base,
                offset,
                drift_ppm,
            } => write!(
                f,
                "base time {base} with offset {offset} and drift {drift_ppm} ppm overflows"
            ),
        }
    }
}

impl std::error::Error for ClockError {}

/// A crash or a restart the host refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    /// No node has this id.
    Unknown(NodeId),
    /// The node is up: it cannot restart.
    AlreadyUp(NodeId),
    /// The node is down: it cannot crash again.
    AlreadyDown(NodeId),
    /// The node's clock overflowed.
    Clock(NodeId, ClockError),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(id) => write!(f, "no node {id}"),
            Self::AlreadyUp(id) => write!(f, "node {id} is up"),
            Self::AlreadyDown(id) => write!(f, "node {id} is down"),
            Self::Clock(id, error) => write!(f, "node {id}'s clock: {error}"),
        }
    }
}

impl std::error::Error for NodeError {}

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
            return Err(ClockError::Drift { drift_ppm });
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
        let base = self.base.get();
        let overflow = ClockError::Overflow {
            base,
            offset: self.offset,
            drift_ppm: self.drift_ppm,
        };
        let rate = PPM
            .checked_add(i128::from(self.drift_ppm))
            .ok_or(overflow)?;
        let local = i128::from(base)
            .checked_mul(rate)
            .and_then(|scaled| scaled.checked_div(PPM))
            .and_then(|scaled| scaled.checked_add(i128::from(self.offset)))
            .ok_or(overflow)?;
        u64::try_from(local).map_err(|_| overflow)
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
        let mut sim = Self {
            name,
            seed,
            scheduler: Rng::new(seed),
            base: SimClock::default(),
            net: Net::new(link, fault_seed(seed))?,
            nodes: Vec::new(),
            step: 0,
            trace: Vec::new(),
            digest: 0xCBF2_9CE4_8422_2325,
        };
        // The links' default configuration.
        sim.absorb();
        Ok(sim)
    }

    /// Adds `node` on a clock of `offset` and `drift_ppm`; returns its id,
    /// in order from 0.
    ///
    /// # Errors
    ///
    /// The clock's refusal, and a failure when the ids run out.
    pub fn add_node(&mut self, node: N, offset: u64, drift_ppm: i64) -> Result<NodeId, Failure> {
        let clock = NodeClock::new(self.base.clone(), offset, drift_ppm)
            .map_err(|error| self.failure(format!("a node's clock: {error}")))?;
        let id = NodeId::try_from(self.nodes.len())
            .map_err(|_| self.failure(format!("node ids exhausted at {}", self.nodes.len())))?;
        self.nodes.push(Slot {
            node,
            clock,
            up: true,
        });
        self.absorb();
        self.note(format!(
            "node {id} added: offset {offset}, drift {drift_ppm} ppm"
        ));
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
            // FNV-1a: the multiplication wraps by definition of the hash.
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

    fn overflow(&self, error: NetOverflow) -> Failure {
        self.failure(format!("network at t={}: {error}", self.base.get()))
    }

    fn local(&self, id: NodeId) -> Result<u64, Failure> {
        self.local_time(id)
            .map_err(|error| self.failure(error.to_string()))
    }

    fn local_time(&self, id: NodeId) -> Result<u64, NodeError> {
        self.slot(id)
            .ok_or(NodeError::Unknown(id))?
            .clock
            .now()
            .map_err(|error| NodeError::Clock(id, error))
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
        self.absorb();
        let id = self
            .net
            .send(from, to, message, self.base.get())
            .map_err(|error| self.overflow(error))?;
        self.absorb();
        Ok(id)
    }

    /// Crashes `id`: no ticks, and messages due at it are dropped.
    ///
    /// # Errors
    ///
    /// [`NodeError::Unknown`] and [`NodeError::AlreadyDown`]; nothing
    /// changes.
    pub fn crash(&mut self, id: NodeId) -> Result<(), NodeError> {
        let slot = self.slot_mut(id).ok_or(NodeError::Unknown(id))?;
        if !slot.up {
            return Err(NodeError::AlreadyDown(id));
        }
        slot.up = false;
        slot.node.crash();
        self.absorb();
        self.note(format!("node {id} crashed"));
        Ok(())
    }

    /// Restarts `id`.
    ///
    /// # Errors
    ///
    /// [`NodeError::Unknown`], [`NodeError::AlreadyUp`] and its clock's
    /// overflow; nothing changes.
    pub fn restart(&mut self, id: NodeId) -> Result<(), NodeError> {
        let now = self.local_time(id)?;
        let slot = self.slot_mut(id).ok_or(NodeError::Unknown(id))?;
        if slot.up {
            return Err(NodeError::AlreadyUp(id));
        }
        slot.up = true;
        slot.node.restart(now);
        self.absorb();
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
        let due = self.net.due(now).map_err(|error| self.overflow(error))?;
        self.absorb();
        for delivery in due {
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

/// Timer firings an [`EchoNode`] catches up in one tick; later ones wait
/// for its next ticks.
pub const CATCH_UP: u64 = 16;

impl Node<Echo> for EchoNode {
    fn tick(&mut self, now: u64, out: &mut Outbox<Echo>) {
        if self.period == 0 {
            return;
        }
        for _ in 0..CATCH_UP {
            if self.next > now {
                return;
            }
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
