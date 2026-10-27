// SPDX-License-Identifier: Apache-2.0

//! The scheduler: one thread, one API call per step, an order drawn from a
//! seeded generator, virtual time (`quantstratum-docs: karyos/design/simulator-and-bench.md`).

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use karyos_client::{ClientConductor, ClientSubscription, MessageLimit, Outcome, PollSummary};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, LossPolicy, Reconfiguration, StreamConfig,
    StreamHandle,
};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::conflation::ConflationConfig;
use karyos_sys::counters::CellRead;
use karyos_sys::error::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use crate::clock::SimClock;
use crate::oracle::{ConflatedView, ReaderView, StreamRecord, key_of};
use crate::payload::{Stamp, encode};
use crate::publisher::{Attempt, Claimed, SimPublisher};
use crate::rng::Rng;

/// Virtual time units a claim may stay uncommitted.
pub const CLAIM_DEADLINE: u64 = 60;
/// Virtual time units a handle has to move at a cutover.
pub const CUTOVER_DEADLINE: u64 = 120;
/// The driver's heartbeat interval, in virtual time units.
pub const HEARTBEAT_INTERVAL: u64 = 10;
/// Virtual time units after which the driver times out a client whose
/// heartbeat stopped.
pub const CLIENT_TIMEOUT: u64 = 200;
/// Commands a client's subscription may take to be served at setup.
const SETUP_LIMIT: u32 = 1000;
/// Steps kept in a failure's trace.
const TRACE: usize = 48;
/// Quiet rounds that end the drain phase.
const QUIET: u32 = 40;
/// Rounds after which the drain phase gives up.
const DRAIN_LIMIT: u32 = 20_000;

/// Which faults a scenario injects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Faults {
    /// Actors pause for a while.
    pub pause: bool,
    /// Publishers pause while holding a claim, letting others run.
    pub pause_in_claim: bool,
    /// Claims are forgotten (`mem::forget`).
    pub forget: bool,
    /// Handles are dropped at an arbitrary step.
    pub crash: bool,
    /// A stream is removed.
    pub removal: bool,
    /// A stream is reconfigured (cutover).
    pub cutover: bool,
    /// A client stops: its heartbeat and its reads stop together, for
    /// long enough that the driver may time it out, sometimes while its
    /// reader holds a loan.
    pub stall: bool,
    /// The driver runs no duty cycle for a while: its `conductor duty at`
    /// must stand still meanwhile and move on after
    /// (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`,
    /// M1).
    pub driver_pause: bool,
}

/// One stream of a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPlan {
    /// Its publication mode.
    pub publication: PublicationMode,
    /// Concurrent publisher handles (1 for an exclusive stream).
    pub publishers: u8,
    /// Required readers.
    pub required: u8,
    /// Optional readers.
    pub optional: u8,
    /// Required readers, each the only subscription of a client that
    /// connects through a conductor and beats: the readers a stall
    /// fault can make the driver lose.
    pub clients: u8,
    /// Keys of a conflated stream (SPEC.md §7.1), 0 for a plain one. A
    /// conflated stream has its driver's feeder and one conflated view
    /// actor; its publishers key each message from its stamp.
    pub keys: u32,
}

/// A scenario: streams, faults and a step budget.
#[derive(Debug, Clone)]
pub struct Scenario {
    /// Its name, printed with failures.
    pub name: &'static str,
    /// The streams.
    pub streams: Vec<StreamPlan>,
    /// The faults.
    pub faults: Faults,
    /// What every stream does when it loses a required reader.
    pub on_required_loss: LossPolicy,
    /// Steps before the drain phase.
    pub steps: u64,
}

/// A failed run: enough to reproduce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The scenario.
    pub scenario: &'static str,
    /// The seed.
    pub seed: u64,
    /// The step of the failure.
    pub step: u64,
    /// What went wrong.
    pub reason: String,
    /// The last steps.
    pub trace: Vec<String>,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "scenario {} seed {} failed at step {}: {}",
            self.scenario, self.seed, self.step, self.reason
        )?;
        writeln!(f, "replay with KARYOS_SIM_SEED={}", self.seed)?;
        for line in &self.trace {
            writeln!(f, "  {line}")?;
        }
        Ok(())
    }
}

/// A completed run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Steps run, drain included.
    pub steps: u64,
    /// Messages accepted over all streams.
    pub accepted: usize,
    /// Messages delivered over all readers.
    pub delivered: usize,
    /// Client readers the driver revoked.
    pub revoked: usize,
    /// Client readers revoked while they held a loan.
    pub revoked_holding: usize,
    /// A digest of the whole trace: equal for equal seeds.
    pub digest: u64,
}

struct Stream {
    handle: StreamHandle,
    record: StreamRecord,
    removed: bool,
    /// Alternates the term length at each cutover.
    larger: bool,
}

enum Kind {
    Exclusive(karyos_client::ClientPublication),
    Concurrent(karyos_client::ClientConcurrentPublication),
    Reader {
        subscription: ClientSubscription,
        view: ReaderView,
    },
    /// A conflated view of a keyed stream.
    Conflated {
        view: karyos_client::ConflatedSubscription,
        oracle: ConflatedView,
    },
    /// A required reader whose client beats while it is not paused.
    Client {
        conductor: Box<ClientConductor>,
        subscription: ClientSubscription,
        view: ReaderView,
        /// Virtual time of its last heartbeat.
        last_beat: u64,
        /// The longest gap between two heartbeats since its last poll that
        /// found it not revoked: the driver revoked it after that poll, so
        /// only a silence since then can explain a revocation.
        silence_since_poll: u64,
    },
}

/// Who a client reader is, for its checks.
struct Client {
    id: u32,
    stream: usize,
    /// The longest gap between its heartbeats since its last poll that
    /// found it not revoked, the current one included.
    silence: u64,
}

struct Actor {
    id: u32,
    stream: usize,
    kind: Kind,
    sequence: u32,
    paused_until: u64,
    closed: bool,
}

/// A run in progress.
struct Sim<'s> {
    scenario: &'s Scenario,
    seed: u64,
    rng: Rng,
    clock: SimClock,
    driver: EmbeddedDriver,
    streams: Vec<Stream>,
    actors: Vec<Option<Actor>>,
    step: u64,
    trace: VecDeque<String>,
    digest: u64,
    /// Publishers stop publishing in the drain phase.
    draining: bool,
    /// Reader observations so far: the drain phase ends when it stops
    /// growing.
    observed: u64,
    /// Client readers revoked while they held a loan.
    revoked_holding: usize,
    /// The driver runs no duty cycle before this step.
    driver_paused_until: u64,
    /// The cell of `conductor duty at`.
    duty_cell: usize,
    /// Its value at the last duty cycle.
    duty_at: u64,
}

/// The simulated driver's configuration. Its streams start at term id 7:
/// a replay of a seed must not depend on a random first term id.
fn driver_config() -> DriverConfig {
    DriverConfig {
        cutover_deadline: CUTOVER_DEADLINE,
        max_retained_generations: 2,
        heartbeat_interval: HEARTBEAT_INTERVAL,
        client_liveness_timeout: CLIENT_TIMEOUT,
        initial_term_id: Some(7),
        ..DriverConfig::default()
    }
}

/// Runs `scenario` with `seed`.
///
/// # Errors
///
/// Returns the failure, with the seed and the last steps.
pub fn run(scenario: &Scenario, seed: u64) -> Result<Report, Failure> {
    let mut sim = Sim::new(scenario, seed)?;
    for _ in 0..scenario.steps {
        sim.step(0)?;
        let by = sim.rng.below(4);
        sim.clock.advance(by);
    }
    sim.drain()?;
    sim.finish()
}

fn mode_publishers(plan: &StreamPlan) -> u8 {
    match plan.publication {
        PublicationMode::Exclusive => 1,
        PublicationMode::Concurrent { .. } => plan.publishers.max(1),
        // An image has no local publisher: its receive owner writes it.
        PublicationMode::Image { .. } => 0,
    }
}

/// Connects a client through a conductor and takes a required
/// subscription to stream `stream_id`, running the driver until it is
/// served. The client beats on every conductor poll, and its own timeout
/// for the driver is out of reach: only the driver's liveness decides.
fn connect_reader(
    driver: &mut EmbeddedDriver,
    stream_id: i32,
) -> Result<(ClientConductor, ClientSubscription), String> {
    let mut conductor = driver
        .connect()
        .map_err(|error| format!("connect: {error}"))?;
    conductor.set_liveness(Duration::ZERO, Duration::from_secs(3600));
    let sequence = conductor
        .add_subscription(
            StreamKey {
                stream_id,
                session_id: 1,
            },
            SubscriberRole::Required,
        )
        .map_err(|error| format!("client subscribe: {error}"))?;
    for _ in 0..SETUP_LIMIT {
        driver
            .do_work()
            .map_err(|error| format!("do_work: {error}"))?;
        let mut served = None;
        let _ = conductor.poll(usize::MAX, |completion| {
            if completion.sequence == sequence {
                served = Some(completion.outcome);
            }
        });
        match served {
            Some(Outcome::Subscription(subscription)) => return Ok((conductor, subscription)),
            Some(other) => return Err(format!("client subscribe: {other:?}")),
            None => {}
        }
    }
    Err("client subscribe: not served".into())
}

impl<'s> Sim<'s> {
    fn new(scenario: &'s Scenario, seed: u64) -> Result<Self, Failure> {
        let clock = SimClock::default();
        let config = driver_config();
        let fail = |reason: String| Failure {
            scenario: scenario.name,
            seed,
            step: 0,
            reason,
            trace: Vec::new(),
        };
        let mut driver = EmbeddedDriver::with_clock(config, Box::new(clock.clone()))
            .map_err(|error| fail(format!("driver: {error}")))?;
        let mut streams = Vec::new();
        let mut actors = Vec::new();
        let mut next_id = 0u32;
        for (index, plan) in scenario.streams.iter().enumerate() {
            let stream_id = i32::try_from(index + 1).unwrap_or(i32::MAX);
            let handle = driver
                .add_stream(StreamConfig {
                    buffer: LogBufferConfig {
                        term_length: TermLength::try_new(MIN_TERM_LENGTH)
                            .map_err(|error| fail(format!("term: {error}")))?,
                        spare_slots: 6,
                        // The feeder of a conflated stream is one more
                        // required participant.
                        max_subscribers: plan.required
                            + plan.optional
                            + plan.clients
                            + u8::from(plan.keys > 0)
                            + 1,
                        mtu: DEFAULT_MTU,
                        max_reserved: MIN_TERM_LENGTH / 8,
                        // Replaced by the driver's draw at the add, which
                        // `driver_config` pins to 7: this value decides
                        // nothing, the field only has to be set.
                        initial_term_id: TermId::new(7),
                        lane: Lane::ZERO,
                        session_id: 1,
                        stream_id,
                        claim_deadline: CLAIM_DEADLINE,
                        publication: plan.publication,
                        schedule_capacity: 0,
                    },
                    allow_unconnected: true,
                    on_required_loss: scenario.on_required_loss,
                    conflation: (plan.keys > 0).then_some(ConflationConfig {
                        keys: plan.keys,
                        // Above the largest payload a publisher sends.
                        value_capacity: 512,
                        journal_capacity: 1024,
                        refresh: false,
                    }),
                })
                .map_err(|error| fail(format!("stream: {error}")))?;
            let mut add = |kind: Kind| {
                actors.push(Some(Actor {
                    id: next_id,
                    stream: index,
                    kind,
                    sequence: 0,
                    paused_until: 0,
                    closed: false,
                }));
                next_id += 1;
            };
            for role in core::iter::repeat_n(Role::Required, usize::from(plan.required)).chain(
                core::iter::repeat_n(Role::Optional, usize::from(plan.optional)),
            ) {
                let subscription = driver
                    .subscribe(handle, role)
                    .map_err(|error| fail(format!("subscribe: {error}")))?;
                let view = ReaderView::new(role, subscription.position());
                add(Kind::Reader { subscription, view });
            }
            if plan.keys > 0 {
                let view = driver
                    .subscribe_conflated(handle)
                    .map_err(|error| fail(format!("conflated view: {error}")))?;
                add(Kind::Conflated {
                    view,
                    oracle: ConflatedView::new(plan.keys),
                });
            }
            for _ in 0..plan.clients {
                let (conductor, subscription) =
                    connect_reader(&mut driver, stream_id).map_err(fail)?;
                let view = ReaderView::new(Role::Required, subscription.position());
                add(Kind::Client {
                    conductor: Box::new(conductor),
                    subscription,
                    view,
                    last_beat: 0,
                    silence_since_poll: 0,
                });
            }
            match plan.publication {
                PublicationMode::Exclusive => {
                    let publication = driver
                        .publication(handle)
                        .map_err(|error| fail(format!("publication: {error}")))?;
                    add(Kind::Exclusive(publication));
                }
                PublicationMode::Concurrent { .. } => {
                    for _ in 0..mode_publishers(plan) {
                        let publication = driver
                            .concurrent_publication(handle)
                            .map_err(|error| fail(format!("publication: {error}")))?;
                        add(Kind::Concurrent(publication));
                    }
                }
                // No scenario drives an image's receive owner yet.
                PublicationMode::Image { .. } => {}
            }
            streams.push(Stream {
                handle,
                record: StreamRecord::default(),
                removed: false,
                larger: true,
            });
        }
        let counters = driver.counters();
        let duty_cell = (0..counters.capacity())
            .find(|&index| {
                matches!(
                    counters.read(index),
                    CellRead::Allocated { metadata, .. }
                        if metadata.label() == b"conductor duty at"
                )
            })
            .ok_or_else(|| fail("no conductor duty at cell".into()))?;
        Ok(Self {
            scenario,
            seed,
            rng: Rng::new(seed),
            clock,
            driver,
            streams,
            actors,
            step: 0,
            trace: VecDeque::new(),
            digest: 0xCBF2_9CE4_8422_2325,
            draining: false,
            observed: 0,
            revoked_holding: 0,
            driver_paused_until: 0,
            duty_cell,
            duty_at: 0,
        })
    }

    fn note(&mut self, event: String) {
        for byte in event.bytes().chain(self.step.to_le_bytes()) {
            self.digest ^= u64::from(byte);
            self.digest = self.digest.wrapping_mul(0x0000_0100_0000_01B3);
        }
        if self.trace.len() == TRACE {
            let _ = self.trace.pop_front();
        }
        self.trace
            .push_back(format!("[{} t={}] {event}", self.step, self.clock.get()));
    }

    fn failure(&self, reason: String) -> Failure {
        Failure {
            scenario: self.scenario.name,
            seed: self.seed,
            step: self.step,
            reason,
            trace: self.trace.iter().cloned().collect(),
        }
    }

    fn runnable(&self) -> Vec<usize> {
        self.actors
            .iter()
            .enumerate()
            .filter_map(|(index, actor)| {
                actor
                    .as_ref()
                    .filter(|actor| !actor.closed && actor.paused_until <= self.step)
                    .map(|_| index)
            })
            .collect()
    }

    /// Every client that is not paused beats, as its conductor's duty
    /// would. A client running a poll is out of `actors` and does not.
    fn beat(&mut self) {
        let now = self.clock.get();
        for actor in self.actors.iter_mut().flatten() {
            if actor.closed || actor.paused_until > self.step {
                continue;
            }
            if let Kind::Client {
                conductor,
                last_beat,
                silence_since_poll,
                ..
            } = &mut actor.kind
            {
                let _ = conductor.poll(usize::MAX, |_| {});
                *silence_since_poll = (*silence_since_poll).max(now - *last_beat);
                *last_beat = now;
            }
        }
    }

    /// One step: an actor's call, or a driver duty cycle.
    fn step(&mut self, depth: u8) -> Result<(), Failure> {
        self.step += 1;
        self.beat();
        let runnable = self.runnable();
        let pick = self.rng.below(runnable.len() as u64 + 1) as usize;
        match runnable.get(pick) {
            Some(&index) => self.run_actor(index, depth),
            None => self.driver_step(),
        }
    }

    /// Up to `count` steps of actors other than the one running.
    fn run_others(&mut self, count: u64, depth: u8) -> Result<(), Failure> {
        for _ in 0..count {
            self.step(depth + 1)?;
            let by = self.rng.below(4);
            self.clock.advance(by);
        }
        Ok(())
    }

    /// The driver's `conductor duty at`; its value is host time, so it is
    /// compared, never noted in the digest.
    fn read_duty_at(&self) -> Result<u64, Failure> {
        match self.driver.counters().read(self.duty_cell) {
            CellRead::Allocated { value, .. } => Ok(value),
            other => Err(self.failure(format!("conductor duty at: {other:?}"))),
        }
    }

    fn driver_step(&mut self) -> Result<(), Failure> {
        if self.driver_paused_until > self.step {
            if self.read_duty_at()? != self.duty_at {
                return Err(self.failure("conductor duty at moved while paused".into()));
            }
            self.note("driver paused".into());
            return Ok(());
        }
        self.driver
            .do_work()
            .map_err(|error| self.failure(format!("do_work: {error}")))?;
        let at = self.read_duty_at()?;
        if at == 0 || at < self.duty_at {
            return Err(self.failure(format!("conductor duty at {at} after {}", self.duty_at)));
        }
        self.duty_at = at;
        self.note("driver duty".into());
        if self.draining {
            return Ok(());
        }
        let faults = self.scenario.faults;
        if faults.driver_pause && self.rng.chance(1, 40) {
            let steps = 1 + self.rng.below(100);
            self.driver_paused_until = self.step + steps;
            self.note(format!("driver pauses for {steps}"));
            return Ok(());
        }
        let index = self.rng.below(self.streams.len() as u64) as usize;
        if faults.removal && self.rng.chance(1, 400) {
            if let Some(stream) = self.streams.get_mut(index).filter(|s| !s.removed) {
                stream.removed = true;
                let handle = stream.handle;
                self.driver
                    .remove_stream(handle)
                    .map_err(|error| self.failure(format!("remove: {error}")))?;
                self.note(format!("stream {index} removed"));
            }
        } else if faults.cutover && self.rng.chance(1, 150) {
            // A removed stream may already be freed.
            let Some(stream) = self.streams.get_mut(index).filter(|s| !s.removed) else {
                return Ok(());
            };
            let term = if stream.larger {
                MIN_TERM_LENGTH * 2
            } else {
                MIN_TERM_LENGTH
            };
            stream.larger = !stream.larger;
            let handle = stream.handle;
            let term_length = TermLength::try_new(term)
                .map_err(|error| self.failure(format!("term: {error}")))?;
            match self.driver.reconfigure_stream(
                handle,
                Reconfiguration {
                    term_length,
                    spare_slots: 6,
                },
            ) {
                Ok(generation) => {
                    self.note(format!(
                        "stream {index} cutover to generation {}",
                        generation.get()
                    ));
                }
                // Expected refusals: a cutover in progress, retained
                // generations in use, a removed stream.
                Err(
                    DriverError::CutoverPending { .. }
                    | DriverError::StreamRetiring { .. }
                    | DriverError::Sys(SysError::ResourcesUnavailable),
                ) => {}
                Err(error) => return Err(self.failure(format!("reconfigure: {error}"))),
            }
        }
        Ok(())
    }

    fn run_actor(&mut self, index: usize, depth: u8) -> Result<(), Failure> {
        let Some(mut actor) = self.actors.get_mut(index).and_then(Option::take) else {
            return Ok(());
        };
        let faults = self.scenario.faults;
        if !self.draining && faults.crash && self.rng.chance(1, 400) {
            self.note(format!("actor {} crashes", actor.id));
            // Dropped: its handles go with it.
            return Ok(());
        }
        if !self.draining && faults.pause && self.rng.chance(1, 25) {
            let steps = self.rng.between(5, 120);
            actor.paused_until = self.step + steps;
            self.note(format!("actor {} pauses for {steps}", actor.id));
        } else if !self.draining
            && faults.stall
            && matches!(actor.kind, Kind::Client { .. })
            && self.rng.chance(1, 30)
        {
            let steps = self.rng.between(20, 300);
            actor.paused_until = self.step + steps;
            self.note(format!("client {} stalls for {steps}", actor.id));
        } else {
            let result = match &mut actor.kind {
                Kind::Exclusive(publication) => self.publish(
                    publication,
                    actor.id,
                    actor.stream,
                    &mut actor.sequence,
                    depth,
                ),
                Kind::Concurrent(publication) => self.publish(
                    publication,
                    actor.id,
                    actor.stream,
                    &mut actor.sequence,
                    depth,
                ),
                Kind::Reader { subscription, view } => self
                    .read(subscription, view, actor.id, actor.stream)
                    .map(|()| false),
                Kind::Conflated { view, oracle } => self
                    .read_conflated(view, oracle, actor.id, actor.stream)
                    .map(|()| false),
                Kind::Client {
                    subscription,
                    view,
                    last_beat,
                    silence_since_poll,
                    ..
                } => {
                    let silence = (*silence_since_poll).max(self.clock.get() - *last_beat);
                    let revoked = self.read_client(
                        subscription,
                        view,
                        Client {
                            id: actor.id,
                            stream: actor.stream,
                            silence,
                        },
                        depth,
                    );
                    // Not revoked yet: a later revocation needs a later
                    // silence.
                    if matches!(revoked, Ok(false)) {
                        *silence_since_poll = 0;
                    }
                    revoked
                }
            };
            match result {
                Ok(closed) => actor.closed |= closed,
                Err(failure) => {
                    if let Some(slot) = self.actors.get_mut(index) {
                        *slot = Some(actor);
                    }
                    return Err(failure);
                }
            }
        }
        if let Some(slot) = self.actors.get_mut(index) {
            *slot = Some(actor);
        }
        Ok(())
    }

    /// One publisher call. Returns whether the publication is closed.
    fn publish(
        &mut self,
        publication: &mut dyn SimPublisher,
        id: u32,
        stream: usize,
        sequence: &mut u32,
        depth: u8,
    ) -> Result<bool, Failure> {
        if self.draining {
            return Ok(false);
        }
        let faults = self.scenario.faults;
        let length = self.rng.between(16, 400) as usize;
        let stamp = Stamp {
            publisher: id,
            sequence: *sequence,
        };
        *sequence += 1;
        let keys = self
            .scenario
            .streams
            .get(stream)
            .map_or(0, |plan| plan.keys);
        let key = if keys > 0 {
            i64::from(key_of(stamp, keys))
        } else {
            0
        };
        let attempt = if self.rng.chance(2, 3) {
            let payload = encode(stamp, length);
            let attempt = publication
                .offer(&payload, key)
                .map_err(|error| self.failure(format!("offer: {error}")))?;
            self.note(format!("actor {id} offer {stamp:?}: {attempt:?}"));
            attempt
        } else {
            let claimed = publication
                .claim(length as u32, key)
                .map_err(|error| self.failure(format!("claim: {error}")))?;
            match claimed {
                Claimed::Outcome(attempt) => {
                    self.note(format!("actor {id} claim {stamp:?}: {attempt:?}"));
                    attempt
                }
                Claimed::Claim(mut claim) => {
                    let position = claim.position();
                    claim.payload().copy_from_slice(&encode(stamp, length));
                    self.note(format!("actor {id} claims {stamp:?} at {position}"));
                    if faults.pause_in_claim && depth == 0 && self.rng.chance(1, 3) {
                        let steps = self.rng.between(1, 12);
                        self.note(format!("actor {id} holds its claim for {steps} steps"));
                        self.run_others(steps, depth)?;
                    }
                    let choice = self.rng.below(10);
                    let attempt = match choice {
                        0 => {
                            claim.abort();
                            Attempt::Aborted(position)
                        }
                        1 => {
                            drop(claim);
                            Attempt::Aborted(position)
                        }
                        2 if faults.forget => {
                            core::mem::forget(claim);
                            Attempt::Aborted(position)
                        }
                        _ => claim.commit(),
                    };
                    self.note(format!(
                        "actor {id} resolves {stamp:?} ({choice}): {attempt:?}"
                    ));
                    attempt
                }
            }
        };
        let Some(record) = self.streams.get_mut(stream).map(|s| &mut s.record) else {
            return Ok(false);
        };
        let recorded = match attempt {
            Attempt::Accepted(position) => record.accepted(position, stamp),
            Attempt::Aborted(position) => record.aborted(position),
            Attempt::Retry => Ok(()),
            Attempt::Closed => return Ok(true),
        };
        recorded.map_err(|reason| self.failure(reason))?;
        Ok(false)
    }

    /// One reader poll, every observation checked.
    fn read(
        &mut self,
        subscription: &mut ClientSubscription,
        view: &mut ReaderView,
        id: u32,
        stream: usize,
    ) -> Result<(), Failure> {
        let limit = self.rng.between(1, 8) as u32;
        let Some(record) = self.streams.get(stream).map(|s| &s.record) else {
            return Ok(());
        };
        let mut errors = Vec::new();
        let polled = subscription.poll(
            |bytes, info| {
                if let Err(error) = view.message(record, info.position, bytes) {
                    errors.push(error);
                }
            },
            MessageLimit::new(limit),
        );
        let summary = match polled {
            Ok(summary) => summary,
            Err(error) => return Err(self.failure(format!("reader {id} poll: {error}"))),
        };
        self.observe(view, id, stream, &summary, errors)
    }

    /// Checks one poll's summary, after the checks of its deliveries.
    fn observe(
        &mut self,
        view: &mut ReaderView,
        id: u32,
        stream: usize,
        summary: &PollSummary,
        errors: Vec<String>,
    ) -> Result<(), Failure> {
        let Some(record) = self.streams.get(stream).map(|s| &s.record) else {
            return Ok(());
        };
        let mut checks = errors;
        if let Some(abort) = summary.aborted
            && let Err(error) = view.aborted(record, abort.position)
        {
            checks.push(error);
        }
        if let Some(overrun) = summary.overrun
            && let Err(error) = view.overrun(overrun.from, overrun.lost_to, overrun.resume)
        {
            checks.push(error);
        }
        if let Some(end) = summary.closed
            && let Err(error) = view.closed_at(end)
        {
            checks.push(error);
        }
        if let Some(error) = checks.into_iter().next() {
            return Err(self.failure(format!("reader {id}: {error}")));
        }
        if summary.delivered > 0 || summary.aborted.is_some() || summary.overrun.is_some() {
            self.observed += 1;
            self.note(format!("reader {id} poll: {summary:?}"));
        }
        Ok(())
    }

    /// One poll of a conflated view with a small random budget, every
    /// value checked.
    fn read_conflated(
        &mut self,
        view: &mut karyos_client::ConflatedSubscription,
        oracle: &mut ConflatedView,
        id: u32,
        stream: usize,
    ) -> Result<(), Failure> {
        let budget = karyos_sys::conflation::Budget {
            keys: self.rng.between(1, 4) as u32,
            retries: 2,
        };
        let Some(record) = self.streams.get(stream).map(|s| &s.record) else {
            return Ok(());
        };
        let mut errors = Vec::new();
        let polled = view.poll_changed_with(budget, |key, value| {
            if let Err(error) = oracle.value(record, key, value.version(), value.payload()) {
                errors.push(error);
            }
        });
        let report = match polled {
            Ok(report) => report,
            Err(error) => return Err(self.failure(format!("conflated view {id}: {error}"))),
        };
        if let Some(error) = errors.into_iter().next() {
            return Err(self.failure(format!("conflated view {id}: {error}")));
        }
        if report.delivered > 0 {
            self.observed += 1;
            self.note(format!("conflated view {id} poll: {report:?}"));
        }
        Ok(())
    }

    /// One poll of a client's required reader. Under the stall fault the
    /// client may stop while it holds the loan of a delivered message:
    /// the other actors and the driver run, the driver's clock moves past
    /// the client timeout or not, and the message must be unchanged when
    /// the client resumes. Returns whether the reader is revoked.
    fn read_client(
        &mut self,
        subscription: &mut ClientSubscription,
        view: &mut ReaderView,
        client: Client,
        depth: u8,
    ) -> Result<bool, Failure> {
        let Client {
            id,
            stream,
            silence,
        } = client;
        let limit = self.rng.between(1, 8) as u32;
        let mut stall =
            (self.scenario.faults.stall && !self.draining && depth == 0 && self.rng.chance(1, 20))
                .then(|| self.rng.between(20, 300));
        let mut errors = Vec::new();
        let mut failure = None;
        let mut held = false;
        // The longest silence since the last poll, including one in a loan
        // stall below.
        let mut silent = silence;
        let polled = subscription.poll(
            |bytes, info| {
                let Some(record) = self.streams.get(stream).map(|s| &s.record) else {
                    return;
                };
                if let Err(error) = view.message(record, info.position, bytes) {
                    errors.push(error);
                }
                let Some(steps) = stall.take() else {
                    return;
                };
                held = true;
                let copy = bytes.to_vec();
                let since = self.clock.get();
                self.note(format!(
                    "client {id} stalls for {steps} holding the loan at {}",
                    info.position
                ));
                if let Err(error) = self.run_others(steps, depth) {
                    failure = Some(error);
                    return;
                }
                silent = silent.max(self.clock.get() - since);
                // Whatever the policy did meanwhile, the loaned slot was
                // not reused.
                if bytes != copy.as_slice() {
                    errors.push(format!("{} changed under a held loan", info.position));
                }
            },
            MessageLimit::new(limit),
        );
        if let Some(failure) = failure {
            return Err(failure);
        }
        let summary = match polled {
            Ok(summary) => summary,
            Err(error) => return Err(self.failure(format!("client {id} poll: {error}"))),
        };
        let newly_revoked = summary.revoked.is_some() && view.revoked().is_none();
        if let Some(position) = summary.revoked {
            if let Err(error) = view.revoked_at(position) {
                errors.push(error);
            }
            // The driver times out only a client silent for the timeout.
            if silent < CLIENT_TIMEOUT {
                errors.push(format!(
                    "revoked at {position} after a silence of {silent} < {CLIENT_TIMEOUT}"
                ));
            }
        }
        self.observe(view, id, stream, &summary, errors)?;
        if newly_revoked {
            self.revoked_holding += usize::from(held);
            self.observed += 1;
            self.note(format!("client {id} revoked: {summary:?}"));
        }
        Ok(summary.revoked.is_some())
    }

    /// Every pause ends; only readers and the driver run until nothing
    /// changes for a while.
    fn drain(&mut self) -> Result<(), Failure> {
        self.draining = true;
        self.driver_paused_until = 0;
        for actor in self.actors.iter_mut().flatten() {
            actor.paused_until = 0;
        }
        let mut quiet = 0;
        let mut rounds = 0;
        while quiet < QUIET {
            rounds += 1;
            if rounds > DRAIN_LIMIT {
                return Err(self.failure("the drain phase did not settle".into()));
            }
            let before = self.observed;
            self.beat();
            for index in 0..self.actors.len() {
                let is_reader = matches!(
                    self.actors.get(index),
                    Some(Some(Actor {
                        kind: Kind::Reader { .. } | Kind::Client { .. } | Kind::Conflated { .. },
                        ..
                    }))
                );
                if is_reader {
                    self.step += 1;
                    self.run_actor(index, 0)?;
                }
            }
            self.step += 1;
            self.driver_step()?;
            self.clock.advance(10);
            quiet = if self.observed == before {
                quiet + 1
            } else {
                0
            };
        }
        Ok(())
    }

    fn finish(self) -> Result<Report, Failure> {
        let mut delivered = 0;
        let mut revoked = 0;
        for actor in self.actors.iter().flatten() {
            if let Kind::Conflated { oracle, .. } = &actor.kind {
                delivered += oracle.delivered();
                let Some(stream) = self.streams.get(actor.stream) else {
                    continue;
                };
                oracle.complete(&stream.record).map_err(|reason| {
                    self.failure(format!("conflated view {}: {reason}", actor.id))
                })?;
                continue;
            }
            if let Kind::Reader { view, .. } | Kind::Client { view, .. } = &actor.kind {
                delivered += view.delivered();
                revoked += usize::from(view.revoked().is_some());
                let Some(stream) = self.streams.get(actor.stream) else {
                    continue;
                };
                view.complete(&stream.record)
                    .map_err(|reason| self.failure(format!("reader {}: {reason}", actor.id)))?;
            }
        }
        Ok(Report {
            steps: self.step,
            accepted: self.streams.iter().map(|s| s.record.accepted_count()).sum(),
            delivered,
            revoked,
            revoked_holding: self.revoked_holding,
            digest: self.digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every simulated stream starts at term id 7, whatever the draw: the
    /// driver's override pins it, so a seed replays the same positions.
    /// The driver `Sim::new` builds is asked for the first term id of each
    /// stream it added: the driver replaces the stream config's own value
    /// with its draw at the add, so the override is what decides.
    #[test]
    fn the_simulated_driver_pins_its_first_term_id() {
        let plan = |publication, publishers| StreamPlan {
            publication,
            publishers,
            required: 1,
            optional: 0,
            clients: 0,
            keys: 0,
        };
        let scenario = Scenario {
            name: "pin",
            streams: vec![
                plan(PublicationMode::Exclusive, 1),
                plan(
                    PublicationMode::Concurrent {
                        publishers: 2,
                        allow_non_lse: true,
                    },
                    2,
                ),
            ],
            faults: Faults::default(),
            on_required_loss: LossPolicy::Hold,
            steps: 0,
        };
        let mut sim = Sim::new(&scenario, 1).unwrap();
        assert_eq!(sim.streams.len(), 2);
        let handles: Vec<StreamHandle> = sim.streams.iter().map(|stream| stream.handle).collect();
        for handle in handles {
            let reader = sim.driver.recording_reader(handle, Role::Optional).unwrap();
            assert_eq!(reader.format().initial_term_id, 7, "{handle:?}");
        }
    }
}
