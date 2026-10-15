// SPDX-License-Identifier: Apache-2.0

//! The scheduler: one thread, one API call per step, an order drawn from a
//! seeded generator, virtual time (`quantstratum-docs: karyos/design/simulator-and-bench.md`).

use std::collections::VecDeque;
use std::fmt;

use karyos_client::{ClientSubscription, MessageLimit};
use karyos_driver::{
    DriverConfig, DriverError, EmbeddedDriver, Reconfiguration, StreamConfig, StreamHandle,
};
use karyos_sys::error::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use crate::clock::SimClock;
use crate::oracle::{ReaderView, StreamRecord};
use crate::payload::{Stamp, encode};
use crate::publisher::{Attempt, Claimed, SimPublisher};
use crate::rng::Rng;

/// Virtual time units a claim may stay uncommitted.
pub const CLAIM_DEADLINE: u64 = 60;
/// Virtual time units a handle has to move at a cutover.
pub const CUTOVER_DEADLINE: u64 = 120;
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

impl<'s> Sim<'s> {
    fn new(scenario: &'s Scenario, seed: u64) -> Result<Self, Failure> {
        let clock = SimClock::default();
        let config = DriverConfig {
            cutover_deadline: CUTOVER_DEADLINE,
            max_retained_generations: 2,
            ..DriverConfig::default()
        };
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
                        max_subscribers: plan.required + plan.optional + 1,
                        mtu: DEFAULT_MTU,
                        max_reserved: MIN_TERM_LENGTH / 8,
                        initial_term_id: TermId::new(7),
                        lane: Lane::ZERO,
                        session_id: 1,
                        stream_id,
                        claim_deadline: CLAIM_DEADLINE,
                        publication: plan.publication,
                    },
                    allow_unconnected: true,
                    on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
                    conflation: None,
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

    /// One step: an actor's call, or a driver duty cycle.
    fn step(&mut self, depth: u8) -> Result<(), Failure> {
        self.step += 1;
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

    fn driver_step(&mut self) -> Result<(), Failure> {
        self.driver
            .do_work()
            .map_err(|error| self.failure(format!("do_work: {error}")))?;
        self.note("driver duty".into());
        if self.draining {
            return Ok(());
        }
        let faults = self.scenario.faults;
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
        let attempt = if self.rng.chance(2, 3) {
            let payload = encode(stamp, length);
            let attempt = publication
                .offer(&payload)
                .map_err(|error| self.failure(format!("offer: {error}")))?;
            self.note(format!("actor {id} offer {stamp:?}: {attempt:?}"));
            attempt
        } else {
            let claimed = publication
                .claim(length as u32)
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

    /// Every pause ends; only readers and the driver run until nothing
    /// changes for a while.
    fn drain(&mut self) -> Result<(), Failure> {
        self.draining = true;
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
            for index in 0..self.actors.len() {
                let is_reader = matches!(
                    self.actors.get(index),
                    Some(Some(Actor {
                        kind: Kind::Reader { .. },
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
        for actor in self.actors.iter().flatten() {
            if let Kind::Reader { view, .. } = &actor.kind {
                delivered += view.delivered();
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
            digest: self.digest,
        })
    }
}
