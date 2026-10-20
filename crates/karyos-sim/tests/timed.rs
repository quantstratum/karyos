// SPDX-License-Identifier: Apache-2.0

//! Timed transmission on virtual time (`quantstratum-docs:
//! karyos/design/timed-tx.md`, section 8; P2.11 T1 step 6, ACS 15462).
//!
//! One timed stream of the embedded driver, its offers checked against the
//! simulator's clock ([`EmbeddedDriver::schedule_stream_with_clock`]), and
//! the sender's side of section 2: a subscription reads the lane's
//! messages in order, a [`ScheduleConsumer`] gives each its requested time,
//! and a [`TimedGate`] over a lane sender and the sockets endpoint with the
//! scripted `SocketOps` submits it. A second, immediate lane shares the
//! sender. Each step the scheduler may offer a timed message (a time drawn
//! from twice the tolerance in the past to the horizon, never below the
//! last), stage an immediate datagram, pump the log into the timed lane's
//! queue, serve the sender, take the step between gates, and advance the
//! clock, now and then past a deadline.
//!
//! Oracles, on every submission:
//!
//! - no timed datagram is submitted before its time;
//! - timed datagrams are submitted in offer order, each with its own time;
//! - an immediate datagram is submitted in the step it was staged: a
//!   waiting timed lane never holds it;
//! - under cancel-on-deadline, a miss seals the stream with
//!   `DeadlineMissed`, no timed datagram is submitted after it, and no
//!   offer is accepted once sealed; otherwise nothing aborts and the late
//!   sends the gate counts are exactly those beyond the tolerance.
//!
//! The run is logical, inside one process: it is not evidence for kernel
//! send timing, which belongs to the ETF batch (T2). A failure prints its
//! seed and trace.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::panic)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;

use core::num::NonZeroU16;

use karyos_client::OfferOutcome;
use karyos_client::schedule::{ClockDomain, ScheduleClock, ScheduleOptions};
use karyos_driver::schedule::{LaneFrame, ScheduleConsumer};
use karyos_driver::timed_gate::{LatePolicy, TimedGate};
use karyos_driver::{EmbeddedDriver, LossPolicy, StreamConfig, StreamHandle};
use karyos_io::backend::{
    Authority, Commit, Exposure, GateDecision, InstanceId, SenderGate, SenderToken, TxBackend,
    TxFrame, TxOptions, TxQueueConfig, TxQueueId, TxReport, TxTicket,
};
use karyos_io::lanes::{LaneGate, LaneSender, Left, Staged};
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsTx};
use karyos_io::sockets::ops::SendResult;
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::lanes::drr::{Budget, DrrConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role, SealReason};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use karyos_sim::{Failure, Rng, SimClock, scenarios};

/// The timed lane (DRR lane 0) and the immediate one (1).
const TIMED: usize = 0;
const IMMEDIATE: usize = 1;
/// Datagrams each lane queue holds.
const BOUND: u16 = 4;
/// Entries of the schedule ring.
const CAPACITY: u32 = 8;
/// The horizon and the tolerance, in virtual nanoseconds.
const HORIZON: u64 = 1_000_000;
const TOLERANCE: u64 = 100_000;
/// Virtual time at the start.
const START: u64 = 1_000_000_000;
/// A datagram: the message's sequence number.
const FRAME: u16 = 8;
/// Steps kept in a failure's trace.
const TRACE: usize = 32;

/// A timed scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimedScenario {
    /// Its name.
    name: &'static str,
    /// Whether the timed lane aborts at a missed deadline.
    cancel_on_deadline: bool,
    /// Steps per run.
    steps: u64,
}

/// The timed scenarios: late messages sent, or a miss aborting the lane.
#[must_use]
fn timed_scenarios() -> Vec<TimedScenario> {
    vec![
        TimedScenario {
            name: "timed-send-late",
            cancel_on_deadline: false,
            steps: 1500,
        },
        TimedScenario {
            name: "timed-cancel",
            cancel_on_deadline: true,
            steps: 1500,
        },
    ]
}

/// What a timed run did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TimedReport {
    /// Timed messages accepted.
    offered: u64,
    /// Timed datagrams submitted.
    sent: u64,
    /// Timed datagrams submitted beyond the tolerance.
    late: u64,
    /// Immediate datagrams submitted.
    immediate: u64,
    /// Whether the timed lane aborted at a missed deadline.
    aborted: bool,
    /// A digest of every submission: equal for equal seeds.
    digest: u64,
}

/// The sender's inner gate: permits everything and records each head
/// that left, for the oracles.
#[derive(Debug)]
struct Recorder {
    left: Rc<RefCell<Vec<(usize, TxTicket, Left)>>>,
}

impl SenderGate for Recorder {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        u16::try_from(candidate.tokens.len())
            .ok()
            .and_then(NonZeroU16::new)
            .map_or(GateDecision::Deny, |count| GateDecision::Permit { count })
    }
}

impl LaneGate for Recorder {
    fn admits(&mut self, _lane: usize) -> bool {
        true
    }

    fn left(&mut self, lane: usize, staged: Staged, how: Left) {
        self.left.borrow_mut().push((lane, staged.ticket, how));
    }
}

/// A datagram staged and not yet submitted.
#[derive(Debug, Clone, Copy)]
struct Pending {
    ticket: TxTicket,
    /// The timed message's sequence and time, or the immediate datagram's
    /// step.
    sequence: u64,
    time: Option<u64>,
}

/// The sockets side: the TX half, its scripted socket and the queues.
struct Wire {
    tx: SocketsTx<ScriptedSocket>,
    socket: ScriptedSocket,
    queues: [TxQueueId; 2],
}

impl Wire {
    fn open() -> Result<Self, String> {
        let mut config = SocketsConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 7000)));
        config.max_datagram = NonZeroU16::new(256).ok_or("max datagram")?;
        config.tx_slots = NonZeroU16::new(16).ok_or("tx slots")?;
        config.max_queues = NonZeroU16::new(4).ok_or("max queues")?;
        config.max_routes = NonZeroU16::new(4).ok_or("max routes")?;
        config.max_batch = NonZeroU16::new(8).ok_or("max batch")?;
        let socket = ScriptedSocket::new();
        let observer = socket.observer();
        let endpoint = SocketsEndpoint::open(&config, InstanceId::FIRST, socket)
            .map_err(|error| format!("endpoint: {error:?}"))?;
        let (mut tx, _rx) = endpoint
            .split()
            .map_err(|error| format!("split: {error:?}"))?;
        let route = tx
            .add_route(SocketAddr::from((Ipv4Addr::LOCALHOST, 7001)))
            .map_err(|error| format!("route: {error:?}"))?;
        let mut open = || {
            tx.open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::new(BOUND).ok_or("bound")?,
            })
            .map_err(|error| format!("queue: {error:?}"))
        };
        let queues = [open()?, open()?];
        Ok(Self {
            tx,
            socket: observer,
            queues,
        })
    }

    /// Commits one datagram carrying `sequence` to `lane`'s queue.
    fn commit(&mut self, lane: usize, sequence: u64) -> Result<(SenderToken, Staged), String> {
        let queue = *self.queues.get(lane).ok_or("lane")?;
        let token = SenderToken::new(sequence);
        let mut frame = self
            .tx
            .claim_tx(queue, usize::from(FRAME))
            .map_err(|error| format!("claim: {error:?}"))?;
        frame.bytes_mut().copy_from_slice(&sequence.to_le_bytes());
        let ticket = frame
            .commit(Commit {
                len: usize::from(FRAME),
                token,
                options: TxOptions::none(),
            })
            .map_err(|error| format!("commit: {error:?}"))?;
        Ok((
            token,
            Staged {
                ticket,
                charge: u64::from(FRAME),
                len: FRAME,
            },
        ))
    }
}

impl Drop for Wire {
    /// Returns every item still pending: a TX half refuses to be dropped
    /// with pending items.
    fn drop(&mut self) {
        let mut report = TxReport::new();
        for queue in self.queues {
            while let Ok(outcome) = self.tx.cancel_pending(queue, &mut report) {
                while report.pop_front().is_some() {}
                if !outcome.more {
                    break;
                }
            }
        }
    }
}

/// One run's state.
struct Run {
    scenario: TimedScenario,
    seed: u64,
    step: u64,
    trace: VecDeque<String>,
    digest: u64,
}

impl Run {
    fn fail(&self, reason: impl Into<String>) -> Failure {
        Failure {
            scenario: self.scenario.name,
            seed: self.seed,
            step: self.step,
            reason: reason.into(),
            trace: self.trace.iter().cloned().collect(),
        }
    }

    fn note(&mut self, event: String) {
        for byte in event.bytes() {
            self.digest ^= u64::from(byte);
            self.digest = self.digest.wrapping_mul(0x0000_0100_0000_01B3);
        }
        if self.trace.len() == TRACE {
            let _ = self.trace.pop_front();
        }
        self.trace.push_back(format!("{}: {event}", self.step));
    }
}

/// The timed lane's schedule ring.
fn ring(driver: &EmbeddedDriver, handle: StreamHandle) -> Option<&[karyos_sys::sync::AtomicU64]> {
    driver.schedule_ring(handle).ok().flatten()
}

fn stream_config() -> Result<StreamConfig, String> {
    Ok(StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH)
                .map_err(|error| format!("term: {error:?}"))?,
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: CAPACITY,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    })
}

/// Runs `scenario` under `seed`.
///
/// # Errors
///
/// The first oracle that fails, with its step and the last steps.
#[allow(
    clippy::too_many_lines,
    reason = "one scheduler loop, its steps in order, as in sim::run"
)]
fn run_timed(scenario: &TimedScenario, seed: u64) -> Result<TimedReport, Failure> {
    let mut run = Run {
        scenario: *scenario,
        seed,
        step: 0,
        trace: VecDeque::with_capacity(TRACE),
        digest: 0xCBF2_9CE4_8422_2325,
    };
    let setup = |reason: String| run.fail(format!("setup: {reason}"));
    let clock = SimClock::default();
    clock.advance(START);
    let mut driver = EmbeddedDriver::new().map_err(|error| setup(format!("{error:?}")))?;
    let handle: StreamHandle = stream_config()
        .and_then(|config| {
            driver
                .add_stream(config)
                .map_err(|error| format!("{error:?}"))
        })
        .map_err(setup)?;
    let virtual_clock = clock.clone();
    driver
        .schedule_stream_with_clock(
            handle,
            ScheduleOptions::default()
                .with_domain(ClockDomain::Monotonic)
                .with_max_horizon(HORIZON)
                .with_lateness_tolerance(TOLERANCE)
                .with_cancel_on_deadline(scenario.cancel_on_deadline),
            ScheduleClock::new(move || virtual_clock.get()),
        )
        .map_err(|error| setup(format!("{error:?}")))?;
    let mut publication = driver
        .publication(handle)
        .map_err(|error| setup(format!("{error:?}")))?;
    let mut subscription = driver
        .subscribe(handle, Role::Required)
        .map_err(|error| setup(format!("{error:?}")))?;
    let mut consumer = ring(&driver, handle)
        .ok_or_else(|| "no schedule ring".to_owned())
        .and_then(|words| {
            ScheduleConsumer::new(words, u64::MAX).map_err(|error| format!("{error:?}"))
        })
        .map_err(setup)?;
    let mut wire = Wire::open().map_err(setup)?;
    let mut sender = DrrConfig::new(&[256, 256], 256)
        .map_err(|error| format!("{error:?}"))
        .and_then(|drr| {
            LaneSender::new(drr, &wire.queues, usize::from(BOUND))
                .map_err(|error| format!("{error:?}"))
        })
        .map_err(setup)?;
    let left = Rc::new(RefCell::new(Vec::new()));
    let policy = LatePolicy {
        tolerance: TOLERANCE,
        cancel_on_deadline: scenario.cancel_on_deadline,
        max_horizon: u64::MAX,
    };
    let mut gate = TimedGate::new(
        Recorder {
            left: Rc::clone(&left),
        },
        &[policy, LatePolicy::default()],
        usize::from(BOUND),
        clock.get(),
    );
    if let Some(counters) = driver.timed_counters(handle).ok().flatten() {
        gate.attach_counters(TIMED, counters);
    }

    let mut rng = Rng::new(seed);
    // Accepted offers not yet read from the log: (position, time, sequence).
    let mut offered: VecDeque<(u64, u64, u64)> = VecDeque::new();
    let mut pending: [VecDeque<Pending>; 2] = [VecDeque::new(), VecDeque::new()];
    let mut last_time = None;
    let mut next_offer = 0u64;
    let mut next_sent = 0u64;
    let mut next_immediate = 0u64;
    let mut sealed = false;
    let mut report = TimedReport {
        offered: 0,
        sent: 0,
        late: 0,
        immediate: 0,
        aborted: false,
        digest: 0,
    };
    for step in 0..scenario.steps {
        run.step = step;
        let now = clock.get();
        gate.set_now(now);
        // 1. A timed offer.
        if rng.chance(1, 2) {
            // The clock starts at START, far above both bounds.
            let (Some(low), Some(high)) =
                (now.checked_sub(2 * TOLERANCE), now.checked_add(HORIZON))
            else {
                return Err(run.fail("the clock left its range"));
            };
            let drawn = rng.between(low, high);
            let time = last_time.map_or(drawn, |last: u64| drawn.max(last));
            match publication.offer_at(&next_offer.to_le_bytes(), time) {
                Ok(OfferOutcome::Accepted { position, .. }) => {
                    if sealed {
                        return Err(run.fail("an offer was accepted after the seal"));
                    }
                    run.note(format!("offer {next_offer} at {time} -> {position}"));
                    offered.push_back((position, time, next_offer));
                    last_time = Some(time);
                    next_offer += 1;
                    report.offered += 1;
                }
                Ok(OfferOutcome::BackPressured) => run.note("offer back pressured".into()),
                Ok(OfferOutcome::Gated) if sealed => run.note("offer gated".into()),
                Ok(other) => return Err(run.fail(format!("offer: {other:?}"))),
                Err(error) => return Err(run.fail(format!("offer refused: {error:?}"))),
            }
        }
        // 2. An immediate datagram.
        if rng.chance(1, 3) && sender.pending(IMMEDIATE) < Some(usize::from(BOUND)) {
            let sequence = next_immediate;
            let (token, staged) = wire
                .commit(IMMEDIATE, sequence)
                .map_err(|reason| run.fail(reason))?;
            gate.stage(IMMEDIATE, token, staged.ticket, None, |_| {
                sender.staged(IMMEDIATE, staged)
            })
            .map_err(|error| run.fail(format!("stage immediate: {error:?}")))?;
            pending[IMMEDIATE].push_back(Pending {
                ticket: staged.ticket,
                sequence: step,
                time: None,
            });
            next_immediate += 1;
        }
        // 3. The log into the timed lane's queue, in order.
        while !gate.deadline_missed(TIMED) && sender.pending(TIMED) < Some(usize::from(BOUND)) {
            let mut read = None;
            let _ = subscription.poll(
                |bytes, info| {
                    let mut sequence = [0u8; 8];
                    if let Some(source) = bytes.get(..8) {
                        sequence.copy_from_slice(source);
                    }
                    read = Some((info.position, u64::from_le_bytes(sequence)));
                },
                karyos_client::MessageLimit::new(1),
            );
            let Some((position, sequence)) = read else {
                break;
            };
            let Some(words) = ring(&driver, handle) else {
                return Err(run.fail("the schedule ring went away"));
            };
            let time = consumer
                .frame(
                    words,
                    LaneFrame::Data {
                        position,
                        begin: true,
                        end: true,
                    },
                )
                .map_err(|error| run.fail(format!("consumer: {error:?}")))?;
            let expected = offered.pop_front();
            if expected != time.map(|time| (position, time, sequence)) {
                return Err(run.fail(format!(
                    "read {sequence} at {position} with {time:?}, expected {expected:?}"
                )));
            }
            let (token, staged) = wire
                .commit(TIMED, sequence)
                .map_err(|reason| run.fail(reason))?;
            gate.stage(TIMED, token, staged.ticket, time, |_| {
                sender.staged(TIMED, staged)
            })
            .map_err(|error| run.fail(format!("stage timed: {error:?}")))?;
            pending[TIMED].push_back(Pending {
                ticket: staged.ticket,
                sequence,
                time,
            });
        }
        // 4. Serve: the kernel accepts every send.
        for _ in 0..2 * BOUND {
            wire.socket.push_send(SendResult::Sent {
                sent: 1,
                error: None,
            });
        }
        let _ = sender.serve(
            &mut wire.tx,
            &mut gate,
            Budget {
                work: 64,
                bytes: 1 << 20,
            },
        );
        let reports: Vec<_> = left.borrow_mut().drain(..).collect();
        for (lane, ticket, how) in reports {
            let Some(head) = pending.get_mut(lane).and_then(VecDeque::pop_front) else {
                return Err(run.fail(format!("lane {lane} left with nothing pending")));
            };
            if head.ticket != ticket || how != Left::Submitted {
                return Err(run.fail(format!("lane {lane} left out of step: {how:?}")));
            }
            if lane == IMMEDIATE {
                if head.sequence != step {
                    return Err(run.fail(format!(
                        "an immediate datagram of step {} was held to {step}",
                        head.sequence
                    )));
                }
                report.immediate += 1;
                run.note(format!("immediate at {now}"));
                continue;
            }
            let Some(time) = head.time else {
                return Err(run.fail("a timed datagram without its time"));
            };
            if now < time {
                return Err(run.fail(format!(
                    "timed {} submitted at {now}, before its time {time}",
                    head.sequence
                )));
            }
            if head.sequence != next_sent {
                return Err(run.fail(format!(
                    "timed {} submitted out of order, expected {next_sent}",
                    head.sequence
                )));
            }
            if report.aborted {
                return Err(run.fail("a timed datagram was submitted after the miss"));
            }
            if now - time > TOLERANCE {
                if scenario.cancel_on_deadline {
                    return Err(run.fail(format!(
                        "timed {} submitted {} late under cancel",
                        head.sequence,
                        now - time
                    )));
                }
                report.late += 1;
            }
            next_sent += 1;
            report.sent += 1;
            run.note(format!("timed {} at {now}", head.sequence));
            let Some(words) = ring(&driver, handle) else {
                return Err(run.fail("the schedule ring went away"));
            };
            consumer
                .message_left(words)
                .map_err(|error| run.fail(format!("release: {error:?}")))?;
        }
        // 5. The step between gates.
        if gate.deadline_missed(TIMED) {
            if !scenario.cancel_on_deadline {
                return Err(run.fail("a miss without cancel-on-deadline"));
            }
            // A declared miss is a real one: the first timed head not yet
            // submitted was past its time plus the tolerance.
            if !report.aborted {
                let first = pending[TIMED].iter().find_map(|head| head.time);
                let real = first
                    .and_then(|time| now.checked_sub(time))
                    .is_some_and(|late| late > TOLERANCE);
                if !real {
                    return Err(run.fail(format!(
                        "a miss declared at {now} with the first pending time {first:?}"
                    )));
                }
            }
            if !report.aborted {
                run.note(format!("deadline missed at {now}"));
            }
            report.aborted = true;
            gate.between_gates(|_| driver.seal_deadline_missed(handle))
                .map_err(|error| run.fail(format!("seal: {error:?}")))?;
            sealed = true;
        }
        // 6. Time passes; now and then past a deadline.
        let by = if rng.chance(1, 60) {
            3 * TOLERANCE
        } else {
            rng.below(TOLERANCE / 2)
        };
        clock.advance(by);
        let _ = driver.do_work();
    }
    if gate.counts().late_sends != report.late {
        return Err(run.fail(format!(
            "the gate counted {} late sends, the oracle {}",
            gate.counts().late_sends,
            report.late
        )));
    }
    if report.aborted && gate.counts().deadline_aborts != 1 {
        return Err(run.fail("a miss not counted once"));
    }
    if sealed {
        let reason = driver
            .seal_reason(handle)
            .map_err(|error| run.fail(format!("{error:?}")))?;
        if reason != Some(SealReason::DeadlineMissed) {
            return Err(run.fail(format!("sealed with {reason:?}")));
        }
    }
    report.digest = run.digest;
    Ok(report)
}

fn sweep(name: &str) -> Vec<TimedReport> {
    let scenario = timed_scenarios()
        .into_iter()
        .find(|scenario| scenario.name == name)
        .unwrap_or_else(|| panic!("no scenario {name}"));
    scenarios::seeds()
        .into_iter()
        .map(|seed| run_timed(&scenario, seed).unwrap_or_else(|failure| panic!("{failure}")))
        .collect()
}

#[test]
fn timed_send_late() {
    let reports = sweep("timed-send-late");
    assert!(reports.iter().all(|report| !report.aborted));
    // One seed (`KARYOS_SIM_SEED`) need not show every path.
    if reports.len() == 1 {
        return;
    }
    assert!(reports.iter().all(|report| !report.aborted));
    assert!(reports.iter().map(|report| report.sent).sum::<u64>() > 0);
    assert!(reports.iter().map(|report| report.late).sum::<u64>() > 0);
    assert!(reports.iter().map(|report| report.immediate).sum::<u64>() > 0);
}

#[test]
fn timed_cancel() {
    let reports = sweep("timed-cancel");
    assert!(reports.iter().all(|report| report.late == 0));
    if reports.len() == 1 {
        return;
    }
    assert!(reports.iter().any(|report| report.aborted));
    assert!(reports.iter().map(|report| report.sent).sum::<u64>() > 0);
}

#[test]
fn a_timed_seed_reproduces_its_run() {
    for scenario in timed_scenarios() {
        let first = run_timed(&scenario, 7).unwrap_or_else(|failure| panic!("{failure}"));
        let second = run_timed(&scenario, 7).unwrap_or_else(|failure| panic!("{failure}"));
        assert_eq!(first, second, "scenario {}", scenario.name);
        let other = run_timed(&scenario, 8).unwrap_or_else(|failure| panic!("{failure}"));
        assert_ne!(first.digest, other.digest, "scenario {}", scenario.name);
    }
}
