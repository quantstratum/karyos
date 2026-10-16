// SPDX-License-Identifier: Apache-2.0

//! The send and receive stages of one wire run over the sockets backend
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.3, M-5,
//! H-5). [`send_role`] drives the TX half of one loopback endpoint and
//! [`receive_role`] the RX half of another; [`run`] composes them on two
//! threads of one process, and `wire::process` runs each in its own.
//! Every result of [`run`] is functional only (E4): eligibility needs one
//! isolated core per process (measurement-harness.md 4.2), which two
//! threads of one process are not.
//!
//! - **Send stage:** from the message's frames ready (stamped from its
//!   [`Template`]) to the last `TxFrame::commit` of its datagrams; the
//!   flush, which makes the system call, is outside the stage. Under R2 a
//!   message released late by its schedule keeps the delay: its stage
//!   starts at its scheduled instant ([`Schedule::lateness`]), so
//!   coordinated omission stays visible.
//! - **Receive stage:** from the first datagram callback of the batch
//!   that delivers the message's first datagram (H-5) to the decision on
//!   its last datagram: [`Protection::open`], then
//!   `ValidatedDatagram::parse` of the frames. The same interval from the
//!   message's own first callback is recorded alongside (H-5).
//!
//! Every message has one send and one receive sample in nanoseconds; a
//! message never received is [`MISSING`]. A message completes when every
//! datagram index of its template has been accepted once. These make the
//! run invalid and stop it: a received sequence never sent (M-11), a
//! datagram the protection or the parser rejects, a duplicate datagram, a
//! saturated sample (design 2.3) and a failed half.
//!
//! **W5 and N (M-5b).** One W5 sequence numbers one datagram that carries
//! [`StageSamples::messages_per_sample`] messages; each of them takes the
//! stages of that datagram. A run of `n` sequences therefore holds
//! `n * messages_per_sample` messages, and the join of batch B4 repeats
//! each W5 sample that many times. Every other shape has one message per
//! sequence.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use karyos_io::backend::{
    Authority, Commit, Exposure, FlushRequest, FlushStop, GateDecision, InstanceId, RxBackend,
    RxDatagram, RxDrop, RxHandler, RxStop, SenderGate, SenderToken, TxBackend, TxFrame,
    TxItemOutcome, TxOptions, TxQueueConfig, TxQueueId, TxReport,
};
use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::{
    InterfaceSel, MulticastConfig, SocketsConfig, SocketsEndpoint, SocketsRx, SocketsTx,
};
use karyos_protocol::protection::{Protection, Verdict};
use karyos_protocol::sizing::TermLength;
use karyos_sys::receive::{ImageParams, ValidatedDatagram};

use crate::decision::drops_exceed;
use crate::manifest::{MtuRule, Shape};
use crate::samples::{MISSING, SATURATED};
use crate::wire::compose::{IDENTITY, TERM, Template, sequence_of};
use crate::wire::load::Schedule;
use crate::workloads::{BenchError, wait_until};

/// How long the receiver waits for traffic after the sender finishes.
pub const DRAIN: Duration = Duration::from_millis(500);

/// The longest a receive role runs.
pub const RECEIVE_DEADLINE: Duration = Duration::from_secs(120);

/// How long the R1 sender waits for a message to complete before it
/// counts the message lost and sends the next.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a receive role of `run` may take: [`RECEIVE_DEADLINE`] plus,
/// under R2, the time its schedule spans.
///
/// # Errors
///
/// A message count or rate the clock cannot hold.
pub fn receive_deadline(run: &StageRun) -> Result<Duration, BenchError> {
    let transfer = match run.load {
        StageLoad::Closed => Duration::ZERO,
        StageLoad::Open { rate } => {
            let total = run
                .warmup
                .checked_add(run.messages)
                .ok_or_else(|| BenchError("message count overflow".into()))?;
            let nanos = u128::from(total)
                .checked_mul(1_000_000_000)
                .and_then(|nanos| nanos.checked_div(u128::from(rate)))
                .and_then(|nanos| u64::try_from(nanos).ok())
                .ok_or_else(|| BenchError(format!("R2 schedule of {total} at {rate}")))?;
            Duration::from_nanos(nanos)
        }
    };
    RECEIVE_DEADLINE
        .checked_add(transfer)
        .ok_or_else(|| BenchError("receive deadline overflow".into()))
}

/// Frames the send queue holds, and datagrams one flush may submit.
const QUEUE_DEPTH: u16 = 64;

/// The most datagrams one message may have: one bit each in a `u64`.
const MAX_DATAGRAMS: usize = 64;

/// The load of one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageLoad {
    /// R1: one message in flight.
    Closed,
    /// R2: open loop at this many messages per second.
    Open {
        /// Messages per second.
        rate: u64,
    },
}

/// One wire run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageRun {
    /// The workload shape.
    pub shape: Shape,
    /// `E_max`.
    pub e_max: u32,
    /// The MTU rule.
    pub rule: MtuRule,
    /// The load.
    pub load: StageLoad,
    /// Measured messages, after `warmup`.
    pub messages: u64,
    /// Messages sent first and discarded.
    pub warmup: u64,
    /// Receivers: 1 for F1 (one unicast route), more for F2 (loopback
    /// multicast, `wire::process` only).
    pub receivers: u16,
}

/// What one receiver of a run measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverSamples {
    /// Receive stage per measured message, ns; [`MISSING`] when lost.
    pub receive: Vec<u32>,
    /// The receive stage from the message's own first callback instead of
    /// its batch's first (H-5, reported alongside); [`MISSING`] when lost.
    pub receive_callback: Vec<u32>,
    /// The size of the receive batches, one entry per poll that delivered.
    pub batches: Vec<u32>,
    /// Drops the backend reported.
    pub drops: u64,
    /// The most allocations one receive poll made, every callback of its
    /// batch included; counted only by the allocation build ([`BUILD`]), 0
    /// otherwise.
    pub allocations: u64,
}

/// The samples of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageSamples {
    /// Send stage per measured message, ns.
    pub send: Vec<u32>,
    /// Every receiver's samples, in receiver order.
    pub receivers: Vec<ReceiverSamples>,
    /// Flushes that stopped for lack of room in the kernel (backpressure,
    /// §5.3).
    pub backpressure: u64,
    /// R1 messages not acknowledged within [`ACK_TIMEOUT`].
    pub ack_timeouts: u64,
    /// The most allocations one send stage made; counted only by the
    /// allocation build ([`BUILD`]), 0 otherwise.
    pub send_allocations: u64,
    /// Messages each sequence stands for: the frames of a W5 datagram,
    /// one otherwise (M-5b).
    pub messages_per_sample: usize,
    /// Whether the result is functional only (E4): always `true` for
    /// [`run`], whose two roles share a process, whatever the host.
    pub functional_only: bool,
    /// Why the result is functional only; empty when it is not.
    pub functional_reasons: Vec<String>,
    /// Where the sender sent: the receiving endpoint's address under F1,
    /// the multicast group under F2.
    pub destination: SocketAddr,
    /// The cores the run used: each receiver's, then the sender's; empty
    /// when unpinned.
    pub cores: Vec<usize>,
}

/// A gate that permits every candidate: the measured path has no guard.
struct Open;

impl SenderGate for Open {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        match u16::try_from(candidate.tokens.len())
            .ok()
            .and_then(NonZeroU16::new)
        {
            Some(count) => GateDecision::Permit { count },
            None => GateDecision::Deny,
        }
    }
}

/// The build this process is: `alloc-count` counts allocations inside
/// both stages and is never used for timing (M-9; coordinator, ACS 15372);
/// `timing` is every other build.
pub const BUILD: &str = if cfg!(feature = "alloc-count") {
    "alloc-count"
} else {
    "timing"
};

/// Runs `f` and, in the allocation build, counts this thread's
/// allocations, reallocations and frees during it
/// (`karyos_sys::alloc_count`); 0 in a timing build.
#[inline]
fn counted<R>(f: impl FnOnce() -> R) -> (R, u64) {
    #[cfg(feature = "alloc-count")]
    {
        karyos_sys::alloc_count::count(f)
    }
    #[cfg(not(feature = "alloc-count"))]
    {
        (f(), 0)
    }
}

/// Nanoseconds as a sample; `None` when the value saturates, at or above
/// [`SATURATED`], which with [`MISSING`] is reserved (design 2.3: the run
/// is then invalid).
fn ns(duration: Duration) -> Option<u32> {
    u32::try_from(duration.as_nanos())
        .ok()
        .filter(|value| *value < SATURATED)
}

/// `value + 1`, or an error naming `what`.
fn increment(value: u64, what: &str) -> Result<u64, BenchError> {
    value
        .checked_add(1)
        .ok_or_else(|| BenchError(format!("{what} overflow")))
}

/// The receive state of one measured message.
#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    /// The first callback of the batch of its first datagram (H-5).
    batch: Option<Instant>,
    /// The callback of its first datagram.
    callback: Option<Instant>,
    /// The datagram indices accepted so far, one bit each.
    seen: u64,
}

/// The receiver: decides every datagram and timestamps each message.
struct Receiver<'p, P: Protection> {
    protection: &'p P,
    template: &'p Template,
    params: ImageParams,
    /// The mask of a complete message: one bit per datagram.
    full: u64,
    first_sequence: u64,
    slots: Vec<Slot>,
    receive: Vec<u32>,
    receive_callback: Vec<u32>,
    /// The warmup message being received and its datagram mask.
    warmup: Option<(u64, u64)>,
    /// One past the highest sequence completed.
    completed: u64,
    batch_start: Option<Instant>,
    batch_len: u32,
    batches: Vec<u32>,
    drops: u64,
    /// The most allocations one poll made (allocation build only).
    allocations: u64,
    /// The condition that invalidated the run, if any.
    fault: Option<BenchError>,
}

impl<'p, P: Protection> Receiver<'p, P> {
    /// The receiver of `run`, sized up front: nothing it records
    /// reallocates inside a receive stage.
    fn new(run: &StageRun, prepared: &'p Prepared, protection: &'p P) -> Result<Self, BenchError> {
        let term_length =
            TermLength::try_new(TERM).map_err(|error| BenchError(format!("term: {error}")))?;
        // The frame budget is the per-datagram limit the parser enforces.
        let params = ImageParams::new(
            IDENTITY.session_id,
            IDENTITY.stream_id,
            1,
            term_length,
            prepared.template.frame_budget(),
        )
        .map_err(|error| BenchError(format!("image: {error:?}")))?;
        let full = 1_u64
            .checked_shl(
                u32::try_from(prepared.template.datagrams())
                    .map_err(|_| BenchError("datagram count".into()))?,
            )
            // 64 datagrams shift out of range: every bit is set.
            .map_or(Some(u64::MAX), |bit| bit.checked_sub(1))
            .ok_or_else(|| BenchError("datagram mask".into()))?;
        // Every batch delivers at least one datagram, so this bounds them.
        let batch_room = usize::try_from(prepared.total)
            .ok()
            .and_then(|total| total.checked_mul(prepared.template.datagrams()))
            .ok_or_else(|| BenchError("batch record size".into()))?;
        Ok(Self {
            protection,
            template: &prepared.template,
            params,
            full,
            first_sequence: run.warmup,
            slots: vec![Slot::default(); prepared.measured],
            receive: vec![MISSING; prepared.measured],
            receive_callback: vec![MISSING; prepared.measured],
            warmup: None,
            completed: 0,
            batch_start: None,
            batch_len: 0,
            batches: Vec::with_capacity(batch_room),
            drops: 0,
            allocations: 0,
            fault: None,
        })
    }

    /// Decides one datagram that arrived at `callback` in a batch whose
    /// first callback was `batch`, and stops the poll on a fault.
    fn accept(&mut self, bytes: &[u8], batch: Instant, callback: Instant) -> ControlFlow<()> {
        match self.decide(bytes, batch, callback) {
            Ok(()) => ControlFlow::Continue(()),
            Err(error) => {
                self.fault.get_or_insert(error);
                ControlFlow::Break(())
            }
        }
    }

    fn decide(
        &mut self,
        bytes: &[u8],
        batch: Instant,
        callback: Instant,
    ) -> Result<(), BenchError> {
        let frames = match self.protection.open(bytes) {
            Verdict::Accept { frames } => bytes.get(..frames),
            Verdict::Reject(rejection) => {
                return Err(BenchError(format!(
                    "datagram rejected by the protection: {rejection:?}"
                )));
            }
        }
        .ok_or_else(|| BenchError("accepted frames past the datagram".into()))?;
        ValidatedDatagram::parse(frames, &self.params)
            .map_err(|error| BenchError(format!("datagram rejected by the parser: {error:?}")))?;
        let decided = Instant::now();
        let sequence =
            sequence_of(frames).ok_or_else(|| BenchError("datagram without a sequence".into()))?;
        let bit = self
            .template
            .datagram_index(frames)
            .and_then(|index| u32::try_from(index).ok())
            .and_then(|index| 1_u64.checked_shl(index))
            .ok_or_else(|| BenchError(format!("sequence {sequence}: unknown datagram")))?;
        let Some(index) = sequence.checked_sub(self.first_sequence) else {
            // A warmup message: tracked only to know when it completes.
            // Datagrams of one message arrive before the next message's.
            let seen = match self.warmup {
                Some((current, seen)) if current == sequence => seen,
                _ => 0,
            };
            if seen & bit != 0 {
                return Err(BenchError(format!(
                    "sequence {sequence}: duplicate datagram"
                )));
            }
            self.warmup = Some((sequence, seen | bit));
            if seen | bit == self.full {
                self.complete(sequence)?;
            }
            return Ok(());
        };
        let index = usize::try_from(index)
            .ok()
            .filter(|index| *index < self.slots.len())
            .ok_or_else(|| BenchError(format!("orphan sequence {sequence} (M-11)")))?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or_else(|| BenchError("slot index".into()))?;
        if slot.seen & bit != 0 {
            return Err(BenchError(format!(
                "sequence {sequence}: duplicate datagram"
            )));
        }
        slot.seen |= bit;
        let from_batch = *slot.batch.get_or_insert(batch);
        let from_callback = *slot.callback.get_or_insert(callback);
        if slot.seen != self.full {
            return Ok(());
        }
        let stage = |start: Instant| {
            decided
                .checked_duration_since(start)
                .and_then(ns)
                .ok_or_else(|| {
                    BenchError(format!(
                        "sequence {sequence}: receive sample saturated (design 2.3)"
                    ))
                })
        };
        let (sample, own) = (stage(from_batch)?, stage(from_callback)?);
        if let (Some(receive), Some(callback)) = (
            self.receive.get_mut(index),
            self.receive_callback.get_mut(index),
        ) {
            *receive = sample;
            *callback = own;
        }
        self.complete(sequence)
    }

    fn complete(&mut self, sequence: u64) -> Result<(), BenchError> {
        self.completed = self.completed.max(increment(sequence, "sequence")?);
        Ok(())
    }
}

impl<P: Protection> RxHandler for Receiver<'_, P> {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        let callback = Instant::now();
        let batch = *self.batch_start.get_or_insert(callback);
        match self.batch_len.checked_add(1) {
            Some(len) => self.batch_len = len,
            None => {
                self.fault
                    .get_or_insert(BenchError("batch length overflow".into()));
                return ControlFlow::Break(());
            }
        }
        self.accept(datagram.bytes(), batch, callback)
    }

    fn dropped(&mut self, _drop: RxDrop) {
        match increment(self.drops, "drop count") {
            Ok(drops) => self.drops = drops,
            Err(error) => {
                self.fault.get_or_insert(error);
            }
        }
    }
}

/// The membership of an F2 endpoint in `group` on the loopback
/// interface, with its own sends looped back to the host's receivers.
fn loopback_group(group: Ipv4Addr) -> MulticastConfig {
    MulticastConfig {
        loopback: true,
        ..MulticastConfig::new(
            IpAddr::V4(group),
            InterfaceSel::Address(Ipv4Addr::LOCALHOST),
        )
    }
}

fn endpoint(
    max_datagram: u32,
    local: SocketAddr,
    group: Option<Ipv4Addr>,
) -> Result<SocketsEndpoint<OsSocket>, BenchError> {
    let mut config = SocketsConfig::new(local);
    config.multicast = group.map(loopback_group);
    config.max_datagram = u16::try_from(max_datagram)
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| BenchError(format!("max datagram {max_datagram}")))?;
    SocketsEndpoint::open(&config, InstanceId::FIRST, OsSocket::new())
        .map_err(|error| BenchError(format!("open endpoint: {error:?}")))
}

/// What both roles of a run derive from it.
#[derive(Debug)]
pub struct Prepared {
    /// The template of the run's shape for the profile.
    pub template: Template,
    /// The profile's envelope in bytes.
    pub envelope: usize,
    /// The endpoint's datagram limit.
    pub max_datagram: u32,
    /// Warmup plus measured messages.
    pub total: u64,
    /// Measured messages.
    pub measured: usize,
    /// Messages each sequence stands for (M-5b).
    pub messages_per_sample: usize,
}

impl Prepared {
    /// Prepares `run` for `protection`.
    ///
    /// # Errors
    ///
    /// A template error, more than 64 datagrams per message or an
    /// arithmetic overflow.
    pub fn new<P: Protection>(run: &StageRun, protection: &P) -> Result<Self, BenchError> {
        let envelope = protection.envelope_len();
        let template = Template::new(
            run.shape,
            run.e_max,
            u32::try_from(envelope).map_err(|_| BenchError("envelope length".into()))?,
            run.rule,
        )?;
        if template.datagrams() > MAX_DATAGRAMS {
            return Err(BenchError(format!(
                "{}: {} datagrams per message, at most {MAX_DATAGRAMS}",
                run.shape,
                template.datagrams()
            )));
        }
        let max_datagram = u32::try_from(template.len())
            .ok()
            .and_then(|len| len.checked_add(u32::try_from(envelope).ok()?))
            .ok_or_else(|| BenchError("datagram length overflow".into()))?
            .max(template.size.mtu);
        let total = run
            .warmup
            .checked_add(run.messages)
            .ok_or_else(|| BenchError("message count overflow".into()))?;
        let measured =
            usize::try_from(run.messages).map_err(|_| BenchError("too many messages".into()))?;
        let messages_per_sample = if run.shape == Shape::W5 {
            template.frames()
        } else {
            1
        };
        Ok(Self {
            template,
            envelope,
            max_datagram,
            total,
            measured,
            messages_per_sample,
        })
    }

    /// A loopback endpoint sized for the run.
    ///
    /// # Errors
    ///
    /// The endpoint cannot open.
    pub fn endpoint(&self) -> Result<SocketsEndpoint<OsSocket>, BenchError> {
        endpoint(
            self.max_datagram,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            None,
        )
    }

    /// The sending endpoint of an F2 run: on loopback, sending to `group`.
    ///
    /// # Errors
    ///
    /// The endpoint cannot open or join.
    pub fn group_sender(&self, group: Ipv4Addr) -> Result<SocketsEndpoint<OsSocket>, BenchError> {
        endpoint(
            self.max_datagram,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            Some(group),
        )
    }

    /// A receiving endpoint of an F2 run: bound to `group` and `port`,
    /// which every receiver of the run shares (port 0 lets the kernel
    /// choose it for the first).
    ///
    /// # Errors
    ///
    /// The endpoint cannot open or join.
    pub fn group_receiver(
        &self,
        group: Ipv4Addr,
        port: u16,
    ) -> Result<SocketsEndpoint<OsSocket>, BenchError> {
        endpoint(
            self.max_datagram,
            SocketAddr::from((group, port)),
            Some(group),
        )
    }
}

/// The receive role's results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// Receive stage per measured message, ns; [`MISSING`] when lost.
    pub receive: Vec<u32>,
    /// The same from the message's own first callback (H-5).
    pub receive_callback: Vec<u32>,
    /// The size of every delivering batch.
    pub batches: Vec<u32>,
    /// Drops the backend reported.
    pub drops: u64,
    /// The most allocations one receive decision made (allocation build
    /// only).
    pub allocations: u64,
}

/// How a receive role learns that the sender is done and reports R1
/// progress.
#[derive(Clone, Copy)]
pub struct ReceiveControl<'a> {
    /// Whether the sender has finished; the role then stops after
    /// [`DRAIN`] of silence.
    pub finished: &'a dyn Fn() -> bool,
    /// Told, after each poll that completed messages, one past the
    /// highest sequence completed (R1).
    pub ack: &'a dyn Fn(u64),
    /// The longest the role runs.
    pub deadline: Duration,
}

/// The receive role: polls `rx` and times every message until the last
/// one completes, or the link has been idle for [`DRAIN`] while
/// `finished` holds, or `deadline` passes.
///
/// # Errors
///
/// A failed half, an orphan sequence (M-11), a rejected or duplicate
/// datagram, a saturated sample or the image parameters. The role stops
/// at the first of them.
pub fn receive_role<P: Protection>(
    run: &StageRun,
    prepared: &Prepared,
    protection: &P,
    rx: &mut SocketsRx<OsSocket>,
    local: SocketAddr,
    control: &ReceiveControl<'_>,
) -> Result<Received, BenchError> {
    let ReceiveControl {
        finished,
        ack,
        deadline,
    } = *control;
    let mut receiver = Receiver::new(run, prepared, protection)?;
    let budget = SocketsConfig::new(local)
        .rx_budget()
        .ok_or_else(|| BenchError("rx budget".into()))?;
    let began = Instant::now();
    let mut idle_since: Option<Instant> = None;
    let mut acked = 0_u64;
    loop {
        receiver.batch_start = None;
        receiver.batch_len = 0;
        // The allocation build counts the whole poll: every callback of a
        // batch, and the backend between them, all inside the H-5 window.
        let (outcome, allocations) = counted(|| rx.poll_rx(budget, &mut receiver));
        receiver.allocations = receiver.allocations.max(allocations);
        if receiver.batch_len > 0 {
            if receiver.batches.len() < receiver.batches.capacity() {
                receiver.batches.push(receiver.batch_len);
            } else {
                receiver
                    .fault
                    .get_or_insert(BenchError("more batches than datagrams sent".into()));
            }
            idle_since = None;
        }
        if let Some(fault) = receiver.fault.take() {
            return Err(fault);
        }
        if receiver.completed > acked {
            acked = receiver.completed;
            ack(acked);
        }
        if acked >= prepared.total || began.elapsed() >= deadline {
            break;
        }
        match outcome.stop {
            RxStop::WouldBlock | RxStop::NoBuffers | RxStop::Interrupted => {
                if finished() {
                    let since = *idle_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= DRAIN {
                        break;
                    }
                }
                thread::yield_now();
            }
            RxStop::Budget | RxStop::HandlerStopped => {}
            RxStop::Failed(failure) => {
                return Err(BenchError(format!("receive half failed: {failure:?}")));
            }
        }
    }
    Ok(Received {
        receive: receiver.receive,
        receive_callback: receiver.receive_callback,
        batches: receiver.batches,
        drops: receiver.drops,
        allocations: receiver.allocations,
    })
}

/// How an R1 wait for one message ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// The receiver completed the message.
    Completed,
    /// [`ACK_TIMEOUT`] passed first.
    TimedOut,
    /// The receiver has stopped.
    Stopped,
}

/// How a send role follows the receiver.
#[derive(Clone, Copy)]
pub struct SendControl<'a> {
    /// Under R1, waits until message `sequence` completes, for at most
    /// [`ACK_TIMEOUT`].
    pub wait: &'a dyn Fn(u64) -> Wait,
    /// Whether the receiver has stopped; the role then fails at once.
    pub stopped: &'a dyn Fn() -> bool,
}

/// The send role's results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// Send stage per measured message, ns.
    pub send: Vec<u32>,
    /// Flushes that stopped for lack of room in the kernel.
    pub backpressure: u64,
    /// R1 messages not acknowledged within [`ACK_TIMEOUT`].
    pub ack_timeouts: u64,
    /// The most allocations one send stage made (allocation build only).
    pub allocations: u64,
}

fn receiver_stopped() -> BenchError {
    BenchError("receiver stopped before the sender finished".into())
}

/// Flushes `queue` until it is empty, counting the flushes the kernel
/// pushed back in `backpressure`.
fn flush_all(
    tx: &mut SocketsTx<OsSocket>,
    queue: TxQueueId,
    report: &mut TxReport,
    backpressure: &mut u64,
    stopped: &dyn Fn() -> bool,
) -> Result<(), BenchError> {
    let max_datagrams = NonZeroU16::new(QUEUE_DEPTH).unwrap_or(NonZeroU16::MIN);
    loop {
        let outcome = tx.flush(
            FlushRequest {
                queue,
                max_datagrams,
                max_bytes: u32::MAX,
            },
            &mut Open,
            report,
        );
        while let Some(entry) = report.pop_front() {
            match entry.outcome {
                TxItemOutcome::Submitted { .. } | TxItemOutcome::Pending { .. } => {}
                TxItemOutcome::Returned { reason } => {
                    return Err(BenchError(format!(
                        "message {} returned unsent: {reason:?}",
                        entry.token.get()
                    )));
                }
                TxItemOutcome::Unknown => {
                    return Err(BenchError(format!(
                        "message {}: exposure unknown",
                        entry.token.get()
                    )));
                }
            }
        }
        match outcome.stop {
            FlushStop::QueueEmpty => return Ok(()),
            FlushStop::Exposed => {}
            FlushStop::WouldBlock
            | FlushStop::NoBuffers
            | FlushStop::Interrupted
            | FlushStop::ErrorLost
            | FlushStop::PeerError => {
                *backpressure = increment(*backpressure, "backpressure count")?;
                if stopped() {
                    return Err(receiver_stopped());
                }
                thread::yield_now();
            }
            stop => return Err(BenchError(format!("flush failed: {stop:?}"))),
        }
    }
}

/// The send role: sends every message of `run` to `peer` and returns the
/// send stage of each measured one. Every message is flushed until the
/// queue is empty before the next; under R1 the role then waits for it
/// through `control`.
///
/// # Errors
///
/// A route, queue, seal, claim, commit or flush error, an item the
/// backend returned, a saturated sample or a stopped receiver.
pub fn send_role<P: Protection>(
    run: &StageRun,
    prepared: &Prepared,
    protection: &P,
    tx: &mut SocketsTx<OsSocket>,
    peer: SocketAddr,
    control: &SendControl<'_>,
) -> Result<Sent, BenchError> {
    let SendControl { wait, stopped } = *control;
    let template = &prepared.template;
    let envelope = prepared.envelope;
    let route = tx
        .add_route(peer)
        .map_err(|error| BenchError(format!("route: {error:?}")))?;
    let queue = tx
        .open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route,
            max_pending: NonZeroU16::new(QUEUE_DEPTH).unwrap_or(NonZeroU16::MIN),
        })
        .map_err(|error| BenchError(format!("queue: {error:?}")))?;
    let mut send = vec![MISSING; prepared.measured];
    let mut message = vec![0_u8; template.len()];
    let room = template
        .len()
        .checked_add(envelope)
        .ok_or_else(|| BenchError("seal buffer size".into()))?;
    let mut buffer = vec![0_u8; room];
    let mut report = TxReport::new();
    let mut backpressure = 0_u64;
    let mut ack_timeouts = 0_u64;
    let mut max_allocations = 0_u64;
    let schedule = match run.load {
        StageLoad::Open { rate } => Some(Schedule::new(Instant::now(), rate)?),
        StageLoad::Closed => None,
    };
    for sequence in 0..prepared.total {
        if stopped() {
            return Err(receiver_stopped());
        }
        let late = match &schedule {
            Some(schedule) => {
                if !wait_until(schedule.instant(sequence)?, stopped) {
                    return Err(receiver_stopped());
                }
                schedule.lateness(sequence, Instant::now())?
            }
            None => Duration::ZERO,
        };
        // The stage, from the stamped frames to the last commit; the
        // allocation build counts what it allocates (M-9).
        let (staged, allocations) = counted(|| -> Result<Instant, BenchError> {
            template.stamp(sequence, &mut message)?;
            let begin = Instant::now();
            for index in 0..template.datagrams() {
                let frames = template
                    .datagram(&message, index)
                    .ok_or_else(|| BenchError("datagram index".into()))?;
                let room = frames
                    .len()
                    .checked_add(envelope)
                    .ok_or_else(|| BenchError("seal length".into()))?;
                let slot = buffer
                    .get_mut(..room)
                    .ok_or_else(|| BenchError("seal buffer".into()))?;
                slot.get_mut(..frames.len())
                    .ok_or_else(|| BenchError("seal buffer".into()))?
                    .copy_from_slice(frames);
                let length = protection
                    .seal(slot, frames.len())
                    .map_err(|error| BenchError(format!("seal: {error}")))?;
                let sealed = slot
                    .get(..length)
                    .ok_or_else(|| BenchError("sealed length".into()))?;
                let mut frame = tx
                    .claim_tx(queue, sealed.len())
                    .map_err(|error| BenchError(format!("claim: {error:?}")))?;
                frame
                    .bytes_mut()
                    .get_mut(..sealed.len())
                    .ok_or_else(|| BenchError("claim capacity".into()))?
                    .copy_from_slice(sealed);
                frame
                    .commit(Commit {
                        len: sealed.len(),
                        token: SenderToken::new(sequence),
                        options: TxOptions::none(),
                    })
                    .map_err(|_| BenchError("commit rejected".into()))?;
            }
            Ok(begin)
        });
        let begin = staged?;
        max_allocations = max_allocations.max(allocations);
        let committed = Instant::now();
        if let Some(index) = sequence
            .checked_sub(run.warmup)
            .and_then(|index| usize::try_from(index).ok())
            && let Some(sample) = send.get_mut(index)
        {
            // The stage of a late message starts at its scheduled instant.
            *sample = committed
                .checked_duration_since(begin)
                .and_then(|stage| stage.checked_add(late))
                .and_then(ns)
                .ok_or_else(|| {
                    BenchError(format!(
                        "sequence {sequence}: send sample saturated (design 2.3)"
                    ))
                })?;
        }
        flush_all(tx, queue, &mut report, &mut backpressure, stopped)?;
        if run.load == StageLoad::Closed {
            match wait(sequence) {
                Wait::Completed => {}
                Wait::Stopped => return Err(receiver_stopped()),
                Wait::TimedOut => {
                    // Each costs ACK_TIMEOUT: past the drop budget the run
                    // is Not demonstrated anyway (M-11), so it ends here.
                    ack_timeouts = increment(ack_timeouts, "ack timeout count")?;
                    if drops_exceed(ack_timeouts, run.messages) {
                        return Err(BenchError(format!(
                            "{ack_timeouts} messages unacknowledged within {ACK_TIMEOUT:?}, above 0.1% (M-11)"
                        )));
                    }
                }
            }
        }
    }
    Ok(Sent {
        send,
        backpressure,
        ack_timeouts,
        allocations: max_allocations,
    })
}

/// Sets its flag when dropped, so a role that returns, fails or panics
/// always tells the other one.
struct SetOnDrop<'a>(&'a AtomicBool);

impl Drop for SetOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Runs one wire run with `protection` on both sides, the two roles on
/// two threads of this process (functional only, E4).
///
/// # Errors
///
/// The errors of [`send_role`] and [`receive_role`], and a role that
/// panicked.
pub fn run<P: Protection + Sync>(
    run: StageRun,
    protection: &P,
) -> Result<StageSamples, BenchError> {
    if run.receivers != 1 {
        return Err(BenchError(format!(
            "{} receivers: the in-process run is F1 only; F2 runs in processes",
            run.receivers
        )));
    }
    let prepared = Prepared::new(&run, protection)?;
    let (mut tx, _tx_rx) = prepared
        .endpoint()?
        .split()
        .map_err(|_| BenchError("split sender".into()))?;
    let receiving = prepared.endpoint()?;
    let receiver_address = receiving.capabilities().local;
    let (_rx_tx, mut rx) = receiving
        .split()
        .map_err(|_| BenchError("split receiver".into()))?;
    let deadline = receive_deadline(&run)?;
    let completed = AtomicU64::new(0);
    let sender_done = AtomicBool::new(false);
    let receiver_done = AtomicBool::new(false);
    let (sent, received) = thread::scope(|scope| {
        let receiving = scope.spawn(|| {
            let _done = SetOnDrop(&receiver_done);
            receive_role(
                &run,
                &prepared,
                protection,
                &mut rx,
                receiver_address,
                &ReceiveControl {
                    finished: &|| sender_done.load(Ordering::Acquire),
                    ack: &|count| completed.store(count, Ordering::Release),
                    deadline,
                },
            )
        });
        let sending = scope.spawn(|| {
            let _done = SetOnDrop(&sender_done);
            let stopped = || receiver_done.load(Ordering::Acquire);
            let wait = |sequence: u64| {
                let start = Instant::now();
                loop {
                    if completed.load(Ordering::Acquire) > sequence {
                        return Wait::Completed;
                    }
                    if stopped() {
                        return Wait::Stopped;
                    }
                    if start.elapsed() >= ACK_TIMEOUT {
                        return Wait::TimedOut;
                    }
                    std::hint::spin_loop();
                }
            };
            send_role(
                &run,
                &prepared,
                protection,
                &mut tx,
                receiver_address,
                &SendControl {
                    wait: &wait,
                    stopped: &stopped,
                },
            )
        });
        let sent = sending
            .join()
            .map_err(|_| BenchError("sender thread panicked".into()));
        let received = receiving
            .join()
            .map_err(|_| BenchError("receiver thread panicked".into()));
        (sent, received)
    });
    // A receiver fault explains a sender that stopped for it: report it
    // first.
    let received = received??;
    let sent = sent??;
    Ok(StageSamples {
        send: sent.send,
        receivers: vec![ReceiverSamples {
            receive: received.receive,
            receive_callback: received.receive_callback,
            batches: received.batches,
            drops: received.drops,
            allocations: received.allocations,
        }],
        backpressure: sent.backpressure,
        ack_timeouts: sent.ack_timeouts,
        send_allocations: sent.allocations,
        messages_per_sample: prepared.messages_per_sample,
        functional_only: true,
        functional_reasons: vec!["the roles share one process".to_string()],
        destination: receiver_address,
        cores: Vec::new(),
    })
}

#[cfg(test)]
mod tests;
