// SPDX-License-Identifier: Apache-2.0

//! The send and receive stages of one wire run over the sockets backend
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.3, M-5,
//! H-5), in one process: the TX half of one loopback endpoint and the RX
//! half of another, each driven by its own thread. Batch B3c-2 moves each
//! role into its own process; until then every result of this module is
//! functional only (E4): eligibility needs one isolated core per process
//! (measurement-harness.md 4.2), which two threads of one process are not.
//!
//! - **Send stage:** from the message's frames ready (stamped from its
//!   [`Template`]) to the last `TxFrame::commit` of its datagrams; the
//!   flush, which makes the system call, is outside the stage.
//! - **Receive stage:** from the first datagram callback of the batch
//!   that delivers the message's first datagram (H-5) to the decision on
//!   its last datagram: [`Protection::open`], then
//!   `ValidatedDatagram::parse` of the frames.
//!
//! Every message has one send and one receive sample in nanoseconds; a
//! message never received is [`MISSING`], and a received sequence never
//! sent invalidates the run (M-11).

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use karyos_io::backend::{
    Authority, Commit, Exposure, FlushRequest, GateDecision, InstanceId, RxBackend, RxDatagram,
    RxDrop, RxHandler, RxStop, SenderGate, SenderToken, TxBackend, TxFrame, TxOptions,
    TxQueueConfig, TxReport,
};
use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
use karyos_protocol::protection::{Protection, Verdict};
use karyos_protocol::sizing::TermLength;
use karyos_sys::receive::{ImageParams, ValidatedDatagram};

use crate::manifest::{MtuRule, Shape};
use crate::samples::MISSING;
use crate::wire::compose::{IDENTITY, Template, sequence_of};
use crate::wire::load::Schedule;
use crate::workloads::BenchError;

/// How long the receiver waits for traffic after the sender finishes.
const DRAIN: Duration = Duration::from_millis(500);

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
}

/// The samples of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageSamples {
    /// Send stage per measured message, ns.
    pub send: Vec<u32>,
    /// Receive stage per measured message, ns; [`MISSING`] when lost.
    pub receive: Vec<u32>,
    /// The size of the receive batches, one entry per poll that delivered.
    pub batches: Vec<u32>,
    /// Drops the backend reported.
    pub backend_drops: u64,
    /// Always `true` for this module: the two roles share a process, so
    /// the result is functional only (E4) whatever the host.
    pub functional_only: bool,
    /// The local address of the receiving endpoint.
    pub receiver: SocketAddr,
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

/// Nanoseconds as a sample, saturating below [`MISSING`].
fn ns(duration: Duration) -> u32 {
    u32::try_from(duration.as_nanos())
        .unwrap_or(MISSING - 1)
        .min(MISSING - 1)
}

/// The receiver: decides every datagram and timestamps each message.
struct Receiver<'p, P: Protection> {
    protection: &'p P,
    params: ImageParams,
    per_message: usize,
    first_sequence: u64,
    /// Per measured message: (stage start, datagrams seen, done).
    started: Vec<Option<Instant>>,
    seen: Vec<u32>,
    receive: Vec<u32>,
    batch_start: Option<Instant>,
    batch_len: u32,
    orphan: Option<u64>,
    invalid: u64,
    drops: u64,
    batches: Vec<u32>,
    received: Arc<AtomicU64>,
}

impl<P: Protection> RxHandler for Receiver<'_, P> {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        let start = *self.batch_start.get_or_insert_with(Instant::now);
        self.batch_len = self.batch_len.saturating_add(1);
        let bytes = datagram.bytes();
        let frames = match self.protection.open(bytes) {
            Verdict::Accept { frames } => bytes.get(..frames),
            Verdict::Reject(_) => None,
        };
        let Some(frames) = frames.filter(|f| ValidatedDatagram::parse(f, &self.params).is_ok())
        else {
            self.invalid = self.invalid.saturating_add(1);
            return ControlFlow::Continue(());
        };
        let decided = Instant::now();
        let Some(sequence) = sequence_of(frames) else {
            self.invalid = self.invalid.saturating_add(1);
            return ControlFlow::Continue(());
        };
        self.received
            .fetch_max(sequence.saturating_add(1), Ordering::Release);
        let Some(index) = sequence.checked_sub(self.first_sequence) else {
            return ControlFlow::Continue(()); // a warmup message
        };
        let Some(index) = usize::try_from(index)
            .ok()
            .filter(|i| *i < self.receive.len())
        else {
            self.orphan.get_or_insert(sequence);
            return ControlFlow::Continue(());
        };
        if let (Some(started), Some(seen), Some(sample)) = (
            self.started.get_mut(index),
            self.seen.get_mut(index),
            self.receive.get_mut(index),
        ) {
            let first = *started.get_or_insert(start);
            *seen = seen.saturating_add(1);
            if usize::try_from(*seen).is_ok_and(|seen| seen == self.per_message) {
                *sample = ns(decided.saturating_duration_since(first));
            }
        }
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _drop: RxDrop) {
        self.drops = self.drops.saturating_add(1);
    }
}

fn endpoint(max_datagram: u32) -> Result<SocketsEndpoint<OsSocket>, BenchError> {
    let mut config = SocketsConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    config.max_datagram = u16::try_from(max_datagram)
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| BenchError(format!("max datagram {max_datagram}")))?;
    SocketsEndpoint::open(&config, InstanceId::FIRST, OsSocket::new())
        .map_err(|error| BenchError(format!("open endpoint: {error:?}")))
}

/// Runs one wire run with `protection` on both sides.
///
/// # Errors
///
/// A template, endpoint, route or queue error, a failed half, an orphan
/// sequence (M-11) or a datagram the receiver rejected.
pub fn run<P: Protection + Sync>(
    run: StageRun,
    protection: &P,
) -> Result<StageSamples, BenchError> {
    let envelope = protection.envelope_len();
    let template = Template::new(
        run.shape,
        run.e_max,
        u32::try_from(envelope).map_err(|_| BenchError("envelope length".into()))?,
        run.rule,
    )?;
    let max_datagram = u32::try_from(template.len())
        .ok()
        .and_then(|len| len.checked_add(u32::try_from(envelope).ok()?))
        .ok_or_else(|| BenchError("datagram length overflow".into()))?
        .max(template.size.mtu);
    let (mut tx, _tx_rx) = endpoint(max_datagram)?
        .split()
        .map_err(|_| BenchError("split sender".into()))?;
    let receiving = endpoint(max_datagram)?;
    let receiver_address = receiving.capabilities().local;
    let (_rx_tx, mut rx) = receiving
        .split()
        .map_err(|_| BenchError("split receiver".into()))?;
    let route = tx
        .add_route(receiver_address)
        .map_err(|error| BenchError(format!("route: {error:?}")))?;
    let queue = tx
        .open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route,
            max_pending: NonZeroU16::new(64).unwrap_or(NonZeroU16::MIN),
        })
        .map_err(|error| BenchError(format!("queue: {error:?}")))?;
    let total = run
        .warmup
        .checked_add(run.messages)
        .ok_or_else(|| BenchError("message count overflow".into()))?;
    let measured =
        usize::try_from(run.messages).map_err(|_| BenchError("too many messages".into()))?;
    let term_length =
        TermLength::try_new(64 * 1024).map_err(|error| BenchError(format!("term: {error}")))?;
    let params = ImageParams::new(
        IDENTITY.session_id,
        IDENTITY.stream_id,
        1,
        term_length,
        max_datagram,
    )
    .map_err(|error| BenchError(format!("image: {error:?}")))?;
    let received = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let per_message = template.datagrams();
    let mut receiver = Receiver {
        protection,
        params,
        per_message,
        first_sequence: run.warmup,
        started: vec![None; measured],
        seen: vec![0; measured],
        receive: vec![MISSING; measured],
        batch_start: None,
        batch_len: 0,
        orphan: None,
        invalid: 0,
        drops: 0,
        batches: Vec::new(),
        received: Arc::clone(&received),
    };
    let budget = SocketsConfig::new(receiver_address)
        .rx_budget()
        .ok_or_else(|| BenchError("rx budget".into()))?;
    let mut send = vec![MISSING; measured];
    let received_samples =
        thread::scope(|scope| -> Result<(Vec<u32>, Vec<u32>, u64), BenchError> {
            let rx_done = Arc::clone(&done);
            let receiving =
                scope.spawn(move || -> Result<(Vec<u32>, Vec<u32>, u64), BenchError> {
                    let mut idle_since: Option<Instant> = None;
                    loop {
                        receiver.batch_start = None;
                        receiver.batch_len = 0;
                        let outcome = rx.poll_rx(budget, &mut receiver);
                        if receiver.batch_len > 0 {
                            receiver.batches.push(receiver.batch_len);
                            idle_since = None;
                        }
                        match outcome.stop {
                            RxStop::WouldBlock | RxStop::NoBuffers | RxStop::Interrupted => {
                                if rx_done.load(Ordering::Acquire) {
                                    let since = *idle_since.get_or_insert_with(Instant::now);
                                    if since.elapsed() >= DRAIN {
                                        break;
                                    }
                                }
                                thread::yield_now();
                            }
                            RxStop::Budget | RxStop::HandlerStopped => {}
                            RxStop::Failed(failure) => {
                                return Err(BenchError(format!(
                                    "receive half failed: {failure:?}"
                                )));
                            }
                        }
                    }
                    if let Some(sequence) = receiver.orphan {
                        return Err(BenchError(format!("orphan sequence {sequence} (M-11)")));
                    }
                    if receiver.invalid > 0 {
                        return Err(BenchError(format!(
                            "{} datagrams rejected by the receiver",
                            receiver.invalid
                        )));
                    }
                    Ok((receiver.receive, receiver.batches, receiver.drops))
                });
            let mut message = vec![0_u8; template.len()];
            let mut buffer = vec![0_u8; template.len() + envelope + 64];
            let mut report = TxReport::new();
            let schedule = match run.load {
                StageLoad::Open { rate } => Some(Schedule::new(Instant::now(), rate)?),
                StageLoad::Closed => None,
            };
            let sending = (|| -> Result<(), BenchError> {
                for sequence in 0..total {
                    if let Some(schedule) = &schedule {
                        let at = schedule.instant(sequence)?;
                        while Instant::now() < at {
                            std::hint::spin_loop();
                        }
                    }
                    template.stamp(sequence, &mut message)?;
                    let begin = Instant::now();
                    for index in 0..per_message {
                        let frames = template
                            .datagram(&message, index)
                            .ok_or_else(|| BenchError("datagram index".into()))?;
                        let slot = buffer
                            .get_mut(..frames.len() + envelope)
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
                    let committed = Instant::now();
                    if let Some(index) = sequence
                        .checked_sub(run.warmup)
                        .and_then(|i| usize::try_from(i).ok())
                        && let Some(sample) = send.get_mut(index)
                    {
                        *sample = ns(committed.saturating_duration_since(begin));
                    }
                    let _ = tx.flush(
                        FlushRequest {
                            queue,
                            max_datagrams: NonZeroU16::new(64).unwrap_or(NonZeroU16::MIN),
                            max_bytes: u32::MAX,
                        },
                        &mut Open,
                        &mut report,
                    );
                    while report.pop_front().is_some() {}
                    if run.load == StageLoad::Closed {
                        let start = Instant::now();
                        while received.load(Ordering::Acquire) <= sequence
                            && start.elapsed() < Duration::from_secs(1)
                        {
                            std::hint::spin_loop();
                        }
                    }
                }
                Ok(())
            })();
            done.store(true, Ordering::Release);
            let received = receiving
                .join()
                .map_err(|_| BenchError("receiver thread panicked".into()))?;
            sending?;
            received
        })?;
    let (receive, batches, backend_drops) = received_samples;
    Ok(StageSamples {
        send,
        receive,
        batches,
        backend_drops,
        functional_only: true,
        receiver: receiver_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ExtBase, ILLUSTRATIVE_E_MAX};
    use karyos_protocol::protection::Trusted;

    fn smoke(shape: Shape, load: StageLoad) -> StageSamples {
        run(
            StageRun {
                shape,
                e_max: ILLUSTRATIVE_E_MAX,
                rule: MtuRule::CountsEnvelope,
                load,
                messages: 200,
                warmup: 20,
            },
            &Trusted,
        )
        .unwrap_or_else(|error| panic!("{shape} {load:?}: {error}"))
    }

    #[test]
    fn every_shape_runs_closed_loop_over_loopback() {
        for shape in [
            Shape::W1,
            Shape::W2,
            Shape::W3,
            Shape::W4,
            Shape::W5,
            Shape::W6,
            Shape::W7,
            Shape::W9(ExtBase::W1),
            Shape::W9(ExtBase::W4),
        ] {
            let samples = smoke(shape, StageLoad::Closed);
            assert_eq!(samples.send.len(), 200);
            assert!(samples.send.iter().all(|s| *s != MISSING), "{shape}");
            let lost = samples.receive.iter().filter(|s| **s == MISSING).count();
            assert_eq!(lost, 0, "{shape}: {lost} lost in closed loop");
            assert!(samples.functional_only);
        }
    }

    #[test]
    fn an_open_loop_run_records_every_message() {
        let samples = smoke(Shape::W1, StageLoad::Open { rate: 20_000 });
        assert_eq!(samples.receive.len(), 200);
        assert!(!samples.batches.is_empty());
    }
}
