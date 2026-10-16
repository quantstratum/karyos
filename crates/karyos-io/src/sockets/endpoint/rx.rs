// SPDX-License-Identifier: Apache-2.0

//! The RX state of one endpoint and `poll_rx` (`quantstratum-docs:
//! karyos/design/sockets-backend.md` 3.7, 4.4 and 4.7).
//!
//! One buffer of `max_datagram + 1` bytes, owned by the half. The kernel
//! writes it only during the receive call, while the half holds the only
//! reference; the handler then gets a shared borrow that ends when it
//! returns. No state of the half changes while the borrow is live, so a
//! panicking handler leaves nothing to restore.

use karyos_sys::host_clock::host_monotonic_ns;

use super::State;
use super::config::SocketsConfig;
use crate::backend::{
    BackendEpoch, BackendFailure, Budget, ClockDomain, ClockEpoch, InstanceId, Observation,
    ObservationPoint, OpenError, PathId, RxDatagram, RxDrop, RxDropReason, RxHandler, RxOutcome,
    RxStop, Spent,
};
use crate::sockets::ops::{Errno, RecvResult, SocketOps};

/// The operation named in receive failures.
const RECV: &str = "recv";

/// The `uncertainty_ns` of every `RecvReturn` observation: a placeholder of
/// 1 ns, equal to the snapshot's `clock.granularity_ns`, until S3 probes
/// the host clock's reading granularity.
const OBSERVATION_UNCERTAINTY_NS: u64 = 1;

/// The RX half's state; `SocketsRx` adds the duplicated socket.
#[derive(Debug)]
pub(super) struct RxCore {
    pub(super) instance: InstanceId,
    pub(super) epoch: BackendEpoch,
    pub(super) state: State,
    max_datagram: u16,
    path: PathId,
    observe: bool,
    clock_epoch: ClockEpoch,
    buffer: Box<[u8]>,
    peer_errors: u64,
    /// The failure that stopped the half (3.10): every later poll returns
    /// it with no system call until `reset` and `reopen`.
    failed: Option<BackendFailure>,
}

impl RxCore {
    /// Allocates the receive buffer for a validated configuration.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` for `max_datagram` when the buffer length
    /// does not fit `usize`, which a validated configuration never gives.
    pub(super) fn new(
        config: &SocketsConfig,
        instance: InstanceId,
        epoch: BackendEpoch,
    ) -> Result<Self, OpenError> {
        let max_datagram = config.max_datagram.get();
        let len = usize::from(max_datagram)
            .checked_add(1)
            .ok_or(OpenError::InvalidConfig {
                field: "max_datagram",
                value: u64::from(max_datagram),
            })?;
        Ok(Self {
            instance,
            epoch,
            state: State::Active,
            max_datagram,
            path: config.path,
            observe: config.rx_observation,
            clock_epoch: config.clock_epoch,
            buffer: vec![0; len].into_boxed_slice(),
            peer_errors: 0,
            failed: None,
        })
    }

    /// Moves to the new epoch of `reopen`; `max_datagram` is unchanged and
    /// a failure that stopped the half is cleared.
    pub(super) fn reopen(&mut self, config: &SocketsConfig, epoch: BackendEpoch) {
        self.epoch = epoch;
        self.state = State::Active;
        self.path = config.path;
        self.observe = config.rx_observation;
        self.clock_epoch = config.clock_epoch;
        self.failed = None;
    }

    /// `ECONNREFUSED` results of receive calls (4.7).
    pub(super) fn peer_errors(&self) -> u64 {
        self.peer_errors
    }

    /// Whether the rest of `budget` admits one whole datagram: one op, one
    /// datagram and `max_datagram` bytes (4.4).
    fn admits(&self, budget: Budget, spent: Spent) -> bool {
        spent.ops < budget.ops()
            && spent.datagrams < budget.datagrams()
            && budget
                .bytes()
                .checked_sub(spent.bytes)
                .is_some_and(|rest| rest >= u64::from(self.max_datagram))
    }

    /// Stops the half with `failure` (3.10) and returns `outcome` with it.
    fn fail(&mut self, mut outcome: RxOutcome, failure: BackendFailure) -> RxOutcome {
        self.failed = Some(failure);
        outcome.stop = RxStop::Failed(failure);
        outcome
    }

    /// Receives within `budget`, lending each datagram to `handler`.
    ///
    /// Every count is checked. The op and datagram counts of a call are
    /// computed before it, so a budget that cannot take them stops with
    /// `Budget` and no call; a count that cannot grow after a call is an
    /// invariant fault, which stops the half like any `Failed`.
    pub(super) fn poll_rx<O: SocketOps, H: RxHandler>(
        &mut self,
        ops: &mut O,
        budget: Budget,
        handler: &mut H,
    ) -> RxOutcome {
        let mut outcome = RxOutcome {
            delivered: 0,
            dropped: 0,
            spent: Spent::default(),
            stop: RxStop::Budget,
        };
        if self.state != State::Active {
            outcome.stop = RxStop::Failed(BackendFailure::NotActive);
            return outcome;
        }
        if let Some(failure) = self.failed {
            outcome.stop = RxStop::Failed(failure);
            return outcome;
        }
        let invariant = BackendFailure::Invariant { operation: RECV };
        loop {
            let next = (
                outcome.spent.ops.checked_add(1),
                outcome.spent.datagrams.checked_add(1),
            );
            let (true, (Some(next_ops), Some(next_datagrams))) =
                (self.admits(budget, outcome.spent), next)
            else {
                outcome.stop = RxStop::Budget;
                return outcome;
            };
            let result = ops.recv(&mut self.buffer);
            let time_ns = self.observe.then(host_monotonic_ns);
            outcome.spent.ops = next_ops;
            let (len, truncated, source) = match result {
                RecvResult::Datagram {
                    len,
                    truncated,
                    source,
                } => (len, truncated, source),
                RecvResult::Error(errno) => match self.classify(errno) {
                    Some(RxStop::Failed(failure)) => return self.fail(outcome, failure),
                    Some(stop) => {
                        outcome.stop = stop;
                        return outcome;
                    }
                    None => continue,
                },
            };
            if len > self.buffer.len() {
                return self.fail(outcome, invariant);
            }
            outcome.spent.datagrams = next_datagrams;
            let reason = if truncated.is_some() || len > usize::from(self.max_datagram) {
                Some(RxDropReason::Oversize {
                    limit: self.max_datagram,
                    received: truncated,
                })
            } else if source.is_none() {
                Some(RxDropReason::UnsupportedSource)
            } else {
                None
            };
            let (None, Some(source)) = (reason, source) else {
                let Some(dropped) = outcome.dropped.checked_add(1) else {
                    return self.fail(outcome, invariant);
                };
                outcome.dropped = dropped;
                handler.dropped(RxDrop {
                    reason: reason.unwrap_or(RxDropReason::UnsupportedSource),
                    source,
                });
                continue;
            };
            let bytes = u64::try_from(len)
                .ok()
                .and_then(|len| outcome.spent.bytes.checked_add(len));
            let (Some(bytes), Some(delivered), Some(datagram)) = (
                bytes,
                outcome.delivered.checked_add(1),
                self.buffer.get(..len),
            ) else {
                return self.fail(outcome, invariant);
            };
            outcome.spent.bytes = bytes;
            outcome.delivered = delivered;
            let observation = time_ns.map(|time_ns| Observation {
                point: ObservationPoint::RecvReturn,
                domain: ClockDomain::HostMonotonic,
                epoch: self.clock_epoch,
                time_ns,
                uncertainty_ns: OBSERVATION_UNCERTAINTY_NS,
            });
            let datagram = RxDatagram::new(datagram, source, self.path, self.epoch, observation);
            if handler.datagram(datagram).is_break() {
                outcome.stop = RxStop::HandlerStopped;
                return outcome;
            }
        }
    }

    /// The receive column of 4.7: the stop, or `None` to continue.
    fn classify(&mut self, errno: Errno) -> Option<RxStop> {
        match errno {
            Errno::AGAIN => Some(RxStop::WouldBlock),
            Errno::INTR => Some(RxStop::Interrupted),
            Errno::NOBUFS | Errno::NOMEM => Some(RxStop::NoBuffers),
            Errno::CONNREFUSED => {
                count_up(&mut self.peer_errors);
                None
            }
            _ => Some(RxStop::Failed(BackendFailure::Os {
                operation: RECV,
                errno: errno.raw(),
            })),
        }
    }
}

/// Adds one to a monitoring counter of system call results, checked. The
/// documented choice for overflow: the counter keeps its value, which can
/// then only be `u64::MAX`, a count one op per call cannot reach in
/// practice. Never used for a position, length or budget count.
pub(super) fn count_up(counter: &mut u64) {
    if let Some(next) = counter.checked_add(1) {
        *counter = next;
    }
}
