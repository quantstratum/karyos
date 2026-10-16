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
    ObservationPoint, PathId, RxDatagram, RxDrop, RxDropReason, RxHandler, RxOutcome, RxStop,
    Spent,
};
use crate::sockets::ops::{Errno, RecvResult, SocketOps};

/// The operation named in receive failures.
const RECV: &str = "recv";

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
}

impl RxCore {
    /// Allocates the receive buffer for a validated configuration.
    pub(super) fn new(config: &SocketsConfig, instance: InstanceId, epoch: BackendEpoch) -> Self {
        let max_datagram = config.max_datagram.get();
        Self {
            instance,
            epoch,
            state: State::Active,
            max_datagram,
            path: config.path,
            observe: config.rx_observation,
            clock_epoch: config.clock_epoch,
            buffer: vec![0; usize::from(max_datagram).saturating_add(1)].into_boxed_slice(),
            peer_errors: 0,
        }
    }

    /// Moves to the new epoch of `reopen`; `max_datagram` is unchanged.
    pub(super) fn reopen(&mut self, config: &SocketsConfig, epoch: BackendEpoch) {
        self.epoch = epoch;
        self.state = State::Active;
        self.path = config.path;
        self.observe = config.rx_observation;
        self.clock_epoch = config.clock_epoch;
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
            && budget.bytes().saturating_sub(spent.bytes) >= u64::from(self.max_datagram)
    }

    /// Receives within `budget`, lending each datagram to `handler`.
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
        loop {
            if !self.admits(budget, outcome.spent) {
                outcome.stop = RxStop::Budget;
                return outcome;
            }
            let result = ops.recv(&mut self.buffer);
            let time_ns = self.observe.then(host_monotonic_ns);
            outcome.spent.ops = outcome.spent.ops.saturating_add(1);
            let (len, truncated, source) = match result {
                RecvResult::Datagram {
                    len,
                    truncated,
                    source,
                } => (len, truncated, source),
                RecvResult::Error(errno) => match self.classify(errno) {
                    Some(stop) => {
                        outcome.stop = stop;
                        return outcome;
                    }
                    None => continue,
                },
            };
            if len > self.buffer.len() {
                outcome.stop = RxStop::Failed(BackendFailure::Invariant { operation: RECV });
                return outcome;
            }
            outcome.spent.datagrams = outcome.spent.datagrams.saturating_add(1);
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
                outcome.dropped = outcome.dropped.saturating_add(1);
                handler.dropped(RxDrop {
                    reason: reason.unwrap_or(RxDropReason::UnsupportedSource),
                    source,
                });
                continue;
            };
            outcome.spent.bytes = outcome
                .spent
                .bytes
                .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
            outcome.delivered = outcome.delivered.saturating_add(1);
            let observation = time_ns.map(|time_ns| Observation {
                point: ObservationPoint::RecvReturn,
                domain: ClockDomain::HostMonotonic,
                epoch: self.clock_epoch,
                time_ns,
                uncertainty_ns: 1,
            });
            let bytes = self.buffer.get(..len).unwrap_or_default();
            let datagram = RxDatagram::new(bytes, source, self.path, self.epoch, observation);
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
                self.peer_errors = self.peer_errors.saturating_add(1);
                None
            }
            _ => Some(RxStop::Failed(BackendFailure::Os {
                operation: RECV,
                errno: errno.raw(),
            })),
        }
    }
}
