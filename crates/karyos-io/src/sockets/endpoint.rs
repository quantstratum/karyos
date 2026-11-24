// SPDX-License-Identifier: Apache-2.0

//! The sockets endpoint state machine over the [`SocketOps`] seam
//! (`quantstratum-docs: karyos/design/sockets-backend.md` 3.3 to 3.10,
//! sections 5 to 7).
//!
//! [`SocketsEndpoint::open`] validates the configuration, creates the
//! socket through [`SocketOps::open`] and allocates every pool and table;
//! nothing later allocates. The control path holds the joined endpoint and
//! [`split`](SocketsEndpoint::split)s it into a [`SocketsTx`] and a
//! [`SocketsRx`] on duplicated descriptors (decision O-9, S-18); socket
//! state changes only while the halves are [`join`](SocketsEndpoint::join)ed
//! again: [`reset`](SocketsEndpoint::reset),
//! [`reopen`](SocketsEndpoint::reopen) and
//! [`retire`](SocketsEndpoint::retire).
//!
//! No item of this module performs a system call itself; every one goes
//! through `O`.

mod config;
mod rx;
mod tx;

#[cfg(test)]
mod tests;

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

pub use config::{
    BufferSize, CapabilitySet, CapabilitySnapshot, ClockInfo, CopyMode, DEFAULT_MAX_BATCH,
    DEFAULT_MAX_DATAGRAM, DEFAULT_MAX_QUEUES, DEFAULT_MAX_ROUTES, DEFAULT_MEMORY_CAP,
    DEFAULT_MULTICAST_TTL, DEFAULT_RECV_BUFFER, DEFAULT_RX_BUDGET_DATAGRAMS, DEFAULT_SEND_BUFFER,
    DEFAULT_TX_SLOTS, InterfaceSel, MAX_BUFFER_REQUEST, MAX_DATAGRAM, MAX_TABLE_ENTRIES,
    MAX_TX_SLOTS, MIN_DATAGRAM, Membership, MulticastConfig, ObservationPoints, Platform,
    Protection, QueueAssignment, SOCKETS_MAX_BATCH, SocketsConfig,
};
pub use tx::{EtfDrainError, RouteInfo, SocketsFrame, TxCommitment};

use self::rx::RxCore;
use self::tx::TxCore;
use super::errqueue::ErrEntry;
use super::ops::{SocketOps, SocketProbes};
use crate::backend::{
    BackendEpoch, Budget, CancelOutcome, CapabilityState, ClaimError, CompletionHandler,
    CompletionOutcome, FlushOutcome, FlushRequest, InstanceId, OpenError, QueueError, RouteError,
    RouteId, RxBackend, RxHandler, RxOutcome, SenderGate, TxBackend, TxQueueConfig, TxQueueId,
    TxReport, TxTicket,
};

/// Pending items discarded by a TX half dropped outside unwinding
/// (decision S-19), over the process. A driver bug, counted and never a
/// panic (karyos#880).
static TX_DISCARDED_ON_DROP: AtomicU64 = AtomicU64::new(0);

/// Pending items discarded by TX halves dropped outside unwinding, over the
/// process: the `tx_discarded_on_drop` counter of section 7.4. Nonzero only
/// after a driver bug.
#[must_use]
pub fn tx_discarded_on_drop() -> u64 {
    TX_DISCARDED_ON_DROP.load(Ordering::Relaxed)
}

#[cfg(test)]
std::thread_local! {
    /// Drops counted by [`TX_DISCARDED_ON_DROP`] on this thread, so a test
    /// observes its own drops and not those of tests running in parallel.
    static TX_DROPS_ON_THIS_THREAD: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Drops outside unwinding with pending items on the calling thread.
#[cfg(test)]
pub(crate) fn tx_drops_on_this_thread() -> u64 {
    TX_DROPS_ON_THIS_THREAD.with(std::cell::Cell::get)
}

/// Records a drop outside unwinding with pending items on this thread.
#[cfg(test)]
pub(crate) fn note_tx_drop_on_this_thread() {
    TX_DROPS_ON_THIS_THREAD.with(|drops| drops.set(drops.get().wrapping_add(1)));
}

/// The life of an endpoint (7.3 and 7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Claims, commits, flushes and receives run.
    Active,
    /// `reset` is returning pending items; nothing else runs.
    Resetting,
    /// `retire` is returning pending items; nothing else runs.
    Retiring,
    /// The reset finished and the socket is closed; `reopen` follows.
    Closed,
    /// Final.
    Retired,
}

/// The result of one [`SocketsEndpoint::reset`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetOutcome {
    /// Items returned in the report with `ReturnReason::Reset`.
    pub returned: u16,
    /// Whether pending items remain: empty the report and call again.
    pub more: bool,
    /// The report still held entries; nothing changed.
    pub report_not_empty: bool,
}

/// The result of one [`SocketsEndpoint::retire`] call (7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retired {
    /// Items were returned and more remain; empty the report and call
    /// again.
    More {
        /// Items returned in the report.
        returned: u16,
    },
    /// Every item is returned and the socket is closed. Final.
    Complete {
        /// Items returned in the report by this call.
        returned: u16,
    },
    /// The report still held entries; nothing changed.
    ReportNotEmpty,
    /// A `reset` is still returning items (`ResetOutcome::more` was true);
    /// nothing changed.
    ResetIncomplete,
}

/// `join` refused halves of different instances or epochs; both come back.
pub struct JoinError<O: SocketOps> {
    /// The TX half, unchanged.
    pub tx: SocketsTx<O>,
    /// The RX half, unchanged.
    pub rx: SocketsRx<O>,
}

impl<O: SocketOps> fmt::Debug for JoinError<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinError")
            .field("tx_instance", &self.tx.core.instance)
            .field("tx_epoch", &self.tx.core.epoch)
            .field("rx_instance", &self.rx.core.instance)
            .field("rx_epoch", &self.rx.core.epoch)
            .finish()
    }
}

impl<O: SocketOps> fmt::Display for JoinError<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("halves of different endpoint instances or epochs")
    }
}

impl<O: SocketOps> std::error::Error for JoinError<O> {}

/// Why [`SocketsEndpoint::split`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SplitFailure {
    /// A reset finished and the socket is closed: `reopen` first.
    #[error("the endpoint is closed; reopen it before splitting")]
    Closed,
    /// The endpoint is retired.
    #[error("the endpoint is retired")]
    Retired,
    /// The descriptor could not be duplicated (`EMFILE`, `ENOMEM`, ...).
    #[error("dup failed with os error {errno}")]
    Os {
        /// Raw OS error number.
        errno: i32,
    },
}

/// `split` refused; the endpoint comes back unchanged, pending items and
/// socket included, mirroring [`JoinError`].
pub struct SplitError<O: SocketOps> {
    /// The endpoint, unchanged.
    pub endpoint: SocketsEndpoint<O>,
    /// Why the split was refused.
    pub error: SplitFailure,
}

impl<O: SocketOps> fmt::Debug for SplitError<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitError")
            .field("endpoint", &self.endpoint)
            .field("error", &self.error)
            .finish()
    }
}

impl<O: SocketOps> fmt::Display for SplitError<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl<O: SocketOps> std::error::Error for SplitError<O> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Whether the sends of an epoch are one `sendmmsg` each (4.3): the rule
/// [`SocketOps::send`] documents and `Spent::ops` counts by.
fn batched(probes: &SocketProbes) -> bool {
    probes.tx_batch == CapabilityState::Active
}

/// The joined endpoint, held by the control path (3.8, 3.10).
pub struct SocketsEndpoint<O: SocketOps> {
    tx: TxCore,
    rx: RxCore,
    ops: O,
    snapshot: CapabilitySnapshot,
}

impl<O: SocketOps> fmt::Debug for SocketsEndpoint<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketsEndpoint")
            .field("state", &self.tx.state)
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

impl<O: SocketOps> SocketsEndpoint<O> {
    /// Validates `config`, creates and configures the socket through `ops`,
    /// checks the required capabilities and allocates every pool. A failure
    /// returns no partial endpoint: the socket is closed (7.4).
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::InvalidConfig`] or
    /// [`OpenError::ProtectionUnavailable`] for the configuration, the
    /// error of [`SocketOps::open`], or [`OpenError::RequiredCapability`].
    pub fn open(
        config: &SocketsConfig,
        instance: InstanceId,
        mut ops: O,
    ) -> Result<Self, OpenError> {
        config.validate()?;
        let epoch = BackendEpoch::FIRST;
        let probes = ops.open(config)?;
        let snapshot = CapabilitySnapshot::build(config, instance, epoch, &probes);
        if let Err(error) = snapshot.check_required(config.require) {
            ops.close();
            return Err(error);
        }
        // A failure here drops `ops`, which closes the socket (SocketOps).
        Ok(Self {
            tx: TxCore::new(config, instance, epoch, batched(&probes))?,
            rx: RxCore::new(config, instance, epoch)?,
            ops,
            snapshot,
        })
    }

    /// The capability snapshot of the current epoch.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilitySnapshot {
        &self.snapshot
    }

    fn set_state(&mut self, state: State) {
        self.tx.state = state;
        self.rx.state = state;
    }

    /// Duplicates the descriptor and splits the endpoint into its TX and
    /// RX halves (3.10). Each half keeps its state and the snapshot of its
    /// epoch. An endpoint still resetting or retiring splits, so its
    /// halves can be handed back; their data calls return `NotActive`.
    ///
    /// # Errors
    ///
    /// Returns [`SplitError`] with the endpoint, unchanged: with
    /// [`SplitFailure::Closed`] after a finished reset and
    /// [`SplitFailure::Retired`] after retirement, both before any system
    /// call, or [`SplitFailure::Os`] when the descriptor cannot be
    /// duplicated. No pending item is lost and the socket stays open.
    #[expect(
        clippy::result_large_err,
        reason = "the endpoint comes back by value, like the halves of JoinError; split is a cold control path call"
    )]
    pub fn split(self) -> Result<(SocketsTx<O>, SocketsRx<O>), SplitError<O>> {
        let refused = match self.tx.state {
            State::Closed => Some(SplitFailure::Closed),
            State::Retired => Some(SplitFailure::Retired),
            State::Active | State::Resetting | State::Retiring => None,
        };
        if let Some(error) = refused {
            return Err(SplitError {
                endpoint: self,
                error,
            });
        }
        let duplicate = match self.ops.try_clone() {
            Ok(duplicate) => duplicate,
            Err(errno) => {
                return Err(SplitError {
                    endpoint: self,
                    error: SplitFailure::Os { errno: errno.raw() },
                });
            }
        };
        let tx = SocketsTx {
            core: self.tx,
            ops: self.ops,
            snapshot: self.snapshot,
            not_sync: PhantomData,
        };
        let rx = SocketsRx {
            core: self.rx,
            ops: duplicate,
            snapshot: self.snapshot,
            not_sync: PhantomData,
        };
        Ok((tx, rx))
    }

    /// Joins the halves of one endpoint: the RX half's duplicate
    /// descriptor is closed.
    ///
    /// # Errors
    ///
    /// Returns [`JoinError`] with both halves, unchanged, when they belong
    /// to different instances or epochs.
    #[expect(
        clippy::result_large_err,
        reason = "the halves come back by value as section 3.8 specifies; join is a cold control path call"
    )]
    pub fn join(tx: SocketsTx<O>, rx: SocketsRx<O>) -> Result<Self, JoinError<O>> {
        if tx.core.instance != rx.core.instance || tx.core.epoch != rx.core.epoch {
            return Err(JoinError { tx, rx });
        }
        let SocketsRx {
            core: rx_core,
            ops: mut duplicate,
            ..
        } = rx;
        duplicate.close();
        drop(duplicate);
        Ok(Self {
            tx: tx.core,
            rx: rx_core,
            ops: tx.ops,
            snapshot: tx.snapshot,
        })
    }

    /// Returns pending items with `ReturnReason::Reset`, up to the report
    /// capacity per call; call until `more` is false (7.3). The first call
    /// stops claims, commits, flushes and receives. Once nothing is
    /// pending it closes every queue, invalidates every route, frees
    /// quarantined slots and closes the socket. Refuses a non-empty report
    /// before any change.
    pub fn reset(&mut self, report: &mut TxReport) -> ResetOutcome {
        let state = self.tx.state;
        let finished = matches!(state, State::Closed | State::Retired);
        let Some(mut writer) = report.writer() else {
            return ResetOutcome {
                returned: 0,
                more: !finished,
                report_not_empty: true,
            };
        };
        if finished {
            return ResetOutcome {
                returned: 0,
                more: false,
                report_not_empty: false,
            };
        }
        // A retirement in progress keeps its final state.
        let (draining, target) = if state == State::Retiring {
            (State::Retiring, State::Retired)
        } else {
            (State::Resetting, State::Closed)
        };
        self.set_state(draining);
        let (returned, more) = self.tx.drain_all(&mut writer);
        if !more && self.tx.finish_reset() {
            self.ops.close();
            self.set_state(target);
        }
        ResetOutcome {
            returned,
            more,
            report_not_empty: false,
        }
    }

    /// Creates and configures a new socket after a finished reset,
    /// advances the epoch, probes again and publishes a new snapshot
    /// (7.3). The pool sizes are fixed for the instance; the other fields
    /// of `config` may change.
    ///
    /// **Deviation from 5.1**, which says storage is allocated by `open`
    /// "or `reopen`": this `reopen` allocates nothing. It requires a
    /// finished reset (state `Closed`), and it requires `max_datagram`,
    /// `tx_slots`, `max_queues` and `max_routes` equal to those of `open`,
    /// so the pools, tables and buffers of the instance are reused as they
    /// are. A different size needs a new endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::ResetIncomplete`] unless a reset finished,
    /// [`OpenError::Retired`] after retirement, the configuration errors of
    /// [`SocketsEndpoint::open`] (a changed pool size is `InvalidConfig`),
    /// [`OpenError::EpochExhausted`], the error of [`SocketOps::open`] or
    /// [`OpenError::RequiredCapability`]. A failure leaves the endpoint
    /// closed in its old epoch.
    pub fn reopen(&mut self, config: &SocketsConfig) -> Result<&CapabilitySnapshot, OpenError> {
        match self.tx.state {
            State::Closed => {}
            State::Retired => return Err(OpenError::Retired),
            State::Active | State::Resetting | State::Retiring => {
                return Err(OpenError::ResetIncomplete);
            }
        }
        config.validate()?;
        let fixed = self.tx.config;
        let sizes = [
            ("max_datagram", fixed.max_datagram, config.max_datagram),
            ("tx_slots", fixed.tx_slots, config.tx_slots),
            ("max_queues", fixed.max_queues, config.max_queues),
            ("max_routes", fixed.max_routes, config.max_routes),
        ];
        for (field, old, new) in sizes {
            if old != new {
                return Err(OpenError::InvalidConfig {
                    field,
                    value: u64::from(new.get()),
                });
            }
        }
        let epoch = self.tx.epoch.next()?;
        let probes = self.ops.open(config)?;
        let snapshot = CapabilitySnapshot::build(config, self.tx.instance, epoch, &probes);
        if let Err(error) = snapshot.check_required(config.require) {
            self.ops.close();
            return Err(error);
        }
        self.tx.reopen(config, epoch, batched(&probes));
        self.rx.reopen(config, epoch);
        self.snapshot = snapshot;
        Ok(&self.snapshot)
    }

    /// Returns pending items like [`reset`](Self::reset), one report at a
    /// time, then closes the socket: call until it returns
    /// [`Retired::Complete`] (7.4). Refuses a non-empty report, and a reset
    /// still in progress, before any change.
    pub fn retire(&mut self, report: &mut TxReport) -> Retired {
        let Some(mut writer) = report.writer() else {
            return Retired::ReportNotEmpty;
        };
        match self.tx.state {
            State::Resetting => Retired::ResetIncomplete,
            State::Retired => Retired::Complete { returned: 0 },
            State::Closed => {
                self.set_state(State::Retired);
                Retired::Complete { returned: 0 }
            }
            State::Active | State::Retiring => {
                self.set_state(State::Retiring);
                let (returned, more) = self.tx.drain_all(&mut writer);
                if more || !self.tx.finish_reset() {
                    return Retired::More { returned };
                }
                self.ops.close();
                self.set_state(State::Retired);
                Retired::Complete { returned }
            }
        }
    }

    /// Pending items over every queue; `None` if the total does not fit
    /// `usize`, which 1024 queues of `u16` counts rule out.
    #[must_use]
    pub fn pending(&self) -> Option<usize> {
        self.tx.pending_total()
    }
}

/// The TX half: the slot pool, queues, routes and the original descriptor.
/// One owning agent; `Send`, neither `Sync` nor `Clone` (3.10).
pub struct SocketsTx<O: SocketOps> {
    core: TxCore,
    ops: O,
    snapshot: CapabilitySnapshot,
    not_sync: PhantomData<Cell<()>>,
}

impl<O: SocketOps> fmt::Debug for SocketsTx<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketsTx")
            .field("instance", &self.core.instance)
            .field("epoch", &self.core.epoch)
            .field("state", &self.core.state)
            .finish_non_exhaustive()
    }
}

impl<O: SocketOps> SocketsTx<O> {
    /// What its open routes and queues take now: routes, queues and the
    /// slots committed to them (karyos#859). Read only; nothing allocates.
    #[must_use]
    pub fn commitment(&self) -> TxCommitment {
        self.core.commitment()
    }

    /// Adds a route to `destination`, measuring its MTU (3.8, 4.5).
    ///
    /// # Errors
    ///
    /// Returns a [`RouteError`], checked in this order: `NotActive`,
    /// `Unsupported` (unspecified address or port 0), `FamilyMismatch`,
    /// `RouteLimit`, then `PathTooSmall` for a measured MTU below the
    /// datagram and its headers or `PathUnverified` for an unmeasured one
    /// when [`crate::backend::Capability::PathMtu`] is required, then
    /// `IdentityExhausted`.
    pub fn add_route(&mut self, destination: SocketAddr) -> Result<RouteId, RouteError> {
        self.core.add_route(&mut self.ops, destination)
    }

    /// Removes `route`.
    ///
    /// # Errors
    ///
    /// Returns `NotActive`, `Unknown` for a removed or stale handle, or
    /// `InUse` while an open queue names it.
    pub fn remove_route(&mut self, route: RouteId) -> Result<(), RouteError> {
        self.core.remove_route(route)
    }

    /// The measurement of `route`.
    ///
    /// # Errors
    ///
    /// Returns `Unknown` for a removed or stale handle.
    pub fn route_info(&self, route: RouteId) -> Result<RouteInfo, RouteError> {
        self.core.route_info(route)
    }

    /// Opens a bounded FIFO queue of one authority and one route.
    ///
    /// # Errors
    ///
    /// Returns a [`QueueError`], checked in this order: `NotActive`,
    /// `RouteUnknown`, `EtfRefused` (an etf queue on an endpoint without
    /// [`SocketsConfig::etf_route`], or to a multicast destination),
    /// `QueueLimit`, `OverCommitted` (decision S-6), `IdentityExhausted`,
    /// then `EtfUnavailable` when the etf queue's socket cannot be set up
    /// (ADR-0109 points 2 and 5).
    pub fn open_queue(&mut self, config: TxQueueConfig) -> Result<TxQueueId, QueueError> {
        self.core.open_queue(&mut self.ops, config)
    }

    /// Drains up to `out.len()` entries of the error queue of etf queue
    /// `queue`'s socket without blocking (ADR-0109 points 6 and 7); returns
    /// how many it wrote. An [`ErrEntry::Txtime`] is a datagram the `etf`
    /// qdisc dropped, named by its send time, with its code.
    ///
    /// # Errors
    ///
    /// [`EtfDrainError::Queue`] with `NotActive`, `UnknownQueue`, or
    /// `EtfRefused` for a queue that is not an etf queue; the receive's
    /// errno otherwise.
    pub fn drain_etf(
        &mut self,
        queue: TxQueueId,
        out: &mut [ErrEntry],
    ) -> Result<usize, EtfDrainError> {
        self.core.drain_etf(&mut self.ops, queue, out)
    }

    /// Returns the pending items of `queue` with `QueueClosed`, up to the
    /// report capacity, then closes it; call again while `more` is true.
    /// Until then the queue takes no claim, commit or flush.
    ///
    /// # Errors
    ///
    /// Returns `ReportNotEmpty` before any change, then `NotActive` or
    /// `UnknownQueue`.
    pub fn close_queue(
        &mut self,
        queue: TxQueueId,
        report: &mut TxReport,
    ) -> Result<CancelOutcome, QueueError> {
        self.core.close_queue(&mut self.ops, queue, report)
    }

    /// Clears a send fault; the head is attempted again at the next flush.
    ///
    /// # Errors
    ///
    /// Returns `NotActive`, `UnknownQueue`, or `NeedsReset` for a queue
    /// faulted by an invariant violation (S-16).
    pub fn retry_queue(&mut self, queue: TxQueueId) -> Result<(), QueueError> {
        self.core.retry_queue(queue)
    }

    /// Whether `ticket` names an item pending now. A ticket of another
    /// instance, epoch or slot generation resolves to nothing.
    #[must_use]
    pub fn is_pending(&self, ticket: TxTicket) -> bool {
        self.core.is_pending(ticket)
    }

    /// Pending items over every queue; `None` if the total does not fit
    /// `usize`, which 1024 queues of `u16` counts rule out.
    #[must_use]
    pub fn pending(&self) -> Option<usize> {
        self.core.pending_total()
    }

    /// `ECONNREFUSED` results of send calls: counted, never submitted.
    #[must_use]
    pub fn peer_errors(&self) -> u64 {
        self.core.peer_errors()
    }

    /// Increments of this half's counters that would have overflowed and
    /// were not applied: the `counter overflows` count of the driver's
    /// counter pattern.
    #[must_use]
    pub fn counter_overflows(&self) -> u64 {
        self.core.counter_overflows()
    }

    /// The capability snapshot of the half's epoch.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilitySnapshot {
        &self.snapshot
    }
}

impl<O: SocketOps> TxBackend for SocketsTx<O> {
    type Frame<'a>
        = SocketsFrame<'a>
    where
        Self: 'a;

    fn claim_tx(&mut self, queue: TxQueueId, len: usize) -> Result<SocketsFrame<'_>, ClaimError> {
        self.core.claim(queue, len)
    }

    fn flush<G: SenderGate>(
        &mut self,
        request: FlushRequest,
        gate: &mut G,
        report: &mut TxReport,
    ) -> FlushOutcome {
        self.core.flush(&mut self.ops, request, gate, report)
    }

    /// Copied sockets report no completion event (decision O-10).
    fn poll_completions<H: CompletionHandler>(
        &mut self,
        _budget: Budget,
        _handler: &mut H,
    ) -> CompletionOutcome {
        CompletionOutcome::default()
    }

    fn cancel_pending(
        &mut self,
        queue: TxQueueId,
        report: &mut TxReport,
    ) -> Result<CancelOutcome, QueueError> {
        self.core.cancel_pending(queue, report)
    }
}

/// The RX half: the receive buffer and the duplicated descriptor. One
/// owning agent; `Send`, neither `Sync` nor `Clone` (3.10).
pub struct SocketsRx<O: SocketOps> {
    core: RxCore,
    ops: O,
    snapshot: CapabilitySnapshot,
    not_sync: PhantomData<Cell<()>>,
}

impl<O: SocketOps> fmt::Debug for SocketsRx<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketsRx")
            .field("instance", &self.core.instance)
            .field("epoch", &self.core.epoch)
            .field("state", &self.core.state)
            .finish_non_exhaustive()
    }
}

impl<O: SocketOps> SocketsRx<O> {
    /// `ECONNREFUSED` results of receive calls: counted, the poll goes on.
    #[must_use]
    pub fn peer_errors(&self) -> u64 {
        self.core.peer_errors()
    }

    /// Increments of this half's counters that would have overflowed and
    /// were not applied: the `counter overflows` count of the driver's
    /// counter pattern.
    #[must_use]
    pub fn counter_overflows(&self) -> u64 {
        self.core.counter_overflows()
    }

    /// The capability snapshot of the half's epoch.
    #[must_use]
    pub fn capabilities(&self) -> &CapabilitySnapshot {
        &self.snapshot
    }
}

impl<O: SocketOps> RxBackend for SocketsRx<O> {
    fn poll_rx<H: RxHandler>(&mut self, budget: Budget, handler: &mut H) -> RxOutcome {
        self.core.poll_rx(&mut self.ops, budget, handler)
    }
}
