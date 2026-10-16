// SPDX-License-Identifier: Apache-2.0

//! The control path between the agents (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §2.3 and §3, DN-4; phase 4b-1).
//!
//! - **Items.** The receiver agent owns every RX half. It hands the sender
//!   agent, which owns every TX half, two kinds of control through one
//!   bounded ring: controls to send (an RSP_SETUP challenge to a source)
//!   and controls it received for a local publication (RSP_SETUP CHALLENGE
//!   and SOLICIT). A full ring drops the item and counts it per kind.
//! - **Control TX.** The sender sends controls through a small cache of
//!   routes per endpoint, one control queue per destination, at most
//!   `control_routes` of them; a full cache reuses the least recently used
//!   entry. The cache belongs to one backend epoch of the endpoint: a reset
//!   reopens the endpoint at its next epoch, whose route and queue ids are
//!   all new, so the cache starts empty again. Any failed send evicts its
//!   entry. Controls pass an always-permit gate, private to this module:
//!   only [`ControlRoutes::send`] uses it, and that takes a typed
//!   [`Control`], so DATA can never pass it (the guard gate is phase 7,
//!   `guards-and-abort.md`).

use std::net::SocketAddr;
use std::num::NonZeroU16;

use karyos_io::backend::{
    Authority, BackendEpoch, Commit, Exposure, FlushRequest, GateDecision, RouteId, SenderGate,
    SenderToken, TxBackend, TxFrame, TxItemOutcome, TxOptions, TxQueueConfig, TxQueueId, TxReport,
};
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::network::{Control, MAX_CONTROL_LENGTH};

use super::EndpointId;

/// A control handed from the receiver agent to the sender agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlItem {
    /// Send `control` on `endpoint` to `destination`.
    Outgoing {
        /// The endpoint to send on.
        endpoint: EndpointId,
        /// Where to.
        destination: SocketAddr,
        /// What.
        control: Control,
    },
    /// `control` arrived on `endpoint` from `source`, for a local
    /// publication.
    Incoming {
        /// The endpoint it arrived on.
        endpoint: EndpointId,
        /// Its backend source.
        source: SocketAddr,
        /// What.
        control: Control,
    },
}

/// The gate of control traffic: every candidate is permitted.
#[derive(Debug, Clone, Copy, Default)]
struct ControlGate;

impl SenderGate for ControlGate {
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

/// Why a control was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlSendError {
    /// The control did not encode.
    Encode,
    /// No route or queue could be set up for the destination.
    Route,
    /// The queue had no room for it.
    Claim,
    /// The kernel did not take it.
    Unsent,
}

/// One cached control destination.
#[derive(Debug, Clone, Copy)]
struct Destination {
    address: SocketAddr,
    route: RouteId,
    queue: TxQueueId,
    used: u64,
}

/// The control routes of one endpoint's TX half, for one backend epoch.
#[derive(Debug)]
pub struct ControlRoutes {
    entries: Vec<Destination>,
    max: usize,
    /// The epoch the cached ids belong to.
    epoch: Option<BackendEpoch>,
    /// A logical clock for least-recently-used eviction.
    tick: u64,
    report: TxReport,
}

/// Datagrams one control queue holds: controls are sent at once.
const CONTROL_QUEUE_DEPTH: u16 = 4;

impl ControlRoutes {
    /// At most `max` cached destinations (at least 1); allocated here.
    #[must_use]
    pub fn new(max: usize) -> Self {
        let max = max.max(1);
        Self {
            entries: Vec::with_capacity(max),
            max,
            epoch: None,
            tick: 0,
            report: TxReport::new(),
        }
    }

    /// Forgets every cached destination without touching any half: for an
    /// endpoint handed back, or a half of a new epoch.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.epoch = None;
    }

    /// The cached destinations, oldest use first (tests).
    #[cfg(test)]
    pub(crate) fn cached(&self) -> Vec<SocketAddr> {
        let mut entries = self.entries.clone();
        entries.sort_by_key(|entry| entry.used);
        entries.iter().map(|entry| entry.address).collect()
    }

    /// Drops the entry of `queue` from `tx` and the cache.
    fn evict<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, queue: TxQueueId) {
        if let Some(index) = self.entries.iter().position(|entry| entry.queue == queue) {
            let old = self.entries.swap_remove(index);
            let _ = tx.close_queue(old.queue, &mut self.report);
            while self.report.pop_front().is_some() {}
            let _ = tx.remove_route(old.route);
        }
    }

    /// The control queue to `address` on `tx`, created on first use; the
    /// least recently used destination makes room when the cache is full.
    fn queue<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
    ) -> Result<TxQueueId, ControlSendError> {
        // A reset reopened the endpoint: the cached ids are of the old
        // epoch, and every one of them is dead.
        let epoch = tx.capabilities().epoch;
        if self.epoch != Some(epoch) {
            self.entries.clear();
            self.epoch = Some(epoch);
        }
        // A u64 use clock does not wrap in practice; if it ever would, the
        // ages start over.
        self.tick = match self.tick.checked_add(1) {
            Some(tick) => tick,
            None => {
                for entry in &mut self.entries {
                    entry.used = 0;
                }
                1
            }
        };
        let tick = self.tick;
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.address == address)
        {
            entry.used = tick;
            return Ok(entry.queue);
        }
        if self.entries.len() >= self.max
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|entry| entry.used)
                .map(|entry| entry.queue)
        {
            self.evict(tx, oldest);
        }
        let route = tx.add_route(address).map_err(|_| ControlSendError::Route)?;
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::new(CONTROL_QUEUE_DEPTH).unwrap_or(NonZeroU16::MIN),
            })
            .map_err(|_| {
                let _ = tx.remove_route(route);
                ControlSendError::Route
            })?;
        self.entries.push(Destination {
            address,
            route,
            queue,
            used: tick,
        });
        Ok(queue)
    }

    /// Encodes `control` and sends it on `tx` to `address`, now. It takes
    /// a typed [`Control`] only, so no DATA can take this path:
    ///
    /// ```compile_fail
    /// # use karyos_driver::agents::control::ControlRoutes;
    /// # use karyos_io::sockets::{OsSocket, endpoint::SocketsTx};
    /// fn send_data(routes: &mut ControlRoutes, tx: &mut SocketsTx<OsSocket>, batch: &[u8]) {
    ///     let to = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    ///     // A DATA batch is bytes, not a `Control`: this does not compile.
    ///     let _ = routes.send(tx, to, batch);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// The [`ControlSendError`] reason; nothing waits for a later cycle,
    /// and the destination's entry is evicted.
    pub fn send<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        address: SocketAddr,
        control: &Control,
    ) -> Result<(), ControlSendError> {
        let mut bytes = [0u8; MAX_CONTROL_LENGTH];
        let length = control
            .encode(&mut bytes)
            .map_err(|_| ControlSendError::Encode)?;
        let encoded = bytes.get(..length).ok_or(ControlSendError::Encode)?;
        let queue = self.queue(tx, address)?;
        let claimed = tx
            .claim_tx(queue, encoded.len())
            .ok()
            .and_then(|mut frame| {
                frame
                    .bytes_mut()
                    .get_mut(..encoded.len())?
                    .copy_from_slice(encoded);
                frame
                    .commit(Commit {
                        len: encoded.len(),
                        token: SenderToken::new(0),
                        options: TxOptions::none(),
                    })
                    .ok()
            });
        if claimed.is_none() {
            self.evict(tx, queue);
            return Err(ControlSendError::Claim);
        }
        let _ = tx.flush(
            FlushRequest {
                queue,
                max_datagrams: NonZeroU16::MIN,
                max_bytes: u32::MAX,
            },
            &mut ControlGate,
            &mut self.report,
        );
        let mut sent = false;
        while let Some(entry) = self.report.pop_front() {
            sent |= matches!(entry.outcome, TxItemOutcome::Submitted { .. });
        }
        if sent {
            return Ok(());
        }
        // Not taken now: a control is not worth a retry; dropping the
        // queue drops it, so no stale control waits.
        self.evict(tx, queue);
        Err(ControlSendError::Unsent)
    }
}

/// One endpoint's control routes, kept by the sender in a table allocated
/// at creation (one per endpoint the agent can hold).
#[derive(Debug)]
pub struct RouteSlot {
    /// The endpoint it serves, `None` while free.
    pub endpoint: Option<EndpointId>,
    /// Its routes.
    pub routes: ControlRoutes,
}
