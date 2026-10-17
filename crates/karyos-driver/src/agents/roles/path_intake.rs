// SPDX-License-Identifier: Apache-2.0

//! The receiver's path queues (`quantstratum-docs:
//! karyos/design/redundant-paths.md` section 5; rp-w8).
//!
//! A datagram of a multi-path image waits in its path's queue between the
//! endpoint's receive poll and the image: each receive endpoint that serves
//! a path of such an image gets one of `sessions.max_paths` queues, of
//! `path_queue_datagrams` entries each. The receiver serves the queues
//! round robin after every endpoint's poll, so a fast path cannot starve a
//! slow one's evidence or statistics, and a full queue drops only its own
//! path's datagram, counted. Within one path the order is the order of
//! arrival: DATA and heartbeats share the queue, so a heartbeat never
//! overtakes that path's earlier DATA.
//!
//! Each entry keeps the time of its receive poll, the arrival time the
//! image's statistics, skew detection and liveness use, whatever the
//! queueing delay.
//!
//! The queues are per local receive endpoint: a path is the endpoint one of
//! an image's bindings arrives on, so the datagrams of every image and
//! source that endpoint serves share its queue, in arrival order. A control
//! that arrives on an endpoint whose queue holds datagrams is handled only
//! once that queue is drained, so a reply such as an ERR never overtakes
//! that path's earlier DATA.
//!
//! **Memory.** The queues hold copies in one slab of `max_paths ×
//! path_queue_datagrams` slots of `MAX_DATAGRAM` bytes (8 KiB, the largest
//! datagram an endpoint can be configured for, so no datagram is too long
//! to queue). It is allocated on the control path when the receiver first
//! binds a later path of an image, never in the receive path; a
//! single-path receiver allocates none. Once allocated it stays until the
//! receiver stops. With `path_queue_datagrams` at least `rx_datagrams` (the
//! defaults: 256 and 64), one poll never fills a queue, since every queue
//! is drained after each poll; a smaller queue drops a poll's excess.

use std::net::SocketAddr;

use karyos_io::sockets::endpoint::MAX_DATAGRAM;
use karyos_protocol::network::Alias;

use super::EndpointId;
use crate::paths::PathConfig;
use crate::paths::queues::{PathQueues, Push};

/// One queued datagram: where it came from, when it was polled, and the
/// slab slot that holds its bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct Queued {
    pub(super) source: SocketAddr,
    pub(super) alias: Alias,
    /// The receive poll's time: its arrival time.
    pub(super) now: u64,
    slot: usize,
    len: usize,
}

/// What [`PathIntake::push`] did. A datagram is bypassed only when its
/// endpoint has no queue, so nothing of its path is waiting: a bypass never
/// overtakes that path's queued datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Queue {
    /// Queued for the drain.
    Queued,
    /// The path's queue was full: dropped, counted.
    Dropped,
    /// Not queued: the caller delivers it now (no queue for its endpoint).
    Bypass,
}

/// The receiver's path queues and their buffers.
#[derive(Debug)]
pub(super) struct PathIntake {
    queues: PathQueues<Queued>,
    /// The endpoint each queue serves, by queue.
    endpoints: Vec<Option<EndpointId>>,
    /// Every slot's bytes, `MAX_DATAGRAM` each, in one allocation. Taken
    /// out while the receiver delivers from it ([`PathIntake::take_slab`]).
    slab: Vec<u8>,
    /// The slots no queued datagram holds.
    free: Vec<usize>,
}

/// The bytes of slot `slot` in `slab`.
fn slot_range(slot: usize, len: usize) -> Option<std::ops::Range<usize>> {
    let start = slot.checked_mul(usize::from(MAX_DATAGRAM))?;
    Some(start..start.checked_add(len)?)
}

impl PathIntake {
    /// The queues of `config.max_paths` endpoints of `config`'s
    /// `path_queue_datagrams` each; it allocates the slab here. `None` when
    /// its size is past `usize` (the agent's validation bounds it first).
    pub(super) fn new(config: &PathConfig) -> Option<Self> {
        let paths = usize::from(config.max_paths);
        let count = paths.checked_mul(usize::from(config.path_queue_datagrams))?;
        let bytes = count.checked_mul(usize::from(MAX_DATAGRAM))?;
        Some(Self {
            queues: PathQueues::new(config),
            endpoints: vec![None; paths],
            slab: vec![0; bytes],
            free: (0..count).rev().collect(),
        })
    }

    /// The queue of `endpoint`, if it has one.
    fn queue_of(&self, endpoint: EndpointId) -> Option<usize> {
        self.endpoints
            .iter()
            .position(|held| *held == Some(endpoint))
    }

    /// Whether `endpoint` has datagrams waiting.
    pub(super) fn holds(&self, endpoint: EndpointId) -> bool {
        self.queue_of(endpoint)
            .is_some_and(|queue| self.queues.len(queue) > 0)
    }

    /// Whether a datagram of `endpoint` goes through the queues: one of a
    /// `multi`-path image, or any while `endpoint`'s queue holds datagrams,
    /// so a path that stops being multi-path keeps its order until its
    /// queue drains.
    pub(super) fn takes(&self, endpoint: EndpointId, multi: bool) -> bool {
        multi || self.holds(endpoint)
    }

    /// Queues a copy of `bytes` from `endpoint`, polled at `now`.
    pub(super) fn push(
        &mut self,
        endpoint: EndpointId,
        (source, alias, now): (SocketAddr, Alias, u64),
        bytes: &[u8],
    ) -> Queue {
        let queue = match self.queue_of(endpoint) {
            Some(queue) => queue,
            None => {
                let Some(queue) = self.endpoints.iter().position(Option::is_none) else {
                    return Queue::Bypass;
                };
                if let Some(slot) = self.endpoints.get_mut(queue) {
                    *slot = Some(endpoint);
                }
                queue
            }
        };
        let len = bytes.len();
        // Longer than a slot (never: a slot holds the largest datagram an
        // endpoint delivers) is dropped, not delivered past the path's
        // queued datagrams.
        if len > usize::from(MAX_DATAGRAM) {
            return Queue::Dropped;
        }
        let Some(slot) = self.free.pop() else {
            return Queue::Dropped;
        };
        let Some(target) = slot_range(slot, len).and_then(|range| self.slab.get_mut(range)) else {
            self.free.push(slot);
            return Queue::Dropped;
        };
        target.copy_from_slice(bytes);
        let entry = Queued {
            source,
            alias,
            now,
            slot,
            len,
        };
        match self.queues.push(queue, entry) {
            Push::Queued => Queue::Queued,
            Push::Full(entry) | Push::UnknownPath(entry) => {
                self.free.push(entry.slot);
                Queue::Dropped
            }
        }
    }

    /// The next datagram round robin across the queues, and its endpoint.
    /// Its bytes are in the slab ([`PathIntake::bytes`]) until
    /// [`PathIntake::release`].
    pub(super) fn pop(&mut self) -> Option<(EndpointId, Queued)> {
        loop {
            let (queue, entry) = self.queues.pop()?;
            if let Some(endpoint) = self.endpoints.get(queue).copied().flatten() {
                return Some((endpoint, entry));
            }
            self.release(entry);
        }
    }

    /// The next datagram of `endpoint` alone, out of turn.
    pub(super) fn pop_from(&mut self, endpoint: EndpointId) -> Option<Queued> {
        let queue = self.queue_of(endpoint)?;
        self.queues.pop_from(queue)
    }

    /// Frees `entry`'s slot once its datagram was delivered.
    pub(super) fn release(&mut self, entry: Queued) {
        self.free.push(entry.slot);
    }

    /// The slab, taken out while the receiver delivers from it (an empty
    /// one is left: nothing is queued meanwhile); [`PathIntake::put_slab`]
    /// gives it back.
    pub(super) fn take_slab(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.slab)
    }

    /// Gives the slab back.
    pub(super) fn put_slab(&mut self, slab: Vec<u8>) {
        self.slab = slab;
    }

    /// The bytes of `entry` in `slab`.
    pub(super) fn bytes<'a>(entry: &Queued, slab: &'a [u8]) -> &'a [u8] {
        slot_range(entry.slot, entry.len)
            .and_then(|range| slab.get(range))
            .unwrap_or(&[])
    }

    /// Frees the queues of endpoints with nothing waiting, for endpoints
    /// to come.
    pub(super) fn release_idle(&mut self) {
        for (queue, endpoint) in self.endpoints.iter_mut().enumerate() {
            if self.queues.len(queue) == 0 {
                *endpoint = None;
            }
        }
    }

    /// Datagrams waiting on every queue; at most the buffers' count, so no
    /// overflow.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> Option<usize> {
        (0..self.endpoints.len())
            .try_fold(0usize, |sum, queue| sum.checked_add(self.queues.len(queue)))
    }
}

#[cfg(test)]
mod tests;
