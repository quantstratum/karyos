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
//! **Memory.** The queues hold copies in `max_paths × path_queue_datagrams`
//! buffers of `MAX_DATAGRAM` bytes (8 KiB, the largest datagram an endpoint
//! can be configured for, so no datagram is too long to queue). They are
//! allocated on the control path when the receiver first binds a later
//! path of an image, never in the receive path; a single-path receiver
//! allocates none. Once allocated they stay until the receiver stops.

use std::net::SocketAddr;

use karyos_io::sockets::endpoint::MAX_DATAGRAM;
use karyos_protocol::network::Alias;

use super::EndpointId;
use crate::paths::PathConfig;
use crate::paths::queues::{PathQueues, Push};

/// One queued datagram: where it came from, when it was polled, and the
/// buffer that holds its bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct Queued {
    pub(super) source: SocketAddr,
    pub(super) alias: Alias,
    /// The receive poll's time: its arrival time.
    pub(super) now: u64,
    buffer: usize,
    len: usize,
}

/// What [`PathIntake::push`] did.
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
    buffers: Vec<Vec<u8>>,
    /// The buffers no queued datagram holds.
    free: Vec<usize>,
}

impl PathIntake {
    /// The queues of `config.max_paths` endpoints of `config`'s
    /// `path_queue_datagrams` each; it allocates every buffer here. `None`
    /// when their count is past `usize` (the agent's validation bounds the
    /// bytes first).
    pub(super) fn new(config: &PathConfig) -> Option<Self> {
        let paths = usize::from(config.max_paths);
        let count = paths.checked_mul(usize::from(config.path_queue_datagrams))?;
        Some(Self {
            queues: PathQueues::new(config),
            endpoints: vec![None; paths],
            buffers: (0..count)
                .map(|_| vec![0; usize::from(MAX_DATAGRAM)])
                .collect(),
            free: (0..count).rev().collect(),
        })
    }

    /// The queue of `endpoint`, if it has one.
    fn queue_of(&self, endpoint: EndpointId) -> Option<usize> {
        self.endpoints
            .iter()
            .position(|held| *held == Some(endpoint))
    }

    /// Whether `endpoint` has datagrams waiting: the caller then queues
    /// every later one of its datagrams too, to keep the path's order.
    pub(super) fn holds(&self, endpoint: EndpointId) -> bool {
        self.queue_of(endpoint)
            .is_some_and(|queue| self.queues.len(queue) > 0)
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
        let Some(buffer) = self.free.pop() else {
            return Queue::Dropped;
        };
        let Some(target) = self
            .buffers
            .get_mut(buffer)
            .and_then(|held| held.get_mut(..len))
        else {
            // Longer than any endpoint delivers: never queued.
            self.free.push(buffer);
            return Queue::Bypass;
        };
        target.copy_from_slice(bytes);
        let entry = Queued {
            source,
            alias,
            now,
            buffer,
            len,
        };
        match self.queues.push(queue, entry) {
            Push::Queued => Queue::Queued,
            Push::Full(entry) | Push::UnknownPath(entry) => {
                self.free.push(entry.buffer);
                Queue::Dropped
            }
        }
    }

    /// The next datagram round robin across the queues: its endpoint, its
    /// entry, and its buffer, taken out until [`PathIntake::give_back`].
    pub(super) fn pop(&mut self) -> Option<(EndpointId, Queued, Vec<u8>)> {
        loop {
            let (queue, entry) = self.queues.pop()?;
            let endpoint = self.endpoints.get(queue).copied().flatten();
            let buffer = self
                .buffers
                .get_mut(entry.buffer)
                .map(std::mem::take)
                .unwrap_or_default();
            if let Some(endpoint) = endpoint {
                return Some((endpoint, entry, buffer));
            }
            self.give_back(entry, buffer);
        }
    }

    /// Returns `buffer`, `entry`'s, once its datagram was delivered.
    pub(super) fn give_back(&mut self, entry: Queued, buffer: Vec<u8>) {
        if let Some(slot) = self.buffers.get_mut(entry.buffer) {
            *slot = buffer;
            self.free.push(entry.buffer);
        }
    }

    /// The bytes of `entry` in `buffer`.
    pub(super) fn bytes<'a>(entry: &Queued, buffer: &'a [u8]) -> &'a [u8] {
        buffer.get(..entry.len).unwrap_or(&[])
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
