// SPDX-License-Identifier: Apache-2.0

//! The path queues of a receive owner (`quantstratum-docs:
//! karyos/design/redundant-paths.md`, section 5).
//!
//! Each path's backend reader hands datagrams to the owner through its own
//! bounded queue of `path_queue_datagrams` entries. A full queue drops and
//! counts the datagram for that path only: a later copy from another path,
//! or repair, can still fill the bytes. The owner serves the queues round
//! robin, one datagram per path per turn, so one fast path cannot starve
//! another's evidence or statistics.

use std::collections::VecDeque;

use super::{PathConfig, bump};

/// The queues of one image's paths, generic over the datagram handed over.
#[derive(Debug)]
pub struct PathQueues<T> {
    queues: Vec<VecDeque<T>>,
    capacity: usize,
    /// The path the next turn starts at.
    next: usize,
    drops: Vec<u64>,
    overflows: u64,
}

/// A datagram refused by a full path queue, returned to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push<T> {
    /// Queued.
    Queued,
    /// The path's queue is full: dropped and counted for that path.
    Full(T),
    /// No such path.
    UnknownPath(T),
}

impl<T> PathQueues<T> {
    /// The queues of `config.max_paths` paths, each holding
    /// `config.path_queue_datagrams`; it allocates only here.
    #[must_use]
    pub fn new(config: &PathConfig) -> Self {
        let paths = usize::from(config.max_paths);
        let capacity = usize::from(config.path_queue_datagrams);
        Self {
            queues: (0..paths)
                .map(|_| VecDeque::with_capacity(capacity))
                .collect(),
            capacity,
            next: 0,
            drops: vec![0; paths],
            overflows: 0,
        }
    }

    /// Hands `datagram` from `path` to the owner.
    pub fn push(&mut self, path: usize, datagram: T) -> Push<T> {
        let (Some(queue), Some(drops)) = (self.queues.get_mut(path), self.drops.get_mut(path))
        else {
            return Push::UnknownPath(datagram);
        };
        if queue.len() >= self.capacity {
            bump(drops, &mut self.overflows);
            return Push::Full(datagram);
        }
        queue.push_back(datagram);
        Push::Queued
    }

    /// The next datagram for the owner and the path it came from: one per
    /// path per turn, starting after the path served last.
    pub fn pop(&mut self) -> Option<(usize, T)> {
        let paths = self.queues.len();
        let start = self.next.min(paths);
        for path in (start..paths).chain(0..start) {
            if let Some(datagram) = self.queues.get_mut(path).and_then(VecDeque::pop_front) {
                self.next = path
                    .checked_add(1)
                    .filter(|next| *next < paths)
                    .unwrap_or(0);
                return Some((path, datagram));
            }
        }
        None
    }

    /// The next datagram of `path` alone, out of turn: the round robin's
    /// place does not move.
    pub fn pop_from(&mut self, path: usize) -> Option<T> {
        self.queues.get_mut(path).and_then(VecDeque::pop_front)
    }

    /// Datagrams waiting on `path`.
    #[must_use]
    pub fn len(&self, path: usize) -> usize {
        self.queues.get(path).map_or(0, VecDeque::len)
    }

    /// Whether no path has a datagram waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(VecDeque::is_empty)
    }

    /// Datagrams `path`'s full queue dropped.
    #[must_use]
    pub fn drops(&self, path: usize) -> u64 {
        self.drops.get(path).copied().unwrap_or(0)
    }

    /// Counts that would have overflowed and kept their last value.
    #[must_use]
    pub fn overflows(&self) -> u64 {
        self.overflows
    }

    /// Drops every datagram of `path`, when its binding goes.
    pub fn clear(&mut self, path: usize) {
        if let Some(queue) = self.queues.get_mut(path) {
            queue.clear();
        }
    }
}
