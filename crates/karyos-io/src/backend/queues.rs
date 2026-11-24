// SPDX-License-Identifier: Apache-2.0

//! TX queue capacity and the no overcommit rule (`quantstratum-docs:
//! karyos/design/sockets-backend.md`, 3.3 and 5.1, decision S-6).
//!
//! A queue's `max_pending` bounds its claimed plus pending frames.
//! `open` fails with `OverCommitted` when the sum of `max_pending` over
//! open queues would exceed `tx_slots`, so each queue always has its own
//! capacity: a stalled lane cannot exhaust the slots a control or repair
//! queue needs, and `QueueFull` comes before the pool can run dry.
//!
//! A quarantined slot (6.3) stays occupied until reset, so it stays
//! charged: to its queue while the queue is open, counting towards that
//! queue's `max_pending`, and to the table once the queue closes, where it
//! keeps that part of the closed queue's capacity committed. Only reset
//! ([`QueueTable::close_all`], with the pool's `release_quarantined`)
//! returns it. A quarantined lane therefore exhausts only its own
//! capacity, never another queue's share of the pool.

use std::num::NonZeroU16;

use super::handles::{HandleTable, IssueError};
use super::{Authority, BackendEpoch, ClaimError, QueueError, RouteId, TxQueueConfig, TxQueueId};

/// The accounting of one open queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueueAccount {
    authority: Authority,
    route: RouteId,
    max_pending: NonZeroU16,
    /// Claimed, pending and quarantined slots charged to the queue.
    charged: u16,
    /// The quarantined part of `charged`; it leaves only at reset.
    quarantined: u16,
    /// Opened as an etf queue (ADR-0109): it takes timed commits.
    etf: bool,
}

impl QueueAccount {
    /// The authority fixed when the queue opened.
    pub(crate) fn authority(&self) -> Authority {
        self.authority
    }

    /// The route fixed when the queue opened.
    pub(crate) fn route(&self) -> RouteId {
        self.route
    }

    /// The queue's capacity.
    pub(crate) fn max_pending(&self) -> u16 {
        self.max_pending.get()
    }

    /// Claimed, pending and quarantined slots charged to the queue.
    pub(crate) fn charged(&self) -> u16 {
        self.charged
    }

    /// Quarantined slots charged to the queue until reset.
    pub(crate) fn quarantined(&self) -> u16 {
        self.quarantined
    }

    /// Whether the queue was opened as an etf queue (ADR-0109 point 1).
    pub(crate) fn etf(&self) -> bool {
        self.etf
    }

    /// Whether the queue holds `max_pending` claimed, pending and
    /// quarantined slots.
    pub(crate) fn is_full(&self) -> bool {
        self.charged >= self.max_pending.get()
    }
}

/// The open queues of one endpoint and the slots committed to them.
#[derive(Debug)]
pub(crate) struct QueueTable {
    queues: HandleTable<TxQueueId, QueueAccount>,
    tx_slots: u32,
    /// `tx_slots` minus the sum of `max_pending` over open queues and minus
    /// `stranded`; never negative, by the no overcommit rule.
    uncommitted: u32,
    /// Quarantined slots of closed queues: still occupied, so still
    /// committed, until reset.
    stranded: u32,
}

impl QueueTable {
    /// An empty table of `max_queues` entries over a pool of `tx_slots`,
    /// issuing handles in `epoch`.
    pub(crate) fn new(max_queues: NonZeroU16, tx_slots: NonZeroU16, epoch: BackendEpoch) -> Self {
        Self {
            queues: HandleTable::new(max_queues, epoch),
            tx_slots: u32::from(tx_slots.get()),
            uncommitted: u32::from(tx_slots.get()),
            stranded: 0,
        }
    }

    /// Opens a queue in the table's epoch. Checked in this order: a free entry
    /// (`QueueLimit`), the no overcommit rule (`OverCommitted`), then the
    /// generation counter (`IdentityExhausted`). A failed open changes
    /// nothing.
    pub(crate) fn open(&mut self, config: TxQueueConfig) -> Result<TxQueueId, QueueError> {
        if !self.queues.has_free() {
            return Err(QueueError::QueueLimit);
        }
        let requested = u32::from(config.max_pending.get());
        let free = self.uncommitted;
        let uncommitted = free
            .checked_sub(requested)
            .ok_or(QueueError::OverCommitted { requested, free })?;
        let account = QueueAccount {
            authority: config.authority,
            route: config.route,
            max_pending: config.max_pending,
            charged: 0,
            quarantined: 0,
            etf: config.etf.is_some(),
        };
        let id = self.queues.insert(account).map_err(|error| match error {
            IssueError::Full => QueueError::QueueLimit,
            IssueError::IdentityExhausted => QueueError::IdentityExhausted,
        })?;
        self.uncommitted = uncommitted;
        Ok(id)
    }

    /// The account of `queue`, if the handle is live.
    pub(crate) fn get(&self, queue: TxQueueId) -> Option<&QueueAccount> {
        self.queues.get(queue)
    }

    /// Charges one claimed frame to `queue`.
    pub(crate) fn charge(&mut self, queue: TxQueueId) -> Result<(), ClaimError> {
        let account = self.queues.get_mut(queue).ok_or(ClaimError::UnknownQueue)?;
        if account.is_full() {
            return Err(ClaimError::QueueFull {
                max_pending: account.max_pending.get(),
            });
        }
        account.charged = account
            .charged
            .checked_add(1)
            .ok_or(ClaimError::QueueFull {
                max_pending: account.max_pending.get(),
            })?;
        Ok(())
    }

    /// Returns one charge of `queue`: its frame was dropped, or its pending
    /// item was submitted or returned. A quarantined charge never returns
    /// here; it leaves only at reset.
    pub(crate) fn discharge(&mut self, queue: TxQueueId) -> bool {
        match self.queues.get_mut(queue) {
            Some(account) if account.charged > account.quarantined => {
                match account.charged.checked_sub(1) {
                    Some(charged) => {
                        account.charged = charged;
                        true
                    }
                    None => {
                        debug_assert!(false, "charged exceeds quarantined");
                        false
                    }
                }
            }
            _ => false,
        }
    }

    /// One pending item of `queue` was quarantined: its charge stays, as
    /// its slot stays occupied, and is marked quarantined until reset.
    pub(crate) fn quarantine(&mut self, queue: TxQueueId) -> bool {
        match self.queues.get_mut(queue) {
            Some(account) if account.charged > account.quarantined => {
                match account.quarantined.checked_add(1) {
                    Some(quarantined) => {
                        account.quarantined = quarantined;
                        true
                    }
                    None => {
                        debug_assert!(false, "quarantined is below charged");
                        false
                    }
                }
            }
            _ => false,
        }
    }

    /// Closes `queue` and frees its committed capacity, except the part its
    /// quarantined slots occupy, which stays committed until reset. The
    /// caller returns its claimed and pending items first.
    pub(crate) fn close(&mut self, queue: TxQueueId) -> Result<QueueAccount, QueueError> {
        let account = self.queues.remove(queue).ok_or(QueueError::UnknownQueue)?;
        debug_assert_eq!(
            account.charged, account.quarantined,
            "a queue closes once it holds only quarantined slots"
        );
        // An open queue's capacity was taken from `uncommitted` at open;
        // its quarantined part moves to `stranded` instead.
        let quarantined = u32::from(account.quarantined);
        // A queue never quarantines more than it holds, so `freed` is
        // never negative; were it, nothing moves and the debug build
        // asserts.
        let freed = u32::from(account.max_pending.get()).checked_sub(quarantined);
        match (
            freed.and_then(|freed| self.uncommitted.checked_add(freed)),
            self.stranded.checked_add(quarantined),
        ) {
            (Some(uncommitted), Some(stranded)) => {
                self.uncommitted = uncommitted;
                self.stranded = stranded;
            }
            _ => debug_assert!(false, "committed capacity never exceeds tx_slots"),
        }
        Ok(account)
    }

    /// Closes every queue and moves the table to `new_epoch` (reset), so no
    /// earlier handle matches again. Every slot becomes uncommitted, as
    /// reset also frees the quarantined slots. Generations are kept.
    pub(crate) fn close_all(&mut self, new_epoch: BackendEpoch) {
        self.queues.clear(new_epoch);
        self.uncommitted = self.tx_slots;
        self.stranded = 0;
    }

    /// Quarantined slots of closed queues, committed until reset.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn stranded(&self) -> u32 {
        self.stranded
    }

    /// Slots not committed to an open queue.
    pub(crate) fn uncommitted(&self) -> u32 {
        self.uncommitted
    }

    /// The open queues.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (TxQueueId, &QueueAccount)> {
        self.queues.iter()
    }

    #[cfg(test)]
    pub(crate) fn set_last_generation(&mut self, generation: u32) {
        self.queues.set_last_generation(generation);
    }
}

/// A route handle for tests: epoch 1, index 0, generation 1.
#[cfg(test)]
pub(crate) fn test_route() -> RouteId {
    RouteId::new(BackendEpoch::FIRST, 0, std::num::NonZeroU32::MIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn config(max_pending: u16) -> TxQueueConfig {
        TxQueueConfig {
            authority: Authority::FIRST,
            route: test_route(),
            max_pending: nz(max_pending),
            etf: None,
        }
    }

    #[test]
    fn queue_capacity_and_overcommit_at_open() {
        let mut table = QueueTable::new(nz(4), nz(10), BackendEpoch::FIRST);
        let lane = table.open(config(6)).unwrap();
        assert_eq!(table.uncommitted(), 4);
        assert_eq!(
            table.open(config(5)),
            Err(QueueError::OverCommitted {
                requested: 5,
                free: 4
            })
        );
        let control = table.open(config(4)).unwrap();
        assert_eq!(table.uncommitted(), 0);
        // Closing a queue frees its capacity.
        table.close(control).unwrap();
        assert_eq!(table.uncommitted(), 4);
        assert_eq!(table.close(control), Err(QueueError::UnknownQueue));
        assert!(table.get(lane).is_some());
        assert_eq!(table.iter().count(), 1);
    }

    #[test]
    fn queue_capacity_queue_full_at_max_pending() {
        let mut table = QueueTable::new(nz(1), nz(2), BackendEpoch::FIRST);
        let queue = table.open(config(2)).unwrap();
        table.charge(queue).unwrap();
        table.charge(queue).unwrap();
        assert!(table.get(queue).unwrap().is_full());
        assert_eq!(
            table.charge(queue),
            Err(ClaimError::QueueFull { max_pending: 2 })
        );
        assert!(table.discharge(queue));
        table.charge(queue).unwrap();
        assert!(table.discharge(queue));
        assert!(table.discharge(queue));
        assert!(!table.discharge(queue), "no charge below zero");
        assert_eq!(table.get(queue).unwrap().charged(), 0);
    }

    #[test]
    fn queue_open_order_limit_overcommit_identity() {
        let mut table = QueueTable::new(nz(1), nz(1), BackendEpoch::FIRST);
        table.set_last_generation(u32::MAX);
        // Overcommit is checked before the generation counter.
        assert_eq!(
            table.open(config(2)),
            Err(QueueError::OverCommitted {
                requested: 2,
                free: 1
            })
        );
        assert_eq!(table.open(config(1)), Err(QueueError::IdentityExhausted));
        assert_eq!(table.uncommitted(), 1, "a failed open changes nothing");
        let mut full = QueueTable::new(nz(1), nz(4), BackendEpoch::FIRST);
        full.open(config(1)).unwrap();
        // The entry limit is checked before overcommit.
        assert_eq!(full.open(config(4)), Err(QueueError::QueueLimit));
    }

    #[test]
    fn handles_across_reset_give_unknown_queue() {
        let mut table = QueueTable::new(nz(1), nz(1), BackendEpoch::FIRST);
        let old = table.open(config(1)).unwrap();
        let next = BackendEpoch::FIRST.next().unwrap();
        table.close_all(next);
        assert_eq!(table.uncommitted(), 1);
        let new = table.open(config(1)).unwrap();
        assert_eq!(new.epoch(), next);
        assert_eq!(new.index(), old.index());
        assert!(table.get(old).is_none());
        assert_eq!(table.charge(old), Err(ClaimError::UnknownQueue));
        assert!(!table.discharge(old));
        assert_eq!(table.close(old), Err(QueueError::UnknownQueue));
        let account = table.get(new).unwrap();
        assert_eq!(account.authority(), Authority::FIRST);
        assert_eq!(account.route(), test_route());
        assert_eq!(account.max_pending(), 1);
    }

    #[test]
    fn quarantined_slots_stay_charged_and_committed_until_reset() {
        let mut table = QueueTable::new(nz(2), nz(3), BackendEpoch::FIRST);
        let lane = table.open(config(2)).unwrap();
        table.charge(lane).unwrap();
        table.charge(lane).unwrap();
        assert!(table.quarantine(lane));
        assert!(table.quarantine(lane));
        assert!(
            !table.quarantine(lane),
            "only a charged slot is quarantined"
        );
        assert!(!table.discharge(lane), "a quarantined charge stays");
        let account = table.get(lane).unwrap();
        assert_eq!((account.charged(), account.quarantined()), (2, 2));
        assert!(account.is_full());
        // Closing keeps the quarantined part committed.
        table.close(lane).unwrap();
        assert_eq!((table.uncommitted(), table.stranded()), (1, 2));
        assert_eq!(
            table.open(config(2)),
            Err(QueueError::OverCommitted {
                requested: 2,
                free: 1
            })
        );
        // Reset returns everything.
        table.close_all(BackendEpoch::FIRST.next().unwrap());
        assert_eq!((table.uncommitted(), table.stranded()), (3, 0));
        table.open(config(3)).unwrap();
    }
}
