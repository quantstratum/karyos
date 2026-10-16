// SPDX-License-Identifier: Apache-2.0

//! The TX ledger: the slot pool and the queue table under the claim and
//! commit check orders of `quantstratum-docs:
//! karyos/design/sockets-backend.md` 3.3 and 3.6.
//!
//! The ledger holds no bytes and makes no system call. The endpoint state
//! (Active, Resetting, Retired) belongs to the endpoint, which passes
//! whether it is Active.

use std::num::NonZeroU16;

use super::pool::{ClaimedSlot, SlotPool};
use super::queues::QueueTable;
use super::{
    BackendEpoch, ClaimError, CommitError, QueueError, TxOptions, TxQueueConfig, TxQueueId,
};

/// Slots, queues and the datagram limit of one endpoint.
#[derive(Debug)]
pub(crate) struct TxLedger {
    pool: SlotPool,
    queues: QueueTable,
    max_datagram: NonZeroU16,
}

impl TxLedger {
    /// A ledger of `tx_slots` slots and `max_queues` queues for datagrams
    /// of at most `max_datagram` bytes. Allocates on the control path only.
    pub(crate) fn new(
        tx_slots: NonZeroU16,
        max_queues: NonZeroU16,
        max_datagram: NonZeroU16,
    ) -> Self {
        Self {
            pool: SlotPool::new(tx_slots),
            queues: QueueTable::new(max_queues, tx_slots),
            max_datagram,
        }
    }

    /// The slot pool.
    pub(crate) fn pool(&self) -> &SlotPool {
        &self.pool
    }

    /// The slot pool, mutably.
    pub(crate) fn pool_mut(&mut self) -> &mut SlotPool {
        &mut self.pool
    }

    /// The queue table.
    pub(crate) fn queues(&self) -> &QueueTable {
        &self.queues
    }

    /// Opens a queue; see [`QueueTable::open`].
    pub(crate) fn open_queue(
        &mut self,
        epoch: BackendEpoch,
        config: TxQueueConfig,
    ) -> Result<TxQueueId, QueueError> {
        self.queues.open(epoch, config)
    }

    /// Claims one slot of `len` bytes for `queue`, checking in the order of
    /// 3.6: `NotActive`, `UnknownQueue`, `Empty`, `TooLarge`, `QueueFull`;
    /// then the pool, which gives `IdentityExhausted` after slot retirement
    /// and `PoolExhausted` otherwise. A failed claim changes nothing.
    pub(crate) fn claim(
        &mut self,
        active: bool,
        queue: TxQueueId,
        len: usize,
    ) -> Result<ClaimedSlot, ClaimError> {
        if !active {
            return Err(ClaimError::NotActive);
        }
        let account = self.queues.get(queue).ok_or(ClaimError::UnknownQueue)?;
        if len == 0 {
            return Err(ClaimError::Empty);
        }
        let max = self.max_datagram.get();
        if len > usize::from(max) {
            return Err(ClaimError::TooLarge { len, max });
        }
        if account.is_full() {
            return Err(ClaimError::QueueFull {
                max_pending: account.max_pending(),
            });
        }
        let claimed = self.pool.claim()?;
        if let Err(error) = self.queues.charge(queue) {
            // Unreachable: the queue was checked above; undo the claim.
            debug_assert!(false, "a checked queue takes a charge");
            self.pool.release_claim(claimed.slot);
            return Err(error);
        }
        Ok(claimed)
    }

    /// A dropped frame: the slot returns to Free and the charge to the
    /// queue.
    pub(crate) fn release_claim(&mut self, queue: TxQueueId, slot: u32) -> bool {
        let released = self.pool.release_claim(slot);
        if released {
            let discharged = self.queues.discharge(queue);
            debug_assert!(discharged, "a claimed slot is charged to its queue");
        }
        released
    }

    /// Checks a commit in the order of 3.3: the endpoint is Active, the
    /// queue is open with the same epoch and generation, `1 <= len <=
    /// capacity` and the options are supported.
    pub(crate) fn check_commit(
        &self,
        active: bool,
        queue: TxQueueId,
        len: usize,
        capacity: usize,
        options: TxOptions,
    ) -> Result<(), CommitError> {
        if !active {
            return Err(CommitError::NotActive);
        }
        if self.queues.get(queue).is_none() {
            return Err(CommitError::UnknownQueue);
        }
        if len == 0 {
            return Err(CommitError::Empty);
        }
        if len > capacity {
            return Err(CommitError::LengthExceedsClaim { len, capacity });
        }
        if !options.is_none() {
            return Err(CommitError::UnsupportedOption);
        }
        Ok(())
    }

    /// A pending item left its queue: submitted with release at submission
    /// or returned without exposure. The slot is Free again.
    pub(crate) fn release_pending(&mut self, queue: TxQueueId, slot: u32) -> bool {
        let released = self.pool.release_pending(slot);
        if released {
            let discharged = self.queues.discharge(queue);
            debug_assert!(discharged, "a pending slot is charged to its queue");
        }
        released
    }

    /// A pending item's exposure is unproven: it leaves its queue and its
    /// slot is quarantined until reset.
    pub(crate) fn quarantine(&mut self, queue: TxQueueId, slot: u32) -> bool {
        let quarantined = self.pool.quarantine(slot);
        if quarantined {
            let discharged = self.queues.discharge(queue);
            debug_assert!(discharged, "a pending slot is charged to its queue");
        }
        quarantined
    }
}

#[cfg(test)]
mod tests {
    use super::super::Authority;
    use super::super::pool::SlotState;
    use super::super::queues::test_route;
    use super::*;
    use proptest::prelude::*;

    fn nz(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn config(max_pending: u16) -> TxQueueConfig {
        TxQueueConfig {
            authority: Authority::FIRST,
            route: test_route(),
            max_pending: nz(max_pending),
        }
    }

    /// One queue of `max_pending`, datagram limit 100.
    fn ledger(tx_slots: u16, max_pending: u16) -> (TxLedger, TxQueueId) {
        let mut ledger = TxLedger::new(nz(tx_slots), nz(4), nz(100));
        let queue = ledger
            .open_queue(BackendEpoch::FIRST, config(max_pending))
            .unwrap();
        (ledger, queue)
    }

    #[test]
    fn claim_error_order() {
        let (mut ledger, queue) = ledger(2, 1);
        let stale = TxQueueId::new(BackendEpoch::FIRST, 3, queue.generation());
        // Each check wins over every later one.
        assert_eq!(ledger.claim(false, stale, 0), Err(ClaimError::NotActive));
        assert_eq!(ledger.claim(true, stale, 0), Err(ClaimError::UnknownQueue));
        assert_eq!(ledger.claim(true, queue, 0), Err(ClaimError::Empty));
        assert_eq!(
            ledger.claim(true, queue, 101),
            Err(ClaimError::TooLarge { len: 101, max: 100 })
        );
        ledger.claim(true, queue, 100).unwrap();
        assert_eq!(
            ledger.claim(true, queue, 101),
            Err(ClaimError::TooLarge { len: 101, max: 100 }),
            "TooLarge before QueueFull"
        );
        assert_eq!(
            ledger.claim(true, queue, 1),
            Err(ClaimError::QueueFull { max_pending: 1 })
        );
        assert_eq!(
            ledger.claim(false, queue, 1),
            Err(ClaimError::NotActive),
            "NotActive before QueueFull"
        );
    }

    #[test]
    fn claim_error_order_identity_exhausted_only_after_retirement() {
        let (mut ledger, queue) = ledger(2, 2);
        let first = ledger.claim(true, queue, 1).unwrap();
        ledger.claim(true, queue, 1).unwrap();
        // QueueFull before the pool: the no overcommit rule makes the pool
        // results unreachable while no slot is retired or quarantined.
        assert_eq!(
            ledger.claim(true, queue, 1),
            Err(ClaimError::QueueFull { max_pending: 2 })
        );
        // Retire slot 0 at its next release.
        ledger.pool_mut().set_last_generation(first.slot, u64::MAX);
        assert!(ledger.release_claim(queue, first.slot));
        assert_eq!(ledger.pool().state(first.slot), Some(SlotState::Retired));
        assert_eq!(
            ledger.claim(true, queue, 1),
            Err(ClaimError::IdentityExhausted)
        );
        assert_eq!(
            ledger.queues().get(queue).unwrap().charged(),
            1,
            "a failed claim leaves no charge"
        );
    }

    #[test]
    fn claim_error_order_pool_exhausted_without_retirement() {
        // Quarantine is the other way to empty the pool below the queue
        // capacities; without retirement it is PoolExhausted.
        let (mut ledger, queue) = ledger(1, 1);
        let claimed = ledger.claim(true, queue, 1).unwrap();
        assert!(ledger.pool_mut().commit(claimed.slot));
        assert!(ledger.quarantine(queue, claimed.slot));
        assert_eq!(ledger.claim(true, queue, 1), Err(ClaimError::PoolExhausted));
    }

    #[test]
    fn queue_capacity_full_lane_never_blocks_control_claim() {
        let mut ledger = TxLedger::new(nz(4), nz(4), nz(100));
        let lane = ledger.open_queue(BackendEpoch::FIRST, config(3)).unwrap();
        let control = ledger.open_queue(BackendEpoch::FIRST, config(1)).unwrap();
        for _ in 0..3 {
            let claimed = ledger.claim(true, lane, 10).unwrap();
            assert!(ledger.pool_mut().commit(claimed.slot));
        }
        assert_eq!(
            ledger.claim(true, lane, 10),
            Err(ClaimError::QueueFull { max_pending: 3 })
        );
        assert!(ledger.claim(true, control, 10).is_ok());
        assert_eq!(
            ledger.open_queue(BackendEpoch::FIRST, config(1)),
            Err(QueueError::OverCommitted {
                requested: 1,
                free: 0
            })
        );
    }

    #[test]
    fn commit_check_order() {
        let (ledger, queue) = ledger(1, 1);
        let stale = TxQueueId::new(BackendEpoch::FIRST, 3, queue.generation());
        let none = TxOptions::none();
        assert_eq!(
            ledger.check_commit(false, stale, 0, 8, none),
            Err(CommitError::NotActive)
        );
        assert_eq!(
            ledger.check_commit(true, stale, 0, 8, none),
            Err(CommitError::UnknownQueue)
        );
        assert_eq!(
            ledger.check_commit(true, queue, 0, 8, none),
            Err(CommitError::Empty)
        );
        assert_eq!(
            ledger.check_commit(true, queue, 9, 8, none),
            Err(CommitError::LengthExceedsClaim {
                len: 9,
                capacity: 8
            })
        );
        assert_eq!(ledger.check_commit(true, queue, 8, 8, none), Ok(()));
    }

    #[derive(Debug, Clone)]
    enum Op {
        Claim { queue: usize, len: usize },
        DropClaim,
        Commit,
        Release { queue: usize },
        Quarantine { queue: usize },
        ResetQuarantine,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (0..3_usize, 0..120_usize).prop_map(|(queue, len)| Op::Claim { queue, len }),
            1 => Just(Op::DropClaim),
            3 => Just(Op::Commit),
            3 => (0..3_usize).prop_map(|queue| Op::Release { queue }),
            1 => (0..3_usize).prop_map(|queue| Op::Quarantine { queue }),
            1 => Just(Op::ResetQuarantine),
        ]
    }

    proptest! {
        /// Slot conservation and per queue accounting under random claims,
        /// drops, commits, releases and quarantines: every slot is in one
        /// state, each queue's charge equals its claimed plus pending
        /// slots, and no claim fails with a pool result while no slot is
        /// retired or quarantined (no overcommit).
        #[test]
        fn queue_capacity_conservation(
            capacities in proptest::collection::vec(1_u16..5, 3),
            ops in proptest::collection::vec(op(), 0..200),
        ) {
            let tx_slots: u16 = capacities.iter().sum();
            let mut ledger = TxLedger::new(nz(tx_slots), nz(3), nz(100));
            let queues: Vec<TxQueueId> = capacities
                .iter()
                .map(|max| ledger.open_queue(BackendEpoch::FIRST, config(*max)).unwrap())
                .collect();
            // Model: the claimed frame (at most one) and each queue's FIFO.
            let mut claimed: Option<(usize, u32)> = None;
            let mut pending: Vec<Vec<u32>> = vec![Vec::new(); 3];
            let mut quarantined = 0_usize;
            for op in ops {
                match op {
                    Op::Claim { queue, len } => {
                        if claimed.is_some() {
                            continue;
                        }
                        let result = ledger.claim(true, queues[queue], len);
                        let full = pending[queue].len() >= usize::from(capacities[queue]);
                        match result {
                            Ok(slot) => {
                                prop_assert!((1..=100).contains(&len) && !full);
                                claimed = Some((queue, slot.slot));
                            }
                            Err(ClaimError::Empty) => prop_assert_eq!(len, 0),
                            Err(ClaimError::TooLarge { .. }) => prop_assert!(len > 100),
                            Err(ClaimError::QueueFull { .. }) => prop_assert!(full),
                            Err(ClaimError::PoolExhausted) => prop_assert!(quarantined > 0),
                            Err(other) => prop_assert!(false, "unexpected {:?}", other),
                        }
                    }
                    Op::DropClaim => {
                        if let Some((queue, slot)) = claimed.take() {
                            prop_assert!(ledger.release_claim(queues[queue], slot));
                        }
                    }
                    Op::Commit => {
                        if let Some((queue, slot)) = claimed.take() {
                            prop_assert!(ledger.pool_mut().commit(slot));
                            pending[queue].push(slot);
                        }
                    }
                    Op::Release { queue } => {
                        if !pending[queue].is_empty() {
                            let slot = pending[queue].remove(0);
                            prop_assert!(ledger.release_pending(queues[queue], slot));
                        }
                    }
                    Op::Quarantine { queue } => {
                        if !pending[queue].is_empty() {
                            let slot = pending[queue].remove(0);
                            prop_assert!(ledger.quarantine(queues[queue], slot));
                            quarantined += 1;
                        }
                    }
                    Op::ResetQuarantine => {
                        prop_assert_eq!(ledger.pool_mut().release_quarantined(), quarantined);
                        quarantined = 0;
                    }
                }
                // Conservation.
                let held = usize::from(claimed.is_some())
                    + pending.iter().map(Vec::len).sum::<usize>()
                    + quarantined;
                prop_assert_eq!(ledger.pool().free_count() + held, usize::from(tx_slots));
                for (index, queue) in queues.iter().enumerate() {
                    let charged = usize::from(ledger.queues().get(*queue).unwrap().charged());
                    let own = pending[index].len()
                        + usize::from(claimed.is_some_and(|(q, _)| q == index));
                    prop_assert_eq!(charged, own);
                }
            }
        }
    }
}
