// SPDX-License-Identifier: Apache-2.0

//! The TX ledger: the slot pool and the queue table under the claim and
//! commit check orders of `quantstratum-docs:
//! karyos/design/sockets-backend.md` 3.3 and 3.6.
//!
//! The ledger holds no bytes and makes no system call. The endpoint state
//! (Active, Resetting, Retired) belongs to the endpoint, which passes
//! whether it is Active.
//!
//! Accounting (5.1, S-6): every slot that is not Free or Retired is
//! charged either to an open queue (claimed, pending or quarantined) or,
//! for a quarantined slot of a closed queue, to the queue table until
//! reset. The charges of a queue never exceed its `max_pending`, and the
//! capacities of open queues plus those stranded charges never exceed
//! `tx_slots`. A claim that passes `QueueFull` therefore finds a Free slot
//! unless slots were retired.

use std::num::NonZeroU16;

use super::pool::{ClaimedSlot, SlotPool};
use super::queues::QueueTable;
use super::{
    BackendEpoch, ClaimError, CommitError, QueueError, TxOptions, TxQueueConfig, TxQueueId,
};

/// Slots, queues and the datagram limit of one endpoint.
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
)]
pub(crate) struct TxLedger {
    pool: SlotPool,
    queues: QueueTable,
    max_datagram: NonZeroU16,
}

impl TxLedger {
    /// A ledger of `tx_slots` slots and `max_queues` queues for datagrams
    /// of at most `max_datagram` bytes, issuing queue handles in `epoch`.
    /// Allocates on the control path only.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn new(
        tx_slots: NonZeroU16,
        max_queues: NonZeroU16,
        max_datagram: NonZeroU16,
        epoch: BackendEpoch,
    ) -> Self {
        Self {
            pool: SlotPool::new(tx_slots),
            queues: QueueTable::new(max_queues, tx_slots, epoch),
            max_datagram,
        }
    }

    /// The slot pool.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn pool(&self) -> &SlotPool {
        &self.pool
    }

    /// The slot pool, mutably.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn pool_mut(&mut self) -> &mut SlotPool {
        &mut self.pool
    }

    /// The queue table.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn queues(&self) -> &QueueTable {
        &self.queues
    }

    /// Opens a queue in the current epoch; see [`QueueTable::open`].
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn open_queue(&mut self, config: TxQueueConfig) -> Result<TxQueueId, QueueError> {
        self.queues.open(config)
    }

    /// Closes a queue; see [`QueueTable::close`]. Its quarantined slots
    /// stay committed until [`TxLedger::reset`].
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn close_queue(&mut self, queue: TxQueueId) -> Result<(), QueueError> {
        self.queues.close(queue).map(|_| ())
    }

    /// Reset step 3 of 7.3, once nothing is claimed or pending: closes
    /// every queue, frees the quarantined slots and moves the queue table
    /// to `new_epoch`. Returns how many quarantined slots were freed.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn reset(&mut self, new_epoch: BackendEpoch) -> usize {
        debug_assert!(
            self.queues
                .iter()
                .all(|(_, account)| account.charged() == account.quarantined()),
            "reset frees slots only once nothing is claimed or pending"
        );
        let released = self.pool.release_quarantined();
        self.queues.close_all(new_epoch);
        released
    }

    /// Claims one slot of `len` bytes for `queue`, checking in the order of
    /// 3.6: `NotActive`, `UnknownQueue`, `Empty`, `TooLarge`, `QueueFull`
    /// (quarantined slots count towards it); then the pool, which gives
    /// `IdentityExhausted` when retirement alone keeps it dry and
    /// `PoolExhausted` when a reset would free a quarantined slot. Under
    /// the accounting of this module the pool runs dry only after
    /// retirement. A failed claim changes nothing.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn release_pending(&mut self, queue: TxQueueId, slot: u32) -> bool {
        let released = self.pool.release_pending(slot);
        if released {
            let discharged = self.queues.discharge(queue);
            debug_assert!(discharged, "a pending slot is charged to its queue");
        }
        released
    }

    /// A pending item's exposure is unproven: it leaves its queue's FIFO
    /// and its slot is quarantined until reset. The slot stays charged to
    /// the queue, so it keeps counting towards the queue's `max_pending`
    /// and never towards another queue's share of the pool.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the sockets endpoint from P2.3 S2")
    )]
    pub(crate) fn quarantine(&mut self, queue: TxQueueId, slot: u32) -> bool {
        let quarantined = self.pool.quarantine(slot);
        if quarantined {
            let charged = self.queues.quarantine(queue);
            debug_assert!(charged, "a pending slot is charged to its queue");
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

    fn empty_ledger(tx_slots: u16) -> TxLedger {
        TxLedger::new(nz(tx_slots), nz(4), nz(100), BackendEpoch::FIRST)
    }

    /// One queue of `max_pending`, datagram limit 100.
    fn ledger(tx_slots: u16, max_pending: u16) -> (TxLedger, TxQueueId) {
        let mut ledger = empty_ledger(tx_slots);
        let queue = ledger.open_queue(config(max_pending)).unwrap();
        (ledger, queue)
    }

    /// Claims, commits and quarantines one slot of `queue`.
    fn quarantine_one(ledger: &mut TxLedger, queue: TxQueueId) -> u32 {
        let claimed = ledger.claim(true, queue, 1).unwrap();
        assert!(ledger.pool_mut().commit(claimed.slot));
        assert!(ledger.quarantine(queue, claimed.slot));
        claimed.slot
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
        // results unreachable while no slot is retired.
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
    fn claim_error_order_quarantine_fills_only_its_own_queue() {
        // A quarantined slot stays charged: the queue reports QueueFull, not
        // a pool result.
        let (mut ledger, queue) = ledger(1, 1);
        quarantine_one(&mut ledger, queue);
        assert_eq!(
            ledger.claim(true, queue, 1),
            Err(ClaimError::QueueFull { max_pending: 1 })
        );
    }

    #[test]
    fn claim_error_order_pool_exhausted_after_retirement_with_quarantine() {
        // The pool runs dry only after retirement. While a quarantined slot
        // remains, a reset would free it: PoolExhausted, not the terminal
        // IdentityExhausted.
        let (mut ledger, queue) = ledger(2, 2);
        let first = ledger.claim(true, queue, 1).unwrap();
        ledger.pool_mut().set_last_generation(first.slot, u64::MAX);
        assert!(ledger.release_claim(queue, first.slot));
        quarantine_one(&mut ledger, queue);
        assert_eq!(ledger.claim(true, queue, 1), Err(ClaimError::PoolExhausted));
        // Reset frees the quarantined slot; then retirement alone keeps
        // the pool dry.
        let next = BackendEpoch::FIRST.next().unwrap();
        assert_eq!(ledger.reset(next), 1);
        assert!(ledger.queues().get(queue).is_none());
        let queue = ledger.open_queue(config(2)).unwrap();
        assert_eq!(queue.epoch(), next);
        ledger.claim(true, queue, 1).unwrap();
        assert_eq!(
            ledger.claim(true, queue, 1),
            Err(ClaimError::IdentityExhausted)
        );
    }

    #[test]
    fn queue_capacity_full_lane_never_blocks_control_claim() {
        let mut ledger = empty_ledger(4);
        let lane = ledger.open_queue(config(3)).unwrap();
        let control = ledger.open_queue(config(1)).unwrap();
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
            ledger.open_queue(config(1)),
            Err(QueueError::OverCommitted {
                requested: 1,
                free: 0
            })
        );
    }

    #[test]
    fn queue_capacity_quarantined_lane_never_blocks_control_claim() {
        // Review repro 1: tx_slots 2, lane and control of max_pending 1.
        let mut ledger = empty_ledger(2);
        let lane = ledger.open_queue(config(1)).unwrap();
        let control = ledger.open_queue(config(1)).unwrap();
        quarantine_one(&mut ledger, lane);
        // The quarantined slot still counts towards the lane's capacity.
        assert_eq!(
            ledger.claim(true, lane, 1),
            Err(ClaimError::QueueFull { max_pending: 1 })
        );
        let account = ledger.queues().get(lane).unwrap();
        assert_eq!((account.charged(), account.quarantined()), (1, 1));
        // The control queue keeps its share of the pool.
        let claimed = ledger.claim(true, control, 1).unwrap();
        assert!(ledger.pool_mut().commit(claimed.slot));
    }

    #[test]
    fn queue_capacity_close_after_quarantine_never_overcommits() {
        // Review repro 2: closing a quarantined lane keeps the quarantined
        // slot committed until reset.
        let mut ledger = empty_ledger(2);
        let lane = ledger.open_queue(config(1)).unwrap();
        quarantine_one(&mut ledger, lane);
        ledger.close_queue(lane).unwrap();
        assert_eq!(ledger.queues().uncommitted(), 1);
        assert_eq!(ledger.queues().stranded(), 1);
        assert_eq!(
            ledger.open_queue(config(2)),
            Err(QueueError::OverCommitted {
                requested: 2,
                free: 1
            })
        );
        let queue = ledger.open_queue(config(1)).unwrap();
        let claimed = ledger.claim(true, queue, 1).unwrap();
        assert_eq!(ledger.pool().free_count(), 0);
        assert_eq!(
            ledger.claim(true, queue, 1),
            Err(ClaimError::QueueFull { max_pending: 1 })
        );
        // Reset returns the stranded slot and the whole capacity.
        assert!(ledger.release_claim(queue, claimed.slot));
        assert_eq!(ledger.reset(BackendEpoch::FIRST.next().unwrap()), 1);
        assert_eq!(ledger.queues().uncommitted(), 2);
        assert_eq!(ledger.queues().stranded(), 0);
        assert_eq!(ledger.pool().free_count(), 2);
        ledger.open_queue(config(2)).unwrap();
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
        Close { queue: usize },
        Open { queue: usize, max: u16 },
        Reset,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (0..3_usize, 0..120_usize).prop_map(|(queue, len)| Op::Claim { queue, len }),
            1 => Just(Op::DropClaim),
            3 => Just(Op::Commit),
            3 => (0..3_usize).prop_map(|queue| Op::Release { queue }),
            1 => (0..3_usize).prop_map(|queue| Op::Quarantine { queue }),
            1 => (0..3_usize).prop_map(|queue| Op::Close { queue }),
            1 => (0..3_usize, 1_u16..6).prop_map(|(queue, max)| Op::Open { queue, max }),
            1 => Just(Op::Reset),
        ]
    }

    /// The model of one queue: its last handle, whether it is open, its
    /// capacity, its FIFO and its quarantined slots.
    #[derive(Debug)]
    struct Lane {
        id: TxQueueId,
        open: bool,
        max: u16,
        pending: Vec<u32>,
        quarantined: usize,
    }

    /// Returns the claimed frame and every pending item of `lane`, as
    /// cancellation, close and reset do before they close a queue.
    fn drain(
        ledger: &mut TxLedger,
        claimed: &mut Option<(usize, u32)>,
        index: usize,
        lane: &mut Lane,
    ) -> Result<(), TestCaseError> {
        if let Some((queue, slot)) = *claimed
            && queue == index
        {
            prop_assert!(ledger.release_claim(lane.id, slot));
            *claimed = None;
        }
        for slot in lane.pending.drain(..) {
            prop_assert!(ledger.release_pending(lane.id, slot));
        }
        Ok(())
    }

    proptest! {
        /// Slot conservation and per queue accounting under random claims,
        /// drops, commits, releases, quarantines, closes, opens and resets:
        /// every slot is in one state; each open queue's charge equals its
        /// claimed, pending and quarantined slots; quarantined slots of
        /// closed queues stay committed until reset; and, as no slot is
        /// retired, no claim ever fails with a pool result (S-6).
        #[test]
        fn queue_capacity_conservation(
            capacities in proptest::collection::vec(1_u16..5, 3),
            ops in proptest::collection::vec(op(), 0..200),
        ) {
            let tx_slots: u16 = capacities.iter().sum();
            let slots = usize::from(tx_slots);
            let mut ledger = TxLedger::new(nz(tx_slots), nz(3), nz(100), BackendEpoch::FIRST);
            let mut lanes: Vec<Lane> = capacities
                .iter()
                .map(|max| Lane {
                    id: ledger.open_queue(config(*max)).unwrap(),
                    open: true,
                    max: *max,
                    pending: Vec::new(),
                    quarantined: 0,
                })
                .collect();
            let mut claimed: Option<(usize, u32)> = None;
            let mut stranded = 0_usize;
            let mut epoch = BackendEpoch::FIRST;
            for op in ops {
                match op {
                    Op::Claim { queue, len } => {
                        if claimed.is_some() {
                            continue;
                        }
                        let lane = &lanes[queue];
                        let result = ledger.claim(true, lane.id, len);
                        if !lane.open {
                            prop_assert_eq!(result, Err(ClaimError::UnknownQueue));
                            continue;
                        }
                        let full = lane.pending.len() + lane.quarantined >= usize::from(lane.max);
                        match result {
                            Ok(slot) => {
                                prop_assert!((1..=100).contains(&len) && !full);
                                claimed = Some((queue, slot.slot));
                            }
                            Err(ClaimError::Empty) => prop_assert_eq!(len, 0),
                            Err(ClaimError::TooLarge { .. }) => prop_assert!(len > 100),
                            Err(ClaimError::QueueFull { .. }) => prop_assert!(full),
                            Err(other) => prop_assert!(false, "unexpected {:?}", other),
                        }
                    }
                    Op::DropClaim => {
                        if let Some((queue, slot)) = claimed.take() {
                            prop_assert!(ledger.release_claim(lanes[queue].id, slot));
                        }
                    }
                    Op::Commit => {
                        if let Some((queue, slot)) = claimed.take() {
                            prop_assert!(ledger.pool_mut().commit(slot));
                            lanes[queue].pending.push(slot);
                        }
                    }
                    Op::Release { queue } => {
                        let lane = &mut lanes[queue];
                        if !lane.pending.is_empty() {
                            let slot = lane.pending.remove(0);
                            prop_assert!(ledger.release_pending(lane.id, slot));
                        }
                    }
                    Op::Quarantine { queue } => {
                        let lane = &mut lanes[queue];
                        if !lane.pending.is_empty() {
                            let slot = lane.pending.remove(0);
                            prop_assert!(ledger.quarantine(lane.id, slot));
                            lane.quarantined += 1;
                        }
                    }
                    Op::Close { queue } => {
                        let lane = &mut lanes[queue];
                        if lane.open {
                            drain(&mut ledger, &mut claimed, queue, lane)?;
                            prop_assert_eq!(ledger.close_queue(lane.id), Ok(()));
                            stranded += lane.quarantined;
                            lane.quarantined = 0;
                            lane.open = false;
                        }
                        prop_assert_eq!(
                            ledger.close_queue(lane.id),
                            Err(QueueError::UnknownQueue)
                        );
                    }
                    Op::Open { queue, max } => {
                        if lanes[queue].open {
                            continue;
                        }
                        let committed: usize = lanes
                            .iter()
                            .filter(|lane| lane.open)
                            .map(|lane| usize::from(lane.max))
                            .sum();
                        let free = slots - committed - stranded;
                        let result = ledger.open_queue(config(max));
                        if usize::from(max) <= free {
                            let lane = &mut lanes[queue];
                            lane.id = result.unwrap();
                            lane.open = true;
                            lane.max = max;
                        } else {
                            prop_assert_eq!(
                                result,
                                Err(QueueError::OverCommitted {
                                    requested: u32::from(max),
                                    free: u32::try_from(free).unwrap(),
                                })
                            );
                        }
                    }
                    Op::Reset => {
                        let mut quarantined = stranded;
                        for (index, lane) in lanes.iter_mut().enumerate() {
                            if lane.open {
                                drain(&mut ledger, &mut claimed, index, lane)?;
                            }
                            quarantined += lane.quarantined;
                        }
                        prop_assert!(claimed.is_none());
                        epoch = epoch.next().unwrap();
                        prop_assert_eq!(ledger.reset(epoch), quarantined);
                        stranded = 0;
                        // Old handles never match; the open queues reopen
                        // in the new epoch with the same capacities.
                        for lane in &mut lanes {
                            prop_assert!(ledger.queues().get(lane.id).is_none());
                            lane.quarantined = 0;
                            if lane.open {
                                lane.id = ledger.open_queue(config(lane.max)).unwrap();
                                prop_assert_eq!(lane.id.epoch(), epoch);
                            }
                        }
                    }
                }
                // Conservation: no slot is retired here.
                let quarantined: usize =
                    lanes.iter().map(|lane| lane.quarantined).sum::<usize>() + stranded;
                let held = usize::from(claimed.is_some())
                    + lanes.iter().map(|lane| lane.pending.len()).sum::<usize>()
                    + quarantined;
                prop_assert_eq!(ledger.pool().free_count() + held, slots);
                prop_assert_eq!(
                    usize::try_from(ledger.pool().quarantined_count()).unwrap(),
                    quarantined
                );
                // Committed capacity: open queues plus stranded quarantine.
                let committed: usize = lanes
                    .iter()
                    .filter(|lane| lane.open)
                    .map(|lane| usize::from(lane.max))
                    .sum();
                prop_assert_eq!(usize::try_from(ledger.queues().stranded()).unwrap(), stranded);
                prop_assert_eq!(
                    usize::try_from(ledger.queues().uncommitted()).unwrap(),
                    slots - committed - stranded
                );
                for (index, lane) in lanes.iter().enumerate().filter(|(_, lane)| lane.open) {
                    let account = ledger.queues().get(lane.id).unwrap();
                    let own = lane.pending.len()
                        + lane.quarantined
                        + usize::from(claimed.is_some_and(|(queue, _)| queue == index));
                    prop_assert_eq!(usize::from(account.charged()), own);
                    prop_assert_eq!(usize::from(account.quarantined()), lane.quarantined);
                    prop_assert!(account.charged() <= account.max_pending());
                }
            }
        }
    }
}
