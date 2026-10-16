// SPDX-License-Identifier: Apache-2.0

//! The TX slot pool and slot identities (`quantstratum-docs:
//! karyos/design/sockets-backend.md`, 3.2 and 7.1).
//!
//! Each slot's generation starts at 1 and increases by one, with checked
//! arithmetic, each time the slot is claimed. A slot whose generation would
//! overflow is retired from the pool when it is freed, so it is never
//! claimed again. With the instance and the epoch, the generation makes a
//! [`super::SubmissionId`] that is never reused within the driver's life.
//!
//! States reachable for copied sockets: Free, Claimed, Pending, then Free
//! again; or Pending, then Quarantined until reset after an invariant
//! violation. Retired is final for the pool's life.

use std::num::{NonZeroU16, NonZeroU64};

use super::ClaimError;

/// The state of one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotState {
    /// In the pool; no references.
    Free,
    /// Granted to one frame; the caller may write it.
    Claimed,
    /// Owned by a queue; immutable.
    Pending,
    /// Exposure unproven; not reused until reset.
    Quarantined,
    /// Its generation cannot advance; never claimed again.
    Retired,
}

/// One granted slot and the generation of this claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaimedSlot {
    /// The slot index.
    pub(crate) slot: u32,
    /// The generation of this claim.
    pub(crate) generation: NonZeroU64,
}

#[derive(Debug, Clone, Copy)]
struct Meta {
    state: SlotState,
    /// The last generation granted; 0 before the first claim.
    last_generation: u64,
}

/// A fixed set of TX slots. Every allocation happens in [`SlotPool::new`],
/// on the control path; no later call allocates or frees.
#[derive(Debug)]
pub(crate) struct SlotPool {
    meta: Box<[Meta]>,
    /// Free slot indices; its capacity is the slot count, so pushing never
    /// reallocates.
    free: Vec<u32>,
    retired: u32,
}

impl SlotPool {
    /// A pool of `slots` Free slots that have never been claimed.
    pub(crate) fn new(slots: NonZeroU16) -> Self {
        let count = slots.get();
        let meta = (0..count)
            .map(|_| Meta {
                state: SlotState::Free,
                last_generation: 0,
            })
            .collect();
        let mut free = Vec::with_capacity(usize::from(count));
        // Reversed, so the lowest index is claimed first.
        free.extend((0..u32::from(count)).rev());
        Self {
            meta,
            free,
            retired: 0,
        }
    }

    /// Slots in the pool, whatever their state.
    pub(crate) fn len(&self) -> usize {
        self.meta.len()
    }

    /// Slots that a claim can take.
    pub(crate) fn free_count(&self) -> usize {
        self.free.len()
    }

    /// Slots retired for generation overflow.
    pub(crate) fn retired_count(&self) -> u32 {
        self.retired
    }

    /// The state of `slot`.
    pub(crate) fn state(&self, slot: u32) -> Option<SlotState> {
        self.meta_of(slot).map(|meta| meta.state)
    }

    /// The last generation granted for `slot`, or `None` before its first
    /// claim or for an index outside the pool.
    pub(crate) fn generation(&self, slot: u32) -> Option<NonZeroU64> {
        self.meta_of(slot)
            .and_then(|meta| NonZeroU64::new(meta.last_generation))
    }

    /// Grants one Free slot with its next generation.
    ///
    /// When no slot is free, the result is `IdentityExhausted` if slots
    /// were retired for generation overflow and `PoolExhausted` otherwise
    /// (3.6).
    pub(crate) fn claim(&mut self) -> Result<ClaimedSlot, ClaimError> {
        while let Some(slot) = self.free.pop() {
            let Some(meta) = usize::try_from(slot)
                .ok()
                .and_then(|index| self.meta.get_mut(index))
            else {
                debug_assert!(false, "a free index names a slot of the pool");
                continue;
            };
            debug_assert_eq!(meta.state, SlotState::Free);
            match meta
                .last_generation
                .checked_add(1)
                .and_then(NonZeroU64::new)
            {
                Some(generation) => {
                    meta.state = SlotState::Claimed;
                    meta.last_generation = generation.get();
                    return Ok(ClaimedSlot { slot, generation });
                }
                // Unreachable while `free_slot` retires exhausted slots;
                // kept so a slot can never be granted a reused generation.
                None => self.retire(slot),
            }
        }
        if self.retired > 0 {
            Err(ClaimError::IdentityExhausted)
        } else {
            Err(ClaimError::PoolExhausted)
        }
    }

    /// Claimed to Pending: a successful commit.
    pub(crate) fn commit(&mut self, slot: u32) -> bool {
        self.transition(slot, SlotState::Claimed, SlotState::Pending)
    }

    /// Claimed to Free: the frame was dropped.
    pub(crate) fn release_claim(&mut self, slot: u32) -> bool {
        self.state(slot) == Some(SlotState::Claimed) && self.free_slot(slot)
    }

    /// Pending to Free: the item was submitted with release at submission,
    /// or returned without exposure.
    pub(crate) fn release_pending(&mut self, slot: u32) -> bool {
        self.state(slot) == Some(SlotState::Pending) && self.free_slot(slot)
    }

    /// Pending to Quarantined: exposure unproven.
    pub(crate) fn quarantine(&mut self, slot: u32) -> bool {
        self.transition(slot, SlotState::Pending, SlotState::Quarantined)
    }

    /// Frees every Quarantined slot (reset, once nothing is pending) and
    /// returns how many.
    pub(crate) fn release_quarantined(&mut self) -> usize {
        (0..self.slot_count())
            .filter(|slot| {
                self.state(*slot) == Some(SlotState::Quarantined) && self.free_slot(*slot)
            })
            .count()
    }

    /// The slot count as a slot index bound; it fits, as `new` takes a
    /// `u16` count.
    fn slot_count(&self) -> u32 {
        u32::try_from(self.meta.len()).unwrap_or_default()
    }

    fn meta_of(&self, slot: u32) -> Option<&Meta> {
        usize::try_from(slot)
            .ok()
            .and_then(|index| self.meta.get(index))
    }

    fn meta_of_mut(&mut self, slot: u32) -> Option<&mut Meta> {
        usize::try_from(slot)
            .ok()
            .and_then(|index| self.meta.get_mut(index))
    }

    fn transition(&mut self, slot: u32, from: SlotState, to: SlotState) -> bool {
        match self.meta_of_mut(slot) {
            Some(meta) if meta.state == from => {
                meta.state = to;
                true
            }
            _ => false,
        }
    }

    /// Returns `slot` to the free list, or retires it when its generation
    /// cannot advance again.
    fn free_slot(&mut self, slot: u32) -> bool {
        let Some(meta) = self.meta_of_mut(slot) else {
            return false;
        };
        if meta.last_generation == u64::MAX {
            self.retire(slot);
        } else {
            meta.state = SlotState::Free;
            debug_assert!(self.free.len() < self.free.capacity());
            self.free.push(slot);
        }
        true
    }

    fn retire(&mut self, slot: u32) {
        if let Some(meta) = self.meta_of_mut(slot) {
            meta.state = SlotState::Retired;
            // At most one retirement per slot, and slots fit in a `u16`.
            if let Some(retired) = self.retired.checked_add(1) {
                self.retired = retired;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn set_last_generation(&mut self, slot: u32, generation: u64) {
        if let Some(meta) = self.meta_of_mut(slot) {
            meta.last_generation = generation;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(slots: u16) -> SlotPool {
        SlotPool::new(NonZeroU16::new(slots).unwrap())
    }

    #[test]
    fn generations_start_at_one_and_advance_per_claim() {
        let mut pool = pool(1);
        assert_eq!(pool.generation(0), None);
        let first = pool.claim().unwrap();
        assert_eq!((first.slot, first.generation.get()), (0, 1));
        assert!(pool.release_claim(0));
        let second = pool.claim().unwrap();
        assert_eq!((second.slot, second.generation.get()), (0, 2));
        assert!(pool.commit(0));
        assert!(pool.release_pending(0));
        assert_eq!(pool.claim().unwrap().generation.get(), 3);
    }

    #[test]
    fn an_empty_pool_without_retirement_is_pool_exhausted() {
        let mut pool = pool(2);
        assert_eq!(pool.claim().unwrap().slot, 0);
        assert_eq!(pool.claim().unwrap().slot, 1);
        assert_eq!(pool.claim(), Err(ClaimError::PoolExhausted));
        assert_eq!(pool.retired_count(), 0);
    }

    #[test]
    fn identity_generation_overflow_retires_the_slot() {
        let mut pool = pool(2);
        pool.set_last_generation(0, u64::MAX - 1);
        let last = pool.claim().unwrap();
        assert_eq!((last.slot, last.generation.get()), (0, u64::MAX));
        assert!(pool.release_claim(0));
        assert_eq!(pool.state(0), Some(SlotState::Retired));
        assert_eq!(pool.retired_count(), 1);
        // The other slot is still claimable.
        assert_eq!(pool.claim().unwrap().slot, 1);
        // Once no other slot is free, the result is IdentityExhausted.
        assert_eq!(pool.claim(), Err(ClaimError::IdentityExhausted));
        // A retired slot leaves no state transition.
        assert!(!pool.release_claim(0));
        assert!(!pool.commit(0));
    }

    #[test]
    fn a_free_slot_with_an_exhausted_generation_is_never_granted() {
        let mut pool = pool(1);
        pool.set_last_generation(0, u64::MAX);
        assert_eq!(pool.claim(), Err(ClaimError::IdentityExhausted));
        assert_eq!(pool.state(0), Some(SlotState::Retired));
    }

    #[test]
    fn quarantined_slots_return_only_at_reset() {
        let mut pool = pool(2);
        pool.claim().unwrap();
        assert!(pool.commit(0));
        assert!(pool.quarantine(0));
        assert!(
            !pool.release_pending(0),
            "a quarantined slot is not pending"
        );
        pool.claim().unwrap();
        assert_eq!(pool.claim(), Err(ClaimError::PoolExhausted));
        assert_eq!(pool.release_quarantined(), 1);
        assert_eq!(pool.state(0), Some(SlotState::Free));
        assert_eq!(pool.claim().unwrap().generation.get(), 2);
    }

    #[test]
    fn transitions_require_their_source_state() {
        let mut pool = pool(1);
        assert!(!pool.commit(0));
        assert!(!pool.quarantine(0));
        assert!(!pool.release_claim(0));
        assert!(!pool.release_pending(0));
        assert!(!pool.commit(7));
        assert_eq!(pool.state(7), None);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.free_count(), 1);
    }
}
