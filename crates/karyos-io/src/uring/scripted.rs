// SPDX-License-Identifier: Apache-2.0

//! [`ScriptedRing`], the [`RingOps`] test double (design section 2): it
//! records every push and enter and returns the completions a test
//! scripts, under the same kernel ownership rule as the real ring, so the
//! state machine runs on any OS and under Miri without a kernel.
//!
//! Every collection is reserved at construction, so the data calls of the
//! state machine stay allocation free over it too.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::net::SocketAddr;

use super::ops::{CONTROL_SLOTS, CancelTarget, Cqe, Errno, PushError, RingOps, UserData};

/// Entries every log of the double holds without reallocating.
const LOG: usize = 4096;

/// One operation a push published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// A copied `SENDMSG`.
    Send {
        /// The slot.
        slot: u16,
        /// The bytes sent.
        len: u16,
        /// The destination.
        destination: SocketAddr,
        /// Its `user_data`.
        user_data: UserData,
    },
    /// A cancel.
    Cancel {
        /// What it cancels.
        target: CancelTarget,
        /// Its `user_data`.
        user_data: UserData,
    },
}

/// The scripted ring.
#[derive(Debug)]
pub struct ScriptedRing {
    slot_len: u16,
    bytes: Vec<Box<[u8]>>,
    /// The `user_data` each kernel owned slot was pushed under.
    owned: Vec<Option<UserData>>,
    sq_size: usize,
    /// Published and not yet consumed by an enter.
    unconsumed: usize,
    pushed: Vec<Pushed>,
    cq: VecDeque<Cqe>,
    enter_results: VecDeque<Result<u32, Errno>>,
    enters: u32,
    overflowed: bool,
    taskrun: bool,
}

impl ScriptedRing {
    /// A ring of `slots` slots of `slot_len` bytes and an SQ of `sq_size`
    /// entries.
    #[must_use]
    pub fn new(slots: u16, slot_len: u16, sq_size: usize) -> Self {
        Self {
            slot_len,
            bytes: (0..slots)
                .map(|_| vec![0; usize::from(slot_len)].into_boxed_slice())
                .collect(),
            owned: vec![None; usize::from(slots)],
            sq_size,
            unconsumed: 0,
            pushed: Vec::with_capacity(LOG),
            cq: VecDeque::with_capacity(LOG),
            enter_results: VecDeque::with_capacity(LOG),
            enters: 0,
            overflowed: false,
            taskrun: false,
        }
    }

    /// Every operation published so far, in order.
    #[must_use]
    pub fn pushed(&self) -> &[Pushed] {
        &self.pushed
    }

    /// Enters so far.
    #[must_use]
    pub fn enters(&self) -> u32 {
        self.enters
    }

    /// SQEs published and not consumed.
    #[must_use]
    pub fn unconsumed(&self) -> usize {
        self.unconsumed
    }

    /// The bytes of `slot`, as the kernel would read them.
    #[must_use]
    pub fn slot_bytes(&self, slot: u16) -> Option<&[u8]> {
        self.bytes.get(usize::from(slot)).map(|bytes| &**bytes)
    }

    /// The `user_data` `slot` is kernel owned under.
    #[must_use]
    pub fn owner(&self, slot: u16) -> Option<UserData> {
        self.owned.get(usize::from(slot)).copied().flatten()
    }

    /// Queues a completion of `user_data`.
    pub fn complete(&mut self, user_data: UserData, result: i32, flags: u32) {
        self.cq.push_back(Cqe {
            user_data,
            result,
            flags,
        });
    }

    /// Queues the completion of the send kernel owned in `slot`; false
    /// if the slot is not kernel owned.
    pub fn complete_slot(&mut self, slot: u16, result: i32) -> bool {
        match self.owner(slot) {
            Some(user_data) => {
                self.complete(user_data, result, 0);
                true
            }
            None => false,
        }
    }

    /// The result of the next enter instead of consuming every SQE.
    pub fn fail_next_enter(&mut self, errno: i32) {
        self.enter_results.push_back(Err(Errno(errno)));
    }

    /// Marks the CQ overflowed.
    pub fn set_overflowed(&mut self) {
        self.overflowed = true;
    }

    /// Sets `IORING_SQ_TASKRUN`.
    pub fn set_taskrun(&mut self, taskrun: bool) {
        self.taskrun = taskrun;
    }

    fn take_sq(&mut self) -> Result<(), PushError> {
        if self.unconsumed >= self.sq_size {
            return Err(PushError::Full);
        }
        self.unconsumed = self.unconsumed.checked_add(1).ok_or(PushError::Full)?;
        Ok(())
    }
}

impl RingOps for ScriptedRing {
    fn slots(&self) -> u16 {
        u16::try_from(self.bytes.len()).unwrap_or(u16::MAX)
    }

    fn slot_len(&self) -> u16 {
        self.slot_len
    }

    fn bytes_mut(&mut self, slot: u16) -> Option<&mut [u8]> {
        if self.owner(slot).is_some() {
            return None;
        }
        self.bytes
            .get_mut(usize::from(slot))
            .map(|bytes| &mut **bytes)
    }

    fn sq_free(&mut self) -> usize {
        self.sq_size.saturating_sub(self.unconsumed)
    }

    fn push_send(
        &mut self,
        slot: u16,
        len: u16,
        destination: SocketAddr,
        user_data: UserData,
    ) -> Result<(), PushError> {
        if len > self.slot_len || usize::from(slot) >= self.owned.len() {
            return Err(PushError::OutOfRange);
        }
        if self.owner(slot).is_some() {
            return Err(PushError::KernelOwned);
        }
        self.take_sq()?;
        if let Some(owner) = self.owned.get_mut(usize::from(slot)) {
            *owner = Some(user_data);
        }
        self.pushed.push(Pushed::Send {
            slot,
            len,
            destination,
            user_data,
        });
        Ok(())
    }

    fn push_cancel(&mut self, target: CancelTarget, user_data: UserData) -> Result<(), PushError> {
        debug_assert!(
            user_data
                .index()
                .checked_sub(self.slots())
                .is_some_and(|control| control < CONTROL_SLOTS),
            "a cancel runs in a control slot"
        );
        self.take_sq()?;
        self.pushed.push(Pushed::Cancel { target, user_data });
        Ok(())
    }

    fn enter(&mut self) -> Result<u32, Errno> {
        self.enters = self.enters.saturating_add(1);
        if let Some(Err(errno)) = self.enter_results.pop_front() {
            return Err(errno);
        }
        let consumed = u32::try_from(self.unconsumed).unwrap_or(u32::MAX);
        self.unconsumed = 0;
        self.taskrun = false;
        Ok(consumed)
    }

    fn needs_enter(&mut self) -> bool {
        self.unconsumed > 0 || self.taskrun
    }

    fn reap(&mut self, out: &mut [Cqe]) -> usize {
        let mut reaped: usize = 0;
        for entry in out.iter_mut() {
            let Some(cqe) = self.cq.pop_front() else {
                break;
            };
            if let Some(owner) = self.owned.get_mut(usize::from(cqe.user_data.index()))
                && *owner == Some(cqe.user_data)
            {
                *owner = None;
            }
            *entry = cqe;
            reaped = reaped.saturating_add(1);
        }
        reaped
    }

    fn cq_overflowed(&mut self) -> bool {
        self.overflowed
    }

    fn kernel_owned(&self) -> u16 {
        let owned = self.owned.iter().filter(|owner| owner.is_some()).count();
        u16::try_from(owned).unwrap_or(u16::MAX)
    }
}
