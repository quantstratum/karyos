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

use super::ops::{
    CONTROL_SLOTS, CQE_BUFFER_SHIFT, CQE_F_BUFFER, CQE_F_MORE, CancelTarget, Cqe, ENOBUFS, Errno,
    PushError, RECVMSG_OUT, RX_NAME_LEN, RingOps, RxRingOps, UserData,
};

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
    /// `bytes_mut` calls on a kernel owned slot: a frame touched while the
    /// kernel owns it, which the double refuses and counts (SPEC.md §13,
    /// "Backend ring and frame ownership").
    touches_while_owned: u64,
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
            touches_while_owned: 0,
        }
    }

    /// Writes attempted on a kernel owned slot so far.
    #[must_use]
    pub fn touches_while_owned(&self) -> u64 {
        self.touches_while_owned
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
            self.touches_while_owned = self.touches_while_owned.saturating_add(1);
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
        if len > self.slot_len || usize::from(slot) >= self.owned.len() || user_data.index() != slot
        {
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
        // As the real ring: a control identity never names a send slot.
        let control = user_data.index().checked_sub(self.slots());
        if !control.is_some_and(|control| control < CONTROL_SLOTS) {
            return Err(PushError::OutOfRange);
        }
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

/// Where one scripted RX buffer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Buffer {
    Posted,
    Completed,
}

/// [`RxRingOps`] test double: [`ScriptedRxRing::deliver`] writes a
/// datagram into the next Posted buffer exactly as the kernel lays it out
/// (`io_uring_recvmsg_out`, the name area, the payload) and queues its
/// completion; with none Posted it ends the arm with `-ENOBUFS`.
#[derive(Debug)]
pub struct ScriptedRxRing {
    bytes: Vec<Box<[u8]>>,
    state: Vec<Buffer>,
    /// Posted buffers in the order the kernel takes them.
    ring: VecDeque<u16>,
    arm: Option<UserData>,
    cq: VecDeque<Cqe>,
    pushed: Vec<Pushed>,
    arms: u32,
    unconsumed: usize,
    registrations: u32,
    overflowed: bool,
    /// A lend that would hand out a buffer the kernel may write: a test
    /// that sets it checks the guard of the state machine, not the ring.
    lent_posted: u32,
}

impl ScriptedRxRing {
    /// `buffers` buffers of `buffer_len` bytes, every one Posted.
    #[must_use]
    pub fn new(buffers: u16, buffer_len: u32) -> Self {
        let len = usize::try_from(buffer_len).unwrap_or(0);
        Self {
            bytes: (0..buffers)
                .map(|_| vec![0; len].into_boxed_slice())
                .collect(),
            state: vec![Buffer::Posted; usize::from(buffers)],
            ring: (0..buffers).collect(),
            arm: None,
            cq: VecDeque::with_capacity(LOG),
            pushed: Vec::with_capacity(LOG),
            arms: 0,
            unconsumed: 0,
            registrations: 1,
            overflowed: false,
            lent_posted: 0,
        }
    }

    /// Arms published so far.
    #[must_use]
    pub fn arms(&self) -> u32 {
        self.arms
    }

    /// Buffer ring registrations so far, the first at construction.
    #[must_use]
    pub fn registrations(&self) -> u32 {
        self.registrations
    }

    /// Every cancel and arm published, in order.
    #[must_use]
    pub fn pushed(&self) -> &[Pushed] {
        &self.pushed
    }

    /// The current arm's `user_data`.
    #[must_use]
    pub fn arm_user_data(&self) -> Option<UserData> {
        self.arm
    }

    /// Lends refused because the buffer was Posted.
    #[must_use]
    pub fn lent_posted(&self) -> u32 {
        self.lent_posted
    }

    /// Writes `payload` from `source` into the next Posted buffer and
    /// queues its completion; `flags` of the recvmsg header (`MSG_TRUNC`
    /// is `0x20`). Ends the arm with `-ENOBUFS` when none is Posted.
    /// Returns the buffer used.
    pub fn deliver(&mut self, payload: &[u8], source: SocketAddr, flags: u32) -> Option<u16> {
        let arm = self.arm?;
        let Some(id) = self.ring.pop_front() else {
            self.end_arm(-ENOBUFS);
            return None;
        };
        let buffer = self.bytes.get_mut(usize::from(id))?;
        let name = usize::try_from(RX_NAME_LEN).unwrap_or(0);
        let start = RECVMSG_OUT.saturating_add(name);
        let room = buffer.len().saturating_sub(start);
        let copied = payload.len().min(room);
        let payload_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let mut header = [0_u8; RECVMSG_OUT];
        let (name_bytes, namelen) = encode(source);
        for (at, value) in [namelen, 0, payload_len, flags].into_iter().enumerate() {
            let offset = at.saturating_mul(4);
            if let Some(field) = header.get_mut(offset..offset.saturating_add(4)) {
                field.copy_from_slice(&value.to_ne_bytes());
            }
        }
        if let Some(target) = buffer.get_mut(..RECVMSG_OUT) {
            target.copy_from_slice(&header);
        }
        if let Some(target) = buffer.get_mut(RECVMSG_OUT..start) {
            target.copy_from_slice(&name_bytes);
        }
        if let (Some(target), Some(source)) = (
            buffer.get_mut(start..start.saturating_add(copied)),
            payload.get(..copied),
        ) {
            target.copy_from_slice(source);
        }
        if let Some(state) = self.state.get_mut(usize::from(id)) {
            *state = Buffer::Completed;
        }
        let total = i32::try_from(start.saturating_add(copied)).unwrap_or(i32::MAX);
        self.cq.push_back(Cqe {
            user_data: arm,
            result: total,
            flags: CQE_F_BUFFER | CQE_F_MORE | (u32::from(id) << CQE_BUFFER_SHIFT),
        });
        Some(id)
    }

    /// Ends the arm with a terminal completion of `result`.
    pub fn end_arm(&mut self, result: i32) {
        if let Some(arm) = self.arm {
            self.cq.push_back(Cqe {
                user_data: arm,
                result,
                flags: 0,
            });
        }
    }

    /// Queues any completion.
    pub fn complete(&mut self, user_data: UserData, result: i32, flags: u32) {
        self.cq.push_back(Cqe {
            user_data,
            result,
            flags,
        });
    }

    /// Marks the CQ overflowed.
    pub fn set_overflowed(&mut self) {
        self.overflowed = true;
    }
}

/// A `sockaddr_in` or `sockaddr_in6` in the 28-byte name area.
fn encode(address: SocketAddr) -> ([u8; 28], u32) {
    let mut name = [0_u8; 28];
    let mut put = |at: usize, bytes: &[u8]| {
        if let Some(target) = name.get_mut(at..at.saturating_add(bytes.len())) {
            target.copy_from_slice(bytes);
        }
    };
    match address {
        SocketAddr::V4(v4) => {
            put(0, &2_u16.to_ne_bytes());
            put(2, &v4.port().to_be_bytes());
            put(4, &v4.ip().octets());
            (name, 16)
        }
        SocketAddr::V6(v6) => {
            put(0, &10_u16.to_ne_bytes());
            put(2, &v6.port().to_be_bytes());
            put(4, &v6.flowinfo().to_be_bytes());
            put(8, &v6.ip().octets());
            put(24, &v6.scope_id().to_ne_bytes());
            (name, 28)
        }
    }
}

impl RxRingOps for ScriptedRxRing {
    fn buffers(&self) -> u16 {
        u16::try_from(self.bytes.len()).unwrap_or(u16::MAX)
    }

    fn buffer_len(&self) -> u32 {
        self.bytes
            .first()
            .and_then(|bytes| u32::try_from(bytes.len()).ok())
            .unwrap_or(0)
    }

    fn arm(&mut self, user_data: UserData) -> Result<(), PushError> {
        if self.arm.is_some() || user_data.index() != 0 {
            return Err(PushError::KernelOwned);
        }
        if self.unconsumed >= LOG {
            return Err(PushError::Full);
        }
        self.unconsumed = self.unconsumed.saturating_add(1);
        self.arm = Some(user_data);
        self.arms = self.arms.saturating_add(1);
        Ok(())
    }

    fn push_cancel(&mut self, target: CancelTarget, user_data: UserData) -> Result<(), PushError> {
        if user_data.index() == 0 {
            return Err(PushError::OutOfRange);
        }
        self.unconsumed = self.unconsumed.saturating_add(1);
        self.pushed.push(Pushed::Cancel { target, user_data });
        Ok(())
    }

    fn enter(&mut self) -> Result<u32, Errno> {
        let consumed = u32::try_from(self.unconsumed).unwrap_or(u32::MAX);
        self.unconsumed = 0;
        Ok(consumed)
    }

    fn needs_enter(&mut self) -> bool {
        self.unconsumed > 0
    }

    fn reap(&mut self, out: &mut [Cqe]) -> usize {
        let mut reaped: usize = 0;
        for entry in out.iter_mut() {
            let Some(cqe) = self.cq.pop_front() else {
                break;
            };
            if Some(cqe.user_data) == self.arm && cqe.flags & CQE_F_MORE == 0 {
                self.arm = None;
            }
            *entry = cqe;
            reaped = reaped.saturating_add(1);
        }
        reaped
    }

    fn lend<T>(&mut self, id: u16, lend: impl FnOnce(&[u8]) -> T) -> Option<T> {
        let index = usize::from(id);
        match self.state.get(index) {
            Some(Buffer::Completed) => {}
            Some(Buffer::Posted) => {
                self.lent_posted = self.lent_posted.saturating_add(1);
                return None;
            }
            None => return None,
        }
        struct Repost<'a> {
            state: &'a mut Buffer,
            ring: &'a mut VecDeque<u16>,
            id: u16,
        }
        impl Drop for Repost<'_> {
            fn drop(&mut self) {
                *self.state = Buffer::Posted;
                self.ring.push_back(self.id);
            }
        }
        let state = self.state.get_mut(index)?;
        let bytes = self.bytes.get(index)?;
        let _repost = Repost {
            state,
            ring: &mut self.ring,
            id,
        };
        Some(lend(bytes))
    }

    fn posted(&self) -> u16 {
        let posted = self
            .state
            .iter()
            .filter(|state| **state == Buffer::Posted)
            .count();
        u16::try_from(posted).unwrap_or(u16::MAX)
    }

    fn arm_live(&self) -> bool {
        self.arm.is_some()
    }

    fn cq_overflowed(&mut self) -> bool {
        self.overflowed
    }

    fn reregister(&mut self) -> Result<(), Errno> {
        if self.arm.is_some() {
            return Err(Errno(16));
        }
        self.state.fill(Buffer::Posted);
        self.ring.clear();
        self.ring.extend(0..self.buffers());
        self.registrations = self.registrations.saturating_add(1);
        Ok(())
    }
}
