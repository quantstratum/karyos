// SPDX-License-Identifier: Apache-2.0

//! [`ScriptedXsk`], the [`XskOps`] test double: a UMEM in heap memory and
//! rings the test drives, under the same ownership rules as the real
//! socket, so the endpoint runs on any OS and under Miri.

#![forbid(unsafe_code)]

use std::collections::VecDeque;

use super::ops::{Completion, Errno, RxDesc, XskOps};

/// Entries every queue of the double holds without reallocating.
const LOG: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxFrame {
    Posted,
    Completed,
}

/// The scripted socket.
#[derive(Debug)]
pub struct ScriptedXsk {
    frame_len: u32,
    tx: Vec<Box<[u8]>>,
    tx_owned: Vec<bool>,
    tx_ring: usize,
    /// Written descriptors not yet published.
    tx_unpublished: VecDeque<(u16, u32)>,
    /// Published descriptors the "kernel" has not consumed.
    tx_published: VecDeque<(u16, u32)>,
    /// Descriptors the kernel consumed and sent, in order.
    sent: Vec<(u16, Vec<u8>)>,
    completions: VecDeque<u64>,
    rx: Vec<Box<[u8]>>,
    rx_state: Vec<RxFrame>,
    /// Posted frames in fill ring order.
    fill: VecDeque<u32>,
    rx_ring: VecDeque<RxDesc>,
    kicks: u32,
    kick_errors: VecDeque<i32>,
    need_wakeup: bool,
    touches_while_owned: u64,
}

impl ScriptedXsk {
    /// `tx` TX frames and `rx` RX frames of `frame_len` bytes, a TX ring of
    /// `tx_ring` entries, every RX frame posted.
    #[must_use]
    pub fn new(frame_len: u32, tx: u16, rx: u32, tx_ring: usize) -> Self {
        let len = usize::try_from(frame_len).unwrap_or(0);
        Self {
            frame_len,
            tx: (0..tx).map(|_| vec![0; len].into_boxed_slice()).collect(),
            tx_owned: vec![false; usize::from(tx)],
            tx_ring,
            tx_unpublished: VecDeque::with_capacity(LOG),
            tx_published: VecDeque::with_capacity(LOG),
            sent: Vec::with_capacity(LOG),
            completions: VecDeque::with_capacity(LOG),
            rx: (0..rx).map(|_| vec![0; len].into_boxed_slice()).collect(),
            rx_state: vec![RxFrame::Posted; usize::try_from(rx).unwrap_or(0)],
            fill: (0..rx).collect(),
            rx_ring: VecDeque::with_capacity(LOG),
            kicks: 0,
            kick_errors: VecDeque::with_capacity(LOG),
            need_wakeup: true,
            touches_while_owned: 0,
        }
    }

    /// The "kernel" consumes every published TX descriptor: records the
    /// bytes it reads and queues a completion of each frame's address.
    pub fn transmit(&mut self) {
        while let Some((frame, len)) = self.tx_published.pop_front() {
            let bytes = self
                .tx
                .get(usize::from(frame))
                .and_then(|bytes| bytes.get(..usize::try_from(len).unwrap_or(0)))
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            self.sent.push((frame, bytes));
            self.completions
                .push_back(u64::from(frame).saturating_mul(u64::from(self.frame_len)));
        }
    }

    /// Frames the kernel sent, with the bytes it read.
    #[must_use]
    pub fn sent(&self) -> &[(u16, Vec<u8>)] {
        &self.sent
    }

    /// Queues a completion entry of any address.
    pub fn complete_addr(&mut self, addr: u64) {
        self.completions.push_back(addr);
    }

    /// Kicks so far.
    #[must_use]
    pub fn kicks(&self) -> u32 {
        self.kicks
    }

    /// The result of the next kick.
    pub fn fail_next_kick(&mut self, errno: i32) {
        self.kick_errors.push_back(errno);
    }

    /// `tx_frame_mut` calls on a kernel owned frame.
    #[must_use]
    pub fn touches_while_owned(&self) -> u64 {
        self.touches_while_owned
    }

    /// The "kernel" receives `frame_bytes` into the next Posted RX frame
    /// and writes its descriptor; `false` when no frame is Posted.
    pub fn receive(&mut self, frame_bytes: &[u8]) -> bool {
        let Some(index) = self.fill.pop_front() else {
            return false;
        };
        let Some(buffer) = self
            .rx
            .get_mut(usize::try_from(index).unwrap_or(usize::MAX))
        else {
            return false;
        };
        let len = frame_bytes.len().min(buffer.len());
        if let (Some(target), Some(source)) = (buffer.get_mut(..len), frame_bytes.get(..len)) {
            target.copy_from_slice(source);
        }
        let base = self.rx_base(index);
        self.rx_ring.push_back(RxDesc {
            addr: base,
            len: u32::try_from(len).unwrap_or(0),
        });
        true
    }

    /// Writes any RX descriptor.
    pub fn push_rx_desc(&mut self, desc: RxDesc) {
        self.rx_ring.push_back(desc);
    }

    fn rx_base(&self, index: u32) -> u64 {
        let tx = u64::try_from(self.tx.len()).unwrap_or(0);
        tx.saturating_add(u64::from(index))
            .saturating_mul(u64::from(self.frame_len))
    }

    /// The RX frame index and offset of `desc`, if it lies inside one RX
    /// frame.
    fn rx_frame_of(&self, desc: RxDesc) -> Option<(usize, usize)> {
        let frame_len = u64::from(self.frame_len);
        let tx_end = u64::try_from(self.tx.len()).ok()?.checked_mul(frame_len)?;
        let offset = desc.addr.checked_sub(tx_end)?;
        let index = usize::try_from(offset / frame_len).ok()?;
        let within = offset % frame_len;
        let end = within.checked_add(u64::from(desc.len))?;
        if index >= self.rx.len() || end > frame_len {
            return None;
        }
        Some((index, usize::try_from(within).ok()?))
    }
}

impl XskOps for ScriptedXsk {
    fn frame_len(&self) -> u32 {
        self.frame_len
    }

    fn tx_frames(&self) -> u16 {
        u16::try_from(self.tx.len()).unwrap_or(u16::MAX)
    }

    fn rx_frames(&self) -> u32 {
        u32::try_from(self.rx.len()).unwrap_or(u32::MAX)
    }

    fn tx_frame_mut(&mut self, frame: u16) -> Option<&mut [u8]> {
        if self
            .tx_owned
            .get(usize::from(frame))
            .copied()
            .unwrap_or(true)
        {
            self.touches_while_owned = self.touches_while_owned.saturating_add(1);
            return None;
        }
        self.tx
            .get_mut(usize::from(frame))
            .map(|bytes| &mut **bytes)
    }

    fn tx_free(&mut self) -> u32 {
        let used = self
            .tx_unpublished
            .len()
            .saturating_add(self.tx_published.len());
        u32::try_from(self.tx_ring.saturating_sub(used)).unwrap_or(0)
    }

    fn push_tx(&mut self, frame: u16, len: u32) -> bool {
        if self.tx_free() == 0 || len > self.frame_len {
            return false;
        }
        match self.tx_owned.get_mut(usize::from(frame)) {
            Some(owned) if !*owned => *owned = true,
            _ => return false,
        }
        self.tx_unpublished.push_back((frame, len));
        true
    }

    fn publish_tx(&mut self) {
        self.tx_published.extend(self.tx_unpublished.drain(..));
    }

    fn tx_needs_wakeup(&mut self) -> bool {
        self.need_wakeup
    }

    fn kick_tx(&mut self) -> Result<(), Errno> {
        self.kicks = self.kicks.saturating_add(1);
        match self.kick_errors.pop_front() {
            Some(errno) => Err(Errno(errno)),
            None => Ok(()),
        }
    }

    fn reap_completions(&mut self, out: &mut [Completion]) -> usize {
        let mut reaped: usize = 0;
        let frame_len = u64::from(self.frame_len);
        for entry in out.iter_mut() {
            let Some(addr) = self.completions.pop_front() else {
                break;
            };
            let frame = if addr % frame_len == 0 {
                u16::try_from(addr / frame_len).ok()
            } else {
                None
            };
            *entry = match frame {
                Some(frame)
                    if self
                        .tx_owned
                        .get(usize::from(frame))
                        .copied()
                        .unwrap_or(false) =>
                {
                    if let Some(owned) = self.tx_owned.get_mut(usize::from(frame)) {
                        *owned = false;
                    }
                    Completion::Released { frame }
                }
                _ => Completion::Invalid { addr },
            };
            reaped = reaped.saturating_add(1);
        }
        reaped
    }

    fn reap_rx(&mut self, out: &mut [RxDesc]) -> usize {
        let mut reaped: usize = 0;
        for entry in out.iter_mut() {
            let Some(desc) = self.rx_ring.pop_front() else {
                break;
            };
            if let Some((index, _)) = self.rx_frame_of(desc)
                && let Some(state @ RxFrame::Posted) = self.rx_state.get_mut(index)
            {
                *state = RxFrame::Completed;
            }
            *entry = desc;
            reaped = reaped.saturating_add(1);
        }
        reaped
    }

    fn lend_rx<T>(&mut self, desc: RxDesc, lend: impl FnOnce(&[u8]) -> T) -> Option<T> {
        struct Repost<'a> {
            state: &'a mut RxFrame,
            fill: &'a mut VecDeque<u32>,
            index: u32,
        }
        impl Drop for Repost<'_> {
            fn drop(&mut self) {
                *self.state = RxFrame::Posted;
                self.fill.push_back(self.index);
            }
        }
        let (index, within) = self.rx_frame_of(desc)?;
        let state = self.rx_state.get_mut(index)?;
        if *state != RxFrame::Completed {
            return None;
        }
        let end = within.checked_add(usize::try_from(desc.len).ok()?)?;
        let bytes = self.rx.get(index)?.get(within..end)?;
        let _repost = Repost {
            state,
            fill: &mut self.fill,
            index: u32::try_from(index).ok()?,
        };
        Some(lend(bytes))
    }

    fn publish_fill(&mut self) {}

    fn fill_needs_wakeup(&mut self) -> bool {
        false
    }

    fn kick_rx(&mut self) -> Result<(), Errno> {
        Ok(())
    }

    fn tx_kernel_owned(&self) -> u16 {
        let owned = self.tx_owned.iter().filter(|owned| **owned).count();
        u16::try_from(owned).unwrap_or(u16::MAX)
    }

    fn rx_posted(&self) -> u32 {
        let posted = self
            .rx_state
            .iter()
            .filter(|state| **state == RxFrame::Posted)
            .count();
        u32::try_from(posted).unwrap_or(u32::MAX)
    }
}
