// SPDX-License-Identifier: Apache-2.0

//! The [`RingOps`] seam of the `io_uring` TX path (`quantstratum-docs:
//! karyos/design/io-uring-backend.md` section 2): the only way the state
//! machine of [`super::tx`] reaches a ring.
//!
//! The seam owns the staging memory the kernel reads, the slot bytes and
//! the `msghdr`, `iovec` and destination address of every slot (3.1), so
//! the rule "no frame is touched while the kernel owns it" (SPEC.md
//! §16.7) is enforced by the implementation of the seam and not by the
//! state machine: a slot is kernel owned from the [`RingOps::push_send`]
//! that names it until [`RingOps::reap`] returns the completion whose
//! `user_data` equals the one pushed, and while it is kernel owned
//! [`RingOps::bytes_mut`] returns `None` and no second send of it is
//! accepted. A completion of any other `user_data` never ends kernel
//! ownership, so a stale or duplicated completion cannot free a slot
//! (3.4).

#![forbid(unsafe_code)]

use std::net::SocketAddr;

/// Control slots of a TX ring for cancel operations (`K`, design 3.4 and
/// 5.3): indices `tx_slots..tx_slots + CONTROL_SLOTS` of `user_data`.
pub const CONTROL_SLOTS: u16 = 8;

/// Bits of a slot generation carried in `user_data` (IU-11).
const GENERATION_BITS: u32 = 48;
/// The mask of those bits.
const GENERATION_MASK: u64 = (1 << GENERATION_BITS) - 1;

/// The 64-bit identity of one operation in flight (IU-11): the 16-bit
/// slot index in the high bits and the low 48 bits of the slot generation
/// in the low bits. The full identity stays in the slot metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserData(u64);

impl UserData {
    /// The `user_data` of an operation of slot `index` in its generation
    /// `generation`; only the low 48 bits of the generation are kept.
    #[must_use]
    pub const fn new(index: u16, generation: u64) -> Self {
        // Widening a `u16` into the top 16 bits of a `u64` cannot lose a
        // bit; `u64::from` is not `const`.
        let high = (index as u64) << GENERATION_BITS;
        Self(high | (generation & GENERATION_MASK))
    }

    /// The value as the kernel carries it.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// A value read back from a completion.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The slot index.
    #[must_use]
    pub const fn index(self) -> u16 {
        // The shift leaves 16 bits, so the conversion is exact.
        (self.0 >> GENERATION_BITS) as u16
    }

    /// The low 48 bits of the generation.
    #[must_use]
    pub const fn generation_bits(self) -> u64 {
        self.0 & GENERATION_MASK
    }

    /// Whether this names generation `generation` of slot `index`.
    #[must_use]
    pub const fn names(self, index: u16, generation: u64) -> bool {
        self.0 == Self::new(index, generation).0
    }
}

/// One completion as [`RingOps::reap`] copies it out of the CQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cqe {
    /// The `user_data` of the operation it completes.
    pub user_data: UserData,
    /// The result: a byte count or a negated errno.
    pub result: i32,
    /// The CQE flags.
    pub flags: u32,
}

impl Cqe {
    /// An empty entry for the stack arrays `reap` fills.
    pub const EMPTY: Self = Self {
        user_data: UserData(0),
        result: 0,
        flags: 0,
    };
}

/// What a cancel operation targets (design 10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelTarget {
    /// The one operation of this `user_data`.
    One(UserData),
    /// Every operation of the ring: `IORING_ASYNC_CANCEL_ANY |
    /// IORING_ASYNC_CANCEL_ALL`. The cancel's own result is the number of
    /// requests it cancelled, which is diagnostic only.
    All,
}

/// Why a push was refused. Nothing was written to the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// No SQ entry is free.
    Full,
    /// The slot is still kernel owned.
    KernelOwned,
    /// The slot index or the length is outside the ring's storage.
    OutOfRange,
}

/// A raw OS error number of a ring call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

/// `EINTR`.
pub const EINTR: i32 = 4;
/// `EAGAIN`.
pub const EAGAIN: i32 = 11;
/// `EBUSY`: `io_uring_enter` with a CQ overflow backlog.
pub const EBUSY: i32 = 16;
/// `EBADR`: completions were dropped.
pub const EBADR: i32 = 53;

/// The ring operations of one TX half (design section 2). The only
/// implementation that reaches a kernel is `ring::OsRing` (Linux, feature
/// `uring`); [`super::scripted::ScriptedRing`] replays completions for the
/// state machine tests.
pub trait RingOps {
    /// The slots of the staging pool, each `slot_len` bytes.
    fn slots(&self) -> u16;

    /// The bytes of one slot.
    fn slot_len(&self) -> u16;

    /// The bytes of `slot` for the caller to write, or `None` while the
    /// kernel owns the slot or for an index outside the pool.
    fn bytes_mut(&mut self, slot: u16) -> Option<&mut [u8]>;

    /// SQ entries free now. Never more than the SQ size.
    fn sq_free(&mut self) -> usize;

    /// Publishes one copied `SENDMSG` of the first `len` bytes of `slot`
    /// to `destination` under `user_data`. On success the slot is kernel
    /// owned until the completion of that `user_data` is reaped.
    ///
    /// # Errors
    ///
    /// [`PushError`]; nothing was published.
    fn push_send(
        &mut self,
        slot: u16,
        len: u16,
        destination: SocketAddr,
        user_data: UserData,
    ) -> Result<(), PushError>;

    /// Publishes one cancel of `target` under `user_data`.
    ///
    /// # Errors
    ///
    /// [`PushError::Full`]; nothing was published.
    fn push_cancel(&mut self, target: CancelTarget, user_data: UserData) -> Result<(), PushError>;

    /// One `io_uring_enter` that submits every published SQE and never
    /// waits for a completion (`min_complete` 0, design 7). Returns the
    /// SQEs the kernel consumed.
    ///
    /// # Errors
    ///
    /// The raw errno: `EINTR` and `EAGAIN` leave the SQEs for the next
    /// enter; `EBUSY` and `EBADR` are the overflow invariant (5.2).
    fn enter(&mut self) -> Result<u32, Errno>;

    /// Whether an enter is due without a new SQE: SQEs remain unconsumed
    /// or the kernel waits for task work (`IORING_SQ_TASKRUN`).
    fn needs_enter(&mut self) -> bool;

    /// Copies up to `out.len()` completions out of the CQ and returns how
    /// many. Ends kernel ownership of each slot whose pushed `user_data` a
    /// completion carries, before it returns.
    fn reap(&mut self, out: &mut [Cqe]) -> usize;

    /// Whether the kernel reported a CQ overflow or dropped completions.
    fn cq_overflowed(&mut self) -> bool;

    /// Slots the kernel owns now.
    fn kernel_owned(&self) -> u16;
}
