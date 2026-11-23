// SPDX-License-Identifier: Apache-2.0

//! [`OsRing`], the [`RingOps`] of a real `io_uring` over the admitted
//! `io-uring` 0.7 crate (`quantstratum-docs:
//! karyos/reviews/dependency-admission-io-uring.md`; design sections 2,
//! 4.1, 6.1 and 10.3). The only module of `karyos-io` with `unsafe`: one
//! SQE push per block, each with its `// SAFETY:` comment.
//!
//! The ring owns the staging memory the kernel reads: each slot's bytes,
//! and its `msghdr`, `iovec` and destination address in a heap block of
//! its own that never moves (design 3.1). A slot is kernel owned from its
//! push until [`RingOps::reap`] copies out the completion of the same
//! `user_data`, and while it is, [`RingOps::bytes_mut`] refuses it and no
//! second send of it is published. [`Drop`] never frees memory the kernel
//! may still read: with operations outstanding it cancels them, reaps for
//! a bounded number of non-blocking rounds and, if some remain, leaks the
//! staging memory and the socket on purpose (IU-12), counted by
//! [`uring_leaked_bytes`].
//!
//! The `msghdr` and `iovec` the kernel reads are `#[repr(C)]` mirrors of
//! the kernel UAPI (`struct user_msghdr`, `struct iovec`) with their
//! sizes asserted at compile time, so no direct `libc` edge is needed
//! (the admission record's alternative); the opcode takes the pointer as
//! the `libc` type by inference.
//!
//! [`OsRxRing`] is the RX ring: one provided buffer ring
//! (`IORING_REGISTER_PBUF_RING`) whose entries are atomics in page aligned
//! memory, and one multishot `RECVMSG` arm. A buffer is Posted until a
//! reaped completion names it, then Completed until
//! [`RxRingOps::lend`] reposts it; the kernel never writes a buffer that
//! is lent.

use std::mem;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use io_uring::{IoUring, Probe, opcode, squeue, types};
use rustix::net::{AddressFamily, SendFlags, SocketFlags, SocketType};

use super::ops::{
    CONTROL_SLOTS, CQE_F_MORE, CancelTarget, Cqe, Errno, PushError, RX_NAME_LEN, RingOps,
    RxRingOps, UserData, buffer_id,
};
use super::rx::UringRxConfig;
use super::tx::UringTxConfig;
use crate::backend::{CapabilityState, OpenError, Reason};

/// Staging bytes leaked by rings dropped with operations outstanding,
/// over the process (`uring_leaked_bytes`, IU-12).
static LEAKED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Staging bytes leaked on purpose by rings dropped while the kernel
/// still owned some of their slots: memory safe, never reused.
#[must_use]
pub fn uring_leaked_bytes() -> u64 {
    LEAKED_BYTES.load(Ordering::Relaxed)
}

/// Non-blocking reap rounds of [`Drop`] before it leaks.
const DROP_ROUNDS: u32 = 64;

/// `struct iovec` of the kernel UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IoVec {
    base: usize,
    len: usize,
}

/// `struct user_msghdr` of the kernel UAPI: pointers as addresses, sizes
/// as `usize`, which is `__kernel_size_t` on Linux.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MsgHdr {
    name: usize,
    namelen: u32,
    iov: usize,
    iovlen: usize,
    control: usize,
    controllen: usize,
    flags: u32,
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(mem::size_of::<IoVec>() == 16);
    assert!(mem::size_of::<MsgHdr>() == 56);
    assert!(mem::offset_of!(MsgHdr, iov) == 16);
    assert!(mem::offset_of!(MsgHdr, control) == 32);
    assert!(mem::offset_of!(MsgHdr, flags) == 48);
};

/// A `sockaddr_in` or `sockaddr_in6`, built byte by byte.
#[repr(C, align(4))]
#[derive(Debug, Clone, Copy)]
struct SockAddr([u8; 28]);

/// `AF_INET` and `AF_INET6` on Linux.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Copies `bytes` into `buffer` at `at`; out of range writes nothing,
/// which the fixed offsets below rule out.
fn put(buffer: &mut [u8], at: usize, bytes: &[u8]) {
    let end = at.saturating_add(bytes.len());
    if let Some(target) = buffer.get_mut(at..end) {
        target.copy_from_slice(bytes);
    }
}

impl SockAddr {
    /// Encodes `address`; returns its length.
    fn encode(&mut self, address: SocketAddr) -> u32 {
        self.0 = [0; 28];
        let buffer = &mut self.0;
        match address {
            SocketAddr::V4(v4) => {
                put(buffer, 0, &AF_INET.to_ne_bytes());
                put(buffer, 2, &v4.port().to_be_bytes());
                put(buffer, 4, &v4.ip().octets());
                16
            }
            SocketAddr::V6(v6) => {
                put(buffer, 0, &AF_INET6.to_ne_bytes());
                put(buffer, 2, &v6.port().to_be_bytes());
                put(buffer, 4, &v6.flowinfo().to_be_bytes());
                put(buffer, 8, &v6.ip().octets());
                put(buffer, 24, &v6.scope_id().to_ne_bytes());
                28
            }
        }
    }
}

/// What the kernel reads for one send, in a heap block that never moves.
#[derive(Debug)]
struct SlotMsg {
    hdr: MsgHdr,
    iov: IoVec,
    addr: SockAddr,
}

#[derive(Debug)]
struct SlotStore {
    bytes: Box<[u8]>,
    msg: Box<SlotMsg>,
}

/// The capability results of [`OsRing::open`] (design 4.1 and 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsRingProbes {
    /// SQPOLL: `NotRequested` unless configured (IU-2).
    pub sqpoll: CapabilityState,
    /// The socket registered as fixed file 0.
    pub fixed_files: CapabilityState,
    /// Whether a send on a full socket buffer parks rather than completes
    /// with `-EAGAIN` (`uring_send_parks`, IU-5).
    pub send_parks: CapabilityState,
    /// The SQ entries the kernel set up.
    pub sq_entries: u32,
    /// The CQ entries the kernel set up.
    pub cq_entries: u32,
}

/// The ring of one TX half and its own UDP socket, opened without
/// `O_NONBLOCK` so the kernel parks a send on a full buffer (IU-5).
pub struct OsRing {
    ring: IoUring,
    socket: Option<OwnedFd>,
    fixed: bool,
    slot_len: u16,
    store: Box<[SlotStore]>,
    /// The `user_data` each kernel owned slot was pushed under.
    owned: Box<[Option<UserData>]>,
}

impl std::fmt::Debug for OsRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsRing")
            .field("fixed", &self.fixed)
            .field("slots", &self.store.len())
            .field("slot_len", &self.slot_len)
            .field("kernel_owned", &self.kernel_owned())
            .finish_non_exhaustive()
    }
}

fn reason(errno: i32) -> Reason {
    match errno {
        1 | 13 => Reason::Denied { errno },
        38 => Reason::Unsupported { errno },
        errno => Reason::ProbeFailed { errno },
    }
}

fn os(operation: &'static str, errno: i32) -> OpenError {
    OpenError::Os { operation, errno }
}

fn io_errno(error: &std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(0)
}

/// `EOPNOTSUPP`, the errno named when a required ring facility is
/// missing.
const EOPNOTSUPP: i32 = 95;

/// The enter based builder of IU-6: `SUBMIT_ALL`, `COOP_TASKRUN`,
/// `TASKRUN_FLAG` and the CQ size.
fn enter_builder(config: &UringTxConfig) -> io_uring::Builder {
    let mut builder = IoUring::builder();
    builder
        .setup_submit_all()
        .setup_coop_taskrun()
        .setup_taskrun_flag()
        .setup_cqsize(config.cq_entries());
    builder
}

fn build_ring(config: &UringTxConfig) -> Result<(IoUring, CapabilityState), OpenError> {
    let Some(sqpoll) = config.sqpoll else {
        let ring = enter_builder(config)
            .build(config.sq_entries())
            .map_err(|error| os("io_uring_setup", io_errno(&error)))?;
        return Ok((ring, CapabilityState::NotRequested));
    };
    // Linux rejects COOP_TASKRUN and TASKRUN_FLAG with SQPOLL (EINVAL):
    // the SQPOLL builder sets only SUBMIT_ALL and the CQ size.
    let mut polled = IoUring::builder();
    polled
        .setup_submit_all()
        .setup_cqsize(config.cq_entries())
        .setup_sqpoll(sqpoll.idle_ms)
        .setup_sqpoll_cpu(sqpoll.cpu);
    match polled.build(config.sq_entries()) {
        Ok(ring) => Ok((ring, CapabilityState::Active)),
        Err(error) => {
            // A declared fallback to enter based submission (design 8).
            let state = CapabilityState::Fallback(reason(io_errno(&error)));
            let ring = enter_builder(config)
                .build(config.sq_entries())
                .map_err(|error| os("io_uring_setup", io_errno(&error)))?;
            Ok((ring, state))
        }
    }
}

impl OsRing {
    /// Creates the UDP socket bound to `local`, sets up the ring with the
    /// flags of IU-6, checks `IORING_FEAT_NODROP`, the CQ size and the
    /// opcodes, registers the socket as a fixed file when the kernel
    /// allows it, probes send parking and allocates the staging memory.
    ///
    /// # Errors
    ///
    /// [`OpenError::Os`] naming the failed step and its errno; a missing
    /// required facility names `EOPNOTSUPP`. Nothing stays open.
    pub fn open(
        local: SocketAddr,
        config: &UringTxConfig,
    ) -> Result<(Self, OsRingProbes), OpenError> {
        config.validate()?;
        let family = match local {
            SocketAddr::V4(_) => AddressFamily::INET,
            SocketAddr::V6(_) => AddressFamily::INET6,
        };
        let socket =
            rustix::net::socket_with(family, SocketType::DGRAM, SocketFlags::CLOEXEC, None)
                .map_err(|errno| os("socket", errno.raw_os_error()))?;
        rustix::net::bind(&socket, &local).map_err(|errno| os("bind", errno.raw_os_error()))?;
        let (ring, sqpoll) = build_ring(config)?;
        let params = ring.params();
        if !params.is_feature_nodrop() {
            return Err(os("io_uring_feature_nodrop", EOPNOTSUPP));
        }
        let (sq_entries, cq_entries) = (params.sq_entries(), params.cq_entries());
        if cq_entries < config.cq_entries() {
            return Err(os("io_uring_cq_size", EOPNOTSUPP));
        }
        let mut probe = Probe::new();
        ring.submitter()
            .register_probe(&mut probe)
            .map_err(|error| os("io_uring_register_probe", io_errno(&error)))?;
        for code in [opcode::SendMsg::CODE, opcode::AsyncCancel::CODE] {
            if !probe.is_supported(code) {
                return Err(os("io_uring_opcode", EOPNOTSUPP));
            }
        }
        let fixed_files = match ring.submitter().register_files(&[socket.as_raw_fd()]) {
            Ok(()) => CapabilityState::Active,
            Err(error) => CapabilityState::Fallback(reason(io_errno(&error))),
        };
        let mut ring = Self::with_ring(
            ring,
            socket,
            fixed_files == CapabilityState::Active,
            config.tx_slots.get(),
            config.max_datagram.get(),
        );
        ring.probe_cancel_any()?;
        let probes = OsRingProbes {
            sqpoll,
            fixed_files,
            send_parks: probe_send_parking(),
            sq_entries,
            cq_entries,
        };
        Ok((ring, probes))
    }

    /// The "cancel any" probe of design 4.1: `ASYNC_CANCEL` with
    /// `CANCEL_ANY | CANCEL_ALL` on the idle ring must complete with 0, or
    /// a reset could wait on a cancel the kernel does not run.
    fn probe_cancel_any(&mut self) -> Result<(), OpenError> {
        const PROBE: &str = "io_uring_cancel_any";
        let control = UserData::new(self.slots(), 0);
        self.push_cancel(CancelTarget::All, control)
            .map_err(|_| os(PROBE, EOPNOTSUPP))?;
        self.ring
            .submit_and_wait(1)
            .map_err(|error| os(PROBE, io_errno(&error)))?;
        let mut cqes = [Cqe::EMPTY; 1];
        let reaped = self.reap(&mut cqes);
        match cqes {
            [cqe] if reaped == 1 && cqe.user_data == control && cqe.result == 0 => Ok(()),
            [cqe] if reaped == 1 && cqe.result < 0 => {
                Err(os(PROBE, cqe.result.checked_neg().unwrap_or(EOPNOTSUPP)))
            }
            _ => Err(os(PROBE, EOPNOTSUPP)),
        }
    }

    fn with_ring(ring: IoUring, socket: OwnedFd, fixed: bool, slots: u16, slot_len: u16) -> Self {
        let store = (0..slots)
            .map(|_| SlotStore {
                bytes: vec![0; usize::from(slot_len)].into_boxed_slice(),
                msg: Box::new(SlotMsg {
                    hdr: MsgHdr {
                        name: 0,
                        namelen: 0,
                        iov: 0,
                        iovlen: 0,
                        control: 0,
                        controllen: 0,
                        flags: 0,
                    },
                    iov: IoVec { base: 0, len: 0 },
                    addr: SockAddr([0; 28]),
                }),
            })
            .collect();
        Self {
            ring,
            socket: Some(socket),
            fixed,
            slot_len,
            store,
            owned: vec![None; usize::from(slots)].into_boxed_slice(),
        }
    }

    /// The local address of the socket.
    ///
    /// # Errors
    ///
    /// The errno of `getsockname`.
    pub fn local_addr(&self) -> Result<SocketAddr, i32> {
        let socket = self.socket.as_ref().ok_or(9)?;
        rustix::net::getsockname(socket)
            .and_then(SocketAddr::try_from)
            .map_err(|errno| errno.raw_os_error())
    }

    /// Publishes one entry the caller built. Every entry this module
    /// builds names only memory of `self.store` that stays valid until its
    /// completion, or no memory at all.
    fn push(&mut self, entry: &squeue::Entry) -> Result<(), PushError> {
        let mut sq = self.ring.submission();
        // SAFETY: `entry` is a SENDMSG whose `msghdr`, `iovec`, address
        // and bytes live in `self.store`, which is freed only once no
        // slot is kernel owned and is leaked by `Drop` otherwise, or a
        // cancel, which names no memory. The slot is marked kernel owned
        // by the caller right after this push, before anything can write
        // it again.
        let pushed = unsafe { sq.push(entry) };
        pushed.map_err(|_| PushError::Full)
    }

    fn push_message(
        &mut self,
        slot: u16,
        len: u16,
        destination: Option<SocketAddr>,
        user_data: UserData,
    ) -> Result<(), PushError> {
        let index = usize::from(slot);
        // A send's identity names its own slot, so no other operation's
        // completion can carry it (control operations use indices from
        // `slots` up, `push_cancel`).
        if len > self.slot_len || user_data.index() != slot {
            return Err(PushError::OutOfRange);
        }
        match self.owned.get(index) {
            None => return Err(PushError::OutOfRange),
            Some(Some(_)) => return Err(PushError::KernelOwned),
            Some(None) => {}
        }
        if self.ring.submission().is_full() {
            return Err(PushError::Full);
        }
        let store = self.store.get_mut(index).ok_or(PushError::OutOfRange)?;
        let msg = &mut *store.msg;
        let namelen = match destination {
            Some(destination) => msg.addr.encode(destination),
            None => 0,
        };
        msg.iov = IoVec {
            base: store.bytes.as_ptr().expose_provenance(),
            len: usize::from(len),
        };
        msg.hdr = MsgHdr {
            name: if namelen == 0 {
                0
            } else {
                ptr::from_ref(&msg.addr).expose_provenance()
            },
            namelen,
            iov: ptr::from_ref(&msg.iov).expose_provenance(),
            iovlen: 1,
            control: 0,
            controllen: 0,
            flags: 0,
        };
        let hdr = ptr::from_ref(&msg.hdr);
        let entry = if self.fixed {
            opcode::SendMsg::new(types::Fixed(0), hdr.cast()).build()
        } else {
            let fd = self.socket.as_ref().map_or(-1, AsRawFd::as_raw_fd);
            opcode::SendMsg::new(types::Fd(fd), hdr.cast()).build()
        };
        self.push(&entry.user_data(user_data.get()))?;
        if let Some(owner) = self.owned.get_mut(index) {
            *owner = Some(user_data);
        }
        Ok(())
    }

    fn release(&mut self, user_data: UserData) {
        if let Some(owner) = self.owned.get_mut(usize::from(user_data.index()))
            && *owner == Some(user_data)
        {
            *owner = None;
        }
    }
}

impl RingOps for OsRing {
    fn slots(&self) -> u16 {
        u16::try_from(self.store.len()).unwrap_or(u16::MAX)
    }

    fn slot_len(&self) -> u16 {
        self.slot_len
    }

    fn bytes_mut(&mut self, slot: u16) -> Option<&mut [u8]> {
        let index = usize::from(slot);
        if self.owned.get(index)?.is_some() {
            return None;
        }
        self.store.get_mut(index).map(|store| &mut *store.bytes)
    }

    fn sq_free(&mut self) -> usize {
        let sq = self.ring.submission();
        sq.capacity().saturating_sub(sq.len())
    }

    fn push_send(
        &mut self,
        slot: u16,
        len: u16,
        destination: SocketAddr,
        user_data: UserData,
    ) -> Result<(), PushError> {
        self.push_message(slot, len, Some(destination), user_data)
    }

    fn push_cancel(&mut self, target: CancelTarget, user_data: UserData) -> Result<(), PushError> {
        // A control identity never names a send slot: a cancel's completion
        // must not end a slot's kernel ownership.
        if user_data.index() < self.slots() {
            return Err(PushError::OutOfRange);
        }
        let entry = match target {
            CancelTarget::One(target) => opcode::AsyncCancel::new(target.get()).build(),
            CancelTarget::All => {
                opcode::AsyncCancel2::new(types::CancelBuilder::any().all()).build()
            }
        };
        self.push(&entry.user_data(user_data.get()))
    }

    fn enter(&mut self) -> Result<u32, Errno> {
        match self.ring.submit() {
            Ok(consumed) => Ok(u32::try_from(consumed).unwrap_or(u32::MAX)),
            Err(error) => Err(Errno(io_errno(&error))),
        }
    }

    fn needs_enter(&mut self) -> bool {
        // CQ_OVERFLOW: NODROP keeps overflowed CQEs on a kernel list that
        // only an enter flushes (design 5.2).
        let sq = self.ring.submission();
        !sq.is_empty() || sq.taskrun() || sq.cq_overflow()
    }

    fn reap(&mut self, out: &mut [Cqe]) -> usize {
        let mut reaped: usize = 0;
        let mut cq = self.ring.completion();
        for (slot, cqe) in out.iter_mut().zip(cq.by_ref()) {
            let user_data = UserData::from_raw(cqe.user_data());
            *slot = Cqe {
                user_data,
                result: cqe.result(),
                flags: cqe.flags(),
            };
            reaped = reaped.saturating_add(1);
        }
        drop(cq);
        for cqe in out.iter().take(reaped) {
            self.release(cqe.user_data);
        }
        reaped
    }

    fn cq_overflowed(&mut self) -> bool {
        self.ring.completion().overflow() > 0 || self.ring.submission().cq_overflow()
    }

    fn kernel_owned(&self) -> u16 {
        let owned = self.owned.iter().filter(|owner| owner.is_some()).count();
        u16::try_from(owned).unwrap_or(u16::MAX)
    }
}

impl Drop for OsRing {
    fn drop(&mut self) {
        if self.kernel_owned() == 0 {
            return;
        }
        let control = UserData::new(self.slots().saturating_add(CONTROL_SLOTS), 0);
        if self.push_cancel(CancelTarget::All, control).is_ok() {
            let _ = self.enter();
        }
        let mut cqes = [Cqe::EMPTY; 64];
        for _ in 0..DROP_ROUNDS {
            let _ = self.enter();
            self.reap(&mut cqes);
            if self.kernel_owned() == 0 {
                return;
            }
            std::thread::yield_now();
        }
        // The kernel may still read the staging memory: leak it and the
        // socket rather than free or reuse them under the kernel.
        let store = mem::take(&mut self.store);
        let bytes = u64::try_from(store.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::from(self.slot_len));
        LEAKED_BYTES.fetch_add(bytes, Ordering::Relaxed);
        mem::forget(store);
        if let Some(socket) = self.socket.take() {
            mem::forget(socket);
        }
    }
}

/// Datagrams the probe writes at most to fill the peer's queue.
const PROBE_FILL: u32 = 1 << 16;

/// The send parking probe of design 4.1: on an `AF_UNIX` datagram pair
/// without `O_NONBLOCK`, fill the peer's queue, submit one `SENDMSG` and
/// see whether it parks (no completion until a cancel, then
/// `-ECANCELED`) or completes with `-EAGAIN`. Control path only.
#[must_use]
pub fn probe_send_parking() -> CapabilityState {
    match send_parks() {
        Ok(()) => CapabilityState::Active,
        Err(errno) => CapabilityState::Fallback(Reason::ProbeFailed { errno }),
    }
}

fn send_parks() -> Result<(), i32> {
    let (sender, _receiver) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|errno| errno.raw_os_error())?;
    let filler = [0_u8; 64];
    let mut full = false;
    for _ in 0..PROBE_FILL {
        match rustix::net::send(&sender, &filler, SendFlags::DONTWAIT) {
            Ok(_) => {}
            Err(rustix::io::Errno::AGAIN) => {
                full = true;
                break;
            }
            Err(errno) => return Err(errno.raw_os_error()),
        }
    }
    if !full {
        return Err(0);
    }
    let ring = IoUring::new(4).map_err(|error| io_errno(&error))?;
    let mut ring = OsRing::with_ring(ring, sender, false, 1, 64);
    let send = UserData::new(0, 1);
    ring.push_message(0, 64, None, send).map_err(|_| 0)?;
    ring.enter().map_err(|errno| errno.0)?;
    std::thread::sleep(Duration::from_millis(20));
    let mut cqes = [Cqe::EMPTY; 4];
    let reaped = ring.reap(&mut cqes);
    if let Some(cqe) = cqes.iter().take(reaped).find(|cqe| cqe.user_data == send) {
        // Completed without a cancel: it did not park.
        return Err(cqe.result.checked_neg().unwrap_or(0));
    }
    ring.push_cancel(CancelTarget::One(send), UserData::new(1, 1))
        .map_err(|_| 0)?;
    ring.enter().map_err(|errno| errno.0)?;
    for _ in 0..100 {
        let reaped = ring.reap(&mut cqes);
        if let Some(cqe) = cqes.iter().take(reaped).find(|cqe| cqe.user_data == send) {
            return if cqe.result == -125 {
                Ok(())
            } else {
                Err(cqe.result.checked_neg().unwrap_or(0))
            };
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(0)
}

/// The buffer group of every RX ring: one group per ring (design 6.2).
const BGID: u16 = 0;
/// Buffer ring entries per page.
const ENTRIES_PER_PAGE: usize = 256;

/// `struct io_uring_buf`; the `resv` field of entry 0 is the ring tail.
#[repr(C)]
#[derive(Debug)]
struct BufEntry {
    addr: AtomicU64,
    len: AtomicU32,
    bid: AtomicU16,
    resv: AtomicU16,
}

/// One page of buffer ring entries: the ring is page aligned, as
/// `IORING_REGISTER_PBUF_RING` requires.
#[repr(C, align(4096))]
#[derive(Debug)]
struct BufPage([BufEntry; ENTRIES_PER_PAGE]);

const _: () = {
    assert!(mem::size_of::<BufEntry>() == 16);
    assert!(mem::size_of::<BufPage>() == 4096);
};

impl BufPage {
    fn new() -> Box<Self> {
        Box::new(Self(std::array::from_fn(|_| BufEntry {
            addr: AtomicU64::new(0),
            len: AtomicU32::new(0),
            bid: AtomicU16::new(0),
            resv: AtomicU16::new(0),
        })))
    }
}

/// Where one RX buffer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufState {
    Posted,
    Completed,
}

/// Writes the entry at `tail` for buffer `id` and publishes the new tail
/// with a Release store (design 6.2).
fn post_entry(pages: &[Box<BufPage>], tail: &mut u16, mask: u16, addr: u64, len: u32, id: u16) {
    let at = usize::from(*tail & mask);
    if let Some(entry) = pages
        .get(at / ENTRIES_PER_PAGE)
        .and_then(|page| page.0.get(at % ENTRIES_PER_PAGE))
    {
        entry.addr.store(addr, Ordering::Relaxed);
        entry.len.store(len, Ordering::Relaxed);
        entry.bid.store(id, Ordering::Relaxed);
    }
    *tail = tail.wrapping_add(1);
    if let Some(first) = pages.first().and_then(|page| page.0.first()) {
        first.resv.store(*tail, Ordering::Release);
    }
}

/// The RX ring of one RX half and its UDP socket.
pub struct OsRxRing {
    ring: IoUring,
    socket: Option<OwnedFd>,
    fixed: bool,
    pages: Box<[Box<BufPage>]>,
    buffers: Box<[Box<[u8]>]>,
    state: Box<[BufState]>,
    tail: u16,
    mask: u16,
    /// The `msghdr` the arm names: only its name and control lengths
    /// count.
    msg: Box<MsgHdr>,
    arm: Option<UserData>,
}

impl std::fmt::Debug for OsRxRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsRxRing")
            .field("fixed", &self.fixed)
            .field("buffers", &self.buffers.len())
            .field("posted", &self.posted())
            .field("arm", &self.arm)
            .finish_non_exhaustive()
    }
}

impl OsRxRing {
    /// Creates the UDP socket bound to `local` and opens the ring on it
    /// ([`OsRxRing::with_socket`]).
    ///
    /// # Errors
    ///
    /// [`OpenError::Os`] naming the failed step.
    pub fn open(local: SocketAddr, config: &UringRxConfig) -> Result<Self, OpenError> {
        let family = match local {
            SocketAddr::V4(_) => AddressFamily::INET,
            SocketAddr::V6(_) => AddressFamily::INET6,
        };
        let socket = rustix::net::socket(family, SocketType::DGRAM, None)
            .map_err(|errno| os("socket", errno.raw_os_error()))?;
        rustix::net::bind(&socket, &local).map_err(|errno| os("bind", errno.raw_os_error()))?;
        Self::with_socket(socket, config)
    }

    /// Sets up the RX ring on `socket` with the flags of IU-6, checks
    /// `NODROP`, the CQ size and the `RECVMSG` opcode, registers the
    /// socket as a fixed file when allowed, then registers the provided
    /// buffer ring and posts every buffer.
    ///
    /// # Errors
    ///
    /// [`OpenError::Os`] naming the failed step; a missing facility names
    /// `EOPNOTSUPP`.
    pub fn with_socket(socket: OwnedFd, config: &UringRxConfig) -> Result<Self, OpenError> {
        config.validate()?;
        let ring = IoUring::builder()
            .setup_submit_all()
            .setup_coop_taskrun()
            .setup_taskrun_flag()
            .setup_cqsize(config.cq_entries())
            .build(config.sq_entries())
            .map_err(|error| os("io_uring_setup", io_errno(&error)))?;
        let params = ring.params();
        if !params.is_feature_nodrop() {
            return Err(os("io_uring_feature_nodrop", EOPNOTSUPP));
        }
        if params.cq_entries() < config.cq_entries() {
            return Err(os("io_uring_cq_size", EOPNOTSUPP));
        }
        let mut probe = Probe::new();
        ring.submitter()
            .register_probe(&mut probe)
            .map_err(|error| os("io_uring_register_probe", io_errno(&error)))?;
        for code in [opcode::RecvMsgMulti::CODE, opcode::AsyncCancel::CODE] {
            if !probe.is_supported(code) {
                return Err(os("io_uring_opcode", EOPNOTSUPP));
            }
        }
        let fixed = ring
            .submitter()
            .register_files(&[socket.as_raw_fd()])
            .is_ok();
        let buffers = config.rx_buffers.get();
        let len = config.buffer_len();
        let pages = (0..usize::from(buffers).div_ceil(ENTRIES_PER_PAGE))
            .map(|_| BufPage::new())
            .collect();
        let mut rx = Self {
            ring,
            socket: Some(socket),
            fixed,
            pages,
            buffers: (0..buffers)
                .map(|_| vec![0; usize::try_from(len).unwrap_or(0)].into_boxed_slice())
                .collect(),
            state: vec![BufState::Posted; usize::from(buffers)].into_boxed_slice(),
            tail: 0,
            mask: buffers.saturating_sub(1),
            msg: Box::new(MsgHdr {
                name: 0,
                namelen: RX_NAME_LEN,
                iov: 0,
                iovlen: 0,
                control: 0,
                controllen: 0,
                flags: 0,
            }),
            arm: None,
        };
        rx.register()
            .map_err(|errno| os("io_uring_register_pbuf_ring", errno.0))?;
        Ok(rx)
    }

    /// The socket's local address.
    ///
    /// # Errors
    ///
    /// The errno of `getsockname`.
    pub fn local_addr(&self) -> Result<SocketAddr, i32> {
        let socket = self.socket.as_ref().ok_or(9)?;
        rustix::net::getsockname(socket)
            .and_then(SocketAddr::try_from)
            .map_err(|errno| errno.raw_os_error())
    }

    /// Registers the buffer ring and posts every buffer.
    fn register(&mut self) -> Result<(), Errno> {
        let addr = self
            .pages
            .first()
            .map_or(0, |page| ptr::from_ref::<BufPage>(page).expose_provenance());
        let entries = self.buffers();
        // SAFETY: the ring memory is `self.pages`, page aligned and
        // `entries` entries long; it stays allocated until the group is
        // unregistered (`reregister`, `Drop`) or is leaked by `Drop` while
        // the arm may still select from it.
        let registered = unsafe {
            self.ring.submitter().register_buf_ring_with_flags(
                u64::try_from(addr).unwrap_or(0),
                entries,
                BGID,
                0,
            )
        };
        registered.map_err(|error| Errno(io_errno(&error)))?;
        self.tail = 0;
        for id in 0..entries {
            self.post(id);
        }
        Ok(())
    }

    fn post(&mut self, id: u16) {
        let Some(buffer) = self.buffers.get(usize::from(id)) else {
            return;
        };
        let addr = u64::try_from(buffer.as_ptr().expose_provenance()).unwrap_or(0);
        let len = u32::try_from(buffer.len()).unwrap_or(0);
        post_entry(&self.pages, &mut self.tail, self.mask, addr, len, id);
        if let Some(state) = self.state.get_mut(usize::from(id)) {
            *state = BufState::Posted;
        }
    }

    fn push(&mut self, entry: &squeue::Entry) -> Result<(), PushError> {
        let mut sq = self.ring.submission();
        // SAFETY: `entry` is the multishot RECVMSG, which names
        // `self.msg` (alive as long as the ring) and buffers of the
        // registered group (alive until unregistered, or leaked by
        // `Drop`), or a cancel, which names no memory.
        let pushed = unsafe { sq.push(entry) };
        pushed.map_err(|_| PushError::Full)
    }
}

impl RxRingOps for OsRxRing {
    fn buffers(&self) -> u16 {
        u16::try_from(self.buffers.len()).unwrap_or(u16::MAX)
    }

    fn buffer_len(&self) -> u32 {
        self.buffers
            .first()
            .and_then(|buffer| u32::try_from(buffer.len()).ok())
            .unwrap_or(0)
    }

    fn arm(&mut self, user_data: UserData) -> Result<(), PushError> {
        let msg = ptr::from_ref::<MsgHdr>(&self.msg);
        let entry = if self.fixed {
            opcode::RecvMsgMulti::new(types::Fixed(0), msg.cast(), BGID).build()
        } else {
            let fd = self.socket.as_ref().map_or(-1, AsRawFd::as_raw_fd);
            opcode::RecvMsgMulti::new(types::Fd(fd), msg.cast(), BGID).build()
        };
        self.push(&entry.user_data(user_data.get()))?;
        self.arm = Some(user_data);
        Ok(())
    }

    fn push_cancel(&mut self, target: CancelTarget, user_data: UserData) -> Result<(), PushError> {
        let entry = match target {
            CancelTarget::One(target) => opcode::AsyncCancel::new(target.get()).build(),
            CancelTarget::All => {
                opcode::AsyncCancel2::new(types::CancelBuilder::any().all()).build()
            }
        };
        self.push(&entry.user_data(user_data.get()))
    }

    fn enter(&mut self) -> Result<u32, Errno> {
        match self.ring.submit() {
            Ok(consumed) => Ok(u32::try_from(consumed).unwrap_or(u32::MAX)),
            Err(error) => Err(Errno(io_errno(&error))),
        }
    }

    fn needs_enter(&mut self) -> bool {
        let sq = self.ring.submission();
        !sq.is_empty() || sq.taskrun()
    }

    fn reap(&mut self, out: &mut [Cqe]) -> usize {
        let mut reaped: usize = 0;
        let mut cq = self.ring.completion();
        for (slot, cqe) in out.iter_mut().zip(cq.by_ref()) {
            *slot = Cqe {
                user_data: UserData::from_raw(cqe.user_data()),
                result: cqe.result(),
                flags: cqe.flags(),
            };
            reaped = reaped.saturating_add(1);
        }
        drop(cq);
        for cqe in out.iter().take(reaped) {
            if Some(cqe.user_data) == self.arm && cqe.flags & CQE_F_MORE == 0 {
                self.arm = None;
            }
            if let Some(id) = buffer_id(cqe.flags)
                && let Some(state) = self.state.get_mut(usize::from(id))
            {
                *state = BufState::Completed;
            }
        }
        reaped
    }

    fn lend<T>(&mut self, id: u16, lend: impl FnOnce(&[u8]) -> T) -> Option<T> {
        struct Repost<'a> {
            pages: &'a [Box<BufPage>],
            tail: &'a mut u16,
            mask: u16,
            state: &'a mut BufState,
            addr: u64,
            len: u32,
            id: u16,
        }
        impl Drop for Repost<'_> {
            fn drop(&mut self) {
                post_entry(
                    self.pages, self.tail, self.mask, self.addr, self.len, self.id,
                );
                *self.state = BufState::Posted;
            }
        }
        let index = usize::from(id);
        let state = self.state.get_mut(index)?;
        if *state != BufState::Completed {
            return None;
        }
        let buffer = self.buffers.get(index)?;
        let _repost = Repost {
            pages: &self.pages,
            tail: &mut self.tail,
            mask: self.mask,
            state,
            addr: u64::try_from(buffer.as_ptr().expose_provenance()).unwrap_or(0),
            len: u32::try_from(buffer.len()).unwrap_or(0),
            id,
        };
        Some(lend(buffer))
    }

    fn posted(&self) -> u16 {
        let posted = self
            .state
            .iter()
            .filter(|state| **state == BufState::Posted)
            .count();
        u16::try_from(posted).unwrap_or(u16::MAX)
    }

    fn arm_live(&self) -> bool {
        self.arm.is_some()
    }

    fn cq_overflowed(&mut self) -> bool {
        self.ring.completion().overflow() > 0 || self.ring.submission().cq_overflow()
    }

    fn reregister(&mut self) -> Result<(), Errno> {
        if self.arm.is_some() {
            return Err(Errno(16));
        }
        self.ring
            .submitter()
            .unregister_buf_ring(BGID)
            .map_err(|error| Errno(io_errno(&error)))?;
        for page in &*self.pages {
            for entry in &page.0 {
                entry.resv.store(0, Ordering::Relaxed);
            }
        }
        self.register()
    }
}

impl Drop for OsRxRing {
    fn drop(&mut self) {
        if let Some(arm) = self.arm {
            let control = UserData::new(1, u64::MAX);
            if self.push_cancel(CancelTarget::One(arm), control).is_ok() {
                let _ = self.enter();
            }
            let mut cqes = [Cqe::EMPTY; 64];
            for _ in 0..DROP_ROUNDS {
                let _ = self.enter();
                let reaped = self.reap(&mut cqes);
                for cqe in cqes.iter().take(reaped) {
                    if let Some(id) = buffer_id(cqe.flags) {
                        let _ = self.lend(id, |_| ());
                    }
                }
                if self.arm.is_none() {
                    break;
                }
                std::thread::yield_now();
            }
        }
        if self.arm.is_some() {
            // The arm may still write: leak every buffer, the ring memory,
            // the msghdr and the socket.
            let buffers = mem::take(&mut self.buffers);
            let bytes = buffers.iter().fold(0_u64, |sum, buffer| {
                sum.saturating_add(u64::try_from(buffer.len()).unwrap_or(u64::MAX))
            });
            LEAKED_BYTES.fetch_add(bytes, Ordering::Relaxed);
            mem::forget(buffers);
            mem::forget(mem::take(&mut self.pages));
            mem::forget(mem::replace(
                &mut self.msg,
                Box::new(MsgHdr {
                    name: 0,
                    namelen: 0,
                    iov: 0,
                    iovlen: 0,
                    control: 0,
                    controllen: 0,
                    flags: 0,
                }),
            ));
            if let Some(socket) = self.socket.take() {
                mem::forget(socket);
            }
            return;
        }
        let _ = self.ring.submitter().unregister_buf_ring(BGID);
    }
}
