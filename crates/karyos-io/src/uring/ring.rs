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

use std::mem;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use io_uring::{IoUring, Probe, opcode, squeue, types};
use rustix::net::{AddressFamily, SendFlags, SocketFlags, SocketType};

use super::ops::{CONTROL_SLOTS, CancelTarget, Cqe, Errno, PushError, RingOps, UserData};
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

fn build_ring(config: &UringTxConfig) -> Result<(IoUring, CapabilityState), OpenError> {
    let mut builder = IoUring::builder();
    builder
        .setup_submit_all()
        .setup_coop_taskrun()
        .setup_taskrun_flag()
        .setup_cqsize(config.cq_entries());
    let Some(sqpoll) = config.sqpoll else {
        let ring = builder
            .build(config.sq_entries())
            .map_err(|error| os("io_uring_setup", io_errno(&error)))?;
        return Ok((ring, CapabilityState::NotRequested));
    };
    let mut polled = builder.clone();
    polled
        .setup_sqpoll(sqpoll.idle_ms)
        .setup_sqpoll_cpu(sqpoll.cpu);
    match polled.build(config.sq_entries()) {
        Ok(ring) => Ok((ring, CapabilityState::Active)),
        Err(error) => {
            // A declared fallback to enter based submission (design 8).
            let state = CapabilityState::Fallback(reason(io_errno(&error)));
            let ring = builder
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
        let socket = rustix::net::socket(family, SocketType::DGRAM, None)
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
        let ring = Self::with_ring(
            ring,
            socket,
            fixed_files == CapabilityState::Active,
            config.tx_slots.get(),
            config.max_datagram.get(),
        );
        let probes = OsRingProbes {
            sqpoll,
            fixed_files,
            send_parks: probe_send_parking(),
            sq_entries,
            cq_entries,
        };
        Ok((ring, probes))
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
        if len > self.slot_len {
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
        SocketFlags::empty(),
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
