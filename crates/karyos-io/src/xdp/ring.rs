// SPDX-License-Identifier: Apache-2.0

//! [`OsXsk`], the [`XskOps`] of a real AF_XDP socket in copy mode
//! (`quantstratum-docs: karyos/design/af-xdp-backend.md` sections 3, 6,
//! 7.3 to 7.5, 8.1 and 11.3). The only module of the `xdp` backend with
//! `unsafe`: accesses to the mapped ring words and descriptors, and byte
//! views of frames the backend owns, one operation per block with its
//! `// SAFETY:` comment.
//!
//! **Copy only.** The bind always names `XDP_COPY | XDP_USE_NEED_WAKEUP`;
//! a bind that could select zero copy is never issued, and `open` fails
//! if the socket reports `XDP_OPTIONS_ZEROCOPY`. Busy polling, NUMA
//! placement, zero copy and multi-buffer frames are deferred (owner item
//! 3) and not implemented.
//!
//! **Teardown (11.3).** [`OsXsk`] declares its fields so that Rust drops
//! the four ring mappings first, then the socket, then the UMEM: once the
//! rings are unmapped, closing the socket releases it, which unbinds it
//! and removes it from every `XSKMAP`; the kernel keeps its own references
//! to the pinned pages, so unmapping the UMEM afterwards is safe.

use std::os::fd::{AsFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering, fence};

use karyos_sys::xsk_map::{RingMapping, UmemRegion};
use rustix::net::xdp::{
    SocketAddrXdp, SocketAddrXdpFlags, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING,
    XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_PGOFF_FILL_RING, XdpOptionsFlags, XdpRingFlags,
    XdpRingOffset, XdpUmemReg, XdpUmemRegFlags,
};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

use super::ops::{Completion, Errno, RxDesc, XskOps};
use crate::backend::OpenError;

/// Bytes of one fill or completion entry (`u64` address).
const ADDR_ENTRY: usize = 8;
/// Bytes of one RX or TX descriptor (`struct xdp_desc`).
const DESC_ENTRY: usize = 16;

/// One mapped ring and its local positions.
#[derive(Debug)]
struct Ring {
    map: RingMapping,
    producer: usize,
    consumer: usize,
    flags: Option<usize>,
    desc: usize,
    size: u32,
    entry: usize,
    /// Our side's private position: the producer for rings we fill, the
    /// consumer for rings the kernel fills.
    local: u32,
}

impl Ring {
    fn map(
        fd: impl AsFd,
        offsets: XdpRingOffset,
        pgoff: u64,
        size: u32,
        entry: usize,
    ) -> Result<Self, OpenError> {
        let to_usize = |value: u64| usize::try_from(value).map_err(|_| invalid("xsk_ring"));
        let desc = to_usize(offsets.desc)?;
        let bytes = usize::try_from(size)
            .ok()
            .and_then(|size| size.checked_mul(entry))
            .and_then(|len| len.checked_add(desc))
            .ok_or_else(|| invalid("xsk_ring"))?;
        let map = RingMapping::new(fd, pgoff, bytes).map_err(|_| os("mmap"))?;
        let ring = Self {
            map,
            producer: to_usize(offsets.producer)?,
            consumer: to_usize(offsets.consumer)?,
            flags: offsets.flags.map(to_usize).transpose()?,
            desc,
            size,
            entry,
            local: 0,
        };
        for word in [Some(ring.producer), Some(ring.consumer), ring.flags]
            .into_iter()
            .flatten()
        {
            if word % 4 != 0 || word.checked_add(4).is_none_or(|end| end > bytes) {
                return Err(invalid("xsk_ring"));
            }
        }
        if desc % 8 != 0 {
            return Err(invalid("xsk_ring"));
        }
        Ok(ring)
    }

    fn word(&self, offset: usize) -> &AtomicU32 {
        let address = self
            .map
            .base()
            .as_ptr()
            .wrapping_add(offset)
            .cast::<AtomicU32>();
        // SAFETY: `offset` is one of the producer, consumer or flags offsets
        // the kernel reported for this mapping, checked in `map` to be
        // 4-aligned and inside it; the mapping lives as long as `self`, and
        // the kernel accesses the word only atomically.
        unsafe { &*address }
    }

    fn producer(&self) -> &AtomicU32 {
        self.word(self.producer)
    }

    fn consumer(&self) -> &AtomicU32 {
        self.word(self.consumer)
    }

    fn needs_wakeup(&self) -> bool {
        // StoreLoad: order the preceding producer store before this load
        // (design 7.3 step 6).
        fence(Ordering::SeqCst);
        self.flags.is_some_and(|flags| {
            self.word(flags).load(Ordering::Acquire) & XdpRingFlags::XDP_RING_NEED_WAKEUP.bits()
                != 0
        })
    }

    /// The address of entry `index` (masked).
    fn entry_ptr(&self, index: u32) -> NonNull<u8> {
        let slot = usize::try_from(index & self.size.wrapping_sub(1)).unwrap_or(0);
        let offset = self.desc.saturating_add(slot.saturating_mul(self.entry));
        // In bounds: `slot < size` and the mapping covers `desc + size *
        // entry` bytes (checked in `map`).
        self.map.base().map_addr(|base| base.saturating_add(offset))
    }

    fn write_u64(&self, index: u32, at: usize, value: u64) {
        let address = self
            .entry_ptr(index)
            .as_ptr()
            .wrapping_add(at)
            .cast::<u64>();
        // SAFETY: inside the entry of `index` (in bounds, see `entry_ptr`),
        // 8-aligned since `desc` and the entry sizes are; the entry is ours
        // to write until the producer store that publishes it.
        unsafe { address.write_volatile(value) }
    }

    fn write_u32(&self, index: u32, at: usize, value: u32) {
        let address = self
            .entry_ptr(index)
            .as_ptr()
            .wrapping_add(at)
            .cast::<u32>();
        // SAFETY: as `write_u64`, at a 4-aligned field of the entry.
        unsafe { address.write_volatile(value) }
    }

    fn read_u64(&self, index: u32, at: usize) -> u64 {
        let address = self
            .entry_ptr(index)
            .as_ptr()
            .wrapping_add(at)
            .cast::<u64>();
        // SAFETY: inside the entry of `index`, which the kernel published
        // before the producer value loaded with Acquire and will not
        // rewrite before our consumer store.
        unsafe { address.read_volatile() }
    }

    fn read_u32(&self, index: u32, at: usize) -> u32 {
        let address = self
            .entry_ptr(index)
            .as_ptr()
            .wrapping_add(at)
            .cast::<u32>();
        // SAFETY: as `read_u64`, at a 4-aligned field of the entry.
        unsafe { address.read_volatile() }
    }

    /// Entries free for us to produce.
    fn free(&self) -> u32 {
        let consumer = self.consumer().load(Ordering::Acquire);
        self.size.saturating_sub(self.local.wrapping_sub(consumer))
    }

    /// Entries the kernel produced that we have not consumed.
    fn available(&self) -> u32 {
        self.producer()
            .load(Ordering::Acquire)
            .wrapping_sub(self.local)
    }
}

fn invalid(field: &'static str) -> OpenError {
    OpenError::InvalidConfig { field, value: 0 }
}

fn os(operation: &'static str) -> OpenError {
    OpenError::Os {
        operation,
        errno: 0,
    }
}

fn errno(operation: &'static str) -> impl Fn(rustix::io::Errno) -> OpenError {
    move |errno| OpenError::Os {
        operation,
        errno: errno.raw_os_error(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxFrame {
    Posted,
    Completed,
}

/// One AF_XDP socket bound in copy mode with its own UMEM (design 6).
/// Field order is the teardown order of 11.3.
#[derive(Debug)]
pub struct OsXsk {
    // Rings first: dropping them unmaps them before the socket closes.
    tx: Ring,
    completion: Ring,
    rx: Ring,
    fill: Ring,
    socket: OwnedFd,
    // UMEM last.
    umem: UmemRegion,
    frame_len: u32,
    tx_frames: u16,
    rx_frames: u32,
    tx_owned: Box<[bool]>,
    rx_state: Box<[RxFrame]>,
}

/// The sizes of one socket (design 6.1 and 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XskSizes {
    /// Frame size `F`, 2048 or 4096.
    pub frame_len: u32,
    /// TX frames `T`, a power of two.
    pub tx_frames: u16,
    /// RX frames `R`, a power of two.
    pub rx_frames: u32,
}

impl OsXsk {
    /// Creates the socket, its UMEM and rings, posts every RX frame to the
    /// fill ring and binds it to `queue` of `ifindex` in copy mode with
    /// need_wakeup. Nothing stays open on failure.
    ///
    /// # Errors
    ///
    /// [`OpenError::InvalidConfig`] for sizes out of range;
    /// [`OpenError::Os`] naming the failed step, for example `xsk_socket`
    /// with `EPERM` without `CAP_NET_RAW`, or `xsk_bind`.
    pub fn open(ifindex: u32, queue: u32, sizes: XskSizes) -> Result<Self, OpenError> {
        let XskSizes {
            frame_len,
            tx_frames,
            rx_frames,
        } = sizes;
        if !matches!(frame_len, 2048 | 4096) {
            return Err(invalid("frame_size"));
        }
        if !tx_frames.is_power_of_two() || !rx_frames.is_power_of_two() {
            return Err(invalid("xsk_frames"));
        }
        let frames = u64::from(tx_frames)
            .checked_add(u64::from(rx_frames))
            .ok_or_else(|| invalid("xsk_frames"))?;
        // The frames registered, `N * F`; the mapping is that rounded up to
        // whole pages (design 6.1).
        let umem_len = frames
            .checked_mul(u64::from(frame_len))
            .and_then(|len| usize::try_from(len).ok())
            .ok_or_else(|| invalid("xsk_frames"))?;
        let mapped_len =
            karyos_sys::xsk_map::page_rounded(umem_len).ok_or_else(|| invalid("xsk_frames"))?;
        let socket = rustix::net::socket_with(
            AddressFamily::XDP,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(errno("xsk_socket"))?;
        let umem = UmemRegion::new(mapped_len).map_err(|_| os("xsk_umem_mmap"))?;
        let umem_addr = u64::try_from(umem.base().as_ptr().expose_provenance())
            .map_err(|_| invalid("xsk_umem"))?;
        rustix::net::sockopt::set_xdp_umem_reg(
            &socket,
            XdpUmemReg {
                addr: umem_addr,
                len: u64::try_from(umem_len).map_err(|_| invalid("xsk_umem"))?,
                chunk_size: frame_len,
                headroom: 0,
                flags: XdpUmemRegFlags::empty(),
                tx_metadata_len: 0,
            },
        )
        .map_err(errno("xsk_umem_reg"))?;
        let tx_size = u32::from(tx_frames);
        rustix::net::sockopt::set_xdp_umem_fill_ring_size(&socket, rx_frames)
            .map_err(errno("xsk_fill_ring"))?;
        rustix::net::sockopt::set_xdp_umem_completion_ring_size(&socket, tx_size)
            .map_err(errno("xsk_completion_ring"))?;
        rustix::net::sockopt::set_xdp_rx_ring_size(&socket, rx_frames)
            .map_err(errno("xsk_rx_ring"))?;
        rustix::net::sockopt::set_xdp_tx_ring_size(&socket, tx_size)
            .map_err(errno("xsk_tx_ring"))?;
        let offsets =
            rustix::net::sockopt::xdp_mmap_offsets(&socket).map_err(errno("xsk_mmap_offsets"))?;
        let tx = Ring::map(&socket, offsets.tx, XDP_PGOFF_TX_RING, tx_size, DESC_ENTRY)?;
        let completion = Ring::map(
            &socket,
            offsets.cr,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            tx_size,
            ADDR_ENTRY,
        )?;
        let rx = Ring::map(
            &socket,
            offsets.rx,
            XDP_PGOFF_RX_RING,
            rx_frames,
            DESC_ENTRY,
        )?;
        let fill = Ring::map(
            &socket,
            offsets.fr,
            XDP_UMEM_PGOFF_FILL_RING,
            rx_frames,
            ADDR_ENTRY,
        )?;
        let mut xsk = Self {
            tx,
            completion,
            rx,
            fill,
            socket,
            umem,
            frame_len,
            tx_frames,
            rx_frames,
            tx_owned: vec![false; usize::from(tx_frames)].into_boxed_slice(),
            rx_state: vec![
                RxFrame::Posted;
                usize::try_from(rx_frames).map_err(|_| invalid("xsk_frames"))?
            ]
            .into_boxed_slice(),
        };
        for index in 0..rx_frames {
            let addr = xsk.rx_addr(index);
            xsk.fill.write_u64(xsk.fill.local, 0, addr);
            xsk.fill.local = xsk.fill.local.wrapping_add(1);
        }
        xsk.publish_fill();
        let flags = SocketAddrXdpFlags::XDP_COPY | SocketAddrXdpFlags::XDP_USE_NEED_WAKEUP;
        rustix::net::bind(&xsk.socket, &SocketAddrXdp::new(flags, ifindex, queue))
            .map_err(errno("xsk_bind"))?;
        let options =
            rustix::net::sockopt::xdp_options(&xsk.socket).map_err(errno("xsk_options"))?;
        if options.contains(XdpOptionsFlags::XDP_OPTIONS_ZEROCOPY) {
            return Err(invalid("xsk_zero_copy"));
        }
        Ok(xsk)
    }

    /// The socket, for the `XSKMAP` entry.
    #[must_use]
    pub fn socket(&self) -> &OwnedFd {
        &self.socket
    }

    /// UMEM bytes pinned by the registration.
    #[must_use]
    pub fn umem_len(&self) -> usize {
        self.umem.len()
    }

    fn rx_addr(&self, index: u32) -> u64 {
        u64::from(self.tx_frames)
            .saturating_add(u64::from(index))
            .saturating_mul(u64::from(self.frame_len))
    }

    fn frame_ptr(&self, addr: u64) -> NonNull<u8> {
        let offset = usize::try_from(addr).unwrap_or(0);
        self.umem
            .base()
            .map_addr(|base| base.saturating_add(offset))
    }

    /// The RX frame index and offset of `desc`, if it lies inside one.
    fn rx_frame_of(&self, desc: RxDesc) -> Option<(usize, u64)> {
        let frame_len = u64::from(self.frame_len);
        let tx_end = u64::from(self.tx_frames).checked_mul(frame_len)?;
        let offset = desc.addr.checked_sub(tx_end)?;
        let index = offset / frame_len;
        let within = offset % frame_len;
        if index >= u64::from(self.rx_frames)
            || within.checked_add(u64::from(desc.len))? > frame_len
        {
            return None;
        }
        Some((usize::try_from(index).ok()?, within))
    }
}

impl XskOps for OsXsk {
    fn frame_len(&self) -> u32 {
        self.frame_len
    }

    fn tx_frames(&self) -> u16 {
        self.tx_frames
    }

    fn rx_frames(&self) -> u32 {
        self.rx_frames
    }

    fn tx_frame_mut(&mut self, frame: u16) -> Option<&mut [u8]> {
        if *self.tx_owned.get(usize::from(frame))? {
            return None;
        }
        let addr = u64::from(frame).checked_mul(u64::from(self.frame_len))?;
        let len = usize::try_from(self.frame_len).ok()?;
        let base = self.frame_ptr(addr);
        // SAFETY: TX frame `frame` lies inside the UMEM (`frame <
        // tx_frames`), it is not kernel owned (checked above), so neither
        // the kernel nor any other reference accesses it; the borrow of
        // `&mut self` keeps it exclusive until it ends.
        Some(unsafe { std::slice::from_raw_parts_mut(base.as_ptr(), len) })
    }

    fn tx_free(&mut self) -> u32 {
        self.tx.free()
    }

    fn push_tx(&mut self, frame: u16, len: u32) -> bool {
        if len > self.frame_len || self.tx.free() == 0 {
            return false;
        }
        match self.tx_owned.get_mut(usize::from(frame)) {
            Some(owned) if !*owned => *owned = true,
            _ => return false,
        }
        let addr = u64::from(frame).saturating_mul(u64::from(self.frame_len));
        let index = self.tx.local;
        self.tx.write_u64(index, 0, addr);
        self.tx.write_u32(index, 8, len);
        self.tx.write_u32(index, 12, 0);
        self.tx.local = index.wrapping_add(1);
        true
    }

    fn publish_tx(&mut self) {
        self.tx.producer().store(self.tx.local, Ordering::Release);
    }

    fn tx_needs_wakeup(&mut self) -> bool {
        self.tx.needs_wakeup()
    }

    fn kick_tx(&mut self) -> Result<(), Errno> {
        rustix::net::send(&self.socket, &[], SendFlags::DONTWAIT)
            .map(|_| ())
            .map_err(|errno| Errno(errno.raw_os_error()))
    }

    fn reap_completions(&mut self, out: &mut [Completion]) -> usize {
        let available = usize::try_from(self.completion.available()).unwrap_or(0);
        let frame_len = u64::from(self.frame_len);
        let mut reaped: usize = 0;
        for entry in out.iter_mut().take(available) {
            let index = self.completion.local;
            let addr = self.completion.read_u64(index, 0);
            self.completion.local = index.wrapping_add(1);
            let frame = if addr.is_multiple_of(frame_len) {
                u16::try_from(addr / frame_len).ok()
            } else {
                None
            };
            *entry = match frame
                .and_then(|frame| Some((frame, self.tx_owned.get_mut(usize::from(frame))?)))
            {
                Some((frame, owned)) if *owned => {
                    *owned = false;
                    Completion::Released { frame }
                }
                _ => Completion::Invalid { addr },
            };
            reaped = reaped.saturating_add(1);
        }
        if reaped > 0 {
            self.completion
                .consumer()
                .store(self.completion.local, Ordering::Release);
        }
        reaped
    }

    fn reap_rx(&mut self, out: &mut [RxDesc]) -> usize {
        let available = usize::try_from(self.rx.available()).unwrap_or(0);
        let mut reaped: usize = 0;
        for entry in out.iter_mut().take(available) {
            let index = self.rx.local;
            let desc = RxDesc {
                addr: self.rx.read_u64(index, 0),
                len: self.rx.read_u32(index, 8),
            };
            self.rx.local = index.wrapping_add(1);
            if let Some((frame, _)) = self.rx_frame_of(desc)
                && let Some(state @ RxFrame::Posted) = self.rx_state.get_mut(frame)
            {
                *state = RxFrame::Completed;
            }
            *entry = desc;
            reaped = reaped.saturating_add(1);
        }
        if reaped > 0 {
            self.rx.consumer().store(self.rx.local, Ordering::Release);
        }
        reaped
    }

    fn lend_rx<T>(&mut self, desc: RxDesc, lend: impl FnOnce(&[u8]) -> T) -> Option<T> {
        struct Repost<'a> {
            fill: &'a mut Ring,
            state: &'a mut RxFrame,
            frame_addr: u64,
        }
        impl Drop for Repost<'_> {
            fn drop(&mut self) {
                let index = self.fill.local;
                self.fill.write_u64(index, 0, self.frame_addr);
                self.fill.local = index.wrapping_add(1);
                *self.state = RxFrame::Posted;
            }
        }
        let (frame, within) = self.rx_frame_of(desc)?;
        if *self.rx_state.get(frame)? != RxFrame::Completed {
            return None;
        }
        let frame_addr = self.rx_addr(u32::try_from(frame).ok()?);
        let start = self.frame_ptr(frame_addr.checked_add(within)?);
        let len = usize::try_from(desc.len).ok()?;
        // SAFETY: `desc` lies inside RX frame `frame` (checked by
        // `rx_frame_of`), which is Completed: the kernel wrote it before
        // publishing its descriptor and does not write it again until the
        // frame is back in the fill ring, which happens only when the guard
        // below drops, after this borrow ends.
        let bytes = unsafe { std::slice::from_raw_parts(start.as_ptr().cast_const(), len) };
        let state = self.rx_state.get_mut(frame)?;
        let _repost = Repost {
            fill: &mut self.fill,
            state,
            frame_addr,
        };
        Some(lend(bytes))
    }

    fn publish_fill(&mut self) {
        self.fill
            .producer()
            .store(self.fill.local, Ordering::Release);
    }

    fn fill_needs_wakeup(&mut self) -> bool {
        self.fill.needs_wakeup()
    }

    fn kick_rx(&mut self) -> Result<(), Errno> {
        let mut empty = [0_u8; 0];
        rustix::net::recv(&self.socket, &mut empty[..], RecvFlags::DONTWAIT)
            .map(|_| ())
            .map_err(|errno| Errno(errno.raw_os_error()))
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
