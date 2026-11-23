// SPDX-License-Identifier: Apache-2.0

//! The two mappings of the AF_XDP copy-mode backend (`quantstratum-docs:
//! karyos/design/af-xdp-backend.md` section 2): an anonymous UMEM region
//! the kernel pins, and a shared mapping of a socket's ring at its page
//! offset (Linux only).
//!
//! Each type owns exactly one mapping and unmaps it on drop. Neither hands
//! out references to the mapped bytes: the kernel reads and writes them
//! concurrently, so the consumer (`karyos-io`'s `xdp::ring`) forms
//! accesses from [`UmemRegion::base`] and [`RingMapping::base`] under its
//! own ownership rules.

use core::ffi::c_void;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use rustix::fd::AsFd;
use rustix::mm::{MapFlags, ProtFlags};

use crate::error::SysError;

fn os(operation: &'static str) -> impl Fn(rustix::io::Errno) -> SysError {
    move |errno| SysError::Os {
        operation,
        errno: errno.raw_os_error(),
    }
}

/// Bytes of every [`UmemRegion`] mapped now, over the process.
static LIVE_UMEM_BYTES: AtomicU64 = AtomicU64::new(0);

/// Bytes of the UMEM regions mapped now, over the process: teardown
/// returns it to its value before `open` (af-xdp-backend.md 11.3).
#[must_use]
pub fn live_umem_bytes() -> u64 {
    LIVE_UMEM_BYTES.load(Ordering::Relaxed)
}

/// `len` rounded up to a whole number of pages, for a [`UmemRegion`] that
/// must hold `len` bytes (af-xdp-backend.md 6.1); `None` on overflow.
#[must_use]
pub fn page_rounded(len: usize) -> Option<usize> {
    len.checked_next_multiple_of(rustix::param::page_size())
}

/// An anonymous, private, zero-filled and prefaulted region for a UMEM:
/// page aligned, `len` a multiple of the page size, never heap memory
/// (design 6.4).
#[derive(Debug)]
pub struct UmemRegion {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: the region is plain memory owned by this value; it is moved
// between threads with its owner and accessed through raw pointers only.
unsafe impl Send for UmemRegion {}

impl UmemRegion {
    /// Maps `len` bytes.
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidRegion`] for a length that is zero, not a
    /// multiple of the page size or over `isize::MAX`;
    /// [`SysError::Os`] naming `mmap`.
    pub fn new(len: usize) -> Result<Self, SysError> {
        let page = rustix::param::page_size();
        if len == 0 || !len.is_multiple_of(page) || isize::try_from(len).is_err() {
            return Err(SysError::InvalidRegion { address: 0, len });
        }
        // SAFETY: a fresh anonymous mapping at an address the kernel chooses
        // (null hint); it aliases no Rust object.
        let raw = unsafe {
            rustix::mm::mmap_anonymous(
                core::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE | MapFlags::POPULATE,
            )
        }
        .map_err(os("mmap"))?;
        let base =
            NonNull::new(raw.cast::<u8>()).ok_or(SysError::InvalidRegion { address: 0, len })?;
        LIVE_UMEM_BYTES.fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::Relaxed);
        Ok(Self { base, len })
    }

    /// The first byte of the region.
    #[must_use]
    pub fn base(&self) -> NonNull<u8> {
        self.base
    }

    /// The region's length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the region is empty; never, by construction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for UmemRegion {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the range mapped in `new`, once. The owner
        // (`karyos-io`'s socket core) drops this only after the socket that
        // registered it is closed, or forgets it (design 11.3).
        let result = unsafe { rustix::mm::munmap(self.base.as_ptr().cast::<c_void>(), self.len) };
        if result.is_ok() {
            LIVE_UMEM_BYTES.fetch_sub(u64::try_from(self.len).unwrap_or(0), Ordering::Relaxed);
        }
    }
}

/// A shared, read and write mapping of `len` bytes of `fd` at page offset
/// `offset`: one ring of an AF_XDP socket.
#[derive(Debug)]
pub struct RingMapping {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: as for `UmemRegion`; the ring words are accessed atomically by
// the owner.
unsafe impl Send for RingMapping {}

impl RingMapping {
    /// Maps the ring of `fd` at `offset` (one of the `XDP_*_PGOFF_*`
    /// offsets).
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidRegion`] for a zero or oversized length;
    /// [`SysError::Os`] naming `mmap`.
    pub fn new(fd: impl AsFd, offset: u64, len: usize) -> Result<Self, SysError> {
        if len == 0 || isize::try_from(len).is_err() {
            return Err(SysError::InvalidRegion { address: 0, len });
        }
        // SAFETY: a fresh shared mapping of the socket's ring at an address
        // the kernel chooses; it aliases no Rust object.
        let raw = unsafe {
            rustix::mm::mmap(
                core::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED | MapFlags::POPULATE,
                fd,
                offset,
            )
        }
        .map_err(os("mmap"))?;
        let base =
            NonNull::new(raw.cast::<u8>()).ok_or(SysError::InvalidRegion { address: 0, len })?;
        Ok(Self { base, len })
    }

    /// The first byte of the mapping.
    #[must_use]
    pub fn base(&self) -> NonNull<u8> {
        self.base
    }

    /// The mapping's length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the mapping is empty; never, by construction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for RingMapping {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the range mapped in `new`, once.
        let result = unsafe { rustix::mm::munmap(self.base.as_ptr().cast::<c_void>(), self.len) };
        let _ = result;
    }
}

#[cfg(test)]
#[cfg(not(miri))]
mod tests {
    use super::*;

    #[test]
    fn a_umem_region_is_page_aligned_and_rejects_partial_pages() {
        let page = rustix::param::page_size();
        let region = UmemRegion::new(page * 2).unwrap();
        assert_eq!(region.len(), page * 2);
        assert_eq!(region.base().as_ptr() as usize % page, 0);
        assert!(UmemRegion::new(page + 1).is_err());
        assert!(UmemRegion::new(0).is_err());
    }
}
