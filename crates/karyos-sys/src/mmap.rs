// SPDX-License-Identifier: Apache-2.0

//! Shared memory backed by a sealed `memfd` (Linux only).
//!
//! The backing is an anonymous `memfd` whose size is sealed before it is
//! mapped (`F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`). The seals live on the
//! inode, so no file descriptor, including one reopened through
//! `/proc/<pid>/fd`, can truncate or extend it: a live mapping can never lose
//! its backing pages. There is no path-based mapping, and no attachment by
//! another process yet; sharing the backing across processes is a later,
//! separately reviewed capability.
//!
//! Contents remain writable by any holder of the file descriptor, as with any
//! shared memory. Processes that bypass the protocol are outside the isolation
//! boundary (SPEC.md §4).

use core::ffi::c_void;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use rustix::fd::OwnedFd;
use rustix::fs::{MemfdFlags, SealFlags};
use rustix::mm::{MapFlags, ProtFlags};

use crate::atomic_view::{AtomicWords, WORD_BYTES};
use crate::error::SysError;

/// Whether to try `mlock` on a new mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockRequest {
    /// Do not lock.
    No,
    /// Try to lock; failure is reported, not fatal.
    Try,
}

/// Outcome of the optional `mlock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    /// Locking was not requested.
    NotRequested,
    /// The mapping is locked.
    Locked,
    /// `mlock` failed with this OS error number; the mapping is usable.
    Failed {
        /// Raw OS error number.
        errno: i32,
    },
}

/// What happened to the optional memory tuning of a mapping. Neither field
/// implies that later page faults cannot occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingReport {
    /// Pages touched once at creation.
    pub prefaulted_pages: usize,
    /// Result of the optional `mlock`.
    pub lock: LockOutcome,
}

/// A size-sealed, shared, read-write mapping of a fresh `memfd`, viewed only
/// as atomic words.
#[derive(Debug)]
pub struct SealedMapping {
    base: NonNull<u8>,
    len: usize,
    // Kept open so the backing can later be shared by descriptor passing. It
    // is never exposed: holders of the descriptor could punch holes in it.
    #[cfg_attr(any(not(test), miri), allow(dead_code))]
    fd: OwnedFd,
    report: MappingReport,
}

// SAFETY: the mapping is process-wide memory, valid from any thread until
// `drop`. `SealedMapping` exposes it only through `AtomicWords`, i.e. shared
// references to `AtomicU64`, which are `Send` and `Sync`. No other state is
// shared without synchronization.
unsafe impl Send for SealedMapping {}
// SAFETY: see the `Send` impl.
unsafe impl Sync for SealedMapping {}

impl SealedMapping {
    /// Creates a sealed mapping of `len` bytes, zero-filled and prefaulted.
    ///
    /// `len` must be a non-zero multiple of the page size. `name` labels the
    /// `memfd` for diagnostics only.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidRegion`] for an invalid length and
    /// [`SysError::Os`] when a system call fails. All resources acquired
    /// before the failure are released.
    pub fn create(name: &str, len: usize, lock: LockRequest) -> Result<Self, SysError> {
        let page = rustix::param::page_size();
        if len == 0 || !len.is_multiple_of(page) || isize::try_from(len).is_err() {
            return Err(SysError::InvalidRegion { address: 0, len });
        }
        let file_len =
            u64::try_from(len).map_err(|_| SysError::InvalidRegion { address: 0, len })?;

        let fd = rustix::fs::memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
            .map_err(os("memfd_create"))?;
        rustix::fs::ftruncate(&fd, file_len).map_err(os("ftruncate"))?;
        rustix::fs::fcntl_add_seals(&fd, SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL)
            .map_err(os("fcntl_add_seals"))?;

        // SAFETY: a fresh mapping at an address chosen by the kernel (null
        // hint) over `len` bytes of a file sealed at exactly `len` bytes; it
        // aliases no existing Rust object.
        let raw = unsafe {
            rustix::mm::mmap(
                core::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &fd,
                0,
            )
        }
        .map_err(os("mmap"))?;
        let base =
            NonNull::new(raw.cast::<u8>()).ok_or(SysError::InvalidRegion { address: 0, len })?;
        let mut mapping = Self {
            base,
            len,
            fd,
            report: MappingReport {
                prefaulted_pages: 0,
                lock: LockOutcome::NotRequested,
            },
        };
        // From here `mapping` owns the region; an early return unmaps it.

        let words = mapping.words_checked()?;
        let page_words = page / WORD_BYTES;
        let mut pages = 0;
        let mut index = 0;
        while let Some(word) = words.get(index) {
            // Prefault: the mapping is fresh and unpublished, so storing the
            // zero it already holds changes nothing observable.
            word.store(0, Ordering::Relaxed);
            pages += 1;
            index = match index.checked_add(page_words) {
                Some(next) => next,
                None => break,
            };
        }
        mapping.report.prefaulted_pages = pages;

        if lock == LockRequest::Try {
            // SAFETY: locks exactly the range this object maps; `mlock` does
            // not change its contents or validity.
            let locked = unsafe { rustix::mm::mlock(mapping.base.as_ptr().cast::<c_void>(), len) };
            mapping.report.lock = match locked {
                Ok(()) => LockOutcome::Locked,
                Err(errno) => LockOutcome::Failed {
                    errno: errno.raw_os_error(),
                },
            };
        }
        Ok(mapping)
    }

    /// Length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always false: a mapping is never empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// What happened to prefaulting and locking.
    #[inline]
    #[must_use]
    pub fn report(&self) -> MappingReport {
        self.report
    }

    /// The mapping as atomic words, borrowed from `self`.
    #[must_use]
    pub fn words(&self) -> AtomicWords<'_> {
        match self.words_checked() {
            Ok(words) => words,
            // `create` validated the same region; this cannot fail.
            Err(_) => AtomicWords::empty(),
        }
    }

    fn words_checked(&self) -> Result<AtomicWords<'_>, SysError> {
        // SAFETY: `base..base + len` is mapped read-write for as long as
        // `self` lives (unmapped only in `drop`), the backing cannot shrink
        // (sealed), the view borrows `self`, and this process accesses the
        // mapping only through `AtomicWords`.
        unsafe { AtomicWords::from_raw(self.base.as_ptr(), self.len) }
    }

    #[cfg(all(test, not(miri)))]
    fn fd(&self) -> &OwnedFd {
        &self.fd
    }
}

impl Drop for SealedMapping {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the range mapped in `create`, once. No view
        // outlives `self`, because every view borrows it.
        let result = unsafe { rustix::mm::munmap(self.base.as_ptr().cast::<c_void>(), self.len) };
        // munmap of a range we mapped cannot fail; there is nothing safe to
        // do if it did, so the error is ignored rather than panicking. The
        // descriptor closes after this, when `self.fd` is dropped.
        let _ = result;
    }
}

fn os(operation: &'static str) -> impl Fn(rustix::io::Errno) -> SysError {
    move |errno| SysError::Os {
        operation,
        errno: errno.raw_os_error(),
    }
}

// Miri cannot execute mmap or memfd system calls; the heap backing covers the
// shared `AtomicWords::from_raw` path under Miri.
#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use rustix::fd::AsRawFd;

    fn page() -> usize {
        rustix::param::page_size()
    }

    #[test]
    fn create_map_access_and_drop() {
        let mapping = SealedMapping::create("karyos-test", 2 * page(), LockRequest::No).unwrap();
        let words = mapping.words();
        assert_eq!(words.len(), 2 * page() / WORD_BYTES);
        assert!(
            words
                .as_slice()
                .iter()
                .all(|w| w.load(Ordering::SeqCst) == 0)
        );
        words.get(5).unwrap().store(0xDEAD_BEEF, Ordering::SeqCst);
        assert_eq!(
            mapping.words().get(5).unwrap().load(Ordering::SeqCst),
            0xDEAD_BEEF
        );
        assert_eq!(mapping.report().prefaulted_pages, 2);
        assert_eq!(mapping.report().lock, LockOutcome::NotRequested);
    }

    #[test]
    fn lock_outcome_is_reported() {
        let mapping = SealedMapping::create("karyos-test", page(), LockRequest::Try).unwrap();
        assert_ne!(mapping.report().lock, LockOutcome::NotRequested);
    }

    #[test]
    fn rejects_invalid_lengths() {
        for len in [0, 1, page() - 8, page() + 8] {
            assert_eq!(
                SealedMapping::create("karyos-test", len, LockRequest::No).err(),
                Some(SysError::InvalidRegion { address: 0, len })
            );
        }
    }

    #[test]
    fn backing_cannot_be_resized_even_through_a_reopened_descriptor() {
        let mapping = SealedMapping::create("karyos-test", page(), LockRequest::No).unwrap();
        let path = format!("/proc/self/fd/{}", mapping.fd().as_raw_fd());
        let reopened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert_eq!(
            reopened.set_len(0).unwrap_err().raw_os_error(),
            Some(rustix::io::Errno::PERM.raw_os_error())
        );
        let grown = u64::try_from(2 * page()).unwrap();
        assert_eq!(
            reopened.set_len(grown).unwrap_err().raw_os_error(),
            Some(rustix::io::Errno::PERM.raw_os_error())
        );
        // The mapping is still fully usable.
        mapping.words().get(0).unwrap().store(1, Ordering::SeqCst);
    }
}
