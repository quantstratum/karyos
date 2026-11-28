// SPDX-License-Identifier: Apache-2.0

//! Encrypted verification on worker threads (`quantstratum-docs:
//! karyos/adr/0126-encrypted-verification-on-worker-threads.md`).
//!
//! A receiving role hands the pure cryptographic step of an encrypted
//! datagram, the AEAD open and the pairwise trailer, to a fixed pool of
//! verifier threads; everything else stays on the role thread
//! (`super::EncOpener::prepare` before, `super::EncOpener::complete`
//! after). This module is the pool:
//!
//! - **A fixed slot table** (decision 4), made once at the first
//!   encrypted subscription: a slot holds the datagram's bytes, the
//!   plaintext buffer, the job's `Lease` and its outcome. It belongs to
//!   the role from reservation (`VerifyPool::dispatch`), to a verifier
//!   while it runs, and back to the role, which consumes and frees it
//!   (`VerifyPool::take`). A slot is never reused before it is freed.
//!   When none is free the datagram is dropped before dispatch.
//! - **Arrival order**: the role consumes results in the order it
//!   dispatched them, one FIFO for the whole role, which orders every
//!   binding and every source; a slot not yet done holds back the later
//!   ones. There is no queue beyond the table.
//! - **One terminal outcome per job**: verified, refused by the open, or
//!   cancelled (`Outcome`), so the order always advances.
//! - **Cancellation** (decision 5): the role cancels queued jobs
//!   (`VerifyPool::cancel_where`), and a verifier reads the opener's
//!   withdrawn mark before it opens and cancels instead.
//! - **Leases**: each job's lease returns exactly once, when the role
//!   consumes the job, or when the pool is dropped.
//!
//! A slot's state is one atomic (free, queued, running, done); its
//! contents are behind a mutex that only the slot's current owner locks,
//! so it is never contended. The dispatch order reaches the verifiers
//! through a ring of slot indices sized like the table; the slot state's
//! compare-and-swap, not the ring, decides who runs a job, so a stale ring
//! entry (a cancelled job's) is skipped. Idle verifiers spin briefly, then
//! park until the role dispatches. Nothing here allocates after
//! construction.
//!
//! With zero verifiers there is no pool: the role opens inline, today's
//! path and the default.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{JoinHandle, Thread};

use karyos_protocol::protection::aes_gcm_siv::{
    EncRejection, HEADER_LEN, MAX_DATAGRAM, MAX_PLAINTEXT, Opened,
};

use super::Lease;

/// Verifier threads a receiver role may run at most.
pub const MAX_ENC_VERIFIERS: u16 = 16;
/// In-flight verification slots per role by default: four receive
/// batches of the default `rx_datagrams` (64).
pub const DEFAULT_ENC_VERIFY_SLOTS: u16 = 256;
/// In-flight verification slots per role at most: about 11 MiB of
/// datagram and plaintext buffers.
pub const MAX_ENC_VERIFY_SLOTS: u16 = 4_096;
/// Spins an idle verifier makes before it parks.
const IDLE_SPINS: u32 = 1 << 12;

/// Pools whose every verifier thread failed to start, so that their role
/// opens inline instead ([`VerifyPool::new`]).
static INLINE_FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// How many receiver roles fell back to opening on their own thread
/// because none of their verifier threads could start.
#[must_use]
pub fn enc_verify_inline_fallbacks() -> u64 {
    INLINE_FALLBACKS.load(Ordering::Relaxed)
}

/// Slot states.
const FREE: u8 = 0;
const QUEUED: u8 = 1;
const RUNNING: u8 = 2;
const DONE: u8 = 3;

/// The verifier pool of a receiving role (ADR-0126): `verifiers` threads
/// and `slots` in-flight jobs. `verifiers` 0, the default, opens every
/// encrypted datagram on the role thread, as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncVerifyConfig {
    /// Verifier threads, 0 to [`MAX_ENC_VERIFIERS`]; 0 runs no pool.
    pub verifiers: u16,
    /// In-flight job slots, 1 to [`MAX_ENC_VERIFY_SLOTS`], allocated with
    /// the pool. A datagram that finds none free is dropped before its
    /// open and counted (`enc_verify_busy`).
    pub slots: u16,
}

impl Default for EncVerifyConfig {
    fn default() -> Self {
        Self {
            verifiers: 0,
            slots: DEFAULT_ENC_VERIFY_SLOTS,
        }
    }
}

impl EncVerifyConfig {
    /// Checks the bounds.
    ///
    /// # Errors
    ///
    /// The bound a value is outside of.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.verifiers > MAX_ENC_VERIFIERS {
            return Err("enc_verify.verifiers must be at most 16");
        }
        if !(1..=MAX_ENC_VERIFY_SLOTS).contains(&self.slots) {
            return Err("enc_verify.slots must be 1 to 4096");
        }
        Ok(())
    }
}

/// A job's terminal outcome (ADR-0126 decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The tag and the pairwise trailer verified: the plaintext is the
    /// job's.
    Verified(Opened),
    /// The open refused it.
    Failed(EncRejection),
    /// Cancelled before its open: its opener was withdrawn.
    Cancelled,
}

/// A consumed job, back on the role thread with its context, its outcome,
/// its lease (returned when this is dropped) and the authenticated header
/// and length of the bytes it verified.
#[derive(Debug)]
pub(crate) struct Done<C> {
    pub(crate) context: C,
    pub(crate) outcome: Outcome,
    pub(crate) lease: Option<Lease>,
    pub(crate) header: [u8; HEADER_LEN],
    pub(crate) len: usize,
}

/// The contents of one slot.
struct Job {
    bytes: [u8; MAX_DATAGRAM],
    len: usize,
    plain: [u8; MAX_PLAINTEXT],
    lease: Option<Lease>,
    outcome: Outcome,
}

/// A value on cache lines of its own (two 64-byte lines, for the
/// adjacent-line prefetch).
#[repr(align(128))]
struct Padded<T>(T);

impl<T> core::ops::Deref for Padded<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

/// One slot: its state and its contents, on cache lines of its own.
#[repr(align(128))]
struct Cell {
    state: AtomicU8,
    job: Mutex<Job>,
}

impl Cell {
    fn lock(&self) -> MutexGuard<'_, Job> {
        self.job.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the role and its verifiers share.
struct Shared {
    cells: Box<[Cell]>,
    /// The dispatch order, slot indices by dispatch number modulo the
    /// table's size.
    ring: Box<[AtomicU32]>,
    /// Jobs dispatched; written by the role only.
    produced: Padded<AtomicU64>,
    /// Ring entries taken by verifiers.
    claimed: Padded<AtomicU64>,
    stop: AtomicBool,
    /// Per verifier: parked, waiting for a dispatch.
    sleeping: Box<[AtomicBool]>,
}

impl Shared {
    /// Takes the next ring entry and runs its job; whether it ran one.
    fn run_one(&self) -> bool {
        loop {
            let claimed = self.claimed.load(Ordering::Acquire);
            if claimed >= self.produced.load(Ordering::Acquire) {
                return false;
            }
            if self
                .claimed
                .compare_exchange_weak(
                    claimed,
                    claimed.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            let at = usize::try_from(claimed % self.ring.len().max(1) as u64).unwrap_or(0);
            let index = self
                .ring
                .get(at)
                .map_or(u32::MAX, |entry| entry.load(Ordering::Acquire));
            if self.run(usize::try_from(index).unwrap_or(usize::MAX)) {
                return true;
            }
        }
    }

    /// Runs the job at `index` if it is queued: the withdrawn mark first,
    /// then the open. Whether it ran it.
    fn run(&self, index: usize) -> bool {
        let Some(cell) = self.cells.get(index) else {
            return false;
        };
        if cell
            .state
            .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let mut guard = cell.lock();
        let Job {
            bytes,
            len,
            plain,
            lease,
            outcome,
        } = &mut *guard;
        *outcome = match lease.as_ref() {
            Some(lease) if !lease.is_withdrawn() => {
                let datagram = bytes.get(..*len).unwrap_or_default();
                match lease.key().open_verified_into(datagram, plain) {
                    Ok(opened) => Outcome::Verified(opened),
                    Err(reason) => Outcome::Failed(reason),
                }
            }
            _ => Outcome::Cancelled,
        };
        drop(guard);
        cell.state.store(DONE, Ordering::Release);
        true
    }

    /// Whether a dispatched job waits for a verifier.
    fn waiting(&self) -> bool {
        self.claimed.load(Ordering::SeqCst) < self.produced.load(Ordering::SeqCst)
    }
}

/// One verifier thread: runs jobs in dispatch order, spins a little when
/// idle, then parks until the role dispatches again or stops.
fn verifier(shared: &Shared, me: usize) {
    let mut idle = 0_u32;
    while !shared.stop.load(Ordering::Acquire) {
        if shared.run_one() {
            idle = 0;
            continue;
        }
        if idle < IDLE_SPINS {
            idle = idle.saturating_add(1);
            core::hint::spin_loop();
            continue;
        }
        idle = 0;
        let Some(sleeping) = shared.sleeping.get(me) else {
            std::thread::yield_now();
            continue;
        };
        sleeping.store(true, Ordering::SeqCst);
        if shared.waiting() || shared.stop.load(Ordering::SeqCst) {
            sleeping.store(false, Ordering::SeqCst);
            continue;
        }
        std::thread::park();
        sleeping.store(false, Ordering::SeqCst);
    }
}

/// A role's verifier pool: the slot table, its verifiers, and the role's
/// own dispatch order and free list. `C` is the context the role records
/// for each job. Owned by the role; dropping it stops and joins the
/// verifiers, after which every lease still in a slot returns.
pub(crate) struct VerifyPool<C> {
    shared: Arc<Shared>,
    /// Per slot, the role's context of its job.
    contexts: Box<[Option<C>]>,
    /// The dispatch order: slot indices, `head` the oldest, `len` in
    /// flight.
    order: Box<[u32]>,
    head: usize,
    len: usize,
    /// Free slot indices, a stack of `free_len`.
    free: Box<[u32]>,
    free_len: usize,
    /// The verifiers that started, each with its own index into
    /// `sleeping`, to wake them.
    threads: Box<[(usize, Thread)]>,
    handles: Vec<JoinHandle<()>>,
}

impl<C> core::fmt::Debug for VerifyPool<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyPool")
            .field("slots", &self.contexts.len())
            .field("verifiers", &self.threads.len())
            .field("in_flight", &self.len)
            .finish_non_exhaustive()
    }
}

impl<C: Copy + Send + 'static> VerifyPool<C> {
    /// The pool of `config`, its table allocated now and every slot's
    /// mutex set up; with `spawn`, its verifiers started (a thread that
    /// cannot start is left out: the role runs a job itself whenever it
    /// waits for one). Without `spawn` (tests) nothing verifies until the
    /// role waits, or a test runs a job.
    ///
    /// `None` when verifiers were asked for and none could start: the
    /// role then opens inline, as with zero verifiers, and the fallback is
    /// counted ([`enc_verify_inline_fallbacks`]).
    pub(crate) fn new(config: EncVerifyConfig, spawn: bool) -> Option<Self> {
        Self::start(config, spawn, |_| false)
    }

    /// [`Self::new`], with verifier `me` failing to start when `fails`
    /// says so (tests).
    fn start(config: EncVerifyConfig, spawn: bool, fails: impl Fn(usize) -> bool) -> Option<Self> {
        let slots = usize::from(config.slots.clamp(1, MAX_ENC_VERIFY_SLOTS));
        let verifiers = usize::from(config.verifiers.min(MAX_ENC_VERIFIERS));
        let shared = Arc::new(Shared {
            cells: (0..slots)
                .map(|_| Cell {
                    state: AtomicU8::new(FREE),
                    job: Mutex::new(Job {
                        bytes: [0; MAX_DATAGRAM],
                        len: 0,
                        plain: [0; MAX_PLAINTEXT],
                        lease: None,
                        outcome: Outcome::Cancelled,
                    }),
                })
                .collect(),
            ring: (0..slots).map(|_| AtomicU32::new(u32::MAX)).collect(),
            produced: Padded(AtomicU64::new(0)),
            claimed: Padded(AtomicU64::new(0)),
            stop: AtomicBool::new(false),
            sleeping: (0..verifiers).map(|_| AtomicBool::new(false)).collect(),
        });
        // A platform whose mutex sets itself up on first use (a lazily
        // boxed pthread mutex on macOS) would allocate at a slot's first
        // dispatch: each is locked once now, before any verifier runs.
        for cell in &*shared.cells {
            drop(cell.lock());
        }
        let mut handles = Vec::with_capacity(verifiers);
        let mut threads = Vec::with_capacity(verifiers);
        if spawn {
            for me in 0..verifiers {
                if fails(me) {
                    continue;
                }
                let held = Arc::clone(&shared);
                let started = std::thread::Builder::new()
                    .name(format!("karyos-enc-verify-{me}"))
                    .spawn(move || verifier(&held, me));
                if let Ok(handle) = started {
                    threads.push((me, handle.thread().clone()));
                    handles.push(handle);
                }
            }
            if verifiers > 0 && handles.is_empty() {
                INLINE_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        Some(Self {
            shared,
            contexts: (0..slots).map(|_| None).collect(),
            order: (0..slots).map(|_| 0).collect(),
            head: 0,
            len: 0,
            free: (0..slots)
                .rev()
                .map(|index| u32::try_from(index).unwrap_or(u32::MAX))
                .collect(),
            free_len: slots,
            threads: threads.into_boxed_slice(),
            handles,
        })
    }

    /// Jobs dispatched and not yet consumed.
    pub(crate) fn in_flight(&self) -> usize {
        self.len
    }

    /// Whether a slot is free.
    pub(crate) fn has_free(&self) -> bool {
        self.free_len > 0
    }

    /// Reserves a slot for `datagram` and queues its job, bound to
    /// `context` and holding `lease` (ADR-0126 decisions 2 and 4), then
    /// wakes a parked verifier. Allocates nothing.
    ///
    /// # Errors
    ///
    /// The lease back when no slot is free, or the datagram does not fit
    /// one: the datagram is dropped before dispatch.
    pub(crate) fn dispatch(
        &mut self,
        datagram: &[u8],
        lease: Lease,
        context: C,
    ) -> Result<(), Lease> {
        if self.free_len == 0 || datagram.len() > MAX_DATAGRAM {
            return Err(lease);
        }
        let Some(index) = self
            .free_len
            .checked_sub(1)
            .and_then(|top| self.free.get(top).copied())
        else {
            return Err(lease);
        };
        let at = usize::try_from(index).unwrap_or(usize::MAX);
        let Some(cell) = self.shared.cells.get(at) else {
            return Err(lease);
        };
        {
            let mut job = cell.lock();
            if let Some(target) = job.bytes.get_mut(..datagram.len()) {
                target.copy_from_slice(datagram);
            }
            job.len = datagram.len();
            job.lease = Some(lease);
            job.outcome = Outcome::Cancelled;
        }
        self.free_len = self.free_len.saturating_sub(1);
        if let Some(held) = self.contexts.get_mut(at) {
            *held = Some(context);
        }
        let size = self.order.len().max(1);
        if let Some(entry) = self.order.get_mut((self.head + self.len) % size) {
            *entry = index;
        }
        self.len = self.len.saturating_add(1);
        cell.state.store(QUEUED, Ordering::Release);
        let produced = self.shared.produced.load(Ordering::Relaxed);
        let ring = self.shared.ring.len().max(1) as u64;
        if let Some(entry) = self
            .shared
            .ring
            .get(usize::try_from(produced % ring).unwrap_or(0))
        {
            entry.store(index, Ordering::Release);
        }
        self.shared
            .produced
            .store(produced.wrapping_add(1), Ordering::SeqCst);
        self.wake();
        Ok(())
    }

    /// Wakes one parked verifier, if any.
    fn wake(&self) {
        for (me, thread) in &*self.threads {
            if self
                .shared
                .sleeping
                .get(*me)
                .is_some_and(|sleeping| sleeping.swap(false, Ordering::SeqCst))
            {
                thread.unpark();
                return;
            }
        }
    }

    /// The oldest job, if it is done: consumed and its slot freed, its
    /// plaintext copied to `plain` when it verified. `None` while it is
    /// not done (it holds back the later ones) or nothing is in flight.
    /// Allocates nothing.
    pub(crate) fn take(&mut self, plain: &mut [u8; MAX_PLAINTEXT]) -> Option<Done<C>> {
        if self.len == 0 {
            return None;
        }
        let index = *self.order.get(self.head)?;
        let at = usize::try_from(index).ok()?;
        let cell = self.shared.cells.get(at)?;
        if cell.state.load(Ordering::Acquire) != DONE {
            return None;
        }
        let (outcome, lease, header, len) = {
            let mut job = cell.lock();
            let outcome = job.outcome;
            if let Outcome::Verified(opened) = outcome {
                let end = opened.frames.min(MAX_PLAINTEXT);
                if let (Some(target), Some(source)) = (plain.get_mut(..end), job.plain.get(..end)) {
                    target.copy_from_slice(source);
                }
            }
            let mut header = [0_u8; HEADER_LEN];
            if let Some(source) = job.bytes.get(..HEADER_LEN) {
                header.copy_from_slice(source);
            }
            (outcome, job.lease.take(), header, job.len)
        };
        let context = self.contexts.get_mut(at).and_then(Option::take)?;
        cell.state.store(FREE, Ordering::Release);
        if let Some(entry) = self.free.get_mut(self.free_len) {
            *entry = index;
            self.free_len = self.free_len.saturating_add(1);
        }
        self.head = (self.head + 1) % self.order.len().max(1);
        self.len = self.len.saturating_sub(1);
        Some(Done {
            context,
            outcome,
            lease,
            header,
            len,
        })
    }

    /// [`Self::take`], waiting for the oldest job to be done; while it
    /// waits the role runs queued jobs itself, so it never waits on a
    /// verifier that is not running. `None` when nothing is in flight.
    pub(crate) fn take_waiting(&mut self, plain: &mut [u8; MAX_PLAINTEXT]) -> Option<Done<C>> {
        loop {
            if self.len == 0 {
                return None;
            }
            if let Some(done) = self.take(plain) {
                return Some(done);
            }
            if !self.shared.run_one() {
                core::hint::spin_loop();
            }
        }
    }

    /// Cancels every queued job whose context `matches` (ADR-0126 decision
    /// 5): no verifier starts it, and it ends cancelled. A running job
    /// finishes. Returns the jobs cancelled. Allocates nothing.
    pub(crate) fn cancel_where(&mut self, mut matches: impl FnMut(&C) -> bool) -> usize {
        let size = self.order.len().max(1);
        let mut cancelled = 0_usize;
        for offset in 0..self.len {
            let Some(index) = self.order.get((self.head + offset) % size).copied() else {
                continue;
            };
            let at = usize::try_from(index).unwrap_or(usize::MAX);
            let (Some(cell), Some(Some(context))) =
                (self.shared.cells.get(at), self.contexts.get(at))
            else {
                continue;
            };
            if !matches(context) {
                continue;
            }
            if cell
                .state
                .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                cell.lock().outcome = Outcome::Cancelled;
                cell.state.store(DONE, Ordering::Release);
                cancelled = cancelled.saturating_add(1);
            }
        }
        cancelled
    }

    /// Runs one queued job on this thread, as a verifier would (tests).
    #[cfg(test)]
    pub(crate) fn verify_one(&self) -> bool {
        self.shared.run_one()
    }

    /// Runs the job `offset` places after the oldest, if it is queued
    /// (tests).
    #[cfg(test)]
    pub(crate) fn verify_at(&self, offset: usize) -> bool {
        let size = self.order.len().max(1);
        self.order
            .get((self.head + offset) % size)
            .is_some_and(|index| {
                self.shared
                    .run(usize::try_from(*index).unwrap_or(usize::MAX))
            })
    }

    /// Verifier threads running.
    #[cfg(test)]
    pub(crate) fn verifiers(&self) -> usize {
        self.handles.len()
    }
}

impl<C> Drop for VerifyPool<C> {
    /// Stops and joins the verifiers; the slots, and every lease still in
    /// one, go with the last reference to the table.
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for (_, thread) in &*self.threads {
            thread.unpark();
        }
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests;
