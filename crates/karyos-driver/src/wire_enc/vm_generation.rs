// SPDX-License-Identifier: Apache-2.0

//! The virtual machine generation change of `quantstratum-docs:
//! karyos/adr/0114-encrypted-protection-profile-v1.md` section 10 in the
//! driver.
//!
//! A [`GenerationSignal`] is the platform's signal. No platform Karyos
//! runs on provides one to user space today, so [`platform_signal`] is
//! [`NoSignal`] everywhere ([`SignalState::Unavailable`]) and the
//! deployment rule of section 10 alone applies; section 3 states what a
//! violation exposes. On Linux, `drivers/virt/vmgenid.c` notifies only the
//! kernel's random number generator: the `NEW_VMGENID=1` uevent added by
//! torvalds/linux ad6bcdad2b67 ("vmgenid: emit uevent when VMGENID
//! updates", 2023-11-30) was reverted by 3aadf100f93d (2024-04-18, Cc
//! stable), so no kernel series to rely on emits it. A platform signal
//! implements [`GenerationSignal`] and is returned by [`platform_signal`];
//! nothing else changes. Tests inject the signal (`InjectedSignal`).
//! The trigger is the signal, never a timer: a [`VmGenerationWatch`] only
//! limits how often it reads it.
//!
//! The fence counts generations. A change moves it to the next one, and
//! from then on, at once and for every encrypted incarnation of the
//! process (step 1), nothing made under an earlier generation seals or
//! opens again (each [`super::EncSealer`] and [`super::EncOpener`] keeps
//! the generation it was made in), and while the fence is [`quiesced`] no
//! key is derived and no bootstrap datagram is opened. Each role that holds
//! an encrypted incarnation is [`register`]ed; at its next duty it closes
//! its incarnations, dropping every derived key and sequence, which erases
//! them (step 2), redraws its identities (step 3: the receiver its
//! `receiver_boot_id`, the sender its publications' `driver_id` through
//! [`successor`], the embedded driver its own through the same table), and
//! reports [`redrawn`]. Once every registered role has, the fence is
//! released: keys are derived again, only under the fresh identities, and
//! the incarnations re-establish through fresh challenges (step 4). No
//! `(key, nonce)` pair can therefore be used on both sides of a change: a
//! key made before it is never used after it, and every key made after it
//! has a new `driver_id` or `receiver_boot_id` in its context.

use core::sync::atomic::{AtomicU64, Ordering};

/// How often a watch reads the platform's signal at most. Between reads
/// the fence itself is a load.
pub(crate) const POLL_INTERVAL_NS: u64 = 1_000_000;

/// Whether the platform gives a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalState {
    /// The signal is read: a change closes the encrypted class.
    Available,
    /// No signal on this platform or host: the deployment rule alone
    /// applies.
    Unavailable,
}

/// A source of VM generation changes.
pub trait GenerationSignal: Send {
    /// Whether this source reads a platform signal.
    fn state(&self) -> SignalState;
    /// Whether a generation change happened since the last call. Never
    /// blocks. A source that may have lost a change reports one.
    fn changed(&mut self) -> bool;
}

/// No signal: a platform without one, or a host where it cannot be read.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSignal;

impl GenerationSignal for NoSignal {
    fn state(&self) -> SignalState {
        SignalState::Unavailable
    }

    fn changed(&mut self) -> bool {
        false
    }
}

/// The platform's signal: none on any supported platform today (see the
/// module documentation), so the deployment rule alone applies.
#[must_use]
pub fn platform_signal() -> Box<dyn GenerationSignal> {
    Box::new(NoSignal)
}

/// A signal a test changes through its [`SignalInjector`].
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Debug)]
pub struct InjectedSignal {
    changes: std::sync::Arc<AtomicU64>,
    seen: u64,
}

/// The handle that changes an [`InjectedSignal`].
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Debug, Clone)]
pub struct SignalInjector(std::sync::Arc<AtomicU64>);

#[cfg(any(test, feature = "test-hooks"))]
impl InjectedSignal {
    /// A signal and the handle that changes it.
    #[must_use]
    pub fn new() -> (Self, SignalInjector) {
        let changes = std::sync::Arc::new(AtomicU64::new(0));
        (
            Self {
                changes: changes.clone(),
                seen: 0,
            },
            SignalInjector(changes),
        )
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl SignalInjector {
    /// Signals one generation change.
    pub fn change(&self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl GenerationSignal for InjectedSignal {
    fn state(&self) -> SignalState {
        SignalState::Available
    }

    fn changed(&mut self) -> bool {
        let changes = self.changes.load(Ordering::Acquire);
        let changed = changes != self.seen;
        self.seen = changes;
        changed
    }
}

/// The fence: the generation, how many roles hold an encrypted
/// incarnation and how many of them redrew in this generation, and the
/// table of `driver_id` successors. Every driver of a process runs on the
/// same machine, so the fence is the process's. A unit test has its own,
/// on its thread, so that one test's change closes no other test's keys.
#[derive(Debug, Default)]
struct Fence {
    generation: u64,
    released: u64,
    registered: u32,
    redrawn: u32,
    /// `(old, new, generation)`: each id is succeeded once per generation.
    successors: Vec<([u64; 2], [u64; 2], u64)>,
}

impl Fence {
    const fn new() -> Self {
        Self {
            generation: 0,
            released: 0,
            registered: 0,
            redrawn: 0,
            successors: Vec::new(),
        }
    }

    fn release_if_done(&mut self) {
        if self.redrawn >= self.registered {
            self.released = self.generation;
        }
    }
}

#[cfg(not(test))]
static FENCE: std::sync::Mutex<Fence> = std::sync::Mutex::new(Fence::new());
/// The generation and the released generation, read without the lock on
/// the data path.
#[cfg(not(test))]
static GENERATION: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
static RELEASED: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static FENCE: std::cell::RefCell<Fence> = const { std::cell::RefCell::new(Fence::new()) };
}

/// Runs `f` on the fence and publishes its generations.
fn with_fence<R>(f: impl FnOnce(&mut Fence) -> R) -> R {
    #[cfg(not(test))]
    {
        let mut fence = FENCE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = f(&mut fence);
        GENERATION.store(fence.generation, Ordering::Release);
        RELEASED.store(fence.released, Ordering::Release);
        result
    }
    #[cfg(test)]
    FENCE.with(|fence| f(&mut fence.borrow_mut()))
}

/// The current generation: the VM generation changes this process has
/// seen.
#[must_use]
pub fn generation() -> u64 {
    #[cfg(not(test))]
    let generation = GENERATION.load(Ordering::Acquire);
    #[cfg(test)]
    let generation = FENCE.with(|fence| fence.borrow().generation);
    generation
}

/// Whether a change is not yet released: some registered role has not
/// redrawn its identities. No key is derived meanwhile.
#[must_use]
pub fn quiesced() -> bool {
    #[cfg(not(test))]
    let quiesced = RELEASED.load(Ordering::Acquire) != GENERATION.load(Ordering::Acquire);
    #[cfg(test)]
    let quiesced = FENCE.with(|fence| {
        let fence = fence.borrow();
        fence.released != fence.generation
    });
    quiesced
}

/// The VM generation changes this process has seen.
#[must_use]
pub fn generation_changes() -> u64 {
    generation()
}

/// Moves the fence to the next generation.
fn mark_changed() {
    with_fence(|fence| {
        fence.generation = fence.generation.saturating_add(1);
        fence.redrawn = 0;
        fence.release_if_done();
    });
}

/// Registers a role that holds an encrypted incarnation, from the
/// current generation on: one made during a change starts fresh, so it
/// counts as redrawn.
pub fn register() {
    with_fence(|fence| {
        fence.registered = fence.registered.saturating_add(1);
        if fence.released != fence.generation {
            fence.redrawn = fence.redrawn.saturating_add(1);
        }
    });
}

/// Reports that a registered role closed its incarnations and redrew its
/// identities for `generation`; the last one releases the fence. A report
/// for an earlier generation changes nothing.
pub fn redrawn(generation: u64) {
    with_fence(|fence| {
        if generation == fence.generation && fence.released != fence.generation {
            fence.redrawn = fence.redrawn.saturating_add(1);
            fence.release_if_done();
        }
    });
}

/// Generations a successor is kept for after the one it was drawn for:
/// every role steps at its next duty and the embedded driver at its next
/// `do_work`, so a caller this far behind is stuck, and fails closed.
pub const KEEP_GENERATIONS: u64 = 4;

/// Successors held at most: one per driver of the process per generation
/// kept. Full, a new one is refused (fail closed).
pub const MAX_SUCCESSORS: usize = 64;

/// The fresh `driver_id` that succeeds `old` in `generation`: drawn once,
/// from the operating system's random source, and then the same for every
/// caller, so that the embedded driver and its sender role agree without a
/// message. Each change takes one step: a caller that missed `n` changes
/// takes `n`, one per generation. An entry is dropped once
/// [`KEEP_GENERATIONS`] newer generations exist, so the table holds at most
/// [`MAX_SUCCESSORS`]. `None` (fail closed: the caller keeps the fence
/// held) when the random source fails, the table is full, or `generation`
/// is not one of the generations kept.
#[must_use]
pub fn successor(old: [u64; 2], generation: u64) -> Option<[u64; 2]> {
    let lookup = |fence: &mut Fence| {
        let kept = generation != 0
            && generation <= fence.generation
            && generation.saturating_add(KEEP_GENERATIONS) > fence.generation;
        kept.then(|| {
            fence
                .successors
                .iter()
                .find(|(held, _, at)| *held == old && *at == generation)
                .map(|(_, new, _)| *new)
        })
    };
    match with_fence(lookup) {
        None => return None,
        Some(Some(new)) => return Some(new),
        Some(None) => {}
    }
    let mut new = [0_u64; 2];
    while new == [0, 0] || new == old {
        karyos_sys::random::fill_u64s(&mut new).ok()?;
    }
    with_fence(|fence| {
        if let Some(held) = lookup(fence)? {
            return Some(held);
        }
        let current = fence.generation;
        fence
            .successors
            .retain(|(_, _, at)| at.saturating_add(KEEP_GENERATIONS) > current);
        if fence.successors.len() >= MAX_SUCCESSORS {
            return None;
        }
        fence.successors.push((old, new, generation));
        Some(new)
    })
}

/// Successors held (tests).
#[cfg(test)]
pub(crate) fn successors_held() -> usize {
    with_fence(|fence| fence.successors.len())
}

/// A role's reader of the signal.
pub struct VmGenerationWatch {
    signal: Box<dyn GenerationSignal>,
    next_read_ns: u64,
}

impl core::fmt::Debug for VmGenerationWatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VmGenerationWatch")
            .field("state", &self.signal.state())
            .finish_non_exhaustive()
    }
}

impl VmGenerationWatch {
    /// A watch of `signal`.
    #[must_use]
    pub fn new(signal: Box<dyn GenerationSignal>) -> Self {
        Self {
            signal,
            next_read_ns: 0,
        }
    }

    /// A watch of the platform's signal.
    #[must_use]
    pub fn platform() -> Self {
        Self::new(platform_signal())
    }

    /// Whether the platform gives a signal.
    #[must_use]
    pub fn state(&self) -> SignalState {
        self.signal.state()
    }

    /// Reads the signal, at most once per `POLL_INTERVAL_NS` of `now_ns`,
    /// moves the fence on a change, and returns the current generation (a
    /// change seen by this watch or any other).
    pub fn poll(&mut self, now_ns: u64) -> u64 {
        if now_ns >= self.next_read_ns {
            self.next_read_ns = now_ns.saturating_add(POLL_INTERVAL_NS);
            if self.signal.changed() {
                mark_changed();
            }
        }
        generation()
    }
}

#[cfg(test)]
mod tests;
