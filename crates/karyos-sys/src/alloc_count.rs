// SPDX-License-Identifier: Apache-2.0

//! A counting global allocator for tests that must prove a call allocates
//! and frees nothing (`quantstratum-docs: karyos/design/ipc-data-path.md`,
//! Tests: "a counting allocator showing no allocation and no free inside
//! the data call that crosses the seal"). Test hook only.
//!
//! A test binary installs it with
//! `#[global_allocator] static A: CountingAllocator = CountingAllocator;`
//! and wraps the call in [`count`]. Only the calling thread's operations
//! are counted, so tests running in parallel do not disturb each other.
//! For a path that spans threads (an executor's tasks, a background
//! thread), each thread of the path [`enroll`]s and [`window`] sums every
//! enrolled thread's operations while it runs (karyos#691).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

thread_local! {
    /// Whether this thread is inside [`count`].
    static ARMED: Cell<bool> = const { Cell::new(false) };
    /// Allocations, reallocations and frees seen while armed.
    static SEEN: Cell<u64> = const { Cell::new(0) };
    /// Allocations and reallocations alone seen while armed.
    static ALLOCATED: Cell<u64> = const { Cell::new(0) };
}

thread_local! {
    /// How many [`Enrolled`] guards this thread holds: while above 0 and a
    /// [`window`] is open, its operations count in the set's totals.
    static ENROLLED: Cell<u32> = const { Cell::new(0) };
}

/// Whether a [`window`] is open.
static WINDOW: AtomicBool = AtomicBool::new(false);
/// Allocations and reallocations of enrolled threads in the window.
static SET_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
/// Frees of enrolled threads in the window.
static SET_FREES: AtomicU64 = AtomicU64::new(0);

/// Counts an operation of an enrolled thread while a window is open.
fn note_set(allocation: bool) {
    if !WINDOW.load(Ordering::Relaxed) || ENROLLED.try_with(Cell::get).unwrap_or(0) == 0 {
        return;
    }
    let counter = if allocation {
        &SET_ALLOCATIONS
    } else {
        &SET_FREES
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// A thread enrolled in the counted set until the guard drops: the
/// declared path's threads (quantstratum-docs:
/// karyos/evaluations/c5-raft-comparison-v1.md, Hard gates, allocation,
/// karyos#691). Guards nest.
#[derive(Debug)]
#[must_use = "the thread is enrolled only while the guard lives"]
pub struct Enrolled(());

impl Drop for Enrolled {
    fn drop(&mut self) {
        let _ = ENROLLED.try_with(|count| count.set(count.get().saturating_sub(1)));
    }
}

/// Enrolls the calling thread in the counted set until the guard drops.
pub fn enroll() -> Enrolled {
    let _ = ENROLLED.try_with(|count| count.set(count.get().saturating_add(1)));
    Enrolled(())
}

/// What the enrolled threads did in a [`window`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetCounts {
    /// Allocations and reallocations.
    pub allocations: u64,
    /// Frees.
    pub frees: u64,
}

/// Runs `call` with the window open: every allocation, reallocation and
/// free of a thread enrolled meanwhile, on any thread, counts. One window
/// at a time in a process (its callers serialize). Meaningful only when
/// [`CountingAllocator`] is the global allocator.
pub fn window<R>(call: impl FnOnce() -> R) -> (R, SetCounts) {
    /// Closes the window on every exit, a panic in `call` included.
    struct Close;

    impl Drop for Close {
        fn drop(&mut self) {
            WINDOW.store(false, Ordering::SeqCst);
        }
    }

    SET_ALLOCATIONS.store(0, Ordering::SeqCst);
    SET_FREES.store(0, Ordering::SeqCst);
    WINDOW.store(true, Ordering::SeqCst);
    let close = Close;
    let result = call();
    drop(close);
    let counts = SetCounts {
        allocations: SET_ALLOCATIONS.load(Ordering::SeqCst),
        frees: SET_FREES.load(Ordering::SeqCst),
    };
    (result, counts)
}

/// The system allocator, counting the calling thread's operations while
/// [`count`] runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct CountingAllocator;

/// Counts an allocation or a reallocation, which also counts in [`note`].
fn note_allocation() {
    let armed = ARMED.try_with(Cell::get).unwrap_or(false);
    if armed {
        let _ = ALLOCATED.try_with(|seen| seen.set(seen.get().saturating_add(1)));
    }
}

fn note() {
    // `try_with`: a thread-local being destroyed is simply not counted.
    // These const-initialized cells need no destructor and never allocate.
    let armed = ARMED.try_with(Cell::get).unwrap_or(false);
    if armed {
        let _ = SEEN.try_with(|seen| seen.set(seen.get().saturating_add(1)));
    }
}

// SAFETY: every method forwards its arguments unchanged to `System`, which
// upholds the `GlobalAlloc` contract; `note`, `note_allocation` and
// `note_set` only touch const-initialized thread-local cells, which need no
// destructor, and static atomics, which never allocate. On the targets these tests
// run on (Linux and macOS, native thread-locals) touching them never
// allocates, so the allocator never re-enters itself; a target with the
// OS-key thread-local fallback would allocate on first access.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        note_allocation();
        note_set(true);
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        note_allocation();
        note_set(true);
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note();
        note_set(false);
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note();
        note_allocation();
        note_set(true);
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Runs `call` and returns its result with the number of allocations,
/// reallocations and frees it made on this thread. Meaningful only when
/// [`CountingAllocator`] is the global allocator.
pub fn count<R>(call: impl FnOnce() -> R) -> (R, u64) {
    /// Disarms the thread on every exit, a panic in `call` included.
    struct Disarm;

    impl Drop for Disarm {
        fn drop(&mut self) {
            let _ = ARMED.try_with(|armed| armed.set(false));
        }
    }

    SEEN.with(|seen| seen.set(0));
    ARMED.with(|armed| armed.set(true));
    let disarm = Disarm;
    let result = call();
    drop(disarm);
    (result, SEEN.with(Cell::get))
}

/// [`count`], counting allocations and reallocations only: for a call
/// that may free (dropping what it retires) but must not allocate.
pub fn count_allocations<R>(call: impl FnOnce() -> R) -> (R, u64) {
    ALLOCATED.with(|seen| seen.set(0));
    let (result, _) = count(call);
    (result, ALLOCATED.with(Cell::get))
}
