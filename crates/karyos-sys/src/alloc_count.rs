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

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Whether this thread is inside [`count`].
    static ARMED: Cell<bool> = const { Cell::new(false) };
    /// Allocations, reallocations and frees seen while armed.
    static SEEN: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting the calling thread's operations while
/// [`count`] runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct CountingAllocator;

fn note() {
    // `try_with`: a thread-local being destroyed is simply not counted.
    // These const-initialized cells need no destructor and never allocate.
    let armed = ARMED.try_with(Cell::get).unwrap_or(false);
    if armed {
        let _ = SEEN.try_with(|seen| seen.set(seen.get().saturating_add(1)));
    }
}

// SAFETY: every method forwards its arguments unchanged to `System`, which
// upholds the `GlobalAlloc` contract; `note` only touches const-initialized
// thread-local cells, which need no destructor. On the targets these tests
// run on (Linux and macOS, native thread-locals) touching them never
// allocates, so the allocator never re-enters itself; a target with the
// OS-key thread-local fallback would allocate on first access.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note();
        // SAFETY: forwarded with the caller's guarantees.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note();
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
