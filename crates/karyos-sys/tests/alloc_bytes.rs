// SPDX-License-Identifier: Apache-2.0

//! The counting allocator's byte count (karyos#893): what a call leaves
//! held, and the most it held, in layout bytes, on the calling thread only.

#![cfg(feature = "test-hooks")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_sys::alloc_count::{Bytes, CountingAllocator, count_bytes};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn bytes_held_and_peak_are_counted_in_layout_bytes() {
    // Kept: 1000 bytes held, and no more at any point.
    let (kept, bytes) = count_bytes(|| Vec::<u8>::with_capacity(1000));
    assert_eq!(
        bytes,
        Bytes {
            net: 1000,
            peak: 1000
        }
    );
    // Freed in the call: nothing held, the peak still seen; a reallocation
    // counts its growth.
    let ((), bytes) = count_bytes(|| {
        let mut buffer = Vec::<u8>::with_capacity(100);
        buffer.reserve_exact(400);
        drop(buffer);
    });
    assert_eq!(bytes, Bytes { net: 0, peak: 400 });
    // What was allocated before the call and freed in it counts negative.
    let ((), bytes) = count_bytes(|| drop(kept));
    assert_eq!(
        bytes,
        Bytes {
            net: -1000,
            peak: 0
        }
    );
    // Another thread's allocations are not this thread's.
    let ((), bytes) = count_bytes(|| {
        std::thread::scope(|scope| {
            let _ = scope.spawn(|| Vec::<u8>::with_capacity(4096)).join();
        });
    });
    assert!(bytes.net < 4096, "{bytes:?}");
}
