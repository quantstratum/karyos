// SPDX-License-Identifier: Apache-2.0

//! A product-style strict allocation profile on the facade's counting
//! allocator (R-CORE-48, karyos#918): no `unsafe` here, no internal crate.

use karyos::alloc_count::{CountingAllocator, count, count_allocations};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// The profile's check: fails on any allocation, reallocation or free.
fn strict<R>(call: impl FnOnce() -> R) -> Result<R, u64> {
    match count(call) {
        (result, 0) => Ok(result),
        (_, operations) => Err(operations),
    }
}

#[test]
fn a_vec_push_is_caught() {
    let mut values: Vec<u64> = Vec::new();
    assert!(strict(|| values.push(1)).is_err());
    let ((), allocations) = count_allocations(|| values.push(2));
    assert!(allocations <= 1, "{allocations}");
}

#[test]
fn a_non_allocating_call_counts_zero() {
    let mut values: Vec<u64> = Vec::with_capacity(8);
    let sum = strict(|| {
        values.push(1);
        values.push(2);
        values.iter().sum::<u64>()
    });
    assert_eq!(sum, Ok(3));
}
