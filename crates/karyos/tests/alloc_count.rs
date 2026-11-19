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
    // Positive controls: exact, nonzero counts prove the allocator is
    // installed, so the zero counts below cannot pass by default.
    let ((), operations) = count(|| drop(std::hint::black_box(Box::new(1u64))));
    assert_eq!(operations, 2, "one allocation and one free");
    let mut values: Vec<u64> = Vec::new();
    assert_eq!(strict(|| values.push(1)), Err(1));
    let mut full: Vec<u64> = Vec::with_capacity(1);
    full.push(1);
    let ((), allocations) = count_allocations(|| full.push(2));
    assert_eq!(allocations, 1, "growing a full Vec is one reallocation");
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
