// SPDX-License-Identifier: Apache-2.0

//! The C5 allocation gate's probe (karyos#691): it counts what it must
//! and nothing else, and one measurement of the `Reference` fixture over
//! W1, which is harness validation, not C5 evidence, as the line it prints
//! says. `Reference` is no candidate and was never built to replicate
//! without allocating, so it is expected to count above zero: the probe is
//! shown to see allocations, not the fixture to pass the gate.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::{Mutex, MutexGuard};

use karyos_sim::harness::corpus::Evidence;
use karyos_sim::harness::probe::{WARMUP, measure};
use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::W1;
use karyos_sys::alloc_count::{CountingAllocator, SetCounts, WindowOpen, enroll, window};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// One window at a time in the process.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The probe's own test: in a window, an enrolled thread's allocation
/// counts and so does its free; a no-op counts nothing; a thread not
/// enrolled counts nothing; a second thread the path declares counts
/// once enrolled.
#[test]
fn the_probe_counts_the_enrolled_threads_and_nothing_else() {
    let _serial = serial();
    let ((), counts) = window(|| {
        let _enrolled = enroll();
        let kept = std::hint::black_box(vec![0u8; 64]);
        drop(kept);
    })
    .unwrap();
    assert_eq!(
        counts,
        SetCounts {
            allocations: 1,
            frees: 1
        }
    );
    let ((), nothing) = window(|| {
        let _enrolled = enroll();
        std::hint::black_box(0u64);
    })
    .unwrap();
    assert_eq!(nothing, SetCounts::default(), "a no-op");
    let ((), outside) = window(|| {
        drop(std::hint::black_box(vec![0u8; 64]));
    })
    .unwrap();
    assert_eq!(outside, SetCounts::default(), "not enrolled");
    // A declared thread, joined inside the window.
    let ((), threaded) = window(|| {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _enrolled = enroll();
                    drop(std::hint::black_box(vec![0u8; 64]));
                })
                .join()
                .unwrap();
        });
    })
    .unwrap();
    assert!(
        threaded.allocations >= 1 && threaded.frees >= 1,
        "{threaded:?}"
    );
    // One window at a time: a second, opened inside the first, is refused
    // and the first keeps its counts.
    let (inner, outer) = window(|| {
        let _enrolled = enroll();
        drop(std::hint::black_box(vec![0u8; 64]));
        window(|| ())
    })
    .unwrap();
    assert_eq!(inner, Err(WindowOpen));
    assert_eq!(outer.allocations, 1, "{outer:?}");
}

/// One W1 case of the `Reference` fixture, measured: entries past the
/// warm-up are counted, and the fixture's allocations are seen.
#[test]
#[allow(
    clippy::print_stdout,
    reason = "the measurement's raw line, marked as harness validation"
)]
fn a_measurement_of_the_reference_fixture_sees_its_allocations() {
    let _serial = serial();
    // The case with the most appends, so the run goes past the warm-up.
    let cases = W1::skeleton().cases();
    let case = cases
        .iter()
        .max_by_key(|case| case.clients * case.operations)
        .unwrap();
    let report = measure::<Reference>(case, 1).unwrap();
    assert!(
        report.entries > 0,
        "nothing past the {WARMUP}-entry warm-up"
    );
    let (allocations, frees) = report.per_entry().unwrap();
    assert!(
        report.counts.allocations > 0,
        "the fixture allocates; a zero would mean the probe missed it"
    );
    println!(
        "{{\"evidence\":\"{}\",\"core\":\"reference\",\"workload\":\"W1\",\"case\":\"{}\",\"seed\":1,\"warmup\":{WARMUP},\"entries\":{},\"allocations\":{},\"frees\":{},\"allocations_per_entry\":{allocations},\"frees_per_entry\":{frees}}}",
        Evidence::HarnessValidation.text(),
        case.name,
        report.entries,
        report.counts.allocations,
        report.counts.frees,
    );
}
