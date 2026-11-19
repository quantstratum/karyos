// SPDX-License-Identifier: Apache-2.0

//! The allocation hard gate for the `raft` adapter (ADR-0008's counting
//! allocator through the harness's probe; quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v1.md, Hard gates: "0
//! allocations and 0 frees per replicated entry on the declared
//! replication path after initialisation"; plan issue 060, karyos#678).
//!
//! The adapter reports its counts rather than being excused: raft-rs
//! builds owned vectors per proposal, per Ready and per message, and the
//! adapter copies entries between raft-rs's and C4's types, so it fails
//! the gate. The counts are written to stderr for the run record.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Write as _;
use std::sync::{Mutex, MutexGuard, PoisonError};

use karyos_raft_eval::openraft_core::{OpenRaft, VARIANT as OPENRAFT_VARIANT};
use karyos_raft_eval::raft_rs::{RaftRs, VARIANT};
use karyos_sim::harness::probe::measure;
use karyos_sim::harness::workloads::{self, W1};
use karyos_sys::alloc_count::CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// One measurement at a time in a process (the probe refuses a second).
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

#[test]
fn raft_replication_path_allocates_and_the_gate_reports_it() {
    // 32 clients, 32-byte payloads, three servers: W1's second case.
    let _serial = serial();
    let case = W1::skeleton().cases().into_iter().nth(1).unwrap();
    let report = measure::<RaftRs>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &report.outcome), Ok(None));
    let (allocations, frees) = report.per_entry().unwrap();
    let _ = writeln!(
        std::io::stderr(),
        "raft 0.7.0 ({}): {} entries past the warm-up, {} allocations and {} frees, \
         {allocations} and {frees} per entry",
        VARIANT.label(),
        report.entries,
        report.counts.allocations,
        report.counts.frees,
    );
    // The gate is 0 and 0: it fails, and says so.
    assert!(allocations > 0 && frees > 0, "{report:?}");
}

/// The same measurement for `openraft` on the manually pumped executor:
/// its tasks run inside the core's calls, on the calling thread, so the
/// probe counts them (no other thread exists to declare).
#[test]
fn openraft_replication_path_allocates_and_the_gate_reports_it() {
    let _serial = serial();
    let case = W1::skeleton().cases().into_iter().nth(1).unwrap();
    let report = measure::<OpenRaft>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &report.outcome), Ok(None));
    let (allocations, frees) = report.per_entry().unwrap();
    let _ = writeln!(
        std::io::stderr(),
        "openraft 0.10.0-alpha.37 ({}): {} entries past the warm-up, {} allocations and {} frees, \
         {allocations} and {frees} per entry",
        OPENRAFT_VARIANT.label(),
        report.entries,
        report.counts.allocations,
        report.counts.frees,
    );
    assert!(allocations > 0 && frees > 0, "{report:?}");
}
