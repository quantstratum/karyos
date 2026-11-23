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

use karyos_raft_eval::openraft_core::{OpenRaftBatch16, VARIANT as OPENRAFT_VARIANT};
use karyos_raft_eval::raft_rs::{RaftRsBatch16, VARIANT};
use karyos_sim::harness::probe::{AllocationReport, WARMUP, measure};
use karyos_sim::harness::workloads::{self, Case, W1};
use karyos_sys::alloc_count::CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// One measurement at a time in a process (the probe refuses a second).
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The measurement's raw line on stderr, for the run record: the case,
/// the seed, the warm-up, the forms the harness drove the core through,
/// and the counts in total and per stage (karyos#691).
fn report(core: &str, variant: &str, case: &Case, seed: u64, report: &AllocationReport) {
    let (allocations, frees) = report.per_entry().unwrap();
    let stages: Vec<String> = report
        .stages
        .iter()
        .map(|(stage, counts)| {
            format!(
                "\"{}\":{{\"allocations\":{},\"frees\":{}}}",
                stage.name(),
                counts.allocations,
                counts.frees
            )
        })
        .collect();
    let _ = writeln!(
        std::io::stderr(),
        "{{\"evidence\":\"C5 v1\",\"core\":\"{core}\",\"variant\":\"{variant}\",\
         \"forms\":\"borrowed: propose_slice, ready_into\",\"workload\":\"W1\",\"batch_entries\":16,\
         \"case\":\"{}\",\"servers\":{},\"clients\":{},\"operations\":{},\
         \"payload\":{},\"seed\":{seed},\"warmup\":{WARMUP},\"entries\":{},\
         \"allocations\":{},\"frees\":{},\"allocations_per_entry\":{allocations},\
         \"frees_per_entry\":{frees},\"stages\":{{{}}}}}",
        case.name,
        case.servers,
        case.clients,
        case.operations,
        case.payload,
        report.entries,
        report.counts.allocations,
        report.counts.frees,
        stages.join(","),
    );
}

#[test]
fn raft_replication_path_allocates_and_the_gate_reports_it() {
    // 32 clients, 32-byte payloads, three servers: W1's second case, with
    // the frozen W1 batch limit of 16 entries per append (karyos#691).
    let _serial = serial();
    let case = W1::skeleton().cases().into_iter().nth(1).unwrap();
    let measured = measure::<RaftRsBatch16>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &measured.outcome), Ok(None));
    report("raft 0.7.0", VARIANT.label(), &case, 1, &measured);
    // The gate is 0 and 0: it fails, and says so.
    let (allocations, frees) = measured.per_entry().unwrap();
    assert!(allocations > 0 && frees > 0, "{measured:?}");
}

/// The same measurement for `openraft` on the manually pumped executor:
/// its tasks run inside the core's calls, on the calling thread, so the
/// probe counts them (no other thread exists to declare).
#[test]
fn openraft_replication_path_allocates_and_the_gate_reports_it() {
    let _serial = serial();
    let case = W1::skeleton().cases().into_iter().nth(1).unwrap();
    let measured = measure::<OpenRaftBatch16>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &measured.outcome), Ok(None));
    report(
        "openraft 0.10.0-alpha.37",
        OPENRAFT_VARIANT.label(),
        &case,
        1,
        &measured,
    );
    let (allocations, frees) = measured.per_entry().unwrap();
    assert!(allocations > 0 && frees > 0, "{measured:?}");
}
