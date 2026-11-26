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

/// C5 version 2's allocation gate in the simulator, for every variant at
/// one commit (quantstratum-docs: karyos/evaluations/c5-raft-comparison-v2.md,
/// "One probe, one revision"; version 1's gate counts W1 and W2): each
/// variant measured with `harness::probe` on W1's allocation case (version
/// 1's, `W1 n=3 payload=32 clients=32`, batch limit 16) and on W2's
/// nominal case under the manifest's declared limits, seed 1, one line per
/// measurement on stdout for the run record. W2's declared limits set each
/// core's batching, so it runs the evaluated builds, not the batch-16 ones.
/// The counts are the gate's evidence, scored by the report: this asserts
/// only that each run passes its case and the probe measured entries.
/// Ignored by default: the run record runs it at its run commit.
#[test]
#[ignore = "C5 v3's allocation measurement; the run record runs it at its commit"]
fn the_c5_v3_allocation_lines() {
    use karyos_raft_eval::openraft_core::OpenRaft;
    use karyos_raft_eval::raft_rs::RaftRs;
    use karyos_sim::harness::custom::Custom;
    use karyos_sim::harness::workloads::W2;

    let _serial = serial();
    let w1 = W1::skeleton().cases().into_iter().nth(1).unwrap();
    let w2 = W2::manifest()
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| case.name.ends_with("nominal"))
        .unwrap();
    let raft = ("raft 0.7.0", VARIANT.label());
    let openraft = ("openraft 0.10.0-alpha.37", OPENRAFT_VARIANT.label());
    let custom = ("custom core (karyos_cluster::consensus)", "not applicable");
    let runs: [(&str, &str, &Case, AllocationReport); 6] = [
        (
            raft.0,
            raft.1,
            &w1,
            measure::<RaftRsBatch16>(&w1, 1).unwrap(),
        ),
        (
            openraft.0,
            openraft.1,
            &w1,
            measure::<OpenRaftBatch16>(&w1, 1).unwrap(),
        ),
        (custom.0, custom.1, &w1, measure::<Custom>(&w1, 1).unwrap()),
        (raft.0, raft.1, &w2, measure::<RaftRs>(&w2, 1).unwrap()),
        (
            openraft.0,
            openraft.1,
            &w2,
            measure::<OpenRaft>(&w2, 1).unwrap(),
        ),
        (custom.0, custom.1, &w2, measure::<Custom>(&w2, 1).unwrap()),
    ];
    for (core, variant, case, measured) in &runs {
        assert_eq!(
            workloads::pass(case, &measured.outcome),
            Ok(None),
            "{core} {}",
            case.name
        );
        assert!(
            measured.entries > 0,
            "{core} {}: nothing measured",
            case.name
        );
        let stages: Vec<String> = measured
            .stages
            .iter()
            .map(|(stage, counts)| {
                format!(
                    "\"{}\":[{},{}]",
                    stage.name(),
                    counts.allocations,
                    counts.frees
                )
            })
            .collect();
        let _ = writeln!(
            std::io::stdout(),
            "{{\"evidence\":\"C5 v3 simulator\",\"core\":\"{core}\",\"variant\":\"{variant}\",\
             \"forms\":\"borrowed: propose_slice, ready_into, entries_into\",\
             \"case\":\"{}\",\"servers\":{},\"clients\":{},\"operations\":{},\
             \"payload\":{},\"limits\":{},\"seed\":1,\"warmup\":{WARMUP},\"entries\":{},\
             \"allocations\":{},\"frees\":{},\"stages\":{{{}}}}}",
            case.name,
            case.servers,
            case.clients,
            case.operations,
            case.payload,
            case.limits.is_some(),
            measured.entries,
            measured.counts.allocations,
            measured.counts.frees,
            stages.join(","),
        );
    }
}
