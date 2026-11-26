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

use karyos_cluster::RaftLog;
use karyos_raft_eval::openraft_core::{OpenRaftBatch16, VARIANT as OPENRAFT_VARIANT};
use karyos_raft_eval::process;
use karyos_raft_eval::raft_rs::{RaftRsBatch16, VARIANT};
use karyos_sim::disk::SimDisk;
use karyos_sim::harness::core::{ConsensusCore, LogView, Persisted, Ready, Refused};
use karyos_sim::harness::node::LOG_DIR;
use karyos_sim::harness::probe::{AllocationReport, WARMUP, measure};
use karyos_sim::harness::probe::{Measured, Probed, Stage, measure_with};
use karyos_sim::harness::workloads::geometry;
use karyos_sim::harness::workloads::{self, Case, W1};
use karyos_sim::net::NodeId;
use karyos_sys::alloc_count::{CountingAllocator, SetCounts, enroll, window};

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

/// A core past the warm-up from its first call: driving it once opens the
/// probe's between-calls stages ([`probe::encoding`], [`probe::application`]).
#[derive(Debug)]
struct Past;

impl ConsensusCore for Past {
    type Message = ();

    fn recover(_id: NodeId, _peers: &[NodeId], _log: &mut LogView<'_>) -> Self {
        Self
    }

    fn propose(&mut self, _command: Vec<u8>, _log: &mut LogView<'_>) -> Result<(), Refused> {
        Ok(())
    }

    fn step(&mut self, _from: NodeId, _message: (), _log: &mut LogView<'_>) {}

    fn tick(&mut self, _now: u64, _log: &mut LogView<'_>) {}

    fn ready(&mut self, _log: &mut LogView<'_>) -> Option<Ready<()>> {
        None
    }

    fn advance(&mut self, _persisted: Persisted, _log: &mut LogView<'_>) {}

    fn term(&self) -> u64 {
        1
    }

    fn leads(&self) -> bool {
        true
    }

    fn received(&self) -> Option<u64> {
        None
    }

    fn committed(&self) -> Option<u64> {
        Some(WARMUP)
    }
}

/// `stage`'s counts in `measured`.
fn staged(measured: &Measured, stage: Stage) -> SetCounts {
    measured
        .stages
        .iter()
        .find(|(name, _)| *name == stage)
        .map(|(_, counts)| *counts)
        .unwrap()
}

/// Runs `run` in a measurement, past a probed core's warm-up.
fn past_warmup(run: impl FnOnce()) -> Measured {
    let mut log = RaftLog::create(
        SimDisk::new(),
        std::path::Path::new(LOG_DIR),
        geometry().unwrap(),
        1,
    )
    .unwrap();
    let mut core = Probed::<Past>::recover(1, &[1], &mut LogView::new(&mut log));
    let ((), measured) = measure_with(|| {
        core.tick(0, &mut LogView::new(&mut log));
        run();
    })
    .unwrap();
    measured
}

/// Codex review of docs#1080 (C5 v3 coverage): what grows the runner's
/// send outbox is counted as the encoding.
#[test]
fn the_runners_send_outbox_is_counted_as_the_encoding() {
    let _serial = serial();
    let mut outbox: Vec<(NodeId, u8)> = Vec::new();
    let measured = past_warmup(|| process::outbox_push(&mut outbox, 2, 7));
    assert_eq!(outbox, [(2, 7)]);
    assert!(
        staged(&measured, Stage::Encoding).allocations >= 1,
        "{:?}",
        measured.stages
    );
}

/// Codex review of docs#1080 (C5 v3): a reply framed into the server's
/// kept frame, prefilled for the largest answer, allocates nothing.
#[test]
fn a_reply_framed_into_the_kept_frame_allocates_nothing() {
    use karyos_sim::harness::node::Wire as Harness;
    let _serial = serial();
    let message: Harness<()> = Harness::Response {
        sequence: 1,
        bytes: vec![7; 9],
        index: 4,
        generation: 1,
    };
    let mut framed = Vec::with_capacity(256);
    let (ok, counts) = window(|| {
        let _enrolled = enroll();
        process::frame_into(3, &message, &mut framed)
    })
    .unwrap();
    assert!(ok);
    assert_eq!(counts, SetCounts::default());
    assert_eq!(Some(framed), process::frame(3, &message));
}

/// Docs#1080 review (C5 v3): an append's read back under declared limits
/// compares the library's entries in place, for both library adapters:
/// once its kept buffers fit, it allocates and frees nothing.
#[test]
fn the_read_back_compares_in_place_and_allocates_nothing() {
    use karyos_cluster::Entry;
    use karyos_raft_eval::openraft_core::{Command, TypeConfig, sent_entries as open_sent};
    use karyos_raft_eval::raft_rs::{ReadBack, read_back, sent_entries, to_raft};

    type Clid =
        <<TypeConfig as openraft::RaftTypeConfig>::LeaderId as openraft::vote::RaftLeaderId>::Committed;

    let _serial = serial();
    let mut log = RaftLog::create(
        SimDisk::new(),
        std::path::Path::new(LOG_DIR),
        geometry().unwrap(),
        1,
    )
    .unwrap();
    let entries: Vec<Entry> = (1..=2)
        .map(|index| Entry {
            index,
            term: 1,
            event_time: 0,
            payload: vec![7; 32],
        })
        .collect();
    let _ = log.append(&entries).unwrap();
    let _ = log.sync().unwrap();
    let raft: Vec<raft::eraftpb::Entry> = entries.iter().map(to_raft).collect();
    let open: Vec<<TypeConfig as openraft::RaftTypeConfig>::Entry> = entries
        .iter()
        .map(|entry| openraft::Entry {
            log_id: openraft::LogId::new(Clid::new(1), entry.index - 1),
            payload: openraft::EntryPayload::Normal(Command(entry.payload.clone())),
        })
        .collect();
    let mut reads = ReadBack::default();
    // The kept buffers grow once.
    assert!(read_back(
        sent_entries(&raft),
        &mut LogView::new(&mut log),
        &mut reads
    ));
    let (both, counts) = window(|| {
        let _enrolled = enroll();
        read_back(sent_entries(&raft), &mut LogView::new(&mut log), &mut reads)
            && read_back(open_sent(&open), &mut LogView::new(&mut log), &mut reads)
    })
    .unwrap();
    assert!(both);
    assert_eq!(counts, SetCounts::default());
    // A mismatch is still caught in place.
    let mut other = raft.clone();
    other[1].data = vec![8; 32].into();
    assert!(!read_back(
        sent_entries(&other),
        &mut LogView::new(&mut log),
        &mut reads
    ));
}
