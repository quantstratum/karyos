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

use karyos_sim::harness::core::{ConsensusCore, LogView, Persisted, Ready, ReadyBuf, Refused};
use karyos_sim::harness::corpus::Evidence;
use karyos_sim::harness::probe::{Stage, WARMUP, measure};
use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::W1;
use karyos_sim::net::NodeId;
use karyos_sys::alloc_count::{CountingAllocator, Enrolled, SetCounts, WindowOpen, enroll, window};

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
    // Every counted operation belongs to one stage (karyos#691).
    let (staged_allocations, staged_frees) =
        report.stages.iter().fold((0, 0), |(a, f), (_, counts)| {
            (a + counts.allocations, f + counts.frees)
        });
    assert_eq!(
        (staged_allocations, staged_frees),
        (report.counts.allocations, report.counts.frees),
        "{report:?}"
    );
    assert_eq!(report.stages.len(), Stage::ALL.len());
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

/// A guard never leaves its thread (codex, karyos#892): this compiles only
/// while `Enrolled` is not `Send`, as two impls then stay unambiguous.
#[test]
fn an_enrolled_guard_is_not_send() {
    trait AmbiguousIfSend<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    <Enrolled as AmbiguousIfSend<_>>::some_item();
}

/// Windows taken in turn from two threads each count only their own
/// call (codex, karyos#892): a window's totals are read before it closes,
/// so the next one cannot reset them first. A stress check: the race it
/// guards is narrower than a test can hit reliably.
#[test]
fn windows_in_turn_keep_their_own_counts() {
    let _serial = serial();
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                for _ in 0..200 {
                    let counts = loop {
                        let measured = window(|| {
                            let _enrolled = enroll();
                            drop(std::hint::black_box(vec![0u8; 64]));
                        });
                        if let Ok(((), counts)) = measured {
                            break counts;
                        }
                        std::thread::yield_now();
                    };
                    assert_eq!(
                        counts,
                        SetCounts {
                            allocations: 1,
                            frees: 1
                        }
                    );
                }
            });
        }
    });
}

/// `Reference`, allocating and freeing once more in each read of its
/// commit index.
#[derive(Debug)]
struct Noisy(Reference);

impl ConsensusCore for Noisy {
    type Message = <Reference as ConsensusCore>::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self(Reference::recover(id, peers, log))
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.0.propose(command, log)
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        self.0.step(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.0.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        self.0.ready(log)
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.0.advance(persisted, log);
    }

    fn term(&self) -> u64 {
        self.0.term()
    }

    fn leads(&self) -> bool {
        self.0.leads()
    }

    fn received(&self) -> Option<u64> {
        self.0.received()
    }

    fn committed(&self) -> Option<u64> {
        drop(std::hint::black_box(Box::new(0u64)));
        self.0.committed()
    }
}

/// A read-only call of the core is on the declared path too (codex,
/// karyos#892): allocations in `committed` past the warm-up are counted.
#[test]
fn allocations_in_a_read_only_call_are_counted() {
    let _serial = serial();
    let cases = W1::skeleton().cases();
    let case = cases
        .iter()
        .max_by_key(|case| case.clients * case.operations)
        .unwrap();
    let plain = measure::<Reference>(case, 1).unwrap();
    let noisy = measure::<Noisy>(case, 1).unwrap();
    assert_eq!(noisy.entries, plain.entries);
    assert!(
        noisy.counts.allocations > plain.counts.allocations
            && noisy.counts.frees > plain.counts.frees,
        "{:?} vs {:?}",
        noisy.counts,
        plain.counts
    );
}

/// A metered read the budget refuses allocates nothing: it is sized from
/// the log's index and refused before any read (karyos#899 review).
#[test]
fn a_refused_metered_read_allocates_nothing() {
    use std::path::Path;

    use karyos_cluster::{Entry, RaftLog};
    use karyos_sim::disk::SimDisk;
    use karyos_sim::harness::core::{ReadBudget, ReadError};
    use karyos_sim::harness::node::LOG_DIR;
    use karyos_sim::harness::workloads::geometry;
    use karyos_sys::alloc_count::count;

    let _serial = serial();
    let mut log =
        RaftLog::create(SimDisk::new(), Path::new(LOG_DIR), geometry().unwrap(), 1).unwrap();
    let entries: Vec<Entry> = (1..=4)
        .map(|index| Entry {
            index,
            term: 1,
            event_time: 0,
            payload: vec![0; 256],
        })
        .collect();
    let _ = log.append(&entries).unwrap();
    let _ = log.sync().unwrap();
    let budget = ReadBudget::new();
    budget.refill(10);
    let mut view = LogView::metered(&mut log, Some(&budget));
    let (refused, operations) = count(|| view.entries(1..5, u64::MAX));
    assert!(matches!(refused, Err(ReadError::Budget)));
    assert_eq!(operations, 0, "a refused read allocates and frees nothing");
}

/// A recycled `ReadyBuf` hands its entries' payload buffers back: once the
/// pool holds an entry large enough, filling the Ready again allocates
/// nothing (plan issue 073, karyos#691).
#[test]
fn a_recycled_ready_buf_reuses_its_buffers() {
    let _serial = serial();
    let mut buf: ReadyBuf<()> = ReadyBuf::default();
    let fill = |buf: &mut ReadyBuf<()>| {
        for index in 1..=4 {
            let entry = buf.entry(index, 1, 0, &[7u8; 64]);
            buf.ready.entries.push(entry);
        }
        let committed = buf.entry(5, 1, 0, &[7u8; 64]);
        buf.ready.committed.push(committed);
        buf.ready.messages.push((1, ()));
    };
    fill(&mut buf);
    buf.recycle();
    assert!(buf.is_empty());
    let ((), counts) = window(|| {
        let _enrolled = enroll();
        fill(&mut buf);
        buf.recycle();
    })
    .unwrap();
    assert_eq!(counts, SetCounts::default());
}

/// A core that is past the warm-up from its first call, leads, and readies
/// one prepared entry, filling the Ready without allocating.
#[derive(Debug)]
struct Prepared(Option<karyos_cluster::Entry>);

impl ConsensusCore for Prepared {
    type Message = ();

    fn recover(_id: NodeId, _peers: &[NodeId], _log: &mut LogView<'_>) -> Self {
        Self(Some(karyos_cluster::Entry {
            index: 1,
            term: 1,
            event_time: 0,
            payload: vec![7; 64],
        }))
    }

    fn propose(&mut self, _command: Vec<u8>, _log: &mut LogView<'_>) -> Result<(), Refused> {
        Ok(())
    }

    fn step(&mut self, _from: NodeId, _message: (), _log: &mut LogView<'_>) {}

    fn tick(&mut self, _now: u64, _log: &mut LogView<'_>) {}

    fn ready(&mut self, _log: &mut LogView<'_>) -> Option<Ready<()>> {
        None
    }

    fn ready_into(&mut self, out: &mut ReadyBuf<()>, _log: &mut LogView<'_>) -> bool {
        match self.0.take() {
            Some(entry) => {
                out.ready.entries.push(entry);
                true
            }
            None => false,
        }
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

/// Codex review of docs#1080 (C5 v3 coverage): the driver's recycling of
/// a Ready, which grows the pool its entries go back to, is counted in
/// the probed core's Ready stage, not left outside every stage.
#[test]
fn a_probed_cores_ready_recycling_is_counted_in_its_ready_stage() {
    use std::path::Path;

    use karyos_cluster::RaftLog;
    use karyos_sim::disk::SimDisk;
    use karyos_sim::harness::core::drive_into;
    use karyos_sim::harness::node::LOG_DIR;
    use karyos_sim::harness::probe::{Probed, measure_with};
    use karyos_sim::harness::workloads::geometry;

    let _serial = serial();
    let mut log =
        RaftLog::create(SimDisk::new(), Path::new(LOG_DIR), geometry().unwrap(), 1).unwrap();
    let mut core = Probed::<Prepared>::recover(1, &[1], &mut LogView::new(&mut log));
    // Room for the Ready's one entry: filling it allocates nothing, and the
    // pool it goes back to starts empty.
    let mut buf: ReadyBuf<()> = ReadyBuf::default();
    buf.ready.entries.reserve(4);
    let ((), measured) = measure_with(|| {
        // Past the warm-up from this first call.
        core.tick(0, &mut LogView::new(&mut log));
        drive_into(
            &mut core,
            &mut log,
            &mut buf,
            (None, None),
            &mut |_, (), _| {},
            &mut |_, _| {},
            &mut |_| {},
        )
        .unwrap();
    })
    .unwrap();
    let ready = measured
        .stages
        .iter()
        .find(|(stage, _)| *stage == Stage::ReadyLeader)
        .map(|(_, counts)| *counts)
        .unwrap();
    assert!(ready.allocations >= 1, "{:?}", measured.stages);
}
