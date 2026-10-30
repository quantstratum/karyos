// SPDX-License-Identifier: Apache-2.0

//! Declared limits in the core interface (W2; karyos#687): a core that
//! takes none cannot pass a case that declares them, a core that takes
//! them refuses with typed backpressure and loses nothing, and the
//! harness holds every core's log reads to its per-duty budget. The
//! `Reference` fixture's runs here are harness validation, not C5
//! evidence.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::Cell;
use std::path::Path;

use karyos_cluster::{Entry, RaftLog};
use karyos_sim::disk::SimDisk;
use karyos_sim::harness::core::{
    ConsensusCore, Limit, Limits, LogView, Persisted, ReadBudget, ReadError, Ready, Refused,
};
use karyos_sim::harness::corpus::{Evidence, Workload, run_corpus};
use karyos_sim::harness::node::{LOG_DIR, Observation};
use karyos_sim::harness::reference::{Message, Reference};
use karyos_sim::harness::workloads::{Case, RunError, geometry, pass, run};
use karyos_sim::net::NodeId;

thread_local! {
    /// The most entries one `Watched` append message carried.
    static LARGEST: Cell<usize> = const { Cell::new(0) };
    /// The most payload bytes one `Watched` append message carried.
    static HEAVIEST: Cell<usize> = const { Cell::new(0) };
}

/// `Reference` with no `recover_with`: a core that takes no limits.
#[derive(Debug)]
struct Plain(Reference);

/// `Reference` that notes the largest append message it sends.
#[derive(Debug)]
struct Watched(Reference);

macro_rules! delegate {
    ($core:ident) => {
        fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
            self.0.propose(command, log)
        }

        fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
            self.0.step(from, message, log);
        }

        fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
            self.0.tick(now, log);
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
            self.0.committed()
        }
    };
}

impl ConsensusCore for Plain {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self(Reference::recover(id, peers, log))
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        self.0.ready(log)
    }

    delegate!(Plain);
}

impl ConsensusCore for Watched {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self(Reference::recover(id, peers, log))
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, karyos_sim::harness::core::Unsupported> {
        Reference::recover_with(id, peers, limits, log).map(Self)
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        let ready = self.0.ready(log)?;
        for (_, message) in &ready.messages {
            if let Message::Append { entries, .. } = message {
                LARGEST.with(|largest| largest.set(largest.get().max(entries.len())));
                let bytes = entries
                    .iter()
                    .map(|entry| entry.payload.len())
                    .sum::<usize>();
                HEAVIEST.with(|heaviest| heaviest.set(heaviest.get().max(bytes)));
            }
        }
        Some(ready)
    }

    delegate!(Watched);
}

/// A healthy case of 3 servers and `clients` clients, under `limits`.
fn limited(name: &str, clients: usize, limits: Limits) -> Case {
    let mut case = Case::healthy(name, 3, clients, 6);
    case.payload = 256;
    case.steps = 2_000;
    case.limits = Some(limits);
    case
}

/// The backpressure refusals a run recorded, by limit.
fn refusals(observations: &[Observation], limit: Limit) -> usize {
    observations
        .iter()
        .filter(|observation| {
            matches!(observation, Observation::Backpressure { limit: named, .. } if *named == limit)
        })
        .count()
}

/// A core that takes no limits cannot run a case that declares them: the
/// run says so, and the corpus records it as not demonstrated, never as
/// passed (decided 2026-10-30 by QS-COORDINATOR).
#[test]
fn a_core_without_limits_is_not_demonstrated_never_passed() {
    let case = limited("w2-like", 2, Limits::W2);
    assert!(matches!(
        run::<Plain>(&case, 1),
        Err(RunError::Unsupported(_))
    ));
    let cases = |_seed: u64| vec![case.clone()];
    let workloads: [Workload<'_>; 1] = [("W2", &cases)];
    let mut out = Vec::new();
    let summary = run_corpus::<Plain>(
        "plain",
        Evidence::HarnessValidation,
        &workloads,
        (1..=2, 1),
        &mut out,
    )
    .unwrap();
    assert_eq!(summary.runs, 2);
    assert_eq!(summary.not_demonstrated, 2);
    assert_eq!(summary.passed + summary.liveness_gaps + summary.errors, 0);
    assert!(summary.failed.is_empty());
    let lines = String::from_utf8(out).unwrap();
    assert_eq!(
        lines.matches("\"verdict\":\"not_demonstrated\"").count(),
        2,
        "{lines}"
    );
    // The same core with no limits declared runs the case as before.
    let mut free = case;
    free.limits = None;
    let outcome = run::<Plain>(&free, 1).unwrap();
    assert_eq!(pass(&free, &outcome), Ok(None));
}

/// Past its queue, a leader refuses a request with typed backpressure;
/// the client sends it again, and every operation completes: nothing is
/// lost.
#[test]
fn past_its_queue_a_leader_pushes_back_and_loses_nothing() {
    let limits = Limits {
        queue: 2,
        ..Limits::W2
    };
    let case = limited("queue", 8, limits);
    let outcome = run::<Reference>(&case, 1).unwrap();
    assert_eq!(pass(&case, &outcome), Ok(None));
    assert!(
        refusals(&outcome.observations, Limit::Queue) > 0,
        "8 clients against a queue of 2 must be pushed back"
    );
    // Under the manifest's W2 limits, 8 clients never reach the queue.
    let mut roomy = case;
    roomy.limits = Some(Limits::W2);
    let outcome = run::<Reference>(&roomy, 1).unwrap();
    assert_eq!(pass(&roomy, &outcome), Ok(None));
    assert_eq!(refusals(&outcome.observations, Limit::Queue), 0);
}

/// Each append message carries at most the in-flight entries; the run
/// still completes.
#[test]
fn an_append_holds_to_the_in_flight_entries() {
    let limits = Limits {
        in_flight_entries: 2,
        ..Limits::W2
    };
    let case = limited("in-flight", 8, limits);
    LARGEST.with(|largest| largest.set(0));
    let outcome = run::<Watched>(&case, 1).unwrap();
    assert_eq!(pass(&case, &outcome), Ok(None));
    let largest = LARGEST.with(Cell::get);
    assert!((1..=2).contains(&largest), "largest append {largest}");
}

/// A run whose servers may read a few entries per duty still completes:
/// each duty reads what fits, and a spent budget refuses the next read
/// until the next duty.
#[test]
fn a_tight_read_budget_slows_a_run_and_loses_nothing() {
    let limits = Limits {
        log_read_bytes: 2_048,
        ..Limits::W2
    };
    let case = limited("read-budget", 4, limits);
    let outcome = run::<Reference>(&case, 1).unwrap();
    assert_eq!(pass(&case, &outcome), Ok(None));
}

/// A metered view never reads past its budget (karyos#899 review, codex:
/// 277-byte entries against an uneven budget overshot it by one entry),
/// and a refused read reads nothing from the disk: frames are sized from
/// the log's index. It returns the frames that fit and spends their bytes;
/// once none fits it is refused, and a refill reads again. A frame larger
/// than the whole budget is never read.
#[test]
fn a_metered_view_spends_and_refuses_its_budget() {
    let disk = SimDisk::new();
    let mut log =
        RaftLog::create(disk.clone(), Path::new(LOG_DIR), geometry().unwrap(), 1).unwrap();
    let entries: Vec<Entry> = (1..=8)
        .map(|index| Entry {
            index,
            term: 1,
            event_time: 0,
            payload: vec![0; 277],
        })
        .collect();
    let _ = log.append(&entries).unwrap();
    let _ = log.sync().unwrap();
    let span = log.frame_span(1).unwrap();
    assert!(span > 277, "a frame holds its header: {span}");
    let room = 2 * span + span / 2;
    let budget = ReadBudget::new();
    budget.refill(room);
    let mut view = LogView::metered(&mut log, Some(&budget));
    let mut read = 0;
    let mut next = 1;
    while let Ok(more) = view.entries(next..9, u64::MAX) {
        read += more.len();
        next += u64::try_from(more.len()).unwrap();
    }
    assert_eq!(read, 2, "two frames fit, never a third");
    assert_eq!(budget.left(), room - 2 * span);
    let before = disk.used();
    assert!(matches!(
        view.entries(next..9, u64::MAX),
        Err(ReadError::Budget)
    ));
    assert_eq!(disk.used(), before, "a refused read touches no disk");
    budget.refill(room);
    assert!(
        !view.entries(next..9, u64::MAX).unwrap().is_empty(),
        "a new duty reads again"
    );
    budget.refill(span - 1);
    let before = disk.used();
    assert!(
        matches!(view.entries(1..9, u64::MAX), Err(ReadError::Budget)),
        "a frame larger than the budget is never read"
    );
    assert_eq!(disk.used(), before);
    // Unmetered, the same read takes them all.
    let mut free = LogView::new(&mut log);
    assert_eq!(free.entries(1..9, u64::MAX).unwrap().len(), 8);
}

/// Each append message carries at most the in-flight bytes, and a command
/// no append could carry within them is refused with typed backpressure,
/// never sent past the cap (karyos#899 review, codex: a 256-byte cap and
/// 273-byte commands sent 273 bytes with no refusal).
#[test]
fn an_append_holds_to_the_in_flight_bytes() {
    // Two 273-byte commands fit in 600 bytes, three do not.
    let case = limited(
        "in-flight bytes",
        8,
        Limits {
            in_flight_bytes: 600,
            ..Limits::W2
        },
    );
    HEAVIEST.with(|heaviest| heaviest.set(0));
    let outcome = run::<Watched>(&case, 1).unwrap();
    assert_eq!(pass(&case, &outcome), Ok(None));
    let heaviest = HEAVIEST.with(Cell::get);
    assert!((1..=600).contains(&heaviest), "heaviest append {heaviest}");
    // Below one command: every request is refused, typed, and nothing is
    // appended past the cap; progress stops, which this case allows.
    let mut tight = limited(
        "in-flight bytes below a command",
        2,
        Limits {
            in_flight_bytes: 256,
            ..Limits::W2
        },
    );
    tight.progress = karyos_sim::harness::workloads::Progress::MayStop;
    tight.steps = 1_000;
    HEAVIEST.with(|heaviest| heaviest.set(0));
    let outcome = run::<Watched>(&tight, 1).unwrap();
    assert!(refusals(&outcome.observations, Limit::InFlightBytes) > 0);
    assert_eq!(HEAVIEST.with(Cell::get), 0, "nothing sent past the cap");
    assert!(pass(&tight, &outcome).is_ok());
}

/// `Reference`, except that server 2 drops every append it is sent: a
/// follower that never applies anything.
#[derive(Debug)]
struct Deaf(Reference, NodeId);

impl ConsensusCore for Deaf {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self(Reference::recover(id, peers, log), id)
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, karyos_sim::harness::core::Unsupported> {
        Reference::recover_with(id, peers, limits, log).map(|core| Self(core, id))
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        self.0.ready(log)
    }

    fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
        if self.1 == 2 && matches!(message, Message::Append { .. }) {
            return;
        }
        self.0.step(from, message, log);
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.0.propose(command, log)
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.0.tick(now, log);
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
        self.0.committed()
    }
}

/// W2 holds every up server to the same applied index and state
/// (karyos#899 review, codex): a follower that never applies fails it,
/// where the generic check, which compares only the servers at the
/// highest index, lets it pass.
#[test]
fn a_follower_that_never_applies_fails_w2() {
    use karyos_sim::harness::workloads::{Failed, W2};
    let cases = W2::skeleton().cases().unwrap();
    let nominal = &cases[0];
    assert!(nominal.converged);
    let outcome = run::<Deaf>(nominal, 1).unwrap();
    assert!(
        matches!(pass(nominal, &outcome), Err(Failed::Diverged(_))),
        "{:?}",
        outcome.states
    );
    let mut lax = nominal.clone();
    lax.converged = false;
    assert_eq!(
        pass(&lax, &outcome),
        Ok(None),
        "the generic check misses it"
    );
}

/// Every raw result line of a W2 run states its client window and the
/// in-flight byte limit it does not reach, so a "pass" never hides the gap
/// the run record states (karyos#899 review, codex); other workloads'
/// lines have a window of 1 and no note.
#[test]
fn w2_lines_carry_their_window_and_coverage_note() {
    use karyos_sim::harness::workloads::{W1, W2};
    let w2 = |_seed: u64| W2::skeleton().cases().unwrap();
    let w1 = |_seed: u64| W1::skeleton().cases().into_iter().take(1).collect();
    let workloads: [Workload<'_>; 2] = [("W2", &w2), ("W1", &w1)];
    let mut out = Vec::new();
    let summary = run_corpus::<Reference>(
        "reference",
        Evidence::HarnessValidation,
        &workloads,
        (1..=1, 1),
        &mut out,
    )
    .unwrap();
    assert!(summary.failed.is_empty(), "{:?}", summary.failed);
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 6);
    let note = format!("\"notes\":[\"{}\"]", W2::IN_FLIGHT_BYTES);
    for line in &lines[..5] {
        assert!(line.contains(&note), "{line}");
        assert!(line.contains("\"window\":"), "{line}");
    }
    let windows: Vec<&str> = lines[..5]
        .iter()
        .filter_map(|line| line.split("\"window\":").nth(1)?.split(',').next())
        .collect();
    assert_eq!(windows, ["1", "32", "2", "1", "1"]);
    for line in &lines[..5] {
        assert!(
            line.contains("\"limits\":{\"in_flight_entries\":4,"),
            "{line}"
        );
    }
    assert!(lines[5].contains("\"window\":1,") && lines[5].contains("\"notes\":[]"));
    assert!(lines[5].contains("\"limits\":null"), "{}", lines[5]);
}

thread_local! {
    /// The step `Lazy`'s leader waits for before it replicates.
    static WAKE: Cell<u64> = const { Cell::new(0) };
}

/// `Reference` whose leader sends nothing until [`WAKE`]: no entry commits
/// while the follower is cut off, so it is never behind.
#[derive(Debug)]
struct Lazy(Reference);

impl ConsensusCore for Lazy {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self(Reference::recover(id, peers, log))
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, karyos_sim::harness::core::Unsupported> {
        Reference::recover_with(id, peers, limits, log).map(Self)
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        self.0.ready(log)
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        if now >= WAKE.with(Cell::get) {
            self.0.tick(now, log);
        }
    }

    fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
        self.0.step(from, message, log);
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.0.propose(command, log)
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
        self.0.committed()
    }
}

/// W2's slow follower must really be behind at the heal (karyos#899
/// review, codex): a core that commits nothing until then ends with every
/// server in the same state, and still fails the case.
#[test]
fn a_follower_never_behind_fails_the_slow_case() {
    use karyos_sim::harness::workloads::{Action, Failed, W2};
    let cases = W2::skeleton().cases().unwrap();
    let slow = cases
        .iter()
        .find(|case| case.name.contains("slow follower"))
        .unwrap();
    let healed = slow
        .schedule
        .iter()
        .find_map(|(step, action)| matches!(action, Action::Heal).then_some(*step))
        .unwrap();
    WAKE.with(|wake| wake.set(healed));
    let outcome = run::<Lazy>(slow, 1).unwrap();
    WAKE.with(|wake| wake.set(0));
    assert!(
        matches!(
            pass(slow, &outcome),
            Err(Failed::NotBehind { reached: 0, .. })
        ),
        "{:?}",
        pass(slow, &outcome)
    );
    let mut lax = slow.clone();
    lax.behind = None;
    assert!(
        pass(&lax, &outcome).is_ok(),
        "without the requirement it passes"
    );
}

/// A metered read that fails part-way is charged for the frames it took
/// (karyos#899 review, codex: a damaged second frame let ten failing reads
/// make 30 disk operations while the budget stayed whole), so its retries
/// end in Budget; an empty range reads and spends nothing.
#[test]
fn a_failed_metered_read_is_charged_and_an_empty_one_is_free() {
    use karyos_archive::disk::Disk;
    use karyos_cluster::log::LOG_RECORDING;

    let mut disk = SimDisk::new();
    let mut log =
        RaftLog::create(disk.clone(), Path::new(LOG_DIR), geometry().unwrap(), 1).unwrap();
    let entries: Vec<Entry> = (1..=2)
        .map(|index| Entry {
            index,
            term: 1,
            event_time: 0,
            payload: vec![0; 256],
        })
        .collect();
    let _ = log.append(&entries).unwrap();
    let _ = log.sync().unwrap();
    let (first, second) = (log.frame_span(1).unwrap(), log.frame_span(2).unwrap());
    // Damage the second frame's magic, in its segment's data file.
    let segment = Path::new(LOG_DIR).join(format!("{LOG_RECORDING:016x}-{:016x}.seg", 0));
    let file = disk.open(&segment).unwrap();
    disk.write_at(&file, first, b"XXXX").unwrap();
    let budget = ReadBudget::new();
    budget.refill(first + second);
    let mut view = LogView::metered(&mut log, Some(&budget));
    assert!(view.entries(1..1, u64::MAX).unwrap().is_empty());
    assert_eq!(budget.left(), first + second, "an empty range is free");
    assert!(matches!(
        view.entries(1..3, u64::MAX),
        Err(ReadError::Log(_))
    ));
    assert_eq!(budget.left(), 0, "the failed read is charged");
    assert!(matches!(
        view.entries(1..3, u64::MAX),
        Err(ReadError::Budget)
    ));
}

/// A case whose entries are larger than a duty's whole log-read budget is
/// refused before it runs: no core could read them back, so replication
/// would only stall (karyos#899 review, QS-REVIEWER).
#[test]
fn a_case_whose_entries_exceed_the_read_budget_is_refused() {
    let case = limited(
        "unreadable",
        2,
        Limits {
            log_read_bytes: 256,
            ..Limits::W2
        },
    );
    assert!(matches!(
        run::<Reference>(&case, 1),
        Err(RunError::Unreadable { budget: 256, entry }) if entry > 256
    ));
}

/// A core that takes no snapshots cannot pass W5's snapshot half: its
/// first compaction is refused, and the run is not demonstrated
/// (decided 2026-10-30 by QS-COORDINATOR).
#[test]
fn a_core_without_snapshots_is_not_demonstrated_on_w5() {
    use karyos_sim::harness::workloads::W5Snapshots;
    for case in W5Snapshots::skeleton().cases().unwrap() {
        assert!(
            matches!(run::<Plain>(&case, 1), Err(RunError::Unsupported(_))),
            "{}",
            case.name
        );
    }
}
