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
/// 277-byte entries against an uneven budget overshot it by one entry). A
/// read returns the entries that fit and spends them; once none fits, it
/// is refused, and a refill reads again. An entry larger than the whole
/// budget is never returned.
#[test]
fn a_metered_view_spends_and_refuses_its_budget() {
    let mut log =
        RaftLog::create(SimDisk::new(), Path::new(LOG_DIR), geometry().unwrap(), 1).unwrap();
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
    let budget = ReadBudget::new();
    budget.refill(600);
    let mut view = LogView::metered(&mut log, Some(&budget));
    let mut read = 0;
    let mut next = 1;
    while let Ok(more) = view.entries(next..9, u64::MAX) {
        read += more.len() * 277;
        next += u64::try_from(more.len()).unwrap();
    }
    assert_eq!(read, 2 * 277, "two entries fit in 600 bytes, never a third");
    assert_eq!(budget.left(), 600 - 2 * 277);
    assert!(matches!(
        view.entries(next..9, u64::MAX),
        Err(ReadError::Budget)
    ));
    budget.refill(600);
    assert!(
        !view.entries(next..9, u64::MAX).unwrap().is_empty(),
        "a new duty reads again"
    );
    budget.refill(276);
    assert!(
        matches!(view.entries(1..9, u64::MAX), Err(ReadError::Budget)),
        "an entry larger than the budget is never returned"
    );
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
