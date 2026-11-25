// SPDX-License-Identifier: Apache-2.0

//! C5 version 2's W2 in-flight byte case (quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v2.md, "W2: an in-flight byte
//! case that reaches its bound"; ADR-0105, decision 4; karyos#691): 3
//! servers, 32 clients each keeping 4 requests open, 8,192-byte request
//! values, 256 KiB (262,144 bytes) in flight per follower and version 1's
//! 64 entries, queue of 1,024 and log read of 1 MiB per duty, 128
//! operations per client (32 on each of its 4 sessions).
//!
//! **Bytes.** The caps count an entry's payload as the harness's `Limits`
//! define it: the client's value in the harness's request encoding, 8,209
//! bytes for an 8,192-byte value (a 17-byte session header). So 31 entries
//! fit the cap, not 32, and the floor of 229,376 bytes is 28 entries'
//! worth of values, which 28 encoded entries exceed.
//!
//! **Oracle**, from the run's own messages, never from an adapter's
//! counters: every append a leader sends is read with its leader term and
//! its entries' indices and payload bytes, and every acknowledgement it
//! steps with its term and acknowledged index. Per leader and follower,
//! within one leader term: an acknowledgement raises the acknowledged
//! watermark, a send counts only the indices above it, each once however
//! often it is resent, and an append or acknowledgement of an earlier term
//! is ignored, so a delayed reply never clears a later term's sends. The
//! payload bytes sent and not acknowledged must never exceed 262,144, and
//! must reach 229,376 at least once per seed. Every refusal is a typed
//! backpressure, and W1's pass condition holds once the load stops.
//!
//! Appends are read from each Ready the core hands its node, before the
//! node sends them: an append the node then holds back (a failed flush)
//! is counted as sent, which can only raise the bytes counted, never hide
//! one over the cap. This case injects no flush failure.
//!
//! The candidates' adapters keep the byte cap by entry size: every
//! 8,192-byte command is over their 4 KiB share and refused with a typed
//! `Backpressure(InFlightBytes)`. The case shows that refusal for them, as
//! their result to report separately; their metered window is not
//! demonstrated, and no per-entry count is made from a case with no
//! replicated command.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::cell::RefCell;

use karyos_raft_eval::openraft_core::{self, OpenRaft};
use karyos_raft_eval::raft_rs::{self, RaftRs};
use karyos_sim::harness::core::{
    ConsensusCore, Limit, Limits, LogView, Persisted, Ready, ReadyBuf, Refused, Unsupported,
};
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::workloads::{self, Case, Outcome};
use karyos_sim::net::NodeId;

const SEEDS: [u64; 4] = [1, 0xC5, 0x0043, 0xDEAD_BEEF];

mod v2;

// The oracle, shared with the real-process runs (`tests/real_processes.rs`).
#[path = "v2/oracle.rs"]
mod oracle;

use oracle::Trace;

use v2::CAP;

/// The bytes in flight the case must reach once per seed.
const REACHED: u64 = 28 * 8192;

/// The frozen case, and the frozen limits it keeps.
fn case() -> Case {
    let case = v2::byte_case();
    let limits = case.limits.unwrap();
    assert_eq!(
        (
            limits.in_flight_entries,
            limits.in_flight_bytes,
            limits.queue,
            limits.log_read_bytes
        ),
        (64, CAP, 1024, 1024 * 1024)
    );
    assert_eq!((case.clients, case.window, case.operations), (32, 4, 32));
    case
}

thread_local! {
    static TRACE: RefCell<Trace> = RefCell::new(Trace::default());
}

/// How a core's messages are read: an append's leader term and entries
/// as (index, payload bytes), and an acknowledgement's term and index.
trait Read: ConsensusCore {
    fn entries(message: &Self::Message) -> Option<(u64, Vec<(u64, u64)>)>;
    fn ack(message: &Self::Message) -> Option<(u64, u64)>;
}

impl Read for RaftRs {
    fn entries(message: &Self::Message) -> Option<(u64, Vec<(u64, u64)>)> {
        raft_rs::append_entries(message)
    }

    fn ack(message: &Self::Message) -> Option<(u64, u64)> {
        raft_rs::append_ack(message)
    }
}

impl Read for OpenRaft {
    fn entries(message: &Self::Message) -> Option<(u64, Vec<(u64, u64)>)> {
        openraft_core::append_entries(message)
    }

    fn ack(message: &Self::Message) -> Option<(u64, u64)> {
        openraft_core::append_ack(message)
    }
}

impl Read for Custom {
    fn entries(message: &Self::Message) -> Option<(u64, Vec<(u64, u64)>)> {
        let karyos_cluster::consensus::Message::Append { term, .. } = message.core else {
            return None;
        };
        Some((
            term,
            message
                .entries
                .iter()
                .map(|entry| (entry.index, u64::try_from(entry.payload.len()).unwrap()))
                .collect(),
        ))
    }

    fn ack(message: &Self::Message) -> Option<(u64, u64)> {
        match message.core {
            karyos_cluster::consensus::Message::AppendReply {
                term,
                outcome: karyos_cluster::consensus::AppendOutcome::Accepted { index },
                ..
            } => Some((term, index)),
            _ => None,
        }
    }
}

/// A core whose appends and acknowledgements are observed.
#[derive(Debug)]
struct Observed<C> {
    id: NodeId,
    core: C,
}

impl<C: Read> Observed<C> {
    fn observe(&self, messages: &[(NodeId, C::Message)]) {
        TRACE.with(|trace| {
            let mut trace = trace.borrow_mut();
            for (to, message) in messages {
                if let Some((term, entries)) = C::entries(message) {
                    trace.sent(self.id, *to, term, &entries);
                }
            }
        });
    }
}

impl<C: Read> ConsensusCore for Observed<C> {
    type Message = C::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self {
            id,
            core: C::recover(id, peers, log),
        }
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Ok(Self {
            id,
            core: C::recover_with(id, peers, limits, log)?,
        })
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.core.propose(command, log)
    }

    fn propose_slice(&mut self, command: &[u8], log: &mut LogView<'_>) -> Result<(), Refused> {
        self.core.propose_slice(command, log)
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        if let Some((term, index)) = C::ack(&message) {
            TRACE.with(|trace| trace.borrow_mut().acked(self.id, from, term, index));
        }
        self.core.step(from, message, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.core.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        let ready = self.core.ready(log)?;
        self.observe(&ready.messages);
        self.observe(&ready.after_persist);
        Some(ready)
    }

    fn ready_into(&mut self, out: &mut ReadyBuf<Self::Message>, log: &mut LogView<'_>) -> bool {
        let ready = self.core.ready_into(out, log);
        self.observe(&out.ready.messages);
        self.observe(&out.ready.after_persist);
        ready
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.core.advance(persisted, log);
    }

    fn term(&self) -> u64 {
        self.core.term()
    }

    fn leads(&self) -> bool {
        self.core.leads()
    }

    fn received(&self) -> Option<u64> {
        self.core.received()
    }

    fn committed(&self) -> Option<u64> {
        self.core.committed()
    }
}

/// Runs `case` of `C` under `seed`: its outcome, the oracle's trace and
/// the refusals it observed.
fn run<C: Read>(case: &Case, seed: u64) -> (Outcome, Trace, Vec<Limit>) {
    TRACE.with(|trace| *trace.borrow_mut() = Trace::default());
    let outcome = workloads::run::<Observed<C>>(case, seed).unwrap();
    let trace = TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()));
    let refused = outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Backpressure { limit, .. } => Some(*limit),
            _ => None,
        })
        .collect();
    (outcome, trace, refused)
}

/// The custom core passes the case on every seed: the bound held, reached
/// with at least 229,376 bytes in flight, typed refusals only, and W1's
/// pass condition after the load.
#[test]
fn the_custom_core_holds_and_reaches_the_byte_cap() {
    let case = case();
    for seed in SEEDS {
        let (outcome, trace, refused) = run::<Custom>(&case, seed);
        assert!(outcome.safety.is_ok(), "seed {seed}");
        assert_eq!(trace.largest, 8192 + 17, "seed {seed}: the encoded value");
        assert!(
            trace.most <= CAP,
            "seed {seed}: {} bytes unacked",
            trace.most
        );
        assert!(
            trace.most >= REACHED,
            "seed {seed}: at most {} bytes in flight",
            trace.most
        );
        assert!(
            refused
                .iter()
                .all(|limit| matches!(limit, Limit::InFlightBytes | Limit::Queue)),
            "seed {seed}: {refused:?}"
        );
        assert_eq!(workloads::pass(&case, &outcome), Ok(None), "seed {seed}");
    }
}

/// Version 1's skeleton byte case (256-byte values, 8 entries and 1 KiB
/// in flight): the custom core fills its byte window, never past it, and
/// passes.
#[test]
fn the_custom_core_fills_a_small_byte_window_and_no_more() {
    let case = v2::byte_case_of(256, 8, 1024, 1, 4);
    let (outcome, trace, _) = run::<Custom>(&case, 1);
    assert!(outcome.safety.is_ok());
    assert!(trace.most <= 1024, "{}", trace.most);
    assert!(trace.most > 1024 - (256 + 17), "{}", trace.most);
    assert_eq!(workloads::pass(&case, &outcome), Ok(None));
}

/// The candidates refuse each 8,192-byte command with
/// `Backpressure(InFlightBytes)`: their result, reported separately. No
/// command is ever replicated, so nothing is in flight but leaders'
/// empty entries, and safety holds.
#[test]
fn the_candidates_refuse_every_command_over_their_share() {
    fn check<C: Read>(name: &str) {
        let case = case();
        for seed in SEEDS {
            let (outcome, trace, refused) = run::<C>(&case, seed);
            assert!(outcome.safety.is_ok(), "{name} seed {seed}");
            assert!(!refused.is_empty(), "{name} seed {seed}");
            assert!(
                refused.iter().all(|limit| *limit == Limit::InFlightBytes),
                "{name} seed {seed}: {refused:?}"
            );
            assert_eq!(
                trace.commands, 0,
                "{name} seed {seed}: a command replicated"
            );
            assert!(
                !trace.windows.is_empty(),
                "{name} seed {seed}: no append read"
            );
        }
    }
    check::<RaftRs>("raft");
    check::<OpenRaft>("openraft");
}

/// The oracle itself: a resend counts once, an acknowledgement frees what
/// it covers and nothing at or below it counts again, a reply of an
/// earlier term changes nothing, a new term starts afresh, and followers
/// are apart.
#[test]
fn the_oracle_counts_each_unacknowledged_index_once() {
    let mut trace = Trace::default();
    trace.sent(0, 1, 1, &[(1, 100), (2, 100)]);
    trace.sent(0, 1, 1, &[(2, 100), (3, 100)]);
    assert_eq!(trace.unacked(0, 1), 300);
    trace.acked(0, 1, 1, 2);
    assert_eq!(trace.unacked(0, 1), 100);
    // A retry of an acknowledged index is not back in the window.
    trace.sent(0, 1, 1, &[(2, 100), (3, 100), (4, 100)]);
    assert_eq!(trace.unacked(0, 1), 200);
    trace.sent(0, 2, 1, &[(1, 50)]);
    assert_eq!(trace.unacked(0, 2), 50);
    assert_eq!(trace.unacked(0, 1), 200);
    // A later term starts afresh; a delayed reply of the earlier one, and
    // an earlier term's append, change nothing.
    trace.sent(0, 1, 2, &[(5, 70)]);
    assert_eq!(trace.unacked(0, 1), 70);
    trace.acked(0, 1, 1, 9);
    trace.sent(0, 1, 1, &[(6, 1000)]);
    assert_eq!(trace.unacked(0, 1), 70);
    assert_eq!(trace.most, 300);
    // The ignored earlier-term append counts for nothing, not even the
    // largest payload seen.
    assert_eq!((trace.largest, trace.commands), (100, 9));
}

/// The byte case's oracle over the corpus seeds, for the run record (C5
/// v2 run record, "W2 in-flight byte case"): one JSON line per core and
/// seed into `KARYOS_C5_OUT/c5-v2-w2-bytes-<core>-<first>-<last>.jsonl`,
/// with the most bytes unacknowledged to one follower, the largest entry,
/// the commands replicated, the refusals by kind, safety and the harness
/// verdict, and whether the seed meets the frozen pass (bound held,
/// reached once, typed refusals only, W1's pass after the load). A result
/// is a line, never a failed test. Ignored by default; `KARYOS_C5_SEEDS`
/// as the corpus runner's (default 1..=1000), `KARYOS_C5_CORES` a subset
/// of `raft,openraft,custom`.
#[test]
#[ignore = "the corpus seeds take long; run on request"]
#[allow(clippy::print_stdout, reason = "each core's count, for the report")]
fn the_byte_case_over_the_corpus_seeds() {
    use std::io::Write as _;
    fn over<C: Read>(name: &str, seeds: std::ops::RangeInclusive<u64>, dir: &std::path::Path) {
        let case = case();
        let path = dir.join(format!(
            "c5-v2-w2-bytes-{name}-{}-{}.jsonl",
            seeds.start(),
            seeds.end()
        ));
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let mut passed = 0u64;
        let mut runs = 0u64;
        for seed in seeds {
            let (outcome, trace, refused) = run::<C>(&case, seed);
            let bytes = refused
                .iter()
                .filter(|limit| **limit == Limit::InFlightBytes)
                .count();
            let queue = refused
                .iter()
                .filter(|limit| **limit == Limit::Queue)
                .count();
            let typed = refused
                .iter()
                .all(|limit| matches!(limit, Limit::InFlightBytes | Limit::Queue));
            let verdict = workloads::pass(&case, &outcome);
            let pass = outcome.safety.is_ok()
                && trace.most <= CAP
                && trace.most >= REACHED
                && typed
                && verdict == Ok(None);
            runs += 1;
            passed += u64::from(pass);
            writeln!(
                out,
                "{{\"core\":\"{name}\",\"seed\":{seed},\"most\":{},\"largest\":{},\"commands\":{},\"refused_in_flight_bytes\":{bytes},\"refused_queue\":{queue},\"refusals_typed\":{typed},\"safety\":{},\"verdict\":\"{verdict:?}\",\"pass\":{pass}}}",
                trace.most,
                trace.largest,
                trace.commands,
                outcome.safety.is_ok(),
            )
            .unwrap();
        }
        out.into_inner().unwrap().sync_all().unwrap();
        println!(
            "c5 v2 W2 bytes: {name}, runs {runs}, pass {passed}, {}",
            path.display()
        );
    }
    let seeds = std::env::var("KARYOS_C5_SEEDS")
        .ok()
        .map_or(1..=1_000, |range| {
            let (first, last) = range.split_once("..=").unwrap();
            first.parse().unwrap()..=last.parse().unwrap()
        });
    let dir = std::env::var_os("KARYOS_C5_OUT").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")),
        std::path::PathBuf::from,
    );
    let cores = std::env::var("KARYOS_C5_CORES").unwrap_or_else(|_| "raft,openraft,custom".into());
    for name in cores.split(',') {
        match name {
            "raft" => over::<RaftRs>(name, seeds.clone(), &dir),
            "openraft" => over::<OpenRaft>(name, seeds.clone(), &dir),
            "custom" => over::<Custom>(name, seeds.clone(), &dir),
            _ => panic!("unknown core {name}: raft, openraft or custom"),
        }
    }
}
