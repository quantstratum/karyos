// SPDX-License-Identifier: Apache-2.0

//! Contract C-TIME (ADR-0111; quantstratum/karyos#744, R-CORE-7): the
//! event times a leader assigns never decrease along a Cluster log's
//! history, across leader changes and restarts, under R-CORE-4's skewed
//! clocks (the simulator's per-node clock offset).
//!
//! Server 0's clock is [`AHEAD`] of the others', so every entry a later
//! leader appends while its clock is behind is clamped: it must carry
//! exactly the watermark before it, the largest event time of the earlier
//! entries.
//!
//! - a handover (the reference core) and an election after a crash (the
//!   custom core, ADR-0105) to a server whose clock is behind;
//! - that leader's restart from its log;
//! - a restart from a snapshot with an empty log after it (an installed
//!   one), then a handover to that server.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use karyos_archive::segment::Geometry;
use karyos_sim::cluster::ClusterSim;
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::harness::core::ConsensusCore;
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::node::{
    ClientNode, Compaction, Member, Observation, Op, Recorder, ServerNode, Shared, Wire,
};
use karyos_sim::harness::reference::{LEADER, Reference};
use karyos_sim::net::{LinkConfig, NodeId};

/// Server 0's clock offset over the others': far more than any run.
const AHEAD: u64 = 1_000_000_000;
const SERVERS: u32 = 3;
/// The first script's appends, all through server 0.
const FIRST: u8 = 5;

type Sim<C> = ClusterSim<Member<C>, Wire<<C as ConsensusCore>::Message>>;

fn appends(from: u8, count: u8) -> Vec<Op> {
    (from..from + count)
        .map(|value| Op::Append(vec![value]))
        .collect()
}

/// Three servers, server 0 ahead, each compacting under `compaction`,
/// and a client of [`FIRST`] appends to `first` (node 3).
fn build<C: ConsensusCore>(
    seed: u64,
    first: NodeId,
    compaction: Option<Compaction>,
) -> (Sim<C>, Shared) {
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let mut sim = Sim::<C>::new("c-time", seed, LinkConfig::default()).unwrap();
    for id in 0..SERVERS {
        let mut server = ServerNode::<C>::new(
            id,
            (0..SERVERS).collect(),
            SimDisk::new(),
            Survives::Synced,
            Geometry::new(4096, 4096).unwrap(),
            Rc::clone(&recorder),
        )
        .unwrap();
        if let Some(compaction) = compaction {
            server = server.with_compaction(compaction);
        }
        let offset = if id == 0 { AHEAD } else { 0 };
        let added = sim
            .add_node(Member::Server(Box::new(server)), offset, 0)
            .unwrap();
        assert_eq!(added, id);
    }
    let client = ClientNode::new(SERVERS, first, appends(0, FIRST), Rc::clone(&recorder));
    assert_eq!(sim.add_node(Member::Client(client), 0, 0).unwrap(), SERVERS);
    (sim, recorder)
}

/// A second client, of `count` appends from value 100, to `server`.
fn second_client<C: ConsensusCore>(
    sim: &mut Sim<C>,
    recorder: &Shared,
    server: NodeId,
    count: u8,
) -> NodeId {
    let id = SERVERS + 1;
    let client = ClientNode::new(id, server, appends(100, count), Rc::clone(recorder));
    assert_eq!(sim.add_node(Member::Client(client), 0, 0).unwrap(), id);
    id
}

fn done<C: ConsensusCore>(sim: &Sim<C>, client: NodeId) -> bool {
    sim.node(client)
        .and_then(Member::client)
        .is_some_and(ClientNode::done)
}

fn leads<C: ConsensusCore>(sim: &Sim<C>, server: NodeId) -> bool {
    sim.node(server)
        .and_then(Member::server)
        .and_then(ServerNode::core)
        .is_some_and(ConsensusCore::leads)
}

/// The committed history, by index, as every server applied it: one
/// entry per index (a restart applies an entry again, the same), its term
/// and event time.
fn history(recorder: &Shared) -> BTreeMap<u64, (u64, u64)> {
    let mut history: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for observation in &recorder.borrow().observations {
        if let Observation::Applied { entry, .. } = observation {
            let seen = *history
                .entry(entry.index)
                .or_insert((entry.term, entry.event_time));
            assert_eq!(
                seen,
                (entry.term, entry.event_time),
                "entry {} applied twice differently",
                entry.index
            );
        }
    }
    history
}

/// C-TIME over `history`: its event times never decrease, and each entry
/// of a term after `ahead_term` (appended by a leader whose clock is
/// behind [`AHEAD`]) equals the watermark before it. Returns how many such
/// clamped entries it checked.
fn assert_c_time(history: &BTreeMap<u64, (u64, u64)>, ahead_term: u64) -> usize {
    let mut watermark = 0u64;
    let mut clamped = 0;
    for (expected, (&index, &(term, event_time))) in (1..).zip(history) {
        assert_eq!(index, expected, "the history has a hole before {index}");
        assert!(
            event_time >= watermark,
            "entry {index} at {event_time} steps back from {watermark}"
        );
        if term > ahead_term {
            assert!(watermark >= AHEAD, "entry {index}: nothing ahead before it");
            assert_eq!(
                event_time, watermark,
                "entry {index}, clamped, is not the watermark"
            );
            clamped += 1;
        } else {
            assert!(event_time >= AHEAD, "entry {index}: server 0 stamped it");
        }
        watermark = watermark.max(event_time);
    }
    clamped
}

/// The term server 0's first entries carry.
fn first_term(history: &BTreeMap<u64, (u64, u64)>) -> u64 {
    history.get(&1).unwrap().0
}

/// The reference core: server 0 leads and the first client's appends
/// commit, then server 0 hands its leadership to server 1, whose clock is
/// behind.
fn handed_over(seed: u64) -> (Sim<Reference>, Shared) {
    let (mut sim, recorder) = build::<Reference>(seed, LEADER, None);
    sim.run_for(600).unwrap();
    assert!(done(&sim, SERVERS), "seed {seed}: the first client is done");
    let _ = sim.send(SERVERS, 0, Wire::Transfer(1)).unwrap();
    sim.run_for(300).unwrap();
    assert!(leads(&sim, 1), "seed {seed}: server 1 leads");
    (sim, recorder)
}

#[test]
fn test_c_time_a_handover_to_a_server_behind_never_steps_back() {
    for seed in [1, 7, 42] {
        let (mut sim, recorder) = handed_over(seed);
        let client = second_client(&mut sim, &recorder, LEADER, 5);
        sim.run_for(800).unwrap();
        assert!(done(&sim, client), "seed {seed}: the second client is done");
        let history = history(&recorder);
        let ahead = first_term(&history);
        // Server 1's no-op and the second client's five appends at least.
        let clamped = assert_c_time(&history, ahead);
        assert!(clamped >= 6, "seed {seed}: {clamped} clamped entries");
    }
}

#[test]
fn test_c_time_an_election_to_a_server_behind_never_steps_back() {
    // The custom core elects its leader: a seed whose first leader is
    // server 0, the one ahead, which then crashes.
    let mut checked = 0;
    let mut skipped = Vec::new();
    for seed in 0..40 {
        let (mut sim, recorder) = build::<Custom>(seed, 0, None);
        sim.run_for(1_500).unwrap();
        if !leads(&sim, 0) || !done(&sim, SERVERS) {
            skipped.push((seed, leads(&sim, 0), done(&sim, SERVERS)));
            continue;
        }
        // Only server 0 has led so far: every committed entry is its own.
        let before = history(&recorder);
        if before.values().any(|&(_, event_time)| event_time < AHEAD) {
            skipped.push((seed, true, true));
            continue;
        }
        let ahead = before.values().map(|&(term, _)| term).max().unwrap();
        sim.crash(0).unwrap();
        sim.run_for(1_500).unwrap();
        let leader = (1..SERVERS).find(|&server| leads(&sim, server));
        let leader = leader.unwrap_or_else(|| panic!("seed {seed}: no new leader"));
        let client = second_client(&mut sim, &recorder, leader, 5);
        sim.run_for(3_000).unwrap();
        assert!(
            done(&sim, client),
            "seed {seed}: the second client is done; leaders {} {}; {:?}",
            leads(&sim, 1),
            leads(&sim, 2),
            history(&recorder)
        );
        assert!(
            leads(&sim, 1) || leads(&sim, 2),
            "seed {seed}: a new leader"
        );
        let history = history(&recorder);
        let clamped = assert_c_time(&history, ahead);
        assert!(clamped >= 6, "seed {seed}: {clamped} clamped entries");
        checked += 1;
        if checked == 2 {
            return;
        }
    }
    panic!("only {checked} seeds elected server 0 first: {skipped:?}");
}

#[test]
fn test_c_time_a_restart_from_the_log_continues_from_its_last_entry() {
    for seed in [1, 7, 42] {
        let (mut sim, recorder) = handed_over(seed);
        sim.crash(1).unwrap();
        sim.restart(1).unwrap();
        sim.run_for(300).unwrap();
        assert!(
            recorder.borrow().observations.iter().any(|o| matches!(
                o,
                Observation::Recovered { node: 1, entries, .. } if !entries.is_empty()
            )),
            "seed {seed}: server 1 recovered from its log"
        );
        assert!(leads(&sim, 1), "seed {seed}: server 1 leads again");
        let client = second_client(&mut sim, &recorder, LEADER, 5);
        sim.run_for(800).unwrap();
        assert!(done(&sim, client), "seed {seed}: the second client is done");
        let history = history(&recorder);
        let clamped = assert_c_time(&history, first_term(&history));
        assert!(clamped >= 6, "seed {seed}: {clamped} clamped entries");
    }
}

/// A tail from before C-TIME need not be ordered: over event times `10,
/// 50, 30`, recovery's watermark is the largest surviving time, 50, never
/// the last entry's 30, and a leader whose raw clock reads below 30 stamps
/// 50 (ADR-0111's upgrade case).
#[test]
fn test_c_time_recovery_takes_the_largest_surviving_time_not_the_last() {
    use std::path::Path;

    use karyos_cluster::{Entry, RaftLog};
    use karyos_sim::harness::core::LogView;
    use karyos_sim::harness::node::LOG_DIR;
    use karyos_sim::harness::workloads::geometry;

    let mut log =
        RaftLog::create(SimDisk::new(), Path::new(LOG_DIR), geometry().unwrap(), 1).unwrap();
    let tail: Vec<Entry> = (1..=3)
        .zip([10, 50, 30])
        .map(|(index, event_time)| Entry {
            index,
            term: karyos_sim::harness::reference::TERM,
            event_time,
            payload: vec![u8::try_from(index).unwrap()],
        })
        .collect();
    let _ = log.append(&tail).unwrap();
    let _ = log.sync().unwrap();
    assert_eq!(LogView::new(&mut log).watermark(), Some(50));
    // A snapshot's log time above every entry is the watermark.
    assert_eq!(
        LogView::new(&mut log).with_base_time(Some(70)).watermark(),
        Some(70)
    );
    let mut core = Reference::recover(LEADER, &[LEADER], &mut LogView::new(&mut log));
    core.tick(20, &mut LogView::new(&mut log));
    core.propose(vec![9], &mut LogView::new(&mut log)).unwrap();
    let ready = core.ready(&mut LogView::new(&mut log)).unwrap();
    let stamped: Vec<u64> = ready.entries.iter().map(|entry| entry.event_time).collect();
    assert!(!stamped.is_empty(), "the proposal is appended");
    assert!(
        stamped.iter().all(|&time| time == 50),
        "raw 20 stamps the surviving maximum 50: {stamped:?}"
    );
}

/// A log empty after a snapshot comes from an install: server 2 is down
/// while server 0 commits the first client's appends and compacts them
/// away, comes back and installs server 0's snapshot, its log restarting
/// after the base, and restarts again over it. Then server 0 hands its
/// leadership to server 2, whose clock is behind.
#[test]
fn test_c_time_a_restart_from_a_snapshot_with_an_empty_log_continues_from_its_log_time() {
    let compaction = Compaction {
        every: u64::from(FIRST),
        keep: 0,
        frame: 1,
        every_bytes: None,
    };
    for seed in [1, 7, 42] {
        let (mut sim, recorder) = build::<Reference>(seed, LEADER, Some(compaction));
        sim.crash(2).unwrap();
        sim.run_for(600).unwrap();
        assert!(done(&sim, SERVERS), "seed {seed}: the first client is done");
        sim.restart(2).unwrap();
        sim.run_for(600).unwrap();
        assert!(
            recorder.borrow().observations.iter().any(|o| matches!(
                o,
                Observation::Installed { node: 2, base, .. } if base.index == u64::from(FIRST)
            )),
            "seed {seed}: server 2 installed the snapshot"
        );
        sim.crash(2).unwrap();
        sim.restart(2).unwrap();
        sim.run_for(300).unwrap();
        let recovered: Vec<Vec<(u64, u64)>> = recorder
            .borrow()
            .observations
            .iter()
            .filter_map(|o| match o {
                Observation::Recovered {
                    node: 2, entries, ..
                } => Some(entries.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            recovered.last(),
            Some(&Vec::new()),
            "seed {seed}: server 2's log was empty after its snapshot"
        );
        let _ = sim.send(SERVERS, 0, Wire::Transfer(2)).unwrap();
        sim.run_for(300).unwrap();
        assert!(leads(&sim, 2), "seed {seed}: server 2 leads");
        let client = second_client(&mut sim, &recorder, 2, 5);
        sim.run_for(800).unwrap();
        assert!(done(&sim, client), "seed {seed}: the second client is done");
        let history = history(&recorder);
        let clamped = assert_c_time(&history, first_term(&history));
        assert!(clamped >= 6, "seed {seed}: {clamped} clamped entries");
    }
}
