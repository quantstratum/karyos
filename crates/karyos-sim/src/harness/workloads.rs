// SPDX-License-Identifier: Apache-2.0

//! ADR-0043's workloads over the harness: generators of [`Case`]s and
//! their pass predicates.
//!
//! **Revision.** This module follows ADR-0043 as of [`ADR_0043`]. The ADR
//! is Proposed, not accepted (owner item 31), so its table may still
//! change; a change there is a change here.
//!
//! Each workload is a struct whose fields are the ADR table's frozen
//! dimensions, holding the values this skeleton runs; each one's doc names
//! the values the ADR freezes where the skeleton runs fewer. W2 and W5
//! need what the harness does not have yet (declared capacity limits,
//! snapshots, client retries): [`w2`] and [`w5`] return a [`NotYet`]
//! saying so.
//!
//! [`run`] runs one case of any [`ConsensusCore`] and returns an
//! [`Outcome`] with safety ([`check::all`]) and liveness ([`Liveness`])
//! apart, so a core that cannot progress (the reference core after its
//! leader's crash) shows a liveness gap, not a safety violation.

use std::cell::RefCell;
use std::rc::Rc;

use karyos_archive::segment::{Geometry, SegmentError};
use karyos_cluster::LogError;

use super::check::{self, Violation};
use super::core::{Change, ConsensusCore};
use super::node::{
    ClientNode, Member, Observation, Op, RETRY_AFTER, Recorder, Ret, ServerNode, ServiceModel,
    Shared, TestService, Wire,
};
use super::reference;
use crate::cluster::{ClusterSim, NodeError};
use crate::disk::{SimDisk, Survives};
use crate::lin::{self, Event, History, Verdict};
use crate::net::{LinkConfig, LinkConfigError, LinkFaults, LinkState, NodeId};
use crate::sim::Failure;

/// The ADR-0043 revision this module follows.
pub const ADR_0043: &str = "quantstratum-docs 03ffb3944343885c8da04557c54814627dbe5001 \
     (2026-10-12), ADR-0043 Proposed, owner item 31";

/// A workload the harness cannot run yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotYet {
    /// The workload.
    pub workload: &'static str,
    /// What it needs first.
    pub reason: &'static str,
}

/// W2, capacity and slow follower.
///
/// # Errors
///
/// Always [`NotYet`].
pub fn w2() -> Result<Vec<Case>, NotYet> {
    Err(NotYet {
        workload: "W2",
        reason: "needs declared in-flight, queue and log-read limits with typed \
                 backpressure, and allocation counters, in the core interface",
    })
}

/// W5, snapshots and retries.
///
/// # Errors
///
/// Always [`NotYet`].
pub fn w5() -> Result<Vec<Case>, NotYet> {
    Err(NotYet {
        workload: "W5",
        reason: "needs snapshots and compaction in the core interface and the \
                 log, and a leader change for its lost-reply retries",
    })
}

/// A scheduled change to a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Crashes a node.
    Crash(NodeId),
    /// Restarts a node.
    Restart(NodeId),
    /// Cuts a server from every other server, both ways.
    Isolate(NodeId),
    /// Cuts one direction between two servers.
    Cut {
        /// The sender.
        from: NodeId,
        /// The receiver.
        to: NodeId,
    },
    /// Cuts every link between two groups of servers.
    Split {
        /// One side.
        left: Vec<NodeId>,
        /// The other.
        right: Vec<NodeId>,
    },
    /// Restores every link.
    Heal,
    /// Starts a spare server ([`Case::spares`]) with an empty log, the
    /// initial servers as its bootstrap peers: a member only once a
    /// configuration entry makes it one.
    Join(NodeId),
    /// An operator's membership change, sent to every server that is up;
    /// a core that does not lead refuses it.
    Change(Change),
}

/// What a case expects of progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// Every client's script completes.
    Expected,
    /// Progress may stop: the case removes what the core needs (its only
    /// leader, or a durable majority); a stop is a [`Liveness`] gap.
    MayStop,
}

/// One run: servers, clients, faults and a schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// Its name, for reports.
    pub name: String,
    /// Servers, ids from 0: the bootstrap voters.
    pub servers: usize,
    /// Spare servers, ids after the servers: down, with empty disks, until
    /// an [`Action::Join`] starts them.
    pub spares: usize,
    /// Clients, ids after the spares, each sending to the leader; the
    /// operator that sends [`Action::Change`] follows them.
    pub clients: usize,
    /// Operations per client: appends, and a final read by client 0.
    pub operations: usize,
    /// Bytes of each appended value.
    pub payload: usize,
    /// The links between servers; clients' links stay up and in order.
    pub server_links: LinkConfig,
    /// The delay of every server-to-client link.
    pub reply_delay: u64,
    /// Ticks a client waits for an answer before it sends again.
    pub retry_after: u64,
    /// What a server's crash keeps of its pending disk operations.
    pub survives: Survives,
    /// Servers whose flushes fail, from the first after
    /// [`Case::flushes_before_failure`] good ones past the log's creation.
    pub failing_flushes: Vec<NodeId>,
    /// The flushes a failing server completes before every later one
    /// fails: 0 fails the vote's save, more fail later appends.
    pub flushes_before_failure: u64,
    /// Each server's clock drift, in parts per million (missing is 0).
    pub drift_ppm: Vec<i64>,
    /// Actions, each before the step it names.
    pub schedule: Vec<(u64, Action)>,
    /// Steps to run.
    pub steps: u64,
    /// Steps after the restarts that end the run, before the checks: see
    /// [`QUIET`].
    pub quiet: u64,
    /// What it expects of progress.
    pub progress: Progress,
    /// The promotion lag [`check::learner_caught_up`] holds a leader to.
    pub promotion_lag: u64,
}

impl Case {
    /// A case of `servers` servers and `clients` clients doing
    /// `operations` each, with no fault.
    #[must_use]
    pub fn healthy(name: &str, servers: usize, clients: usize, operations: usize) -> Self {
        Self {
            name: name.to_owned(),
            servers,
            clients,
            operations,
            payload: 32,
            server_links: LinkConfig::default(),
            reply_delay: 1,
            retry_after: RETRY_AFTER,
            survives: Survives::Synced,
            failing_flushes: Vec::new(),
            flushes_before_failure: 0,
            drift_ppm: Vec::new(),
            schedule: Vec::new(),
            steps: 600,
            quiet: QUIET,
            progress: Progress::Expected,
            spares: 0,
            promotion_lag: reference::PROMOTION_LAG,
        }
    }
}

/// The quiet period: steps a run takes after restarting its crashed and
/// stopped servers, before its final checks. Each restart reopens the log
/// at once, so a lost or unopened log is already reported; the quiet
/// period lets the restarted servers take part again (their positions,
/// resent entries and re-applied commits, under the same checks), and
/// lets what was in flight land, so a server is unverified only when its
/// restart really fails. 100 steps are 25 of the reference's resend
/// periods and twice the longest link delay the workloads set (50).
/// Liveness and the servers' states are taken before the restarts, so
/// the quiet period changes neither.
pub const QUIET: u64 = 100;

/// Why progress stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// No server that is up leads.
    NoLeader,
    /// A server leads, but clients still wait.
    Stalled {
        /// Clients with requests left.
        waiting: usize,
    },
}

/// What a run gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The safety checks.
    pub safety: Result<(), Violation>,
    /// Whether every client finished.
    pub liveness: Result<(), Liveness>,
    /// Every observation.
    pub observations: Vec<Observation>,
    /// The clients' history.
    pub history: History<Op, Ret>,
    /// The cluster's trace.
    pub trace: Vec<String>,
    /// The cluster's trace digest.
    pub digest: u64,
    /// Each server that is up: its last applied index and state digest.
    pub states: Vec<(NodeId, Option<u64>, u64)>,
    /// Retried commands the up servers answered from deduplication.
    pub deduplicated: u64,
}

/// A case its run did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// A safety check.
    Safety(Box<Violation>),
    /// Progress stopped where the case expects it.
    Liveness(Liveness),
    /// Up servers that applied the same index ended in different states.
    Diverged(Vec<(NodeId, Option<u64>, u64)>),
    /// The same seed gave a different run.
    NotReplayed,
    /// The servers' state is not the linearized history's.
    WrongState {
        /// The linearized history's digest.
        expected: u64,
        /// The up servers' last applied index and digest.
        states: Vec<(NodeId, Option<u64>, u64)>,
    },
}

/// A run that could not be set up or stepped.
#[derive(Debug)]
pub enum RunError {
    /// The cluster.
    Sim(Failure),
    /// A link configuration.
    Link(LinkConfigError),
    /// A node's crash or restart.
    Node(NodeError),
    /// A server's log.
    Log(LogError),
    /// The log geometry.
    Geometry(SegmentError),
    /// A count beyond the node id range.
    Count,
}

/// The servers' log geometry: terms that fit the largest W1 payload.
///
/// # Errors
///
/// None for these constants; the type allows it.
pub fn geometry() -> Result<Geometry, SegmentError> {
    Geometry::new(64 * 1024, 1024 * 1024)
}

/// Flushes a failing disk fails, from its first after its log's creation:
/// more than a run makes (the disk keeps each number).
const FAILING: u64 = 1_000;

/// The flushes a new log's creation takes on a fresh disk.
fn creation_syncs<C: ConsensusCore>(geometry: Geometry) -> Option<u64> {
    (1..64u64).find_map(|first| {
        let disk = SimDisk::new().with_failed_syncs(first..first.checked_add(FAILING)?);
        let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
        ServerNode::<C>::new(0, vec![0], disk, Survives::Synced, geometry, recorder)
            .is_ok()
            .then(|| first.checked_sub(1))
            .flatten()
    })
}

/// The script of the `index`th client of `case`.
fn script(case: &Case, index: usize) -> Vec<Op> {
    (0..case.operations)
        .map(|operation| {
            if index == 0 && case.operations > 1 && operation + 1 == case.operations {
                return Op::Read;
            }
            let mut value = vec![0u8; case.payload.max(2)];
            if let Some(first) = value.first_mut() {
                *first = u8::try_from(index % 256).unwrap_or(0);
            }
            if let Some(second) = value.get_mut(1) {
                *second = u8::try_from(operation % 256).unwrap_or(0);
            }
            value.truncate(case.payload);
            Op::Append(value)
        })
        .collect()
}

/// A crash keeps `survives`, a seeded mode seeded apart per server.
fn per_server(survives: Survives, id: NodeId) -> Survives {
    match survives {
        Survives::Subset { seed } => Survives::Subset {
            seed: seed ^ u64::from(id),
        },
        Survives::Torn { seed } => Survives::Torn {
            seed: seed ^ u64::from(id),
        },
        other => other,
    }
}

/// Runs `case` of core `C` under `seed`.
///
/// # Errors
///
/// [`RunError`] when the run cannot be set up or stepped.
pub fn run<C: ConsensusCore>(case: &Case, seed: u64) -> Result<Outcome, RunError> {
    let geometry = geometry().map_err(RunError::Geometry)?;
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let mut sim: ClusterSim<Member<C>, Wire<C::Message>> =
        ClusterSim::new("harness", seed, LinkConfig::default()).map_err(RunError::Link)?;
    let servers = u32::try_from(case.servers).map_err(|_| RunError::Count)?;
    let peers: Vec<NodeId> = (0..servers).collect();
    let spares = u32::try_from(case.spares)
        .ok()
        .and_then(|spares| servers.checked_add(spares))
        .ok_or(RunError::Count)?;
    let everyone: Vec<NodeId> = (0..spares).collect();
    let first_failing = if case.failing_flushes.is_empty() {
        None
    } else {
        Some(
            creation_syncs::<C>(geometry)
                .and_then(|syncs| syncs.checked_add(1))
                .and_then(|first| first.checked_add(case.flushes_before_failure))
                .ok_or(RunError::Count)?,
        )
    };
    for &id in &everyone {
        let mut disk = SimDisk::new();
        if let Some(first) = first_failing
            && case.failing_flushes.contains(&id)
        {
            let last = first.checked_add(FAILING).ok_or(RunError::Count)?;
            disk = disk.with_failed_syncs(first..last);
        }
        let server = ServerNode::<C>::new(
            id,
            peers.clone(),
            disk,
            per_server(case.survives, id),
            geometry,
            Rc::clone(&recorder),
        )
        .map_err(RunError::Log)?;
        let index = usize::try_from(id).map_err(|_| RunError::Count)?;
        let drift = case.drift_ppm.get(index).copied().unwrap_or(0);
        let _ = sim
            .add_node(Member::Server(Box::new(server)), 0, drift)
            .map_err(RunError::Sim)?;
        // A spare waits down, its log empty, for its join.
        if id >= servers {
            sim.crash(id).map_err(RunError::Node)?;
        }
    }
    let leader = peers.first().copied().ok_or(RunError::Count)?;
    let mut clients = Vec::new();
    for index in 0..case.clients {
        let id = u32::try_from(index)
            .ok()
            .and_then(|index| spares.checked_add(index))
            .ok_or(RunError::Count)?;
        let client = ClientNode::new(id, leader, script(case, index), Rc::clone(&recorder))
            .with_retry_after(case.retry_after);
        let added = sim
            .add_node(Member::Client(client), 0, 0)
            .map_err(RunError::Sim)?;
        clients.push(added);
    }
    // The operator, a client with no script, only where a change is
    // scheduled, so a phase 4 case runs the nodes it always did.
    let changes = case
        .schedule
        .iter()
        .any(|(_, action)| matches!(action, Action::Change(_)));
    let mut operator = None;
    if changes {
        let id = u32::try_from(case.clients)
            .ok()
            .and_then(|count| spares.checked_add(count))
            .ok_or(RunError::Count)?;
        let node = ClientNode::new(id, leader, Vec::new(), Rc::clone(&recorder));
        operator = Some(
            sim.add_node(Member::Client(node), 0, 0)
                .map_err(RunError::Sim)?,
        );
    }
    for &from in &everyone {
        for &to in everyone.iter().filter(|to| **to != from) {
            sim.net_mut()
                .configure(from, to, case.server_links)
                .map_err(RunError::Link)?;
        }
        let replies = LinkConfig {
            min_delay: case.reply_delay,
            max_delay: case.reply_delay,
            ..LinkConfig::default()
        };
        for &client in clients.iter().chain(&operator) {
            sim.net_mut()
                .configure(from, client, replies)
                .map_err(RunError::Link)?;
        }
    }
    let mut joined: Vec<NodeId> = peers.clone();
    let mut schedule = case.schedule.clone();
    schedule.sort_by_key(|(step, _)| *step);
    let mut done = 0u64;
    for (step, action) in schedule {
        if let Some(steps) = step.checked_sub(done).filter(|steps| *steps > 0) {
            sim.run_for(steps).map_err(RunError::Sim)?;
            done = step;
        }
        match action {
            Action::Crash(id) => sim.crash(id).map_err(RunError::Node)?,
            Action::Restart(id) => sim.restart(id).map_err(RunError::Node)?,
            Action::Isolate(id) => sim.net_mut().isolate(id, &everyone),
            Action::Cut { from, to } => sim.net_mut().cut(from, to),
            Action::Split { left, right } => sim.net_mut().split(&left, &right),
            Action::Heal => sim.net_mut().heal(),
            Action::Join(id) => {
                sim.restart(id).map_err(RunError::Node)?;
                if !joined.contains(&id) {
                    joined.push(id);
                }
            }
            Action::Change(change) => {
                // Present: this case schedules a change.
                let operator = operator.ok_or(RunError::Count)?;
                for &id in &everyone {
                    if sim
                        .node(id)
                        .and_then(Member::server)
                        .is_some_and(ServerNode::is_up)
                    {
                        let _ = sim
                            .send(operator, id, Wire::Change(change))
                            .map_err(RunError::Sim)?;
                    }
                }
            }
        }
    }
    if let Some(steps) = case.steps.checked_sub(done).filter(|steps| *steps > 0) {
        sim.run_for(steps).map_err(RunError::Sim)?;
    }

    let waiting = clients
        .iter()
        .filter(|id| {
            sim.node(**id)
                .and_then(Member::client)
                .is_some_and(|client| !client.done())
        })
        .count();
    let up: Vec<(NodeId, &ServerNode<C>)> = joined
        .iter()
        .filter_map(|id| Some((*id, sim.node(*id).and_then(Member::server)?)))
        .filter(|(_, server)| server.is_up())
        .collect();
    let liveness = if waiting == 0 {
        Ok(())
    } else if !up
        .iter()
        .any(|(_, server)| server.core().is_some_and(ConsensusCore::leads))
    {
        Err(Liveness::NoLeader)
    } else {
        Err(Liveness::Stalled { waiting })
    };
    let states = up
        .iter()
        .map(|(id, server)| (*id, server.service().applied(), server.service().digest()))
        .collect();
    let deduplicated = up
        .iter()
        .map(|(_, server)| server.service().deduplicated())
        .try_fold(0u64, u64::checked_add)
        .ok_or(RunError::Count)?;
    // Every server that is not up, crashed or stopped by a drive error,
    // restarts before the checks, so what it held durably is verified
    // (`check::durable_kept`); then the quiet period runs.
    let stopped: Vec<NodeId> = joined
        .iter()
        .copied()
        .filter(|id| {
            sim.node(*id)
                .and_then(Member::server)
                .is_some_and(|server| !server.is_up())
        })
        .collect();
    for id in stopped {
        // A stopped server is up to the simulator: crash it first.
        match sim.crash(id) {
            Ok(()) | Err(NodeError::AlreadyDown(_)) => {}
            Err(error) => return Err(RunError::Node(error)),
        }
        sim.restart(id).map_err(RunError::Node)?;
    }
    sim.run_for(case.quiet).map_err(RunError::Sim)?;
    let recorded = recorder.borrow();
    Ok(Outcome {
        safety: check::all(&recorded.observations, &recorded.history, case.servers)
            .and_then(|()| check::membership(&recorded.observations, case.promotion_lag)),
        liveness,
        observations: recorded.observations.clone(),
        history: recorded.history.clone(),
        trace: sim.trace().to_vec(),
        digest: sim.digest(),
        states,
        deduplicated,
    })
}

/// The pass predicate of W1, W3, W4 and W6: every safety check holds,
/// canonical responses included ([`check::responses_agree`]); progress
/// completes where the case expects it, else a stop is returned as the
/// gap it is; the up servers that applied the most agree on the state
/// digest; and where every client finished, that digest is the one the
/// linearized history builds, each append once.
///
/// # Errors
///
/// [`Failed`].
pub fn pass(case: &Case, outcome: &Outcome) -> Result<Option<Liveness>, Failed> {
    outcome
        .safety
        .clone()
        .map_err(|violation| Failed::Safety(Box::new(violation)))?;
    let gap = match (outcome.liveness, case.progress) {
        (Ok(()), _) => None,
        (Err(gap), Progress::MayStop) => Some(gap),
        (Err(gap), Progress::Expected) => return Err(Failed::Liveness(gap)),
    };
    let applied = outcome.states.iter().map(|(_, applied, _)| *applied).max();
    let mut digests = outcome
        .states
        .iter()
        .filter(|(_, last, _)| Some(*last) == applied)
        .map(|(_, _, digest)| *digest);
    let first = digests.next();
    if digests.any(|digest| Some(digest) != first) {
        return Err(Failed::Diverged(outcome.states.clone()));
    }
    // Where every client finished, the state is the register the
    // clients' linearized appends make, each once.
    if gap.is_none()
        && let Some(state) = first
    {
        let expected = linearized_digest(&outcome.history)?;
        if state != expected {
            return Err(Failed::WrongState {
                expected,
                states: outcome.states.clone(),
            });
        }
    }
    Ok(gap)
}

/// The digest of the register the linearization of `history` builds.
fn linearized_digest(history: &History<Op, Ret>) -> Result<u64, Failed> {
    let violation = match lin::check(&ServiceModel, history, check::LIMIT) {
        Ok(Verdict::Linearizable(order)) => return Ok(digest_in(history, &order)),
        Ok(Verdict::NotLinearizable(counterexample)) => Violation::NotLinearizable(counterexample),
        Ok(Verdict::Undecided { explored }) => Violation::Undecided { explored },
        Err(error) => Violation::MalformedHistory(error),
    };
    Err(Failed::Safety(Box::new(violation)))
}

/// The digest of the register the appends of `history` build in `order`.
fn digest_in(history: &History<Op, Ret>, order: &[usize]) -> u64 {
    let ops: Vec<&Op> = history
        .events()
        .iter()
        .filter_map(|event| match event {
            Event::Invoke { op, .. } => Some(op),
            Event::Return { .. } => None,
        })
        .collect();
    let values: Vec<Vec<u8>> = order
        .iter()
        .filter_map(|index| match ops.get(*index) {
            Some(Op::Append(value)) => Some(value.clone()),
            _ => None,
        })
        .collect();
    TestService::digest_of(&values)
}

/// W1, normal sequencer and OMS-like commands.
///
/// The ADR freezes 3 and 5 processes; payloads of 32 B, 256 B, 1 KiB and
/// 8 KiB; 1 and 32 clients; batch limits of 1, 16 and 64 entries plus a
/// byte cap. The skeleton runs every process count, payload and client
/// count, and the reference core's one batch byte cap: a batch limit is
/// the core's, not the workload's, so it is recorded, not varied.
/// Allocation and copy counters and the latency timestamps are not
/// measured yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W1 {
    /// Servers.
    pub processes: Vec<usize>,
    /// Bytes per appended value.
    pub payload_bytes: Vec<usize>,
    /// Concurrent clients.
    pub clients: Vec<usize>,
    /// Entries per append message at most; empty when the core caps
    /// bytes only.
    pub batch_entries: Vec<usize>,
    /// Frame bytes per append message at most.
    pub batch_bytes: u64,
    /// Operations per client.
    pub operations: usize,
}

impl W1 {
    /// The values ADR-0043 freezes (its byte cap is the reference's).
    #[must_use]
    pub fn adr() -> Self {
        Self {
            processes: vec![3, 5],
            payload_bytes: vec![32, 256, 1024, 8192],
            clients: vec![1, 32],
            batch_entries: vec![1, 16, 64],
            batch_bytes: reference::BATCH_BYTES,
            operations: 4,
        }
    }

    /// The values the skeleton runs with the reference core.
    #[must_use]
    pub fn skeleton() -> Self {
        Self {
            batch_entries: Vec::new(),
            ..Self::adr()
        }
    }

    /// Every combination, as cases.
    #[must_use]
    pub fn cases(&self) -> Vec<Case> {
        let mut cases = Vec::new();
        for &processes in &self.processes {
            for &payload in &self.payload_bytes {
                for &clients in &self.clients {
                    let mut case = Case::healthy(
                        &format!("W1 n={processes} payload={payload} clients={clients}"),
                        processes,
                        clients,
                        self.operations,
                    );
                    case.payload = payload;
                    cases.push(case);
                }
            }
        }
        cases
    }
}

/// W3's faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum W3Fault {
    /// The leader crashes and stays down.
    LeaderCrash,
    /// The leader is cut off from the servers for a while.
    LeaderPause,
    /// A follower is isolated, then returns.
    IsolatedFollowerReturning,
    /// One direction from the leader to a follower is cut.
    AsymmetricLink,
    /// Server links lose, duplicate and reorder messages.
    LossyLinks,
    /// A partition that leaves the leader a quorum.
    PartitionWithQuorum,
    /// A partition that leaves the leader none, healed later.
    PartitionWithoutQuorum,
}

/// W3, elections and partitions.
///
/// The ADR freezes leader crash and pause, an isolated follower returning,
/// asymmetric links, lost, duplicated and reordered messages, and
/// partitions with and without quorum: the skeleton runs each. Its pass
/// condition is the safety checks, and progress once the quorum and timing
/// assumptions hold again; a leader crash without elections is a gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W3 {
    /// Servers.
    pub processes: usize,
    /// Clients.
    pub clients: usize,
    /// The faults.
    pub faults: Vec<W3Fault>,
    /// Rates of the lossy links, in parts per million.
    pub lossy: LinkFaults,
}

impl W3 {
    /// The values the skeleton runs.
    #[must_use]
    pub fn skeleton() -> Self {
        Self {
            processes: 3,
            clients: 2,
            faults: vec![
                W3Fault::LeaderCrash,
                W3Fault::LeaderPause,
                W3Fault::IsolatedFollowerReturning,
                W3Fault::AsymmetricLink,
                W3Fault::LossyLinks,
                W3Fault::PartitionWithQuorum,
                W3Fault::PartitionWithoutQuorum,
            ],
            lossy: LinkFaults {
                loss_ppm: 100_000,
                reorder_ppm: 100_000,
                duplicate_ppm: 100_000,
            },
        }
    }

    /// One case per fault.
    #[must_use]
    pub fn cases(&self) -> Vec<Case> {
        self.faults
            .iter()
            .map(|fault| {
                let mut case =
                    Case::healthy(&format!("W3 {fault:?}"), self.processes, self.clients, 4);
                case.schedule = match fault {
                    W3Fault::LeaderCrash => {
                        case.progress = Progress::MayStop;
                        // Before the first request can commit.
                        vec![(2, Action::Crash(0))]
                    }
                    W3Fault::LeaderPause => vec![(10, Action::Isolate(0)), (120, Action::Heal)],
                    W3Fault::IsolatedFollowerReturning => {
                        vec![(10, Action::Isolate(2)), (120, Action::Heal)]
                    }
                    W3Fault::AsymmetricLink => vec![(5, Action::Cut { from: 0, to: 1 })],
                    W3Fault::LossyLinks => {
                        case.server_links.state = LinkState::Lossy(self.lossy);
                        case.server_links.max_delay = 3;
                        Vec::new()
                    }
                    W3Fault::PartitionWithQuorum => vec![(
                        10,
                        Action::Split {
                            left: vec![0, 1],
                            right: vec![2],
                        },
                    )],
                    W3Fault::PartitionWithoutQuorum => vec![
                        (
                            10,
                            Action::Split {
                                left: vec![0],
                                right: vec![1, 2],
                            },
                        ),
                        (150, Action::Heal),
                    ],
                };
                case
            })
            .collect()
    }
}

/// W4's persistence cuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum W4Cut {
    /// A follower crashes at the step and restarts 40 steps later.
    FollowerCrash {
        /// The crash's step.
        step: u64,
    },
    /// The leader crashes at the step and restarts 40 steps later.
    LeaderCrash {
        /// The crash's step.
        step: u64,
    },
    /// One follower's flushes fail after `after` good ones: progress
    /// continues on the others.
    FailedFlush {
        /// Good flushes first.
        after: u64,
    },
    /// Every follower's flushes fail after `after` good ones: no durable
    /// majority.
    FailedFlushes {
        /// Good flushes first.
        after: u64,
    },
}

/// W4, persistence cuts.
///
/// The ADR freezes crashes before and after vote persistence, the append
/// write, flush completion, reply release and the application checkpoint;
/// a torn suffix; a failed flush. The skeleton crashes servers at a sweep
/// of steps (which fall at each phase of a duty over the seeds) under
/// every survival mode, torn suffixes among them, and fails flushes. The
/// reference core votes only once, at its first Ready, so crashes around
/// a vote of a later term wait for a core with elections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W4 {
    /// Servers.
    pub processes: usize,
    /// Clients.
    pub clients: usize,
    /// The cuts.
    pub cuts: Vec<W4Cut>,
    /// The survival modes of a crash, the seeded ones by the run's seed.
    pub survives: Vec<Survives>,
}

impl W4 {
    /// The values the skeleton runs, its seeded survival modes by `seed`.
    #[must_use]
    pub fn skeleton(seed: u64) -> Self {
        let mut cuts: Vec<W4Cut> = [1, 6, 9, 13, 18, 25]
            .into_iter()
            .flat_map(|step| [W4Cut::FollowerCrash { step }, W4Cut::LeaderCrash { step }])
            .collect();
        cuts.extend(
            [0, 2, 4, 7]
                .into_iter()
                .flat_map(|after| [W4Cut::FailedFlush { after }, W4Cut::FailedFlushes { after }]),
        );
        Self {
            processes: 3,
            clients: 2,
            cuts,
            survives: vec![
                Survives::Synced,
                Survives::Everything,
                Survives::Subset { seed },
                Survives::Torn { seed },
            ],
        }
    }

    /// Every cut under every survival mode, as cases.
    #[must_use]
    pub fn cases(&self) -> Vec<Case> {
        let mut cases = Vec::new();
        for &cut in &self.cuts {
            for &survives in &self.survives {
                let mut case = Case::healthy(
                    &format!("W4 {cut:?} {survives:?}"),
                    self.processes,
                    self.clients,
                    4,
                );
                case.survives = survives;
                match cut {
                    W4Cut::FollowerCrash { step } => {
                        case.schedule =
                            vec![(step, Action::Crash(2)), (step + 40, Action::Restart(2))];
                    }
                    W4Cut::LeaderCrash { step } => {
                        // The requests the leader held are lost with it;
                        // a client retries, but a stop is a gap.
                        case.progress = Progress::MayStop;
                        case.schedule =
                            vec![(step, Action::Crash(0)), (step + 40, Action::Restart(0))];
                    }
                    W4Cut::FailedFlush { after } => {
                        case.failing_flushes = vec![2];
                        case.flushes_before_failure = after;
                    }
                    W4Cut::FailedFlushes { after } => {
                        case.progress = Progress::MayStop;
                        case.failing_flushes = vec![1, 2];
                        case.flushes_before_failure = after;
                    }
                }
                cases.push(case);
            }
        }
        cases
    }
}

/// W6, deterministic replay and scheduler limits.
///
/// The ADR freezes the same seed, configuration and input repeated;
/// virtual clock jumps; bounded work budgets; flush and network completion
/// permutations. The skeleton repeats each case under skewed clocks and
/// variable link delays, which permute completions, and every duty runs
/// under `drive`'s Ready budget ([`super::core::MAX_READIES`]). Clock
/// jumps need the multi-node host to offer them, and are not run yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W6 {
    /// Runs of each case.
    pub repetitions: usize,
    /// Each server's clock drift, in parts per million.
    pub drift_ppm: Vec<i64>,
    /// The longest link delay, so deliveries permute.
    pub max_delay: u64,
}

impl W6 {
    /// The values the skeleton runs.
    #[must_use]
    pub fn skeleton() -> Self {
        Self {
            repetitions: 2,
            drift_ppm: vec![0, 200, -300],
            max_delay: 3,
        }
    }

    /// The cases it repeats.
    #[must_use]
    pub fn cases(&self) -> Vec<Case> {
        let mut healthy = Case::healthy("W6 healthy", 3, 2, 4);
        healthy.drift_ppm.clone_from(&self.drift_ppm);
        healthy.server_links.max_delay = self.max_delay;
        let mut crash = healthy.clone();
        crash.name = "W6 follower crash".to_owned();
        crash.survives = Survives::Torn { seed: 7 };
        crash.schedule = vec![(12, Action::Crash(1)), (50, Action::Restart(1))];
        // Replies slower than the clients' patience: every request is
        // sent again and applied twice, and deduplication answers it.
        let mut retried = healthy.clone();
        retried.name = "W6 slow replies".to_owned();
        retried.reply_delay = 50;
        retried.retry_after = 30;
        retried.steps = 1200;
        vec![healthy, crash, retried]
    }

    /// `case` of core `C` repeated under `seed`: every run must give the
    /// first one's outcome, trace and digest included, and the first must
    /// [`pass`].
    ///
    /// # Errors
    ///
    /// [`RunError`] when a run cannot be set up or stepped.
    pub fn pass<C: ConsensusCore>(
        &self,
        case: &Case,
        seed: u64,
    ) -> Result<Result<Option<Liveness>, Failed>, RunError> {
        let first = run::<C>(case, seed)?;
        for _ in 1..self.repetitions {
            if run::<C>(case, seed)? != first {
                return Ok(Err(Failed::NotReplayed));
            }
        }
        Ok(pass(case, &first))
    }
}
