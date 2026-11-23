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
//! the values the ADR freezes where the skeleton runs fewer. W2 declares its
//! limits to the core ([`Case::limits`]); a core that takes none has its
//! W2 cases not demonstrated, never passed.
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
use super::core::{Change, ConsensusCore, Limits, Unsupported};
use super::node::{
    ClientNode, Compaction, Member, Observation, Op, RETRY_AFTER, Recorder, Ret, ServerError,
    ServerNode, ServiceModel, Shared, TestService, Wire,
};
use super::reference;
use super::standby::{ExternalLease, FeedFault, Fencing};
use crate::cluster::{ClusterSim, NodeError};
use crate::disk::{SimDisk, Survives};
use crate::lin::{self, Event, History, Verdict};
use crate::net::{LinkConfig, LinkConfigError, LinkFaults, LinkState, NodeId};
use crate::sim::Failure;

/// The ADR-0043 revision this module follows.
pub const ADR_0043: &str = "quantstratum-docs 03ffb3944343885c8da04557c54814627dbe5001 \
     (2026-10-12), ADR-0043 Proposed, owner item 31";

/// A W2 count or step bound past its type ([`W2::cases`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct W2Overflow;

/// W2, capacity and slow follower (karyos#687), under declared
/// [`Limits`].
///
/// The manifest freezes 3 servers, 32 clients, 256 B payloads, the limits
/// of [`Limits::W2`], bursts at 4x each limit, and a follower paused for
/// 2,000 ticks while the leader continues, then catching up from 10,000
/// entries behind. The pause is an isolation: the follower runs, and
/// nothing reaches it or leaves it. Its pass condition is W1's, the
/// follower caught up to the same state, with every refusal typed.
///
/// The bursts at 4x each limit come from pipelined clients
/// ([`Case::window`]): 4x the queue's requests open at once, 4x the
/// in-flight entries, and a follower behind by 4x the log-read limit's
/// bytes. At 256 B, 64 entries are 16 KiB, so the 1 MiB in-flight byte
/// limit is never the one reached: every W2 run record says so
/// ([`W2::IN_FLIGHT_BYTES`]), and the report scores that sub-check not
/// demonstrated (decided 2026-10-30 by QS-COORDINATOR;
/// quantstratum-docs#731 proposes a large-payload case).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W2 {
    /// Servers.
    pub processes: usize,
    /// Clients.
    pub clients: usize,
    /// Bytes per appended value.
    pub payload_bytes: usize,
    /// The declared limits.
    pub limits: Limits,
    /// Steps the follower is cut off.
    pub pause: u64,
    /// Entries committed while it is cut off, at least.
    pub behind: u64,
}

impl W2 {
    /// The follower the slow case cuts off: not the reference's leader.
    pub const SLOW: NodeId = 2;

    /// What every W2 v1 run record states of the in-flight byte limit.
    pub const IN_FLIGHT_BYTES: &str =
        "in-flight bytes limit: not reached by W2 v1 (256 B payloads)";

    /// The bursts' factor over each limit.
    pub const BURST: u64 = 4;

    /// The values the manifest freezes.
    #[must_use]
    pub fn manifest() -> Self {
        Self {
            processes: 3,
            clients: 32,
            payload_bytes: 256,
            limits: Limits::W2,
            pause: 2_000,
            behind: 10_000,
        }
    }

    /// The values the skeleton runs in the test suite: the manifest's
    /// shape, a tenth of its catch-up, and limits a sixteenth of the
    /// manifest's, so its bursts stay small.
    #[must_use]
    pub fn skeleton() -> Self {
        Self {
            clients: 8,
            pause: 1_000,
            behind: 1_000,
            limits: Limits {
                in_flight_entries: 4,
                in_flight_bytes: 64 * 1024,
                queue: 64,
                log_read_bytes: 64 * 1024,
            },
            ..Self::manifest()
        }
    }

    /// Its cases: the clients under the limits, the bursts at
    /// [`W2::BURST`] times the queue and the in-flight entries, the slow
    /// follower, and one behind by [`W2::BURST`] times the log-read limit.
    ///
    /// # Errors
    ///
    /// [`W2Overflow`] when a count or a step bound derived from its values
    /// passes its type: values no frozen profile comes near.
    pub fn cases(&self) -> Result<Vec<Case>, W2Overflow> {
        let clients = self.clients.max(1);
        let payload = u64::try_from(self.payload_bytes.max(1)).map_err(|_| W2Overflow)?;
        let read_behind = self
            .limits
            .log_read_bytes
            .checked_mul(Self::BURST)
            .ok_or(W2Overflow)?
            .div_ceil(payload);
        Ok(vec![
            self.nominal(clients),
            self.burst(clients, "queue", self.limits.queue)?,
            self.burst(clients, "in-flight entries", self.limits.in_flight_entries)?,
            self.slow(clients, self.behind, Some(self.pause), "slow follower")?,
            self.slow(clients, read_behind, None, "log-read burst")?,
        ])
    }

    /// The clients under the limits.
    fn nominal(&self, clients: usize) -> Case {
        let mut case = Case::healthy(
            &format!("W2 n={} clients={clients} nominal", self.processes),
            self.processes,
            clients,
            4,
        );
        case.payload = self.payload_bytes;
        case.limits = Some(self.limits);
        case.converged = true;
        case.notes = vec![Self::IN_FLIGHT_BYTES];
        case
    }

    /// [`W2::BURST`] times `limit` requests open at once: each client's
    /// window holds its share, one request each.
    fn burst(&self, clients: usize, what: &str, limit: u64) -> Result<Case, W2Overflow> {
        let open = limit.checked_mul(Self::BURST).ok_or(W2Overflow)?;
        let window = usize::try_from(open)
            .map_err(|_| W2Overflow)?
            .div_ceil(clients);
        let mut case = Case::healthy(
            &format!(
                "W2 n={} clients={clients} window={window} burst {}x {what}",
                self.processes,
                Self::BURST
            ),
            self.processes,
            clients,
            1,
        );
        case.payload = self.payload_bytes;
        case.limits = Some(self.limits);
        case.converged = true;
        case.notes = vec![Self::IN_FLIGHT_BYTES];
        case.window = window;
        let _ = case.sessions().ok_or(W2Overflow)?;
        // A refused request waits its retry interval: a few intervals.
        let intervals = Self::BURST.checked_add(2).ok_or(W2Overflow)?;
        let waits = case.retry_after.checked_mul(intervals).ok_or(W2Overflow)?;
        case.steps = case.steps.max(waits);
        Ok(case)
    }

    /// A follower cut off for `pause` steps (by default, long enough for
    /// the leader to commit `behind` entries), then catching up.
    fn slow(
        &self,
        clients: usize,
        behind: u64,
        pause: Option<u64>,
        what: &str,
    ) -> Result<Case, W2Overflow> {
        // Every client's share of the entries the follower misses, and
        // two more each for what it holds before it is cut off.
        let share = usize::try_from(behind)
            .map_err(|_| W2Overflow)?
            .div_ceil(clients)
            .checked_add(2)
            .ok_or(W2Overflow)?;
        let mut case = Case::healthy(
            &format!(
                "W2 n={} clients={clients} {what} {behind} behind",
                self.processes
            ),
            self.processes,
            clients,
            share,
        );
        case.payload = self.payload_bytes;
        case.limits = Some(self.limits);
        case.converged = true;
        case.notes = vec![Self::IN_FLIGHT_BYTES];
        case.behind = Some((Self::SLOW, behind));
        // By default, long enough for the share to commit while it is cut
        // off: a few steps for each operation.
        let work = u64::try_from(share)
            .ok()
            .and_then(|share| share.checked_mul(8))
            .ok_or(W2Overflow)?;
        let healed = pause.unwrap_or(work).checked_add(10).ok_or(W2Overflow)?;
        case.schedule = vec![(10, Action::Isolate(Self::SLOW)), (healed, Action::Heal)];
        // Then twice the catch-up the reference needs at its in-flight
        // entries per resend.
        let catch_up = behind
            .div_ceil(self.limits.in_flight_entries.max(1))
            .checked_mul(reference::RESEND)
            .and_then(|steps| steps.checked_mul(2))
            .ok_or(W2Overflow)?;
        case.steps = healed.max(work).checked_add(catch_up).ok_or(W2Overflow)?;
        Ok(case)
    }
}

/// W5, snapshots and retries (karyos#687): compaction, a follower held
/// behind the compaction point, snapshot build and install interrupted, and
/// a lost client reply followed by a leader change and a retry.
///
/// The manifest freezes 3 servers, 2 clients, 256 B payloads, compaction
/// every 1,000 applied entries keeping 100, a follower held behind the
/// compaction point, and snapshot build and install interrupted at every
/// manifest and truncation boundary. A build or an install runs whole
/// within one step of the simulator, so a step's crash cannot cut it: its
/// boundaries are crashed one disk operation at a time by the snapshot
/// store's and the log install's own tests (`tests/snapshot_crash.rs`,
/// `tests/log_install.rs`). Here, in whole runs, a follower crashes after
/// the heal and installs once restarted, and a server crashes between two
/// of its builds. A core that takes no snapshots has these cases not
/// demonstrated, never passed.
///
/// The retries: a client's reply is lost (the leader's link to it cut),
/// the operator hands the leadership over, and the client's retry, sent to
/// the old leader and redirected, is answered from the new leader's
/// deduplication table, which keeps each client's last
/// [`super::node::RETENTION`] answers and answers an older retry
/// [`super::node::Ret::Expired`]. A core that cannot hand its leadership
/// over has this case not demonstrated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W5 {
    /// Servers.
    pub processes: usize,
    /// Clients.
    pub clients: usize,
    /// Bytes per appended value.
    pub payload_bytes: usize,
    /// The compaction.
    pub compaction: Compaction,
}

impl W5 {
    /// The follower held behind: not the reference's leader.
    pub const BEHIND: NodeId = 2;

    /// The values the manifest freezes.
    #[must_use]
    pub fn manifest() -> Self {
        Self {
            processes: 3,
            clients: 2,
            payload_bytes: 256,
            compaction: Compaction {
                every: 1_000,
                keep: 100,
            },
        }
    }

    /// The values the skeleton runs in the test suite: a tenth of the
    /// manifest's compaction.
    #[must_use]
    pub fn skeleton() -> Self {
        Self {
            compaction: Compaction {
                every: 100,
                keep: 10,
            },
            ..Self::manifest()
        }
    }

    /// Its cases.
    ///
    /// # Errors
    ///
    /// [`W2Overflow`] when a count derived from its values passes its type.
    pub fn cases(&self) -> Result<Vec<Case>, W2Overflow> {
        let every = self.compaction.every.max(1);
        // Three compactions' worth of entries, between the clients.
        let entries = every.checked_mul(3).ok_or(W2Overflow)?;
        let clients = self.clients.max(1);
        let share = usize::try_from(entries)
            .map_err(|_| W2Overflow)?
            .div_ceil(clients);
        let work = u64::try_from(share)
            .ok()
            .and_then(|share| share.checked_mul(8))
            .ok_or(W2Overflow)?;
        let steps = work.checked_mul(2).ok_or(W2Overflow)?;
        let base = |name: &str| {
            let mut case = Case::healthy(
                &format!("W5 n={} {name}", self.processes),
                self.processes,
                clients,
                share,
            );
            case.payload = self.payload_bytes;
            case.compaction = Some(self.compaction);
            case.converged = true;
            case.steps = steps;
            case
        };
        let compaction = base("compaction under load");
        // Held behind the compaction point until two compactions passed.
        let mut behind = base("follower behind the compaction point");
        let heal = work
            .checked_mul(2)
            .ok_or(W2Overflow)?
            .checked_div(3)
            .ok_or(W2Overflow)?;
        behind.schedule = vec![(1, Action::Isolate(Self::BEHIND)), (heal, Action::Heal)];
        let gap = every.checked_add(self.compaction.keep).ok_or(W2Overflow)?;
        behind.behind = Some((Self::BEHIND, gap));
        behind.steps = work.checked_mul(3).ok_or(W2Overflow)?;
        // The same, the follower crashing right after the heal and
        // installing once restarted.
        let mut install = behind.clone();
        install.name = format!("W5 n={} follower crash around its install", self.processes);
        install.schedule.extend([
            (
                heal.checked_add(2).ok_or(W2Overflow)?,
                Action::Crash(Self::BEHIND),
            ),
            (
                heal.checked_add(40).ok_or(W2Overflow)?,
                Action::Restart(Self::BEHIND),
            ),
        ]);
        // A follower crashing between its first and second snapshot
        // builds, restarting from its snapshot and its log.
        let mut build = base("follower crash between builds");
        let at = work.checked_div(3).ok_or(W2Overflow)?;
        build.schedule = vec![
            (at, Action::Crash(1)),
            (at.checked_add(40).ok_or(W2Overflow)?, Action::Restart(1)),
        ];
        // A lost reply, a handover and the retry: the first client's
        // replies from the leader are cut while its request commits; the
        // leadership moves to server 1; the cut heals before the retry.
        let mut retry = base("lost reply, leader change and retry");
        retry.compaction = None;
        retry.handover = Some(1);
        retry.retried = true;
        retry.operations = 8;
        let client = NodeId::try_from(self.processes).map_err(|_| W2Overflow)?;
        // Mid-run: each operation takes a few steps.
        let lost = 12;
        retry.schedule = vec![
            (
                lost,
                Action::Cut {
                    from: 0,
                    to: client,
                },
            ),
            (lost + 10, Action::TransferLeadership(1)),
            (lost + 30, Action::Heal),
        ];
        retry.steps = 2_000;
        Ok(vec![compaction, behind, install, build, retry])
    }
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
    /// An operator's leadership handover to `to`, sent to every server
    /// that is up; a core that does not lead refuses it (W5).
    TransferLeadership(NodeId),
    /// The primary's leader stops reaching the arbiter: its lease is no
    /// longer renewed ([`Case::lease`]).
    CutArbiter,
    /// The operator stops every primary server and confirms it.
    OperatorStop,
    /// Promotes the standby once `Fencing` is verified, sending clients to
    /// its leader (but those of [`Case::stay_on_primary`]); refused, and
    /// recorded so, when it is not.
    Promote(Fencing),
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
    /// Standby servers, ids after the spares, fed by the primary (phase 5,
    /// P5-S2); 0 for none.
    pub standby: usize,
    /// The primary's lease, in ticks, when it fences by lease.
    pub lease: Option<u64>,
    /// Ticks the arbiter waits past a lease's end for the clocks' skew.
    pub lease_margin: u64,
    /// Faults on the feed, each on one send of its primary index.
    pub feed_faults: Vec<(u64, FeedFault)>,
    /// Clients, by index, that stay on the primary after a promotion.
    pub stay_on_primary: Vec<usize>,
    /// The limits every server's core is declared (W2), if any: a core
    /// that takes none cannot run the case ([`RunError::Unsupported`]).
    pub limits: Option<Limits>,
    /// Requests each client keeps open at once, at least 1: a pipelined
    /// client (W2's bursts; decided 2026-10-30 by QS-COORDINATOR). Each
    /// open slot is a session of its own, its own process in the history
    /// and its own deduplication, so `clients x window` sessions run
    /// [`Case::operations`] each. A harness capability, named in every
    /// run record.
    pub window: usize,
    /// Every up server must end at the same applied index and state, not
    /// only those at the highest: W2's catch-up is the point of the case
    /// (karyos#899 review).
    pub converged: bool,
    /// What the case does not cover, stated in every raw result line of
    /// its runs: W2's [`W2::IN_FLIGHT_BYTES`].
    pub notes: Vec<&'static str>,
    /// Its servers' log compaction (W5), if any.
    pub compaction: Option<Compaction>,
    /// A handover the case must show taken (W5): its target must answer
    /// a handover `Ok` and then commit as leader, or the case fails
    /// ([`Failed::NotShown`]; karyos#905 review).
    pub handover: Option<NodeId>,
    /// The case must show a retry across the handover (W5), or it fails
    /// ([`Failed::NotShown`]): one request, redirected by another server
    /// to the handover's target, then answered from deduplication by that
    /// target after it took the handover and committed as leader
    /// (karyos#905 review).
    pub retried: bool,
    /// A follower cut off until the first heal, and the entries the
    /// leaders must have committed past its own commit by then: W2's slow
    /// follower must really be that far behind, or the case fails
    /// ([`Failed::NotBehind`]; karyos#899 review).
    pub behind: Option<(NodeId, u64)>,
    /// Faults injected into servers and clients, so the checks can be
    /// shown to catch a faulty driver, disk, service or client with a real
    /// core behind them (karyos#1038; the `test-hooks` feature). Empty in
    /// every workload.
    #[cfg(feature = "test-hooks")]
    pub faults: Faults,
}

/// What [`Case::faults`] injects (karyos#1038, tests).
#[cfg(feature = "test-hooks")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Faults {
    /// Servers whose driver injects a fault.
    pub drive: Vec<(NodeId, super::core::DriveFault)>,
    /// Servers whose service records altered answers.
    pub altered_responses: Vec<NodeId>,
    /// Clients, by index, that record each read with a value no one wrote.
    pub corrupt_reads: Vec<usize>,
}

impl Case {
    /// The client sessions it runs, every client's window; `None` past
    /// `usize::MAX`.
    #[must_use]
    pub fn sessions(&self) -> Option<usize> {
        self.clients.checked_mul(self.window.max(1))
    }
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
            standby: 0,
            lease: None,
            lease_margin: 0,
            feed_faults: Vec::new(),
            stay_on_primary: Vec::new(),
            limits: None,
            window: 1,
            converged: false,
            notes: Vec::new(),
            behind: None,
            compaction: None,
            handover: None,
            retried: false,
            #[cfg(feature = "test-hooks")]
            faults: Faults::default(),
        }
    }
}

/// How far the leaders' commit was past `follower`'s own at the first
/// heal: the highest commit a leader observed before it, less the
/// follower's highest commit before it; `None` without a heal, or with the
/// follower ahead of the leaders, neither of which is a gap.
fn gap_at_heal(observations: &[Observation], follower: NodeId) -> Option<u64> {
    let heal = observations
        .iter()
        .position(|observation| matches!(observation, Observation::Healed))?;
    let before = observations.get(..heal).unwrap_or_default();
    let highest = |wanted: &dyn Fn(NodeId, bool) -> bool| {
        before
            .iter()
            .filter_map(|observation| match observation {
                Observation::Commit {
                    node,
                    leader,
                    index,
                    ..
                } if wanted(*node, *leader) => Some(*index),
                _ => None,
            })
            .max()
            .unwrap_or(0)
    };
    let leaders = highest(&|_, leader| leader);
    let own = highest(&|node, _| node == follower);
    leaders.checked_sub(own)
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
    /// Whether a standby was promoted: the states are the standby's.
    pub promoted: bool,
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
    /// What the case must show did not happen: `"handover"`
    /// ([`Case::handover`]) or `"retry"` ([`Case::retried`]).
    NotShown(&'static str),
    /// The cut-off follower was not as far behind at the heal as the case
    /// requires ([`Case::behind`]).
    NotBehind {
        /// The entries required.
        required: u64,
        /// The entries the leaders' commits were past the follower's.
        reached: u64,
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
    /// The case declares limits its core does not take: what it would
    /// show is not demonstrated for that core, never passed.
    Unsupported(Unsupported),
    /// The case's entries do not fit one duty's log-read budget, so no
    /// core could ever read them back (karyos#899 review).
    Unreadable {
        /// Log bytes one of its entries spans.
        entry: u64,
        /// [`Limits::log_read_bytes`].
        budget: u64,
    },
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
    if let Some(limits) = case.limits {
        // The largest entry the case writes: a client's append, framed.
        let command = super::node::Command {
            client: NodeId::MAX,
            sequence: u64::MAX,
            op: Op::Append(vec![0; case.payload]),
        };
        let entry = u64::try_from(command.encode().len())
            .ok()
            .and_then(|bytes| bytes.checked_add(karyos_cluster::log::FRAME_HEADER_LEN))
            .ok_or(RunError::Count)?;
        if entry > limits.log_read_bytes {
            return Err(RunError::Unreadable {
                entry,
                budget: limits.log_read_bytes,
            });
        }
    }
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
    let standby_end = u32::try_from(case.standby)
        .ok()
        .and_then(|standby| spares.checked_add(standby))
        .ok_or(RunError::Count)?;
    let primary: Vec<NodeId> = (0..spares).collect();
    let standby: Vec<NodeId> = (spares..standby_end).collect();
    let everyone: Vec<NodeId> = (0..standby_end).collect();
    let lease = case
        .lease
        .map(|duration| Rc::new(RefCell::new(ExternalLease::new(duration))));
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
        let in_standby = standby.contains(&id);
        let group = if in_standby { &standby } else { &peers };
        let survives = per_server(case.survives, id);
        let mut server = match case.limits {
            None => ServerNode::<C>::new(
                id,
                group.clone(),
                disk,
                survives,
                geometry,
                Rc::clone(&recorder),
            )
            .map_err(RunError::Log)?,
            Some(limits) => ServerNode::<C>::with_limits(
                id,
                group.clone(),
                (disk, survives),
                geometry,
                Rc::clone(&recorder),
                limits,
            )
            .map_err(|error| match error {
                ServerError::Log(error) => RunError::Log(error),
                ServerError::Unsupported(unsupported) => RunError::Unsupported(unsupported),
            })?,
        };
        if in_standby {
            server = server.as_standby(primary.clone());
        } else {
            if !standby.is_empty() {
                server = server.with_feed(standby.clone(), &case.feed_faults);
            }
            if let Some(lease) = &lease {
                server = server.with_lease(Rc::clone(lease));
            }
        }
        if let Some(compaction) = case.compaction {
            server = server.with_compaction(compaction);
        }
        #[cfg(feature = "test-hooks")]
        {
            let drive_fault = case
                .faults
                .drive
                .iter()
                .find(|(node, _)| *node == id)
                .map_or(super::core::DriveFault::None, |(_, fault)| *fault);
            let alters = case.faults.altered_responses.contains(&id);
            if drive_fault != super::core::DriveFault::None || alters {
                server = server.with_faults(drive_fault, alters);
            }
        }
        let index = usize::try_from(id).map_err(|_| RunError::Count)?;
        let drift = case.drift_ppm.get(index).copied().unwrap_or(0);
        let _ = sim
            .add_node(Member::Server(Box::new(server)), 0, drift)
            .map_err(RunError::Sim)?;
        // A spare waits down, its log empty, for its join.
        if id >= servers && !in_standby {
            sim.crash(id).map_err(RunError::Node)?;
        }
    }
    let leader = peers.first().copied().ok_or(RunError::Count)?;
    let mut clients = Vec::new();
    for index in 0..case.sessions().ok_or(RunError::Count)? {
        let id = u32::try_from(index)
            .ok()
            .and_then(|index| standby_end.checked_add(index))
            .ok_or(RunError::Count)?;
        let mut client = ClientNode::new(id, leader, script(case, index), Rc::clone(&recorder))
            .with_retry_after(case.retry_after);
        #[cfg(feature = "test-hooks")]
        if case.faults.corrupt_reads.contains(&index) {
            client = client.corrupting_reads();
        }
        let added = sim
            .add_node(Member::Client(client), 0, 0)
            .map_err(RunError::Sim)?;
        clients.push(added);
    }
    // The operator, a client with no script, only where a change is
    // scheduled, so a phase 4 case runs the nodes it always did.
    let changes = case.schedule.iter().any(|(_, action)| {
        matches!(
            action,
            Action::Change(_) | Action::Promote(_) | Action::TransferLeadership(_)
        )
    });
    let mut operator = None;
    if changes {
        let id = case
            .sessions()
            .and_then(|count| u32::try_from(count).ok())
            .and_then(|count| standby_end.checked_add(count))
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
    let mut joined: Vec<NodeId> = peers.iter().chain(&standby).copied().collect();
    let mut stopped = false;
    let mut promoted = false;
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
            Action::Heal => {
                sim.net_mut().heal();
                recorder.borrow_mut().observations.push(Observation::Healed);
            }
            Action::Join(id) => {
                sim.restart(id).map_err(RunError::Node)?;
                if !joined.contains(&id) {
                    joined.push(id);
                }
            }
            Action::CutArbiter => {
                if let Some(lease) = &lease {
                    lease.borrow_mut().renewing = false;
                }
            }
            Action::OperatorStop => {
                for &id in &primary {
                    match sim.crash(id) {
                        Ok(()) | Err(NodeError::AlreadyDown(_)) => {}
                        Err(error) => return Err(RunError::Node(error)),
                    }
                }
                stopped = true;
            }
            Action::Promote(fencing) => {
                // Present: this case schedules a promotion.
                let operator = operator.ok_or(RunError::Count)?;
                let fenced = match fencing {
                    Fencing::OperatorStop => stopped,
                    Fencing::Lease => lease.as_ref().is_some_and(|lease| {
                        lease.borrow().expired_at(sim.now(), case.lease_margin)
                    }),
                };
                let observation = if fenced {
                    let lease_end = match fencing {
                        Fencing::Lease => lease.as_ref().and_then(|lease| lease.borrow().end()),
                        Fencing::OperatorStop => None,
                    };
                    Observation::Fenced { fencing, lease_end }
                } else {
                    Observation::PromotionRefused { fencing }
                };
                recorder.borrow_mut().observations.push(observation);
                if fenced {
                    promoted = true;
                    let unknown: Vec<(NodeId, u64)> = clients
                        .iter()
                        .filter_map(|id| {
                            let open = sim.node(*id).and_then(Member::client)?.open()?;
                            Some((*id, open))
                        })
                        .collect();
                    for &id in &standby {
                        let _ = sim
                            .send(
                                operator,
                                id,
                                Wire::Promote {
                                    unknown: unknown.clone(),
                                },
                            )
                            .map_err(RunError::Sim)?;
                    }
                    let server = standby.first().copied().ok_or(RunError::Count)?;
                    for (index, &client) in clients.iter().enumerate() {
                        if !case.stay_on_primary.contains(&index) {
                            let _ = sim
                                .send(operator, client, Wire::Redirect { server })
                                .map_err(RunError::Sim)?;
                        }
                    }
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
            Action::TransferLeadership(to) => {
                let operator = operator.ok_or(RunError::Count)?;
                for &id in &everyone {
                    if sim
                        .node(id)
                        .and_then(Member::server)
                        .is_some_and(ServerNode::is_up)
                    {
                        let _ = sim
                            .send(operator, id, Wire::Transfer(to))
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
    // The group that serves at the end: the standby once promoted.
    let acting: Vec<NodeId> = joined
        .iter()
        .copied()
        .filter(|id| standby.contains(id) == promoted)
        .collect();
    let up: Vec<(NodeId, &ServerNode<C>)> = acting
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
    // A core that lacks a capability the case needs: not demonstrated.
    if recorded
        .observations
        .iter()
        .any(|observation| matches!(observation, Observation::Unsupported { .. }))
    {
        return Err(RunError::Unsupported(Unsupported));
    }
    Ok(Outcome {
        safety: safety(case, &recorded, &primary, &standby),
        liveness,
        observations: recorded.observations.clone(),
        history: recorded.history.clone(),
        trace: sim.trace().to_vec(),
        digest: sim.digest(),
        states,
        deduplicated,
        promoted,
    })
}

/// The safety checks of a run: every check over all of it, or with a
/// standby, each group's on its own observations, the history across the
/// promotion, and the standby's checks.
fn safety(
    case: &Case,
    recorded: &Recorder,
    primary: &[NodeId],
    standby: &[NodeId],
) -> Result<(), Violation> {
    let observations = &recorded.observations;
    if standby.is_empty() {
        check::all(observations, &recorded.history, case.servers)?;
    } else {
        check::group(&check::of_servers(observations, primary), case.servers)?;
        check::group(&check::of_servers(observations, standby), case.standby)?;
        // The standby's checks name a violation C3 would only see as a
        // history it cannot linearize, or one it gives up on.
        check::standby(observations, standby)?;
        check::linearizable(&check::across_promotion(&recorded.history, observations))?;
    }
    check::membership(observations, case.promotion_lag)
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
    if let Some(to) = case.handover {
        let observations = &outcome.observations;
        // The target took the handover, then committed as leader: from
        // there on it leads.
        let leads = observations
            .iter()
            .position(|observation| {
                matches!(
                    observation,
                    Observation::Transfer { to: target, result: Ok(()), .. } if *target == to
                )
            })
            .and_then(|taken| {
                observations
                    .iter()
                    .skip(taken)
                    .position(|observation| {
                        matches!(
                            observation,
                            Observation::Commit { node, leader: true, .. } if *node == to
                        )
                    })
                    .and_then(|led| taken.checked_add(led))
            });
        let Some(leads) = leads else {
            return Err(Failed::NotShown("handover"));
        };
        // One request redirected to the target by another server, then
        // answered from deduplication by the target, once it leads.
        if case.retried {
            let retried = observations
                .iter()
                .enumerate()
                .skip(leads)
                .any(|(at, observation)| {
                    let Observation::Deduplicated {
                        node,
                        client,
                        sequence,
                    } = observation
                    else {
                        return false;
                    };
                    *node == to
                        && observations.iter().take(at).any(|earlier| {
                            matches!(
                                earlier,
                                Observation::Redirected {
                                    node: from,
                                    client: c,
                                    sequence: s,
                                    to: target,
                                } if *from != to && c == client && s == sequence && *target == to
                            )
                        })
                });
            if !retried {
                return Err(Failed::NotShown("retry"));
            }
        }
    } else if case.retried {
        return Err(Failed::NotShown("retry"));
    }
    if let Some((follower, required)) = case.behind {
        match gap_at_heal(&outcome.observations, follower) {
            Some(reached) if reached >= required => {}
            reached => {
                return Err(Failed::NotBehind {
                    required,
                    reached: reached.unwrap_or_default(),
                });
            }
        }
    }
    if case.converged
        && outcome
            .states
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if (a.1, a.2) != (b.1, b.2)))
    {
        return Err(Failed::Diverged(outcome.states.clone()));
    }
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
    // Across a promotion, the old generation's unknown outcomes may or
    // may not be in the state: the history's checks stand for it.
    if gap.is_none()
        && !outcome.promoted
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
    let violation = match lin::check(&ServiceModel::default(), history, check::LIMIT) {
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
