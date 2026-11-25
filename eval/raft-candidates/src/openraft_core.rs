// SPDX-License-Identifier: Apache-2.0

//! `openraft` 0.10.0-alpha.37 behind [`ConsensusCore`], on the bounded,
//! manually pumped [`Executor`] (plan issue 076, karyos#690; owner item
//! 33).
//!
//! OpenRaft is an actor: its core, replication and state machine run as
//! tasks that talk through channels. Here every one of them is a task of
//! the node's own [`Executor`], which runs only when the harness calls the
//! core: each [`ConsensusCore`] call does its work (a tick moves the
//! virtual clock, a message is handed to its RPC handler, a proposal to
//! `client_write_ff`) and pumps the executor, at most
//! [`PUMP_BUDGET`] polls. No Tokio, no thread, no wall clock: OpenRaft
//! runs with default features off.
//!
//! **Mapping to the harness** (`crates/karyos-sim/src/harness/core.rs`,
//! the openraft paragraph):
//!
//! - `RaftLogStorage::append(entries, callback)` writes to the in-memory
//!   view OpenRaft reads, queues the entries for the next [`Ready`], and
//!   keeps the callback; [`ConsensusCore::advance`] fires it once
//!   [`drive`](karyos_sim::harness::core::drive) made them durable.
//!   `IOFlushed` is never fired at a write's completion.
//! - `save_vote` puts the vote in the next [`Ready`]'s hard state and
//!   returns only after `advance`: a vote reply waits for the vote to be
//!   durable.
//! - `truncate_after` removes the entries from the view at once and, for
//!   those already handed to the log, asks for a truncation in the next
//!   [`Ready`] before its entries.
//! - The state machine's `apply` hands each entry to the next [`Ready`]'s
//!   `committed`.
//! - The network sends each RPC as a [`Message::Request`] and waits for
//!   its [`Message::Response`]; a lost one is OpenRaft's own RPC timeout.
//!   The pre-vote RPC is a real one: the peer runs OpenRaft's pre-vote
//!   handler, never the trait's default, which synthesises a grant.
//!
//! **Indices.** OpenRaft's log starts at 0 (its initialisation writes the
//! membership there); C4's at 1: harness index = OpenRaft index + 1.
//! Terms are OpenRaft's standard leader ids (one leader per term), so an
//! entry's committed leader id is its term.
//!
//! **Declared limits** (W2, karyos#679): `recover_with` takes them.
//! `max_payload_entries` is the in-flight entry cap, and OpenRaft's
//! sequential append stream keeps one append in flight per follower while
//! it is answered (not strict across an RPC timeout, after which the next
//! append can leave with the first unacknowledged; karyos#975); the
//! queue and the in-flight bytes are refused in `propose`
//! ([`crate::raft_rs::refuse_past`], the byte cap kept by entry size); an
//! entry cap outside `1..=MAX_IN_FLIGHT_ENTRIES` is `Unsupported`.
//! OpenRaft reads the adapter's in-memory view; under declared limits an
//! outgoing append's logged entries are read back through the harness's
//! metered log before it leaves, and an append the duty's budget cannot
//! cover is held back as lost (karyos#1040).
//!
//! **Not taken here:** snapshots and compaction (W5, karyos#679): they
//! answer `Unsupported`, which the harness reports as not demonstrated.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use futures_channel::oneshot;
use futures_util::StreamExt;
use karyos_cluster::{Entry, HardState};
use karyos_sim::harness::core::{
    ConsensusCore, Limits, LogView, NotLeader, Persisted, Ready, ReadyBuf, Refused,
    TransferRefused, Unsupported,
};
use karyos_sim::harness::reference::{decode_configuration, encode_configuration};
use karyos_sim::net::NodeId;
use openraft::error::{NetworkError, RPCError, StreamingError, Unreachable};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, TransferLeaderRequest,
    TransferLeaderResponse, VoteRequest, VoteResponse,
};
use openraft::storage::{EntryResponder, IOFlushed, RaftLogStorage, RaftStateMachine};
use openraft::{
    EmptyNode, EntryPayload, LogState, Membership, OptionalSend, Raft, RaftLogReader,
    RaftNetworkFactory, RaftNetworkV2, RaftSnapshotBuilder, ServerState, SnapshotPolicy,
    StoredMembership,
};
use openraft_rt::WatchReceiver;

use crate::executor::{Executor, SimRuntime};
use crate::variant::Variant;
use openraft_rt::AsyncRuntime as _;

/// The build of `openraft` this adapter runs: the admitted release,
/// unpatched.
pub const VARIANT: Variant = Variant::Baseline;

/// Polls one core call pumps at most: the work budget of a call.
pub const PUMP_BUDGET: usize = 4096;

/// Milliseconds (harness ticks) between heartbeats: one harness step is
/// one OpenRaft millisecond (C5 v2 manifest, Timing).
pub const HEARTBEAT_MS: u64 = 5;

/// The election timeout's range, in milliseconds (harness ticks),
/// `[15, 30)` (C5 v2 manifest, Timing). OpenRaft draws it again at every
/// reset with `RT::thread_rng()`, which this adapter's runtime seeds from
/// the node's executor (`executor::SimRuntime::thread_rng`), so the draw
/// is the manifest's, from a seeded source.
pub const ELECTION_MS: (u64, u64) = (15, 30);

/// The retry delays after a failed RPC, on the harness's clock. OpenRaft's
/// default, 200 ms then up to 1 s, is 40 heartbeats here, which on a lossy
/// link stalls a follower for most of a run; raft-rs retries at its next
/// heartbeat. The adapter scales it to its own heartbeat instead, from
/// one heartbeat up to the longest election timeout: an adapter setting,
/// the same for every workload, not a workload parameter.
pub const BACKOFF: &str = "5ms, 10ms, 20ms ..30ms";

/// The shortest an RPC waits for its answer: OpenRaft's replication asks
/// for its heartbeat interval, 5 ticks, which is shorter than a reply's
/// round trip on the workloads' slower links; this is the election
/// timeout's upper bound instead. An adapter setting, the same for every
/// workload.
pub const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(ELECTION_MS.1);

/// Entries per append without declared limits.
pub const DEFAULT_PAYLOAD_ENTRIES: u64 = 300;

/// A client command: the harness's encoded bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command(pub Vec<u8>);

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "command of {} bytes", self.0.len())
    }
}

openraft::declare_raft_types!(
    /// The evaluation's OpenRaft types: standard leader ids, the
    /// harness's commands, and the simulator's runtime.
    pub TypeConfig:
        D = Command,
        R = (),
        NodeId = u64,
        Node = EmptyNode,
        Term = u64,
        LeaderId = openraft::impls::leader_id_std::LeaderId<u64, u64>,
        AsyncRuntime = SimRuntime,
);

type C = TypeConfig;
type OEntry = <C as openraft::RaftTypeConfig>::Entry;
type OVote = <C as openraft::RaftTypeConfig>::Vote;
type Clid = <<C as openraft::RaftTypeConfig>::LeaderId as openraft::vote::RaftLeaderId>::Committed;
type OLogId = openraft::LogId<Clid>;
// openraft's own aliases need its `type-alias` feature, not admitted.
type SnapshotOf<SD> = openraft::storage::Snapshot<Clid, u64, EmptyNode, SD>;
type SnapshotMetaOf = openraft::storage::SnapshotMeta<Clid, u64, EmptyNode>;
type StoredMembershipOf = StoredMembership<Clid, u64, EmptyNode>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An OpenRaft entry as the harness logs it.
fn to_harness(entry: &OEntry) -> Option<Entry> {
    let payload = match &entry.payload {
        EntryPayload::Blank => Vec::new(),
        EntryPayload::Normal(command) => command.0.clone(),
        EntryPayload::Membership(membership) => {
            let voters: Vec<NodeId> = membership
                .voter_ids()
                .filter_map(|id| NodeId::try_from(id).ok())
                .collect();
            encode_configuration(&voters, &[])
        }
    };
    Some(Entry {
        index: entry.log_id.index.checked_add(1)?,
        term: entry.log_id.leader_id.term,
        // OpenRaft carries no event time: the entry's is its index's
        // place in the log, which the test service ignores.
        event_time: 0,
        payload,
    })
}

/// [`to_harness`], a normal entry's payload copied into a buffer from
/// `spare` (plan issue 073, karyos#691); a membership entry is encoded anew.
fn to_harness_into(spare: &mut Vec<Entry>, entry: &OEntry) -> Option<Entry> {
    let EntryPayload::Normal(command) = &entry.payload else {
        return to_harness(entry);
    };
    let mut harness = spare.pop().unwrap_or(Entry {
        index: 0,
        term: 0,
        event_time: 0,
        payload: Vec::new(),
    });
    harness.index = entry.log_id.index.checked_add(1)?;
    harness.term = entry.log_id.leader_id.term;
    harness.event_time = 0;
    harness.payload.clear();
    harness.payload.extend_from_slice(&command.0);
    Some(harness)
}

/// A harness entry as OpenRaft holds it.
fn to_openraft(entry: &Entry) -> Option<OEntry> {
    let payload = if entry.payload.is_empty() {
        EntryPayload::Blank
    } else if let Some((voters, _)) = decode_configuration(&entry.payload) {
        let voters: BTreeSet<u64> = voters.into_iter().map(u64::from).collect();
        EntryPayload::Membership(Membership::new_with_defaults(vec![voters], []))
    } else {
        EntryPayload::Normal(Command(entry.payload.clone()))
    };
    Some(OEntry {
        log_id: log_id(entry.term, entry.index.checked_sub(1)?),
        payload,
    })
}

fn log_id(term: u64, index: u64) -> OLogId {
    openraft::LogId::new(Clid::new(term), index)
}

/// The vote kept in C4's `HardState`, never committed: the bit is not
/// stored, and leader restoration is off (`OpenRaftCore::config`).
fn vote_of(state: &HardState) -> Option<OVote> {
    let voted_for = state.voted_for?;
    Some(OVote {
        leader_id: openraft::impls::leader_id_std::LeaderId {
            term: state.current_term,
            voted_for,
        },
        committed: false,
    })
}

fn hard_state_of(vote: &OVote) -> HardState {
    HardState {
        current_term: vote.leader_id.term,
        voted_for: Some(vote.leader_id.voted_for),
        commit: None,
    }
}

/// An RPC between two nodes' OpenRaft.
#[derive(Clone)]
pub enum Request {
    /// Append entries, or a heartbeat.
    Append(Arc<AppendEntriesRequest<C>>),
    /// A vote request.
    Vote(Arc<VoteRequest<C>>),
    /// A pre-vote request: the receiver runs OpenRaft's pre-vote handler.
    PreVote(Arc<VoteRequest<C>>),
    /// A leadership handover.
    TransferLeader(Arc<TransferLeaderRequest<C>>),
}

/// An RPC's answer.
#[derive(Clone)]
pub enum Response {
    /// To [`Request::Append`].
    Append(Arc<AppendEntriesResponse<C>>),
    /// To [`Request::Vote`] or [`Request::PreVote`].
    Vote(Arc<VoteResponse<C>>),
    /// To [`Request::TransferLeader`].
    TransferLeader(Arc<TransferLeaderResponse<C>>),
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Append(_) => "Append",
            Self::Vote(_) => "Vote",
            Self::PreVote(_) => "PreVote",
            Self::TransferLeader(_) => "TransferLeader",
        })
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Append(_) => "Append",
            Self::Vote(_) => "Vote",
            Self::TransferLeader(_) => "TransferLeader",
        })
    }
}

/// Two RPCs are equal when their bytes are ([`crate::openraft_wire`]): the
/// same comparison in the simulator and between real processes. Two that
/// cannot be encoded are equal only when they are the same message.
impl PartialEq for Request {
    fn eq(&self, other: &Self) -> bool {
        match (
            crate::openraft_wire::request_bytes(self),
            crate::openraft_wire::request_bytes(other),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => match (self, other) {
                (Self::Append(a), Self::Append(b)) => Arc::ptr_eq(a, b),
                (Self::Vote(a), Self::Vote(b)) | (Self::PreVote(a), Self::PreVote(b)) => {
                    Arc::ptr_eq(a, b)
                }
                (Self::TransferLeader(a), Self::TransferLeader(b)) => Arc::ptr_eq(a, b),
                _ => false,
            },
        }
    }
}

/// Two answers are equal when their bytes are ([`crate::openraft_wire`]),
/// as for [`Request`]: an answer equals its own decoded wire form and any
/// answer built with the same content (karyos#959 review). Every answer
/// encodes.
impl PartialEq for Response {
    fn eq(&self, other: &Self) -> bool {
        crate::openraft_wire::response_bytes(self) == crate::openraft_wire::response_bytes(other)
    }
}

/// The adapter's messages between nodes.
#[derive(Clone, PartialEq)]
pub enum Message {
    /// An RPC, numbered by its sender.
    Request {
        /// The sender's number for it, unique within its incarnation.
        id: u64,
        /// The sender's incarnation: drawn at each recovery, so a number
        /// reused after a restart names a different request.
        incarnation: u64,
        /// The RPC.
        request: Request,
    },
    /// An RPC's answer; `None` when the receiver's OpenRaft failed it.
    Response {
        /// The request's number.
        id: u64,
        /// The request's incarnation, echoed.
        incarnation: u64,
        /// The request answered, echoed: the sender accepts the answer
        /// only for the very request it sent under `id`, to that peer
        /// (karyos#959 review).
        request: Request,
        /// The answer.
        response: Option<Response>,
    },
}

/// The incarnation is left out: it is drawn from the wall clock, so the
/// trace stays a function of the harness's seed. It only decides whether
/// a stale answer is dropped, which any two distinct draws decide alike.
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request { id, request, .. } => f
                .debug_struct("Request")
                .field("id", id)
                .field("request", request)
                .finish_non_exhaustive(),
            Self::Response {
                id,
                request,
                response,
                ..
            } => f
                .debug_struct("Response")
                .field("id", id)
                .field("request", request)
                .field("response", response)
                .finish_non_exhaustive(),
        }
    }
}

/// A fresh incarnation: distinct for every recovery in this process (a
/// counter) and, across processes, independent of any clock (karyos#959
/// review: a wall-clock seed repeats after a rollback or a VM restore).
/// Each process starts its counter at a 64-bit nonce from the operating
/// system's entropy: std's `RandomState` keys SipHash from it, with no
/// dependency beyond std. Two processes of a node collide only if their
/// counter ranges overlap, about `n·m / 2^64` for `n` and `m` recoveries,
/// negligible for this evaluation; nothing is persisted, so the
/// simulator's runs stay a function of their seed (the incarnation is not
/// in the trace).
#[must_use]
pub fn next_incarnation() -> u64 {
    static NEXT: OnceLock<AtomicU64> = OnceLock::new();
    NEXT.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        AtomicU64::new(hasher.finish())
    })
    .fetch_add(1, Ordering::Relaxed)
}

/// What OpenRaft's storage, network and state machine share with the
/// adapter: the in-memory view and what waits for the next [`Ready`].
#[derive(Default)]
struct Io {
    /// The log as written, by OpenRaft index: what OpenRaft reads.
    log: BTreeMap<u64, OEntry>,
    vote: Option<OVote>,
    /// For the next Ready.
    truncate_from: Option<u64>,
    entries: Vec<Entry>,
    hard_state: Option<HardState>,
    callbacks: Vec<IOFlushed<C>>,
    vote_waiters: Vec<oneshot::Sender<()>>,
    committed: Vec<Entry>,
    /// Entries the node is done with, their payload buffers kept for the
    /// next conversion (plan issue 073, karyos#691).
    spare: Vec<Entry>,
    outbox: Vec<(NodeId, Message)>,
    /// Handed in a Ready, released at its advance.
    flushing: Vec<IOFlushed<C>>,
    voting: Vec<oneshot::Sender<()>>,
    /// The last harness index handed to the log.
    handed: Option<u64>,
    /// RPCs waiting for their answer, by number: the peer, the request
    /// and where its answer goes.
    waiting: BTreeMap<u64, Waiting>,
    next_rpc: u64,
    /// This recovery's incarnation, sent with every RPC.
    incarnation: u64,
    applied: Option<OLogId>,
    membership: StoredMembershipOf,
}

/// An RPC waiting for its answer.
struct Waiting {
    target: NodeId,
    request: Request,
    answer: oneshot::Sender<Option<Response>>,
}

/// Whether an answer from `from`, for `incarnation`, echoing `request`,
/// answers `waiting` (found under the answer's number). Numbers restart
/// with each incarnation of a node, so the answer must carry this
/// incarnation: an answer to an earlier one is dropped even when its
/// request is byte-identical to the one now waiting. The peer and the
/// echoed request must match too.
fn answers(
    waiting: &Waiting,
    current: u64,
    from: NodeId,
    incarnation: u64,
    request: &Request,
) -> bool {
    incarnation == current && waiting.target == from && waiting.request == *request
}

type Shared = Arc<Mutex<Io>>;

/// OpenRaft's log store and reader over the adapter's shared view.
#[derive(Clone)]
pub struct LogStore {
    io: Shared,
}

impl RaftLogReader<C> for LogStore {
    async fn try_get_log_entries<RB>(&mut self, range: RB) -> Result<Vec<OEntry>, io::Error>
    where
        RB: std::ops::RangeBounds<u64> + Clone + fmt::Debug + OptionalSend,
    {
        Ok(lock(&self.io)
            .log
            .range(range)
            .map(|(_, entry)| entry.clone())
            .collect())
    }

    async fn read_vote(&mut self) -> Result<Option<OVote>, io::Error> {
        Ok(lock(&self.io).vote)
    }
}

impl RaftLogStorage<C> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<C>, io::Error> {
        let last = lock(&self.io)
            .log
            .last_key_value()
            .map(|(_, entry)| entry.log_id);
        Ok(LogState {
            last_purged_log_id: None,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &OVote) -> Result<(), io::Error> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut io = lock(&self.io);
            io.vote = Some(*vote);
            io.hard_state = Some(hard_state_of(vote));
            io.vote_waiters.push(sender);
        }
        // Durable once the harness's drive saved it and advanced the core.
        receiver
            .await
            .map_err(|_| io::Error::other("the vote's persistence was dropped"))
    }

    async fn append<I>(&mut self, entries: I, callback: IOFlushed<C>) -> Result<(), io::Error>
    where
        I: IntoIterator<Item = OEntry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut io = lock(&self.io);
        for entry in entries {
            let harness = to_harness_into(&mut io.spare, &entry)
                .ok_or_else(|| io::Error::other("index overflow"))?;
            io.entries.push(harness);
            let _ = io.log.insert(entry.log_id.index, entry);
        }
        io.callbacks.push(callback);
        Ok(())
    }

    async fn truncate_after(&mut self, last: Option<OLogId>) -> Result<(), io::Error> {
        // OpenRaft index of the first entry removed.
        let from = match last {
            Some(last) => last
                .index
                .checked_add(1)
                .ok_or_else(|| io::Error::other("index overflow"))?,
            None => 0,
        };
        let mut io = lock(&self.io);
        let _ = io.log.split_off(&from);
        let harness_from = from
            .checked_add(1)
            .ok_or_else(|| io::Error::other("index overflow"))?;
        io.entries.retain(|entry| entry.index < harness_from);
        if io.handed.is_some_and(|handed| handed >= harness_from) {
            io.truncate_from = Some(
                io.truncate_from
                    .map_or(harness_from, |at| at.min(harness_from)),
            );
            io.handed = harness_from.checked_sub(1).filter(|last| *last > 0);
        }
        Ok(())
    }

    async fn purge(&mut self, _upto: OLogId) -> Result<(), io::Error> {
        // No compaction runs without snapshots (karyos#679): entries stay.
        Ok(())
    }
}

/// OpenRaft's state machine: it hands what it applies to the harness.
#[derive(Clone)]
pub struct StateMachine {
    io: Shared,
}

/// Snapshots are not taken yet (karyos#679).
#[derive(Clone)]
pub struct NoSnapshots;

fn no_snapshots() -> io::Error {
    io::Error::other("snapshots are not supported by the adapter yet (karyos#679)")
}

impl RaftSnapshotBuilder<C> for NoSnapshots {
    type SnapshotData = ();

    async fn build_snapshot(&mut self) -> Result<SnapshotOf<()>, io::Error> {
        Err(no_snapshots())
    }
}

impl RaftStateMachine<C> for StateMachine {
    type SnapshotData = ();
    type SnapshotBuilder = NoSnapshots;

    async fn applied_state(&mut self) -> Result<(Option<OLogId>, StoredMembershipOf), io::Error> {
        let io = lock(&self.io);
        Ok((io.applied, io.membership.clone()))
    }

    async fn apply<Strm>(&mut self, mut entries: Strm) -> Result<(), io::Error>
    where
        Strm: futures_util::Stream<Item = Result<EntryResponder<C>, io::Error>>
            + Unpin
            + OptionalSend,
    {
        while let Some(item) = entries.next().await {
            let (entry, responder) = item?;
            {
                let mut io = lock(&self.io);
                io.applied = Some(entry.log_id);
                if let EntryPayload::Membership(membership) = &entry.payload {
                    io.membership = StoredMembership::new(Some(entry.log_id), membership.clone());
                }
                let harness = to_harness_into(&mut io.spare, &entry)
                    .ok_or_else(|| io::Error::other("index overflow"))?;
                io.committed.push(harness);
            }
            if let Some(responder) = responder {
                responder.send(());
            }
        }
        Ok(())
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        NoSnapshots
    }

    async fn install_snapshot(
        &mut self,
        _meta: &SnapshotMetaOf,
        _snapshot: (),
    ) -> Result<(), io::Error> {
        Err(no_snapshots())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<SnapshotOf<()>>, io::Error> {
        Ok(None)
    }
}

/// OpenRaft's network: RPCs as harness messages.
#[derive(Clone)]
pub struct Network {
    io: Shared,
}

/// One peer's RPC client.
#[derive(Clone)]
pub struct Client {
    io: Shared,
    target: NodeId,
}

impl RaftNetworkFactory<C> for Network {
    type Network = Client;

    async fn new_client(&mut self, target: u64, _node: &EmptyNode) -> Client {
        Client {
            io: Arc::clone(&self.io),
            // An id OpenRaft knows is one the harness gave.
            target: NodeId::try_from(target).unwrap_or(NodeId::MAX),
        }
    }
}

fn unreachable(what: &str) -> RPCError<C> {
    RPCError::Unreachable(Unreachable::new(&io::Error::other(what.to_owned())))
}

impl Client {
    /// Sends `request` and waits for its answer, at most the option's
    /// hard TTL or [`RPC_TIMEOUT`], the longer, on the executor's clock: a
    /// lost request or answer is a timeout, as on a real network, never a
    /// wait forever (OpenRaft's sequential append stream does not time an
    /// RPC out itself).
    async fn call(&self, request: Request, option: &RPCOption) -> Result<Response, RPCError<C>> {
        let (sender, receiver) = oneshot::channel();
        {
            let mut io = lock(&self.io);
            // Answers that will never be waited for again.
            io.waiting
                .retain(|_, waiting| !waiting.answer.is_canceled());
            let id = io.next_rpc;
            io.next_rpc = id.saturating_add(1);
            let _ = io.waiting.insert(
                id,
                Waiting {
                    target: self.target,
                    request: request.clone(),
                    answer: sender,
                },
            );
            let incarnation = io.incarnation;
            io.outbox.push((
                self.target,
                Message::Request {
                    id,
                    incarnation,
                    request,
                },
            ));
        }
        match SimRuntime::timeout(option.hard_ttl().max(RPC_TIMEOUT), receiver).await {
            Ok(Ok(Some(response))) => Ok(response),
            Ok(Ok(None)) => Err(unreachable("the peer failed the request")),
            Ok(Err(_)) => Err(unreachable("the request was dropped")),
            Err(_) => Err(unreachable("the request timed out")),
        }
    }
}

impl RaftNetworkV2<C> for Client {
    type SnapshotData = ();

    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<C>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<C>, RPCError<C>> {
        match self.call(Request::Append(Arc::new(rpc)), &option).await? {
            Response::Append(response) => Ok((*response).clone()),
            _ => Err(unreachable("a wrong answer")),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<C>,
        option: RPCOption,
    ) -> Result<VoteResponse<C>, RPCError<C>> {
        match self.call(Request::Vote(Arc::new(rpc)), &option).await? {
            Response::Vote(response) => Ok((*response).clone()),
            _ => Err(unreachable("a wrong answer")),
        }
    }

    async fn pre_vote(
        &mut self,
        rpc: VoteRequest<C>,
        option: RPCOption,
    ) -> Result<VoteResponse<C>, RPCError<C>> {
        match self.call(Request::PreVote(Arc::new(rpc)), &option).await? {
            Response::Vote(response) => Ok((*response).clone()),
            _ => Err(unreachable("a wrong answer")),
        }
    }

    async fn full_snapshot(
        &mut self,
        _vote: OVote,
        _snapshot: SnapshotOf<()>,
        _cancel: impl std::future::Future<Output = openraft::error::ReplicationClosed>
        + OptionalSend
        + 'static,
        _option: RPCOption,
    ) -> Result<SnapshotResponse<C>, StreamingError<C>> {
        Err(StreamingError::Network(NetworkError::new(&no_snapshots())))
    }

    async fn transfer_leader(
        &mut self,
        req: TransferLeaderRequest<C>,
        option: RPCOption,
    ) -> Result<TransferLeaderResponse<C>, RPCError<C>> {
        match self
            .call(Request::TransferLeader(Arc::new(req)), &option)
            .await?
        {
            Response::TransferLeader(response) => Ok((*response).clone()),
            _ => Err(unreachable("a wrong answer")),
        }
    }
}

type Handle = Raft<C, StateMachine>;

/// `openraft` 0.10.0-alpha.37 behind [`ConsensusCore`], pre-vote on when
/// `PRE_VOTE` (see the module).
pub struct OpenRaftCore<const PRE_VOTE: bool, const BATCH: u64 = 0> {
    executor: Executor,
    /// `None` when OpenRaft refused to start: the node stays silent.
    raft: Option<Handle>,
    io: Shared,
    last_tick: Option<u64>,
    /// A Ready is out and not advanced.
    out: bool,
    /// Calls that ended with tasks still woken: the work budget was hit.
    overruns: u64,
    /// The declared limits (W2), when started with them.
    limits: Option<Limits>,
    /// The kept buffers of the metered read back
    /// ([`crate::raft_rs::read_back`]).
    reads: crate::raft_rs::ReadBack,
}

/// `openraft` with pre-vote on: the evaluated core.
pub type OpenRaft = OpenRaftCore<true>;

/// `openraft` with pre-vote off: only a negative control.
pub type OpenRaftNoPreVote = OpenRaftCore<false>;

/// [`OpenRaft`] with a batch entry cap of 16 (`max_payload_entries`), W1's
/// primary batch limit (quantstratum-docs:
/// karyos/evaluations/c5-raft-comparison-v1.md, W1; karyos#691).
pub type OpenRaftBatch16 = OpenRaftCore<true, 16>;

/// The entries an outgoing message appends and their payload bytes, for a
/// test that observes appends (karyos#691); `None` for any other message.
#[must_use]
pub fn append_shape(message: &Message) -> Option<(usize, u64)> {
    let Message::Request {
        request: Request::Append(rpc),
        ..
    } = message
    else {
        return None;
    };
    let bytes = rpc
        .entries
        .iter()
        .filter_map(to_harness)
        .fold(0u64, |sum, entry| {
            sum.saturating_add(u64::try_from(entry.payload.len()).unwrap_or(u64::MAX))
        });
    Some((rpc.entries.len(), bytes))
}

/// An append's leader term and its entries as (harness index, payload
/// bytes), read from the message itself for an oracle that never trusts
/// the adapter's counters (C5 version 2's W2 byte case; karyos#691);
/// `None` for any other message.
#[must_use]
pub fn append_entries(message: &Message) -> Option<(u64, Vec<(u64, u64)>)> {
    let Message::Request {
        request: Request::Append(rpc),
        ..
    } = message
    else {
        return None;
    };
    let entries = rpc
        .entries
        .iter()
        .filter_map(|entry| {
            let harness = to_harness(entry)?;
            let bytes = match &entry.payload {
                EntryPayload::Normal(command) => command.0.len(),
                _ => 0,
            };
            Some((harness.index, u64::try_from(bytes).unwrap_or(u64::MAX)))
        })
        .collect();
    Some((rpc.vote.leader_id.term, entries))
}

/// The leader term and harness index an append's answer acknowledges:
/// the echoed request's last entry (or, for an empty one, its previous
/// entry) on `Success`, the matched entry on `PartialSuccess`; `None` for
/// any other message or answer, and for an empty append with no previous
/// entry, which acknowledges nothing.
#[must_use]
pub fn append_ack(message: &Message) -> Option<(u64, u64)> {
    let Message::Response {
        request: Request::Append(rpc),
        response: Some(Response::Append(response)),
        ..
    } = message
    else {
        return None;
    };
    let matched = match &**response {
        AppendEntriesResponse::Success => rpc
            .entries
            .last()
            .map(|entry| entry.log_id)
            .or(rpc.prev_log_id),
        AppendEntriesResponse::PartialSuccess(Some(id)) => Some(*id),
        _ => None,
    }?;
    Some((rpc.vote.leader_id.term, matched.index.checked_add(1)?))
}

impl<const PRE_VOTE: bool, const BATCH: u64> fmt::Debug for OpenRaftCore<PRE_VOTE, BATCH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenRaftCore")
            .field("pre_vote", &PRE_VOTE)
            .field("executor", &self.executor)
            .field("running", &self.raft.is_some())
            .finish_non_exhaustive()
    }
}

/// The node's executor seed: fixed per node, so a run is a function of
/// the harness's seed and calls.
fn seed_of(id: NodeId) -> u64 {
    crate::executor::splitmix64(u64::from(id) ^ 0x0000_43C5)
}

impl<const PRE_VOTE: bool, const BATCH: u64> OpenRaftCore<PRE_VOTE, BATCH> {
    /// The node's executor.
    #[must_use]
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// Calls that ended with work left by the budget.
    #[must_use]
    pub fn overruns(&self) -> u64 {
        self.overruns
    }

    /// Whether OpenRaft started.
    #[must_use]
    pub fn running(&self) -> bool {
        self.raft.is_some()
    }

    fn start(id: NodeId, peers: &[NodeId], limits: Option<&Limits>, log: &mut LogView<'_>) -> Self {
        let executor = Executor::new(seed_of(id));
        let mut io = Io {
            incarnation: next_incarnation(),
            ..Io::default()
        };
        let mut readable = true;
        if let Some(last) = log.last_index()
            && let Some(end) = last.checked_add(1)
        {
            let first = log.first_index();
            match log.entries(first..end, u64::MAX) {
                Ok(entries) => {
                    for entry in entries {
                        match to_openraft(&entry) {
                            Some(entry) => {
                                let _ = io.log.insert(entry.log_id.index, entry);
                            }
                            None => readable = false,
                        }
                    }
                    io.handed = Some(last);
                }
                Err(_) => readable = false,
            }
        }
        io.vote = log.hard_state().as_ref().and_then(vote_of);
        let pristine = io.log.is_empty() && io.vote.is_none();
        let io = Arc::new(Mutex::new(io));
        let mut core = Self {
            executor,
            raft: None,
            io: Arc::clone(&io),
            last_tick: None,
            out: false,
            overruns: 0,
            limits: limits.copied(),
            reads: crate::raft_rs::ReadBack::default(),
        };
        let Some(config) = Self::config(limits).filter(|_| readable) else {
            return core;
        };
        let started: Arc<Mutex<Option<Handle>>> = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&started);
        let network = Network {
            io: Arc::clone(&io),
        };
        let store = LogStore {
            io: Arc::clone(&io),
        };
        let machine = StateMachine { io };
        core.executor.enter(|| {
            core.spawn(async move {
                if let Ok(raft) = Raft::new(u64::from(id), config, network, store, machine).await {
                    *lock(&slot) = Some(raft);
                }
            });
        });
        core.pump();
        core.raft = lock(&started).take();
        if pristine && let Some(raft) = core.raft.clone() {
            let members: BTreeSet<u64> = peers.iter().copied().map(u64::from).collect();
            core.executor.enter(|| {
                core.spawn(async move {
                    // Every node initialises with the same membership; a
                    // node that already has a log refuses, which is fine.
                    let _ = raft.initialize(members).await;
                });
            });
            core.pump();
        }
        core
    }

    fn propose_command(&mut self, command: Vec<u8>) -> Result<(), Refused> {
        let leader = self
            .metrics(|metrics| metrics.current_leader)
            .flatten()
            .and_then(|leader| NodeId::try_from(leader).ok());
        if !self.leads() {
            return Err(NotLeader { leader }.into());
        }
        let Some(raft) = self.raft.clone() else {
            return Err(NotLeader { leader: None }.into());
        };
        if let Some(limits) = self.limits {
            let (last, committed) = self
                .metrics(|metrics| {
                    (
                        metrics.last_log_index.unwrap_or(0),
                        metrics
                            .local_committed
                            .map_or(0, |committed| committed.index),
                    )
                })
                .unwrap_or((0, 0));
            crate::raft_rs::refuse_past(&limits, &command, last, committed)?;
        }
        self.executor.enter(|| {
            drop(self.executor.spawn(async move {
                let _ = raft.client_write_ff(Command(command), None).await;
            }));
        });
        self.pump();
        Ok(())
    }

    fn pump(&mut self) {
        if self.executor.pump(PUMP_BUDGET).left > 0 {
            self.overruns = self.overruns.saturating_add(1);
        }
    }

    fn metrics<R>(&self, read: impl FnOnce(&openraft::RaftMetrics<C>) -> R) -> Option<R> {
        let raft = self.raft.as_ref()?;
        let metrics = raft.metrics();
        let current = metrics.borrow_watched();
        Some(read(&current))
    }

    fn spawn<F>(&self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        drop(self.executor.spawn(future));
    }

    fn config(limits: Option<&Limits>) -> Option<Arc<openraft::Config>> {
        let config = openraft::Config {
            cluster_name: "karyos-c5".to_owned(),
            heartbeat_interval: HEARTBEAT_MS,
            election_timeout_min: ELECTION_MS.0,
            election_timeout_max: ELECTION_MS.1,
            enable_pre_vote: Some(PRE_VOTE),
            snapshot_policy: SnapshotPolicy::Never,
            backoff: BACKOFF.to_owned(),
            // Under declared limits, at most the in-flight entries' count
            // in one append; OpenRaft's sequential append stream keeps one
            // append in flight per follower while it is answered. Not
            // strict across RPC timeouts: the adapter fails an RPC after
            // RPC_TIMEOUT ticks, and OpenRaft then sends the next append
            // while the first may still be in flight or unacknowledged
            // (karyos#975).
            // A capped variant (`BATCH` > 0, W1's batch limit, karyos#691)
            // never sends more than `BATCH` entries an append, under
            // declared limits too: the smaller of the two.
            max_payload_entries: match (limits, BATCH) {
                (Some(limits), 0) => limits.in_flight_entries,
                (Some(limits), batch) => limits.in_flight_entries.min(batch),
                (None, 0) => DEFAULT_PAYLOAD_ENTRIES,
                (None, batch) => batch,
            },
            // The durable vote is C4's `HardState`, which has no place for
            // OpenRaft's `committed` bit, so a restarted leader comes back
            // with an uncommitted vote. Leader restoration is off to match:
            // a restarted leader always stands for a new election, as in
            // standard Raft, and that is the recovery evaluated here
            // (karyos#959 review).
            enable_leader_restore: Some(false),
            ..openraft::Config::default()
        };
        config.validate().ok().map(Arc::new)
    }
}

impl<const PRE_VOTE: bool, const BATCH: u64> ConsensusCore for OpenRaftCore<PRE_VOTE, BATCH> {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self::start(id, peers, None, log)
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        // OpenRaft refuses `max_payload_entries = 0`, and both adapters
        // bound the cap the same way: refused here, before startup, not a
        // core without Raft (karyos#963 review).
        if !crate::raft_rs::limits_supported(limits) {
            return Err(Unsupported);
        }
        Ok(Self::start(id, peers, Some(limits), log))
    }

    fn propose(&mut self, command: Vec<u8>, _log: &mut LogView<'_>) -> Result<(), Refused> {
        self.propose_command(command)
    }

    fn step(&mut self, from: NodeId, message: Self::Message, _log: &mut LogView<'_>) {
        match message {
            Message::Response {
                id,
                incarnation,
                request,
                response,
            } => {
                let mut io = lock(&self.io);
                let current = io.incarnation;
                // Another peer's, or an earlier incarnation's: dropped.
                if io
                    .waiting
                    .get(&id)
                    .is_some_and(|waiting| answers(waiting, current, from, incarnation, &request))
                    && let Some(waiting) = io.waiting.remove(&id)
                {
                    drop(io);
                    let _ = waiting.answer.send(response);
                }
            }
            Message::Request {
                id,
                incarnation,
                request,
            } => {
                let Some(raft) = self.raft.clone() else {
                    return;
                };
                let io = Arc::clone(&self.io);
                self.executor.enter(|| {
                    drop(self.executor.spawn(async move {
                        let echoed = request.clone();
                        let response = match request {
                            Request::Append(rpc) => raft
                                .append_entries((*rpc).clone())
                                .await
                                .ok()
                                .map(|r| Response::Append(Arc::new(r))),
                            Request::Vote(rpc) => raft
                                .vote((*rpc).clone())
                                .await
                                .ok()
                                .map(|r| Response::Vote(Arc::new(r))),
                            Request::PreVote(rpc) => raft
                                .pre_vote((*rpc).clone())
                                .await
                                .ok()
                                .map(|r| Response::Vote(Arc::new(r))),
                            Request::TransferLeader(rpc) => raft
                                .handle_transfer_leader((*rpc).clone())
                                .await
                                .ok()
                                .map(|r| Response::TransferLeader(Arc::new(r))),
                        };
                        lock(&io).outbox.push((
                            from,
                            Message::Response {
                                id,
                                incarnation,
                                request: echoed,
                                response,
                            },
                        ));
                    }));
                });
            }
        }
        self.pump();
    }

    fn tick(&mut self, now: u64, _log: &mut LogView<'_>) {
        // The executor's clock is the node's: one millisecond a tick. The
        // first tick sets its origin.
        let origin = *self.last_tick.get_or_insert(now);
        let elapsed = now.saturating_sub(origin);
        self.executor.advance_to(elapsed);
        self.pump();
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        let mut out = ReadyBuf::default();
        self.ready_into(&mut out, log).then_some(out.ready)
    }

    /// The Ready swapped into `out` in place: the node's outgoing vectors
    /// trade places with `out`'s empty ones, which keep their capacity, and
    /// `out`'s spare entries go back to the node's pool.
    fn ready_into(&mut self, out: &mut ReadyBuf<Self::Message>, log: &mut LogView<'_>) -> bool {
        if self.out {
            return false;
        }
        self.pump();
        let mut io = lock(&self.io);
        out.take_spare(&mut io.spare);
        std::mem::swap(&mut out.ready.messages, &mut io.outbox);
        // Under declared limits, an append leaves only once its logged
        // entries were read back through the metered log (karyos#1040);
        // one held back is lost to its peer, and its RPC times out and is
        // retried, as after a loss on the network.
        if self.limits.is_some() {
            let reads = &mut self.reads;
            out.ready.messages.retain(|(_, message)| match message {
                Message::Request {
                    request: Request::Append(rpc),
                    ..
                } => {
                    let sent: Option<Vec<Entry>> = rpc.entries.iter().map(to_harness).collect();
                    sent.is_some_and(|sent| crate::raft_rs::read_back(&sent, log, reads))
                }
                _ => true,
            });
        }
        out.ready.truncate_from = io.truncate_from.take();
        std::mem::swap(&mut out.ready.entries, &mut io.entries);
        out.ready.hard_state = io.hard_state.take();
        std::mem::swap(&mut out.ready.committed, &mut io.committed);
        if out.is_empty() && io.callbacks.is_empty() && io.vote_waiters.is_empty() {
            return false;
        }
        if let Some(last) = out.ready.entries.last() {
            io.handed = Some(last.index);
        }
        // Appended, not taken: the emptied vectors keep their capacity.
        let inner = &mut *io;
        inner.flushing.append(&mut inner.callbacks);
        inner.voting.append(&mut inner.vote_waiters);
        drop(io);
        self.out = true;
        true
    }

    fn advance(&mut self, _persisted: Persisted, _log: &mut LogView<'_>) {
        self.out = false;
        let (flushing, voting) = {
            let mut io = lock(&self.io);
            (
                std::mem::take(&mut io.flushing),
                std::mem::take(&mut io.voting),
            )
        };
        let (mut flushing, mut voting) = (flushing, voting);
        self.executor.enter(|| {
            for callback in flushing.drain(..) {
                callback.io_completed(Ok(()));
            }
            for waiter in voting.drain(..) {
                let _ = waiter.send(());
            }
        });
        // The emptied vectors go back, keeping their capacity, unless the
        // callbacks queued new ones meanwhile.
        {
            let mut io = lock(&self.io);
            if io.flushing.is_empty() {
                io.flushing = flushing;
            }
            if io.voting.is_empty() {
                io.voting = voting;
            }
        }
        self.pump();
    }

    fn term(&self) -> u64 {
        self.metrics(|metrics| metrics.current_term).unwrap_or(0)
    }

    fn leads(&self) -> bool {
        self.metrics(|metrics| metrics.state == ServerState::Leader)
            .unwrap_or(false)
    }

    fn received(&self) -> Option<u64> {
        lock(&self.io)
            .log
            .last_key_value()
            .and_then(|(index, _)| index.checked_add(1))
    }

    fn committed(&self) -> Option<u64> {
        self.metrics(|metrics| metrics.local_committed.map(|committed| committed.index))
            .flatten()
            .and_then(|index| index.checked_add(1))
    }

    fn transfer_leadership(
        &mut self,
        to: NodeId,
        _log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        let leader = self
            .metrics(|metrics| metrics.current_leader)
            .flatten()
            .and_then(|leader| NodeId::try_from(leader).ok());
        if !self.leads() {
            return Err(TransferRefused::NotLeader(NotLeader { leader }));
        }
        let voter = self
            .metrics(|metrics| {
                metrics
                    .membership_config
                    .membership()
                    .voter_ids()
                    .any(|id| id == u64::from(to))
            })
            .unwrap_or(false);
        if !voter || leader == Some(to) {
            return Err(TransferRefused::Invalid);
        }
        let Some(raft) = self.raft.clone() else {
            return Err(TransferRefused::NotLeader(NotLeader { leader: None }));
        };
        self.executor.enter(|| {
            drop(self.executor.spawn(async move {
                let _ = raft.trigger().transfer_leader(u64::from(to)).await;
            }));
        });
        self.pump();
        Ok(())
    }
}

impl<const PRE_VOTE: bool, const BATCH: u64> crate::process::Wire
    for OpenRaftCore<PRE_VOTE, BATCH>
{
    fn encode(message: &Message) -> Option<Vec<u8>> {
        crate::openraft_wire::encode(message)
    }

    fn decode(bytes: &[u8]) -> Option<Message> {
        crate::openraft_wire::decode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_rpc(term: u64, prev: Option<(u64, u64)>, entries: &[(u64, &[u8])]) -> Request {
        Request::Append(Arc::new(AppendEntriesRequest {
            vote: OVote {
                leader_id: openraft::impls::leader_id_std::LeaderId { term, voted_for: 1 },
                committed: true,
            },
            prev_log_id: prev.map(|(term, index)| log_id(term, index)),
            entries: entries
                .iter()
                .map(|(index, payload)| OEntry {
                    log_id: log_id(term, *index),
                    payload: if payload.is_empty() {
                        EntryPayload::Blank
                    } else {
                        EntryPayload::Normal(Command(payload.to_vec()))
                    },
                })
                .collect(),
            leader_commit: None,
        }))
    }

    fn answer(request: Request, response: AppendEntriesResponse<C>) -> Message {
        Message::Response {
            id: 1,
            incarnation: 1,
            request,
            response: Some(Response::Append(Arc::new(response))),
        }
    }

    /// The oracle's reading of OpenRaft's appends (karyos#691): harness
    /// indices are OpenRaft's plus one, payload bytes are the commands',
    /// and each answer acknowledges exactly what it covers.
    #[test]
    fn appends_and_their_answers_are_read_in_harness_indices() {
        let rpc = append_rpc(3, Some((2, 4)), &[(5, &[7; 100]), (6, &[]), (7, &[7; 10])]);
        let request = Message::Request {
            id: 1,
            incarnation: 1,
            request: rpc.clone(),
        };
        assert_eq!(
            append_entries(&request),
            Some((3, vec![(6, 100), (7, 0), (8, 10)]))
        );
        assert_eq!(
            append_ack(&answer(rpc.clone(), AppendEntriesResponse::Success)),
            Some((3, 8))
        );
        assert_eq!(
            append_ack(&answer(
                rpc.clone(),
                AppendEntriesResponse::PartialSuccess(Some(log_id(3, 5)))
            )),
            Some((3, 6))
        );
        assert_eq!(
            append_ack(&answer(rpc.clone(), AppendEntriesResponse::Conflict)),
            None
        );
        // An empty append acknowledges its previous entry, OpenRaft's 0
        // being the harness's 1; with none, nothing.
        let heartbeat = append_rpc(3, Some((1, 0)), &[]);
        assert_eq!(
            append_ack(&answer(heartbeat, AppendEntriesResponse::Success)),
            Some((3, 1))
        );
        let empty = append_rpc(3, None, &[]);
        assert_eq!(
            append_ack(&answer(empty, AppendEntriesResponse::Success)),
            None
        );
        assert_eq!(append_ack(&request), None);
    }

    /// The regression of the karyos#959 review: after a restart the RPC
    /// numbers start again, so an answer to an earlier incarnation's
    /// request can carry the number of a new one. It is refused, as is an
    /// answer from another peer; only the request sent, from its peer,
    /// is answered.
    fn vote_request_of(term: u64) -> Request {
        Request::Vote(Arc::new(VoteRequest::new(
            OVote {
                leader_id: openraft::impls::leader_id_std::LeaderId { term, voted_for: 0 },
                committed: false,
            },
            None,
        )))
    }

    #[test]
    fn an_answer_is_accepted_only_for_the_request_sent_to_that_peer() {
        let sent = vote_request_of(2);
        let (answer, _receiver) = oneshot::channel();
        let waiting = Waiting {
            target: 2,
            request: sent.clone(),
            answer,
        };
        let (before, now) = (7, 8);
        // The same number, an earlier incarnation's request: dropped.
        assert!(!answers(&waiting, now, 2, now, &vote_request_of(1)));
        // Another peer's: dropped.
        assert!(!answers(&waiting, now, 1, now, &sent));
        assert!(answers(&waiting, now, 2, now, &sent));
        // Decoded in another process: the same content answers.
        assert!(answers(&waiting, now, 2, now, &vote_request_of(2)));
        // The P1 of the karyos#959 review: after a restart the node sends a
        // byte-identical request under the same number; the answer made
        // for the earlier incarnation is dropped all the same.
        assert!(!answers(&waiting, now, 2, before, &vote_request_of(2)));
    }

    #[test]
    fn every_recovery_draws_a_new_incarnation() {
        let draws: BTreeSet<u64> = (0..1000).map(|_| next_incarnation()).collect();
        assert_eq!(draws.len(), 1000);
    }
}
