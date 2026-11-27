// SPDX-License-Identifier: Apache-2.0

//! The nodes a harness run is made of, over C1's [`ClusterSim`]: servers,
//! each a [`ConsensusCore`] over C4's log on its own simulated disk with
//! the deterministic test service, and scripted clients. They share one
//! wire type and report to one [`Recorder`].
//!
//! - **The test service** (ADR-0043, Workloads) is an append-only
//!   register: `Append(bytes)` adds a value, `Read` returns them all. It
//!   deduplicates a client's retried sequence number, keeps a state
//!   digest, and answers in canonical response bytes.
//! - **A crash** drops the server's core and log and keeps the disk C2's
//!   [`SimDisk::after_crash`] gives under the node's survival mode. **A
//!   restart** reopens the log and rebuilds the core from it
//!   ([`ConsensusCore::recover`]); a refused open is recorded as an
//!   [`Observation::OpenFailed`], and the node stays down.
//! - **A log error** in [`drive`](super::core::drive) stops the node until a restart. One the
//!   core caused by breaking C4's contract (an append that is not next, a
//!   term or commit going back, a truncation below the commit) is an
//!   [`Observation::Contract`], which the checks report as a violation;
//!   one of the disk is an [`Observation::OpenFailed`].
//! - **Positions** are indices, not the byte positions of SPEC.md §9:
//!   received is the core's last index, written or not; written and
//!   durable are the log's; committed is the core's; applied is the
//!   service's.
//! - **Membership** (phase 5): an operator's [`Wire::Change`] goes to a
//!   server's core, and the server records the core's answer
//!   ([`Observation::Change`]) and every configuration the core reports
//!   ([`Observation::Configuration`]). A core with static membership
//!   reports none.
//! - **A standby** (phase 5, P5-S2; [`super::standby`]): a primary server
//!   with a feed sends its committed entries to the standby's servers
//!   while its core leads; a standby server whose core leads verifies and
//!   proposes them, and its service applies them with effects disabled
//!   until a promotion. A primary server with a lease takes a command and
//!   releases a reply only while it holds the lease on its own clock. Every
//!   reply carries its server's generation, and a client rejects a lower
//!   one once it has seen a higher one.
//! - **Cluster log replication** (ADR-0120, karyos#714): in place of the
//!   feed, a primary server whose core leads pushes its log's stored
//!   bytes, its `ClusterLog` seals of one epoch and a status to the
//!   standby ([`Wire::ReplStart`] and the rest), as schema 6 would; the
//!   standby's leader checks them with
//!   [`karyos_cluster::standby::Standby`] and proposes what passes. Its
//!   acknowledgement names its copy's received and checked ends, and
//!   whether a seal stalled, so the sender resends from there.
//!
//! [`ClusterSim`]: crate::cluster::ClusterSim

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::rc::Rc;

use karyos_archive::integrity::SealRecord;
use karyos_archive::segment::Geometry;
use karyos_cluster::client::Accepted;
use karyos_cluster::cluster_identity::{ClusterId, IdentityRecord};
use karyos_cluster::peer_frame::{Admission, PeerGate};
use karyos_cluster::snapshot::{
    PendingSnapshot, Section, SectionKind, SnapshotConfig, SnapshotError, SnapshotReader,
    SnapshotStore, WRITE_CHUNK,
};
use karyos_cluster::standby::{
    Position, RecoveryPoint, Refusal, ReplicaCheck, Sealed, Standby, StandbyConfig, TailBound,
};
use karyos_cluster::{Entry, LogError, RaftLog};

use super::core::{
    Applying, Change, ChangeRefused, Configuration, ConsensusCore, DriveError, DriveFault, Limit,
    Limits, LogView, NotLeader, ReadBudget, ReadyBuf, Refused, Release, SnapshotBase, Step,
    TransferRefused, Unsupported, drive_inner,
};
use super::standby::{
    self, ExternalLease, FEED_BATCH_BYTES, FEED_PERIOD, FIRST_GENERATION, FeedEntry, FeedFault,
    FeedRefusal, Fencing, PromotionReport, STATUS_INTERVAL,
};
use crate::cluster::{Node, Outbox};
use crate::disk::{SimDisk, Survives};
use crate::lin::{self, History};
use crate::net::NodeId;

/// The tag every command's bytes start with, so a core's own entries do
/// not decode as commands.
pub const COMMAND_MAGIC: [u8; 4] = *b"KC5\x01";

/// The directory of a server's log on its disk.
pub const LOG_DIR: &str = "/raft";
/// Harness ticks a committed log tail may wait unsealed before the log's
/// seal duty seals it ([`karyos_cluster::RaftLog::tick`]; karyos#1050).
pub const SEAL_TICKS: u64 = 10;
/// The directory of a server's snapshot store, beside its log (W5).
pub const SNAPSHOT_DIR: &str = "/snap";
/// The version of the service section a snapshot holds.
pub const SERVICE_SECTION_VERSION: u64 = 2;
/// A snapshot transfer's window: the pieces a leader has sent a follower
/// and not had acknowledged, at most (karyos#682).
pub const SNAPSHOT_WINDOW: u64 = 4;
/// Ticks a follower's transfer may go without a piece before it is
/// dropped: its leader asks again, and a stale one goes.
pub const SNAPSHOT_STALL: u64 = 2_000;
/// Ticks a leader's transfer may go without its window moving before the
/// core's next ask starts it again: a piece lost, or sent to a follower
/// that was down. Well under [`SNAPSHOT_STALL`], so a follower that comes
/// back is served again long before it would give up.
pub const SNAPSHOT_RETRY: u64 = 200;

/// A case's log compaction (W5), driven by the snapshot store's own
/// policy ([`SnapshotConfig`]; karyos#682): a snapshot is due after
/// `every` applied entries or the default byte trigger's log bytes
/// ([`SnapshotConfig::due`]), the store keeps its default number of
/// snapshots, and the log is purged below the oldest kept one but a
/// catch-up allowance of `keep` entries' bytes ([`SnapshotConfig::log_floor`]),
/// `frame` bytes each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compaction {
    /// Applied entries between snapshots: the entry trigger.
    pub every: u64,
    /// Entries' worth of log bytes kept below the oldest kept snapshot,
    /// for a slow follower: the allowance, in entries.
    pub keep: u64,
    /// The log bytes of one of the case's entries (its frame), which turns
    /// `keep` into the allowance's bytes.
    pub frame: u64,
    /// The byte trigger, when not item 37's default.
    pub every_bytes: Option<u64>,
}

impl Compaction {
    /// The snapshot store's configuration it stands for: item 37's
    /// defaults with the entry trigger `every` and an allowance of `keep`
    /// frames.
    #[must_use]
    pub fn config(&self) -> SnapshotConfig {
        let config = SnapshotConfig::default()
            .with_every_entries(self.every.max(1))
            .with_allowance(self.keep.saturating_mul(self.frame));
        match self.every_bytes {
            Some(bytes) => config.with_every_bytes(bytes.max(1)),
            None => config,
        }
    }
}

/// One piece of a snapshot transfer, as [`Wire::Snapshot`] carries it.
#[derive(Debug)]
struct Piece {
    base: SnapshotBase,
    term: u64,
    transfer: u64,
    digest: u32,
    length: u64,
    offset: u64,
    bytes: Vec<u8>,
}

/// A snapshot a follower receives: its sender's transfer, the frozen
/// metadata every piece must repeat, and the bytes so far, streamed into
/// its store (karyos#682).
#[derive(Debug)]
struct Incoming {
    from: NodeId,
    /// Its sender's term when it started the transfer.
    term: u64,
    transfer: u64,
    base: SnapshotBase,
    digest: u32,
    length: u64,
    pending: PendingSnapshot<SimDisk>,
    /// When the last piece arrived.
    last: u64,
}

/// A snapshot a leader sends: read from its store as the follower
/// acknowledges, at most [`SNAPSHOT_WINDOW`] pieces ahead.
#[derive(Debug)]
struct Outgoing {
    /// Its term when it started the transfer.
    term: u64,
    transfer: u64,
    base: SnapshotBase,
    digest: u32,
    length: u64,
    reader: SnapshotReader<SimDisk>,
    sent: u64,
    acked: u64,
    /// When it started, or last saw its window move.
    moved: u64,
}

/// A client's operation on the test service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Op {
    /// Appends a value.
    Append(Vec<u8>),
    /// Reads every value.
    Read,
}

/// What the test service answers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ret {
    /// The register's length after the append.
    Appended(u64),
    /// Every value, in order.
    Values(Vec<Vec<u8>>),
    /// A retry of a request whose answer the deduplication table no longer
    /// keeps ([`RETENTION`]): its outcome is unknown, reported explicitly,
    /// never applied again (W5).
    Expired,
}

impl Ret {
    /// Another valid answer than this one (karyos#1038, tests): a faulty
    /// service's.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    fn altered(self) -> Self {
        match self {
            Self::Appended(length) => Self::Appended(length.wrapping_add(1_000)),
            Self::Values(mut values) => {
                values.push(b"altered".to_vec());
                Self::Values(values)
            }
            Self::Expired => Self::Appended(0),
        }
    }

    /// The canonical response bytes: a tag, then the length or the values,
    /// each length-prefixed, little endian.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::Appended(length) => {
                bytes.push(0);
                bytes.extend_from_slice(&length.to_le_bytes());
            }
            Self::Expired => bytes.push(2),
            Self::Values(values) => {
                bytes.push(1);
                for value in values {
                    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
                    bytes.extend_from_slice(&length.to_le_bytes());
                    bytes.extend_from_slice(value);
                }
            }
        }
        bytes
    }

    /// The answer in canonical response bytes, if they are some.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (tag, mut rest) = bytes.split_first()?;
        match tag {
            0 => {
                let length = rest.first_chunk::<8>()?;
                (rest.len() == 8).then(|| Self::Appended(u64::from_le_bytes(*length)))
            }
            1 => {
                let mut values = Vec::new();
                while !rest.is_empty() {
                    let (length, tail) = rest.split_first_chunk::<4>()?;
                    let length = usize::try_from(u32::from_le_bytes(*length)).ok()?;
                    let value = tail.get(..length)?;
                    values.push(value.to_vec());
                    rest = tail.get(length..)?;
                }
                Some(Self::Values(values))
            }
            2 => rest.is_empty().then_some(Self::Expired),
            _ => None,
        }
    }
}

/// A client's request: who, which of its operations, and what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The client.
    pub client: NodeId,
    /// Its sequence number, from 1; a retry repeats it.
    pub sequence: u64,
    /// The operation.
    pub op: Op,
}

impl Command {
    /// Its bytes in the log: [`COMMAND_MAGIC`], client, sequence, a tag,
    /// then the value.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode_into(&mut bytes);
        bytes
    }

    /// [`Command::encode`] into `bytes`, cleared first: a node that keeps
    /// `bytes` encodes without allocating once it has grown (karyos#691).
    pub fn encode_into(&self, bytes: &mut Vec<u8>) {
        bytes.clear();
        bytes.extend_from_slice(&COMMAND_MAGIC);
        bytes.extend_from_slice(&self.client.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        match &self.op {
            Op::Append(value) => {
                bytes.push(0);
                bytes.extend_from_slice(value);
            }
            Op::Read => bytes.push(1),
        }
    }

    /// The command in a log entry's payload, if it is one.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(&COMMAND_MAGIC)?;
        let (client, rest) = rest.split_first_chunk::<4>()?;
        let (sequence, rest) = rest.split_first_chunk::<8>()?;
        let (tag, value) = rest.split_first()?;
        let op = match tag {
            0 => Op::Append(value.to_vec()),
            1 if value.is_empty() => Op::Read,
            _ => return None,
        };
        Some(Self {
            client: u32::from_le_bytes(*client),
            sequence: u64::from_le_bytes(*sequence),
            op,
        })
    }
}

/// The answers a client's deduplication keeps (W5's retention): a retry
/// of an older request is answered [`Ret::Expired`].
pub const RETENTION: usize = 10_000;

/// One client's deduplication: its last [`RETENTION`] answers by
/// sequence, and the highest sequence it evicted. A sequence at or below
/// the floor and not kept was answered and forgotten: [`Ret::Expired`]. One
/// above it and not kept was never applied, even below one that was (a
/// window's requests may commit out of order; karyos#905 review).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Answers {
    by_sequence: BTreeMap<u64, Ret>,
    floor: u64,
}

/// The deterministic test service: an append-only register, with a
/// deduplication table of each client's last [`RETENTION`] answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestService {
    values: Vec<Vec<u8>>,
    /// Per client, its retained answers.
    answered: BTreeMap<NodeId, Answers>,
    applied: Option<u64>,
    deduplicated: u64,
    /// Retries answered [`Ret::Expired`].
    expired: u64,
    /// Answers kept per client.
    retention: usize,
    /// The log time: the largest event time applied, as the sessions
    /// section of a shipped snapshot records it (ADR-0111, decision 4).
    log_time: u64,
    /// The last configuration entry applied, as the consensus section of
    /// a shipped snapshot records the configuration (karyos#711).
    configuration: Option<Vec<u8>>,
}

impl Default for TestService {
    fn default() -> Self {
        Self::with_retention(RETENTION)
    }
}

impl TestService {
    /// A service keeping `retention` answers per client (tests of the
    /// expiry use a small one).
    #[must_use]
    pub fn with_retention(retention: usize) -> Self {
        Self {
            values: Vec::new(),
            answered: BTreeMap::new(),
            applied: None,
            deduplicated: 0,
            expired: 0,
            retention: retention.max(1),
            log_time: 0,
            configuration: None,
        }
    }

    /// The core's configuration entry `payload` applied: kept, so its
    /// snapshot carries the configuration at its base.
    pub fn set_configuration(&mut self, payload: &[u8]) {
        self.configuration = Some(payload.to_vec());
    }

    /// The last configuration entry applied, if any.
    #[must_use]
    pub fn configuration(&self) -> Option<&[u8]> {
        self.configuration.as_deref()
    }

    /// Applies the committed `entry`; returns the command and its answer:
    /// the kept answer for a retried sequence, [`Ret::Expired`] for one
    /// whose answer is no longer kept. An entry that holds no command (a
    /// core's own entry) answers nothing.
    pub fn apply(&mut self, entry: &Entry) -> Option<(Command, Ret)> {
        self.applied = Some(entry.index);
        self.log_time = self.log_time.max(entry.event_time);
        let command = Command::decode(&entry.payload)?;
        let answers = self.answered.entry(command.client).or_default();
        if let Some(ret) = answers.by_sequence.get(&command.sequence) {
            if let Some(count) = self.deduplicated.checked_add(1) {
                self.deduplicated = count;
            }
            return Some((command, ret.clone()));
        }
        if command.sequence <= answers.floor {
            if let Some(count) = self.expired.checked_add(1) {
                self.expired = count;
            }
            return Some((command, Ret::Expired));
        }
        let ret = match &command.op {
            Op::Append(value) => {
                self.values.push(value.clone());
                Ret::Appended(u64::try_from(self.values.len()).unwrap_or(u64::MAX))
            }
            Op::Read => Ret::Values(self.values.clone()),
        };
        let _ = answers.by_sequence.insert(command.sequence, ret.clone());
        while answers.by_sequence.len() > self.retention {
            if let Some((evicted, _)) = answers.by_sequence.pop_first() {
                answers.floor = answers.floor.max(evicted);
            }
        }
        Some((command, ret))
    }

    /// Retries it answered [`Ret::Expired`].
    #[must_use]
    pub fn expired(&self) -> u64 {
        self.expired
    }

    /// The last index applied.
    #[must_use]
    pub fn applied(&self) -> Option<u64> {
        self.applied
    }

    /// The log time: the largest event time applied (ADR-0111).
    #[must_use]
    pub fn log_time(&self) -> u64 {
        self.log_time
    }

    /// Its whole state as a snapshot's service section (W5; karyos#687):
    /// the values, the deduplication table, the last index applied, the
    /// deduplicated and expired counts and the log time, each
    /// length-prefixed, little endian; `None`
    /// when a length passes its prefix.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        fn count(bytes: &mut Vec<u8>, n: usize) -> Option<()> {
            bytes.extend_from_slice(&u32::try_from(n).ok()?.to_le_bytes());
            Some(())
        }
        let mut bytes = SERVICE_MAGIC.to_vec();
        count(&mut bytes, self.values.len())?;
        for value in &self.values {
            count(&mut bytes, value.len())?;
            bytes.extend_from_slice(value);
        }
        count(&mut bytes, self.retention)?;
        count(&mut bytes, self.answered.len())?;
        for (client, answers) in &self.answered {
            bytes.extend_from_slice(&client.to_le_bytes());
            bytes.extend_from_slice(&answers.floor.to_le_bytes());
            count(&mut bytes, answers.by_sequence.len())?;
            for (sequence, ret) in &answers.by_sequence {
                bytes.extend_from_slice(&sequence.to_le_bytes());
                let ret = ret.canonical();
                count(&mut bytes, ret.len())?;
                bytes.extend_from_slice(&ret);
            }
        }
        match self.applied {
            Some(index) => {
                bytes.push(1);
                bytes.extend_from_slice(&index.to_le_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.deduplicated.to_le_bytes());
        bytes.extend_from_slice(&self.expired.to_le_bytes());
        bytes.extend_from_slice(&self.log_time.to_le_bytes());
        // Only when there is one, so a service of a static membership
        // encodes as before.
        if let Some(configuration) = &self.configuration {
            count(&mut bytes, configuration.len())?;
            bytes.extend_from_slice(configuration);
        }
        Some(bytes)
    }

    /// A service restored from [`TestService::encode`]'s bytes; `None` for
    /// bytes that are not exactly one, so a malformed or cut snapshot is
    /// refused, never half restored.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            let (head, tail) = (rest.get(..n)?, rest.get(n..)?);
            *rest = tail;
            Some(head)
        }
        fn u32_at(rest: &mut &[u8]) -> Option<usize> {
            let bytes = take(rest, 4)?.first_chunk::<4>()?;
            usize::try_from(u32::from_le_bytes(*bytes)).ok()
        }
        fn u64_at(rest: &mut &[u8]) -> Option<u64> {
            Some(u64::from_le_bytes(*take(rest, 8)?.first_chunk::<8>()?))
        }
        let mut rest = bytes.strip_prefix(&SERVICE_MAGIC)?;
        let mut values = Vec::new();
        for _ in 0..u32_at(&mut rest)? {
            let length = u32_at(&mut rest)?;
            values.push(take(&mut rest, length)?.to_vec());
        }
        let retention = u32_at(&mut rest)?;
        if retention == 0 {
            return None;
        }
        let mut answered = BTreeMap::new();
        for _ in 0..u32_at(&mut rest)? {
            let client = NodeId::from_le_bytes(*take(&mut rest, 4)?.first_chunk::<4>()?);
            let floor = u64_at(&mut rest)?;
            let mut answers = Answers {
                by_sequence: BTreeMap::new(),
                floor,
            };
            let kept = u32_at(&mut rest)?;
            if kept > retention {
                return None;
            }
            for _ in 0..kept {
                let sequence = u64_at(&mut rest)?;
                let length = u32_at(&mut rest)?;
                let ret = Ret::decode(take(&mut rest, length)?)?;
                if sequence <= floor || answers.by_sequence.insert(sequence, ret).is_some() {
                    return None;
                }
            }
            if answered.insert(client, answers).is_some() {
                return None;
            }
        }
        let applied = match take(&mut rest, 1)? {
            [0] => None,
            [1] => Some(u64_at(&mut rest)?),
            _ => return None,
        };
        let deduplicated = u64_at(&mut rest)?;
        let expired = u64_at(&mut rest)?;
        let log_time = u64_at(&mut rest)?;
        let configuration = if rest.is_empty() {
            None
        } else {
            let length = u32_at(&mut rest)?;
            Some(take(&mut rest, length)?.to_vec())
        };
        rest.is_empty().then_some(Self {
            values,
            answered,
            applied,
            deduplicated,
            expired,
            retention,
            log_time,
            configuration,
        })
    }

    /// Retried commands it answered from its deduplication table.
    #[must_use]
    pub fn deduplicated(&self) -> u64 {
        self.deduplicated
    }

    /// A digest of the state: see [`TestService::digest_of`].
    #[must_use]
    pub fn digest(&self) -> u64 {
        Self::digest_of(&self.values)
    }

    /// The digest of a register holding `values`: FNV-1a over them, each
    /// closed by a 0xFF (its multiplication wraps by the hash's
    /// definition).
    #[must_use]
    pub fn digest_of(values: &[Vec<u8>]) -> u64 {
        let mut digest = 0xCBF2_9CE4_8422_2325u64;
        for value in values {
            for byte in value.iter().chain(&[0xFF]) {
                digest ^= u64::from(*byte);
                digest = digest.wrapping_mul(0x0000_0100_0000_01B3);
            }
        }
        digest
    }
}

/// The tag a [`TestService::encode`] section starts with.
pub const SERVICE_MAGIC: [u8; 4] = *b"KRSV";

/// The test service as C3's sequential model.
///
/// Its state is a [`SharedLog`]: appending shares the earlier values, so
/// the checker's search clones a state in O(1) and hashes it by its length
/// and digest, while equality stays exact, value by value (karyos#687;
/// decided 2026-10-30 by QS-COORDINATOR: the checker never trusts a
/// digest alone).
#[derive(Debug, Clone, Copy)]
pub struct ServiceModel {
    /// Folds a value into the digest of the values before it.
    fold: fn(u64, &[u8]) -> u64,
}

impl Default for ServiceModel {
    fn default() -> Self {
        Self { fold: fnv1a }
    }
}

impl ServiceModel {
    /// The model with `fold` as its digest: a test forces collisions with
    /// it, and the model still tells the states apart.
    #[cfg(test)]
    pub(crate) fn with_fold(fold: fn(u64, &[u8]) -> u64) -> Self {
        Self { fold }
    }
}

/// FNV-1a over the earlier digest, the value's length and its bytes.
fn fnv1a(digest: u64, value: &[u8]) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    digest
        .to_le_bytes()
        .iter()
        .chain(&length.to_le_bytes())
        .chain(value)
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
        })
}

impl lin::Model for ServiceModel {
    type State = SharedLog;
    type Op = Op;
    type Ret = Ret;

    fn init(&self) -> Self::State {
        SharedLog::default()
    }

    fn step(&self, state: &Self::State, op: &Op) -> (Self::State, Ret) {
        match op {
            Op::Append(value) => match state.push(value.clone(), self.fold) {
                Some(next) => {
                    let length = next.len();
                    (next, Ret::Appended(length))
                }
                // A log of u64::MAX values cannot be built from a history
                // (it holds fewer operations); were it, the append answers
                // length 0, which no recorded append returns, so the
                // checker refuses it rather than accept a wrapped count.
                None => (state.clone(), Ret::Appended(0)),
            },
            Op::Read => (state.clone(), Ret::Values(state.values())),
        }
    }
}

/// The values appended, newest last, as a persistent list: a push shares
/// every earlier value, so a clone is O(1). It hashes by its length and
/// digest, and compares equal only value by value.
#[derive(Debug, Clone, Default)]
pub struct SharedLog {
    last: Option<Rc<Link>>,
}

/// One value of a [`SharedLog`], and the values before it.
#[derive(Debug)]
struct Link {
    value: Vec<u8>,
    before: Option<Rc<Link>>,
    /// Values up to this one.
    length: u64,
    /// The fold of the values up to this one.
    digest: u64,
}

impl SharedLog {
    /// Values held.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.last.as_ref().map_or(0, |link| link.length)
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.last.is_none()
    }

    fn digest(&self) -> u64 {
        self.last.as_ref().map_or(0, |link| link.digest)
    }

    /// It with `value` appended, its digest folded by `fold`; `None` when
    /// its length would pass `u64::MAX`.
    fn push(&self, value: Vec<u8>, fold: fn(u64, &[u8]) -> u64) -> Option<Self> {
        let length = self.len().checked_add(1)?;
        let digest = fold(self.digest(), &value);
        Some(Self {
            last: Some(Rc::new(Link {
                value,
                before: self.last.clone(),
                length,
                digest,
            })),
        })
    }

    /// Its values, oldest first.
    #[must_use]
    pub fn values(&self) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let mut at = self.last.as_deref();
        while let Some(link) = at {
            values.push(link.value.clone());
            at = link.before.as_deref();
        }
        values.reverse();
        values
    }
}

impl PartialEq for SharedLog {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() || self.digest() != other.digest() {
            return false;
        }
        // Equal digests prove nothing: compare value by value, down to a
        // shared tail.
        let (mut left, mut right) = (self.last.as_ref(), other.last.as_ref());
        loop {
            match (left, right) {
                (None, None) => return true,
                (Some(a), Some(b)) => {
                    if Rc::ptr_eq(a, b) {
                        return true;
                    }
                    if a.value != b.value {
                        return false;
                    }
                    (left, right) = (a.before.as_ref(), b.before.as_ref());
                }
                _ => return false,
            }
        }
    }
}

impl Eq for SharedLog {}

impl std::hash::Hash for SharedLog {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.len().hash(state);
        self.digest().hash(state);
    }
}

impl Drop for SharedLog {
    // Iterative: a long list dropped link by link would recurse as deep as
    // it is long.
    fn drop(&mut self) {
        let mut at = self.last.take();
        while let Some(link) = at {
            match Rc::try_unwrap(link) {
                Ok(mut link) => at = link.before.take(),
                Err(_) => break,
            }
        }
    }
}

#[cfg(test)]
mod service_snapshot_tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    fn service() -> TestService {
        let mut service = TestService::default();
        let commands = [
            (1, 1, Op::Append(b"a".to_vec())),
            (2, 1, Op::Append(b"bb".to_vec())),
            (1, 2, Op::Read),
            (2, 1, Op::Append(b"bb".to_vec())),
        ];
        for (index, (client, sequence, op)) in (1u64..).zip(commands) {
            let command = Command {
                client,
                sequence,
                op,
            };
            let _ = service.apply(&Entry {
                index,
                term: 1,
                event_time: 0,
                payload: command.encode(),
            });
        }
        service
    }

    /// A service restored from its snapshot section is the same service:
    /// values, deduplication answers, last index and count (karyos#687).
    #[test]
    fn a_service_round_trips_through_its_snapshot_section() {
        let service = service();
        assert_eq!(service.deduplicated(), 1);
        let bytes = service.encode().unwrap();
        assert_eq!(TestService::decode(&bytes), Some(service.clone()));
        assert_eq!(
            TestService::decode(&TestService::default().encode().unwrap()),
            Some(TestService::default())
        );
    }

    /// A client's retry is answered from its kept answers; once its answer
    /// fell out of the retention, it is answered Expired, explicitly, and
    /// never applied again (W5). The section keeps the retained answers.
    #[test]
    fn a_retry_past_the_retention_is_answered_expired() {
        let mut service = TestService::with_retention(2);
        let apply = |service: &mut TestService, index: u64, sequence: u64| {
            let command = Command {
                client: 7,
                sequence,
                op: Op::Append(vec![u8::try_from(sequence).unwrap()]),
            };
            service
                .apply(&Entry {
                    index,
                    term: 1,
                    event_time: 0,
                    payload: command.encode(),
                })
                .map(|(_, ret)| ret)
        };
        for sequence in 1..=3 {
            assert_eq!(
                apply(&mut service, sequence, sequence),
                Some(Ret::Appended(sequence))
            );
        }
        // Kept: 2 and 3. A retry of 3 is answered as it was; of 1, expired.
        assert_eq!(apply(&mut service, 4, 3), Some(Ret::Appended(3)));
        assert_eq!(apply(&mut service, 5, 1), Some(Ret::Expired));
        assert_eq!((service.deduplicated(), service.expired()), (1, 1));
        assert_eq!(
            service.digest(),
            TestService::digest_of(&[vec![1], vec![2], vec![3]])
        );
        let restored = TestService::decode(&service.encode().unwrap()).unwrap();
        assert_eq!(restored, service);
        let mut restored = restored;
        assert_eq!(apply(&mut restored, 6, 2), Some(Ret::Appended(2)));
        assert_eq!(Ret::decode(&Ret::Expired.canonical()), Some(Ret::Expired));
        // A gap: 5 applied before 4 (a window across a redirect). 4 was
        // never applied, so it is, not answered Expired.
        let mut service = TestService::with_retention(2);
        assert_eq!(apply(&mut service, 1, 5), Some(Ret::Appended(1)));
        assert_eq!(apply(&mut service, 2, 4), Some(Ret::Appended(2)));
        assert_eq!(service.expired(), 0);
    }

    /// Every cut, an extra byte and another tag are refused: a snapshot
    /// is restored whole or not at all.
    #[test]
    fn a_malformed_section_is_refused() {
        let bytes = service().encode().unwrap();
        for cut in 0..bytes.len() {
            assert_eq!(TestService::decode(&bytes[..cut]), None, "cut at {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(TestService::decode(&longer), None);
        let mut other = bytes;
        other[0] ^= 1;
        assert_eq!(TestService::decode(&other), None);
    }
}

#[cfg(test)]
mod shared_log_tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;
    use crate::lin::Model;

    /// Every digest the same: equal states are still told only by their
    /// values (karyos#687).
    fn colliding(_: u64, _: &[u8]) -> u64 {
        7
    }

    #[test]
    fn colliding_digests_never_make_different_logs_equal() {
        let model = ServiceModel::with_fold(colliding);
        let push = |state: &SharedLog, value: u8| model.step(state, &Op::Append(vec![value])).0;
        let empty = model.init();
        let ab = push(&push(&empty, 1), 2);
        let ba = push(&push(&empty, 2), 1);
        let ab_again = push(&push(&empty, 1), 2);
        assert_eq!(ab.digest(), ba.digest(), "forced to collide");
        assert_ne!(ab, ba);
        assert_eq!(ab, ab_again);
        assert_eq!(
            model.step(&ab, &Op::Read).1,
            Ret::Values(vec![vec![1], vec![2]])
        );
        assert_eq!(
            model.step(&ba, &Op::Read).1,
            Ret::Values(vec![vec![2], vec![1]])
        );
        // A memo keyed by the colliding state keeps both.
        let seen: std::collections::HashSet<SharedLog> = [ab, ba, ab_again].into_iter().collect();
        assert_eq!(seen.len(), 2);
    }

    /// Two appends left open, then a read of the second before the first,
    /// under colliding digests: the search reaches {both appended} first
    /// as [1, 2], which the read refutes, then as [2, 1]. Keyed by a digest
    /// alone, the memo would take the second for the first and prune it,
    /// a false "not linearizable"; compared value by value, it is
    /// linearizable.
    #[test]
    fn the_checker_tells_apart_states_whose_digests_collide() {
        use crate::lin::{History, Verdict, check};
        let model = ServiceModel::with_fold(colliding);
        let mut history = History::default();
        history
            .invoke(1, Op::Append(vec![1]))
            .invoke(2, Op::Append(vec![2]))
            .invoke(3, Op::Read)
            .ret(3, Ret::Values(vec![vec![2], vec![1]]));
        let verdict = check(&model, &history, crate::harness::check::LIMIT).unwrap();
        assert!(matches!(verdict, Verdict::Linearizable(_)), "{verdict:?}");
    }

    #[test]
    fn a_long_log_drops_without_recursing() {
        let model = ServiceModel::default();
        let mut log = model.init();
        for value in 0..200_000u32 {
            log = log.push(value.to_le_bytes().to_vec(), fnv1a).unwrap();
        }
        assert_eq!(log.len(), 200_000);
        drop(log);
    }
}

/// What a node reports, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// A server's core panicked inside a call through the harness's core
    /// trait (karyos#976): the server stops, as after a drive error, until
    /// a restart reopens its log, and the run goes on so that the checks
    /// see what came before. Whatever the core, its panic is caught at the
    /// same boundary.
    CorePanicked {
        /// The server.
        node: NodeId,
    },
    /// A server's [`drive`](super::core::drive) step.
    Drive {
        /// The server.
        node: NodeId,
        /// The step.
        step: Step,
    },
    /// A server sent a message that waited for persistence.
    Released {
        /// The server.
        node: NodeId,
        /// The receiver.
        to: NodeId,
        /// What it waited for, and what the log held at the send.
        release: Release,
    },
    /// A server released its reply to the client's command at `index`.
    Reply {
        /// The server.
        node: NodeId,
        /// The client.
        client: NodeId,
        /// The entry's index.
        index: u64,
        /// The entry's term.
        term: u64,
        /// The server's generation.
        generation: u64,
        /// The server's clock at the release.
        at: u64,
    },
    /// A server crashed: its positions are gone until its restart.
    Crashed {
        /// The server.
        node: NodeId,
    },
    /// A server's restart reopened its log.
    Recovered {
        /// The server.
        node: NodeId,
        /// Every entry the log holds: index and term.
        entries: Vec<(u64, u64)>,
        /// The log's durable last index.
        durable: Option<u64>,
    },
    /// A server's core broke C4's contract: the log refused its write.
    Contract {
        /// The server.
        node: NodeId,
        /// What it broke.
        breach: Breach,
        /// The log's error.
        error: String,
    },
    /// A server's core led a term for the first time (karyos#691: the
    /// custom core's trace checking sees every election, not only those
    /// whose leader commits).
    Leading {
        /// The server.
        node: NodeId,
        /// The term it leads.
        term: u64,
    },
    /// A server's commit index moved.
    Commit {
        /// The server.
        node: NodeId,
        /// Its term then.
        term: u64,
        /// Whether it led then.
        leader: bool,
        /// The new commit index.
        index: u64,
        /// The term of the entry at it.
        entry_term: u64,
    },
    /// A server applied an entry.
    Applied {
        /// The server.
        node: NodeId,
        /// The entry.
        entry: Entry,
        /// What the log held then.
        applying: Applying,
        /// The service's canonical response bytes, for a command.
        response: Option<Vec<u8>>,
    },
    /// A client got a successful answer to the command at `index`.
    Success {
        /// The client.
        client: NodeId,
        /// The entry's index.
        index: u64,
        /// The answering server's generation.
        generation: u64,
    },
    /// A server dropped a peer frame of another cluster identity before
    /// its core saw it (ADR-0123 decision 3), or refused a request for
    /// another identity unjournalled (decision 4).
    ForeignDropped {
        /// The server.
        node: NodeId,
        /// The sender.
        from: NodeId,
        /// The identity it carried.
        cluster: ClusterId,
    },
    /// A client refused an answer of a cluster identity it does not accept.
    ForeignCluster {
        /// The client.
        client: NodeId,
        /// The identity it carried.
        cluster: ClusterId,
    },
    /// An isolated rebuild refused a promotion (ADR-0123 decision 5).
    IsolatedPromotion {
        /// The server.
        node: NodeId,
    },
    /// A client rejected an answer of a generation below one it has seen.
    StaleGeneration {
        /// The client.
        client: NodeId,
        /// The answer's generation.
        generation: u64,
    },
    /// A server's core refused a client request with backpressure (W2):
    /// the client was told, and sends it again.
    Backpressure {
        /// The server.
        node: NodeId,
        /// The client.
        client: NodeId,
        /// The request's sequence.
        sequence: u64,
        /// The limit it named.
        limit: Limit,
    },
    /// A standby server refused a feed entry, and the rest of its send.
    FeedRefused {
        /// The server.
        node: NodeId,
        /// The primary's index of the entry.
        index: u64,
        /// Why.
        reason: FeedRefusal,
    },
    /// A standby server's service applied a primary entry from the feed.
    FeedApplied {
        /// The server.
        node: NodeId,
        /// The primary's index.
        index: u64,
        /// The primary's term.
        term: u64,
        /// The payload.
        payload: Vec<u8>,
    },
    /// The harness verified the fencing a promotion asks for.
    Fenced {
        /// How.
        fencing: Fencing,
        /// For a lease, the end of the last one the holder renewed, on
        /// the holder's clock: its fencing point.
        lease_end: Option<u64>,
    },
    /// The harness refused a promotion: its fencing is not verified.
    PromotionRefused {
        /// The fencing it asked for.
        fencing: Fencing,
    },
    /// A standby server refused a replicated request, range or seal
    /// (ADR-0120).
    ReplicationRefused {
        /// The server.
        node: NodeId,
        /// The source server.
        source: NodeId,
        /// Why.
        refusal: Refusal,
    },
    /// A standby server started a copy of a source's log.
    CopyStarted {
        /// The server.
        node: NodeId,
        /// The source server.
        source: NodeId,
        /// Where the copy starts in the source's log.
        start: u64,
    },
    /// A standby server's recovery point, at a status (ADR-0120 decision
    /// 8).
    RecoveryPoint {
        /// The server.
        node: NodeId,
        /// The point.
        point: RecoveryPoint,
    },
    /// A standby server whose core leads was promoted.
    Promoted {
        /// The server.
        node: NodeId,
        /// What it reports.
        report: PromotionReport,
    },
    /// A server's positions after a duty.
    Positions {
        /// The server.
        node: NodeId,
        /// Its positions.
        positions: Positions,
    },
    /// A server's log refused to open at a restart, or its disk failed:
    /// the environment, not the core.
    OpenFailed {
        /// The server.
        node: NodeId,
        /// The error.
        error: String,
    },
    /// A server's core reports a configuration: at each start, and after a
    /// duty that changed it (before that duty's [`Observation::Commit`]).
    /// Only a core that changes its membership reports one.
    Configuration {
        /// The server.
        node: NodeId,
        /// The configuration.
        configuration: Configuration,
        /// The term of the entry that set it, as the server's log holds it
        /// then; `None` for the bootstrap configuration or an entry not
        /// written yet.
        entry_term: Option<u64>,
    },
    /// A server's service answered a retried request from its
    /// deduplication table (W5).
    Deduplicated {
        /// The server.
        node: NodeId,
        /// The client.
        client: NodeId,
        /// The request's sequence.
        sequence: u64,
    },
    /// A server sent a client's request on to the leader its core named
    /// (W5).
    Redirected {
        /// The server.
        node: NodeId,
        /// The client.
        client: NodeId,
        /// The request's sequence.
        sequence: u64,
        /// The leader named.
        to: NodeId,
    },
    /// A client's retry was answered [`Ret::Expired`]: its outcome is
    /// unknown (W5).
    Expired {
        /// The client.
        client: NodeId,
        /// The request's sequence.
        sequence: u64,
    },
    /// A server's core answered an operator's leadership handover (W5).
    Transfer {
        /// The server.
        node: NodeId,
        /// The target.
        to: NodeId,
        /// What it answered.
        result: Result<(), TransferRefused>,
    },
    /// The harness healed every link ([`super::workloads::Action::Heal`]):
    /// a mark in the order of observations.
    Healed,
    /// The harness split the links between `left` and `right`
    /// ([`super::workloads::Action::Split`]): a mark in the order of
    /// observations, so a check can tell what came after the partition.
    Split {
        /// One side.
        left: Vec<NodeId>,
        /// The other.
        right: Vec<NodeId>,
    },
    /// A leader-relative trigger of a case acted, at harness step `at`
    /// ([`super::workloads::LostReply`], C5 version 2's W5 retry).
    Triggered {
        /// The trigger: `"cut"`, `"lost"`, `"crash"`, `"restart"`, or
        /// `"deadline"` when the deadline's step ended.
        what: &'static str,
        /// The server it acted on, the leader `L`.
        node: NodeId,
        /// The client concerned.
        client: NodeId,
        /// The step.
        at: u64,
        /// For `"lost"`: the request `R`, as (index, term, sequence).
        request: Option<(u64, u64, u64)>,
    },
    /// A server took a snapshot of its service and compacted its log
    /// below `first` (W5): what it dropped, the snapshot holds.
    Compacted {
        /// The server.
        node: NodeId,
        /// The snapshot's base.
        base: SnapshotBase,
        /// The log's first index after the purge.
        first: u64,
    },
    /// A server installed a leader's snapshot (W5): its log restarts after
    /// `base`, and its service holds the state of `digest`.
    Installed {
        /// The server.
        node: NodeId,
        /// The snapshot's base.
        base: SnapshotBase,
        /// The restored service's digest.
        digest: u64,
    },
    /// A server wrote a piece of a leader's snapshot into its store as it
    /// arrived (karyos#682): `length` bytes at `offset` of a service
    /// section of `total`.
    SnapshotPiece {
        /// The server.
        node: NodeId,
        /// The snapshot's base.
        base: SnapshotBase,
        /// The sender's transfer.
        transfer: u64,
        /// Where the piece starts.
        offset: u64,
        /// Its bytes.
        length: u64,
        /// The section's length.
        total: u64,
    },
    /// A server dropped a snapshot piece by [`super::workloads::Case::lose_snapshot_piece`].
    SnapshotPieceLost {
        /// The server.
        node: NodeId,
        /// The snapshot's base.
        base: SnapshotBase,
        /// The sender's transfer.
        transfer: u64,
        /// The piece's offset.
        offset: u64,
    },
    /// A leader sent a piece of a snapshot transfer.
    SnapshotSent {
        /// The leader.
        node: NodeId,
        /// The follower.
        to: NodeId,
        /// The transfer.
        transfer: u64,
        /// The piece's offset.
        offset: u64,
    },
    /// A server dropped a snapshot transfer it was receiving: `"gap"`,
    /// `"superseded"`, `"overtaken"`, `"stalled"`, `"metadata changed"` or
    /// `"write failed"`.
    SnapshotAbandoned {
        /// The server.
        node: NodeId,
        /// The snapshot's base.
        base: SnapshotBase,
        /// The transfer.
        transfer: u64,
        /// Why.
        reason: &'static str,
    },
    /// A server refused a snapshot it was sent.
    SnapshotRefused {
        /// The server.
        node: NodeId,
        /// The snapshot's base.
        base: SnapshotBase,
        /// Why.
        reason: String,
    },
    /// A server's core lacks a capability the case needs: the case is
    /// not demonstrated for it, never passed.
    Unsupported {
        /// The server.
        node: NodeId,
        /// What it lacks.
        what: &'static str,
    },
    /// A server's core answered an operator's membership change.
    Change {
        /// The server.
        node: NodeId,
        /// The change.
        change: Change,
        /// The core's answer: accepted (appended, not yet committed) or
        /// refused.
        result: Result<(), ChangeRefused>,
    },
}

/// What a core broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breach {
    /// An append that is not the next index.
    NotNext,
    /// An entry's term below the last.
    TermBack,
    /// An entry too large for the log.
    TooLarge,
    /// A read or truncation outside the log.
    OutOfRange,
    /// A prefix purge past the commit.
    PurgeBeyondCommit,
    /// A truncation that would remove committed entries.
    TruncateBelowCommit,
    /// A hard state the log refuses.
    HardState,
    /// A commit above the durable last index.
    CommitBeyondDurable,
    /// A commit going back.
    CommitBack,
    /// Still ready after [`super::core::MAX_READIES`] Readys.
    WorkBudget,
}

impl Breach {
    /// The breach `error` is, or `None` for the environment's error.
    #[must_use]
    pub fn of(error: &LogError) -> Option<Self> {
        Some(match error {
            LogError::NotNext { .. } => Self::NotNext,
            LogError::TermBack { .. } => Self::TermBack,
            LogError::TooLarge { .. } => Self::TooLarge,
            LogError::OutOfRange { .. } => Self::OutOfRange,
            LogError::PurgeBeyondCommit { .. } => Self::PurgeBeyondCommit,
            LogError::TruncateBelowCommit { .. } => Self::TruncateBelowCommit,
            LogError::HardState(_) => Self::HardState,
            LogError::CommitBeyondDurable { .. } => Self::CommitBeyondDurable,
            LogError::CommitBack { .. } => Self::CommitBack,
            _ => return None,
        })
    }
}

/// A server's five positions (after SPEC.md §9), as indices (see the
/// module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Positions {
    /// The core's last index, written or not.
    pub received: Option<u64>,
    /// The log's last index written.
    pub written: Option<u64>,
    /// The log's durable last index.
    pub durable: Option<u64>,
    /// The core's commit index.
    pub committed: Option<u64>,
    /// The service's last applied index.
    pub applied: Option<u64>,
}

/// Everything a run's nodes report: the observations, in order, and the
/// clients' history for C3.
#[derive(Debug, Default)]
pub struct Recorder {
    /// Every observation, in order.
    pub observations: Vec<Observation>,
    /// The clients' invocations and returns, in real-time order.
    pub history: History<Op, Ret>,
}

/// A recorder the nodes of one run share.
pub type Shared = Rc<RefCell<Recorder>>;

/// The cluster identity of a run's servers (ADR-0123 decision 1).
pub const HARNESS_CLUSTER: ClusterId = ClusterId([0x4b; 32]);
/// The cluster identity of a run's standby group (decision 6).
pub const HARNESS_STANDBY: ClusterId = ClusterId([0x53; 32]);
const HARNESS_IDENTITY: IdentityRecord = IdentityRecord {
    identity: HARNESS_CLUSTER,
    isolated_from: None,
};

/// The one message type of a harness run.
#[derive(Debug, Clone, PartialEq)]
pub enum Wire<M> {
    /// Between cores, in a peer frame of the sender's cluster identity
    /// (ADR-0123 decision 3).
    Core(ClusterId, M),
    /// A client's request, for the cluster identity it names (ADR-0123
    /// decision 4).
    Request(ClusterId, Command),
    /// A server's answer: `ret` for the command at `index`.
    Response {
        /// The server's cluster identity.
        cluster: ClusterId,
        /// The client's sequence number.
        sequence: u64,
        /// The answer, in canonical response bytes ([`Ret::canonical`]).
        bytes: Vec<u8>,
        /// The entry's index.
        index: u64,
        /// The server's generation.
        generation: u64,
    },
    /// A server cannot take the request.
    Refused {
        /// The server's cluster identity.
        cluster: ClusterId,
        /// The client's sequence number.
        sequence: u64,
    },
    /// The server's core pushed back on the request (W2's backpressure):
    /// the client sends it again after its retry interval, not at once,
    /// so a full queue is not flooded.
    Busy {
        /// The server's cluster identity.
        cluster: ClusterId,
        /// The client's sequence number.
        sequence: u64,
    },
    /// An operator's membership change, which the server's core takes or
    /// refuses ([`Observation::Change`]); nothing answers it.
    Change(Change),
    /// An operator's leadership handover to a server, which the core takes
    /// or refuses ([`Observation::Transfer`]); nothing answers it (W5).
    Transfer(NodeId),
    /// One piece of a leader's snapshot (W5; karyos#682): `bytes` at
    /// `offset` of the service section of the snapshot at `base`, whose
    /// section is `length` bytes and whose whole snapshot's CRC-32C is
    /// `digest`, in transfer `transfer` of its sender. The leader streams
    /// the section from its store through a `SnapshotReader`, at most
    /// [`SNAPSHOT_WINDOW`] pieces of `WRITE_CHUNK` unacknowledged, and the
    /// follower writes each into its own store as it arrives.
    Snapshot {
        /// The sender's cluster identity, as its peer frame carries it.
        cluster: ClusterId,
        /// The snapshot's base.
        base: SnapshotBase,
        /// The sender's term when it started the transfer: with the base
        /// and the transfer, what orders two transfers' starts.
        term: u64,
        /// The sender's transfer.
        transfer: u64,
        /// The whole snapshot's CRC-32C, as the sender's store holds it.
        digest: u32,
        /// The service section's length.
        length: u64,
        /// Where `bytes` start in it.
        offset: u64,
        /// The piece.
        bytes: Vec<u8>,
    },
    /// A follower's acknowledgement of a transfer: it holds the section's
    /// bytes before `next`; once `installed`, it has checked, published and
    /// installed the snapshot (or holds state past it), and only that ends
    /// the sender's transfer.
    SnapshotAck {
        /// The sender's cluster identity, as its peer frame carries it.
        cluster: ClusterId,
        /// The snapshot's base.
        base: SnapshotBase,
        /// The transfer.
        transfer: u64,
        /// The bytes it holds.
        next: u64,
        /// Whether the snapshot is installed.
        installed: bool,
    },
    /// The primary's committed entries after the standby's verified
    /// position, and its commit.
    Feed {
        /// The entries, consecutive unless a fault left one out.
        entries: Vec<FeedEntry>,
        /// The term of the entry before the first, `None` before the log's
        /// first index.
        prev_term: Option<u64>,
        /// The primary leader's commit index.
        commit: Option<u64>,
    },
    /// The standby's verified position, to the primary.
    FeedAck {
        /// The last primary index its service applied.
        verified: Option<u64>,
    },
    /// The harness promotes the standby, the old primary fenced.
    Promote {
        /// How the old primary was fenced.
        fencing: Fencing,
        /// The requests known to be in flight, by client and sequence.
        unknown: Vec<(NodeId, u64)>,
    },
    /// A primary server's Cluster log replication starts at `start`, the
    /// first seal boundary of its epoch at or after its store's start.
    ReplStart {
        /// The position.
        start: u64,
    },
    /// Stored bytes of the source's log, whole frames.
    ReplBytes {
        /// Their position in the source's log.
        position: u64,
        /// The bytes.
        bytes: Vec<u8>,
    },
    /// A `ClusterLog` seal of the replication's epoch.
    ReplSeal {
        /// The seal.
        seal: SealRecord,
    },
    /// The source's status: where its epoch's seals end.
    ReplStatus {
        /// The sealed end.
        sealed: u64,
    },
    /// The source ended its request (`state` 5 `interrupted`).
    ReplEnd,
    /// The standby holds no copy of the sender's request (it restarted,
    /// or its leader changed and discarded the copy): the sender starts
    /// its request again, its byte and seal cursors back at its start
    /// (karyos#714 review).
    ReplReset,
    /// The standby's acknowledgement of a status.
    ReplAck {
        /// Where its copy's received bytes end.
        received: u64,
        /// Where its checked seals end.
        checked: u64,
        /// Whether a seal waited or was refused since the last one: the
        /// sender resends from `received`.
        stalled: bool,
    },
    /// The harness sends a client to another server.
    Redirect {
        /// The cluster identity of the server or operator that sends it
        /// (ADR-0123 decision 4): a client follows only an accepted one.
        cluster: ClusterId,
        /// The server.
        server: NodeId,
    },
}

/// A primary server's feed to the standby.
#[derive(Debug, Clone)]
struct FeedOut {
    /// The standby's servers.
    to: Vec<NodeId>,
    /// The standby's verified position, as acknowledged.
    acked: Option<u64>,
    /// Faults still to apply, one send each, by index.
    faults: BTreeMap<u64, FeedFault>,
}

/// A primary server's Cluster log replication to the standby
/// (ADR-0120).
#[derive(Debug, Clone)]
struct ReplicationOut {
    /// The standby's servers.
    to: Vec<NodeId>,
    /// Damage still to apply in transit, one send each, by the index of
    /// the frame sent.
    faults: BTreeMap<u64, FeedFault>,
    /// The request under way.
    active: Option<ReplicationActive>,
}

/// A replication request under way.
#[derive(Debug, Clone, Copy)]
struct ReplicationActive {
    epoch: u64,
    start: u64,
    /// The next byte to send.
    next: u64,
    /// Where the standby's checked seals end.
    checked: u64,
    /// The standby acknowledged it.
    accepted: bool,
}

/// A standby server's state.
#[derive(Debug, Default)]
struct StandbyIn {
    /// The primary's servers, which acknowledgements go to.
    primary: Vec<NodeId>,
    /// The last primary index the service applied, and its term.
    verified: Option<(u64, u64)>,
    /// The last primary index proposed, and its term.
    proposed: Option<(u64, u64)>,
    /// The last primary commit learnt from the feed.
    learnt: Option<u64>,
    /// Promoted: it takes requests and replies.
    promoted: bool,
    /// Its follower of the primary's Cluster log, when it follows over
    /// replication rather than the feed.
    follower: Option<Standby<ReplicaCheck<SimDisk>>>,
    /// It follows over replication.
    replicated: bool,
    /// Whether its core led at its last duty.
    leading: bool,
    /// A seal waited or was refused since the last acknowledgement.
    stalled: bool,
}

/// A server: a core over C4's log on its own disk, and the test service.
pub struct ServerNode<C: ConsensusCore> {
    id: NodeId,
    peers: Vec<NodeId>,
    geometry: Geometry,
    disk: SimDisk,
    survives: Survives,
    running: Option<(C, RaftLog<SimDisk>)>,
    service: TestService,
    /// Requests this server took, by client and sequence: it answers them.
    pending: BTreeSet<(NodeId, u64)>,
    commit: Option<u64>,
    /// The highest term its core was seen to lead ([`Observation::Leading`]).
    led: Option<u64>,
    /// The configuration last recorded.
    configuration: Option<Configuration>,
    /// The core's configuration stamp when it was last asked.
    configuration_stamp: Option<u64>,
    /// Why the disk cannot come back, when its crash could not be taken.
    lost: Option<String>,
    recorder: Shared,
    /// Its generation: [`FIRST_GENERATION`], one more after a promotion.
    generation: u64,
    /// Its clock at its last tick or delivery.
    now: u64,
    /// The feed to a standby, for a primary server.
    feed: Option<FeedOut>,
    /// The Cluster log replication to a standby, for a primary server.
    replication: Option<ReplicationOut>,
    /// The lease it holds to act, for a primary server.
    lease: Option<Rc<RefCell<ExternalLease>>>,
    /// The standby state, for a standby server.
    standby: Option<StandbyIn>,
    /// The limits its core is declared (W2), at every start.
    limits: Option<Limits>,
    /// Its duty's log-read budget, refilled at each tick and delivery
    /// under [`Limits::log_read_bytes`].
    budget: ReadBudget,
    /// Its compaction, if the case has one (W5).
    compaction: Option<Compaction>,
    /// Its snapshot store, when it compacts.
    snapshots: Option<SnapshotStore<SimDisk>>,
    /// A leader's snapshot being received: its base and the bytes so far,
    /// streamed into the store as they arrive.
    incoming: Option<Incoming>,
    /// The snapshot transfers it sends, by follower.
    outgoing: BTreeMap<NodeId, Outgoing>,
    /// Its next transfer's number.
    next_transfer: u64,
    /// The piece of its first received transfer it drops, and the pieces
    /// of that transfer seen so far; `None` once dropped, or never.
    lose_piece: Option<(u64, u64)>,
    /// Its latest snapshot's base.
    base: Option<SnapshotBase>,
    /// The log bytes of the applied entries since that base, counted up to
    /// the index given: the byte trigger's input.
    since_bytes: (u64, u64),
    /// The fault its driver injects (karyos#1038, tests).
    drive_fault: DriveFault,
    /// Its service answers differently (karyos#1038, tests).
    #[cfg(feature = "test-hooks")]
    alters_responses: bool,
    /// The Ready its core fills in place ([`ConsensusCore::ready_into`]).
    ready: ReadyBuf<C::Message>,
    /// The bytes of the request it proposes, kept across requests.
    command: Vec<u8>,
    /// Its cluster identity record (ADR-0123 decision 1).
    identity: IdentityRecord,
    /// The check of its peers' frames (decision 3).
    gate: PeerGate,
}

/// Why a server could not be created.
#[derive(Debug)]
pub enum ServerError {
    /// The log's refusal to be created.
    Log(LogError),
    /// Its core takes no limits.
    Unsupported(Unsupported),
}

impl From<LogError> for ServerError {
    fn from(error: LogError) -> Self {
        Self::Log(error)
    }
}

/// `step`'s value, or `None` when it panicked: a core's panic caught at
/// the harness's core boundary (karyos#976).
fn caught<R>(step: impl FnOnce() -> R) -> Option<R> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)).ok()
}

impl<C: ConsensusCore> ServerNode<C> {
    /// Server `id` of `peers`, with a new log on `disk`; a crash keeps what
    /// `survives`.
    ///
    /// # Errors
    ///
    /// The log's refusal to be created.
    pub fn new(
        id: NodeId,
        peers: Vec<NodeId>,
        disk: SimDisk,
        survives: Survives,
        geometry: Geometry,
        recorder: Shared,
    ) -> Result<Self, LogError> {
        let mut log = RaftLog::create(disk.clone(), Path::new(LOG_DIR), geometry, 1)?;
        let core = caught(|| C::recover(id, &peers, &mut LogView::new(&mut log)));
        Ok(Self::assemble(
            id,
            peers,
            (disk, survives),
            geometry,
            recorder,
            (core, log),
            None,
        ))
    }

    /// [`ServerNode::new`] under declared `limits` (W2), at its first start
    /// and every restart.
    ///
    /// # Errors
    ///
    /// The log's refusal to be created, and [`Unsupported`] for a core
    /// that takes no limits.
    pub fn with_limits(
        id: NodeId,
        peers: Vec<NodeId>,
        (disk, survives): (SimDisk, Survives),
        geometry: Geometry,
        recorder: Shared,
        limits: Limits,
    ) -> Result<Self, ServerError> {
        Self::create(
            id,
            peers,
            (disk, survives),
            geometry,
            recorder,
            Some(limits),
        )
    }

    fn create(
        id: NodeId,
        peers: Vec<NodeId>,
        (disk, survives): (SimDisk, Survives),
        geometry: Geometry,
        recorder: Shared,
        limits: Option<Limits>,
    ) -> Result<Self, ServerError> {
        let mut log = RaftLog::create(disk.clone(), Path::new(LOG_DIR), geometry, 1)?;
        let core = caught(|| Self::recovered(id, &peers, (limits, None, None), &mut log))
            .transpose()
            .map_err(ServerError::Unsupported)?;
        Ok(Self::assemble(
            id,
            peers,
            (disk, survives),
            geometry,
            recorder,
            (core, log),
            limits,
        ))
    }

    /// A server running `core` over `log`; down, with its panic recorded,
    /// when the core panicked in its recovery (`None`) or in its first
    /// queries (karyos#976).
    fn assemble(
        id: NodeId,
        peers: Vec<NodeId>,
        (disk, survives): (SimDisk, Survives),
        geometry: Geometry,
        recorder: Shared,
        (core, log): (Option<C>, RaftLog<SimDisk>),
        limits: Option<Limits>,
    ) -> Self {
        let queried = core.and_then(|core| {
            caught(|| (core.committed(), core.configuration())).map(|queries| (core, queries))
        });
        let (running, commit, configuration) = match queried {
            Some((core, (commit, configuration))) => (Some((core, log)), commit, configuration),
            None => (None, None, None),
        };
        let panicked = running.is_none();
        let mut server = Self {
            id,
            peers,
            geometry,
            disk,
            survives,
            running,
            service: TestService::default(),
            pending: BTreeSet::new(),
            commit,
            led: None,
            configuration: None,
            configuration_stamp: None,
            lost: None,
            recorder,
            generation: FIRST_GENERATION,
            now: 0,
            feed: None,
            replication: None,
            lease: None,
            standby: None,
            limits,
            budget: ReadBudget::new(),
            identity: HARNESS_IDENTITY,
            gate: PeerGate::new(HARNESS_CLUSTER),
            compaction: None,
            snapshots: None,
            incoming: None,
            outgoing: BTreeMap::new(),
            next_transfer: 1,
            lose_piece: None,
            since_bytes: (0, 0),
            base: None,
            drive_fault: DriveFault::None,
            #[cfg(feature = "test-hooks")]
            alters_responses: false,
            ready: ReadyBuf::default(),
            command: Vec::new(),
        };
        if let Some(configuration) = configuration {
            server.record_configuration(configuration, None);
        }
        if panicked {
            server.observe(Observation::CorePanicked { node: server.id });
        }
        server
    }

    /// Server `id` of `peers` over the log already on `disk`, started as
    /// a restart would; it is down if the log does not open.
    #[must_use]
    pub fn open(
        id: NodeId,
        peers: Vec<NodeId>,
        disk: SimDisk,
        survives: Survives,
        geometry: Geometry,
        recorder: Shared,
    ) -> Self {
        let mut server = Self {
            id,
            peers,
            geometry,
            disk,
            survives,
            running: None,
            service: TestService::default(),
            pending: BTreeSet::new(),
            commit: None,
            led: None,
            configuration: None,
            configuration_stamp: None,
            lost: None,
            recorder,
            generation: FIRST_GENERATION,
            now: 0,
            feed: None,
            replication: None,
            lease: None,
            standby: None,
            limits: None,
            budget: ReadBudget::new(),
            identity: HARNESS_IDENTITY,
            gate: PeerGate::new(HARNESS_CLUSTER),
            compaction: None,
            snapshots: None,
            incoming: None,
            outgoing: BTreeMap::new(),
            next_transfer: 1,
            lose_piece: None,
            since_bytes: (0, 0),
            base: None,
            drive_fault: DriveFault::None,
            #[cfg(feature = "test-hooks")]
            alters_responses: false,
            ready: ReadyBuf::default(),
            command: Vec::new(),
        };
        let _ = server.guarded(Self::start);
        server
    }

    /// Drops piece `piece` (from 0) of the first snapshot transfer it
    /// receives, as if the network lost it ([`super::workloads::Case::lose_snapshot_piece`]).
    #[must_use]
    pub const fn losing_snapshot_piece(mut self, piece: u64) -> Self {
        self.lose_piece = Some((piece, 0));
        self
    }

    /// Compacts its log under `compaction` (W5), with a snapshot store
    /// beside its log; it is lost when the store does not open.
    #[must_use]
    pub fn with_compaction(mut self, compaction: Compaction) -> Self {
        self.compaction = Some(compaction);
        match Self::open_snapshots(&self.disk, self.geometry, compaction.config()) {
            Ok(store) => self.snapshots = Some(store),
            Err(error) => self.lost = Some(error),
        }
        self
    }

    fn open_snapshots(
        disk: &SimDisk,
        geometry: Geometry,
        config: SnapshotConfig,
    ) -> Result<SnapshotStore<SimDisk>, String> {
        SnapshotStore::open(disk.clone(), Path::new(SNAPSHOT_DIR), geometry, config)
            .map(|opened| opened.store)
            .map_err(|error| format!("snapshot store: {error}"))
    }

    /// The service section of `store`'s latest snapshot, and its base.
    fn latest_service(store: &SnapshotStore<SimDisk>) -> Option<(SnapshotBase, Vec<u8>)> {
        Self::service_of(store, store.latest()?)
    }

    /// The snapshot a restarted node stands on: the newest the log's
    /// commit reaches (compacted below it, or installed at it). One past
    /// the commit is staged, an install a crash or a refusal cut short:
    /// the log does not stand on it, and its service state is not yet the
    /// node's (karyos#682).
    fn active_service(
        store: &SnapshotStore<SimDisk>,
        commit: Option<u64>,
    ) -> Option<(SnapshotBase, Vec<u8>)> {
        let commit = commit?;
        let info = store
            .snapshots()
            .iter()
            .rev()
            .find(|info| info.index <= commit)
            .copied()?;
        Self::service_of(store, info)
    }

    /// The service section of snapshot `info`, and its base.
    fn service_of(
        store: &SnapshotStore<SimDisk>,
        info: karyos_cluster::snapshot::SnapshotInfo,
    ) -> Option<(SnapshotBase, Vec<u8>)> {
        let sections = store.read(&info).ok()?;
        let service = sections
            .into_iter()
            .find(|section| section.kind == SectionKind::Service)?;
        Some((
            SnapshotBase {
                index: info.index,
                term: info.term,
            },
            service.bytes,
        ))
    }

    /// Takes a snapshot of its service and compacts its log, when the
    /// store's policy says one is due ([`SnapshotConfig::due`]: entries or
    /// log bytes applied since the last), then purges the log below
    /// [`SnapshotConfig::log_floor`].
    fn compact(&mut self, core: &mut C, log: &mut RaftLog<SimDisk>) {
        let (Some(compaction), Some(store), Some(applied)) = (
            self.compaction,
            self.snapshots.as_mut(),
            self.service.applied(),
        ) else {
            return;
        };
        let config = compaction.config();
        let from = self.base.map_or(0, |base| base.index);
        let Some(entries) = applied.checked_sub(from) else {
            return;
        };
        // The log bytes since the base, counted once per entry.
        let (counted_to, mut bytes) = self.since_bytes;
        let start = counted_to.max(from);
        if start != counted_to {
            bytes = 0;
        }
        let held = log.first_index();
        for index in start.saturating_add(1)..=applied {
            match log.frame_span(index) {
                Some(span) => bytes = bytes.saturating_add(span),
                // Below the log's first index after an install: not this
                // node's bytes to count.
                None if index < held => {}
                None => {
                    return self.observe(Observation::SnapshotRefused {
                        node: self.id,
                        base: SnapshotBase { index, term: 0 },
                        reason: "an applied entry's frame is missing".to_owned(),
                    });
                }
            }
        }
        self.since_bytes = (applied, bytes);
        if !config.due(entries, bytes) {
            return;
        }
        let (Some(term), Some(bytes)) = (log.term(applied), self.service.encode()) else {
            return;
        };
        let written = store.write(
            applied,
            term,
            &[Section::new(
                SectionKind::Service,
                SERVICE_SECTION_VERSION,
                &bytes,
            )],
        );
        if let Err(error) = written {
            self.observe(Observation::SnapshotRefused {
                node: self.id,
                base: SnapshotBase {
                    index: applied,
                    term,
                },
                reason: format!("write: {error}"),
            });
            return;
        }
        let base = SnapshotBase {
            index: applied,
            term,
        };
        self.base = Some(base);
        self.since_bytes = (applied, 0);
        // Below the oldest kept snapshot, but the allowance's bytes.
        let oldest = store.snapshots().first().map_or(applied, |info| info.index);
        let first = log.first_index();
        let mut starts = Vec::new();
        let mut at = 0u64;
        for index in first..=oldest.saturating_add(1) {
            starts.push(at);
            at = at.saturating_add(log.frame_span(index).unwrap_or(0));
        }
        let floor = config.log_floor(first, oldest, |index| {
            index
                .checked_sub(first)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| starts.get(offset).copied())
        });
        if let Err(error) = log.purge_prefix(floor) {
            // The snapshot is published: the core is told of it, and the
            // log keeps what the purge did not remove.
            self.observe(Observation::SnapshotRefused {
                node: self.id,
                base,
                reason: format!("purge: {error}"),
            });
        }
        let first = log.first_index();
        // The duty's budget holds for the hook's reads too.
        let budget = self.limits.map(|_| self.budget.clone());
        if core
            .compacted(
                base,
                &mut LogView::metered(log, budget.as_ref()).with_base(Some(base)),
            )
            .is_err()
        {
            // The core takes no snapshots: never again under it.
            self.compaction = None;
            self.observe(Observation::Unsupported {
                node: self.id,
                what: "compacted",
            });
        }
        self.observe(Observation::Compacted {
            node: self.id,
            base,
            first,
        });
    }

    /// Sends `to`, which needs entries its log no longer holds, its latest
    /// snapshot, streamed from its store as `to` acknowledges it. A
    /// transfer of that snapshot already moving goes on, however often the
    /// core asks; a new one starts only for a newer snapshot, or when the
    /// last has gone [`SNAPSHOT_RETRY`] ticks without an acknowledgement.
    fn send_snapshot(&mut self, to: NodeId, term: u64, out: &mut Outbox<Wire<C::Message>>) {
        let Some(store) = self.snapshots.as_ref() else {
            return;
        };
        let Some(info) = store.latest() else {
            return;
        };
        if self.outgoing.get(&to).is_some_and(|outgoing| {
            outgoing.base.index == info.index
                && self.now.saturating_sub(outgoing.moved) <= SNAPSHOT_RETRY
        }) {
            return;
        }
        let Ok(mut reader) = store.reader(&info) else {
            return;
        };
        let length = loop {
            match reader.next_section() {
                Ok(Some(header)) if header.kind == SectionKind::Service => break header.length,
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return,
            }
        };
        let transfer = self.next_transfer;
        self.next_transfer = transfer.saturating_add(1);
        let outgoing = Outgoing {
            term,
            transfer,
            base: SnapshotBase {
                index: info.index,
                term: info.term,
            },
            digest: info.digest,
            length,
            reader,
            sent: 0,
            acked: 0,
            moved: self.now,
        };
        let _ = self.outgoing.insert(to, outgoing);
        self.pump_snapshot(to, out);
    }

    /// Sends `to` the next pieces of its transfer that fit the window. The
    /// last is sent only once the reader has checked the snapshot's end:
    /// a snapshot that does not verify is not sent whole.
    fn pump_snapshot(&mut self, to: NodeId, out: &mut Outbox<Wire<C::Message>>) {
        let cluster = self.identity.identity;
        let Some(outgoing) = self.outgoing.get_mut(&to) else {
            return;
        };
        let window = SNAPSHOT_WINDOW.saturating_mul(WRITE_CHUNK as u64);
        let mut broken = false;
        while outgoing.sent < outgoing.length
            && outgoing.sent.saturating_sub(outgoing.acked) < window
        {
            let left = outgoing.length - outgoing.sent;
            let take = usize::try_from(left)
                .unwrap_or(WRITE_CHUNK)
                .min(WRITE_CHUNK);
            let mut bytes = vec![0u8; take];
            let read = match outgoing.reader.read(&mut bytes) {
                Ok(read) if read > 0 => read,
                _ => {
                    broken = true;
                    break;
                }
            };
            bytes.truncate(read);
            let read = read as u64;
            // The last piece waits for the end's check: the digest over the
            // whole snapshot.
            if outgoing.sent.saturating_add(read) >= outgoing.length
                && !matches!(outgoing.reader.next_section(), Ok(None))
            {
                broken = true;
                break;
            }
            self.recorder
                .borrow_mut()
                .observations
                .push(Observation::SnapshotSent {
                    node: self.id,
                    to,
                    transfer: outgoing.transfer,
                    offset: outgoing.sent,
                });
            out.push((
                to,
                Wire::Snapshot {
                    cluster,
                    base: outgoing.base,
                    term: outgoing.term,
                    transfer: outgoing.transfer,
                    digest: outgoing.digest,
                    length: outgoing.length,
                    offset: outgoing.sent,
                    bytes,
                },
            ));
            outgoing.sent = outgoing.sent.saturating_add(read);
        }
        if broken {
            let _ = self.outgoing.remove(&to);
        }
    }

    /// A follower's acknowledgement: the window moves, and a transfer ends
    /// only once the follower has installed it. One received whole but not
    /// installed (its check or its install failed) waits, and once it has
    /// gone [`SNAPSHOT_RETRY`] ticks without moving the core's next ask
    /// starts it again.
    fn snapshot_acked(
        &mut self,
        from: NodeId,
        (base, transfer, next, installed): (SnapshotBase, u64, u64, bool),
        out: &mut Outbox<Wire<C::Message>>,
    ) {
        let Some(outgoing) = self.outgoing.get_mut(&from) else {
            return;
        };
        if outgoing.transfer != transfer || outgoing.base != base {
            return;
        }
        if installed {
            let _ = self.outgoing.remove(&from);
            return;
        }
        let acked = next.min(outgoing.sent);
        if acked > outgoing.acked {
            outgoing.acked = acked;
            outgoing.moved = self.now;
        }
        self.pump_snapshot(from, out);
    }

    /// Drops the transfer it receives, with `reason`.
    fn abandon_incoming(&mut self, reason: &'static str) {
        let Some(incoming) = self.incoming.take() else {
            return;
        };
        if let Some(store) = self.snapshots.as_mut() {
            let _ = store.abandon(incoming.pending);
        }
        self.observe(Observation::SnapshotAbandoned {
            node: self.id,
            base: incoming.base,
            transfer: incoming.transfer,
            reason,
        });
    }

    /// Drops a transfer its service has overtaken, or that has gone
    /// [`SNAPSHOT_STALL`] ticks without a piece.
    fn expire_incoming(&mut self) {
        let Some(incoming) = self.incoming.as_ref() else {
            return;
        };
        let overtaken = self
            .service
            .applied()
            .is_some_and(|applied| incoming.base.index <= applied);
        let stalled = self.now.saturating_sub(incoming.last) > SNAPSHOT_STALL;
        if overtaken {
            self.abandon_incoming("overtaken");
        } else if stalled {
            self.abandon_incoming("stalled");
        }
    }

    /// Reopens its snapshot store after a failure that leaves it refusing
    /// writes: what was published stays, what was not is removed.
    fn reopen_snapshots(&mut self) {
        let Some(compaction) = self.compaction else {
            return;
        };
        match Self::open_snapshots(&self.disk, self.geometry, compaction.config()) {
            Ok(store) => self.snapshots = Some(store),
            Err(error) => self.lost = Some(error),
        }
    }

    /// Takes one piece of a leader's snapshot. The first piece of a
    /// transfer starts it, superseding the one it receives only when it is
    /// newer: a later base, a later sender's term at the same base, or a
    /// later transfer of the same sender and term; every next piece must repeat the transfer's metadata
    /// and continue it exactly: a duplicate is acknowledged again and
    /// changes nothing, a gap drops the transfer (its leader asks again),
    /// and a piece of another transfer is ignored. Each piece is written
    /// into the store as it arrives and acknowledged; the last seals the
    /// snapshot, which is read back and checked before it is published and
    /// installed, and only then acknowledged installed. A snapshot already
    /// staged at that base is installed without being received again; a
    /// piece of a base its state has reached is acknowledged installed.
    fn receive_snapshot(
        &mut self,
        core: &mut C,
        log: &mut RaftLog<SimDisk>,
        (from, piece): (NodeId, Piece),
        out: &mut Outbox<Wire<C::Message>>,
    ) {
        let node = self.id;
        let cluster = self.identity.identity;
        self.expire_incoming();
        let ack = |out: &mut Outbox<Wire<C::Message>>, next: u64, installed: bool| {
            out.push((
                from,
                Wire::SnapshotAck {
                    cluster,
                    base: piece.base,
                    transfer: piece.transfer,
                    next,
                    installed,
                },
            ));
        };
        if self
            .service
            .applied()
            .is_some_and(|applied| piece.base.index <= applied)
        {
            // It holds that state already: an installed acknowledgement
            // lost, or a transfer it no longer needs.
            return ack(out, piece.length, true);
        }
        if let Some((lose, seen)) = self.lose_piece.as_mut() {
            if *seen == *lose {
                self.lose_piece = None;
                return self.observe(Observation::SnapshotPieceLost {
                    node,
                    base: piece.base,
                    transfer: piece.transfer,
                    offset: piece.offset,
                });
            }
            *seen += 1;
        }
        let current = self
            .incoming
            .as_ref()
            .is_some_and(|incoming| incoming.from == from && incoming.transfer == piece.transfer);
        if !current {
            if piece.offset != 0 {
                // A piece of a transfer it is not receiving: stale.
                return;
            }
            if let Some(incoming) = self.incoming.as_ref() {
                let start = (piece.base.index, piece.term);
                let held = (incoming.base.index, incoming.term);
                let newer = start > held
                    || (start == held
                        && from == incoming.from
                        && piece.transfer > incoming.transfer);
                if !newer {
                    return;
                }
                self.abandon_incoming("superseded");
            }
            let Some(store) = self.snapshots.as_mut() else {
                return self.observe(Observation::SnapshotRefused {
                    node,
                    base: piece.base,
                    reason: "no snapshot store".to_owned(),
                });
            };
            // A retry of an install a refusal or a crash cut short finds
            // the snapshot staged: verified, it is reused, not received
            // again.
            let staged = store.latest().is_some_and(|info| {
                info.index == piece.base.index
                    && info.term == piece.base.term
                    && info.digest == piece.digest
                    && store.verify(&info).is_ok()
            });
            if staged {
                if self.install_snapshot(core, log, piece.base) {
                    ack(out, piece.length, true);
                }
                return;
            }
            let mut pending = match store.begin(piece.base.index, piece.base.term) {
                Ok(pending) => pending,
                Err(error) => {
                    return self.observe(Observation::SnapshotRefused {
                        node,
                        base: piece.base,
                        reason: format!("begin: {error}"),
                    });
                }
            };
            if let Err(error) =
                pending.section(SectionKind::Service, SERVICE_SECTION_VERSION, piece.length)
            {
                let _ = store.abandon(pending);
                return self.observe(Observation::SnapshotRefused {
                    node,
                    base: piece.base,
                    reason: format!("section: {error}"),
                });
            }
            self.incoming = Some(Incoming {
                from,
                term: piece.term,
                transfer: piece.transfer,
                base: piece.base,
                digest: piece.digest,
                length: piece.length,
                pending,
                last: self.now,
            });
        }
        let Some(incoming) = self.incoming.as_mut() else {
            return;
        };
        if piece.base != incoming.base
            || piece.digest != incoming.digest
            || piece.length != incoming.length
        {
            return self.abandon_incoming("metadata changed");
        }
        let expected = incoming.length - incoming.pending.left();
        let pieced = u64::try_from(piece.bytes.len()).unwrap_or(u64::MAX);
        if piece.offset < expected {
            // A duplicate: it holds it already.
            return ack(out, expected, false);
        }
        if piece.offset > expected || pieced > incoming.pending.left() {
            return self.abandon_incoming("gap");
        }
        if let Err(error) = incoming.pending.write(&piece.bytes) {
            self.abandon_incoming("write failed");
            return self.observe(Observation::SnapshotRefused {
                node,
                base: piece.base,
                reason: format!("write: {error}"),
            });
        }
        incoming.last = self.now;
        let next = expected.saturating_add(pieced);
        self.observe(Observation::SnapshotPiece {
            node,
            base: piece.base,
            transfer: piece.transfer,
            offset: piece.offset,
            length: pieced,
            total: piece.length,
        });
        if next < piece.length {
            return ack(out, next, false);
        }
        // The last piece: acknowledged only once the snapshot is installed.
        let Some(incoming) = self.incoming.take() else {
            return;
        };
        if self.finish_snapshot(core, log, incoming) {
            ack(out, next, true);
        }
    }

    /// Seals a received snapshot, reads it back and checks it (its digest
    /// is the sender's, its service decodes at its base) before publishing
    /// it, keeping the snapshot the node stands on from the purge, then
    /// installs it: whether it did.
    fn finish_snapshot(
        &mut self,
        core: &mut C,
        log: &mut RaftLog<SimDisk>,
        incoming: Incoming,
    ) -> bool {
        let node = self.id;
        let base = incoming.base;
        let refuse = |this: &Self, reason: String| {
            this.observe(Observation::SnapshotRefused { node, base, reason });
            false
        };
        let Some(store) = self.snapshots.as_mut() else {
            return refuse(self, "no snapshot store".to_owned());
        };
        let sealed = match store.seal(incoming.pending) {
            Ok(sealed) => sealed,
            Err(error) => {
                let failed = matches!(error, SnapshotError::Failed);
                let refused = refuse(self, format!("seal: {error}"));
                if failed {
                    self.reopen_snapshots();
                }
                return refused;
            }
        };
        let info = sealed.info();
        let service = store.read(&info).ok().and_then(|sections| {
            sections
                .into_iter()
                .find(|section| section.kind == SectionKind::Service)
                .and_then(|section| TestService::decode(&section.bytes))
        });
        let valid = info.digest == incoming.digest
            && service
                .as_ref()
                .is_some_and(|service| service.applied() == Some(base.index));
        if !valid {
            let _ = store.abandon_sealed(sealed);
            return refuse(
                self,
                "a snapshot not its sender's, or not at its base".to_owned(),
            );
        }
        let pin = self.base.and_then(|active| {
            store
                .snapshots()
                .iter()
                .find(|kept| kept.index == active.index && kept.term == active.term)
                .map(|kept| kept.id)
        });
        if let Err(error) = store.publish_sealed(sealed, pin) {
            let failed = matches!(
                error,
                SnapshotError::Failed | SnapshotError::Store(_) | SnapshotError::Io(_)
            );
            let refused = refuse(self, format!("publish: {error}"));
            if failed {
                self.reopen_snapshots();
            }
            return refused;
        }
        self.install_snapshot(core, log, base)
    }

    /// Installs a leader's snapshot its store holds published at `base`:
    /// the log restarts after it, the service restores it, and the core is
    /// told; any refusal is recorded and changes nothing further. Whether
    /// its log and service now stand on it.
    fn install_snapshot(
        &mut self,
        core: &mut C,
        log: &mut RaftLog<SimDisk>,
        base: SnapshotBase,
    ) -> bool {
        let node = self.id;
        let refuse = |this: &Self, reason: String| {
            this.observe(Observation::SnapshotRefused { node, base, reason });
            false
        };
        let Some(store) = self.snapshots.as_mut() else {
            return refuse(self, "no snapshot store".to_owned());
        };
        let Some((published, bytes)) = Self::latest_service(store) else {
            return refuse(self, "no service section".to_owned());
        };
        if published != base {
            return refuse(self, "another snapshot is the latest".to_owned());
        }
        let Some(service) = TestService::decode(&bytes) else {
            return refuse(self, "malformed service section".to_owned());
        };
        if service.applied() != Some(base.index) {
            return refuse(self, "service section not at its base".to_owned());
        }
        if let Err(error) = log.install(base.index, base.term, store) {
            return refuse(self, format!("install: {error}"));
        }
        self.base = Some(base);
        let digest = service.digest();
        let base_time = service.log_time();
        let configuration = service.configuration().map(<[u8]>::to_vec);
        self.service = service;
        self.observe(Observation::Installed { node, base, digest });
        let budget = self.limits.map(|_| self.budget.clone());
        if let Err(refused) = core.install(
            base,
            &mut LogView::metered(log, budget.as_ref())
                .with_base(Some(base))
                .with_base_time(Some(base_time))
                .with_base_configuration(configuration),
        ) {
            match refused {
                super::core::InstallRefused::Unsupported => {
                    self.compaction = None;
                    self.observe(Observation::Unsupported {
                        node,
                        what: "install",
                    });
                }
                super::core::InstallRefused::Stale => {
                    let _ = refuse(self, "the core holds the base already".to_owned());
                }
            }
        }
        true
    }

    /// Feeds its committed entries to the standby servers `to` while its
    /// core leads, applying each of `faults` to one send of its index.
    #[must_use]
    pub fn with_feed(mut self, to: Vec<NodeId>, faults: &[(u64, FeedFault)]) -> Self {
        self.feed = Some(FeedOut {
            to,
            acked: None,
            faults: faults.iter().copied().collect(),
        });
        self
    }

    /// Takes a command and releases a reply only while it holds `lease`,
    /// which it renews while its core leads.
    #[must_use]
    pub fn with_lease(mut self, lease: Rc<RefCell<ExternalLease>>) -> Self {
        self.lease = Some(lease);
        self
    }

    /// Replicates its Cluster log to the standby servers `to` while its
    /// core leads (ADR-0120), damaging in transit one send of each frame
    /// `faults` names.
    #[must_use]
    pub fn with_replication(mut self, to: Vec<NodeId>, faults: &[(u64, FeedFault)]) -> Self {
        self.replication = Some(ReplicationOut {
            to,
            faults: faults.iter().copied().collect(),
            active: None,
        });
        self
    }

    /// A standby server that follows the primary's Cluster log over
    /// replication rather than the feed (after [`ServerNode::as_standby`]).
    #[must_use]
    pub fn over_replication(mut self) -> Self {
        let follower = follower_on(&self.disk);
        if let Some(standby) = self.standby.as_mut() {
            standby.replicated = true;
            standby.follower = follower;
        }
        self
    }

    /// A standby server, fed by the servers `primary`. Its group has its
    /// own cluster identity (ADR-0123 decision 6), [`HARNESS_STANDBY`].
    #[must_use]
    pub fn as_standby(mut self, primary: Vec<NodeId>) -> Self {
        self.standby = Some(StandbyIn {
            primary,
            ..StandbyIn::default()
        });
        self.with_identity(IdentityRecord {
            identity: HARNESS_STANDBY,
            isolated_from: None,
        })
    }

    /// The server under `identity` (ADR-0123): its frames carry it, its
    /// gate admits only it, and an isolated record keeps it from taking
    /// requests, replying or being promoted.
    #[must_use]
    pub fn with_identity(mut self, identity: IdentityRecord) -> Self {
        self.identity = identity;
        self.gate = PeerGate::new(identity.identity);
        if identity.isolated()
            && let Some(follower) = self.standby.as_mut().and_then(|s| s.follower.as_mut())
        {
            follower.isolate();
        }
        self
    }

    /// Its cluster identity record.
    #[must_use]
    pub fn identity(&self) -> IdentityRecord {
        self.identity
    }

    /// The peer frames and requests it dropped for another identity.
    #[must_use]
    pub fn foreign_dropped(&self) -> u64 {
        self.gate.dropped()
    }

    /// Whether `message` from `from` passes the identity checks (ADR-0123
    /// decisions 3 and 4): a peer frame or a request of another identity is
    /// dropped before the core sees it, counted and observed.
    fn admitted(
        &mut self,
        from: NodeId,
        message: &Wire<C::Message>,
        _out: &mut Outbox<Wire<C::Message>>,
    ) -> bool {
        let cluster = match message {
            Wire::Core(cluster, _)
            | Wire::Request(cluster, _)
            | Wire::Snapshot { cluster, .. }
            | Wire::SnapshotAck { cluster, .. } => *cluster,
            _ => return true,
        };
        match self.gate.admit(u64::from(from), cluster) {
            Admission::Admit => true,
            Admission::DroppedFirst | Admission::Dropped => {
                self.observe(Observation::ForeignDropped {
                    node: self.id,
                    from,
                    cluster,
                });
                false
            }
        }
    }

    /// Its core over `log`, under `limits` when it has them.
    fn recovered(
        id: NodeId,
        peers: &[NodeId],
        (limits, base, restored): (Option<Limits>, Option<SnapshotBase>, Option<&TestService>),
        log: &mut RaftLog<SimDisk>,
    ) -> Result<C, Unsupported> {
        // The core sees the snapshot its node recovers over (karyos#903
        // review), its log time (ADR-0111) and the configuration at its
        // base (karyos#711).
        let mut view = LogView::new(log)
            .with_base(base)
            .with_base_time(restored.map(TestService::log_time))
            .with_base_configuration(
                restored
                    .and_then(TestService::configuration)
                    .map(<[u8]>::to_vec),
            );
        match limits {
            Some(limits) => C::recover_with(id, peers, &limits, &mut view),
            None => Ok(C::recover(id, peers, &mut view)),
        }
    }

    /// A new duty: its read budget refilled, when it has limits (a handle
    /// on the same budget).
    fn refill(&self) -> Option<ReadBudget> {
        let limits = self.limits?;
        self.budget.refill(limits.log_read_bytes);
        Some(self.budget.clone())
    }

    /// Its generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether it takes requests: not an isolated rebuild (ADR-0123
    /// decision 5), not a standby that waits for its promotion, and not a
    /// lease holder past its lease.
    fn acts(&self) -> bool {
        !self.identity.isolated()
            && self.standby.as_ref().is_none_or(|standby| standby.promoted)
            && self
                .lease
                .as_ref()
                .is_none_or(|lease| lease.borrow().held_at(self.now))
    }

    /// A clean shutdown (karyos#1050 review): the server stops and its log
    /// closes, sealing its committed tail; a restart reopens it.
    ///
    /// # Errors
    ///
    /// The log's close error.
    pub fn shutdown(&mut self) -> Result<(), LogError> {
        match self.running.take() {
            Some((_, log)) => log.close(),
            None => Ok(()),
        }
    }

    /// Whether it is up: its log open and its core running.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.running.is_some()
    }

    /// The core, while up.
    #[must_use]
    pub fn core(&self) -> Option<&C> {
        self.running.as_ref().map(|(core, _)| core)
    }

    /// The test service.
    #[must_use]
    pub fn service(&self) -> &TestService {
        &self.service
    }

    fn observe(&self, observation: Observation) {
        self.recorder.borrow_mut().observations.push(observation);
    }

    /// The server with `drive` injected into its driver and, with
    /// `alters_responses`, its service's recorded answers altered: the
    /// faults that show the harness checks catch a faulty driver, disk or
    /// service with a real core behind them (karyos#1038, tests).
    #[must_use]
    #[cfg(feature = "test-hooks")]
    pub fn with_faults(mut self, drive: DriveFault, alters_responses: bool) -> Self {
        self.drive_fault = drive;
        self.alters_responses = alters_responses;
        self
    }

    /// Drives the core, then records its commit and positions.
    fn duty(&mut self, out: &mut Outbox<Wire<C::Message>>) {
        let Some((mut core, mut log)) = self.running.take() else {
            return;
        };
        let node = self.id;
        let cluster = self.identity.identity;
        let recorder = Rc::clone(&self.recorder);
        let mut applied = Vec::new();
        let mut snapshot_to = Vec::new();
        let budget = self.limits.is_some().then_some(&self.budget);
        let driven = drive_inner(
            &mut core,
            &mut log,
            &mut self.ready,
            (budget, self.base, self.drive_fault),
            &mut |to, message, release| {
                if let Some(release) = release {
                    recorder
                        .borrow_mut()
                        .observations
                        .push(Observation::Released { node, to, release });
                }
                out.push((to, Wire::Core(cluster, message)));
            },
            &mut |entry, applying| applied.push((entry.clone(), applying)),
            &mut |step| {
                if let Step::SnapshotTo(to) = step {
                    snapshot_to.push(to);
                }
                recorder
                    .borrow_mut()
                    .observations
                    .push(Observation::Drive { node, step });
            },
        );
        if let Err(error) = driven {
            // The node stops until a restart reopens the log.
            let observation = match &error {
                DriveError::Log(error) => match Breach::of(error) {
                    Some(breach) => Observation::Contract {
                        node,
                        breach,
                        error: error.to_string(),
                    },
                    None => Observation::OpenFailed {
                        node,
                        error: error.to_string(),
                    },
                },
                DriveError::WorkBudget { readies } => Observation::Contract {
                    node,
                    breach: Breach::WorkBudget,
                    error: format!("still ready after {readies} Readys"),
                },
            };
            self.observe(observation);
            return;
        }
        let acts = self.acts();
        let verified_before = self.standby.as_ref().and_then(|standby| standby.verified);
        for (entry, applying) in applied {
            // A snapshot already holds it (W5): the service skips it.
            if self
                .service
                .applied()
                .is_some_and(|applied| entry.index <= applied)
                && self.base.is_some()
            {
                continue;
            }
            // A standby's service applies the primary entry an entry
            // wraps, once.
            let mut served = entry.clone();
            if let Some(standby) = self.standby.as_mut()
                && let Some((index, term, payload)) = standby::unwrap(&entry.payload)
            {
                if standby
                    .verified
                    .is_none_or(|(verified, _)| index > verified)
                {
                    standby.verified = Some((index, term));
                    if let Some(follower) = standby.follower.as_mut() {
                        follower.applied(Position { index, term });
                    }
                    if standby
                        .proposed
                        .is_none_or(|(proposed, _)| index > proposed)
                    {
                        standby.proposed = Some((index, term));
                    }
                    served.payload = payload.to_vec();
                    recorder
                        .borrow_mut()
                        .observations
                        .push(Observation::FeedApplied {
                            node,
                            index,
                            term,
                            payload: payload.to_vec(),
                        });
                } else {
                    // Applied before: the service only moves its position.
                    served.payload = Vec::new();
                }
            }
            if C::is_configuration_entry(&served.payload) {
                self.service.set_configuration(&served.payload);
            }
            let deduplicated = self.service.deduplicated();
            let answer = self.service.apply(&served);
            // A faulty service (tests): another valid answer, both recorded
            // and sent.
            #[cfg(feature = "test-hooks")]
            let answer = match answer {
                Some((command, ret)) if self.alters_responses => Some((command, ret.altered())),
                other => other,
            };
            let replayed = self.service.deduplicated() > deduplicated;
            let response = answer.as_ref().map(|(_, ret)| ret.canonical());
            if let Some((command, ret)) = answer
                && self.pending.remove(&(command.client, command.sequence))
                && acts
            {
                // The evidence of a retry is a retained answer actually sent
                // to a waiting client, not a replica's application.
                if replayed {
                    self.observe(Observation::Deduplicated {
                        node,
                        client: command.client,
                        sequence: command.sequence,
                    });
                }
                self.observe(Observation::Reply {
                    node,
                    client: command.client,
                    index: entry.index,
                    term: entry.term,
                    generation: self.generation,
                    at: self.now,
                });
                out.push((
                    command.client,
                    Wire::Response {
                        cluster: self.identity.identity,
                        sequence: command.sequence,
                        bytes: ret.canonical(),
                        index: entry.index,
                        generation: self.generation,
                    },
                ));
            }
            self.observe(Observation::Applied {
                node,
                entry,
                applying,
                response,
            });
        }
        // A standby's leader acknowledges a verified position that moved.
        if let Some(standby) = &self.standby
            && standby.follower.is_none()
            && standby.verified != verified_before
            && core.leads()
        {
            let verified = standby.verified.map(|(index, _)| index);
            for &to in &standby.primary {
                out.push((to, Wire::FeedAck { verified }));
            }
        }
        // A standby leader change (ADR-0120 decision 7): the new leader
        // rebuilds V from its own log, as its service applied it, and
        // discards any copy it held.
        if let Some(standby) = self.standby.as_mut() {
            let leads = core.leads();
            if leads
                && !standby.leading
                && let Some(follower) = standby.follower.as_mut()
            {
                follower.rebuild(
                    standby
                        .verified
                        .map(|(index, term)| Position { index, term }),
                );
            }
            standby.leading = leads;
        }
        // Asked only when the core says it may have moved: building it
        // allocates, and the replication path must not (ADR-0105).
        let stamp = core.configuration_stamp();
        let moved = stamp.is_none() || stamp != self.configuration_stamp;
        self.configuration_stamp = stamp;
        if moved
            && let Some(configuration) = core.configuration()
            && self.configuration.as_ref() != Some(&configuration)
        {
            let entry_term = configuration.index.and_then(|index| log.term(index));
            self.record_configuration(configuration, entry_term);
        }
        if core.leads() && self.led < Some(core.term()) {
            self.led = Some(core.term());
            self.observe(Observation::Leading {
                node,
                term: core.term(),
            });
        }
        let committed = core.committed();
        if committed > self.commit
            && let Some(index) = committed
        {
            self.observe(Observation::Commit {
                node,
                term: core.term(),
                leader: core.leads(),
                index,
                entry_term: log.term(index).unwrap_or(0),
            });
            self.commit = committed;
        }
        self.compact(&mut core, &mut log);
        self.expire_incoming();
        for to in snapshot_to {
            self.send_snapshot(to, core.term(), out);
        }
        self.positions(&core, &log);
        self.running = Some((core, log));
    }

    fn record_configuration(&mut self, configuration: Configuration, entry_term: Option<u64>) {
        self.observe(Observation::Configuration {
            node: self.id,
            configuration: configuration.clone(),
            entry_term,
        });
        self.configuration = Some(configuration);
    }

    fn positions(&self, core: &C, log: &RaftLog<SimDisk>) {
        self.observe(Observation::Positions {
            node: self.id,
            positions: Positions {
                received: core.received(),
                // An installed log that holds nothing yet: the snapshot
                // holds up to its base, durably.
                written: log
                    .last_index()
                    .or_else(|| log.base().map(|(index, _)| index)),
                durable: log
                    .durable_index()
                    .or_else(|| log.base().map(|(index, _)| index)),
                committed: core.committed(),
                applied: self.service.applied(),
            },
        });
    }

    /// Opens the log and recovers the core from it.
    fn start(&mut self) {
        if let Some(error) = self.lost.clone() {
            self.observe(Observation::OpenFailed {
                node: self.id,
                error,
            });
            return;
        }
        // A transfer a crash cut short is gone: the store's reopen removes
        // what it wrote, unpublished.
        self.incoming = None;
        self.outgoing.clear();
        self.since_bytes = (0, 0);
        if let Some(compaction) = self.compaction {
            match Self::open_snapshots(&self.disk, self.geometry, compaction.config()) {
                Ok(store) => self.snapshots = Some(store),
                Err(error) => {
                    self.observe(Observation::OpenFailed {
                        node: self.id,
                        error,
                    });
                    return;
                }
            }
        }
        let opened = RaftLog::open_with(
            self.disk.clone(),
            Path::new(LOG_DIR),
            self.geometry,
            self.snapshots.as_ref(),
        );
        let mut log = match opened {
            Ok(opened) => opened.log,
            Err(error) => {
                self.observe(Observation::OpenFailed {
                    node: self.id,
                    error: error.to_string(),
                });
                return;
            }
        };
        let commit = log.hard_state().and_then(|state| state.commit);
        let latest = self
            .snapshots
            .as_ref()
            .and_then(|store| Self::active_service(store, commit));
        self.base = latest.as_ref().map(|(base, _)| *base);
        // The snapshot's service: its log time is the C-TIME watermark of
        // a log empty after it (ADR-0111, decision 4), and it holds the
        // configuration at its base (karyos#711).
        let restored = latest
            .as_ref()
            .and_then(|(_, bytes)| TestService::decode(bytes));
        let first = log.first_index();
        let entries: Vec<(u64, u64)> = log
            .last_index()
            .map(|last| {
                (first..=last)
                    .filter_map(|index| log.term(index).map(|term| (index, term)))
                    .collect()
            })
            .unwrap_or_default();
        self.observe(Observation::Recovered {
            node: self.id,
            entries,
            durable: log.durable_index(),
        });
        let recovering = (self.limits, self.base, restored.as_ref());
        let core = match Self::recovered(self.id, &self.peers, recovering, &mut log) {
            Ok(core) => core,
            // The core took its limits at its creation: it is not the
            // same core if it refuses them now.
            Err(Unsupported) => {
                self.lost = Some("its core no longer takes its limits".to_owned());
                return;
            }
        };
        // The service's state is its latest snapshot's, then rebuilt from
        // the log as the core hands out its committed entries again (those
        // the snapshot holds are skipped); the recovered commit is a
        // baseline, not a new commit.
        self.service = latest
            .and_then(|(_, bytes)| TestService::decode(&bytes))
            .unwrap_or_default();
        self.commit = core.committed();
        // A standby rebuilds its verified position as its service does.
        if let Some(standby) = self.standby.as_mut() {
            standby.verified = None;
            standby.proposed = None;
            standby.leading = false;
            standby.stalled = false;
            // Its replica's journal and catalog reopen on the disk the
            // crash left; V is rebuilt as its service applies its log.
            if standby.replicated {
                standby.follower = follower_on(&self.disk);
            }
        }
        // Recorded at every start, so a check compares it with the log; the
        // new core's stamp starts again.
        self.configuration_stamp = core.configuration_stamp();
        if let Some(configuration) = core.configuration() {
            let entry_term = configuration.index.and_then(|index| log.term(index));
            self.record_configuration(configuration, entry_term);
        }
        self.positions(&core, &log);
        self.running = Some((core, log));
    }
}

impl<C: ConsensusCore> ServerNode<C> {
    /// Runs `step` on the server; a panic of its core is caught, recorded
    /// as [`Observation::CorePanicked`] and stops the server (karyos#976).
    /// What `step` pushed to `out` before the panic is kept: it was sent.
    fn guarded<R>(&mut self, step: impl FnOnce(&mut Self) -> R) -> Option<R> {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| step(&mut *self)));
        match caught {
            Ok(value) => Some(value),
            Err(_) => {
                // The core and its log view are in an unknown state: both
                // are dropped, as at a crash, but the disk is kept.
                self.running = None;
                self.pending.clear();
                self.observe(Observation::CorePanicked { node: self.id });
                None
            }
        }
    }

    fn tick_unguarded(&mut self, now: u64, out: &mut Outbox<Wire<C::Message>>) {
        self.now = now;
        let budget = self.refill();
        if let Some((core, log)) = self.running.as_mut() {
            core.tick(
                now,
                &mut LogView::metered(log, budget.as_ref()).with_base(self.base),
            );
            // The log's seal duty on the harness clock (karyos#1050
            // review): a committed tail waits at most `SEAL_TICKS` ticks
            // unsealed. A failed seal poisons the log; the next drive
            // stops the server.
            log.set_seal_interval(SEAL_TICKS);
            let _ = log.tick(now);
            if core.leads() {
                if let Some(lease) = &self.lease {
                    let mut lease = lease.borrow_mut();
                    if lease.renewing {
                        lease.renewed_at = Some(now);
                    }
                }
                if let Some(feed) = self.feed.as_mut()
                    && now.is_multiple_of(FEED_PERIOD)
                {
                    send_feed(feed, core.committed(), log, out);
                }
            }
            if let Some(replication) = self.replication.as_mut()
                && now.is_multiple_of(FEED_PERIOD)
            {
                send_replication(replication, core.leads(), log, out);
            }
        }
        self.duty(out);
    }

    fn deliver_unguarded(
        &mut self,
        from: NodeId,
        message: Wire<C::Message>,
        now: u64,
        out: &mut Outbox<Wire<C::Message>>,
    ) {
        self.now = now;
        if !self.admitted(from, &message, out) {
            return;
        }
        if let Wire::SnapshotAck {
            cluster: _,
            base,
            transfer,
            next,
            installed,
        } = message
        {
            self.snapshot_acked(from, (base, transfer, next, installed), out);
            return;
        }
        if let Wire::Snapshot {
            cluster: _,
            base,
            term,
            transfer,
            digest,
            length,
            offset,
            bytes,
        } = message
        {
            // A delivery is a duty: its budget refills.
            let _ = self.refill();
            if let Some((mut core, mut log)) = self.running.take() {
                let piece = Piece {
                    base,
                    term,
                    transfer,
                    digest,
                    length,
                    offset,
                    bytes,
                };
                self.receive_snapshot(&mut core, &mut log, (from, piece), out);
                self.running = Some((core, log));
            }
            self.duty(out);
            return;
        }
        let acts = self.acts();
        let budget = self.refill();
        let Some((core, log)) = self.running.as_mut() else {
            return;
        };
        let mut view = LogView::metered(log, budget.as_ref()).with_base(self.base);
        match message {
            Wire::Core(_, message) => core.step(from, message, &mut view),
            Wire::Request(_, command) if !acts => out.push((
                command.client,
                Wire::Refused {
                    cluster: self.identity.identity,
                    sequence: command.sequence,
                },
            )),
            Wire::Request(_, command) => {
                let key = (command.client, command.sequence);
                command.encode_into(&mut self.command);
                match core.propose_slice(&self.command, &mut view) {
                    Ok(()) => {
                        let _ = self.pending.insert(key);
                    }
                    Err(refused) => {
                        if let Refused::Backpressure(limit) = refused {
                            self.recorder.borrow_mut().observations.push(
                                Observation::Backpressure {
                                    node: self.id,
                                    client: command.client,
                                    sequence: command.sequence,
                                    limit,
                                },
                            );
                        }
                        let sequence = command.sequence;
                        let answer = match refused {
                            Refused::Backpressure(_) => Wire::Busy {
                                cluster: self.identity.identity,
                                sequence,
                            },
                            // It names another leader (a handover, W5):
                            // the client goes there.
                            Refused::NotLeader(NotLeader {
                                leader: Some(leader),
                            }) if leader != self.id => {
                                self.recorder.borrow_mut().observations.push(
                                    Observation::Redirected {
                                        node: self.id,
                                        client: command.client,
                                        sequence,
                                        to: leader,
                                    },
                                );
                                Wire::Redirect {
                                    cluster: self.identity.identity,
                                    server: leader,
                                }
                            }
                            Refused::NotLeader(_) => Wire::Refused {
                                cluster: self.identity.identity,
                                sequence,
                            },
                        };
                        out.push((command.client, answer));
                    }
                }
            }
            Wire::Transfer(to) => {
                let result = core.transfer_leadership(to, &mut view);
                let node = self.id;
                let mut recorder = self.recorder.borrow_mut();
                if result == Err(TransferRefused::Unsupported) {
                    recorder.observations.push(Observation::Unsupported {
                        node,
                        what: "transfer_leadership",
                    });
                }
                recorder
                    .observations
                    .push(Observation::Transfer { node, to, result });
            }
            Wire::Change(change) => {
                let result = core.propose_change(change, &mut view);
                self.recorder
                    .borrow_mut()
                    .observations
                    .push(Observation::Change {
                        node: self.id,
                        change,
                        result,
                    });
            }
            Wire::Feed {
                entries,
                prev_term,
                commit,
            } => {
                if let Some(standby) = self.standby.as_mut()
                    && !standby.promoted
                    && core.leads()
                {
                    let refused = take_feed(standby, core, &mut view, &entries, prev_term, commit);
                    if let Some((index, reason)) = refused {
                        self.recorder
                            .borrow_mut()
                            .observations
                            .push(Observation::FeedRefused {
                                node: self.id,
                                index,
                                reason,
                            });
                    }
                }
            }
            Wire::ReplStart { start } => {
                if let Some(standby) = self.standby.as_mut()
                    && !standby.promoted
                    && core.leads()
                    && let Some(follower) = standby.follower.as_mut()
                {
                    let before = follower.copy();
                    let observation = match follower.begin(u64::from(from), start, self.now) {
                        Ok(()) if follower.copy() != before => Some(Observation::CopyStarted {
                            node: self.id,
                            source: from,
                            start,
                        }),
                        Ok(()) => None,
                        Err(refusal) => Some(Observation::ReplicationRefused {
                            node: self.id,
                            source: from,
                            refusal,
                        }),
                    };
                    if let Some(observation) = observation {
                        self.recorder.borrow_mut().observations.push(observation);
                    }
                }
            }
            Wire::ReplBytes { position, bytes } => {
                if let Some(standby) = self.standby.as_mut()
                    && !standby.promoted
                    && core.leads()
                    && let Some(follower) = standby.follower.as_mut()
                {
                    let _ = follower.receive(u64::from(from), position, &bytes);
                }
            }
            Wire::ReplSeal { seal } => {
                if let Some(standby) = self.standby.as_mut()
                    && !standby.promoted
                    && core.leads()
                    && let Some(follower) = standby.follower.as_mut()
                {
                    match follower.seal(u64::from(from), &seal) {
                        Ok(Sealed::Ready(ready)) => {
                            for entry in ready {
                                if core.propose(entry.wrapped, &mut view).is_err() {
                                    // Not proposed: a new copy from V.
                                    follower.rebuild(
                                        standby
                                            .verified
                                            .map(|(index, term)| Position { index, term }),
                                    );
                                    break;
                                }
                            }
                        }
                        Ok(Sealed::Waiting) => standby.stalled = true,
                        Err(Refusal::NotActive { .. }) => {}
                        Err(refusal) => {
                            standby.stalled = true;
                            self.recorder.borrow_mut().observations.push(
                                Observation::ReplicationRefused {
                                    node: self.id,
                                    source: from,
                                    refusal,
                                },
                            );
                        }
                    }
                }
            }
            Wire::ReplStatus { sealed } => {
                if let Some(standby) = self.standby.as_mut()
                    && !standby.promoted
                    && core.leads()
                    && let Some(follower) = standby.follower.as_mut()
                {
                    match follower.status(u64::from(from), sealed, self.now) {
                        // No copy of this request: the source starts it
                        // again.
                        Err(Refusal::NotActive { .. }) => out.push((from, Wire::ReplReset)),
                        Err(_) => {}
                        Ok(ends) => {
                            let point = follower.recovery_point(self.now);
                            self.recorder.borrow_mut().observations.push(
                                Observation::RecoveryPoint {
                                    node: self.id,
                                    point,
                                },
                            );
                            out.push((
                                from,
                                Wire::ReplAck {
                                    received: ends.received,
                                    checked: ends.checked,
                                    stalled: standby.stalled,
                                },
                            ));
                            standby.stalled = false;
                        }
                    }
                }
            }
            Wire::ReplEnd => {
                if let Some(follower) = self
                    .standby
                    .as_mut()
                    .and_then(|standby| standby.follower.as_mut())
                {
                    follower.end(u64::from(from));
                }
            }
            Wire::ReplReset => {
                if let Some(active) = self
                    .replication
                    .as_mut()
                    .and_then(|replication| replication.active.as_mut())
                {
                    active.accepted = false;
                    active.next = active.start;
                    active.checked = active.start;
                }
            }
            Wire::ReplAck {
                received,
                checked,
                stalled,
            } => {
                if let Some(active) = self
                    .replication
                    .as_mut()
                    .and_then(|replication| replication.active.as_mut())
                {
                    active.accepted = true;
                    active.checked = active.checked.max(checked);
                    if stalled {
                        active.next = received.max(active.start);
                    }
                }
            }
            Wire::FeedAck { verified } => {
                if let Some(feed) = self.feed.as_mut() {
                    feed.acked = feed.acked.max(verified);
                }
            }
            Wire::Promote { .. }
                if karyos_cluster::standby::refuse_isolated(self.identity.isolated()).is_err() =>
            {
                // ADR-0123 decision 5, by the standby's own rule: an
                // isolated rebuild is never promoted.
                self.observe(Observation::IsolatedPromotion { node: self.id });
            }
            Wire::Promote { fencing, unknown } => {
                if let Some(standby) = self.standby.as_mut()
                    && !standby.promoted
                {
                    standby.promoted = true;
                    self.generation = self.generation.saturating_add(1);
                    // The harness verified the fencing: the follower is
                    // told so, as the operator or the arbiter would.
                    let evidence = match fencing {
                        Fencing::OperatorStop => karyos_cluster::standby::Fencing::OperatorStop {
                            members: standby.primary.iter().map(|&id| u64::from(id)).collect(),
                            confirmed: standby.primary.iter().map(|&id| u64::from(id)).collect(),
                        },
                        Fencing::Lease => karyos_cluster::standby::Fencing::Lease { expired: true },
                    };
                    let in_flight = unknown
                        .iter()
                        .map(|&(client, sequence)| karyos_cluster::standby::InFlight {
                            client: u64::from(client),
                            sequence,
                        })
                        .collect();
                    let replication = standby
                        .follower
                        .as_mut()
                        .and_then(|follower| follower.promote(&evidence, in_flight).ok());
                    // Over replication the primary's commit is not learnt:
                    // the last sealed entry the standby took stands for it.
                    let learnt_commit = match &standby.follower {
                        Some(follower) => follower
                            .tail()
                            .map(|tail| tail.index)
                            .max(standby.verified.map(|(index, _)| index)),
                        None => standby.learnt,
                    };
                    if core.leads() {
                        let report = PromotionReport {
                            generation: self.generation,
                            verified: standby.verified.map(|(index, _)| index),
                            learnt_commit,
                            unknown,
                            replication,
                        };
                        self.recorder
                            .borrow_mut()
                            .observations
                            .push(Observation::Promoted {
                                node: self.id,
                                report,
                            });
                    }
                }
            }
            Wire::Response { .. }
            | Wire::Snapshot { .. }
            | Wire::SnapshotAck { .. }
            | Wire::Refused { .. }
            | Wire::Busy { .. }
            | Wire::Redirect { .. } => {}
        }
        self.duty(out);
    }
}

impl<C: ConsensusCore> Node<Wire<C::Message>> for ServerNode<C> {
    fn tick(&mut self, now: u64, out: &mut Outbox<Wire<C::Message>>) {
        let _ = self.guarded(|server| server.tick_unguarded(now, out));
    }

    fn deliver(
        &mut self,
        from: NodeId,
        message: Wire<C::Message>,
        now: u64,
        out: &mut Outbox<Wire<C::Message>>,
    ) {
        let _ = self.guarded(|server| server.deliver_unguarded(from, message, now, out));
    }

    fn crash(&mut self) {
        self.running = None;
        self.pending.clear();
        // Its transfers die with it: the restart's store reopen removes
        // what a receive wrote, unpublished.
        self.incoming = None;
        self.outgoing.clear();
        self.observe(Observation::Crashed { node: self.id });
        match self.disk.after_crash(self.survives) {
            Ok(disk) => self.disk = disk,
            // The pre-crash disk is no state to restart from: the node
            // stays down, and its restart reports why.
            Err(error) => self.lost = Some(error.to_string()),
        }
    }

    fn restart(&mut self, _now: u64) {
        let _ = self.guarded(Self::start);
    }
}

/// The follower settings of every standby server over replication: the
/// harness's logs start at [`standby::PRIMARY_FIRST_INDEX`], and the
/// log's seal duty runs every [`SEAL_TICKS`].
fn follower_config() -> StandbyConfig {
    StandbyConfig {
        primary_first_index: standby::PRIMARY_FIRST_INDEX,
        status_interval: STATUS_INTERVAL,
        tail_bound: TailBound::Interval(SEAL_TICKS),
        generation: FIRST_GENERATION,
    }
}

/// The directory of a standby server's replica journal and copy
/// catalog, beside its log.
pub const REPLICA_DIR: &str = "/replica";

/// A fresh follower whose seals the schema 6 replica on `disk` verifies;
/// `None` when the replica cannot open (the server then follows nothing).
fn follower_on(disk: &SimDisk) -> Option<Standby<ReplicaCheck<SimDisk>>> {
    let check = ReplicaCheck::open(disk.clone(), Path::new(REPLICA_DIR)).ok()?;
    Some(Standby::new(follower_config(), check, None))
}

/// One period of `replication` from a server whose core leads (or no
/// longer does): ends a request the log says must end; starts one at the
/// log's replication start; sends its stored frames up to its epoch's
/// sealed end, from the next position, [`FEED_BATCH_BYTES`] at most,
/// damaging the first one its faults name (one per period, so each
/// damage fails or stalls a send of its own); then the seals past the standby's
/// checked end that the bytes sent cover, and a status. A failed read
/// stops the period.
fn send_replication<M>(
    replication: &mut ReplicationOut,
    leads: bool,
    log: &mut RaftLog<SimDisk>,
    out: &mut Outbox<Wire<M>>,
) {
    if let Some(active) = replication.active
        && log
            .replication_end(active.epoch, active.next, leads)
            .is_some()
    {
        for &to in &replication.to {
            out.push((to, Wire::ReplEnd));
        }
        replication.active = None;
    }
    if !leads {
        return;
    }
    if replication.active.is_none() {
        let Ok(Some(start)) = log.replication_start() else {
            return;
        };
        replication.active = Some(ReplicationActive {
            epoch: log.seal_epoch(),
            start,
            next: start,
            checked: start,
            accepted: false,
        });
    }
    let Some(active) = replication.active.as_mut() else {
        return;
    };
    let Ok((epoch, seals)) = log.replication_seals() else {
        return;
    };
    if epoch != active.epoch {
        return;
    }
    if !active.accepted {
        for &to in &replication.to {
            out.push((
                to,
                Wire::ReplStart {
                    start: active.start,
                },
            ));
        }
    }
    let sealed = seals
        .last()
        .map_or(active.start, |seal| seal.end)
        .max(active.start);
    let mut budget = FEED_BATCH_BYTES;
    let mut damaged = false;
    while active.next < sealed && budget > 0 {
        let mut header = [0u8; karyos_cluster::log::FRAME_HEADER];
        if log.read_stored(active.next, &mut header).is_err() {
            return;
        }
        let length = header
            .get(4..8)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map_or(0, u32::from_le_bytes);
        let span = u64::from(length).saturating_add(karyos_cluster::log::FRAME_HEADER_LEN);
        let Ok(size) = usize::try_from(span) else {
            return;
        };
        let mut frame = vec![0u8; size];
        if log.read_stored(active.next, &mut frame).is_err() {
            return;
        }
        let index = frame
            .get(8..16)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_le_bytes);
        let fault = index
            .filter(|_| !damaged)
            .and_then(|index| replication.faults.remove(&index));
        damaged |= fault.is_some();
        match fault {
            Some(FeedFault::Skip) => {}
            Some(FeedFault::Corrupt) => {
                if let Some(byte) = frame.get_mut(karyos_cluster::log::FRAME_HEADER) {
                    *byte ^= 0xFF;
                }
            }
            Some(FeedFault::Term) => {
                if let Some(term) = frame.get_mut(16..24) {
                    let raised = <[u8; 8]>::try_from(&*term)
                        .map_or(0, u64::from_le_bytes)
                        .saturating_add(1);
                    term.copy_from_slice(&raised.to_le_bytes());
                }
            }
            None => {}
        }
        if fault != Some(FeedFault::Skip) {
            for &to in &replication.to {
                out.push((
                    to,
                    Wire::ReplBytes {
                        position: active.next,
                        bytes: frame.clone(),
                    },
                ));
            }
        }
        active.next = active.next.saturating_add(span);
        budget = budget.saturating_sub(span);
    }
    for seal in seals
        .iter()
        .filter(|seal| seal.end > active.checked && seal.end <= active.next)
    {
        for &to in &replication.to {
            out.push((to, Wire::ReplSeal { seal: *seal }));
        }
    }
    for &to in &replication.to {
        out.push((to, Wire::ReplStatus { sealed }));
    }
}

/// Sends `feed` the committed entries after its acknowledged position, up
/// to `commit`, from `log`, with the commit; a failed read sends none.
fn send_feed<M>(
    feed: &mut FeedOut,
    commit: Option<u64>,
    log: &mut RaftLog<SimDisk>,
    out: &mut Outbox<Wire<M>>,
) {
    let from = feed
        .acked
        .map_or(Some(log.first_index()), |acked| acked.checked_add(1));
    let entries = match (from, commit.and_then(|commit| commit.checked_add(1))) {
        (Some(from), Some(end)) if from < end => {
            log.entries(from..end, FEED_BATCH_BYTES).unwrap_or_default()
        }
        _ => Vec::new(),
    };
    let prev_term = entries
        .first()
        .and_then(|first| first.index.checked_sub(1))
        .and_then(|before| log.term(before));
    let mut sent = Vec::with_capacity(entries.len());
    for entry in entries {
        let checksum = standby::checksum(entry.index, entry.term, &entry.payload);
        let mut fed = FeedEntry {
            index: entry.index,
            term: entry.term,
            checksum,
            payload: entry.payload,
        };
        match feed.faults.remove(&fed.index) {
            Some(FeedFault::Skip) => continue,
            Some(FeedFault::Corrupt) => {
                if let Some(first) = fed.payload.first_mut() {
                    *first ^= 0xFF;
                }
            }
            Some(FeedFault::Term) => fed.term = fed.term.saturating_add(1),
            None => {}
        }
        sent.push(fed);
    }
    for &to in &feed.to {
        out.push((
            to,
            Wire::Feed {
                entries: sent.clone(),
                prev_term,
                commit,
            },
        ));
    }
}

/// Takes a feed send at a standby whose core leads: checks each entry
/// after the last one proposed by log matching and checksum, and proposes
/// what passes. Returns the first refused entry and why.
fn take_feed<C: ConsensusCore>(
    standby: &mut StandbyIn,
    core: &mut C,
    view: &mut LogView<'_>,
    entries: &[FeedEntry],
    prev_term: Option<u64>,
    commit: Option<u64>,
) -> Option<(u64, FeedRefusal)> {
    standby.learnt = standby.learnt.max(commit);
    let mut previous = prev_term;
    for entry in entries {
        let last = standby.proposed;
        if last.is_some_and(|(index, _)| entry.index <= index) {
            previous = Some(entry.term);
            continue;
        }
        let expected = last.map_or(Some(standby::PRIMARY_FIRST_INDEX), |(index, _)| {
            index.checked_add(1)
        });
        let refusal = if Some(entry.index) != expected {
            Some(FeedRefusal::Gap)
        } else if previous != last.map(|(_, term)| term) {
            Some(FeedRefusal::Term)
        } else if standby::checksum(entry.index, entry.term, &entry.payload) != entry.checksum {
            Some(FeedRefusal::Checksum)
        } else {
            None
        };
        if let Some(reason) = refusal {
            return Some((entry.index, reason));
        }
        let wrapped = standby::wrap(entry.index, entry.term, &entry.payload);
        if core.propose(wrapped, view).is_err() {
            return None;
        }
        standby.proposed = Some((entry.index, entry.term));
        previous = Some(entry.term);
    }
    None
}

/// Ticks a client waits for an answer before it sends its request
/// again, by default.
pub const RETRY_AFTER: u64 = 400;

/// A scripted client: it sends its next request to its server once the
/// last one was answered, and sends an unanswered one again (the same
/// sequence number) when it is refused or after its retry delay, so the
/// service's deduplication answers a command applied twice.
#[derive(Debug, Clone)]
pub struct ClientNode {
    id: NodeId,
    server: NodeId,
    script: Vec<Op>,
    next: usize,
    /// The request waiting for its answer, and when it was last sent.
    open: Option<(Command, u64)>,
    retry_after: u64,
    /// The open request was refused: send it again now.
    refused: bool,
    recorder: Shared,
    /// The highest generation it has seen, 0 before the first answer.
    generation: u64,
    /// The cluster identities it accepts (ADR-0123 decision 4), boxed to
    /// keep the node small.
    accepted: Box<Accepted>,
    /// Its requests name the standby's identity, not the primary's: the
    /// latest accepted answer was the standby's.
    to_standby: bool,
    /// It records each read with a value no one wrote (karyos#1038,
    /// tests): a faulty client.
    #[cfg(feature = "test-hooks")]
    corrupts_reads: bool,
}

impl ClientNode {
    /// Client `id`, sending `script` to `server` in order.
    #[must_use]
    pub fn new(id: NodeId, server: NodeId, script: Vec<Op>, recorder: Shared) -> Self {
        Self {
            id,
            server,
            script,
            next: 0,
            open: None,
            retry_after: RETRY_AFTER,
            refused: false,
            recorder,
            generation: 0,
            accepted: Box::new(Accepted {
                primary: HARNESS_CLUSTER,
                standby: Some(HARNESS_STANDBY),
            }),
            to_standby: false,
            #[cfg(feature = "test-hooks")]
            corrupts_reads: false,
        }
    }

    /// The client accepting only `accepted` (ADR-0123 decision 4): by
    /// default the run's cluster and its standby.
    #[must_use]
    pub fn accepting(mut self, accepted: Accepted) -> Self {
        self.accepted = Box::new(accepted);
        self.to_standby = false;
        self
    }

    /// The identity its requests name.
    fn cluster(&self) -> ClusterId {
        match self.accepted.standby {
            Some(standby) if self.to_standby => standby,
            _ => self.accepted.primary,
        }
    }

    /// The client recording each read with a value no one wrote: a faulty
    /// client (karyos#1038, tests).
    #[must_use]
    #[cfg(feature = "test-hooks")]
    pub fn corrupting_reads(mut self) -> Self {
        self.corrupts_reads = true;
        self
    }

    /// Its open request's sequence number, if one waits for its answer.
    #[must_use]
    pub fn open(&self) -> Option<u64> {
        self.open.as_ref().map(|(command, _)| command.sequence)
    }

    /// Sends an unanswered request again after `ticks`.
    #[must_use]
    pub fn with_retry_after(mut self, ticks: u64) -> Self {
        self.retry_after = ticks;
        self
    }

    /// Whether every request of its script was answered.
    #[must_use]
    pub fn done(&self) -> bool {
        self.open.is_none() && self.next == self.script.len()
    }
}

impl<M> Node<Wire<M>> for ClientNode {
    fn tick(&mut self, now: u64, out: &mut Outbox<Wire<M>>) {
        let cluster = self.cluster();
        if let Some((command, sent)) = self.open.as_mut() {
            let due = now
                .checked_sub(*sent)
                .is_some_and(|waited| waited >= self.retry_after);
            if self.refused || due {
                self.refused = false;
                *sent = now;
                out.push((self.server, Wire::Request(cluster, command.clone())));
            }
            return;
        }
        let Some(op) = self.script.get(self.next).cloned() else {
            return;
        };
        let Some(sequence) = u64::try_from(self.next)
            .ok()
            .and_then(|next| next.checked_add(1))
        else {
            return;
        };
        // `next` indexes the script, so it is below `usize::MAX`.
        self.next += 1;
        let _ = self
            .recorder
            .borrow_mut()
            .history
            .invoke(self.id, op.clone());
        let command = Command {
            client: self.id,
            sequence,
            op,
        };
        out.push((self.server, Wire::Request(cluster, command.clone())));
        self.open = Some((command, now));
    }

    fn deliver(&mut self, _from: NodeId, message: Wire<M>, _now: u64, _out: &mut Outbox<Wire<M>>) {
        let open = self.open.as_ref().map(|(command, _)| command.sequence);
        if let Wire::Response { cluster, .. }
        | Wire::Refused { cluster, .. }
        | Wire::Busy { cluster, .. }
        | Wire::Redirect { cluster, .. } = &message
            && !self.accepted.accepts(*cluster)
        {
            self.recorder
                .borrow_mut()
                .observations
                .push(Observation::ForeignCluster {
                    client: self.id,
                    cluster: *cluster,
                });
            return;
        }
        let standby = match &message {
            Wire::Response { cluster, .. } | Wire::Redirect { cluster, .. } => {
                Some(*cluster != self.accepted.primary)
            }
            _ => None,
        };
        match message {
            Wire::Response { generation, .. } if generation < self.generation => {
                self.recorder
                    .borrow_mut()
                    .observations
                    .push(Observation::StaleGeneration {
                        client: self.id,
                        generation,
                    });
            }
            Wire::Response {
                cluster: _,
                sequence,
                bytes,
                index,
                generation,
            } if open == Some(sequence) => {
                // Accepted: later requests name this answer's cluster.
                self.to_standby = standby.unwrap_or(self.to_standby);
                // Bytes that do not decode are no answer: the retry asks
                // again.
                let Some(ret) = Ret::decode(&bytes) else {
                    return;
                };
                self.open = None;
                // Its answer expired: the outcome is unknown, so it stays
                // open in the history (taken or not), and the client stops.
                if ret == Ret::Expired {
                    self.next = self.script.len();
                    self.recorder
                        .borrow_mut()
                        .observations
                        .push(Observation::Expired {
                            client: self.id,
                            sequence,
                        });
                    return;
                }
                self.generation = generation;
                #[cfg(feature = "test-hooks")]
                let ret = match ret {
                    Ret::Values(mut values) if self.corrupts_reads => {
                        values.push(b"never written".to_vec());
                        Ret::Values(values)
                    }
                    other => other,
                };
                let mut recorder = self.recorder.borrow_mut();
                let _ = recorder.history.ret(self.id, ret);
                recorder.observations.push(Observation::Success {
                    client: self.id,
                    index,
                    generation,
                });
            }
            Wire::Refused { sequence, .. } if open == Some(sequence) => self.refused = true,
            Wire::Redirect { server, .. } => {
                self.server = server;
                self.to_standby = standby.unwrap_or(self.to_standby);
                // An open request goes to the new server at once.
                self.refused = self.open.is_some();
            }
            _ => {}
        }
    }
}

/// A member of a harness run: a server or a client, over one wire.
pub enum Member<C: ConsensusCore> {
    /// A server.
    Server(Box<ServerNode<C>>),
    /// A client.
    Client(ClientNode),
}

impl<C: ConsensusCore> Member<C> {
    /// The server, if it is one.
    #[must_use]
    pub fn server(&self) -> Option<&ServerNode<C>> {
        match self {
            Self::Server(server) => Some(server),
            Self::Client(_) => None,
        }
    }

    /// The client, if it is one.
    #[must_use]
    pub fn client(&self) -> Option<&ClientNode> {
        match self {
            Self::Client(client) => Some(client),
            Self::Server(_) => None,
        }
    }
}

impl<C: ConsensusCore> Node<Wire<C::Message>> for Member<C> {
    fn tick(&mut self, now: u64, out: &mut Outbox<Wire<C::Message>>) {
        match self {
            Self::Server(server) => server.tick(now, out),
            Self::Client(client) => client.tick(now, out),
        }
    }

    fn deliver(
        &mut self,
        from: NodeId,
        message: Wire<C::Message>,
        now: u64,
        out: &mut Outbox<Wire<C::Message>>,
    ) {
        match self {
            Self::Server(server) => server.deliver(from, message, now, out),
            Self::Client(client) => client.deliver(from, message, now, out),
        }
    }

    fn crash(&mut self) {
        match self {
            Self::Server(server) => server.crash(),
            Self::Client(client) => Node::<Wire<C::Message>>::crash(client),
        }
    }

    fn restart(&mut self, now: u64) {
        match self {
            Self::Server(server) => server.restart(now),
            Self::Client(client) => Node::<Wire<C::Message>>::restart(client, now),
        }
    }
}
