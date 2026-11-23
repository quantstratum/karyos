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
//!
//! [`ClusterSim`]: crate::cluster::ClusterSim

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::rc::Rc;

use karyos_archive::segment::Geometry;
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_cluster::{Entry, LogError, RaftLog};

use super::core::{
    Applying, Change, ChangeRefused, Configuration, ConsensusCore, DriveError, DriveFault, Limit,
    Limits, LogView, NotLeader, ReadBudget, ReadyBuf, Refused, Release, SnapshotBase, Step,
    TransferRefused, Unsupported, drive_inner,
};
use super::standby::{
    self, ExternalLease, FEED_BATCH_BYTES, FEED_PERIOD, FIRST_GENERATION, FeedEntry, FeedFault,
    FeedRefusal, Fencing, PromotionReport,
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

/// A case's log compaction (W5): a snapshot every `every` applied
/// entries, the log purged below it but its last `keep` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compaction {
    /// Applied entries between snapshots.
    pub every: u64,
    /// Entries kept below a snapshot's base, for a slow follower.
    pub keep: u64,
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
        }
    }

    /// Applies the committed `entry`; returns the command and its answer:
    /// the kept answer for a retried sequence, [`Ret::Expired`] for one
    /// whose answer is no longer kept. An entry that holds no command (a
    /// core's own entry) answers nothing.
    pub fn apply(&mut self, entry: &Entry) -> Option<(Command, Ret)> {
        self.applied = Some(entry.index);
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

    /// Its whole state as a snapshot's service section (W5; karyos#687):
    /// the values, the deduplication table, the last index applied and
    /// the deduplicated count, each length-prefixed, little endian; `None`
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
        rest.is_empty().then_some(Self {
            values,
            answered,
            applied,
            deduplicated,
            expired,
            retention,
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

/// The one message type of a harness run.
#[derive(Debug, Clone, PartialEq)]
pub enum Wire<M> {
    /// Between cores.
    Core(M),
    /// A client's request.
    Request(Command),
    /// A server's answer: `ret` for the command at `index`.
    Response {
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
        /// The client's sequence number.
        sequence: u64,
    },
    /// The server's core pushed back on the request (W2's backpressure):
    /// the client sends it again after its retry interval, not at once,
    /// so a full queue is not flooded.
    Busy {
        /// The client's sequence number.
        sequence: u64,
    },
    /// An operator's membership change, which the server's core takes or
    /// refuses ([`Observation::Change`]); nothing answers it.
    Change(Change),
    /// An operator's leadership handover to a server, which the core takes
    /// or refuses ([`Observation::Transfer`]); nothing answers it (W5).
    Transfer(NodeId),
    /// A leader's snapshot (W5): its base and its service section.
    Snapshot {
        /// The snapshot's base.
        base: SnapshotBase,
        /// The service's state at the base ([`TestService::encode`]).
        service: Vec<u8>,
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
        /// The requests known to be in flight, by client and sequence.
        unknown: Vec<(NodeId, u64)>,
    },
    /// The harness sends a client to another server.
    Redirect {
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

/// A standby server's state.
#[derive(Debug, Clone, Default)]
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
    /// The configuration last recorded.
    configuration: Option<Configuration>,
    /// Why the disk cannot come back, when its crash could not be taken.
    lost: Option<String>,
    recorder: Shared,
    /// Its generation: [`FIRST_GENERATION`], one more after a promotion.
    generation: u64,
    /// Its clock at its last tick or delivery.
    now: u64,
    /// The feed to a standby, for a primary server.
    feed: Option<FeedOut>,
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
    /// Its latest snapshot's base.
    base: Option<SnapshotBase>,
    /// The fault its driver injects (karyos#1038, tests).
    drive_fault: DriveFault,
    /// Its service answers differently (karyos#1038, tests).
    #[cfg(feature = "test-hooks")]
    alters_responses: bool,
    /// The Ready its core fills in place ([`ConsensusCore::ready_into`]).
    ready: ReadyBuf<C::Message>,
    /// The bytes of the request it proposes, kept across requests.
    command: Vec<u8>,
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
        let core = C::recover(id, &peers, &mut LogView::new(&mut log));
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
        let core = Self::recovered(id, &peers, (limits, None), &mut log)
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

    /// A server running `core` over `log`.
    fn assemble(
        id: NodeId,
        peers: Vec<NodeId>,
        (disk, survives): (SimDisk, Survives),
        geometry: Geometry,
        recorder: Shared,
        (core, log): (C, RaftLog<SimDisk>),
        limits: Option<Limits>,
    ) -> Self {
        let commit = core.committed();
        let configuration = core.configuration();
        let mut server = Self {
            id,
            peers,
            geometry,
            disk,
            survives,
            running: Some((core, log)),
            service: TestService::default(),
            pending: BTreeSet::new(),
            commit,
            configuration: None,
            lost: None,
            recorder,
            generation: FIRST_GENERATION,
            now: 0,
            feed: None,
            lease: None,
            standby: None,
            limits,
            budget: ReadBudget::new(),
            compaction: None,
            snapshots: None,
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
            configuration: None,
            lost: None,
            recorder,
            generation: FIRST_GENERATION,
            now: 0,
            feed: None,
            lease: None,
            standby: None,
            limits: None,
            budget: ReadBudget::new(),
            compaction: None,
            snapshots: None,
            base: None,
            drive_fault: DriveFault::None,
            #[cfg(feature = "test-hooks")]
            alters_responses: false,
            ready: ReadyBuf::default(),
            command: Vec::new(),
        };
        server.start();
        server
    }

    /// Compacts its log under `compaction` (W5), with a snapshot store
    /// beside its log; it is lost when the store does not open.
    #[must_use]
    pub fn with_compaction(mut self, compaction: Compaction) -> Self {
        self.compaction = Some(compaction);
        match Self::open_snapshots(&self.disk, self.geometry) {
            Ok(store) => self.snapshots = Some(store),
            Err(error) => self.lost = Some(error),
        }
        self
    }

    fn open_snapshots(
        disk: &SimDisk,
        geometry: Geometry,
    ) -> Result<SnapshotStore<SimDisk>, String> {
        SnapshotStore::open(
            disk.clone(),
            Path::new(SNAPSHOT_DIR),
            geometry,
            SnapshotConfig::default(),
        )
        .map(|opened| opened.store)
        .map_err(|error| format!("snapshot store: {error}"))
    }

    /// The service section of `store`'s latest snapshot, and its base.
    fn latest_service(store: &SnapshotStore<SimDisk>) -> Option<(SnapshotBase, Vec<u8>)> {
        let info = store.latest()?;
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

    /// Takes a snapshot of its service and compacts its log, when its
    /// service has applied [`Compaction::every`] entries since the last.
    fn compact(&mut self, core: &mut C, log: &mut RaftLog<SimDisk>) {
        let (Some(compaction), Some(store), Some(applied)) = (
            self.compaction,
            self.snapshots.as_mut(),
            self.service.applied(),
        ) else {
            return;
        };
        let since = self
            .base
            .map_or(Some(applied), |base| applied.checked_sub(base.index));
        if since.is_none_or(|since| since < compaction.every.max(1)) {
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
        // Keep the last `keep` entries below the base for a slow follower.
        if let Some(below) = applied
            .checked_add(1)
            .and_then(|next| next.checked_sub(compaction.keep))
        {
            let _ = log.purge_prefix(below);
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

    /// Sends its latest snapshot to `to`, which needs entries its log no
    /// longer holds.
    fn send_snapshot(&self, to: NodeId, out: &mut Outbox<Wire<C::Message>>) {
        let Some((base, service)) = self.snapshots.as_ref().and_then(Self::latest_service) else {
            return;
        };
        out.push((to, Wire::Snapshot { base, service }));
    }

    /// Installs a leader's snapshot: written to its store first, then the
    /// log restarts after it, the service restores it, and the core is
    /// told; any refusal is recorded and changes nothing further.
    fn install_snapshot(
        &mut self,
        core: &mut C,
        log: &mut RaftLog<SimDisk>,
        (base, bytes): (SnapshotBase, Vec<u8>),
    ) {
        let node = self.id;
        let refuse = |this: &Self, reason: String| {
            this.observe(Observation::SnapshotRefused { node, base, reason });
        };
        if self
            .service
            .applied()
            .is_some_and(|applied| base.index <= applied)
        {
            return;
        }
        let Some(service) = TestService::decode(&bytes) else {
            return refuse(self, "malformed service section".to_owned());
        };
        if service.applied() != Some(base.index) {
            return refuse(self, "service section not at its base".to_owned());
        }
        let Some(store) = self.snapshots.as_mut() else {
            return refuse(self, "no snapshot store".to_owned());
        };
        if let Err(error) = store.write(
            base.index,
            base.term,
            &[Section::new(
                SectionKind::Service,
                SERVICE_SECTION_VERSION,
                &bytes,
            )],
        ) {
            return refuse(self, format!("write: {error}"));
        }
        if let Err(error) = log.install(base.index, base.term, store) {
            return refuse(self, format!("install: {error}"));
        }
        self.base = Some(base);
        let digest = service.digest();
        self.service = service;
        self.observe(Observation::Installed { node, base, digest });
        let budget = self.limits.map(|_| self.budget.clone());
        if let Err(refused) = core.install(
            base,
            &mut LogView::metered(log, budget.as_ref()).with_base(Some(base)),
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
                    refuse(self, "the core holds the base already".to_owned());
                }
            }
        }
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

    /// A standby server, fed by the servers `primary`.
    #[must_use]
    pub fn as_standby(mut self, primary: Vec<NodeId>) -> Self {
        self.standby = Some(StandbyIn {
            primary,
            ..StandbyIn::default()
        });
        self
    }

    /// Its core over `log`, under `limits` when it has them.
    fn recovered(
        id: NodeId,
        peers: &[NodeId],
        (limits, base): (Option<Limits>, Option<SnapshotBase>),
        log: &mut RaftLog<SimDisk>,
    ) -> Result<C, Unsupported> {
        // The core sees the snapshot its node recovers over (karyos#903
        // review).
        let mut view = LogView::new(log).with_base(base);
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

    /// Whether it takes requests: not a standby that waits for its
    /// promotion, and not a lease holder past its lease.
    fn acts(&self) -> bool {
        self.standby.as_ref().is_none_or(|standby| standby.promoted)
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
                out.push((to, Wire::Core(message)));
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
            && standby.verified != verified_before
            && core.leads()
        {
            let verified = standby.verified.map(|(index, _)| index);
            for &to in &standby.primary {
                out.push((to, Wire::FeedAck { verified }));
            }
        }
        if let Some(configuration) = core.configuration()
            && self.configuration.as_ref() != Some(&configuration)
        {
            let entry_term = configuration.index.and_then(|index| log.term(index));
            self.record_configuration(configuration, entry_term);
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
        for to in snapshot_to {
            self.send_snapshot(to, out);
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
        if self.compaction.is_some() {
            match Self::open_snapshots(&self.disk, self.geometry) {
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
        let latest = self.snapshots.as_ref().and_then(Self::latest_service);
        self.base = latest.as_ref().map(|(base, _)| *base);
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
        let core = match Self::recovered(self.id, &self.peers, (self.limits, self.base), &mut log) {
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
        }
        // Recorded at every start, so a check compares it with the log.
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
        if let Wire::Snapshot { base, service } = message {
            // A delivery is a duty: its budget refills.
            let _ = self.refill();
            if let Some((mut core, mut log)) = self.running.take() {
                self.install_snapshot(&mut core, &mut log, (base, service));
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
            Wire::Core(message) => core.step(from, message, &mut view),
            Wire::Request(command) if !acts => out.push((
                command.client,
                Wire::Refused {
                    sequence: command.sequence,
                },
            )),
            Wire::Request(command) => {
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
                            Refused::Backpressure(_) => Wire::Busy { sequence },
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
                                Wire::Redirect { server: leader }
                            }
                            Refused::NotLeader(_) => Wire::Refused { sequence },
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
            Wire::FeedAck { verified } => {
                if let Some(feed) = self.feed.as_mut() {
                    feed.acked = feed.acked.max(verified);
                }
            }
            Wire::Promote { unknown } => {
                if let Some(standby) = self.standby.as_mut()
                    && !standby.promoted
                {
                    standby.promoted = true;
                    self.generation = self.generation.saturating_add(1);
                    if core.leads() {
                        let report = PromotionReport {
                            generation: self.generation,
                            verified: standby.verified.map(|(index, _)| index),
                            learnt_commit: standby.learnt,
                            unknown,
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
            #[cfg(feature = "test-hooks")]
            corrupts_reads: false,
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
        if let Some((command, sent)) = self.open.as_mut() {
            let due = now
                .checked_sub(*sent)
                .is_some_and(|waited| waited >= self.retry_after);
            if self.refused || due {
                self.refused = false;
                *sent = now;
                out.push((self.server, Wire::Request(command.clone())));
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
        out.push((self.server, Wire::Request(command.clone())));
        self.open = Some((command, now));
    }

    fn deliver(&mut self, _from: NodeId, message: Wire<M>, _now: u64, _out: &mut Outbox<Wire<M>>) {
        let open = self.open.as_ref().map(|(command, _)| command.sequence);
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
                sequence,
                bytes,
                index,
                generation,
            } if open == Some(sequence) => {
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
            Wire::Refused { sequence } if open == Some(sequence) => self.refused = true,
            Wire::Redirect { server } => {
                self.server = server;
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
