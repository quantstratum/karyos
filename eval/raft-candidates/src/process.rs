// SPDX-License-Identifier: Apache-2.0

//! A candidate core in a real process (plan issue 060, karyos#678: the
//! adapter "runs unchanged under `karyos-sim` and in real processes").
//!
//! [`run_node`] drives the same [`ConsensusCore`] the simulator drives,
//! through the same [`drive`], over C4's log on real files
//! ([`StdDisk`]), with its messages in UDP datagrams between processes and
//! its ticks from the process's monotonic clock ([`TICK_MS`] a tick).
//! Nothing of the core changes: only its surroundings do.
//!
//! The run is a smoke test of that path, not a workload: the leader
//! proposes `commands` numbered commands one at a time, every node applies
//! what commits, and each reports how many distinct commands it applied
//! and a digest of the applied order once it has them all. No client, no
//! fault, no measurement.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use karyos_archive::disk::StdDisk;
use karyos_cluster::{Entry, LogError, RaftLog};
use karyos_sim::harness::core::{ConsensusCore, DriveError, LogView, drive};
use karyos_sim::harness::workloads;
use karyos_sim::net::NodeId;

/// A core whose messages cross a process boundary.
pub trait Wire: ConsensusCore {
    /// The message's bytes; `None` when it cannot be encoded.
    fn encode(message: &Self::Message) -> Option<Vec<u8>>;

    /// The message in `bytes`; `None` when they are not one.
    fn decode(bytes: &[u8]) -> Option<Self::Message>;
}

/// The largest datagram a node sends or reads.
pub const MAX_DATAGRAM: usize = 65_000;

/// Milliseconds of the process clock per core tick. The simulator's tick
/// is virtual; here a durable write is a real `fsync`, several
/// milliseconds, so an election timeout of 10 ticks must be longer than a
/// vote's persistence: at 1 ms a tick, elections time out before any vote
/// is durable and no leader is ever elected. A setting of the runner, not
/// of the core.
pub const TICK_MS: u64 = 10;

/// Datagrams a node reads at most per loop: a flood never starves its
/// ticks.
pub const MAX_READS_PER_LOOP: usize = 256;

/// One node of a real-process run.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Its id.
    pub id: NodeId,
    /// Every node's id and UDP address, itself included.
    pub peers: Vec<(NodeId, SocketAddr)>,
    /// The directory of its C4 log, created if missing; it must hold no
    /// log yet.
    pub dir: PathBuf,
    /// Commands the leader proposes, numbered from 1.
    pub commands: u64,
    /// How long the run may take.
    pub deadline: Duration,
    /// How long a node keeps serving after it applied every command, so
    /// that the others finish too.
    pub linger: Duration,
}

/// What a node applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Distinct commands applied.
    pub applied: u64,
    /// A digest of every command applied, in the order applied.
    pub digest: u64,
    /// Every command applied, in the order applied, a repeat included,
    /// with the log index of the entry that carried it: a proposal retried
    /// after 100 ms can commit twice, at two indexes, while an entry
    /// applied twice repeats its index; the test tells them apart
    /// (karyos#956 review).
    pub sequence: Vec<(u64, u64)>,
}

/// Why a real-process run stopped.
#[derive(Debug)]
pub enum ProcessError {
    /// The socket or the directory failed.
    Io(io::Error),
    /// The log refused to open or create.
    Log(LogError),
    /// Persistence failed.
    Drive(DriveError),
    /// The deadline passed with commands still unapplied.
    Deadline(Report),
    /// The configuration does not name this node.
    NotAPeer,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "i/o: {error}"),
            Self::Log(error) => write!(f, "log: {error:?}"),
            Self::Drive(error) => write!(f, "drive: {error:?}"),
            Self::Deadline(report) => write!(
                f,
                "deadline passed with {} commands applied",
                report.applied
            ),
            Self::NotAPeer => f.write_str("the node is not among its peers"),
        }
    }
}

impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Command `number`'s payload.
#[must_use]
pub fn command(number: u64) -> Vec<u8> {
    let mut payload = b"real-process command ".to_vec();
    payload.extend_from_slice(&number.to_le_bytes());
    payload
}

fn number_of(payload: &[u8]) -> Option<u64> {
    let tail = payload.strip_prefix(b"real-process command ")?;
    <[u8; 8]>::try_from(tail).ok().map(u64::from_le_bytes)
}

/// A digest step (a hash: modular arithmetic is its definition).
fn mix(digest: u64, number: u64) -> u64 {
    (digest ^ number)
        .wrapping_mul(0x0100_0000_01B3)
        .rotate_left(17)
}

/// Runs node `config.id` of core `C` until it applied every command and
/// lingered, or the deadline passed.
///
/// # Errors
///
/// [`ProcessError`].
pub fn run_node<C: Wire>(config: &NodeConfig) -> Result<Report, ProcessError> {
    let own = config
        .peers
        .iter()
        .find(|(id, _)| *id == config.id)
        .map(|(_, address)| *address)
        .ok_or(ProcessError::NotAPeer)?;
    let ids: Vec<NodeId> = config.peers.iter().map(|(id, _)| *id).collect();
    let socket = UdpSocket::bind(own)?;
    socket.set_read_timeout(Some(Duration::from_millis(1)))?;
    std::fs::create_dir_all(&config.dir)?;
    let geometry = workloads::geometry().map_err(|_| ProcessError::NotAPeer)?;
    // A fresh log: the run starts every node from nothing (a smoke test,
    // not a recovery test; recovery is the simulator's to check).
    let mut log = RaftLog::create(StdDisk, &config.dir, geometry, 1).map_err(ProcessError::Log)?;
    let mut core = C::recover(config.id, &ids, &mut LogView::new(&mut log));
    let start = Instant::now();
    let mut seen = BTreeSet::new();
    let mut report = Report {
        applied: 0,
        digest: 0,
        sequence: Vec::new(),
    };
    let mut next = 1u64;
    let mut proposed_at: Option<Instant> = None;
    let mut done_at: Option<Instant> = None;
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut outbox: Vec<(NodeId, C::Message)> = Vec::new();
    loop {
        let elapsed = start.elapsed();
        if done_at.is_some_and(|at| at.elapsed() >= config.linger) {
            return Ok(report);
        }
        if elapsed >= config.deadline {
            return Err(ProcessError::Deadline(report));
        }
        // Messages first, at most a loop's worth.
        for _ in 0..MAX_READS_PER_LOOP {
            match socket.recv_from(&mut buffer) {
                Ok((length, _)) => {
                    let Some((header, body)) =
                        buffer.get(..length).and_then(|b| b.split_at_checked(4))
                    else {
                        continue;
                    };
                    let Ok(from) = <[u8; 4]>::try_from(header).map(NodeId::from_le_bytes) else {
                        continue;
                    };
                    if let Some(message) = C::decode(body) {
                        core.step(from, message, &mut LogView::new(&mut log));
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let now = u64::try_from(start.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .checked_div(TICK_MS)
            .unwrap_or(0);
        core.tick(now, &mut LogView::new(&mut log));
        // The leader proposes the next command, again if it did not
        // commit within 100 ms (a leader change can drop it).
        if core.leads()
            && next <= config.commands
            && proposed_at.is_none_or(|at| at.elapsed() >= Duration::from_millis(100))
            && core
                .propose(command(next), &mut LogView::new(&mut log))
                .is_ok()
        {
            proposed_at = Some(Instant::now());
        }
        drive(
            &mut core,
            &mut log,
            &mut |to, message, _| outbox.push((to, message)),
            &mut |entry: &Entry, _| {
                if let Some(number) = number_of(&entry.payload) {
                    report.sequence.push((entry.index, number));
                    report.digest = mix(mix(report.digest, entry.index), number);
                    if seen.insert(number) {
                        report.applied = report.applied.saturating_add(1);
                    }
                }
            },
            &mut |_| {},
        )
        .map_err(ProcessError::Drive)?;
        if seen.contains(&next) {
            next = next.saturating_add(1);
            proposed_at = None;
        }
        if done_at.is_none() && report.applied >= config.commands {
            done_at = Some(Instant::now());
        }
        for (to, message) in outbox.drain(..) {
            let Some(address) = config
                .peers
                .iter()
                .find(|(id, _)| *id == to)
                .map(|(_, address)| *address)
            else {
                continue;
            };
            let Some(body) = C::encode(&message) else {
                continue;
            };
            let mut datagram = config.id.to_le_bytes().to_vec();
            datagram.extend_from_slice(&body);
            if datagram.len() <= MAX_DATAGRAM {
                // A lost datagram is the network's to lose.
                let _ = socket.send_to(&datagram, address);
            }
        }
    }
}
