// SPDX-License-Identifier: Apache-2.0

//! A candidate core in a real process (plan issue 060, karyos#678: the
//! adapter "runs unchanged under `karyos-sim` and in real processes"; C5
//! v2, "Processes", karyos#691).
//!
//! [`run_server`] drives the same [`ConsensusCore`] the simulator drives,
//! through the same [`drive_into`], over C4's log on real files
//! ([`StdDisk`]), with its messages in UDP datagrams between processes and
//! its ticks from the process's monotonic clock ([`TICK_MS`] a tick).
//! Nothing of the core changes: only its surroundings do.
//!
//! **The service is the harness's own.** A server serves
//! `harness::node`'s test service ([`TestService`]: the append-only
//! register, its per-client session table and deduplication, and its
//! state digest) over the real log, as `harness::node::ServerNode` serves
//! it over the simulated disk: a client's [`Command`] is proposed through
//! [`ConsensusCore::propose_slice`]; a refusal that names another leader
//! redirects the client there, any other `NotLeader` refuses it, and a
//! backpressure says busy; each committed entry is applied once, and the
//! server that took the request answers it, from the deduplication table
//! for a retry. It records what `ServerNode` records, the same
//! [`Observation`]s, each stamped from the host's monotonic clock
//! ([`crate::record`]), so the run is checked by the harness's own checks
//! and pass conditions.
//!
//! **The wire.** Between servers, a core's message is one or more UDP
//! datagrams ([`MAX_DATAGRAM`] at most each; a larger message is cut into
//! fragments and put back together on arrival, and a lost fragment loses
//! the message, which the core's protocol resends). Between a client and
//! a server, each harness message (`harness::node::Wire`: a request, a
//! response, a refusal, a busy or a redirect) is one length-prefixed
//! frame on a TCP connection on the server's address ([`frame`],
//! [`unframe`]): a response to a read carries every value of the register,
//! up to a mebibyte in W1, more than a datagram holds. The test's stop is
//! one datagram ([`STOP`]).
//!
//! **Time.** One core tick is [`TICK_MS`] milliseconds of the process's
//! monotonic clock: version 1's frozen tick, so a case's ticks (its
//! `retry_after`, its `steps`, its `quiet`) are that many 10 ms of process
//! time, and so are the cores' heartbeat and election timeouts, which
//! each adapter counts in ticks.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use karyos_archive::disk::StdDisk;
use karyos_cluster::{LogError, RaftLog};
use karyos_sim::harness::core::{
    ConsensusCore, DriveError, Limits, LogView, NotLeader, ReadBudget, ReadyBuf, Refused,
    drive_into,
};
use karyos_sim::harness::node::{
    Breach, Command, Observation, Positions, SEAL_TICKS, ServiceBounds, TestService,
    Wire as Harness,
};
use karyos_sim::harness::probe::{self, Probed};
use karyos_sim::harness::standby::FIRST_GENERATION;
use karyos_sim::harness::workloads::{self, Action, Case};
use karyos_sim::net::NodeId;

use crate::record::{self, Item};

/// A core whose messages cross a process boundary.
pub trait Wire: ConsensusCore {
    /// The message's bytes into `out`, cleared first: the runner keeps
    /// `out`, so an encoding that writes in place allocates nothing once it
    /// has grown (C5 v3); `false` when it cannot be encoded.
    fn encode_into(message: &Self::Message, out: &mut Vec<u8>) -> bool;

    /// The message in `bytes`; `None` when they are not one.
    fn decode(bytes: &[u8]) -> Option<Self::Message>;

    /// The runner's own pool of decoded messages (C5 v3): what a message is
    /// decoded into, lent to the core's `step`
    /// ([`ConsensusCore::step_lent`]) and taken back.
    type Decoder;

    /// A pool, prefilled: at the node's initialisation.
    fn decoder() -> Self::Decoder;

    /// The message in `bytes`, decoded into `decoder`; `None` when they are
    /// not one.
    fn decode_lent<'a>(
        decoder: &'a mut Self::Decoder,
        bytes: &[u8],
    ) -> Option<&'a mut Self::Message>;

    /// An append's leader term and its entries as (index, payload bytes),
    /// read from the message itself, never from the adapter's counters
    /// (the W2 byte case's oracle, C5 v2); `None` for any other message.
    fn appended(message: &Self::Message) -> Option<(u64, Vec<(u64, u64)>)>;

    /// The term and index an accepted append reply acknowledges; `None`
    /// for any other message.
    fn acknowledged(message: &Self::Message) -> Option<(u64, u64)>;
}

/// A probed core's messages are its inner core's. [`run_server`] counts
/// their encoding and decoding itself, so this delegates only.
impl<C: Wire> Wire for Probed<C> {
    fn encode_into(message: &Self::Message, out: &mut Vec<u8>) -> bool {
        C::encode_into(message, out)
    }

    fn decode(bytes: &[u8]) -> Option<Self::Message> {
        C::decode(bytes)
    }

    type Decoder = C::Decoder;

    fn decoder() -> Self::Decoder {
        C::decoder()
    }

    fn decode_lent<'a>(
        decoder: &'a mut Self::Decoder,
        bytes: &[u8],
    ) -> Option<&'a mut Self::Message> {
        C::decode_lent(decoder, bytes)
    }

    fn appended(message: &Self::Message) -> Option<(u64, Vec<(u64, u64)>)> {
        C::appended(message)
    }

    fn acknowledged(message: &Self::Message) -> Option<(u64, u64)> {
        C::acknowledged(message)
    }
}

/// The largest datagram a node sends or reads.
pub const MAX_DATAGRAM: usize = 65_000;

/// A core datagram's header: its kind, the sender, the message's number
/// from that sender, the fragment's position and the fragment count.
const HEADER: usize = 1 + 4 + 4 + 2 + 2;

/// A core message's bytes per datagram at most.
const FRAGMENT: usize = MAX_DATAGRAM - HEADER;

/// Fragments one message is cut into at most: 4 MB, past any W1 append.
const MAX_FRAGMENTS: u16 = 64;

/// Messages a node keeps half put together at most; the oldest goes first.
const MAX_PARTIAL: usize = 64;

/// The datagram kind of a core's message.
const CORE: u8 = 0;

/// The test's stop: one datagram of this byte. A server that gets it
/// serves its case's `quiet` ticks more, then reports.
pub const STOP: u8 = 1;

/// The largest client frame read: a response holds the register at most.
pub const MAX_FRAME: usize = 64 << 20;

/// Milliseconds of the process clock per core tick: version 1's frozen
/// tick (quantstratum-docs: karyos/evaluations/c5-raft-comparison-v1.md,
/// Timing), in the simulator one step of virtual time. Every count of
/// ticks, the cores' heartbeat and election timeouts and the case's retry,
/// steps and quiet period, is that many of these on a real process. A
/// durable write is a real `fsync` here, several milliseconds, so a tick
/// much shorter would let elections time out before a vote is durable.
pub const TICK_MS: u64 = 10;

/// Datagrams a node reads at most per loop: a flood never starves its
/// ticks.
pub const MAX_READS_PER_LOOP: usize = 256;

/// Messages the outbox holds between two sends without growing, reserved
/// at the node's initialisation.
const OUTBOX_ROOM: usize = 4096;

/// The W1 cases a real-process run takes: the harness's frozen W1
/// (`W1::skeleton().cases()`, every process count, payload and client
/// count of ADR-0043), so every value of a run is its [`Case`]'s.
#[must_use]
pub fn w1_cases() -> Vec<Case> {
    workloads::W1::skeleton().cases()
}

/// The W2 cases a real-process run takes: the manifest's frozen W2
/// (`W2::manifest().cases()`: the nominal load, the bursts at 4x the
/// queue and the in-flight entries, the paused follower and the log-read
/// burst), then C5 v2's in-flight byte case ([`crate::v2::byte_case`]).
#[must_use]
pub fn w2_cases() -> Vec<Case> {
    let mut cases = workloads::W2::manifest().cases().unwrap_or_default();
    cases.push(crate::v2::byte_case());
    cases
}

/// Every case a node or client process takes, by index: [`w1_cases`],
/// then [`w2_cases`].
#[must_use]
pub fn cases() -> Vec<Case> {
    let mut cases = w1_cases();
    cases.extend(w2_cases());
    cases
}

/// When a server is cut from every other server (`Action::Isolate`) and
/// healed again (`Action::Heal`), from `case`'s schedule: `(server, from,
/// until)` in ticks of each server's own clock, `until` `None` when no
/// heal follows. These are the only actions a process run takes (W2's).
///
/// # Errors
///
/// The name of the first other action: a process run refuses it rather
/// than run the case without it.
pub fn isolations(case: &Case) -> Result<Vec<(NodeId, u64, Option<u64>)>, String> {
    let mut schedule = case.schedule.clone();
    schedule.sort_by_key(|(step, _)| *step);
    let mut cuts: Vec<(NodeId, u64, Option<u64>)> = Vec::new();
    for (step, action) in schedule {
        match action {
            Action::Isolate(server) => cuts.push((server, step, None)),
            Action::Heal => {
                for cut in &mut cuts {
                    if cut.2.is_none() {
                        cut.2 = Some(step);
                    }
                }
            }
            other => return Err(format!("{other:?}")),
        }
    }
    Ok(cuts)
}

/// The steps at which `case` heals, in order.
fn heals(case: &Case) -> Vec<u64> {
    let mut heals: Vec<u64> = case
        .schedule
        .iter()
        .filter(|(_, action)| *action == Action::Heal)
        .map(|(step, _)| *step)
        .collect();
    heals.sort_unstable();
    heals
}

/// Whether the link between servers `a` and `b` is cut at tick `now`.
fn cut(cuts: &[(NodeId, u64, Option<u64>)], now: u64, a: NodeId, b: NodeId) -> bool {
    a != b
        && cuts.iter().any(|(server, from, until)| {
            (*server == a || *server == b) && now >= *from && until.is_none_or(|until| now < until)
        })
}

/// The id of client session `session` of `case`: after the servers, the
/// spares and the standby, as `harness::workloads::run` numbers them.
#[must_use]
pub fn client_id(case: &Case, session: usize) -> Option<NodeId> {
    case.servers
        .checked_add(case.spares)?
        .checked_add(case.standby)?
        .checked_add(session)
        .and_then(|id| NodeId::try_from(id).ok())
}

/// One server of a real-process run.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Its id.
    pub id: NodeId,
    /// Every server's id and address, itself included: UDP between
    /// servers, TCP from clients, on the same address.
    pub peers: Vec<(NodeId, SocketAddr)>,
    /// The directory of its C4 log, created if missing; it must hold no
    /// log yet.
    pub dir: PathBuf,
    /// The case it serves.
    pub case: Case,
    /// How long it may serve without the test's stop.
    pub deadline: Duration,
}

/// A server's state when it stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerState {
    /// The service's last applied index.
    pub applied: Option<u64>,
    /// The service's state digest ([`TestService::digest`]).
    pub digest: u64,
    /// Retries it answered from its deduplication table.
    pub deduplicated: u64,
    /// Whether its core led.
    pub leads: bool,
    /// Whether it was still serving: a drive error stops a server, as in
    /// the simulator, until a restart this run never makes.
    pub up: bool,
}

/// What a server reports: its stamped observations and its final state.
#[derive(Debug, Clone)]
pub struct Served {
    /// Every observation, stamped ([`record::now`]), in order.
    pub items: Vec<(u64, Item)>,
    /// Its state at the end.
    pub state: ServerState,
}

/// Why a real-process run stopped.
#[derive(Debug)]
pub enum ProcessError {
    /// The socket or the directory failed.
    Io(io::Error),
    /// The log refused to open or create.
    Log(LogError),
    /// The log geometry.
    Geometry,
    /// The case's service bounds pass a count's type.
    Bounds,
    /// The deadline passed without the test's stop.
    Deadline,
    /// The case schedules an action a process run does not take.
    Schedule(String),
    /// The configuration does not name this node.
    NotAPeer,
    /// A peer's address is not on the loopback: the runner speaks
    /// unauthenticated UDP and TCP, so it refuses to bind or send off the
    /// host (karyos#956 review).
    NotLoopback(SocketAddr),
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "i/o: {error}"),
            Self::Log(error) => write!(f, "log: {error:?}"),
            Self::Geometry => f.write_str("the log geometry is refused"),
            Self::Bounds => f.write_str("the case's service bounds do not fit"),
            Self::Deadline => f.write_str("the deadline passed without a stop"),
            Self::Schedule(action) => write!(f, "a process run does not take {action}"),
            Self::NotAPeer => f.write_str("the node is not among its peers"),
            Self::NotLoopback(address) => {
                write!(f, "{address} is not a loopback address")
            }
        }
    }
}

impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Whether `error` only says that nothing is there yet.
fn idle(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// The ticks of the clock since `start`.
#[must_use]
pub fn ticks_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .checked_div(TICK_MS)
        .unwrap_or(0)
}

/// `message`'s client frame, for or from client session `client`: its
/// length, the session's id, a kind, then its fields, little endian; `None`
/// for a message no client or server sends the other. The id routes a
/// server's answer to its session: one client process runs every session
/// of its window over one connection.
#[must_use]
pub fn frame<M>(client: NodeId, message: &Harness<M>) -> Option<Vec<u8>> {
    let mut framed = Vec::new();
    frame_into(client, message, &mut framed).then_some(framed)
}

/// [`frame`] into `out`, cleared first: a server keeps `out`, prefilled
/// for its largest answer, so framing a reply within the case's bounds
/// allocates nothing (C5 v3). `false`, `out` unspecified, for a message
/// [`frame`] refuses.
pub fn frame_into<M>(client: NodeId, message: &Harness<M>, out: &mut Vec<u8>) -> bool {
    out.clear();
    // The body's length, set once the body is written.
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&client.to_le_bytes());
    let body = out;
    match message {
        Harness::Request(command) => {
            body.push(1);
            body.extend_from_slice(&command.encode());
        }
        Harness::Response {
            sequence,
            bytes,
            index,
            generation,
        } => {
            body.push(2);
            body.extend_from_slice(&sequence.to_le_bytes());
            body.extend_from_slice(&index.to_le_bytes());
            body.extend_from_slice(&generation.to_le_bytes());
            body.extend_from_slice(bytes);
        }
        Harness::Refused { sequence } => {
            body.push(3);
            body.extend_from_slice(&sequence.to_le_bytes());
        }
        Harness::Busy { sequence } => {
            body.push(4);
            body.extend_from_slice(&sequence.to_le_bytes());
        }
        Harness::Redirect { server } => {
            body.push(5);
            body.extend_from_slice(&server.to_le_bytes());
        }
        _ => return false,
    }
    let Ok(length) = u32::try_from(body.len().saturating_sub(4)) else {
        return false;
    };
    if let Some(prefix) = body.get_mut(..4) {
        prefix.copy_from_slice(&length.to_le_bytes());
    }
    true
}

/// The requests a server has proposed and not yet answered, by client and
/// sequence (C5 v3): a vector prefilled at initialisation from the case's
/// bounds, so inserting a request and removing it once answered neither
/// allocates nor frees within them. A request already pending is not
/// added again.
#[derive(Debug)]
pub struct Pending(Vec<(NodeId, u64)>);

impl Pending {
    /// Room for `room` requests.
    #[must_use]
    pub fn prefilled(room: usize) -> Self {
        Self(Vec::with_capacity(room))
    }

    /// Adds `request` unless it is pending already.
    pub fn insert(&mut self, request: (NodeId, u64)) {
        if !self.0.contains(&request) {
            self.0.push(request);
        }
    }

    /// Removes `request`: whether it was pending.
    pub fn remove(&mut self, request: (NodeId, u64)) -> bool {
        match self.0.iter().position(|pending| *pending == request) {
            Some(at) => {
                let _ = self.0.swap_remove(at);
                true
            }
            None => false,
        }
    }

    /// Forgets every request, keeping the room.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Requests pending.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether none is pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The pending requests a server holds at most within the case's bounds:
/// each client's answers kept ([`ServiceBounds::answers`]), at least one.
#[must_use]
pub fn pending_room(bounds: &ServiceBounds) -> usize {
    bounds.clients.len().saturating_mul(bounds.answers.max(1))
}

/// Replies a server queues between two sends at most within the case's
/// bounds: an answer for each pending request and a refusal, a busy or a
/// redirect for each client.
#[must_use]
pub fn reply_room(bounds: &ServiceBounds) -> usize {
    pending_room(bounds).saturating_add(bounds.clients.len())
}

/// A reply frame's header: its length, the session, the kind, the
/// sequence, the index and the generation.
const FRAME_HEADER: usize = 4 + 8 + 1 + 8 + 8 + 8;

/// Bytes a connection queues between two flushes without growing.
const OUTPUT_ROOM: usize = 1 << 16;

/// A client frame's session and message.
pub type Framed<M> = (NodeId, Harness<M>);

/// The next whole frame's session and message in `buffer`, which loses its
/// bytes:
/// `Some(None)` for a frame that is no message, `None` while no whole
/// frame is there. A length past [`MAX_FRAME`] is an error: the stream
/// is not this protocol.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`].
pub fn unframe<M>(buffer: &mut Vec<u8>) -> io::Result<Option<Option<Framed<M>>>> {
    let Some(length) = buffer.first_chunk::<4>().copied() else {
        return Ok(None);
    };
    let length = usize::try_from(u32::from_le_bytes(length)).unwrap_or(usize::MAX);
    if length > MAX_FRAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let Some(end) = length.checked_add(4).filter(|end| *end <= buffer.len()) else {
        return Ok(None);
    };
    let message = buffer.get(4..end).and_then(|body| {
        let (client, body) = body.split_first_chunk::<4>()?;
        Some((NodeId::from_le_bytes(*client), message_of(body)?))
    });
    let _ = buffer.drain(..end);
    Ok(Some(message))
}

fn message_of<M>(body: &[u8]) -> Option<Harness<M>> {
    let (kind, rest) = body.split_first()?;
    let u64_at = |at: usize| -> Option<u64> {
        rest.get(at..)?
            .first_chunk::<8>()
            .map(|bytes| u64::from_le_bytes(*bytes))
    };
    Some(match kind {
        1 => Harness::Request(Command::decode(rest)?),
        2 => Harness::Response {
            sequence: u64_at(0)?,
            index: u64_at(8)?,
            generation: u64_at(16)?,
            bytes: rest.get(24..)?.to_vec(),
        },
        3 if rest.len() == 8 => Harness::Refused {
            sequence: u64_at(0)?,
        },
        4 if rest.len() == 8 => Harness::Busy {
            sequence: u64_at(0)?,
        },
        5 if rest.len() == 4 => Harness::Redirect {
            server: NodeId::from_le_bytes(*rest.first_chunk::<4>()?),
        },
        _ => return None,
    })
}

/// A TCP connection carrying client frames, read and written without
/// blocking.
#[derive(Debug)]
pub struct Connection {
    stream: TcpStream,
    input: Vec<u8>,
    output: Vec<u8>,
    closed: bool,
}

impl Connection {
    /// `stream`, set not to block.
    ///
    /// # Errors
    ///
    /// The socket's.
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            input: Vec::new(),
            // Room for its queued frames between two flushes (C5 v3).
            output: Vec::with_capacity(OUTPUT_ROOM),
            closed: false,
        })
    }

    /// Whether the peer closed it or it failed.
    #[must_use]
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// Queues `frame` for sending.
    pub fn queue(&mut self, frame: &[u8]) {
        self.output.extend_from_slice(frame);
    }

    /// Writes what it can of the queue, without reading: what arrived
    /// waits for the next [`Connection::poll`].
    pub fn flush(&mut self) {
        while !self.closed && !self.output.is_empty() {
            match self.stream.write(&self.output) {
                Ok(0) => self.closed = true,
                Ok(written) => {
                    let _ = self.output.drain(..written.min(self.output.len()));
                }
                Err(error) if idle(&error) => break,
                Err(_) => self.closed = true,
            }
        }
    }

    /// Writes what it can of the queue and reads what arrived; then every
    /// whole message that arrived, in order.
    pub fn poll<M>(&mut self, scratch: &mut [u8]) -> Vec<Framed<M>> {
        self.flush();
        while !self.closed {
            match self.stream.read(scratch) {
                Ok(0) => self.closed = true,
                Ok(read) => self
                    .input
                    .extend_from_slice(scratch.get(..read).unwrap_or_default()),
                Err(error) if idle(&error) => break,
                Err(_) => self.closed = true,
            }
        }
        let mut messages = Vec::new();
        loop {
            match unframe(&mut self.input) {
                Ok(Some(Some(message))) => messages.push(message),
                Ok(Some(None)) => {}
                Ok(None) => break,
                Err(_) => {
                    self.closed = true;
                    break;
                }
            }
        }
        messages
    }
}

/// The messages a node puts back together from their fragments, in
/// buffers it keeps (C5 v3): [`MAX_PARTIAL`] slots, each with room for
/// [`MAX_FRAGMENTS`] fragments, fragment buffers drawn from a free list
/// and returned to it, and one buffer the whole message is joined in.
/// Only a message larger than a datagram is cut into fragments.
#[derive(Debug, Default)]
struct Reassembly {
    slots: Vec<Slot>,
    free: Vec<Vec<u8>>,
    whole: Vec<u8>,
}

/// One message being put back together: its sender and number, and its
/// fragments so far.
#[derive(Debug, Default)]
struct Slot {
    key: Option<(NodeId, u32)>,
    fragments: Vec<Option<Vec<u8>>>,
    /// When it was last added to: the oldest is reused first.
    touched: u64,
}

/// Fragment buffers a node keeps, prefilled.
const FRAGMENT_BUFFERS: usize = 64;

impl Reassembly {
    /// Prefilled at the node's initialisation.
    fn new() -> Self {
        Self {
            slots: (0..MAX_PARTIAL)
                .map(|_| Slot {
                    key: None,
                    fragments: Vec::with_capacity(usize::from(MAX_FRAGMENTS)),
                    touched: 0,
                })
                .collect(),
            free: (0..FRAGMENT_BUFFERS)
                .map(|_| Vec::with_capacity(MAX_DATAGRAM))
                .collect(),
            whole: Vec::with_capacity(usize::from(MAX_FRAGMENTS).saturating_mul(FRAGMENT)),
        }
    }

    /// Empties `slot`, its buffers back to the free list.
    fn clear(free: &mut Vec<Vec<u8>>, slot: &mut Slot) {
        for fragment in slot.fragments.drain(..).flatten() {
            free.push(fragment);
        }
        slot.key = None;
    }

    /// Adds fragment `position` of `count` of message `key`; the whole
    /// message's bytes once every fragment arrived.
    fn add(
        &mut self,
        key: (NodeId, u32),
        (position, count): (u16, u16),
        chunk: &[u8],
        clock: u64,
    ) -> Option<&[u8]> {
        let Self { slots, free, whole } = self;
        let at = match slots.iter().position(|slot| slot.key == Some(key)) {
            Some(at) => at,
            None => {
                // A free slot, or the one touched longest ago.
                let at = slots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, slot)| (slot.key.is_some(), slot.touched))
                    .map(|(at, _)| at)?;
                let slot = slots.get_mut(at)?;
                Self::clear(free, slot);
                slot.key = Some(key);
                slot.fragments.resize_with(usize::from(count), || None);
                at
            }
        };
        let slot = slots.get_mut(at)?;
        if slot.fragments.len() != usize::from(count) {
            return None;
        }
        slot.touched = clock;
        let mut buffer = free.pop().unwrap_or_default();
        buffer.clear();
        buffer.extend_from_slice(chunk);
        if let Some(previous) = slot
            .fragments
            .get_mut(usize::from(position))
            .and_then(|fragment| fragment.replace(buffer))
        {
            free.push(previous);
        }
        if slot.fragments.iter().any(Option::is_none) {
            return None;
        }
        whole.clear();
        for fragment in slot.fragments.iter().flatten() {
            whole.extend_from_slice(fragment);
        }
        Self::clear(free, slot);
        Some(whole.as_slice())
    }
}

/// A server's state around its core and log: what `ServerNode` keeps.
struct Serving<M> {
    id: NodeId,
    service: TestService,
    /// The service's answer to the entry it applies, kept (C5 v3).
    response: Vec<u8>,
    /// Requests it took, by client and sequence: it answers them.
    pending: Pending,
    commit: Option<u64>,
    configuration: Option<karyos_sim::harness::core::Configuration>,
    positions: Option<Positions>,
    items: Vec<(u64, Item)>,
    /// Messages to clients.
    replies: Vec<(NodeId, Harness<M>)>,
    /// Buffers for the response bytes of replies (C5 v3): a reply's bytes
    /// are copied into one inside the application window and it comes
    /// back once the reply is framed, so answering allocates nothing.
    reply_bytes: ReplyBytes,
    /// The frame a reply is written into before it is queued, kept and
    /// prefilled for the largest answer and its header (C5 v3).
    framed: Vec<u8>,
    ready: ReadyBuf<M>,
    command: Vec<u8>,
    /// Its clock, in ticks.
    now: u64,
    /// A drive error stopped it.
    stopped: bool,
    /// The limits its core was declared (W2), if any.
    limits: Option<Limits>,
    /// Its duty's log-read budget, refilled at each tick and delivery, as
    /// `ServerNode`'s.
    budget: ReadBudget,
    /// Whether it records the appends it sends and the acknowledgements
    /// it steps (W2: the byte oracle's trace).
    traces: bool,
}

/// A server's pool of reply buffers (C5 v3), prefilled at initialisation
/// from the case's bounds: one buffer of [`REPLY_SMALL`] bytes per client
/// for an append's answer, and one of the service's largest answer
/// ([`ServiceBounds::response_bytes`]) for a read. Taken and given back
/// inside [`probe::application`], so a miss, a buffer grown or the pool
/// grown, is counted as `apply`.
struct ReplyBytes(Vec<Vec<u8>>);

/// Bytes of a small reply buffer: an append's answer is 9.
const REPLY_SMALL: usize = 16;

impl ReplyBytes {
    fn prefilled(bounds: &ServiceBounds) -> Self {
        let mut pool = Vec::with_capacity(bounds.clients.len().saturating_add(1));
        pool.push(Vec::with_capacity(bounds.response_bytes()));
        pool.extend((0..bounds.clients.len()).map(|_| Vec::with_capacity(REPLY_SMALL)));
        Self(pool)
    }

    /// A copy of `bytes` in a pooled buffer: the smallest one it fits.
    fn copy(&mut self, bytes: &[u8]) -> Vec<u8> {
        let fits = self
            .0
            .iter()
            .enumerate()
            .filter(|(_, buffer)| buffer.capacity() >= bytes.len())
            .min_by_key(|(_, buffer)| buffer.capacity())
            .map(|(at, _)| at);
        let mut buffer = match fits {
            Some(at) => self.0.swap_remove(at),
            None => self.0.pop().unwrap_or_default(),
        };
        buffer.clear();
        buffer.extend_from_slice(bytes);
        buffer
    }

    /// A reply's buffer, back once the reply is framed.
    fn give_back(&mut self, mut buffer: Vec<u8>) {
        buffer.clear();
        self.0.push(buffer);
    }
}

fn observe(items: &mut Vec<(u64, Item)>, observation: Observation) {
    items.push((record::now(), Item::Observation(observation)));
}

impl<M> Serving<M> {
    fn observe(&mut self, observation: Observation) {
        observe(&mut self.items, observation);
    }

    /// A new duty: its read budget refilled, when it has limits, as
    /// `ServerNode::refill`. A loop of [`run_server`] is one duty: its
    /// deliveries, its tick and its drive share one budget.
    fn refill(&self) {
        if let Some(limits) = self.limits {
            self.budget.refill(limits.log_read_bytes);
        }
    }

    /// The duty's budget, when it has limits.
    fn metered(&self) -> Option<ReadBudget> {
        self.limits.map(|_| self.budget.clone())
    }

    /// `ServerNode`'s handling of a client's request.
    fn request<C: ConsensusCore<Message = M>>(
        &mut self,
        core: &mut C,
        log: &mut RaftLog<StdDisk>,
        command: &Command,
    ) {
        let sequence = command.sequence;
        if self.stopped {
            self.replies
                .push((command.client, Harness::Refused { sequence }));
            return;
        }
        command.encode_into(&mut self.command);
        let budget = self.metered();
        match core.propose_slice(&self.command, &mut LogView::metered(log, budget.as_ref())) {
            Ok(()) => {
                self.pending.insert((command.client, sequence));
            }
            Err(Refused::Backpressure(limit)) => {
                self.observe(Observation::Backpressure {
                    node: self.id,
                    client: command.client,
                    sequence,
                    limit,
                });
                self.replies
                    .push((command.client, Harness::Busy { sequence }));
            }
            Err(Refused::NotLeader(NotLeader {
                leader: Some(leader),
            })) if leader != self.id => {
                self.observe(Observation::Redirected {
                    node: self.id,
                    client: command.client,
                    sequence,
                    to: leader,
                });
                self.replies
                    .push((command.client, Harness::Redirect { server: leader }));
            }
            Err(Refused::NotLeader(_)) => self
                .replies
                .push((command.client, Harness::Refused { sequence })),
        }
    }

    /// `ServerNode`'s duty: drive the core, apply what committed and
    /// answer it, and record its configuration, commit and positions.
    fn duty<C: Wire<Message = M>>(
        &mut self,
        core: &mut C,
        log: &mut RaftLog<StdDisk>,
        out: &mut Vec<(NodeId, M)>,
    ) {
        if self.stopped {
            return;
        }
        let node = self.id;
        let now = self.now;
        let traces = self.traces;
        let items = RefCell::new(std::mem::take(&mut self.items));
        let Self {
            service,
            response,
            pending,
            replies,
            reply_bytes,
            ready,
            limits,
            budget,
            ..
        } = self;
        let budget = limits.is_some().then_some(&*budget);
        let driven = drive_into(
            core,
            log,
            ready,
            (budget, None),
            &mut |to, message, release| {
                if traces && let Some((term, entries)) = C::appended(&message) {
                    items.borrow_mut().push((
                        record::now(),
                        Item::Sent {
                            leader: node,
                            to,
                            term,
                            entries,
                        },
                    ));
                }
                if let Some(release) = release {
                    observe(
                        &mut items.borrow_mut(),
                        Observation::Released { node, to, release },
                    );
                }
                outbox_push(out, to, message);
            },
            &mut |entry, applying| {
                // The application is the declared path's apply stage once
                // a probed core is past its warm-up (version 1's
                // allocation gate counts "application"): the harness's
                // test service, prefilled to the case's bounds and
                // answering into the node's kept response buffer, so it
                // allocates nothing (C5 v3).
                // A reply's bytes are the application's output: copied into
                // a pooled buffer inside the same window (C5 v3).
                // Its client's request leaves the pending set in the same
                // window: the set is prefilled and frees nothing (C5 v3).
                let answered = probe::application(|| {
                    let applied = service.apply_into(entry, response)?;
                    let bytes = pending
                        .remove((applied.client, applied.sequence))
                        .then(|| reply_bytes.copy(response));
                    Some((applied, bytes))
                });
                // The judge's record of the answer: instrumentation, off the
                // declared path, so outside the window (C5 v3 run record).
                let response = answered.is_some().then(|| response.clone());
                let mut items = items.borrow_mut();
                if let Some((applied, Some(bytes))) = answered {
                    if applied.replayed {
                        observe(
                            &mut items,
                            Observation::Deduplicated {
                                node,
                                client: applied.client,
                                sequence: applied.sequence,
                            },
                        );
                    }
                    observe(
                        &mut items,
                        Observation::Reply {
                            node,
                            client: applied.client,
                            index: entry.index,
                            term: entry.term,
                            generation: FIRST_GENERATION,
                            at: now,
                        },
                    );
                    // The reply is the application's output: queued in the
                    // window, on the prefilled queue (C5 v3).
                    probe::application(|| {
                        replies.push((
                            applied.client,
                            Harness::Response {
                                sequence: applied.sequence,
                                bytes,
                                index: entry.index,
                                generation: FIRST_GENERATION,
                            },
                        ));
                    });
                }
                observe(
                    &mut items,
                    Observation::Applied {
                        node,
                        entry: entry.clone(),
                        applying,
                        response,
                    },
                );
            },
            &mut |step| observe(&mut items.borrow_mut(), Observation::Drive { node, step }),
        );
        self.items = items.into_inner();
        if let Err(error) = driven {
            // The server stops, as `ServerNode` does until a restart.
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
            self.stopped = true;
            self.pending.clear();
            return;
        }
        self.record_state(core, log);
    }

    /// The configuration, commit and positions, each when it changed.
    fn record_state<C: ConsensusCore<Message = M>>(&mut self, core: &C, log: &RaftLog<StdDisk>) {
        let node = self.id;
        if let Some(configuration) = core.configuration()
            && self.configuration.as_ref() != Some(&configuration)
        {
            let entry_term = configuration.index.and_then(|index| log.term(index));
            self.observe(Observation::Configuration {
                node,
                configuration: configuration.clone(),
                entry_term,
            });
            self.configuration = Some(configuration);
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
        let positions = Positions {
            received: core.received(),
            written: log.last_index(),
            durable: log.durable_index(),
            committed: core.committed(),
            applied: self.service.applied(),
        };
        if self.positions != Some(positions) {
            self.observe(Observation::Positions { node, positions });
            self.positions = Some(positions);
        }
    }
}

/// The core message in a datagram's fragment, once every fragment of it
/// arrived, decoded into the node's own pool (`decoder`) to be lent to the
/// core: the reassembly and the decoding are the declared path's encoding
/// stage once a probed core is past its warm-up (C5 v2, "Processes"; C5
/// v3); outside a measurement it counts nothing.
fn arrived<'d, C: Wire>(
    datagram: &[u8],
    reassembly: &mut Reassembly,
    decoder: &'d mut C::Decoder,
    clock: u64,
) -> Option<(NodeId, &'d mut C::Message)> {
    let (header, chunk) = datagram.split_at_checked(HEADER)?;
    let (kind, header) = header.split_first()?;
    if *kind != CORE {
        return None;
    }
    let (from, header) = header.split_first_chunk::<4>()?;
    let (number, header) = header.split_first_chunk::<4>()?;
    let (position, header) = header.split_first_chunk::<2>()?;
    let count = u16::from_le_bytes(*header.first_chunk::<2>()?);
    let position = u16::from_le_bytes(*position);
    let from = NodeId::from_le_bytes(*from);
    if count == 0 || count > MAX_FRAGMENTS || position >= count {
        return None;
    }
    let key = (from, u32::from_le_bytes(*number));
    probe::encoding(move || {
        let bytes = if count == 1 {
            chunk
        } else {
            reassembly.add(key, (position, count), chunk, clock)?
        };
        C::decode_lent(decoder, bytes)
    })
    .map(|message| (from, message))
}

/// Sends `message` to `address` as one or more datagrams, numbered
/// `number`: its encoding, its datagrams and their frees, after the send,
/// are one encoding step of the declared path once a probed core is past
/// its warm-up (C5 v2, "Processes"; version 1's allocation gate counts
/// "adapters and encoding included"); outside a measurement it counts
/// nothing. The message itself is freed here too, as the outbox hands it
/// over.
fn send<C: Wire>(
    socket: &UdpSocket,
    (id, number): (NodeId, u32),
    message: C::Message,
    address: SocketAddr,
    buffers: &mut Buffers,
) {
    probe::encoding(|| {
        transmit::<C>(socket, (id, number), &message, address, buffers);
        drop(message);
    });
}

/// The buffers a node encodes and sends in, kept and prefilled at its
/// initialisation (C5 v3): the message's bytes and one datagram.
#[derive(Debug)]
struct Buffers {
    body: Vec<u8>,
    datagram: Vec<u8>,
}

impl Buffers {
    fn new() -> Self {
        Self {
            body: Vec::with_capacity(usize::from(MAX_FRAGMENTS).saturating_mul(FRAGMENT)),
            datagram: Vec::with_capacity(MAX_DATAGRAM),
        }
    }
}

/// `message`'s datagrams, sent to `address`, encoded in `buffers`.
fn transmit<C: Wire>(
    socket: &UdpSocket,
    (id, number): (NodeId, u32),
    message: &C::Message,
    address: SocketAddr,
    buffers: &mut Buffers,
) {
    let Buffers { body, datagram } = buffers;
    if !C::encode_into(message, body) {
        return;
    }
    let Ok(count) = u16::try_from(body.len().div_ceil(FRAGMENT).max(1)) else {
        return;
    };
    if count > MAX_FRAGMENTS {
        return;
    }
    for position in 0..count {
        let start = usize::from(position).saturating_mul(FRAGMENT);
        let chunk = body
            .get(start..start.saturating_add(FRAGMENT).min(body.len()))
            .unwrap_or_default();
        datagram.clear();
        datagram.push(CORE);
        datagram.extend_from_slice(&id.to_le_bytes());
        datagram.extend_from_slice(&number.to_le_bytes());
        datagram.extend_from_slice(&position.to_le_bytes());
        datagram.extend_from_slice(&count.to_le_bytes());
        datagram.extend_from_slice(chunk);
        // A lost datagram is the network's to lose.
        let _ = socket.send_to(datagram, address);
    }
}

/// Queues `message` to `to` on the runner's send outbox, counted as the
/// encoding: what grows the outbox is the send path's (C5 v3 coverage).
pub fn outbox_push<M>(out: &mut Vec<(NodeId, M)>, to: NodeId, message: M) {
    probe::encoding(|| out.push((to, message)));
}

/// Runs server `config.id` of core `C`, serving `config.case`'s clients,
/// until the test's stop and the case's quiet period after it.
///
/// # Errors
///
/// [`ProcessError`].
pub fn run_server<C: Wire>(config: &NodeConfig) -> Result<Served, ProcessError> {
    if let Some((_, address)) = config
        .peers
        .iter()
        .find(|(_, address)| !address.ip().is_loopback())
    {
        return Err(ProcessError::NotLoopback(*address));
    }
    let own = config
        .peers
        .iter()
        .find(|(id, _)| *id == config.id)
        .map(|(_, address)| *address)
        .ok_or(ProcessError::NotAPeer)?;
    let ids: Vec<NodeId> = config.peers.iter().map(|(id, _)| *id).collect();
    let socket = UdpSocket::bind(own)?;
    socket.set_read_timeout(Some(Duration::from_millis(1)))?;
    let listener = TcpListener::bind(own)?;
    listener.set_nonblocking(true)?;
    std::fs::create_dir_all(&config.dir)?;
    let geometry = workloads::geometry().map_err(|_| ProcessError::Geometry)?;
    // A fresh log: the run starts every node from nothing (W1 has no
    // crash; recovery is the simulator's to check).
    let mut log = RaftLog::create(StdDisk, &config.dir, geometry, 1).map_err(ProcessError::Log)?;
    log.set_seal_interval(SEAL_TICKS);
    let cuts = isolations(&config.case).map_err(ProcessError::Schedule)?;
    let mut heals = heals(&config.case).into_iter().peekable();
    // A core under declared limits (W2) takes them at its start, as the
    // simulator's servers do; one that refuses them reports it, and the
    // case is not demonstrated for it, never skipped.
    let core = match config.case.limits {
        None => Ok(C::recover(config.id, &ids, &mut LogView::new(&mut log))),
        Some(limits) => C::recover_with(config.id, &ids, &limits, &mut LogView::new(&mut log)),
    };
    let Ok(mut core) = core else {
        return Ok(Served {
            items: vec![(
                record::now(),
                Item::Observation(Observation::Unsupported {
                    node: config.id,
                    what: "limits",
                }),
            )],
            state: ServerState {
                applied: None,
                digest: TestService::default().digest(),
                deduplicated: 0,
                leads: false,
                up: false,
            },
        });
    };
    // The service prefilled to the case's bounds, the same policy for every
    // variant (C5 v3), and room for its largest answer.
    let bounds = workloads::service_bounds(&config.case).ok_or(ProcessError::Bounds)?;
    let mut serving: Serving<C::Message> = Serving {
        id: config.id,
        service: TestService::prefilled(&bounds),
        response: Vec::with_capacity(bounds.response_bytes()),
        pending: Pending::prefilled(pending_room(&bounds)),
        commit: core.committed(),
        configuration: None,
        positions: None,
        items: Vec::new(),
        replies: Vec::with_capacity(reply_room(&bounds)),
        reply_bytes: ReplyBytes::prefilled(&bounds),
        framed: Vec::with_capacity(bounds.response_bytes().saturating_add(FRAME_HEADER)),
        ready: ReadyBuf::default(),
        command: Vec::with_capacity(command_room(&bounds)),
        now: 0,
        stopped: false,
        limits: config.case.limits,
        budget: ReadBudget::new(),
        traces: config.case.limits.is_some(),
    };
    serving.record_state(&core, &log);
    let start = Instant::now();
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut scratch = vec![0u8; 1 << 16];
    // Room for the messages of the Readys between two sends, at
    // initialisation; what still grows it is counted as the encoding
    // ([`outbox_push`]).
    let mut outbox: Vec<(NodeId, C::Message)> = Vec::with_capacity(OUTBOX_ROOM);
    let mut reassembly = Reassembly::new();
    let mut decoder = C::decoder();
    let mut buffers = Buffers::new();
    let mut connections: Vec<Connection> = Vec::new();
    let mut clients: BTreeMap<NodeId, usize> = BTreeMap::new();
    let mut number = 0u32;
    let mut ticked: Option<u64> = None;
    let mut stop_at: Option<u64> = None;
    loop {
        let now = ticks_since(start);
        serving.now = now;
        if stop_at.is_some_and(|at| now >= at.saturating_add(config.case.quiet)) {
            break;
        }
        if start.elapsed() >= config.deadline {
            return Err(ProcessError::Deadline);
        }
        // The first server marks each heal in the order of observations,
        // as the simulator's run does ([`Observation::Healed`]).
        while heals.next_if(|at| now >= *at).is_some() {
            if config.id == 0 {
                serving.observe(Observation::Healed);
            }
        }
        serving.refill();
        let budget = serving.metered();
        // New clients.
        loop {
            match listener.accept() {
                Ok((stream, _)) => connections.push(Connection::new(stream)?),
                Err(error) if idle(&error) => break,
                Err(error) => return Err(error.into()),
            }
        }
        // Messages first, at most a loop's worth.
        for _ in 0..MAX_READS_PER_LOOP {
            match socket.recv_from(&mut buffer) {
                Ok((length, _)) => {
                    let datagram = buffer.get(..length).unwrap_or_default();
                    if datagram == [STOP] {
                        stop_at = stop_at.or(Some(now));
                        continue;
                    }
                    if serving.stopped {
                        continue;
                    }
                    if let Some((from, message)) =
                        arrived::<C>(datagram, &mut reassembly, &mut decoder, now)
                    {
                        // An isolated server's link is cut both ways.
                        if cut(&cuts, now, config.id, from) {
                            continue;
                        }
                        if serving.traces
                            && let Some((term, index)) = C::acknowledged(message)
                        {
                            serving.items.push((
                                record::now(),
                                Item::Acked {
                                    leader: config.id,
                                    from,
                                    term,
                                    index,
                                },
                            ));
                        }
                        // Lent: the node keeps the message and its buffers
                        // (C5 v3).
                        core.step_lent(
                            from,
                            message,
                            &mut LogView::metered(&mut log, budget.as_ref()),
                        );
                    }
                }
                Err(error) if idle(&error) => break,
                Err(error) => return Err(error.into()),
            }
        }
        // Clients' requests, each on the connection that sent it.
        for (at, connection) in connections.iter_mut().enumerate() {
            for (_, message) in connection.poll::<C::Message>(&mut scratch) {
                if let Harness::Request(command) = message {
                    let _ = clients.insert(command.client, at);
                    serving.request(&mut core, &mut log, &command);
                }
            }
        }
        if ticked != Some(now) && !serving.stopped {
            ticked = Some(now);
            core.tick(now, &mut LogView::metered(&mut log, budget.as_ref()));
            // The log's seal duty on the harness clock, as the simulator's
            // servers run it (karyos#1050): a failed seal poisons the log,
            // and the next drive stops the server.
            let _ = log.tick(now);
        }
        serving.duty(&mut core, &mut log, &mut outbox);
        for (to, message) in outbox.drain(..) {
            let address = config
                .peers
                .iter()
                .find(|(id, _)| *id == to)
                .map(|(_, address)| *address)
                .filter(|_| !cut(&cuts, now, config.id, to));
            // A message not sent (a cut link, an unknown peer) is done with
            // all the same.
            match address {
                Some(address) => {
                    number = number.wrapping_add(1);
                    send::<C>(&socket, (config.id, number), message, address, &mut buffers);
                }
                None => probe::encoding(|| drop(message)),
            }
        }
        // Framing and queueing a reply is the application's, counted with
        // it, into the server's kept frame and the connection's prefilled
        // queue; the reply's buffer goes back to the pool in the same
        // window (C5 v3).
        let (replies, framed, reply_bytes) = (
            &mut serving.replies,
            &mut serving.framed,
            &mut serving.reply_bytes,
        );
        probe::application(|| {
            for (client, message) in replies.drain(..) {
                if let Some(connection) =
                    clients.get(&client).and_then(|at| connections.get_mut(*at))
                    && frame_into(client, &message, framed)
                {
                    connection.queue(framed);
                }
                if let Harness::Response { bytes, .. } = message {
                    reply_bytes.give_back(bytes);
                }
            }
        });
        for connection in &mut connections {
            connection.flush();
        }
    }
    let state = ServerState {
        applied: serving.service.applied(),
        digest: serving.service.digest(),
        deduplicated: serving.service.deduplicated(),
        leads: !serving.stopped && core.leads(),
        up: !serving.stopped,
    };
    // The decoder's last message, freed as a decoding is (C5 v3 coverage).
    drop_decoder::<C>(decoder);
    Ok(Served {
        items: serving.items,
        state,
    })
}

/// Bytes of the largest command a client of the case proposes: its magic,
/// client, sequence and tag, and a value of the case's payload; the node
/// encodes each request into a buffer prefilled to it (C5 v3).
#[must_use]
pub fn command_room(bounds: &ServiceBounds) -> usize {
    karyos_sim::harness::node::COMMAND_MAGIC
        .len()
        .saturating_add(std::mem::size_of::<NodeId>() + 8 + 1)
        .saturating_add(bounds.payload)
}

/// Drops `decoder`, the node's decode slot, counted as the encoding: what
/// it still holds is a decoded message's (C5 v3 coverage).
pub fn drop_decoder<C: Wire>(decoder: C::Decoder) {
    probe::encoding(|| drop(decoder));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reply pool hands out a prefilled buffer that fits and takes it
    /// back, so answering within the bounds grows nothing (C5 v3).
    #[test]
    fn a_reply_takes_a_prefilled_buffer_that_fits_and_gives_it_back() {
        let bounds = ServiceBounds {
            clients: vec![4, 5],
            values: 8,
            payload: 32,
            answers: 4,
        };
        let mut pool = ReplyBytes::prefilled(&bounds);
        let room = pool.0.capacity();
        let large = bounds.response_bytes();
        assert_eq!(pool.0.len(), 3);

        let appended = pool.copy(&[0; 9]);
        assert_eq!(appended, [0; 9]);
        assert_eq!(appended.capacity(), REPLY_SMALL);
        let read = pool.copy(&vec![1; large]);
        assert_eq!(read.len(), large);
        assert!(read.capacity() >= large);
        // The small buffers left fit an append; the large one was taken.
        assert!(pool.0.iter().all(|buffer| buffer.capacity() == REPLY_SMALL));

        pool.give_back(appended);
        pool.give_back(read);
        assert_eq!(pool.0.len(), 3);
        assert_eq!(pool.0.capacity(), room);
        assert!(pool.0.iter().all(Vec::is_empty));
        assert_eq!(
            pool.0
                .iter()
                .filter(|buffer| buffer.capacity() >= large)
                .count(),
            1
        );
    }

    #[test]
    fn every_client_message_round_trips_through_its_frame() {
        let command = Command {
            client: 3,
            sequence: 2,
            op: karyos_sim::harness::node::Op::Append(vec![1, 2, 3]),
        };
        for message in [
            Harness::<()>::Request(command),
            Harness::Response {
                sequence: 2,
                bytes: vec![0, 1],
                index: 9,
                generation: 1,
            },
            Harness::Refused { sequence: 2 },
            Harness::Busy { sequence: 2 },
            Harness::Redirect { server: 1 },
        ] {
            let mut buffer = frame(7, &message).unwrap_or_default();
            // Split across two reads: nothing until the frame is whole.
            let tail = buffer.split_off(3);
            assert!(matches!(unframe::<()>(&mut buffer), Ok(None)));
            buffer.extend_from_slice(&tail);
            assert!(matches!(
                unframe::<()>(&mut buffer),
                Ok(Some(Some((7, ref got)))) if *got == message
            ));
            assert!(buffer.is_empty());
        }
    }

    #[test]
    fn a_frame_too_long_is_refused() {
        let mut buffer = u32::MAX.to_le_bytes().to_vec();
        assert!(unframe::<()>(&mut buffer).is_err());
    }
}
