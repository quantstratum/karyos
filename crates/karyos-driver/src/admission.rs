// SPDX-License-Identifier: Apache-2.0

//! The admission server of a driver in IPC mode (Linux;
//! `quantstratum-docs: karyos/design/ipc-admission.md`, `quantstratum-docs: karyos/design/ipc-admission-server.md`).
//!
//! The driver listens on a `SOCK_SEQPACKET` socket in a private directory.
//! A connection must send a valid `Hello` with the client's pidfd within
//! the hello timeout. The driver then creates the client's command ring in
//! a region, registers the client, and queues `Admitted` with the manifest
//! of its CnC regions (command ring, broadcast buffer, counters, client
//! counters), followed
//! by one `Region` message per record with its descriptor. Every socket is
//! non-blocking; each client's outbound queue is bounded and drained from
//! the duty cycle, and a client whose next message does not fit is
//! retired.
//!
//! A client's log buffer grants (`quantstratum-docs:
//! karyos/design/ipc-data-path.md`) live in its export ledger: a `Fetch` of
//! a `Held` grant queues its `Manifest` and `Region` messages, and a
//! `Detach` of an exported (or failed) grant ends its registration. A trace
//! journal grant (`quantstratum-docs:
//! karyos/design/trace-journal-region.md`) is fetched the same way: one
//! `Manifest` with the journal number as registration, zero stream
//! registration and incarnation, and one `Journal` record, then its
//! `Region` with the journal region's descriptor (size seals only: the
//! client writes it); its `Detach` tells the driver its writer is gone.
//!
//! A client ends with `Leave` or with the exit proof (its pidfd becomes
//! readable). `Leave` is accepted only while no grant was exported and no
//! fetch is open, also while the bootstrap is still queued: the client
//! sends it only after unmapping every region it attached and closing
//! every descriptor it received, which is also how it rolls back a failed
//! attach. Messages still queued for it are dropped with their
//! descriptors. Its regions are never reused, so the release frees
//! admission capacity only. A socket closed without `Leave`, a `Leave`
//! with exports left, or any other protocol error stops serving the
//! client: grants never sent end at once, and the rest stays charged until
//! the exit proof.
//!
//! A tool (`quantstratum-docs: karyos/design/observability-and-tools.md`,
//! Tool attach) sends `ToolHello` instead, without a descriptor. The driver
//! checks its uid (`SO_PEERCRED`) as for a client and admits at most
//! `max_tools` tool connections, also while the driver is terminal, so
//! that its diagnostics stay readable. A tool gets no client slot, command
//! ring or capability: it is answered `ToolAdmitted` with the records of the
//! six diagnostic regions (driver counters, client counters, error log,
//! loss report, trace mirror, guard audit), then one `Region` per record, in record
//! order, each with the region's descriptor reopened read-only (owner
//! decision Q7, A1). The
//! connection stays open after this bootstrap, so the tool notices the
//! driver's exit when it closes. A tool holds nothing the driver must
//! reclaim (diagnostic regions are never reused while the driver lives), so
//! closing its socket frees its connection; any message it sends after
//! `ToolHello` closes the connection too.
//!
//! A readiness probe (R-CORE-35) sends `ProbeHello` instead, without a
//! descriptor. The driver checks its uid as for a tool, answers one
//! `ProbeState` with [`EmbeddedDriver::readiness`] and closes the
//! connection: no slot, no region, no descriptor, and it counts neither
//! against `max_clients` nor against `max_tools`. One step answers at most
//! [`MAX_PROBES_PER_STEP`] probes; the next ones in that step are refused
//! with `LIMIT`.

use std::collections::VecDeque;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;

use karyos_client::link::ClientLink;
use karyos_protocol::admission::{
    Capability, MAX_MESSAGE_LENGTH, Message, Record, RegionKind as WireKind, VERSION,
    hello_version, probe_hello_version, refusal, tool_hello_version,
};
use karyos_sys::command_ring::RingConsumer;
use karyos_sys::host_clock::age_ns;
use karyos_sys::ipc::{self, PidFd, Recv, Region, Sent};

use crate::counters::Event;
use crate::embedded::{EmbeddedDriver, StreamTerms};
use crate::error::DriverError;
use crate::ledger::{BindingRegion, Grant, GrantState, Ledger, Participant};
use karyos_sys::log_buffer::Role;

/// Probes one admission step answers; past it a `ProbeHello` is refused
/// with `LIMIT` (R-CORE-35).
pub const MAX_PROBES_PER_STEP: usize = 4;

/// Region id of the broadcast buffer.
pub(crate) const BROADCAST_REGION: u64 = 1;
/// Region id of the counters.
pub(crate) const COUNTERS_REGION: u64 = 2;
/// First region id of the command rings.
const FIRST_RING_REGION: u64 = 3;
/// CnC regions of the bootstrap: the command ring, the broadcast buffer,
/// the driver counters and the client counters.
const BOOTSTRAP_REGIONS: u64 = 4;
/// Messages of the bootstrap: `Admitted` and one `Region` per CnC record.
const BOOTSTRAP_MESSAGES: usize = 1 + BOOTSTRAP_REGIONS as usize;
/// Diagnostic regions granted to a tool: the driver counters, the client
/// counters, the error log, the loss report, the trace mirror and the
/// guard audit ring.
const TOOL_REGIONS: u64 = 6;
/// A small default for [`IpcConfig::max_tools`].
pub const DEFAULT_MAX_TOOLS: usize = 4;

/// Settings of the admission socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcConfig {
    /// The private directory of the socket (mode `0700`, created if
    /// absent).
    pub dir: PathBuf,
    /// Connections accepted but not yet past `Hello`.
    pub max_pending_hellos: usize,
    /// How long a connection has to send `Hello`, in the driver clock's
    /// unit.
    pub hello_timeout: u64,
    /// Messages queued for one client; at least the five of its bootstrap.
    pub max_outbound_per_client: usize,
    /// How long a client has to take its bootstrap (`Admitted` and its
    /// `Region` messages), in the driver clock's unit; a client that has
    /// not drained it by then is retired.
    pub fetch_deadline: u64,
    /// Grants one client holds at once, in any state but ended
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Bounds), and
    /// registrations it holds at once: a command beyond either is refused
    /// with `ResourcesUnavailable` and reserves nothing. Every add that
    /// makes a registration counts (`AddPublication`,
    /// `AddConcurrentPublication`, `AddSubscription`,
    /// `AddImageSubscription` and a conflated view). A registration whose
    /// last grant ended (detached, or ended unsent) is reclaimed, so it no
    /// longer counts.
    pub max_exports_per_client: usize,
    /// Fetches of one client whose messages are still queued; a `Fetch`
    /// beyond it is refused with `LIMIT`.
    pub max_fetches_per_client: usize,
    /// Records in one manifest; a grant of more regions is refused with
    /// `LIMIT`.
    pub max_regions_per_fetch: usize,
    /// Bytes of the regions of one fetch; a larger grant is refused with
    /// `LIMIT`.
    pub max_fetch_bytes: u64,
    /// Tool connections admitted at once (nonzero; [`DEFAULT_MAX_TOOLS`] is
    /// a small default); a `ToolHello` beyond it is refused with `LIMIT`.
    pub max_tools: usize,
}

/// A connection waiting for its `Hello`.
#[derive(Debug)]
struct Pending {
    socket: OwnedFd,
    since: u64,
}

/// A message waiting for its client's socket, with its descriptor and,
/// for a fetch of a grant, what its sending means for the grant.
#[derive(Debug)]
struct Outgoing {
    bytes: Vec<u8>,
    fd: Option<OwnedFd>,
    mark: Option<Mark>,
}

/// The place of one message in a grant's fetch.
#[derive(Debug, Clone, Copy)]
struct Mark {
    fetch: u64,
    export: u64,
    /// It carries a descriptor of the grant: once sent, the grant is
    /// charged until its `Detach` or the exit proof.
    descriptor: bool,
    /// The grant's last message: once sent, the grant is `Exported`.
    exported: bool,
    /// The fetch's last message: once sent, the fetch is no longer open.
    ends: bool,
}

/// An admitted client with an open socket.
#[derive(Debug)]
struct Remote<T: StreamTerms> {
    client: u64,
    socket: OwnedFd,
    pidfd: PidFd,
    link: Arc<ClientLink<T>>,
    outbound: VecDeque<Outgoing>,
    /// Since when its queue has been non-empty: a fetch (the bootstrap
    /// included) that does not drain within `fetch_deadline` retires it.
    draining_since: Option<u64>,
    /// The last fetch id it used; ids only grow.
    last_fetch: u64,
    /// Its fetches whose messages are still queued.
    open: Vec<u64>,
    /// Its socket closed before its exit proof, and its drain waits for a
    /// later step's bound (karyos#827).
    gone: bool,
}

/// An admitted tool: its socket and what is still queued of its bootstrap.
/// It holds nothing else.
#[derive(Debug)]
struct Tool {
    socket: OwnedFd,
    outbound: VecDeque<Outgoing>,
    /// When it was admitted: a bootstrap not drained within
    /// `fetch_deadline` closes the connection.
    since: u64,
}

/// A client whose socket is gone, charged until its exit proof.
#[derive(Debug)]
struct Retiring<T: StreamTerms> {
    /// Its client id, for the diagnostic of a closed client turned faulty.
    client: u64,
    pidfd: PidFd,
    link: Arc<ClientLink<T>>,
    /// Since when it has been closed without an exit proof, when it was
    /// retired as closed rather than faulty (karyos#827): past
    /// [`CLOSED_EXIT_PROOF_NS`] it counts as faulty, once.
    closed_since: Option<u64>,
}

/// How long a client whose socket closed may go without an exit proof
/// before it counts as faulty (karyos#827): a dying process's pidfd reads
/// exited within microseconds of its socket's close, so a second is far
/// past any death. Its own bound, not `fetch_deadline`, so a short fetch
/// deadline never turns a clean exit faulty (the #831 review, point 3).
const CLOSED_EXIT_PROOF_NS: u64 = 1_000_000_000;

/// What happened to a remote client in one step.
enum Step {
    Keep,
    Leave,
    /// A leave with a fetch outstanding: clean, but what was exported
    /// stays charged until the exit proof (karyos#851).
    LeaveCharged,
    Retire,
    /// Its socket closed (end of file, `EPIPE` or `ECONNRESET`), or a
    /// `Fetch` came after its exit: it is drained as exited (karyos#827).
    Gone,
}

/// The admission socket and its connections.
#[derive(Debug)]
pub(crate) struct Admission<T: StreamTerms> {
    instance: u128,
    config: IpcConfig,
    listener: OwnedFd,
    pending: Vec<Pending>,
    remotes: Vec<Remote<T>>,
    retiring: Vec<Retiring<T>>,
    tools: Vec<Tool>,
    /// Probes answered in the current step (R-CORE-35).
    probes: usize,
    next_region: u64,
}

/// The most datagrams the driver reads from an exited client's socket
/// before it releases the client (karyos#827). The driver's own bound: a
/// connected `SOCK_SEQPACKET` pair is limited by the sender's send buffer
/// in bytes, not by `net.unix.max_dgram_qlen`, so with a raised
/// `wmem_default` a client can queue more. A client that follows the
/// protocol has at most one `Detach` per export
/// (`max_exports_per_client`), one `Fetch` per fetch it may open and its
/// `Leave` queued, far below it; what is left past it is counted in
/// "admission messages dropped at exit".
const EXIT_DRAIN_DATAGRAMS: usize = 1024;

/// The most exited clients drained in one admission step (karyos#827), so
/// that many exits at once do not stall the duty cycle; the rest wait for
/// the next step.
const EXIT_DRAINS_PER_STEP: usize = 8;

/// The descriptors an IPC driver with `network` can hold at the bounds of
/// `config` (network-shared-terms, resolution 4): one per image lane
/// (`max_images` images of at most four lanes, each a region that keeps
/// its `memfd` to pass it), one per stream mapping (`max_streams` lane
/// streams, each with up to `max_retained_generations` predecessors) and
/// a socket, a pidfd and its command ring's `memfd` per client
/// (`max_clients`). The fixed regions, the admission socket, the network
/// sockets and the standard streams are not counted, so this is a lower
/// bound. `None` on overflow.
///
/// An exposed image lane also takes a `max_streams` slot, but it is the
/// image lane's own region, never cut over (N-4a): it adds no descriptor
/// and leaves its slot's `1 + max_retained_generations` unused. The sum is
/// still reached, so it is not lowered: when every stream slot holds a
/// local stream with all its retained mappings, every installed image
/// stays unexposed (no slot is free) and still holds its lane regions.
pub(crate) fn descriptors_needed(
    config: &crate::embedded::DriverConfig,
    network: &crate::net::NetworkConfig,
) -> Option<u64> {
    let lanes = u64::try_from(karyos_protocol::network::MAX_LANES).ok()?;
    let images = u64::try_from(network.agents.sessions.max_images)
        .ok()?
        .checked_mul(lanes)?;
    let mappings = u64::try_from(config.max_retained_generations)
        .ok()?
        .checked_add(1)?;
    let streams = u64::try_from(config.max_streams)
        .ok()?
        .checked_mul(mappings)?;
    let clients = u64::try_from(config.max_clients).ok()?.checked_mul(3)?;
    images.checked_add(streams)?.checked_add(clients)
}

/// Refuses `needed` descriptors (`None`: more than `u64` counts) above
/// the soft limit of `(soft, hard)` (`None`: unlimited).
///
/// # Errors
///
/// [`DriverError::DescriptorLimit`] with the numbers and the hard limit.
pub(crate) fn check_descriptors(
    needed: Option<u64>,
    (soft, hard): (Option<u64>, Option<u64>),
) -> Result<(), DriverError> {
    let Some(limit) = soft else {
        return Ok(());
    };
    match needed {
        Some(needed) if needed <= limit => Ok(()),
        needed => Err(DriverError::DescriptorLimit {
            needed: needed.unwrap_or(u64::MAX),
            limit,
            hard,
        }),
    }
}

/// A driver's instance and its region id counter: every region the
/// driver creates takes the next id, which is never reused.
#[derive(Debug)]
pub(crate) struct RegionIds<'a> {
    instance: u128,
    next: &'a mut u64,
}

impl<'a> RegionIds<'a> {
    /// The ids of `instance` from `*next` on.
    pub(crate) fn new(instance: u128, next: &'a mut u64) -> Self {
        Self { instance, next }
    }

    /// The instance and a fresh region id.
    ///
    /// # Errors
    ///
    /// [`DriverError::RegionIdsExhausted`] once the counter is spent.
    pub(crate) fn next(&mut self) -> Result<(u128, u64), DriverError> {
        let region = *self.next;
        *self.next = region
            .checked_add(1)
            .ok_or(DriverError::RegionIdsExhausted)?;
        Ok((self.instance, region))
    }
}

/// The admission instance id of a driver: its `driver_id` (SPEC.md §4)
/// as one 128-bit value. The `driver_id` is the single per-instance id;
/// IPC mode uses it for admission (coordinator decision, ACS 13555), so
/// region headers, `Admitted` and loss records name the same instance. Its
/// two words `[high, low]` pack as `u128::from(high) << 64 |
/// u128::from(low)`, as a loss record's instance does.
pub(crate) fn instance_of(driver_id: [u64; 2]) -> u128 {
    let [high, low] = driver_id;
    u128::from(high) << 64 | u128::from(low)
}

fn encode(message: &Message) -> Option<Vec<u8>> {
    let mut out = [0u8; MAX_MESSAGE_LENGTH];
    let length = message.encode(&mut out).ok()?;
    out.get(..length).map(<[u8]>::to_vec)
}

/// Refuses a hello, recording why in the error log (keyed by the refusal
/// code, so a flood of refused hellos updates one record).
fn reject<T: StreamTerms>(driver: &mut EmbeddedDriver<T>, socket: &OwnedFd, code: u64, why: &str) {
    driver.diagnostics.error(
        &mut driver.counters,
        crate::diagnostics::ErrorCode::HelloRejected,
        [0, code],
        why,
    );
    refuse(socket, code);
}

/// Sends one refusal on a connection that is then closed; best effort.
fn refuse(socket: &OwnedFd, code: u64) {
    if let Some(bytes) = encode(&Message::Refused { fetch: 0, code }) {
        let _ = ipc::send(socket.as_fd(), &bytes, None);
    }
}

/// An admission step's work count, checked (SPEC.md §14): a sum that does
/// not fit keeps the count and records the first overflow, which the duty
/// cycle reports as [`DriverError::WorkCountOverflow`] after the step ran
/// to its end, as `add_work` does for the other terms.
#[derive(Debug, Default)]
struct Work {
    count: u32,
    overflow: Option<DriverError>,
}

impl Work {
    fn add(&mut self, delta: u32) {
        match self.count.checked_add(delta) {
            Some(sum) => self.count = sum,
            None => {
                self.overflow.get_or_insert(DriverError::WorkCountOverflow {
                    count: self.count,
                    delta,
                });
            }
        }
    }

    /// Adds `delta` items; a count that does not fit `u32` overflows.
    fn add_items(&mut self, delta: usize) {
        match u32::try_from(delta) {
            Ok(delta) => self.add(delta),
            Err(_) => {
                self.overflow.get_or_insert(DriverError::WorkCountOverflow {
                    count: self.count,
                    delta: u32::MAX,
                });
            }
        }
    }

    /// The count of the work that fit, and the first overflow if any.
    fn done(self) -> (u32, Option<DriverError>) {
        (self.count, self.overflow)
    }
}

/// The manifest record of one CnC or diagnostic grant of `region`.
fn record(region: &Region, export: u64) -> Option<Record> {
    let header = region.record();
    // The one wire and sys kind table (`karyos_protocol::admission::SYS_KINDS`).
    let kind = WireKind::from_sys(header.kind);
    Some(Record {
        region: header.region,
        export,
        kind,
        layout: u32::try_from(header.layout).ok()?,
        structure_length: u64::try_from(header.structure_length).ok()?,
        generation: header.generation,
        stream_id: 0,
        session_id: 0,
        lane: 0,
        capability: Capability::None,
        allow_unconnected: false,
    })
}

impl<T: StreamTerms> Admission<T> {
    /// Opens the socket of the driver whose instance id is `instance`
    /// ([`instance_of`] its `driver_id`), which every region it creates
    /// and `Admitted` carry.
    pub(crate) fn new(config: IpcConfig, instance: u128) -> Result<Self, DriverError> {
        if config.max_pending_hellos == 0
            || config.hello_timeout == 0
            || config.fetch_deadline == 0
            || config.max_exports_per_client == 0
            || config.max_fetches_per_client == 0
            || config.max_regions_per_fetch == 0
            || config.max_fetch_bytes == 0
            || config.max_tools == 0
            || config.max_outbound_per_client < BOOTSTRAP_MESSAGES
        {
            return Err(DriverError::InvalidConfig);
        }
        let backlog = i32::try_from(config.max_pending_hellos).unwrap_or(i32::MAX);
        let listener = ipc::listen(&config.dir, backlog)?;
        Ok(Self {
            instance,
            config,
            listener,
            pending: Vec::new(),
            remotes: Vec::new(),
            retiring: Vec::new(),
            tools: Vec::new(),
            probes: 0,
            next_region: FIRST_RING_REGION,
        })
    }

    /// The driver instance id: the driver's `driver_id` as one value.
    pub(crate) fn instance(&self) -> u128 {
        self.instance
    }

    /// The time namespace of admitted client `client` against the
    /// driver's, through the process its pidfd proves
    /// (`quantstratum-docs: karyos/design/trace-tool.md`, T2); `None` for
    /// a client that is not admitted with an open socket.
    pub(crate) fn time_namespace(
        &self,
        client: u64,
    ) -> Option<karyos_sys::trace_mirror::TimeNamespace> {
        self.remotes
            .iter()
            .find(|remote| remote.client == client)
            .map(|remote| crate::trace_journals::time_namespace_of(&remote.pidfd))
    }

    /// The process id of admitted client `client`, as its pidfd proves;
    /// `None` for a client that is not admitted with an open socket.
    pub(crate) fn pid(&self, client: u64) -> Option<u32> {
        self.remotes
            .iter()
            .find(|remote| remote.client == client)
            .and_then(|remote| u32::try_from(remote.pidfd.pid()).ok())
    }

    /// Takes `count` consecutive ids from a checked counter.
    /// The driver instance and a fresh region id for a stream's log buffer
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Terms in the
    /// types). Region ids are never reused.
    pub(crate) fn next_region(&mut self) -> Result<(u128, u64), DriverError> {
        self.region_ids().next()
    }

    /// The next region id this admission gives, for a test that checks
    /// a refusal took none.
    #[cfg(test)]
    pub(crate) fn peek_next_region(&self) -> u64 {
        self.next_region
    }

    /// The instance and the region id counter, borrowed apart from the
    /// rest of the admission: the image table takes its lanes' region ids
    /// from it on the driver thread.
    pub(crate) fn region_ids(&mut self) -> RegionIds<'_> {
        RegionIds::new(self.instance, &mut self.next_region)
    }

    fn take_ids(next: &mut u64, count: u64) -> Option<u64> {
        let first = *next;
        *next = first.checked_add(count)?;
        Some(first)
    }

    /// One admission step: accepts, reads `Hello`s and client messages,
    /// drains the outbound queues and checks exit proofs. Returns work
    /// done.
    fn serve(&mut self, driver: &mut EmbeddedDriver<T>) -> (u32, Option<DriverError>) {
        let mut work = Work::default();
        self.probes = 0;
        // Accept up to the pending bound.
        let mut now = None;
        while self.pending.len() < self.config.max_pending_hellos {
            let Ok(Some(socket)) = ipc::accept(self.listener.as_fd()) else {
                break;
            };
            let since = *now.get_or_insert_with(|| driver.clock.now());
            self.pending.push(Pending { socket, since });
            work.add(1);
        }
        // One datagram per pending connection.
        let mut index = 0;
        while let Some(pending) = self.pending.get(index) {
            let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
            match ipc::recv(pending.socket.as_fd(), &mut buffer) {
                Ok(Recv::WouldBlock) => {
                    let now = *now.get_or_insert_with(|| driver.clock.now());
                    if age_ns(now, pending.since) >= self.config.hello_timeout {
                        drop(self.pending.swap_remove(index));
                        work.add(1);
                    } else {
                        index += 1;
                    }
                }
                Ok(Recv::Message(received)) => {
                    let pending = self.pending.swap_remove(index);
                    let bytes = buffer.get(..received.len).unwrap_or(&[]);
                    let now = *now.get_or_insert_with(|| driver.clock.now());
                    self.hello(driver, pending.socket, bytes, received.fd, now);
                    work.add(1);
                }
                Ok(Recv::PeerClosed) | Err(_) => {
                    drop(self.pending.swap_remove(index));
                    work.add(1);
                }
            }
        }
        // One datagram per client, then its outbound queue (karyos#827):
        // - a client the conductor found faulty is retired first, exited or
        //   not;
        // - a client whose exit is proven is not served: what it queued
        //   before it exited is drained and it is released, at most
        //   `EXIT_DRAINS_PER_STEP` of them a step;
        // - a client whose socket closed (end of file, `EPIPE` or
        //   `ECONNRESET`) counts as exited for the drain, since Linux
        //   closes a dying process's descriptors before its pidfd reads
        //   exited: drained the same way, then retired as closed, its slot
        //   charged until the exit proof; one that gives no exit proof
        //   within `CLOSED_EXIT_PROOF_NS` then counts as faulty. Otherwise
        //   only a protocol error retires a client as faulty.
        let mut index = 0;
        let mut drains = 0usize;
        while let Some(remote) = self.remotes.get_mut(index) {
            let faulty = driver
                .faulty_pending
                .iter()
                .position(|client| *client == remote.client)
                .map(|found| driver.faulty_pending.swap_remove(found));
            // Its pidfd polled once (the #831 review, point 6).
            let proven = faulty.is_none() && remote.pidfd.exited().unwrap_or(false);
            let exited = faulty.is_none() && (remote.gone || proven);
            if exited {
                if drains < EXIT_DRAINS_PER_STEP {
                    drains += 1;
                    let now = *now.get_or_insert_with(|| driver.clock.now());
                    self.release_at(index, proven, now, driver, &mut work);
                } else {
                    index += 1;
                }
                continue;
            }
            let step = if faulty.is_some() {
                Step::Retire
            } else {
                Self::receive(remote, driver, &self.config)
            };
            let step = match step {
                Step::Keep => {
                    let (step, sent) = Self::drain(remote);
                    Self::account(driver, remote.client, &sent);
                    step
                }
                other => other,
            };
            if remote.outbound.is_empty() {
                remote.draining_since = None;
            } else if remote.draining_since.is_none() {
                remote.draining_since = Some(*now.get_or_insert_with(|| driver.clock.now()));
            }
            let step = match (step, remote.draining_since) {
                (Step::Keep, Some(since))
                    if age_ns(*now.get_or_insert_with(|| driver.clock.now()), since)
                        >= self.config.fetch_deadline =>
                {
                    driver.diagnostics.error(
                        &mut driver.counters,
                        crate::diagnostics::ErrorCode::FetchDeadlineMissed,
                        [remote.client, 0],
                        "admission messages not drained within the fetch deadline",
                    );
                    Step::Retire
                }
                (step, _) => step,
            };
            match step {
                Step::Keep => index += 1,
                // Drained at once; past this step's bound, at the next.
                Step::Gone if drains < EXIT_DRAINS_PER_STEP => {
                    drains += 1;
                    let proven = remote.pidfd.exited().unwrap_or(false);
                    let now = *now.get_or_insert_with(|| driver.clock.now());
                    self.release_at(index, proven, now, driver, &mut work);
                }
                Step::Gone => {
                    remote.gone = true;
                    index += 1;
                }
                Step::Leave => {
                    let remote = self.remotes.swap_remove(index);
                    Self::fail_open(driver, &remote);
                    remote.link.mark_closed();
                    work.add(1);
                }
                Step::LeaveCharged => {
                    let remote = self.remotes.swap_remove(index);
                    Self::fail_open(driver, &remote);
                    driver.retire_leaving_client(remote.client);
                    self.retiring.push(Retiring {
                        client: remote.client,
                        pidfd: remote.pidfd,
                        link: remote.link,
                        closed_since: None,
                    });
                    work.add(1);
                }
                Step::Retire => {
                    let remote = self.remotes.swap_remove(index);
                    Self::fail_open(driver, &remote);
                    driver.retire_faulty_client(remote.client);
                    self.retiring.push(Retiring {
                        client: remote.client,
                        pidfd: remote.pidfd,
                        link: remote.link,
                        closed_since: None,
                    });
                    work.add(1);
                }
            }
        }
        // A faulty client no longer admitted has nothing left to retire.
        driver.faulty_pending.clear();
        self.serve_tools(driver, &mut now, &mut work);
        // Exit proofs of retired clients; an admitted client's is checked
        // before it is served, above.
        let before = self.retiring.len();
        let mut index = 0;
        while let Some(retiring) = self.retiring.get_mut(index) {
            if retiring.pidfd.exited().unwrap_or(false) {
                retiring.link.mark_closed();
                let _ = self.retiring.swap_remove(index);
                continue;
            }
            // A client closed with no exit proof within
            // `CLOSED_EXIT_PROOF_NS` is a live process that closed its
            // socket: faulty, once, named in a diagnostic, its slot still
            // charged until its exit proof (QS-COORDINATOR, 2026-10-28).
            if let Some(since) = retiring.closed_since
                && age_ns(*now.get_or_insert_with(|| driver.clock.now()), since)
                    >= CLOSED_EXIT_PROOF_NS
            {
                driver.counters.add(Event::ClientsFaulty, 1);
                driver.diagnostics.error(
                    &mut driver.counters,
                    crate::diagnostics::ErrorCode::ClientProtocolViolation,
                    [retiring.client, 0],
                    "a client closed its socket and gave no exit proof",
                );
                retiring.closed_since = None;
            }
            index += 1;
        }
        work.add_items(before - self.retiring.len());
        work.done()
    }

    /// Handles the first datagram of a connection: admits the client or
    /// refuses it and closes the connection.
    fn hello(
        &mut self,
        driver: &mut EmbeddedDriver<T>,
        socket: OwnedFd,
        bytes: &[u8],
        fd: Option<OwnedFd>,
        now: u64,
    ) {
        if let Some(version) = tool_hello_version(bytes) {
            return self.tool_hello(driver, socket, bytes, fd, version, now);
        }
        if let Some(version) = probe_hello_version(bytes) {
            return self.probe(driver, &socket, bytes, fd, version);
        }
        let Some(version) = hello_version(bytes) else {
            return;
        };
        if version != VERSION {
            reject(
                driver,
                &socket,
                refusal::INCOMPATIBLE_VERSION,
                "incompatible version",
            );
            return;
        }
        let pidfd = match (Message::decode(bytes), fd) {
            (Ok(Message::Hello { .. }), Some(fd)) => match PidFd::validate(fd) {
                Ok(pidfd) => pidfd,
                Err(_) => return reject(driver, &socket, refusal::PROFILE, "invalid pidfd"),
            },
            _ => return reject(driver, &socket, refusal::PROFILE, "malformed hello"),
        };
        let proven = ipc::peer_credentials(socket.as_fd()).is_ok_and(|peer| {
            peer.uid.as_raw() == ipc::own_uid() && peer.pid.as_raw_nonzero().get() == pidfd.pid()
        });
        if !proven || pidfd.exited().unwrap_or(true) {
            return reject(driver, &socket, refusal::PROFILE, "peer not proven");
        }
        if !driver.admitting {
            return reject(driver, &socket, refusal::SHUTTING_DOWN, "not admitting");
        }
        if driver.terminal || driver.clients.len() >= driver.config.max_clients {
            return reject(driver, &socket, refusal::LIMIT, "client limit or terminal");
        }
        match self.bootstrap(driver) {
            Some((client, link, outbound)) => self.remotes.push(Remote {
                client,
                socket,
                pidfd,
                link,
                outbound,
                draining_since: Some(now),
                last_fetch: 0,
                open: Vec::new(),
                gone: false,
            }),
            None => reject(driver, &socket, refusal::RESOURCES, "bootstrap resources"),
        }
    }

    /// Creates the client's ring, registers the client and builds its
    /// bootstrap messages.
    fn bootstrap(
        &mut self,
        driver: &mut EmbeddedDriver<T>,
    ) -> Option<(u64, Arc<ClientLink<T>>, VecDeque<Outgoing>)> {
        let mut next_region = self.next_region;
        let mut next_export = driver.next_export;
        let region = Self::take_ids(&mut next_region, 1)?;
        let first_export = Self::take_ids(&mut next_export, BOOTSTRAP_REGIONS)?;
        let consumer =
            RingConsumer::create_in(self.instance, region, driver.config.ring_capacity).ok()?;
        let regions = [
            consumer.region()?,
            driver.broadcast.region()?,
            driver.counters.region()?,
            driver.client_counters.region()?,
        ];
        let mut records = Vec::with_capacity(regions.len());
        let mut fds = Vec::with_capacity(regions.len());
        for (offset, region) in (0u64..).zip(regions) {
            records.push(record(region, first_export.checked_add(offset)?)?);
            fds.push(region.descriptor()?.try_clone_to_owned().ok()?);
        }
        let link = Arc::new(ClientLink::new());
        let ledger = Ledger::new(
            self.config.max_exports_per_client,
            self.config.max_regions_per_fetch,
            self.config.max_fetch_bytes,
        );
        let client = driver
            .admit(consumer, Arc::clone(&link), Some(ledger))
            .ok()?;
        self.next_region = next_region;
        driver.next_export = next_export;
        let mut outbound = VecDeque::with_capacity(BOOTSTRAP_MESSAGES);
        outbound.push_back(Outgoing {
            bytes: encode(&Message::Admitted {
                instance: self.instance,
                version: VERSION,
                client,
                records,
            })?,
            fd: None,
            mark: None,
        });
        for (index, fd) in (0u64..).zip(fds) {
            outbound.push_back(Outgoing {
                bytes: encode(&Message::Region { fetch: 0, index })?,
                fd: Some(fd),
                mark: None,
            });
        }
        Some((client, link, outbound))
    }

    /// Handles a `ToolHello` of `version`: admits the tool or refuses it and
    /// closes the connection. Refusals reach the error log as a client
    /// hello's do.
    fn tool_hello(
        &mut self,
        driver: &mut EmbeddedDriver<T>,
        socket: OwnedFd,
        bytes: &[u8],
        fd: Option<OwnedFd>,
        version: u64,
        now: u64,
    ) {
        if version != VERSION {
            return reject(
                driver,
                &socket,
                refusal::INCOMPATIBLE_VERSION,
                "incompatible tool version",
            );
        }
        // A tool passes no descriptor; one that does is closed with the
        // refusal.
        if fd.is_some() || !matches!(Message::decode(bytes), Ok(Message::ToolHello { .. })) {
            return reject(driver, &socket, refusal::PROFILE, "malformed tool hello");
        }
        let same_uid = ipc::peer_credentials(socket.as_fd())
            .is_ok_and(|peer| peer.uid.as_raw() == ipc::own_uid());
        if !same_uid {
            return reject(driver, &socket, refusal::PROFILE, "tool of another uid");
        }
        if self.tools.len() >= self.config.max_tools {
            return reject(driver, &socket, refusal::LIMIT, "tool limit");
        }
        match self.tool_bootstrap(driver) {
            Some(outbound) => self.tools.push(Tool {
                socket,
                outbound,
                since: now,
            }),
            None => reject(
                driver,
                &socket,
                refusal::RESOURCES,
                "tool bootstrap resources",
            ),
        }
    }

    /// Answers a `ProbeHello` of `version` with the driver's readiness, or
    /// refuses it; the connection closes either way (R-CORE-35).
    fn probe(
        &mut self,
        driver: &mut EmbeddedDriver<T>,
        socket: &OwnedFd,
        bytes: &[u8],
        fd: Option<OwnedFd>,
        version: u64,
    ) {
        if version != VERSION {
            return reject(
                driver,
                socket,
                refusal::INCOMPATIBLE_VERSION,
                "incompatible probe version",
            );
        }
        if fd.is_some() || !matches!(Message::decode(bytes), Ok(Message::ProbeHello { .. })) {
            return reject(driver, socket, refusal::PROFILE, "malformed probe hello");
        }
        let same_uid = ipc::peer_credentials(socket.as_fd())
            .is_ok_and(|peer| peer.uid.as_raw() == ipc::own_uid());
        if !same_uid {
            return reject(driver, socket, refusal::PROFILE, "probe of another uid");
        }
        if self.probes >= MAX_PROBES_PER_STEP {
            return reject(driver, socket, refusal::LIMIT, "probe limit");
        }
        self.probes += 1;
        let (state, reason) = driver.readiness().wire();
        let answer = Message::ProbeState {
            state,
            reason,
            uptime_ns: driver.uptime(),
        };
        // Best effort, as a refusal: a probe that went away learns nothing.
        if let Some(bytes) = encode(&answer) {
            let _ = ipc::send(socket.as_fd(), &bytes, None);
        }
    }

    /// Builds a tool's bootstrap: `ToolAdmitted` with the six diagnostic
    /// records, then one `Region` per record with a read-only descriptor
    /// (A1). Export ids come from the driver's checked counter, so no id is
    /// ever given twice, although no ledger charges a tool's grants.
    fn tool_bootstrap(&self, driver: &mut EmbeddedDriver<T>) -> Option<VecDeque<Outgoing>> {
        let regions = [
            driver.counters.region()?,
            driver.client_counters.region()?,
            driver.diagnostics.error_region()?,
            driver.diagnostics.loss_region()?,
            driver.trace_journals.region()?,
            driver.guards.region()?,
        ];
        let mut next_export = driver.next_export;
        let first_export = Self::take_ids(&mut next_export, TOOL_REGIONS)?;
        let mut records = Vec::with_capacity(regions.len());
        let mut fds = Vec::with_capacity(regions.len());
        for (offset, region) in (0u64..).zip(regions) {
            records.push(record(region, first_export.checked_add(offset)?)?);
            fds.push(region.read_only_descriptor().ok()?);
        }
        let mut outbound = VecDeque::with_capacity(regions.len() + 1);
        outbound.push_back(Outgoing {
            bytes: encode(&Message::ToolAdmitted {
                instance: self.instance,
                version: VERSION,
                records,
            })?,
            fd: None,
            mark: None,
        });
        for (index, fd) in (0u64..).zip(fds) {
            outbound.push_back(Outgoing {
                bytes: encode(&Message::Region { fetch: 0, index })?,
                fd: Some(fd),
                mark: None,
            });
        }
        driver.next_export = next_export;
        Some(outbound)
    }

    /// One step of every tool connection: a tool sends nothing after
    /// `ToolHello`, so any datagram, a closed socket or a receive error
    /// closes the connection; then its bootstrap is drained, and a
    /// bootstrap not drained within `fetch_deadline` closes it too. Returns
    /// work done.
    fn serve_tools(
        &mut self,
        driver: &mut EmbeddedDriver<T>,
        now: &mut Option<u64>,
        work: &mut Work,
    ) {
        let mut index = 0;
        while let Some(tool) = self.tools.get_mut(index) {
            let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
            let mut keep = matches!(
                ipc::recv(tool.socket.as_fd(), &mut buffer),
                Ok(Recv::WouldBlock)
            );
            while keep && let Some(next) = tool.outbound.front() {
                match ipc::send(
                    tool.socket.as_fd(),
                    &next.bytes,
                    next.fd.as_ref().map(AsFd::as_fd),
                ) {
                    Ok(Sent::Sent) => {
                        drop(tool.outbound.pop_front());
                        work.add(1);
                    }
                    Ok(Sent::WouldBlock) => break,
                    Err(_) => keep = false,
                }
            }
            if keep
                && !tool.outbound.is_empty()
                && age_ns(*now.get_or_insert_with(|| driver.clock.now()), tool.since)
                    >= self.config.fetch_deadline
            {
                driver.diagnostics.error(
                    &mut driver.counters,
                    crate::diagnostics::ErrorCode::FetchDeadlineMissed,
                    [0, 0],
                    "tool bootstrap not drained within the fetch deadline",
                );
                keep = false;
            }
            if keep {
                index += 1;
            } else {
                // Closes the socket; queued descriptors are closed with it.
                drop(self.tools.swap_remove(index));
                work.add(1);
            }
        }
    }

    /// Reads at most one datagram of an admitted client.
    fn receive(remote: &mut Remote<T>, driver: &mut EmbeddedDriver<T>, config: &IpcConfig) -> Step {
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        match ipc::recv(remote.socket.as_fd(), &mut buffer) {
            Ok(Recv::WouldBlock) => Step::Keep,
            Ok(Recv::Message(received)) if received.fd.is_none() => {
                match Self::decoded(&buffer, &received) {
                    // Leave releases the client like its exit proof, so it
                    // is accepted only while nothing was exported and no
                    // fetch is open; otherwise it is a protocol error and
                    // everything sent stays charged until the exit proof.
                    Some(Message::Leave)
                        if remote.open.is_empty()
                            && driver.ledger(remote.client).is_none_or(Ledger::only_held) =>
                    {
                        Step::Leave
                    }
                    // A Leave with a fetch outstanding (one the client
                    // abandoned, or exports it has not detached) is a clean
                    // leave, never a fault (QS-COORDINATOR, karyos#851):
                    // the client stops being served, but what was exported
                    // stays charged until its exit proof, as it may still
                    // be mapped.
                    Some(Message::Leave) => Step::LeaveCharged,
                    // Never served once the client's exit is proven: it
                    // would send a region to a dead client (karyos#827).
                    Some(Message::Fetch { .. }) if remote.pidfd.exited().unwrap_or(false) => {
                        driver.counters.add(Event::FetchesDroppedAtExit, 1);
                        Step::Gone
                    }
                    Some(Message::Fetch { fetch, key }) => {
                        Self::fetch(remote, driver, config, fetch, key)
                    }
                    Some(Message::Detach { export }) => Self::detach(remote, driver, export),
                    _ => Step::Retire,
                }
            }
            // The end of the connection, confirmed by `POLLRDHUP` (a 0-byte
            // datagram queued just before it is read past by the drain), or
            // the peer gone: drained, then released or retired as closed.
            Ok(Recv::PeerClosed) if ipc::peer_hung_up(remote.socket.as_fd()) => Step::Gone,
            Err(error) if ipc::peer_gone(&error) => Step::Gone,
            // A descriptor on a message that takes none, a 0-byte datagram
            // from a live client, or a receive error: a protocol error.
            Ok(Recv::Message(_) | Recv::PeerClosed) | Err(_) => Step::Retire,
        }
    }

    /// A client message as `receive` and `drain_exited` both read it: one
    /// that carries no descriptor and decodes; `None` otherwise.
    fn decoded(buffer: &[u8], received: &ipc::Received) -> Option<Message> {
        if received.fd.is_some() {
            return None;
        }
        Message::decode(buffer.get(..received.len).unwrap_or(&[])).ok()
    }

    /// Releases admitted client `index` (karyos#827), whose exit is proven,
    /// or whose socket closed before it (`proven` false): its queued
    /// outbound messages are dropped and counted, since nothing is sent to
    /// a dead client; what it queued is drained. A proven exit releases it
    /// like a `Leave`; a closed socket retires it as closed, its slot
    /// charged until the exit proof and counted faulty if none comes within
    /// `CLOSED_EXIT_PROOF_NS`.
    fn release_at(
        &mut self,
        index: usize,
        proven: bool,
        now: u64,
        driver: &mut EmbeddedDriver<T>,
        work: &mut Work,
    ) {
        let mut remote = self.remotes.swap_remove(index);
        // Its partly sent fetches fail first, so a queued `Detach` of one
        // of their grants is served.
        Self::fail_open(driver, &remote);
        if let Ok(unsent) = u64::try_from(remote.outbound.len())
            && unsent > 0
        {
            driver.counters.add(Event::OutboundDroppedAtExit, unsent);
        }
        remote.outbound.clear();
        let served = Self::drain_exited(&mut remote, driver);
        if proven {
            remote.link.mark_closed();
        } else {
            driver.retire_closed_client(remote.client);
            self.retiring.push(Retiring {
                client: remote.client,
                pidfd: remote.pidfd,
                link: remote.link,
                closed_since: Some(now),
            });
        }
        work.add_items(served.saturating_add(1));
    }

    /// Reads what an exited client queued on its socket before it exited
    /// (karyos#827), and returns how many messages it served. It runs
    /// instead of the client's turn, never after it, so nothing is fetched
    /// or sent for a dead client.
    ///
    /// - A `Detach` ends its grant as one, as for a live client; one naming
    ///   no detachable export is dropped and counted.
    /// - A `Leave` changes nothing: the exit releases the client anyway.
    /// - A `Fetch` would create state for a dead client: discarded unread
    ///   and counted, so `Fetch` messages in front of a `Detach` cost only
    ///   their reads.
    /// - A message that carries a descriptor or does not decode is dropped
    ///   and counted; so is a 0-byte datagram. A failed receive ends the
    ///   drain, and `ECONNRESET`, reported once, takes no datagram.
    ///
    /// It reads at most [`EXIT_DRAIN_DATAGRAMS`] datagrams and stops exactly
    /// there; a message still queued then is counted once as dropped, and
    /// the exit discards the rest with the socket.
    fn drain_exited(remote: &mut Remote<T>, driver: &mut EmbeddedDriver<T>) -> usize {
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        let mut served = 0;
        // Datagrams taken, which the bound counts: a skipped `ECONNRESET`
        // takes none (the #831 review, point 9).
        let mut taken = 0;
        // A 0-byte read with the peer hung up is the end of the stream, or
        // a 0-byte datagram queued before the close: the next read tells
        // them apart (the #831 review, point 1). At the end, every read is
        // 0 bytes.
        let mut zero_at_close = false;
        let mut reset_seen = false;
        while taken < EXIT_DRAIN_DATAGRAMS {
            let received = match ipc::recv(remote.socket.as_fd(), &mut buffer) {
                Ok(Recv::Message(received)) => {
                    if core::mem::take(&mut zero_at_close) {
                        // The 0-byte read was a datagram after all.
                        driver
                            .counters
                            .add(Event::AdmissionMessagesDroppedAtExit, 1);
                    }
                    taken += 1;
                    received
                }
                Ok(Recv::WouldBlock) => return served,
                Ok(Recv::PeerClosed) if ipc::peer_hung_up(remote.socket.as_fd()) => {
                    if zero_at_close {
                        return served;
                    }
                    zero_at_close = true;
                    continue;
                }
                // A 0-byte datagram: dropped and counted, and the drain
                // goes on.
                Ok(Recv::PeerClosed) => {
                    taken += 1;
                    driver
                        .counters
                        .add(Event::AdmissionMessagesDroppedAtExit, 1);
                    continue;
                }
                // A dying client that left a reply unread sets the socket's
                // error (`ECONNRESET`), reported once and before any
                // datagram: nothing was taken, and the drain goes on.
                Err(error) if ipc::peer_gone(&error) && !reset_seen => {
                    reset_seen = true;
                    continue;
                }
                // A protocol error took exactly one datagram: counted, and
                // the drain goes on. A failed call ends it.
                Err(error) => {
                    taken += 1;
                    driver
                        .counters
                        .add(Event::AdmissionMessagesDroppedAtExit, 1);
                    if matches!(error, karyos_sys::error::SysError::Os { .. }) {
                        return served;
                    }
                    continue;
                }
            };
            match Self::decoded(&buffer, &received) {
                Some(Message::Detach { export }) => {
                    if matches!(Self::detach(remote, driver, export), Step::Keep) {
                        served += 1;
                    } else {
                        driver
                            .counters
                            .add(Event::AdmissionMessagesDroppedAtExit, 1);
                    }
                }
                Some(Message::Leave) => served += 1,
                Some(Message::Fetch { .. }) => {
                    driver.counters.add(Event::FetchesDroppedAtExit, 1);
                }
                _ => driver
                    .counters
                    .add(Event::AdmissionMessagesDroppedAtExit, 1),
            }
        }
        if matches!(
            ipc::recv(remote.socket.as_fd(), &mut buffer),
            Ok(Recv::Message(_))
        ) {
            driver
                .counters
                .add(Event::AdmissionMessagesDroppedAtExit, 1);
        }
        served
    }

    /// Serves `Fetch { fetch, key }` (`quantstratum-docs:
    /// karyos/design/ipc-data-path.md`, Grants and the export ledger, step
    /// 2): only for a `Held` grant of this client, moved to `Exporting`
    /// before anything is queued, so a second fetch of the key is refused.
    /// Queues one `Manifest` and one `Region` per record.
    fn fetch(
        remote: &mut Remote<T>,
        driver: &mut EmbeddedDriver<T>,
        config: &IpcConfig,
        fetch: u64,
        key: u64,
    ) -> Step {
        // Fetch 0 is the bootstrap's alone.
        if fetch == 0 {
            return Step::Retire;
        }
        let bound = config.max_outbound_per_client;
        let refuse = |remote: &mut Remote<T>, code: u64| {
            Self::queue(remote, &Message::Refused { fetch, code }, bound)
        };
        // Fetch ids only grow; a reused one is refused.
        if fetch <= remote.last_fetch {
            return refuse(remote, refusal::LIMIT);
        }
        remote.last_fetch = fetch;
        if remote.open.len() >= config.max_fetches_per_client {
            return refuse(remote, refusal::LIMIT);
        }
        let Some(grant) = driver
            .ledger(remote.client)
            .and_then(|ledger| ledger.held(key))
            .copied()
        else {
            return refuse(remote, refusal::UNKNOWN_KEY);
        };
        if let Participant::Journal { journal } = grant.participant {
            let found = driver
                .trace_journals
                .journal_region(journal)
                .and_then(|region| Some((record(region, grant.export)?, descriptor(region))));
            let Some((record, fd)) = found else {
                return refuse(remote, refusal::RESOURCES);
            };
            return Self::queue_fetch(
                remote,
                driver,
                config,
                fetch,
                key,
                vec![(grant, record, fd)],
                0,
            );
        }
        if grant.participant == Participant::Conflation {
            // The table's region, reopened read-only (A1): the view never
            // gets the driver's writable descriptor. Gone with the feeder
            // (stream removed, feeder lost or ended), it is refused.
            let found = driver
                .streams
                .iter()
                .find(|s| s.id == grant.stream)
                .and_then(|stream| {
                    let region = stream.feeder.as_ref()?.writer.region()?;
                    let record = Record {
                        stream_id: stream.stream_id,
                        session_id: stream.session_id,
                        lane: stream.config.lane.get(),
                        ..record(region, grant.export)?
                    };
                    Some((record, region.read_only_descriptor().ok()))
                });
            let Some((record, fd)) = found else {
                return refuse(remote, refusal::RESOURCES);
            };
            return Self::queue_fetch(
                remote,
                driver,
                config,
                fetch,
                key,
                vec![(grant, record, fd)],
                0,
            );
        }
        let Some(stream) = driver.streams.iter().find(|s| s.id == grant.stream) else {
            return refuse(remote, refusal::RESOURCES);
        };
        // The mapping of the grant's own incarnation and generation: never
        // another incarnation's buffer; a retired one is refused. Its base
        // goes in the manifest, so the client's positions are absolute.
        let Some((region, base)) = stream
            .grant_buffer(grant.incarnation, grant.generation)
            .and_then(|(buffer, base)| {
                Some((
                    <T as crate::embedded::sealed::Create>::region(buffer)?,
                    base,
                ))
            })
        else {
            return refuse(remote, refusal::RESOURCES);
        };
        let Some(record) = grant_record(
            region,
            &grant,
            stream.stream_id,
            stream.session_id,
            stream.config.lane.get(),
            stream.allow_unconnected,
        ) else {
            return refuse(remote, refusal::RESOURCES);
        };
        let mut parts = vec![(grant, record, descriptor(region))];
        // A guarded publication's binding, under the same key: its regions
        // in manifest order, each its own export.
        let binding = driver
            .ledger(remote.client)
            .map(|ledger| ledger.held_binding(key))
            .unwrap_or_default();
        for part in binding {
            let Some(found) = binding_part(driver, &part, record) else {
                return refuse(remote, refusal::RESOURCES);
            };
            parts.push(found);
        }
        Self::queue_fetch(remote, driver, config, fetch, key, parts, base)
    }

    /// Queues the `Manifest` and one `Region` per record of a grant's
    /// fetch, after the fetch bounds; every grant of the fetch is spent
    /// before anything is queued. `parts` holds the grant, its record and
    /// descriptor, then those of a guarded publication's binding, in
    /// manifest order. `base` is the stream position where a log buffer
    /// grant's mapping starts; zero for any other region.
    fn queue_fetch(
        remote: &mut Remote<T>,
        driver: &mut EmbeddedDriver<T>,
        config: &IpcConfig,
        fetch: u64,
        key: u64,
        parts: Vec<(Grant, Record, Option<OwnedFd>)>,
        base: u64,
    ) -> Step {
        let bound = config.max_outbound_per_client;
        let refuse = |remote: &mut Remote<T>, code: u64| {
            Self::queue(remote, &Message::Refused { fetch, code }, bound)
        };
        let Some((grant, _, _)) = parts.first() else {
            return refuse(remote, refusal::RESOURCES);
        };
        let grant = *grant;
        // One log buffer region per grant: one lane, or one journal, and a
        // guarded publication's binding beside it. The byte bound counts
        // whole regions, headers included.
        let bytes = parts.iter().try_fold(0u64, |total, (_, record, _)| {
            u64::try_from(karyos_sys::ipc::HEADER_STRIDE)
                .ok()
                .and_then(|header| record.structure_length.checked_add(header))
                .and_then(|bytes| total.checked_add(bytes))
        });
        if config.max_regions_per_fetch < parts.len()
            || bytes.is_none_or(|bytes| bytes > config.max_fetch_bytes)
        {
            return refuse(remote, refusal::LIMIT);
        }
        let mut regions = Vec::with_capacity(parts.len());
        for (part, record, fd) in parts {
            let Some(fd) = fd else {
                return refuse(remote, refusal::RESOURCES);
            };
            regions.push((part.export, record, fd));
        }
        // The publication identity of the grant, whose driver part is the
        // instance of `Admitted` (ACS 13555), and the incarnation the grant
        // was issued on (a fresh incarnation follows a guard close and
        // reopen; a mapping cutover keeps it). A journal grant names no
        // stream: both are zero.
        let (stream_registration, incarnation) = match grant.participant {
            Participant::Journal { .. } => (0, 0),
            // The publication's identity: the aggregate's registration; the
            // record's lane names the lane.
            _ => (
                driver
                    .streams
                    .iter()
                    .find(|s| s.id == grant.stream)
                    .map_or(grant.stream, |s| s.aggregate.registration),
                grant.incarnation,
            ),
        };
        let Some(manifest) = encode(&Message::Manifest {
            fetch,
            key,
            registration: grant.registration,
            stream_registration,
            incarnation,
            base,
            records: regions.iter().map(|(_, record, _)| *record).collect(),
        }) else {
            return refuse(remote, refusal::RESOURCES);
        };
        let mut messages = Vec::with_capacity(regions.len());
        for (index, (export, _, fd)) in (0u64..).zip(regions) {
            let Some(bytes) = encode(&Message::Region { fetch, index }) else {
                return refuse(remote, refusal::RESOURCES);
            };
            messages.push((export, bytes, fd));
        }
        if messages
            .len()
            .checked_add(remote.outbound.len())
            .is_none_or(|queued| queued >= bound)
        {
            return Step::Retire;
        }
        // Effect: every grant of the fetch is spent before anything is
        // queued.
        if let Some(ledger) = driver.ledger_mut(remote.client) {
            for (export, _, _) in &messages {
                ledger.set_state(*export, GrantState::Exporting);
            }
        }
        remote.outbound.push_back(Outgoing {
            bytes: manifest,
            fd: None,
            mark: Some(Mark {
                fetch,
                export: grant.export,
                descriptor: false,
                exported: false,
                ends: false,
            }),
        });
        let count = messages.len();
        for (index, (export, bytes, fd)) in messages.into_iter().enumerate() {
            remote.outbound.push_back(Outgoing {
                bytes,
                fd: Some(fd),
                mark: Some(Mark {
                    fetch,
                    export,
                    descriptor: true,
                    exported: true,
                    ends: index.checked_add(1) == Some(count),
                }),
            });
        }
        remote.open.push(fetch);
        Step::Keep
    }

    /// Serves `Detach { export }` (`quantstratum-docs:
    /// karyos/design/ipc-data-path.md`, Detach, exit and Leave): accepted
    /// only from the socket of the client that owns the export, for an
    /// `Exported` or `Failed` grant; the client unmapped it first, which is
    /// the proof that ends its registration. Anything else is a protocol
    /// error.
    fn detach(remote: &Remote<T>, driver: &mut EmbeddedDriver<T>, export: u64) -> Step {
        let Some(grant) = driver
            .ledger_mut(remote.client)
            .and_then(|ledger| ledger.detach(export))
        else {
            return Step::Retire;
        };
        driver.end_grant(&grant);
        driver.counters.add(Event::GrantsDetached, 1);
        Step::Keep
    }

    /// Applies what the sent messages mean for their grants: a sent
    /// descriptor charges the grant, a fetch's last message exports it.
    fn account(driver: &mut EmbeddedDriver<T>, client: u64, sent: &[Mark]) {
        if sent.is_empty() {
            return;
        }
        let Some(ledger) = driver.ledger_mut(client) else {
            return;
        };
        let mut exported = 0u64;
        for mark in sent {
            if mark.descriptor {
                ledger.mark_sent(mark.export);
            }
            if mark.exported {
                ledger.set_state(mark.export, GrantState::Exported);
                exported += 1;
            }
        }
        driver.counters.add(Event::GrantsExported, exported);
    }

    /// Marks `Failed` every grant whose fetch still had messages queued
    /// when the client left or was retired.
    fn fail_open(driver: &mut EmbeddedDriver<T>, remote: &Remote<T>) {
        let Some(ledger) = driver.ledger_mut(remote.client) else {
            return;
        };
        for mark in remote.outbound.iter().filter_map(|outgoing| outgoing.mark) {
            ledger.set_state(mark.export, GrantState::Failed);
        }
    }

    /// Queues one message without a descriptor; retires the client when
    /// its queue is full.
    fn queue(remote: &mut Remote<T>, message: &Message, bound: usize) -> Step {
        let Some(bytes) = encode(message) else {
            return Step::Retire;
        };
        if remote.outbound.len() >= bound {
            return Step::Retire;
        }
        remote.outbound.push_back(Outgoing {
            bytes,
            fd: None,
            mark: None,
        });
        Step::Keep
    }

    /// Sends queued messages while the socket takes them; returns the
    /// marks of the messages sent.
    fn drain(remote: &mut Remote<T>) -> (Step, Vec<Mark>) {
        let mut sent = Vec::new();
        // Its exit checked once per drain, at the first descriptor (the
        // #831 review, point 5).
        let mut exited = None;
        while let Some(next) = remote.outbound.front() {
            // No descriptor goes to a client whose exit is proven
            // (karyos#827). The window from its descriptors' close to its
            // pidfd's readiness remains; a send in it fails with `EPIPE`.
            if next.fd.is_some()
                && *exited.get_or_insert_with(|| remote.pidfd.exited().unwrap_or(false))
            {
                return (Step::Gone, sent);
            }
            match ipc::send(
                remote.socket.as_fd(),
                &next.bytes,
                next.fd.as_ref().map(AsFd::as_fd),
            ) {
                Ok(Sent::Sent) => {
                    if let Some(mark) = remote.outbound.pop_front().and_then(|done| done.mark) {
                        if mark.ends {
                            remote.open.retain(|open| *open != mark.fetch);
                        }
                        sent.push(mark);
                    }
                }
                Ok(Sent::WouldBlock) => break,
                Err(error) if ipc::peer_gone(&error) => return (Step::Gone, sent),
                Err(_) => return (Step::Retire, sent),
            }
        }
        (Step::Keep, sent)
    }
}

/// The record and descriptor of a guarded publication's binding grant
/// `grant`, beside the log buffer record `buffer` of its publication: the
/// ring and the guard words read-only, the consumed cell writable for its
/// client alone. `None` when its region is gone.
fn binding_part<T: StreamTerms>(
    driver: &EmbeddedDriver<T>,
    grant: &Grant,
    buffer: Record,
) -> Option<(Grant, Record, Option<OwnedFd>)> {
    let Participant::Binding { region: which } = grant.participant else {
        return None;
    };
    let held = |export: u64| {
        driver
            .binding_exports
            .iter()
            .find(|(held, _)| *held == export)
            .and_then(|(_, words)| words.shared())
    };
    let (region, fd) = match which {
        BindingRegion::Outcomes => {
            let region = held(grant.export)?;
            (region, region.read_only_descriptor().ok())
        }
        BindingRegion::Consumed => {
            let region = held(grant.export)?;
            (region, descriptor(region))
        }
        BindingRegion::Guards => {
            let region = driver.guards.guard_words().shared()?;
            (region, region.read_only_descriptor().ok())
        }
    };
    let record = Record {
        stream_id: buffer.stream_id,
        session_id: buffer.session_id,
        lane: 0,
        ..record(region, grant.export)?
    };
    Some((*grant, record, fd))
}

/// A copy of the descriptor of a region the driver created.
fn descriptor(region: &Region) -> Option<OwnedFd> {
    region
        .descriptor()
        .and_then(|fd| fd.try_clone_to_owned().ok())
}

/// The manifest record of a grant's log buffer region; a publication's
/// carries its stream's `allow_unconnected` (quantstratum-docs:
/// karyos/design/ipc-admission.md, Unconnected offers).
fn grant_record(
    region: &Region,
    grant: &Grant,
    stream_id: i32,
    session_id: i32,
    lane: u8,
    allow_unconnected: bool,
) -> Option<Record> {
    let header = region.record();
    Some(Record {
        region: header.region,
        export: grant.export,
        kind: WireKind::LogBuffer,
        layout: u32::try_from(header.layout).ok()?,
        structure_length: u64::try_from(header.structure_length).ok()?,
        generation: header.generation,
        stream_id,
        session_id,
        lane,
        capability: match grant.participant {
            Participant::Exclusive => Capability::ExclusivePublication,
            Participant::Concurrent { slot } => Capability::ConcurrentPublication {
                slot: u64::try_from(slot).ok()?,
            },
            Participant::Subscriber {
                cell,
                role: Role::Required,
            } => Capability::RequiredSubscriber {
                cell: u64::try_from(cell).ok()?,
            },
            Participant::Subscriber {
                cell,
                role: Role::Optional,
            } => Capability::OptionalSubscriber {
                cell: u64::try_from(cell).ok()?,
            },
            Participant::Subscriber {
                cell,
                role: Role::Observer,
            } => Capability::ObserverSubscriber {
                cell: u64::try_from(cell).ok()?,
            },
            // The driver's walker is never granted to a client.
            Participant::Subscriber {
                role: Role::Walker, ..
            } => return None,
            // A journal or conflation grant has no log buffer record.
            Participant::Journal { .. } | Participant::Conflation | Participant::Binding { .. } => {
                return None;
            }
        },
        // Encoded only with a publication's capability.
        allow_unconnected,
    })
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// The admission step of a duty cycle: the count of the work that fit
    /// in `u32`, and [`DriverError::WorkCountOverflow`] if some did not
    /// (the step ran to its end); 0 without IPC.
    pub(crate) fn serve_admission(&mut self) -> (u32, Option<DriverError>) {
        let Some(mut admission) = self.admission.take() else {
            return (0, None);
        };
        let work = admission.serve(self);
        self.admission = Some(admission);
        work
    }

    /// Tool connections admitted and not yet closed; 0 without IPC.
    #[must_use]
    pub fn tools(&self) -> usize {
        self.admission
            .as_ref()
            .map_or(0, |admission| admission.tools.len())
    }

    /// The driver instance id, in IPC mode: the `driver_id` as one value,
    /// `u128::from(high) << 64 | u128::from(low)` of
    /// [`EmbeddedDriver::driver_id`]'s `[high, low]`.
    #[must_use]
    pub fn instance(&self) -> Option<u128> {
        self.admission.as_ref().map(Admission::instance)
    }
}

#[cfg(test)]
mod work_tests {
    use super::Work;
    use crate::error::DriverError;

    /// A work count that does not fit keeps its count and reports its
    /// first overflow; later additions do not replace it.
    #[test]
    fn an_overflowing_work_count_reports_its_first_overflow() {
        let mut work = Work::default();
        work.add(2);
        work.add_items(3);
        assert_eq!(work.count, 5);
        assert!(work.overflow.is_none());
        work.add(u32::MAX);
        work.add(1);
        // The work that fit is still counted.
        assert!(matches!(
            work.done(),
            (
                6,
                Some(DriverError::WorkCountOverflow {
                    count: 5,
                    delta: u32::MAX
                })
            )
        ));
        let mut work = Work::default();
        work.add_items(usize::MAX);
        assert!(matches!(
            work.done(),
            (
                0,
                Some(DriverError::WorkCountOverflow {
                    count: 0,
                    delta: u32::MAX
                })
            )
        ));
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::{check_descriptors, descriptors_needed};
    use crate::embedded::DriverConfig;
    use crate::error::DriverError;
    use crate::net::NetworkConfig;

    /// The defaults: 64 images of four lanes, 64 streams of three mappings
    /// and 16 clients of three descriptors (socket, pidfd, ring `memfd`).
    #[test]
    fn the_default_bounds_need_their_image_lanes_streams_and_clients() {
        let needed = descriptors_needed(&DriverConfig::default(), &NetworkConfig::default());
        assert_eq!(needed, Some(64 * 4 + 64 * 3 + 16 * 3));
    }

    /// The bound is reached, so it is not lowered for exposed image lanes:
    /// a table of one stream slot and one retained mapping, and one image
    /// of four lanes. The local stream takes the slot (two mappings), so
    /// the image cannot be exposed and keeps its four lane regions: six
    /// regions, as the sum counts, plus a client's three descriptors.
    #[test]
    fn the_bound_is_reached_when_images_stay_unexposed() {
        let config = DriverConfig {
            max_streams: 1,
            max_retained_generations: 1,
            max_clients: 1,
            ..DriverConfig::default()
        };
        let mut network = NetworkConfig::default();
        network.agents.sessions.max_images = 1;
        assert_eq!(descriptors_needed(&config, &network), Some(4 + 2 + 3));
    }

    /// A limit below the bounds refuses with both numbers; one at or above
    /// them, or none, passes; an overflowing count is refused as the
    /// largest.
    #[test]
    fn a_limit_below_the_bounds_is_refused_with_both_numbers() {
        assert_eq!(
            check_descriptors(Some(480), (Some(479), Some(4096))),
            Err(DriverError::DescriptorLimit {
                needed: 480,
                limit: 479,
                hard: Some(4096)
            })
        );
        assert_eq!(check_descriptors(Some(480), (Some(480), None)), Ok(()));
        assert_eq!(check_descriptors(Some(480), (None, None)), Ok(()));
        assert_eq!(
            check_descriptors(None, (Some(1024), None)),
            Err(DriverError::DescriptorLimit {
                needed: u64::MAX,
                limit: 1024,
                hard: None
            })
        );
        let config = DriverConfig {
            max_retained_generations: usize::MAX,
            ..DriverConfig::default()
        };
        assert_eq!(descriptors_needed(&config, &NetworkConfig::default()), None);
    }
}
