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
//! five diagnostic regions (driver counters, client counters, error log,
//! loss report, trace mirror), then one `Region` per record, in record
//! order, each with the region's descriptor reopened read-only (owner
//! decision Q7, A1). The
//! connection stays open after this bootstrap, so the tool notices the
//! driver's exit when it closes. A tool holds nothing the driver must
//! reclaim (diagnostic regions are never reused while the driver lives), so
//! closing its socket frees its connection; any message it sends after
//! `ToolHello` closes the connection too.

use std::collections::VecDeque;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;

use karyos_client::link::ClientLink;
use karyos_protocol::admission::{
    Capability, MAX_MESSAGE_LENGTH, Message, Record, RegionKind as WireKind, VERSION,
    hello_version, refusal, tool_hello_version,
};
use karyos_sys::command_ring::RingConsumer;
use karyos_sys::host_clock::age_ns;
use karyos_sys::ipc::{self, PidFd, Recv, Region, Sent};

use crate::counters::Event;
use crate::embedded::{EmbeddedDriver, StreamTerms};
use crate::error::DriverError;
use crate::ledger::{Grant, GrantState, Ledger, Participant};
use karyos_sys::log_buffer::Role;

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
/// counters, the error log, the loss report and the trace mirror.
const TOOL_REGIONS: u64 = 5;
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
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Bounds); a
    /// command beyond it is refused and reserves nothing.
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
    /// The fetch's last message: once sent, the grant is `Exported`.
    last: bool,
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
    pidfd: PidFd,
    link: Arc<ClientLink<T>>,
}

/// What happened to a remote client in one step.
enum Step {
    Keep,
    Leave,
    Retire,
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
    next_region: u64,
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

    /// Takes `count` consecutive ids from a checked counter.
    /// The driver instance and a fresh region id for a stream's log buffer
    /// (`quantstratum-docs: karyos/design/ipc-data-path.md`, Terms in the
    /// types). Region ids are never reused.
    pub(crate) fn next_region(&mut self) -> Result<(u128, u64), DriverError> {
        let region =
            Self::take_ids(&mut self.next_region, 1).ok_or(DriverError::RegionIdsExhausted)?;
        Ok((self.instance, region))
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
        // One datagram per client, then its outbound queue.
        let mut index = 0;
        while let Some(remote) = self.remotes.get_mut(index) {
            let step = match Self::receive(remote, driver, &self.config) {
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
                Step::Leave => {
                    let remote = self.remotes.swap_remove(index);
                    Self::fail_open(driver, &remote);
                    remote.link.mark_closed();
                    work.add(1);
                }
                Step::Retire => {
                    let remote = self.remotes.swap_remove(index);
                    Self::fail_open(driver, &remote);
                    driver.retire_faulty_client(remote.client);
                    self.retiring.push(Retiring {
                        pidfd: remote.pidfd,
                        link: remote.link,
                    });
                    work.add(1);
                }
            }
        }
        self.serve_tools(driver, &mut now, &mut work);
        // Exit proofs.
        let before = self.remotes.len() + self.retiring.len();
        self.remotes.retain(|remote| {
            let exited = remote.pidfd.exited().unwrap_or(false);
            if exited {
                remote.link.mark_closed();
            }
            !exited
        });
        self.retiring.retain(|retiring| {
            let exited = retiring.pidfd.exited().unwrap_or(false);
            if exited {
                retiring.link.mark_closed();
            }
            !exited
        });
        work.add_items(before - self.remotes.len() - self.retiring.len());
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

    /// Builds a tool's bootstrap: `ToolAdmitted` with the five diagnostic
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
                let bytes = buffer.get(..received.len).unwrap_or(&[]);
                match Message::decode(bytes) {
                    // Leave releases the client like its exit proof, so it
                    // is accepted only while nothing was exported and no
                    // fetch is open; otherwise it is a protocol error and
                    // everything sent stays charged until the exit proof.
                    Ok(Message::Leave)
                        if remote.open.is_empty()
                            && driver.ledger(remote.client).is_none_or(Ledger::only_held) =>
                    {
                        Step::Leave
                    }
                    Ok(Message::Fetch { fetch, key }) => {
                        Self::fetch(remote, driver, config, fetch, key)
                    }
                    Ok(Message::Detach { export }) => Self::detach(remote, driver, export),
                    _ => Step::Retire,
                }
            }
            // A descriptor on a message that takes none, a closed socket or
            // a receive error.
            Ok(Recv::Message(_) | Recv::PeerClosed) | Err(_) => Step::Retire,
        }
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
            return Self::queue_fetch(remote, driver, config, fetch, key, &grant, record, fd);
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
            return Self::queue_fetch(remote, driver, config, fetch, key, &grant, record, fd);
        }
        let Some(stream) = driver.streams.iter().find(|s| s.id == grant.stream) else {
            return refuse(remote, refusal::RESOURCES);
        };
        // The mapping of the grant's own incarnation and generation: never
        // another incarnation's buffer; a retired one is refused.
        let buffer = stream.grant_buffer(grant.incarnation, grant.generation);
        let Some(region) =
            buffer.and_then(|buffer| <T as crate::embedded::sealed::Create>::region(buffer))
        else {
            return refuse(remote, refusal::RESOURCES);
        };
        let Some(record) = grant_record(
            region,
            &grant,
            stream.stream_id,
            stream.session_id,
            stream.config.lane.get(),
        ) else {
            return refuse(remote, refusal::RESOURCES);
        };
        let fd = descriptor(region);
        Self::queue_fetch(remote, driver, config, fetch, key, &grant, record, fd)
    }

    /// Queues the `Manifest` and the one `Region` of a grant's fetch, after
    /// the fetch bounds; the grant is spent before anything is queued.
    #[allow(
        clippy::too_many_arguments,
        reason = "one fetch's whole context; a struct would only rename it"
    )]
    fn queue_fetch(
        remote: &mut Remote<T>,
        driver: &mut EmbeddedDriver<T>,
        config: &IpcConfig,
        fetch: u64,
        key: u64,
        grant: &Grant,
        record: Record,
        fd: Option<OwnedFd>,
    ) -> Step {
        let bound = config.max_outbound_per_client;
        let refuse = |remote: &mut Remote<T>, code: u64| {
            Self::queue(remote, &Message::Refused { fetch, code }, bound)
        };
        // One region per grant: one lane, or one journal. The byte bound
        // counts whole regions, header included.
        let bytes = u64::try_from(karyos_sys::ipc::HEADER_STRIDE)
            .ok()
            .and_then(|header| record.structure_length.checked_add(header));
        if config.max_regions_per_fetch < 1
            || bytes.is_none_or(|bytes| bytes > config.max_fetch_bytes)
        {
            return refuse(remote, refusal::LIMIT);
        }
        let Some(fd) = fd else {
            return refuse(remote, refusal::RESOURCES);
        };
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
        let (Some(manifest), Some(region_message)) = (
            encode(&Message::Manifest {
                fetch,
                key,
                registration: grant.registration,
                stream_registration,
                incarnation,
                records: vec![record],
            }),
            encode(&Message::Region { fetch, index: 0 }),
        ) else {
            return refuse(remote, refusal::RESOURCES);
        };
        if remote.outbound.len() + 2 > bound {
            return Step::Retire;
        }
        // Effect: the grant is spent before anything is queued.
        if let Some(ledger) = driver.ledger_mut(remote.client) {
            ledger.set_state(grant.export, GrantState::Exporting);
        }
        let mark = |descriptor: bool, last: bool| {
            Some(Mark {
                fetch,
                export: grant.export,
                descriptor,
                last,
            })
        };
        remote.outbound.push_back(Outgoing {
            bytes: manifest,
            fd: None,
            mark: mark(false, false),
        });
        remote.outbound.push_back(Outgoing {
            bytes: region_message,
            fd: Some(fd),
            mark: mark(true, true),
        });
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
            if mark.last {
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
        while let Some(next) = remote.outbound.front() {
            match ipc::send(
                remote.socket.as_fd(),
                &next.bytes,
                next.fd.as_ref().map(AsFd::as_fd),
            ) {
                Ok(Sent::Sent) => {
                    if let Some(mark) = remote.outbound.pop_front().and_then(|done| done.mark) {
                        if mark.last {
                            remote.open.retain(|open| *open != mark.fetch);
                        }
                        sent.push(mark);
                    }
                }
                Ok(Sent::WouldBlock) => break,
                Err(_) => return (Step::Retire, sent),
            }
        }
        (Step::Keep, sent)
    }
}

/// A copy of the descriptor of a region the driver created.
fn descriptor(region: &Region) -> Option<OwnedFd> {
    region
        .descriptor()
        .and_then(|fd| fd.try_clone_to_owned().ok())
}

/// The manifest record of a grant's log buffer region.
fn grant_record(
    region: &Region,
    grant: &Grant,
    stream_id: i32,
    session_id: i32,
    lane: u8,
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
            Participant::Journal { .. } | Participant::Conflation => return None,
        },
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
