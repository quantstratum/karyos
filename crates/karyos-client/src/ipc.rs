// SPDX-License-Identifier: Apache-2.0

//! A client in another process than its driver (Linux;
//! `quantstratum-docs: karyos/design/ipc-admission.md`, `quantstratum-docs: karyos/design/ipc-admission-server.md`).
//!
//! [`attach`] connects to the driver's admission socket after checking its
//! directory, socket and peer uid, sends `Hello` with a pidfd of this
//! process, and receives `Admitted` and one `Region` per record. It maps
//! each region only after the descriptor checks and the header comparison
//! of [`Region::attach`], and builds the client conductor over the
//! attached command ring and broadcast buffer. The driver counters are
//! mapped read-only; the client counters region is mapped writable, and
//! each counter the client is allocated keeps the session, so `Leave` is
//! sent only after the last one is gone and the region unmapped.
//!
//! Its log buffer grants (`quantstratum-docs: karyos/design/ipc-data-path.md`,
//! The client) complete as [`Outcome::Fetchable`](crate::Outcome::Fetchable);
//! [`RemoteClient::take_publication`], [`RemoteClient::take_concurrent_publication`]
//! and [`RemoteClient::take_subscription`] fetch one, check its manifest
//! record and region against the request, adopt it and return a handle
//! that owns its own mapping. Dropping that handle unmaps the mapping and
//! then sends the grant's `Detach`.
//!
//! The process keeps the one-process contract of the first profile: it
//! does not fork while it holds the socket, a received descriptor or a
//! mapping. The socket, the fetch counter and the set of live exports form
//! a session shared by the [`RemoteClient`] and every handle it took.
//! Closing the client closes the conductor and unmaps the CnC regions;
//! when the last handle is gone too, and every export was detached, the
//! session sends `Leave`, the proof that no access can follow. A failed
//! attach unmaps what it had received and sends `Leave`.
//!
//! Each taken handle gets a remote generation link
//! (`quantstratum-docs: karyos/design/ipc-data-path.md`, Generations across
//! processes). [`RemoteClient::poll`], the control path, serves the driver's
//! cutover events: on `SuccessorReady` it fetches the successor grant, checks
//! it as any fetch, prepares its adoption and offers it to the handle's link;
//! on `Fenced`, on a `PublicationClosed` of the handle's stream and when the
//! driver is lost it closes the link. It also drops what a handle left in its
//! link when it moved, unmapping the predecessor and sending its `Detach`.
//!
//! A taken subscription reports its overruns as an in-process one does
//! ([`crate::loss`]): through the client conductor's loss report queue,
//! sent as `ReportLoss` by [`RemoteClient::poll`]. Its publication identity
//! is the instance of `Admitted`, which is the driver's `driver_id`
//! (`[high, low]` is `instance >> 64` and the low 64 bits), with the stream
//! registration and incarnation of the grant's `Manifest` (coordinator
//! decision, ACS 13555).

use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use karyos_protocol::admission::{
    Capability, MAX_MESSAGE_LENGTH, Message, Record, RegionKind as WireKind, VERSION, refusal,
};
use karyos_protocol::cnc::{Event, StreamKey, SubscriberRole};
use karyos_protocol::trace_hook::PublicationIdentity;
use karyos_sys::broadcast::BroadcastReceiver;
use karyos_sys::command_ring::RingProducer;
use karyos_sys::counters::{CellRead, ClientCells, CountersReader};
use karyos_sys::error::SysError;
use karyos_sys::ipc::{
    self, PidFd, ReadOnlyRegion, Recv, Region, RegionKind, RegionRecord, SealProfile, Sent,
};
use karyos_sys::log_buffer::{
    ConcurrentPublication, LogBuffer, PreparedConcurrentPublication, PreparedPublication,
    PreparedSubscription, Publication, Role, Subscription,
};
use karyos_sys::term_bytes::SharedTerms;

use crate::concurrent::ClientConcurrentPublication;
use crate::conductor::{
    ClientConductor, Completion, ConductorError, ConductorPoll, Fetchable, Request,
};
use crate::error::ClientError;
use crate::generation::{GenerationLink, Successor};
use crate::link::{ClientLink, Export, Owner};
use crate::loss::{LossReporter, LossReports};
use crate::publication::ClientPublication;
use crate::subscription::ClientSubscription;

/// Why an attach failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttachError {
    /// The driver refused the client with this code
    /// (`karyos_protocol::admission::refusal`).
    #[error("the driver refused the client (code {code})")]
    Refused {
        /// The refusal code.
        code: u64,
    },
    /// The driver runs another protocol version: it refused this one, or
    /// admitted the client at another.
    #[error("the driver does not run protocol version {VERSION}")]
    IncompatibleVersion {
        /// The version the driver announced, when it admitted the client.
        driver: Option<u64>,
    },
    /// The driver sent a message out of order, malformed, or with a
    /// missing or extra descriptor.
    #[error("admission protocol error")]
    Protocol,
    /// The driver did not answer within the timeout.
    #[error("the driver did not answer in time")]
    Timeout,
    /// A system call or a region check failed.
    #[error(transparent)]
    Sys(#[from] SysError),
}

/// A client admitted by a driver in another process.
#[derive(Debug)]
pub struct RemoteClient {
    instance: u128,
    client: u64,
    conductor: Option<ClientConductor>,
    counters: Option<CountersReader>,
    /// The conductor's loss report queue, given to the subscriptions taken.
    losses: Arc<LossReports>,
    /// Shared with every handle taken; dropped last, after the CnC
    /// mappings above.
    session: Option<Arc<Session>>,
}

/// The socket, the fetch counter and the live exports of one client
/// (`quantstratum-docs: karyos/design/ipc-data-path.md`, The client,
/// Session). The last reference sends `Leave` if every export was
/// detached; its control sends block at most the attach timeout and are
/// made only from `Drop`, `close` and the `take_*` calls.
#[derive(Debug)]
struct Session {
    instance: u128,
    socket: OwnedFd,
    /// Held for a whole Fetch, Manifest and Region exchange, aborts
    /// included: replies carry no thread, so one fetch at a time reads the
    /// socket.
    fetching: Mutex<()>,
    state: Mutex<SessionState>,
    /// The generation links of the handles taken, for the cutover events.
    links: Mutex<Vec<RemoteLink>>,
}

/// A taken handle's link, with what its successor fetches are checked
/// against.
#[derive(Debug)]
struct RemoteLink {
    /// The registration its grants answer, the same across generations.
    registration: u64,
    /// The stream registration and incarnation of its first grant; a
    /// successor grant must carry the same.
    publication: (u64, u64),
    request: Request,
    /// The generation of the latest mapping offered or taken.
    generation: u64,
    link: Weak<GenerationLink<SharedTerms>>,
}

#[derive(Debug)]
struct SessionState {
    /// The next fetch id; 0 was the bootstrap.
    next_fetch: u64,
    /// Exports whose descriptor arrived and which were not detached.
    live: Vec<u64>,
    /// A send failed: nothing more is sent, and the driver releases what
    /// is charged at this process's exit proof.
    broken: bool,
}

impl Session {
    fn state(&self) -> std::sync::MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn links(&self) -> std::sync::MutexGuard<'_, Vec<RemoteLink>> {
        self.links.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Control path: drops what moved handles left behind, then serves the
    /// cutover `events` in order; with `driver_lost`, closes every link.
    fn serve_cutovers(self: &Arc<Self>, events: Vec<Event>, driver_lost: bool) {
        let live: Vec<Arc<GenerationLink<SharedTerms>>> = {
            let mut links = self.links();
            links.retain(|entry| entry.link.strong_count() > 0);
            links
                .iter()
                .filter_map(|entry| entry.link.upgrade())
                .collect()
        };
        // The handle's mapping is unmapped by this drop, then its `Detach`
        // is sent: the predecessor of a move, or a failed successor.
        for link in &live {
            drop(link.take_retired());
        }
        for event in events {
            match event {
                Event::SuccessorReady {
                    registration,
                    key,
                    base,
                    generation,
                    ..
                } => self.offer_successor(registration, key, base, generation),
                Event::Fenced { registration, .. } => {
                    self.close_where(|entry| entry.registration == registration);
                }
                Event::PublicationClosed { stream, .. } => {
                    self.close_where(|entry| entry.request.stream() == stream);
                }
                _ => {}
            }
        }
        if driver_lost {
            self.close_where(|_| true);
        }
    }

    /// Closes the links whose entry matches; an offered successor is
    /// dropped here, on the control path.
    fn close_where(&self, matches: impl Fn(&RemoteLink) -> bool) {
        let closing: Vec<Arc<GenerationLink<SharedTerms>>> = self
            .links()
            .iter()
            .filter(|entry| matches(entry))
            .filter_map(|entry| entry.link.upgrade())
            .collect();
        for link in closing {
            drop(link.close());
        }
    }

    /// Fetches the successor grant `key` of `registration`, checks it
    /// against the handle's request and the event's `generation`, prepares
    /// its adoption and offers it at `base`. Any failure leaves the handle
    /// to the driver's fence; a successor the link does not take is dropped
    /// (unmapped, then detached).
    fn offer_successor(self: &Arc<Self>, registration: u64, key: u64, base: u64, generation: u64) {
        let target = self
            .links()
            .iter()
            .find(|entry| entry.registration == registration && entry.generation < generation)
            .and_then(|entry| {
                entry
                    .link
                    .upgrade()
                    .map(|link| (entry.request, entry.publication, link))
            });
        let Some((request, publication, link)) = target else {
            return;
        };
        let fetchable = Fetchable {
            key,
            registration,
            request,
        };
        let Ok(fetched) = fetch(self, &fetchable) else {
            return;
        };
        let export = fetched.record.export;
        let prepared = check(&fetched, &request)
            .and_then(|()| {
                (fetched.record.generation == generation
                    && (fetched.stream_registration, fetched.incarnation) == publication)
                    .then_some(())
                    .ok_or(AttachError::Protocol)
            })
            .and_then(|()| prepare_successor(&fetched, &request, export, self));
        drop(fetched);
        match prepared {
            Ok(successor) => {
                if link.offer(base, successor).is_ok()
                    && let Some(entry) = self
                        .links()
                        .iter_mut()
                        .find(|entry| entry.registration == registration)
                {
                    entry.generation = generation;
                }
            }
            // Unmapped first: the Detach is the proof.
            Err(_) => self.detach(export),
        }
    }

    /// Sends `Detach { export }` once its mapping is gone, and forgets the
    /// export.
    fn detach(&self, export: u64) {
        let mut state = self.state();
        if state.broken {
            return;
        }
        if send(&self.socket, &Message::Detach { export }, None).is_err() {
            state.broken = true;
            return;
        }
        state.live.retain(|live| *live != export);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        // Leave only once nothing is left mapped or charged: the driver's
        // own rule. Otherwise the exit proof releases the rest.
        if !state.broken && state.live.is_empty() {
            let _ = send(&self.socket, &Message::Leave, None);
        }
    }
}

/// The export of a handle taken from a fetch: dropped after the handle's
/// mapping, it sends the grant's `Detach`.
#[derive(Debug)]
struct Detach {
    session: Arc<Session>,
    export: u64,
}

impl Drop for Detach {
    fn drop(&mut self) {
        self.session.detach(self.export);
    }
}

/// A fetched log buffer: its record, the attached buffer, and the stream
/// registration and incarnation its manifest named.
struct Fetched {
    record: Record,
    buffer: Arc<LogBuffer<SharedTerms>>,
    stream_registration: u64,
    incarnation: u64,
}

/// One received message, with its descriptor.
pub(crate) fn receive(socket: &OwnedFd) -> Result<(Message, Option<OwnedFd>), AttachError> {
    let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
    match ipc::recv(socket.as_fd(), &mut buffer)? {
        Recv::Message(received) => {
            let bytes = buffer.get(..received.len).unwrap_or(&[]);
            let message = Message::decode(bytes).map_err(|_| AttachError::Protocol)?;
            Ok((message, received.fd))
        }
        Recv::WouldBlock => Err(AttachError::Timeout),
        Recv::PeerClosed => Err(AttachError::Protocol),
    }
}

pub(crate) fn send(
    socket: &OwnedFd,
    message: &Message,
    fd: Option<&OwnedFd>,
) -> Result<(), AttachError> {
    let mut out = [0u8; MAX_MESSAGE_LENGTH];
    let length = message
        .encode(&mut out)
        .map_err(|_| AttachError::Protocol)?;
    let bytes = out.get(..length).ok_or(AttachError::Protocol)?;
    match ipc::send(socket.as_fd(), bytes, fd.map(AsFd::as_fd))? {
        Sent::Sent => Ok(()),
        Sent::WouldBlock => Err(AttachError::Timeout),
    }
}

/// The region header a record describes.
fn expected(instance: u128, record: &Record) -> Result<RegionRecord, AttachError> {
    let kind = match record.kind {
        WireKind::CommandRing => RegionKind::CommandRing,
        WireKind::Broadcast => RegionKind::Broadcast,
        WireKind::Counters => RegionKind::Counters,
        WireKind::ClientCounters => RegionKind::ClientCounters,
        // Log buffers come with a fetch; the error log and the loss report
        // are granted to tools only.
        WireKind::LogBuffer | WireKind::ErrorLog | WireKind::LossReport => {
            return Err(AttachError::Protocol);
        }
    };
    Ok(RegionRecord {
        instance,
        region: record.region,
        kind,
        generation: record.generation,
        layout: u64::from(record.layout),
        structure_length: usize::try_from(record.structure_length)
            .map_err(|_| AttachError::Protocol)?,
    })
}

/// The CnC regions of a bootstrap, mapped and checked. The driver counters
/// are mapped read-only: only the driver writes them (owner decision Q7,
/// A2). The client counters are mapped writable: the client writes its own
/// cells.
#[derive(Default)]
struct Staged {
    ring: Option<Region>,
    broadcast: Option<Region>,
    counters: Option<ReadOnlyRegion>,
    client_counters: Option<Region>,
}

/// Receives the bootstrap after `Hello`: `Admitted`, then one `Region`
/// per record, each mapped as soon as it arrives.
fn bootstrap(socket: &OwnedFd) -> Result<(u128, u64, Staged), AttachError> {
    let (instance, client, records) = match receive(socket)? {
        (
            Message::Admitted {
                instance,
                version,
                client,
                records,
            },
            None,
        ) => {
            if version != VERSION {
                return Err(AttachError::IncompatibleVersion {
                    driver: Some(version),
                });
            }
            (instance, client, records)
        }
        (
            Message::Refused {
                code: refusal::INCOMPATIBLE_VERSION,
                ..
            },
            None,
        ) => return Err(AttachError::IncompatibleVersion { driver: None }),
        (Message::Refused { code, .. }, None) => return Err(AttachError::Refused { code }),
        _ => return Err(AttachError::Protocol),
    };
    let mut staged = Staged::default();
    for (index, record) in (0u64..).zip(&records) {
        let (
            Message::Region {
                fetch: 0,
                index: got,
            },
            Some(fd),
        ) = receive(socket)?
        else {
            return Err(AttachError::Protocol);
        };
        if got != index {
            return Err(AttachError::Protocol);
        }
        let expected = expected(instance, record)?;
        let duplicate = match record.kind {
            WireKind::CommandRing => staged.ring.replace(Region::attach(fd, expected)?).is_some(),
            WireKind::Broadcast => staged
                .broadcast
                .replace(Region::attach(fd, expected)?)
                .is_some(),
            WireKind::Counters => staged
                .counters
                .replace(ReadOnlyRegion::attach(
                    fd,
                    expected,
                    SealProfile::DriverOnly,
                )?)
                .is_some(),
            WireKind::ClientCounters => staged
                .client_counters
                .replace(Region::attach(fd, expected)?)
                .is_some(),
            WireKind::LogBuffer | WireKind::ErrorLog | WireKind::LossReport => {
                return Err(AttachError::Protocol);
            }
        };
        if duplicate {
            return Err(AttachError::Protocol);
        }
    }
    Ok((instance, client, staged))
}

/// Attaches to the driver whose admission socket is in `dir`, waiting at
/// most `timeout` for each of its messages. `max_pending` bounds the
/// conductor's pending requests, as for an in-process client.
///
/// # Errors
///
/// Returns [`AttachError`]. Every region already mapped is unmapped and
/// every received descriptor closed; if the driver had admitted the client,
/// `Leave` is sent so that it releases the client at once.
pub fn attach(
    dir: &Path,
    timeout: Duration,
    max_pending: usize,
) -> Result<RemoteClient, AttachError> {
    let socket = ipc::connect(dir, timeout)?;
    let pidfd = PidFd::of_self()?;
    // `PidFd` keeps its descriptor private; pass a duplicate.
    let pidfd_fd = pidfd.as_fd().try_clone_to_owned().map_err(|error| {
        AttachError::Sys(SysError::Os {
            operation: "dup(pidfd)",
            errno: error.raw_os_error().unwrap_or(0),
        })
    })?;
    send(
        &socket,
        &Message::Hello { version: VERSION },
        Some(&pidfd_fd),
    )?;
    drop(pidfd_fd);
    let built = bootstrap(&socket).and_then(|(instance, client, staged)| {
        let (Some(ring), Some(broadcast), Some(counters), Some(client_counters)) = (
            staged.ring,
            staged.broadcast,
            staged.counters,
            staged.client_counters,
        ) else {
            return Err(AttachError::Protocol);
        };
        let producer = RingProducer::attach(ring)?;
        let receiver = BroadcastReceiver::attach(broadcast)?;
        let counters = CountersReader::attach_read_only(counters)?;
        let cells = ClientCells::attach(client_counters)?;
        let owner = Owner {
            driver: instance as u64,
            client,
        };
        let conductor = ClientConductor::new(
            owner,
            producer,
            receiver,
            Arc::new(ClientLink::new()),
            max_pending,
        )
        .with_counters(cells);
        Ok((instance, client, conductor, counters))
    });
    match built {
        Ok((instance, client, mut conductor, counters)) => {
            let losses = conductor.loss_report_queue();
            conductor.set_remote();
            let session = Arc::new(Session {
                instance,
                socket,
                fetching: Mutex::new(()),
                state: Mutex::new(SessionState {
                    next_fetch: 1,
                    live: Vec::new(),
                    broken: false,
                }),
                links: Mutex::new(Vec::new()),
            });
            conductor.set_session(Arc::clone(&session) as Arc<dyn core::any::Any + Send + Sync>);
            Ok(RemoteClient {
                instance,
                client,
                conductor: Some(conductor),
                counters: Some(counters),
                losses,
                session: Some(session),
            })
        }
        Err(error) => {
            // Everything staged is unmapped by now (dropped); tell the
            // driver, which may have admitted this client.
            let _ = send(&socket, &Message::Leave, None);
            Err(error)
        }
    }
}

impl RemoteClient {
    /// The admission socket while it is open: the transport of fetches.
    /// Test hook for raw admission messages.
    #[doc(hidden)]
    #[must_use]
    pub fn admission_socket(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.session.as_ref().map(|session| session.socket.as_fd())
    }

    /// The driver instance id.
    #[must_use]
    pub fn instance(&self) -> u128 {
        self.instance
    }

    /// The client id the driver assigned.
    #[must_use]
    pub fn client(&self) -> u64 {
        self.client
    }

    /// Loss reports of the taken subscriptions queued and not yet sent, as
    /// [`ClientConductor::loss_reports_queued`].
    #[must_use]
    pub fn loss_reports_queued(&self) -> usize {
        self.losses.queued()
    }

    /// Loss reports dropped because the queue was full, as
    /// [`ClientConductor::loss_reports_dropped`].
    #[must_use]
    pub fn loss_reports_dropped(&self) -> u64 {
        self.losses.dropped()
    }

    /// Requests a publication on `stream` (the client conductor's
    /// `add_publication`); returns the request sequence.
    ///
    /// # Errors
    ///
    /// As [`ClientConductor::add_publication`].
    pub fn add_publication(
        &mut self,
        stream: StreamKey,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        self.conductor_mut()?
            .add_publication(stream, allow_unconnected)
    }

    /// Requests a concurrent publication handle on `stream`.
    ///
    /// # Errors
    ///
    /// As [`ClientConductor::add_concurrent_publication`].
    pub fn add_concurrent_publication(
        &mut self,
        stream: StreamKey,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        self.conductor_mut()?
            .add_concurrent_publication(stream, allow_unconnected)
    }

    /// Requests a subscription to `stream` with `role`.
    ///
    /// # Errors
    ///
    /// As [`ClientConductor::add_subscription`].
    pub fn add_subscription(
        &mut self,
        stream: StreamKey,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        self.conductor_mut()?.add_subscription(stream, role)
    }

    /// Requests a client counter, as [`ClientConductor::allocate_counter`];
    /// it completes as [`Outcome::Counter`](crate::Outcome::Counter), whose
    /// handle writes the client counters region this client mapped.
    ///
    /// # Errors
    ///
    /// As [`ClientConductor::allocate_counter`].
    pub fn allocate_counter(
        &mut self,
        type_id: u64,
        label: &str,
        stream: u64,
        participant: u64,
    ) -> Result<u64, ConductorError> {
        self.conductor_mut()?
            .allocate_counter(type_id, label, stream, participant)
    }

    /// Reports completed requests to `on`, as [`ClientConductor::poll`],
    /// then serves the cutovers of the handles taken: it fetches and
    /// prepares their successors, closes the fenced ones and drops what
    /// moved handles left behind (the control path; it may block on the
    /// admission socket for the attach timeout per message). A moved
    /// handle's predecessor stays charged in the driver's ledger until this
    /// poll detaches it: a client at its export bound whose predecessor is
    /// still charged gets no successor at the next cutover and is fenced
    /// at once, so poll between cutovers.
    pub fn poll<F>(&mut self, limit: usize, on: F) -> ConductorPoll
    where
        F: FnMut(Completion),
    {
        let Some(conductor) = self.conductor.as_mut() else {
            return ConductorPoll::default();
        };
        let report = conductor.poll(limit, on);
        let events = conductor.take_cutover_events();
        let driver_lost = conductor.driver_lost();
        if let Some(session) = &self.session {
            session.serve_cutovers(events, driver_lost);
        }
        report
    }

    /// Takes the driver events received by earlier polls, as
    /// [`ClientConductor::take_events`].
    pub fn take_events(&mut self) -> Vec<karyos_protocol::cnc::Event> {
        self.conductor
            .as_mut()
            .map(|conductor| conductor.take_events().collect())
            .unwrap_or_default()
    }

    /// Requests submitted and not yet reported.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.conductor.as_ref().map_or(0, ClientConductor::pending)
    }

    /// Cells of the driver's counters region.
    #[must_use]
    pub fn counter_capacity(&self) -> usize {
        self.counters.as_ref().map_or(0, CountersReader::capacity)
    }

    /// Reads counter cell `index` of the driver's counters region.
    #[must_use]
    pub fn read_counter(&self, index: usize) -> CellRead {
        self.counters
            .as_ref()
            .map_or(CellRead::Free, |counters| counters.read(index))
    }

    /// Takes the exclusive publication of a [`Fetchable`] grant: fetches
    /// it, checks it against the request and adopts it. Blocks at most the
    /// attach timeout per message.
    ///
    /// # Errors
    ///
    /// Returns [`AttachError::Refused`] when the driver refuses the fetch,
    /// [`AttachError::Protocol`] for a grant of another kind than
    /// `fetchable` asked for or a manifest or region that does not match
    /// it, [`AttachError::Timeout`], and [`AttachError::Sys`]. A grant
    /// whose descriptor arrived is unmapped and detached.
    pub fn take_publication(
        &self,
        fetchable: &Fetchable,
    ) -> Result<ClientPublication<SharedTerms>, AttachError> {
        let Request::Publication {
            allow_unconnected, ..
        } = fetchable.request
        else {
            return Err(AttachError::Protocol);
        };
        self.take(fetchable, |fetched, export| {
            let inner = prepare_publication(fetched, export)?
                .activate()
                .map_err(|refused| AttachError::Sys(refused.error))?;
            Ok(ClientPublication::new(inner, allow_unconnected))
        })
    }

    /// Takes a concurrent publication handle of a [`Fetchable`] grant, as
    /// [`RemoteClient::take_publication`].
    ///
    /// # Errors
    ///
    /// As [`RemoteClient::take_publication`].
    pub fn take_concurrent_publication(
        &self,
        fetchable: &Fetchable,
    ) -> Result<ClientConcurrentPublication<SharedTerms>, AttachError> {
        let Request::ConcurrentPublication {
            allow_unconnected, ..
        } = fetchable.request
        else {
            return Err(AttachError::Protocol);
        };
        self.take(fetchable, |fetched, export| {
            let inner = prepare_concurrent(fetched, export)?
                .activate()
                .map_err(|refused| AttachError::Sys(refused.error))?;
            Ok(ClientConcurrentPublication::new(inner, allow_unconnected))
        })
    }

    /// Takes the subscription of a [`Fetchable`] grant, as
    /// [`RemoteClient::take_publication`].
    ///
    /// # Errors
    ///
    /// As [`RemoteClient::take_publication`].
    pub fn take_subscription(
        &self,
        fetchable: &Fetchable,
    ) -> Result<ClientSubscription<SharedTerms>, AttachError> {
        let Request::Subscription { role, .. } = fetchable.request else {
            return Err(AttachError::Protocol);
        };
        self.take(fetchable, |fetched, export| {
            let inner = prepare_subscription(fetched, role, export)?
                .activate()
                .map_err(|refused| AttachError::Sys(refused.error))?;
            // Its overruns are reported as an in-process subscription's:
            // the identity of the grant, the subscription's registration
            // and the conductor's queue.
            Ok(
                ClientSubscription::new(inner).with_loss_reports(LossReporter {
                    publication: PublicationIdentity {
                        driver: [(self.instance >> 64) as u64, self.instance as u64],
                        registration: fetched.stream_registration,
                        stream_id: fetched.record.stream_id,
                        session_id: fetched.record.session_id,
                        incarnation: fetched.incarnation,
                    },
                    registration: fetchable.registration,
                    reports: Arc::clone(&self.losses),
                }),
            )
        })
    }

    /// Fetches `fetchable`'s grant, checks the record and the buffer against
    /// the request, and builds the handle with `adopt`, with its export and
    /// a remote generation link registered for the cutover events. On any
    /// failure after the descriptor arrived, the mapping is dropped and the
    /// export detached.
    fn take<H>(
        &self,
        fetchable: &Fetchable,
        adopt: impl FnOnce(&Fetched, u64) -> Result<H, AttachError>,
    ) -> Result<H, AttachError>
    where
        H: WithExport,
    {
        let session = self.session.as_ref().ok_or(AttachError::Protocol)?;
        let fetched = fetch(session, fetchable)?;
        let export = fetched.record.export;
        let generation = fetched.record.generation;
        let publication = (fetched.stream_registration, fetched.incarnation);
        let built = check(&fetched, &fetchable.request).and_then(|()| adopt(&fetched, export));
        match built {
            Ok(handle) => {
                drop(fetched);
                let link = GenerationLink::new_remote();
                // The first mapping starts at position 0. A refusal drops the
                // handle, which unmaps and detaches.
                let handle = handle
                    .with_export(Export::new(Detach {
                        session: Arc::clone(session),
                        export,
                    }))
                    .with_link(Arc::clone(&link))
                    .map_err(|_| AttachError::Protocol)?;
                session.links().push(RemoteLink {
                    registration: fetchable.registration,
                    publication,
                    request: fetchable.request,
                    generation,
                    link: Arc::downgrade(&link),
                });
                Ok(handle)
            }
            Err(error) => {
                // Unmapped first: the Detach is the proof.
                drop(fetched);
                session.detach(export);
                Err(error)
            }
        }
    }

    fn conductor_mut(&mut self) -> Result<&mut ClientConductor, ConductorError> {
        self.conductor.as_mut().ok_or(ConductorError::Closed)
    }

    /// Closes the conductor, unmaps every region and sends `Leave`. Same as
    /// dropping the client.
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for RemoteClient {
    fn drop(&mut self) {
        // The CnC mappings go first; the session sends Leave once its last
        // handle is gone too.
        drop(self.conductor.take());
        drop(self.counters.take());
        drop(self.session.take());
    }
}

/// A handle that keeps the export of the grant it was adopted from and
/// its remote generation link.
trait WithExport: Sized {
    fn with_export(self, export: Export) -> Self;
    fn with_link(self, link: Arc<GenerationLink<SharedTerms>>) -> Result<Self, ClientError>;
}

impl WithExport for ClientPublication<SharedTerms> {
    fn with_export(self, export: Export) -> Self {
        ClientPublication::with_export(self, export)
    }

    fn with_link(self, link: Arc<GenerationLink<SharedTerms>>) -> Result<Self, ClientError> {
        self.with_generation(link, 0)
    }
}

impl WithExport for ClientConcurrentPublication<SharedTerms> {
    fn with_export(self, export: Export) -> Self {
        ClientConcurrentPublication::with_export(self, export)
    }

    fn with_link(self, link: Arc<GenerationLink<SharedTerms>>) -> Result<Self, ClientError> {
        self.with_generation(link, 0)
    }
}

impl WithExport for ClientSubscription<SharedTerms> {
    fn with_export(self, export: Export) -> Self {
        ClientSubscription::with_export(self, export)
    }

    fn with_link(self, link: Arc<GenerationLink<SharedTerms>>) -> Result<Self, ClientError> {
        self.with_generation(link, 0)
    }
}

/// Prepares the exclusive publication of a fetched grant.
fn prepare_publication(
    fetched: &Fetched,
    export: u64,
) -> Result<PreparedPublication<Arc<LogBuffer<SharedTerms>>>, AttachError> {
    if fetched.record.capability != Capability::ExclusivePublication {
        return Err(AttachError::Protocol);
    }
    Ok(Publication::prepare_adopt(
        Arc::clone(&fetched.buffer),
        export,
    )?)
}

/// Prepares the publisher slot of a fetched grant.
fn prepare_concurrent(
    fetched: &Fetched,
    export: u64,
) -> Result<PreparedConcurrentPublication<Arc<LogBuffer<SharedTerms>>>, AttachError> {
    let Capability::ConcurrentPublication { slot } = fetched.record.capability else {
        return Err(AttachError::Protocol);
    };
    let slot = usize::try_from(slot).map_err(|_| AttachError::Protocol)?;
    Ok(ConcurrentPublication::prepare_adopt(
        Arc::clone(&fetched.buffer),
        slot,
        export,
    )?)
}

/// Prepares the subscriber cell of a fetched grant, which must have the
/// requested `role`.
fn prepare_subscription(
    fetched: &Fetched,
    role: SubscriberRole,
    export: u64,
) -> Result<PreparedSubscription<Arc<LogBuffer<SharedTerms>>>, AttachError> {
    let (cell, granted) = match fetched.record.capability {
        Capability::RequiredSubscriber { cell } => (cell, SubscriberRole::Required),
        Capability::OptionalSubscriber { cell } => (cell, SubscriberRole::Optional),
        Capability::ObserverSubscriber { cell } => (cell, SubscriberRole::Observer),
        _ => return Err(AttachError::Protocol),
    };
    if granted != role {
        return Err(AttachError::Protocol);
    }
    let cell = usize::try_from(cell).map_err(|_| AttachError::Protocol)?;
    Ok(Subscription::prepare_adopt(
        Arc::clone(&fetched.buffer),
        cell,
        Role::from(role),
        export,
    )?)
}

/// Prepares a fetched successor grant of the kind `request` asked for,
/// with its export and, for a subscription, its copy buffer (control
/// path: everything that allocates happens here).
fn prepare_successor(
    fetched: &Fetched,
    request: &Request,
    export: u64,
    session: &Arc<Session>,
) -> Result<Successor<SharedTerms>, AttachError> {
    let detach = || {
        Export::new(Detach {
            session: Arc::clone(session),
            export,
        })
    };
    Ok(match *request {
        Request::Publication { .. } => Successor::PreparedPublication {
            prepared: prepare_publication(fetched, export)?,
            export: detach(),
        },
        Request::ConcurrentPublication { .. } => Successor::PreparedConcurrent {
            prepared: prepare_concurrent(fetched, export)?,
            export: detach(),
        },
        Request::Subscription { role, .. } => {
            let prepared = prepare_subscription(fetched, role, export)?;
            let length = usize::try_from(fetched.buffer.max_message_length())
                .map_err(|_| AttachError::Protocol)?;
            Successor::PreparedSubscription {
                prepared,
                scratch: vec![0u8; length].into_boxed_slice(),
                export: detach(),
            }
        }
    })
}

/// Sends `Fetch` for `fetchable` and receives its `Manifest` and its one
/// `Region`: the manifest must answer this fetch, with its key and the
/// registration of the `Ready` response, and carry one log buffer record;
/// the region is attached against that record and the session's full
/// instance.
fn fetch(session: &Session, fetchable: &Fetchable) -> Result<Fetched, AttachError> {
    let _exchange = session
        .fetching
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let fetch = {
        let mut state = session.state();
        if state.broken {
            return Err(AttachError::Protocol);
        }
        let fetch = state.next_fetch;
        state.next_fetch = fetch.checked_add(1).ok_or(AttachError::Protocol)?;
        fetch
    };
    send(
        &session.socket,
        &Message::Fetch {
            fetch,
            key: fetchable.key,
        },
        None,
    )?;
    let (record, stream_registration, incarnation) = match receive(&session.socket)? {
        (Message::Refused { fetch: got, code }, None) if got == fetch => {
            return Err(AttachError::Refused { code });
        }
        (
            Message::Manifest {
                fetch: got,
                key,
                registration,
                stream_registration,
                incarnation,
                records,
            },
            None,
        ) if got == fetch => {
            let expected = key == fetchable.key && registration == fetchable.registration;
            match records[..] {
                [record] if expected && record.kind == WireKind::LogBuffer => {
                    (record, stream_registration, incarnation)
                }
                // Not the grant requested: the fetch is aborted, but its
                // regions still follow; each descriptor is closed and its
                // export detached, so nothing stays charged.
                _ => {
                    abort(session, fetch, &records);
                    return Err(AttachError::Protocol);
                }
            }
        }
        // A message for no fetch of ours: the session is out of step.
        _ => {
            session.state().broken = true;
            return Err(AttachError::Protocol);
        }
    };
    let received = receive(&session.socket)?;
    let (
        Message::Region {
            fetch: got,
            index: 0,
        },
        Some(fd),
    ) = received
    else {
        session.state().broken = true;
        return Err(AttachError::Protocol);
    };
    if got != fetch {
        session.state().broken = true;
        return Err(AttachError::Protocol);
    }
    // The descriptor arrived: from here the export is charged and must be
    // detached.
    session.state().live.push(record.export);
    let attached = log_buffer_region(session.instance, &record)
        .and_then(|expected| Region::attach(fd, expected).map_err(AttachError::from))
        .and_then(|region| LogBuffer::attach(region).map_err(AttachError::from));
    match attached {
        Ok(buffer) => Ok(Fetched {
            record,
            buffer: Arc::new(buffer),
            stream_registration,
            incarnation,
        }),
        Err(error) => {
            session.detach(record.export);
            Err(error)
        }
    }
}

/// Receives and discards the regions of an aborted fetch, detaching each
/// export whose descriptor arrived.
fn abort(session: &Session, fetch: u64, records: &[Record]) {
    for (index, record) in (0u64..).zip(records) {
        match receive(&session.socket) {
            Ok((
                Message::Region {
                    fetch: got,
                    index: at,
                },
                Some(fd),
            )) if got == fetch && at == index => {
                session.state().live.push(record.export);
                drop(fd);
                session.detach(record.export);
            }
            _ => {
                session.state().broken = true;
                return;
            }
        }
    }
}

/// The region header a log buffer record describes.
fn log_buffer_region(instance: u128, record: &Record) -> Result<RegionRecord, AttachError> {
    Ok(RegionRecord {
        instance,
        region: record.region,
        kind: RegionKind::LogBuffer,
        generation: record.generation,
        layout: u64::from(record.layout),
        structure_length: usize::try_from(record.structure_length)
            .map_err(|_| AttachError::Protocol)?,
    })
}

/// Checks a fetched record and its buffer against the request: consistent
/// data alone does not prove it is the grant that was requested.
fn check(fetched: &Fetched, request: &Request) -> Result<(), AttachError> {
    let stream = request.stream();
    let config = fetched.buffer.config();
    let record = &fetched.record;
    let matches = record.stream_id == stream.stream_id
        && record.session_id == stream.session_id
        && config.stream_id == stream.stream_id
        && config.session_id == stream.session_id
        && record.lane == config.lane.get();
    if matches {
        Ok(())
    } else {
        Err(AttachError::Protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    use crate::generation::LinkStatus;

    /// A session over one end of a socket pair; the peer is returned so the
    /// session's sends do not fail.
    fn session() -> (Arc<Session>, UnixStream) {
        let (ours, peer) = UnixStream::pair().unwrap();
        let session = Arc::new(Session {
            instance: 1,
            socket: OwnedFd::from(ours),
            fetching: Mutex::new(()),
            state: Mutex::new(SessionState {
                next_fetch: 1,
                live: Vec::new(),
                broken: false,
            }),
            links: Mutex::new(Vec::new()),
        });
        (session, peer)
    }

    fn register(
        session: &Session,
        registration: u64,
        request: Request,
    ) -> Arc<GenerationLink<SharedTerms>> {
        let link = GenerationLink::new_remote();
        session.links().push(RemoteLink {
            registration,
            publication: (1, 1),
            request,
            generation: 0,
            link: Arc::downgrade(&link),
        });
        link
    }

    const STREAM: StreamKey = StreamKey {
        stream_id: 2,
        session_id: 1,
    };
    const OTHER: StreamKey = StreamKey {
        stream_id: 3,
        session_id: 1,
    };

    /// A lost driver closes every link, so a remote handle waiting at a
    /// seal that marks a successor ends instead of waiting for ever: the
    /// bound of the wait.
    #[test]
    fn a_lost_driver_closes_every_remote_link() {
        let (session, _peer) = session();
        let first = register(
            &session,
            1,
            Request::Subscription {
                stream: STREAM,
                role: SubscriberRole::Required,
            },
        );
        let second = register(
            &session,
            2,
            Request::Publication {
                stream: OTHER,
                allow_unconnected: false,
            },
        );
        // Waiting at a seal with a successor.
        assert!(matches!(first.next(true), crate::generation::Next::Wait));
        session.serve_cutovers(Vec::new(), false);
        assert_eq!(first.status(), LinkStatus::Current);
        session.serve_cutovers(Vec::new(), true);
        assert_eq!(first.status(), LinkStatus::Closed);
        assert_eq!(second.status(), LinkStatus::Closed);
        assert!(matches!(first.next(true), crate::generation::Next::End));
    }

    /// `PublicationClosed` closes the links of its stream, publication and
    /// subscription alike, and no other; `Fenced` closes its registration's.
    #[test]
    fn publication_closed_and_fenced_close_only_their_links() {
        let (session, _peer) = session();
        let subscription = register(
            &session,
            1,
            Request::Subscription {
                stream: STREAM,
                role: SubscriberRole::Optional,
            },
        );
        let publication = register(
            &session,
            2,
            Request::Publication {
                stream: STREAM,
                allow_unconnected: true,
            },
        );
        let other = register(
            &session,
            3,
            Request::ConcurrentPublication {
                stream: OTHER,
                allow_unconnected: true,
            },
        );
        let fenced = register(
            &session,
            4,
            Request::Subscription {
                stream: OTHER,
                role: SubscriberRole::Required,
            },
        );
        session.serve_cutovers(
            vec![Event::PublicationClosed {
                stream: STREAM,
                reason: karyos_protocol::cnc::CloseReason::RequiredParticipantLost,
            }],
            false,
        );
        assert_eq!(subscription.status(), LinkStatus::Closed);
        assert_eq!(publication.status(), LinkStatus::Closed);
        assert_eq!(other.status(), LinkStatus::Current);
        assert_eq!(fenced.status(), LinkStatus::Current);
        session.serve_cutovers(
            vec![Event::Fenced {
                stream: OTHER,
                registration: 4,
            }],
            false,
        );
        assert_eq!(fenced.status(), LinkStatus::Closed);
        assert_eq!(other.status(), LinkStatus::Current);
    }

    /// A link whose handle is gone is forgotten at the next service.
    #[test]
    fn dropped_handles_leave_the_registry() {
        let (session, _peer) = session();
        let link = register(
            &session,
            1,
            Request::Publication {
                stream: STREAM,
                allow_unconnected: true,
            },
        );
        drop(link);
        session.serve_cutovers(Vec::new(), false);
        assert!(session.links().is_empty());
    }
}
