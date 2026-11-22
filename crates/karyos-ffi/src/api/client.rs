// SPDX-License-Identifier: Apache-2.0

//! Clients (F2): connect, serve and close.
//!
//! A client is the facade's `Client` over one of its two connections: a
//! remote one (`Client::connect`, Linux), or, for the tests until F5
//! exports the embedded driver, an in-process conductor
//! (`Client::with_conductor`), so the exported functions also run under
//! Miri and on macOS (quantstratum-docs: karyos/design/ffi-gap-analysis.md
//! §4.7).

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use karyos_client::{Client, ClientConductor, ClientError, Context, IdleStrategy, StreamId};

use crate::api::publication::Lanes;
use crate::api::subscription::Reader;

use crate::api::driver;
use crate::handles::{Handle, Kind, Table};
use crate::status::{Failure, Status};

/// The most clients open at once (`KARYOS_MAX_CLIENTS`).
pub(crate) const MAX_CLIENTS: u32 = 64;

/// `KARYOS_IDLE_BUSY_SPIN`.
pub(crate) const IDLE_BUSY_SPIN: u32 = 0;
/// `KARYOS_IDLE_YIELD`.
pub(crate) const IDLE_YIELD: u32 = 1;
/// `KARYOS_IDLE_SLEEP`.
pub(crate) const IDLE_SLEEP: u32 = 2;
/// `KARYOS_IDLE_YIELD_THEN_SLEEP`: the default (ADR-0066).
pub(crate) const IDLE_YIELD_THEN_SLEEP: u32 = 3;

/// A client over either connection.
pub(crate) enum AnyClient {
    /// Attached to a driver in another process.
    #[cfg(target_os = "linux")]
    Remote(Client<karyos_client::ipc::RemoteClient>),
    /// Over a conductor of an embedded driver.
    Embedded(Client<ClientConductor>),
}

impl AnyClient {
    /// Serves the connection once; whether anything was served.
    pub(crate) fn poll(&mut self) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => client.poll(),
            Self::Embedded(client) => client.poll(),
        }
    }

    /// The exclusive publication of `stream_id` on `uri`, or with
    /// `concurrent` a concurrent handle on lane 0 of a `karyos:ipc` stream
    /// (F7a-1). A control call: it waits for the driver up to the context's
    /// timeout.
    pub(crate) fn add_publication(
        &mut self,
        uri: &str,
        stream_id: StreamId,
        concurrent: bool,
    ) -> Result<Lanes, Failure> {
        let failure = |error: ClientError| Failure::from(&error);
        match (self, concurrent) {
            #[cfg(target_os = "linux")]
            (Self::Remote(client), false) => client
                .add_exclusive_publication(uri, stream_id)
                .map(Lanes::Remote)
                .map_err(failure),
            #[cfg(target_os = "linux")]
            (Self::Remote(client), true) => client
                .add_concurrent_publication(uri, stream_id)
                .map(|handle| Lanes::ConcurrentRemote(Box::new(handle)))
                .map_err(failure),
            (Self::Embedded(client), false) => client
                .add_exclusive_publication(uri, stream_id)
                .map(Lanes::Embedded)
                .map_err(failure),
            (Self::Embedded(client), true) => client
                .add_concurrent_publication(uri, stream_id)
                .map(|handle| Lanes::ConcurrentEmbedded(Box::new(handle)))
                .map_err(failure),
        }
    }

    /// The exclusive publication of `stream_id` on the `karyos:udp` channel
    /// `uri` whose receivers have `roles` (owner item 7, karyos#637). A
    /// control call, as [`AnyClient::add_publication`].
    pub(crate) fn add_publication_with_roles(
        &mut self,
        uri: &str,
        stream_id: StreamId,
        roles: &karyos_client::PublicationRoles,
    ) -> Result<Lanes, Failure> {
        let failure = |error: ClientError| Failure::from(&error);
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => client
                .add_exclusive_publication_with_roles(uri, stream_id, roles)
                .map(Lanes::Remote)
                .map_err(failure),
            Self::Embedded(client) => client
                .add_exclusive_publication_with_roles(uri, stream_id, roles)
                .map(Lanes::Embedded)
                .map_err(failure),
        }
    }

    /// The subscription of `stream_id` on the `karyos:udp` channel `uri`
    /// with `options`, whose images name the receiver `identity` (owner
    /// item 7, karyos#637). A control call, as
    /// [`AnyClient::add_subscription_with`].
    pub(crate) fn add_subscription_as(
        &mut self,
        uri: &str,
        stream_id: StreamId,
        options: karyos_client::SubscriptionOptions,
        identity: karyos_client::ReceiverIdentity,
    ) -> Result<Reader, Failure> {
        let failure = |error: ClientError| Failure::from(&error);
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => client
                .add_subscription_as(uri, stream_id, options, identity)
                .map(Reader::Remote)
                .map_err(failure),
            Self::Embedded(client) => client
                .add_subscription_as(uri, stream_id, options, identity)
                .map(Reader::Embedded)
                .map_err(failure),
        }
    }

    /// The admission state of this client's network publication
    /// `registration` (karyos#637).
    pub(crate) fn network_admission(
        &self,
        registration: u64,
    ) -> Option<karyos_client::NetworkAdmission> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => client.network_admission_of(registration),
            Self::Embedded(client) => client.network_admission_of(registration),
        }
    }

    /// The subscription of `stream_id` on `uri` with `options` (a control
    /// call: it waits for the driver up to the context's timeout).
    pub(crate) fn add_subscription_with(
        &mut self,
        uri: &str,
        stream_id: StreamId,
        options: karyos_client::SubscriptionOptions,
    ) -> Result<Reader, Failure> {
        let failure = |error: ClientError| Failure::from(&error);
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => client
                .add_subscription_with(uri, stream_id, options)
                .map(Reader::Remote)
                .map_err(failure),
            Self::Embedded(client) => client
                .add_subscription_with(uri, stream_id, options)
                .map(Reader::Embedded)
                .map_err(failure),
        }
    }

    /// Turns `reader`, this client's, into a rejoin that recovers its
    /// overruns from the Archive `source` names (F9b): its own connection
    /// to the control streams, an `ArchiveClient` over it and this
    /// client's replay targets, with `secondary` after a failed merge. On
    /// failure nothing stays open: the reader is removed, and the
    /// connection's streams are released by their drop.
    ///
    /// # Errors
    ///
    /// [`Status::UnsupportedChannel`] for a network subscription;
    /// [`Status::InvalidArgument`] for one that names no publication to
    /// recover; the driver's refusal of either control stream.
    pub(crate) fn rejoin(
        &mut self,
        reader: Reader,
        source: crate::api::archive::RejoinSource,
        replay_stream_id: i32,
        secondary: karyos_client::Secondary,
    ) -> Result<Reader, Failure> {
        match (self, reader) {
            #[cfg(target_os = "linux")]
            (Self::Remote(client), Reader::Remote(live)) => {
                rejoin_reader(client, live, source, replay_stream_id, secondary)
                    .map(|rejoining| Reader::RemoteRejoining(Box::new(rejoining)))
            }
            (Self::Embedded(client), Reader::Embedded(live)) => {
                rejoin_reader(client, live, source, replay_stream_id, secondary)
                    .map(|rejoining| Reader::EmbeddedRejoining(Box::new(rejoining)))
            }
            // Only a plain reader of the client's own connection rejoins.
            (client, reader) => {
                client.remove_subscription(reader);
                Err(Status::Internal.into())
            }
        }
    }

    /// A view of the conflation table of the `karyos:ipc` stream
    /// `stream_id` (F7b-2c): a remote client takes it; an embedded one is
    /// refused by its driver, which gives views itself. A control call.
    pub(crate) fn add_conflated_subscription(
        &mut self,
        uri: &str,
        stream_id: StreamId,
    ) -> Result<karyos_client::ConflatedSubscription, Failure> {
        let failure = |error: ClientError| Failure::from(&error);
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => client
                .add_conflated_subscription(uri, stream_id)
                .map_err(failure),
            Self::Embedded(client) => client
                .add_conflated_subscription(uri, stream_id)
                .map_err(failure),
        }
    }

    /// Releases `reader`, granted to this client.
    pub(crate) fn remove_subscription(&mut self, reader: Reader) {
        match (self, reader) {
            #[cfg(target_os = "linux")]
            (Self::Remote(client), Reader::Remote(reader)) => client.remove_subscription(reader),
            (Self::Embedded(client), Reader::Embedded(reader)) => {
                client.remove_subscription(reader);
            }
            // A rejoin gives its live reader back to be removed; its
            // Archive streams are released by their drop (F9b).
            #[cfg(target_os = "linux")]
            (Self::Remote(client), Reader::RemoteRejoining(reader)) => {
                if let Some(live) = reader.into_subscription() {
                    client.remove_subscription(live);
                }
            }
            (Self::Embedded(client), Reader::EmbeddedRejoining(reader)) => {
                if let Some(live) = reader.into_subscription() {
                    client.remove_subscription(live);
                }
            }
            // A subscription always has its client's connection; another
            // one is only dropped.
            #[cfg(target_os = "linux")]
            (_, reader) => drop(reader),
        }
    }

    /// Releases `lanes`, granted to this client.
    pub(crate) fn remove_publication(&mut self, lanes: Lanes) {
        match (self, lanes) {
            #[cfg(target_os = "linux")]
            (Self::Remote(client), Lanes::Remote(lanes)) => client.remove_publication(lanes),
            (Self::Embedded(client), Lanes::Embedded(lanes)) => client.remove_publication(lanes),
            #[cfg(target_os = "linux")]
            (Self::Remote(client), Lanes::ConcurrentRemote(handle)) => {
                client.remove_concurrent_publication(*handle);
            }
            (Self::Embedded(client), Lanes::ConcurrentEmbedded(handle)) => {
                client.remove_concurrent_publication(*handle);
            }
            // A publication always has its client's connection; another
            // one is only dropped.
            #[cfg(target_os = "linux")]
            (_, lanes) => drop(lanes),
        }
    }
}

/// A client handle's object: the client and its children's handles, which
/// its close ends first.
pub(crate) struct ClientEntry {
    /// The client.
    pub(crate) client: AnyClient,
    /// Its open publications.
    pub(crate) publications: Vec<Handle>,
    /// Its open subscriptions.
    pub(crate) subscriptions: Vec<Handle>,
    /// Its open conflated subscriptions (F7b-2c).
    pub(crate) conflated: Vec<Handle>,
    /// Its open Archive connections (F9a).
    pub(crate) archives: Vec<Handle>,
    /// Its subscriber of replay targets, opened by its first replay
    /// subscription (F9c): one target is asked for at a time.
    pub(crate) replay_target: Option<ReplayTarget>,
    /// The longest wait of its control calls, as its context set it.
    pub(crate) timeout: Duration,
    /// The state of the embedded driver whose conductor it is over, when
    /// the C ABI created that driver (F5): the client follows its failure
    /// and its close ([`driver::DriverState::usable`]).
    pub(crate) driver: Option<driver::DriverState>,
}

impl ClientEntry {
    /// Whether the client may act; see [`driver::DriverState::usable`].
    ///
    /// # Errors
    ///
    /// [`Status::Internal`] once its driver is poisoned,
    /// [`Status::Closed`] once it is closed.
    pub(crate) fn usable(&self) -> Result<(), Status> {
        self.driver
            .as_ref()
            .map_or(Ok(()), driver::DriverState::usable)
    }
}

/// The table of clients, allocated on first use.
pub(crate) fn clients() -> &'static Table<ClientEntry> {
    static CLIENTS: OnceLock<Table<ClientEntry>> = OnceLock::new();
    CLIENTS.get_or_init(|| Table::new(Kind::Client, MAX_CLIENTS))
}

/// A client's entry for its table, over `driver` when the C ABI created
/// it.
fn entry(client: AnyClient, driver: Option<driver::DriverState>, timeout: Duration) -> ClientEntry {
    ClientEntry {
        client,
        publications: Vec::new(),
        subscriptions: Vec::new(),
        conflated: Vec::new(),
        archives: Vec::new(),
        replay_target: None,
        timeout,
        driver,
    }
}

/// A client's subscriber of replay targets (F9c), of either connection.
pub(crate) enum ReplayTarget {
    /// Of a client attached to a driver in another process.
    #[cfg(target_os = "linux")]
    Remote(karyos_client::ReplayTargetSubscriber<karyos_sys::term_bytes::SharedTerms>),
    /// Of a client over an embedded driver's conductor.
    Embedded(karyos_client::ReplayTargetSubscriber<karyos_sys::term_bytes::HeapTerms>),
}

impl AnyClient {
    /// The replay target at `stream_id` and `session_id` as a reader, once
    /// a poll of this client has the grant; `None` until then. `target` is
    /// the client's subscriber, opened here on first use. Asking for
    /// another target withdraws the one asked for before, whose grant,
    /// taken or not, the client releases on its next poll.
    pub(crate) fn replay_target(
        &mut self,
        target: &mut Option<ReplayTarget>,
        stream_id: i32,
        session_id: i32,
    ) -> Option<Reader> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => {
                if !matches!(target, Some(ReplayTarget::Remote(_))) {
                    *target = Some(ReplayTarget::Remote(client.replay_targets()));
                }
                let Some(ReplayTarget::Remote(subscriber)) = target else {
                    return None;
                };
                subscriber
                    .subscribe(stream_id, session_id)
                    .map(|granted| Reader::Remote(granted.into()))
            }
            Self::Embedded(client) => {
                if !matches!(target, Some(ReplayTarget::Embedded(_))) {
                    *target = Some(ReplayTarget::Embedded(client.replay_targets()));
                }
                let Some(ReplayTarget::Embedded(subscriber)) = target else {
                    return None;
                };
                subscriber
                    .subscribe(stream_id, session_id)
                    .map(|granted| Reader::Embedded(granted.into()))
            }
        }
    }
}

/// A client's options, as `karyos_client_options` carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    /// The driver's directory.
    pub(crate) dir: Option<PathBuf>,
    /// `KARYOS_IDLE_*`.
    pub(crate) idle_strategy: u32,
    /// The sleep of `KARYOS_IDLE_SLEEP`, in nanoseconds.
    pub(crate) idle_sleep_ns: u64,
    /// The longest wait of a control call, in nanoseconds.
    pub(crate) timeout_ns: u64,
    /// The most requests in flight.
    pub(crate) max_pending: u32,
    /// The most images a network subscription attaches.
    pub(crate) max_images: u32,
}

impl Options {
    /// The facade's defaults, without a directory.
    pub(crate) fn defaults() -> Self {
        let context = Context::builder().build();
        let (timeout, max_pending, max_images) = context.map_or(
            (
                karyos_client::DEFAULT_TIMEOUT,
                karyos_client::DEFAULT_MAX_PENDING,
                karyos_client::DEFAULT_MAX_IMAGES,
            ),
            |context| {
                (
                    context.timeout(),
                    context.max_pending(),
                    context.max_images(),
                )
            },
        );
        Self {
            dir: None,
            idle_strategy: IDLE_YIELD_THEN_SLEEP,
            idle_sleep_ns: 0,
            timeout_ns: u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX),
            max_pending: u32::try_from(max_pending).unwrap_or(u32::MAX),
            max_images: u32::try_from(max_images).unwrap_or(u32::MAX),
        }
    }

    /// The facade's context.
    fn context(&self) -> Result<Context, Failure> {
        let idle = match self.idle_strategy {
            IDLE_BUSY_SPIN => IdleStrategy::BusySpin,
            IDLE_YIELD => IdleStrategy::Yield,
            IDLE_SLEEP => IdleStrategy::Sleep(Duration::from_nanos(self.idle_sleep_ns)),
            IDLE_YIELD_THEN_SLEEP => IdleStrategy::YieldThenSleep,
            _ => return Err(Status::InvalidArgument.into()),
        };
        let max_pending = usize::try_from(self.max_pending).map_err(|_| Status::InvalidArgument)?;
        let max_images = usize::try_from(self.max_images).map_err(|_| Status::InvalidArgument)?;
        let mut builder = Context::builder()
            .idle_strategy(idle)
            .timeout(Duration::from_nanos(self.timeout_ns))
            .max_pending(max_pending)
            .max_images(max_images);
        if let Some(dir) = &self.dir {
            builder = builder.dir(dir.clone());
        }
        builder.build().map_err(|error| Failure::from(&error))
    }
}

/// Attaches to the driver of `options.dir` and opens a client handle.
///
/// # Errors
///
/// The context's and the attach's failures; [`Status::Unsupported`] where
/// no cross-process client exists (not Linux).
pub(crate) fn connect(options: &Options) -> Result<Handle, Failure> {
    let context = options.context()?;
    connect_with(context)
}

#[cfg(target_os = "linux")]
fn connect_with(context: Context) -> Result<Handle, Failure> {
    let timeout = context.timeout();
    let client = Client::connect(context).map_err(|error| Failure::from(&error))?;
    Ok(clients().insert(entry(AnyClient::Remote(client), None, timeout))?)
}

#[cfg(not(target_os = "linux"))]
fn connect_with(_context: Context) -> Result<Handle, Failure> {
    Err(Status::Unsupported.into())
}

/// Opens a client handle over an embedded driver's conductor.
///
/// # Errors
///
/// [`Status::HandlesExhausted`].
#[cfg(test)]
pub(crate) fn insert_embedded(client: Client<ClientConductor>) -> Result<Handle, Status> {
    clients().insert(entry(
        AnyClient::Embedded(client),
        None,
        karyos_client::DEFAULT_TIMEOUT,
    ))
}

/// The releases of `client`'s publications that could not be sent
/// (`Client::publication_releases_failed`; tests).
#[cfg(test)]
pub(crate) fn publication_releases_failed(client: Handle) -> Result<u64, Status> {
    with_client(client, |entry| match &entry.client {
        #[cfg(target_os = "linux")]
        AnyClient::Remote(client) => client.publication_releases_failed(),
        AnyClient::Embedded(client) => client.publication_releases_failed(),
    })
}

/// Opens a client handle over a new conductor of the embedded driver
/// `owner`, with the facade's default context.
///
/// # Errors
///
/// The driver's refusal, the context's, and the table's.
pub(crate) fn connect_embedded(owner: Handle) -> Result<Handle, Failure> {
    let (conductor, state) = driver::conductor(owner)?;
    let context = Context::builder()
        .build()
        .map_err(|error| Failure::from(&error))?;
    let timeout = context.timeout();
    let client = Client::with_conductor(conductor, context);
    Ok(clients().insert(entry(AnyClient::Embedded(client), Some(state), timeout))?)
}

/// Serves `client` once; whether anything was served.
///
/// # Errors
///
/// As [`Table::with`].
pub(crate) fn poll(client: Handle) -> Result<bool, Status> {
    with_client(client, |entry| {
        entry.usable()?;
        Ok(entry.client.poll())
    })?
}

/// A child its close ended while another call held its client
/// (`karyos.h`, Threads): stale from that close on, and released to the
/// client by the client's next call, or by its close. Each entry is boxed:
/// the kinds differ widely in size, and a close builds one only to move it.
pub(crate) enum Ended {
    /// A publication.
    Publication(Handle, Box<crate::api::publication::Entry>),
    /// A subscription.
    Subscription(Handle, Box<crate::api::subscription::Entry>),
    /// A conflated view of a client.
    Conflated(Handle, Box<crate::api::conflated::Entry>),
    /// An Archive connection of a client.
    Archive(Handle, Box<crate::api::archive::Entry>),
}

impl Ended {
    /// Releases the child to its client and forgets its handle there.
    fn release(self, entry: &mut ClientEntry) {
        match self {
            Self::Publication(handle, publication) => {
                entry.publications.retain(|open| *open != handle);
                publication.release(&mut entry.client);
            }
            Self::Subscription(handle, subscription) => {
                entry.subscriptions.retain(|open| *open != handle);
                subscription.release(&mut entry.client);
            }
            // A view is released by its drop.
            Self::Conflated(handle, view) => {
                entry.conflated.retain(|open| *open != handle);
                drop(view);
            }
            Self::Archive(handle, archive) => {
                entry.archives.retain(|open| *open != handle);
                archive.release(&mut entry.client);
            }
        }
    }
}

/// The children ended under a held client, each with its client, until
/// that client releases them. Each is a child its own close removed from
/// its table, so there are never more than the children's tables hold.
/// The mutex is held only to push or take entries and, in a client's
/// close, for that close's tries of its children's slots: it never waits
/// on a handle.
fn ended() -> MutexGuard<'static, Vec<(Handle, Ended)>> {
    static ENDED: Mutex<Vec<(Handle, Ended)>> = Mutex::new(Vec::new());
    // A panic never happens while it is held: only pushes and moves.
    ENDED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The entries of the ended list, changed only under its mutex: a client
/// call finds the list empty without taking the mutex, so the clients'
/// calls do not serialize on it while no close is deferred.
static ENDED_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Pushes `child` of `client` onto `held`, the locked ended list.
fn push_ended(held: &mut Vec<(Handle, Ended)>, client: Handle, child: Ended) {
    held.push((client, child));
    ENDED_COUNT.store(held.len(), Ordering::Release);
}

/// Takes `client`'s ended children out of `held`, the locked ended list.
fn take_ended(held: &mut Vec<(Handle, Ended)>, client: Handle) -> Vec<Ended> {
    let taken = held
        .extract_if(.., |(owner, _)| *owner == client)
        .map(|(_, child)| child)
        .collect();
    ENDED_COUNT.store(held.len(), Ordering::Release);
    taken
}

/// Runs `f` on `client`'s entry, holding its slot, after releasing the
/// children whose close another call's hold of the client deferred: every
/// control call and poll of a client goes through here (`karyos.h`,
/// Threads).
///
/// # Errors
///
/// As [`Table::with`].
pub(crate) fn with_client<R>(
    client: Handle,
    f: impl FnOnce(&mut ClientEntry) -> R,
) -> Result<R, Status> {
    clients().with(client, |entry| {
        // A push racing this load is released by the client's next call.
        let taken = if ENDED_COUNT.load(Ordering::Acquire) == 0 {
            Vec::new()
        } else {
            take_ended(&mut ended(), client)
        };
        for child in taken {
            child.release(entry);
        }
        f(entry)
    })
}

/// Closes `handle`, a child of `client` in `table`: through the client,
/// which releases it at once, when the client is free. While another call
/// holds the client, on another thread or by this thread's callback, the
/// child ends now under its own slot, so the close answers ok and the
/// handle is stale, and the client releases it at its next call or its
/// close (`karyos.h`, Threads). Only a hold of the child itself answers
/// [`Status::Busy`] or [`Status::Reentrant`].
///
/// # Errors
///
/// The child's handle failures, and the client's other than a hold.
pub(crate) fn close_child<T>(
    client: Handle,
    table: &'static Table<T>,
    handle: Handle,
    wrap: fn(Handle, T) -> Ended,
) -> Result<(), Status> {
    match with_client(client, |entry| {
        let removed = table.remove(handle)?;
        wrap(handle, removed).release(entry);
        Ok(())
    }) {
        Ok(done) => done,
        Err(Status::Busy | Status::Reentrant) => {
            let mut held = ended();
            let removed = table.remove(handle)?;
            push_ended(&mut held, client, wrap(handle, removed));
            Ok(())
        }
        Err(status) => Err(status),
    }
}

/// Closes `entry`'s children, all or none, releasing each to its client:
/// while one is in use nothing is closed. The children an earlier close
/// ended under a held client are released first, whatever the outcome.
///
/// # Errors
///
/// As [`Table::remove_all`].
pub(crate) fn close_entry(client: Handle, entry: &mut ClientEntry) -> Result<(), Status> {
    // The ended children are taken, and every child of all four tables is
    // tried, under one hold of the ended list: a child's close then either
    // ended before (and is released here) or finds its slot taken by this
    // close, so none is left on the list for a closed client.
    let (ended_children, taken) = {
        let mut held = ended();
        let ended_children = take_ended(&mut held, client);
        let taken = (|| -> Result<_, Status> {
            Ok((
                crate::api::publication::table().take_all(&entry.publications)?,
                crate::api::subscription::table().take_all(&entry.subscriptions)?,
                crate::api::conflated::table().take_all(&entry.conflated)?,
                crate::api::archive::table().take_all(&entry.archives)?,
            ))
        })();
        (ended_children, taken)
    };
    for child in ended_children {
        child.release(entry);
    }
    let (publications, subscriptions, conflated, archives) = taken?;
    for publication in publications.close()? {
        publication.release(&mut entry.client);
    }
    for subscription in subscriptions.close()? {
        subscription.release(&mut entry.client);
    }
    // A view is released by its drop: it unmaps its table and sends its
    // grant's `Detach`.
    drop(conflated.close()?);
    for archive in archives.close()? {
        archive.release(&mut entry.client);
    }
    entry.publications.clear();
    entry.subscriptions.clear();
    entry.conflated.clear();
    entry.archives.clear();
    Ok(())
}

/// Closes `client` and its children: the driver releases what it granted
/// the client. All or nothing: while a child is in use, by another thread
/// ([`Status::Busy`]) or by this one's callback ([`Status::Reentrant`]),
/// nothing is closed.
///
/// # Errors
///
/// As [`Table::remove_with`].
pub(crate) fn close(client: Handle) -> Result<(), Status> {
    let (entry, ()) = clients().remove_with(client, |entry| close_entry(client, entry))?;
    // Dropping the client leaves the driver.
    drop(entry);
    Ok(())
}

/// [`AnyClient::rejoin`] on one connection.
fn rejoin_reader<C>(
    client: &mut Client<C>,
    live: karyos_client::Subscription<C::Terms>,
    source: crate::api::archive::RejoinSource,
    replay_stream_id: i32,
    secondary: karyos_client::Secondary,
) -> Result<karyos_client::RejoiningSubscription<C::Terms>, Failure>
where
    C: karyos_client::Connection,
    C::Terms: 'static,
    karyos_archive::client::connection::Requests<C::Terms>: karyos_archive::client::ControlRequests,
    karyos_archive::client::connection::Responses<C::Terms>:
        karyos_archive::client::ControlResponses,
{
    use karyos_archive::client::connection::ArchiveConnection;
    use karyos_archive::client::{ArchiveClient, ClientConfig};
    if live.registration().is_some() {
        client.remove_subscription(live);
        return Err(Status::UnsupportedChannel.into());
    }
    let (requests, responses) = match ArchiveConnection::open(client, source.streams) {
        Ok(connection) => connection.into_transports(),
        Err(error) => {
            client.remove_subscription(live);
            return Err(crate::api::archive::open_failure(error));
        }
    };
    let mut config = ClientConfig::new(source.client_id, replay_stream_id);
    config.deadline = source.deadline;
    let targets = client.replay_targets();
    let archive = match ArchiveClient::new(config, requests, responses, targets) {
        Ok(archive) => archive,
        // The default channel always fits; the transports drop.
        Err(_) => {
            client.remove_subscription(live);
            return Err(Status::Internal.into());
        }
    };
    match live.rejoin_with(Box::new(archive), secondary) {
        Ok(rejoining) => Ok(rejoining),
        Err(refused) => {
            let karyos_client::NotRejoinable { subscription, .. } = *refused;
            client.remove_subscription(subscription);
            Err(Status::InvalidArgument.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    use karyos_driver::EmbeddedDriver;

    use crate::api::{publication, subscription};

    /// A stream with one concurrent publisher, so a second publication
    /// is refused until the first one's release reaches the driver.
    const ONE_PUBLISHER: i32 = 2101;

    /// Waits a little in a test's loop: a millisecond's sleep under Miri,
    /// so the interpreter runs the thread that has work (MIRI.md, The
    /// profile); a yield natively.
    fn idle() {
        #[cfg(miri)]
        std::thread::sleep(Duration::from_millis(1));
        #[cfg(not(miri))]
        std::thread::yield_now();
    }

    /// An embedded driver driven on a thread of its own, and a client of
    /// it: closed, and the thread stopped, when dropped.
    struct Rig {
        client: Handle,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = close(self.client);
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn rig() -> Rig {
        use karyos_sys::frame::Lane;
        use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
        use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
        use karyos_sys::term::TermId;
        let mut driver = EmbeddedDriver::with_config(karyos_driver::DriverConfig {
            client_liveness_timeout: 3_600_000_000_000,
            ..karyos_driver::DriverConfig::default()
        })
        .unwrap();
        let _ = driver
            .add_stream(karyos_driver::StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 3,
                    max_subscribers: 4,
                    mtu: DEFAULT_MTU,
                    max_reserved: MIN_TERM_LENGTH / 8,
                    initial_term_id: TermId::new(7),
                    lane: Lane::ZERO,
                    session_id: 1,
                    stream_id: ONE_PUBLISHER,
                    claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                    publication: PublicationMode::Concurrent {
                        publishers: 1,
                        allow_non_lse: true,
                    },
                    schedule_capacity: 0,
                },
                allow_unconnected: true,
                on_required_loss: karyos_driver::LossPolicy::Hold,
                conflation: None,
            })
            .unwrap();
        #[cfg_attr(not(miri), allow(unused_mut))]
        let mut conductor = driver.connect().unwrap();
        // An hour's driver timeout under Miri, as abi's tests (karyos#1117).
        #[cfg(miri)]
        conductor.set_liveness(Duration::ZERO, Duration::from_secs(3600));
        let builder = Context::builder().timeout(Duration::from_secs(3600));
        #[cfg(miri)]
        let builder = builder.idle_strategy(IdleStrategy::Sleep(Duration::from_millis(1)));
        let client =
            insert_embedded(Client::with_conductor(conductor, builder.build().unwrap())).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                if driver.do_work().unwrap() == 0 {
                    idle();
                }
            }
        });
        Rig {
            client,
            stop,
            thread: Some(thread),
        }
    }

    /// Holds `client`'s slot on another thread, as a control call in
    /// progress does, until the returned sender is dropped.
    fn hold(client: Handle) -> (mpsc::Sender<()>, JoinHandle<()>) {
        let (held, is_held) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            clients()
                .with(client, |_| {
                    held.send(()).unwrap();
                    let _ = released.recv();
                })
                .unwrap();
        });
        is_held.recv().unwrap();
        (release, holder)
    }

    /// The children of `client` ended under a hold, not released yet.
    fn ended_of(client: Handle) -> usize {
        ended().iter().filter(|(owner, _)| *owner == client).count()
    }

    /// A close under a client another thread holds answers ok at once and
    /// the handle is stale; the publisher slot it held is released by the
    /// client's next call (`karyos.h`, Threads).
    #[test]
    fn a_close_under_a_held_client_ends_now_and_releases_at_the_next_call() {
        let rig = rig();
        let first = publication::add(rig.client, "karyos:ipc", ONE_PUBLISHER, true).unwrap();
        assert!(
            publication::add(rig.client, "karyos:ipc", ONE_PUBLISHER, true).is_err(),
            "one publisher only"
        );
        let (release, holder) = hold(rig.client);
        assert_eq!(publication::close(first), Ok(()));
        assert_eq!(
            publication::offer(first, 0, b"x").map_err(|failure| failure.status),
            Err(Status::Closed)
        );
        assert_eq!(publication::close(first), Err(Status::Closed));
        assert_eq!(ended_of(rig.client), 1);
        drop(release);
        holder.join().unwrap();
        // The client's next call releases it, so its publisher slot is free.
        poll(rig.client).unwrap();
        assert_eq!(ended_of(rig.client), 0);
        let second = publication::add(rig.client, "karyos:ipc", ONE_PUBLISHER, true).unwrap();
        assert_eq!(publication::close(second), Ok(()));
    }

    /// Sibling closes on four threads at once, while a fifth holds the
    /// client: every one answers ok, and the client's close releases them.
    #[test]
    fn sibling_closes_on_several_threads_all_answer_ok() {
        let rig = rig();
        let subscriptions: Vec<Handle> = (0..4)
            .map(|_| subscription::add(rig.client, "karyos:ipc", ONE_PUBLISHER).unwrap())
            .collect();
        let (release, holder) = hold(rig.client);
        let closers: Vec<_> = subscriptions
            .iter()
            .map(|&handle| std::thread::spawn(move || subscription::close(handle)))
            .collect();
        for closer in closers {
            assert_eq!(closer.join().unwrap(), Ok(()));
        }
        assert_eq!(ended_of(rig.client), 4);
        drop(release);
        holder.join().unwrap();
        // The client's close releases what its children's closes ended.
        assert_eq!(close(rig.client), Ok(()));
        assert_eq!(ended_of(rig.client), 0);
        for handle in subscriptions {
            assert_eq!(subscription::close(handle), Err(Status::Closed));
        }
    }

    /// A close of a child whose own slot is held still answers busy: only
    /// the client's hold is deferred.
    #[test]
    fn a_held_child_still_answers_busy() {
        let rig = rig();
        let opened = subscription::add(rig.client, "karyos:ipc", ONE_PUBLISHER).unwrap();
        let (held, is_held) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            subscription::table()
                .with(opened, |_| {
                    held.send(()).unwrap();
                    let _ = released.recv();
                })
                .unwrap();
        });
        is_held.recv().unwrap();
        assert_eq!(subscription::close(opened), Err(Status::Busy));
        drop(release);
        holder.join().unwrap();
        assert_eq!(subscription::close(opened), Ok(()));
        assert_eq!(ended_of(rig.client), 0);
    }

    /// Each `KARYOS_IDLE_*` maps to its facade strategy, and the default is
    /// `KARYOS_IDLE_YIELD_THEN_SLEEP` (ADR-0066).
    #[test]
    fn each_idle_strategy_maps_to_the_facades() {
        assert_eq!(Options::defaults().idle_strategy, IDLE_YIELD_THEN_SLEEP);
        // The ABI's default is the facade's: bindings define none of their
        // own (ADR-0066).
        assert_eq!(
            Options::defaults().context().unwrap().idle_strategy(),
            Context::builder().build().unwrap().idle_strategy()
        );
        for (code, strategy) in [
            (IDLE_BUSY_SPIN, IdleStrategy::BusySpin),
            (IDLE_YIELD, IdleStrategy::Yield),
            (IDLE_SLEEP, IdleStrategy::Sleep(Duration::from_nanos(7))),
            (IDLE_YIELD_THEN_SLEEP, IdleStrategy::YieldThenSleep),
        ] {
            let options = Options {
                idle_strategy: code,
                idle_sleep_ns: 7,
                ..Options::defaults()
            };
            assert_eq!(options.context().unwrap().idle_strategy(), strategy);
        }
        let unknown = Options {
            idle_strategy: 4,
            ..Options::defaults()
        };
        assert!(unknown.context().is_err());
    }
}
