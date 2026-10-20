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
use std::sync::OnceLock;
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
    clients().with(client, |entry| match &entry.client {
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
    clients().with(client, |entry| {
        entry.usable()?;
        Ok(entry.client.poll())
    })?
}

/// Closes `entry`'s children, all or none, releasing each to its client:
/// while one is in use nothing is closed. A driver's close (F5) closes its
/// clients' children with it.
///
/// # Errors
///
/// As [`Table::remove_all`].
pub(crate) fn close_entry(entry: &mut ClientEntry) -> Result<(), Status> {
    // Every child of all four tables is taken before any is closed, so
    // while one is in use nothing is.
    let publications = crate::api::publication::table().take_all(&entry.publications)?;
    let subscriptions = crate::api::subscription::table().take_all(&entry.subscriptions)?;
    let conflated = crate::api::conflated::table().take_all(&entry.conflated)?;
    let archives = crate::api::archive::table().take_all(&entry.archives)?;
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
    let (entry, ()) = clients().remove_with(client, close_entry)?;
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
