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
    fn poll(&mut self) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => client.poll(),
            Self::Embedded(client) => client.poll(),
        }
    }

    /// The exclusive publication of `stream_id` on `uri` (a control call:
    /// it waits for the driver up to the context's timeout).
    pub(crate) fn add_publication(
        &mut self,
        uri: &str,
        stream_id: StreamId,
    ) -> Result<Lanes, Failure> {
        let failure = |error: ClientError| Failure::from(&error);
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(client) => client
                .add_exclusive_publication(uri, stream_id)
                .map(Lanes::Remote)
                .map_err(failure),
            Self::Embedded(client) => client
                .add_exclusive_publication(uri, stream_id)
                .map(Lanes::Embedded)
                .map_err(failure),
        }
    }

    /// Releases `lanes`, granted to this client.
    pub(crate) fn remove_publication(&mut self, lanes: Lanes) {
        match (self, lanes) {
            #[cfg(target_os = "linux")]
            (Self::Remote(client), Lanes::Remote(lanes)) => client.remove_publication(lanes),
            (Self::Embedded(client), Lanes::Embedded(lanes)) => client.remove_publication(lanes),
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
fn entry(client: AnyClient, driver: Option<driver::DriverState>) -> ClientEntry {
    ClientEntry {
        client,
        publications: Vec::new(),
        driver,
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
            idle_strategy: IDLE_YIELD,
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
    let client = Client::connect(context).map_err(|error| Failure::from(&error))?;
    Ok(clients().insert(entry(AnyClient::Remote(client), None))?)
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
    clients().insert(entry(AnyClient::Embedded(client), None))
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
    let client = Client::with_conductor(conductor, context);
    Ok(clients().insert(entry(AnyClient::Embedded(client), Some(state)))?)
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
    let publications = crate::api::publication::table().remove_all(&entry.publications)?;
    for publication in publications {
        publication.release(&mut entry.client);
    }
    entry.publications.clear();
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
