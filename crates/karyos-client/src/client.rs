// SPDX-License-Identifier: Apache-2.0

//! The application facade of SPEC §10 (W7): a [`Client`] that names
//! channels by URI and blocks on the control path.
//!
//! ```text
//! let ctx = Context::builder().dir("/dev/shm/karyos").build()?;
//! let mut client = Client::connect(ctx)?;
//! let mut orders = client.add_exclusive_publication(
//!     "karyos:udp?endpoint=10.0.0.5:40123", StreamId::new(1001))?;
//! let mut md = client.add_subscription("karyos:ipc", StreamId::new(2001))?;
//! ```
//!
//! A client has one of two connections:
//!
//! - **Remote** (`Client::connect`, Linux): it attaches to the driver
//!   whose admission socket is in the context's directory. Its streams are
//!   shared terms, and the driver serves network channels on heap terms
//!   only (D3), so a `karyos:udp` URI is refused with
//!   [`ClientError::UnsupportedChannel`] until shared-term network streams.
//! - **In process** ([`Client::with_conductor`]): a conductor of an
//!   embedded driver that the application drives itself, on another
//!   thread (`EmbeddedDriver::do_work` or its agents). A driver driven on
//!   the caller's thread cannot answer while a control call waits: the call
//!   returns [`ClientError::Timeout`] at the context's timeout. The plain
//!   [`ClientConductor`] with its own `poll` stays the API for a driver
//!   driven on the same thread.
//!
//! Control calls (`add_*`) submit one request and serve the connection,
//! idling with the context's [`IdleStrategy`], until it completes or the
//! context's timeout passes. [`Client::poll`] serves the connection
//! without waiting: the application calls it regularly, as the remote
//! cutovers, the heartbeats and the images of network subscriptions are
//! served there.
//!
//! A `karyos:ipc` subscription reads the only stream of its id. A
//! `karyos:udp` subscription reads the images the driver announces for it
//! (`ImageAvailable`), each attached as it arrives and dropped when it
//! retires (`ImageUnavailable`), and polls them in turn: a client-side
//! fan-in until the driver aggregates images (D2). At most
//! [`Context::max_images`] images are attached; another is refused and
//! counted ([`Subscription::images_refused`]), never dropped silently.
//! Every subscription takes the role `required` for now; role and rejoin
//! policy by URI are a follow-up.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use karyos_protocol::cnc::{ErrorCode, Event, StreamId, StreamKey, SubscriberRole};
use karyos_sys::term_bytes::TermBytes;
use thiserror::Error;

use crate::conductor::{
    ClientConductor, Completion, ConductorError, ConductorPoll, EVENT_QUEUE, Outcome,
};
use crate::error::ClientError;
use crate::publication::ClientPublication;
use crate::subscription::{ClientSubscription, MessageInfo, MessageLimit, PollError, PollSummary};

/// Default wait of a control call.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default most images a network subscription attaches at once.
pub const DEFAULT_MAX_IMAGES: usize = 8;

/// Default most requests in flight on a client's conductor.
pub const DEFAULT_MAX_PENDING: usize = 64;

/// The role every facade subscription takes.
const ROLE: SubscriberRole = SubscriberRole::Required;

/// How a control call waits between two services of its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleStrategy {
    /// Spin without yielding.
    BusySpin,
    /// Yield the thread.
    Yield,
    /// Sleep for the period.
    Sleep(Duration),
}

impl IdleStrategy {
    fn idle(self) {
        match self {
            Self::BusySpin => core::hint::spin_loop(),
            Self::Yield => std::thread::yield_now(),
            Self::Sleep(period) => std::thread::sleep(period),
        }
    }
}

/// A client's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    dir: Option<PathBuf>,
    idle: IdleStrategy,
    timeout: Duration,
    max_pending: usize,
    max_images: usize,
}

impl Context {
    /// A builder with the defaults.
    #[must_use]
    pub fn builder() -> ContextBuilder {
        ContextBuilder {
            context: Self {
                dir: None,
                idle: IdleStrategy::Yield,
                timeout: DEFAULT_TIMEOUT,
                max_pending: DEFAULT_MAX_PENDING,
                max_images: DEFAULT_MAX_IMAGES,
            },
        }
    }

    /// The driver's directory, which holds its admission socket.
    #[must_use]
    pub fn dir(&self) -> Option<&std::path::Path> {
        self.dir.as_deref()
    }

    /// How a control call waits.
    #[must_use]
    pub fn idle_strategy(&self) -> IdleStrategy {
        self.idle
    }

    /// The longest wait of a control call.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The most images a network subscription attaches at once.
    #[must_use]
    pub fn max_images(&self) -> usize {
        self.max_images
    }
}

/// Builds a [`Context`].
#[derive(Debug, Clone)]
pub struct ContextBuilder {
    context: Context,
}

impl ContextBuilder {
    /// The driver's directory (`Client::connect` requires it).
    #[must_use]
    pub fn dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.context.dir = Some(dir.into());
        self
    }

    /// How a control call waits ([`IdleStrategy::Yield`] by default).
    #[must_use]
    pub fn idle_strategy(mut self, idle: IdleStrategy) -> Self {
        self.context.idle = idle;
        self
    }

    /// The longest wait of a control call ([`DEFAULT_TIMEOUT`] by default).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.context.timeout = timeout;
        self
    }

    /// The most requests in flight ([`DEFAULT_MAX_PENDING`] by default).
    #[must_use]
    pub fn max_pending(mut self, max_pending: usize) -> Self {
        self.context.max_pending = max_pending;
        self
    }

    /// The most images a network subscription attaches at once
    /// ([`DEFAULT_MAX_IMAGES`] by default).
    #[must_use]
    pub fn max_images(mut self, max_images: usize) -> Self {
        self.context.max_images = max_images;
        self
    }

    /// The context.
    ///
    /// # Errors
    ///
    /// [`ClientError::InvalidContext`] for a zero timeout, pending bound or
    /// image bound.
    pub fn build(self) -> Result<Context, ClientError> {
        let context = self.context;
        if context.timeout.is_zero() {
            return Err(ClientError::InvalidContext {
                reason: "the timeout is zero",
            });
        }
        if context.max_pending == 0 {
            return Err(ClientError::InvalidContext {
                reason: "no request may be pending",
            });
        }
        if context.max_images == 0 {
            return Err(ClientError::InvalidContext {
                reason: "no image may be attached",
            });
        }
        Ok(context)
    }
}

/// A failed subscription poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SubscriptionError {
    /// An image's poll failed after `delivered` messages of this poll.
    #[error("image poll failed after {delivered} messages: {error}")]
    Poll {
        /// The image's session id, for a network subscription.
        session_id: Option<i32>,
        /// Messages delivered by this poll, the failed image's included.
        delivered: u32,
        /// The failure.
        error: PollError,
    },
    /// The subscription is closed.
    #[error(transparent)]
    Closed(ClientError),
}

/// What a subscription poll did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubscriptionPoll {
    /// Messages delivered, over every image.
    pub delivered: u32,
    /// The first image whose poll reported more than deliveries (an
    /// overrun, an abort, a skip, a seal or a revocation).
    pub stopped: Option<ImageStop>,
}

/// An image's poll that reported more than deliveries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageStop {
    /// The image's session id, for a network subscription.
    pub session_id: Option<i32>,
    /// Its poll's summary.
    pub summary: PollSummary,
}

/// Adds one to `count`; at its end it keeps its value (SPEC §14: checked,
/// never wrapped).
fn bump(count: &mut u64) {
    if let Some(next) = count.checked_add(1) {
        *count = next;
    }
}

fn stopped(summary: &PollSummary) -> bool {
    summary.overrun.is_some()
        || summary.aborted.is_some()
        || summary.skipped.is_some()
        || summary.closed.is_some()
        || summary.revoked.is_some()
        || summary.closed_by_overrun.is_some()
}

mod sealed {
    pub trait Sealed {}
}

/// A client's connection to its driver: a remote client or an in-process
/// conductor.
pub trait Connection: sealed::Sealed {
    /// The term storage of its handles.
    type Terms: TermBytes;

    #[doc(hidden)]
    fn add_network_publication(&mut self, uri: &str, stream_id: i32)
    -> Result<u64, ConductorError>;

    #[doc(hidden)]
    fn add_network_subscription(
        &mut self,
        uri: &str,
        stream_id: i32,
    ) -> Result<u64, ConductorError>;

    #[doc(hidden)]
    fn add_subscription(&mut self, stream: StreamKey) -> Result<u64, ConductorError>;

    #[doc(hidden)]
    fn remove_network_subscription(&mut self, registration: u64) -> Result<u64, ConductorError>;

    #[doc(hidden)]
    fn poll_into(&mut self, limit: usize, completions: &mut Vec<Completion>) -> ConductorPoll;

    #[doc(hidden)]
    fn events_into(&mut self, events: &mut Vec<Event>);

    #[doc(hidden)]
    fn events_dropped(&self) -> u64;

    #[doc(hidden)]
    fn publication(&self, outcome: Outcome) -> Result<ClientPublication<Self::Terms>, ClientError>;

    #[doc(hidden)]
    fn subscription(
        &self,
        outcome: Outcome,
    ) -> Result<ClientSubscription<Self::Terms>, ClientError>;

    /// Releases what a late answer granted; whether it granted anything.
    #[doc(hidden)]
    fn release(&mut self, outcome: Outcome) -> bool;
}

impl sealed::Sealed for ClientConductor {}

impl Connection for ClientConductor {
    type Terms = karyos_sys::term_bytes::HeapTerms;

    fn add_network_publication(
        &mut self,
        uri: &str,
        stream_id: i32,
    ) -> Result<u64, ConductorError> {
        ClientConductor::add_network_publication(self, uri, stream_id, false)
    }

    fn add_network_subscription(
        &mut self,
        uri: &str,
        stream_id: i32,
    ) -> Result<u64, ConductorError> {
        ClientConductor::add_network_subscription(self, uri, stream_id, ROLE)
    }

    fn add_subscription(&mut self, stream: StreamKey) -> Result<u64, ConductorError> {
        ClientConductor::add_subscription(self, stream, ROLE)
    }

    fn remove_network_subscription(&mut self, registration: u64) -> Result<u64, ConductorError> {
        ClientConductor::remove_network_subscription(self, registration)
    }

    fn poll_into(&mut self, limit: usize, completions: &mut Vec<Completion>) -> ConductorPoll {
        self.poll(limit, |completion| completions.push(completion))
    }

    fn events_into(&mut self, events: &mut Vec<Event>) {
        events.extend(self.take_events());
    }

    fn events_dropped(&self) -> u64 {
        ClientConductor::events_dropped(self)
    }

    fn publication(&self, outcome: Outcome) -> Result<ClientPublication<Self::Terms>, ClientError> {
        match outcome {
            Outcome::Publication(publication) => Ok(publication),
            other => Err(refusal(&other)),
        }
    }

    fn subscription(
        &self,
        outcome: Outcome,
    ) -> Result<ClientSubscription<Self::Terms>, ClientError> {
        match outcome {
            Outcome::Subscription(subscription) => Ok(subscription),
            other => Err(refusal(&other)),
        }
    }

    fn release(&mut self, outcome: Outcome) -> bool {
        match outcome {
            // Removed by the matching command; a handle that cannot be
            // removed now is dropped, which ends its lease.
            Outcome::Publication(publication) => self.remove_publication(publication).is_ok(),
            Outcome::Subscription(subscription) => self.remove_subscription(subscription).is_ok(),
            Outcome::NetworkSubscription { registration } => {
                ClientConductor::remove_network_subscription(self, registration).is_ok()
            }
            _ => false,
        }
    }
}

#[cfg(target_os = "linux")]
impl sealed::Sealed for crate::ipc::RemoteClient {}

#[cfg(target_os = "linux")]
impl Connection for crate::ipc::RemoteClient {
    type Terms = karyos_sys::term_bytes::SharedTerms;

    fn add_network_publication(
        &mut self,
        uri: &str,
        stream_id: i32,
    ) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::add_network_publication(self, uri, stream_id, false)
    }

    fn add_network_subscription(
        &mut self,
        uri: &str,
        stream_id: i32,
    ) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::add_network_subscription(self, uri, stream_id, ROLE)
    }

    fn add_subscription(&mut self, stream: StreamKey) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::add_subscription(self, stream, ROLE)
    }

    fn remove_network_subscription(&mut self, registration: u64) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::remove_network_subscription(self, registration)
    }

    fn poll_into(&mut self, limit: usize, completions: &mut Vec<Completion>) -> ConductorPoll {
        self.poll(limit, |completion| completions.push(completion))
    }

    fn events_into(&mut self, events: &mut Vec<Event>) {
        events.extend(self.take_events());
    }

    fn events_dropped(&self) -> u64 {
        crate::ipc::RemoteClient::events_dropped(self)
    }

    fn publication(&self, outcome: Outcome) -> Result<ClientPublication<Self::Terms>, ClientError> {
        match outcome {
            Outcome::Fetchable(fetchable) => Ok(self.take_publication(&fetchable)?),
            other => Err(refusal(&other)),
        }
    }

    fn subscription(
        &self,
        outcome: Outcome,
    ) -> Result<ClientSubscription<Self::Terms>, ClientError> {
        match outcome {
            Outcome::Fetchable(fetchable) => Ok(self.take_subscription(&fetchable)?),
            other => Err(refusal(&other)),
        }
    }

    fn release(&mut self, outcome: Outcome) -> bool {
        match outcome {
            // Taken and dropped: the handle detaches its export and ends
            // its registration.
            Outcome::Fetchable(fetchable) => match fetchable.request {
                crate::conductor::Request::Publication { .. } => {
                    self.take_publication(&fetchable).is_ok()
                }
                crate::conductor::Request::Subscription { .. } => {
                    self.take_subscription(&fetchable).is_ok()
                }
                _ => false,
            },
            Outcome::NetworkSubscription { registration } => {
                crate::ipc::RemoteClient::remove_network_subscription(self, registration).is_ok()
            }
            _ => false,
        }
    }
}

/// The error of an outcome that is not the grant asked for.
fn refusal(outcome: &Outcome) -> ClientError {
    match *outcome {
        Outcome::Refused {
            code: ErrorCode::UnsupportedChannel,
            detail,
        } => ClientError::UnsupportedChannel { detail },
        Outcome::Refused { code, detail } => ClientError::Refused { code, detail },
        _ => ClientError::Unknown,
    }
}

/// What a network subscription's images hand over from the client to the
/// subscription.
#[derive(Debug)]
struct Inbox<T: TermBytes> {
    /// Something is waiting: the subscription locks only then.
    changed: AtomicBool,
    state: Mutex<InboxState<T>>,
}

#[derive(Debug)]
struct InboxState<T: TermBytes> {
    /// Images attached and not yet taken.
    arrived: Vec<(i32, ClientSubscription<T>)>,
    /// Sessions of images retired.
    retired: Vec<i32>,
    /// Why the subscription is closed.
    closed: Option<ClientError>,
    /// Images refused: beyond the bound, or their attach failed.
    refused: u64,
}

impl<T: TermBytes> Inbox<T> {
    fn new() -> Self {
        Self {
            changed: AtomicBool::new(false),
            state: Mutex::new(InboxState {
                arrived: Vec::new(),
                retired: Vec::new(),
                closed: None,
                refused: 0,
            }),
        }
    }

    fn update(&self, change: impl FnOnce(&mut InboxState<T>)) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        change(&mut state);
        self.changed.store(true, Ordering::Release);
    }

    fn refused(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .refused
    }
}

/// A network subscription the client serves.
#[derive(Debug)]
struct Network<T: TermBytes> {
    registration: u64,
    inbox: Weak<Inbox<T>>,
    /// Images attached or being attached.
    images: usize,
}

/// An image attach in flight.
#[derive(Debug, Clone, Copy)]
struct Attach {
    sequence: u64,
    registration: u64,
    session_id: i32,
    /// Its image retired first: the grant is dropped.
    cancelled: bool,
}

/// What a waited request found.
enum Found<T: TermBytes> {
    Outcome(Box<Outcome>),
    Network(u64, Arc<Inbox<T>>),
}

/// The application's client (SPEC §10): see the module docs.
#[derive(Debug)]
pub struct Client<C: Connection> {
    connection: C,
    context: Context,
    networks: Vec<Network<C::Terms>>,
    attaches: Vec<Attach>,
    /// Network subscriptions dropped whose removal is not submitted yet.
    removals: Vec<u64>,
    events_dropped: u64,
    /// Late grants released after their request timed out.
    late_released: u64,
    completions: Vec<Completion>,
    events: Vec<Event>,
}

#[cfg(target_os = "linux")]
impl Client<crate::ipc::RemoteClient> {
    /// Attaches to the driver whose admission socket is in the context's
    /// directory, waiting at most the context's timeout per message.
    ///
    /// # Errors
    ///
    /// [`ClientError::NoDirectory`], `ClientError::Attach`.
    pub fn connect(context: Context) -> Result<Self, ClientError> {
        let dir = context.dir.as_deref().ok_or(ClientError::NoDirectory)?;
        let remote = crate::ipc::attach(dir, context.timeout, context.max_pending)?;
        Ok(Self::new(remote, context))
    }
}

impl Client<ClientConductor> {
    /// A client over an in-process conductor of an embedded driver, which
    /// the application drives on another thread (see the module docs).
    #[must_use]
    pub fn with_conductor(conductor: ClientConductor, context: Context) -> Self {
        Self::new(conductor, context)
    }
}

impl<C: Connection> Client<C> {
    fn new(connection: C, context: Context) -> Self {
        let events_dropped = connection.events_dropped();
        Self {
            connection,
            context,
            networks: Vec::new(),
            attaches: Vec::new(),
            removals: Vec::new(),
            events_dropped,
            late_released: 0,
            completions: Vec::new(),
            events: Vec::new(),
        }
    }

    /// The connection.
    #[must_use]
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// Grants that arrived after their request timed out, released at
    /// once (the handle dropped, or the network subscription removed).
    #[must_use]
    pub fn late_grants_released(&self) -> u64 {
        self.late_released
    }

    /// The exclusive publication of `stream_id` on the channel `uri`: a
    /// `karyos:ipc` URI names the only stream of the id, a `karyos:udp`
    /// one creates a network publication. Offers are refused while no
    /// subscriber is connected.
    ///
    /// # Errors
    ///
    /// [`ClientError::Conductor`] for a URI that does not parse or a
    /// request that cannot be submitted, [`ClientError::Timeout`],
    /// [`ClientError::UnsupportedChannel`], [`ClientError::Refused`],
    /// [`ClientError::Unknown`], and on Linux `ClientError::Attach`.
    pub fn add_exclusive_publication(
        &mut self,
        uri: &str,
        stream_id: StreamId,
    ) -> Result<ClientPublication<C::Terms>, ClientError> {
        let sequence = self
            .connection
            .add_network_publication(uri, stream_id.get())?;
        match self.wait(sequence)? {
            Found::Outcome(outcome) => self.connection.publication(*outcome),
            Found::Network(..) => Err(ClientError::Unknown),
        }
    }

    /// A subscription of `stream_id` on the channel `uri`: a `karyos:ipc`
    /// URI reads the only stream of the id, a `karyos:udp` one the images
    /// of a network subscription (see the module docs).
    ///
    /// # Errors
    ///
    /// As [`Client::add_exclusive_publication`].
    pub fn add_subscription(
        &mut self,
        uri: &str,
        stream_id: StreamId,
    ) -> Result<Subscription<C::Terms>, ClientError> {
        let sequence = self
            .connection
            .add_network_subscription(uri, stream_id.get())?;
        match self.wait(sequence)? {
            Found::Outcome(outcome) => Ok(Subscription {
                kind: Kind::Stream(Box::new(self.connection.subscription(*outcome)?)),
            }),
            Found::Network(registration, inbox) => Ok(Subscription {
                kind: Kind::Images(Images {
                    registration,
                    inbox,
                    images: Vec::new(),
                    next: 0,
                    closed: None,
                }),
            }),
        }
    }

    /// Serves the connection once without waiting: completions, driver
    /// events, the images of network subscriptions, the removal of dropped
    /// ones and, for a remote client, the cutovers of its handles. Returns
    /// whether any completion or event was served.
    pub fn poll(&mut self) -> bool {
        let (served, _) = self.service(None);
        served
    }

    /// Serves until request `sequence` completes or the timeout passes.
    fn wait(&mut self, sequence: u64) -> Result<Found<C::Terms>, ClientError> {
        let start = Instant::now();
        loop {
            if let (_, Some(found)) = self.service(Some(sequence)) {
                return Ok(found);
            }
            if start.elapsed() >= self.context.timeout {
                return Err(ClientError::Timeout);
            }
            self.context.idle.idle();
        }
    }

    /// Serves the connection once; returns whether anything was served and
    /// the completion of `wanted`, when it arrived.
    fn service(&mut self, wanted: Option<u64>) -> (bool, Option<Found<C::Terms>>) {
        let mut completions = core::mem::take(&mut self.completions);
        let mut events = core::mem::take(&mut self.events);
        // At most one queue of events per service: none is dropped before
        // it is taken.
        let _ = self.connection.poll_into(EVENT_QUEUE, &mut completions);
        self.connection.events_into(&mut events);
        let served = !completions.is_empty() || !events.is_empty();
        let mut found = None;
        for completion in completions.drain(..) {
            if Some(completion.sequence) == wanted {
                found = Some(self.found(completion.outcome));
            } else {
                // Anything else is an attach, or a late answer released.
                self.attached(completion);
            }
        }
        for event in events.drain(..) {
            self.event(event);
        }
        let dropped = self.connection.events_dropped();
        if dropped != self.events_dropped {
            self.events_dropped = dropped;
            for network in &self.networks {
                if let Some(inbox) = network.inbox.upgrade() {
                    inbox.update(|state| state.closed = Some(ClientError::EventsLost));
                }
            }
        }
        self.remove_dropped();
        self.completions = completions;
        self.events = events;
        (served, found)
    }

    fn found(&mut self, outcome: Outcome) -> Found<C::Terms> {
        match outcome {
            Outcome::NetworkSubscription { registration } => {
                // Registered before the events of this service, which may
                // announce its first images.
                let inbox = Arc::new(Inbox::new());
                self.networks.push(Network {
                    registration,
                    inbox: Arc::downgrade(&inbox),
                    images: 0,
                });
                Found::Network(registration, inbox)
            }
            other => Found::Outcome(Box::new(other)),
        }
    }

    /// Hands an image's grant to its subscription.
    fn attached(&mut self, completion: Completion) {
        let Some(index) = self
            .attaches
            .iter()
            .position(|attach| attach.sequence == completion.sequence)
        else {
            // A late answer to a request that timed out: what it granted
            // is released, so timeouts cannot accumulate driver resources.
            if self.connection.release(completion.outcome) {
                bump(&mut self.late_released);
            }
            return;
        };
        let attach = self.attaches.swap_remove(index);
        let Some(position) = self
            .networks
            .iter()
            .position(|network| network.registration == attach.registration)
        else {
            return;
        };
        let inbox = self.networks.get(position).and_then(|n| n.inbox.upgrade());
        let subscription = self.connection.subscription(completion.outcome);
        let Some(inbox) = inbox else {
            return;
        };
        match subscription {
            Ok(subscription) if !attach.cancelled => {
                inbox.update(|state| state.arrived.push((attach.session_id, subscription)));
            }
            // Retired before it was attached: dropped, its count already
            // returned.
            Ok(_) => {}
            Err(_) => {
                if let Some(network) = self.networks.get_mut(position) {
                    // Counted when the attach was sent.
                    if let Some(images) = network.images.checked_sub(1) {
                        network.images = images;
                    }
                }
                inbox.update(|state| bump(&mut state.refused));
            }
        }
    }

    fn event(&mut self, event: Event) {
        match event {
            Event::ImageAvailable {
                stream,
                registration,
            } => self.image_available(stream, registration),
            Event::ImageUnavailable {
                stream,
                registration,
            } => self.image_unavailable(stream, registration),
            _ => {}
        }
    }

    fn image_available(&mut self, stream: StreamKey, registration: u64) {
        let Some(network) = self
            .networks
            .iter_mut()
            .find(|network| network.registration == registration)
        else {
            return;
        };
        let Some(inbox) = network.inbox.upgrade() else {
            return;
        };
        if network.images >= self.context.max_images {
            inbox.update(|state| bump(&mut state.refused));
            return;
        }
        match self.connection.add_subscription(stream) {
            Ok(sequence) => {
                // Below max_images, which is a usize.
                if let Some(images) = network.images.checked_add(1) {
                    network.images = images;
                }
                self.attaches.push(Attach {
                    sequence,
                    registration,
                    session_id: stream.session_id,
                    cancelled: false,
                });
            }
            Err(_) => inbox.update(|state| bump(&mut state.refused)),
        }
    }

    fn image_unavailable(&mut self, stream: StreamKey, registration: u64) {
        let Some(network) = self
            .networks
            .iter_mut()
            .find(|network| network.registration == registration)
        else {
            return;
        };
        let pending = self.attaches.iter_mut().find(|attach| {
            attach.registration == registration
                && attach.session_id == stream.session_id
                && !attach.cancelled
        });
        let counted = match pending {
            Some(attach) => {
                attach.cancelled = true;
                true
            }
            None => network.inbox.upgrade().is_some_and(|inbox| {
                inbox.update(|state| state.retired.push(stream.session_id));
                true
            }),
        };
        if counted && let Some(images) = network.images.checked_sub(1) {
            network.images = images;
        }
    }

    /// Removes the network subscriptions whose handle was dropped.
    fn remove_dropped(&mut self) {
        let removals = &mut self.removals;
        self.networks.retain(|network| {
            let live = network.inbox.strong_count() > 0;
            if !live {
                removals.push(network.registration);
            }
            live
        });
        let connection = &mut self.connection;
        // What cannot be submitted now is tried again at the next service.
        self.removals.retain(|&registration| {
            connection
                .remove_network_subscription(registration)
                .is_err()
        });
    }
}

/// A subscription of a [`Client`].
#[derive(Debug)]
pub struct Subscription<T: TermBytes> {
    kind: Kind<T>,
}

#[derive(Debug)]
enum Kind<T: TermBytes> {
    Stream(Box<ClientSubscription<T>>),
    Images(Images<T>),
}

#[derive(Debug)]
struct Images<T: TermBytes> {
    registration: u64,
    inbox: Arc<Inbox<T>>,
    images: Vec<(i32, ClientSubscription<T>)>,
    /// The image the next poll starts at.
    next: usize,
    closed: Option<ClientError>,
}

impl<T: TermBytes> Subscription<T> {
    /// The network subscription's registration; `None` for a stream.
    #[must_use]
    pub fn registration(&self) -> Option<u64> {
        match &self.kind {
            Kind::Stream(_) => None,
            Kind::Images(images) => Some(images.registration),
        }
    }

    /// The images attached; 1 for a stream.
    #[must_use]
    pub fn image_count(&self) -> usize {
        match &self.kind {
            Kind::Stream(_) => 1,
            Kind::Images(images) => images.images.len(),
        }
    }

    /// Images refused: announced beyond [`Context::max_images`], or whose
    /// attach failed. Always 0 for a stream.
    #[must_use]
    pub fn images_refused(&self) -> u64 {
        match &self.kind {
            Kind::Stream(_) => 0,
            Kind::Images(images) => images.inbox.refused(),
        }
    }

    /// Delivers at most `limit` messages in all to `handler`. A network
    /// subscription polls its images in turn, starting after the image the
    /// last poll ended at, so none starves.
    ///
    /// # Errors
    ///
    /// [`SubscriptionError::Closed`] once the subscription is closed, and
    /// [`SubscriptionError::Poll`] when an image's poll fails.
    #[expect(
        clippy::result_large_err,
        reason = "the error carries the image's poll error by value, as ClientSubscription::poll does, so a failed poll reports its progress"
    )]
    pub fn poll<H>(
        &mut self,
        mut handler: H,
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        match &mut self.kind {
            Kind::Stream(subscription) => match subscription.poll(&mut handler, limit) {
                Ok(summary) => Ok(SubscriptionPoll {
                    delivered: summary.delivered,
                    stopped: stopped(&summary).then_some(ImageStop {
                        session_id: None,
                        summary,
                    }),
                }),
                Err(error) => Err(SubscriptionError::Poll {
                    session_id: None,
                    delivered: error.summary.delivered,
                    error,
                }),
            },
            Kind::Images(images) => images.poll(&mut handler, limit),
        }
    }
}

impl<T: TermBytes> Images<T> {
    /// Takes what the client handed over.
    fn adopt(&mut self) {
        if !self.inbox.changed.swap(false, Ordering::Acquire) {
            return;
        }
        let mut state = self
            .inbox
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.images.append(&mut state.arrived);
        for session_id in state.retired.drain(..) {
            self.images.retain(|(session, _)| *session != session_id);
        }
        if self.closed.is_none() {
            self.closed = state.closed;
        }
        drop(state);
        if self.closed.is_some() {
            self.images.clear();
        }
        if self.next >= self.images.len() {
            self.next = 0;
        }
    }

    #[expect(
        clippy::result_large_err,
        reason = "the error carries the image's poll error by value, as ClientSubscription::poll does, so a failed poll reports its progress"
    )]
    fn poll(
        &mut self,
        handler: &mut impl FnMut(&[u8], MessageInfo),
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError> {
        self.adopt();
        if let Some(error) = self.closed {
            return Err(SubscriptionError::Closed(error));
        }
        let mut result = SubscriptionPoll::default();
        let count = self.images.len();
        let start = self.next;
        for offset in 0..count {
            // Deliveries never exceed the limit.
            let Some(remaining) = limit.get().checked_sub(result.delivered) else {
                break;
            };
            if remaining == 0 {
                break;
            }
            let index = (start + offset) % count;
            let Some((session_id, image)) = self.images.get_mut(index) else {
                break;
            };
            self.next = (index + 1) % count;
            match image.poll(&mut *handler, MessageLimit::new(remaining)) {
                Ok(summary) => {
                    // Within the limit, a u32.
                    if let Some(delivered) = result.delivered.checked_add(summary.delivered) {
                        result.delivered = delivered;
                    }
                    if result.stopped.is_none() && stopped(&summary) {
                        result.stopped = Some(ImageStop {
                            session_id: Some(*session_id),
                            summary,
                        });
                    }
                }
                Err(error) => {
                    return Err(SubscriptionError::Poll {
                        session_id: Some(*session_id),
                        delivered: result
                            .delivered
                            .checked_add(error.summary.delivered)
                            .unwrap_or(result.delivered),
                        error,
                    });
                }
            }
        }
        Ok(result)
    }
}
