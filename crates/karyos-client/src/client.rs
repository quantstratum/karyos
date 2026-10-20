// SPDX-License-Identifier: Apache-2.0

//! The application facade of SPEC §10 (W7): a [`Client`] that names
//! channels by URI and blocks on the control path.
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use karyos_client::{Client, Context, MessageLimit, StreamId};
//!
//! let ctx = Context::builder().dir("/dev/shm/karyos").build()?;
//! let mut client = Client::connect(ctx)?;
//! let mut orders =
//!     client.add_exclusive_publication("karyos:ipc", StreamId::new(1001))?;
//! let _ = orders.offer(b"order")?;
//! let mut md = client.add_subscription("karyos:ipc", StreamId::new(2001))?;
//! md.poll(|payload, _info| drop(payload), MessageLimit::new(16))?;
//! client.poll();
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! A client has one of two connections:
//!
//! - **Remote** (`Client::connect`, Linux): it attaches to the driver
//!   whose admission socket is in the context's directory. Its streams are
//!   shared terms, `karyos:udp` ones included: the driver's network
//!   publications and images are regions the client fetches.
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
//! (`ImageAvailable`), each attached by its registration as it arrives
//! and dropped when it retires (`ImageUnavailable`), and polls them in
//! turn: a fan-in over every image of the stream, images of one alias
//! from several sources included (`quantstratum-docs:
//! karyos/design/per-source-images.md`, D2-4). Two images of one alias
//! share their session id, which is all a stop or a failed poll names of
//! its image. At most [`Context::max_images`] images are attached;
//! another is refused and counted ([`Subscription::images_refused`]),
//! never dropped silently.
//! [`Client::add_subscription`] takes a required reader that rejoins at
//! the head; [`Client::add_subscription_with`] names the role and rejoin
//! policy ([`SubscriptionOptions`]), which each image of a network
//! subscription takes too. Role and policy by URI are a follow-up.
//!
//! A lap of the client's broadcast receiver loses what was broadcast
//! meanwhile: the network subscriptions are then closed with
//! [`ClientError::EventsLost`], as their images can no longer be tracked,
//! and the answer to a control call waiting at that moment may be lost
//! too: the call then returns [`ClientError::Timeout`] or
//! [`ClientError::Unknown`], and the facade cannot release what it
//! granted, which stays held until the client leaves.
//! `ClientError::Attach` exists on Linux only, where remote clients do.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use karyos_protocol::cnc::{ErrorCode, Event, StreamId, StreamKey, SubscriberRole};
use karyos_sys::term_bytes::TermBytes;
use thiserror::Error;

use crate::concurrent::ClientConcurrentPublication;
use crate::conductor::{
    ClientConductor, Completion, ConductorError, ConductorPoll, EVENT_QUEUE, Outcome,
};
use crate::error::ClientError;
use crate::publication::ClientPublication;
use crate::subscription::{
    ClientSubscription, MessageInfo, MessageLimit, PollError, PollSummary, RejoinPolicy,
};

mod publish;

pub use publish::{Accepted, Claim, MessageLength, OfferError, Publication};

/// Default wait of a control call.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default most images a network subscription attaches at once.
pub const DEFAULT_MAX_IMAGES: usize = 8;

/// Default most requests in flight on a client's conductor.
pub const DEFAULT_MAX_PENDING: usize = 64;

/// How a subscription reads ([`Client::add_subscription_with`]): its
/// role and what follows an overrun. The default is what
/// [`Client::add_subscription`] takes: a required reader, rejoining at the
/// head.
#[derive(Debug)]
#[non_exhaustive]
pub struct SubscriptionOptions {
    /// Required (bounds its publisher, never lapped), optional or observer
    /// (lapped when behind; SPEC.md §4).
    pub role: SubscriberRole,
    /// What follows an overrun of an optional or observer reader; accepted
    /// and never used for a required one.
    pub rejoin: RejoinPolicy,
}

impl Default for SubscriptionOptions {
    /// A required reader that rejoins at the head.
    fn default() -> Self {
        Self::new(SubscriberRole::Required, RejoinPolicy::default())
    }
}

impl SubscriptionOptions {
    /// Options of `role` and `rejoin`.
    #[must_use]
    pub fn new(role: SubscriberRole, rejoin: RejoinPolicy) -> Self {
        Self { role, rejoin }
    }
}

/// How a control call waits between two services of its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

    /// The most requests in flight on the client's conductor.
    #[must_use]
    pub fn max_pending(&self) -> usize {
        self.max_pending
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
        // A network subscription queues three times as many image
        // changes: one adoption's retirements, arrivals and a close's
        // drain.
        if context.max_images.checked_mul(3).is_none() {
            return Err(ClientError::InvalidContext {
                reason: "too many images to queue their changes",
            });
        }
        Ok(context)
    }
}

/// A failed subscription poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct SubscriptionPoll {
    /// Messages delivered, over every image.
    pub delivered: u32,
    /// The first image whose poll reported more than deliveries (an
    /// overrun, an abort, a skip, a seal or a revocation).
    pub stopped: Option<ImageStop>,
    /// A handle stopped at its mapping's seal without moving to its
    /// successor ([`Subscription::poll_adopted`] only): adopt, then poll
    /// again.
    pub stopped_at_seal: bool,
}

/// An image of a network subscription attached or retired, as
/// [`Subscription::image_changes`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageChange {
    /// The image's attach id: a session retired and announced again is
    /// another image.
    pub image_id: u64,
    /// Its session.
    pub session_id: i32,
    /// Its lane.
    pub lane: karyos_sys::frame::Lane,
    /// Attached (`true`) or retired (`false`).
    pub available: bool,
}

impl ImageChange {
    /// A change of image `image_id` of session `session_id` on `lane`:
    /// for sources other than a client's, and tests.
    #[must_use]
    pub const fn new(
        image_id: u64,
        session_id: i32,
        lane: karyos_sys::frame::Lane,
        available: bool,
    ) -> Self {
        Self {
            image_id,
            session_id,
            lane,
            available,
        }
    }
}

/// An image's poll that reported more than deliveries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageStop {
    /// The image's session id, for a network subscription.
    pub session_id: Option<i32>,
    /// The image's lane, for a network subscription.
    pub lane: Option<karyos_sys::frame::Lane>,
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
    fn add_network_concurrent_publication(
        &mut self,
        uri: &str,
        stream_id: i32,
    ) -> Result<u64, ConductorError>;

    #[doc(hidden)]
    fn add_network_subscription(
        &mut self,
        uri: &str,
        stream_id: i32,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError>;

    #[doc(hidden)]
    fn add_subscription(
        &mut self,
        stream: StreamKey,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError>;

    /// Attaches to lane 0 of the image `image` of the alias `stream`
    /// (`quantstratum-docs: karyos/design/per-source-images.md`, D2-5).
    #[doc(hidden)]
    fn add_image_subscription(
        &mut self,
        stream: StreamKey,
        image: u64,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError>;

    #[doc(hidden)]
    fn add_publication_on_lane(
        &mut self,
        stream: StreamKey,
        lane: karyos_sys::frame::Lane,
    ) -> Result<u64, ConductorError>;

    /// Releases a publication handle the facade will not hand out: asks
    /// the driver to remove it, and returns whether that was sent. A
    /// removal that cannot be sent now (the command ring full, a handle
    /// this connection did not issue, a closed link) drops the handle
    /// instead: in process that ends its lease; for a remote client it
    /// detaches its export, and the driver keeps the publication, with no
    /// EOS, until the client ends. The facade counts these
    /// ([`Client::publication_releases_failed`]).
    #[doc(hidden)]
    fn release_publication(&mut self, publication: ClientPublication<Self::Terms>) -> bool;

    /// Releases a concurrent handle, as `release_publication` does an
    /// exclusive one: whether the removal was submitted.
    #[doc(hidden)]
    fn release_concurrent_publication(
        &mut self,
        publication: ClientConcurrentPublication<Self::Terms>,
    ) -> bool;

    #[doc(hidden)]
    fn remove_network_subscription(&mut self, registration: u64) -> Result<u64, ConductorError>;

    /// Releases an image's subscription handle the facade no longer reads:
    /// it is removed, so the driver forgets its registration; whether the
    /// removal was submitted. One that cannot be removed now is dropped:
    /// in process that ends its lease; for a remote client it detaches its
    /// export, and the registration stays until the client ends.
    #[doc(hidden)]
    fn release_subscription(&mut self, subscription: ClientSubscription<Self::Terms>) -> bool;

    #[doc(hidden)]
    fn poll_into(&mut self, limit: usize, completions: &mut Vec<Completion>) -> ConductorPoll;

    #[doc(hidden)]
    fn events_into(&mut self, events: &mut Vec<Event>);

    #[doc(hidden)]
    fn events_dropped(&self) -> u64;

    #[doc(hidden)]
    fn laps(&self) -> u64;

    #[doc(hidden)]
    fn publication(&self, outcome: Outcome) -> Result<ClientPublication<Self::Terms>, ClientError>;

    #[doc(hidden)]
    fn concurrent_publication(
        &self,
        outcome: Outcome,
    ) -> Result<ClientConcurrentPublication<Self::Terms>, ClientError>;

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

    fn add_network_concurrent_publication(
        &mut self,
        uri: &str,
        stream_id: i32,
    ) -> Result<u64, ConductorError> {
        ClientConductor::add_network_concurrent_publication(self, uri, stream_id, false)
    }

    fn add_network_subscription(
        &mut self,
        uri: &str,
        stream_id: i32,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        ClientConductor::add_network_subscription(self, uri, stream_id, role)
    }

    fn add_subscription(
        &mut self,
        stream: StreamKey,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        ClientConductor::add_subscription(self, stream, role)
    }

    fn add_image_subscription(
        &mut self,
        stream: StreamKey,
        image: u64,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        ClientConductor::add_image_subscription(
            self,
            stream,
            image,
            karyos_sys::frame::Lane::ZERO,
            role,
        )
    }

    fn add_publication_on_lane(
        &mut self,
        stream: StreamKey,
        lane: karyos_sys::frame::Lane,
    ) -> Result<u64, ConductorError> {
        ClientConductor::add_publication_on_lane(self, stream, lane, false)
    }

    fn release_publication(&mut self, publication: ClientPublication<Self::Terms>) -> bool {
        // A handle that cannot be removed now is dropped, ending its lease.
        self.remove_publication(publication).is_ok()
    }

    fn release_concurrent_publication(
        &mut self,
        publication: ClientConcurrentPublication<Self::Terms>,
    ) -> bool {
        // A handle that cannot be removed now is dropped, ending its lease.
        self.remove_concurrent_publication(publication).is_ok()
    }

    fn release_subscription(&mut self, subscription: ClientSubscription<Self::Terms>) -> bool {
        // A handle that cannot be removed now is dropped, ending its lease.
        self.remove_subscription(subscription).is_ok()
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

    fn laps(&self) -> u64 {
        ClientConductor::laps(self)
    }

    fn publication(&self, outcome: Outcome) -> Result<ClientPublication<Self::Terms>, ClientError> {
        match outcome {
            Outcome::Publication(publication) => Ok(publication),
            other => Err(refusal(&other)),
        }
    }

    fn concurrent_publication(
        &self,
        outcome: Outcome,
    ) -> Result<ClientConcurrentPublication<Self::Terms>, ClientError> {
        match outcome {
            Outcome::ConcurrentPublication(publication) => Ok(publication),
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
            Outcome::ConcurrentPublication(publication) => {
                self.remove_concurrent_publication(publication).is_ok()
            }
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

    fn add_network_concurrent_publication(
        &mut self,
        uri: &str,
        stream_id: i32,
    ) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::add_network_concurrent_publication(self, uri, stream_id, false)
    }

    fn add_network_subscription(
        &mut self,
        uri: &str,
        stream_id: i32,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::add_network_subscription(self, uri, stream_id, role)
    }

    fn add_subscription(
        &mut self,
        stream: StreamKey,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::add_subscription(self, stream, role)
    }

    fn add_image_subscription(
        &mut self,
        stream: StreamKey,
        image: u64,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::add_image_subscription(self, stream, image, role)
    }

    fn add_publication_on_lane(
        &mut self,
        stream: StreamKey,
        lane: karyos_sys::frame::Lane,
    ) -> Result<u64, ConductorError> {
        crate::ipc::RemoteClient::add_publication_on_lane(self, stream, lane, false)
    }

    fn release_publication(&mut self, publication: ClientPublication<Self::Terms>) -> bool {
        // A handle that cannot be removed now is dropped: it detaches its
        // export, and its registration ends with the client.
        crate::ipc::RemoteClient::remove_publication(self, publication).is_ok()
    }

    fn release_concurrent_publication(
        &mut self,
        publication: ClientConcurrentPublication<Self::Terms>,
    ) -> bool {
        // As an exclusive handle: one that cannot be removed now is
        // dropped, and its registration ends with the client.
        crate::ipc::RemoteClient::remove_concurrent_publication(self, publication).is_ok()
    }

    fn release_subscription(&mut self, subscription: ClientSubscription<Self::Terms>) -> bool {
        // A handle that cannot be removed now is dropped: it detaches its
        // export, and its registration ends with the client.
        crate::ipc::RemoteClient::remove_subscription(self, subscription).is_ok()
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

    fn laps(&self) -> u64 {
        crate::ipc::RemoteClient::laps(self)
    }

    fn publication(&self, outcome: Outcome) -> Result<ClientPublication<Self::Terms>, ClientError> {
        match outcome {
            Outcome::Fetchable(fetchable) => Ok(self.take_publication(&fetchable)?),
            other => Err(refusal(&other)),
        }
    }

    fn concurrent_publication(
        &self,
        outcome: Outcome,
    ) -> Result<ClientConcurrentPublication<Self::Terms>, ClientError> {
        match outcome {
            Outcome::Fetchable(fetchable) => Ok(self.take_concurrent_publication(&fetchable)?),
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
            // Taken, then released: a publication is removed, as a
            // released one is; a subscription is dropped, which detaches
            // its export and ends its registration.
            Outcome::Fetchable(fetchable) => match fetchable.request {
                crate::conductor::Request::Publication { .. } => {
                    match self.take_publication(&fetchable) {
                        Ok(publication) => {
                            // Released either way: removed, or dropped
                            // until the client ends (`release_publication`).
                            let _ = self.release_publication(publication);
                            true
                        }
                        Err(_) => false,
                    }
                }
                // Taken and dropped: it detaches its export, and its
                // registration ends with the client.
                crate::conductor::Request::ConcurrentPublication { .. } => {
                    self.take_concurrent_publication(&fetchable).is_ok()
                }
                crate::conductor::Request::Subscription { .. } => {
                    match self.take_subscription(&fetchable) {
                        Ok(subscription) => {
                            // Released either way, as a publication is.
                            let _ = self.release_subscription(subscription);
                            true
                        }
                        Err(_) => false,
                    }
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
    /// Images attached and not yet taken, by attach id.
    arrived: Vec<Image<T>>,
    /// Attach ids of taken images retired since. With `arrived`, at most
    /// one entry per slot, so both stay within `max_images`.
    retired: Vec<u64>,
    /// Why the subscription is closed.
    closed: Option<ClientError>,
    /// Images refused: beyond the bound, or their attach failed.
    refused: u64,
}

/// An attached image: its attach id (the request sequence), its session
/// and its subscription.
#[derive(Debug)]
struct Image<T: TermBytes> {
    id: u64,
    session_id: i32,
    /// Its lane, read when it was attached.
    lane: karyos_sys::frame::Lane,
    subscription: ClientSubscription<T>,
}

impl<T: TermBytes> Inbox<T> {
    fn new(max_images: usize) -> Self {
        Self {
            changed: AtomicBool::new(false),
            state: Mutex::new(InboxState {
                arrived: Vec::with_capacity(max_images),
                retired: Vec::with_capacity(max_images),
                closed: None,
                refused: 0,
            }),
        }
    }

    /// Retires the image `id`: one not taken yet is returned, for the
    /// client to release; a taken one is released by its subscription.
    fn retire(&self, id: u64) -> Option<ClientSubscription<T>> {
        let mut removed = None;
        self.update(|state| {
            if let Some(index) = state.arrived.iter().position(|image| image.id == id) {
                removed = Some(state.arrived.swap_remove(index));
            } else {
                state.retired.push(id);
            }
        });
        removed.map(|image| image.subscription)
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
    /// The image handles its subscription let go of, for the client to
    /// release; it outlives the subscription, so a dropped one's images
    /// are released too.
    released: Released<T>,
    /// The images holding a slot, attached or being attached: at most
    /// `max_images`. A refused image holds none.
    slots: Vec<Slot>,
    /// Closed (events were lost): its events are ignored.
    closed: bool,
    /// The subscription's role, which each image takes.
    role: SubscriberRole,
    /// The subscription's rejoin policy, a copy of which each image takes
    /// ([`RejoinPolicy::duplicate`]).
    rejoin: RejoinPolicy,
}

/// An image holding a slot of its network subscription.
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// The attach request's sequence: the image's id.
    id: u64,
    /// The image's aggregate registration, which names it in the driver's
    /// events (per-source-images.md, D2-5).
    image: u64,
    session_id: i32,
    /// Its grant arrived and was handed to the subscription.
    attached: bool,
}

/// An image attach in flight.
#[derive(Debug, Clone, Copy)]
struct Attach {
    sequence: u64,
    registration: u64,
    /// Its image retired first: the grant is released.
    cancelled: bool,
}

/// The image handles a network subscription let go of: at most
/// `max_images` at a time, since each held a slot.
type Released<T> = Arc<Mutex<Vec<ClientSubscription<T>>>>;

/// What a waited request found.
enum Found<T: TermBytes> {
    Outcome(Box<Outcome>),
    Network(u64, Arc<Inbox<T>>, Released<T>),
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
    /// The connection's broadcast laps seen so far.
    laps: u64,
    /// Late grants released after their request timed out.
    late_released: u64,
    /// Publication handles released whose removal could not be sent.
    releases_failed: u64,
    /// Subscription handles released whose removal could not be sent.
    subscription_releases_failed: u64,
    completions: Vec<Completion>,
    events: Vec<Event>,
    /// The role and rejoin policy of the network subscription being added,
    /// which its record takes when its grant arrives, before the events
    /// that announce its first images.
    adding: Option<(SubscriberRole, RejoinPolicy)>,
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
        let laps = connection.laps();
        // Every attach is a request in flight: at most max_pending.
        let attaches = Vec::with_capacity(context.max_pending);
        Self {
            connection,
            context,
            networks: Vec::new(),
            attaches,
            removals: Vec::new(),
            events_dropped,
            laps,
            late_released: 0,
            releases_failed: 0,
            subscription_releases_failed: 0,
            completions: Vec::new(),
            events: Vec::new(),
            adding: None,
        }
    }

    /// Grants that arrived after their request timed out, released at
    /// once (the handle dropped, or the network subscription removed).
    #[must_use]
    pub fn late_grants_released(&self) -> u64 {
        self.late_released
    }

    /// Publication handles released ([`Client::remove_publication`], or a
    /// lane given back when a publication was refused) whose removal could
    /// not be sent: the handle was dropped instead, so the driver keeps the
    /// publication until its lease ends (in process) or the client ends
    /// (remote), with no EOS. Sticky at `u64::MAX`.
    #[must_use]
    pub fn publication_releases_failed(&self) -> u64 {
        self.releases_failed
    }

    /// Subscription handles released ([`Client::remove_subscription`], or
    /// an image's handle let go of) whose removal could not be sent: the
    /// handle was dropped instead. In process its lease ends; for a remote
    /// client its export is detached, and the driver reclaims the
    /// registration once its last grant ends. Sticky at `u64::MAX`.
    #[must_use]
    pub fn subscription_releases_failed(&self) -> u64 {
        self.subscription_releases_failed
    }

    /// The exclusive publication of `stream_id` on the channel `uri`: a
    /// `karyos:ipc` URI names the only stream of the id, a `karyos:udp`
    /// one creates a network publication. Offers are refused while no
    /// subscriber is connected.
    ///
    /// It holds every lane, all or nothing. A URI that names `lanes` takes
    /// exactly that many: the driver refuses a count other than the
    /// stream's with `LaneMismatch` before granting anything, so the
    /// publication can be asked for again. A lane refused or timed out
    /// after lane 0 releases the lanes granted, but the stream's exclusive
    /// publication is granted once per incarnation: it cannot be taken
    /// again until the stream is configured anew.
    /// A URI that names none takes the lanes the stream configures, which
    /// the facade does not know (a driver's default, an IPC aggregate's
    /// configuration): lanes are taken until the driver refuses one with
    /// `UnknownStream`.
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
    ) -> Result<Publication<C::Terms>, ClientError> {
        let sequence = self
            .connection
            .add_network_publication(uri, stream_id.get())?;
        let first = match self.wait(sequence)? {
            Found::Outcome(outcome) => self.connection.publication(*outcome)?,
            Found::Network(..) => return Err(ClientError::Unknown),
        };
        // The URI's lane count when it names one; it parsed when the
        // request was submitted.
        let named = karyos_protocol::channel::ChannelConfig::parse(uri)
            .ok()
            .and_then(|channel| channel.common.lanes);
        let count = named.unwrap_or(karyos_sys::frame::Lane::COUNT);
        let stream = first.stream();
        let mut lanes = vec![first];
        for index in 1..count {
            let refused = match karyos_sys::frame::Lane::try_new(index) {
                Ok(lane) => match self.lane_grant(stream, lane) {
                    Ok(Some(publication)) => {
                        lanes.push(publication);
                        continue;
                    }
                    // The stream configures no more lanes: the end of an
                    // unnamed count, a refusal of a named one.
                    Ok(None) if named.is_none() => break,
                    // The driver checks a named count against the stream
                    // before lane 0 (LaneMismatch); this is a stream that
                    // changed meanwhile. The detail is the stream id, as
                    // the driver's.
                    Ok(None) => ClientError::Refused {
                        code: ErrorCode::UnknownStream,
                        detail: u64::from(stream.stream_id.cast_unsigned()),
                    },
                    Err(error) => error,
                },
                Err(_) => ClientError::Unknown,
            };
            for publication in lanes {
                if !self.connection.release_publication(publication) {
                    bump(&mut self.releases_failed);
                }
            }
            return Err(refused);
        }
        Ok(Publication::new(lanes))
    }

    /// A concurrent publication of `stream_id` on the `karyos:ipc` channel
    /// `uri`: a handle on lane 0 of the only stream of the id, shared with
    /// its other publishers (SPEC §4, concurrent publication; M11). The
    /// stream must be configured concurrent: the driver refuses an
    /// exclusive one with `InvalidPublicationMode`, and a `karyos:udp`
    /// channel with `UnsupportedChannel`, as a network publication is
    /// exclusive. Offers are refused while no subscriber is connected.
    ///
    /// # Errors
    ///
    /// As [`Client::add_exclusive_publication`].
    pub fn add_concurrent_publication(
        &mut self,
        uri: &str,
        stream_id: StreamId,
    ) -> Result<ClientConcurrentPublication<C::Terms>, ClientError> {
        let sequence = self
            .connection
            .add_network_concurrent_publication(uri, stream_id.get())?;
        match self.wait(sequence)? {
            Found::Outcome(outcome) => self.connection.concurrent_publication(*outcome),
            Found::Network(..) => Err(ClientError::Unknown),
        }
    }

    /// The exclusive publication of `lane` of `stream`; `None` when the
    /// stream does not configure the lane.
    fn lane_grant(
        &mut self,
        stream: StreamKey,
        lane: karyos_sys::frame::Lane,
    ) -> Result<Option<ClientPublication<C::Terms>>, ClientError> {
        let sequence = self.connection.add_publication_on_lane(stream, lane)?;
        match self.wait(sequence)? {
            Found::Outcome(outcome) => match *outcome {
                Outcome::Refused {
                    code: ErrorCode::UnknownStream,
                    ..
                } => Ok(None),
                other => self.connection.publication(other).map(Some),
            },
            Found::Network(..) => Err(ClientError::Unknown),
        }
    }

    /// Releases `publication`'s handles, as dropping it does not remove
    /// them from the driver at once.
    ///
    /// ```no_run
    /// # #[cfg(target_os = "linux")]
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use karyos_client::{Client, Context, StreamId};
    ///
    /// let mut client = Client::connect(Context::builder().dir("/dev/shm/karyos").build()?)?;
    /// let orders = client.add_exclusive_publication("karyos:ipc", StreamId::new(1001))?;
    /// client.remove_publication(orders);
    /// # Ok(())
    /// # }
    /// # #[cfg(not(target_os = "linux"))]
    /// # fn main() {}
    /// ```
    pub fn remove_publication(&mut self, publication: Publication<C::Terms>) {
        for lane in publication.into_lanes() {
            if !self.connection.release_publication(lane) {
                bump(&mut self.releases_failed);
            }
        }
    }

    /// Removes a concurrent handle this client took
    /// ([`Client::add_concurrent_publication`]), as
    /// [`Client::remove_publication`] does an exclusive publication: the
    /// driver frees its publisher slot, so the stream's `publishers` bound
    /// counts it no more. A removal that cannot be sent drops the handle
    /// instead and is counted ([`Client::publication_releases_failed`]):
    /// in process its lease ends; for a remote client the slot is held
    /// until the client ends.
    pub fn remove_concurrent_publication(
        &mut self,
        publication: ClientConcurrentPublication<C::Terms>,
    ) {
        if !self.connection.release_concurrent_publication(publication) {
            bump(&mut self.releases_failed);
        }
    }

    /// Removes a subscription this client handed out, as
    /// [`Client::remove_publication`] does a publication: a `karyos:ipc`
    /// one is removed at the driver; a `karyos:udp` one releases every
    /// image it reads, and its network subscription is removed. A removal
    /// that cannot be sent drops the handle instead and is counted
    /// ([`Client::subscription_releases_failed`]). Dropping a subscription
    /// without this ends it too: in process its lease ends, and for a
    /// remote client the driver reclaims its registration once its grant
    /// is detached.
    pub fn remove_subscription(&mut self, subscription: Subscription<C::Terms>) {
        match subscription.kind {
            Kind::Stream(subscription) => {
                if !self.connection.release_subscription(*subscription) {
                    bump(&mut self.subscription_releases_failed);
                }
            }
            // Its images go to the client's release bin as it drops.
            Kind::Images(images) => drop(images),
        }
        self.remove_dropped();
    }

    /// A subscription of `stream_id` on the channel `uri`: a `karyos:ipc`
    /// URI reads the only stream of the id, a `karyos:udp` one the images
    /// of a network subscription (see the module docs). A required reader
    /// that rejoins at the head ([`SubscriptionOptions::default`]).
    ///
    /// # Errors
    ///
    /// As [`Client::add_exclusive_publication`].
    pub fn add_subscription(
        &mut self,
        uri: &str,
        stream_id: StreamId,
    ) -> Result<Subscription<C::Terms>, ClientError> {
        self.add_subscription_with(uri, stream_id, SubscriptionOptions::default())
    }

    /// As [`Client::add_subscription`], with the reader's role and rejoin
    /// policy (`quantstratum-docs: karyos/design/rejoin-policies.md`). Each
    /// image of a network subscription takes the role and a copy of the
    /// policy; a snapshot policy serves one stream, so a network
    /// subscription refuses it.
    ///
    /// # Errors
    ///
    /// As [`Client::add_exclusive_publication`];
    /// [`ClientError::InvalidContext`] for a snapshot policy (or a replay
    /// whose secondary is one) on a `karyos:udp` URI, before anything is
    /// requested.
    pub fn add_subscription_with(
        &mut self,
        uri: &str,
        stream_id: StreamId,
        options: SubscriptionOptions,
    ) -> Result<Subscription<C::Terms>, ClientError> {
        let SubscriptionOptions { role, rejoin } = options;
        let network = uri.starts_with("karyos:udp");
        if network && rejoin.duplicate().is_none() {
            return Err(ClientError::InvalidContext {
                reason: "a snapshot rejoin serves one stream, not a network subscription's images",
            });
        }
        // The context's build checked it.
        let max_changes =
            self.context
                .max_images
                .checked_mul(3)
                .ok_or(ClientError::InvalidContext {
                    reason: "too many images to queue their changes",
                })?;
        let sequence = self
            .connection
            .add_network_subscription(uri, stream_id.get(), role)?;
        // A network grant's record takes the role and policy when the grant
        // arrives (`found`), before the events announcing its images; a
        // stream subscription takes the policy back here.
        self.adding = Some((role, rejoin));
        let found = self.wait(sequence);
        let unclaimed = self.adding.take();
        match found? {
            Found::Outcome(outcome) => {
                let subscription = self.connection.subscription(*outcome)?;
                let subscription = match unclaimed {
                    Some((_, rejoin)) => subscription.with_rejoin(rejoin),
                    None => subscription,
                };
                Ok(Subscription {
                    kind: Kind::Stream(Box::new(subscription)),
                })
            }
            Found::Network(registration, inbox, released) => Ok(Subscription {
                kind: Kind::Images(Images {
                    registration,
                    inbox,
                    released,
                    images: Vec::with_capacity(self.context.max_images),
                    next: 0,
                    closed: None,
                    changes: std::collections::VecDeque::with_capacity(max_changes),
                    max_changes,
                    changes_lost: 0,
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
        // it is taken. Losses show as laps, checked below.
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
        // A lap lost what was broadcast meanwhile, image events included:
        // no network subscription can know its images any more.
        let (dropped, laps) = (self.connection.events_dropped(), self.connection.laps());
        if dropped != self.events_dropped || laps != self.laps {
            self.events_dropped = dropped;
            self.laps = laps;
            for network in &mut self.networks {
                network.closed = true;
                network.slots.clear();
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
                let inbox = Arc::new(Inbox::new(self.context.max_images));
                let released = Arc::new(Mutex::new(Vec::with_capacity(self.context.max_images)));
                let (role, rejoin) = self
                    .adding
                    .take()
                    .unwrap_or((SubscriberRole::Required, RejoinPolicy::default()));
                self.networks.push(Network {
                    registration,
                    inbox: Arc::downgrade(&inbox),
                    released: Arc::clone(&released),
                    slots: Vec::with_capacity(self.context.max_images),
                    closed: false,
                    role,
                    rejoin,
                });
                Found::Network(registration, inbox, released)
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
        let network = self
            .networks
            .iter_mut()
            .find(|network| network.registration == attach.registration);
        let inbox = network.as_ref().and_then(|network| network.inbox.upgrade());
        let (Some(network), Some(inbox), false) = (network, inbox, attach.cancelled) else {
            // Its image retired first, or its subscription is gone: the
            // grant is released, its slot already free.
            let _ = self.connection.release(completion.outcome);
            return;
        };
        let Some(slot) = network
            .slots
            .iter_mut()
            .find(|slot| slot.id == attach.sequence)
        else {
            let _ = self.connection.release(completion.outcome);
            return;
        };
        match self.connection.subscription(completion.outcome) {
            Ok(subscription) => {
                slot.attached = true;
                // Each image takes a copy of its subscription's policy; the
                // add refused a policy that cannot be copied.
                let subscription = match network.rejoin.duplicate() {
                    Some(rejoin) => subscription.with_rejoin(rejoin),
                    None => subscription,
                };
                // A subscription just attached is open, so it names its
                // lane; one that does not is refused as a failed attach,
                // never given a lane it does not read.
                let Some(lane) = subscription.lane() else {
                    let _ = self.connection.release_subscription(subscription);
                    network.slots.retain(|slot| slot.id != attach.sequence);
                    inbox.update(|state| bump(&mut state.refused));
                    return;
                };
                let image = Image {
                    id: slot.id,
                    session_id: slot.session_id,
                    lane,
                    subscription,
                };
                inbox.update(|state| state.arrived.push(image));
            }
            Err(_) => {
                network.slots.retain(|slot| slot.id != attach.sequence);
                inbox.update(|state| bump(&mut state.refused));
            }
        }
    }

    fn event(&mut self, event: Event) {
        match event {
            Event::ImageAvailable {
                stream,
                registration,
                image,
                ..
            } => self.image_available(stream, registration, image),
            Event::ImageUnavailable {
                registration,
                image,
                ..
            } => self.image_unavailable(registration, image),
            _ => {}
        }
    }

    fn image_available(&mut self, stream: StreamKey, registration: u64, image: u64) {
        let Some(network) = self
            .networks
            .iter_mut()
            .find(|network| network.registration == registration && !network.closed)
        else {
            return;
        };
        let Some(inbox) = network.inbox.upgrade() else {
            return;
        };
        // An image already holding a slot is not attached twice. Images
        // are told apart by registration: two sources may share an alias.
        if network.slots.iter().any(|slot| slot.image == image) {
            return;
        }
        if network.slots.len() >= self.context.max_images {
            inbox.update(|state| bump(&mut state.refused));
            return;
        }
        match self
            .connection
            .add_image_subscription(stream, image, network.role)
        {
            Ok(sequence) => {
                network.slots.push(Slot {
                    id: sequence,
                    image,
                    session_id: stream.session_id,
                    attached: false,
                });
                self.attaches.push(Attach {
                    sequence,
                    registration,
                    cancelled: false,
                });
            }
            Err(_) => inbox.update(|state| bump(&mut state.refused)),
        }
    }

    fn image_unavailable(&mut self, registration: u64, image: u64) {
        let Some(network) = self
            .networks
            .iter_mut()
            .find(|network| network.registration == registration && !network.closed)
        else {
            return;
        };
        // Only an image holding a slot frees one; a refused one held none.
        let Some(index) = network.slots.iter().position(|slot| slot.image == image) else {
            return;
        };
        let slot = network.slots.swap_remove(index);
        if slot.attached {
            // Released outside the inbox's lock: removing a subscription
            // ends its lease, which the subscription's own poll must never
            // wait behind.
            if let Some(subscription) = network
                .inbox
                .upgrade()
                .and_then(|inbox| inbox.retire(slot.id))
                && !self.connection.release_subscription(subscription)
            {
                bump(&mut self.subscription_releases_failed);
            }
        } else if let Some(attach) = self
            .attaches
            .iter_mut()
            .find(|attach| attach.sequence == slot.id)
        {
            attach.cancelled = true;
        }
    }

    /// Releases the image handles the subscriptions let go of, then removes
    /// the network subscriptions whose handle was dropped.
    fn remove_dropped(&mut self) {
        for network in &self.networks {
            let released = core::mem::take(
                &mut *network
                    .released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            for subscription in released {
                if !self.connection.release_subscription(subscription) {
                    bump(&mut self.subscription_releases_failed);
                }
            }
        }
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

impl<T: TermBytes> Drop for Images<T> {
    /// The images still read go to the client to release with the
    /// network subscription.
    fn drop(&mut self) {
        let images = core::mem::take(&mut self.images);
        self.release(images);
        let arrived = core::mem::take(
            &mut self
                .inbox
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .arrived,
        );
        self.release(arrived);
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
    /// Where it hands the image handles it lets go of to the client.
    released: Released<T>,
    /// Reserved for `max_images`: adopting never reallocates.
    images: Vec<Image<T>>,
    /// The image the next poll starts at.
    next: usize,
    closed: Option<ClientError>,
    /// The image changes not yet drained, oldest first, at most
    /// `max_changes`. Full, the oldest goes.
    changes: std::collections::VecDeque<ImageChange>,
    /// `3 * max_images`, which bounds one adoption: retirements, arrivals
    /// and, with a close, every image left. The queue was reserved to it
    /// (its capacity may be larger; this is the bound).
    max_changes: usize,
    /// The changes dropped from a full queue.
    changes_lost: u64,
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

    /// Presents to `each`, oldest first, the images attached and retired
    /// since the last call, and forgets them: a network subscription's
    /// images as it adopts them, each with its attach id. Nothing for a
    /// stream. It allocates nothing; changes beyond the queue's room
    /// (three times [`Context::max_images`]) drop the oldest, counted by
    /// [`Subscription::image_changes_lost`].
    pub fn image_changes(&mut self, each: &mut dyn FnMut(ImageChange)) {
        while let Some(change) = self.next_image_change() {
            each(change);
        }
    }

    /// The oldest image change not yet drained, taken: one at a time, as
    /// [`Subscription::image_changes`] gives them all. `None` for a
    /// stream or once none is left.
    pub fn next_image_change(&mut self) -> Option<ImageChange> {
        match &mut self.kind {
            Kind::Stream(_) => None,
            Kind::Images(images) => {
                images.adopt();
                images.changes.pop_front()
            }
        }
    }

    /// Image changes dropped from a full queue before they were drained;
    /// it holds at `u64::MAX`.
    #[must_use]
    pub fn image_changes_lost(&self) -> u64 {
        match &self.kind {
            Kind::Stream(_) => 0,
            Kind::Images(images) => images.changes_lost,
        }
    }

    /// [`Subscription::poll`], with a handler that may decline a message,
    /// as [`ClientSubscription::poll_taking`]: the poll stops there, and a
    /// required reader's message waits for the next poll, which starts at
    /// that image. What the earlier images delivered stays taken.
    ///
    /// # Errors
    ///
    /// As [`Subscription::poll`].
    #[expect(
        clippy::result_large_err,
        reason = "the error carries the image's poll error by value, as ClientSubscription::poll does, so a failed poll reports its progress"
    )]
    pub fn poll_taking<H>(
        &mut self,
        mut handler: H,
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError>
    where
        H: FnMut(&[u8], MessageInfo) -> bool,
    {
        match &mut self.kind {
            Kind::Stream(subscription) => match subscription.poll_taking(&mut handler, limit) {
                Ok(summary) => Ok(SubscriptionPoll {
                    delivered: summary.delivered,
                    stopped_at_seal: summary.stopped_at_seal,
                    stopped: stopped(&summary).then_some(ImageStop {
                        session_id: None,
                        lane: None,
                        summary,
                    }),
                }),
                Err(error) => Err(SubscriptionError::Poll {
                    session_id: None,
                    delivered: error.summary.delivered,
                    error,
                }),
            },
            Kind::Images(images) => images.poll_taking(&mut handler, limit),
        }
    }

    /// Delivers at most `limit` messages in all to `handler`. A network
    /// subscription polls its images in turn, starting after the image the
    /// last poll ended at, so none starves. It first adopts the images that
    /// have arrived, and moves to a successor mapping at a seal within the
    /// poll.
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
        handler: H,
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        self.poll_with(handler, limit, false)
    }

    /// Adopts what the subscription's handles have been offered since the
    /// last adoption: for a network subscription, the images its client has
    /// attached or retired (as every [`Subscription::poll`] does first),
    /// whose changes queue for [`Subscription::next_image_change`]; and for
    /// every handle that [`Subscription::poll_adopted`] left at a mapping's
    /// seal, its successor mapping, when offered
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`). Never
    /// allocates.
    pub fn adopt(&mut self) {
        match &mut self.kind {
            Kind::Stream(subscription) => subscription.advance(),
            Kind::Images(images) => {
                images.adopt();
                for image in &mut images.images {
                    image.subscription.advance();
                }
            }
        }
    }

    /// The largest message the subscription can deliver: its stream's for
    /// a `karyos:ipc` subscription; for a network one, the largest of its
    /// adopted images', 0 with none. It changes only at an adoption
    /// ([`Subscription::adopt`]), so a caller that adopts, reads it and
    /// then polls with [`Subscription::poll_adopted`] never sees a larger
    /// message in that poll (quantstratum-docs:
    /// karyos/design/ffi-gap-analysis.md §4.4, the C ABI's private copy).
    #[must_use]
    pub fn max_message_length(&self) -> u32 {
        match &self.kind {
            Kind::Stream(subscription) => subscription.max_message_length(),
            Kind::Images(images) => images
                .images
                .iter()
                .map(|image| image.subscription.max_message_length())
                .max()
                .unwrap_or(0),
        }
    }

    /// [`Subscription::poll`] without adopting: it polls only the images
    /// already adopted and never moves to a successor mapping, so neither
    /// an image that arrives meanwhile nor a successor offered meanwhile
    /// is read before the next [`Subscription::adopt`]. A handle at the
    /// seal of a mapping with a successor stops there and sets
    /// `stopped_at_seal`: adopt, then poll again. The same handler and the
    /// same acknowledgement as [`Subscription::poll`]; no message is
    /// declined.
    ///
    /// # Errors
    ///
    /// As [`Subscription::poll`].
    #[expect(
        clippy::result_large_err,
        reason = "the error carries the image's poll error by value, as ClientSubscription::poll does, so a failed poll reports its progress"
    )]
    pub fn poll_adopted<H>(
        &mut self,
        handler: H,
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        self.poll_with(handler, limit, true)
    }

    /// The poll: with `hold`, [`Subscription::poll_adopted`]'s; otherwise
    /// [`Subscription::poll`]'s, which adopts first and moves.
    #[expect(
        clippy::result_large_err,
        reason = "the error carries the image's poll error by value, as ClientSubscription::poll does, so a failed poll reports its progress"
    )]
    fn poll_with<H>(
        &mut self,
        mut handler: H,
        limit: MessageLimit,
        hold: bool,
    ) -> Result<SubscriptionPoll, SubscriptionError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        match &mut self.kind {
            Kind::Stream(subscription) => match if hold {
                subscription.poll_holding(&mut handler, limit)
            } else {
                subscription.poll(&mut handler, limit)
            } {
                Ok(summary) => Ok(SubscriptionPoll {
                    delivered: summary.delivered,
                    stopped_at_seal: summary.stopped_at_seal,
                    stopped: stopped(&summary).then_some(ImageStop {
                        session_id: None,
                        lane: None,
                        summary,
                    }),
                }),
                Err(error) => Err(SubscriptionError::Poll {
                    session_id: None,
                    delivered: error.summary.delivered,
                    error,
                }),
            },
            Kind::Images(images) => {
                if !hold {
                    images.adopt();
                }
                images.poll(&mut handler, limit, hold)
            }
        }
    }
}

impl<T: TermBytes> Images<T> {
    /// Hands `images` to the client to release: removed there, so the
    /// driver forgets their registrations.
    fn release(&self, images: Vec<Image<T>>) {
        if images.is_empty() {
            return;
        }
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        released.extend(images.into_iter().map(|image| image.subscription));
    }

    /// Queues `image`'s change, dropping the oldest when full: never
    /// allocates.
    fn change(
        changes: &mut std::collections::VecDeque<ImageChange>,
        max: usize,
        lost: &mut u64,
        image: &Image<T>,
        available: bool,
    ) {
        if changes.len() >= max && changes.pop_front().is_some() {
            bump(lost);
        }
        if changes.len() < max {
            changes.push_back(ImageChange {
                image_id: image.id,
                session_id: image.session_id,
                lane: image.lane,
                available,
            });
        }
    }

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
        // Keyed by attach id: a session retired and announced again is a
        // new image, whatever the order of the two. What it lets go of goes
        // straight to the client's bin, reserved for `max_images`, so the
        // poll path allocates nothing.
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in state.retired.drain(..) {
            if let Some(index) = self.images.iter().position(|image| image.id == id) {
                let image = self.images.remove(index);
                Self::change(
                    &mut self.changes,
                    self.max_changes,
                    &mut self.changes_lost,
                    &image,
                    false,
                );
                released.push(image.subscription);
            }
        }
        for image in &state.arrived {
            Self::change(
                &mut self.changes,
                self.max_changes,
                &mut self.changes_lost,
                image,
                true,
            );
        }
        self.images.append(&mut state.arrived);
        if self.closed.is_none() {
            self.closed = state.closed;
        }
        drop(state);
        if self.closed.is_some() {
            for image in self.images.drain(..) {
                Self::change(
                    &mut self.changes,
                    self.max_changes,
                    &mut self.changes_lost,
                    &image,
                    false,
                );
                released.push(image.subscription);
            }
        }
        drop(released);
        if self.next >= self.images.len() {
            self.next = 0;
        }
    }

    /// Polls the adopted images; adopts none. With `hold`, an image at a
    /// seal does not move to its successor.
    #[expect(
        clippy::result_large_err,
        reason = "the error carries the image's poll error by value, as ClientSubscription::poll does, so a failed poll reports its progress"
    )]
    fn poll(
        &mut self,
        handler: &mut impl FnMut(&[u8], MessageInfo),
        limit: MessageLimit,
        hold: bool,
    ) -> Result<SubscriptionPoll, SubscriptionError> {
        self.poll_each(limit, |image, limit| {
            if hold {
                image.poll_holding(&mut *handler, limit)
            } else {
                image.poll(&mut *handler, limit)
            }
            .map(|summary| (summary, false))
        })
    }

    #[expect(
        clippy::result_large_err,
        reason = "the error carries the image's poll error by value, as ClientSubscription::poll does, so a failed poll reports its progress"
    )]
    fn poll_taking(
        &mut self,
        handler: &mut impl FnMut(&[u8], MessageInfo) -> bool,
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError> {
        self.adopt();
        self.poll_each(limit, |image, limit| {
            let mut declined = false;
            image
                .poll_taking(
                    |bytes, info| {
                        let taken = handler(bytes, info);
                        declined = !taken;
                        taken
                    },
                    limit,
                )
                .map(|summary| (summary, declined))
        })
    }

    /// Polls the images in turn under one `limit`, each by `poll`, which
    /// also reports whether the handler declined a message: the poll then
    /// stops, and the next starts at that image, whose message waits.
    #[expect(
        clippy::result_large_err,
        reason = "the error carries the image's poll error by value, as ClientSubscription::poll does, so a failed poll reports its progress"
    )]
    fn poll_each(
        &mut self,
        limit: MessageLimit,
        mut poll: impl FnMut(
            &mut ClientSubscription<T>,
            MessageLimit,
        ) -> Result<(PollSummary, bool), PollError>,
    ) -> Result<SubscriptionPoll, SubscriptionError> {
        // The callers adopt first, or not (`poll_adopted`).
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
            let Some(index) = start
                .checked_add(offset)
                .and_then(|index| index.checked_rem(count))
            else {
                break;
            };
            let Some(Image {
                session_id,
                lane,
                subscription: image,
                ..
            }) = self.images.get_mut(index)
            else {
                break;
            };
            self.next = index
                .checked_add(1)
                .and_then(|next| next.checked_rem(count))
                .unwrap_or(0);
            match poll(image, MessageLimit::new(remaining)) {
                Ok((summary, declined)) => {
                    // Within the limit, a u32.
                    if let Some(delivered) = result.delivered.checked_add(summary.delivered) {
                        result.delivered = delivered;
                    }
                    result.stopped_at_seal |= summary.stopped_at_seal;
                    if result.stopped.is_none() && stopped(&summary) {
                        result.stopped = Some(ImageStop {
                            session_id: Some(*session_id),
                            lane: Some(*lane),
                            summary,
                        });
                    }
                    if declined {
                        // The declined message is this image's next.
                        self.next = index;
                        break;
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

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig, Role};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    /// An image of attach id `id`, session `session`, over its own log.
    fn image(id: u64, session: i32) -> Image<karyos_sys::term_bytes::HeapTerms> {
        let buffer = Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 2,
                max_subscribers: 2,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: session,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
                schedule_capacity: 0,
            })
            .unwrap(),
        );
        let mut conductor = buffer.conductor_owned().unwrap();
        let subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
        Image {
            id,
            session_id: session,
            lane: Lane::ZERO,
            subscription,
        }
    }

    /// #440 review F1: one adoption's worst case, every image retired, as
    /// many arriving and a close draining them, is `3 * max_images`
    /// changes: all are queued, none lost.
    #[test]
    fn one_adoption_queues_every_change() {
        let max_images = 2;
        let inbox = Arc::new(Inbox::new(max_images));
        let mut images = Images {
            registration: 1,
            inbox: Arc::clone(&inbox),
            released: Arc::new(Mutex::new(Vec::with_capacity(4 * max_images))),
            images: Vec::with_capacity(max_images),
            next: 0,
            closed: None,
            changes: std::collections::VecDeque::with_capacity(3 * max_images),
            max_changes: 3 * max_images,
            changes_lost: 0,
        };
        images.images.push(image(1, 1));
        images.images.push(image(2, 2));
        inbox.update(|state| {
            state.retired.extend([1, 2]);
            state.arrived.push(image(3, 3));
            state.arrived.push(image(4, 4));
            state.closed = Some(ClientError::EmptyMessage);
        });
        images.adopt();
        let seen: Vec<(u64, bool)> = images
            .changes
            .iter()
            .map(|change| (change.image_id, change.available))
            .collect();
        assert_eq!(
            seen,
            [
                (1, false),
                (2, false),
                (3, true),
                (4, true),
                (3, false),
                (4, false)
            ]
        );
        assert_eq!(images.changes_lost, 0);
    }

    /// A network subscription of no image yet, and its client's inbox.
    fn network() -> (
        Subscription<karyos_sys::term_bytes::HeapTerms>,
        Arc<Inbox<karyos_sys::term_bytes::HeapTerms>>,
    ) {
        let inbox = Arc::new(Inbox::new(2));
        let subscription = Subscription {
            kind: Kind::Images(Images {
                registration: 1,
                inbox: Arc::clone(&inbox),
                released: Arc::new(Mutex::new(Vec::with_capacity(8))),
                images: Vec::with_capacity(2),
                next: 0,
                closed: None,
                changes: std::collections::VecDeque::with_capacity(6),
                max_changes: 6,
                changes_lost: 0,
            }),
        };
        (subscription, inbox)
    }

    /// Item 57 (FFI F4): an image that arrives between `adopt` and
    /// `poll_adopted` is not read by that poll, and its size does not count
    /// before it is adopted; the next adoption takes it.
    #[test]
    fn an_image_arriving_after_adopt_waits_for_the_next() {
        let (mut subscription, inbox) = network();
        subscription.adopt();
        assert_eq!(subscription.max_message_length(), 0);
        let arrived = image(1, 1);
        let max = arrived.subscription.max_message_length();
        inbox.update(|state| state.arrived.push(arrived));
        let poll = subscription
            .poll_adopted(|_, _| {}, MessageLimit::new(8))
            .unwrap();
        assert_eq!((poll.delivered, poll.stopped_at_seal), (0, false));
        assert_eq!(subscription.image_count(), 0, "not adopted by the poll");
        assert_eq!(subscription.max_message_length(), 0);
        subscription.adopt();
        assert_eq!(subscription.image_count(), 1);
        assert_eq!(subscription.max_message_length(), max);
    }

    /// Item 57 (FFI F4): an image's successor of a larger term, offered
    /// after `adopt`, is not read by `poll_adopted`, which stops at the
    /// seal; the next adoption moves the image, the largest message grows,
    /// and a message of exactly that length is delivered.
    #[test]
    fn an_image_successor_offered_after_adopt_waits_for_the_next() {
        let (mut subscription, _inbox) = network();
        let (held, mut later) = crate::subscription::testing::at_seal();
        if let Kind::Images(images) = &mut subscription.kind {
            images.images.push(Image {
                id: 1,
                session_id: 1,
                lane: Lane::ZERO,
                subscription: held,
            });
        }
        subscription.adopt();
        let before = subscription.max_message_length();
        let max = later.offer();
        let mut seen = Vec::new();
        let poll = subscription
            .poll_adopted(|bytes, _| seen.push(bytes.len()), MessageLimit::new(8))
            .unwrap();
        assert!(poll.stopped_at_seal);
        assert_eq!(poll.delivered, 0);
        assert_eq!(subscription.max_message_length(), before);
        subscription.adopt();
        assert_eq!(subscription.max_message_length(), max);
        let poll = subscription
            .poll_adopted(|bytes, _| seen.push(bytes.len()), MessageLimit::new(8))
            .unwrap();
        assert!(!poll.stopped_at_seal);
        assert_eq!(seen, [max as usize]);
    }

    /// DESIGN's P1 on #499, for an image: a fenced cutover of an image held
    /// at its seal is reported as that image's close by the next
    /// `poll_adopted` after an adoption, which no longer stops at the seal.
    #[test]
    fn an_image_whose_cutover_was_fenced_is_reported_closed() {
        let (mut subscription, _inbox) = network();
        let (held, later) = crate::subscription::testing::at_seal();
        if let Kind::Images(images) = &mut subscription.kind {
            images.images.push(Image {
                id: 1,
                session_id: 1,
                lane: Lane::ZERO,
                subscription: held,
            });
        }
        subscription.adopt();
        let poll = subscription
            .poll_adopted(|_, _| {}, MessageLimit::new(8))
            .unwrap();
        assert!(poll.stopped_at_seal);
        later.fence();
        subscription.adopt();
        let poll = subscription
            .poll_adopted(|_, _| {}, MessageLimit::new(8))
            .unwrap();
        assert!(!poll.stopped_at_seal);
        let stop = poll.stopped.unwrap();
        assert!(stop.summary.closed.is_some(), "{stop:?}");
    }
}
