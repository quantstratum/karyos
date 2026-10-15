// SPDX-License-Identifier: Apache-2.0

//! The client conductor (SPEC.md §3; quantstratum-docs: karyos/design/client-commands.md):
//! writes commands to the client's command ring, reads driver responses
//! from the broadcast buffer, and turns ready capabilities into handles.
//!
//! Requests are identified by a checked, never reused sequence. A request
//! whose response may have been lost (the receiver was lapped, the
//! broadcast closed or the driver dropped) completes as
//! [`Outcome::Unknown`], terminally: it is never retried automatically, and
//! a late response for it is ignored.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use karyos_protocol::cnc::ErrorCode;
use karyos_protocol::cnc::{
    Command, Event, MAX_COMMAND_LENGTH, Response, StreamKey, SubscriberRole,
};
use karyos_sys::broadcast::{BroadcastReceiver, Received};
use karyos_sys::command_ring::{RingError, RingProducer};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};
use thiserror::Error;

use crate::concurrent::ClientConcurrentPublication;
use crate::generation::GenerationLink;
use crate::link::{Capability, ClientLink, Origin, Owner};
use crate::publication::ClientPublication;
use crate::subscription::ClientSubscription;

/// Errors submitting a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConductorError {
    /// The command ring has no room; retry after the driver drains it.
    #[error("command ring full")]
    Full,
    /// The client or the driver is closed.
    #[error("client or driver closed")]
    Closed,
    /// The pending request limit is reached.
    #[error("too many pending requests")]
    TooManyPending,
    /// Request sequences are exhausted.
    #[error("request sequences exhausted")]
    SequencesExhausted,
    /// The handle was not issued through this conductor.
    #[error("the handle belongs to another client")]
    ForeignHandle,
}

/// How a request ended.
#[derive(Debug)]
pub enum Outcome<T: TermBytes = HeapTerms> {
    /// The publication, ready to offer.
    Publication(ClientPublication<T>),
    /// A concurrent publication handle, ready to offer.
    ConcurrentPublication(ClientConcurrentPublication<T>),
    /// The subscription, ready to poll.
    Subscription(ClientSubscription<T>),
    /// The command succeeded.
    Succeeded,
    /// The driver refused the command; it had no effect.
    Refused {
        /// Why.
        code: ErrorCode,
        /// A bounded detail value.
        detail: u64,
    },
    /// The response may have been lost; the command may or may not have
    /// taken effect. Terminal.
    Unknown,
}

impl<T: TermBytes> Outcome<T> {
    /// Attaches a generation link to a delivered handle. A base the handle
    /// refuses would be a driver defect: the handle is dropped and the
    /// outcome is not known.
    fn with_generation(self, link: Arc<GenerationLink<T>>, base: u64) -> Self {
        let attached = match self {
            Self::Publication(handle) => handle.with_generation(link, base).map(Self::Publication),
            Self::ConcurrentPublication(handle) => handle
                .with_generation(link, base)
                .map(Self::ConcurrentPublication),
            Self::Subscription(handle) => {
                handle.with_generation(link, base).map(Self::Subscription)
            }
            other => Ok(other),
        };
        attached.unwrap_or(Self::Unknown)
    }
}

/// A completed request.
#[derive(Debug)]
pub struct Completion<T: TermBytes = HeapTerms> {
    /// The request sequence returned when it was submitted.
    pub sequence: u64,
    /// How it ended.
    pub outcome: Outcome<T>,
}

/// What one [`ClientConductor::poll`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConductorPoll {
    /// Broadcast records read, including other clients' responses and lap
    /// reports.
    pub records: usize,
    /// Whether the poll observed `Pending`: a complete drain.
    pub drained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    AddPublication,
    AddConcurrentPublication,
    AddSubscription,
    Remove,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    sequence: u64,
    kind: Kind,
}

/// A client's conductor (not `Clone`). Dropping it closes the client: the
/// command ring producer is dropped first, then the close flag is set.
#[derive(Debug)]
pub struct ClientConductor<T: TermBytes = HeapTerms> {
    owner: Owner,
    producer: Option<RingProducer>,
    receiver: BroadcastReceiver,
    link: Arc<ClientLink<T>>,
    next_sequence: u64,
    pending: Vec<Pending>,
    /// Requests already terminalized as `Unknown` whose notification has
    /// not been delivered yet. A notification leaves this queue only after
    /// its callback returns, so a panicking callback loses none.
    unknown: VecDeque<u64>,
    max_pending: usize,
    /// Liveness (quantstratum-docs:
    /// `karyos/design/required-participant-loss.md`), on this client's own
    /// monotonic clock: how often it advances its heartbeat, and how long
    /// the driver's may stay unchanged before the driver is presumed lost.
    heartbeat_interval: Duration,
    driver_timeout: Duration,
    last_beat: Option<Instant>,
    /// The driver heartbeat last seen and when it was first seen.
    driver_seen: Option<(u64, Instant)>,
    driver_lost: bool,
    /// Driver events received and not yet taken, at most [`EVENT_QUEUE`].
    events: VecDeque<Event>,
    /// Events dropped because the queue was full.
    events_dropped: u64,
}

/// Driver events a client keeps until the application takes them.
pub const EVENT_QUEUE: usize = 64;

/// Default heartbeat interval of a client.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(100);
/// Default time a client waits for the driver's heartbeat to change.
pub const DEFAULT_DRIVER_TIMEOUT: Duration = Duration::from_secs(10);

impl<T: TermBytes> ClientConductor<T> {
    /// Creates the conductor for an admitted client (called by the driver,
    /// control path: allocates the pending list).
    #[must_use]
    pub fn new(
        owner: Owner,
        producer: RingProducer,
        receiver: BroadcastReceiver,
        link: Arc<ClientLink<T>>,
        max_pending: usize,
    ) -> Self {
        Self {
            owner,
            producer: Some(producer),
            receiver,
            link,
            next_sequence: 1,
            pending: Vec::with_capacity(max_pending),
            unknown: VecDeque::with_capacity(max_pending),
            max_pending,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            driver_timeout: DEFAULT_DRIVER_TIMEOUT,
            last_beat: None,
            driver_seen: None,
            driver_lost: false,
            events: VecDeque::with_capacity(EVENT_QUEUE),
            events_dropped: 0,
        }
    }

    /// Sets the heartbeat interval and the driver timeout, both on this
    /// client's own monotonic clock. A timeout shorter than ten intervals
    /// is raised to ten intervals.
    pub fn set_liveness(&mut self, heartbeat_interval: Duration, driver_timeout: Duration) {
        self.heartbeat_interval = heartbeat_interval;
        self.driver_timeout = driver_timeout.max(heartbeat_interval.saturating_mul(10));
    }

    /// Takes the driver events received by earlier polls, oldest first
    /// (quantstratum-docs: `karyos/design/required-participant-loss.md`,
    /// Reporting): every client sees every event, and filters by stream.
    pub fn take_events(&mut self) -> impl Iterator<Item = Event> + '_ {
        self.events.drain(..)
    }

    /// Events dropped because the application did not take them before
    /// [`EVENT_QUEUE`] more arrived.
    #[must_use]
    pub fn events_dropped(&self) -> u64 {
        self.events_dropped
    }

    /// Whether the driver's heartbeat stopped for the driver timeout: the
    /// client then refuses new requests and fails those pending, and keeps
    /// what it already holds until it is dropped.
    #[must_use]
    pub fn driver_lost(&self) -> bool {
        self.driver_lost
    }

    /// Advances this client's heartbeat once per interval and samples the
    /// driver's; called by every poll, the client's duty.
    fn serve_liveness(&mut self) {
        let now = Instant::now();
        let due = self
            .last_beat
            .is_none_or(|last| now.saturating_duration_since(last) >= self.heartbeat_interval);
        if due && let Some(producer) = self.producer.as_mut() {
            // An exhausted heartbeat closes the ring, which `closed` sees.
            let _ = producer.beat();
            self.last_beat = Some(now);
        }
        let beat = self.receiver.heartbeat();
        match self.driver_seen {
            Some((seen, since)) if seen == beat => {
                if now.saturating_duration_since(since) >= self.driver_timeout {
                    self.driver_lost = true;
                }
            }
            _ => self.driver_seen = Some((beat, now)),
        }
    }

    /// The client's owner identity.
    #[must_use]
    pub fn owner(&self) -> Owner {
        self.owner
    }

    /// Requests that are submitted and not yet reported.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len() + self.unknown.len()
    }

    /// Requests the stream's exclusive publication; returns the request
    /// sequence.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_publication(
        &mut self,
        stream: StreamKey,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        self.submit(Kind::AddPublication, |sequence| Command::AddPublication {
            sequence,
            stream,
            allow_unconnected,
        })
    }

    /// Requests a concurrent publication handle on the stream; returns the
    /// request sequence. The driver refuses it with
    /// `InvalidPublicationMode` for an exclusive stream and with
    /// `PublicationTaken` while all its publisher slots are held.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_concurrent_publication(
        &mut self,
        stream: StreamKey,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        self.submit(Kind::AddConcurrentPublication, |sequence| {
            Command::AddConcurrentPublication {
                sequence,
                stream,
                allow_unconnected,
            }
        })
    }

    /// Requests a subscription to the stream; returns the request sequence.
    ///
    /// # Errors
    ///
    /// See [`ConductorError`]; nothing is submitted on error.
    pub fn add_subscription(
        &mut self,
        stream: StreamKey,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        self.submit(Kind::AddSubscription, |sequence| Command::AddSubscription {
            sequence,
            stream,
            role,
        })
    }

    /// Removes a publication this conductor handed out. The handle is
    /// dropped only after the command is written.
    ///
    /// # Errors
    ///
    /// Returns the handle intact with the error, so the caller can retry.
    #[allow(
        clippy::result_large_err,
        reason = "the handle is returned intact so the caller can retry; boxing it would allocate on every Full"
    )]
    pub fn remove_publication(
        &mut self,
        publication: ClientPublication<T>,
    ) -> Result<u64, (ClientPublication<T>, ConductorError)> {
        let Some(registration) = self.owned(publication.origin()) else {
            return Err((publication, ConductorError::ForeignHandle));
        };
        match self.submit(Kind::Remove, |sequence| Command::RemovePublication {
            sequence,
            registration,
        }) {
            Ok(sequence) => {
                // The Remove is queued: the driver keeps the registration
                // until it serves it.
                if let Some(origin) = publication.origin() {
                    origin.lease.mark_removing();
                }
                drop(publication);
                Ok(sequence)
            }
            Err(error) => Err((publication, error)),
        }
    }

    /// Removes a concurrent publication handle this conductor handed out,
    /// as [`ClientConductor::remove_publication`]; dropping the handle frees
    /// its publisher slot.
    ///
    /// # Errors
    ///
    /// Returns the handle intact with the error, so the caller can retry.
    #[allow(
        clippy::result_large_err,
        reason = "the handle is returned intact so the caller can retry; boxing it would allocate on every Full"
    )]
    pub fn remove_concurrent_publication(
        &mut self,
        publication: ClientConcurrentPublication<T>,
    ) -> Result<u64, (ClientConcurrentPublication<T>, ConductorError)> {
        let Some(registration) = self.owned(publication.origin()) else {
            return Err((publication, ConductorError::ForeignHandle));
        };
        match self.submit(Kind::Remove, |sequence| Command::RemovePublication {
            sequence,
            registration,
        }) {
            Ok(sequence) => {
                // The Remove is queued: the driver keeps the registration
                // until it serves it.
                if let Some(origin) = publication.origin() {
                    origin.lease.mark_removing();
                }
                drop(publication);
                Ok(sequence)
            }
            Err(error) => Err((publication, error)),
        }
    }

    /// Removes a subscription this conductor handed out. The handle is
    /// dropped (detaching its registry cell) only after the command is
    /// written.
    ///
    /// # Errors
    ///
    /// Returns the handle intact with the error, so the caller can retry.
    #[allow(
        clippy::result_large_err,
        reason = "the handle is returned intact so the caller can retry; boxing it would allocate on every Full"
    )]
    pub fn remove_subscription(
        &mut self,
        subscription: ClientSubscription<T>,
    ) -> Result<u64, (ClientSubscription<T>, ConductorError)> {
        let Some(registration) = self.owned(subscription.origin()) else {
            return Err((subscription, ConductorError::ForeignHandle));
        };
        match self.submit(Kind::Remove, |sequence| Command::RemoveSubscription {
            sequence,
            registration,
        }) {
            Ok(sequence) => {
                // The Remove is queued: the driver keeps the registration
                // until it serves it.
                if let Some(origin) = subscription.origin() {
                    origin.lease.mark_removing();
                }
                drop(subscription);
                Ok(sequence)
            }
            Err(error) => Err((subscription, error)),
        }
    }

    fn owned(&self, origin: Option<&Origin>) -> Option<u64> {
        origin
            .filter(|origin| origin.owner == self.owner)
            .map(|origin| origin.registration)
    }

    /// Whether this client can no longer be served: its ring was closed (by
    /// itself or by the driver, which retires a faulty client), the
    /// broadcast buffer closed, or the driver was dropped.
    fn closed(&self) -> bool {
        self.producer
            .as_ref()
            .is_none_or(karyos_sys::command_ring::RingProducer::is_closed)
            || self.receiver.is_closed()
            || self.link.driver_gone()
            || self.driver_lost
    }

    fn submit(
        &mut self,
        kind: Kind,
        command: impl FnOnce(u64) -> Command,
    ) -> Result<u64, ConductorError> {
        if self.closed() {
            return Err(ConductorError::Closed);
        }
        if self.pending() >= self.max_pending {
            return Err(ConductorError::TooManyPending);
        }
        let sequence = self.next_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(ConductorError::SequencesExhausted)?;
        let command = command(sequence);
        let mut bytes = [0u8; MAX_COMMAND_LENGTH];
        // Every command fits MAX_COMMAND_LENGTH by construction.
        let length = command
            .encode(&mut bytes)
            .map_err(|_| ConductorError::Closed)?;
        let producer = self.producer.as_mut().ok_or(ConductorError::Closed)?;
        match producer.write(command.type_id(), bytes.get(..length).unwrap_or(&[])) {
            Ok(_) => {
                self.next_sequence = next;
                self.pending.push(Pending { sequence, kind });
                Ok(sequence)
            }
            Err(RingError::Full) => Err(ConductorError::Full),
            Err(_) => Err(ConductorError::Closed),
        }
    }

    /// Makes at most `limit` broadcast receive attempts and reports
    /// completed requests to `on`. Each attempt reads one record of any
    /// client or a lap report, plus at most one padding record before it.
    /// Returns early when nothing more is published.
    pub fn poll<F>(&mut self, limit: usize, mut on: F) -> ConductorPoll
    where
        F: FnMut(Completion<T>),
    {
        let mut report = ConductorPoll::default();
        self.serve_liveness();
        // A closed client resolves its pending requests now, however small
        // the budget and however busy the broadcast buffer.
        if self.closed() {
            self.fail_pending(&mut on);
        } else {
            self.deliver_unknown(&mut on);
        }
        while report.records < limit {
            // Copy what is needed out of the receiver before acting on it.
            let step = match self.receiver.receive() {
                Received::Pending => None,
                Received::Lapped { .. } => Some(None),
                Received::Message {
                    type_id, payload, ..
                } if Event::is_event_type(type_id) => {
                    // Driver events answer no request: queue them for the
                    // application, dropping the oldest when full.
                    if let Ok(event) = Event::decode(type_id, payload) {
                        if self.events.len() == EVENT_QUEUE {
                            self.events.pop_front();
                            self.events_dropped = self.events_dropped.saturating_add(1);
                        }
                        self.events.push_back(event);
                    }
                    Some(Some(None))
                }
                Received::Message {
                    type_id, payload, ..
                } => Some(Some(Response::decode(type_id, payload).ok())),
            };
            let response = match step {
                None => {
                    report.drained = true;
                    if self.closed() {
                        self.fail_pending(&mut on);
                    }
                    break;
                }
                Some(None) => {
                    report.records += 1;
                    self.fail_pending(&mut on);
                    continue;
                }
                Some(Some(response)) => {
                    report.records += 1;
                    response
                }
            };
            let Some(response) = response else {
                continue;
            };
            let request = response.request();
            if request.client != self.owner.client {
                continue;
            }
            let Some(index) = self
                .pending
                .iter()
                .position(|pending| pending.sequence == request.sequence)
            else {
                // Late response for a request already completed: ignored.
                continue;
            };
            let pending = self.pending.swap_remove(index);
            let outcome = self.outcome(pending.kind, response);
            on(Completion {
                sequence: pending.sequence,
                outcome,
            });
        }
        report
    }

    fn outcome(&self, kind: Kind, response: Response) -> Outcome<T> {
        match (kind, response) {
            (
                Kind::AddPublication,
                Response::PublicationReady {
                    registration, key, ..
                },
            )
            | (
                Kind::AddConcurrentPublication,
                Response::PublicationReady {
                    registration, key, ..
                },
            )
            | (
                Kind::AddSubscription,
                Response::SubscriptionReady {
                    registration, key, ..
                },
            ) => match self.link.take(key) {
                Ok(entry) => {
                    let origin = Origin {
                        owner: self.owner,
                        registration,
                        lease: entry.lease,
                    };
                    let generation = entry.generation;
                    let outcome = match (kind, entry.capability) {
                        (
                            Kind::AddPublication,
                            Capability::Publication {
                                inner,
                                allow_unconnected,
                            },
                        ) => Outcome::Publication(ClientPublication::from_hand_over(
                            inner,
                            allow_unconnected,
                            origin,
                        )),
                        (
                            Kind::AddConcurrentPublication,
                            Capability::ConcurrentPublication {
                                inner,
                                allow_unconnected,
                            },
                        ) => Outcome::ConcurrentPublication(
                            ClientConcurrentPublication::from_hand_over(
                                inner,
                                allow_unconnected,
                                origin,
                            ),
                        ),
                        (Kind::AddSubscription, Capability::Subscription(inner)) => {
                            Outcome::Subscription(ClientSubscription::from_hand_over(inner, origin))
                        }
                        // A capability of another kind than requested would
                        // be a driver defect: it is dropped (ending its
                        // lease and freeing what it holds), never converted.
                        _ => Outcome::Unknown,
                    };
                    match generation {
                        Some((link, base)) => outcome.with_generation(link, base),
                        None => outcome,
                    }
                }
                Err(_) => Outcome::Unknown,
            },
            (Kind::Remove, Response::OperationSucceeded { .. }) => Outcome::Succeeded,
            (_, Response::Error { code, detail, .. }) => Outcome::Refused { code, detail },
            // A response of the wrong kind would be a driver defect; the
            // outcome is not known.
            _ => Outcome::Unknown,
        }
    }

    /// Terminalizes every pending request as `Unknown` before any callback
    /// runs (a late response can no longer match it), then delivers the
    /// notifications.
    fn fail_pending<F: FnMut(Completion<T>)>(&mut self, on: &mut F) {
        self.unknown
            .extend(self.pending.drain(..).map(|pending| pending.sequence));
        self.deliver_unknown(on);
    }

    fn deliver_unknown<F: FnMut(Completion<T>)>(&mut self, on: &mut F) {
        while let Some(&sequence) = self.unknown.front() {
            on(Completion {
                sequence,
                outcome: Outcome::Unknown,
            });
            self.unknown.pop_front();
        }
    }

    /// Closes the client: drops the command ring producer, then sets the
    /// close flag. Same as dropping the conductor.
    pub fn close(self) {
        drop(self);
    }
}

impl<T: TermBytes> Drop for ClientConductor<T> {
    fn drop(&mut self) {
        drop(self.producer.take());
        self.link.mark_closed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{HandOverEntry, Lease, LeaseEnd, StreamLeases};
    use karyos_protocol::cnc::RequestId;
    use karyos_sys::broadcast::broadcast;
    use karyos_sys::command_ring::command_ring;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    // A capability of another kind than the request is never converted: a
    // driver defect the real driver cannot produce, injected by hand.
    #[test]
    fn a_capability_of_another_kind_is_dropped_as_unknown() {
        let mut transmitter = broadcast(4096).unwrap();
        let (producer, _consumer) = command_ring(1024).unwrap();
        let link = Arc::new(ClientLink::new());
        let owner = Owner {
            driver: 1,
            client: 1,
        };
        let mut client = ClientConductor::new(
            owner,
            producer,
            transmitter.receiver(),
            Arc::clone(&link),
            4,
        );
        let sequence = client.add_concurrent_publication(
            StreamKey {
                stream_id: 2,
                session_id: 1,
            },
            true,
        );
        let sequence = sequence.unwrap();
        let buffer = Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 2,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
            })
            .unwrap(),
        );
        let leases = Arc::new(StreamLeases::default());
        link.hold(HandOverEntry {
            key: 9,
            capability: Capability::Publication {
                inner: buffer.publication_owned().unwrap().unwrap(),
                allow_unconnected: true,
            },
            lease: Lease::acquire(&leases, &Arc::new(LeaseEnd::default())),
            generation: None,
        });
        let response = Response::PublicationReady {
            request: RequestId {
                client: 1,
                sequence,
            },
            registration: 9,
            key: 9,
        };
        let mut payload = [0u8; karyos_protocol::cnc::MAX_RESPONSE_LENGTH];
        let length = response.encode(&mut payload).unwrap();
        let _ = transmitter
            .transmit(response.type_id(), &payload[..length])
            .unwrap();
        let mut done = Vec::new();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
        assert_eq!(done.len(), 1);
        assert!(matches!(done[0].outcome, Outcome::Unknown));
        // Taken and dropped: its lease ended.
        assert_eq!(leases.live(), 0);
    }
}
