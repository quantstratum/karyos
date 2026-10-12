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

use std::sync::Arc;

use karyos_protocol::cnc::ErrorCode;
use karyos_protocol::cnc::{Command, MAX_COMMAND_LENGTH, Response, StreamKey, SubscriberRole};
use karyos_sys::broadcast::{BroadcastReceiver, Received};
use karyos_sys::command_ring::{RingError, RingProducer};
use thiserror::Error;

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
pub enum Outcome {
    /// The publication, ready to offer.
    Publication(ClientPublication),
    /// The subscription, ready to poll.
    Subscription(ClientSubscription),
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

/// A completed request.
#[derive(Debug)]
pub struct Completion {
    /// The request sequence returned when it was submitted.
    pub sequence: u64,
    /// How it ended.
    pub outcome: Outcome,
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
pub struct ClientConductor {
    owner: Owner,
    producer: Option<RingProducer>,
    receiver: BroadcastReceiver,
    link: Arc<ClientLink>,
    next_sequence: u64,
    pending: Vec<Pending>,
    max_pending: usize,
}

impl ClientConductor {
    /// Creates the conductor for an admitted client (called by the driver,
    /// control path: allocates the pending list).
    #[must_use]
    pub fn new(
        owner: Owner,
        producer: RingProducer,
        receiver: BroadcastReceiver,
        link: Arc<ClientLink>,
        max_pending: usize,
    ) -> Self {
        Self {
            owner,
            producer: Some(producer),
            receiver,
            link,
            next_sequence: 1,
            pending: Vec::with_capacity(max_pending),
            max_pending,
        }
    }

    /// The client's owner identity.
    #[must_use]
    pub fn owner(&self) -> Owner {
        self.owner
    }

    /// Requests that are submitted and not yet completed.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
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
    pub fn remove_publication(
        &mut self,
        publication: ClientPublication,
    ) -> Result<u64, (ClientPublication, ConductorError)> {
        let Some(registration) = self.owned(publication.origin()) else {
            return Err((publication, ConductorError::ForeignHandle));
        };
        match self.submit(Kind::Remove, |sequence| Command::RemovePublication {
            sequence,
            registration,
        }) {
            Ok(sequence) => {
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
    pub fn remove_subscription(
        &mut self,
        subscription: ClientSubscription,
    ) -> Result<u64, (ClientSubscription, ConductorError)> {
        let Some(registration) = self.owned(subscription.origin()) else {
            return Err((subscription, ConductorError::ForeignHandle));
        };
        match self.submit(Kind::Remove, |sequence| Command::RemoveSubscription {
            sequence,
            registration,
        }) {
            Ok(sequence) => {
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

    fn closed(&self) -> bool {
        self.producer.is_none() || self.receiver.is_closed() || self.link.driver_gone()
    }

    fn submit(
        &mut self,
        kind: Kind,
        command: impl FnOnce(u64) -> Command,
    ) -> Result<u64, ConductorError> {
        if self.closed() {
            return Err(ConductorError::Closed);
        }
        if self.pending.len() >= self.max_pending {
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

    /// Reads at most `limit` broadcast records and reports completed
    /// requests to `on`. Returns early when nothing more is published.
    pub fn poll<F>(&mut self, limit: usize, mut on: F) -> ConductorPoll
    where
        F: FnMut(Completion),
    {
        let mut report = ConductorPoll::default();
        while report.records < limit {
            // Copy what is needed out of the receiver before acting on it.
            let step = match self.receiver.receive() {
                Received::Pending => None,
                Received::Lapped { .. } => Some(None),
                Received::Message {
                    type_id, payload, ..
                } => Some(Some(Response::decode(type_id, payload).ok())),
            };
            let response = match step {
                None => {
                    report.drained = true;
                    if self.receiver.is_closed() || self.link.driver_gone() {
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

    fn outcome(&self, kind: Kind, response: Response) -> Outcome {
        match (kind, response) {
            (
                Kind::AddPublication,
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
                    match entry.capability {
                        Capability::Publication {
                            inner,
                            allow_unconnected,
                        } => Outcome::Publication(ClientPublication::from_hand_over(
                            inner,
                            allow_unconnected,
                            origin,
                        )),
                        Capability::Subscription(inner) => {
                            Outcome::Subscription(ClientSubscription::from_hand_over(inner, origin))
                        }
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

    fn fail_pending<F: FnMut(Completion)>(&mut self, on: &mut F) {
        for pending in self.pending.drain(..) {
            on(Completion {
                sequence: pending.sequence,
                outcome: Outcome::Unknown,
            });
        }
    }

    /// Closes the client: drops the command ring producer, then sets the
    /// close flag. Same as dropping the conductor.
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for ClientConductor {
    fn drop(&mut self) {
        drop(self.producer.take());
        self.link.mark_closed();
    }
}
