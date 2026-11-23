// SPDX-License-Identifier: Apache-2.0

//! The Archive's control streams over a facade client (`quantstratum-docs:
//! karyos/design/ffi-archive.md`, F9-0): what a requester opens to talk to
//! an Archive, and hands to an [`super::ArchiveClient`] or a
//! [`super::list::RecordingLister`] as their [`ControlRequests`] and
//! [`ControlResponses`].
//!
//! The request stream is shared by every requester, so the connection
//! takes a concurrent publication on it (archive-control-codec.md section
//! 7a: the host configures it `PublicationMode::Concurrent`). The response
//! stream is shared too, and read through an optional subscription that
//! rejoins at the head: a requester that stops reading is lapped and loses
//! answers, timing out its own requests, rather than holding back the
//! Archive's answers to everyone. Every requester sees every answer; the
//! consumer ([`super::ArchiveClient`], [`super::list::RecordingLister`])
//! keeps those of its own correlation ids. Both are `karyos:ipc` streams
//! of the client's driver. The client must be polled
//! ([`karyos_client::Client::poll`]) while the connection is used, as for
//! any of its handles, and a connection is closed through the client that
//! opened it ([`ArchiveConnection::close`], or [`Requests::close`] and
//! [`Responses::close`] once its transports are taken).

use karyos_client::{
    Client, ClientConcurrentPublication, ClientError, ClientSubscription, ConcurrentOfferOutcome,
    Connection, MessageLimit, RejoinPolicy, ReplayTargetSubscriber, StreamId, SubscriberRole,
    Subscription, SubscriptionOptions,
};
use karyos_sys::term_bytes::TermBytes;

use super::{ControlRequests, ControlResponses, ReplayTargets};

/// The two control streams of an Archive, as its host configures them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ControlStreams {
    /// The request stream, shared by every requester.
    pub requests: i32,
    /// The response stream.
    pub responses: i32,
}

impl ControlStreams {
    /// The streams `requests` and `responses`.
    #[must_use]
    pub const fn new(requests: i32, responses: i32) -> Self {
        Self {
            requests,
            responses,
        }
    }
}

/// Why an [`ArchiveConnection`] could not be opened: which stream the
/// client could not take, and the client's error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OpenError {
    /// The request stream: absent, not concurrent, or the driver refused.
    #[error("request stream: {0}")]
    Requests(ClientError),
    /// The response stream.
    #[error("response stream: {0}")]
    Responses(ClientError),
}

/// A requester's connection to an Archive: its request publication and
/// response subscription, taken from a facade client.
#[derive(Debug)]
pub struct ArchiveConnection<T: TermBytes> {
    requests: Requests<T>,
    responses: Responses<T>,
}

impl<T: TermBytes> ArchiveConnection<T> {
    /// Takes a concurrent publication on `streams.requests` and an
    /// optional subscription, rejoining at the head, on
    /// `streams.responses` from `client`. Two control calls: each waits
    /// for the driver up to the client's timeout.
    ///
    /// # Errors
    ///
    /// [`OpenError`], naming the stream and the client's error. A
    /// publication taken before a failed subscription is removed from
    /// `client`, so a failed open holds none of the request stream's
    /// publisher slots.
    pub fn open<C>(client: &mut Client<C>, streams: ControlStreams) -> Result<Self, OpenError>
    where
        C: Connection<Terms = T>,
    {
        let requests = client
            .add_concurrent_publication("karyos:ipc", StreamId::new(streams.requests))
            .map_err(OpenError::Requests)?;
        let responses = match client.add_subscription_with(
            "karyos:ipc",
            StreamId::new(streams.responses),
            SubscriptionOptions::new(SubscriberRole::Optional, RejoinPolicy::RejoinAtHead),
        ) {
            Ok(responses) => responses,
            Err(error) => {
                client.remove_concurrent_publication(requests);
                return Err(OpenError::Responses(error));
            }
        };
        Ok(Self {
            requests: Requests(requests),
            responses: Responses {
                subscription: responses,
                oversized: 0,
            },
        })
    }

    /// Removes both streams' handles from `client`, which opened them.
    pub fn close<C>(self, client: &mut Client<C>)
    where
        C: Connection<Terms = T>,
    {
        self.requests.close(client);
        self.responses.close(client);
    }

    /// The two transports, for an [`super::ArchiveClient`] or a
    /// [`super::list::RecordingLister`].
    #[must_use]
    pub fn into_transports(self) -> (Requests<T>, Responses<T>) {
        (self.requests, self.responses)
    }
}

/// The request stream of an [`ArchiveConnection`].
#[derive(Debug)]
pub struct Requests<T: TermBytes>(ClientConcurrentPublication<T>);

impl<T: TermBytes> Requests<T> {
    /// Removes the publication from `client`, which opened it, freeing its
    /// publisher slot.
    pub fn close<C>(self, client: &mut Client<C>)
    where
        C: Connection<Terms = T>,
    {
        client.remove_concurrent_publication(self.0);
    }
}

impl<T: TermBytes> ControlRequests for Requests<T>
where
    ClientConcurrentPublication<T>: Send,
{
    /// Offers the request; `false` when it was not accepted now (back
    /// pressure, no subscriber yet, an administrative action), so the
    /// caller offers it again later.
    fn send(&mut self, message: &[u8]) -> bool {
        matches!(
            self.0.offer(message),
            Ok(ConcurrentOfferOutcome::Accepted { .. })
        )
    }
}

/// The response stream of an [`ArchiveConnection`].
#[derive(Debug)]
pub struct Responses<T: TermBytes> {
    subscription: Subscription<T>,
    oversized: u64,
}

impl<T: TermBytes> Responses<T> {
    /// Takes an optional subscription, rejoining at the head, on
    /// `karyos:ipc` stream `stream_id` of `client`'s driver: a requester's
    /// own answer stream, which a retention state query names (ADR-0101).
    /// One control call, which waits up to the client's timeout.
    ///
    /// # Errors
    ///
    /// The client's error: no such stream, or the driver refused.
    pub fn open<C>(client: &mut Client<C>, stream_id: i32) -> Result<Self, ClientError>
    where
        C: Connection<Terms = T>,
    {
        let subscription = client.add_subscription_with(
            "karyos:ipc",
            StreamId::new(stream_id),
            SubscriptionOptions::new(SubscriberRole::Optional, RejoinPolicy::RejoinAtHead),
        )?;
        Ok(Self {
            subscription,
            oversized: 0,
        })
    }

    /// Answers dropped because they were longer than the caller's buffer
    /// (`ControlResponses::next`), since the connection was opened. An
    /// answer the Archive sends is at most `MAX_ANSWER` bytes, so with a
    /// buffer that large this stays 0.
    #[must_use]
    pub const fn oversized(&self) -> u64 {
        self.oversized
    }

    /// Removes the subscription from `client`, which opened it.
    pub fn close<C>(self, client: &mut Client<C>)
    where
        C: Connection<Terms = T>,
    {
        client.remove_subscription(self.subscription);
    }
}

impl<T: TermBytes> ControlResponses for Responses<T>
where
    Subscription<T>: Send,
{
    /// Copies the next answer into `out`. One longer than `out` is the
    /// stream's to drop, as the trait has it: it is consumed, `None` is
    /// returned and [`Responses::oversized`] counts it.
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut length = None;
        let mut oversized = false;
        let _ = self.subscription.poll(
            |bytes, _| {
                if let Some(to) = out.get_mut(..bytes.len()) {
                    to.copy_from_slice(bytes);
                    length = Some(bytes.len());
                } else {
                    oversized = true;
                }
            },
            MessageLimit::new(1),
        );
        if oversized && let Some(next) = self.oversized.checked_add(1) {
            // Once at `u64::MAX` it stays there, never wrapping.
            self.oversized = next;
        }
        length
    }
}

/// The replay targets of an [`super::ArchiveClient`] over a facade client:
/// the client's [`ReplayTargetSubscriber`] (`Client::replay_targets`),
/// whose requests that client's polls submit and complete. A target the
/// Archive client stops asking for is released by the client.
impl<T: TermBytes> ReplayTargets<T> for ReplayTargetSubscriber<T>
where
    ReplayTargetSubscriber<T>: Send,
{
    fn subscribe(&mut self, stream_id: i32, session_id: i32) -> Option<ClientSubscription<T>> {
        ReplayTargetSubscriber::subscribe(self, stream_id, session_id)
    }
}
