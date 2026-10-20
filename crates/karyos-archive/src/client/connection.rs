// SPDX-License-Identifier: Apache-2.0

//! The Archive's control streams over a facade client (`quantstratum-docs:
//! karyos/design/ffi-archive.md`, F9-0): what a requester opens to talk to
//! an Archive, and hands to an [`super::ArchiveClient`] or a
//! [`super::list::RecordingLister`] as their [`ControlRequests`] and
//! [`ControlResponses`].
//!
//! The request stream is shared by every requester, so the connection
//! takes a concurrent publication on it (archive-control-codec.md section
//! 7a: the host configures it `PublicationMode::Concurrent`); the response
//! stream is read through an ordinary subscription, and answers addressed
//! to other requesters are skipped by their correlation id. Both are
//! `karyos:ipc` streams of the client's driver. The client must be polled
//! ([`karyos_client::Client::poll`]) while the connection is used, as for
//! any of its handles.

use karyos_client::{
    Client, ClientConcurrentPublication, ClientError, ConcurrentOfferOutcome, Connection,
    MessageLimit, StreamId, Subscription,
};
use karyos_sys::term_bytes::TermBytes;

use super::{ControlRequests, ControlResponses};

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

/// A requester's connection to an Archive: its request publication and
/// response subscription, taken from a facade client.
#[derive(Debug)]
pub struct ArchiveConnection<T: TermBytes> {
    requests: Requests<T>,
    responses: Responses<T>,
}

impl<T: TermBytes> ArchiveConnection<T> {
    /// Takes a concurrent publication on `streams.requests` and a
    /// subscription on `streams.responses` from `client`. Two control
    /// calls: each waits for the driver up to the client's timeout.
    ///
    /// # Errors
    ///
    /// The client's errors for either; a publication taken before a failed
    /// subscription is dropped, which ends its lease.
    pub fn open<C>(client: &mut Client<C>, streams: ControlStreams) -> Result<Self, ClientError>
    where
        C: Connection<Terms = T>,
    {
        let requests =
            client.add_concurrent_publication("karyos:ipc", StreamId::new(streams.requests))?;
        let responses = client.add_subscription("karyos:ipc", StreamId::new(streams.responses))?;
        Ok(Self {
            requests: Requests(requests),
            responses: Responses(responses),
        })
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
pub struct Responses<T: TermBytes>(Subscription<T>);

impl<T: TermBytes> ControlResponses for Responses<T>
where
    Subscription<T>: Send,
{
    /// Copies the next answer into `out`; one longer than `out` is skipped,
    /// as no answer the Archive sends is (`MAX_ANSWER`).
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut length = None;
        let _ = self.0.poll(
            |bytes, _| {
                if let Some(to) = out.get_mut(..bytes.len()) {
                    to.copy_from_slice(bytes);
                    length = Some(bytes.len());
                }
            },
            MessageLimit::new(1),
        );
        length
    }
}
