// SPDX-License-Identifier: Apache-2.0

//! The facade path to an Archive-backed rejoin (`quantstratum-docs:
//! karyos/design/ffi-archive.md`, F9-0): a [`Subscription`] of one stream
//! becomes a [`RejoiningSubscription`], whose overruns are recovered from
//! a [`ReplayProvider`]'s replays and merged back into the live stream
//! ([`ReplayRejoin`]), falling back to a [`Secondary`] policy. It knows no
//! Archive: `karyos_archive::client::ArchiveClient` is one such provider.

use karyos_protocol::trace_hook::PublicationIdentity;
use karyos_sys::term_bytes::TermBytes;

use super::{ImageStop, Kind, Subscription, SubscriptionError, SubscriptionPoll, stopped};
use crate::error::ClientError;
use crate::merge::{MergeError, ReplayProvider, ReplayRejoin};
use crate::subscription::{MessageInfo, MessageLimit, Secondary};

/// A subscription [`Subscription::rejoin_with`] could not turn into a
/// rejoin, given back with the reason.
#[derive(Debug)]
#[non_exhaustive]
pub struct NotRejoinable<T: TermBytes> {
    /// The subscription, unchanged.
    pub subscription: Subscription<T>,
    /// Why: `ClientError::InvalidOptions`.
    pub error: ClientError,
}

/// A subscription that recovers its overruns from replays
/// ([`Subscription::rejoin_with`]).
#[derive(Debug)]
pub struct RejoiningSubscription<T: TermBytes> {
    inner: ReplayRejoin<T>,
    /// The publication whose replays recover the gaps.
    source: PublicationIdentity,
}

impl<T: TermBytes> Subscription<T> {
    /// This subscription, its overruns recovered from `provider`'s replays
    /// of its publication and merged back into the live stream, with
    /// `secondary` applied when no replay covers a gap
    /// ([`ReplayRejoin`]). Its own rejoin policy (`RejoinPolicy::Close`,
    /// a snapshot or any other) is set aside while it rejoins: the rejoin
    /// recovers every overrun, and `secondary` replaces that policy when no
    /// replay covers a gap. [`RejoiningSubscription::into_subscription`]
    /// gives the policy back with the subscription.
    ///
    /// # Errors
    ///
    /// [`NotRejoinable`] (boxed: it holds the subscription), with the
    /// subscription unchanged and
    /// `ClientError::InvalidOptions`, for a network subscription (its
    /// images are several publications) and for a subscription that names
    /// no publication to recover (one its driver handed over without an
    /// identity).
    pub fn rejoin_with(
        self,
        provider: Box<dyn ReplayProvider<T>>,
        secondary: Secondary,
    ) -> Result<RejoiningSubscription<T>, Box<NotRejoinable<T>>> {
        let refused = |kind, reason| {
            Box::new(NotRejoinable {
                subscription: Subscription { kind },
                error: ClientError::InvalidOptions { reason },
            })
        };
        match self.kind {
            Kind::Stream(stream) => match stream.loss_source() {
                Some(source) => Ok(RejoiningSubscription {
                    inner: ReplayRejoin::new(*stream, source, provider, secondary),
                    source,
                }),
                None => Err(refused(
                    Kind::Stream(stream),
                    "the subscription names no publication to recover from",
                )),
            },
            Kind::Images(images) => Err(refused(
                Kind::Images(images),
                "a network subscription's images are several publications: no replay source",
            )),
        }
    }
}

impl<T: TermBytes> RejoiningSubscription<T> {
    /// Delivers at most `limit` messages to `handler`, as
    /// [`Subscription::poll`] does, recovering an overrun: while a gap is
    /// asked for nothing is delivered, then the replay's messages up to the
    /// cutover and the live stream's after it, each once and in order.
    ///
    /// # Errors
    ///
    /// [`SubscriptionError::Poll`] when the live reader's poll fails.
    #[expect(
        clippy::result_large_err,
        reason = "as Subscription::poll: the error carries the poll error by value"
    )]
    pub fn poll<H>(
        &mut self,
        mut handler: H,
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        report(self.inner.poll(&mut handler, limit))
    }

    /// Adopts what the subscription's readers have been offered since the
    /// last adoption, as [`Subscription::adopt`] does: a successor mapping
    /// of the live reader, or of a replay being merged, that
    /// [`RejoiningSubscription::poll_adopted`] stopped before, and a replay
    /// handed out since. Never allocates.
    pub fn adopt(&mut self) {
        self.inner.adopt();
    }

    /// The largest message the subscription can deliver until the next
    /// [`RejoiningSubscription::adopt`]: the live stream's, and while a
    /// replay is merged, the larger of that and the replay's stream's. It
    /// changes only at an adoption, as [`Subscription::max_message_length`]
    /// does.
    #[must_use]
    pub fn max_message_length(&self) -> u32 {
        self.inner.max_message_length()
    }

    /// [`RejoiningSubscription::poll`] without adopting, as
    /// [`Subscription::poll_adopted`]: no reader moves to a successor
    /// mapping, and a replay handed out during the poll is read only after
    /// the next [`RejoiningSubscription::adopt`]. A caller that adopts,
    /// reads [`RejoiningSubscription::max_message_length`] and then polls
    /// this way never sees a longer message in that poll.
    ///
    /// # Errors
    ///
    /// As [`RejoiningSubscription::poll`].
    #[expect(
        clippy::result_large_err,
        reason = "as Subscription::poll: the error carries the poll error by value"
    )]
    pub fn poll_adopted<H>(
        &mut self,
        mut handler: H,
        limit: MessageLimit,
    ) -> Result<SubscriptionPoll, SubscriptionError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        report(self.inner.poll_adopted(&mut handler, limit))
    }

    /// Whether a gap is being recovered: asked for, or merging.
    #[must_use]
    pub fn is_recovering(&self) -> bool {
        self.inner.is_recovering()
    }

    /// The last merge's typed failure, if a merge failed.
    #[must_use]
    pub fn merge_failure(&self) -> Option<MergeError> {
        self.inner.merge_failure()
    }

    /// The publication whose replays recover the gaps.
    #[must_use]
    pub fn source(&self) -> &PublicationIdentity {
        &self.source
    }

    /// Gives the subscription back, with its own rejoin policy and loss
    /// reports, at any time: a gap asked for is withdrawn and a merge under
    /// way stopped (`ReplayRejoin::into_live`), and after a merge failure
    /// the live reader comes back too. Remove it with
    /// [`super::Client::remove_subscription`]. `None` only after a panic
    /// in the middle of a state change, where the live reader was lost;
    /// never during a recovery or after a failure. Dropping a rejoining
    /// subscription ends its reader as dropping a subscription does.
    #[must_use]
    pub fn into_subscription(self) -> Option<Subscription<T>> {
        self.inner.into_live().map(|live| Subscription {
            kind: Kind::Stream(Box::new(live)),
        })
    }
}

/// A rejoin's poll, reported as [`Subscription::poll`] reports.
#[expect(
    clippy::result_large_err,
    reason = "as Subscription::poll: the error carries the poll error by value"
)]
fn report(
    polled: Result<crate::subscription::PollSummary, crate::subscription::PollError>,
) -> Result<SubscriptionPoll, SubscriptionError> {
    match polled {
        Ok(summary) => Ok(SubscriptionPoll {
            delivered: summary.delivered,
            stopped_at_seal: summary.stopped_at_seal,
            // A rejoin's outcome alone is reported too: it may come
            // in a poll with nothing else (the replay merged).
            stopped: (stopped(&summary) || summary.rejoin.is_some()).then_some(ImageStop {
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
    }
}
