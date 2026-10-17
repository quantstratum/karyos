// SPDX-License-Identifier: Apache-2.0

//! The SPEC §10 publication shape (W8): offers and claims return
//! `Result<Accepted, OfferError>`, a claim borrows its publication, and a
//! claim dropped uncommitted aborts its block.
//!
//! A [`Publication`] holds one handle per lane of its stream: lane 0 from
//! the channel URI's grant and every further lane the aggregate
//! configures. [`Publication::offer`] offers on lane 0,
//! [`Publication::offer_on`] on any configured lane.

use karyos_sys::frame::Lane;
use karyos_sys::term_bytes::TermBytes;
use thiserror::Error;

use crate::error::ClientError;
use crate::publication::{
    ClaimOutcome, ClientClaim, ClientPublication, CommitOutcome, OfferOutcome,
};

/// A message accepted into the local publication log at `position` in
/// `lane`. Positions are per lane, so the pair identifies the message.
/// Acceptance is local only: it does not imply backend submission, wire
/// transmission, receiver delivery, archive durability or Cluster
/// commitment (SPEC §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    lane: Lane,
    position: u64,
}

impl Accepted {
    /// The lane the message was appended to.
    #[must_use]
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// The message's position in that lane.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }
}

/// Why an offer, a claim or a commit was not accepted (SPEC §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OfferError {
    /// No subscriber is attached and the publication does not allow
    /// unconnected offers.
    #[error("no subscriber is connected")]
    NotConnected,
    /// The flow-control limit does not admit the message; retry later.
    #[error("back pressured")]
    BackPressured,
    /// The call only padded or rotated, or waits for the driver; retry.
    #[error("an administrative action; retry")]
    AdminAction,
    /// The stream is sealed: the publication accepts nothing again.
    #[error("the publication is closed")]
    Closed,
    /// The publication's guard closed, or a deadline was missed: the
    /// incarnation accepts nothing again.
    #[error("the publication is gated")]
    Gated,
    /// The rate limit holds no token for another message; retry later.
    #[error("rate limited")]
    RateLimited,
    /// The message exceeds the publication's maximum message length.
    #[error("message of {length} bytes exceeds the maximum of {max}")]
    MessageTooLarge {
        /// The message length.
        length: u32,
        /// The maximum message length.
        max: u32,
    },
    /// The block was aborted: an abort won over the commit, or the commit
    /// deadline passed. Subscribers skip it.
    #[error("the block at {position} of lane {lane:?} was aborted")]
    Aborted {
        /// The lane of the block.
        lane: Lane,
        /// Its position in that lane.
        position: u64,
    },
    /// A timed send was refused (`ClientError::InvalidSchedule`).
    #[error("invalid schedule: {reason}")]
    InvalidSchedule {
        /// What is wrong.
        reason: &'static str,
    },
    /// The lane is not one the stream configures.
    #[error("lane {lane:?} is not configured")]
    InvalidLane {
        /// The lane asked for.
        lane: Lane,
    },
    /// Another client error.
    #[error(transparent)]
    Client(ClientError),
}

impl From<ClientError> for OfferError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::MessageTooLarge { length, max } => Self::MessageTooLarge { length, max },
            ClientError::InvalidSchedule { reason } => Self::InvalidSchedule { reason },
            other => Self::Client(other),
        }
    }
}

/// A message length of at least one byte (SPEC §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageLength(u32);

impl MessageLength {
    /// The length `length`.
    ///
    /// # Errors
    ///
    /// [`ClientError::EmptyMessage`] for 0.
    pub const fn try_new(length: u32) -> Result<Self, ClientError> {
        if length == 0 {
            Err(ClientError::EmptyMessage)
        } else {
            Ok(Self(length))
        }
    }

    /// The length in bytes.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// An exclusive publication of a [`Client`](super::Client): one handle per
/// configured lane.
#[derive(Debug)]
pub struct Publication<T: TermBytes> {
    lanes: Vec<ClientPublication<T>>,
}

fn offered(outcome: OfferOutcome) -> Result<Accepted, OfferError> {
    match outcome {
        OfferOutcome::Accepted { lane, position } => Ok(Accepted { lane, position }),
        OfferOutcome::BackPressured => Err(OfferError::BackPressured),
        OfferOutcome::AdminAction => Err(OfferError::AdminAction),
        OfferOutcome::NotConnected => Err(OfferError::NotConnected),
        OfferOutcome::Closed => Err(OfferError::Closed),
        OfferOutcome::Gated => Err(OfferError::Gated),
        OfferOutcome::RateLimited => Err(OfferError::RateLimited),
    }
}

impl<T: TermBytes> Publication<T> {
    /// A publication over `lanes`, lane 0 first.
    pub(crate) fn new(lanes: Vec<ClientPublication<T>>) -> Self {
        Self { lanes }
    }

    /// The handles, lane 0 first, to release them.
    pub(crate) fn into_lanes(self) -> Vec<ClientPublication<T>> {
        self.lanes
    }

    /// The lanes the stream configures.
    #[must_use]
    pub fn lane_count(&self) -> usize {
        self.lanes.len()
    }

    /// The largest message a lane accepts; `None` for an unconfigured lane.
    #[must_use]
    pub fn max_message_length(&self, lane: Lane) -> Option<u32> {
        self.lanes
            .get(usize::from(lane.get()))
            .map(ClientPublication::max_message_length)
    }

    fn lane(&mut self, lane: Lane) -> Result<&mut ClientPublication<T>, OfferError> {
        self.lanes
            .get_mut(usize::from(lane.get()))
            .ok_or(OfferError::InvalidLane { lane })
    }

    /// Offers `payload` on lane 0.
    ///
    /// # Errors
    ///
    /// See [`OfferError`].
    #[must_use = "an offer can be refused"]
    pub fn offer(&mut self, payload: &[u8]) -> Result<Accepted, OfferError> {
        self.offer_on(Lane::ZERO, payload)
    }

    /// Offers `payload` on `lane`.
    ///
    /// # Errors
    ///
    /// [`OfferError::InvalidLane`] for a lane the stream does not
    /// configure, and see [`OfferError`].
    #[must_use = "an offer can be refused"]
    pub fn offer_on(&mut self, lane: Lane, payload: &[u8]) -> Result<Accepted, OfferError> {
        offered(self.lane(lane)?.offer(payload)?)
    }

    /// Reserves one complete frame of `length` on lane 0, to encode in
    /// place.
    ///
    /// # Errors
    ///
    /// See [`OfferError`].
    #[must_use = "a claim can be refused, and dropping it aborts it"]
    pub fn try_claim(&mut self, length: MessageLength) -> Result<Claim<'_, T>, OfferError> {
        self.try_claim_on(Lane::ZERO, length)
    }

    /// Reserves one complete frame of `length` on `lane`.
    ///
    /// # Errors
    ///
    /// As [`Publication::offer_on`].
    #[must_use = "a claim can be refused, and dropping it aborts it"]
    pub fn try_claim_on(
        &mut self,
        lane: Lane,
        length: MessageLength,
    ) -> Result<Claim<'_, T>, OfferError> {
        match self.lane(lane)?.try_claim(length.get())? {
            ClaimOutcome::Claimed(inner) => Ok(Claim { inner }),
            ClaimOutcome::BackPressured => Err(OfferError::BackPressured),
            ClaimOutcome::AdminAction => Err(OfferError::AdminAction),
            ClaimOutcome::NotConnected => Err(OfferError::NotConnected),
            ClaimOutcome::Aborted { lane, position } => Err(OfferError::Aborted { lane, position }),
            ClaimOutcome::Closed => Err(OfferError::Closed),
            ClaimOutcome::Gated => Err(OfferError::Gated),
            ClaimOutcome::RateLimited => Err(OfferError::RateLimited),
        }
    }
}

/// A claimed frame of a [`Publication`]. It mutably borrows the
/// publication, so it cannot outlive it; dropping it uncommitted aborts
/// its block, which subscribers skip.
///
/// ```compile_fail,E0505
/// # use karyos_client::{MessageLength, Publication};
/// # use karyos_sys::term_bytes::HeapTerms;
/// fn outlive(mut publication: Publication<HeapTerms>) {
///     let claim = publication.try_claim(MessageLength::try_new(8).unwrap());
///     drop(publication);
///     let _ = claim.map(|claim| claim.commit());
/// }
/// ```
#[derive(Debug)]
#[must_use = "dropping a claim aborts it"]
pub struct Claim<'a, T: TermBytes> {
    inner: ClientClaim<'a, T>,
}

impl<T: TermBytes> Claim<'_, T> {
    /// The lane of the frame.
    #[must_use]
    pub fn lane(&self) -> Lane {
        self.inner.lane()
    }

    /// The frame's position in its lane.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.inner.position()
    }

    /// The payload: exactly the claimed length, zeroed at claim time.
    pub fn payload(&mut self) -> &mut [u8] {
        self.inner.payload()
    }

    /// Commits the frame: exactly one of commit and abort wins.
    ///
    /// # Errors
    ///
    /// [`OfferError::Aborted`] when an abort won.
    #[must_use = "a commit can lose to an abort"]
    pub fn commit(self) -> Result<Accepted, OfferError> {
        match self.inner.commit() {
            CommitOutcome::Accepted { lane, position } => Ok(Accepted { lane, position }),
            CommitOutcome::Aborted { lane, position } => {
                Err(OfferError::Aborted { lane, position })
            }
        }
    }

    /// Aborts the frame; subscribers skip it.
    pub fn abort(self) {
        self.inner.abort();
    }
}
