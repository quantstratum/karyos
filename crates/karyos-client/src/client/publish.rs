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
    #[inline]
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// The message's position in that lane.
    #[must_use]
    #[inline]
    pub fn position(&self) -> u64 {
        self.position
    }
}

/// Why an offer, a claim or a commit was not accepted (SPEC §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
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
    /// Another client error. SPEC §10's `MaxPositionExceeded`,
    /// `ResourcesUnavailable` and `UnsupportedCapability` are reported
    /// here until the publication returns them as their own outcomes.
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
pub struct MessageLength(core::num::NonZeroU32);

impl MessageLength {
    /// The length `length`.
    ///
    /// # Errors
    ///
    /// [`ClientError::EmptyMessage`] for 0.
    pub const fn try_new(length: u32) -> Result<Self, ClientError> {
        match core::num::NonZeroU32::new(length) {
            Some(length) => Ok(Self(length)),
            None => Err(ClientError::EmptyMessage),
        }
    }

    /// The length in bytes.
    #[must_use]
    #[inline]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Per-offer options ([`Publication::offer_on_with`]). The default is what
/// [`Publication::offer_on`] sends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OfferOptions {
    /// The value written in every fragment's header, which subscribers
    /// read as `MessageInfo::reserved_value`. On a conflated stream it is
    /// the message's key, in `0..keys` of the stream's table; see
    /// [`Publication::offer_on_with`].
    pub reserved_value: i64,
}

impl OfferOptions {
    /// The default options: a reserved value of 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// These options with `reserved_value`.
    #[must_use]
    pub fn with_reserved_value(mut self, reserved_value: i64) -> Self {
        self.reserved_value = reserved_value;
        self
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

fn claimed<T: TermBytes>(outcome: ClaimOutcome<'_, T>) -> Result<Claim<'_, T>, OfferError> {
    match outcome {
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

fn committed(outcome: CommitOutcome) -> Result<Accepted, OfferError> {
    match outcome {
        CommitOutcome::Accepted { lane, position } => Ok(Accepted { lane, position }),
        CommitOutcome::Aborted { lane, position } => Err(OfferError::Aborted { lane, position }),
    }
}

impl<T: TermBytes> Publication<T> {
    /// A publication over `lanes`, lane 0 first.
    pub(crate) fn new(lanes: Vec<ClientPublication<T>>) -> Self {
        Self { lanes }
    }

    /// A publication over the handles of an in-process driver's stream,
    /// lane 0 first, as `EmbeddedDriver::publication` returns them: the
    /// facade API over handles that no [`crate::Client`] granted. The
    /// publication then owns them; a client's
    /// [`crate::Client::remove_publication`] cannot release them to their
    /// driver, so it drops them and counts the release as failed.
    ///
    /// The handles must be of one registration of one driver. That is the
    /// caller's duty: this checks only that there is at least one, that
    /// handle `n` publishes on lane `n`, and that every one publishes to
    /// the same stream and session.
    ///
    /// # Errors
    ///
    /// The handles, untouched, when a check fails.
    pub fn from_handles(
        lanes: Vec<ClientPublication<T>>,
    ) -> Result<Self, Vec<ClientPublication<T>>> {
        let Some(first) = lanes.first() else {
            return Err(lanes);
        };
        let stream = first.stream();
        // Handle n on lane n: a handle past the last lane cannot be.
        let ordered = (0u8..)
            .zip(&lanes)
            .all(|(index, lane)| lane.lane().get() == index && lane.stream() == stream);
        if ordered {
            Ok(Self::new(lanes))
        } else {
            Err(lanes)
        }
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

    /// Offers `payload` on `lane` with `options`: its reserved value, which
    /// on a conflated stream is its key.
    ///
    /// On a conflated stream the driver is authoritative: a key outside
    /// the table never enters the conflated view, and the driver counts it
    /// as a rejected key. Every publication also refuses such a key, or a
    /// value larger than the capacity, before it appends: the table's shape
    /// comes with the log buffer it publishes to, in process or attached.
    /// Conflation is a view over the log, not a filter on it: an appended
    /// message reaches the stream's subscribers whatever its key.
    ///
    /// # Errors
    ///
    /// As [`Publication::offer_on`]; a key or value the publication checks
    /// and refuses, as [`OfferError::Client`] with
    /// `ClientError::Conflation`.
    #[must_use = "an offer can be refused"]
    pub fn offer_on_with(
        &mut self,
        lane: Lane,
        payload: &[u8],
        options: OfferOptions,
    ) -> Result<Accepted, OfferError> {
        let append = karyos_sys::log_buffer::AppendOptions {
            reserved_value: options.reserved_value,
            ..karyos_sys::log_buffer::AppendOptions::default()
        };
        offered(self.lane(lane)?.offer_with(payload, append)?)
    }

    /// Offers `payload` on the timed `lane` with its requested not-before
    /// time `tx_time`, in the lane's clock domain (`quantstratum-docs:
    /// karyos/design/timed-tx.md`). The lane's handle checks the time
    /// first, before anything is reserved; on a network route the driver's
    /// sender holds the message until its time, and local readers read it
    /// at its commit. On an IPC stream nothing sends, so the lane takes only
    /// its `schedule_capacity` timed offers, then back pressures for good.
    ///
    /// # Errors
    ///
    /// [`OfferError::InvalidLane`] for a lane the stream does not
    /// configure; [`OfferError::InvalidSchedule`] for a lane that is not
    /// timed or a time below the lane's last; `ClientError::ScheduleTooFar`
    /// and `ClientError::ScheduleOverflow` as [`OfferError::Client`]; and
    /// see [`OfferError`].
    #[must_use = "an offer can be refused"]
    pub fn offer_at_on(
        &mut self,
        lane: Lane,
        payload: &[u8],
        tx_time: u64,
    ) -> Result<Accepted, OfferError> {
        offered(self.lane(lane)?.offer_at(payload, tx_time)?)
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
        claimed(self.lane(lane)?.try_claim(length.get())?)
    }

    /// Delivers up to `limit` outcome records of `lane`'s guarded handle
    /// to `handler`, in sequence order, each with its sequence
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, "The
    /// outcome stream", G5); a lane that is not guarded has none. Returns
    /// how many were delivered.
    ///
    /// # Errors
    ///
    /// [`OfferError::InvalidLane`] for a lane the stream does not
    /// configure, and the outcome stream's errors, such as
    /// [`ClientError::OutcomesLost`], as [`OfferError::Client`].
    pub fn poll_outcomes_on(
        &mut self,
        lane: Lane,
        limit: usize,
        handler: impl FnMut(u64, karyos_sys::outcome_ring::Record),
    ) -> Result<usize, OfferError> {
        Ok(self.lane(lane)?.poll_outcomes(limit, handler)?)
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
        committed(self.inner.commit())
    }

    /// Aborts the frame; subscribers skip it.
    pub fn abort(self) {
        self.inner.abort();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;
    use karyos_sys::term_bytes::HeapTerms;

    fn lane(index: u8) -> Lane {
        Lane::try_new(index).unwrap()
    }

    /// The exclusive handle of a new heap buffer on `lane` of `stream_id`.
    fn handle(lane: Lane, stream_id: i32) -> ClientPublication {
        use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig, PublicationMode};
        use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};

        let buffer = std::sync::Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 1,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: karyos_sys::term::TermId::new(7),
                lane,
                session_id: 1,
                stream_id,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            })
            .unwrap(),
        );
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), true)
    }

    /// The handles of lanes 0 to n of one stream make a publication with
    /// those lanes.
    #[test]
    fn handles_of_one_stream_in_lane_order_make_a_publication() {
        let publication =
            Publication::from_handles(vec![handle(lane(0), 2), handle(lane(1), 2)]).unwrap();
        assert_eq!(publication.lane_count(), 2);
        assert!(publication.max_message_length(lane(1)).is_some());
        assert!(publication.max_message_length(lane(2)).is_none());
    }

    /// No handles, handles out of lane order, handles of two streams and
    /// more handles than lanes are refused, and handed back.
    #[test]
    fn handles_that_cannot_be_one_publication_are_handed_back() {
        let refused = |lanes: Vec<ClientPublication>| {
            let count = lanes.len();
            let back = Publication::from_handles(lanes).unwrap_err();
            assert_eq!(back.len(), count);
        };
        refused(Vec::new());
        refused(vec![handle(lane(1), 2)]);
        refused(vec![handle(lane(1), 2), handle(lane(0), 2)]);
        refused(vec![handle(lane(0), 2), handle(lane(0), 2)]);
        refused(vec![handle(lane(0), 2), handle(lane(1), 3)]);
        let mut five: Vec<ClientPublication> = (0..Lane::COUNT)
            .map(|index| handle(lane(index), 2))
            .collect();
        five.push(handle(lane(0), 2));
        refused(five);
    }

    /// Every offer outcome maps to its own result: only an acceptance is
    /// `Ok`, with its lane and position.
    #[test]
    fn every_offer_outcome_maps() {
        assert_eq!(
            offered(OfferOutcome::Accepted {
                lane: lane(1),
                position: 64
            }),
            Ok(Accepted {
                lane: lane(1),
                position: 64
            })
        );
        for (outcome, error) in [
            (OfferOutcome::BackPressured, OfferError::BackPressured),
            (OfferOutcome::AdminAction, OfferError::AdminAction),
            (OfferOutcome::NotConnected, OfferError::NotConnected),
            (OfferOutcome::Closed, OfferError::Closed),
            (OfferOutcome::Gated, OfferError::Gated),
            (OfferOutcome::RateLimited, OfferError::RateLimited),
        ] {
            assert_eq!(offered(outcome), Err(error), "{outcome:?}");
        }
    }

    /// Every claim refusal maps to its own error, an abort with its lane
    /// and position.
    #[test]
    fn every_claim_refusal_maps() {
        let refusals: [(ClaimOutcome<'_, HeapTerms>, OfferError); 7] = [
            (ClaimOutcome::BackPressured, OfferError::BackPressured),
            (ClaimOutcome::AdminAction, OfferError::AdminAction),
            (ClaimOutcome::NotConnected, OfferError::NotConnected),
            (
                ClaimOutcome::Aborted {
                    lane: lane(2),
                    position: 128,
                },
                OfferError::Aborted {
                    lane: lane(2),
                    position: 128,
                },
            ),
            (ClaimOutcome::Closed, OfferError::Closed),
            (ClaimOutcome::Gated, OfferError::Gated),
            (ClaimOutcome::RateLimited, OfferError::RateLimited),
        ];
        for (outcome, error) in refusals {
            assert_eq!(claimed(outcome).err(), Some(error));
        }
    }

    /// A commit is accepted or aborted, each with its lane and position.
    #[test]
    fn both_commit_outcomes_map() {
        assert_eq!(
            committed(CommitOutcome::Accepted {
                lane: lane(3),
                position: 32
            }),
            Ok(Accepted {
                lane: lane(3),
                position: 32
            })
        );
        assert_eq!(
            committed(CommitOutcome::Aborted {
                lane: Lane::ZERO,
                position: 96
            }),
            Err(OfferError::Aborted {
                lane: Lane::ZERO,
                position: 96
            })
        );
    }

    #[test]
    fn a_message_length_is_never_zero() {
        assert_eq!(MessageLength::try_new(0), Err(ClientError::EmptyMessage));
        assert_eq!(MessageLength::try_new(64).unwrap().get(), 64);
    }
}
