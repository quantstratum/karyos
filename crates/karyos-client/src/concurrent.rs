// SPDX-License-Identifier: Apache-2.0

//! The embedded concurrent publication (SPEC.md §4 concurrent publication;
//! `quantstratum-docs: karyos/design/client-concurrent-publication.md`).

use std::sync::Arc;

use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, CommitOutcome as SysCommitOutcome, ConcurrentClaim,
    ConcurrentClaimOutcome as SysClaimOutcome, ConcurrentOfferOutcome as SysOfferOutcome,
    ConcurrentPublication, LogBuffer,
};

use crate::error::ClientError;
use crate::link::{Lease, Origin};
use crate::publication::CommitOutcome;

/// Result of [`ClientConcurrentPublication::offer`]. Each call performs at
/// most one reservation attempt and one rotation attempt; nothing is
/// retried silently. Embedded API, provisional, as
/// [`crate::OfferOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "back pressure, aborts and admin actions must be handled"]
pub enum ConcurrentOfferOutcome {
    /// The message was accepted into the local publication log, with the
    /// meaning of [`crate::OfferOutcome::Accepted`].
    Accepted {
        /// The lane the message was appended to.
        lane: Lane,
        /// Position of the message in that lane.
        position: u64,
    },
    /// The flow-control limit does not admit the message; retry later.
    BackPressured,
    /// The handle waits for a later term, or its reservation crossed or
    /// landed past the term end; retry.
    AdminAction,
    /// No subscriber is attached and the publication does not allow
    /// unconnected offers (SPEC.md §4 connection rule); nothing reserved.
    NotConnected,
    /// The commit deadline abort won the reserved block before its mark or
    /// its commit: the message was not published and may be offered again.
    Aborted {
        /// The lane of the reservation.
        lane: Lane,
        /// Its position in that lane.
        position: u64,
    },
}

/// Result of [`ClientConcurrentPublication::try_claim`]. Embedded API,
/// provisional, as [`ConcurrentOfferOutcome`].
#[derive(Debug)]
#[must_use = "back pressure, aborts and admin actions must be handled"]
pub enum ConcurrentClaimOutcome<'a> {
    /// A block was reserved and marked; write the payload, then commit.
    Claimed(ClientConcurrentClaim<'a>),
    /// The flow-control limit does not admit the claim; retry later.
    BackPressured,
    /// The handle waits for a later term, or its reservation crossed or
    /// landed past the term end; retry.
    AdminAction,
    /// No subscriber is attached and the publication does not allow
    /// unconnected claims (SPEC.md §4 connection rule); nothing reserved.
    NotConnected,
    /// The reservation was consumed but aborted at its deadline before it
    /// could be marked; nothing was written.
    Aborted {
        /// The lane of the reservation.
        lane: Lane,
        /// Its position in that lane.
        position: u64,
    },
}

/// A claimed block of a [`ClientConcurrentPublication`]. It mutably
/// borrows the publication; [`ClientConcurrentClaim::commit`] publishes it,
/// and [`ClientConcurrentClaim::abort`] or dropping it uncommitted aborts
/// it. A claim forgotten with `mem::forget` is aborted by the publication's
/// next mutable operation, or when the publication is dropped.
///
/// The payload cannot outlive the claim:
///
/// ```compile_fail,E0597
/// # use karyos_client::{ClientConcurrentPublication, ConcurrentClaimOutcome};
/// fn escape(publication: &mut ClientConcurrentPublication) {
///     let payload;
///     {
///         let Ok(ConcurrentClaimOutcome::Claimed(mut claim)) = publication.try_claim(8) else {
///             return;
///         };
///         payload = claim.payload();
///     }
///     payload[0] = 1;
/// }
/// ```
///
/// nor be used after `commit`:
///
/// ```compile_fail,E0505
/// # use karyos_client::ClientConcurrentClaim;
/// fn after_commit(mut claim: ClientConcurrentClaim<'_>) {
///     let payload = claim.payload();
///     let _ = claim.commit();
///     payload[0] = 1;
/// }
/// ```
#[derive(Debug)]
pub struct ClientConcurrentClaim<'a> {
    inner: ConcurrentClaim<'a, Arc<LogBuffer>>,
    lane: Lane,
}

impl ClientConcurrentClaim<'_> {
    /// The lane of the block.
    #[must_use]
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// The block's position in its lane.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.inner.position()
    }

    /// The payload: exactly the claimed length, zeroed at claim time.
    pub fn payload(&mut self) -> &mut [u8] {
        self.inner.payload()
    }

    /// Commits the block: exactly one of commit and abort wins.
    pub fn commit(self) -> CommitOutcome {
        let lane = self.lane;
        match self.inner.commit() {
            SysCommitOutcome::Committed { position } => CommitOutcome::Accepted { lane, position },
            SysCommitOutcome::Aborted { position } => CommitOutcome::Aborted { lane, position },
        }
    }

    /// Aborts the block; subscribers skip it.
    pub fn abort(self) {
        self.inner.abort();
    }
}

/// One concurrent publication handle on a stream: one of the stream's `P`
/// publisher slots. Each publishing thread holds its own handle.
#[derive(Debug)]
pub struct ClientConcurrentPublication {
    // Declared first: the sys handle frees its publisher slot before the
    // stream lease below ends.
    inner: ConcurrentPublication<Arc<LogBuffer>>,
    allow_unconnected: bool,
    origin: Option<Origin>,
    /// The stream lease of a handle from the direct driver API, held only
    /// for its drop.
    _lease: Option<Lease>,
}

impl ClientConcurrentPublication {
    /// Wraps a concurrent handle. Connectivity, limits and the lane are
    /// read from the buffer the handle publishes to.
    #[must_use]
    pub fn new(inner: ConcurrentPublication<Arc<LogBuffer>>, allow_unconnected: bool) -> Self {
        Self {
            inner,
            allow_unconnected,
            origin: None,
            _lease: None,
        }
    }

    /// Wraps a handle from the direct driver API; it keeps the stream's
    /// lease until it is dropped.
    #[must_use]
    pub fn with_lease(
        inner: ConcurrentPublication<Arc<LogBuffer>>,
        allow_unconnected: bool,
        lease: Lease,
    ) -> Self {
        Self {
            _lease: Some(lease),
            ..Self::new(inner, allow_unconnected)
        }
    }

    /// Wraps a handle handed over through a client conductor; it keeps the
    /// stream's lease until it is dropped.
    #[must_use]
    pub fn from_hand_over(
        inner: ConcurrentPublication<Arc<LogBuffer>>,
        allow_unconnected: bool,
        origin: Origin,
    ) -> Self {
        Self {
            inner,
            allow_unconnected,
            origin: Some(origin),
            _lease: None,
        }
    }

    /// The owner and registration, for a handle from a client conductor.
    #[must_use]
    pub fn origin(&self) -> Option<&Origin> {
        self.origin.as_ref()
    }

    /// Largest message accepted without a trace extension.
    #[inline]
    #[must_use]
    pub fn max_message_length(&self) -> u32 {
        self.inner.buffer().max_message_length()
    }

    /// Offers one message.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyMessage`], [`ClientError::MessageTooLarge`]
    /// and lower-layer errors. A validation error makes no new reservation;
    /// a forgotten claim resolved first may still have published its
    /// `ABORTED` word.
    pub fn offer(&mut self, payload: &[u8]) -> Result<ConcurrentOfferOutcome, ClientError> {
        self.offer_with(payload, AppendOptions::default())
    }

    /// Offers one message with header options (EOS, reserved value, an
    /// opaque trace extension). A forgotten claim is aborted first, even
    /// when the offer then returns `NotConnected` or an error.
    ///
    /// # Errors
    ///
    /// As [`ClientConcurrentPublication::offer`].
    pub fn offer_with(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<ConcurrentOfferOutcome, ClientError> {
        // A forgotten claim is resolved before any early return.
        self.inner.resolve_forgotten_claim();
        if !self.connected() {
            return Ok(ConcurrentOfferOutcome::NotConnected);
        }
        let lane = self.inner.buffer().lane();
        Ok(offer_outcome(self.inner.offer(payload, options)?, lane))
    }

    /// Claims one unfragmented block of `length` payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyMessage`], [`ClientError::MessageTooLarge`]
    /// (above `max_message_length`, one fragment or the reservation limit)
    /// and lower-layer errors. A validation error makes no new
    /// reservation; a forgotten claim is still resolved first.
    pub fn try_claim(&mut self, length: u32) -> Result<ConcurrentClaimOutcome<'_>, ClientError> {
        self.try_claim_with(length, AppendOptions::default())
    }

    /// Claims with header options (EOS, reserved value, an opaque trace
    /// extension).
    ///
    /// # Errors
    ///
    /// As [`ClientConcurrentPublication::try_claim`].
    pub fn try_claim_with(
        &mut self,
        length: u32,
        options: AppendOptions,
    ) -> Result<ConcurrentClaimOutcome<'_>, ClientError> {
        // A forgotten claim is resolved before any early return; the
        // connection check only prevents a new reservation.
        self.inner.resolve_forgotten_claim();
        if !self.connected() {
            return Ok(ConcurrentClaimOutcome::NotConnected);
        }
        let lane = self.inner.buffer().lane();
        Ok(claim_outcome(self.inner.try_claim(length, options)?, lane))
    }

    /// The connection rule (SPEC.md §4): one advisory load of the attached
    /// subscriber count, any role counting, unless unconnected use is
    /// allowed.
    fn connected(&self) -> bool {
        self.allow_unconnected || self.inner.buffer().attached_subscribers() > 0
    }
}

/// The sys offer outcome on the buffer's lane.
fn offer_outcome(outcome: SysOfferOutcome, lane: Lane) -> ConcurrentOfferOutcome {
    match outcome {
        SysOfferOutcome::Appended { position } => {
            ConcurrentOfferOutcome::Accepted { lane, position }
        }
        SysOfferOutcome::Aborted { position } => ConcurrentOfferOutcome::Aborted { lane, position },
        SysOfferOutcome::BackPressured => ConcurrentOfferOutcome::BackPressured,
        SysOfferOutcome::AdminAction => ConcurrentOfferOutcome::AdminAction,
    }
}

/// The sys claim outcome on the buffer's lane.
fn claim_outcome(
    outcome: SysClaimOutcome<'_, Arc<LogBuffer>>,
    lane: Lane,
) -> ConcurrentClaimOutcome<'_> {
    match outcome {
        SysClaimOutcome::Claimed(inner) => {
            ConcurrentClaimOutcome::Claimed(ClientConcurrentClaim { inner, lane })
        }
        SysClaimOutcome::BackPressured => ConcurrentClaimOutcome::BackPressured,
        SysClaimOutcome::AdminAction => ConcurrentClaimOutcome::AdminAction,
        SysClaimOutcome::Aborted { position } => ConcurrentClaimOutcome::Aborted { lane, position },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The `Aborted` arms are reached only when the conductor's deadline
    // abort wins between a writer's `fetch_add` and its mark or commit,
    // which the sys tests drive with pause points; the mapping is checked
    // here, the race in karyos-sys.
    #[test]
    fn every_sys_outcome_keeps_its_position_and_gains_the_lane() {
        let lane = Lane::try_new(3).unwrap();
        assert_eq!(
            offer_outcome(SysOfferOutcome::Appended { position: 64 }, lane),
            ConcurrentOfferOutcome::Accepted { lane, position: 64 }
        );
        assert_eq!(
            offer_outcome(SysOfferOutcome::Aborted { position: 96 }, lane),
            ConcurrentOfferOutcome::Aborted { lane, position: 96 }
        );
        assert_eq!(
            offer_outcome(SysOfferOutcome::BackPressured, lane),
            ConcurrentOfferOutcome::BackPressured
        );
        assert_eq!(
            offer_outcome(SysOfferOutcome::AdminAction, lane),
            ConcurrentOfferOutcome::AdminAction
        );
        assert!(matches!(
            claim_outcome(SysClaimOutcome::Aborted { position: 128 }, lane),
            ConcurrentClaimOutcome::Aborted { lane: l, position: 128 } if l == lane
        ));
        assert!(matches!(
            claim_outcome(SysClaimOutcome::BackPressured, lane),
            ConcurrentClaimOutcome::BackPressured
        ));
        assert!(matches!(
            claim_outcome(SysClaimOutcome::AdminAction, lane),
            ConcurrentClaimOutcome::AdminAction
        ));
    }

    #[test]
    fn handles_can_move_to_publishing_threads() {
        fn send<T: Send>() {}
        send::<ClientConcurrentPublication>();
    }
}
