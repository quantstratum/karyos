// SPDX-License-Identifier: Apache-2.0

//! The embedded publication (SPEC.md §4 and §10, `offer`).

use std::sync::Arc;

use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, AppendOutcome, Claim, ClaimOutcome as SysClaimOutcome,
    CommitOutcome as SysCommitOutcome, LogBuffer, Publication,
};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use crate::error::ClientError;
use crate::generation::{End, GenerationLink, Next, Successor, representable};
use crate::link::{Export, Lease, Origin};

/// Result of an offer. Each call performs at most one append attempt:
/// padding, rotation and waiting for the driver are reported to the caller
/// as [`OfferOutcome::AdminAction`] and never retried silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "back pressure and admin actions must be handled"]
pub enum OfferOutcome {
    /// The message was accepted into the local publication log at
    /// `position` in `lane`. Positions are per lane, so the pair identifies
    /// the message. Acceptance is local only: it does not imply backend
    /// submission, wire transmission, receiver delivery, archive durability
    /// or Cluster commitment (SPEC.md §10).
    Accepted {
        /// The lane the message was appended to.
        lane: Lane,
        /// Position of the message in that lane.
        position: u64,
    },
    /// The flow-control limit does not admit the message; retry later.
    BackPressured,
    /// The offer only padded or rotated, or waits for the driver; retry.
    AdminAction,
    /// No subscriber is attached and the publication does not allow
    /// unconnected offers (SPEC.md §4 connection rule).
    NotConnected,
    /// The stream is sealed: the publication accepts nothing again
    /// (`quantstratum-docs: karyos/design/publication-seal.md`).
    Closed,
}

/// Result of [`ClientPublication::try_claim`]. Each call makes at most
/// one reservation attempt, like an offer. Embedded API, provisional: it
/// converges with the publication error and outcome types of ADR-0026 when
/// those land.
#[derive(Debug)]
#[must_use = "back pressure and admin actions must be handled"]
pub enum ClaimOutcome<'a, T: TermBytes = HeapTerms> {
    /// A block was reserved; write the payload, then commit.
    Claimed(ClientClaim<'a, T>),
    /// The flow-control limit does not admit the claim; retry later.
    BackPressured,
    /// The call only padded or rotated, or waits for the driver; retry.
    AdminAction,
    /// No subscriber is attached and the publication does not allow
    /// unconnected claims (SPEC.md §4 connection rule); nothing reserved.
    NotConnected,
    /// The reservation was consumed but aborted before it could be
    /// marked (the commit deadline passed); nothing was written.
    Aborted {
        /// The lane of the reservation.
        lane: Lane,
        /// Its position in that lane.
        position: u64,
    },
    /// The stream is sealed: the publication reserves nothing again
    /// (`quantstratum-docs: karyos/design/publication-seal.md`).
    Closed,
}

/// Result of [`ClientClaim::commit`]. Embedded API, provisional, as
/// [`ClaimOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a commit can lose to an abort"]
pub enum CommitOutcome {
    /// The message was accepted into the local publication log, with the
    /// meaning of [`OfferOutcome::Accepted`].
    Accepted {
        /// The lane of the message.
        lane: Lane,
        /// Its position in that lane.
        position: u64,
    },
    /// An abort won; subscribers skip the block.
    Aborted {
        /// The lane of the block.
        lane: Lane,
        /// Its position in that lane.
        position: u64,
    },
}

/// A claimed block of a [`ClientPublication`] (SPEC.md §4 claims). It
/// mutably borrows the publication; [`ClientClaim::commit`] publishes it,
/// and [`ClientClaim::abort`] or dropping it uncommitted aborts it. A claim
/// forgotten with `mem::forget` is aborted by the publication's next mutable
/// operation (`offer`, `offer_with`, `try_claim`, `try_claim_with`), or when
/// the publication is dropped.
///
/// The payload cannot outlive the claim:
///
/// ```compile_fail,E0597
/// # use karyos_client::{ClaimOutcome, ClientPublication};
/// fn escape(publication: &mut ClientPublication) {
///     let payload;
///     {
///         let Ok(ClaimOutcome::Claimed(mut claim)) = publication.try_claim(8) else {
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
/// # use karyos_client::ClientClaim;
/// fn after_commit(mut claim: ClientClaim<'_>) {
///     let payload = claim.payload();
///     let _ = claim.commit();
///     payload[0] = 1;
/// }
/// ```
#[derive(Debug)]
pub struct ClientClaim<'a, T: TermBytes = HeapTerms> {
    inner: Claim<'a, Arc<LogBuffer<T>>>,
    lane: Lane,
    /// The base of the claim's mapping generation.
    base: u64,
}

impl<T: TermBytes> ClientClaim<'_, T> {
    /// The lane of the block.
    #[must_use]
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// The block's position in its lane.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.base + self.inner.position()
    }

    /// The payload: exactly the claimed length, zeroed at claim time.
    pub fn payload(&mut self) -> &mut [u8] {
        self.inner.payload()
    }

    /// Commits the block: exactly one of commit and abort wins.
    pub fn commit(self) -> CommitOutcome {
        let (lane, base) = (self.lane, self.base);
        match self.inner.commit() {
            SysCommitOutcome::Committed { position } => CommitOutcome::Accepted {
                lane,
                position: base + position,
            },
            SysCommitOutcome::Aborted { position } => CommitOutcome::Aborted {
                lane,
                position: base + position,
            },
        }
    }

    /// Aborts the block; subscribers skip it.
    pub fn abort(self) {
        self.inner.abort();
    }
}

/// An exclusive publication on one stream.
#[derive(Debug)]
pub struct ClientPublication<T: TermBytes = HeapTerms> {
    inner: Publication<Arc<LogBuffer<T>>>,
    allow_unconnected: bool,
    origin: Option<Origin>,
    /// The link to the stream's successor mappings, if the driver gave one
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`).
    link: Option<Arc<GenerationLink<T>>>,
    /// The stream position where this handle's mapping starts.
    base: u64,
    /// The stream lease of a handle from the direct driver API, held only
    /// for its drop.
    _lease: Option<Lease>,
    /// The export of a handle adopted from another process's grant. Last:
    /// it is dropped after the mapping, and its drop sends `Detach`.
    _export: Option<Export>,
}

impl<T: TermBytes> ClientPublication<T> {
    /// Attaches the export of a grant adopted from another process.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    #[must_use]
    pub(crate) fn with_export(mut self, export: Export) -> Self {
        self._export = Some(export);
        self
    }

    /// Wraps the buffer's publication. Connectivity, limits and the lane
    /// are read from the buffer the publication itself appends to.
    #[must_use]
    pub fn new(inner: Publication<Arc<LogBuffer<T>>>, allow_unconnected: bool) -> Self {
        Self {
            inner,
            allow_unconnected,
            origin: None,
            link: None,
            base: 0,
            _lease: None,
            _export: None,
        }
    }

    /// Attaches the generation link the driver keeps for this handle, and
    /// the base of the mapping it uses.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::PositionsExhausted`] when the mapping starting
    /// at `base` could report a position at or above `2^63`; the handle is
    /// then dropped, releasing what it holds.
    pub fn with_generation(
        mut self,
        link: Arc<GenerationLink<T>>,
        base: u64,
    ) -> Result<Self, ClientError> {
        if !representable(base, self.inner.buffer()) {
            return Err(ClientError::PositionsExhausted { base });
        }
        self.link = Some(link);
        self.base = base;
        Ok(self)
    }

    /// The handle's generation link, if any.
    #[must_use]
    pub fn generation_link(&self) -> Option<&Arc<GenerationLink<T>>> {
        self.link.as_ref()
    }

    /// Wraps a publication from the direct driver API; the handle keeps the
    /// stream's lease until it is dropped.
    #[must_use]
    pub fn with_lease(
        inner: Publication<Arc<LogBuffer<T>>>,
        allow_unconnected: bool,
        lease: Lease,
    ) -> Self {
        Self {
            _lease: Some(lease),
            ..Self::new(inner, allow_unconnected)
        }
    }

    /// Wraps a publication handed over through a client conductor; the
    /// handle keeps the stream's lease until it is dropped.
    #[must_use]
    pub fn from_hand_over(
        inner: Publication<Arc<LogBuffer<T>>>,
        allow_unconnected: bool,
        origin: Origin,
    ) -> Self {
        Self {
            origin: Some(origin),
            ..Self::new(inner, allow_unconnected)
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
    /// and lower-layer errors. An error makes no new reservation; a
    /// forgotten claim resolved first may still have published its
    /// `ABORTED` word (see [`ClientPublication::offer_with`]).
    pub fn offer(&mut self, payload: &[u8]) -> Result<OfferOutcome, ClientError> {
        self.offer_with(payload, AppendOptions::default())
    }

    /// Offers one message with header options (EOS, reserved value, an
    /// opaque trace extension).
    ///
    /// A forgotten claim is aborted first, even when the offer then returns
    /// `NotConnected` or an error: that may publish the earlier claim's
    /// `ABORTED` word, but such a return never makes a new reservation.
    ///
    /// # Errors
    ///
    /// As [`ClientPublication::offer`].
    pub fn offer_with(
        &mut self,
        payload: &[u8],
        options: AppendOptions,
    ) -> Result<OfferOutcome, ClientError> {
        // A forgotten claim is resolved before any early return.
        self.inner.resolve_forgotten_claim();
        if !self.connected() {
            // A sealed publication still releases (publication-seal.md).
            if self.inner.close_if_sealed() {
                return Ok(self.after_end().offer());
            }
            return Ok(OfferOutcome::NotConnected);
        }
        Ok(match self.inner.append(payload, options)? {
            AppendOutcome::Appended { position } => OfferOutcome::Accepted {
                lane: self.inner.buffer().lane(),
                position: self.base + position,
            },
            AppendOutcome::BackPressured => OfferOutcome::BackPressured,
            AppendOutcome::AdminAction => OfferOutcome::AdminAction,
            AppendOutcome::Closed => self.after_end().offer(),
        })
    }

    /// Claims one unfragmented block of `length` payload bytes (SPEC.md §4
    /// claims; `quantstratum-docs: karyos/design/client-claims.md`).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyMessage`], [`ClientError::MessageTooLarge`]
    /// (above `max_message_length`, one fragment or the reservation limit)
    /// and lower-layer errors, such as `ResourcesUnavailable` once the claim
    /// record's serial is exhausted. An error makes no new reservation; a
    /// forgotten claim is still resolved first.
    pub fn try_claim(&mut self, length: u32) -> Result<ClaimOutcome<'_, T>, ClientError> {
        self.try_claim_with(length, AppendOptions::default())
    }

    /// Claims with header options (EOS, reserved value, an opaque trace
    /// extension).
    ///
    /// # Errors
    ///
    /// As [`ClientPublication::try_claim`].
    pub fn try_claim_with(
        &mut self,
        length: u32,
        options: AppendOptions,
    ) -> Result<ClaimOutcome<'_, T>, ClientError> {
        // A forgotten claim is resolved before any early return; the
        // connection check only prevents a new reservation.
        self.inner.resolve_forgotten_claim();
        if !self.connected() {
            if self.inner.close_if_sealed() {
                return Ok(self.after_end().claim());
            }
            return Ok(ClaimOutcome::NotConnected);
        }
        // A handle closed by an earlier call moves (or reports the end)
        // here, before the attempt borrows it.
        if self.inner.is_closed() {
            return Ok(self.after_end().claim());
        }
        let lane = self.inner.buffer().lane();
        let base = self.base;
        let link = self.link.as_deref();
        Ok(match self.inner.try_claim(length, options)? {
            SysClaimOutcome::Claimed(inner) => {
                ClaimOutcome::Claimed(ClientClaim { inner, lane, base })
            }
            SysClaimOutcome::BackPressured => ClaimOutcome::BackPressured,
            SysClaimOutcome::AdminAction => ClaimOutcome::AdminAction,
            SysClaimOutcome::Aborted { position } => ClaimOutcome::Aborted {
                lane,
                position: base + position,
            },
            // Just closed: the next call moves, if a successor is coming.
            SysClaimOutcome::Closed => End::peek(link).claim(),
        })
    }

    /// The handle's mapping ended (its sys handle is closed). With a link,
    /// moves to an offered successor, or waits for a pending one; both
    /// report `AdminAction` (SPEC.md §4), and the next attempt publishes on
    /// the successor. Otherwise the publication is closed.
    fn after_end(&mut self) -> End {
        let Some(link) = &self.link else {
            return End::Closed;
        };
        match link.next() {
            Next::Wait => End::Retry,
            Next::Moved {
                base,
                successor: Successor::Publication(inner),
            } => {
                self.inner = inner;
                self.base = base;
                End::Retry
            }
            // A successor of another kind is a driver bug: never used.
            Next::Moved { .. } | Next::End => End::Closed,
        }
    }

    /// The connection rule (SPEC.md §4): one advisory load of the attached
    /// subscriber count, any role counting, unless unconnected use is
    /// allowed.
    fn connected(&self) -> bool {
        self.allow_unconnected || self.inner.buffer().attached_subscribers() > 0
    }
}

impl End {
    fn offer(self) -> OfferOutcome {
        match self {
            End::Retry => OfferOutcome::AdminAction,
            End::Closed => OfferOutcome::Closed,
        }
    }

    fn claim<'a, T: TermBytes>(self) -> ClaimOutcome<'a, T> {
        match self {
            End::Retry => ClaimOutcome::AdminAction,
            End::Closed => ClaimOutcome::Closed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::{Aborted, ClientSubscription, MessageLimit};
    use karyos_sys::log_buffer::{
        ClaimDeadline, Conductor, DEFAULT_CLAIM_DEADLINE, LogBufferConfig, Role,
    };
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    fn lane() -> Lane {
        Lane::try_new(1).unwrap()
    }

    fn setup(
        allow_unconnected: bool,
    ) -> (Arc<LogBuffer>, Conductor<Arc<LogBuffer>>, ClientPublication) {
        let buffer = Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 3,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: lane(),
                session_id: 1,
                stream_id: 2,
                claim_deadline: DEFAULT_CLAIM_DEADLINE,
                publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            })
            .unwrap(),
        );
        let conductor = buffer.conductor_owned().unwrap();
        let publication = ClientPublication::new(
            buffer.publication_owned().unwrap().unwrap(),
            allow_unconnected,
        );
        (buffer, conductor, publication)
    }

    fn claimed(outcome: Result<ClaimOutcome<'_>, ClientError>) -> ClientClaim<'_> {
        match outcome.unwrap() {
            ClaimOutcome::Claimed(claim) => claim,
            other => panic!("not claimed: {other:?}"),
        }
    }

    fn no_delivery(_: &[u8], _: crate::subscription::MessageInfo) {
        panic!("nothing to deliver");
    }

    #[test]
    fn a_sealed_publication_reports_closed_and_readers_reach_the_end() {
        let (buffer, mut conductor, mut publication) = setup(false);
        let mut subscription =
            ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
        assert!(matches!(
            publication.offer(b"last").unwrap(),
            OfferOutcome::Accepted { .. }
        ));
        conductor.seal().unwrap();
        assert_eq!(publication.offer(b"late").unwrap(), OfferOutcome::Closed);
        assert!(matches!(
            publication.try_claim(4).unwrap(),
            ClaimOutcome::Closed
        ));
        let _ = conductor.duty_cycle().unwrap();
        let mut seen = Vec::new();
        let summary = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
            .unwrap();
        assert_eq!(seen, vec![b"last".to_vec()]);
        assert_eq!(summary.delivered, 1);
        let end = summary.closed.unwrap();
        // Repeated: the end is terminal.
        let again = subscription
            .poll(no_delivery, MessageLimit::new(8))
            .unwrap();
        assert_eq!(again.closed, Some(end));
        drop(buffer);
    }

    #[test]
    fn a_sealed_publication_without_subscribers_still_releases() {
        let (_buffer, mut conductor, mut publication) = setup(false);
        conductor.seal().unwrap();
        let _ = conductor.duty_cycle().unwrap();
        assert_eq!(
            conductor.seal_state(),
            karyos_sys::log_buffer::SealState::Sealed
        );
        // Not connected, but sealed: Closed, and the publication released.
        assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::Closed);
        let _ = conductor.duty_cycle().unwrap();
        assert_eq!(
            conductor.seal_state(),
            karyos_sys::log_buffer::SealState::Retired { position: 0 }
        );
        assert!(matches!(
            publication.try_claim(4).unwrap(),
            ClaimOutcome::Closed
        ));
    }

    #[test]
    fn a_claim_is_committed_and_delivered() {
        let (_buffer, mut conductor, mut publication) = setup(false);
        let mut subscription =
            ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
        let mut claim = claimed(publication.try_claim(5));
        assert_eq!(claim.lane(), lane());
        claim.payload().copy_from_slice(b"hello");
        let position = claim.position();
        assert_eq!(
            claim.commit(),
            CommitOutcome::Accepted {
                lane: lane(),
                position,
            }
        );
        let mut seen = Vec::new();
        let summary = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(4))
            .unwrap();
        assert_eq!(summary.delivered, 1);
        assert_eq!(seen, vec![b"hello".to_vec()]);
    }

    #[test]
    fn aborted_dropped_and_forgotten_claims_are_reported_to_subscribers() {
        let (_buffer, mut conductor, mut publication) = setup(false);
        let mut subscription =
            ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
        claimed(publication.try_claim(8)).abort();
        drop(claimed(publication.try_claim(40)));
        core::mem::forget(claimed(publication.try_claim(8)));
        // Connected: the next call resolves the forgotten claim, then offers.
        assert!(matches!(
            publication.offer(b"next").unwrap(),
            OfferOutcome::Accepted { .. }
        ));
        for (position, extent) in [(0, 64), (64, 96), (160, 64)] {
            let summary = subscription
                .poll(no_delivery, MessageLimit::new(4))
                .unwrap();
            assert_eq!(summary.aborted, Some(Aborted { position, extent }));
        }
        let mut seen = Vec::new();
        let _ = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(4))
            .unwrap();
        assert_eq!(seen, vec![b"next".to_vec()]);
    }

    #[test]
    fn not_connected_still_resolves_a_forgotten_claim() {
        for offer in [false, true] {
            let (buffer, mut conductor, mut publication) = setup(false);
            let subscription = conductor.subscribe(Role::Optional).unwrap();
            core::mem::forget(claimed(publication.try_claim(8)));
            assert_eq!(
                conductor.abort_expired_claims(0).unwrap(),
                ClaimDeadline::Waiting
            );
            // The last subscriber leaves.
            drop(subscription);
            assert_eq!(buffer.attached_subscribers(), 0);
            if offer {
                assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::NotConnected);
            } else {
                assert!(matches!(
                    publication.try_claim(8).unwrap(),
                    ClaimOutcome::NotConnected
                ));
            }
            // Resolved before the early return: the record is gone even at
            // the latest representable time, and nothing new was reserved.
            assert_eq!(
                conductor.abort_expired_claims(u64::MAX).unwrap(),
                ClaimDeadline::Idle
            );
            let probe = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
            assert_eq!(
                probe.position(),
                64,
                "the head moved past the forgotten claim only"
            );
            drop(probe);
        }
    }

    #[test]
    fn a_claim_admitted_while_connected_commits_after_a_detach() {
        let (_buffer, mut conductor, mut publication) = setup(false);
        let subscription = conductor.subscribe(Role::Optional).unwrap();
        let mut claim = claimed(publication.try_claim(3));
        drop(subscription);
        claim.payload().copy_from_slice(b"abc");
        assert!(matches!(claim.commit(), CommitOutcome::Accepted { .. }));
        assert!(matches!(
            publication.try_claim(3).unwrap(),
            ClaimOutcome::NotConnected
        ));
    }

    #[test]
    fn unconnected_claims_are_allowed_when_configured() {
        let (_buffer, _conductor, mut publication) = setup(true);
        let claim = claimed(publication.try_claim(8));
        assert!(matches!(claim.commit(), CommitOutcome::Accepted { .. }));
    }

    #[test]
    fn claim_sizes_are_checked() {
        let (_buffer, _conductor, mut publication) = setup(true);
        assert!(matches!(
            publication.try_claim(0),
            Err(ClientError::EmptyMessage)
        ));
        assert!(matches!(
            publication.try_claim(DEFAULT_MTU),
            Err(ClientError::MessageTooLarge { .. })
        ));
    }
}
