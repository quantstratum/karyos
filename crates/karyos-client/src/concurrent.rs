// SPDX-License-Identifier: Apache-2.0

//! The embedded concurrent publication (SPEC.md §4 concurrent publication;
//! `quantstratum-docs: karyos/design/client-concurrent-publication.md`).

use std::sync::Arc;

use karyos_sys::conflation::{ConflationConfig, ConflationError};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::ConflationShape;
use karyos_sys::log_buffer::{
    AppendOptions, CommitOutcome as SysCommitOutcome, ConcurrentClaim,
    ConcurrentClaimOutcome as SysClaimOutcome, ConcurrentOfferOutcome as SysOfferOutcome,
    ConcurrentPublication, LogBuffer,
};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use karyos_protocol::frame::TraceExtension;
use karyos_protocol::trace_hook::{PublicationIdentity, TraceHook};

use crate::error::ClientError;
use crate::generation::{
    End, GenerationLink, Next, Retired, RetiredHandle, Successor, representable,
};
use crate::link::{Export, Lease, Origin};
use crate::publication::CommitOutcome;
use crate::trace::{PublishTrace, TraceDecision};

/// Result of [`ClientConcurrentPublication::offer`]. Each call performs at
/// most one reservation attempt and one rotation attempt; nothing is
/// retried silently. Embedded API, provisional, as
/// [`crate::OfferOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "back pressure, aborts and admin actions must be handled"]
#[non_exhaustive]
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
    /// The stream is sealed: the handle accepts nothing again
    /// (`quantstratum-docs: karyos/design/publication-seal.md`).
    Closed,
}

/// Result of [`ClientConcurrentPublication::try_claim`]. Embedded API,
/// provisional, as [`ConcurrentOfferOutcome`].
#[derive(Debug)]
#[must_use = "back pressure, aborts and admin actions must be handled"]
#[non_exhaustive]
pub enum ConcurrentClaimOutcome<'a, T: TermBytes = HeapTerms> {
    /// A block was reserved and marked; write the payload, then commit.
    Claimed(ClientConcurrentClaim<'a, T>),
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
    /// The stream is sealed: the handle reserves nothing again
    /// (`quantstratum-docs: karyos/design/publication-seal.md`).
    Closed,
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
pub struct ClientConcurrentClaim<'a, T: TermBytes = HeapTerms> {
    inner: ConcurrentClaim<'a, Arc<LogBuffer<T>>>,
    lane: Lane,
    /// The base of the claim's mapping generation.
    base: u64,
    /// The handle's trace and the claim's extension, for a traced claim.
    trace: Option<(&'a mut PublishTrace, TraceExtension)>,
}

impl<T: TermBytes> ClientConcurrentClaim<'_, T> {
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

    /// Commits the block: exactly one of commit and abort wins. A traced
    /// claim records its `Publish` observation after a winning commit; an
    /// aborted one records nothing.
    pub fn commit(self) -> CommitOutcome {
        let (lane, base) = (self.lane, self.base);
        match self.inner.commit() {
            SysCommitOutcome::Committed { position } => {
                let position = base + position;
                if let Some((trace, extension)) = self.trace {
                    trace.committed(&extension, lane, position);
                }
                CommitOutcome::Accepted { lane, position }
            }
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

/// One concurrent publication handle on a stream: one of the stream's `P`
/// publisher slots. Each publishing thread holds its own handle.
#[derive(Debug)]
pub struct ClientConcurrentPublication<T: TermBytes = HeapTerms> {
    // Declared first: the sys handle frees its publisher slot before the
    // stream lease below ends.
    inner: ConcurrentPublication<Arc<LogBuffer<T>>>,
    allow_unconnected: bool,
    origin: Option<Origin>,
    /// The link to the stream's successor mappings, if the driver gave one
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`).
    link: Option<Arc<GenerationLink<T>>>,
    /// The stream position where this handle's mapping starts.
    base: u64,
    /// The trace hook and publication identity, for a traced handle.
    trace: Option<PublishTrace>,
    /// Limits for the stream's conflated view, when configured by the driver.
    /// The table's shape, or why the one `with_conflation` was given has
    /// none: every keyed offer and claim then fails with it.
    conflation: Option<Result<ConflationShape, ConflationError>>,
    /// The stream lease of a handle from the direct driver API, held only
    /// for its drop.
    _lease: Option<Lease>,
    /// The export of a handle adopted from another process's grant. Last:
    /// it is dropped after the mapping, and its drop sends `Detach`.
    _export: Option<Export>,
}

impl<T: TermBytes> ClientConcurrentPublication<T> {
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

    /// Wraps a concurrent handle. Connectivity, limits and the lane are
    /// read from the buffer the handle publishes to.
    #[must_use]
    pub fn new(inner: ConcurrentPublication<Arc<LogBuffer<T>>>, allow_unconnected: bool) -> Self {
        let conflation = inner.buffer().conflation().map(Ok);
        Self {
            inner,
            allow_unconnected,
            origin: None,
            link: None,
            base: 0,
            trace: None,
            conflation,
            _lease: None,
            _export: None,
        }
    }

    /// Binds keyed conflation limits to this publication, in place of the
    /// table its buffer carries: every publication of a conflated stream
    /// already reads its stream's from the buffer (F7b-2c-2), in process
    /// or attached, so this is for tests and for buffers built without one.
    /// A `config` whose value capacity has no shape (past `u32`) is kept as
    /// its refusal: every later offer and claim fails with it.
    #[must_use]
    pub fn with_conflation(mut self, config: ConflationConfig) -> Self {
        self.conflation = Some(config.shape());
        self
    }

    /// Why the stream was sealed, once an attempt returned `Closed`; `None`
    /// while the handle is open.
    #[must_use]
    pub fn seal_reason(&self) -> Option<karyos_sys::log_buffer::SealReason> {
        self.inner.seal_reason()
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

    /// Wraps a handle from the direct driver API; it keeps the stream's
    /// lease until it is dropped.
    #[must_use]
    pub fn with_lease(
        inner: ConcurrentPublication<Arc<LogBuffer<T>>>,
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
        inner: ConcurrentPublication<Arc<LogBuffer<T>>>,
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
            // A sealed handle still releases (publication-seal.md).
            if self.inner.close_if_sealed().is_some() {
                return Ok(self.after_end().concurrent_offer());
            }
            return Ok(ConcurrentOfferOutcome::NotConnected);
        }
        if let Some(shape) = self.conflation {
            shape?.validate_publication(options.reserved_value, payload.len())?;
        }
        let lane = self.inner.buffer().lane();
        match offer_outcome(self.inner.offer(payload, options)?, lane, self.base) {
            ConcurrentOfferOutcome::Closed => Ok(self.after_end().concurrent_offer()),
            outcome => Ok(outcome),
        }
    }

    /// Traces this handle's messages through `hook`, which records them for
    /// the publication `identity` (control path).
    #[must_use]
    pub fn with_trace(mut self, hook: Box<dyn TraceHook>, identity: PublicationIdentity) -> Self {
        self.trace = Some(PublishTrace::new(hook, identity));
        self
    }

    /// Whether the handle has a trace hook.
    #[must_use]
    pub fn is_traced(&self) -> bool {
        self.trace.is_some()
    }

    /// Control path: lets the hook refill what the data path consumes.
    pub fn trace_maintenance(&mut self) {
        if let Some(trace) = &mut self.trace {
            trace.maintain();
        }
    }

    /// Decides once whether to trace a logical message caused by `parent`;
    /// pass the decision to every attempt of that message.
    pub fn trace_message(&mut self, parent: Option<&TraceExtension>) -> TraceDecision {
        let lane = self.inner.buffer().lane();
        match &mut self.trace {
            Some(trace) => trace.decide(parent, lane),
            None => TraceDecision::UNTRACED,
        }
    }

    /// Offers one message with `decision`'s extension in every fragment; an
    /// accepted traced message records its `Publish` observation. Any other
    /// return appended nothing: retry with the same decision.
    ///
    /// # Errors
    ///
    /// As [`ClientConcurrentPublication::offer`].
    pub fn offer_with_trace(
        &mut self,
        payload: &[u8],
        decision: &TraceDecision,
    ) -> Result<ConcurrentOfferOutcome, ClientError> {
        let options = AppendOptions {
            extension: decision.bytes(),
            ..AppendOptions::default()
        };
        let outcome = self.offer_with(payload, options)?;
        if let (ConcurrentOfferOutcome::Accepted { lane, position }, Some(extension), Some(trace)) =
            (outcome, decision.extension(), &mut self.trace)
        {
            trace.committed(&extension, lane, position);
        }
        Ok(outcome)
    }

    /// Claims with `decision`'s extension; the claim records the `Publish`
    /// observation when its commit wins.
    ///
    /// # Errors
    ///
    /// As [`ClientConcurrentPublication::try_claim`].
    pub fn try_claim_with_trace(
        &mut self,
        length: u32,
        decision: &TraceDecision,
    ) -> Result<ConcurrentClaimOutcome<'_, T>, ClientError> {
        let options = AppendOptions {
            extension: decision.bytes(),
            ..AppendOptions::default()
        };
        self.claim(length, options, decision.extension())
    }

    /// Claims one unfragmented block of `length` payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EmptyMessage`], [`ClientError::MessageTooLarge`]
    /// (above `max_message_length`, one fragment or the reservation limit)
    /// and lower-layer errors. A validation error makes no new
    /// reservation; a forgotten claim is still resolved first.
    pub fn try_claim(&mut self, length: u32) -> Result<ConcurrentClaimOutcome<'_, T>, ClientError> {
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
    ) -> Result<ConcurrentClaimOutcome<'_, T>, ClientError> {
        self.claim(length, options, None)
    }

    /// One claim attempt; a traced claim carries the handle's trace.
    fn claim(
        &mut self,
        length: u32,
        options: AppendOptions,
        extension: Option<TraceExtension>,
    ) -> Result<ConcurrentClaimOutcome<'_, T>, ClientError> {
        // A forgotten claim is resolved before any early return; the
        // connection check only prevents a new reservation.
        self.inner.resolve_forgotten_claim();
        if !self.connected() {
            if self.inner.close_if_sealed().is_some() {
                return Ok(self.after_end().concurrent_claim());
            }
            return Ok(ConcurrentClaimOutcome::NotConnected);
        }
        // A handle closed by an earlier call moves (or reports the end)
        // here, before the attempt borrows it.
        if self.inner.is_closed() {
            return Ok(self.after_end().concurrent_claim());
        }
        if let Some(shape) = self.conflation {
            let shape = shape?;
            // A claim length no usize of this target holds is no value it
            // can carry.
            let value_length =
                usize::try_from(length).map_err(|_| ConflationError::InvalidConfig)?;
            shape.validate_publication(options.reserved_value, value_length)?;
        }
        let lane = self.inner.buffer().lane();
        let base = self.base;
        let end = End::peek(self.link.as_deref());
        let trace = match (extension, &mut self.trace) {
            (Some(extension), Some(trace)) => Some((trace, extension)),
            _ => None,
        };
        Ok(claim_outcome(
            self.inner.try_claim(length, options)?,
            lane,
            base,
            end,
            trace,
        ))
    }

    /// The handle's mapping ended (its sys handle is closed). With a link,
    /// moves to an offered successor, or waits for a pending one; both
    /// report `AdminAction` (SPEC.md §4). Otherwise the handle is closed.
    fn after_end(&mut self) -> End {
        let Some(link) = &self.link else {
            return End::Closed;
        };
        match link.next(self.inner.buffer().sealed_with_successor()) {
            Next::Wait => End::Retry,
            Next::Moved {
                base,
                successor: Successor::Concurrent(inner),
            } => {
                self.inner = inner;
                self.base = base;
                End::Retry
            }
            // A remote successor is activated here, without allocating; the
            // predecessor waits in the link for the control path.
            Next::Moved {
                base,
                successor: Successor::PreparedConcurrent { prepared, export },
            } => match prepared.activate() {
                Ok(inner) => {
                    let predecessor = core::mem::replace(&mut self.inner, inner);
                    let predecessor_export = self._export.replace(export);
                    self.base = base;
                    link.retire(Retired {
                        _handle: Some(RetiredHandle::Concurrent(predecessor)),
                        _export: predecessor_export,
                    });
                    End::Retry
                }
                // The driver's fence won: this mapping is the last.
                Err(refused) => {
                    link.fail_activation(match refused.prepared {
                        Some(prepared) => Retired {
                            _handle: Some(RetiredHandle::Successor(
                                Successor::PreparedConcurrent { prepared, export },
                            )),
                            _export: None,
                        },
                        None => Retired {
                            _handle: None,
                            _export: Some(export),
                        },
                    });
                    End::Closed
                }
            },
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
    fn concurrent_offer(self) -> ConcurrentOfferOutcome {
        match self {
            End::Retry => ConcurrentOfferOutcome::AdminAction,
            End::Closed => ConcurrentOfferOutcome::Closed,
        }
    }

    fn concurrent_claim<'a, T: TermBytes>(self) -> ConcurrentClaimOutcome<'a, T> {
        match self {
            End::Retry => ConcurrentClaimOutcome::AdminAction,
            End::Closed => ConcurrentClaimOutcome::Closed,
        }
    }
}

/// The sys offer outcome on the buffer's lane.
fn offer_outcome(outcome: SysOfferOutcome, lane: Lane, base: u64) -> ConcurrentOfferOutcome {
    match outcome {
        SysOfferOutcome::Appended { position } => ConcurrentOfferOutcome::Accepted {
            lane,
            position: base + position,
        },
        SysOfferOutcome::Aborted { position } => ConcurrentOfferOutcome::Aborted {
            lane,
            position: base + position,
        },
        SysOfferOutcome::BackPressured => ConcurrentOfferOutcome::BackPressured,
        SysOfferOutcome::AdminAction => ConcurrentOfferOutcome::AdminAction,
        SysOfferOutcome::Closed => ConcurrentOfferOutcome::Closed,
    }
}

/// The sys claim outcome on the buffer's lane.
/// `end` is what a just-closed handle reports: the next call moves.
fn claim_outcome<'a, T: TermBytes>(
    outcome: SysClaimOutcome<'a, Arc<LogBuffer<T>>>,
    lane: Lane,
    base: u64,
    end: End,
    trace: Option<(&'a mut PublishTrace, TraceExtension)>,
) -> ConcurrentClaimOutcome<'a, T> {
    match outcome {
        SysClaimOutcome::Claimed(inner) => ConcurrentClaimOutcome::Claimed(ClientConcurrentClaim {
            inner,
            lane,
            base,
            trace,
        }),
        SysClaimOutcome::BackPressured => ConcurrentClaimOutcome::BackPressured,
        SysClaimOutcome::AdminAction => ConcurrentClaimOutcome::AdminAction,
        SysClaimOutcome::Aborted { position } => ConcurrentClaimOutcome::Aborted {
            lane,
            position: base + position,
        },
        SysClaimOutcome::Closed => end.concurrent_claim(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::log_buffer::{
        Conductor, DEFAULT_CLAIM_DEADLINE, LogBufferConfig, PublicationMode, Role,
    };
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    // The `Aborted` arms are reached only when the conductor's deadline
    // abort wins between a writer's `fetch_add` and its mark or commit,
    // which the sys tests drive with pause points; the mapping is checked
    // here, the race in karyos-sys.
    #[test]
    fn every_sys_outcome_gains_the_base_and_the_lane() {
        let lane = Lane::try_new(3).unwrap();
        assert_eq!(
            offer_outcome(SysOfferOutcome::Appended { position: 64 }, lane, 1000),
            ConcurrentOfferOutcome::Accepted {
                lane,
                position: 1064
            }
        );
        assert_eq!(
            offer_outcome(SysOfferOutcome::Aborted { position: 96 }, lane, 1000),
            ConcurrentOfferOutcome::Aborted {
                lane,
                position: 1096
            }
        );
        assert_eq!(
            offer_outcome(SysOfferOutcome::BackPressured, lane, 1000),
            ConcurrentOfferOutcome::BackPressured
        );
        assert_eq!(
            offer_outcome(SysOfferOutcome::AdminAction, lane, 1000),
            ConcurrentOfferOutcome::AdminAction
        );
        assert!(matches!(
            claim_outcome::<HeapTerms>(SysClaimOutcome::Aborted { position: 128 }, lane, 1000, End::Closed, None),
            ConcurrentClaimOutcome::Aborted { lane: l, position: 1128 } if l == lane
        ));
        assert!(matches!(
            claim_outcome::<HeapTerms>(
                SysClaimOutcome::BackPressured,
                lane,
                1000,
                End::Closed,
                None
            ),
            ConcurrentClaimOutcome::BackPressured
        ));
        assert!(matches!(
            claim_outcome::<HeapTerms>(SysClaimOutcome::AdminAction, lane, 1000, End::Closed, None),
            ConcurrentClaimOutcome::AdminAction
        ));
        assert_eq!(
            offer_outcome(SysOfferOutcome::Closed, lane, 1000),
            ConcurrentOfferOutcome::Closed
        );
        assert!(matches!(
            claim_outcome::<HeapTerms>(SysClaimOutcome::Closed, lane, 1000, End::Closed, None),
            ConcurrentClaimOutcome::Closed
        ));
        // A cutover is coming: the just-closed handle retries.
        assert!(matches!(
            claim_outcome::<HeapTerms>(SysClaimOutcome::Closed, lane, 1000, End::Retry, None),
            ConcurrentClaimOutcome::AdminAction
        ));
    }

    #[test]
    fn handles_can_move_to_publishing_threads() {
        fn send<T: Send>() {}
        send::<ClientConcurrentPublication>();
    }

    #[test]
    fn conflated_concurrent_offers_validate_before_reserving() {
        let buffer = Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 3,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Concurrent {
                    publishers: 1,
                    allow_non_lse: true,
                },
                schedule_capacity: 0,
            })
            .unwrap(),
        );
        let mut conductor: Conductor<Arc<LogBuffer>> = buffer.conductor_owned().unwrap();
        let inner = conductor.concurrent_publication().unwrap().unwrap();
        let mut publication =
            ClientConcurrentPublication::new(inner, true).with_conflation(ConflationConfig {
                keys: 2,
                value_capacity: 4,
                journal_capacity: 1024,
            });
        let subscription = conductor.subscribe(Role::Required).unwrap();
        let client_subscription = crate::ClientSubscription::new(subscription);

        assert!(matches!(
            publication.offer_with(
                b"x",
                AppendOptions {
                    reserved_value: i64::from(u32::MAX) + 1,
                    ..AppendOptions::default()
                }
            ),
            Err(ClientError::Conflation(
                karyos_sys::conflation::ConflationError::KeyOutOfRange { .. }
            ))
        ));
        assert!(matches!(
            publication.offer_with(
                b"oversize",
                AppendOptions {
                    reserved_value: 1,
                    ..AppendOptions::default()
                }
            ),
            Err(ClientError::Conflation(
                karyos_sys::conflation::ConflationError::ValueTooLarge { length: 8, max: 4 }
            ))
        ));
        assert_eq!(client_subscription.position(), 0);
        assert!(matches!(
            publication
                .offer_with(
                    b"ok",
                    AppendOptions {
                        reserved_value: 1,
                        ..AppendOptions::default()
                    }
                )
                .unwrap(),
            ConcurrentOfferOutcome::Accepted { position: 0, .. }
        ));
    }

    fn concurrent_buffer() -> Arc<LogBuffer> {
        Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 3,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Concurrent {
                    publishers: 2,
                    allow_non_lse: true,
                },
                schedule_capacity: 0,
            })
            .unwrap(),
        )
    }

    /// Counts the drops of the exports it marks.
    struct DropMark(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for DropMark {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn a_remote_concurrent_publication_activates_or_closes_at_the_seal() {
        for fenced in [false, true] {
            let predecessor = concurrent_buffer();
            let mut conductor: Conductor<Arc<LogBuffer>> = predecessor.conductor_owned().unwrap();
            let link = GenerationLink::new_remote();
            let detached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut publication = ClientConcurrentPublication::new(
                conductor.concurrent_publication().unwrap().unwrap(),
                true,
            )
            .with_generation(Arc::clone(&link), 0)
            .unwrap()
            .with_export(crate::link::Export::new(DropMark(Arc::clone(&detached))));
            conductor.seal_for_cutover().unwrap();
            assert_eq!(
                publication.offer(b"late").unwrap(),
                ConcurrentOfferOutcome::AdminAction,
                "an unresolved seal is pending"
            );
            let successor = concurrent_buffer();
            let mut successor_conductor: Conductor<Arc<LogBuffer>> =
                successor.conductor_owned().unwrap();
            let slot = successor_conductor
                .register_concurrent_publication(7)
                .unwrap()
                .unwrap();
            let prepared =
                ConcurrentPublication::prepare_adopt(Arc::clone(&successor), slot, 7).unwrap();
            if fenced {
                assert!(successor_conductor.fence_concurrent_publication(slot, 7));
            }
            link.offer(
                1 << 20,
                Successor::PreparedConcurrent {
                    prepared,
                    export: crate::link::Export::new(DropMark(Arc::clone(&detached))),
                },
            )
            .unwrap();
            if fenced {
                assert_eq!(
                    publication.offer(b"late").unwrap(),
                    ConcurrentOfferOutcome::Closed
                );
                assert_eq!(link.status(), crate::LinkStatus::Closed);
            } else {
                // Neither the move nor the first offer on the successor
                // allocates or frees.
                let (moved, operations) =
                    karyos_sys::alloc_count::count(|| publication.offer(b"late"));
                assert_eq!(moved.unwrap(), ConcurrentOfferOutcome::AdminAction);
                assert_eq!(operations, 0, "the move allocated or freed");
                let (accepted, operations) =
                    karyos_sys::alloc_count::count(|| publication.offer(b"late"));
                assert!(matches!(
                    accepted.unwrap(),
                    ConcurrentOfferOutcome::Accepted { position, .. } if position == 1 << 20
                ));
                assert_eq!(operations, 0);
            }
            assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 0);
            drop(link.take_retired());
            assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
    }
}
