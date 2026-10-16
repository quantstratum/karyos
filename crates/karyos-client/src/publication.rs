// SPDX-License-Identifier: Apache-2.0

//! The embedded publication (SPEC.md §4 and §10, `offer`).

use std::sync::Arc;

use karyos_sys::conflation::ConflationConfig;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, AppendOutcome, Claim, ClaimOutcome as SysClaimOutcome,
    CommitOutcome as SysCommitOutcome, LogBuffer, Publication,
};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use karyos_protocol::frame::TraceExtension;
use karyos_protocol::trace_hook::{PublicationIdentity, TraceHook};

use crate::error::ClientError;
use crate::generation::{
    End, GenerationLink, Next, Retired, RetiredHandle, Successor, representable,
};
use crate::guarded::{Admission, GuardBinding};
use crate::link::{Export, Lease, Origin};
use crate::trace::{PublishTrace, TraceDecision};

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
    /// The publication's guard closed, or a scheduled message missed its
    /// deadline: the incarnation ended and accepts nothing again; after a
    /// reopen the application takes a new publication
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, GC-8).
    Gated,
    /// The publication's rate limit holds no token for another message;
    /// nothing was appended, retry later. An early rejection by the
    /// handle's copy of the limit; the driver's sender gate is
    /// authoritative (`quantstratum-docs:
    /// karyos/design/guards-and-abort.md`, Rate limits).
    RateLimited,
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
    /// The publication's guard closed or a deadline was missed, as
    /// [`OfferOutcome::Gated`].
    Gated,
    /// The rate limit holds no token for another message, as
    /// [`OfferOutcome::RateLimited`]; nothing reserved.
    RateLimited,
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
    /// The handle's trace and the claim's extension, for a traced claim.
    trace: Option<(&'a mut PublishTrace, TraceExtension)>,
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
    /// The trace hook and publication identity, for a traced handle.
    trace: Option<PublishTrace>,
    /// Limits for the stream's conflated view, when configured by the driver.
    conflation: Option<ConflationConfig>,
    /// The stream lease of a handle from the direct driver API, held only
    /// for its drop.
    _lease: Option<Lease>,
    /// The guard and outcome ring of a guarded handle (`quantstratum-docs:
    /// karyos/design/guards-and-abort.md`).
    guard: Option<GuardBinding>,
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
            trace: None,
            conflation: None,
            _lease: None,
            guard: None,
            _export: None,
        }
    }

    /// Binds the handle to its guard and outcome ring. The driver calls
    /// this while issuing a guarded publication; callers should normally
    /// obtain handles from the driver.
    #[must_use]
    pub fn with_guard(mut self, binding: GuardBinding) -> Self {
        self.guard = Some(binding);
        self
    }

    /// The guard binding of a guarded handle.
    #[must_use]
    pub fn guard(&self) -> Option<&GuardBinding> {
        self.guard.as_ref()
    }

    /// Reads up to `limit` outcome records of a guarded handle in sequence
    /// order (see [`GuardBinding::poll_outcomes`]); 0 for an unguarded one.
    ///
    /// # Errors
    ///
    /// [`ClientError::Outcomes`] for a corrupt record.
    pub fn poll_outcomes(
        &mut self,
        limit: usize,
        handler: impl FnMut(u64, karyos_sys::outcome_ring::Record),
    ) -> Result<usize, ClientError> {
        match &mut self.guard {
            Some(binding) => binding.poll_outcomes(limit, handler),
            None => Ok(0),
        }
    }

    /// Binds the stream's keyed conflation limits to this publication.
    /// The driver calls this while issuing a publication for a conflated
    /// stream; callers should normally obtain handles from the driver.
    #[must_use]
    pub fn with_conflation(mut self, config: ConflationConfig) -> Self {
        self.conflation = Some(config);
        self
    }

    /// Why the stream was sealed, once an attempt returned `Closed`; `None`
    /// while the handle is open.
    #[must_use]
    pub fn seal_reason(&self) -> Option<karyos_sys::log_buffer::SealReason> {
        self.inner.seal_reason()
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

    /// Control path: lets the hook refill what the data path consumes. Call
    /// it from the handle's thread in the application's control loop.
    pub fn trace_maintenance(&mut self) {
        if let Some(trace) = &mut self.trace {
            trace.maintain();
        }
    }

    /// Decides once whether to trace a logical message caused by `parent`
    /// (the trace context of the message being handled, if any). Pass the
    /// decision to every attempt of that message; without a hook the
    /// message is untraced.
    pub fn trace_message(&mut self, parent: Option<&TraceExtension>) -> TraceDecision {
        let lane = self.inner.buffer().lane();
        match &mut self.trace {
            Some(trace) => trace.decide(parent, lane),
            None => TraceDecision::UNTRACED,
        }
    }

    /// Offers one message with `decision`'s extension in every fragment. A
    /// return other than `Accepted` appended nothing: retry with the same
    /// decision. An accepted traced message records its `Publish`
    /// observation.
    ///
    /// # Errors
    ///
    /// As [`ClientPublication::offer`]; the extension is part of the
    /// message size.
    pub fn offer_with_trace(
        &mut self,
        payload: &[u8],
        decision: &TraceDecision,
    ) -> Result<OfferOutcome, ClientError> {
        let options = AppendOptions {
            extension: decision.bytes(),
            ..AppendOptions::default()
        };
        let outcome = self.offer_with(payload, options)?;
        if let (OfferOutcome::Accepted { lane, position }, Some(extension), Some(trace)) =
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
    /// As [`ClientPublication::try_claim`].
    pub fn try_claim_with_trace(
        &mut self,
        length: u32,
        decision: &TraceDecision,
    ) -> Result<ClaimOutcome<'_, T>, ClientError> {
        let options = AppendOptions {
            extension: decision.bytes(),
            ..AppendOptions::default()
        };
        self.claim(length, options, decision.extension())
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
        let admission = self.guard.as_ref().map(GuardBinding::admission);
        if let Some(refused) = admission.filter(|admission| *admission != Admission::Open) {
            // A sealed handle releases first and reports its seal
            // (publication-seal.md: a guard seal reports `Gated` and
            // releases), whatever the guard check says.
            if let Some(reason) = self.inner.close_if_sealed() {
                if reason.is_gate() {
                    return Ok(OfferOutcome::Gated);
                }
                return Ok(self.after_end().offer());
            }
            return match refused {
                Admission::Lost => Err(ClientError::OutcomesLost),
                Admission::BackPressured => Ok(OfferOutcome::BackPressured),
                Admission::Gated | Admission::Open => Ok(OfferOutcome::Gated),
            };
        }
        if !self.connected() {
            // A sealed publication still releases (publication-seal.md);
            // a guard or deadline seal is `Gated` (GC-8).
            if let Some(reason) = self.inner.close_if_sealed() {
                if reason.is_gate() {
                    return Ok(OfferOutcome::Gated);
                }
                return Ok(self.after_end().offer());
            }
            return Ok(OfferOutcome::NotConnected);
        }
        if let Some(config) = self.conflation {
            config.validate_publication(options.reserved_value, payload.len())?;
        }
        // The rate copy is asked last, so it refuses only a message that
        // would otherwise be appended.
        if let Some(binding) = &mut self.guard
            && !binding.rate_admits()
        {
            return Ok(OfferOutcome::RateLimited);
        }
        Ok(match self.inner.append(payload, options)? {
            AppendOutcome::Appended { position } => {
                // An accepted message gets exactly one final record, and
                // takes one token of the rate copy.
                if let Some(binding) = &mut self.guard {
                    binding.reserve();
                    binding.charge_rate();
                }
                OfferOutcome::Accepted {
                    lane: self.inner.buffer().lane(),
                    position: self.base + position,
                }
            }
            AppendOutcome::BackPressured => OfferOutcome::BackPressured,
            AppendOutcome::AdminAction => OfferOutcome::AdminAction,
            AppendOutcome::Closed => self.after_end().offer(),
            AppendOutcome::Gated => OfferOutcome::Gated,
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
        self.claim(length, options, None)
    }

    /// One claim attempt; a traced claim carries the handle's trace.
    fn claim(
        &mut self,
        length: u32,
        options: AppendOptions,
        extension: Option<TraceExtension>,
    ) -> Result<ClaimOutcome<'_, T>, ClientError> {
        // A forgotten claim is resolved before any early return; the
        // connection check only prevents a new reservation.
        self.inner.resolve_forgotten_claim();
        let admission = self.guard.as_ref().map(GuardBinding::admission);
        if let Some(refused) = admission.filter(|admission| *admission != Admission::Open) {
            // As in `offer_with`: a sealed handle releases first.
            if let Some(reason) = self.inner.close_if_sealed() {
                if reason.is_gate() {
                    return Ok(ClaimOutcome::Gated);
                }
                return Ok(self.after_end().claim());
            }
            return match refused {
                Admission::Lost => Err(ClientError::OutcomesLost),
                Admission::BackPressured => Ok(ClaimOutcome::BackPressured),
                Admission::Gated | Admission::Open => Ok(ClaimOutcome::Gated),
            };
        }
        if !self.connected() {
            if let Some(reason) = self.inner.close_if_sealed() {
                if reason.is_gate() {
                    return Ok(ClaimOutcome::Gated);
                }
                return Ok(self.after_end().claim());
            }
            return Ok(ClaimOutcome::NotConnected);
        }
        // A handle closed by an earlier call moves (or reports the end)
        // here, before the attempt borrows it; a guard or deadline seal has
        // no successor and stays `Gated`.
        if self.inner.is_closed() {
            if self
                .inner
                .seal_reason()
                .is_some_and(karyos_sys::log_buffer::SealReason::is_gate)
            {
                return Ok(ClaimOutcome::Gated);
            }
            return Ok(self.after_end().claim());
        }
        if let Some(config) = self.conflation {
            let value_length = usize::try_from(length).map_err(|_| {
                ClientError::from(karyos_sys::conflation::ConflationError::ValueTooLarge {
                    length: usize::MAX,
                    max: config.value_capacity,
                })
            })?;
            config.validate_publication(options.reserved_value, value_length)?;
        }
        if let Some(binding) = &mut self.guard
            && !binding.rate_admits()
        {
            return Ok(ClaimOutcome::RateLimited);
        }
        let lane = self.inner.buffer().lane();
        let base = self.base;
        let link = self.link.as_deref();
        let guard = self.guard.as_mut();
        let trace = match (extension, &mut self.trace) {
            (Some(extension), Some(trace)) => Some((trace, extension)),
            _ => None,
        };
        let outcome = self.inner.try_claim(length, options)?;
        if let Some(binding) = guard
            && reserves(&outcome)
        {
            binding.reserve();
            if matches!(outcome, SysClaimOutcome::Claimed(_)) {
                binding.charge_rate();
            }
        }
        Ok(match outcome {
            SysClaimOutcome::Claimed(inner) => ClaimOutcome::Claimed(ClientClaim {
                inner,
                lane,
                base,
                trace,
            }),
            SysClaimOutcome::BackPressured => ClaimOutcome::BackPressured,
            SysClaimOutcome::AdminAction => ClaimOutcome::AdminAction,
            SysClaimOutcome::Aborted { position } => ClaimOutcome::Aborted {
                lane,
                position: base + position,
            },
            // Just closed: the next call moves, if a successor is coming.
            SysClaimOutcome::Closed => End::peek(link).claim(),
            SysClaimOutcome::Gated => ClaimOutcome::Gated,
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
        match link.next(self.inner.buffer().sealed_with_successor()) {
            Next::Wait => End::Retry,
            Next::Moved {
                base,
                successor: Successor::Publication(inner),
            } => {
                self.inner = inner;
                self.base = base;
                End::Retry
            }
            // A remote successor is activated here, without allocating; the
            // predecessor waits in the link for the control path.
            Next::Moved {
                base,
                successor: Successor::PreparedPublication { prepared, export },
            } => match prepared.activate() {
                Ok(inner) => {
                    let predecessor = core::mem::replace(&mut self.inner, inner);
                    let predecessor_export = self._export.replace(export);
                    self.base = base;
                    link.retire(Retired {
                        _handle: Some(RetiredHandle::Publication(predecessor)),
                        _export: predecessor_export,
                    });
                    End::Retry
                }
                // The driver's fence won: this mapping is the last.
                Err(refused) => {
                    link.fail_activation(match refused.prepared {
                        Some(prepared) => Retired {
                            _handle: Some(RetiredHandle::Successor(
                                Successor::PreparedPublication { prepared, export },
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

/// Whether a claim attempt reserved a block of the log: a claimed block,
/// committed or aborted later, and a reservation aborted at once each get
/// exactly one final outcome record.
fn reserves<T: TermBytes>(outcome: &SysClaimOutcome<'_, Arc<LogBuffer<T>>>) -> bool {
    matches!(
        outcome,
        SysClaimOutcome::Claimed(_) | SysClaimOutcome::Aborted { .. }
    )
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

    #[test]
    fn conflated_offers_and_claims_validate_before_reserving() {
        let (buffer, mut conductor, publication) = setup(true);
        let mut publication = publication.with_conflation(ConflationConfig {
            keys: 2,
            value_capacity: 4,
            journal_capacity: 1024,
        });
        let subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());

        assert_eq!(
            publication.offer_with(
                b"x",
                AppendOptions {
                    reserved_value: -1,
                    ..AppendOptions::default()
                }
            ),
            Err(ClientError::Conflation(
                karyos_sys::conflation::ConflationError::KeyOutOfRange { key: -1 }
            ))
        );
        assert!(matches!(
            publication.try_claim_with(
                5,
                AppendOptions {
                    reserved_value: 1,
                    ..AppendOptions::default()
                }
            ),
            Err(ClientError::Conflation(
                karyos_sys::conflation::ConflationError::ValueTooLarge { length: 5, max: 4 }
            ))
        ));
        assert_eq!(subscription.position(), 0);

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
            OfferOutcome::Accepted { position: 0, .. }
        ));
        drop(buffer);
    }

    /// Counts the drops of the exports it marks.
    struct DropMark(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for DropMark {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn a_remote_publication_activates_its_prepared_successor_at_the_seal() {
        let (_buffer, mut conductor, publication) = setup(true);
        let link = GenerationLink::new_remote();
        let detached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut publication = publication
            .with_generation(Arc::clone(&link), 0)
            .unwrap()
            .with_export(Export::new(DropMark(Arc::clone(&detached))));
        assert!(matches!(
            publication.offer(b"before").unwrap(),
            OfferOutcome::Accepted { position: 0, .. }
        ));
        conductor.seal_for_cutover().unwrap();
        // The seal is unresolved until the control path offers a successor.
        assert_eq!(
            publication.offer(b"after").unwrap(),
            OfferOutcome::AdminAction
        );
        assert_eq!(
            publication.offer(b"after").unwrap(),
            OfferOutcome::AdminAction
        );

        let (successor, mut successor_conductor) = fresh_exclusive();
        assert!(successor_conductor.register_publication(7).unwrap());
        let prepared = Publication::prepare_adopt(Arc::clone(&successor), 7).unwrap();
        link.offer(
            1 << 20,
            Successor::PreparedPublication {
                prepared,
                export: Export::new(DropMark(Arc::clone(&detached))),
            },
        )
        .unwrap();
        // The call that reaches the seal moves; the next one publishes.
        // Neither allocates nor frees.
        let (moved, operations) = karyos_sys::alloc_count::count(|| publication.offer(b"after"));
        assert_eq!(moved.unwrap(), OfferOutcome::AdminAction);
        assert_eq!(operations, 0, "the move allocated or freed");
        let (accepted, operations) = karyos_sys::alloc_count::count(|| publication.offer(b"after"));
        assert!(matches!(
            accepted.unwrap(),
            OfferOutcome::Accepted { position, .. } if position == 1 << 20
        ));
        assert_eq!(operations, 0);
        // The predecessor and its export wait for the control path.
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 0);
        drop(link.take_retired());
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(publication);
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    /// A guard close or a missed deadline seals with a gate reason: offers
    /// and claims report `Gated`, connected or not, never `Closed`
    /// (guards-and-abort.md, GC-8; quantstratum/karyos#178).
    #[test]
    fn a_gate_seal_is_gated_connected_or_not() {
        use karyos_sys::log_buffer::SealReason;
        for reason in [SealReason::GuardClosed, SealReason::DeadlineMissed] {
            for allow_unconnected in [false, true] {
                let (_buffer, mut conductor, mut publication) = setup(allow_unconnected);
                conductor.seal_with_reason(reason).unwrap();
                for _ in 0..2 {
                    assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::Gated);
                    assert!(matches!(publication.try_claim(8), Ok(ClaimOutcome::Gated)));
                }
            }
        }
        // Any other seal stays `Closed`.
        let (_buffer, mut conductor, mut publication) = setup(false);
        conductor
            .seal_with_reason(SealReason::StreamRemoved)
            .unwrap();
        assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::Closed);
    }

    #[test]
    fn a_remote_publication_whose_successor_was_fenced_is_closed() {
        let (_buffer, mut conductor, publication) = setup(true);
        let link = GenerationLink::new_remote();
        let detached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut publication = publication
            .with_generation(Arc::clone(&link), 0)
            .unwrap()
            .with_export(Export::new(DropMark(Arc::clone(&detached))));
        conductor.seal_for_cutover().unwrap();
        let (successor, mut successor_conductor) = fresh_exclusive();
        assert!(successor_conductor.register_publication(7).unwrap());
        let prepared = Publication::prepare_adopt(Arc::clone(&successor), 7).unwrap();
        // The driver's fence wins before the handle reaches the seal.
        assert!(successor_conductor.fence_publication(7));
        link.offer(
            1 << 20,
            Successor::PreparedPublication {
                prepared,
                export: Export::new(DropMark(Arc::clone(&detached))),
            },
        )
        .unwrap();
        assert_eq!(publication.offer(b"after").unwrap(), OfferOutcome::Closed);
        assert_eq!(link.status(), crate::LinkStatus::Closed);
        assert_eq!(publication.offer(b"after").unwrap(), OfferOutcome::Closed);
        assert!(matches!(publication.try_claim(8), Ok(ClaimOutcome::Closed)));
        // The failed successor is kept, not dropped by the data call.
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 0);
        drop(link.take_retired());
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn a_remote_publication_closes_at_once_at_a_final_seal() {
        let (_buffer, mut conductor, publication) = setup(true);
        let link = GenerationLink::new_remote();
        let mut publication = publication.with_generation(Arc::clone(&link), 0).unwrap();
        conductor.seal().unwrap();
        // No successor mark: no wait, whatever the control path knows.
        assert_eq!(publication.offer(b"after").unwrap(), OfferOutcome::Closed);
        assert!(matches!(publication.try_claim(8), Ok(ClaimOutcome::Closed)));
    }

    /// A fresh exclusive buffer whose publication is not issued.
    fn fresh_exclusive() -> (Arc<LogBuffer>, Conductor<Arc<LogBuffer>>) {
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
        (buffer, conductor)
    }

    mod guarded {
        use super::*;
        use crate::guarded::{GuardBinding, HeapWords};
        use karyos_sys::guard;
        use karyos_sys::outcome_ring::{
            Kind, OutcomeWriter, Produced, Record, capacity, init, ring_words,
        };
        use karyos_sys::sync::{AtomicU64, Ordering};

        /// `C_m` of the tests, and a ring with room for one range record.
        const MESSAGES: u64 = 2;

        struct Driver {
            conductor: Conductor<Arc<LogBuffer>>,
            guard: Arc<HeapWords>,
            ring: Arc<HeapWords>,
            consumed: Arc<AtomicU64>,
            writer: OutcomeWriter,
        }

        impl Driver {
            fn outcome(&mut self, kind: Kind) {
                let record = Record {
                    kind,
                    lane: 0,
                    receiver: 0,
                    incarnation: 1,
                    start: 0,
                    end: 64,
                    epoch: 2,
                    reason: 0,
                    lost: 0,
                };
                assert!(matches!(
                    self.writer
                        .produce(self.ring.words(), &self.consumed, record)
                        .unwrap(),
                    Produced::Written(_)
                ));
            }
        }

        /// A publication bound to guard word 1 at open epoch 2.
        fn guarded() -> (Driver, ClientPublication) {
            guarded_with(None)
        }

        thread_local! {
            /// The rate copy's clock in these tests, per test thread.
            static NOW: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
        }

        fn now() -> u64 {
            NOW.with(core::cell::Cell::get)
        }

        fn advance(nanos: u64) {
            NOW.with(|now| now.set(now.get() + nanos));
        }

        /// As [`guarded`], with a rate limit read against [`now`].
        fn guarded_with(
            rate: Option<karyos_sys::rate_limit::RatePolicy>,
        ) -> (Driver, ClientPublication) {
            let slots = capacity(MESSAGES, 1).unwrap();
            let guard = Arc::new(HeapWords::zeroed(2));
            guard.words()[1].store(guard::created(), Ordering::Relaxed);
            assert_eq!(guard::reopen(&guard.words()[1], 1), Ok(2));
            let ring = Arc::new(HeapWords::zeroed(
                ring_words(usize::try_from(slots).unwrap()).unwrap(),
            ));
            init(ring.words(), slots).unwrap();
            let consumed = Arc::new(AtomicU64::new(0));
            let binding = GuardBinding::new(
                Arc::clone(&guard) as Arc<dyn crate::guarded::SharedWords>,
                1,
                2,
                Arc::clone(&ring) as Arc<dyn crate::guarded::SharedWords>,
                Arc::clone(&consumed) as Arc<dyn crate::guarded::ConsumedCell>,
                1,
                MESSAGES,
            )
            .unwrap();
            let binding = match rate {
                Some(policy) => binding.with_rate(policy, now),
                None => binding,
            };
            let (_buffer, conductor, publication) = setup(true);
            let driver = Driver {
                conductor,
                guard,
                ring,
                consumed,
                writer: OutcomeWriter::new(slots).unwrap(),
            };
            (driver, publication.with_guard(binding))
        }

        fn accepted(outcome: OfferOutcome) -> bool {
            matches!(outcome, OfferOutcome::Accepted { .. })
        }

        fn messages_per_second(per_second: u64, burst: u64) -> karyos_sys::rate_limit::RatePolicy {
            karyos_sys::rate_limit::RatePolicy {
                messages: karyos_sys::rate_limit::Rate { per_second, burst },
                // A byte limit the copy ignores: the gate charges frames.
                bytes: Some(karyos_sys::rate_limit::Rate {
                    per_second: 1,
                    burst: 1,
                }),
            }
        }

        /// G-e3: the handle's copy of the rate limit refuses early, appends
        /// and reserves nothing, and an accepted message takes one token.
        #[test]
        fn a_spent_rate_copy_refuses_offers_and_claims_early() {
            let (mut driver, mut publication) = guarded_with(Some(messages_per_second(10, 1)));
            let binding =
                |publication: &ClientPublication| publication.guard().unwrap().rate_tokens();
            assert_eq!(binding(&publication), Some(1));
            // A payload far above the byte burst: only the message bucket is
            // copied, so it is not refused for its size.
            assert!(accepted(publication.offer(&[7; 256]).unwrap()));
            assert_eq!(binding(&publication), Some(0));
            let before = driver.conductor.head().unwrap();
            assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::RateLimited);
            assert!(matches!(
                publication.try_claim(8).unwrap(),
                ClaimOutcome::RateLimited
            ));
            assert_eq!(driver.conductor.head().unwrap(), before, "nothing appended");
            assert_eq!(publication.guard().unwrap().outstanding(), 1);
            // A tenth of a second earns one token: a claim takes it.
            advance(100_000_000);
            let ClaimOutcome::Claimed(claim) = publication.try_claim(8).unwrap() else {
                panic!("not claimed");
            };
            drop(claim);
            assert_eq!(binding(&publication), Some(0));
            // C_m = 2 reservations wait for their records: back pressure
            // comes first, and a refusal charges nothing.
            assert_eq!(
                publication.offer(b"y").unwrap(),
                OfferOutcome::BackPressured
            );
            driver.outcome(Kind::Submitted);
            driver.outcome(Kind::Aborted);
            let _ = publication.poll_outcomes(8, |_, _| {}).unwrap();
            assert_eq!(publication.guard().unwrap().outstanding(), 0);
            assert_eq!(publication.offer(b"y").unwrap(), OfferOutcome::RateLimited);
            advance(100_000_000);
            assert!(accepted(publication.offer(b"z").unwrap()));
            assert_eq!(binding(&publication), Some(0));
        }

        #[test]
        fn a_closed_guard_is_gated_before_any_reservation() {
            let (driver, mut publication) = guarded();
            assert_eq!(
                guard::close(&driver.guard.words()[1]),
                Ok(guard::Closed::Now { epoch: 3 })
            );
            assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::Gated);
            assert!(matches!(publication.try_claim(8), Ok(ClaimOutcome::Gated)));
            assert_eq!(publication.guard().unwrap().outstanding(), 0);
            // A reopen is a new epoch: the handle bound to epoch 2 stays
            // gated.
            assert_eq!(guard::reopen(&driver.guard.words()[1], 3), Ok(4));
            assert_eq!(publication.offer(b"x").unwrap(), OfferOutcome::Gated);
        }

        #[test]
        fn reservations_bound_admission_until_their_records_are_read() {
            let (mut driver, mut publication) = guarded();
            assert!(accepted(publication.offer(b"a").unwrap()));
            let claim = claimed(publication.try_claim(8));
            let _ = claim.commit();
            assert_eq!(publication.guard().unwrap().outstanding(), MESSAGES);
            assert_eq!(
                publication.offer(b"c").unwrap(),
                OfferOutcome::BackPressured
            );
            assert!(matches!(
                publication.try_claim(8),
                Ok(ClaimOutcome::BackPressured)
            ));
            // A range record releases nothing; a final message record
            // releases one reservation once it is read.
            driver.outcome(Kind::Range);
            assert_eq!(publication.poll_outcomes(8, |_, _| {}).unwrap(), 1);
            assert_eq!(
                publication.offer(b"c").unwrap(),
                OfferOutcome::BackPressured
            );
            driver.outcome(Kind::Submitted);
            let mut kinds = Vec::new();
            assert_eq!(
                publication
                    .poll_outcomes(8, |_, record| kinds.push(record.kind))
                    .unwrap(),
                1
            );
            assert_eq!(kinds, [Kind::Submitted]);
            assert_eq!(driver.consumed.load(Ordering::Relaxed), 2);
            assert_eq!(publication.guard().unwrap().outstanding(), 1);
            assert!(accepted(publication.offer(b"c").unwrap()));
        }

        #[test]
        fn a_panicking_handler_releases_nothing() {
            let (mut driver, mut publication) = guarded();
            assert!(accepted(publication.offer(b"a").unwrap()));
            driver.outcome(Kind::Aborted);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                publication.poll_outcomes(1, |_, _| panic!("handler"))
            }));
            assert!(result.is_err());
            assert_eq!(publication.guard().unwrap().outstanding(), 1);
            assert_eq!(publication.poll_outcomes(1, |_, _| {}).unwrap(), 1);
            assert_eq!(publication.guard().unwrap().outstanding(), 0);
        }

        #[test]
        fn a_faulted_outcome_stream_is_terminal() {
            let (mut driver, mut publication) = guarded();
            assert!(accepted(publication.offer(b"a").unwrap()));
            assert!(accepted(publication.offer(b"b").unwrap()));
            // The client has not read; a third record faults it.
            driver.outcome(Kind::Submitted);
            driver.outcome(Kind::Submitted);
            driver.outcome(Kind::Range);
            assert_eq!(
                driver
                    .writer
                    .produce(
                        driver.ring.words(),
                        &driver.consumed,
                        Record {
                            kind: Kind::Submitted,
                            lane: 0,
                            receiver: 0,
                            incarnation: 1,
                            start: 0,
                            end: 64,
                            epoch: 2,
                            reason: 0,
                            lost: 0,
                        }
                    )
                    .unwrap(),
                Produced::Lost
            );
            let mut kinds = Vec::new();
            assert_eq!(
                publication
                    .poll_outcomes(8, |_, record| kinds.push(record.kind))
                    .unwrap(),
                4
            );
            assert_eq!(
                kinds,
                [
                    Kind::Submitted,
                    Kind::Submitted,
                    Kind::Range,
                    Kind::OutcomesLost
                ]
            );
            assert!(publication.guard().unwrap().outcomes_ended());
            assert_eq!(publication.offer(b"c"), Err(ClientError::OutcomesLost));
            assert!(matches!(
                publication.try_claim(8),
                Err(ClientError::OutcomesLost)
            ));
        }

        /// A final message record with no outstanding reservation is a
        /// driver protocol break: reported, consumed, releasing nothing.
        #[test]
        fn an_unreserved_final_record_is_corrupt() {
            let (mut driver, mut publication) = guarded();
            driver.outcome(Kind::Submitted);
            assert_eq!(
                publication.poll_outcomes(8, |_, _| {}),
                Err(ClientError::Outcomes(
                    karyos_sys::outcome_ring::OutcomeError::Corrupt { sequence: 1 }
                ))
            );
            assert_eq!(publication.guard().unwrap().outstanding(), 0);
        }

        #[test]
        fn claim_outcomes_that_reserve() {
            assert!(reserves::<HeapTerms>(&SysClaimOutcome::Aborted {
                position: 64
            }));
            assert!(!reserves::<HeapTerms>(&SysClaimOutcome::BackPressured));
            assert!(!reserves::<HeapTerms>(&SysClaimOutcome::AdminAction));
            assert!(!reserves::<HeapTerms>(&SysClaimOutcome::Closed));
            assert!(!reserves::<HeapTerms>(&SysClaimOutcome::Gated));
        }

        /// A guard close seals the handle; the early check refuses, but the
        /// handle still releases its seal and reports `Gated`.
        #[test]
        fn a_guard_sealed_handle_releases_before_the_early_check() {
            let (mut driver, mut publication) = guarded();
            assert!(accepted(publication.offer(b"a").unwrap()));
            assert_eq!(
                guard::close(&driver.guard.words()[1]),
                Ok(guard::Closed::Now { epoch: 3 })
            );
            driver
                .conductor
                .seal_with_reason(karyos_sys::log_buffer::SealReason::GuardClosed)
                .unwrap();
            let _ = driver.conductor.duty_cycle().unwrap();
            assert_eq!(publication.offer(b"b").unwrap(), OfferOutcome::Gated);
            let _ = driver.conductor.duty_cycle().unwrap();
            assert!(
                matches!(
                    driver.conductor.seal_state(),
                    karyos_sys::log_buffer::SealState::Retired { .. }
                ),
                "{:?}",
                driver.conductor.seal_state()
            );
            assert!(matches!(publication.try_claim(8), Ok(ClaimOutcome::Gated)));
        }

        #[test]
        fn a_binding_refuses_a_bad_ring() {
            let ring = Arc::new(HeapWords::zeroed(ring_words(3).unwrap()));
            init(ring.words(), 3).unwrap();
            ring.words()[0].store(2, Ordering::Relaxed);
            let words = |words: HeapWords| Arc::new(words) as Arc<dyn crate::guarded::SharedWords>;
            let cell = || Arc::new(AtomicU64::new(0)) as Arc<dyn crate::guarded::ConsumedCell>;
            assert_eq!(
                GuardBinding::new(
                    words(HeapWords::zeroed(1)),
                    0,
                    2,
                    ring as Arc<dyn crate::guarded::SharedWords>,
                    cell(),
                    1,
                    1,
                )
                .unwrap_err(),
                ClientError::Outcomes(karyos_sys::outcome_ring::OutcomeError::Version(2))
            );
            let ring = Arc::new(HeapWords::zeroed(ring_words(3).unwrap()));
            init(ring.words(), 3).unwrap();
            // A guard index past the guard view.
            assert_eq!(
                GuardBinding::new(
                    words(HeapWords::zeroed(1)),
                    1,
                    2,
                    Arc::clone(&ring) as Arc<dyn crate::guarded::SharedWords>,
                    cell(),
                    1,
                    1
                )
                .unwrap_err(),
                ClientError::Outcomes(karyos_sys::outcome_ring::OutcomeError::Layout)
            );
            assert_eq!(
                GuardBinding::new(words(HeapWords::zeroed(1)), 0, 2, ring, cell(), 1, 0)
                    .unwrap_err(),
                ClientError::Outcomes(karyos_sys::outcome_ring::OutcomeError::Layout)
            );
        }
    }
}
