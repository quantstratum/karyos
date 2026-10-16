// SPDX-License-Identifier: Apache-2.0

//! The embedded subscription with copy delivery (SPEC.md §4 reader roles,
//! §10 `poll`).
//!
//! Each message is copied, under the log buffer's loan, into a private
//! buffer allocated when the subscription is created; the handler then runs
//! on that copy, so a slow handler never pins term memory. For a required
//! subscription the message is acknowledged only after the handler returns:
//! if the handler panics, the panic unwinds before the acknowledgement and
//! the next poll delivers the same message again. An optional subscription's
//! copy is its acknowledgement, so a failed handler is not replayed.
//!
//! An overrun optional or observer reader follows its rejoin policy
//! (`quantstratum-docs: karyos/design/rejoin-policies.md`, SPEC.md §4,
//! Recovery of an overrun reader): it rejoins at the head, rebuilds through
//! a snapshot source, or closes; `replay` falls back to a secondary policy
//! in phase 1, which has no Archive. A subscription handed over by a client
//! conductor also queues a loss report of each overrun for its conductor
//! ([`crate::loss`]).

use std::sync::Arc;

use karyos_sys::frame::EXTENSION_LENGTH;
use karyos_sys::log_buffer::{LogBuffer, PollOutcome, SealReason, SkipReason, Subscription};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use karyos_protocol::frame::TraceExtension;
use karyos_protocol::trace_hook::{PublicationIdentity, SubscriberIdentity, TraceHook};

use crate::error::ClientError;
use crate::generation::{GenerationLink, Next, Retired, RetiredHandle, Successor, representable};
use crate::link::{Export, Lease, Origin};
use crate::loss::LossReporter;
use crate::trace::DeliveryTrace;

/// Metadata delivered with each message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInfo {
    /// Stream position of the message.
    pub position: u64,
    /// Reserved value of the first fragment.
    pub reserved_value: i64,
    /// End of stream.
    pub end_of_stream: bool,
    /// The opaque trace extension, if the message carries one.
    pub extension: Option<[u8; EXTENSION_LENGTH as usize]>,
}

impl MessageInfo {
    /// The decoded trace context (SPEC.md §10, `Fragment::trace()`): `None`
    /// for an untraced message and for an extension that does not decode,
    /// which the subscription counts. Pass it as the parent of the messages
    /// this one causes.
    #[must_use]
    pub fn trace(&self) -> Option<TraceExtension> {
        self.extension
            .and_then(|bytes| TraceExtension::decode(&bytes).ok())
    }
}

/// Messages delivered whose trace extension did not decode. The count is
/// checked: it never wraps or saturates silently; once it would overflow it
/// keeps its value and `overflowed` stays set (SPEC.md §14, ADR-0007).
/// Delivery is never affected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InvalidExtensions {
    /// Messages counted.
    pub count: u64,
    /// The count would have overflowed.
    pub overflowed: bool,
}

impl InvalidExtensions {
    fn count_one(&mut self) {
        match self.count.checked_add(1) {
            Some(count) => self.count = count,
            None => self.overflowed = true,
        }
    }
}

/// Upper bound on whole messages delivered by one poll. Counts reassembled
/// messages, never fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageLimit(u32);

impl MessageLimit {
    /// A limit of `messages` whole messages; 0 makes a poll do nothing.
    #[inline]
    #[must_use]
    pub const fn new(messages: u32) -> Self {
        Self(messages)
    }

    /// The number of messages.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A lost range reported by an optional subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overrun {
    /// First position not delivered.
    pub from: u64,
    /// End of the range known lost (below the retention floor).
    pub lost_to: u64,
    /// Position delivery resumed from.
    pub resume: u64,
}

/// The application's rebuild of its state after an overrun
/// (`quantstratum-docs: karyos/design/rejoin-policies.md`, `snapshot`).
pub trait SnapshotSource: Send {
    /// Brings the application's state to where it would be after consuming
    /// every message before `overrun.resume`. Runs once per overrun, on the
    /// polling thread, outside any loan, before any message at or after
    /// `resume` is delivered.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotFailed`] when the state could not be rebuilt; the
    /// subscription then closes rather than resume on top of it.
    fn rebuild(&mut self, overrun: &Overrun) -> Result<(), SnapshotFailed>;
}

/// A snapshot source could not rebuild the application's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, thiserror::Error)]
#[error("the snapshot source could not rebuild the state")]
pub struct SnapshotFailed;

/// What follows an overrun of an optional or observer reader, declared at
/// creation (SPEC.md §4 and §10). A required reader is never lapped, so for
/// it the policy is accepted and never used.
#[derive(Default)]
pub enum RejoinPolicy {
    /// Delivery continues at the head (the default).
    #[default]
    RejoinAtHead,
    /// The source rebuilds the state before delivery continues at the head.
    Snapshot(Box<dyn SnapshotSource>),
    /// The subscription disposes of its live state and stays closed.
    Close,
    /// Replay from a recording; in phase 1 there is no Archive, so the
    /// secondary policy applies and the outcome reports why.
    Replay {
        /// The policy applied instead.
        secondary: Secondary,
    },
}

/// The policy `replay` falls back to.
pub enum Secondary {
    /// As [`RejoinPolicy::RejoinAtHead`].
    RejoinAtHead,
    /// As [`RejoinPolicy::Snapshot`].
    Snapshot(Box<dyn SnapshotSource>),
    /// As [`RejoinPolicy::Close`].
    Close,
}

impl core::fmt::Debug for RejoinPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RejoinAtHead => f.write_str("RejoinAtHead"),
            Self::Snapshot(_) => f.write_str("Snapshot(..)"),
            Self::Close => f.write_str("Close"),
            Self::Replay { secondary } => f
                .debug_struct("Replay")
                .field("secondary", secondary)
                .finish(),
        }
    }
}

impl core::fmt::Debug for Secondary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RejoinAtHead => f.write_str("RejoinAtHead"),
            Self::Snapshot(_) => f.write_str("Snapshot(..)"),
            Self::Close => f.write_str("Close"),
        }
    }
}

/// What a non-replay policy did after an overrun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryOutcome {
    /// Delivery continues at `resume`.
    ResumedAtHead,
    /// The snapshot source rebuilt the state; delivery continues at
    /// `resume`.
    SnapshotRebuilt,
    /// The snapshot source failed or panicked: the subscription is closed.
    SnapshotFailed,
    /// The subscription is closed.
    Closed,
}

/// Why `replay` was not used. The values are fixed now, so they never
/// change meaning when phase 3 adds Archive replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayFallbackReason {
    /// No Archive exists (phase 1).
    NoArchive,
    /// No recording covers the gap (phase 3).
    NoRecording,
    /// The recording's retention does not reach the gap (phase 3).
    RetentionShort,
}

/// What the rejoin policy did after an overrun, reported with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejoinOutcome {
    /// Delivery continues at `resume`.
    ResumedAtHead,
    /// The snapshot source rebuilt the state; delivery continues at
    /// `resume`.
    SnapshotRebuilt,
    /// The snapshot source failed or panicked: the subscription is closed.
    SnapshotFailed,
    /// The subscription is closed.
    Closed,
    /// `replay` fell back to its secondary policy.
    ReplayFallback {
        /// Why replay was not used.
        reason: ReplayFallbackReason,
        /// What the secondary policy did.
        secondary: SecondaryOutcome,
    },
}

impl RejoinOutcome {
    /// Whether the outcome closed the subscription.
    #[must_use]
    pub fn closed(self) -> bool {
        matches!(
            self,
            Self::SnapshotFailed
                | Self::Closed
                | Self::ReplayFallback {
                    secondary: SecondaryOutcome::SnapshotFailed | SecondaryOutcome::Closed,
                    ..
                }
        )
    }
}

impl From<SecondaryOutcome> for RejoinOutcome {
    fn from(outcome: SecondaryOutcome) -> Self {
        match outcome {
            SecondaryOutcome::ResumedAtHead => Self::ResumedAtHead,
            SecondaryOutcome::SnapshotRebuilt => Self::SnapshotRebuilt,
            SecondaryOutcome::SnapshotFailed => Self::SnapshotFailed,
            SecondaryOutcome::Closed => Self::Closed,
        }
    }
}

/// An aborted block the poll skipped: the claim that reserved it never
/// committed, so its extent carries no message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aborted {
    /// Stream position of the block.
    pub position: u64,
    /// Bytes skipped.
    pub extent: u32,
}

/// A range of an image skipped because it delivers no message
/// (`quantstratum-docs: karyos/design/receive-publication.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skipped {
    /// Stream position of the range.
    pub position: u64,
    /// Bytes skipped.
    pub extent: u32,
    /// Why the range delivers no message.
    pub reason: SkipReason,
}

/// What one poll did. A poll stops at the first overrun or aborted block,
/// so no loss or abort report is ever overwritten or hidden behind later
/// deliveries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PollSummary {
    /// Messages delivered to the handler (and acknowledged) before the poll
    /// stopped.
    pub delivered: u32,
    /// The overrun that stopped the poll, if any.
    pub overrun: Option<Overrun>,
    /// The aborted block that stopped the poll, if any; the next poll
    /// resumes after it.
    pub aborted: Option<Aborted>,
    /// The skipped range of an image that stopped the poll, if any; the
    /// next poll resumes after it.
    pub skipped: Option<Skipped>,
    /// The seal position, when the poll reached it: the stream is sealed
    /// and no message can follow (`quantstratum-docs: karyos/design/publication-seal.md`).
    /// Every later poll reports it again.
    pub closed: Option<u64>,
    /// Why the stream was sealed, set together with `closed`.
    pub close_reason: Option<SealReason>,
    /// The read position, when the subscription was revoked because its
    /// client was lost (quantstratum-docs: `karyos/design/required-participant-loss.md`): the subscription is over, and every later
    /// poll reports it again.
    pub revoked: Option<u64>,
    /// What the rejoin policy did, set together with `overrun`, and again
    /// on every later poll of a subscription it closed.
    pub rejoin: Option<RejoinOutcome>,
    /// The lost range, when the rejoin policy closed the subscription:
    /// every later poll reports the same, touching no buffer or link.
    pub closed_by_overrun: Option<Overrun>,
}

/// A poll that failed after possibly delivering messages: `summary` reports
/// the deliveries that were handled and acknowledged before `cause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("poll failed after {} deliveries: {cause}", summary.delivered)]
pub struct PollError {
    /// Progress made before the failure.
    pub summary: PollSummary,
    /// The failure.
    pub cause: ClientError,
}

/// A subscription on one stream.
#[derive(Debug)]
pub struct ClientSubscription<T: TermBytes = HeapTerms> {
    /// The live cell; `None` once the rejoin policy closed the
    /// subscription.
    inner: Option<Subscription<Arc<LogBuffer<T>>>>,
    /// What follows an overrun.
    rejoin: RejoinPolicy,
    /// A closure by the rejoin policy: the lost range, the outcome and the
    /// acknowledged position, reported by every later poll.
    closed: Option<(Overrun, RejoinOutcome, u64)>,
    scratch: Box<[u8]>,
    origin: Option<Origin>,
    /// The link to the stream's successor mappings, if the driver gave one
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`).
    link: Option<Arc<GenerationLink<T>>>,
    /// The stream position where this handle's mapping starts.
    base: u64,
    /// The trace hook, identities and delivery boundary, for a traced
    /// subscription.
    trace: Option<DeliveryTrace>,
    /// Messages whose extension did not decode; delivered untraced.
    invalid_extensions: InvalidExtensions,
    /// Where each overrun is reported, for a handle from a client
    /// conductor that knows the stream's identity; boxed, since overruns
    /// are rare and the handle stays small.
    loss: Option<Box<LossReporter>>,
    /// The stream lease of a handle from the direct driver API, held only
    /// for its drop.
    _lease: Option<Lease>,
    /// The export of a handle adopted from another process's grant. Last:
    /// it is dropped after the mapping, and its drop sends `Detach`.
    _export: Option<Export>,
}

impl<T: TermBytes> ClientSubscription<T> {
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

    /// Wraps a log buffer subscription, allocating its private copy buffer
    /// (control path) for the largest message of the buffer it reads.
    #[must_use]
    pub fn new(inner: Subscription<Arc<LogBuffer<T>>>) -> Self {
        let max_message_length = inner.buffer().max_message_length();
        Self {
            inner: Some(inner),
            rejoin: RejoinPolicy::RejoinAtHead,
            closed: None,
            scratch: vec![0u8; max_message_length as usize].into_boxed_slice(),
            origin: None,
            link: None,
            base: 0,
            trace: None,
            invalid_extensions: InvalidExtensions::default(),
            loss: None,
            _lease: None,
            _export: None,
        }
    }

    /// Sets what follows an overrun (control path; the default is
    /// [`RejoinPolicy::RejoinAtHead`]).
    #[must_use]
    pub fn with_rejoin(mut self, policy: RejoinPolicy) -> Self {
        self.rejoin = policy;
        self
    }

    /// Records the `SubscriberPoll` observation of every traced message
    /// through `hook`, for messages of `publication` received by
    /// `subscriber` (control path). Each position is recorded at its first
    /// delivery attempt only. Binding a new hook to a traced subscription
    /// keeps its delivery boundary, so a message attempted before the
    /// rebinding is not recorded again by the new hook.
    #[must_use]
    pub fn with_trace(
        mut self,
        hook: Box<dyn TraceHook>,
        publication: PublicationIdentity,
        subscriber: SubscriberIdentity,
    ) -> Self {
        let boundary = self.trace.as_ref().map_or(0, DeliveryTrace::boundary);
        self.trace = Some(DeliveryTrace::new(hook, publication, subscriber, boundary));
        self
    }

    /// Whether the subscription has a trace hook.
    #[must_use]
    pub fn is_traced(&self) -> bool {
        self.trace.is_some()
    }

    /// Control path: lets the hook refill what it consumes.
    pub fn trace_maintenance(&mut self) {
        if let Some(trace) = &mut self.trace {
            trace.maintain();
        }
    }

    /// The delivery boundary of a traced subscription: the end of the
    /// highest message it attempted to deliver (its position plus its
    /// reserved extent), advanced before the handler runs and independently
    /// of acknowledgement; 0 before the first attempt or without a hook. A
    /// message at `p` was attempted when the boundary is above `p`.
    #[must_use]
    pub fn delivery_boundary(&self) -> u64 {
        self.trace.as_ref().map_or(0, DeliveryTrace::boundary)
    }

    /// Messages delivered whose extension did not decode.
    #[must_use]
    pub fn invalid_extensions(&self) -> InvalidExtensions {
        self.invalid_extensions
    }

    /// Attaches the generation link the driver keeps for this handle, and
    /// the base of the mapping it reads.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::PositionsExhausted`] when the mapping starting
    /// at `base` could report a position at or above `2^63`, and
    /// [`ClientError::ClosedByOverrun`] for a subscription its rejoin policy
    /// closed, which no cutover may reach; the handle is then dropped,
    /// releasing what it holds.
    pub fn with_generation(
        mut self,
        link: Arc<GenerationLink<T>>,
        base: u64,
    ) -> Result<Self, ClientError> {
        let Some(inner) = &self.inner else {
            return Err(ClientError::ClosedByOverrun);
        };
        if !representable(base, inner.buffer()) {
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

    /// Wraps a subscription from the direct driver API; the handle keeps
    /// the stream's lease until it is dropped.
    #[must_use]
    pub fn with_lease(inner: Subscription<Arc<LogBuffer<T>>>, lease: Lease) -> Self {
        let mut subscription = Self::new(inner);
        subscription._lease = Some(lease);
        subscription
    }

    /// Wraps a subscription handed over through a client conductor; the
    /// handle keeps the stream's lease until it is dropped.
    #[must_use]
    pub fn from_hand_over(inner: Subscription<Arc<LogBuffer<T>>>, origin: Origin) -> Self {
        let mut subscription = Self::new(inner);
        subscription.origin = Some(origin);
        subscription
    }

    /// Reports each overrun through `reporter` (control path).
    #[must_use]
    pub(crate) fn with_loss_reports(mut self, reporter: LossReporter) -> Self {
        self.loss = Some(Box::new(reporter));
        self
    }

    /// The owner and registration, for a handle from a client conductor.
    #[must_use]
    pub fn origin(&self) -> Option<&Origin> {
        self.origin.as_ref()
    }

    /// Delivers up to `message_limit` messages to `handler`.
    ///
    /// The handler gets a slice of the private copy, valid only for that
    /// call; no loan is held while it runs. A normal return means the message
    /// was handled. Work is bounded: a limit of 0 does nothing; otherwise at
    /// most `message_limit + 1` lower-layer polls run, each copying at most
    /// one message after stepping over at most one PAD. The poll stops when
    /// nothing is published, at the first overrun, or at the first aborted
    /// block, which it reports and which needs no acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`PollError`] carrying the deliveries handled before a
    /// lower-layer failure, such as a required subscription whose data is
    /// gone. A message handed to the handler and not yet acknowledged stays
    /// pending for redelivery; a PAD stepped over before the failure may
    /// still have been acknowledged.
    #[expect(
        clippy::result_large_err,
        reason = "the error carries the whole summary by value so a failed poll reports its progress; the Ok summary is as large, so boxing the error saves nothing"
    )]
    pub fn poll<H>(
        &mut self,
        mut handler: H,
        message_limit: MessageLimit,
    ) -> Result<PollSummary, PollError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        let message_limit = message_limit.get();
        let mut summary = PollSummary::default();
        if let Some((overrun, outcome, _)) = self.closed {
            summary.rejoin = Some(outcome);
            summary.closed_by_overrun = Some(overrun);
            return Ok(summary);
        }
        if message_limit == 0 {
            return Ok(summary);
        }
        let attempts = message_limit.checked_add(1).unwrap_or(message_limit);
        for _ in 0..attempts {
            if summary.delivered == message_limit {
                break;
            }
            let Some(inner) = self.inner.as_mut() else {
                break;
            };
            let outcome = match inner.poll(&mut self.scratch) {
                Ok(outcome) => outcome,
                Err(error) => {
                    return Err(PollError {
                        summary,
                        cause: ClientError::from(error),
                    });
                }
            };
            match outcome {
                PollOutcome::Message {
                    position,
                    length,
                    end_of_stream,
                    reserved_value,
                    extension,
                } => {
                    let info = MessageInfo {
                        position: self.base + position,
                        reserved_value,
                        end_of_stream,
                        extension,
                    };
                    if let Some(trace) = &mut self.trace {
                        let decoded = info.trace();
                        if decoded.is_none() && extension.is_some() {
                            self.invalid_extensions.count_one();
                        }
                        let lane = inner.buffer().lane();
                        // The read cursor is already past the message.
                        let end = self.base + inner.position();
                        trace.attempt(decoded.as_ref(), lane, info.position, end);
                    } else if extension.is_some_and(|bytes| TraceExtension::decode(&bytes).is_err())
                    {
                        self.invalid_extensions.count_one();
                    }
                    let message = self.scratch.get(..length as usize).unwrap_or(&[]);
                    handler(message, info);
                    // Reached only if the handler returned.
                    inner.acknowledge();
                    summary.delivered += 1;
                }
                PollOutcome::Overrun {
                    from,
                    lost_to,
                    resume,
                } => {
                    let overrun = Overrun {
                        from: self.base + from,
                        lost_to: self.base + lost_to,
                        resume: self.base + resume,
                    };
                    // Read before a `close` outcome drops the cell.
                    let lane = inner.buffer().lane().get();
                    summary.overrun = Some(overrun);
                    let outcome = self.rejoin(&overrun);
                    summary.rejoin = Some(outcome);
                    if let Some(loss) = &self.loss {
                        loss.report(lane, &overrun, &self.rejoin, outcome);
                    }
                    if outcome.closed() {
                        summary.closed_by_overrun = Some(overrun);
                    }
                    break;
                }
                PollOutcome::Aborted { position, extent } => {
                    summary.aborted = Some(Aborted {
                        position: self.base + position,
                        extent,
                    });
                    break;
                }
                PollOutcome::Skipped {
                    position,
                    extent,
                    reason,
                } => {
                    summary.skipped = Some(Skipped {
                        position: self.base + position,
                        extent,
                        reason,
                    });
                    break;
                }
                PollOutcome::Closed { position, reason } => match self.after_end() {
                    // Moved: the successor's first message is next, in the
                    // same poll and budget.
                    Some(true) => {}
                    // A cutover is pending: nothing to deliver yet.
                    Some(false) => break,
                    None => {
                        summary.closed = Some(self.base + position);
                        summary.close_reason = Some(reason);
                        break;
                    }
                },
                PollOutcome::Revoked { position } => {
                    summary.revoked = Some(self.base + position);
                    break;
                }
                PollOutcome::Pending => break,
            }
        }
        Ok(summary)
    }

    /// The acknowledged stream position.
    #[inline]
    #[must_use]
    pub fn position(&self) -> u64 {
        match (&self.inner, self.closed) {
            (Some(inner), _) => self.base + inner.acknowledged_position(),
            (None, Some((_, _, position))) => position,
            (None, None) => self.base,
        }
    }

    /// Whether the rejoin policy closed the subscription.
    #[must_use]
    pub fn is_closed_by_overrun(&self) -> bool {
        self.closed.is_some()
    }

    /// Applies the rejoin policy after `overrun` was reported (the poll
    /// that observed it, outside any loan).
    fn rejoin(&mut self, overrun: &Overrun) -> RejoinOutcome {
        let outcome = match &mut self.rejoin {
            RejoinPolicy::RejoinAtHead => RejoinOutcome::ResumedAtHead,
            RejoinPolicy::Snapshot(source) => rebuild(source.as_mut(), overrun).into(),
            RejoinPolicy::Close => RejoinOutcome::Closed,
            RejoinPolicy::Replay { secondary } => RejoinOutcome::ReplayFallback {
                reason: ReplayFallbackReason::NoArchive,
                secondary: match secondary {
                    Secondary::RejoinAtHead => SecondaryOutcome::ResumedAtHead,
                    Secondary::Snapshot(source) => rebuild(source.as_mut(), overrun),
                    Secondary::Close => SecondaryOutcome::Closed,
                },
            },
        };
        if outcome.closed() {
            self.close_by_overrun(*overrun, outcome);
        }
        outcome
    }

    /// The `close` policy: disposes of the whole live state at once. The
    /// cell detaches (its last access, outside any loan), the generation
    /// link closes for good and its offered successor is dropped, which
    /// detaches its cell, then the link, the stream lease and a remote
    /// grant's export are released; only the closure result stays.
    fn close_by_overrun(&mut self, overrun: Overrun, outcome: RejoinOutcome) {
        let position = self.position();
        drop(self.inner.take());
        if let Some(link) = self.link.take() {
            drop(link.close());
            // A remote handle's predecessor or failed successor, if any.
            drop(link.take_retired());
        }
        self._lease = None;
        self._export = None;
        self.closed = Some((overrun, outcome, position));
    }

    /// The poll reached the seal of the handle's mapping. With a link,
    /// moves to an offered successor (`Some(true)`) or finds a pending
    /// cutover (`Some(false)`); `None` when no successor will come.
    fn after_end(&mut self) -> Option<bool> {
        let link = self.link.as_ref()?;
        let inner = self.inner.as_ref()?;
        match link.next(inner.buffer().sealed_with_successor()) {
            Next::Wait => Some(false),
            Next::Moved {
                base,
                successor: Successor::Subscription { inner, scratch },
            } => {
                // The predecessor's cell is detached by this drop.
                self.inner = Some(inner);
                self.scratch = scratch;
                self.base = base;
                Some(true)
            }
            // A remote successor is activated here, without allocating; the
            // predecessor waits in the link for the control path.
            Next::Moved {
                base,
                successor:
                    Successor::PreparedSubscription {
                        prepared,
                        scratch,
                        export,
                    },
            } => match prepared.activate() {
                Ok(inner) => {
                    let Some(predecessor) = self.inner.replace(inner) else {
                        unreachable!("a handle at its seal holds its cell")
                    };
                    let predecessor_scratch = core::mem::replace(&mut self.scratch, scratch);
                    let predecessor_export = self._export.replace(export);
                    self.base = base;
                    link.retire(Retired {
                        _handle: Some(RetiredHandle::Subscription {
                            inner: predecessor,
                            scratch: predecessor_scratch,
                        }),
                        _export: predecessor_export,
                    });
                    Some(true)
                }
                // The driver's fence won: this mapping is the last.
                Err(refused) => {
                    link.fail_activation(match refused.prepared {
                        Some(prepared) => Retired {
                            _handle: Some(RetiredHandle::Successor(
                                Successor::PreparedSubscription {
                                    prepared,
                                    scratch,
                                    export,
                                },
                            )),
                            _export: None,
                        },
                        None => Retired {
                            _handle: None,
                            _export: Some(export),
                        },
                    });
                    None
                }
            },
            // A successor of another kind is a driver bug: never used.
            Next::Moved { .. } | Next::End => None,
        }
    }
}

/// Runs `source` once for `overrun`; a panic counts as a failure.
fn rebuild(source: &mut dyn SnapshotSource, overrun: &Overrun) -> SecondaryOutcome {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| source.rebuild(overrun))) {
        Ok(Ok(())) => SecondaryOutcome::SnapshotRebuilt,
        Ok(Err(SnapshotFailed)) | Err(_) => SecondaryOutcome::SnapshotFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{AppendOptions, ClaimOutcome, LogBufferConfig, Role};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    fn buffer() -> Arc<LogBuffer> {
        Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 2,
                max_subscribers: 2,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            })
            .unwrap(),
        )
    }

    /// DATA, ABORTED, DATA: the abort stops the poll after the first
    /// delivery and is reported; a required subscriber needs no
    /// acknowledgement for it and is not stalled by it.
    #[test]
    fn an_aborted_block_stops_the_poll_and_is_reported() {
        let buffer = buffer();
        let mut conductor = buffer.conductor_owned().unwrap();
        let mut subscription =
            ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
        let mut publication = buffer.publication_owned().unwrap().unwrap();
        let _ = publication
            .append(b"first", AppendOptions::default())
            .unwrap();
        let ClaimOutcome::Claimed(mut claim) =
            publication.try_claim(40, AppendOptions::default()).unwrap()
        else {
            panic!("not claimed");
        };
        claim.payload().fill(0xEE);
        let aborted_at = claim.position();
        claim.abort();
        let _ = publication
            .append(b"second", AppendOptions::default())
            .unwrap();

        let mut seen = Vec::new();
        let summary = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
            .unwrap();
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.overrun, None);
        assert_eq!(
            summary.aborted,
            Some(Aborted {
                position: aborted_at,
                extent: 96,
            })
        );
        assert_eq!(seen, vec![b"first".to_vec()]);
        // Already past the extent: nothing to acknowledge.
        assert_eq!(subscription.position(), aborted_at + 96);

        let summary = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
            .unwrap();
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.aborted, None);
        assert_eq!(seen, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    /// The invalid-extension count is checked, with and without a hook: at
    /// its limit it keeps its value, reports the overflow, and the message
    /// is still delivered.
    #[test]
    fn the_invalid_extension_count_is_checked() {
        for traced in [false, true] {
            let buffer = buffer();
            let mut conductor = buffer.conductor_owned().unwrap();
            let mut subscription =
                ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
            if traced {
                let (hook, _seen) = crate::trace::test_hook::recording(false);
                subscription = subscription.with_trace(
                    hook,
                    karyos_protocol::trace_hook::PublicationIdentity::default(),
                    karyos_protocol::trace_hook::SubscriberIdentity {
                        driver: [1, 2],
                        registration: 1,
                        incarnation: 1,
                    },
                );
            }
            subscription.invalid_extensions.count = u64::MAX;
            let mut publication = buffer.publication_owned().unwrap().unwrap();
            let mut bytes = [0u8; 64];
            bytes[0] = 9;
            let options = AppendOptions {
                extension: Some(bytes),
                ..AppendOptions::default()
            };
            let _ = publication.append(b"odd", options).unwrap();
            let mut seen = Vec::new();
            let summary = subscription
                .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(1))
                .unwrap();
            assert_eq!(summary.delivered, 1);
            assert_eq!(seen, vec![b"odd".to_vec()]);
            assert_eq!(
                subscription.invalid_extensions(),
                InvalidExtensions {
                    count: u64::MAX,
                    overflowed: true,
                }
            );
        }
    }

    /// An abort first in line still stops the poll with nothing delivered,
    /// and counts as one of the bounded lower-layer polls.
    #[test]
    fn an_aborted_block_alone_is_reported_with_no_delivery() {
        let buffer = buffer();
        let mut conductor = buffer.conductor_owned().unwrap();
        let mut subscription =
            ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
        let mut publication = buffer.publication_owned().unwrap().unwrap();
        let ClaimOutcome::Claimed(claim) =
            publication.try_claim(8, AppendOptions::default()).unwrap()
        else {
            panic!("not claimed");
        };
        drop(claim);
        let summary = subscription
            .poll(|_, _| panic!("nothing to deliver"), MessageLimit::new(1))
            .unwrap();
        assert_eq!(summary.delivered, 0);
        assert_eq!(
            summary.aborted,
            Some(Aborted {
                position: 0,
                extent: 64,
            })
        );
    }

    /// Counts the drops of the exports it marks.
    struct DropMark(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for DropMark {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// A remote subscription on a predecessor sealed after `before`, and a
    /// successor with cell `cell` registered for export 7 and its publisher.
    struct RemoteCutover {
        link: Arc<GenerationLink>,
        subscription: ClientSubscription,
        successor: Arc<LogBuffer>,
        publication: karyos_sys::log_buffer::Publication<Arc<LogBuffer>>,
        conductor: karyos_sys::log_buffer::Conductor<Arc<LogBuffer>>,
        cell: usize,
        detached: Arc<std::sync::atomic::AtomicUsize>,
    }

    fn remote_cutover() -> RemoteCutover {
        let predecessor = buffer();
        let mut conductor = predecessor.conductor_owned().unwrap();
        let link = GenerationLink::new_remote();
        let detached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut subscription =
            ClientSubscription::new(conductor.subscribe(Role::Required).unwrap())
                .with_generation(Arc::clone(&link), 0)
                .unwrap()
                .with_export(Export::new(DropMark(Arc::clone(&detached))));
        let mut publication = predecessor.publication_owned().unwrap().unwrap();
        let _ = publication
            .append(b"before", AppendOptions::default())
            .unwrap();
        conductor.seal_for_cutover().unwrap();
        assert_eq!(
            publication
                .append(b"late", AppendOptions::default())
                .unwrap(),
            karyos_sys::log_buffer::AppendOutcome::Closed
        );
        let _ = conductor.duty_cycle().unwrap();
        let mut seen = Vec::new();
        let summary = subscription
            .poll(|bytes, _| seen.push(bytes.to_vec()), MessageLimit::new(8))
            .unwrap();
        assert_eq!(seen, vec![b"before".to_vec()]);
        // The seal is unresolved: not the end.
        assert_eq!(summary.closed, None);
        let successor = buffer();
        let mut successor_conductor = successor.conductor_owned().unwrap();
        let cell = successor_conductor
            .register_subscriber_with(Role::Required, false, 7)
            .unwrap();
        let successor_publication = successor.publication_owned().unwrap().unwrap();
        RemoteCutover {
            link,
            subscription,
            successor,
            publication: successor_publication,
            conductor: successor_conductor,
            cell,
            detached,
        }
    }

    #[test]
    fn a_remote_subscription_activates_its_prepared_successor_at_the_seal() {
        let RemoteCutover {
            link,
            mut subscription,
            successor,
            mut publication,
            cell,
            detached,
            ..
        } = remote_cutover();
        let prepared =
            Subscription::prepare_adopt(Arc::clone(&successor), cell, Role::Required, 7).unwrap();
        let scratch = vec![0u8; successor.max_message_length() as usize].into_boxed_slice();
        link.offer(
            1 << 20,
            Successor::PreparedSubscription {
                prepared,
                scratch,
                export: Export::new(DropMark(Arc::clone(&detached))),
            },
        )
        .unwrap();
        let _ = publication
            .append(b"after", AppendOptions::default())
            .unwrap();
        // The poll that crosses the seal neither allocates nor frees.
        let mut seen = None;
        let (summary, operations) = karyos_sys::alloc_count::count(|| {
            subscription
                .poll(
                    |bytes, info| {
                        if bytes == b"after" {
                            seen = Some(info.position);
                        }
                    },
                    MessageLimit::new(8),
                )
                .ok()
        });
        let summary = summary.unwrap();
        assert_eq!(operations, 0, "the move allocated or freed");
        assert_eq!(summary.closed, None);
        assert_eq!(summary.delivered, 1);
        assert_eq!(seen, Some(1 << 20));
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 0);
        drop(link.take_retired());
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn a_remote_subscription_whose_successor_was_fenced_ends() {
        let RemoteCutover {
            link,
            mut subscription,
            successor,
            mut conductor,
            cell,
            detached,
            ..
        } = remote_cutover();
        let prepared =
            Subscription::prepare_adopt(Arc::clone(&successor), cell, Role::Required, 7).unwrap();
        assert!(conductor.fence_subscriber(cell, 7));
        let scratch = vec![0u8; successor.max_message_length() as usize].into_boxed_slice();
        link.offer(
            1 << 20,
            Successor::PreparedSubscription {
                prepared,
                scratch,
                export: Export::new(DropMark(Arc::clone(&detached))),
            },
        )
        .unwrap();
        let summary = subscription.poll(|_, _| {}, MessageLimit::new(8)).unwrap();
        assert!(summary.closed.is_some());
        assert_eq!(link.status(), crate::LinkStatus::Closed);
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 0);
        drop(link.take_retired());
        assert_eq!(detached.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
