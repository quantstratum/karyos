// SPDX-License-Identifier: Apache-2.0

//! The live Gateway's sources and dispatch (quantstratum-docs:
//! karyos/design/recording-group-gateway.md, sections 4, 5 and 7).
//!
//! A dispatch reads the clock once and takes one event: a timer due at
//! that time first, else the next source in turn that has one. A message
//! source is polled for one message through `poll_taking`, so strict
//! capture declines a message it cannot record and it stays pending. What
//! a poll reports instead of a message (an overrun, a skipped range, an
//! aborted block) is a loss event, and a subscription's end a lifecycle
//! event; strict capture keeps either pending until it can be recorded.
//!
//! A message's payload is recorded by reference when the source's
//! recording word names a `required` recording of this Archive that
//! started at or before the message, and the payload is above the inline
//! threshold; otherwise inline up to `MAX_INLINE`, and above it
//! unavailable: strict declines the message, best effort records it with
//! payload 3.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::{
    ClientError, ClientSubscription, ConflatedSubscription, ImageChange, MessageInfo, MessageLimit,
    PollError, PollSummary, RejoinOutcome, ReplayFallbackReason, SecondaryOutcome, Subscription,
    SubscriptionError,
};
use karyos_sys::conflation::{Budget, ConflationConfig};
use karyos_sys::frame::Lane;
use karyos_sys::freshness::Freshness as ReadFreshness;
use karyos_sys::log_buffer::SealReason;
use karyos_sys::term_bytes::TermBytes;

use super::{Gateway, Port};

#[cfg(test)]
mod tests;
use crate::group::capture::Refusal;
use crate::group::gateway::{
    ConflatedId, Dispatched, Event, GatewayError, Handler, MessagePayload, SubscriptionId, TimerId,
};
use crate::group::record::Capture;
use crate::group::record::{
    CONFLATED_EVENT, ConflatedEvent, EXTENSION, EndReason, FallbackReason, Freshness, GroupRecord,
    LifecycleEvent, LifecycleKind, Loss, LossEvent, MAX_INLINE, MessageEvent, OverrunOutcome,
    Payload, TimerEvent,
};

/// A message source's identity, recorded with each of its events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceIdentity {
    /// The publication incarnation.
    pub incarnation: u64,
    /// The stream.
    pub stream_id: i32,
    /// The session.
    pub session_id: i32,
    /// The lane.
    pub lane: Lane,
}

/// The `required` recording of a source this Archive keeps, shared with
/// the Archive's thread: set on the configuration path, cleared when the
/// recording stops or fails. The event loop reads it with Acquire loads,
/// once per message; once it reads 0, later payloads are inline.
#[derive(Debug, Default)]
pub struct RecordingWord {
    id: AtomicU64,
    start: AtomicU64,
}

impl RecordingWord {
    /// A word naming no recording.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            id: AtomicU64::new(0),
            start: AtomicU64::new(0),
        }
    }

    /// Names recording `id`, which starts at `start`. The start is stored
    /// first and the id published with Release, so a reader that sees the
    /// id sees its start.
    pub fn set(&self, id: u64, start: u64) {
        self.start.store(start, Ordering::Relaxed);
        self.id.store(id, Ordering::Release);
    }

    /// Names no recording any more.
    pub fn clear(&self) {
        self.id.store(0, Ordering::Release);
    }

    /// The recording and its start, if one is named.
    #[must_use]
    pub fn read(&self) -> Option<(u64, u64)> {
        let id = self.id.load(Ordering::Acquire);
        (id != 0).then(|| (id, self.start.load(Ordering::Relaxed)))
    }
}

/// A source of messages the Gateway polls one message at a time.
pub trait MessageSource {
    /// Polls up to `limit` messages; `handler` takes each, or declines it
    /// by returning false, which stops the poll and leaves a required
    /// reader's message pending.
    ///
    /// # Errors
    ///
    /// The client's [`PollError`].
    #[expect(clippy::result_large_err, reason = "the client's own poll error")]
    fn poll_taking(
        &mut self,
        handler: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        limit: MessageLimit,
    ) -> Result<PollSummary, PollError>;

    /// The oldest image change not yet taken: an image of a network
    /// subscription attached or retired. None for a source of one image.
    fn next_image_change(&mut self) -> Option<ImageChange> {
        None
    }

    /// Whether it takes every session of its stream: a network
    /// subscription's images. It is then its stream's only source.
    fn fan_in(&self) -> bool {
        false
    }

    /// [`MessageSource::poll_taking`], with the session of the image whose
    /// report the summary carries, when it names one.
    ///
    /// # Errors
    ///
    /// As [`MessageSource::poll_taking`].
    #[expect(clippy::result_large_err, reason = "the client's own poll error")]
    fn poll_reporting(
        &mut self,
        handler: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        limit: MessageLimit,
    ) -> Result<(PollSummary, Option<i32>), PollError> {
        self.poll_taking(handler, limit)
            .map(|summary| (summary, None))
    }
}

/// A network subscription's images, polled in turn: their messages carry
/// each image's session, and their attaches and retirements are its
/// image changes. A closed subscription is a failed poll with an empty
/// summary, which the Gateway records as an end closed at 0 (#439's M13).
impl<T: TermBytes> MessageSource for Subscription<T> {
    fn poll_taking(
        &mut self,
        handler: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        limit: MessageLimit,
    ) -> Result<PollSummary, PollError> {
        self.poll_reporting(handler, limit)
            .map(|(summary, _)| summary)
    }

    fn fan_in(&self) -> bool {
        true
    }

    fn poll_reporting(
        &mut self,
        handler: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        limit: MessageLimit,
    ) -> Result<(PollSummary, Option<i32>), PollError> {
        match Subscription::poll_taking(self, handler, limit) {
            // The image that reported more than deliveries: its report,
            // with the deliveries over every image, and its session.
            Ok(poll) => {
                let session = poll.stopped.and_then(|stop| stop.session_id);
                let summary = PollSummary {
                    delivered: poll.delivered,
                    ..poll.stopped.map(|stop| stop.summary).unwrap_or_default()
                };
                Ok((summary, session))
            }
            Err(SubscriptionError::Poll { error, .. }) => Err(error),
            Err(SubscriptionError::Closed(cause)) => Err(PollError {
                summary: PollSummary::default(),
                cause,
            }),
        }
    }

    fn next_image_change(&mut self) -> Option<ImageChange> {
        Subscription::next_image_change(self)
    }
}

impl<T: TermBytes> MessageSource for ClientSubscription<T> {
    fn poll_taking(
        &mut self,
        handler: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        limit: MessageLimit,
    ) -> Result<PollSummary, PollError> {
        ClientSubscription::poll_taking(self, handler, limit)
    }
}

/// What takes a conflated value: its key, bytes, version and freshness.
pub type ValueHandler<'a> = dyn FnMut(u32, &[u8], u64, ReadFreshness) + 'a;

/// A conflated view the Gateway polls one value at a time.
pub trait ConflatedSource {
    /// The view's table configuration: its largest value bounds what an
    /// event needs.
    fn config(&self) -> ConflationConfig;

    /// Delivers at most one changed key's latest value to `handler`
    /// (key, value, version, freshness); returns how many it delivered.
    ///
    /// # Errors
    ///
    /// The client's [`ClientError::ViewClosed`] once the view closed.
    fn poll_one(&mut self, handler: &mut ValueHandler<'_>) -> Result<u32, ClientError>;
}

impl ConflatedSource for ConflatedSubscription {
    fn config(&self) -> ConflationConfig {
        ConflatedSubscription::config(self)
    }

    fn poll_one(&mut self, handler: &mut ValueHandler<'_>) -> Result<u32, ClientError> {
        let budget = Budget {
            keys: 1,
            retries: 4,
        };
        self.poll_changed_with(budget, |key, value| {
            handler(key, value.payload(), value.version(), value.freshness());
        })
        .map(|report| report.delivered)
    }
}

/// A conflated view added at configuration.
pub(super) struct View {
    source: Option<Box<dyn ConflatedSource + Send>>,
    stream_id: i32,
    session_id: i32,
    /// Closed for good: polled no more.
    closed: bool,
}

impl core::fmt::Debug for View {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("View")
            .field("stream_id", &self.stream_id)
            .field("session_id", &self.session_id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// An event a source reported that strict capture could not record yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Loss {
        loss: Loss,
        from: u64,
        lost_to: u64,
        resume: u64,
        /// The image's session, for a network subscription's.
        session_id: Option<i32>,
    },
    Ended {
        position: u64,
        reason: EndReason,
    },
    /// An image of a network subscription attached or retired: it names
    /// no position.
    Image {
        session_id: i32,
        available: bool,
    },
}

/// A message source added at configuration.
pub(super) struct Source {
    source: Option<Box<dyn MessageSource + Send>>,
    /// It takes every session of its stream.
    fan_in: bool,
    identity: SourceIdentity,
    word: Arc<RecordingWord>,
    held: Option<Held>,
    /// Its end was delivered: it is polled no more.
    ended: bool,
}

impl core::fmt::Debug for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Source")
            .field("identity", &self.identity)
            .field("held", &self.held)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

/// The record's overrun outcome and fallback reason for a rejoin outcome.
fn overrun(outcome: RejoinOutcome) -> (OverrunOutcome, Option<FallbackReason>) {
    let secondary = |outcome| match outcome {
        SecondaryOutcome::ResumedAtHead => OverrunOutcome::ResumedAtHead,
        SecondaryOutcome::SnapshotRebuilt => OverrunOutcome::SnapshotRebuilt,
        SecondaryOutcome::SnapshotFailed => OverrunOutcome::SnapshotFailed,
        SecondaryOutcome::Closed => OverrunOutcome::Closed,
    };
    match outcome {
        RejoinOutcome::ResumedAtHead => (OverrunOutcome::ResumedAtHead, None),
        RejoinOutcome::SnapshotRebuilt => (OverrunOutcome::SnapshotRebuilt, None),
        RejoinOutcome::SnapshotFailed => (OverrunOutcome::SnapshotFailed, None),
        RejoinOutcome::Closed => (OverrunOutcome::Closed, None),
        RejoinOutcome::Replaying => (OverrunOutcome::Replaying, None),
        RejoinOutcome::Replayed { .. } => (OverrunOutcome::Replayed, None),
        RejoinOutcome::ReplayFallback {
            reason,
            secondary: then,
        } => (
            secondary(then),
            Some(match reason {
                ReplayFallbackReason::NoArchive => FallbackReason::NoArchive,
                ReplayFallbackReason::NoRecording => FallbackReason::NoRecording,
                ReplayFallbackReason::RetentionShort => FallbackReason::RetentionShort,
                ReplayFallbackReason::RecordingBehind => FallbackReason::RecordingBehind,
                ReplayFallbackReason::Refused => FallbackReason::Refused,
                ReplayFallbackReason::MergeFailed => FallbackReason::MergeFailed,
                ReplayFallbackReason::Withdrawn => FallbackReason::Withdrawn,
            }),
        ),
    }
}

/// What a poll that delivered no message reported, as an event to hold.
fn reported(summary: &PollSummary) -> Option<Held> {
    let end = |position: u64, extent: u32| position.checked_add(u64::from(extent));
    if let (Some(lost), Some(outcome)) = (summary.overrun, summary.rejoin) {
        let (outcome, fallback) = overrun(outcome);
        return Some(Held::Loss {
            loss: Loss::Overrun { outcome, fallback },
            from: lost.from,
            lost_to: lost.lost_to,
            resume: lost.resume,
            session_id: None,
        });
    }
    if let Some(skipped) = summary.skipped
        && let Some(to) = end(skipped.position, skipped.extent)
    {
        return Some(Held::Loss {
            loss: Loss::Skipped(skipped.reason),
            from: skipped.position,
            lost_to: to,
            resume: to,
            session_id: None,
        });
    }
    if let Some(aborted) = summary.aborted
        && let Some(to) = end(aborted.position, aborted.extent)
    {
        return Some(Held::Loss {
            loss: Loss::Aborted,
            from: aborted.position,
            lost_to: to,
            resume: to,
            session_id: None,
        });
    }
    if let Some(lost) = summary.closed_by_overrun {
        return Some(Held::Ended {
            position: lost.resume,
            reason: EndReason::Overrun,
        });
    }
    if let Some(position) = summary.revoked {
        return Some(Held::Ended {
            position,
            reason: EndReason::Revoked,
        });
    }
    // A seal with no cause is the stream's end; one with a cause (the
    // stream removed, a required participant lost, ...) closed it.
    summary.closed.map(|position| Held::Ended {
        position,
        reason: match summary.close_reason {
            None | Some(SealReason::Unspecified) => EndReason::EndOfStream,
            Some(_) => EndReason::Closed,
        },
    })
}

impl<P: Port, C: FnMut() -> u64> Gateway<P, C> {
    /// Adds a message source with its identity and the word naming its
    /// `required` recording here, if any: the word of the source's own
    /// lane (`ArchiveHandle::recording_word`). Configuration only: it
    /// allocates.
    ///
    /// # Errors
    ///
    /// [`GatewayError::DuplicateSource`] for a second source of the same
    /// stream and session, even on another lane: replay could not tell
    /// them apart.
    pub fn add_subscription(
        &mut self,
        source: Box<dyn MessageSource + Send>,
        identity: SourceIdentity,
        word: Arc<RecordingWord>,
    ) -> Result<SubscriptionId, GatewayError> {
        // A network subscription takes every session of its stream: it is
        // then the stream's only source, so replay maps it as one.
        let fan_in = source.fan_in();
        if self.sources.iter().any(|slot| {
            let same_stream = slot.identity.stream_id == identity.stream_id;
            let either_fans_in = fan_in || slot.fan_in;
            same_stream && (either_fans_in || slot.identity.session_id == identity.session_id)
        }) {
            return Err(GatewayError::DuplicateSource {
                stream_id: identity.stream_id,
                session_id: identity.session_id,
            });
        }
        let id = u16::try_from(self.sources.len()).map_err(|_| GatewayError::Ended)?;
        self.sources.push(Source {
            source: Some(source),
            fan_in,
            identity,
            word,
            held: None,
            ended: false,
        });
        Ok(SubscriptionId(id))
    }

    /// Adds a conflated view of stream `stream_id`, session `session_id`.
    /// Configuration only: it allocates.
    ///
    /// # Errors
    ///
    /// [`GatewayError::TooLarge`] for a view whose largest value exceeds
    /// `MAX_INLINE` or does not fit the event budget: its values could
    /// not be recorded.
    pub fn add_conflated(
        &mut self,
        source: Box<dyn ConflatedSource + Send>,
        stream_id: i32,
        session_id: i32,
    ) -> Result<ConflatedId, GatewayError> {
        let largest = source.config().value_capacity;
        let event = usize::from(CONFLATED_EVENT.block_length)
            .checked_add(12 + 2)
            .and_then(|head| head.checked_add(largest))
            .and_then(|event| event.checked_add(super::END));
        if largest > MAX_INLINE || event.is_none_or(|event| event > self.buffer.len()) {
            return Err(GatewayError::TooLarge(largest));
        }
        let id = u16::try_from(self.views.len()).map_err(|_| GatewayError::TooLarge(largest))?;
        self.views.push(View {
            source: Some(source),
            stream_id,
            session_id,
            closed: false,
        });
        Ok(ConflatedId(id))
    }

    /// Under strict capture, whether an event can be admitted now: a
    /// source's message or a view's value is consumed when read (an
    /// optional reader acknowledges on copy), so strict capture reads one
    /// only when it can record it. The refusal is counted as a dispatch's
    /// would be.
    fn strict_admit(&mut self) -> Result<(), GatewayError> {
        if self.capture != Capture::Strict {
            return Ok(());
        }
        match self.sender.admit() {
            Ok(()) => Ok(()),
            Err(Refusal::Ended | Refusal::Failed | Refusal::Closing) => Err(GatewayError::Ended),
            Err(refusal) => {
                let _ = self.count(refusal);
                Err(GatewayError::Refused(refusal))
            }
        }
    }

    /// Polls view `index` for one value; `None` when it had none or was
    /// skipped. Its value is consumed when read, so strict capture polls it
    /// only when an event can be admitted: a skipped view may conflate
    /// further versions meanwhile, as conflation does, and the recorded
    /// value is the one the handler saw.
    fn poll_view(
        &mut self,
        index: usize,
        now: u64,
        handler: &mut dyn Handler,
    ) -> Result<Option<Dispatched>, GatewayError> {
        let Some(view) = self.views.get_mut(index) else {
            return Ok(None);
        };
        if view.closed {
            return Ok(None);
        }
        let (stream_id, session_id) = (view.stream_id, view.session_id);
        self.strict_admit()?;
        let Some(mut source) = self
            .views
            .get_mut(index)
            .and_then(|view| view.source.take())
        else {
            return Ok(None);
        };
        let id = ConflatedId(u16::try_from(index).unwrap_or(u16::MAX));
        let mut result = None;
        let polled = source.poll_one(&mut |key, value, version, read| {
            let freshness = match read {
                ReadFreshness::Fresh => Some(Freshness::Fresh),
                ReadFreshness::Stale { since } => Some(Freshness::Stale { since }),
                // The client delivers coherent values only.
                ReadFreshness::Retry => None,
            };
            let first = |group_seq: u64, out: &mut [u8]| {
                let freshness = freshness.ok_or(Refusal::TooLarge)?;
                GroupRecord::Conflated(ConflatedEvent {
                    group_seq,
                    logical_time: now,
                    version,
                    key,
                    stream_id,
                    session_id,
                    freshness,
                    value,
                })
                .encode(out)
                .map_err(|_| Refusal::TooLarge)
            };
            let event = Event::Conflated {
                source: id,
                key,
                version,
                freshness: freshness.unwrap_or(Freshness::Fresh),
                value,
            };
            result = Some(self.dispatch_event(&event, now, &first, handler));
        });
        if let Some(view) = self.views.get_mut(index) {
            view.source = Some(source);
            view.closed |= polled.is_err();
        }
        result.transpose()
    }

    /// The timer due at `now` with the earliest deadline, taken from the
    /// table.
    fn due(&mut self, now: u64) -> Option<(TimerId, u64)> {
        let (slot, deadline) = self
            .deadlines
            .iter()
            .enumerate()
            .filter_map(|(slot, deadline)| deadline.filter(|at| *at <= now).map(|at| (slot, at)))
            .min_by_key(|(_, at)| *at)?;
        let timer = TimerId(u16::try_from(slot).ok()?);
        Some((timer, deadline))
    }

    /// Takes the next event and delivers it: a timer due now first, else
    /// the next source in turn that has one.
    pub(super) fn dispatch_next(
        &mut self,
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
        let now = (self.clock)();
        if let Some((timer, deadline)) = self.due(now) {
            if let Some(slot) = self.deadlines.get_mut(usize::from(timer.0)) {
                *slot = None;
            }
            let first = |group_seq: u64, out: &mut [u8]| {
                GroupRecord::Timer(TimerEvent {
                    group_seq,
                    logical_time: deadline,
                    timer_id: u64::from(timer.0),
                })
                .encode(out)
                .map_err(|_| Refusal::TooLarge)
            };
            let result = self.dispatch_event(&Event::Timer { timer }, deadline, &first, handler);
            if matches!(result, Err(GatewayError::Refused(_))) {
                // Not taken: it stays due.
                if let Some(slot) = self.deadlines.get_mut(usize::from(timer.0)) {
                    *slot = Some(deadline);
                }
            }
            return result;
        }
        let _ = self.flush();
        // The message sources, then the views, in turn.
        let sources = self.sources.len();
        let count = sources
            .checked_add(self.views.len())
            .ok_or(GatewayError::Ended)?;
        for _ in 0..count {
            let index = self.turn;
            self.turn = index
                .checked_add(1)
                .filter(|next| *next < count)
                .unwrap_or(0);
            let dispatched = match index.checked_sub(sources) {
                None => self.poll_source(index, now, handler)?,
                Some(view) => self.poll_view(view, now, handler)?,
            };
            if let Some(dispatched) = dispatched {
                return Ok(dispatched);
            }
        }
        Ok(Dispatched::Idle)
    }

    /// Polls source `index` for one event; `None` when it had none.
    fn poll_source(
        &mut self,
        index: usize,
        now: u64,
        handler: &mut dyn Handler,
    ) -> Result<Option<Dispatched>, GatewayError> {
        let Some(slot) = self.sources.get_mut(index) else {
            return Ok(None);
        };
        if let Some(held) = slot.held {
            return self.deliver_held(index, held, now, handler).map(Some);
        }
        if slot.ended {
            return Ok(None);
        }
        self.strict_admit()?;
        let Some(slot) = self.sources.get_mut(index) else {
            return Ok(None);
        };
        let Some(mut source) = slot.source.take() else {
            return Ok(None);
        };
        // A poll's image changes come before its messages.
        if let Some(change) = source.next_image_change() {
            slot.source = Some(source);
            let held = Held::Image {
                session_id: change.session_id,
                available: change.available,
            };
            slot.held = Some(held);
            return self.deliver_held(index, held, now, handler).map(Some);
        }
        let (identity, word) = (slot.identity, Arc::clone(&slot.word));
        let id = SubscriptionId(u16::try_from(index).unwrap_or(u16::MAX));
        let mut result = None;
        let polled = source.poll_reporting(
            &mut |bytes, info| {
                let dispatched =
                    self.dispatch_message(id, identity, &word, bytes, info, now, handler);
                // Strict declines what it refused: it stays pending.
                let taken = !matches!(dispatched, Err(GatewayError::Refused(_)));
                result = Some(dispatched);
                taken
            },
            MessageLimit::new(1),
        );
        if let Some(slot) = self.sources.get_mut(index) {
            slot.source = Some(source);
        }
        if let Some(result) = result {
            return result.map(Some);
        }
        let held = match polled {
            // A loss is the stopped image's, in its session.
            Ok((summary, session)) => reported(&summary).map(|held| match held {
                Held::Loss {
                    loss,
                    from,
                    lost_to,
                    resume,
                    ..
                } => Held::Loss {
                    loss,
                    from,
                    lost_to,
                    resume,
                    session_id: session,
                },
                other => other,
            }),
            // A poll that failed ends the source as closed.
            Err(error) => Some(Held::Ended {
                position: error.summary.closed.unwrap_or(0),
                reason: EndReason::Closed,
            }),
        };
        let Some(held) = held else {
            return Ok(None);
        };
        if let Some(slot) = self.sources.get_mut(index) {
            slot.held = Some(held);
        }
        self.deliver_held(index, held, now, handler).map(Some)
    }

    /// Delivers a loss or an end source `index` reported; it stays held
    /// while strict capture refuses it.
    ///
    /// Defensive: a source is read only after `strict_admit`, and nothing
    /// between that check and this delivery uses the ring or the in
    /// flight bound, so strict capture does not refuse here today; best
    /// effort never refuses. The hold keeps a report from being lost
    /// should a later change let admission fail in between.
    fn deliver_held(
        &mut self,
        index: usize,
        held: Held,
        now: u64,
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
        let Some(slot) = self.sources.get(index) else {
            return Ok(Dispatched::Idle);
        };
        let identity = slot.identity;
        let source = SubscriptionId(u16::try_from(index).unwrap_or(u16::MAX));
        let result = match held {
            Held::Loss {
                loss,
                from,
                lost_to,
                resume,
                session_id,
            } => {
                let session_id = session_id.unwrap_or(identity.session_id);
                let first = |group_seq: u64, out: &mut [u8]| {
                    GroupRecord::Loss(LossEvent {
                        group_seq,
                        logical_time: now,
                        incarnation: identity.incarnation,
                        from,
                        lost_to,
                        resume,
                        stream_id: identity.stream_id,
                        session_id,
                        lane: identity.lane,
                        loss,
                    })
                    .encode(out)
                    .map_err(|_| Refusal::TooLarge)
                };
                let event = Event::Loss {
                    source,
                    loss,
                    from,
                    lost_to,
                    resume,
                };
                self.dispatch_event(&event, now, &first, handler)
            }
            Held::Ended { position, reason } => {
                let kind = LifecycleKind::SubscriptionEnded(reason);
                let first = |group_seq: u64, out: &mut [u8]| {
                    GroupRecord::Lifecycle(LifecycleEvent {
                        group_seq,
                        logical_time: now,
                        incarnation: identity.incarnation,
                        position,
                        stream_id: identity.stream_id,
                        session_id: identity.session_id,
                        lane: identity.lane,
                        kind,
                    })
                    .encode(out)
                    .map_err(|_| Refusal::TooLarge)
                };
                self.dispatch_event(&Event::Lifecycle { source, kind }, now, &first, handler)
            }
            Held::Image {
                session_id,
                available,
            } => {
                let kind = if available {
                    LifecycleKind::ImageAvailable
                } else {
                    LifecycleKind::ImageUnavailable
                };
                // The image's session: replay finds the source by stream
                // and session, so two images of one alias with one session
                // name one source (owner note item 20, the image id).
                let first = |group_seq: u64, out: &mut [u8]| {
                    GroupRecord::Lifecycle(LifecycleEvent {
                        group_seq,
                        logical_time: now,
                        incarnation: identity.incarnation,
                        position: 0,
                        stream_id: identity.stream_id,
                        session_id,
                        lane: identity.lane,
                        kind,
                    })
                    .encode(out)
                    .map_err(|_| Refusal::TooLarge)
                };
                self.dispatch_event(&Event::Lifecycle { source, kind }, now, &first, handler)
            }
        };
        if !matches!(result, Err(GatewayError::Refused(_)))
            && let Some(slot) = self.sources.get_mut(index)
        {
            slot.held = None;
            slot.ended |= matches!(held, Held::Ended { .. });
        }
        result
    }

    /// Records and delivers one message, its payload placed by the source's
    /// recording word.
    #[expect(clippy::too_many_arguments, reason = "one message and its context")]
    fn dispatch_message(
        &mut self,
        source: SubscriptionId,
        identity: SourceIdentity,
        word: &RecordingWord,
        bytes: &[u8],
        info: MessageInfo,
        now: u64,
        handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
        let length = bytes.len();
        // A client message's length is a u32; one past it cannot be
        // recorded, and is declined.
        let length32 =
            u32::try_from(length).map_err(|_| GatewayError::Refused(Refusal::TooLarge))?;
        let threshold = usize::try_from(self.inline_threshold).unwrap_or(usize::MAX);
        // The word names the recording of the source's own stream, session
        // and lane: another image of a network subscription is not in it,
        // and is placed as without a word.
        let recorded = info.session_id == identity.session_id;
        // The word is read once: the record and the decision agree.
        let payload = match word.read() {
            // A recording that started after the message does not hold it.
            Some((recording_id, start))
                if recorded && length > threshold && info.position >= start =>
            {
                Payload::Reference {
                    recording_id,
                    length: length32,
                }
            }
            _ if length <= MAX_INLINE => Payload::Inline(bytes),
            _ => Payload::Unavailable { length: length32 },
        };
        let placed = |group_seq: u64, out: &mut [u8]| {
            let extension: Option<&[u8; EXTENSION]> = info.extension.as_ref();
            GroupRecord::Message(MessageEvent {
                group_seq,
                logical_time: now,
                incarnation: identity.incarnation,
                position: info.position,
                extent: info.extent,
                stream_id: identity.stream_id,
                // The image's, which a network subscription's differ in.
                session_id: info.session_id,
                lane: identity.lane,
                reserved_value: info.reserved_value,
                end_of_stream: info.end_of_stream,
                extension,
                payload,
            })
            .encode(out)
            .map_err(|_| Refusal::TooLarge)
        };
        if self.capture == Capture::Strict && matches!(payload, Payload::Unavailable { .. }) {
            // Strict cannot record its payload (a strict journal holds no
            // unavailable payload), and the message is already read: the
            // journal ends at it, a skipped range ended incomplete and not
            // delivered, never silently.
            let _ = self.count(Refusal::TooLarge);
            let end = info.position.checked_add(u64::from(info.extent));
            let lost = |group_seq: u64, out: &mut [u8]| {
                let end = end.ok_or(Refusal::TooLarge)?;
                GroupRecord::Loss(LossEvent {
                    group_seq,
                    logical_time: now,
                    incarnation: identity.incarnation,
                    from: info.position,
                    lost_to: end,
                    resume: end,
                    stream_id: identity.stream_id,
                    session_id: identity.session_id,
                    lane: identity.lane,
                    loss: Loss::Skipped(karyos_sys::log_buffer::SkipReason::MessageTooLarge),
                })
                .encode(out)
                .map_err(|_| Refusal::TooLarge)
            };
            return Err(self.end_incomplete(&lost));
        }
        let event = Event::Message {
            source,
            lane: identity.lane,
            position: info.position,
            extent: info.extent,
            length: length32,
            reserved_value: info.reserved_value,
            end_of_stream: info.end_of_stream,
            extension: info.extension.as_ref(),
            payload: MessagePayload::Bytes(bytes),
        };
        self.dispatch_event(&event, now, &placed, handler)
    }
}
