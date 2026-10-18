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
    ClientSubscription, MessageInfo, MessageLimit, PollError, PollSummary, RejoinOutcome,
    ReplayFallbackReason, SecondaryOutcome,
};
use karyos_sys::frame::Lane;
use karyos_sys::term_bytes::TermBytes;

use super::{Gateway, Port};

#[cfg(test)]
mod tests;
use crate::group::capture::Refusal;
use crate::group::gateway::{
    Dispatched, Event, GatewayError, Handler, MessagePayload, SubscriptionId, TimerId,
};
use crate::group::record::Capture;
use crate::group::record::{
    EXTENSION, EndReason, FallbackReason, GroupRecord, LifecycleEvent, LifecycleKind, Loss,
    LossEvent, MAX_INLINE, MessageEvent, OverrunOutcome, Payload, TimerEvent,
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

/// An event a source reported that strict capture could not record yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Loss {
        loss: Loss,
        from: u64,
        lost_to: u64,
        resume: u64,
    },
    Ended {
        position: u64,
        reason: EndReason,
    },
}

/// A message source added at configuration.
pub(super) struct Source {
    source: Option<Box<dyn MessageSource + Send>>,
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
    summary.closed.map(|position| Held::Ended {
        position,
        reason: EndReason::EndOfStream,
    })
}

impl<P: Port, C: FnMut() -> u64> Gateway<P, C> {
    /// Adds a message source with its identity and the word naming its
    /// `required` recording here, if any. Configuration only: it
    /// allocates.
    pub fn add_subscription(
        &mut self,
        source: Box<dyn MessageSource + Send>,
        identity: SourceIdentity,
        word: Arc<RecordingWord>,
    ) -> Result<SubscriptionId, GatewayError> {
        let id = u16::try_from(self.sources.len()).map_err(|_| GatewayError::Ended)?;
        self.sources.push(Source {
            source: Some(source),
            identity,
            word,
            held: None,
            ended: false,
        });
        Ok(SubscriptionId(id))
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
        let count = self.sources.len();
        for _ in 0..count {
            let index = self.turn;
            self.turn = index
                .checked_add(1)
                .filter(|next| *next < count)
                .unwrap_or(0);
            if let Some(dispatched) = self.poll_source(index, now, handler)? {
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
        let Some(mut source) = slot.source.take() else {
            return Ok(None);
        };
        let (identity, word) = (slot.identity, Arc::clone(&slot.word));
        let id = SubscriptionId(u16::try_from(index).unwrap_or(u16::MAX));
        let mut result = None;
        let polled = source.poll_taking(
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
            Ok(summary) => reported(&summary),
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
            } => {
                let first = |group_seq: u64, out: &mut [u8]| {
                    GroupRecord::Loss(LossEvent {
                        group_seq,
                        logical_time: now,
                        incarnation: identity.incarnation,
                        from,
                        lost_to,
                        resume,
                        stream_id: identity.stream_id,
                        session_id: identity.session_id,
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
        let strict = self.capture == Capture::Strict;
        let placed = |group_seq: u64, out: &mut [u8]| {
            let payload = match word.read() {
                // A recording that started after the message does not
                // hold it.
                Some((recording_id, start)) if length > threshold && info.position >= start => {
                    Payload::Reference {
                        recording_id,
                        length: length32,
                    }
                }
                _ if length <= MAX_INLINE => Payload::Inline(bytes),
                // Strict cannot record it: the message is declined.
                _ if strict => return Err(Refusal::TooLarge),
                _ => Payload::Unavailable { length: length32 },
            };
            let extension: Option<&[u8; EXTENSION]> = info.extension.as_ref();
            GroupRecord::Message(MessageEvent {
                group_seq,
                logical_time: now,
                incarnation: identity.incarnation,
                position: info.position,
                extent: info.extent,
                stream_id: identity.stream_id,
                session_id: identity.session_id,
                lane: identity.lane,
                reserved_value: info.reserved_value,
                end_of_stream: info.end_of_stream,
                extension,
                payload,
            })
            .encode(out)
            .map_err(|_| Refusal::TooLarge)
        };
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
