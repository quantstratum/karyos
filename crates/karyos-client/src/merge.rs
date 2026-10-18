// SPDX-License-Identifier: Apache-2.0

//! The live merge (SPEC.md §8.2; `quantstratum-docs:
//! karyos/design/archive-gap-analysis.md`, A6): a replay of a recording of
//! one publication, read up to an explicit cutover position, then the live
//! stream of that publication from there.
//!
//! A replay delivers a recording at its recorded positions (A5), so the
//! replay and the live stream are the same log: the merge deduplicates by
//! position. The cutover `P` is the live reader's position when the merge
//! is made. Below `P` the replay's messages are delivered; at and past `P`
//! the live reader's, and the replay's are duplicates, dropped. Positions
//! are in bytes of the stream. The merge switches only at `P` exactly: a
//! replay that ends below it, or that steps over it inside a frame, is a
//! typed [`MergeError`], never merged over. So is a replay of another
//! publication or incarnation (an epoch change), a reader of another lane
//! than 0, and a live reader lapped while the replay ran. A gap in the
//! recording below `P` is reported as the replay's local gap, and the merge
//! goes on. The merge never learns where the replay starts: it delivers
//! whatever the replay holds below `P`.
//!
//! The live reader is not polled while the replay delivers below `P`. A
//! required live reader therefore holds its publisher back for the
//! replay's duration; an optional one can be lapped, which the merge
//! reports as [`MergeError::LiveOverrun`].
//!
//! Only lane 0 of a single stream is merged (A6, Q6). The merge does not
//! know the Archive (SPEC.md §14): a [`ReplayProvider`] hands it replays.

use karyos_protocol::trace_hook::PublicationIdentity;
use karyos_sys::frame::{HEADER_LENGTH, Lane};
use karyos_sys::log_buffer::{SealReason, SkipReason};
use karyos_sys::sizing::align_frame;
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use crate::error::ClientError;
use crate::loss::LossReporter;
use crate::subscription::{
    Aborted, ClientSubscription, MessageInfo, MessageLimit, Overrun, PollError, PollSummary,
    RejoinOutcome, RejoinPolicy, ReplayFallbackReason, Secondary, SecondaryOutcome, Skipped,
    rebuild,
};
use karyos_protocol::cnc::RejoinPolicyCode;

/// Stops a replay the merge no longer needs: run once, at the cutover, when
/// the merge fails or gives its live reader back, or when it is dropped.
/// Stopping a replay that already ended is harmless.
pub trait ReplayStop: Send {
    /// Stops the replay. It runs on the polling thread and must not block:
    /// it posts the stop, or queues it.
    fn stop(&mut self);
}

/// A replay handed out by a [`ReplayProvider`]: a subscription to a stream
/// that delivers a recording of `source`'s lane 0 at its recorded
/// positions, and how to stop it.
pub struct Replay<T: TermBytes = HeapTerms> {
    subscription: ClientSubscription<T>,
    source: PublicationIdentity,
    stop: Option<Box<dyn ReplayStop>>,
}

impl<T: TermBytes> Replay<T> {
    /// A replay of a recording of `source`, read through `subscription`.
    #[must_use]
    pub fn new(subscription: ClientSubscription<T>, source: PublicationIdentity) -> Self {
        Self {
            subscription,
            source,
            stop: None,
        }
    }

    /// Runs `stop` when the replay is no longer needed.
    #[must_use]
    pub fn with_stop(mut self, stop: Box<dyn ReplayStop>) -> Self {
        self.stop = Some(stop);
        self
    }

    /// The publication the recording is of.
    #[inline]
    #[must_use]
    pub fn source(&self) -> &PublicationIdentity {
        &self.source
    }
}

impl<T: TermBytes> core::fmt::Debug for Replay<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Replay")
            .field("subscription", &self.subscription)
            .field("source", &self.source)
            .field("stop", &self.stop.is_some())
            .finish()
    }
}

impl<T: TermBytes> Drop for Replay<T> {
    fn drop(&mut self) {
        if let Some(mut stop) = self.stop.take() {
            stop.stop();
        }
    }
}

/// A replay a [`ReplayProvider`] is asked for: lane 0 of a recording of
/// `source`, over `[from, to)`, in bytes of the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayRequest {
    /// The live stream's publication: the recording must be of it.
    pub source: PublicationIdentity,
    /// The first position replayed.
    pub from: u64,
    /// The position the replay must reach: the merge's cutover, the live
    /// reader's position when the merge is made, with no poll of it in
    /// between.
    pub to: u64,
}

/// Why a [`ReplayProvider`] cannot hand out a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayUnavailable {
    /// No recording of the source exists.
    NoRecording,
    /// The recordings of the source no longer hold the range's start.
    RetentionShort,
    /// The recording did not reach the range's end in the time allowed.
    RecordingBehind,
    /// The Archive refused the replay.
    Refused,
}

/// Where a request to a [`ReplayProvider`] stands.
#[derive(Debug)]
pub enum ReplayStatus<T: TermBytes = HeapTerms> {
    /// Not answered yet: ask again.
    Pending,
    /// The replay, ready to read.
    Ready(Box<Replay<T>>),
    /// No replay will come.
    Unavailable(ReplayUnavailable),
}

/// Hands out replays of recordings: the Archive's client implements it,
/// and the merge uses it without knowing the Archive (SPEC.md §14).
pub trait ReplayProvider<T: TermBytes = HeapTerms>: Send {
    /// Asks for `request`'s replay, or polls the request already asked for.
    /// Never blocks: it runs on the polling thread, which may be the only
    /// one that drives the driver and the Archive, so any wait is spread
    /// over calls, and a deadline is the provider's.
    fn replay(&mut self, request: &ReplayRequest) -> ReplayStatus<T>;

    /// Withdraws the request pending, if any. A replay already handed out
    /// is stopped through its own [`ReplayStop`].
    fn cancel(&mut self);
}

/// Why a merge failed. Every failure but [`MergeError::Live`] is final:
/// later polls report it again, deliver nothing, and the replay is
/// stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MergeError {
    /// The replay is of another publication or incarnation than the live
    /// stream: an epoch change, which no merge spans.
    #[error("the replay is of {replay:?}, the live stream is {live:?}: an epoch change")]
    EpochChanged {
        /// The replay's source.
        replay: PublicationIdentity,
        /// The live stream's publication.
        live: PublicationIdentity,
    },
    /// The replay ended below the cutover: what lies between is missing.
    #[error("the replay ended at {end} ({reason:?}), below the cutover at {cutover}")]
    ReplayShort {
        /// Where the replay ended.
        end: u64,
        /// Why its stream was sealed.
        reason: SealReason,
        /// The cutover.
        cutover: u64,
    },
    /// The replay and the live stream disagree at `position`: a message
    /// or a frame runs across the cutover, or the replay's message at the
    /// cutover is not the live stream's. They are not the same log. When
    /// the live reader's first message disagrees, it is at `position`: a
    /// required live reader keeps it pending, so
    /// [`LiveMerge::into_live`] delivers it again; an optional or observer
    /// one acknowledged it on copy, so it is gone.
    #[error("the replay and the live stream disagree at {position} (cutover at {cutover})")]
    Mismatch {
        /// Where.
        position: u64,
        /// The cutover.
        cutover: u64,
    },
    /// The live reader or the replay reads another lane than 0, the only
    /// one merged (A6, Q6); `None` for a reader its rejoin policy closed.
    #[error("the live reader reads lane {live:?} and the replay {replay:?}: only lane 0 merges")]
    Lane {
        /// The live reader's lane.
        live: Option<Lane>,
        /// The replay's lane.
        replay: Option<Lane>,
    },
    /// The replay's reader was lapped.
    #[error("the replay was lapped: {0:?}")]
    ReplayOverrun(Overrun),
    /// The replay's reader was revoked.
    #[error("the replay was revoked at {position}")]
    ReplayRevoked {
        /// The replay reader's position.
        position: u64,
    },
    /// The replay's poll failed.
    #[error("the replay failed: {0}")]
    Replay(ClientError),
    /// The live reader was lapped before it delivered at the cutover: the
    /// range it lost follows the replay, so the merge has a hole there.
    /// The live reader's rejoin policy has already run.
    #[error("the live reader was lapped: {0:?}")]
    LiveOverrun(Overrun),
    /// The live reader's poll failed after the cutover; as for
    /// [`ClientSubscription::poll`], the merge goes on.
    #[error("the live reader failed: {0}")]
    Live(ClientError),
}

/// What one [`LiveMerge::poll`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MergePoll {
    /// The poll's deliveries and reports. Before the cutover, `skipped` and
    /// `aborted` are the replay's, below the cutover; the replay's own end
    /// is never reported. From the cutover on, it is the live reader's
    /// summary.
    pub summary: PollSummary,
    /// The cutover position, on the poll that switched to the live reader.
    pub cutover: Option<u64>,
}

/// A merge that failed after possibly delivering messages: `poll` reports
/// what was delivered before `cause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the merge failed after {} deliveries: {cause}", poll.summary.delivered)]
pub struct MergeFailed {
    /// Progress made before the failure.
    pub poll: MergePoll,
    /// The failure.
    pub cause: MergeError,
}

/// Where the merge stands.
enum State<T: TermBytes> {
    /// Delivering the replay, below the cutover.
    Replaying(Box<Replay<T>>),
    /// Delivering the live reader. `expect` is the replay's message at the
    /// cutover, which the live reader's first message must equal in
    /// position and length; `first` holds until the live reader delivered.
    Live {
        expect: Option<(u64, usize)>,
        first: bool,
    },
    /// Failed for good.
    Failed(MergeError),
}

/// What one replay poll of one message found.
#[derive(Clone, Copy)]
enum Event {
    /// A message below the cutover, delivered.
    Delivered(u64),
    /// A message below the cutover that runs past it even unfragmented,
    /// not delivered.
    Across(u64),
    /// A message at or past the cutover, not delivered: its position and
    /// length.
    Duplicate(u64, usize),
    Skipped(Skipped),
    Aborted(Aborted),
    Closed(u64, SealReason),
    /// Nothing; the reader may have stepped over a term's padding.
    Nothing,
}

/// A replay merged into a live stream at an explicit cutover (see the
/// module documentation).
pub struct LiveMerge<T: TermBytes = HeapTerms> {
    live: ClientSubscription<T>,
    cutover: u64,
    /// Where the replay looks at its frame at the cutover: the cutover, or
    /// the next term's start once it stepped over term padding there.
    reach: u64,
    state: State<T>,
}

impl<T: TermBytes> core::fmt::Debug for LiveMerge<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = match &self.state {
            State::Replaying(_) => "Replaying",
            State::Live { .. } => "Live",
            State::Failed(_) => "Failed",
        };
        f.debug_struct("LiveMerge")
            .field("live", &self.live)
            .field("cutover", &self.cutover)
            .field("state", &state)
            .finish()
    }
}

impl<T: TermBytes> LiveMerge<T> {
    /// Merges `replay` into `live`, the subscription of publication
    /// `source`, at the live reader's position now. A replay of another
    /// source fails the merge with [`MergeError::EpochChanged`], and a
    /// reader of another lane than 0 with [`MergeError::Lane`]; the replay
    /// then stops.
    #[must_use]
    pub fn new(
        live: ClientSubscription<T>,
        source: PublicationIdentity,
        replay: Box<Replay<T>>,
    ) -> Self {
        let cutover = live.position();
        let lanes = (live.lane(), replay.subscription.lane());
        let state = if lanes != (Some(Lane::ZERO), Some(Lane::ZERO)) {
            State::Failed(MergeError::Lane {
                live: lanes.0,
                replay: lanes.1,
            })
        } else if replay.source == source {
            State::Replaying(replay)
        } else {
            State::Failed(MergeError::EpochChanged {
                replay: replay.source,
                live: source,
            })
        };
        Self {
            live,
            cutover,
            reach: cutover,
            state,
        }
    }

    /// The cutover position, in bytes of the stream.
    #[inline]
    #[must_use]
    pub fn cutover(&self) -> u64 {
        self.cutover
    }

    /// Whether the merge switched to the live reader.
    #[inline]
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self.state, State::Live { .. })
    }

    /// Whether the merge is done: live, with the live reader's first
    /// message checked against the replay's at the cutover, or with
    /// nothing there to check.
    #[inline]
    #[must_use]
    pub fn is_settled(&self) -> bool {
        matches!(self.state, State::Live { expect: None, .. })
    }

    /// The final failure, if the merge failed.
    #[inline]
    #[must_use]
    pub fn failure(&self) -> Option<MergeError> {
        match self.state {
            State::Failed(cause) => Some(cause),
            _ => None,
        }
    }

    /// Gives the live reader back, stopping the replay if it still runs.
    /// It is where the merge left it: at the cutover until the merge
    /// switched. After a [`MergeError::Mismatch`] on its first message, a
    /// required live reader is just before that message: at the cutover,
    /// or at the next term's start when term padding lies at the cutover
    /// (it stepped over it); an optional or observer one acknowledged the
    /// message, and is past it.
    #[must_use]
    pub fn into_live(self) -> ClientSubscription<T> {
        self.live
    }

    /// Delivers up to `message_limit` messages to `handler`: the replay's
    /// below the cutover, then the live reader's. A limit of 0 does
    /// nothing, but a failed merge still reports its failure. A poll stops
    /// at the replay's first report (a skipped range or an aborted block
    /// below the cutover) and at the cutover itself; after it, the live
    /// reader is polled as [`ClientSubscription::poll`] polls.
    ///
    /// # Errors
    ///
    /// Returns [`MergeFailed`] carrying what was delivered before the
    /// failure. A replay message that runs past the cutover is not
    /// delivered when it would even unfragmented; a fragmented one is
    /// found only once delivered, before the [`MergeError::Mismatch`] it
    /// causes.
    #[expect(
        clippy::result_large_err,
        reason = "the error carries the poll by value so a failed merge reports its progress, as ClientSubscription::poll does"
    )]
    pub fn poll<H>(
        &mut self,
        mut handler: H,
        message_limit: MessageLimit,
    ) -> Result<MergePoll, MergeFailed>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        let mut poll = MergePoll::default();
        if let State::Failed(cause) = self.state {
            return Err(MergeFailed { poll, cause });
        }
        if message_limit.get() == 0 {
            return Ok(poll);
        }
        let failure = match self.state {
            State::Failed(cause) => Some(cause),
            State::Replaying(_) => self.replay(&mut handler, message_limit, &mut poll).err(),
            State::Live { .. } => self.live(&mut handler, message_limit, &mut poll),
        };
        match failure {
            // The live reader's own failure: the merge goes on.
            Some(cause @ MergeError::Live(_)) => Err(MergeFailed { poll, cause }),
            Some(cause) => {
                // A replay still held drops, and stops, here.
                self.state = State::Failed(cause);
                Err(MergeFailed { poll, cause })
            }
            None => Ok(poll),
        }
    }

    /// Polls the replay one message at a time, below the cutover, until
    /// the limit, a report, the cutover or nothing to read.
    fn replay<H>(
        &mut self,
        handler: &mut H,
        message_limit: MessageLimit,
        poll: &mut MergePoll,
    ) -> Result<(), MergeError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        let cutover = self.cutover;
        let limit = message_limit.get();
        // As the subscription's own bound: at most one more poll than
        // messages, and one to look at the cutover.
        for _ in 0..=limit {
            let reach = self.reach;
            let State::Replaying(replay) = &mut self.state else {
                break;
            };
            // Past the cutover only where it looks at the cutover, or if
            // the replay started past it, which `step` finds.
            let before = replay.subscription.position();
            // At the cutover, the replay's next frame is looked at, for the
            // live reader's first message to be checked against it.
            let at = before == reach;
            if !at && poll.summary.delivered == limit {
                break;
            }
            let (event, after) = Self::replay_one(replay, cutover, handler)?;
            let step = if at {
                Self::at_cutover(event, cutover)?
            } else {
                Self::step(before, event, after, cutover, poll)?
            };
            if matches!(step, Step::Stop) && matches!(event, Event::Nothing) && after > cutover {
                // Term padding at the cutover, stepped over: its message
                // is at the next term's start, not written yet.
                self.reach = after;
            }
            let expect = match step {
                Step::Next => continue,
                Step::Stop => return Ok(()),
                Step::Cutover(expect) => expect,
            };
            // At the cutover: the replay drops and stops.
            self.state = State::Live {
                expect,
                first: true,
            };
            poll.cutover = Some(cutover);
            return Ok(());
        }
        Ok(())
    }

    /// Judges the replay's event at the cutover: its message there, after
    /// any padding, is what the live reader must deliver first. Any other
    /// frame is the live reader's to report.
    fn at_cutover(event: Event, cutover: u64) -> Result<Step, MergeError> {
        Ok(match event {
            Event::Duplicate(position, length) => Step::Cutover(Some((position, length))),
            // Not written yet: it comes.
            Event::Nothing => Step::Stop,
            // Nothing below the cutover is left.
            Event::Delivered(position) | Event::Across(position) => {
                return Err(MergeError::Mismatch { position, cutover });
            }
            Event::Skipped(_) | Event::Aborted(_) | Event::Closed(..) => Step::Cutover(None),
        })
    }

    /// Judges one replay event below the cutover: the reader was at
    /// `before`, below it, and is now at `after`.
    fn step(
        before: u64,
        event: Event,
        after: u64,
        cutover: u64,
        poll: &mut MergePoll,
    ) -> Result<Step, MergeError> {
        let mismatch = |position| MergeError::Mismatch { position, cutover };
        let start = match event {
            Event::Delivered(position)
            | Event::Across(position)
            | Event::Duplicate(position, _) => position,
            Event::Skipped(skipped) => skipped.position,
            Event::Aborted(aborted) => aborted.position,
            Event::Closed(position, _) => position,
            Event::Nothing => after,
        };
        if start > cutover {
            // The cutover lies inside the term padding stepped over, or
            // before where the replay started.
            return Err(mismatch(before));
        }
        if start == cutover {
            // Past the term's padding, the event is the cutover's.
            return Self::at_cutover(event, cutover);
        }
        match event {
            // Not delivered: it would run past the cutover.
            Event::Across(position) => return Err(mismatch(position)),
            Event::Delivered(position) => {
                poll.summary.delivered += 1;
                if after > cutover {
                    // A fragmented message, delivered already: found once
                    // it ended.
                    return Err(mismatch(position));
                }
            }
            Event::Skipped(skipped) => {
                // Only a gap of the recording may run across the cutover:
                // it is reported up to it, and the live reader delivers
                // past it.
                let gap = matches!(skipped.reason, SkipReason::LocalGap(_));
                if after > cutover && !gap {
                    return Err(mismatch(skipped.position));
                }
                let extent = cutover
                    .checked_sub(skipped.position)
                    .and_then(|below| u32::try_from(below).ok())
                    .map_or(skipped.extent, |below| below.min(skipped.extent));
                poll.summary.skipped = Some(Skipped { extent, ..skipped });
            }
            Event::Aborted(aborted) => {
                if after > cutover {
                    return Err(mismatch(aborted.position));
                }
                poll.summary.aborted = Some(aborted);
            }
            Event::Closed(end, reason) => {
                return Err(MergeError::ReplayShort {
                    end,
                    reason,
                    cutover,
                });
            }
            Event::Nothing | Event::Duplicate(..) => {}
        }
        Ok(if after > cutover {
            // A gap of the recording across the cutover: what follows it
            // is the live reader's.
            Step::Cutover(None)
        } else if after == cutover || matches!(event, Event::Delivered(_)) {
            Step::Next
        } else {
            // A report stops the poll, as does nothing to read.
            Step::Stop
        })
    }

    /// One replay poll of at most one message; returns what it found and
    /// the reader's position after it.
    fn replay_one<H>(
        replay: &mut Replay<T>,
        cutover: u64,
        handler: &mut H,
    ) -> Result<(Event, u64), MergeError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        let mut seen = None;
        let summary = replay
            .subscription
            .poll(
                |bytes, info| {
                    seen = Some(if info.position >= cutover {
                        Event::Duplicate(info.position, bytes.len())
                    } else if shortest_end(info.position, bytes.len())
                        .is_none_or(|end| end > cutover)
                    {
                        Event::Across(info.position)
                    } else {
                        handler(bytes, info);
                        Event::Delivered(info.position)
                    });
                },
                MessageLimit::new(1),
            )
            .map_err(|error| MergeError::Replay(error.cause))?;
        if let Some(overrun) = summary.overrun.or(summary.closed_by_overrun) {
            return Err(MergeError::ReplayOverrun(overrun));
        }
        if let Some(position) = summary.revoked {
            return Err(MergeError::ReplayRevoked { position });
        }
        let event = if let Some(event) = seen {
            event
        } else if let Some(skipped) = summary.skipped {
            Event::Skipped(skipped)
        } else if let Some(aborted) = summary.aborted {
            Event::Aborted(aborted)
        } else if let (Some(end), Some(reason)) = (summary.closed, summary.close_reason) {
            Event::Closed(end, reason)
        } else {
            Event::Nothing
        };
        Ok((event, replay.subscription.position()))
    }

    /// Polls the live reader into `poll`, checking its first message
    /// against the replay's at the cutover before delivering it; returns
    /// the failure, if any.
    fn live<H>(
        &mut self,
        handler: &mut H,
        message_limit: MessageLimit,
        poll: &mut MergePoll,
    ) -> Option<MergeError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        let cutover = self.cutover;
        let State::Live { expect, first } = &mut self.state else {
            return None;
        };
        // Until the expected message came, one at a time.
        let limit = if expect.is_some() {
            MessageLimit::new(1)
        } else {
            message_limit
        };
        let mut mismatch = None;
        let mut delivered = 0;
        let polled = self.live.poll_taking(
            |bytes, info| {
                if let Some((position, length)) = *expect
                    && (info.position != position || bytes.len() != length)
                {
                    // Declined: a required reader keeps it pending.
                    mismatch = Some(info.position);
                    return false;
                }
                *expect = None;
                *first = false;
                delivered += 1;
                handler(bytes, info);
                true
            },
            limit,
        );
        let summary = match polled {
            Ok(summary) => summary,
            Err(error) => {
                poll.summary = PollSummary {
                    delivered,
                    ..error.summary
                };
                return Some(MergeError::Live(error.cause));
            }
        };
        poll.summary = PollSummary {
            delivered,
            ..summary
        };
        if let Some(position) = mismatch {
            return Some(MergeError::Mismatch { position, cutover });
        }
        if let (true, Some(overrun)) = (*first, summary.overrun.or(summary.closed_by_overrun)) {
            return Some(MergeError::LiveOverrun(overrun));
        }
        let other =
            summary.skipped.is_some() || summary.aborted.is_some() || summary.closed.is_some();
        match *expect {
            // The replay had a message at the cutover; the live reader
            // found something else there.
            Some((position, _)) if other => Some(MergeError::Mismatch { position, cutover }),
            _ => None,
        }
    }
}

/// The least position a message of `length` bytes at `position` can end
/// at: one frame, unfragmented. `None` past the representable.
fn shortest_end(position: u64, length: usize) -> Option<u64> {
    let frame = u32::try_from(length)
        .ok()
        .and_then(|length| length.checked_add(HEADER_LENGTH))
        .and_then(|length| align_frame(length).ok())?;
    position.checked_add(u64::from(frame))
}

/// What to do after one replay event.
enum Step {
    /// Poll the replay again.
    Next,
    /// End this poll.
    Stop,
    /// Switch to the live reader, expecting its first message to be this
    /// one, if any.
    Cutover(Option<(u64, usize)>),
}

/// A subscription whose overruns are recovered from a recording: the
/// `replay` rejoin policy with an Archive (SPEC.md §4 and §8.2;
/// `quantstratum-docs: karyos/design/rejoin-policies.md`, A6c).
///
/// On an overrun `{ from, lost_to, resume }` the live reader rejoins at
/// `resume`, and the poll reports the overrun with
/// [`RejoinOutcome::Replaying`]. The provider is asked for `[from,
/// resume)`, polled across polls, and nothing is delivered meanwhile; the
/// provider's own deadline bounds the wait. Its replay is merged into the
/// live reader at `resume` ([`LiveMerge`]): the poll on which the merge
/// settles ([`LiveMerge::is_settled`]) reports [`RejoinOutcome::Replayed`],
/// and the live reader goes on alone. When the provider has no replay,
/// or the merge fails, the secondary policy applies to the gap and the
/// poll reports [`RejoinOutcome::ReplayFallback`] with its reason; a
/// merge's typed error is kept ([`ReplayRejoin::merge_failure`]). Each
/// overrun is reported to the driver once, when it resolved.
///
/// While the gap is recovered the live reader is not polled: a required
/// one holds its publisher back, and an optional one can be lapped, which
/// fails the merge ([`MergeError::LiveOverrun`]) and applies the
/// secondary policy. Only lane 0 of a single subscription is recovered
/// (A6, Q6); another lane fails its merges.
pub struct ReplayRejoin<T: TermBytes = HeapTerms> {
    state: Rejoin<T>,
    source: PublicationIdentity,
    provider: Box<dyn ReplayProvider<T>>,
    secondary: Secondary,
    loss: Option<Box<LossReporter>>,
    lane: u8,
    failure: Option<MergeError>,
}

/// Where a [`ReplayRejoin`] stands.
enum Rejoin<T: TermBytes> {
    /// Delivering the live reader.
    Live(ClientSubscription<T>),
    /// Asking for the gap of `overrun`; the live reader holds at its
    /// resume.
    Asking {
        live: ClientSubscription<T>,
        overrun: Overrun,
    },
    /// Merging the replay of `overrun`'s gap, until it settles.
    Merging {
        merge: Box<LiveMerge<T>>,
        overrun: Overrun,
    },
    /// Only between two states, within a poll, with no handler running.
    Moving,
}

impl<T: TermBytes> core::fmt::Debug for ReplayRejoin<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = match &self.state {
            Rejoin::Live(_) => "Live",
            Rejoin::Asking { .. } => "Asking",
            Rejoin::Merging { .. } => "Merging",
            Rejoin::Moving => "Moving",
        };
        f.debug_struct("ReplayRejoin")
            .field("state", &state)
            .field("source", &self.source)
            .field("secondary", &self.secondary)
            .finish_non_exhaustive()
    }
}

impl<T: TermBytes> ReplayRejoin<T> {
    /// Recovers `subscription`'s overruns, the subscription of publication
    /// `source`, from `provider`'s replays, falling back to `secondary`.
    /// The subscription's own rejoin policy becomes `RejoinAtHead`, and its
    /// loss reports are made here instead.
    #[must_use]
    pub fn new(
        subscription: ClientSubscription<T>,
        source: PublicationIdentity,
        provider: Box<dyn ReplayProvider<T>>,
        secondary: Secondary,
    ) -> Self {
        let mut live = subscription.with_rejoin(RejoinPolicy::RejoinAtHead);
        let loss = live.take_loss_reports();
        let lane = live.lane().map_or(0, Lane::get);
        Self {
            state: Rejoin::Live(live),
            source,
            provider,
            secondary,
            loss,
            lane,
            failure: None,
        }
    }

    /// Whether a gap is being recovered: asked for, or merging.
    #[inline]
    #[must_use]
    pub fn is_recovering(&self) -> bool {
        matches!(self.state, Rejoin::Asking { .. } | Rejoin::Merging { .. })
    }

    /// The last merge's typed failure, if a merge failed.
    #[inline]
    #[must_use]
    pub fn merge_failure(&self) -> Option<MergeError> {
        self.failure
    }

    /// Gives the live reader back: a gap asked for is withdrawn, a replay
    /// merging is stopped. `None` only after a panic between two states,
    /// where no handler runs.
    #[must_use]
    pub fn into_live(mut self) -> Option<ClientSubscription<T>> {
        match std::mem::replace(&mut self.state, Rejoin::Moving) {
            Rejoin::Live(live) => Some(live),
            Rejoin::Asking { live, .. } => {
                self.provider.cancel();
                Some(live)
            }
            Rejoin::Merging { merge, .. } => Some(merge.into_live()),
            Rejoin::Moving => None,
        }
    }

    /// Delivers up to `message_limit` messages to `handler`, as
    /// [`ClientSubscription::poll`] does, recovering overruns (see the type
    /// documentation).
    ///
    /// # Errors
    ///
    /// As [`ClientSubscription::poll`]: the live reader's poll failures.
    #[expect(clippy::result_large_err, reason = "as ClientSubscription::poll")]
    pub fn poll<H>(
        &mut self,
        mut handler: H,
        message_limit: MessageLimit,
    ) -> Result<PollSummary, PollError>
    where
        H: FnMut(&[u8], MessageInfo),
    {
        if let Rejoin::Asking { overrun, .. } = self.state
            && let Some(resolved) = self.ask(overrun)
        {
            return Ok(resolved);
        }
        match &mut self.state {
            Rejoin::Live(live) => {
                let summary = live.poll(&mut handler, message_limit)?;
                Ok(self.overran(summary))
            }
            Rejoin::Merging { merge, .. } => match merge.poll(&mut handler, message_limit) {
                Ok(poll) => Ok(self.merged(poll.summary)),
                Err(failed) => self.merge_failed(failed),
            },
            Rejoin::Asking { .. } | Rejoin::Moving => Ok(PollSummary::default()),
        }
    }

    /// After a live poll: an overrun starts its recovery, reported as
    /// `Replaying`.
    fn overran(&mut self, mut summary: PollSummary) -> PollSummary {
        let Some(overrun) = summary
            .overrun
            .filter(|_| summary.closed_by_overrun.is_none())
        else {
            return summary;
        };
        match std::mem::replace(&mut self.state, Rejoin::Moving) {
            Rejoin::Live(live) => {
                summary.rejoin = Some(RejoinOutcome::Replaying);
                self.state = Rejoin::Asking { live, overrun };
            }
            other => self.state = other,
        }
        summary
    }

    /// Asks the provider for `overrun`'s gap: a replay starts its merge;
    /// none applies the secondary policy, and returns that poll's report.
    fn ask(&mut self, overrun: Overrun) -> Option<PollSummary> {
        let request = ReplayRequest {
            source: self.source,
            from: overrun.from,
            to: overrun.resume,
        };
        let status = self.provider.replay(&request);
        let Rejoin::Asking { live, overrun } = std::mem::replace(&mut self.state, Rejoin::Moving)
        else {
            return None;
        };
        match status {
            ReplayStatus::Pending => {
                self.state = Rejoin::Asking { live, overrun };
                None
            }
            ReplayStatus::Ready(replay) => {
                self.state = Rejoin::Merging {
                    merge: Box::new(LiveMerge::new(live, self.source, replay)),
                    overrun,
                };
                None
            }
            ReplayStatus::Unavailable(reason) => Some(self.fall_back(live, overrun, reason.into())),
        }
    }

    /// After a merge poll: once settled the gap is recovered, reported as
    /// `Replayed`, and the live reader goes on alone.
    fn merged(&mut self, mut summary: PollSummary) -> PollSummary {
        let settled = matches!(&self.state, Rejoin::Merging { merge, .. } if merge.is_settled());
        if !settled {
            return summary;
        }
        let Rejoin::Merging { merge, overrun } = std::mem::replace(&mut self.state, Rejoin::Moving)
        else {
            return summary;
        };
        let outcome = RejoinOutcome::Replayed {
            cutover: merge.cutover(),
        };
        self.report(&overrun, outcome);
        summary.rejoin = Some(outcome);
        self.state = Rejoin::Live(merge.into_live());
        summary
    }

    /// A merge that failed: the secondary policy applies to the gap, from
    /// the overrun's start to where the live reader is now. The live
    /// reader's own poll failure is passed on, and the merge goes on.
    #[expect(clippy::result_large_err, reason = "as ClientSubscription::poll")]
    fn merge_failed(&mut self, failed: MergeFailed) -> Result<PollSummary, PollError> {
        if let MergeError::Live(cause) = failed.cause {
            return Err(PollError {
                summary: failed.poll.summary,
                cause,
            });
        }
        self.failure = Some(failed.cause);
        let Rejoin::Merging { merge, overrun } = std::mem::replace(&mut self.state, Rejoin::Moving)
        else {
            return Ok(failed.poll.summary);
        };
        let live = merge.into_live();
        let position = live.position();
        let gap = Overrun {
            from: overrun.from,
            lost_to: position,
            resume: position,
        };
        let summary = self.fall_back(live, gap, ReplayFallbackReason::MergeFailed);
        Ok(PollSummary {
            delivered: failed.poll.summary.delivered,
            ..summary
        })
    }

    /// Applies the secondary policy to `overrun`'s gap and reports it.
    fn fall_back(
        &mut self,
        mut live: ClientSubscription<T>,
        overrun: Overrun,
        reason: ReplayFallbackReason,
    ) -> PollSummary {
        let secondary = match &mut self.secondary {
            Secondary::RejoinAtHead => SecondaryOutcome::ResumedAtHead,
            Secondary::Snapshot(source) => rebuild(source.as_mut(), &overrun),
            Secondary::Close => SecondaryOutcome::Closed,
        };
        let outcome = RejoinOutcome::ReplayFallback { reason, secondary };
        self.report(&overrun, outcome);
        let closed = outcome.closed();
        if closed {
            live.close_by_overrun(overrun, outcome);
        }
        self.state = Rejoin::Live(live);
        PollSummary {
            rejoin: Some(outcome),
            closed_by_overrun: closed.then_some(overrun),
            ..PollSummary::default()
        }
    }

    /// Reports how the overrun resolved, once, to the driver.
    fn report(&self, overrun: &Overrun, outcome: RejoinOutcome) {
        if let Some(loss) = &self.loss {
            loss.report_as(self.lane, overrun, RejoinPolicyCode::Replay, outcome);
        }
    }
}

impl From<ReplayUnavailable> for ReplayFallbackReason {
    fn from(reason: ReplayUnavailable) -> Self {
        match reason {
            ReplayUnavailable::NoRecording => Self::NoRecording,
            ReplayUnavailable::RetentionShort => Self::RetentionShort,
            ReplayUnavailable::RecordingBehind => Self::RecordingBehind,
            ReplayUnavailable::Refused => Self::Refused,
        }
    }
}

#[cfg(test)]
mod tests;
