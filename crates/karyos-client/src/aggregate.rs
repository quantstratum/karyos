// SPDX-License-Identifier: Apache-2.0

//! The aggregate subscriber (`quantstratum-docs:
//! karyos/design/aggregate-subscriber.md`, P2.4 l3): one frame-level
//! reader per configured lane of one aggregate, served in DRR order, one
//! frame per DRR step, each complete message delivered once with its lane.
//!
//! A poll first runs a control step outside DRR service, for the lanes the
//! DRR would find ineligible for a reason other than pending data: an
//! overrun applies the lane's rejoin policy, a message left `Ready` by a
//! panicking handler is taken, a lane at its seal moves to its successor,
//! and a lane that ended becomes terminal. The DRR then serves the lanes:
//! its probe peeks each lane's next block without serving it, applying a
//! zero-charge `Interrupted` skip itself, and its serve step calls
//! `serve_frame`, taking a complete message in the same step.
//!
//! Each lane keeps a first-loss position, set by its first overrun,
//! local gap or skipped range and never cleared. The aggregate's terminal
//! is a clean EOS only when every lane closed at its seal on the stream's
//! removal and no lane has a first loss (L6, GU-13).

use std::sync::Arc;

use karyos_protocol::lanes::drr::{Budget, Drr, DrrConfig, LaneSource, Probe, Report, Service};
use karyos_sys::error::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    FrameEnd, FrameReader, FrameStep, LogBuffer, Peek, SealReason, SkipReason, Stepped,
};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use crate::error::ClientError;
use crate::generation::{GenerationLink, Next, Successor};
use crate::link::{Export, Lease};
use crate::loss::LossReporter;
use crate::subscription::{
    ClientSubscription, LaneParts, MessageInfo, Overrun, RejoinOutcome, RejoinPolicy, Skipped,
    apply_rejoin,
};
use crate::trace::DeliveryTrace;

/// A lane's term contradicts what its reader found.
fn corrupt(reason: &'static str) -> ClientError {
    ClientError::Sys(SysError::CorruptTerm { offset: 0, reason })
}

/// Peeks one probe makes: a zero-charge `Interrupted` step is applied and
/// the interrupting frame peeked once more. Such steps cannot chain (the
/// interrupting frame is never a zero-charge step), so the applied step is
/// folded into the probe's own unit of work.
const PEEKS_PER_PROBE: u32 = 2;

/// How a lane ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneEnd {
    /// Closed at its seal, with no successor.
    Closed {
        /// The seal position.
        position: u64,
        /// Why the buffer was sealed.
        reason: SealReason,
    },
    /// Closed by its rejoin policy after an overrun.
    ClosedByOverrun(Overrun),
    /// Revoked.
    Revoked {
        /// The reader's position.
        position: u64,
    },
    /// Ended with an error.
    Failed(ClientError),
}

impl LaneEnd {
    /// Whether the lane ended without loss: closed at its seal by the
    /// stream's removal (L6). `Unspecified` is not clean: it also stands
    /// for a reason code this build does not know, which could be a loss.
    #[must_use]
    pub fn clean(self) -> bool {
        matches!(
            self,
            Self::Closed {
                reason: SealReason::StreamRemoved,
                ..
            }
        )
    }
}

/// What one poll did on one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LanePoll {
    /// Messages delivered.
    pub delivered: u64,
    /// The overrun the control step handled, with the rejoin outcome.
    pub overrun: Option<(Overrun, RejoinOutcome)>,
    /// The last range skipped.
    pub skipped: Option<Skipped>,
    /// The lane's first loss since its join, if any (never cleared).
    pub first_loss: Option<u64>,
    /// How the lane ended, once it did.
    pub end: Option<LaneEnd>,
}

/// The aggregate's terminal: every configured lane ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terminal {
    /// Whether it is a clean EOS: every lane closed at its seal with a
    /// normal reason and no lane reported a loss.
    pub clean: bool,
}

/// What one [`AggregateSubscription::poll`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatePoll {
    /// The DRR's report.
    pub drr: Report,
    /// Per configured lane, in lane order.
    pub lanes: Vec<LanePoll>,
    /// Set once every lane ended.
    pub terminal: Option<Terminal>,
}

/// One lane: its frame reader and the subscription state around it.
struct LaneState<T: TermBytes> {
    lane: Lane,
    reader: Option<FrameReader<Arc<LogBuffer<T>>>>,
    rejoin: RejoinPolicy,
    link: Option<Arc<GenerationLink<T>>>,
    base: u64,
    trace: Option<DeliveryTrace>,
    loss: Option<Box<LossReporter>>,
    /// The charge the last probe found.
    peeked: u32,
    first_loss: Option<u64>,
    end: Option<LaneEnd>,
    poll: LanePoll,
    _lease: Option<Lease>,
    /// Last: dropped after the mapping.
    _export: Option<Export>,
}

impl<T: TermBytes> LaneState<T> {
    fn new(lane: Lane, subscription: ClientSubscription<T>) -> Self {
        let LaneParts {
            inner,
            rejoin,
            link,
            base,
            trace,
            loss,
            lease,
            export,
        } = subscription.into_lane_parts();
        Self {
            lane,
            reader: inner.map(FrameReader::new),
            rejoin,
            link,
            base,
            trace,
            loss,
            peeked: 0,
            first_loss: None,
            end: None,
            poll: LanePoll::default(),
            _lease: lease,
            _export: export,
        }
    }

    /// Records a loss at `position` if it is the lane's first.
    fn lost(&mut self, position: u64) {
        self.first_loss.get_or_insert(position);
    }

    /// Ends the lane: its cell detaches, and its link closes.
    fn finish(&mut self, end: LaneEnd) {
        drop(self.reader.take());
        if let Some(link) = self.link.take() {
            drop(link.close());
            drop(link.take_retired());
        }
        self.end = Some(end);
    }

    /// Records a stepped record: a skipped range is a loss unless the
    /// reader joined in the middle of a message.
    fn stepped(&mut self, kind: Stepped) {
        if let Stepped::Skipped {
            position,
            extent,
            reason,
        } = kind
        {
            let position = self.base + position;
            self.poll.skipped = Some(Skipped {
                position,
                extent,
                reason,
            });
            if reason != SkipReason::JoinedMidMessage {
                self.lost(position);
            }
        }
    }

    /// Takes a complete message and delivers it to `handler`; a traced
    /// lane records the delivery attempt once the handler returned.
    fn take<H>(&mut self, handler: &mut H)
    where
        H: FnMut(&[u8], Lane, MessageInfo),
    {
        let Some(reader) = self.reader.as_mut() else {
            return;
        };
        let base = self.base;
        let lane = self.lane;
        let mut taken = None;
        let delivered = reader.take(|bytes, info| {
            let info = MessageInfo {
                position: base + info.position,
                reserved_value: info.reserved_value,
                end_of_stream: info.end_of_stream,
                extension: info.extension,
            };
            taken = Some(info);
            handler(bytes, lane, info);
        });
        if let (true, Some(info)) = (delivered, taken) {
            self.poll.delivered += 1;
            if let Some(trace) = self.trace.as_mut() {
                // The cursor is past the message now.
                let end = base + reader.subscription().position();
                trace.attempt(info.trace().as_ref(), lane, info.position, end);
            }
        }
    }

    /// The control step for this lane, outside DRR service: overruns,
    /// `Ready` messages, cutovers and ends. Returns the units of work it
    /// spent: one per lane it peeked.
    fn control<H>(&mut self, handler: &mut H) -> u32
    where
        H: FnMut(&[u8], Lane, MessageInfo),
    {
        if self.end.is_some() {
            return 0;
        }
        let Some(reader) = self.reader.as_mut() else {
            return 0;
        };
        match reader.peek() {
            Ok(Peek::Ready) => self.take(handler),
            Ok(Peek::Ended) => match reader.serve_frame() {
                Ok(FrameStep::Ended(end)) => self.ended(end),
                Ok(_) => {}
                Err(error) => self.finish(LaneEnd::Failed(ClientError::from(error))),
            },
            Ok(Peek::Step { .. } | Peek::Pending) => {}
            Err(error) => self.finish(LaneEnd::Failed(ClientError::from(error))),
        }
        1
    }

    /// Handles a frame reader's end: an overrun applies the rejoin policy,
    /// a seal moves to a successor if there is one.
    fn ended(&mut self, end: FrameEnd) {
        match end {
            FrameEnd::Overrun {
                from,
                lost_to,
                resume,
            } => {
                let overrun = Overrun {
                    from: self.base + from,
                    lost_to: self.base + lost_to,
                    resume: self.base + resume,
                };
                self.lost(overrun.from);
                let outcome = apply_rejoin(&mut self.rejoin, &overrun);
                if let Some(loss) = &self.loss {
                    loss.report(self.lane.get(), &overrun, &self.rejoin, outcome);
                }
                self.poll.overrun = Some((overrun, outcome));
                if outcome.closed() {
                    self.finish(LaneEnd::ClosedByOverrun(overrun));
                }
            }
            FrameEnd::Revoked { position } => self.finish(LaneEnd::Revoked {
                position: self.base + position,
            }),
            FrameEnd::Closed { position, reason } => {
                if !self.move_to_successor() {
                    self.finish(LaneEnd::Closed {
                        position: self.base + position,
                        reason,
                    });
                }
            }
        }
    }

    /// At the seal of the lane's mapping: moves to an offered successor, or
    /// waits for a pending one. `false` when no successor will come.
    fn move_to_successor(&mut self) -> bool {
        let (Some(link), Some(reader)) = (self.link.as_ref(), self.reader.as_ref()) else {
            return false;
        };
        match link.next(reader.subscription().buffer().sealed_with_successor()) {
            // A pending cutover: the lane waits, ineligible.
            Next::Wait => true,
            Next::Moved {
                base,
                successor: Successor::Subscription { inner, .. },
            } => {
                // The predecessor's cell detaches with its reader.
                self.reader = Some(FrameReader::new(inner));
                self.base = base;
                true
            }
            // A remote successor needs the IPC path, outside l3; a
            // successor of another kind is a driver bug.
            Next::Moved { .. } | Next::End => false,
        }
    }
}

/// An aggregate subscription: one frame reader per configured lane and one
/// DRR (`quantstratum-docs: karyos/design/aggregate-subscriber.md`).
pub struct AggregateSubscription<T: TermBytes = HeapTerms> {
    lanes: Vec<LaneState<T>>,
    drr: Drr,
    /// Run at the start of each DRR serve step: tests reproduce a race
    /// between a probe's peek and the serve there.
    #[cfg(test)]
    between: Option<Box<dyn FnMut()>>,
    /// Run just before the probe applies a zero-charge step: tests
    /// reproduce a race between the probe's peek and that serve there.
    #[cfg(test)]
    before_zero_charge: Option<Box<dyn FnMut()>>,
}

impl<T: TermBytes> core::fmt::Debug for AggregateSubscription<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AggregateSubscription")
            .field("lanes", &self.lanes.len())
            .field("drr", &self.drr)
            .finish()
    }
}

impl<T: TermBytes> AggregateSubscription<T> {
    /// An aggregate subscription over `lanes`, one subscription per
    /// configured lane in lane order, served under `config` (the
    /// aggregate's profile).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Protocol`] when `lanes` does not hold one
    /// subscription per configured lane.
    pub fn new(
        config: DrrConfig,
        lanes: Vec<(Lane, ClientSubscription<T>)>,
    ) -> Result<Self, ClientError> {
        if lanes.len() != config.lanes() {
            return Err(ClientError::Sys(SysError::Protocol {
                reason: "one subscription per configured lane",
            }));
        }
        // A subscription its rejoin policy already closed has no cell, so
        // its lane could never report a terminal.
        if lanes
            .iter()
            .any(|(_, subscription)| subscription.is_closed_by_overrun())
        {
            return Err(ClientError::ClosedByOverrun);
        }
        Ok(Self {
            lanes: lanes
                .into_iter()
                .map(|(lane, subscription)| LaneState::new(lane, subscription))
                .collect(),
            drr: Drr::new(config),
            #[cfg(test)]
            between: None,
            #[cfg(test)]
            before_zero_charge: None,
        })
    }

    /// The DRR state, for diagnostics.
    #[must_use]
    pub fn drr(&self) -> &Drr {
        &self.drr
    }

    /// Serves the lanes within `budget`, delivering each complete message
    /// once to `handler` with its lane. The handler gets a slice of the
    /// lane's assembly, valid only for that call, with no loan held; a
    /// required lane acknowledges after it returns. If it panics, the
    /// message is delivered again by a later poll's control step.
    pub fn poll<H>(&mut self, mut handler: H, budget: Budget) -> AggregatePoll
    where
        H: FnMut(&[u8], Lane, MessageInfo),
    {
        for lane in &mut self.lanes {
            lane.poll = LanePoll::default();
        }
        // The control step, outside DRR service.
        // Its units come out of the call's work before the DRR runs.
        let mut spent = 0u32;
        for lane in &mut self.lanes {
            spent = spent.saturating_add(lane.control(&mut handler));
        }
        let budget = Budget {
            work: budget.work.saturating_sub(spent),
            ..budget
        };
        let max_charge = self.drr.config().max_charge();
        let drr = self.drr.run(
            budget,
            &mut Source {
                lanes: &mut self.lanes,
                handler: &mut handler,
                max_charge,
                #[cfg(test)]
                between: self.between.as_mut(),
                #[cfg(test)]
                before_zero_charge: self.before_zero_charge.as_mut(),
            },
        );
        let lanes: Vec<LanePoll> = self
            .lanes
            .iter()
            .map(|lane| LanePoll {
                first_loss: lane.first_loss,
                end: lane.end,
                ..lane.poll
            })
            .collect();
        let terminal = lanes
            .iter()
            .all(|lane| lane.end.is_some())
            .then(|| Terminal {
                clean: lanes
                    .iter()
                    .all(|lane| lane.first_loss.is_none() && lane.end.is_some_and(LaneEnd::clean)),
            });
        AggregatePoll {
            drr,
            lanes,
            terminal,
        }
    }
}

/// The DRR's view of the lanes for one poll.
struct Source<'a, T: TermBytes, H> {
    #[cfg(test)]
    between: Option<&'a mut Box<dyn FnMut()>>,
    #[cfg(test)]
    before_zero_charge: Option<&'a mut Box<dyn FnMut()>>,
    lanes: &'a mut [LaneState<T>],
    handler: &'a mut H,
    max_charge: u64,
}

impl<T: TermBytes, H> LaneSource for Source<'_, T, H>
where
    H: FnMut(&[u8], Lane, MessageInfo),
{
    fn probe(&mut self, lane: usize) -> Probe {
        let Some(state) = self.lanes.get_mut(lane) else {
            return Probe::Ineligible;
        };
        for _ in 0..PEEKS_PER_PROBE {
            if state.end.is_some() {
                return Probe::Ineligible;
            }
            let Some(reader) = state.reader.as_mut() else {
                return Probe::Ineligible;
            };
            match reader.peek() {
                Ok(Peek::Step { charge: 0 }) => {
                    // An Interrupted skip: applied here, outside DRR
                    // service, and the probe looks at the interrupting
                    // frame.
                    #[cfg(test)]
                    if let Some(hook) = self.before_zero_charge.as_mut() {
                        hook();
                    }
                    match reader.serve_frame() {
                        Ok(FrameStep::Stepped { charge: 0, kind }) => state.stepped(kind),
                        // The reader ended between the peek and the serve:
                        // an overrun was consumed by `serve_frame`, so its
                        // loss and rejoin policy are applied now.
                        Ok(FrameStep::Ended(end)) => {
                            state.ended(end);
                            return Probe::Ineligible;
                        }
                        // Nothing was read: a floor or a slot moved first.
                        Ok(FrameStep::Pending) => return Probe::Ineligible,
                        // A copy or a charged step where the peek saw a
                        // zero-charge one: committed frames are immutable,
                        // so the term is corrupt, and nothing is served.
                        Ok(_) => {
                            state.finish(LaneEnd::Failed(corrupt("a zero-charge step changed")));
                            return Probe::Ineligible;
                        }
                        Err(error) => {
                            state.finish(LaneEnd::Failed(ClientError::from(error)));
                            return Probe::Ineligible;
                        }
                    }
                }
                Ok(Peek::Step { charge }) => {
                    if u64::from(charge) > self.max_charge {
                        // Above every frame of the geometry: a corrupt term.
                        state.finish(LaneEnd::Failed(corrupt("charge above every frame")));
                        return Probe::Ineligible;
                    }
                    state.peeked = charge;
                    return Probe::Eligible {
                        charge: u64::from(charge),
                    };
                }
                Ok(Peek::Ready | Peek::Pending | Peek::Ended) => return Probe::Ineligible,
                Err(error) => {
                    state.finish(LaneEnd::Failed(ClientError::from(error)));
                    return Probe::Ineligible;
                }
            }
        }
        Probe::Ineligible
    }

    fn serve(&mut self, lane: usize) -> Service {
        #[cfg(test)]
        if let Some(between) = self.between.as_mut() {
            between();
        }
        let Some(state) = self.lanes.get_mut(lane) else {
            return Service::NotServed;
        };
        let Some(reader) = state.reader.as_mut() else {
            return Service::NotServed;
        };
        let peeked = state.peeked;
        let step = match reader.serve_frame() {
            Ok(step) => step,
            Err(error) => {
                state.finish(LaneEnd::Failed(ClientError::from(error)));
                return Service::NotServed;
            }
        };
        let charge = match step {
            FrameStep::Copied { charge }
            | FrameStep::Complete { charge, .. }
            | FrameStep::Stepped { charge, .. } => charge,
            // Nothing was copied between the peek and the serve. An overrun
            // found here was consumed by `serve_frame`, which rejoined: its
            // loss and rejoin policy are applied now, outside any loan.
            FrameStep::Ended(end) => {
                state.ended(end);
                return Service::NotServed;
            }
            FrameStep::Ready | FrameStep::Pending => return Service::NotServed,
        };
        if charge != peeked {
            // Committed frames are immutable: served at the peeked charge
            // so the DRR's accounting stays bounded, then the lane ends, and
            // a message it completed is not delivered.
            debug_assert_eq!(charge, peeked, "a committed frame changed its charge");
            state.finish(LaneEnd::Failed(corrupt(
                "a committed frame changed its charge",
            )));
            return Service::Served;
        }
        match step {
            FrameStep::Complete { .. } => state.take(&mut *self.handler),
            FrameStep::Stepped { kind, .. } => state.stepped(kind),
            _ => {}
        }
        Service::Served
    }
}

#[cfg(test)]
mod tests;
