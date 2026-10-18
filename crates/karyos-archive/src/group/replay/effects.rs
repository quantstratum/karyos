// SPDX-License-Identifier: Apache-2.0

//! The handler's calls under replay, checked against their recorded
//! observations (`quantstratum-docs: karyos/design/recording-group-replay.md`
//! section 4).
//!
//! [`ReplayEffects`] is the [`Effects`] a replayed event's handler acts
//! through. Each call but `clock` is the event's next observation: it is
//! never performed, it is checked against the recorded observation of
//! its index, and the recorded result is returned. The first difference
//! is kept as a [`Divergence`]; after it every call returns a neutral
//! answer and nothing more is checked, since the recorded results no
//! longer answer the handler.
//!
//! Checked: an operation's kind and its publication's stream and
//! session; an output intent's `length` and `crc32c` (an offer's payload,
//! a commit's claimed bytes; section 5); a claim's length against the
//! scratch claim; a delivery poll's `max` (template 15), after which
//! exactly its recorded `count` deliveries are presented; a timer's id,
//! action and deadline; an external value's kind.

use super::{ReplayError, ReplayEvent};
use crate::crc32c::crc32c;
use crate::group::gateway::{self, ClaimCommit, DeliveryOutcome, Effects, PublicationId, TimerId};
use crate::group::record::{
    DeliveryObservation, DeliveryPoll, GroupRecord, Operation, Outcome, OutcomeObservation,
    TimerAction, TimerObservation,
};

#[cfg(test)]
mod tests;

/// A call the handler made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    /// `offer`.
    Offer {
        /// The publication.
        publication: PublicationId,
        /// The payload's length.
        length: u32,
        /// Its CRC-32C.
        crc32c: u32,
    },
    /// `claim`.
    Claim {
        /// The publication.
        publication: PublicationId,
        /// The length asked for.
        length: usize,
    },
    /// A claim's commit, or its abort when `write` returned false.
    Commit {
        /// The claim's publication.
        publication: PublicationId,
        /// The claimed bytes' length.
        length: u32,
        /// Their CRC-32C, as written.
        crc32c: u32,
        /// `write` returned false.
        aborted: bool,
    },
    /// `poll_outcomes`.
    PollOutcomes {
        /// The publication.
        publication: PublicationId,
        /// The call's maximum.
        max: u32,
    },
    /// `schedule`.
    Schedule {
        /// The timer.
        timer: TimerId,
        /// Its deadline.
        deadline: u64,
    },
    /// `cancel`.
    Cancel {
        /// The timer.
        timer: TimerId,
    },
    /// `external`.
    External {
        /// The application's kind.
        kind: u32,
    },
}

/// The recorded observation a call was checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// An operation's outcome (template 11).
    Outcome {
        /// Offer, claim or commit.
        operation: Operation,
        /// The stream.
        stream_id: i32,
        /// The session.
        session_id: i32,
        /// The output intent's length; 0 for a claim.
        length: u32,
        /// Its CRC-32C; 0 for a claim.
        crc32c: u32,
    },
    /// A delivery poll (template 15).
    Poll {
        /// The call's maximum.
        max: u32,
        /// The stream.
        stream_id: i32,
        /// The session.
        session_id: i32,
    },
    /// A timer operation (template 12).
    Timer {
        /// Create or cancel.
        action: TimerAction,
        /// The timer.
        timer_id: u64,
        /// Its deadline.
        deadline: u64,
    },
    /// An external value (template 13).
    External {
        /// The application's kind.
        kind: u32,
    },
    /// A delivery outcome (template 14).
    Delivery {
        /// The stream.
        stream_id: i32,
        /// The session.
        session_id: i32,
    },
    /// A record that is no observation, or that does not decode: the
    /// journal checked it, so this is not expected.
    Other,
}

/// How a replayed handler differed from its recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivergenceKind {
    /// A call past the event's recorded observations.
    Extra {
        /// The call.
        found: Call,
    },
    /// The handler returned with recorded observations left.
    Missing {
        /// The first one it did not make.
        expected: Recorded,
    },
    /// A call of another kind than recorded, or with other arguments: a
    /// publication, a timer or a kind the record does not name, an output
    /// intent's other bytes, or an abort where a commit was recorded.
    Call {
        /// The recorded observation.
        expected: Recorded,
        /// The call.
        found: Call,
    },
}

/// The first difference between a replayed handler and its recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Divergence {
    /// The event.
    pub group_seq: u64,
    /// The observation's index within the event.
    pub index: u32,
    /// What differed.
    pub kind: DivergenceKind,
}

impl Call {
    /// The template the call would record.
    #[must_use]
    pub const fn template(&self) -> u16 {
        match self {
            Self::Offer { .. } | Self::Claim { .. } | Self::Commit { .. } => 11,
            Self::Schedule { .. } | Self::Cancel { .. } => 12,
            Self::External { .. } => 13,
            Self::PollOutcomes { .. } => 15,
        }
    }
}

impl Recorded {
    /// The record's template; 0 for [`Recorded::Other`].
    #[must_use]
    pub const fn template(&self) -> u16 {
        match self {
            Self::Outcome { .. } => 11,
            Self::Timer { .. } => 12,
            Self::External { .. } => 13,
            Self::Delivery { .. } => 14,
            Self::Poll { .. } => 15,
            Self::Other => 0,
        }
    }
}

impl From<Divergence> for gateway::Divergence {
    fn from(divergence: Divergence) -> Self {
        let (expected, found) = match divergence.kind {
            DivergenceKind::Extra { found } => (0, found.template()),
            DivergenceKind::Missing { expected } => (expected.template(), 0),
            DivergenceKind::Call { expected, found } => (expected.template(), found.template()),
        };
        Self {
            group_seq: divergence.group_seq,
            index: divergence.index,
            expected,
            found,
        }
    }
}

/// A replayed event's [`Effects`].
#[derive(Debug)]
pub struct ReplayEffects<'e, 's> {
    event: ReplayEvent<'e>,
    /// Per publication id, its `(stream_id, session_id)`.
    publications: &'s [(i32, i32)],
    /// The scratch claim's buffer, of the largest claim.
    scratch: &'s mut [u8],
    logical_time: u64,
    /// The recorded observations matched so far: the next one is record
    /// `matched + 1`.
    matched: u32,
    /// The event's recorded observations: records 1 to `len - 2`.
    observations: u32,
    /// The event's capture is incomplete: a call past its recorded
    /// observations is no divergence, since the capture stopped there,
    /// and gets a neutral answer.
    incomplete: bool,
    /// A call went past an incomplete event's recorded observations.
    past_recorded: bool,
    diverged: Option<Divergence>,
}

impl<'e, 's> ReplayEffects<'e, 's> {
    /// The effects of `event`, with the configuration's `publications`
    /// (`(stream_id, session_id)` by publication id) and a `scratch`
    /// buffer of the largest claim.
    ///
    /// # Errors
    ///
    /// [`ReplayError::Record`] for an event whose first record does not
    /// decode, and [`ReplayError::Records`] for one of fewer than two
    /// records or more observations than a `u32` counts: none for one the
    /// cursor gave.
    pub fn new(
        event: ReplayEvent<'e>,
        publications: &'s [(i32, i32)],
        scratch: &'s mut [u8],
    ) -> Result<Self, ReplayError> {
        let observations = event
            .len()
            .checked_sub(2)
            .and_then(|observations| u32::try_from(observations).ok())
            .ok_or(ReplayError::Records {
                capacity: event.len(),
            })?;
        let logical_time = match event.record(0).transpose()? {
            Some(GroupRecord::Message(record)) => record.logical_time,
            Some(GroupRecord::Conflated(record)) => record.logical_time,
            Some(GroupRecord::Timer(record)) => record.logical_time,
            Some(GroupRecord::Lifecycle(record)) => record.logical_time,
            Some(GroupRecord::External(record)) => record.logical_time,
            Some(GroupRecord::Loss(record)) => record.logical_time,
            _ => 0,
        };
        Ok(Self {
            event,
            publications,
            scratch,
            logical_time,
            matched: 0,
            observations,
            incomplete: event.incomplete(),
            past_recorded: false,
            diverged: None,
        })
    }

    /// How the handler ended the event: `Ok` when it made exactly the
    /// recorded observations (for an incomplete event, at least them),
    /// else the first [`Divergence`].
    ///
    /// # Errors
    ///
    /// The divergence.
    pub fn finish(self) -> Result<(), Divergence> {
        if let Some(divergence) = self.diverged {
            return Err(divergence);
        }
        if self.matched < self.observations && !self.past_recorded {
            return Err(Divergence {
                group_seq: self.event.group_seq(),
                index: self.index(),
                kind: DivergenceKind::Missing {
                    expected: self
                        .peek()
                        .map_or(Recorded::Other, |record| recorded(&record)),
                },
            });
        }
        Ok(())
    }

    /// The divergence so far.
    #[must_use]
    pub const fn divergence(&self) -> Option<Divergence> {
        self.diverged
    }

    /// The recorded observations the handler's calls matched so far, in
    /// order: those a capture repeats, since a matched call is the
    /// recorded one.
    #[must_use]
    pub const fn matched(&self) -> u32 {
        self.matched
    }

    /// The next observation's index.
    const fn index(&self) -> u32 {
        self.matched
    }

    fn peek(&self) -> Option<GroupRecord<'e>> {
        if self.matched >= self.observations {
            return None;
        }
        let record = usize::try_from(self.matched).ok()?.checked_add(1)?;
        self.event.record(record).and_then(Result::ok)
    }

    /// The next observation was taken: below `observations`, so it never
    /// overflows.
    fn advance(&mut self) {
        if let Some(matched) = self.matched.checked_add(1) {
            self.matched = matched;
        }
    }

    fn publication(&self, publication: PublicationId) -> Option<(i32, i32)> {
        self.publications.get(usize::from(publication.0)).copied()
    }

    /// Diverges at the next observation, unless replay already did:
    /// `call` is not the recorded one there.
    fn diverge(&mut self, call: Call) {
        if self.diverged.is_some() || self.past_recorded {
            return;
        }
        let kind = match self.peek() {
            // Past an incomplete event's recorded observations, as `take`
            // treats a call there: no divergence.
            None if self.incomplete => {
                self.past_recorded = true;
                return;
            }
            Some(record) => DivergenceKind::Call {
                expected: recorded(&record),
                found: call,
            },
            None => DivergenceKind::Extra { found: call },
        };
        self.diverged = Some(Divergence {
            group_seq: self.event.group_seq(),
            index: self.index(),
            kind,
        });
    }

    /// Takes the next observation for `call`, or diverges: `matches` says
    /// whether the record answers the call.
    fn take(
        &mut self,
        call: Call,
        matches: impl FnOnce(&GroupRecord<'e>) -> bool,
    ) -> Option<GroupRecord<'e>> {
        if self.diverged.is_some() || self.past_recorded {
            return None;
        }
        let index = self.index();
        let kind = match self.peek() {
            None if self.incomplete => {
                self.past_recorded = true;
                return None;
            }
            None => DivergenceKind::Extra { found: call },
            Some(record) if matches(&record) => {
                self.advance();
                return Some(record);
            }
            Some(record) => DivergenceKind::Call {
                expected: recorded(&record),
                found: call,
            },
        };
        self.diverged = Some(Divergence {
            group_seq: self.event.group_seq(),
            index,
            kind,
        });
        None
    }

    /// The next observation, an outcome of `operation` on `publication`
    /// with the output intent `(length, crc32c)`, `(0, 0)` for a claim.
    fn outcome(
        &mut self,
        call: Call,
        operation: Operation,
        publication: PublicationId,
        intent: (u32, u32),
    ) -> Option<OutcomeObservation> {
        self.outcome_where(call, operation, publication, intent, |_| true)
    }

    /// [`Self::outcome`], with a recorded outcome `allowed` admits.
    fn outcome_where(
        &mut self,
        call: Call,
        operation: Operation,
        publication: PublicationId,
        intent: (u32, u32),
        allowed: impl FnOnce(&Outcome) -> bool,
    ) -> Option<OutcomeObservation> {
        let source = self.publication(publication);
        match self.take(call, |record| {
            matches!(record, GroupRecord::Outcome(observation)
                if observation.operation == operation
                    && Some((observation.stream_id, observation.session_id)) == source
                    && (observation.length, observation.crc32c) == intent
                    && allowed(&observation.outcome))
        }) {
            Some(GroupRecord::Outcome(observation)) => Some(observation),
            _ => None,
        }
    }

    fn timer(&mut self, call: Call, action: TimerAction, timer: TimerId, deadline: Option<u64>) {
        let _ = self.take(call, |record| {
            matches!(record, GroupRecord::TimerOperation(TimerObservation {
                action: recorded, timer_id, deadline: at, ..
            }) if *recorded == action
                && *timer_id == u64::from(timer.0)
                && deadline.is_none_or(|deadline| deadline == *at))
        });
    }
}

/// What `record` is, as a divergence names it.
fn recorded(record: &GroupRecord<'_>) -> Recorded {
    match record {
        GroupRecord::Outcome(observation) => Recorded::Outcome {
            operation: observation.operation,
            stream_id: observation.stream_id,
            session_id: observation.session_id,
            length: observation.length,
            crc32c: observation.crc32c,
        },
        GroupRecord::Poll(poll) => Recorded::Poll {
            max: poll.max,
            stream_id: poll.stream_id,
            session_id: poll.session_id,
        },
        GroupRecord::TimerOperation(observation) => Recorded::Timer {
            action: observation.action,
            timer_id: observation.timer_id,
            deadline: observation.deadline,
        },
        GroupRecord::ExternalObservation(observation) => Recorded::External {
            kind: observation.kind,
        },
        GroupRecord::Delivery(observation) => Recorded::Delivery {
            stream_id: observation.stream_id,
            session_id: observation.session_id,
        },
        _ => Recorded::Other,
    }
}

/// The answer to a call replay cannot answer from the recording: past
/// an incomplete event's recorded observations, or after a divergence.
/// It is what the live strict Gateway returns for a call it cannot record
/// and so does not perform (recording-group-gateway.md section 8), so a
/// handler sees the same outcome in both.
const NEUTRAL: Outcome = Outcome::Gated;

impl Effects for ReplayEffects<'_, '_> {
    fn clock(&self) -> u64 {
        self.logical_time
    }

    fn offer(&mut self, publication: PublicationId, payload: &[u8]) -> Outcome {
        let Some(intent) = digest(payload) else {
            // No record holds a length past `u32`.
            self.diverge(Call::Offer {
                publication,
                length: u32::MAX,
                crc32c: crc32c(payload),
            });
            return NEUTRAL;
        };
        let call = Call::Offer {
            publication,
            length: intent.0,
            crc32c: intent.1,
        };
        self.outcome(call, Operation::Offer, publication, intent)
            .map_or(NEUTRAL, |observation| observation.outcome)
    }

    fn claim(
        &mut self,
        publication: PublicationId,
        length: usize,
        write: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        let refused = |claim| ClaimCommit {
            claim,
            commit: None,
        };
        let call = Call::Claim {
            publication,
            length,
        };
        let Some(observation) = self.outcome(call, Operation::Claim, publication, (0, 0)) else {
            return refused(NEUTRAL);
        };
        let Outcome::Accepted { lane, position } = observation.outcome else {
            return refused(observation.outcome);
        };
        // What a commit that cannot be answered from the recording returns:
        // an abort at the claim, as a commit only accepts or aborts.
        let unanswered = Outcome::Aborted { lane, position };
        // A claim longer than the largest configured one: the recording
        // was made under another configuration. Its claim matched; the
        // divergence is at its commit, the next observation, where the
        // capture ends too.
        let Some(bytes) = self.scratch.get_mut(..length) else {
            self.diverge(call);
            return ClaimCommit {
                claim: observation.outcome,
                commit: Some(unanswered),
            };
        };
        // Bytes an earlier claim left are not this claim's.
        bytes.fill(0);
        let committed = write(bytes);
        let crc = crc32c(bytes);
        let Some(intent) = digest(bytes) else {
            self.diverge(call);
            return ClaimCommit {
                claim: observation.outcome,
                commit: Some(unanswered),
            };
        };
        let call = Call::Commit {
            publication,
            length: intent.0,
            crc32c: crc,
            aborted: !committed,
        };
        // An abort is recorded as an aborted commit; a commit may have been
        // recorded aborted too, when it lost to a guard's abort.
        let commit = self
            .outcome_where(call, Operation::Commit, publication, intent, |outcome| {
                committed || matches!(outcome, Outcome::Aborted { .. })
            })
            .map_or(unanswered, |observation| observation.outcome);
        ClaimCommit {
            claim: observation.outcome,
            commit: Some(commit),
        }
    }

    fn poll_outcomes(
        &mut self,
        publication: PublicationId,
        max: u32,
        each: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32 {
        let source = self.publication(publication);
        let call = Call::PollOutcomes { publication, max };
        let Some(GroupRecord::Poll(DeliveryPoll { count, .. })) = self.take(call, |record| {
            matches!(record, GroupRecord::Poll(poll)
                if poll.max == max && Some((poll.stream_id, poll.session_id)) == source)
        }) else {
            return 0;
        };
        // The journal's order rules put exactly `count` deliveries of the
        // poll's stream and session next.
        for _ in 0..count {
            let Some(GroupRecord::Delivery(observation)) = self.peek() else {
                return 0;
            };
            self.advance();
            each(&delivery(&observation));
        }
        count
    }

    fn schedule(&mut self, timer: TimerId, deadline: u64) {
        self.timer(
            Call::Schedule { timer, deadline },
            TimerAction::Create,
            timer,
            Some(deadline),
        );
    }

    fn cancel(&mut self, timer: TimerId) {
        self.timer(Call::Cancel { timer }, TimerAction::Cancel, timer, None);
    }

    fn external(&mut self, kind: u32, _read: &mut dyn FnMut(&mut [u8]) -> usize) -> &[u8] {
        match self.take(Call::External { kind }, |record| {
            matches!(record, GroupRecord::ExternalObservation(observation) if observation.kind == kind)
        }) {
            Some(GroupRecord::ExternalObservation(observation)) => observation.value,
            _ => &[],
        }
    }
}

/// An output intent's `(length, crc32c)`; `None` for a length past
/// `u32`, which no record holds.
fn digest(bytes: &[u8]) -> Option<(u32, u32)> {
    Some((u32::try_from(bytes.len()).ok()?, crc32c(bytes)))
}

fn delivery(observation: &DeliveryObservation) -> DeliveryOutcome {
    DeliveryOutcome {
        kind: observation.kind,
        lane: observation.lane,
        receiver: observation.receiver,
        incarnation: observation.incarnation,
        start: observation.start,
        end: observation.end,
        epoch: observation.epoch,
        reason: observation.reason,
        lost: observation.lost,
    }
}
