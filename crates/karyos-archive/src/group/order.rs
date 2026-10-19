// SPDX-License-Identifier: Apache-2.0

//! The order rules of a recording group's journal (`quantstratum-docs:
//! karyos/design/recording-group-records.md` section 7): one definition
//! that the journal store (A7b) and recovery (A7c) apply.
//!
//! An [`OrderCheck`] takes the journal's records in order and reports the
//! first that breaks a rule, with its ordinal. Its state is a few words;
//! nothing allocates.

use super::record::{Capture, EndOutcome, Role};

#[cfg(test)]
mod tests;

/// The rule a record broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OrderRule {
    /// The first record is not the header, or a later one is.
    Header,
    /// An event or gap whose `group_seq` is not the next one.
    Sequence,
    /// An event opened inside another event.
    Nested,
    /// An observation or end outside an event, or naming another event.
    OutsideEvent,
    /// An observation whose index is not the next one.
    Index,
    /// An end whose observation count is not the event's.
    Count,
    /// A delivery observation its poll did not announce, or on another
    /// publication than its poll's, or another record before a poll's
    /// delivery observations are all there.
    Poll,
    /// A record after a strict journal's incomplete end.
    AfterIncomplete,
    /// A gap marker in a strict journal.
    StrictGap,
    /// An uncaptured payload (payload 3) or a reference unavailable record
    /// in a strict journal, or a reference unavailable record naming an
    /// event before the first or not ended (A7d). That the event's payload
    /// is by reference, and is named once, is the prefix tracker's check:
    /// it holds the events waiting on their payloads, and this checker
    /// holds a few words.
    Unavailable,
    /// A checkpoint naming an event before the first or not ended, or one
    /// whose `group_seq` or `checkpoint_id` is not above the previous
    /// recorded checkpoint's (A9). A failed write leaves no record, so
    /// only recorded checkpoints count.
    Checkpoint,
    /// A `group_seq` or index past `u64` or `u32`.
    Exhausted,
    /// A role no decoded record has: a header whose first `group_seq` is
    /// 0, a gap that ends before it starts, or a checkpoint whose
    /// `group_seq` or `checkpoint_id` is 0. Roles are plain values, so
    /// the checker refuses these itself.
    Invalid,
}

/// A record that broke an order rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("journal record {ordinal} breaks the order rule {rule:?}")]
#[non_exhaustive]
pub struct OrderError {
    /// The record's ordinal in the journal, from 0.
    pub ordinal: u64,
    /// The rule.
    pub rule: OrderRule,
}

/// Where a journal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No header yet.
    Start,
    /// Between events: the next is `next_seq`.
    Between,
    /// Inside event `seq`, expecting observation `index` or its end;
    /// `owed` delivery observations on `publication` come first.
    InEvent {
        seq: u64,
        index: u32,
        owed: u32,
        publication: (i32, i32),
    },
    /// A strict journal ended at an incomplete event.
    Ended,
}

/// The order checker of one journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderCheck {
    state: State,
    capture: Capture,
    first_seq: u64,
    next_seq: u64,
    ordinal: u64,
    /// The last recorded checkpoint's `(group_seq, checkpoint_id)`.
    checkpoint: Option<(u64, u64)>,
}

impl Default for OrderCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderCheck {
    /// A checker before the header.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Start,
            capture: Capture::Strict,
            first_seq: 0,
            next_seq: 0,
            ordinal: 0,
            checkpoint: None,
        }
    }

    /// Takes the next record; the checker stays as it was when the record
    /// breaks a rule.
    ///
    /// # Errors
    ///
    /// [`OrderError`] for the first rule the record breaks.
    pub fn push(&mut self, role: Role) -> Result<(), OrderError> {
        let error = |rule| OrderError {
            ordinal: self.ordinal,
            rule,
        };
        let ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or_else(|| error(OrderRule::Exhausted))?;
        let mut next = *self;
        let state = next.next(role).map_err(error)?;
        *self = Self {
            state,
            ordinal,
            ..next
        };
        Ok(())
    }

    fn next(&mut self, role: Role) -> Result<State, OrderRule> {
        match (self.state, role) {
            (
                State::Start,
                Role::Header {
                    first_group_seq: 0, ..
                },
            ) => Err(OrderRule::Invalid),
            (
                State::Start,
                Role::Header {
                    capture,
                    first_group_seq,
                },
            ) => {
                self.capture = capture;
                self.first_seq = first_group_seq;
                self.next_seq = first_group_seq;
                Ok(State::Between)
            }
            (State::Start, _) | (_, Role::Header { .. }) => Err(OrderRule::Header),
            (State::Ended, _) => Err(OrderRule::AfterIncomplete),
            (State::Between, Role::Uncaptured(_)) if self.capture == Capture::Strict => {
                Err(OrderRule::Unavailable)
            }
            (State::Between, Role::Event(seq) | Role::Uncaptured(seq)) if seq == self.next_seq => {
                Ok(State::InEvent {
                    seq,
                    index: 0,
                    owed: 0,
                    publication: (0, 0),
                })
            }
            (State::Between, Role::Event(_) | Role::Uncaptured(_)) => Err(OrderRule::Sequence),
            (State::Between, Role::Gap(gap)) if gap.to_seq < gap.from_seq => {
                Err(OrderRule::Invalid)
            }
            (State::Between, Role::Gap(_)) if self.capture == Capture::Strict => {
                Err(OrderRule::StrictGap)
            }
            (State::Between, Role::Gap(gap)) if gap.from_seq == self.next_seq => {
                self.next_seq = gap.to_seq.checked_add(1).ok_or(OrderRule::Exhausted)?;
                Ok(State::Between)
            }
            (State::Between, Role::Gap(_)) => Err(OrderRule::Sequence),
            (State::Between, Role::Unavailable(0)) => Err(OrderRule::Invalid),
            (State::Between, Role::Unavailable(seq))
                if self.capture == Capture::Strict
                    || seq >= self.next_seq
                    || seq < self.first_seq =>
            {
                Err(OrderRule::Unavailable)
            }
            (State::Between, Role::Unavailable(_)) => Ok(State::Between),
            (
                State::Between,
                Role::Checkpoint {
                    group_seq,
                    checkpoint_id,
                },
            ) => {
                if group_seq == 0 || checkpoint_id == 0 {
                    return Err(OrderRule::Invalid);
                }
                let ended = group_seq >= self.first_seq && group_seq < self.next_seq;
                let above = self
                    .checkpoint
                    .is_none_or(|(seq, id)| group_seq > seq && checkpoint_id > id);
                if !ended || !above {
                    return Err(OrderRule::Checkpoint);
                }
                self.checkpoint = Some((group_seq, checkpoint_id));
                Ok(State::Between)
            }
            (
                State::Between,
                Role::Observation(..) | Role::Poll { .. } | Role::Delivery { .. } | Role::End(_),
            ) => Err(OrderRule::OutsideEvent),
            (
                State::InEvent { .. },
                Role::Event(_)
                | Role::Uncaptured(_)
                | Role::Gap(_)
                | Role::Unavailable(_)
                | Role::Checkpoint { .. },
            ) => Err(OrderRule::Nested),
            (
                State::InEvent {
                    seq,
                    index,
                    owed,
                    publication,
                },
                Role::Delivery {
                    group_seq,
                    index: at,
                    stream_id,
                    session_id,
                },
            ) => {
                if group_seq != seq {
                    Err(OrderRule::OutsideEvent)
                } else if at != index {
                    Err(OrderRule::Index)
                } else if owed == 0 || (stream_id, session_id) != publication {
                    Err(OrderRule::Poll)
                } else {
                    Ok(State::InEvent {
                        seq,
                        index: index.checked_add(1).ok_or(OrderRule::Exhausted)?,
                        owed: owed - 1,
                        publication,
                    })
                }
            }
            (State::InEvent { owed: 1.., .. }, _) => Err(OrderRule::Poll),
            (State::InEvent { seq, index, .. }, Role::Observation(of, at)) => {
                if of != seq {
                    Err(OrderRule::OutsideEvent)
                } else if at != index {
                    Err(OrderRule::Index)
                } else {
                    let index = index.checked_add(1).ok_or(OrderRule::Exhausted)?;
                    Ok(State::InEvent {
                        seq,
                        index,
                        owed: 0,
                        publication: (0, 0),
                    })
                }
            }
            (
                State::InEvent { seq, index, .. },
                Role::Poll {
                    group_seq,
                    index: at,
                    count,
                    stream_id,
                    session_id,
                },
            ) => {
                if group_seq != seq {
                    Err(OrderRule::OutsideEvent)
                } else if at != index {
                    Err(OrderRule::Index)
                } else {
                    Ok(State::InEvent {
                        seq,
                        index: index.checked_add(1).ok_or(OrderRule::Exhausted)?,
                        owed: count,
                        publication: (stream_id, session_id),
                    })
                }
            }
            (State::InEvent { seq, index, .. }, Role::End(end)) => {
                if end.group_seq != seq {
                    Err(OrderRule::OutsideEvent)
                } else if end.observations != index {
                    Err(OrderRule::Count)
                } else {
                    self.next_seq = seq.checked_add(1).ok_or(OrderRule::Exhausted)?;
                    if end.outcome == EndOutcome::Incomplete && self.capture == Capture::Strict {
                        Ok(State::Ended)
                    } else {
                        Ok(State::Between)
                    }
                }
            }
        }
    }

    /// Whether the records so far end between events (or at a strict
    /// journal's end): a journal cut here holds only whole events.
    #[must_use]
    pub const fn at_boundary(&self) -> bool {
        matches!(self.state, State::Between | State::Ended)
    }

    /// The `group_seq` the next event or gap must take; 0 before the
    /// header.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The last recorded checkpoint's `(group_seq, checkpoint_id)`.
    #[must_use]
    pub const fn last_checkpoint(&self) -> Option<(u64, u64)> {
        self.checkpoint
    }

    /// How many records it took.
    #[must_use]
    pub const fn records(&self) -> u64 {
        self.ordinal
    }
}
