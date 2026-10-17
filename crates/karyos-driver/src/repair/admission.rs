// SPDX-License-Identifier: Apache-2.0

//! NAK admission (`quantstratum-docs: karyos/design/reliable-transport.md`,
//! "Sender request and retention validation"; R4; ACS 15597).
//!
//! [`Admission::admit`] runs steps 1 to 5 of the eight-step order; the
//! first failure decides:
//!
//! 1. **Context.** A reliable publication, a lane of the incarnation and a
//!    known requester ([`Requester`]); otherwise dropped with no reply.
//! 2. **Requester window.** For a member with an accepted SM: a range that
//!    starts below its consumption is stale; below its join point, or
//!    ending above `consumption + window`, it cannot come from valid
//!    receive state. Before any accepted SM only the join point is
//!    checked, and a drop there is counted on its own (the receiver's join
//!    race, ACS 15711). Each is dropped and counted with no reply; stale
//!    requests are counted apart.
//! 3. **Term bound.** `start + length` by checked addition, at most
//!    `2^31 × term_length`, with `start` and `start + length - 32` in one
//!    term: otherwise `RANGE_INVALID`.
//! 4. **Floor.** Any byte below the lane's retention floor answers
//!    `RANGE_UNAVAILABLE` with the floor as the lowest retained position.
//! 5. **Sent frontier.** `start + length` beyond the lane's NAK bound
//!    (`sent_position`, or `sent_high` with redundant paths), read once by
//!    the caller, answers `RANGE_INVALID`.
//!
//! A NAK that passes is a [`Request`] for the job table, which applies
//! coalescing (6) and capacity (7); the start boundary (8) is checked when
//! the job is first served.
//!
//! **ERR linger.** At most one ERR NAK_REPLY per receiver, lane and range
//! within `nak_reply_linger` (default 1 ms, the coalescing linger): a
//! repeat is dropped and counted. The table holds `err_linger_entries`
//! (default 256); an expired entry is reused, and with none an ERR is
//! dropped and counted rather than sent twice. The receiver's retry is the
//! next opportunity. Nothing here allocates after construction; positions
//! and times are checked.

use karyos_protocol::network::{Nak, NakReply, NakReplyReason, Receiver};
use karyos_sys::host_clock::age_ns;

/// The largest term count a position may span (schemas 3.4).
const MAX_TERMS: u64 = 1 << 31;

/// A frame's alignment and the shortest NAK.
const FRAME: u64 = 32;

/// Whether a NAK range of `length` bytes from `start` satisfies the term
/// rule of schemas 3.4 for `term_length` (step 3): `start + length` by
/// checked addition, at most `2^31 × term_length`, with `start` and
/// `start + length - 32` in one term. A receiver checks a peer's group
/// NAK with the same rule (RC-15).
#[must_use]
pub fn in_one_term(start: u64, length: u32, term_length: u32) -> bool {
    let term = u64::from(term_length);
    let end = start.checked_add(u64::from(length));
    let limit = MAX_TERMS.checked_mul(term);
    match (end, end.and_then(|end| end.checked_sub(FRAME)), limit) {
        (Some(end), Some(last), Some(limit)) if term > 0 && end <= limit => {
            start.checked_div(term) == last.checked_div(term)
        }
        _ => false,
    }
}

/// What the sender knows of the requester on the NAK's lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requester {
    /// Not a receiver this publication answered: step 1 drops it.
    Unknown,
    /// Answered, no accepted SM yet: its join point on the lane.
    Joined {
        /// The lane's join point.
        join: u64,
    },
    /// A member with an accepted SM.
    Member {
        /// The lane's join point.
        join: u64,
        /// Its last accepted consumption.
        consumption: u64,
        /// Its window, fixed at the join.
        window: u32,
    },
}

/// The context of one NAK, gathered by the sender agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NakContext {
    /// Whether the publication is reliable; a NAK on an unreliable one
    /// fails step 1.
    pub reliable: bool,
    /// The incarnation's lane count.
    pub lane_count: u8,
    /// The requester on the NAK's lane.
    pub requester: Requester,
    /// The lane's retention floor: the lowest retained position.
    pub floor: u64,
    /// The lane's NAK bound, read once: `sent_position`, or `sent_high`
    /// with redundant paths.
    pub nak_bound: u64,
    /// The incarnation's term length, a power of two.
    pub term_length: u32,
}

/// Why a NAK was dropped with no reply; each is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// Step 1: unknown requester, or a lane outside the incarnation.
    Context,
    /// Step 1: the publication is not reliable.
    Unreliable,
    /// Step 2: it starts below the requester's consumption.
    Stale,
    /// Step 2: it starts below the requester's join point.
    BelowJoin,
    /// Step 2, before any accepted SM: it starts below the join point.
    BeforeSm,
    /// Step 2: it ends above `consumption + window`.
    BeyondWindow,
    /// The same ERR went to the same range within `nak_reply_linger`.
    ErrLinger,
    /// The ERR linger table is full of live entries.
    ErrTableFull,
}

/// A NAK that passed steps 1 to 5: one range of one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// The requesting receiver.
    pub receiver: Receiver,
    /// The lane.
    pub lane: u8,
    /// The first requested position.
    pub start: u64,
    /// The length in bytes.
    pub length: u32,
}

/// The outcome of [`Admission::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// Dropped with no reply.
    Dropped(Dropped),
    /// Answered with this ERR NAK_REPLY.
    Reply(NakReply),
    /// For the job table.
    Pass(Request),
}

/// What admission counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmissionCounts {
    /// NAKs that passed to the job table.
    pub passed: u64,
    /// Step 1 drops: context.
    pub context: u64,
    /// Step 1 drops: unreliable publication.
    pub unreliable: u64,
    /// Step 2 drops: stale requests.
    pub stale: u64,
    /// Step 2 drops: below the join point.
    pub below_join: u64,
    /// Step 2 drops before any accepted SM: below the join point.
    pub before_sm: u64,
    /// Step 2 drops: beyond the window.
    pub beyond_window: u64,
    /// `RANGE_INVALID` answers (steps 3 and 5).
    pub range_invalid: u64,
    /// `RANGE_UNAVAILABLE` answers (step 4).
    pub range_unavailable: u64,
    /// ERRs dropped as repeats within the linger.
    pub err_linger: u64,
    /// ERRs dropped for a full linger table.
    pub err_table_full: u64,
    /// An increment did not apply (sticky).
    pub overflowed: bool,
}

impl AdmissionCounts {
    fn bump(&mut self, field: impl FnOnce(&mut Self) -> &mut u64) {
        let count = field(self);
        match count.checked_add(1) {
            Some(next) => *count = next,
            None => self.overflowed = true,
        }
    }
}

/// One ERR sent: the range it answered and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ErrSent {
    receiver: Receiver,
    lane: u8,
    start: u64,
    length: u32,
    at: u64,
}

/// Why an [`Admission`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// No ERR linger entry.
    #[error("err_linger_entries is 0")]
    Entries,
}

/// One incarnation's NAK admission and ERR linger.
#[derive(Debug)]
pub struct Admission {
    linger: u64,
    entries: Vec<Option<ErrSent>>,
    counts: AdmissionCounts,
}

impl Admission {
    /// Admission with an ERR linger of `nak_reply_linger` nanoseconds over
    /// `err_linger_entries` entries, allocated here.
    ///
    /// # Errors
    ///
    /// [`AdmissionError::Entries`] for no entry.
    pub fn new(nak_reply_linger: u64, err_linger_entries: usize) -> Result<Self, AdmissionError> {
        if err_linger_entries == 0 {
            return Err(AdmissionError::Entries);
        }
        Ok(Self {
            linger: nak_reply_linger,
            entries: vec![None; err_linger_entries],
            counts: AdmissionCounts::default(),
        })
    }

    /// The counts.
    #[must_use]
    pub const fn counts(&self) -> &AdmissionCounts {
        &self.counts
    }

    /// Admits `nak` in `ctx` at `now`: steps 1 to 5, then the ERR linger
    /// for an answer.
    pub fn admit(&mut self, nak: &Nak, ctx: &NakContext, now: u64) -> Admitted {
        let lane = nak.range.lane.get();
        let start = nak.range.start;
        let length = nak.range.length;
        // 1. Context.
        if !ctx.reliable {
            return self.drop(Dropped::Unreliable);
        }
        if lane >= ctx.lane_count || ctx.requester == Requester::Unknown {
            return self.drop(Dropped::Context);
        }
        let end = start.checked_add(u64::from(length));
        // 2. Requester window.
        match ctx.requester {
            Requester::Unknown => return self.drop(Dropped::Context),
            Requester::Joined { join } => {
                if start < join {
                    return self.drop(Dropped::BeforeSm);
                }
            }
            Requester::Member {
                join,
                consumption,
                window,
            } => {
                if start < join {
                    return self.drop(Dropped::BelowJoin);
                }
                if start < consumption {
                    return self.drop(Dropped::Stale);
                }
                let edge = consumption.checked_add(u64::from(window));
                if end.zip(edge).is_none_or(|(end, edge)| end > edge) {
                    return self.drop(Dropped::BeyondWindow);
                }
            }
        }
        // 3. Term bound.
        if !in_one_term(start, length, ctx.term_length) {
            return self.reply(nak, NakReplyReason::RangeInvalid, now);
        }
        // 4. Floor.
        if start < ctx.floor {
            return self.reply(
                nak,
                NakReplyReason::RangeUnavailable {
                    lowest_retained: ctx.floor,
                },
                now,
            );
        }
        // 5. Sent frontier.
        if end.is_none_or(|end| end > ctx.nak_bound) {
            return self.reply(nak, NakReplyReason::RangeInvalid, now);
        }
        self.counts.bump(|c| &mut c.passed);
        Admitted::Pass(Request {
            receiver: nak.receiver,
            lane,
            start,
            length,
        })
    }

    /// The ERR for a request the job table later refused at its start
    /// boundary (step 8), under the same linger. A `RANGE_UNAVAILABLE`
    /// names a lowest retained position above the request's start
    /// (schemas 4.5).
    pub fn reply_to(&mut self, nak: &Nak, reason: NakReplyReason, now: u64) -> Admitted {
        if let NakReplyReason::RangeUnavailable { lowest_retained } = reason {
            debug_assert!(
                lowest_retained > nak.range.start,
                "RANGE_UNAVAILABLE must name a position above the request"
            );
        }
        self.reply(nak, reason, now)
    }

    fn drop(&mut self, reason: Dropped) -> Admitted {
        self.counts.bump(|c| match reason {
            Dropped::Context => &mut c.context,
            Dropped::Unreliable => &mut c.unreliable,
            Dropped::Stale => &mut c.stale,
            Dropped::BelowJoin => &mut c.below_join,
            Dropped::BeforeSm => &mut c.before_sm,
            Dropped::BeyondWindow => &mut c.beyond_window,
            Dropped::ErrLinger => &mut c.err_linger,
            Dropped::ErrTableFull => &mut c.err_table_full,
        });
        Admitted::Dropped(reason)
    }

    /// An ERR for `nak`, unless the same one went within the linger.
    fn reply(&mut self, nak: &Nak, reason: NakReplyReason, now: u64) -> Admitted {
        let sent = ErrSent {
            receiver: nak.receiver,
            lane: nak.range.lane.get(),
            start: nak.range.start,
            length: nak.range.length,
            at: now,
        };
        let linger = self.linger;
        let live = |entry: &ErrSent| age_ns(now, entry.at) < linger;
        let same = |entry: &ErrSent| {
            entry.receiver == sent.receiver
                && entry.lane == sent.lane
                && entry.start == sent.start
                && entry.length == sent.length
        };
        if self.entries.iter().flatten().any(|e| same(e) && live(e)) {
            return self.drop(Dropped::ErrLinger);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none_or(|e| !live(&e) || same(&e)));
        let Some(slot) = slot else {
            return self.drop(Dropped::ErrTableFull);
        };
        *slot = Some(sent);
        self.counts.bump(|c| match reason {
            NakReplyReason::RangeInvalid => &mut c.range_invalid,
            NakReplyReason::RangeUnavailable { .. } => &mut c.range_unavailable,
        });
        Admitted::Reply(NakReply::answering(nak, reason))
    }
}

#[cfg(test)]
mod tests;
