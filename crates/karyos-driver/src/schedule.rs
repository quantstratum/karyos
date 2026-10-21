// SPDX-License-Identifier: Apache-2.0

//! The sender's side of a timed lane's schedule (`quantstratum-docs:
//! karyos/design/timed-tx.md`, section 2 step 3 and section 4; P2.11 T1,
//! step 4): the [`ScheduleConsumer`] gives each frame of the lane, read in
//! order, the requested time of its message, and frees the message's entry
//! once its last fragment left for good. The sender's staging, which feeds
//! it, is phase 5 of `driver-network-agents.md`.

use std::collections::VecDeque;

use karyos_sys::schedule_ring::{ScheduleError, ScheduleReader};
use karyos_sys::sync::AtomicU64;

/// A frame of a timed lane, as the sender reads it in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneFrame {
    /// A data fragment at `position`: `begin` for a message's first,
    /// `end` for its last.
    Data {
        /// Its stream position (the buffer's own, as the entries carry).
        position: u64,
        /// The message's first fragment.
        begin: bool,
        /// The message's last fragment.
        end: bool,
    },
    /// Padding at a term's end: no message.
    Pad,
    /// An aborted block at `position`: a message whose writer was aborted
    /// before commit, or no message at all.
    Aborted {
        /// Its stream position.
        position: u64,
    },
}

/// Why the consumer refused a frame or a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScheduleConsumerError {
    /// The lane's frames and its entries disagree: a first frame with no
    /// entry at its position, a continuation outside a message, padding
    /// inside one, or a report with no message outstanding. Never guessed.
    #[error("the schedule and the lane disagree at position {position}: {reason}")]
    CorruptTerm {
        /// The frame's position (0 for a report).
        position: u64,
        /// Which rule failed.
        reason: &'static str,
    },
    /// The ring refused an operation.
    #[error(transparent)]
    Ring(#[from] ScheduleError),
}

/// The sender's reader of one timed lane's ring. Entries are read when
/// their message's first frame is read and released, in order, once the
/// message's last fragment left for good, so the ring bounds the timed
/// messages outstanding (the publisher's back pressure).
#[derive(Debug)]
pub struct ScheduleConsumer {
    reader: ScheduleReader,
    /// The time of the message being read, between its first and last
    /// fragments.
    current: Option<u64>,
    /// Read entries not yet released, oldest first: whether each message is
    /// done (its last fragment left, or it was aborted).
    outstanding: VecDeque<bool>,
    /// Entries read before the last rewind ([`Self::rewind`]): read again,
    /// their messages are resent, not scheduled.
    replay_to: u64,
    /// Whether the message being read is one read again.
    current_replayed: bool,
    /// After a rewind, until the first frame: the rewind may land inside a
    /// message, whose continuation then takes the entry at `head`.
    resuming: bool,
    /// The sender's own horizon: an entry's time past `now` plus it is a
    /// violation of the publisher (timed-tx.md section 11, TT-6).
    max_horizon: u64,
    /// The sender's clock at its last duty ([`Self::set_now`]).
    now: u64,
    /// A frame and the entries disagreed ([`ScheduleConsumerError::
    /// CorruptTerm`] from [`Self::frame`]): the lane's publisher wrote both,
    /// so it breached the protocol (timed-tx.md section 11, TT-6), for
    /// good, as a [`ScheduleError::Violation`] of the ring is.
    breached: bool,
}

/// A frame's message: its requested time, and whether it was read before
/// a rewind (resent at once, outside the timed policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scheduled {
    /// The message's requested time.
    pub time: u64,
    /// The message was read before the last rewind.
    pub replayed: bool,
}

impl ScheduleConsumer {
    /// The consumer of the timed lane whose ring is `ring`, sized by the
    /// ring's own capacity; it allocates only here. It checks each entry's
    /// time against the sender's clock plus `max_horizon`, its own
    /// configuration, never the ring's binding words.
    ///
    /// # Errors
    ///
    /// [`ScheduleConsumerError::Ring`] for a ring that is not one.
    pub fn new(ring: &[AtomicU64], max_horizon: u64) -> Result<Self, ScheduleConsumerError> {
        let reader = ScheduleReader::attach(ring)?;
        let capacity = usize::try_from(reader.capacity()).map_err(|_| ScheduleError::Layout)?;
        Ok(Self {
            reader,
            current: None,
            outstanding: VecDeque::with_capacity(capacity),
            replay_to: 0,
            current_replayed: false,
            resuming: false,
            max_horizon,
            now: 0,
            breached: false,
        })
    }

    /// The sender's clock, read once a duty: the entries read from now on
    /// are checked against it.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// Whether the lane's publisher breached the ring's protocol: a
    /// [`ScheduleError::Violation`] of the ring, or a frame its entries
    /// contradict (an entry's position is checked against its frame,
    /// timed-tx.md section 11, TT-6). Every later frame is refused, so the
    /// sender stages nothing more of the lane, and reports it once for the
    /// conductor to seal the lane with `ScheduleViolation`.
    #[must_use]
    pub fn violated(&self) -> bool {
        self.breached || self.reader.violated()
    }

    /// Runs one frame's step, refused after a breach; a frame its entries
    /// contradict is a breach, for good.
    fn checked<T>(
        &mut self,
        step: impl FnOnce(&mut Self) -> Result<T, ScheduleConsumerError>,
    ) -> Result<T, ScheduleConsumerError> {
        if self.violated() {
            return Err(ScheduleError::Violation.into());
        }
        let result = step(self);
        if matches!(result, Err(ScheduleConsumerError::CorruptTerm { .. })) {
            self.breached = true;
        }
        result
    }

    /// A reliable lane's log was rewound to a position no message of an
    /// entry not yet released lies below (the registered position, up to
    /// which entries are released): every entry not released is read
    /// again, in order. The oldest `sent` of them, whose messages were
    /// sent (or may have been) in whole or in part, are marked replayed;
    /// the later ones were only read, and keep their time. A position
    /// inside a message resumes it at its next fragment.
    ///
    /// # Errors
    ///
    /// [`ScheduleConsumerError::CorruptTerm`] when `sent` is above the
    /// entries outstanding, or they above the entries read; nothing
    /// changes.
    pub fn rewind(&mut self, sent: usize) -> Result<(), ScheduleConsumerError> {
        let corrupt = ScheduleConsumerError::CorruptTerm {
            position: 0,
            reason: "a rewind past the entries outstanding",
        };
        if sent > self.outstanding.len() {
            return Err(corrupt);
        }
        let outstanding = u64::try_from(self.outstanding.len()).map_err(|_| corrupt)?;
        let sent = u64::try_from(sent).map_err(|_| corrupt)?;
        let replay_to = self
            .reader
            .read()
            .checked_sub(outstanding)
            .and_then(|released| released.checked_add(sent))
            .ok_or(corrupt)?;
        self.replay_to = self.replay_to.max(replay_to);
        self.reader.rewind_to_released();
        self.outstanding.clear();
        self.current = None;
        self.current_replayed = false;
        self.resuming = true;
        Ok(())
    }

    /// [`Self::frame`], with whether the message was read before the last
    /// rewind.
    ///
    /// # Errors
    ///
    /// As [`Self::frame`].
    pub fn frame_scheduled(
        &mut self,
        ring: &[AtomicU64],
        frame: LaneFrame,
    ) -> Result<Option<Scheduled>, ScheduleConsumerError> {
        self.checked(|consumer| consumer.scheduled_step(ring, frame))
    }

    fn scheduled_step(
        &mut self,
        ring: &[AtomicU64],
        frame: LaneFrame,
    ) -> Result<Option<Scheduled>, ScheduleConsumerError> {
        let resuming = std::mem::take(&mut self.resuming);
        // A rewind inside a message: its continuation takes the entry at
        // `head`, the message's own, which starts below the frame.
        if resuming
            && let LaneFrame::Data {
                position,
                begin: false,
                end,
            } = frame
        {
            let index = self.reader.read();
            let entry = self
                .reader
                .peek(ring, self.now, self.max_horizon)?
                .filter(|entry| entry.position < position)
                .ok_or(ScheduleConsumerError::CorruptTerm {
                    position,
                    reason: "a resumed continuation with no entry below it",
                })?;
            self.reader.advance()?;
            self.outstanding.push_back(false);
            self.current_replayed = index < self.replay_to;
            if !end {
                self.current = Some(entry.time);
            }
            return Ok(Some(Scheduled {
                time: entry.time,
                replayed: self.current_replayed,
            }));
        }
        let index = self.reader.read();
        let first = matches!(frame, LaneFrame::Data { begin: true, .. });
        let time = self.frame_step(ring, frame)?;
        if first {
            self.current_replayed = index < self.replay_to;
        }
        Ok(time.map(|time| Scheduled {
            time,
            replayed: self.current_replayed,
        }))
    }

    /// The requested time of `frame`'s message, read in lane order; `None`
    /// for padding and aborted blocks, which carry no message to send.
    ///
    /// - A first fragment takes the next entry, which must name its
    ///   position; its later fragments carry the same time.
    /// - Padding takes no entry.
    /// - An aborted block takes the next entry only if it names the block's
    ///   position (a message aborted before commit), which is then done.
    ///
    /// # Errors
    ///
    /// [`ScheduleConsumerError::CorruptTerm`] when a rule fails, which is
    /// the publisher's breach: from then on, as after a ring violation,
    /// every frame is [`ScheduleError::Violation`]. Ring errors.
    pub fn frame(
        &mut self,
        ring: &[AtomicU64],
        frame: LaneFrame,
    ) -> Result<Option<u64>, ScheduleConsumerError> {
        self.checked(|consumer| consumer.frame_step(ring, frame))
    }

    fn frame_step(
        &mut self,
        ring: &[AtomicU64],
        frame: LaneFrame,
    ) -> Result<Option<u64>, ScheduleConsumerError> {
        let corrupt = |position, reason| ScheduleConsumerError::CorruptTerm { position, reason };
        match frame {
            LaneFrame::Data {
                position,
                begin: true,
                end,
            } => {
                if self.current.is_some() {
                    return Err(corrupt(position, "a first fragment inside a message"));
                }
                let entry = self
                    .reader
                    .peek(ring, self.now, self.max_horizon)?
                    .filter(|entry| entry.position == position)
                    .ok_or(corrupt(
                        position,
                        "a first fragment with no entry at its position",
                    ))?;
                self.reader.advance()?;
                self.outstanding.push_back(false);
                if !end {
                    self.current = Some(entry.time);
                }
                Ok(Some(entry.time))
            }
            LaneFrame::Data {
                position,
                begin: false,
                end,
            } => {
                let time = self
                    .current
                    .ok_or(corrupt(position, "a continuation outside a message"))?;
                if end {
                    self.current = None;
                }
                Ok(Some(time))
            }
            LaneFrame::Pad => {
                if self.current.is_some() {
                    return Err(corrupt(0, "padding inside a message"));
                }
                Ok(None)
            }
            LaneFrame::Aborted { position } => {
                if self.current.is_some() {
                    return Err(corrupt(position, "an aborted block inside a message"));
                }
                let matches = self
                    .reader
                    .peek(ring, self.now, self.max_horizon)?
                    .is_some_and(|entry| entry.position == position);
                if matches {
                    self.reader.advance()?;
                    self.outstanding.push_back(true);
                    self.release_done(ring)?;
                }
                Ok(None)
            }
        }
    }

    /// The oldest outstanding message's last fragment left for good (every
    /// path submitted it): its entry, and any done ones behind it, are
    /// released in order.
    ///
    /// # Errors
    ///
    /// [`ScheduleConsumerError::CorruptTerm`] with no message outstanding,
    /// and ring errors.
    pub fn message_left(&mut self, ring: &[AtomicU64]) -> Result<(), ScheduleConsumerError> {
        let oldest = self.outstanding.iter_mut().find(|done| !**done).ok_or(
            ScheduleConsumerError::CorruptTerm {
                position: 0,
                reason: "a message left with none outstanding",
            },
        )?;
        *oldest = true;
        self.release_done(ring)
    }

    /// The message read last never left (its last fragment was read but
    /// not staged): its entry, the newest outstanding, is done, and the
    /// done entries at the front are released. An older message still
    /// waiting to leave keeps its entry.
    ///
    /// # Errors
    ///
    /// [`ScheduleConsumerError::CorruptTerm`] with no message outstanding,
    /// and ring errors.
    pub fn message_lost(&mut self, ring: &[AtomicU64]) -> Result<(), ScheduleConsumerError> {
        let newest = self
            .outstanding
            .iter_mut()
            .rev()
            .find(|done| !**done)
            .ok_or(ScheduleConsumerError::CorruptTerm {
                position: 0,
                reason: "a message lost with none outstanding",
            })?;
        *newest = true;
        self.release_done(ring)
    }

    fn release_done(&mut self, ring: &[AtomicU64]) -> Result<(), ScheduleConsumerError> {
        while self.outstanding.front() == Some(&true) {
            self.reader.release(ring)?;
            let _ = self.outstanding.pop_front();
        }
        Ok(())
    }

    /// Messages read and not yet released.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }
}

#[cfg(test)]
mod tests;
