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
}

impl ScheduleConsumer {
    /// The consumer of the timed lane whose ring is `ring`, sized by the
    /// ring's own capacity; it allocates only here.
    ///
    /// # Errors
    ///
    /// [`ScheduleConsumerError::Ring`] for a ring that is not one.
    pub fn new(ring: &[AtomicU64]) -> Result<Self, ScheduleConsumerError> {
        let reader = ScheduleReader::attach(ring)?;
        let capacity = usize::try_from(reader.capacity()).map_err(|_| ScheduleError::Layout)?;
        Ok(Self {
            reader,
            current: None,
            outstanding: VecDeque::with_capacity(capacity),
        })
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
    /// [`ScheduleConsumerError::CorruptTerm`] when a rule fails, and ring
    /// errors.
    pub fn frame(
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
                    .peek(ring)?
                    .filter(|entry| entry.position == position)
                    .ok_or(corrupt(
                        position,
                        "a first fragment with no entry at its position",
                    ))?;
                self.reader.advance(ring)?;
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
                    .peek(ring)?
                    .is_some_and(|entry| entry.position == position);
                if matches {
                    self.reader.advance(ring)?;
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
