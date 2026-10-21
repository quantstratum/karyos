// SPDX-License-Identifier: Apache-2.0

//! A guarded network publication's submission frontier (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, "Trusted sockets in Phase 2").
//!
//! The sender gate of a guarded network publication tells the driver's
//! outcome walker, per lane, how far the fate of its first sends is
//! decided, so that the walker records a message `Submitted` only once a
//! backend took every frame of it, `Unknown` when it may have left whole,
//! and `Aborted` when it never will (its last frame never leaves; a
//! partial fragmented message is `Aborted`, as guards-and-abort.md's kind
//! table defines it):
//!
//! - **`resolved`**: prefix-closed. Below it every datagram has a copy
//!   submitted on some route or is a hole counted in `unknown_hi`.
//! - **`unknown_hi`**: the highest end of a datagram that may have left
//!   unproven (an `Unknown` report, an exposure a reset or a removal cut
//!   short, a divergence) or that left no copy at all outside a close (a
//!   reliable lane may still repair it). A message starting below it may
//!   have been sent.
//! - **`sent_hi`**: the highest end of a datagram that may have left:
//!   submitted, or counted in `unknown_hi`. A message ending above it
//!   never left whole.
//! - **`staged_hi`**: the highest end the gate staged: nothing above it
//!   was ever exposed.
//! - **The final word**: 0 while the gate may still decide positions;
//!   then the reason (an `AbortReason` code) once it will decide nothing
//!   more, with [`SUPERSEDED`] set when the driver, not the gate, ended it
//!   (a network close or an agent failure: the gate never runs again).
//!
//! Each field is monotone. There is no sequence lock:
//!
//! - **Gate (`publish`).** The only writer of the four positions. It
//!   stores `unknown_hi`, `sent_hi` and `staged_hi` (Relaxed), then
//!   `resolved` with Release, so a walker that sees a `resolved` also sees
//!   every hole below it. It sets the final word with [`SubmissionFrontier::finish`]
//!   after its last publication for the lane, and never publishes the lane
//!   again.
//! - **Conductor (`supersede`).** The final word's only other writer, once
//!   the gate has stopped for good: a compare-exchange from 0, so the
//!   first of the two writers wins and the word never changes again.
//! - **Walker (`read`).** Loads the final word with Acquire, then
//!   `resolved` with Acquire, then the three others (Relaxed). A final word
//!   the gate wrote brings the gate's last publication with it; a
//!   `resolved` brings the holes published with or before it. A value read
//!   later is never lower, so every decision the walker takes errs towards
//!   `Unknown` or waiting, never towards a `Submitted` that did not happen.

use crate::frame::Lane;
use crate::sync::{AtomicU64, Ordering};

/// Lanes a publication carries.
const LANES: usize = Lane::COUNT as usize;

/// The final word's bit for an end the driver wrote, not the gate.
pub const SUPERSEDED: u64 = 1 << 63;

/// One lane's positions, as the gate publishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Frontier {
    /// Below it every datagram's fate is decided (prefix-closed).
    pub resolved: u64,
    /// The highest end of a datagram that may have left unproven, or that
    /// left no copy outside a close.
    pub unknown_hi: u64,
    /// The highest end of a datagram that may have left: submitted, or
    /// counted in `unknown_hi`.
    pub sent_hi: u64,
    /// The highest end staged.
    pub staged_hi: u64,
}

/// Whether a lane's gate will decide more positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Final {
    /// It may.
    Open,
    /// The gate decided its last position, for `reason`.
    Finished {
        /// The `AbortReason` code.
        reason: u64,
    },
    /// The driver ended it for `reason`: the gate never ran again, so its
    /// last publication may not cover what it exposed.
    Superseded {
        /// The `AbortReason` code.
        reason: u64,
    },
}

/// Why a final word was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FinalError {
    /// A reason of 0, or one with the [`SUPERSEDED`] bit.
    #[error("invalid final reason {reason}")]
    InvalidReason {
        /// The refused reason.
        reason: u64,
    },
    /// No such lane.
    #[error("lane {lane} out of range")]
    UnknownLane {
        /// The refused lane.
        lane: usize,
    },
}

/// Loom only: how a negative control weakens a writer.
#[cfg(loom)]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterControl {
    /// The production writers.
    None,
    /// `resolved` stored Relaxed: a hole below it may be unseen.
    RelaxedResolved,
    /// The gate's final word stored Relaxed: its last publication may be
    /// unseen.
    RelaxedFinal,
    /// The final word stored without a compare-exchange: the second writer
    /// replaces the first.
    UncheckedFinal,
}

#[derive(Debug)]
struct LaneCell {
    resolved: AtomicU64,
    unknown_hi: AtomicU64,
    sent_hi: AtomicU64,
    staged_hi: AtomicU64,
    last: AtomicU64,
}

impl LaneCell {
    fn new() -> Self {
        Self {
            resolved: AtomicU64::new(0),
            unknown_hi: AtomicU64::new(0),
            sent_hi: AtomicU64::new(0),
            staged_hi: AtomicU64::new(0),
            last: AtomicU64::new(0),
        }
    }
}

/// The cell: the gate writes the positions, the gate or the conductor the
/// final word, and the walker reads.
#[derive(Debug)]
pub struct SubmissionFrontier {
    lanes: [LaneCell; LANES],
    #[cfg(loom)]
    control: WriterControl,
}

impl Default for SubmissionFrontier {
    fn default() -> Self {
        Self::new()
    }
}

impl SubmissionFrontier {
    /// A cell with nothing staged and every lane open.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lanes: core::array::from_fn(|_| LaneCell::new()),
            #[cfg(loom)]
            control: WriterControl::None,
        }
    }

    /// Loom only: the cell with a negative control's writers.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_control(control: WriterControl) -> Self {
        Self {
            control,
            ..Self::new()
        }
    }

    /// The gate: publishes `frontier` for `lane` (single writer; each
    /// field never lower than before). A lane out of range is ignored.
    pub fn publish(&self, lane: Lane, frontier: Frontier) {
        let Some(cell) = self.lanes.get(usize::from(lane.get())) else {
            return;
        };
        cell.unknown_hi
            .store(frontier.unknown_hi, Ordering::Relaxed);
        cell.sent_hi.store(frontier.sent_hi, Ordering::Relaxed);
        cell.staged_hi.store(frontier.staged_hi, Ordering::Relaxed);
        #[cfg(not(loom))]
        let order = Ordering::Release;
        #[cfg(loom)]
        let order = if self.control == WriterControl::RelaxedResolved {
            Ordering::Relaxed
        } else {
            Ordering::Release
        };
        cell.resolved.store(frontier.resolved, order);
    }

    /// The gate: `lane` will decide nothing more, for `reason`, after its
    /// last [`SubmissionFrontier::publish`]. Returns whether this call set
    /// the word (`false`: it was already final).
    ///
    /// # Errors
    ///
    /// [`FinalError`] for a reason of 0 or with the [`SUPERSEDED`] bit, or
    /// a lane out of range.
    pub fn finish(&self, lane: Lane, reason: u64) -> Result<bool, FinalError> {
        self.set_final(usize::from(lane.get()), reason, reason)
    }

    /// The conductor: `lane`'s gate will never run again (a network close
    /// or an agent failure), for `reason`. Returns whether this call set
    /// the word (`false`: the gate had already finished it).
    ///
    /// # Errors
    ///
    /// As [`SubmissionFrontier::finish`].
    pub fn supersede(&self, lane: Lane, reason: u64) -> Result<bool, FinalError> {
        self.set_final(usize::from(lane.get()), reason, reason | SUPERSEDED)
    }

    fn set_final(&self, lane: usize, reason: u64, word: u64) -> Result<bool, FinalError> {
        if reason == 0 || reason & SUPERSEDED != 0 {
            return Err(FinalError::InvalidReason { reason });
        }
        let cell = self
            .lanes
            .get(lane)
            .ok_or(FinalError::UnknownLane { lane })?;
        #[cfg(loom)]
        match self.control {
            WriterControl::UncheckedFinal => {
                cell.last.store(word, Ordering::Release);
                return Ok(true);
            }
            WriterControl::RelaxedFinal => {
                return Ok(cell
                    .last
                    .compare_exchange(0, word, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok());
            }
            WriterControl::None | WriterControl::RelaxedResolved => {}
        }
        Ok(cell
            .last
            .compare_exchange(0, word, Ordering::Release, Ordering::Relaxed)
            .is_ok())
    }

    /// The walker: `lane`'s final state, then its positions (module docs
    /// for the order). A lane out of range reads open with nothing staged.
    #[must_use]
    pub fn read(&self, lane: Lane) -> (Final, Frontier) {
        let Some(cell) = self.lanes.get(usize::from(lane.get())) else {
            return (Final::Open, Frontier::default());
        };
        let word = cell.last.load(Ordering::Acquire);
        let state = match word {
            0 => Final::Open,
            word if word & SUPERSEDED != 0 => Final::Superseded {
                reason: word & !SUPERSEDED,
            },
            reason => Final::Finished { reason },
        };
        let resolved = cell.resolved.load(Ordering::Acquire);
        let frontier = Frontier {
            resolved,
            unknown_hi: cell.unknown_hi.load(Ordering::Relaxed),
            sent_hi: cell.sent_hi.load(Ordering::Relaxed),
            staged_hi: cell.staged_hi.load(Ordering::Relaxed),
        };
        (state, frontier)
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    const ZERO: Lane = Lane::ZERO;

    #[test]
    fn a_new_cell_is_open_with_nothing_staged() {
        let cell = SubmissionFrontier::new();
        assert_eq!(cell.read(ZERO), (Final::Open, Frontier::default()));
    }

    #[test]
    fn the_last_publication_is_read() {
        let cell = SubmissionFrontier::new();
        let frontier = Frontier {
            resolved: 128,
            unknown_hi: 64,
            sent_hi: 160,
            staged_hi: 192,
        };
        cell.publish(ZERO, frontier);
        assert_eq!(cell.read(ZERO), (Final::Open, frontier));
        assert_eq!(cell.read(Lane::try_new(1).unwrap()).1, Frontier::default());
    }

    #[test]
    fn the_first_final_word_wins() {
        let cell = SubmissionFrontier::new();
        assert_eq!(cell.finish(ZERO, 1), Ok(true));
        assert_eq!(cell.supersede(ZERO, 5), Ok(false));
        assert_eq!(cell.finish(ZERO, 4), Ok(false));
        assert_eq!(cell.read(ZERO).0, Final::Finished { reason: 1 });
        let lane = Lane::try_new(2).unwrap();
        assert_eq!(cell.supersede(lane, 5), Ok(true));
        assert_eq!(cell.finish(lane, 1), Ok(false));
        assert_eq!(cell.read(lane).0, Final::Superseded { reason: 5 });
    }

    #[test]
    fn a_reason_is_nonzero_and_below_the_superseded_bit() {
        let cell = SubmissionFrontier::new();
        assert_eq!(
            cell.finish(ZERO, 0),
            Err(FinalError::InvalidReason { reason: 0 })
        );
        assert_eq!(
            cell.supersede(ZERO, SUPERSEDED | 1),
            Err(FinalError::InvalidReason {
                reason: SUPERSEDED | 1
            })
        );
        assert_eq!(cell.read(ZERO).0, Final::Open);
    }
}
