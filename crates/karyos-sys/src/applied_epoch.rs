// SPDX-License-Identifier: Apache-2.0

//! A sender's applied guard epoch (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, "The sender gate and applied
//! epoch" and "The effective-close acknowledgement").
//!
//! The sender serving a guard publishes, each time its gate observes a
//! guard epoch above the one it applied, that epoch together with the last
//! positions it submitted per lane under the previous epoch, and the
//! backend work it still has in flight (`quantstratum-docs:
//! karyos/design/driver-network-agents.md`, DN-7); it publishes again as
//! that work drains. The guard's
//! owner reads the pair to build the effective-close acknowledgement: a
//! sender is applied for close epoch `c` once its applied epoch is at
//! least `c`, and the positions it reports are those of that same
//! publication, never of a later one.
//!
//! The cell is a sequence lock with a single writer, the sender:
//!
//! - **Writer.** Stores the sequence odd (Relaxed), then a Release fence,
//!   then the positions and the epoch (Relaxed), then the sequence even
//!   with Release. The fence keeps the field stores after the odd
//!   sequence; the even store publishes them.
//! - **Reader.** Loads the sequence with Acquire (odd: a publication is in
//!   progress, try again), the epoch and the positions (Relaxed), an
//!   Acquire fence, and the sequence again (Relaxed). Equal sequences mean
//!   the fields were all written by the publication that the first load
//!   saw completed; anything else is a torn read, and the reader tries
//!   again.
//!
//! The sequence is a counter of publications that wraps by design and is
//! compared for equality only, as the positions epoch is.

use crate::frame::Lane;
use crate::sync::{AtomicU64, Ordering, fence};

/// Lanes a publication carries.
const LANES: usize = Lane::COUNT as usize;

/// One applied epoch, the last positions submitted per lane under the
/// epoch before it, and the work still in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// The guard epoch the sender applied; 0 before any.
    pub epoch: u64,
    /// The last position submitted per lane under the previous epoch.
    pub positions: [u64; LANES],
    /// Backend work in flight as the gate counts it: items exposed and not
    /// yet reported, and items whose exposure is unproven (`Unknown`) until
    /// the control path resolves them (`quantstratum-docs:
    /// karyos/design/driver-network-agents.md`, DN-7).
    pub in_flight: u64,
}

/// The cell, in memory the sender writes and the owner reads.
#[derive(Debug)]
pub struct AppliedEpoch {
    sequence: AtomicU64,
    epoch: AtomicU64,
    positions: [AtomicU64; LANES],
    in_flight: AtomicU64,
    /// Loom only: the negative controls' variants of the writer.
    #[cfg(loom)]
    control: WriterControl,
}

/// Loom only: how a negative control weakens the writer.
#[cfg(loom)]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterControl {
    /// The production writer.
    None,
    /// The even sequence stored Relaxed: nothing publishes the fields.
    RelaxedRelease,
    /// The fields stored before the odd sequence, with no fence: a reader
    /// can see the old sequence with new fields.
    FieldsBeforeSequence,
    /// The in-flight count stored after the even sequence, outside the
    /// lock: a reader can pair it with another publication.
    InFlightOutsideSequence,
}

impl Default for AppliedEpoch {
    fn default() -> Self {
        Self::new()
    }
}

impl AppliedEpoch {
    /// A cell with nothing applied.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            positions: core::array::from_fn(|_| AtomicU64::new(0)),
            in_flight: AtomicU64::new(0),
            #[cfg(loom)]
            control: WriterControl::None,
        }
    }

    /// Loom only: the cell with a negative control's writer.
    #[cfg(loom)]
    #[doc(hidden)]
    #[must_use]
    pub fn with_control(control: WriterControl) -> Self {
        Self {
            control,
            ..Self::new()
        }
    }

    /// The sender: publishes `applied`. Single writer only.
    pub fn publish(&self, applied: Applied) {
        #[cfg(loom)]
        let control = self.control;
        #[cfg(not(loom))]
        let control_fields_first = false;
        #[cfg(loom)]
        let control_fields_first = control == WriterControl::FieldsBeforeSequence;
        let sequence = self.sequence.load(Ordering::Relaxed);
        if control_fields_first {
            self.store_fields(applied);
        }
        self.sequence
            .store(sequence.wrapping_add(1), Ordering::Relaxed);
        if !control_fields_first {
            fence(Ordering::Release);
            self.store_fields(applied);
        }
        #[cfg(not(loom))]
        let order = Ordering::Release;
        #[cfg(loom)]
        let order = if control == WriterControl::RelaxedRelease {
            Ordering::Relaxed
        } else {
            Ordering::Release
        };
        self.sequence.store(sequence.wrapping_add(2), order);
        #[cfg(loom)]
        if control == WriterControl::InFlightOutsideSequence {
            self.in_flight.store(applied.in_flight, Ordering::Relaxed);
        }
    }

    fn store_fields(&self, applied: Applied) {
        for (cell, position) in self.positions.iter().zip(applied.positions) {
            cell.store(position, Ordering::Relaxed);
        }
        self.epoch.store(applied.epoch, Ordering::Relaxed);
        #[cfg(loom)]
        let inside = self.control != WriterControl::InFlightOutsideSequence;
        #[cfg(not(loom))]
        let inside = true;
        if inside {
            self.in_flight.store(applied.in_flight, Ordering::Relaxed);
        }
    }

    /// Test hook: leaves the sequence odd, as a writer stopped in the
    /// middle of a publication, so that readers keep seeing one in
    /// progress.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn stall_writer(&self) {
        let sequence = self.sequence.load(Ordering::Relaxed);
        if sequence.is_multiple_of(2) {
            self.sequence
                .store(sequence.wrapping_add(1), Ordering::Relaxed);
        }
    }

    /// The owner: one attempt to read a consistent publication; `None`
    /// while a publication is in progress or the read was torn, which the
    /// caller answers by trying again.
    #[must_use]
    pub fn try_read(&self) -> Option<Applied> {
        let first = self.sequence.load(Ordering::Acquire);
        if first % 2 == 1 {
            return None;
        }
        let epoch = self.epoch.load(Ordering::Relaxed);
        let positions = core::array::from_fn(|lane| {
            self.positions
                .get(lane)
                .map_or(0, |cell| cell.load(Ordering::Relaxed))
        });
        let in_flight = self.in_flight.load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        let second = self.sequence.load(Ordering::Relaxed);
        (first == second).then_some(Applied {
            epoch,
            positions,
            in_flight,
        })
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn a_new_cell_reads_nothing_applied() {
        let cell = AppliedEpoch::new();
        assert_eq!(
            cell.try_read(),
            Some(Applied {
                epoch: 0,
                positions: [0; LANES],
                in_flight: 0,
            })
        );
    }

    #[test]
    fn the_last_publication_is_read_whole() {
        let cell = AppliedEpoch::new();
        let first = Applied {
            epoch: 3,
            positions: [64, 0, 128, 0],
            in_flight: 2,
        };
        let second = Applied {
            epoch: 5,
            positions: [192, 32, 128, 0],
            in_flight: 0,
        };
        cell.publish(first);
        assert_eq!(cell.try_read(), Some(first));
        cell.publish(second);
        assert_eq!(cell.try_read(), Some(second));
    }

    #[test]
    fn an_odd_sequence_is_a_publication_in_progress() {
        let cell = AppliedEpoch::new();
        cell.sequence.store(1, Ordering::Relaxed);
        assert_eq!(cell.try_read(), None);
    }

    #[test]
    fn the_sequence_wraps() {
        let cell = AppliedEpoch::new();
        cell.sequence.store(u64::MAX - 1, Ordering::Relaxed);
        let applied = Applied {
            epoch: 7,
            positions: [1, 2, 3, 4],
            in_flight: 9,
        };
        cell.publish(applied);
        assert_eq!(cell.sequence.load(Ordering::Relaxed), 0);
        assert_eq!(cell.try_read(), Some(applied));
    }
}
