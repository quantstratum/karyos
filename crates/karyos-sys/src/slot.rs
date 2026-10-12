// SPDX-License-Identifier: Apache-2.0

//! Term slot descriptors and their 64-bit encoding (SPEC.md §4, term slot
//! states).

use crate::error::SysError;
use crate::term::{Generation, TermId};

/// Maximum number of slots in one lane of a log buffer (`3 + S`).
pub const MAX_SLOTS: u8 = 128;

const TERM_SHIFT: u32 = 32;
const GENERATION_SHIFT: u32 = 8;
const GENERATION_MASK: u64 = 0x00FF_FFFF;
const STATE_MASK: u64 = 0xFF;

/// Index of a physical slot within one lane, below [`MAX_SLOTS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SlotIndex(u8);

impl SlotIndex {
    /// Validates a slot index.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidSlotIndex`] when `value >= 128`.
    #[inline]
    pub const fn try_new(value: u8) -> Result<Self, SysError> {
        if value < MAX_SLOTS {
            Ok(Self(value))
        } else {
            Err(SysError::InvalidSlotIndex { value })
        }
    }

    /// Returns the index.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// State of a term slot. Zero is reserved for an uninitialised mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SlotState {
    /// Cleaned and unassigned; refuses loans.
    Free = 1,
    /// Assigned to a term and published, not yet active; refuses loans.
    Ready = 2,
    /// Readable and writable; grants loans for exactly its identity.
    Active = 3,
    /// No new loans; existing loans may finish.
    Reclaiming = 4,
    /// Being zeroed exclusively by the driver; refuses loans.
    Cleaning = 5,
}

impl SlotState {
    #[inline]
    const fn from_code(raw: u64, code: u8) -> Result<Self, SysError> {
        match code {
            1 => Ok(Self::Free),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Active),
            4 => Ok(Self::Reclaiming),
            5 => Ok(Self::Cleaning),
            0 => Err(SysError::UninitialisedDescriptor { raw }),
            state => Err(SysError::UnknownSlotState { raw, state }),
        }
    }
}

/// A decoded slot descriptor: state plus the full term identity.
///
/// `Free` and `Cleaning` descriptors keep the identity of the slot's last
/// term; only `Active` grants loans, so validation ignores it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Descriptor {
    term_id: TermId,
    generation: Generation,
    state: SlotState,
}

impl Descriptor {
    /// Builds a descriptor.
    #[inline]
    #[must_use]
    pub const fn new(term_id: TermId, generation: Generation, state: SlotState) -> Self {
        Self {
            term_id,
            generation,
            state,
        }
    }

    /// The term id this descriptor refers to.
    #[inline]
    #[must_use]
    pub const fn term_id(self) -> TermId {
        self.term_id
    }

    /// The mapping generation.
    #[inline]
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// The slot state.
    #[inline]
    #[must_use]
    pub const fn state(self) -> SlotState {
        self.state
    }

    /// Returns the same identity with another state.
    #[inline]
    #[must_use]
    pub const fn with_state(self, state: SlotState) -> Self {
        Self { state, ..self }
    }

    /// Encodes as `term_id << 32 | generation << 8 | state`.
    #[inline]
    #[must_use]
    pub const fn encode(self) -> u64 {
        ((self.term_id.get() as u64) << TERM_SHIFT)
            | ((self.generation.get() as u64) << GENERATION_SHIFT)
            | self.state as u64
    }

    /// Decodes a raw descriptor word.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::UninitialisedDescriptor`] for state 0 and
    /// [`SysError::UnknownSlotState`] for an undefined state code.
    #[inline]
    pub const fn decode(raw: u64) -> Result<Self, SysError> {
        let state = match SlotState::from_code(raw, (raw & STATE_MASK) as u8) {
            Ok(state) => state,
            Err(err) => return Err(err),
        };
        let generation =
            match Generation::try_new(((raw >> GENERATION_SHIFT) & GENERATION_MASK) as u32) {
                Ok(generation) => generation,
                Err(err) => return Err(err),
            };
        Ok(Self {
            term_id: TermId::new((raw >> TERM_SHIFT) as u32),
            generation,
            state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::term::GENERATION_LIMIT;

    #[test]
    fn slot_index_bound() {
        assert!(SlotIndex::try_new(127).is_ok());
        assert_eq!(
            SlotIndex::try_new(128),
            Err(SysError::InvalidSlotIndex { value: 128 })
        );
    }

    #[test]
    fn descriptor_round_trips_at_field_bounds() {
        let states = [
            SlotState::Free,
            SlotState::Ready,
            SlotState::Active,
            SlotState::Reclaiming,
            SlotState::Cleaning,
        ];
        for term in [0, 1, u32::MAX] {
            for generation in [0, 1, GENERATION_LIMIT - 1] {
                for state in states {
                    let d = Descriptor::new(
                        TermId::new(term),
                        Generation::try_new(generation).unwrap(),
                        state,
                    );
                    assert_eq!(Descriptor::decode(d.encode()), Ok(d));
                }
            }
        }
    }

    #[test]
    fn descriptor_layout_matches_spec() {
        let d = Descriptor::new(
            TermId::new(0xAABB_CCDD),
            Generation::try_new(0x12_3456).unwrap(),
            SlotState::Active,
        );
        assert_eq!(d.encode(), 0xAABB_CCDD_1234_5603);
    }

    #[test]
    fn descriptor_rejects_zero_and_unknown_states() {
        assert_eq!(
            Descriptor::decode(0x1_0000_0100),
            Err(SysError::UninitialisedDescriptor { raw: 0x1_0000_0100 })
        );
        assert_eq!(
            Descriptor::decode(0x06),
            Err(SysError::UnknownSlotState {
                raw: 0x06,
                state: 6
            })
        );
    }
}
