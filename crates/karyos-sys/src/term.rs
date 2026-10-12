// SPDX-License-Identifier: Apache-2.0

//! Term identity: raw term ids, term counts and mapping generations
//! (SPEC.md §4, term identity arithmetic).

use crate::error::SysError;

/// Exclusive upper bound of a term count within one incarnation.
pub const TERM_COUNT_LIMIT: u32 = 1 << 31;

/// Exclusive upper bound of a mapping generation (24 bits).
pub const GENERATION_LIMIT: u32 = 1 << 24;

/// A raw 32-bit term id as carried on the wire and in descriptors.
///
/// Term ids advance modulo `2^32` from a random initial term id. This type is
/// the single place where that rollover is modelled; positions are never
/// computed from a raw term id, only from a [`TermCount`].
///
/// Its two `wrapping_*` calls are the one deliberate exception to the
/// convention that forbids `wrapping_*` arithmetic (SPEC.md §14): term ids are
/// defined modulo `2^32` (SPEC.md §4), so wrapping is the specified algorithm
/// here, not an overflow being hidden. Exhaustion is checked on
/// [`TermCount`], which never wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TermId(u32);

impl TermId {
    /// Wraps a raw term id.
    #[inline]
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw 32-bit pattern.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns the term id `count` terms after `self` (modulo `2^32`).
    #[inline]
    #[must_use]
    pub const fn advanced_by(self, count: TermCount) -> Self {
        // Explicit rollover model: term ids are defined modulo 2^32.
        Self(self.0.wrapping_add(count.get()))
    }

    /// Returns the term count of `self` relative to `initial`.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidTermCount`] when the distance modulo `2^32`
    /// is not below `2^31`, which no live term of the incarnation can have.
    #[inline]
    pub const fn count_from(self, initial: TermId) -> Result<TermCount, SysError> {
        // Explicit rollover model: the distance is defined modulo 2^32.
        TermCount::try_new(self.0.wrapping_sub(initial.0))
    }
}

/// The number of terms since the initial term of an incarnation, below `2^31`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TermCount(u32);

impl TermCount {
    /// The first term of an incarnation.
    pub const ZERO: Self = Self(0);

    /// Validates a term count.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidTermCount`] when `value >= 2^31`.
    #[inline]
    pub const fn try_new(value: u32) -> Result<Self, SysError> {
        if value < TERM_COUNT_LIMIT {
            Ok(Self(value))
        } else {
            Err(SysError::InvalidTermCount { value })
        }
    }

    /// Returns the count.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns the next term count.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::MaxPositionExceeded`] when the next count would
    /// reach `2^31`; the incarnation must then be closed.
    #[inline]
    pub const fn next(self) -> Result<Self, SysError> {
        match self.0.checked_add(1) {
            Some(next) if next < TERM_COUNT_LIMIT => Ok(Self(next)),
            _ => Err(SysError::MaxPositionExceeded {
                count: self.0 as u64 + 1,
            }),
        }
    }
}

/// A mapping generation, 24 bits wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Generation(u32);

impl Generation {
    /// Validates a generation.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidGeneration`] when `value >= 2^24`.
    #[inline]
    pub const fn try_new(value: u32) -> Result<Self, SysError> {
        if value < GENERATION_LIMIT {
            Ok(Self(value))
        } else {
            Err(SysError::InvalidGeneration { value })
        }
    }

    /// Returns the generation.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns the generation of a successor mapping.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::GenerationExhausted`] when the successor would need
    /// generation `2^24`.
    #[inline]
    pub const fn next(self) -> Result<Self, SysError> {
        match self.0.checked_add(1) {
            Some(next) if next < GENERATION_LIMIT => Ok(Self(next)),
            _ => Err(SysError::GenerationExhausted { generation: self.0 }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_id_rolls_over_modulo_2_32() {
        let initial = TermId::new(u32::MAX - 1);
        let count = TermCount::try_new(3).unwrap();
        let later = initial.advanced_by(count);
        assert_eq!(later.get(), 1);
        assert_eq!(later.count_from(initial).unwrap(), count);
    }

    #[test]
    fn count_from_rejects_distances_of_2_31_or_more() {
        let initial = TermId::new(0);
        assert_eq!(
            TermId::new(TERM_COUNT_LIMIT).count_from(initial),
            Err(SysError::InvalidTermCount {
                value: TERM_COUNT_LIMIT
            })
        );
        assert!(
            TermId::new(TERM_COUNT_LIMIT - 1)
                .count_from(initial)
                .is_ok()
        );
        // A term "before" the initial term is a huge forward distance.
        assert!(TermId::new(u32::MAX).count_from(initial).is_err());
    }

    #[test]
    fn term_count_limit_is_max_position_exceeded() {
        let last = TermCount::try_new(TERM_COUNT_LIMIT - 1).unwrap();
        assert_eq!(
            last.next(),
            Err(SysError::MaxPositionExceeded {
                count: u64::from(TERM_COUNT_LIMIT)
            })
        );
        assert!(TermCount::try_new(TERM_COUNT_LIMIT).is_err());
        assert_eq!(TermCount::ZERO.next().unwrap().get(), 1);
    }

    #[test]
    fn generation_is_24_bits() {
        assert!(Generation::try_new(GENERATION_LIMIT).is_err());
        let last = Generation::try_new(GENERATION_LIMIT - 1).unwrap();
        assert_eq!(
            last.next(),
            Err(SysError::GenerationExhausted {
                generation: GENERATION_LIMIT - 1
            })
        );
        assert_eq!(Generation::default().next().unwrap().get(), 1);
    }
}
