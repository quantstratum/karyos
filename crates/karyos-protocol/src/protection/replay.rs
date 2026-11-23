// SPDX-License-Identifier: Apache-2.0

//! The replay window of an authenticated sender, session and key epoch
//! (wire threat model manifest 4.3: 1024 envelope sequences; ADR-0086
//! section 6).
//!
//! The window is consulted only after the tag verifies, and it advances
//! only through [`ReplayWindow::accept`], so a forged datagram can never
//! move it.

/// Envelope sequences the window remembers behind its highest one.
pub const WINDOW: u64 = 1024;

const WORDS: usize = 16;

/// Why an envelope sequence is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// Already accepted.
    Duplicate,
    /// Older than the window.
    TooOld,
}

/// A 1024-sequence sliding window, 128 bytes of bitmap. Allocates nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplayWindow {
    /// The highest accepted sequence, if any.
    highest: Option<u64>,
    /// Bit `i` set: `highest - i` accepted.
    bits: [u64; WORDS],
}

impl ReplayWindow {
    /// An empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: [0; WORDS],
        }
    }

    /// The highest accepted sequence.
    #[must_use]
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Whether `seq` would be accepted. Changes nothing.
    ///
    /// # Errors
    ///
    /// [`Replay`] when it would not.
    pub fn check(&self, seq: u64) -> Result<(), Replay> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if seq > highest {
            return Ok(());
        }
        let age = highest.checked_sub(seq).ok_or(Replay::TooOld)?;
        if age >= WINDOW {
            return Err(Replay::TooOld);
        }
        if self.bit(age) {
            Err(Replay::Duplicate)
        } else {
            Ok(())
        }
    }

    /// Records `seq` as accepted, after its tag verified.
    ///
    /// # Errors
    ///
    /// [`Replay`] when [`ReplayWindow::check`] refuses it; nothing changes.
    pub fn accept(&mut self, seq: u64) -> Result<(), Replay> {
        self.check(seq)?;
        match self.highest {
            Some(highest) if seq <= highest => {
                let age = highest.checked_sub(seq).ok_or(Replay::TooOld)?;
                self.set(age);
            }
            Some(highest) => {
                let shift = seq.checked_sub(highest).ok_or(Replay::TooOld)?;
                self.shift(shift);
                self.highest = Some(seq);
                self.set(0);
            }
            None => {
                self.highest = Some(seq);
                self.set(0);
            }
        }
        Ok(())
    }

    fn bit(&self, age: u64) -> bool {
        let (word, bit) = split(age);
        self.bits.get(word).is_some_and(|w| w & (1_u64 << bit) != 0)
    }

    fn set(&mut self, age: u64) {
        let (word, bit) = split(age);
        if let Some(w) = self.bits.get_mut(word) {
            *w |= 1_u64 << bit;
        }
    }

    /// Ages every remembered sequence by `by`, dropping those past the
    /// window.
    fn shift(&mut self, by: u64) {
        if by >= WINDOW {
            self.bits = [0; WORDS];
            return;
        }
        let (words, bits) = split(by);
        let mut next = [0_u64; WORDS];
        for (index, slot) in next.iter_mut().enumerate() {
            let Some(from) = index.checked_sub(words) else {
                continue;
            };
            let low = self.bits.get(from).copied().unwrap_or(0);
            let carry = if bits == 0 {
                0
            } else {
                from.checked_sub(1)
                    .and_then(|below| self.bits.get(below))
                    .map_or(0, |w| w >> (64_u32.saturating_sub(bits)))
            };
            *slot = low.checked_shl(bits).unwrap_or(0) | carry;
        }
        self.bits = next;
    }
}

/// The word and bit of an age below [`WINDOW`].
fn split(age: u64) -> (usize, u32) {
    let word = usize::try_from(age / 64).unwrap_or(usize::MAX);
    let bit = u32::try_from(age % 64).unwrap_or(0);
    (word, bit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn first_sequence_is_accepted_and_then_a_duplicate() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.accept(5), Ok(()));
        assert_eq!(window.accept(5), Err(Replay::Duplicate));
        assert_eq!(window.highest(), Some(5));
    }

    #[test]
    fn edges_of_the_window() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.accept(2000), Ok(()));
        assert_eq!(window.check(2000 - WINDOW), Err(Replay::TooOld));
        assert_eq!(window.accept(2000 - WINDOW + 1), Ok(()));
        assert_eq!(window.accept(2000 - WINDOW + 1), Err(Replay::Duplicate));
        assert_eq!(window.accept(2001), Ok(()));
        assert_eq!(window.check(2000 - WINDOW + 1), Err(Replay::TooOld));
    }

    #[test]
    fn a_refused_sequence_changes_nothing() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.accept(10), Ok(()));
        let before = window.clone();
        assert_eq!(window.accept(10), Err(Replay::Duplicate));
        assert_eq!(window, before);
    }

    #[test]
    fn the_last_sequence_is_accepted_once() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.accept(u64::MAX), Ok(()));
        assert_eq!(window.accept(u64::MAX), Err(Replay::Duplicate));
    }

    proptest! {
        /// Matches a model that remembers every accepted sequence.
        #[test]
        fn matches_the_model(seqs in proptest::collection::vec(0_u64..3000, 1..400)) {
            let mut window = ReplayWindow::new();
            let mut seen = std::collections::BTreeSet::new();
            let mut highest: Option<u64> = None;
            for seq in seqs {
                let expected = match highest {
                    Some(h) if seq <= h && h - seq >= WINDOW => Err(Replay::TooOld),
                    _ if seen.contains(&seq) => Err(Replay::Duplicate),
                    _ => Ok(()),
                };
                prop_assert_eq!(window.accept(seq), expected);
                if expected.is_ok() {
                    seen.insert(seq);
                    highest = Some(highest.map_or(seq, |h| h.max(seq)));
                }
            }
        }
    }
}
