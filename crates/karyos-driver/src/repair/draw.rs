// SPDX-License-Identifier: Apache-2.0

//! The driver's draw of a multicast cycle's NAK delay (RC-2, ACS 15597):
//! an integer uniform over `[0, bound]`, without bias, from random words
//! drawn from the operating system into a pool on the timer step
//! ([`OsDelayDraw::refill`]). A draw makes no system call. Rejection
//! sampling discards the few words that would bias the result, so a draw
//! takes one word except with probability below `bound / 2^64`.
//!
//! An empty pool, or a failed refill, draws the bound itself: the NAK goes
//! at the latest deadline of the cycle, which delays it but suppresses
//! nothing. Each such draw is counted.

use super::loss::DelayDraw;

/// Words the pool holds: a cycle per lane per image for a burst of losses
/// before the next timer step, with room to spare.
const POOL: usize = 32;

/// The pool is restocked only at or below this many words, so a refill on
/// every timer step makes no system call in steady state.
const LOW_WATER: usize = POOL / 2;

/// Random words for [`DelayDraw`], drawn into a pool on the timer step;
/// a draw only takes from it. Neither `Copy` nor `Clone`: a copied pool
/// would repeat its draws.
#[derive(Debug)]
pub struct OsDelayDraw {
    pool: [u64; POOL],
    len: usize,
    /// Draws made from an empty pool (the bound was drawn) since the last
    /// [`OsDelayDraw::take_empty`].
    empty: u64,
    /// Whether `empty` could not count a draw.
    overflowed: bool,
    /// Tests: a fixed delay, at most the bound, in place of a random one.
    #[cfg(test)]
    fixed: Option<u64>,
    /// Tests: the bound of the last draw.
    #[cfg(test)]
    last_bound: Option<u64>,
}

impl OsDelayDraw {
    /// A full pool, drawn now: call it on the control path.
    #[must_use]
    pub fn new() -> Self {
        let mut draw = Self {
            pool: [0; POOL],
            len: 0,
            empty: 0,
            overflowed: false,
            #[cfg(test)]
            fixed: None,
            #[cfg(test)]
            last_bound: None,
        };
        let _ = draw.refill();
        draw
    }

    /// Restocks the pool when it is at or below half full; returns whether
    /// it called the operating system. A failed call leaves the pool as it
    /// was.
    pub fn refill(&mut self) -> bool {
        if self.len > LOW_WATER {
            return false;
        }
        let Some(missing) = self.pool.get_mut(self.len..) else {
            return false;
        };
        if karyos_sys::random::fill_u64s(missing).is_ok() {
            self.len = POOL;
        }
        true
    }

    /// The words at hand.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The draws made from an empty pool since the last call, and whether
    /// that count overflowed; both reset. The agent moves them into its
    /// counters on the timer step.
    pub fn take_empty(&mut self) -> (u64, bool) {
        let taken = (self.empty, self.overflowed);
        self.empty = 0;
        self.overflowed = false;
        taken
    }

    /// Tests: every later draw is `delay`, or the bound if smaller.
    #[cfg(test)]
    pub(crate) fn fix(&mut self, delay: u64) {
        self.fixed = Some(delay);
    }

    /// Tests: the bound of the last draw.
    #[cfg(test)]
    pub(crate) fn last_bound(&self) -> Option<u64> {
        self.last_bound
    }

    fn word(&mut self) -> Option<u64> {
        let last = self.len.checked_sub(1)?;
        let word = self.pool.get(last).copied()?;
        self.len = last;
        Some(word)
    }
}

impl Default for OsDelayDraw {
    fn default() -> Self {
        Self::new()
    }
}

impl DelayDraw for OsDelayDraw {
    fn draw(&mut self, bound: u64) -> u64 {
        #[cfg(test)]
        {
            self.last_bound = Some(bound);
            if let Some(delay) = self.fixed {
                return delay.min(bound);
            }
        }
        uniform(bound, || self.word()).unwrap_or_else(|| {
            match self.empty.checked_add(1) {
                Some(next) => self.empty = next,
                None => self.overflowed = true,
            }
            bound
        })
    }
}

/// An integer uniform over `[0, bound]` from the words of `next`, or
/// `None` when `next` runs out. A word below `2^64 mod (bound + 1)` is
/// rejected, so each kept residue has the same number of preimages.
fn uniform(bound: u64, mut next: impl FnMut() -> Option<u64>) -> Option<u64> {
    let Some(span) = bound.checked_add(1) else {
        // The whole range: every word is uniform.
        return next();
    };
    let span = u128::from(span);
    let threshold = (1u128 << 64).checked_rem(span)?;
    loop {
        let word = u128::from(next()?);
        if word >= threshold {
            return u64::try_from(word.checked_rem(span)?).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draw_stays_within_its_bound() {
        let mut draw = OsDelayDraw::new();
        for bound in [0, 1, 7, 1_000_000, u64::MAX] {
            let _ = draw.refill();
            assert!(draw.draw(bound) <= bound);
        }
        assert_eq!(draw.take_empty(), (0, false));
    }

    #[test]
    fn a_zero_bound_draws_zero() {
        let mut words = [u64::MAX, 3].into_iter();
        assert_eq!(uniform(0, || words.next()), Some(0));
    }

    /// A word below `2^64 mod span` is rejected: with span 3, `2^64 mod 3`
    /// is 1, so 0 is rejected and the next word decides.
    #[test]
    fn a_biasing_word_is_rejected() {
        let mut words = [0u64, 5].into_iter();
        assert_eq!(uniform(2, || words.next()), Some(5 % 3));
        let mut words = [1u64].into_iter();
        assert_eq!(uniform(2, || words.next()), Some(1));
    }

    #[test]
    fn the_full_range_takes_the_word() {
        let mut words = [42u64].into_iter();
        assert_eq!(uniform(u64::MAX, || words.next()), Some(42));
    }

    #[test]
    fn an_empty_pool_draws_the_bound_and_counts() {
        let mut draw = OsDelayDraw {
            pool: [0; POOL],
            len: 0,
            empty: 0,
            overflowed: false,
            fixed: None,
            last_bound: None,
        };
        assert_eq!(draw.draw(500), 500);
        assert_eq!(draw.take_empty(), (1, false));
        assert_eq!(draw.take_empty(), (0, false));
    }

    #[test]
    fn a_refill_happens_only_at_low_water() {
        let mut draw = OsDelayDraw::new();
        assert_eq!(draw.len(), POOL);
        assert!(!draw.refill());
        for _ in 0..(POOL - LOW_WATER) {
            let _ = draw.draw(10);
        }
        assert_eq!(draw.len(), LOW_WATER);
        assert!(draw.refill());
        assert_eq!(draw.len(), POOL);
    }
}
