// SPDX-License-Identifier: Apache-2.0

//! The driver's draw of a multicast cycle's NAK delay (RC-2, ACS 15597):
//! an integer uniform over `[0, bound]`, without bias, from random words
//! drawn from the operating system into a pool on the timer step
//! ([`OsDelayDraw::refill`]). A draw makes no system call. Rejection
//! sampling discards the few words that would bias the result, so a draw
//! takes one word except with probability below `bound / 2^64`.
//!
//! **Sizing** (#296 review): one timer step starts at most one cycle per
//! lane of each image, so the pool keeps at least `per_step = images ×
//! lanes` words plus a margin for rejections at the start of every step.
//! A burst of losses on every image then never empties it: an empty pool
//! would put every receiver's NAK at the bound in lockstep, which defeats
//! the random delay.
//!
//! An empty pool, after a failed refill, draws the bound itself: the NAK
//! goes at the latest deadline of the cycle, which delays it but
//! suppresses nothing. Each such draw is counted, and so is each failed
//! refill.

use super::loss::DelayDraw;

/// Words kept beyond one step's draws, for rejected words.
const MARGIN: usize = 8;

/// What a refill did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refill {
    /// The pool held a step's words: no system call.
    Full,
    /// The pool was restocked from the operating system.
    Drew,
    /// The system call failed: the pool is as it was.
    Failed,
}

/// Random words for [`DelayDraw`], drawn into a pool on the timer step;
/// a draw only takes from it. Neither `Copy` nor `Clone`: a copied pool
/// would repeat its draws.
#[derive(Debug)]
pub struct OsDelayDraw {
    /// Twice a step's words, allocated at construction.
    pool: Box<[u64]>,
    len: usize,
    /// The words one timer step may take: a refill restocks below it.
    per_step: usize,
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
    /// Tests: refills fail.
    #[cfg(test)]
    fail_refills: bool,
}

impl OsDelayDraw {
    /// A full pool for `images` images of up to `lanes` lanes, drawn now:
    /// call it on the control path. `None` when the size overflows.
    #[must_use]
    pub fn new(images: usize, lanes: usize) -> Option<Self> {
        let per_step = images.checked_mul(lanes)?.checked_add(MARGIN)?;
        let capacity = per_step.checked_mul(2)?;
        let mut draw = Self {
            pool: vec![0; capacity].into_boxed_slice(),
            len: 0,
            per_step,
            empty: 0,
            overflowed: false,
            #[cfg(test)]
            fixed: None,
            #[cfg(test)]
            last_bound: None,
            #[cfg(test)]
            fail_refills: false,
        };
        let _ = draw.refill();
        Some(draw)
    }

    /// Restocks the pool when it holds fewer than a step's words, on the
    /// timer step before any draw. A failed call leaves the pool as it was.
    pub fn refill(&mut self) -> Refill {
        if self.len >= self.per_step {
            return Refill::Full;
        }
        #[cfg(test)]
        if self.fail_refills {
            return Refill::Failed;
        }
        let Some(missing) = self.pool.get_mut(self.len..) else {
            return Refill::Failed;
        };
        if karyos_sys::random::fill_u64s(missing).is_err() {
            return Refill::Failed;
        }
        self.len = self.pool.len();
        Refill::Drew
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

    /// Tests: empties the pool, and makes later refills fail or not.
    #[cfg(test)]
    pub(crate) fn drain(&mut self, fail_refills: bool) {
        self.len = 0;
        self.fail_refills = fail_refills;
    }

    fn word(&mut self) -> Option<u64> {
        let last = self.len.checked_sub(1)?;
        let word = self.pool.get(last).copied()?;
        self.len = last;
        Some(word)
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

    fn pool() -> OsDelayDraw {
        OsDelayDraw::new(2, 4).unwrap()
    }

    #[test]
    fn a_draw_stays_within_its_bound() {
        let mut draw = pool();
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
        let mut draw = pool();
        draw.drain(true);
        assert_eq!(draw.refill(), Refill::Failed);
        assert_eq!(draw.draw(500), 500);
        assert_eq!(draw.take_empty(), (1, false));
        assert_eq!(draw.take_empty(), (0, false));
    }

    /// The pool holds twice a step's words (2 images of 4 lanes plus 8)
    /// and is restocked once fewer than a step's remain: a step of draws on
    /// every lane of every image never empties it.
    #[test]
    fn a_refill_keeps_a_steps_words() {
        let mut draw = pool();
        let per_step = 2 * 4 + MARGIN;
        assert_eq!(draw.len(), 2 * per_step);
        assert_eq!(draw.refill(), Refill::Full);
        for _ in 0..per_step {
            let _ = draw.draw(10);
        }
        assert_eq!(draw.refill(), Refill::Full);
        let _ = draw.draw(10);
        assert_eq!(draw.refill(), Refill::Drew);
        assert_eq!(draw.len(), 2 * per_step);
        for _ in 0..per_step {
            let _ = draw.draw(10);
        }
        assert_eq!(draw.take_empty(), (0, false));
    }

    #[test]
    fn an_oversized_pool_is_refused() {
        assert!(OsDelayDraw::new(usize::MAX, 4).is_none());
    }
}
