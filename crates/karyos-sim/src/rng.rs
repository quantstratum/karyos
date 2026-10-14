// SPDX-License-Identifier: Apache-2.0

//! The simulator's generator: SplitMix64, so that a seed reproduces a run
//! exactly on every platform, with no external dependency.

/// A SplitMix64 generator.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// A generator from `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform value in `0..n`, by rejection; 0 when `n` is 0.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // The largest multiple of `n` that fits: values above it are drawn
        // again, so every residue is equally likely.
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let value = self.next_u64();
            if value < zone {
                return value % n;
            }
        }
    }

    /// A uniform value in `low..=high` (`low` when `high < low`).
    pub fn between(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            return low;
        }
        low + self.below(high - low + 1)
    }

    /// `true` with probability `numerator / denominator`.
    pub fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
        self.below(denominator) < numerator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_reproduces_its_sequence() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        // The reference values of SplitMix64 from seed 0.
        let mut zero = Rng::new(0);
        assert_eq!(zero.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(zero.next_u64(), 0x6E78_9E6A_A1B9_65F4);
    }

    #[test]
    fn bounded_draws_stay_in_range_and_cover_it() {
        let mut rng = Rng::new(7);
        let mut seen = [false; 5];
        for _ in 0..1000 {
            let value = rng.below(5);
            assert!(value < 5);
            seen[value as usize] = true;
            let between = rng.between(3, 6);
            assert!((3..=6).contains(&between));
        }
        assert!(seen.iter().all(|&hit| hit));
        assert_eq!(rng.below(0), 0);
        assert_eq!(rng.between(9, 2), 9);
    }
}
