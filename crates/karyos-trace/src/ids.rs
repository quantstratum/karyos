// SPDX-License-Identifier: Apache-2.0

//! The id source of a trace agent (`quantstratum-docs:
//! karyos/design/trace-data-path.md`, "Identities and clocks"): a fixed
//! buffer of random words, filled at creation and refilled only on the
//! control path, so that taking an id never blocks, allocates or makes a
//! system call.

use std::fs::File;
use std::io::{self, Read};

use crate::sampling::IdSource;

/// A cryptographically strong source of random words, used only on the
/// control path.
pub trait RandomSource: Send {
    /// Fills `words` with random values.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when the source cannot be read.
    fn fill(&mut self, words: &mut [u64]) -> io::Result<()>;
}

/// The operating system's random source, `/dev/urandom`, read with the
/// standard library (Linux and macOS).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, words: &mut [u64]) -> io::Result<()> {
        let mut file = File::open("/dev/urandom")?;
        let mut bytes = [0u8; 8];
        for word in words {
            file.read_exact(&mut bytes)?;
            *word = u64::from_le_bytes(bytes);
        }
        Ok(())
    }
}

/// [`IdSource`] over a fixed buffer of random words. When the buffer is
/// empty it returns `None` (the message is published untraced) until
/// [`BufferedIds::refill`] runs on the control path.
#[derive(Debug)]
pub struct BufferedIds<R = OsRandom> {
    words: Box<[u64]>,
    /// The next buffer: a refill writes here and swaps only on success, so
    /// a source that fails part way changes nothing.
    spare: Box<[u64]>,
    available: usize,
    source: R,
}

impl<R: RandomSource> BufferedIds<R> {
    /// A buffer of `capacity` words (at least 2), filled from `source`
    /// (control path).
    ///
    /// # Errors
    ///
    /// Returns the source's error.
    pub fn new(capacity: usize, source: R) -> io::Result<Self> {
        let capacity = capacity.max(2);
        let mut ids = Self {
            words: vec![0; capacity].into_boxed_slice(),
            spare: vec![0; capacity].into_boxed_slice(),
            available: 0,
            source,
        };
        ids.refill()?;
        Ok(ids)
    }

    /// Words left before a refill is needed.
    #[must_use]
    pub fn available(&self) -> usize {
        self.available
    }

    /// Refills the whole buffer from the source (control path). The source
    /// writes a spare buffer, which replaces the current one only when the
    /// fill succeeds.
    ///
    /// # Errors
    ///
    /// Returns the source's error; the buffer, its words and the count
    /// available are then unchanged, even if the source wrote part of the
    /// spare before failing.
    pub fn refill(&mut self) -> io::Result<()> {
        if self.available == self.words.len() {
            return Ok(());
        }
        self.source.fill(&mut self.spare)?;
        core::mem::swap(&mut self.words, &mut self.spare);
        self.available = self.words.len();
        Ok(())
    }

    fn take(&mut self) -> Option<u64> {
        let index = self.available.checked_sub(1)?;
        self.available = index;
        self.words.get(index).copied()
    }
}

impl<R: RandomSource> IdSource for BufferedIds<R> {
    fn trace_id(&mut self) -> Option<[u64; 2]> {
        if self.available < 2 {
            return None;
        }
        Some([self.take()?, self.take()?])
    }

    fn span_id(&mut self) -> Option<u64> {
        self.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts its fills; the test decides when it may be asked.
    struct Counting(u64, usize);

    impl RandomSource for Counting {
        fn fill(&mut self, words: &mut [u64]) -> io::Result<()> {
            self.1 += 1;
            for word in words {
                self.0 += 1;
                *word = self.0;
            }
            Ok(())
        }
    }

    #[test]
    fn ids_run_out_and_only_a_refill_restores_them() {
        let mut ids = BufferedIds::new(3, Counting(0, 0)).unwrap();
        assert_eq!(ids.source.1, 1);
        assert_eq!(ids.trace_id(), Some([3, 2]));
        assert_eq!(ids.span_id(), Some(1));
        assert_eq!(ids.span_id(), None);
        assert_eq!(ids.trace_id(), None);
        // Taking ids never fills.
        assert_eq!(ids.source.1, 1);
        ids.refill().unwrap();
        assert_eq!(ids.source.1, 2);
        assert_eq!(ids.available(), 3);
        // A full buffer is not refilled again.
        ids.refill().unwrap();
        assert_eq!(ids.source.1, 2);
    }

    /// Writes one word, then fails, on its second fill.
    struct FailsPartWay(usize);

    impl RandomSource for FailsPartWay {
        fn fill(&mut self, words: &mut [u64]) -> io::Result<()> {
            self.0 += 1;
            if self.0 == 1 {
                for (word, value) in words.iter_mut().zip(1..) {
                    *word = value;
                }
                return Ok(());
            }
            words[0] = 999;
            Err(io::Error::other("source failed"))
        }
    }

    #[test]
    fn a_failed_refill_changes_nothing() {
        let mut ids = BufferedIds::new(4, FailsPartWay(0)).unwrap();
        assert_eq!(ids.span_id(), Some(4));
        assert!(ids.refill().is_err());
        assert_eq!(ids.available(), 3);
        assert_eq!(ids.trace_id(), Some([3, 2]));
        assert_eq!(ids.span_id(), Some(1));
        assert_eq!(ids.span_id(), None);
    }

    #[test]
    fn a_trace_id_needs_two_words() {
        let mut ids = BufferedIds::new(2, Counting(0, 0)).unwrap();
        assert_eq!(ids.span_id(), Some(2));
        assert_eq!(ids.trace_id(), None);
        assert_eq!(ids.available(), 1);
    }

    #[test]
    fn the_os_source_fills_with_varied_words() {
        let mut words = [0u64; 8];
        OsRandom.fill(&mut words).unwrap();
        let mut sorted = words;
        sorted.sort_unstable();
        // Eight random words are distinct with overwhelming probability.
        assert!(sorted.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
