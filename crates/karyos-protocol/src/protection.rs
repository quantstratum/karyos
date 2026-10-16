// SPDX-License-Identifier: Apache-2.0

//! The protection seam of the wire data path
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.2, M-4).
//!
//! A [`Protection`] seals the committed frames of one datagram on send and
//! opens a received datagram before any of its frames is used. The seam is
//! minimal on purpose: P2.1 owns its evolution (coordinator decision 4,
//! ACS 14786), and the candidate profiles
//! of the wire threat model manifest (version 2.0) are implementations of
//! this trait in a later batch. Neither call allocates.
//!
//! - [`Trusted`] is the baseline of every comparison: an envelope of zero
//!   bytes, sealing and opening nothing.
//! - `Synthetic` (feature `test-hooks`, or tests) spins for a calibrated
//!   time on each side. It checks the measurement harness end to end and
//!   is never a profile: its results never reach a decision report.

/// A datagram buffer too small for its frames and the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("datagram of {available} bytes cannot hold {needed} bytes")]
pub struct SealError {
    /// Bytes the frames and the envelope need.
    pub needed: usize,
    /// Bytes the buffer has.
    pub available: usize,
}

/// The decision on a received datagram, taken before any frame is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The datagram is accepted; its frames are the first `frames` bytes.
    Accept {
        /// Length of the frames, the datagram without its envelope.
        frames: usize,
    },
    /// The datagram is rejected and none of its frames may be used.
    Reject(Rejection),
}

/// Why a received datagram is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Shorter than the envelope.
    Short,
}

/// Seals and opens datagrams of one channel.
pub trait Protection {
    /// Bytes the envelope adds to every datagram.
    fn envelope_len(&self) -> usize;

    /// Seals the first `frames` bytes of `datagram`, writing the envelope
    /// after them, and returns the length to send. Allocates nothing.
    ///
    /// # Errors
    ///
    /// [`SealError`] when `datagram` cannot hold the frames and the
    /// envelope.
    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError>;

    /// Opens a received datagram. Allocates nothing.
    fn open(&self, datagram: &[u8]) -> Verdict;
}

/// The length the frames and an envelope of `envelope` bytes need, checked
/// against the buffer.
fn sealed_len(datagram: &[u8], frames: usize, envelope: usize) -> Result<usize, SealError> {
    let needed = frames.checked_add(envelope).ok_or(SealError {
        needed: usize::MAX,
        available: datagram.len(),
    })?;
    if needed > datagram.len() {
        return Err(SealError {
            needed,
            available: datagram.len(),
        });
    }
    Ok(needed)
}

/// The trusted channel: no envelope, nothing sealed or checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Trusted;

impl Protection for Trusted {
    fn envelope_len(&self) -> usize {
        0
    }

    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        sealed_len(datagram, frames, 0)
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        Verdict::Accept {
            frames: datagram.len(),
        }
    }
}

/// A test profile that spins for `spin_ns` nanoseconds on each side and
/// carries an envelope of `envelope` zero bytes. It checks the harness end
/// to end (measurement-harness.md §5.2) and is never a candidate profile.
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Synthetic {
    /// Nanoseconds spent in each of `seal` and `open`.
    pub spin_ns: u64,
    /// Bytes of envelope.
    pub envelope: usize,
}

#[cfg(any(test, feature = "test-hooks"))]
impl Synthetic {
    /// Busy-waits for `spin_ns` nanoseconds on the monotonic clock.
    fn spin(&self) {
        let start = std::time::Instant::now();
        let target = std::time::Duration::from_nanos(self.spin_ns);
        while start.elapsed() < target {
            std::hint::spin_loop();
        }
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl Protection for Synthetic {
    fn envelope_len(&self) -> usize {
        self.envelope
    }

    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        let total = sealed_len(datagram, frames, self.envelope)?;
        if let Some(envelope) = datagram.get_mut(frames..total) {
            envelope.fill(0);
        }
        self.spin();
        Ok(total)
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        self.spin();
        match datagram.len().checked_sub(self.envelope) {
            Some(frames) => Verdict::Accept { frames },
            None => Verdict::Reject(Rejection::Short),
        }
    }
}

#[cfg(test)]
mod tests;
