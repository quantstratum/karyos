// SPDX-License-Identifier: Apache-2.0

//! The guard word (`quantstratum-docs: karyos/design/guards-and-abort.md`,
//! G2): one `u64` holding `(epoch << 1) | open`, with the epoch in bits 63
//! to 1 and `open` in bit 0.
//!
//! - A guard is created at epoch 1, `Closed`. Each transition adds one to
//!   the epoch with checked arithmetic, so odd epochs are `Closed` and
//!   even epochs `Open`, and a higher epoch always compares greater as an
//!   unsigned word.
//! - The largest epoch, `2^63 - 1`, is odd: a guard can always be closed.
//!   A reopen that would need an epoch above it is refused with
//!   [`GuardError::Exhausted`], and the guard stays closed for good.
//! - Only the guard's owner writes the word, on the driver's control path,
//!   with Release; every reader loads it with Acquire. A word that breaks
//!   the encoding is a broken invariant: [`load`] reports it and it is
//!   treated as closed, never used to open.
//!
//! The functions work on any `AtomicU64`: a heap word in process, or a
//! word of a driver region that clients map read-only for their early
//! admission check.

use crate::sync::{AtomicU64, Ordering};

/// The largest epoch; odd, so a `Closed` epoch.
pub const MAX_EPOCH: u64 = (1 << 63) - 1;

/// The state of a guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardState {
    /// The epoch, from 1.
    pub epoch: u64,
    /// Whether admission is open.
    pub open: bool,
}

/// Why a guard operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    /// A reopen named an epoch the guard is not closed at.
    #[error("the guard is not closed at epoch {expected} (now {current:?})")]
    NotClosedAt {
        /// The epoch the reopen expected to replace.
        expected: u64,
        /// The guard's current state.
        current: GuardState,
    },
    /// A reopen would need an epoch above [`MAX_EPOCH`]; the guard stays
    /// closed for good.
    #[error("the guard's epochs are exhausted")]
    Exhausted,
    /// The word breaks the encoding: a broken invariant, treated as closed.
    #[error("guard word {word:#x} breaks the encoding")]
    Corrupt {
        /// The word read.
        word: u64,
    },
}

/// The word of `state`; `None` when the state breaks the encoding.
#[must_use]
pub const fn encode(state: GuardState) -> Option<u64> {
    if state.epoch == 0 || state.epoch > MAX_EPOCH || state.open != state.epoch.is_multiple_of(2) {
        return None;
    }
    Some((state.epoch << 1) | state.open as u64)
}

/// The state of `word`.
///
/// # Errors
///
/// [`GuardError::Corrupt`] for a word that breaks the encoding: epoch 0,
/// or an `open` bit that disagrees with the epoch's parity.
pub const fn decode(word: u64) -> Result<GuardState, GuardError> {
    let state = GuardState {
        epoch: word >> 1,
        open: word & 1 == 1,
    };
    match encode(state) {
        Some(_) => Ok(state),
        None => Err(GuardError::Corrupt { word }),
    }
}

/// The word of a new guard: epoch 1, `Closed`.
#[must_use]
pub const fn created() -> u64 {
    2
}

/// The guard's state, from one Acquire load.
///
/// # Errors
///
/// [`GuardError::Corrupt`] for a word that breaks the encoding; the caller
/// treats the guard as closed and reports the error.
pub fn load(word: &AtomicU64) -> Result<GuardState, GuardError> {
    decode(word.load(Ordering::Acquire))
}

/// Whether admission bound to open epoch `epoch` is still allowed: the word
/// is exactly `(epoch, Open)`, from one Acquire load. A closed guard, a
/// later epoch (open or not) and a corrupt word all refuse.
#[must_use]
pub fn admits(word: &AtomicU64, epoch: u64) -> bool {
    encode(GuardState { epoch, open: true })
        .is_some_and(|open| word.load(Ordering::Acquire) == open)
}

/// The outcome of [`close`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// The guard was open and is now closed at this epoch.
    Now {
        /// The new, odd, epoch.
        epoch: u64,
    },
    /// The guard was already closed at this epoch: nothing changed.
    Already {
        /// The current epoch.
        epoch: u64,
    },
}

/// Closes the guard. Idempotent at the current epoch: a second close of a
/// closed guard changes nothing. Owner only: the word has no other writer.
///
/// # Errors
///
/// [`GuardError::Corrupt`] for a word that breaks the encoding; nothing is
/// stored.
pub fn close(word: &AtomicU64) -> Result<Closed, GuardError> {
    let state = decode(word.load(Ordering::Relaxed))?;
    if !state.open {
        return Ok(Closed::Already { epoch: state.epoch });
    }
    // An open epoch is even and below MAX_EPOCH, which is odd.
    let epoch = state.epoch + 1;
    word.store(epoch << 1, Ordering::Release);
    Ok(Closed::Now { epoch })
}

/// Reopens a guard closed at `expected`, returning the new open epoch. A
/// stale reopen, naming an epoch the guard is no longer closed at, is
/// refused, so it can never reopen a later close. Owner only.
///
/// # Errors
///
/// [`GuardError::NotClosedAt`] when the guard is open or closed at another
/// epoch; [`GuardError::Exhausted`] at [`MAX_EPOCH`]; [`GuardError::Corrupt`]
/// for a broken word. Nothing is stored on error.
pub fn reopen(word: &AtomicU64, expected: u64) -> Result<u64, GuardError> {
    let current = decode(word.load(Ordering::Relaxed))?;
    if current.open || current.epoch != expected {
        return Err(GuardError::NotClosedAt { expected, current });
    }
    let epoch = current
        .epoch
        .checked_add(1)
        .filter(|epoch| *epoch <= MAX_EPOCH)
        .ok_or(GuardError::Exhausted)?;
    word.store((epoch << 1) | 1, Ordering::Release);
    Ok(epoch)
}

#[cfg(all(test, not(loom)))]
mod tests;
