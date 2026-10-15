// SPDX-License-Identifier: Apache-2.0

//! The state word of a participant cell and its loss transitions
//! (`quantstratum-docs: karyos/design/required-participant-loss.md`): the
//! states, which of them bound the publisher, and the steps that move a
//! cell between them. The log buffer's conductor and subscribers call these
//! steps; the Loom models of `loom_participant` check them in every
//! interleaving.
//!
//! These are raw protocol helpers over atomics, like `loan`: they do not
//! enforce who owns a cell or which step a party may take. The log buffer's
//! capability types do.

use crate::error::SysError;
use crate::loan::{participant_quiescent, revoke};
use crate::registration;
use crate::sync::{AtomicU64, Ordering};

/// A free cell: the conductor may admit a participant into it.
pub const CELL_FREE: u64 = 0;
/// A required reader: it bounds the publisher.
pub const CELL_REQUIRED: u64 = 1;
/// An optional reader: never bounds, holds a spare-slot credit.
pub const CELL_OPTIONAL: u64 = 2;
/// A publication's cell.
pub const CELL_PUBLICATION: u64 = 3;
/// A required reader admitted under `continue`: it bounds the publisher
/// and holds a spare-slot credit.
pub const CELL_REQUIRED_RESERVED: u64 = 4;
/// A revoked required reader under `hold`: it still bounds the publisher
/// until a scan after the revocation finds its loan word empty.
pub const CELL_LOST_HOLDING: u64 = 5;
/// A revoked reader that no longer bounds and holds no credit.
pub const CELL_LOST: u64 = 6;
/// A revoked reader that keeps its credit until it is freed.
pub const CELL_LOST_RESERVED: u64 = 7;
/// An observer: copies only, never bounds, holds a spare-slot credit
/// (`quantstratum-docs: karyos/design/observer-role.md`).
pub const CELL_OBSERVER: u64 = 8;

/// Whether a cell in `state` bounds the publication limit.
#[must_use]
pub const fn bounds(state: u64) -> bool {
    matches!(
        state,
        CELL_REQUIRED | CELL_REQUIRED_RESERVED | CELL_LOST_HOLDING
    )
}

/// Driver: revokes the participant of a cell found in state `from` and
/// moves it to `to`. The revocation flag is set and the loan word scanned
/// first, so no acquisition after this call succeeds. Returns `None` when
/// the state changed meanwhile (a detach that stored `FREE` first means the
/// participant left and nothing was lost), else whether the scan after the
/// revocation found the loan word empty.
///
/// # Errors
///
/// Returns [`SysError::InvalidLoanWord`] when the loan word is malformed.
pub fn revoke_cell(
    state: &AtomicU64,
    revoked: &AtomicU64,
    loan: &AtomicU64,
    from: u64,
    to: u64,
) -> Result<Option<bool>, SysError> {
    let quiescent = revoke(revoked, core::slice::from_ref(loan))?;
    if state
        .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some(quiescent))
}

/// Driver: withdraws the bound of a `hold` cell whose revocation already
/// came, from `CELL_LOST_HOLDING` to `CELL_LOST`, when a scan finds its loan
/// word empty. A compare-exchange from that state only, so a cell freed
/// and admitted again meanwhile is never touched. Returns whether it moved.
///
/// # Errors
///
/// Returns [`SysError::InvalidLoanWord`] when the loan word is malformed.
pub fn withdraw_if_quiescent(state: &AtomicU64, loan: &AtomicU64) -> Result<bool, SysError> {
    Ok(state.load(Ordering::Acquire) == CELL_LOST_HOLDING
        && participant_quiescent(core::slice::from_ref(loan))?
        && withdraw(state))
}

/// Driver: withdraws a `CELL_LOST_HOLDING` cell's bound after a scan found
/// its loan word empty; returns whether it moved.
pub fn withdraw(state: &AtomicU64) -> bool {
    state
        .compare_exchange(
            CELL_LOST_HOLDING,
            CELL_LOST,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Holder: leaves its cell, its last access. The registration is cleared
/// before `FREE` is published, so a delayed end of its export never
/// touches the next occupant; no loan is held at this point.
///
/// `FREE` is written with a swap, a read-modify-write like the driver's
/// loss transition ([`revoke_cell`]) on the same word, as every write to
/// the seal word is: the two are then ordered by the word's modification
/// order alone, which the Loom models check (loom does not order a plain
/// store against a compare-exchange as the memory model does).
pub fn leave(state: &AtomicU64, registration_word: &AtomicU64) {
    registration::clear(registration_word);
    let _ = state.swap(CELL_FREE, Ordering::Release);
}

/// Conductor: admits `occupant` into a cell whose `FREE` it observed with
/// an Acquire load, in `admitted` state. That load synchronizes with the
/// previous holder's [`leave`], so its loan release happens before this
/// reuse and its loan word is zero; the revocation flag starts clear and
/// the state is published last.
pub fn admit(
    state: &AtomicU64,
    revoked: &AtomicU64,
    registration_word: &AtomicU64,
    occupant: u64,
    admitted: u64,
) {
    revoked.store(0, Ordering::Relaxed);
    registration_word.store(occupant, Ordering::Relaxed);
    state.store(admitted, Ordering::Release);
}
