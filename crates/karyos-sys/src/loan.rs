// SPDX-License-Identifier: Apache-2.0

//! Loan words and the loan, reclaim and cleaning handshakes (SPEC.md §4,
//! term slot states).
//!
//! A participant publishes `(slot, generation, term)` in one of its loan words
//! and then validates the slot descriptor; the driver moves the descriptor to
//! `RECLAIMING` and then scans every loan word. Both sides use `SeqCst`, so in
//! the single total order of `SeqCst` operations they cannot both miss each
//! other: either the participant sees `RECLAIMING` and backs off, or the
//! driver sees the loan and keeps the slot quarantined.
//!
//! Each side also issues a `SeqCst` fence between its store and its load.
//! This is the fence formulation of the same store-then-load handshake, and
//! it is the one Loom can check: Loom models `SeqCst` loads and stores as
//! acquire/release, which cannot exclude the store-buffering outcome, but it
//! models `SeqCst` fences exactly.

use crate::error::SysError;
use crate::slot::{Descriptor, SlotIndex, SlotState};
use crate::sync::{AtomicU64, Ordering, fence};
use crate::term::{Generation, TermCount, TermId};

const VALID_FLAG: u64 = 0x80;
const SLOT_MASK: u64 = 0x7F;

/// The term a participant wants to access, with its physical slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoanTarget {
    slot: SlotIndex,
    generation: Generation,
    initial_term_id: TermId,
    count: TermCount,
}

impl LoanTarget {
    /// Describes term `count` of the incarnation that started at
    /// `initial_term_id`, held in `slot` of a mapping of `generation`.
    #[inline]
    #[must_use]
    pub const fn new(
        slot: SlotIndex,
        generation: Generation,
        initial_term_id: TermId,
        count: TermCount,
    ) -> Self {
        Self {
            slot,
            generation,
            initial_term_id,
            count,
        }
    }

    /// The physical slot.
    #[inline]
    #[must_use]
    pub const fn slot(self) -> SlotIndex {
        self.slot
    }

    /// The raw term id of the target term.
    #[inline]
    #[must_use]
    pub const fn term_id(self) -> TermId {
        self.initial_term_id.advanced_by(self.count)
    }

    /// The loan word value that names this target.
    #[inline]
    #[must_use]
    pub const fn loan(self) -> Loan {
        Loan {
            slot: self.slot,
            generation: self.generation,
            term_id: self.term_id(),
        }
    }
}

/// A decoded, non-empty loan word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Loan {
    slot: SlotIndex,
    generation: Generation,
    term_id: TermId,
}

impl Loan {
    /// The physical slot the loan pins.
    #[inline]
    #[must_use]
    pub const fn slot(self) -> SlotIndex {
        self.slot
    }

    /// The mapping generation of the loan.
    #[inline]
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// The raw term id of the loan.
    #[inline]
    #[must_use]
    pub const fn term_id(self) -> TermId {
        self.term_id
    }

    /// Encodes as `term_id << 32 | generation << 8 | 0x80 | slot`.
    #[inline]
    #[must_use]
    pub const fn encode(self) -> u64 {
        ((self.term_id.get() as u64) << 32)
            | ((self.generation.get() as u64) << 8)
            | VALID_FLAG
            | self.slot.get() as u64
    }

    /// Decodes a raw loan word; zero means no loan.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidLoanWord`] for a non-zero word without the
    /// valid flag.
    #[inline]
    pub const fn decode(raw: u64) -> Result<Option<Self>, SysError> {
        if raw == 0 {
            return Ok(None);
        }
        if raw & VALID_FLAG == 0 {
            return Err(SysError::InvalidLoanWord { raw });
        }
        let slot = match SlotIndex::try_new((raw & SLOT_MASK) as u8) {
            Ok(slot) => slot,
            Err(err) => return Err(err),
        };
        let generation = match Generation::try_new(((raw >> 8) & 0x00FF_FFFF) as u32) {
            Ok(generation) => generation,
            Err(err) => return Err(err),
        };
        Ok(Some(Self {
            slot,
            generation,
            term_id: TermId::new((raw >> 32) as u32),
        }))
    }

    /// Whether this loan pins the slot described by `descriptor` at `slot`.
    #[inline]
    #[must_use]
    pub fn pins(self, slot: SlotIndex, descriptor: Descriptor) -> bool {
        self.slot == slot
            && self.generation == descriptor.generation()
            && self.term_id == descriptor.term_id()
    }
}

/// Result of a loan attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use = "a granted loan must eventually be released"]
pub enum LoanOutcome {
    /// The loan is valid; the term's bytes may be accessed until release.
    Granted,
    /// The term is not active yet; try again later.
    Retry,
    /// The term is gone (reclaimed, cleaned or reassigned).
    Overrun,
    /// The participant has been revoked and can take no new loan.
    Revoked,
}

/// Value of a participant's revoked flag once the driver has revoked it.
pub const REVOKED: u64 = 1;

/// Takes a loan on `target` through `word`, validating it against
/// `descriptor` and the participant's `revoked` flag.
///
/// The loan word must belong to the caller, be empty and belong to the bank of
/// the lane that `target.slot()` indexes. On any outcome other than
/// [`LoanOutcome::Granted`] the word is cleared before returning. A revoked
/// participant never gets a loan, whatever the descriptor says.
///
/// # Errors
///
/// Returns an error when the descriptor is malformed, belongs to another
/// mapping generation or names a term outside the incarnation. The loan word
/// is cleared in that case too.
pub fn take_loan(
    word: &AtomicU64,
    revoked: &AtomicU64,
    descriptor: &AtomicU64,
    target: LoanTarget,
) -> Result<LoanOutcome, SysError> {
    word.store(target.loan().encode(), Ordering::SeqCst);
    fence(Ordering::SeqCst);
    let observed = descriptor.load(Ordering::SeqCst);
    let outcome = if revoked.load(Ordering::SeqCst) == 0 {
        classify(observed, target)
    } else {
        Ok(LoanOutcome::Revoked)
    };
    if !matches!(outcome, Ok(LoanOutcome::Granted)) {
        word.store(0, Ordering::SeqCst);
    }
    outcome
}

fn classify(raw: u64, target: LoanTarget) -> Result<LoanOutcome, SysError> {
    let found = Descriptor::decode(raw)?;
    if found.generation() != target.generation {
        return Err(SysError::GenerationMismatch {
            expected: target.generation.get(),
            found: found.generation().get(),
        });
    }
    let found_count = found.term_id().count_from(target.initial_term_id)?;
    Ok(match found_count.cmp(&target.count) {
        core::cmp::Ordering::Less => LoanOutcome::Retry,
        core::cmp::Ordering::Greater => LoanOutcome::Overrun,
        core::cmp::Ordering::Equal => match found.state() {
            SlotState::Active => LoanOutcome::Granted,
            SlotState::Ready => LoanOutcome::Retry,
            SlotState::Reclaiming | SlotState::Cleaning | SlotState::Free => LoanOutcome::Overrun,
        },
    })
}

/// Ends a granted loan. Every access under the loan must happen before this
/// call; the `Release` store orders them before the driver's scan.
#[inline]
pub fn release_loan(word: &AtomicU64) {
    word.store(0, Ordering::Release);
}

/// Driver: revokes a participant and reports whether it is quiescent.
///
/// Stores the participant's revoked flag, then scans all its loan words (in
/// every lane bank). Returns `true` only when every word is empty: from then
/// on no acquisition by this participant can succeed, because an acquisition
/// stores its word before loading the flag. Returns `false` while a loan is
/// still held; call [`participant_quiescent`] again until it returns `true`.
///
/// Quiescence does not free the registration. The loan words and the flag
/// stay allocated, flag set, until the participant proves detach or its
/// process verifiably exits (SPEC.md §4, IPC flow control).
///
/// # Errors
///
/// Returns [`SysError::InvalidLoanWord`] when a loan word is malformed.
pub fn revoke(revoked: &AtomicU64, loan_words: &[AtomicU64]) -> Result<bool, SysError> {
    revoked.store(REVOKED, Ordering::SeqCst);
    // Pairs with the fence in `take_loan`, as in `begin_reclaim`.
    fence(Ordering::SeqCst);
    participant_quiescent(loan_words)
}

/// Driver: whether every loan word of a revoked participant is empty. Only
/// meaningful after [`revoke`]; reading empty words without revocation never
/// proves quiescence.
///
/// # Errors
///
/// Returns [`SysError::InvalidLoanWord`] when a loan word is malformed.
pub fn participant_quiescent(loan_words: &[AtomicU64]) -> Result<bool, SysError> {
    for word in loan_words {
        if Loan::decode(word.load(Ordering::SeqCst))?.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Driver: moves `active` to `RECLAIMING`, after which no new loan is granted.
///
/// # Errors
///
/// Returns [`SysError::UnexpectedDescriptor`] when `active` is not an `Active`
/// descriptor or the slot no longer holds it.
pub fn begin_reclaim(descriptor: &AtomicU64, active: Descriptor) -> Result<Descriptor, SysError> {
    let reclaiming = active.with_state(SlotState::Reclaiming);
    let result = transition(
        descriptor,
        active,
        SlotState::Active,
        reclaiming,
        Ordering::SeqCst,
    );
    // Pairs with the fence in `take_loan`: every later `loan_held` scan sees
    // any loan whose holder saw this slot `ACTIVE`.
    fence(Ordering::SeqCst);
    result
}

/// Driver: whether any loan word still pins the slot `slot` described by
/// `reclaiming`. Call after [`begin_reclaim`]; repeat until it returns
/// `false` before cleaning.
///
/// # Errors
///
/// Returns [`SysError::InvalidLoanWord`] when a loan word is malformed.
pub fn loan_held(
    words: &[AtomicU64],
    slot: SlotIndex,
    reclaiming: Descriptor,
) -> Result<bool, SysError> {
    for word in words {
        // `SeqCst` (at least `Acquire`) is required: a scan that reads a
        // released word must synchronize with the holder's `Release` so its
        // accesses happen before cleaning. The Loom models check this: with a
        // `Relaxed` load they report a race on the term bytes.
        if let Some(loan) = Loan::decode(word.load(Ordering::SeqCst))?
            && loan.pins(slot, reclaiming)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Driver: moves a quarantined slot from `RECLAIMING` to `CLEANING`. Only call
/// after [`loan_held`] returned `false` for this descriptor.
///
/// # Errors
///
/// Returns [`SysError::UnexpectedDescriptor`] when the slot does not hold
/// `reclaiming`.
pub fn begin_cleaning(
    descriptor: &AtomicU64,
    reclaiming: Descriptor,
) -> Result<Descriptor, SysError> {
    let cleaning = reclaiming.with_state(SlotState::Cleaning);
    transition(
        descriptor,
        reclaiming,
        SlotState::Reclaiming,
        cleaning,
        Ordering::AcqRel,
    )
}

/// Driver: publishes a descriptor the driver owns exclusively (`FREE` after
/// cleaning, `READY` after initialising the slot's tail) with `Release`.
pub fn publish(descriptor: &AtomicU64, value: Descriptor) {
    descriptor.store(value.encode(), Ordering::Release);
}

/// Rotation: moves `ready` to `ACTIVE`. Finding the slot already `ACTIVE` with
/// the same identity counts as success, so the step can be repeated.
///
/// # Errors
///
/// Returns [`SysError::UnexpectedDescriptor`] when the slot holds anything
/// else.
pub fn activate(descriptor: &AtomicU64, ready: Descriptor) -> Result<Descriptor, SysError> {
    let active = ready.with_state(SlotState::Active);
    match transition(
        descriptor,
        ready,
        SlotState::Ready,
        active,
        Ordering::AcqRel,
    ) {
        Err(SysError::UnexpectedDescriptor { found, .. }) if found == active.encode() => Ok(active),
        other => other,
    }
}

fn transition(
    descriptor: &AtomicU64,
    from: Descriptor,
    required: SlotState,
    to: Descriptor,
    ordering: Ordering,
) -> Result<Descriptor, SysError> {
    if from.state() != required {
        return Err(SysError::WrongSourceState {
            required: required as u8,
            given: from.state() as u8,
        });
    }
    let failure = match ordering {
        Ordering::SeqCst => Ordering::SeqCst,
        _ => Ordering::Acquire,
    };
    descriptor
        .compare_exchange(from.encode(), to.encode(), ordering, failure)
        .map(|_| to)
        .map_err(|found| SysError::UnexpectedDescriptor {
            expected: from.encode(),
            found,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    static NOT_REVOKED: AtomicU64 = AtomicU64::new(0);

    fn ids() -> (SlotIndex, Generation, TermId) {
        (
            SlotIndex::try_new(5).unwrap(),
            Generation::try_new(7).unwrap(),
            TermId::new(u32::MAX - 1),
        )
    }

    fn target(count: u32) -> LoanTarget {
        let (slot, generation, initial) = ids();
        LoanTarget::new(
            slot,
            generation,
            initial,
            TermCount::try_new(count).unwrap(),
        )
    }

    fn descriptor(count: u32, state: SlotState) -> Descriptor {
        let (_, generation, initial) = ids();
        Descriptor::new(
            initial.advanced_by(TermCount::try_new(count).unwrap()),
            generation,
            state,
        )
    }

    #[test]
    fn loan_word_round_trip_and_layout() {
        let loan = target(3).loan();
        assert_eq!(loan.term_id().get(), 1);
        assert_eq!(loan.encode(), 0x0000_0001_0000_0785);
        assert_eq!(Loan::decode(loan.encode()), Ok(Some(loan)));
        assert_eq!(Loan::decode(0), Ok(None));
        assert_eq!(
            Loan::decode(0x1_0000_0005),
            Err(SysError::InvalidLoanWord { raw: 0x1_0000_0005 })
        );
    }

    #[test]
    fn zero_identity_loan_is_distinct_from_empty() {
        let loan = LoanTarget::new(
            SlotIndex::try_new(0).unwrap(),
            Generation::try_new(0).unwrap(),
            TermId::new(0),
            TermCount::ZERO,
        )
        .loan();
        assert_eq!(loan.encode(), VALID_FLAG);
        assert_eq!(Loan::decode(loan.encode()), Ok(Some(loan)));
        assert_eq!(Loan::decode(0), Ok(None));
    }

    #[test]
    fn outcomes_follow_state_and_term_order() {
        let cases = [
            (descriptor(3, SlotState::Active), LoanOutcome::Granted),
            (descriptor(3, SlotState::Ready), LoanOutcome::Retry),
            (descriptor(2, SlotState::Active), LoanOutcome::Retry),
            (descriptor(2, SlotState::Free), LoanOutcome::Retry),
            (descriptor(3, SlotState::Reclaiming), LoanOutcome::Overrun),
            (descriptor(3, SlotState::Cleaning), LoanOutcome::Overrun),
            (descriptor(3, SlotState::Free), LoanOutcome::Overrun),
            (descriptor(6, SlotState::Active), LoanOutcome::Overrun),
        ];
        for (found, expected) in cases {
            let word = AtomicU64::new(0);
            let desc = AtomicU64::new(found.encode());
            assert_eq!(
                take_loan(&word, &NOT_REVOKED, &desc, target(3)),
                Ok(expected),
                "{found:?}"
            );
            let held = word.load(Ordering::SeqCst);
            if expected == LoanOutcome::Granted {
                assert_eq!(held, target(3).loan().encode());
            } else {
                assert_eq!(held, 0);
            }
        }
    }

    #[test]
    fn generation_mismatch_is_an_error_and_clears_the_word() {
        let (_, _, initial) = ids();
        let other = Descriptor::new(initial, Generation::try_new(8).unwrap(), SlotState::Active);
        let word = AtomicU64::new(0);
        let desc = AtomicU64::new(other.encode());
        assert_eq!(
            take_loan(&word, &NOT_REVOKED, &desc, target(0)),
            Err(SysError::GenerationMismatch {
                expected: 7,
                found: 8
            })
        );
        assert_eq!(word.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn reclaim_quarantines_until_loans_end() {
        let (slot, _, _) = ids();
        let active = descriptor(3, SlotState::Active);
        let desc = AtomicU64::new(active.encode());
        let words = [AtomicU64::new(0), AtomicU64::new(0)];
        assert_eq!(
            take_loan(&words[1], &NOT_REVOKED, &desc, target(3)),
            Ok(LoanOutcome::Granted)
        );

        let reclaiming = begin_reclaim(&desc, active).unwrap();
        assert_eq!(
            take_loan(&words[0], &NOT_REVOKED, &desc, target(3)),
            Ok(LoanOutcome::Overrun)
        );
        assert_eq!(loan_held(&words, slot, reclaiming), Ok(true));

        release_loan(&words[1]);
        assert_eq!(loan_held(&words, slot, reclaiming), Ok(false));
        let cleaning = begin_cleaning(&desc, reclaiming).unwrap();
        assert_eq!(cleaning.state(), SlotState::Cleaning);
        publish(&desc, cleaning.with_state(SlotState::Free));
        assert_eq!(
            take_loan(&words[0], &NOT_REVOKED, &desc, target(3)),
            Ok(LoanOutcome::Overrun)
        );
    }

    #[test]
    fn loans_on_other_slots_or_terms_do_not_pin() {
        let (slot, _, _) = ids();
        let reclaiming = descriptor(3, SlotState::Reclaiming);
        let other_term = AtomicU64::new(target(4).loan().encode());
        let (_, generation, initial) = ids();
        let other_slot_target = LoanTarget::new(
            SlotIndex::try_new(6).unwrap(),
            generation,
            initial,
            TermCount::try_new(3).unwrap(),
        );
        let other_slot = AtomicU64::new(other_slot_target.loan().encode());
        let words = [other_term, other_slot];
        assert_eq!(loan_held(&words, slot, reclaiming), Ok(false));
    }

    #[test]
    fn transitions_reject_wrong_states() {
        let active = descriptor(3, SlotState::Active);
        let desc = AtomicU64::new(active.encode());
        assert!(begin_cleaning(&desc, active).is_err());
        assert!(begin_reclaim(&desc, active.with_state(SlotState::Ready)).is_err());
        let stale = descriptor(2, SlotState::Active);
        assert!(begin_reclaim(&desc, stale).is_err());
    }

    #[test]
    fn activation_rejects_a_non_ready_argument_without_reading_the_slot() {
        let active = descriptor(4, SlotState::Active);
        for actual in [SlotState::Reclaiming, SlotState::Free] {
            let desc = AtomicU64::new(descriptor(4, actual).encode());
            assert_eq!(
                activate(&desc, active),
                Err(SysError::WrongSourceState {
                    required: SlotState::Ready as u8,
                    given: SlotState::Active as u8,
                })
            );
            assert_eq!(desc.load(Ordering::SeqCst), descriptor(4, actual).encode());
        }
    }

    #[test]
    fn activation_is_idempotent() {
        let ready = descriptor(4, SlotState::Ready);
        let desc = AtomicU64::new(ready.encode());
        let active = activate(&desc, ready).unwrap();
        assert_eq!(activate(&desc, ready), Ok(active));
        publish(&desc, descriptor(4, SlotState::Reclaiming));
        assert!(activate(&desc, ready).is_err());
    }

    #[test]
    fn revoked_participant_gets_no_loan() {
        let active = descriptor(3, SlotState::Active);
        let desc = AtomicU64::new(active.encode());
        let revoked = AtomicU64::new(0);
        let words = [AtomicU64::new(0)];
        assert_eq!(revoke(&revoked, &words), Ok(true));
        assert_eq!(
            take_loan(&words[0], &revoked, &desc, target(3)),
            Ok(LoanOutcome::Revoked)
        );
        assert_eq!(words[0].load(Ordering::SeqCst), 0);
    }

    #[test]
    fn revocation_waits_for_held_loans() {
        let active = descriptor(3, SlotState::Active);
        let desc = AtomicU64::new(active.encode());
        let revoked = AtomicU64::new(0);
        let words = [AtomicU64::new(0), AtomicU64::new(0)];
        assert_eq!(
            take_loan(&words[1], &revoked, &desc, target(3)),
            Ok(LoanOutcome::Granted)
        );
        assert_eq!(revoke(&revoked, &words), Ok(false));
        release_loan(&words[1]);
        assert_eq!(participant_quiescent(&words), Ok(true));
    }
}
