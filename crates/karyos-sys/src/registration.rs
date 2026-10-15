// SPDX-License-Identifier: Apache-2.0

//! Registration words: the export a participant's cell, publisher slot or
//! exclusive publication is registered for, with its adoption and fence
//! marks (`quantstratum-docs: karyos/design/ipc-log-buffer.md`, Binding;
//! `karyos/design/ipc-data-path.md`, Ending a registration and Generations
//! across processes).
//!
//! A word holds 0 (no export), or an export id in `1..=MAX_EXPORT`,
//! optionally with [`ADOPTED`] (the grant's one adoption) or [`FENCED`] (the
//! driver fenced the grant at a cutover deadline). Adoption and fencing are
//! each one compare-exchange from the bare export, so exactly one of them
//! wins; ending a registration clears the word only while it still names
//! the export, so a delayed end never touches a later occupant.

use crate::sync::{AtomicU64, Ordering};

/// Bit set by the one adoption of a grant.
pub const ADOPTED: u64 = 1 << 63;
/// Bit set when the driver fences a grant that did not move at a cutover.
pub const FENCED: u64 = 1 << 62;
/// The largest export id: export ids stay below both marks.
pub const MAX_EXPORT: u64 = FENCED - 1;

const MARKS: u64 = ADOPTED | FENCED;

/// Whether `export` can name a registration: in `1..=MAX_EXPORT`.
#[must_use]
pub const fn valid_export(export: u64) -> bool {
    export != 0 && export <= MAX_EXPORT
}

/// Whether the registration word value `raw` names `export`, adopted,
/// fenced or neither.
#[must_use]
pub const fn names(raw: u64, export: u64) -> bool {
    valid_export(export) && raw & !MARKS == export
}

/// Claims the registration word for its one adoption: it must hold exactly
/// `export`, and is marked adopted in the same step, so a second adoption
/// of the same grant, concurrent or later, is refused, as is the adoption
/// of a fenced or ended grant. A claim is never returned: an adoption that
/// fails after it leaves the grant spent, and the registration ends with
/// the driver's.
pub fn claim(word: &AtomicU64, export: u64) -> bool {
    valid_export(export)
        && word
            .compare_exchange(
                export,
                export | ADOPTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
}

/// Ends the registration of `export`: clears the word if it still names
/// `export`, adopted, fenced or neither, and returns whether it did. A word
/// that holds another export or none is left untouched. Linearized with a
/// concurrent [`claim`] on the same word: an adoption that comes after
/// fails.
pub fn end(word: &AtomicU64, export: u64) -> bool {
    let mut raw = word.load(Ordering::Acquire);
    // Retries only while a concurrent claim or fence marks the same export.
    while names(raw, export) {
        match word.compare_exchange(raw, 0, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => raw = actual,
        }
    }
    false
}

/// Clears the word at the end of an occupant that holds its cell, slot or
/// publication itself (an ordinary drop or detach). Its `Release` orders
/// the occupant's accesses before a later reader of the word.
pub fn clear(word: &AtomicU64) {
    word.store(0, Ordering::Release);
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn export_ids_stay_below_both_marks() {
        assert!(!valid_export(0));
        assert!(valid_export(1));
        assert!(valid_export(MAX_EXPORT));
        assert!(!valid_export(FENCED));
        assert!(!valid_export(ADOPTED));
        assert!(!valid_export(ADOPTED | 1));
    }

    #[test]
    fn a_claim_is_taken_once_and_only_for_the_bare_export() {
        let word = AtomicU64::new(7);
        assert!(!claim(&word, 8));
        assert!(claim(&word, 7));
        assert!(!claim(&word, 7));
        assert_eq!(word.load(Ordering::Relaxed), 7 | ADOPTED);
        let fenced = AtomicU64::new(7 | FENCED);
        assert!(!claim(&fenced, 7));
    }

    #[test]
    fn an_end_clears_only_its_own_export() {
        for raw in [7, 7 | ADOPTED, 7 | FENCED] {
            let word = AtomicU64::new(raw);
            assert!(!end(&word, 8));
            assert_eq!(word.load(Ordering::Relaxed), raw);
            assert!(end(&word, 7));
            assert_eq!(word.load(Ordering::Relaxed), 0);
            // Ended: a stale adoption and a second end both fail.
            assert!(!claim(&word, 7));
            assert!(!end(&word, 7));
        }
        // An invalid export never matches, not even an empty word.
        let empty = AtomicU64::new(0);
        assert!(!end(&empty, 0));
    }
}
