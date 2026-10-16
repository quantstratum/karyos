// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use proptest::prelude::*;

use super::*;

fn state(epoch: u64, open: bool) -> GuardState {
    GuardState { epoch, open }
}

#[test]
fn a_new_guard_is_closed_at_epoch_one() {
    let word = AtomicU64::new(created());
    assert_eq!(load(&word), Ok(state(1, false)));
    assert!(!admits(&word, 1));
}

#[test]
fn reopen_and_close_alternate_parity() {
    let word = AtomicU64::new(created());
    assert_eq!(reopen(&word, 1), Ok(2));
    assert_eq!(load(&word), Ok(state(2, true)));
    assert!(admits(&word, 2));
    assert_eq!(close(&word), Ok(Closed::Now { epoch: 3 }));
    assert!(!admits(&word, 2));
    assert_eq!(close(&word), Ok(Closed::Already { epoch: 3 }));
    assert_eq!(load(&word), Ok(state(3, false)));
    assert_eq!(reopen(&word, 3), Ok(4));
    // An incarnation bound to epoch 2 is not admitted at epoch 4.
    assert!(!admits(&word, 2));
    assert!(admits(&word, 4));
}

#[test]
fn a_stale_reopen_is_refused() {
    let word = AtomicU64::new(created());
    assert_eq!(reopen(&word, 1), Ok(2));
    assert_eq!(close(&word), Ok(Closed::Now { epoch: 3 }));
    // Expecting epoch 1, a closed epoch that is no longer current.
    assert_eq!(
        reopen(&word, 1),
        Err(GuardError::NotClosedAt {
            expected: 1,
            current: state(3, false)
        })
    );
    // An open guard cannot be reopened.
    assert_eq!(reopen(&word, 3), Ok(4));
    assert!(matches!(
        reopen(&word, 4),
        Err(GuardError::NotClosedAt { .. })
    ));
    assert_eq!(load(&word), Ok(state(4, true)));
}

#[test]
fn the_last_epoch_is_closed_and_cannot_reopen() {
    let word = AtomicU64::new(encode(state(MAX_EPOCH - 1, true)).unwrap());
    assert_eq!(close(&word), Ok(Closed::Now { epoch: MAX_EPOCH }));
    assert_eq!(load(&word), Ok(state(MAX_EPOCH, false)));
    assert_eq!(reopen(&word, MAX_EPOCH), Err(GuardError::Exhausted));
    assert_eq!(load(&word), Ok(state(MAX_EPOCH, false)), "nothing stored");
    assert_eq!(close(&word), Ok(Closed::Already { epoch: MAX_EPOCH }));
}

#[test]
fn a_corrupt_word_is_never_open() {
    // Epoch 0, and an open bit on an odd epoch.
    for raw in [0, 1, (3 << 1) | 1, (2 << 1)] {
        let word = AtomicU64::new(raw);
        assert_eq!(load(&word), Err(GuardError::Corrupt { word: raw }));
        assert!(!admits(&word, 2));
        assert_eq!(close(&word), Err(GuardError::Corrupt { word: raw }));
        assert!(reopen(&word, 1).is_err());
        assert_eq!(word.load(Ordering::Relaxed), raw, "nothing stored");
    }
}

#[test]
fn admits_refuses_an_unencodable_epoch() {
    let word = AtomicU64::new(created());
    assert!(!admits(&word, 0));
    assert!(!admits(&word, 1), "odd epochs are never open");
}

proptest! {
    // Under Miri: fewer cases and no failure file.
    #![proptest_config(crate::receive::tests_config())]

    /// Every valid state round trips, and a higher epoch is a greater word.
    #[test]
    fn valid_states_round_trip_and_order(epoch in 1..=MAX_EPOCH) {
        let open = epoch.is_multiple_of(2);
        let word = encode(state(epoch, open)).unwrap();
        prop_assert_eq!(decode(word), Ok(state(epoch, open)));
        prop_assert!(encode(state(epoch, !open)).is_none());
        if epoch < MAX_EPOCH {
            let next = encode(state(epoch + 1, !open)).unwrap();
            prop_assert!(next > word);
        }
    }

    /// No word decodes to an open state whose parity is wrong.
    #[test]
    fn any_decoded_word_is_consistent(raw in any::<u64>()) {
        if let Ok(decoded) = decode(raw) {
            prop_assert!(decoded.epoch >= 1);
            prop_assert_eq!(decoded.open, decoded.epoch.is_multiple_of(2));
            prop_assert_eq!(encode(decoded), Some(raw));
        }
    }
}
