// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use super::*;

fn bound(kind: PreviewKind, operator: u32, reason: &[u8]) -> Bound {
    Bound {
        kind,
        dir: PathBuf::from("/d"),
        guard: 7,
        requester: Requester::local(operator),
        reason: reason.to_vec(),
    }
}

fn open_at(epoch: u64) -> Seen {
    Seen {
        instance: 9,
        state: Some(GuardState { epoch, open: true }),
    }
}

fn token(answer: &PreviewAnswer) -> Token {
    match answer {
        PreviewAnswer::Previewed {
            token: Some(token), ..
        } => *token,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_token_is_bound_to_its_principal_target_and_parameters() {
    let mut previews = Previews::default();
    let now = Instant::now();
    let close = bound(PreviewKind::Close, 1000, b"halt");
    let answer = previews.preview(close.clone(), open_at(2), now);
    assert!(matches!(
        answer,
        PreviewAnswer::Previewed {
            epoch_after: Some(3),
            state: Some(GuardState {
                epoch: 2,
                open: true
            }),
            ..
        }
    ));
    let token = token(&answer);
    // Each mismatch is refused and keeps the preview for its principal.
    assert_eq!(
        previews.take(
            token,
            &bound(PreviewKind::Close, 1001, b"halt"),
            Some(9),
            now
        ),
        Err(SubmitRefusal::PrincipalMismatch)
    );
    let mut other_guard = close.clone();
    other_guard.guard = 8;
    assert_eq!(
        previews.take(token, &other_guard, Some(9), now),
        Err(SubmitRefusal::TargetMismatch)
    );
    assert_eq!(
        previews.take(
            token,
            &bound(PreviewKind::Reopen, 1000, b"halt"),
            Some(9),
            now
        ),
        Err(SubmitRefusal::TargetMismatch)
    );
    assert_eq!(
        previews.take(
            token,
            &bound(PreviewKind::Close, 1000, b"other"),
            Some(9),
            now
        ),
        Err(SubmitRefusal::ParametersMismatch)
    );
    // The match: the previewed epoch, once.
    assert_eq!(previews.take(token, &close, Some(9), now), Ok(2));
    assert_eq!(
        previews.take(token, &close, Some(9), now),
        Err(SubmitRefusal::TokenUnknown)
    );
}

#[test]
fn a_new_driver_instance_or_an_expired_preview_is_refused() {
    let mut previews = Previews::default();
    let now = Instant::now();
    let close = bound(PreviewKind::Close, 1000, b"");
    let first = token(&previews.preview(close.clone(), open_at(2), now));
    assert_eq!(
        previews.take(first, &close, Some(10), now),
        Err(SubmitRefusal::TargetChanged)
    );
    assert_eq!(
        previews.take(first, &close, Some(9), now),
        Err(SubmitRefusal::TokenUnknown)
    );
    let second = token(&previews.preview(close.clone(), open_at(2), now));
    assert_eq!(
        previews.take(second, &close, Some(9), now + PREVIEW_TTL),
        Err(SubmitRefusal::TokenExpired)
    );
}

/// RR-CON-0008: a state the agent cannot read is unavailable, and so is
/// the token; an operation with nothing to change has no token either.
#[test]
fn an_unknown_state_or_no_change_gives_no_token() {
    let mut previews = Previews::default();
    let now = Instant::now();
    let unknown = Seen {
        instance: 9,
        state: None,
    };
    assert_eq!(
        previews.preview(bound(PreviewKind::Close, 1, b""), unknown, now),
        PreviewAnswer::Previewed {
            kind: PreviewKind::Close,
            guard: 7,
            instance: 9,
            state: None,
            epoch_after: None,
            token: None,
        }
    );
    // A close of a closed guard changes nothing.
    let closed = Seen {
        instance: 9,
        state: Some(GuardState {
            epoch: 3,
            open: false,
        }),
    };
    assert!(matches!(
        previews.preview(bound(PreviewKind::Close, 1, b""), closed, now),
        PreviewAnswer::Previewed {
            token: None,
            epoch_after: None,
            ..
        }
    ));
    assert!(matches!(
        previews.preview(bound(PreviewKind::Reopen, 1, b""), closed, now),
        PreviewAnswer::Previewed {
            epoch_after: Some(4),
            token: Some(_),
            ..
        }
    ));
}

#[test]
fn tokens_are_hex_and_parse_back() {
    let token = Token::fresh().unwrap();
    let hex = token.hex();
    assert_eq!(hex.len(), 32);
    assert_eq!(Token::parse(&hex), Some(token));
    assert_eq!(Token::parse("zz"), None);
    assert_eq!(Token::parse(&"g".repeat(32)), None);
    assert_ne!(Token::fresh().unwrap(), token);
}

#[test]
fn the_newest_transition_gives_the_state() {
    let entry = |guard, after| crate::api::GuardEntry {
        seq: 0,
        time: 0,
        guard,
        before: 0,
        after,
        operation: 0,
        requester_kind: 0,
        requester: 0,
        outcome: 0,
        refusal: 0,
        operator: 0,
        parameters: 0,
    };
    // Words: (2, open) = 5, (3, closed) = 6; an unknown guard's record 0.
    let audit = [entry(7, 5), entry(8, 5), entry(7, 6), entry(7, 0)];
    assert_eq!(
        last_state(&audit, 7),
        Some(GuardState {
            epoch: 3,
            open: false
        })
    );
    assert_eq!(last_state(&audit, 9), None);
}

/// karyos#738: a used id answers its retained outcome to a retry, refuses
/// a conflict, and is a tombstone past `RETAINED` or from before the boot.
#[test]
fn a_used_id_is_retained_then_a_tombstone() {
    use crate::operations::GuardAnswer;
    let mut outcomes = Outcomes::default();
    let close = bound(PreviewKind::Close, 1000, b"halt");
    let answer = GuardAnswer::State {
        operation: 5,
        guard: 7,
        state: GuardState {
            epoch: 3,
            open: false,
        },
    };
    let used = Used {
        kind: PreviewKind::Close,
        dir: Some(close.dir.clone()),
        guard: 7,
        requester: close.requester,
        reason: close.reason.clone(),
    };
    let at = 1_000;
    assert_eq!(outcomes.answer(5, &close, at), None);
    assert_eq!(
        outcomes.answer(0, &close, at),
        Some(Err(SubmitRefusal::OperationConflict))
    );
    outcomes.record(5, used, answer, at);
    assert_eq!(outcomes.answer(5, &close, at + 1), Some(Ok(answer)));
    assert_eq!(
        outcomes.answer(5, &bound(PreviewKind::Reopen, 1000, b"halt"), at + 1),
        Some(Err(SubmitRefusal::OperationConflict))
    );
    let retained = u64::try_from(RETAINED.as_nanos()).unwrap();
    assert_eq!(outcomes.answer(5, &close, at + retained), Some(Ok(answer)));
    assert_eq!(
        outcomes.answer(5, &close, at + retained + 1),
        Some(Err(SubmitRefusal::OperationExpired))
    );
}

/// karyos#738 review: the outcomes are rebuilt from the journal's
/// `Submitted` records only, each with its driver target, its whole reply
/// and its boot. A record of another boot is a tombstone, another target
/// a conflict, and a direct operation's records are no caller id at all.
#[test]
fn outcomes_are_rebuilt_from_submitted_records() {
    use crate::journal::{JournalRecord, Kind, UNKNOWN_OUTCOME};
    use crate::operations::GuardAnswer;
    let close = bound(PreviewKind::Close, 1000, b"halt");
    let used = Used {
        kind: PreviewKind::Close,
        dir: Some(close.dir.clone()),
        guard: 7,
        requester: close.requester,
        reason: close.reason.clone(),
    };
    let boot = b"boot-a".as_slice();
    let state = GuardAnswer::State {
        operation: 1,
        guard: 7,
        state: GuardState {
            epoch: 3,
            open: false,
        },
    };
    let refused = GuardAnswer::Refused {
        operation: 4,
        code: 29,
        detail: 6,
    };
    let records = [
        submitted_record(1, &used, (2, state), (10, boot)),
        submitted_record(
            3,
            &used,
            (2, GuardAnswer::NoAnswer { operation: 3 }),
            (13, boot),
        ),
        submitted_record(4, &used, (2, refused), (16, boot)),
        submitted_record(5, &used, (2, state), (17, b"boot-b".as_slice())),
        // A direct close's records: no caller id.
        JournalRecord::new(Kind::CloseOutcome, 18),
    ];
    // The records round-trip the journal's encoding.
    for record in &records {
        assert_eq!(
            JournalRecord::decode(&record.encode()).as_ref(),
            Some(record)
        );
    }
    assert_eq!(records[1].code, UNKNOWN_OUTCOME);
    let outcomes = Outcomes::rebuild(&records, (100, boot));
    let mut ids: Vec<u64> = outcomes.ids().collect();
    ids.sort_unstable();
    assert_eq!(ids, [1, 3, 4, 5]);
    assert_eq!(outcomes.answer(1, &close, 100), Some(Ok(state)));
    assert_eq!(
        outcomes.answer(3, &close, 100),
        Some(Ok(GuardAnswer::NoAnswer { operation: 3 }))
    );
    // The whole refusal, its detail included.
    assert_eq!(outcomes.answer(4, &close, 100), Some(Ok(refused)));
    // Another boot's: a tombstone, whatever its monotonic time.
    assert_eq!(
        outcomes.answer(5, &close, 100),
        Some(Err(SubmitRefusal::OperationExpired))
    );
    // The same id on another driver: a conflict.
    let mut elsewhere = close.clone();
    elsewhere.dir = PathBuf::from("/other");
    assert_eq!(
        outcomes.answer(1, &elsewhere, 100),
        Some(Err(SubmitRefusal::OperationConflict))
    );
    // No boot identity: nothing is taken for this boot's.
    let unknown = Outcomes::rebuild(&records, (100, b"".as_slice()));
    assert_eq!(
        unknown.answer(1, &close, 100),
        Some(Err(SubmitRefusal::OperationExpired))
    );
}

/// karyos#738 review: a guard closed at the last epoch can never reopen,
/// so a reopen preview there gives no epoch after and no token.
#[test]
fn no_reopen_is_previewed_past_the_last_epoch() {
    let mut previews = Previews::default();
    let last = Seen {
        instance: 9,
        state: Some(GuardState {
            epoch: karyos_sys::guard::MAX_EPOCH,
            open: false,
        }),
    };
    assert!(matches!(
        previews.preview(bound(PreviewKind::Reopen, 1, b""), last, Instant::now()),
        PreviewAnswer::Previewed {
            epoch_after: None,
            token: None,
            ..
        }
    ));
}
