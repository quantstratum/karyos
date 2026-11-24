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
