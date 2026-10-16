// SPDX-License-Identifier: Apache-2.0

// FrameReader tests in image mode (`quantstratum-docs:
// karyos/design/frame-level-service.md`, Evidence before merge: resumed
// incomplete messages, skips and equivalence with `poll`), included after
// `receive_owner/tests.rs`, whose helpers they use.

use crate::log_buffer::{FrameEnd, FrameReader, FrameStep, MessageInfo, STEP_CHARGE, Stepped};

/// What a reader produced: a message (its bytes and position) or a skip.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Message { position: u64, bytes: Vec<u8> },
    Skip { position: u64, extent: u32, reason: SkipReason },
    Aborted { position: u64, extent: u32 },
}

/// Serves `reader` at most `calls` times; `charged` carries a partial
/// message's charges across calls, and every delivered message's charges
/// must sum its block's reserved extent.
fn serve(
    reader: &mut FrameReader<&LogBuffer<Terms>>,
    calls: usize,
    charged: &mut u64,
    out: &mut Vec<Seen>,
) {
    for _ in 0..calls {
        match reader.serve_frame().unwrap() {
            FrameStep::Copied { charge } => *charged += u64::from(charge),
            FrameStep::Complete { charge, info } => {
                *charged += u64::from(charge);
                let mut bytes = Vec::new();
                assert!(reader.take(|message, _| bytes = message.to_vec()));
                let extent = reader.subscription().position() - info.position;
                assert_eq!(*charged, extent, "charges of the message at {}", info.position);
                *charged = 0;
                out.push(Seen::Message {
                    position: info.position,
                    bytes,
                });
            }
            FrameStep::Stepped { charge, kind } => {
                let interrupted = matches!(
                    kind,
                    Stepped::Skipped {
                        reason: SkipReason::Interrupted,
                        ..
                    }
                );
                assert_eq!(charge, if interrupted { 0 } else { STEP_CHARGE });
                match kind {
                    Stepped::Skipped {
                        position,
                        extent,
                        reason,
                    } => {
                        // A skip discards the partial message's charges.
                        *charged = 0;
                        out.push(Seen::Skip {
                            position,
                            extent,
                            reason,
                        });
                    }
                    Stepped::Aborted { position, extent } => {
                        out.push(Seen::Aborted { position, extent });
                    }
                    Stepped::Pad { .. } => {}
                }
            }
            FrameStep::Pending => return,
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Everything a required reader's `poll` delivers now, as `Seen`.
fn poll_all(subscription: &mut crate::log_buffer::Subscription<&LogBuffer<Terms>>) -> Vec<Seen> {
    let mut out = Vec::new();
    let mut bytes = vec![0u8; 16 * 1024];
    loop {
        match subscription.poll(&mut bytes).unwrap() {
            PollOutcome::Message {
                position, length, ..
            } => {
                subscription.acknowledge();
                out.push(Seen::Message {
                    position,
                    bytes: bytes[..length as usize].to_vec(),
                });
            }
            PollOutcome::Skipped {
                position,
                extent,
                reason,
            } => out.push(Seen::Skip {
                position,
                extent,
                reason,
            }),
            PollOutcome::Aborted { position, extent } => {
                out.push(Seen::Aborted { position, extent });
            }
            PollOutcome::Pending => return out,
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Adjacent skips of a run without BEGIN merged: such a run ends at the
/// first uncommitted frame, so a reader that came earlier skips it in
/// several pieces.
fn merged(seen: Vec<Seen>) -> Vec<Seen> {
    let mut out: Vec<Seen> = Vec::new();
    for item in seen {
        if let (
            Some(Seen::Skip {
                position,
                extent,
                reason,
            }),
            Seen::Skip {
                position: next,
                extent: more,
                reason: SkipReason::Orphan | SkipReason::JoinedMidMessage,
            },
        ) = (out.last_mut(), &item)
            && matches!(reason, SkipReason::Orphan | SkipReason::JoinedMidMessage)
            && *position + u64::from(*extent) == *next
        {
            *extent += more;
            continue;
        }
        out.push(item);
    }
    out
}

#[test]
fn an_incomplete_message_resumes_at_its_first_missing_fragment() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut owner = owner(&buffer);
    let parts = [
        fragment(0, 0, 32, true, false, 1),
        fragment(0, 64, 32, false, false, 2),
        fragment(0, 128, 32, false, true, 3),
    ];
    // END first: nothing to serve at the block start.
    assert_eq!(recv(&mut owner, &parts[2]), committed(128, 64));
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Pending);
    // BEGIN: copied once, then the missing middle is pending and the
    // assembly is kept.
    assert_eq!(recv(&mut owner, &parts[0]), committed(0, 64));
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Copied { charge: 64 });
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Pending);
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Pending);
    // The middle: resumed there, never from BEGIN.
    assert_eq!(recv(&mut owner, &parts[1]), committed(64, 64));
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Copied { charge: 64 });
    let FrameStep::Complete { charge, info } = reader.serve_frame().unwrap() else {
        panic!("expected the END fragment");
    };
    assert_eq!((charge, info.position, info.length), (64, 0, 96));
    let expected: Vec<u8> = parts.iter().flat_map(|p| p[32..].to_vec()).collect();
    assert!(reader.take(|bytes, _: MessageInfo| assert_eq!(bytes, &expected[..])));
    assert_eq!(reader.subscription().position(), 192);
}

#[test]
fn skips_match_poll_and_discard_the_assembly() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut polled = conductor.subscribe(Role::Required).unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut owner = owner(&buffer);
    let mut seen = Vec::new();
    let mut charged = 0;
    // Interrupted by ABORTED, after the reader copied the BEGIN.
    recv(&mut owner, &fragment(0, 0, 32, true, false, 1)).unwrap();
    serve(&mut reader, 4, &mut charged, &mut seen);
    assert_eq!(charged, 64, "the BEGIN was copied");
    recv(&mut owner, &record(FrameType::Aborted, 0, 64, 64)).unwrap();
    // Interrupted by a new BEGIN.
    recv(&mut owner, &fragment(0, 128, 32, true, false, 2)).unwrap();
    recv(&mut owner, &fragment(0, 192, 32, true, true, 3)).unwrap();
    // Over the bound: six full fragments reserve more than TERM / 8.
    let full = 1408 - 32;
    for i in 0..6u32 {
        let bytes = fragment(0, 256 + i * 1408, full, i == 0, false, i as u8);
        recv(&mut owner, &bytes).unwrap();
        serve(&mut reader, 2, &mut charged, &mut seen);
    }
    // No END before the term end.
    let tail = 256 + 6 * 1408;
    recv(&mut owner, &record(FrameType::Aborted, 0, tail, TERM - 128 - tail)).unwrap();
    recv(&mut owner, &fragment(0, TERM - 128, 96, true, false, 4)).unwrap();
    recv(&mut owner, &data(1, 0, 64, 5)).unwrap();
    serve(&mut reader, usize::MAX, &mut charged, &mut seen);
    let polled = poll_all(&mut polled);
    assert_eq!(seen, polled);
    let reasons: Vec<SkipReason> = seen
        .iter()
        .filter_map(|item| match item {
            Seen::Skip { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect();
    assert_eq!(
        reasons,
        [
            SkipReason::Interrupted,
            SkipReason::Interrupted,
            SkipReason::MessageTooLarge,
            SkipReason::MissingEnd
        ]
    );
}

#[test]
fn a_reader_joined_mid_message_skips_the_rest() {
    let buffer = image(64);
    let mut conductor = buffer.conductor().unwrap();
    let mut polled = conductor.subscribe(Role::Required).unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut owner = owner(&buffer);
    recv(&mut owner, &fragment(0, 64, 32, false, true, 1)).unwrap();
    recv(&mut owner, &fragment(0, 128, 32, true, true, 2)).unwrap();
    // A later orphan is a peer fault.
    recv(&mut owner, &fragment(0, 192, 32, false, true, 3)).unwrap();
    let mut seen = Vec::new();
    serve(&mut reader, usize::MAX, &mut 0, &mut seen);
    assert_eq!(seen, poll_all(&mut polled));
    assert!(matches!(
        seen[..],
        [
            Seen::Skip {
                reason: SkipReason::JoinedMidMessage,
                ..
            },
            Seen::Message { position: 128, .. },
            Seen::Skip {
                reason: SkipReason::Orphan,
                ..
            }
        ]
    ));
}

/// A run without BEGIN longer than `SKIP_WALK_FRAMES` is several skip
/// steps, each charged `STEP_CHARGE`; together they cover what `poll`
/// skips at once.
#[test]
fn a_long_run_without_begin_is_several_bounded_steps() {
    use crate::log_buffer::SKIP_WALK_FRAMES;
    let buffer = image(64);
    let mut conductor = buffer.conductor().unwrap();
    let mut polled = conductor.subscribe(Role::Required).unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut owner = owner(&buffer);
    let frames = SKIP_WALK_FRAMES as u32 + 6;
    for i in 0..frames {
        recv(&mut owner, &fragment(0, 64 + i * 64, 32, false, false, i as u8)).unwrap();
    }
    let mut seen = Vec::new();
    serve(&mut reader, usize::MAX, &mut 0, &mut seen);
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(matches!(
        seen[0],
        Seen::Skip { extent, .. } if extent == SKIP_WALK_FRAMES as u32 * 64
    ));
    assert_eq!(merged(seen), merged(poll_all(&mut polled)));
}

#[test]
fn a_lapped_image_reader_rejoins_through_the_image_walk() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut owner = owner(&buffer);
    recv(&mut owner, &fragment(0, 0, 32, true, false, 1)).unwrap();
    assert!(matches!(
        reader.serve_frame().unwrap(),
        FrameStep::Copied { .. }
    ));
    // The image moves on by whole terms while the reader holds a partial
    // assembly of term 0.
    recv(&mut owner, &fragment(0, 64, 32, false, true, 2)).unwrap();
    finish(&mut owner, 0, 128);
    conductor.duty_cycle().unwrap();
    while owner.duty() {}
    for count in 1..8u32 {
        let start = u64::from(count) * u64::from(TERM);
        assert_eq!(
            recv(&mut owner, &data(count, 0, 64, count as u8)),
            committed(start, 64)
        );
        finish(&mut owner, count, 64);
        conductor.duty_cycle().unwrap();
        while owner.duty() {}
    }
    let mut ended = None;
    for _ in 0..4 {
        match reader.serve_frame().unwrap() {
            FrameStep::Ended(end @ FrameEnd::Overrun { .. }) => {
                ended = Some(end);
                break;
            }
            FrameStep::Pending => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    let Some(FrameEnd::Overrun { from, resume, .. }) = ended else {
        panic!("the reader was not lapped");
    };
    assert_eq!(from, 0);
    assert!(resume > 0);
}

proptest! {
    #![proptest_config(model_config())]

    /// For any tiling of a term, any arrival order and any split of the
    /// work into calls between arrivals, the frame reader yields what
    /// `poll` yields once every frame arrived, each message charged its
    /// reserved extent once. Some BEGIN flags are dropped, to produce
    /// interrupted messages and runs without BEGIN.
    #[test]
    fn frame_service_matches_poll_on_an_image(
        pieces in tiling(),
        order in prop::collection::vec(any::<prop::sample::Index>(), 1..96),
        orphans in prop::collection::vec(any::<prop::sample::Index>(), 0..4),
        calls in prop::collection::vec(0usize..4, 96),
    ) {
        let mut pieces = pieces;
        for index in orphans {
            let piece = index.get_mut(&mut pieces);
            if let Kind::Data { end, fill, .. } = piece.kind {
                piece.kind = Kind::Data { begin: false, end, fill };
            }
        }
        let buffer = image(0);
        let mut conductor = buffer.conductor().unwrap();
        let mut polled = conductor.subscribe(Role::Required).unwrap();
        let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
        let mut owner = owner(&buffer);
        let mut seen = Vec::new();
        let mut charged = 0;
        let mut arrivals: Vec<Piece> = order.iter().map(|i| *i.get(&pieces)).collect();
        arrivals.extend(pieces.iter().copied());
        for (piece, calls) in arrivals.into_iter().zip(calls.iter().cycle()) {
            let _ = recv(&mut owner, &piece.bytes());
            serve(&mut reader, *calls, &mut charged, &mut seen);
        }
        serve(&mut reader, usize::MAX, &mut charged, &mut seen);
        prop_assert_eq!(merged(seen), merged(poll_all(&mut polled)));
    }
}
