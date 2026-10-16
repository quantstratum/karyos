// SPDX-License-Identifier: Apache-2.0

// FrameReader tests in publication mode (`quantstratum-docs:
// karyos/design/frame-level-service.md`, Evidence before merge), included
// once per term backing by `log_buffer.rs` after `common.rs`.

use proptest::prelude::*;

/// Whether the reader's loan word is zero: every call, its errors and early
/// returns included, released the loan it took.
fn fr_loan_released(reader: &FrameReader<&LogBuffer<Terms>>) -> bool {
    let subscription = reader.subscription();
    subscription.buffer().cells()[subscription.cell()]
        .loan
        .load(Ordering::Acquire)
        == 0
}

/// Nothing is committed between a peek and the next serve here, so the
/// peek predicts the step and its charge exactly (aggregate-subscriber.md,
/// AS-1).
fn fr_peek_predicts(peeked: Peek, step: FrameStep) {
    let expected = match step {
        FrameStep::Copied { charge }
        | FrameStep::Complete { charge, .. }
        | FrameStep::Stepped { charge, .. } => Peek::Step { charge },
        FrameStep::Ready => Peek::Ready,
        FrameStep::Pending => Peek::Pending,
        FrameStep::Ended(_) => Peek::Ended,
    };
    assert_eq!(peeked, expected, "peek before {step:?}");
}

/// A message the reader delivered, with the charges of its fragments.
#[derive(Debug, PartialEq, Eq)]
struct FrDelivered {
    bytes: Vec<u8>,
    info: MessageInfo,
    charged: u64,
}

/// Serves `reader` until it has nothing to serve, taking every complete
/// message; checks that a delivered message's charges sum its block's
/// reserved extent.
fn fr_drain(
    reader: &mut FrameReader<&LogBuffer<Terms>>,
    charged: &mut u64,
    out: &mut Vec<FrDelivered>,
) {
    fr_serve(reader, usize::MAX, charged, out);
}

/// At most `calls` calls of `serve_frame`; `charged` carries the charges
/// of a partial message from one call to the next.
fn fr_serve(
    reader: &mut FrameReader<&LogBuffer<Terms>>,
    calls: usize,
    charged: &mut u64,
    out: &mut Vec<FrDelivered>,
) {
    for _ in 0..calls {
        let peeked = reader.peek().unwrap();
        assert!(fr_loan_released(reader));
        let step = reader.serve_frame().unwrap();
        assert!(fr_loan_released(reader));
        fr_peek_predicts(peeked, step);
        match step {
            FrameStep::Copied { charge } => *charged += u64::from(charge),
            FrameStep::Complete { charge, info } => {
                *charged += u64::from(charge);
                assert_eq!(reader.serve_frame().unwrap(), FrameStep::Ready);
                let mut bytes = Vec::new();
                assert!(reader.take(|message, taken| {
                    assert_eq!(taken, info);
                    bytes = message.to_vec();
                }));
                // The cursor moved past the block: its reserved extent.
                let extent = reader.subscription().position() - info.position;
                assert_eq!(*charged, extent, "charges of the message at {}", info.position);
                out.push(FrDelivered {
                    bytes,
                    info,
                    charged: *charged,
                });
                *charged = 0;
            }
            FrameStep::Stepped { charge, .. } => assert_eq!(charge, STEP_CHARGE),
            FrameStep::Pending => return,
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Polls `subscription` until it has nothing, as `FrDelivered` without
/// charges.
fn fr_poll_all(subscription: &mut Subscription<&LogBuffer<Terms>>, out: &mut Vec<FrDelivered>) {
    let mut bytes = vec![0u8; 64 * 1024];
    loop {
        match subscription.poll(&mut bytes).unwrap() {
            PollOutcome::Message {
                position,
                length,
                end_of_stream,
                reserved_value,
                extension,
            } => {
                subscription.acknowledge();
                out.push(FrDelivered {
                    bytes: bytes[..length as usize].to_vec(),
                    info: MessageInfo {
                        position,
                        length,
                        end_of_stream,
                        reserved_value,
                        extension,
                    },
                    charged: 0,
                });
            }
            PollOutcome::Aborted { .. } => {}
            PollOutcome::Pending => return,
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// A message of `length` bytes, fragmented above one MTU.
fn fr_message(sequence: u32, length: usize) -> Vec<u8> {
    (0..length.max(4))
        .map(|i| (i as u8).wrapping_mul(31) ^ (sequence as u8))
        .collect()
}

#[test]
fn a_fragmented_message_is_served_one_frame_per_call() {
    let buffer = new_buffer(config(2, 2)).unwrap();
    let conductor_buffer = &buffer;
    let mut conductor = conductor_buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Required).unwrap());
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = fr_message(1, 5000);
    let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
    let mut copied = 0;
    let info = loop {
        match reader.serve_frame().unwrap() {
            FrameStep::Copied { charge } => {
                copied += 1;
                assert!(charge > 0 && charge <= DEFAULT_MTU);
                // A required reader publishes nothing while it assembles.
                assert_eq!(reader.subscription().acknowledged_position(), 0);
            }
            FrameStep::Complete { info, .. } => break info,
            other => panic!("unexpected {other:?}"),
        }
    };
    assert!(copied >= 3, "5000 bytes take several fragments");
    assert_eq!((info.position, info.length), (0, 5000));
    // Ready charges nothing, again and again, until taken.
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Ready);
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Ready);
    assert!(reader.take(|bytes, _| assert_eq!(bytes, &data[..])));
    assert!(!reader.take(|_, _| panic!("delivered twice")));
    assert!(reader.subscription().acknowledged_position() > 0);
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Pending);
}

#[test]
fn a_panicking_handler_gets_the_message_again() {
    let buffer = new_buffer(config(2, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Required).unwrap());
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = fr_message(2, 3000);
    let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
    while !matches!(reader.serve_frame().unwrap(), FrameStep::Complete { .. }) {}
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reader.take(|_, _| panic!("handler failed"))
    }));
    assert!(failed.is_err());
    assert!(reader.ready());
    assert_eq!(reader.subscription().acknowledged_position(), 0);
    assert!(reader.take(|bytes, _| assert_eq!(bytes, &data[..])));
}

#[test]
fn a_required_reader_revoked_mid_assembly_ends_without_delivery() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let subscription = conductor.subscribe_as(Role::Required, false, 7).unwrap();
    let cell = subscription.cell();
    let mut reader = FrameReader::new(subscription);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = append_retrying(&mut publication, &mut conductor, &fr_message(3, 5000), || {});
    assert!(matches!(
        reader.serve_frame().unwrap(),
        FrameStep::Copied { .. }
    ));
    assert_eq!(
        conductor.revoke_participant(cell, 7, LossPolicy::Abort),
        Ok(Revocation::Sealed)
    );
    let ended = reader.serve_frame().unwrap();
    assert!(matches!(ended, FrameStep::Ended(FrameEnd::Revoked { .. })));
    assert!(fr_loan_released(&reader));
    // Terminal: the same answer again, and nothing to take.
    assert_eq!(reader.serve_frame().unwrap(), ended);
    assert!(!reader.take(|_, _| panic!("delivered after revocation")));
}

#[test]
fn an_uncommitted_interior_fragment_of_a_publication_is_corrupt() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = append_retrying(&mut publication, &mut conductor, &fr_message(4, 3000), || {});
    let FrameStep::Copied { charge } = reader.serve_frame().unwrap() else {
        panic!("expected the first fragment");
    };
    // A peer clears the second fragment's word 0 inside the committed
    // block: never pending, always corrupt, and terminal.
    word0_of_term0(&buffer, charge).store(0, Ordering::Relaxed);
    let error = reader.serve_frame().unwrap_err();
    assert!(matches!(error, SysError::CorruptTerm { .. }), "{error:?}");
    assert!(fr_loan_released(&reader));
    assert_eq!(reader.serve_frame(), Err(error));
}

#[test]
fn a_lapped_optional_reader_discards_its_assembly_and_rejoins() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = append_retrying(&mut publication, &mut conductor, &fr_message(5, 5000), || {});
    assert!(matches!(
        reader.serve_frame().unwrap(),
        FrameStep::Copied { .. }
    ));
    let messages = if cfg!(miri) { 140 } else { 300 };
    for sequence in 0..messages {
        let _ = append_retrying(&mut publication, &mut conductor, &message(sequence), || {});
        let _ = conductor.duty_cycle().unwrap();
    }
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert!(matches!(
        reader.serve_frame().unwrap(),
        FrameStep::Ended(FrameEnd::Overrun { from: 0, resume, .. }) if resume == head
    ));
    // Not terminal: the next message is read whole.
    let _ = append_retrying(&mut publication, &mut conductor, &message(999), || {});
    let mut delivered = Vec::new();
    fr_drain(&mut reader, &mut 0, &mut delivered);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].bytes, message(999));
}

#[test]
fn a_reader_at_the_seal_is_closed() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = append_retrying(&mut publication, &mut conductor, &fr_message(6, 100), || {});
    conductor.seal().unwrap();
    let _ = publication.append(&[1], AppendOptions::default()).unwrap();
    drop(publication);
    let _ = conductor.duty_cycle().unwrap();
    let mut delivered = Vec::new();
    fr_serve(&mut reader, 1, &mut 0, &mut delivered);
    assert_eq!(delivered.len(), 1);
    let closed = reader.serve_frame().unwrap();
    assert!(matches!(closed, FrameStep::Ended(FrameEnd::Closed { .. })), "{closed:?}");
    assert_eq!(reader.serve_frame().unwrap(), closed);
}

/// One step of the equivalence test: append a message of this length, then
/// serve the frame reader this many times.
fn fr_ops() -> impl Strategy<Value = Vec<(usize, usize)>> {
    prop::collection::vec((1usize..6000, 0usize..6), 1..40)
}

proptest! {
    #![proptest_config(if cfg!(miri) {
        ProptestConfig { cases: 2, ..crate::receive::tests_config() }
    } else {
        ProptestConfig { cases: 64, ..ProptestConfig::default() }
    })]

    /// For any log and any split of the work into calls, with appends
    /// between calls, the messages `serve_frame` and `take` deliver, in
    /// order, are those `poll` delivers, and each is charged its block's
    /// reserved extent once.
    #[test]
    fn frame_service_delivers_what_poll_delivers(ops in fr_ops()) {
        let buffer = new_buffer(config(2, 2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut polled = conductor.subscribe(Role::Required).unwrap();
        let mut reader = FrameReader::new(conductor.subscribe(Role::Required).unwrap());
        let mut publication = buffer.publication().unwrap().unwrap();
        let (mut by_poll, mut by_frame) = (Vec::new(), Vec::new());
        let mut charged = 0u64;
        for (sequence, (length, calls)) in ops.iter().enumerate() {
            let data = fr_message(sequence as u32, *length);
            let _ = append_retrying(&mut publication, &mut conductor, &data, || {
                fr_poll_all(&mut polled, &mut by_poll);
                fr_drain(&mut reader, &mut charged, &mut by_frame);
            });
            fr_poll_all(&mut polled, &mut by_poll);
            fr_serve(&mut reader, *calls, &mut charged, &mut by_frame);
        }
        for _ in 0..4 {
            let _ = conductor.duty_cycle().unwrap();
            fr_poll_all(&mut polled, &mut by_poll);
            fr_drain(&mut reader, &mut charged, &mut by_frame);
        }
        let strip = |delivered: &[FrDelivered]| -> Vec<(Vec<u8>, MessageInfo)> {
            delivered.iter().map(|d| (d.bytes.clone(), d.info)).collect()
        };
        prop_assert_eq!(by_frame.len(), ops.len());
        prop_assert_eq!(strip(&by_frame), strip(&by_poll));
    }
}

/// Closed is terminal: once returned, a later call answers it again without
/// reading the term, so a word changed or reused after the seal never turns
/// it into an overrun or an error.
#[test]
fn closed_is_terminal() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = append_retrying(&mut publication, &mut conductor, &fr_message(7, 100), || {});
    conductor.seal().unwrap();
    let _ = publication.append(&[1], AppendOptions::default()).unwrap();
    drop(publication);
    let _ = conductor.duty_cycle().unwrap();
    let mut delivered = Vec::new();
    fr_serve(&mut reader, 1, &mut 0, &mut delivered);
    let closed = reader.serve_frame().unwrap();
    assert!(matches!(closed, FrameStep::Ended(FrameEnd::Closed { .. })), "{closed:?}");
    // A word that reads as corrupt at the reader's position: never read.
    let at = u32::try_from(reader.subscription().position()).unwrap();
    word0_of_term0(&buffer, at).store(u64::MAX, Ordering::Release);
    assert_eq!(reader.serve_frame().unwrap(), closed);
    assert!(fr_loan_released(&reader));
}

/// The retention floor is rechecked after the loan when a message resumes:
/// a floor published past the assembly's start, with the term still
/// active, ends the assembly as an overrun.
#[test]
fn a_floor_past_the_assembly_overruns_it() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = append_retrying(&mut publication, &mut conductor, &fr_message(8, 5000), || {});
    assert!(matches!(reader.serve_frame().unwrap(), FrameStep::Copied { .. }));
    let head = buffer.reserved_head().load(Ordering::Acquire);
    // The term stays active; only the floor moves past the start.
    buffer.floor().store(64, Ordering::Release);
    assert_eq!(
        reader.serve_frame().unwrap(),
        FrameStep::Ended(FrameEnd::Overrun {
            from: 0,
            lost_to: 64,
            resume: head
        })
    );
    assert!(fr_loan_released(&reader));
    assert!(!reader.ready());
}
