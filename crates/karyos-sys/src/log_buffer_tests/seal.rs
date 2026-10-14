// SPDX-License-Identifier: Apache-2.0

// Sealing tests (`quantstratum-docs: karyos/design/publication-seal.md`), included once per term
// backing after `common.rs`, whose helpers they use.

/// Polls until the subscription reports something other than a message,
/// returning the messages read and that outcome.
fn drain_to_end(subscription: &mut Subscription<&LogBuffer<Terms>>) -> (u32, PollOutcome) {
    let mut out = vec![0u8; 8192];
    let mut messages = 0;
    loop {
        match subscription.poll(&mut out).unwrap() {
            PollOutcome::Message { .. } => {
                subscription.acknowledge();
                messages += 1;
            }
            other => return (messages, other),
        }
    }
}

#[test]
fn an_exclusive_seal_closes_the_next_attempt_and_positions_at_the_last_block() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    for sequence in 0..3 {
        assert!(matches!(
            publication.append(&message(sequence), AppendOptions::default()).unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    let end = buffer.reserved_head.load(Ordering::Acquire);
    assert_eq!(conductor.seal_state(), SealState::Active);
    conductor.seal().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Sealed);
    // The publisher has not released: no position yet, and the reader
    // still reads the backlog and then waits.
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Sealed);
    assert_eq!(drain_to_end(&mut subscription), (3, PollOutcome::Pending));
    for _ in 0..2 {
        assert_eq!(
            publication.append(&message(9), AppendOptions::default()).unwrap(),
            AppendOutcome::Closed
        );
        assert!(matches!(
            publication.try_claim(8, AppendOptions::default()).unwrap(),
            ClaimOutcome::Closed
        ));
    }
    // Released: the loan is gone and the seal is positioned at the end of
    // the last granted block.
    assert_eq!(buffer.cell(0).unwrap().loan.load(Ordering::SeqCst), 0);
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.limit.load(Ordering::Acquire), 0, "the limit stays zero");
    assert_eq!(conductor.seal_state(), SealState::Retired { position: end });
    for _ in 0..2 {
        assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: end });
    }
    assert!(publication.close_if_sealed());
}

#[test]
fn a_claim_in_hand_at_the_seal_commits_and_delays_the_position() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
    claim.payload().fill(7);
    conductor.seal().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
    assert!(matches!(claim.commit(), CommitOutcome::Committed { .. }));
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Sealed);
    assert_eq!(drain_to_end(&mut subscription), (1, PollOutcome::Pending));
    assert_eq!(
        publication.append(&message(1), AppendOptions::default()).unwrap(),
        AppendOutcome::Closed
    );
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 96 });
    assert_eq!(conductor.seal_state(), SealState::Retired { position: 96 });
}

#[test]
fn a_claim_in_hand_at_the_seal_loses_to_the_deadline_below_the_position() {
    // The other side of the commit-time boundary: in the Sealed state the
    // commit is decided by the claim's own compare-exchange alone, and a
    // claim cannot outlive positioning.
    let buffer = new_buffer(LogBufferConfig {
        claim_deadline: 100,
        ..config(3, 2)
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
    let position = claim.position();
    assert_eq!(conductor.abort_expired_claims(0).unwrap(), ClaimDeadline::Waiting);
    conductor.seal().unwrap();
    assert_eq!(
        conductor.abort_expired_claims(100).unwrap(),
        ClaimDeadline::Aborted {
            position,
            extent: 96,
        }
    );
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Sealed, "the claim is outstanding");
    claim.payload().fill(7);
    assert_eq!(claim.commit(), CommitOutcome::Aborted { position });
    assert_eq!(
        publication.append(&message(1), AppendOptions::default()).unwrap(),
        AppendOutcome::Closed
    );
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position,
            extent: 96,
        }
    );
    assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 96 });
}

#[test]
fn a_forgotten_claim_is_aborted_before_closed() {
    for claim_next in [false, true] {
        let buffer = new_buffer(config(3, 2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Optional).unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        core::mem::forget(claimed(publication.try_claim(64, AppendOptions::default())));
        conductor.seal().unwrap();
        if claim_next {
            assert!(matches!(
                publication.try_claim(8, AppendOptions::default()).unwrap(),
                ClaimOutcome::Closed
            ));
        } else {
            assert!(publication.close_if_sealed());
        }
        let _ = conductor.duty_cycle().unwrap();
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Aborted {
                position: 0,
                extent: 96,
            }
        );
        assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 96 });
    }
}

#[test]
fn an_unissued_or_dropped_publication_does_not_delay_the_position() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    conductor.seal().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Retired { position: 0 });
    assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 0 });
    // Issuance after the seal is refused, and the publication is spent.
    assert!(matches!(buffer.publication(), Err(SysError::Sealed)));
    assert!(buffer.publication().unwrap().is_none());

    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication.append(&message(2), AppendOptions::default()).unwrap();
    let end = buffer.reserved_head.load(Ordering::Acquire);
    conductor.seal().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Sealed);
    drop(publication);
    let _ = conductor.duty_cycle().unwrap();
    // No subscriber is attached: positioned is already retired.
    assert_eq!(conductor.seal_state(), SealState::Retired { position: end });
}

#[test]
fn a_second_seal_has_no_effect() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _subscription = conductor.subscribe(Role::Optional).unwrap();
    conductor.seal().unwrap();
    conductor.seal().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Sealed);
    let _ = conductor.duty_cycle().unwrap();
    let positioned = buffer.seal.load(Ordering::Acquire);
    conductor.seal().unwrap();
    assert_eq!(buffer.seal.load(Ordering::Acquire), positioned);
}

#[test]
fn the_position_after_a_term_crossing_is_the_next_term_start() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = sized_message(1, 3000);
    let mut read = 0;
    loop {
        match publication.append(&data, AppendOptions::default()).unwrap() {
            AppendOutcome::Appended { .. } => {}
            AppendOutcome::AdminAction => break,
            other => panic!("unexpected {other:?}"),
        }
        read += drain_to_end(&mut subscription).0;
        let _ = conductor.duty_cycle().unwrap();
    }
    // The crossing padded the term: the head is the next term's start.
    assert_eq!(buffer.reserved_head.load(Ordering::Acquire), TERM);
    conductor.seal().unwrap();
    assert_eq!(
        publication.append(&data, AppendOptions::default()).unwrap(),
        AppendOutcome::Closed
    );
    let _ = conductor.duty_cycle().unwrap();
    let (rest, end) = drain_to_end(&mut subscription);
    assert!(read + rest > 0);
    assert_eq!(end, PollOutcome::Closed { position: TERM });
    assert_eq!(conductor.seal_state(), SealState::Retired { position: TERM });
}

#[test]
fn retirement_waits_for_attached_subscribers_only() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = conductor.subscribe(Role::Required).unwrap();
    let lagging = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication.append(&message(3), AppendOptions::default()).unwrap();
    let end = buffer.reserved_head.load(Ordering::Acquire);
    conductor.seal().unwrap();
    assert!(publication.close_if_sealed());
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Positioned { position: end });
    assert_eq!(drain_to_end(&mut reader), (1, PollOutcome::Closed { position: end }));
    assert_eq!(conductor.seal_state(), SealState::Positioned { position: end });
    drop(lagging);
    assert_eq!(conductor.seal_state(), SealState::Retired { position: end });
}

#[test]
fn a_concurrent_seal_is_positioned_at_once_and_handles_close() {
    let buffer = new_buffer(concurrent_config(3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut a = conductor.concurrent_publication().unwrap().unwrap();
    let mut b = conductor.concurrent_publication().unwrap().unwrap();
    for handle in [&mut a, &mut b] {
        assert!(matches!(
            handle.offer(&message(5), AppendOptions::default()).unwrap(),
            ConcurrentOfferOutcome::Appended { .. }
        ));
    }
    let end = buffer.head().unwrap().unwrap();
    conductor.seal().unwrap();
    // The fence positions the seal with both handles still holding.
    assert_eq!(conductor.seal_state(), SealState::Positioned { position: end });
    assert!(!buffer.publishers.iter().all(crate::publication::publisher_slot_free));
    assert!(matches!(
        conductor.concurrent_publication(),
        Err(SysError::Sealed)
    ));
    assert_eq!(
        a.offer(&message(6), AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Closed
    );
    assert!(matches!(
        a.try_claim(8, AppendOptions::default()).unwrap(),
        ConcurrentClaimOutcome::Closed
    ));
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(drain_to_end(&mut subscription), (2, PollOutcome::Closed { position: end }));
    assert_eq!(conductor.seal_state(), SealState::Retired { position: end });
    // The head stays at the seal position across duty cycles.
    assert_eq!(buffer.head().unwrap(), Some(end));
    assert!(b.close_if_sealed());
    // Released slots and loans; a closed handle's drop does nothing more.
    assert!(buffer.publishers.iter().all(crate::publication::publisher_slot_free));
    drop(a);
    drop(b);
}

#[test]
fn a_concurrent_forgotten_claim_is_aborted_before_closed() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let ConcurrentClaimOutcome::Claimed(claim) =
        handle.try_claim(64, AppendOptions::default()).unwrap()
    else {
        panic!("not claimed");
    };
    core::mem::forget(claim);
    conductor.seal().unwrap();
    assert_eq!(
        handle.offer(&message(1), AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Closed
    );
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 0,
            extent: 96,
        }
    );
    assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 96 });
}

#[test]
fn a_concurrent_seal_after_a_crossing_positions_at_the_next_term() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let data = sized_message(1, 3000);
    loop {
        match handle.offer(&data, AppendOptions::default()).unwrap() {
            ConcurrentOfferOutcome::Appended { .. } => {}
            ConcurrentOfferOutcome::AdminAction => break,
            other => panic!("unexpected {other:?}"),
        }
        let _ = drain_to_end(&mut subscription);
        let _ = conductor.duty_cycle().unwrap();
    }
    conductor.seal().unwrap();
    assert_eq!(
        handle.offer(&data, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Closed
    );
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Positioned { position: TERM });
    let (_, end) = drain_to_end(&mut subscription);
    assert_eq!(end, PollOutcome::Closed { position: TERM });
}

#[test]
fn close_if_sealed_does_nothing_on_an_active_buffer() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    assert!(!handle.close_if_sealed());
    let exclusive = new_buffer(config(3, 2)).unwrap();
    let mut publication = exclusive.publication().unwrap().unwrap();
    assert!(!publication.close_if_sealed());
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Active);
    assert!(matches!(
        handle.offer(&message(1), AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { .. }
    ));
}

// The concurrent fence (`quantstratum-docs: karyos/design/mapping-generations.md`).

#[test]
fn a_reservation_admitted_before_the_fence_lands_past_the_end_and_closes() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    assert!(matches!(
        handle.offer(&message(1), AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { .. }
    ));
    let end = buffer.head().unwrap().unwrap();
    // The limit admitted the next offer; the fence comes before its
    // `fetch_add`, which then lands past the end and holds nothing.
    let outcome = handle
        .offer_pausing(&message(2), AppendOptions::default(), &mut |point| {
            if point == WriterPause::Reserve {
                conductor.seal().unwrap();
            }
        })
        .unwrap();
    assert_eq!(outcome, ConcurrentOfferOutcome::Closed);
    assert_eq!(conductor.seal_state(), SealState::Positioned { position: end });
    assert_eq!(buffer.head().unwrap(), Some(end));
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(drain_to_end(&mut subscription), (1, PollOutcome::Closed { position: end }));
}

#[test]
fn a_reservation_granted_before_the_fence_commits_below_the_position() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let reserved = u64::from(reserved_of(&message(1)));
    // Granted, then the seal is positioned before the writer marks.
    let outcome = handle
        .offer_pausing(&message(1), AppendOptions::default(), &mut |point| {
            if point == WriterPause::Mark {
                conductor.seal().unwrap();
                assert_eq!(
                    conductor.seal_state(),
                    SealState::Positioned { position: reserved }
                );
            }
        })
        .unwrap();
    assert!(matches!(outcome, ConcurrentOfferOutcome::Appended { .. }));
    assert_eq!(
        handle.offer(&message(2), AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Closed
    );
    assert_eq!(
        drain_to_end(&mut subscription),
        (1, PollOutcome::Closed { position: reserved })
    );
}

#[test]
fn a_paused_zero_span_below_the_position_is_aborted_by_the_deadline() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let reserved = u64::from(reserved_of(&message(1)));
    let outcome = handle
        .offer_pausing(&message(1), AppendOptions::default(), &mut |point| {
            if point == WriterPause::Mark {
                conductor.seal().unwrap();
                // Readers wait at the paused writer's zero span.
                assert_eq!(poll(&mut subscription), PollOutcome::Pending);
                assert_eq!(serve(&mut conductor, 0), waiting());
                assert_eq!(serve(&mut conductor, DEADLINE), aborted(1, reserved));
                assert_eq!(
                    poll(&mut subscription),
                    PollOutcome::Aborted {
                        position: 0,
                        extent: reserved as u32,
                    }
                );
                assert_eq!(
                    poll(&mut subscription),
                    PollOutcome::Closed { position: reserved }
                );
            }
        })
        .unwrap();
    assert!(matches!(outcome, ConcurrentOfferOutcome::Aborted { .. }));
}

#[test]
fn a_fenced_buffer_never_rotates() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut a = conductor.concurrent_publication().unwrap().unwrap();
    let mut b = conductor.concurrent_publication().unwrap().unwrap();
    let data = sized_message(1, 3000);
    // Fill term 0 until `a` crosses (it pads its remainder) without
    // rotating: the seal comes before any rotation help completes.
    let mut sealed = false;
    while !sealed {
        let outcome = a
            .offer_pausing(&data, AppendOptions::default(), &mut |point| {
                if point == WriterPause::PadCommit {
                    conductor.seal().unwrap();
                    sealed = true;
                }
            })
            .unwrap();
        match outcome {
            ConcurrentOfferOutcome::Appended { .. } | ConcurrentOfferOutcome::BackPressured => {
                let _ = drain_to_end(&mut subscription);
                let _ = conductor.duty_cycle().unwrap();
            }
            // The crossing's own call observes the seal after its `PAD`.
            ConcurrentOfferOutcome::AdminAction | ConcurrentOfferOutcome::Closed => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(conductor.seal_state(), SealState::Positioned { position: TERM });
    for _ in 0..3 {
        let _ = conductor.duty_cycle().unwrap();
        for handle in [&mut a, &mut b] {
            assert_eq!(
                handle.offer(&data, AppendOptions::default()).unwrap(),
                ConcurrentOfferOutcome::Closed
            );
        }
    }
    assert_eq!(
        crate::publication::active_term_count(buffer.active_count.load(Ordering::Acquire)),
        0
    );
    let (_, end) = drain_to_end(&mut subscription);
    assert_eq!(end, PollOutcome::Closed { position: TERM });
}

#[test]
fn a_buffer_carries_its_generation() {
    let generation = Generation::try_new(5).unwrap();
    let config = concurrent_config(2);
    let buffer = new_buffer_with_generation(config, generation).unwrap();
    assert_eq!(buffer.generation(), generation);
    let word = buffer.descriptor(0).unwrap().load(Ordering::Acquire);
    assert_eq!(Descriptor::decode(word).unwrap().generation(), generation);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    assert!(matches!(
        handle.offer(&message(1), AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { .. }
    ));
    assert!(matches!(poll(&mut subscription), PollOutcome::Message { .. }));
    assert!(Generation::try_new(1 << 24).is_err());
}
