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
    let end = buffer.reserved_head().load(Ordering::Acquire);
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
    assert_eq!(buffer.limit().load(Ordering::Acquire), 0, "the limit stays zero");
    assert_eq!(conductor.seal_state(), SealState::Retired { position: end });
    for _ in 0..2 {
        assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: end, reason: SealReason::Unspecified });
    }
    assert!(publication.close_if_sealed().is_some());
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
    assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 96, reason: SealReason::Unspecified });
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
    assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 96, reason: SealReason::Unspecified });
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
            assert!(publication.close_if_sealed().is_some());
        }
        let _ = conductor.duty_cycle().unwrap();
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Aborted {
                position: 0,
                extent: 96,
            }
        );
        assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 96, reason: SealReason::Unspecified });
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
    assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 0, reason: SealReason::Unspecified });
    // Issuance after the seal is refused, and the publication is spent.
    assert!(matches!(buffer.publication(), Err(SysError::Sealed)));
    assert!(buffer.publication().unwrap().is_none());

    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication.append(&message(2), AppendOptions::default()).unwrap();
    let end = buffer.reserved_head().load(Ordering::Acquire);
    conductor.seal().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Sealed);
    drop(publication);
    let _ = conductor.duty_cycle().unwrap();
    // No subscriber is attached: positioned is already retired.
    assert_eq!(conductor.seal_state(), SealState::Retired { position: end });
}

#[test]
fn a_cutover_seal_marks_its_successor_and_positioning_keeps_the_mark() {
    for cutover in [false, true] {
        let buffer = new_buffer(config(3, 2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        assert!(matches!(
            publication.append(&message(0), AppendOptions::default()).unwrap(),
            AppendOutcome::Appended { .. }
        ));
        let end = buffer.reserved_head().load(Ordering::Acquire);
        assert!(!buffer.sealed_with_successor());
        assert_eq!(buffer.terminal_seal(), None);
        if cutover {
            conductor.seal_for_cutover().unwrap();
        } else {
            conductor.seal().unwrap();
        }
        assert_eq!(conductor.seal_state(), SealState::Sealed);
        assert_eq!(buffer.sealed_with_successor(), cutover);
        // Terminal only without a successor; no position yet.
        let terminal = |position| (!cutover).then_some((SealReason::Unspecified, position));
        assert_eq!(buffer.terminal_seal(), terminal(None));
        drop(publication);
        let _ = conductor.duty_cycle().unwrap();
        // The position is the same either way; the mark survives it.
        assert_eq!(conductor.seal_state(), SealState::Retired { position: end });
        assert_eq!(buffer.sealed_with_successor(), cutover);
        assert_eq!(buffer.terminal_seal(), terminal(Some(end)));
        // A later seal of either kind changes nothing.
        conductor.seal().unwrap();
        conductor.seal_for_cutover().unwrap();
        assert_eq!(buffer.sealed_with_successor(), cutover);
    }
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
    let positioned = buffer.seal().load(Ordering::Acquire);
    conductor.seal().unwrap();
    assert_eq!(buffer.seal().load(Ordering::Acquire), positioned);
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
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), TERM);
    conductor.seal().unwrap();
    assert_eq!(
        publication.append(&data, AppendOptions::default()).unwrap(),
        AppendOutcome::Closed
    );
    let _ = conductor.duty_cycle().unwrap();
    let (rest, end) = drain_to_end(&mut subscription);
    assert!(read + rest > 0);
    assert_eq!(end, PollOutcome::Closed { position: TERM, reason: SealReason::Unspecified });
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
    let end = buffer.reserved_head().load(Ordering::Acquire);
    conductor.seal().unwrap();
    assert!(publication.close_if_sealed().is_some());
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Positioned { position: end });
    assert_eq!(drain_to_end(&mut reader), (1, PollOutcome::Closed { position: end, reason: SealReason::Unspecified }));
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
    assert!(!buffer.publisher_words().all(crate::publication::publisher_slot_free));
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
    assert_eq!(drain_to_end(&mut subscription), (2, PollOutcome::Closed { position: end, reason: SealReason::Unspecified }));
    assert_eq!(conductor.seal_state(), SealState::Retired { position: end });
    // The head stays at the seal position across duty cycles.
    assert_eq!(buffer.head().unwrap(), Some(end));
    assert!(b.close_if_sealed().is_some());
    // Released slots and loans; a closed handle's drop does nothing more.
    assert!(buffer.publisher_words().all(crate::publication::publisher_slot_free));
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
    assert_eq!(poll(&mut subscription), PollOutcome::Closed { position: 96, reason: SealReason::Unspecified });
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
    assert_eq!(end, PollOutcome::Closed { position: TERM, reason: SealReason::Unspecified });
}

#[test]
fn close_if_sealed_does_nothing_on_an_active_buffer() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    assert!(handle.close_if_sealed().is_none());
    let exclusive = new_buffer(config(3, 2)).unwrap();
    let mut publication = exclusive.publication().unwrap().unwrap();
    assert!(publication.close_if_sealed().is_none());
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
    assert_eq!(drain_to_end(&mut subscription), (1, PollOutcome::Closed { position: end, reason: SealReason::Unspecified }));
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
        (1, PollOutcome::Closed { position: reserved, reason: SealReason::Unspecified })
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
                    PollOutcome::Closed { position: reserved, reason: SealReason::Unspecified }
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
        crate::publication::active_term_count(buffer.active_count().load(Ordering::Acquire)),
        0
    );
    let (_, end) = drain_to_end(&mut subscription);
    assert_eq!(end, PollOutcome::Closed { position: TERM, reason: SealReason::Unspecified });
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

#[test]
fn the_fenced_term_is_never_reclaimed_while_it_is_the_active_count() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let data = sized_message(1, 3000);
    let mut sealed = false;
    while !sealed {
        let outcome = handle
            .offer_pausing(&data, AppendOptions::default(), &mut |point| {
                if point == WriterPause::PadCommit {
                    conductor.seal().unwrap();
                    sealed = true;
                }
            })
            .unwrap();
        if !sealed {
            assert!(!matches!(outcome, ConcurrentOfferOutcome::Closed));
        }
        let _ = drain_to_end(&mut subscription);
        let _ = conductor.duty_cycle().unwrap();
    }
    // The required reader reaches the seal at the term end, so the floor
    // is that end; the fenced term is still the active count.
    let (_, end) = drain_to_end(&mut subscription);
    assert_eq!(end, PollOutcome::Closed { position: TERM, reason: SealReason::Unspecified });
    for _ in 0..3 {
        let _ = conductor.duty_cycle().unwrap();
    }
    let Lookup::Slot(slot) = buffer.lookup(TermCount::ZERO).unwrap() else {
        panic!("term 0 has no slot");
    };
    let found = Descriptor::decode(buffer.descriptor(slot).unwrap().load(Ordering::Acquire)).unwrap();
    assert_eq!(found.state(), SlotState::Active);
}

/// Every reason recorded by `seal_with_reason` reaches the reader at the
/// seal position, the closed publisher and the conductor.
#[test]
fn a_seal_reason_reaches_readers_publishers_and_the_conductor() {
    for reason in [
        SealReason::Unspecified,
        SealReason::RequiredParticipantLost,
        SealReason::ConflationVersionsExhausted,
        SealReason::StreamRemoved,
        SealReason::ConflationFeederLost,
        SealReason::ImageRetired,
        SealReason::EndOfStream,
    ] {
        let buffer = new_buffer(config(3, 2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Required).unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        assert!(matches!(
            publication.append(&message(0), AppendOptions::default()).unwrap(),
            AppendOutcome::Appended { .. }
        ));
        assert_eq!(conductor.seal_reason(), None);
        assert_eq!(publication.seal_reason(), None);
        conductor.seal_with_reason(reason).unwrap();
        assert_eq!(conductor.seal_reason(), Some(reason));
        // Open until it observes the seal.
        assert_eq!(publication.seal_reason(), None);
        assert_eq!(
            publication.append(&message(1), AppendOptions::default()).unwrap(),
            AppendOutcome::Closed
        );
        assert_eq!(publication.seal_reason(), Some(reason));
        let _ = conductor.duty_cycle().unwrap();
        let end = buffer.reserved_head().load(Ordering::Acquire);
        assert_eq!(
            drain_to_end(&mut subscription),
            (1, PollOutcome::Closed { position: end, reason })
        );
        assert_eq!(buffer.terminal_seal(), Some((reason, Some(end))));
        assert_eq!(SealReason::from_code(reason.code()), reason);
    }
    // A code this build does not know reads as unspecified.
    assert_eq!(SealReason::from_code(99), SealReason::Unspecified);
}

/// The first final seal decides the reason, even with none; a cutover
/// seal is not terminal and has none.
#[test]
fn the_first_final_seal_decides_the_reason_and_a_cutover_seal_has_none() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    conductor
        .seal_with_reason(SealReason::RequiredParticipantLost)
        .unwrap();
    conductor.seal_with_reason(SealReason::StreamRemoved).unwrap();
    conductor.seal().unwrap();
    assert_eq!(
        conductor.seal_reason(),
        Some(SealReason::RequiredParticipantLost)
    );

    // The check is on the seal word: a first seal with no reason leaves
    // the reason word at 0, and a later reason is not written after a
    // swap a reader may already have observed.
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    conductor.seal().unwrap();
    conductor
        .seal_with_reason(SealReason::RequiredParticipantLost)
        .unwrap();
    assert_eq!(conductor.seal_reason(), Some(SealReason::Unspecified));

    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    conductor.seal_for_cutover().unwrap();
    assert_eq!(conductor.seal_state(), SealState::Sealed);
    assert_eq!(conductor.seal_reason(), None);
    // A later terminal seal does not overwrite the cutover's.
    conductor.seal_with_reason(SealReason::StreamRemoved).unwrap();
    assert_eq!(conductor.seal_reason(), None);
}

/// A guard close, a missed deadline or a schedule violation seals with a
/// gate reason: the
/// publication reports `Gated`, never `Closed`, on every later attempt, and
/// `close_if_sealed` returns the reason (guards-and-abort.md, GC-8).
#[test]
fn a_gate_seal_reports_gated() {
    for reason in [
        SealReason::GuardClosed,
        SealReason::DeadlineMissed,
        SealReason::ScheduleViolation,
    ] {
        let buffer = new_buffer(config(3, 2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let _subscription = conductor.subscribe(Role::Optional).unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        conductor.seal_with_reason(reason).unwrap();
        for _ in 0..2 {
            assert_eq!(
                publication.append(&message(9), AppendOptions::default()).unwrap(),
                AppendOutcome::Gated,
                "{reason:?}"
            );
            assert!(matches!(
                publication.try_claim(8, AppendOptions::default()).unwrap(),
                ClaimOutcome::Gated
            ));
        }
        assert_eq!(publication.close_if_sealed(), Some(reason));
        assert_eq!(publication.seal_reason(), Some(reason));
        assert!(reason.is_gate());
    }
}

/// Any other reason keeps `Closed`, and `close_if_sealed` returns it.
#[test]
fn a_non_gate_seal_reports_closed() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    conductor
        .seal_with_reason(SealReason::RequiredParticipantLost)
        .unwrap();
    assert_eq!(
        publication.append(&message(9), AppendOptions::default()).unwrap(),
        AppendOutcome::Closed
    );
    assert_eq!(
        publication.close_if_sealed(),
        Some(SealReason::RequiredParticipantLost)
    );
    assert!(!SealReason::RequiredParticipantLost.is_gate());
}

/// The reason codes are stable, and an unknown code reads `Unspecified`.
#[test]
fn seal_reason_codes_round_trip() {
    for (reason, code) in [
        (SealReason::Unspecified, 0),
        (SealReason::RequiredParticipantLost, 1),
        (SealReason::ConflationVersionsExhausted, 2),
        (SealReason::StreamRemoved, 3),
        (SealReason::ConflationFeederLost, 4),
        (SealReason::GuardClosed, 5),
        (SealReason::DeadlineMissed, 6),
        (SealReason::ImageRetired, 7),
        (SealReason::EndOfStream, 8),
        (SealReason::ScheduleViolation, 9),
    ] {
        assert_eq!(reason.code(), code);
        assert_eq!(SealReason::from_code(code), reason);
    }
    assert!(!SealReason::ImageRetired.is_gate());
    assert!(!SealReason::EndOfStream.is_gate());
    assert!(SealReason::ScheduleViolation.is_gate());
    assert_eq!(SealReason::from_code(10), SealReason::Unspecified);
}

/// A guard close aborts the admitted claim at once, whatever its deadline
/// (`quantstratum-docs: karyos/design/guards-and-abort.md`): the abort wins
/// the block's decision word and the commit reports `Aborted`; with no
/// claim it is `Idle`, and after a commit it is `Resolved`.
#[test]
fn a_guard_close_aborts_the_admitted_claim_at_once() {
    let buffer = new_buffer(LogBufferConfig {
        claim_deadline: 1_000_000,
        ..config(3, 2)
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    assert_eq!(conductor.abort_admitted_claim().unwrap(), ClaimDeadline::Idle);
    let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
    let position = claim.position();
    conductor.seal_with_reason(SealReason::GuardClosed).unwrap();
    assert_eq!(
        conductor.abort_admitted_claim().unwrap(),
        ClaimDeadline::Aborted {
            position,
            extent: 96,
        }
    );
    claim.payload().fill(7);
    assert_eq!(claim.commit(), CommitOutcome::Aborted { position });
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position,
            extent: 96,
        }
    );
}

#[test]
fn a_committed_claim_is_not_aborted_by_a_guard_close() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
    let position = claim.position();
    claim.payload().fill(7);
    assert!(matches!(claim.commit(), CommitOutcome::Committed { .. }));
    // The record is cleared at commit: nothing is admitted any more.
    assert!(matches!(
        conductor.abort_admitted_claim().unwrap(),
        ClaimDeadline::Idle | ClaimDeadline::Resolved
    ));
    let _ = position;
}

/// Review of karyos#207, P1-2: a guard close that seals and aborts while a
/// claim is between its record and its reserved head finds nothing
/// admitted (`Idle`); the driver therefore repeats the abort every duty
/// cycle until the publication releases at the seal, and the repeat wins.
#[test]
fn a_claim_admitted_after_the_close_is_aborted_by_the_repeat() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut first = None;
    let outcome = publication
        .try_claim_pausing(64, AppendOptions::default(), &mut |point| {
            if point == ClaimPause::BeforeHead {
                conductor.seal_with_reason(SealReason::GuardClosed).unwrap();
                first = Some(conductor.abort_admitted_claim().unwrap());
            }
        });
    assert_eq!(first, Some(ClaimDeadline::Idle), "not admitted yet");
    let mut claim = claimed(outcome);
    let position = claim.position();
    assert_eq!(conductor.seal_state(), SealState::Sealed);
    // The driver's repeat on its next duty cycle.
    assert_eq!(
        conductor.abort_admitted_claim().unwrap(),
        ClaimDeadline::Aborted {
            position,
            extent: 96,
        }
    );
    claim.payload().fill(7);
    assert_eq!(claim.commit(), CommitOutcome::Aborted { position });
}

/// A seal reason code this build does not know reads as `Unspecified`, both
/// from the code and from a sealed buffer's reason word, so a reader closes
/// with a typed reason and never fails. This is what a build from before
/// `EndOfStream` (code 8) sees for an image's clean end: a closed lane,
/// with no claim of a clean end.
#[test]
fn an_unknown_seal_reason_reads_as_unspecified() {
    for code in [10, 200, u64::MAX] {
        assert_eq!(SealReason::from_code(code), SealReason::Unspecified);
    }
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    // A newer conductor's code: stored, then a seal that writes no reason
    // of its own.
    buffer.seal_reason_word().store(200, Ordering::Relaxed);
    conductor.seal().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(conductor.seal_reason(), Some(SealReason::Unspecified));
    for _ in 0..2 {
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Closed {
                position: 0,
                reason: SealReason::Unspecified
            }
        );
    }
}

/// karyos#1102: a concurrent buffer sealed with a gate reason reports
/// `Gated` to its handles, offers and claims alike, as an exclusive one
/// does (GC-8); a seal with another reason still reports `Closed`.
#[test]
fn a_concurrent_gate_seal_reports_gated() {
    for (reason, gated) in [
        (SealReason::GuardClosed, true),
        (SealReason::DeadlineMissed, true),
        (SealReason::Unspecified, false),
    ] {
        let buffer = new_buffer(concurrent_config(2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let _subscription = conductor.subscribe(Role::Optional).unwrap();
        let mut handle = conductor.concurrent_publication().unwrap().unwrap();
        conductor.seal_with_reason(reason).unwrap();
        let (offer, claim) = if gated {
            (ConcurrentOfferOutcome::Gated, "Gated")
        } else {
            (ConcurrentOfferOutcome::Closed, "Closed")
        };
        // The first attempt observes the seal; the next answers at once.
        for _ in 0..2 {
            assert_eq!(
                handle.offer(&message(1), AppendOptions::default()).unwrap(),
                offer,
                "{reason:?}"
            );
            let outcome = handle.try_claim(8, AppendOptions::default()).unwrap();
            let name = match outcome {
                ConcurrentClaimOutcome::Gated => "Gated",
                ConcurrentClaimOutcome::Closed => "Closed",
                _ => "other",
            };
            assert_eq!(name, claim, "{reason:?}");
        }
    }
}

/// karyos#1102: a guard close aborts a concurrent buffer's outstanding
/// claim at once, whatever its deadline: `abort_marked_claims` repeated
/// while `waiting` aborts the marked block, and the reader skips it.
#[test]
fn a_guard_close_aborts_concurrent_claims_at_once() {
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
    let mut aborted = 0;
    for _ in 0..4 {
        let report = conductor.abort_marked_claims().unwrap();
        aborted += report.aborted;
        if !report.waiting && aborted > 0 {
            break;
        }
    }
    assert_eq!(aborted, 1, "the marked block, long before its deadline");
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 0,
            extent: 96,
        }
    );
    // Each mode keeps its own call.
    assert!(matches!(
        conductor.abort_admitted_claim(),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    let exclusive = new_buffer(config(6, 4)).unwrap();
    let mut exclusive = exclusive.conductor().unwrap();
    assert!(matches!(
        exclusive.abort_marked_claims(),
        Err(DeadlineError {
            error: SysError::InvalidPublicationMode { .. },
            ..
        })
    ));
}
