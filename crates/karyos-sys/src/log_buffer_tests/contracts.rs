// SPDX-License-Identifier: Apache-2.0

// Named contract acceptance tests of SPEC.md §13 (`test_<unit>_<scenario>_
// <expected>`), traced in quantstratum-docs: karyos/`testing/contract-traceability.md`.
// Included once per term backing after `common.rs`.

/// A message of `len` bytes tagged with its writer and sequence, so a
/// reader can tell interleaved or torn fragments apart.
fn tagged_message(writer: u8, sequence: u32, len: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ writer ^ (sequence as u8))
        .collect();
    data[0] = writer;
    data[1..5].copy_from_slice(&sequence.to_le_bytes());
    data
}

/// §13 "Message sizes": 64 KiB terms, MTU 1408, concurrent publication
/// with `EXT` off. 8000 bytes is accepted in six contiguous fragments,
/// 8001 returns `MessageTooLarge`, and multi-fragment messages from two
/// writers at once never interleave and reassemble exactly.
#[test]
fn test_log_buffer_message_sizes_8000_fits_8001_refused_writers_never_interleave() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut first = conductor.concurrent_publication().unwrap().unwrap();
    let mut second = conductor.concurrent_publication().unwrap().unwrap();

    // 8000 bytes: one block of six fragments, contiguous from offset 0.
    let data = tagged_message(1, 0, 8000);
    let position = offer_concurrent(&mut first, &mut conductor, &data, || {});
    assert_eq!(position, 0);
    let fragments = frames(&buffer);
    assert_eq!(fragments.len(), 6);
    assert!(fragments[0].1.flags().begin());
    assert!(fragments.iter().all(|(_, word)| word.frame_length() <= DEFAULT_MTU as i32));
    assert_eq!(poll_message(&mut subscription), Some(data));

    // 8001 bytes is refused before anything is reserved.
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert!(matches!(
        second.offer(&tagged_message(2, 0, 8001), AppendOptions::default()),
        Err(SysError::Layout(LayoutError::MessageTooLarge {
            length: 8001,
            max: 8000
        }))
    ));
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), head);

    // Two writers, each publishing multi-fragment messages at once.
    let per_writer: u32 = if cfg!(miri) { 4 } else { 200 };
    let lengths = [8000usize, 2900, 5000];
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::Acquire) {
                let _ = conductor.duty_cycle().unwrap();
                std::thread::yield_now();
            }
        });
        for (writer, handle) in [(1u8, &mut first), (2u8, &mut second)] {
            scope.spawn(move || {
                for sequence in 1..=per_writer {
                    let data = tagged_message(writer, sequence, lengths[sequence as usize % 3]);
                    loop {
                        match handle.offer(&data, AppendOptions::default()).unwrap() {
                            ConcurrentOfferOutcome::Appended { .. } => break,
                            ConcurrentOfferOutcome::BackPressured
                            | ConcurrentOfferOutcome::AdminAction => std::thread::yield_now(),
                            outcome => panic!("unexpected {outcome:?}"),
                        }
                    }
                }
            });
        }
        let mut next = [1u32, 1u32];
        while next != [per_writer + 1; 2] {
            match poll_message(&mut subscription) {
                Some(message) => {
                    let writer = message[0];
                    let sequence = u32::from_le_bytes(message[1..5].try_into().unwrap());
                    let slot = &mut next[usize::from(writer) - 1];
                    assert_eq!(sequence, *slot, "writer {writer} out of order");
                    let expected =
                        tagged_message(writer, sequence, lengths[sequence as usize % 3]);
                    assert_eq!(message, expected, "torn or interleaved message");
                    *slot += 1;
                }
                None => std::thread::yield_now(),
            }
        }
        done.store(true, Ordering::Release);
    });
}

/// §13 "Cleaner lag": the driver conductor is paused for longer than one
/// term. Rotation returns `AdminAction` and no slot is reused before it is
/// cleaned (every byte read later is intact); normal rotation resumes when
/// the conductor does.
#[test]
fn test_log_buffer_cleaner_lag_rotation_waits_and_resumes_intact() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut expected = Vec::new();
    let mut received = Vec::new();
    let mut sequence = 0u32;
    let next = |sequence: &mut u32| {
        *sequence += 1;
        sized_message(*sequence, 3000)
    };
    // Conductor paused. Flow control is lifted by hand (the conductor that
    // would advance the limit is the one paused), so only rotation can stop
    // the publisher: publish and drain until only AdminAction is left.
    buffer.limit().store(4 * TERM, Ordering::Release);
    let mut admin_in_a_row = 0;
    let mut data = next(&mut sequence);
    for _ in 0..10_000 {
        if admin_in_a_row == 50 {
            break;
        }
        while let Some(message) = poll_message(&mut subscription) {
            received.push(message);
        }
        match publication.append(&data, AppendOptions::default()).unwrap() {
            AppendOutcome::Appended { .. } => {
                expected.push(core::mem::replace(&mut data, next(&mut sequence)));
                admin_in_a_row = 0;
            }
            AppendOutcome::AdminAction => admin_in_a_row += 1,
            outcome => panic!("unexpected {outcome:?}"),
        }
    }
    assert_eq!(admin_in_a_row, 50, "rotation never stopped");
    // More than one term was written while the conductor slept, and the
    // active term count stopped where only the conductor can advance it.
    assert!(expected.len() * 3104 > TERM as usize);
    let stalled = buffer.active_count().load(Ordering::Acquire);
    for _ in 0..10 {
        assert!(matches!(
            publication.append(&data, AppendOptions::default()).unwrap(),
            AppendOutcome::AdminAction
        ));
    }
    assert_eq!(buffer.active_count().load(Ordering::Acquire), stalled);
    // The conductor resumes: rotation continues through several terms.
    let target = expected.len() * 4;
    while expected.len() < target {
        let _ = append_retrying(&mut publication, &mut conductor, &data, || {
            while let Some(message) = poll_message(&mut subscription) {
                received.push(message);
            }
        });
        expected.push(core::mem::replace(&mut data, next(&mut sequence)));
    }
    for _ in 0..100 {
        let _ = conductor.duty_cycle().unwrap();
        while let Some(message) = poll_message(&mut subscription) {
            received.push(message);
        }
    }
    assert!(buffer.active_count().load(Ordering::Acquire) > stalled + 2);
    assert_eq!(received, expected);
}

/// §13 "Registration churn": handles close and register repeatedly while
/// a full term stays unrotated. Each publisher slot makes at most one
/// end-crossing reservation per term, so the tail's offset half stays
/// below 2^31 however long the churn lasts.
#[test]
fn test_log_buffer_registration_churn_one_crossing_per_slot_per_term() {
    let publishers: u8 = 3;
    let buffer = new_buffer(concurrent_config(publishers)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _subscription = conductor.subscribe(Role::Optional).unwrap();
    // Term 0 32 bytes from its end, term 1 not prepared (the driver is
    // behind), and a limit that admits every reservation.
    let t0 = u64::from(buffer.initial_term_id.get());
    buffer
        .tail(0)
        .unwrap()
        .store((t0 << 32) | (TERM - 32), Ordering::Release);
    let t1 = buffer
        .initial_term_id
        .advanced_by(TermCount::try_new(1).unwrap());
    buffer.descriptor(1).unwrap().store(
        Descriptor::new(t1, buffer.generation, SlotState::Free).encode(),
        Ordering::Release,
    );
    buffer
        .table_slot(TermCount::try_new(1).unwrap())
        .unwrap()
        .store(0, Ordering::Release);
    buffer.limit().store(2 * TERM, Ordering::Release);
    let data = vec![5u8; 7000];
    let reservation = u64::from(reserved_of(&data));
    let rounds = if cfg!(miri) { 5 } else { 200 };
    for _ in 0..rounds {
        let mut handles: Vec<_> = (0..publishers)
            .map(|_| conductor.concurrent_publication().unwrap().unwrap())
            .collect();
        for handle in &mut handles {
            for _ in 0..3 {
                assert_eq!(
                    handle.offer(&data, AppendOptions::default()).unwrap(),
                    ConcurrentOfferOutcome::AdminAction
                );
            }
        }
        for handle in handles {
            handle.close();
        }
        let offset = buffer.tail(0).unwrap().load(Ordering::Acquire) & u64::from(u32::MAX);
        // At most one crossing reservation per slot in term 0, ever.
        assert!(offset <= TERM - 32 + u64::from(publishers) * reservation);
        assert!(offset < 1 << 31);
    }
    // Term 0 was never rotated while the churn lasted.
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 0);
}

/// §13 "Rotator pause": concurrent publishers at the registration bound;
/// the owner of the term end pauses before committing its padding. The
/// other publisher continues in the next term through a helper, no offer
/// reserves more than once, the tail's offset half stays below 2^31, and
/// readers get the aborted remainder at the deadline.
#[test]
fn test_log_buffer_rotator_pause_others_continue_and_remainder_aborts() {
    let publishers = 2;
    let buffer = new_buffer(deadline_concurrent_config(publishers)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = conductor.concurrent_publication().unwrap().unwrap();
    let mut other = conductor.concurrent_publication().unwrap().unwrap();
    // Every slot is issued: the registration bound.
    assert!(conductor.concurrent_publication().unwrap().is_none());
    let data = vec![3u8; 3000];
    let reserved = reserved_of(&data);
    let tail = |buffer: &LogBuffer<Terms>| buffer.tail(0).unwrap().load(Ordering::Acquire);
    while (tail(&buffer) as u32) + reserved <= MIN_TERM_LENGTH {
        let _ = offer_concurrent(&mut owner, &mut conductor, &data, || {
            while poll_message(&mut subscription).is_some() {}
        });
    }
    while poll_message(&mut subscription).is_some() {}
    let _ = conductor.duty_cycle().unwrap();
    let start = tail(&buffer) as u32;
    let extent = MIN_TERM_LENGTH - start;
    let mut others = Vec::new();
    let outcome = owner
        .offer_pausing(&data, AppendOptions::default(), &mut |point| {
            if point != WriterPause::PadCommit {
                return;
            }
            // The owner crossed and holds the remainder of term 0, paused
            // before its PAD. The other publisher reaches the next term
            // through a helper (here the conductor) and publishes there.
            for attempt in 0..10 {
                match other.offer(&message(attempt), AppendOptions::default()).unwrap() {
                    ConcurrentOfferOutcome::Appended { position } => {
                        assert!(position >= TERM, "published below the paused owner");
                        others.push(message(attempt));
                        if others.len() == 3 {
                            break;
                        }
                    }
                    ConcurrentOfferOutcome::AdminAction | ConcurrentOfferOutcome::BackPressured => {
                        let _ = conductor.duty_cycle().unwrap();
                    }
                    outcome => panic!("unexpected {outcome:?}"),
                }
            }
            assert_eq!(others.len(), 3, "the other publisher never continued");
            // Term 0's tail grew by the crossing reservations only.
            let offset = tail(&buffer) & u64::from(u32::MAX);
            assert!(offset <= u64::from(MIN_TERM_LENGTH + u32::from(publishers) * reserved));
            assert!(offset < 1 << 31);
            // The remainder is aborted at the deadline.
            let mut calls = 0;
            while serve(&mut conductor, 0) != waiting() {
                calls += 1;
                assert!(calls < 10, "the marked PAD was never observed");
            }
            assert_eq!(serve(&mut conductor, DEADLINE), aborted(1, u64::from(extent)));
        })
        .unwrap();
    // The owner's offer made one reservation, the crossing, and reports it.
    assert_eq!(outcome, ConcurrentOfferOutcome::AdminAction);
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: u64::from(start),
            extent,
        }
    );
    for expected in others {
        assert_eq!(poll_message(&mut subscription), Some(expected));
    }
}

/// Drains an optional reader, which may be overrun: it never bounds.
fn drain_optional(subscription: &mut Subscription<&LogBuffer<Terms>>) {
    loop {
        match poll(subscription) {
            PollOutcome::Pending => return,
            PollOutcome::Message { .. } | PollOutcome::Overrun { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// §13 "Required set transitions", the limit part (the `hold`, `continue`
/// and `abort` policies come with P4, and `NotConnected` is the client
/// layer's): without required participants the limit follows
/// `head_snapshot + window` and stays finite; a required participant that
/// joins later bounds the publisher again; when it leaves the limit follows
/// the head again; the limit never decreases.
#[test]
fn test_log_buffer_required_set_transitions_limit_follows_and_never_decreases() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let window = TERM / 2;
    let mut conductor = buffer.conductor().unwrap();
    let mut optional = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut limits = Vec::new();
    let mut sample = |conductor: &mut Conductor<&LogBuffer<Terms>>| {
        let _ = conductor.duty_cycle().unwrap();
        let limit = buffer.limit().load(Ordering::Acquire);
        limits.push(limit);
        limit
    };
    let data = vec![4u8; 1000];
    // Optional readers only: the limit follows the head, finitely, and the
    // publisher is never held back for long.
    for _ in 0..200 {
        let _ = append_retrying(&mut publication, &mut conductor, &data, || {
            drain_optional(&mut optional);
        });
    }
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert_eq!(sample(&mut conductor), head + window);
    // A required subscriber joins and reads nothing: it bounds the
    // publisher at its position plus the window.
    let required = conductor.subscribe(Role::Required).unwrap();
    let joined = buffer.reserved_head().load(Ordering::Acquire);
    let bound = sample(&mut conductor);
    assert_eq!(bound, joined + window);
    let mut back_pressured = false;
    for _ in 0..1000 {
        match publication.append(&data, AppendOptions::default()).unwrap() {
            AppendOutcome::Appended { .. } => {}
            AppendOutcome::AdminAction => {
                let _ = sample(&mut conductor);
            }
            AppendOutcome::BackPressured => {
                back_pressured = true;
                break;
            }
            AppendOutcome::Closed => panic!("not sealed"),
        }
        drain_optional(&mut optional);
    }
    assert!(back_pressured, "the required subscriber never bounded the publisher");
    assert_eq!(sample(&mut conductor), bound);
    assert!(buffer.reserved_head().load(Ordering::Acquire) <= bound);
    // It leaves: the limit follows the head again.
    drop(required);
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert_eq!(sample(&mut conductor), head + window);
    assert!(matches!(
        publication.append(&data, AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { .. }
    ));
    assert!(limits.windows(2).all(|pair| pair[0] <= pair[1]), "{limits:?}");
}
