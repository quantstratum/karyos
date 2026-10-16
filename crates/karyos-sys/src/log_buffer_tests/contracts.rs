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
    assert_eq!(
        first.offer(&data, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { position: 0 }
    );
    assert_eq!(first.offer_attempt_counts(), (1, 0));
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
    // Every participant stops when any of them ends early (a failed
    // assertion or an unexpected outcome) or when the deadline passes, so a
    // contract violation fails the test instead of hanging it.
    let stop = AtomicBool::new(false);
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(if cfg!(miri) { 3600 } else { 60 });
    let running = || !stop.load(Ordering::Acquire) && std::time::Instant::now() < deadline;
    std::thread::scope(|scope| {
        let stop = &stop;
        scope.spawn(|| {
            let _stop = StopOnDrop(stop);
            while running() {
                let _ = conductor.duty_cycle().unwrap();
                std::thread::yield_now();
            }
        });
        for (writer, handle) in [(1u8, &mut first), (2u8, &mut second)] {
            scope.spawn(move || {
                // Only a writer that ends early stops the others.
                let mut early = Some(StopOnDrop(stop));
                for sequence in 1..=per_writer {
                    let data = tagged_message(writer, sequence, lengths[sequence as usize % 3]);
                    loop {
                        assert!(running(), "writer {writer} stopped before its last offer");
                        match handle.offer(&data, AppendOptions::default()).unwrap() {
                            ConcurrentOfferOutcome::Appended { .. } => break,
                            ConcurrentOfferOutcome::BackPressured
                            | ConcurrentOfferOutcome::AdminAction => std::thread::yield_now(),
                            outcome => panic!("unexpected {outcome:?}"),
                        }
                    }
                }
                core::mem::forget(early.take());
            });
        }
        let _stop = StopOnDrop(stop);
        let mut next = [1u32, 1u32];
        while next != [per_writer + 1; 2] {
            assert!(running(), "messages missing: next {next:?}");
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
    });
}

/// §13 "Concurrent publication": a fragmented reservation aborted after its
/// payload is written remains one extent, even when another writer commits
/// behind it. The reader must not expose the later message through the gap.
#[test]
fn test_log_buffer_aborted_fragmented_offer_with_two_writers_never_interleaves() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut first = conductor.concurrent_publication().unwrap().unwrap();
    let mut second = conductor.concurrent_publication().unwrap().unwrap();
    let first_data = tagged_message(1, 0, 8000);
    let second_data = tagged_message(2, 0, 5000);
    let first_extent = reserved_of(&first_data);
    let (paused_tx, paused_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);

    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            first
                .offer_pausing(
                    &first_data,
                    AppendOptions::default(),
                    &mut |point| {
                        if point == WriterPause::Commit {
                            paused_tx.send(()).unwrap();
                            resume_rx.recv().unwrap();
                        }
                    },
                )
                .unwrap()
        });

        // The first writer has filled every fragment but has not committed
        // the block. A later committed block must remain hidden behind it.
        paused_rx.recv().unwrap();
        assert_eq!(poll_message(&mut subscription), None);
        assert!(matches!(
            second.offer(&second_data, AppendOptions::default()).unwrap(),
            ConcurrentOfferOutcome::Appended { position } if position == u64::from(first_extent)
        ));
        assert_eq!(poll_message(&mut subscription), None);

        // The deadline turns the first reservation into exactly one aborted
        // extent, after which the reader can consume the intact second block.
        assert_eq!(serve(&mut conductor, 0), waiting());
        assert_eq!(
            serve(&mut conductor, DEADLINE),
            aborted(1, u64::from(first_extent))
        );
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Aborted {
                position: 0,
                extent: first_extent,
            }
        );
        assert_eq!(poll_message(&mut subscription), Some(second_data));

        resume_tx.send(()).unwrap();
        assert_eq!(
            writer.join().unwrap(),
            ConcurrentOfferOutcome::Aborted { position: 0 }
        );
    });
}

/// §13 "Concurrent publication": the deadline aborts a fragmented writer
/// paused between fragment copies while a later fragmented writer commits.
#[test]
fn test_log_buffer_aborted_fragmented_offer_mid_copy_with_two_writers_never_interleaves() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut first = conductor.concurrent_publication().unwrap().unwrap();
    let mut second = conductor.concurrent_publication().unwrap().unwrap();
    let first_data = tagged_message(1, 0, 8000);
    let second_data = tagged_message(2, 0, 5000);
    let first_extent = reserved_of(&first_data);
    let (paused_tx, paused_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);

    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            first
                .offer_pausing(
                    &first_data,
                    AppendOptions::default(),
                    &mut |point| {
                        if point == WriterPause::AfterFragment(0) {
                            paused_tx.send(()).unwrap();
                            resume_rx.recv().unwrap();
                        }
                    },
                )
                .unwrap()
        });

        // One fragment is copied. The first word0 is still reserved, so the
        // reader cannot expose this incomplete message.
        paused_rx.recv().unwrap();
        assert_eq!(poll_message(&mut subscription), None);
        assert!(matches!(
            second.offer(&second_data, AppendOptions::default()).unwrap(),
            ConcurrentOfferOutcome::Appended { position } if position == u64::from(first_extent)
        ));
        assert_eq!(poll_message(&mut subscription), None);

        // The deadline publishes one aborted extent, then the reader gets
        // the later writer's intact fragmented message.
        assert_eq!(serve(&mut conductor, 0), waiting());
        assert_eq!(
            serve(&mut conductor, DEADLINE),
            aborted(1, u64::from(first_extent))
        );
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Aborted {
                position: 0,
                extent: first_extent,
            }
        );
        assert_eq!(poll_message(&mut subscription), Some(second_data));

        resume_tx.send(()).unwrap();
        assert_eq!(
            writer.join().unwrap(),
            ConcurrentOfferOutcome::Aborted { position: 0 }
        );
    });
}

/// Negative control for the between-fragments pause: without a deadline,
/// resuming the writer commits the complete message and never exposes a
/// partial prefix.
#[test]
fn test_log_buffer_fragmented_offer_after_fragment_pause_commits_intact() {
    let buffer = new_buffer(deadline_concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = conductor.concurrent_publication().unwrap().unwrap();
    let data = tagged_message(1, 0, 8000);
    let expected = data.clone();
    let (paused_tx, paused_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);

    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            publication
                .offer_pausing(
                    &data,
                    AppendOptions::default(),
                    &mut |point| {
                        if point == WriterPause::AfterFragment(0) {
                            paused_tx.send(()).unwrap();
                            resume_rx.recv().unwrap();
                        }
                    },
                )
                .unwrap()
        });

        paused_rx.recv().unwrap();
        assert_eq!(poll_message(&mut subscription), None);
        resume_tx.send(()).unwrap();
        assert_eq!(
            writer.join().unwrap(),
            ConcurrentOfferOutcome::Appended { position: 0 }
        );
        assert_eq!(poll_message(&mut subscription), Some(expected));
    });
}

/// Sets the flag when dropped: at the end of a participant's scope, also
/// when it unwinds.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// §13 "Cleaner lag": the driver conductor is paused for longer than one
/// term. Rotation returns `AdminAction` and no slot is reused before it is
/// cleaned (every byte read later is intact); normal rotation resumes when
/// the conductor does. While the conductor is paused the descriptors and
/// the slot table are inspected after every append: no slot leaves its
/// term or becomes `FREE`, `READY` or `RECLAIMING`, and the only transition
/// is the publication's own activation of the prepared `READY` slot. After
/// the conductor resumes, a slot takes a new term only once its old term
/// lies wholly below the published floor (it was reclaimed and cleaned).
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
    let descriptors = |buffer: &LogBuffer<Terms>| -> Vec<Descriptor> {
        (0..buffer.slots)
            .map(|slot| {
                Descriptor::decode(buffer.descriptor(slot).unwrap().load(Ordering::Acquire))
                    .unwrap()
            })
            .collect()
    };
    let table = |buffer: &LogBuffer<Terms>| -> Vec<u64> {
        buffer
            .table()
            .iter()
            .map(|entry| entry.load(Ordering::Acquire))
            .collect()
    };
    let paused_descriptors = descriptors(&buffer);
    let paused_table = table(&buffer);
    let check_paused = |buffer: &LogBuffer<Terms>| {
        for (before, now) in paused_descriptors.iter().zip(descriptors(buffer)) {
            let activated = before.state() == SlotState::Ready
                && now == before.with_state(SlotState::Active);
            assert!(
                now == *before || activated,
                "a slot changed while the conductor was paused: {before:?} to {now:?}"
            );
        }
        assert_eq!(table(buffer), paused_table, "the slot table changed");
    };
    let mut admin_in_a_row = 0;
    let mut data = next(&mut sequence);
    for _ in 0..10_000 {
        check_paused(&buffer);
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
    check_paused(&buffer);
    // At the stall no slot holds the next term: nothing was prepared, and
    // no slot was taken for it before being cleaned.
    let next_term = buffer
        .initial_term_id
        .advanced_by(TermCount::try_new(stalled as u32 + 1).unwrap());
    let stalled_descriptors = descriptors(&buffer);
    assert!(
        stalled_descriptors
            .iter()
            .all(|descriptor| descriptor.term_id() != next_term
                || descriptor.state() == SlotState::Free),
        "the next term was prepared without the conductor: {stalled_descriptors:?}"
    );
    assert_eq!(
        stalled_descriptors
            .iter()
            .filter(|descriptor| descriptor.state() == SlotState::Active)
            .count(),
        2,
        "the written terms stay ACTIVE until the conductor reclaims them"
    );
    // The conductor resumes: rotation continues through several terms.
    let target = expected.len() * 4;
    let mut reused = 0u32;
    while expected.len() < target {
        let before = descriptors(&buffer);
        let _ = append_retrying(&mut publication, &mut conductor, &data, || {
            while let Some(message) = poll_message(&mut subscription) {
                received.push(message);
            }
        });
        let floor = buffer.floor().load(Ordering::Acquire);
        for (old, now) in before.iter().zip(descriptors(&buffer)) {
            // A FREE slot was cleaned already; any other slot that takes a
            // new term is reused within this call.
            if old.state() != SlotState::Free && now.term_id() != old.term_id() {
                // Its old term was wholly below the floor, so it was
                // reclaimed and cleaned before the slot was prepared again.
                let count = old.term_id().count_from(buffer.initial_term_id).unwrap();
                assert!(
                    buffer.position(count, buffer.term_length) <= floor,
                    "slot reused for {now:?} while {old:?} was above the floor {floor}"
                );
                reused += 1;
            }
        }
        expected.push(core::mem::replace(&mut data, next(&mut sequence)));
    }
    assert!(reused > 0, "no slot was reused after the conductor resumed");
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
    let mut reservation_seen = false;
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
                let (reservations, rotations) = handle.offer_attempt_counts();
                assert!(reservations <= 1, "one reservation per offer");
                assert!(rotations <= 1, "one rotation attempt per offer");
                if reservations == 1 {
                    assert!(!reservation_seen, "the stalled term has one crossing reservation");
                    reservation_seen = true;
                    assert_eq!((reservations, rotations), (1, 1));
                }
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
    assert!(reservation_seen);
    // Term 0 was never rotated while the churn lasted.
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 0);
}

/// §13 "Delayed rotation": the crossing offer reserves once and tries to
/// rotate once; a later offer retries rotation without another reservation.
#[test]
fn test_log_buffer_delayed_rotation_retries_without_reserving_again() {
    let buffer = new_buffer(concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _subscription = conductor.subscribe(Role::Optional).unwrap();
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
    let mut publication = conductor.concurrent_publication().unwrap().unwrap();
    let data = vec![5u8; 7000];

    assert_eq!(
        publication.offer(&data, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(publication.offer_attempt_counts(), (1, 1));
    assert_eq!(
        publication.offer(&data, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(publication.offer_attempt_counts(), (0, 1));
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
                let outcome = other.offer(&message(attempt), AppendOptions::default()).unwrap();
                match outcome {
                    ConcurrentOfferOutcome::Appended { position } => {
                        assert_eq!(other.offer_attempt_counts(), (1, 0));
                        assert!(position >= TERM, "published below the paused owner");
                        others.push(message(attempt));
                        if others.len() == 3 {
                            break;
                        }
                    }
                    ConcurrentOfferOutcome::AdminAction => {
                        assert_eq!(other.offer_attempt_counts(), (0, 1));
                        let _ = conductor.duty_cycle().unwrap();
                    }
                    ConcurrentOfferOutcome::BackPressured => {
                        assert_eq!(other.offer_attempt_counts(), (0, 0));
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
    assert_eq!(owner.offer_attempt_counts(), (1, 1));
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

/// §13 "Offer that only pads": an exact-fill offer reserves once without
/// rotating; the following offer only requests rotation and reserves nothing.
#[test]
fn test_log_buffer_exact_fill_then_pad_only_offer_has_exact_attempt_counts() {
    let buffer = new_buffer(concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    buffer.limit().store(2 * TERM, Ordering::Release);
    let mut publication = conductor.concurrent_publication().unwrap().unwrap();
    let data = vec![7u8; 8000];

    for index in 0u64..8 {
        assert_eq!(
            publication.offer(&data, AppendOptions::default()).unwrap(),
            ConcurrentOfferOutcome::Appended {
                position: index * 8192,
            }
        );
        assert_eq!(publication.offer_attempt_counts(), (1, 0));
    }
    assert_eq!(buffer.tail(0).unwrap().load(Ordering::Acquire) as u32, TERM as u32);

    assert_eq!(
        publication.offer(&data, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(publication.offer_attempt_counts(), (0, 1));
}

/// The word 0 at `offset` of slot 0, as a reader would load it.
fn slot0_word0(buffer: &LogBuffer<Terms>, offset: u32) -> Word0 {
    // SAFETY: single-threaded test; slot 0 holds the published term.
    Word0::unpack(load_interior(unsafe { buffer.regions.word0(0, offset) })).unwrap()
}

/// §13 "Offer that only pads", immediate rotation on the concurrent path:
/// the offer whose reservation crosses the term end makes exactly one
/// reservation and one rotation attempt, which succeeds at once (the next
/// term is `READY`), and returns `AdminAction`, never `Appended`. The
/// remainder of the term is one committed `PAD` frame up to the term end,
/// read back from the buffer, and a reader crosses it without an abort:
/// it receives exactly the messages reported `Appended`, the crossing
/// offer's payload never.
#[test]
fn test_log_buffer_pad_only_offer_with_immediate_rotation_commits_one_pad() {
    let buffer = new_buffer(concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = conductor.concurrent_publication().unwrap().unwrap();
    // 3104 reserved bytes: never an exact fill of a 64 KiB term.
    let reserved = reserved_of(&tagged_message(1, 0, 3000));
    assert_ne!(MIN_TERM_LENGTH % reserved, 0);
    let mut appended = Vec::new();
    let mut received = Vec::new();
    let mut sequence = 0u32;
    let start = loop {
        // The conductor prepares the next term before the crossing, so the
        // crossing offer's rotation succeeds at once.
        let _ = conductor.duty_cycle().unwrap();
        while let Some(message) = poll_message(&mut subscription) {
            received.push(message);
        }
        let start = buffer.tail(0).unwrap().load(Ordering::Acquire) as u32;
        let data = tagged_message(1, sequence, 3000);
        sequence += 1;
        match publication.offer(&data, AppendOptions::default()).unwrap() {
            ConcurrentOfferOutcome::Appended { position } => {
                assert_eq!(publication.offer_attempt_counts(), (1, 0));
                assert!(position < TERM);
                appended.push(data);
            }
            ConcurrentOfferOutcome::AdminAction => break start,
            outcome => panic!("unexpected {outcome:?}"),
        }
        assert!(sequence < 100, "term 0 never filled");
    };
    // One reservation (the crossing) and one rotation attempt, which
    // succeeded: term 1 is active.
    assert!(start + reserved > MIN_TERM_LENGTH);
    assert_eq!(publication.offer_attempt_counts(), (1, 1));
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    // The remainder is one committed PAD frame up to the term end.
    let pad = slot0_word0(&buffer, start);
    assert_eq!(pad.frame_type_code(), FrameType::Pad.code());
    assert_eq!(pad.frame_length(), (MIN_TERM_LENGTH - start) as i32);
    // The reader reaches the PAD with no abort (`poll_message` panics on
    // any outcome but a message or `Pending`) and receives exactly what was
    // reported Appended.
    while let Some(message) = poll_message(&mut subscription) {
        received.push(message);
    }
    assert_eq!(received, appended);
    // The next message lands at the start of term 1.
    let next = tagged_message(1, sequence, 3000);
    assert_eq!(
        publication.offer(&next, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { position: TERM }
    );
    assert_eq!(publication.offer_attempt_counts(), (1, 0));
    assert_eq!(poll_message(&mut subscription), Some(next));
}

/// §13 "Offer that only pads", delayed rotation on the concurrent path:
/// when the next term is not prepared, the crossing offer still commits
/// its remainder as one `PAD` frame (read back) and returns `AdminAction`
/// rather than `Appended`, after one reservation and one (failed)
/// rotation attempt.
#[test]
fn test_log_buffer_pad_only_offer_with_delayed_rotation_commits_one_pad() {
    let buffer = new_buffer(concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    // Connected, so the offer is not refused as unconnected.
    let _subscription = conductor.subscribe(Role::Optional).unwrap();
    let t0 = u64::from(buffer.initial_term_id.get());
    let start = MIN_TERM_LENGTH - 32;
    buffer
        .tail(0)
        .unwrap()
        .store((t0 << 32) | u64::from(start), Ordering::Release);
    buffer.reserved_head().store(u64::from(start), Ordering::Release);
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
    let mut publication = conductor.concurrent_publication().unwrap().unwrap();

    assert_eq!(
        publication
            .offer(&vec![5u8; 7000], AppendOptions::default())
            .unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(publication.offer_attempt_counts(), (1, 1));
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 0);
    let pad = slot0_word0(&buffer, start);
    assert_eq!(pad.frame_type_code(), FrameType::Pad.code());
    assert_eq!(pad.frame_length(), 32);
}

/// §13 "Immediate offer": one successful append has one reservation and no
/// rotation attempt.
#[test]
fn test_log_buffer_immediate_offer_has_one_reservation_and_no_rotation() {
    let buffer = new_buffer(concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = conductor.concurrent_publication().unwrap().unwrap();

    assert_eq!(
        publication
            .offer(&[9; 32], AppendOptions::default())
            .unwrap(),
        ConcurrentOfferOutcome::Appended { position: 0 }
    );
    assert_eq!(publication.offer_attempt_counts(), (1, 0));

    drop(publication.try_claim(8, AppendOptions::default()).unwrap());
    assert_eq!(publication.offer_attempt_counts(), (1, 0));
}

/// §13 "Required set transitions", the guard itself: the duty cycle never
/// lowers a published limit or floor, even when its own computation gives
/// less. A limit and a floor are published above what the required set
/// yields (as a later transition could, with a bound that moved back); the
/// next duty cycles keep both, and the publisher may use the published
/// limit. Without the `max` guards the limit would fall back to `base +
/// window`.
#[test]
fn test_log_buffer_required_set_a_published_limit_and_floor_are_never_lowered() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let window = TERM / 2;
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = vec![8u8; 1000];
    let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
    while poll_message(&mut required).is_some() {}
    let _ = conductor.duty_cycle().unwrap();
    // The required reader is at the head: the computed limit.
    let computed = buffer.reserved_head().load(Ordering::Acquire) + window;
    assert_eq!(buffer.limit().load(Ordering::Acquire), computed);
    // A limit and a floor above the computation are published.
    let raised = computed + 4096;
    buffer.limit().store(raised, Ordering::Release);
    let floor = buffer.floor().load(Ordering::Acquire);
    buffer.floor().store(floor + 64, Ordering::Release);
    for _ in 0..3 {
        let _ = conductor.duty_cycle().unwrap();
        assert_eq!(
            buffer.limit().load(Ordering::Acquire),
            raised,
            "the duty cycle lowered the published limit"
        );
        assert_eq!(
            buffer.floor().load(Ordering::Acquire),
            floor + 64,
            "the duty cycle lowered the published floor"
        );
    }
}

/// Slots pinned outside the rotation: every slot that is not `FREE` and
/// does not hold the previous, active or next term, in any state.
fn pinned_outside_rotation(buffer: &LogBuffer<Terms>) -> Vec<u8> {
    let active = buffer.active_count().load(Ordering::Acquire) as u32;
    (0..buffer.slots)
        .filter(|slot| {
            let descriptor =
                Descriptor::decode(buffer.descriptor(*slot).unwrap().load(Ordering::Acquire))
                    .unwrap();
            if descriptor.state() == SlotState::Free {
                return false;
            }
            let count = descriptor
                .term_id()
                .count_from(buffer.initial_term_id)
                .unwrap()
                .get();
            count + 1 < active || count > active + 1
        })
        .collect()
}

/// §13 "Required set transitions", the `continue` reservation: a required
/// reader admitted under `continue` (one spare-slot credit) is revoked
/// while it holds a read loan on term 0. Its bound is withdrawn at once and
/// the publisher runs ten terms; at every duty cycle the slots pinned
/// outside the rotation are exactly the reader's term 0 slot, never more
/// than its reservation, and that slot is never cleaned or reused. Once the
/// loan ends the slot is reclaimed and nothing stays pinned.
#[test]
fn test_log_buffer_required_set_continue_pins_only_within_its_reservation() {
    // S = 3, C = 1: the exclusive publication and the reserved reader take
    // the two credits.
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let reader = conductor.subscribe_as(Role::Required, true, 9).unwrap();
    let cell = reader.cell();
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = vec![2u8; 1000];
    let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
    let found = buffer.cells().get(cell).unwrap();
    let target = buffer.target(0, TermCount::ZERO).unwrap();
    assert_eq!(
        take_loan(&found.loan, &found.revoked, buffer.descriptor(0).unwrap(), target),
        Ok(LoanOutcome::Granted)
    );
    assert_eq!(
        conductor.revoke_participant(cell, 9, LossPolicy::Continue),
        Ok(Revocation::Withdrawn)
    );
    let reservation = 1;
    let mut most = 0;
    while buffer.reserved_head().load(Ordering::Acquire) < 10 * TERM {
        let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
        let _ = conductor.duty_cycle().unwrap();
        let pinned = pinned_outside_rotation(&buffer);
        assert!(
            pinned.len() <= reservation,
            "continue pinned {pinned:?}, beyond its reservation of {reservation}"
        );
        assert!(pinned.iter().all(|slot| *slot == 0), "{pinned:?}");
        most = most.max(pinned.len());
    }
    assert_eq!(most, reservation, "the held loan never pinned its slot");
    // Term 0's slot was never cleaned or reused under the loan.
    let held = Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire)).unwrap();
    assert_eq!(held.term_id(), buffer.initial_term_id);
    assert_eq!(held.state(), SlotState::Reclaiming);
    // The loan ends: the slot is reclaimed and nothing stays pinned.
    release_loan(&found.loan);
    for _ in 0..3 {
        let _ = conductor.duty_cycle().unwrap();
    }
    assert!(pinned_outside_rotation(&buffer).is_empty());
    drop(reader);
}

/// §13 "Required set transitions": limits never decrease across the
/// `hold`, `continue` and `abort` transitions. A bounding required reader
/// and a second required reader admitted under the policy read along; the
/// second is revoked mid-stream, holding a loan under `hold`. The limit is
/// sampled after every duty cycle, before and after the revocation, the
/// withdrawal of a held bound and the remaining reader's progress: it
/// never decreases while the publication is open. Under `abort` the
/// revocation seals the publication instead (its limit closes to zero by
/// the seal, not by the required set).
#[test]
fn test_log_buffer_required_set_limits_never_decrease_across_hold_continue_abort() {
    for policy in [LossPolicy::Hold, LossPolicy::Continue, LossPolicy::Abort] {
        let buffer = new_buffer(config(3, 3)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut steady = conductor.subscribe(Role::Required).unwrap();
        let reserve = policy == LossPolicy::Continue;
        let mut lost = conductor.subscribe_as(Role::Required, reserve, 9).unwrap();
        let cell = lost.cell();
        let mut publication = buffer.publication().unwrap().unwrap();
        let data = vec![6u8; 1000];
        let mut limits = Vec::new();
        // Twenty appends, the steady reader draining, a duty cycle and a
        // limit sample each; false once the publication is closed.
        let mut round = |conductor: &mut Conductor<&LogBuffer<Terms>>,
                         steady: &mut Subscription<&LogBuffer<Terms>>,
                         limits: &mut Vec<u64>| {
            for _ in 0..20 {
                if let AppendOutcome::Closed =
                    publication.append(&data, AppendOptions::default()).unwrap()
                {
                    return false;
                }
                while poll_message(steady).is_some() {}
                let _ = conductor.duty_cycle().unwrap();
                limits.push(buffer.limit().load(Ordering::Acquire));
            }
            true
        };
        // Both readers read along.
        for _ in 0..5 {
            assert!(round(&mut conductor, &mut steady, &mut limits));
            while poll_message(&mut lost).is_some() {}
        }
        // The second reader is revoked holding a loan.
        let found = buffer.cells().get(cell).unwrap();
        let count = buffer
            .active_count()
            .load(Ordering::Acquire)
            .try_into()
            .unwrap();
        let slot = buffer
            .table_slot(TermCount::try_new(count).unwrap())
            .unwrap()
            .load(Ordering::Acquire) as u8;
        let target = buffer.target(slot, TermCount::try_new(count).unwrap()).unwrap();
        assert_eq!(
            take_loan(&found.loan, &found.revoked, buffer.descriptor(slot).unwrap(), target),
            Ok(LoanOutcome::Granted)
        );
        let revocation = conductor.revoke_participant(cell, 9, policy).unwrap();
        limits.push(buffer.limit().load(Ordering::Acquire));
        let open = (0..5).all(|_| round(&mut conductor, &mut steady, &mut limits));
        // The loan ends; a held bound is withdrawn.
        release_loan(&found.loan);
        let open = open && (0..5).all(|_| round(&mut conductor, &mut steady, &mut limits));
        let sealed = conductor.seal_state() != SealState::Active;
        match policy {
            LossPolicy::Abort => {
                assert_eq!(revocation, Revocation::Sealed);
                assert!(sealed && !open, "abort did not seal");
                assert_eq!(
                    conductor.seal_reason(),
                    Some(SealReason::RequiredParticipantLost)
                );
                // Until the seal the limit never decreased.
                let until = limits
                    .iter()
                    .position(|limit| *limit == 0)
                    .unwrap_or(limits.len());
                let open_limits = &limits[..until];
                assert!(
                    open_limits.windows(2).all(|pair| pair[0] <= pair[1]),
                    "{policy:?}: {open_limits:?}"
                );
            }
            _ => {
                assert!(!sealed && open, "{policy:?} sealed the publication");
                assert!(
                    limits.windows(2).all(|pair| pair[0] <= pair[1]),
                    "{policy:?}: {limits:?}"
                );
            }
        }
        assert!(matches!(poll(&mut lost), PollOutcome::Revoked { .. }));
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
            AppendOutcome::Closed | AppendOutcome::Gated => panic!("not sealed"),
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
