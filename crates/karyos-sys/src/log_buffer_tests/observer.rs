// SPDX-License-Identifier: Apache-2.0

// The observer role (roadmap P2; quantstratum-docs:
// `karyos/design/observer-role.md`): it never bounds the publisher, holds a
// spare-slot credit, keeps the publication connected, and holds a loan only
// inside one copy. Included once per term backing after `loss.rs`, whose
// `hold_loan` it uses.

/// Appends `messages` messages of `data`, running a duty cycle after each,
/// and returns how often the publication was back-pressured.
fn publish_running_duty(
    publication: &mut Publication<&LogBuffer<Terms>>,
    conductor: &mut Conductor<&LogBuffer<Terms>>,
    data: &[u8],
    messages: u32,
) -> u32 {
    let mut back_pressured = 0;
    for _ in 0..messages {
        loop {
            match publication.append(data, AppendOptions::default()).unwrap() {
                AppendOutcome::Appended { .. } => break,
                AppendOutcome::BackPressured => back_pressured += 1,
                AppendOutcome::AdminAction => {}
                AppendOutcome::Closed => panic!("not sealed"),
            }
            let _ = conductor.duty_cycle().unwrap();
        }
        let _ = conductor.duty_cycle().unwrap();
    }
    back_pressured
}

#[test]
fn test_observer_never_bounds_the_limit() {
    // S = 3, C = 1: two credits, the publication's and the observer's.
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut observer = conductor.subscribe(Role::Observer).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    // A stalled observer: many terms go by without it polling.
    let data = vec![3u8; 7000];
    let back_pressured = publish_running_duty(&mut publication, &mut conductor, &data, 60);
    assert_eq!(back_pressured, 0, "an observer bounded the publisher");
    match poll(&mut observer) {
        PollOutcome::Overrun {
            from,
            lost_to,
            resume,
        } => {
            assert_eq!(from, 0);
            assert!(lost_to > 0 && resume >= lost_to);
        }
        other => panic!("expected an overrun, got {other:?}"),
    }
}

#[test]
fn test_observer_credit_counts_against_spares() {
    // S = 4, C = 1: three credits for the publication, an optional reader
    // and an observer.
    let buffer = new_buffer(config(4, 4)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _optional = conductor.subscribe(Role::Optional).unwrap();
    let observer = conductor.subscribe(Role::Observer).unwrap();
    for role in [Role::Observer, Role::Optional] {
        assert_eq!(
            conductor.subscribe(role).err(),
            Some(SysError::ResourcesUnavailable)
        );
    }
    // A required reader takes no credit.
    let _required = conductor.subscribe(Role::Required).unwrap();
    // Closing the observer returns its credit.
    observer.close();
    assert!(conductor.subscribe(Role::Observer).is_ok());
}

#[test]
fn test_observer_keeps_the_publication_connected() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    assert_eq!(buffer.attached_subscribers(), 0);
    let observer = conductor.subscribe(Role::Observer).unwrap();
    assert_eq!(buffer.attached_subscribers(), 1);
    observer.close();
    assert_eq!(buffer.attached_subscribers(), 0);
}

#[test]
fn test_observer_slow_handler_pins_nothing() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut observer = conductor.subscribe(Role::Observer).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let first = message(1);
    let _ = publication.append(&first, AppendOptions::default()).unwrap();
    // The copy delivers, and the loan ends with the poll.
    assert_eq!(poll_message(&mut observer), Some(first));
    let cell = buffer.cells().get(observer.cell()).unwrap();
    assert_eq!(cell.loan.load(Ordering::Acquire), 0);
    // While its handler is slow, terms are reclaimed and cleaned.
    let data = vec![4u8; 7000];
    let mut cleaned = 0;
    let mut quarantined = 0;
    for _ in 0..60 {
        loop {
            let outcome = publication.append(&data, AppendOptions::default()).unwrap();
            let report = conductor.duty_cycle().unwrap();
            cleaned += report.cleaned;
            quarantined += report.quarantined;
            if matches!(outcome, AppendOutcome::Appended { .. }) {
                break;
            }
        }
    }
    assert!(cleaned > 0, "nothing was reclaimed");
    assert_eq!(quarantined, 0, "the observer pinned a slot");
    assert!(matches!(poll(&mut observer), PollOutcome::Overrun { .. }));
}

#[test]
fn test_observer_is_revoked_like_an_optional_reader() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let cell = conductor.register_subscriber(Role::Observer, 9).unwrap();
    assert_eq!(cell_state(&buffer, cell), CELL_OBSERVER);
    let _ = conductor
        .revoke_participant(cell, 9, LossPolicy::Hold)
        .unwrap();
    // Revoked, it keeps its credit until it is freed.
    assert_eq!(cell_state(&buffer, cell), CELL_LOST_RESERVED);
}

/// SPEC.md §13 "Stall isolation and capacity", phase 1 part: a paused claim
/// of one concurrent publisher, optional readers and an observer paused
/// inside their copies, while another publisher runs ten terms; then one
/// more admission arrives. Pinned slots are counted in every state outside
/// the three rotation slots (an `ACTIVE` or `READY` slot of an earlier term
/// counts as much as a `RECLAIMING` or `CLEANING` one), and the publisher's
/// outcomes are matched explicitly against `ResourcesUnavailable`.
#[test]
fn test_stall_isolation_optional_observer_claim() {
    // Two publishers, two optional readers and an observer: five credits.
    let config = LogBufferConfig {
        publication: PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: true,
        },
        ..config(6, 4)
    };
    let buffer = new_buffer(config).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let readers: Vec<_> = [Role::Optional, Role::Optional, Role::Observer]
        .into_iter()
        .map(|role| conductor.subscribe(role).unwrap())
        .collect();
    let mut paused = conductor.concurrent_publication().unwrap().unwrap();
    let mut running = conductor.concurrent_publication().unwrap().unwrap();
    // One more admission does not fit the spares.
    assert_eq!(
        conductor.subscribe(Role::Optional).err(),
        Some(SysError::ResourcesUnavailable)
    );
    // Something committed in term 0 for the readers to be copying.
    let first = message(1);
    loop {
        if let ConcurrentOfferOutcome::Appended { .. } =
            running.offer(&first, AppendOptions::default()).unwrap()
        {
            break;
        }
        let _ = conductor.duty_cycle().unwrap();
    }
    // Every reader pauses inside its copy of term 0: a loan held.
    for reader in &readers {
        hold_loan(&buffer, reader.cell());
    }
    let committed = word0_of_term0(&buffer, 0).load(Ordering::Acquire);
    assert!(committed as u32 as i32 > 0, "term 0 holds no committed frame");
    // Publisher A pauses inside a claim, holding its write credit.
    let claim = concurrent_claimed(paused.try_claim(64, AppendOptions::default()));
    // Publisher B runs ten terms at full rate.
    let data = vec![9u8; 6000];
    let target = 10 * TERM;
    let mut appended = 0u64;
    let mut cycles = 0u32;
    let mut most_pinned = 0usize;
    while appended < target {
        match running.offer(&data, AppendOptions::default()) {
            Ok(ConcurrentOfferOutcome::Appended { .. }) => appended += data.len() as u64,
            Ok(ConcurrentOfferOutcome::BackPressured) => {
                panic!("back-pressured by a paused reader")
            }
            Ok(ConcurrentOfferOutcome::AdminAction) => {}
            Err(SysError::ResourcesUnavailable) => {
                panic!("the running publisher got ResourcesUnavailable")
            }
            other => panic!("unexpected {other:?}"),
        }
        let _ = conductor.duty_cycle().unwrap();
        cycles += 1;
        assert!(cycles < 100_000, "publisher B made no progress");
        // Pinned plus uncleaned slots never exceed S: every slot that is not
        // FREE and does not hold the previous, active or next term, in any
        // state, ACTIVE and READY included.
        let active = buffer.active_count().load(Ordering::Acquire) as u32;
        let mut pinned = 0usize;
        let mut pinned_live = 0usize;
        for slot in 0..buffer.slots {
            let descriptor =
                Descriptor::decode(buffer.descriptor(slot).unwrap().load(Ordering::Acquire))
                    .unwrap();
            if descriptor.state() == SlotState::Free {
                continue;
            }
            let count = descriptor
                .term_id()
                .count_from(buffer.initial_term_id)
                .unwrap()
                .get();
            if count + 1 < active || count > active + 1 {
                pinned += 1;
                if matches!(descriptor.state(), SlotState::Active | SlotState::Ready) {
                    pinned_live += 1;
                }
            }
        }
        assert!(
            pinned <= usize::from(buffer.spare_slots),
            "{pinned} slots pinned ({pinned_live} ACTIVE or READY), S = {}",
            buffer.spare_slots
        );
        // A term below the floor leaves ACTIVE in the duty cycle that finds
        // it there, loans or not: what stays pinned is RECLAIMING.
        assert_eq!(pinned_live, 0, "an earlier term stayed ACTIVE or READY");
        most_pinned = most_pinned.max(pinned);
    }
    // The stalled holders did pin something, within the spares.
    assert!(most_pinned >= 1, "no slot was ever pinned");
    // One more admission after the run still does not fit the spares, and
    // the running publisher is unaffected by the refusal.
    assert_eq!(
        conductor.subscribe(Role::Optional).err(),
        Some(SysError::ResourcesUnavailable)
    );
    assert!(matches!(
        running.offer(&data, AppendOptions::default()),
        Ok(ConcurrentOfferOutcome::Appended { .. } | ConcurrentOfferOutcome::AdminAction)
    ));
    // Term 0, under the readers' loans, was never cleaned or reused.
    let state = Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire)).unwrap();
    assert_eq!(state.term_id(), buffer.initial_term_id);
    assert_ne!(state.state(), SlotState::Free);
    // Each paused reader, still under its loan, finds the committed frame
    // intact; then its copy ends and it is lapped.
    for reader in &readers {
        let loan = &buffer.cells().get(reader.cell()).unwrap().loan;
        assert_ne!(loan.load(Ordering::Acquire), 0, "the reader's loan was lost");
        assert_eq!(word0_of_term0(&buffer, 0).load(Ordering::Acquire), committed);
        let mut bytes = vec![0u8; first.len()];
        // SAFETY: the reader's read loan on term 0 is held; the frame's
        // word 0 was loaded with Acquire above; the payload starts after its
        // 32-byte header, a multiple of 8, and lies inside the slot.
        unsafe { buffer.regions.read_bytes(0, HEADER_LENGTH, &mut bytes) };
        assert_eq!(bytes, first, "a held term's bytes changed");
        release_loan(loan);
    }
    drop(claim);
    for mut reader in readers {
        assert!(matches!(poll(&mut reader), PollOutcome::Overrun { .. }));
    }
}

/// Under Miri's data race detector: a publisher, an observer and the
/// conductor's duty cycle on three threads. The observer delivers a
/// contiguous run of the published messages or reports an overrun, and
/// resumes after it with later messages.
#[test]
fn test_observer_concurrent_publish_and_reclaim_no_data_race() {
    let (total, len): (u32, usize) = if cfg!(miri) { (60, 7000) } else { (3000, 3000) };
    let buffer = new_buffer(config(3, 2)).unwrap();
    let published = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    let mut conductor = buffer.conductor().unwrap();
    let mut observer = conductor.subscribe(Role::Observer).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    std::thread::scope(|scope| {
        let duty = scope.spawn(|| {
            while !finished.load(Ordering::Acquire) {
                let _ = conductor.duty_cycle().unwrap();
                std::thread::yield_now();
            }
        });
        scope.spawn(|| {
            for sequence in 0..total {
                let data = sized_message(sequence, len);
                while !matches!(
                    publication.append(&data, AppendOptions::default()).unwrap(),
                    AppendOutcome::Appended { .. }
                ) {
                    std::thread::yield_now();
                }
            }
            published.store(true, Ordering::Release);
        });
        let mut out = vec![0u8; 8192];
        let mut last = None::<u32>;
        let mut contiguous = true;
        loop {
            match observer.poll(&mut out).unwrap() {
                PollOutcome::Message { length, .. } => {
                    let sequence = u32::from_le_bytes(out[..4].try_into().unwrap());
                    assert_eq!(&out[..length as usize], &sized_message(sequence, len)[..]);
                    if let Some(previous) = last {
                        // Contiguous until an overrun, increasing after it.
                        assert!(if contiguous { sequence == previous + 1 } else { sequence > previous });
                    } else {
                        assert!(!contiguous || sequence == 0);
                    }
                    contiguous = true;
                    last = Some(sequence);
                    if sequence + 1 == total {
                        break;
                    }
                }
                PollOutcome::Overrun { .. } => contiguous = false,
                PollOutcome::Pending => {
                    if published.load(Ordering::Acquire)
                        && observer.position() >= buffer.reserved_head().load(Ordering::Acquire)
                    {
                        break;
                    }
                    std::thread::yield_now();
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        finished.store(true, Ordering::Release);
        duty.join().unwrap();
    });
}
