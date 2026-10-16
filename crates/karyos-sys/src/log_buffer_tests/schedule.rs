// SPDX-License-Identifier: Apache-2.0

// The schedule ring of a timed lane in its buffer (`quantstratum-docs:
// karyos/design/timed-tx.md`, TT-1): included by each backing's tests.

/// A timed buffer carries an initialised ring of its capacity; an untimed
/// one has none.
#[test]
fn a_timed_buffer_carries_its_schedule_ring() {
    let untimed = new_buffer(config(3, 2)).unwrap();
    assert!(untimed.schedule_ring().is_none());
    let timed = new_buffer(LogBufferConfig {
        schedule_capacity: 4,
        ..config(3, 2)
    })
    .unwrap();
    let ring = timed.schedule_ring().unwrap();
    assert_eq!(ring.len(), crate::schedule_ring::ring_words(4).unwrap());
    let mut publisher = crate::schedule_ring::SchedulePublisher::attach(ring).unwrap();
    let reader = crate::schedule_ring::ScheduleReader::attach(ring).unwrap();
    assert_eq!(publisher.has_room(ring), Ok(true));
    let entry = crate::schedule_ring::Entry {
        position: 0,
        time: 42,
    };
    publisher.push(ring, entry).unwrap();
    assert_eq!(reader.peek(ring), Ok(Some(entry)));
}

/// A schedule capacity is a power of two up to the bound, on an exclusive
/// publication.
#[test]
fn a_schedule_needs_a_bounded_power_of_two_and_an_exclusive_publication() {
    let max = crate::schedule_ring::MAX_CAPACITY;
    for capacity in [3, 6, 1000, max * 2, max + 1, u32::MAX] {
        assert_eq!(
            new_buffer(LogBufferConfig {
                schedule_capacity: capacity,
                ..config(3, 2)
            })
            .err(),
            Some(SysError::Schedule(
                crate::schedule_ring::ScheduleError::Capacity { capacity }
            )),
            "{capacity}"
        );
    }
    let concurrent = LogBufferConfig {
        schedule_capacity: 4,
        publication: PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: true,
        },
        ..config(3, 2)
    };
    assert!(matches!(
        new_buffer(concurrent),
        Err(SysError::InvalidPublicationMode { .. })
    ));
}

fn timed(capacity: u32) -> LogBufferConfig {
    LogBufferConfig {
        schedule_capacity: capacity,
        ..config(2, 2)
    }
}

/// A timed lane carries timed messages only, and only a timed lane takes
/// them.
#[test]
fn a_timed_lane_takes_scheduled_appends_only() {
    let buffer = new_buffer(timed(4)).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let not_scheduled = Err(SysError::Schedule(
        crate::schedule_ring::ScheduleError::NotScheduled,
    ));
    assert_eq!(
        publication.append(b"a", AppendOptions::default()),
        not_scheduled
    );
    assert!(matches!(
        publication.try_claim(8, AppendOptions::default()),
        Err(SysError::Schedule(
            crate::schedule_ring::ScheduleError::NotScheduled
        ))
    ));
    let plain = new_buffer(config(2, 2)).unwrap();
    let mut plain_publication = plain.publication().unwrap().unwrap();
    assert_eq!(
        plain_publication.append_scheduled(b"a", AppendOptions::default(), 1),
        not_scheduled
    );
    assert_eq!(plain_publication.schedule_has_room(), not_scheduled.map(|_| true));
}

/// Times never go backwards on a timed lane, also in sys: a time below the
/// last is refused before anything is reserved; an equal one is accepted.
#[test]
fn a_time_below_the_last_is_refused() {
    let buffer = new_buffer(timed(4)).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    assert!(matches!(
        publication.append_scheduled(b"a", AppendOptions::default(), 20),
        Ok(AppendOutcome::Appended { .. })
    ));
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert_eq!(
        publication.append_scheduled(b"b", AppendOptions::default(), 19),
        Err(SysError::Schedule(
            crate::schedule_ring::ScheduleError::Backwards
        ))
    );
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), head);
    assert!(matches!(
        publication.append_scheduled(b"c", AppendOptions::default(), 20),
        Ok(AppendOutcome::Appended { .. })
    ));
}

/// A sealed timed lane whose ring is full still observes its seal and
/// releases, as an append does (#234 P2-1).
#[test]
fn a_full_schedule_still_observes_the_seal() {
    let buffer = new_buffer(timed(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    assert!(matches!(
        publication.append_scheduled(b"a", AppendOptions::default(), 1),
        Ok(AppendOutcome::Appended { .. })
    ));
    assert_eq!(
        publication.append_scheduled(b"b", AppendOptions::default(), 2),
        Ok(AppendOutcome::BackPressured)
    );
    conductor.seal().unwrap();
    assert_eq!(
        publication.append_scheduled(b"b", AppendOptions::default(), 2),
        Ok(AppendOutcome::Closed)
    );
    assert_ne!(buffer.exclusive_released().load(Ordering::Acquire), 0);
}

/// The entry is pushed before the block's commit store: at the pause
/// between them, the sender already finds the entry while no reader sees
/// the message (#234 P3, the push-before-commit order).
#[test]
fn the_entry_is_visible_before_the_block_is_committed() {
    let buffer = new_buffer(timed(4)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let ring = buffer.schedule_ring().unwrap();
    let reader = crate::schedule_ring::ScheduleReader::attach(ring).unwrap();
    let mut paused = false;
    let outcome = publication
        .append_scheduled_pausing(b"a", AppendOptions::default(), 7, &mut || {
            paused = true;
            assert_eq!(reader.peek(ring).unwrap().map(|entry| entry.time), Some(7));
            assert!(poll_message(&mut subscription).is_none(), "committed early");
        })
        .unwrap();
    assert!(paused);
    let AppendOutcome::Appended { position } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(
        reader.peek(ring).unwrap(),
        Some(crate::schedule_ring::Entry { position, time: 7 })
    );
    assert!(poll_message(&mut subscription).is_some());
}

/// A full ring back pressures before the reservation: nothing is reserved.
#[test]
fn a_full_schedule_backpressures_before_reserving() {
    let buffer = new_buffer(timed(2)).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    for time in [10, 20] {
        assert!(matches!(
            publication
                .append_scheduled(b"a", AppendOptions::default(), time)
                .unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert_eq!(
        publication
            .append_scheduled(b"b", AppendOptions::default(), 30)
            .unwrap(),
        AppendOutcome::BackPressured
    );
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), head);
}

/// Through many rotations, back pressure and admin actions, the ring holds
/// exactly one entry per appended message, in order, naming its first
/// frame: an append that reserved nothing pushed nothing.
#[test]
fn scheduled_appends_keep_the_ring_in_step_with_the_log() {
    let buffer = new_buffer(timed(4)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let ring = buffer.schedule_ring().unwrap();
    let mut reader = crate::schedule_ring::ScheduleReader::attach(ring).unwrap();
    let mut expected = Vec::new();
    let mut seen = Vec::new();
    let mut refused = 0u32;
    let total: u32 = if cfg!(miri) { 60 } else { 600 };
    let drain = |subscription: &mut Subscription<&LogBuffer<Terms>>,
                 reader: &mut crate::schedule_ring::ScheduleReader,
                 seen: &mut Vec<(u64, u64)>| {
        while poll_message(subscription).is_some() {}
        while let Some(entry) = reader.peek(ring).unwrap() {
            seen.push((entry.position, entry.time));
            reader.advance(ring).unwrap();
            reader.release(ring).unwrap();
        }
    };
    for sequence in 0..total {
        let time = u64::from(sequence) * 3;
        loop {
            match publication
                .append_scheduled(&message(sequence), AppendOptions::default(), time)
                .unwrap()
            {
                AppendOutcome::Appended { position } => {
                    expected.push((position, time));
                    break;
                }
                AppendOutcome::BackPressured | AppendOutcome::AdminAction => {
                    refused += 1;
                    drain(&mut subscription, &mut reader, &mut seen);
                    let _ = conductor.duty_cycle().unwrap();
                }
                other => panic!("{other:?}"),
            }
        }
        if sequence % 3 == 0 {
            drain(&mut subscription, &mut reader, &mut seen);
            let _ = conductor.duty_cycle().unwrap();
        }
    }
    drain(&mut subscription, &mut reader, &mut seen);
    assert!(refused > 0, "no refusal was exercised");
    assert_eq!(seen, expected);
}
