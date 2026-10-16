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
    let ring = timed_ring_words();
    crate::schedule_ring::init(&ring, 4).unwrap();
    let mut other = crate::schedule_ring::SchedulePublisher::attach(&ring).unwrap();
    assert_eq!(
        plain.publication().unwrap().unwrap().append_scheduled(
            b"a",
            AppendOptions::default(),
            &mut other,
            1
        ),
        not_scheduled
    );
}

fn timed_ring_words() -> Vec<AtomicU64> {
    (0..crate::schedule_ring::ring_words(4).unwrap())
        .map(|_| AtomicU64::new(0))
        .collect()
}

/// A full ring back pressures before the reservation: nothing is reserved.
#[test]
fn a_full_schedule_backpressures_before_reserving() {
    let buffer = new_buffer(timed(2)).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let ring = buffer.schedule_ring().unwrap();
    let mut publisher = crate::schedule_ring::SchedulePublisher::attach(ring).unwrap();
    for time in [10, 20] {
        assert!(matches!(
            publication
                .append_scheduled(b"a", AppendOptions::default(), &mut publisher, time)
                .unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert_eq!(
        publication
            .append_scheduled(b"b", AppendOptions::default(), &mut publisher, 30)
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
    let mut publisher = crate::schedule_ring::SchedulePublisher::attach(ring).unwrap();
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
            reader.release(ring).unwrap();
        }
    };
    for sequence in 0..total {
        let time = u64::from(sequence) * 3;
        loop {
            match publication
                .append_scheduled(
                    &message(sequence),
                    AppendOptions::default(),
                    &mut publisher,
                    time,
                )
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
