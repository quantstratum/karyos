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

/// A schedule capacity is a power of two, on an exclusive publication.
#[test]
fn a_schedule_needs_a_power_of_two_and_an_exclusive_publication() {
    for capacity in [3, 6, 1000] {
        assert!(
            matches!(
                new_buffer(LogBufferConfig {
                    schedule_capacity: capacity,
                    ..config(3, 2)
                }),
                Err(SysError::InvalidPublicationMode { .. })
            ),
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
