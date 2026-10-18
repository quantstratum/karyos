// SPDX-License-Identifier: Apache-2.0

use karyos_sys::schedule_ring::{Entry, ScheduleError, SchedulePublisher, init, ring_words};
use karyos_sys::sync::AtomicU64;

use super::{LaneFrame, ScheduleConsumer, ScheduleConsumerError};

fn ring(capacity: usize) -> Vec<AtomicU64> {
    let ring: Vec<AtomicU64> = (0..ring_words(capacity).unwrap())
        .map(|_| AtomicU64::new(0))
        .collect();
    init(&ring, capacity as u64).unwrap();
    ring
}

fn push(ring: &[AtomicU64], publisher: &mut SchedulePublisher, position: u64, time: u64) {
    assert_eq!(publisher.has_room(ring), Ok(true));
    publisher.push(ring, Entry { position, time }).unwrap();
}

fn data(position: u64, begin: bool, end: bool) -> LaneFrame {
    LaneFrame::Data {
        position,
        begin,
        end,
    }
}

fn corrupt(result: Result<Option<u64>, ScheduleConsumerError>) -> bool {
    matches!(result, Err(ScheduleConsumerError::CorruptTerm { .. }))
}

/// Every fragment of a message carries its entry's time; the entry is
/// released only when the message left, which frees the publisher's room.
#[test]
fn fragments_carry_the_time_and_the_entry_is_released_when_the_message_left() {
    let ring = ring(2);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    push(&ring, &mut publisher, 0, 10);
    push(&ring, &mut publisher, 96, 20);
    assert_eq!(publisher.has_room(&ring), Ok(false));
    assert_eq!(consumer.frame(&ring, data(0, true, false)), Ok(Some(10)));
    assert_eq!(consumer.frame(&ring, data(32, false, false)), Ok(Some(10)));
    assert_eq!(consumer.frame(&ring, data(64, false, true)), Ok(Some(10)));
    assert_eq!(consumer.frame(&ring, data(96, true, true)), Ok(Some(20)));
    // Both read; neither left, so the ring stays full.
    assert_eq!(consumer.outstanding(), 2);
    assert_eq!(publisher.has_room(&ring), Ok(false));
    consumer.message_left(&ring).unwrap();
    assert_eq!(consumer.outstanding(), 1);
    assert_eq!(publisher.has_room(&ring), Ok(true));
    consumer.message_left(&ring).unwrap();
    assert_eq!(consumer.outstanding(), 0);
    assert!(matches!(
        consumer.message_left(&ring),
        Err(ScheduleConsumerError::CorruptTerm { .. })
    ));
}

/// A first fragment needs the next entry at its own position; anything
/// else is corruption, never a guessed time.
#[test]
fn a_first_fragment_without_its_entry_is_corrupt() {
    let ring = ring(4);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    // No entry at all.
    assert!(corrupt(consumer.frame(&ring, data(0, true, true))));
    push(&ring, &mut publisher, 64, 5);
    // An entry at another position.
    assert!(corrupt(consumer.frame(&ring, data(0, true, true))));
    // A continuation outside a message.
    assert!(corrupt(consumer.frame(&ring, data(64, false, true))));
    // The matching frame still reads it: the refusals consumed nothing.
    assert_eq!(consumer.frame(&ring, data(64, true, false)), Ok(Some(5)));
    // Inside a message: a new first fragment, padding or an aborted block.
    assert!(corrupt(consumer.frame(&ring, data(128, true, true))));
    assert!(corrupt(consumer.frame(&ring, LaneFrame::Pad)));
    assert!(corrupt(
        consumer.frame(&ring, LaneFrame::Aborted { position: 128 })
    ));
}

/// Padding takes no entry; an aborted block takes the next entry only at
/// its position, and that entry is released in order with the others.
#[test]
fn padding_takes_no_entry_and_an_aborted_message_takes_its_own() {
    let ring = ring(4);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    push(&ring, &mut publisher, 0, 1);
    push(&ring, &mut publisher, 32, 2);
    push(&ring, &mut publisher, 96, 3);
    assert_eq!(consumer.frame(&ring, LaneFrame::Pad), Ok(None));
    assert_eq!(consumer.frame(&ring, data(0, true, true)), Ok(Some(1)));
    // An aborted block with no entry (not a message) takes nothing.
    assert_eq!(
        consumer.frame(&ring, LaneFrame::Aborted { position: 16 }),
        Ok(None)
    );
    assert_eq!(consumer.outstanding(), 1);
    // The aborted message at 32 takes its entry; it is done but waits
    // behind the message at 0, which has not left.
    assert_eq!(
        consumer.frame(&ring, LaneFrame::Aborted { position: 32 }),
        Ok(None)
    );
    assert_eq!(consumer.outstanding(), 2);
    assert_eq!(consumer.frame(&ring, data(96, true, true)), Ok(Some(3)));
    // The message at 0 leaves: it and the aborted one are released.
    consumer.message_left(&ring).unwrap();
    assert_eq!(consumer.outstanding(), 1);
    consumer.message_left(&ring).unwrap();
    assert_eq!(consumer.outstanding(), 0);
}

/// An aborted message at the head of the outstanding ones is released at
/// once.
#[test]
fn an_aborted_message_with_nothing_ahead_is_released_at_once() {
    let ring = ring(1);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    push(&ring, &mut publisher, 0, 1);
    assert_eq!(publisher.has_room(&ring), Ok(false));
    assert_eq!(
        consumer.frame(&ring, LaneFrame::Aborted { position: 0 }),
        Ok(None)
    );
    assert_eq!(consumer.outstanding(), 0);
    assert_eq!(publisher.has_room(&ring), Ok(true));
}

/// Entries are consumed and released across the ring's wrap.
#[test]
fn the_consumer_follows_the_ring_across_a_wrap() {
    let ring = ring(2);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    for round in 0..5u64 {
        let position = round * 32;
        push(&ring, &mut publisher, position, round);
        assert_eq!(
            consumer.frame(&ring, data(position, true, true)),
            Ok(Some(round))
        );
        consumer.message_left(&ring).unwrap();
    }
    assert_eq!(consumer.outstanding(), 0);
}

/// A ring that is not one is refused at construction.
#[test]
fn a_ring_that_is_not_one_is_refused() {
    let words: Vec<AtomicU64> = (0..4).map(|_| AtomicU64::new(0)).collect();
    assert_eq!(
        ScheduleConsumer::new(&words).err(),
        Some(ScheduleConsumerError::Ring(ScheduleError::Layout))
    );
}

/// A message lost before it left (its last fragment never staged) frees
/// its own entry, the newest; an older one still waiting keeps its slot.
#[test]
fn a_lost_message_frees_its_own_entry() {
    let ring = ring(2);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    push(&ring, &mut publisher, 0, 10);
    push(&ring, &mut publisher, 64, 20);
    let _ = consumer.frame(&ring, data(0, true, true)).unwrap();
    let _ = consumer.frame(&ring, data(64, true, true)).unwrap();
    consumer.message_lost(&ring).unwrap();
    // The first still waits: nothing is released, the ring is still full.
    assert_eq!(consumer.outstanding(), 2);
    assert_eq!(publisher.has_room(&ring), Ok(false));
    consumer.message_left(&ring).unwrap();
    assert_eq!(consumer.outstanding(), 0);
    assert_eq!(publisher.has_room(&ring), Ok(true));
}

/// A rewind to a message boundary reads the entries not released again,
/// in order, each marked replayed; a message read after them is not.
#[test]
fn a_rewind_replays_the_unreleased_messages() {
    use super::Scheduled;

    let ring = ring(4);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    for (position, time) in [(0, 10), (64, 20), (128, 30)] {
        push(&ring, &mut publisher, position, time);
    }
    for position in [0, 64] {
        let _ = consumer.frame(&ring, data(position, true, true)).unwrap();
    }
    // The first left and was acknowledged: released. The second was read.
    consumer.message_left(&ring).unwrap();
    consumer.rewind();
    assert_eq!(consumer.outstanding(), 0);
    let again = consumer
        .frame_scheduled(&ring, data(64, true, true))
        .unwrap();
    assert_eq!(
        again,
        Some(Scheduled {
            time: 20,
            replayed: true
        })
    );
    let next = consumer
        .frame_scheduled(&ring, data(128, true, true))
        .unwrap();
    assert_eq!(
        next,
        Some(Scheduled {
            time: 30,
            replayed: false
        })
    );
}

/// A rewind inside a message (a block boundary between its fragments):
/// its next fragment takes the message's own entry, at `head`, below it;
/// with none below, the term is corrupt.
#[test]
fn a_rewind_inside_a_message_resumes_it() {
    use super::Scheduled;

    let ring = ring(4);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    push(&ring, &mut publisher, 0, 10);
    let _ = consumer.frame(&ring, data(0, true, false)).unwrap();
    let _ = consumer.frame(&ring, data(1408, false, false)).unwrap();
    consumer.rewind();
    let resumed = consumer
        .frame_scheduled(&ring, data(1408, false, false))
        .unwrap();
    assert_eq!(
        resumed,
        Some(Scheduled {
            time: 10,
            replayed: true
        })
    );
    assert_eq!(consumer.frame(&ring, data(2816, false, true)), Ok(Some(10)));
    consumer.message_left(&ring).unwrap();
    assert_eq!(consumer.outstanding(), 0);
    // An entry at or past the fragment is no message it continues.
    let ring = super::tests::ring(4);
    let mut publisher = SchedulePublisher::attach(&ring).unwrap();
    let mut consumer = ScheduleConsumer::new(&ring).unwrap();
    push(&ring, &mut publisher, 4096, 10);
    consumer.rewind();
    assert!(matches!(
        consumer.frame_scheduled(&ring, data(1408, false, true)),
        Err(ScheduleConsumerError::CorruptTerm { .. })
    ));
}
