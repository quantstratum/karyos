// SPDX-License-Identifier: Apache-2.0

// Log buffer tests, included once per term backing by `log_buffer.rs`; the
// including module defines `Terms` and `new_buffer`.

use crate::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH};
use super::concurrent::WriterPause;

const TERM: u64 = MIN_TERM_LENGTH as u64;

fn config(spare_slots: u8, max_subscribers: u8) -> LogBufferConfig {
    LogBufferConfig {
        term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        spare_slots,
        max_subscribers,
        mtu: DEFAULT_MTU,
        max_reserved: MIN_TERM_LENGTH / 8,
        initial_term_id: TermId::new(u32::MAX - 1),
        lane: Lane::ZERO,
        session_id: 3,
        stream_id: 4,
        claim_deadline: DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Exclusive,
        schedule_capacity: 0,
    }
}

fn message(sequence: u32) -> Vec<u8> {
    let len = 24 + (sequence as usize * 53) % 3000;
    let mut data: Vec<u8> = (0..len).map(|i| (i as u8) ^ (sequence as u8)).collect();
    data[..4].copy_from_slice(&sequence.to_le_bytes());
    data
}

/// Appends until the message is accepted, running duty cycles on
/// back pressure and admin actions. Returns how many cycles it needed.
fn append_retrying(
    publication: &mut Publication<&LogBuffer<Terms>>,
    conductor: &mut Conductor<&LogBuffer<Terms>>,
    data: &[u8],
    mut drain: impl FnMut(),
) -> u32 {
    for attempt in 0..1000 {
        match publication.append(data, AppendOptions::default()).unwrap() {
            AppendOutcome::Appended { .. } => return attempt,
            AppendOutcome::BackPressured | AppendOutcome::AdminAction => {
                drain();
                let _ = conductor.duty_cycle().unwrap();
            }
            AppendOutcome::Closed | AppendOutcome::Gated => panic!("not sealed"),
        }
    }
    panic!("append never succeeded");
}

fn poll(subscription: &mut Subscription<&LogBuffer<Terms>>) -> PollOutcome {
    let mut out = vec![0u8; 8192];
    subscription.poll(&mut out).unwrap()
}

fn poll_message(subscription: &mut Subscription<&LogBuffer<Terms>>) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 8192];
    match subscription.poll(&mut out).unwrap() {
        PollOutcome::Message { length, .. } => {
            // Handled: acknowledge (a no-op for optional subscribers).
            subscription.acknowledge();
            out.truncate(length as usize);
            Some(out)
        }
        PollOutcome::Pending => None,
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn required_subscriber_reads_everything_through_many_rotations() {
    let buffer = new_buffer(config(2, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut expected = 0u32;
    let total: u32 = if cfg!(miri) { 160 } else { 1200 };
    for sequence in 0..total {
        let data = message(sequence);
        let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
        while let Some(read) = poll_message(&mut subscription) {
            assert_eq!(read, message(expected));
            expected += 1;
        }
        let _ = conductor.duty_cycle().unwrap();
        let head = buffer.reserved_head().load(Ordering::Acquire);
        assert!(head - buffer.floor().load(Ordering::Acquire) <= TERM);
    }
    while expected < total {
        let _ = conductor.duty_cycle().unwrap();
        if let Some(read) = poll_message(&mut subscription) {
            assert_eq!(read, message(expected));
            expected += 1;
        }
    }
    // Many terms went through five slots: slots were reused.
    let minimum = if cfg!(miri) { 2 } else { 10 };
    assert!(buffer.active_count().load(Ordering::Acquire) > minimum);
}

#[test]
fn required_subscriber_back_pressures_the_publication() {
    let buffer = new_buffer(config(2, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = vec![7u8; 3000];
    let mut appended = 0;
    let mut pressured = false;
    for _ in 0..2000 {
        match publication.append(&data, AppendOptions::default()).unwrap() {
            AppendOutcome::Appended { .. } => appended += 1,
            AppendOutcome::BackPressured => {
                pressured = true;
                break;
            }
            AppendOutcome::AdminAction => {}
            AppendOutcome::Closed | AppendOutcome::Gated => panic!("not sealed"),
        }
        let _ = conductor.duty_cycle().unwrap();
    }
    assert!(pressured, "the publication was never back-pressured");
    // Never more than the window ahead of the required subscriber.
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert!(head <= TERM / 2);
    // Reading releases the publication.
    while poll_message(&mut subscription).is_some() {}
    let _ = conductor.duty_cycle().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    assert!(matches!(
        publication.append(&data, AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { .. }
    ));
    assert!(appended > 0);
}

#[test]
fn lapped_optional_subscriber_rejoins_at_the_head() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut lagging = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let messages = if cfg!(miri) { 140 } else { 300 };
    for sequence in 0..messages {
        let _ = append_retrying(&mut publication, &mut conductor, &message(sequence), || {});
        let _ = conductor.duty_cycle().unwrap();
    }
    let head = buffer.reserved_head().load(Ordering::Acquire);
    match poll(&mut lagging) {
        PollOutcome::Overrun {
            from,
            lost_to,
            resume,
        } => {
            assert_eq!(from, 0);
            assert!(lost_to > 0 && lost_to <= resume);
            assert_eq!(resume, head);
        }
        other => panic!("expected Overrun, found {other:?}"),
    }
    let _ = append_retrying(&mut publication, &mut conductor, &message(999), || {});
    assert_eq!(poll_message(&mut lagging), Some(message(999)));
}

#[test]
fn rotation_waits_for_the_conductor() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    // Lift flow control far enough to cross two terms without cycles.
    buffer.limit().store(4 * TERM, Ordering::Release);
    let data = vec![9u8; 7000];
    let mut admin = 0;
    let mut appended = 0;
    for _ in 0..100 {
        match publication.append(&data, AppendOptions::default()).unwrap() {
            AppendOutcome::Appended { .. } => appended += 1,
            AppendOutcome::AdminAction => admin += 1,
            AppendOutcome::BackPressured => panic!("unexpected back pressure"),
            AppendOutcome::Closed | AppendOutcome::Gated => panic!("not sealed"),
        }
    }
    // Term 0 and the prepared term 1 filled up; term 2 needs the
    // conductor, so later appends only report AdminAction.
    assert!(appended > 0 && admin > 50);
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    let report = conductor.duty_cycle().unwrap();
    assert!(report.prepared);
    assert!(matches!(
        publication.append(&data, AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { .. } | AppendOutcome::AdminAction
    ));
}

#[test]
fn admission_respects_cells_and_credits() {
    // S = 2, C = 1: one credit, used by the publication.
    let buffer = new_buffer(config(2, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    assert_eq!(
        conductor.subscribe(Role::Optional).err(),
        Some(SysError::ResourcesUnavailable)
    );
    let a = conductor.subscribe(Role::Required).unwrap();
    let b = conductor.subscribe(Role::Required).unwrap();
    let c = conductor.subscribe(Role::Required).unwrap();
    assert_eq!(
        conductor.subscribe(Role::Required).err(),
        Some(SysError::ResourcesUnavailable)
    );
    // Closing frees a cell exactly once; a forgotten handle leaks it.
    b.close();
    let d = conductor.subscribe(Role::Required).unwrap();
    let _leaked = core::mem::ManuallyDrop::new(d);
    assert!(conductor.subscribe(Role::Required).is_err());
    drop(a);
    drop(c);
    assert!(conductor.subscribe(Role::Required).is_ok());
    assert!(new_buffer(config(1, 1)).is_err());
    assert!(new_buffer(config(126, 1)).is_err());
}

#[test]
fn a_loan_quarantines_its_slot_until_released() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    // A paused reader in a spare cell pins term 0 in slot 0, which is
    // ACTIVE from the start.
    let pinned = buffer.cells().get(1).unwrap();
    let target = buffer.target(0, TermCount::ZERO).unwrap();
    assert_eq!(
        take_loan(
            &pinned.loan,
            &pinned.revoked,
            buffer.descriptor(0).unwrap(),
            target
        ),
        Ok(LoanOutcome::Granted)
    );
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = vec![5u8; 7000];
    let mut quarantined = false;
    // Publish several terms; term 0 falls below the floor but stays
    // quarantined, so slot 0 is never freed or reused.
    for _ in 0..60 {
        let _ = publication.append(&data, AppendOptions::default()).unwrap();
        let report = conductor.duty_cycle().unwrap();
        quarantined |= report.quarantined > 0;
        // The diagnostic accessor reports what the cycle left quarantined.
        assert_eq!(
            conductor.quarantined_slots(),
            report.quarantined as usize
        );
        let state =
            Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire)).unwrap();
        assert_eq!(state.term_id(), buffer.initial_term_id);
        assert_ne!(state.state(), SlotState::Free);
    }
    assert!(quarantined, "term 0 never reached reclamation");
    release_loan(&pinned.loan);
    let report = conductor.duty_cycle().unwrap();
    assert!(report.cleaned > 0);
    assert_eq!(conductor.quarantined_slots(), 0);
    let state = Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire))
        .unwrap()
        .state();
    assert!(matches!(state, SlotState::Free | SlotState::Ready));
}

/// Codex's floor probes: without required subscribers the floor is
/// `head - window`; with a required subscriber it is its position. An
/// optional cursor below the floor is overrun, not served.
#[test]
fn optional_cursors_below_the_floor_are_overrun() {
    let small = vec![3u8; 992];
    // Optional only: 48 x 992 reserve 49152; floor = 49152 - 32768.
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut optional = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    buffer.limit().store(4 * TERM, Ordering::Release);
    for _ in 0..48 {
        let _ = publication
            .append(&small, AppendOptions::default())
            .unwrap();
    }
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.floor().load(Ordering::Acquire), 16_384);
    assert!(matches!(
        poll(&mut optional),
        PollOutcome::Overrun {
            from: 0,
            lost_to: 16_384,
            resume: 49_152
        }
    ));

    // Required consumed 8 x 992 = 8192: floor = 8192.
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe(Role::Required).unwrap();
    let mut optional = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    for _ in 0..16 {
        let _ = publication
            .append(&small, AppendOptions::default())
            .unwrap();
    }
    for _ in 0..8 {
        assert!(poll_message(&mut required).is_some());
    }
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.floor().load(Ordering::Acquire), 8192);
    assert!(matches!(
        poll(&mut optional),
        PollOutcome::Overrun {
            from: 0,
            lost_to: 8192,
            ..
        }
    ));
}

#[test]
fn the_floor_is_rechecked_after_the_loan_is_granted() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = append_retrying(&mut publication, &mut conductor, &message(1), || {});
    // The term is still ACTIVE, but the floor has passed the position, as
    // if raised while the subscriber was paused before its loan.
    buffer.floor().store(1, Ordering::Release);
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Overrun { from: 0, .. }
    ));
}

#[test]
fn the_conductor_completes_a_half_done_rotation() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    // The publication filled term 0 and stopped after publishing its
    // boundary, before activating term 1 and advancing the count.
    buffer.reserved_head().store(TERM, Ordering::Release);
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    let state = Descriptor::decode(buffer.descriptor(1).unwrap().load(Ordering::Acquire))
        .unwrap()
        .state();
    assert_eq!(state, SlotState::Active);
    // A second cycle is idempotent.
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
}

/// Vectors: 60 payloads of 992 bytes reserve 61440; an 8000-byte message
/// then pads 4096, reports AdminAction, and lands at the next term start.
/// 64 payloads of 992 fill a term exactly, with no PAD.
#[test]
fn pad_then_retry_and_exact_fill_vectors() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    buffer.limit().store(4 * TERM, Ordering::Release);
    let small = vec![1u8; 992];
    for _ in 0..60 {
        assert!(matches!(
            publication
                .append(&small, AppendOptions::default())
                .unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), 61_440);
    let big = vec![2u8; 8000];
    assert_eq!(
        publication.append(&big, AppendOptions::default()).unwrap(),
        AppendOutcome::AdminAction
    );
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), TERM);
    assert_eq!(
        publication.append(&big, AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { position: TERM }
    );
    let _ = conductor.duty_cycle().unwrap();

    let exact = new_buffer(config(2, 1)).unwrap();
    let mut exact_publication = exact.publication().unwrap().unwrap();
    exact.limit().store(4 * TERM, Ordering::Release);
    for _ in 0..64 {
        assert!(matches!(
            exact_publication
                .append(&small, AppendOptions::default())
                .unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    assert_eq!(exact.reserved_head().load(Ordering::Acquire), TERM);
    // The next append rotates without a PAD and reports AdminAction.
    assert_eq!(
        exact_publication
            .append(&small, AppendOptions::default())
            .unwrap(),
        AppendOutcome::AdminAction
    );
    assert_eq!(
        exact_publication
            .append(&small, AppendOptions::default())
            .unwrap(),
        AppendOutcome::Appended { position: TERM }
    );
}

#[test]
fn capabilities_are_issued_once_across_borrowed_and_owned_forms() {
    let buffer = Arc::new(new_buffer(config(2, 1)).unwrap());
    assert!(buffer.publication_owned().unwrap().is_some());
    assert!(buffer.publication().unwrap().is_none());
    assert!(buffer.publication_owned().unwrap().is_none());
    assert!(buffer.conductor().is_some());
    assert!(buffer.conductor_owned().is_none());
}

/// Owned capabilities keep the buffer alive after the creator's handle is
/// dropped, and work across threads.
#[test]
fn owned_capabilities_outlive_the_creating_handle() {
    let buffer = Arc::new(new_buffer(config(2, 1)).unwrap());
    let mut conductor = buffer.conductor_owned().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication_owned().unwrap().unwrap();
    drop(buffer);
    let count: u32 = if cfg!(miri) { 20 } else { 200 };
    std::thread::scope(|scope| {
        scope.spawn(move || {
            for sequence in 0..count {
                let data = message(sequence);
                loop {
                    match publication.append(&data, AppendOptions::default()).unwrap() {
                        AppendOutcome::Appended { .. } => break,
                        _ => std::thread::yield_now(),
                    }
                }
            }
        });
        scope.spawn(move || {
            let mut out = vec![0u8; 8192];
            let mut expected = 0;
            while expected < count {
                let _ = conductor.duty_cycle().unwrap();
                match subscription.poll(&mut out).unwrap() {
                    PollOutcome::Message { length, .. } => {
                        assert_eq!(&out[..length as usize], &message(expected)[..]);
                        subscription.acknowledge();
                        expected += 1;
                    }
                    PollOutcome::Pending => std::thread::yield_now(),
                    other => panic!("unexpected {other:?}"),
                }
            }
        });
    });
}

/// A required subscriber that does not acknowledge gets the same message
/// again and keeps bounding the publisher at the unacknowledged position;
/// acknowledging releases it.
#[test]
fn unacknowledged_messages_are_redelivered_and_keep_bounding() {
    let buffer = new_buffer(config(2, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = vec![4u8; 3000];
    let _ = publication.append(&data, AppendOptions::default()).unwrap();
    let mut out = vec![0u8; 8192];
    let first = required.poll(&mut out).unwrap();
    assert!(matches!(first, PollOutcome::Message { position: 0, .. }));
    // The handler failed: no acknowledgement. Redelivery, same position.
    assert_eq!(required.poll(&mut out).unwrap(), first);
    // The publisher stays bounded by the unacknowledged position.
    let mut pressured = false;
    for _ in 0..100 {
        let _ = conductor.duty_cycle().unwrap();
        if publication.append(&data, AppendOptions::default()).unwrap()
            == AppendOutcome::BackPressured
        {
            pressured = true;
            break;
        }
    }
    assert!(pressured);
    assert!(buffer.reserved_head().load(Ordering::Acquire) <= TERM / 2);
    assert_eq!(buffer.floor().load(Ordering::Acquire), 0);
    // Acknowledge, then the next poll moves on and the bound advances.
    required.acknowledge();
    assert!(matches!(
        required.poll(&mut out).unwrap(),
        PollOutcome::Message { position, .. } if position > 0
    ));
    required.acknowledge();
    let _ = conductor.duty_cycle().unwrap();
    assert!(buffer.floor().load(Ordering::Acquire) > 0);
}

/// A failed redelivery (short buffer) keeps the original pending end, so
/// acknowledging the original delivery still works; a crossing PAD
/// before the unacknowledged message is consumed on its own.
#[test]
fn failed_redelivery_keeps_the_pending_message() {
    let buffer = new_buffer(config(2, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    buffer.limit().store(4 * TERM, Ordering::Release);
    // Fill term 0 so the next message lands after a PAD in term 1.
    let filler = vec![1u8; 992];
    for _ in 0..60 {
        let _ = publication
            .append(&filler, AppendOptions::default())
            .unwrap();
    }
    let big = vec![2u8; 8000];
    assert_eq!(
        publication.append(&big, AppendOptions::default()).unwrap(),
        AppendOutcome::AdminAction
    );
    let _ = publication.append(&big, AppendOptions::default()).unwrap();
    let after = vec![3u8; 100];
    let _ = publication
        .append(&after, AppendOptions::default())
        .unwrap();
    let mut out = vec![0u8; 8192];
    for _ in 0..60 {
        assert!(matches!(
            required.poll(&mut out).unwrap(),
            PollOutcome::Message { .. }
        ));
        required.acknowledge();
    }
    // Crosses the PAD, delivers the 8000-byte message at the term start.
    let first = required.poll(&mut out).unwrap();
    assert!(
        matches!(first, PollOutcome::Message { position, length: 8000, .. } if position == TERM)
    );
    // Redelivery into a short buffer fails; the pending message and the
    // acknowledged position are preserved.
    let mut short = vec![0u8; 100];
    assert!(matches!(
        required.poll(&mut short),
        Err(SysError::BufferTooShort { .. })
    ));
    // The original delivery can still be acknowledged.
    required.acknowledge();
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(
        buffer.cells()[1].position.load(Ordering::Acquire),
        TERM + 8192
    );
    // The next poll delivers the following message, not the
    // acknowledged one again.
    assert!(matches!(
        required.poll(&mut out).unwrap(),
        PollOutcome::Message { position, length: 100, .. } if position == TERM + 8192
    ));
}

/// A required subscriber whose data is gone gets an error, never a
/// silent rejoin: its cursor and pending message stay put.
#[test]
fn a_required_subscriber_never_skips_silently() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&message(1), AppendOptions::default())
        .unwrap();
    // Force an impossible floor above the required position.
    buffer.floor().store(1, Ordering::Release);
    let mut out = vec![0u8; 8192];
    assert_eq!(
        required.poll(&mut out),
        Err(SysError::RequiredSubscriberLapped { position: 0 })
    );
    assert_eq!(required.position(), 0);
}

#[test]
fn traced_messages_return_their_extension() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let extension = [0x5Au8; 64];
    let options = AppendOptions {
        extension: Some(extension),
        ..AppendOptions::default()
    };
    let _ = publication.append(&message(1), options).unwrap();
    let _ = publication
        .append(&message(2), AppendOptions::default())
        .unwrap();
    let mut out = vec![0u8; 8192];
    assert!(matches!(
        subscription.poll(&mut out).unwrap(),
        PollOutcome::Message { extension: Some(bytes), .. } if bytes == extension
    ));
    subscription.acknowledge();
    assert!(matches!(
        subscription.poll(&mut out).unwrap(),
        PollOutcome::Message {
            extension: None,
            ..
        }
    ));
}

#[test]
fn capabilities_are_issued_once() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    assert!(buffer.publication().unwrap().is_some());
    assert!(buffer.publication().unwrap().is_none());
    assert!(buffer.conductor().is_some());
    assert!(buffer.conductor().is_none());
}

fn sized_message(sequence: u32, len: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..len).map(|i| (i as u8) ^ (sequence as u8)).collect();
    data[..4].copy_from_slice(&sequence.to_le_bytes());
    data
}

/// Publisher, conductor, a required and an optional subscriber on four
/// threads, with messages large enough to rotate through every slot and
/// reuse cleaned ones, also under Miri, which checks the loan, cleaning
/// and reuse orderings.
#[test]
fn concurrent_publication_reuse_and_subscribers() {
    let (total, len): (u32, usize) = if cfg!(miri) { (70, 7000) } else { (3000, 3000) };
    let buffer = new_buffer(config(3, 2)).unwrap();
    let slots = u64::from(buffer.slots);
    let published = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe(Role::Required).unwrap();
    let mut optional = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    std::thread::scope(|scope| {
        let conductor_thread = scope.spawn(|| {
            let mut cleaned = 0u32;
            while !finished.load(Ordering::Acquire) {
                cleaned += conductor.duty_cycle().unwrap().cleaned;
                std::thread::yield_now();
            }
            cleaned
        });
        scope.spawn(|| {
            for sequence in 0..total {
                let data = sized_message(sequence, len);
                loop {
                    match publication.append(&data, AppendOptions::default()).unwrap() {
                        AppendOutcome::Appended { .. } => break,
                        _ => std::thread::yield_now(),
                    }
                }
            }
            published.store(true, Ordering::Release);
        });
        let required_thread = scope.spawn(move || {
            let mut out = vec![0u8; 8192];
            let mut expected = 0u32;
            while expected < total {
                match required.poll(&mut out).unwrap() {
                    PollOutcome::Message { length, .. } => {
                        assert_eq!(&out[..length as usize], &sized_message(expected, len)[..]);
                        required.acknowledge();
                        expected += 1;
                    }
                    PollOutcome::Pending => std::thread::yield_now(),
                    other => panic!("unexpected {other:?}"),
                }
            }
            expected
        });
        let buffer = &buffer;
        let published = &published;
        let optional_thread = scope.spawn(move || {
            let mut out = vec![0u8; 8192];
            let mut last = None::<u32>;
            let (mut seen, mut lost) = (0u32, 0u64);
            loop {
                match optional.poll(&mut out).unwrap() {
                    PollOutcome::Message { length, .. } => {
                        let sequence = u32::from_le_bytes(out[..4].try_into().unwrap());
                        assert_eq!(&out[..length as usize], &sized_message(sequence, len)[..]);
                        if let Some(previous) = last {
                            assert!(sequence > previous);
                        }
                        last = Some(sequence);
                        seen += 1;
                    }
                    PollOutcome::Overrun { from, resume, .. } => lost += resume - from,
                    PollOutcome::Aborted { .. } => panic!("nothing was aborted"),
                    PollOutcome::Closed { .. } => panic!("not sealed"),
                    PollOutcome::Revoked { .. } => panic!("not revoked"),
                    PollOutcome::Skipped { .. } => panic!("not an image"),
                    PollOutcome::Pending => {
                        // Done once everything is published and the
                        // cursor reached the final head; receiving the
                        // last message is not required (it may be lost).
                        if published.load(Ordering::Acquire)
                            && optional.position()
                                >= buffer.reserved_head().load(Ordering::Acquire)
                        {
                            break (seen, lost);
                        }
                        std::thread::yield_now();
                    }
                }
            }
        });
        assert_eq!(required_thread.join().unwrap(), total);
        let (seen, lost) = optional_thread.join().unwrap();
        assert!(seen > 0 || lost > 0);
        finished.store(true, Ordering::Release);
        let cleaned = conductor_thread.join().unwrap();
        // Slots were cleaned and the term count passed the slot count, so
        // cleaned slots were rewritten while subscribers were running.
        assert!(cleaned > 0);
        assert!(buffer.active_count().load(Ordering::Acquire) >= slots);
    });
}

/// Every length from 1 to 64 bytes and the maximum, with and without the
/// extension, round-trips byte for byte; the maximum is fragmented.
#[test]
fn every_short_length_and_the_maximum_round_trip() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let maximum = buffer.max_message_length() as usize;
    // The extension is repeated in every fragment; a too-large append
    // writes nothing and reports the traced maximum.
    let traced = AppendOptions {
        extension: Some([0; EXTENSION_LENGTH as usize]),
        ..AppendOptions::default()
    };
    let Err(SysError::Layout(LayoutError::MessageTooLarge { max, .. })) =
        publication.append(&vec![0; maximum], traced)
    else {
        panic!("the untraced maximum fits with the extension");
    };
    let mut cases: Vec<(u8, usize)> = (1..=64).flat_map(|len| [(0, len), (1, len)]).collect();
    cases.push((0, maximum));
    cases.push((1, max as usize));
    let mut out = vec![0u8; maximum];
    for (round, len) in cases {
        let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31) ^ round).collect();
        let extension = [round.wrapping_add(len as u8); EXTENSION_LENGTH as usize];
        let options = AppendOptions {
            extension: (round == 1).then_some(extension),
            ..AppendOptions::default()
        };
        loop {
            match publication.append(&data, options).unwrap() {
                AppendOutcome::Appended { .. } => break,
                _ => {
                    let _ = conductor.duty_cycle().unwrap();
                }
            }
        }
        loop {
            match subscription.poll(&mut out).unwrap() {
                PollOutcome::Message {
                    length,
                    extension: got,
                    ..
                } => {
                    assert_eq!(&out[..length as usize], &data[..], "length {len}");
                    assert_eq!(got, options.extension);
                    subscription.acknowledge();
                    break;
                }
                PollOutcome::Pending => {
                    let _ = conductor.duty_cycle().unwrap();
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }
}

/// Frame starts and word 0s of the block at the start of slot 0.
fn frames(buffer: &LogBuffer<Terms>) -> Vec<(u32, Word0)> {
    let mut frames = Vec::new();
    let mut offset = 0;
    loop {
        // SAFETY: single-threaded test; slot 0 holds the published block.
        let raw = load_interior(unsafe { buffer.regions.word0(0, offset) });
        let word = Word0::unpack(raw).unwrap();
        frames.push((offset, word));
        if word.flags().end() {
            return frames;
        }
        offset += align_frame(word.frame_length() as u32).unwrap();
    }
}

/// A word 0 changed between the validating pass and the copying pass of a
/// block (possible on shared terms) is caught before its value is used.
#[test]
fn a_word0_changed_between_passes_is_corrupt() {
    let data = sized_message(9, 3000);
    let lane = Lane::ZERO;
    type Mutation = fn(Word0) -> u64;
    let mutations: [(&str, usize, Mutation); 8] = [
        // Same aligned extent (280 and 279 both reserve 288): only the
        // final length check sees it.
        ("lowered by one", 2, |w| {
            Word0::new(w.frame_length() - 1, w.flags(), FrameType::Data)
                .pack()
                .to_le()
        }),
        ("zero length", 1, |w| {
            Word0::new(0, w.flags(), FrameType::Data).pack().to_le()
        }),
        ("header-only first", 0, |w| {
            Word0::new(32, w.flags(), FrameType::Data).pack().to_le()
        }),
        ("past block end", 1, |w| {
            Word0::new(w.frame_length() + 4096, w.flags(), FrameType::Data)
                .pack()
                .to_le()
        }),
        ("END cleared", 2, |w| {
            let f = w.flags();
            Word0::new(w.frame_length(), Flags::new(f.begin(), false, false, f.ext(), f.lane()), FrameType::Data)
                .pack()
                .to_le()
        }),
        ("uncommitted", 1, |w| {
            Word0::new(-1, w.flags(), FrameType::Data).pack().to_le()
        }),
        ("pad", 1, |w| Word0::new(w.frame_length(), w.flags(), FrameType::Pad).pack().to_le()),
        ("BEGIN moved", 1, |w| {
            let f = w.flags();
            Word0::new(w.frame_length(), Flags::new(true, f.end(), f.eos(), f.ext(), f.lane()), FrameType::Data)
                .pack()
                .to_le()
        }),
    ];
    for (name, index, mutate) in mutations {
        let buffer = new_buffer(config(2, 1)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Required).unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        let _ = publication.append(&data, AppendOptions::default()).unwrap();
        let frames = frames(&buffer);
        assert_eq!(frames.len(), 3, "the message spans three fragments");
        assert_eq!(frames[2].1.frame_length(), 280);
        assert!(frames.iter().all(|(_, w)| w.flags().lane() == lane));
        let context = SubscriptionContext {
            buffer: &buffer,
            cursor: &mut subscription.cursor,
        };
        let Validated::Block(block) = context.validate_block(0, 0).unwrap() else {
            panic!("{name}: block not validated");
        };
        let (offset, word) = frames[index];
        // SAFETY: single-threaded test; a frame start of the block.
        unsafe { buffer.regions.word0(0, offset) }.store(mutate(word), Ordering::Relaxed);
        let mut out = vec![0u8; 8192];
        let result = context.copy_block(0, 0, block, &mut out);
        assert!(
            matches!(result, Err(SysError::CorruptTerm { .. })),
            "{name}: {result:?}"
        );
    }
}

// Claims (quantstratum-docs: karyos/design/claims.md).

fn claimed<O: BufferOwner + core::fmt::Debug>(outcome: Result<ClaimOutcome<'_, O>, SysError>) -> Claim<'_, O> {
    match outcome.unwrap() {
        ClaimOutcome::Claimed(claim) => claim,
        other => panic!("not claimed: {other:?}"),
    }
}

/// The raw first word 0 at `offset` of term 0 (slot 0).
fn word0_of_term0(buffer: &LogBuffer<Terms>, offset: u32) -> &AtomicU64 {
    // SAFETY: test-only peer access to a frame start of the active term 0,
    // only ever accessed atomically.
    unsafe { buffer.regions.word0(0, offset) }
}

#[test]
fn claim_and_commit_round_trip_alternating_with_append() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let extension = [9u8; EXTENSION_LENGTH as usize];
    let options = AppendOptions {
        end_of_stream: true,
        reserved_value: -5,
        extension: Some(extension),
    };
    let mut positions = Vec::new();
    for round in 0..4u8 {
        // Lengths with a partial last word.
        let length = 13 + u32::from(round) * 100;
        let mut claim = claimed(publication.try_claim(length, options));
        let payload = claim.payload();
        assert_eq!(payload.len(), length as usize);
        assert!(payload.iter().all(|byte| *byte == 0), "payload starts zeroed");
        payload.fill(round + 1);
        let position = claim.position();
        assert_eq!(claim.commit(), CommitOutcome::Committed { position });
        positions.push(position);
        let appended = publication
            .append(&message(u32::from(round)), AppendOptions::default())
            .unwrap();
        assert!(matches!(appended, AppendOutcome::Appended { .. }));
    }
    let mut out = vec![0u8; 8192];
    for round in 0..4u8 {
        match subscription.poll(&mut out).unwrap() {
            PollOutcome::Message {
                position,
                length,
                end_of_stream,
                reserved_value,
                extension: found,
            } => {
                assert_eq!(position, positions[usize::from(round)]);
                assert_eq!(length, 13 + u32::from(round) * 100);
                assert!(out[..length as usize].iter().all(|byte| *byte == round + 1));
                assert!(end_of_stream);
                assert_eq!(reserved_value, -5);
                assert_eq!(found, Some(extension));
            }
            other => panic!("unexpected {other:?}"),
        }
        subscription.acknowledge();
        assert_eq!(poll_message(&mut subscription), Some(message(u32::from(round))));
    }
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
}

#[test]
fn aborted_claims_are_skipped_without_acknowledgement() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe(Role::Required).unwrap();
    let mut optional = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication.append(&message(0), AppendOptions::default()).unwrap();
    // Explicit abort, then an abort by drop.
    let mut claim = claimed(publication.try_claim(100, AppendOptions::default()));
    claim.payload().fill(0xAB);
    let first = claim.position();
    claim.abort();
    let claim = claimed(publication.try_claim(40, AppendOptions::default()));
    let second = claim.position();
    drop(claim);
    let _ = publication.append(&message(1), AppendOptions::default()).unwrap();
    for subscription in [&mut required, &mut optional] {
        assert_eq!(poll_message(subscription), Some(message(0)));
        assert_eq!(
            poll(subscription),
            PollOutcome::Aborted {
                position: first,
                extent: 160,
            }
        );
        // No acknowledgement: the position is already past the extent.
        assert_eq!(subscription.acknowledged_position(), first + 160);
        assert_eq!(
            poll(subscription),
            PollOutcome::Aborted {
                position: second,
                extent: 96,
            }
        );
        assert_eq!(poll_message(subscription), Some(message(1)));
    }
}

#[test]
fn a_commit_that_loses_reports_aborted() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
    let position = claim.position();
    // Another party (standing in for the deadline abort) wins.
    let flags = Flags::new(true, true, false, false, Lane::ZERO);
    assert!(abort_block(
        word0_of_term0(&buffer, 0),
        Word0::new(-96, flags, FrameType::Data),
        Word0::new(96, Flags::NONE, FrameType::Aborted),
    ));
    // The writer may keep writing after the abort won; nobody reads it.
    claim.payload().fill(1);
    assert_eq!(poll(&mut subscription), PollOutcome::Aborted { position, extent: 96 });
    claim.payload().fill(2);
    assert_eq!(claim.commit(), CommitOutcome::Aborted { position });
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
}

#[test]
fn a_panic_inside_the_claim_aborts_it() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
        claim.payload()[0] = 1;
        panic!("encoder failed");
    }));
    assert!(result.is_err());
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 0,
            extent: 96,
        }
    );
    let _ = publication.append(&message(3), AppendOptions::default()).unwrap();
    assert_eq!(poll_message(&mut subscription), Some(message(3)));
}

#[test]
fn a_forgotten_claim_is_aborted_by_the_next_call() {
    for next in 0..4 {
        let buffer = new_buffer(config(3, 3)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Optional).unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
        claim.payload().fill(5);
        core::mem::forget(claim);
        // Still pending: the block is marked, not terminal.
        assert_eq!(poll(&mut subscription), PollOutcome::Pending);
        match next {
            0 => {
                let _ = publication.append(&message(4), AppendOptions::default()).unwrap();
            }
            1 => {
                let claim = claimed(publication.try_claim(8, AppendOptions::default()));
                assert_eq!(claim.position(), 96);
                core::mem::forget(claim);
            }
            2 => publication.close(),
            _ => drop(publication),
        }
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Aborted {
                position: 0,
                extent: 96,
            }
        );
        if next == 0 {
            assert_eq!(poll_message(&mut subscription), Some(message(4)));
        }
        // Close and drop end the publication's accesses: its write loan is
        // released, after the claim was resolved.
        let held = buffer.cell(0).unwrap().loan.load(Ordering::SeqCst) != 0;
        assert_eq!(held, next < 2);
    }
}

#[test]
fn closing_the_publication_resolves_its_claim_then_releases_its_loan() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    // Fill term 0 and move the publication's loan to term 1.
    let mut sequence = 0;
    while buffer.active_count().load(Ordering::Acquire) == 0 {
        let _ = append_retrying(&mut publication, &mut conductor, &message(sequence), || {});
        while poll_message(&mut subscription).is_some() {}
        sequence += 1;
    }
    let active = buffer.active_count().load(Ordering::Acquire) as u32;
    let Lookup::Slot(slot) = buffer.lookup(TermCount::try_new(active).unwrap()).unwrap() else {
        panic!("active term without a slot");
    };
    let claim = claimed(publication.try_claim(64, AppendOptions::default()));
    core::mem::forget(claim);
    let index = SlotIndex::try_new(slot).unwrap();
    let descriptor = Descriptor::decode(
        buffer
            .descriptor(slot)
            .unwrap()
            .load(Ordering::Acquire),
    )
    .unwrap();
    let held = |buffer: &LogBuffer<Terms>| {
        loan_held(
            core::slice::from_ref(&buffer.cell(0).unwrap().loan),
            index,
            descriptor.with_state(SlotState::Reclaiming),
        )
        .unwrap()
    };
    assert!(held(&buffer));
    publication.close();
    assert!(!held(&buffer), "the write loan survived close");
    // The forgotten claim was aborted before the loan was released.
    assert!(matches!(poll(&mut subscription), PollOutcome::Aborted { extent: 96, .. }));
}

#[test]
fn claims_at_the_term_end_pad_and_rotate() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut committed = 0u32;
    let mut admin = 0;
    while committed < 200 {
        let _ = conductor.duty_cycle().unwrap();
        while poll_message(&mut subscription).is_some() {}
        match publication.try_claim(1000, AppendOptions::default()).unwrap() {
            ClaimOutcome::Claimed(mut claim) => {
                claim.payload()[..4].copy_from_slice(&committed.to_le_bytes());
                let position = claim.position();
                // Never across a term boundary.
                assert_eq!(position / TERM, (position + 1056 - 1) / TERM);
                assert!(matches!(claim.commit(), CommitOutcome::Committed { .. }));
                committed += 1;
            }
            ClaimOutcome::AdminAction => admin += 1,
            ClaimOutcome::BackPressured => {}
            ClaimOutcome::Aborted { .. } => panic!("nothing aborts"),
            ClaimOutcome::Closed | ClaimOutcome::Gated => panic!("not sealed"),
        }
    }
    assert!(admin > 0, "the claims never reached a term end");
}

#[test]
fn claim_sizes_are_checked() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let with_extension = AppendOptions {
        extension: Some([0u8; EXTENSION_LENGTH as usize]),
        ..AppendOptions::default()
    };
    assert!(matches!(
        publication.try_claim(0, AppendOptions::default()),
        Err(SysError::EmptyMessage)
    ));
    // One fragment of the MTU: 1408 - 32 without, 1408 - 96 with the
    // extension.
    for (options, max) in [(AppendOptions::default(), 1376), (with_extension, 1312)] {
        assert!(matches!(
            publication.try_claim(max + 1, options),
            Err(SysError::Layout(LayoutError::MessageTooLarge { .. }))
        ));
        let mut claim = claimed(publication.try_claim(max, options));
        assert_eq!(claim.payload().len(), max as usize);
        claim.abort();
    }
    // A buffer whose reservation limit is below one fragment.
    let small = new_buffer(LogBufferConfig {
        max_reserved: 512,
        ..config(3, 3)
    })
    .unwrap();
    let mut publication = small.publication().unwrap().unwrap();
    let max = small.max_message_length();
    assert_eq!(max, 512 - 32);
    assert!(matches!(
        publication.try_claim(max + 1, AppendOptions::default()),
        Err(SysError::Layout(LayoutError::MessageTooLarge { .. }))
    ));
    assert!(matches!(
        publication.try_claim(max - 64 + 1, with_extension),
        Err(SysError::Layout(LayoutError::MessageTooLarge { .. }))
    ));
    claimed(publication.try_claim(max, AppendOptions::default())).abort();
}

#[test]
fn claims_are_back_pressured() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _required = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut pressured = false;
    for _ in 0..2000 {
        let _ = conductor.duty_cycle().unwrap();
        match publication.try_claim(1000, AppendOptions::default()).unwrap() {
            ClaimOutcome::Claimed(claim) => {
                let _ = claim.commit();
            }
            ClaimOutcome::BackPressured => {
                pressured = true;
                break;
            }
            ClaimOutcome::AdminAction => {}
            ClaimOutcome::Aborted { .. } => panic!("nothing aborts"),
            ClaimOutcome::Closed | ClaimOutcome::Gated => panic!("not sealed"),
        }
    }
    assert!(pressured);
    assert!(buffer.reserved_head().load(Ordering::Acquire) <= TERM / 2);
}

#[test]
fn aborted_words_are_validated() {
    let lane = Lane::try_new(2).unwrap();
    let make = || {
        new_buffer(LogBufferConfig {
            lane,
            ..config(3, 3)
        })
        .unwrap()
    };
    let raw = |length: i32, flags: u8, version: u8| {
        u64::from(length as u32)
            | (u64::from(version) << 32)
            | (u64::from(flags) << 40)
            | (u64::from(FrameType::Aborted.code()) << 48)
    };
    let lane_flags = Flags::new(false, false, false, false, lane).get();
    let other_lane = Flags::new(false, false, false, false, Lane::ZERO).get();
    let reserved_bits = lane_flags | 0x40;
    // Valid: the claim's own flags, BEGIN/END set, and an extent larger
    // than `max_reserved` inside the term.
    let begin_end = Flags::new(true, true, true, true, lane).get();
    let big = 8192 * 4;
    assert!(big > MIN_TERM_LENGTH / 8);
    for (word, extent) in [
        (raw(96, lane_flags, PROTOCOL_VERSION), 96),
        (raw(96, begin_end, PROTOCOL_VERSION), 96),
        (raw(big as i32, lane_flags, PROTOCOL_VERSION), big),
        (raw(TERM as i32, lane_flags, PROTOCOL_VERSION), TERM as u32),
    ] {
        let buffer = make();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Required).unwrap();
        word0_of_term0(&buffer, 0).store(word.to_le(), Ordering::Release);
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Aborted {
                position: 0,
                extent,
            }
        );
        assert_eq!(subscription.acknowledged_position(), u64::from(extent));
    }
    // Zero or negative lengths are pending, whatever the type bits say.
    for word in [raw(0, lane_flags, PROTOCOL_VERSION), raw(-96, 0xFF, 0)] {
        let buffer = make();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Required).unwrap();
        word0_of_term0(&buffer, 0).store(word.to_le(), Ordering::Release);
        assert_eq!(poll(&mut subscription), PollOutcome::Pending);
    }
    // Corrupt: nothing advances or is acknowledged.
    for word in [
        raw(96, lane_flags, PROTOCOL_VERSION + 1),
        raw(96, reserved_bits, PROTOCOL_VERSION),
        raw(96, other_lane, PROTOCOL_VERSION),
        raw(100, lane_flags, PROTOCOL_VERSION),
        raw(TERM as i32 + 32, lane_flags, PROTOCOL_VERSION),
    ] {
        let buffer = make();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Required).unwrap();
        word0_of_term0(&buffer, 0).store(word.to_le(), Ordering::Release);
        let mut out = vec![0u8; 64];
        assert!(matches!(
            subscription.poll(&mut out),
            Err(SysError::CorruptTerm { .. })
        ));
        assert_eq!(subscription.position(), 0);
        assert_eq!(subscription.acknowledged_position(), 0);
        assert_eq!(buffer.cell(1).unwrap().position.load(Ordering::Acquire), 0);
    }
}

#[test]
fn the_claim_staging_is_sized_by_the_largest_admissible_claim() {
    // An MTU far above the reservation limit.
    let buffer = new_buffer(LogBufferConfig {
        mtu: 1 << 20,
        ..config(3, 3)
    })
    .unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let max = buffer.max_message_length();
    assert_eq!(max, MIN_TERM_LENGTH / 8 - 32);
    let expected = if <Terms as crate::term_bytes::sealed::Access>::DIRECT {
        0
    } else {
        max as usize
    };
    assert_eq!(publication.staging.len(), expected);
    let mut claim = claimed(publication.try_claim(max, AppendOptions::default()));
    assert_eq!(claim.payload().len(), max as usize);
    claim.payload().fill(3);
    assert!(matches!(claim.commit(), CommitOutcome::Committed { .. }));
}

// Commit-deadline abort (quantstratum-docs: karyos/design/claim-deadline.md).

const DEADLINE: u64 = 100;

fn deadline_config(claim_deadline: u64) -> LogBufferConfig {
    LogBufferConfig {
        claim_deadline,
        ..config(3, 3)
    }
}

#[test]
fn a_zero_claim_deadline_is_refused() {
    assert!(matches!(
        new_buffer(deadline_config(0)),
        Err(SysError::InvalidClaimDeadline { value: 0 })
    ));
}

#[test]
fn the_deadline_aborts_a_marked_claim_at_exactly_the_deadline() {
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    assert_eq!(conductor.abort_expired_claims(0).unwrap(), ClaimDeadline::Idle);
    let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
    let position = claim.position();
    assert_eq!(conductor.abort_expired_claims(10).unwrap(), ClaimDeadline::Waiting);
    assert_eq!(
        conductor.abort_expired_claims(10 + DEADLINE - 1).unwrap(),
        ClaimDeadline::Waiting
    );
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
    assert_eq!(
        conductor.abort_expired_claims(10 + DEADLINE).unwrap(),
        ClaimDeadline::Aborted {
            position,
            extent: 96,
        }
    );
    // The writer keeps writing; nobody reads it; its commit loses.
    claim.payload().fill(7);
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position,
            extent: 96,
        }
    );
    claim.payload().fill(8);
    assert_eq!(claim.commit(), CommitOutcome::Aborted { position });
    // The record was cleared after the terminal compare-exchange.
    assert_eq!(conductor.abort_expired_claims(u64::MAX).unwrap(), ClaimDeadline::Idle);
}

/// SPEC.md §13 "Commit versus abort" under concurrency (issue #69): a
/// writer, the deadline aborter with the reclaimer (the conductor's duty
/// cycle) and a required reader on three threads, also under Miri's data
/// race detector. The writer pauses after marking, while writing and just
/// before commit; every eleventh claim waits for the deadline abort and its
/// commit must lose; every seventh is forgotten in the live process and
/// aborted by the next call. The reader sees exactly the writer's decisions:
/// a committed claim's bytes, or an aborted block it never reads.
#[test]
fn concurrent_claims_race_the_deadline_the_reader_and_the_reclaimer() {
    let (total, len): (u32, u32) = if cfg!(miri) { (150, 1024) } else { (3000, 1024) };
    let buffer = new_buffer(deadline_config(50)).unwrap();
    let written = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    let aborts = AtomicU64::new(0);
    // The position of the deadline's last abort, plus one.
    let last_abort = AtomicU64::new(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    std::thread::scope(|scope| {
        let duty = scope.spawn(|| {
            let mut now = 0u64;
            let mut cleaned = 0;
            while !finished.load(Ordering::Acquire) {
                now += 1;
                if let ClaimDeadline::Aborted { position, .. } =
                    conductor.abort_expired_claims(now).unwrap()
                {
                    aborts.fetch_add(1, Ordering::AcqRel);
                    last_abort.store(position + 1, Ordering::Release);
                }
                cleaned += conductor.duty_cycle().unwrap().cleaned;
                std::thread::yield_now();
            }
            cleaned
        });
        let writer = scope.spawn(|| {
            // Per block: its position, and the sequence it committed.
            let mut decided = Vec::new();
            let mut sequence = 0;
            while sequence < total {
                match publication.try_claim(len, AppendOptions::default()).unwrap() {
                    ClaimOutcome::Claimed(mut claim) => {
                        let position = claim.position();
                        let data = sized_message(sequence, len as usize);
                        let half = data.len() / 2;
                        std::thread::yield_now();
                        claim.payload()[..half].copy_from_slice(&data[..half]);
                        std::thread::yield_now();
                        claim.payload()[half..].copy_from_slice(&data[half..]);
                        if sequence % 7 == 6 {
                            // Forgotten: the next call aborts it.
                            core::mem::forget(claim);
                            decided.push((position, None));
                        } else {
                            if sequence % 11 == 10 {
                                // The deadline aborts this claim first.
                                while last_abort.load(Ordering::Acquire) != position + 1 {
                                    std::thread::yield_now();
                                }
                            }
                            std::thread::yield_now();
                            match claim.commit() {
                                CommitOutcome::Committed { position: at } => {
                                    assert_ne!(sequence % 11, 10, "a commit after the abort won");
                                    assert_eq!(at, position);
                                    decided.push((position, Some(sequence)));
                                }
                                CommitOutcome::Aborted { position: at } => {
                                    assert_eq!(at, position);
                                    decided.push((position, None));
                                }
                            }
                        }
                        sequence += 1;
                    }
                    // Aborted before it was marked: nothing was written.
                    ClaimOutcome::Aborted { position } => decided.push((position, None)),
                    _ => std::thread::yield_now(),
                }
            }
            publication.close();
            written.store(true, Ordering::Release);
            decided
        });
        let mut seen = Vec::new();
        let mut out = vec![0u8; len as usize];
        loop {
            match subscription.poll(&mut out).unwrap() {
                PollOutcome::Message {
                    position, length, ..
                } => {
                    let sequence = u32::from_le_bytes(out[..4].try_into().unwrap());
                    assert_eq!(&out[..length as usize], &sized_message(sequence, len as usize)[..]);
                    subscription.acknowledge();
                    seen.push((position, Some(sequence)));
                }
                PollOutcome::Aborted { position, .. } => seen.push((position, None)),
                PollOutcome::Pending => {
                    // A failed writer ends the run; its join reports why.
                    if writer.is_finished() && !written.load(Ordering::Acquire) {
                        break;
                    }
                    if written.load(Ordering::Acquire)
                        && subscription.position() >= buffer.reserved_head().load(Ordering::Acquire)
                    {
                        break;
                    }
                    std::thread::yield_now();
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        finished.store(true, Ordering::Release);
        let decided = writer.join().unwrap();
        let cleaned = duty.join().unwrap();
        assert_eq!(seen, decided);
        assert!(cleaned > 0, "nothing was reclaimed");
        // At least every claim that waited for the deadline was aborted by it.
        let waited = (0..total).filter(|s| s % 11 == 10 && s % 7 != 6).count();
        assert!(aborts.load(Ordering::Acquire) >= waited as u64);
    });
}

#[test]
fn the_deadline_aborts_claims_with_end_of_stream_and_extension() {
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let options = AppendOptions {
        end_of_stream: true,
        reserved_value: 3,
        extension: Some([1u8; EXTENSION_LENGTH as usize]),
    };
    let claim = claimed(publication.try_claim(8, options));
    assert_eq!(conductor.abort_expired_claims(0).unwrap(), ClaimDeadline::Waiting);
    assert!(matches!(
        conductor.abort_expired_claims(DEADLINE).unwrap(),
        ClaimDeadline::Aborted { extent: 128, .. }
    ));
    assert!(matches!(claim.commit(), CommitOutcome::Aborted { .. }));
}

#[test]
fn an_admitted_claim_paused_before_its_mark_is_aborted_and_writes_nothing() {
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut seen = Vec::new();
    let outcome = publication
        .try_claim_pausing(64, AppendOptions::default(), &mut |point| {
            if point == ClaimPause::BeforeMark {
                seen.push(conductor.abort_expired_claims(0).unwrap());
                seen.push(conductor.abort_expired_claims(DEADLINE).unwrap());
            }
        })
        .unwrap();
    assert_eq!(
        seen,
        [
            ClaimDeadline::Waiting,
            ClaimDeadline::Aborted {
                position: 0,
                extent: 96,
            }
        ]
    );
    assert!(matches!(outcome, ClaimOutcome::Aborted { position: 0 }));
    drop(outcome);
    // Nothing but the aborted word was written: the header stays clean.
    let mut header = [0u8; 24];
    // SAFETY: test-only read of bytes 8..32 of the aborted block of the
    // active term; nothing writes them.
    unsafe { buffer.regions.read_bytes(0, 8, &mut header) };
    assert_eq!(header, [0u8; 24]);
    assert_eq!(conductor.abort_expired_claims(u64::MAX).unwrap(), ClaimDeadline::Idle);
    // The reservation stays consumed; the required reader skips it.
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 0,
            extent: 96,
        }
    );
    let _ = publication.append(&message(1), AppendOptions::default()).unwrap();
    assert_eq!(poll_message(&mut subscription), Some(message(1)));
    publication.close();
}

#[test]
fn a_claim_before_its_head_store_is_not_admitted() {
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut seen = Vec::new();
    let mut required = None;
    let mut limit = 0;
    let outcome = publication
        .try_claim_pausing(64, AppendOptions::default(), &mut |point| {
            if point == ClaimPause::BeforeHead {
                seen.push(conductor.abort_expired_claims(0).unwrap());
                seen.push(conductor.abort_expired_claims(u64::MAX).unwrap());
                let _ = conductor.duty_cycle().unwrap();
                limit = buffer.limit().load(Ordering::Acquire);
                // A required subscriber admitted at the unmoved head.
                required = Some(conductor.subscribe(Role::Required).unwrap());
            }
        })
        .unwrap();
    assert_eq!(seen, [ClaimDeadline::Idle, ClaimDeadline::Idle]);
    let ClaimOutcome::Claimed(claim) = outcome else {
        panic!("not claimed");
    };
    // Admitted now: timed from its first observation and aborted.
    assert_eq!(conductor.abort_expired_claims(5).unwrap(), ClaimDeadline::Waiting);
    assert!(matches!(
        conductor.abort_expired_claims(5 + DEADLINE).unwrap(),
        ClaimDeadline::Aborted { position: 0, .. }
    ));
    drop(claim);
    let mut required = required.unwrap();
    assert!(matches!(poll(&mut required), PollOutcome::Aborted { position: 0, extent: 96 }));
    let _ = conductor.duty_cycle().unwrap();
    // The limit never goes below one already granted.
    assert!(buffer.limit().load(Ordering::Acquire) >= limit);
    let _late = conductor.subscribe(Role::Required).unwrap();
    let _ = conductor.duty_cycle().unwrap();
    assert!(buffer.limit().load(Ordering::Acquire) >= limit);
}

#[test]
fn the_claim_timer_follows_the_clock() {
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let claim = claimed(publication.try_claim(8, AppendOptions::default()));
    assert_eq!(conductor.abort_expired_claims(1000).unwrap(), ClaimDeadline::Waiting);
    // Back: re-anchored, never earlier.
    assert_eq!(
        conductor.abort_expired_claims(500).unwrap(),
        ClaimDeadline::ClockWentBack
    );
    assert_eq!(
        conductor.abort_expired_claims(1000 + DEADLINE).unwrap(),
        ClaimDeadline::Aborted {
            position: 0,
            extent: 64,
        }
    );
    // Already aborted: an expired, terminal claim is resolved.
    assert_eq!(
        conductor.abort_expired_claims(2000).unwrap(),
        ClaimDeadline::Resolved
    );
    drop(claim);
    // A new claim of equal size restarts the timer.
    let claim = claimed(publication.try_claim(8, AppendOptions::default()));
    assert_eq!(conductor.abort_expired_claims(5000).unwrap(), ClaimDeadline::Waiting);
    assert_eq!(
        conductor.abort_expired_claims(5000 + DEADLINE - 1).unwrap(),
        ClaimDeadline::Waiting
    );
    assert!(matches!(claim.commit(), CommitOutcome::Committed { .. }));
    assert_eq!(conductor.abort_expired_claims(u64::MAX).unwrap(), ClaimDeadline::Idle);
}

/// `service_deadlines` on an exclusive buffer reports each legacy
/// outcome as one count; only `Waiting` sets `waiting`.
#[test]
fn the_exclusive_deadline_report_matches_the_legacy_outcome() {
    let at = |now: u64| move || now;
    let report = |conductor: &mut Conductor<_>, now: u64| {
        conductor.service_deadlines(&mut at(now)).unwrap()
    };
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    assert_eq!(report(&mut conductor, 0), DeadlineReport::default());
    let claim = claimed(publication.try_claim(8, AppendOptions::default()));
    assert_eq!(
        report(&mut conductor, 1000),
        DeadlineReport {
            waiting: true,
            ..DeadlineReport::default()
        }
    );
    assert_eq!(
        report(&mut conductor, 500),
        DeadlineReport {
            clock_went_back: 1,
            ..DeadlineReport::default()
        }
    );
    assert_eq!(
        report(&mut conductor, 1000 + DEADLINE),
        DeadlineReport {
            aborted: 1,
            aborted_bytes: 64,
            ..DeadlineReport::default()
        }
    );
    assert_eq!(
        report(&mut conductor, 2000 + DEADLINE),
        DeadlineReport {
            resolved: 1,
            ..DeadlineReport::default()
        }
    );
    drop(claim);
    assert_eq!(report(&mut conductor, u64::MAX), DeadlineReport::default());

    let buffer = new_buffer(deadline_config(u64::MAX)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let _claim = claimed(publication.try_claim(8, AppendOptions::default()));
    assert_eq!(
        report(&mut conductor, 1),
        DeadlineReport {
            unrepresentable: 1,
            ..DeadlineReport::default()
        }
    );
}

#[test]
fn an_unrepresentable_expiry_is_reported() {
    let buffer = new_buffer(deadline_config(u64::MAX)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let claim = claimed(publication.try_claim(8, AppendOptions::default()));
    assert_eq!(
        conductor.abort_expired_claims(1).unwrap(),
        ClaimDeadline::Unrepresentable
    );
    assert_eq!(
        conductor.abort_expired_claims(u64::MAX).unwrap(),
        ClaimDeadline::Unrepresentable
    );
    drop(claim);
    // Exactly `first_seen + deadline = u64::MAX`: expires at `u64::MAX`.
    let claim = claimed(publication.try_claim(8, AppendOptions::default()));
    assert_eq!(conductor.abort_expired_claims(0).unwrap(), ClaimDeadline::Waiting);
    assert_eq!(
        conductor.abort_expired_claims(u64::MAX - 1).unwrap(),
        ClaimDeadline::Waiting
    );
    assert!(matches!(
        conductor.abort_expired_claims(u64::MAX).unwrap(),
        ClaimDeadline::Aborted { .. }
    ));
    assert!(matches!(claim.commit(), CommitOutcome::Aborted { .. }));
}

#[test]
fn a_forgotten_claim_aborted_at_the_deadline_is_resolved_by_the_next_call() {
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    core::mem::forget(claimed(publication.try_claim(64, AppendOptions::default())));
    assert_eq!(conductor.abort_expired_claims(0).unwrap(), ClaimDeadline::Waiting);
    assert!(matches!(
        conductor.abort_expired_claims(DEADLINE).unwrap(),
        ClaimDeadline::Aborted { .. }
    ));
    // The loan is still held until the next call resolves the claim.
    assert_ne!(buffer.cell(0).unwrap().loan.load(Ordering::SeqCst), 0);
    let _ = publication.append(&message(2), AppendOptions::default()).unwrap();
    assert_eq!(conductor.abort_expired_claims(u64::MAX).unwrap(), ClaimDeadline::Idle);
    assert!(matches!(poll(&mut subscription), PollOutcome::Aborted { .. }));
    assert_eq!(poll_message(&mut subscription), Some(message(2)));
}

#[test]
fn claims_stop_when_the_record_serial_would_run_out() {
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    // A resting serial is a multiple of four; this one leaves room for
    // exactly one more claim.
    buffer.claim_serial().store(u64::MAX - 7, Ordering::Relaxed);
    let claim = claimed(publication.try_claim(8, AppendOptions::default()));
    // The last claim is observable and abortable.
    assert_eq!(conductor.abort_expired_claims(0).unwrap(), ClaimDeadline::Waiting);
    assert!(matches!(
        conductor.abort_expired_claims(DEADLINE).unwrap(),
        ClaimDeadline::Aborted { .. }
    ));
    claim.abort();
    assert_eq!(buffer.claim_serial().load(Ordering::Relaxed), u64::MAX - 3);
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert!(matches!(
        publication.try_claim(8, AppendOptions::default()),
        Err(SysError::ResourcesUnavailable)
    ));
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), head);
    // Offers are unaffected.
    assert!(matches!(
        publication.append(&message(0), AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { .. }
    ));
}

#[test]
fn the_last_claim_the_serial_admits_can_be_forgotten() {
    for close in [false, true] {
        let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Optional).unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        buffer.claim_serial().store(u64::MAX - 7, Ordering::Relaxed);
        core::mem::forget(claimed(publication.try_claim(8, AppendOptions::default())));
        // The last admitted claim is observable before it is resolved.
        assert_eq!(conductor.abort_expired_claims(0).unwrap(), ClaimDeadline::Waiting);
        if close {
            publication.close();
        } else {
            let head = buffer.reserved_head().load(Ordering::Acquire);
            // The next call resolves the forgotten claim (its clear fits),
            // then refuses the new claim without moving the head.
            assert!(matches!(
                publication.try_claim(8, AppendOptions::default()),
                Err(SysError::ResourcesUnavailable)
            ));
            assert_eq!(buffer.reserved_head().load(Ordering::Acquire), head);
        }
        assert_eq!(buffer.claim_serial().load(Ordering::Relaxed), u64::MAX - 3);
        assert_eq!(conductor.abort_expired_claims(u64::MAX).unwrap(), ClaimDeadline::Idle);
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Aborted {
                position: 0,
                extent: 64,
            }
        );
    }
}

#[test]
fn the_clock_is_read_only_after_an_admitted_claim_is_observed() {
    let buffer = new_buffer(deadline_config(DEADLINE)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut reads = 0;
    let mut clock = || {
        reads += 1;
        7
    };
    assert_eq!(
        conductor.abort_expired_claims_with(&mut clock).unwrap(),
        ClaimDeadline::Idle
    );
    let mut seen = Vec::new();
    let outcome = publication
        .try_claim_pausing(8, AppendOptions::default(), &mut |point| {
            if point == ClaimPause::BeforeHead {
                // Not admitted: the clock is not read.
                seen.push(conductor.abort_expired_claims_with(&mut || panic!("read")).unwrap());
            }
        })
        .unwrap();
    assert_eq!(seen, [ClaimDeadline::Idle]);
    assert_eq!(
        conductor.abort_expired_claims_with(&mut clock).unwrap(),
        ClaimDeadline::Waiting
    );
    assert_eq!(reads, 1);
    assert_eq!(
        conductor
            .abort_expired_claims_with(&mut || 7 + DEADLINE)
            .unwrap(),
        ClaimDeadline::Aborted {
            position: 0,
            extent: 64,
        }
    );
    drop(outcome);
}

/// The test hook fails the deadline call before it touches anything, also
/// with 128 slots and a real claim present.
#[cfg(feature = "test-hooks")]
#[test]
fn an_injected_deadline_fault_leaves_the_protocol_state_intact() {
    let buffer = new_buffer(LogBufferConfig {
        spare_slots: 125,
        ..deadline_config(DEADLINE)
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut claim = claimed(publication.try_claim(8, AppendOptions::default()));
    let serial = buffer.claim_serial().load(Ordering::Relaxed);
    let record = buffer.claim_record().load(Ordering::Relaxed);
    let loan = buffer.cell(0).unwrap().loan.load(Ordering::SeqCst);
    let word = word0_of_term0(&buffer, 0).load(Ordering::Acquire);
    buffer.inject_deadline_fault();
    assert!(matches!(
        conductor.abort_expired_claims_with(&mut || panic!("clock read")),
        Err(SysError::ResourcesUnavailable)
    ));
    assert_eq!(
        conductor.service_deadlines(&mut || panic!("clock read")),
        Err(DeadlineError {
            report: DeadlineReport::default(),
            error: SysError::ResourcesUnavailable,
        })
    );
    assert_eq!(buffer.claim_serial().load(Ordering::Relaxed), serial);
    assert_eq!(buffer.claim_record().load(Ordering::Relaxed), record);
    assert_eq!(buffer.cell(0).unwrap().loan.load(Ordering::SeqCst), loan);
    assert_eq!(word0_of_term0(&buffer, 0).load(Ordering::Acquire), word);
    claim.payload().fill(1);
    assert!(matches!(claim.commit(), CommitOutcome::Committed { .. }));
}

// Concurrent mode, batch a1 (quantstratum-docs: karyos/design/concurrent-publication.md).

/// Infrastructure fixture: allows targets without LSE, so the tests run
/// everywhere; the LSE refusal is tested explicitly.
fn concurrent_config(publishers: u8) -> LogBufferConfig {
    LogBufferConfig {
        publication: PublicationMode::Concurrent {
            publishers,
            allow_non_lse: true,
        },
        // 3 publishers + 2 optional subscribers fit S - C = 5.
        ..config(6, 4)
    }
}

#[test]
fn concurrent_mode_creation_checks() {
    assert!(new_buffer(concurrent_config(3)).is_ok());
    assert!(matches!(
        new_buffer(concurrent_config(0)),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    // 5 × 8192 > 65536 / 2.
    assert!(matches!(
        new_buffer(concurrent_config(5)),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    // More publishers than spare credits.
    let tight = LogBufferConfig {
        publication: PublicationMode::Concurrent {
            publishers: 3,
            allow_non_lse: false,
        },
        ..config(3, 4)
    };
    assert!(matches!(new_buffer(tight), Err(SysError::ResourcesUnavailable)));
    // Without a single-instruction fetch_add only with explicit allowance.
    let config = LogBufferConfig {
        publication: PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: false,
        },
        ..concurrent_config(2)
    };
    assert!(check_publication_mode_on(&config, true).is_ok());
    assert!(matches!(
        check_publication_mode_on(&config, false),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    let allowed = LogBufferConfig {
        publication: PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: true,
        },
        ..config
    };
    assert!(check_publication_mode_on(&allowed, false).is_ok());
}

#[test]
fn a_concurrent_buffer_has_no_exclusive_publication() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    assert!(matches!(
        buffer.publication(),
        Err(SysError::InvalidPublicationMode { .. })
    ));
}

#[test]
fn publisher_credits_are_reserved_for_the_buffer_life() {
    let buffer = new_buffer(concurrent_config(3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    // S - C = 5: 3 publishers + 2 optional subscribers exactly.
    let first = conductor.subscribe(Role::Optional).unwrap();
    let _second = conductor.subscribe(Role::Optional).unwrap();
    let before = buffer.attached_subscribers();
    assert!(matches!(
        conductor.subscribe(Role::Optional),
        Err(SysError::ResourcesUnavailable)
    ));
    assert_eq!(buffer.attached_subscribers(), before);
    // A required subscriber takes no credit.
    let _required = conductor.subscribe(Role::Required).unwrap();
    drop(first);
    let _third = conductor.subscribe(Role::Optional).unwrap();
}

#[test]
fn the_concurrent_head_is_derived_from_the_active_tail() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let t0 = u64::from(buffer.initial_term_id.get());
    assert_eq!(buffer.head().unwrap(), Some(0));
    // A reservation of 96 bytes in term 0.
    buffer.tail(0).unwrap().store((t0 << 32) | 96, Ordering::Release);
    assert_eq!(buffer.head().unwrap(), Some(96));
    // The limit derives from that head and the concurrent window.
    let _ = conductor.duty_cycle().unwrap();
    let window = TERM / 2 - 8192;
    assert_eq!(buffer.limit().load(Ordering::Acquire), 96 + window);
    // Past the end: clamped to the term end.
    buffer
        .tail(0)
        .unwrap()
        .store((t0 << 32) | (TERM + 500), Ordering::Release);
    assert_eq!(buffer.head().unwrap(), Some(TERM));
    // A tail of another term identity yields no head.
    buffer
        .tail(0)
        .unwrap()
        .store(((t0 + 5) << 32) | 64, Ordering::Release);
    assert_eq!(buffer.head().unwrap(), None);
    assert!(matches!(
        conductor.duty_cycle(),
        Err(SysError::CorruptTerm { .. })
    ));
}

#[test]
fn the_conductor_rotates_a_full_concurrent_term_and_prepares_tails() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let t0 = u64::from(buffer.initial_term_id.get());
    let limit = buffer.limit().load(Ordering::Acquire);
    buffer
        .tail(0)
        .unwrap()
        .store((t0 << 32) | TERM, Ordering::Release);
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    // Term 1 (slot 1) starts empty; the next term's tail is prepared with
    // its own identity.
    assert_eq!(buffer.head().unwrap(), Some(TERM));
    let _ = conductor.duty_cycle().unwrap();
    let Lookup::Slot(slot) = buffer.lookup(TermCount::try_new(2).unwrap()).unwrap() else {
        panic!("term 2 not prepared");
    };
    let t2 = buffer
        .initial_term_id
        .advanced_by(TermCount::try_new(2).unwrap());
    assert_eq!(
        buffer.tail(slot).unwrap().load(Ordering::Acquire),
        u64::from(t2.get()) << 32
    );
    assert!(buffer.limit().load(Ordering::Acquire) >= limit);
}

#[test]
fn the_deadline_service_is_idle_for_concurrent_buffers() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    assert!(matches!(
        conductor.abort_expired_claims_with(&mut || panic!("clock read")),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    assert_eq!(
        conductor
            .service_deadlines(&mut || panic!("clock read"))
            .unwrap(),
        DeadlineReport::default()
    );
}

/// A rejoin never resumes inside the range it reports lost, even when the
/// floor and the head advance between its two reads: it is an overrun from
/// the cursor to at least the old floor, resuming at or past it.
#[test]
fn a_rejoin_paused_between_its_reads_never_resumes_below_the_lost_range() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    // Lap the subscriber: its position falls below the floor.
    while buffer.floor().load(Ordering::Acquire) < TERM {
        let _ = append_retrying(&mut publication, &mut conductor, &message(1), || {});
    }
    let before = buffer.reserved_head().load(Ordering::Acquire);
    let old_floor = buffer.floor().load(Ordering::Acquire);
    let mut context = SubscriptionContext {
        buffer: &buffer,
        cursor: &mut subscription.cursor,
    };
    // Between the reads, the head moves more than a window ahead and the
    // conductor publishes a floor above the old head.
    let step = context
        .overrun_with(&mut || {
            while buffer.reserved_head().load(Ordering::Acquire) <= before + TERM / 2 {
                let _ = append_retrying(&mut publication, &mut conductor, &message(2), || {});
            }
            let _ = conductor.duty_cycle().unwrap();
            assert!(buffer.floor().load(Ordering::Acquire) > before);
        })
        .unwrap();
    match step {
        Step::Done(PollOutcome::Overrun {
            from,
            lost_to,
            resume,
        }) => {
            assert!(from < lost_to);
            assert!(lost_to >= old_floor, "lost to below the old floor");
            assert!(lost_to <= resume, "resumed inside the lost range");
        }
        _ => panic!("unexpected step"),
    }
}

/// A rejoin whose head snapshot is inconsistent (an injected inconsistent
/// snapshot: the active term's tail names another term, as a reader sees
/// when the slot is reused under it) waits: `Pending`, the cursor unmoved
/// and nothing published. Once the snapshot is consistent again, the next
/// poll is an overrun that never resumes inside the lost range.
#[test]
fn a_rejoin_with_an_inconsistent_head_snapshot_waits_then_overruns() {
    let buffer = new_buffer(concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    // Lap the subscriber: its position falls below the floor.
    while buffer.floor().load(Ordering::Acquire) < TERM {
        let _ = offer_concurrent(&mut handle, &mut conductor, &message(1), || {});
        let _ = conductor.duty_cycle().unwrap();
    }
    let cell = subscription.cell();
    let from = subscription.cursor.position;
    let published = buffer.cell(cell).unwrap().position.load(Ordering::Acquire);
    let count = TermCount::try_new(
        u32::try_from(buffer.active_count().load(Ordering::Acquire)).unwrap(),
    )
    .unwrap();
    let Lookup::Slot(slot) = buffer.lookup(count).unwrap() else {
        panic!("no active slot");
    };
    let tail = buffer.tail(slot).unwrap();
    let consistent = tail.load(Ordering::Acquire);
    let mut context = SubscriptionContext {
        buffer: &buffer,
        cursor: &mut subscription.cursor,
    };
    let step = context
        .overrun_with(&mut || {
            // Another term's id in the tail's high half.
            let other = (consistent >> 32).wrapping_add(1);
            tail.store((other << 32) | (consistent & 0xffff_ffff), Ordering::Release);
        })
        .unwrap();
    assert!(matches!(step, Step::Done(PollOutcome::Pending)));
    assert_eq!(subscription.cursor.position, from, "the cursor moved");
    assert_eq!(
        buffer.cell(cell).unwrap().position.load(Ordering::Acquire),
        published,
        "a position was published"
    );
    tail.store(consistent, Ordering::Release);
    let mut out = vec![0u8; 4096];
    match subscription.poll(&mut out).unwrap() {
        PollOutcome::Overrun {
            from: lost_from,
            lost_to,
            resume,
        } => {
            assert_eq!(lost_from, from);
            assert!(from < lost_to);
            assert!(lost_to <= resume, "resumed inside the lost range");
        }
        other => panic!("unexpected {other:?}"),
    }
}

// Concurrent handles, batch a2.

fn offer_concurrent(
    handle: &mut ConcurrentPublication<&LogBuffer<Terms>>,
    conductor: &mut Conductor<&LogBuffer<Terms>>,
    data: &[u8],
    mut drain: impl FnMut(),
) -> u64 {
    for _ in 0..1000 {
        match handle.offer(data, AppendOptions::default()).unwrap() {
            ConcurrentOfferOutcome::Appended { position } => return position,
            outcome @ (ConcurrentOfferOutcome::Aborted { .. }
            | ConcurrentOfferOutcome::Closed
            | ConcurrentOfferOutcome::Gated) => {
                panic!("unexpected {outcome:?}")
            }
            ConcurrentOfferOutcome::BackPressured | ConcurrentOfferOutcome::AdminAction => {
                drain();
                let _ = conductor.duty_cycle().unwrap();
            }
        }
    }
    panic!("concurrent offer never succeeded");
}

#[test]
fn concurrent_handles_are_issued_up_to_their_slots() {
    let exclusive = new_buffer(config(3, 3)).unwrap();
    assert!(matches!(
        exclusive.conductor().unwrap().concurrent_publication(),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let first = conductor.concurrent_publication().unwrap().unwrap();
    let _second = conductor.concurrent_publication().unwrap().unwrap();
    assert!(conductor.concurrent_publication().unwrap().is_none());
    drop(first);
    assert!(conductor.concurrent_publication().unwrap().is_some());
}

#[test]
fn concurrent_offers_are_disjoint_contiguous_and_delivered() {
    let buffer = new_buffer(concurrent_config(3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut handles: Vec<_> = (0..3)
        .map(|_| conductor.concurrent_publication().unwrap().unwrap())
        .collect();
    let mut expected = Vec::new();
    let mut received = Vec::new();
    let total: u32 = if cfg!(miri) { 60 } else { 600 };
    let mut previous_end = None::<u64>;
    for sequence in 0..total {
        let data = message(sequence);
        let handle = &mut handles[(sequence % 3) as usize];
        let position = offer_concurrent(handle, &mut conductor, &data, || {
            while let Some(message) = poll_message(&mut subscription) {
                received.push(message);
            }
        });
        // Sequential calls: each block starts where the previous ended,
        // except across a term end.
        if let Some(end) = previous_end
            && position / TERM == end / TERM
        {
            assert_eq!(position, end);
        }
        previous_end = Some(position + u64::from(reserved_of(&data)));
        expected.push(data);
    }
    for _ in 0..1000 {
        while let Some(message) = poll_message(&mut subscription) {
            received.push(message);
        }
        if received.len() == expected.len() {
            break;
        }
        let _ = conductor.duty_cycle().unwrap();
    }
    assert_eq!(received, expected);
    // Under Miri fewer messages pass one term end; natively several.
    let rotations = if cfg!(miri) { 0 } else { 2 };
    assert!(
        buffer.active_count().load(Ordering::Acquire) > rotations,
        "no rotation"
    );
}

fn reserved_of(data: &[u8]) -> u32 {
    FragmentPlan::new(DEFAULT_MTU, Flags::NONE)
        .unwrap()
        .reserved(data.len() as u32)
        .unwrap()
}

#[test]
fn the_crossing_owner_pads_its_remainder_and_the_others_catch_up() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut a = conductor.concurrent_publication().unwrap().unwrap();
    let mut b = conductor.concurrent_publication().unwrap().unwrap();
    // 3104 reserved bytes: never an exact fill of a 64 KiB term.
    let data = vec![3u8; 3000];
    // Fill term 0 until a reservation crosses.
    let mut crossed = false;
    for _ in 0..100 {
        let _ = conductor.duty_cycle().unwrap();
        while poll_message(&mut subscription).is_some() {}
        match a.offer(&data, AppendOptions::default()).unwrap() {
            ConcurrentOfferOutcome::Appended { .. } => {}
            ConcurrentOfferOutcome::AdminAction => {
                crossed = true;
                break;
            }
            ConcurrentOfferOutcome::BackPressured => {}
            outcome @ (ConcurrentOfferOutcome::Aborted { .. }
            | ConcurrentOfferOutcome::Closed
            | ConcurrentOfferOutcome::Gated) => {
                panic!("unexpected {outcome:?}")
            }
        }
    }
    assert!(crossed);
    // The remainder is a committed PAD up to the term end.
    let t0 = u64::from(buffer.initial_term_id.get());
    let raw = buffer.tail(0).unwrap().load(Ordering::Acquire);
    assert_eq!(raw >> 32, t0);
    assert!(raw as u32 >= MIN_TERM_LENGTH);
    // The crossing owner rotated (term 1 was prepared).
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    // B finds term 0 full: no reservation there.
    assert_eq!(
        b.offer(&data, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(buffer.tail(0).unwrap().load(Ordering::Acquire), raw);
    // Both catch up and publish in term 1, never again in term 0.
    while poll_message(&mut subscription).is_some() {}
    let pa = offer_concurrent(&mut a, &mut conductor, &data, || {});
    let pb = offer_concurrent(&mut b, &mut conductor, &data, || {});
    assert_eq!(pa / TERM, 1);
    assert_eq!(pb / TERM, 1);
}

#[test]
fn a_live_handle_catches_up_after_three_rotations() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut paused = conductor.concurrent_publication().unwrap().unwrap();
    let mut writer = conductor.concurrent_publication().unwrap().unwrap();
    // The paused handle holds its loan on term 0 while three rotations
    // pass; its slot cannot be reclaimed meanwhile.
    let data = vec![1u8; 6000];
    while buffer.active_count().load(Ordering::Acquire) < 3 {
        let _ = offer_concurrent(&mut writer, &mut conductor, &data, || {
            while poll_message(&mut subscription).is_some() {}
        });
    }
    // Its next call finds term 0 full (one crossing at most), then it
    // catches up to the active term, never waiting for term 1.
    let mut outcomes = Vec::new();
    for _ in 0..3 {
        outcomes.push(paused.offer(&data, AppendOptions::default()).unwrap());
        if matches!(outcomes.last(), Some(ConcurrentOfferOutcome::Appended { .. })) {
            break;
        }
    }
    let Some(ConcurrentOfferOutcome::Appended { position }) = outcomes.last().copied() else {
        panic!("never caught up: {outcomes:?}");
    };
    assert_eq!(
        position / TERM,
        buffer.active_count().load(Ordering::Acquire)
    );
}

#[test]
fn a_reissued_slot_never_crosses_a_term_twice() {
    let buffer = new_buffer(concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    // Term 0 32 bytes from its end, term 1 not prepared yet (the driver is
    // behind), and a limit that admits the reservation.
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
    let data = vec![2u8; 100];
    // The holder crosses term 0, owns the remainder, cannot rotate, and
    // closes while term 0 is still active.
    let mut holder = conductor.concurrent_publication().unwrap().unwrap();
    assert_eq!(
        holder.offer(&data, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 0);
    holder.close();
    // Reissued in the still active, crossed term: it waits.
    let mut reissued = conductor.concurrent_publication().unwrap().unwrap();
    let tail = buffer.tail(0).unwrap().load(Ordering::Acquire);
    for _ in 0..3 {
        assert_eq!(
            reissued.offer(&data, AppendOptions::default()).unwrap(),
            ConcurrentOfferOutcome::AdminAction
        );
    }
    // It made no reservation in term 0.
    assert_eq!(buffer.tail(0).unwrap().load(Ordering::Acquire), tail);
    // The conductor prepares and rotates; the handle publishes in term 1.
    let _ = conductor.duty_cycle().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    while poll(&mut subscription) != PollOutcome::Pending {}
    let position = offer_concurrent(&mut reissued, &mut conductor, &data, || {});
    assert_eq!(position / TERM, 1);
}

#[test]
fn a_reissue_after_cleaning_and_reassignment_starts_at_the_active_term() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let data = vec![4u8; 6000];
    let mut writer = conductor.concurrent_publication().unwrap().unwrap();
    let mut closing = conductor.concurrent_publication().unwrap().unwrap();
    let _ = offer_concurrent(&mut closing, &mut conductor, &data, || {});
    closing.close();
    // Rotations pass and term 0's slot is cleaned and reassigned.
    while buffer.active_count().load(Ordering::Acquire) < 4 {
        let _ = offer_concurrent(&mut writer, &mut conductor, &data, || {
            while poll_message(&mut subscription).is_some() {}
        });
    }
    let found = Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire)).unwrap();
    assert_ne!(found.term_id(), buffer.initial_term_id, "slot 0 was not reused");
    let mut reissued = conductor.concurrent_publication().unwrap().unwrap();
    let position = offer_concurrent(&mut reissued, &mut conductor, &data, || {
        while poll_message(&mut subscription).is_some() {}
    });
    assert!(position / TERM >= 4);
}

#[test]
fn concurrent_offers_are_back_pressured() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _required = conductor.subscribe(Role::Required).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let data = vec![5u8; 3000];
    let mut pressured = false;
    for _ in 0..1000 {
        let _ = conductor.duty_cycle().unwrap();
        if handle.offer(&data, AppendOptions::default()).unwrap() == ConcurrentOfferOutcome::BackPressured {
            pressured = true;
            break;
        }
    }
    assert!(pressured);
    // Never past the window plus one message above the bounding position.
    let head = buffer.head().unwrap().unwrap();
    assert!(head <= TERM / 2);
}

/// The last representable term: a handle reports `MaxPositionExceeded`
/// every time instead of waiting for a term that cannot exist, and makes
/// no reservation.
#[test]
fn a_concurrent_handle_stops_at_the_last_term() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    // Seed a coherent identity: slot 0 holds the last term, 32 bytes from
    // its end; no loan exists yet.
    let last = TermCount::try_new((1 << 31) - 1).unwrap();
    assert!(last.next().is_err());
    let term_id = buffer.initial_term_id.advanced_by(last);
    buffer.descriptor(0).unwrap().store(
        Descriptor::new(term_id, buffer.generation, SlotState::Active).encode(),
        Ordering::Release,
    );
    buffer
        .table_slot(last)
        .unwrap()
        .store(table_entry(last.get(), 0), Ordering::Release);
    buffer
        .tail(0)
        .unwrap()
        .store((u64::from(term_id.get()) << 32) | (TERM - 32), Ordering::Release);
    buffer
        .active_count()
        .store(u64::from(last.get()), Ordering::Release);
    let mut conductor = buffer.conductor().unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let tail = buffer.tail(0).unwrap().load(Ordering::Acquire);
    for _ in 0..4 {
        assert!(matches!(
            handle.offer(b"x", AppendOptions::default()),
            Err(SysError::MaxPositionExceeded { .. })
        ));
    }
    assert_eq!(buffer.tail(0).unwrap().load(Ordering::Acquire), tail);
    // A crossed last term: the handle crosses it, closes, and a reissue
    // reports the exhaustion and leaves the slot free.
    buffer
        .tail(0)
        .unwrap()
        .store((u64::from(term_id.get()) << 32) | TERM, Ordering::Release);
    handle.close();
    let free = buffer.publisher(0).unwrap().load(Ordering::Acquire);
    assert!(matches!(
        conductor.concurrent_publication(),
        Err(SysError::MaxPositionExceeded { .. })
    ));
    assert_eq!(buffer.publisher(0).unwrap().load(Ordering::Acquire), free);
}

/// SPEC.md §13 "First start and identity limits" (issue #68): the exclusive
/// publication in the last representable term count fills it to the end,
/// then refuses with `MaxPositionExceeded`, every time, reserving and
/// writing nothing.
#[test]
fn an_exclusive_publication_stops_at_the_last_term() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let _conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let last = TermCount::try_new((1 << 31) - 1).unwrap();
    assert!(last.next().is_err());
    let term_id = buffer.initial_term_id.advanced_by(last);
    // Seed a coherent identity, as `a_concurrent_handle_stops_at_the_last_term`
    // does: slot 0 holds the last term, one message from its end, and the
    // publication holds its write loan there.
    let flags = Flags::new(true, true, false, false, buffer.config.lane);
    let reserved = crate::sizing::reserved_length(flags, 1).unwrap();
    let tail = MIN_TERM_LENGTH - reserved;
    let cell = buffer.cell(0).unwrap();
    release_loan(&cell.loan);
    buffer.descriptor(0).unwrap().store(
        Descriptor::new(term_id, buffer.generation, SlotState::Active).encode(),
        Ordering::Release,
    );
    buffer
        .table_slot(last)
        .unwrap()
        .store(table_entry(last.get(), 0), Ordering::Release);
    buffer
        .active_count()
        .store(u64::from(last.get()), Ordering::Release);
    buffer
        .reserved_head()
        .store(buffer.position(last, tail), Ordering::Release);
    buffer.limit().store(u64::MAX, Ordering::Release);
    assert_eq!(
        take_loan(
            &cell.loan,
            &cell.revoked,
            buffer.descriptor(0).unwrap(),
            buffer.target(0, last).unwrap(),
        )
        .unwrap(),
        LoanOutcome::Granted
    );
    publication.state = PublicationState::Active {
        count: last,
        slot: 0,
        tail,
    };
    // The last message fits exactly.
    assert!(matches!(
        publication.append(b"x", AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { .. }
    ));
    let head = buffer.reserved_head().load(Ordering::Acquire);
    assert_eq!(head, buffer.position(last, MIN_TERM_LENGTH));
    // Nothing more: no successor term exists.
    for _ in 0..4 {
        assert!(matches!(
            publication.append(b"y", AppendOptions::default()),
            Err(SysError::MaxPositionExceeded { .. })
        ));
        assert!(matches!(
            publication.try_claim(1, AppendOptions::default()),
            Err(SysError::MaxPositionExceeded { .. })
        ));
    }
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), head);
    assert_eq!(
        publication.state,
        PublicationState::Active {
            count: last,
            slot: 0,
            tail: MIN_TERM_LENGTH,
        }
    );
    assert_eq!(buffer.active_count().load(Ordering::Acquire), u64::from(last.get()));
}

/// Issue #68: a buffer of the last mapping generation, which has no
/// successor, runs normally: its descriptors and loans carry the 24-bit
/// value across rotations and reclamation.
#[test]
fn a_buffer_of_the_last_generation_rotates_and_delivers() {
    let last = Generation::try_new((1 << 24) - 1).unwrap();
    assert!(matches!(
        last.next(),
        Err(SysError::GenerationExhausted { .. })
    ));
    let buffer = new_buffer_with_generation(config(3, 2), last).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = vec![6u8; 7000];
    let mut cleaned = 0;
    for _ in 0..60 {
        loop {
            let outcome = publication.append(&data, AppendOptions::default()).unwrap();
            cleaned += conductor.duty_cycle().unwrap().cleaned;
            if matches!(outcome, AppendOutcome::Appended { .. }) {
                break;
            }
        }
        assert_eq!(poll_message(&mut subscription), Some(data.clone()));
    }
    assert!(cleaned > 0, "no slot was reclaimed");
    assert!(buffer.reserved_head().load(Ordering::Acquire) > 4 * TERM);
    for slot in 0..buffer.slots {
        let word = buffer.descriptor(slot).unwrap().load(Ordering::Acquire);
        assert_eq!(Descriptor::decode(word).unwrap().generation(), last);
    }
}

// Claims on concurrent handles, batch a3.

fn concurrent_claimed<'a, O: BufferOwner + core::fmt::Debug>(
    outcome: Result<ConcurrentClaimOutcome<'a, O>, SysError>,
) -> ConcurrentClaim<'a, O> {
    match outcome.unwrap() {
        ConcurrentClaimOutcome::Claimed(claim) => claim,
        other => panic!("not claimed: {other:?}"),
    }
}

#[test]
fn concurrent_claims_commit_between_other_handles_offers() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut claimer = conductor.concurrent_publication().unwrap().unwrap();
    let mut offerer = conductor.concurrent_publication().unwrap().unwrap();
    let mut claim = concurrent_claimed(claimer.try_claim(5, AppendOptions::default()));
    // Another handle publishes while the claim is open.
    let offered = offer_concurrent(&mut offerer, &mut conductor, &message(9), || {});
    assert!(offered > claim.position());
    // Readers wait at the open claim (head of line).
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
    assert!(claim.payload().iter().all(|byte| *byte == 0));
    claim.payload().copy_from_slice(b"hello");
    let position = claim.position();
    assert_eq!(claim.commit(), CommitOutcome::Committed { position });
    assert_eq!(poll_message(&mut subscription), Some(b"hello".to_vec()));
    assert_eq!(poll_message(&mut subscription), Some(message(9)));
}

#[test]
fn concurrent_claims_abort_by_abort_drop_and_forget() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    concurrent_claimed(handle.try_claim(8, AppendOptions::default())).abort();
    drop(concurrent_claimed(handle.try_claim(40, AppendOptions::default())));
    core::mem::forget(concurrent_claimed(handle.try_claim(8, AppendOptions::default())));
    // The next mutable operation resolves the forgotten claim.
    let _ = offer_concurrent(&mut handle, &mut conductor, &message(1), || {});
    for (position, extent) in [(0, 64), (64, 96), (160, 64)] {
        assert_eq!(poll(&mut subscription), PollOutcome::Aborted { position, extent });
    }
    assert_eq!(poll_message(&mut subscription), Some(message(1)));
    // Dropping the handle resolves a forgotten claim before its loan goes.
    core::mem::forget(concurrent_claimed(handle.try_claim(8, AppendOptions::default())));
    drop(handle);
    assert!(matches!(poll(&mut subscription), PollOutcome::Aborted { extent: 64, .. }));
    let held = buffer.cell(0).unwrap().loan.load(Ordering::SeqCst);
    assert_eq!(held, 0);
}

#[test]
fn concurrent_claim_sizes_are_checked() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    assert!(matches!(
        handle.try_claim(0, AppendOptions::default()),
        Err(SysError::EmptyMessage)
    ));
    assert!(matches!(
        handle.try_claim(1377, AppendOptions::default()),
        Err(SysError::Layout(LayoutError::MessageTooLarge { .. }))
    ));
    let mut claim = concurrent_claimed(handle.try_claim(1376, AppendOptions::default()));
    assert_eq!(claim.payload().len(), 1376);
    claim.abort();
}

// Rotation by publishers, batch b.

#[test]
fn publishers_rotate_without_the_conductor() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let t0 = u64::from(buffer.initial_term_id.get());
    buffer
        .tail(0)
        .unwrap()
        .store((t0 << 32) | (TERM - 32), Ordering::Release);
    buffer.limit().store(2 * TERM, Ordering::Release);
    // The crossing owner pads and rotates to the prepared term 1.
    assert_eq!(
        handle.offer(&[1u8; 100], AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    let t1 = buffer
        .initial_term_id
        .advanced_by(TermCount::try_new(1).unwrap());
    let found = Descriptor::decode(buffer.descriptor(1).unwrap().load(Ordering::Acquire)).unwrap();
    assert_eq!(found, Descriptor::new(t1, buffer.generation, SlotState::Active));
    // And then publishes in term 1 without a duty cycle.
    assert!(matches!(
        handle.offer(&[1u8; 100], AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { position } if position == TERM
    ));
}

#[test]
fn a_rotation_attempt_is_idempotent_and_detects_supersession() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let one = TermCount::try_new(1).unwrap();
    let t1 = buffer.initial_term_id.advanced_by(one);
    let rotate = |next: TermCount, term: TermId| {
        rotate_to(
            buffer.descriptor(1).unwrap(),
            buffer.active_count(),
            term,
            buffer.generation,
            next,
        )
        .unwrap()
    };
    assert_eq!(rotate(one, t1), Rotation::Completed);
    // Repeating it, as a second helper would, changes nothing.
    assert_eq!(rotate(one, t1), Rotation::Completed);
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    // A helper paused across later rotations finds the count beyond and
    // the slot reassigned to a later term: it writes nothing.
    buffer.active_count().store(3, Ordering::Release);
    let t4 = buffer.initial_term_id.advanced_by(TermCount::try_new(4).unwrap());
    let ready4 = Descriptor::new(t4, buffer.generation, SlotState::Ready).encode();
    buffer.descriptor(1).unwrap().store(ready4, Ordering::Release);
    assert_eq!(rotate(one, t1), Rotation::Superseded);
    assert_eq!(buffer.descriptor(1).unwrap().load(Ordering::Acquire), ready4);
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 3);
    // A term not prepared yet: the driver is behind.
    let five = TermCount::try_new(5).unwrap();
    let t5 = buffer.initial_term_id.advanced_by(five);
    assert_eq!(rotate(five, t5), Rotation::NotReady);
}

/// An exactly full term, or a crossing owner that could not rotate, is
/// rotated by the next publisher call once the successor is ready, with no
/// conductor duty.
#[test]
fn a_full_term_is_rotated_by_the_next_publisher_call() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = conductor.concurrent_publication().unwrap().unwrap();
    let mut peer = conductor.concurrent_publication().unwrap().unwrap();
    let t0 = u64::from(buffer.initial_term_id.get());
    // Exactly full: no crossing reservation will ever happen in term 0.
    buffer.tail(0).unwrap().store((t0 << 32) | TERM, Ordering::Release);
    buffer.limit().store(2 * TERM, Ordering::Release);
    // The peer finds the term full and rotates; its next call publishes.
    assert_eq!(
        peer.offer(b"x", AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    assert!(matches!(
        peer.offer(b"x", AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { position } if position == TERM
    ));
    // The owner, still in term 0, finds it full, then catches up.
    assert_eq!(
        owner.offer(b"y", AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert!(matches!(
        owner.offer(b"y", AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { position } if position == TERM + 64
    ));
    // A crossed handle whose successor was not ready helps once it is.
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = conductor.concurrent_publication().unwrap().unwrap();
    buffer
        .tail(0)
        .unwrap()
        .store((t0 << 32) | (TERM - 32), Ordering::Release);
    buffer.limit().store(2 * TERM, Ordering::Release);
    let one = TermCount::try_new(1).unwrap();
    let t1 = buffer.initial_term_id.advanced_by(one);
    let ready = Descriptor::new(t1, buffer.generation, SlotState::Ready).encode();
    buffer.descriptor(1).unwrap().store(
        Descriptor::new(t1, buffer.generation, SlotState::Free).encode(),
        Ordering::Release,
    );
    assert_eq!(
        owner.offer(&[1u8; 100], AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 0);
    // The successor becomes ready (as the conductor's preparation would).
    buffer.descriptor(1).unwrap().store(ready, Ordering::Release);
    assert_eq!(
        owner.offer(&[1u8; 100], AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::AdminAction
    );
    assert_eq!(buffer.active_count().load(Ordering::Acquire), 1);
    assert!(matches!(
        owner.offer(&[1u8; 100], AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { position } if position == TERM
    ));
}

// Concurrent deadline, batch c2 (quantstratum-docs: karyos/design/concurrent-deadline.md).

fn deadline_concurrent_config(publishers: u8) -> LogBufferConfig {
    LogBufferConfig {
        claim_deadline: DEADLINE,
        ..concurrent_config(publishers)
    }
}

fn serve(conductor: &mut Conductor<&LogBuffer<Terms>>, now: u64) -> DeadlineReport {
    conductor.service_deadlines(&mut || now).unwrap()
}

fn waiting() -> DeadlineReport {
    DeadlineReport {
        waiting: true,
        ..DeadlineReport::default()
    }
}

fn aborted(count: u32, bytes: u64) -> DeadlineReport {
    DeadlineReport {
        aborted: count,
        aborted_bytes: bytes,
        ..DeadlineReport::default()
    }
}

#[test]
fn a_marked_concurrent_claim_is_aborted_at_its_deadline_while_its_writer_writes() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let mut other = conductor.concurrent_publication().unwrap().unwrap();
    let mut claim = concurrent_claimed(handle.try_claim(8, AppendOptions::default()));
    claim.payload().fill(7);
    let behind = offer_concurrent(&mut other, &mut conductor, &message(1), || {});
    assert_eq!(behind, 64);
    assert_eq!(serve(&mut conductor, 10), waiting());
    assert_eq!(serve(&mut conductor, 10 + DEADLINE - 1), waiting());
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
    assert_eq!(serve(&mut conductor, 10 + DEADLINE), aborted(1, 64));
    // The writer keeps writing its payload; its commit loses.
    claim.payload().fill(9);
    assert_eq!(claim.commit(), CommitOutcome::Aborted { position: 0 });
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 0,
            extent: 64,
        }
    );
    assert_eq!(poll_message(&mut subscription), Some(message(1)));
    assert_eq!(serve(&mut conductor, u64::MAX), DeadlineReport::default());
}

#[test]
fn a_marked_fragmented_offer_is_aborted_and_its_commit_reports_the_abort() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let data = sized_message(2, 3000);
    let reserved = reserved_of(&data);
    let outcome = handle
        .offer_pausing(&data, AppendOptions::default(), &mut |point| {
            if point == WriterPause::Commit {
                assert_eq!(serve(&mut conductor, 0), waiting());
                assert_eq!(
                    serve(&mut conductor, DEADLINE),
                    aborted(1, u64::from(reserved))
                );
            }
        })
        .unwrap();
    assert_eq!(outcome, ConcurrentOfferOutcome::Aborted { position: 0 });
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 0,
            extent: reserved,
        }
    );
    // The handle publishes again after the abort.
    let position = offer_concurrent(&mut handle, &mut conductor, &data, || {});
    assert_eq!(position, u64::from(reserved));
    assert_eq!(poll_message(&mut subscription), Some(data));
}

#[test]
fn a_marked_crossing_pad_is_aborted_and_the_owner_still_rotates() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let data = vec![3u8; 3000];
    let reserved = reserved_of(&data);
    let tail = |buffer: &LogBuffer<Terms>| buffer.tail(0).unwrap().load(Ordering::Acquire) as u32;
    while tail(&buffer) + reserved <= MIN_TERM_LENGTH {
        let _ = offer_concurrent(&mut handle, &mut conductor, &data, || {
            while poll_message(&mut subscription).is_some() {}
        });
    }
    while poll_message(&mut subscription).is_some() {}
    let _ = conductor.duty_cycle().unwrap();
    let start = tail(&buffer);
    let extent = MIN_TERM_LENGTH - start;
    let outcome = handle
        .offer_pausing(&data, AppendOptions::default(), &mut |point| {
            if point == WriterPause::PadCommit {
                // The scan reaches the PAD within a few budgeted calls.
                let mut calls = 0;
                while serve(&mut conductor, 0) != waiting() {
                    calls += 1;
                    assert!(calls < 10, "the marked PAD was never observed");
                }
                assert_eq!(
                    serve(&mut conductor, DEADLINE),
                    aborted(1, u64::from(extent))
                );
            }
        })
        .unwrap();
    assert_eq!(outcome, ConcurrentOfferOutcome::AdminAction);
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: u64::from(start),
            extent,
        }
    );
    let position = offer_concurrent(&mut handle, &mut conductor, &data, || {});
    assert_eq!(position, TERM);
    assert_eq!(poll_message(&mut subscription), Some(data));
}

#[test]
fn a_writer_paused_before_its_mark_inside_a_zero_span_writes_nothing() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut paused = conductor.concurrent_publication().unwrap().unwrap();
    let mut other = conductor.concurrent_publication().unwrap().unwrap();
    let mut behind = 0;
    let outcome = paused
        .offer_pausing(&message(1), AppendOptions::default(), &mut |point| {
            if point == WriterPause::Mark {
                behind = offer_concurrent(&mut other, &mut conductor, &message(2), || {});
                assert_eq!(serve(&mut conductor, 0), waiting());
                assert_eq!(poll(&mut subscription), PollOutcome::Pending);
                // The walk takes the span up to the committed block.
                assert_eq!(serve(&mut conductor, DEADLINE), aborted(1, behind));
            }
        })
        .unwrap();
    assert_eq!(outcome, ConcurrentOfferOutcome::Aborted { position: 0 });
    // The paused writer's mark failed: the span's word is untouched by it.
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 0,
            extent: behind as u32,
        }
    );
    assert_eq!(poll_message(&mut subscription), Some(message(2)));
    // A paused claim is refused the same way.
    let mut position = None;
    let outcome = paused
        .try_claim_pausing(8, AppendOptions::default(), &mut |point| {
            if point == WriterPause::Mark {
                position = Some(buffer.conductor_head().unwrap() - 64);
                assert_eq!(serve(&mut conductor, 0), waiting());
                assert_eq!(serve(&mut conductor, DEADLINE), aborted(1, 64));
            }
        })
        .unwrap();
    assert!(matches!(
        outcome,
        ConcurrentClaimOutcome::Aborted { position: p } if Some(p) == position
    ));
}

#[test]
fn a_mark_noticed_by_the_failed_first_take_is_served_in_the_same_call() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let reserved = reserved_of(&message(1));
    let outcome = handle
        .offer_pausing(&message(1), AppendOptions::default(), &mut |point| {
            match point {
                // A zero span, first observed at 0.
                WriterPause::Mark => assert_eq!(serve(&mut conductor, 0), waiting()),
                // Marked since: the walk's first compare-exchange fails and
                // the mark is aborted at the span's original deadline.
                WriterPause::Commit => assert_eq!(
                    serve(&mut conductor, DEADLINE),
                    aborted(1, u64::from(reserved))
                ),
                _ => {}
            }
        })
        .unwrap();
    assert_eq!(outcome, ConcurrentOfferOutcome::Aborted { position: 0 });
}

#[test]
fn a_zero_span_marked_before_its_deadline_keeps_its_first_observation() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let reserved = reserved_of(&message(1));
    let outcome = handle
        .offer_pausing(&message(1), AppendOptions::default(), &mut |point| {
            match point {
                WriterPause::Mark => assert_eq!(serve(&mut conductor, 0), waiting()),
                WriterPause::Commit => {
                    // The scan finds the mark: same position, same timer.
                    assert_eq!(serve(&mut conductor, DEADLINE - 1), waiting());
                    assert_eq!(
                        serve(&mut conductor, DEADLINE),
                        aborted(1, u64::from(reserved))
                    );
                }
                _ => {}
            }
        })
        .unwrap();
    assert_eq!(outcome, ConcurrentOfferOutcome::Aborted { position: 0 });
}

#[test]
fn a_span_longer_than_the_walk_budget_completes_over_several_calls() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    conductor.deadlines.set_budgets(1, 2);
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut paused = conductor.concurrent_publication().unwrap().unwrap();
    let mut other = conductor.concurrent_publication().unwrap().unwrap();
    let data = sized_message(1, 100);
    assert_eq!(reserved_of(&data), 160);
    let outcome = paused
        .offer_pausing(&data, AppendOptions::default(), &mut |point| {
            if point == WriterPause::Mark {
                let _ = offer_concurrent(&mut other, &mut conductor, &message(2), || {});
                assert_eq!(serve(&mut conductor, 0), waiting());
                // One compare-exchange per call: five boundaries taken,
                // readers waiting meanwhile, then the failed one ends it.
                for _ in 0..5 {
                    assert_eq!(serve(&mut conductor, DEADLINE), waiting());
                    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
                }
                assert_eq!(serve(&mut conductor, DEADLINE), aborted(1, 160));
            }
        })
        .unwrap();
    assert_eq!(outcome, ConcurrentOfferOutcome::Aborted { position: 0 });
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 0,
            extent: 160,
        }
    );
    assert_eq!(poll_message(&mut subscription), Some(message(2)));
}

#[test]
fn several_stuck_writers_are_timed_at_once() {
    let buffer = new_buffer(deadline_concurrent_config(3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut handles: Vec<_> = (0..3)
        .map(|_| conductor.concurrent_publication().unwrap().unwrap())
        .collect();
    for handle in &mut handles {
        core::mem::forget(concurrent_claimed(handle.try_claim(8, AppendOptions::default())));
    }
    assert_eq!(serve(&mut conductor, 0), waiting());
    assert_eq!(serve(&mut conductor, DEADLINE), aborted(3, 192));
    for position in [0, 64, 128] {
        assert_eq!(
            poll(&mut subscription),
            PollOutcome::Aborted {
                position,
                extent: 64,
            }
        );
    }
}

#[test]
fn a_younger_reservation_is_outside_an_older_spans_frozen_bound() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut older = conductor.concurrent_publication().unwrap().unwrap();
    let mut younger = conductor.concurrent_publication().unwrap().unwrap();
    let reserved = reserved_of(&message(1));
    let mut inner = None;
    let outcome = older
        .offer_pausing(&message(1), AppendOptions::default(), &mut |point| {
            if point != WriterPause::Mark {
                return;
            }
            assert_eq!(serve(&mut conductor, 0), waiting());
            inner = Some(
                younger
                    .offer_pausing(&message(2), AppendOptions::default(), &mut |point| {
                        if point == WriterPause::Mark {
                            // Admitted after the older span's first
                            // observation: the walk stops at its frozen
                            // bound, and the younger zero is timed anew.
                            let report = serve(&mut conductor, DEADLINE);
                            assert_eq!(
                                report,
                                DeadlineReport {
                                    waiting: true,
                                    ..aborted(1, u64::from(reserved))
                                }
                            );
                            assert_eq!(serve(&mut conductor, 2 * DEADLINE - 1), waiting());
                        }
                    })
                    .unwrap(),
            );
        })
        .unwrap();
    assert_eq!(outcome, ConcurrentOfferOutcome::Aborted { position: 0 });
    assert_eq!(
        inner,
        Some(ConcurrentOfferOutcome::Appended {
            position: u64::from(reserved),
        })
    );
    assert_eq!(serve(&mut conductor, 2 * DEADLINE - 1), DeadlineReport::default());
    assert!(matches!(poll(&mut subscription), PollOutcome::Aborted { .. }));
    assert_eq!(poll_message(&mut subscription), Some(message(2)));
}

#[test]
fn a_call_reports_every_outcome_it_meets() {
    let buffer = new_buffer(deadline_concurrent_config(4)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut handles: Vec<_> = (0..4)
        .map(|_| conductor.concurrent_publication().unwrap().unwrap())
        .collect();
    let [first, second, third, fourth] = handles.as_mut_slice() else {
        panic!("four handles");
    };
    core::mem::forget(concurrent_claimed(first.try_claim(8, AppendOptions::default())));
    let kept = concurrent_claimed(second.try_claim(8, AppendOptions::default()));
    core::mem::forget(concurrent_claimed(third.try_claim(8, AppendOptions::default())));
    assert_eq!(serve(&mut conductor, 0), waiting());
    // A fourth block, first observed by a scan whose clock reads 1000
    // while the step 1 clock read 50.
    core::mem::forget(concurrent_claimed(fourth.try_claim(8, AppendOptions::default())));
    let mut reads = [50, 1000].into_iter();
    let report = conductor
        .service_deadlines(&mut || reads.next().unwrap())
        .unwrap();
    assert_eq!(report, waiting());
    assert_eq!(kept.commit(), CommitOutcome::Committed { position: 64 });
    // Two aborted, one already committed after its expiry, one timer
    // re-anchored, and still waiting on it.
    assert_eq!(
        serve(&mut conductor, 500),
        DeadlineReport {
            aborted: 2,
            aborted_bytes: 128,
            resolved: 1,
            clock_went_back: 1,
            unrepresentable: 0,
            waiting: true,
        }
    );
}

#[test]
fn a_concurrent_call_failing_after_an_abort_carries_it() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut first = conductor.concurrent_publication().unwrap().unwrap();
    let mut second = conductor.concurrent_publication().unwrap().unwrap();
    core::mem::forget(concurrent_claimed(first.try_claim(8, AppendOptions::default())));
    core::mem::forget(concurrent_claimed(second.try_claim(8, AppendOptions::default())));
    assert_eq!(serve(&mut conductor, 0), waiting());
    // A peer rewrites the second marked word.
    let foreign = Word0::new(-96, Flags::new(true, true, false, false, Lane::ZERO), FrameType::Data);
    word0_of_term0(&buffer, 64).store(foreign.pack().to_le(), Ordering::Release);
    let error = conductor.service_deadlines(&mut || DEADLINE).unwrap_err();
    assert_eq!(
        error.report,
        DeadlineReport {
            waiting: true,
            ..aborted(1, 64)
        }
    );
    assert!(matches!(error.error, SysError::CorruptTerm { offset: 64, .. }));
}

#[test]
fn an_unrepresentable_concurrent_expiry_is_counted_per_call() {
    let buffer = new_buffer(LogBufferConfig {
        claim_deadline: u64::MAX,
        ..concurrent_config(2)
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let _claim = concurrent_claimed(handle.try_claim(8, AppendOptions::default()));
    assert_eq!(serve(&mut conductor, 1), waiting());
    let unrepresentable = DeadlineReport {
        unrepresentable: 1,
        waiting: true,
        ..DeadlineReport::default()
    };
    assert_eq!(serve(&mut conductor, 2), unrepresentable);
    assert_eq!(serve(&mut conductor, u64::MAX), unrepresentable);
}

/// An aborted writer keeps its loan while it writes its live payload
/// (direct on heap terms, staging on shared terms): other publishers
/// rotate past its term and the conductor's reclaim attempts quarantine
/// the slot until the writer's accesses end.
#[test]
fn an_aborted_writer_keeps_its_slot_until_its_accesses_end() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut stuck = conductor.concurrent_publication().unwrap().unwrap();
    let mut other = conductor.concurrent_publication().unwrap().unwrap();
    let mut claim = concurrent_claimed(stuck.try_claim(64, AppendOptions::default()));
    assert_eq!(serve(&mut conductor, 0), waiting());
    assert_eq!(serve(&mut conductor, DEADLINE), aborted(1, 96));
    let data = vec![5u8; 3000];
    let mut quarantined = 0;
    while buffer.active_count().load(Ordering::Acquire) < 4 {
        claim.payload().fill(1);
        let _ = offer_concurrent(&mut other, &mut conductor, &data, || {});
        quarantined += conductor.duty_cycle().unwrap().quarantined;
        let _ = serve(&mut conductor, DEADLINE);
    }
    assert!(quarantined > 0, "term 0's slot was never quarantined");
    let term0 = buffer.initial_term_id;
    let found = Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire)).unwrap();
    assert_eq!((found.term_id(), found.state()), (term0, SlotState::Reclaiming));
    claim.payload().fill(2);
    assert_eq!(claim.commit(), CommitOutcome::Aborted { position: 0 });
    // The writer's next calls leave term 0; then the slot is cleaned.
    let _ = offer_concurrent(&mut stuck, &mut conductor, &data, || {});
    let _ = conductor.duty_cycle().unwrap();
    let found = Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire)).unwrap();
    assert!(found.term_id() != term0 || found.state() == SlotState::Free);
}

/// A writer's block marked by hand at the active term 0's tail: its
/// `fetch_add` and mark. Returns its start.
fn mark_by_hand(buffer: &LogBuffer<Terms>, extent: u32) -> u32 {
    let start = buffer.tail(0).unwrap().fetch_add(u64::from(extent), Ordering::AcqRel) as u32;
    let flags = Flags::new(true, true, false, false, Lane::ZERO);
    let reserved = Word0::new(-(extent as i32), flags, FrameType::Data);
    assert!(mark_block(word0_of_term0(buffer, start), reserved));
    start
}

fn commit_by_hand(buffer: &LogBuffer<Terms>, start: u32, extent: u32) {
    let flags = Flags::new(true, true, false, false, Lane::ZERO);
    let reserved = Word0::new(-(extent as i32), flags, FrameType::Data);
    let committed = Word0::new(HEADER_LENGTH as i32 + 8, flags, FrameType::Data);
    assert!(commit_block(word0_of_term0(buffer, start), reserved, committed));
}

/// With the minimum scan budget, a marked frontier costs no read once
/// step 1 confirmed it, so the look-ahead gets past a fragmented block.
#[test]
fn the_minimum_scan_budget_discovers_past_a_fragmented_block() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    conductor.deadlines.set_budgets(1, 2);
    let mut first = conductor.concurrent_publication().unwrap().unwrap();
    let mut second = conductor.concurrent_publication().unwrap().unwrap();
    let a = concurrent_claimed(first.try_claim(8, AppendOptions::default()));
    let data = sized_message(2, 3000);
    assert!(matches!(
        second.offer(&data, AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { .. }
    ));
    let c = concurrent_claimed(second.try_claim(8, AppendOptions::default()));
    // The first call observes the frontier; the next ones walk the three
    // fragments and reach C.
    for _ in 0..4 {
        let _ = serve(&mut conductor, 0);
    }
    assert_eq!(serve(&mut conductor, DEADLINE), aborted(2, 128));
    assert_eq!(a.commit(), CommitOutcome::Aborted { position: 0 });
    assert!(matches!(c.commit(), CommitOutcome::Aborted { .. }));
}

/// Cleaning an unrelated slot keeps a fragment walk's continuation.
#[test]
fn cleaning_another_slot_keeps_the_fragment_walk() {
    let buffer = new_buffer(deadline_concurrent_config(3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    conductor.deadlines.set_budgets(1, 2);
    let mut first = conductor.concurrent_publication().unwrap().unwrap();
    let mut second = conductor.concurrent_publication().unwrap().unwrap();
    let mut writer = conductor.concurrent_publication().unwrap().unwrap();
    let a = concurrent_claimed(first.try_claim(8, AppendOptions::default()));
    let data = sized_message(2, 3000);
    let _ = writer.offer(&data, AppendOptions::default()).unwrap();
    let c = concurrent_claimed(second.try_claim(8, AppendOptions::default()));
    assert_eq!(serve(&mut conductor, 0), waiting());
    let mut total = 0;
    for cycle in 0..6 {
        // Each cycle cleans at least one slot other than term 0's.
        let mut cleaned = 0;
        for _ in 0..1000 {
            let _ = writer.offer(&data, AppendOptions::default()).unwrap();
            cleaned += conductor.duty_cycle().unwrap().cleaned;
            if cleaned > 0 {
                break;
            }
        }
        assert!(cleaned > 0);
        total += serve(&mut conductor, DEADLINE * (cycle + 1)).aborted;
    }
    assert_eq!(total, 2);
    assert_eq!(a.commit(), CommitOutcome::Aborted { position: 0 });
    assert!(matches!(c.commit(), CommitOutcome::Aborted { .. }));
}

/// A writer that completes an observed block and marks another during
/// one call never loses the new block's discovery to stale entries.
#[test]
fn a_block_discovered_beside_stale_observations_keeps_its_timer() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let a = mark_by_hand(&buffer, 64);
    let b = mark_by_hand(&buffer, 64);
    assert_eq!(serve(&mut conductor, 0), waiting());
    let mut c = None;
    let report = conductor
        .service_deadlines_pausing(&mut || 1, &mut || {
            // After step 1 confirmed both: B completes, its writer marks C.
            commit_by_hand(&buffer, b, 64);
            c = Some(mark_by_hand(&buffer, 64));
        })
        .unwrap();
    assert_eq!(report, waiting());
    assert_eq!((a, b, c), (0, 64, Some(128)));
    // C, discovered at 1, is aborted at 1 + DEADLINE with A; B resolved.
    assert_eq!(
        serve(&mut conductor, 1 + DEADLINE),
        DeadlineReport {
            resolved: 1,
            ..aborted(2, 128)
        }
    );
}

/// The production scan budget keeps a 128-fragment walk across unrelated
/// cleaning.
#[test]
fn the_default_scan_budget_keeps_a_long_fragment_walk_across_cleaning() {
    let buffer = new_buffer(LogBufferConfig {
        mtu: 64,
        ..deadline_concurrent_config(3)
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut first = conductor.concurrent_publication().unwrap().unwrap();
    let mut second = conductor.concurrent_publication().unwrap().unwrap();
    let mut writer = conductor.concurrent_publication().unwrap().unwrap();
    let a = concurrent_claimed(first.try_claim(8, AppendOptions::default()));
    let data = sized_message(2, 4096);
    let _ = writer.offer(&data, AppendOptions::default()).unwrap();
    let c = concurrent_claimed(second.try_claim(8, AppendOptions::default()));
    assert_eq!(serve(&mut conductor, 0), waiting());
    let mut total = 0;
    for cycle in 0..6 {
        let mut cleaned = 0;
        for _ in 0..1000 {
            let _ = writer.offer(&data, AppendOptions::default()).unwrap();
            cleaned += conductor.duty_cycle().unwrap().cleaned;
            if cleaned > 0 {
                break;
            }
        }
        assert!(cleaned > 0);
        total += serve(&mut conductor, DEADLINE * (cycle + 1)).aborted;
    }
    assert_eq!(total, 2);
    assert_eq!(a.commit(), CommitOutcome::Aborted { position: 0 });
    assert!(matches!(c.commit(), CommitOutcome::Aborted { .. }));
}

/// When the frontier's marked block commits, the frontier moves past the
/// region the look-ahead already scanned without reading it again, so a
/// partly walked fragmented block resumes where it stopped.
#[test]
fn a_committed_frontier_does_not_replay_the_lookahead() {
    let buffer = new_buffer(LogBufferConfig {
        mtu: 64,
        ..deadline_concurrent_config(3)
    })
    .unwrap();
    let mut conductor = buffer.conductor().unwrap();
    conductor.deadlines.set_budgets(1, 2);
    let mut a = conductor.concurrent_publication().unwrap().unwrap();
    let mut b = conductor.concurrent_publication().unwrap().unwrap();
    let mut c = conductor.concurrent_publication().unwrap().unwrap();
    // Three and ten fragments of 32 payload bytes.
    let (first, second) = (sized_message(1, 96), sized_message(2, 320));
    let outcome = a
        .offer_pausing(&first, AppendOptions::default(), &mut |point| {
            if point != WriterPause::Commit {
                return;
            }
            assert!(matches!(
                b.offer(&second, AppendOptions::default()).unwrap(),
                ConcurrentOfferOutcome::Appended { .. }
            ));
            core::mem::forget(concurrent_claimed(c.try_claim(8, AppendOptions::default())));
            // A observed, then eight calls of the look-ahead into B.
            for _ in 0..8 {
                assert_eq!(serve(&mut conductor, 0), waiting());
            }
        })
        .unwrap();
    assert!(matches!(outcome, ConcurrentOfferOutcome::Appended { .. }));
    // B's remaining fragments and C take three more calls: C is first
    // observed at 3 at the latest, and expires by 3 + DEADLINE.
    for now in 1..=3 {
        let _ = serve(&mut conductor, now);
    }
    assert_eq!(serve(&mut conductor, 3 + DEADLINE), aborted(1, 64));
}

/// Layout properties of a log buffer across rotations (SPEC.md §13, "Log
/// buffers, codecs": base and EXT64 sizing, MTU fragmentation, rotation and
/// padding; issue #10). Random base and EXT64 messages through the
/// exclusive publication: each block starts where the model of SPEC.md §4
/// puts it (aligned, never crossing a term end, a PAD filling exactly the
/// remainder a block does not fit), and a required reader receives every
/// message intact at that position.
mod layout_properties {
    use proptest::prelude::*;

    use super::*;

    fn message_specs() -> impl Strategy<Value = Vec<(usize, bool)>> {
        let count = if cfg!(miri) { 1..12 } else { 1..120 };
        prop::collection::vec((4usize..=6000, any::<bool>()), count)
    }

    proptest! {
        #![proptest_config(crate::receive::tests_config())]

        #[test]
        fn blocks_are_aligned_never_cross_a_term_and_pads_fill_the_rest(specs in message_specs()) {
            let buffer = new_buffer(config(3, 2)).unwrap();
            let mut conductor = buffer.conductor().unwrap();
            let mut subscription = conductor.subscribe(Role::Required).unwrap();
            let mut publication = buffer.publication().unwrap().unwrap();
            let base = FragmentPlan::new(DEFAULT_MTU, Flags::NONE).unwrap();
            let ext = FragmentPlan::new(DEFAULT_MTU, Flags::new(false, false, false, true, Lane::ZERO))
                .unwrap();
            let mut out = vec![0u8; 8192];
            let mut expected = 0u64;
            for (sequence, (len, with_extension)) in specs.into_iter().enumerate() {
                let sequence = sequence as u32;
                let data = sized_message(sequence, len);
                let plan = if with_extension { ext } else { base };
                let reserved = u64::from(plan.reserved(len as u32).unwrap());
                prop_assert_eq!(reserved % u64::from(FRAME_ALIGNMENT), 0);
                // A block that does not fit the rest of its term moves to
                // the next one; a PAD fills exactly that rest.
                let offset = expected % TERM;
                if offset + reserved > TERM {
                    expected += TERM - offset;
                }
                let options = AppendOptions {
                    extension: with_extension.then_some([sequence as u8; EXTENSION_LENGTH as usize]),
                    ..AppendOptions::default()
                };
                let position = loop {
                    match publication.append(&data, options).unwrap() {
                        AppendOutcome::Appended { position } => break position,
                        AppendOutcome::Closed | AppendOutcome::Gated => panic!("not sealed"),
                        _ => {
                            let _ = conductor.duty_cycle().unwrap();
                        }
                    }
                };
                prop_assert_eq!(position, expected);
                prop_assert!(position % TERM + reserved <= TERM, "a block crossed a term end");
                let _ = conductor.duty_cycle().unwrap();
                match subscription.poll(&mut out).unwrap() {
                    PollOutcome::Message { position: read, length, extension, .. } => {
                        subscription.acknowledge();
                        prop_assert_eq!(read, expected);
                        prop_assert_eq!(&out[..length as usize], &data[..]);
                        prop_assert_eq!(extension, options.extension);
                    }
                    other => prop_assert!(false, "expected a message, got {other:?}"),
                }
                expected += reserved;
            }
        }
    }
}

/// `LogBuffer::validate` accepts and refuses exactly what `new` does,
/// without building a buffer (W5c).
#[test]
fn validate_agrees_with_new() {
    let valid = config(3, 4);
    assert_eq!(LogBuffer::<Terms>::validate(&valid), Ok(()));
    assert!(new_buffer(valid).is_ok());
    let mut deadline = config(3, 4);
    deadline.claim_deadline = 0;
    for invalid in [config(0, 4), config(200, 4), deadline] {
        let expected = new_buffer(invalid).err();
        assert!(expected.is_some());
        assert_eq!(LogBuffer::<Terms>::validate(&invalid).err(), expected);
    }
}

/// F7b-2c-2: a buffer carries its stream's conflation table only when the
/// table fits it (some keys, a value that is not empty and fits one
/// message), and its configuration block then holds the shape in words 19
/// and 20.
#[test]
fn a_conflation_shape_must_fit_its_buffer() {
    let max = new_buffer(config(3, 4)).unwrap().max_message_length();
    for shape in [
        ConflationShape::new(0, 8),
        ConflationShape::new(4, 0),
        ConflationShape::new(4, max + 1),
    ] {
        assert_eq!(
            new_buffer(config(3, 4)).unwrap().with_conflation(shape).err(),
            Some(SysError::InvalidConflationShape {
                keys: shape.keys,
                value_capacity: shape.value_capacity,
            })
        );
    }
    assert_eq!(new_buffer(config(3, 4)).unwrap().conflation(), None);
    let shape = ConflationShape::new(4, max);
    let buffer = new_buffer(config(3, 4))
        .unwrap()
        .with_conflation(shape)
        .unwrap();
    assert_eq!(buffer.conflation(), Some(shape));
    let words = config_words(
        buffer.config(),
        buffer.generation,
        buffer.max_message_length(),
        buffer.conflation(),
    );
    assert_eq!(
        (words[19], words[20], words[21]),
        (4, u64::from(max), 0)
    );
    let block = |index: usize| {
        buffer
            .backing
            .word(buffer.layout.config + index)
            .unwrap()
            .load(Ordering::Acquire)
    };
    assert_eq!((block(19), block(20), block(21)), (4, u64::from(max), 0));
}

/// SPEC §14: `attached_subscribers` counts only the buffer's subscriber
/// cells, so it reaches `max_subscribers` and never passes it.
#[test]
fn the_attached_count_reaches_the_subscriber_cells_and_stops() {
    let buffer = new_buffer(config(3, 4)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut readers = Vec::new();
    for attached in 1..=4u32 {
        readers.push(conductor.subscribe(Role::Required).unwrap());
        assert_eq!(buffer.attached_subscribers(), attached);
    }
    assert!(conductor.subscribe(Role::Required).is_err());
    assert_eq!(buffer.attached_subscribers(), 4);
}
