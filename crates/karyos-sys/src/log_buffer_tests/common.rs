// SPDX-License-Identifier: Apache-2.0

// Log buffer tests, included once per term backing by `log_buffer.rs`; the
// including module defines `Terms` and `new_buffer`.

use crate::term_bytes::sealed::Access as _;
use crate::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH};

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
        let head = buffer.reserved_head.load(Ordering::Acquire);
        assert!(head - buffer.floor.load(Ordering::Acquire) <= TERM);
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
    assert!(buffer.active_count.load(Ordering::Acquire) > minimum);
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
        }
        let _ = conductor.duty_cycle().unwrap();
    }
    assert!(pressured, "the publication was never back-pressured");
    // Never more than the window ahead of the required subscriber.
    let head = buffer.reserved_head.load(Ordering::Acquire);
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
    let head = buffer.reserved_head.load(Ordering::Acquire);
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
    buffer.limit.store(4 * TERM, Ordering::Release);
    let data = vec![9u8; 7000];
    let mut admin = 0;
    let mut appended = 0;
    for _ in 0..100 {
        match publication.append(&data, AppendOptions::default()).unwrap() {
            AppendOutcome::Appended { .. } => appended += 1,
            AppendOutcome::AdminAction => admin += 1,
            AppendOutcome::BackPressured => panic!("unexpected back pressure"),
        }
    }
    // Term 0 and the prepared term 1 filled up; term 2 needs the
    // conductor, so later appends only report AdminAction.
    assert!(appended > 0 && admin > 50);
    assert_eq!(buffer.active_count.load(Ordering::Acquire), 1);
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
    let pinned = buffer.cells.get(1).unwrap();
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
        let state =
            Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire)).unwrap();
        assert_eq!(state.term_id(), buffer.initial_term_id);
        assert_ne!(state.state(), SlotState::Free);
    }
    assert!(quarantined, "term 0 never reached reclamation");
    release_loan(&pinned.loan);
    let report = conductor.duty_cycle().unwrap();
    assert!(report.cleaned > 0);
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
    buffer.limit.store(4 * TERM, Ordering::Release);
    for _ in 0..48 {
        let _ = publication
            .append(&small, AppendOptions::default())
            .unwrap();
    }
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.floor.load(Ordering::Acquire), 16_384);
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
    assert_eq!(buffer.floor.load(Ordering::Acquire), 8192);
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
    buffer.floor.store(1, Ordering::Release);
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
    buffer.reserved_head.store(TERM, Ordering::Release);
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.active_count.load(Ordering::Acquire), 1);
    let state = Descriptor::decode(buffer.descriptor(1).unwrap().load(Ordering::Acquire))
        .unwrap()
        .state();
    assert_eq!(state, SlotState::Active);
    // A second cycle is idempotent.
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(buffer.active_count.load(Ordering::Acquire), 1);
}

/// Vectors: 60 payloads of 992 bytes reserve 61440; an 8000-byte message
/// then pads 4096, reports AdminAction, and lands at the next term start.
/// 64 payloads of 992 fill a term exactly, with no PAD.
#[test]
fn pad_then_retry_and_exact_fill_vectors() {
    let buffer = new_buffer(config(2, 1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    buffer.limit.store(4 * TERM, Ordering::Release);
    let small = vec![1u8; 992];
    for _ in 0..60 {
        assert!(matches!(
            publication
                .append(&small, AppendOptions::default())
                .unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    assert_eq!(buffer.reserved_head.load(Ordering::Acquire), 61_440);
    let big = vec![2u8; 8000];
    assert_eq!(
        publication.append(&big, AppendOptions::default()).unwrap(),
        AppendOutcome::AdminAction
    );
    assert_eq!(buffer.reserved_head.load(Ordering::Acquire), TERM);
    assert_eq!(
        publication.append(&big, AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { position: TERM }
    );
    let _ = conductor.duty_cycle().unwrap();

    let exact = new_buffer(config(2, 1)).unwrap();
    let mut exact_publication = exact.publication().unwrap().unwrap();
    exact.limit.store(4 * TERM, Ordering::Release);
    for _ in 0..64 {
        assert!(matches!(
            exact_publication
                .append(&small, AppendOptions::default())
                .unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    assert_eq!(exact.reserved_head.load(Ordering::Acquire), TERM);
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
                    PollOutcome::Overrun { .. } => panic!("required subscriber lapped"),
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
    assert!(buffer.reserved_head.load(Ordering::Acquire) <= TERM / 2);
    assert_eq!(buffer.floor.load(Ordering::Acquire), 0);
    // Acknowledge, then the next poll moves on and the bound advances.
    required.acknowledge();
    assert!(matches!(
        required.poll(&mut out).unwrap(),
        PollOutcome::Message { position, .. } if position > 0
    ));
    required.acknowledge();
    let _ = conductor.duty_cycle().unwrap();
    assert!(buffer.floor.load(Ordering::Acquire) > 0);
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
    buffer.limit.store(4 * TERM, Ordering::Release);
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
        buffer.cells[1].position.load(Ordering::Acquire),
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
    buffer.floor.store(1, Ordering::Release);
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
                    PollOutcome::Overrun { .. } => panic!("a required subscriber was lapped"),
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
                    PollOutcome::Pending => {
                        // Done once everything is published and the
                        // cursor reached the final head; receiving the
                        // last message is not required (it may be lost).
                        if published.load(Ordering::Acquire)
                            && optional.position()
                                >= buffer.reserved_head.load(Ordering::Acquire)
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
        assert!(buffer.active_count.load(Ordering::Acquire) >= slots);
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
