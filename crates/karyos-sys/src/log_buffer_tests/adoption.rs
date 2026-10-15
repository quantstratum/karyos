// SPDX-License-Identifier: Apache-2.0

// Registration for another process and adoption
// (`quantstratum-docs: karyos/design/ipc-log-buffer.md`), on one backing in one process: the
// creator registers through its conductor, a "participant" adopts from the
// same buffer. Included once per term backing after `common.rs`.

#[test]
fn an_adopted_subscriber_reads_what_the_creator_publishes() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let cell = conductor.register_subscriber(Role::Required, 7).unwrap();
    let mut adopted = Subscription::adopt(&buffer, cell, Role::Required, 7).unwrap();
    assert_eq!(adopted.cell(), cell);
    for sequence in 0..3 {
        assert!(matches!(
            publication.append(&message(sequence), AppendOptions::default()).unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    for _ in 0..3 {
        assert!(matches!(poll(&mut adopted), PollOutcome::Message { .. }));
        adopted.acknowledge();
    }
    assert_eq!(poll(&mut adopted), PollOutcome::Pending);
    // The adopted handle bounds the publisher like any required reader:
    // its drop detaches the cell.
    drop(adopted);
    assert!(matches!(
        Subscription::adopt(&buffer, cell, Role::Required, 7),
        Err(SysError::Protocol { .. })
    ));
}

#[test]
fn an_adopted_exclusive_publication_publishes_once_and_fresh() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    assert!(conductor.register_publication(11).unwrap());
    assert!(!conductor.register_publication(12).unwrap());
    assert!(buffer.publication().unwrap().is_none());
    assert!(matches!(
        Publication::adopt(&buffer, 12),
        Err(SysError::Protocol { .. })
    ));
    let mut adopted = Publication::adopt(&buffer, 11).unwrap();
    assert!(matches!(
        adopted.append(&message(1), AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { .. }
    ));
    assert!(matches!(poll(&mut subscription), PollOutcome::Message { .. }));
    // No longer fresh: a second adoption of the same grant is refused.
    assert!(matches!(
        Publication::adopt(&buffer, 11),
        Err(SysError::Protocol { .. })
    ));
}

#[test]
fn an_adopted_concurrent_handle_publishes_and_frees_its_slot() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let slot = conductor.register_concurrent_publication(21).unwrap().unwrap();
    let other = conductor.register_concurrent_publication(22).unwrap().unwrap();
    assert_ne!(slot, other);
    assert!(conductor.register_concurrent_publication(23).unwrap().is_none());
    assert!(matches!(
        ConcurrentPublication::adopt(&buffer, slot, 22),
        Err(SysError::Protocol { .. })
    ));
    let mut adopted = ConcurrentPublication::adopt(&buffer, slot, 21).unwrap();
    assert!(matches!(
        adopted.offer(&message(5), AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { .. }
    ));
    assert!(matches!(poll(&mut subscription), PollOutcome::Message { .. }));
    drop(adopted);
    // The slot is free again; its registration names an export never
    // reused, so the old grant cannot be adopted any more.
    assert!(matches!(
        ConcurrentPublication::adopt(&buffer, slot, 21),
        Err(SysError::Protocol { .. })
    ));
    assert!(conductor.register_concurrent_publication(24).unwrap().is_some());
}

#[test]
fn adoption_refuses_what_was_not_granted() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let cell = conductor.register_subscriber(Role::Optional, 3).unwrap();
    // Wrong export, wrong role, export 0, a publisher cell, a free cell, an
    // index past the end.
    for (cell, role, export) in [
        (cell, Role::Optional, 4),
        (cell, Role::Required, 3),
        (cell, Role::Optional, 0),
        (0, Role::Optional, 3),
        (cell + 1, Role::Optional, 3),
        (usize::MAX, Role::Optional, 3),
    ] {
        assert!(matches!(
            Subscription::adopt(&buffer, cell, role, export),
            Err(SysError::Protocol { .. })
        ));
    }
    assert!(matches!(
        conductor.register_subscriber(Role::Optional, 0),
        Err(SysError::Protocol { .. })
    ));
    assert!(matches!(
        conductor.register_publication(0),
        Err(SysError::Protocol { .. })
    ));
    // The publication was never registered.
    assert!(matches!(
        Publication::adopt(&buffer, 3),
        Err(SysError::Protocol { .. })
    ));
    // Modes: no concurrent registration or adoption on an exclusive
    // buffer, and the reverse.
    assert!(matches!(
        conductor.register_concurrent_publication(9),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    assert!(matches!(
        ConcurrentPublication::adopt(&buffer, 0, 9),
        Err(SysError::InvalidPublicationMode { .. })
    ));
}

#[test]
fn a_grant_is_adopted_once() {
    // Subscriber: a second live adoption of the same registration would
    // share one cell between two cursors.
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let cell = conductor.register_subscriber(Role::Required, 42).unwrap();
    let first = Subscription::adopt(&buffer, cell, Role::Required, 42).unwrap();
    assert!(matches!(
        Subscription::adopt(&buffer, cell, Role::Required, 42),
        Err(SysError::Protocol { .. })
    ));
    drop(first);

    // Exclusive publication: two fresh adoptions would hold two loans.
    assert!(conductor.register_publication(43).unwrap());
    let publication = Publication::adopt(&buffer, 43).unwrap();
    assert!(matches!(
        Publication::adopt(&buffer, 43),
        Err(SysError::Protocol { .. })
    ));
    drop(publication);

    // Concurrent publication: two handles would share one publisher slot.
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let slot = conductor.register_concurrent_publication(41).unwrap().unwrap();
    let handle = ConcurrentPublication::adopt(&buffer, slot, 41).unwrap();
    assert!(matches!(
        ConcurrentPublication::adopt(&buffer, slot, 41),
        Err(SysError::Protocol { .. })
    ));
    drop(handle);

    // An export with the adopted bit cannot be registered, so no
    // registration word can equal an adopted one.
    assert!(matches!(
        conductor.register_concurrent_publication(41 | 1 << 63),
        Err(SysError::Protocol { .. })
    ));
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    for export in [1u64 << 63, u64::MAX] {
        assert!(matches!(
            conductor.register_subscriber(Role::Optional, export),
            Err(SysError::Protocol { .. })
        ));
        assert!(matches!(
            conductor.register_publication(export),
            Err(SysError::Protocol { .. })
        ));
    }
}

#[test]
fn an_ended_subscriber_frees_its_cell_and_its_grant_is_spent() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let cell = conductor.register_subscriber(Role::Required, 7).unwrap();
    assert_eq!(buffer.attached_subscribers(), 1);
    // A wrong export, a publisher cell and an out of range cell are stale.
    assert!(!conductor.end_subscriber(cell, 8));
    assert!(!conductor.end_subscriber(0, 7));
    assert!(!conductor.end_subscriber(usize::MAX, 7));
    // Never adopted: the driver ends it on its own knowledge.
    assert!(conductor.end_subscriber(cell, 7));
    assert_eq!(buffer.attached_subscribers(), 0);
    assert_eq!(buffer.cells()[cell].registration.load(Ordering::Acquire), 0);
    assert!(matches!(
        Subscription::adopt(&buffer, cell, Role::Required, 7),
        Err(SysError::Protocol { .. })
    ));
    assert!(!conductor.end_subscriber(cell, 7));
}

#[test]
fn an_adopted_subscriber_is_ended_with_its_loan() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let cell = conductor.register_subscriber(Role::Required, 7).unwrap();
    let adopted = Subscription::adopt(&buffer, cell, Role::Required, 7).unwrap();
    // The participant died holding a loan; its handle is never dropped.
    let found = &buffer.cells()[cell];
    let target = buffer.target(0, TermCount::ZERO).unwrap();
    assert_eq!(
        take_loan(&found.loan, &found.revoked, buffer.descriptor(0).unwrap(), target),
        Ok(LoanOutcome::Granted)
    );
    core::mem::forget(adopted);
    assert!(conductor.end_subscriber(cell, 7));
    assert_eq!(found.loan.load(Ordering::Acquire), 0);
    assert_eq!(found.registration.load(Ordering::Acquire), 0);
    assert_eq!(buffer.attached_subscribers(), 0);
}

#[test]
fn a_delayed_end_never_touches_a_later_occupant() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let cell = conductor.register_subscriber(Role::Required, 7).unwrap();
    assert!(conductor.end_subscriber(cell, 7));
    // Reused by another remote grant, then by an in-process subscriber.
    assert_eq!(conductor.register_subscriber(Role::Required, 9).unwrap(), cell);
    assert!(!conductor.end_subscriber(cell, 7));
    assert_eq!(buffer.attached_subscribers(), 1);
    assert!(conductor.end_subscriber(cell, 9));
    let local = conductor.subscribe(Role::Required).unwrap();
    assert_eq!(local.cell(), cell);
    assert!(!conductor.end_subscriber(cell, 7));
    assert!(!conductor.end_subscriber(cell, 9));
    assert_eq!(buffer.attached_subscribers(), 1);
}

#[test]
fn an_ordinary_detach_clears_the_registration_before_freeing() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let cell = conductor.register_subscriber(Role::Optional, 7).unwrap();
    let adopted = Subscription::adopt(&buffer, cell, Role::Optional, 7).unwrap();
    drop(adopted);
    assert_eq!(buffer.cells()[cell].registration.load(Ordering::Acquire), 0);
    // The delayed Detach that follows ends nothing.
    assert!(!conductor.end_subscriber(cell, 7));
}

#[test]
fn ended_publications_clear_their_registration() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    assert!(conductor.register_publication(11).unwrap());
    let adopted = Publication::adopt(&buffer, 11).unwrap();
    drop(adopted);
    assert_eq!(
        buffer
            .control()
            .publication_registration
            .word
            .load(Ordering::Acquire),
        0
    );
}

#[test]
fn an_export_at_a_mark_is_refused() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    for export in [0, registration::FENCED, registration::ADOPTED] {
        assert!(matches!(
            conductor.register_subscriber(Role::Required, export),
            Err(SysError::Protocol { .. })
        ));
    }
    assert!(
        conductor
            .register_subscriber(Role::Required, registration::MAX_EXPORT)
            .is_ok()
    );
}

#[test]
fn a_dropped_concurrent_handle_clears_its_slot_registration() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let slot = conductor.register_concurrent_publication(21).unwrap().unwrap();
    let adopted = ConcurrentPublication::adopt(&buffer, slot, 21).unwrap();
    assert_eq!(
        buffer.publisher_lines()[slot]
            .registration
            .load(Ordering::Acquire),
        21 | registration::ADOPTED
    );
    drop(adopted);
    assert_eq!(
        buffer.publisher_lines()[slot]
            .registration
            .load(Ordering::Acquire),
        0
    );
}

#[test]
fn an_ended_concurrent_registration_frees_its_slot_at_the_next_service() {
    let buffer = new_buffer(deadline_concurrent_config(1)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let slot = conductor.register_concurrent_publication(21).unwrap().unwrap();
    assert_eq!(conductor.end_concurrent_publication(slot, 22), Ok(false));
    assert_eq!(conductor.end_concurrent_publication(9, 21), Ok(false));
    assert_eq!(conductor.end_concurrent_publication(slot, 21), Ok(true));
    assert_eq!(conductor.end_concurrent_publication(slot, 21), Ok(false));
    // Ended: the grant cannot be adopted, and the slot is held until a
    // service passes the head observed at the end.
    assert!(matches!(
        ConcurrentPublication::adopt(&buffer, slot, 21),
        Err(SysError::Protocol { .. })
    ));
    assert_eq!(conductor.ending_publishers(), 1);
    assert!(conductor.concurrent_publication().unwrap().is_none());
    assert_eq!(serve(&mut conductor, 0), DeadlineReport::default());
    assert_eq!(conductor.ending_publishers(), 0);
    assert!(conductor.concurrent_publication().unwrap().is_some());
}

#[test]
fn a_dead_concurrent_publisher_is_resolved_by_the_deadline_only() {
    let buffer = new_buffer(deadline_concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let slot = conductor.register_concurrent_publication(21).unwrap().unwrap();
    let mut dead = ConcurrentPublication::adopt(&buffer, slot, 21).unwrap();
    let mut live = conductor.concurrent_publication().unwrap().unwrap();
    // The dead publisher dies with a block open; the live one keeps
    // writing in the same term.
    core::mem::forget(concurrent_claimed(dead.try_claim(8, AppendOptions::default())));
    dead.die();
    assert!(matches!(
        live.offer(&message(1), AppendOptions::default()).unwrap(),
        ConcurrentOfferOutcome::Appended { .. }
    ));
    assert_eq!(conductor.end_concurrent_publication(slot, 21), Ok(true));
    assert_eq!(serve(&mut conductor, 0), waiting());
    // Before the deadline nothing is aborted and the slot keeps its loan.
    assert_eq!(serve(&mut conductor, DEADLINE - 1), waiting());
    assert_eq!(conductor.ending_publishers(), 1);
    assert_ne!(buffer.cells()[slot].loan.load(Ordering::Acquire), 0);
    let report = serve(&mut conductor, DEADLINE);
    assert_eq!(report.aborted, 1);
    let _ = serve(&mut conductor, DEADLINE);
    assert_eq!(conductor.ending_publishers(), 0);
    assert_eq!(buffer.cells()[slot].loan.load(Ordering::Acquire), 0);
    // Readers skip the aborted block and get the live publisher's message.
    assert!(matches!(poll(&mut subscription), PollOutcome::Aborted { .. }));
    assert_eq!(poll_message(&mut subscription), Some(message(1)));
    // The freed slot is issued again; the live one is still held.
    let _reissued = conductor.concurrent_publication().unwrap().unwrap();
    assert!(conductor.concurrent_publication().unwrap().is_none());
    drop(live);
}

#[test]
fn ending_a_concurrent_publication_of_an_exclusive_buffer_is_refused() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    assert!(matches!(
        conductor.end_concurrent_publication(0, 21),
        Err(SysError::InvalidPublicationMode { .. })
    ));
}
