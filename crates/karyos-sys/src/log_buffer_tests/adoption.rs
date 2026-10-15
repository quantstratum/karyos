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
