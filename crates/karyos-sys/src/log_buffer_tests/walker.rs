// SPDX-License-Identifier: Apache-2.0

// The driver's walker (quantstratum-docs:
// `karyos/design/guards-and-abort.md`, "Local streams"): an observer that
// does not keep the publication connected and is not listed as a
// subscriber; credit, lapping, revocation and the seal's retirement are as
// for an observer. Included once per term backing after `observer.rs`,
// whose `publish_running_duty` it uses, and `seal.rs` (`drain_to_end`).

#[test]
fn test_walker_does_not_bound_the_limit() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _walker = conductor.subscribe(Role::Walker).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let window = u64::from(buffer.term_length() / 2);
    for sequence in 0..4 {
        assert!(matches!(
            publication
                .append(&message(sequence), AppendOptions::default())
                .unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    let _ = conductor.duty_cycle().unwrap();
    let head = conductor.head().unwrap();
    assert!(head > 0);
    // The limit follows the head, as with no reader at all; the stalled
    // walker at position 0 holds only the floor.
    assert_eq!(buffer.limit().load(Ordering::Acquire), head + window);
    assert_eq!(buffer.floor().load(Ordering::Acquire), 0);
}

/// Coordinator, ACS 15161: a fast required reader moves the limit and
/// would move the floor past a slow observer; the walker holds the floor,
/// so it is never lapped. The publisher stalls on reclamation instead.
#[test]
fn test_walker_is_never_lapped_behind_a_fast_required_reader() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe(Role::Required).unwrap();
    let mut walker = conductor.subscribe(Role::Walker).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = vec![3u8; 7000];
    let mut appended = 0u32;
    // Bounded: the stalled walker eventually stops the publisher.
    for _ in 0..400 {
        if matches!(
            publication.append(&data, AppendOptions::default()).unwrap(),
            AppendOutcome::Appended { .. }
        ) {
            appended += 1;
        }
        while poll_message(&mut required).is_some() {}
        let _ = conductor.duty_cycle().unwrap();
    }
    assert!(appended > 4, "the publisher never moved: {appended}");
    // The walker reads every message from the start: no overrun.
    let mut out = vec![0u8; 8192];
    for _ in 0..appended {
        match walker.poll(&mut out).unwrap() {
            PollOutcome::Message { length, .. } => assert_eq!(length, 7000),
            other => panic!("the walker was lapped or stalled: {other:?}"),
        }
    }
    // Once it has passed them, reclamation proceeds and the publisher runs.
    let _ = conductor.duty_cycle().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    let mut resumed = false;
    for _ in 0..20 {
        if matches!(
            publication.append(&data, AppendOptions::default()).unwrap(),
            AppendOutcome::Appended { .. }
        ) {
            resumed = true;
            break;
        }
        while poll_message(&mut required).is_some() {}
        let _ = conductor.duty_cycle().unwrap();
    }
    assert!(resumed, "reclamation did not proceed after the walker passed");
}

#[test]
fn test_walker_credit_counts_against_spares() {
    // S = 4, C = 1: three credits for the publication, an observer and
    // the walker.
    let buffer = new_buffer(config(4, 4)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let _observer = conductor.subscribe(Role::Observer).unwrap();
    let walker = conductor.subscribe(Role::Walker).unwrap();
    assert_eq!(
        conductor.subscribe(Role::Walker).err(),
        Some(SysError::ResourcesUnavailable)
    );
    walker.close();
    assert!(conductor.subscribe(Role::Walker).is_ok());
}

#[test]
fn test_walker_does_not_connect_and_is_not_listed() {
    let buffer = new_buffer(config(4, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let walker = conductor.subscribe(Role::Walker).unwrap();
    assert_eq!(cell_state(&buffer, walker.cell()), CELL_WALKER);
    assert_eq!(buffer.attached_subscribers(), 0, "the walker connected");
    assert_eq!(conductor.subscribers().count(), 0, "the walker is listed");
    // Its position is still known to the driver by cell.
    assert_eq!(conductor.cell_position(walker.cell()), Some(0));
    // A real observer connects and is listed beside it.
    let observer = conductor.subscribe(Role::Observer).unwrap();
    assert_eq!(buffer.attached_subscribers(), 1);
    let listed: Vec<usize> = conductor.subscribers().map(|cell| cell.cell).collect();
    assert_eq!(listed, [observer.cell()]);
    observer.close();
    assert_eq!(buffer.attached_subscribers(), 0);
    walker.close();
}

#[test]
fn test_walker_is_revoked_like_an_optional_reader() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let cell = conductor.register_subscriber(Role::Walker, 9).unwrap();
    assert_eq!(cell_state(&buffer, cell), CELL_WALKER);
    let _ = conductor
        .revoke_participant(cell, 9, LossPolicy::Hold)
        .unwrap();
    assert_eq!(cell_state(&buffer, cell), CELL_LOST_RESERVED);
}

/// The seal retires only once the walker passed its position: the walker's
/// last pass reads every frame up to the seal.
#[test]
fn test_walker_holds_the_seal_until_it_passes() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut walker = conductor.subscribe(Role::Walker).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    for sequence in 0..3 {
        assert!(matches!(
            publication
                .append(&message(sequence), AppendOptions::default())
                .unwrap(),
            AppendOutcome::Appended { .. }
        ));
    }
    conductor.seal().unwrap();
    assert_eq!(
        publication.append(&message(9), AppendOptions::default()).unwrap(),
        AppendOutcome::Closed
    );
    let _ = conductor.duty_cycle().unwrap();
    assert!(
        !matches!(conductor.seal_state(), SealState::Retired { .. }),
        "retired before the walker passed the seal"
    );
    // The walker reads the three messages, then the positioned seal.
    let (read, end) = drain_to_end(&mut walker);
    assert_eq!(read, 3);
    assert!(matches!(end, PollOutcome::Closed { .. }), "{end:?}");
    let _ = conductor.duty_cycle().unwrap();
    assert!(matches!(conductor.seal_state(), SealState::Retired { .. }));
}
