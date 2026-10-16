// SPDX-License-Identifier: Apache-2.0

// The driver's walker (quantstratum-docs:
// `karyos/design/guards-and-abort.md`, "Local streams"): an observer that
// does not keep the publication connected and is not listed as a
// subscriber; credit, lapping, revocation and the seal's retirement are as
// for an observer. Included once per term backing after `observer.rs`,
// whose `publish_running_duty` it uses, and `seal.rs` (`drain_to_end`).

#[test]
fn test_walker_never_bounds_the_limit() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut walker = conductor.subscribe(Role::Walker).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = vec![3u8; 7000];
    let back_pressured = publish_running_duty(&mut publication, &mut conductor, &data, 60);
    assert_eq!(back_pressured, 0, "the walker bounded the publisher");
    assert!(matches!(poll(&mut walker), PollOutcome::Overrun { from: 0, .. }));
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
