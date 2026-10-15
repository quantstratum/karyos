// SPDX-License-Identifier: Apache-2.0

// Losing a participant (roadmap P4, batch p4a; quantstratum-docs:
// `karyos/design/required-participant-loss.md`): the cell states, the
// revocation under each policy, the rescan and `PollOutcome::Revoked`.
// Included once per term backing after `common.rs`.

/// Holds a read loan on term 0 for `cell`, as a reader paused inside its
/// copy would.
fn hold_loan(buffer: &LogBuffer<Terms>, cell: usize) {
    let found = buffer.cells().get(cell).unwrap();
    let target = buffer.target(0, TermCount::ZERO).unwrap();
    assert_eq!(
        take_loan(
            &found.loan,
            &found.revoked,
            buffer.descriptor(0).unwrap(),
            target
        ),
        Ok(LoanOutcome::Granted)
    );
}

fn cell_state(buffer: &LogBuffer<Terms>, cell: usize) -> u64 {
    buffer.cells()[cell].state.load(Ordering::Acquire)
}

#[test]
fn test_log_buffer_loss_hold_keeps_the_bound_while_a_loan_is_held() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe_as(Role::Required, false, 7).unwrap();
    let cell = required.cell();
    let mut publication = buffer.publication().unwrap().unwrap();
    hold_loan(&buffer, cell);
    assert_eq!(
        conductor.revoke_participant(cell, 7, LossPolicy::Hold),
        Ok(Revocation::Holding)
    );
    assert_eq!(cell_state(&buffer, cell), CELL_LOST_HOLDING);
    // No longer connected, but it still bounds the publisher.
    assert_eq!(buffer.attached_subscribers(), 0);
    let data = vec![1u8; 1000];
    let mut back_pressured = false;
    for _ in 0..1000 {
        match publication.append(&data, AppendOptions::default()).unwrap() {
            AppendOutcome::BackPressured => {
                back_pressured = true;
                break;
            }
            AppendOutcome::AdminAction => {
                let report = conductor.duty_cycle().unwrap();
                assert_eq!(report.bounds_withdrawn, 0);
            }
            AppendOutcome::Appended { .. } => {}
            AppendOutcome::Closed => panic!("not sealed"),
        }
    }
    assert!(back_pressured, "a holding reader stopped bounding");
    // The loan ends: the next duty cycle withdraws the bound.
    release_loan(&buffer.cells()[cell].loan);
    assert_eq!(conductor.duty_cycle().unwrap().bounds_withdrawn, 1);
    assert_eq!(cell_state(&buffer, cell), CELL_LOST);
    let _ = conductor.duty_cycle().unwrap();
    assert!(matches!(
        publication.append(&data, AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { .. }
    ));
    // The reader learns it was revoked, again on every later poll.
    assert!(matches!(poll(&mut required), PollOutcome::Revoked { .. }));
    assert!(matches!(poll(&mut required), PollOutcome::Revoked { .. }));
    // Its own detach frees the cell (the detach proof).
    drop(required);
    assert_eq!(cell_state(&buffer, cell), CELL_FREE);
}

#[test]
fn test_log_buffer_loss_hold_without_a_loan_withdraws_at_once() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let required = conductor.subscribe_as(Role::Required, false, 7).unwrap();
    let cell = required.cell();
    assert_eq!(
        conductor.revoke_participant(cell, 7, LossPolicy::Hold),
        Ok(Revocation::Withdrawn)
    );
    assert_eq!(cell_state(&buffer, cell), CELL_LOST);
    assert_eq!(buffer.attached_subscribers(), 0);
}

#[test]
fn test_log_buffer_loss_continue_withdraws_at_once_and_keeps_the_credit() {
    // S = 3: two credits, one taken by the exclusive publication.
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let reserved = conductor.subscribe_as(Role::Required, true, 9).unwrap();
    let cell = reserved.cell();
    assert_eq!(cell_state(&buffer, cell), CELL_REQUIRED_RESERVED);
    // Its credit is taken: no optional reader fits.
    assert_eq!(
        conductor.subscribe(Role::Optional).err(),
        Some(SysError::ResourcesUnavailable)
    );
    hold_loan(&buffer, cell);
    assert_eq!(
        conductor.revoke_participant(cell, 9, LossPolicy::Continue),
        Ok(Revocation::Withdrawn)
    );
    assert_eq!(cell_state(&buffer, cell), CELL_LOST_RESERVED);
    // The credit stays charged while the cell may still be accessed.
    assert_eq!(
        conductor.subscribe(Role::Optional).err(),
        Some(SysError::ResourcesUnavailable)
    );
    release_loan(&buffer.cells()[cell].loan);
    drop(reserved);
    assert!(conductor.subscribe(Role::Optional).is_ok());
}

#[test]
fn test_log_buffer_loss_abort_seals_the_buffer() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let required = conductor.subscribe_as(Role::Required, false, 7).unwrap();
    assert_eq!(
        conductor.revoke_participant(required.cell(), 7, LossPolicy::Abort),
        Ok(Revocation::Sealed)
    );
    assert_eq!(cell_state(&buffer, required.cell()), CELL_LOST);
    assert_ne!(conductor.seal_state(), SealState::Active);
}

#[test]
fn test_log_buffer_loss_an_optional_reader_is_revoked_under_any_policy() {
    for policy in [LossPolicy::Hold, LossPolicy::Continue, LossPolicy::Abort] {
        let buffer = new_buffer(config(3, 3)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut optional = conductor.subscribe_as(Role::Optional, false, 11).unwrap();
        assert_eq!(
            conductor.revoke_participant(optional.cell(), 11, policy),
            Ok(Revocation::Withdrawn)
        );
        assert_eq!(cell_state(&buffer, optional.cell()), CELL_LOST_RESERVED);
        assert_eq!(conductor.seal_state(), SealState::Active);
        assert!(matches!(poll(&mut optional), PollOutcome::Revoked { .. }));
    }
}

#[test]
fn test_log_buffer_loss_a_stale_action_leaves_the_next_occupant_untouched() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let first = conductor.subscribe_as(Role::Required, false, 7).unwrap();
    let cell = first.cell();
    drop(first);
    let second = conductor.subscribe_as(Role::Required, false, 8).unwrap();
    assert_eq!(second.cell(), cell);
    // An action for occupant 7 outlived it.
    assert_eq!(
        conductor.revoke_participant(cell, 7, LossPolicy::Hold),
        Ok(Revocation::Stale)
    );
    assert_eq!(cell_state(&buffer, cell), CELL_REQUIRED);
    assert_eq!(buffer.cells()[cell].revoked.load(Ordering::Acquire), 0);
    assert_eq!(buffer.attached_subscribers(), 1);
    // A free cell and an unknown cell are stale too.
    drop(second);
    assert_eq!(
        conductor.revoke_participant(cell, 8, LossPolicy::Hold),
        Ok(Revocation::Stale)
    );
    assert_eq!(
        conductor.revoke_participant(usize::MAX, 8, LossPolicy::Hold),
        Ok(Revocation::Stale)
    );
}

#[test]
fn test_log_buffer_loss_a_policy_that_does_not_match_the_admission_is_refused() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let plain = conductor.subscribe_as(Role::Required, false, 7).unwrap();
    assert!(matches!(
        conductor.revoke_participant(plain.cell(), 7, LossPolicy::Continue),
        Err(SysError::Protocol { .. })
    ));
    drop(plain);
    let reserved = conductor.subscribe_as(Role::Required, true, 8).unwrap();
    assert!(matches!(
        conductor.revoke_participant(reserved.cell(), 8, LossPolicy::Hold),
        Err(SysError::Protocol { .. })
    ));
    // Neither refusal revoked anything.
    assert_eq!(cell_state(&buffer, reserved.cell()), CELL_REQUIRED_RESERVED);
    // Occupant ids are export ids: nonzero, below bit 63.
    for occupant in [0, 1 << 63] {
        assert!(matches!(
            conductor.subscribe_as(Role::Optional, false, occupant),
            Err(SysError::Protocol { .. })
        ));
    }
}
