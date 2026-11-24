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
            AppendOutcome::Closed | AppendOutcome::Gated => panic!("not sealed"),
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

/// A revoked required reader whose data the publisher then overwrote (its
/// bound was withdrawn under `continue`) is told it was revoked, not that a
/// required reader was lapped: a resumed reader gets `Revoked`
/// (`quantstratum-docs: karyos/design/required-participant-loss.md`).
#[test]
fn test_log_buffer_loss_a_revoked_reader_whose_data_is_gone_is_revoked() {
    let buffer = new_buffer(config(3, 3)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = conductor.subscribe_as(Role::Required, true, 9).unwrap();
    assert_eq!(
        conductor.revoke_participant(reader.cell(), 9, LossPolicy::Continue),
        Ok(Revocation::Withdrawn)
    );
    // The publisher runs far past the reader's data.
    let mut publication = buffer.publication().unwrap().unwrap();
    // Under Miri the run stops once the publisher has written two terms
    // more than the slots hold, so every slot, the reader's included, was
    // rewritten (karyos#161); elsewhere it runs the full 2000 messages.
    let past = (u64::from(buffer.slots) + 2) * u64::from(buffer.term_length());
    let mut appended = 0;
    let mut bytes = 0u64;
    for sequence in 0..2000 {
        let data = message(sequence);
        if let AppendOutcome::Appended { .. } = publication
            .append(&data, AppendOptions::default())
            .unwrap()
        {
            appended += 1;
            bytes += data.len() as u64;
        }
        let _ = conductor.duty_cycle().unwrap();
        if cfg!(miri) && bytes > past {
            break;
        }
    }
    if cfg!(miri) {
        assert!(bytes > past, "{bytes} <= {past}");
    } else {
        assert!(appended > 1000, "{appended}");
    }
    let mut out = vec![0u8; 8192];
    assert!(matches!(
        reader.poll(&mut out),
        Ok(PollOutcome::Revoked { .. })
    ));
}

/// Credits in use, as admission counts them: the publishers' plus every
/// subscriber cell that holds a spare-slot credit.
fn credits_in_use(buffer: &LogBuffer<Terms>) -> u32 {
    let subscribers = buffer
        .cells()
        .iter()
        .skip(buffer.first_subscriber_cell())
        .filter(|cell| holds_credit(cell.state.load(Ordering::Acquire)))
        .count() as u32;
    buffer.first_subscriber_cell() as u32 + subscribers
}

/// SPEC.md §13 "No re-admission bypass": an evicted optional reader that
/// still holds a loan asks to rejoin, as its own occupant. It is refused
/// with `ResourcesUnavailable` while its loan lasts and while its cell is
/// not freed, under every policy; only after its loan ends and its cell is
/// freed is the same occupant admitted again. At every step the credits in
/// use never exceed `S - C`.
#[test]
fn test_log_buffer_loss_an_evicted_reader_holding_a_loan_cannot_rejoin_until_its_loans_end() {
    for policy in [LossPolicy::Hold, LossPolicy::Continue, LossPolicy::Abort] {
        // S = 3, C = 1: two credits, one taken by the exclusive publication.
        let buffer = new_buffer(config(3, 3)).unwrap();
        let limit = u32::from(buffer.spare_slots - CLEANING_HEADROOM);
        let mut conductor = buffer.conductor().unwrap();
        let evicted = conductor.subscribe_as(Role::Optional, false, 11).unwrap();
        let cell = evicted.cell();
        assert_eq!(credits_in_use(&buffer), limit);
        hold_loan(&buffer, cell);
        assert_eq!(
            conductor.revoke_participant(cell, 11, policy),
            Ok(Revocation::Withdrawn)
        );
        assert_eq!(cell_state(&buffer, cell), CELL_LOST_RESERVED);
        // The evicted reader asks to rejoin while it holds its loan: refused,
        // as an optional reader or an observer, and nothing is admitted.
        for role in [Role::Optional, Role::Observer] {
            assert_eq!(
                conductor.subscribe_as(role, false, 11).err(),
                Some(SysError::ResourcesUnavailable),
                "{policy:?} {role:?}: rejoined under a live loan"
            );
            assert_eq!(credits_in_use(&buffer), limit);
        }
        // The loan ends, but the cell is not freed until the holder leaves:
        // still refused.
        release_loan(&buffer.cells()[cell].loan);
        let _ = conductor.duty_cycle().unwrap();
        assert_eq!(
            conductor.subscribe_as(Role::Optional, false, 11).err(),
            Some(SysError::ResourcesUnavailable),
            "{policy:?}: rejoined before its cell was freed"
        );
        assert_eq!(credits_in_use(&buffer), limit);
        // Its loans ended and its cell is freed: the same occupant rejoins,
        // within the credits.
        drop(evicted);
        assert_eq!(cell_state(&buffer, cell), CELL_FREE);
        let rejoined = conductor.subscribe_as(Role::Optional, false, 11).unwrap();
        assert_eq!(credits_in_use(&buffer), limit);
        assert_eq!(
            conductor.subscribe(Role::Optional).err(),
            Some(SysError::ResourcesUnavailable)
        );
        drop(rejoined);
    }
}

/// SPEC.md §13 "Required participant revocation": while a revoked reader
/// may still touch its cell (its loan word, its flag), no participant is
/// admitted into that cell. With one subscriber cell, a required reader
/// revoked under `hold` while holding a loan leaves its cell
/// `LOST_HOLDING`, then `LOST` once a rescan finds the loan ended; under
/// `continue` it is `LOST_RESERVED`. In every case an admission is refused
/// and the cell keeps the revoked reader's flag, registration and state;
/// only the reader's own detach frees it, and the next participant starts
/// with a clear flag and an empty loan word.
#[test]
fn test_log_buffer_loss_no_admission_into_a_lost_cell_while_its_reader_may_touch_it() {
    for (policy, reserve, held, lost) in [
        (LossPolicy::Hold, false, CELL_LOST_HOLDING, CELL_LOST),
        (
            LossPolicy::Continue,
            true,
            CELL_LOST_RESERVED,
            CELL_LOST_RESERVED,
        ),
    ] {
        let buffer = new_buffer(config(3, 1)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut revoked = conductor.subscribe_as(Role::Required, reserve, 7).unwrap();
        let cell = revoked.cell();
        let refused = |conductor: &mut Conductor<&LogBuffer<Terms>>| {
            for (role, reserve) in [
                (Role::Required, false),
                (Role::Required, true),
                (Role::Optional, false),
            ] {
                assert_eq!(
                    conductor.subscribe_as(role, reserve, 8).err(),
                    Some(SysError::ResourcesUnavailable),
                    "{policy:?}: {role:?} admitted into the lost cell"
                );
            }
        };
        hold_loan(&buffer, cell);
        let _ = conductor.revoke_participant(cell, 7, policy).unwrap();
        assert_eq!(cell_state(&buffer, cell), held);
        refused(&mut conductor);
        let found = &buffer.cells()[cell];
        assert_ne!(found.loan.load(Ordering::Acquire), 0, "the loan word was reused");
        assert_ne!(found.revoked.load(Ordering::Acquire), 0, "the flag was cleared");
        // The loan ends; a rescan withdraws a holding bound. The reader may
        // still touch its cell until it detaches: still refused.
        release_loan(&found.loan);
        let _ = conductor.duty_cycle().unwrap();
        assert_eq!(cell_state(&buffer, cell), lost);
        refused(&mut conductor);
        assert_ne!(found.revoked.load(Ordering::Acquire), 0);
        // The reader learns it was revoked, then detaches: the cell is free
        // and the next participant starts clean.
        assert!(matches!(poll(&mut revoked), PollOutcome::Revoked { .. }));
        drop(revoked);
        assert_eq!(cell_state(&buffer, cell), CELL_FREE);
        let next = conductor.subscribe_as(Role::Required, false, 8).unwrap();
        assert_eq!(next.cell(), cell);
        assert_eq!(found.revoked.load(Ordering::Acquire), 0);
        assert_eq!(found.loan.load(Ordering::Acquire), 0);
    }
}

/// karyos#1067: a poll whose loan attempt read the revocation flag clear,
/// just before the driver revoked its reader under `abort` and sealed,
/// then finds the seal positioned at its cursor. It reports the
/// revocation, not the seal; the seal check is the poll's tail after that
/// loan attempt.
#[test]
fn test_log_buffer_loss_a_reader_revoked_during_its_poll_is_revoked_not_closed() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut required = conductor.subscribe_as(Role::Required, false, 7).unwrap();
    assert_eq!(poll(&mut required), PollOutcome::Pending);
    assert_eq!(
        conductor.revoke_participant(required.cell(), 7, LossPolicy::Abort),
        Ok(Revocation::Sealed)
    );
    let _ = conductor.duty_cycle().unwrap();
    assert!(matches!(
        decode_seal(buffer.seal().load(Ordering::Acquire)),
        SealWord::Positioned(0)
    ));
    assert_eq!(
        required.at_seal_or_pending(),
        Ok(PollOutcome::Revoked { position: 0 })
    );
    assert_eq!(poll(&mut required), PollOutcome::Revoked { position: 0 });
}

/// karyos#1067: the same window for a frame reader between messages.
#[test]
fn test_log_buffer_loss_a_frame_reader_revoked_during_its_serve_is_revoked_not_closed() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let required = conductor.subscribe_as(Role::Required, false, 7).unwrap();
    let cell = required.cell();
    let mut reader = FrameReader::new(required);
    assert_eq!(reader.serve_frame().unwrap(), FrameStep::Pending);
    assert_eq!(
        conductor.revoke_participant(cell, 7, LossPolicy::Abort),
        Ok(Revocation::Sealed)
    );
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(
        reader.pending_at_seal(),
        FrameStep::Ended(FrameEnd::Revoked { position: 0 })
    );
}
