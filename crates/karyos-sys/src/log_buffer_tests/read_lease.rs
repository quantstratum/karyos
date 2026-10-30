// SPDX-License-Identifier: Apache-2.0

// Read lease tests (R-CORE-45; SPEC.md §16.6), included once per term
// backing by `log_buffer.rs` after `common.rs` and `sender_read.rs`.

/// Leases at the cursor of `reader` for a datagram of the default MTU.
fn rl_lease<'a>(
    reader: &mut SenderRead<&'a LogBuffer<Terms>>,
) -> Result<LeaseOutcome<&'a LogBuffer<Terms>>, ReadError> {
    reader.lease_committed(reader.position(), ReadOrigin::Cursor, DEFAULT_MTU as usize)
}

/// A lease carries exactly the frames a copy carries: the staging path
/// over the lease (`copy_to`) is byte for byte what `read_committed`
/// copies, at the same length and cursor.
#[test]
fn read_lease_bytes_are_those_a_copy_gives() {
    // Two buffers with the same messages: one leased, one copied.
    let leased = new_buffer(config(3, 2)).unwrap();
    let copied_from = new_buffer(config(3, 2)).unwrap();
    leased.install_leases(2).unwrap();
    let mut conductor = leased.conductor().unwrap();
    let mut other = copied_from.conductor().unwrap();
    let mut leasing = sr_reader(&mut conductor);
    let mut copying = sr_reader(&mut other);
    let mut publications = [
        leased.publication().unwrap().unwrap(),
        copied_from.publication().unwrap().unwrap(),
    ];
    for i in 0..5 {
        for publication in &mut publications {
            let _ = publication
                .append(&sized_message(i, 50 + 37 * i as usize), AppendOptions::default())
                .unwrap();
        }
    }
    let buffer = &leased;
    let Ok(LeaseOutcome::Leased(lease)) = rl_lease(&mut leasing) else {
        panic!("not leased");
    };
    assert!(sr_loan_released(&leasing), "the cell's own loan is not used");
    assert_eq!(buffer.leases_live(), 1);
    let mut copied = sr_out();
    let Ok(ReadOutcome::Copied { len, next }) = sr_read(&mut copying, &mut copied) else {
        panic!("not copied");
    };
    assert_eq!((lease.len(), lease.next(), lease.position()), (len, next, 0));
    assert_eq!(leasing.position(), next);
    let mut staged = vec![0xAAu8; DEFAULT_MTU as usize];
    assert_eq!(lease.copy_to(&mut staged), Ok(len));
    assert_eq!(&staged[..len], &copied[..len], "byte for byte");
    assert_eq!(
        lease.copy_to(&mut staged[..len - 1]),
        Err(LeaseCopyError::TooSmall { needed: len })
    );
    drop(lease);
    assert_eq!(buffer.leases_live(), 0);
    let counters = leasing.counters();
    assert_eq!((counters.leases, counters.lease_bytes), (1, len as u64));
    assert_eq!(counters.reads, 0);
}

/// A lease outliving its term's rotation keeps the term: reclaim
/// quarantines the slot while it lives, the bytes read the same, and once
/// it ends the slot is cleaned.
#[test]
fn read_lease_outliving_a_rotation_keeps_its_bytes() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    buffer.install_leases(1).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(9, 300), AppendOptions::default())
        .unwrap();
    let Ok(LeaseOutcome::Leased(lease)) = rl_lease(&mut reader) else {
        panic!("not leased");
    };
    let mut before = sr_out();
    let len = lease.copy_to(&mut before).unwrap();
    sr_sent(&mut reader);
    // Several terms on: the reader copies and registers what it sent, so
    // the floor passes term 0 and its slot comes due for reclaim.
    let slots = u64::from(buffer.slots);
    let mut out = sr_out();
    let mut quarantined = 0;
    while reader.position() < (slots + 1) * TERM {
        let _ = append_retrying(
            &mut publication,
            &mut conductor,
            &sized_message(1, 7000),
            || {},
        );
        while let Ok(ReadOutcome::Copied { .. } | ReadOutcome::Canonical { .. }) =
            sr_read(&mut reader, &mut out)
        {}
        sr_sent(&mut reader);
        quarantined += conductor.duty_cycle().unwrap().quarantined;
    }
    assert!(quarantined > 0, "the leased term was quarantined");
    let mut after = sr_out();
    assert_eq!(lease.copy_to(&mut after), Ok(len));
    assert_eq!(&after[..len], &before[..len], "the term was not cleaned");
    drop(lease);
    let report = conductor.duty_cycle().unwrap();
    assert!(report.cleaned > 0, "cleaned once the lease ended: {report:?}");
    assert_eq!(buffer.leases_live(), 0);
}

/// The bank bounds the live leases: one past it stages, counted, with the
/// cursor unmoved; a buffer with no bank always stages.
#[test]
fn read_lease_past_the_bank_stages() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    for i in 0..2 {
        let _ = publication
            .append(&sized_message(i, 2000), AppendOptions::default())
            .unwrap();
    }
    assert!(matches!(
        rl_lease(&mut reader),
        Ok(LeaseOutcome::Stage(StageReason::BankFull))
    ));
    assert_eq!(reader.position(), 0, "unmoved");
    buffer.install_leases(1).unwrap();
    assert_eq!(buffer.install_leases(2), Err(SysError::ResourcesUnavailable));
    // A frame per lease: the MTU holds one 2000-byte message.
    let Ok(LeaseOutcome::Leased(first)) = rl_lease(&mut reader) else {
        panic!("not leased");
    };
    let at = reader.position();
    assert!(matches!(
        rl_lease(&mut reader),
        Ok(LeaseOutcome::Stage(StageReason::BankFull))
    ));
    assert_eq!(reader.position(), at, "unmoved");
    assert_eq!(reader.counters().leases_staged, 2);
    drop(first);
    // The rest, a lease at a time (each ends at once), to the head.
    let mut leased = 0;
    while let Ok(LeaseOutcome::Leased(_)) = rl_lease(&mut reader) {
        leased += 1;
    }
    assert!(leased > 0);
    assert!(matches!(rl_lease(&mut reader), Ok(LeaseOutcome::Pending)));
    assert_eq!(buffer.leases_live(), 0);
}

/// Padding at the cursor is a canonical record, synthesized: it stages,
/// the lease word stays empty, and the copy path then produces it.
#[test]
fn read_lease_of_a_record_stages() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    buffer.install_leases(1).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut out = sr_out();
    // Nine 7000-byte messages (7200 bytes each) and a 600-byte one leave
    // 96 bytes in term 0; the next message pads them.
    let mut sizes = vec![7000; 9];
    sizes.extend([600, 100]);
    for size in sizes {
        let _ = append_retrying(
            &mut publication,
            &mut conductor,
            &sized_message(3, size),
            || {},
        );
        while reader.position() < TERM - 96
            && let Ok(ReadOutcome::Copied { .. }) = sr_read(&mut reader, &mut out)
        {}
        sr_sent(&mut reader);
    }
    assert_eq!(reader.position(), TERM - 96);
    assert!(matches!(
        rl_lease(&mut reader),
        Ok(LeaseOutcome::Stage(StageReason::Record))
    ));
    assert_eq!(buffer.leases_live(), 0);
    assert_eq!(reader.position(), TERM - 96, "unmoved");
    assert!(matches!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Canonical {
            record: CanonicalKind::Pad,
            ..
        })
    ));
    assert!(matches!(rl_lease(&mut reader), Ok(LeaseOutcome::Leased(_))));
}

/// A lease ends on whichever thread drops it, as a backend's completion
/// does: the term is cleaned after, never before.
#[test]
fn read_lease_released_on_another_thread() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    buffer.install_leases(1).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(4, 120), AppendOptions::default())
        .unwrap();
    let Ok(LeaseOutcome::Leased(lease)) = rl_lease(&mut reader) else {
        panic!("not leased");
    };
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let mut out = sr_out();
                assert!(lease.copy_to(&mut out).is_ok());
            })
            .join()
            .unwrap();
    });
    assert_eq!(buffer.leases_live(), 0);
}
