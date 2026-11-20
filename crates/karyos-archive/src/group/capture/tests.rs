// SPDX-License-Identifier: Apache-2.0

// The capture path: events through the ring into the journal and its
// prefixes; the ring's room counted exactly across wraps; the in-flight
// bound, lifted once a gap stops the prefixes; references settled when
// their recording ends, in each mode; a failed journal; the waiter; and
// durability that survives a crash at every write boundary.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use karyos_sys::frame::Lane;

use super::*;
use crate::fault::{FaultDisk, Survives};
use crate::group::journal::{JournalConfig, MIN_SEGMENT_LENGTH};
use crate::group::record::{
    Clock, EndOutcome, EventEnd, GapMarker, GapReason, JournalHeader, MAX_RECORD, MessageEvent,
    Payload,
};
use crate::segment::SyncPolicy;

/// Recordings' positions: none here, as for recordings that ended.
#[derive(Default)]
struct Recordings(RefCell<BTreeMap<u64, (u64, u64)>>);

impl Coverage for Recordings {
    fn ended(&self, _recording_id: u64) -> Option<u64> {
        None
    }

    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        self.0.borrow().get(&recording_id).copied()
    }
}

/// A policy that syncs on its own only past the test's time: durability
/// comes from the job's explicit syncs.
const UNSYNCED: SyncPolicy = SyncPolicy::Every {
    interval_ns: u64::MAX,
};

fn header(capture: Capture) -> JournalHeader<'static> {
    JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture,
        reopen_hold: 0,
        manifest: b"m",
    }
}

fn config(policy: SyncPolicy) -> JournalConfig {
    JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy,
    }
}

fn journal(disk: FaultDisk, capture: Capture, policy: SyncPolicy) -> GroupJournal<FaultDisk> {
    GroupJournal::create(disk, Path::new("/g"), &header(capture), config(policy)).unwrap()
}

fn settings(ring_capacity: usize, max_event: usize, in_flight: usize) -> CaptureConfig {
    CaptureConfig {
        ring_capacity,
        max_event,
        in_flight,
    }
}

/// Event `seq`'s records: a message of `length` inline bytes, or naming
/// `recording`'s frames `[0, 64)`, then its end.
fn event(seq: u64, length: usize, recording: Option<u64>) -> Vec<u8> {
    event_at(seq, length, recording, 0, EndOutcome::Complete)
}

/// The bytes an event of 200 bytes takes in its recording (`event_at`'s
/// extent), the stride of [`run_referenced`]'s positions.
const EXTENT: u64 = 256;

/// [`event`] at `position`, ending `outcome`.
fn event_at(
    seq: u64,
    length: usize,
    recording: Option<u64>,
    position: u64,
    outcome: EndOutcome,
) -> Vec<u8> {
    let value = vec![0x5A; length];
    let message = GroupRecord::Message(MessageEvent {
        group_seq: seq,
        logical_time: seq,
        incarnation: 1,
        position,
        extent: u32::try_from(length + 32)
            .unwrap()
            .next_multiple_of(32)
            .max(64),
        stream_id: 1,
        session_id: 1,
        lane: Lane::ZERO,
        reserved_value: 0,
        end_of_stream: false,
        extension: None,
        payload: match recording {
            Some(recording_id) => Payload::Reference {
                recording_id,
                length: 10,
            },
            None => Payload::Inline(&value),
        },
        image: 0,
    });
    let end = GroupRecord::End(EventEnd {
        group_seq: seq,
        observations: 0,
        outcome,
    });
    let mut out = vec![0u8; MAX_RECORD];
    let mut bytes = Vec::new();
    for record in [message, end] {
        let length = record.encode(&mut out).unwrap();
        bytes.extend_from_slice(&out[..length]);
    }
    bytes
}

fn gap(from: u64, to: u64) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = GroupRecord::Gap(GapMarker {
        from_seq: from,
        to_seq: to,
        reason: GapReason::RingFull,
    })
    .encode(&mut out)
    .unwrap();
    out.truncate(length);
    out
}

/// The `group_seq`s of the journal's events and marks, in order.
fn journal_events<D: Disk>(journal: &mut GroupJournal<D>) -> Vec<Role> {
    let mut roles = Vec::new();
    journal
        .walk(0, |_, _, record| {
            if let role @ (Role::Event(_) | Role::Gap(_) | Role::Unavailable(_)) = record.role() {
                roles.push(role);
            }
            true
        })
        .unwrap();
    roles
}

fn new(
    capture_mode: Capture,
    policy: SyncPolicy,
    settings: CaptureConfig,
) -> (CaptureSender, CaptureJob<FaultDisk>) {
    capture(
        settings,
        journal(FaultDisk::default(), capture_mode, policy),
        &Recordings::default(),
    )
    .unwrap()
}

/// Events sent through the ring land in the journal in order, delivered
/// and complete once the job drained them, and durable once synced; a
/// waiter sees it.
#[test]
fn events_go_through_the_ring_into_the_journal_and_its_prefixes() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    let waiter = sender.waiter();
    for seq in 1..=3 {
        sender.admit().unwrap();
        sender.send(&event(seq, 100, None), seq).unwrap();
    }
    assert_eq!(sender.view().snapshot(), (0, 0, 0), "nothing drained yet");
    assert!(job.duty(0, 16, &none).unwrap());
    assert_eq!(sender.view().snapshot(), (3, 3, 0), "written, not durable");
    assert_eq!(
        waiter.wait_durable(3, Duration::ZERO),
        Err(WaitError::Timeout { durable: 0 })
    );
    job.sync(&none).unwrap();
    assert_eq!(sender.view().snapshot(), (3, 3, 3));
    assert_eq!(waiter.wait_durable(3, Duration::ZERO), Ok(3));
    assert_eq!(
        journal_events(&mut job.journal),
        [Role::Event(1), Role::Event(2), Role::Event(3)]
    );
    assert!(!job.duty(0, 16, &none).unwrap(), "nothing more to read");
}

/// The ring's room is counted exactly, padding at a wrap included: an
/// admitted event is always written, and once the job drains, room comes
/// back. Events of every size up to the budget, through a small ring, all
/// arrive in order.
#[test]
fn an_admitted_event_always_fits_the_ring() {
    let none = Recordings::default();
    // A ring of 2048 bytes takes messages of up to 248 bytes: an event of
    // 116 bytes of records and up to 132 of payload.
    let (mut sender, mut job) = new(
        Capture::Strict,
        SyncPolicy::PerSegment,
        settings(2048, 248, 1024),
    );
    let mut sent = 0u64;
    let mut refusals = 0;
    let mut seq = 1u64;
    let mut length = 0usize;
    while seq <= 400 {
        match sender.admit() {
            Ok(()) => {
                let records = event(seq, length % 133, None);
                assert!(records.len() <= 248, "{}", records.len());
                sender.send(&records, seq).unwrap();
                sent += 1;
                seq += 1;
                length += 7;
            }
            Err(Refusal::RingFull) => {
                refusals += 1;
                assert!(job.duty(0, 1 + (refusals % 3), &none).unwrap());
            }
            Err(other) => panic!("{other:?}"),
        }
    }
    while job.duty(0, 16, &none).unwrap() {}
    assert!(refusals > 50, "the ring filled: {refusals}");
    let events = journal_events(&mut job.journal);
    assert_eq!(events.len(), usize::try_from(sent).unwrap());
    assert!(
        events
            .iter()
            .zip(1u64..)
            .all(|(role, seq)| *role == Role::Event(seq))
    );
}

/// The in-flight bound: as many events as the tracker holds, not yet
/// durable, keep the next one out until a sync makes them durable.
#[test]
fn events_in_flight_are_bounded_until_durable() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 2));
    for seq in 1..=2 {
        sender.admit().unwrap();
        sender.send(&event(seq, 10, None), seq).unwrap();
    }
    assert_eq!(sender.admit(), Err(Refusal::InFlight));
    job.duty(0, 16, &none).unwrap();
    assert_eq!(
        sender.admit(),
        Err(Refusal::InFlight),
        "written, not durable"
    );
    job.sync(&none).unwrap();
    sender.admit().unwrap();
}

/// R-CORE-12 in process: the sender's crate-root answers follow the
/// prefixes, written but not durable until a sync.
#[test]
fn test_capture_group_durable_follows_the_durable_prefix() {
    use crate::durable::Durability;
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 2));
    sender.admit().unwrap();
    sender.send(&event(1, 10, None), 1).unwrap();
    job.duty(0, 16, &none).unwrap();
    assert_eq!(sender.group_durable().durable_group_seq, 0, "written only");
    assert_eq!(sender.durability(1), Durability::Pending(0));
    job.sync(&none).unwrap();
    assert_eq!(sender.group_durable().durable_group_seq, 1);
    assert_eq!(sender.durability(1), Durability::Reached(1));
    assert_eq!(
        sender.group_durable().durable_group_seq,
        sender.view().durable_group_seq()
    );
}

/// A best-effort group marks an event it could not take with a gap,
/// which needs only ring room; the gap stops the prefixes, so no event is
/// in flight any more and the bound is lifted.
#[test]
fn a_gap_needs_only_room_and_lifts_the_in_flight_bound() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 1));
    sender.send(&event(1, 10, None), 1).unwrap();
    job.duty(0, 16, &none).unwrap();
    assert_eq!(sender.admit(), Err(Refusal::InFlight));
    sender.room().unwrap();
    sender.send(&gap(2, 2), 2).unwrap();
    job.duty(0, 16, &none).unwrap();
    assert!(job.tracker().stopped());
    sender.admit().unwrap();
    sender.send(&event(3, 10, None), 3).unwrap();
    job.duty(0, 16, &none).unwrap();
    assert_eq!(
        journal_events(&mut job.journal),
        [
            Role::Event(1),
            Role::Gap(GapMarker {
                from_seq: 2,
                to_seq: 2,
                reason: GapReason::RingFull
            }),
            Role::Event(3)
        ]
    );
}

/// A best-effort group: a recording that ended covering its reference
/// counts it covered; one that ended short of it has it marked
/// unavailable in the journal. Either way the prefixes go on, with the
/// recordings no longer answering.
#[test]
fn a_recording_that_ends_settles_its_references() {
    let recordings = Recordings::default();
    let gone = Recordings::default();
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 8));
    sender.send(&event(1, 10, Some(7)), 1).unwrap();
    sender.send(&event(2, 10, Some(8)), 2).unwrap();
    sender.send(&event(3, 10, None), 3).unwrap();
    job.duty(0, 16, &recordings).unwrap();
    job.sync(&recordings).unwrap();
    assert_eq!(sender.view().snapshot(), (3, 0, 0), "both payloads missing");
    // Recording 7 ended with event 1's frames durable; 8 short of 2's.
    job.recording_ended(7, 64, &gone).unwrap();
    assert_eq!(sender.view().snapshot(), (3, 1, 1));
    job.recording_ended(8, 32, &gone).unwrap();
    job.sync(&gone).unwrap();
    assert_eq!(sender.view().snapshot(), (3, 3, 3));
    assert_eq!(
        journal_events(&mut job.journal),
        [
            Role::Event(1),
            Role::Event(2),
            Role::Event(3),
            Role::Unavailable(2)
        ]
    );
    assert_eq!(job.state(), GroupState::Running);
}

/// A strict group ends at a reference its recording will never cover: the
/// sender refuses, the waiter returns, the job reads no more, and the
/// prefixes stay before the event.
#[test]
fn a_strict_group_ends_at_a_reference_never_covered() {
    let gone = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    let waiter = sender.waiter();
    sender.send(&event(1, 10, None), 1).unwrap();
    sender.send(&event(2, 10, Some(8)), 2).unwrap();
    job.duty(0, 16, &gone).unwrap();
    job.sync(&gone).unwrap();
    job.recording_ended(8, 32, &gone).unwrap();
    assert_eq!(job.state(), GroupState::Ended);
    assert_eq!(sender.admit(), Err(Refusal::Ended));
    assert_eq!(
        waiter.wait_durable(2, Duration::from_secs(5)),
        Err(WaitError::Stopped {
            durable: 1,
            state: GroupState::Ended
        })
    );
    sender.send(&event(3, 10, None), 3).unwrap();
    assert!(!job.duty(0, 16, &gone).unwrap());
    assert_eq!(sender.view().snapshot(), (2, 1, 1));
    assert_eq!(
        journal_events(&mut job.journal),
        [Role::Event(1), Role::Event(2)]
    );
}

/// A journal that fails a write fails the group: the job stops, the
/// sender refuses, the waiter returns.
#[test]
fn a_failed_journal_fails_the_group() {
    let none = Recordings::default();
    let free = FaultDisk::default();
    let journal_alone = journal(free.clone(), Capture::Strict, UNSYNCED);
    let created = free.used();
    drop(journal_alone);
    let disk = FaultDisk::with_budget(created + 10);
    let (mut sender, mut job) = capture(
        settings(4096, 400, 8),
        journal(disk, Capture::Strict, UNSYNCED),
        &none,
    )
    .unwrap();
    let waiter = sender.waiter();
    sender.send(&event(1, 100, None), 1).unwrap();
    assert!(job.duty(0, 16, &none).is_err());
    assert_eq!(job.state(), GroupState::Failed);
    assert_eq!(sender.admit(), Err(Refusal::Failed));
    assert_eq!(
        waiter.wait_durable(1, Duration::from_secs(5)),
        Err(WaitError::Stopped {
            durable: 0,
            state: GroupState::Failed
        })
    );
    assert!(
        !job.duty(0, 16, &none).unwrap(),
        "a failed job reads nothing"
    );
}

/// What the waiter saw durable survives a crash at every write boundary:
/// the recovered journal's durable prefix is never behind it.
#[test]
fn durability_survives_a_crash_at_every_write_boundary() {
    let none = Recordings::default();
    // The work of a whole run, to bound the budgets.
    let whole = FaultDisk::default();
    run(&whole, &none);
    let total = whole.used();
    let mut crashed = 0;
    for budget in 0..=total {
        let disk = FaultDisk::with_budget(budget);
        let seen = run(&disk, &none);
        if !disk.has_crashed() {
            continue;
        }
        crashed += 1;
        let restarted = disk.after_crash(Survives::Synced);
        let Ok(recovered) = GroupJournal::recover(
            restarted,
            Path::new("/g"),
            1,
            config(SyncPolicy::PerSegment),
        ) else {
            assert_eq!(seen, 0, "budget {budget}: nothing was durable");
            continue;
        };
        let mut journal = recovered.journal;
        let recovery = prefix::recover(&mut journal, &none, 64).unwrap();
        assert!(
            recovery.tracker.durable_group_seq() >= seen,
            "budget {budget}: durable {seen} was lost"
        );
    }
    assert!(crashed > 100, "{crashed}");
}

/// Sends 12 events of 200 bytes, draining and syncing after each; returns
/// the highest `durable_group_seq` seen before the disk crashed.
fn run(disk: &FaultDisk, coverage: &Recordings) -> u64 {
    let Ok(journal) = GroupJournal::create(
        disk.clone(),
        Path::new("/g"),
        &header(Capture::Strict),
        config(SyncPolicy::PerSegment),
    ) else {
        return 0;
    };
    let Ok((mut sender, mut job)) = capture(settings(65_536, 4096, 64), journal, coverage) else {
        return 0;
    };
    let mut seen = 0;
    for seq in 1..=12 {
        if sender.admit().is_err() || sender.send(&event(seq, 200, None), seq).is_err() {
            break;
        }
        if job.duty(0, 16, coverage).is_err() || job.sync(coverage).is_err() {
            break;
        }
        seen = sender.view().durable_group_seq();
    }
    seen
}

/// Plan item 3 (contract-traceability-phase-3.md): events whose payloads
/// are references into recording 7, which writes each payload before its
/// event is sent and makes it durable two events later, crashed together
/// at every journal write boundary. The recording keeps what was durable,
/// the journal what recovery finds. The recovered durable prefix keeps
/// every event the waiter saw durable, and never counts an event whose
/// referenced frames the recording lost.
#[test]
fn a_referenced_payload_survives_a_crash_of_the_journal_and_its_recording() {
    let whole = FaultDisk::default();
    let _ = run_referenced(&whole, &Recordings::default());
    let total = whole.used();
    let mut crashed = 0;
    for budget in 0..=total {
        let disk = FaultDisk::with_budget(budget);
        let recording = Recordings::default();
        let seen = run_referenced(&disk, &recording);
        if !disk.has_crashed() {
            continue;
        }
        crashed += 1;
        // The recording crashed too: it keeps only what was durable.
        let durable = recording
            .0
            .borrow()
            .get(&7)
            .map_or(0, |(_, durable)| *durable);
        let kept = Recordings::default();
        let _ = kept.0.borrow_mut().insert(7, (durable, durable));
        let restarted = disk.after_crash(Survives::Synced);
        let Ok(recovered) = GroupJournal::recover(
            restarted,
            Path::new("/g"),
            1,
            config(SyncPolicy::PerSegment),
        ) else {
            assert_eq!(seen, 0, "budget {budget}: nothing was durable");
            continue;
        };
        let mut journal = recovered.journal;
        let recovery = prefix::recover(&mut journal, &kept, 64).unwrap();
        let recovered = recovery.tracker.durable_group_seq();
        assert!(
            recovered >= seen,
            "budget {budget}: durable {seen} was lost (recovered {recovered})"
        );
        // Event n's frames end at n * EXTENT: none past the recording's
        // durable end is counted.
        assert!(
            recovered * EXTENT <= durable,
            "budget {budget}: event {recovered} counted past the recording's {durable}"
        );
        assert!(recovery.tracker.complete_recording_seq() * EXTENT <= durable);
    }
    assert!(crashed > 100, "{crashed}");
}

/// Plan item 3's damage case: after a whole run, the recording comes back
/// shorter than what the journal had counted (its tail lost to media
/// damage, so its durable end is cut at event 3's frames). Recovery counts
/// no event past what the recording still holds: the prefixes stop at
/// event 3, and none of the events whose frames were lost is complete or
/// durable.
#[test]
fn a_damaged_referenced_range_is_not_counted_at_recovery() {
    let disk = FaultDisk::default();
    let recording = Recordings::default();
    let seen = run_referenced(&disk, &recording);
    assert_eq!(seen, 10, "two events wait for their frames");
    let damaged = Recordings::default();
    let _ = damaged.0.borrow_mut().insert(7, (3 * EXTENT, 3 * EXTENT));
    let mut journal =
        GroupJournal::recover(disk, Path::new("/g"), 1, config(SyncPolicy::PerSegment))
            .unwrap()
            .journal;
    let recovery = prefix::recover(&mut journal, &damaged, 64).unwrap();
    assert_eq!(recovery.tracker.durable_group_seq(), 3);
    assert_eq!(recovery.tracker.complete_recording_seq(), 3);
}

/// [`run`] with each event's payload a reference into recording 7, at its
/// position: the recording writes event `n`'s frames before it is sent
/// and makes them durable when event `n + 2` is sent, `coverage` its
/// state. A frame written and not yet durable is what a crash loses.
fn run_referenced(disk: &FaultDisk, coverage: &Recordings) -> u64 {
    let Ok(journal) = GroupJournal::create(
        disk.clone(),
        Path::new("/g"),
        &header(Capture::Strict),
        config(SyncPolicy::PerSegment),
    ) else {
        return 0;
    };
    let Ok((mut sender, mut job)) = capture(settings(65_536, 4096, 64), journal, coverage) else {
        return 0;
    };
    let mut seen = 0;
    for seq in 1..=12 {
        let start = (seq - 1) * EXTENT;
        let durable = if seq >= 2 { (seq - 2) * EXTENT } else { 0 };
        let _ = coverage.0.borrow_mut().insert(7, (seq * EXTENT, durable));
        let event = event_at(seq, 200, Some(7), start, EndOutcome::Complete);
        if sender.admit().is_err() || sender.send(&event, seq).is_err() {
            break;
        }
        if job.duty(0, 16, coverage).is_err() || job.sync(coverage).is_err() {
            break;
        }
        seen = sender.view().durable_group_seq();
    }
    seen
}

#[test]
fn a_waiter_times_out() {
    let (sender, _job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    assert_eq!(
        sender.waiter().wait_durable(1, Duration::from_millis(10)),
        Err(WaitError::Timeout { durable: 0 })
    );
}

#[test]
fn settings_that_cannot_work_are_refused() {
    let none = Recordings::default();
    let make = |settings| {
        capture(
            settings,
            journal(FaultDisk::default(), Capture::Strict, UNSYNCED),
            &none,
        )
        .map(|_| ())
    };
    for settings in [
        settings(3000, 100, 8),
        settings(512, 10, 8),
        settings(1024, 121, 8),
    ] {
        assert!(matches!(
            make(settings),
            Err(CaptureSetup::Config(CaptureError::Ring { .. }))
        ));
    }
    assert!(make(settings(1024, 120, 8)).is_ok());
    assert!(matches!(
        make(settings(1024, 120, 0)),
        Err(CaptureSetup::Config(CaptureError::InFlight))
    ));
    let (mut sender, _job) = new(Capture::Strict, UNSYNCED, settings(1024, 100, 8));
    assert_eq!(sender.send(&event(1, 100, None), 1), Err(Refusal::TooLarge));
}

/// A waiter on another thread wakes when the job makes its event durable,
/// long before its deadline: the job notifies it.
#[test]
fn a_waiter_on_another_thread_wakes_at_durability() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    let waiter = sender.waiter();
    let waiting = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        (
            waiter.wait_durable(1, Duration::from_secs(30)),
            start.elapsed(),
        )
    });
    sender.send(&event(1, 10, None), 1).unwrap();
    job.duty(0, 16, &none).unwrap();
    // Let the waiter park before the sync.
    std::thread::sleep(Duration::from_millis(50));
    job.sync(&none).unwrap();
    let (woke, after) = waiting.join().unwrap();
    assert_eq!(woke, Ok(1));
    assert!(after < Duration::from_secs(10), "{after:?}");
}

/// Both ends count a message as the ring lays it out: an 8-byte header and
/// the payload, rounded up to 8 bytes; a message's end is where the ring
/// puts the next one when no padding comes between.
#[test]
fn the_framing_is_the_rings() {
    for (payload, framed) in [(0, 8), (1, 16), (7, 16), (8, 16), (9, 24), (120, 128)] {
        assert_eq!(extent(payload), Some(framed), "{payload}");
    }
    let (mut producer, mut consumer) = command_ring(4096).unwrap();
    let mut previous: Option<(u64, usize)> = None;
    for payload in 0..=100 {
        let start = producer.write(RECORDS, &vec![1u8; payload]).unwrap();
        if let Some((at, length)) = previous {
            assert_eq!(start, at + extent(length).unwrap(), "after {length} bytes");
        }
        previous = Some((start, payload));
        let read = consumer.read().unwrap().unwrap();
        assert_eq!(read.position, start);
        if start + extent(payload).unwrap() > 4096 - 256 {
            break;
        }
    }
}

/// A message whose payload was not captured (payload 3) is an event like
/// the others: delivered, complete and durable in a best-effort group.
#[test]
fn an_uncaptured_message_is_delivered() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 8));
    let message = GroupRecord::Message(MessageEvent {
        group_seq: 1,
        logical_time: 1,
        incarnation: 1,
        position: 0,
        extent: 70_048,
        stream_id: 1,
        session_id: 1,
        lane: Lane::ZERO,
        reserved_value: 0,
        end_of_stream: false,
        extension: None,
        payload: Payload::Unavailable { length: 70_000 },
        image: 0,
    });
    let end = GroupRecord::End(EventEnd {
        group_seq: 1,
        observations: 0,
        outcome: EndOutcome::Complete,
    });
    let mut out = vec![0u8; MAX_RECORD];
    let mut bytes = Vec::new();
    for record in [message, end] {
        let length = record.encode(&mut out).unwrap();
        bytes.extend_from_slice(&out[..length]);
    }
    sender.send(&bytes, 1).unwrap();
    job.duty(0, 16, &none).unwrap();
    job.sync(&none).unwrap();
    assert_eq!(sender.view().snapshot(), (1, 1, 1));
}

/// Recordings that ended: each with its durable end.
#[derive(Default)]
struct Ended(BTreeMap<u64, u64>);

impl Coverage for Ended {
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        self.0.get(&recording_id).map(|&end| (end, end))
    }

    fn ended(&self, recording_id: u64) -> Option<u64> {
        self.0.get(&recording_id).copied()
    }
}

/// A7d-1c: a reference that reaches the journal after its recording
/// ended, sent before the stop and drained after it, is settled by the
/// job: covered when the end reaches it; otherwise marked (best effort),
/// or the strict group ends.
#[test]
fn a_reference_after_its_recording_ended_is_settled() {
    let ended = Ended([(7, 64), (8, 32)].into_iter().collect());
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 8));
    sender.send(&event(1, 10, Some(7)), 1).unwrap();
    sender.send(&event(2, 10, Some(8)), 2).unwrap();
    job.duty(0, 16, &ended).unwrap();
    job.sync(&ended).unwrap();
    assert_eq!(sender.view().snapshot(), (2, 2, 2));
    assert_eq!(
        journal_events(&mut job.journal),
        [Role::Event(1), Role::Event(2), Role::Unavailable(2)]
    );
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    sender.send(&event(1, 10, Some(8)), 1).unwrap();
    job.duty(0, 16, &ended).unwrap();
    assert_eq!(job.state(), GroupState::Ended);
}

/// #408 review P1, the exact race: the event loop read the recording's id,
/// the recording ended and was settled, then the event reached the job.
/// It is settled when the job reads it: marked (best effort), or the
/// strict group ends.
#[test]
fn a_reference_sent_before_its_recording_ended_and_read_after_is_settled() {
    let ended = Ended([(8, 32)].into_iter().collect());
    for capture_mode in [Capture::BestEffort, Capture::Strict] {
        let (mut sender, mut job) = new(capture_mode, UNSYNCED, settings(4096, 400, 8));
        sender.send(&event(1, 10, None), 1).unwrap();
        job.duty(0, 16, &ended).unwrap();
        // Recording 8 ends; nothing waiting refers to it yet.
        job.recording_ended(8, 32, &ended).unwrap();
        assert_eq!(job.state(), GroupState::Running);
        sender.send(&event(2, 10, Some(8)), 2).unwrap();
        job.duty(0, 16, &ended).unwrap();
        job.sync(&ended).unwrap();
        match capture_mode {
            Capture::BestEffort => {
                assert_eq!(sender.view().snapshot(), (2, 2, 2));
                assert_eq!(
                    journal_events(&mut job.journal),
                    [Role::Event(1), Role::Event(2), Role::Unavailable(2)]
                );
            }
            Capture::Strict => assert_eq!(job.state(), GroupState::Ended),
        }
    }
}

/// #408 review P3, mutants b2 and b3: the credit is exact at the
/// boundary. A ring of 1024 bytes and events of exactly 128 framed bytes:
/// full after eight; one drained frees exactly one event's room, which is
/// admitted (not a byte too few); a smaller event then leaves the room
/// eight bytes short of the padding and the largest event, refused (not a
/// byte too many).
#[test]
fn the_credit_is_exact_at_the_boundary() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(1024, 120, 1024));
    // 116 bytes of records and 4 of payload: 120, framed 128.
    let records = |seq| event(seq, 4, None);
    assert_eq!(records(1).len(), 120);
    for seq in 1..=8 {
        sender.admit().unwrap();
        sender.send(&records(seq), seq).unwrap();
    }
    assert_eq!(sender.admit(), Err(Refusal::RingFull));
    assert!(job.duty(0, 1, &none).unwrap());
    // Exactly 128 free at the ring's start: admitted.
    sender.admit().unwrap();
    sender.send(&records(9), 9).unwrap();
    assert_eq!(sender.admit(), Err(Refusal::RingFull));
    // Drain one more (128 free), then send a smaller event of 120 framed
    // bytes (no payload, 116 raw): 8 free, 128 needed.
    assert!(job.duty(0, 1, &none).unwrap());
    let smaller = event(10, 0, None);
    assert_eq!(smaller.len(), 116);
    sender.admit().unwrap();
    sender.send(&smaller, 10).unwrap();
    assert_eq!(sender.admit(), Err(Refusal::RingFull), "8 bytes short");
    // Two more drained: 264 free, to the end 128 at most: admitted again.
    assert!(job.duty(0, 2, &none).unwrap());
    sender.admit().unwrap();
}

/// #408 review P3, mutant e2: a waiter woken before its `group_seq` is
/// durable waits on.
#[test]
fn a_waiter_woken_early_waits_on() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    let waiter = sender.waiter();
    let waiting = std::thread::spawn(move || waiter.wait_durable(2, Duration::from_secs(30)));
    sender.send(&event(1, 10, None), 1).unwrap();
    job.duty(0, 16, &none).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    // Event 1 durable: the waiter wakes, and waits on for 2.
    job.sync(&none).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(!waiting.is_finished(), "woke at 1 and returned");
    sender.send(&event(2, 10, None), 2).unwrap();
    job.duty(0, 16, &none).unwrap();
    job.sync(&none).unwrap();
    assert_eq!(waiting.join().unwrap(), Ok(2));
}

/// #408 review P2: a journal that never syncs on its own is refused, and
/// one that syncs only at segment ends is synced by the job at the
/// in-flight bound, so the group goes on.
#[test]
fn a_group_journal_syncs_at_its_in_flight_bound() {
    let none = Recordings::default();
    assert!(matches!(
        capture(
            settings(4096, 400, 2),
            journal(FaultDisk::default(), Capture::Strict, SyncPolicy::None),
            &none,
        ),
        Err(CaptureSetup::Config(CaptureError::NoSync))
    ));
    let (mut sender, mut job) = new(
        Capture::Strict,
        SyncPolicy::PerSegment,
        settings(4096, 400, 2),
    );
    for seq in 1..=6 {
        sender.admit().unwrap();
        sender.send(&event(seq, 10, None), seq).unwrap();
        job.duty(0, 16, &none).unwrap();
    }
    assert!(sender.view().durable_group_seq() >= 5);
}

/// #408 review P3: a strict group that ends at an uncovered reference
/// first counts what is covered before it.
#[test]
fn a_strict_end_counts_what_is_covered_first() {
    let gone = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    let waiter = sender.waiter();
    sender
        .send(&event_at(1, 10, Some(7), 0, EndOutcome::Complete), 1)
        .unwrap();
    sender
        .send(&event_at(2, 10, Some(7), 64, EndOutcome::Complete), 2)
        .unwrap();
    job.duty(0, 16, &gone).unwrap();
    job.sync(&gone).unwrap();
    // Recording 7 ended at 64: event 1 is covered, event 2 is not.
    job.recording_ended(7, 64, &gone).unwrap();
    assert_eq!(job.state(), GroupState::Ended);
    assert_eq!(waiter.wait_durable(1, Duration::ZERO), Ok(1));
}

/// #408 review P3: a strict journal ends at an incomplete event, so the
/// group takes nothing more.
#[test]
fn a_strict_incomplete_end_ends_the_group() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    sender
        .send(&event_at(1, 10, None, 0, EndOutcome::Incomplete), 1)
        .unwrap();
    job.duty(0, 16, &none).unwrap();
    assert_eq!(job.state(), GroupState::Ended);
    assert_eq!(sender.admit(), Err(Refusal::Ended));
}

/// #408 review P3: a gap's events were delivered, not captured.
#[test]
fn a_gap_counts_its_events_delivered() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 8));
    sender.send(&gap(1, 3), 3).unwrap();
    job.duty(0, 16, &none).unwrap();
    assert_eq!(sender.view().delivered_seq(), 3);
}

/// #408 review P3: a recovered journal with more events waiting on their
/// payloads than the tracker holds is refused, typed.
#[test]
fn a_recovery_with_no_room_is_refused() {
    let none = Recordings::default();
    let disk = FaultDisk::default();
    let mut journal = journal(disk.clone(), Capture::Strict, SyncPolicy::PerSegment);
    for seq in 1..=2 {
        journal.append(&event(seq, 10, Some(7))).unwrap();
    }
    journal.close().unwrap();
    let recovered = |capacity| {
        let journal = GroupJournal::recover(
            disk.after_crash(Survives::Synced),
            Path::new("/g"),
            1,
            config(SyncPolicy::PerSegment),
        )
        .unwrap()
        .journal;
        capture(settings(4096, 400, capacity), journal, &none).map(|_| ())
    };
    assert!(matches!(
        recovered(1),
        Err(CaptureSetup::Config(CaptureError::RecoveryFull {
            capacity: 1
        }))
    ));
    assert!(recovered(2).is_ok());
}

/// #408 review P2: an event budget whose framing overflows is refused.
#[test]
fn an_event_budget_that_overflows_is_refused() {
    let none = Recordings::default();
    assert!(matches!(
        capture(
            settings(1024, usize::MAX, 8),
            journal(FaultDisk::default(), Capture::Strict, UNSYNCED),
            &none,
        ),
        Err(CaptureSetup::Config(CaptureError::Ring { .. }))
    ));
}

/// #408 re-check P2: once the prefixes stopped, nothing is in flight, so
/// the job does not sync the journal at every duty.
#[test]
fn no_sync_at_the_bound_after_a_stop() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(
        Capture::BestEffort,
        SyncPolicy::PerSegment,
        settings(4096, 400, 1),
    );
    sender.send(&gap(1, 1), 1).unwrap();
    job.duty(0, 16, &none).unwrap();
    let durable = job.journal().durable();
    for seq in 2..=6 {
        sender.send(&event(seq, 10, None), seq).unwrap();
        job.duty(0, 16, &none).unwrap();
    }
    assert_eq!(job.journal().durable(), durable);
}

/// Positions only while it records, then its end: an ended recording.
struct GoneQuiet;

impl Coverage for GoneQuiet {
    fn positions(&self, _recording_id: u64) -> Option<(u64, u64)> {
        None
    }

    fn ended(&self, _recording_id: u64) -> Option<u64> {
        Some(64)
    }
}

/// #408 re-check P3: an ended recording whose positions answer nothing
/// still settles a reference its end covers.
#[test]
fn a_covered_reference_settles_with_no_positions() {
    let (mut sender, mut job) = new(Capture::Strict, UNSYNCED, settings(4096, 400, 8));
    sender.send(&event(1, 10, Some(7)), 1).unwrap();
    job.duty(0, 16, &GoneQuiet).unwrap();
    job.sync(&GoneQuiet).unwrap();
    assert_eq!(sender.view().snapshot(), (1, 1, 1));
}

/// #408 re-check P3: a recovered strict journal that ended at an
/// incomplete event takes nothing more.
#[test]
fn a_recovered_strict_end_stays_ended() {
    let none = Recordings::default();
    let disk = FaultDisk::default();
    let mut journal = journal(disk.clone(), Capture::Strict, SyncPolicy::PerSegment);
    journal
        .append(&event_at(1, 10, None, 0, EndOutcome::Incomplete))
        .unwrap();
    journal.close().unwrap();
    let journal = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new("/g"),
        1,
        config(SyncPolicy::PerSegment),
    )
    .unwrap()
    .journal;
    let (sender, _job) = capture(settings(4096, 400, 8), journal, &none).unwrap();
    assert_eq!(sender.admit(), Err(Refusal::Ended));
}

/// #411 review P2: a close drains what the ring holds and refuses the
/// sender first, so a live sender cannot keep the drain going.
#[test]
fn a_close_drains_the_ring_and_refuses_the_sender() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 8));
    for seq in 1..=3 {
        sender.admit().unwrap();
        sender.send(&event(seq, 10, None), seq).unwrap();
    }
    job.drain_to_close(0, &none).unwrap();
    assert_eq!(sender.view().delivered_seq(), 3);
    assert_eq!(sender.admit(), Err(Refusal::Closing));
    assert_eq!(sender.room(), Err(Refusal::Closing));
    assert_eq!(sender.send(&event(4, 10, None), 4), Err(Refusal::Closing));
    assert_eq!(sender.state(), GroupState::Running);
    job.close().unwrap();
    assert_eq!(sender.admit(), Err(Refusal::Ended));
}

/// Holds every checkpoint's bytes, durable; no recording.
struct CheckpointsHeld;

impl Coverage for CheckpointsHeld {
    fn positions(&self, _recording_id: u64) -> Option<(u64, u64)> {
        None
    }

    fn ended(&self, _recording_id: u64) -> Option<u64> {
        None
    }

    fn checkpoint(&self, _position: u64, _end: u64) -> crate::group::prefix::CheckpointHeld {
        crate::group::prefix::CheckpointHeld::Durable
    }
}

/// #414 re-check P3 (mutant N): a waiter on an event a new range let go
/// hears of it when the range opens, though no durable value rose: event
/// 1 is written, not durable; a gap at 2; a checkpoint at 2 opens a range.
/// The waiter on event 2, a gap's, returns Stopped at once, not at its
/// deadline.
#[test]
fn a_waiter_on_a_let_go_event_is_woken_when_a_range_opens() {
    use crate::group::record::CheckpointRecord;

    let held = CheckpointsHeld;
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 8));
    let waiter = sender.waiter();
    sender.send(&event(1, 10, None), 1).unwrap();
    sender.room().unwrap();
    sender.send(&gap(2, 2), 2).unwrap();
    job.duty(0, 16, &held).unwrap();
    let waiting = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        (
            waiter.wait_durable(2, Duration::from_secs(20)),
            start.elapsed(),
        )
    });
    // Let the waiter park first.
    std::thread::sleep(Duration::from_millis(50));
    let mut record = vec![0u8; 64];
    let length = GroupRecord::Checkpoint(CheckpointRecord {
        group_seq: 2,
        checkpoint_id: 1,
        position: 0,
        length: 10,
        crc32c: 0,
        format: 7,
    })
    .encode(&mut record)
    .unwrap();
    sender.room().unwrap();
    sender.send(&record[..length], 2).unwrap();
    job.duty(0, 16, &held).unwrap();
    assert_eq!(job.tracker().range().start.unwrap().group_seq, 2);
    let (woke, after) = waiting.join().unwrap();
    assert!(
        matches!(woke, Err(WaitError::Stopped { durable: 0, .. })),
        "{woke:?}"
    );
    assert!(
        after < Duration::from_secs(10),
        "woken at the deadline: {after:?}"
    );
}

/// A checkpoint record sent through the ring.
fn checkpoint_message(group_seq: u64, id: u64) -> Vec<u8> {
    use crate::group::record::CheckpointRecord;

    let mut record = vec![0u8; 64];
    let length = GroupRecord::Checkpoint(CheckpointRecord {
        group_seq,
        checkpoint_id: id,
        position: 0,
        length: 10,
        crc32c: 0,
        format: 7,
    })
    .encode(&mut record)
    .unwrap();
    record.truncate(length);
    record
}

/// #414 wiring item, the coordinator's scenario (A9-3): in_flight 2, a
/// gap, events 3 and 4, a checkpoint at 2 that opens a range holding them
/// (the queue full), then event 5, sent while the stop still let it in.
/// The tracker is full at 5's end: the job syncs, advances and takes it
/// again, once, and the group goes on. Once the range opened, the stop is
/// lifted, so the in-flight bound applies again.
#[test]
fn a_full_queue_after_a_range_opens_syncs_and_takes_the_event_again() {
    let held = CheckpointsHeld;
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 2));
    sender.send(&event(1, 10, None), 1).unwrap();
    sender.send(&gap(2, 2), 2).unwrap();
    job.duty(0, 16, &held).unwrap();
    assert!(job.tracker().stopped());
    sender.send(&event(3, 10, None), 3).unwrap();
    sender.send(&event(4, 10, None), 4).unwrap();
    sender.send(&checkpoint_message(2, 1), 4).unwrap();
    job.duty(0, 16, &held).unwrap();
    assert_eq!(job.tracker().range().start.unwrap().group_seq, 2);
    assert!(!job.tracker().stopped());
    // The stop is lifted: the in-flight bound applies again.
    assert_eq!(sender.admit(), Err(Refusal::InFlight));
    // Admitted under the stop, before the sender saw it lifted.
    sender.send(&event(5, 10, None), 5).unwrap();
    job.duty(0, 16, &held).unwrap();
    assert_eq!(sender.state(), GroupState::Running);
    job.sync(&held).unwrap();
    assert_eq!(job.tracker().range().durable, 5);
    assert_eq!(sender.view().durable_group_seq(), 5);
}

/// A9-3: the job writes a checkpoint only once its journal holds the
/// event it names (the request may come before the ring is drained), at
/// most the budget's bytes a call, and feeds the record to the prefixes.
#[test]
fn the_job_writes_a_checkpoint_once_its_event_is_journaled() {
    use crate::group::checkpoint::{CheckpointSlot, CheckpointStore, CheckpointWriter};

    let held = CheckpointsHeld;
    let disk = FaultDisk::default();
    let (mut sender, mut job) = capture(
        settings(4096, 400, 8),
        journal(disk.clone(), Capture::BestEffort, UNSYNCED),
        &held,
    )
    .unwrap();
    let store =
        CheckpointStore::create(disk, Path::new("/checkpoints"), 1, config(UNSYNCED)).unwrap();
    let mut writer = CheckpointWriter::new(store, job.journal()).unwrap();
    let mut slot = CheckpointSlot::new(64);
    let request = slot
        .take(2, 7, |buffer| {
            buffer[..10].copy_from_slice(b"0123456789");
            10
        })
        .unwrap();
    sender.send(&event(1, 10, None), 1).unwrap();
    sender.send(&gap(2, 2), 2).unwrap();
    // The ring is not drained: the journal does not hold event 2.
    assert_eq!(
        job.checkpoint(&mut writer, &request, 4).unwrap(),
        CheckpointStep::NotReady
    );
    job.duty(0, 16, &held).unwrap();
    assert_eq!(
        job.checkpoint(&mut writer, &request, 4).unwrap(),
        CheckpointStep::Writing { written: 4 }
    );
    assert_eq!(
        job.checkpoint(&mut writer, &request, 4).unwrap(),
        CheckpointStep::Writing { written: 8 }
    );
    assert!(matches!(
        job.checkpoint(&mut writer, &request, 4).unwrap(),
        CheckpointStep::Recorded(_)
    ));
    job.refresh(&held);
    assert_eq!(job.tracker().range().start.unwrap().group_seq, 2);
}

/// #426 review (mutant e2): the retry after a full queue is once. With
/// the queue still full after the sync (its events wait on a recording
/// that never covers them), the group fails, typed, as before.
#[test]
fn a_queue_still_full_after_the_retry_fails_the_group() {
    let held = CheckpointsHeld;
    let (mut sender, mut job) = new(Capture::BestEffort, UNSYNCED, settings(4096, 400, 2));
    sender.send(&event(1, 10, None), 1).unwrap();
    sender.send(&gap(2, 2), 2).unwrap();
    job.duty(0, 16, &held).unwrap();
    sender.send(&event(3, 10, Some(7)), 3).unwrap();
    sender.send(&event(4, 10, Some(7)), 4).unwrap();
    sender.send(&checkpoint_message(2, 1), 4).unwrap();
    job.duty(0, 16, &held).unwrap();
    assert_eq!(job.tracker().range().start.unwrap().group_seq, 2);
    sender.send(&event(5, 10, None), 5).unwrap();
    assert!(matches!(
        job.duty(0, 16, &held),
        Err(JobError::Prefix(PrefixError::Full { .. }))
    ));
    assert_eq!(sender.state(), GroupState::Failed);
}

/// #437 review M8: the list of events a recording leaves uncovered is
/// reserved when the group starts, three times `in_flight`, so the job
/// never grows it.
#[test]
fn the_uncovered_list_is_reserved_at_start() {
    // A hold above `in_flight`: the list is three times the hold.
    let journal = GroupJournal::create(
        FaultDisk::default(),
        Path::new("/g"),
        &JournalHeader {
            reopen_hold: 9,
            ..header(Capture::BestEffort)
        },
        config(SyncPolicy::PerSegment),
    )
    .unwrap();
    let (_sender, job) =
        capture(settings(1 << 16, 4096, 5), journal, &Recordings::default()).unwrap();
    assert!(
        job.uncovered.capacity() >= 27,
        "{}",
        job.uncovered.capacity()
    );
}
