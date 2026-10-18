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
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        self.0.borrow().get(&recording_id).copied()
    }
}

const NONE: SyncPolicy = SyncPolicy::None;

fn header(capture: Capture) -> JournalHeader<'static> {
    JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture,
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
    let value = vec![0x5A; length];
    let message = GroupRecord::Message(MessageEvent {
        group_seq: seq,
        logical_time: seq,
        incarnation: 1,
        position: 0,
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
    });
    let end = GroupRecord::End(EventEnd {
        group_seq: seq,
        observations: 0,
        outcome: EndOutcome::Complete,
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
    let (mut sender, mut job) = new(Capture::Strict, NONE, settings(4096, 400, 8));
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
    // 108 bytes of records and up to 140 of payload.
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
                let records = event(seq, length % 141, None);
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
    let (mut sender, mut job) = new(Capture::Strict, NONE, settings(4096, 400, 2));
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

/// A best-effort group marks an event it could not take with a gap,
/// which needs only ring room; the gap stops the prefixes, so no event is
/// in flight any more and the bound is lifted.
#[test]
fn a_gap_needs_only_room_and_lifts_the_in_flight_bound() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::BestEffort, NONE, settings(4096, 400, 1));
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
    let (mut sender, mut job) = new(Capture::BestEffort, NONE, settings(4096, 400, 8));
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
    let (mut sender, mut job) = new(Capture::Strict, NONE, settings(4096, 400, 8));
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
    let journal_alone = journal(free.clone(), Capture::Strict, NONE);
    let created = free.used();
    drop(journal_alone);
    let disk = FaultDisk::with_budget(created + 10);
    let (mut sender, mut job) = capture(
        settings(4096, 400, 8),
        journal(disk, Capture::Strict, NONE),
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

#[test]
fn a_waiter_times_out() {
    let (sender, _job) = new(Capture::Strict, NONE, settings(4096, 400, 8));
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
            journal(FaultDisk::default(), Capture::Strict, NONE),
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
    let (mut sender, _job) = new(Capture::Strict, NONE, settings(1024, 100, 8));
    assert_eq!(sender.send(&event(1, 100, None), 1), Err(Refusal::TooLarge));
}

/// A waiter on another thread wakes when the job makes its event durable,
/// long before its deadline: the job notifies it.
#[test]
fn a_waiter_on_another_thread_wakes_at_durability() {
    let none = Recordings::default();
    let (mut sender, mut job) = new(Capture::Strict, NONE, settings(4096, 400, 8));
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
        assert_eq!(extent(payload), framed, "{payload}");
    }
    let (mut producer, mut consumer) = command_ring(4096).unwrap();
    let mut previous: Option<(u64, usize)> = None;
    for payload in 0..=100 {
        let start = producer.write(RECORDS, &vec![1u8; payload]).unwrap();
        if let Some((at, length)) = previous {
            assert_eq!(start, at + extent(length), "after {length} bytes");
        }
        previous = Some((start, payload));
        let read = consumer.read().unwrap().unwrap();
        assert_eq!(read.position, start);
        if start + extent(payload) > 4096 - 256 {
            break;
        }
    }
}
