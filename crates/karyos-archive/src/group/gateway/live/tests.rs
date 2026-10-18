// SPDX-License-Identifier: Apache-2.0

// The live Gateway: each observation recorded as the handler saw it, in
// order, through the ring into the journal; the clock read once per event;
// strict refusing what it cannot record; best effort delivering it and
// coalescing the refused events into one gap marker with the first
// refusal's reason; an event whose observations overflow its buffer ending
// incomplete, its calls still performed.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;

use karyos_sys::frame::Lane;

use super::*;
use crate::fault::FaultDisk;
use crate::group::capture::{CaptureConfig, CaptureJob, capture};
use crate::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use crate::group::prefix::Coverage;
use crate::group::record::{Clock, JournalHeader, MAX_RECORD};
use crate::segment::SyncPolicy;

struct NoRecordings;

impl Coverage for NoRecordings {
    fn positions(&self, _: u64) -> Option<(u64, u64)> {
        None
    }
    fn ended(&self, _: u64) -> Option<u64> {
        None
    }
}

/// A port that accepts everything, counting its calls.
#[derive(Default)]
struct Accepting {
    calls: u32,
    position: u64,
    claimed: Vec<u8>,
    deliveries: u32,
}

impl Port for Accepting {
    fn publication(&self, publication: PublicationId) -> (i32, i32) {
        (i32::from(publication.0) + 100, 7)
    }
    fn offer(&mut self, _: PublicationId, payload: &[u8]) -> Outcome {
        self.calls += 1;
        self.position += payload.len() as u64;
        Outcome::Accepted {
            lane: Lane::ZERO,
            position: self.position,
        }
    }
    fn claim(
        &mut self,
        _: PublicationId,
        length: usize,
        write: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        self.calls += 1;
        self.claimed = vec![0; length];
        let position = self.position;
        let committed = write(&mut self.claimed);
        let commit = if committed {
            Outcome::Accepted {
                lane: Lane::ZERO,
                position,
            }
        } else {
            Outcome::Aborted {
                lane: Lane::ZERO,
                position,
            }
        };
        ClaimCommit {
            claim: Outcome::Accepted {
                lane: Lane::ZERO,
                position,
            },
            commit: Some(commit),
        }
    }
    fn poll_outcomes(
        &mut self,
        _: PublicationId,
        max: u32,
        each: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32 {
        self.calls += 1;
        let count = self.deliveries.min(max);
        for start in 0..count {
            each(&DeliveryOutcome {
                kind: 1,
                incarnation: 3,
                lost: 0,
                lane: Lane::ZERO,
                receiver: 0,
                start: u64::from(start) * 64,
                end: u64::from(start) * 64 + 64,
                epoch: 1,
                reason: 0,
            });
        }
        count
    }
    fn schedule(&mut self, _: TimerId, _: u64) {
        self.calls += 1;
    }
    fn cancel(&mut self, _: TimerId) {
        self.calls += 1;
    }
}

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
        manifest: b"m",
    }
}

fn config() -> JournalConfig {
    JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: UNSYNCED,
    }
}

type Clocked = Box<dyn FnMut() -> u64>;

/// A Gateway over a fresh journal: its job, the disk, and how often the
/// clock was read.
fn gateway(
    mode: Capture,
    ring_capacity: usize,
    max_event: usize,
) -> (
    Gateway<Accepting, Clocked>,
    CaptureJob<FaultDisk>,
    FaultDisk,
    Rc<Cell<u64>>,
) {
    let disk = FaultDisk::default();
    let journal =
        GroupJournal::create(disk.clone(), Path::new("/g"), &header(mode), config()).unwrap();
    let (sender, job) = capture(
        CaptureConfig {
            ring_capacity,
            max_event,
            in_flight: 64,
        },
        journal,
        &NoRecordings,
    )
    .unwrap();
    let reads = Rc::new(Cell::new(0));
    let clock: Clocked = {
        let reads = Rc::clone(&reads);
        Box::new(move || {
            reads.set(reads.get() + 1);
            1000 * reads.get()
        })
    };
    let gateway = Gateway::new(Accepting::default(), clock, sender, mode, 1, max_event, 8).unwrap();
    (gateway, job, disk, reads)
}

/// Drains the ring, closes the journal, and returns its records re-encoded
/// after the header, each as bytes.
fn records(mut job: CaptureJob<FaultDisk>, disk: &FaultDisk) -> Vec<Vec<u8>> {
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    job.close().unwrap();
    let mut journal = GroupJournal::recover(disk.clone(), Path::new("/g"), 1, config())
        .unwrap()
        .journal;
    let mut out = Vec::new();
    let mut buffer = vec![0u8; MAX_RECORD];
    journal
        .walk(0, |_, _, record| {
            if !matches!(record, GroupRecord::Header(_)) {
                let length = record.encode(&mut buffer).unwrap();
                out.push(buffer[..length].to_vec());
            }
            true
        })
        .unwrap();
    out
}

fn decoded(bytes: &[Vec<u8>]) -> Vec<GroupRecord<'_>> {
    bytes
        .iter()
        .map(|record| GroupRecord::decode(record).unwrap())
        .collect()
}

/// Each kind of observation is recorded as the handler saw it, in call
/// order with its index: an offer and a commit with their bytes' length
/// and crc32c, an abort with the bytes as written, a poll before its
/// deliveries (an empty one too), timer operations and an external value.
#[test]
fn every_observation_is_recorded_as_the_handler_saw_it() {
    let (mut gateway, job, disk, reads) = gateway(Capture::Strict, 1 << 16, 4096);
    gateway.port().deliveries = 2;
    let mut seen_clock = Vec::new();
    let mut handler = |event: &Event<'_>, effects: &mut dyn Effects| {
        assert_eq!(
            *event,
            Event::External {
                kind: 9,
                value: b"in"
            }
        );
        seen_clock.push(effects.clock());
        let _ = effects.offer(PublicationId(1), b"hello");
        let _ = effects.claim(PublicationId(2), 4, &mut |bytes| {
            bytes.copy_from_slice(b"abcd");
            true
        });
        let _ = effects.claim(PublicationId(2), 3, &mut |bytes| {
            bytes.copy_from_slice(b"xyz");
            false
        });
        assert_eq!(effects.poll_outcomes(PublicationId(3), 8, &mut |_| {}), 2);
        assert_eq!(effects.poll_outcomes(PublicationId(3), 0, &mut |_| {}), 0);
        effects.schedule(TimerId(4), 77);
        effects.cancel(TimerId(4));
        let value = effects.external(5, &mut |out| {
            out[..3].copy_from_slice(b"ext");
            3
        });
        assert_eq!(value, b"ext");
        seen_clock.push(effects.clock());
    };
    assert_eq!(
        gateway.deliver_external(9, b"in", &mut handler),
        Ok(Dispatched::Event { group_seq: 1 })
    );
    // The clock was read once, and `clock()` returned that read.
    assert_eq!(reads.get(), 1);
    assert_eq!(seen_clock, [1000, 1000]);
    assert_eq!(gateway.port().calls, 7);
    let bytes = records(job, &disk);
    let records = decoded(&bytes);
    let outcome = |index, operation, stream_id, length, crc32c, outcome| {
        GroupRecord::Outcome(OutcomeObservation {
            group_seq: 1,
            index,
            stream_id,
            session_id: 7,
            operation,
            outcome,
            length,
            crc32c,
        })
    };
    let accepted = |position| Outcome::Accepted {
        lane: Lane::ZERO,
        position,
    };
    let delivery = |index, start: u64| {
        GroupRecord::Delivery(DeliveryObservation {
            group_seq: 1,
            index,
            stream_id: 103,
            session_id: 7,
            kind: 1,
            lane: Lane::ZERO,
            receiver: 0,
            incarnation: 3,
            start,
            end: start + 64,
            epoch: 1,
            reason: 0,
            lost: 0,
        })
    };
    let poll = |index, max, count| {
        GroupRecord::Poll(DeliveryPoll {
            group_seq: 1,
            index,
            max,
            count,
            stream_id: 103,
            session_id: 7,
        })
    };
    let expected = vec![
        GroupRecord::External(ExternalEvent {
            group_seq: 1,
            logical_time: 1000,
            kind: 9,
            value: b"in",
        }),
        outcome(0, Operation::Offer, 101, 5, crc32c(b"hello"), accepted(5)),
        outcome(1, Operation::Claim, 102, 0, 0, accepted(5)),
        outcome(2, Operation::Commit, 102, 4, crc32c(b"abcd"), accepted(5)),
        outcome(3, Operation::Claim, 102, 0, 0, accepted(5)),
        outcome(
            4,
            Operation::Commit,
            102,
            3,
            crc32c(b"xyz"),
            Outcome::Aborted {
                lane: Lane::ZERO,
                position: 5,
            },
        ),
        poll(5, 8, 2),
        delivery(6, 0),
        delivery(7, 64),
        poll(8, 0, 0),
        GroupRecord::TimerOperation(TimerObservation {
            group_seq: 1,
            index: 9,
            timer_id: 4,
            deadline: 77,
            action: TimerAction::Create,
        }),
        GroupRecord::TimerOperation(TimerObservation {
            group_seq: 1,
            index: 10,
            timer_id: 4,
            deadline: 77,
            action: TimerAction::Cancel,
        }),
        GroupRecord::ExternalObservation(ExternalObservation {
            group_seq: 1,
            index: 11,
            kind: 5,
            value: b"ext",
        }),
        GroupRecord::End(EventEnd {
            group_seq: 1,
            observations: 12,
            outcome: EndOutcome::Complete,
        }),
    ];
    assert_eq!(records, expected);
}

/// The ring's capacity for these tests: eight events of 1 KiB, no more.
const SMALL_RING: usize = 8 * 1024;

/// Fills the ring with events the job does not drain, until one is
/// refused; returns how many were taken.
fn fill(gateway: &mut Gateway<Accepting, Clocked>) -> u64 {
    let mut taken = 0;
    while let Ok(Dispatched::Event { .. }) =
        gateway.deliver_external(1, &[0u8; 600], &mut |_: &Event<'_>, _: &mut dyn Effects| {})
    {
        taken += 1;
    }
    taken
}

/// Strict capture never delivers what it cannot record: a full ring
/// refuses the event, typed and counted, and the handler does not run.
#[test]
fn strict_refuses_an_event_it_cannot_record() {
    let (mut gateway, mut job, _disk, _) = gateway(Capture::Strict, SMALL_RING, 1000);
    let taken = fill(&mut gateway);
    assert!(taken > 0);
    let mut ran = false;
    assert_eq!(
        gateway.deliver_external(1, b"x", &mut |_: &Event<'_>, _: &mut dyn Effects| ran =
            true),
        Err(GatewayError::Refused(Refusal::RingFull))
    );
    assert!(!ran);
    assert_eq!(gateway.stats().ring_full, 2);
    assert_eq!(gateway.stats().uncaptured, 0);
    // Once drained it takes events again, numbered on.
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    assert_eq!(
        gateway.deliver_external(1, b"x", &mut |_: &Event<'_>, _: &mut dyn Effects| {}),
        Ok(Dispatched::Event {
            group_seq: taken + 1
        })
    );
    // A value over `MAX_INLINE` cannot be recorded: refused.
    let large = vec![0u8; MAX_INLINE + 1];
    assert_eq!(
        gateway.deliver_external(1, &large, &mut |_: &Event<'_>, _: &mut dyn Effects| ran =
            true),
        Err(GatewayError::TooLarge(MAX_INLINE + 1))
    );
    assert!(!ran);
    assert_eq!(gateway.stats().payload_unavailable, 1);
}

/// Best effort delivers what it cannot record. The events refused in a
/// row become one gap marker, written before the next recorded event, with
/// the first refusal's reason.
#[test]
fn best_effort_coalesces_refused_events_into_one_gap() {
    for (first_large, reason) in [
        (false, GapReason::RingFull),
        (true, GapReason::PayloadUnavailable),
    ] {
        let (mut gateway, mut job, disk, _) = gateway(Capture::BestEffort, SMALL_RING, 1000);
        let mut delivered = 0;
        let mut count = |_: &Event<'_>, _: &mut dyn Effects| delivered += 1;
        if first_large {
            let large = vec![0u8; MAX_INLINE + 1];
            assert_eq!(
                gateway.deliver_external(1, &large, &mut count),
                Ok(Dispatched::Uncaptured)
            );
        }
        let before = gateway.next_seq();
        let taken = fill(&mut gateway);
        // The refused one ran; three more run, refused in a row.
        for _ in 0..3 {
            assert_eq!(
                gateway.deliver_external(1, b"x", &mut count),
                Ok(Dispatched::Uncaptured)
            );
        }
        // Drained, the next event first writes the gap.
        while job.duty(0, 1024, &NoRecordings).unwrap() {}
        let next = gateway.next_seq();
        assert_eq!(
            gateway.deliver_external(1, b"y", &mut count),
            Ok(Dispatched::Event { group_seq: next })
        );
        let stats = *gateway.stats();
        assert_eq!(stats.gaps, if first_large { 2 } else { 1 });
        assert_eq!(stats.uncaptured, 4 + u64::from(first_large));
        let bytes = records(job, &disk);
        let gaps: Vec<GapMarker> = decoded(&bytes)
            .into_iter()
            .filter_map(|record| match record {
                GroupRecord::Gap(gap) => Some(gap),
                _ => None,
            })
            .collect();
        let refused_from = before + taken;
        let mut expected = Vec::new();
        if first_large {
            expected.push(GapMarker {
                from_seq: 1,
                to_seq: 1,
                reason: GapReason::PayloadUnavailable,
            });
        }
        expected.push(GapMarker {
            from_seq: refused_from,
            to_seq: refused_from + 3,
            reason: GapReason::RingFull,
        });
        assert_eq!(gaps, expected, "{reason:?}");
    }
}

/// A gap's reason is its first refusal's. A value too large while the
/// ring is full joins the ring-full gap; a value too large with room opens
/// its own gap, written at once, so a later full ring opens another.
#[test]
fn a_gap_keeps_its_first_reason() {
    let (mut gateway, mut job, disk, _) = gateway(Capture::BestEffort, SMALL_RING, 1000);
    let taken = fill(&mut gateway);
    let large = vec![0u8; MAX_INLINE + 1];
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    assert_eq!(
        gateway.deliver_external(1, &large, noop),
        Ok(Dispatched::Uncaptured)
    );
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    assert_eq!(
        gateway.deliver_external(1, &large, noop),
        Ok(Dispatched::Uncaptured)
    );
    let again = fill(&mut gateway);
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    assert!(matches!(
        gateway.deliver_external(1, b"z", noop),
        Ok(Dispatched::Event { .. })
    ));
    let bytes = records(job, &disk);
    let gaps: Vec<GapMarker> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Gap(gap) => Some(gap),
            _ => None,
        })
        .collect();
    let first = taken + 1;
    let large_alone = first + 2;
    let refilled = large_alone + 1 + again;
    assert_eq!(
        gaps,
        [
            GapMarker {
                from_seq: first,
                to_seq: first + 1,
                reason: GapReason::RingFull,
            },
            GapMarker {
                from_seq: large_alone,
                to_seq: large_alone,
                reason: GapReason::PayloadUnavailable,
            },
            GapMarker {
                from_seq: refilled,
                to_seq: refilled,
                reason: GapReason::RingFull,
            },
        ]
    );
    assert_eq!(gateway.stats().payload_unavailable, 1);
    // The large value behind the pending gap counts as gap pending.
    assert_eq!(gateway.stats().ring_full, 2);
    assert_eq!(gateway.stats().gap_pending, 1);
}

/// Observations past the event buffer end the event incomplete. Best
/// effort still performs every call; strict performs none it cannot
/// record, refusing it as gated, and then refuses every later event.
#[test]
fn an_event_past_its_buffer_ends_incomplete() {
    for mode in [Capture::BestEffort, Capture::Strict] {
        let (mut gateway, mut job, _disk, _) = gateway(mode, 1 << 16, 512);
        let mut outcomes = Vec::new();
        let mut handler = |_: &Event<'_>, effects: &mut dyn Effects| {
            for _ in 0..20 {
                outcomes.push(effects.offer(PublicationId(1), b"p"));
            }
        };
        assert_eq!(
            gateway.deliver_external(1, b"", &mut handler),
            Ok(Dispatched::Event { group_seq: 1 })
        );
        // The offers that fit beside the external event and its end.
        let fit = (512 - (12 + 20 + 2) - END) / OUTCOME;
        let performed = match mode {
            Capture::BestEffort => 20,
            Capture::Strict => fit,
        };
        assert_eq!(gateway.port().calls as usize, performed);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Outcome::Gated)
                .count(),
            20 - performed
        );
        assert_eq!(gateway.stats().incomplete, 1);
        while job.duty(0, 1024, &NoRecordings).unwrap() {}
        let next = gateway.deliver_external(1, b"", &mut |_: &Event<'_>, _: &mut dyn Effects| {});
        match mode {
            Capture::Strict => assert_eq!(next, Err(GatewayError::Ended)),
            Capture::BestEffort => assert_eq!(next, Ok(Dispatched::Event { group_seq: 2 })),
        }
    }
}

/// Strict never performs a call it cannot record: with room for no
/// observation, an offer, a claim, a poll and timer operations are refused
/// and the port is never called (REVIEWER-01's repro).
#[test]
fn strict_performs_no_call_it_cannot_record() {
    let max_event = 12 + 20 + 2 + END + 10;
    let (mut gateway, job, disk, _) = gateway(Capture::Strict, 1 << 16, max_event);
    let mut handler = |_: &Event<'_>, effects: &mut dyn Effects| {
        assert_eq!(effects.offer(PublicationId(1), b"p"), Outcome::Gated);
        let mut wrote = false;
        assert_eq!(
            effects.claim(PublicationId(1), 4, &mut |_| {
                wrote = true;
                true
            }),
            ClaimCommit {
                claim: Outcome::Gated,
                commit: None
            }
        );
        assert!(!wrote);
        assert_eq!(effects.poll_outcomes(PublicationId(1), 1, &mut |_| {}), 0);
        effects.schedule(TimerId(1), 5);
        effects.cancel(TimerId(1));
    };
    assert_eq!(
        gateway.deliver_external(1, b"", &mut handler),
        Ok(Dispatched::Event { group_seq: 1 })
    );
    assert_eq!(gateway.port().calls, 0);
    let bytes = records(job, &disk);
    assert_eq!(
        decoded(&bytes).last(),
        Some(&GroupRecord::End(EventEnd {
            group_seq: 1,
            observations: 0,
            outcome: EndOutcome::Incomplete,
        }))
    );
}

/// A cancel repeats its timer's pending deadline; a timer not pending
/// records 0, and a cancel clears it.
#[test]
fn a_cancel_repeats_the_pending_deadline() {
    let (mut gateway, job, disk, _) = gateway(Capture::Strict, 1 << 16, 4096);
    let mut handler = |_: &Event<'_>, effects: &mut dyn Effects| {
        effects.schedule(TimerId(2), 40);
        effects.schedule(TimerId(2), 50);
        effects.cancel(TimerId(2));
        effects.cancel(TimerId(2));
        effects.cancel(TimerId(3));
        // Past the table: recorded with no deadline to repeat.
        effects.schedule(TimerId(100), 9);
        effects.cancel(TimerId(100));
    };
    gateway.deliver_external(1, b"", &mut handler).unwrap();
    let bytes = records(job, &disk);
    let cancels: Vec<(u64, u64)> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::TimerOperation(TimerObservation {
                timer_id,
                deadline,
                action: TimerAction::Cancel,
                ..
            }) => Some((timer_id, deadline)),
            _ => None,
        })
        .collect();
    assert_eq!(cancels, [(2, 50), (2, 0), (3, 0), (100, 0)]);
}

/// The configuration refuses a buffer too small for an event, and a first
/// `group_seq` of 0.
#[test]
fn a_gateway_that_cannot_work_is_refused() {
    let journal = GroupJournal::create(
        FaultDisk::default(),
        Path::new("/g"),
        &header(Capture::Strict),
        config(),
    )
    .unwrap();
    let make = || {
        capture(
            CaptureConfig {
                ring_capacity: 1 << 16,
                max_event: 4096,
                in_flight: 8,
            },
            GroupJournal::create(
                FaultDisk::default(),
                Path::new("/g"),
                &header(Capture::Strict),
                config(),
            )
            .unwrap(),
            &NoRecordings,
        )
        .unwrap()
        .0
    };
    drop(journal);
    assert!(matches!(
        Gateway::new(
            Accepting::default(),
            || 0,
            make(),
            Capture::Strict,
            1,
            40,
            8
        ),
        Err(ConfigError::Buffer(40))
    ));
    assert!(matches!(
        Gateway::new(
            Accepting::default(),
            || 0,
            make(),
            Capture::Strict,
            0,
            4096,
            8
        ),
        Err(ConfigError::FirstSeq)
    ));
}

/// A strict refusal is final for its event: after a call too large to
/// record, a later one that would fit is refused too, so the recorded
/// observations end where the handler's calls stopped being performed.
#[test]
fn a_strict_refusal_ends_the_event_for_later_calls() {
    let max_event = 12 + 20 + 2 + END + OUTCOME;
    let (mut gateway, job, disk, _) = gateway(Capture::Strict, 1 << 16, max_event);
    let mut handler = |_: &Event<'_>, effects: &mut dyn Effects| {
        assert_eq!(effects.poll_outcomes(PublicationId(1), 4, &mut |_| {}), 0);
        assert_eq!(effects.offer(PublicationId(1), b"p"), Outcome::Gated);
    };
    gateway.deliver_external(1, b"", &mut handler).unwrap();
    assert_eq!(gateway.port().calls, 0);
    let bytes = records(job, &disk);
    assert_eq!(
        decoded(&bytes).last(),
        Some(&GroupRecord::End(EventEnd {
            group_seq: 1,
            observations: 0,
            outcome: EndOutcome::Incomplete,
        }))
    );
}

/// Timer 0 cannot be recorded: strict refuses its operations, and best
/// effort performs them and ends the event incomplete.
#[test]
fn timer_zero_is_not_recorded() {
    for mode in [Capture::Strict, Capture::BestEffort] {
        let (mut gateway, _job, _disk, _) = gateway(mode, 1 << 16, 4096);
        let mut handler = |_: &Event<'_>, effects: &mut dyn Effects| {
            effects.schedule(TimerId(0), 5);
        };
        gateway.deliver_external(1, b"", &mut handler).unwrap();
        let performed = u32::from(mode == Capture::BestEffort);
        assert_eq!(gateway.port().calls, performed, "{mode:?}");
        assert_eq!(gateway.stats().incomplete, 1, "{mode:?}");
    }
}

/// A strict Gateway whose event buffer leaves exactly `room` bytes for
/// observations after an empty external event.
fn with_room(
    room: usize,
) -> (
    Gateway<Accepting, Clocked>,
    CaptureJob<FaultDisk>,
    FaultDisk,
) {
    let (gateway, job, disk, _) = gateway(Capture::Strict, 1 << 16, 12 + 20 + 2 + END + room);
    (gateway, job, disk)
}

/// The strict room check at its boundaries: a claim needs two template 11
/// records, a poll its template 15 and `max` deliveries, an offer one
/// template 11, each exactly.
#[test]
fn strict_room_is_checked_at_its_boundaries() {
    // A claim with room for one record is refused, unperformed; with room
    // for two it runs and both are recorded.
    for (room, performed) in [(OUTCOME, false), (2 * OUTCOME, true)] {
        let (mut gateway, job, disk) = with_room(room);
        let mut result = None;
        gateway
            .deliver_external(1, b"", &mut |_: &Event<'_>, effects: &mut dyn Effects| {
                result = Some(effects.claim(PublicationId(1), 4, &mut |_| true));
            })
            .unwrap();
        assert_eq!(gateway.port().calls, u32::from(performed), "{room}");
        let records = decoded(&records(job, &disk)).len();
        if performed {
            assert!(result.unwrap().commit.is_some());
            // The event, op 2, op 3 and the end.
            assert_eq!(records, 4);
        } else {
            assert_eq!(
                result,
                Some(ClaimCommit {
                    claim: Outcome::Gated,
                    commit: None
                })
            );
            assert_eq!(records, 2);
        }
    }
    // A poll of max 2 one byte short of its poll and two deliveries is
    // refused (room enough for the deliveries alone); with that room it
    // runs.
    for (room, performed) in [
        (POLL + 2 * DELIVERY - 1, false),
        (POLL + 2 * DELIVERY, true),
    ] {
        let (mut gateway, job, disk) = with_room(room);
        gateway.port().deliveries = 2;
        let mut presented = 0;
        gateway
            .deliver_external(1, b"", &mut |_: &Event<'_>, effects: &mut dyn Effects| {
                presented = effects.poll_outcomes(PublicationId(1), 2, &mut |_| {});
            })
            .unwrap();
        assert_eq!(gateway.port().calls, u32::from(performed), "{room}");
        assert_eq!(presented, if performed { 2 } else { 0 });
        let records = decoded(&records(job, &disk)).len();
        assert_eq!(records, if performed { 5 } else { 2 });
    }
    // An offer with room for exactly one record runs and is recorded.
    let (mut gateway, job, disk) = with_room(OUTCOME);
    gateway
        .deliver_external(1, b"", &mut |_: &Event<'_>, effects: &mut dyn Effects| {
            assert_ne!(effects.offer(PublicationId(1), b"p"), Outcome::Gated);
        })
        .unwrap();
    assert_eq!(gateway.port().calls, 1);
    assert_eq!(
        decoded(&records(job, &disk)).last(),
        Some(&GroupRecord::End(EventEnd {
            group_seq: 1,
            observations: 1,
            outcome: EndOutcome::Complete,
        }))
    );
}

/// A Gateway over a fresh journal whose group keeps checkpoints of up to
/// 16 bytes: its job, and the writer's end of the handoff.
fn checkpointing() -> (
    Gateway<Accepting, Clocked>,
    CaptureJob<FaultDisk>,
    crate::group::checkpoint::CheckpointInbox,
) {
    let disk = FaultDisk::default();
    let journal = GroupJournal::create(
        disk.clone(),
        Path::new("/g"),
        &header(Capture::Strict),
        config(),
    )
    .unwrap();
    let (mut sender, job) = capture(
        CaptureConfig {
            ring_capacity: 1 << 16,
            max_event: 4096,
            in_flight: 64,
        },
        journal,
        &NoRecordings,
    )
    .unwrap();
    let (handle, inbox) = crate::group::checkpoint::handoff(16);
    sender.attach_checkpoints(handle);
    let clock: Clocked = Box::new(|| 1);
    let gateway = Gateway::new(
        Accepting::default(),
        clock,
        sender,
        Capture::Strict,
        1,
        4096,
        8,
    )
    .unwrap();
    (gateway, job, inbox)
}

/// A checkpoint names the last event dispatched, `next_seq - 1`, and none
/// is taken before the first event.
#[test]
fn a_checkpoint_names_the_last_event_dispatched() {
    let (mut gateway, _job, inbox) = checkpointing();
    let mut written = false;
    assert!(matches!(
        gateway.checkpoint(9, |_| {
            written = true;
            1
        }),
        Err(CheckpointError::NothingDispatched)
    ));
    assert!(!written);
    for _ in 0..2 {
        gateway
            .deliver_external(1, b"", &mut |_: &Event<'_>, _: &mut dyn Effects| {})
            .unwrap();
    }
    gateway
        .checkpoint(9, |bytes| {
            bytes[..3].copy_from_slice(b"abc");
            3
        })
        .unwrap();
    let request = inbox.take().unwrap();
    assert_eq!((request.group_seq, request.format), (2, 9));
    assert_eq!(request.bytes(), b"abc");
    assert_eq!(gateway.checkpoint_stats().taken, 1);
    // The handle's own refusal: one in flight.
    assert!(matches!(
        gateway.checkpoint(9, |_| 1),
        Err(CheckpointError::InFlight)
    ));
    assert!(gateway.last_checkpoint().is_none());
    inbox.give_back(request, Err(CheckpointError::Stopped));
    assert!(matches!(
        gateway.last_checkpoint(),
        Some(LastCheckpoint::Failed { group_seq: 2 })
    ));
}

/// A group started without checkpoints refuses one, typed, and counts
/// nothing.
#[test]
fn a_group_without_checkpoints_refuses_one() {
    let (mut gateway, _job, _disk, _reads) = gateway(Capture::Strict, 1 << 16, 4096);
    gateway
        .deliver_external(1, b"", &mut |_: &Event<'_>, _: &mut dyn Effects| {})
        .unwrap();
    assert!(matches!(
        gateway.checkpoint(1, |_| 1),
        Err(CheckpointError::NoCheckpoints)
    ));
    assert_eq!(gateway.checkpoint_stats(), CheckpointStats::default());
    assert!(gateway.last_checkpoint().is_none());
}

/// Once the group stopped, a checkpoint is refused `Stopped` before the
/// handle is reached: not `InFlight`, and `write` is not called.
#[test]
fn stopped_wins_over_the_handles_refusals() {
    let (mut gateway, job, _inbox) = checkpointing();
    gateway
        .deliver_external(1, b"", &mut |_: &Event<'_>, _: &mut dyn Effects| {})
        .unwrap();
    gateway.checkpoint(1, |_| 1).unwrap();
    job.close().unwrap();
    let mut written = false;
    assert!(matches!(
        gateway.checkpoint(1, |_| {
            written = true;
            1
        }),
        Err(CheckpointError::Stopped)
    ));
    assert!(!written);
    // The handle was not reached: its in-flight refusal is not counted.
    assert_eq!(gateway.checkpoint_stats().in_flight, 0);
}
