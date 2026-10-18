// SPDX-License-Identifier: Apache-2.0

// ReplayGateway: each recorded event kind presented to the handler as
// recorded, its calls answered from the recording; the end of the prefix;
// and what it cannot reproduce (a gap, a payload it cannot give, a source
// the configuration lacks), a divergence, and an external delivery.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_sys::frame::Lane;

use super::*;
use crate::fault::{FaultDisk, Survives};
use crate::group::gateway::{Effects, PublicationId};
use crate::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use crate::group::prefix::{Coverage, recover};
use crate::group::record::{
    CONTRACT_VERSION, Capture, Clock, EndOutcome, EventEnd, ExternalEvent, GapMarker, GapReason,
    JournalHeader, LifecycleEvent, LifecycleKind, Loss, LossEvent, MAX_RECORD, MessageEvent,
    Operation, Outcome, OutcomeObservation, TimerEvent,
};
use crate::group::replay::{CaptureJournal, CursorConfig, ReplayConfig};
use crate::segment::SyncPolicy;

const CONFIG: JournalConfig = JournalConfig {
    segment_length: MIN_SEGMENT_LENGTH,
    policy: SyncPolicy::PerSegment,
};
/// Subscription 0 is stream 10, session 3; publication 0 is stream 20,
/// session 5.
const SUBSCRIPTIONS: [(i32, i32); 1] = [(10, 3)];
const PUBLICATIONS: [(i32, i32); 1] = [(20, 5)];

/// Only recording 7, written and durable to 4096.
struct Seven;

impl Coverage for Seven {
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        (recording_id == 7).then_some((4096, 4096))
    }

    fn ended(&self, _recording_id: u64) -> Option<u64> {
        None
    }
}

fn message(seq: u64, stream_id: i32, payload: Payload<'static>) -> GroupRecord<'static> {
    GroupRecord::Message(MessageEvent {
        group_seq: seq,
        logical_time: seq * 10,
        incarnation: 1,
        position: seq * 64,
        extent: 64,
        stream_id,
        session_id: 3,
        lane: Lane::ZERO,
        reserved_value: 7,
        end_of_stream: false,
        extension: None,
        payload,
    })
}

fn end(seq: u64, observations: u32, outcome: EndOutcome) -> GroupRecord<'static> {
    GroupRecord::End(EventEnd {
        group_seq: seq,
        observations,
        outcome,
    })
}

/// Event 1, a message whose handler offered its payload, accepted.
fn offered() -> [GroupRecord<'static>; 3] {
    let (length, crc32c) = (2, crate::crc32c::crc32c(b"hi"));
    [
        message(1, 10, Payload::Inline(b"hi")),
        GroupRecord::Outcome(OutcomeObservation {
            group_seq: 1,
            index: 0,
            stream_id: 20,
            session_id: 5,
            operation: Operation::Offer,
            outcome: Outcome::Accepted {
                lane: Lane::ZERO,
                position: 0,
            },
            length,
            crc32c,
        }),
        end(1, 1, EndOutcome::Complete),
    ]
}

fn header(capture: Capture) -> JournalHeader<'static> {
    JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: CONTRACT_VERSION,
        clock: Clock::HostMonotonic,
        capture,
        manifest: b"m",
    }
}

fn replaying(
    capture: Capture,
    records: &[GroupRecord<'_>],
    present_unavailable: bool,
) -> ReplayGateway<FaultDisk> {
    replaying_from(capture, records, present_unavailable, None)
}

fn replaying_from(
    capture: Capture,
    records: &[GroupRecord<'_>],
    present_unavailable: bool,
    archive: Option<Archive<FaultDisk>>,
) -> ReplayGateway<FaultDisk> {
    let header = header(capture);
    let disk = FaultDisk::default();
    let mut journal = GroupJournal::create(disk.clone(), Path::new("/g"), &header, CONFIG).unwrap();
    let mut out = vec![0u8; MAX_RECORD];
    for record in records {
        let length = record.encode(&mut out).unwrap();
        let _ = journal.append(&out[..length]).unwrap();
    }
    let _ = journal.close().unwrap();
    let mut journal = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new("/g"),
        1,
        CONFIG,
    )
    .unwrap()
    .journal;
    let recovery = recover(&mut journal, &Seven, 8).unwrap();
    let replay = ReplayConfig {
        manifest: b"m",
        accept_manifest: false,
    };
    let room = CursorConfig {
        bytes: 8 * 256,
        records: 8,
    };
    let cursor = ReplayCursor::open(journal, &recovery, &replay, room).unwrap();
    ReplayGateway::new(
        cursor,
        &GatewayConfig {
            publications: &PUBLICATIONS,
            subscriptions: &SUBSCRIPTIONS,
            conflated: &[],
            max_claim: 64,
            max_payload: 256,
            present_unavailable,
        },
        archive,
    )
    .unwrap()
}

/// A handler that writes down each event and, on a message, offers its
/// payload.
#[derive(Default)]
struct Echo {
    seen: Vec<String>,
}

impl Handler for Echo {
    fn on_event(&mut self, event: &Event<'_>, effects: &mut dyn Effects) {
        self.seen.push(format!("{event:?} at {}", effects.clock()));
        if let Event::Message { payload, .. } = event
            && !payload.is_empty()
        {
            let _ = effects.offer(PublicationId(0), payload);
        }
    }
}

#[test]
fn each_event_is_presented_as_recorded_then_the_end() {
    let mut records = offered().to_vec();
    records.extend([
        GroupRecord::Timer(TimerEvent {
            group_seq: 2,
            logical_time: 20,
            timer_id: 4,
        }),
        end(2, 0, EndOutcome::Complete),
        GroupRecord::External(ExternalEvent {
            group_seq: 3,
            logical_time: 30,
            kind: 9,
            value: b"quote",
        }),
        end(3, 0, EndOutcome::Complete),
        GroupRecord::Loss(LossEvent {
            group_seq: 4,
            logical_time: 40,
            incarnation: 1,
            from: 64,
            lost_to: 128,
            resume: 128,
            stream_id: 10,
            session_id: 3,
            lane: Lane::ZERO,
            loss: Loss::Aborted,
        }),
        end(4, 0, EndOutcome::Complete),
        GroupRecord::Lifecycle(LifecycleEvent {
            group_seq: 5,
            logical_time: 50,
            incarnation: 1,
            position: 128,
            stream_id: 10,
            session_id: 3,
            lane: Lane::ZERO,
            kind: LifecycleKind::ImageAvailable,
        }),
        end(5, 0, EndOutcome::Complete),
    ]);
    let mut gateway = replaying(Capture::Strict, &records, false);
    let mut echo = Echo::default();
    for seq in 1..=5 {
        assert_eq!(
            gateway.dispatch(&mut echo),
            Ok(Dispatched::Event { group_seq: seq })
        );
    }
    assert_eq!(gateway.dispatch(&mut echo), Ok(Dispatched::End));
    assert_eq!(gateway.dispatch(&mut echo), Ok(Dispatched::End));
    let source = SubscriptionId(0);
    let wanted = [
        format!(
            "{:?} at 10",
            Event::Message {
                source,
                lane: Lane::ZERO,
                position: 64,
                reserved_value: 7,
                end_of_stream: false,
                extension: None,
                payload: b"hi",
            }
        ),
        format!("{:?} at 20", Event::Timer { timer: TimerId(4) }),
        format!(
            "{:?} at 30",
            Event::External {
                kind: 9,
                value: b"quote"
            }
        ),
        format!(
            "{:?} at 40",
            Event::Loss {
                source,
                loss: Loss::Aborted,
                from: 64,
                lost_to: 128,
                resume: 128,
            }
        ),
        format!(
            "{:?} at 50",
            Event::Lifecycle {
                source,
                kind: LifecycleKind::ImageAvailable,
            }
        ),
    ];
    assert_eq!(echo.seen, wanted);
}

/// A handler that does not make its recorded call diverges, and replay
/// stops there.
#[test]
fn a_divergence_stops_replay() {
    let mut gateway = replaying(Capture::Strict, &offered(), false);
    let mut quiet = |_: &Event<'_>, _: &mut dyn Effects| {};
    let diverged = gateway.dispatch(&mut quiet);
    assert!(matches!(
        diverged,
        Err(GatewayError::Diverged(divergence))
            if divergence.group_seq == 1 && divergence.index == 0
                && divergence.expected == 11 && divergence.found == 0
    ));
    assert_eq!(gateway.dispatch(&mut Echo::default()), diverged);
}

/// A payload by reference that cannot be read, or a source the
/// configuration lacks, is not reproducible; with the opt-in the message
/// is presented with no payload.
#[test]
fn what_replay_cannot_give_is_not_reproducible() {
    let referenced = [
        message(
            1,
            10,
            Payload::Reference {
                recording_id: 8,
                length: 10,
            },
        ),
        end(1, 0, EndOutcome::Complete),
    ];
    // The reference never completes the prefix (recording 8 is not
    // covered, only 7 is), so the prefix ends before it.
    let mut gateway = replaying(Capture::Strict, &referenced, false);
    assert_eq!(gateway.dispatch(&mut Echo::default()), Ok(Dispatched::End));
    // Uncaptured (payload 3) in a best-effort journal.
    let GroupRecord::Message(event) = message(1, 10, Payload::Unavailable { length: 70_000 })
    else {
        panic!("a message");
    };
    let uncaptured = [
        GroupRecord::Message(MessageEvent {
            extent: 70_080,
            ..event
        }),
        end(1, 0, EndOutcome::Complete),
    ];
    let mut gateway = replaying(Capture::BestEffort, &uncaptured, false);
    let refused = gateway.dispatch(&mut Echo::default());
    assert_eq!(refused, Err(GatewayError::NotReproducible { group_seq: 1 }));
    assert_eq!(gateway.dispatch(&mut Echo::default()), refused);
    let mut presented = replaying(Capture::BestEffort, &uncaptured, true);
    let mut echo = Echo::default();
    assert_eq!(
        presented.dispatch(&mut echo),
        Ok(Dispatched::Event { group_seq: 1 })
    );
    assert!(echo.seen[0].contains("payload: []"), "{:?}", echo.seen);
    // Another stream than the configuration's subscriptions.
    let elsewhere = [
        message(1, 11, Payload::Inline(b"hi")),
        end(1, 0, EndOutcome::Complete),
    ];
    let mut gateway = replaying(Capture::Strict, &elsewhere, false);
    assert_eq!(
        gateway.dispatch(&mut Echo::default()),
        Err(GatewayError::NotReproducible { group_seq: 1 })
    );
}

/// A gap stops replay at its first event; an incomplete event too.
#[test]
fn a_gap_or_an_incomplete_event_is_not_reproducible() {
    let mut records = offered().to_vec();
    records.push(GroupRecord::Gap(GapMarker {
        from_seq: 2,
        to_seq: 3,
        reason: GapReason::RingFull,
    }));
    let mut gateway = replaying(Capture::BestEffort, &records, false);
    let mut echo = Echo::default();
    assert_eq!(
        gateway.dispatch(&mut echo),
        Ok(Dispatched::Event { group_seq: 1 })
    );
    assert_eq!(
        gateway.dispatch(&mut echo),
        Err(GatewayError::NotReproducible { group_seq: 2 })
    );
    let incomplete = [
        message(1, 10, Payload::Inline(b"")),
        end(1, 0, EndOutcome::Incomplete),
    ];
    let mut gateway = replaying(Capture::Strict, &incomplete, false);
    assert_eq!(
        gateway.dispatch(&mut Echo::default()),
        Err(GatewayError::NotReproducible { group_seq: 1 })
    );
}

#[test]
fn an_external_delivery_is_refused_in_replay() {
    let mut gateway = replaying(Capture::Strict, &offered(), false);
    assert_eq!(
        gateway.deliver_external(9, b"quote", &mut Echo::default()),
        Err(GatewayError::ExternalInReplay)
    );
    // Nothing was consumed: the recorded event is still next.
    assert_eq!(
        gateway.dispatch(&mut Echo::default()),
        Ok(Dispatched::Event { group_seq: 1 })
    );
}

/// Recording 7 in `/archive`, holding one data frame of `payload` at 0;
/// and the message event that names it.
fn by_reference(payload: &[u8]) -> (Archive<FaultDisk>, GroupRecord<'static>) {
    use crate::segment::{Geometry, SegmentStore};
    use karyos_sys::frame::{Flags, FrameType, Word0};

    let geometry = Geometry::new(4096, 8192).unwrap();
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new("/archive"),
        7,
        geometry,
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    let length = 32 + payload.len();
    let word0 = Word0::new(
        i32::try_from(length).unwrap(),
        Flags::new(true, true, false, false, Lane::ZERO),
        FrameType::Data,
    );
    let mut frame = vec![0u8; length.next_multiple_of(32)];
    frame[..8].copy_from_slice(&word0.pack().to_le_bytes());
    frame[32..length].copy_from_slice(payload);
    store.stamp(1);
    let _ = store.append(0, &frame).unwrap();
    store.close().unwrap();
    let GroupRecord::Message(event) = message(
        1,
        10,
        Payload::Reference {
            recording_id: 7,
            length: u32::try_from(payload.len()).unwrap(),
        },
    ) else {
        panic!("a message");
    };
    let event = GroupRecord::Message(MessageEvent {
        position: 0,
        extent: u32::try_from(frame.len()).unwrap(),
        ..event
    });
    let archive = Archive {
        disk,
        dir: Path::new("/archive").to_path_buf(),
        recordings: vec![(7, geometry)],
    };
    (archive, event)
}

/// A payload by reference is read from its recording and presented whole;
/// without the Archive, or with one that lacks the recording, it is not
/// reproducible.
#[test]
fn a_payload_by_reference_is_read_from_its_recording() {
    let (archive, event) = by_reference(b"by reference!");
    let records = [event, end(1, 0, EndOutcome::Complete)];
    let mut gateway = replaying_from(Capture::Strict, &records, false, Some(archive.clone()));
    let mut payloads = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if let Event::Message { payload, .. } = event {
            payloads.push(payload.to_vec());
        }
    };
    assert_eq!(
        gateway.dispatch(&mut handler),
        Ok(Dispatched::Event { group_seq: 1 })
    );
    assert_eq!(payloads, [b"by reference!".to_vec()]);
    for archive in [
        None,
        Some(Archive {
            recordings: Vec::new(),
            ..archive
        }),
    ] {
        let mut gateway = replaying_from(Capture::Strict, &records, false, archive);
        assert_eq!(
            gateway.dispatch(&mut Echo::default()),
            Err(GatewayError::NotReproducible { group_seq: 1 })
        );
    }
}

/// An incomplete event runs with its recorded observations, checked as
/// usual; a call past them is no divergence (the capture stopped there),
/// and replay stops after the event, not reproducible.
#[test]
fn an_incomplete_event_replays_its_recorded_observations() {
    let [first, offer, _] = offered();
    let records = [first, offer, end(1, 1, EndOutcome::Incomplete)];
    let mut more = |_: &Event<'_>, effects: &mut dyn Effects| {
        let recorded = Outcome::Accepted {
            lane: Lane::ZERO,
            position: 0,
        };
        assert_eq!(effects.offer(PublicationId(0), b"hi"), recorded);
        assert_eq!(effects.offer(PublicationId(0), b"hi"), Outcome::Gated);
    };
    let mut gateway = replaying(Capture::Strict, &records, false);
    assert_eq!(
        gateway.dispatch(&mut more),
        Err(GatewayError::NotReproducible { group_seq: 1 })
    );
    // A recorded call that differs is still a divergence.
    let mut other = |_: &Event<'_>, effects: &mut dyn Effects| {
        let _ = effects.offer(PublicationId(0), b"ho");
    };
    let mut gateway = replaying(Capture::Strict, &records, false);
    assert!(matches!(
        gateway.dispatch(&mut other),
        Err(GatewayError::Diverged(divergence)) if divergence.group_seq == 1
    ));
}

/// Replays `records` through `handler` into a capture under the manifest
/// `replay`, until a stop; returns the stop and the capture's records,
/// encoded.
fn captured(
    capture: Capture,
    records: &[GroupRecord<'_>],
    handler: &mut dyn Handler,
) -> (Result<Dispatched, GatewayError>, Vec<Vec<u8>>) {
    let journal = CaptureJournal::create(
        FaultDisk::default(),
        Path::new("/c"),
        &header(capture),
        b"replay",
        CONFIG,
    )
    .unwrap();
    let mut gateway = replaying(capture, records, false).with_capture(journal);
    let stop = loop {
        match gateway.dispatch(handler) {
            Ok(Dispatched::Event { .. }) => {}
            stop => break stop,
        }
    };
    let (_, journal) = gateway.into_parts();
    let mut journal = journal.unwrap().into_journal();
    let mut out = vec![0u8; MAX_RECORD];
    let mut written = Vec::new();
    let _ = journal
        .walk(0, |_, _, record| {
            let length = record.encode(&mut out).unwrap();
            written.push(out[..length].to_vec());
            true
        })
        .unwrap();
    (stop, written)
}

fn encoded(record: &GroupRecord<'_>) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = record.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

/// A replay that matches its recording captures the same records, under
/// the replaying caller's manifest; one that diverges captures the event
/// up to its divergence, ended incomplete, and nothing after.
#[test]
fn the_capture_holds_what_the_handler_did() {
    let mut records = offered().to_vec();
    records.extend([
        GroupRecord::Timer(TimerEvent {
            group_seq: 2,
            logical_time: 20,
            timer_id: 4,
        }),
        end(2, 0, EndOutcome::Complete),
    ]);
    let (stop, written) = captured(Capture::Strict, &records, &mut Echo::default());
    assert_eq!(stop, Ok(Dispatched::End));
    let mut wanted = vec![encoded(&GroupRecord::Header(JournalHeader {
        manifest: b"replay",
        ..header(Capture::Strict)
    }))];
    wanted.extend(records.iter().map(encoded));
    assert_eq!(written, wanted);
    // A handler that makes no call: event 1 ends incomplete with no
    // observation, and replay stops there.
    let mut quiet = |_: &Event<'_>, _: &mut dyn Effects| {};
    let (stop, written) = captured(Capture::Strict, &records, &mut quiet);
    assert!(matches!(stop, Err(GatewayError::Diverged(_))));
    assert_eq!(
        written[1..],
        [
            encoded(&records[0]),
            encoded(&end(1, 0, EndOutcome::Incomplete))
        ]
    );
}

/// An incomplete event is captured with the observations it matched,
/// ended incomplete.
#[test]
fn an_incomplete_event_is_captured_incomplete() {
    let [first, offer, _] = offered();
    let records = [first, offer, end(1, 1, EndOutcome::Incomplete)];
    let (stop, written) = captured(Capture::Strict, &records, &mut Echo::default());
    assert_eq!(stop, Err(GatewayError::NotReproducible { group_seq: 1 }));
    assert_eq!(
        written[1..],
        [
            encoded(&records[0]),
            encoded(&records[1]),
            encoded(&records[2])
        ]
    );
}

/// An event a reference unavailable (template 22) names is not presented
/// with the payload, even while its recording still holds the frames:
/// not reproducible, or with the opt-in, presented with no payload.
#[test]
fn a_reference_named_unavailable_is_not_read() {
    use crate::group::record::ReferenceUnavailable;

    let (archive, event) = by_reference(b"by reference!");
    let records = [
        event,
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Unavailable(ReferenceUnavailable {
            group_seq: 1,
            recording_id: 7,
        }),
    ];
    let mut gateway = replaying_from(Capture::BestEffort, &records, false, Some(archive.clone()));
    assert_eq!(
        gateway.dispatch(&mut Echo::default()),
        Err(GatewayError::NotReproducible { group_seq: 1 })
    );
    let mut gateway = replaying_from(Capture::BestEffort, &records, true, Some(archive));
    let mut payloads = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if let Event::Message { payload, .. } = event {
            payloads.push(payload.to_vec());
        }
    };
    assert_eq!(
        gateway.dispatch(&mut handler),
        Ok(Dispatched::Event { group_seq: 1 })
    );
    assert_eq!(payloads, [Vec::<u8>::new()]);
}

/// A table that names one stream and session twice is refused at
/// configuration: an event would silently be its first id's.
#[test]
fn a_duplicate_source_is_refused_at_configuration() {
    let gateway = || replaying(Capture::Strict, &offered(), false).into_parts().0;
    for (publications, subscriptions) in [
        (&[(20, 5), (20, 5)][..], &SUBSCRIPTIONS[..]),
        (&PUBLICATIONS[..], &[(10, 3), (10, 3)][..]),
    ] {
        let refused = ReplayGateway::new(
            gateway(),
            &GatewayConfig {
                publications,
                subscriptions,
                conflated: &[],
                max_claim: 64,
                max_payload: 256,
                present_unavailable: false,
            },
            None,
        );
        assert!(matches!(refused, Err(ReplayError::InvalidConfig)));
    }
}

/// An incomplete event a reference unavailable names is not presented
/// either: the cursor's scan covers the event it gives after the prefix.
#[test]
fn an_incomplete_event_named_unavailable_is_not_presented() {
    use crate::group::record::ReferenceUnavailable;

    let (archive, event) = by_reference(b"by reference!");
    let records = [
        event,
        end(1, 0, EndOutcome::Incomplete),
        GroupRecord::Unavailable(ReferenceUnavailable {
            group_seq: 1,
            recording_id: 7,
        }),
    ];
    let mut gateway = replaying_from(Capture::BestEffort, &records, false, Some(archive));
    let mut never = |_: &Event<'_>, _: &mut dyn Effects| panic!("presented");
    assert_eq!(
        gateway.dispatch(&mut never),
        Err(GatewayError::NotReproducible { group_seq: 1 })
    );
}
