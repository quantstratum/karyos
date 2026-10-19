// SPDX-License-Identifier: Apache-2.0

// The Gateway's sources over a real subscription: a timer due first, then
// messages in turn, each recorded with its source and extent; payload
// placement by the recording word; strict declining what it cannot record,
// which stays pending; a loss and a subscription's end as events of their
// own; and the observation budget.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;
use std::sync::Arc;

use karyos_client::{ClientSubscription, ConflatedSubscription};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, ClaimOutcome, Conductor, LogBuffer, LogBufferConfig, Publication, Role,
};
use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
use karyos_sys::term::TermId;

use super::*;
use crate::fault::FaultDisk;
use crate::group::capture::{CaptureConfig, CaptureJob, GroupState, capture};
use crate::group::gateway::live::{Gateway, Port};
use crate::group::gateway::{ClaimCommit, DeliveryOutcome, Effects, GroupGateway, PublicationId};
use crate::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use crate::group::prefix::Coverage;
use crate::group::record::{Clock, JournalHeader, MAX_RECORD, Outcome};
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

/// A port that offers nothing; the handlers here only read their events.
struct Idle;

impl Port for Idle {
    fn publication(&self, _: PublicationId) -> (i32, i32) {
        (0, 0)
    }
    fn offer(&mut self, _: PublicationId, _: &[u8]) -> Outcome {
        Outcome::BackPressured
    }
    fn claim(
        &mut self,
        _: PublicationId,
        _: usize,
        _: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        ClaimCommit {
            claim: Outcome::BackPressured,
            commit: None,
        }
    }
    fn poll_outcomes(
        &mut self,
        _: PublicationId,
        _: u32,
        _: &mut dyn FnMut(&DeliveryOutcome),
    ) -> u32 {
        0
    }
    fn schedule(&mut self, _: TimerId, _: u64) {}
    fn cancel(&mut self, _: TimerId) {}
}

const IDENTITY: SourceIdentity = SourceIdentity {
    incarnation: 4,
    stream_id: 2,
    session_id: 1,
    lane: Lane::ZERO,
};

fn log(term_length: u32) -> Arc<LogBuffer> {
    Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(term_length).unwrap(),
            // Room for an optional or observer reader's credit.
            spare_slots: 4,
            max_subscribers: 2,
            mtu: DEFAULT_MTU,
            max_reserved: term_length / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
        })
        .unwrap(),
    )
}

type Clocked = Box<dyn FnMut() -> u64>;

struct Rig {
    gateway: Gateway<Idle, Clocked>,
    job: CaptureJob<FaultDisk>,
    disk: FaultDisk,
    publication: Publication<Arc<LogBuffer>>,
    conductor: Conductor<Arc<LogBuffer>>,
    word: Arc<RecordingWord>,
}

/// A Gateway over one required subscription of a fresh log, the clock
/// reading 1000 at every call.
fn rig(mode: Capture, ring_capacity: usize, max_event: usize, term_length: u32) -> Rig {
    rig_as(Role::Required, mode, ring_capacity, max_event, term_length)
}

/// [`rig`] with a subscription of `role`.
fn rig_as(
    role: Role,
    mode: Capture,
    ring_capacity: usize,
    max_event: usize,
    term_length: u32,
) -> Rig {
    let disk = FaultDisk::default();
    let header = JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 64,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: mode,
        reopen_hold: 0,
        manifest: b"m",
    };
    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::Every {
            interval_ns: u64::MAX,
        },
    };
    let journal = GroupJournal::create(disk.clone(), Path::new("/g"), &header, config).unwrap();
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
    let clock: Clocked = Box::new(|| 1000);
    let mut gateway = Gateway::new(Idle, clock, sender, mode, 1, max_event, 8).unwrap();
    gateway.set_inline_threshold(64);
    let buffer = log(term_length);
    let mut conductor = buffer.conductor_owned().unwrap();
    let subscription = ClientSubscription::new(conductor.subscribe(role).unwrap());
    let publication = buffer.publication_owned().unwrap().unwrap();
    let word = Arc::new(RecordingWord::new());
    let _ = gateway
        .add_subscription(Box::new(subscription), IDENTITY, Arc::clone(&word))
        .unwrap();
    Rig {
        gateway,
        job,
        disk,
        publication,
        conductor,
        word,
    }
}

fn records(mut job: CaptureJob<FaultDisk>, disk: &FaultDisk) -> Vec<Vec<u8>> {
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    job.close().unwrap();
    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::Every {
            interval_ns: u64::MAX,
        },
    };
    let mut journal = GroupJournal::recover(disk.clone(), Path::new("/g"), 1, config)
        .unwrap()
        .journal;
    let mut out = Vec::new();
    let mut buffer = vec![0u8; MAX_RECORD];
    journal
        .walk(0, |_, _, record| {
            if !matches!(record, GroupRecord::Header(_) | GroupRecord::End(_)) {
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

fn append(rig: &mut Rig, payload: &[u8]) {
    let _ = rig
        .publication
        .append(payload, AppendOptions::default())
        .unwrap();
}

/// Messages in order, each recorded with its source's identity, its
/// position and extent, and its payload inline; a timer due at the
/// dispatch's read goes first, at its deadline.
#[test]
fn a_due_timer_goes_first_then_messages_in_order() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    append(&mut rig, b"first");
    append(&mut rig, b"second");
    // Schedule timer 3 for 900 in an external event; 1000 reads it due.
    rig.gateway
        .deliver_external(1, b"", &mut |_: &Event<'_>, effects: &mut dyn Effects| {
            effects.schedule(TimerId(3), 900);
        })
        .unwrap();
    let mut seen = Vec::new();
    let mut handler = |event: &Event<'_>, effects: &mut dyn Effects| {
        seen.push((format!("{event:?}"), effects.clock()));
    };
    let mut events = Vec::new();
    loop {
        match rig.gateway.dispatch(&mut handler).unwrap() {
            Dispatched::Idle => break,
            dispatched => events.push(dispatched),
        }
    }
    assert_eq!(
        events,
        [2, 3, 4].map(|group_seq| Dispatched::Event { group_seq })
    );
    assert!(seen[0].0.starts_with("Timer"), "{seen:?}");
    assert_eq!(seen[0].1, 900);
    assert_eq!(seen[1].1, 1000);
    let bytes = records(rig.job, &rig.disk);
    let records = decoded(&bytes);
    let messages: Vec<&MessageEvent<'_>> = records
        .iter()
        .filter_map(|record| match record {
            GroupRecord::Message(message) => Some(message),
            _ => None,
        })
        .collect();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].payload, Payload::Inline(b"first"));
    assert_eq!(messages[1].payload, Payload::Inline(b"second"));
    assert_eq!(
        messages[0].position + u64::from(messages[0].extent),
        messages[1].position
    );
    assert_eq!(
        (
            messages[0].incarnation,
            messages[0].stream_id,
            messages[0].session_id
        ),
        (4, 2, 1)
    );
    assert!(records.iter().any(|record| matches!(
        record,
        GroupRecord::Timer(TimerEvent {
            logical_time: 900,
            timer_id: 3,
            ..
        })
    )));
}

/// A payload above the inline threshold is recorded by reference while
/// the source's word names a recording that started at or before it;
/// inline once the word is cleared, or for a recording that started after
/// the message.
#[test]
fn a_payload_is_placed_by_the_recording_word() {
    let mut rig = rig(Capture::BestEffort, 1 << 16, 4096, 64 * 1024);
    let large = [9u8; 200];
    for _ in 0..3 {
        append(&mut rig, &large);
    }
    append(&mut rig, b"small");
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    rig.word.set(7, 0);
    rig.gateway.dispatch(noop).unwrap();
    rig.word.set(7, u64::MAX);
    rig.gateway.dispatch(noop).unwrap();
    rig.word.clear();
    rig.gateway.dispatch(noop).unwrap();
    rig.word.set(7, 0);
    rig.gateway.dispatch(noop).unwrap();
    let bytes = records(rig.job, &rig.disk);
    let payloads: Vec<Payload<'_>> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Message(message) => Some(message.payload),
            _ => None,
        })
        .collect();
    assert_eq!(
        payloads,
        [
            Payload::Reference {
                recording_id: 7,
                length: 200
            },
            Payload::Inline(&large),
            Payload::Inline(&large),
            // At the threshold or below: inline.
            Payload::Inline(b"small"),
        ]
    );
}

/// Strict declines a message it cannot record: the ring full, the message
/// stays pending and comes again once there is room.
#[test]
fn strict_declines_a_message_it_cannot_record() {
    let mut rig = rig(Capture::Strict, 8 * 1024, 1000, 64 * 1024);
    for _ in 0..12 {
        append(&mut rig, &[1u8; 600]);
    }
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    let mut taken = 0;
    let refused = loop {
        match rig.gateway.dispatch(noop) {
            Ok(Dispatched::Event { .. }) => taken += 1,
            other => break other,
        }
    };
    assert_eq!(refused, Err(GatewayError::Refused(Refusal::RingFull)));
    let mut job = rig.job;
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    // The declined message comes next, numbered on: nothing was lost.
    let mut delivered = 0;
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(noop) {
        delivered += 1;
        while job.duty(0, 1024, &NoRecordings).unwrap() {}
    }
    assert_eq!(taken + delivered, 12);
}

/// A payload that cannot be recorded, already read from its source:
/// above `MAX_INLINE` with no recording, or under it but past the event
/// budget. Strict ends the journal at it: the handler gets the skipped
/// range as a loss whose effects are refused from the start, the Gateway
/// refuses every later dispatch at once, and the job ends the group
/// (not failed). Best effort delivers the message: its payload recorded
/// unavailable above `MAX_INLINE`, else the message is a gap.
#[test]
fn a_payload_that_cannot_be_recorded() {
    for (length, max_event) in [(MAX_INLINE + 1, 4096), (2000, 1000)] {
        for mode in [Capture::Strict, Capture::BestEffort] {
            let mut rig = rig(mode, 1 << 20, max_event, 1024 * 1024);
            append(&mut rig, &vec![5u8; length]);
            let mut seen = Vec::new();
            let result =
                rig.gateway
                    .dispatch(&mut |event: &Event<'_>, effects: &mut dyn Effects| {
                        seen.push((
                            matches!(
                                event,
                                Event::Loss {
                                    loss: Loss::Skipped(
                                        karyos_sys::log_buffer::SkipReason::MessageTooLarge
                                    ),
                                    ..
                                }
                            ),
                            effects.offer(PublicationId(1), b"p"),
                        ));
                    });
            match (mode, length > MAX_INLINE) {
                (Capture::BestEffort, false) => assert_eq!(result, Ok(Dispatched::Uncaptured)),
                _ => assert_eq!(result, Ok(Dispatched::Event { group_seq: 1 }), "{length}"),
            }
            match mode {
                Capture::Strict => {
                    assert_eq!(seen, [(true, Outcome::Gated)], "{length}");
                    assert_eq!(rig.gateway.stats().incomplete, 1);
                    // Latched: refused before the job runs.
                    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
                    assert_eq!(rig.gateway.dispatch(noop), Err(GatewayError::Ended));
                    assert_eq!(
                        rig.gateway.deliver_external(1, b"", noop),
                        Err(GatewayError::Ended)
                    );
                    let mut job = rig.job;
                    while job.duty(0, 1024, &NoRecordings).unwrap() {}
                    assert_eq!(job.state(), GroupState::Ended, "{length}");
                    let bytes = records(job, &rig.disk);
                    let records = decoded(&bytes);
                    assert!(records.iter().any(|record| matches!(
                        record,
                        GroupRecord::Loss(LossEvent {
                            group_seq: 1,
                            loss: Loss::Skipped(
                                karyos_sys::log_buffer::SkipReason::MessageTooLarge
                            ),
                            ..
                        })
                    )));
                }
                Capture::BestEffort => {
                    assert_eq!(seen.len(), 1);
                    assert!(!seen[0].0, "{length}: a message");
                    let bytes = records(rig.job, &rig.disk);
                    let records = decoded(&bytes);
                    if length > MAX_INLINE {
                        assert!(records.iter().any(|record| matches!(
                            record,
                            GroupRecord::Message(MessageEvent {
                                payload: Payload::Unavailable { .. },
                                ..
                            })
                        )));
                    } else {
                        // Under `MAX_INLINE`, an unavailable payload is not
                        // a record: the message is a gap, delivered.
                        assert!(
                            records
                                .iter()
                                .any(|record| matches!(record, GroupRecord::Gap(_)))
                        );
                    }
                }
            }
        }
    }
}

/// An event the observation budget ends incomplete ends the strict
/// journal: the Gateway refuses every later dispatch at once, before the
/// job ends the group, which ends (not fails).
#[test]
fn a_strict_incomplete_event_is_latched() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    rig.gateway.set_observation_budget(0);
    append(&mut rig, b"one");
    append(&mut rig, b"two");
    let mut handler = |_: &Event<'_>, effects: &mut dyn Effects| {
        assert_eq!(effects.offer(PublicationId(1), b"p"), Outcome::Gated);
    };
    assert_eq!(
        rig.gateway.dispatch(&mut handler),
        Ok(Dispatched::Event { group_seq: 1 })
    );
    assert_eq!(rig.gateway.dispatch(&mut handler), Err(GatewayError::Ended));
    let mut job = rig.job;
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    assert_eq!(job.state(), GroupState::Ended);
}

/// The kinds of events a handler saw, dispatching until idle.
fn kinds_until_idle(rig: &mut Rig) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        kinds.push(match event {
            Event::Message { .. } => "message",
            Event::Loss {
                loss: Loss::Aborted,
                ..
            } => "aborted",
            Event::Lifecycle {
                kind: LifecycleKind::SubscriptionEnded(EndReason::EndOfStream),
                ..
            } => "ended",
            _ => "other",
        });
    };
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(&mut handler) {}
    assert_eq!(rig.gateway.dispatch(&mut handler), Ok(Dispatched::Idle));
    kinds
}

/// An aborted block is a loss event of its own.
#[test]
fn an_aborted_block_is_a_loss_event() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    append(&mut rig, b"one");
    let ClaimOutcome::Claimed(claim) = rig
        .publication
        .try_claim(40, AppendOptions::default())
        .unwrap()
    else {
        panic!("not claimed");
    };
    claim.abort();
    append(&mut rig, b"two");
    assert_eq!(
        kinds_until_idle(&mut rig),
        ["message", "aborted", "message"]
    );
    let bytes = records(rig.job, &rig.disk);
    assert!(decoded(&bytes).iter().any(|record| matches!(
        record,
        GroupRecord::Loss(LossEvent {
            loss: Loss::Aborted,
            stream_id: 2,
            ..
        })
    )));
}

/// A sealed stream's end is a lifecycle event, after which the source is
/// polled no more.
#[test]
fn a_subscription_end_is_a_lifecycle_event() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    append(&mut rig, b"last");
    rig.conductor.seal().unwrap();
    // A write after the seal finds it closed, and the duty positions the
    // seal for readers.
    let _ = rig.publication.append(b"late", AppendOptions::default());
    let _ = rig.conductor.duty_cycle().unwrap();
    assert_eq!(kinds_until_idle(&mut rig), ["message", "ended"]);
}

/// The observation budget: strict refuses a call past it, best effort
/// performs it, and the event ends incomplete either way.
#[test]
fn the_observation_budget_holds_per_event() {
    for mode in [Capture::Strict, Capture::BestEffort] {
        let mut rig = rig(mode, 1 << 16, 4096, 64 * 1024);
        rig.gateway.set_observation_budget(2);
        let mut outcomes = Vec::new();
        rig.gateway
            .deliver_external(1, b"", &mut |_: &Event<'_>, effects: &mut dyn Effects| {
                for _ in 0..3 {
                    outcomes.push(effects.offer(PublicationId(1), b"p"));
                }
            })
            .unwrap();
        assert_eq!(rig.gateway.stats().incomplete, 1, "{mode:?}");
        let gated = outcomes.iter().filter(|o| **o == Outcome::Gated).count();
        assert_eq!(gated, usize::from(mode == Capture::Strict), "{mode:?}");
    }
}

/// The handler's message event carries the payload's bytes, its length
/// and its extent, as the client delivered them.
#[test]
fn a_message_event_carries_its_length_and_extent() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    append(&mut rig, b"hello");
    append(&mut rig, b"next");
    let mut seen = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if let Event::Message {
            position,
            extent,
            length,
            payload,
            ..
        } = *event
        {
            seen.push((
                position,
                extent,
                length,
                payload == MessagePayload::Bytes(b"hello"),
            ));
        }
    };
    rig.gateway.dispatch(&mut handler).unwrap();
    rig.gateway.dispatch(&mut handler).unwrap();
    assert_eq!(seen.len(), 2);
    let (position, extent, length, bytes) = seen[0];
    assert_eq!((length, bytes), (5, true));
    assert_eq!(position + u64::from(extent), seen[1].0);
}

fn view(
    value_capacity: usize,
) -> (
    karyos_sys::conflation::ConflationWriter,
    ConflatedSubscription,
) {
    let writer = karyos_sys::conflation::conflation(4, value_capacity, 4096).unwrap();
    let view = ConflatedSubscription::new(
        writer.reader(),
        karyos_sys::conflation::Budget {
            keys: 4,
            retries: 4,
        },
    );
    (writer, view)
}

/// A view whose largest value cannot fit an event, or exceeds
/// `MAX_INLINE`, is refused when it is added.
#[test]
fn a_view_too_large_is_refused_when_added() {
    let mut rig = rig(Capture::Strict, 1 << 16, 512, 64 * 1024);
    let (_writer, large) = view(1024);
    assert_eq!(
        rig.gateway.add_conflated(Box::new(large), 5, 1),
        Err(GatewayError::TooLarge(1024))
    );
    let (_writer, small) = view(64);
    assert!(rig.gateway.add_conflated(Box::new(small), 5, 1).is_ok());
}

/// A view's values are events, one per dispatch, each recorded with its
/// key, version and freshness, after the message sources' turn.
#[test]
fn conflated_values_are_events() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    let (mut writer, view) = view(64);
    rig.gateway.add_conflated(Box::new(view), 5, 1).unwrap();
    writer.write(2, b"two").unwrap();
    writer.write(3, b"three").unwrap();
    let mut values = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if let Event::Conflated { key, value, .. } = event {
            values.push((*key, value.to_vec()));
        }
    };
    let mut dispatched = 0;
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(&mut handler) {
        dispatched += 1;
    }
    assert_eq!(dispatched, 2);
    // Each value with its own key, in whichever order the view gave them.
    values.sort();
    assert_eq!(values, [(2, b"two".to_vec()), (3, b"three".to_vec())]);
    let bytes = records(rig.job, &rig.disk);
    let keys: Vec<(u32, i32)> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Conflated(event) => Some((event.key, event.stream_id)),
            _ => None,
        })
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter()
            .all(|(key, stream)| [2, 3].contains(key) && *stream == 5)
    );
}

/// Strict polls a view only when an event can be admitted: with the ring
/// full its value stays in the table, and comes once there is room.
#[test]
fn strict_leaves_a_view_unread_without_room() {
    let mut rig = rig(Capture::Strict, 8 * 1024, 1000, 64 * 1024);
    let (mut writer, view) = view(64);
    rig.gateway.add_conflated(Box::new(view), 5, 1).unwrap();
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    while let Ok(Dispatched::Event { .. }) = rig.gateway.deliver_external(1, &[0u8; 600], noop) {}
    writer.write(1, b"kept").unwrap();
    let mut seen = 0;
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if matches!(event, Event::Conflated { .. }) {
            seen += 1;
        }
    };
    assert_eq!(
        rig.gateway.dispatch(&mut handler),
        Err(GatewayError::Refused(Refusal::RingFull))
    );
    let mut job = rig.job;
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    assert!(matches!(
        rig.gateway.dispatch(&mut handler),
        Ok(Dispatched::Event { .. })
    ));
    assert_eq!(seen, 1);
}

/// A log of stream 2 whose session is `session`.
fn log_of(session: i32, lane: Lane, term_length: u32) -> Arc<LogBuffer> {
    Arc::new(
        LogBuffer::new(LogBufferConfig {
            session_id: session,
            lane,
            ..*log(term_length).config()
        })
        .unwrap(),
    )
}

/// The lane of the fan-in's image of `session`.
fn lane_of(session: i32) -> Lane {
    fan_images()
        .iter()
        .find(|(image, _)| *image == session)
        .map_or(Lane::ZERO, |(_, lane)| *lane)
}

/// A network subscription's stand-in: images polled in turn, and the
/// image changes the test scripts.
struct Images {
    images: Vec<ClientSubscription>,
    next: usize,
    changes: Arc<std::sync::Mutex<std::collections::VecDeque<ImageChange>>>,
}

impl MessageSource for Images {
    fn poll_taking(
        &mut self,
        handler: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        limit: MessageLimit,
    ) -> Result<PollSummary, PollError> {
        self.poll_reporting(handler, limit)
            .map(|(summary, _)| summary)
    }

    fn next_image_change(&mut self) -> Option<ImageChange> {
        self.changes.lock().unwrap().pop_front()
    }

    fn fan_in(&self) -> bool {
        true
    }

    fn poll_reporting(
        &mut self,
        handler: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        limit: MessageLimit,
    ) -> Result<(PollSummary, Option<(i32, Lane)>), PollError> {
        let count = self.images.len();
        for offset in 0..count {
            let index = (self.next + offset) % count;
            let summary = self.images[index].poll_taking(&mut *handler, limit)?;
            if summary != PollSummary::default() {
                self.next = (index + 1) % count;
                return Ok((summary, Some(fan_images()[index])));
            }
        }
        Ok((PollSummary::default(), None))
    }
}

/// The fan-in's images' sessions, in order.
/// The fan-in's images' sessions and lanes, in order: the second on
/// lane 1.
fn fan_images() -> [(i32, Lane); 2] {
    [(1, Lane::ZERO), (3, Lane::try_new(1).unwrap())]
}

struct Fanned {
    gateway: Gateway<Idle, Clocked>,
    job: CaptureJob<FaultDisk>,
    disk: FaultDisk,
    publications: Vec<Publication<Arc<LogBuffer>>>,
    changes: Arc<std::sync::Mutex<std::collections::VecDeque<ImageChange>>>,
    word: Arc<RecordingWord>,
    _conductors: Vec<Conductor<Arc<LogBuffer>>>,
}

/// A Gateway over one fan-in source of two images, sessions 1 and 3.
fn fanned(mode: Capture, ring_capacity: usize) -> Fanned {
    let disk = FaultDisk::default();
    let header = JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 64,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: mode,
        reopen_hold: 0,
        manifest: b"m",
    };
    let journal =
        GroupJournal::create(disk.clone(), Path::new("/g"), &header, journal_config()).unwrap();
    let (sender, job) = capture(
        CaptureConfig {
            ring_capacity,
            max_event: 1000,
            in_flight: 64,
        },
        journal,
        &NoRecordings,
    )
    .unwrap();
    let clock: Clocked = Box::new(|| 1000);
    let mut gateway = Gateway::new(Idle, clock, sender, mode, 1, 1000, 8).unwrap();
    gateway.set_inline_threshold(64);
    let (mut images, mut publications, mut conductors) = (Vec::new(), Vec::new(), Vec::new());
    for (session, lane) in fan_images() {
        let buffer = log_of(session, lane, 64 * 1024);
        let mut conductor = buffer.conductor_owned().unwrap();
        images.push(ClientSubscription::new(
            conductor.subscribe(Role::Required).unwrap(),
        ));
        publications.push(buffer.publication_owned().unwrap().unwrap());
        conductors.push(conductor);
    }
    let changes = Arc::default();
    let source = Images {
        images,
        next: 0,
        changes: Arc::clone(&changes),
    };
    let word = Arc::new(RecordingWord::new());
    let _ = gateway
        .add_subscription(Box::new(source), IDENTITY, Arc::clone(&word))
        .unwrap();
    Fanned {
        gateway,
        job,
        disk,
        publications,
        changes,
        word,
        _conductors: conductors,
    }
}

fn journal_config() -> JournalConfig {
    JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::Every {
            interval_ns: u64::MAX,
        },
    }
}

/// What a handler saw, live or in replay: the event's kind and source.
fn seen(event: &Event<'_>) -> (&'static str, u16) {
    match event {
        Event::Message { source, .. } => ("message", source.0),
        Event::Lifecycle {
            source,
            kind: LifecycleKind::ImageAvailable,
        } => ("available", source.0),
        Event::Lifecycle {
            source,
            kind: LifecycleKind::ImageUnavailable,
        } => ("unavailable", source.0),
        _ => ("other", u16::MAX),
    }
}

/// Task 2 (A7d-3b): a fan-in source's image changes are lifecycle
/// events, each before that poll's messages, recorded with the image's
/// session and no position, as are its messages. Two images attach, read
/// in turn; one retires and reattaches. Replay presents the same events,
/// by stream and session.
#[test]
fn image_changes_are_lifecycle_events_live_and_in_replay() {
    use crate::group::prefix::recover;
    use crate::group::replay::gateway::{GatewayConfig, ReplayGateway};
    use crate::group::replay::{CursorConfig, ReplayConfig, ReplayCursor};

    let mut rig = fanned(Capture::Strict, 1 << 16);
    let push = |rig: &Fanned, id: u64, session: i32, available: bool| {
        rig.changes.lock().unwrap().push_back(ImageChange::new(
            id,
            session,
            lane_of(session),
            available,
        ));
    };
    push(&rig, 10, 1, true);
    push(&rig, 11, 3, true);
    for (image, payload) in [(0, b"a"), (1, b"b")] {
        let _ = rig.publications[image]
            .append(payload, AppendOptions::default())
            .unwrap();
    }
    let mut live = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| live.push(seen(event));
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(&mut handler) {}
    push(&rig, 10, 1, false);
    push(&rig, 12, 1, true);
    let _ = rig.publications[0]
        .append(b"c", AppendOptions::default())
        .unwrap();
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(&mut handler) {}
    // One source, live and in replay: the fan-in's every image is it.
    let expected = [
        ("available", 0),
        ("available", 0),
        ("message", 0),
        ("message", 0),
        ("unavailable", 0),
        ("available", 0),
        ("message", 0),
    ];
    assert_eq!(live, expected);
    let bytes = records(rig.job, &rig.disk);
    let recorded: Vec<(&str, i32)> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Lifecycle(event) => {
                assert_eq!(event.position, 0, "image events carry no position");
                assert_eq!(event.incarnation, IDENTITY.incarnation);
                Some((
                    if event.kind == LifecycleKind::ImageAvailable {
                        "available"
                    } else {
                        "unavailable"
                    },
                    event.session_id,
                ))
            }
            GroupRecord::Message(message) => Some(("message", message.session_id)),
            _ => None,
        })
        .collect();
    assert_eq!(
        recorded,
        [
            ("available", 1),
            ("available", 3),
            ("message", 1),
            ("message", 3),
            ("unavailable", 1),
            ("available", 1),
            ("message", 1)
        ]
    );
    // Replay: the network stream's one entry takes every session.
    let mut journal = GroupJournal::recover(rig.disk.clone(), Path::new("/g"), 1, journal_config())
        .unwrap()
        .journal;
    let recovery = recover(&mut journal, &NoRecordings, 64).unwrap();
    let cursor = ReplayCursor::open(
        journal,
        &recovery,
        &ReplayConfig {
            manifest: b"m",
            accept_manifest: false,
        },
        CursorConfig {
            bytes: 4 * MAX_RECORD,
            records: 8,
        },
    )
    .unwrap();
    let mut replay = ReplayGateway::new(
        cursor,
        &GatewayConfig {
            publications: &[],
            subscriptions: &[(2, 1, Lane::ZERO)],
            network: &[2],
            conflated: &[],
            max_claim: 0,
            max_payload: 0,
            present_unavailable: false,
        },
        None,
    )
    .unwrap();
    let mut replayed = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| replayed.push(seen(event));
    while let Ok(Dispatched::Event { .. }) = replay.dispatch(&mut handler) {}
    assert_eq!(replayed, expected);
}

/// Strict capture without room refuses an image event: it stays held and
/// goes first at the source's next turn, before the message waiting.
#[test]
fn a_refused_image_event_waits_for_the_next_turn() {
    let mut rig = fanned(Capture::Strict, 8 * 1024);
    let _ = rig.publications[0]
        .append(&[0u8; 600], AppendOptions::default())
        .unwrap();
    // Fill the ring with external events the job does not drain.
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    while rig.gateway.deliver_external(1, &[0u8; 600], noop).is_ok() {}
    rig.changes
        .lock()
        .unwrap()
        .push_back(ImageChange::new(10, 1, Lane::ZERO, true));
    let mut kinds = Vec::new();
    let refused = rig
        .gateway
        .dispatch(&mut |event: &Event<'_>, _: &mut dyn Effects| kinds.push(seen(event).0));
    assert!(
        matches!(refused, Err(GatewayError::Refused(_))),
        "{refused:?}"
    );
    assert!(kinds.is_empty(), "refused: not delivered");
    while rig.job.duty(0, 1024, &NoRecordings).unwrap() {}
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| kinds.push(seen(event).0);
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(&mut handler) {}
    assert_eq!(kinds, ["available", "message"]);
}

/// The placement's bounds, exactly: a payload of the inline threshold's
/// length stays inline though the word names a recording, and one of
/// `MAX_INLINE` bytes is recorded inline by strict capture.
#[test]
fn placement_bounds_are_exact() {
    let mut rig = rig(Capture::Strict, 1 << 20, 70_000, 1024 * 1024);
    append(&mut rig, &[9u8; 64]);
    append(&mut rig, &vec![5u8; MAX_INLINE]);
    rig.word.set(7, 0);
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    assert_eq!(
        rig.gateway.dispatch(noop),
        Ok(Dispatched::Event { group_seq: 1 })
    );
    rig.word.clear();
    assert_eq!(
        rig.gateway.dispatch(noop),
        Ok(Dispatched::Event { group_seq: 2 })
    );
    let bytes = records(rig.job, &rig.disk);
    let lengths: Vec<Option<usize>> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Message(message) => Some(match message.payload {
                Payload::Inline(bytes) => Some(bytes.len()),
                _ => None,
            }),
            _ => None,
        })
        .collect();
    assert_eq!(lengths, [Some(64), Some(MAX_INLINE)]);
}

/// A timer due exactly at the dispatch's read fires; of two due timers
/// the earlier deadline goes first.
#[test]
fn due_timers_fire_earliest_first_at_their_deadline() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    rig.gateway
        .deliver_external(1, b"", &mut |_: &Event<'_>, effects: &mut dyn Effects| {
            effects.schedule(TimerId(1), 1000);
            effects.schedule(TimerId(2), 800);
        })
        .unwrap();
    let mut fired = Vec::new();
    let mut handler = |event: &Event<'_>, effects: &mut dyn Effects| {
        if let Event::Timer { timer } = event {
            fired.push((*timer, effects.clock()));
        }
    };
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(&mut handler) {}
    assert_eq!(fired, [(TimerId(2), 800), (TimerId(1), 1000)]);
}

/// A view whose largest value is exactly `MAX_INLINE` is accepted.
#[test]
fn a_view_of_max_inline_values_is_accepted() {
    let mut rig = rig(Capture::Strict, 1 << 20, 70_000, 64 * 1024);
    let (_writer, view) = view(MAX_INLINE);
    assert!(rig.gateway.add_conflated(Box::new(view), 5, 1).is_ok());
}

/// A second source of the same stream, session and lane is refused:
/// replay names a source by all three. Another lane is another source.
#[test]
fn a_second_source_of_a_stream_session_and_lane_is_refused() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    let same = ClientSubscription::new(rig.conductor.subscribe(Role::Required).unwrap());
    assert_eq!(
        rig.gateway
            .add_subscription(Box::new(same), IDENTITY, Arc::new(RecordingWord::new())),
        Err(GatewayError::DuplicateSource {
            stream_id: 2,
            session_id: 1,
            lane: Lane::ZERO,
        })
    );
    // Another lane: a lane-1 buffer of the same stream and session.
    let lane_one = Lane::try_new(1).unwrap();
    let buffer = log_of(1, lane_one, 64 * 1024);
    let mut conductor = buffer.conductor_owned().unwrap();
    let other = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let other_lane = SourceIdentity {
        lane: lane_one,
        ..IDENTITY
    };
    assert!(
        rig.gateway
            .add_subscription(Box::new(other), other_lane, Arc::new(RecordingWord::new()))
            .is_ok()
    );
    drop(conductor);
}

/// Strict capture reads an optional or observer source only when it can
/// record what it reads: such a reader acknowledges on copy, so a message
/// read and then refused would be lost without trace. With the ring full
/// nothing is read, and every message comes once there is room.
#[test]
fn strict_reads_an_optional_source_only_with_room() {
    for role in [Role::Optional, Role::Observer] {
        let mut rig = rig_as(role, Capture::Strict, 8 * 1024, 1000, 64 * 1024);
        for index in 0..12u8 {
            append(&mut rig, &[index; 600]);
        }
        let seen = std::cell::RefCell::new(Vec::new());
        let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
            if let Event::Message {
                payload: MessagePayload::Bytes(bytes),
                ..
            } = event
            {
                seen.borrow_mut().push(bytes[0]);
            }
        };
        let mut job = rig.job;
        let mut refused = 0;
        while seen.borrow().len() < 12 {
            match rig.gateway.dispatch(&mut handler) {
                Ok(Dispatched::Event { .. }) => {}
                Err(GatewayError::Refused(Refusal::RingFull | Refusal::InFlight)) => {
                    refused += 1;
                    while job.duty(0, 1024, &NoRecordings).unwrap() {}
                }
                other => panic!("{role:?}: {other:?} after {:?}", seen.borrow()),
            }
            assert!(refused < 100, "{role:?}: no progress");
        }
        assert!(refused > 0, "{role:?}: the ring never filled");
        assert_eq!(*seen.borrow(), (0..12).collect::<Vec<u8>>(), "{role:?}");
    }
}

/// A message source that reports one scripted poll summary, then nothing.
struct Scripted(Option<karyos_client::PollSummary>);

impl MessageSource for Scripted {
    fn poll_taking(
        &mut self,
        _: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        _: MessageLimit,
    ) -> Result<karyos_client::PollSummary, karyos_client::PollError> {
        Ok(self.0.take().unwrap_or_default())
    }
}

/// The loss events a scripted source's summary makes, as recorded.
fn scripted_losses(summary: karyos_client::PollSummary) -> Vec<(u64, u64, u64, Loss)> {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    let identity = SourceIdentity {
        stream_id: 9,
        ..IDENTITY
    };
    let _ = rig
        .gateway
        .add_subscription(
            Box::new(Scripted(Some(summary))),
            identity,
            Arc::new(RecordingWord::new()),
        )
        .unwrap();
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(noop) {}
    let bytes = records(rig.job, &rig.disk);
    decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Loss(loss) => Some((loss.from, loss.lost_to, loss.resume, loss.loss)),
            _ => None,
        })
        .collect()
}

/// An overrun is a loss event with its three positions, each its own, and
/// its rejoin outcome.
#[test]
fn an_overrun_is_a_loss_event_with_its_positions() {
    let summary = {
        let mut value = karyos_client::PollSummary::default();
        value.overrun = Some(karyos_client::Overrun::new(100, 200, 300));
        value.rejoin = Some(RejoinOutcome::ResumedAtHead);
        value
    };
    assert_eq!(
        scripted_losses(summary),
        [(
            100,
            200,
            300,
            Loss::Overrun {
                outcome: OverrunOutcome::ResumedAtHead,
                fallback: None
            }
        )]
    );
}

/// A skipped range is a loss event from its position to its end, where
/// delivery resumes, with its reason.
#[test]
fn a_skipped_range_is_a_loss_event() {
    let summary = {
        let mut value = karyos_client::PollSummary::default();
        value.skipped = Some(karyos_client::Skipped::new(
            64,
            32,
            karyos_sys::log_buffer::SkipReason::MissingEnd,
        ));
        value
    };
    assert_eq!(
        scripted_losses(summary),
        [(
            64,
            96,
            96,
            Loss::Skipped(karyos_sys::log_buffer::SkipReason::MissingEnd)
        )]
    );
}

/// A due timer strict capture refuses stays due, at its deadline, and
/// fires once there is room.
#[test]
fn a_refused_timer_stays_due() {
    let mut rig = rig(Capture::Strict, 8 * 1024, 1000, 64 * 1024);
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    rig.gateway
        .deliver_external(1, b"", &mut |_: &Event<'_>, effects: &mut dyn Effects| {
            effects.schedule(TimerId(2), 900);
        })
        .unwrap();
    while let Ok(Dispatched::Event { .. }) = rig.gateway.deliver_external(1, &[0u8; 600], noop) {}
    let mut fired = Vec::new();
    let mut handler = |event: &Event<'_>, effects: &mut dyn Effects| {
        if let Event::Timer { timer } = event {
            fired.push((*timer, effects.clock()));
        }
    };
    assert_eq!(
        rig.gateway.dispatch(&mut handler),
        Err(GatewayError::Refused(Refusal::RingFull))
    );
    let mut job = rig.job;
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    assert!(matches!(
        rig.gateway.dispatch(&mut handler),
        Ok(Dispatched::Event { .. })
    ));
    assert_eq!(fired, [(TimerId(2), 900)]);
}

/// A seal with no cause ends the source as its stream's end; a seal with
/// a cause closes it.
#[test]
fn a_seal_reason_names_the_end() {
    for (reason, expected) in [
        (None, EndReason::EndOfStream),
        (
            Some(karyos_sys::log_buffer::SealReason::Unspecified),
            EndReason::EndOfStream,
        ),
        (
            Some(karyos_sys::log_buffer::SealReason::StreamRemoved),
            EndReason::Closed,
        ),
    ] {
        let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
        let summary = {
            let mut value = karyos_client::PollSummary::default();
            value.closed = Some(640);
            value.close_reason = reason;
            value
        };
        let _ = rig
            .gateway
            .add_subscription(
                Box::new(Scripted(Some(summary))),
                SourceIdentity {
                    stream_id: 9,
                    ..IDENTITY
                },
                Arc::new(RecordingWord::new()),
            )
            .unwrap();
        let mut ends = Vec::new();
        let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
            if let Event::Lifecycle { kind, .. } = event {
                ends.push(*kind);
            }
        };
        while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(&mut handler) {}
        assert_eq!(
            ends,
            [LifecycleKind::SubscriptionEnded(expected)],
            "{reason:?}"
        );
    }
}

/// A view whose largest value makes an event of exactly the byte budget is
/// accepted; one byte more is refused.
#[test]
fn a_view_at_the_event_budget_is_accepted() {
    let budget = 512;
    let rig_budget = || rig(Capture::Strict, 1 << 16, budget, 64 * 1024);
    let head =
        usize::from(CONFLATED_EVENT.block_length) + 12 + 2 + crate::group::gateway::live::END;
    let fits = budget - head;
    let (_writer, at) = view(fits);
    assert!(
        rig_budget()
            .gateway
            .add_conflated(Box::new(at), 5, 1)
            .is_ok()
    );
    let (_writer, over) = view(fits + 1);
    assert_eq!(
        rig_budget().gateway.add_conflated(Box::new(over), 5, 1),
        Err(GatewayError::TooLarge(fits + 1))
    );
}

/// #445 review P1-a: the recording word names the source's own session's
/// recording; a large message of another image is placed as without a
/// word (inline), the source's own by reference.
#[test]
fn only_the_words_session_is_placed_by_reference() {
    let mut rig = fanned(Capture::BestEffort, 1 << 16);
    rig.word.set(7, 0);
    for image in [0, 1] {
        let _ = rig.publications[image]
            .append(
                &[u8::try_from(image).unwrap(); 100],
                AppendOptions::default(),
            )
            .unwrap();
    }
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(noop) {}
    let bytes = records(rig.job, &rig.disk);
    let placed: Vec<(i32, bool)> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Message(message) => Some((
                message.session_id,
                matches!(message.payload, Payload::Reference { .. }),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(placed, [(1, true), (3, false)]);
}

/// #445 review P2: a loss an image reports is recorded in that image's
/// session.
#[test]
fn an_image_loss_is_in_its_session() {
    let mut rig = fanned(Capture::Strict, 1 << 16);
    let ClaimOutcome::Claimed(claim) = rig.publications[1]
        .try_claim(40, AppendOptions::default())
        .unwrap()
    else {
        panic!("not claimed");
    };
    claim.abort();
    let _ = rig.publications[1]
        .append(b"after", AppendOptions::default())
        .unwrap();
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(noop) {}
    let bytes = records(rig.job, &rig.disk);
    let losses: Vec<i32> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Loss(loss) => Some(loss.session_id),
            _ => None,
        })
        .collect();
    assert_eq!(losses, [3]);
}

/// #445 review P1-b: a network subscription is its stream's only source.
#[test]
fn a_fan_in_is_its_streams_only_source() {
    let mut rig = fanned(Capture::Strict, 1 << 16);
    let buffer = log_of(5, Lane::ZERO, 64 * 1024);
    let mut conductor = buffer.conductor_owned().unwrap();
    let other = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let identity = SourceIdentity {
        session_id: 5,
        ..IDENTITY
    };
    assert!(matches!(
        rig.gateway
            .add_subscription(Box::new(other), identity, Arc::new(RecordingWord::new())),
        Err(GatewayError::DuplicateSource { stream_id: 2, .. })
    ));
}

/// The strict end at a payload that cannot be recorded: live and replay
/// present the same loss, with every call refused.
#[test]
fn the_strict_end_replays_as_it_was_captured() {
    use crate::group::prefix::recover;
    use crate::group::replay::gateway::{GatewayConfig, ReplayGateway};
    use crate::group::replay::{CursorConfig, ReplayConfig, ReplayCursor};
    let mut rig = rig(Capture::Strict, 1 << 20, 4096, 1024 * 1024);
    append(&mut rig, &vec![5u8; MAX_INLINE + 1]);
    struct Seen(Vec<(String, Outcome)>);
    impl Handler for Seen {
        fn on_event(&mut self, event: &Event<'_>, effects: &mut dyn Effects) {
            self.0
                .push((format!("{event:?}"), effects.offer(PublicationId(1), b"p")));
        }
    }
    let mut live = Seen(Vec::new());
    let _ = rig.gateway.dispatch(&mut live).unwrap();
    let live = live.0;
    let mut job = rig.job;
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    job.close().unwrap();
    let mut journal = GroupJournal::recover(
        rig.disk.clone(),
        Path::new("/g"),
        1,
        JournalConfig {
            segment_length: MIN_SEGMENT_LENGTH,
            policy: SyncPolicy::Every {
                interval_ns: u64::MAX,
            },
        },
    )
    .unwrap()
    .journal;
    let recovery = recover(&mut journal, &NoRecordings, 8).unwrap();
    let cursor = ReplayCursor::open(
        journal,
        &recovery,
        &ReplayConfig {
            manifest: b"m",
            accept_manifest: false,
        },
        CursorConfig {
            bytes: 4096,
            records: 8,
        },
    )
    .unwrap();
    let mut replay = ReplayGateway::new(
        cursor,
        &GatewayConfig {
            publications: &[(1, 1)],
            subscriptions: &[(2, 1, Lane::ZERO)],
            network: &[],
            conflated: &[],
            max_claim: 64,
            max_payload: 0,
            present_unavailable: false,
        },
        None,
    )
    .unwrap();
    let mut replayed = Seen(Vec::new());
    while let Ok(Dispatched::Event { .. }) = replay.dispatch(&mut replayed) {}
    let replayed = replayed.0;
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].1, Outcome::Gated);
    assert_eq!(replayed, live);
}

/// A second view of one stream and session is refused: replay names a
/// view by the pair.
#[test]
fn a_second_view_of_a_stream_and_session_is_refused() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    let (_first, one) = view(64);
    let (_second, two) = view(64);
    rig.gateway.add_conflated(Box::new(one), 5, 1).unwrap();
    assert_eq!(
        rig.gateway.add_conflated(Box::new(two), 5, 1),
        Err(GatewayError::DuplicateSource {
            stream_id: 5,
            session_id: 1,
            lane: Lane::ZERO,
        })
    );
}

/// A view alone, with the ring full: strict reads none of its values and
/// refuses the dispatch; once there is room the value comes, once.
#[test]
fn strict_reads_a_view_only_with_room() {
    let mut rig = rig(Capture::Strict, 8 * 1024, 1000, 64 * 1024);
    // Only the view: the message source ended, polled no more.
    rig.gateway.sources[0].ended = true;
    let (mut writer, view) = view(64);
    rig.gateway.add_conflated(Box::new(view), 5, 1).unwrap();
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    while let Ok(Dispatched::Event { .. }) = rig.gateway.deliver_external(1, &[0u8; 600], noop) {}
    writer.write(1, b"kept").unwrap();
    let mut seen = 0;
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if matches!(event, Event::Conflated { .. }) {
            seen += 1;
        }
    };
    assert_eq!(
        rig.gateway.dispatch(&mut handler),
        Err(GatewayError::Refused(Refusal::RingFull))
    );
    let mut job = rig.job;
    while job.duty(0, 1024, &NoRecordings).unwrap() {}
    assert!(matches!(
        rig.gateway.dispatch(&mut handler),
        Ok(Dispatched::Event { .. })
    ));
    assert_eq!(rig.gateway.dispatch(&mut handler), Ok(Dispatched::Idle));
    assert_eq!(seen, 1);
}

/// Replays the journal on `disk` with `subscriptions`, giving each
/// event's kind and source.
fn replayed(
    disk: &FaultDisk,
    subscriptions: &[(i32, i32, Lane)],
    network: &[i32],
) -> Vec<(&'static str, u16)> {
    use crate::group::prefix::recover;
    use crate::group::replay::gateway::{GatewayConfig, ReplayGateway};
    use crate::group::replay::{CursorConfig, ReplayConfig, ReplayCursor};

    let mut journal = GroupJournal::recover(disk.clone(), Path::new("/g"), 1, journal_config())
        .unwrap()
        .journal;
    let recovery = recover(&mut journal, &NoRecordings, 64).unwrap();
    let cursor = ReplayCursor::open(
        journal,
        &recovery,
        &ReplayConfig {
            manifest: b"m",
            accept_manifest: false,
        },
        CursorConfig {
            bytes: 4 * MAX_RECORD,
            records: 8,
        },
    )
    .unwrap();
    let mut replay = ReplayGateway::new(
        cursor,
        &GatewayConfig {
            publications: &[],
            subscriptions,
            network,
            conflated: &[],
            max_claim: 0,
            max_payload: 0,
            present_unavailable: false,
        },
        None,
    )
    .unwrap();
    let mut seen_events = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| seen_events.push(seen(event));
    while let Ok(Dispatched::Event { .. }) = replay.dispatch(&mut handler) {}
    seen_events
}

/// Lanes in replay keys: two subscriptions of one stream and session,
/// on lanes 0 and 1, are two sources, live and in replay; their messages
/// are recorded on their lanes.
#[test]
fn two_lanes_of_a_session_are_two_sources() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    let lane_one = Lane::try_new(1).unwrap();
    let buffer = log_of(1, lane_one, 64 * 1024);
    let mut conductor = buffer.conductor_owned().unwrap();
    let second = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let mut publication = buffer.publication_owned().unwrap().unwrap();
    let id = rig
        .gateway
        .add_subscription(
            Box::new(second),
            SourceIdentity {
                lane: lane_one,
                ..IDENTITY
            },
            Arc::new(RecordingWord::new()),
        )
        .unwrap();
    assert_eq!(id, SubscriptionId(1));
    append(&mut rig, b"zero");
    let _ = publication
        .append(b"one", AppendOptions::default())
        .unwrap();
    let mut live = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| live.push(seen(event));
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(&mut handler) {}
    assert_eq!(live, [("message", 0), ("message", 1)]);
    let disk = rig.disk.clone();
    let bytes = records(rig.job, &rig.disk);
    let lanes: Vec<u8> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Message(message) => Some(message.lane.get()),
            _ => None,
        })
        .collect();
    assert_eq!(lanes, [0, 1]);
    let subscriptions = [(2, 1, Lane::ZERO), (2, 1, lane_one)];
    assert_eq!(replayed(&disk, &subscriptions, &[]), live);
    drop(conductor);
}

/// A network subscription's image on lane 1: its message and its
/// lifecycle event are recorded on lane 1, not the source's.
#[test]
fn a_fan_in_image_is_recorded_on_its_lane() {
    let mut rig = fanned(Capture::Strict, 1 << 16);
    rig.changes
        .lock()
        .unwrap()
        .push_back(ImageChange::new(11, 3, lane_of(3), true));
    let _ = rig.publications[1]
        .append(b"b", AppendOptions::default())
        .unwrap();
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    while let Ok(Dispatched::Event { .. }) = rig.gateway.dispatch(noop) {}
    let bytes = records(rig.job, &rig.disk);
    let lanes: Vec<(&str, u8)> = decoded(&bytes)
        .into_iter()
        .filter_map(|record| match record {
            GroupRecord::Message(message) => Some(("message", message.lane.get())),
            GroupRecord::Lifecycle(event) => Some(("lifecycle", event.lane.get())),
            _ => None,
        })
        .collect();
    assert_eq!(lanes, [("lifecycle", 1), ("message", 1)]);
}

/// #450 review P2: a source added under an identity naming another lane
/// than the one it reads is refused, typed: its messages would be
/// recorded on its own lane and replayed as another source's.
#[test]
fn a_source_under_another_lane_is_refused() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    let lane_one = Lane::try_new(1).unwrap();
    // A lane-0 buffer of the same stream and session, named lane 1.
    let buffer = log_of(1, Lane::ZERO, 64 * 1024);
    let mut conductor = buffer.conductor_owned().unwrap();
    let second = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    assert_eq!(
        rig.gateway.add_subscription(
            Box::new(second),
            SourceIdentity {
                lane: lane_one,
                ..IDENTITY
            },
            Arc::new(RecordingWord::new()),
        ),
        Err(GatewayError::WrongLane {
            named: lane_one,
            read: Lane::ZERO,
        })
    );
    drop(conductor);
}

/// A message source whose every poll fails, counting its polls.
struct Failing(Arc<std::sync::atomic::AtomicU32>);

impl MessageSource for Failing {
    fn poll_taking(
        &mut self,
        _: &mut dyn FnMut(&[u8], MessageInfo) -> bool,
        _: MessageLimit,
    ) -> Result<karyos_client::PollSummary, karyos_client::PollError> {
        let _ = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(karyos_client::PollError::new(
            karyos_client::PollSummary::default(),
            karyos_client::ClientError::OutcomesLost,
        ))
    }
}

/// A poll that fails ends its source as closed, at the summary's seal or
/// else 0, and the source is not polled again.
#[test]
fn a_failed_poll_ends_its_source() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    rig.gateway.sources[0].ended = true;
    let polls = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let _ = rig
        .gateway
        .add_subscription(
            Box::new(Failing(Arc::clone(&polls))),
            SourceIdentity {
                stream_id: 9,
                ..IDENTITY
            },
            Arc::new(RecordingWord::new()),
        )
        .unwrap();
    let mut kinds = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if let Event::Lifecycle { kind, .. } = event {
            kinds.push(*kind);
        }
    };
    for _ in 0..4 {
        let _ = rig.gateway.dispatch(&mut handler);
    }
    assert_eq!(kinds, [LifecycleKind::SubscriptionEnded(EndReason::Closed)]);
    assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 1);
    let bytes = records(rig.job, &rig.disk);
    assert!(decoded(&bytes).iter().any(|record| matches!(
        record,
        GroupRecord::Lifecycle(LifecycleEvent {
            position: 0,
            kind: LifecycleKind::SubscriptionEnded(EndReason::Closed),
            ..
        })
    )));
}

/// A view whose poll fails is closed: it is not polled again.
struct ClosedView(Arc<std::sync::atomic::AtomicU32>);

impl ConflatedSource for ClosedView {
    fn config(&self) -> karyos_sys::conflation::ConflationConfig {
        let (_writer, view) = view(64);
        ConflatedSource::config(&view)
    }

    fn poll_one(&mut self, _: &mut ValueHandler<'_>) -> Result<u32, karyos_client::ClientError> {
        let _ = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(karyos_client::ClientError::OutcomesLost)
    }
}

#[test]
fn a_closed_view_is_not_polled_again() {
    let mut rig = rig(Capture::Strict, 1 << 16, 4096, 64 * 1024);
    rig.gateway.sources[0].ended = true;
    let polls = Arc::new(std::sync::atomic::AtomicU32::new(0));
    rig.gateway
        .add_conflated(Box::new(ClosedView(Arc::clone(&polls))), 5, 1)
        .unwrap();
    let noop = &mut |_: &Event<'_>, _: &mut dyn Effects| {};
    for _ in 0..4 {
        assert_eq!(rig.gateway.dispatch(noop), Ok(Dispatched::Idle));
    }
    assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 1);
}

/// The message size the Gateway computes is the encoded record's, with
/// and without an extension, for inline payloads and a reference.
#[test]
fn the_message_size_is_the_records() {
    let mut out = vec![0u8; MAX_RECORD];
    for (payload, extension) in [
        (Payload::Inline(&[]), None),
        (Payload::Inline(&[7u8; 300]), Some([1u8; EXTENSION])),
        (
            Payload::Reference {
                recording_id: 3,
                length: 70_000,
            },
            Some([1u8; EXTENSION]),
        ),
    ] {
        let (inline, length) = match payload {
            Payload::Inline(bytes) => (bytes.len(), bytes.len()),
            Payload::Reference { length, .. } | Payload::Unavailable { length } => {
                (0, usize::try_from(length).unwrap())
            }
        };
        // Its frames: the payload behind a 32-byte header, aligned to 32.
        let extent = u32::try_from((length + 32).div_ceil(32) * 32).unwrap();
        let encoded = GroupRecord::Message(MessageEvent {
            group_seq: 1,
            logical_time: 0,
            incarnation: 1,
            position: 0,
            extent,
            stream_id: 2,
            session_id: 1,
            lane: Lane::ZERO,
            reserved_value: 0,
            end_of_stream: false,
            extension: extension.as_ref(),
            payload,
        })
        .encode(&mut out)
        .unwrap();
        assert_eq!(message_size(inline, extension.is_some()), Some(encoded));
    }
}

/// Best effort, the group closed while the handler runs (a concurrent
/// stop): the event cannot be sent, but the handler saw the message, so it
/// is taken and never delivered again (REVIEWER-01's probe, #447).
#[test]
fn a_close_during_a_dispatch_delivers_once() {
    let rig = rig(Capture::BestEffort, 1 << 16, 4096, 64 * 1024);
    let Rig {
        mut gateway,
        job,
        mut publication,
        ..
    } = rig;
    let _ = publication
        .append(b"only", karyos_sys::log_buffer::AppendOptions::default())
        .unwrap();
    let job = std::cell::RefCell::new(job);
    let mut seen = Vec::new();
    let mut handler = |event: &Event<'_>, _: &mut dyn Effects| {
        if let Event::Message { position, .. } = event {
            seen.push(*position);
            job.borrow_mut().drain_to_close(0, &NoRecordings).unwrap();
        }
    };
    let mut outcomes = Vec::new();
    for _ in 0..4 {
        outcomes.push(gateway.dispatch(&mut handler));
    }
    drop(handler);
    assert_eq!(seen.len(), 1, "{seen:?}; {outcomes:?}");
    assert_eq!(outcomes[0], Err(GatewayError::Ended));
}

/// A message whose record and end exactly fill the event buffer fits, and
/// strict capture records it; one byte less ends the journal at it.
#[test]
fn a_message_that_exactly_fills_the_buffer_fits() {
    let payload = 600;
    let exact = message_size(payload, false).unwrap() + crate::group::gateway::live::END;
    for (max_event, delivered) in [(exact, true), (exact - 1, false)] {
        let mut rig = rig(Capture::Strict, 1 << 16, max_event, 64 * 1024);
        append(&mut rig, &vec![3u8; payload]);
        let mut message = None;
        let result = rig
            .gateway
            .dispatch(&mut |event: &Event<'_>, _: &mut dyn Effects| {
                message = Some(matches!(event, Event::Message { .. }));
            });
        assert_eq!(
            result,
            Ok(Dispatched::Event { group_seq: 1 }),
            "{max_event}"
        );
        assert_eq!(message, Some(delivered), "{max_event}");
    }
}
