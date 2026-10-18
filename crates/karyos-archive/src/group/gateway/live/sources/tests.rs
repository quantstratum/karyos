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

use karyos_client::ClientSubscription;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, ClaimOutcome, Conductor, LogBuffer, LogBufferConfig, Publication, Role,
};
use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
use karyos_sys::term::TermId;

use super::*;
use crate::fault::FaultDisk;
use crate::group::capture::{CaptureConfig, CaptureJob, capture};
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
            spare_slots: 2,
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
    let disk = FaultDisk::default();
    let header = JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 64,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: mode,
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
    let subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
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

/// A payload above `MAX_INLINE` with no recording: strict declines it,
/// best effort records it with payload unavailable.
#[test]
fn a_payload_past_max_inline_is_unavailable() {
    for mode in [Capture::Strict, Capture::BestEffort] {
        let mut rig = rig(mode, 1 << 20, 4096, 1024 * 1024);
        append(&mut rig, &vec![5u8; MAX_INLINE + 1]);
        let mut ran = false;
        let result = rig
            .gateway
            .dispatch(&mut |_: &Event<'_>, _: &mut dyn Effects| ran = true);
        match mode {
            Capture::Strict => {
                assert_eq!(result, Err(GatewayError::Refused(Refusal::TooLarge)));
                assert!(!ran);
            }
            Capture::BestEffort => {
                assert_eq!(result, Ok(Dispatched::Event { group_seq: 1 }));
                assert!(ran);
                let bytes = records(rig.job, &rig.disk);
                assert!(decoded(&bytes).iter().any(|record| matches!(
                    record,
                    GroupRecord::Message(MessageEvent {
                        payload: Payload::Unavailable { .. },
                        ..
                    })
                )));
            }
        }
    }
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
