// SPDX-License-Identifier: Apache-2.0

//! The live Gateway allocates nothing per event once configured
//! (recording-group-gateway.md section 2): a dispatch that takes a
//! message, one that fires a timer, an external event and the effects a
//! handler calls, over a counting global allocator.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::sync::Arc;

use karyos_archive::disk::StdDisk;
use karyos_archive::group::capture::{CaptureConfig, capture};
use karyos_archive::group::gateway::live::{Gateway, Port, RecordingWord, SourceIdentity};
use karyos_archive::group::gateway::{
    ClaimCommit, DeliveryOutcome, Dispatched, Effects, Event, GroupGateway, PublicationId, TimerId,
};
use karyos_archive::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use karyos_archive::group::prefix::Coverage;
use karyos_archive::group::record::{Capture, Clock, JournalHeader, Outcome};
use karyos_archive::segment::SyncPolicy;
use karyos_client::ClientSubscription;
use karyos_sys::alloc_count::{CountingAllocator, count};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{AppendOptions, LogBuffer, LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Nothing;

impl Coverage for Nothing {
    fn positions(&self, _: u64) -> Option<(u64, u64)> {
        None
    }
    fn ended(&self, _: u64) -> Option<u64> {
        None
    }
}

/// Accepts every call, allocating nothing.
struct Accepting;

impl Port for Accepting {
    fn publication(&self, _: PublicationId) -> (i32, i32) {
        (1, 1)
    }
    fn offer(&mut self, _: PublicationId, _: &[u8]) -> Outcome {
        Outcome::BackPressured
    }
    fn claim(
        &mut self,
        _: PublicationId,
        _: usize,
        write: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> ClaimCommit {
        let mut bytes = [0u8; 16];
        let commit = write(&mut bytes);
        ClaimCommit::new(
            Outcome::Accepted {
                lane: Lane::ZERO,
                position: 0,
            },
            Some(if commit {
                Outcome::Accepted {
                    lane: Lane::ZERO,
                    position: 0,
                }
            } else {
                Outcome::Aborted {
                    lane: Lane::ZERO,
                    position: 0,
                }
            }),
        )
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

#[test]
fn a_gateway_allocates_nothing_per_event() {
    let dir = std::env::temp_dir().join(format!("karyos-gateway-alloc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let header = JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 64,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        reopen_hold: 0,
        manifest: b"m",
    };
    let config = JournalConfig::new(MIN_SEGMENT_LENGTH, SyncPolicy::PerSegment);
    let journal = GroupJournal::create(StdDisk, &dir, &header, config).unwrap();
    let (sender, mut job) =
        capture(CaptureConfig::new(1 << 16, 4096, 64), journal, &Nothing).unwrap();
    let mut clock = 0u64;
    let mut gateway = Gateway::new(
        Accepting,
        move || {
            clock += 10;
            clock
        },
        sender,
        Capture::Strict,
        1,
        4096,
        8,
    )
    .unwrap();
    let buffer = Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 2,
            max_subscribers: 2,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
        })
        .unwrap(),
    );
    let mut conductor = buffer.conductor_owned().unwrap();
    let subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let mut publication = buffer.publication_owned().unwrap().unwrap();
    let word = Arc::new(RecordingWord::new());
    word.set(9, 0);
    let identity = SourceIdentity::new(1, 2, 1, Lane::ZERO);
    let _ = gateway
        .add_subscription(Box::new(subscription), identity, word)
        .unwrap();
    for payload in [&[1u8; 8][..], &[2u8; 200][..], &[3u8; 8][..]] {
        let _ = publication
            .append(payload, AppendOptions::default())
            .unwrap();
    }
    let mut handler = |_: &Event<'_>, effects: &mut dyn Effects| {
        let _ = effects.offer(PublicationId(1), b"out");
        let _ = effects.claim(PublicationId(1), 8, &mut |bytes| {
            bytes.fill(4);
            true
        });
        effects.schedule(TimerId(1), effects.clock() + 5);
        let _ = effects.external(2, &mut |out| {
            out[0] = 1;
            1
        });
    };
    let mut events = 0;
    for _ in 0..8 {
        let (dispatched, allocations) = count(|| gateway.dispatch(&mut handler));
        assert_eq!(allocations, 0, "a dispatch allocated: {dispatched:?}");
        if matches!(dispatched, Ok(Dispatched::Event { .. })) {
            events += 1;
        }
        // The Archive's side runs elsewhere; its allocations do not count.
        while job.duty(0, 64, &Nothing).unwrap() {}
    }
    let (external, allocations) = count(|| gateway.deliver_external(1, b"in", &mut handler));
    assert_eq!(allocations, 0, "an external event allocated");
    assert!(matches!(external, Ok(Dispatched::Event { .. })));
    // Three messages (inline, by reference, inline) and the timers fired.
    assert!(events >= 3, "{events}");
    let _ = job.close().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Reports a fixed sequence of poll summaries, then nothing: allocates
/// nothing.
struct Reports {
    summaries: [Option<karyos_client::PollSummary>; 4],
    next: usize,
}

impl karyos_archive::group::gateway::live::MessageSource for Reports {
    fn poll_taking(
        &mut self,
        _: &mut dyn FnMut(&[u8], karyos_client::MessageInfo) -> bool,
        _: karyos_client::MessageLimit,
    ) -> Result<karyos_client::PollSummary, karyos_client::PollError> {
        let summary = self
            .summaries
            .get_mut(self.next)
            .and_then(Option::take)
            .unwrap_or_default();
        self.next += 1;
        Ok(summary)
    }
}

/// An overrun, a skip, an abort, an end and a conflated value each
/// dispatch without allocating.
#[test]
fn reports_and_values_dispatch_without_allocating() {
    use karyos_client::{Aborted, Overrun, PollSummary, RejoinOutcome, Skipped};
    let dir = std::env::temp_dir().join(format!(
        "karyos-gateway-alloc-reports-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let header = JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 64,
        contract_version: 1,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        reopen_hold: 0,
        manifest: b"m",
    };
    let config = JournalConfig::new(MIN_SEGMENT_LENGTH, SyncPolicy::PerSegment);
    let journal = GroupJournal::create(StdDisk, &dir, &header, config).unwrap();
    let (sender, mut job) =
        capture(CaptureConfig::new(1 << 16, 4096, 64), journal, &Nothing).unwrap();
    let mut gateway = Gateway::new(Accepting, || 10, sender, Capture::Strict, 1, 4096, 8).unwrap();
    let reports = Reports {
        summaries: [
            Some({
                let mut value = PollSummary::default();
                value.overrun = Some(Overrun::new(64, 128, 192));
                value.rejoin = Some(RejoinOutcome::ResumedAtHead);
                value
            }),
            Some({
                let mut value = PollSummary::default();
                value.skipped = Some(Skipped::new(
                    192,
                    32,
                    karyos_sys::log_buffer::SkipReason::MissingEnd,
                ));
                value
            }),
            Some({
                let mut value = PollSummary::default();
                value.aborted = Some(Aborted::new(224, 32));
                value
            }),
            Some({
                let mut value = PollSummary::default();
                value.closed = Some(256);
                value
            }),
        ],
        next: 0,
    };
    let identity = SourceIdentity::new(1, 2, 1, Lane::ZERO);
    let _ = gateway
        .add_subscription(Box::new(reports), identity, Arc::new(RecordingWord::new()))
        .unwrap();
    let writer = karyos_sys::conflation::conflation(4, 64, 4096).unwrap();
    let view = karyos_client::ConflatedSubscription::new(
        writer.reader(),
        karyos_sys::conflation::Budget::new(4, 4),
    );
    let mut writer = writer;
    let _ = gateway.add_conflated(Box::new(view), 5, 1).unwrap();
    writer.write(1, b"value").unwrap();
    let mut handler = |_: &Event<'_>, _: &mut dyn Effects| {};
    let mut events = 0;
    for _ in 0..8 {
        let (dispatched, allocations) = count(|| gateway.dispatch(&mut handler));
        assert_eq!(allocations, 0, "a dispatch allocated: {dispatched:?}");
        if matches!(dispatched, Ok(Dispatched::Event { .. })) {
            events += 1;
        }
        while job.duty(0, 64, &Nothing).unwrap() {}
    }
    // The overrun, the skip, the abort, the end and the value.
    assert_eq!(events, 5);
    let _ = job.close().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
