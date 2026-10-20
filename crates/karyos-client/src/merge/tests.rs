// SPDX-License-Identifier: Apache-2.0

//! The merge over two log buffers holding the same messages at the same
//! positions, one read as the replay and one as the live stream: a poll
//! allocates nothing, nor frees, but the cutover's, which frees the
//! replay.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::sync::Arc;

use karyos_sys::log_buffer::{AppendOptions, LogBuffer, LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;

fn buffer() -> Arc<LogBuffer> {
    buffer_of(MIN_TERM_LENGTH)
}

/// A buffer of terms of `term_length`, reserving up to an eighth of one:
/// its largest message grows with it.
fn buffer_of(term_length: u32) -> Arc<LogBuffer> {
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

/// Appends messages `from..to`, each holding its index.
fn append(
    publication: &mut karyos_sys::log_buffer::Publication<Arc<LogBuffer>>,
    from: u32,
    to: u32,
) {
    for index in from..to {
        let mut message = [0u8; 100];
        message[..4].copy_from_slice(&index.to_le_bytes());
        let _ = publication
            .append(&message, AppendOptions::default())
            .unwrap();
    }
}

/// Every poll of a merge, on the replay and on the live reader, neither
/// allocates nor frees; the cutover's frees exactly what dropping a replay
/// frees.
#[test]
fn a_merge_poll_does_not_allocate() {
    let (replayed, live) = (buffer(), buffer());
    let mut conductor = replayed.conductor_owned().unwrap();
    let replay = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let mut replayed_publication = replayed.publication_owned().unwrap().unwrap();
    let mut live_publication = live.publication_owned().unwrap().unwrap();
    append(&mut replayed_publication, 0, 30);
    append(&mut live_publication, 0, 20);
    let reader = ClientSubscription::new(
        live.conductor_owned()
            .unwrap()
            .subscribe(Role::Required)
            .unwrap(),
    );
    append(&mut live_publication, 20, 30);
    let source = PublicationIdentity::default();
    // What dropping a replay costs, on a reader of the same buffer.
    let other = Box::new(Replay::new(
        ClientSubscription::new(conductor.subscribe(Role::Required).unwrap()),
        source,
    ));
    let ((), dropping) = karyos_sys::alloc_count::count(|| drop(other));
    let mut merge = LiveMerge::new(reader, source, Box::new(Replay::new(replay, source)));
    let mut seen = Vec::with_capacity(64);
    let mut cutovers = 0;
    for _ in 0..16 {
        let (polled, operations) = karyos_sys::alloc_count::count(|| {
            merge
                .poll(
                    |bytes, _| seen.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                    MessageLimit::new(4),
                )
                .ok()
        });
        if polled.unwrap().cutover.is_some() {
            cutovers += 1;
            assert_eq!(
                operations, dropping,
                "the cutover did more than free the replay"
            );
        } else {
            assert_eq!(operations, 0, "a poll allocated or freed");
        }
    }
    assert_eq!(seen, (0..30).collect::<Vec<_>>());
    assert_eq!(cutovers, 1);
}

/// A provider's reason is the fallback's reason, one for one.
#[test]
fn a_provider_reason_is_the_fallback_reason() {
    for (unavailable, reason) in [
        (
            ReplayUnavailable::NoRecording,
            ReplayFallbackReason::NoRecording,
        ),
        (
            ReplayUnavailable::RetentionShort,
            ReplayFallbackReason::RetentionShort,
        ),
        (
            ReplayUnavailable::RecordingBehind,
            ReplayFallbackReason::RecordingBehind,
        ),
        (ReplayUnavailable::Refused, ReplayFallbackReason::Refused),
    ] {
        assert_eq!(ReplayFallbackReason::from(unavailable), reason);
    }
}

/// A provider that keeps the requests it is asked, and answers none yet.
#[derive(Clone, Default)]
struct Asked(Arc<std::sync::Mutex<Vec<ReplayRequest>>>);

impl ReplayProvider for Asked {
    fn replay(&mut self, request: &ReplayRequest) -> ReplayStatus {
        self.0.lock().unwrap().push(*request);
        ReplayStatus::Pending
    }

    fn cancel(&mut self) {}
}

/// The gap asked for runs to the overrun's resume, where the live reader
/// rejoined, not to the end of the range known lost: an overrun whose
/// `lost_to` lies below its `resume` also skipped messages still
/// retained, and the replay must hold them too.
#[test]
fn the_gap_asked_for_runs_to_the_resume() {
    let reader = ClientSubscription::new(
        buffer()
            .conductor_owned()
            .unwrap()
            .subscribe(Role::Required)
            .unwrap(),
    );
    let asked = Asked::default();
    let source = PublicationIdentity::default();
    let mut rejoin = ReplayRejoin::new(
        reader,
        source,
        Box::new(asked.clone()),
        Secondary::RejoinAtHead,
    );
    let overrun = Overrun {
        from: 64,
        lost_to: 4096,
        resume: 8192,
    };
    rejoin.state = match std::mem::replace(&mut rejoin.state, Rejoin::Moving) {
        Rejoin::Live(live) => Rejoin::Asking { live, overrun },
        other => other,
    };
    assert!(rejoin.is_recovering());
    assert_eq!(rejoin.ask(overrun), None);
    assert_eq!(
        *asked.0.lock().unwrap(),
        [ReplayRequest {
            source,
            from: 64,
            to: 8192,
        }]
    );
    assert!(rejoin.is_recovering(), "still asking");
}

/// A provider whose replay is ready at the first ask.
struct Ready(Option<Box<Replay>>);

impl ReplayProvider for Ready {
    fn replay(&mut self, _: &ReplayRequest) -> ReplayStatus {
        self.0
            .take()
            .map_or(ReplayStatus::Pending, ReplayStatus::Ready)
    }

    fn cancel(&mut self) {}
}

/// F9b (ffi-archive.md): a holding poll reads nothing it has not adopted.
/// The replay handed out in a `poll_adopted`, of a stream whose messages
/// can be longer than the live one's, is not read in that poll, and the
/// largest message stays the live reader's until `adopt`; after it, the
/// merge delivers every message once, in order.
#[test]
fn a_replay_handed_out_in_a_holding_poll_waits_for_the_next_adopt() {
    let (replayed, live) = (buffer_of(2 * MIN_TERM_LENGTH), buffer());
    let mut replayed_publication = replayed.publication_owned().unwrap().unwrap();
    let mut live_publication = live.publication_owned().unwrap().unwrap();
    // The replay reads from the start; the live reader joins at 20.
    let replay = ClientSubscription::new(
        replayed
            .conductor_owned()
            .unwrap()
            .subscribe(Role::Required)
            .unwrap(),
    );
    append(&mut replayed_publication, 0, 30);
    append(&mut live_publication, 0, 20);
    let reader = ClientSubscription::new(
        live.conductor_owned()
            .unwrap()
            .subscribe(Role::Required)
            .unwrap(),
    );
    append(&mut live_publication, 20, 30);
    let (small, large) = (reader.max_message_length(), replay.max_message_length());
    assert!(large > small, "{large} > {small}");
    let source = PublicationIdentity::default();
    let resume = reader.position();
    let mut rejoin = ReplayRejoin::new(
        reader,
        source,
        Box::new(Ready(Some(Box::new(Replay::new(replay, source))))),
        Secondary::RejoinAtHead,
    );
    let overrun = Overrun {
        from: 0,
        lost_to: resume,
        resume,
    };
    rejoin.state = match std::mem::replace(&mut rejoin.state, Rejoin::Moving) {
        Rejoin::Live(live) => Rejoin::Asking { live, overrun },
        other => other,
    };
    let mut seen = Vec::new();
    let read = |rejoin: &mut ReplayRejoin, seen: &mut Vec<u32>| {
        rejoin
            .poll_adopted(
                |bytes, _| seen.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                MessageLimit::new(64),
            )
            .unwrap()
            .delivered
    };
    // The replay is handed out, and held.
    assert_eq!(read(&mut rejoin, &mut seen), 0);
    assert!(rejoin.is_recovering());
    assert_eq!(rejoin.max_message_length(), small, "not before the adopt");
    assert_eq!(read(&mut rejoin, &mut seen), 0, "still held");
    rejoin.adopt();
    assert_eq!(rejoin.max_message_length(), large);
    for _ in 0..8 {
        rejoin.adopt();
        let _ = read(&mut rejoin, &mut seen);
    }
    assert_eq!(seen, (0..30).collect::<Vec<_>>());
    // Once the replay is merged, only the live reader's size remains.
    rejoin.adopt();
    assert_eq!(rejoin.max_message_length(), small);
}
