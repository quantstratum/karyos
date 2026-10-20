// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::*;

type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

struct Requests {
    sent: Queue,
    room: Arc<AtomicBool>,
}

impl ControlRequests for Requests {
    fn send(&mut self, message: &[u8]) -> bool {
        if !self.room.load(Ordering::Acquire) {
            return false;
        }
        self.sent.lock().unwrap().push_back(message.to_vec());
        true
    }
}

struct Responses(Queue);

impl ControlResponses for Responses {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let message = self.0.lock().unwrap().pop_front()?;
        out[..message.len()].copy_from_slice(&message);
        Some(message.len())
    }
}

const CLIENT: u32 = 7;

/// A replayer of client 7 and its fake Archive's queues.
struct Rig {
    replayer: Replayer<Requests, Responses>,
    sent: Queue,
    answers: Queue,
    room: Arc<AtomicBool>,
    now: Instant,
}

fn rig() -> Rig {
    let (sent, answers) = (Queue::default(), Queue::default());
    let room = Arc::new(AtomicBool::new(true));
    let replayer = Replayer::new(
        ReplayerConfig::new(CLIENT),
        Requests {
            sent: Arc::clone(&sent),
            room: Arc::clone(&room),
        },
        Responses(Arc::clone(&answers)),
    );
    Rig {
        replayer,
        sent,
        answers,
        room,
        now: Instant::now(),
    }
}

/// A request as the fake Archive reads it.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Replay {
        correlation_id: u64,
        recording_id: u64,
        target_stream_id: i32,
    },
    Stop {
        correlation_id: u64,
        replay_id: u64,
    },
}

impl Rig {
    /// The requests sent so far, oldest first.
    fn sent(&self) -> Vec<Sent> {
        self.sent
            .lock()
            .unwrap()
            .drain(..)
            .map(|bytes| match ControlMessage::decode(&bytes).unwrap() {
                ControlMessage::Replay(replay) => Sent::Replay {
                    correlation_id: replay.correlation_id,
                    recording_id: replay.recording_id,
                    target_stream_id: replay.target_stream_id,
                },
                ControlMessage::StopReplay(stop) => Sent::Stop {
                    correlation_id: stop.correlation_id,
                    replay_id: stop.replay_id,
                },
                other => panic!("unexpected request {other:?}"),
            })
            .collect()
    }

    /// The Archive answers `correlation_id`.
    fn answer(&self, correlation_id: u64, code: ResponseCode, id: u64, message: &str) {
        let mut bytes = vec![0; MAX_ANSWER];
        let length = ControlMessage::ControlResponse(ControlResponse {
            correlation_id,
            id,
            code,
            message,
        })
        .encode(&mut bytes)
        .unwrap();
        bytes.truncate(length);
        self.answers.lock().unwrap().push_back(bytes);
    }

    fn poll(&mut self) -> Option<ReplayerEvent> {
        self.replayer.poll(self.now)
    }

    fn later(&mut self, by: Duration) {
        self.now = self.now.checked_add(by).unwrap();
    }
}

fn correlation(low: u32) -> u64 {
    (u64::from(CLIENT) << 32) | u64::from(low)
}

#[test]
fn a_replay_is_started_and_stopped() {
    let mut rig = rig();
    let request = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    assert_eq!(request.get(), 1);
    assert_eq!(
        rig.sent(),
        [Sent::Replay {
            correlation_id: correlation(1),
            recording_id: 3,
            target_stream_id: 1001,
        }]
    );
    assert_eq!(rig.poll(), None);
    // The replay id's low 32 bits are its target's session.
    let replay_id = (5 << 32) | 9;
    rig.answer(correlation(1), ResponseCode::Ok, replay_id, "");
    assert_eq!(
        rig.poll(),
        Some(ReplayerEvent::Started {
            request,
            replay_id,
            session_id: 9,
        })
    );
    let stop = rig.replayer.stop(replay_id, rig.now).unwrap();
    assert_eq!(
        rig.sent(),
        [Sent::Stop {
            correlation_id: correlation(2),
            replay_id,
        }]
    );
    rig.answer(correlation(2), ResponseCode::Ok, 0, "");
    assert_eq!(
        rig.poll(),
        Some(ReplayerEvent::Stopped {
            request: stop,
            replay_id,
        })
    );
    assert_eq!((rig.poll(), rig.replayer.pending()), (None, 0));
}

#[test]
fn a_refusal_carries_its_code_and_message() {
    let mut rig = rig();
    let request = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    rig.answer(
        correlation(1),
        ResponseCode::UnknownRecording,
        0,
        "no recording 3",
    );
    assert_eq!(
        rig.poll(),
        Some(ReplayerEvent::Refused {
            request,
            code: ResponseCode::UnknownRecording,
            message: "no recording 3".to_owned(),
        })
    );
    let stop = rig.replayer.stop(44, rig.now).unwrap();
    rig.answer(correlation(2), ResponseCode::UnknownReplay, 0, "");
    assert!(matches!(
        rig.poll(),
        Some(ReplayerEvent::Refused { request, code: ResponseCode::UnknownReplay, .. })
            if request == stop
    ));
}

#[test]
fn another_requesters_answers_are_skipped() {
    let mut rig = rig();
    let request = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    // The same low bits under another client id, then a stray low id.
    rig.answer((8 << 32) | 1, ResponseCode::Ok, 77, "");
    rig.answer(correlation(99), ResponseCode::Ok, 78, "");
    assert_eq!(rig.poll(), None);
    assert_eq!(rig.replayer.pending(), 1);
    rig.answer(correlation(1), ResponseCode::Ok, 79, "");
    assert!(matches!(
        rig.poll(),
        Some(ReplayerEvent::Started { replay_id: 79, request: r, .. }) if r == request
    ));
    // Nothing was sent for the strays.
    assert_eq!(rig.sent().len(), 1);
}

#[test]
fn a_poll_reads_a_bounded_number_of_answers_and_reports_one_event() {
    let mut rig = rig();
    let first = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    let second = rig
        .replayer
        .start(&ReplaySpec::new(4, 0, 1001), rig.now)
        .unwrap();
    for _ in 0..ANSWERS_PER_CALL {
        rig.answer((8 << 32) | 1, ResponseCode::Ok, 1, "");
    }
    rig.answer(correlation(1), ResponseCode::Ok, 11, "");
    rig.answer(correlation(2), ResponseCode::Ok, 12, "");
    // The first poll reads only the strays.
    assert_eq!(rig.poll(), None);
    // The next reads both answers and reports them one per poll.
    assert!(matches!(rig.poll(), Some(ReplayerEvent::Started { request, .. }) if request == first));
    assert!(
        matches!(rig.poll(), Some(ReplayerEvent::Started { request, .. }) if request == second)
    );
    assert_eq!(rig.poll(), None);
}

#[test]
fn requests_wait_for_room_and_go_in_order() {
    let mut rig = rig();
    rig.room.store(false, Ordering::Release);
    rig.replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    rig.replayer.stop(50, rig.now).unwrap();
    assert!(rig.sent().is_empty());
    assert_eq!(rig.poll(), None);
    rig.room.store(true, Ordering::Release);
    assert_eq!(rig.poll(), None);
    let sent = rig.sent();
    assert!(
        matches!(sent[0], Sent::Replay { correlation_id, .. } if correlation_id == correlation(1))
    );
    assert_eq!(
        sent[1],
        Sent::Stop {
            correlation_id: correlation(2),
            replay_id: 50,
        }
    );
}

#[test]
fn a_bad_spec_is_refused_and_takes_no_id() {
    let mut rig = rig();
    let now = rig.now;
    let mut spec = ReplaySpec::new(0, 0, 1001);
    assert_eq!(
        rig.replayer.start(&spec, now),
        Err(ReplayerError::InvalidSpec)
    );
    spec.recording_id = 3;
    spec.target_channel = String::new();
    assert_eq!(
        rig.replayer.start(&spec, now),
        Err(ReplayerError::InvalidSpec)
    );
    spec.target_channel = "c".repeat(MAX_CHANNEL + 1);
    assert_eq!(
        rig.replayer.start(&spec, now),
        Err(ReplayerError::InvalidSpec)
    );
    spec.target_channel = "karyos:ipc".to_owned();
    spec.rate = ReplayRate::Scaled { ppm: 0 };
    assert_eq!(
        rig.replayer.start(&spec, now),
        Err(ReplayerError::InvalidSpec)
    );
    assert_eq!(rig.replayer.stop(0, now), Err(ReplayerError::InvalidSpec));
    spec.rate = ReplayRate::Scaled { ppm: 500_000 };
    spec.target_channel = "c".repeat(MAX_CHANNEL);
    assert_eq!(rig.replayer.start(&spec, now).unwrap().get(), 1);
    assert!(rig.sent().len() == 1 && rig.replayer.pending() == 1);
}

#[test]
fn busy_at_max_pending_including_events_not_polled() {
    let mut rig = rig();
    let now = rig.now;
    for recording_id in 1..=u64::try_from(MAX_PENDING).unwrap() {
        rig.replayer
            .start(&ReplaySpec::new(recording_id, 0, 1001), now)
            .unwrap();
    }
    assert_eq!(
        rig.replayer.start(&ReplaySpec::new(99, 0, 1001), now),
        Err(ReplayerError::Busy)
    );
    assert_eq!(rig.replayer.stop(5, now), Err(ReplayerError::Busy));
    // All answered in one poll: one event is reported, the rest wait to
    // be polled and still count.
    for low in 1..=u32::try_from(MAX_PENDING).unwrap() {
        rig.answer(correlation(low), ResponseCode::Ok, u64::from(low), "");
    }
    assert!(rig.poll().is_some());
    assert_eq!(rig.replayer.pending(), 0);
    rig.replayer
        .start(&ReplaySpec::new(99, 0, 1001), now)
        .unwrap();
    assert_eq!(
        rig.replayer.start(&ReplaySpec::new(100, 0, 1001), now),
        Err(ReplayerError::Busy)
    );
}

#[test]
fn an_expired_replay_request_stops_its_late_start() {
    let mut rig = rig();
    let deadline = ReplayerConfig::new(CLIENT).deadline;
    let request = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    rig.sent();
    rig.later(deadline.checked_sub(Duration::from_nanos(1)).unwrap());
    assert_eq!(rig.poll(), None);
    rig.later(Duration::from_nanos(1));
    assert_eq!(rig.poll(), Some(ReplayerEvent::Expired { request }));
    assert_eq!(rig.replayer.pending(), 0);
    // The late answer: no event, and the replay it started is stopped.
    rig.answer(correlation(1), ResponseCode::Ok, 31, "");
    assert_eq!(rig.poll(), None);
    assert_eq!(
        rig.sent(),
        [Sent::Stop {
            correlation_id: correlation(2),
            replay_id: 31,
        }]
    );
    // That stop's answer is the replayer's own: no event either.
    rig.answer(correlation(2), ResponseCode::Ok, 0, "");
    assert_eq!(rig.poll(), None);
    // A late refusal stops nothing.
    let request = rig
        .replayer
        .start(&ReplaySpec::new(4, 0, 1001), rig.now)
        .unwrap();
    rig.later(deadline);
    assert_eq!(rig.poll(), Some(ReplayerEvent::Expired { request }));
    rig.sent();
    rig.answer(correlation(3), ResponseCode::UnknownRecording, 0, "");
    assert_eq!(rig.poll(), None);
    assert!(rig.sent().is_empty());
}

#[test]
fn a_request_never_sent_expires_and_leaves_nothing_to_stop() {
    let mut rig = rig();
    rig.room.store(false, Ordering::Release);
    let request = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    rig.later(ReplayerConfig::new(CLIENT).deadline);
    assert_eq!(rig.poll(), Some(ReplayerEvent::Expired { request }));
    rig.room.store(true, Ordering::Release);
    // Its id is free and never reached the Archive: an answer under it
    // stops nothing.
    rig.answer(correlation(1), ResponseCode::Ok, 31, "");
    assert_eq!(rig.poll(), None);
    assert!(rig.sent().is_empty());
}

#[test]
fn correlation_ids_skip_0_on_a_wrap_and_wait_for_a_busy_id() {
    let mut rig = rig();
    rig.replayer.next = u32::MAX;
    let last = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    assert_eq!(last.get(), u32::MAX);
    let first = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    assert_eq!(first.get(), 1);
    // Back to an id still waiting: Busy, and nothing is taken.
    rig.replayer.next = u32::MAX;
    assert_eq!(
        rig.replayer.start(&ReplaySpec::new(3, 0, 1001), rig.now),
        Err(ReplayerError::Busy)
    );
    assert_eq!(rig.replayer.next, u32::MAX);
    rig.answer(correlation(u32::MAX), ResponseCode::Ok, 5, "");
    assert!(rig.poll().is_some());
    assert_eq!(
        rig.replayer
            .start(&ReplaySpec::new(3, 0, 1001), rig.now)
            .unwrap()
            .get(),
        u32::MAX
    );
}

#[test]
fn an_expired_requests_id_is_not_reused_while_its_late_answer_may_come() {
    let mut rig = rig();
    let request = rig
        .replayer
        .start(&ReplaySpec::new(3, 0, 1001), rig.now)
        .unwrap();
    rig.later(ReplayerConfig::new(CLIENT).deadline);
    assert_eq!(rig.poll(), Some(ReplayerEvent::Expired { request }));
    rig.replayer.next = 1;
    assert_eq!(
        rig.replayer.start(&ReplaySpec::new(4, 0, 1001), rig.now),
        Err(ReplayerError::Busy)
    );
}
