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

use karyos_sys::sizing::MIN_TERM_LENGTH;

use super::*;
use crate::catalog::{Stop, StopReason};
use crate::control::{ControlResponse, RecordingDescriptor};

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

/// A lister of client 7 and its fake Archive's queues.
struct Rig {
    lister: RecordingLister<Requests, Responses>,
    sent: Queue,
    answers: Queue,
    room: Arc<AtomicBool>,
}

fn rig(page: u32, max_recordings: usize) -> Rig {
    let (sent, answers) = (Queue::default(), Queue::default());
    let room = Arc::new(AtomicBool::new(true));
    let lister = RecordingLister::new(
        ListerConfig::new(7).with_bounds(page, max_recordings),
        Requests {
            sent: Arc::clone(&sent),
            room: Arc::clone(&room),
        },
        Responses(Arc::clone(&answers)),
    );
    Rig {
        lister,
        sent,
        answers,
        room,
    }
}

impl Rig {
    /// The list request sent last: its correlation id, first id and count.
    fn request(&self) -> (u64, u64, u32) {
        let bytes = self.sent.lock().unwrap().pop_back().unwrap();
        match ControlMessage::decode(&bytes).unwrap() {
            ControlMessage::ListRecordings(list) => {
                (list.correlation_id, list.from_id, list.max_count)
            }
            other => panic!("{other:?}"),
        }
    }

    fn answer(&self, message: &ControlMessage<'_>) {
        let mut out = vec![0; MAX_ANSWER];
        let length = message.encode(&mut out).unwrap();
        out.truncate(length);
        self.answers.lock().unwrap().push_back(out);
    }

    /// The Archive's page: descriptors of `ids`, then the count.
    fn page(&self, correlation_id: u64, ids: &[u64]) {
        for &id in ids {
            self.answer(&ControlMessage::RecordingDescriptor(descriptor(
                correlation_id,
                id,
            )));
        }
        self.answer(&ControlMessage::ControlResponse(ControlResponse {
            correlation_id,
            id: u64::try_from(ids.len()).unwrap(),
            code: ResponseCode::Ok,
            message: "",
        }));
    }
}

fn descriptor<'a>(correlation_id: u64, recording_id: u64) -> RecordingDescriptor<'a> {
    RecordingDescriptor {
        correlation_id,
        recording_id,
        start: 0,
        start_time_ns: 1,
        state: RecordingState::Stopped(Stop {
            position: 100,
            time_ns: 2,
            reason: StopReason::Stopped,
            incomplete: false,
        }),
        geometry: Geometry::new(MIN_TERM_LENGTH, 4 * u64::from(MIN_TERM_LENGTH)).unwrap(),
        source: SourceIncarnation {
            driver: [1, 2],
            registration: recording_id,
            incarnation: 1,
        },
        stream_id: 10,
        session_id: 1,
        channel: "karyos:ipc",
    }
}

fn ids(poll: &ListPoll) -> Vec<u64> {
    match poll {
        ListPoll::Done(listing) => listing
            .recordings
            .iter()
            .map(|recording| recording.recording_id)
            .collect(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_listing_follows_full_pages_to_a_short_one() {
    let mut rig = rig(2, 100);
    assert_eq!(rig.lister.poll(), ListPoll::Idle);
    rig.lister.start();
    assert_eq!(rig.lister.poll(), ListPoll::Pending);
    let (first, from, count) = rig.request();
    assert_eq!((first >> 32, from, count), (7, 0, 2));
    rig.page(first, &[3, 5]);
    // A full page: the next one from the id after its last.
    assert_eq!(rig.lister.poll(), ListPoll::Pending);
    let (second, from, _) = rig.request();
    assert_ne!(second, first);
    assert_eq!(from, 6);
    rig.page(second, &[8]);
    let done = rig.lister.poll();
    assert_eq!(ids(&done), [3, 5, 8]);
    let ListPoll::Done(listing) = done else {
        unreachable!()
    };
    assert_eq!(listing.left_out, 0);
    assert_eq!(listing.recordings[0].channel, "karyos:ipc");
    assert_eq!(rig.lister.poll(), ListPoll::Idle);
}

#[test]
fn another_requesters_answers_are_skipped() {
    let mut rig = rig(10, 100);
    rig.lister.start();
    let _ = rig.lister.poll();
    let (correlation_id, _, _) = rig.request();
    rig.page(correlation_id + 1000, &[1, 2]);
    rig.page(correlation_id, &[4]);
    // Up to 64 answers a poll: the stranger's three, then ours.
    assert_eq!(ids(&rig.lister.poll()), [4]);
}

#[test]
fn a_refusal_ends_the_listing() {
    let mut rig = rig(10, 100);
    rig.lister.start();
    let _ = rig.lister.poll();
    let (correlation_id, _, _) = rig.request();
    rig.answer(&ControlMessage::ControlResponse(ControlResponse {
        correlation_id,
        id: 0,
        code: ResponseCode::Error,
        message: "catalog unreadable",
    }));
    assert_eq!(
        rig.lister.poll(),
        ListPoll::Refused {
            code: ResponseCode::Error,
            message: "catalog unreadable".to_owned()
        }
    );
}

#[test]
fn recordings_past_the_bound_are_counted_not_kept() {
    let mut rig = rig(10, 2);
    rig.lister.start();
    let _ = rig.lister.poll();
    let (correlation_id, _, _) = rig.request();
    rig.page(correlation_id, &[1, 2, 3, 4]);
    let ListPoll::Done(listing) = rig.lister.poll() else {
        panic!()
    };
    assert_eq!(listing.recordings.len(), 2);
    assert_eq!(listing.left_out, 2);
}

#[test]
fn a_request_without_room_is_offered_again() {
    let mut rig = rig(10, 100);
    rig.room.store(false, Ordering::Release);
    rig.lister.start();
    assert_eq!(rig.lister.poll(), ListPoll::Pending);
    assert!(rig.sent.lock().unwrap().is_empty());
    rig.room.store(true, Ordering::Release);
    assert_eq!(rig.lister.poll(), ListPoll::Pending);
    let (correlation_id, from, _) = rig.request();
    assert_eq!(from, 0);
    rig.page(correlation_id, &[]);
    assert_eq!(ids(&rig.lister.poll()), Vec::<u64>::new());
}
