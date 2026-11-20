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
use crate::control::{ControlResponse, IntegrityOutcome, NO_INCONSISTENT};

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

struct Rig {
    requester: RetentionRequester<Requests, Responses>,
    sent: Queue,
    answers: Queue,
    room: Arc<AtomicBool>,
}

fn rig() -> Rig {
    let (sent, answers) = (Queue::default(), Queue::default());
    let room = Arc::new(AtomicBool::new(true));
    let requester = RetentionRequester::new(
        7,
        Requests {
            sent: Arc::clone(&sent),
            room: Arc::clone(&room),
        },
        Responses(Arc::clone(&answers)),
    );
    Rig {
        requester,
        sent,
        answers,
        room,
    }
}

impl Rig {
    fn sent(&self) -> ControlMessage<'static> {
        let bytes = self.sent.lock().unwrap().pop_back().unwrap();
        ControlMessage::decode(Vec::leak(bytes)).unwrap()
    }

    fn answer(&self, message: &ControlMessage<'_>) {
        let mut out = vec![0u8; 512];
        let length = message.encode(&mut out).unwrap();
        out.truncate(length);
        self.answers.lock().unwrap().push_back(out);
    }

    fn respond(&self, correlation_id: u64, id: u64, code: ResponseCode, message: &str) {
        self.answer(&ControlMessage::ControlResponse(ControlResponse {
            correlation_id,
            id,
            code,
            message,
        }));
    }
}

fn range(correlation_id: u64, start: u64, end: u64) -> RangeOutcome {
    RangeOutcome {
        correlation_id,
        recording_id: 42,
        start,
        end,
        first_inconsistent: NO_INCONSISTENT,
        reasons: 0,
        outcome: IntegrityOutcome::Verified,
    }
}

/// A hold waits for room, is sent with client 7's correlation id, skips
/// another requester's answer and ends at its own, verbatim.
#[test]
fn a_hold_is_sent_when_there_is_room_and_answered_verbatim() {
    let mut rig = rig();
    assert_eq!(rig.requester.poll(), RetentionPoll::Idle);
    rig.room.store(false, Ordering::Release);
    rig.requester
        .start(RetentionRequest::Hold { recording: 42 });
    assert_eq!(rig.requester.poll(), RetentionPoll::Pending);
    assert!(rig.sent.lock().unwrap().is_empty());
    rig.room.store(true, Ordering::Release);
    assert_eq!(rig.requester.poll(), RetentionPoll::Pending);
    let ControlMessage::HoldRecording(hold) = rig.sent() else {
        panic!("not a hold");
    };
    assert_eq!(hold.recording_id, 42);
    assert_eq!(hold.correlation_id >> 32, 7);
    rig.respond(hold.correlation_id + 1, 42, ResponseCode::Ok, "");
    rig.respond(hold.correlation_id, 0, ResponseCode::HeldInMemoryOnly, "");
    assert_eq!(
        rig.requester.poll(),
        RetentionPoll::Answered {
            code: ResponseCode::HeldInMemoryOnly,
            id: 0,
            message: String::new(),
        }
    );
    assert_eq!(rig.requester.poll(), RetentionPoll::Idle);
}

/// A purge carries its fields; a refusal's name comes back verbatim; a
/// purge with an operator of 0 does not encode and is never sent.
#[test]
fn a_purge_carries_its_fields_and_its_refusal() {
    let mut rig = rig();
    rig.requester.start(RetentionRequest::Purge {
        recording: 42,
        before: 4096,
        request_id: 9,
        operator: 1000,
    });
    assert_eq!(rig.requester.poll(), RetentionPoll::Pending);
    let ControlMessage::PurgeRecording(purge) = rig.sent() else {
        panic!("not a purge");
    };
    assert_eq!(
        (
            purge.recording_id,
            purge.before,
            purge.request_id,
            purge.operator
        ),
        (42, 4096, 9, 1000)
    );
    rig.respond(purge.correlation_id, 0, ResponseCode::Refused, "legal_hold");
    assert_eq!(
        rig.requester.poll(),
        RetentionPoll::Answered {
            code: ResponseCode::Refused,
            id: 0,
            message: "legal_hold".to_owned(),
        }
    );
    rig.requester.start(RetentionRequest::Purge {
        recording: 42,
        before: 4096,
        request_id: 9,
        operator: 0,
    });
    assert_eq!(rig.requester.poll(), RetentionPoll::Invalid);
    assert!(rig.sent.lock().unwrap().is_empty());
}

/// A verification gathers its own ranges in order, skips another
/// request's, and ends at the count; a count above what came is
/// reported missing. A refusal of a verification is an answer.
#[test]
fn a_verification_gathers_its_ranges() {
    let mut rig = rig();
    rig.requester
        .start(RetentionRequest::Verify { recording: 42 });
    let _ = rig.requester.poll();
    let ControlMessage::VerifyRecording(verify) = rig.sent() else {
        panic!("not a verification");
    };
    let id = verify.correlation_id;
    rig.answer(&ControlMessage::RangeOutcome(range(id, 0, 10)));
    rig.answer(&ControlMessage::RangeOutcome(range(id + 1, 10, 20)));
    assert_eq!(rig.requester.poll(), RetentionPoll::Pending);
    rig.answer(&ControlMessage::RangeOutcome(range(id, 10, 30)));
    rig.respond(id, 3, ResponseCode::Ok, "");
    assert_eq!(
        rig.requester.poll(),
        RetentionPoll::Verified {
            ranges: vec![range(id, 0, 10), range(id, 10, 30)],
            missing: 1,
        }
    );
    rig.requester
        .start(RetentionRequest::Verify { recording: 42 });
    let _ = rig.requester.poll();
    let ControlMessage::VerifyRecording(verify) = rig.sent() else {
        panic!("not a verification");
    };
    rig.respond(
        verify.correlation_id,
        0,
        ResponseCode::Error,
        "no retention engine attached",
    );
    assert!(matches!(
        rig.requester.poll(),
        RetentionPoll::Answered {
            code: ResponseCode::Error,
            ..
        }
    ));
}
