// SPDX-License-Identifier: Apache-2.0

//! A retention requester over the Archive's control streams (ADR-0088,
//! Proposed; karyos#967): a legal hold, a hold release, a purge and a seal
//! verification, one at a time, for a tool such as the management agent.
//!
//! [`RetentionRequester::start`] begins a request; each
//! [`RetentionRequester::poll`] sends it when there is room and reads the
//! answers there are, never blocking. A hold, a release or a purge ends at
//! its [`ControlResponse`](crate::control::ControlResponse); a
//! verification gathers one [`RangeOutcome`] per range and ends at the
//! response with their count. The Archive's codes and refusal names are
//! passed on verbatim. A lost answer leaves the request pending: its owner
//! bounds the wait.
//!
//! Correlation ids carry [`RetentionRequester::new`]'s `client_id` in
//! their high 32 bits, as the lister's do; answers to other requesters
//! are skipped.

use super::{ControlRequests, ControlResponses};
use crate::control::{
    ControlMessage, HoldRecording, PurgeRecording, RangeOutcome, ReleaseHold, ResponseCode,
    VerifyRecording,
};
use crate::server::{MAX_ANSWER, MAX_REQUEST};

/// Answers read at most per poll.
const ANSWERS_PER_POLL: usize = 64;

/// The ranges one verification keeps at most; past it they are counted,
/// not kept.
pub const MAX_RANGES: usize = 65_536;

/// One retention request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionRequest {
    /// A legal hold on the recording.
    Hold {
        /// The recording.
        recording: u64,
    },
    /// The release of the recording's legal hold.
    Release {
        /// The recording.
        recording: u64,
    },
    /// A purge of the recording below `before`.
    Purge {
        /// The recording.
        recording: u64,
        /// The first position kept.
        before: u64,
        /// The purge's id, never 0.
        request_id: u64,
        /// The operator the requester authenticated, never 0.
        operator: u64,
    },
    /// A seal verification of the recording.
    Verify {
        /// The recording.
        recording: u64,
    },
}

/// Where a request is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionPoll {
    /// No request.
    Idle,
    /// Sent or waiting for room; no answer yet.
    Pending,
    /// The Archive answered a hold, a release or a purge, or refused a
    /// verification: its code, the response's id and its message,
    /// verbatim.
    Answered {
        /// The code.
        code: ResponseCode,
        /// The response's id: the recording on success, else 0.
        id: u64,
        /// The message: the refusal's name, empty on success.
        message: String,
    },
    /// A verification's ranges, in the order sent.
    Verified {
        /// The ranges kept, at most [`MAX_RANGES`].
        ranges: Vec<RangeOutcome>,
        /// The ranges the Archive counted that are not in `ranges`: past
        /// the bound, or lost on the way.
        missing: u64,
    },
    /// The request does not encode (an id of 0): nothing was sent.
    Invalid,
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Idle,
    Sending {
        correlation_id: u64,
        request: RetentionRequest,
    },
    Waiting {
        correlation_id: u64,
        verify: bool,
    },
}

/// The requester.
#[derive(Debug)]
pub struct RetentionRequester<Q, R> {
    client_id: u32,
    requests: Q,
    responses: R,
    next: u32,
    step: Step,
    ranges: Vec<RangeOutcome>,
    request: Vec<u8>,
    answer: Vec<u8>,
}

impl<Q: ControlRequests, R: ControlResponses> RetentionRequester<Q, R> {
    /// A requester for `client_id` over `requests` and `responses`.
    #[must_use]
    pub fn new(client_id: u32, requests: Q, responses: R) -> Self {
        Self {
            client_id,
            requests,
            responses,
            next: 1,
            step: Step::Idle,
            ranges: Vec::new(),
            request: vec![0; MAX_REQUEST],
            answer: vec![0; MAX_ANSWER],
        }
    }

    /// Its transports back.
    #[must_use]
    pub fn into_transports(self) -> (Q, R) {
        (self.requests, self.responses)
    }

    /// Begins `request`, abandoning any request still pending: its late
    /// answers are skipped by their correlation id.
    pub fn start(&mut self, request: RetentionRequest) {
        self.ranges.clear();
        let low = self.next;
        self.next = self.next.checked_add(1).unwrap_or(1);
        let correlation_id = (u64::from(self.client_id) << 32) | u64::from(low);
        self.step = Step::Sending {
            correlation_id,
            request,
        };
    }

    fn send(&mut self) -> Option<RetentionPoll> {
        let Step::Sending {
            correlation_id,
            request,
        } = self.step
        else {
            return None;
        };
        let (message, verify) = match request {
            RetentionRequest::Hold { recording } => (
                ControlMessage::HoldRecording(HoldRecording {
                    correlation_id,
                    recording_id: recording,
                }),
                false,
            ),
            RetentionRequest::Release { recording } => (
                ControlMessage::ReleaseHold(ReleaseHold {
                    correlation_id,
                    recording_id: recording,
                }),
                false,
            ),
            RetentionRequest::Purge {
                recording,
                before,
                request_id,
                operator,
            } => (
                ControlMessage::PurgeRecording(PurgeRecording {
                    correlation_id,
                    recording_id: recording,
                    before,
                    request_id,
                    operator,
                }),
                false,
            ),
            RetentionRequest::Verify { recording } => (
                ControlMessage::VerifyRecording(VerifyRecording {
                    correlation_id,
                    recording_id: recording,
                }),
                true,
            ),
        };
        let encoded = message
            .encode(&mut self.request)
            .ok()
            .and_then(|length| self.request.get(..length));
        let Some(bytes) = encoded else {
            self.step = Step::Idle;
            return Some(RetentionPoll::Invalid);
        };
        if !self.requests.send(bytes) {
            return Some(RetentionPoll::Pending);
        }
        self.step = Step::Waiting {
            correlation_id,
            verify,
        };
        None
    }

    /// Sends the request when there is room and reads the answers there
    /// are.
    pub fn poll(&mut self) -> RetentionPoll {
        if let Some(answer) = self.send() {
            return answer;
        }
        let Step::Waiting {
            correlation_id,
            verify,
        } = self.step
        else {
            return RetentionPoll::Idle;
        };
        let mut answer = std::mem::take(&mut self.answer);
        let mut ended = None;
        for _ in 0..ANSWERS_PER_POLL {
            let Some(length) = self.responses.next(&mut answer) else {
                break;
            };
            let Some(bytes) = answer.get(..length) else {
                continue;
            };
            match ControlMessage::decode(bytes) {
                Ok(ControlMessage::RangeOutcome(range))
                    if verify && range.correlation_id == correlation_id =>
                {
                    // Past the bound a range is not kept; the count says
                    // how many are missing.
                    if self.ranges.len() < MAX_RANGES {
                        self.ranges.push(range);
                    }
                }
                Ok(ControlMessage::ControlResponse(response))
                    if response.correlation_id == correlation_id =>
                {
                    ended = Some(if verify && response.code == ResponseCode::Ok {
                        let kept = u64::try_from(self.ranges.len()).unwrap_or(u64::MAX);
                        RetentionPoll::Verified {
                            ranges: std::mem::take(&mut self.ranges),
                            missing: response.id.saturating_sub(kept),
                        }
                    } else {
                        RetentionPoll::Answered {
                            code: response.code,
                            id: response.id,
                            message: response.message.to_owned(),
                        }
                    });
                    break;
                }
                // Another requester's answers, signals, and what does not
                // decode are skipped.
                _ => {}
            }
        }
        self.answer = answer;
        match ended {
            Some(done) => {
                self.step = Step::Idle;
                done
            }
            None => RetentionPoll::Pending,
        }
    }
}

#[cfg(test)]
mod tests;
