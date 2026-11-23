// SPDX-License-Identifier: Apache-2.0

//! A retention state requester (ADR-0101; archive-control-codec.md
//! section 11): one schema 1 version 2 `RetentionState` query at a time,
//! for a tool such as the management agent.
//!
//! The query names a stream of the requester's own for its answer, which
//! the requester subscribed to first: the descriptors and the summary are
//! read there, never on the shared response stream, which a version 1
//! reader decodes in full. The shared stream is read only for the one
//! refusal frame a `ControlResponse` carries, by correlation id. A
//! version 1 Archive answers code 5 there: [`RetentionStatePoll::Unsupported`].
//! A lost answer leaves the query pending: its owner bounds the wait.

use super::{ControlRequests, ControlResponses};
use crate::control::{
    ControlMessage, MAX_LIST_COUNT, ResponseCode, RetentionDescriptor, RetentionState,
    RetentionSummary,
};
use crate::server::{MAX_ANSWER, MAX_REQUEST};

/// Answers read at most per poll, on each stream.
const ANSWERS_PER_POLL: usize = 64;

/// Where a query is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionStatePoll {
    /// No query.
    Idle,
    /// Sent or waiting for room; not answered yet.
    Pending,
    /// The descriptors in the order sent, and the summary.
    Answered {
        /// The descriptors kept, at most the query's `max_count`.
        descriptors: Vec<RetentionDescriptor>,
        /// The summary.
        summary: RetentionSummary,
    },
    /// The Archive has no version 2: "retention state unsupported by this
    /// Archive".
    Unsupported,
    /// Refused on the shared stream: the code and message, verbatim.
    Refused {
        /// The code.
        code: ResponseCode,
        /// The message.
        message: String,
    },
    /// The query does not encode (a `max_count` or channel outside its
    /// bounds): nothing was sent.
    Invalid,
}

#[derive(Debug, Clone)]
enum Step {
    Idle,
    Sending {
        correlation_id: u64,
        from_id: u64,
        max_count: u32,
    },
    Waiting {
        correlation_id: u64,
    },
}

/// The requester.
#[derive(Debug)]
pub struct RetentionStateRequester<Q, R, A> {
    client_id: u32,
    requests: Q,
    shared: R,
    own: A,
    own_stream_id: i32,
    own_channel: String,
    next: u32,
    step: Step,
    descriptors: Vec<RetentionDescriptor>,
    request: Vec<u8>,
    answer: Vec<u8>,
}

impl<Q: ControlRequests, R: ControlResponses, A: ControlResponses>
    RetentionStateRequester<Q, R, A>
{
    /// A requester for `client_id` over `requests`, the `shared` response
    /// stream and `own`, its own answer stream: stream `own_stream_id` of
    /// `own_channel`.
    #[must_use]
    pub fn new(
        client_id: u32,
        requests: Q,
        shared: R,
        own: A,
        own_stream_id: i32,
        own_channel: &str,
    ) -> Self {
        Self {
            client_id,
            requests,
            shared,
            own,
            own_stream_id,
            own_channel: own_channel.to_owned(),
            next: 1,
            step: Step::Idle,
            descriptors: Vec::new(),
            request: vec![0; MAX_REQUEST],
            answer: vec![0; MAX_ANSWER],
        }
    }

    /// Its transports back.
    #[must_use]
    pub fn into_transports(self) -> (Q, R, A) {
        (self.requests, self.shared, self.own)
    }

    /// Begins a query of at most `max_count` recordings from `from_id`
    /// (inclusive; 0 from the first).
    pub fn start(&mut self, from_id: u64, max_count: u32) {
        self.descriptors.clear();
        let low = self.next;
        self.next = self.next.checked_add(1).unwrap_or(1);
        let correlation_id = (u64::from(self.client_id) << 32) | u64::from(low);
        self.step = Step::Sending {
            correlation_id,
            from_id,
            max_count,
        };
    }

    fn send(&mut self) -> Option<RetentionStatePoll> {
        let Step::Sending {
            correlation_id,
            from_id,
            max_count,
        } = self.step.clone()
        else {
            return None;
        };
        let message = ControlMessage::RetentionState(RetentionState {
            correlation_id,
            from_id,
            max_count,
            response_stream_id: self.own_stream_id,
            response_channel: &self.own_channel,
        });
        let encoded = message
            .encode(&mut self.request)
            .ok()
            .and_then(|length| self.request.get(..length));
        let Some(bytes) = encoded else {
            self.step = Step::Idle;
            return Some(RetentionStatePoll::Invalid);
        };
        if !self.requests.send(bytes) {
            return Some(RetentionStatePoll::Pending);
        }
        self.step = Step::Waiting { correlation_id };
        None
    }

    /// Sends the query when there is room and reads the answers there are.
    pub fn poll(&mut self) -> RetentionStatePoll {
        if let Some(answer) = self.send() {
            return answer;
        }
        let Step::Waiting { correlation_id } = self.step else {
            return RetentionStatePoll::Idle;
        };
        let mut answer = std::mem::take(&mut self.answer);
        let ended = self
            .read_own(&mut answer, correlation_id)
            .or_else(|| self.read_shared(&mut answer, correlation_id));
        self.answer = answer;
        match ended {
            Some(ended) => {
                self.step = Step::Idle;
                ended
            }
            None => RetentionStatePoll::Pending,
        }
    }

    /// The answer on the requester's own stream: descriptors kept up to
    /// the query's bound, until the summary.
    fn read_own(&mut self, answer: &mut [u8], correlation_id: u64) -> Option<RetentionStatePoll> {
        let max = usize::try_from(MAX_LIST_COUNT).unwrap_or(usize::MAX);
        for _ in 0..ANSWERS_PER_POLL {
            let length = self.own.next(answer)?;
            let Some(bytes) = answer.get(..length) else {
                continue;
            };
            match ControlMessage::decode(bytes) {
                Ok(ControlMessage::RetentionDescriptor(descriptor))
                    if descriptor.correlation_id == correlation_id =>
                {
                    if self.descriptors.len() < max {
                        self.descriptors.push(descriptor);
                    }
                }
                Ok(ControlMessage::RetentionSummary(summary))
                    if summary.correlation_id == correlation_id =>
                {
                    return Some(RetentionStatePoll::Answered {
                        descriptors: std::mem::take(&mut self.descriptors),
                        summary,
                    });
                }
                _ => {}
            }
        }
        None
    }

    /// A refusal on the shared stream: the query's `ControlResponse`.
    fn read_shared(
        &mut self,
        answer: &mut [u8],
        correlation_id: u64,
    ) -> Option<RetentionStatePoll> {
        for _ in 0..ANSWERS_PER_POLL {
            let length = self.shared.next(answer)?;
            let Some(bytes) = answer.get(..length) else {
                continue;
            };
            if let Ok(ControlMessage::ControlResponse(response)) = ControlMessage::decode(bytes)
                && response.correlation_id == correlation_id
            {
                return Some(match response.code {
                    ResponseCode::UnsupportedSchema => RetentionStatePoll::Unsupported,
                    code => RetentionStatePoll::Refused {
                        code,
                        message: response.message.to_owned(),
                    },
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "tests, as ADR-0007 allows"
    )]

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::control::{ControlResponse, HoldState, NO_EXPIRY};

    #[derive(Clone, Default)]
    struct Stream(Arc<Mutex<VecDeque<Vec<u8>>>>);

    impl Stream {
        fn push(&self, message: &ControlMessage<'_>) {
            let mut out = vec![0u8; MAX_ANSWER];
            let length = message.encode(&mut out).unwrap();
            out.truncate(length);
            self.0.lock().unwrap().push_back(out);
        }
    }

    impl ControlRequests for Stream {
        fn send(&mut self, message: &[u8]) -> bool {
            self.0.lock().unwrap().push_back(message.to_vec());
            true
        }
    }

    impl ControlResponses for Stream {
        fn next(&mut self, out: &mut [u8]) -> Option<usize> {
            let message = self.0.lock().unwrap().pop_front()?;
            out[..message.len()].copy_from_slice(&message);
            Some(message.len())
        }
    }

    fn rig() -> (
        RetentionStateRequester<Stream, Stream, Stream>,
        Stream,
        Stream,
        Stream,
    ) {
        let (requests, shared, own) = (Stream::default(), Stream::default(), Stream::default());
        let requester = RetentionStateRequester::new(
            7,
            requests.clone(),
            shared.clone(),
            own.clone(),
            77,
            "karyos:ipc",
        );
        (requester, requests, shared, own)
    }

    /// The query names its own stream; its descriptors and summary are
    /// read there, another requester's are skipped.
    #[test]
    fn a_query_is_answered_on_its_own_stream() {
        let (mut requester, requests, _shared, own) = rig();
        requester.start(0, 100);
        assert_eq!(requester.poll(), RetentionStatePoll::Pending);
        let sent = requests.0.lock().unwrap().pop_front().unwrap();
        let ControlMessage::RetentionState(query) = ControlMessage::decode(&sent).unwrap() else {
            panic!("a query");
        };
        assert_eq!(
            (
                query.response_stream_id,
                query.response_channel,
                query.max_count
            ),
            (77, "karyos:ipc", 100)
        );
        let descriptor = |correlation_id, recording_id| RetentionDescriptor {
            correlation_id,
            recording_id,
            hold_since_ns: 0,
            close_time_ns: 0,
            earliest_expiry_ns: NO_EXPIRY,
            policy: 0,
            policy_version: 0,
            hold: HoldState::None,
        };
        let id = query.correlation_id;
        own.push(&ControlMessage::RetentionDescriptor(descriptor(id + 1, 9)));
        own.push(&ControlMessage::RetentionDescriptor(descriptor(id, 1)));
        let summary = RetentionSummary {
            correlation_id: id,
            count: 1,
            min_free_bytes: 0,
            free_bytes: u64::MAX,
        };
        own.push(&ControlMessage::RetentionSummary(summary));
        assert_eq!(
            requester.poll(),
            RetentionStatePoll::Answered {
                descriptors: vec![descriptor(id, 1)],
                summary,
            }
        );
        assert_eq!(requester.poll(), RetentionStatePoll::Idle);
    }

    /// A version 1 Archive's code 5 is "unsupported"; another refusal is
    /// passed on verbatim; an out-of-bounds query sends nothing.
    #[test]
    fn refusals_and_an_archive_without_version_2() {
        let (mut requester, requests, shared, _own) = rig();
        for (code, expected) in [
            (
                ResponseCode::UnsupportedSchema,
                RetentionStatePoll::Unsupported,
            ),
            (
                ResponseCode::Error,
                RetentionStatePoll::Refused {
                    code: ResponseCode::Error,
                    message: "busy".to_owned(),
                },
            ),
        ] {
            requester.start(0, 10);
            assert_eq!(requester.poll(), RetentionStatePoll::Pending);
            let sent = requests.0.lock().unwrap().pop_front().unwrap();
            let correlation_id = u64::from_le_bytes(sent[12..20].try_into().unwrap());
            shared.push(&ControlMessage::ControlResponse(ControlResponse {
                correlation_id,
                id: 0,
                code,
                message: if code == ResponseCode::Error {
                    "busy"
                } else {
                    ""
                },
            }));
            assert_eq!(requester.poll(), expected);
        }
        requester.start(0, 0);
        assert_eq!(requester.poll(), RetentionStatePoll::Invalid);
        assert!(requests.0.lock().unwrap().is_empty());
    }
}
