// SPDX-License-Identifier: Apache-2.0

//! A recording lister over the Archive's control streams (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M11): the whole catalog,
//! page by page, for a tool such as the management agent.
//!
//! [`RecordingLister::start`] begins a listing from the first recording;
//! each [`RecordingLister::poll`] sends what it can and reads the answers
//! there are, never blocking. A page asks for [`ListerConfig::page`]
//! recordings; the Archive answers one descriptor each, then a response
//! with the count. A page that delivered any recording asks for the next
//! one from the id after its last, whatever its count: the Archive leaves
//! out a recording it cannot describe (a channel that is not UTF-8) or
//! cannot queue, so a short page does not mean the end. The listing ends
//! at an empty page, or when the Archive refuses; a page whose recordings
//! were all left out therefore ends it early. At most
//! [`ListerConfig::max_recordings`] are kept; past it the listing goes on
//! to its end, counting what it left out. A lost answer leaves the listing
//! pending: its owner bounds the wait and starts it again.
//!
//! Correlation ids carry [`ListerConfig::client_id`] in their high 32 bits,
//! as the replay client's do; answers to other requesters are skipped.

use super::{ControlRequests, ControlResponses};
use crate::catalog::SourceIncarnation;
use crate::control::{
    ControlMessage, ListRecordings, MAX_LIST_COUNT, RecordingState, ResponseCode,
};
use crate::segment::Geometry;
use crate::server::{MAX_ANSWER, MAX_REQUEST};

/// Answers read at most per poll.
const ANSWERS_PER_POLL: usize = 64;

/// The lister's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListerConfig {
    /// This requester's id, the high 32 bits of its correlation ids, unique
    /// among the Archive's requesters.
    pub client_id: u32,
    /// Recordings asked for in one page, 1 to [`MAX_LIST_COUNT`].
    pub page: u32,
    /// Recordings kept at most per listing.
    pub max_recordings: usize,
}

impl ListerConfig {
    /// A lister `client_id` asking for pages of [`MAX_LIST_COUNT`] and
    /// keeping up to 10 000 recordings.
    #[must_use]
    pub fn new(client_id: u32) -> Self {
        Self {
            client_id,
            page: MAX_LIST_COUNT,
            max_recordings: 10_000,
        }
    }

    /// With pages of `page` recordings (kept within 1 to
    /// [`MAX_LIST_COUNT`]) and at most `max_recordings` kept.
    #[must_use]
    pub fn with_bounds(mut self, page: u32, max_recordings: usize) -> Self {
        self.page = page.clamp(1, MAX_LIST_COUNT);
        self.max_recordings = max_recordings;
        self
    }
}

/// One recording, as a listing keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListedRecording {
    /// The recording, never 0.
    pub recording_id: u64,
    /// Its first position.
    pub start: u64,
    /// When it started.
    pub start_time_ns: u64,
    /// Whether it still records, or where it stopped.
    pub state: RecordingState,
    /// Its segment geometry.
    pub geometry: Geometry,
    /// The publication recorded.
    pub source: SourceIncarnation,
    /// The recorded stream.
    pub stream_id: i32,
    /// The recorded session.
    pub session_id: i32,
    /// The channel.
    pub channel: String,
}

/// A listing that ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Listing {
    /// The recordings kept, in id order.
    pub recordings: Vec<ListedRecording>,
    /// Recordings listed past [`ListerConfig::max_recordings`], not kept.
    pub left_out: u64,
}

/// What a poll found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListPoll {
    /// No listing was started, or the last one already ended.
    Idle,
    /// The listing goes on.
    Pending,
    /// The listing ended.
    Done(Listing),
    /// The Archive refused a page.
    Refused {
        /// Its code.
        code: ResponseCode,
        /// Its message.
        message: String,
    },
}

/// Where a listing stands.
#[derive(Debug, Clone, Copy)]
enum Step {
    Idle,
    /// The page from `from_id`, to be sent under `correlation_id`.
    Sending {
        correlation_id: u64,
        from_id: u64,
    },
    /// The page sent; its last recording so far.
    Waiting {
        correlation_id: u64,
        last: Option<u64>,
    },
}

/// The lister (see the module).
#[derive(Debug)]
pub struct RecordingLister<Q, R> {
    config: ListerConfig,
    requests: Q,
    responses: R,
    next: u32,
    step: Step,
    kept: Vec<ListedRecording>,
    left_out: u64,
    /// The recordings a bounded listing has left to keep
    /// ([`RecordingLister::start_from`]): no page is asked for past them.
    /// `None` lists to the end.
    left: Option<usize>,
    request: Vec<u8>,
    answer: Vec<u8>,
}

impl<Q: ControlRequests, R: ControlResponses> RecordingLister<Q, R> {
    /// A lister sending on `requests` and reading `responses`.
    #[must_use]
    pub fn new(config: ListerConfig, requests: Q, responses: R) -> Self {
        Self {
            config,
            requests,
            responses,
            next: 1,
            step: Step::Idle,
            kept: Vec::new(),
            left_out: 0,
            left: None,
            request: vec![0; MAX_REQUEST],
            answer: vec![0; MAX_ANSWER],
        }
    }

    /// The transports back, dropping a listing under way: to close them
    /// (`connection::Requests::close`).
    #[must_use]
    pub fn into_transports(self) -> (Q, R) {
        (self.requests, self.responses)
    }

    /// Its transports, borrowed: another requester of the same Archive (a
    /// retention state query, ADR-0101) uses them between listings, so a
    /// connection holds one request and one response handle only.
    pub fn transports_mut(&mut self) -> (&mut Q, &mut R) {
        (&mut self.requests, &mut self.responses)
    }

    /// Begins a listing from the first recording, dropping one under way.
    pub fn start(&mut self) {
        self.begin(0, None);
    }

    /// Begins a bounded listing, dropping one under way: the recordings
    /// from id `from_id` on, in id order, at most `count` (and at most
    /// [`ListerConfig::max_recordings`]). Its pages ask the Archive for no
    /// more than are left to list, and none is asked for once `count` are
    /// kept, so a page of a large catalog costs `count` recordings, not
    /// the whole catalog. A `count` of 0 lists nothing.
    pub fn start_from(&mut self, from_id: u64, count: usize) {
        self.begin(from_id, Some(count));
    }

    fn begin(&mut self, from_id: u64, bound: Option<usize>) {
        self.kept.clear();
        self.left_out = 0;
        self.left = bound.map(|count| count.min(self.config.max_recordings));
        if self.left == Some(0) {
            self.step = Step::Idle;
            return;
        }
        let correlation_id = self.correlation_id();
        self.step = Step::Sending {
            correlation_id,
            from_id,
        };
    }

    /// The next correlation id: this client's in the high 32 bits.
    fn correlation_id(&mut self) -> u64 {
        let low = self.next;
        self.next = self.next.checked_add(1).unwrap_or(1);
        (u64::from(self.config.client_id) << 32) | u64::from(low)
    }

    /// Sends the page of [`Step::Sending`], if any: `None` once it is sent
    /// (or there is none), what to answer otherwise.
    fn send(&mut self) -> Option<ListPoll> {
        let Step::Sending {
            correlation_id,
            from_id,
        } = self.step
        else {
            return None;
        };
        // A bounded listing asks for no more than it has left to keep.
        let page = match self.left.map(u32::try_from) {
            Some(Ok(left)) => self.config.page.min(left),
            _ => self.config.page,
        };
        let message = ControlMessage::ListRecordings(ListRecordings {
            correlation_id,
            from_id,
            max_count: page.clamp(1, MAX_LIST_COUNT),
        });
        let Ok(length) = message.encode(&mut self.request) else {
            self.step = Step::Idle;
            return Some(ListPoll::Refused {
                code: ResponseCode::InvalidRequest,
                message: "the list request does not encode".to_owned(),
            });
        };
        let Some(bytes) = self.request.get(..length) else {
            self.step = Step::Idle;
            return Some(ListPoll::Idle);
        };
        if !self.requests.send(bytes) {
            return Some(ListPoll::Pending);
        }
        self.step = Step::Waiting {
            correlation_id,
            last: None,
        };
        None
    }

    /// Sends what it can and reads the answers there are.
    pub fn poll(&mut self) -> ListPoll {
        if let Some(answer) = self.send() {
            return answer;
        }
        let Step::Waiting {
            correlation_id,
            mut last,
        } = self.step
        else {
            return ListPoll::Idle;
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
                Ok(ControlMessage::RecordingDescriptor(descriptor))
                    if descriptor.correlation_id == correlation_id =>
                {
                    last = Some(descriptor.recording_id);
                    if self.kept.len() < self.config.max_recordings && self.left != Some(0) {
                        // Not 0 here: one fewer is left to keep.
                        if let Some(left) = self.left.as_mut()
                            && let Some(fewer) = left.checked_sub(1)
                        {
                            *left = fewer;
                        }
                        self.kept.push(ListedRecording {
                            recording_id: descriptor.recording_id,
                            start: descriptor.start,
                            start_time_ns: descriptor.start_time_ns,
                            state: descriptor.state,
                            geometry: descriptor.geometry,
                            source: descriptor.source,
                            stream_id: descriptor.stream_id,
                            session_id: descriptor.session_id,
                            channel: descriptor.channel.to_owned(),
                        });
                    } else if let Some(more) = self.left_out.checked_add(1) {
                        self.left_out = more;
                    }
                }
                Ok(ControlMessage::ControlResponse(response))
                    if response.correlation_id == correlation_id =>
                {
                    ended = Some(match response.code {
                        ResponseCode::Ok => Ok(response.id),
                        code => Err((code, response.message.to_owned())),
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
            None => {
                self.step = Step::Waiting {
                    correlation_id,
                    last,
                };
                ListPoll::Pending
            }
            // A page that delivered a recording: the next one, from the id
            // after its last, goes out now. No answer of its can have come
            // yet, so this poll stops there.
            // A bounded listing that kept its count is done.
            Some(Ok(_)) if self.left == Some(0) => self.done(),
            Some(Ok(_)) => match last.and_then(|last| last.checked_add(1)) {
                Some(from_id) => {
                    let correlation_id = self.correlation_id();
                    self.step = Step::Sending {
                        correlation_id,
                        from_id,
                    };
                    self.send().unwrap_or(ListPoll::Pending)
                }
                None => self.done(),
            },
            Some(Err((code, message))) => {
                self.step = Step::Idle;
                ListPoll::Refused { code, message }
            }
        }
    }

    fn done(&mut self) -> ListPoll {
        self.step = Step::Idle;
        ListPoll::Done(Listing {
            recordings: std::mem::take(&mut self.kept),
            left_out: std::mem::replace(&mut self.left_out, 0),
        })
    }
}

#[cfg(test)]
mod tests;
