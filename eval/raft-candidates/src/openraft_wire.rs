// SPDX-License-Identifier: Apache-2.0

//! The bytes of the `openraft` adapter's messages between real processes
//! (karyos#959 review: the adapter runs unchanged in real processes).
//!
//! OpenRaft serialises its RPCs only with its `serde` feature, which the
//! admission does not include, so the adapter encodes them itself: a tag
//! byte per variant, little-endian `u64`s, `u32` lengths. Only what the
//! adapter sends is encoded: append, vote, pre-vote and handover requests
//! and their answers, and entries whose membership is one voter set
//! (static membership; a joint configuration is refused).

use std::collections::BTreeSet;
use std::sync::Arc;

use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, TransferLeaderError, TransferLeaderRequest,
    VoteRequest, VoteResponse,
};
use openraft::{EntryPayload, Membership};

use crate::openraft_core::{Command, Message, Request, Response, TypeConfig};

type C = TypeConfig;
type OEntry = <C as openraft::RaftTypeConfig>::Entry;
type OVote = <C as openraft::RaftTypeConfig>::Vote;
type Clid = <<C as openraft::RaftTypeConfig>::LeaderId as openraft::vote::RaftLeaderId>::Committed;
type OLogId = openraft::LogId<Clid>;

/// Encodes `message`; `None` for what the adapter never sends (a joint
/// membership).
#[must_use]
pub fn encode(message: &Message) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match message {
        Message::Request {
            id,
            incarnation,
            request,
        } => {
            out.push(0);
            u64_to(&mut out, *id);
            u64_to(&mut out, *incarnation);
            request_to(&mut out, request)?;
        }
        Message::Response {
            id,
            incarnation,
            request,
            response,
        } => {
            out.push(1);
            u64_to(&mut out, *id);
            u64_to(&mut out, *incarnation);
            request_to(&mut out, request)?;
            match response {
                None => out.push(0),
                Some(response) => {
                    out.push(1);
                    response_to(&mut out, response);
                }
            }
        }
    }
    Some(out)
}

/// Decodes a message; `None` for bytes that are not exactly one.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<Message> {
    let mut input = Reader { bytes };
    let message = match input.u8()? {
        0 => Message::Request {
            id: input.u64()?,
            incarnation: input.u64()?,
            request: input.request()?,
        },
        1 => Message::Response {
            id: input.u64()?,
            incarnation: input.u64()?,
            request: input.request()?,
            response: match input.u8()? {
                0 => None,
                1 => Some(input.response()?),
                _ => return None,
            },
        },
        _ => return None,
    };
    input.bytes.is_empty().then_some(message)
}

/// The request's bytes: equal bytes are an equal request.
#[must_use]
pub fn request_bytes(request: &Request) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    request_to(&mut out, request)?;
    Some(out)
}

/// The answer's bytes: equal bytes are an equal answer.
#[must_use]
pub fn response_bytes(response: &Response) -> Vec<u8> {
    let mut out = Vec::new();
    response_to(&mut out, response);
    out
}

fn u64_to(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn len_to(out: &mut Vec<u8>, len: usize) -> Option<()> {
    out.extend_from_slice(&u32::try_from(len).ok()?.to_le_bytes());
    Some(())
}

fn log_id_to(out: &mut Vec<u8>, log_id: Option<&OLogId>) {
    match log_id {
        None => out.push(0),
        Some(log_id) => {
            out.push(1);
            u64_to(out, log_id.leader_id.term);
            u64_to(out, log_id.index);
        }
    }
}

fn vote_to(out: &mut Vec<u8>, vote: &OVote) {
    u64_to(out, vote.leader_id.term);
    u64_to(out, vote.leader_id.voted_for);
    out.push(u8::from(vote.committed));
}

fn entry_to(out: &mut Vec<u8>, entry: &OEntry) -> Option<()> {
    log_id_to(out, Some(&entry.log_id));
    match &entry.payload {
        EntryPayload::Blank => out.push(0),
        EntryPayload::Normal(command) => {
            out.push(1);
            len_to(out, command.0.len())?;
            out.extend_from_slice(&command.0);
        }
        EntryPayload::Membership(membership) => {
            let [voters] = membership.get_joint_config().as_slice() else {
                return None;
            };
            out.push(2);
            len_to(out, voters.len())?;
            for voter in voters {
                u64_to(out, *voter);
            }
        }
    }
    Some(())
}

fn request_to(out: &mut Vec<u8>, request: &Request) -> Option<()> {
    match request {
        Request::Append(rpc) => {
            out.push(0);
            vote_to(out, &rpc.vote);
            log_id_to(out, rpc.prev_log_id.as_ref());
            len_to(out, rpc.entries.len())?;
            for entry in &rpc.entries {
                entry_to(out, entry)?;
            }
            log_id_to(out, rpc.leader_commit.as_ref());
        }
        Request::Vote(rpc) | Request::PreVote(rpc) => {
            out.push(if matches!(request, Request::Vote(_)) {
                1
            } else {
                2
            });
            vote_to(out, &rpc.vote);
            log_id_to(out, rpc.last_log_id.as_ref());
            out.push(u8::from(rpc.leadership_transfer));
        }
        Request::TransferLeader(rpc) => {
            out.push(3);
            vote_to(out, rpc.from_leader());
            u64_to(out, *rpc.to_node_id());
            log_id_to(out, rpc.last_log_id());
        }
    }
    Some(())
}

fn response_to(out: &mut Vec<u8>, response: &Response) {
    match response {
        Response::Append(answer) => {
            out.push(0);
            match answer.as_ref() {
                AppendEntriesResponse::Success => out.push(0),
                AppendEntriesResponse::PartialSuccess(matching) => {
                    out.push(1);
                    log_id_to(out, matching.as_ref());
                }
                AppendEntriesResponse::Conflict => out.push(2),
                AppendEntriesResponse::HigherVote(vote) => {
                    out.push(3);
                    vote_to(out, vote);
                }
            }
        }
        Response::Vote(answer) => {
            out.push(1);
            vote_to(out, &answer.vote);
            out.push(u8::from(answer.vote_granted));
            log_id_to(out, answer.last_log_id.as_ref());
        }
        Response::TransferLeader(answer) => {
            out.push(2);
            // Each refusal keeps its own code and fields, so it crosses the
            // wire as the value OpenRaft returned (karyos#959 review).
            match answer.as_ref() {
                Ok(()) => out.push(0),
                Err(TransferLeaderError::VoteChanged { expected, actual }) => {
                    out.push(1);
                    vote_to(out, expected);
                    vote_to(out, actual);
                }
                Err(TransferLeaderError::LogNotFlushed { expected, actual }) => {
                    out.push(2);
                    log_id_to(out, expected.as_ref());
                    log_id_to(out, actual.as_ref());
                }
            }
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Option<&[u8]> {
        let (head, tail) = self.bytes.split_at_checked(count)?;
        self.bytes = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn u64(&mut self) -> Option<u64> {
        <[u8; 8]>::try_from(self.take(8)?)
            .ok()
            .map(u64::from_le_bytes)
    }

    fn len(&mut self) -> Option<usize> {
        let raw = <[u8; 4]>::try_from(self.take(4)?).ok()?;
        usize::try_from(u32::from_le_bytes(raw)).ok()
    }

    fn log_id(&mut self) -> Option<Option<OLogId>> {
        match self.u8()? {
            0 => Some(None),
            1 => {
                let term = self.u64()?;
                let index = self.u64()?;
                Some(Some(openraft::LogId::new(Clid::new(term), index)))
            }
            _ => None,
        }
    }

    fn vote(&mut self) -> Option<OVote> {
        let term = self.u64()?;
        let voted_for = self.u64()?;
        let committed = self.bool()?;
        Some(OVote {
            leader_id: openraft::impls::leader_id_std::LeaderId { term, voted_for },
            committed,
        })
    }

    fn entry(&mut self) -> Option<OEntry> {
        let log_id = self.log_id()??;
        let payload = match self.u8()? {
            0 => EntryPayload::Blank,
            1 => {
                let len = self.len()?;
                EntryPayload::Normal(Command(self.take(len)?.to_vec()))
            }
            2 => {
                let count = self.len()?;
                // Each voter is 8 bytes: a count the input cannot hold is
                // refused before anything is allocated for it.
                if count > self.bytes.len() / 8 {
                    return None;
                }
                let mut voters = BTreeSet::new();
                for _ in 0..count {
                    let _ = voters.insert(self.u64()?);
                }
                EntryPayload::Membership(Membership::new_with_defaults(vec![voters], []))
            }
            _ => return None,
        };
        Some(OEntry { log_id, payload })
    }

    fn request(&mut self) -> Option<Request> {
        Some(match self.u8()? {
            0 => {
                let vote = self.vote()?;
                let prev_log_id = self.log_id()?;
                let count = self.len()?;
                // An entry is at least 18 bytes.
                if count > self.bytes.len() / 18 {
                    return None;
                }
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(self.entry()?);
                }
                let leader_commit = self.log_id()?;
                Request::Append(Arc::new(AppendEntriesRequest {
                    vote,
                    prev_log_id,
                    entries,
                    leader_commit,
                }))
            }
            tag @ (1 | 2) => {
                let vote = self.vote()?;
                let last_log_id = self.log_id()?;
                let mut rpc = VoteRequest::new(vote, last_log_id);
                rpc.leadership_transfer = self.bool()?;
                let rpc = Arc::new(rpc);
                if tag == 1 {
                    Request::Vote(rpc)
                } else {
                    Request::PreVote(rpc)
                }
            }
            3 => {
                let vote = self.vote()?;
                let to = self.u64()?;
                let last_log_id = self.log_id()?;
                Request::TransferLeader(Arc::new(TransferLeaderRequest::new(vote, to, last_log_id)))
            }
            _ => return None,
        })
    }

    fn response(&mut self) -> Option<Response> {
        Some(match self.u8()? {
            0 => Response::Append(Arc::new(match self.u8()? {
                0 => AppendEntriesResponse::Success,
                1 => AppendEntriesResponse::PartialSuccess(self.log_id()?),
                2 => AppendEntriesResponse::Conflict,
                3 => AppendEntriesResponse::HigherVote(self.vote()?),
                _ => return None,
            })),
            1 => {
                let vote = self.vote()?;
                let granted = self.bool()?;
                let last_log_id = self.log_id()?;
                Response::Vote(Arc::new(VoteResponse::new(vote, last_log_id, granted)))
            }
            2 => Response::TransferLeader(Arc::new(match self.u8()? {
                0 => Ok(()),
                1 => Err(TransferLeaderError::VoteChanged {
                    expected: self.vote()?,
                    actual: self.vote()?,
                }),
                2 => Err(TransferLeaderError::LogNotFlushed {
                    expected: self.log_id()?,
                    actual: self.log_id()?,
                }),
                _ => return None,
            })),
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(term: u64) -> OVote {
        OVote {
            leader_id: openraft::impls::leader_id_std::LeaderId { term, voted_for: 1 },
            committed: true,
        }
    }

    fn append() -> Request {
        let log_id = |index| Some(openraft::LogId::new(Clid::new(3), index));
        Request::Append(Arc::new(AppendEntriesRequest {
            vote: vote(3),
            prev_log_id: log_id(4),
            entries: vec![
                OEntry {
                    log_id: openraft::LogId::new(Clid::new(3), 5),
                    payload: EntryPayload::Blank,
                },
                OEntry {
                    log_id: openraft::LogId::new(Clid::new(3), 6),
                    payload: EntryPayload::Normal(Command(vec![1, 2, 3])),
                },
                OEntry {
                    log_id: openraft::LogId::new(Clid::new(3), 7),
                    payload: EntryPayload::Membership(Membership::new_with_defaults(
                        vec![[0, 1, 2].into_iter().collect()],
                        [],
                    )),
                },
            ],
            leader_commit: log_id(5),
        }))
    }

    fn round_trip(message: &Message) {
        let bytes = encode(message).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(encode(&decoded).unwrap(), bytes);
        // The values too, not only their bytes (karyos#959 review).
        assert_eq!(&decoded, message);
        // Every proper prefix is refused, never read past its end.
        for cut in 0..bytes.len() {
            assert!(decode(&bytes[..cut]).is_none(), "prefix {cut}");
        }
        // As are trailing bytes.
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode(&longer).is_none());
    }

    #[test]
    fn every_message_the_adapter_sends_round_trips() {
        let vote_request = Arc::new(VoteRequest::new(vote(4), None));
        for request in [
            append(),
            Request::Vote(Arc::clone(&vote_request)),
            Request::PreVote(vote_request),
            Request::TransferLeader(Arc::new(TransferLeaderRequest::new(vote(4), 2, None))),
        ] {
            round_trip(&Message::Request {
                id: 9,
                incarnation: 0x0102_0304_0506_0708,
                request: request.clone(),
            });
            round_trip(&Message::Response {
                id: 9,
                incarnation: 0x0102_0304_0506_0708,
                request,
                response: None,
            });
        }
        for response in [
            Response::Append(Arc::new(AppendEntriesResponse::Success)),
            Response::Append(Arc::new(AppendEntriesResponse::PartialSuccess(None))),
            Response::Append(Arc::new(AppendEntriesResponse::Conflict)),
            Response::Append(Arc::new(AppendEntriesResponse::HigherVote(vote(8)))),
            Response::Vote(Arc::new(VoteResponse::new(vote(4), None, true))),
            Response::TransferLeader(Arc::new(Ok(()))),
            Response::TransferLeader(Arc::new(Err(TransferLeaderError::VoteChanged {
                expected: vote(4),
                actual: vote(5),
            }))),
            Response::TransferLeader(Arc::new(Err(TransferLeaderError::LogNotFlushed {
                expected: Some(openraft::LogId::new(Clid::new(4), 9)),
                actual: None,
            }))),
        ] {
            round_trip(&Message::Response {
                id: 1,
                incarnation: 0x0102_0304_0506_0708,
                request: append(),
                response: Some(response),
            });
        }
    }

    #[test]
    fn a_count_the_input_cannot_hold_is_refused_before_allocating() {
        let mut bytes = encode(&Message::Request {
            id: 1,
            incarnation: 0x0102_0304_0506_0708,
            request: append(),
        })
        .unwrap();
        // The entry count follows tag, id, incarnation, request tag, vote and prev log id.
        let at = 1 + 8 + 8 + 1 + 17 + 17;
        bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&bytes).is_none());
    }
}
