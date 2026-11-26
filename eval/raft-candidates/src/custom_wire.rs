// SPDX-License-Identifier: Apache-2.0

//! The custom core's messages between real processes (C5 v2, "Processes";
//! quantstratum-docs: karyos/evaluations/c5-raft-comparison-v2.md): the
//! encoding of `karyos_sim::harness::custom::Message`, the core's
//! [`CoreMessage`] and an append's entries, for the real-process runner
//! ([`crate::process`]).
//!
//! A message is a tag byte, then its fields as little-endian `u64`s (a
//! `bool` as one byte, 0 or 1), then, for every message, the entries: a
//! `u32` count and, per entry, its index, term and event time as `u64`s,
//! a `u32` payload length and the payload. Decoding is strict: an
//! unknown tag, a `bool` other than 0 or 1, a short or a long datagram
//! is not a message. The format is the runner's, not the core's: the
//! custom core defines no wire form, and nothing here is shipped.

use karyos_cluster::Entry;
use karyos_cluster::consensus::{AppendOutcome, Message as CoreMessage};
use karyos_sim::harness::custom::{Custom, Message};

use crate::process::Wire;

const PRE_VOTE: u8 = 0;
const PRE_VOTE_REPLY: u8 = 1;
const VOTE: u8 = 2;
const VOTE_REPLY: u8 = 3;
const APPEND: u8 = 4;
const APPEND_REPLY: u8 = 5;
const ACCEPTED: u8 = 0;
const REJECTED: u8 = 1;

/// `message` in the runner's form; `None` when an entry's count or a
/// payload's length does not fit its `u32`.
#[must_use]
pub fn encode(message: &Message) -> Option<Vec<u8>> {
    let payloads: usize = message
        .entries
        .iter()
        .map(|entry| entry.payload.len())
        .sum();
    let mut out = Vec::with_capacity(
        64_usize
            .saturating_add(message.entries.len().saturating_mul(28))
            .saturating_add(payloads),
    );
    let words = |out: &mut Vec<u8>, words: &[u64]| {
        for word in words {
            out.extend_from_slice(&word.to_le_bytes());
        }
    };
    match message.core {
        CoreMessage::PreVote {
            term,
            last_index,
            last_term,
            round,
        } => {
            out.push(PRE_VOTE);
            words(&mut out, &[term, last_index, last_term, round]);
        }
        CoreMessage::PreVoteReply {
            term,
            granted,
            round,
        } => {
            out.push(PRE_VOTE_REPLY);
            words(&mut out, &[term]);
            out.push(u8::from(granted));
            words(&mut out, &[round]);
        }
        CoreMessage::Vote {
            term,
            last_index,
            last_term,
        } => {
            out.push(VOTE);
            words(&mut out, &[term, last_index, last_term]);
        }
        CoreMessage::VoteReply { term, granted } => {
            out.push(VOTE_REPLY);
            words(&mut out, &[term]);
            out.push(u8::from(granted));
        }
        CoreMessage::Append {
            term,
            prev_index,
            prev_term,
            entries,
            commit,
            epoch,
        } => {
            out.push(APPEND);
            words(
                &mut out,
                &[term, prev_index, prev_term, entries, commit, epoch],
            );
        }
        CoreMessage::AppendReply {
            term,
            outcome,
            epoch,
        } => {
            out.push(APPEND_REPLY);
            words(&mut out, &[term, epoch]);
            match outcome {
                AppendOutcome::Accepted { index } => {
                    out.push(ACCEPTED);
                    words(&mut out, &[index]);
                }
                AppendOutcome::Rejected { probe, hint } => {
                    out.push(REJECTED);
                    words(&mut out, &[probe, hint]);
                }
            }
        }
    }
    out.extend_from_slice(&u32::try_from(message.entries.len()).ok()?.to_le_bytes());
    for entry in &message.entries {
        words(&mut out, &[entry.index, entry.term, entry.event_time]);
        out.extend_from_slice(&u32::try_from(entry.payload.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&entry.payload);
    }
    Some(out)
}

/// A reader over a datagram that fails on the first short read.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn bytes(&mut self, count: usize) -> Option<&[u8]> {
        let (head, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(head)
    }

    fn byte(&mut self) -> Option<u8> {
        self.bytes(1)?.first().copied()
    }

    fn flag(&mut self) -> Option<bool> {
        match self.byte()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn word(&mut self) -> Option<u64> {
        <[u8; 8]>::try_from(self.bytes(8)?)
            .ok()
            .map(u64::from_le_bytes)
    }

    fn length(&mut self) -> Option<usize> {
        let length = <[u8; 4]>::try_from(self.bytes(4)?)
            .ok()
            .map(u32::from_le_bytes)?;
        usize::try_from(length).ok()
    }
}

/// The message in `bytes`; `None` when they are not exactly one.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<Message> {
    let mut reader = Reader(bytes);
    let core = match reader.byte()? {
        PRE_VOTE => CoreMessage::PreVote {
            term: reader.word()?,
            last_index: reader.word()?,
            last_term: reader.word()?,
            round: reader.word()?,
        },
        PRE_VOTE_REPLY => CoreMessage::PreVoteReply {
            term: reader.word()?,
            granted: reader.flag()?,
            round: reader.word()?,
        },
        VOTE => CoreMessage::Vote {
            term: reader.word()?,
            last_index: reader.word()?,
            last_term: reader.word()?,
        },
        VOTE_REPLY => CoreMessage::VoteReply {
            term: reader.word()?,
            granted: reader.flag()?,
        },
        APPEND => CoreMessage::Append {
            term: reader.word()?,
            prev_index: reader.word()?,
            prev_term: reader.word()?,
            entries: reader.word()?,
            commit: reader.word()?,
            epoch: reader.word()?,
        },
        APPEND_REPLY => {
            let term = reader.word()?;
            let epoch = reader.word()?;
            let outcome = match reader.byte()? {
                ACCEPTED => AppendOutcome::Accepted {
                    index: reader.word()?,
                },
                REJECTED => AppendOutcome::Rejected {
                    probe: reader.word()?,
                    hint: reader.word()?,
                },
                _ => return None,
            };
            CoreMessage::AppendReply {
                term,
                outcome,
                epoch,
            }
        }
        _ => return None,
    };
    let count = reader.length()?;
    // Each entry takes at least 28 bytes: a count past what the datagram
    // can hold is refused before anything is reserved for it.
    if count > reader.0.len() / 28 {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let index = reader.word()?;
        let term = reader.word()?;
        let event_time = reader.word()?;
        let length = reader.length()?;
        let payload = reader.bytes(length)?.to_vec();
        entries.push(Entry {
            index,
            term,
            event_time,
            payload,
        });
    }
    reader.0.is_empty().then_some(Message { core, entries })
}

impl Wire for Custom {
    fn encode(message: &Message) -> Option<Vec<u8>> {
        encode(message)
    }

    fn decode(bytes: &[u8]) -> Option<Message> {
        decode(bytes)
    }

    /// The adapter's pool gave out its appends' entries and vectors: they
    /// come back to it through the Ready buffer once sent (C5 v3).
    const RECLAIMS_SENT: bool = true;

    fn appended(message: &Message) -> Option<(u64, Vec<(u64, u64)>)> {
        let CoreMessage::Append { term, .. } = message.core else {
            return None;
        };
        Some((
            term,
            message
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.index,
                        u64::try_from(entry.payload.len()).unwrap_or(u64::MAX),
                    )
                })
                .collect(),
        ))
    }

    fn acknowledged(message: &Message) -> Option<(u64, u64)> {
        match message.core {
            CoreMessage::AppendReply {
                term,
                outcome: AppendOutcome::Accepted { index },
                ..
            } => Some((term, index)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_message() -> Vec<Message> {
        let entry = |index: u64, payload: &[u8]| Entry {
            index,
            term: 3,
            event_time: 1_000 + index,
            payload: payload.to_vec(),
        };
        let bare = |core| Message {
            core,
            entries: Vec::new(),
        };
        vec![
            bare(CoreMessage::PreVote {
                term: 4,
                last_index: 9,
                last_term: 3,
                round: 2,
            }),
            bare(CoreMessage::PreVoteReply {
                term: 4,
                granted: true,
                round: 2,
            }),
            bare(CoreMessage::Vote {
                term: 4,
                last_index: 9,
                last_term: 3,
            }),
            bare(CoreMessage::VoteReply {
                term: 4,
                granted: false,
            }),
            Message {
                core: CoreMessage::Append {
                    term: 4,
                    prev_index: 9,
                    prev_term: 3,
                    entries: 2,
                    commit: 8,
                    epoch: 7,
                },
                entries: vec![entry(10, b"ten"), entry(11, b"")],
            },
            bare(CoreMessage::AppendReply {
                term: 4,
                outcome: AppendOutcome::Accepted { index: 11 },
                epoch: 7,
            }),
            bare(CoreMessage::AppendReply {
                term: 4,
                outcome: AppendOutcome::Rejected { probe: 5, hint: 6 },
                epoch: 7,
            }),
        ]
    }

    #[test]
    fn every_message_decodes_to_itself() {
        for message in every_message() {
            let bytes = encode(&message);
            assert_eq!(bytes.as_deref().and_then(decode), Some(message));
        }
    }

    /// Strict decoding: every proper prefix, a trailing byte, an unknown
    /// tag, a `bool` other than 0 or 1 and an entry count past the
    /// datagram are refused.
    #[test]
    fn anything_but_exactly_one_message_is_refused() {
        for message in every_message() {
            let Some(bytes) = encode(&message) else {
                panic!("{message:?}");
            };
            for cut in 0..bytes.len() {
                assert_eq!(bytes.get(..cut).and_then(decode), None, "{cut}");
            }
            let mut long = bytes.clone();
            long.push(0);
            assert_eq!(decode(&long), None);
        }
        assert_eq!(decode(&[9]), None);
        let Some(mut reply) = encode(&every_message()[3]) else {
            panic!("a vote reply encodes");
        };
        if let Some(flag) = reply.get_mut(9) {
            *flag = 2;
        }
        assert_eq!(decode(&reply), None);
        let Some(mut vote) = encode(&every_message()[2]) else {
            panic!("a vote encodes");
        };
        let count = vote.len() - 4;
        vote.truncate(count);
        vote.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&vote), None);
    }
}
