// SPDX-License-Identifier: Apache-2.0

//! The trace stream (ADR-0117, point 1): the messages `karyosd` publishes
//! from its driver's trace mirror on a local IPC stream, which it records
//! as an ordinary Archive recording, so the Archive can produce time
//! evidence from the observations it holds.
//!
//! Every message is a whole number of little-endian 64-bit words. Word 0
//! is the header: bits 0..32 the magic [`STREAM_MAGIC`] (`KTRS` as bytes),
//! bits 32..40 the layout version [`STREAM_VERSION`], bits 40..48 the
//! kind, and bits 48..64 zero. Each kind has a fixed length:
//!
//! | Kind | Words | Fields after the header |
//! | --- | --- | --- |
//! | 1 self | 9 | the driver's own time namespace word, its time namespace inode, the declared clock (driver id low and high, journal, domain, epoch), its granularity in ns |
//! | 2 facts | 6 | journal, facts generation (nonzero), kind, time namespace word, provenance word |
//! | 3 record | 29 | journal, facts generation in force when read (0: none known), the record's journal sequence, its 25 words |
//! | 4 loss | 4 | journal (0: ring records whose journal is unknown), first and last lost sequence |
//!
//! - **Self** comes first: the namespace word the driver writes for a
//!   journal in its own namespace (T2's `1`), so a reader compares a
//!   journal's facts against it, never infers it; and the clock the
//!   recording declares, all zero when none is declared.
//! - **Facts** are published the first time a journal is seen and at every
//!   change of its kind, namespace or provenance, each change with the
//!   next generation of that journal.
//! - A **record** names the facts generation in force when it was read; a
//!   reader that holds no facts message of that generation before the
//!   record knows nothing about its clock.
//! - A **loss** names records the mirror's ring overwrote before they were
//!   read: by journal and journal sequence when a gap in a journal's
//!   sequences shows them, or with journal 0 by ring sequence when the
//!   ring's boundary does.
//!
//! The layout is pinned by golden vectors (the module's tests). The codec
//! allocates nothing: encoding writes into the caller's buffer.

use crate::record::RECORD_WORDS;

/// The header's magic: the bytes `KTRS`.
pub const STREAM_MAGIC: u32 = u32::from_le_bytes(*b"KTRS");
/// The layout version this codec writes and reads.
pub const STREAM_VERSION: u8 = 1;
/// Words of a self message.
pub const SELF_WORDS: usize = 9;
/// Words of a facts message.
pub const FACTS_WORDS: usize = 6;
/// Words of a record message.
pub const RECORD_MESSAGE_WORDS: usize = 4 + RECORD_WORDS;
/// Words of a loss message.
pub const LOSS_WORDS: usize = 4;
/// The longest message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = RECORD_MESSAGE_WORDS * 8;

const KIND_SELF: u64 = 1;
const KIND_FACTS: u64 = 2;
const KIND_RECORD: u64 = 3;
const KIND_LOSS: u64 = 4;

/// The first message of a trace stream: the driver's own time namespace
/// and the recording's declared clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DriverSelf {
    /// The time namespace word the driver writes in a journal's table
    /// entry for a client in its own namespace (`trace-tool.md` T2: 1).
    pub namespace: u64,
    /// The inode of the driver's time namespace (`/proc/self/ns/time`),
    /// for the record; 0 when unknown.
    pub namespace_inode: u64,
    /// The declared clock `[driver low, driver high, journal, domain,
    /// epoch]`; all zero declares none.
    pub clock: [u64; 5],
    /// The declared clock's granularity, in ns.
    pub granularity: u64,
}

/// A journal's facts, as its table entry gives them (`trace-tool.md` T2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalFacts {
    /// The journal number, nonzero.
    pub journal: u64,
    /// The facts generation, from 1, increased with each change.
    pub generation: u64,
    /// The journal's kind word (1 subscriber, 2 publisher, 3 network
    /// sender, 4 network receiver).
    pub kind: u64,
    /// Its time namespace word (0 unknown, 1 the driver's, 2 another).
    pub time_namespace: u64,
    /// Its clock provenance word, as the client sent it.
    pub provenance: u64,
}

/// One observation record of a journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamRecord {
    /// The journal number, nonzero.
    pub journal: u64,
    /// The facts generation in force when the record was read; 0 when no
    /// facts were known.
    pub generation: u64,
    /// The record's sequence in its journal.
    pub sequence: u64,
    /// The record's words: the observation and its collection stamp.
    pub words: [u64; RECORD_WORDS],
}

/// Records lost before they were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamLoss {
    /// The journal; 0 for ring records whose journal is unknown, named by
    /// ring sequence.
    pub journal: u64,
    /// The first lost sequence.
    pub first: u64,
    /// The last lost sequence, at least `first`.
    pub last: u64,
}

/// One message of the trace stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(
    clippy::large_enum_variant,
    reason = "decoded on the control path and consumed at once; boxing would allocate per message"
)]
pub enum StreamMessage {
    /// The driver's own namespace and the declared clock.
    DriverSelf(DriverSelf),
    /// A journal's facts.
    Facts(JournalFacts),
    /// An observation record.
    Record(StreamRecord),
    /// A loss.
    Loss(StreamLoss),
}

/// Why a message does not encode or decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StreamError {
    /// The buffer is shorter than the message.
    #[error("the buffer holds {have} bytes, the message {need}")]
    Short {
        /// Bytes needed.
        need: usize,
        /// Bytes given.
        have: usize,
    },
    /// The bytes are not a whole number of words, or not the kind's length.
    #[error("a message of {length} bytes is not of its kind's length")]
    Length {
        /// Its length.
        length: usize,
    },
    /// The header names another magic or version, or sets reserved bits.
    #[error("not a trace stream message of layout version {STREAM_VERSION}")]
    Header,
    /// An unknown kind.
    #[error("unknown trace stream message kind {kind}")]
    Kind {
        /// The kind.
        kind: u64,
    },
    /// A field breaks its kind's rules: a zero journal of a facts or
    /// record message, a zero facts generation, or a loss whose last
    /// sequence is before its first.
    #[error("a trace stream message field is out of range")]
    Field,
}

const fn header(kind: u64) -> u64 {
    STREAM_MAGIC as u64 | (STREAM_VERSION as u64) << 32 | kind << 40
}

impl StreamMessage {
    /// The message's length in bytes.
    #[must_use]
    pub const fn length(&self) -> usize {
        8 * match self {
            Self::DriverSelf(_) => SELF_WORDS,
            Self::Facts(_) => FACTS_WORDS,
            Self::Record(_) => RECORD_MESSAGE_WORDS,
            Self::Loss(_) => LOSS_WORDS,
        }
    }

    fn check(&self) -> Result<(), StreamError> {
        let valid = match self {
            Self::DriverSelf(_) => true,
            Self::Facts(facts) => facts.journal != 0 && facts.generation != 0,
            Self::Record(record) => record.journal != 0,
            Self::Loss(loss) => loss.first <= loss.last,
        };
        if valid { Ok(()) } else { Err(StreamError::Field) }
    }

    /// Encodes the message into `out`; returns its length.
    ///
    /// # Errors
    ///
    /// [`StreamError::Short`] and [`StreamError::Field`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, StreamError> {
        self.check()?;
        let length = self.length();
        let have = out.len();
        let out = out.get_mut(..length).ok_or(StreamError::Short {
            need: length,
            have,
        })?;
        let mut put = |words: &mut dyn Iterator<Item = u64>| {
            for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
                *chunk = word.to_le_bytes();
            }
        };
        match self {
            Self::DriverSelf(own) => put(&mut [
                header(KIND_SELF),
                own.namespace,
                own.namespace_inode,
            ]
            .into_iter()
            .chain(own.clock)
            .chain([own.granularity])),
            Self::Facts(facts) => put(&mut [
                header(KIND_FACTS),
                facts.journal,
                facts.generation,
                facts.kind,
                facts.time_namespace,
                facts.provenance,
            ]
            .into_iter()),
            Self::Record(record) => put(&mut [
                header(KIND_RECORD),
                record.journal,
                record.generation,
                record.sequence,
            ]
            .into_iter()
            .chain(record.words)),
            Self::Loss(loss) => put(&mut [header(KIND_LOSS), loss.journal, loss.first, loss.last]
                .into_iter()),
        }
        Ok(length)
    }

    /// Decodes one whole message.
    ///
    /// # Errors
    ///
    /// [`StreamError::Length`], [`StreamError::Header`],
    /// [`StreamError::Kind`] and [`StreamError::Field`].
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        let (chunks, rest) = bytes.as_chunks::<8>();
        if !rest.is_empty() || chunks.is_empty() {
            return Err(StreamError::Length {
                length: bytes.len(),
            });
        }
        let word = |index: usize| chunks.get(index).map_or(0, |chunk| u64::from_le_bytes(*chunk));
        let head = word(0);
        let kind = head >> 40 & 0xFF;
        if head & 0xFFFF_FFFF != u64::from(STREAM_MAGIC)
            || head >> 32 & 0xFF != u64::from(STREAM_VERSION)
            || head >> 48 != 0
        {
            return Err(StreamError::Header);
        }
        let words = match kind {
            KIND_SELF => SELF_WORDS,
            KIND_FACTS => FACTS_WORDS,
            KIND_RECORD => RECORD_MESSAGE_WORDS,
            KIND_LOSS => LOSS_WORDS,
            kind => return Err(StreamError::Kind { kind }),
        };
        if chunks.len() != words {
            return Err(StreamError::Length {
                length: bytes.len(),
            });
        }
        let message = match kind {
            KIND_SELF => Self::DriverSelf(DriverSelf {
                namespace: word(1),
                namespace_inode: word(2),
                clock: [word(3), word(4), word(5), word(6), word(7)],
                granularity: word(8),
            }),
            KIND_FACTS => Self::Facts(JournalFacts {
                journal: word(1),
                generation: word(2),
                kind: word(3),
                time_namespace: word(4),
                provenance: word(5),
            }),
            KIND_RECORD => {
                let mut words = [0u64; RECORD_WORDS];
                for (index, value) in words.iter_mut().enumerate() {
                    *value = word(index.saturating_add(4));
                }
                Self::Record(StreamRecord {
                    journal: word(1),
                    generation: word(2),
                    sequence: word(3),
                    words,
                })
            }
            _ => Self::Loss(StreamLoss {
                journal: word(1),
                first: word(2),
                last: word(3),
            }),
        };
        message.check()?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests;
