// SPDX-License-Identifier: Apache-2.0

//! Client commands and driver responses carried by the CnC structures
//! (SPEC.md §3; quantstratum-docs: karyos/design/client-commands.md).
//!
//! Every message is a fixed little-endian layout of 64-bit words, identified
//! by the record type of the command ring or broadcast buffer. Decoding is
//! strict: the length must match the type exactly, and reserved bits and
//! values are rejected, because commands come from untrusted clients.
//!
//! A command carries only the client's request sequence; the driver knows
//! the sender from the ring it read the command from and forms the
//! [`RequestId`]. Responses carry the full [`RequestId`].
//!
//! Layouts (type id: words, each a little-endian `u64`):
//!
//! | Type | Message | Word 0 | Word 1 | Word 2 | Word 3 |
//! | --- | --- | --- | --- | --- | --- |
//! | `0x01` | `AddPublication` | sequence | stream id (low 32) and session id (high 32) | flags: bit 0 allow unconnected, others zero | |
//! | `0x02` | `AddSubscription` | sequence | stream and session as above | role: 0 required, 1 optional | |
//! | `0x03` | `RemovePublication` | sequence | registration | | |
//! | `0x04` | `RemoveSubscription` | sequence | registration | | |
//! | `0x05` | `AddConcurrentPublication` | sequence | stream and session as above | flags as `AddPublication` | |
//! | `0x06` | `AllocateCounter` | sequence | type id | stream registration or 0 | participant registration or 0 |
//! | `0x07` | `ReleaseCounter` | sequence | cell | registration | |
//! | `0x81` | `PublicationReady` | client | sequence | registration | hand-over key |
//! | `0x82` | `SubscriptionReady` | client | sequence | registration | hand-over key |
//! | `0x83` | `OperationSucceeded` | client | sequence | | |
//! | `0x84` | `Error` | client | sequence | code (1 to 6, see [`ErrorCode`]) | detail |
//! | `0x85` | `CounterAllocated` | client | sequence | cell | registration |
//!
//! `AllocateCounter` (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Client counters") continues
//! after its four words with the label: word 4 is its length in bytes (at
//! most [`MAX_LABEL_LENGTH`], the other bits zero), and words 5 to 12 hold
//! its UTF-8 bytes, padded with zero bytes.
//!
//! Driver events (record types `0xC0` to `0xFF`, [`Event`]) answer no
//! request and are broadcast to every client:
//!
//! | Type | Event | Word 0 | Word 1 | Word 2 | Word 3 | Word 4 |
//! | --- | --- | --- | --- | --- | --- | --- |
//! | `0xC1` | `ParticipantLost` | stream and session | registration | client | policy: 1 hold, 2 continue, 3 abort | position |
//! | `0xC2` | `RequiredBoundWithdrawn` | stream and session | registration | position | | |
//! | `0xC3` | `PublicationClosed` | stream and session | reason: 1 required participant lost | | | |
//! | `0xC4` | `SuccessorReady` | stream and session | registration | hand-over key of the successor grant | base position | generation |
//! | `0xC5` | `Fenced` | stream and session | registration | | | |

use thiserror::Error;

/// Longest counter label, in bytes: the label of a counter cell.
pub const MAX_LABEL_LENGTH: usize = karyos_sys::counters::MAX_LABEL_LENGTH;
/// Words of an encoded counter label.
const LABEL_WORDS: usize = MAX_LABEL_LENGTH / 8;
/// Words of an encoded `AllocateCounter`: four, the label length and the
/// label.
const ALLOCATE_COUNTER_WORDS: usize = 5 + LABEL_WORDS;
/// Largest encoded command, in bytes: `AllocateCounter`.
pub const MAX_COMMAND_LENGTH: usize = ALLOCATE_COUNTER_WORDS * 8;
/// Largest encoded response, in bytes.
pub const MAX_RESPONSE_LENGTH: usize = 4 * 8;
/// Largest encoded driver event, in bytes.
pub const MAX_EVENT_LENGTH: usize = 5 * 8;

const ADD_PUBLICATION: u32 = 0x01;
const ADD_SUBSCRIPTION: u32 = 0x02;
const REMOVE_PUBLICATION: u32 = 0x03;
const REMOVE_SUBSCRIPTION: u32 = 0x04;
const ADD_CONCURRENT_PUBLICATION: u32 = 0x05;
const ALLOCATE_COUNTER: u32 = 0x06;
const RELEASE_COUNTER: u32 = 0x07;
const PUBLICATION_READY: u32 = 0x81;
const SUBSCRIPTION_READY: u32 = 0x82;
const OPERATION_SUCCEEDED: u32 = 0x83;
const ERROR: u32 = 0x84;
const COUNTER_ALLOCATED: u32 = 0x85;
const PARTICIPANT_LOST: u32 = 0xC1;
const REQUIRED_BOUND_WITHDRAWN: u32 = 0xC2;
const PUBLICATION_CLOSED: u32 = 0xC3;
const SUCCESSOR_READY: u32 = 0xC4;
const FENCED: u32 = 0xC5;

const ALLOW_UNCONNECTED: u64 = 1;

/// Errors decoding or encoding CnC messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CncError {
    /// The record type is not a message of this direction.
    #[error("unknown message type {type_id:#x}")]
    UnknownType {
        /// The record type.
        type_id: u32,
    },
    /// The length does not match the type's fixed layout.
    #[error("message type {type_id:#x} has {length} bytes, expected {expected}")]
    WrongLength {
        /// The record type.
        type_id: u32,
        /// The length found.
        length: usize,
        /// The layout's length.
        expected: usize,
    },
    /// A reserved bit or value is set.
    #[error("message type {type_id:#x} sets a reserved value")]
    Reserved {
        /// The record type.
        type_id: u32,
    },
    /// The output buffer is too short.
    #[error("buffer of {available} bytes is shorter than the required {required}")]
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

/// A subscriber's role (SPEC.md §4 reader roles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriberRole {
    /// Bounds the publisher; never lapped.
    Required,
    /// Does not bound the publisher; may be lapped.
    Optional,
    /// Does not bound the publisher, may be lapped, and only copies
    /// (`quantstratum-docs: karyos/design/observer-role.md`).
    Observer,
}

impl From<SubscriberRole> for karyos_sys::log_buffer::Role {
    fn from(role: SubscriberRole) -> Self {
        match role {
            SubscriberRole::Required => Self::Required,
            SubscriberRole::Optional => Self::Optional,
            SubscriberRole::Observer => Self::Observer,
        }
    }
}

/// A request, identified by the client (as known to the driver) and the
/// client's request sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId {
    /// The driver-assigned client id.
    pub client: u64,
    /// The client's request sequence.
    pub sequence: u64,
}

/// A stream's wire identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    /// Wire stream id.
    pub stream_id: i32,
    /// Session id.
    pub session_id: i32,
}

/// The label of a client counter: UTF-8 of at most [`MAX_LABEL_LENGTH`]
/// bytes, stored inline so that [`Command`] stays `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CounterLabel {
    bytes: [u8; MAX_LABEL_LENGTH],
    length: u8,
}

impl CounterLabel {
    /// The label `label`; `None` when it exceeds [`MAX_LABEL_LENGTH`]
    /// bytes.
    #[must_use]
    pub fn new(label: &str) -> Option<Self> {
        Self::from_bytes(label.as_bytes())
    }

    /// The label of `bytes`; `None` unless they are UTF-8 of at most
    /// [`MAX_LABEL_LENGTH`] bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        core::str::from_utf8(bytes).ok()?;
        let length = u8::try_from(bytes.len())
            .ok()
            .filter(|&length| usize::from(length) <= MAX_LABEL_LENGTH)?;
        let mut stored = [0u8; MAX_LABEL_LENGTH];
        stored.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self {
            bytes: stored,
            length,
        })
    }

    /// The label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only UTF-8 is ever stored (checked by every constructor).
        self.bytes
            .get(..usize::from(self.length))
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

/// A command from a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Create the stream's exclusive publication.
    AddPublication {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream: StreamKey,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// Admit a subscriber to the stream.
    AddSubscription {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream: StreamKey,
        /// The subscriber's role.
        role: SubscriberRole,
    },
    /// Issue a concurrent publication handle on one of the stream's
    /// publisher slots.
    AddConcurrentPublication {
        /// Request sequence.
        sequence: u64,
        /// The stream.
        stream: StreamKey,
        /// Accept offers with no subscriber attached.
        allow_unconnected: bool,
    },
    /// Remove a publication of either kind the client owns.
    RemovePublication {
        /// Request sequence.
        sequence: u64,
        /// The registration.
        registration: u64,
    },
    /// Remove a subscription the client owns.
    RemoveSubscription {
        /// Request sequence.
        sequence: u64,
        /// The registration.
        registration: u64,
    },
    /// Allocate a client counter cell, owned by the client, in the client
    /// counters region (`quantstratum-docs:
    /// karyos/design/observability-and-tools.md`, "Client counters").
    AllocateCounter {
        /// Request sequence.
        sequence: u64,
        /// Application-defined counter type.
        type_id: u64,
        /// The counter's label.
        label: CounterLabel,
        /// Registration of a live stream, or 0.
        stream: u64,
        /// Registration of a live participant of this client, or 0.
        participant: u64,
    },
    /// Release the client counter allocation `registration` in `cell`.
    ReleaseCounter {
        /// Request sequence.
        sequence: u64,
        /// The cell.
        cell: u64,
        /// The allocation's registration.
        registration: u64,
    },
}

/// Why the driver refused a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Every publication the stream can issue is out: its exclusive
    /// publication, or all publisher slots of a concurrent stream.
    PublicationTaken,
    /// No such stream.
    UnknownStream,
    /// No such registration owned by this client.
    UnknownRegistration,
    /// A limit (cells, credits, pending requests, hand-over) is reached.
    ResourcesUnavailable,
    /// An identity counter is exhausted.
    IdentitiesExhausted,
    /// The requested publication kind does not match the stream's mode.
    InvalidPublicationMode,
}

impl ErrorCode {
    const fn code(self) -> u64 {
        match self {
            Self::PublicationTaken => 1,
            Self::UnknownStream => 2,
            Self::UnknownRegistration => 3,
            Self::ResourcesUnavailable => 4,
            Self::IdentitiesExhausted => 5,
            Self::InvalidPublicationMode => 6,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::PublicationTaken,
            2 => Self::UnknownStream,
            3 => Self::UnknownRegistration,
            4 => Self::ResourcesUnavailable,
            5 => Self::IdentitiesExhausted,
            6 => Self::InvalidPublicationMode,
            _ => return None,
        })
    }
}

/// A driver response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// The publication is ready for hand-over.
    PublicationReady {
        /// The request.
        request: RequestId,
        /// The new registration.
        registration: u64,
        /// The hand-over key.
        key: u64,
    },
    /// The subscription is ready for hand-over.
    SubscriptionReady {
        /// The request.
        request: RequestId,
        /// The new registration.
        registration: u64,
        /// The hand-over key.
        key: u64,
    },
    /// The command succeeded and returns nothing.
    OperationSucceeded {
        /// The request.
        request: RequestId,
    },
    /// The command was refused; it had no effect.
    Error {
        /// The request.
        request: RequestId,
        /// Why.
        code: ErrorCode,
        /// A bounded detail value (for example the stream id).
        detail: u64,
    },
    /// A client counter cell was allocated for the client.
    CounterAllocated {
        /// The request.
        request: RequestId,
        /// The cell in the client counters region.
        cell: u64,
        /// The allocation's fresh registration.
        registration: u64,
    },
}

fn stream_word(stream: StreamKey) -> u64 {
    u64::from(stream.stream_id.cast_unsigned())
        | (u64::from(stream.session_id.cast_unsigned()) << 32)
}

fn stream_from(word: u64) -> StreamKey {
    StreamKey {
        stream_id: (word as u32).cast_signed(),
        session_id: ((word >> 32) as u32).cast_signed(),
    }
}

fn write_words(words: &[u64], out: &mut [u8]) -> Result<usize, CncError> {
    let required = words.len() * 8;
    let available = out.len();
    let target = out.get_mut(..required).ok_or(CncError::BufferTooShort {
        required,
        available,
    })?;
    for (chunk, word) in target.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    Ok(required)
}

/// Reads exactly `N` words.
fn read_words<const N: usize>(type_id: u32, bytes: &[u8]) -> Result<[u64; N], CncError> {
    if bytes.len() != N * 8 {
        return Err(CncError::WrongLength {
            type_id,
            length: bytes.len(),
            expected: N * 8,
        });
    }
    let mut words = [0u64; N];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    Ok(words)
}

impl Command {
    /// The record type of this command.
    #[must_use]
    pub const fn type_id(&self) -> u32 {
        match self {
            Self::AddPublication { .. } => ADD_PUBLICATION,
            Self::AddConcurrentPublication { .. } => ADD_CONCURRENT_PUBLICATION,
            Self::AddSubscription { .. } => ADD_SUBSCRIPTION,
            Self::RemovePublication { .. } => REMOVE_PUBLICATION,
            Self::RemoveSubscription { .. } => REMOVE_SUBSCRIPTION,
            Self::AllocateCounter { .. } => ALLOCATE_COUNTER,
            Self::ReleaseCounter { .. } => RELEASE_COUNTER,
        }
    }

    /// The request sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match *self {
            Self::AddPublication { sequence, .. }
            | Self::AddConcurrentPublication { sequence, .. }
            | Self::AddSubscription { sequence, .. }
            | Self::RemovePublication { sequence, .. }
            | Self::RemoveSubscription { sequence, .. }
            | Self::AllocateCounter { sequence, .. }
            | Self::ReleaseCounter { sequence, .. } => sequence,
        }
    }

    /// Encodes the command into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CncError> {
        match *self {
            Self::AddPublication {
                sequence,
                stream,
                allow_unconnected,
            }
            | Self::AddConcurrentPublication {
                sequence,
                stream,
                allow_unconnected,
            } => write_words(
                &[sequence, stream_word(stream), u64::from(allow_unconnected)],
                out,
            ),
            Self::AddSubscription {
                sequence,
                stream,
                role,
            } => {
                let role = match role {
                    SubscriberRole::Required => 0,
                    SubscriberRole::Optional => 1,
                    SubscriberRole::Observer => 2,
                };
                write_words(&[sequence, stream_word(stream), role], out)
            }
            Self::RemovePublication {
                sequence,
                registration,
            }
            | Self::RemoveSubscription {
                sequence,
                registration,
            } => write_words(&[sequence, registration], out),
            Self::AllocateCounter {
                sequence,
                type_id,
                label,
                stream,
                participant,
            } => {
                let mut words = [0u64; ALLOCATE_COUNTER_WORDS];
                let (head, tail) = words.split_at_mut(5);
                head.copy_from_slice(&[
                    sequence,
                    type_id,
                    stream,
                    participant,
                    u64::from(label.length),
                ]);
                for (word, chunk) in tail.iter_mut().zip(label.bytes.as_chunks::<8>().0) {
                    *word = u64::from_le_bytes(*chunk);
                }
                write_words(&words, out)
            }
            Self::ReleaseCounter {
                sequence,
                cell,
                registration,
            } => write_words(&[sequence, cell, registration], out),
        }
    }

    /// Decodes a command of record type `type_id`.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::UnknownType`], [`CncError::WrongLength`] and
    /// [`CncError::Reserved`].
    pub fn decode(type_id: u32, bytes: &[u8]) -> Result<Self, CncError> {
        match type_id {
            ADD_PUBLICATION | ADD_CONCURRENT_PUBLICATION => {
                let [sequence, stream, flags] = read_words::<3>(type_id, bytes)?;
                if flags & !ALLOW_UNCONNECTED != 0 {
                    return Err(CncError::Reserved { type_id });
                }
                let stream = stream_from(stream);
                let allow_unconnected = flags == ALLOW_UNCONNECTED;
                Ok(if type_id == ADD_PUBLICATION {
                    Self::AddPublication {
                        sequence,
                        stream,
                        allow_unconnected,
                    }
                } else {
                    Self::AddConcurrentPublication {
                        sequence,
                        stream,
                        allow_unconnected,
                    }
                })
            }
            ADD_SUBSCRIPTION => {
                let [sequence, stream, role] = read_words::<3>(type_id, bytes)?;
                let role = match role {
                    0 => SubscriberRole::Required,
                    1 => SubscriberRole::Optional,
                    2 => SubscriberRole::Observer,
                    _ => return Err(CncError::Reserved { type_id }),
                };
                Ok(Self::AddSubscription {
                    sequence,
                    stream: stream_from(stream),
                    role,
                })
            }
            REMOVE_PUBLICATION => {
                let [sequence, registration] = read_words::<2>(type_id, bytes)?;
                Ok(Self::RemovePublication {
                    sequence,
                    registration,
                })
            }
            REMOVE_SUBSCRIPTION => {
                let [sequence, registration] = read_words::<2>(type_id, bytes)?;
                Ok(Self::RemoveSubscription {
                    sequence,
                    registration,
                })
            }
            ALLOCATE_COUNTER => {
                let words = read_words::<ALLOCATE_COUNTER_WORDS>(type_id, bytes)?;
                let reserved = CncError::Reserved { type_id };
                let [sequence, counter_type, stream, participant, length] =
                    *words.first_chunk::<5>().ok_or(reserved)?;
                let length = usize::try_from(length)
                    .ok()
                    .filter(|&length| length <= MAX_LABEL_LENGTH)
                    .ok_or(reserved)?;
                let mut label = [0u8; MAX_LABEL_LENGTH];
                for (chunk, word) in label
                    .as_chunks_mut::<8>()
                    .0
                    .iter_mut()
                    .zip(words.iter().skip(5))
                {
                    *chunk = word.to_le_bytes();
                }
                // The padding after the label is zero.
                let (text, padding) = label.split_at(length);
                if padding.iter().any(|byte| *byte != 0) {
                    return Err(reserved);
                }
                Ok(Self::AllocateCounter {
                    sequence,
                    type_id: counter_type,
                    label: CounterLabel::from_bytes(text).ok_or(reserved)?,
                    stream,
                    participant,
                })
            }
            RELEASE_COUNTER => {
                let [sequence, cell, registration] = read_words::<3>(type_id, bytes)?;
                Ok(Self::ReleaseCounter {
                    sequence,
                    cell,
                    registration,
                })
            }
            _ => Err(CncError::UnknownType { type_id }),
        }
    }
}

impl Response {
    /// The record type of this response.
    #[must_use]
    pub const fn type_id(&self) -> u32 {
        match self {
            Self::PublicationReady { .. } => PUBLICATION_READY,
            Self::SubscriptionReady { .. } => SUBSCRIPTION_READY,
            Self::OperationSucceeded { .. } => OPERATION_SUCCEEDED,
            Self::Error { .. } => ERROR,
            Self::CounterAllocated { .. } => COUNTER_ALLOCATED,
        }
    }

    /// The request answered.
    #[must_use]
    pub const fn request(&self) -> RequestId {
        match *self {
            Self::PublicationReady { request, .. }
            | Self::SubscriptionReady { request, .. }
            | Self::OperationSucceeded { request }
            | Self::Error { request, .. }
            | Self::CounterAllocated { request, .. } => request,
        }
    }

    /// Encodes the response into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CncError> {
        match *self {
            Self::PublicationReady {
                request,
                registration,
                key,
            }
            | Self::SubscriptionReady {
                request,
                registration,
                key,
            } => write_words(&[request.client, request.sequence, registration, key], out),
            Self::OperationSucceeded { request } => {
                write_words(&[request.client, request.sequence], out)
            }
            Self::Error {
                request,
                code,
                detail,
            } => write_words(
                &[request.client, request.sequence, code.code(), detail],
                out,
            ),
            Self::CounterAllocated {
                request,
                cell,
                registration,
            } => write_words(&[request.client, request.sequence, cell, registration], out),
        }
    }

    /// Decodes a response of record type `type_id`.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::UnknownType`], [`CncError::WrongLength`] and
    /// [`CncError::Reserved`].
    pub fn decode(type_id: u32, bytes: &[u8]) -> Result<Self, CncError> {
        match type_id {
            PUBLICATION_READY | SUBSCRIPTION_READY => {
                let [client, sequence, registration, key] = read_words::<4>(type_id, bytes)?;
                let request = RequestId { client, sequence };
                Ok(if type_id == PUBLICATION_READY {
                    Self::PublicationReady {
                        request,
                        registration,
                        key,
                    }
                } else {
                    Self::SubscriptionReady {
                        request,
                        registration,
                        key,
                    }
                })
            }
            OPERATION_SUCCEEDED => {
                let [client, sequence] = read_words::<2>(type_id, bytes)?;
                Ok(Self::OperationSucceeded {
                    request: RequestId { client, sequence },
                })
            }
            ERROR => {
                let [client, sequence, code, detail] = read_words::<4>(type_id, bytes)?;
                let code = ErrorCode::from_code(code).ok_or(CncError::Reserved { type_id })?;
                Ok(Self::Error {
                    request: RequestId { client, sequence },
                    code,
                    detail,
                })
            }
            COUNTER_ALLOCATED => {
                let [client, sequence, cell, registration] = read_words::<4>(type_id, bytes)?;
                Ok(Self::CounterAllocated {
                    request: RequestId { client, sequence },
                    cell,
                    registration,
                })
            }
            _ => Err(CncError::UnknownType { type_id }),
        }
    }
}

/// What `on_required_loss` did with a lost required participant
/// (quantstratum-docs: `karyos/design/required-participant-loss.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LossPolicyCode {
    /// `hold`: it keeps bounding the publisher until its loan ends.
    Hold,
    /// `continue`: its bound was withdrawn at once.
    Continue,
    /// `abort`: the publication was sealed.
    Abort,
}

impl LossPolicyCode {
    const fn code(self) -> u64 {
        match self {
            Self::Hold => 1,
            Self::Continue => 2,
            Self::Abort => 3,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Hold),
            2 => Some(Self::Continue),
            3 => Some(Self::Abort),
            _ => None,
        }
    }
}

/// Why a publication was closed, reported with its `Closed` outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// A required participant was lost under the `abort` policy.
    RequiredParticipantLost,
}

impl CloseReason {
    const fn code(self) -> u64 {
        match self {
            Self::RequiredParticipantLost => 1,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::RequiredParticipantLost),
            _ => None,
        }
    }
}

/// A driver event on the broadcast buffer: not an answer to a request, so
/// every client sees it (quantstratum-docs:
/// `karyos/design/required-participant-loss.md`, Reporting). A client that
/// does not know an event type skips it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A participant of a lost client was handled by the stream's
    /// `on_required_loss` policy, at the time out, under every policy.
    ParticipantLost {
        /// The stream.
        stream: StreamKey,
        /// The participant's registration.
        registration: u64,
        /// Its client.
        client: u64,
        /// The policy applied.
        policy: LossPolicyCode,
        /// Its last published position.
        position: u64,
    },
    /// A lost `hold` participant stopped bounding the publisher: a scan
    /// after its revocation found its loan ended. It may never come for a
    /// participant paused with a loan.
    RequiredBoundWithdrawn {
        /// The stream.
        stream: StreamKey,
        /// The participant's registration.
        registration: u64,
        /// Its last published position.
        position: u64,
    },
    /// The stream's publication was closed for `reason`.
    PublicationClosed {
        /// The stream.
        stream: StreamKey,
        /// Why.
        reason: CloseReason,
    },
    /// A cutover opened on a stream where a remote client holds
    /// `registration` (`quantstratum-docs: karyos/design/ipc-data-path.md`,
    /// Generations across processes): its successor participant is reserved
    /// under a new grant, which the client fetches with `key` and adopts
    /// when its handle reaches the predecessor's seal.
    SuccessorReady {
        /// The stream.
        stream: StreamKey,
        /// The registration whose handle moves.
        registration: u64,
        /// The hand-over key of the successor grant.
        key: u64,
        /// The stream position where the successor starts.
        base: u64,
        /// The successor's mapping generation.
        generation: u64,
    },
    /// The driver fenced `registration`'s successor at the cutover
    /// deadline: its adoption fails and its handle reports `Closed`.
    Fenced {
        /// The stream.
        stream: StreamKey,
        /// The registration fenced.
        registration: u64,
    },
}

impl Event {
    /// The record type of this event.
    #[must_use]
    pub const fn type_id(&self) -> u32 {
        match self {
            Self::ParticipantLost { .. } => PARTICIPANT_LOST,
            Self::RequiredBoundWithdrawn { .. } => REQUIRED_BOUND_WITHDRAWN,
            Self::PublicationClosed { .. } => PUBLICATION_CLOSED,
            Self::SuccessorReady { .. } => SUCCESSOR_READY,
            Self::Fenced { .. } => FENCED,
        }
    }

    /// Whether `type_id` is an event's record type (as opposed to a
    /// response's).
    #[must_use]
    pub const fn is_event_type(type_id: u32) -> bool {
        type_id & 0xC0 == 0xC0
    }

    /// Encodes the event into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CncError> {
        match *self {
            Self::ParticipantLost {
                stream,
                registration,
                client,
                policy,
                position,
            } => write_words(
                &[
                    stream_word(stream),
                    registration,
                    client,
                    policy.code(),
                    position,
                ],
                out,
            ),
            Self::RequiredBoundWithdrawn {
                stream,
                registration,
                position,
            } => write_words(&[stream_word(stream), registration, position], out),
            Self::PublicationClosed { stream, reason } => {
                write_words(&[stream_word(stream), reason.code()], out)
            }
            Self::SuccessorReady {
                stream,
                registration,
                key,
                base,
                generation,
            } => write_words(
                &[stream_word(stream), registration, key, base, generation],
                out,
            ),
            Self::Fenced {
                stream,
                registration,
            } => write_words(&[stream_word(stream), registration], out),
        }
    }

    /// Decodes an event of record type `type_id`.
    ///
    /// # Errors
    ///
    /// Returns [`CncError::UnknownType`], [`CncError::WrongLength`] and
    /// [`CncError::Reserved`].
    pub fn decode(type_id: u32, bytes: &[u8]) -> Result<Self, CncError> {
        match type_id {
            PARTICIPANT_LOST => {
                let [stream, registration, client, policy, position] =
                    read_words::<5>(type_id, bytes)?;
                Ok(Self::ParticipantLost {
                    stream: stream_from(stream),
                    registration,
                    client,
                    policy: LossPolicyCode::from_code(policy)
                        .ok_or(CncError::Reserved { type_id })?,
                    position,
                })
            }
            REQUIRED_BOUND_WITHDRAWN => {
                let [stream, registration, position] = read_words::<3>(type_id, bytes)?;
                Ok(Self::RequiredBoundWithdrawn {
                    stream: stream_from(stream),
                    registration,
                    position,
                })
            }
            PUBLICATION_CLOSED => {
                let [stream, reason] = read_words::<2>(type_id, bytes)?;
                Ok(Self::PublicationClosed {
                    stream: stream_from(stream),
                    reason: CloseReason::from_code(reason).ok_or(CncError::Reserved { type_id })?,
                })
            }
            SUCCESSOR_READY => {
                let [stream, registration, key, base, generation] =
                    read_words::<5>(type_id, bytes)?;
                Ok(Self::SuccessorReady {
                    stream: stream_from(stream),
                    registration,
                    key,
                    base,
                    generation,
                })
            }
            FENCED => {
                let [stream, registration] = read_words::<2>(type_id, bytes)?;
                Ok(Self::Fenced {
                    stream: stream_from(stream),
                    registration,
                })
            }
            _ => Err(CncError::UnknownType { type_id }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream() -> StreamKey {
        StreamKey {
            stream_id: -2,
            session_id: i32::MAX,
        }
    }

    #[test]
    fn commands_round_trip() {
        let commands = [
            Command::AddPublication {
                sequence: 1,
                stream: stream(),
                allow_unconnected: true,
            },
            Command::AddSubscription {
                sequence: u64::MAX,
                stream: stream(),
                role: SubscriberRole::Optional,
            },
            Command::AddSubscription {
                sequence: 5,
                stream: stream(),
                role: SubscriberRole::Observer,
            },
            Command::AddConcurrentPublication {
                sequence: 2,
                stream: stream(),
                allow_unconnected: false,
            },
            Command::RemovePublication {
                sequence: 3,
                registration: 9,
            },
            Command::RemoveSubscription {
                sequence: 4,
                registration: 10,
            },
            Command::AllocateCounter {
                sequence: 5,
                type_id: u64::MAX,
                label: CounterLabel::new("loss reports dropped").unwrap(),
                stream: 11,
                participant: 12,
            },
            Command::AllocateCounter {
                sequence: 6,
                type_id: 1,
                label: CounterLabel::new("").unwrap(),
                stream: 0,
                participant: 0,
            },
            Command::AllocateCounter {
                sequence: 7,
                type_id: 2,
                label: CounterLabel::new(&"\u{e9}".repeat(32)).unwrap(),
                stream: 0,
                participant: 0,
            },
            Command::ReleaseCounter {
                sequence: 8,
                cell: 3,
                registration: 13,
            },
        ];
        for command in commands {
            let mut out = [0u8; MAX_COMMAND_LENGTH];
            let length = command.encode(&mut out).unwrap();
            assert_eq!(
                Command::decode(command.type_id(), &out[..length]),
                Ok(command)
            );
        }
    }

    #[test]
    fn responses_round_trip() {
        let request = RequestId {
            client: 7,
            sequence: 8,
        };
        let responses = [
            Response::PublicationReady {
                request,
                registration: 1,
                key: 2,
            },
            Response::SubscriptionReady {
                request,
                registration: 3,
                key: 4,
            },
            Response::OperationSucceeded { request },
            Response::Error {
                request,
                code: ErrorCode::ResourcesUnavailable,
                detail: 5,
            },
            Response::Error {
                request,
                code: ErrorCode::InvalidPublicationMode,
                detail: 6,
            },
            Response::CounterAllocated {
                request,
                cell: 7,
                registration: 8,
            },
        ];
        for response in responses {
            let mut out = [0u8; MAX_RESPONSE_LENGTH];
            let length = response.encode(&mut out).unwrap();
            assert_eq!(
                Response::decode(response.type_id(), &out[..length]),
                Ok(response)
            );
            assert_eq!(response.request(), request);
        }
    }

    /// Literal bytes, so a layout change cannot hide behind a matching
    /// encoder and decoder.
    #[test]
    fn golden_bytes() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AddPublication {
            sequence: 0x0102,
            stream: StreamKey {
                stream_id: -2,
                session_id: 7,
            },
            allow_unconnected: true,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                0x02, 0x01, 0, 0, 0, 0, 0, 0, // sequence
                0xfe, 0xff, 0xff, 0xff, 7, 0, 0, 0, // stream -2, session 7
                1, 0, 0, 0, 0, 0, 0, 0, // allow unconnected
            ]
        );
        let mut out = [0u8; MAX_RESPONSE_LENGTH];
        let length = Response::Error {
            request: RequestId {
                client: 3,
                sequence: 4,
            },
            code: ErrorCode::UnknownRegistration,
            detail: 0x0506,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                3, 0, 0, 0, 0, 0, 0, 0, // client
                4, 0, 0, 0, 0, 0, 0, 0, // sequence
                3, 0, 0, 0, 0, 0, 0, 0, // code: unknown registration
                0x06, 0x05, 0, 0, 0, 0, 0, 0, // detail
            ]
        );
        assert_eq!(
            Command::AddSubscription {
                sequence: 0,
                stream: StreamKey {
                    stream_id: 0,
                    session_id: 0
                },
                role: SubscriberRole::Optional
            }
            .type_id(),
            0x02
        );
        assert_eq!(
            Response::OperationSucceeded {
                request: RequestId {
                    client: 0,
                    sequence: 0
                }
            }
            .type_id(),
            0x83
        );
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AddConcurrentPublication {
            sequence: 0x0102,
            stream: StreamKey {
                stream_id: -2,
                session_id: 7,
            },
            allow_unconnected: false,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                0x02, 0x01, 0, 0, 0, 0, 0, 0, // sequence
                0xfe, 0xff, 0xff, 0xff, 7, 0, 0, 0, // stream -2, session 7
                0, 0, 0, 0, 0, 0, 0, 0, // flags
            ]
        );
        assert_eq!(ErrorCode::InvalidPublicationMode.code(), 6);
        let mut response = [0u8; MAX_RESPONSE_LENGTH];
        response[16] = 6;
        assert!(matches!(
            Response::decode(0x84, &response),
            Ok(Response::Error {
                code: ErrorCode::InvalidPublicationMode,
                ..
            })
        ));
    }

    #[test]
    fn decoding_is_strict() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let command = Command::AddSubscription {
            sequence: 1,
            stream: stream(),
            role: SubscriberRole::Required,
        };
        let length = command.encode(&mut out).unwrap();
        // Wrong length, unknown type, reserved role and flag values.
        assert!(matches!(
            Command::decode(command.type_id(), &out[..length - 8]),
            Err(CncError::WrongLength { .. })
        ));
        assert!(matches!(
            Command::decode(0x81, &out[..length]),
            Err(CncError::UnknownType { .. })
        ));
        out[16] = 3;
        assert!(matches!(
            Command::decode(command.type_id(), &out[..length]),
            Err(CncError::Reserved { .. })
        ));
        out[16] = 2;
        assert!(matches!(
            Command::decode(0x01, &out[..length]),
            Err(CncError::Reserved { .. })
        ));
        assert!(matches!(
            Command::decode(0x05, &out[..length]),
            Err(CncError::Reserved { .. })
        ));
        assert!(matches!(
            Command::decode(0x08, &out[..length]),
            Err(CncError::UnknownType { .. })
        ));
        let mut response = [0u8; MAX_RESPONSE_LENGTH];
        response[16] = 99;
        assert!(matches!(
            Response::decode(0x84, &response),
            Err(CncError::Reserved { .. })
        ));
        assert_eq!(
            Command::RemovePublication {
                sequence: 1,
                registration: 1
            }
            .encode(&mut [0u8; 15]),
            Err(CncError::BufferTooShort {
                required: 16,
                available: 15
            })
        );
    }

    #[test]
    fn counter_labels_are_bounded_utf8() {
        assert_eq!(
            CounterLabel::new("bytes sent").unwrap().as_str(),
            "bytes sent"
        );
        assert_eq!(
            CounterLabel::new(&"x".repeat(64)).unwrap().as_str().len(),
            64
        );
        assert!(CounterLabel::new(&"x".repeat(65)).is_none());
        assert!(CounterLabel::from_bytes(&[0xFF, 0xFE]).is_none());
        assert!(CounterLabel::from_bytes(b"ok").is_some());
        // The largest command fits the bound exactly.
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AllocateCounter {
            sequence: 1,
            type_id: 1,
            label: CounterLabel::new(&"x".repeat(64)).unwrap(),
            stream: 0,
            participant: 0,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(length, MAX_COMMAND_LENGTH);
        assert_eq!(MAX_COMMAND_LENGTH, 104);
    }

    /// Literal bytes of the counter messages.
    #[test]
    fn counter_golden_bytes() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::AllocateCounter {
            sequence: 0x0102,
            type_id: 4,
            label: CounterLabel::new("ab").unwrap(),
            stream: 5,
            participant: 6,
        }
        .encode(&mut out)
        .unwrap();
        let mut expected = vec![
            0x02, 0x01, 0, 0, 0, 0, 0, 0, // sequence
            4, 0, 0, 0, 0, 0, 0, 0, // type id
            5, 0, 0, 0, 0, 0, 0, 0, // stream
            6, 0, 0, 0, 0, 0, 0, 0, // participant
            2, 0, 0, 0, 0, 0, 0, 0, // label length
            b'a', b'b', 0, 0, 0, 0, 0, 0, // label
        ];
        expected.resize(MAX_COMMAND_LENGTH, 0);
        assert_eq!(&out[..length], &expected[..]);
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let length = Command::ReleaseCounter {
            sequence: 1,
            cell: 2,
            registration: 3,
        }
        .encode(&mut out)
        .unwrap();
        assert_eq!(
            &out[..length],
            &[
                1, 0, 0, 0, 0, 0, 0, 0, // sequence
                2, 0, 0, 0, 0, 0, 0, 0, // cell
                3, 0, 0, 0, 0, 0, 0, 0, // registration
            ]
        );
        let response = Response::CounterAllocated {
            request: RequestId {
                client: 1,
                sequence: 2,
            },
            cell: 3,
            registration: 4,
        };
        assert_eq!(response.type_id(), 0x85);
        let mut out = [0u8; MAX_RESPONSE_LENGTH];
        assert_eq!(response.encode(&mut out), Ok(MAX_RESPONSE_LENGTH));
    }

    #[test]
    fn counter_commands_are_decoded_strictly() {
        let mut out = [0u8; MAX_COMMAND_LENGTH];
        let command = Command::AllocateCounter {
            sequence: 1,
            type_id: 1,
            label: CounterLabel::new("abc").unwrap(),
            stream: 0,
            participant: 0,
        };
        let length = command.encode(&mut out).unwrap();
        assert_eq!(Command::decode(0x06, &out[..length]), Ok(command));
        // Wrong lengths.
        assert!(matches!(
            Command::decode(0x06, &out[..length - 8]),
            Err(CncError::WrongLength { .. })
        ));
        let mut longer = [0u8; MAX_COMMAND_LENGTH + 8];
        longer[..length].copy_from_slice(&out[..length]);
        assert!(matches!(
            Command::decode(0x06, &longer),
            Err(CncError::WrongLength { .. })
        ));
        assert!(matches!(
            Command::decode(0x07, &out[..16]),
            Err(CncError::WrongLength { .. })
        ));
        // A label length above 64, or with high bits set.
        for (byte, value) in [(32usize, 65u8), (33, 1)] {
            let mut bad = out;
            bad[byte] = value;
            assert_eq!(
                Command::decode(0x06, &bad[..length]),
                Err(CncError::Reserved { type_id: 0x06 }),
                "byte {byte} = {value}"
            );
        }
        // Nonzero padding after the label.
        let mut bad = out;
        bad[40 + 3] = b'd';
        assert_eq!(
            Command::decode(0x06, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x06 })
        );
        bad[103] = 1;
        bad[40 + 3] = 0;
        assert_eq!(
            Command::decode(0x06, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x06 })
        );
        // A label that is not UTF-8.
        let mut bad = out;
        bad[40] = 0xFF;
        assert_eq!(
            Command::decode(0x06, &bad[..length]),
            Err(CncError::Reserved { type_id: 0x06 })
        );
        // A response type is no command, and a counter response decodes
        // only at its exact length.
        assert!(matches!(
            Command::decode(0x85, &out[..32]),
            Err(CncError::UnknownType { .. })
        ));
        assert!(matches!(
            Response::decode(0x85, &out[..24]),
            Err(CncError::WrongLength { .. })
        ));
    }

    #[test]
    fn events_round_trip_and_are_told_apart_from_responses() {
        let events = [
            Event::ParticipantLost {
                stream: stream(),
                registration: 7,
                client: 3,
                policy: LossPolicyCode::Continue,
                position: 4096,
            },
            Event::RequiredBoundWithdrawn {
                stream: stream(),
                registration: 7,
                position: 8192,
            },
            Event::PublicationClosed {
                stream: stream(),
                reason: CloseReason::RequiredParticipantLost,
            },
            Event::SuccessorReady {
                stream: stream(),
                registration: 7,
                key: 9,
                base: 1 << 40,
                generation: 3,
            },
            Event::Fenced {
                stream: stream(),
                registration: 7,
            },
        ];
        for event in events {
            let mut out = [0u8; MAX_EVENT_LENGTH];
            let length = event.encode(&mut out).unwrap();
            assert!(Event::is_event_type(event.type_id()));
            assert_eq!(Event::decode(event.type_id(), &out[..length]), Ok(event));
            // A response decoder does not take an event.
            assert!(Response::decode(event.type_id(), &out[..length]).is_err());
        }
        for response_type in [
            PUBLICATION_READY,
            SUBSCRIPTION_READY,
            OPERATION_SUCCEEDED,
            ERROR,
            COUNTER_ALLOCATED,
        ] {
            assert!(!Event::is_event_type(response_type));
        }
        // Unknown policy and reason codes are refused.
        let mut out = [0u8; 64];
        let length = Event::PublicationClosed {
            stream: stream(),
            reason: CloseReason::RequiredParticipantLost,
        }
        .encode(&mut out)
        .unwrap();
        out[8] = 9;
        assert!(Event::decode(PUBLICATION_CLOSED, &out[..length]).is_err());
    }
}
