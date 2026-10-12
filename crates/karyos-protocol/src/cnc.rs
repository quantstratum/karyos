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

use thiserror::Error;

/// Largest encoded command, in bytes.
pub const MAX_COMMAND_LENGTH: usize = 3 * 8;
/// Largest encoded response, in bytes.
pub const MAX_RESPONSE_LENGTH: usize = 4 * 8;

const ADD_PUBLICATION: u32 = 0x01;
const ADD_SUBSCRIPTION: u32 = 0x02;
const REMOVE_PUBLICATION: u32 = 0x03;
const REMOVE_SUBSCRIPTION: u32 = 0x04;
const PUBLICATION_READY: u32 = 0x81;
const SUBSCRIPTION_READY: u32 = 0x82;
const OPERATION_SUCCEEDED: u32 = 0x83;
const ERROR: u32 = 0x84;

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
    /// Remove a publication the client owns.
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
}

/// Why the driver refused a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The stream already has its publication.
    PublicationTaken,
    /// No such stream.
    UnknownStream,
    /// No such registration owned by this client.
    UnknownRegistration,
    /// A limit (cells, credits, pending requests, hand-over) is reached.
    ResourcesUnavailable,
    /// An identity counter is exhausted.
    IdentitiesExhausted,
}

impl ErrorCode {
    const fn code(self) -> u64 {
        match self {
            Self::PublicationTaken => 1,
            Self::UnknownStream => 2,
            Self::UnknownRegistration => 3,
            Self::ResourcesUnavailable => 4,
            Self::IdentitiesExhausted => 5,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::PublicationTaken,
            2 => Self::UnknownStream,
            3 => Self::UnknownRegistration,
            4 => Self::ResourcesUnavailable,
            5 => Self::IdentitiesExhausted,
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
            Self::AddSubscription { .. } => ADD_SUBSCRIPTION,
            Self::RemovePublication { .. } => REMOVE_PUBLICATION,
            Self::RemoveSubscription { .. } => REMOVE_SUBSCRIPTION,
        }
    }

    /// The request sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match *self {
            Self::AddPublication { sequence, .. }
            | Self::AddSubscription { sequence, .. }
            | Self::RemovePublication { sequence, .. }
            | Self::RemoveSubscription { sequence, .. } => sequence,
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
            ADD_PUBLICATION => {
                let [sequence, stream, flags] = read_words::<3>(type_id, bytes)?;
                if flags & !ALLOW_UNCONNECTED != 0 {
                    return Err(CncError::Reserved { type_id });
                }
                Ok(Self::AddPublication {
                    sequence,
                    stream: stream_from(stream),
                    allow_unconnected: flags == ALLOW_UNCONNECTED,
                })
            }
            ADD_SUBSCRIPTION => {
                let [sequence, stream, role] = read_words::<3>(type_id, bytes)?;
                let role = match role {
                    0 => SubscriberRole::Required,
                    1 => SubscriberRole::Optional,
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
        }
    }

    /// The request answered.
    #[must_use]
    pub const fn request(&self) -> RequestId {
        match *self {
            Self::PublicationReady { request, .. }
            | Self::SubscriptionReady { request, .. }
            | Self::OperationSucceeded { request }
            | Self::Error { request, .. } => request,
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
            Command::RemovePublication {
                sequence: 3,
                registration: 9,
            },
            Command::RemoveSubscription {
                sequence: 4,
                registration: 10,
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
        out[16] = 2;
        assert!(matches!(
            Command::decode(command.type_id(), &out[..length]),
            Err(CncError::Reserved { .. })
        ));
        out[16] = 2;
        assert!(matches!(
            Command::decode(0x01, &out[..length]),
            Err(CncError::Reserved { .. })
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
}
