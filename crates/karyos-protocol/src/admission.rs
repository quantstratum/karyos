// SPDX-License-Identifier: Apache-2.0

//! Messages of the admission socket (`quantstratum-docs: karyos/design/ipc-admission.md`), the
//! control-path bootstrap through which a client process receives its
//! shared-memory regions from the driver.
//!
//! One message per `SOCK_SEQPACKET` datagram, a fixed little-endian layout
//! of 64-bit words; word 0 holds the message type. Decoding is strict: the
//! length must match the type (or, for a manifest, its record count),
//! reserved bits and values are rejected, and a manifest holds at most
//! [`MAX_RECORDS`] records. Descriptors travel beside the bytes (`Hello`
//! carries the client's pidfd, `Region` the region); this module only
//! encodes the words.
//!
//! Layouts (words):
//!
//! | Type | Message | Words after the type |
//! | --- | --- | --- |
//! | `0x01` | `Hello` | version; flags (bit 0 first profile accepted, bit 1 no fork while holding anything; both required) |
//! | `0x02` | `Fetch` | fetch id (nonzero); hand-over key |
//! | `0x03` | `Detach` | export id (nonzero) |
//! | `0x04` | `Leave` | none |
//! | `0x81` | `Admitted` | instance (low, high); client id; record count; records |
//! | `0x82` | `Manifest` | fetch id; hand-over key; registration; record count; records |
//! | `0x83` | `Region` | fetch id; record index |
//! | `0x84` | `Refused` | fetch id or 0; code (nonzero) |
//!
//! A record is eight words: region id; export id; kind (bits 0..8) and
//! layout version (bits 8..40); structure length; generation; stream id
//! (low 32) and session id (high 32); lane (bits 0..8) and capability
//! (bits 8..16: 0 none, 1 required subscriber, 2 optional subscriber, 3
//! exclusive publication, 4 concurrent publication); the cell or publisher
//! slot the capability names (0 when none).

use thiserror::Error;

/// The protocol version a client announces in `Hello`.
pub const VERSION: u64 = 1;
/// Most records in one manifest.
pub const MAX_RECORDS: usize = 16;
/// Words of one record.
pub const RECORD_WORDS: usize = 8;
/// Largest encoded message, in bytes: a manifest with [`MAX_RECORDS`].
pub const MAX_MESSAGE_LENGTH: usize = (5 + MAX_RECORDS * RECORD_WORDS) * 8;

const HELLO: u64 = 0x01;
const FETCH: u64 = 0x02;
const DETACH: u64 = 0x03;
const LEAVE: u64 = 0x04;
const ADMITTED: u64 = 0x81;
const MANIFEST: u64 = 0x82;
const REGION: u64 = 0x83;
const REFUSED: u64 = 0x84;

/// `Hello` flags: the first profile accepted, and no fork while holding the
/// socket, a descriptor or a mapping.
const PROFILE_FLAGS: u64 = 0b11;

/// Errors decoding or encoding admission messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AdmissionError {
    /// No type word, or an unknown type.
    #[error("unknown admission message")]
    UnknownType,
    /// The length does not match the type.
    #[error("admission message of {length} bytes, expected {expected}")]
    WrongLength {
        /// The length found.
        length: usize,
        /// The length the type and record count require.
        expected: usize,
    },
    /// A reserved bit or value is set, or a required value is zero.
    #[error("admission message with a reserved or missing value")]
    Reserved,
    /// More records than [`MAX_RECORDS`].
    #[error("manifest of {count} records")]
    TooManyRecords {
        /// The record count found.
        count: u64,
    },
    /// The output buffer is too short.
    #[error("buffer of {available} bytes, {required} required")]
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

/// What a region holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// A client's command ring.
    CommandRing,
    /// The broadcast buffer.
    Broadcast,
    /// The counters.
    Counters,
    /// One log buffer generation.
    LogBuffer,
}

impl RegionKind {
    const fn code(self) -> u64 {
        match self {
            Self::CommandRing => 1,
            Self::Broadcast => 2,
            Self::Counters => 3,
            Self::LogBuffer => 4,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::CommandRing),
            2 => Some(Self::Broadcast),
            3 => Some(Self::Counters),
            4 => Some(Self::LogBuffer),
            _ => None,
        }
    }
}

/// The capability a record grants in its region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// None: a control region.
    None,
    /// A required subscriber registered in `cell`.
    RequiredSubscriber {
        /// The registry cell.
        cell: u64,
    },
    /// An optional subscriber registered in `cell`.
    OptionalSubscriber {
        /// The registry cell.
        cell: u64,
    },
    /// The exclusive publication.
    ExclusivePublication,
    /// A concurrent handle registered in publisher slot `slot`.
    ConcurrentPublication {
        /// The publisher slot.
        slot: u64,
    },
}

impl Capability {
    const fn words(self) -> (u64, u64) {
        match self {
            Self::None => (0, 0),
            Self::RequiredSubscriber { cell } => (1, cell),
            Self::OptionalSubscriber { cell } => (2, cell),
            Self::ExclusivePublication => (3, 0),
            Self::ConcurrentPublication { slot } => (4, slot),
        }
    }

    const fn from_words(code: u64, index: u64) -> Option<Self> {
        match (code, index) {
            (0, 0) => Some(Self::None),
            (1, cell) => Some(Self::RequiredSubscriber { cell }),
            (2, cell) => Some(Self::OptionalSubscriber { cell }),
            (3, 0) => Some(Self::ExclusivePublication),
            (4, slot) => Some(Self::ConcurrentPublication { slot }),
            _ => None,
        }
    }
}

/// One region of a manifest: what the client must find in the region's
/// header, and the capability its grant carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// The region id.
    pub region: u64,
    /// The export id of this grant (nonzero, never reused).
    pub export: u64,
    /// What the region holds.
    pub kind: RegionKind,
    /// The layout version of its structure.
    pub layout: u32,
    /// Bytes of its structure after the header stride.
    pub structure_length: u64,
    /// Its mapping generation.
    pub generation: u64,
    /// Stream id (log buffers; 0 otherwise).
    pub stream_id: i32,
    /// Session id (log buffers; 0 otherwise).
    pub session_id: i32,
    /// Lane (log buffers; 0 otherwise).
    pub lane: u8,
    /// The capability granted.
    pub capability: Capability,
}

impl Record {
    fn words(&self) -> [u64; RECORD_WORDS] {
        let (capability, index) = self.capability.words();
        [
            self.region,
            self.export,
            self.kind.code() | (u64::from(self.layout) << 8),
            self.structure_length,
            self.generation,
            u64::from(self.stream_id.cast_unsigned())
                | (u64::from(self.session_id.cast_unsigned()) << 32),
            u64::from(self.lane) | (capability << 8),
            index,
        ]
    }

    fn from_words(words: &[u64]) -> Result<Self, AdmissionError> {
        let &[
            region,
            export,
            kind,
            structure_length,
            generation,
            identity,
            lane,
            index,
        ] = words
        else {
            return Err(AdmissionError::Reserved);
        };
        if export == 0 || kind >> 40 != 0 || lane >> 16 != 0 {
            return Err(AdmissionError::Reserved);
        }
        Ok(Self {
            region,
            export,
            kind: RegionKind::from_code(kind & 0xFF).ok_or(AdmissionError::Reserved)?,
            layout: (kind >> 8) as u32,
            structure_length,
            generation,
            stream_id: (identity as u32).cast_signed(),
            session_id: ((identity >> 32) as u32).cast_signed(),
            lane: (lane & 0xFF) as u8,
            capability: Capability::from_words(lane >> 8, index).ok_or(AdmissionError::Reserved)?,
        })
    }
}

/// An admission message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// The client's first message, carrying its pidfd.
    Hello {
        /// The protocol version.
        version: u64,
    },
    /// A fetch of the regions waiting for a hand-over key.
    Fetch {
        /// The client's fetch id (nonzero, never reused).
        fetch: u64,
        /// The hand-over key from a `Ready` response.
        key: u64,
    },
    /// The client unmapped the region of an export.
    Detach {
        /// The export id.
        export: u64,
    },
    /// The client is done: every export detached, no fetch open.
    Leave,
    /// The bootstrap answer: fetch 0, the client's CnC regions.
    Admitted {
        /// The driver instance id.
        instance: u128,
        /// The client id.
        client: u64,
        /// The CnC regions.
        records: Vec<Record>,
    },
    /// The regions of a fetch.
    Manifest {
        /// The fetch id it answers.
        fetch: u64,
        /// The hand-over key fetched.
        key: u64,
        /// The registration the regions belong to.
        registration: u64,
        /// The regions.
        records: Vec<Record>,
    },
    /// One region's descriptor follows with this message.
    Region {
        /// The fetch id (0 for the bootstrap).
        fetch: u64,
        /// The record index in the manifest.
        index: u64,
    },
    /// A refusal.
    Refused {
        /// The fetch id refused, or 0.
        fetch: u64,
        /// Why (nonzero).
        code: u64,
    },
}

fn records_words(records: &[Record], words: &mut Vec<u64>) -> Result<(), AdmissionError> {
    if records.len() > MAX_RECORDS {
        return Err(AdmissionError::TooManyRecords {
            count: records.len() as u64,
        });
    }
    words.push(records.len() as u64);
    for record in records {
        words.extend_from_slice(&record.words());
    }
    Ok(())
}

fn records_from(header: usize, words: &[u64]) -> Result<Vec<Record>, AdmissionError> {
    let count = *words.get(header).ok_or(AdmissionError::Reserved)?;
    let records = usize::try_from(count)
        .ok()
        .filter(|count| *count <= MAX_RECORDS)
        .ok_or(AdmissionError::TooManyRecords { count })?;
    let expected = header + 1 + records * RECORD_WORDS;
    if words.len() != expected {
        return Err(AdmissionError::WrongLength {
            length: words.len() * 8,
            expected: expected * 8,
        });
    }
    words
        .get(header + 1..)
        .unwrap_or(&[])
        .as_chunks::<RECORD_WORDS>()
        .0
        .iter()
        .map(|record| Record::from_words(record))
        .collect()
}

impl Message {
    /// The words of the message.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::TooManyRecords`].
    fn words(&self) -> Result<Vec<u64>, AdmissionError> {
        let mut words = Vec::new();
        match self {
            Self::Hello { version } => words.extend([HELLO, *version, PROFILE_FLAGS]),
            Self::Fetch { fetch, key } => words.extend([FETCH, *fetch, *key]),
            Self::Detach { export } => words.extend([DETACH, *export]),
            Self::Leave => words.push(LEAVE),
            Self::Admitted {
                instance,
                client,
                records,
            } => {
                words.extend([
                    ADMITTED,
                    *instance as u64,
                    (*instance >> 64) as u64,
                    *client,
                ]);
                records_words(records, &mut words)?;
            }
            Self::Manifest {
                fetch,
                key,
                registration,
                records,
            } => {
                words.extend([MANIFEST, *fetch, *key, *registration]);
                records_words(records, &mut words)?;
            }
            Self::Region { fetch, index } => words.extend([REGION, *fetch, *index]),
            Self::Refused { fetch, code } => words.extend([REFUSED, *fetch, *code]),
        }
        Ok(words)
    }

    /// Refuses a message that [`Message::decode`] would refuse, so that
    /// every encoded message decodes to itself.
    fn check(&self) -> Result<(), AdmissionError> {
        let records = match self {
            Self::Fetch { fetch: 0, .. }
            | Self::Detach { export: 0 }
            | Self::Manifest { fetch: 0, .. }
            | Self::Refused { code: 0, .. } => return Err(AdmissionError::Reserved),
            Self::Admitted { records, .. } | Self::Manifest { records, .. } => records.as_slice(),
            _ => &[],
        };
        if records.iter().any(|record| record.export == 0) {
            return Err(AdmissionError::Reserved);
        }
        Ok(())
    }

    /// Encodes the message into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Reserved`] for a message that could not be
    /// decoded (a zero fetch id, export id or refusal code),
    /// [`AdmissionError::TooManyRecords`] and
    /// [`AdmissionError::BufferTooShort`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, AdmissionError> {
        self.check()?;
        let words = self.words()?;
        let required = words.len() * 8;
        let available = out.len();
        let target = out
            .get_mut(..required)
            .ok_or(AdmissionError::BufferTooShort {
                required,
                available,
            })?;
        for (chunk, word) in target.as_chunks_mut::<8>().0.iter_mut().zip(&words) {
            *chunk = word.to_le_bytes();
        }
        Ok(required)
    }

    /// Decodes one message.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::UnknownType`],
    /// [`AdmissionError::WrongLength`], [`AdmissionError::Reserved`] and
    /// [`AdmissionError::TooManyRecords`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AdmissionError> {
        let (chunks, rest) = bytes.as_chunks::<8>();
        if !rest.is_empty() || chunks.len() > MAX_MESSAGE_LENGTH / 8 {
            return Err(AdmissionError::WrongLength {
                length: bytes.len(),
                expected: bytes.len() - rest.len(),
            });
        }
        let words: Vec<u64> = chunks
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect();
        let exact = |n: usize| {
            if words.len() == n {
                Ok(())
            } else {
                Err(AdmissionError::WrongLength {
                    length: bytes.len(),
                    expected: n * 8,
                })
            }
        };
        let word = |i: usize| words.get(i).copied().unwrap_or(0);
        match words.first().copied().ok_or(AdmissionError::UnknownType)? {
            HELLO => {
                exact(3)?;
                if word(2) != PROFILE_FLAGS {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Hello { version: word(1) })
            }
            FETCH => {
                exact(3)?;
                if word(1) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Fetch {
                    fetch: word(1),
                    key: word(2),
                })
            }
            DETACH => {
                exact(2)?;
                if word(1) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Detach { export: word(1) })
            }
            LEAVE => {
                exact(1)?;
                Ok(Self::Leave)
            }
            ADMITTED => Ok(Self::Admitted {
                instance: u128::from(word(1)) | (u128::from(word(2)) << 64),
                client: word(3),
                records: records_from(4, &words)?,
            }),
            MANIFEST => {
                if word(1) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Manifest {
                    fetch: word(1),
                    key: word(2),
                    registration: word(3),
                    records: records_from(4, &words)?,
                })
            }
            REGION => {
                exact(3)?;
                Ok(Self::Region {
                    fetch: word(1),
                    index: word(2),
                })
            }
            REFUSED => {
                exact(3)?;
                if word(2) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Refused {
                    fetch: word(1),
                    code: word(2),
                })
            }
            _ => Err(AdmissionError::UnknownType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(export: u64, capability: Capability) -> Record {
        Record {
            region: 9,
            export,
            kind: RegionKind::LogBuffer,
            layout: 1,
            structure_length: 4096,
            generation: 2,
            stream_id: -5,
            session_id: 77,
            lane: 3,
            capability,
        }
    }

    fn round_trip(message: &Message) {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let len = message.encode(&mut out).unwrap();
        assert_eq!(Message::decode(&out[..len]).unwrap(), *message);
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(&Message::Hello { version: VERSION });
        round_trip(&Message::Fetch { fetch: 1, key: 40 });
        round_trip(&Message::Detach { export: 8 });
        round_trip(&Message::Leave);
        round_trip(&Message::Region { fetch: 0, index: 2 });
        round_trip(&Message::Refused { fetch: 3, code: 6 });
        round_trip(&Message::Admitted {
            instance: u128::MAX - 7,
            client: 4,
            records: vec![Record {
                kind: RegionKind::CommandRing,
                capability: Capability::None,
                ..record(1, Capability::None)
            }],
        });
        let capabilities = [
            Capability::None,
            Capability::RequiredSubscriber { cell: 4 },
            Capability::OptionalSubscriber { cell: 0 },
            Capability::ExclusivePublication,
            Capability::ConcurrentPublication { slot: 2 },
        ];
        let records: Vec<Record> = capabilities
            .iter()
            .enumerate()
            .map(|(i, capability)| record(i as u64 + 1, *capability))
            .collect();
        round_trip(&Message::Manifest {
            fetch: 5,
            key: 6,
            registration: 7,
            records,
        });
        round_trip(&Message::Manifest {
            fetch: 5,
            key: 6,
            registration: 7,
            records: vec![record(1, Capability::None); MAX_RECORDS],
        });
    }

    #[test]
    fn decoding_is_strict() {
        let encode = |message: &Message| {
            let mut out = vec![0u8; MAX_MESSAGE_LENGTH];
            let len = message.encode(&mut out).unwrap();
            out.truncate(len);
            out
        };
        let mut hello = encode(&Message::Hello { version: 1 });
        hello[16] = 1;
        assert_eq!(Message::decode(&hello), Err(AdmissionError::Reserved));
        // Raw words that `encode` refuses to produce.
        let raw = |words: &[u64]| -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        };
        for words in [
            vec![FETCH, 0, 1],
            vec![DETACH, 0],
            vec![REFUSED, 1, 0],
            vec![MANIFEST, 0, 1, 2, 0],
        ] {
            assert_eq!(
                Message::decode(&raw(&words)),
                Err(AdmissionError::Reserved),
                "{words:?}"
            );
        }
        let mut leave = encode(&Message::Leave);
        leave.extend([0u8; 8]);
        assert!(matches!(
            Message::decode(&leave),
            Err(AdmissionError::WrongLength { .. })
        ));
        assert_eq!(Message::decode(&[]), Err(AdmissionError::UnknownType));
        assert_eq!(Message::decode(&[7u8; 8]), Err(AdmissionError::UnknownType));
        assert!(matches!(
            Message::decode(&[1u8; 9]),
            Err(AdmissionError::WrongLength { .. })
        ));
        // A manifest whose count disagrees with its records.
        let mut manifest = encode(&Message::Manifest {
            fetch: 1,
            key: 2,
            registration: 3,
            records: vec![record(1, Capability::None); 2],
        });
        manifest[32] = 3;
        assert!(matches!(
            Message::decode(&manifest),
            Err(AdmissionError::WrongLength { .. })
        ));
        manifest[32] = 200;
        assert!(matches!(
            Message::decode(&manifest),
            Err(AdmissionError::TooManyRecords { .. })
        ));
        // A record with export 0, an unknown kind, an unknown capability or
        // an index on a capability without one.
        for (offset, value) in [(48, 0u8), (56, 9), (89, 7), (96, 1)] {
            let mut bad = encode(&Message::Manifest {
                fetch: 1,
                key: 2,
                registration: 3,
                records: vec![record(1, Capability::None)],
            });
            bad[offset] = value;
            assert_eq!(
                Message::decode(&bad),
                Err(AdmissionError::Reserved),
                "byte {offset}"
            );
        }
        // Too many records to encode.
        let mut out = vec![0u8; MAX_MESSAGE_LENGTH + 64];
        assert!(matches!(
            Message::Manifest {
                fetch: 1,
                key: 2,
                registration: 3,
                records: vec![record(1, Capability::None); MAX_RECORDS + 1],
            }
            .encode(&mut out),
            Err(AdmissionError::TooManyRecords { .. })
        ));
        assert!(matches!(
            Message::Leave.encode(&mut []),
            Err(AdmissionError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn what_cannot_be_decoded_is_not_encoded() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        for message in [
            Message::Fetch { fetch: 0, key: 0 },
            Message::Detach { export: 0 },
            Message::Refused { fetch: 1, code: 0 },
            Message::Manifest {
                fetch: 0,
                key: 1,
                registration: 2,
                records: Vec::new(),
            },
            Message::Manifest {
                fetch: 1,
                key: 1,
                registration: 2,
                records: vec![record(0, Capability::None)],
            },
            Message::Admitted {
                instance: 1,
                client: 1,
                records: vec![record(0, Capability::None)],
            },
        ] {
            assert_eq!(
                message.encode(&mut out),
                Err(AdmissionError::Reserved),
                "{message:?}"
            );
        }
    }
}
