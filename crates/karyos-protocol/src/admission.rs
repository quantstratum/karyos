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
//! | `0x81` | `Admitted` | instance (low, high); protocol version; client id; record count; records |
//! | `0x82` | `Manifest` | fetch id; hand-over key; registration; stream registration (nonzero); incarnation (nonzero); record count; records |
//! | `0x83` | `Region` | fetch id; record index |
//! | `0x84` | `Refused` | fetch id or 0; code (nonzero) |
//!
//! **Versions.** The client announces its protocol version in `Hello`;
//! the driver answers `Admitted` carrying the version it runs (equal to the
//! client's), or `Refused` with [`refusal::INCOMPATIBLE_VERSION`]. The
//! first two words of `Hello` (type, version) and the whole `Refused`
//! layout are fixed for every version, so a driver can read the version of
//! any `Hello` with [`hello_version`] and refuse it in a form every client
//! can decode.
//!
//! **Layout changes within a version.** Before the first release, a layout
//! change keeps [`VERSION`] and changes encoder and decoder together, as the
//! client counters record of the bootstrap and the observer capability did;
//! strict decoding makes a peer of another build fail at its first changed
//! message. That holds only because every decoder demands an exact length
//! and the old and new layouts of the changed message can never have the
//! same length for any record count; a change that keeps some length equal
//! (for example one that adds exactly one record's words) must bump
//! [`VERSION`] instead (review of #124). The stream registration and incarnation words of `Manifest`
//! follow that rule (coordinator decision, ACS 13555: they carry the
//! publication identity of the grant, whose driver part is the instance of
//! `Admitted`).
//!
//! **Instance.** The instance of `Admitted` is the driver's 128-bit
//! `driver_id` (SPEC.md §4), the one id per driver instance (ACS 13555).
//! The `driver_id` is held as two words `[high, low]`; the instance is
//! `u128::from(high) << 64 | u128::from(low)`, the packing of a loss
//! record's instance, and travels low word first.
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
/// Largest encoded message, in bytes: `Manifest` with [`MAX_RECORDS`]
/// (seven words before its records; `Admitted` has six).
pub const MAX_MESSAGE_LENGTH: usize = (7 + MAX_RECORDS * RECORD_WORDS) * 8;

/// Refusal codes of `Refused` (nonzero). A client treats a code it does not
/// know as a refusal without a reason.
pub mod refusal {
    /// The driver does not run the protocol version of the `Hello`.
    pub const INCOMPATIBLE_VERSION: u64 = 1;
    /// The `Hello` breaks the first profile: flags, uid, or its pidfd.
    pub const PROFILE: u64 = 2;
    /// A limit is reached: clients, pending hellos, fetches or exports.
    pub const LIMIT: u64 = 3;
    /// The driver failed to create or describe a region.
    pub const RESOURCES: u64 = 4;
    /// The fetch names no hand-over entry held for this client.
    pub const UNKNOWN_KEY: u64 = 5;
}

/// The protocol version of a `Hello` datagram of any version: its type and
/// version words are fixed. `None` when the datagram is not a `Hello`.
#[must_use]
pub fn hello_version(bytes: &[u8]) -> Option<u64> {
    let (chunks, _) = bytes.as_chunks::<8>();
    match chunks {
        [kind, version, ..] if u64::from_le_bytes(*kind) == HELLO => {
            Some(u64::from_le_bytes(*version))
        }
        _ => None,
    }
}

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
    /// The client counters, which the client maps writable to update the
    /// cells the driver allocated for it.
    ClientCounters,
}

impl RegionKind {
    const fn code(self) -> u64 {
        match self {
            Self::CommandRing => 1,
            Self::Broadcast => 2,
            Self::Counters => 3,
            Self::LogBuffer => 4,
            Self::ClientCounters => 5,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::CommandRing),
            2 => Some(Self::Broadcast),
            3 => Some(Self::Counters),
            4 => Some(Self::LogBuffer),
            5 => Some(Self::ClientCounters),
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
    /// An observer subscriber registered in `cell`
    /// (`quantstratum-docs: karyos/design/observer-role.md`).
    ObserverSubscriber {
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
            Self::ObserverSubscriber { cell } => (5, cell),
        }
    }

    const fn from_words(code: u64, index: u64) -> Option<Self> {
        match (code, index) {
            (0, 0) => Some(Self::None),
            (1, cell) => Some(Self::RequiredSubscriber { cell }),
            (2, cell) => Some(Self::OptionalSubscriber { cell }),
            (3, 0) => Some(Self::ExclusivePublication),
            (4, slot) => Some(Self::ConcurrentPublication { slot }),
            (5, cell) => Some(Self::ObserverSubscriber { cell }),
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
        /// The protocol version the driver runs: the client's.
        version: u64,
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
        /// The registration of the grant's stream: with the driver instance
        /// of `Admitted` and `incarnation`, the publication identity a loss
        /// report of the grant names (nonzero).
        stream_registration: u64,
        /// The publication incarnation of the grant's stream (nonzero).
        incarnation: u64,
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
                version,
                client,
                records,
            } => {
                words.extend([
                    ADMITTED,
                    *instance as u64,
                    (*instance >> 64) as u64,
                    *version,
                    *client,
                ]);
                records_words(records, &mut words)?;
            }
            Self::Manifest {
                fetch,
                key,
                registration,
                stream_registration,
                incarnation,
                records,
            } => {
                words.extend([
                    MANIFEST,
                    *fetch,
                    *key,
                    *registration,
                    *stream_registration,
                    *incarnation,
                ]);
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
            | Self::Manifest {
                stream_registration: 0,
                ..
            }
            | Self::Manifest { incarnation: 0, .. }
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
    /// decoded (a zero fetch id, export id, refusal code, or stream
    /// registration or incarnation of a manifest),
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
                version: word(3),
                client: word(4),
                records: records_from(5, &words)?,
            }),
            MANIFEST => {
                if word(1) == 0 || word(4) == 0 || word(5) == 0 {
                    return Err(AdmissionError::Reserved);
                }
                Ok(Self::Manifest {
                    fetch: word(1),
                    key: word(2),
                    registration: word(3),
                    stream_registration: word(4),
                    incarnation: word(5),
                    records: records_from(6, &words)?,
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
            version: VERSION,
            client: 4,
            records: vec![
                Record {
                    kind: RegionKind::CommandRing,
                    capability: Capability::None,
                    ..record(1, Capability::None)
                },
                Record {
                    kind: RegionKind::ClientCounters,
                    capability: Capability::None,
                    ..record(2, Capability::None)
                },
            ],
        });
        let capabilities = [
            Capability::None,
            Capability::RequiredSubscriber { cell: 4 },
            Capability::OptionalSubscriber { cell: 0 },
            Capability::ExclusivePublication,
            Capability::ConcurrentPublication { slot: 2 },
            Capability::ObserverSubscriber { cell: 3 },
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
            stream_registration: 8,
            incarnation: 1,
            records,
        });
        round_trip(&Message::Manifest {
            fetch: 5,
            key: 6,
            registration: 7,
            stream_registration: 8,
            incarnation: 1,
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
            vec![MANIFEST, 0, 1, 2, 3, 1, 0],
            // A zero stream registration or incarnation.
            vec![MANIFEST, 1, 1, 2, 0, 1, 0],
            vec![MANIFEST, 1, 1, 2, 3, 0, 0],
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
            stream_registration: 8,
            incarnation: 1,
            records: vec![record(1, Capability::None); 2],
        });
        manifest[48] = 3;
        assert!(matches!(
            Message::decode(&manifest),
            Err(AdmissionError::WrongLength { .. })
        ));
        manifest[48] = 200;
        assert!(matches!(
            Message::decode(&manifest),
            Err(AdmissionError::TooManyRecords { .. })
        ));
        // A record with export 0, an unknown kind, an unknown capability or
        // an index on a capability without one.
        for (offset, value) in [(64, 0u8), (72, 9), (105, 7), (112, 1)] {
            let mut bad = encode(&Message::Manifest {
                fetch: 1,
                key: 2,
                registration: 3,
                stream_registration: 8,
                incarnation: 1,
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
                stream_registration: 8,
                incarnation: 1,
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
                stream_registration: 8,
                incarnation: 1,
                records: Vec::new(),
            },
            Message::Manifest {
                fetch: 1,
                key: 1,
                registration: 2,
                stream_registration: 8,
                incarnation: 1,
                records: vec![record(0, Capability::None)],
            },
            Message::Admitted {
                instance: 1,
                version: VERSION,
                client: 1,
                records: vec![record(0, Capability::None)],
            },
            Message::Manifest {
                fetch: 1,
                key: 1,
                registration: 2,
                stream_registration: 0,
                incarnation: 1,
                records: Vec::new(),
            },
            Message::Manifest {
                fetch: 1,
                key: 1,
                registration: 2,
                stream_registration: 3,
                incarnation: 0,
                records: Vec::new(),
            },
        ] {
            assert_eq!(
                message.encode(&mut out),
                Err(AdmissionError::Reserved),
                "{message:?}"
            );
        }
    }

    #[test]
    fn the_version_of_any_hello_can_be_read() {
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let len = Message::Hello { version: 7 }.encode(&mut out).unwrap();
        assert_eq!(hello_version(&out[..len]), Some(7));
        // A longer Hello of a future version still yields its version.
        let mut future = out[..len].to_vec();
        future.extend_from_slice(&[0xAB; 16]);
        assert!(Message::decode(&future).is_err());
        assert_eq!(hello_version(&future), Some(7));
        let len = Message::Leave.encode(&mut out).unwrap();
        assert_eq!(hello_version(&out[..len]), None);
        assert_eq!(hello_version(&[1, 0, 0, 0, 0, 0, 0, 0]), None);
        // The refusal of an incompatible version decodes as any refusal.
        round_trip(&Message::Refused {
            fetch: 0,
            code: refusal::INCOMPATIBLE_VERSION,
        });
        // The largest message is a Manifest with every record; an Admitted
        // with every record fits too.
        let records = vec![record(1, Capability::None); MAX_RECORDS];
        let manifest = Message::Manifest {
            fetch: 1,
            key: 2,
            registration: 3,
            stream_registration: 4,
            incarnation: 1,
            records: records.clone(),
        };
        assert_eq!(manifest.encode(&mut out), Ok(MAX_MESSAGE_LENGTH));
        let admitted = Message::Admitted {
            instance: 1,
            version: VERSION,
            client: 2,
            records,
        };
        assert_eq!(admitted.encode(&mut out), Ok(MAX_MESSAGE_LENGTH - 8));
    }

    /// The manifest's words, literally: the stream registration and the
    /// incarnation follow the registration, before the record count.
    #[test]
    fn a_manifest_carries_the_publication_identity_of_its_grant() {
        let message = Message::Manifest {
            fetch: 5,
            key: 6,
            registration: 7,
            stream_registration: 0x0102_0304,
            incarnation: 9,
            records: vec![record(1, Capability::OptionalSubscriber { cell: 2 })],
        };
        let mut out = [0u8; MAX_MESSAGE_LENGTH];
        let length = message.encode(&mut out).unwrap();
        assert_eq!(length, (7 + RECORD_WORDS) * 8);
        let words: Vec<u64> = out[..length]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect();
        assert_eq!(words[..7], [MANIFEST, 5, 6, 7, 0x0102_0304, 9, 1]);
        assert_eq!(Message::decode(&out[..length]).unwrap(), message);
        // The layout without these words (the record count after the
        // registration) is refused: its record words are read as the count
        // and come out two words short.
        let mut short = words.clone();
        short.drain(4..6);
        let bytes: Vec<u8> = short.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert!(matches!(
            Message::decode(&bytes),
            Err(AdmissionError::WrongLength { .. })
        ));
        // A manifest of the largest size plus one word is refused.
        let mut long = vec![0u8; MAX_MESSAGE_LENGTH + 8];
        long[0] = MANIFEST as u8;
        assert!(matches!(
            Message::decode(&long),
            Err(AdmissionError::WrongLength { .. })
        ));
    }
}

/// Decoder properties of the admission messages (issue #121, the control
/// protocol harness standing in for fuzzing, #11 option B), in the style
/// of the frame parser's. The driver decodes datagrams from processes it
/// has not admitted yet, so: decoding any bytes never panics; every valid
/// message round-trips within [`MAX_MESSAGE_LENGTH`], and an encodable
/// message always decodes to itself; decoding is canonical (whatever
/// decodes re-encodes to the same bytes); a flipped byte or a changed
/// length is refused unless the result re-encodes to exactly the input;
/// and [`hello_version`] reads the version of a `Hello` of any layout.
#[cfg(test)]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod properties {
    use proptest::prelude::*;

    use super::*;

    const TYPES: [u64; 8] = [
        HELLO, FETCH, DETACH, LEAVE, ADMITTED, MANIFEST, REGION, REFUSED,
    ];

    fn encoded(message: &Message) -> Result<Vec<u8>, AdmissionError> {
        let mut out = vec![0u8; MAX_MESSAGE_LENGTH];
        let length = message.encode(&mut out)?;
        out.truncate(length);
        Ok(out)
    }

    fn word(bytes: &[u8], index: usize) -> Option<u64> {
        let chunk = bytes.get(index * 8..index * 8 + 8)?;
        Some(u64::from_le_bytes(chunk.try_into().unwrap()))
    }

    /// Canonicality, and [`hello_version`] against a model: the second
    /// word of anything at least two words long whose first word is
    /// `Hello`'s type.
    fn check_decoded(bytes: &[u8]) -> Result<bool, TestCaseError> {
        let version = match (word(bytes, 0), word(bytes, 1)) {
            (Some(HELLO), Some(version)) => Some(version),
            _ => None,
        };
        prop_assert_eq!(hello_version(bytes), version);
        match Message::decode(bytes) {
            Ok(message) => {
                prop_assert!(bytes.len() <= MAX_MESSAGE_LENGTH);
                prop_assert_eq!(&encoded(&message).unwrap()[..], bytes);
                if let Message::Hello { version } = message {
                    prop_assert_eq!(hello_version(bytes), Some(version));
                }
                Ok(true)
            }
            Err(AdmissionError::UnknownType) => {
                prop_assert!(word(bytes, 0).is_none_or(|kind| !TYPES.contains(&kind)));
                Ok(false)
            }
            Err(AdmissionError::WrongLength { length, .. }) => {
                prop_assert_eq!(length, bytes.len());
                Ok(false)
            }
            Err(AdmissionError::TooManyRecords { count }) => {
                prop_assert!(count > MAX_RECORDS as u64);
                Ok(false)
            }
            Err(AdmissionError::Reserved) => Ok(false),
            Err(error) => {
                prop_assert!(false, "decoding returned {error:?}");
                Ok(false)
            }
        }
    }

    /// A word biased to the small values the layouts give meaning to.
    fn small_word() -> impl Strategy<Value = u64> {
        prop_oneof![
            3 => 0u64..=MAX_RECORDS as u64 + 1,
            1 => prop::sample::select(&TYPES[..]),
            1 => (1u64..=5, any::<u32>()).prop_map(|(kind, layout)| kind | u64::from(layout) << 8),
            1 => (any::<u8>(), 0u64..=5).prop_map(|(lane, capability)| u64::from(lane) | capability << 8),
            2 => any::<u64>(),
        ]
    }

    fn to_bytes(words: Vec<u64>) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// The words of a record, each shaped like its field (kind and layout,
    /// lane and capability) or, now and then, anything.
    fn record_words() -> impl Strategy<Value = Vec<u64>> {
        let field = |shaped: BoxedStrategy<u64>| prop_oneof![7 => shaped, 1 => any::<u64>()];
        (
            field(any::<u64>().boxed()),
            field((0u64..=3).boxed()),
            field(
                (0u64..=6, 0u64..=3)
                    .prop_map(|(kind, layout)| kind | layout << 8)
                    .boxed(),
            ),
            any::<[u64; 3]>(),
            field(
                (0u64..=4, 0u64..=6)
                    .prop_map(|(lane, capability)| lane | capability << 8)
                    .boxed(),
            ),
            field((0u64..=2).boxed()),
        )
            .prop_map(
                |(region, export, kind, [length, generation, identity], lane, index)| {
                    vec![
                        region, export, kind, length, generation, identity, lane, index,
                    ]
                },
            )
    }

    /// Any bytes up to a word past the largest message; or words with a
    /// known type first, of any count, of the type's fixed count, or (for
    /// `Admitted` and `Manifest`) with a record count and that many
    /// record-shaped records.
    fn input() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            1 => prop::collection::vec(any::<u8>(), 0..=MAX_MESSAGE_LENGTH + 8),
            1 => (
                prop::sample::select(&TYPES[..]),
                prop::collection::vec(small_word(), 0..=8),
            )
                .prop_map(|(kind, rest)| to_bytes(core::iter::once(kind).chain(rest).collect())),
            2 => prop::sample::select(
                &[(HELLO, 2), (FETCH, 2), (DETACH, 1), (LEAVE, 0), (REGION, 2), (REFUSED, 2)][..],
            )
                .prop_flat_map(|(kind, count)| {
                    prop::collection::vec(small_word(), count).prop_map(move |rest| {
                        to_bytes(core::iter::once(kind).chain(rest).collect())
                    })
                }),
            4 => (
                prop::sample::select(&[ADMITTED, MANIFEST][..]),
                prop::collection::vec(prop_oneof![3 => 1u64..=8, 1 => 0u64..=0], 5),
                prop::collection::vec(record_words(), 0..=MAX_RECORDS),
            )
                .prop_map(|(kind, header, records)| {
                    let header = &header[..if kind == ADMITTED { 4 } else { 5 }];
                    to_bytes(
                        core::iter::once(kind)
                            .chain(header.iter().copied())
                            .chain(core::iter::once(records.len() as u64))
                            .chain(records.into_iter().flatten())
                            .collect(),
                    )
                }),
        ]
    }

    fn record(nonzero: bool) -> impl Strategy<Value = Record> {
        let kind = prop::sample::select(
            &[
                RegionKind::CommandRing,
                RegionKind::Broadcast,
                RegionKind::Counters,
                RegionKind::LogBuffer,
                RegionKind::ClientCounters,
            ][..],
        );
        let capability = prop_oneof![
            Just(Capability::None),
            any::<u64>().prop_map(|cell| Capability::RequiredSubscriber { cell }),
            any::<u64>().prop_map(|cell| Capability::OptionalSubscriber { cell }),
            any::<u64>().prop_map(|cell| Capability::ObserverSubscriber { cell }),
            Just(Capability::ExclusivePublication),
            any::<u64>().prop_map(|slot| Capability::ConcurrentPublication { slot }),
        ];
        let export = if nonzero {
            (1..=u64::MAX).boxed()
        } else {
            prop_oneof![1..=u64::MAX, Just(0u64)].boxed()
        };
        (
            any::<u64>(),
            export,
            kind,
            any::<u32>(),
            any::<[u64; 2]>(),
            any::<(i32, i32, u8)>(),
            capability,
        )
            .prop_map(
                |(
                    region,
                    export,
                    kind,
                    layout,
                    [structure_length, generation],
                    (stream_id, session_id, lane),
                    capability,
                )| Record {
                    region,
                    export,
                    kind,
                    layout,
                    structure_length,
                    generation,
                    stream_id,
                    session_id,
                    lane,
                    capability,
                },
            )
    }

    /// A message; `valid` keeps every value decodable (nonzero where the
    /// layout requires it, at most [`MAX_RECORDS`] records), otherwise
    /// zeros and long manifests are frequent.
    fn message(valid: bool) -> impl Strategy<Value = Message> {
        let id = move || {
            if valid {
                (1..=u64::MAX).boxed()
            } else {
                prop_oneof![1..=u64::MAX, Just(0u64)].boxed()
            }
        };
        let records = move || {
            let most = if valid { MAX_RECORDS } else { MAX_RECORDS + 2 };
            prop::collection::vec(record(valid), 0..=most)
        };
        prop_oneof![
            any::<u64>().prop_map(|version| Message::Hello { version }),
            (id(), any::<u64>()).prop_map(|(fetch, key)| Message::Fetch { fetch, key }),
            id().prop_map(|export| Message::Detach { export }),
            Just(Message::Leave),
            (any::<u128>(), any::<(u64, u64)>(), records()).prop_map(
                |(instance, (version, client), records)| Message::Admitted {
                    instance,
                    version,
                    client,
                    records,
                }
            ),
            (id(), any::<(u64, u64)>(), id(), id(), records()).prop_map(
                |(fetch, (key, registration), stream_registration, incarnation, records)| {
                    Message::Manifest {
                        fetch,
                        key,
                        registration,
                        stream_registration,
                        incarnation,
                        records,
                    }
                }
            ),
            any::<(u64, u64)>().prop_map(|(fetch, index)| Message::Region { fetch, index }),
            (any::<u64>(), id()).prop_map(|(fetch, code)| Message::Refused { fetch, code }),
        ]
    }

    proptest! {
        #[test]
        fn any_datagram_is_refused_or_canonical(bytes in input()) {
            check_decoded(&bytes)?;
        }

        #[test]
        fn messages_round_trip_and_resist_mutation(
            message in message(true),
            flip in any::<prop::sample::Index>(),
            mask in 1u8..=255,
            cut in any::<prop::sample::Index>(),
            extra in prop::collection::vec(any::<u8>(), 1..=16),
        ) {
            let bytes = encoded(&message).unwrap();
            prop_assert!(bytes.len() <= MAX_MESSAGE_LENGTH);
            prop_assert_eq!(Message::decode(&bytes).unwrap(), message.clone());
            prop_assert!(check_decoded(&bytes)?);
            let mut short = vec![0u8; bytes.len() - 1];
            prop_assert_eq!(
                message.encode(&mut short),
                Err(AdmissionError::BufferTooShort {
                    required: bytes.len(),
                    available: bytes.len() - 1,
                })
            );

            let mut flipped = bytes.clone();
            flipped[flip.index(bytes.len())] ^= mask;
            check_decoded(&flipped)?;

            // The type fixes the length (with the record count, which the
            // bytes keep): a prefix or an extension is refused.
            prop_assert!(!check_decoded(&bytes[..cut.index(bytes.len())])?);
            let mut longer = bytes.clone();
            longer.extend_from_slice(&extra);
            prop_assert!(!check_decoded(&longer)?);
        }

        /// What encodes decodes to itself: the encoder refuses exactly the
        /// values the decoder could not return.
        #[test]
        fn an_encodable_message_decodes_to_itself(message in message(false)) {
            match encoded(&message) {
                Ok(bytes) => {
                    prop_assert_eq!(Message::decode(&bytes).unwrap(), message);
                }
                Err(AdmissionError::Reserved) => {}
                Err(AdmissionError::TooManyRecords { count }) => {
                    prop_assert!(count > MAX_RECORDS as u64);
                }
                Err(error) => prop_assert!(false, "encoding returned {error:?}"),
            }
        }

        /// A `Hello` of any version, and of any later layout that keeps its
        /// first two words, yields its version.
        #[test]
        fn hello_version_reads_any_hello(
            version in any::<u64>(),
            rest in prop::collection::vec(any::<u8>(), 0..=64),
        ) {
            let bytes = encoded(&Message::Hello { version }).unwrap();
            prop_assert_eq!(hello_version(&bytes), Some(version));
            let mut later = bytes[..16].to_vec();
            later.extend_from_slice(&rest);
            prop_assert_eq!(hello_version(&later), Some(version));
            prop_assert_eq!(hello_version(&bytes[..15]), None);
        }
    }
}
