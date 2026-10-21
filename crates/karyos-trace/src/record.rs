// SPDX-License-Identifier: Apache-2.0

//! The trace observation record (SPEC.md §7.3; layout in
//! `quantstratum-docs: karyos/design/trace-records.md`): one observation of one frame, encoded as
//! [`OBSERVATION_WORDS`] little-endian words, followed in the journal by the
//! writer's collection stamp ([`RECORD_WORDS`] in all). Encoding and decoding
//! apply the same checks, so a writer cannot produce a record a collector
//! would reject.

use karyos_protocol::journal::Stamp;

use crate::error::TraceError;

/// Words of an encoded observation (words 0 to 21 of a record).
pub const OBSERVATION_WORDS: usize = 22;
/// Words of a journal record: the observation and the collection stamp
/// (time, clock, epoch) in words 22 to 24.
pub const RECORD_WORDS: usize = OBSERVATION_WORDS + 3;
// The width the driver sizes network journals with.
const _: () = assert!(RECORD_WORDS == karyos_protocol::trace_hook::TRACE_RECORD_WORDS);
/// Layout version written in word 0: version 3 carries `path` and
/// `attempt` in word 21 on `SenderPickup` and `path` on `ReceiverCommit`
/// (`quantstratum-docs: karyos/design/trace-network.md`, NT-2), in the
/// same width; every other rule is version 2's.
pub const RECORD_VERSION: u8 = 3;
/// Layout version 2, still decoded: it adds the `root` flag (bit 56) to
/// version 1 (`quantstratum-docs: karyos/design/trace-records.md`, "Root
/// flag", ACS 13936). Its network points carry no path.
pub const RECORD_VERSION_2: u8 = 2;
/// The oldest layout version still decoded: version 1, whose bit 56 was
/// reserved, decodes with `root` false.
pub const RECORD_VERSION_1: u8 = 1;
/// Word 0 bit of the `root` flag (layout version 2).
const ROOT_BIT: u64 = 1 << 56;
/// Word 0 bits that are reserved in every version: the `destination` token
/// (bits 24..56, zero until enabled) and bits 57..64.
const RESERVED_BITS: u64 = !0xFF_FFFF & !ROOT_BIT;
/// Highest lane (SPEC.md §7.4: four lanes).
pub const MAX_LANE: u8 = 3;

/// Where an observation was taken. Each point names what it measures: none
/// stands for ring submission time on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Point {
    /// The publication committed the frame.
    Publish,
    /// The sender picked the frame up for transmission.
    SenderPickup,
    /// The receiver committed the frame to its image.
    ReceiverCommit,
    /// A subscriber polled the frame.
    SubscriberPoll,
    /// Kernel software transmit stamp (`SO_TIMESTAMPING`).
    KernelTx,
    /// Kernel software receive stamp (`SO_TIMESTAMPING`).
    KernelRx,
    /// NIC hardware transmit stamp.
    HardwareTx,
    /// NIC hardware receive stamp.
    HardwareRx,
}

impl Point {
    /// Wire code (1..=8).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Publish => 1,
            Self::SenderPickup => 2,
            Self::ReceiverCommit => 3,
            Self::SubscriberPoll => 4,
            Self::KernelTx => 5,
            Self::KernelRx => 6,
            Self::HardwareTx => 7,
            Self::HardwareRx => 8,
        }
    }

    /// The point of a wire code.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::UnknownPoint`] for any other code.
    pub const fn from_code(code: u8) -> Result<Self, TraceError> {
        Ok(match code {
            1 => Self::Publish,
            2 => Self::SenderPickup,
            3 => Self::ReceiverCommit,
            4 => Self::SubscriberPoll,
            5 => Self::KernelTx,
            6 => Self::KernelRx,
            7 => Self::HardwareTx,
            8 => Self::HardwareRx,
            _ => return Err(TraceError::UnknownPoint { code }),
        })
    }

    /// Whether the observation is taken per packet by the kernel or the
    /// NIC, so its record must carry packet context (and only such records
    /// may).
    #[must_use]
    pub const fn is_packet_level(self) -> bool {
        matches!(
            self,
            Self::KernelTx | Self::KernelRx | Self::HardwareTx | Self::HardwareRx
        )
    }

    /// Whether a driver agent records the observation per frame and path,
    /// so a layout version 3 record must carry its path (and only such
    /// records may).
    #[must_use]
    pub const fn is_network_level(self) -> bool {
        matches!(self, Self::SenderPickup | Self::ReceiverCommit)
    }
}

/// The publication an observation belongs to. Position alone is not
/// globally unique, so every record carries the whole identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PublicationId {
    /// Driver instance: the random 128-bit `driver_id` of SPEC.md §4,
    /// as two words.
    pub driver: [u64; 2],
    /// Publication registration.
    pub registration: u64,
    /// Wire stream id.
    pub stream_id: i32,
    /// Wire session id.
    pub session_id: i32,
    /// Publication incarnation.
    pub incarnation: u64,
}

/// The `EXT` identity of the traced message (SPEC.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TraceIds {
    /// Trace id, the two words of the extension.
    pub trace_id: [u64; 2],
    /// Span id; zero when unused.
    pub span_id: u64,
    /// Parent span id within the trace; zero when absent.
    pub parent_span_id: u64,
    /// Logical message id.
    pub message_id: u64,
}

/// An observation time with its clock domain, calibration epoch and
/// uncertainty (the half-width of the interval around `time`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ObservedTime {
    /// Time in the clock's unit.
    pub time: u64,
    /// Clock domain.
    pub clock: u64,
    /// Calibration epoch.
    pub epoch: u64,
    /// Half-width of the uncertainty interval, same unit as `time`.
    pub uncertainty: u64,
}

/// The subscriber of a [`Point::SubscriberPoll`] observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriberId {
    /// The subscriber's driver instance (`driver_id`, two words), so a
    /// remote subscriber is not confused with a local one.
    pub driver: [u64; 2],
    /// Subscriber registration (nonzero), scoped by `driver`.
    pub registration: u64,
    /// Subscriber incarnation.
    pub incarnation: u64,
}

/// The packet of a packet-level observation; one record is written per
/// frame the packet carried. This context is local to the journal's
/// observer: a receive-side token and attempt are the observer's own and do
/// not identify the sender's transmission across hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketId {
    /// Packet token (nonzero), never reassigned to a different packet or
    /// submission within the observer's driver instance; the frames of one
    /// packet share it.
    pub packet: u64,
    /// Send path, a reusable identity.
    pub path: u32,
    /// Submission attempt within this packet, telling retransmissions of a
    /// frame apart.
    pub attempt: u32,
}

/// The path of a network observation (layout version 3): one record per
/// path and attempt on `SenderPickup`, and the winning path on
/// `ReceiverCommit`, whose attempt is zero (DATA carries none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkPath {
    /// Send path, a reusable identity; 0 is a valid path.
    pub path: u32,
    /// 0 for the first send; the repair count for a retransmission.
    pub attempt: u32,
}

/// One observation of one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceRecord {
    /// Observation point.
    pub point: Point,
    /// The publication.
    pub publication: PublicationId,
    /// Lane, 0..=[`MAX_LANE`].
    pub lane: u8,
    /// Frame position in its lane.
    pub position: u64,
    /// Trace identity of the message.
    pub ids: TraceIds,
    /// When it was observed.
    pub observed: ObservedTime,
    /// Present exactly for [`Point::SubscriberPoll`].
    pub subscriber: Option<SubscriberId>,
    /// Present exactly for packet-level points.
    pub packet: Option<PacketId>,
    /// Present exactly for network-level points in layout version 3; a
    /// version 1 or 2 record decodes with none.
    pub network: Option<NetworkPath>,
    /// The `Publish` of a message that started a fresh trace (no incoming
    /// context); never set on a parentless join or on another point. A
    /// version 1 record decodes with `root` false.
    pub root: bool,
}

/// Splits a word into its two little-endian 32-bit halves.
const fn halves(word: u64) -> (u32, u32) {
    (word as u32, (word >> 32) as u32)
}

/// Joins two 32-bit halves into a word.
const fn join(low: u32, high: u32) -> u64 {
    (low as u64) | ((high as u64) << 32)
}

impl TraceRecord {
    /// Checks the rules shared by encoding and decoding, for the layout
    /// version the encoder writes.
    ///
    /// # Errors
    ///
    /// [`TraceError::Lane`], [`TraceError::Subscriber`],
    /// [`TraceError::Packet`], [`TraceError::NetworkPath`] and
    /// [`TraceError::Root`].
    pub fn validate(&self) -> Result<(), TraceError> {
        self.validate_as(RECORD_VERSION)
    }

    /// As [`TraceRecord::validate`], for a record of layout `version`.
    fn validate_as(&self, version: u8) -> Result<(), TraceError> {
        if self.lane > MAX_LANE {
            return Err(TraceError::Lane { lane: self.lane });
        }
        if self.root && self.point != Point::Publish {
            return Err(TraceError::Root);
        }
        let polls = self.point == Point::SubscriberPoll;
        let subscriber_valid = match self.subscriber {
            Some(subscriber) => polls && subscriber.registration != 0,
            None => !polls,
        };
        if !subscriber_valid {
            return Err(TraceError::Subscriber);
        }
        let packet_valid = match self.packet {
            Some(packet) => self.point.is_packet_level() && packet.packet != 0,
            None => !self.point.is_packet_level(),
        };
        if !packet_valid {
            return Err(TraceError::Packet);
        }
        let carries_path = version >= RECORD_VERSION && self.point.is_network_level();
        let network_valid = match self.network {
            Some(network) => {
                carries_path && (self.point == Point::SenderPickup || network.attempt == 0)
            }
            None => !carries_path,
        };
        if !network_valid {
            return Err(TraceError::NetworkPath);
        }
        Ok(())
    }

    /// Encodes the record.
    ///
    /// # Errors
    ///
    /// As [`TraceRecord::validate`].
    pub fn encode(&self) -> Result<[u64; OBSERVATION_WORDS], TraceError> {
        self.validate()?;
        let subscriber = self.subscriber.map_or(([0, 0], 0, 0), |s| {
            (s.driver, s.registration, s.incarnation)
        });
        // Validation keeps the two apart: packet context only on packet
        // points, a network path only on network points.
        let packet = match (self.packet, self.network) {
            (Some(p), _) => (p.packet, join(p.path, p.attempt)),
            (None, Some(n)) => (0, join(n.path, n.attempt)),
            (None, None) => (0, 0),
        };
        Ok([
            u64::from(RECORD_VERSION)
                | (u64::from(self.point.code()) << 8)
                | (u64::from(self.lane) << 16)
                | if self.root { ROOT_BIT } else { 0 },
            self.publication.driver[0],
            self.publication.driver[1],
            self.publication.registration,
            join(
                self.publication.stream_id as u32,
                self.publication.session_id as u32,
            ),
            self.publication.incarnation,
            self.position,
            self.ids.trace_id[0],
            self.ids.trace_id[1],
            self.ids.span_id,
            self.ids.parent_span_id,
            self.ids.message_id,
            self.observed.time,
            self.observed.clock,
            self.observed.epoch,
            self.observed.uncertainty,
            subscriber.0[0],
            subscriber.0[1],
            subscriber.1,
            subscriber.2,
            packet.0,
            packet.1,
        ])
    }

    /// Decodes and checks a record of layout version 3, 2 (whose network
    /// points carry no path) or 1 (whose `root` is also false), each
    /// under its own rule.
    ///
    /// # Errors
    ///
    /// [`TraceError::Version`], [`TraceError::UnknownPoint`],
    /// [`TraceError::ReservedBits`] (bit 56 included in a version 1
    /// record), and the errors of [`TraceRecord::validate`].
    pub fn decode(words: &[u64; OBSERVATION_WORDS]) -> Result<Self, TraceError> {
        let [
            head,
            driver_low,
            driver_high,
            registration,
            stream_session,
            incarnation,
            position,
            trace_low,
            trace_high,
            span_id,
            parent_span_id,
            message_id,
            time,
            clock,
            epoch,
            uncertainty,
            subscriber_driver_low,
            subscriber_driver_high,
            subscriber,
            subscriber_incarnation,
            packet,
            path_attempt,
        ] = *words;
        let version = head as u8;
        if !(RECORD_VERSION_1..=RECORD_VERSION).contains(&version) {
            return Err(TraceError::Version { version });
        }
        let root = head & ROOT_BIT != 0;
        // Bit 56 was reserved in version 1.
        if head & RESERVED_BITS != 0 || (root && version == RECORD_VERSION_1) {
            return Err(TraceError::ReservedBits);
        }
        let point = Point::from_code((head >> 8) as u8)?;
        let (stream_id, session_id) = halves(stream_session);
        let subscriber_words = [
            subscriber_driver_low,
            subscriber_driver_high,
            subscriber,
            subscriber_incarnation,
        ];
        let subscriber = subscriber_words
            .iter()
            .any(|word| *word != 0)
            .then_some(SubscriberId {
                driver: [subscriber_driver_low, subscriber_driver_high],
                registration: subscriber,
                incarnation: subscriber_incarnation,
            });
        let (packet, network) = if version >= RECORD_VERSION && point.is_network_level() {
            // Version 3: word 21 is the path, and the packet word is zero.
            if packet != 0 {
                return Err(TraceError::NetworkPath);
            }
            let (path, attempt) = halves(path_attempt);
            (None, Some(NetworkPath { path, attempt }))
        } else {
            let packet = (packet != 0 || path_attempt != 0).then(|| {
                let (path, attempt) = halves(path_attempt);
                PacketId {
                    packet,
                    path,
                    attempt,
                }
            });
            (packet, None)
        };
        let record = Self {
            point,
            publication: PublicationId {
                driver: [driver_low, driver_high],
                registration,
                stream_id: stream_id as i32,
                session_id: session_id as i32,
                incarnation,
            },
            lane: (head >> 16) as u8,
            position,
            ids: TraceIds {
                trace_id: [trace_low, trace_high],
                span_id,
                parent_span_id,
                message_id,
            },
            observed: ObservedTime {
                time,
                clock,
                epoch,
                uncertainty,
            },
            subscriber,
            packet,
            network,
            root,
        };
        record.validate_as(version)?;
        Ok(record)
    }
}

/// Encodes a journal record: the observation and, in words 22 to 24, the
/// collection stamp the writer passes to the journal with it.
///
/// # Errors
///
/// As [`TraceRecord::validate`].
pub fn encode_record(
    record: &TraceRecord,
    collected: Stamp,
) -> Result<[u64; RECORD_WORDS], TraceError> {
    let observation = record.encode()?;
    let mut words = [0u64; RECORD_WORDS];
    for (word, value) in words.iter_mut().zip(observation) {
        *word = value;
    }
    let [time, clock, epoch] = [collected.time, collected.clock, collected.epoch];
    if let Some(tail) = words.get_mut(OBSERVATION_WORDS..) {
        for (word, value) in tail.iter_mut().zip([time, clock, epoch]) {
            *word = value;
        }
    }
    Ok(words)
}

/// Decodes a journal record into its observation and collection stamp.
///
/// # Errors
///
/// As [`TraceRecord::decode`].
pub fn decode_record(words: &[u64; RECORD_WORDS]) -> Result<(TraceRecord, Stamp), TraceError> {
    let mut observation = [0u64; OBSERVATION_WORDS];
    for (word, value) in observation.iter_mut().zip(words) {
        *word = *value;
    }
    let record = TraceRecord::decode(&observation)?;
    let [.., time, clock, epoch] = *words;
    Ok((record, Stamp { time, clock, epoch }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POINTS: [Point; 8] = [
        Point::Publish,
        Point::SenderPickup,
        Point::ReceiverCommit,
        Point::SubscriberPoll,
        Point::KernelTx,
        Point::KernelRx,
        Point::HardwareTx,
        Point::HardwareRx,
    ];

    pub(crate) fn sample(point: Point) -> TraceRecord {
        TraceRecord {
            point,
            publication: PublicationId {
                driver: [u64::MAX, 1],
                registration: 7,
                stream_id: i32::MIN,
                session_id: i32::MAX,
                incarnation: 3,
            },
            lane: MAX_LANE,
            position: u64::MAX - 31,
            ids: TraceIds {
                trace_id: [1, u64::MAX],
                span_id: 9,
                parent_span_id: 10,
                message_id: 11,
            },
            observed: ObservedTime {
                time: 1_000,
                clock: 2,
                epoch: 4,
                uncertainty: 50,
            },
            subscriber: (point == Point::SubscriberPoll).then_some(SubscriberId {
                driver: [8, u64::MAX],
                registration: 5,
                incarnation: 6,
            }),
            packet: point.is_packet_level().then_some(PacketId {
                packet: 99,
                path: u32::MAX,
                attempt: 2,
            }),
            network: point.is_network_level().then_some(NetworkPath {
                path: u32::MAX,
                attempt: if point == Point::SenderPickup { 7 } else { 0 },
            }),
            root: point == Point::Publish,
        }
    }

    #[test]
    fn every_point_round_trips() {
        for point in POINTS {
            assert_eq!(Point::from_code(point.code()), Ok(point));
            let record = sample(point);
            let words = record.encode().unwrap();
            assert_eq!(TraceRecord::decode(&words), Ok(record), "{point:?}");
        }
        assert_eq!(
            Point::from_code(0),
            Err(TraceError::UnknownPoint { code: 0 })
        );
        assert_eq!(
            Point::from_code(9),
            Err(TraceError::UnknownPoint { code: 9 })
        );
    }

    #[test]
    fn encoding_refuses_what_decoding_refuses() {
        let mut lane = sample(Point::Publish);
        lane.lane = 4;
        assert_eq!(lane.encode(), Err(TraceError::Lane { lane: 4 }));

        let mut missing = sample(Point::SubscriberPoll);
        missing.subscriber = None;
        assert_eq!(missing.encode(), Err(TraceError::Subscriber));

        let mut zero = sample(Point::SubscriberPoll);
        zero.subscriber = Some(SubscriberId {
            driver: [1, 1],
            registration: 0,
            incarnation: 1,
        });
        assert_eq!(zero.encode(), Err(TraceError::Subscriber));

        let mut stray = sample(Point::Publish);
        stray.subscriber = Some(SubscriberId {
            driver: [1, 1],
            registration: 1,
            incarnation: 0,
        });
        assert_eq!(stray.encode(), Err(TraceError::Subscriber));

        let mut packet = sample(Point::Publish);
        packet.packet = Some(PacketId {
            packet: 1,
            path: 0,
            attempt: 0,
        });
        assert_eq!(packet.encode(), Err(TraceError::Packet));

        let mut required = sample(Point::HardwareTx);
        required.packet = None;
        assert_eq!(required.encode(), Err(TraceError::Packet));

        // Path 0 and attempt 0 are valid with a packet token.
        let mut zero_path = sample(Point::KernelTx);
        zero_path.packet = Some(PacketId {
            packet: 4,
            path: 0,
            attempt: 0,
        });
        assert_eq!(
            TraceRecord::decode(&zero_path.encode().unwrap()),
            Ok(zero_path)
        );
    }

    #[test]
    fn decoding_checks_every_word_rule() {
        let good = sample(Point::KernelRx).encode().unwrap();
        let mut version = good;
        version[0] = (version[0] & !0xFF) | 4;
        assert_eq!(
            TraceRecord::decode(&version),
            Err(TraceError::Version { version: 4 })
        );
        let mut reserved = good;
        reserved[0] |= 1 << 40;
        assert_eq!(
            TraceRecord::decode(&reserved),
            Err(TraceError::ReservedBits)
        );
        let mut point = good;
        point[0] = (point[0] & !0xFF00) | (0x20 << 8);
        assert_eq!(
            TraceRecord::decode(&point),
            Err(TraceError::UnknownPoint { code: 0x20 })
        );
        let mut lane = good;
        lane[0] = (lane[0] & !0xFF_0000) | (7 << 16);
        assert_eq!(
            TraceRecord::decode(&lane),
            Err(TraceError::Lane { lane: 7 })
        );
        // A subscriber word on a kernel point.
        let mut stray = good;
        stray[18] = 1;
        assert_eq!(TraceRecord::decode(&stray), Err(TraceError::Subscriber));
        // A packet path without a packet identity.
        let mut path = good;
        path[20] = 0;
        assert_eq!(TraceRecord::decode(&path), Err(TraceError::Packet));
        assert_eq!(
            TraceRecord::decode(&[0; OBSERVATION_WORDS]),
            Err(TraceError::Version { version: 0 })
        );
        // Stray transport fields on a point that is not packet level.
        let mut transport = sample(Point::Publish).encode().unwrap();
        transport[21] = 9 | (7 << 32);
        assert_eq!(TraceRecord::decode(&transport), Err(TraceError::Packet));
        // A packet-level point with no packet context.
        let mut absent = good;
        absent[20] = 0;
        absent[21] = 0;
        assert_eq!(TraceRecord::decode(&absent), Err(TraceError::Packet));
    }

    /// Golden layout: explicit word positions and point codes, so the
    /// encoder and decoder cannot agree on a wrong offset.
    #[test]
    fn golden_layout() {
        let record = TraceRecord {
            point: Point::SubscriberPoll,
            publication: PublicationId {
                driver: [0x0101, 0x0202],
                registration: 0x03,
                stream_id: -2,
                session_id: 5,
                incarnation: 0x06,
            },
            lane: 2,
            position: 0x07,
            ids: TraceIds {
                trace_id: [0x08, 0x09],
                span_id: 0x0A,
                parent_span_id: 0x0B,
                message_id: 0x0C,
            },
            observed: ObservedTime {
                time: 0x0D,
                clock: 0x0E,
                epoch: 0x0F,
                uncertainty: 0x10,
            },
            subscriber: Some(SubscriberId {
                driver: [0x11, 0x12],
                registration: 0x13,
                incarnation: 0x14,
            }),
            packet: None,
            network: None,
            root: false,
        };
        let golden: [u64; OBSERVATION_WORDS] = [
            0x0002_0403, // version 3, point 4 (SubscriberPoll), lane 2
            0x0101,
            0x0202,
            0x03,
            0x0000_0005_FFFF_FFFE, // stream -2 low, session 5 high
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0,
            0,
        ];
        assert_eq!(record.encode(), Ok(golden));
        assert_eq!(TraceRecord::decode(&golden), Ok(record));
        let codes: Vec<u8> = POINTS.iter().map(|point| point.code()).collect();
        assert_eq!(codes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let collected = Stamp {
            time: 0x15,
            clock: 0x16,
            epoch: 0x17,
        };
        let full = encode_record(&record, collected).unwrap();
        assert_eq!(full[..OBSERVATION_WORDS], golden);
        assert_eq!(full[OBSERVATION_WORDS..], [0x15, 0x16, 0x17]);
        assert_eq!(decode_record(&full), Ok((record, collected)));
        // Versions 1 and 2 of the same layout decode to the same record.
        for version in [RECORD_VERSION_1, RECORD_VERSION_2] {
            let mut old = golden;
            old[0] = 0x0002_0400 | u64::from(version);
            assert_eq!(TraceRecord::decode(&old), Ok(record));
        }
    }

    /// Layout version 2's root flag: bit 56 of word 0 on a `Publish`.
    #[test]
    fn the_root_flag_round_trips_in_version_2() {
        let root = sample(Point::Publish);
        assert!(root.root);
        let words = root.encode().unwrap();
        assert_eq!(words[0] & 0xFF, 3, "the encoder writes version 3");
        assert_eq!(words[0] >> 56, 1);
        assert_eq!(TraceRecord::decode(&words), Ok(root));
        let plain = TraceRecord {
            root: false,
            ..root
        };
        let words = plain.encode().unwrap();
        assert_eq!(words[0] >> 24, 0);
        assert_eq!(TraceRecord::decode(&words), Ok(plain));
    }

    /// A version 1 record decodes with `root` false; a version 1 record
    /// with bit 56 set, and `root` on a point other than `Publish`, are
    /// refused on both sides.
    #[test]
    fn version_1_records_are_never_roots_and_root_is_validated() {
        let plain = TraceRecord {
            root: false,
            ..sample(Point::Publish)
        };
        let mut v1 = plain.encode().unwrap();
        v1[0] = (v1[0] & !0xFF) | 1;
        assert_eq!(TraceRecord::decode(&v1), Ok(plain));
        let mut flagged = v1;
        flagged[0] |= 1 << 56;
        assert_eq!(TraceRecord::decode(&flagged), Err(TraceError::ReservedBits));
        for point in POINTS.iter().copied().filter(|p| *p != Point::Publish) {
            let wrong = TraceRecord {
                root: true,
                ..sample(point)
            };
            assert_eq!(wrong.encode(), Err(TraceError::Root), "{point:?}");
            let mut words = sample(point).encode().unwrap();
            words[0] |= 1 << 56;
            assert_eq!(TraceRecord::decode(&words), Err(TraceError::Root));
        }
        // Bit 57 stays reserved in version 2.
        let mut reserved = plain.encode().unwrap();
        reserved[0] |= 1 << 57;
        assert_eq!(
            TraceRecord::decode(&reserved),
            Err(TraceError::ReservedBits)
        );
    }

    /// Layout version 3 (NT-2): path and attempt in word 21 on
    /// `SenderPickup`, the path on `ReceiverCommit`, packet word zero.
    #[test]
    fn version_3_records_carry_the_network_path() {
        let pickup = sample(Point::SenderPickup);
        let words = pickup.encode().unwrap();
        assert_eq!(words[20], 0);
        assert_eq!(words[21], u64::from(u32::MAX) | (7 << 32));
        // Two pickups of one frame on two paths, or two attempts, differ.
        let other_path = TraceRecord {
            network: Some(NetworkPath {
                path: 0,
                attempt: 7,
            }),
            ..pickup
        };
        let other_attempt = TraceRecord {
            network: Some(NetworkPath {
                path: u32::MAX,
                attempt: 0,
            }),
            ..pickup
        };
        let encoded = [
            words,
            other_path.encode().unwrap(),
            other_attempt.encode().unwrap(),
        ];
        assert!(encoded[0] != encoded[1] && encoded[0] != encoded[2]);
        assert!(encoded[1] != encoded[2]);
        for (record, words) in [pickup, other_path, other_attempt].iter().zip(encoded) {
            assert_eq!(TraceRecord::decode(&words), Ok(*record));
        }
        // Path 0, attempt 0 is a valid path, not an absent one.
        let commit = TraceRecord {
            network: Some(NetworkPath {
                path: 0,
                attempt: 0,
            }),
            ..sample(Point::ReceiverCommit)
        };
        let words = commit.encode().unwrap();
        assert_eq!((words[20], words[21]), (0, 0));
        assert_eq!(TraceRecord::decode(&words), Ok(commit));
    }

    /// The network path rules, refused alike on both sides.
    #[test]
    fn the_network_path_is_validated_on_both_sides() {
        for point in [Point::SenderPickup, Point::ReceiverCommit] {
            let missing = TraceRecord {
                network: None,
                ..sample(point)
            };
            assert_eq!(missing.encode(), Err(TraceError::NetworkPath), "{point:?}");
            // A packet token beside the path.
            let mut token = sample(point).encode().unwrap();
            token[20] = 1;
            assert_eq!(TraceRecord::decode(&token), Err(TraceError::NetworkPath));
        }
        let attempt = TraceRecord {
            network: Some(NetworkPath {
                path: 1,
                attempt: 1,
            }),
            ..sample(Point::ReceiverCommit)
        };
        assert_eq!(attempt.encode(), Err(TraceError::NetworkPath));
        let mut words = sample(Point::ReceiverCommit).encode().unwrap();
        words[21] |= 1 << 32;
        assert_eq!(TraceRecord::decode(&words), Err(TraceError::NetworkPath));
        for point in POINTS.iter().copied().filter(|p| !p.is_network_level()) {
            let stray = TraceRecord {
                network: Some(NetworkPath {
                    path: 1,
                    attempt: 0,
                }),
                ..sample(point)
            };
            assert_eq!(stray.encode(), Err(TraceError::NetworkPath), "{point:?}");
        }
    }

    /// Versions 1 and 2 keep their rule on the network points: no path,
    /// and words 20 and 21 zero.
    #[test]
    fn older_network_records_keep_their_rule() {
        for version in [RECORD_VERSION_1, RECORD_VERSION_2] {
            for point in [Point::SenderPickup, Point::ReceiverCommit] {
                let mut words = sample(point).encode().unwrap();
                words[0] = (words[0] & !0xFF) | u64::from(version);
                // The version 3 path word is a stray packet word here.
                assert_eq!(TraceRecord::decode(&words), Err(TraceError::Packet));
                words[21] = 0;
                let decoded = TraceRecord::decode(&words).unwrap();
                assert_eq!(decoded.network, None);
                assert_eq!(
                    decoded,
                    TraceRecord {
                        network: None,
                        ..sample(point)
                    }
                );
            }
        }
    }
}
