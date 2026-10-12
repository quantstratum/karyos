// SPDX-License-Identifier: Apache-2.0

//! The trace observation record (SPEC.md §7.3; layout in
//! `quantstratum-docs: karyos/design/trace-records.md`): one observation of one frame, encoded as
//! [`RECORD_WORDS`] little-endian words. Encoding and decoding apply the same
//! checks, so a writer cannot produce a record a collector would reject.

use crate::error::TraceError;

/// Words of an encoded record.
pub const RECORD_WORDS: usize = 22;
/// Layout version written in word 0.
pub const RECORD_VERSION: u8 = 1;
/// Highest lane (SPEC.md §7.4: four lanes).
pub const MAX_LANE: u8 = 3;

/// Where an observation was taken. Each point names what it measures: none
/// stands for ring submission time on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Checks the rules shared by encoding and decoding.
    ///
    /// # Errors
    ///
    /// [`TraceError::Lane`], [`TraceError::Subscriber`] and
    /// [`TraceError::Packet`].
    pub fn validate(&self) -> Result<(), TraceError> {
        if self.lane > MAX_LANE {
            return Err(TraceError::Lane { lane: self.lane });
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
        Ok(())
    }

    /// Encodes the record.
    ///
    /// # Errors
    ///
    /// As [`TraceRecord::validate`].
    pub fn encode(&self) -> Result<[u64; RECORD_WORDS], TraceError> {
        self.validate()?;
        let subscriber = self.subscriber.map_or(([0, 0], 0, 0), |s| {
            (s.driver, s.registration, s.incarnation)
        });
        let packet = self
            .packet
            .map_or((0, 0), |p| (p.packet, join(p.path, p.attempt)));
        Ok([
            u64::from(RECORD_VERSION)
                | (u64::from(self.point.code()) << 8)
                | (u64::from(self.lane) << 16),
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

    /// Decodes and checks a record.
    ///
    /// # Errors
    ///
    /// [`TraceError::Version`], [`TraceError::UnknownPoint`],
    /// [`TraceError::ReservedBits`], and the errors of
    /// [`TraceRecord::validate`].
    pub fn decode(words: &[u64; RECORD_WORDS]) -> Result<Self, TraceError> {
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
        if version != RECORD_VERSION {
            return Err(TraceError::Version { version });
        }
        if head >> 24 != 0 {
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
        let packet = (packet != 0 || path_attempt != 0).then(|| {
            let (path, attempt) = halves(path_attempt);
            PacketId {
                packet,
                path,
                attempt,
            }
        });
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
        };
        record.validate()?;
        Ok(record)
    }
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
        version[0] = (version[0] & !0xFF) | 2;
        assert_eq!(
            TraceRecord::decode(&version),
            Err(TraceError::Version { version: 2 })
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
            TraceRecord::decode(&[0; RECORD_WORDS]),
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
        };
        let golden: [u64; RECORD_WORDS] = [
            0x0002_0401, // version 1, point 4 (SubscriberPoll), lane 2
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
    }
}
