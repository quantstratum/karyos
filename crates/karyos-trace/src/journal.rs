// SPDX-License-Identifier: Apache-2.0

//! A typed trace journal over the record journal (SPEC.md §7.3; design in
//! `quantstratum-docs: karyos/design/trace-records.md`): one observation point writes
//! [`TraceRecord`]s, one collector takes them back decoded, with the
//! journal's sequence gaps and loss snapshots passed through unchanged.
//! Attributing losses to traces is not done here.

use karyos_protocol::journal::{
    Append, JournalConsumer, JournalWriter, Losses, Stamp, Taken, record_journal,
};

use crate::error::TraceError;
use crate::record::{RECORD_WORDS, TraceRecord};

/// The observer that owns a trace journal: the observing driver instance,
/// which need not be the publication's, and the journal within it. Clock
/// domains and epochs and packet context in its records, gaps and loss
/// snapshots are scoped by this identity. Caller obligations: the journal
/// number is never reused within the driver instance, a clock and epoch
/// pair is never repurposed for a restarted or different clock, and a packet
/// token is never reassigned to a different packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObserverId {
    /// The observing driver's random 128-bit `driver_id`, two words.
    pub driver: [u64; 2],
    /// The journal within that driver.
    pub journal: u64,
}

/// Creates a trace journal of `capacity` records (a power of two) and
/// `drop_ranges` drop-range entries, owned by `observer` (control path).
/// The observer identity is immutable and readable from both ends.
///
/// # Errors
///
/// Returns [`TraceError::Journal`] for an invalid configuration.
pub fn trace_journal(
    capacity: usize,
    drop_ranges: usize,
    observer: ObserverId,
) -> Result<(TraceWriter, TraceCollector), TraceError> {
    let (writer, consumer) = record_journal(capacity, RECORD_WORDS, drop_ranges)?;
    Ok((
        TraceWriter { writer, observer },
        TraceCollector { consumer, observer },
    ))
}

/// The journal's only writer: one observation point.
#[derive(Debug)]
pub struct TraceWriter {
    writer: JournalWriter,
    observer: ObserverId,
}

impl TraceWriter {
    /// The observer that owns the journal.
    #[must_use]
    pub fn observer(&self) -> ObserverId {
        self.observer
    }

    /// Encodes and appends `record`. `collected` is this writer's own
    /// monotonic collection time, not the record's observation time: a late
    /// hardware stamp has an old observation time and a current collection
    /// stamp.
    ///
    /// # Errors
    ///
    /// Returns the record's validation errors before the journal assigns a
    /// sequence, and [`TraceError::Journal`] for journal refusals
    /// (`StampRegression`, `Exhausted`, `Closed`).
    pub fn record(&mut self, record: &TraceRecord, collected: Stamp) -> Result<Append, TraceError> {
        let words = record.encode()?;
        Ok(self.writer.append(&words, collected)?)
    }

    /// Closes the journal; the collector can still drain it.
    pub fn close(&mut self) {
        self.writer.close();
    }
}

/// What [`TraceCollector::take`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collected {
    /// A decoded record.
    Record {
        /// Its journal sequence.
        sequence: u64,
        /// Sequences `[from, to)` before it that were never stored, if any.
        gap: Option<(u64, u64)>,
        /// The observation.
        record: TraceRecord,
    },
    /// A stored record that failed to decode; it is skipped, never trusted.
    Corrupt {
        /// Its journal sequence.
        sequence: u64,
        /// Sequences before it that were never stored, if any.
        gap: Option<(u64, u64)>,
        /// Why it was rejected.
        error: TraceError,
    },
    /// No record is waiting; the journal is open.
    Empty,
    /// The journal is closed and drained.
    Closed,
}

/// The journal's only collector.
#[derive(Debug)]
pub struct TraceCollector {
    consumer: JournalConsumer,
    observer: ObserverId,
}

impl TraceCollector {
    /// The observer that owns the journal; it scopes the clocks and packet
    /// identities of every record taken here.
    #[must_use]
    pub fn observer(&self) -> ObserverId {
        self.observer
    }

    /// Takes and decodes the oldest record.
    #[must_use]
    pub fn take(&mut self) -> Collected {
        match self.consumer.take() {
            Taken::Record(taken) => {
                let mut words = [0u64; RECORD_WORDS];
                for (word, value) in words.iter_mut().zip(taken.payload) {
                    *word = *value;
                }
                match TraceRecord::decode(&words) {
                    Ok(record) => Collected::Record {
                        sequence: taken.sequence,
                        gap: taken.gap,
                        record,
                    },
                    Err(error) => Collected::Corrupt {
                        sequence: taken.sequence,
                        gap: taken.gap,
                        error,
                    },
                }
            }
            Taken::Empty => Collected::Empty,
            Taken::Closed => Collected::Closed,
        }
    }

    /// The journal's loss snapshot, unchanged: horizon, stored count, drop
    /// ranges, watermark and unstable entries. It reports storage loss only;
    /// which traces a loss affects is decided elsewhere.
    #[must_use]
    pub fn losses(&mut self) -> Losses<'_> {
        self.consumer.losses()
    }
}

#[cfg(test)]
mod tests {
    use karyos_protocol::journal::{DropRange, record_journal};

    use super::*;
    use crate::record::{ObservedTime, Point, PublicationId, TraceIds};

    const OBSERVER: ObserverId = ObserverId {
        driver: [3, 4],
        journal: 1,
    };

    fn record(position: u64, time: u64) -> TraceRecord {
        TraceRecord {
            point: Point::Publish,
            publication: PublicationId {
                driver: [1, 2],
                registration: 5,
                stream_id: 10,
                session_id: -3,
                incarnation: 1,
            },
            lane: 0,
            position,
            ids: TraceIds {
                trace_id: [7, 8],
                span_id: 1,
                parent_span_id: 0,
                message_id: position,
            },
            observed: ObservedTime {
                time,
                clock: 1,
                epoch: 0,
                uncertainty: 0,
            },
            subscriber: None,
            packet: None,
        }
    }

    fn stamp(time: u64) -> Stamp {
        Stamp {
            time,
            clock: 1,
            epoch: 0,
        }
    }

    #[test]
    fn records_round_trip_with_the_observer() {
        let (mut writer, mut collector) = trace_journal(4, 2, OBSERVER).unwrap();
        assert_eq!(writer.observer(), OBSERVER);
        assert_eq!(collector.observer(), OBSERVER);
        let sent = record(64, 100);
        assert_eq!(
            writer.record(&sent, stamp(100)),
            Ok(Append::Stored { sequence: 0 })
        );
        assert_eq!(
            collector.take(),
            Collected::Record {
                sequence: 0,
                gap: None,
                record: sent
            }
        );
        assert_eq!(collector.take(), Collected::Empty);
        writer.close();
        assert_eq!(collector.take(), Collected::Closed);
    }

    /// A late hardware stamp: an old observation time with a current
    /// collection stamp is accepted; a collection-stamp regression is not.
    #[test]
    fn collection_time_is_separate_from_observation_time() {
        let (mut writer, _collector) = trace_journal(4, 2, OBSERVER).unwrap();
        writer.record(&record(0, 500), stamp(500)).unwrap();
        let mut late = record(32, 100);
        late.point = Point::HardwareTx;
        late.packet = Some(crate::record::PacketId {
            packet: 1,
            path: 0,
            attempt: 0,
        });
        assert!(writer.record(&late, stamp(600)).is_ok());
        assert_eq!(
            writer.record(&record(64, 700), stamp(599)),
            Err(TraceError::Journal(
                karyos_protocol::journal::JournalError::StampRegression
            ))
        );
    }

    #[test]
    fn an_invalid_record_is_refused_before_a_sequence_is_assigned() {
        let (mut writer, mut collector) = trace_journal(4, 2, OBSERVER).unwrap();
        let mut bad = record(0, 0);
        bad.lane = 9;
        assert_eq!(
            writer.record(&bad, stamp(0)),
            Err(TraceError::Lane { lane: 9 })
        );
        assert_eq!(collector.losses().attempted, 0);
    }

    /// Stored 0, dropped 1 and 2, malformed stored 3, valid 4: the corrupt
    /// record carries the gap `[1, 3)`, the next valid one has none, and
    /// the corruption leaves the storage accounting alone.
    #[test]
    fn a_corrupt_record_carries_the_gap_before_it() {
        let (mut raw, consumer) = record_journal(1, RECORD_WORDS, 2).unwrap();
        let mut collector = TraceCollector {
            consumer,
            observer: OBSERVER,
        };
        let valid = |position| record(position, 0).encode().unwrap();
        raw.append(&valid(0), stamp(0)).unwrap();
        raw.append(&valid(1), stamp(1)).unwrap();
        raw.append(&valid(2), stamp(2)).unwrap();
        assert!(matches!(
            collector.take(),
            Collected::Record {
                sequence: 0,
                gap: None,
                ..
            }
        ));
        let mut malformed = valid(3);
        malformed[0] = 0;
        raw.append(&malformed, stamp(3)).unwrap();
        assert_eq!(
            collector.take(),
            Collected::Corrupt {
                sequence: 3,
                gap: Some((1, 3)),
                error: TraceError::Version { version: 0 },
            }
        );
        raw.append(&valid(4), stamp(4)).unwrap();
        assert!(matches!(
            collector.take(),
            Collected::Record {
                sequence: 4,
                gap: None,
                ..
            }
        ));
        let losses = collector.losses();
        assert_eq!((losses.attempted, losses.stored), (5, 3));
        assert_eq!(
            losses.ranges,
            &[DropRange {
                first: 1,
                last: 2,
                first_time: 1,
                last_time: 2,
                clock: 1,
                epoch: 0,
            }]
        );
    }
}
