// SPDX-License-Identifier: Apache-2.0

//! Storage of the CnC rings (`quantstratum-docs: karyos/design/ipc-cnc-regions.md`): the command
//! ring and the broadcast buffer keep a trailer of control words and a data
//! area, either in heap memory of this process or in a shared region.
//!
//! In a region the structure after the header stride is a configuration
//! line (capacity, largest record extent, trailer words), the trailer and
//! the data area, each starting on a 128-byte stride. The creator writes the
//! configuration line before handing the region out; a participant reads it
//! once, validates it and the region's size against it, and from then on
//! uses only its validated copy.

use core::sync::atomic::AtomicU64;

use crate::atomic_view::HeapWords;

/// Layout version of a CnC ring region.
#[cfg(target_os = "linux")]
pub const LAYOUT_VERSION: u64 = 1;

/// Words of a 128-byte stride.
#[cfg(target_os = "linux")]
const STRIDE: usize = 16;

/// Where the words live.
#[derive(Debug)]
enum Store {
    /// Two heap allocations of this process.
    Heap { data: HeapWords, trailer: HeapWords },
    /// A shared region (Linux).
    #[cfg(target_os = "linux")]
    Mapped(crate::ipc::Region),
}

/// The validated words of one ring.
#[derive(Debug)]
pub(crate) struct RingStore {
    store: Store,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "used by regions"))]
    data_words: usize,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code, reason = "used by regions"))]
    trailer_words: usize,
    max_extent: u64,
}

/// The geometry every owned ring has: a power-of-two `capacity` of at least
/// `min_capacity` bytes, and a largest record extent of `capacity / 8`.
fn geometry(capacity: usize, min_capacity: usize) -> Option<(usize, u64)> {
    if capacity < min_capacity || !capacity.is_power_of_two() {
        return None;
    }
    Some((capacity / 8, u64::try_from(capacity / 8).ok()?))
}

impl RingStore {
    /// A ring of `capacity` bytes in heap memory.
    pub(crate) fn heap(capacity: usize, min_capacity: usize, trailer_words: usize) -> Option<Self> {
        let (data_words, max_extent) = geometry(capacity, min_capacity)?;
        Some(Self {
            store: Store::Heap {
                data: HeapWords::zeroed(data_words).ok()?,
                trailer: HeapWords::zeroed(trailer_words).ok()?,
            },
            data_words,
            trailer_words,
            max_extent,
        })
    }

    /// The data area.
    pub(crate) fn data(&self) -> &[AtomicU64] {
        match &self.store {
            Store::Heap { data, .. } => data.words().as_slice(),
            #[cfg(target_os = "linux")]
            Store::Mapped(region) => {
                let start = STRIDE + self.trailer_words;
                region
                    .structure()
                    .as_slice()
                    .get(start..start + self.data_words)
                    .unwrap_or(&[])
            }
        }
    }

    /// The trailer.
    pub(crate) fn trailer(&self) -> &[AtomicU64] {
        match &self.store {
            Store::Heap { trailer, .. } => trailer.words().as_slice(),
            #[cfg(target_os = "linux")]
            Store::Mapped(region) => region
                .structure()
                .as_slice()
                .get(STRIDE..STRIDE + self.trailer_words)
                .unwrap_or(&[]),
        }
    }

    /// The largest record extent in bytes.
    pub(crate) fn max_extent(&self) -> u64 {
        self.max_extent
    }
}

#[cfg(target_os = "linux")]
mod mapped {
    use core::sync::atomic::Ordering;

    use super::{LAYOUT_VERSION, RingStore, STRIDE, Store, geometry};
    use crate::atomic_view::WORD_BYTES;
    use crate::error::SysError;
    use crate::ipc::{Region, RegionKind, RegionRecord};

    /// Words of the structure: configuration line, trailer, data.
    fn structure_words(trailer_words: usize, data_words: usize) -> Option<usize> {
        STRIDE.checked_add(trailer_words)?.checked_add(data_words)
    }

    impl RingStore {
        /// A ring of `capacity` bytes in a new shared region of `kind`
        /// (driver side). `trailer_words` must be a multiple of the stride.
        pub(crate) fn create_in(
            instance: u128,
            region: u64,
            kind: RegionKind,
            capacity: usize,
            min_capacity: usize,
            trailer_words: usize,
        ) -> Result<Self, SysError> {
            let invalid = SysError::InvalidRegion {
                address: 0,
                len: capacity,
            };
            let (data_words, max_extent) = geometry(capacity, min_capacity).ok_or(invalid)?;
            if !trailer_words.is_multiple_of(STRIDE) {
                return Err(invalid);
            }
            let structure_length = structure_words(trailer_words, data_words)
                .and_then(|words| words.checked_mul(WORD_BYTES))
                .ok_or(invalid)?;
            let mapped = Region::create(RegionRecord {
                instance,
                region,
                kind,
                generation: 0,
                layout: LAYOUT_VERSION,
                structure_length,
            })?;
            let config = mapped.structure();
            for (index, value) in [capacity as u64, max_extent, trailer_words as u64]
                .into_iter()
                .enumerate()
            {
                config
                    .get(index)
                    .ok_or(invalid)?
                    .store(value, Ordering::Release);
            }
            Ok(Self {
                store: Store::Mapped(mapped),
                data_words,
                trailer_words,
                max_extent,
            })
        }

        /// Attaches to a ring in an attached region (participant side). The
        /// region must be of `kind` with this layout version, its
        /// configuration line must describe a ring this process would create
        /// with `min_capacity` and `trailer_words`, and that ring must fill
        /// the region exactly.
        pub(crate) fn attach(
            region: Region,
            kind: RegionKind,
            min_capacity: usize,
            trailer_words: usize,
        ) -> Result<Self, SysError> {
            let record = region.record();
            let invalid = SysError::InvalidRegion {
                address: 0,
                len: record.structure_length,
            };
            if record.kind != kind || record.layout != LAYOUT_VERSION || record.generation != 0 {
                return Err(invalid);
            }
            let structure = region.structure();
            let mut config = [0u64; STRIDE];
            for (index, word) in config.iter_mut().enumerate() {
                *word = structure.get(index).ok_or(invalid)?.load(Ordering::Acquire);
            }
            let [capacity, max_extent, trailer, rest @ ..] = config;
            let capacity = usize::try_from(capacity).map_err(|_| invalid)?;
            let (data_words, expected_extent) = geometry(capacity, min_capacity).ok_or(invalid)?;
            let structure_length = structure_words(trailer_words, data_words)
                .and_then(|words| words.checked_mul(WORD_BYTES));
            if max_extent != expected_extent
                || trailer != trailer_words as u64
                || rest.iter().any(|word| *word != 0)
                || structure_length != Some(record.structure_length)
            {
                return Err(invalid);
            }
            Ok(Self {
                store: Store::Mapped(region),
                data_words,
                trailer_words,
                max_extent,
            })
        }

        /// The shared region, to pass its descriptor; `None` on the heap.
        pub(crate) fn region(&self) -> Option<&Region> {
            match &self.store {
                Store::Mapped(region) => Some(region),
                Store::Heap { .. } => None,
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use core::sync::atomic::Ordering;

    use rustix::fd::AsFd;

    use crate::broadcast::{BroadcastReceiver, BroadcastTransmitter, Received};
    use crate::command_ring::{RingConsumer, RingProducer};
    use crate::counters::{CellRead, CountersReader};
    use crate::error::SysError;
    use crate::ipc::{Recv, Region, RegionKind, Sent, recv, send, seqpacket_pair};

    /// Passes `region`'s descriptor over a socket pair and attaches it as a
    /// participant would, expecting `record`.
    fn pass(region: &Region, kind: RegionKind) -> Result<Region, SysError> {
        let (a, b) = seqpacket_pair().unwrap();
        assert_eq!(
            send(a.as_fd(), b"r", region.descriptor()).unwrap(),
            Sent::Sent
        );
        let mut buffer = [0u8; 8];
        let Recv::Message(received) = recv(b.as_fd(), &mut buffer).unwrap() else {
            panic!("no message");
        };
        let mut record = region.record();
        record.kind = kind;
        Region::attach(received.fd.unwrap(), record)
    }

    #[test]
    fn a_command_ring_crosses_a_region() {
        let mut consumer = RingConsumer::create_in(7, 1, 1024).unwrap();
        let region = consumer.region().unwrap();
        let mut producer =
            RingProducer::attach(pass(region, RegionKind::CommandRing).unwrap()).unwrap();
        assert_eq!(producer.max_payload(), 120);
        for sequence in 0..40u32 {
            producer.write(sequence, &sequence.to_le_bytes()).unwrap();
            let read = consumer.read().unwrap().unwrap();
            assert_eq!(
                (read.type_id, read.payload),
                (sequence, &sequence.to_le_bytes()[..])
            );
        }
        consumer.close();
        assert!(producer.is_closed());
    }

    #[test]
    fn a_broadcast_buffer_crosses_a_region() {
        let mut transmitter = BroadcastTransmitter::create_in(7, 2, 1024).unwrap();
        transmitter.transmit(1, b"before").unwrap();
        let region = transmitter.region().unwrap();
        let mut receiver =
            BroadcastReceiver::attach(pass(region, RegionKind::Broadcast).unwrap()).unwrap();
        // A new receiver starts at the committed tail.
        assert_eq!(receiver.receive(), Received::Pending);
        for sequence in 2..40u32 {
            transmitter
                .transmit(sequence, &sequence.to_le_bytes())
                .unwrap();
            let Received::Message {
                type_id, payload, ..
            } = receiver.receive()
            else {
                panic!("no message");
            };
            assert_eq!((type_id, payload), (sequence, &sequence.to_le_bytes()[..]));
        }
    }

    #[test]
    fn attachment_checks_the_kind_and_the_configuration() {
        let consumer = RingConsumer::create_in(7, 1, 1024).unwrap();
        let region = consumer.region().unwrap();
        // A command ring is not a broadcast buffer: the header check
        // refuses the wrong kind before any structure word is read.
        assert!(pass(region, RegionKind::Broadcast).is_err());
        assert!(BroadcastReceiver::attach(pass(region, RegionKind::CommandRing).unwrap()).is_err());

        // Every configuration word is checked against the region.
        let config = region.structure();
        for (index, bad) in [(0usize, 2048u64), (0, 1000), (1, 64), (2, 16), (3, 1)] {
            let word = config.get(index).unwrap();
            let good = word.load(Ordering::Acquire);
            word.store(bad, Ordering::Release);
            assert!(
                RingProducer::attach(pass(region, RegionKind::CommandRing).unwrap()).is_err(),
                "word {index} = {bad}"
            );
            word.store(good, Ordering::Release);
        }
        assert!(RingProducer::attach(pass(region, RegionKind::CommandRing).unwrap()).is_ok());
    }

    #[test]
    fn counters_cross_a_region() {
        let (mut manager, local) = crate::counters::counters_in(7, 3, 4).unwrap();
        let region = local.region().unwrap();
        let reader = CountersReader::attach(pass(region, RegionKind::Counters).unwrap()).unwrap();
        assert_eq!(reader.capacity(), 4);
        let sent = manager.allocate(9, "bytes sent").unwrap();
        sent.increment(41).unwrap();
        sent.increment(1).unwrap();
        let CellRead::Allocated {
            metadata, value, ..
        } = reader.read(sent.index())
        else {
            panic!("expected an allocated cell");
        };
        assert_eq!(
            (metadata.type_id, metadata.label(), value),
            (9, &b"bytes sent"[..], 42)
        );
        let index = sent.index();
        manager.free(sent).unwrap();
        assert_eq!(reader.read(index), CellRead::Free);
        assert_eq!(reader.read(4), CellRead::Free);

        // The configuration line is checked against the region.
        let config = region.structure();
        for (index, bad) in [(0usize, 0u64), (0, 5), (0, 3), (1, 1)] {
            let word = config.get(index).unwrap();
            let good = word.load(Ordering::Acquire);
            word.store(bad, Ordering::Release);
            assert!(
                CountersReader::attach(pass(region, RegionKind::Counters).unwrap()).is_err(),
                "word {index} = {bad}"
            );
            word.store(good, Ordering::Release);
        }
        assert!(CountersReader::attach(pass(region, RegionKind::Counters).unwrap()).is_ok());
        assert!(crate::counters::counters_in(7, 3, 0).is_err());
    }

    #[test]
    fn creation_checks_the_geometry() {
        assert!(RingConsumer::create_in(7, 1, 512).is_err());
        assert!(RingConsumer::create_in(7, 1, 1536).is_err());
        assert!(BroadcastTransmitter::create_in(7, 2, 1000).is_err());
    }
}
