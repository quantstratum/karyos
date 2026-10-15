// SPDX-License-Identifier: Apache-2.0

//! The per-stream positions sampling pass
//! (`quantstratum-docs: karyos/design/observability-and-tools.md`,
//! "Per-stream positions").
//!
//! Each stream lane has a cell for the publication limit, the head and the
//! retention floor, and each attached subscriber a cell for its position.
//! Cells are allocated, set and released only inside a pass, between its
//! odd and its even `positions epoch`, so a tool that reads a consistent
//! pass also reads a consistent membership. Membership is recomputed in the
//! pass by comparing the streams and the conductors' attached subscribers
//! with the cells held. Positions are stream positions: the current
//! mapping's base plus the conductor's value.

use karyos_sys::counters::{Counter, CounterKeys, KIND_NONE, KIND_SUBSCRIBER};
use karyos_sys::log_buffer::SubscriberCell;

use crate::counters::{DriverCounters, Event, TYPE_POSITION};
use crate::embedded::{Stream, StreamTerms};

/// The lane of every stream until streams have more than one.
const LANE: u8 = 0;

/// The cells of one subscriber.
#[derive(Debug)]
struct SubscriberCells {
    /// The registry cell of the subscriber in the current mapping.
    cell: usize,
    /// Its registration, 0 for an in-process subscription without one.
    registration: u64,
    /// Its position cell; `None` when no cell was free.
    position: Option<Counter>,
}

/// The cells of one stream lane.
#[derive(Debug)]
struct StreamCells {
    /// The stream's id.
    stream: u64,
    limit: Option<Counter>,
    head: Option<Counter>,
    floor: Option<Counter>,
    subscribers: Vec<SubscriberCells>,
}

/// The sampling state: the epoch, when the last pass ran and the cells
/// held.
#[derive(Debug, Default)]
pub(crate) struct Positions {
    /// The epoch of the last completed pass: even.
    epoch: u64,
    /// The host `CLOCK_MONOTONIC` reading of the last pass.
    last: Option<u64>,
    streams: Vec<StreamCells>,
    /// Reused buffer of the attached subscribers of one stream.
    attached: Vec<SubscriberCell>,
}

impl Positions {
    /// Whether a pass is due at host time `now`, `interval` nanoseconds
    /// after the last one.
    pub(crate) fn due(&self, now: u64, interval: u64) -> bool {
        self.last
            .is_none_or(|last| now.saturating_sub(last) >= interval)
    }

    /// Makes the next duty cycle run a pass.
    #[cfg(test)]
    pub(crate) fn force_due(&mut self) {
        self.last = None;
    }

    /// Runs one sampling pass at host time `now`, which it stores as
    /// `positions sampled at`.
    pub(crate) fn sample<T: StreamTerms>(
        &mut self,
        now: u64,
        counters: &mut DriverCounters,
        streams: &[Stream<T>],
    ) {
        self.last = Some(now);
        let odd = self.epoch.wrapping_add(1);
        counters.begin_pass(odd);
        self.streams.retain_mut(|cells| {
            let live = streams.iter().any(|stream| stream.id == cells.stream);
            if !live {
                cells.release(counters);
            }
            live
        });
        for stream in streams {
            let index = match self
                .streams
                .iter()
                .position(|cells| cells.stream == stream.id)
            {
                Some(index) => index,
                None => {
                    self.streams
                        .push(StreamCells::allocate(counters, stream.id));
                    self.streams.len() - 1
                }
            };
            let Some(cells) = self.streams.get_mut(index) else {
                continue;
            };
            self.attached.clear();
            self.attached.extend(stream.conductor.subscribers());
            cells.sync_subscribers(counters, &self.attached);
            let at = |value: u64| stream.base.saturating_add(value);
            // Positions, then floor, then head, then limit: each only grows,
            // so within a pass no position or floor exceeds the head.
            for (subscriber, attached) in cells.subscribers.iter().zip(&self.attached) {
                set(subscriber.position.as_ref(), at(attached.position));
            }
            set(cells.floor.as_ref(), at(stream.conductor.floor()));
            if let Ok(head) = stream.conductor.head() {
                set(cells.head.as_ref(), at(head));
            }
            set(cells.limit.as_ref(), at(stream.conductor.limit()));
        }
        counters.set(Event::PositionsSampledAt, now);
        self.epoch = odd.wrapping_add(1);
        counters.end_pass(self.epoch);
    }
}

impl StreamCells {
    fn allocate(counters: &mut DriverCounters, stream: u64) -> Self {
        let keys = CounterKeys {
            stream,
            lane: LANE,
            kind: KIND_NONE,
            participant: 0,
        };
        Self {
            stream,
            limit: counters.allocate_keyed(TYPE_POSITION, "stream limit", keys),
            head: counters.allocate_keyed(TYPE_POSITION, "stream head", keys),
            floor: counters.allocate_keyed(TYPE_POSITION, "stream floor", keys),
            subscribers: Vec::new(),
        }
    }

    /// Makes the held subscriber cells match `attached`, in its order:
    /// keeps the cells of subscribers still attached, releases the others
    /// and allocates cells for new ones.
    fn sync_subscribers(&mut self, counters: &mut DriverCounters, attached: &[SubscriberCell]) {
        let unchanged = self.subscribers.len() == attached.len()
            && self
                .subscribers
                .iter()
                .zip(attached)
                .all(|(held, now)| held.matches(now));
        if unchanged {
            return;
        }
        let mut held = core::mem::take(&mut self.subscribers);
        for now in attached {
            let cells = match held.iter().position(|cells| cells.matches(now)) {
                Some(index) => held.swap_remove(index),
                None => SubscriberCells::allocate(counters, self.stream, now),
            };
            self.subscribers.push(cells);
        }
        for cells in held {
            cells.release(counters);
        }
    }

    fn release(&mut self, counters: &mut DriverCounters) {
        for counter in [self.limit.take(), self.head.take(), self.floor.take()]
            .into_iter()
            .flatten()
        {
            counters.free(counter);
        }
        for cells in self.subscribers.drain(..) {
            cells.release(counters);
        }
    }
}

impl SubscriberCells {
    fn allocate(counters: &mut DriverCounters, stream: u64, attached: &SubscriberCell) -> Self {
        let keys = CounterKeys {
            stream,
            lane: LANE,
            kind: KIND_SUBSCRIBER,
            participant: attached.registration,
        };
        let label = format!("subscriber position cell {}", attached.cell);
        Self {
            cell: attached.cell,
            registration: attached.registration,
            position: counters.allocate_keyed(TYPE_POSITION, &label, keys),
        }
    }

    fn matches(&self, attached: &SubscriberCell) -> bool {
        self.cell == attached.cell && self.registration == attached.registration
    }

    fn release(self, counters: &mut DriverCounters) {
        if let Some(counter) = self.position {
            counters.free(counter);
        }
    }
}

/// Sets a position cell when it exists.
fn set(counter: Option<&Counter>, value: u64) {
    if let Some(counter) = counter {
        counter.set(value);
    }
}

#[cfg(test)]
mod tests {
    use karyos_sys::counters::{CellRead, CounterMetadata};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    use super::*;
    use crate::counters::FIXED_COUNTERS;
    use crate::embedded::{DriverConfig, EmbeddedDriver, StreamConfig};
    use crate::error::DriverError;

    fn stream_config(stream_id: i32) -> StreamConfig {
        StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id,
                claim_deadline: 100,
                publication: PublicationMode::Exclusive,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        }
    }

    /// A driver whose first duty cycle samples and whose later ones sample
    /// only after `force_due`.
    fn driver(counters_capacity: usize) -> EmbeddedDriver {
        let config = DriverConfig {
            counters_capacity,
            position_sample_interval: u64::MAX,
            ..DriverConfig::default()
        };
        EmbeddedDriver::with_config(config).unwrap()
    }

    /// Every allocated position cell: metadata and value.
    fn positions(driver: &EmbeddedDriver) -> Vec<(CounterMetadata, u64)> {
        let reader = driver.counters();
        (0..reader.capacity())
            .filter_map(|index| match reader.read(index) {
                CellRead::Allocated {
                    metadata, value, ..
                } if metadata.type_id == TYPE_POSITION => Some((metadata, value)),
                _ => None,
            })
            .collect()
    }

    fn position(driver: &EmbeddedDriver, label: &str) -> Option<u64> {
        positions(driver)
            .into_iter()
            .find(|(metadata, _)| metadata.label() == label.as_bytes())
            .map(|(_, value)| value)
    }

    fn fixed(driver: &EmbeddedDriver, label: &str) -> u64 {
        let reader = driver.counters();
        (0..reader.capacity())
            .find_map(|index| match reader.read(index) {
                CellRead::Allocated {
                    metadata, value, ..
                } if metadata.label() == label.as_bytes() => Some(value),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn a_pass_samples_the_conductor_readings() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let _reader = driver.subscribe(handle, Role::Required).unwrap();
        let mut writer = driver.publication(handle).unwrap();
        let _ = writer.offer(b"one").unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(fixed(&driver, "positions epoch"), 2);
        assert_ne!(fixed(&driver, "positions sampled at"), 0);
        let stream = &driver.streams[0];
        let subscriber = stream.conductor.subscribers().next().unwrap();
        let head = stream.conductor.head().unwrap();
        assert_ne!(head, 0);
        assert_eq!(position(&driver, "stream head"), Some(head));
        assert_eq!(
            position(&driver, "stream limit"),
            Some(stream.conductor.limit())
        );
        assert_eq!(
            position(&driver, "stream floor"),
            Some(stream.conductor.floor())
        );
        let label = format!("subscriber position cell {}", subscriber.cell);
        assert_eq!(position(&driver, &label), Some(subscriber.position));
        let keys = positions(&driver)
            .into_iter()
            .find(|(metadata, _)| metadata.label() == label.as_bytes())
            .unwrap()
            .0
            .keys;
        assert_eq!(
            keys,
            CounterKeys {
                stream: stream.id,
                lane: LANE,
                kind: KIND_SUBSCRIBER,
                participant: subscriber.registration,
            }
        );

        // Not due before the interval: the cells keep the last pass.
        let _ = writer.offer(b"two").unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(fixed(&driver, "positions epoch"), 2);
        assert_eq!(position(&driver, "stream head"), Some(head));
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(fixed(&driver, "positions epoch"), 4);
        let later = driver.streams[0].conductor.head().unwrap();
        assert!(later > head);
        assert_eq!(position(&driver, "stream head"), Some(later));
    }

    #[test]
    fn positions_continue_across_a_mapping_cutover() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let mut writer = driver.publication(handle).unwrap();
        let _ = writer.offer(b"one").unwrap();
        let _ = driver.do_work().unwrap();
        let before = position(&driver, "stream head").unwrap();
        let _ = driver
            .reconfigure_stream(
                handle,
                crate::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 5,
                },
            )
            .unwrap();
        // The exclusive writer seals, the driver opens the successor, the
        // writer moves and then publishes at the seal position.
        let _ = writer.offer(b"two").unwrap();
        let _ = driver.do_work().unwrap();
        let _ = writer.offer(b"two").unwrap();
        assert!(matches!(
            writer.offer(b"two").unwrap(),
            karyos_client::OfferOutcome::Accepted { .. }
        ));
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        let stream = &driver.streams[0];
        assert_ne!(stream.base, 0);
        let head = stream.base + stream.conductor.head().unwrap();
        assert!(head > before);
        assert_eq!(position(&driver, "stream head"), Some(head));
    }

    #[test]
    fn cells_are_released_with_the_subscriber_and_the_stream() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let reader = driver.subscribe(handle, Role::Optional).unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(positions(&driver).len(), 4);
        drop(reader);
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        let held = positions(&driver);
        assert_eq!(held.len(), 3);
        assert!(
            held.iter()
                .all(|(metadata, _)| metadata.keys.kind == KIND_NONE)
        );
        driver.remove_stream(handle).unwrap();
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert!(driver.streams.is_empty());
        assert!(positions(&driver).is_empty());
        assert_eq!(fixed(&driver, "counters unavailable"), 0);
    }

    #[test]
    fn exhaustion_admits_the_stream_without_its_cells() {
        // Room for two position cells only.
        let mut driver = driver(FIXED_COUNTERS + 2);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let _reader = driver.subscribe(handle, Role::Optional).unwrap();
        let mut writer = driver.publication(handle).unwrap();
        let _ = writer.offer(b"one").unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(positions(&driver).len(), 2);
        // The floor and the subscriber found no cell.
        assert_eq!(fixed(&driver, "counters unavailable"), 2);
        assert_eq!(position(&driver, "stream floor"), None);
        assert_eq!(fixed(&driver, "positions epoch"), 2);
    }

    #[test]
    fn the_counters_region_has_the_configured_capacity() {
        let driver = driver(100);
        assert_eq!(driver.counters().capacity(), 100);
        let config = DriverConfig {
            counters_capacity: FIXED_COUNTERS - 1,
            ..DriverConfig::default()
        };
        assert!(matches!(
            EmbeddedDriver::with_config(config),
            Err(DriverError::InvalidConfig)
        ));
        let config = DriverConfig {
            position_sample_interval: 0,
            ..DriverConfig::default()
        };
        assert!(matches!(
            EmbeddedDriver::with_config(config),
            Err(DriverError::InvalidConfig)
        ));
    }
}
