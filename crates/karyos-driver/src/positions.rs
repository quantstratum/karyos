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
//! with the cells held. Positions are stream positions: a mapping's base
//! plus the conductor's value.
//!
//! During a mapping cutover a subscriber that has not moved yet reads the
//! predecessor: its predecessor cell is sampled (at the predecessor's base)
//! and the successor cell reserved for it is not, until it moves.
//!
//! A pass releases every departed cell, of every stream, before it
//! allocates any, and stops scanning the region after its first refused
//! allocation. Dropping the driver releases the remaining cells in a final
//! pass, so a reader that outlives it sees that change at an odd epoch.

use karyos_client::LinkStatus;
use karyos_sys::counters::{Counter, CounterKeys, KIND_NONE, KIND_SUBSCRIBER};
use karyos_sys::host_clock::age_ns;

use crate::counters::{DriverCounters, Event, TYPE_POSITION};
use crate::embedded::{Stream, StreamTerms};
use crate::generations::MemberKind;

/// One attached subscriber cell of one mapping, as sampled.
#[derive(Debug, Clone, Copy)]
struct Attached {
    /// The publication incarnation of the mapping
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, The fresh
    /// incarnation): a replaced incarnation reuses the generation, so the
    /// pair names the mapping.
    incarnation: u64,
    /// The mapping's generation.
    generation: u32,
    /// The registry cell in that mapping.
    cell: usize,
    /// The occupant or export id, 0 for none.
    registration: u64,
    /// Its stream position: the mapping's base plus the cell position;
    /// `None` if the sum does not fit (checked, SPEC.md §14).
    position: Option<u64>,
}

/// The cells of one subscriber.
#[derive(Debug)]
struct SubscriberCells {
    incarnation: u64,
    generation: u32,
    cell: usize,
    registration: u64,
    /// Its position cell; `None` while no cell was free.
    position: Option<Counter>,
}

/// The cells of one stream lane.
#[derive(Debug)]
struct StreamCells {
    /// The stream's id.
    stream: u64,
    /// Its aggregate's registration: the stream key of its cells.
    registration: u64,
    /// The stream's lane.
    lane: u8,
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
    /// Reused buffers of the attached subscribers, one per stream in the
    /// order of the driver's streams.
    attached: Vec<Vec<Attached>>,
}

/// The allocator of one pass: after the first refused allocation it stops
/// scanning the region, since nothing frees a cell later in the pass
/// (releases all come first).
struct PassAllocator<'a> {
    counters: &'a mut DriverCounters,
    exhausted: bool,
}

impl PassAllocator<'_> {
    /// A cell for a new member; a refusal counts in `counters unavailable`.
    fn new_cell(&mut self, label: &str, keys: CounterKeys) -> Option<Counter> {
        if self.exhausted {
            self.counters.count_unavailable();
            return None;
        }
        let counter = self.counters.allocate_keyed(TYPE_POSITION, label, keys);
        self.exhausted = counter.is_none();
        counter
    }

    /// A cell for a member refused in an earlier pass, not counted again.
    fn retry(&mut self, label: &str, keys: CounterKeys) -> Option<Counter> {
        if self.exhausted {
            return None;
        }
        let counter = self.counters.retry_keyed(TYPE_POSITION, label, keys);
        self.exhausted = counter.is_none();
        counter
    }
}

impl Positions {
    /// Whether a pass is due at host time `now`, `interval` nanoseconds
    /// after the last one.
    pub(crate) fn due(&self, now: u64, interval: u64) -> bool {
        self.last.is_none_or(|last| age_ns(now, last) >= interval)
    }

    /// Makes the next duty cycle run a pass.
    #[cfg(test)]
    pub(crate) fn force_due(&mut self) {
        self.last = None;
    }

    /// Sets the epoch of the last completed pass.
    #[cfg(test)]
    pub(crate) fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Runs one sampling pass at host time `now`, which it stores as
    /// `positions sampled at`.
    ///
    /// Every departed cell, of any stream, is released before any cell is
    /// allocated, so a member that leaves one stream frees its cell for a
    /// member that joins another in the same pass.
    pub(crate) fn sample<T: StreamTerms>(
        &mut self,
        now: u64,
        counters: &mut DriverCounters,
        streams: &[Stream<T>],
    ) {
        self.last = Some(now);
        let (odd, even) = next_epochs(self.epoch);
        counters.begin_pass(odd);
        // Releases: removed streams, then departed subscribers. Positions
        // are loaded here, before each stream's floor, head and limit below:
        // each only grows, so within a pass no position exceeds the head.
        self.streams.retain_mut(|cells| {
            let live = streams.iter().any(|stream| stream.id == cells.stream);
            if !live {
                cells.release(counters);
            }
            live
        });
        self.attached.resize_with(streams.len(), Vec::new);
        for (stream, attached) in streams.iter().zip(self.attached.iter_mut()) {
            collect_attached(stream, attached);
            if let Some(cells) = self
                .streams
                .iter_mut()
                .find(|cells| cells.stream == stream.id)
            {
                cells.release_departed(counters, attached);
            }
        }
        // Allocations and values.
        let mut overflowed = false;
        let mut allocator = PassAllocator {
            counters,
            exhausted: false,
        };
        for (stream, attached) in streams.iter().zip(&self.attached) {
            let index = match self
                .streams
                .iter()
                .position(|cells| cells.stream == stream.id)
            {
                Some(index) => index,
                None => {
                    let lane = stream.config.lane.get();
                    self.streams.push(StreamCells::allocate(
                        &mut allocator,
                        stream.id,
                        stream.aggregate.registration,
                        lane,
                    ));
                    self.streams.len() - 1
                }
            };
            let Some(cells) = self.streams.get_mut(index) else {
                continue;
            };
            cells.admit(&mut allocator, attached);
            for (subscriber, attached) in cells.subscribers.iter().zip(attached) {
                overflowed |= !set_checked(subscriber.position.as_ref(), attached.position);
            }
            let at = |value: u64| stream.base.checked_add(value);
            overflowed |= !set_checked(cells.floor.as_ref(), at(stream.conductor.floor()));
            if let Ok(head) = stream.conductor.head() {
                overflowed |= !set_checked(cells.head.as_ref(), at(head));
            }
            overflowed |= !set_checked(cells.limit.as_ref(), at(stream.conductor.limit()));
        }
        let counters = allocator.counters;
        // A pass in which some position did not fit counts one overflow.
        if overflowed {
            counters.add(Event::CounterOverflows, 1);
        }
        counters.set(Event::PositionsSampledAt, now);
        self.epoch = even;
        counters.end_pass(even);
    }

    /// Releases every cell in a final pass, so that a reader that outlives
    /// the driver sees the membership change at an odd epoch, as it would
    /// in any pass.
    pub(crate) fn close(&mut self, counters: &mut DriverCounters) {
        if self.streams.is_empty() {
            return;
        }
        let (odd, even) = next_epochs(self.epoch);
        counters.begin_pass(odd);
        for cells in &mut self.streams {
            cells.release(counters);
        }
        self.streams.clear();
        self.epoch = even;
        counters.end_pass(even);
    }
}

/// The odd and the even epoch of the pass after `epoch`. The even one is
/// never 0, which only the region's initial state shows (no pass yet).
///
/// The epoch is a seqlock sequence, not a position, length or counter: it
/// wraps by design, and this is its modelled rollover (SPEC.md §14, "term
/// rollover is modelled explicitly"; coordinator decision, ACS 14545,
/// quantstratum/karyos#157 group 7). A reader compares two epochs for
/// equality only, never for order, so a wrap cannot make it accept a torn
/// pass; the one value it must not see again, 0, is skipped explicitly.
fn next_epochs(epoch: u64) -> (u64, u64) {
    let odd = epoch.wrapping_add(1) | 1;
    let even = match odd.wrapping_add(1) {
        0 => 2,
        even => even,
    };
    (odd, even)
}

/// The attached subscriber cells of every live mapping of `stream`:
/// replaced incarnations first, then the oldest mapping first, skipping
/// the successor cells reserved for subscribers that have not moved yet
/// (they still read their predecessor cell).
fn collect_attached<T: StreamTerms>(stream: &Stream<T>, out: &mut Vec<Attached>) {
    out.clear();
    // Replaced incarnations first: their readers still read to the seal.
    for replaced in &stream.replaced {
        let generation = stream.generation.get();
        out.extend(replaced.conductor.subscribers().map(|cell| Attached {
            incarnation: replaced.incarnation,
            generation,
            cell: cell.cell,
            registration: cell.registration,
            position: replaced.base.checked_add(cell.position),
        }));
    }
    for retained in &stream.retained {
        let generation = retained.generation.get();
        out.extend(retained.conductor.subscribers().map(|cell| Attached {
            incarnation: stream.incarnation,
            generation,
            cell: cell.cell,
            registration: cell.registration,
            position: retained.base.checked_add(cell.position),
        }));
    }
    let generation = stream.generation.get();
    let offered = |cell: usize| {
        stream.members.iter().any(|member| {
            matches!(
                member.kind,
                MemberKind::Subscriber { cell: held, .. } | MemberKind::Recording { cell: held, .. }
                    if held == cell
            ) && member
                .link
                .upgrade()
                .is_some_and(|link| link.status() == LinkStatus::Offered)
        })
    };
    out.extend(
        stream
            .conductor
            .subscribers()
            .filter(|cell| !offered(cell.cell))
            .map(|cell| Attached {
                incarnation: stream.incarnation,
                generation,
                cell: cell.cell,
                registration: cell.registration,
                position: stream.base.checked_add(cell.position),
            }),
    );
}

impl StreamCells {
    fn keys(stream: u64, lane: u8) -> CounterKeys {
        CounterKeys {
            stream,
            lane,
            kind: KIND_NONE,
            participant: 0,
        }
    }

    fn allocate(
        allocator: &mut PassAllocator<'_>,
        stream: u64,
        registration: u64,
        lane: u8,
    ) -> Self {
        let keys = Self::keys(registration, lane);
        Self {
            stream,
            registration,
            lane,
            limit: allocator.new_cell("stream limit", keys),
            head: allocator.new_cell("stream head", keys),
            floor: allocator.new_cell("stream floor", keys),
            subscribers: Vec::new(),
        }
    }

    /// Releases the cells of subscribers no longer in `attached`.
    fn release_departed(&mut self, counters: &mut DriverCounters, attached: &[Attached]) {
        self.subscribers.retain_mut(|cells| {
            let present = attached.iter().any(|now| cells.matches(now));
            if !present && let Some(counter) = cells.position.take() {
                counters.free(counter);
            }
            present
        });
    }

    /// Makes the held subscriber cells match `attached`, in its order,
    /// after [`release_departed`](Self::release_departed): keeps the cells
    /// of subscribers still attached, allocates for new ones, and retries
    /// cells refused in an earlier pass (counted once, when first refused).
    fn admit(&mut self, allocator: &mut PassAllocator<'_>, attached: &[Attached]) {
        let stream = self.registration;
        let lane = self.lane;
        let keys = Self::keys(stream, lane);
        for (counter, label) in [
            (&mut self.limit, "stream limit"),
            (&mut self.head, "stream head"),
            (&mut self.floor, "stream floor"),
        ] {
            if counter.is_none() {
                *counter = allocator.retry(label, keys);
            }
        }
        let mut held = core::mem::take(&mut self.subscribers);
        for now in attached {
            let cells = match held.iter().position(|cells| cells.matches(now)) {
                Some(index) => {
                    let mut cells = held.swap_remove(index);
                    if cells.position.is_none() {
                        cells.position = allocator.retry(&cells.label(), cells.keys(stream, lane));
                    }
                    cells
                }
                None => SubscriberCells::allocate(allocator, stream, lane, now),
            };
            self.subscribers.push(cells);
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
            if let Some(counter) = cells.position {
                counters.free(counter);
            }
        }
    }
}

impl SubscriberCells {
    fn allocate(
        allocator: &mut PassAllocator<'_>,
        stream: u64,
        lane: u8,
        attached: &Attached,
    ) -> Self {
        let mut cells = Self {
            incarnation: attached.incarnation,
            generation: attached.generation,
            cell: attached.cell,
            registration: attached.registration,
            position: None,
        };
        cells.position = allocator.new_cell(&cells.label(), cells.keys(stream, lane));
        cells
    }

    fn keys(&self, stream: u64, lane: u8) -> CounterKeys {
        CounterKeys {
            stream,
            lane,
            kind: KIND_SUBSCRIBER,
            participant: self.registration,
        }
    }

    fn label(&self) -> String {
        // The first incarnation keeps the label tools already read; a later
        // one names itself.
        if self.incarnation == crate::embedded::FIRST_INCARNATION {
            format!(
                "subscriber position generation {} cell {}",
                self.generation, self.cell
            )
        } else {
            format!(
                "subscriber position incarnation {} generation {} cell {}",
                self.incarnation, self.generation, self.cell
            )
        }
    }

    fn matches(&self, attached: &Attached) -> bool {
        self.incarnation == attached.incarnation
            && self.generation == attached.generation
            && self.cell == attached.cell
            && self.registration == attached.registration
    }
}

/// Sets a position cell when it exists.
fn set(counter: Option<&Counter>, value: u64) {
    if let Some(counter) = counter {
        counter.set(value);
    }
}

/// Sets a position cell to `value`, or leaves it at its last value when
/// the position did not fit (`None`). Returns whether it fit.
fn set_checked(counter: Option<&Counter>, value: Option<u64>) -> bool {
    match value {
        Some(value) => {
            set(counter, value);
            true
        }
        None => false,
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
                schedule_capacity: 0,
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

    /// Label and value of every subscriber position cell.
    fn subscribers(driver: &EmbeddedDriver) -> Vec<(String, u64)> {
        positions(driver)
            .into_iter()
            .filter(|(metadata, _)| metadata.keys.kind == KIND_SUBSCRIBER)
            .map(|(metadata, value)| (String::from_utf8(metadata.label().to_vec()).unwrap(), value))
            .collect()
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

    /// A position that does not fit (checked, SPEC.md §14) leaves its cell
    /// at its last value, and the pass counts one counter overflow.
    #[test]
    fn a_position_that_does_not_fit_keeps_its_cell_and_counts_an_overflow() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let _reader = driver.subscribe(handle, Role::Required).unwrap();
        let mut writer = driver.publication(handle).unwrap();
        let _ = writer.offer(b"one").unwrap();
        let _ = driver.do_work().unwrap();
        let head = position(&driver, "stream head").unwrap();
        assert_ne!(head, 0);
        let overflows = fixed(&driver, "counter overflows");
        driver.streams[0].base = u64::MAX;
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(fixed(&driver, "positions epoch"), 4);
        assert_eq!(fixed(&driver, "counter overflows"), overflows + 1);
        assert_eq!(position(&driver, "stream head"), Some(head));
    }

    /// A clock that stepped back gives an age of zero (`age_ns`): no pass
    /// is due until it reaches the interval again.
    #[test]
    fn a_clock_that_steps_back_makes_no_pass_due() {
        let positions = Positions {
            last: Some(1_000),
            ..Positions::default()
        };
        assert!(!positions.due(500, 100));
        assert!(!positions.due(1_099, 100));
        assert!(positions.due(1_100, 100));
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
        let label = format!(
            "subscriber position generation {} cell {}",
            stream.generation.get(),
            subscriber.cell
        );
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
                lane: 0,
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
    fn a_subscriber_that_has_not_moved_reports_its_predecessor_position() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let mut reader = driver.subscribe(handle, Role::Required).unwrap();
        let mut writer = driver.publication(handle).unwrap();
        let _ = writer.offer(b"one").unwrap();
        let _ = driver.do_work().unwrap();
        let cell = driver.streams[0]
            .conductor
            .subscribers()
            .next()
            .unwrap()
            .cell;
        let _ = driver
            .reconfigure_stream(
                handle,
                crate::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 5,
                },
            )
            .unwrap();
        // The writer seals; the driver opens the successor and offers the
        // reader a successor cell, which it has not taken.
        let _ = writer.offer(b"two").unwrap();
        let _ = driver.do_work().unwrap();
        let base = driver.streams[0].base;
        assert_ne!(base, 0);
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(
            subscribers(&driver),
            vec![(format!("subscriber position generation 0 cell {cell}"), 0)]
        );
        // The reader drains the predecessor and moves.
        for _ in 0..4 {
            let _ = reader.poll(|_, _| {}, karyos_client::MessageLimit::new(8));
        }
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        let sampled = subscribers(&driver);
        let successor = sampled
            .iter()
            .find(|(label, _)| label.starts_with("subscriber position generation 1 "))
            .unwrap();
        assert_eq!(successor.1, base);
        assert!(sampled.iter().all(|(_, position)| *position <= base));
    }

    /// Gap 6: a recording reader that has not moved reports its
    /// predecessor cell only, not the successor cell reserved for it.
    #[test]
    fn a_recording_that_has_not_moved_reports_its_predecessor_position() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let _recording = driver.recording_reader(handle, Role::Optional).unwrap();
        let mut writer = driver.publication(handle).unwrap();
        let _ = writer.offer(b"one").unwrap();
        let _ = driver.do_work().unwrap();
        let cell = driver.streams[0]
            .conductor
            .subscribers()
            .next()
            .unwrap()
            .cell;
        let _ = driver
            .reconfigure_stream(
                handle,
                crate::Reconfiguration {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                    spare_slots: 5,
                },
            )
            .unwrap();
        let _ = writer.offer(b"two").unwrap();
        let _ = driver.do_work().unwrap();
        assert_ne!(driver.streams[0].base, 0);
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(
            subscribers(&driver),
            vec![(format!("subscriber position generation 0 cell {cell}"), 0)]
        );
    }

    #[test]
    fn membership_changes_only_inside_a_pass() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let _ = driver.do_work().unwrap();
        let epoch = fixed(&driver, "positions epoch");
        // Admitted between passes: no cell until the next pass.
        let reader = driver.subscribe(handle, Role::Optional).unwrap();
        let _ = driver.do_work().unwrap();
        assert!(subscribers(&driver).is_empty());
        assert_eq!(fixed(&driver, "positions epoch"), epoch);
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(subscribers(&driver).len(), 1);
        assert_eq!(fixed(&driver, "positions epoch"), epoch + 2);
        // Gone between passes: its cell stays until the next pass.
        drop(reader);
        let _ = driver.do_work().unwrap();
        assert_eq!(subscribers(&driver).len(), 1);
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert!(subscribers(&driver).is_empty());
    }

    #[test]
    fn a_cell_released_in_one_stream_serves_a_join_in_an_earlier_one() {
        // Room for both streams' cells and one subscriber cell (REVIEWER-02's
        // repro, #108): streams are sampled in order, the earlier one gains a
        // subscriber while the later one loses its own in the same pass.
        let mut driver = driver(FIXED_COUNTERS + 7);
        let earlier = driver.add_stream(stream_config(2)).unwrap();
        let later = driver.add_stream(stream_config(3)).unwrap();
        let leaving = driver.subscribe(later, Role::Optional).unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(subscribers(&driver).len(), 1);
        drop(leaving);
        let _joining = driver.subscribe(earlier, Role::Optional).unwrap();
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        let held = positions(&driver);
        let joined = held
            .iter()
            .filter(|(metadata, _)| {
                metadata.keys.kind == KIND_SUBSCRIBER
                    && metadata.keys.stream == driver.streams[0].id
            })
            .count();
        assert_eq!(joined, 1, "joining subscriber has no cell");
        assert_eq!(fixed(&driver, "counters unavailable"), 0);
    }

    #[test]
    fn refusals_after_exhaustion_are_counted_without_rescanning() {
        // Room for the stream's cells only: every subscriber is refused,
        // each counted once, and later passes add no count.
        let mut driver = driver(FIXED_COUNTERS + 3);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let _first = driver.subscribe(handle, Role::Required).unwrap();
        let _second = driver.subscribe(handle, Role::Optional).unwrap();
        let _ = driver.do_work().unwrap();
        assert!(subscribers(&driver).is_empty());
        assert_eq!(fixed(&driver, "counters unavailable"), 2);
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(fixed(&driver, "counters unavailable"), 2);
    }

    #[test]
    fn dropping_the_driver_releases_cells_in_a_final_pass() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let _reader = driver.subscribe(handle, Role::Optional).unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(positions(&driver).len(), 4);
        let before = fixed(&driver, "positions epoch");
        let region = driver.counters();
        drop(_reader);
        drop(driver);
        let mut epoch = None;
        for index in 0..region.capacity() {
            if let CellRead::Allocated {
                metadata,
                value,
                release_pending,
            } = region.read(index)
            {
                if metadata.label() == b"positions epoch" {
                    epoch = Some(value);
                }
                if metadata.type_id == TYPE_POSITION {
                    assert!(release_pending, "a position cell outlived the final pass");
                }
            }
        }
        assert_eq!(epoch, Some(before + 2));
    }

    #[test]
    fn a_replacement_subscriber_reuses_the_released_cell() {
        // Room for the three stream cells and one subscriber cell.
        let mut driver = driver(FIXED_COUNTERS + 4);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let first = driver.subscribe(handle, Role::Optional).unwrap();
        let _ = driver.do_work().unwrap();
        assert_eq!(subscribers(&driver).len(), 1);
        // Replaced between two passes.
        drop(first);
        let _second = driver.subscribe(handle, Role::Optional).unwrap();
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(subscribers(&driver).len(), 1);
        assert_eq!(fixed(&driver, "counters unavailable"), 0);
    }

    #[test]
    fn a_refused_cell_is_retried_and_counted_once() {
        // Room for two streams' cells and nothing more.
        let mut driver = driver(FIXED_COUNTERS + 6);
        // Streams are sampled in order: the later one's subscriber finds
        // no cell.
        let removed = driver.add_stream(stream_config(2)).unwrap();
        let kept = driver.add_stream(stream_config(3)).unwrap();
        let _reader = driver.subscribe(kept, Role::Optional).unwrap();
        let _ = driver.do_work().unwrap();
        assert!(subscribers(&driver).is_empty());
        assert_eq!(fixed(&driver, "counters unavailable"), 1);
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(fixed(&driver, "counters unavailable"), 1);
        driver.remove_stream(removed).unwrap();
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        assert_eq!(subscribers(&driver).len(), 1);
        assert_eq!(fixed(&driver, "counters unavailable"), 1);
    }

    #[test]
    fn cells_carry_the_stream_lane() {
        let mut driver = driver(64);
        let mut config = stream_config(2);
        config.buffer.lane = Lane::try_new(3).unwrap();
        let handle = driver.add_stream(config).unwrap();
        let _reader = driver.subscribe(handle, Role::Optional).unwrap();
        let _ = driver.do_work().unwrap();
        let held = positions(&driver);
        assert_eq!(held.len(), 4);
        assert!(held.iter().all(|(metadata, _)| metadata.keys.lane == 3));
    }

    #[test]
    fn the_epoch_never_returns_to_zero() {
        assert_eq!(next_epochs(0), (1, 2));
        assert_eq!(next_epochs(2), (3, 4));
        assert_eq!(next_epochs(u64::MAX - 1), (u64::MAX, 2));
        // An odd epoch is never stored, but the wrap from it skips 0 too.
        assert_eq!(next_epochs(u64::MAX), (1, 2));
        let mut driver = driver(64);
        driver.positions.set_epoch(u64::MAX - 1);
        let _ = driver.do_work().unwrap();
        assert_eq!(fixed(&driver, "positions epoch"), 2);
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

    /// G-d2b: a reader still on a replaced incarnation keeps its sampled
    /// position, and a reader of the fresh incarnation is told apart by
    /// its label.
    #[test]
    fn readers_of_a_replaced_incarnation_are_sampled() {
        let mut driver = driver(64);
        let handle = driver.add_stream(stream_config(2)).unwrap();
        let guard = driver.add_guard("orders").unwrap();
        driver.guard_stream(handle, guard, 4, None).unwrap();
        assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
        let _old_reader = driver.subscribe(handle, Role::Required).unwrap();
        let mut writer = driver.publication(handle).unwrap();
        let _ = writer.offer(b"one").unwrap();
        let _ = driver.close_guard(guard, 2).unwrap();
        drop(writer);
        let _ = driver.do_work().unwrap();
        assert_eq!(driver.reopen_guard(guard, 3, 3), Ok(4));
        let _fresh = driver.publication(handle).unwrap();
        let _new_reader = driver.subscribe(handle, Role::Required).unwrap();
        driver.positions.force_due();
        let _ = driver.do_work().unwrap();
        let sampled = subscribers(&driver);
        assert_eq!(sampled.len(), 2, "{sampled:?}");
        // The old reader, same cell and registration word in its own
        // incarnation, never read: position 0. The fresh reader starts at
        // the fresh incarnation's base, the seal position.
        let base = driver.streams[0].base;
        assert!(base > 0);
        let old = sampled
            .iter()
            .find(|(label, _)| label.starts_with("subscriber position generation"))
            .unwrap();
        let fresh = sampled
            .iter()
            .find(|(label, _)| label.starts_with("subscriber position incarnation 2"))
            .unwrap();
        assert_eq!((old.1, fresh.1), (0, base), "{sampled:?}");
    }
}
