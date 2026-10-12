// SPDX-License-Identifier: Apache-2.0

//! The embedded driver's system counters (SPEC.md §11): client admission,
//! command service, the terminal state and stream lifecycle, in a counters
//! region that tools read through a [`CountersReader`].
//!
//! Event counters only grow. An increment that would overflow leaves the
//! counter unchanged (ADR-0007, no silent wrap or saturation) and is
//! recorded by the `counter overflows` counter instead.

use karyos_sys::counters::{Counter, CountersManager, CountersReader, counters};

use crate::error::DriverError;

/// Type id of an event counter (only grows).
pub const TYPE_EVENTS: u64 = 1;
/// Type id of a gauge (current value).
pub const TYPE_GAUGE: u64 = 2;

/// Counters the driver allocates, in cell order.
const LABELS: [(u64, &str); 12] = [
    (TYPE_EVENTS, "clients admitted"),
    (TYPE_EVENTS, "clients retired"),
    (TYPE_EVENTS, "clients faulty"),
    (TYPE_EVENTS, "commands served"),
    (TYPE_EVENTS, "commands refused"),
    (TYPE_EVENTS, "responses sent"),
    (TYPE_GAUGE, "terminal"),
    (TYPE_GAUGE, "streams active"),
    (TYPE_GAUGE, "streams retiring"),
    (TYPE_EVENTS, "streams freed"),
    (TYPE_EVENTS, "registrations swept"),
    (TYPE_EVENTS, "counter overflows"),
];

/// One of the driver's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    ClientsAdmitted,
    ClientsRetired,
    ClientsFaulty,
    CommandsServed,
    CommandsRefused,
    ResponsesSent,
    Terminal,
    StreamsActive,
    StreamsRetiring,
    StreamsFreed,
    RegistrationsSwept,
    CounterOverflows,
}

/// The driver's counters region and its counter capabilities.
#[derive(Debug)]
pub(crate) struct DriverCounters {
    _manager: CountersManager,
    reader: CountersReader,
    counters: Vec<Counter>,
}

impl DriverCounters {
    /// Allocates the region and every counter (control path).
    pub(crate) fn new() -> Result<Self, DriverError> {
        let (mut manager, reader) =
            counters(LABELS.len()).map_err(|_| DriverError::InvalidConfig)?;
        let counters = LABELS
            .iter()
            .map(|&(type_id, label)| manager.allocate(type_id, label))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DriverError::InvalidConfig)?;
        Ok(Self {
            _manager: manager,
            reader,
            counters,
        })
    }

    fn counter(&self, event: Event) -> Option<&Counter> {
        self.counters.get(event as usize)
    }

    /// Adds `delta` to an event counter.
    pub(crate) fn add(&self, event: Event, delta: u64) {
        let Some(counter) = self.counter(event) else {
            return;
        };
        if counter.increment(delta).is_err()
            && let Some(overflows) = self.counter(Event::CounterOverflows)
        {
            // Overflowing the overflow counter itself leaves it at its last
            // value; nothing further can record it.
            let _ = overflows.increment(1);
        }
    }

    /// Sets a gauge.
    pub(crate) fn set(&self, event: Event, value: u64) {
        if let Some(counter) = self.counter(event) {
            counter.set(value);
        }
    }

    /// A read-only view for tools.
    pub(crate) fn reader(&self) -> CountersReader {
        self.reader.clone()
    }
}

#[cfg(test)]
mod tests {
    use karyos_sys::counters::CellRead;

    use super::*;

    /// `Event` discriminants index `LABELS`: every event names its own
    /// label.
    #[test]
    fn events_match_their_labels() {
        let counters = DriverCounters::new().unwrap();
        let events = [
            (Event::ClientsAdmitted, "clients admitted"),
            (Event::ClientsRetired, "clients retired"),
            (Event::ClientsFaulty, "clients faulty"),
            (Event::CommandsServed, "commands served"),
            (Event::CommandsRefused, "commands refused"),
            (Event::ResponsesSent, "responses sent"),
            (Event::Terminal, "terminal"),
            (Event::StreamsActive, "streams active"),
            (Event::StreamsRetiring, "streams retiring"),
            (Event::StreamsFreed, "streams freed"),
            (Event::RegistrationsSwept, "registrations swept"),
            (Event::CounterOverflows, "counter overflows"),
        ];
        assert_eq!(events.len(), LABELS.len());
        let reader = counters.reader();
        for (event, label) in events {
            counters.add(event, 1);
            let index = counters.counter(event).unwrap().index();
            let CellRead::Allocated {
                metadata, value, ..
            } = reader.read(index)
            else {
                panic!("counter {label} not allocated");
            };
            assert_eq!(metadata.label(), label.as_bytes());
            assert_eq!(value, 1);
        }
    }

    #[test]
    fn an_overflow_is_recorded_not_wrapped() {
        let counters = DriverCounters::new().unwrap();
        counters.set(Event::CommandsServed, u64::MAX);
        counters.add(Event::CommandsServed, 1);
        let reader = counters.reader();
        let read = |event| match reader.read(counters.counter(event).unwrap().index()) {
            CellRead::Allocated { value, .. } => value,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(read(Event::CommandsServed), u64::MAX);
        assert_eq!(read(Event::CounterOverflows), 1);
    }
}
