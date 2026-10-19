// SPDX-License-Identifier: Apache-2.0

//! Each guard's close acknowledgement as a tool reads it
//! (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`,
//! M4b): the driver counts the senders of a guard's close in effect by
//! state and writes the counts inside a pass on the guard's `guard ack
//! pass` cell, read here as one ([`crate::groups`]).

use karyos_sys::counters::{CountersReader, KIND_GUARD};

/// The label of a guard's acknowledgement pass cell.
pub const PASS_LABEL: &str = "guard ack pass";

const EPOCH: &str = "guard ack epoch";
const APPLIED: &str = "guard senders applied";
const IN_FLIGHT: &str = "guard senders in flight";
const PENDING: &str = "guard senders pending";
const OVERDUE: &str = "guard senders overdue";

/// One guard's close acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuardAck {
    /// The guard id.
    pub guard: u64,
    /// Whether the counts come from one completed pass (see
    /// [`crate::groups::Group::consistent`]).
    pub consistent: bool,
    /// The close epoch counted; 0 while no close is in effect (the guard
    /// is open, or only created).
    pub epoch: u64,
    /// Senders that applied the close with nothing in flight: it is
    /// effective there.
    pub applied: u64,
    /// Senders that applied it with work still in flight.
    pub in_flight: u64,
    /// Senders that have not applied it yet, within the timeout.
    pub pending: u64,
    /// Senders that have not applied it past `guard_ack_timeout`.
    pub overdue: u64,
}

/// Every guard's close acknowledgement in `reader`.
#[must_use]
pub fn guard_acks(reader: &CountersReader) -> Vec<GuardAck> {
    let labels = [EPOCH, APPLIED, IN_FLIGHT, PENDING, OVERDUE];
    crate::groups::read_groups(reader, KIND_GUARD, PASS_LABEL, |label| {
        labels.contains(&label)
    })
    .into_iter()
    .map(|group| {
        let value = |name: &str| {
            group
                .gauges
                .iter()
                .find(|(label, _)| label == name)
                .map_or(0, |(_, value)| *value)
        };
        GuardAck {
            guard: group.participant,
            // Every count must be there to trust the group.
            consistent: group.consistent && group.gauges.len() == labels.len(),
            epoch: value(EPOCH),
            applied: value(APPLIED),
            in_flight: value(IN_FLIGHT),
            pending: value(PENDING),
            overdue: value(OVERDUE),
        }
    })
    .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests, as ADR-0007 allows"
    )]

    use karyos_sys::counters::{CounterKeys, counters};

    use super::*;

    /// A guard's counts read as one between passes; the word gauge beside
    /// them (labelled with the guard's name) is not one of them.
    #[test]
    fn a_guards_acknowledgement_reads_as_one() {
        let (mut manager, reader) = counters(16).unwrap();
        let keys = CounterKeys {
            kind: KIND_GUARD,
            participant: 4,
            ..CounterKeys::DRIVER
        };
        let word = manager.allocate_keyed(2, "kill switch", keys).unwrap();
        word.set(3);
        let pass = manager.allocate_keyed(2, PASS_LABEL, keys).unwrap();
        let cells: Vec<_> = [EPOCH, APPLIED, IN_FLIGHT, PENDING, OVERDUE]
            .iter()
            .map(|label| manager.allocate_keyed(2, label, keys).unwrap())
            .collect();
        // Allocated, no pass yet: not to be trusted.
        assert!(!guard_acks(&reader)[0].consistent);
        pass.begin_pass(1);
        for (cell, value) in cells.iter().zip([3, 1, 0, 2, 1]) {
            cell.set(value);
        }
        assert!(!guard_acks(&reader)[0].consistent, "a pass in progress");
        pass.end_pass(2);
        assert_eq!(
            guard_acks(&reader),
            [GuardAck {
                guard: 4,
                consistent: true,
                epoch: 3,
                applied: 1,
                in_flight: 0,
                pending: 2,
                overdue: 1,
            }]
        );
    }
}
