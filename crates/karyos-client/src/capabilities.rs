// SPDX-License-Identifier: Apache-2.0

//! Each network endpoint's capability gauges as a tool reads them
//! (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`,
//! M3 and M6b): the gauges of one endpoint are written together inside a
//! sampling pass on its `capability pass` cell, so they are read as one
//! with `read_pass` over that cell ([`crate::groups`]), or reported
//! inconsistent after a few attempts. Never waits. It lives here, beside the tool attach, so both
//! `karyos-tools` and the management agent read the groups the same way.

use karyos_sys::counters::{CountersReader, KIND_ENDPOINT};

/// The label of an endpoint's pass cell, as the driver writes it.
pub const PASS_LABEL: &str = "capability pass";

/// One endpoint's capability gauges.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndpointCapabilities {
    /// The endpoint's instance id (`key2`).
    pub endpoint: u64,
    /// Whether the values come from one completed pass. `false` when every
    /// attempt overlapped a write, when no pass completed yet (the pass
    /// cell still 0: the gauges hold their allocation zeros), or when the
    /// endpoint has no pass cell (the region had no room for it).
    pub consistent: bool,
    /// Label and value of each gauge, in cell order.
    pub gauges: Vec<(String, u64)>,
}

/// Every endpoint's capability gauges in `reader`, in the order of their
/// first cells.
#[must_use]
pub fn endpoint_capabilities(reader: &CountersReader) -> Vec<EndpointCapabilities> {
    crate::groups::read_groups(reader, KIND_ENDPOINT, PASS_LABEL, |_| true)
        .into_iter()
        .map(|group| EndpointCapabilities {
            endpoint: group.participant,
            consistent: group.consistent,
            gauges: group.gauges,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use karyos_sys::counters::{CounterKeys, counters};

    use super::*;

    fn keys(endpoint: u64) -> CounterKeys {
        CounterKeys {
            kind: KIND_ENDPOINT,
            participant: endpoint,
            ..CounterKeys::DRIVER
        }
    }

    /// A group read between passes is consistent; one read while its pass
    /// cell is odd (a write in progress) is not; an endpoint without a pass
    /// cell is never consistent; other cells are not endpoints.
    #[test]
    fn a_group_reads_as_one_only_between_passes() {
        let (mut manager, reader) = counters(8).unwrap();
        let _driver = manager.allocate(1, "streams active").unwrap();
        let pass = manager.allocate_keyed(2, PASS_LABEL, keys(7)).unwrap();
        let epoch = manager
            .allocate_keyed(2, "capability epoch", keys(7))
            .unwrap();
        // Allocated, no pass begun yet: the gauges' zeros are no read
        // (IMPLEMENT's P2 on #474).
        let read = endpoint_capabilities(&reader);
        assert!(!read[0].consistent);
        let mtu = manager
            .allocate_keyed(2, "capability max datagram", keys(7))
            .unwrap();
        let lone = manager
            .allocate_keyed(2, "capability epoch", keys(9))
            .unwrap();
        pass.begin_pass(1);
        epoch.set(1);
        mtu.set(1408);
        pass.end_pass(2);
        lone.set(3);
        let read = endpoint_capabilities(&reader);
        assert_eq!(
            read,
            [
                EndpointCapabilities {
                    endpoint: 7,
                    consistent: true,
                    gauges: vec![
                        ("capability epoch".to_owned(), 1),
                        ("capability max datagram".to_owned(), 1408),
                    ],
                },
                EndpointCapabilities {
                    endpoint: 9,
                    consistent: false,
                    gauges: vec![("capability epoch".to_owned(), 3)],
                },
            ]
        );
        // A writer in the middle of a pass: the group is not one read.
        pass.begin_pass(3);
        epoch.set(2);
        let read = endpoint_capabilities(&reader);
        assert!(!read[0].consistent);
        pass.end_pass(4);
        let read = endpoint_capabilities(&reader);
        assert!(read[0].consistent);
        assert_eq!(read[0].gauges[0], ("capability epoch".to_owned(), 2));
    }
}
