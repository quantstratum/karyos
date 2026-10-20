// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::num::NonZeroU32;

use karyos_io::backend::{BackendEpoch, ClockDomain, ClockEpoch, InstanceId};
use karyos_io::sockets::endpoint::{BufferSize, ClockInfo, ObservationPoints};
use karyos_sys::counters::CellRead;

use super::*;

const LIBRARY_API: CapabilityState = CapabilityState::Unavailable(Reason::LibraryApi);

/// A sockets snapshot of endpoint `id` at `epoch`, with TX batching on a
/// platform fallback and a send buffer below its request.
fn snapshot(id: u32, epoch: u32) -> CapabilitySnapshot {
    CapabilitySnapshot {
        instance: InstanceId::new(NonZeroU32::new(id).unwrap()),
        epoch: BackendEpoch::new(NonZeroU32::new(epoch).unwrap()),
        platform: Platform::Linux,
        copy_mode: CopyMode::Staged,
        local: "127.0.0.1:4000".parse().unwrap(),
        interface: None,
        queue_assignment: QueueAssignment::KernelSelected,
        max_datagram: 1408,
        observation_points: ObservationPoints {
            send_return: false,
            recv_return: true,
        },
        clock: ClockInfo {
            domain: ClockDomain::HostMonotonic,
            epoch: ClockEpoch::new(1),
            granularity_ns: 1,
        },
        dont_fragment: CapabilityState::Active,
        tx_batch: CapabilityState::Fallback(Reason::Platform),
        rx_batch: LIBRARY_API,
        gso: LIBRARY_API,
        gro: LIBRARY_API,
        kernel_stamps: LIBRARY_API,
        hardware_stamps: LIBRARY_API,
        busy_poll: LIBRARY_API,
        user_observations: CapabilityState::Active,
        send_buffer: BufferSize {
            requested: NonZeroU32::new(1 << 20),
            effective: Some(212_992),
            state: CapabilityState::Fallback(Reason::BelowRequest { effective: 212_992 }),
        },
        recv_buffer: BufferSize::NOT_REQUESTED,
        multicast: None,
        enobufs_reported: false,
    }
}

/// Label -> value of the cells of endpoint `id`.
fn gauges(counters: &DriverCounters, id: u32) -> Vec<(String, u64)> {
    let reader = counters.reader();
    (0..reader.capacity())
        .filter_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.keys.kind == KIND_ENDPOINT
                && metadata.keys.participant == u64::from(id) =>
            {
                assert_eq!((metadata.keys.stream, metadata.keys.lane), (0, 0));
                assert_eq!(metadata.type_id, TYPE_GAUGE);
                Some((String::from_utf8(metadata.label().to_vec()).unwrap(), value))
            }
            _ => None,
        })
        .collect()
}

fn gauge(counters: &DriverCounters, id: u32, label: &str) -> u64 {
    gauges(counters, id)
        .into_iter()
        .find(|(name, _)| name == label)
        .unwrap()
        .1
}

#[test]
fn a_state_packs_its_code_reason_and_detail() {
    assert_eq!(state_code(CapabilityState::NotRequested), 0);
    assert_eq!(state_code(CapabilityState::Active), 1);
    assert_eq!(
        state_code(CapabilityState::Fallback(Reason::Platform)),
        2 | 2 << 8
    );
    assert_eq!(state_code(LIBRARY_API), 3 | 3 << 8);
    assert_eq!(
        state_code(CapabilityState::Unavailable(Reason::Denied { errno: 1 })),
        3 | 5 << 8 | 1 << 32
    );
    assert_eq!(
        state_code(CapabilityState::Fallback(Reason::BelowRequest {
            effective: u32::MAX
        })),
        2 | 7 << 8 | u64::from(u32::MAX) << 32
    );
    assert_eq!(
        state_code(CapabilityState::Fallback(Reason::Unverified)),
        2 | 8 << 8
    );
}

/// An endpoint gets its gauges when it appears, keyed by its instance;
/// its fallbacks count once per epoch; a reopen rewrites them and counts
/// again; a steady sync writes nothing; an endpoint that leaves frees its
/// cells; the close frees the rest.
#[test]
fn endpoint_gauges_follow_the_table() {
    let mut counters = DriverCounters::with_capacity(crate::counters::FIXED_COUNTERS + 64).unwrap();
    let mut cells = CapabilityCells::default();
    let one = snapshot(1, 1);
    let two = snapshot(2, 1);
    cells.sync(
        &mut counters,
        [(EndpointId(1), &one), (EndpointId(2), &two)].into_iter(),
        0,
    );
    // The gauges and their pass cell, even after one pass.
    assert_eq!(gauges(&counters, 1).len(), LABELS.len() + 1);
    assert_eq!(gauge(&counters, 1, PASS_LABEL), 2);
    assert_eq!(gauge(&counters, 1, "capability epoch"), 1);
    assert_eq!(gauge(&counters, 1, "capability platform"), 1);
    assert_eq!(gauge(&counters, 1, "capability max datagram"), 1408);
    assert_eq!(gauge(&counters, 1, "capability observation points"), 2);
    assert_eq!(gauge(&counters, 1, "capability dont fragment"), 1);
    assert_eq!(gauge(&counters, 1, "capability tx batch"), 2 | 2 << 8);
    assert_eq!(gauge(&counters, 1, "capability gso"), 3 | 3 << 8);
    assert_eq!(gauge(&counters, 1, "capability recv buffer"), 0);
    assert_eq!(gauge(&counters, 1, "capability send buffer bytes"), 212_992);
    assert_eq!(gauge(&counters, 1, "capability recv buffer bytes"), 0);
    // Two endpoints, two fallbacks each.
    assert_eq!(counters.value(Event::CapabilityFallback), 4);
    // A steady sync counts nothing again.
    cells.sync(
        &mut counters,
        [(EndpointId(1), &one), (EndpointId(2), &two)].into_iter(),
        0,
    );
    assert_eq!(counters.value(Event::CapabilityFallback), 4);
    // Endpoint 1 reopens at epoch 2 with TX batching active; endpoint 2
    // leaves; one open was refused for a required capability.
    let reopened = CapabilitySnapshot {
        tx_batch: CapabilityState::Active,
        ..snapshot(1, 2)
    };
    cells.sync(&mut counters, [(EndpointId(1), &reopened)].into_iter(), 1);
    assert_eq!(gauge(&counters, 1, "capability epoch"), 2);
    // The rewrite was a second pass.
    assert_eq!(gauge(&counters, 1, PASS_LABEL), 4);
    assert_eq!(gauge(&counters, 1, "capability tx batch"), 1);
    assert_eq!(counters.value(Event::CapabilityFallback), 5);
    assert!(gauges(&counters, 2).is_empty());
    assert_eq!(counters.value(Event::CapabilityMissing), 1);
    // The missing count moves by its delta only.
    cells.sync(&mut counters, [(EndpointId(1), &reopened)].into_iter(), 3);
    assert_eq!(counters.value(Event::CapabilityMissing), 3);
    cells.close(&mut counters);
    assert!(gauges(&counters, 1).is_empty());
}

/// A region with no room for an endpoint's gauges skips them and counts
/// each refusal in `counters unavailable`; the endpoint still counts its
/// fallbacks.
#[test]
fn a_full_region_skips_the_gauges() {
    let mut counters = DriverCounters::with_capacity(crate::counters::FIXED_COUNTERS + 3).unwrap();
    let mut cells = CapabilityCells::default();
    let one = snapshot(1, 1);
    cells.sync(&mut counters, [(EndpointId(1), &one)].into_iter(), 0);
    // The pass cell first, then two gauges.
    assert_eq!(gauges(&counters, 1).len(), 3);
    assert_eq!(gauge(&counters, 1, PASS_LABEL), 2);
    assert_eq!(
        counters.value(Event::CountersUnavailable),
        u64::try_from(LABELS.len() - 2).unwrap()
    );
    assert_eq!(counters.value(Event::CapabilityFallback), 2);
}
