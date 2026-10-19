// SPDX-License-Identifier: Apache-2.0

//! Each network endpoint's effective capabilities in the CnC, for tools
//! (SPEC §16.8; `quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md`, M3).
//!
//! - **Cells.** Each endpoint in the table has one gauge per entry of
//!   [`LABELS`], keyed by participant kind [`KIND_ENDPOINT`] and its
//!   instance id (`key2`), stream and lane zero. The conductor allocates
//!   them when it first sees the endpoint, rewrites them when the endpoint
//!   reopens at a new capability epoch, and frees them when the endpoint
//!   leaves the table or the network closes. It is their only writer.
//! - **States.** A capability's gauge holds [`state_code`]: the state in
//!   bits 7 to 0 (0 not requested, 1 active, 2 fallback, 3 unavailable),
//!   the reason in bits 15 to 8 (0 none, 1 not built, 2 platform, 3 library
//!   API, 4 unsupported, 5 denied, 6 probe failed, 7 below request, 8
//!   unverified) and the reason's detail in bits 63 to 32: the OS error
//!   number, or the effective value below the request.
//! - **Degradations.** `capability fallback` counts, once per endpoint
//!   epoch, every capability whose state is a fallback; `capability
//!   missing` counts opens and reopens refused because a required
//!   capability was not active. Unrequested capabilities the platform
//!   lacks are reported in their gauges and counted in neither.
//!
//! Allocation happens only when an endpoint appears; a steady duty cycle
//! compares epochs and writes nothing.

use karyos_io::backend::{CapabilityState, Reason};
use karyos_io::sockets::endpoint::{CapabilitySnapshot, CopyMode, Platform, QueueAssignment};
use karyos_sys::counters::{Counter, CounterKeys, KIND_ENDPOINT};

use crate::agents::EndpointId;
use crate::counters::{DriverCounters, Event, TYPE_GAUGE};

/// An endpoint's capability gauges, in [`values`] order.
pub(crate) const LABELS: [&str; 20] = [
    "capability epoch",
    "capability platform",
    "capability copy mode",
    "capability queue assignment",
    "capability max datagram",
    "capability observation points",
    "capability clock granularity",
    "capability dont fragment",
    "capability tx batch",
    "capability rx batch",
    "capability gso",
    "capability gro",
    "capability kernel stamps",
    "capability hardware stamps",
    "capability busy poll",
    "capability user observations",
    "capability send buffer",
    "capability recv buffer",
    "capability send buffer bytes",
    "capability recv buffer bytes",
];

/// The states of `snapshot`'s capabilities, in the order of their labels.
fn states(snapshot: &CapabilitySnapshot) -> [CapabilityState; 11] {
    [
        snapshot.dont_fragment,
        snapshot.tx_batch,
        snapshot.rx_batch,
        snapshot.gso,
        snapshot.gro,
        snapshot.kernel_stamps,
        snapshot.hardware_stamps,
        snapshot.busy_poll,
        snapshot.user_observations,
        snapshot.send_buffer.state,
        snapshot.recv_buffer.state,
    ]
}

/// The gauges of `snapshot`, in [`LABELS`] order. Platform 1 is Linux, 2
/// macOS; copy mode 1 is staged; queue assignment 1 is kernel selected;
/// observation points has bit 0 for send return and bit 1 for receive
/// return; a buffer's bytes are 0 when the platform does not report them.
fn values(snapshot: &CapabilitySnapshot) -> [u64; LABELS.len()] {
    let [
        dont_fragment,
        tx_batch,
        rx_batch,
        gso,
        gro,
        kernel_stamps,
        hardware_stamps,
        busy_poll,
        user_observations,
        send_buffer,
        recv_buffer,
    ] = states(snapshot).map(state_code);
    [
        u64::from(snapshot.epoch.get().get()),
        match snapshot.platform {
            Platform::Linux => 1,
            Platform::MacOs => 2,
        },
        match snapshot.copy_mode {
            CopyMode::Staged => 1,
        },
        match snapshot.queue_assignment {
            QueueAssignment::KernelSelected => 1,
        },
        u64::from(snapshot.max_datagram),
        u64::from(snapshot.observation_points.send_return)
            | u64::from(snapshot.observation_points.recv_return) << 1,
        snapshot.clock.granularity_ns,
        dont_fragment,
        tx_batch,
        rx_batch,
        gso,
        gro,
        kernel_stamps,
        hardware_stamps,
        busy_poll,
        user_observations,
        send_buffer,
        recv_buffer,
        u64::from(snapshot.send_buffer.effective.unwrap_or(0)),
        u64::from(snapshot.recv_buffer.effective.unwrap_or(0)),
    ]
}

/// `state` as a gauge (module documentation, States).
pub(crate) fn state_code(state: CapabilityState) -> u64 {
    let (code, reason) = match state {
        CapabilityState::NotRequested => (0, None),
        CapabilityState::Active => (1, None),
        CapabilityState::Fallback(reason) => (2, Some(reason)),
        CapabilityState::Unavailable(reason) => (3, Some(reason)),
    };
    let (reason, detail) = match reason {
        None => (0, 0),
        Some(Reason::NotBuilt) => (1, 0),
        Some(Reason::Platform) => (2, 0),
        Some(Reason::LibraryApi) => (3, 0),
        Some(Reason::Unsupported { errno }) => (4, errno.unsigned_abs()),
        Some(Reason::Denied { errno }) => (5, errno.unsigned_abs()),
        Some(Reason::ProbeFailed { errno }) => (6, errno.unsigned_abs()),
        Some(Reason::BelowRequest { effective }) => (7, effective),
        Some(Reason::Unverified) => (8, 0),
    };
    code | reason << 8 | u64::from(detail) << 32
}

/// The capabilities of `snapshot` that run on a fallback.
fn fallbacks(snapshot: &CapabilitySnapshot) -> u64 {
    let count = states(snapshot)
        .iter()
        .filter(|state| matches!(state, CapabilityState::Fallback(_)))
        .count();
    // At most the 11 capabilities: it fits.
    u64::try_from(count).unwrap_or(0)
}

/// One endpoint's cells.
#[derive(Debug)]
struct EndpointCells {
    id: EndpointId,
    /// The capability epoch the cells show.
    epoch: u32,
    cells: Vec<Option<Counter>>,
    /// Seen in the current sync.
    seen: bool,
}

/// Every endpoint's cells, and the `capability missing` count published.
#[derive(Debug, Default)]
pub(crate) struct CapabilityCells {
    endpoints: Vec<EndpointCells>,
    missing: u64,
}

impl CapabilityCells {
    /// Brings the cells in line with `snapshots`, the endpoint table's
    /// current epochs, and `missing`, its count of refused opens (control
    /// path, each conductor duty cycle).
    pub(crate) fn sync<'a>(
        &mut self,
        counters: &mut DriverCounters,
        snapshots: impl Iterator<Item = (EndpointId, &'a CapabilitySnapshot)>,
        missing: u64,
    ) {
        for endpoint in &mut self.endpoints {
            endpoint.seen = false;
        }
        for (id, snapshot) in snapshots {
            let epoch = snapshot.epoch.get().get();
            match self.endpoints.iter_mut().find(|cells| cells.id == id) {
                Some(cells) => {
                    cells.seen = true;
                    if cells.epoch != epoch {
                        cells.epoch = epoch;
                        write(counters, &cells.cells, snapshot);
                    }
                }
                None => {
                    let keys = CounterKeys {
                        kind: KIND_ENDPOINT,
                        participant: u64::from(id.0),
                        ..CounterKeys::DRIVER
                    };
                    let cells = LABELS
                        .iter()
                        .map(|label| counters.allocate_keyed(TYPE_GAUGE, label, keys))
                        .collect();
                    let cells = EndpointCells {
                        id,
                        epoch,
                        cells,
                        seen: true,
                    };
                    write(counters, &cells.cells, snapshot);
                    self.endpoints.push(cells);
                }
            }
        }
        let mut index = 0;
        while let Some(endpoint) = self.endpoints.get(index) {
            if endpoint.seen {
                index += 1;
            } else {
                let gone = self.endpoints.swap_remove(index);
                free(counters, gone.cells);
            }
        }
        if let Some(delta) = missing.checked_sub(self.missing).filter(|delta| *delta > 0) {
            counters.add(Event::CapabilityMissing, delta);
            self.missing = missing;
        }
    }

    /// Frees every endpoint's cells (the network closed).
    pub(crate) fn close(&mut self, counters: &mut DriverCounters) {
        for endpoint in self.endpoints.drain(..) {
            free(counters, endpoint.cells);
        }
    }
}

/// Writes `snapshot` into `cells` and counts its fallbacks.
fn write(counters: &DriverCounters, cells: &[Option<Counter>], snapshot: &CapabilitySnapshot) {
    for (cell, value) in cells.iter().zip(values(snapshot)) {
        if let Some(cell) = cell {
            cell.set(value);
        }
    }
    let fallbacks = fallbacks(snapshot);
    if fallbacks > 0 {
        counters.add(Event::CapabilityFallback, fallbacks);
    }
}

fn free(counters: &mut DriverCounters, cells: Vec<Option<Counter>>) {
    for cell in cells.into_iter().flatten() {
        counters.free(cell);
    }
}

#[cfg(test)]
mod tests;
