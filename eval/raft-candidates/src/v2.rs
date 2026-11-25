// SPDX-License-Identifier: Apache-2.0

//! C5 version 2's frozen W2 in-flight byte case (quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v2.md, "W2: an in-flight byte
//! case that reaches its bound"), shared by its oracle
//! (`tests/w2_bytes.rs`), the corpus runner (`tests/corpus.rs`) and the
//! real-process runs (`tests/real_processes.rs`, through the node and
//! client processes), so all run the very same case.

use karyos_sim::harness::core::Limits;
use karyos_sim::harness::workloads::{Case, W2};

/// The frozen byte cap per follower.
pub const CAP: u64 = 256 * 1024;

/// The case's note in every raw result line.
pub const NOTE: &str = "C5 v2 W2 in-flight byte case (quantstratum-docs#1026): 8,192-byte values, 256 KiB in flight per follower";

/// The frozen case: 3 servers, 32 clients with 4 requests open each,
/// 8,192-byte values, 256 KiB and version 1's 64 entries in flight, queue
/// of 1,024, log read of 1 MiB, 128 operations per client.
#[must_use]
pub fn byte_case() -> Case {
    byte_case_of(8192, 64, CAP, 4, 128)
}

/// W2's manifest limits but `in_flight_entries` and `in_flight_bytes`,
/// with `payload` values, `window` requests open per client and
/// `per_client` operations per client.
#[must_use]
pub fn byte_case_of(
    payload: usize,
    in_flight_entries: u64,
    in_flight_bytes: u64,
    window: usize,
    per_client: usize,
) -> Case {
    let w2 = W2 {
        payload_bytes: payload,
        limits: Limits {
            in_flight_entries,
            in_flight_bytes,
            ..W2::manifest().limits
        },
        ..W2::manifest()
    };
    let mut case = w2
        .cases()
        .ok()
        .and_then(|cases| cases.into_iter().next())
        .unwrap_or_else(|| unreachable!("W2's manifest has a nominal case"));
    case.name = format!(
        "W2 v2 n=3 clients=32 window={window} payload={payload} in-flight {in_flight_entries} entries {in_flight_bytes} B"
    );
    case.window = window;
    case.operations = per_client / window;
    case.notes = vec![NOTE];
    case
}
