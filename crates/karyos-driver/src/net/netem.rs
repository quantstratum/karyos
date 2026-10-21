// SPDX-License-Identifier: Apache-2.0

//! Network fault tests (W6): they run only under `scripts/netem-test.sh`,
//! which shapes the Linux container's loopback with tc netem (loss,
//! reorder, delay, duplicate) and sets `KARYOS_NETEM_ACTIVE=1` once the
//! shaping is in place. Each test is ignored in the normal suites and
//! refuses to run without that variable, so a run over a plain loopback is
//! never taken for a netem pass.
//!
//! The driver's own fault tests over this shaping live with the
//! two-driver harness of the end-to-end tests, in `net::e2e::netem`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]
#![allow(
    clippy::print_stdout,
    reason = "the job's log records what the faults did (run with --nocapture)"
)]

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Fails a test run outside `scripts/netem-test.sh`.
pub(super) fn require_netem() {
    assert_eq!(
        std::env::var("KARYOS_NETEM_ACTIVE").as_deref(),
        Ok("1"),
        "run through scripts/netem-test.sh (tc netem on the container's loopback)"
    );
}

/// What the shaped loopback did to a probe of datagrams.
#[derive(Debug, Clone, Copy)]
pub(super) struct Shaping {
    pub(super) sent: u32,
    pub(super) received: u32,
    pub(super) lost: u32,
    pub(super) duplicates: u32,
    pub(super) reordered: u32,
}

/// Sends `sent` numbered datagrams over the loopback and counts what
/// arrives: lost, duplicated and reordered under the netem profile in
/// place.
pub(super) fn probe_loopback(sent: u32) -> Shaping {
    let receiver = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let sender = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let to = receiver.local_addr().unwrap();
    let mut seen = BTreeSet::new();
    let (mut received, mut duplicates, mut reordered, mut last) = (0u32, 0u32, 0u32, None);
    let mut buffer = [0u8; 16];
    let mut count = |number: u32| {
        received += 1;
        if !seen.insert(number) {
            duplicates += 1;
        }
        if last.is_some_and(|last| number < last) {
            reordered += 1;
        }
        last = Some(number);
    };
    // Paced in batches, drained between them, so the receiving socket's
    // buffer never overflows: what is missing is what netem dropped.
    for batch in (0..sent).collect::<Vec<_>>().chunks(50) {
        for number in batch {
            let _ = sender.send_to(&number.to_le_bytes(), to).unwrap();
        }
        let quiet = Instant::now() + Duration::from_millis(20);
        while Instant::now() < quiet {
            if let Ok(len) = receiver.recv(&mut buffer) {
                count(u32::from_le_bytes(buffer[..len.min(4)].try_into().unwrap()));
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let Ok(len) = receiver.recv(&mut buffer) else {
            break;
        };
        count(u32::from_le_bytes(buffer[..len.min(4)].try_into().unwrap()));
    }
    let lost = sent - u32::try_from(seen.len()).unwrap();
    Shaping {
        sent,
        received,
        lost,
        duplicates,
        reordered,
    }
}

/// The job's own check: datagrams over the shaped loopback are lost,
/// reordered or duplicated, so the driver's tests here really run under
/// faults.
#[test]
#[ignore = "runs under scripts/netem-test.sh"]
fn netem_shapes_the_loopback() {
    require_netem();
    let Shaping {
        sent,
        received,
        lost,
        duplicates,
        reordered,
    } = probe_loopback(2000);
    println!(
        "netem: sent {sent}, received {received}, lost {lost}, duplicated {duplicates}, reordered {reordered}"
    );
    assert!(
        lost > 0 || duplicates > 0 || reordered > 0,
        "netem had no visible effect on {sent} datagrams"
    );
}
