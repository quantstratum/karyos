// SPDX-License-Identifier: Apache-2.0

//! Loopback UDP ports for tests that name an endpoint before any socket
//! binds it (karyos#520).
//!
//! A port read back from a socket bound to port 0 and then dropped is the
//! kernel's ephemeral port: until the driver binds it, any other bind to
//! port 0, of a test running in parallel or of the test's own publisher,
//! may be handed the same number, and the driver's bind then fails
//! (`ResourcesUnavailable`). The longer the test waits and the busier the
//! host, the likelier that is. [`test_port`] picks from a range below every
//! ephemeral range in use (Linux 32768 to 60999, macOS 49152 to 65535), so
//! no bind to port 0 ever takes it. What remains is another explicit
//! binder of the same range, such as another test process using this
//! helper: each process starts at an offset of its own and walks the range
//! once, skipping ports it cannot bind. A port is still only checked, not
//! held, before the driver binds it: a near certainty, not a guarantee.
//! The race goes away only when a subscription can take `endpoint=host:0`
//! and report the port it bound, owner item 26 (quantstratum-docs:
//! `karyos/design/ephemeral-subscription-port.md`, docs#181).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};

/// The first port of the range.
const FIRST: u32 = 20_000;
/// Ports in the range: 20000 to 31999.
const COUNT: u32 = 12_000;

/// A loopback UDP port no socket holds now, outside the ephemeral range.
///
/// # Panics
///
/// When every port of the range was handed out or found taken.
#[must_use]
#[allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]
pub(crate) fn test_port() -> u16 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    // A process's own starting point, so that test processes running at
    // once rarely walk the same ports.
    let start = std::process::id().wrapping_mul(2_654_435_761) % COUNT;
    loop {
        let taken = NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(taken < COUNT, "no free test port left in the range");
        // The range ends at 31999, within a u16: a failure here is loud.
        let port = u16::try_from(FIRST + (start + taken) % COUNT).unwrap();
        if UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).is_ok() {
            return port;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    /// The range is the point: a thousand binds to port 0, the race of
    /// karyos#520, never land in it on this host, and the ports handed out
    /// are in it and distinct. One socket at a time, within any limit of
    /// open files.
    #[test]
    fn ephemeral_binds_never_land_in_the_test_range() {
        let range = FIRST..FIRST + COUNT;
        for _ in 0..1000 {
            let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let port = u32::from(socket.local_addr().unwrap().port());
            assert!(
                !range.contains(&port),
                "ephemeral port {port} in the test range"
            );
        }
        let (first, second) = (test_port(), test_port());
        assert!(range.contains(&u32::from(first)) && range.contains(&u32::from(second)));
        assert_ne!(first, second);
    }
}
