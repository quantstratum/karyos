// SPDX-License-Identifier: Apache-2.0

//! Tests of [`PortableSocket`] on the loopback interface (`quantstratum-docs:
//! karyos/design/sockets-backend.md` section 9, "Loopback, Linux and
//! macOS"): setup, the recorded gaps of `std`, the send and receive results
//! the kernel really returns, duplication and close. Unprivileged; the
//! endpoint level rows of section 12 run in `endpoint/tests/loopback.rs`
//! on both platforms.

use std::net::{Ipv6Addr, UdpSocket};
use std::time::{Duration, Instant};

use super::*;

fn ipv4_any_port() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A configuration on `local` with no buffer requests.
fn config(local: SocketAddr) -> SocketsConfig {
    let mut config = SocketsConfig::new(local);
    config.send_buffer = None;
    config.recv_buffer = None;
    config
}

/// An open socket on an ephemeral loopback port, and its address.
fn open_ipv4() -> (PortableSocket, SocketAddr) {
    let mut socket = PortableSocket::new();
    let probes = socket.open(&config(ipv4_any_port())).unwrap();
    (socket, probes.local)
}

/// How long [`recv_one`] waits for loopback traffic that should already be
/// there: a time limit rather than a number of tries, so a loaded host
/// does not fail the test.
const PATIENCE: Duration = Duration::from_secs(10);

/// Receives one datagram, retrying `EAGAIN` until [`PATIENCE`] runs out:
/// loopback delivery is synchronous, so the first call normally succeeds.
/// Neither the clock nor the yield allocates, so the no allocation test
/// uses it too.
fn recv_one(socket: &mut PortableSocket, buffer: &mut [u8]) -> RecvResult {
    let start = Instant::now();
    loop {
        match socket.recv(buffer) {
            RecvResult::Error(Errno::AGAIN) if start.elapsed() < PATIENCE => {
                std::thread::yield_now();
            }
            result => return result,
        }
    }
}

/// Records a skipped case with its reason (section 9).
#[expect(
    clippy::print_stderr,
    reason = "section 9 records every skip with its reason in the test log"
)]
fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

const SENT_ONE: SendResult = SendResult::Sent {
    sent: 1,
    error: None,
};

/// The probes record what `std` cannot do (4.1, 8.1): no don't fragment,
/// no batching, and buffer requests without an effective size.
#[test]
fn open_binds_and_records_the_gaps_of_std() {
    let mut socket = PortableSocket::new();
    assert!(!socket.is_open());
    let probes = socket.open(&config(ipv4_any_port())).unwrap();
    assert!(socket.is_open());
    assert_eq!(probes.local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(probes.local.port(), 0, "local_addr reports the chosen port");
    assert_eq!(probes.interface, None);
    assert_eq!(
        probes.dont_fragment,
        CapabilityState::Fallback(Reason::LibraryApi)
    );
    assert_eq!(probes.tx_batch, CapabilityState::Fallback(Reason::Platform));
    assert_eq!(probes.send_buffer, BufferSize::NOT_REQUESTED);
    assert_eq!(probes.recv_buffer, BufferSize::NOT_REQUESTED);
    assert_eq!(probes.multicast, None);

    let requested = NonZeroU32::new(64 * 1024).unwrap();
    let mut wanted = config(ipv4_any_port());
    wanted.send_buffer = Some(requested);
    wanted.recv_buffer = Some(requested);
    let probes = socket.open(&wanted).unwrap();
    for buffer in [probes.send_buffer, probes.recv_buffer] {
        assert_eq!(
            buffer,
            BufferSize {
                requested: Some(requested),
                effective: None,
                state: CapabilityState::Fallback(Reason::LibraryApi),
            }
        );
    }
}

#[test]
fn open_ipv6_loopback() {
    let mut socket = PortableSocket::new();
    let local = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    match socket.open(&config(local)) {
        Ok(probes) => assert!(probes.local.is_ipv6()),
        Err(OpenError::Os { operation, errno }) => {
            skip(&format!(
                "IPv6 loopback unavailable ({operation}: os error {errno})"
            ));
        }
        Err(other) => panic!("unexpected {other:?}"),
    }
}

/// `open` on an open socket closes the old one before it binds again:
/// reopening on the same address succeeds without a `close` call, and the
/// port stays held by this socket until `open` itself closes it, so a
/// parallel test binding port 0 cannot take it in between.
#[test]
fn reopen_closes_the_old_socket_and_a_failed_open_keeps_none() {
    let (mut socket, local) = open_ipv4();
    // Binding the same address again fails while the first socket is
    // open (`EADDRINUSE`, 48 on macOS); that open leaves no socket.
    let mut second = PortableSocket::new();
    assert_eq!(
        second.open(&config(local)),
        Err(OpenError::Os {
            operation: "bind",
            errno: 48,
        })
    );
    assert!(!second.is_open());
    // Reopen without `close`: the old socket is closed first.
    let probes = socket.open(&config(local)).unwrap();
    assert_eq!(probes.local, local);
    let (mut peer, _) = open_ipv4();
    assert_eq!(peer.send(&RouteAddr::new(local), &[b"reopened"]), SENT_ONE);
    let mut buffer = [0_u8; 16];
    assert!(matches!(
        recv_one(&mut socket, &mut buffer),
        RecvResult::Datagram { len: 8, .. }
    ));
    socket.close();
    assert!(!socket.is_open());
}

/// What `std` cannot express is refused, never replaced: an IPv4
/// membership by a nonzero interface index, an IPv6 hop limit other than
/// the macOS default and an IPv6 group on an IPv4 interface address.
#[test]
fn multicast_options_std_cannot_set_are_refused() {
    let mut socket = PortableSocket::new();
    let mut by_index = config(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    by_index.multicast = Some(MulticastConfig::new(
        IpAddr::V4(Ipv4Addr::new(239, 255, 77, 9)),
        InterfaceSel::Index(1),
    ));
    assert_eq!(
        socket.open(&by_index),
        Err(OpenError::InvalidConfig {
            field: "multicast.interface",
            value: 1,
        })
    );
    assert!(!socket.is_open());

    let group = IpAddr::V6("ff02::1:2".parse().unwrap());
    let local = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let mut hops = config(local);
    let mut multicast = MulticastConfig::new(group, InterfaceSel::Index(1));
    multicast.ttl = 8;
    hops.multicast = Some(multicast);
    let mut on_address = config(local);
    on_address.multicast = Some(MulticastConfig::new(
        group,
        InterfaceSel::Address(Ipv4Addr::LOCALHOST),
    ));
    let refusals = [
        (hops, "multicast.ttl", 8),
        (on_address, "multicast.interface", 0),
    ];
    for (wanted, field, value) in refusals {
        match socket.open(&wanted) {
            Err(OpenError::InvalidConfig {
                field: refused,
                value: got,
            }) => assert_eq!((refused, got), (field, value)),
            Err(OpenError::Os { operation, errno }) => {
                skip(&format!("IPv6 unavailable ({operation}: os error {errno})"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(!socket.is_open());
    }
}

#[test]
fn a_closed_socket_makes_no_call() {
    let mut socket = PortableSocket::new();
    let route = RouteAddr::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)));
    assert_eq!(socket.send(&route, &[b"x"]), SendResult::Error(Errno::BADF));
    assert_eq!(socket.recv(&mut [0; 8]), RecvResult::Error(Errno::BADF));
    assert_eq!(socket.try_clone().err(), Some(Errno::BADF));
    assert_eq!(socket.send_counted(&route, &[b"x"]).calls, 0);
}

#[test]
fn an_idle_socket_would_block() {
    let (mut socket, _) = open_ipv4();
    assert_eq!(socket.recv(&mut [0; 64]), RecvResult::Error(Errno::AGAIN));
}

/// Loopback round trip at the seam: one `send_to` per datagram; bytes,
/// order and source address.
#[test]
fn single_sends_arrive_in_order_with_their_source() {
    let (mut sender, from) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let payloads: [&[u8]; 3] = [b"one", b"two two", b"three three three"];
    assert_eq!(
        sender.send_counted(&route, &payloads),
        CountedSend {
            result: SendResult::Sent {
                sent: 3,
                error: None
            },
            calls: 3,
        }
    );
    assert_eq!(
        sender.send_counted(&route, &[]),
        CountedSend {
            result: SendResult::Sent {
                sent: 0,
                error: None
            },
            calls: 0,
        }
    );
    for payload in payloads {
        let mut buffer = [0_u8; 64];
        assert_eq!(
            recv_one(&mut receiver, &mut buffer),
            RecvResult::Datagram {
                len: payload.len(),
                truncated: None,
                source: Some(from),
            }
        );
        assert_eq!(buffer.get(..payload.len()).unwrap(), payload);
    }
    assert_eq!(receiver.recv(&mut [0; 8]), RecvResult::Error(Errno::AGAIN));
}

/// A send error after accepted datagrams, provoked for real: a datagram
/// above the UDP limit fails with `EMSGSIZE`. The single sends stop there
/// and report it with the count; a failing head is the call's error.
#[test]
fn single_sends_stop_at_the_first_error() {
    let (mut sender, _) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let oversized = vec![0_u8; 70_000];
    let datagrams: [&[u8]; 3] = [b"first", &oversized, b"third"];
    assert_eq!(
        sender.send_counted(&route, &datagrams),
        CountedSend {
            result: SendResult::Sent {
                sent: 1,
                error: Some(Errno::MSGSIZE)
            },
            calls: 2,
        }
    );
    assert_eq!(
        sender.send_counted(&route, &datagrams[1..]),
        CountedSend {
            result: SendResult::Error(Errno::MSGSIZE),
            calls: 1,
        }
    );
    let mut buffer = [0_u8; 16];
    assert!(matches!(
        recv_one(&mut receiver, &mut buffer),
        RecvResult::Datagram { len: 5, .. }
    ));
    assert_eq!(buffer.get(..5).unwrap(), b"first");
    assert_eq!(receiver.recv(&mut buffer), RecvResult::Error(Errno::AGAIN));
}

/// Section 4.4 on macOS: without `MSG_TRUNC` a datagram longer than the
/// buffer fills it and its length is lost; the rest is discarded, so the
/// next receive gets the next datagram.
#[test]
fn a_long_datagram_fills_the_buffer_without_a_length() {
    let (mut sender, from) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let long = vec![7_u8; 9000];
    assert_eq!(
        sender.send(&route, &[&long, b"next"]),
        SendResult::Sent {
            sent: 2,
            error: None
        }
    );
    let mut buffer = [0_u8; 257];
    assert_eq!(
        recv_one(&mut receiver, &mut buffer),
        RecvResult::Datagram {
            len: 257,
            truncated: None,
            source: Some(from),
        }
    );
    assert_eq!(
        recv_one(&mut receiver, &mut buffer),
        RecvResult::Datagram {
            len: 4,
            truncated: None,
            source: Some(from),
        }
    );
}

/// Section 12, `ECONNREFUSED`: an unconnected UDP socket gets no ICMP
/// error on macOS either, so a send to a port nobody listens on succeeds
/// and nothing is reported later on either direction.
#[test]
fn a_closed_port_reports_nothing_on_an_unconnected_socket() {
    let closed = {
        let probe = UdpSocket::bind(ipv4_any_port()).unwrap();
        probe.local_addr().unwrap()
    };
    let (mut socket, _) = open_ipv4();
    let route = RouteAddr::new(closed);
    for _ in 0..3 {
        assert_eq!(socket.send(&route, &[b"anyone?"]), SENT_ONE);
        assert_eq!(socket.recv(&mut [0; 16]), RecvResult::Error(Errno::AGAIN));
    }
}

/// `split`'s duplicate (3.10): both sockets work, and closing one leaves
/// the other working.
#[test]
fn a_duplicate_outlives_the_closed_original() {
    let (mut original, from) = open_ipv4();
    let (mut peer, to) = open_ipv4();
    let mut duplicate = original.try_clone().unwrap();
    original.close();
    let route = RouteAddr::new(to);
    assert_eq!(
        original.send(&route, &[b"x"]),
        SendResult::Error(Errno::BADF)
    );
    assert_eq!(duplicate.send(&route, &[b"dup"]), SENT_ONE);
    let mut buffer = [0_u8; 8];
    assert_eq!(
        recv_one(&mut peer, &mut buffer),
        RecvResult::Datagram {
            len: 3,
            truncated: None,
            source: Some(from),
        }
    );
    assert_eq!(peer.send(&RouteAddr::new(from), &[b"back"]), SENT_ONE);
    assert!(matches!(
        recv_one(&mut duplicate, &mut buffer),
        RecvResult::Datagram { len: 4, .. }
    ));
}

/// Section 4.5 on macOS: no route MTU is measured, loopback included.
#[test]
fn route_mtu_is_never_measured() {
    let (mut socket, local) = open_ipv4();
    assert_eq!(socket.route_mtu(&RouteAddr::new(local)), None);
}

/// Section 4.3 and 4.4: the data calls allocate nothing, sending or
/// receiving.
#[test]
fn data_calls_do_not_allocate() {
    let (mut sender, _) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let datagrams: [&[u8]; 4] = [b"a", b"bb", b"ccc", b"dddd"];
    let mut buffer = [0_u8; 64];
    let ((), allocations) = karyos_sys::alloc_count::count(|| {
        assert!(matches!(
            sender.send(&route, &datagrams),
            SendResult::Sent {
                sent: 4,
                error: None
            }
        ));
        for _ in 0..4 {
            assert!(matches!(
                recv_one(&mut receiver, &mut buffer),
                RecvResult::Datagram { .. }
            ));
        }
        assert_eq!(receiver.recv(&mut buffer), RecvResult::Error(Errno::AGAIN));
    });
    assert_eq!(allocations, 0);
}
