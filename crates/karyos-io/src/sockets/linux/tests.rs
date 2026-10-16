// SPDX-License-Identifier: Apache-2.0

//! Tests of [`LinuxSocket`] on the loopback interface (`quantstratum-docs:
//! karyos/design/sockets-backend.md` section 9, "Loopback, Linux"):
//! setup, probes, the send and receive results the kernel really returns,
//! duplication and close. Unprivileged; the endpoint level rows of section
//! 12 run in `endpoint/tests/loopback.rs`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU32;

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
fn open_ipv4() -> (LinuxSocket, SocketAddr) {
    let mut socket = LinuxSocket::new();
    let probes = socket.open(&config(ipv4_any_port())).unwrap();
    (socket, probes.local)
}

/// Receives one datagram, retrying `EAGAIN` for a bounded time: loopback
/// delivery is synchronous, so the first call normally succeeds.
fn recv_one(socket: &mut LinuxSocket, buffer: &mut [u8]) -> RecvResult {
    for _ in 0..1000 {
        match socket.recv(buffer) {
            RecvResult::Error(Errno::AGAIN) => std::thread::yield_now(),
            result => return result,
        }
    }
    RecvResult::Error(Errno::AGAIN)
}

/// Records a skipped case with its reason (section 9).
#[expect(
    clippy::print_stderr,
    reason = "section 9 records every skip with its reason in the test log"
)]
pub(crate) fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

/// The hand typed errno values of `ops.rs` equal `rustix`'s on Linux.
#[test]
fn errno_values_match_rustix() {
    let pairs = [
        (Errno::PERM, OsErrno::PERM),
        (Errno::INTR, OsErrno::INTR),
        (Errno::BADF, OsErrno::BADF),
        (Errno::AGAIN, OsErrno::AGAIN),
        (Errno::AGAIN, OsErrno::WOULDBLOCK),
        (Errno::NOMEM, OsErrno::NOMEM),
        (Errno::ACCES, OsErrno::ACCESS),
        (Errno::FAULT, OsErrno::FAULT),
        (Errno::INVAL, OsErrno::INVAL),
        (Errno::NOSYS, OsErrno::NOSYS),
        (Errno::NOTSOCK, OsErrno::NOTSOCK),
        (Errno::MSGSIZE, OsErrno::MSGSIZE),
        (Errno::ADDRNOTAVAIL, OsErrno::ADDRNOTAVAIL),
        (Errno::NETDOWN, OsErrno::NETDOWN),
        (Errno::NETUNREACH, OsErrno::NETUNREACH),
        (Errno::NOBUFS, OsErrno::NOBUFS),
        (Errno::CONNREFUSED, OsErrno::CONNREFUSED),
        (Errno::HOSTUNREACH, OsErrno::HOSTUNREACH),
    ];
    for (ours, rustix) in pairs {
        assert_eq!(ours.raw(), rustix.raw_os_error(), "{rustix:?}");
        assert_eq!(errno(rustix), ours);
    }
}

#[test]
fn open_binds_probes_and_reports_the_library_gaps_elsewhere() {
    let mut socket = LinuxSocket::new();
    assert!(!socket.is_open());
    let probes = socket.open(&config(ipv4_any_port())).unwrap();
    assert!(socket.is_open());
    assert_eq!(probes.local.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(
        probes.local.port(),
        0,
        "getsockname reports the chosen port"
    );
    assert_eq!(probes.interface, None);
    assert_eq!(probes.dont_fragment, CapabilityState::Active);
    // Docker's default seccomp profile and an unconfined host allow
    // `sendmmsg`; a refusal would be `Unsupported` or `Denied`, never
    // absence.
    assert_eq!(probes.tx_batch, CapabilityState::Active);
    assert!(socket.batch);
    assert_eq!(probes.send_buffer, BufferSize::NOT_REQUESTED);
    assert_eq!(probes.recv_buffer, BufferSize::NOT_REQUESTED);
    assert_eq!(probes.multicast, None);
}

#[test]
fn open_ipv6_loopback_sets_v6only_and_dont_fragment() {
    let mut socket = LinuxSocket::new();
    let local = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    match socket.open(&config(local)) {
        Ok(probes) => {
            assert!(probes.local.is_ipv6());
            assert_eq!(probes.dont_fragment, CapabilityState::Active);
            let fd = socket.fd.as_ref().unwrap();
            assert!(sockopt::ipv6_v6only(fd).unwrap());
        }
        // A container without IPv6 has no `::1`: a recorded skip.
        Err(OpenError::Os { operation, errno }) => {
            skip(&format!(
                "IPv6 loopback unavailable ({operation}: os error {errno})"
            ));
        }
        Err(other) => panic!("unexpected {other:?}"),
    }
}

/// Section 12, buffer sizes: the effective sizes are read back. A request
/// within `wmem_max` and `rmem_max` is met; one far above them is recorded
/// as `BelowRequest` with the effective size, unless the privileged
/// `_FORCE` form succeeded.
#[test]
fn buffer_sizes_are_read_back() {
    let small = NonZeroU32::new(64 * 1024).unwrap();
    let mut wanted = config(ipv4_any_port());
    wanted.send_buffer = Some(small);
    wanted.recv_buffer = Some(small);
    let mut socket = LinuxSocket::new();
    let probes = socket.open(&wanted).unwrap();
    for buffer in [probes.send_buffer, probes.recv_buffer] {
        assert_eq!(buffer.requested, Some(small));
        assert!(buffer.effective.unwrap() >= small.get());
        assert_eq!(buffer.state, CapabilityState::Active);
    }

    let huge = NonZeroU32::new(1 << 30).unwrap();
    wanted.send_buffer = Some(huge);
    wanted.recv_buffer = Some(huge);
    let probes = socket.open(&wanted).unwrap();
    for buffer in [probes.send_buffer, probes.recv_buffer] {
        let effective = buffer.effective.unwrap();
        assert_eq!(buffer.requested, Some(huge));
        if effective >= huge.get() {
            assert_eq!(buffer.state, CapabilityState::Active);
        } else {
            assert_eq!(
                buffer.state,
                CapabilityState::Fallback(Reason::BelowRequest { effective })
            );
        }
    }
    // Linux reports twice the set value; the read back of a met request is
    // twice the request, halved by the probe.
    let fd = socket.fd.as_ref().unwrap();
    let read = sockopt::socket_recv_buffer_size(fd).unwrap();
    assert_eq!(
        u32::try_from(read / 2).unwrap(),
        probes.recv_buffer.effective.unwrap()
    );
}

#[test]
fn reopen_closes_the_old_descriptor_and_a_failed_open_keeps_none() {
    let (mut socket, local) = open_ipv4();
    // Binding the same address again fails while the first socket is
    // open; that open leaves no socket.
    let mut second = LinuxSocket::new();
    assert_eq!(
        second.open(&config(local)),
        Err(OpenError::Os {
            operation: "bind",
            errno: OsErrno::ADDRINUSE.raw_os_error(),
        })
    );
    assert!(!second.is_open());
    // Open closes the old descriptor first, so the port is free again.
    socket.close();
    assert!(!socket.is_open());
    second.open(&config(local)).unwrap();
}

#[test]
fn an_ipv6_group_needs_an_interface_index() {
    let mut wanted = config(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)));
    wanted.multicast = Some(MulticastConfig::new(
        "ff02::1:2".parse().unwrap(),
        InterfaceSel::Address(Ipv4Addr::LOCALHOST),
    ));
    let mut socket = LinuxSocket::new();
    match socket.open(&wanted) {
        Err(OpenError::InvalidConfig { field, .. }) => assert_eq!(field, "multicast.interface"),
        Err(OpenError::Os { operation, errno }) => {
            skip(&format!(
                "IPv6 loopback unavailable ({operation}: os error {errno})"
            ));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!socket.is_open());
}

#[test]
fn a_closed_socket_makes_no_call() {
    let mut socket = LinuxSocket::new();
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

/// Loopback round trip at the seam, batched and single: bytes, order and
/// source address.
#[test]
fn batched_and_single_sends_arrive_in_order_with_their_source() {
    let (mut sender, from) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let payloads: [&[u8]; 3] = [b"one", b"two two", b"three three three"];
    for batch in [true, false] {
        sender.batch = batch;
        assert_eq!(
            sender.send_counted(&route, &payloads),
            CountedSend {
                result: SendResult::Sent {
                    sent: 3,
                    error: None
                },
                calls: if batch { 1 } else { 3 },
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
    }
    assert_eq!(receiver.recv(&mut [0; 8]), RecvResult::Error(Errno::AGAIN));
}

/// A full batch of `SOCKETS_MAX_BATCH` datagrams in one `sendmmsg`.
#[test]
fn a_full_batch_is_one_call() {
    let (mut sender, _) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let bytes: Vec<[u8; 2]> = (0..BATCH)
        .map(|at| [u8::try_from(at).unwrap(), 0xAB])
        .collect();
    let datagrams: Vec<&[u8]> = bytes.iter().map(<[u8; 2]>::as_slice).collect();
    assert_eq!(
        sender.send(&route, &datagrams),
        SendResult::Sent {
            sent: BATCH,
            error: None
        }
    );
    for expected in &bytes {
        let mut buffer = [0_u8; 8];
        assert!(matches!(
            recv_one(&mut receiver, &mut buffer),
            RecvResult::Datagram { len: 2, .. }
        ));
        assert_eq!(buffer.get(..2).unwrap(), expected);
    }
}

/// Section 12, partial `sendmmsg`, provoked for real: a datagram above the
/// UDP limit of 65,535 bytes fails with `EMSGSIZE` after the first was
/// sent. `sendmmsg` returns the count and loses the error; the single send
/// path reports it.
#[test]
fn a_partial_sendmmsg_returns_the_count_and_loses_the_error() {
    let (mut sender, _) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let oversized = vec![0_u8; 70_000];
    let datagrams: [&[u8]; 3] = [b"first", &oversized, b"third"];

    // One op per `sendmmsg`, one per single `sendmsg`.
    sender.batch = true;
    assert_eq!(
        sender.send_counted(&route, &datagrams),
        CountedSend {
            result: SendResult::Sent {
                sent: 1,
                error: None
            },
            calls: 1,
        }
    );
    sender.batch = false;
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
    // A failing head is the call's error in both paths, after one call.
    for batch in [true, false] {
        sender.batch = batch;
        assert_eq!(
            sender.send_counted(&route, &datagrams[1..]),
            CountedSend {
                result: SendResult::Error(Errno::MSGSIZE),
                calls: 1,
            }
        );
    }
    let mut buffer = [0_u8; 16];
    for _ in 0..2 {
        assert!(matches!(
            recv_one(&mut receiver, &mut buffer),
            RecvResult::Datagram { len: 5, .. }
        ));
        assert_eq!(buffer.get(..5).unwrap(), b"first");
    }
    assert_eq!(receiver.recv(&mut buffer), RecvResult::Error(Errno::AGAIN));
}

/// Section 4.4: `MSG_TRUNC` reports the true length of a datagram longer
/// than the buffer.
#[test]
fn a_long_datagram_reports_its_true_length() {
    let (mut sender, from) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let long = vec![7_u8; 9000];
    assert_eq!(
        sender.send(&route, &[&long]),
        SendResult::Sent {
            sent: 1,
            error: None
        }
    );
    let mut buffer = [0_u8; 257];
    assert_eq!(
        recv_one(&mut receiver, &mut buffer),
        RecvResult::Datagram {
            len: 257,
            truncated: Some(9000),
            source: Some(from),
        }
    );
}

/// Section 12, `ECONNREFUSED`: an unconnected UDP socket gets no ICMP
/// error without `IP_RECVERR` (S-9), so a send to a port nobody listens on
/// succeeds and nothing is reported later on either direction. The
/// `PeerError` mapping of a reported `ECONNREFUSED` is covered by the
/// scripted tests.
#[test]
fn a_closed_port_reports_nothing_on_an_unconnected_socket() {
    let closed = {
        let probe = UdpSocket::bind(ipv4_any_port()).unwrap();
        probe.local_addr().unwrap()
    };
    let (mut socket, _) = open_ipv4();
    let route = RouteAddr::new(closed);
    for _ in 0..3 {
        assert_eq!(
            socket.send(&route, &[b"anyone?"]),
            SendResult::Sent {
                sent: 1,
                error: None
            }
        );
        assert_eq!(socket.recv(&mut [0; 16]), RecvResult::Error(Errno::AGAIN));
    }
}

/// `split`'s duplicate (3.10): both descriptors work, and closing one
/// leaves the other working.
#[test]
fn a_duplicate_outlives_the_closed_original() {
    let (mut original, from) = open_ipv4();
    let (mut peer, to) = open_ipv4();
    let mut duplicate = original.try_clone().unwrap();
    assert_eq!(duplicate.batch, original.batch);
    original.close();
    let route = RouteAddr::new(to);
    assert_eq!(
        original.send(&route, &[b"x"]),
        SendResult::Error(Errno::BADF)
    );
    assert_eq!(
        duplicate.send(&route, &[b"dup"]),
        SendResult::Sent {
            sent: 1,
            error: None
        }
    );
    let mut buffer = [0_u8; 8];
    assert_eq!(
        recv_one(&mut peer, &mut buffer),
        RecvResult::Datagram {
            len: 3,
            truncated: None,
            source: Some(from),
        }
    );
    // The duplicate receives on the shared socket as well.
    assert_eq!(
        peer.send(&RouteAddr::new(from), &[b"back"]),
        SendResult::Sent {
            sent: 1,
            error: None
        }
    );
    assert!(matches!(
        recv_one(&mut duplicate, &mut buffer),
        RecvResult::Datagram { len: 4, .. }
    ));
}

/// Section 4.5: the loopback route is measured (`lo` has an MTU of
/// 65,536); a destination the temporary socket cannot connect to, the
/// broadcast address without `SO_BROADCAST` (`EACCES`), is unmeasured.
#[test]
fn route_mtu_is_measured_on_loopback_and_none_when_connect_fails() {
    let (mut socket, local) = open_ipv4();
    let mtu = socket.route_mtu(&RouteAddr::new(local)).unwrap();
    assert!(mtu >= 1500, "loopback MTU {mtu}");
    let broadcast = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
    assert_eq!(socket.route_mtu(&RouteAddr::new(broadcast)), None);
}

/// Section 4.3 and 4.4: the data calls allocate nothing, batched, single
/// or receiving.
#[test]
fn data_calls_do_not_allocate() {
    let (mut sender, _) = open_ipv4();
    let (mut receiver, to) = open_ipv4();
    let route = RouteAddr::new(to);
    let datagrams: [&[u8]; 4] = [b"a", b"bb", b"ccc", b"dddd"];
    let mut buffer = [0_u8; 64];
    let ((), allocations) = karyos_sys::alloc_count::count(|| {
        for batch in [true, false] {
            sender.batch = batch;
            assert!(matches!(
                sender.send(&route, &datagrams),
                SendResult::Sent {
                    sent: 4,
                    error: None
                }
            ));
            for _ in 0..4 {
                assert!(matches!(
                    receiver.recv(&mut buffer),
                    RecvResult::Datagram { .. }
                ));
            }
        }
        assert_eq!(receiver.recv(&mut buffer), RecvResult::Error(Errno::AGAIN));
    });
    assert_eq!(allocations, 0);
}
