// SPDX-License-Identifier: Apache-2.0

//! Tests of [`LinuxSocket`] on the loopback interface (`quantstratum-docs:
//! karyos/design/sockets-backend.md` section 9, "Loopback, Linux"):
//! setup, probes, the send and receive results the kernel really returns,
//! duplication and close. Unprivileged; the endpoint level rows of section
//! 12 run in `endpoint/tests/loopback.rs`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use super::*;
use crate::sockets::endpoint::MAX_BUFFER_REQUEST;

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

/// How long [`recv_one`] waits for loopback traffic that should already be
/// there: a time limit rather than a number of tries, so a loaded host
/// (parallel tests, an emulated container) does not fail the test.
const PATIENCE: Duration = Duration::from_secs(10);

/// Receives one datagram, retrying `EAGAIN` until [`PATIENCE`] runs out:
/// loopback delivery is synchronous, so the first call normally succeeds.
/// Neither the clock nor the yield allocates, so the no allocation test
/// uses it too.
fn recv_one(socket: &mut LinuxSocket, buffer: &mut [u8]) -> RecvResult {
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
        (Errno::ADDRINUSE, OsErrno::ADDRINUSE),
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

/// S3 review P3: a request above `c_int::MAX` never reaches `rustix`,
/// which would reject it with `EINVAL`; the largest valid request is set
/// and read back like any other.
#[test]
fn a_buffer_request_beyond_a_c_int_is_a_configuration_error() {
    let (socket, _) = open_ipv4();
    let fd = socket.fd.as_ref().unwrap();
    for (request, direction) in [(1_u32 << 31, Direction::Send), (u32::MAX, Direction::Recv)] {
        assert_eq!(
            buffer(fd, NonZeroU32::new(request), direction),
            Err(OpenError::InvalidConfig {
                field: direction.field(),
                value: u64::from(request),
            })
        );
    }
    let largest = NonZeroU32::new(MAX_BUFFER_REQUEST).unwrap();
    for direction in [Direction::Send, Direction::Recv] {
        let size = buffer(fd, Some(largest), direction).unwrap();
        let effective = size.effective.unwrap();
        assert_eq!(size.requested, Some(largest));
        if effective >= largest.get() {
            assert_eq!(size.state, CapabilityState::Active);
        } else {
            assert_eq!(
                size.state,
                CapabilityState::Fallback(Reason::BelowRequest { effective })
            );
        }
    }
}

/// `open` on an open socket closes the old descriptor before it binds
/// again: reopening on the same address succeeds without a `close` call,
/// which would fail with `EADDRINUSE` if the old descriptor were still
/// open. The port stays held by this socket until `open` itself closes
/// it, so a parallel test binding port 0 cannot take it in between (only
/// the instant inside `open`, between its close and its bind, is open to
/// that race).
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
    // Reopen without `close`: the old descriptor is closed first.
    let probes = socket.open(&config(local)).unwrap();
    assert_eq!(probes.local, local);
    assert!(socket.is_open());
    // The reopened socket is the one bound to `local`.
    let (mut peer, _) = open_ipv4();
    assert_eq!(
        peer.send(&RouteAddr::new(local), &[b"reopened"]),
        SendResult::Sent {
            sent: 1,
            error: None
        }
    );
    let mut buffer = [0_u8; 16];
    assert!(matches!(
        recv_one(&mut socket, &mut buffer),
        RecvResult::Datagram { len: 8, .. }
    ));
    socket.close();
    assert!(!socket.is_open());
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
                    recv_one(&mut receiver, &mut buffer),
                    RecvResult::Datagram { .. }
                ));
            }
        }
        assert_eq!(receiver.recv(&mut buffer), RecvResult::Error(Errno::AGAIN));
    });
    assert_eq!(allocations, 0);
}

/// How long a socket that must not receive a datagram is watched after the
/// socket that must receive it did: loopback delivery to every matching
/// socket happens in the same send, so a leak shows at once; the window
/// only covers scheduling.
const LEAK_WINDOW: Duration = Duration::from_millis(300);

/// The address of the host's interface toward a public route, for a second
/// interface beside loopback; `None` on a host with no such route.
fn lan_address() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match probe.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_loopback() => Some(address),
        _ => None,
    }
}

/// A Karyos socket bound to the wildcard address on `port` (0 for any),
/// joining `group` on the interface of `interface`; `None` when the host
/// cannot join there (recorded by the caller as a skip).
fn joined(port: u16, group: Ipv4Addr, interface: Ipv4Addr) -> Option<(LinuxSocket, u16)> {
    let mut wanted = config(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
    let mut multicast = MulticastConfig::new(group.into(), InterfaceSel::Address(interface));
    multicast.ttl = 1;
    multicast.loopback = true;
    wanted.multicast = Some(multicast);
    let mut socket = LinuxSocket::new();
    let probes = socket.open(&wanted).ok()?;
    Some((socket, probes.local.port()))
}

/// The negative control: a plain socket set up as the Karyos one is but
/// without `IP_MULTICAST_ALL` off, so the kernel's default (on) applies.
fn leaky(port: u16, group: Ipv4Addr, interface: Ipv4Addr) -> Option<OwnedFd> {
    let fd = rustix::net::socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        Some(ipproto::UDP),
    )
    .ok()?;
    sockopt::set_socket_reuseaddr(&fd, true).ok()?;
    rustix::net::bind(&fd, &SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).ok()?;
    sockopt::set_ip_add_membership(&fd, &group, &interface).ok()?;
    Some(fd)
}

/// Whether `fd` receives a datagram within [`LEAK_WINDOW`].
fn leaky_receives(fd: &OwnedFd) -> bool {
    let mut buffer = [0_u8; 64];
    let start = Instant::now();
    while start.elapsed() < LEAK_WINDOW {
        if rustix::net::recv(fd, &mut buffer, RecvFlags::DONTWAIT).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// Whether `socket` receives a datagram within [`LEAK_WINDOW`].
fn receives_within_window(socket: &mut LinuxSocket) -> bool {
    let mut buffer = [0_u8; 64];
    let start = Instant::now();
    while start.elapsed() < LEAK_WINDOW {
        if matches!(socket.recv(&mut buffer), RecvResult::Datagram { .. }) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// Sends one datagram to `group` on `port`, out of the interface of
/// `interface`, looped back to this host's members.
fn send_to_group(group: Ipv4Addr, port: u16, interface: Ipv4Addr) -> bool {
    let Some((mut sender, _)) = joined(0, group, interface) else {
        return false;
    };
    let route = RouteAddr::new(SocketAddr::from((group, port)));
    matches!(
        sender.send(&route, &[b"path"]),
        SendResult::Sent {
            sent: 1,
            error: None
        }
    )
}

/// Owner item 12 (karyos#624): sockets bound to the wildcard address on one
/// port, each joining its own group, receive only their own group. The
/// negative control, a socket joined the same way with the kernel's
/// default `IP_MULTICAST_ALL`, receives the other group's datagram: the
/// leak the option prevents is real on this host, so the positive result
/// cannot pass vacuously.
#[test]
fn a_socket_receives_only_the_group_it_joined() {
    let Some(lan) = lan_address() else {
        skip("no interface toward a public route");
        return;
    };
    let (first, second) = (
        Ipv4Addr::new(239, 255, 62, 41),
        Ipv4Addr::new(239, 255, 62, 42),
    );
    let Some((mut own, port)) = joined(0, first, lan) else {
        skip("this host cannot join a group on its LAN interface");
        return;
    };
    let (mut other, _) = joined(port, second, lan).unwrap();
    let control = leaky(port, second, lan).unwrap();
    assert!(send_to_group(first, port, lan));
    let mut buffer = [0_u8; 64];
    assert!(matches!(
        recv_one(&mut own, &mut buffer),
        RecvResult::Datagram { len: 4, .. }
    ));
    assert!(
        leaky_receives(&control),
        "negative control: without the option the other group's datagram arrives"
    );
    assert!(
        !receives_within_window(&mut other),
        "a socket received a group it did not join"
    );
}

/// Owner item 12's two-interface proof (karyos#624): two sockets on one
/// port join the same group, one on loopback and one on the LAN interface;
/// a datagram sent out of loopback reaches the loopback path's socket only.
/// The negative control, joined on the LAN interface with the kernel's
/// default, receives it: a path socket without the option would count the
/// other path's datagrams.
#[test]
fn a_path_socket_receives_only_its_own_interface() {
    let Some(lan) = lan_address() else {
        skip("no interface toward a public route");
        return;
    };
    let group = Ipv4Addr::new(239, 255, 62, 43);
    let Some((mut loopback_path, port)) = joined(0, group, Ipv4Addr::LOCALHOST) else {
        skip("this host cannot join a group on loopback");
        return;
    };
    let Some((mut lan_path, _)) = joined(port, group, lan) else {
        skip("this host cannot join a group on its LAN interface");
        return;
    };
    let control = leaky(port, group, lan).unwrap();
    assert!(send_to_group(group, port, Ipv4Addr::LOCALHOST));
    let mut buffer = [0_u8; 64];
    assert!(matches!(
        recv_one(&mut loopback_path, &mut buffer),
        RecvResult::Datagram { len: 4, .. }
    ));
    assert!(
        leaky_receives(&control),
        "negative control: without the option the loopback datagram reaches the LAN path"
    );
    assert!(
        !receives_within_window(&mut lan_path),
        "the LAN path's socket received a datagram of the loopback path"
    );
}
