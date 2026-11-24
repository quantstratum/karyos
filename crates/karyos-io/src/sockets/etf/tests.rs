// SPDX-License-Identifier: Apache-2.0

//! The `etf` socket on a real kernel: a veth pair with an `etf` qdisc, a
//! datagram whose `SCM_TXTIME` has passed comes back on the error queue as
//! a `TXTIME` drop with its own time, and one in the future is
//! accepted. Then the etf queue of an endpoint (ADR-0109): its datagrams
//! leave from the endpoint's port, inbound datagrams reach only the
//! endpoint socket, a time already past goes on the endpoint socket, late,
//! and a forced drop is drained with its time. Needs `CAP_NET_ADMIN`,
//! `CAP_NET_RAW` (a packet socket sees the frames) and the kernel's
//! `sch_etf`; skipped where missing unless `KARYOS_ETF_REQUIRED` is set.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests and their helpers, as ADR-0007 allows"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::*;
use crate::backend::TxOptions;
use crate::sockets::errqueue::TxtimeCode;

fn required() -> bool {
    std::env::var_os("KARYOS_ETF_REQUIRED").is_some()
}

/// Minimal rtnetlink writes for the test environment only.
mod rtnl {
    use rustix::net::netlink::SocketAddrNetlink;
    use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

    pub fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u16::try_from(4 + payload.len()).unwrap().to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    pub fn ifinfo(index: i32, flags: u32, change: u32) -> Vec<u8> {
        let mut out = vec![0_u8; 16];
        out[4..8].copy_from_slice(&index.to_ne_bytes());
        out[8..12].copy_from_slice(&flags.to_ne_bytes());
        out[12..16].copy_from_slice(&change.to_ne_bytes());
        out
    }

    pub fn request(kind: u16, flags: u16, payload: &[u8]) -> Result<(), i32> {
        let socket = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|errno| errno.raw_os_error())?;
        let mut message = Vec::new();
        message.extend_from_slice(&u32::try_from(16 + payload.len()).unwrap().to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&(flags | 0x1 | 0x4).to_ne_bytes());
        message.extend_from_slice(&1_u32.to_ne_bytes());
        message.extend_from_slice(&0_u32.to_ne_bytes());
        message.extend_from_slice(payload);
        rustix::net::sendto(
            &socket,
            &message,
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )
        .map_err(|errno| errno.raw_os_error())?;
        let mut buffer = [0_u8; 4096];
        let (len, _) = rustix::net::recv(&socket, &mut buffer[..], RecvFlags::empty())
            .map_err(|errno| errno.raw_os_error())?;
        if len >= 20 && u16::from_ne_bytes([buffer[4], buffer[5]]) == 2 {
            let error = i32::from_ne_bytes(buffer[16..20].try_into().unwrap());
            if error != 0 {
                return Err(-error);
            }
        }
        Ok(())
    }

    pub fn index(name: &str) -> Result<u32, i32> {
        rustix::net::netdevice::name_to_index(
            rustix::net::socket(AddressFamily::INET, SocketType::DGRAM, None)
                .map_err(|e| e.raw_os_error())?,
            name,
        )
        .map_err(|errno| errno.raw_os_error())
    }

    pub fn delete(name: &str) {
        let mut link = ifinfo(0, 0, 0);
        link.extend(attr(3, format!("{name}\0").as_bytes()));
        let _ = request(17, 0, &link);
    }

    /// Removes the pair on every exit of the test, once created.
    pub struct Pair(pub String);

    impl Drop for Pair {
        fn drop(&mut self) {
            delete(&self.0);
        }
    }

    pub fn veth(a: &str, b: &str) -> Result<(), i32> {
        let mut peer = ifinfo(0, 0, 0);
        peer.extend(attr(3, format!("{b}\0").as_bytes()));
        let info = [attr(1, b"veth"), attr(2 | 0x8000, &attr(1 | 0x8000, &peer))].concat();
        let mut link = ifinfo(0, 0, 0);
        link.extend(attr(3, format!("{a}\0").as_bytes()));
        link.extend(attr(18 | 0x8000, &info));
        request(16, 0x400 | 0x200, &link)?;
        for name in [a, b] {
            request(16, 0, &ifinfo(i32::try_from(index(name)?).unwrap(), 1, 1))?;
        }
        Ok(())
    }

    pub fn address(name: &str, host: [u8; 4]) -> Result<(), i32> {
        let mut address = vec![2_u8, 24, 0, 0];
        address.extend_from_slice(&index(name)?.to_ne_bytes());
        address.extend(attr(2, &host));
        address.extend(attr(1, &host));
        request(20, 0x400 | 0x200, &address)
    }

    /// A permanent neighbour entry, so a datagram reaches the qdisc
    /// without waiting for ARP.
    pub fn neighbour(name: &str, host: [u8; 4], mac: [u8; 6]) -> Result<(), i32> {
        let mut ndmsg = vec![0_u8; 12];
        ndmsg[0] = 2;
        ndmsg[4..8].copy_from_slice(&i32::try_from(index(name)?).unwrap().to_ne_bytes());
        ndmsg[8..10].copy_from_slice(&0x80_u16.to_ne_bytes());
        ndmsg.extend(attr(1, &host));
        ndmsg.extend(attr(2, &mac));
        request(28, 0x400 | 0x100, &ndmsg)
    }

    /// The root `etf` qdisc of `name`: `CLOCK_TAI`, `delta_ns`, no offload,
    /// no deadline mode.
    pub fn etf(name: &str, delta_ns: i32) -> Result<(), i32> {
        let mut tcmsg = vec![0_u8; 20];
        tcmsg[4..8].copy_from_slice(&i32::try_from(index(name)?).unwrap().to_ne_bytes());
        tcmsg[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
        let mut parms = Vec::new();
        parms.extend_from_slice(&delta_ns.to_ne_bytes());
        parms.extend_from_slice(&11_i32.to_ne_bytes());
        parms.extend_from_slice(&0_i32.to_ne_bytes());
        tcmsg.extend(attr(1, b"etf\0"));
        tcmsg.extend(attr(2 | 0x8000, &attr(1, &parms)));
        request(36, 0x400 | 0x200, &tcmsg)
    }
}

fn tai_now_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Tai);
    u64::try_from(now.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(now.tv_nsec).unwrap()
}

#[test]
fn a_datagram_past_its_txtime_is_dropped_and_reported_with_its_time() {
    // Names of this process only: the test never touches an interface it
    // did not create, and registers the cleanup only once it exists.
    let a = format!("ke{:x}", std::process::id());
    let b = format!("kf{:x}", std::process::id());
    if let Err(errno) = rtnl::veth(&a, &b) {
        if required() {
            panic!("veth setup failed with errno {errno}");
        }
        eprintln!("veth unavailable here (errno {errno}); skipped");
        return;
    }
    let _pair = rtnl::Pair(a.clone());
    let setup = rtnl::address(&a, [10, 78, 0, 1])
        .and_then(|()| rtnl::neighbour(&a, [10, 78, 0, 9], [2, 0, 0, 0, 0, 9]))
        // A 50 ms delta: the qdisc dequeues that early, so a loaded VM's
        // late timer cannot turn the future datagram into a miss.
        .and_then(|()| rtnl::etf(&a, 50_000_000));
    if let Err(errno) = setup {
        if required() {
            panic!("address, neighbour or etf qdisc setup failed with errno {errno}");
        }
        eprintln!("etf qdisc unavailable here (errno {errno}); skipped");
        return;
    }
    let socket = EtfSocket::open(SocketAddr::from((Ipv4Addr::new(10, 78, 0, 1), 0))).unwrap();
    let to = SocketAddr::from((Ipv4Addr::new(10, 78, 0, 9), 47_100));
    let past = tai_now_ns() - 1_000_000_000;
    socket
        .send(&SocketAddrAny::from(to), b"too late", past)
        .unwrap();
    // A generous lead, so a loaded runner cannot make it late too.
    let future = tai_now_ns() + 200_000_000;
    socket
        .send(&SocketAddrAny::from(to), b"on time", future)
        .unwrap();
    let mut entries = [ErrEntry::Truncated; 4];
    let mut found = 0;
    for _ in 0..100 {
        found = socket.drain_errors(&mut entries).unwrap();
        if found > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Past the future datagram's time: it was sent, not dropped.
    std::thread::sleep(Duration::from_millis(300));
    let later = socket.drain_errors(&mut entries[found..]).unwrap();
    let entries = &entries[..found + later];
    assert!(
        // A time already past at enqueue fails the qdisc's validity check
        // (`SO_EE_CODE_TXTIME_INVALID_PARAM`); `MISSED` is the same drop
        // found at dequeue. Either is a known failed submission.
        matches!(entries, [ErrEntry::Txtime { txtime_ns, code: TxtimeCode::InvalidParam | TxtimeCode::Missed, .. }] if *txtime_ns == past),
        "the past datagram is reported with its own time and the future one is not: {entries:?}"
    );
}

#[test]
fn so_txtime_is_set_on_the_route_socket() {
    let socket = EtfSocket::open(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    match socket {
        Ok(socket) => {
            let (clock, flags) = rustix::net::sockopt::get_txtime(&socket.fd).unwrap();
            assert_eq!(clock, ClockId::Tai);
            assert!(flags.contains(TxTimeFlags::REPORT_ERRORS));
        }
        Err(error) if !required() => eprintln!("SO_TXTIME unavailable here ({error}); skipped"),
        Err(error) => panic!("{error}"),
    }
}

/// The etf queue of an endpoint on a real kernel (ADR-0109): a veth pair
/// `k<tag><pid>` with a root `etf` qdisc of `delta_ns` on its first end,
/// the address `10.79.<net>.1` and a permanent neighbour `10.79.<net>.9`.
/// `None` when skipped.
mod route {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::num::NonZeroU16;
    use std::ops::ControlFlow;

    use super::{required, rtnl};
    use crate::backend::{
        Authority, Commit, EtfQueue, Exposure, GateDecision, InstanceId, RouteId, RxDatagram,
        RxDrop, RxHandler, SenderGate, SenderToken, TxBackend, TxEntry, TxFrame, TxOptions,
        TxQueueConfig, TxQueueId, TxReport,
    };
    use crate::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsRx, SocketsTx};
    use crate::sockets::linux::LinuxSocket;

    pub struct Route {
        pub tx: SocketsTx<LinuxSocket>,
        pub rx: SocketsRx<LinuxSocket>,
        pub queue: TxQueueId,
        pub local: SocketAddr,
        pub peer: SocketAddr,
        _pair: rtnl::Pair,
    }

    pub fn open(tag: char, net: u8, delta_ns: i32) -> Option<Route> {
        let a = format!("k{tag}{:x}", std::process::id());
        let b = format!("j{tag}{:x}", std::process::id());
        if let Err(errno) = rtnl::veth(&a, &b) {
            assert!(!required(), "veth setup failed with errno {errno}");
            eprintln!("veth unavailable here (errno {errno}); skipped");
            return None;
        }
        let pair = rtnl::Pair(a.clone());
        let setup = rtnl::address(&a, [10, 79, net, 1])
            .and_then(|()| rtnl::neighbour(&a, [10, 79, net, 9], [2, 0, 0, 0, 0, 9]))
            .and_then(|()| rtnl::etf(&a, delta_ns));
        if let Err(errno) = setup {
            assert!(
                !required(),
                "address, neighbour or etf qdisc setup failed with errno {errno}"
            );
            eprintln!("etf qdisc unavailable here (errno {errno}); skipped");
            return None;
        }
        let mut config = SocketsConfig::new(SocketAddr::from((Ipv4Addr::new(10, 79, net, 1), 0)));
        config.etf_route = true;
        let endpoint =
            SocketsEndpoint::open(&config, InstanceId::FIRST, LinuxSocket::new()).unwrap();
        let local = endpoint.capabilities().local;
        let (mut tx, rx) = endpoint.split().unwrap();
        let peer = SocketAddr::from((Ipv4Addr::new(10, 79, net, 9), 47_100));
        let route: RouteId = tx.add_route(peer).unwrap();
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: NonZeroU16::new(8).unwrap(),
                etf: Some(EtfQueue {
                    interface: rtnl::index(&a).unwrap(),
                    priority: 0,
                    delta_ns: u32::try_from(delta_ns).unwrap(),
                }),
            })
            .unwrap();
        Some(Route {
            tx,
            rx,
            queue,
            local,
            peer,
            _pair: pair,
        })
    }

    struct Permit;

    impl SenderGate for Permit {
        fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
            GateDecision::Permit {
                count: NonZeroU16::new(u16::try_from(candidate.tokens.len()).unwrap()).unwrap(),
            }
        }
    }

    impl Route {
        /// Commits `bytes` with `options` and flushes the queue; the
        /// entry of the one datagram.
        pub fn send(&mut self, bytes: &[u8], options: TxOptions) -> TxEntry {
            let mut frame = self.tx.claim_tx(self.queue, bytes.len()).unwrap();
            frame.bytes_mut().copy_from_slice(bytes);
            frame
                .commit(Commit {
                    len: bytes.len(),
                    token: SenderToken::new(1),
                    options,
                })
                .unwrap();
            let mut report = TxReport::new();
            self.tx.flush(
                crate::backend::FlushRequest {
                    queue: self.queue,
                    max_datagrams: NonZeroU16::new(8).unwrap(),
                    max_bytes: u32::MAX,
                },
                &mut Permit,
                &mut report,
            );
            let entry = report.pop_front().unwrap();
            assert!(report.pop_front().is_none());
            entry
        }

        /// Datagrams the endpoint socket receives within a few polls.
        pub fn received(&mut self) -> u32 {
            struct Count(u32);
            impl RxHandler for Count {
                fn datagram(&mut self, _: RxDatagram<'_>) -> ControlFlow<()> {
                    self.0 += 1;
                    ControlFlow::Continue(())
                }
                fn dropped(&mut self, _: RxDrop) {}
            }
            let mut count = Count(0);
            let budget = SocketsConfig::new(self.local).rx_budget().unwrap();
            for _ in 0..50 {
                crate::backend::RxBackend::poll_rx(&mut self.rx, budget, &mut count);
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            count.0
        }
    }
}

/// UDP source ports of IPv4 frames to `to` seen by a packet socket within
/// `wait`, whose payload starts with `marker`.
fn captured_sources(capture: &OwnedFd, to: SocketAddr, marker: &[u8], wait: Duration) -> Vec<u16> {
    let SocketAddr::V4(to) = to else {
        panic!("IPv4 only")
    };
    let mut ports = Vec::new();
    let mut frame = [0_u8; 2048];
    let deadline = std::time::Instant::now() + wait;
    while std::time::Instant::now() < deadline {
        let Ok((len, _)) =
            rustix::net::recv(capture, &mut frame[..], rustix::net::RecvFlags::DONTWAIT)
        else {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        };
        // Ethernet, then IPv4 with its header length, then UDP.
        let frame = &frame[..len];
        if len < 14 + 20 + 8 || frame[12..14] != [0x08, 0x00] || frame[23] != 17 {
            continue;
        }
        let ip = &frame[14..];
        let header = usize::from(ip[0] & 0x0F) * 4;
        let udp = &ip[header..];
        let payload = &udp[8..];
        if ip[16..20] == to.ip().octets()
            && udp[2..4] == to.port().to_be_bytes()
            && payload.starts_with(marker)
        {
            ports.push(u16::from_be_bytes([udp[0], udp[1]]));
        }
    }
    ports
}

/// A packet socket seeing every IPv4 frame of the host (`CAP_NET_RAW`).
fn capture() -> OwnedFd {
    rustix::net::socket_with(
        AddressFamily::PACKET,
        SocketType::RAW,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        Some(rustix::net::eth::IP),
    )
    .unwrap()
}

#[test]
fn an_etf_queue_datagram_leaves_from_the_endpoint_port() {
    let Some(mut route) = route::open('a', 1, 50_000_000) else {
        return;
    };
    let capture = capture();
    let entry = route.send(b"etf-source", TxOptions::txtime(tai_now_ns() + 100_000_000));
    assert!(!entry.late);
    let ports = captured_sources(
        &capture,
        route.peer,
        b"etf-source",
        Duration::from_millis(400),
    );
    assert!(
        !ports.is_empty() && ports.iter().all(|port| *port == route.local.port()),
        "the etf socket sends from the endpoint's port {}: {ports:?}",
        route.local.port()
    );
}

#[test]
fn inbound_datagrams_never_land_on_the_etf_socket() {
    let Some(mut route) = route::open('b', 2, 50_000_000) else {
        return;
    };
    let sender =
        std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::new(10, 79, 2, 1), 0))).unwrap();
    for _ in 0..200 {
        sender.send_to(b"inbound", route.local).unwrap();
    }
    assert_eq!(
        route.received(),
        200,
        "every inbound datagram reaches the endpoint socket"
    );
}

#[test]
fn a_past_time_goes_on_the_endpoint_socket_late() {
    let Some(mut route) = route::open('c', 3, 50_000_000) else {
        return;
    };
    let past = tai_now_ns() - 1_000_000_000;
    let entry = route.send(b"late", TxOptions::txtime(past));
    assert!(entry.late);
    assert!(matches!(
        entry.outcome,
        crate::backend::TxItemOutcome::Submitted { .. }
    ));
    // Had it gone to the etf socket, the qdisc would have reported it.
    std::thread::sleep(Duration::from_millis(100));
    let mut entries = [ErrEntry::Truncated; 4];
    assert_eq!(route.tx.drain_etf(route.queue, &mut entries), Ok(0));
}

#[test]
fn a_forced_drop_is_drained_with_its_time() {
    // A 300 ms delta: the first datagram leaves 300 ms before its time,
    // and the qdisc then drops any later datagram timed before it.
    let Some(mut route) = route::open('d', 4, 300_000_000) else {
        return;
    };
    let start = tai_now_ns();
    let first = start + 1_000_000_000;
    assert!(!route.send(b"first", TxOptions::txtime(first)).late);
    // Past the first datagram's dequeue at `first - delta`.
    while tai_now_ns() < start + 750_000_000 {
        std::thread::sleep(Duration::from_millis(5));
    }
    let earlier = tai_now_ns() + 50_000_000;
    assert!(earlier < first);
    let entry = route.send(b"earlier", TxOptions::txtime(earlier));
    assert!(!entry.late, "still ahead: it went to the etf socket");
    let mut entries = [ErrEntry::Truncated; 4];
    let mut found = 0;
    for _ in 0..200 {
        found += route
            .tx
            .drain_etf(route.queue, &mut entries[found..])
            .unwrap();
        if found > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        matches!(&entries[..found], [ErrEntry::Txtime { txtime_ns, code: TxtimeCode::InvalidParam | TxtimeCode::Missed, .. }] if *txtime_ns == earlier),
        "the dropped datagram is drained with its own time: {:?}",
        &entries[..found]
    );
}
