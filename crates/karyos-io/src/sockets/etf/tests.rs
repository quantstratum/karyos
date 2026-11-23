// SPDX-License-Identifier: Apache-2.0

//! The `etf` socket on a real kernel: a veth pair with an `etf` qdisc, a
//! datagram whose `SCM_TXTIME` has passed comes back on the error queue as
//! a `TXTIME` drop with its own time, and one in the future is
//! accepted. Needs `CAP_NET_ADMIN` and the kernel's `sch_etf`; skipped
//! where missing unless `KARYOS_ETF_REQUIRED` is set.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests and their helpers, as ADR-0007 allows"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::*;
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
    socket.send(to, b"too late", past).unwrap();
    // A generous lead, so a loaded runner cannot make it late too.
    let future = tai_now_ns() + 200_000_000;
    socket.send(to, b"on time", future).unwrap();
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
