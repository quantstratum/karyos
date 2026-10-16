// SPDX-License-Identifier: Apache-2.0

//! The Linux [`SocketOps`]: UDP sockets through safe `rustix` calls only
//! (`quantstratum-docs: karyos/design/sockets-backend.md` section 4,
//! decisions O-1, O-3, O-6 and O-8).
//!
//! - Setup (4.1): `socket_with(family, DGRAM, NONBLOCK | CLOEXEC, UDP)`,
//!   `IPV6_V6ONLY` for IPv6, `SO_REUSEADDR` when the endpoint joins a
//!   group, `bind`, `IP_MTU_DISCOVER` or `IPV6_MTU_DISCOVER` set to `DO`
//!   and read back, `SO_SNDBUF` and `SO_RCVBUF` set and read back, then the
//!   multicast membership, interface, TTL or hops and loop. `EINTR` is
//!   retried once on this control path (4.7). A failure drops the
//!   descriptor, which closes it, so no partial socket or membership is
//!   kept.
//! - Send (4.3): one `sendmmsg` over [`MMsgHdr::new_with_addr`] entries in
//!   fixed stack arrays when the batching probe was `Active`, otherwise one
//!   `sendmsg_addr` per datagram stopping at the first error. Each
//!   `msg_len` and each single send result must equal the datagram length;
//!   anything else is [`SendResult::OutOfAbi`].
//! - Receive (4.4): one `recvmsg` with `MSG_TRUNC` per call, the source
//!   address and the true length of a datagram that fills or exceeds the
//!   buffer.
//! - `split` duplicates with `fcntl_dupfd_cloexec` (3.10); `add_route`
//!   measures `IP_MTU` or `IPV6_MTU` on a temporary connected socket (4.5).
//! - Probes (8.2): `sendmmsg` with zero messages, the buffer and don't
//!   fragment read backs. The capabilities `rustix` 1.1.5 has no API for
//!   (`recvmmsg`, GSO, GRO, `SO_TIMESTAMPING`, `SO_BUSY_POLL`) are reported
//!   `Unavailable(LibraryApi)` by the snapshot (decision O-3);
//!   `IP_MULTICAST_ALL` and `IP_PKTINFO` are not set.
//!
//! The data calls neither allocate nor block: the socket is nonblocking
//! from creation and every send and receive also passes `MSG_DONTWAIT`.
//! The system calls the backend needs, for a seccomp profile, are
//! `socket`, `bind`, `connect`, `getsockname`, `setsockopt`, `getsockopt`,
//! `fcntl`, `sendmsg`, `sendmmsg`, `recvmsg` and `close` (8.2).

#![forbid(unsafe_code)]

use std::io::{IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;

use rustix::fd::OwnedFd;
use rustix::io::Errno as OsErrno;
use rustix::net::sockopt::{self, Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};
use rustix::net::{
    AddressFamily, MMsgHdr, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendFlags, SocketAddrAny, SocketFlags, SocketType, ipproto,
};

use super::endpoint::{
    BufferSize, InterfaceSel, Membership, MulticastConfig, SOCKETS_MAX_BATCH, SocketsConfig,
};
use super::ops::{Errno, RecvResult, RouteAddr, SendResult, SocketOps, SocketProbes};
use crate::backend::{CapabilityState, OpenError, Reason};

/// Entries of one `sendmmsg`: the stack arrays of one exposure, equal to
/// [`SOCKETS_MAX_BATCH`] (checked below without a cast).
const BATCH: usize = 64;
const _: () = assert!(
    SOCKETS_MAX_BATCH == 64,
    "BATCH must equal SOCKETS_MAX_BATCH"
);

/// A UDP socket on Linux, or a closed one before [`SocketOps::open`] and
/// after [`SocketOps::close`]. A data call on a closed socket returns
/// `EBADF` without a system call.
#[derive(Debug, Default)]
pub struct LinuxSocket {
    fd: Option<OwnedFd>,
    /// Whether the `sendmmsg` probe of the last open was `Active`.
    batch: bool,
}

impl LinuxSocket {
    /// A closed socket; [`SocketOps::open`] creates the descriptor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fd: None,
            batch: false,
        }
    }

    /// Whether the socket holds a descriptor.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.fd.is_some()
    }
}

/// The backend's errno from `rustix`'s.
fn errno(error: OsErrno) -> Errno {
    Errno::from_raw(error.raw_os_error())
}

/// Maps a setup failure to [`OpenError::Os`] naming `operation`.
fn os(operation: &'static str) -> impl Fn(OsErrno) -> OpenError {
    move |error| OpenError::Os {
        operation,
        errno: error.raw_os_error(),
    }
}

/// Runs a control path call, retrying it once after `EINTR` (4.7).
fn retry_intr<T>(mut call: impl FnMut() -> rustix::io::Result<T>) -> rustix::io::Result<T> {
    match call() {
        Err(OsErrno::INTR) => call(),
        result => result,
    }
}

/// The reason of a failed probe (8.2): `ENOSYS` is `Unsupported`, never
/// absence; `EPERM` and `EACCES` are `Denied`; anything else
/// `ProbeFailed`.
fn probe_reason(error: OsErrno) -> Reason {
    let errno = error.raw_os_error();
    match error {
        OsErrno::NOSYS => Reason::Unsupported { errno },
        OsErrno::PERM | OsErrno::ACCESS => Reason::Denied { errno },
        _ => Reason::ProbeFailed { errno },
    }
}

/// `ProbeFailed` for a probe whose call succeeded with a value other than
/// the one set; there is no errno, so it is 0.
const MISMATCH: Reason = Reason::ProbeFailed { errno: 0 };

/// Sets `IP_MTU_DISCOVER` or `IPV6_MTU_DISCOVER` to `DO` and reads it back
/// (4.1, 8.2). A failure leaves fragmentation possible: `Fallback`.
fn dont_fragment(fd: &OwnedFd, ipv4: bool) -> CapabilityState {
    let result = if ipv4 {
        retry_intr(|| sockopt::set_ip_mtu_discover(fd, Ipv4PathMtuDiscovery::DO))
            .and_then(|()| sockopt::ip_mtu_discover(fd))
            .map(|value| value == Ipv4PathMtuDiscovery::DO)
    } else {
        retry_intr(|| sockopt::set_ipv6_mtu_discover(fd, Ipv6PathMtuDiscovery::DO))
            .and_then(|()| sockopt::ipv6_mtu_discover(fd))
            .map(|value| value == Ipv6PathMtuDiscovery::DO)
    };
    match result {
        Ok(true) => CapabilityState::Active,
        Ok(false) => CapabilityState::Fallback(MISMATCH),
        Err(error) => CapabilityState::Fallback(probe_reason(error)),
    }
}

/// The kernel buffer a [`buffer`] call sizes.
#[derive(Debug, Clone, Copy)]
enum Direction {
    Send,
    Recv,
}

impl Direction {
    fn set(self, fd: &OwnedFd, size: usize) -> rustix::io::Result<()> {
        match self {
            Self::Send => sockopt::set_socket_send_buffer_size(fd, size),
            Self::Recv => sockopt::set_socket_recv_buffer_size(fd, size),
        }
    }

    /// The privileged `SO_SNDBUFFORCE` or `SO_RCVBUFFORCE`.
    fn set_force(self, fd: &OwnedFd, size: usize) -> rustix::io::Result<()> {
        match self {
            Self::Send => sockopt::set_socket_send_buffer_size_force(fd, size),
            Self::Recv => sockopt::set_socket_recv_buffer_size_force(fd, size),
        }
    }

    /// The size read back, halved: Linux doubles the set value for its
    /// bookkeeping overhead and reports the doubled value (8.2), so half of
    /// it is in the units of the request. `None` when the halved value
    /// does not fit `u32`, which the kernel's `int` sizes cannot reach.
    fn effective(self, fd: &OwnedFd) -> Result<Option<u32>, OpenError> {
        let read = match self {
            Self::Send => sockopt::socket_send_buffer_size(fd).map_err(os("getsockopt SO_SNDBUF")),
            Self::Recv => sockopt::socket_recv_buffer_size(fd).map_err(os("getsockopt SO_RCVBUF")),
        }?;
        Ok(read
            .checked_div(2)
            .and_then(|half| u32::try_from(half).ok()))
    }

    /// The configuration field of the request.
    const fn field(self) -> &'static str {
        match self {
            Self::Send => "send_buffer",
            Self::Recv => "recv_buffer",
        }
    }

    const fn set_name(self) -> &'static str {
        match self {
            Self::Send => "setsockopt SO_SNDBUF",
            Self::Recv => "setsockopt SO_RCVBUF",
        }
    }
}

/// Sets a buffer size and reads it back (4.1, 8.2). When the read back is
/// below the request (the `wmem_max` or `rmem_max` limit), the privileged
/// `_FORCE` form is tried once; its failure is not an error, and the
/// effective size below the request is recorded as `BelowRequest`. A read
/// back that cannot be represented is recorded as `ProbeFailed` with no
/// effective size, never as a made up one.
fn buffer(
    fd: &OwnedFd,
    requested: Option<NonZeroU32>,
    direction: Direction,
) -> Result<BufferSize, OpenError> {
    let Some(request) = requested else {
        return Ok(BufferSize::NOT_REQUESTED);
    };
    // `SO_SNDBUF` and `SO_RCVBUF` take a C `int`, and `rustix` rejects a
    // larger value with `EINVAL`. `SocketsConfig::validate` already refuses
    // such a request (`MAX_BUFFER_REQUEST`); this guard keeps a caller that
    // skipped it from reaching the kernel. The `usize` is the type `rustix`
    // takes; a nonnegative `c_int` always fits it.
    let (Ok(_), Ok(size)) = (
        std::ffi::c_int::try_from(request.get()),
        usize::try_from(request.get()),
    ) else {
        return Err(OpenError::InvalidConfig {
            field: direction.field(),
            value: u64::from(request.get()),
        });
    };
    retry_intr(|| direction.set(fd, size)).map_err(os(direction.set_name()))?;
    let mut effective = direction.effective(fd)?;
    let below = |effective: Option<u32>| matches!(effective, Some(size) if size < request.get());
    if below(effective) && retry_intr(|| direction.set_force(fd, size)).is_ok() {
        effective = direction.effective(fd)?;
    }
    let state = match effective {
        Some(size) if size >= request.get() => CapabilityState::Active,
        Some(size) => CapabilityState::Fallback(Reason::BelowRequest { effective: size }),
        None => CapabilityState::Fallback(MISMATCH),
    };
    Ok(BufferSize {
        requested,
        effective,
        state,
    })
}

/// Joins the group and sets the multicast interface, TTL or hop limit and
/// loop (4.1). An IPv6 group needs an interface index.
fn join(fd: &OwnedFd, multicast: MulticastConfig) -> Result<Membership, OpenError> {
    let ttl = u32::from(multicast.ttl);
    match (multicast.group, multicast.interface) {
        (IpAddr::V4(group), interface) => {
            match interface {
                InterfaceSel::Address(address) => {
                    retry_intr(|| sockopt::set_ip_add_membership(fd, &group, &address))
                        .map_err(os("setsockopt IP_ADD_MEMBERSHIP"))?;
                    retry_intr(|| sockopt::set_ip_multicast_if(fd, &address))
                        .map_err(os("setsockopt IP_MULTICAST_IF"))?;
                }
                InterfaceSel::Index(index) => {
                    let any = Ipv4Addr::UNSPECIFIED;
                    retry_intr(|| {
                        sockopt::set_ip_add_membership_with_ifindex(fd, &group, &any, index)
                    })
                    .map_err(os("setsockopt IP_ADD_MEMBERSHIP"))?;
                    retry_intr(|| {
                        sockopt::set_ip_multicast_if_with_ifindex(fd, &group, &any, index)
                    })
                    .map_err(os("setsockopt IP_MULTICAST_IF"))?;
                }
            }
            retry_intr(|| sockopt::set_ip_multicast_ttl(fd, ttl))
                .map_err(os("setsockopt IP_MULTICAST_TTL"))?;
            retry_intr(|| sockopt::set_ip_multicast_loop(fd, multicast.loopback))
                .map_err(os("setsockopt IP_MULTICAST_LOOP"))?;
        }
        (IpAddr::V6(group), InterfaceSel::Index(index)) => {
            retry_intr(|| sockopt::set_ipv6_add_membership(fd, &group, index))
                .map_err(os("setsockopt IPV6_ADD_MEMBERSHIP"))?;
            retry_intr(|| sockopt::set_ipv6_multicast_if(fd, index))
                .map_err(os("setsockopt IPV6_MULTICAST_IF"))?;
            retry_intr(|| sockopt::set_ipv6_multicast_hops(fd, ttl))
                .map_err(os("setsockopt IPV6_MULTICAST_HOPS"))?;
            retry_intr(|| sockopt::set_ipv6_multicast_loop(fd, multicast.loopback))
                .map_err(os("setsockopt IPV6_MULTICAST_LOOP"))?;
        }
        (IpAddr::V6(_), InterfaceSel::Address(_)) => {
            return Err(OpenError::InvalidConfig {
                field: "multicast.interface",
                value: 0,
            });
        }
    }
    Ok(Membership {
        group: multicast.group,
        interface: multicast.interface,
    })
}

/// The batching probe (8.2): `sendmmsg` with zero messages.
fn probe_batch(fd: &OwnedFd) -> CapabilityState {
    match rustix::net::sendmmsg(fd, &mut [], SendFlags::DONTWAIT) {
        Ok(0) => CapabilityState::Active,
        Ok(_) => CapabilityState::Fallback(MISMATCH),
        Err(error) => CapabilityState::Fallback(probe_reason(error)),
    }
}

/// Creates, configures and binds a socket for `config` (4.1) and probes it
/// (8.2).
fn configure(config: &SocketsConfig) -> Result<(OwnedFd, SocketProbes), OpenError> {
    let ipv4 = config.local.is_ipv4();
    let family = if ipv4 {
        AddressFamily::INET
    } else {
        AddressFamily::INET6
    };
    let fd = retry_intr(|| {
        rustix::net::socket_with(
            family,
            SocketType::DGRAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            Some(ipproto::UDP),
        )
    })
    .map_err(os("socket"))?;
    if !ipv4 {
        retry_intr(|| sockopt::set_ipv6_v6only(&fd, true)).map_err(os("setsockopt IPV6_V6ONLY"))?;
    }
    if config.multicast.is_some() {
        retry_intr(|| sockopt::set_socket_reuseaddr(&fd, true))
            .map_err(os("setsockopt SO_REUSEADDR"))?;
    }
    retry_intr(|| rustix::net::bind(&fd, &config.local)).map_err(os("bind"))?;
    let dont_fragment = dont_fragment(&fd, ipv4);
    let send_buffer = buffer(&fd, config.send_buffer, Direction::Send)?;
    let recv_buffer = buffer(&fd, config.recv_buffer, Direction::Recv)?;
    let multicast = match config.multicast {
        Some(multicast) => Some(join(&fd, multicast)?),
        None => None,
    };
    let tx_batch = probe_batch(&fd);
    let local = rustix::net::getsockname(&fd)
        .and_then(SocketAddr::try_from)
        .map_err(os("getsockname"))?;
    // `rustix` has no address to interface lookup (it needs netlink or
    // `getifaddrs`); the index is known only when the configuration names
    // one.
    let interface = match config.multicast.map(|multicast| multicast.interface) {
        Some(InterfaceSel::Index(index)) if index != 0 => Some(index),
        _ => None,
    };
    let probes = SocketProbes {
        local,
        interface,
        dont_fragment,
        tx_batch,
        send_buffer,
        recv_buffer,
        multicast,
    };
    Ok((fd, probes))
}

/// One `sendmmsg` entry's buffers.
struct Entry<'d> {
    iov: [IoSlice<'d>; 1],
    control: SendAncillaryBuffer<'static, 'static, 'static>,
}

/// A send result with the system calls that produced it: one per
/// `sendmmsg` and one per single `sendmsg_addr`, for `Spent.ops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountedSend {
    /// The result of the send.
    pub result: SendResult,
    /// System calls made; zero when the socket is closed or nothing was
    /// offered.
    pub calls: usize,
}

/// Sends up to [`BATCH`] datagrams with one `sendmmsg` (4.3).
fn send_batch(fd: &OwnedFd, address: &SocketAddrAny, datagrams: &[&[u8]]) -> CountedSend {
    let count = datagrams.len().min(BATCH);
    let mut entries: [Entry<'_>; BATCH] = std::array::from_fn(|at| Entry {
        iov: [IoSlice::new(datagrams.get(at).copied().unwrap_or_default())],
        control: SendAncillaryBuffer::default(),
    });
    let mut headers = entries.each_mut().map(|entry| {
        let Entry { iov, control } = entry;
        MMsgHdr::new_with_addr(address, &*iov, control)
    });
    let batch = headers.get_mut(..count).unwrap_or_default();
    let result = match rustix::net::sendmmsg(fd, batch, SendFlags::DONTWAIT) {
        Ok(sent) => {
            let lengths = batch.iter().zip(datagrams).take(sent);
            let short = lengths
                .enumerate()
                .find(|(_, (header, datagram))| header.bytes_sent() != datagram.len());
            match short {
                Some((proven, _)) => SendResult::OutOfAbi { proven },
                None => SendResult::Sent { sent, error: None },
            }
        }
        Err(error) => SendResult::Error(errno(error)),
    };
    CountedSend { result, calls: 1 }
}

/// Sends `datagrams` with one `sendmsg_addr` each, stopping at the first
/// error (4.3). Never returns `Sent { sent: 0, error: None }`: a first
/// failure is the call's error, and a loop that runs to the end sent every
/// datagram of a non-empty slice.
fn send_each(fd: &OwnedFd, address: &SocketAddrAny, datagrams: &[&[u8]]) -> CountedSend {
    // `sent` datagrams before this one, and the calls including this one.
    for ((sent, calls), datagram) in (0_usize..).zip(1_usize..).zip(datagrams) {
        let iov = [IoSlice::new(datagram)];
        let mut control = SendAncillaryBuffer::default();
        let result =
            match rustix::net::sendmsg_addr(fd, address, &iov, &mut control, SendFlags::DONTWAIT) {
                Ok(len) if len == datagram.len() => continue,
                Ok(_) => SendResult::OutOfAbi { proven: sent },
                Err(error) if sent == 0 => SendResult::Error(errno(error)),
                Err(error) => SendResult::Sent {
                    sent,
                    error: Some(errno(error)),
                },
            };
        return CountedSend { result, calls };
    }
    CountedSend {
        result: SendResult::Sent {
            sent: datagrams.len(),
            error: None,
        },
        calls: datagrams.len(),
    }
}

impl LinuxSocket {
    /// [`SocketOps::send`] with the number of system calls it made.
    pub fn send_counted(&mut self, route: &RouteAddr, datagrams: &[&[u8]]) -> CountedSend {
        let Some(fd) = self.fd.as_ref() else {
            return CountedSend {
                result: SendResult::Error(Errno::BADF),
                calls: 0,
            };
        };
        if datagrams.is_empty() {
            // Nothing offered, nothing called: zero of zero is exact.
            return CountedSend {
                result: SendResult::Sent {
                    sent: 0,
                    error: None,
                },
                calls: 0,
            };
        }
        if self.batch {
            send_batch(fd, route.os(), datagrams)
        } else {
            send_each(fd, route.os(), datagrams)
        }
    }
}

impl SocketOps for LinuxSocket {
    fn send(&mut self, route: &RouteAddr, datagrams: &[&[u8]]) -> SendResult {
        self.send_counted(route, datagrams).result
    }

    fn recv(&mut self, buffer: &mut [u8]) -> RecvResult {
        let Some(fd) = self.fd.as_ref() else {
            return RecvResult::Error(Errno::BADF);
        };
        let capacity = buffer.len();
        let mut iov = [IoSliceMut::new(buffer)];
        let mut control = RecvAncillaryBuffer::new(&mut []);
        let flags = RecvFlags::DONTWAIT | RecvFlags::TRUNC;
        match rustix::net::recvmsg(fd, &mut iov, &mut control, flags) {
            Ok(message) => {
                // A datagram that fills the buffer reports its length too:
                // `max_datagram + 1` bytes is oversize, and `MSG_TRUNC`
                // makes the length exact (4.4).
                let truncated =
                    message.flags.contains(ReturnFlags::TRUNC) || message.bytes >= capacity;
                RecvResult::Datagram {
                    len: message.bytes.min(capacity),
                    truncated: truncated.then_some(message.bytes),
                    source: message
                        .address
                        .and_then(|address| SocketAddr::try_from(address).ok()),
                }
            }
            Err(error) => RecvResult::Error(errno(error)),
        }
    }

    fn open(&mut self, config: &SocketsConfig) -> Result<SocketProbes, OpenError> {
        self.close();
        let (fd, probes) = configure(config)?;
        self.batch = probes.tx_batch == CapabilityState::Active;
        self.fd = Some(fd);
        Ok(probes)
    }

    fn close(&mut self) {
        self.fd = None;
    }

    fn try_clone(&self) -> Result<Self, Errno> {
        let fd = self.fd.as_ref().ok_or(Errno::BADF)?;
        let duplicate = retry_intr(|| rustix::io::fcntl_dupfd_cloexec(fd, 0)).map_err(errno)?;
        Ok(Self {
            fd: Some(duplicate),
            batch: self.batch,
        })
    }

    fn route_mtu(&mut self, route: &RouteAddr) -> Option<u32> {
        let ipv4 = route.address().is_ipv4();
        let family = if ipv4 {
            AddressFamily::INET
        } else {
            AddressFamily::INET6
        };
        let probe = retry_intr(|| {
            rustix::net::socket_with(
                family,
                SocketType::DGRAM,
                SocketFlags::CLOEXEC,
                Some(ipproto::UDP),
            )
        })
        .ok()?;
        retry_intr(|| rustix::net::connect(&probe, route.os())).ok()?;
        let mtu = if ipv4 {
            sockopt::ip_mtu(&probe)
        } else {
            sockopt::ipv6_mtu(&probe)
        };
        mtu.ok()
    }
}

#[cfg(test)]
mod tests;
