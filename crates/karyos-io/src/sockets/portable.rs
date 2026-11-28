// SPDX-License-Identifier: Apache-2.0

//! The macOS [`SocketOps`]: UDP sockets through `std::net::UdpSocket` only
//! (`quantstratum-docs: karyos/design/sockets-backend.md` section 4,
//! decisions O-2 and S-10). macOS is a functional platform (SPEC.md
//! §16.2); the gaps of `std` are recorded in the snapshot, never filled
//! with a made up value.
//!
//! - Setup (4.1): `UdpSocket::bind`, then `set_nonblocking(true)`, then
//!   the multicast membership, TTL and loop. `EINTR` is retried once on
//!   this control path (4.7). A failure drops the socket, which closes it,
//!   so no partial socket or membership is kept.
//! - Send (4.3): one `send_to` per datagram, stopping at the first error.
//!   macOS has no `sendmmsg`, so TX batching is `Fallback(Platform)` and
//!   every [`SocketOps::send`] is single sends. Each result must equal the
//!   datagram length; anything else is [`SendResult::OutOfAbi`].
//! - Receive (4.4): one `recv_from` per call into the endpoint's
//!   `max_datagram + 1` buffer. `std` passes no `MSG_TRUNC`, so a datagram
//!   that fills the buffer is reported with `truncated: None`, which the
//!   endpoint drops as `Oversize { received: None }`.
//! - `split` duplicates with `UdpSocket::try_clone` (3.10); `add_route`
//!   gets no route MTU, which selects `Fallback(Unverified)` (4.5).
//!
//! What `std` cannot do, and how it is recorded (4.1, 8.1):
//!
//! - Don't fragment: no `IP_DONTFRAG` setter; `Fallback(LibraryApi)`,
//!   datagrams may fragment.
//! - Buffer sizes: no `SO_SNDBUF` or `SO_RCVBUF` setter or getter; a
//!   request is `Fallback(LibraryApi)` with no effective size, and the OS
//!   default is in use.
//! - `SO_REUSEADDR`: no setter; one receiver per group port per host.
//! - `IPV6_V6ONLY`: no setter on `UdpSocket`; an IPv6 socket is bound dual
//!   stack, the macOS default. Routes are still refused across families.
//! - Multicast TX interface: no `IP_MULTICAST_IF` setter; datagrams to the
//!   group leave through the default route interface.
//! - IPv4 membership by interface index: `join_multicast_v4` takes an
//!   address only; a nonzero index is refused, never replaced by another
//!   interface.
//! - IPv6 multicast hop limit: no `IPV6_MULTICAST_HOPS` setter; only the
//!   macOS default of 1 (`IPV6_DEFAULT_MULTICAST_HOPS`) is accepted.
//!
//! The data calls neither allocate nor block: the socket is nonblocking
//! from creation, and `std` builds the C socket address on the stack.

#![forbid(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU32;

use super::endpoint::{BufferSize, InterfaceSel, Membership, MulticastConfig, SocketsConfig};
use super::ops::{Errno, RecvResult, RouteAddr, SendResult, SocketOps, SocketProbes};
use super::std_results::{recv_error, retry_intr, send_step};
use crate::backend::{CapabilityState, OpenError, Reason};

/// A UDP socket on macOS, or a closed one before [`SocketOps::open`] and
/// after [`SocketOps::close`]. A data call on a closed socket returns
/// `EBADF` without a system call.
#[derive(Debug, Default)]
pub struct PortableSocket {
    socket: Option<UdpSocket>,
}

impl PortableSocket {
    /// A closed socket; [`SocketOps::open`] creates it.
    #[must_use]
    pub const fn new() -> Self {
        Self { socket: None }
    }

    /// Whether the socket is open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.socket.is_some()
    }
}

/// The raw OS error number of a setup failure. `std` makes up a few errors
/// without one (an address list that resolves to nothing, which a single
/// `SocketAddr` cannot give); those are reported as 0, the value the
/// backend uses wherever a failure has no errno.
fn raw(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(0)
}

/// Maps a setup failure to [`OpenError::Os`] naming `operation`.
fn os(operation: &'static str) -> impl Fn(io::Error) -> OpenError {
    move |error| OpenError::Os {
        operation,
        errno: raw(&error),
    }
}

/// The IPv6 multicast hop limit of a macOS socket that never set
/// `IPV6_MULTICAST_HOPS`: `IPV6_DEFAULT_MULTICAST_HOPS` of
/// `netinet6/in6.h` (RFC 3493 5.2). The only `ttl` an IPv6 group accepts.
const OS_MULTICAST_HOPS: u8 = 1;

/// `std` has no API for don't fragment or buffer sizes (decision O-2):
/// the declared fallback, fragmentation possible or the OS default buffer,
/// is in use.
const LIBRARY_API: CapabilityState = CapabilityState::Fallback(Reason::LibraryApi);

/// A buffer request `std` cannot apply or read back: recorded with no
/// effective size, never a made up one (4.1).
const fn buffer(requested: Option<NonZeroU32>) -> BufferSize {
    match requested {
        None => BufferSize::NOT_REQUESTED,
        Some(_) => BufferSize {
            requested,
            effective: None,
            state: LIBRARY_API,
        },
    }
}

/// Joins the group and sets the multicast TTL and loop (4.1), within what
/// `std` offers; see the module documentation for the refusals.
fn join(socket: &UdpSocket, multicast: MulticastConfig) -> Result<Membership, OpenError> {
    match (multicast.group, multicast.interface) {
        (IpAddr::V4(group), interface) => {
            let address = match interface {
                InterfaceSel::Address(address) => address,
                // Index 0 is "any interface", which the unspecified address
                // also means to `IP_ADD_MEMBERSHIP`.
                InterfaceSel::Index(0) => Ipv4Addr::UNSPECIFIED,
                InterfaceSel::Index(index) => {
                    return Err(OpenError::InvalidConfig {
                        field: "multicast.interface",
                        value: u64::from(index),
                    });
                }
            };
            retry_intr(|| socket.join_multicast_v4(&group, &address))
                .map_err(os("setsockopt IP_ADD_MEMBERSHIP"))?;
            retry_intr(|| socket.set_multicast_ttl_v4(u32::from(multicast.ttl)))
                .map_err(os("setsockopt IP_MULTICAST_TTL"))?;
            retry_intr(|| socket.set_multicast_loop_v4(multicast.loopback))
                .map_err(os("setsockopt IP_MULTICAST_LOOP"))?;
        }
        (IpAddr::V6(group), InterfaceSel::Index(index)) => {
            // The hop limit cannot be set; a value other than the macOS
            // default would be silently ignored, so it is refused.
            if multicast.ttl != OS_MULTICAST_HOPS {
                return Err(OpenError::InvalidConfig {
                    field: "multicast.ttl",
                    value: u64::from(multicast.ttl),
                });
            }
            retry_intr(|| socket.join_multicast_v6(&group, index))
                .map_err(os("setsockopt IPV6_JOIN_GROUP"))?;
            retry_intr(|| socket.set_multicast_loop_v6(multicast.loopback))
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

/// Creates, binds and configures a socket for `config` (4.1) and records
/// what `std` establishes about it (8.1).
fn configure(config: &SocketsConfig) -> Result<(UdpSocket, SocketProbes), OpenError> {
    let socket = retry_intr(|| UdpSocket::bind(config.local)).map_err(os("bind"))?;
    retry_intr(|| socket.set_nonblocking(true)).map_err(os("ioctl FIONBIO"))?;
    let multicast = match config.multicast {
        Some(multicast) => Some(join(&socket, multicast)?),
        None => None,
    };
    let local = socket.local_addr().map_err(os("getsockname"))?;
    // `std` has no address to interface lookup; the index is known only
    // when the configuration names one.
    let interface = match config.multicast.map(|multicast| multicast.interface) {
        Some(InterfaceSel::Index(index)) if index != 0 => Some(index),
        _ => None,
    };
    let probes = SocketProbes {
        local,
        interface,
        dont_fragment: LIBRARY_API,
        // macOS has no `sendmmsg`: single sends, the declared fallback.
        tx_batch: CapabilityState::Fallback(Reason::Platform),
        // macOS has no `recvmmsg`: `recv_batch` is the default loop of
        // single `recv_from` calls, which is not batching.
        rx_batch: CapabilityState::Unavailable(Reason::Platform),
        send_buffer: buffer(config.send_buffer),
        recv_buffer: buffer(config.recv_buffer),
        multicast,
    };
    Ok((socket, probes))
}

/// A send result with the system calls that produced it, one per
/// `send_to`, for `Spent.ops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountedSend {
    /// The result of the send.
    pub result: SendResult,
    /// System calls made; zero when the socket is closed or nothing was
    /// offered.
    pub calls: usize,
}

/// Sends `datagrams` with one `send_to` each, stopping at the first error
/// (4.3). Never returns `Sent { sent: 0, error: None }` for a non-empty
/// slice: a first failure is the call's error, and a loop that runs to the
/// end sent every datagram.
fn send_each(socket: &UdpSocket, address: SocketAddr, datagrams: &[&[u8]]) -> CountedSend {
    // `sent` datagrams before this one, and the calls including this one.
    for ((sent, calls), datagram) in (0_usize..).zip(1_usize..).zip(datagrams) {
        if let Some(result) = send_step(sent, datagram.len(), &socket.send_to(datagram, address)) {
            return CountedSend { result, calls };
        }
    }
    CountedSend {
        result: SendResult::Sent {
            sent: datagrams.len(),
            error: None,
        },
        calls: datagrams.len(),
    }
}

impl PortableSocket {
    /// [`SocketOps::send`] with the number of system calls it made.
    pub fn send_counted(&mut self, route: &RouteAddr, datagrams: &[&[u8]]) -> CountedSend {
        let Some(socket) = self.socket.as_ref() else {
            return CountedSend {
                result: SendResult::Error(Errno::BADF),
                calls: 0,
            };
        };
        // An empty slice makes no call and gives `Sent { sent: 0 }`: zero
        // of zero is exact.
        send_each(socket, route.address(), datagrams)
    }
}

impl SocketOps for PortableSocket {
    fn send(&mut self, route: &RouteAddr, datagrams: &[&[u8]]) -> SendResult {
        self.send_counted(route, datagrams).result
    }

    fn recv(&mut self, buffer: &mut [u8]) -> RecvResult {
        let Some(socket) = self.socket.as_ref() else {
            return RecvResult::Error(Errno::BADF);
        };
        match socket.recv_from(buffer) {
            // Without `MSG_TRUNC` the kernel copies at most the buffer and
            // discards the rest; a full buffer is reported as is, with no
            // length, and the endpoint drops it as oversize (4.4).
            Ok((len, source)) => RecvResult::Datagram {
                len,
                truncated: None,
                source: Some(source),
            },
            Err(error) => recv_error(&error),
        }
    }

    fn open(&mut self, config: &SocketsConfig) -> Result<SocketProbes, OpenError> {
        self.close();
        let (socket, probes) = configure(config)?;
        self.socket = Some(socket);
        Ok(probes)
    }

    fn close(&mut self) {
        self.socket = None;
    }

    fn share_recv(&self) -> Result<Box<dyn super::ops::SharedRecv>, Errno> {
        Ok(Box::new(self.try_clone()?))
    }

    fn try_clone(&self) -> Result<Self, Errno> {
        let socket = self.socket.as_ref().ok_or(Errno::BADF)?;
        let duplicate =
            retry_intr(|| socket.try_clone()).map_err(|error| Errno::from_raw(raw(&error)))?;
        Ok(Self {
            socket: Some(duplicate),
        })
    }

    /// `std` cannot read a route MTU (no `IP_MTU` on macOS either): every
    /// route takes the declared fallback, `Fallback(Unverified)`, or fails
    /// with `PathUnverified` when the path MTU is required (4.5).
    fn route_mtu(&mut self, _route: &RouteAddr) -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests;
