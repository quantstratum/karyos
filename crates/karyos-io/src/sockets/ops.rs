// SPDX-License-Identifier: Apache-2.0

//! The `SocketOps` seam (`quantstratum-docs: karyos/design/sockets-backend.md`
//! 3.9): the only place that performs socket system calls. The endpoint is
//! generic over it, monomorphized, never `dyn`, so its state machine,
//! partial batches and error mapping run against a scripted double as well
//! as the operating system.

use std::net::SocketAddr;

use super::endpoint::{BufferSize, Membership, SocketsConfig};
use crate::backend::{CapabilityState, OpenError};

/// The destination of a route, stored once at `add_route` so sends never
/// convert or allocate: on Linux it also holds the `rustix` socket address
/// the send calls take (3.8).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteAddr {
    address: SocketAddr,
    #[cfg(target_os = "linux")]
    os: rustix::net::SocketAddrAny,
}

impl RouteAddr {
    /// Stores `address`, converted once for the platform's send calls.
    #[inline]
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            #[cfg(target_os = "linux")]
            os: rustix::net::SocketAddrAny::from(address),
        }
    }

    /// The destination as the Linux send calls take it.
    #[cfg(target_os = "linux")]
    #[inline]
    pub(crate) fn os(&self) -> &rustix::net::SocketAddrAny {
        &self.os
    }

    /// The destination.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

/// A raw OS error number, as the platform's system calls report it.
///
/// The named constants are the codes the sockets backend classifies
/// (section 4.7) and probes (8.2), with the values of the build target:
/// Linux on an `asm-generic` errno architecture (such as x86_64 and
/// aarch64), or macOS. Any other target fails to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Errno(i32);

impl Errno {
    /// `EPERM`.
    pub const PERM: Self = Self(codes::EPERM);
    /// `EINTR`.
    pub const INTR: Self = Self(codes::EINTR);
    /// `EBADF`.
    pub const BADF: Self = Self(codes::EBADF);
    /// `EAGAIN`, equal to `EWOULDBLOCK` on both platforms.
    pub const AGAIN: Self = Self(codes::EAGAIN);
    /// `ENOMEM`.
    pub const NOMEM: Self = Self(codes::ENOMEM);
    /// `EACCES`.
    pub const ACCES: Self = Self(codes::EACCES);
    /// `EFAULT`.
    pub const FAULT: Self = Self(codes::EFAULT);
    /// `EINVAL`.
    pub const INVAL: Self = Self(codes::EINVAL);
    /// `ENOSYS`.
    pub const NOSYS: Self = Self(codes::ENOSYS);
    /// `ENOTSOCK`.
    pub const NOTSOCK: Self = Self(codes::ENOTSOCK);
    /// `EMSGSIZE`.
    pub const MSGSIZE: Self = Self(codes::EMSGSIZE);
    /// `EADDRINUSE`.
    pub const ADDRINUSE: Self = Self(codes::EADDRINUSE);
    /// `EADDRNOTAVAIL`.
    pub const ADDRNOTAVAIL: Self = Self(codes::EADDRNOTAVAIL);
    /// `ENETDOWN`.
    pub const NETDOWN: Self = Self(codes::ENETDOWN);
    /// `ENETUNREACH`.
    pub const NETUNREACH: Self = Self(codes::ENETUNREACH);
    /// `ENOBUFS`.
    pub const NOBUFS: Self = Self(codes::ENOBUFS);
    /// `ECONNREFUSED`.
    pub const CONNREFUSED: Self = Self(codes::ECONNREFUSED);
    /// `EHOSTUNREACH`.
    pub const HOSTUNREACH: Self = Self(codes::EHOSTUNREACH);

    /// Wraps a raw OS error number.
    #[inline]
    #[must_use]
    pub const fn from_raw(raw: i32) -> Self {
        Self(raw)
    }

    /// Returns the raw OS error number.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> i32 {
        self.0
    }
}

// The Linux values of `include/uapi/asm-generic/errno-base.h` and
// `errno.h`. They hold only on architectures that use the asm-generic
// table: mips, sparc and alpha define their own numbers, so they are
// rejected below rather than given wrong values.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "mips32r6",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64"
    )
))]
compile_error!("the Linux errno table of karyos-io covers asm-generic architectures only");

// Every other target, Android included (it uses the Linux numbers), needs
// its own reviewed table.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("karyos-io has errno values for Linux and macOS only (SPEC.md §16.2)");

#[cfg(target_os = "linux")]
mod codes {
    pub(super) const EPERM: i32 = 1;
    pub(super) const EINTR: i32 = 4;
    pub(super) const EBADF: i32 = 9;
    pub(super) const EAGAIN: i32 = 11;
    pub(super) const ENOMEM: i32 = 12;
    pub(super) const EACCES: i32 = 13;
    pub(super) const EFAULT: i32 = 14;
    pub(super) const EINVAL: i32 = 22;
    pub(super) const ENOSYS: i32 = 38;
    pub(super) const ENOTSOCK: i32 = 88;
    pub(super) const EMSGSIZE: i32 = 90;
    pub(super) const EADDRINUSE: i32 = 98;
    pub(super) const EADDRNOTAVAIL: i32 = 99;
    pub(super) const ENETDOWN: i32 = 100;
    pub(super) const ENETUNREACH: i32 = 101;
    pub(super) const ENOBUFS: i32 = 105;
    pub(super) const ECONNREFUSED: i32 = 111;
    pub(super) const EHOSTUNREACH: i32 = 113;
}

// The BSD values of macOS, the other supported platform (SPEC.md §16.2).
#[cfg(target_os = "macos")]
mod codes {
    pub(super) const EPERM: i32 = 1;
    pub(super) const EINTR: i32 = 4;
    pub(super) const EBADF: i32 = 9;
    pub(super) const ENOMEM: i32 = 12;
    pub(super) const EACCES: i32 = 13;
    pub(super) const EFAULT: i32 = 14;
    pub(super) const EINVAL: i32 = 22;
    pub(super) const EAGAIN: i32 = 35;
    pub(super) const ENOTSOCK: i32 = 38;
    pub(super) const EMSGSIZE: i32 = 40;
    pub(super) const EADDRINUSE: i32 = 48;
    pub(super) const EADDRNOTAVAIL: i32 = 49;
    pub(super) const ENETDOWN: i32 = 50;
    pub(super) const ENETUNREACH: i32 = 51;
    pub(super) const ENOBUFS: i32 = 55;
    pub(super) const ECONNREFUSED: i32 = 61;
    pub(super) const EHOSTUNREACH: i32 = 65;
    pub(super) const ENOSYS: i32 = 78;
}

/// The only place that performs socket system calls.
///
/// The data calls, [`send`](Self::send) and [`recv`](Self::recv), are
/// nonblocking: they never wait, poll a descriptor or retry. The other
/// methods run on the control path only: `open` and `reopen` create and
/// configure the socket ([`open`](Self::open)), `reset` and `retire` close
/// it ([`close`](Self::close)), `split` duplicates its descriptor
/// ([`try_clone`](Self::try_clone)) and `add_route` measures the route MTU
/// ([`route_mtu`](Self::route_mtu)), sections 3.8, 3.10, 4.1 and 4.5.
///
/// **Dropping a value closes its descriptor**, as [`close`](Self::close)
/// does. The endpoint relies on it: a failed `open` or `reopen` and a
/// failed `split` drop the handles they hold, and `join` drops the RX
/// half's duplicate, without any other cleanup call (7.4).
pub trait SocketOps: Sized {
    /// Sends `datagrams`, in order, to `route`. When the probes of the
    /// last [`open`](Self::open) reported
    /// [`SocketProbes::tx_batch`] `Active`, this is exactly one
    /// `sendmmsg`; otherwise it is single sends, one per datagram, stopping
    /// at the first error (4.3). The endpoint counts `Spent::ops` from this
    /// rule (5.3), so an implementation must not batch without an `Active`
    /// probe or split a batch into several calls when it is `Active`.
    fn send(&mut self, route: &RouteAddr, datagrams: &[&[u8]]) -> SendResult;

    /// Receives one datagram into `buffer`.
    fn recv(&mut self, buffer: &mut [u8]) -> RecvResult;

    /// Whether the sockets of a channel's redundant paths are isolated per
    /// interface: a datagram arriving on one path's interface is never
    /// received by another path's socket (`quantstratum-docs:
    /// karyos/design/redundant-paths.md`). Without it every datagram would
    /// count on every path, so the driver refuses a channel with `paths`.
    /// `false` until a backend can guarantee it (owner item 12: on Linux,
    /// `IP_MULTICAST_ALL` off per path socket).
    #[must_use]
    fn isolates_paths() -> bool {
        false
    }

    /// Creates, configures and binds the socket for `config` (4.1) and
    /// runs the probes of 8.2. A failure leaves no socket open.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::Os`] when a setup call fails; no partial socket
    /// is kept.
    fn open(&mut self, config: &SocketsConfig) -> Result<SocketProbes, OpenError>;

    /// Closes this descriptor. Datagrams still in the kernel send buffer may
    /// go out; neither direction touches user memory afterwards. Closing a
    /// closed socket does nothing.
    fn close(&mut self);

    /// Duplicates the descriptor for the other half of `split` (3.10):
    /// `fcntl_dupfd_cloexec` on Linux, `UdpSocket::try_clone` on macOS.
    /// Closing either descriptor leaves the other working.
    ///
    /// # Errors
    ///
    /// Returns the OS error of the duplication.
    fn try_clone(&self) -> Result<Self, Errno>;

    /// Measures the route MTU towards `route` (4.5): `IP_MTU` or
    /// `IPV6_MTU` on a connected temporary socket on Linux. `None` when it
    /// cannot be measured, always on macOS, which selects the declared
    /// fallback.
    fn route_mtu(&mut self, route: &RouteAddr) -> Option<u32>;
}

/// What [`SocketOps::open`] established about the new socket: the platform
/// dependent rows of the capability snapshot (8.1); the endpoint adds the
/// rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketProbes {
    /// The bound local address, with the port the kernel chose for port 0.
    pub local: SocketAddr,
    /// Index of the interface owning `local`; `None` for a wildcard.
    pub interface: Option<u32>,
    /// `IP_MTU_DISCOVER` set to `Do` and read back.
    pub dont_fragment: CapabilityState,
    /// The `sendmmsg` probe. `Active` means every
    /// [`SocketOps::send`] of the epoch is one `sendmmsg` call.
    pub tx_batch: CapabilityState,
    /// The send buffer request and its read back.
    pub send_buffer: BufferSize,
    /// The receive buffer request and its read back.
    pub recv_buffer: BufferSize,
    /// The joined group, when the configuration has one.
    pub multicast: Option<Membership>,
}

/// The result of one [`SocketOps::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResult {
    /// The first `sent` datagrams were handed off. `error` is the failure
    /// of datagram `sent`, when the call reported it.
    Sent {
        /// Datagrams the kernel accepted, from the first.
        sent: usize,
        /// The failure of datagram `sent`, when reported.
        error: Option<Errno>,
    },
    /// The call failed before handing off any datagram.
    Error(Errno),
    /// The call returned a result outside its documented ABI (4.3): a
    /// `msg_len` (`MMsgHdr::bytes_sent`) or a single send result that is
    /// not the datagram's length. Only the first `proven` datagrams carry a
    /// valid length; the exposure of every later datagram of the call is
    /// unproven. A count above the request is detected by the endpoint
    /// from [`SendResult::Sent`].
    OutOfAbi {
        /// Datagrams, from the first, whose acceptance a valid length
        /// proves.
        proven: usize,
    },
}

/// The result of one [`SocketOps::recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvResult {
    /// One datagram; `len` bytes of `buffer` hold its start.
    Datagram {
        /// Bytes written into the buffer.
        len: usize,
        /// The true datagram length, when the datagram filled or exceeded
        /// the buffer and the call reports it (`MSG_TRUNC` on Linux). A
        /// full buffer alone is ambiguous: `None` with `len` equal to the
        /// buffer's length means the length is unknown (macOS).
        truncated: Option<usize>,
        /// The sender, when the call reported one.
        source: Option<SocketAddr>,
    },
    /// The call failed.
    Error(Errno),
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::net::Ipv6Addr;

    use super::*;

    fn kind(errno: Errno) -> ErrorKind {
        Error::from_raw_os_error(errno.raw()).kind()
    }

    /// The constants match the platform: checked through the standard
    /// library's errno to `ErrorKind` mapping where that mapping is stable,
    /// and otherwise against the numbers of the platform headers. No
    /// `strerror` text is compared, as it differs between C libraries
    /// (glibc, musl, the BSDs).
    #[test]
    fn errno_constants_match_the_platform() {
        assert_eq!(kind(Errno::AGAIN), ErrorKind::WouldBlock);
        assert_eq!(kind(Errno::INTR), ErrorKind::Interrupted);
        assert_eq!(kind(Errno::NOMEM), ErrorKind::OutOfMemory);
        assert_eq!(kind(Errno::PERM), ErrorKind::PermissionDenied);
        assert_eq!(kind(Errno::ACCES), ErrorKind::PermissionDenied);
        assert_eq!(kind(Errno::INVAL), ErrorKind::InvalidInput);
        assert_eq!(kind(Errno::NOSYS), ErrorKind::Unsupported);
        assert_eq!(kind(Errno::ADDRINUSE), ErrorKind::AddrInUse);
        assert_eq!(kind(Errno::ADDRNOTAVAIL), ErrorKind::AddrNotAvailable);
        assert_eq!(kind(Errno::NETDOWN), ErrorKind::NetworkDown);
        assert_eq!(kind(Errno::NETUNREACH), ErrorKind::NetworkUnreachable);
        assert_eq!(kind(Errno::HOSTUNREACH), ErrorKind::HostUnreachable);
        assert_eq!(kind(Errno::CONNREFUSED), ErrorKind::ConnectionRefused);
        // Codes without a stable `ErrorKind`: the raw number round trips
        // through `std::io::Error` and equals the header value.
        #[cfg(target_os = "linux")]
        let expected = [
            (Errno::PERM, 1),
            (Errno::BADF, 9),
            (Errno::FAULT, 14),
            (Errno::NOTSOCK, 88),
            (Errno::MSGSIZE, 90),
            (Errno::NOBUFS, 105),
        ];
        #[cfg(target_os = "macos")]
        let expected = [
            (Errno::PERM, 1),
            (Errno::BADF, 9),
            (Errno::FAULT, 14),
            (Errno::NOTSOCK, 38),
            (Errno::MSGSIZE, 40),
            (Errno::NOBUFS, 55),
        ];
        for (errno, raw) in expected {
            assert_eq!(errno.raw(), raw);
            assert_eq!(Error::from_raw_os_error(raw).raw_os_error(), Some(raw));
        }
        assert_eq!(Errno::from_raw(Errno::AGAIN.raw()), Errno::AGAIN);
    }

    #[test]
    fn a_route_address_is_stored_unchanged() {
        let address = SocketAddr::from((Ipv6Addr::LOCALHOST, 9));
        assert_eq!(RouteAddr::new(address).address(), address);
    }
}
