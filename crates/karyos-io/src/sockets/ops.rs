// SPDX-License-Identifier: Apache-2.0

//! The `SocketOps` seam (`quantstratum-docs: karyos/design/sockets-backend.md`
//! 3.9): the only place that performs socket system calls. The endpoint is
//! generic over it, monomorphized, never `dyn`, so its state machine,
//! partial batches and error mapping run against a scripted double as well
//! as the operating system.

use std::net::SocketAddr;

/// The destination of a route, stored once at `add_route` so sends never
/// convert or allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteAddr {
    address: SocketAddr,
}

impl RouteAddr {
    /// Stores `address`.
    #[inline]
    #[must_use]
    pub const fn new(address: SocketAddr) -> Self {
        Self { address }
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
    pub(super) const EADDRNOTAVAIL: i32 = 49;
    pub(super) const ENETDOWN: i32 = 50;
    pub(super) const ENETUNREACH: i32 = 51;
    pub(super) const ENOBUFS: i32 = 55;
    pub(super) const ECONNREFUSED: i32 = 61;
    pub(super) const EHOSTUNREACH: i32 = 65;
    pub(super) const ENOSYS: i32 = 78;
}

/// The only place that performs socket system calls. Both calls are
/// nonblocking: they never wait, poll a descriptor or retry.
pub trait SocketOps {
    /// Sends `datagrams`, in order, to `route`: one `sendmmsg`, or single
    /// sends stopping at the first error.
    fn send(&mut self, route: &RouteAddr, datagrams: &[&[u8]]) -> SendResult;

    /// Receives one datagram into `buffer`.
    fn recv(&mut self, buffer: &mut [u8]) -> RecvResult;
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
}

/// The result of one [`SocketOps::recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvResult {
    /// One datagram; `len` bytes of `buffer` hold its start.
    Datagram {
        /// Bytes written into the buffer.
        len: usize,
        /// The true datagram length when the kernel reported truncation.
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
