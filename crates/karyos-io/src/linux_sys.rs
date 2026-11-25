// SPDX-License-Identifier: Apache-2.0

//! The Linux system calls `rustix` 1.1.5 has no API for, behind a safe
//! interface: the only place in `karyos-io` that calls `libc`, and its only
//! `unsafe` outside the `ring` modules (joint admission record
//! `quantstratum-docs: karyos/reviews/dependency-admission-libc-linux-sockets.md`;
//! owner items 12 and 29).
//!
//! - [`set_multicast_all_off`]: `setsockopt(IPPROTO_IP, IP_MULTICAST_ALL, 0)`,
//!   or `setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)` for an IPv6
//!   socket. A socket bound to the wildcard address then receives only the
//!   groups it joined itself, on the interface it joined them on, never a
//!   group another socket of the host joined on the same port
//!   (sockets-backend.md section 4.1). That is what isolates the sockets of
//!   a channel's redundant paths from one another.
//! - [`drain_error_queue`]: for the `etf` route of timed sends, drains an
//!   `etf` socket's error queue with `recvmsg(MSG_ERRQUEUE |
//!   MSG_DONTWAIT)` into decoded entries. The control area is a zeroed byte
//!   array of fixed size, parsed in safe code by [`super::sockets::errqueue`];
//!   the `unsafe` there is the system call and the zero initialisation of the
//!   `msghdr` it takes, nothing else.
//! - [`attach_reuseport_first`]: for the `etf` route (ADR-0109 point 5),
//!   attaches the one-instruction classic BPF program `ret #0` to a
//!   `SO_REUSEPORT` socket with `SO_ATTACH_REUSEPORT_CBPF`, so every
//!   inbound datagram of its group goes to the group's first socket, the
//!   endpoint socket, never to the `etf` socket that joins it later.
//! - [`set_priority`]: `setsockopt(SOL_SOCKET, SO_PRIORITY)` of the `etf`
//!   socket, through the same integer option call as
//!   [`set_multicast_all_off`].

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use crate::sockets::errqueue::{ErrEntry, parse_control};

/// Bytes of the control area: one `cmsghdr` with a `sock_extended_err`
/// and its offender address, with room to spare.
const CONTROL: usize = 256;

/// Drains up to `out.len()` entries of `fd`'s error queue, without
/// blocking; returns how many it wrote. An empty queue ends the drain.
///
/// # Errors
///
/// The errno of `recvmsg` other than `EAGAIN`.
pub(crate) fn drain_error_queue(fd: impl AsFd, out: &mut [ErrEntry]) -> Result<usize, i32> {
    let raw = fd.as_fd().as_raw_fd();
    let mut drained: usize = 0;
    for entry in out.iter_mut() {
        // The offending datagram's bytes are not needed: a small buffer,
        // truncated by the kernel, is enough.
        let mut payload = [0_u8; 64];
        let mut control = [0_u8; CONTROL];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: `msghdr` is a plain C struct for which all zero bytes is
        // a valid value (null pointers, zero lengths).
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = CONTROL as _;
        // SAFETY: `msg` names `iov` and `control`, both alive and writable
        // for their stated lengths until the call returns; `raw` is an
        // open descriptor borrowed through `fd`.
        let received =
            unsafe { libc::recvmsg(raw, &raw mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        if received < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EAGAIN {
                break;
            }
            return Err(errno);
        }
        // `msg_controllen` is a `size_t` on glibc and a `socklen_t` on musl.
        #[allow(clippy::useless_conversion, reason = "a u32 on musl")]
        let written = usize::try_from(msg.msg_controllen)
            .unwrap_or(0)
            .min(CONTROL);
        let truncated = msg.msg_flags & libc::MSG_CTRUNC != 0;
        *entry = parse_control(control.get(..written).unwrap_or_default(), truncated);
        drained = drained.saturating_add(1);
    }
    Ok(drained)
}

/// Sets `IP_MULTICAST_ALL` (IPv4) or `IPV6_MULTICAST_ALL` (IPv6) to 0 on
/// `fd`: it receives only the multicast groups it joined itself.
///
/// # Errors
///
/// The operating system's error, for example `ENOPROTOOPT` on a kernel
/// without the option (IPv6 needs Linux 4.20).
pub(crate) fn set_multicast_all_off(fd: BorrowedFd<'_>, ipv6: bool) -> io::Result<()> {
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_ALL)
    } else {
        (libc::IPPROTO_IP, libc::IP_MULTICAST_ALL)
    };
    set_int(fd, IntOption::new(level, option), 0)
}

/// Sets `SO_PRIORITY` of `fd` to `priority`: the queue its datagrams take
/// through the interface's root qdisc.
///
/// # Errors
///
/// The operating system's error, for example `EPERM` for a priority above
/// 6 without `CAP_NET_ADMIN`, or `EINVAL` for one that does not fit a C
/// `int`.
pub(crate) fn set_priority(fd: BorrowedFd<'_>, priority: u32) -> io::Result<()> {
    let value =
        libc::c_int::try_from(priority).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    set_int(
        fd,
        IntOption::new(libc::SOL_SOCKET, libc::SO_PRIORITY),
        value,
    )
}

/// A socket option the kernel defines as a C `int`: the only kind
/// [`set_int`] passes, so the kernel reads exactly one `int`.
#[derive(Debug, Clone, Copy)]
struct IntOption {
    level: libc::c_int,
    option: libc::c_int,
}

impl IntOption {
    const fn new(level: libc::c_int, option: libc::c_int) -> Self {
        Self { level, option }
    }
}

/// `setsockopt` of an integer option.
fn set_int(fd: BorrowedFd<'_>, option: IntOption, value: libc::c_int) -> io::Result<()> {
    let length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `fd` is a live descriptor borrowed for the call; the option
    // value points to `value`, a live `c_int` of exactly `length` bytes
    // that the kernel only reads; `level` and `option` are an integer
    // option pair the kernel defines (`IntOption`), so no other memory is
    // touched.
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            option.level,
            option.option,
            (&raw const value).cast::<libc::c_void>(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `BPF_RET | BPF_K`: return the constant `k`.
const BPF_RET_K: u16 = 0x06;

/// Attaches the classic BPF program `ret #0` to `fd` with
/// `SO_ATTACH_REUSEPORT_CBPF` (ADR-0109 point 5): the kernel then hands
/// every datagram of `fd`'s `SO_REUSEPORT` group to the group's socket of
/// index 0, the first one bound. `fd` must have set `SO_REUSEPORT` and be
/// bound.
///
/// # Errors
///
/// The operating system's error, for example `EINVAL` for a socket
/// without a reuseport group.
pub(crate) fn attach_reuseport_first(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut program = [libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    let fprog = libc::sock_fprog {
        len: 1,
        filter: program.as_mut_ptr(),
    };
    let length = libc::socklen_t::try_from(size_of::<libc::sock_fprog>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `fd` is a live descriptor borrowed for the call; the option
    // value points to `fprog`, a live `sock_fprog` of exactly `length`
    // bytes whose `filter` points to `program`, one live `sock_filter` as
    // `len` says; the kernel copies both before the call returns and
    // writes neither.
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_REUSEPORT_CBPF,
            (&raw const fprog).cast::<libc::c_void>(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::os::fd::AsFd;

    use super::{attach_reuseport_first, set_multicast_all_off, set_priority};

    #[test]
    fn the_option_is_accepted_on_an_ipv4_socket() {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert!(set_multicast_all_off(socket.as_fd(), false).is_ok());
    }

    #[test]
    fn the_ipv6_option_on_an_ipv4_socket_is_an_error_not_a_panic() {
        // The IPv6 option on an IPv4 socket is refused by the kernel.
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert!(set_multicast_all_off(socket.as_fd(), true).is_err());
    }

    #[test]
    fn the_steering_program_attaches_only_to_a_reuseport_group() {
        let grouped = rustix::net::socket(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::DGRAM,
            None,
        )
        .unwrap();
        rustix::net::sockopt::set_socket_reuseport(&grouped, true).unwrap();
        rustix::net::bind(&grouped, &std::net::SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        assert!(attach_reuseport_first(grouped.as_fd()).is_ok());
        // A bound socket without `SO_REUSEPORT` has no group to steer.
        let alone = UdpSocket::bind("127.0.0.1:0").unwrap();
        let error = attach_reuseport_first(alone.as_fd()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn the_priority_is_set_and_an_oversized_one_refused() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Priorities 0 to 6 need no capability.
        set_priority(socket.as_fd(), 3).unwrap();
        let error = set_priority(socket.as_fd(), u32::MAX).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    }
}
