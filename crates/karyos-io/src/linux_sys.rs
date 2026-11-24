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
    let off: libc::c_int = 0;
    let length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `fd` is a live descriptor borrowed for the call; the option
    // value points to `off`, a live `c_int` of exactly `length` bytes that
    // the kernel only reads; `level` and `option` are an integer option
    // pair the kernel defines, so no other memory is touched.
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            option,
            (&raw const off).cast::<libc::c_void>(),
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

    use super::set_multicast_all_off;

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
}
