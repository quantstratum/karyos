// SPDX-License-Identifier: Apache-2.0

//! The Linux system calls `rustix` 1.1.5 has no API for, behind a safe
//! interface: the only `unsafe` of `karyos-io` outside `uring::ring`
//! (quantstratum-docs: karyos/reviews/dependency-admission-libc-linux-sockets.md,
//! owner item 12).
//!
//! - [`set_multicast_all_off`]: `setsockopt(IPPROTO_IP, IP_MULTICAST_ALL, 0)`,
//!   or `setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)` for an IPv6
//!   socket. A socket bound to the wildcard address then receives only the
//!   groups it joined itself, on the interface it joined them on, never a
//!   group another socket of the host joined on the same port
//!   (sockets-backend.md section 4.1). That is what isolates the sockets of
//!   a channel's redundant paths from one another.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

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
