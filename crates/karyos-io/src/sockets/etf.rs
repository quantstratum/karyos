// SPDX-License-Identifier: Apache-2.0

//! The `etf` route's socket (`quantstratum-docs: karyos/design/timed-tx.md`
//! section 5, TT-5; owner item 29): a dedicated UDP socket per scheduled
//! publication with `SO_TXTIME` on `CLOCK_TAI` and
//! `SOF_TXTIME_REPORT_ERRORS`, each datagram carrying its time in
//! `SCM_TXTIME`, and its error queue drained into decoded entries.
//!
//! The dedicated socket keeps future packets out of the immediate queue.
//! Hardware launch time is not here: it stays refused at configuration
//! (SPEC.md §16, hardware track). Whether the interface has an `etf` qdisc
//! cannot be probed from the socket; the configuration declares it.

#![forbid(unsafe_code)]

use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;

use rustix::net::sockopt::set_txtime;
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
    TxTimeFlags,
};
use rustix::time::ClockId;

use super::errqueue::ErrEntry;
use crate::backend::OpenError;

/// A raw OS error number of an `etf` socket call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtfErrno(pub i32);

/// The `etf` socket of one scheduled publication.
#[derive(Debug)]
pub struct EtfSocket {
    fd: OwnedFd,
}

impl EtfSocket {
    /// Creates a nonblocking UDP socket bound to `local` and configures
    /// `SO_TXTIME` on `CLOCK_TAI` with error reports. A failure of
    /// `SO_TXTIME` is what rejects a required `etf` configuration.
    ///
    /// # Errors
    ///
    /// [`OpenError::Os`] naming `socket`, `bind` or `so_txtime`.
    pub fn open(local: SocketAddr) -> Result<Self, OpenError> {
        let family = match local {
            SocketAddr::V4(_) => AddressFamily::INET,
            SocketAddr::V6(_) => AddressFamily::INET6,
        };
        let os = |operation| {
            move |errno: rustix::io::Errno| OpenError::Os {
                operation,
                errno: errno.raw_os_error(),
            }
        };
        let fd = rustix::net::socket_with(
            family,
            SocketType::DGRAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .map_err(os("socket"))?;
        rustix::net::bind(&fd, &local).map_err(os("bind"))?;
        set_txtime(&fd, ClockId::Tai, TxTimeFlags::REPORT_ERRORS).map_err(os("so_txtime"))?;
        Ok(Self { fd })
    }

    /// The local address of the socket.
    ///
    /// # Errors
    ///
    /// The errno of `getsockname`.
    pub fn local_addr(&self) -> Result<SocketAddr, EtfErrno> {
        rustix::net::getsockname(&self.fd)
            .and_then(SocketAddr::try_from)
            .map_err(|errno| EtfErrno(errno.raw_os_error()))
    }

    /// Sends `bytes` to `destination` with `SCM_TXTIME` = `txtime_ns`
    /// (nanoseconds of `CLOCK_TAI`), without blocking.
    ///
    /// # Errors
    ///
    /// The errno of `sendmsg`, for example `EAGAIN`.
    pub fn send(
        &self,
        destination: SocketAddr,
        bytes: &[u8],
        txtime_ns: u64,
    ) -> Result<(), EtfErrno> {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(TxTime(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::TxTime(txtime_ns)) {
            return Err(EtfErrno(105));
        }
        let sent = rustix::net::sendmsg_addr(
            &self.fd,
            &destination,
            &[IoSlice::new(bytes)],
            &mut control,
            SendFlags::DONTWAIT,
        )
        .map_err(|errno| EtfErrno(errno.raw_os_error()))?;
        if sent == bytes.len() {
            Ok(())
        } else {
            Err(EtfErrno(90))
        }
    }

    /// Drains up to `out.len()` error queue entries (ETF drops and others)
    /// without blocking; returns how many.
    ///
    /// # Errors
    ///
    /// The errno of `recvmsg` other than `EAGAIN`.
    pub fn drain_errors(&self, out: &mut [ErrEntry]) -> Result<usize, EtfErrno> {
        crate::linux_sys::drain_error_queue(&self.fd, out).map_err(EtfErrno)
    }
}

#[cfg(test)]
#[expect(
    clippy::print_stderr,
    reason = "a skipped kernel test says why on the test output"
)]
mod tests;
