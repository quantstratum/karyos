// SPDX-License-Identifier: Apache-2.0

//! The classification of `std::net` results for the macOS [`SocketOps`]
//! (`quantstratum-docs: karyos/design/sockets-backend.md` sections 4.3,
//! 4.4 and 4.7), kept apart from the socket calls so that every branch is
//! tested: some of them, such as an error without an errno, a short send
//! or `EINTR`, cannot be provoked on a real socket. Pure functions of
//! `std::io` values, built on every target in tests, so the Linux gate
//! runs them too.
//!
//! [`SocketOps`]: super::ops::SocketOps

#![forbid(unsafe_code)]

use std::io::{self, ErrorKind};

use super::ops::{Errno, RecvResult, SendResult};

/// Runs a control path call, retrying it once after `EINTR` (4.7).
pub(super) fn retry_intr<T>(mut call: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    match call() {
        Err(error) if error.kind() == ErrorKind::Interrupted => call(),
        result => result,
    }
}

/// Classifies the `send_to` of a datagram of `len` bytes, after `sent`
/// datagrams of the call were handed off (4.3). `None` when the datagram
/// was handed off whole and the next one may be sent; otherwise the
/// result of the call.
pub(super) fn send_step(sent: usize, len: usize, result: &io::Result<usize>) -> Option<SendResult> {
    match result {
        Ok(written) if *written == len => None,
        // Any other length is outside the ABI of `sendto` for a datagram.
        Ok(_) => Some(SendResult::OutOfAbi { proven: sent }),
        Err(error) => Some(match error.raw_os_error() {
            Some(raw) if sent == 0 => SendResult::Error(Errno::from_raw(raw)),
            Some(raw) => SendResult::Sent {
                sent,
                error: Some(Errno::from_raw(raw)),
            },
            // An error `std` made up without a system call result proves
            // nothing about this datagram: its exposure is unproven (6.3),
            // never assumed absent.
            None => SendResult::OutOfAbi { proven: sent },
        }),
    }
}

/// Classifies a failed `recv_from` (4.4).
pub(super) fn recv_error(error: &io::Error) -> RecvResult {
    match error.raw_os_error() {
        Some(raw) => RecvResult::Error(Errno::from_raw(raw)),
        // `std` reports a source address of a family other than IPv4 or
        // IPv6 as an `InvalidInput` error without an errno, made after
        // `recvfrom` consumed the datagram and lost its length: an
        // `UnsupportedSource` drop (4.4) with nothing lent.
        None if error.kind() == ErrorKind::InvalidInput => RecvResult::Datagram {
            len: 0,
            truncated: None,
            source: None,
        },
        // Any other error without an errno is not documented for
        // `recv_from`; 0 makes it a failure of the half, the conservative
        // outcome, rather than a guessed class.
        None => RecvResult::Error(Errno::from_raw(0)),
    }
}

#[cfg(test)]
mod tests;
