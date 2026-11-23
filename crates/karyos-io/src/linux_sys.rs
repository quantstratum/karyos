// SPDX-License-Identifier: Apache-2.0

//! The narrow Linux `libc` module of the joint admission record
//! (`quantstratum-docs: karyos/reviews/dependency-admission-libc-linux-sockets.md`;
//! owner items 12 and 29): the only place in `karyos-io` that calls `libc`.
//!
//! It exposes one safe call for the `etf` route of timed sends: draining
//! an `etf` socket's error queue with `recvmsg(MSG_ERRQUEUE |
//! MSG_DONTWAIT)` into decoded entries. The control area is a zeroed byte
//! array of fixed size, parsed in safe code by [`super::sockets::errqueue`];
//! the `unsafe` here is the system call and the zero initialisation of the
//! `msghdr` it takes, nothing else.

use std::os::fd::{AsFd, AsRawFd};

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
