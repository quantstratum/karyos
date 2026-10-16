// SPDX-License-Identifier: Apache-2.0

//! Tests of the `std::net` result classification, with `std::io::Error`
//! values built by hand: the branches a real socket cannot reach (an error
//! without an errno, a short send, `EINTR`) are pinned here on every
//! target.

use std::io::{self, ErrorKind};

use super::*;

/// An error the way a system call reports it.
fn os_error(errno: Errno) -> io::Error {
    io::Error::from_raw_os_error(errno.raw())
}

/// A call that fails with `first` on its first run and returns 7 after,
/// counting its runs.
fn failing_once(first: io::Error, calls: &mut usize) -> impl FnMut() -> io::Result<u32> + '_ {
    let mut first = Some(first);
    move || {
        *calls += 1;
        first.take().map_or(Ok(7), Err)
    }
}

#[test]
fn eintr_is_retried_once_on_the_control_path() {
    let mut calls = 0;
    let result = retry_intr(failing_once(os_error(Errno::INTR), &mut calls));
    assert_eq!(result.ok(), Some(7));
    assert_eq!(calls, 2);
}

#[test]
fn a_second_eintr_is_returned() {
    let mut calls = 0;
    let result: io::Result<u32> = retry_intr(|| {
        calls += 1;
        Err(os_error(Errno::INTR))
    });
    assert_eq!(
        result.err().and_then(|error| error.raw_os_error()),
        Some(Errno::INTR.raw())
    );
    assert_eq!(calls, 2);
}

#[test]
fn other_failures_and_successes_are_not_retried() {
    let mut calls = 0;
    let result = retry_intr(failing_once(os_error(Errno::AGAIN), &mut calls));
    assert_eq!(
        result.err().and_then(|error| error.raw_os_error()),
        Some(Errno::AGAIN.raw())
    );
    assert_eq!(calls, 1);

    let mut calls = 0;
    let result = retry_intr(|| {
        calls += 1;
        io::Result::Ok(3)
    });
    assert_eq!(result.ok(), Some(3));
    assert_eq!(calls, 1);
}

#[test]
fn a_whole_datagram_continues_the_call() {
    assert_eq!(send_step(0, 64, &Ok(64)), None);
    assert_eq!(send_step(3, 0, &Ok(0)), None);
}

#[test]
fn a_short_or_long_send_is_out_of_abi() {
    assert_eq!(
        send_step(0, 64, &Ok(63)),
        Some(SendResult::OutOfAbi { proven: 0 })
    );
    assert_eq!(
        send_step(2, 64, &Ok(0)),
        Some(SendResult::OutOfAbi { proven: 2 })
    );
    assert_eq!(
        send_step(1, 64, &Ok(65)),
        Some(SendResult::OutOfAbi { proven: 1 })
    );
}

#[test]
fn a_first_send_failure_is_the_call_error() {
    assert_eq!(
        send_step(0, 64, &Err(os_error(Errno::AGAIN))),
        Some(SendResult::Error(Errno::AGAIN))
    );
    assert_eq!(
        send_step(0, 64, &Err(os_error(Errno::MSGSIZE))),
        Some(SendResult::Error(Errno::MSGSIZE))
    );
}

#[test]
fn a_later_send_failure_reports_the_datagrams_sent() {
    assert_eq!(
        send_step(2, 64, &Err(os_error(Errno::NOBUFS))),
        Some(SendResult::Sent {
            sent: 2,
            error: Some(Errno::NOBUFS)
        })
    );
}

#[test]
fn a_send_failure_without_errno_is_out_of_abi() {
    for kind in [ErrorKind::Other, ErrorKind::InvalidInput] {
        assert_eq!(
            send_step(0, 64, &Err(io::Error::new(kind, "made up by std"))),
            Some(SendResult::OutOfAbi { proven: 0 })
        );
        assert_eq!(
            send_step(2, 64, &Err(io::Error::new(kind, "made up by std"))),
            Some(SendResult::OutOfAbi { proven: 2 })
        );
    }
}

#[test]
fn a_receive_failure_with_errno_keeps_it() {
    assert_eq!(
        recv_error(&os_error(Errno::AGAIN)),
        RecvResult::Error(Errno::AGAIN)
    );
    // `EINVAL` maps to `InvalidInput` too, but has an errno: a failure,
    // never the unsupported source drop.
    assert_eq!(
        recv_error(&os_error(Errno::INVAL)),
        RecvResult::Error(Errno::INVAL)
    );
}

#[test]
fn an_unsupported_source_is_an_empty_datagram_without_source() {
    let result = recv_error(&io::Error::new(
        ErrorKind::InvalidInput,
        "invalid socket address family",
    ));
    assert_eq!(
        result,
        RecvResult::Datagram {
            len: 0,
            truncated: None,
            source: None
        }
    );
}

#[test]
fn another_receive_failure_without_errno_is_error_zero() {
    assert_eq!(
        recv_error(&io::Error::other("made up by std")),
        RecvResult::Error(Errno::from_raw(0))
    );
}
