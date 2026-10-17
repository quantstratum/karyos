// SPDX-License-Identifier: Apache-2.0

//! The bound of a retried interrupted call (SPEC.md §14, bounded loops).
//! A blocking socket call that a signal interrupts (`EINTR`) is called
//! again only while the socket's own timeout has not passed since the
//! first attempt; past it, the caller reports what the kernel reports for
//! that timeout. Kept free of system calls so it is tested on every
//! platform.

use core::time::Duration;

/// Whether a call interrupted `elapsed` after its first attempt may be
/// called again, given the socket's timeout: only while `elapsed` is below
/// it. Without a timeout (`None`) the call would block without bound
/// anyway, so it is always called again.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the IPC sockets that use it are Linux only")
)]
pub(crate) fn retry_interrupted_within(elapsed: Duration, timeout: Option<Duration>) -> bool {
    timeout.is_none_or(|timeout| elapsed < timeout)
}

#[cfg(test)]
mod tests {
    use super::retry_interrupted_within;
    use core::time::Duration;

    #[test]
    fn an_interrupted_call_is_retried_only_within_its_timeout() {
        let timeout = Some(Duration::from_millis(100));
        assert!(retry_interrupted_within(Duration::from_millis(99), timeout));
        assert!(!retry_interrupted_within(
            Duration::from_millis(100),
            timeout
        ));
        assert!(!retry_interrupted_within(
            Duration::from_millis(101),
            timeout
        ));
        assert!(retry_interrupted_within(Duration::ZERO, timeout));
    }

    #[test]
    fn an_interrupted_call_without_a_timeout_is_always_retried() {
        assert!(retry_interrupted_within(Duration::ZERO, None));
        assert!(retry_interrupted_within(Duration::MAX, None));
    }
}
