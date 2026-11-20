// SPDX-License-Identifier: Apache-2.0

//! A child process's lifecycle calls that `std` does not offer (Linux;
//! karyos#1017), behind the crate's syscall boundary: reading a child's
//! exit without reaping it, killing its process group while it is
//! unreaped, and reading its output without blocking.
//!
//! A child that is not reaped keeps its pid and so its process group id:
//! a group signalled before the leader is reaped can never be another,
//! reused group.

use std::io;
use std::os::fd::AsFd;
use std::process::Child;
use std::time::Duration;

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};

/// Whether `child` has exited, and successfully, read without reaping it
/// (`waitid` with `WNOWAIT`): `None` while it runs. A failed call reads
/// as a failed exit.
#[must_use]
pub fn exited_unreaped(child: &Child) -> Option<bool> {
    let pid = Pid::from_child(child);
    match waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(Some(status)) => Some(status.exited() && status.exit_status() == Some(0)),
        Ok(None) => None,
        Err(_) => Some(false),
    }
}

/// Sends `SIGKILL` to the process group `child` leads (a child started
/// with `process_group(0)`). Call it before `child` is reaped.
///
/// # Errors
///
/// The operating system's error, as `ESRCH` when no process of the group
/// remains.
pub fn kill_group(child: &Child) -> io::Result<()> {
    kill_process_group(Pid::from_child(child), Signal::KILL).map_err(io::Error::from)
}

/// Sets `fd` non-blocking.
///
/// # Errors
///
/// The operating system's error.
pub fn set_nonblocking(fd: impl AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(())
}

/// Waits at most `timeout` (below one second) for `fd` to be readable or
/// closed.
pub fn wait_readable(fd: impl AsFd, timeout: Duration) {
    let mut fds = [rustix::event::PollFd::new(
        &fd,
        rustix::event::PollFlags::IN,
    )];
    let tick = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: timeout.subsec_nanos().into(),
    };
    let _ = rustix::event::poll(&mut fds, Some(&tick));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use std::process::{Command, Stdio};

    use super::*;

    /// The exit reads the same twice, then `wait` still reaps it.
    #[test]
    fn an_exit_is_read_without_reaping() {
        let mut child = Command::new("true").stdout(Stdio::null()).spawn().unwrap();
        let start = std::time::Instant::now();
        let mut seen = None;
        while seen.is_none() && start.elapsed() < Duration::from_secs(10) {
            seen = exited_unreaped(&child);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(seen, Some(true));
        assert_eq!(exited_unreaped(&child), Some(true));
        assert!(child.wait().unwrap().success());
    }

    /// A group is killed while its leader is unreaped.
    #[test]
    fn a_group_is_killed_before_its_leader_is_reaped() {
        let mut command = Command::new("sleep");
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut child = command.arg("30").spawn().unwrap();
        kill_group(&child).unwrap();
        assert!(!child.wait().unwrap().success());
    }
}
