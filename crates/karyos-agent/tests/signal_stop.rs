// SPDX-License-Identifier: Apache-2.0

//! The `karyos-agent` binary's stop on a signal (Linux; owner item 55,
//! karyos#710): `SIGTERM` writes the durable `agent stopped` record and
//! the next start records no unknown interval; a stop past its deadline
//! and a second signal exit unclean, and the next start records the
//! unclean stop. A stop whose durable record fails is the journal's
//! `a_failed_journal_cannot_stop_cleanly` unit test, and the binary maps
//! that error to exit status 1.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use karyos_agent::journal::{GapReason, Journal};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-signal-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("driver")).unwrap();
    dir
}

/// The agent binary on `dir`'s journal, stopping within `stop_timeout_ms`.
fn spawn_agent(dir: &Path, stop_timeout_ms: u64) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_karyos-agent"))
        .arg("--api-dir")
        .arg(dir.join("api"))
        .arg("--driver")
        .arg(dir.join("driver"))
        .arg("--journal")
        .arg(dir.join("journal"))
        .arg("--role")
        .arg(format!("{}=viewer", karyos_sys::ipc::own_uid()))
        .arg("--refresh-ms")
        .arg("10")
        .arg("--stop-timeout-ms")
        .arg(stop_timeout_ms.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Serving once its socket exists: the journal is open and the signal
    // flags registered before the bind.
    let start = Instant::now();
    while !dir.join("api").join("agent.sock").exists() {
        assert!(start.elapsed() < Duration::from_secs(30), "never served");
        std::thread::sleep(Duration::from_millis(5));
    }
    child
}

fn signal(child: &Child, name: &str) {
    let sent = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(sent.success());
}

fn wait(child: &mut Child) -> ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            panic!("the agent did not exit");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn reopened_gap(dir: &Path) -> Option<GapReason> {
    Journal::open(&dir.join("journal"), u64::MAX / 2)
        .unwrap()
        .gap()
        .map(|gap| gap.reason)
}

/// `SIGTERM` (and `SIGINT`) stop the agent cleanly: exit 0, and the next
/// start finds `agent stopped` last, so no unknown interval.
#[test]
fn a_signal_stops_the_agent_cleanly() {
    for name in ["TERM", "INT"] {
        let dir = dir(&format!("clean-{name}"));
        let mut agent = spawn_agent(&dir, 5_000);
        signal(&agent, name);
        let status = wait(&mut agent);
        assert_eq!(status.code(), Some(0), "SIG{name}");
        assert_eq!(reopened_gap(&dir), None, "SIG{name}");
    }
}

/// A stop past its deadline (here a zero one) exits with status 3 and
/// leaves the run unclean: the next start records the unclean stop.
#[test]
fn a_stop_past_its_deadline_stays_unclean() {
    let dir = dir("deadline");
    let mut agent = spawn_agent(&dir, 0);
    signal(&agent, "TERM");
    let status = wait(&mut agent);
    assert_eq!(status.code(), Some(3));
    assert_eq!(reopened_gap(&dir), Some(GapReason::UncleanStop));
}
