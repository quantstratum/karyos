// SPDX-License-Identifier: Apache-2.0

//! The `raft` adapter in real processes (plan issue 060, karyos#678: the
//! same adapter "runs unchanged under `karyos-sim` and in real
//! processes"): three `raft-eval-node` processes, each running
//! `RaftRs`, the very type the simulator tests drive, over C4's log on
//! real files and UDP on the loopback, elect a leader, commit its
//! commands, and all apply the same commands in the same order.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const NODES: u32 = 3;
const COMMANDS: u64 = 20;

/// A free loopback port: bound, read, released.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn three_processes_commit_and_apply_the_same_commands() {
    let peers: Vec<String> = (0..NODES)
        .map(|id| format!("{id}=127.0.0.1:{}", free_port()))
        .collect();
    let root = std::env::temp_dir().join(format!(
        "karyos-raft-eval-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let mut children: Vec<_> = (0..NODES)
        .map(|id| {
            Command::new(env!("CARGO_BIN_EXE_raft-eval-node"))
                .arg(id.to_string())
                .arg(root.join(format!("node-{id}")))
                .arg(COMMANDS.to_string())
                .args(&peers)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(60);
    while children
        .iter_mut()
        .any(|child| child.try_wait().unwrap().is_none())
    {
        if Instant::now() > deadline {
            for child in &mut children {
                let _ = child.kill();
            }
            panic!("the processes did not finish");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let reports: Vec<String> = children
        .into_iter()
        .map(|child| {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        })
        .collect();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        reports[0].starts_with(&format!("applied {COMMANDS} ")),
        "{reports:?}"
    );
    assert!(
        reports.iter().all(|report| *report == reports[0]),
        "{reports:?}"
    );
}
