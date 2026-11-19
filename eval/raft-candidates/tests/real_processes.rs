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

/// Distinct free loopback addresses, one per node: every socket stays
/// bound until all are chosen, so the OS cannot hand out one port twice.
fn free_addresses() -> Vec<String> {
    let sockets: Vec<UdpSocket> = (0..NODES)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    sockets
        .iter()
        .map(|socket| socket.local_addr().unwrap().to_string())
        .collect()
}

/// Attempts at the run: a port can still be taken by another process
/// between its release here and a child's bind; only that failure is
/// retried, with fresh ports (karyos#956 review).
const ATTEMPTS: usize = 3;

#[test]
fn three_processes_commit_and_apply_the_same_commands() {
    for attempt in 1..=ATTEMPTS {
        match run_once() {
            Ok(()) => return,
            Err(stderr) if attempt < ATTEMPTS && stderr.contains("in use") => {}
            Err(stderr) => panic!("{stderr}"),
        }
    }
}

/// One run; `Err` with a failed child's stderr.
fn run_once() -> Result<(), String> {
    let peers: Vec<String> = free_addresses()
        .into_iter()
        .enumerate()
        .map(|(id, address)| format!("{id}={address}"))
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
    loop {
        let statuses: Vec<_> = children
            .iter_mut()
            .map(|child| child.try_wait().unwrap())
            .collect();
        if statuses.iter().all(Option::is_some) {
            break;
        }
        // A failed child (a port taken) stalls the others: stop them.
        if statuses.iter().flatten().any(|status| !status.success()) {
            for child in &mut children {
                let _ = child.kill();
            }
            break;
        }
        if Instant::now() > deadline {
            for child in &mut children {
                let _ = child.kill();
            }
            panic!("the processes did not finish");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut reports = Vec::new();
    let mut failed = None;
    for child in children {
        let output = child.wait_with_output().unwrap();
        if output.status.success() {
            reports.push(String::from_utf8(output.stdout).unwrap().trim().to_owned());
        } else if failed.as_ref().is_none_or(String::is_empty) {
            failed = Some(String::from_utf8_lossy(&output.stderr).into_owned());
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    if let Some(stderr) = failed {
        return Err(stderr);
    }
    // Every node applied the same sequence (a repeat included); each log
    // entry once, at strictly increasing indexes, so a repeated command is
    // a retried proposal at another index, never an entry applied twice;
    // and the commands' first applications are 1..=COMMANDS in order
    // (karyos#956 review).
    assert!(
        reports.iter().all(|report| *report == reports[0]),
        "{reports:?}"
    );
    let fields: Vec<&str> = reports[0].split(' ').collect();
    assert_eq!(fields.len(), 4, "{reports:?}");
    assert_eq!(fields[0], "applied");
    assert_eq!(fields[1], COMMANDS.to_string(), "{reports:?}");
    let applied: Vec<(u64, u64)> = fields[3]
        .split(',')
        .map(|pair| {
            let (index, number) = pair.split_once(':').unwrap();
            (index.parse().unwrap(), number.parse().unwrap())
        })
        .collect();
    assert!(
        applied.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "an entry applied twice or out of order: {applied:?}"
    );
    let sequence: Vec<u64> = applied.iter().map(|(_, number)| *number).collect();
    let mut firsts = Vec::new();
    for &number in &sequence {
        if firsts.contains(&number) {
            continue;
        }
        firsts.push(number);
    }
    assert_eq!(firsts, (1..=COMMANDS).collect::<Vec<_>>(), "{sequence:?}");
    Ok(())
}
