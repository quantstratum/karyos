// SPDX-License-Identifier: Apache-2.0

//! Both adapters in real processes (plan issues 060 and 076, karyos#678
//! and karyos#690: each adapter "runs unchanged under `karyos-sim` and in
//! real processes"): three `raft-eval-node` processes, each running
//! `RaftRs` or `OpenRaft`, the very types the simulator tests drive, over C4's log on
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

fn three_processes_commit_and_apply_the_same_commands(core: &str) {
    for attempt in 1..=ATTEMPTS {
        match run_once(core) {
            Ok(()) => return,
            Err(stderr) if attempt < ATTEMPTS && stderr.contains("in use") => {}
            Err(stderr) => panic!("{stderr}"),
        }
    }
}

/// One run; `Err` with a failed child's stderr.
/// The children and their log directory, cleaned up however the run ends:
/// a panic (a timeout, a failed assertion) kills and reaps every child
/// still running and removes the logs (karyos#956 review).
struct Run {
    children: Vec<std::process::Child>,
    root: std::path::PathBuf,
}

impl Drop for Run {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run_once(core: &str) -> Result<(), String> {
    let peers: Vec<String> = free_addresses()
        .into_iter()
        .enumerate()
        .map(|(id, address)| format!("{id}={address}"))
        .collect();
    let root = std::env::temp_dir().join(format!(
        "karyos-raft-eval-{core}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let mut run = Run {
        children: Vec::new(),
        root: root.clone(),
    };
    // Each child joins the guard as it starts, so a later spawn failing
    // still stops the earlier ones.
    for id in 0..NODES {
        let child = Command::new(env!("CARGO_BIN_EXE_raft-eval-node"))
            .arg(core)
            .arg(id.to_string())
            .arg(root.join(format!("node-{id}")))
            .arg(COMMANDS.to_string())
            .args(&peers)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        run.children.push(child);
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let statuses: Vec<_> = run
            .children
            .iter_mut()
            .map(|child| child.try_wait().unwrap())
            .collect();
        if statuses.iter().all(Option::is_some) {
            break;
        }
        // A failed child (a port taken) stalls the others: stop them.
        if statuses.iter().flatten().any(|status| !status.success()) {
            for child in &mut run.children {
                let _ = child.kill();
            }
            break;
        }
        if Instant::now() > deadline {
            // The guard kills, reaps and cleans up.
            panic!("the processes did not finish");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut reports = Vec::new();
    let mut failed = None;
    for child in std::mem::take(&mut run.children) {
        let output = child.wait_with_output().unwrap();
        if output.status.success() {
            reports.push(String::from_utf8(output.stdout).unwrap().trim().to_owned());
        } else if failed.as_ref().is_none_or(String::is_empty) {
            failed = Some(String::from_utf8_lossy(&output.stderr).into_owned());
        }
    }
    drop(run);
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

/// A malformed argument is a usage error, exit 2, never a panic: a count
/// that does not parse, and on Unix an argument that is not UTF-8
/// (karyos#956 review).
#[test]
fn a_malformed_argument_is_a_usage_error() {
    let status = Command::new(env!("CARGO_BIN_EXE_raft-eval-node"))
        .args(["raft", "0", "/tmp/unused", "many"])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let status = Command::new(env!("CARGO_BIN_EXE_raft-eval-node"))
            .arg(std::ffi::OsStr::from_bytes(b"\xff"))
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(2));
    }
}

#[test]
fn raft_three_processes_commit_and_apply_the_same_commands() {
    three_processes_commit_and_apply_the_same_commands("raft");
}

/// OpenRaft on its manually pumped executor, the same `OpenRaft` type the
/// simulator tests drive: the executor runs its tasks inside the core's
/// calls, so a process needs no runtime of its own (karyos#690).
#[test]
fn openraft_three_processes_commit_and_apply_the_same_commands() {
    three_processes_commit_and_apply_the_same_commands("openraft");
}

/// The P1 of the karyos#959 review: a restarted process draws a new
/// incarnation, whatever the clock. Two processes started one after the
/// other, as a node restarted twice, never draw the same one.
#[test]
fn every_process_draws_its_own_incarnation() {
    let draw = || {
        let output = Command::new(env!("CARGO_BIN_EXE_raft-eval-node"))
            .arg("incarnation")
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap()
    };
    let draws: std::collections::BTreeSet<u64> = (0..3).map(|_| draw()).collect();
    assert_eq!(draws.len(), 3);
}
