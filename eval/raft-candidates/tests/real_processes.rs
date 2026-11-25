// SPDX-License-Identifier: Apache-2.0

//! Every variant in real processes (plan issues 060 and 076, karyos#678
//! and karyos#690: each adapter "runs unchanged under `karyos-sim` and in
//! real processes"; C5 v2, "Processes", karyos#691): three and five
//! `raft-eval-node` processes, each running `RaftRs`, `OpenRaft` or the
//! custom core (`harness::custom::Custom`), the very types the simulator
//! tests drive, over C4's log on real files and UDP on the loopback,
//! elect a leader, commit its commands, and all apply the same commands
//! in the same order.
//!
//! Each node's core is wrapped in the allocation probe
//! (`harness::probe::Probed`), with the encoding and decoding of its
//! messages counted as the `encoding` stage, and each run writes one line
//! to stdout for the C5 v2 run record (quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v2-run-record.md): the variant,
//! the processes, the commit, the tick, the encoding, the host, and the
//! counts in total and per stage, summed over the nodes, with `entries`
//! the most any node committed past the warm-up while it led: each leader
//! reports its own highest commit index, so the maximum, as the
//! simulator's probe takes it across leaders, counts every entry once
//! (Codex review of #1256). The test asserts
//! that the run applies every command and that the probe measured
//! entries; the counts are the gate's evidence, not asserted here (the
//! gate is the report's to score). These are functional runs on one host
//! (version 1, Environments): five processes on it are not five failure
//! domains, and nothing here is a performance result.
//!
//! **Buffer recycling on this path** (C5 v2, "Buffer recycling"), for
//! the run record:
//! - The runner reuses its receive buffer and its outbox between loops.
//!   Each message's encoding, its datagram (the 4-byte sender header and
//!   the body, in a new vector) and the frees of both and of the message
//!   after the send are counted as the `encoding` stage, as is each
//!   decoding; a decoded message is freed inside the core's `step`.
//! - `raft` (raft-rs 0.7.0): recycles nothing; raft-rs's messages and
//!   entries are owned `protobuf` values, and their encoding
//!   (`protobuf` 2.28.0) builds a new vector per message.
//! - `openraft` (0.10.0-alpha.37): recycles nothing; its encoding
//!   (`openraft_wire`) builds a new vector per message.
//! - `custom`: the adapter's own pool, one per thread, prefilled at
//!   initialisation, as in the simulator (`harness::custom`); its
//!   encoding (`custom_wire`) builds a new vector per message, and its
//!   decoding a new entry vector and payload per append.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Commands per run: past the probe's warm-up of 16, so it measures.
const COMMANDS: u64 = 64;

/// Distinct free loopback addresses, one per node: every socket stays
/// bound until all are chosen, so the OS cannot hand out one port twice.
fn free_addresses(nodes: u32) -> Vec<String> {
    let sockets: Vec<UdpSocket> = (0..nodes)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    sockets
        .iter()
        .map(|socket| socket.local_addr().unwrap().to_string())
        .collect()
}

/// One real-process run at a time. Each node makes every vote and append
/// durable before it answers, and on Apple targets `StdDisk` syncs with
/// `F_FULLFSYNC`, which flushes the whole device's cache: libtest's
/// parallel runs (six at once, 24 processes) then wait on one another's
/// flushes, and every run takes about the node's 60 s deadline (they all
/// apply their commands, at that pace) while each run alone takes
/// seconds. Serialised here, on every platform, so the runs are the
/// functional checks they are meant to be, not a measure of the host's
/// flush contention.
static ONE_RUN_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// How long the test waits for its processes: past the nodes' own 60 s
/// deadline (`raft-eval-node`), so a node that gives up reports its own
/// error instead of the test's timeout.
const WAIT: Duration = Duration::from_secs(75);

/// Attempts at the run: a port can still be taken by another process
/// between its release here and a child's bind; only that failure is
/// retried, with fresh ports (karyos#956 review).
const ATTEMPTS: usize = 3;

fn processes_commit_and_apply_the_same_commands(core: &str, nodes: u32) {
    // A failed run's panic poisons the lock; the next run still goes.
    let _serial = ONE_RUN_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for attempt in 1..=ATTEMPTS {
        match run_once(core, nodes) {
            Ok(probes) => {
                record(core, nodes, &probes);
                return;
            }
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

/// A log directory of this run's own: created here, so it did not exist
/// before and no other run or file is taken over by the guard's cleanup
/// (karyos#956 review: a name built from the clock alone could collide).
fn reserve_root(core: &str) -> std::path::PathBuf {
    let mut attempt = 0u64;
    loop {
        let root = std::env::temp_dir().join(format!(
            "karyos-raft-eval-{core}-{}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&root) {
            Ok(()) => return root,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt += 1;
            }
            Err(error) => panic!("{}: {error}", root.display()),
        }
    }
}

/// One node's probe line: entries, allocations, frees, and the stages by
/// name with their allocations and frees.
#[derive(Debug, Default)]
struct Probe {
    entries: u64,
    allocations: u64,
    frees: u64,
    stages: Vec<(String, u64, u64)>,
}

fn probe_of(line: &str) -> Probe {
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields.len(), 6, "{line}");
    assert_eq!(fields[0], "probe", "{line}");
    assert_eq!(fields[1], "16", "the warm-up: {line}");
    let stages = fields[5]
        .split(',')
        .map(|stage| {
            let (name, counts) = stage.split_once('=').unwrap();
            let (allocations, frees) = counts.split_once(':').unwrap();
            (
                name.to_owned(),
                allocations.parse().unwrap(),
                frees.parse().unwrap(),
            )
        })
        .collect();
    Probe {
        entries: fields[2].parse().unwrap(),
        allocations: fields[3].parse().unwrap(),
        frees: fields[4].parse().unwrap(),
        stages,
    }
}

/// The variant, its revision and its encoding, as the run record names
/// them.
fn variant(core: &str) -> (&'static str, &'static str) {
    match core {
        "raft" => ("raft 0.7.0, baseline", "protobuf 2.28.0 (raft-proto)"),
        "openraft" => (
            "openraft 0.10.0-alpha.37, baseline",
            "openraft_wire (eval/raft-candidates)",
        ),
        "custom" => (
            "custom core (karyos_cluster::consensus)",
            "custom_wire (eval/raft-candidates)",
        ),
        _ => panic!("{core}"),
    }
}

/// `text` as the inside of a JSON string: quotes, backslashes and control
/// characters escaped, so a run's line is always one parseable line
/// (Codex review of #1256).
fn json_escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out
}

/// The output of `program args`, trimmed; `unknown` when it cannot run.
fn output_of(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |text| text.trim().to_owned())
}

/// The run's line for the C5 v2 run record, on stdout, summed over the
/// nodes; the probe measured entries past the warm-up on the leaders.
fn record(core: &str, nodes: u32, probes: &[Probe]) {
    use std::io::Write as _;
    let entries: u64 = probes.iter().map(|probe| probe.entries).max().unwrap_or(0);
    assert!(entries > 0, "the probe measured no entry: {probes:?}");
    let allocations: u64 = probes.iter().map(|probe| probe.allocations).sum();
    let frees: u64 = probes.iter().map(|probe| probe.frees).sum();
    let stages: Vec<String> = probes[0]
        .stages
        .iter()
        .map(|(name, _, _)| {
            let (allocated, freed) = probes.iter().fold((0u64, 0u64), |(a, f), probe| {
                let (_, more_a, more_f) = probe
                    .stages
                    .iter()
                    .find(|(other, _, _)| other == name)
                    .unwrap();
                (a + more_a, f + more_f)
            });
            format!("\"{name}\":[{allocated},{freed}]")
        })
        .collect();
    let (variant, encoding) = variant(core);
    let commit = json_escaped(
        &std::env::var("KARYOS_COMMIT")
            .unwrap_or_else(|_| output_of("git", &["rev-parse", "HEAD"])),
    );
    let host = json_escaped(&output_of("uname", &["-n"]));
    let _ = writeln!(
        std::io::stdout(),
        "{{\"evidence\":\"C5 v2 processes\",\"variant\":\"{variant}\",\
         \"processes\":{nodes},\"commit\":\"{commit}\",\"tick_ms\":{},\
         \"encoding\":\"{encoding}\",\"host\":\"{host}\",\"warmup\":16,\
         \"entries\":{entries},\"allocations\":{allocations},\"frees\":{frees},\
         \"stages\":{{{}}}}}",
        karyos_raft_eval::process::TICK_MS,
        stages.join(","),
    );
}

fn run_once(core: &str, nodes: u32) -> Result<Vec<Probe>, String> {
    let peers: Vec<String> = free_addresses(nodes)
        .into_iter()
        .enumerate()
        .map(|(id, address)| format!("{id}={address}"))
        .collect();
    let root = reserve_root(core);
    let mut run = Run {
        children: Vec::new(),
        root: root.clone(),
    };
    // Each child joins the guard as it starts, so a later spawn failing
    // still stops the earlier ones.
    for id in 0..nodes {
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
    let deadline = Instant::now() + WAIT;
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
            // Each node's stderr says where it stood; the guard reaps the
            // rest and cleans up.
            let stderr: Vec<String> = std::mem::take(&mut run.children)
                .into_iter()
                .map(|mut child| {
                    let _ = child.kill();
                    child.wait_with_output().map_or_else(
                        |error| error.to_string(),
                        |output| String::from_utf8_lossy(&output.stderr).into_owned(),
                    )
                })
                .collect();
            panic!("the processes did not finish: {stderr:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut reports = Vec::new();
    let mut probes = Vec::new();
    let mut failed = None;
    for child in std::mem::take(&mut run.children) {
        let output = child.wait_with_output().unwrap();
        if output.status.success() {
            let stdout = String::from_utf8(output.stdout).unwrap();
            // Exactly its two lines: anything else on a node's stdout (a
            // stray print in a core or adapter) is a failure, not noise
            // to skip (the debug prints left in harness::custom).
            let lines: Vec<&str> = stdout.trim().lines().collect();
            assert_eq!(lines.len(), 2, "a node's stdout: {stdout}");
            reports.push(lines[0].to_owned());
            probes.push(probe_of(lines[1]));
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
    Ok(probes)
}

/// The run record's strings are escaped: a quote, a backslash and a
/// control character cannot break its line (Codex review of #1256).
#[test]
fn the_run_record_escapes_its_strings() {
    assert_eq!(json_escaped("plain-host"), "plain-host");
    assert_eq!(json_escaped("a\"b\\c\nd\u{1}"), "a\\\"b\\\\c\\nd\\u0001");
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
    processes_commit_and_apply_the_same_commands("raft", 3);
}

#[test]
fn raft_five_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("raft", 5);
}

/// OpenRaft on its manually pumped executor, the same `OpenRaft` type the
/// simulator tests drive: the executor runs its tasks inside the core's
/// calls, so a process needs no runtime of its own (karyos#690).
#[test]
fn openraft_three_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("openraft", 3);
}

#[test]
fn openraft_five_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("openraft", 5);
}

/// The custom core (ADR-0105), the `Custom` adapter the simulator drives,
/// over the runner's own encoding (`custom_wire`).
#[test]
fn custom_three_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("custom", 3);
}

#[test]
fn custom_five_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("custom", 5);
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

/// The karyos#956 review: a peer off the loopback is refused before any
/// socket is bound, a usage the runner does not support.
#[test]
fn a_peer_off_the_loopback_is_refused() {
    let output = Command::new(env!("CARGO_BIN_EXE_raft-eval-node"))
        .args(["raft", "0", "/tmp/unused", "1", "0=192.0.2.1:7000"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not a loopback address"),
        "{output:?}"
    );
}
