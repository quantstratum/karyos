// SPDX-License-Identifier: Apache-2.0

//! The frozen W1 workload on real processes, for every variant (plan
//! issues 060 and 076, karyos#678 and karyos#690: each adapter "runs
//! unchanged under `karyos-sim` and in real processes"; quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v1.md, Environments: "W1 and W2
//! functionally, and the allocation gate on real processes"; C5 v2,
//! "Processes", karyos#691).
//!
//! Each run takes one case of the harness's frozen W1
//! (`process::w1_cases()`, `W1::skeleton().cases()`) and starts its
//! servers, 3 or 5 `raft-eval-node` processes of one variant (`raft`:
//! `RaftRsBatch16`; `openraft`: `OpenRaftBatch16`; `custom`: the custom
//! core, `harness::custom::Custom`), the very types the simulator tests
//! drive, over C4's log on real files, and one `raft-eval-client` process
//! per client session, running the harness's `ClientNode` on the case's
//! script and retry delay. Every value of the run is the case's: its
//! servers, sessions, operations, payload, `retry_after`, `steps` (each
//! client's budget, in ticks of [`TICK_MS`]) and `quiet`. Once every
//! client has exited, the test stops the servers; each serves the case's
//! quiet period, then reports.
//!
//! **The checks are the simulator's.** The servers' and clients'
//! stamped observations and the clients' histories are merged in the
//! order of their stamps (`record::merge`) into the harness's `Recorder`;
//! the servers' last applied index, state digest and deduplicated count,
//! and the clients that did not finish, make the liveness and the states
//! as `workloads::run` takes them; `workloads::outcome` runs the
//! simulator's safety checks over them, the linearizability check of the
//! clients' history included; and `workloads::pass` judges the outcome
//! as it judges a simulated run: every check holds, every client
//! finishes, the servers that applied the most agree, and their state is
//! the one the linearized history builds.
//!
//! **The clock is the precondition.** The merge orders events of
//! different processes by their stamps, so every process reads the same
//! `CLOCK_MONOTONIC` of the same host (`record::CLOCK`, named in each run
//! record line as `clock`). `karyos_sys::host_clock` reads it on Linux
//! only; elsewhere each process has its own origin, so these runs are
//! compiled for Linux only.
//!
//! **Timing.** One core tick is [`TICK_MS`] (10 ms) of process time,
//! version 1's frozen tick: each adapter's heartbeat and election
//! timeouts, in ticks, are that many 10 ms on a process, and so are the
//! case's ticks.
//!
//! **The run record.** Each run writes one line to stdout for the C5 v2
//! run record (quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v2-run-record.md): the variant,
//! the processes, the commit, the tick, the encoding, the host, the
//! warm-up, the case, the clock, and the allocation probe's counts in
//! total and per stage, summed over the servers, with `entries` the most
//! any server committed past the warm-up while it led (each leader
//! reports its own highest commit index, so the maximum, as the
//! simulator's probe takes it across leaders, counts every entry once;
//! Codex review of #1256). The counts are the gate's evidence, not
//! asserted here (the gate is the report's to score). These are
//! functional runs on one host (version 1, Environments): five processes
//! on it are not five failure domains, and nothing here is a performance
//! result.
//!
//! **Buffer recycling on this path** (C5 v2, "Buffer recycling"), for
//! the run record:
//! - The runner reuses its receive buffer, its outbox and its `ReadyBuf`
//!   between loops. Each message's encoding, its datagrams (a 13-byte
//!   header and the body, cut into fragments of at most `MAX_DATAGRAM`)
//!   and the frees of both and of the message after the send are counted
//!   as the `encoding` stage, as is each decoding (a fragmented message's
//!   reassembly included); a decoded message is freed inside the core's
//!   `step`. The test service's application of each committed entry
//!   (`TestService::apply`, the harness's own) is counted as the `apply`
//!   stage: its register and deduplication table grow by each entry.
//! - `raft` (raft-rs 0.7.0): recycles nothing; raft-rs's messages and
//!   entries are owned `protobuf` values, and their encoding
//!   (`protobuf` 2.28.0) builds a new vector per message.
//! - `openraft` (0.10.0-alpha.37): recycles nothing; its encoding
//!   (`openraft_wire`) builds a new vector per message.
//! - `custom`: the adapter's own pool, one per thread, prefilled at
//!   initialisation, as in the simulator (`harness::custom`); its
//!   encoding (`custom_wire`) builds a new vector per message, and its
//!   decoding a new entry vector and payload per append.
//!
//! **What runs by default.** `cargo test --release` runs, for every
//! variant, W1's primary operating point (3 servers, 256-byte payloads,
//! 32 clients, at the batch limit of 16) and the same case on 5 servers.
//! The full W1 matrix, every case on 3 and 5 servers for every variant, is
//! `#[ignore]`d for its length:
//!
//! ```text
//! cd eval/raft-candidates
//! cargo test --release --locked --test real_processes -- --ignored --nocapture w1_full_matrix
//! ```

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
use w1::*;

#[cfg(target_os = "linux")]
mod w1 {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use std::io::Read as _;
    use std::net::{TcpListener, UdpSocket};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use karyos_raft_eval::process::{STOP, TICK_MS, w1_cases};
    use karyos_raft_eval::record::{self, Item};
    use karyos_sim::harness::probe::WARMUP;
    use karyos_sim::harness::workloads::{self, Case, Liveness};
    use karyos_sim::net::NodeId;

    use super::json_escaped;

    /// One run at a time: a run's 37 processes at most share the host
    /// with no other run's.
    static SERIAL: Mutex<()> = Mutex::new(());

    pub fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Distinct free loopback addresses, one per server, each free for UDP
    /// (between servers) and TCP (from clients) on the same port: every
    /// socket stays bound until all are chosen, so the OS cannot hand out
    /// one port twice.
    fn free_addresses(nodes: usize) -> Vec<String> {
        let mut held = Vec::new();
        while held.len() < nodes {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = udp.local_addr().unwrap();
            if let Ok(tcp) = TcpListener::bind(address) {
                held.push((udp, tcp, address.to_string()));
            }
        }
        held.into_iter().map(|(_, _, address)| address).collect()
    }

    /// Attempts at the run: a port can still be taken by another process
    /// between its release here and a child's bind; only that failure is
    /// retried, with fresh ports (karyos#956 review).
    const ATTEMPTS: usize = 3;

    /// How long the test waits past the clients' own budget, and for the
    /// servers' quiet period, before it calls the run hung.
    const SLACK: Duration = Duration::from_secs(60);

    /// The children and their log directory, cleaned up however the run
    /// ends: a panic (a timeout, a failed assertion) kills and reaps every
    /// child still running and removes the logs (karyos#956 review).
    struct Run {
        children: Vec<Child>,
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

    /// A child's output, read as it comes so that no pipe fills.
    struct Output {
        stdout: JoinHandle<String>,
        stderr: JoinHandle<String>,
    }

    fn drain(child: &mut Child) -> Output {
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        Output {
            stdout: std::thread::spawn(move || {
                let mut text = String::new();
                let _ = stdout.read_to_string(&mut text);
                text
            }),
            stderr: std::thread::spawn(move || {
                let mut text = String::new();
                let _ = stderr.read_to_string(&mut text);
                text
            }),
        }
    }

    /// One server's probe line: entries, allocations, frees, and the
    /// stages by name with their allocations and frees.
    #[derive(Debug, Default)]
    pub struct Probe {
        entries: u64,
        allocations: u64,
        frees: u64,
        stages: Vec<(String, u64, u64)>,
    }

    fn probe_of(line: &str) -> Probe {
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 6, "{line}");
        assert_eq!(fields[0], "probe", "{line}");
        assert_eq!(fields[1], WARMUP.to_string(), "the warm-up: {line}");
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

    /// A server's state line: its id, last applied index, digest,
    /// deduplicated count, and whether it led and was up.
    struct State {
        id: NodeId,
        applied: Option<u64>,
        digest: u64,
        deduplicated: u64,
        leads: bool,
        up: bool,
    }

    fn state_of(line: &str) -> State {
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 7, "{line}");
        assert_eq!(fields[0], "state", "{line}");
        State {
            id: fields[1].parse().unwrap(),
            applied: (fields[2] != "-").then(|| fields[2].parse().unwrap()),
            digest: fields[3].parse().unwrap(),
            deduplicated: fields[4].parse().unwrap(),
            leads: fields[5] == "1",
            up: fields[6] == "1",
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
    /// servers; `entries` the most any leader measured past the warm-up.
    fn record_line(core: &str, case: &Case, probes: &[Probe]) {
        use std::io::Write as _;
        let entries: u64 = probes.iter().map(|probe| probe.entries).max().unwrap_or(0);
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
             \"processes\":{},\"commit\":\"{commit}\",\"tick_ms\":{TICK_MS},\
             \"encoding\":\"{encoding}\",\"host\":\"{host}\",\"warmup\":{WARMUP},\
             \"entries\":{entries},\"allocations\":{allocations},\"frees\":{frees},\
             \"stages\":{{{}}},\"case\":\"{}\",\"batch_entries\":16,\"clock\":\"{}\"}}",
            case.servers,
            stages.join(","),
            json_escaped(&case.name),
            json_escaped(record::CLOCK),
        );
    }

    /// Runs W1 case `index` of variant `core` on processes and passes it
    /// through the simulator's pass conditions.
    pub fn w1_case_passes(core: &str, index: usize) {
        let _serial = serial();
        let case = w1_cases().into_iter().nth(index).unwrap();
        for attempt in 1..=ATTEMPTS {
            match run_once(core, index, &case) {
                Ok(probes) => {
                    record_line(core, &case, &probes);
                    return;
                }
                Err(stderr) if attempt < ATTEMPTS && stderr.contains("in use") => {}
                Err(stderr) => panic!("{core} {}: {stderr}", case.name),
            }
        }
    }

    /// Waits for every child of `children`; `false` past `deadline`.
    fn wait_all(children: &mut [Child], deadline: Instant) -> bool {
        loop {
            if children
                .iter_mut()
                .all(|child| child.try_wait().unwrap().is_some())
            {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// One run; `Err` with a failed child's stderr.
    fn run_once(core: &str, index: usize, case: &Case) -> Result<Vec<Probe>, String> {
        let addresses = free_addresses(case.servers);
        let peers: Vec<String> = addresses
            .iter()
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
        let mut outputs = Vec::new();
        for id in 0..case.servers {
            let mut child = Command::new(env!("CARGO_BIN_EXE_raft-eval-node"))
                .arg(core)
                .arg(id.to_string())
                .arg(root.join(format!("node-{id}")))
                .arg(index.to_string())
                .args(&peers)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            outputs.push(drain(&mut child));
            run.children.push(child);
        }
        let sessions = case.sessions().unwrap();
        for session in 0..sessions {
            let mut child = Command::new(env!("CARGO_BIN_EXE_raft-eval-client"))
                .arg(index.to_string())
                .arg(session.to_string())
                .args(&peers)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            outputs.push(drain(&mut child));
            run.children.push(child);
        }
        let budget = Duration::from_millis(case.steps * TICK_MS) + SLACK;
        let clients_done = {
            let (_, clients) = run.children.split_at_mut(case.servers);
            wait_all(clients, Instant::now() + budget)
        };
        // A server that failed (a port taken) leaves the clients waiting:
        // its error is reported below either way.
        assert!(clients_done, "the clients did not finish");
        let stop = UdpSocket::bind("127.0.0.1:0").unwrap();
        for address in &addresses {
            stop.send_to(&[STOP], address).unwrap();
        }
        let servers_done = wait_all(
            &mut run.children[..case.servers],
            Instant::now() + Duration::from_millis(case.quiet * TICK_MS) + SLACK,
        );
        assert!(servers_done, "the servers did not stop");
        let mut failed = None;
        let mut texts = Vec::new();
        for (child, output) in std::mem::take(&mut run.children).into_iter().zip(outputs) {
            let mut child = child;
            let status = child.wait().unwrap();
            let stdout = output.stdout.join().unwrap();
            let stderr = output.stderr.join().unwrap();
            if !status.success() && failed.as_ref().is_none_or(String::is_empty) {
                failed = Some(stderr);
            }
            texts.push(stdout);
        }
        drop(run);
        if let Some(stderr) = failed {
            return Err(stderr);
        }
        let mut processes = Vec::new();
        let mut probes = Vec::new();
        let mut states = Vec::new();
        let mut waiting = 0usize;
        let mut stuck: Vec<String> = Vec::new();
        for text in &texts {
            let mut items: Vec<(u64, Item)> = Vec::new();
            for line in text.lines() {
                if line.starts_with("probe ") {
                    probes.push(probe_of(line));
                } else if line.starts_with("state ") {
                    states.push(state_of(line));
                } else if let Some(client) = line.strip_prefix("client ") {
                    let (_, done) = client.split_once(' ').unwrap();
                    if done != "1" {
                        waiting += 1;
                        let lines: Vec<&str> = text.lines().collect();
                        let tail = lines.len().saturating_sub(6);
                        stuck.push(lines[tail..].join(" | "));
                    }
                } else {
                    let decoded = record::decode(line);
                    assert!(decoded.is_some(), "a line that is no record: {line}");
                    items.extend(decoded);
                }
            }
            processes.push(items);
        }
        assert_eq!(probes.len(), case.servers);
        assert_eq!(states.len(), case.servers);
        let recorded = record::merge(processes);
        // As `workloads::run` takes them: the servers that are up.
        let up: Vec<&State> = states.iter().filter(|state| state.up).collect();
        let liveness = if waiting == 0 {
            Ok(())
        } else if !up.iter().any(|state| state.leads) {
            Err(Liveness::NoLeader)
        } else {
            Err(Liveness::Stalled { waiting })
        };
        let deduplicated = up.iter().map(|state| state.deduplicated).sum();
        let up_states = up
            .iter()
            .map(|state| (state.id, state.applied, state.digest))
            .collect();
        let outcome =
            workloads::outcome(case, &recorded, liveness, up_states, deduplicated).unwrap();
        assert_eq!(
            workloads::pass(case, &outcome),
            Ok(None),
            "{core} {}: {} observations, {} history events; waiting clients: {stuck:?}",
            case.name,
            outcome.observations.len(),
            outcome.history.events().len()
        );
        // A case with more entries than the warm-up measures past it.
        let operations = sessions * case.operations;
        if u64::try_from(operations).unwrap() > 2 * WARMUP {
            assert!(
                probes.iter().any(|probe| probe.entries > 0),
                "the probe measured no entry: {probes:?}"
            );
        }
        Ok(probes)
    }

    /// The index of the W1 case of `servers`, `payload` and `clients`.
    pub fn case_of(servers: usize, payload: usize, clients: usize) -> usize {
        w1_cases()
            .iter()
            .position(|case| {
                case.servers == servers && case.payload == payload && case.clients == clients
            })
            .unwrap()
    }
}

/// `text` as the inside of a JSON string: quotes, backslashes and control
/// characters escaped, so a run's line is always one parseable line
/// (Codex review of #1256).
pub fn json_escaped(text: &str) -> String {
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

/// The run record's strings are escaped: a quote, a backslash and a
/// control character cannot break its line (Codex review of #1256).
#[test]
fn the_run_record_escapes_its_strings() {
    assert_eq!(json_escaped("plain-host"), "plain-host");
    assert_eq!(json_escaped("a\"b\\c\nd\u{1}"), "a\\\"b\\\\c\\nd\\u0001");
}

/// A malformed argument is a usage error, exit 2, never a panic: a case
/// that does not parse or is not one, a client session past the case's,
/// and on Unix an argument that is not UTF-8 (karyos#956 review).
#[test]
fn a_malformed_argument_is_a_usage_error() {
    for args in [
        &["raft", "0", "/tmp/unused", "many"][..],
        &["raft", "0", "/tmp/unused", "999"][..],
    ] {
        let status = Command::new(env!("CARGO_BIN_EXE_raft-eval-node"))
            .args(args)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(2), "{args:?}");
    }
    for args in [
        &["many", "0", "0=127.0.0.1:7000"][..],
        &["0", "1", "0=127.0.0.1:7000"][..],
        &["0", "0"][..],
        &["0", "0", "0=192.0.2.1:7000"][..],
    ] {
        let status = Command::new(env!("CARGO_BIN_EXE_raft-eval-client"))
            .args(args)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(2), "{args:?}");
    }
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

/// W1's primary operating point (version 1: 3 servers, 256-byte payloads,
/// 32 clients, batch 16) and the same case on 5 servers, for `core`.
#[cfg(target_os = "linux")]
fn w1_operating_point_passes(core: &str) {
    for servers in [3, 5] {
        w1_case_passes(core, case_of(servers, 256, 32));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn raft_passes_w1_on_three_and_five_processes() {
    w1_operating_point_passes("raft");
}

/// OpenRaft on its manually pumped executor, the same type the simulator
/// tests drive: the executor runs its tasks inside the core's calls, so a
/// process needs no runtime of its own (karyos#690).
#[cfg(target_os = "linux")]
#[test]
fn openraft_passes_w1_on_three_and_five_processes() {
    w1_operating_point_passes("openraft");
}

/// The custom core (ADR-0105), the `Custom` adapter the simulator drives,
/// over the runner's own encoding (`custom_wire`).
#[cfg(target_os = "linux")]
#[test]
fn custom_passes_w1_on_three_and_five_processes() {
    w1_operating_point_passes("custom");
}

/// Every W1 case, on 3 and 5 servers, for every variant: see the module
/// for the command.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "the full W1 matrix on processes takes minutes; run it with --ignored"]
fn w1_full_matrix() {
    for core in ["raft", "openraft", "custom"] {
        for index in 0..karyos_raft_eval::process::w1_cases().len() {
            w1_case_passes(core, index);
        }
    }
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
