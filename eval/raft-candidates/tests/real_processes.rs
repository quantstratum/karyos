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
//! **The smoke runs, on every platform.** PR A's 3- and 5-process runs of
//! every variant stay, on macOS too (`*_processes_commit_and_apply_the_same_commands`):
//! the same runner on W1's case of 32 clients and 32-byte payloads, judged
//! per server only (every client finishes; every server ends up, at the
//! same last applied index with the same state digest), with no stamp
//! ordering across processes, and their run-record lines.
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

//!
//! **W2** (version 1, Environments: "W2 functionally"; C5 v2, "W2: an
//! in-flight byte case that reaches its bound"). Every case of the
//! manifest's frozen W2 (`W2::manifest().cases()`) and v2's byte case
//! (`karyos_raft_eval::v2::byte_case`), on its 3 servers, for every
//! variant (`process::w2_cases()`):
//! - each server's core takes the case's declared `limits` at its start
//!   (`ConsensusCore::recover_with`); a core that refuses them reports it,
//!   and the case is not demonstrated for it, as the simulator reports it;
//!   each server meters its log reads per duty (one loop of the server)
//!   with the harness's `ReadBudget`, as `ServerNode` does;
//! - the bursts are the clients' windows (`Case::window`): one process
//!   per client runs its window of sessions, each one request open;
//! - the paused follower is the case's own schedule, `Isolate` then
//!   `Heal` at its steps: each server drops every core datagram to and
//!   from the isolated server in that window of its own ticks, as the
//!   simulator cuts its links (the server keeps running, as it does in
//!   the simulator), and server 0 marks the heal (`Observation::Healed`);
//!   a process run refuses any other scheduled action;
//! - every run lasts its case's `steps`, whenever the clients finish, so
//!   the heal and the catch-up after it happen as in the simulator;
//! - the byte case's oracle reads the appends each server sent and the
//!   acknowledgements it stepped (`record::Item::Sent`, `Item::Acked`),
//!   from the messages themselves (`process::Wire::appended`,
//!   `acknowledged`), with `tests/w2_bytes.rs`'s own oracle
//!   (`tests/v2/oracle.rs`).
//!
//! By default `cargo test --release` runs W2's nominal case for every
//! variant; every W2 case is `#[ignore]`d for its length:
//!
//! ```text
//! cd eval/raft-candidates
//! cargo test --release --locked --test real_processes -- --ignored --nocapture w2_full
//! ```

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// One process-spawning test at a time in this test binary (as
/// karyos#1272): libtest runs tests in parallel, and a run's servers and
/// clients, up to 37 processes, each `fsync`ing its log, must not share
/// the host's disk with another run's, or every flush waits on all of
/// them. On Apple targets `StdDisk` syncs with `F_FULLFSYNC`, which
/// flushes the whole device's cache, so parallel runs there each took
/// about the node's deadline while one alone takes seconds (karyos#1272).
/// This is the one lock of every real-process run, on every platform: it
/// replaces #1272's `ONE_RUN_AT_A_TIME`. Poison-tolerant, as the
/// allocation tests' `SERIAL`: a failed run does not fail the next.
static SERIAL: Mutex<()> = Mutex::new(());

/// Takes [`SERIAL`] for the test's lifetime.
pub fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

use w1::*;

// The W2 byte case's oracle, shared with `tests/w2_bytes.rs`.
#[cfg(target_os = "linux")]
#[path = "v2/oracle.rs"]
mod oracle;

/// The runner of every multi-process run, compiled on every platform: the
/// smoke runs use it everywhere, the W1 and W2 runs, which order events
/// across processes by their stamps, on Linux only.
mod w1 {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
    // What only the Linux runs use.
    #![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

    use std::io::Read as _;
    use std::net::{TcpListener, UdpSocket};
    use std::process::{Child, Command, Stdio};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use karyos_raft_eval::process::{STOP, TICK_MS, cases, w1_cases};
    use karyos_raft_eval::record::{self, Item};
    use karyos_sim::harness::core::Limit;
    use karyos_sim::harness::node::Observation;
    use karyos_sim::harness::probe::WARMUP;
    use karyos_sim::harness::workloads::{self, Case, Failed, Liveness, Outcome, RunError};
    use karyos_sim::net::NodeId;

    use super::json_escaped;

    pub use super::serial;

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
            "{{\"evidence\":\"C5 v3 processes\",\"variant\":\"{variant}\",\
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
        let case = w1_cases().into_iter().nth(index).unwrap();
        let ran = run_case(core, index, &case);
        let outcome = ran.outcome.as_ref().unwrap();
        assert_eq!(
            workloads::pass(&case, outcome),
            Ok(None),
            "{core} {}: {} observations, {} history events; waiting clients: {:?}",
            case.name,
            outcome.observations.len(),
            outcome.history.events().len(),
            ran.stuck
        );
        // A case with more entries than the warm-up measures past it.
        let operations = case.sessions().unwrap() * case.operations;
        if u64::try_from(operations).unwrap() > 2 * WARMUP {
            assert!(
                ran.probes.iter().any(|probe| probe.entries > 0),
                "the probe measured no entry: {:?}",
                ran.probes
            );
        }
    }

    /// What a run of a case gave.
    pub struct Ran {
        /// The outcome, or why the harness could not judge it (a core
        /// that refused the case's limits: not demonstrated).
        pub outcome: Result<Outcome, RunError>,
        /// Every server's probe line.
        pub probes: Vec<Probe>,
        /// The appends the servers sent and the acknowledgements they
        /// stepped, merged by stamp (W2's byte oracle).
        pub trace: Vec<Item>,
        /// The last lines of each client process with a session that did
        /// not finish.
        pub stuck: Vec<String>,
        /// Each server's id, last applied index, state digest and whether
        /// it was up, from its own state line: no stamp ordering.
        pub states: Vec<(NodeId, Option<u64>, u64, bool)>,
        /// Client sessions whose script did not complete.
        pub waiting: usize,
    }

    /// Runs case `index` of `cases()` for variant `core` on processes, one
    /// run at a time, and writes its run-record line.
    pub fn run_case(core: &str, index: usize, case: &Case) -> Ran {
        let _serial = serial();
        for attempt in 1..=ATTEMPTS {
            match run_once(core, index, case) {
                Ok(ran) => {
                    record_line(core, case, &ran.probes);
                    return ran;
                }
                Err(stderr) if attempt < ATTEMPTS && stderr.contains("in use") => {}
                Err(stderr) => panic!("{core} {}: {stderr}", case.name),
            }
        }
        unreachable!("the last attempt returns or panics")
    }

    /// W2 case `index` of `w2_cases()` for `core` on processes: what
    /// `workloads::pass` says of it, the typed refusals it saw, and its
    /// trace; `Err` with the harness's reason when it is not demonstrated.
    pub fn w2_case(core: &str, index: usize) -> (Case, Result<W2Result, RunError>) {
        let offset = w1_cases().len();
        let case = cases().into_iter().nth(offset + index).unwrap();
        let ran = run_case(core, offset + index, &case);
        let result = ran.outcome.map(|outcome| {
            let refused = outcome
                .observations
                .iter()
                .filter_map(|observation| match observation {
                    Observation::Backpressure { limit, .. } => Some(*limit),
                    _ => None,
                })
                .collect();
            W2Result {
                safety: outcome.safety.is_ok(),
                pass: workloads::pass(&case, &outcome),
                refused,
                trace: ran.trace,
                stuck: ran.stuck,
            }
        });
        (case, result)
    }

    /// A W2 run's result.
    #[derive(Debug)]
    pub struct W2Result {
        pub safety: bool,
        pub pass: Result<Option<Liveness>, Failed>,
        pub refused: Vec<Limit>,
        pub trace: Vec<Item>,
        pub stuck: Vec<String>,
    }

    /// Every child's stderr, once each is killed and reaped: what a run
    /// that timed out says of itself (as karyos#1272).
    fn stderr_of(children: Vec<Child>, outputs: Vec<Output>) -> String {
        let mut said = Vec::new();
        for (mut child, output) in children.into_iter().zip(outputs) {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = output.stderr.join().unwrap_or_default();
            if !stderr.trim().is_empty() {
                said.push(stderr.trim().to_owned());
            }
        }
        said.join(" | ")
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
    fn run_once(core: &str, index: usize, case: &Case) -> Result<Ran, String> {
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
        let started = Instant::now();
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
        // One process per client, running its window of sessions.
        for client in 0..case.clients {
            let mut child = Command::new(env!("CARGO_BIN_EXE_raft-eval-client"))
                .arg(index.to_string())
                .arg(client.to_string())
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
        if !clients_done {
            panic!(
                "the clients did not finish: {}",
                stderr_of(std::mem::take(&mut run.children), outputs)
            );
        }
        // The run lasts its case's steps whatever the clients did, as the
        // simulator's does: a schedule's actions past the clients' end (a
        // heal, and the catch-up after it) still happen.
        let steps = Duration::from_millis(case.steps * TICK_MS);
        if let Some(left) = steps.checked_sub(started.elapsed()) {
            std::thread::sleep(left);
        }
        let stop = UdpSocket::bind("127.0.0.1:0").unwrap();
        for address in &addresses {
            stop.send_to(&[STOP], address).unwrap();
        }
        let servers_done = wait_all(
            &mut run.children[..case.servers],
            Instant::now() + Duration::from_millis(case.quiet * TICK_MS) + SLACK,
        );
        if !servers_done {
            panic!(
                "the servers did not stop: {}",
                stderr_of(std::mem::take(&mut run.children), outputs)
            );
        }
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
        let mut traces = Vec::new();
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
                    if let Some((stamp, item)) = decoded {
                        if matches!(item, Item::Sent { .. } | Item::Acked { .. }) {
                            traces.push((stamp, item));
                        } else {
                            items.push((stamp, item));
                        }
                    }
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
        let outcome = workloads::outcome(case, &recorded, liveness, up_states, deduplicated);
        // The stamp order of the trace, as the oracle reads it.
        traces.sort_by_key(|(stamp, _)| *stamp);
        let states = states
            .iter()
            .map(|state| (state.id, state.applied, state.digest, state.up))
            .collect();
        Ok(Ran {
            outcome,
            probes,
            trace: traces.into_iter().map(|(_, item)| item).collect(),
            stuck,
            states,
            waiting,
        })
    }

    /// PR A's smoke run, kept on every platform (karyos#678, karyos#690,
    /// karyos#691; macOS included, where karyos#1272's serial runs are
    /// checked): `servers` processes of `core` serve W1's case of 32
    /// clients and 32-byte payloads, and every server applies the same
    /// commands in the same order. Judged per server, never across
    /// processes by stamps: every client finishes, every server is up,
    /// and all end at the same last applied index with the same state
    /// digest (the test service's digest covers every value in the order
    /// applied); the probe measured entries past its warm-up. Its
    /// run-record line is written as every run's.
    pub fn processes_commit_and_apply_the_same_commands(core: &str, servers: usize) {
        let index = case_of(servers, 32, 32);
        let case = cases().into_iter().nth(index).unwrap();
        let ran = run_case(core, index, &case);
        assert_eq!(
            ran.waiting, 0,
            "{core} {}: clients unfinished: {:?}",
            case.name, ran.stuck
        );
        assert_eq!(ran.states.len(), servers, "{core} {}", case.name);
        let (_, applied, digest, _) = ran.states[0];
        assert!(applied.is_some(), "{core} {}: {:?}", case.name, ran.states);
        assert!(
            ran.states
                .iter()
                .all(|state| state.3 && state.1 == applied && state.2 == digest),
            "{core} {}: the servers disagree: {:?}",
            case.name,
            ran.states
        );
        assert!(
            ran.probes.iter().any(|probe| probe.entries > 0),
            "{core} {}: the probe measured no entry: {:?}",
            case.name,
            ran.probes
        );
        // The custom core's process path past the warm-up (C5 v3): what its
        // adapter pools comes back to it, so its core stages allocate and
        // free nothing, summed over the servers.
        // The shared test service, prefilled to the case's bounds,
        // allocates nothing past the warm-up whatever the core (C5 v3).
        assert_eq!(
            stage_total(&ran.probes, "apply"),
            (0, 0),
            "{core} {}: the service's application: {:?}",
            case.name,
            ran.probes
        );
        if core == "custom" {
            for stage in CUSTOM_ZERO {
                assert_eq!(
                    stage_total(&ran.probes, stage),
                    (0, 0),
                    "{core} {}: stage {stage}: {:?}",
                    case.name,
                    ran.probes
                );
            }
        }
    }

    /// The custom core's stages that count nothing past the warm-up on a
    /// process (C5 v3).
    pub const CUSTOM_ZERO: [&str; 9] = [
        "propose",
        "step_leader",
        "step_follower",
        "tick",
        "ready_leader",
        "ready_follower",
        "advance_leader",
        "advance_follower",
        "encoding",
    ];

    /// `stage`'s allocations and frees, summed over the servers.
    pub fn stage_total(probes: &[Probe], stage: &str) -> (u64, u64) {
        probes
            .iter()
            .flat_map(|probe| probe.stages.iter())
            .filter(|(name, _, _)| name == stage)
            .fold((0, 0), |(a, f), (_, more_a, more_f)| {
                (a + more_a, f + more_f)
            })
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
    let _serial = serial();
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

#[test]
fn raft_three_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("raft", 3);
}

#[test]
fn raft_five_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("raft", 5);
}

/// OpenRaft on its manually pumped executor, the same type the simulator
/// tests drive.
#[test]
fn openraft_three_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("openraft", 3);
}

#[test]
fn openraft_five_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("openraft", 5);
}

/// The custom core (ADR-0105), over the runner's own encoding.
#[test]
fn custom_three_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("custom", 3);
}

#[test]
fn custom_five_processes_commit_and_apply_the_same_commands() {
    processes_commit_and_apply_the_same_commands("custom", 5);
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
    let _serial = serial();
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
    let _serial = serial();
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

/// The byte oracle's reading of a run's trace (C5 v2, W2's byte case):
/// the most payload bytes ever unacknowledged to one follower, and the
/// largest entry payload seen in an append.
#[cfg(target_os = "linux")]
fn bytes_in_flight(trace: &[karyos_raft_eval::record::Item]) -> (u64, u64) {
    use karyos_raft_eval::record::Item;
    let mut oracle = oracle::Trace::default();
    for item in trace {
        match item {
            Item::Sent {
                leader,
                to,
                term,
                entries,
            } => oracle.sent(*leader, *to, *term, entries),
            Item::Acked {
                leader,
                from,
                term,
                index,
            } => oracle.acked(*leader, *from, *term, *index),
            _ => {}
        }
    }
    (oracle.most, oracle.largest)
}

/// Each limit refused, once, in the order first refused.
#[cfg(target_os = "linux")]
fn distinct(refused: &[karyos_sim::harness::core::Limit]) -> Vec<karyos_sim::harness::core::Limit> {
    let mut seen = Vec::new();
    for limit in refused {
        if !seen.contains(limit) {
            seen.push(*limit);
        }
    }
    seen
}

/// W2 case `index` of `w2_cases()` for `core` on 3 processes, judged as
/// the simulator's W2 tests judge it (`tests/workloads.rs`, `w2`;
/// `tests/w2_bytes.rs`), with its result as one line (`"w2"`) beside its
/// run record:
/// - safety holds in every case;
/// - only the queue burst is refused, each refusal a typed
///   `Backpressure(Queue)`; the byte case's candidates refuse every
///   command over their share, a typed `Backpressure(InFlightBytes)`, as
///   their result to report;
/// - every case passes `workloads::pass`, but a slow follower's or a
///   log-read burst's leader may commit fewer entries than the case
///   requires while the follower is cut off: the typed
///   `Failed::NotBehind` the simulator expects of OpenRaft, here of any
///   core whose real throughput falls short, reported, never a pass;
/// - the custom core's byte case keeps every follower's unacknowledged
///   payload bytes at or under 262,144 and reaches 229,376 at least once
///   (the v2 oracle, from the appends the servers sent and the
///   acknowledgements they stepped).
///
/// A core that refuses the case's limits is not demonstrated: the line
/// says so and nothing else is asserted.
#[cfg(target_os = "linux")]
fn w2_case_is_judged(core: &str, index: usize) {
    use karyos_sim::harness::core::Limit;
    use karyos_sim::harness::workloads::Failed;
    use std::io::Write as _;
    let (case, result) = w2_case(core, index);
    let summary = match &result {
        Err(error) => format!("not demonstrated: {error:?}"),
        Ok(ran) => {
            let (most, largest) = bytes_in_flight(&ran.trace);
            format!(
                "{:?}; refused {:?}; most unacked {most} B, largest entry {largest} B; sessions unfinished in {} clients",
                ran.pass,
                distinct(&ran.refused),
                ran.stuck.len()
            )
        }
    };
    let _ = writeln!(
        std::io::stdout(),
        "{{\"w2\":\"{}\",\"variant\":\"{core}\",\"result\":\"{}\"}}",
        json_escaped(&case.name),
        json_escaped(&summary)
    );
    let Ok(ran) = result else {
        return;
    };
    assert!(ran.safety, "{core} {}: {summary}", case.name);
    let bytes = case.name.starts_with("W2 v2");
    if bytes && core != "custom" {
        assert!(
            !ran.refused.is_empty()
                && ran
                    .refused
                    .iter()
                    .all(|limit| *limit == Limit::InFlightBytes),
            "{core} {}: {summary}",
            case.name
        );
        return;
    }
    if case.name.contains("burst 4x queue") {
        assert!(
            !ran.refused.is_empty() && ran.refused.iter().all(|limit| *limit == Limit::Queue),
            "{core} {}: {summary}",
            case.name
        );
    } else {
        assert!(ran.refused.is_empty(), "{core} {}: {summary}", case.name);
    }
    let short = case.name.contains("slow follower") || case.name.contains("log-read burst");
    match &ran.pass {
        Ok(None) => {}
        Err(Failed::NotBehind { .. }) if short => {}
        other => panic!("{core} {}: {other:?}; {summary}", case.name),
    }
    if bytes {
        let (most, _) = bytes_in_flight(&ran.trace);
        assert!(
            (28 * 8192..=256 * 1024).contains(&most),
            "{core} {}: {summary}",
            case.name
        );
    }
}

/// W2's nominal case on 3 processes for every variant.
#[cfg(target_os = "linux")]
#[test]
fn every_variant_passes_w2_nominal_on_three_processes() {
    for core in ["raft", "openraft", "custom"] {
        w2_case_is_judged(core, 0);
    }
}

/// Every W2 case, the manifest's and v2's byte case, on 3 processes for
/// every variant: see the module for the command.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "W2 on processes takes many minutes; run it with --ignored"]
fn w2_full() {
    for core in ["raft", "openraft", "custom"] {
        for index in 0..karyos_raft_eval::process::w2_cases().len() {
            w2_case_is_judged(core, index);
        }
    }
}
