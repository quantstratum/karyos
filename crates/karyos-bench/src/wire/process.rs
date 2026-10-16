// SPDX-License-Identifier: Apache-2.0

//! The wire roles in their own processes
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.3): the
//! bench binary runs itself again once per role, with [`ROLE`] and
//! [`RUN`] in the environment, as the IPC workloads do (`ipc.rs`). Each
//! child times only its own stage and writes its own sample file in the
//! format of `samples.rs`.
//!
//! The receive child starts first and prints `WIRE_READY <data> <control>`:
//! the address of its endpoint and of a plain UDP control socket. The send
//! child says hello to the control socket, so the receiver learns where to
//! answer, and runs. Control traffic is outside both timed stages, and
//! every control datagram carries the run's nonce ([`NONCE`]); one with
//! another nonce is ignored. A control datagram can be lost, so every one
//! that matters is repeated:
//!
//! - the sender repeats its hello until it hears from the receiver, which
//!   answers each hello with its acknowledgement count;
//! - the receiver acknowledges the messages completed so far (R1) and,
//!   when it stops for any reason, tells the sender, three times;
//! - the parent tells the receiver at every poll, once the send child has
//!   exited however it ended, so the receiver drains and ends.
//!
//! The parent bounds the whole run by a deadline and kills both children
//! when it passes, or when the sender outlives a receiver that finished.
//! A child exits on its own when its standard input closes, so a parent
//! that dies leaves no orphan.
//!
//! **Pinning.** With [`Cores`], each child starts under `taskset -c` on
//! its own core and reads its affinity back (`Cpus_allowed_list` of
//! `/proc/self/status`) into its sidecar. A result is functional only
//! (E4) unless both read-backs show the requested core and this host is
//! decision eligible (`env::decision_eligible`: E1 to E3 on its declared
//! host); every reason is recorded (coordinator decision, ACS 15273).

use std::cell::Cell;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use karyos_protocol::protection::Trusted;

use crate::env;
use crate::inventory::{Inventory, Scope, parse_cpu_list};
use crate::manifest::{ExtBase, Fanout, Load, MtuRule, Point, Shape};
use crate::samples::{self, Header, RunSamples, SATURATED, Stage};
use crate::wire::stage::{
    ACK_TIMEOUT, Prepared, ReceiveControl, SendControl, StageLoad, StageRun, StageSamples, Wait,
    receive_deadline, receive_role, send_role,
};
use crate::workloads::{self, BenchError};

/// The role of a wire child: `rx` or `tx`.
pub const ROLE: &str = "KARYOS_BENCH_WIRE_ROLE";

/// The run of a wire child, as [`encode_run`] writes it.
pub const RUN: &str = "KARYOS_BENCH_WIRE_RUN";

/// The sample file a wire child writes.
pub const OUT: &str = "KARYOS_BENCH_WIRE_OUT";

/// The send child's peers: `<data> <control>` of the receiver.
pub const PEER: &str = "KARYOS_BENCH_WIRE_PEER";

/// The run's nonce, in decimal, carried by every control datagram.
pub const NONCE: &str = "KARYOS_BENCH_WIRE_NONCE";

/// The run index at its point, written into the sample headers.
pub const INDEX: &str = "KARYOS_BENCH_WIRE_INDEX";

/// Injected faults, as [`Faults::encode`] writes them; honoured only by
/// a build with the feature `test-hooks` (see [`FAULTS_ENABLED`]).
pub const FAULTS: &str = "KARYOS_BENCH_WIRE_FAULTS";

/// Whether this build accepts injected faults: only with the feature
/// `test-hooks`, which only dev-dependencies enable. Any other build
/// refuses [`FAULTS`] and non-default [`Faults`] (coordinator, ACS 15309).
pub const FAULTS_ENABLED: bool = cfg!(any(test, feature = "test-hooks"));

/// Whether [`FAULTS`] is set in this process's environment.
#[must_use]
pub fn faults_requested() -> bool {
    std::env::var_os(FAULTS).is_some()
}

/// Refuses injected faults in a build that does not accept them.
fn faults_allowed(faults: &Faults) -> Result<(), BenchError> {
    if *faults != Faults::default() && !FAULTS_ENABLED {
        return Err(BenchError(
            "injected faults need the feature test-hooks; a measurement build refuses them".into(),
        ));
    }
    Ok(())
}

/// The test that runs a wire child in a test binary.
pub const CHILD_TEST: &str = "wire_child";

/// The exit code of a child whose parent has gone.
pub const ORPHANED: i32 = 70;

/// The line the receive child prints when it is ready.
const READY: &str = "WIRE_READY";

/// How long the parent waits for the receive child to be ready.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the parent checks its children and repeats its news.
const CHILD_POLL: Duration = Duration::from_millis(10);

/// How often the sender repeats its hello until it hears back.
const HELLO_EVERY: Duration = Duration::from_millis(10);

/// The margin of the run deadline over the receive deadline.
const RUN_MARGIN: Duration = Duration::from_secs(30);

/// How long the sender may outlive a receiver that finished.
const OUTLIVE: Duration = Duration::from_secs(2);

/// How many times the receiver says it has stopped.
const STOP_REPEATS: usize = 3;

/// Control datagrams: a tag byte, the run's nonce and a value, both
/// little-endian `u64`.
const CONTROL_LEN: usize = 17;

/// Send child to receiver: where to send acknowledgements.
const HELLO: u8 = b'H';

/// Parent to receiver: the send child has exited.
const DONE: u8 = b'D';

/// Receiver to send child: messages completed so far.
const ACK: u8 = b'A';

/// Receiver to send child: the receiver has stopped.
const STOP: u8 = b'S';

fn error(what: &str, cause: impl std::fmt::Display) -> BenchError {
    BenchError(format!("{what}: {cause}"))
}

fn control(tag: u8, nonce: u64, value: u64) -> [u8; CONTROL_LEN] {
    let mut bytes = [tag; CONTROL_LEN];
    if let Some(field) = bytes.get_mut(1..9) {
        field.copy_from_slice(&nonce.to_le_bytes());
    }
    if let Some(field) = bytes.get_mut(9..) {
        field.copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// The tag and value of a control datagram of run `nonce`; `None` for a
/// malformed datagram or another run's.
fn parse_control(bytes: &[u8], nonce: u64) -> Option<(u8, u64)> {
    let (&tag, rest) = bytes.split_first()?;
    let (theirs, value) = rest.split_at_checked(8)?;
    (u64::from_le_bytes(theirs.try_into().ok()?) == nonce)
        .then_some(())
        .and(Some((tag, u64::from_le_bytes(value.try_into().ok()?))))
}

/// Faults a test injects into a run; none by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Faults {
    /// Hellos the sender drops before sending one.
    pub drop_hellos: u32,
    /// Done notices the parent drops before sending one.
    pub drop_dones: u32,
    /// The receiver never says it has stopped.
    pub no_stop: bool,
    /// The receive child exits with failure, without any notice, once
    /// this many messages completed.
    pub rx_crash_at: Option<u64>,
    /// The receive role's deadline in milliseconds, in place of
    /// [`receive_deadline`]: the receiver then ends normally while the
    /// sender still runs.
    pub rx_deadline_ms: Option<u64>,
    /// The send child exits with failure waiting for this message.
    pub tx_crash_at: Option<u64>,
    /// The sender stops responding waiting for this message.
    pub tx_freeze_at: Option<u64>,
}

impl Faults {
    /// The text form: `key=value` pairs joined by `,`.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut parts = Vec::new();
        if self.drop_hellos > 0 {
            parts.push(format!("drop_hellos={}", self.drop_hellos));
        }
        if self.drop_dones > 0 {
            parts.push(format!("drop_dones={}", self.drop_dones));
        }
        if self.no_stop {
            parts.push("no_stop=1".to_string());
        }
        for (key, value) in [
            ("rx_crash_at", self.rx_crash_at),
            ("rx_deadline_ms", self.rx_deadline_ms),
            ("tx_crash_at", self.tx_crash_at),
            ("tx_freeze_at", self.tx_freeze_at),
        ] {
            if let Some(value) = value {
                parts.push(format!("{key}={value}"));
            }
        }
        parts.join(",")
    }

    /// The inverse of [`Self::encode`].
    ///
    /// # Errors
    ///
    /// An unknown key or a malformed value.
    pub fn decode(text: &str) -> Result<Self, BenchError> {
        let mut faults = Self::default();
        for part in text.split(',').filter(|part| !part.is_empty()) {
            let bad = || BenchError(format!("bad fault {part}"));
            let (key, value) = part.split_once('=').ok_or_else(bad)?;
            let number = value.parse::<u64>().map_err(|_| bad())?;
            match key {
                "drop_hellos" => faults.drop_hellos = u32::try_from(number).map_err(|_| bad())?,
                "drop_dones" => faults.drop_dones = u32::try_from(number).map_err(|_| bad())?,
                "no_stop" => faults.no_stop = number == 1,
                "rx_crash_at" => faults.rx_crash_at = Some(number),
                "rx_deadline_ms" => faults.rx_deadline_ms = Some(number),
                "tx_crash_at" => faults.tx_crash_at = Some(number),
                "tx_freeze_at" => faults.tx_freeze_at = Some(number),
                _ => return Err(bad()),
            }
        }
        Ok(faults)
    }
}

/// The cores of the two roles, one each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cores {
    /// The receive child's core.
    pub receiver: usize,
    /// The send child's core.
    pub sender: usize,
}

impl Cores {
    /// The first two cores of `inventory` that are both isolated and in
    /// `nohz_full`; `None` with fewer.
    #[must_use]
    pub fn of(inventory: &Inventory) -> Option<Self> {
        let nohz = inventory.nohz_full_cores();
        let mut quiet = inventory
            .isolated_cores()
            .into_iter()
            .filter(|core| nohz.contains(core));
        Some(Self {
            receiver: quiet.next()?,
            sender: quiet.next()?,
        })
    }

    /// This host's cores, when it has two and `taskset` runs; otherwise
    /// why not.
    ///
    /// # Errors
    ///
    /// Fewer than two quiet cores, or no `taskset`.
    pub fn detect() -> Result<Self, String> {
        let cores = Self::of(&Inventory::detect(Scope::Classification))
            .ok_or_else(|| "fewer than two isolated nohz_full cores".to_string())?;
        env::command("taskset", &["--version"])
            .map(|_| cores)
            .ok_or_else(|| "taskset unavailable".to_string())
    }
}

/// This process's CPU affinity, read back from the kernel.
///
/// # Errors
///
/// Off Linux, or an unreadable `/proc/self/status`.
pub fn affinity() -> Result<Vec<usize>, String> {
    if !cfg!(target_os = "linux") {
        return Err(format!("unavailable on {}", std::env::consts::OS));
    }
    let status = std::fs::read_to_string("/proc/self/status").map_err(|cause| cause.to_string())?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(parse_cpu_list)
        .ok_or_else(|| "no Cpus_allowed_list".to_string())
}

/// The sidecar line of [`affinity`].
fn affinity_line() -> String {
    match affinity() {
        Ok(cores) => format!(
            "affinity {}\n",
            cores
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Err(reason) => format!("affinity unavailable ({reason})\n"),
    }
}

/// Why `role`'s read-back affinity `line` does not show `core` pinned.
fn pin_reason(role: &str, line: &str, core: Option<usize>) -> Option<String> {
    let Some(core) = core else {
        return Some(format!("{role} not pinned"));
    };
    let expected = core.to_string();
    (line != expected).then(|| format!("{role} affinity {line}, expected {expected}"))
}

/// How the parent runs one pair of processes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessOptions {
    /// The run index at its point, written into the sample headers.
    pub run_index: u32,
    /// Each child's core; unpinned without.
    pub cores: Option<Cores>,
    /// The run deadline; by default [`receive_deadline`] plus 30 s.
    pub deadline: Option<Duration>,
    /// Injected faults; tests only.
    pub faults: Faults,
}

/// The text form of a shape: its display name.
fn parse_shape(text: &str) -> Option<Shape> {
    Some(match text {
        "W1" => Shape::W1,
        "W2" => Shape::W2,
        "W3" => Shape::W3,
        "W4" => Shape::W4,
        "W5" => Shape::W5,
        "W6" => Shape::W6,
        "W7" => Shape::W7,
        "W9-W1" => Shape::W9(ExtBase::W1),
        "W9-W4" => Shape::W9(ExtBase::W4),
        _ => return None,
    })
}

/// `shape,e_max,rule,load,messages,warmup`: the rule is `counts` or
/// `excludes`, the load `closed` or `open:<rate>`.
#[must_use]
pub fn encode_run(run: &StageRun) -> String {
    let rule = match run.rule {
        MtuRule::CountsEnvelope => "counts",
        MtuRule::ExcludesEnvelope => "excludes",
    };
    let load = match run.load {
        StageLoad::Closed => "closed".to_string(),
        StageLoad::Open { rate } => format!("open:{rate}"),
    };
    format!(
        "{},{},{rule},{load},{},{}",
        run.shape, run.e_max, run.messages, run.warmup
    )
}

/// The inverse of [`encode_run`].
///
/// # Errors
///
/// A malformed run.
pub fn decode_run(text: &str) -> Result<StageRun, BenchError> {
    let bad = || BenchError(format!("bad wire run {text}"));
    let mut parts = text.split(',');
    let mut next = || parts.next().ok_or_else(bad);
    let shape = parse_shape(next()?).ok_or_else(bad)?;
    let e_max = next()?.parse().map_err(|_| bad())?;
    let rule = match next()? {
        "counts" => MtuRule::CountsEnvelope,
        "excludes" => MtuRule::ExcludesEnvelope,
        _ => return Err(bad()),
    };
    let load = match next()? {
        "closed" => StageLoad::Closed,
        open => StageLoad::Open {
            rate: open
                .strip_prefix("open:")
                .and_then(|rate| rate.parse().ok())
                .filter(|rate| *rate > 0)
                .ok_or_else(bad)?,
        },
    };
    let messages = next()?.parse().map_err(|_| bad())?;
    let warmup = next()?.parse().map_err(|_| bad())?;
    if parts.next().is_some() {
        return Err(bad());
    }
    Ok(StageRun {
        shape,
        e_max,
        rule,
        load,
        messages,
        warmup,
    })
}

/// The manifest point of a run.
fn point(run: &StageRun) -> Result<Point, BenchError> {
    Ok(Point {
        shape: run.shape,
        load: match run.load {
            StageLoad::Closed => Load::R1,
            StageLoad::Open { rate } => Load::R2 {
                rate: u32::try_from(rate)
                    .map_err(|_| BenchError(format!("R2 rate {rate} outside the manifest")))?,
            },
        },
        fanout: Fanout::F1,
    })
}

/// A wire child's environment: its run, sample file, run index, nonce
/// and faults.
struct ChildContext {
    run: StageRun,
    out: PathBuf,
    index: u32,
    nonce: u64,
    faults: Faults,
}

fn variable(name: &str) -> Result<String, BenchError> {
    std::env::var(name).map_err(|cause| error(name, cause))
}

impl ChildContext {
    fn from_env() -> Result<Self, BenchError> {
        Ok(Self {
            run: decode_run(&variable(RUN)?)?,
            out: PathBuf::from(variable(OUT)?),
            index: variable(INDEX)?
                .parse()
                .map_err(|cause| error(INDEX, cause))?,
            nonce: variable(NONCE)?
                .parse()
                .map_err(|cause| error(NONCE, cause))?,
            faults: {
                let faults = Faults::decode(&std::env::var(FAULTS).unwrap_or_default())?;
                faults_allowed(&faults)?;
                faults
            },
        })
    }

    /// Writes `data` with a header: the measured clock resolution
    /// (design §2), the run index from the parent, and seed 0, since a
    /// wire run draws no random number.
    fn write_samples(&self, path: &Path, stage: Stage, data: Vec<u32>) -> Result<(), BenchError> {
        let saturated = data.iter().filter(|sample| **sample == SATURATED).count();
        let header = Header {
            point: point(&self.run)?,
            profile: "trusted".to_string(),
            stage,
            run: self.index,
            seed: 0,
            clock_resolution_ns: u32::try_from(workloads::resolution())
                .map_err(|cause| error("clock resolution", cause))?,
            warmup: self.run.warmup,
            saturated: u64::try_from(saturated).map_err(|cause| error("saturated", cause))?,
        };
        samples::write_file(
            path,
            &RunSamples {
                header,
                samples: data,
            },
        )
        .map_err(|cause| error("sample file", cause))
    }
}

fn join(values: &[u32]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Runs the wire child part when [`ROLE`] is set: `None` otherwise.
#[must_use]
pub fn child() -> Option<Result<(), BenchError>> {
    let role = std::env::var(ROLE).ok()?;
    // The parent holds this child's standard input open while it lives.
    std::thread::spawn(|| {
        let mut buffer = [0_u8; 64];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) | Err(_) => std::process::exit(ORPHANED),
                Ok(_) => {}
            }
        }
    });
    Some(run_child(&role))
}

fn run_child(role: &str) -> Result<(), BenchError> {
    let context = ChildContext::from_env()?;
    let prepared = Prepared::new(&context.run, &Trusted)?;
    match role {
        "rx" => receive_child(&context, &prepared),
        "tx" => send_child(&context, &prepared),
        other => Err(BenchError(format!("no wire role {other}"))),
    }
}

/// The receiver's control socket. Dropping it, on any exit including a
/// panic, tells the send child that the receiver has stopped.
struct ReceiverControl {
    socket: UdpSocket,
    nonce: u64,
    peer: Cell<Option<SocketAddr>>,
    done: Cell<bool>,
    completed: Cell<u64>,
    no_stop: bool,
}

impl ReceiverControl {
    /// Reads every pending control datagram of this run; answers each
    /// hello with the acknowledgement count.
    fn pump(&self) {
        let mut buffer = [0_u8; CONTROL_LEN];
        while let Ok((length, from)) = self.socket.recv_from(&mut buffer) {
            match buffer
                .get(..length)
                .and_then(|bytes| parse_control(bytes, self.nonce))
            {
                Some((HELLO, _)) => {
                    self.peer.set(Some(from));
                    self.send(ACK, self.completed.get());
                }
                Some((DONE, _)) => self.done.set(true),
                _ => {}
            }
        }
    }

    fn send(&self, tag: u8, value: u64) {
        if let Some(to) = self.peer.get() {
            let _ = self.socket.send_to(&control(tag, self.nonce, value), to);
        }
    }

    fn ack(&self, count: u64) {
        self.completed.set(count);
        if self.peer.get().is_none() {
            self.pump();
        }
        self.send(ACK, count);
    }
}

impl Drop for ReceiverControl {
    fn drop(&mut self) {
        if self.no_stop {
            return;
        }
        if self.peer.get().is_none() {
            self.pump();
        }
        for _ in 0..STOP_REPEATS {
            self.send(STOP, 0);
        }
    }
}

fn receive_child(context: &ChildContext, prepared: &Prepared) -> Result<(), BenchError> {
    let run = &context.run;
    let endpoint = prepared.endpoint()?;
    let local = endpoint.capabilities().local;
    let (_tx, mut rx) = endpoint
        .split()
        .map_err(|_| BenchError("split receiver".into()))?;
    let socket =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|cause| error("control", cause))?;
    socket
        .set_nonblocking(true)
        .map_err(|cause| error("control", cause))?;
    let control_address = socket
        .local_addr()
        .map_err(|cause| error("control", cause))?;
    let control = ReceiverControl {
        socket,
        nonce: context.nonce,
        peer: Cell::new(None),
        done: Cell::new(false),
        completed: Cell::new(0),
        no_stop: context.faults.no_stop,
    };
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{READY} {local} {control_address}")
            .map_err(|cause| error("ready", cause))?;
        stdout.flush().map_err(|cause| error("ready", cause))?;
    }
    let faults = context.faults;
    let received = receive_role(
        run,
        prepared,
        &Trusted,
        &mut rx,
        local,
        &ReceiveControl {
            finished: &|| {
                control.pump();
                control.done.get()
            },
            ack: &|count| {
                if faults.rx_crash_at.is_some_and(|at| count >= at) {
                    // An injected crash (tests only): no destructor runs.
                    std::process::exit(1);
                }
                control.ack(count);
            },
            deadline: match faults.rx_deadline_ms {
                Some(millis) => Duration::from_millis(millis),
                None => receive_deadline(run)?,
            },
        },
    )?;
    context.write_samples(
        &context.out,
        Stage::Receive { receiver: 0 },
        received.receive,
    )?;
    std::fs::write(
        context.out.with_extension("rx"),
        format!(
            "{}drops {}\nbatches {}\ncallback {}\n",
            affinity_line(),
            received.drops,
            join(&received.batches),
            join(&received.receive_callback)
        ),
    )
    .map_err(|cause| error("rx sidecar", cause))
}

/// The send child's control socket, connected to the receiver's.
struct SenderControl {
    socket: UdpSocket,
    nonce: u64,
    completed: Cell<u64>,
    stopped: Cell<bool>,
    /// Whether any datagram of the receiver has arrived.
    heard: Cell<bool>,
    last_hello: Cell<Option<Instant>>,
    hellos_to_drop: Cell<u32>,
}

impl SenderControl {
    fn hello(&self) {
        self.last_hello.set(Some(Instant::now()));
        match self.hellos_to_drop.get().checked_sub(1) {
            Some(left) => self.hellos_to_drop.set(left),
            None => {
                let _ = self.socket.send(&control(HELLO, self.nonce, 0));
            }
        }
    }

    /// Repeats the hello until the receiver is heard, then reads every
    /// pending control datagram of this run; an error other than an empty
    /// socket means the receiver is gone.
    fn pump(&self) {
        if !self.heard.get()
            && self
                .last_hello
                .get()
                .is_none_or(|at| at.elapsed() >= HELLO_EVERY)
        {
            self.hello();
        }
        let mut buffer = [0_u8; CONTROL_LEN];
        loop {
            match self.socket.recv(&mut buffer) {
                Ok(length) => match buffer
                    .get(..length)
                    .and_then(|bytes| parse_control(bytes, self.nonce))
                {
                    Some((ACK, count)) => {
                        self.heard.set(true);
                        self.completed.set(self.completed.get().max(count));
                    }
                    Some((STOP, _)) => {
                        self.heard.set(true);
                        self.stopped.set(true);
                    }
                    _ => {}
                },
                Err(cause) if cause.kind() == ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.stopped.set(true);
                    return;
                }
            }
        }
    }

    fn wait(&self, sequence: u64) -> Wait {
        let start = Instant::now();
        loop {
            self.pump();
            if self.completed.get() > sequence {
                return Wait::Completed;
            }
            if self.stopped.get() {
                return Wait::Stopped;
            }
            if start.elapsed() >= ACK_TIMEOUT {
                return Wait::TimedOut;
            }
            std::thread::yield_now();
        }
    }

    fn stopped(&self) -> bool {
        self.pump();
        self.stopped.get()
    }
}

fn send_child(context: &ChildContext, prepared: &Prepared) -> Result<(), BenchError> {
    let peers = variable(PEER)?;
    let mut parts = peers.split_whitespace();
    let (Some(data), Some(control_peer), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(BenchError(format!("bad peers {peers}")));
    };
    let data: SocketAddr = data.parse().map_err(|cause| error("peer", cause))?;
    let control_peer: SocketAddr = control_peer
        .parse()
        .map_err(|cause| error("control peer", cause))?;
    let socket =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|cause| error("control", cause))?;
    socket
        .connect(control_peer)
        .map_err(|cause| error("control", cause))?;
    socket
        .set_nonblocking(true)
        .map_err(|cause| error("control", cause))?;
    let control = SenderControl {
        socket,
        nonce: context.nonce,
        completed: Cell::new(0),
        stopped: Cell::new(false),
        heard: Cell::new(false),
        last_hello: Cell::new(None),
        hellos_to_drop: Cell::new(context.faults.drop_hellos),
    };
    control.hello();
    let (mut tx, _rx) = prepared
        .endpoint()?
        .split()
        .map_err(|_| BenchError("split sender".into()))?;
    let faults = context.faults;
    let sent = send_role(
        &context.run,
        prepared,
        &Trusted,
        &mut tx,
        data,
        &SendControl {
            wait: &|sequence| {
                if faults.tx_crash_at.is_some_and(|at| sequence >= at) {
                    std::process::exit(1);
                }
                if faults.tx_freeze_at.is_some_and(|at| sequence >= at) {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                control.wait(sequence)
            },
            stopped: &|| control.stopped(),
        },
    )?;
    context.write_samples(&context.out, Stage::Send, sent.send)?;
    std::fs::write(
        context.out.with_extension("tx"),
        format!(
            "{}backpressure {}\nack_timeouts {}\n",
            affinity_line(),
            sent.backpressure,
            sent.ack_timeouts
        ),
    )
    .map_err(|cause| error("tx sidecar", cause))
}

/// Kills and reaps a child on drop, by its own handle.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

/// The parent's view of one run's children.
struct Spawn<'a> {
    run: &'a StageRun,
    nonce: u64,
    options: &'a ProcessOptions,
}

impl Spawn<'_> {
    fn child(
        &self,
        role: &str,
        out: &Path,
        peer: Option<&str>,
        core: Option<usize>,
    ) -> Result<Guard, BenchError> {
        let executable = std::env::current_exe().map_err(|cause| error("executable", cause))?;
        // `taskset` execs the child in place: the guard's PID stays the
        // child's.
        let mut command = match core {
            Some(core) => {
                let mut taskset = Command::new("taskset");
                taskset.arg("-c").arg(core.to_string()).arg(executable);
                taskset
            }
            None => Command::new(executable),
        };
        command
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads", "1"])
            .env(ROLE, role)
            .env(RUN, encode_run(self.run))
            .env(OUT, out)
            .env(NONCE, self.nonce.to_string())
            .env(INDEX, self.options.run_index.to_string())
            // Held open by the parent: its end tells the child to exit.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(peer) = peer {
            command.env(PEER, peer);
        }
        if self.options.faults == Faults::default() {
            command.env_remove(FAULTS);
        } else {
            command.env(FAULTS, self.options.faults.encode());
        }
        command
            .spawn()
            .map(Guard)
            .map_err(|cause| error("wire child", cause))
    }
}

fn check(status: ExitStatus, role: &str) -> Result<(), BenchError> {
    if status.success() {
        Ok(())
    } else {
        Err(BenchError(format!("{role} child failed: {status}")))
    }
}

/// The values of exactly the lines `keys` of a sidecar, in that order:
/// every line is `<key> <value>`; an unknown, repeated or missing key is
/// an error.
fn sidecar<'a>(text: &'a str, keys: &[&str]) -> Result<Vec<&'a str>, BenchError> {
    let mut values: Vec<Option<&str>> = vec![None; keys.len()];
    for line in text.lines() {
        let (key, value) = line
            .split_once(' ')
            .ok_or_else(|| BenchError(format!("bad sidecar line {line}")))?;
        let slot = keys
            .iter()
            .position(|known| *known == key)
            .and_then(|index| values.get_mut(index))
            .ok_or_else(|| BenchError(format!("unknown sidecar key {key}")))?;
        if slot.replace(value).is_some() {
            return Err(BenchError(format!("repeated sidecar key {key}")));
        }
    }
    keys.iter()
        .zip(values)
        .map(|(key, value)| value.ok_or_else(|| BenchError(format!("sidecar without {key}"))))
        .collect()
}

/// A comma-separated list of numbers; empty for an empty text, an error
/// for an empty item.
fn numbers(text: &str) -> Result<Vec<u32>, BenchError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|value| value.parse().map_err(|cause| error("sidecar value", cause)))
        .collect()
}

/// Checks that `samples` belong to `run`'s `stage` and hold `expected`.
fn check_samples(
    samples: &RunSamples,
    run: &StageRun,
    stage: Stage,
    index: u32,
    expected: usize,
) -> Result<(), BenchError> {
    let header = &samples.header;
    if header.point != point(run)? || header.stage != stage || header.run != index {
        return Err(BenchError(format!(
            "sample header {} {:?} run {} does not match the run",
            header.point, header.stage, header.run
        )));
    }
    if samples.samples.len() != expected {
        return Err(BenchError(format!(
            "{:?}: {} samples, {expected} expected",
            stage,
            samples.samples.len()
        )));
    }
    Ok(())
}

/// Why a result is functional only: `pinning`, the reasons the children
/// are not verified on their cores, then every condition
/// `env::decision_eligible` finds unmet (E1 to E3 on the declared host).
/// Empty only for a decision-eligible result.
#[must_use]
pub fn functional_reasons(pinning: Vec<String>) -> Vec<String> {
    let inventory = Inventory::detect(Scope::Classification);
    let record = env::host_record(&inventory.host);
    let mut reasons = pinning;
    if let Err(ineligible) = env::decision_eligible(&inventory, record.as_deref(), Fanout::F1) {
        reasons.extend(ineligible.iter().map(ToString::to_string));
    }
    reasons
}

/// A nonce for one run: the clock, the process and a counter mixed.
fn nonce() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::from(now.subsec_nanos())
        ^ now.as_secs().rotate_left(32)
        ^ u64::from(std::process::id()).rotate_left(16)
        ^ COUNTER.fetch_add(1, Ordering::Relaxed).rotate_left(48)
}

/// Runs one wire run with each role in its own process, writing the
/// sample files into `dir` (`send.samples`, `receive.samples`).
///
/// # Errors
///
/// A child that fails, never gets ready, outlives the deadline or the
/// receiver, or writes samples that do not match the run.
pub fn run_processes(
    run: &StageRun,
    dir: &Path,
    options: &ProcessOptions,
) -> Result<StageSamples, BenchError> {
    faults_allowed(&options.faults)?;
    let prepared = Prepared::new(run, &Trusted)?;
    let expected =
        usize::try_from(run.messages).map_err(|_| BenchError("too many messages".into()))?;
    let budget = match options.deadline {
        Some(deadline) => deadline,
        None => receive_deadline(run)?
            .checked_add(RUN_MARGIN)
            .ok_or_else(|| BenchError("run deadline overflow".into()))?,
    };
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| BenchError("run deadline overflow".into()))?;
    std::fs::create_dir_all(dir).map_err(|cause| error("sample directory", cause))?;
    let send_out = dir.join("send.samples");
    let receive_out = dir.join("receive.samples");
    let spawn = Spawn {
        run,
        nonce: nonce(),
        options,
    };
    let mut receiver = spawn.child("rx", &receive_out, None, options.cores.map(|c| c.receiver))?;
    let stdout = receiver
        .0
        .stdout
        .take()
        .ok_or_else(|| BenchError("the receive child has no output".into()))?;
    let (sender, ready) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Read to the end: closing the pipe early would fail the child's
        // later output.
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(at) = line.find(READY) {
                let _ = sender.send(line.get(at..).unwrap_or_default().to_string());
            }
        }
    });
    let line = ready
        .recv_timeout(READY_TIMEOUT.min(deadline.saturating_duration_since(Instant::now())))
        .map_err(|_| BenchError("the receive child never got ready".into()))?;
    let peers = line
        .strip_prefix(READY)
        .map(str::trim)
        .ok_or_else(|| BenchError(format!("bad ready line {line}")))?
        .to_string();
    let mut addresses = peers
        .split_whitespace()
        .map(|address| address.parse::<SocketAddr>().ok());
    let (Some(Some(receiver_address)), Some(Some(control_address)), None) =
        (addresses.next(), addresses.next(), addresses.next())
    else {
        return Err(BenchError(format!("bad ready line {line}")));
    };
    let mut sender_child = spawn.child(
        "tx",
        &send_out,
        Some(&peers),
        options.cores.map(|c| c.sender),
    )?;
    let parent =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|cause| error("control", cause))?;
    let mut dones_to_drop = options.faults.drop_dones;
    let mut sent: Option<ExitStatus> = None;
    let mut received: Option<ExitStatus> = None;
    let mut receiver_ended: Option<Instant> = None;
    // Both children are polled until both have exited. On any early
    // return, the guards kill and reap what is still running.
    while sent.is_none() || received.is_none() {
        if sent.is_none() {
            sent = sender_child
                .0
                .try_wait()
                .map_err(|cause| error("tx", cause))?;
        }
        if received.is_none() {
            received = receiver.0.try_wait().map_err(|cause| error("rx", cause))?;
        }
        if let Some(status) = received {
            // A receiver that failed ends the run at once.
            check(status, "rx")?;
            let ended = *receiver_ended.get_or_insert_with(Instant::now);
            if sent.is_none() && ended.elapsed() >= OUTLIVE {
                return Err(BenchError(format!(
                    "the sender outlived the receiver by {OUTLIVE:?}"
                )));
            }
        }
        if sent.is_some() && received.is_none() {
            // Repeated until the receiver exits: one notice can be lost.
            match dones_to_drop.checked_sub(1) {
                Some(left) => dones_to_drop = left,
                None => {
                    let _ = parent.send_to(&control(DONE, spawn.nonce, 0), control_address);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(BenchError(format!("the run deadline of {budget:?} passed")));
        }
        std::thread::sleep(CHILD_POLL);
    }
    if let Some(status) = sent {
        check(status, "tx")?;
    }
    let send = samples::read_file(&send_out).map_err(|cause| error("send samples", cause))?;
    let receive =
        samples::read_file(&receive_out).map_err(|cause| error("receive samples", cause))?;
    check_samples(&send, run, Stage::Send, options.run_index, expected)?;
    check_samples(
        &receive,
        run,
        Stage::Receive { receiver: 0 },
        options.run_index,
        expected,
    )?;
    let rx = std::fs::read_to_string(receive_out.with_extension("rx"))
        .map_err(|cause| error("rx sidecar", cause))?;
    let tx = std::fs::read_to_string(send_out.with_extension("tx"))
        .map_err(|cause| error("tx sidecar", cause))?;
    let rx = sidecar(&rx, &["affinity", "drops", "batches", "callback"])?;
    let tx = sidecar(&tx, &["affinity", "backpressure", "ack_timeouts"])?;
    let field = |values: &[&str], index: usize| -> Result<u64, BenchError> {
        values
            .get(index)
            .ok_or_else(|| BenchError("sidecar field".into()))?
            .parse()
            .map_err(|cause| error("sidecar number", cause))
    };
    let receive_callback = numbers(rx.get(3).copied().unwrap_or_default())?;
    let affinity = |values: &[&'_ str]| values.first().copied().unwrap_or_default().to_string();
    let pinning: Vec<String> = [
        pin_reason("rx", &affinity(&rx), options.cores.map(|c| c.receiver)),
        pin_reason("tx", &affinity(&tx), options.cores.map(|c| c.sender)),
    ]
    .into_iter()
    .flatten()
    .collect();
    let functional_reasons = functional_reasons(pinning);
    if receive_callback.len() != expected {
        return Err(BenchError(format!(
            "{} callback samples, {expected} expected",
            receive_callback.len()
        )));
    }
    Ok(StageSamples {
        send: send.samples,
        receive: receive.samples,
        receive_callback,
        batches: numbers(rx.get(2).copied().unwrap_or_default())?,
        backend_drops: field(&rx, 1)?,
        backpressure: field(&tx, 1)?,
        ack_timeouts: field(&tx, 2)?,
        messages_per_sample: prepared.messages_per_sample,
        functional_only: !functional_reasons.is_empty(),
        functional_reasons,
        receiver: receiver_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_survives_its_text_form() {
        for load in [StageLoad::Closed, StageLoad::Open { rate: 100_000 }] {
            for rule in MtuRule::ALL {
                for shape in [Shape::W1, Shape::W6, Shape::W9(ExtBase::W4)] {
                    let run = StageRun {
                        shape,
                        e_max: 64,
                        rule,
                        load,
                        messages: 1_000_000,
                        warmup: 100_000,
                    };
                    assert_eq!(decode_run(&encode_run(&run)).ok(), Some(run));
                }
            }
        }
        for bad in [
            "",
            "W1",
            "W8.0,64,counts,closed,1,1",
            "W1,64,both,closed,1,1",
            "W1,64,counts,open:0,1,1",
            "W1,64,counts,closed,1,1,9",
        ] {
            assert!(decode_run(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn control_datagrams_carry_the_run_nonce() {
        let bytes = control(ACK, 77, 1_234_567);
        assert_eq!(parse_control(&bytes, 77), Some((ACK, 1_234_567)));
        assert_eq!(parse_control(&bytes, 78), None);
        assert_eq!(parse_control(bytes.get(..16).unwrap_or_default(), 77), None);
    }

    #[test]
    fn pinning_needs_the_requested_core_read_back() {
        assert_eq!(pin_reason("rx", "3", Some(3)), None);
        assert_eq!(
            pin_reason("rx", "0,1,2,3", Some(3)).as_deref(),
            Some("rx affinity 0,1,2,3, expected 3")
        );
        assert_eq!(
            pin_reason("tx", "unavailable (unavailable on macos)", Some(3)).as_deref(),
            Some("tx affinity unavailable (unavailable on macos), expected 3")
        );
        assert_eq!(
            pin_reason("tx", "3", None).as_deref(),
            Some("tx not pinned")
        );
    }

    #[test]
    fn sidecars_parse_strictly() {
        let keys = ["drops", "batches", "callback"];
        let text = "drops 3\nbatches 1,2,30\ncallback \n";
        assert_eq!(sidecar(text, &keys).ok(), Some(vec!["3", "1,2,30", ""]));
        for bad in [
            "drops 3\nbatches 1\n",
            "drops 3\ndrops 4\nbatches 1\ncallback \n",
            "drops 3\nbatches 1\ncallback \nextra 1\n",
            "drops\nbatches 1\ncallback \n",
        ] {
            assert!(sidecar(bad, &keys).is_err(), "{bad:?}");
        }
        assert_eq!(numbers("1,2,30").ok(), Some(vec![1, 2, 30]));
        assert_eq!(numbers("").ok(), Some(vec![]));
        for bad in ["1,,2", "1,", ",1", "1,x"] {
            assert!(numbers(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn faults_survive_their_text_form() {
        let faults = Faults {
            drop_hellos: 3,
            drop_dones: 2,
            no_stop: true,
            rx_crash_at: Some(5),
            rx_deadline_ms: Some(6),
            tx_crash_at: Some(7),
            tx_freeze_at: Some(8),
        };
        assert_eq!(Faults::decode(&faults.encode()).ok(), Some(faults));
        assert_eq!(Faults::decode("").ok(), Some(Faults::default()));
        assert!(Faults::decode("unknown=1").is_err());
        assert!(Faults::decode("drop_hellos=x").is_err());
    }
}
