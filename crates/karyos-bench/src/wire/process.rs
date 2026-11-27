// SPDX-License-Identifier: Apache-2.0

//! The wire roles in their own processes
//! (`quantstratum-docs: karyos/design/measurement-harness.md` §5.3): the
//! bench binary runs itself again once per role, with [`ROLE`] and
//! [`RUN`] in the environment, as the IPC workloads do (`ipc.rs`). Each
//! child times only its own stage and writes its own sample file in the
//! format of `samples.rs`.
//!
//! Under F1 one receive child starts first and prints
//! `WIRE_READY <data> <control>`: the address of its endpoint and of a
//! plain UDP control socket. Under F2 (`StageRun::receivers` above 1) every
//! receive child joins one loopback multicast group: the first binds the
//! group with port 0 and reports the port, the others bind that port
//! too, which needs `SO_REUSEADDR` (the Linux backend). The group comes
//! from the run's nonce inside `239.255.0.0/16`, and a group the host has
//! already joined is refused. The send child then says hello to every
//! control socket, so each receiver learns where to answer, and runs.
//! Control traffic is outside both timed stages, and every control
//! datagram carries the run's nonce ([`NONCE`]); one with another nonce is
//! ignored. A control datagram can be lost, so every one that matters is
//! repeated:
//!
//! - the sender repeats its hello to each receiver until it hears from
//!   it; each answers every hello with its acknowledgement count;
//! - each receiver acknowledges the messages completed so far (R1) and,
//!   when it stops for any reason, tells the sender, three times; under
//!   R1 the sender waits for the smallest count, and a stop from any
//!   receiver stops it;
//! - the parent tells every receiver at every poll, once the send child
//!   has exited however it ended, so the receivers drain and end.
//!
//! The parent bounds the whole run by a deadline and kills every child
//! when it passes, when a receiver fails, or when the sender outlives
//! the receivers. A child exits on its own when its standard input
//! closes, so a parent that dies leaves no orphan.
//!
//! **Pinning.** With [`Cores`], each child starts under `taskset -c` on
//! its own core and reads its affinity back (`Cpus_allowed_list` of
//! `/proc/self/status`) into its sidecar. A result is functional only
//! (E4) unless every read-back shows the requested core and this host is
//! decision eligible for the run's fan-out (`env::decision_eligible`: E1
//! to E3 on its declared host); every reason is recorded (coordinator
//! decision, ACS 15273).

use std::cell::Cell;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::wire::profile::Profile;

use crate::env;
use crate::inventory::{Inventory, Scope, parse_cpu_list};
use crate::manifest::{ExtBase, Fanout, Load, MtuRule, Point, Shape};
use crate::samples::{self, Header, RunSamples, SATURATED, Stage};
use crate::wire::stage::{
    ACK_TIMEOUT, Prepared, ReceiveControl, ReceiverSamples, SendControl, StageLoad, StageRun,
    StageSamples, Wait, receive_deadline, receive_role, send_role,
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

/// The configuration name, written into the sample headers as the
/// profile; it follows the sample files' profile rule.
pub const PROFILE: &str = "KARYOS_BENCH_WIRE_PROFILE";

/// The multicast group and port of an F2 receive child, `<group>:<port>`;
/// port 0 for the first receiver.
pub const GROUP: &str = "KARYOS_BENCH_WIRE_GROUP";

/// The index of a receive child, from 0.
pub const RECEIVER: &str = "KARYOS_BENCH_WIRE_RECEIVER";

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
    /// The receive child the receiver faults apply to; every receiver
    /// without it.
    pub only_receiver: Option<u16>,
    /// The receiver waits this many milliseconds before acknowledging
    /// the run's last message.
    pub rx_last_ack_delay_ms: Option<u64>,
    /// The run's nonce, in place of a fresh one, so a test can predict the
    /// multicast group.
    pub nonce: Option<u64>,
}

impl Faults {
    /// Whether the receiver faults apply to receive child `receiver`.
    #[must_use]
    pub fn applies_to(&self, receiver: u16) -> bool {
        self.only_receiver.is_none_or(|only| only == receiver)
    }
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
            ("only_receiver", self.only_receiver.map(u64::from)),
            ("rx_last_ack_delay_ms", self.rx_last_ack_delay_ms),
            ("nonce", self.nonce),
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
                "only_receiver" => {
                    faults.only_receiver = Some(u16::try_from(number).map_err(|_| bad())?);
                }
                "rx_last_ack_delay_ms" => faults.rx_last_ack_delay_ms = Some(number),
                "nonce" => faults.nonce = Some(number),
                _ => return Err(bad()),
            }
        }
        Ok(faults)
    }
}

/// The quiet cores of this host: isolated and in `nohz_full`. A run with
/// `k` receivers takes the first `k` for its receivers and the next for
/// its sender; two processes never share one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cores {
    /// The quiet cores, ascending.
    pub quiet: Vec<usize>,
}

impl Cores {
    /// The quiet cores of `inventory`; `None` with fewer than two, the
    /// fewest any run needs.
    #[must_use]
    pub fn of(inventory: &Inventory) -> Option<Self> {
        let quiet = quiet_cores(&inventory.isolated_cores(), &inventory.nohz_full_cores());
        (quiet.len() >= 2).then_some(Self { quiet })
    }

    /// This host's cores, when it has two quiet ones and `taskset` runs;
    /// otherwise why not.
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

    /// The receivers' cores and the sender's for `receivers` receivers;
    /// `None` when there are too few.
    #[must_use]
    pub fn assign(&self, receivers: usize) -> Option<(Vec<usize>, usize)> {
        let sender = *self.quiet.get(receivers)?;
        Some((self.quiet.get(..receivers)?.to_vec(), sender))
    }
}

/// The cores both `isolated` and in `nohz`, in order.
fn quiet_cores(isolated: &[usize], nohz: &[usize]) -> Vec<usize> {
    isolated
        .iter()
        .copied()
        .filter(|core| nohz.contains(core))
        .collect()
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOptions {
    /// The configuration, written into the sample headers as the profile.
    pub profile: String,
    /// The run index at its point, written into the sample headers.
    pub run_index: u32,
    /// Each child's core; unpinned without.
    pub cores: Option<Cores>,
    /// The run deadline; by default [`receive_deadline`] plus 30 s.
    pub deadline: Option<Duration>,
    /// Injected faults; tests only.
    pub faults: Faults,
}

impl Default for ProcessOptions {
    fn default() -> Self {
        Self {
            profile: "trusted".to_string(),
            run_index: 0,
            cores: None,
            deadline: None,
            faults: Faults::default(),
        }
    }
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

/// `shape,e_max,rule,load,messages,warmup,receivers`: the rule is
/// `counts` or `excludes`, the load `closed` or `open:<rate>`.
#[must_use]
pub fn encode_run(run: &StageRun) -> String {
    let rule = match run.rule {
        MtuRule::CountsEnvelope => "counts",
        MtuRule::ExcludesEnvelope => "excludes",
    };
    let load = match run.load {
        StageLoad::Closed => "closed".to_string(),
        StageLoad::Open { rate } => format!("open:{rate}"),
        StageLoad::Rotation { rate } => format!("rotation:{rate}"),
    };
    format!(
        "{},{},{rule},{load},{},{},{}",
        run.shape, run.e_max, run.messages, run.warmup, run.receivers
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
        rotation if rotation.starts_with("rotation:") => StageLoad::Rotation {
            rate: rotation
                .strip_prefix("rotation:")
                .and_then(|rate| rate.parse().ok())
                .ok_or_else(|| BenchError(format!("bad load {rotation}")))?,
        },
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
    let receivers = next()?
        .parse()
        .ok()
        .filter(|receivers| *receivers > 0)
        .ok_or_else(bad)?;
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
        receivers,
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
            StageLoad::Rotation { rate } => Load::R5 {
                rate: u32::try_from(rate)
                    .map_err(|_| BenchError(format!("R5 rate {rate} outside the manifest")))?,
            },
        },
        fanout: fanout(run)?,
    })
}

/// The fan-out of a run: F1 with one receiver, F2 with more.
fn fanout(run: &StageRun) -> Result<Fanout, BenchError> {
    Ok(match run.receivers {
        1 => Fanout::F1,
        receivers => Fanout::F2 {
            receivers: u8::try_from(receivers)
                .map_err(|_| BenchError(format!("{receivers} receivers")))?,
        },
    })
}

/// The multicast group of the run with `nonce`, inside
/// `239.255.0.0/16`: the administratively scoped block of the
/// organisation-local scope.
#[must_use]
pub fn group_of(nonce: u64) -> Ipv4Addr {
    // Every bit of the nonce counts: its four 16-bit words folded.
    let folded = nonce ^ (nonce >> 16) ^ (nonce >> 32) ^ (nonce >> 48);
    let [low, high, ..] = folded.to_le_bytes();
    Ipv4Addr::new(239, 255, high, low)
}

/// Whether this host has joined `group` on any interface already: the
/// group's entry in `/proc/net/igmp` (Linux), whose groups are the
/// address bytes in reverse order, in hex.
fn joined(group: Ipv4Addr) -> Result<bool, BenchError> {
    let table = std::fs::read_to_string("/proc/net/igmp")
        .map_err(|cause| error("/proc/net/igmp", cause))?;
    Ok(listed(&table, group))
}

/// Whether the `/proc/net/igmp` text `table` lists `group`.
fn listed(table: &str, group: Ipv4Addr) -> bool {
    let [a, b, c, d] = group.octets();
    let entry = format!("{d:02X}{c:02X}{b:02X}{a:02X}");
    table
        .lines()
        .any(|line| line.split_whitespace().next() == Some(entry.as_str()))
}

/// A wire child's environment: its run, sample file, configuration,
/// run index, nonce and faults.
struct ChildContext {
    run: StageRun,
    receiver: u16,
    group: Option<SocketAddrV4>,
    profile: String,
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
            receiver: match std::env::var(RECEIVER) {
                Ok(index) => index.parse().map_err(|cause| error(RECEIVER, cause))?,
                Err(_) => 0,
            },
            group: match std::env::var(GROUP) {
                Ok(group) => Some(group.parse().map_err(|cause| error(GROUP, cause))?),
                Err(_) => None,
            },
            out: PathBuf::from(variable(OUT)?),
            profile: variable(PROFILE)?,
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
            profile: self.profile.clone(),
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
    let profile = Profile::for_run(&context.profile, context.run.load)?;
    let prepared = Prepared::new(&context.run, &profile)?;
    match role {
        "rx" => receive_child(&context, &prepared, &profile),
        "tx" => send_child(&context, &prepared, &profile),
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
        // The count tells the sender which messages this receiver has: a
        // stop after the last one it waits for is no stop for it.
        for _ in 0..STOP_REPEATS {
            self.send(STOP, self.completed.get());
        }
    }
}

fn receive_child(
    context: &ChildContext,
    prepared: &Prepared,
    profile: &Profile,
) -> Result<(), BenchError> {
    let run = &context.run;
    let endpoint = match (run.receivers, context.group) {
        (1, None) => prepared.endpoint()?,
        (_, Some(group)) => prepared.group_receiver(*group.ip(), group.port())?,
        (receivers, None) => {
            return Err(BenchError(format!("{receivers} receivers without a group")));
        }
    };
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
        no_stop: context.faults.no_stop && context.faults.applies_to(context.receiver),
    };
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{READY} {local} {control_address}")
            .map_err(|cause| error("ready", cause))?;
        stdout.flush().map_err(|cause| error("ready", cause))?;
    }
    // Receiver faults (tests only) apply to the named receiver alone.
    let faults = if context.faults.applies_to(context.receiver) {
        context.faults
    } else {
        Faults::default()
    };
    let total = prepared.total;
    let received = receive_role(
        run,
        prepared,
        profile,
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
                if let (Some(millis), true) = (faults.rx_last_ack_delay_ms, count >= total) {
                    std::thread::sleep(Duration::from_millis(millis));
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
        Stage::Receive {
            receiver: context.receiver,
        },
        received.receive,
    )?;
    std::fs::write(
        context.out.with_extension("rx"),
        format!(
            "{}drops {}\nbatches {}\ncallback {}\nallocations {}\n",
            affinity_line(),
            received.drops,
            join(&received.batches),
            join(&received.receive_callback),
            received.allocations
        ),
    )
    .map_err(|cause| error("rx sidecar", cause))
}

/// The send child's control socket, talking to every receiver's.
struct SenderControl {
    socket: UdpSocket,
    nonce: u64,
    /// Each receiver's control address.
    peers: Vec<SocketAddr>,
    /// Each receiver's cumulative acknowledgement.
    completed: Vec<Cell<u64>>,
    /// Whether each receiver has been heard from.
    heard: Vec<Cell<bool>>,
    /// Each receiver's stop, with the messages it had completed.
    stops: Vec<Cell<Option<u64>>>,
    /// Whether the control socket failed.
    failed: Cell<bool>,
    /// Warmup plus measured messages of the run.
    total: u64,
    last_hello: Cell<Option<Instant>>,
    hellos_to_drop: Cell<u32>,
}

impl SenderControl {
    /// Says hello to every receiver not heard from yet.
    fn hello(&self) {
        self.last_hello.set(Some(Instant::now()));
        for (peer, heard) in self.peers.iter().zip(&self.heard) {
            if heard.get() {
                continue;
            }
            match self.hellos_to_drop.get().checked_sub(1) {
                Some(left) => self.hellos_to_drop.set(left),
                None => {
                    let _ = self.socket.send_to(&control(HELLO, self.nonce, 0), peer);
                }
            }
        }
    }

    /// Repeats the hellos until every receiver is heard, then reads every
    /// pending control datagram of this run from a known receiver.
    fn pump(&self) {
        if self.heard.iter().any(|heard| !heard.get())
            && self
                .last_hello
                .get()
                .is_none_or(|at| at.elapsed() >= HELLO_EVERY)
        {
            self.hello();
        }
        let mut buffer = [0_u8; CONTROL_LEN];
        loop {
            match self.socket.recv_from(&mut buffer) {
                Ok((length, from)) => {
                    let Some(index) = self.peers.iter().position(|peer| *peer == from) else {
                        continue;
                    };
                    let (Some(heard), Some(completed), Some(stop)) = (
                        self.heard.get(index),
                        self.completed.get(index),
                        self.stops.get(index),
                    ) else {
                        continue;
                    };
                    match buffer
                        .get(..length)
                        .and_then(|bytes| parse_control(bytes, self.nonce))
                    {
                        Some((ACK, count)) => {
                            heard.set(true);
                            completed.set(completed.get().max(count));
                        }
                        Some((STOP, count)) => {
                            heard.set(true);
                            completed.set(completed.get().max(count));
                            stop.set(Some(count));
                        }
                        _ => {}
                    }
                }
                Err(cause) if cause.kind() == ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.failed.set(true);
                    return;
                }
            }
        }
    }

    /// The messages every receiver has completed.
    fn completed(&self) -> u64 {
        self.completed.iter().map(Cell::get).min().unwrap_or(0)
    }

    /// Whether a receiver stopped with fewer than `count` messages
    /// completed, or with no more than `count` when `inclusive`.
    fn stopped_short(&self, count: u64, inclusive: bool) -> bool {
        self.failed.get()
            || self.stops.iter().any(|stop| {
                stop.get()
                    .is_some_and(|completed| completed < count || (inclusive && completed == count))
            })
    }

    fn wait(&self, sequence: u64) -> Wait {
        let start = Instant::now();
        loop {
            self.pump();
            if self.completed() > sequence {
                return Wait::Completed;
            }
            // A receiver that stopped after this message is no stop for it.
            if self.stopped_short(sequence, true) {
                return Wait::Stopped;
            }
            if start.elapsed() >= ACK_TIMEOUT {
                return Wait::TimedOut;
            }
            std::thread::yield_now();
        }
    }

    /// Whether a receiver stopped before the run's last message.
    fn stopped(&self) -> bool {
        self.pump();
        self.stopped_short(self.total, false)
    }
}

fn send_child(
    context: &ChildContext,
    prepared: &Prepared,
    profile: &Profile,
) -> Result<(), BenchError> {
    let peers = variable(PEER)?;
    let mut parts = peers.split_whitespace();
    let data: SocketAddr = parts
        .next()
        .ok_or_else(|| BenchError(format!("bad peers {peers}")))?
        .parse()
        .map_err(|cause| error("peer", cause))?;
    let controls: Vec<SocketAddr> = parts
        .map(|peer| peer.parse().map_err(|cause| error("control peer", cause)))
        .collect::<Result<_, _>>()?;
    if controls.len() != usize::from(context.run.receivers) {
        return Err(BenchError(format!(
            "{} control peers for {} receivers",
            controls.len(),
            context.run.receivers
        )));
    }
    let socket =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|cause| error("control", cause))?;
    socket
        .set_nonblocking(true)
        .map_err(|cause| error("control", cause))?;
    let control = SenderControl {
        socket,
        nonce: context.nonce,
        completed: controls.iter().map(|_| Cell::new(0)).collect(),
        heard: controls.iter().map(|_| Cell::new(false)).collect(),
        stops: controls.iter().map(|_| Cell::new(None)).collect(),
        peers: controls,
        failed: Cell::new(false),
        total: prepared.total,
        last_hello: Cell::new(None),
        hellos_to_drop: Cell::new(context.faults.drop_hellos),
    };
    control.hello();
    let endpoint = match data {
        SocketAddr::V4(group) if group.ip().is_multicast() => prepared.group_sender(*group.ip())?,
        _ => prepared.endpoint()?,
    };
    let (mut tx, _rx) = endpoint
        .split()
        .map_err(|_| BenchError("split sender".into()))?;
    let faults = context.faults;
    let sent = send_role(
        &context.run,
        prepared,
        profile,
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
            "{}backpressure {}\nack_timeouts {}\nallocations {}\n",
            affinity_line(),
            sent.backpressure,
            sent.ack_timeouts,
            sent.allocations
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
        extra: &[(&str, String)],
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
            .env(PROFILE, &self.options.profile)
            // Held open by the parent: its end tells the child to exit.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(peer) = peer {
            command.env(PEER, peer);
        }
        for (name, value) in extra {
            command.env(name, value);
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
    options: &ProcessOptions,
    expected: usize,
) -> Result<(), BenchError> {
    let header = &samples.header;
    if header.point != point(run)?
        || header.stage != stage
        || header.run != options.run_index
        || header.profile != options.profile
    {
        return Err(BenchError(format!(
            "sample header {} {:?} {} run {} does not match the run",
            header.point, header.stage, header.profile, header.run
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
pub fn functional_reasons(pinning: Vec<String>, fanout: Fanout) -> Vec<String> {
    let inventory = Inventory::detect(Scope::Classification);
    let record = env::host_record(&inventory.host);
    reasons_for(pinning, &inventory, record.as_deref(), fanout)
}

/// [`functional_reasons`] for a given host and record.
fn reasons_for(
    pinning: Vec<String>,
    inventory: &Inventory,
    record: Option<&str>,
    fanout: Fanout,
) -> Vec<String> {
    let mut reasons = pinning;
    if let Err(ineligible) = env::decision_eligible(inventory, record, fanout) {
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

/// A receive child that has said it is ready.
struct Receiver {
    guard: Guard,
    /// Where its endpoint receives: its own address, or the group.
    data: SocketAddr,
    /// Its control socket.
    control: SocketAddr,
    /// Its exit, once it has exited.
    status: Option<ExitStatus>,
}

/// Waits for receive child `index`'s ready line, until `deadline`.
fn ready(
    child: &mut Guard,
    index: u16,
    deadline: Instant,
) -> Result<(SocketAddr, SocketAddr), BenchError> {
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| BenchError(format!("rx{index} has no output")))?;
    let (sender, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Read to the end: closing the pipe early would fail the child's
        // later output.
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(at) = line.find(READY) {
                let _ = sender.send(line.get(at..).unwrap_or_default().to_string());
            }
        }
    });
    let line = match lines
        .recv_timeout(READY_TIMEOUT.min(deadline.saturating_duration_since(Instant::now())))
    {
        Ok(line) => line,
        Err(_) => {
            return Err(BenchError(
                match child.0.try_wait().map_err(|cause| error("rx", cause))? {
                    Some(status) => format!("rx{index} exited before it was ready: {status}"),
                    None => format!("rx{index} never got ready"),
                },
            ));
        }
    };
    let mut addresses = line
        .strip_prefix(READY)
        .unwrap_or_default()
        .split_whitespace()
        .map(|address| address.parse::<SocketAddr>().ok());
    match (addresses.next(), addresses.next(), addresses.next()) {
        (Some(Some(data)), Some(Some(control)), None) => Ok((data, control)),
        _ => Err(BenchError(format!("rx{index}: bad ready line {line}"))),
    }
}

/// The name of receiver `index`'s sample file.
fn receive_file(index: u16) -> String {
    format!("receive-{index}.samples")
}

/// Runs one wire run with each role in its own process, writing the
/// sample files into `dir` (`send.samples` and `receive-<i>.samples`).
/// Under F2 every receiver joins one loopback multicast group.
///
/// # Errors
///
/// F2 off Linux, a group already joined on the host, a child that fails,
/// never gets ready, outlives the deadline or the receivers, or writes
/// samples that do not match the run.
pub fn run_processes(
    run: &StageRun,
    dir: &Path,
    options: &ProcessOptions,
) -> Result<StageSamples, BenchError> {
    faults_allowed(&options.faults)?;
    let prepared = Prepared::new(run, &Profile::for_run(&options.profile, run.load)?)?;
    let expected =
        usize::try_from(run.messages).map_err(|_| BenchError("too many messages".into()))?;
    let count = usize::from(run.receivers);
    let fanout = fanout(run)?;
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
    let spawn = Spawn {
        run,
        nonce: options.faults.nonce.unwrap_or_else(nonce),
        options,
    };
    let group = if count > 1 {
        if !cfg!(target_os = "linux") {
            return Err(BenchError(
                "F2 needs receivers sharing the group port (SO_REUSEADDR), Linux only".into(),
            ));
        }
        let group = group_of(spawn.nonce);
        if joined(group)? {
            return Err(BenchError(format!(
                "multicast group {group} is already joined on this host"
            )));
        }
        Some(group)
    } else {
        None
    };
    let assigned = options.cores.as_ref().map(|cores| cores.assign(count));
    let core_of =
        |index: usize| -> Option<usize> { assigned.as_ref()?.as_ref()?.0.get(index).copied() };
    let sender_core = assigned.as_ref().and_then(|a| a.as_ref().map(|(_, s)| *s));
    // The first receiver binds the group with port 0; the others bind the
    // port it reports.
    let mut receivers: Vec<Receiver> = Vec::with_capacity(count);
    for index in 0..run.receivers {
        let out = dir.join(receive_file(index));
        let mut extra = vec![(RECEIVER, index.to_string())];
        if let Some(group) = group {
            let port = receivers.first().map_or(0, |first| first.data.port());
            extra.push((GROUP, SocketAddrV4::new(group, port).to_string()));
        }
        let mut guard = spawn.child("rx", &out, None, core_of(usize::from(index)), &extra)?;
        let (data, control) = ready(&mut guard, index, deadline)?;
        receivers.push(Receiver {
            guard,
            data,
            control,
            status: None,
        });
    }
    let destination = receivers
        .first()
        .map(|first| first.data)
        .ok_or_else(|| BenchError("no receiver".into()))?;
    let mut peers = destination.to_string();
    for receiver in &receivers {
        peers.push(' ');
        peers.push_str(&receiver.control.to_string());
    }
    let send_out = dir.join("send.samples");
    let mut sender_child = spawn.child("tx", &send_out, Some(&peers), sender_core, &[])?;
    let parent =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|cause| error("control", cause))?;
    let mut dones_to_drop = options.faults.drop_dones;
    let mut sent: Option<ExitStatus> = None;
    let mut receivers_ended: Option<Instant> = None;
    // Every child is polled until all have exited. On any early return,
    // the guards kill and reap what is still running.
    while sent.is_none() || receivers.iter().any(|r| r.status.is_none()) {
        if sent.is_none() {
            sent = sender_child
                .0
                .try_wait()
                .map_err(|cause| error("tx", cause))?;
        }
        for (index, receiver) in receivers.iter_mut().enumerate() {
            if receiver.status.is_none() {
                receiver.status = receiver
                    .guard
                    .0
                    .try_wait()
                    .map_err(|cause| error("rx", cause))?;
                // A receiver that failed ends the run at once.
                if let Some(status) = receiver.status {
                    check(status, &format!("rx{index}"))?;
                }
            }
        }
        // A receiver that ended, even one that never heard a hello and so
        // could not say it stopped, ends the run unless the sender follows.
        if receivers.iter().any(|r| r.status.is_some()) {
            let ended = *receivers_ended.get_or_insert_with(Instant::now);
            if sent.is_none() && ended.elapsed() >= OUTLIVE {
                return Err(BenchError(format!(
                    "the sender outlived a receiver by {OUTLIVE:?}"
                )));
            }
        }
        if sent.is_some() {
            // Repeated until each receiver exits: one notice can be lost.
            for receiver in receivers.iter().filter(|r| r.status.is_none()) {
                match dones_to_drop.checked_sub(1) {
                    Some(left) => dones_to_drop = left,
                    None => {
                        let _ = parent.send_to(&control(DONE, spawn.nonce, 0), receiver.control);
                    }
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
    check_samples(&send, run, Stage::Send, options, expected)?;
    let tx = std::fs::read_to_string(send_out.with_extension("tx"))
        .map_err(|cause| error("tx sidecar", cause))?;
    let tx = sidecar(
        &tx,
        &["affinity", "backpressure", "ack_timeouts", "allocations"],
    )?;
    let field = |values: &[&str], index: usize| -> Result<u64, BenchError> {
        values
            .get(index)
            .ok_or_else(|| BenchError("sidecar field".into()))?
            .parse()
            .map_err(|cause| error("sidecar number", cause))
    };
    let mut pinning: Vec<String> = Vec::new();
    if assigned.as_ref().is_some_and(Option::is_none) {
        pinning.push(format!(
            "{} receivers and a sender need {} quiet cores; the host has {}",
            count,
            count.checked_add(1).unwrap_or(count),
            options.cores.as_ref().map_or(0, |cores| cores.quiet.len())
        ));
    }
    let mut per_receiver = Vec::with_capacity(count);
    for index in 0..run.receivers {
        let out = dir.join(receive_file(index));
        let receive = samples::read_file(&out).map_err(|cause| error("receive samples", cause))?;
        check_samples(
            &receive,
            run,
            Stage::Receive { receiver: index },
            options,
            expected,
        )?;
        let rx = std::fs::read_to_string(out.with_extension("rx"))
            .map_err(|cause| error("rx sidecar", cause))?;
        let rx = sidecar(
            &rx,
            &["affinity", "drops", "batches", "callback", "allocations"],
        )?;
        let receive_callback = numbers(rx.get(3).copied().unwrap_or_default())?;
        if receive_callback.len() != expected {
            return Err(BenchError(format!(
                "rx{index}: {} callback samples, {expected} expected",
                receive_callback.len()
            )));
        }
        pinning.extend(pin_reason(
            &format!("rx{index}"),
            rx.first().copied().unwrap_or_default(),
            core_of(usize::from(index)),
        ));
        per_receiver.push(ReceiverSamples {
            receive: receive.samples,
            receive_callback,
            batches: numbers(rx.get(2).copied().unwrap_or_default())?,
            drops: field(&rx, 1)?,
            allocations: field(&rx, 4)?,
        });
    }
    pinning.extend(pin_reason(
        "tx",
        tx.first().copied().unwrap_or_default(),
        sender_core,
    ));
    let functional_reasons = functional_reasons(pinning, fanout);
    let cores = match &assigned {
        Some(Some((receivers, sender))) => receivers
            .iter()
            .copied()
            .chain(std::iter::once(*sender))
            .collect(),
        _ => Vec::new(),
    };
    Ok(StageSamples {
        send: send.samples,
        receivers: per_receiver,
        backpressure: field(&tx, 1)?,
        ack_timeouts: field(&tx, 2)?,
        send_allocations: field(&tx, 3)?,
        messages_per_sample: prepared.messages_per_sample,
        functional_only: !functional_reasons.is_empty(),
        functional_reasons,
        destination,
        cores,
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
                        receivers: 4,
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
            "W1,64,counts,open:0,1,1,1",
            "W1,64,counts,closed,1,1",
            "W1,64,counts,closed,1,1,0",
            "W1,64,counts,closed,1,1,1,9",
        ] {
            assert!(decode_run(bad).is_err(), "{bad}");
        }
    }

    /// A sender's control over one receiver at `peer`, its socket
    /// nonblocking as `send_child` sets it.
    fn sender_control(peer: SocketAddr) -> SenderControl {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        SenderControl {
            socket,
            nonce: 7,
            peers: vec![peer],
            completed: vec![Cell::new(0)],
            heard: vec![Cell::new(false)],
            stops: vec![Cell::new(None)],
            failed: Cell::new(false),
            total: 100,
            last_hello: Cell::new(None),
            hellos_to_drop: Cell::new(0),
        }
    }

    /// Pumps until the receiver's STOP is read, whatever the load: the
    /// datagram's arrival is not what the tests below measure.
    fn read_stop(control: &SenderControl) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while control.stops[0].get().is_none() {
            assert!(Instant::now() < deadline, "the STOP never arrived");
            control.pump();
            std::thread::yield_now();
        }
    }

    /// karyos#602: a receiver's STOP ends the sender's R1 wait at once as
    /// `Stopped`, neither as `TimedOut` nor only after `ACK_TIMEOUT`, and
    /// a STOP that counts the awaited message completes it. The STOP is
    /// read before any wait is timed, so the datagram's travel under host
    /// load is not measured.
    #[test]
    fn a_stop_ends_the_wait_without_an_ack_timeout() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let tracker = sender_control(receiver.local_addr().unwrap());
        let sender = tracker.socket.local_addr().unwrap();
        // The receiver stopped with messages 0 to 4 completed.
        receiver.send_to(&control(STOP, 7, 5), sender).unwrap();
        read_stop(&tracker);
        // Stopped on the STOP itself, not once ACK_TIMEOUT passed: a wait
        // that reads the stop only after its timeout takes at least
        // ACK_TIMEOUT every time, so one prompt answer in five tells the
        // two apart under any load, where a single timed answer would not.
        let prompt = (0..5).any(|_| {
            let started = Instant::now();
            assert_eq!(tracker.wait(5), Wait::Stopped);
            started.elapsed() < ACK_TIMEOUT
        });
        assert!(
            prompt,
            "every wait took ACK_TIMEOUT: the stop was read late"
        );
        assert_eq!(tracker.wait(9), Wait::Stopped);
        assert!(tracker.stopped());
        // A receiver that stopped after the awaited message is no stop for
        // it.
        assert_eq!(tracker.wait(4), Wait::Completed);
    }

    #[test]
    fn groups_are_organisation_local_and_follow_every_bit_of_the_nonce() {
        assert_eq!(group_of(0x1234), Ipv4Addr::new(239, 255, 0x12, 0x34));
        assert!(group_of(u64::MAX).is_multicast());
        assert_ne!(group_of(1), group_of(2));
        // Nonces that differ only in their high words still differ.
        assert_ne!(group_of(1 << 16), group_of(0));
        assert_ne!(group_of(1 << 48), group_of(0));
    }

    #[test]
    fn a_joined_group_is_found_in_the_igmp_table() {
        let table = "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n\
                     1\tlo        :     2      V3\n\
                     \t\t\t\t3412FFEF     1 0:00000000\t\t0\n\
                     \t\t\t\t010000E0     1 0:00000000\t\t0\n";
        assert!(listed(table, Ipv4Addr::new(239, 255, 0x12, 0x34)));
        assert!(listed(table, Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!listed(table, Ipv4Addr::new(239, 255, 0x34, 0x12)));
    }

    #[test]
    fn cores_go_to_the_receivers_then_the_sender() {
        let cores = Cores {
            quiet: vec![2, 3, 4, 5, 6],
        };
        assert_eq!(cores.assign(1), Some((vec![2], 3)));
        assert_eq!(cores.assign(4), Some((vec![2, 3, 4, 5], 6)));
        assert_eq!(cores.assign(5), None);
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
    fn quiet_cores_are_isolated_and_in_nohz_full() {
        assert_eq!(quiet_cores(&[2, 3, 4, 5], &[3, 4, 6]), [3, 4]);
        assert!(quiet_cores(&[2, 3], &[]).is_empty());
    }

    #[test]
    fn a_result_is_eligible_only_pinned_on_an_eligible_host() {
        use crate::inventory::tests::{capture, tuned};
        let (tree, canned) = tuned();
        let inventory = capture(&tree, &canned, "linux", "x86_64");
        let record = crate::inventory::render(
            &inventory,
            &env::classify(&inventory),
            &[] as &[crate::inventory::Eligibility],
        );
        // A pinned run on an eligible host has no reason left.
        assert!(reasons_for(Vec::new(), &inventory, Some(&record), Fanout::F1).is_empty());
        // Unpinned, or without the host record, it stays functional only.
        assert_eq!(
            reasons_for(
                vec!["rx not pinned".into()],
                &inventory,
                Some(&record),
                Fanout::F1
            ),
            ["rx not pinned"]
        );
        assert!(!reasons_for(Vec::new(), &inventory, None, Fanout::F1).is_empty());
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
            only_receiver: Some(3),
            rx_last_ack_delay_ms: Some(100),
            nonce: Some(u64::MAX),
        };
        assert_eq!(Faults::decode(&faults.encode()).ok(), Some(faults));
        assert_eq!(Faults::decode("").ok(), Some(Faults::default()));
        assert!(Faults::decode("unknown=1").is_err());
        assert!(Faults::decode("drop_hellos=x").is_err());
    }
}
