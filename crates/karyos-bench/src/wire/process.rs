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
//! child sends a hello to the control socket, so the receiver learns where
//! to answer, and runs. Control traffic is outside both timed stages:
//!
//! - the receiver acknowledges the messages completed so far (R1) and
//!   tells the sender when it stops, for any reason, so the sender stops
//!   too;
//! - the parent tells the receiver when the send child has exited, so the
//!   receiver drains and ends however the sender ended.
//!
//! Every result is functional only (E4) for now, with the reason "not
//! pinned": batch B4 pins each child to its own isolated core, reads the
//! affinity back in the child, and only then clears the flag on a host
//! that is decision eligible (`env::decision_eligible`: E1 to E3 on its
//! declared host). The reasons of this host's ineligibility are recorded
//! too.

use std::cell::Cell;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use karyos_protocol::protection::Trusted;

use crate::env;
use crate::inventory::{Inventory, Scope};
use crate::manifest::{ExtBase, Fanout, Load, MtuRule, Point, Shape};
use crate::samples::{self, Header, RunSamples, SATURATED, Stage};
use crate::wire::stage::{
    ACK_TIMEOUT, Prepared, RECEIVE_DEADLINE, ReceiveControl, SendControl, StageLoad, StageRun,
    StageSamples, receive_role, send_role,
};
use crate::workloads::BenchError;

/// The role of a wire child: `rx` or `tx`.
pub const ROLE: &str = "KARYOS_BENCH_WIRE_ROLE";

/// The run of a wire child, as [`encode_run`] writes it.
pub const RUN: &str = "KARYOS_BENCH_WIRE_RUN";

/// The sample file a wire child writes.
pub const OUT: &str = "KARYOS_BENCH_WIRE_OUT";

/// The send child's peers: `<data> <control>` of the receiver.
pub const PEER: &str = "KARYOS_BENCH_WIRE_PEER";

/// The test that runs a wire child in a test binary.
pub const CHILD_TEST: &str = "wire_child";

/// The line the receive child prints when it is ready.
const READY: &str = "WIRE_READY";

/// How long the parent waits for the receive child to be ready.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the parent checks its children.
const CHILD_POLL: Duration = Duration::from_millis(10);

/// Control datagrams: a tag byte, then a little-endian `u64`.
const CONTROL_LEN: usize = 9;

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

fn control(tag: u8, value: u64) -> [u8; CONTROL_LEN] {
    let mut bytes = [tag; CONTROL_LEN];
    if let Some(field) = bytes.get_mut(1..) {
        field.copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn parse_control(bytes: &[u8]) -> Option<(u8, u64)> {
    let (&tag, value) = bytes.split_first()?;
    Some((tag, u64::from_le_bytes(value.try_into().ok()?)))
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

fn write_samples(
    path: &Path,
    run: &StageRun,
    stage: Stage,
    data: Vec<u32>,
) -> Result<(), BenchError> {
    let saturated = data.iter().filter(|sample| **sample == SATURATED).count();
    let header = Header {
        point: point(run)?,
        profile: "trusted".to_string(),
        stage,
        run: 0,
        seed: 0,
        clock_resolution_ns: 1,
        warmup: run.warmup,
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
    Some(run_child(&role))
}

fn run_child(role: &str) -> Result<(), BenchError> {
    let run = decode_run(&std::env::var(RUN).map_err(|cause| error(RUN, cause))?)?;
    let out = PathBuf::from(std::env::var(OUT).map_err(|cause| error(OUT, cause))?);
    let prepared = Prepared::new(&run, &Trusted)?;
    match role {
        "rx" => receive_child(&run, &prepared, &out),
        "tx" => send_child(&run, &prepared, &out),
        other => Err(BenchError(format!("no wire role {other}"))),
    }
}

/// The receiver's control socket. Dropping it, on any exit including a
/// panic, tells the send child that the receiver has stopped.
struct ReceiverControl {
    socket: UdpSocket,
    peer: Cell<Option<SocketAddr>>,
    done: Cell<bool>,
}

impl ReceiverControl {
    /// Reads every pending control datagram.
    fn pump(&self) {
        let mut buffer = [0_u8; CONTROL_LEN];
        while let Ok((length, from)) = self.socket.recv_from(&mut buffer) {
            match buffer.get(..length).and_then(parse_control) {
                Some((HELLO, _)) => self.peer.set(Some(from)),
                Some((DONE, _)) => self.done.set(true),
                _ => {}
            }
        }
    }

    fn tell(&self, tag: u8, value: u64) {
        if self.peer.get().is_none() {
            self.pump();
        }
        if let Some(to) = self.peer.get() {
            let _ = self.socket.send_to(&control(tag, value), to);
        }
    }
}

impl Drop for ReceiverControl {
    fn drop(&mut self) {
        self.tell(STOP, 0);
    }
}

fn receive_child(run: &StageRun, prepared: &Prepared, out: &Path) -> Result<(), BenchError> {
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
        peer: Cell::new(None),
        done: Cell::new(false),
    };
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{READY} {local} {control_address}")
            .map_err(|cause| error("ready", cause))?;
        stdout.flush().map_err(|cause| error("ready", cause))?;
    }
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
            ack: &|count| control.tell(ACK, count),
            deadline: RECEIVE_DEADLINE,
        },
    )?;
    write_samples(out, run, Stage::Receive { receiver: 0 }, received.receive)?;
    std::fs::write(
        out.with_extension("rx"),
        format!(
            "drops {}\nbatches {}\ncallback {}\n",
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
    completed: Cell<u64>,
    stopped: Cell<bool>,
}

impl SenderControl {
    /// Reads every pending control datagram; an error other than an empty
    /// socket means the receiver is gone.
    fn pump(&self) {
        let mut buffer = [0_u8; CONTROL_LEN];
        loop {
            match self.socket.recv(&mut buffer) {
                Ok(length) => match buffer.get(..length).and_then(parse_control) {
                    Some((ACK, count)) => self.completed.set(self.completed.get().max(count)),
                    Some((STOP, _)) => self.stopped.set(true),
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

    fn wait(&self, sequence: u64) -> bool {
        let start = Instant::now();
        loop {
            self.pump();
            if self.completed.get() > sequence {
                return true;
            }
            if self.stopped.get() {
                return false;
            }
            if start.elapsed() >= ACK_TIMEOUT {
                return true;
            }
            std::thread::yield_now();
        }
    }

    fn stopped(&self) -> bool {
        self.pump();
        self.stopped.get()
    }
}

fn send_child(run: &StageRun, prepared: &Prepared, out: &Path) -> Result<(), BenchError> {
    let peers = std::env::var(PEER).map_err(|cause| error(PEER, cause))?;
    let mut parts = peers.split_whitespace();
    let (Some(data), Some(control_peer)) = (parts.next(), parts.next()) else {
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
    socket
        .send(&control(HELLO, 0))
        .map_err(|cause| error("hello", cause))?;
    let control = SenderControl {
        socket,
        completed: Cell::new(0),
        stopped: Cell::new(false),
    };
    let (mut tx, _rx) = prepared
        .endpoint()?
        .split()
        .map_err(|_| BenchError("split sender".into()))?;
    let sent = send_role(
        run,
        prepared,
        &Trusted,
        &mut tx,
        data,
        &SendControl {
            wait: &|sequence| control.wait(sequence),
            stopped: &|| control.stopped(),
        },
    )?;
    write_samples(out, run, Stage::Send, sent.send)?;
    std::fs::write(
        out.with_extension("tx"),
        format!("backpressure {}\n", sent.backpressure),
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

fn spawn(role: &str, run: &StageRun, out: &Path, peer: Option<&str>) -> Result<Guard, BenchError> {
    let mut command =
        Command::new(std::env::current_exe().map_err(|cause| error("executable", cause))?);
    command
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads", "1"])
        .env(ROLE, role)
        .env(RUN, encode_run(run))
        .env(OUT, out)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(peer) = peer {
        command.env(PEER, peer);
    }
    command
        .spawn()
        .map(Guard)
        .map_err(|cause| error("wire child", cause))
}

fn check(status: std::process::ExitStatus, role: &str) -> Result<(), BenchError> {
    if status.success() {
        Ok(())
    } else {
        Err(BenchError(format!("{role} child failed: {status}")))
    }
}

/// The value of the sidecar line `key`.
fn sidecar<'a>(text: &'a str, key: &str) -> Result<&'a str, BenchError> {
    text.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(' '))
        .ok_or_else(|| BenchError(format!("sidecar without {key}")))
}

fn numbers(text: &str) -> Result<Vec<u32>, BenchError> {
    text.split(',')
        .filter(|value| !value.is_empty())
        .map(|value| value.parse().map_err(|cause| error("sidecar value", cause)))
        .collect()
}

/// Why a result of this host is functional only: always "not pinned"
/// until batch B4 pins the children, then every condition
/// `env::decision_eligible` finds unmet (E1 to E3 on the declared host).
#[must_use]
pub fn functional_reasons() -> Vec<String> {
    let inventory = Inventory::detect(Scope::Classification);
    let record = env::host_record(&inventory.host);
    let mut reasons = vec!["not pinned".to_string()];
    if let Err(ineligible) = env::decision_eligible(&inventory, record.as_deref(), Fanout::F1) {
        reasons.extend(ineligible.iter().map(ToString::to_string));
    }
    reasons
}

/// Runs one wire run with each role in its own process, writing the
/// sample files into `dir` (`send.samples`, `receive.samples`).
///
/// # Errors
///
/// A child that fails, never gets ready or writes no samples.
pub fn run_processes(run: &StageRun, dir: &Path) -> Result<StageSamples, BenchError> {
    let prepared = Prepared::new(run, &Trusted)?;
    std::fs::create_dir_all(dir).map_err(|cause| error("sample directory", cause))?;
    let send_out = dir.join("send.samples");
    let receive_out = dir.join("receive.samples");
    let mut receiver = spawn("rx", run, &receive_out, None)?;
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
        .recv_timeout(READY_TIMEOUT)
        .map_err(|_| BenchError("the receive child never got ready".into()))?;
    let peers = line
        .strip_prefix(READY)
        .map(str::trim)
        .ok_or_else(|| BenchError(format!("bad ready line {line}")))?
        .to_string();
    let mut addresses = peers
        .split_whitespace()
        .map(|address| address.parse::<SocketAddr>().ok());
    let (Some(Some(receiver_address)), Some(Some(control_address))) =
        (addresses.next(), addresses.next())
    else {
        return Err(BenchError(format!("bad ready line {line}")));
    };
    let mut sender_child = spawn("tx", run, &send_out, Some(&peers))?;
    let parent =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|cause| error("control", cause))?;
    // A receiver that fails first ends the run; the guards kill the
    // sender. Once the sender exits, however it ended, the receiver is
    // told so it drains and ends.
    let sent = loop {
        if let Some(status) = sender_child
            .0
            .try_wait()
            .map_err(|cause| error("tx", cause))?
        {
            let _ = parent.send_to(&control(DONE, 0), control_address);
            break status;
        }
        if let Some(status) = receiver.0.try_wait().map_err(|cause| error("rx", cause))? {
            check(status, "rx")?;
        }
        std::thread::sleep(CHILD_POLL);
    };
    let received = receiver.0.wait().map_err(|cause| error("rx", cause))?;
    check(received, "rx")?;
    check(sent, "tx")?;
    let send = samples::read_file(&send_out).map_err(|cause| error("send samples", cause))?;
    let receive =
        samples::read_file(&receive_out).map_err(|cause| error("receive samples", cause))?;
    let rx = std::fs::read_to_string(receive_out.with_extension("rx"))
        .map_err(|cause| error("rx sidecar", cause))?;
    let tx = std::fs::read_to_string(send_out.with_extension("tx"))
        .map_err(|cause| error("tx sidecar", cause))?;
    Ok(StageSamples {
        send: send.samples,
        receive: receive.samples,
        receive_callback: numbers(sidecar(&rx, "callback")?)?,
        batches: numbers(sidecar(&rx, "batches")?)?,
        backend_drops: sidecar(&rx, "drops")?
            .parse()
            .map_err(|cause| error("drops", cause))?,
        backpressure: sidecar(&tx, "backpressure")?
            .parse()
            .map_err(|cause| error("backpressure", cause))?,
        messages_per_sample: prepared.messages_per_sample,
        functional_only: true,
        functional_reasons: functional_reasons(),
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
        ] {
            assert!(decode_run(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn control_datagrams_round_trip_and_sidecars_parse() {
        let bytes = control(ACK, 1_234_567);
        assert_eq!(parse_control(&bytes), Some((ACK, 1_234_567)));
        assert_eq!(parse_control(bytes.get(..8).unwrap_or_default()), None);
        let text = "drops 3\nbatches 1,2,30\ncallback \n";
        assert_eq!(sidecar(text, "drops").ok(), Some("3"));
        assert_eq!(numbers("1,2,30").ok(), Some(vec![1, 2, 30]));
        assert_eq!(numbers("").ok(), Some(vec![]));
        assert!(sidecar(text, "backpressure").is_err());
        assert!(numbers("1,x").is_err());
    }
}
