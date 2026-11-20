// SPDX-License-Identifier: Apache-2.0

//! Network streams over shared terms across processes (Linux;
//! quantstratum-docs: karyos/design/network-shared-terms.md, Tests,
//! "Across processes on Linux (n5)"): remote clients of IPC drivers
//! publish and subscribe on `karyos:udp` over loopback, take image grants,
//! and are killed or stopped while they hold them. Each child is this test
//! binary run again with `--exact child`; it reports on stdout, one line
//! per step, and the parent runs the drivers' duty cycles meanwhile.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout
)]

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use karyos_client::aggregate::AggregateSubscription;
use karyos_client::ipc::{RemoteClient, attach};
use karyos_client::{Fetchable, MessageLimit, OfferOutcome, Outcome};
use karyos_driver::agents::ThreadingMode;
use karyos_driver::embedded::{AggregateConfig, StreamTerms};
use karyos_driver::net::NetworkConfig;
use karyos_driver::{
    DriverConfig, EmbeddedDriver, IpcConfig, LossPolicy, SealReason, StreamConfig, SystemClock,
};
use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_protocol::cnc::{Event, StreamKey, SubscriberRole};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::counters::CellRead;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

const SCENARIO: &str = "KARYOS_NET_PROCESS_SCENARIO";
const DIR: &str = "KARYOS_NET_PROCESS_DIR";
/// The scenario's argument: a socket address, or nothing.
const ARG: &str = "KARYOS_NET_PROCESS_ARG";

/// The stream id every test publishes.
const STREAM_ID: i32 = 10;
/// Messages one exchange sends.
const MESSAGES: u32 = 200;
/// How long a parent or a child waits for any one step.
const STEP: Duration = Duration::from_secs(20);

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// A subscription bound on any loopback port: the kernel picks it, and
/// `network_subscription_address` reads it back.
const ANY_PORT: SocketAddr = SocketAddr::new(LOOPBACK, 0);

const BUDGET: Budget = Budget {
    work: 256,
    bytes: 1 << 22,
};

type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("karyos-netproc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    TempDir(dir)
}

/// A test's directory, removed when the test ends, passed or not.
struct TempDir(PathBuf);

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The network of every driver here: Shared agents, so each duty cycle
/// runs them, on 64 KiB terms.
fn network() -> NetworkConfig {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.stream_defaults.term_length = MIN_TERM_LENGTH;
    network
}

/// An IPC driver with `network`, listening in `dir`. A process another
/// test forks holds a copy of a just-dropped listener until its exec, so a
/// restart retries briefly.
fn ipc_driver(dir: &Path, network: NetworkConfig) -> IpcDriver {
    let config = DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    };
    let start = Instant::now();
    loop {
        let created = EmbeddedDriver::with_ipc(
            config,
            IpcConfig {
                dir: dir.to_path_buf(),
                max_pending_hellos: 4,
                hello_timeout: 5_000_000_000,
                max_outbound_per_client: 16,
                fetch_deadline: 5_000_000_000,
                max_exports_per_client: 16,
                max_fetches_per_client: 4,
                max_regions_per_fetch: 4,
                max_fetch_bytes: 1 << 30,
                max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
            },
            Box::new(SystemClock::new()),
        );
        match created {
            Ok(driver) => return driver,
            Err(_) if start.elapsed() < Duration::from_secs(2) => std::thread::yield_now(),
            Err(error) => panic!("{error:?}"),
        }
    }
}

/// A heap driver with `network`.
fn heap_driver(network: NetworkConfig) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// A loopback address on a port the OS picked as free, for a `karyos:udp`
/// URI, which cannot name port 0. The probe socket closes before the child
/// subscribes, so another process may take the port in between: the child
/// cannot bind it itself, since a subscription URI names its port and a
/// remote client has no call that reads back the address a driver bound.
/// The window is one process spawn; a collision fails the subscription
/// loudly, never silently.
fn free_address() -> SocketAddr {
    std::net::UdpSocket::bind(ANY_PORT)
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A reliable unicast channel to `address` over loopback.
fn channel(address: SocketAddr) -> UdpConfig {
    UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        path_skew: None,
        destination: Destination::Unicast(address),
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// A one-lane publication of [`STREAM_ID`] and `session_id`.
fn aggregate(session_id: i32) -> AggregateConfig {
    AggregateConfig {
        stream: StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id,
                stream_id: STREAM_ID,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        },
        quanta: vec![u64::from(DEFAULT_MTU.next_multiple_of(32))],
    }
}

fn key(session_id: i32) -> StreamKey {
    StreamKey {
        stream_id: STREAM_ID,
        session_id,
    }
}

/// A numbered message: its index, then filler.
fn message(index: u32) -> [u8; 256] {
    let mut payload = [0u8; 256];
    payload[..4].copy_from_slice(&index.to_le_bytes());
    payload
}

fn index_of(payload: &[u8]) -> u32 {
    u32::from_le_bytes(payload[..4].try_into().unwrap())
}

/// A child process, killed when the test ends however it ends.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A child running `scenario` against the driver in `dir`, with `arg`,
/// its stdout lines delivered on a channel.
fn spawn(scenario: &str, dir: &Path, arg: &str) -> (Guard, Receiver<String>) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child", "--nocapture", "--test-threads", "1"])
        .env(SCENARIO, scenario)
        .env(DIR, dir)
        .env(ARG, arg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // A child's panic shows in the test's log.
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // libtest may print `test child ... ` on the same line first.
            if let Some(at) = line.find("child: ") {
                let _ = sender.send(line[at + "child: ".len()..].to_string());
            }
        }
    });
    (Guard(child), receiver)
}

/// Writes `line` to the child's stdin: it continues past its next wait.
fn tell(child: &mut Child, line: &str) {
    writeln!(child.stdin.as_mut().unwrap(), "{line}").unwrap();
}

/// Runs both drivers' duty cycles until `done`, within [`STEP`].
fn pump<P: StreamTerms, Q: StreamTerms>(
    a: &mut EmbeddedDriver<P>,
    b: &mut EmbeddedDriver<Q>,
    what: &str,
    mut done: impl FnMut(&mut EmbeddedDriver<P>, &mut EmbeddedDriver<Q>) -> bool,
) {
    let start = Instant::now();
    while !done(a, b) {
        assert!(start.elapsed() < STEP, "not reached: {what}");
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        std::thread::sleep(Duration::from_micros(50));
    }
}

/// Runs both drivers until the child reports a line starting with
/// `prefix`; returns the rest of it.
fn pump_until_report<P: StreamTerms, Q: StreamTerms>(
    a: &mut EmbeddedDriver<P>,
    b: &mut EmbeddedDriver<Q>,
    reports: &Receiver<String>,
    prefix: &str,
) -> String {
    let mut found = None;
    pump(a, b, prefix, |_, _| {
        if let Ok(report) = reports.try_recv() {
            let rest = report
                .strip_prefix(prefix)
                .unwrap_or_else(|| panic!("expected {prefix}, got {report}"));
            found = Some(rest.to_string());
        }
        found.is_some()
    });
    found.unwrap()
}

fn counter<T: StreamTerms>(driver: &EmbeddedDriver<T>, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

/// The open descriptors of shared regions (`/memfd:karyos-region`, as
/// `/proc/self/fd` links name them): what an image or a grant leaks.
/// Sockets are not counted, since a removed publication's socket closes
/// on its own schedule.
fn region_descriptors() -> usize {
    descriptor_targets()
        .iter()
        .filter(|target| target.starts_with("/memfd:karyos-region"))
        .count()
}

/// What each open descriptor names, for a failure's report.
fn descriptor_targets() -> Vec<String> {
    let mut targets: Vec<String> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .map(|target| target.display().to_string())
        .collect();
    targets.sort();
    targets
}

/// Polls `reader` while both drivers run until it has `count` messages,
/// asserting they arrive in order from 0; returns how many arrived.
fn read_in_order<P: StreamTerms, Q: StreamTerms>(
    a: &mut EmbeddedDriver<P>,
    b: &mut EmbeddedDriver<Q>,
    reader: &mut AggregateSubscription<Q>,
    count: u32,
) -> u32 {
    let mut seen = 0u32;
    pump(a, b, "every message", |_, _| {
        let _ = reader.poll(
            |payload, _, _| {
                assert_eq!(index_of(payload), seen, "in order");
                seen += 1;
            },
            BUDGET,
        );
        seen == count
    });
    seen
}

/// Case 1: a remote publisher process on an IPC driver A publishes by
/// `karyos:udp` to driver B; B's in-process subscriber of the image reads
/// the exact sequence.
fn remote_publisher_reaches<Q: StreamTerms>(name: &str, mut b: EmbeddedDriver<Q>) {
    let dir = dir(name);
    let mut a = ipc_driver(&dir, network());
    let _subscription = b
        .add_network_subscription(STREAM_ID, &channel(ANY_PORT))
        .unwrap();
    let address = b.network_subscription_address(STREAM_ID).unwrap();
    let (mut child, reports) = spawn("udp-publish", &dir, &address.to_string());
    let session: i32 = pump_until_report(&mut a, &mut b, &reports, "session ")
        .parse()
        .unwrap();
    let mut image = None;
    pump(&mut a, &mut b, "the image", |_, b| {
        image = b.network_image(STREAM_ID, session);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    tell(&mut child.0, "go");
    assert_eq!(
        read_in_order(&mut a, &mut b, &mut reader, MESSAGES),
        MESSAGES
    );
    assert_eq!(
        pump_until_report(&mut a, &mut b, &reports, "sent "),
        MESSAGES.to_string()
    );
    // The publisher leaves: no message beyond the sequence arrives.
    tell(&mut child.0, "go");
    pump(&mut a, &mut b, "the publisher left", |a, _| {
        a.clients() == 0
    });
    assert!(child.0.wait().unwrap().success());
    let mut extra = 0u32;
    let _ = reader.poll(|_, _, _| extra += 1, BUDGET);
    assert_eq!(extra, 0);
    assert_eq!(counter(&a, "grants exported"), 1);
    assert_eq!(counter(&a, "grants detached"), 1);
}

/// Case 1, heap subscriber.
#[test]
fn a_remote_udp_publisher_process_reaches_a_heap_subscriber() {
    remote_publisher_reaches("pub-heap", heap_driver(network()));
}

/// Case 1, IPC subscriber.
#[test]
fn a_remote_udp_publisher_process_reaches_an_ipc_subscriber() {
    let other = dir("pub-ipc-b");
    remote_publisher_reaches("pub-ipc", ipc_driver(&other, network()));
}

/// The horizon of the timed publication below: the sender's own bound.
const TIMED_HORIZON: u64 = 5_000_000_000;
/// How far ahead the remote timed publisher schedules its first message.
const TIMED_AHEAD: u64 = 200_000_000;

/// T-x2 (quantstratum-docs: karyos/design/timed-tx.md, section 11): a
/// remote process takes a timed lane's handle over the control path, its
/// schedule read from the ring's binding, and its message is sent no
/// earlier than its time. The same process then breaches the ring with a
/// binding of its own making, a time past the sender's horizon: the sender
/// reports it, the lane is sealed with `ScheduleViolation` (the handle
/// meets `Gated`), and the client is retired as faulty. The time
/// namespace refusal needs an unshared time namespace, which this harness
/// cannot create unprivileged: it is covered by the unit tests only.
#[test]
fn a_remote_timed_publisher_is_sent_on_time_and_retired_for_a_breach() {
    const SESSION: i32 = 31;
    let dir = dir("timed");
    let mut a = ipc_driver(&dir, network());
    let mut b = heap_driver(network());
    let _subscription = b
        .add_network_subscription(STREAM_ID, &channel(ANY_PORT))
        .unwrap();
    let address = b.network_subscription_address(STREAM_ID).unwrap();
    let mut config = aggregate(SESSION);
    config.stream.buffer.schedule_capacity = 4;
    let _publication = a
        .add_timed_network_publication(
            config,
            &channel(address),
            None,
            karyos_client::schedule::ScheduleOptions::default().with_max_horizon(TIMED_HORIZON),
        )
        .unwrap();
    let mut image = None;
    pump(&mut a, &mut b, "the image", |_, b| {
        image = b.network_image(STREAM_ID, SESSION);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let (mut child, reports) = spawn("timed-publish", &dir, &SESSION.to_string());
    assert_eq!(
        pump_until_report(&mut a, &mut b, &reports, "bound "),
        TIMED_HORIZON.to_string()
    );
    tell(&mut child.0, "go");
    let at: u64 = pump_until_report(&mut a, &mut b, &reports, "offered ")
        .parse()
        .unwrap();
    let mut read_at = None;
    pump(&mut a, &mut b, "the timed message", |_, _| {
        let _ = reader.poll(
            |payload, _, _| {
                assert_eq!(index_of(payload), 0);
                read_at = Some(karyos_sys::host_clock::host_monotonic_ns());
            },
            BUDGET,
        );
        read_at.is_some()
    });
    let read_at = read_at.unwrap();
    assert!(read_at >= at, "read {} ns before its time", at - read_at);
    // The breach: sealed, counted once, and the client retired as faulty.
    tell(&mut child.0, "breach");
    assert_eq!(
        pump_until_report(&mut a, &mut b, &reports, "gated "),
        format!("{:?}", Some(SealReason::ScheduleViolation))
    );
    pump(&mut a, &mut b, "the client retired", |a, _| {
        counter(a, "clients faulty") == 1
    });
    assert_eq!(counter(&a, "schedule violations"), 1);
    tell(&mut child.0, "go");
    assert!(child.0.wait().unwrap().success());
    // Nothing past the breach reached the subscriber.
    let mut extra = 0u32;
    let _ = reader.poll(|_, _, _| extra += 1, BUDGET);
    assert_eq!(extra, 0);
}

/// Case 2: a remote subscriber process on an IPC driver B subscribes by
/// `karyos:udp`, gets `NetworkSubscription`, then `ImageAvailable` for the
/// image of a heap driver A's publication, takes the image's grant and
/// reads the exact sequence.
#[test]
fn a_remote_udp_subscriber_process_reads_an_image_it_took() {
    let dir = dir("sub");
    let mut b = ipc_driver(&dir, network());
    let mut a = heap_driver(network());
    // A URI names no port 0: the OS picks a free one.
    let address = free_address();
    let (mut child, reports) = spawn("udp-subscribe", &dir, &address.to_string());
    let registration = pump_until_report(&mut a, &mut b, &reports, "subscribed ");
    assert_eq!(b.network_subscription_address(STREAM_ID), Some(address));
    let publication = a
        .add_network_publication(aggregate(3), &channel(address))
        .unwrap();
    assert_eq!(
        pump_until_report(&mut a, &mut b, &reports, "image "),
        format!("{registration} {}", key(3).session_id)
    );
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut sent = 0u32;
    let mut read = None;
    pump(&mut a, &mut b, "the subscriber read", |_, _| {
        while sent < MESSAGES {
            match lane.offer(&message(sent)).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        if let Ok(report) = reports.try_recv() {
            read = Some(report);
        }
        read.is_some()
    });
    assert_eq!(read.unwrap(), format!("received {MESSAGES} in order"));
    tell(&mut child.0, "go");
    pump(&mut a, &mut b, "the subscriber left", |_, b| {
        b.clients() == 0
    });
    assert!(child.0.wait().unwrap().success());
    assert_eq!(counter(&b, "grants exported"), 1);
    assert_eq!(counter(&b, "grants detached"), 1);
}

/// Case 5: a remote publisher process on `karyos:udp` killed in the middle
/// of an offer, after reserving its block and before writing it: the exit
/// proof ends its grant and aborts the reserved range
/// (quantstratum-docs: karyos/design/ipc-data-path.md, d4), its
/// registration ends, and the sender sends past the range to the
/// removal's EOS. The subscriber reads every message before the kill and
/// then a clean end at the EOS.
#[test]
fn a_remote_udp_publisher_killed_mid_offer_is_resolved_and_sent_past() {
    let dir = dir("kill-mid-offer");
    let mut a = ipc_driver(&dir, network());
    let mut b = heap_driver(network());
    let _subscription = b
        .add_network_subscription(STREAM_ID, &channel(ANY_PORT))
        .unwrap();
    let address = b.network_subscription_address(STREAM_ID).unwrap();
    let (mut child, reports) = spawn("udp-publish-kill-at-reserved", &dir, &address.to_string());
    let session: i32 = pump_until_report(&mut a, &mut b, &reports, "session ")
        .parse()
        .unwrap();
    let mut image = None;
    pump(&mut a, &mut b, "the image", |_, b| {
        image = b.network_image(STREAM_ID, session);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    tell(&mut child.0, "go");
    let mut seen = 0u32;
    let mut paused = false;
    pump(&mut a, &mut b, "the writer paused", |_, _| {
        let _ = reader.poll(
            |payload, _, _| {
                assert_eq!(index_of(payload), seen, "in order");
                seen += 1;
            },
            BUDGET,
        );
        if let Ok(report) = reports.try_recv() {
            assert_eq!(report, "paused");
            paused = true;
        }
        paused && seen == MESSAGES
    });
    child.0.kill().unwrap();
    let _ = child.0.wait();
    pump(&mut a, &mut b, "the exit proof", |a, _| a.clients() == 0);
    assert_eq!(counter(&a, "grants ended"), 1);
    let mut end = None;
    let mut terminal = None;
    pump(&mut a, &mut b, "the image's end", |_, _| {
        let poll = reader.poll(|_, _, _| seen += 1, BUDGET);
        end = poll.lanes[0].end;
        terminal = poll.terminal;
        terminal.is_some()
    });
    assert_eq!(seen, MESSAGES, "nothing after the kill");
    let Some(karyos_client::aggregate::LaneEnd::Closed { position, reason }) = end else {
        panic!("not closed: {end:?}");
    };
    assert_eq!(reason, SealReason::EndOfStream);
    // The seal is past the aborted block, one frame after the 200: the
    // sender sent through the range instead of stopping at it, and
    // delivered none of it as data.
    let frame = u64::try_from(32 + 256).unwrap();
    assert_eq!(position, u64::from(MESSAGES + 1) * frame);
    assert!(terminal.unwrap().clean);
}

/// Case 6, resolution 9: the image is retired while a remote `Fetch` of
/// its `Held` grant is in flight. B runs until the image's stream is
/// retiring (held by the grant, so not freed) before the child sends its
/// `Fetch`, so the fetch always meets a retired image. The grant is
/// fetched and then reports closed at the seal (any other outcome, a
/// refusal, a timeout or an error, fails); never left open, and the stream
/// frees once the subscriber leaves.
#[test]
fn an_image_retired_during_a_remote_fetch_never_leaves_the_grant_open() {
    let dir = dir("fetch-retire");
    let mut b = ipc_driver(&dir, network());
    let mut a = heap_driver(network());
    let _subscription = b
        .add_network_subscription(STREAM_ID, &channel(ANY_PORT))
        .unwrap();
    let address = b.network_subscription_address(STREAM_ID).unwrap();
    let publication = a
        .add_network_publication(aggregate(3), &channel(address))
        .unwrap();
    let mut image = None;
    pump(&mut a, &mut b, "the image", |_, b| {
        image = b.network_image(STREAM_ID, 3);
        image.is_some()
    });
    let lane = image.unwrap().lane(Lane::ZERO).unwrap();
    let (mut child, reports) = spawn("image-fetch-on-go", &dir, "3");
    let _ = pump_until_report(&mut a, &mut b, &reports, "granted");
    a.remove_aggregate(&publication).unwrap();
    pump(&mut a, &mut b, "the image retiring", |_, b| {
        b.stream_state(lane).unwrap() == karyos_driver::StreamState::Retiring
    });
    tell(&mut child.0, "go");
    let _ = pump_until_report(&mut a, &mut b, &reports, "fetching");
    let outcome = pump_until_report(&mut a, &mut b, &reports, "");
    println!("case 6 branch: {outcome}");
    // A refusal is unreachable in this ordering: the `Held` grant keeps
    // the retiring stream (it frees only once no grant names it), so
    // admission still finds its buffer and serves the `Fetch`. A change
    // that makes a retiring stream's fetch refused fails here, not passes.
    assert_eq!(outcome, "closed EndOfStream");
    pump(&mut a, &mut b, "the subscriber left", |_, b| {
        b.clients() == 0
    });
    assert!(child.0.wait().unwrap().success());
    // Closed at the seal and the subscriber gone, nothing holds the
    // image's stream any more: `network_image` hides a retiring stream,
    // so the state is read.
    pump(&mut a, &mut b, "the image freed", |_, b| {
        b.stream_state(lane).unwrap() == karyos_driver::StreamState::Freed
    });
}

/// Case 7: many image install and retire rounds with a remote subscriber
/// leave the driver's descriptor count where it started. The drivers run
/// in a child process of their own, which spawns the subscriber, so no
/// other test's descriptors are counted.
#[test]
fn image_rounds_with_remote_subscribers_keep_the_descriptor_count() {
    let dir = dir("image-descriptors");
    let (mut child, reports) = spawn("image-descriptor-driver", &dir, "");
    let report = reports.recv_timeout(Duration::from_secs(120)).unwrap();
    assert_eq!(report, "descriptors stable");
    assert!(child.0.wait().unwrap().success());
}

/// Image rounds of the descriptor test, after its warm-up round. With the
/// warm-up they make 16 registrations, the remote client's cap
/// (`max_exports_per_client`), so a reclaim regression shows as leaked
/// region descriptors in the report, not as a refused 17th subscription.
const ROUNDS: i32 = 15;

/// One image round: A publishes `session`, B installs its image, the
/// remote subscriber takes and reads it, A removes the publication, and
/// the subscriber reads the image closed and drops it.
fn image_round(
    a: &mut EmbeddedDriver,
    b: &mut IpcDriver,
    client: &mut Child,
    reports: &Receiver<String>,
    address: SocketAddr,
    session: i32,
) {
    let detached = counter(b, "grants detached");
    let publication = a
        .add_network_publication(aggregate(session), &channel(address))
        .unwrap();
    pump(a, b, "the image", |_, b| {
        b.network_image(STREAM_ID, session).is_some()
    });
    tell(client, &session.to_string());
    assert_eq!(
        pump_until_report(a, b, reports, "taken "),
        session.to_string()
    );
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut sent = 0u32;
    pump(a, b, "a round's messages", |_, _| {
        while sent < 8 {
            match lane.offer(&message(sent)).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        sent == 8
    });
    drop(lane);
    a.remove_aggregate(&publication).unwrap();
    assert_eq!(
        pump_until_report(a, b, reports, "closed "),
        format!("{session} read 8")
    );
    // The grant's Detach, then the image gone.
    pump(a, b, "the grant detached", |_, b| {
        counter(b, "grants detached") == detached + 1
            && b.network_image(STREAM_ID, session).is_none()
    });
}

/// The driver side of the descriptor test, in its own process.
fn image_descriptor_driver(dir: &Path) {
    let mut b = ipc_driver(dir, network());
    // No linger: a removed publication gives its sockets back at once.
    let mut quick = network();
    quick.stream_defaults.publication_linger = 0;
    let mut a = heap_driver(quick);
    let _subscription = b
        .add_network_subscription(STREAM_ID, &channel(ANY_PORT))
        .unwrap();
    let address = b.network_subscription_address(STREAM_ID).unwrap();
    let (mut client, reports) = spawn("image-subscribe-rounds", dir, "");
    let _ = pump_until_report(&mut a, &mut b, &reports, "attached");
    // Warm up: the first round creates what the drivers keep.
    image_round(&mut a, &mut b, &mut client.0, &reports, address, 1);
    let before = region_descriptors();
    let before_targets = descriptor_targets();
    let detached = counter(&b, "grants detached");
    for session in 2..2 + ROUNDS {
        image_round(&mut a, &mut b, &mut client.0, &reports, address, session);
    }
    // The last image's regions go once its stream frees: run until the
    // count is back, within a bound, so a leak shows as a difference.
    let mut after = region_descriptors();
    let start = Instant::now();
    while after != before && start.elapsed() < Duration::from_secs(5) {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        std::thread::sleep(Duration::from_millis(1));
        after = region_descriptors();
    }
    let after_targets = descriptor_targets();
    let rounds = u64::try_from(ROUNDS).unwrap();
    tell(&mut client.0, "leave");
    pump(&mut a, &mut b, "the subscriber left", |_, b| {
        b.clients() == 0
    });
    assert!(client.0.wait().unwrap().success());
    if after != before || counter(&b, "grants detached") != detached + rounds {
        report(&format!(
            "region descriptors before {before} after {after}, detached {} of {}, before {before_targets:?} after {:?}",
            counter(&b, "grants detached") - detached,
            rounds,
            after_targets
        ));
        return;
    }
    report("descriptors stable");
}

fn report(line: &str) {
    // A newline first: libtest may have started a line without ending it.
    let mut stdout = std::io::stdout();
    writeln!(stdout, "\nchild: {line}").unwrap();
    stdout.flush().unwrap();
}

/// The next line the parent writes.
fn wait_for_line() -> String {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    line.trim().to_string()
}

/// The next completion of `client`, within [`STEP`].
fn next_outcome(client: &mut RemoteClient) -> Outcome {
    let mut outcome = None;
    let start = Instant::now();
    while outcome.is_none() {
        assert!(start.elapsed() < STEP, "no completion");
        let _ = client.poll(usize::MAX, |completion| outcome = Some(completion.outcome));
        std::thread::yield_now();
    }
    outcome.unwrap()
}

fn fetchable(outcome: Outcome) -> Fetchable {
    match outcome {
        Outcome::Fetchable(grant) => grant,
        other => panic!("expected a grant, got {other:?}"),
    }
}

/// Takes the publication of a `karyos:udp` channel to `address`.
fn udp_publication(
    client: &mut RemoteClient,
    address: &str,
) -> karyos_client::ClientPublication<SharedTerms> {
    let uri = format!("karyos:udp?endpoint={address}|interface=127.0.0.1");
    let _ = client
        .add_network_publication(&uri, STREAM_ID, false)
        .unwrap();
    let grant = fetchable(next_outcome(client));
    client.take_publication(&grant).unwrap()
}

/// Offers `payload` until accepted, within [`STEP`].
fn offer(publication: &mut karyos_client::ClientPublication<SharedTerms>, payload: &[u8]) {
    let start = Instant::now();
    while !matches!(
        publication.offer(payload).unwrap(),
        OfferOutcome::Accepted { .. }
    ) {
        assert!(start.elapsed() < STEP, "offer");
        std::thread::yield_now();
    }
}

/// Reports the pause and waits to be killed; bounded, so a failed parent
/// never leaves this process behind.
fn pause_here(_: karyos_sys::test_pause::PausePoint) {
    report("paused");
    std::thread::sleep(Duration::from_secs(30));
    std::process::exit(1);
}

/// Subscribes to the image `session` and takes its grant.
fn take_image(
    client: &mut RemoteClient,
    session: i32,
) -> karyos_client::ClientSubscription<SharedTerms> {
    let _ = client
        .add_subscription(key(session), SubscriberRole::Required)
        .unwrap();
    let grant = fetchable(next_outcome(client));
    client.take_subscription(&grant).unwrap()
}

/// Polls `subscription` until it reports closed; returns the messages
/// read, in order from 0, and the close reason.
fn read_to_close(
    subscription: &mut karyos_client::ClientSubscription<SharedTerms>,
) -> (u32, Option<SealReason>) {
    let mut seen = 0u32;
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < STEP, "never closed after {seen}");
        let summary = subscription
            .poll(
                |payload, _| {
                    assert_eq!(index_of(payload), seen, "in order");
                    seen += 1;
                },
                MessageLimit::new(64),
            )
            .unwrap();
        if summary.closed.is_some() {
            return (seen, summary.close_reason);
        }
        std::thread::yield_now();
    }
}

/// Runs only as a child process of the tests above.
#[test]
fn child() {
    let (Some(scenario), Some(dir)) = (std::env::var_os(SCENARIO), std::env::var_os(DIR)) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let arg = std::env::var(ARG).unwrap_or_default();
    let timeout = Duration::from_secs(5);
    match scenario.to_str().unwrap() {
        "udp-publish" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let mut publication = udp_publication(&mut client, &arg);
            report(&format!("session {}", publication.stream().session_id));
            let _ = wait_for_line();
            for index in 0..MESSAGES {
                offer(&mut publication, &message(index));
            }
            report(&format!("sent {MESSAGES}"));
            let _ = wait_for_line();
            drop(publication);
            drop(client);
        }
        "timed-publish" => {
            use karyos_client::schedule::{ScheduleBinding, ScheduleClock};

            let session: i32 = arg.parse().unwrap();
            let mut client = attach(&dir, timeout, 16).unwrap();
            let _ = client.add_publication(key(session), false).unwrap();
            let grant = fetchable(next_outcome(&mut client));
            let mut publication = client.take_publication(&grant).unwrap();
            let options = publication.schedule().unwrap().options();
            report(&format!("bound {}", options.max_horizon));
            let _ = wait_for_line();
            let at = karyos_sys::host_clock::host_monotonic_ns() + TIMED_AHEAD;
            let start = Instant::now();
            while !matches!(
                publication.offer_at(&message(0), at).unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                assert!(start.elapsed() < STEP, "offer_at");
                std::thread::yield_now();
            }
            report(&format!("offered {at}"));
            let _ = wait_for_line();
            // A hostile publisher: its own, looser binding, and a time
            // past the sender's horizon, which the sender alone checks.
            let hostile = options.with_max_horizon(u64::MAX / 2);
            let mut publication = publication.with_schedule(ScheduleBinding::new(
                hostile,
                ScheduleClock::host(hostile.domain).unwrap(),
            ));
            let far = karyos_sys::host_clock::host_monotonic_ns() + 100 * TIMED_HORIZON;
            let start = Instant::now();
            let gated = loop {
                assert!(start.elapsed() < STEP, "never gated");
                let outcome = publication.offer_at(&message(1), far);
                if matches!(outcome, Ok(OfferOutcome::Gated)) {
                    break publication.seal_reason();
                }
                std::thread::yield_now();
            };
            report(&format!("gated {gated:?}"));
            let _ = wait_for_line();
            drop(publication);
            drop(client);
        }
        "udp-publish-kill-at-reserved" => {
            use karyos_sys::test_pause::{PausePoint, arm};
            let mut client = attach(&dir, timeout, 16).unwrap();
            let mut publication = udp_publication(&mut client, &arg);
            report(&format!("session {}", publication.stream().session_id));
            let _ = wait_for_line();
            for index in 0..MESSAGES {
                offer(&mut publication, &message(index));
            }
            arm(PausePoint::ExclusiveReserved, pause_here);
            offer(&mut publication, &message(MESSAGES));
            panic!("never paused");
        }
        "udp-subscribe" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            let _ = client
                .add_network_subscription(
                    &format!("karyos:udp?endpoint={arg}"),
                    STREAM_ID,
                    SubscriberRole::Required,
                )
                .unwrap();
            let Outcome::NetworkSubscription { registration, .. } = next_outcome(&mut client)
            else {
                panic!("no network subscription");
            };
            report(&format!("subscribed {registration}"));
            let mut available = None;
            let start = Instant::now();
            while available.is_none() {
                assert!(start.elapsed() < STEP, "no ImageAvailable");
                let _ = client.poll(usize::MAX, |completion| {
                    panic!("unexpected {:?}", completion.outcome)
                });
                for event in client.take_events() {
                    if let Event::ImageAvailable {
                        stream,
                        registration: of,
                        ..
                    } = event
                    {
                        assert_eq!(of, registration);
                        available = Some(stream);
                    }
                }
                std::thread::yield_now();
            }
            let stream = available.unwrap();
            assert_eq!(stream.stream_id, STREAM_ID);
            let mut subscription = take_image(&mut client, stream.session_id);
            report(&format!("image {registration} {}", stream.session_id));
            let mut seen = 0u32;
            let start = Instant::now();
            while seen < MESSAGES {
                assert!(start.elapsed() < STEP, "stalled at {seen}");
                let _ = subscription
                    .poll(
                        |payload, _| {
                            assert_eq!(index_of(payload), seen, "in order");
                            seen += 1;
                        },
                        MessageLimit::new(64),
                    )
                    .unwrap();
                std::thread::yield_now();
            }
            report(&format!("received {MESSAGES} in order"));
            let _ = wait_for_line();
            drop(subscription);
            drop(client);
        }
        "image-fetch-on-go" => {
            let session: i32 = arg.parse().unwrap();
            let mut client = attach(&dir, timeout, 16).unwrap();
            let _ = client
                .add_subscription(key(session), SubscriberRole::Required)
                .unwrap();
            let grant = fetchable(next_outcome(&mut client));
            report("granted");
            let _ = wait_for_line();
            report("fetching");
            match client.take_subscription(&grant) {
                Err(karyos_client::ipc::AttachError::Refused { .. }) => report("refused"),
                Err(other) => report(&format!("failed {other:?}")),
                Ok(mut subscription) => {
                    let (_, reason) = read_to_close(&mut subscription);
                    report(&format!("closed {:?}", reason.unwrap()));
                }
            }
            drop(client);
        }
        "image-subscribe-rounds" => {
            let mut client = attach(&dir, timeout, 16).unwrap();
            report("attached");
            loop {
                let line = wait_for_line();
                if line == "leave" {
                    break;
                }
                let session: i32 = line.parse().unwrap();
                let mut subscription = take_image(&mut client, session);
                report(&format!("taken {session}"));
                let (seen, _) = read_to_close(&mut subscription);
                drop(subscription);
                report(&format!("closed {session} read {seen}"));
            }
            drop(client);
        }
        "image-descriptor-driver" => image_descriptor_driver(&dir),
        other => panic!("unknown scenario {other}"),
    }
}
