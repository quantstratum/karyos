// SPDX-License-Identifier: Apache-2.0

//! The `karyosd` binary (Linux; `quantstratum-docs:
//! karyos/design/observability-and-tools.md`, Binaries and its tests): it
//! starts, admits a client process (this test process), and exits 0 on
//! `SIGTERM` after the client leaves and 3 when a client stays attached
//! past the linger; a startup error exits 2. Signals are sent with the
//! system `kill` tool, so the tests need no new dependency.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use karyos_client::Outcome;
use karyos_client::ipc::{RemoteClient, attach};
use karyos_protocol::cnc::StreamKey;

/// The stream `karyosd` configures in these tests.
const KEY: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyosd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A `karyosd` process, killed when the test ends however it ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// Sends `SIGTERM` (no libc: the system `kill` tool).
    fn terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Waits at most `limit` for the exit.
    fn wait(&mut self, limit: Duration) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(start.elapsed() < limit, "karyosd did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Starts `karyosd` on `dir` with one stream and `linger`.
fn start(dir: &Path, linger: &str) -> Daemon {
    start_with(dir, linger, &[])
}

/// As [`start`], with `extra` arguments.
fn start_with(dir: &Path, linger: &str, extra: &[&str]) -> Daemon {
    start_logging(dir, linger, extra, Stdio::null())
}

/// As [`start_with`], its log on `stderr`.
fn start_logging(dir: &Path, linger: &str, extra: &[&str], stderr: Stdio) -> Daemon {
    let child = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--dir")
        .arg(dir)
        .args([
            "--stream",
            &format!("{}:{}", KEY.stream_id, KEY.session_id),
            "--term-length",
            "64k",
            "--shutdown-linger",
            linger,
            "--log-level",
            "warn",
        ])
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .unwrap();
    Daemon(child)
}

/// Attaches once the daemon's socket answers, within a bounded wait.
fn attach_when_ready(dir: &Path) -> RemoteClient {
    let start = Instant::now();
    loop {
        match attach(dir, Duration::from_secs(5), 16) {
            Ok(client) => return client,
            Err(error) => {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "attach failed: {error:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Takes the stream's publication through a grant, so that the stream has
/// a registration and an export to retire, then drops it.
fn publish_once(client: &mut RemoteClient) {
    let _ = client.add_publication(KEY, true).unwrap();
    let mut fetchable = None;
    let start = Instant::now();
    while fetchable.is_none() {
        assert!(start.elapsed() < Duration::from_secs(10), "no grant");
        let _ = client.poll(usize::MAX, |completion| match completion.outcome {
            Outcome::Fetchable(grant) => fetchable = Some(grant),
            other => panic!("expected a grant, got {other:?}"),
        });
        std::thread::yield_now();
    }
    let publication = client.take_publication(&fetchable.unwrap()).unwrap();
    drop(publication);
}

#[test]
fn karyosd_exits_0_on_sigterm_after_the_client_leaves() {
    let dir = dir("clean");
    let mut daemon = start(&dir, "5s");
    let mut client = attach_when_ready(&dir);
    publish_once(&mut client);
    drop(client);
    daemon.terminate();
    let status = daemon.wait(Duration::from_secs(10));
    assert_eq!(status.code(), Some(0), "{status:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn karyosd_exits_3_when_a_client_stays_past_the_linger() {
    let dir = dir("linger");
    let mut daemon = start(&dir, "200ms");
    let mut client = attach_when_ready(&dir);
    publish_once(&mut client);
    daemon.terminate();
    let status = daemon.wait(Duration::from_secs(10));
    assert_eq!(status.code(), Some(3), "{status:?}");
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn karyosd_refuses_new_clients_once_shutting_down() {
    let dir = dir("refuse");
    let mut daemon = start(&dir, "5s");
    let client = attach_when_ready(&dir);
    daemon.terminate();
    // The daemon stays up while the first client is attached; a new
    // client is refused within the linger.
    let start = Instant::now();
    loop {
        match attach(&dir, Duration::from_secs(5), 16) {
            Err(karyos_client::ipc::AttachError::Refused { code }) => {
                assert_eq!(
                    code,
                    karyos_protocol::admission::refusal::SHUTTING_DOWN,
                    "refused for another reason"
                );
                break;
            }
            Ok(late) => drop(late),
            Err(error) => panic!("{error:?}"),
        }
        assert!(start.elapsed() < Duration::from_secs(4), "never refused");
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(client);
    let status = daemon.wait(Duration::from_secs(10));
    assert_eq!(status.code(), Some(0), "{status:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn karyosd_exits_2_on_a_startup_error() {
    // The driver refuses a zero client limit.
    let dir = dir("startup");
    let output = Command::new(env!("CARGO_BIN_EXE_karyosd"))
        .arg("--dir")
        .arg(&dir)
        .args(["--max-clients", "0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("karyosd: "), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--network on`: through two `karyosd` processes, a client of one creates
/// a `karyos:udp` subscription and a client of the other an exclusive
/// publication, by URI, on loopback, and the subscriber reads what the
/// publisher offers (SPEC §10). Without the flag a network subscription is
/// refused: the daemon runs no network agents.
#[test]
fn karyosd_with_the_network_carries_a_udp_pair() {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    use karyos_client::{Client, Context, MessageLimit, OfferError, StreamId};

    let port = test_port();
    let context = |dir: &Path| {
        Context::builder()
            .dir(dir)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
    };
    let (receiving, sending) = (dir("network-rx"), dir("network-tx"));
    let mut receiver = start_with(&receiving, "1s", &["--network", "on"]);
    let mut sender = start_with(&sending, "1s", &["--network", "on"]);
    drop(attach_when_ready(&receiving));
    drop(attach_when_ready(&sending));
    let mut subscriber = Client::connect(context(&receiving)).unwrap();
    let mut publisher = Client::connect(context(&sending)).unwrap();
    let mut reading = subscriber
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(7),
        )
        .unwrap();
    let mut publication = publisher
        .add_exclusive_publication(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
            StreamId::new(7),
        )
        .unwrap();
    // The image joins where it attaches: offers before it are not seen.
    let began = Instant::now();
    while reading.image_count() == 0 {
        assert!(began.elapsed() < Duration::from_secs(20), "no image");
        let _ = (subscriber.poll(), publisher.poll());
        let _ = reading.poll(|_, _| {}, MessageLimit::new(0));
        std::thread::sleep(Duration::from_millis(1));
    }
    let (mut sent, mut seen) = (0u32, 0u32);
    while seen < 16 {
        assert!(began.elapsed() < Duration::from_secs(30), "seen {seen}");
        let _ = (subscriber.poll(), publisher.poll());
        while sent < 16 {
            match publication.offer(&sent.to_le_bytes()) {
                Ok(_) => sent += 1,
                Err(
                    OfferError::BackPressured | OfferError::AdminAction | OfferError::NotConnected,
                ) => break,
                Err(error) => panic!("{error}"),
            }
        }
        let _ = reading
            .poll(
                |bytes, _| {
                    assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), seen);
                    seen += 1;
                },
                MessageLimit::new(16),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    drop((reading, publication, subscriber, publisher));
    for daemon in [&mut receiver, &mut sender] {
        daemon.terminate();
        assert_eq!(daemon.wait(Duration::from_secs(10)).code(), Some(0));
    }
    // Off, the default: a network subscription is refused.
    let dir = self::dir("no-network");
    let mut daemon = start(&dir, "1s");
    drop(attach_when_ready(&dir));
    let mut client = Client::connect(context(&dir)).unwrap();
    assert!(
        client
            .add_subscription(
                &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
                StreamId::new(7),
            )
            .is_err()
    );
    drop(client);
    daemon.terminate();
    assert_eq!(daemon.wait(Duration::from_secs(10)).code(), Some(0));
}

/// M3b: with the network on, `karyosd` logs an endpoint's capabilities
/// when it first appears: one line naming every capability and its state.
#[test]
fn karyosd_logs_an_endpoints_capabilities_when_it_appears() {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    use karyos_client::{Client, Context, StreamId};

    let port = test_port();
    let dir = dir("capabilities");
    let log = std::env::temp_dir().join(format!("karyosd-{}-capabilities.log", std::process::id()));
    let file = std::fs::File::create(&log).unwrap();
    let mut daemon = start_logging(
        &dir,
        "1s",
        &["--network", "on", "--log-level", "info"],
        Stdio::from(file),
    );
    drop(attach_when_ready(&dir));
    let context = Context::builder()
        .dir(&dir)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let mut client = Client::connect(context).unwrap();
    let reading = client
        .add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            StreamId::new(7),
        )
        .unwrap();
    let began = Instant::now();
    let line = loop {
        assert!(
            began.elapsed() < Duration::from_secs(20),
            "no capability log"
        );
        let _ = client.poll();
        let text = std::fs::read_to_string(&log).unwrap();
        if let Some(line) = text
            .lines()
            .find(|line| line.contains("endpoint capabilities"))
        {
            break line.to_owned();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    for capability in [
        "epoch=1",
        "platform=linux",
        "copy_mode=staged",
        "queue_assignment=kernel_selected",
        "max_datagram=",
        "observation_points=",
        "clock_granularity=",
        "send_buffer_bytes=",
        "recv_buffer_bytes=",
        "dont_fragment=",
        "tx_batch=",
        "rx_batch=",
        "gso=unavailable(library_api)",
        "gro=",
        "kernel_stamps=",
        "hardware_stamps=",
        "busy_poll=",
        "user_observations=active",
        "send_buffer=",
        "recv_buffer=",
    ] {
        assert!(line.contains(capability), "{capability} not in {line}");
    }
    drop((reading, client));
    daemon.terminate();
    assert_eq!(daemon.wait(Duration::from_secs(10)).code(), Some(0));
    // Logged once: the endpoint did not reopen.
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("endpoint capabilities"))
            .count(),
        1,
        "{text}"
    );
    let _ = std::fs::remove_file(&log);
}

/// A loopback UDP port no socket holds now, picked below every ephemeral
/// range (Linux 32768 to 60999, macOS 49152 to 65535), so no bind to port
/// 0 can take it before the driver binds it (karyos#520). As karyos-driver's
/// `test_ports`: a process starts at its own offset and walks the range,
/// skipping ports it cannot bind. Owner item 26 (an `endpoint=host:0`
/// subscription that reports its port) would remove the race.
fn test_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    const FIRST: u32 = 20_000;
    const COUNT: u32 = 12_000;
    let start = std::process::id().wrapping_mul(2_654_435_761) % COUNT;
    loop {
        let taken = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(taken < COUNT, "no free test port left in the range");
        let port = u16::try_from(FIRST + (start + taken) % COUNT).unwrap();
        if std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}
