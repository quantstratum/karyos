// SPDX-License-Identifier: Apache-2.0

//! The workloads between processes (Linux; SPEC.md §12, "IPC between
//! processes"): the benchmark runs an IPC driver and one side of the
//! exchange, and a child process, this binary run again, attaches to the
//! driver as a remote client and runs the other side over shared terms.
//!
//! - `ipc-ping-pong`: the parent offers on stream 1 and polls stream 2
//!   in process; the child polls stream 1 and echoes on stream 2. The
//!   parent records each round trip.
//! - `ipc-throughput`: the parent offers on stream 1; the child reads every
//!   message. The rate is the parent's accepted offers per second over the
//!   measured phase, once the child read them all.
//!
//! The child learns its part from [`CHILD`], set on its environment; a
//! binary that runs workloads calls [`child`] first, and a test binary
//! names the test that does so in [`CHILD_TEST`]. The driver's duty runs
//! on its own thread in the parent; the child polls its control path only
//! to take its grants, and the client liveness timeout is long enough
//! that it never has to beat during a run.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use karyos_client::ipc::{RemoteClient, attach};
use karyos_client::{ClientSubscription, MessageLimit, OfferOutcome, Outcome};
use karyos_driver::{
    DriverConfig, EmbeddedDriver, IpcConfig, StreamConfig, StreamHandle, SystemClock,
};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

use crate::workloads::{
    BenchError, Config, Measurement, Workload, error, histogram, record, resolution,
};

/// The environment variable that makes a process the child of an IPC
/// workload: `<workload>:<message bytes>:<messages>:<admission directory>`.
pub const CHILD: &str = "KARYOS_BENCH_IPC_CHILD";

/// The test a test binary runs as the child: the arguments the parent
/// passes select it, and the benchmark binary ignores them.
pub const CHILD_TEST: &str = "ipc_child";

const PING: StreamKey = StreamKey {
    stream_id: 1,
    session_id: 1,
};
const PONG: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

type IpcDriver = EmbeddedDriver<SharedTerms>;

/// A child process, killed if the workload ends before it does.
struct Guard(Option<Child>);

impl Guard {
    /// Waits at most `limit` for the child to exit successfully.
    fn finish(mut self, limit: Duration) -> Result<(), BenchError> {
        let Some(mut child) = self.0.take() else {
            return Ok(());
        };
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().map_err(|cause| error("child", cause))? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(BenchError(format!("the child process failed: {status}")))
                };
            }
            if start.elapsed() > limit {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BenchError("the child process did not finish".into()));
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A private directory for the admission socket.
fn private_dir() -> Result<PathBuf, BenchError> {
    use std::os::unix::fs::PermissionsExt;
    static RUNS: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "karyos-bench-ipc-{}-{}",
        std::process::id(),
        RUNS.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).map_err(|cause| error("directory", cause))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|cause| error("directory", cause))?;
    Ok(dir)
}

fn driver(dir: &Path) -> Result<IpcDriver, BenchError> {
    EmbeddedDriver::with_ipc(
        DriverConfig {
            // The child does not beat while it measures.
            client_liveness_timeout: 3_600_000_000_000,
            ..DriverConfig::default()
        },
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 2,
            hello_timeout: 5_000_000_000,
            max_outbound_per_client: 8,
            fetch_deadline: 5_000_000_000,
            max_exports_per_client: 4,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
        },
        Box::new(SystemClock::new()),
    )
    .map_err(|cause| error("driver", cause))
}

fn stream(
    driver: &mut IpcDriver,
    key: StreamKey,
    config: &Config,
) -> Result<StreamHandle, BenchError> {
    let term_length =
        TermLength::try_new(config.term_length).map_err(|cause| error("term length", cause))?;
    driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length,
                spare_slots: 6,
                max_subscribers: 2,
                mtu: DEFAULT_MTU,
                max_reserved: config.term_length / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: key.session_id,
                stream_id: key.stream_id,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
            },
            allow_unconnected: false,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
            conflation: None,
        })
        .map_err(|cause| error("stream", cause))
}

/// Runs the driver's duty on its own thread until `stop` is set.
fn duty_thread(
    mut driver: IpcDriver,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<(), BenchError>> {
    thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            let _ = driver.do_work().map_err(|cause| error("duty", cause))?;
            thread::yield_now();
        }
        Ok(())
    })
}

fn join(handle: thread::JoinHandle<Result<(), BenchError>>) -> Result<(), BenchError> {
    handle
        .join()
        .map_err(|_| BenchError("the duty thread panicked".into()))?
}

/// Starts the child of `config` against the driver in `dir`.
fn spawn(config: &Config, dir: &Path) -> Result<Guard, BenchError> {
    let total = config.warmup + config.iterations;
    let child = Command::new(std::env::current_exe().map_err(|cause| error("executable", cause))?)
        .args(["--exact", CHILD_TEST, "--test-threads", "1"])
        .env(
            CHILD,
            format!(
                "{}:{}:{total}:{}",
                config.workload.name(),
                config.message,
                dir.display()
            ),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|cause| error("child", cause))?;
    Ok(Guard(Some(child)))
}

/// Offers `payload` until it is accepted; a stream with no subscriber yet
/// (the child still attaching) is retried.
fn offer(
    publication: &mut karyos_client::ClientPublication<SharedTerms>,
    payload: &[u8],
) -> Result<(), BenchError> {
    loop {
        match publication
            .offer(payload)
            .map_err(|cause| error("offer", cause))?
        {
            OfferOutcome::Accepted { .. } => return Ok(()),
            OfferOutcome::Closed => return Err(BenchError("the stream closed".into())),
            _ => thread::yield_now(),
        }
    }
}

/// Polls until one message arrives.
fn receive(subscription: &mut ClientSubscription<SharedTerms>) -> Result<(), BenchError> {
    loop {
        let summary = subscription
            .poll(|_, _| {}, MessageLimit::new(1))
            .map_err(|cause| error("poll", cause))?;
        if summary.delivered == 1 {
            return Ok(());
        }
        if summary.closed.is_some() {
            return Err(BenchError("the stream closed".into()));
        }
        thread::yield_now();
    }
}

/// `ipc-ping-pong`: see the module documentation.
///
/// # Errors
///
/// Returns the first driver, client or child error.
pub fn ping_pong(config: Config) -> Result<Measurement, BenchError> {
    let resolution = resolution();
    let dir = private_dir()?;
    let mut driver = driver(&dir)?;
    let ping = stream(&mut driver, PING, &config)?;
    let pong = stream(&mut driver, PONG, &config)?;
    let mut ping_out = driver
        .publication(ping)
        .map_err(|cause| error("publication", cause))?;
    let mut pong_in = driver
        .subscribe(pong, Role::Required)
        .map_err(|cause| error("subscribe", cause))?;
    let stop = Arc::new(AtomicBool::new(false));
    let duty = duty_thread(driver, Arc::clone(&stop));
    let child = spawn(&config, &dir)?;
    let payload = vec![7u8; config.message];
    let mut latencies = histogram()?;
    let mut measured_from = Instant::now();
    let mut outcome = Ok(());
    for iteration in 0..config.warmup + config.iterations {
        if iteration == config.warmup {
            measured_from = Instant::now();
        }
        let begin = Instant::now();
        if let Err(cause) = offer(&mut ping_out, &payload).and_then(|()| receive(&mut pong_in)) {
            outcome = Err(cause);
            break;
        }
        if iteration >= config.warmup {
            record(&mut latencies, begin.elapsed().as_nanos(), resolution)?;
        }
    }
    let seconds = measured_from.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    let finished = outcome.and_then(|()| child.finish(Duration::from_secs(30)));
    stop.store(true, Ordering::Release);
    join(duty)?;
    let _ = std::fs::remove_dir_all(&dir);
    finished?;
    Ok(Measurement {
        config,
        latency: Some(latencies),
        producer_lateness: None,
        rate: config.iterations as f64 / seconds,
        resolution,
        cleaned_slots_per_second: None,
        term_rotations_per_second: None,
    })
}

/// `ipc-throughput`: see the module documentation.
///
/// # Errors
///
/// Returns the first driver, client or child error.
pub fn throughput(config: Config) -> Result<Measurement, BenchError> {
    let resolution = resolution();
    let dir = private_dir()?;
    let mut driver = driver(&dir)?;
    let ping = stream(&mut driver, PING, &config)?;
    let mut out = driver
        .publication(ping)
        .map_err(|cause| error("publication", cause))?;
    let stop = Arc::new(AtomicBool::new(false));
    let duty = duty_thread(driver, Arc::clone(&stop));
    let child = spawn(&config, &dir)?;
    let payload = vec![7u8; config.message];
    let mut outcome = Ok(());
    for _ in 0..config.warmup {
        if let Err(cause) = offer(&mut out, &payload) {
            outcome = Err(cause);
            break;
        }
    }
    let measured_from = Instant::now();
    if outcome.is_ok() {
        for _ in 0..config.iterations {
            if let Err(cause) = offer(&mut out, &payload) {
                outcome = Err(cause);
                break;
            }
        }
    }
    // The child read every message once it exits successfully.
    let finished = outcome.and_then(|()| child.finish(Duration::from_secs(30)));
    let seconds = measured_from.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    stop.store(true, Ordering::Release);
    join(duty)?;
    let _ = std::fs::remove_dir_all(&dir);
    finished?;
    Ok(Measurement {
        config,
        latency: None,
        producer_lateness: None,
        rate: config.iterations as f64 / seconds,
        resolution,
        cleaned_slots_per_second: None,
        term_rotations_per_second: None,
    })
}

/// Takes the grant `request` asked for, polling the control path.
fn grant(client: &mut RemoteClient) -> Result<karyos_client::Fetchable, BenchError> {
    let start = Instant::now();
    loop {
        let mut fetchable = None;
        let _ = client.poll(usize::MAX, |completion| {
            if let Outcome::Fetchable(grant) = completion.outcome {
                fetchable = Some(grant);
            }
        });
        if let Some(fetchable) = fetchable {
            return Ok(fetchable);
        }
        if start.elapsed() > Duration::from_secs(10) {
            return Err(BenchError("no grant".into()));
        }
        thread::sleep(Duration::from_micros(100));
    }
}

/// Runs the child part when [`CHILD`] is set: `None` otherwise.
#[must_use]
pub fn child() -> Option<Result<(), BenchError>> {
    let spec = std::env::var(CHILD).ok()?;
    Some(run_child(&spec))
}

fn run_child(spec: &str) -> Result<(), BenchError> {
    let mut parts = spec.splitn(4, ':');
    let (Some(workload), Some(message), Some(total), Some(dir)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(BenchError(format!("bad child spec {spec}")));
    };
    let workload =
        Workload::parse(workload).ok_or_else(|| BenchError(format!("no workload {workload}")))?;
    let message: usize = message.parse().map_err(|cause| error("message", cause))?;
    let total: u64 = total.parse().map_err(|cause| error("messages", cause))?;
    let mut client = attach(Path::new(dir), Duration::from_secs(5), 16)
        .map_err(|cause| error("attach", cause))?;
    let _ = client
        .add_subscription(PING, SubscriberRole::Required)
        .map_err(|cause| error("subscribe", cause))?;
    let fetchable = grant(&mut client)?;
    let mut ping_in = client
        .take_subscription(&fetchable)
        .map_err(|cause| error("take subscription", cause))?;
    match workload {
        Workload::IpcPingPong => {
            let _ = client
                .add_publication(PONG, false)
                .map_err(|cause| error("publication", cause))?;
            let fetchable = grant(&mut client)?;
            let mut pong_out = client
                .take_publication(&fetchable)
                .map_err(|cause| error("take publication", cause))?;
            let payload = vec![9u8; message];
            for _ in 0..total {
                receive(&mut ping_in)?;
                offer(&mut pong_out, &payload)?;
            }
        }
        Workload::IpcThroughput => {
            let mut read = 0u64;
            while read < total {
                let summary = ping_in
                    .poll(|_, _| {}, MessageLimit::new(64))
                    .map_err(|cause| error("poll", cause))?;
                read += u64::from(summary.delivered);
                if summary.delivered == 0 {
                    thread::yield_now();
                }
            }
        }
        other => return Err(BenchError(format!("{} has no child", other.name()))),
    }
    drop(ping_in);
    drop(client);
    Ok(())
}
