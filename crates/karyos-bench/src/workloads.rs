// SPDX-License-Identifier: Apache-2.0

//! The workloads over the embedded driver
//! (`quantstratum-docs: karyos/design/simulator-and-bench.md`, s2).

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use karyos_client::{
    ClaimOutcome, ClientSubscription, CommitOutcome, ConcurrentOfferOutcome, MessageLimit,
    OfferOutcome,
};
use karyos_driver::{EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
use karyos_sys::term::TermId;
use karyos_trace::clocks::Latency;
use karyos_trace::histogram::Histogram;

/// A named workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workload {
    /// Offer then poll on one thread.
    OfferPoll,
    /// Claim, write, commit, then poll on one thread.
    Claim,
    /// A round trip between two threads over two streams.
    PingPong,
    /// Concurrent publishers and one subscriber on their own threads.
    Throughput,
}

impl Workload {
    /// Every workload.
    pub const ALL: [Self; 4] = [
        Self::OfferPoll,
        Self::Claim,
        Self::PingPong,
        Self::Throughput,
    ];

    /// Its name on the command line and in the history.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OfferPoll => "offer-poll",
            Self::Claim => "claim",
            Self::PingPong => "ping-pong",
            Self::Throughput => "throughput",
        }
    }

    /// The workload named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|workload| workload.name() == name)
    }
}

/// The canonical configuration of a run: two runs are comparable only when
/// these are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The workload.
    pub workload: Workload,
    /// Payload bytes per message.
    pub message: usize,
    /// Publisher threads (throughput) or 1.
    pub publishers: u8,
    /// Measured iterations (per publisher for throughput).
    pub iterations: u64,
    /// Discarded warm-up iterations.
    pub warmup: u64,
    /// Term length in bytes.
    pub term_length: u32,
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} message={} publishers={} iterations={} warmup={} term={}",
            self.workload.name(),
            self.message,
            self.publishers,
            self.iterations,
            self.warmup,
            self.term_length
        )
    }
}

/// What a run measured.
#[derive(Debug, Clone)]
pub struct Measurement {
    /// The configuration.
    pub config: Config,
    /// Per-iteration latencies in nanoseconds (round trips for ping-pong);
    /// `None` for throughput.
    pub latency: Option<Histogram>,
    /// Messages per second over the measured phase.
    pub rate: f64,
    /// The width of a latency interval: the clock's observed resolution.
    pub resolution: u64,
}

/// A failed run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchError(pub String);

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BenchError {}

fn error(context: &str, cause: impl fmt::Display) -> BenchError {
    BenchError(format!("{context}: {cause}"))
}

/// The smallest positive difference between consecutive clock readings.
fn resolution() -> u64 {
    let mut smallest = u64::MAX;
    for _ in 0..1000 {
        let start = Instant::now();
        let mut next = Instant::now();
        while next == start {
            next = Instant::now();
        }
        let delta = u64::try_from((next - start).as_nanos()).unwrap_or(u64::MAX);
        smallest = smallest.min(delta.max(1));
    }
    smallest
}

fn histogram() -> Result<Histogram, BenchError> {
    // Three significant digits up to one minute, in nanoseconds.
    Histogram::new(3, 60_000_000_000, 1).map_err(|cause| error("histogram", cause))
}

fn record(histogram: &mut Histogram, nanos: u128, resolution: u64) -> Result<(), BenchError> {
    let min = i64::try_from(nanos).unwrap_or(i64::MAX);
    let max = min.saturating_add(i64::try_from(resolution).unwrap_or(i64::MAX));
    histogram
        .record(Latency::Available { min, max })
        .map_err(|cause| error("record", cause))
}

fn stream(
    driver: &mut EmbeddedDriver,
    stream_id: i32,
    config: &Config,
    publication: PublicationMode,
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
                session_id: 1,
                stream_id,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication,
            },
            allow_unconnected: false,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
        })
        .map_err(|cause| error("stream", cause))
}

/// Polls until one message arrives, running the driver's duty when the
/// stream has nothing (single-threaded workloads).
fn receive(
    subscription: &mut ClientSubscription,
    mut duty: impl FnMut() -> Result<(), BenchError>,
) -> Result<(), BenchError> {
    loop {
        let summary = subscription
            .poll(|_, _| {}, MessageLimit::new(1))
            .map_err(|cause| error("poll", cause))?;
        if summary.delivered == 1 {
            return Ok(());
        }
        duty()?;
    }
}

/// Runs `config`.
///
/// # Errors
///
/// Returns the first driver or client error.
pub fn run(config: Config) -> Result<Measurement, BenchError> {
    match config.workload {
        Workload::OfferPoll | Workload::Claim => single_thread(config),
        Workload::PingPong => ping_pong(config),
        Workload::Throughput => throughput(config),
    }
}

fn single_thread(config: Config) -> Result<Measurement, BenchError> {
    let resolution = resolution();
    let mut driver = EmbeddedDriver::new().map_err(|cause| error("driver", cause))?;
    let handle = stream(&mut driver, 1, &config, PublicationMode::Exclusive)?;
    let mut subscription = driver
        .subscribe(handle, Role::Required)
        .map_err(|cause| error("subscribe", cause))?;
    let mut publication = driver
        .publication(handle)
        .map_err(|cause| error("publication", cause))?;
    let payload = vec![7u8; config.message];
    let length = u32::try_from(config.message).map_err(|cause| error("message", cause))?;
    let mut latencies = histogram()?;
    let started = Instant::now();
    let mut measured_from = started;
    for iteration in 0..config.warmup + config.iterations {
        if iteration == config.warmup {
            measured_from = Instant::now();
        }
        let begin = Instant::now();
        loop {
            let done = match config.workload {
                Workload::Claim => match publication
                    .try_claim(length)
                    .map_err(|cause| error("claim", cause))?
                {
                    ClaimOutcome::Claimed(mut claim) => {
                        claim.payload().copy_from_slice(&payload);
                        matches!(claim.commit(), CommitOutcome::Accepted { .. })
                    }
                    _ => false,
                },
                _ => matches!(
                    publication
                        .offer(&payload)
                        .map_err(|cause| error("offer", cause))?,
                    OfferOutcome::Accepted { .. }
                ),
            };
            if done {
                break;
            }
            driver.do_work().map_err(|cause| error("duty", cause))?;
        }
        receive(&mut subscription, || {
            driver
                .do_work()
                .map(|_| ())
                .map_err(|cause| error("duty", cause))
        })?;
        if iteration >= config.warmup {
            record(&mut latencies, begin.elapsed().as_nanos(), resolution)?;
        }
    }
    let seconds = measured_from.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    Ok(Measurement {
        config,
        latency: Some(latencies),
        rate: config.iterations as f64 / seconds,
        resolution,
    })
}

/// Runs the driver's duty on its own thread until `stop` is set.
fn duty_thread(
    mut driver: EmbeddedDriver,
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

fn join<T>(handle: thread::JoinHandle<Result<T, BenchError>>) -> Result<T, BenchError> {
    handle
        .join()
        .map_err(|_| BenchError("a workload thread panicked".into()))?
}

fn ping_pong(config: Config) -> Result<Measurement, BenchError> {
    let resolution = resolution();
    let mut driver = EmbeddedDriver::new().map_err(|cause| error("driver", cause))?;
    let ping = stream(&mut driver, 1, &config, PublicationMode::Exclusive)?;
    let pong = stream(&mut driver, 2, &config, PublicationMode::Exclusive)?;
    let mut ping_in = driver
        .subscribe(ping, Role::Required)
        .map_err(|cause| error("subscribe", cause))?;
    let mut pong_in = driver
        .subscribe(pong, Role::Required)
        .map_err(|cause| error("subscribe", cause))?;
    let mut ping_out = driver
        .publication(ping)
        .map_err(|cause| error("publication", cause))?;
    let mut pong_out = driver
        .publication(pong)
        .map_err(|cause| error("publication", cause))?;
    let stop = Arc::new(AtomicBool::new(false));
    let duty = duty_thread(driver, Arc::clone(&stop));
    let total = config.warmup + config.iterations;
    let message = config.message;
    let echo = thread::spawn(move || -> Result<(), BenchError> {
        let payload = vec![9u8; message];
        for _ in 0..total {
            receive(&mut ping_in, || {
                thread::yield_now();
                Ok(())
            })?;
            while !matches!(
                pong_out
                    .offer(&payload)
                    .map_err(|cause| error("offer", cause))?,
                OfferOutcome::Accepted { .. }
            ) {
                thread::yield_now();
            }
        }
        Ok(())
    });
    let payload = vec![7u8; config.message];
    let mut latencies = histogram()?;
    let mut measured_from = Instant::now();
    let mut outcome = Ok(());
    for iteration in 0..total {
        if iteration == config.warmup {
            measured_from = Instant::now();
        }
        let begin = Instant::now();
        let step = (|| {
            while !matches!(
                ping_out
                    .offer(&payload)
                    .map_err(|cause| error("offer", cause))?,
                OfferOutcome::Accepted { .. }
            ) {
                thread::yield_now();
            }
            receive(&mut pong_in, || {
                thread::yield_now();
                Ok(())
            })
        })();
        if let Err(cause) = step {
            outcome = Err(cause);
            break;
        }
        if iteration >= config.warmup {
            record(&mut latencies, begin.elapsed().as_nanos(), resolution)?;
        }
    }
    let seconds = measured_from.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    stop.store(true, Ordering::Release);
    join(duty)?;
    outcome?;
    join(echo)?;
    Ok(Measurement {
        config,
        latency: Some(latencies),
        rate: config.iterations as f64 / seconds,
        resolution,
    })
}

fn throughput(config: Config) -> Result<Measurement, BenchError> {
    let mut driver = EmbeddedDriver::new().map_err(|cause| error("driver", cause))?;
    let publishers = config.publishers.max(1);
    let handle = stream(
        &mut driver,
        1,
        &config,
        PublicationMode::Concurrent {
            publishers,
            allow_non_lse: true,
        },
    )?;
    let mut subscription = driver
        .subscribe(handle, Role::Required)
        .map_err(|cause| error("subscribe", cause))?;
    let mut handles = Vec::new();
    for _ in 0..publishers {
        handles.push(
            driver
                .concurrent_publication(handle)
                .map_err(|cause| error("publication", cause))?,
        );
    }
    let stop = Arc::new(AtomicBool::new(false));
    let duty = duty_thread(driver, Arc::clone(&stop));
    let warmup = config.warmup;
    let iterations = config.iterations;
    // Publishers send their warm-up, then wait until the subscriber has
    // drained all of it; the measured phase starts for everyone at once.
    let barrier = Arc::new(Barrier::new(usize::from(publishers) + 1));
    // Set by a publisher that fails, so the subscriber stops waiting for
    // messages that will never come.
    let failed = Arc::new(AtomicBool::new(false));
    let threads: Vec<_> = handles
        .into_iter()
        .map(|mut publication| {
            let payload = vec![7u8; config.message];
            let barrier = Arc::clone(&barrier);
            let failed = Arc::clone(&failed);
            thread::spawn(move || -> Result<(), BenchError> {
                let mut send = |count: u64| -> Result<(), BenchError> {
                    for _ in 0..count {
                        while !matches!(
                            publication
                                .offer(&payload)
                                .map_err(|cause| error("offer", cause))?,
                            ConcurrentOfferOutcome::Accepted { .. }
                        ) {
                            thread::yield_now();
                        }
                    }
                    Ok(())
                };
                let warmed = send(warmup);
                if warmed.is_err() {
                    failed.store(true, Ordering::Release);
                }
                // Reached even after an error, so no thread waits forever.
                let _ = barrier.wait();
                warmed?;
                let measured = send(iterations);
                if measured.is_err() {
                    failed.store(true, Ordering::Release);
                }
                measured
            })
        })
        .collect();
    let mut receive_count = |count: u64| -> Result<(), BenchError> {
        let mut received = 0u64;
        while received < count {
            if failed.load(Ordering::Acquire) {
                return Err(BenchError("a publisher failed".into()));
            }
            let summary = subscription
                .poll(|_, _| {}, MessageLimit::new(64))
                .map_err(|cause| error("poll", cause))?;
            received += u64::from(summary.delivered);
            if summary.delivered == 0 {
                thread::yield_now();
            }
        }
        Ok(())
    };
    let warmed = receive_count(warmup * u64::from(publishers));
    // The clock starts before the barrier releases any measured send, so
    // the interval covers every counted message (at the cost of including
    // the release itself).
    let started = Instant::now();
    let _ = barrier.wait();
    let measured = warmed.and_then(|()| receive_count(iterations * u64::from(publishers)));
    let seconds = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    stop.store(true, Ordering::Release);
    join(duty)?;
    measured?;
    for thread in threads {
        join(thread)?;
    }
    Ok(Measurement {
        config,
        latency: None,
        // Only the measured phase: every warm-up message was received before
        // the clock started.
        rate: (iterations * u64::from(publishers)) as f64 / seconds,
        resolution: 0,
    })
}
