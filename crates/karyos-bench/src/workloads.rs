// SPDX-License-Identifier: Apache-2.0

//! The workloads over the embedded driver
//! (`quantstratum-docs: karyos/design/simulator-and-bench.md`, s2).

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use karyos_client::{
    ClaimOutcome, ClientSubscription, CommitOutcome, ConcurrentOfferOutcome, MessageLimit,
    OfferOutcome,
};
use karyos_driver::{EmbeddedDriver, StreamConfig, StreamHandle};
use karyos_protocol::frame::FrameHeader;
use karyos_protocol::trace_hook::{SubscriberIdentity, TraceHook};
use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::log_buffer::{
    AppendOptions, ConcurrentOfferOutcome as SysConcurrentOfferOutcome, LogBuffer, LogBufferConfig,
    PublicationMode, ReceiveOwner, Received, Role,
};
use karyos_sys::receive::{ImageParams, Item, ValidatedDatagram};
use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
use karyos_sys::term::{TermCount, TermId};
use karyos_sys::term_bytes::TermBytes;
use karyos_trace::clocks::Latency;
use karyos_trace::histogram::Histogram;
use karyos_trace::{
    BufferedIds, MonotonicClock, ObserverId, OsRandom, Sampling, TraceAgent, TraceCollector,
    trace_journal,
};

use crate::terms;

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
    /// One publisher follows a fixed send schedule; latency starts at the
    /// scheduled instant, so late sends retain their full delay.
    OpenLoop,
    /// Concurrent term production against the log buffer cleaner, with no
    /// subscriber so the run measures publication and reclamation only.
    CleanerThroughput,
    /// A receive owner commits each validated frame into an image
    /// (`quantstratum-docs: karyos/design/receive-publication.md`).
    Receive,
    /// A receive owner compares each frame's duplicate with the committed
    /// one: the cost of redundant paths.
    ReceiveDuplicate,
    /// Offer and poll with no trace hooks attached.
    TraceOff,
    /// Offer and poll with publication and subscriber trace hooks attached.
    TraceOn,
    /// A round trip with the echo in another process, over an IPC driver
    /// (Linux).
    IpcPingPong,
    /// One publisher and a subscriber in another process, over an IPC
    /// driver (Linux).
    IpcThroughput,
    /// A sender read stages each committed message into a datagram buffer
    /// of one MTU, as the network sender's `Outbound` does; no socket
    /// (`quantstratum-docs: karyos/design/network-shared-terms.md`, N-5).
    SenderRead,
    /// A sender read answers a NAK of `nak_frames` already sent frames by
    /// NAK reads into a datagram buffer of one MTU (N-5).
    SenderNak,
    /// The lanes of one image and their receive owner are created, as the
    /// conductor's image table does at `CreateImage` (N-5).
    ImageInstall,
    /// The first term of a freshly installed one-lane image is filled with
    /// received frames: the first touch of its memory (N-5).
    ImageFirstFill,
    /// Appends to an Archive segment store on a real disk, never synced
    /// (`crate::archive`): `(warmup + iterations) × message` bytes written
    /// to the run directory, removed afterwards.
    ArchiveAppend,
    /// Appends to an Archive segment store and syncs each append, data
    /// then index (`crate::archive`).
    ArchiveSync,
}

impl Workload {
    /// Every workload.
    pub const ALL: [Self; 18] = [
        Self::OfferPoll,
        Self::Claim,
        Self::PingPong,
        Self::Throughput,
        Self::OpenLoop,
        Self::CleanerThroughput,
        Self::Receive,
        Self::ReceiveDuplicate,
        Self::TraceOff,
        Self::TraceOn,
        Self::IpcPingPong,
        Self::IpcThroughput,
        Self::SenderRead,
        Self::SenderNak,
        Self::ImageInstall,
        Self::ImageFirstFill,
        Self::ArchiveAppend,
        Self::ArchiveSync,
    ];

    /// Its name on the command line and in the history.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OfferPoll => "offer-poll",
            Self::Claim => "claim",
            Self::PingPong => "ping-pong",
            Self::Throughput => "throughput",
            Self::OpenLoop => "open-loop",
            Self::CleanerThroughput => "cleaner-throughput",
            Self::Receive => "receive",
            Self::ReceiveDuplicate => "receive-duplicate",
            Self::TraceOff => "trace-off",
            Self::TraceOn => "trace-on",
            Self::IpcPingPong => "ipc-ping-pong",
            Self::IpcThroughput => "ipc-throughput",
            Self::SenderRead => "sender-read",
            Self::SenderNak => "sender-nak",
            Self::ImageInstall => "image-install",
            Self::ImageFirstFill => "image-first-fill",
            Self::ArchiveAppend => "archive-append",
            Self::ArchiveSync => "archive-sync",
        }
    }

    /// The workload named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|workload| workload.name() == name)
    }

    /// The term backings it runs on, its default first.
    #[must_use]
    pub const fn backings(self) -> &'static [Backing] {
        match self {
            Self::Receive | Self::ReceiveDuplicate | Self::SenderRead | Self::SenderNak => {
                &[Backing::Heap, Backing::Shared, Backing::Region]
            }
            Self::ImageInstall | Self::ImageFirstFill => &[Backing::Heap, Backing::Region],
            // Every stream of an IPC driver is in a shared region.
            Self::IpcPingPong | Self::IpcThroughput => &[Backing::Region],
            Self::OfferPoll
            | Self::Claim
            | Self::PingPong
            | Self::Throughput
            | Self::OpenLoop
            | Self::CleanerThroughput
            | Self::TraceOff
            | Self::TraceOn
            // No term memory: the backing is nominal.
            | Self::ArchiveAppend
            | Self::ArchiveSync => &[Backing::Heap],
        }
    }

    /// The backing of its records written before the backing was part of
    /// the canonical configuration, and of its default configurations.
    #[must_use]
    pub const fn default_backing(self) -> Backing {
        match self.backings() {
            [first, ..] => *first,
            [] => Backing::Heap,
        }
    }

    /// Whether it runs on `backing`.
    #[must_use]
    pub fn supports(self, backing: Backing) -> bool {
        self.backings().contains(&backing)
    }
}

/// What a workload's term memory is
/// (`quantstratum-docs: karyos/design/network-shared-terms.md`, N-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backing {
    /// `HeapTerms`: private heap memory moved with plain copies.
    Heap,
    /// `SharedTerms` on heap words of this process (`LogBuffer::new_shared`):
    /// every byte moved as an aligned atomic word.
    Shared,
    /// `SharedTerms` in a real shared region (`LogBuffer::create_in`), as an
    /// IPC driver creates every stream (Linux).
    Region,
}

impl Backing {
    /// Every backing.
    pub const ALL: [Self; 3] = [Self::Heap, Self::Shared, Self::Region];

    /// Its name on the command line and in the history.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Heap => "heap",
            Self::Shared => "shared",
            Self::Region => "region",
        }
    }

    /// The backing named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|backing| backing.name() == name)
    }
}

/// Why a configuration cannot run on its backing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingRefused {
    /// The workload does not run on this backing.
    Unsupported {
        /// The workload.
        workload: Workload,
        /// The backing it was given.
        backing: Backing,
    },
    /// A region is created only on Linux, where the driver's IPC mode
    /// exists.
    NeedsLinux {
        /// The workload.
        workload: Workload,
    },
}

impl fmt::Display for BackingRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { workload, backing } => write!(
                f,
                "{} does not run on backing {}; it runs on {}",
                workload.name(),
                backing.name(),
                workload
                    .backings()
                    .iter()
                    .map(|backing| backing.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::NeedsLinux { workload } => write!(
                f,
                "{} on backing region needs Linux: shared regions exist there only",
                workload.name()
            ),
        }
    }
}

impl std::error::Error for BackingRefused {}

impl From<BackingRefused> for BenchError {
    fn from(refused: BackingRefused) -> Self {
        Self(refused.to_string())
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
    /// Scheduled messages per second for `open-loop`.
    pub target_rate: Option<u64>,
    /// Frames of each NAK range for `sender-nak`.
    pub nak_frames: Option<u32>,
    /// Lanes of each image for `image-install`.
    pub lanes: Option<u8>,
    /// The term memory.
    pub backing: Backing,
}

impl Config {
    /// Whether the workload runs on the configured backing here.
    ///
    /// # Errors
    ///
    /// [`BackingRefused::Unsupported`] for a backing the workload does not
    /// run on, and [`BackingRefused::NeedsLinux`] for a region on any other
    /// target.
    pub fn check_backing(&self) -> Result<(), BackingRefused> {
        if !self.workload.supports(self.backing) {
            return Err(BackingRefused::Unsupported {
                workload: self.workload,
                backing: self.backing,
            });
        }
        if self.backing == Backing::Region && !cfg!(target_os = "linux") {
            return Err(BackingRefused::NeedsLinux {
                workload: self.workload,
            });
        }
        Ok(())
    }
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
        )?;
        if let Some(rate) = self.target_rate {
            write!(f, " target_rate={rate}")?;
        }
        if let Some(frames) = self.nak_frames {
            write!(f, " nak_frames={frames}")?;
        }
        if let Some(lanes) = self.lanes {
            write!(f, " lanes={lanes}")?;
        }
        // Last, so a record written before the backing existed reads as
        // its workload's default backing (`report::compare`).
        write!(f, " backing={}", self.backing.name())
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
    /// Open-loop producer lateness from scheduled time to accepted offer.
    pub producer_lateness: Option<Histogram>,
    /// Messages per second over the measured phase.
    pub rate: f64,
    /// The width of a latency interval: the clock's observed resolution.
    pub resolution: u64,
    /// Slots cleaned per second, for the cleaner workload.
    pub cleaned_slots_per_second: Option<f64>,
    /// Term boundaries crossed per second, for the cleaner workload.
    pub term_rotations_per_second: Option<f64>,
    /// Where an archive workload wrote and how it synced.
    pub archive: Option<crate::archive::ArchiveRun>,
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

pub(crate) fn error(context: &str, cause: impl fmt::Display) -> BenchError {
    BenchError(format!("{context}: {cause}"))
}

/// The smallest positive difference between consecutive clock readings.
pub(crate) fn resolution() -> u64 {
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

pub(crate) fn histogram() -> Result<Histogram, BenchError> {
    // Three significant digits up to one minute, in nanoseconds.
    Histogram::new(3, 60_000_000_000, 1).map_err(|cause| error("histogram", cause))
}

pub(crate) fn record(
    histogram: &mut Histogram,
    nanos: u128,
    resolution: u64,
) -> Result<(), BenchError> {
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
                schedule_capacity: 0,
            },
            allow_unconnected: false,
            on_required_loss: karyos_sys::log_buffer::LossPolicy::Hold,
            conflation: None,
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
    config.check_backing()?;
    match config.workload {
        Workload::OfferPoll | Workload::Claim | Workload::TraceOff => single_thread(config, false),
        Workload::TraceOn => single_thread(config, true),
        Workload::PingPong => ping_pong(config),
        Workload::Throughput => throughput(config),
        Workload::OpenLoop => open_loop(config),
        Workload::CleanerThroughput => cleaner_throughput(config),
        Workload::Receive => receive_on(config, false),
        Workload::ReceiveDuplicate => receive_on(config, true),
        Workload::SenderRead => crate::terms::sender_read(config),
        Workload::SenderNak => crate::terms::sender_nak(config),
        Workload::ImageInstall => crate::terms::image_install(config),
        Workload::ImageFirstFill => crate::terms::image_first_fill(config),
        Workload::ArchiveAppend | Workload::ArchiveSync => crate::archive::run(config),
        #[cfg(target_os = "linux")]
        Workload::IpcPingPong => crate::ipc::ping_pong(config),
        #[cfg(target_os = "linux")]
        Workload::IpcThroughput => crate::ipc::throughput(config),
        #[cfg(not(target_os = "linux"))]
        Workload::IpcPingPong | Workload::IpcThroughput => Err(BenchError(format!(
            "{} needs Linux: the driver's IPC mode exists there only",
            config.workload.name()
        ))),
    }
}

/// [`receive_frames`] on the configured backing.
fn receive_on(config: Config, duplicate: bool) -> Result<Measurement, BenchError> {
    let term_length =
        TermLength::try_new(config.term_length).map_err(|cause| error("term length", cause))?;
    let lane = LogBufferConfig {
        term_length,
        spare_slots: 6,
        max_subscribers: 2,
        mtu: DEFAULT_MTU,
        max_reserved: config.term_length / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 1,
        stream_id: 1,
        claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Image {
            join: 0,
            local_gaps: false,
        },
        schedule_capacity: 0,
    };
    match config.backing {
        Backing::Heap => receive_frames(config, duplicate, terms::heap(lane)?),
        Backing::Shared => receive_frames(config, duplicate, terms::shared(lane)?),
        Backing::Region => receive_frames(config, duplicate, terms::region(lane)?),
    }
}

/// One thread: validate a datagram of one frame and hand it to the image's
/// receive owner, measuring only the owner's call: the commit, or with
/// `duplicate` the comparison of a second copy. Parsing and validation
/// happen before the timer starts. A PAD closes each term and the conductor
/// prepares the next; neither is measured.
fn receive_frames<T: TermBytes>(
    config: Config,
    duplicate: bool,
    buffer: LogBuffer<T>,
) -> Result<Measurement, BenchError> {
    let resolution = resolution();
    let term_length =
        TermLength::try_new(config.term_length).map_err(|cause| error("term length", cause))?;
    let params = ImageParams::new(1, 1, 1, term_length, DEFAULT_MTU)
        .map_err(|cause| error("image params", cause))?;
    let buffer = Arc::new(buffer);
    let mut conductor = buffer
        .conductor()
        .ok_or_else(|| BenchError("the image's conductor was taken".into()))?;
    let mut owner = ReceiveOwner::new(params, vec![Arc::clone(&buffer)])
        .map_err(|cause| error("receive owner", cause))?;
    let frame_length =
        u32::try_from(config.message + 32).map_err(|cause| error("message", cause))?;
    let reserved = frame_length.next_multiple_of(32);
    let flags = Flags::new(true, true, false, false, Lane::ZERO);
    let mut bytes = vec![7u8; frame_length as usize];
    let mut pad = [0u8; 32];
    let mut latencies = histogram()?;
    let (mut term, mut offset) = (0u32, 0u32);
    let mut measured_from = Instant::now();
    let handle = |owner: &mut ReceiveOwner<T>, bytes: &[u8]| -> Result<Received, BenchError> {
        let datagram =
            ValidatedDatagram::parse(bytes, &params).map_err(|cause| error("parse", cause))?;
        let Some(Item::Frame(frame)) = datagram.items().next() else {
            return Err(BenchError("no frame".into()));
        };
        owner
            .receive(&frame)
            .map_err(|cause| error("receive", cause))
    };
    for iteration in 0..config.warmup + config.iterations {
        if iteration == config.warmup {
            measured_from = Instant::now();
        }
        let term_id = TermCount::try_new(term)
            .map(|count| TermId::new(7).advanced_by(count))
            .map_err(|cause| error("term", cause))?;
        if offset + reserved > config.term_length {
            // A term filled exactly needs no PAD.
            let extent = config.term_length - offset;
            if extent > 0 {
                header(
                    Word0::new(32, Flags::NONE, FrameType::Pad),
                    term_id,
                    offset,
                    i64::from(extent),
                )
                .encode(&mut pad)
                .map_err(|cause| error("pad", cause))?;
                handle(&mut owner, &pad)?;
            }
            conductor
                .duty_cycle()
                .map_err(|cause| error("duty", cause))?;
            while owner.duty() {}
            (term, offset) = (term + 1, 0);
        }
        let term_id = TermCount::try_new(term)
            .map(|count| TermId::new(7).advanced_by(count))
            .map_err(|cause| error("term", cause))?;
        header(
            Word0::new(frame_length.cast_signed(), flags, FrameType::Data),
            term_id,
            offset,
            0,
        )
        .encode(&mut bytes)
        .map_err(|cause| error("header", cause))?;
        let datagram =
            ValidatedDatagram::parse(&bytes, &params).map_err(|cause| error("parse", cause))?;
        let Some(Item::Frame(frame)) = datagram.items().next() else {
            return Err(BenchError("no frame".into()));
        };
        let begin = Instant::now();
        let first = owner
            .receive(&frame)
            .map_err(|cause| error("receive", cause))?;
        let end = if duplicate {
            let begin = Instant::now();
            let second = owner
                .receive(&frame)
                .map_err(|cause| error("receive", cause))?;
            if second != Received::Duplicate {
                return Err(BenchError(format!("a duplicate was {second:?}")));
            }
            begin.elapsed().as_nanos()
        } else {
            begin.elapsed().as_nanos()
        };
        if !matches!(first, Received::Committed { .. }) {
            return Err(BenchError(format!("a frame was {first:?}")));
        }
        if iteration >= config.warmup {
            record(&mut latencies, end, resolution)?;
        }
        offset += reserved;
    }
    let seconds = measured_from.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    Ok(Measurement {
        config,
        latency: Some(latencies),
        producer_lateness: None,
        rate: config.iterations as f64 / seconds,
        resolution,
        cleaned_slots_per_second: None,
        term_rotations_per_second: None,
        archive: None,
    })
}

/// The header of a frame of the receive workloads' image.
pub(crate) fn header(word0: Word0, term: TermId, offset: u32, reserved_value: i64) -> FrameHeader {
    FrameHeader {
        word0,
        term_offset: offset.cast_signed(),
        session_id: 1,
        stream_id: 1,
        term_id: term.get().cast_signed(),
        reserved_value,
    }
}

fn single_thread(config: Config, traced: bool) -> Result<Measurement, BenchError> {
    let resolution = resolution();
    let mut driver = EmbeddedDriver::new().map_err(|cause| error("driver", cause))?;
    let handle = stream(&mut driver, 1, &config, PublicationMode::Exclusive)?;
    let mut subscription = driver
        .subscribe(handle, Role::Required)
        .map_err(|cause| error("subscribe", cause))?;
    let mut publication = driver
        .publication(handle)
        .map_err(|cause| error("publication", cause))?;
    let mut _trace_collectors: Vec<TraceCollector> = Vec::new();
    if traced {
        let publication_identity = driver
            .trace_identity(handle)
            .map_err(|cause| error("trace identity", cause))?;
        let subscriber_identity = SubscriberIdentity {
            driver: driver.driver_id(),
            registration: driver
                .next_trace_number()
                .map_err(|cause| error("trace identity", cause))?,
            incarnation: 1,
        };
        let total = config
            .warmup
            .checked_add(config.iterations)
            .ok_or_else(|| BenchError("trace iteration count overflow".into()))?;
        let (publish_hook, publish_collector) = trace_hook(&mut driver, total)?;
        let (delivery_hook, delivery_collector) = trace_hook(&mut driver, total)?;
        publication = publication.with_trace(publish_hook, publication_identity);
        subscription =
            subscription.with_trace(delivery_hook, publication_identity, subscriber_identity);
        _trace_collectors.push(publish_collector);
        _trace_collectors.push(delivery_collector);
    }
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
        // No trace maintenance in the timed loop: `trace_hook` presizes each
        // id buffer for every message and fills it at creation, so a refill
        // here would only add its cost to the measurement.
        let trace_decision = traced.then(|| publication.trace_message(None));
        loop {
            let done = if let Some(decision) = &trace_decision {
                matches!(
                    publication
                        .offer_with_trace(&payload, decision)
                        .map_err(|cause| error("offer", cause))?,
                    OfferOutcome::Accepted { .. }
                )
            } else {
                match config.workload {
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
                }
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
        producer_lateness: None,
        rate: config.iterations as f64 / seconds,
        resolution,
        cleaned_slots_per_second: None,
        term_rotations_per_second: None,
        archive: None,
    })
}

fn trace_hook(
    driver: &mut EmbeddedDriver,
    messages: u64,
) -> Result<(Box<dyn TraceHook>, TraceCollector), BenchError> {
    let journal = driver
        .next_trace_number()
        .map_err(|cause| error("trace journal identity", cause))?;
    let records = usize::try_from(messages)
        .map_err(|cause| error("trace journal capacity", cause))?
        .checked_next_power_of_two()
        .ok_or_else(|| BenchError("trace journal capacity overflow".into()))?
        .max(4);
    // A traced message takes three id words (a two-word trace id and a span
    // id), so the buffer filled at creation lasts the whole run.
    let id_words = usize::try_from(messages)
        .map_err(|cause| error("trace id capacity", cause))?
        .checked_mul(3)
        .ok_or_else(|| BenchError("trace id capacity overflow".into()))?
        .max(2);
    let ids = BufferedIds::new(id_words, OsRandom).map_err(|cause| error("trace ids", cause))?;
    let observer = ObserverId {
        driver: driver.driver_id(),
        journal,
    };
    let (writer, collector) = trace_journal(records, 4, observer, journal)
        .map_err(|cause| error("trace journal", cause))?;
    let agent = TraceAgent::new(Sampling::All, ids, MonotonicClock::new(journal), writer);
    Ok((Box::new(agent), collector))
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
        producer_lateness: None,
        rate: config.iterations as f64 / seconds,
        resolution,
        cleaned_slots_per_second: None,
        term_rotations_per_second: None,
        archive: None,
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
        producer_lateness: None,
        // Only the measured phase: every warm-up message was received before
        // the clock started.
        rate: (iterations * u64::from(publishers)) as f64 / seconds,
        resolution: 0,
        cleaned_slots_per_second: None,
        term_rotations_per_second: None,
        archive: None,
    })
}

fn cleaner_throughput(config: Config) -> Result<Measurement, BenchError> {
    let term_length =
        TermLength::try_new(config.term_length).map_err(|cause| error("term length", cause))?;
    let publishers = config.publishers.max(1);
    let buffer = Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length,
            spare_slots: 6,
            max_subscribers: 2,
            mtu: DEFAULT_MTU,
            max_reserved: config.term_length / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 1,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Concurrent {
                publishers,
                allow_non_lse: true,
            },
            schedule_capacity: 0,
        })
        .map_err(|cause| error("log buffer", cause))?,
    );
    let mut conductor = buffer
        .conductor_owned()
        .ok_or_else(|| BenchError("the log buffer's conductor was taken".into()))?;
    let mut publications = Vec::with_capacity(usize::from(publishers));
    for _ in 0..publishers {
        publications.push(
            conductor
                .concurrent_publication()
                .map_err(|cause| error("publication", cause))?
                .ok_or_else(|| BenchError("the log buffer has no publication slot".into()))?,
        );
    }
    let cleaned = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let cleaner = {
        let cleaned = Arc::clone(&cleaned);
        let stop = Arc::clone(&stop);
        thread::spawn(move || -> Result<(), BenchError> {
            while !stop.load(Ordering::Acquire) {
                let report = conductor
                    .duty_cycle()
                    .map_err(|cause| error("cleaner duty", cause))?;
                cleaned.fetch_add(u64::from(report.cleaned), Ordering::Relaxed);
                if report.cleaned == 0 {
                    thread::yield_now();
                }
            }
            Ok(())
        })
    };

    let payload = vec![7u8; config.message];
    let term_bytes = u64::from(config.term_length);
    let max_term = Arc::new(AtomicU64::new(0));
    let ready = Arc::new(Barrier::new(usize::from(publishers) + 1));
    let start = Arc::new(Barrier::new(usize::from(publishers) + 1));
    let producers: Vec<_> = publications
        .into_iter()
        .map(|mut publication| {
            let payload = payload.clone();
            let max_term = Arc::clone(&max_term);
            let ready = Arc::clone(&ready);
            let start = Arc::clone(&start);
            thread::spawn(move || -> Result<(), BenchError> {
                let mut send = |count: u64| -> Result<(), BenchError> {
                    for _ in 0..count {
                        let term = loop {
                            match publication
                                .offer(&payload, AppendOptions::default())
                                .map_err(|cause| error("offer", cause))?
                            {
                                SysConcurrentOfferOutcome::Appended { position } => {
                                    break position / term_bytes;
                                }
                                SysConcurrentOfferOutcome::Aborted { .. }
                                | SysConcurrentOfferOutcome::BackPressured
                                | SysConcurrentOfferOutcome::AdminAction => thread::yield_now(),
                                SysConcurrentOfferOutcome::Closed => {
                                    return Err(BenchError("the publication closed".into()));
                                }
                            }
                        };
                        max_term.fetch_max(term, Ordering::Relaxed);
                    }
                    Ok(())
                };
                let warmed = send(config.warmup);
                let _ = ready.wait();
                let _ = start.wait();
                warmed?;
                send(config.iterations)
            })
        })
        .collect();

    let _ = ready.wait();
    let measured_cleaned_start = cleaned.load(Ordering::Relaxed);
    let measured_term_start = max_term.load(Ordering::Relaxed);
    let measured_from = Instant::now();
    let _ = start.wait();
    let mut outcome = Ok(());
    for producer in producers {
        if let Err(cause) = join(producer)
            && outcome.is_ok()
        {
            outcome = Err(cause);
        }
    }
    // Snapshot the cleaner while the producers are done and before stopping
    // its thread, so the rates exclude cleaner work after term production.
    let measured_cleaned_end = cleaned.load(Ordering::Relaxed);
    let measured_term_end = max_term.load(Ordering::Relaxed);
    let measured_end = Instant::now();
    stop.store(true, Ordering::Release);
    let joined = join(cleaner);
    outcome?;
    joined?;
    let seconds = measured_end
        .saturating_duration_since(measured_from)
        .as_secs_f64()
        .max(f64::MIN_POSITIVE);
    let cleaned_slots = measured_cleaned_end.saturating_sub(measured_cleaned_start);
    let measured_rotations = measured_term_end.saturating_sub(measured_term_start);
    Ok(Measurement {
        config,
        latency: None,
        producer_lateness: None,
        rate: (config.iterations * u64::from(publishers)) as f64 / seconds,
        resolution: 0,
        cleaned_slots_per_second: Some(cleaned_slots as f64 / seconds),
        term_rotations_per_second: Some(measured_rotations as f64 / seconds),
        archive: None,
    })
}

/// One producer sends at the configured rate regardless of how late an
/// earlier offer became. Every sample is measured from its scheduled time
/// through delivery, including time spent waiting to publish.
fn open_loop(config: Config) -> Result<Measurement, BenchError> {
    let target_rate = config
        .target_rate
        .filter(|rate| *rate > 0 && *rate <= 1_000_000_000)
        .ok_or_else(|| {
            BenchError("open-loop target rate must be 1..=1000000000 messages/s".into())
        })?;
    if config.iterations == 0 {
        return Err(BenchError("open-loop iterations must be positive".into()));
    }
    let total = config
        .warmup
        .checked_add(config.iterations)
        .ok_or_else(|| BenchError("open-loop iteration count overflow".into()))?;
    let schedule_start = Instant::now()
        .checked_add(Duration::from_millis(10))
        .ok_or_else(|| BenchError("open-loop start instant overflow".into()))?;
    let measured_start = scheduled_instant(schedule_start, config.warmup, target_rate)?;
    let _ = scheduled_instant(schedule_start, total - 1, target_rate)?;
    let mut latencies = histogram()?;
    let producer_lateness = histogram()?;
    let resolution = resolution();
    let mut driver = EmbeddedDriver::new().map_err(|cause| error("driver", cause))?;
    let handle = stream(&mut driver, 1, &config, PublicationMode::Exclusive)?;
    let mut subscription = driver
        .subscribe(handle, Role::Required)
        .map_err(|cause| error("subscribe", cause))?;
    let mut publication = driver
        .publication(handle)
        .map_err(|cause| error("publication", cause))?;
    let stop_duty = Arc::new(AtomicBool::new(false));
    let duty = duty_thread(driver, Arc::clone(&stop_duty));
    let failed = Arc::new(AtomicBool::new(false));
    let producer_failed = Arc::clone(&failed);
    let payload = vec![7u8; config.message];
    let producer = thread::spawn(move || -> Result<Histogram, BenchError> {
        let mut producer_lateness = producer_lateness;
        for index in 0..total {
            if producer_failed.load(Ordering::Acquire) {
                return Err(BenchError(
                    "receiver stopped before the schedule finished".into(),
                ));
            }
            let scheduled = scheduled_instant(schedule_start, index, target_rate)?;
            if !wait_until(scheduled, &|| producer_failed.load(Ordering::Acquire)) {
                return Err(BenchError(
                    "receiver stopped before the schedule finished".into(),
                ));
            }
            let accepted_at = loop {
                match publication.offer(&payload) {
                    Ok(OfferOutcome::Accepted { .. }) => {
                        break Instant::now();
                    }
                    Ok(_) => thread::yield_now(),
                    Err(cause) => {
                        producer_failed.store(true, Ordering::Release);
                        return Err(error("offer", cause));
                    }
                }
                if producer_failed.load(Ordering::Acquire) {
                    return Err(BenchError(
                        "receiver stopped before the offer completed".into(),
                    ));
                }
            };
            if index >= config.warmup
                && let Err(cause) = record(
                    &mut producer_lateness,
                    scheduled_latency_ns(scheduled, accepted_at),
                    resolution,
                )
            {
                producer_failed.store(true, Ordering::Release);
                return Err(cause);
            }
        }
        Ok(producer_lateness)
    });

    let mut received = 0u64;
    let mut receive_result = Ok(());
    while received < total {
        if failed.load(Ordering::Acquire) {
            receive_result = Err(BenchError("the scheduled producer failed".into()));
            break;
        }
        let mut sample_error = None;
        let summary = match subscription.poll(
            |_, _| {
                if received >= config.warmup && sample_error.is_none() {
                    let sample =
                        scheduled_instant(schedule_start, received, target_rate).and_then(|due| {
                            record(
                                &mut latencies,
                                scheduled_latency_ns(due, Instant::now()),
                                resolution,
                            )
                        });
                    if let Err(cause) = sample {
                        sample_error = Some(cause);
                    }
                }
                received = received.saturating_add(1);
            },
            MessageLimit::new(64),
        ) {
            Ok(summary) => summary,
            Err(cause) => {
                failed.store(true, Ordering::Release);
                receive_result = Err(error("poll", cause));
                break;
            }
        };
        if let Some(cause) = sample_error {
            failed.store(true, Ordering::Release);
            receive_result = Err(cause);
            break;
        }
        if received > total {
            failed.store(true, Ordering::Release);
            receive_result = Err(BenchError("received more messages than scheduled".into()));
            break;
        }
        if receive_result.is_err() {
            break;
        }
        if summary.delivered == 0 {
            thread::yield_now();
        }
    }
    if receive_result.is_err() {
        failed.store(true, Ordering::Release);
    }
    let finished = Instant::now();
    stop_duty.store(true, Ordering::Release);
    let producer_result = join(producer);
    join(duty)?;
    receive_result?;
    let producer_lateness = producer_result?;
    let seconds = finished
        .saturating_duration_since(measured_start)
        .as_secs_f64()
        .max(f64::MIN_POSITIVE);
    Ok(Measurement {
        config,
        latency: Some(latencies),
        producer_lateness: Some(producer_lateness),
        rate: config.iterations as f64 / seconds,
        resolution,
        cleaned_slots_per_second: None,
        term_rotations_per_second: None,
        archive: None,
    })
}

pub(crate) fn scheduled_instant(
    start: Instant,
    index: u64,
    target_rate: u64,
) -> Result<Instant, BenchError> {
    let offset = (u128::from(index) * 1_000_000_000) / u128::from(target_rate);
    let offset = u64::try_from(offset)
        .map_err(|_| BenchError("open-loop schedule duration overflow".into()))?;
    start
        .checked_add(Duration::from_nanos(offset))
        .ok_or_else(|| BenchError("open-loop scheduled instant overflow".into()))
}

fn scheduled_latency_ns(scheduled: Instant, delivered: Instant) -> u128 {
    delivered.saturating_duration_since(scheduled).as_nanos()
}

/// Waits until `scheduled`, sleeping while it is far and spinning in its
/// last 200 µs; `false` as soon as `stop` holds.
pub(crate) fn wait_until(scheduled: Instant, stop: &dyn Fn() -> bool) -> bool {
    loop {
        if stop() {
            return false;
        }
        let remaining = scheduled.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        let spin_window = Duration::from_micros(200);
        if remaining > spin_window {
            thread::sleep(
                remaining
                    .saturating_sub(spin_window)
                    .min(Duration::from_millis(10)),
            );
        } else {
            std::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{scheduled_instant, scheduled_latency_ns};
    use std::time::{Duration, Instant};

    #[test]
    fn open_loop_schedule_is_anchored_to_start_not_previous_send() {
        let start = Instant::now();
        assert_eq!(
            scheduled_instant(start, 10, 3).unwrap_or_else(|cause| panic!("{cause}")),
            start + Duration::from_nanos(3_333_333_333)
        );
        assert_eq!(
            scheduled_instant(start, 11, 3).unwrap_or_else(|cause| panic!("{cause}")),
            start + Duration::from_nanos(3_666_666_666)
        );
    }

    #[test]
    fn open_loop_latency_keeps_time_before_a_late_send() {
        let scheduled = Instant::now();
        let late_send = scheduled + Duration::from_micros(900);
        let delivered = late_send + Duration::from_micros(100);
        assert_eq!(scheduled_latency_ns(scheduled, delivered), 1_000_000);
    }
}
