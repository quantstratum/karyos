// SPDX-License-Identifier: Apache-2.0

//! The copies a network stream adds on each term backing
//! (`quantstratum-docs: karyos/design/network-shared-terms.md`, N-5, step
//! n0), measured through public karyos-sys API only, before the driver's
//! network stack becomes generic over its terms.
//!
//! - `sender-read`: one exclusive publisher appends a message; a
//!   [`SenderRead`] stages it into a datagram buffer of one MTU, read after
//!   read, as the sender's `Outbound` does. Only the staging is timed: the
//!   append before it and the registration of the sent position after it
//!   are not. No socket is involved.
//! - `sender-nak`: `nak_frames` one-frame messages are appended, staged and
//!   registered as sent; then the timed part reads them again from the
//!   range's first frame with [`SenderRead::read_nak`], into the same MTU
//!   buffer, until every frame of the range was copied. One sample is one
//!   whole range, as one NAK asks for it. The conductor's duty runs only
//!   while the range is appended, with the registered position still below
//!   its first frame, so no term of the range is reclaimed before it is
//!   read.
//! - `image-install`: the lanes of one image, `lanes` of them at the
//!   configured term length, and their receive owner are created as the
//!   conductor's image table does at `CreateImage` (spare slots and
//!   subscribers of its default template); dropping them is not timed.
//! - `image-first-fill`: a one-lane image is installed as `image-install`
//!   does, untimed; then the timed part hands its receive owner one frame
//!   after another until the first term is full. One sample is one whole
//!   term, so it holds the first touch of every page of the term, which
//!   `image-install` leaves out; `receive` measures the same frames on a
//!   term that was touched before.
//!
//! A [`Backing::Heap`] lane is `LogBuffer::new`, a [`Backing::Shared`]
//! lane `LogBuffer::new_shared` and a [`Backing::Region`] lane
//! `LogBuffer::create_in` in a new region (Linux), each region with a new
//! id of this process.

use std::sync::Arc;
use std::time::Instant;

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::log_buffer::{
    AppendOptions, AppendOutcome, Conductor, DEFAULT_CLAIM_DEADLINE, DEFAULT_CORRUPT_RETRIES,
    DEFAULT_NAK_CHECKPOINT_STRIDE, LogBuffer, LogBufferConfig, NakRead, Publication,
    PublicationMode, ReadOrigin, ReadOutcome, ReceiveOwner, Received, Role, SenderRead,
};
use karyos_sys::receive::{ImageParams, Item, ValidatedDatagram};
use karyos_sys::sizing::{DEFAULT_MTU, FragmentPlan, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::{HeapTerms, SharedTerms, TermBytes};

use crate::workloads::{
    Backing, BackingRefused, BenchError, Config, Measurement, error, header, histogram, record,
    resolution,
};

/// Spare slots of an image lane: the image table's default template.
const IMAGE_SPARE_SLOTS: u8 = 5;

/// Subscribers of an image lane: the image table's default template.
const IMAGE_MAX_SUBSCRIBERS: u8 = 8;

/// Duty cycles an append may wait for before the run fails.
const STALLED_APPENDS: u32 = 100_000;

/// Reads at one position that may come back `Pending` or `Retry` before the
/// run fails.
const STALLED_READS: u32 = 100_000;

/// The occupant id of the sender read's cell.
const OCCUPANT: u64 = 1;

/// A heap lane.
///
/// # Errors
///
/// The buffer's validation errors.
pub(crate) fn heap(config: LogBufferConfig) -> Result<LogBuffer<HeapTerms>, BenchError> {
    LogBuffer::new(config).map_err(|cause| error("heap lane", cause))
}

/// A lane of atomic words on the heap of this process.
///
/// # Errors
///
/// The buffer's validation errors.
pub(crate) fn shared(config: LogBufferConfig) -> Result<LogBuffer<SharedTerms>, BenchError> {
    LogBuffer::new_shared(config).map_err(|cause| error("shared lane", cause))
}

/// A lane in a new shared region, as an IPC driver creates a stream.
///
/// # Errors
///
/// The buffer's validation errors, the region's system call errors, and a
/// region id past `u64::MAX`.
#[cfg(target_os = "linux")]
pub(crate) fn region(config: LogBufferConfig) -> Result<LogBuffer<SharedTerms>, BenchError> {
    use std::sync::atomic::{AtomicU64, Ordering};

    use karyos_sys::term::Generation;

    /// The driver instance the bench's regions name; a region's id is
    /// unique within it, as the admission's ids are within a driver.
    const INSTANCE: u128 = u128::from_le_bytes(*b"karyos-bench-n0\0");
    /// The next region id, never reused within this process.
    static NEXT_REGION: AtomicU64 = AtomicU64::new(1);

    let region = NEXT_REGION
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| BenchError("region ids exhausted".into()))?;
    LogBuffer::create_in(INSTANCE, region, config, Generation::default())
        .map_err(|cause| error("region lane", cause))
}

/// A region exists on Linux only; `Config::check_backing` refuses it
/// before any run reaches this.
///
/// # Errors
///
/// Always.
#[cfg(not(target_os = "linux"))]
pub(crate) fn region(_config: LogBufferConfig) -> Result<LogBuffer<SharedTerms>, BenchError> {
    Err(BenchError("a shared region needs Linux".into()))
}

/// The publication lane of the sender workloads.
fn sender_lane(config: &Config) -> Result<LogBufferConfig, BenchError> {
    let term_length =
        TermLength::try_new(config.term_length).map_err(|cause| error("term length", cause))?;
    Ok(LogBufferConfig {
        term_length,
        spare_slots: 6,
        max_subscribers: 2,
        mtu: DEFAULT_MTU,
        max_reserved: config.term_length / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 1,
        stream_id: 1,
        claim_deadline: DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Exclusive,
        schedule_capacity: 0,
    })
}

/// Bytes a message of `message` bytes reserves in a term at the default
/// MTU.
fn block_length(message: usize) -> Result<u64, BenchError> {
    let plan =
        FragmentPlan::new(DEFAULT_MTU, Flags::NONE).map_err(|cause| error("fragments", cause))?;
    let length = u32::try_from(message).map_err(|cause| error("message", cause))?;
    plan.reserved(length)
        .map(u64::from)
        .map_err(|cause| error("message", cause))
}

/// `warmup + iterations`, checked.
fn total(config: &Config) -> Result<u64, BenchError> {
    config
        .warmup
        .checked_add(config.iterations)
        .ok_or_else(|| BenchError("iteration count overflow".into()))
}

/// A publisher, its conductor and a sender read on one lane.
struct Sender<'a, T: TermBytes> {
    conductor: Conductor<&'a LogBuffer<T>>,
    publication: Publication<&'a LogBuffer<T>>,
    reader: SenderRead<&'a LogBuffer<T>>,
    /// The datagram buffer: one MTU, as `Outbound` claims it.
    out: Vec<u8>,
}

impl<'a, T: TermBytes> Sender<'a, T> {
    fn new(buffer: &'a LogBuffer<T>) -> Result<Self, BenchError> {
        let mut conductor = buffer
            .conductor()
            .ok_or_else(|| BenchError("the lane's conductor was taken".into()))?;
        // The sender is a required participant with its slot credit
        // reserved, as the driver admits it.
        let subscription = conductor
            .subscribe_as(Role::Required, true, OCCUPANT)
            .map_err(|cause| error("sender subscription", cause))?;
        let reader = SenderRead::new(subscription, DEFAULT_CORRUPT_RETRIES)
            .map_err(|cause| error("sender read", cause))?;
        let publication = buffer
            .publication()
            .map_err(|cause| error("publication", cause))?
            .ok_or_else(|| BenchError("the lane's publication was taken".into()))?;
        let mtu = usize::try_from(DEFAULT_MTU).map_err(|cause| error("mtu", cause))?;
        Ok(Self {
            conductor,
            publication,
            reader,
            out: vec![0u8; mtu],
        })
    }

    /// Appends `payload`, running the conductor's duty while the append
    /// waits for it; returns the block's start.
    fn append(&mut self, payload: &[u8]) -> Result<u64, BenchError> {
        for _ in 0..STALLED_APPENDS {
            match self
                .publication
                .append(payload, AppendOptions::default())
                .map_err(|cause| error("append", cause))?
            {
                AppendOutcome::Appended { position } => return Ok(position),
                AppendOutcome::BackPressured | AppendOutcome::AdminAction => {
                    let _ = self
                        .conductor
                        .duty_cycle()
                        .map_err(|cause| error("duty", cause))?;
                }
                AppendOutcome::Closed | AppendOutcome::Gated => {
                    return Err(BenchError("the publication closed".into()));
                }
            }
        }
        Err(BenchError(format!(
            "an append waited {STALLED_APPENDS} duty cycles"
        )))
    }

    /// Stages everything from the cursor to `end`, a block end, read after
    /// read into the datagram buffer: frames and the canonical PAD record
    /// that closes a term.
    fn stage(&mut self, end: u64) -> Result<(), BenchError> {
        let mut stalled = 0u32;
        while self.reader.position() < end {
            let from = self.reader.position();
            match self
                .reader
                .read_committed(from, ReadOrigin::Cursor, &mut self.out)
            {
                Ok(ReadOutcome::Copied { .. } | ReadOutcome::Canonical { .. }) => stalled = 0,
                Ok(ReadOutcome::Pending) | Err(karyos_sys::log_buffer::ReadError::Retry) => {
                    stalled = stalled
                        .checked_add(1)
                        .filter(|count| *count < STALLED_READS)
                        .ok_or_else(|| BenchError(format!("no frame to stage at {from}")))?;
                }
                Err(cause) => return Err(BenchError(format!("sender read: {cause:?}"))),
            }
        }
        if self.reader.position() == end {
            Ok(())
        } else {
            Err(BenchError(format!(
                "staging ended at {} past the block end {end}",
                self.reader.position()
            )))
        }
    }

    /// Registers everything staged as sent, as the backend's submission
    /// does.
    fn sent(&mut self) -> Result<(), BenchError> {
        let position = self.reader.position();
        match self.reader.boundary_at_or_below(position) {
            Some(boundary) => self
                .reader
                .sent(boundary)
                .map_err(|cause| BenchError(format!("sent: {cause:?}"))),
            None => Ok(()),
        }
    }
}

/// `sender-read` on the configured backing.
///
/// # Errors
///
/// The first lane, publication or read error.
pub(crate) fn sender_read(config: Config) -> Result<Measurement, BenchError> {
    let lane = sender_lane(&config)?;
    match config.backing {
        Backing::Heap => stage_messages(config, &heap(lane)?),
        Backing::Shared => stage_messages(config, &shared(lane)?),
        Backing::Region => stage_messages(config, &region(lane)?),
    }
}

fn stage_messages<T: TermBytes>(
    config: Config,
    buffer: &LogBuffer<T>,
) -> Result<Measurement, BenchError> {
    let resolution = resolution();
    let block = block_length(config.message)?;
    let total = total(&config)?;
    let mut sender = Sender::new(buffer)?;
    let payload = vec![7u8; config.message];
    let mut latencies = histogram()?;
    let mut measured_from = Instant::now();
    for iteration in 0..total {
        if iteration == config.warmup {
            measured_from = Instant::now();
        }
        let start = sender.append(&payload)?;
        let end = start
            .checked_add(block)
            .ok_or_else(|| BenchError("position overflow".into()))?;
        let begin = Instant::now();
        sender.stage(end)?;
        let elapsed = begin.elapsed().as_nanos();
        sender.sent()?;
        if iteration >= config.warmup {
            record(&mut latencies, elapsed, resolution)?;
        }
    }
    finish(config, latencies, measured_from, resolution)
}

/// `sender-nak` on the configured backing.
///
/// # Errors
///
/// A fragmented message size or a missing range, and the first lane,
/// publication or read error.
pub(crate) fn sender_nak(config: Config) -> Result<Measurement, BenchError> {
    let lane = sender_lane(&config)?;
    match config.backing {
        Backing::Heap => nak_ranges(config, &heap(lane)?),
        Backing::Shared => nak_ranges(config, &shared(lane)?),
        Backing::Region => nak_ranges(config, &region(lane)?),
    }
}

fn nak_ranges<T: TermBytes>(
    config: Config,
    buffer: &LogBuffer<T>,
) -> Result<Measurement, BenchError> {
    let frames = config
        .nak_frames
        .filter(|frames| *frames > 0)
        .ok_or_else(|| BenchError("sender-nak needs a positive nak_frames".into()))?;
    let plan =
        FragmentPlan::new(DEFAULT_MTU, Flags::NONE).map_err(|cause| error("fragments", cause))?;
    let message = u32::try_from(config.message).map_err(|cause| error("message", cause))?;
    if message == 0 || message > plan.payload_per_fragment() {
        return Err(BenchError(format!(
            "sender-nak takes messages of one frame: 1 to {} bytes",
            plan.payload_per_fragment()
        )));
    }
    let resolution = resolution();
    let reserved =
        usize::try_from(block_length(config.message)?).map_err(|cause| error("frame", cause))?;
    // From the checkpoint of its own stride, a scan makes at most
    // `stride / 32 + 1` word 0 loads.
    let stride = DEFAULT_NAK_CHECKPOINT_STRIDE.min(config.term_length);
    let loads = (stride / 32)
        .checked_add(1)
        .ok_or_else(|| BenchError("load budget overflow".into()))?;
    let total = total(&config)?;
    let mut sender = Sender::new(buffer)?;
    let mut scratch = sender.out.clone();
    let payload = vec![7u8; config.message];
    let mut latencies = histogram()?;
    let mut measured_from = Instant::now();
    for iteration in 0..total {
        if iteration == config.warmup {
            measured_from = Instant::now();
        }
        // The range: appended and staged with the registered position
        // below its first frame, then registered at once.
        let mut first = None;
        for _ in 0..frames {
            let start = sender.append(&payload)?;
            let end = u64::try_from(reserved)
                .ok()
                .and_then(|reserved| start.checked_add(reserved))
                .ok_or_else(|| BenchError("position overflow".into()))?;
            sender.stage(end)?;
            first = first.or(Some(start));
        }
        sender.sent()?;
        let from = first.ok_or_else(|| BenchError("an empty range".into()))?;
        let nak = NakRead {
            bound: sender.reader.sent_position(),
            loads,
        };
        let begin = Instant::now();
        read_range(
            &mut sender.reader,
            from,
            frames,
            reserved,
            nak,
            &mut scratch,
        )?;
        let elapsed = begin.elapsed().as_nanos();
        if iteration >= config.warmup {
            record(&mut latencies, elapsed, resolution)?;
        }
    }
    finish(config, latencies, measured_from, resolution)
}

/// Reads `frames` frames of `reserved` bytes each from `from` with NAK
/// reads, each into at most one MTU of `scratch` and never more than the
/// range still needs.
fn read_range<T: TermBytes>(
    reader: &mut SenderRead<&LogBuffer<T>>,
    mut from: u64,
    frames: u32,
    reserved: usize,
    nak: NakRead,
    scratch: &mut [u8],
) -> Result<(), BenchError> {
    let mut left = usize::try_from(frames).map_err(|cause| error("frames", cause))?;
    while left > 0 {
        let want = left
            .checked_mul(reserved)
            .ok_or_else(|| BenchError("range overflow".into()))?
            .min(scratch.len());
        let out = scratch
            .get_mut(..want)
            .ok_or_else(|| BenchError("scratch too small".into()))?;
        let (result, _) = reader.read_nak(from, nak, out);
        match result {
            Ok(ReadOutcome::Copied { len, next }) => {
                left = left
                    .checked_sub(len.div_ceil(reserved))
                    .ok_or_else(|| BenchError("a NAK read copied past its range".into()))?;
                from = next;
            }
            Ok(ReadOutcome::Canonical {
                record: karyos_sys::log_buffer::CanonicalKind::Pad,
                next,
            }) => from = next,
            other => return Err(BenchError(format!("NAK read at {from}: {other:?}"))),
        }
    }
    Ok(())
}

/// `image-install` on the configured backing.
///
/// # Errors
///
/// [`BackingRefused::Unsupported`] on a shared backing, a missing or
/// invalid lane count, and the first lane or receive owner error.
pub(crate) fn image_install(config: Config) -> Result<Measurement, BenchError> {
    match config.backing {
        Backing::Heap => install_images(config, heap),
        Backing::Region => install_images(config, region),
        // N-5 compares the heap path with region creation only.
        Backing::Shared => Err(BackingRefused::Unsupported {
            workload: config.workload,
            backing: config.backing,
        }
        .into()),
    }
}

fn install_images<T: TermBytes>(
    config: Config,
    make: fn(LogBufferConfig) -> Result<LogBuffer<T>, BenchError>,
) -> Result<Measurement, BenchError> {
    let lanes = config
        .lanes
        .ok_or_else(|| BenchError("image-install needs lanes".into()))?;
    let term_length =
        TermLength::try_new(config.term_length).map_err(|cause| error("term length", cause))?;
    let params = ImageParams::new(1, 1, lanes, term_length, DEFAULT_MTU)
        .map_err(|cause| error("image params", cause))?;
    let resolution = resolution();
    let total = total(&config)?;
    let mut latencies = histogram()?;
    let mut measured_from = Instant::now();
    for iteration in 0..total {
        if iteration == config.warmup {
            measured_from = Instant::now();
        }
        let begin = Instant::now();
        let owner = install(params, lanes, term_length, make)?;
        let elapsed = begin.elapsed().as_nanos();
        drop(owner);
        if iteration >= config.warmup {
            record(&mut latencies, elapsed, resolution)?;
        }
    }
    finish(config, latencies, measured_from, resolution)
}

/// `image-first-fill` on the configured backing.
///
/// # Errors
///
/// [`BackingRefused::Unsupported`] on a shared backing, a message that does
/// not fit one frame of the term, and the first lane, receive owner or
/// receive error.
pub(crate) fn image_first_fill(config: Config) -> Result<Measurement, BenchError> {
    match config.backing {
        Backing::Heap => first_fills(config, heap),
        Backing::Region => first_fills(config, region),
        // Shared heap words are touched when they are allocated.
        Backing::Shared => Err(BackingRefused::Unsupported {
            workload: config.workload,
            backing: config.backing,
        }
        .into()),
    }
}

fn first_fills<T: TermBytes>(
    config: Config,
    make: fn(LogBufferConfig) -> Result<LogBuffer<T>, BenchError>,
) -> Result<Measurement, BenchError> {
    let term_length =
        TermLength::try_new(config.term_length).map_err(|cause| error("term length", cause))?;
    let params = ImageParams::new(1, 1, 1, term_length, DEFAULT_MTU)
        .map_err(|cause| error("image params", cause))?;
    let frame_length = config
        .message
        .checked_add(32)
        .and_then(|length| u32::try_from(length).ok())
        .filter(|length| *length <= DEFAULT_MTU && *length <= config.term_length)
        .ok_or_else(|| BenchError(format!("message {} needs one frame", config.message)))?;
    let reserved = frame_length.next_multiple_of(32);
    let frames = config.term_length / reserved;
    let flags = Flags::new(true, true, false, false, Lane::ZERO);
    let mut bytes =
        vec![7u8; usize::try_from(frame_length).map_err(|cause| error("frame", cause))?];
    let resolution = resolution();
    let total = total(&config)?;
    let mut latencies = histogram()?;
    let mut measured_from = Instant::now();
    for iteration in 0..total {
        if iteration == config.warmup {
            measured_from = Instant::now();
        }
        let mut owner = install(params, 1, term_length, make)?;
        let mut elapsed = 0u128;
        for frame in 0..frames {
            header(
                Word0::new(frame_length.cast_signed(), flags, FrameType::Data),
                TermId::new(7),
                frame * reserved,
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
            let received = owner
                .receive(&frame)
                .map_err(|cause| error("receive", cause))?;
            elapsed = elapsed
                .checked_add(begin.elapsed().as_nanos())
                .ok_or_else(|| BenchError("fill time overflow".into()))?;
            if !matches!(received, Received::Committed { .. }) {
                return Err(BenchError(format!("a frame was {received:?}")));
            }
        }
        drop(owner);
        if iteration >= config.warmup {
            record(&mut latencies, elapsed, resolution)?;
        }
    }
    finish(config, latencies, measured_from, resolution)
}

/// The lanes of one image and their receive owner, as the image table's
/// `allocate` builds them.
fn install<T: TermBytes>(
    params: ImageParams,
    lanes: u8,
    term_length: TermLength,
    make: fn(LogBufferConfig) -> Result<LogBuffer<T>, BenchError>,
) -> Result<ReceiveOwner<T>, BenchError> {
    let mut buffers = Vec::with_capacity(usize::from(lanes));
    for index in 0..lanes {
        let lane = Lane::try_new(index).map_err(|cause| error("lane", cause))?;
        buffers.push(Arc::new(make(LogBufferConfig {
            term_length,
            spare_slots: IMAGE_SPARE_SLOTS,
            max_subscribers: IMAGE_MAX_SUBSCRIBERS,
            mtu: DEFAULT_MTU,
            max_reserved: term_length.get() / 8,
            initial_term_id: TermId::new(7),
            lane,
            session_id: 1,
            stream_id: 1,
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Image {
                join: 0,
                local_gaps: false,
            },
            schedule_capacity: 0,
        })?));
    }
    ReceiveOwner::new(params, buffers).map_err(|cause| error("receive owner", cause))
}

fn finish(
    config: Config,
    latencies: karyos_trace::histogram::Histogram,
    measured_from: Instant,
    resolution: u64,
) -> Result<Measurement, BenchError> {
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
