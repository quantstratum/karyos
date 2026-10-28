// SPDX-License-Identifier: Apache-2.0

//! Focused microbenchmarks for the keyed table, the trace sampling hook,
//! the term byte copies of each backing, and a rate-limited send's charge
//! with and without the published policy check.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_main};
use karyos_protocol::trace_hook::{PublicationIdentity, PublishContext, TraceHook};
use karyos_sys::conflation::{Budget, conflation};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, AppendOutcome, DEFAULT_CLAIM_DEADLINE, DEFAULT_CORRUPT_RETRIES, LogBuffer,
    LogBufferConfig, NakRead, PublicationMode, ReadOrigin, ReadOutcome, Role, SenderRead,
};
use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::TermBytes;
use karyos_trace::{
    BufferedIds, MonotonicClock, ObserverId, OsRandom, Sampling, TraceAgent, trace_journal,
};

fn conflation_write_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("conflation write plus poll");
    for message_size in [32usize, 256, 1024] {
        let mut writer =
            conflation(1, message_size, 1024).unwrap_or_else(|_| std::process::abort());
        let mut reader = writer.reader();
        let payload = vec![0x5a; message_size];
        group.throughput(Throughput::Bytes(
            u64::try_from(message_size).unwrap_or(u64::MAX),
        ));
        group.bench_function(BenchmarkId::from_parameter(message_size), |b| {
            b.iter(|| {
                let write = writer
                    .write(0, black_box(&payload))
                    .unwrap_or_else(|_| std::process::abort());
                let poll = reader.poll_changed(
                    Budget {
                        keys: 1,
                        retries: 3,
                    },
                    |key, version, value, freshness| {
                        black_box((key, version, value, freshness));
                    },
                );
                black_box((write, poll));
            });
        });
    }
    group.finish();
}

fn trace_sampling(c: &mut Criterion, name: &str, sampling: Sampling) {
    c.bench_function(name, |b| {
        b.iter_custom(|iterations| {
            let id_words = usize::try_from(iterations.saturating_mul(3))
                .unwrap_or(usize::MAX)
                .max(2);
            let ids =
                BufferedIds::new(id_words, OsRandom).unwrap_or_else(|_| std::process::abort());
            let domain = 1;
            let observer = ObserverId {
                driver: [1, 2],
                journal: domain,
            };
            let (writer, _collector) =
                trace_journal(4, 2, observer, domain).unwrap_or_else(|_| std::process::abort());
            let mut agent = TraceAgent::new(sampling, ids, MonotonicClock::new(domain), writer);
            let context = PublishContext {
                publication: PublicationIdentity {
                    driver: [1, 2],
                    registration: 1,
                    stream_id: 1,
                    session_id: 1,
                    incarnation: 1,
                },
                lane: Lane::ZERO,
            };
            let started = Instant::now();
            for _ in 0..iterations {
                black_box(agent.on_publish(None, &context));
            }
            started.elapsed()
        });
    });
}

fn trace_decisions(c: &mut Criterion) {
    trace_sampling(c, "trace hook decision off", Sampling::Off);
    trace_sampling(c, "trace hook decision all", Sampling::All);
}

/// Payload sizes of the term copies: up to one full frame at the default
/// MTU (`quantstratum-docs: karyos/design/network-shared-terms.md`, N-5).
const TERM_COPY_SIZES: [usize; 4] = [32, 256, 1024, 1376];

/// An exclusive lane of 64 KiB terms.
fn term_lane() -> LogBufferConfig {
    let term_length = TermLength::try_new(64 * 1024).unwrap_or_else(|_| std::process::abort());
    LogBufferConfig {
        term_length,
        spare_slots: 6,
        max_subscribers: 2,
        mtu: DEFAULT_MTU,
        max_reserved: term_length.get() / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 1,
        stream_id: 1,
        claim_deadline: DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Exclusive,
        schedule_capacity: 0,
    }
}

/// `TermBytes::write_bytes` is sealed in karyos-sys, so the nearest public
/// path is timed: an exclusive append of one message, which writes its
/// payload with `write_bytes` after the header. Appends are timed in runs
/// until the publication waits; then, untimed, a sender read consumes
/// them and the conductor's duty prepares the next term. Reported only.
fn term_write<T: TermBytes>(c: &mut Criterion, backing: &str, make: fn() -> LogBuffer<T>) {
    let mut group = c.benchmark_group(format!("term write (exclusive append), {backing}"));
    for size in TERM_COPY_SIZES {
        let payload = vec![0x5a; size];
        group.throughput(Throughput::Bytes(u64::try_from(size).unwrap_or(u64::MAX)));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_custom(|iterations| {
                let buffer = make();
                let mut conductor = buffer.conductor().unwrap_or_else(|| std::process::abort());
                let mut reader = conductor
                    .subscribe_as(Role::Required, true, 1)
                    .ok()
                    .and_then(|subscription| {
                        SenderRead::new(subscription, DEFAULT_CORRUPT_RETRIES).ok()
                    })
                    .unwrap_or_else(|| std::process::abort());
                let mut publication = buffer
                    .publication()
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| std::process::abort());
                let mut out = vec![0u8; usize::try_from(DEFAULT_MTU).unwrap_or(usize::MAX)];
                let mut elapsed = Duration::ZERO;
                let mut done = 0u64;
                let mut idle = 0u32;
                while done < iterations {
                    let before = done;
                    let started = Instant::now();
                    while done < iterations {
                        match publication.append(black_box(&payload), AppendOptions::default()) {
                            Ok(AppendOutcome::Appended { position }) => {
                                black_box(position);
                                done += 1;
                            }
                            _ => break,
                        }
                    }
                    elapsed += started.elapsed();
                    // The publication waits: the reader consumes what was
                    // appended and the conductor prepares the next term.
                    while let Ok(ReadOutcome::Copied { .. } | ReadOutcome::Canonical { .. }) =
                        reader.read_committed(reader.position(), ReadOrigin::Cursor, &mut out)
                    {
                    }
                    if let Some(boundary) = reader.boundary_at_or_below(reader.position())
                        && reader.sent(boundary).is_err()
                    {
                        std::process::abort();
                    }
                    // Sticky abort on a publication that makes no progress.
                    idle = if done > before { 0 } else { idle + 1 };
                    if idle > 1_000 || conductor.duty_cycle().is_err() {
                        std::process::abort();
                    }
                }
                elapsed
            });
        });
    }
    group.finish();
}

/// `TermBytes::read_bytes` is sealed in karyos-sys, so the nearest public
/// path is timed: a sender's NAK read of one already sent frame into a
/// datagram buffer, which validates the frame and copies it with
/// `read_bytes`. It moves nothing, so every iteration reads the same frame.
/// Reported only.
fn term_read<T: TermBytes>(c: &mut Criterion, backing: &str, make: fn() -> LogBuffer<T>) {
    let mut group = c.benchmark_group(format!("term read (sender NAK read), {backing}"));
    for size in TERM_COPY_SIZES {
        let buffer = make();
        let mut conductor = buffer.conductor().unwrap_or_else(|| std::process::abort());
        let mut reader = conductor
            .subscribe_as(Role::Required, true, 1)
            .ok()
            .and_then(|subscription| SenderRead::new(subscription, DEFAULT_CORRUPT_RETRIES).ok())
            .unwrap_or_else(|| std::process::abort());
        let mut publication = buffer
            .publication()
            .ok()
            .flatten()
            .unwrap_or_else(|| std::process::abort());
        let mut out = vec![0u8; usize::try_from(DEFAULT_MTU).unwrap_or(usize::MAX)];
        if !matches!(
            publication.append(&vec![0x5a; size], AppendOptions::default()),
            Ok(AppendOutcome::Appended { position: 0 })
        ) {
            std::process::abort();
        }
        let Ok(ReadOutcome::Copied { next, .. }) =
            reader.read_committed(0, ReadOrigin::Cursor, &mut out)
        else {
            std::process::abort();
        };
        if reader.sent(next).is_err() {
            std::process::abort();
        }
        let nak = NakRead {
            bound: next,
            loads: 64 * 1024 / 32 + 1,
        };
        group.throughput(Throughput::Bytes(u64::try_from(size).unwrap_or(u64::MAX)));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| {
                let (result, loads) = reader.read_nak(black_box(0), nak, &mut out);
                if !matches!(result, Ok(ReadOutcome::Copied { .. })) {
                    std::process::abort();
                }
                black_box(loads);
            });
        });
    }
    group.finish();
}

fn heap_lane() -> LogBuffer {
    LogBuffer::new(term_lane()).unwrap_or_else(|_| std::process::abort())
}

fn shared_lane() -> LogBuffer<karyos_sys::term_bytes::SharedTerms> {
    LogBuffer::new_shared(term_lane()).unwrap_or_else(|_| std::process::abort())
}

/// R-CORE-21 (karyos#740): one sender gate serve's rate work, a refill and
/// a datagram's charge, alone and after the published policy check the gate
/// adds to each serve (one Acquire load of an unchanged sequence word). The
/// PR states the difference against its 5% bound.
fn rate_serve(c: &mut Criterion) {
    use karyos_sys::rate_limit::{Rate, RateLimiter, RatePolicy};
    use karyos_sys::rate_policy_slot::{SLOT_WORDS, SlotRead, publish, try_read};
    use karyos_sys::sync::{AtomicU64, Ordering};

    let policy = RatePolicy {
        messages: Rate {
            per_second: u64::MAX / 4,
            burst: u64::MAX / 4,
        },
        bytes: Some(Rate {
            per_second: u64::MAX / 4,
            burst: u64::MAX / 4,
        }),
    };
    let mut group = c.benchmark_group("rate serve");
    let mut now = 0u64;
    let mut limiter = RateLimiter::new(policy, 0);
    group.bench_function("refill and charge", |b| {
        b.iter(|| {
            now = now.wrapping_add(1_000);
            limiter.refill_at(black_box(now));
            black_box(limiter.try_admit_datagram(black_box(1_200), 1))
        });
    });
    let words: Vec<AtomicU64> = (0..SLOT_WORDS).map(|_| AtomicU64::new(0)).collect();
    publish(&words, 0, 1, &policy);
    let seen = words.first().map_or(0, |word| word.load(Ordering::Relaxed));
    let view: &[AtomicU64] = &words;
    let mut limiter = RateLimiter::new(policy, 0);
    group.bench_function("policy check, refill and charge", |b| {
        b.iter(|| {
            now = now.wrapping_add(1_000);
            let sequence = words.first().map(|word| word.load(Ordering::Acquire));
            if sequence != Some(black_box(seen))
                && let SlotRead::Policy { policy, .. } = try_read(&view, 0)
            {
                limiter.set_policy(policy, now);
            }
            limiter.refill_at(black_box(now));
            black_box(limiter.try_admit_datagram(black_box(1_200), 1))
        });
    });
    group.finish();
}

fn term_copies(c: &mut Criterion) {
    term_write(c, "heap", heap_lane);
    term_write(c, "shared", shared_lane);
    term_read(c, "heap", heap_lane);
    term_read(c, "shared", shared_lane);
}

// criterion 0.7's `criterion_group!` generates an undocumented public
// function, which the workspace `missing_docs` lint would reject.
#[allow(
    missing_docs,
    reason = "criterion_group! generates an undocumented pub fn"
)]
mod group {
    use super::{conflation_write_poll, rate_serve, term_copies, trace_decisions};
    criterion::criterion_group!(
        benches,
        conflation_write_poll,
        trace_decisions,
        term_copies,
        rate_serve
    );
}
use group::benches;
criterion_main!(benches);
