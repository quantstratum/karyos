// SPDX-License-Identifier: Apache-2.0

//! The session table's costs at item 37's initial values (karyos#685,
//! plan issue 069), at the client counts and payloads C5's W1 and W2
//! freeze (`karyos_sim::harness::workloads`):
//!
//! - **allocation**: [`SessionTable::new`] for each profile, and the first
//!   fill, every session's window written once with full replies, which
//!   is when the eagerly reserved pages are first touched;
//! - **lookup**: one applied request with `live` sessions, the client in
//!   the last slot the scan reaches, at W1's and W2's 1 and 32 clients and
//!   at each profile's full table; replies of W2's 256 B and W1's largest
//!   8 KiB;
//! - **retry**: a retained reply, and the refusal of a request past a full
//!   window, which W2's queue burst (4 × 1024 requests over 32 clients,
//!   128 per client against a window of 64) reaches;
//! - **snapshot section**: [`SessionTable::encode`] and
//!   [`SessionTable::decode`] of a full table, against the 256 MiB
//!   snapshot trigger.
//!
//! These are microbenchmarks of the table at the workloads' parameters,
//! not timings inside a simulated run.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_main};
use karyos_cluster::dedup::{DedupConfig, Outcome, Request, SessionTable};

/// W1's and W2's clients, and each profile's full table.
const LIVE: [u32; 4] = [1, 32, 64, 1024];
/// W2's payload and W1's largest.
const REPLIES: [usize; 2] = [256, 8 * 1024];

fn profiles() -> [(&'static str, DedupConfig); 2] {
    [
        ("default", DedupConfig::default()),
        ("large", DedupConfig::large()),
    ]
}

fn table(config: DedupConfig) -> SessionTable {
    SessionTable::new(config).unwrap_or_else(|_| std::process::abort())
}

/// A table with `live` sessions, clients 1 to `live`, each epoch its
/// client; the log time is `live`.
fn registered(config: DedupConfig, live: u32) -> SessionTable {
    let mut table = table(config);
    for client in 1..=u64::from(live) {
        if table.register(client, client, client).is_err() {
            std::process::abort();
        }
    }
    table
}

fn answer(length: usize) -> impl FnOnce(&mut [u8]) -> Option<usize> {
    move |reply| {
        reply.get_mut(..length)?.fill(0x5a);
        Some(length)
    }
}

/// Every session's window written once with full replies.
fn fill(table: &mut SessionTable) {
    let config = table.config();
    let length = usize::try_from(config.response_bytes).unwrap_or(usize::MAX);
    for client in 1..=u64::from(config.sessions) {
        for sequence in 0..u64::from(config.window) {
            let outcome = table.request(
                Request::new(client, client, sequence, 0),
                u64::from(config.sessions),
                answer(length),
            );
            if !matches!(outcome, Outcome::Applied(_)) {
                std::process::abort();
            }
        }
    }
}

fn allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup allocation");
    group.sample_size(10);
    for (name, config) in profiles() {
        let bytes = config.reserved_bytes().unwrap_or(0);
        group.throughput(Throughput::Bytes(bytes));
        group.bench_function(BenchmarkId::new("new", name), |b| {
            b.iter(|| black_box(table(black_box(config))));
        });
        group.bench_function(BenchmarkId::new("new and first fill", name), |b| {
            b.iter_custom(|iterations| {
                let mut total = Duration::ZERO;
                for _ in 0..iterations {
                    let started = Instant::now();
                    let mut table = registered(config, config.sessions);
                    fill(&mut table);
                    total += started.elapsed();
                    drop(black_box(table));
                }
                total
            });
        });
    }
    group.finish();
}

fn lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup lookup");
    for live in LIVE {
        let config = if live <= DedupConfig::default().sessions {
            DedupConfig::default()
        } else {
            DedupConfig::large()
        };
        for length in REPLIES {
            let mut table = registered(config, live);
            let client = u64::from(live);
            let mut sequence = 0u64;
            group.throughput(Throughput::Elements(1));
            group.bench_function(
                BenchmarkId::new(format!("applied {length} B"), format!("live={live}")),
                |b| {
                    b.iter(|| {
                        // Every earlier reply acknowledged: the window
                        // never fills.
                        let request = Request::new(client, client, sequence, sequence);
                        sequence += 1;
                        let outcome =
                            table.request(black_box(request), u64::from(live), answer(length));
                        black_box(matches!(outcome, Outcome::Applied(_)));
                    });
                },
            );
        }
    }
    group.finish();
}

fn retry(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup retry");
    for live in [32, 1024] {
        let config = if live <= DedupConfig::default().sessions {
            DedupConfig::default()
        } else {
            DedupConfig::large()
        };
        let client = u64::from(live);
        let window = u64::from(config.window);
        let mut table = registered(config, live);
        for sequence in 0..window {
            let _ = table.request(
                Request::new(client, client, sequence, 0),
                u64::from(live),
                answer(256),
            );
        }
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("retained", format!("live={live}")), |b| {
            b.iter(|| {
                let outcome = table.request(
                    black_box(Request::new(client, client, window - 1, 0)),
                    u64::from(live),
                    answer(256),
                );
                black_box(matches!(outcome, Outcome::Retained(_)));
            });
        });
        group.bench_function(
            BenchmarkId::new("window full", format!("live={live}")),
            |b| {
                b.iter(|| {
                    let outcome = table.request(
                        black_box(Request::new(client, client, window, 0)),
                        u64::from(live),
                        answer(256),
                    );
                    black_box(matches!(outcome, Outcome::WindowFull));
                });
            },
        );
    }
    group.finish();
}

fn snapshot_section(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup snapshot section");
    group.sample_size(10);
    for (name, config) in profiles() {
        let mut table = registered(config, config.sessions);
        fill(&mut table);
        let encoded = table.encode();
        // The section's size is in the benchmark's name.
        let name = format!("{name} {} B", encoded.len());
        group.throughput(Throughput::Bytes(
            u64::try_from(encoded.len()).unwrap_or(u64::MAX),
        ));
        group.bench_function(BenchmarkId::new("encode", &name), |b| {
            b.iter(|| black_box(table.encode()));
        });
        group.bench_function(BenchmarkId::new("decode", &name), |b| {
            b.iter(|| {
                black_box(
                    SessionTable::decode(black_box(&encoded))
                        .unwrap_or_else(|_| std::process::abort()),
                )
            });
        });
    }
    group.finish();
}

// criterion 0.7's `criterion_group!` generates an undocumented public
// function, which the workspace `missing_docs` lint would reject.
#[allow(
    missing_docs,
    reason = "criterion_group! generates an undocumented pub fn"
)]
mod group {
    use super::{allocation, lookup, retry, snapshot_section};
    criterion::criterion_group!(benches, allocation, lookup, retry, snapshot_section);
}
use group::benches;
criterion_main!(benches);
