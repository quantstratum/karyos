// SPDX-License-Identifier: Apache-2.0

//! Focused microbenchmarks for the keyed table and trace sampling hook.

use std::hint::black_box;
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_main};
use karyos_protocol::trace_hook::{PublicationIdentity, PublishContext, TraceHook};
use karyos_sys::conflation::{Budget, conflation};
use karyos_sys::frame::Lane;
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
                    |key, version, value| {
                        black_box((key, version, value));
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

// criterion 0.7's `criterion_group!` generates an undocumented public
// function, which the workspace `missing_docs` lint would reject.
#[allow(
    missing_docs,
    reason = "criterion_group! generates an undocumented pub fn"
)]
mod group {
    use super::{conflation_write_poll, trace_decisions};
    criterion::criterion_group!(benches, conflation_write_poll, trace_decisions);
}
use group::benches;
criterion_main!(benches);
