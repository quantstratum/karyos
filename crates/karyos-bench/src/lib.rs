// SPDX-License-Identifier: Apache-2.0

//! System benchmarks.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far
//! (`quantstratum-docs: karyos/design/simulator-and-bench.md`, s2): the embedded data path
//! workloads (offer and poll, claim, a two-thread round trip, concurrent
//! throughput, open-loop scheduled load, cleaner slots against term
//! production, and a receive owner committing or comparing frames of an
//! image), latency histograms from `karyos-trace`, environment labels and a
//! stored history. Open-loop latency is measured from the scheduled send time
//! through delivery, so producer delay remains visible. Every report is
//! labelled `unqualified`: nothing here establishes a SPEC.md §12 target,
//! which needs a qualified physical
//! host (SPEC.md §15, §17).

pub mod env;
pub mod report;
pub mod workloads;

pub use workloads::{BenchError, Config, Measurement, Workload, run};

/// The default configurations: each workload at the message sizes of the
/// design, with `iterations` measured and a tenth of them as warm-up.
#[must_use]
pub fn defaults(iterations: u64) -> Vec<Config> {
    let term_length = 64 * 1024;
    let warmup = (iterations / 10).max(1);
    let mut configs = Vec::new();
    for workload in [Workload::OfferPoll, Workload::Claim, Workload::PingPong] {
        for message in [32, 256, 1024] {
            configs.push(Config {
                workload,
                message,
                publishers: 1,
                iterations,
                warmup,
                term_length,
                target_rate: None,
            });
        }
    }
    for workload in [Workload::Receive, Workload::ReceiveDuplicate] {
        for message in [32, 256, 1024] {
            configs.push(Config {
                workload,
                message,
                publishers: 1,
                iterations,
                warmup,
                term_length,
                target_rate: None,
            });
        }
    }
    for publishers in [1, 2] {
        configs.push(Config {
            workload: Workload::Throughput,
            message: 64,
            publishers,
            iterations,
            warmup,
            term_length,
            target_rate: None,
        });
    }
    for message in [32, 256, 1024] {
        configs.push(Config {
            workload: Workload::OpenLoop,
            message,
            publishers: 1,
            iterations,
            warmup,
            term_length,
            target_rate: Some(10_000),
        });
    }
    for message in [32, 256, 1024] {
        let iterations = iterations.max(cleaner_minimum_iterations(message, term_length));
        configs.push(Config {
            workload: Workload::CleanerThroughput,
            message,
            publishers: 1,
            iterations,
            warmup: (iterations / 10).max(warmup),
            term_length,
            target_rate: None,
        });
    }
    configs
}

fn cleaner_minimum_iterations(message: usize, term_length: u32) -> u64 {
    const MINIMUM_ROTATIONS: u64 = 1_000;
    let message = u64::try_from(message).unwrap_or(u64::MAX);
    let block = message.saturating_add(32).div_ceil(32).saturating_mul(32);
    let messages_per_rotation = u64::from(term_length).div_ceil(block).saturating_add(1);
    MINIMUM_ROTATIONS.saturating_mul(messages_per_rotation)
}
