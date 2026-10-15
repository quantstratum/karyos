// SPDX-License-Identifier: Apache-2.0

//! System benchmarks.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far
//! (`quantstratum-docs: karyos/design/simulator-and-bench.md`, s2): the embedded data path
//! workloads (offer and poll, claim, a two-thread round trip, concurrent
//! throughput, and a receive owner committing or comparing frames of an
//! image), latency histograms from `karyos-trace`, environment labels
//! and a stored history. Every report is labelled `unqualified`: nothing
//! here establishes a SPEC.md §12 target, which needs a qualified physical
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
        });
    }
    configs
}
