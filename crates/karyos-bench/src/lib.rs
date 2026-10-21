// SPDX-License-Identifier: Apache-2.0

//! System benchmarks.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far
//! (`quantstratum-docs: karyos/design/simulator-and-bench.md`, s2): the embedded data path
//! workloads (offer and poll, claim, a two-thread round trip, concurrent
//! throughput, open-loop scheduled load, cleaner slots against term
//! production, and a receive owner committing or comparing frames of an
//! image), the copies of network streams on each term backing (a sender
//! read staging or answering NAKs, the receive owner, image install;
//! `quantstratum-docs: karyos/design/network-shared-terms.md`, N-5), latency
//! histograms from `karyos-trace`, environment labels and a stored history.
//! Open-loop latency is measured from the scheduled send time through
//! delivery, so producer delay remains visible. Every report is
//! labelled with its environment class (E1 to E4 of manifest 6.3) and
//! verdict, such as `E4 non-decision` ([`mod@env`]): nothing here establishes
//! a SPEC.md §12 target, which needs an eligible physical host (SPEC.md
//! §15, §17).
//!
//! The P2.8 measurement harness (`quantstratum-docs:
//! karyos/design/measurement-harness.md`) has batch B1: the frozen
//! manifest as data ([`manifest`]), raw per-message samples ([`samples`]),
//! the statistics of manifest section 8 ([`stats`]) and the decision rules
//! of manifest sections 7 and 8 ([`decision`]); and batch B2: the host
//! inventory of the environments README ([`inventory`], `karyos-bench
//! inventory`), environment classification and decision eligibility
//! ([`mod@env`]).
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

/// Counts the allocations of this crate's unit tests in the allocation
/// build (`alloc-count`, M-9), so the zero-allocation stages are tested.
#[cfg(all(test, feature = "alloc-count"))]
#[global_allocator]
static ALLOCATOR: karyos_sys::alloc_count::CountingAllocator =
    karyos_sys::alloc_count::CountingAllocator;

pub mod analyze;
pub mod archive;
pub mod decision;
pub mod env;
pub mod inventory;
#[cfg(target_os = "linux")]
pub mod ipc;
pub mod manifest;
pub mod measure;
pub mod plan;
pub mod preflight;
pub mod report;
pub mod samples;
pub mod stats;
mod terms;
pub mod wire;
pub mod workloads;

pub use workloads::{Backing, BackingRefused, BenchError, Config, Measurement, Workload, run};

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
                nak_frames: None,
                lanes: None,
                backing: Backing::Heap,
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
                nak_frames: None,
                lanes: None,
                backing: Backing::Heap,
            });
        }
    }
    // The receive owner's write on every backing, with one full frame of
    // the default MTU (network-shared-terms.md, N-5).
    for backing in Backing::ALL
        .into_iter()
        .filter(|backing| available(*backing))
    {
        let messages: &[usize] = if backing == Backing::Heap {
            &[1376]
        } else {
            &[32, 256, 1024, 1376]
        };
        for &message in messages {
            configs.push(Config {
                workload: Workload::Receive,
                message,
                publishers: 1,
                iterations,
                warmup,
                term_length,
                target_rate: None,
                nak_frames: None,
                lanes: None,
                backing,
            });
        }
    }
    for workload in [Workload::TraceOff, Workload::TraceOn] {
        for message in [32, 256, 1024] {
            configs.push(Config {
                workload,
                message,
                publishers: 1,
                iterations,
                warmup,
                term_length,
                target_rate: None,
                nak_frames: None,
                lanes: None,
                backing: Backing::Heap,
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
            nak_frames: None,
            lanes: None,
            backing: Backing::Heap,
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
            nak_frames: None,
            lanes: None,
            backing: Backing::Heap,
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
            nak_frames: None,
            lanes: None,
            backing: Backing::Heap,
        });
    }
    // Between processes: only where the driver's IPC mode exists.
    if cfg!(target_os = "linux") {
        for message in [32, 256, 1024] {
            configs.push(Config {
                workload: Workload::IpcPingPong,
                message,
                publishers: 1,
                iterations,
                warmup,
                term_length,
                target_rate: None,
                nak_frames: None,
                lanes: None,
                backing: Backing::Region,
            });
        }
        configs.push(Config {
            workload: Workload::IpcThroughput,
            message: 32,
            publishers: 1,
            iterations,
            warmup,
            term_length,
            target_rate: None,
            nak_frames: None,
            lanes: None,
            backing: Backing::Region,
        });
    }
    configs.extend(network_terms(iterations, warmup));
    configs
}

/// The archive workloads (`archive::run`), run only when named with
/// `--workload`: they write to a disk, so no default run does, and their
/// records are compared only under the same host and filesystem. A sync
/// costs milliseconds on some disks, so `archive-sync` measures at most
/// 2000 iterations.
#[must_use]
pub fn archive_configs(iterations: u64) -> Vec<Config> {
    let mut configs = Vec::new();
    for workload in [Workload::ArchiveAppend, Workload::ArchiveSync] {
        let iterations = match workload {
            Workload::ArchiveSync => iterations.min(2000),
            _ => iterations,
        };
        for message in [4096, 65536] {
            configs.push(Config {
                workload,
                message,
                publishers: 1,
                iterations,
                warmup: (iterations / 10).max(1),
                term_length: 1 << 20,
                target_rate: None,
                nak_frames: None,
                lanes: None,
                backing: Backing::Heap,
            });
        }
    }
    configs
}

/// Whether `backing` exists on this target: a region only on Linux.
fn available(backing: Backing) -> bool {
    backing != Backing::Region || cfg!(target_os = "linux")
}

/// The sender and image workloads of network streams over shared terms
/// (`quantstratum-docs: karyos/design/network-shared-terms.md`, N-5) on
/// every backing they run on here: unfragmented messages up to one full
/// frame at the default MTU, and for `sender-read` also 8 KiB and 64 KiB
/// messages, fragmented, over 1 MiB terms. `sender-nak` reads ranges of 1,
/// 16 and 256 frames over 1 MiB terms, so a whole range fits the
/// publication's window before it is registered. `image-install` and
/// `image-first-fill` (1376 byte messages over 64 KiB, 1 MiB and 16 MiB
/// terms) run a hundredth of the iterations, at least ten.
fn network_terms(iterations: u64, warmup: u64) -> Vec<Config> {
    let config = |workload, message, term_length, backing| Config {
        workload,
        message,
        publishers: 1,
        iterations,
        warmup,
        term_length,
        target_rate: None,
        nak_frames: None,
        lanes: None,
        backing,
    };
    let mut configs = Vec::new();
    for backing in Backing::ALL
        .into_iter()
        .filter(|backing| available(*backing))
    {
        for message in [32, 256, 1024, 1376] {
            configs.push(config(Workload::SenderRead, message, 64 * 1024, backing));
        }
        for message in [8 * 1024, 64 * 1024] {
            configs.push(config(Workload::SenderRead, message, 1024 * 1024, backing));
        }
        for nak_frames in [1, 16, 256] {
            for message in [32, 256, 1024, 1376] {
                configs.push(Config {
                    nak_frames: Some(nak_frames),
                    ..config(Workload::SenderNak, message, 1024 * 1024, backing)
                });
            }
        }
    }
    // An install of four 64 MiB lanes takes tens of milliseconds on some
    // hosts: a hundredth of the iterations, at least ten.
    let installs = (iterations / 100).max(10);
    for backing in Workload::ImageInstall
        .backings()
        .iter()
        .copied()
        .filter(|backing| available(*backing))
    {
        for lanes in [1, 4] {
            for term_length in [64 * 1024, 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024] {
                configs.push(Config {
                    lanes: Some(lanes),
                    iterations: installs,
                    warmup: (installs / 10).max(1),
                    ..config(Workload::ImageInstall, 0, term_length, backing)
                });
            }
        }
    }
    for backing in Workload::ImageFirstFill
        .backings()
        .iter()
        .copied()
        .filter(|backing| available(*backing))
    {
        for term_length in [64 * 1024, 1024 * 1024, 16 * 1024 * 1024] {
            configs.push(Config {
                iterations: installs,
                warmup: (installs / 10).max(1),
                ..config(Workload::ImageFirstFill, 1376, term_length, backing)
            });
        }
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
