// SPDX-License-Identifier: Apache-2.0

//! One server of a real-process run of a candidate's adapter (karyos#678,
//! karyos#690, karyos#691):
//! `raft-eval-node <raft|openraft|custom> <id> <dir> <case> <id>=<address>...`,
//! `<case>` the index of a case in `process::cases()` (W1, then W2). It serves
//! the harness's test service to that case's clients
//! ([`run_server`]) until the test's stop datagram and the case's quiet
//! period after it; then it prints every observation it recorded, one
//! stamped line each (`karyos_raft_eval::record`), its state line
//! `state <id> <applied> <digest> <deduplicated> <leads> <up>`, and the
//! allocation probe's line for its own declared path (C5 v2,
//! "Processes"), and exits 0; a malformed argument prints the usage and
//! exits 2; any other failure prints the error to stderr and exits 1.
//!
//! The cores are the W1 variants at its primary batch limit of 16
//! entries: `RaftRsBatch16`, `OpenRaftBatch16` and the custom core
//! (`harness::custom::Custom`, whose batch is 16), the types the
//! simulator's allocation tests drive.
//!
//! The probe line is `probe <warmup> <entries> <allocations> <frees>
//! <stage>=<allocations>:<frees>,...`, every stage of
//! `harness::probe::Stage::ALL` by name: the node's core is wrapped in
//! `Probed`, so every call of it past the warm-up counts, and so do the
//! encoding and decoding of its messages ([`Stage::Encoding`]) and the
//! service's application of each committed entry ([`Stage::Apply`]).
//! `entries` is what the node committed past the warm-up while it led: a
//! follower's is 0.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use karyos_raft_eval::openraft_core::OpenRaftBatch16;
use karyos_raft_eval::process::{NodeConfig, ProcessError, Served, Wire, cases, run_server};
use karyos_raft_eval::raft_rs::RaftRsBatch16;
use karyos_raft_eval::record;
use karyos_sim::harness::custom::Custom;
use karyos_sim::harness::probe::{Measured, Probed, Stage, WARMUP, measure_with};
use karyos_sys::alloc_count::CountingAllocator;

/// The counting allocator of ADR-0008: the probe counts nothing without it.
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// How long a server serves without the test's stop.
const DEADLINE: Duration = Duration::from_secs(300);

/// The arguments, read as OS strings: `std::env::args` panics on one that
/// is not UTF-8, while a malformed argument here is a usage error
/// (karyos#956 review). The directory is taken as given; the core, the
/// numbers and the addresses must be UTF-8 and parse.
fn config() -> Option<(String, NodeConfig)> {
    let mut args = std::env::args_os().skip(1);
    let core = args.next()?.into_string().ok()?;
    let id = args.next()?.into_string().ok()?.parse().ok()?;
    let dir = PathBuf::from(args.next()?);
    let index: usize = args.next()?.into_string().ok()?.parse().ok()?;
    let case = cases().into_iter().nth(index)?;
    let peers = args
        .map(|peer| {
            let peer = peer.into_string().ok()?;
            let (id, address) = peer.split_once('=')?;
            Some((id.parse().ok()?, address.parse::<SocketAddr>().ok()?))
        })
        .collect::<Option<Vec<_>>>()?;
    Some((
        core,
        NodeConfig {
            id,
            peers,
            dir,
            case,
            deadline: DEADLINE,
        },
    ))
}

/// Why a measured run gave no report.
enum Failed {
    /// The run itself.
    Run(ProcessError),
    /// The probe's window was already open (never, in a node process).
    Window,
}

/// Runs the server with its core probed.
fn measured<C: Wire>(config: &NodeConfig) -> Result<(Served, Measured), Failed> {
    let (run, measured) =
        measure_with(|| run_server::<Probed<C>>(config)).map_err(|_| Failed::Window)?;
    Ok((run.map_err(Failed::Run)?, measured))
}

/// The report on stdout: every stamped observation, the state line and
/// the probe line.
fn report(id: u32, served: &Served, measured: &Measured) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for (stamp, item) in &served.items {
        if let Some(line) = record::encode(*stamp, item) {
            writeln!(out, "{line}")?;
        }
    }
    let state = &served.state;
    writeln!(
        out,
        "state {id} {} {} {} {} {}",
        state
            .applied
            .map_or_else(|| "-".to_owned(), |applied| applied.to_string()),
        state.digest,
        state.deduplicated,
        u8::from(state.leads),
        u8::from(state.up),
    )?;
    let stages: Vec<String> = measured
        .stages
        .iter()
        .map(|(stage, counts): &(Stage, _)| {
            format!("{}={}:{}", stage.name(), counts.allocations, counts.frees)
        })
        .collect();
    writeln!(
        out,
        "probe {WARMUP} {} {} {} {}",
        measured.entries,
        measured.counts.allocations,
        measured.counts.frees,
        stages.join(","),
    )?;
    out.flush()
}

fn main() -> ExitCode {
    // `raft-eval-node incarnation`: prints the incarnation this process
    // draws first, so a test can compare two processes (karyos#959).
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "incarnation")
    {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            karyos_raft_eval::openraft_core::next_incarnation()
        );
        return ExitCode::SUCCESS;
    }
    let Some((core, config)) = config() else {
        let _ = writeln!(
            std::io::stderr(),
            "usage: raft-eval-node <raft|openraft|custom> <id> <dir> <case> <id>=<address>..."
        );
        return ExitCode::from(2);
    };
    let run = match core.as_str() {
        "raft" => measured::<RaftRsBatch16>(&config),
        "openraft" => measured::<OpenRaftBatch16>(&config),
        "custom" => measured::<Custom>(&config),
        _ => {
            let _ = writeln!(
                std::io::stderr(),
                "unknown core {core}: raft, openraft or custom"
            );
            return ExitCode::from(2);
        }
    };
    match run {
        Ok((served, measured)) => match report(config.id, &served, &measured) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "raft-eval-node {}: {error}", config.id);
                ExitCode::FAILURE
            }
        },
        Err(Failed::Run(error)) => {
            let _ = writeln!(std::io::stderr(), "raft-eval-node {}: {error}", config.id);
            ExitCode::FAILURE
        }
        Err(Failed::Window) => {
            let _ = writeln!(
                std::io::stderr(),
                "raft-eval-node {}: the probe window was open",
                config.id
            );
            ExitCode::FAILURE
        }
    }
}
