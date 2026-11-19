// SPDX-License-Identifier: Apache-2.0

//! One node of a real-process run of a candidate's adapter (karyos#678,
//! karyos#690):
//! `raft-eval-node <raft|openraft> <id> <dir> <commands> <id>=<address>...`.
//! On success it prints `applied <count> <digest> <index>:<command>,...`
//! and exits 0; a malformed argument prints the usage and exits 2; any
//! other failure prints the error to stderr and exits 1.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use karyos_raft_eval::openraft_core::OpenRaft;
use karyos_raft_eval::process::{NodeConfig, run_node};
use karyos_raft_eval::raft_rs::RaftRs;

/// The arguments, read as OS strings: `std::env::args` panics on one that
/// is not UTF-8, while a malformed argument here is a usage error
/// (karyos#956 review). The directory is taken as given; the core, the
/// numbers and the addresses must be UTF-8 and parse.
fn config() -> Option<(String, NodeConfig)> {
    let mut args = std::env::args_os().skip(1);
    let core = args.next()?.into_string().ok()?;
    let id = args.next()?.into_string().ok()?.parse().ok()?;
    let dir = PathBuf::from(args.next()?);
    let commands = args.next()?.into_string().ok()?.parse().ok()?;
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
            commands,
            deadline: Duration::from_secs(30),
            linger: Duration::from_millis(500),
        },
    ))
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
            "usage: raft-eval-node <raft|openraft> <id> <dir> <commands> <id>=<address>..."
        );
        return ExitCode::from(2);
    };
    let run = match core.as_str() {
        "raft" => run_node::<RaftRs>(&config),
        "openraft" => run_node::<OpenRaft>(&config),
        _ => {
            let _ = writeln!(std::io::stderr(), "unknown core {core}: raft or openraft");
            return ExitCode::from(2);
        }
    };
    match run {
        Ok(report) => {
            let _ = writeln!(
                std::io::stdout(),
                "applied {} {:x} {}",
                report.applied,
                report.digest,
                report
                    .sequence
                    .iter()
                    .map(|(index, number)| format!("{index}:{number}"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "raft-eval-node {}: {error}", config.id);
            ExitCode::FAILURE
        }
    }
}
