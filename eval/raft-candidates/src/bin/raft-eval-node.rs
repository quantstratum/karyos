// SPDX-License-Identifier: Apache-2.0

//! One node of a real-process run of the `raft` adapter (karyos#678):
//! `raft-eval-node <id> <dir> <commands> <id>=<address>...`. On success it
//! prints `applied <count> <digest>` and exits 0; otherwise it prints the
//! error to stderr and exits 1.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use karyos_raft_eval::process::{NodeConfig, run_node};
use karyos_raft_eval::raft_rs::RaftRs;

fn config() -> Option<NodeConfig> {
    let mut args = std::env::args().skip(1);
    let id = args.next()?.parse().ok()?;
    let dir = PathBuf::from(args.next()?);
    let commands = args.next()?.parse().ok()?;
    let peers = args
        .map(|peer| {
            let (id, address) = peer.split_once('=')?;
            Some((id.parse().ok()?, address.parse::<SocketAddr>().ok()?))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(NodeConfig {
        id,
        peers,
        dir,
        commands,
        deadline: Duration::from_secs(30),
        linger: Duration::from_millis(500),
    })
}

fn main() -> ExitCode {
    let Some(config) = config() else {
        let _ = writeln!(
            std::io::stderr(),
            "usage: raft-eval-node <id> <dir> <commands> <id>=<address>..."
        );
        return ExitCode::FAILURE;
    };
    match run_node::<RaftRs>(&config) {
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
