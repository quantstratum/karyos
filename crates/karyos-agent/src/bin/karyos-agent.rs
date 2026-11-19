// SPDX-License-Identifier: Apache-2.0

//! `karyos-agent`: the per-host management agent (SPEC.md §11, ADR-0055;
//! quantstratum-docs: karyos/design/management-agent-gap-analysis.md, M7).
//! It reads each driver's CnC as a tool at every refresh and serves API v1
//! on a local Unix socket until it is killed. Exit status: 2 on a bad
//! command line or when the socket cannot be bound, 1 when serving fails.

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(args) = karyos_agent::cli::parse(&args) else {
        let _ = std::io::stderr().write_all(karyos_agent::cli::USAGE.as_bytes());
        return ExitCode::from(2);
    };
    serve(args)
}

#[cfg(not(target_os = "linux"))]
fn serve(args: karyos_agent::cli::Args) -> ExitCode {
    let _ = args;
    let _ = writeln!(std::io::stderr(), "karyos-agent: Linux only");
    ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn serve(args: karyos_agent::cli::Args) -> ExitCode {
    use std::time::{Duration, Instant};

    use karyos_agent::server::{ApiConfig, Principal, Role, Server};
    use karyos_agent::{Agent, AgentConfig};

    let roles = args
        .roles
        .iter()
        .filter_map(|(uid, name)| Role::parse(name).map(|role| (*uid, role)))
        .collect();
    // Parsed and checked by the command line already.
    let principals = args
        .principals
        .iter()
        .filter_map(|(name, operator, role)| {
            Role::parse(role).and_then(|role| Principal::new(name, *operator, role))
        })
        .collect();
    let mut config = ApiConfig::new(args.api_dir, roles).with_relays(args.relays, principals);
    if let Some(gid) = args.relay_group {
        config = config.with_relay_group(gid);
    }
    let mut server = match Server::bind(config) {
        Ok(server) => server,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "karyos-agent: {error}");
            return ExitCode::from(2);
        }
    };
    let mut config = args.archives.iter().fold(
        AgentConfig::new(args.drivers).with_alerts(args.alerts),
        |config, (dir, streams)| {
            config.with_archive(
                dir.clone(),
                karyos_agent::catalog::CatalogConfig::new(*streams),
            )
        },
    );
    if let Some(journal) = args.journal {
        config = config.with_journal(journal);
    }
    if let Some(id) = args.agent_id {
        config = config.with_agent_id(id);
    }
    let mut agent = Agent::new(config);
    // Between refreshes the socket is polled every 10 ms.
    let tick = Duration::from_millis(10).min(args.refresh);
    loop {
        agent.refresh();
        let next = Instant::now().checked_add(args.refresh);
        loop {
            if let Err(error) = server.poll(&mut agent) {
                let _ = writeln!(std::io::stderr(), "karyos-agent: {error}");
                return ExitCode::from(1);
            }
            if next.is_none_or(|next| Instant::now() >= next) {
                break;
            }
            std::thread::sleep(tick);
        }
    }
}
