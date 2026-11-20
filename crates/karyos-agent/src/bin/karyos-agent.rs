// SPDX-License-Identifier: Apache-2.0

//! `karyos-agent`: the per-host management agent (SPEC.md §11, ADR-0055;
//! quantstratum-docs: karyos/design/management-agent-gap-analysis.md, M7).
//! It reads each driver's CnC as a tool at every refresh and serves API v1
//! on a local Unix socket until `SIGTERM` or `SIGINT`.
//!
//! **Stop** (owner item 55, karyos#710). Each signal only sets a flag
//! (`signal_hook::flag`); the serving loop reads it between polls and runs
//! the agent's one clean stop, [`karyos_agent::Agent::stop`], which writes
//! the durable `agent stopped` journal record. The stop is bounded by
//! `--stop-timeout-ms` (default 5 s): a watchdog thread exits the process
//! when it passes, and a second signal exits at once. Either way, and when
//! the record cannot be made durable, no `agent stopped` record is
//! written and the next start records an unclean stop, an unknown
//! interval. No library code handles a signal.
//!
//! Exit status: 0 after a clean stop; 2 on a bad command line or when the
//! socket cannot be bound; 1 when serving fails or the stop could not be
//! recorded; 3 when the stop passed its deadline; 1 on a second signal.

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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use signal_hook::consts::signal::{SIGINT, SIGTERM};

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
    // Registered before the socket is bound, so a signal during startup
    // stops the agent at once. A first signal sets `stop`; a second one,
    // with `stop` already set, exits at once with status 1, unclean.
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        let registered =
            signal_hook::flag::register_conditional_shutdown(signal, 1, Arc::clone(&stop))
                .and_then(|_| signal_hook::flag::register(signal, Arc::clone(&stop)));
        if let Err(error) = registered {
            let _ = writeln!(
                std::io::stderr(),
                "karyos-agent: signal registration failed: {error}"
            );
            return ExitCode::from(2);
        }
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
    // Between refreshes the socket is polled every 10 ms, and the stop
    // flag read as often.
    let tick = Duration::from_millis(10).min(args.refresh);
    while !stop.load(Ordering::Relaxed) {
        agent.refresh();
        let next = Instant::now().checked_add(args.refresh);
        while !stop.load(Ordering::Relaxed) {
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
    stop_cleanly(&mut agent, args.stop_timeout)
}

/// The exit status of a stop past its deadline.
#[cfg(target_os = "linux")]
const DEADLINE_EXIT: i32 = 3;

/// Runs the agent's clean stop within `timeout`: a watchdog exits the
/// process with [`DEADLINE_EXIT`] when it passes, before `agent stopped`
/// is durable, so that run stays unclean. A zero timeout exits at once,
/// without trying.
#[cfg(target_os = "linux")]
fn stop_cleanly(agent: &mut karyos_agent::Agent, timeout: std::time::Duration) -> ExitCode {
    if timeout.is_zero() {
        let _ = writeln!(
            std::io::stderr(),
            "karyos-agent: stop deadline passed; the stop is unclean"
        );
        return ExitCode::from(3);
    }
    // The watchdog is never joined: the process ends before or with it.
    let watchdog = std::thread::Builder::new()
        .name("karyos-agent-stop".to_owned())
        .spawn(move || {
            std::thread::sleep(timeout);
            let _ = writeln!(
                std::io::stderr(),
                "karyos-agent: stop deadline passed; the stop is unclean"
            );
            std::process::exit(DEADLINE_EXIT);
        });
    if let Err(error) = watchdog {
        // Without a bound the stop is not attempted: unclean, as item 55
        // requires a bounded one.
        let _ = writeln!(
            std::io::stderr(),
            "karyos-agent: no stop watchdog ({error}); the stop is unclean"
        );
        return ExitCode::from(1);
    }
    match agent.stop() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "karyos-agent: the stop was not recorded ({error}); the stop is unclean"
            );
            ExitCode::from(1)
        }
    }
}
