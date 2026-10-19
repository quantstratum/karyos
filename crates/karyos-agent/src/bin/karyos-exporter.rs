// SPDX-License-Identifier: Apache-2.0

//! `karyos-exporter`: the agent's view of each driver in the Prometheus
//! text format, over HTTP on a loopback address (SPEC.md §11, ADR-0055;
//! quantstratum-docs: karyos/design/management-agent-gap-analysis.md, M8;
//! owner item 51, interim 4). A separate process from `karyos-agent`; off
//! unless started. Exit status: 2 on a bad command line or when the address
//! cannot be bound, 1 when serving fails.

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(args) = karyos_agent::cli::parse_exporter(&args) else {
        let _ = std::io::stderr().write_all(karyos_agent::cli::EXPORTER_USAGE.as_bytes());
        return ExitCode::from(2);
    };
    serve(args)
}

#[cfg(not(target_os = "linux"))]
fn serve(args: karyos_agent::cli::ExporterArgs) -> ExitCode {
    let _ = args;
    let _ = writeln!(std::io::stderr(), "karyos-exporter: Linux only");
    ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn serve(args: karyos_agent::cli::ExporterArgs) -> ExitCode {
    use std::time::{Duration, Instant};

    use karyos_agent::{Agent, AgentConfig, exporter};

    let mut listener = match exporter::bind(args.listen) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "karyos-exporter: {error}");
            return ExitCode::from(2);
        }
    };
    let mut agent = Agent::new(AgentConfig::new(args.drivers));
    // Between refreshes the listener is polled every 10 ms; a scrape reads
    // the view of the last refresh.
    let tick = Duration::from_millis(10).min(args.refresh);
    loop {
        agent.refresh();
        let next = Instant::now().checked_add(args.refresh);
        loop {
            if let Err(error) = listener.poll(|| exporter::render(&agent.view())) {
                let _ = writeln!(std::io::stderr(), "karyos-exporter: {error}");
                return ExitCode::from(1);
            }
            if next.is_none_or(|next| Instant::now() >= next) {
                break;
            }
            std::thread::sleep(tick);
        }
    }
}
