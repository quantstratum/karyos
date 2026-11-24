// SPDX-License-Identifier: Apache-2.0

//! `karyos-exporter`: the agent's view of each driver in the Prometheus
//! text format, over HTTP on a loopback address (SPEC.md §11, ADR-0055;
//! quantstratum-docs: karyos/design/management-agent-gap-analysis.md, M8;
//! owner item 51, interim 4; R-CORE-39, karyos#734). A separate process
//! from `karyos-agent`; off unless started. Exit status: 2 on a bad command
//! line, an address that cannot be bound or a token file refused, 1 when
//! serving fails.

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

    // The token first: off loopback, no listener starts without a valid
    // one (karyos#887).
    let token = match args
        .token_file
        .as_deref()
        .map(exporter::Token::read)
        .transpose()
    {
        Ok(token) => token,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "karyos-exporter: {error}");
            return ExitCode::from(2);
        }
    };
    let bound = match &args.tls {
        None => exporter::bind(args.listen).map(|listener| match token {
            Some(token) => listener.with_token(token),
            None => listener,
        }),
        #[cfg(feature = "exporter-tls")]
        Some((cert, key)) => exporter::tls::server_config(cert, key)
            .map_err(exporter::ExportError::from)
            .and_then(|config| exporter::bind_tls(args.listen, config, token)),
        #[cfg(not(feature = "exporter-tls"))]
        Some(_) => {
            let _ = writeln!(
                std::io::stderr(),
                "karyos-exporter: --tls-cert and --tls-key need a build with the exporter-tls feature"
            );
            return ExitCode::from(2);
        }
    };
    let bound = bound.and_then(|listener| match args.deadline {
        Some(deadline) => listener.with_deadline(deadline),
        None => Ok(listener),
    });
    let mut listener = match bound {
        Ok(listener) => listener,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "karyos-exporter: {error}");
            return ExitCode::from(2);
        }
    };
    let mut config = AgentConfig::new(args.drivers);
    if let Some(id) = args.agent_id {
        config = config.with_agent_id(id);
    }
    let mut agent = Agent::new(config);
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
