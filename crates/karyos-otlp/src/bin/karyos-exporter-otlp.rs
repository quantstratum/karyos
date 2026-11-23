// SPDX-License-Identifier: Apache-2.0

//! `karyos-exporter-otlp`: the agent's view of each driver pushed to an
//! OpenTelemetry collector over OTLP/HTTP (SPEC.md §14; karyos#706). The
//! same metric families as `karyos-exporter`'s Prometheus endpoint, from
//! the same definition, with no listening port. A separate process, off
//! unless started with a collector. Exit status: 2 on a bad command line
//! or a collector refused, 1 when exporting cannot start.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// The command line's usage.
const USAGE: &str = "\
usage: karyos-exporter-otlp --otlp-endpoint ADDRESS:PORT --driver DIR [--driver DIR]... \
[--otlp-interval-ms MS] [--otlp-timeout-ms MS] [--otlp-allow-remote] \
[--refresh-ms MS] [--agent-id NAME]

Pushes the agent's view of each driver, the metric families of
karyos-exporter's Prometheus endpoint, to the OpenTelemetry collector at
http://ADDRESS:PORT/v1/metrics over OTLP/HTTP (binary protobuf, HTTP/1.1,
in clear) every MS milliseconds (--otlp-interval-ms, default 10000), each
request bounded by --otlp-timeout-ms (default 5000). ADDRESS must be a
loopback address unless --otlp-allow-remote, which writes a warning at
start. It reads each driver's CnC as a tool every --refresh-ms
milliseconds (default 1000), taking one of each driver's tool slots
(max_tools) while attached. --agent-id names it in karyos_exporter_info.
Off unless started: without it, no OTLP is sent. Linux only.
";

/// A parsed command line.
#[derive(Debug)]
struct Args {
    endpoint: SocketAddr,
    drivers: Vec<PathBuf>,
    interval: Duration,
    timeout: Duration,
    allow_remote: bool,
    refresh: Duration,
    agent_id: Option<String>,
}

fn parse(args: &[String]) -> Option<Args> {
    let mut endpoint = None;
    let mut drivers = Vec::new();
    let mut interval = karyos_otlp::DEFAULT_INTERVAL;
    let mut timeout = karyos_otlp::DEFAULT_TIMEOUT;
    let mut allow_remote = false;
    let mut refresh = Duration::from_secs(1);
    let mut agent_id = None;
    let millis = |value: &str| {
        value
            .parse::<u64>()
            .ok()
            .filter(|ms| *ms > 0)
            .map(Duration::from_millis)
    };
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        if flag == "--otlp-allow-remote" {
            allow_remote = true;
            continue;
        }
        let value = args.next()?;
        match flag.as_str() {
            "--otlp-endpoint" => endpoint = Some(value.parse().ok()?),
            "--driver" => drivers.push(PathBuf::from(value)),
            "--otlp-interval-ms" => interval = millis(value)?,
            "--otlp-timeout-ms" => timeout = millis(value)?,
            "--refresh-ms" => refresh = millis(value)?,
            "--agent-id" => agent_id = Some(value.clone()),
            _ => return None,
        }
    }
    if drivers.is_empty() {
        return None;
    }
    Some(Args {
        endpoint: endpoint?,
        drivers,
        interval,
        timeout,
        allow_remote,
        refresh,
        agent_id,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(args) = parse(&args) else {
        let _ = std::io::stderr().write_all(USAGE.as_bytes());
        return ExitCode::from(2);
    };
    serve(args)
}

#[cfg(not(target_os = "linux"))]
fn serve(args: Args) -> ExitCode {
    let _ = args;
    let _ = writeln!(std::io::stderr(), "karyos-exporter-otlp: Linux only");
    ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn serve(args: Args) -> ExitCode {
    use karyos_agent::{Agent, AgentConfig, exporter};
    use karyos_otlp::{OtlpConfig, OtlpError, OtlpExport};

    let mut config = OtlpConfig::new(args.endpoint)
        .with_interval(args.interval)
        .with_timeout(args.timeout);
    if args.allow_remote {
        config = config.allowing_remote();
    }
    let export = match OtlpExport::start(&config) {
        Ok(export) => export,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "karyos-exporter-otlp: {error}");
            return ExitCode::from(match error {
                OtlpError::NotLoopback(_) => 2,
                _ => 1,
            });
        }
    };
    if !args.endpoint.ip().is_loopback() {
        let _ = writeln!(
            std::io::stderr(),
            "karyos-exporter-otlp: warning: exporting to {}, not a loopback address, in clear",
            args.endpoint
        );
    }
    let mut agent_config = AgentConfig::new(args.drivers);
    if let Some(id) = args.agent_id {
        agent_config = agent_config.with_agent_id(id);
    }
    let mut agent = Agent::new(agent_config);
    // Each refresh publishes its pass; the reader exports the latest at
    // its own interval, never holding this loop.
    loop {
        agent.refresh();
        export.publish(exporter::families(&agent.view()));
        std::thread::sleep(args.refresh);
    }
}
