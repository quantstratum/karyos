// SPDX-License-Identifier: Apache-2.0

//! `karyos-bench`: runs the embedded workloads and reports them.
//!
//! ```text
//! karyos-bench [--workload <name>] [--iterations <n>] [--record <dir>] [--compare <dir>]
//! ```
//!
//! `--record` appends to `<dir>/history.jsonl`; `--compare` prints the
//! change against the last record with the same workload, configuration,
//! host and profile. Comparisons report, they never fail.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use karyos_bench::env::Labels;
use karyos_bench::{Workload, defaults, report, run};

struct Options {
    workload: Option<Workload>,
    iterations: u64,
    record: Option<PathBuf>,
    compare: Option<PathBuf>,
}

fn parse() -> Result<Options, String> {
    let mut options = Options {
        workload: None,
        iterations: 20_000,
        record: None,
        compare: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--workload" => {
                let name = value()?;
                options.workload =
                    Some(Workload::parse(&name).ok_or(format!("unknown workload {name}"))?);
            }
            "--iterations" => {
                options.iterations = value()?
                    .parse()
                    .map_err(|_| "--iterations needs a number".to_string())?;
            }
            "--record" => options.record = Some(PathBuf::from(value()?)),
            "--compare" => options.compare = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(options)
}

fn main() -> ExitCode {
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let options = match parse() {
        Ok(options) => options,
        Err(message) => {
            let _ = writeln!(err, "karyos-bench: {message}");
            return ExitCode::from(2);
        }
    };
    let labels = Labels::detect();
    let history = |dir: &PathBuf| dir.join("history.jsonl");
    let previous = options
        .compare
        .as_ref()
        .and_then(|dir| std::fs::read_to_string(history(dir)).ok())
        .unwrap_or_default();
    let mut lines = Vec::new();
    for config in defaults(options.iterations)
        .into_iter()
        .filter(|config| options.workload.is_none_or(|w| w == config.workload))
    {
        let measurement = match run(config) {
            Ok(measurement) => measurement,
            Err(cause) => {
                let _ = writeln!(err, "karyos-bench: {config}: {cause}");
                return ExitCode::FAILURE;
            }
        };
        let line = report::history_line(&measurement, &labels);
        let _ = write!(out, "{}", report::text(&measurement, &labels));
        if let Some(comparison) = report::compare(&previous, &line) {
            let _ = writeln!(out, "{comparison}");
        }
        lines.push(line);
    }
    if let Some(dir) = &options.record {
        let path = history(dir);
        let written = std::fs::create_dir_all(dir).and_then(|()| {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            lines.iter().try_for_each(|line| writeln!(file, "{line}"))
        });
        if let Err(cause) = written {
            let _ = writeln!(err, "karyos-bench: {}: {cause}", path.display());
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
