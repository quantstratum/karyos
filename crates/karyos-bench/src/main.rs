// SPDX-License-Identifier: Apache-2.0

//! `karyos-bench`: runs the embedded workloads and reports them.
//!
//! ```text
//! karyos-bench [--workload <name>] [--backing heap|shared|region]
//!              [--iterations <n>] [--rate <messages/s>]
//!              [--record <dir>] [--compare <dir>]
//! ```
//!
//! `--record` appends to `<dir>/history.jsonl`; `--compare` prints the
//! change against the last record with the same workload, configuration,
//! host and profile. `--rate` changes the scheduled rate for `open-loop`.
//! `--backing` runs the default configurations of that term backing:
//! every workload that runs on it, or with `--workload` that workload's
//! default configurations moved to it, which a workload that does not run
//! on it refuses. A region exists on Linux only. Comparisons report, they
//! never fail.
//!
//! ```text
//! karyos-bench inventory --out <dir> [--records <dir>]
//! ```
//!
//! writes this host's environment record to `<dir>/environments/<host>.md`
//! (measurement-harness.md 4.3) and prints its class and its decision
//! eligibility per fan-out with every failed condition. `--records` names
//! the directory of filed records (`quantstratum-docs:
//! karyos/environments`), which eligibility checks against; without it
//! the host has no record and is ineligible.
//!
//! ```text
//! karyos-bench measure --out <dir> [--plan primary|synthetic|encrypted] [--plan-only]
//!              [--runs <n>] [--messages <N>] [--warmup <n>]
//!              [--e-max <bytes>] [--rule counts|excludes]
//! ```
//!
//! expands the plan (`plan.rs`) and runs it into `<dir>`
//! (`measure.rs`), each child pinned to an isolated core when the host
//! has two. `KARYOS_MEASURE_SMOKE=1` starts from the smoke plan, whose
//! small `N` is labelled `insufficient samples`. `--plan-only` prints
//! the plan and its estimated runtime and runs nothing.
//!
//! ```text
//! karyos-bench analyze --out <dir>
//! karyos-bench alloc --out <dir>      (the alloc-count build only)
//! karyos-bench build-info             (prints `build timing` or `build alloc-count`,
//!                                       with `+synthetic` in a synthetic build)
//! ```
//!
//! decides every point of a `measure` directory and writes `report.md`
//! and `analysis.json` into it (`analyze.rs`).
//!
//! ```text
//! karyos-bench enc-cost --point W1|W2|W3|W4|W5|ctl152|rekey
//!              --profile trusted|encrypted [--samples <N>] [--warmup <n>]
//!              [--run <k>] [--backend <label>] [--header]
//! ```
//!
//! times one complete seal and open of the encrypted profile, or of the
//! trusted channel, per envelope (one datagram, 20 messages at W5) at one
//! point (`enc_cost.rs`) and prints one CSV row per operation, in
//! nanoseconds per envelope operation; one process is one run.
//!
//! ```text
//! karyos-bench timeouts pause --seconds <s> [--tick-us <us>]
//! karyos-bench timeouts echo --bind <addr> --seconds <s>
//! karyos-bench timeouts rtt --to <addr> [--count <n>] [--interval-us <us>] [--size <bytes>]
//! ```
//!
//! measures the inputs of the Cluster's election-timeout defaults
//! (`timeouts.rs`): this host's timer overshoot, or the UDP round trip to
//! an `echo` on another host, each printed as one JSON line with the
//! host's load through the run.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use karyos_bench::env::{self, Labels};
use karyos_bench::inventory::{self, Eligibility, Inventory, Scope};
use karyos_bench::manifest::{ILLUSTRATIVE_E_MAX, MtuRule, primary};
use karyos_bench::plan::{self, PlanOptions};
use karyos_bench::wire::process::Cores;
use karyos_bench::{
    Backing, Config, Workload, analyze, archive_configs, defaults, measure, report, run,
};

/// The allocation build counts allocations with this allocator; it never
/// measures timing (`alloc-count`, M-9).
#[cfg(feature = "alloc-count")]
#[global_allocator]
static ALLOCATOR: karyos_sys::alloc_count::CountingAllocator =
    karyos_sys::alloc_count::CountingAllocator;

struct Options {
    workload: Option<Workload>,
    backing: Option<Backing>,
    iterations: u64,
    rate: Option<u64>,
    record: Option<PathBuf>,
    compare: Option<PathBuf>,
}

fn parse() -> Result<Options, String> {
    let mut options = Options {
        workload: None,
        backing: None,
        iterations: 20_000,
        rate: None,
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
            "--backing" => {
                let name = value()?;
                options.backing = Some(
                    Backing::parse(&name)
                        .ok_or(format!("unknown backing {name}: heap, shared or region"))?,
                );
            }
            "--iterations" => {
                options.iterations = value()?
                    .parse()
                    .map_err(|_| "--iterations needs a number".to_string())?;
            }
            "--rate" => {
                options.rate = Some(value()?.parse().map_err(|_| {
                    "--rate needs a positive messages-per-second value".to_string()
                })?);
            }
            "--record" => options.record = Some(PathBuf::from(value()?)),
            "--compare" => options.compare = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(options)
}

/// The default configurations `options` select.
fn selected(options: &Options) -> Vec<Config> {
    let mut all = defaults(options.iterations);
    // The archive workloads write to a disk: only when named.
    if options.workload.is_some() {
        all.extend(archive_configs(options.iterations));
    }
    let configs = all
        .into_iter()
        .filter(|config| options.workload.is_none_or(|w| w == config.workload));
    match (options.backing, options.workload) {
        (None, _) => configs.collect(),
        (Some(backing), None) => configs.filter(|config| config.backing == backing).collect(),
        // The workload's default configurations on `backing`: `run`
        // refuses a backing the workload does not run on.
        (Some(backing), Some(workload)) => {
            let mut moved: Vec<Config> = Vec::new();
            for config in configs.filter(|config| config.backing == workload.default_backing()) {
                let config = Config { backing, ..config };
                if !moved.contains(&config) {
                    moved.push(config);
                }
            }
            moved
        }
    }
}

fn inventory_command(args: &[String]) -> Result<String, String> {
    let mut out = None;
    let mut records = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .map(PathBuf::from)
                .ok_or(format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--out" => out = Some(value()?),
            "--records" => records = Some(value()?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let out = out.ok_or("inventory needs --out <dir>")?;
    let inventory = Inventory::detect(Scope::Full);
    let classification = env::classify(&inventory);
    let record = records
        .as_ref()
        .and_then(|dir| std::fs::read_to_string(dir.join(format!("{}.md", inventory.host))).ok());
    let eligibility: Vec<Eligibility> = env::FANOUTS
        .iter()
        .map(|fanout| {
            (
                *fanout,
                env::decision_eligible(&inventory, record.as_deref(), *fanout),
            )
        })
        .collect();
    let text = inventory::render(&inventory, &classification, &eligibility);
    let path = inventory::write(&out, &inventory, &text)
        .map_err(|cause| format!("{}: {cause}", out.display()))?;
    let mut report = format!(
        "wrote {}\nhost {}: class {} ({})\n",
        path.display(),
        inventory.host,
        classification.environment,
        classification.environment.usage()
    );
    for basis in &classification.basis {
        report.push_str(&format!("  {basis}\n"));
    }
    for (fanout, verdict) in &eligibility {
        let what = env::fanout_label(*fanout);
        match verdict {
            Ok(()) => report.push_str(&format!("{what}: eligible\n")),
            Err(reasons) => {
                report.push_str(&format!("{what}: ineligible\n"));
                for reason in reasons {
                    report.push_str(&format!("  {reason}\n"));
                }
            }
        }
    }
    Ok(report)
}

fn measure_command(args: &[String], out: &mut dyn Write) -> Result<usize, String> {
    let smoke = std::env::var("KARYOS_MEASURE_SMOKE").is_ok_and(|value| value == "1");
    let mut options = if smoke {
        PlanOptions::smoke(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope)
    } else {
        PlanOptions::decision(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope)
    };
    let mut dir = None;
    let mut plan_only = false;
    // The last --plan wins.
    let mut synthetic = false;
    let mut encrypted = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        let number = |text: &String| {
            text.parse::<u64>()
                .map_err(|_| format!("{arg} needs a number"))
        };
        match arg.as_str() {
            "--out" => dir = Some(PathBuf::from(value()?)),
            "--plan" => match value()?.as_str() {
                "primary" => (synthetic, encrypted) = (false, false),
                // The B3e check: report-only, in a synthetic build.
                "synthetic" => (synthetic, encrypted) = (true, false),
                // The encrypted class's cost (karyos#650).
                "encrypted" => (synthetic, encrypted) = (false, true),
                set => {
                    return Err(format!(
                        "unknown plan {set}: primary, synthetic or encrypted"
                    ));
                }
            },
            "--plan-only" => plan_only = true,
            "--runs" => {
                options.runs =
                    u32::try_from(number(value()?)?).map_err(|_| "--runs too large".to_string())?;
            }
            "--messages" => options.messages = number(value()?)?,
            "--warmup" => options.warmup = number(value()?)?,
            "--e-max" => {
                options.e_max = u32::try_from(number(value()?)?)
                    .map_err(|_| "--e-max too large".to_string())?;
            }
            "--rule" => {
                options.rule = match value()?.as_str() {
                    "counts" => MtuRule::CountsEnvelope,
                    "excludes" => MtuRule::ExcludesEnvelope,
                    other => return Err(format!("unknown rule {other}")),
                };
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if synthetic {
        options = options.with_synthetic_check();
    }
    if encrypted {
        options = options.with_encrypted();
    }
    if karyos_bench::wire::process::faults_requested() {
        return Err(format!(
            "{} is set: a measurement never runs with injected faults",
            karyos_bench::wire::process::FAULTS
        ));
    }
    if cfg!(feature = "alloc-count") {
        return Err(
            "this is the allocation build (alloc-count): it never measures timing; use `alloc`"
                .to_string(),
        );
    }
    let plan = plan::expand(&primary(), &options).map_err(|error| error.0)?;
    if plan_only {
        let _ = write!(out, "{}", plan::render(&plan));
        return Ok(0);
    }
    let dir = dir.ok_or("measure needs --out <dir>")?;
    let cores = Cores::detect();
    let _ = write!(out, "{}", plan::render(&plan));
    match &cores {
        Ok(cores) => {
            let _ = writeln!(
                out,
                "pinned: quiet cores {:?}; receivers first, then the sender",
                cores.quiet
            );
        }
        Err(reason) => {
            let _ = writeln!(out, "unpinned: {reason}; every result is functional only");
        }
    }
    let facts = measure::HostFacts::detect();
    match &facts.record {
        Some((path, _)) => {
            let _ = writeln!(out, "host record: {}", path.display());
        }
        None => {
            let _ = writeln!(out, "host record: none (set KARYOS_ENVIRONMENTS)");
        }
    }
    measure::run_plan(&plan, &dir, &Labels::detect(), &cores, &facts, out).map_err(|error| error.0)
}

fn alloc_command(args: &[String], out: &mut dyn Write) -> Result<usize, String> {
    let dir = match args {
        [flag, dir] if flag == "--out" => PathBuf::from(dir),
        _ => return Err("alloc needs --out <dir>".to_string()),
    };
    if !cfg!(feature = "alloc-count") {
        return Err(
            "this is a timing build: counting allocations needs the alloc-count build".to_string(),
        );
    }
    measure::run_alloc(&dir, out).map_err(|error| error.0)
}

fn analyze_command(args: &[String]) -> Result<String, String> {
    let (dir, interval_on_e4) = match args {
        [flag, dir] if flag == "--out" => (PathBuf::from(dir), false),
        [flag, dir, e4] if flag == "--out" && e4 == "--interval-on-e4" => {
            (PathBuf::from(dir), true)
        }
        _ => return Err("analyze needs --out <dir> [--interval-on-e4]".to_string()),
    };
    let analysis = analyze::write_with(&dir, interval_on_e4).map_err(|error| error.0)?;
    Ok(format!(
        "wrote {}: {}, overall {}\n",
        dir.join("report.md").display(),
        if analysis.decision_grade() {
            "decision grade"
        } else {
            "not decision grade"
        },
        analysis.overall.label()
    ))
}

/// `karyos-bench enc-cost ...`: one run of one point, as CSV rows.
fn enc_cost_command(args: &[String]) -> Result<String, String> {
    use karyos_bench::enc_cost::{Point, Profile, Run, run};
    let mut point = None;
    let mut profile = None;
    let mut samples = 1_000_000_u64;
    let mut warmup = 100_000_u64;
    let mut index = 1_u32;
    let mut backend = "accel".to_string();
    let mut header = false;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        if flag == "--header" {
            header = true;
            continue;
        }
        let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let bad = |_| format!("bad {flag} {value}");
        match flag.as_str() {
            "--point" => point = Some(Point::of(value).map_err(|e| e.0)?),
            "--profile" => profile = Some(Profile::of(value).map_err(|e| e.0)?),
            "--samples" => samples = value.parse().map_err(bad)?,
            "--warmup" => warmup = value.parse().map_err(bad)?,
            "--run" => index = value.parse().map_err(bad)?,
            "--backend" => backend.clone_from(value),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let (Some(point), Some(profile)) = (point, profile) else {
        return Err("enc-cost needs --point and --profile".to_string());
    };
    karyos_bench::enc_cost::timing_build(cfg!(feature = "alloc-count")).map_err(|e| e.0)?;
    let result = run(point, profile, warmup, samples).map_err(|e| e.0)?;
    let mut out = String::new();
    if header {
        out.push_str(&karyos_bench::enc_cost::build_identity());
        out.push('\n');
        out.push_str(Run::HEADER);
        out.push('\n');
    }
    out.push_str(&result.csv(&backend, index));
    Ok(out)
}

/// `karyos-bench timeouts <probe> ...`: one probe, its report on `out`.
fn timeouts(args: &[String], out: &mut impl Write, err: &mut impl Write) -> ExitCode {
    use karyos_bench::timeouts;
    use std::time::Duration;
    let usage = "usage: karyos-bench timeouts pause --seconds <s> [--tick-us <us>] | echo --bind <addr> --seconds <s> | rtt --to <addr> [--count <n>] [--interval-us <us>] [--size <bytes>]";
    let Some(probe) = args.first() else {
        let _ = writeln!(err, "{usage}");
        return ExitCode::from(2);
    };
    let mut seconds = 10u64;
    let mut tick_us = 1_000u64;
    let mut count = 10_000u64;
    let mut interval_us = 1_000u64;
    let mut size = 64usize;
    let mut address: Option<std::net::SocketAddr> = None;
    let mut rest = args.iter().skip(1);
    while let Some(flag) = rest.next() {
        let Some(value) = rest.next() else {
            let _ = writeln!(err, "{flag} needs a value\n{usage}");
            return ExitCode::from(2);
        };
        let parsed = match flag.as_str() {
            "--seconds" => value.parse().map(|v| seconds = v).is_ok(),
            "--tick-us" => value.parse().map(|v| tick_us = v).is_ok(),
            "--count" => value.parse().map(|v| count = v).is_ok(),
            "--interval-us" => value.parse().map(|v| interval_us = v).is_ok(),
            "--size" => value.parse().map(|v| size = v).is_ok(),
            "--bind" | "--to" => value.parse().map(|v| address = Some(v)).is_ok(),
            _ => false,
        };
        if !parsed {
            let _ = writeln!(err, "bad {flag} {value}\n{usage}");
            return ExitCode::from(2);
        }
    }
    let line = match (probe.as_str(), address) {
        ("pause", _) => Ok(timeouts::pause(
            Duration::from_secs(seconds),
            Duration::from_micros(tick_us),
        )
        .json()),
        ("echo", Some(bind)) => timeouts::echo(bind, Duration::from_secs(seconds))
            .map(|answered| format!("{{\"probe\":\"echo\",\"answered\":{answered}}}")),
        ("rtt", Some(to)) => {
            timeouts::rtt(to, count, Duration::from_micros(interval_us), size).map(|r| r.json())
        }
        _ => {
            let _ = writeln!(err, "{usage}");
            return ExitCode::from(2);
        }
    };
    match line {
        Ok(line) => {
            let _ = writeln!(out, "{line}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(err, "karyos-bench timeouts: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    // The child of an IPC workload runs its part and nothing else.
    #[cfg(target_os = "linux")]
    if let Some(result) = karyos_bench::ipc::child() {
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(cause) => {
                let _ = writeln!(std::io::stderr(), "karyos-bench child: {cause}");
                ExitCode::FAILURE
            }
        };
    }
    // A wire child runs its role and nothing else.
    if let Some(result) = karyos_bench::wire::process::child() {
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(cause) => {
                let _ = writeln!(std::io::stderr(), "karyos-bench wire child: {cause}");
                ExitCode::FAILURE
            }
        };
    }
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("enc-cost") {
        return match enc_cost_command(args.get(1..).unwrap_or_default()) {
            Ok(rows) => {
                let _ = write!(out, "{rows}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                let _ = writeln!(err, "karyos-bench enc-cost: {message}");
                ExitCode::from(2)
            }
        };
    }
    if args.first().map(String::as_str) == Some("timeouts") {
        return timeouts(args.get(1..).unwrap_or(&[]), &mut out, &mut err);
    }
    if args.first().map(String::as_str) == Some("inventory") {
        return match inventory_command(args.get(1..).unwrap_or_default()) {
            Ok(report) => {
                let _ = write!(out, "{report}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                let _ = writeln!(err, "karyos-bench inventory: {message}");
                ExitCode::from(2)
            }
        };
    }
    if args.first().map(String::as_str) == Some("build-info") {
        // Which build this binary is: measure.sh and `make
        // timing-build-check` refuse to time anything but `timing`.
        let _ = writeln!(out, "build {}", karyos_bench::wire::stage::BUILD);
        return ExitCode::SUCCESS;
    }
    if args.first().map(String::as_str) == Some("alloc") {
        return match alloc_command(args.get(1..).unwrap_or_default(), &mut out) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(failed) => {
                let _ = writeln!(
                    err,
                    "karyos-bench alloc: {failed} points allocate or failed"
                );
                ExitCode::FAILURE
            }
            Err(message) => {
                let _ = writeln!(err, "karyos-bench alloc: {message}");
                ExitCode::from(2)
            }
        };
    }
    if args.first().map(String::as_str) == Some("analyze") {
        return match analyze_command(args.get(1..).unwrap_or_default()) {
            Ok(report) => {
                let _ = write!(out, "{report}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                let _ = writeln!(err, "karyos-bench analyze: {message}");
                ExitCode::from(2)
            }
        };
    }
    if args.first().map(String::as_str) == Some("measure") {
        return match measure_command(args.get(1..).unwrap_or_default(), &mut out) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(failed) => {
                let _ = writeln!(err, "karyos-bench measure: {failed} runs failed");
                ExitCode::FAILURE
            }
            Err(message) => {
                let _ = writeln!(err, "karyos-bench measure: {message}");
                ExitCode::from(2)
            }
        };
    }
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
    let configs = selected(&options);
    if configs.is_empty() {
        let _ = writeln!(
            err,
            "karyos-bench: no default configuration runs on backing {} here",
            options.backing.map_or("heap", Backing::name)
        );
        return ExitCode::from(2);
    }
    for mut config in configs {
        if config.workload == Workload::OpenLoop
            && let Some(rate) = options.rate
        {
            config.target_rate = Some(rate);
        }
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
