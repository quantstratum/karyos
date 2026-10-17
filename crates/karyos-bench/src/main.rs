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
//! karyos-bench measure --out <dir> [--plan primary] [--plan-only]
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

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use karyos_bench::env::{self, Labels};
use karyos_bench::inventory::{self, Eligibility, Inventory, Scope};
use karyos_bench::manifest::{ILLUSTRATIVE_E_MAX, MtuRule, primary};
use karyos_bench::plan::{self, PlanOptions};
use karyos_bench::wire::process::Cores;
use karyos_bench::{Backing, Config, Workload, analyze, defaults, measure, report, run};

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
    let configs = defaults(options.iterations)
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
                "primary" => synthetic = false,
                // The B3e check: report-only, in a synthetic build.
                "synthetic" => synthetic = true,
                set => return Err(format!("unknown plan {set}: primary or synthetic")),
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
