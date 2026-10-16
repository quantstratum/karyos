// SPDX-License-Identifier: Apache-2.0

//! The `measure` subcommand (`quantstratum-docs:
//! karyos/design/measurement-harness.md` 5.5): runs every run of a
//! [`Plan`] in a fresh pair of processes and records it.
//!
//! The output directory holds:
//!
//! - `measure.json`: the manifest version and hash, the labels of this
//!   host, the plan's options and label, and the cores or why there are
//!   none;
//! - `plan.txt`: the plan as [`plan::render`] prints it;
//! - `runs/<index>_<point>_<configuration>_r<round>/`: the raw sample
//!   files and sidecars of each run;
//! - `results.jsonl`: one hand-written JSON line per run, in plan order.
//!
//! A run that fails is recorded with its error and the plan goes on: an
//! invalid run is a result the analysis (batch B4b) must see.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::env::Labels;
use crate::manifest::{MANIFEST_SHA256, VERSION};
use crate::plan::{self, INSUFFICIENT, Plan, PlannedRun};
use crate::samples::MISSING;
use crate::wire::process::{Cores, FAULTS, ProcessOptions, faults_requested, run_processes};
use crate::wire::stage::{StageLoad, StageSamples};
use crate::workloads::BenchError;

/// `text` as a JSON string literal.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn count_missing(samples: &[u32]) -> usize {
    samples.iter().filter(|sample| **sample == MISSING).count()
}

/// The `results.jsonl` line of one run: `outcome` is its samples or the
/// error that ended it.
#[must_use]
pub fn result_line(
    index: usize,
    planned: &PlannedRun,
    dir: &str,
    cores: Option<Cores>,
    duration: Duration,
    outcome: &Result<StageSamples, BenchError>,
) -> String {
    let run = &planned.run;
    let load = match run.load {
        StageLoad::Closed => "R1".to_string(),
        StageLoad::Open { rate } => format!("R2@{rate}"),
    };
    let mut fields = vec![
        format!("\"index\":{index}"),
        format!("\"point\":{}", json_string(&planned.point.to_string())),
        format!("\"configuration\":{}", json_string(&planned.configuration)),
        format!("\"round\":{}", planned.round),
        format!("\"load\":{}", json_string(&load)),
        format!("\"sequences\":{}", run.messages),
        format!("\"messages_per_sample\":{}", planned.messages_per_sample),
        format!("\"surplus\":{}", planned.surplus),
        format!("\"warmup\":{}", run.warmup),
        format!("\"e_max\":{}", run.e_max),
        format!("\"rule\":{}", json_string(&format!("{:?}", run.rule))),
        format!(
            "\"cores\":{}",
            cores.map_or_else(
                || "null".to_string(),
                |c| format!("[{},{}]", c.receiver, c.sender)
            )
        ),
        format!("\"duration_ms\":{}", duration.as_millis()),
        format!("\"dir\":{}", json_string(dir)),
    ];
    match outcome {
        Ok(samples) => {
            let reasons: Vec<String> = samples
                .functional_reasons
                .iter()
                .map(|reason| json_string(reason))
                .collect();
            fields.extend([
                format!("\"send_missing\":{}", count_missing(&samples.send)),
                format!("\"receive_missing\":{}", count_missing(&samples.receive)),
                format!("\"backend_drops\":{}", samples.backend_drops),
                format!("\"backpressure\":{}", samples.backpressure),
                format!("\"batches\":{}", samples.batches.len()),
                format!("\"functional_only\":{}", samples.functional_only),
                format!("\"functional_reasons\":[{}]", reasons.join(",")),
                "\"error\":null".to_string(),
            ]);
        }
        Err(error) => fields.push(format!("\"error\":{}", json_string(&error.0))),
    }
    format!("{{{}}}", fields.join(","))
}

/// The `measure.json` of a plan.
#[must_use]
pub fn header(plan: &Plan, labels: &Labels, cores: &Result<Cores, String>) -> String {
    let options = &plan.options;
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let configurations: Vec<String> = options
        .configurations
        .iter()
        .map(|name| json_string(name))
        .collect();
    let fields = [
        format!("\"manifest_version\":{}", json_string(VERSION)),
        format!("\"manifest_sha256\":{}", json_string(MANIFEST_SHA256)),
        format!("\"started_unix\":{started}"),
        "\"faults\":\"off\"".to_string(),
        format!("\"host\":{}", json_string(&labels.host)),
        format!("\"os\":{}", json_string(labels.os)),
        format!("\"arch\":{}", json_string(labels.arch)),
        format!("\"cpu\":{}", json_string(&labels.cpu)),
        format!("\"profile\":{}", json_string(labels.profile)),
        format!("\"commit\":{}", json_string(&labels.commit)),
        format!("\"environment\":{}", json_string(&labels.qualification)),
        format!("\"messages\":{}", options.messages),
        format!("\"warmup\":{}", options.warmup),
        format!("\"rounds\":{}", options.runs),
        format!("\"e_max\":{}", options.e_max),
        format!(
            "\"e_max_status\":{}",
            json_string("provisional E_max (illustrative, manifest 6.1)")
        ),
        format!("\"rule\":{}", json_string(&format!("{:?}", options.rule))),
        format!("\"configurations\":[{}]", configurations.join(",")),
        format!(
            "\"label\":{}",
            if options.sufficient() {
                "null".to_string()
            } else {
                json_string(INSUFFICIENT)
            }
        ),
        match cores {
            Ok(c) => format!("\"cores\":[{},{}]", c.receiver, c.sender),
            Err(reason) => format!("\"cores\":null,\"unpinned\":{}", json_string(reason)),
        },
    ];
    format!("{{{}}}\n", fields.join(","))
}

/// Runs every run of `plan` into `out`, printing one line per run to
/// `log`; returns how many runs failed.
///
/// # Errors
///
/// [`FAULTS`] set in the environment (a measurement never runs with
/// injected faults, ACS 15309), an output directory that already holds a
/// measurement, or one that cannot be written.
pub fn run_plan(
    plan: &Plan,
    out: &Path,
    labels: &Labels,
    cores: &Result<Cores, String>,
    log: &mut dyn Write,
) -> Result<usize, BenchError> {
    if faults_requested() {
        return Err(BenchError(format!(
            "{FAULTS} is set: a measurement never runs with injected faults"
        )));
    }
    let io = |what: &str, cause: std::io::Error| BenchError(format!("{what}: {cause}"));
    for name in ["measure.json", "results.jsonl"] {
        if out.join(name).exists() {
            return Err(BenchError(format!(
                "{} already holds {name}: a measurement never overwrites another",
                out.display()
            )));
        }
    }
    std::fs::create_dir_all(out.join("runs")).map_err(|cause| io("output directory", cause))?;
    std::fs::write(out.join("measure.json"), header(plan, labels, cores))
        .map_err(|cause| io("measure.json", cause))?;
    std::fs::write(out.join("plan.txt"), plan::render(plan))
        .map_err(|cause| io("plan.txt", cause))?;
    let mut results = std::fs::File::create(out.join("results.jsonl"))
        .map_err(|cause| io("results.jsonl", cause))?;
    let pinned = cores.as_ref().ok().copied();
    let total = plan.runs.len();
    let mut failed = 0_usize;
    for (index, planned) in plan.runs.iter().enumerate() {
        let dir = format!("runs/{index:04}_{}", planned.slug());
        let started = Instant::now();
        let options = ProcessOptions {
            run_index: planned.round,
            cores: pinned,
            ..ProcessOptions::default()
        };
        let outcome = run_processes(&planned.run, &out.join(&dir), &options);
        let duration = started.elapsed();
        let line = result_line(index, planned, &dir, pinned, duration, &outcome);
        writeln!(results, "{line}").map_err(|cause| io("results.jsonl", cause))?;
        let summary = match &outcome {
            Ok(samples) => format!(
                "receive missing {}, backpressure {}",
                count_missing(&samples.receive),
                samples.backpressure
            ),
            Err(error) => {
                failed = failed
                    .checked_add(1)
                    .ok_or_else(|| BenchError("failure count".into()))?;
                format!("failed: {}", error.0)
            }
        };
        let _ = writeln!(
            log,
            "[{}/{total}] {} {} round {}: {summary} ({} ms)",
            index.checked_add(1).unwrap_or(index),
            planned.point,
            planned.configuration,
            planned.round,
            duration.as_millis()
        );
    }
    Ok(failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ILLUSTRATIVE_E_MAX, MtuRule, primary};
    use crate::plan::{PlanOptions, expand};

    #[test]
    fn measure_json_records_faults_off_and_the_provisional_e_max() {
        let plan = expand(
            &primary(),
            &PlanOptions::smoke(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope),
        )
        .unwrap();
        let header = header(&plan, &Labels::detect(), &Err("none".into()));
        assert!(header.contains("\"faults\":\"off\""), "{header}");
        assert!(
            header.contains("\"e_max_status\":\"provisional E_max (illustrative, manifest 6.1)\""),
            "{header}"
        );
        assert!(header.contains("\"unpinned\":\"none\""), "{header}");
    }

    #[test]
    fn a_measurement_never_overwrites_another() {
        let out = std::env::temp_dir().join(format!("karyos-measure-reuse-{}", std::process::id()));
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("results.jsonl"), "").unwrap();
        let plan = expand(
            &primary(),
            &PlanOptions::smoke(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope),
        )
        .unwrap();
        let error = run_plan(
            &plan,
            &out,
            &Labels::detect(),
            &Err("none".into()),
            &mut Vec::new(),
        )
        .err()
        .map(|error| error.0)
        .unwrap_or_default();
        assert!(error.contains("never overwrites"), "{error}");
        assert!(!out.join("measure.json").exists());
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn json_strings_escape_what_json_needs() {
        assert_eq!(json_string("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }

    #[test]
    fn a_failed_run_keeps_its_place_and_its_error() {
        let plan = expand(
            &primary(),
            &PlanOptions::smoke(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope),
        )
        .unwrap();
        let planned = plan.runs.first().unwrap();
        let line = result_line(
            3,
            planned,
            "runs/0003_x",
            None,
            Duration::from_millis(12),
            &Err(BenchError("orphan sequence 9 (M-11)".into())),
        );
        assert!(
            line.starts_with("{\"index\":3,\"point\":\"W1/R1/F1\""),
            "{line}"
        );
        assert!(line.contains("\"cores\":null"), "{line}");
        assert!(
            line.ends_with("\"error\":\"orphan sequence 9 (M-11)\"}"),
            "{line}"
        );
    }
}
