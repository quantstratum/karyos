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
//! - `preflight-start.txt`, and `preflight.txt` in every run directory:
//!   the preflight snapshots ([`preflight`]), taken before the first run
//!   and before each run;
//! - `runs/<index>_<point>_<configuration>_r<round>/`: the raw sample
//!   files and sidecars of each run;
//! - `results.jsonl`: one hand-written JSON line per run, in plan order.
//!
//! A run that fails is recorded with its error and the plan goes on: an
//! invalid run is a result the analysis (batch B4b) must see.

use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::env::{self, Ineligible, Labels};
use crate::inventory::{Inventory, Scope};
use crate::manifest::{Fanout, MANIFEST_SHA256, VERSION};
use crate::plan::{self, INSUFFICIENT, Plan, PlannedRun};
use crate::preflight;
use crate::samples::MISSING;
use crate::wire::process::{Cores, FAULTS, ProcessOptions, faults_requested, run_processes};
use crate::wire::stage::{ReceiverSamples, StageLoad, StageSamples};
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

/// One number per receiver, joined by `,`.
fn per_receiver<T: std::fmt::Display>(
    samples: &StageSamples,
    value: impl Fn(&ReceiverSamples) -> T,
) -> String {
    samples
        .receivers
        .iter()
        .map(|receiver| value(receiver).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn core_list(cores: &[usize]) -> String {
    format!(
        "[{}]",
        cores
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// The `results.jsonl` line of one run: `outcome` is its samples or the
/// error that ended it.
#[must_use]
pub fn result_line(
    index: usize,
    planned: &PlannedRun,
    dir: &str,
    cores: Option<&Cores>,
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
        format!("\"receivers\":{}", run.receivers),
        format!(
            "\"cores\":{}",
            cores.map_or_else(|| "null".to_string(), |c| core_list(&c.quiet))
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
                format!(
                    "\"receive_missing\":[{}]",
                    per_receiver(samples, |r| count_missing(&r.receive))
                ),
                format!("\"backend_drops\":[{}]", per_receiver(samples, |r| r.drops)),
                format!("\"backpressure\":{}", samples.backpressure),
                format!("\"ack_timeouts\":{}", samples.ack_timeouts),
                format!(
                    "\"batches\":[{}]",
                    per_receiver(samples, |r| r.batches.len())
                ),
                format!("\"functional_only\":{}", samples.functional_only),
                format!("\"functional_reasons\":[{}]", reasons.join(",")),
                "\"error\":null".to_string(),
            ]);
        }
        Err(error) => fields.push(format!("\"error\":{}", json_string(&error.0))),
    }
    format!("{{{}}}", fields.join(","))
}

/// What a measurement records about its host's decision eligibility.
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    /// The F1 conditions of `env::decision_eligible` the host fails.
    pub ineligible: Vec<Ineligible>,
    /// The host record cited: its path and text, if one was found.
    pub record: Option<(PathBuf, String)>,
}

impl HostFacts {
    /// This host's facts: its record from `KARYOS_ENVIRONMENTS`, if any,
    /// and the F1 eligibility against it.
    #[must_use]
    pub fn detect() -> Self {
        let inventory = Inventory::detect(Scope::Classification);
        let record = std::env::var_os("KARYOS_ENVIRONMENTS").and_then(|dir| {
            let path = Path::new(&dir).join(format!("{}.md", inventory.host));
            std::fs::read_to_string(&path).ok().map(|text| (path, text))
        });
        let ineligible = env::decision_eligible(
            &inventory,
            record.as_ref().map(|(_, text)| text.as_str()),
            Fanout::F1,
        )
        .err()
        .unwrap_or_default();
        Self { ineligible, record }
    }
}

/// The `measure.json` of a plan.
#[must_use]
pub fn header(
    plan: &Plan,
    labels: &Labels,
    cores: &Result<Cores, String>,
    facts: &HostFacts,
) -> String {
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
        format!("\"class\":{}", json_string(&labels.environment.to_string())),
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
        format!("\"f2\":{}", options.f2),
        format!(
            "\"label\":{}",
            if options.sufficient() {
                "null".to_string()
            } else {
                json_string(INSUFFICIENT)
            }
        ),
        match cores {
            Ok(c) => format!("\"cores\":{}", core_list(&c.quiet)),
            Err(reason) => format!("\"cores\":null,\"unpinned\":{}", json_string(reason)),
        },
        format!("\"eligible\":{}", facts.ineligible.is_empty()),
        format!(
            "\"ineligible\":[{}]",
            facts
                .ineligible
                .iter()
                .map(|reason| json_string(&reason.encode()))
                .collect::<Vec<_>>()
                .join(",")
        ),
        format!(
            "\"host_record\":{}",
            facts.record.as_ref().map_or_else(
                || "null".to_string(),
                |(path, _)| json_string(&path.display().to_string())
            )
        ),
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
    facts: &HostFacts,
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
    std::fs::write(out.join("measure.json"), header(plan, labels, cores, facts))
        .map_err(|cause| io("measure.json", cause))?;
    if let Some((_, text)) = &facts.record {
        // The record the eligibility and the preflight checks cite.
        std::fs::write(out.join("host-record.md"), text)
            .map_err(|cause| io("host-record.md", cause))?;
    }
    std::fs::write(out.join("plan.txt"), plan::render(plan))
        .map_err(|cause| io("plan.txt", cause))?;
    std::fs::write(out.join("preflight-start.txt"), preflight::capture())
        .map_err(|cause| io("preflight-start.txt", cause))?;
    let mut results = std::fs::File::create(out.join("results.jsonl"))
        .map_err(|cause| io("results.jsonl", cause))?;
    let pinned = cores.as_ref().ok();
    let total = plan.runs.len();
    let mut failed = 0_usize;
    for (index, planned) in plan.runs.iter().enumerate() {
        let dir = format!("runs/{index:04}_{}", planned.slug());
        let started = Instant::now();
        // The preflight snapshot of this run (4.2 condition 4).
        std::fs::create_dir_all(out.join(&dir)).map_err(|cause| io("run directory", cause))?;
        std::fs::write(out.join(&dir).join("preflight.txt"), preflight::capture())
            .map_err(|cause| io("preflight.txt", cause))?;
        let options = ProcessOptions {
            profile: planned.configuration.clone(),
            run_index: planned.round,
            cores: pinned.cloned(),
            ..ProcessOptions::default()
        };
        let outcome = run_processes(&planned.run, &out.join(&dir), &options);
        let duration = started.elapsed();
        let line = result_line(index, planned, &dir, pinned, duration, &outcome);
        writeln!(results, "{line}").map_err(|cause| io("results.jsonl", cause))?;
        let summary = match &outcome {
            Ok(samples) => format!(
                "receive missing [{}], backpressure {}",
                per_receiver(samples, |r| count_missing(&r.receive)),
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
        let facts = HostFacts {
            ineligible: vec![Ineligible::ClockSource("hpet".into())],
            record: None,
        };
        let header = header(&plan, &Labels::detect(), &Err("none".into()), &facts);
        assert!(header.contains("\"eligible\":false"), "{header}");
        assert!(
            header.contains("\"ineligible\":[\"clock_source\\u0009hpet\"]"),
            "{header}"
        );
        assert!(header.contains("\"host_record\":null"), "{header}");
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
            &HostFacts::default(),
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
