// SPDX-License-Identifier: Apache-2.0

//! The analysis of a `measure` output directory (`quantstratum-docs:
//! karyos/design/measurement-harness.md` 5.4): it reads `measure.json`,
//! `results.jsonl`, the raw samples and the preflight snapshots, decides
//! every point with `decision.rs`, and writes `report.md` and
//! `analysis.json` beside them.
//!
//! - The directory must cite manifest [`VERSION`] with [`MANIFEST_SHA256`];
//!   any other hash is refused (coordinator, ACS 15349).
//! - The plan is expanded again from `measure.json`, and every line of
//!   `results.jsonl` must be the planned run of its index.
//! - Each run's decision samples are the per-message sum of its send and
//!   receive stages (M-5a, `samples::combine`); W5 samples are expanded to
//!   exactly `N` messages (`plan::keep_n`, ACS 15286).
//! - The configurations are `trusted`, the baseline, and the two sides it
//!   compares, `a` and `b` in plan order (ACS 15349).
//! - A point with a failed run is Not demonstrated. A run's functional
//!   reasons, and any preflight drift from the first snapshot or from the
//!   previous run, block a decision grade in addition to `decision::grade`.

use std::fmt::Write as _;
use std::path::Path;

use crate::decision::{
    self, Attempt, Cause, Config, DECISION_METHOD, DecisionSet, Environment, Grade, GradeInputs,
    Outcome, Overall, PointInput, PointResult, Side, Verdict,
};
use crate::manifest::{EMax, MANIFEST_SHA256, MtuRule, Point, VERSION, primary};
use crate::plan::{self, INSUFFICIENT, Plan, PlanOptions};
use crate::preflight;
use crate::samples::{self, MISSING};
use crate::stats::{self, BootstrapSpec, Resampling};
use crate::workloads::BenchError;

/// The seed handed to the interval method. It is recorded only for a
/// method that draws random numbers: the run-level Welch t interval is
/// deterministic, and a recorded but unused seed would suggest a
/// reproducibility input that does not exist (ACS 15356).
pub const SEED: u64 = 0x6b61_7279_6f73_2e38;

/// The seed to record: `None` for a deterministic method.
#[must_use]
pub fn recorded_seed() -> Option<u64> {
    (DECISION_METHOD != Resampling::RunWelchT).then_some(SEED)
}

/// The seed as the report states it.
fn seed_text() -> String {
    recorded_seed().map_or_else(
        || "seed: none (RunWelchT is deterministic)".to_string(),
        |seed| format!("seed {seed:#x}"),
    )
}

/// The baseline configuration's name.
const BASELINE: &str = "trusted";

/// One value of a flat JSON object as `measure` writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Json {
    /// A string, unescaped.
    Str(String),
    /// A list of strings.
    List(Vec<String>),
    /// A number, boolean or null, as written.
    Raw(String),
}

/// A cursor over one JSON line.
struct Cursor<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl Cursor<'_> {
    fn bad(&self, what: &str) -> BenchError {
        BenchError(format!("malformed JSON: {what}"))
    }

    fn expect(&mut self, c: char) -> Result<(), BenchError> {
        (self.chars.next() == Some(c))
            .then_some(())
            .ok_or_else(|| self.bad(&format!("expected {c}")))
    }

    fn string(&mut self) -> Result<String, BenchError> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.chars.next().ok_or_else(|| self.bad("open string"))? {
                '"' => return Ok(out),
                '\\' => match self.chars.next().ok_or_else(|| self.bad("escape"))? {
                    'n' => out.push('\n'),
                    'u' => {
                        let hex: String = (0..4).filter_map(|_| self.chars.next()).collect();
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| self.bad("\\u"))?;
                        out.push(char::from_u32(code).ok_or_else(|| self.bad("\\u"))?);
                    }
                    other => out.push(other),
                },
                c => out.push(c),
            }
        }
    }

    fn value(&mut self) -> Result<Json, BenchError> {
        match self.chars.peek() {
            Some('"') => Ok(Json::Str(self.string()?)),
            Some('[') => {
                self.expect('[')?;
                let mut items = Vec::new();
                if self.chars.peek() == Some(&']') {
                    self.expect(']')?;
                    return Ok(Json::List(items));
                }
                loop {
                    items.push(match self.value()? {
                        Json::Str(text) | Json::Raw(text) => text,
                        Json::List(_) => return Err(self.bad("nested list")),
                    });
                    match self.chars.next() {
                        Some(',') => {}
                        Some(']') => return Ok(Json::List(items)),
                        _ => return Err(self.bad("list")),
                    }
                }
            }
            _ => {
                let mut raw = String::new();
                while let Some(&c) = self.chars.peek() {
                    if c == ',' || c == '}' || c == ']' {
                        break;
                    }
                    raw.push(c);
                    self.chars.next();
                }
                if raw.is_empty() {
                    return Err(self.bad("empty value"));
                }
                Ok(Json::Raw(raw))
            }
        }
    }
}

/// The fields of one flat JSON object line.
fn parse_object(line: &str) -> Result<Vec<(String, Json)>, BenchError> {
    let mut cursor = Cursor {
        chars: line.trim().chars().peekable(),
    };
    cursor.expect('{')?;
    let mut fields: Vec<(String, Json)> = Vec::new();
    if cursor.chars.peek() == Some(&'}') {
        return Ok(fields);
    }
    loop {
        let key = cursor.string()?;
        cursor.expect(':')?;
        let value = cursor.value()?;
        if fields.iter().any(|(known, _)| *known == key) {
            return Err(BenchError(format!("repeated JSON key {key}")));
        }
        fields.push((key, value));
        match cursor.chars.next() {
            Some(',') => {}
            Some('}') => break,
            _ => return Err(cursor.bad("object")),
        }
    }
    if cursor.chars.next().is_some() {
        return Err(cursor.bad("trailing text"));
    }
    Ok(fields)
}

/// Typed access to one parsed object.
struct Object(Vec<(String, Json)>);

impl Object {
    fn get(&self, key: &str) -> Result<&Json, BenchError> {
        self.0
            .iter()
            .find(|(known, _)| known == key)
            .map(|(_, value)| value)
            .ok_or_else(|| BenchError(format!("no field {key}")))
    }

    fn string(&self, key: &str) -> Result<&str, BenchError> {
        match self.get(key)? {
            Json::Str(text) => Ok(text),
            _ => Err(BenchError(format!("{key} is not a string"))),
        }
    }

    fn optional_string(&self, key: &str) -> Result<Option<&str>, BenchError> {
        match self.get(key)? {
            Json::Str(text) => Ok(Some(text)),
            Json::Raw(raw) if raw == "null" => Ok(None),
            _ => Err(BenchError(format!("{key} is not a string or null"))),
        }
    }

    fn number(&self, key: &str) -> Result<u64, BenchError> {
        match self.get(key)? {
            Json::Raw(raw) => raw
                .parse()
                .map_err(|_| BenchError(format!("{key} is not a number"))),
            _ => Err(BenchError(format!("{key} is not a number"))),
        }
    }

    fn list(&self, key: &str) -> Result<&[String], BenchError> {
        match self.get(key)? {
            Json::List(items) => Ok(items),
            _ => Err(BenchError(format!("{key} is not a list"))),
        }
    }
}

fn read(path: &Path) -> Result<String, BenchError> {
    std::fs::read_to_string(path)
        .map_err(|cause| BenchError(format!("{}: {cause}", path.display())))
}

/// One run as the analysis saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    /// Its index in the plan.
    pub index: usize,
    /// Its configuration.
    pub configuration: String,
    /// Its round.
    pub round: u32,
    /// Decision samples after the expansion to `N`.
    pub n: u64,
    /// Missing messages among them (M-11).
    pub missing: u64,
    /// Saturated samples (design 2.3).
    pub saturated: u64,
    /// p50, p99 and p99.9 of the decision samples, ns; `None` when
    /// infinite.
    pub quantiles: [Option<u32>; 3],
    /// Kernel pushbacks of the sender.
    pub backpressure: u64,
    /// R1 messages not acknowledged in time.
    pub ack_timeouts: u64,
    /// Why the run is functional only; empty for an eligible run.
    pub functional_reasons: Vec<String>,
    /// The error that ended the run, if it failed.
    pub error: Option<String>,
}

/// One point as the analysis decided it.
#[derive(Debug, Clone)]
pub struct PointSummary {
    /// The point.
    pub point: Point,
    /// Its runs, in plan order.
    pub runs: Vec<RunSummary>,
    /// The evaluation, when every run succeeded.
    pub result: Option<PointResult>,
    /// The outcome.
    pub outcome: Outcome,
}

/// The analysis of one `measure` directory.
#[derive(Debug, Clone)]
pub struct Analysis {
    /// The host the runs come from.
    pub host: String,
    /// The commit that measured.
    pub commit: String,
    /// The build profile.
    pub profile: String,
    /// The environment class.
    pub environment: Environment,
    /// Its qualification line.
    pub qualification: String,
    /// The plan's fixed options.
    pub options: PlanOptions,
    /// The cores the children were pinned to, or why they were not.
    pub cores: String,
    /// Every planned point, decided or not.
    pub points: Vec<PointSummary>,
    /// Points of the set the harness cannot run yet.
    pub skipped: Vec<(Point, String)>,
    /// The overall result (8.6).
    pub overall: Overall,
    /// The grade of `decision::grade`.
    pub grade: Grade,
    /// Further reasons no decision may rest on this result: functional
    /// reasons of the runs and preflight drift, each named once.
    pub blockers: Vec<String>,
    /// Preflight drift, naming the run and the field.
    pub drift: Vec<String>,
    /// The total runtime of the runs, ms.
    pub runtime_ms: u64,
}

impl Analysis {
    /// Whether a decision may rest on this result.
    #[must_use]
    pub fn decision_grade(&self) -> bool {
        self.grade == Grade::Decision && self.blockers.is_empty()
    }
}

fn parse_rule(text: &str) -> Result<MtuRule, BenchError> {
    match text {
        "CountsEnvelope" => Ok(MtuRule::CountsEnvelope),
        "ExcludesEnvelope" => Ok(MtuRule::ExcludesEnvelope),
        other => Err(BenchError(format!("unknown rule {other}"))),
    }
}

fn parse_class(text: &str) -> Result<Environment, BenchError> {
    match text {
        "E1" => Ok(Environment::E1),
        "E2" => Ok(Environment::E2),
        "E3" => Ok(Environment::E3),
        "E4" => Ok(Environment::E4),
        other => Err(BenchError(format!("unknown environment class {other}"))),
    }
}

/// The decision samples of one successful run, exactly `N` of them, with
/// the saturation count of both stages.
fn decision_samples(dir: &Path, per: u64, n: u64) -> Result<(Vec<u32>, u64), BenchError> {
    let file = |name: &str| {
        samples::read_file(&dir.join(name))
            .map_err(|cause| BenchError(format!("{}: {cause}", dir.join(name).display())))
    };
    let (send, receive) = (file("send.samples")?, file("receive.samples")?);
    let (combined, saturated) = samples::combine(&send.samples, &[&receive.samples])
        .map_err(|cause| BenchError(format!("{}: {cause}", dir.display())))?;
    let saturated = [send.header.saturated, receive.header.saturated, saturated]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
        .ok_or_else(|| BenchError("saturation count overflow".into()))?;
    Ok((plan::keep_n(&combined, per, n)?, saturated))
}

/// The runs of configuration `name` among one point's runs.
fn config<'a>(runs: &'a [(String, Vec<u32>, u64)], name: &'a str) -> Config<'a> {
    let mine = || {
        runs.iter()
            .filter(move |(configuration, _, _)| configuration == name)
    };
    Config {
        profile: name,
        runs: mine().map(|(_, kept, _)| kept.as_slice()).collect(),
        // A saturation count past u64 is still a saturation.
        saturated: mine()
            .try_fold(0_u64, |total, (_, _, saturated)| {
                total.checked_add(*saturated)
            })
            .unwrap_or(u64::MAX),
    }
}

/// Analyzes the `measure` directory `out`.
///
/// # Errors
///
/// Another manifest, a malformed or inconsistent file, or results that
/// are not the plan's.
pub fn analyze(out: &Path) -> Result<Analysis, BenchError> {
    let header = Object(parse_object(&read(&out.join("measure.json"))?)?);
    let (version, hash) = (
        header.string("manifest_version")?,
        header.string("manifest_sha256")?,
    );
    if version != VERSION || hash != MANIFEST_SHA256 {
        return Err(BenchError(format!(
            "measured under manifest {version} ({hash}); this analysis is for {VERSION} ({MANIFEST_SHA256})"
        )));
    }
    if header.string("faults")? != "off" {
        return Err(BenchError(
            "the runs were not measured with faults off".into(),
        ));
    }
    let options = PlanOptions {
        runs: u32::try_from(header.number("rounds")?).map_err(|_| BenchError("rounds".into()))?,
        messages: header.number("messages")?,
        warmup: header.number("warmup")?,
        e_max: u32::try_from(header.number("e_max")?).map_err(|_| BenchError("e_max".into()))?,
        rule: parse_rule(header.string("rule")?)?,
        configurations: header.list("configurations")?.to_vec(),
    };
    let plan: Plan = plan::expand(&primary(), &options)?;
    let (a, b) = match options.configurations.as_slice() {
        [first, a, b] if first == BASELINE => (a.clone(), b.clone()),
        _ => {
            return Err(BenchError(format!(
                "the analysis needs {BASELINE}, a and b; the plan has {:?}",
                options.configurations
            )));
        }
    };
    let environment = parse_class(header.string("class")?)?;
    let lines: Vec<Object> = read(&out.join("results.jsonl"))?
        .lines()
        .map(|line| parse_object(line).map(Object))
        .collect::<Result<_, _>>()?;
    if lines.len() != plan.runs.len() {
        return Err(BenchError(format!(
            "{} results for {} planned runs",
            lines.len(),
            plan.runs.len()
        )));
    }
    let start = read(&out.join("preflight-start.txt"))?;
    let mut previous = start.clone();
    let mut drift = Vec::new();
    let mut blockers: Vec<String> = Vec::new();
    let mut runtime_ms = 0_u64;
    let mut points: Vec<PointSummary> = Vec::new();
    let spec = BootstrapSpec::manifest(DECISION_METHOD, SEED);
    let mut point_runs: Vec<(String, Vec<u32>, u64)> = Vec::new();
    for (index, (planned, line)) in plan.runs.iter().zip(&lines).enumerate() {
        let expected = (
            u64::try_from(index).map_err(|_| BenchError("index".into()))?,
            planned.point.to_string(),
            planned.configuration.as_str(),
            u64::from(planned.round),
        );
        let found = (
            line.number("index")?,
            line.string("point")?.to_string(),
            line.string("configuration")?,
            line.number("round")?,
        );
        if expected != found {
            return Err(BenchError(format!(
                "result {index} is {found:?}, the plan has {expected:?}"
            )));
        }
        runtime_ms = runtime_ms
            .checked_add(line.number("duration_ms")?)
            .ok_or_else(|| BenchError("runtime overflow".into()))?;
        let dir = out.join(line.string("dir")?);
        let label = format!(
            "run {index} ({} {} round {})",
            planned.point, planned.configuration, planned.round
        );
        let snapshot = read(&dir.join("preflight.txt"))?;
        for (against, base) in [
            ("the first snapshot", &start),
            ("the previous run", &previous),
        ] {
            for field in preflight::drift(base, &snapshot)? {
                let entry = format!("{label} against {against}: {field}");
                if !drift.contains(&entry) {
                    drift.push(entry);
                }
            }
        }
        previous = snapshot;
        let error = line.optional_string("error")?.map(ToString::to_string);
        let mut summary = RunSummary {
            index,
            configuration: planned.configuration.clone(),
            round: planned.round,
            n: 0,
            missing: 0,
            saturated: 0,
            quantiles: [None; 3],
            backpressure: 0,
            ack_timeouts: 0,
            functional_reasons: Vec::new(),
            error: error.clone(),
        };
        if error.is_none() {
            summary.backpressure = line.number("backpressure")?;
            summary.ack_timeouts = line.number("ack_timeouts")?;
            summary.functional_reasons = line.list("functional_reasons")?.to_vec();
            for reason in &summary.functional_reasons {
                if !blockers.contains(reason) {
                    blockers.push(reason.clone());
                }
            }
            let (kept, saturated) =
                decision_samples(&dir, planned.messages_per_sample, options.messages)?;
            let finite = |value: Option<u32>| value.filter(|v| *v != MISSING);
            summary.n = u64::try_from(kept.len()).map_err(|_| BenchError("n".into()))?;
            summary.missing = samples::missing(&kept);
            summary.saturated = saturated;
            summary.quantiles = [
                finite(stats::quantile(&kept, 1, 2)),
                finite(stats::quantile(&kept, 99, 100)),
                finite(stats::p999(&kept)),
            ];
            point_runs.push((planned.configuration.clone(), kept, saturated));
        }
        let last = plan
            .runs
            .get(index.checked_add(1).unwrap_or(index))
            .is_none_or(|next| next.point != planned.point);
        match points.last_mut() {
            Some(current) if current.point == planned.point => current.runs.push(summary),
            _ => points.push(PointSummary {
                point: planned.point,
                runs: vec![summary],
                result: None,
                outcome: Outcome::NotDemonstrated(Cause::NotMeasured),
            }),
        }
        if last {
            let current = points
                .last_mut()
                .ok_or_else(|| BenchError("point".into()))?;
            let failed: Vec<String> = current
                .runs
                .iter()
                .filter_map(|run| {
                    run.error
                        .as_ref()
                        .map(|e| format!("run {}: {e}", run.index))
                })
                .collect();
            if failed.is_empty() {
                let result = decision::evaluate_point(&PointInput {
                    point: planned.point,
                    environment,
                    a: config(&point_runs, &a),
                    b: config(&point_runs, &b),
                    trusted: config(&point_runs, BASELINE),
                    attempt: Attempt::First,
                    spec,
                })
                .map_err(|cause| BenchError(format!("{}: {cause}", planned.point)))?;
                current.outcome = result.outcome.clone();
                current.result = Some(result);
            } else {
                current.outcome = Outcome::NotDemonstrated(Cause::Other(format!(
                    "{} failed runs: {}",
                    failed.len(),
                    failed.join("; ")
                )));
            }
            point_runs.clear();
        }
    }
    blockers.extend(
        drift
            .iter()
            .map(|entry| format!("preflight drift: {entry}")),
    );
    let outcomes: Vec<(Point, Outcome)> = points
        .iter()
        .map(|point| (point.point, point.outcome.clone()))
        .collect();
    let overall = decision::overall(&outcomes, DecisionSet::default());
    let results: Vec<PointResult> = points.iter().filter_map(|p| p.result.clone()).collect();
    let grade = decision::grade(&GradeInputs {
        e_max: EMax::Provisional(options.e_max),
        ineligible: &[],
        min_warmup: options.warmup,
        results: &results,
        overall: &overall,
    });
    Ok(Analysis {
        host: header.string("host")?.to_string(),
        commit: header.string("commit")?.to_string(),
        profile: header.string("profile")?.to_string(),
        environment,
        qualification: header.string("environment")?.to_string(),
        cores: match header.get("cores")? {
            Json::List(cores) => format!("rx core {}", cores.join(", tx core ")),
            _ => format!(
                "unpinned: {}",
                header.string("unpinned").unwrap_or("unknown")
            ),
        },
        options,
        points,
        skipped: plan.skipped,
        overall,
        grade,
        blockers,
        drift,
        runtime_ms,
    })
}

fn ns(value: Option<u32>) -> String {
    value.map_or_else(|| "∞".to_string(), |v| v.to_string())
}

fn outcome_text(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Win(Side::A) => "a wins".to_string(),
        Outcome::Win(Side::B) => "b wins".to_string(),
        Outcome::Tie => "tie".to_string(),
        Outcome::NotDemonstrated(cause) => format!("Not demonstrated: {cause}"),
    }
}

/// `report.md`.
#[must_use]
pub fn report(analysis: &Analysis) -> String {
    let options = &analysis.options;
    let mut out = String::new();
    let _ = writeln!(out, "# Wire measurement report\n");
    let headline = if analysis.decision_grade() {
        "decision grade".to_string()
    } else {
        "not decision grade".to_string()
    };
    let _ = writeln!(out, "**Grade:** {headline}.\n");
    let _ = writeln!(
        out,
        "- Manifest {VERSION}, SHA-256 `{MANIFEST_SHA256}` (note \
         `karyos/threat-model-manifest-v2-hash`)."
    );
    let _ = writeln!(
        out,
        "- Host `{}`, commit `{}`, build `{}`, environment {} ({}).",
        analysis.host,
        analysis.commit,
        analysis.profile,
        analysis.environment,
        analysis.qualification
    );
    let _ = writeln!(out, "- Cores: {}. Faults: off.", analysis.cores);
    let _ = writeln!(
        out,
        "- E_max {}, rule {:?}; N {} after a warmup of {}; {} rounds of {}.",
        EMax::Provisional(options.e_max),
        options.rule,
        options.messages,
        options.warmup,
        options.runs,
        options.configurations.join(", ")
    );
    if !options.sufficient() {
        let _ = writeln!(out, "- Label: **{INSUFFICIENT}**.");
    }
    let _ = writeln!(
        out,
        "- Method: {DECISION_METHOD} (manifest 2.0 §8.3): a 95% Welch t interval on \
         per-run p99.9 values, Welch-Satterthwaite degrees of freedom rounded \
         down; {}.",
        seed_text()
    );
    let _ = writeln!(
        out,
        "- Measured runtime: {} s.\n",
        analysis.runtime_ms / 1000
    );
    let _ = writeln!(out, "## Points\n");
    for point in &analysis.points {
        let _ = writeln!(
            out,
            "### {}: {}\n",
            point.point,
            outcome_text(&point.outcome)
        );
        if let Some(result) = &point.result {
            for (name, per_run, cv) in &result.spread {
                let per_run: Vec<String> = per_run
                    .iter()
                    .map(|v| ns(Some(*v).filter(|v| *v != MISSING)))
                    .collect();
                let _ = writeln!(
                    out,
                    "- {name}: run p99.9 [{}] ns, CV {}",
                    per_run.join(", "),
                    cv.map_or_else(|| "n/a".to_string(), |cv| format!("{:.1}%", cv * 100.0))
                );
            }
            if let Some(bootstrap) = &result.bootstrap {
                let interval = |estimate: &stats::Estimate| match estimate.interval.ends {
                    Some((low, high)) => format!("{} [{low}, {high}]", estimate.point),
                    None => format!("{} (no interval)", estimate.point),
                };
                let _ = writeln!(out, "- added a: {} ns", interval(&bootstrap.added_a));
                let _ = writeln!(out, "- added b: {} ns", interval(&bootstrap.added_b));
                let _ = writeln!(
                    out,
                    "- difference a - b: {} ns",
                    interval(&bootstrap.difference)
                );
            }
        }
        let _ = writeln!(
            out,
            "\n| run | configuration | round | n | missing | saturated | p50 | p99 | p99.9 | backpressure | ack timeouts | error |"
        );
        let _ = writeln!(
            out,
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
        );
        for run in &point.runs {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                run.index,
                run.configuration,
                run.round,
                run.n,
                run.missing,
                run.saturated,
                ns(run.quantiles[0]),
                ns(run.quantiles[1]),
                ns(run.quantiles[2]),
                run.backpressure,
                run.ack_timeouts,
                run.error.as_deref().unwrap_or("").replace('|', "\\|")
            );
        }
        let _ = writeln!(out);
    }
    for (point, reason) in &analysis.skipped {
        let _ = writeln!(out, "- {point}: skipped, {reason}");
    }
    let overall = &analysis.overall;
    let verdict = match overall.verdict {
        Verdict::Wins(Side::A) => "a wins",
        Verdict::Wins(Side::B) => "b wins",
        Verdict::Tie => "tie",
    };
    let _ = writeln!(out, "\n## Overall (8.6)\n");
    let _ = writeln!(
        out,
        "{verdict}, {}: {} won by a, {} by b, {} ties.",
        overall.label(),
        overall.wins_a.len(),
        overall.wins_b.len(),
        overall.ties.len()
    );
    for (point, cause) in &overall.missing {
        let _ = writeln!(out, "- {point}: {cause}");
    }
    let _ = writeln!(out, "\n## Grade\n");
    match &analysis.grade {
        Grade::Decision => {
            let _ = writeln!(out, "- `decision::grade`: decision.");
        }
        Grade::NotDecisionGrade(reasons) => {
            for reason in reasons {
                let _ = writeln!(out, "- {reason}");
            }
        }
    }
    for blocker in &analysis.blockers {
        let _ = writeln!(out, "- {blocker}");
    }
    let _ = writeln!(out, "\n## Gates (manifest 7)\n");
    for (gate, status) in decision::GateTable::default().rows() {
        let _ = writeln!(out, "- {}: {status:?}", gate.name());
    }
    let _ = writeln!(out, "\n{}", decision::AARCH64_ROW);
    out
}

fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
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

fn json_list(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|item| json_string(item))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// `analysis.json`: one object, machine readable.
#[must_use]
pub fn json(analysis: &Analysis) -> String {
    let points: Vec<String> = analysis
        .points
        .iter()
        .map(|point| {
            let estimates = point
                .result
                .as_ref()
                .and_then(|result| result.bootstrap.as_ref())
                .map_or_else(
                    || "null".to_string(),
                    |bootstrap| {
                        let estimate = |e: &stats::Estimate| {
                            format!(
                                "{{\"point\":{},\"interval\":{}}}",
                                json_string(&e.point.to_string()),
                                e.interval.ends.map_or_else(
                                    || "null".to_string(),
                                    |(low, high)| json_list(&[low.to_string(), high.to_string()])
                                )
                            )
                        };
                        format!(
                            "{{\"added_a\":{},\"added_b\":{},\"difference\":{}}}",
                            estimate(&bootstrap.added_a),
                            estimate(&bootstrap.added_b),
                            estimate(&bootstrap.difference)
                        )
                    },
                );
            format!(
                "{{\"point\":{},\"outcome\":{},\"runs\":{},\"estimates\":{estimates}}}",
                json_string(&point.point.to_string()),
                json_string(&outcome_text(&point.outcome)),
                point.runs.len()
            )
        })
        .collect();
    let grade = match &analysis.grade {
        Grade::Decision => Vec::new(),
        Grade::NotDecisionGrade(reasons) => reasons.iter().map(ToString::to_string).collect(),
    };
    let fields = [
        format!("\"manifest_version\":{}", json_string(VERSION)),
        format!("\"manifest_sha256\":{}", json_string(MANIFEST_SHA256)),
        format!("\"host\":{}", json_string(&analysis.host)),
        format!("\"commit\":{}", json_string(&analysis.commit)),
        format!(
            "\"class\":{}",
            json_string(&analysis.environment.to_string())
        ),
        format!(
            "\"method\":{{\"name\":{},\"level\":0.95,\"df\":\"Welch-Satterthwaite, rounded down\",\"seed\":{},\"seed_note\":{}}}",
            json_string(&DECISION_METHOD.to_string()),
            recorded_seed().map_or_else(|| "null".to_string(), |seed| seed.to_string()),
            json_string(&seed_text())
        ),
        format!("\"messages\":{}", analysis.options.messages),
        format!("\"rounds\":{}", analysis.options.runs),
        format!("\"decision_grade\":{}", analysis.decision_grade()),
        format!("\"grade_reasons\":{}", json_list(&grade)),
        format!("\"blockers\":{}", json_list(&analysis.blockers)),
        format!("\"overall\":{}", json_string(analysis.overall.label())),
        format!("\"points\":[{}]", points.join(",")),
    ];
    format!("{{{}}}\n", fields.join(","))
}

/// Analyzes `out` and writes `report.md` and `analysis.json` into it.
///
/// # Errors
///
/// The errors of [`analyze`], or a file that cannot be written.
pub fn write(out: &Path) -> Result<Analysis, BenchError> {
    let analysis = analyze(out)?;
    for (name, text) in [
        ("report.md", report(&analysis)),
        ("analysis.json", json(&analysis)),
    ] {
        std::fs::write(out.join(name), text)
            .map_err(|cause| BenchError(format!("{name}: {cause}")))?;
    }
    Ok(analysis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_json_reader_reads_what_measure_writes() {
        let fields =
            parse_object(r#"{"a":"x\"y\\z\n","b":12,"c":null,"d":["p","q\"r"],"e":[],"f":true}"#)
                .unwrap();
        let object = Object(fields);
        assert_eq!(object.string("a").unwrap(), "x\"y\\z\n");
        assert_eq!(object.number("b").unwrap(), 12);
        assert_eq!(object.optional_string("c").unwrap(), None);
        assert_eq!(object.list("d").unwrap(), ["p", "q\"r"]);
        assert!(object.list("e").unwrap().is_empty());
        assert!(object.number("a").is_err());
        assert!(parse_object(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse_object(r#"{"a":1} x"#).is_err());
        assert!(parse_object(r#"{"a":"open}"#).is_err());
    }

    use std::time::Duration;

    use crate::manifest::ILLUSTRATIVE_E_MAX;
    use crate::measure::result_line;
    use crate::samples::{Header, RunSamples, Stage};
    use crate::wire::stage::StageSamples;

    /// A measured directory of the smoke plan with `N` = 10, class
    /// `class`, every run passed through `edit` before it is written.
    fn fixture(
        name: &str,
        class: &str,
        hash: &str,
        edit: impl Fn(usize, &mut Result<StageSamples, BenchError>, &mut String),
    ) -> std::path::PathBuf {
        let out =
            std::env::temp_dir().join(format!("karyos-analyze-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let mut options = PlanOptions::smoke(ILLUSTRATIVE_E_MAX, MtuRule::CountsEnvelope);
        options.messages = 10;
        options.warmup = 0;
        let plan = plan::expand(&primary(), &options).unwrap();
        let configurations: Vec<String> = options
            .configurations
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect();
        std::fs::create_dir_all(out.join("runs")).unwrap();
        std::fs::write(
            out.join("measure.json"),
            format!(
                "{{\"manifest_version\":\"{VERSION}\",\"manifest_sha256\":\"{hash}\",\
                 \"faults\":\"off\",\"host\":\"h\",\"profile\":\"release\",\
                 \"commit\":\"c\",\"class\":\"{class}\",\"environment\":\"{class}\",\
                 \"messages\":10,\"warmup\":0,\"rounds\":5,\"e_max\":64,\
                 \"rule\":\"CountsEnvelope\",\"configurations\":[{}],\
                 \"cores\":null,\"unpinned\":\"none\"}}\n",
                configurations.join(",")
            ),
        )
        .unwrap();
        std::fs::write(out.join("preflight-start.txt"), "clocksource tsc\n").unwrap();
        let mut results = String::new();
        for (index, planned) in plan.runs.iter().enumerate() {
            let dir = format!("runs/{index:04}");
            std::fs::create_dir_all(out.join(&dir)).unwrap();
            let count = usize::try_from(planned.run.messages).unwrap();
            // Every run alike, but for a spread the CV gate accepts.
            let base = 1_000 + u32::try_from(index % 5).unwrap() * 10;
            let data: Vec<u32> = (0..count)
                .map(|i| base + u32::try_from(i).unwrap())
                .collect();
            let mut outcome = Ok(StageSamples {
                send: data.clone(),
                receive: data,
                receive_callback: vec![0; count],
                batches: vec![1; count],
                backend_drops: 0,
                backpressure: 0,
                ack_timeouts: 0,
                messages_per_sample: usize::try_from(planned.messages_per_sample).unwrap(),
                functional_only: false,
                functional_reasons: Vec::new(),
                receiver: "127.0.0.1:1".parse().unwrap(),
            });
            let mut preflight = "clocksource tsc\n".to_string();
            edit(index, &mut outcome, &mut preflight);
            std::fs::write(out.join(&dir).join("preflight.txt"), &preflight).unwrap();
            if let Ok(samples) = &outcome {
                for (file, stage, values) in [
                    ("send.samples", Stage::Send, &samples.send),
                    (
                        "receive.samples",
                        Stage::Receive { receiver: 0 },
                        &samples.receive,
                    ),
                ] {
                    let header = Header {
                        point: planned.point,
                        profile: planned.configuration.clone(),
                        stage,
                        run: planned.round,
                        seed: 0,
                        clock_resolution_ns: 1,
                        warmup: 0,
                        saturated: 0,
                    };
                    samples::write_file(
                        &out.join(&dir).join(file),
                        &RunSamples {
                            header,
                            samples: values.clone(),
                        },
                    )
                    .unwrap();
                }
            }
            results.push_str(&result_line(
                index,
                planned,
                &dir,
                None,
                Duration::from_millis(1),
                &outcome,
            ));
            results.push('\n');
        }
        std::fs::write(out.join("results.jsonl"), results).unwrap();
        out
    }

    fn none(_: usize, _: &mut Result<StageSamples, BenchError>, _: &mut String) {}

    #[test]
    fn a_measured_directory_is_decided_point_by_point() {
        let out = fixture("ok", "E1", MANIFEST_SHA256, none);
        let analysis = write(&out).unwrap();
        assert_eq!(analysis.points.len(), 8);
        // W5 expands its one sequence of 21 messages to exactly N = 10.
        let w5 = analysis
            .points
            .iter()
            .find(|p| p.point.shape == crate::manifest::Shape::W5)
            .unwrap();
        assert!(w5.runs.iter().all(|run| run.n == 10));
        // E1 decides, so every point has its interval; the grade still
        // refuses the provisional E_max and the small N.
        assert!(
            analysis
                .points
                .iter()
                .all(|p| p.result.as_ref().is_some_and(|r| r.bootstrap.is_some()))
        );
        assert!(!analysis.decision_grade());
        let report = read(&out.join("report.md")).unwrap();
        assert!(report.contains(MANIFEST_SHA256));
        assert!(report.contains(INSUFFICIENT));
        let json = read(&out.join("analysis.json")).unwrap();
        assert!(json.trim().starts_with('{') && json.trim().ends_with('}'));
        assert!(json.contains("\"decision_grade\":false"));
        assert!(json.contains("\"seed\":null"));
        assert!(report.contains("seed: none (RunWelchT is deterministic)"));
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn another_manifest_is_refused() {
        let out = fixture("hash", "E4", &"0".repeat(64), none);
        let error = analyze(&out).err().map(|e| e.0).unwrap_or_default();
        assert!(error.contains("measured under manifest"), "{error}");
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn a_failed_run_leaves_its_point_not_demonstrated() {
        let out = fixture("failed", "E1", MANIFEST_SHA256, |index, outcome, _| {
            if index == 4 {
                *outcome = Err(BenchError("orphan sequence 9 (M-11)".into()));
            }
        });
        let analysis = analyze(&out).unwrap();
        let first = analysis.points.first().unwrap();
        assert!(
            matches!(&first.outcome, Outcome::NotDemonstrated(Cause::Other(cause)) if cause.contains("run 4: orphan")),
            "{:?}",
            first.outcome
        );
        assert!(analysis.points.get(1).is_some_and(|p| p.result.is_some()));
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn preflight_drift_names_the_run_and_the_field() {
        let out = fixture("drift", "E1", MANIFEST_SHA256, |index, _, preflight| {
            if index == 7 {
                *preflight = "clocksource hpet\n".to_string();
            }
        });
        let analysis = analyze(&out).unwrap();
        assert!(
            analysis
                .drift
                .iter()
                .any(|d| d.starts_with("run 7 ") && d.contains("clocksource: tsc -> hpet")),
            "{:?}",
            analysis.drift
        );
        // Run 8 returns to tsc: it drifted from the previous run.
        assert!(
            analysis
                .drift
                .iter()
                .any(|d| d.starts_with("run 8 ") && d.contains("previous"))
        );
        assert!(
            analysis
                .blockers
                .iter()
                .any(|b| b.starts_with("preflight drift"))
        );
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn results_that_are_not_the_plan_are_refused() {
        let out = fixture("swap", "E1", MANIFEST_SHA256, none);
        let results = read(&out.join("results.jsonl")).unwrap();
        let swapped = results.replacen(
            "\"configuration\":\"trusted\"",
            "\"configuration\":\"trusted-b\"",
            1,
        );
        std::fs::write(out.join("results.jsonl"), swapped).unwrap();
        let error = analyze(&out).err().map(|e| e.0).unwrap_or_default();
        assert!(error.contains("the plan has"), "{error}");
        let _ = std::fs::remove_dir_all(&out);
    }
}
