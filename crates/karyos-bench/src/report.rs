// SPDX-License-Identifier: Apache-2.0

//! The text report and the stored history (`quantstratum-docs: karyos/design/simulator-and-bench.md`).
//!
//! The history is one JSON object per line, written with `std` only. Every
//! value is a number or a string of [`crate::env::clean`] characters, so a
//! field can be read back by name without a JSON library.

use karyos_trace::histogram::{Histogram, Quantile};

use crate::env::Labels;
use crate::workloads::{Measurement, Workload};

/// The reported quantiles, as `(name, numerator, denominator)`.
pub const QUANTILES: [(&str, u64, u64); 5] = [
    ("p50", 1, 2),
    ("p90", 9, 10),
    ("p99", 99, 100),
    ("p999", 999, 1000),
    ("max", 1, 1),
];

/// A quantile's upper bound in nanoseconds, where known.
fn upper(histogram: &Histogram, numerator: u64, denominator: u64) -> Option<i64> {
    match histogram.quantile(numerator, denominator).ok()? {
        Quantile::Interval { high, .. } => high,
        Quantile::Empty | Quantile::Incomplete => None,
    }
}

fn interval(histogram: &Histogram, numerator: u64, denominator: u64) -> String {
    match histogram.quantile(numerator, denominator) {
        Ok(Quantile::Interval { low, high }) => format!(
            "[{}, {}] ns",
            low.map_or("-inf".into(), |v| v.to_string()),
            high.map_or("+inf".into(), |v| v.to_string())
        ),
        Ok(Quantile::Empty) => "empty".into(),
        Ok(Quantile::Incomplete) | Err(_) => "incomplete".into(),
    }
}

/// The comparison key: workload, canonical configuration, host and
/// profile. Records are compared only under the same key.
#[must_use]
pub fn key(measurement: &Measurement, labels: &Labels) -> String {
    format!(
        "{}|host={}|cpu={}|profile={}",
        measurement.config, labels.host, labels.cpu, labels.profile
    )
}

/// The text report of one measurement.
#[must_use]
pub fn text(measurement: &Measurement, labels: &Labels) -> String {
    let mut out = format!(
        "{}\n  host {} ({} {}, {}, {} cores), {} build, commit {}, environment: {}\n",
        measurement.config,
        labels.host,
        labels.os,
        labels.arch,
        labels.cpu,
        labels.cores,
        labels.profile,
        labels.commit,
        labels.qualification
    );
    if let Some(histogram) = &measurement.latency {
        let what = match measurement.config.workload {
            Workload::PingPong => "round trip",
            Workload::OpenLoop => "scheduled latency (due time to delivery)",
            _ => "latency",
        };
        out.push_str(&format!(
            "  {what} (interval width {} ns):",
            measurement.resolution
        ));
        for (name, numerator, denominator) in QUANTILES {
            out.push_str(&format!(
                " {name} {}",
                interval(histogram, numerator, denominator)
            ));
        }
        out.push('\n');
        if measurement.config.workload == Workload::PingPong
            && let Some(median) = upper(histogram, 1, 2)
        {
            out.push_str(&format!(
                "  one-way estimate: half the median round trip, about {} ns, \
                 only under the assumption of symmetric paths\n",
                median / 2
            ));
        }
    }
    out.push_str(&format!("  rate {:.0} messages/s\n", measurement.rate));
    out
}

/// The history line of one measurement.
#[must_use]
pub fn history_line(measurement: &Measurement, labels: &Labels) -> String {
    let config = measurement.config;
    let mut fields = vec![
        format!("\"key\":\"{}\"", key(measurement, labels)),
        format!("\"workload\":\"{}\"", config.workload.name()),
        format!("\"message\":{}", config.message),
        format!("\"publishers\":{}", config.publishers),
        format!("\"iterations\":{}", config.iterations),
        format!("\"warmup\":{}", config.warmup),
        format!("\"term\":{}", config.term_length),
        format!(
            "\"target_rate\":{}",
            config
                .target_rate
                .map_or_else(|| "null".into(), |rate| rate.to_string())
        ),
        format!("\"host\":\"{}\"", labels.host),
        format!("\"cpu\":\"{}\"", labels.cpu),
        format!("\"os\":\"{}\"", labels.os),
        format!("\"arch\":\"{}\"", labels.arch),
        format!("\"profile\":\"{}\"", labels.profile),
        format!("\"commit\":\"{}\"", labels.commit),
        format!("\"environment\":\"{}\"", labels.qualification),
        format!("\"rate\":{:.0}", measurement.rate),
    ];
    if let Some(histogram) = &measurement.latency {
        for (name, numerator, denominator) in QUANTILES {
            if let Some(value) = upper(histogram, numerator, denominator) {
                fields.push(format!("\"{name}_ns\":{value}"));
            }
        }
    }
    format!("{{{}}}", fields.join(","))
}

/// The raw value of field `name` in a history line.
#[must_use]
pub fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let marker = format!("\"{name}\":");
    let start = line.find(&marker)? + marker.len();
    let rest = line.get(start..)?;
    let value = match rest.strip_prefix('"') {
        Some(quoted) => quoted.get(..quoted.find('"')?)?,
        None => rest.get(..rest.find([',', '}'])?)?,
    };
    Some(value)
}

/// The comparison of `line` against the last earlier line with the same
/// key in `history`, or `None` when there is none. Reports only.
#[must_use]
pub fn compare(history: &str, line: &str) -> Option<String> {
    let key = field(line, "key")?;
    let previous = history
        .lines()
        .rev()
        .find(|earlier| field(earlier, "key") == Some(key))?;
    let mut out = format!(
        "  against commit {}:",
        field(previous, "commit").unwrap_or("unknown")
    );
    for name in QUANTILES
        .iter()
        .map(|(name, ..)| format!("{name}_ns"))
        .chain(["rate".to_string()])
    {
        let (Some(before), Some(after)) = (
            field(previous, &name).and_then(|v| v.parse::<f64>().ok()),
            field(line, &name).and_then(|v| v.parse::<f64>().ok()),
        ) else {
            continue;
        };
        if before > 0.0 {
            out.push_str(&format!(
                " {name} {:+.1}%",
                (after - before) / before * 100.0
            ));
        }
    }
    Some(out)
}
