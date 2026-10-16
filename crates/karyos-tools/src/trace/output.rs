// SPDX-License-Identifier: Apache-2.0

//! The plain text report of `karyos-trace` (`quantstratum-docs:
//! karyos/design/trace-tool.md`, "The command"): one section per
//! publication with its message count, the latency from `Publish` to each
//! `SubscriberPoll` and the trace counts by answer, then one line with the
//! mirror loss and the journals excluded as malformed.
//!
//! A latency is an interval that holds every value the observations and
//! the calibration allow, so each quantile prints as `[low, high]` ns (one
//! number when both ends meet, `-inf` or `+inf` for an end beyond the
//! histogram's range). Pairs whose clocks cannot be compared count as
//! unavailable.

use std::fmt::Write;

use karyos_trace::{Histogram, HistogramError, PublicationId, Quantile, TraceReport, Unavailable};

use super::mirror::MirrorTool;

/// The quantiles printed, as `(label, numerator, denominator)`.
const QUANTILES: [(&str, u64, u64); 5] = [
    ("min", 0, 1),
    ("p50", 1, 2),
    ("p99", 99, 100),
    ("p99.9", 999, 1000),
    ("max", 1, 1),
];

/// Every reason a latency is unavailable, with its label.
const REASONS: [(Unavailable, &str); 4] = [
    (Unavailable::NoCalibration, "no calibration"),
    (Unavailable::NotValid, "outside the calibration"),
    (Unavailable::Ambiguous, "ambiguous calibration"),
    (Unavailable::Overflow, "overflow"),
];

/// One end of a quantile.
fn end(value: Option<i64>, unbounded: &str) -> String {
    value.map_or_else(|| unbounded.to_owned(), |value| value.to_string())
}

/// A quantile as text.
fn quantile(quantile: Quantile) -> String {
    match quantile {
        Quantile::Interval { low, high } if low.is_some() && low == high => end(low, ""),
        Quantile::Interval { low, high } => {
            format!("[{}, {}]", end(low, "-inf"), end(high, "+inf"))
        }
        Quantile::Empty => "none".to_owned(),
        Quantile::Incomplete => "incomplete".to_owned(),
    }
}

/// The latency line of one publication.
fn latency(histogram: Option<&Histogram>) -> Result<String, HistogramError> {
    let Some(histogram) = histogram else {
        return Ok("unavailable (no Publish and SubscriberPoll pair)".to_owned());
    };
    let unavailable: Vec<String> = REASONS
        .iter()
        .filter_map(|(reason, label)| {
            let count = histogram.unavailable(*reason);
            (count > 0).then(|| format!("{count} {label}"))
        })
        .collect();
    if histogram.available() == 0 {
        return Ok(format!("unavailable ({})", unavailable.join(", ")));
    }
    let mut line = format!("count {}", histogram.available());
    for (label, numerator, denominator) in QUANTILES {
        let _ = write!(
            line,
            ", {label} {}",
            quantile(histogram.quantile(numerator, denominator)?)
        );
    }
    line.push_str(" ns");
    if !unavailable.is_empty() {
        let _ = write!(line, "; unavailable {}", unavailable.join(", "));
    }
    Ok(line)
}

/// The report of `tool`'s journals as plain text: one section per
/// publication, then the mirror loss line.
///
/// # Errors
///
/// Returns the histogram's errors for an invalid configuration, which the
/// tool's configuration never is.
pub fn render(tool: &MirrorTool, report: &TraceReport) -> Result<String, HistogramError> {
    let latencies = report.latencies()?;
    let histogram = |publication: &PublicationId| {
        latencies
            .iter()
            .find(|(p, _)| p == publication)
            .map(|(_, histogram)| histogram)
    };
    let mut out = String::new();
    let summaries = report.summary();
    if summaries.is_empty() {
        out.push_str("no traced messages\n");
    }
    for summary in &summaries {
        let publication = summary.publication;
        let _ = writeln!(
            out,
            "publication {} incarnation {} (stream {}, session {})",
            publication.registration,
            publication.incarnation,
            publication.stream_id,
            publication.session_id
        );
        let _ = writeln!(out, "  messages: {}", summary.messages);
        let _ = writeln!(
            out,
            "  latency Publish to SubscriberPoll: {}",
            latency(histogram(&publication))?
        );
        let _ = writeln!(
            out,
            "  traces: complete {}, incomplete {}, provisional {}, out of scope {}",
            summary.complete, summary.incomplete, summary.provisional, summary.out_of_scope
        );
    }
    let malformed = tool.malformed();
    let malformed = if malformed.is_empty() {
        "none".to_owned()
    } else {
        malformed
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(
        out,
        "mirror loss: {} ring records overwritten, {} journal sequences; journals excluded as malformed: {malformed}",
        tool.overwritten(),
        tool.mirror_lost()
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use karyos_sys::trace_mirror::trace_mirror;
    use karyos_trace::Latency;

    use super::*;
    use crate::trace::mirror::HISTOGRAM;

    #[test]
    fn quantiles_print_as_intervals_or_points() {
        let interval = |low, high| Quantile::Interval { low, high };
        assert_eq!(quantile(interval(Some(5), Some(5))), "5");
        assert_eq!(quantile(interval(Some(-3), Some(9))), "[-3, 9]");
        assert_eq!(quantile(interval(None, Some(9))), "[-inf, 9]");
        assert_eq!(quantile(interval(Some(1), None)), "[1, +inf]");
        assert_eq!(quantile(Quantile::Empty), "none");
        assert_eq!(quantile(Quantile::Incomplete), "incomplete");
    }

    #[test]
    fn the_latency_line_counts_available_and_unavailable_pairs() {
        assert_eq!(
            latency(None).unwrap(),
            "unavailable (no Publish and SubscriberPoll pair)"
        );
        let mut histogram = Histogram::new(HISTOGRAM.digits, HISTOGRAM.highest, 1).unwrap();
        histogram
            .record(Latency::Unavailable(Unavailable::NoCalibration))
            .unwrap();
        assert_eq!(
            latency(Some(&histogram)).unwrap(),
            "unavailable (1 no calibration)"
        );
        histogram
            .record(Latency::Available { min: 90, max: 110 })
            .unwrap();
        let line = latency(Some(&histogram)).unwrap();
        assert!(line.starts_with("count 1, min [90, 110], p50 "), "{line}");
        assert!(
            line.ends_with(" ns; unavailable 1 no calibration"),
            "{line}"
        );
    }

    #[test]
    fn an_empty_mirror_reports_no_messages_and_no_loss() {
        let mirror = trace_mirror(2, 1, 8).unwrap();
        let mut tool = MirrorTool::new(7);
        let _ = tool.scan(&mirror.reader());
        let report = tool.report().unwrap();
        assert_eq!(
            render(&tool, &report).unwrap(),
            "no traced messages\nmirror loss: 0 ring records overwritten, 0 journal sequences; journals excluded as malformed: none\n"
        );
    }
}
