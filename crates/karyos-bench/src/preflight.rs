// SPDX-License-Identifier: Apache-2.0

//! The preflight snapshot of a measured run (`quantstratum-docs:
//! karyos/design/measurement-harness.md` 4.2 condition 4 and 4.3): the
//! host fields that can drift between runs (governor and frequency
//! limits, cpuidle, boost, transparent huge pages, interrupt affinity,
//! `irqbalance` and the clock source), one `<key> <value>` line each. An
//! unreadable field is `unavailable (<reason>)`, never left out.
//!
//! `measure` writes one snapshot before the first run and one before
//! every run; the analysis reports every field that differs from the
//! previous snapshot or from the first, naming the run (coordinator,
//! ACS 15349). Any drift makes the result ineligible.

use std::fmt::Write as _;

use crate::inventory::{Inventory, Reading, Scope};
use crate::workloads::BenchError;

/// A reading as one line's value.
fn value(reading: &Reading) -> String {
    match reading {
        Ok(text) => text.split_whitespace().collect::<Vec<_>>().join(" "),
        Err(reason) => format!("unavailable ({reason})"),
    }
}

/// The snapshot of `inventory`.
#[must_use]
pub fn render(inventory: &Inventory) -> String {
    let mut out = String::new();
    let mut line = |key: String, reading: &Reading| {
        let _ = writeln!(out, "{key} {}", value(reading));
    };
    match &inventory.cpus {
        Err(reason) => line("cpus".into(), &Err(reason.clone())),
        Ok(cpus) => {
            for cpu in cpus {
                let index = cpu.index;
                line(format!("governor.cpu{index}"), &cpu.governor);
                line(format!("min_freq.cpu{index}"), &cpu.min_freq);
                line(format!("max_freq.cpu{index}"), &cpu.max_freq);
                match &cpu.idle {
                    Err(reason) => line(format!("cpuidle.cpu{index}"), &Err(reason.clone())),
                    Ok(states) => {
                        for state in states {
                            line(
                                format!("cpuidle.cpu{index}.{}.disable", state.state),
                                &state.disable,
                            );
                        }
                    }
                }
            }
        }
    }
    line("boost".into(), &inventory.boost);
    line("thp_enabled".into(), &inventory.thp_enabled);
    line("thp_defrag".into(), &inventory.thp_defrag);
    match &inventory.irq_affinity {
        Err(reason) => line("irq_affinity".into(), &Err(reason.clone())),
        Ok(interfaces) => {
            for interface in interfaces {
                for (irq, _, affinity) in &interface.irqs {
                    line(format!("irq.{}.{irq}", interface.interface), affinity);
                }
            }
        }
    }
    line("irqbalance".into(), &inventory.irqbalance);
    line("clocksource".into(), &inventory.clocksource);
    out
}

/// The heading of the preflight block of a host record.
pub const RECORD_HEADING: &str = "## Preflight fields (4.3)";

/// The preflight block of a host record: the snapshot of `inventory` in
/// a fenced block under [`RECORD_HEADING`], which every run's snapshot
/// is compared with (4.2 condition 4).
#[must_use]
pub fn record_block(inventory: &Inventory) -> String {
    format!(
        "\n{RECORD_HEADING}\n\nThe fields every measured run's preflight snapshot must match:\n\n```text\n{}```\n",
        render(inventory)
    )
}

/// The preflight snapshot inside a host record's block, if it has one.
#[must_use]
pub fn from_record(record: &str) -> Option<&str> {
    let after = record.split_once(RECORD_HEADING)?.1;
    let body = after.split_once("```text\n")?.1;
    Some(body.split_once("```")?.0)
}

/// This host's snapshot now.
#[must_use]
pub fn capture() -> String {
    render(&Inventory::detect(Scope::Full))
}

/// The `(key, value)` pairs of a snapshot.
///
/// # Errors
///
/// A line without a value or a repeated key.
pub fn parse(text: &str) -> Result<Vec<(&str, &str)>, BenchError> {
    let mut fields: Vec<(&str, &str)> = Vec::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once(' ')
            .ok_or_else(|| BenchError(format!("bad preflight line {line}")))?;
        if fields.iter().any(|(known, _)| *known == key) {
            return Err(BenchError(format!("repeated preflight key {key}")));
        }
        fields.push((key, value));
    }
    Ok(fields)
}

/// Every field of `after` that differs from `before`, appeared or
/// disappeared, as `<key>: <before> -> <after>`.
///
/// # Errors
///
/// Either snapshot does not parse.
pub fn drift(before: &str, after: &str) -> Result<Vec<String>, BenchError> {
    let (before, after) = (parse(before)?, parse(after)?);
    let find = |fields: &[(&str, &str)], key: &str| {
        fields
            .iter()
            .find(|(known, _)| *known == key)
            .map(|(_, value)| (*value).to_string())
    };
    let mut keys: Vec<&str> = before.iter().map(|(key, _)| *key).collect();
    for (key, _) in &after {
        if !keys.contains(key) {
            keys.push(key);
        }
    }
    let absent = || "absent".to_string();
    Ok(keys
        .into_iter()
        .filter_map(|key| {
            let (old, new) = (find(&before, key), find(&after, key));
            (old != new).then(|| {
                format!(
                    "{key}: {} -> {}",
                    old.unwrap_or_else(absent),
                    new.unwrap_or_else(absent)
                )
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_names_every_changed_field() {
        let before = "governor.cpu2 performance\nboost 0\nclocksource tsc\n";
        let after = "governor.cpu2 powersave\nboost 0\nclocksource tsc\nthp_enabled never\n";
        assert_eq!(
            drift(before, after).unwrap(),
            [
                "governor.cpu2: performance -> powersave",
                "thp_enabled: absent -> never"
            ]
        );
        assert!(drift(before, before).unwrap().is_empty());
        assert!(parse("boost 0\nboost 1\n").is_err());
        assert!(parse("boost\n").is_err());
    }

    #[test]
    fn a_host_record_carries_its_preflight_block() {
        let inventory = Inventory::detect(Scope::Classification);
        let block = record_block(&inventory);
        let record = format!("# host\n\nother text\n{block}");
        assert_eq!(from_record(&record), Some(render(&inventory).as_str()));
        assert_eq!(from_record("# host\n"), None);
    }

    #[test]
    fn a_snapshot_lists_unavailable_fields() {
        let text = capture();
        let fields = parse(&text).unwrap();
        assert!(fields.iter().any(|(key, _)| *key == "clocksource"));
        assert!(fields.iter().any(|(key, _)| *key == "boost"));
    }
}
