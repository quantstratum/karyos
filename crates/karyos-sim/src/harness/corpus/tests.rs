// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;
use crate::harness::reference::Reference;
use crate::harness::workloads::W1;

/// A run of the reference fixture over two seeds: one line per case and
/// seed, each a JSON object that says it is harness validation, not C5
/// evidence, in its data.
#[test]
fn every_line_says_what_it_is_evidence_of() {
    let cases = W1::skeleton().cases();
    let cases = &cases[..2];
    let two = |_seed: u64| cases.to_vec();
    let mut out = Vec::new();
    let summary = run_corpus::<Reference>(
        "reference",
        Evidence::HarnessValidation,
        &[("W1", &two)],
        1..=2,
        &mut out,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(summary.runs, 4);
    assert_eq!(summary.passed + summary.liveness_gaps, 4, "{summary:?}");
    assert!(summary.failed.is_empty() && summary.errors == 0);
    for line in &lines {
        assert!(
            line.starts_with(
                "{\"evidence\":\"harness validation, not C5 evidence\",\"core\":\"reference\",\"workload\":\"W1\","
            ),
            "{line}"
        );
        assert!(line.ends_with('}'));
        assert!(line.contains("\"verdict\":\"pass\""), "{line}");
        assert!(line.contains("\"error\":null"), "{line}");
    }
    assert!(lines[0].contains(&format!("\"case\":{}", string(&cases[0].name))));
    assert!(lines[0].contains("\"seed\":1,"));
    assert!(lines[3].contains("\"seed\":2,"));
}

/// The same seed gives the same lines: the runner adds nothing that
/// varies between runs.
#[test]
fn a_corpus_run_is_reproducible() {
    let cases = W1::skeleton().cases();
    let one = |_seed: u64| cases[..1].to_vec();
    let lines = || {
        let mut out = Vec::new();
        run_corpus::<Reference>(
            "reference",
            Evidence::HarnessValidation,
            &[("W1", &one)],
            7..=8,
            &mut out,
        )
        .unwrap();
        out
    };
    assert_eq!(lines(), lines());
}

/// Strings are escaped as JSON requires.
#[test]
fn strings_are_escaped() {
    assert_eq!(string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\u000ad\"");
}
