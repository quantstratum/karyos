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
        (1..=2, 1),
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
    assert!(lines[0].contains("\"seed\":1,\"repetitions\":1,"));
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
            (7..=8, 1),
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

/// The determinism mode: every seed's run repeated; the reference fixture
/// replays exactly, so every repetition agrees.
#[test]
fn the_determinism_mode_repeats_each_seed() {
    let cases = W1::skeleton().cases();
    let one = |_seed: u64| cases[..1].to_vec();
    let mut out = Vec::new();
    let summary = run_corpus::<Reference>(
        "reference",
        Evidence::HarnessValidation,
        &[("W1", &one)],
        (3..=4, 3),
        &mut out,
    )
    .unwrap();
    assert_eq!(summary.runs, 2);
    assert!(summary.failed.is_empty(), "{summary:?}");
    let text = String::from_utf8(out).unwrap();
    assert!(text.lines().all(|line| line.contains("\"repetitions\":3,")));
}

/// A field of a line, as its raw JSON text up to the next field.
fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let key = format!("\"{name}\":");
    let (_, rest) = line.split_once(key.as_str()).unwrap();
    let end = match rest.strip_prefix(['[', '{']) {
        Some(_) => {
            // Up to the matching close.
            let (open, close) = if rest.starts_with('[') {
                ('[', ']')
            } else {
                ('{', '}')
            };
            let mut depth = 0;
            let mut quoted = false;
            let mut escaped = false;
            let mut end = 0;
            for (at, c) in rest.char_indices() {
                if quoted {
                    match c {
                        _ if escaped => escaped = false,
                        '\\' => escaped = true,
                        '"' => quoted = false,
                        _ => {}
                    }
                    continue;
                }
                match c {
                    '"' => quoted = true,
                    c if c == open => depth += 1,
                    c if c == close => {
                        depth -= 1;
                        if depth == 0 {
                            end = at + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            end
        }
        None => rest.find([',', '}']).unwrap(),
    };
    &rest[..end]
}

/// Each fault a run applies is in its line with its step and phase, and
/// the summary counts the runs that reached each kind in each phase,
/// once a run however often it applies the kind there: a crash at step
/// 1 falls before the first commit, one late in the run after the last.
#[test]
fn every_fault_is_covered_by_its_phase() {
    use crate::harness::workloads::Action;
    let mut case = W1::skeleton().cases()[0].clone();
    // Two crashes before the first commit count the run once there.
    case.schedule = vec![
        (1, Action::Crash(2)),
        (2, Action::Restart(2)),
        (3, Action::Crash(1)),
    ];
    let mut late = case.clone();
    late.name.push_str(" late");
    late.schedule = vec![(late.steps - 1, Action::Crash(2))];
    let cases = vec![case, late];
    let both = |_seed: u64| cases.clone();
    let mut out = Vec::new();
    let summary = run_corpus::<Reference>(
        "reference",
        Evidence::HarnessValidation,
        &[("W1", &both)],
        (1..=1, 1),
        &mut out,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        field(lines[0], "coverage"),
        "[{\"step\":1,\"fault\":\"Crash(2)\",\"phase\":\"before_first_commit\"},{\"step\":2,\"fault\":\"Restart(2)\",\"phase\":\"before_first_commit\"},{\"step\":3,\"fault\":\"Crash(1)\",\"phase\":\"before_first_commit\"}]"
    );
    assert!(
        field(lines[1], "coverage").contains("\"phase\":\"after_last_commit\""),
        "{}",
        lines[1]
    );
    let crash = summary.coverage[&("W1".to_owned(), "Crash".to_owned())];
    assert_eq!(crash, [1, 0, 1]);
    assert_eq!(
        summary.coverage[&("W1".to_owned(), "Restart".to_owned())],
        [1, 0, 0]
    );
}

/// A named seed carries its run's full trace; another seed does not.
#[test]
fn a_named_seed_carries_its_trace() {
    let cases = W1::skeleton().cases();
    let one = |_seed: u64| cases[..1].to_vec();
    for (seed, named) in [(10, true), (11, false)] {
        let mut out = Vec::new();
        let _ = run_corpus::<Reference>(
            "reference",
            Evidence::HarnessValidation,
            &[("W1", &one)],
            (seed..=seed, 1),
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        let trace = field(text.trim_end(), "trace");
        if named {
            let outcome = run::<Reference>(&cases[0], seed).unwrap();
            assert!(!outcome.trace.is_empty());
            assert_eq!(trace, super::trace(&outcome.trace));
        } else {
            assert_eq!(trace, "null");
        }
        assert_eq!(
            field(text.trim_end(), "minimised"),
            "null",
            "a pass is not minimised"
        );
    }
}

/// A failing run is shrunk to the faults it needs: of a crash, a restart
/// and two isolations, only what takes two of the three servers away
/// stays, each fault left needed, and the shrunk case still fails the
/// same check; its line carries it.
#[test]
fn a_failing_run_is_minimised_to_the_faults_it_needs() {
    use crate::harness::workloads::Action;
    let mut case = W1::skeleton().cases()[0].clone();
    case.name = "W1 stalled".to_owned();
    case.schedule = vec![
        (3, Action::Crash(2)),
        (4, Action::Restart(2)),
        (5, Action::Isolate(0)),
        (5, Action::Isolate(1)),
    ];
    let (kind, _) = failing::<Reference>(&case, 1).expect("the case fails");
    let shrunk = minimise::<Reference>(&case, 1, kind).unwrap();
    assert!(
        shrunk.case.schedule.len() < case.schedule.len(),
        "{:?}",
        shrunk.case.schedule
    );
    // Every fault left is needed: without any one of them, the run no
    // longer fails the same check.
    for at in 0..shrunk.case.schedule.len() {
        let mut fewer = shrunk.case.clone();
        let _ = fewer.schedule.remove(at);
        assert_ne!(
            failing::<Reference>(&fewer, 1).map(|(got, _)| got),
            Some(kind),
            "fault {at} of {:?} is not needed",
            shrunk.case.schedule
        );
    }
    assert!(
        shrunk.minimal,
        "the fixed point is reached within the budget"
    );
    assert!(shrunk.case.steps <= case.steps);
    assert_eq!(
        failing::<Reference>(&shrunk.case, 1).map(|(got, _)| got),
        Some(kind)
    );
    // The runner writes it in the failing line.
    let cases = vec![case];
    let one = |_seed: u64| cases.clone();
    let mut out = Vec::new();
    let summary = run_corpus::<Reference>(
        "reference",
        Evidence::HarnessValidation,
        &[("W1", &one)],
        (1..=1, 1),
        &mut out,
    )
    .unwrap();
    assert_eq!(summary.failed.len(), 1);
    let text = String::from_utf8(out).unwrap();
    let minimised = field(text.trim_end(), "minimised");
    assert!(
        minimised.starts_with(&format!(
            "{{\"minimal\":true,\"steps\":{},\"schedule\":[",
            shrunk.case.steps
        )),
        "{minimised}"
    );
    assert!(minimised.ends_with(&format!("\"trace\":{}}}", super::trace(&shrunk.trace))));
}

/// A budget that runs out before the fixed point leaves the case shrunk
/// as far as it got, still failing the same check, and marked not
/// minimal; the full budget on the same case reaches it.
#[test]
fn a_minimisation_cut_by_its_budget_is_marked_not_minimal() {
    use crate::harness::workloads::Action;
    let mut case = W1::skeleton().cases()[0].clone();
    case.name = "W1 stalled".to_owned();
    case.schedule = vec![
        (3, Action::Crash(2)),
        (4, Action::Restart(2)),
        (5, Action::Isolate(0)),
        (5, Action::Isolate(1)),
    ];
    let (kind, _) = failing::<Reference>(&case, 1).expect("the case fails");
    let cut = super::minimise_within::<Reference>(&case, 1, kind, 2).unwrap();
    assert!(!cut.minimal, "{:?}", cut.case.schedule);
    assert_eq!(
        failing::<Reference>(&cut.case, 1).map(|(got, _)| got),
        Some(kind)
    );
    let full = minimise::<Reference>(&case, 1, kind).unwrap();
    assert!(full.minimal);
    assert!(full.case.schedule.len() <= cut.case.schedule.len());
}

/// With a trace directory, a named seed's trace goes to its own file, one
/// JSON string per trace line, and its line names the file, the count and
/// the digest of its bytes; a seed not named writes no file.
#[test]
fn a_named_seed_writes_its_trace_to_a_file_its_line_names() {
    let cases = W1::skeleton().cases();
    let one = |_seed: u64| cases[..1].to_vec();
    let dir = std::env::temp_dir().join(format!("karyos-corpus-traces-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut out = Vec::new();
    let _ = run_corpus_with_traces::<Reference>(
        "reference",
        Evidence::HarnessValidation,
        &[("W1", &one)],
        (10..=11, 1),
        &mut out,
        &dir,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    let outcome = run::<Reference>(&cases[0], 10).unwrap();
    let relative = format!("W1/{}/10.trace", slug(&cases[0].name));
    let written = std::fs::read_to_string(dir.join(&relative)).unwrap();
    let expected: String = outcome
        .trace
        .iter()
        .map(|line| format!("{}\n", string(line)))
        .collect();
    assert_eq!(written, expected);
    let named = lines[0];
    assert!(
        named.contains(&format!(
            "\"trace\":{{\"file\":{},\"lines\":{},\"digest\":{}}}",
            string(&relative),
            outcome.trace.len(),
            fnv1a(written.as_bytes())
        )),
        "{named}"
    );
    assert_eq!(field(lines[1], "trace"), "null");
    assert!(
        !dir.join(format!("W1/{}/11.trace", slug(&cases[0].name)))
            .exists()
    );
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        slug("W2 n=3 clients=32 window=8"),
        "W2-n-3-clients-32-window-8"
    );
}
