// SPDX-License-Identifier: Apache-2.0

//! The runner of the language-neutral conformance suite in
//! `conformance/` (interim format 1, `conformance/FORMAT.md`; SPEC.md
//! §10.2, §13; quantstratum-docs: karyos/design/ffi-gap-analysis.md, F6).
//! It runs every scenario through the exported symbols, as a binding's
//! runner does through its own API, and checks the coverage map. Miri
//! skips it: it reads the suite's files, which Miri's isolation forbids,
//! and its calls go through `support::abi`, which `tests/abi.rs` runs
//! under Miri.

// Test helpers outside `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use karyos_ffi as _;

mod support {
    #[allow(dead_code, reason = "each test binary calls a part of the ABI")]
    pub mod abi;
}

use support::abi;

/// The format version this runner reads.
const FORMAT: &str = "1";

/// A value of a scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Integer(i64),
    Text(String),
    Null,
    Variable(String),
}

/// A `call` and its `expect`.
#[derive(Debug, Clone)]
struct Step {
    line: usize,
    function: String,
    arguments: BTreeMap<String, Value>,
    status: Option<String>,
    results: BTreeMap<String, Value>,
}

/// A parsed scenario.
#[derive(Debug)]
struct Scenario {
    file: PathBuf,
    id: String,
    abi: (u32, u32),
    covers: String,
    steps: Vec<Step>,
}

/// What a call returned: its status, if it returns one, and its results.
#[derive(Debug, Default)]
struct Returned {
    status: Option<i32>,
    results: BTreeMap<String, Value>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// The `KARYOS_OK` and `KARYOS_E_*` codes of the header.
fn statuses() -> BTreeMap<String, i32> {
    let header = std::fs::read_to_string(root().join("include/karyos.h")).unwrap();
    header
        .lines()
        .filter_map(|line| line.trim().strip_prefix("#define "))
        .filter_map(|define| {
            let mut parts = define.split_whitespace();
            let name = parts.next()?;
            let value = parts.next()?;
            (name == "KARYOS_OK" || name.starts_with("KARYOS_E_"))
                .then(|| (name.to_owned(), value.parse().unwrap()))
        })
        .collect()
}

/// The tokens of a line: bare words and quoted strings, the comment cut.
fn tokens(line: &str, at: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c == '#' {
            break;
        }
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut token = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            if !quoted && (c.is_whitespace() || c == '#') {
                break;
            }
            chars.next();
            match c {
                '"' => {
                    quoted = !quoted;
                    token.push('"');
                }
                '\\' if quoted => match chars.next() {
                    Some(escaped @ ('"' | '\\')) => {
                        token.push('\\');
                        token.push(escaped);
                    }
                    other => panic!("{at}: escape \\{other:?} is not one of \\\" \\\\"),
                },
                other => token.push(other),
            }
        }
        assert!(!quoted, "{at}: unterminated string");
        tokens.push(token);
    }
    tokens
}

fn value(token: &str, at: &str) -> Value {
    if token == "null" {
        Value::Null
    } else if let Some(name) = token.strip_prefix('$') {
        assert!(!name.is_empty(), "{at}: empty variable name");
        Value::Variable(name.to_owned())
    } else if let Some(text) = token.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        Value::Text(text.replace("\\\"", "\"").replace("\\\\", "\\"))
    } else {
        Value::Integer(
            token
                .parse()
                .unwrap_or_else(|_| panic!("{at}: `{token}` is no value")),
        )
    }
}

fn pairs(tokens: &[String], at: &str) -> BTreeMap<String, Value> {
    let mut pairs = BTreeMap::new();
    for token in tokens {
        let (name, raw) = token
            .split_once('=')
            .unwrap_or_else(|| panic!("{at}: `{token}` is not name=value"));
        let previous = pairs.insert(name.to_owned(), value(raw, at));
        assert!(previous.is_none(), "{at}: `{name}` given twice");
    }
    pairs
}

/// Checks a header line: given once, before the first call.
fn header<T>(slot: &Option<T>, started: bool, keyword: &str, at: &str) {
    assert!(slot.is_none(), "{at}: `{keyword}` given twice");
    assert!(!started, "{at}: `{keyword}` after a call");
}

fn parse(file: &Path) -> Scenario {
    let text = std::fs::read_to_string(file).unwrap();
    let name = file.display().to_string();
    let mut format = None;
    let (mut id, mut abi, mut covers) = (None, None, None);
    let mut steps: Vec<Step> = Vec::new();
    let mut open: Option<(usize, String, BTreeMap<String, Value>)> = None;
    for (index, line) in text.lines().enumerate() {
        let at = format!("{name}:{}", index + 1);
        let tokens = tokens(line, &at);
        let Some((keyword, rest)) = tokens.split_first() else {
            continue;
        };
        if format.is_none() {
            assert_eq!(keyword, "format", "{at}: the first line must be `format`");
        }
        let single = || {
            assert_eq!(rest.len(), 1, "{at}: `{keyword}` takes one token");
            rest[0].clone()
        };
        let started = !steps.is_empty() || open.is_some();
        match keyword.as_str() {
            "format" => {
                header(&format, started, keyword, &at);
                let version = single();
                assert_eq!(version, FORMAT, "{at}: unknown format {version}");
                format = Some(version);
            }
            "id" => {
                header(&id, started, keyword, &at);
                id = Some(single());
            }
            "abi" => {
                header(&abi, started, keyword, &at);
                let version = single();
                let (major, minor) = version
                    .split_once('.')
                    .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)))
                    .unwrap_or_else(|| panic!("{at}: `{version}` is not MAJOR.MINOR"));
                abi = Some((major, minor));
            }
            "covers" => {
                header(&covers, started, keyword, &at);
                let Value::Text(row) = value(&single(), &at) else {
                    panic!("{at}: `covers` takes a quoted string");
                };
                covers = Some(row);
            }
            "call" => {
                assert!(open.is_none(), "{at}: a call before the last one's expect");
                let (function, arguments) = rest
                    .split_first()
                    .unwrap_or_else(|| panic!("{at}: `call` needs a function"));
                open = Some((index + 1, function.clone(), pairs(arguments, &at)));
            }
            "expect" => {
                let (line, function, arguments) = open
                    .take()
                    .unwrap_or_else(|| panic!("{at}: `expect` without a call"));
                let (status, results) = match rest.split_first() {
                    Some((first, results)) if first.starts_with("KARYOS_") => {
                        (Some(first.clone()), results)
                    }
                    _ => (None, rest),
                };
                steps.push(Step {
                    line,
                    function,
                    arguments,
                    status,
                    results: pairs(results, &at),
                });
            }
            other => panic!("{at}: unknown keyword `{other}`"),
        }
    }
    assert!(open.is_none(), "{name}: the last call has no expect");
    assert!(!steps.is_empty(), "{name}: no call");
    Scenario {
        file: file.to_path_buf(),
        id: id.unwrap_or_else(|| panic!("{name}: no id")),
        abi: abi.unwrap_or_else(|| panic!("{name}: no abi")),
        covers: covers.unwrap_or_else(|| panic!("{name}: no covers")),
        steps,
    }
}

/// The pointer arguments a scenario passes as `null`.
fn nulls(step: &Step, names: &[&str], at: &str) -> Vec<bool> {
    for (name, argument) in &step.arguments {
        assert!(
            names.contains(&name.as_str()),
            "{at}: unknown argument `{name}`"
        );
        assert_eq!(*argument, Value::Null, "{at}: `{name}` takes only null");
    }
    names
        .iter()
        .map(|name| step.arguments.contains_key(*name))
        .collect()
}

fn integer_argument(step: &Step, name: &str, at: &str) -> i64 {
    assert_eq!(step.arguments.len(), 1, "{at}: one argument, `{name}`");
    match step.arguments.get(name) {
        Some(Value::Integer(value)) => *value,
        other => panic!("{at}: `{name}` must be an integer, got {other:?}"),
    }
}

/// Calls the step's function through the C ABI.
fn call(step: &Step, at: &str) -> Returned {
    match step.function.as_str() {
        "karyos_abi_version" => {
            let null = nulls(step, &["major", "minor", "patch"], at);
            let (status, values) = abi::abi_version_with([null[0], null[1], null[2]]);
            let results = ["major", "minor", "patch"]
                .into_iter()
                .zip(values)
                .filter_map(|(name, value)| {
                    Some((name.to_owned(), Value::Integer(i64::from(value?))))
                })
                .collect();
            Returned {
                status: Some(status),
                results,
            }
        }
        "karyos_status_message" => {
            let status = i32::try_from(integer_argument(step, "status", at))
                .unwrap_or_else(|_| panic!("{at}: `status` is not an int32_t"));
            Returned {
                status: None,
                results: BTreeMap::from([(
                    "text".to_owned(),
                    Value::Text(abi::status_message(status)),
                )]),
            }
        }
        other => panic!("{at}: this runner does not know `{other}`"),
    }
}

/// Runs a scenario; `false` when it was skipped for its ABI version.
fn run(scenario: &Scenario, statuses: &BTreeMap<String, i32>, library: (u32, u32)) -> bool {
    let name = scenario.file.display();
    if scenario.abi.0 != library.0 || scenario.abi.1 > library.1 {
        return false;
    }
    let mut variables: BTreeMap<String, Value> = BTreeMap::new();
    for step in &scenario.steps {
        let at = format!("{name}:{}", step.line);
        for argument in step.arguments.values() {
            if let Value::Variable(variable) = argument {
                assert!(
                    variables.contains_key(variable),
                    "{at}: `${variable}` is unbound"
                );
            }
        }
        let returned = call(step, &at);
        match (&step.status, returned.status) {
            (Some(expected), Some(got)) => {
                let code = *statuses
                    .get(expected)
                    .unwrap_or_else(|| panic!("{at}: the header has no `{expected}`"));
                assert_eq!(
                    got, code,
                    "{at}: status {got}, expected {expected} ({code})"
                );
            }
            (None, None) => {}
            (Some(_), None) => panic!("{at}: `{}` returns no status", step.function),
            (None, Some(got)) => panic!("{at}: the status ({got}) is not checked"),
        }
        for (result, expected) in &step.results {
            let got = returned
                .results
                .get(result)
                .unwrap_or_else(|| panic!("{at}: `{result}` was not written"));
            match expected {
                Value::Variable(variable) => match variables.get(variable) {
                    Some(bound) => assert_eq!(got, bound, "{at}: `{result}` vs `${variable}`"),
                    None => {
                        variables.insert(variable.clone(), got.clone());
                    }
                },
                literal => assert_eq!(got, literal, "{at}: `{result}`"),
            }
        }
    }
    true
}

fn scenarios() -> Vec<Scenario> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(root().join("conformance/scenarios"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    for file in &files {
        assert_eq!(
            file.extension().and_then(|e| e.to_str()),
            Some("kcs"),
            "{}: scenarios end in .kcs",
            file.display()
        );
    }
    files.iter().map(|file| parse(file)).collect()
}

/// The coverage map: each row's scenario ids, or `None` while pending.
fn index() -> BTreeMap<String, Option<Vec<String>>> {
    let text = std::fs::read_to_string(root().join("conformance/index.txt")).unwrap();
    let mut rows = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (row, covered) = line
            .split_once(':')
            .unwrap_or_else(|| panic!("index.txt:{}: no `:`", number + 1));
        let covered = covered.trim();
        let ids = if covered.starts_with("pending ") {
            None
        } else {
            Some(covered.split_whitespace().map(str::to_owned).collect())
        };
        let previous = rows.insert(row.trim().to_owned(), ids);
        assert!(previous.is_none(), "index.txt:{}: row repeated", number + 1);
    }
    rows
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the suite's files, which Miri's isolation forbids"
)]
fn every_scenario_passes_at_the_library_abi_version() {
    let statuses = statuses();
    let (status, [major, minor, _]) = abi::abi_version_with([false; 3]);
    assert_eq!(status, statuses["KARYOS_OK"]);
    let library = (major.unwrap(), minor.unwrap());
    let scenarios = scenarios();
    assert!(!scenarios.is_empty());
    let ran = scenarios
        .iter()
        .filter(|scenario| run(scenario, &statuses, library))
        .count();
    // Every scenario targets this library's ABI today; a skip would hide
    // a scenario, so none may be skipped here.
    assert_eq!(ran, scenarios.len());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the suite's files, which Miri's isolation forbids"
)]
fn the_index_maps_every_scenario_and_every_id_exists() {
    let scenarios = scenarios();
    let mut ids = BTreeSet::new();
    for scenario in &scenarios {
        assert!(
            ids.insert(scenario.id.clone()),
            "id {} repeated",
            scenario.id
        );
    }
    let index = index();
    let mut indexed = BTreeSet::new();
    for (row, covered) in &index {
        for id in covered.iter().flatten() {
            assert!(
                ids.contains(id),
                "index row `{row}` names unknown scenario {id}"
            );
            indexed.insert(id.clone());
        }
    }
    for scenario in &scenarios {
        assert!(
            indexed.contains(&scenario.id),
            "{} is not in index.txt",
            scenario.id
        );
        let covered = index
            .get(&scenario.covers)
            .unwrap_or_else(|| panic!("{} covers unknown row `{}`", scenario.id, scenario.covers));
        assert!(
            covered.iter().flatten().any(|id| *id == scenario.id),
            "{} covers `{}`, whose index line does not name it",
            scenario.id,
            scenario.covers
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the suite's files, which Miri's isolation forbids"
)]
fn the_parser_refuses_what_the_format_does_not_allow() {
    let at = "test";
    assert_eq!(
        tokens(r#"expect text="a \"b\" # c" # comment"#, at),
        ["expect", r#"text="a \"b\" # c""#]
    );
    assert_eq!(
        value(r#""a \"b\" \\""#, at),
        Value::Text(r#"a "b" \"#.to_owned())
    );
    assert_eq!(value("-1", at), Value::Integer(-1));
    assert_eq!(value("$x", at), Value::Variable("x".to_owned()));
    assert_eq!(value("null", at), Value::Null);
    for broken in [
        "id x\nformat 1\n",
        "format 2\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\ncall f\ncall g\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\nexpect KARYOS_OK\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\ncall f\n",
        "format 1\nid a\nabi zero\ncovers \"r\"\ncall f\nexpect\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\ncall f x=1 x=2\nexpect\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\nbogus\n",
    ] {
        let dir = std::env::temp_dir().join(format!("karyos-ffi-kcs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("broken.kcs");
        std::fs::write(&file, broken).unwrap();
        let parsed = std::panic::catch_unwind(|| parse(&file));
        assert!(parsed.is_err(), "accepted:\n{broken}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the suite's files, which Miri's isolation forbids"
)]
fn a_scenario_of_another_major_or_a_newer_minor_is_skipped() {
    let statuses = statuses();
    let step = Step {
        line: 1,
        function: "karyos_abi_version".to_owned(),
        arguments: BTreeMap::new(),
        status: Some("KARYOS_OK".to_owned()),
        results: BTreeMap::new(),
    };
    let scenario = |abi| Scenario {
        file: PathBuf::from("test.kcs"),
        id: "test".to_owned(),
        abi,
        covers: "abi version".to_owned(),
        steps: vec![step.clone()],
    };
    assert!(run(&scenario((0, 1)), &statuses, (0, 1)));
    assert!(run(&scenario((0, 1)), &statuses, (0, 2)));
    assert!(!run(&scenario((0, 2)), &statuses, (0, 1)));
    assert!(!run(&scenario((1, 0)), &statuses, (0, 1)));
}
