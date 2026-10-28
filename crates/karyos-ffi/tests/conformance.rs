// SPDX-License-Identifier: Apache-2.0

//! The reference runner of the language-neutral conformance suite in
//! `conformance/` (formats 1 and 2, `conformance/FORMAT.md`; SPEC.md
//! §10.2, §13; ADR-0073). It runs every ABI-layer scenario through the
//! exported symbols, as a binding's runner does through its own API, runs
//! every semantic scenario through its own adapter over those symbols
//! (`support::semantic`), and checks the coverage map. Miri skips it: it
//! reads the suite's files, which Miri's isolation forbids, and its calls
//! go through `support::abi`, which `tests/abi.rs` runs under Miri.

// Test helpers outside `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use karyos_ffi as _;

mod support {
    #[allow(dead_code, reason = "each test binary calls a part of the ABI")]
    pub mod abi;
    pub mod semantic;
    pub mod sha256;
}

use support::{abi, semantic, sha256};

/// The format versions this runner reads.
const FORMATS: [&str; 2] = ["1", "2"];

/// The lowest ABI version this suite needs (FORMAT.md, Versions): 0.1.3,
/// whose readiness calls two scenarios make (karyos#794), after 0.1.2's
/// roles calls (karyos#637).
const MINIMUM_ABI: [u32; 3] = [0, 1, 3];

/// Whether a library of ABI `library` can run this suite (FORMAT.md,
/// Versions): before 1.0 exactly the suite's 0.y, at least its 0.y.z;
/// from 1.0 the same major and at least its minor and patch.
fn suite_runs_on(library: [u32; 3]) -> bool {
    let [major, minor, _] = MINIMUM_ABI;
    let same = if major == 0 {
        library[..2] == [major, minor]
    } else {
        library[0] == major
    };
    same && library >= MINIMUM_ABI
}

/// The binding SPECs' delivery steps a format 2 `since` names, in order
/// (FORMAT.md, Format 2).
const STEPS: [&str; 6] = ["B0", "B1", "B2", "B3", "B4", "B5"];

/// The features a format 2 scenario may need (FORMAT.md, Features).
const FEATURES: [&str; 9] = [
    "archive-replay",
    "claim-retry",
    "concurrent-publication",
    "conflation",
    "embedded-driver",
    "guarded-publication",
    "incompatible-driver",
    "remote-driver",
    "tai-clock",
];

/// The bounds of a scenario file (FORMAT.md, Bounds).
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 4096;
const MAX_TOKENS: usize = 64;
const MAX_STEPS: usize = 1024;
const MAX_VARIABLES: usize = 256;
const MAX_SCENARIOS: usize = 4096;

/// The argument names that take an object of the semantic layer.
const OBJECTS: [&str; 7] = [
    "archive",
    "driver",
    "client",
    "publication",
    "subscription",
    "conflated",
    "claim",
];

/// An op of the semantic layer: its required and optional arguments, the
/// results its `ok` may name, and the features a scenario needs for it
/// (FORMAT.md, Ops).
struct Op {
    name: &'static str,
    required: &'static [&'static str],
    optional: &'static [&'static str],
    results: &'static [&'static str],
    features: &'static [&'static str],
}

const fn op(
    name: &'static str,
    required: &'static [&'static str],
    optional: &'static [&'static str],
    results: &'static [&'static str],
    features: &'static [&'static str],
) -> Op {
    Op {
        name,
        required,
        optional,
        results,
        features,
    }
}

const EMBEDDED: &[&str] = &["embedded-driver"];
const STREAM: &[&str] = &[
    "allow_unconnected",
    "publication_mode",
    "publishers",
    "spare_slots",
    "term_length",
    "conflation_keys",
    "conflation_value_capacity",
    "conflation_journal_capacity",
];
const MESSAGE: &[&str] = &["lane", "payload", "length"];
const ACCEPTED: &[&str] = &["lane", "position"];

const OPS: &[Op] = &[
    op(
        "library.version",
        &[],
        &[],
        &["major", "minor", "patch"],
        &[],
    ),
    op("clock.now", &["domain"], &[], &["now"], &[]),
    op("driver.create", &[], &[], &["driver"], EMBEDDED),
    op(
        "driver.add_stream",
        &["driver", "stream_id"],
        STREAM,
        &[],
        EMBEDDED,
    ),
    op(
        "driver.start",
        &["driver"],
        &["idle_strategy", "idle_sleep_ns"],
        &[],
        EMBEDDED,
    ),
    op("driver.do_work", &["driver"], &[], &["work"], EMBEDDED),
    op(
        "driver.subscribe_conflated",
        &["driver", "stream_id"],
        &[],
        &["conflated"],
        &["embedded-driver", "conflation"],
    ),
    op("driver.close", &["driver"], &[], &[], EMBEDDED),
    // A provided driver's client, or one connected to `dir`'s admission
    // socket (FORMAT.md, Incompatible driver).
    op("client.connect", &[], &["driver", "dir"], &["client"], &[]),
    op("client.poll", &["client"], &[], &["served"], &[]),
    op("client.close", &["client"], &[], &[], &[]),
    op(
        "publication.add",
        &["client", "stream_id"],
        &["uri"],
        &["publication"],
        &[],
    ),
    op(
        "publication.add_concurrent",
        &["client", "stream_id"],
        &["uri"],
        &["publication"],
        &["concurrent-publication"],
    ),
    op(
        "publication.offer",
        &["publication"],
        &["lane", "payload", "length", "reserved_value"],
        ACCEPTED,
        &[],
    ),
    // A timed lane's offer at `tx_time`, or `delay_ns` after the runner's
    // monotonic clock reading (FORMAT.md, Ops).
    op(
        "publication.offer_at",
        &["publication"],
        &["lane", "payload", "length", "tx_time", "delay_ns"],
        &["lane", "position", "tx_time"],
        &[],
    ),
    op(
        "publication.publish_claimed",
        &["publication"],
        MESSAGE,
        ACCEPTED,
        &[],
    ),
    op(
        "publication.claim",
        &["publication", "length"],
        &["lane"],
        &["claim"],
        &["claim-retry"],
    ),
    op("claim.commit", &["claim"], &[], ACCEPTED, &["claim-retry"]),
    op("claim.abort", &["claim"], &[], &[], &["claim-retry"]),
    op(
        "publication.poll_outcomes",
        &["publication"],
        &["lane", "limit", "until"],
        &["delivered"],
        &["guarded-publication"],
    ),
    op("publication.close", &["publication"], &[], &[], &[]),
    op(
        "subscription.add",
        &["client", "stream_id"],
        &["uri", "role", "rejoin"],
        &["subscription"],
        &[],
    ),
    op(
        "subscription.poll",
        &["subscription"],
        &["limit", "until", "not_before"],
        &["delivered", "last"],
        &[],
    ),
    op("subscription.close", &["subscription"], &[], &[], &[]),
    op(
        "conflated.add",
        &["client", "stream_id"],
        &["uri"],
        &["conflated"],
        &["conflation"],
    ),
    op(
        "conflated.poll",
        &["conflated"],
        &["key_budget", "until"],
        &["delivered"],
        &["conflation"],
    ),
    op("conflated.close", &["conflated"], &[], &[], &["conflation"]),
    op(
        "archive.connect",
        &["client"],
        &[],
        &["archive"],
        &["archive-replay"],
    ),
    op(
        "archive.replay",
        &["archive", "recording", "target_stream_id"],
        &["position", "length", "rate", "scale_ppm"],
        &["replay", "session"],
        &["archive-replay"],
    ),
    op(
        "archive.stop_replay",
        &["archive", "replay"],
        &[],
        &[],
        &["archive-replay"],
    ),
    op("archive.close", &["archive"], &[], &[], &["archive-replay"]),
    op(
        "replay.subscribe",
        &["client", "stream_id", "session"],
        &[],
        &["subscription"],
        &["archive-replay"],
    ),
    op(
        "subscription.poll_to_end",
        &["subscription"],
        &["limit"],
        &["delivered", "last"],
        &[],
    ),
    op(
        "subscription.end",
        &["subscription"],
        &[],
        &["reason", "position", "seal_code"],
        &[],
    ),
];

/// The ops whose refusal carries the Archive's response code, `code`
/// (FORMAT.md, Outcomes).
const ARCHIVE_REFUSALS: [&str; 2] = ["archive.replay", "archive.stop_replay"];

/// A value of a scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// Within 64-bit signed range in format 1; from -2^63 to 2^64 - 1 in
    /// format 2.
    Integer(i128),
    Text(String),
    Null,
    Variable(String),
    /// An object of the semantic layer, as the adapter numbers it.
    Object(usize),
}

/// What an `expect` checks of a result: equality, or (format 2) a lower
/// bound, `name>=value`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expected {
    Equal(Value),
    AtLeast(Value),
}

/// The layer of a format 2 scenario's steps (FORMAT.md, Layers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layer {
    Abi,
    Semantic,
}

/// A `call` or an `op`, and its `expect`.
#[derive(Debug, Clone)]
struct Step {
    line: usize,
    layer: Layer,
    function: String,
    arguments: BTreeMap<String, Value>,
    /// The ABI layer's `KARYOS_*` name, if any; the semantic layer's `ok`
    /// or status name.
    status: Option<String>,
    results: BTreeMap<String, Expected>,
}

/// A parsed scenario.
#[derive(Debug)]
struct Scenario {
    file: PathBuf,
    format: u8,
    id: String,
    abi: (u32, u32),
    covers: String,
    /// The step index (in [`STEPS`]) from which it is required; format 2.
    since: Option<usize>,
    features: BTreeSet<String>,
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

/// A value of a scenario of `format`.
fn value(token: &str, format: u8, at: &str) -> Value {
    if token == "null" {
        Value::Null
    } else if let Some(name) = token.strip_prefix('$') {
        assert!(!name.is_empty(), "{at}: empty variable name");
        Value::Variable(name.to_owned())
    } else if let Some(text) = token.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        Value::Text(text.replace("\\\"", "\"").replace("\\\\", "\\"))
    } else {
        let integer: i128 = token
            .parse()
            .unwrap_or_else(|_| panic!("{at}: `{token}` is no value"));
        let highest = if format == 1 {
            i128::from(i64::MAX)
        } else {
            i128::from(u64::MAX)
        };
        assert!(
            integer >= i128::from(i64::MIN) && integer <= highest,
            "{at}: `{token}` is out of range for format {format}"
        );
        Value::Integer(integer)
    }
}

fn pairs(tokens: &[String], format: u8, at: &str) -> BTreeMap<String, Value> {
    let mut pairs = BTreeMap::new();
    for token in tokens {
        let (name, raw) = token
            .split_once('=')
            .unwrap_or_else(|| panic!("{at}: `{token}` is not name=value"));
        let previous = pairs.insert(name.to_owned(), value(raw, format, at));
        assert!(previous.is_none(), "{at}: `{name}` given twice");
    }
    pairs
}

/// An `expect`'s results: `name=value`, and in format 2 `name>=value`.
fn expected(tokens: &[String], format: u8, at: &str) -> BTreeMap<String, Expected> {
    pairs(tokens, format, at)
        .into_iter()
        .map(|(name, value)| match name.strip_suffix('>') {
            Some(name) => {
                assert_eq!(format, 2, "{at}: `>=` is format 2");
                (name.to_owned(), Expected::AtLeast(value))
            }
            None => (name, Expected::Equal(value)),
        })
        .fold(BTreeMap::new(), |mut results, (name, expected)| {
            let previous = results.insert(name.clone(), expected);
            assert!(previous.is_none(), "{at}: `{name}` given twice");
            results
        })
}

/// Checks a header line: given once, before the first call.
fn header<T>(slot: &Option<T>, started: bool, keyword: &str, at: &str) {
    assert!(slot.is_none(), "{at}: `{keyword}` given twice");
    assert!(!started, "{at}: `{keyword}` after a call");
}

/// Checks an `op` step against [`OPS`] and the scenario's features: its
/// name, its arguments, its object arguments as variables, and its
/// expectation (FORMAT.md, Ops, Outcomes).
fn check_op(step: &Step, features: &BTreeSet<String>, names: &BTreeSet<String>, at: &str) {
    let op = OPS
        .iter()
        .find(|op| op.name == step.function)
        .unwrap_or_else(|| panic!("{at}: unknown op `{}`", step.function));
    for feature in op.features {
        assert!(
            features.contains(*feature),
            "{at}: `{}` needs `feature {feature}`",
            op.name
        );
    }
    for (name, argument) in &step.arguments {
        assert!(
            op.required.contains(&name.as_str()) || op.optional.contains(&name.as_str()),
            "{at}: `{}` takes no argument `{name}`",
            op.name
        );
        if OBJECTS.contains(&name.as_str()) {
            assert!(
                matches!(argument, Value::Variable(_)),
                "{at}: `{name}` is an object, passed as a variable"
            );
        }
    }
    for name in op.required {
        assert!(
            step.arguments.contains_key(*name),
            "{at}: `{}` needs `{name}`",
            op.name
        );
    }
    // The text arguments with a fixed set of values, and the TAI domain's
    // feature (FORMAT.md, Ops).
    for (name, allowed) in [
        ("domain", &["monotonic", "tai"][..]),
        ("rate", &["full", "as_recorded", "scaled"][..]),
        (
            "idle_strategy",
            &["busy_spin", "yield", "sleep", "yield_then_sleep"][..],
        ),
    ] {
        if let Some(value) = step.arguments.get(name) {
            assert!(
                matches!(value, Value::Text(text) if allowed.contains(&text.as_str())),
                "{at}: `{name}` is one of {allowed:?}, not {value:?}"
            );
        }
    }
    if step.arguments.get("domain") == Some(&Value::Text("tai".to_owned())) {
        assert!(
            features.contains("tai-clock"),
            "{at}: `domain=\"tai\"` needs `feature tai-clock`"
        );
    }
    match step.status.as_deref() {
        Some("ok") => {
            for name in step.results.keys() {
                assert!(
                    op.results.contains(&name.as_str()),
                    "{at}: `{}` has no result `{name}`",
                    op.name
                );
            }
        }
        Some(status) => {
            assert!(
                names.contains(status),
                "{at}: `{status}` is no status of the header"
            );
            // The semantic layer answers a stale handle `closed`: a binding
            // never produces `invalid_handle` (FORMAT.md, Close).
            assert_ne!(
                status, "invalid_handle",
                "{at}: `invalid_handle` is no op outcome"
            );
            // Only an Archive's refusal carries a result: its code.
            let code_only = status == "refused"
                && ARCHIVE_REFUSALS.contains(&op.name)
                && step.results.keys().all(|name| name == "code");
            assert!(
                step.results.is_empty() || code_only,
                "{at}: a status expects no results"
            );
        }
        None => panic!("{at}: an op's expect is `ok` or `status=<name>`"),
    }
}

fn parse(file: &Path) -> Scenario {
    let text = std::fs::read_to_string(file).unwrap();
    parse_text(&text, file, &statuses())
}

fn parse_text(text: &str, file: &Path, statuses: &BTreeMap<String, i32>) -> Scenario {
    let name = file.display().to_string();
    assert!(
        text.len() <= MAX_FILE_BYTES,
        "{name}: over {MAX_FILE_BYTES} bytes"
    );
    // The semantic layer's status names: the header's `KARYOS_E_*`, in
    // lower case without the prefix.
    let names: BTreeSet<String> = statuses
        .keys()
        .filter_map(|status| Some(status.strip_prefix("KARYOS_E_")?.to_ascii_lowercase()))
        .collect();
    let mut format: Option<u8> = None;
    let (mut id, mut abi, mut covers) = (None, None, None);
    let mut since: Option<usize> = None;
    let mut features = BTreeSet::new();
    let mut steps: Vec<Step> = Vec::new();
    let mut open: Option<(usize, Layer, String, BTreeMap<String, Value>)> = None;
    for (index, line) in text.lines().enumerate() {
        let at = format!("{name}:{}", index + 1);
        assert!(
            line.len() <= MAX_LINE_BYTES,
            "{at}: over {MAX_LINE_BYTES} bytes"
        );
        let tokens = tokens(line, &at);
        assert!(tokens.len() <= MAX_TOKENS, "{at}: over {MAX_TOKENS} tokens");
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
        let version = format.unwrap_or(1);
        match keyword.as_str() {
            "format" => {
                header(&format, started, keyword, &at);
                let given = single();
                assert!(
                    FORMATS.contains(&given.as_str()),
                    "{at}: unknown format {given}"
                );
                format = Some(given.parse().unwrap());
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
                let Value::Text(row) = value(&single(), version, &at) else {
                    panic!("{at}: `covers` takes a quoted string");
                };
                covers = Some(row);
            }
            "since" => {
                assert_eq!(version, 2, "{at}: `since` is format 2");
                header(&since, started, keyword, &at);
                let step = single();
                since = Some(
                    STEPS
                        .iter()
                        .position(|known| *known == step)
                        .unwrap_or_else(|| panic!("{at}: unknown step `{step}`")),
                );
            }
            "feature" => {
                assert_eq!(version, 2, "{at}: `feature` is format 2");
                assert!(!started, "{at}: `feature` after a step");
                let feature = single();
                assert!(
                    FEATURES.contains(&feature.as_str()),
                    "{at}: unknown feature `{feature}`"
                );
                assert!(
                    features.insert(feature.clone()),
                    "{at}: `feature {feature}` given twice"
                );
            }
            "call" | "op" => {
                assert!(open.is_none(), "{at}: a step before the last one's expect");
                let layer = if keyword == "op" {
                    assert_eq!(version, 2, "{at}: `op` is format 2");
                    Layer::Semantic
                } else {
                    Layer::Abi
                };
                if let Some(first) = steps.first() {
                    assert_eq!(first.layer, layer, "{at}: `call` and `op` in one scenario");
                }
                assert!(steps.len() < MAX_STEPS, "{at}: over {MAX_STEPS} steps");
                let (function, arguments) = rest
                    .split_first()
                    .unwrap_or_else(|| panic!("{at}: `{keyword}` needs a name"));
                open = Some((
                    index + 1,
                    layer,
                    function.clone(),
                    pairs(arguments, version, &at),
                ));
            }
            "expect" => {
                let (line, layer, function, arguments) = open
                    .take()
                    .unwrap_or_else(|| panic!("{at}: `expect` without a step"));
                let (status, results) = match (layer, rest.split_first()) {
                    (Layer::Abi, Some((first, results))) if first.starts_with("KARYOS_") => {
                        (Some(first.clone()), results)
                    }
                    (Layer::Abi, _) => (None, rest),
                    (Layer::Semantic, Some((first, results))) if first == "ok" => {
                        (Some("ok".to_owned()), results)
                    }
                    (Layer::Semantic, Some((first, results))) => {
                        let status = first
                            .strip_prefix("status=")
                            .unwrap_or_else(|| panic!("{at}: `ok` or `status=<name>` first"));
                        (Some(status.to_owned()), results)
                    }
                    (Layer::Semantic, None) => panic!("{at}: `ok` or `status=<name>` first"),
                };
                let step = Step {
                    line,
                    layer,
                    function,
                    arguments,
                    status,
                    results: expected(results, version, &at),
                };
                if layer == Layer::Semantic {
                    check_op(&step, &features, &names, &at);
                }
                steps.push(step);
            }
            other => panic!("{at}: unknown keyword `{other}`"),
        }
    }
    assert!(open.is_none(), "{name}: the last step has no expect");
    assert!(!steps.is_empty(), "{name}: no step");
    let format = format.unwrap_or_else(|| panic!("{name}: no format"));
    if format == 2 {
        assert!(since.is_some(), "{name}: format 2 needs `since`");
    }
    let variables: BTreeSet<&str> = steps
        .iter()
        .flat_map(|step| {
            let results = step.results.values().map(|expected| match expected {
                Expected::Equal(value) | Expected::AtLeast(value) => value,
            });
            step.arguments.values().chain(results)
        })
        .filter_map(|value| match value {
            Value::Variable(name) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        variables.len() <= MAX_VARIABLES,
        "{name}: over {MAX_VARIABLES} variables"
    );
    Scenario {
        file: file.to_path_buf(),
        format,
        id: id.unwrap_or_else(|| panic!("{name}: no id")),
        abi: abi.unwrap_or_else(|| panic!("{name}: no abi")),
        covers: covers.unwrap_or_else(|| panic!("{name}: no covers")),
        since,
        features,
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

/// The handle argument `name`, the step's only one.
fn handle_argument(step: &Step, name: &str, at: &str) -> u64 {
    let value = integer_argument(step, name, at);
    u64::try_from(value).unwrap_or_else(|_| panic!("{at}: `{name}` is not a uint64_t"))
}

/// What a function that writes one handle returned.
fn with_handle(status: i32, name: &str, handle: u64) -> Returned {
    Returned {
        status: Some(status),
        results: BTreeMap::from([(name.to_owned(), Value::Integer(i128::from(handle)))]),
    }
}

/// What a function that writes one count returned.
fn with_count(status: i32, name: &str, count: u32) -> Returned {
    Returned {
        status: Some(status),
        results: BTreeMap::from([(name.to_owned(), Value::Integer(i128::from(count)))]),
    }
}

fn integer_argument(step: &Step, name: &str, at: &str) -> i128 {
    assert_eq!(step.arguments.len(), 1, "{at}: one argument, `{name}`");
    match step.arguments.get(name) {
        Some(Value::Integer(value)) => *value,
        other => panic!("{at}: `{name}` must be an integer, got {other:?}"),
    }
}

/// A step's arguments, checked against the names a function takes.
struct Arguments<'a> {
    step: &'a Step,
    at: &'a str,
}

impl<'a> Arguments<'a> {
    /// The arguments of `step`, every one of them among `names`.
    fn new(step: &'a Step, names: &[&str], at: &'a str) -> Self {
        for name in step.arguments.keys() {
            assert!(
                names.contains(&name.as_str()),
                "{at}: unknown argument `{name}`"
            );
        }
        Self { step, at }
    }

    fn integer(&self, name: &str) -> Option<i128> {
        match self.step.arguments.get(name) {
            None => None,
            Some(Value::Integer(value)) => Some(*value),
            Some(other) => panic!("{}: `{name}` must be an integer, got {other:?}", self.at),
        }
    }

    /// An integer argument that fits `T`, or `default`.
    fn narrow<T: TryFrom<i128>>(&self, name: &str, default: T) -> T {
        self.integer(name).map_or(default, |value| {
            T::try_from(value)
                .unwrap_or_else(|_| panic!("{}: `{name}` does not fit its C type", self.at))
        })
    }

    /// A required handle argument.
    fn handle(&self, name: &str) -> u64 {
        let value = self
            .integer(name)
            .unwrap_or_else(|| panic!("{}: `{name}` is required", self.at));
        u64::try_from(value).unwrap_or_else(|_| panic!("{}: `{name}` is not a uint64_t", self.at))
    }

    fn text(&self, name: &str) -> Option<String> {
        match self.step.arguments.get(name) {
            None => None,
            Some(Value::Text(text)) => Some(text.clone()),
            Some(other) => panic!("{}: `{name}` must be a string, got {other:?}", self.at),
        }
    }

    /// The message an offer passes: `payload`'s bytes, or `length` zero
    /// bytes; one of them is required.
    fn message(&self) -> Vec<u8> {
        match (self.text("payload"), self.integer("length")) {
            (Some(payload), None) => payload.into_bytes(),
            (None, Some(_)) => vec![0; self.narrow::<usize>("length", 0)],
            _ => panic!("{}: `payload` or `length`, one of them", self.at),
        }
    }
}

/// A roles list argument (karyos#637): a string of comma-separated
/// entries, each `id` (`per` 1) or `id:tag` (`per` 2), or `null`; absent
/// is empty. `count`, when given, is the count passed instead of the
/// entries' (a null list with a count, or a count past the words).
fn roles_list(
    arguments: &Arguments<'_>,
    name: &str,
    count: &str,
    at: &str,
    per: usize,
) -> abi::RolesList {
    let words = match arguments.step.arguments.get(name) {
        None => Some(Vec::new()),
        Some(Value::Null) => None,
        Some(Value::Text(text)) => Some(
            text.split(',')
                .filter(|entry| !entry.is_empty())
                .flat_map(|entry| entry.split(':'))
                .map(|word| {
                    word.parse::<u64>()
                        .unwrap_or_else(|_| panic!("{at}: `{name}` holds `{word}`"))
                })
                .collect(),
        ),
        Some(other) => panic!("{at}: `{name}` must be a string or null, got {other:?}"),
    };
    let entries = words.as_ref().map_or(0, |words| words.len() / per);
    abi::RolesList {
        count: arguments.narrow(count, entries),
        words,
    }
}

/// The size a sized struct argument names, or `T`'s.
fn size_argument<T>(arguments: &Arguments<'_>, name: &str) -> u32 {
    let own = u32::try_from(size_of::<T>()).unwrap();
    arguments.narrow(name, own)
}

/// What a call that writes a `karyos_accepted` returned: its status, the
/// lane and position when they were written, and whether the struct's tail
/// past this header's size is intact.
fn with_accepted(status: i32, accepted: &abi::SizedStruct<abi::Accepted>) -> Returned {
    let mut results = BTreeMap::from([("tail".to_owned(), tail(accepted.tail_intact()))]);
    if let Some((lane, position)) = abi::accepted_fields(accepted) {
        results.insert("lane".to_owned(), Value::Integer(i128::from(lane)));
        results.insert("position".to_owned(), Value::Integer(i128::from(position)));
    }
    Returned {
        status: Some(status),
        results,
    }
}

/// A sized struct's tail as a result.
fn tail(intact: bool) -> Value {
    Value::Text(if intact { "intact" } else { "changed" }.to_owned())
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
                    Some((name.to_owned(), Value::Integer(i128::from(value?))))
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
        "karyos_driver_create" => {
            let arguments = Arguments::new(step, &["size", "reserved"], at);
            let (status, mut options) = abi::driver_options();
            assert_eq!(status, 0, "{at}: karyos_driver_options_init");
            options.reserved = arguments.narrow("reserved", options.reserved);
            let size = size_argument::<abi::DriverOptions>(&arguments, "size");
            let (status, driver) = abi::driver_create_sized(&options, size);
            with_handle(status, "driver", driver)
        }
        "karyos_driver_start" => {
            let arguments = Arguments::new(step, &["driver", "idle_strategy", "idle_sleep_ns"], at);
            Returned {
                status: Some(abi::driver_start(
                    arguments.handle("driver"),
                    arguments.narrow("idle_strategy", 3),
                    arguments.narrow("idle_sleep_ns", 0),
                )),
                results: BTreeMap::new(),
            }
        }
        "karyos_driver_startup_complete" => {
            let (status, complete) =
                abi::driver_startup_complete(handle_argument(step, "driver", at));
            with_count(status, "complete", complete)
        }
        "karyos_driver_readiness" => {
            let arguments = Arguments::new(step, &["driver", "size"], at);
            let size = size_argument::<abi::Readiness>(&arguments, "size");
            let (status, out) = abi::driver_readiness_sized(arguments.handle("driver"), size);
            let mut results = BTreeMap::from([("tail".to_owned(), tail(out.tail_intact()))]);
            if let Some((state, reason, reserved)) = abi::readiness_fields(&out) {
                results.insert("state".to_owned(), Value::Integer(i128::from(state)));
                results.insert("reason".to_owned(), Value::Integer(i128::from(reason)));
                results.insert("reserved".to_owned(), Value::Integer(i128::from(reserved)));
            }
            Returned {
                status: Some(status),
                results,
            }
        }
        "karyos_driver_stop" => Returned {
            status: Some(abi::driver_stop(handle_argument(step, "driver", at))),
            results: BTreeMap::new(),
        },
        "karyos_driver_add_stream" => {
            let arguments = Arguments::new(
                step,
                &[
                    "driver",
                    "stream_id",
                    "allow_unconnected",
                    "schedule_capacity",
                    "conflation_keys",
                    "conflation_value_capacity",
                    "conflation_journal_capacity",
                    "publication_mode",
                    "publishers",
                    "size",
                ],
                at,
            );
            let stream_id = arguments
                .integer("stream_id")
                .map(|_| arguments.narrow("stream_id", 0))
                .unwrap_or_else(|| panic!("{at}: `stream_id` is required"));
            let (status, mut options) = abi::stream_options(stream_id);
            assert_eq!(status, 0, "{at}: karyos_stream_options_init");
            options.allow_unconnected =
                arguments.narrow("allow_unconnected", options.allow_unconnected);
            options.schedule_capacity =
                arguments.narrow("schedule_capacity", options.schedule_capacity);
            options.conflation_keys = arguments.narrow("conflation_keys", options.conflation_keys);
            options.conflation_value_capacity = arguments.narrow(
                "conflation_value_capacity",
                options.conflation_value_capacity,
            );
            options.conflation_journal_capacity = arguments.narrow(
                "conflation_journal_capacity",
                options.conflation_journal_capacity,
            );
            options.publication_mode =
                arguments.narrow("publication_mode", options.publication_mode);
            options.publishers = arguments.narrow("publishers", options.publishers);
            let size = size_argument::<abi::StreamOptions>(&arguments, "size");
            Returned {
                status: Some(abi::driver_add_stream_sized(
                    arguments.handle("driver"),
                    &options,
                    size,
                )),
                results: BTreeMap::new(),
            }
        }
        "karyos_client_connect" => {
            let arguments = Arguments::new(step, &["size"], at);
            let size = arguments
                .integer("size")
                .map(|_| size_argument::<abi::ClientOptions>(&arguments, "size"))
                .unwrap_or_else(|| panic!("{at}: `size` is required"));
            Returned {
                status: Some(abi::client_connect_sized(size)),
                results: BTreeMap::new(),
            }
        }
        "karyos_client_add_publication" | "karyos_client_add_concurrent_publication" => {
            let arguments =
                Arguments::new(step, &["client", "stream_id", "uri", "detail_size"], at);
            let uri = std::ffi::CString::new(
                arguments
                    .text("uri")
                    .unwrap_or_else(|| "karyos:ipc".to_owned()),
            )
            .unwrap_or_else(|_| panic!("{at}: `uri` holds a NUL"));
            let stream_id = arguments
                .integer("stream_id")
                .map(|_| arguments.narrow("stream_id", 0))
                .unwrap_or_else(|| panic!("{at}: `stream_id` is required"));
            let (status, publication, detail) = abi::client_add_publication_of(
                arguments.handle("client"),
                &uri,
                stream_id,
                size_argument::<abi::Detail>(&arguments, "detail_size"),
                step.function == "karyos_client_add_concurrent_publication",
            );
            let mut results =
                BTreeMap::from([("detail_tail".to_owned(), tail(detail.tail_intact()))]);
            if status == 0 {
                results.insert(
                    "publication".to_owned(),
                    Value::Integer(i128::from(publication)),
                );
            }
            let written = abi::detail_fields(&detail);
            results.insert(
                "detail_written".to_owned(),
                Value::Integer(i128::from(written.is_some())),
            );
            if let Some((code, value)) = written {
                results.insert("code".to_owned(), Value::Integer(i128::from(code)));
                results.insert("value".to_owned(), Value::Integer(i128::from(value)));
            }
            Returned {
                status: Some(status),
                results,
            }
        }
        "karyos_publication_offer" => {
            let arguments = Arguments::new(
                step,
                &["publication", "lane", "payload", "length", "accepted_size"],
                at,
            );
            let (status, accepted) = abi::publication_offer_on(
                arguments.handle("publication"),
                arguments.narrow("lane", 0),
                &arguments.message(),
                size_argument::<abi::Accepted>(&arguments, "accepted_size"),
            );
            with_accepted(status, &accepted)
        }
        "karyos_publication_offer_with" => {
            let arguments = Arguments::new(
                step,
                &[
                    "publication",
                    "lane",
                    "payload",
                    "length",
                    "size",
                    "reserved",
                    "reserved_value",
                    "accepted_size",
                ],
                at,
            );
            let (status, mut options) = abi::offer_options();
            assert_eq!(status, 0, "{at}: karyos_offer_options_init");
            options.reserved = arguments.narrow("reserved", options.reserved);
            options.reserved_value = arguments.narrow("reserved_value", options.reserved_value);
            let (status, accepted) = abi::publication_offer_with(
                arguments.handle("publication"),
                arguments.narrow("lane", 0),
                &arguments.message(),
                &options,
                size_argument::<abi::OfferOptions>(&arguments, "size"),
                size_argument::<abi::Accepted>(&arguments, "accepted_size"),
            );
            with_accepted(status, &accepted)
        }
        "karyos_publication_offer_at" => {
            let arguments = Arguments::new(
                step,
                &[
                    "publication",
                    "lane",
                    "payload",
                    "length",
                    "tx_time",
                    "accepted_size",
                ],
                at,
            );
            let tx_time = arguments
                .integer("tx_time")
                .map(|value| {
                    u64::try_from(value)
                        .unwrap_or_else(|_| panic!("{at}: `tx_time` is not a uint64_t"))
                })
                .unwrap_or_else(|| panic!("{at}: `tx_time` is required"));
            let (status, accepted) = abi::publication_offer_at(
                arguments.handle("publication"),
                arguments.narrow("lane", 0),
                &arguments.message(),
                tx_time,
                size_argument::<abi::Accepted>(&arguments, "accepted_size"),
            );
            with_accepted(status, &accepted)
        }
        "karyos_clock_now" => {
            let arguments = Arguments::new(step, &["domain"], at);
            let domain = arguments
                .integer("domain")
                .map(|_| arguments.narrow("domain", 0))
                .unwrap_or_else(|| panic!("{at}: `domain` is required"));
            let (status, now) = abi::clock_now(domain);
            let results = now
                .map(|now| BTreeMap::from([("now".to_owned(), Value::Integer(i128::from(now)))]))
                .unwrap_or_default();
            Returned {
                status: Some(status),
                results,
            }
        }
        "karyos_publication_claim" => {
            let arguments = Arguments::new(step, &["publication", "lane", "length"], at);
            let length = arguments
                .integer("length")
                .map(|_| arguments.narrow("length", 0))
                .unwrap_or_else(|| panic!("{at}: `length` is required"));
            let (status, claim) = abi::publication_claim(
                arguments.handle("publication"),
                arguments.narrow("lane", 0),
                length,
            );
            if status == 0 {
                with_handle(status, "claim", claim)
            } else {
                Returned {
                    status: Some(status),
                    results: BTreeMap::new(),
                }
            }
        }
        "karyos_claim_commit" => {
            let arguments = Arguments::new(step, &["claim", "accepted_size"], at);
            let (status, accepted) = abi::claim_commit(
                arguments.handle("claim"),
                size_argument::<abi::Accepted>(&arguments, "accepted_size"),
            );
            with_accepted(status, &accepted)
        }
        "karyos_claim_abort" => Returned {
            status: Some(abi::claim_abort(handle_argument(step, "claim", at))),
            results: BTreeMap::new(),
        },
        "karyos_client_add_publication_with_roles" => {
            let arguments = Arguments::new(
                step,
                &[
                    "client",
                    "stream_id",
                    "uri",
                    "strategy",
                    "tagged_group",
                    "required",
                    "required_count",
                    "required_fill",
                    "tags",
                    "tag_count",
                    "detail_size",
                ],
                at,
            );
            let uri = std::ffi::CString::new(
                arguments
                    .text("uri")
                    .unwrap_or_else(|| "karyos:udp?group=239.255.0.21:40001|fc=min".to_owned()),
            )
            .unwrap_or_else(|_| panic!("{at}: `uri` holds a NUL"));
            let stream_id = arguments
                .integer("stream_id")
                .map(|_| arguments.narrow("stream_id", 0))
                .unwrap_or_else(|| panic!("{at}: `stream_id` is required"));
            let required = roles_list(&arguments, "required", "required_count", at, 1);
            let required = match arguments.integer("required_fill") {
                Some(_) => {
                    let fill: u64 = arguments.narrow("required_fill", 0);
                    abi::RolesList {
                        words: Some((1..=fill).collect()),
                        count: usize::try_from(fill).unwrap(),
                    }
                }
                None => required,
            };
            let tags = roles_list(&arguments, "tags", "tag_count", at, 2);
            let (status, publication, detail) = abi::client_add_publication_with_roles(
                arguments.handle("client"),
                &uri,
                stream_id,
                arguments.narrow("strategy", 0),
                arguments.narrow("tagged_group", 0),
                &required,
                &tags,
                size_argument::<abi::Detail>(&arguments, "detail_size"),
            );
            let mut results = BTreeMap::new();
            if status == 0 {
                results.insert(
                    "publication".to_owned(),
                    Value::Integer(i128::from(publication)),
                );
            }
            if let Some((code, value)) = abi::detail_fields(&detail) {
                results.insert("code".to_owned(), Value::Integer(i128::from(code)));
                results.insert("value".to_owned(), Value::Integer(i128::from(value)));
            }
            Returned {
                status: Some(status),
                results,
            }
        }
        "karyos_client_add_subscription_as" => {
            let arguments = Arguments::new(
                step,
                &[
                    "client",
                    "stream_id",
                    "uri",
                    "receiver_id",
                    "group_tag",
                    "rejoin",
                    "archive",
                ],
                at,
            );
            let uri = std::ffi::CString::new(
                arguments
                    .text("uri")
                    .unwrap_or_else(|| "karyos:udp?group=239.255.0.21:40001".to_owned()),
            )
            .unwrap_or_else(|_| panic!("{at}: `uri` holds a NUL"));
            let stream_id = arguments
                .integer("stream_id")
                .map(|_| arguments.narrow("stream_id", 0))
                .unwrap_or_else(|| panic!("{at}: `stream_id` is required"));
            let (status, mut options) = abi::subscription_options();
            assert_eq!(status, 0, "{at}: karyos_subscription_options_init");
            options.rejoin = arguments.narrow("rejoin", options.rejoin);
            options.archive = arguments
                .integer("archive")
                .map_or(options.archive, |_| arguments.handle("archive"));
            let (status, subscription) = abi::client_add_subscription_as(
                arguments.handle("client"),
                &uri,
                stream_id,
                &options,
                size_argument::<abi::SubscriptionOptions>(&arguments, "size"),
                (
                    arguments.narrow("receiver_id", 77),
                    arguments.narrow("group_tag", 0),
                ),
            );
            let mut results = BTreeMap::new();
            if status == 0 {
                results.insert(
                    "subscription".to_owned(),
                    Value::Integer(i128::from(subscription)),
                );
            }
            Returned {
                status: Some(status),
                results,
            }
        }
        "karyos_client_add_subscription_with" => {
            let arguments = Arguments::new(
                step,
                &[
                    "client",
                    "stream_id",
                    "uri",
                    "size",
                    "role",
                    "rejoin",
                    "reserved",
                    "archive",
                    "archive_client_id",
                    "replay_stream_id",
                    "secondary",
                ],
                at,
            );
            let uri = std::ffi::CString::new(
                arguments
                    .text("uri")
                    .unwrap_or_else(|| "karyos:ipc".to_owned()),
            )
            .unwrap_or_else(|_| panic!("{at}: `uri` holds a NUL"));
            let stream_id = arguments
                .integer("stream_id")
                .map(|_| arguments.narrow("stream_id", 0))
                .unwrap_or_else(|| panic!("{at}: `stream_id` is required"));
            let (status, mut options) = abi::subscription_options();
            assert_eq!(status, 0, "{at}: karyos_subscription_options_init");
            options.role = arguments.narrow("role", options.role);
            options.rejoin = arguments.narrow("rejoin", options.rejoin);
            options.reserved = arguments.narrow("reserved", options.reserved);
            options.archive = arguments
                .integer("archive")
                .map_or(options.archive, |_| arguments.handle("archive"));
            options.archive_client_id =
                arguments.narrow("archive_client_id", options.archive_client_id);
            options.replay_stream_id =
                arguments.narrow("replay_stream_id", options.replay_stream_id);
            options.secondary = arguments.narrow("secondary", options.secondary);
            let (status, subscription) = abi::client_add_subscription_with(
                arguments.handle("client"),
                &uri,
                stream_id,
                &options,
                size_argument::<abi::SubscriptionOptions>(&arguments, "size"),
            );
            if status == 0 {
                with_handle(status, "subscription", subscription)
            } else {
                Returned {
                    status: Some(status),
                    results: BTreeMap::new(),
                }
            }
        }
        "karyos_subscription_close" => Returned {
            status: Some(abi::subscription_close(handle_argument(
                step,
                "subscription",
                at,
            ))),
            results: BTreeMap::new(),
        },
        "karyos_publication_network_admission" => {
            let arguments = Arguments::new(step, &["publication", "admission"], at);
            let null = match step.arguments.get("admission") {
                None => false,
                Some(Value::Null) => true,
                Some(other) => panic!("{at}: `admission` takes only null, got {other:?}"),
            };
            let (status, admission) =
                abi::publication_network_admission(arguments.handle("publication"), null);
            let mut results = BTreeMap::new();
            if admission != u32::MAX {
                results.insert(
                    "admission".to_owned(),
                    Value::Integer(i128::from(admission)),
                );
            }
            Returned {
                status: Some(status),
                results,
            }
        }
        "karyos_publication_close" => Returned {
            status: Some(abi::publication_close(handle_argument(
                step,
                "publication",
                at,
            ))),
            results: BTreeMap::new(),
        },
        "karyos_driver_connect" => {
            let (status, client) = abi::driver_connect(handle_argument(step, "driver", at));
            with_handle(status, "client", client)
        }
        "karyos_driver_do_work" => {
            let (status, work) = abi::driver_do_work(handle_argument(step, "driver", at));
            with_count(status, "work", work)
        }
        "karyos_driver_subscribe_conflated" => {
            let arguments = Arguments::new(step, &["driver", "stream_id"], at);
            let stream_id = arguments
                .integer("stream_id")
                .map(|_| arguments.narrow("stream_id", 0))
                .unwrap_or_else(|| panic!("{at}: `stream_id` is required"));
            let (status, conflated) =
                abi::driver_subscribe_conflated(arguments.handle("driver"), stream_id);
            if status == 0 {
                with_handle(status, "conflated", conflated)
            } else {
                Returned {
                    status: Some(status),
                    results: BTreeMap::new(),
                }
            }
        }
        "karyos_conflated_poll" => {
            let arguments = Arguments::new(step, &["conflated", "key_budget"], at);
            let (status, delivered, counted) = abi::conflated_poll(
                arguments.handle("conflated"),
                arguments.narrow("key_budget", 1),
            );
            assert_eq!(delivered, counted, "{at}: the count is the handler's calls");
            with_count(status, "delivered", delivered)
        }
        "karyos_client_add_conflated_subscription" => {
            let arguments = Arguments::new(step, &["client", "stream_id", "uri"], at);
            let uri = std::ffi::CString::new(
                arguments
                    .text("uri")
                    .unwrap_or_else(|| "karyos:ipc".to_owned()),
            )
            .unwrap_or_else(|_| panic!("{at}: `uri` holds a NUL"));
            let stream_id = arguments
                .integer("stream_id")
                .map(|_| arguments.narrow("stream_id", 0))
                .unwrap_or_else(|| panic!("{at}: `stream_id` is required"));
            let (status, conflated) =
                abi::client_add_conflated_subscription(arguments.handle("client"), &uri, stream_id);
            if status == 0 {
                with_handle(status, "conflated", conflated)
            } else {
                Returned {
                    status: Some(status),
                    results: BTreeMap::new(),
                }
            }
        }
        "karyos_conflated_close" => Returned {
            status: Some(abi::conflated_close(handle_argument(step, "conflated", at))),
            results: BTreeMap::new(),
        },
        "karyos_archive_connect" => {
            let arguments = Arguments::new(
                step,
                &[
                    "client",
                    "requests",
                    "responses",
                    "client_id",
                    "reserved",
                    "deadline_ns",
                    "size",
                ],
                at,
            );
            let options = abi::ArchiveOptions {
                size: size_argument::<abi::ArchiveOptions>(&arguments, "size"),
                reserved: arguments.narrow("reserved", 0),
                requests: arguments.narrow("requests", 0),
                responses: arguments.narrow("responses", 0),
                client_id: arguments.narrow("client_id", 1),
                deadline_ns: arguments.narrow("deadline_ns", 0),
            };
            let (status, archive) = abi::archive_connect(arguments.handle("client"), &options);
            if status == 0 {
                with_handle(status, "archive", archive)
            } else {
                Returned {
                    status: Some(status),
                    results: BTreeMap::new(),
                }
            }
        }
        "karyos_archive_list" => {
            let arguments = Arguments::new(step, &["archive", "after_id", "limit"], at);
            let (status, delivered, counted) = abi::archive_list(
                arguments.handle("archive"),
                arguments.narrow("after_id", 0),
                arguments.narrow("limit", 1),
            );
            assert_eq!(delivered, counted, "{at}: the count is the handler's calls");
            with_count(status, "delivered", delivered)
        }
        "karyos_archive_close" => Returned {
            status: Some(abi::archive_close(handle_argument(step, "archive", at))),
            results: BTreeMap::new(),
        },
        "karyos_subscription_poll" => {
            let arguments = Arguments::new(step, &["subscription", "limit", "handler"], at);
            let on_message = match arguments.text("handler").as_deref() {
                None | Some("keep") => abi::OnMessage::Keep,
                Some("reenter") => abi::OnMessage::Reenter,
                Some(other) => panic!("{at}: `handler` is \"keep\" or \"reenter\", not {other:?}"),
            };
            let (status, delivered, messages, reentered) = abi::subscription_poll(
                arguments.handle("subscription"),
                arguments.narrow("limit", 1),
                on_message,
            );
            assert_eq!(
                usize::try_from(delivered).unwrap(),
                messages.len(),
                "{at}: the count is the handler's calls"
            );
            let mut returned = with_count(status, "delivered", delivered);
            if let Some(last) = messages.last() {
                let text = String::from_utf8(last.clone())
                    .unwrap_or_else(|_| panic!("{at}: a message that is not UTF-8"));
                returned
                    .results
                    .insert("last".to_owned(), Value::Text(text));
            }
            if let Some(code) = reentered {
                let name = statuses()
                    .into_iter()
                    .find_map(|(name, value)| (value == code).then_some(name))
                    .unwrap_or_else(|| panic!("{at}: status {code} is not in the header"));
                returned
                    .results
                    .insert("reentered".to_owned(), Value::Text(name));
            }
            returned
        }
        "karyos_publication_poll_outcomes" => {
            let arguments = Arguments::new(step, &["publication", "lane", "limit"], at);
            let (status, delivered, records) = abi::publication_poll_outcomes(
                arguments.handle("publication"),
                arguments.narrow("lane", 0),
                arguments.narrow("limit", 1),
            );
            assert_eq!(
                usize::try_from(delivered).unwrap(),
                records.len(),
                "{at}: the count is the handler's calls"
            );
            with_count(status, "delivered", delivered)
        }
        "karyos_driver_close" => Returned {
            status: Some(abi::driver_close(handle_argument(step, "driver", at))),
            results: BTreeMap::new(),
        },
        "karyos_client_poll" => {
            let (status, served) = abi::client_poll(handle_argument(step, "client", at));
            with_count(status, "served", served)
        }
        "karyos_client_close" => Returned {
            status: Some(abi::client_close(handle_argument(step, "client", at))),
            results: BTreeMap::new(),
        },
        other => panic!("{at}: this runner does not know `{other}`"),
    }
}

/// Whether a scenario for ABI `wanted` runs against a library of ABI
/// `library` (FORMAT.md, Versions): the same major, and then for 1.0 and
/// later a minor not newer than the library's, before 1.0 the same minor
/// (a `0.y` minor may break).
fn runs(wanted: (u32, u32), library: (u32, u32)) -> bool {
    match (wanted, library) {
        ((0, minor), (0, library_minor)) => minor == library_minor,
        ((major, minor), (library_major, library_minor)) => {
            major == library_major && minor <= library_minor
        }
    }
}

/// What a runner targets: the step of its binding's SPEC and the features
/// it offers (FORMAT.md, Reporting).
struct Runner {
    step: usize,
    offered: BTreeSet<&'static str>,
    absent: BTreeSet<&'static str>,
    /// What it provides for `archive-replay`, when it offers it.
    archive: Option<archive_host::Provided>,
    /// What it provides for `incompatible-driver`, when it offers it.
    incompatible: Option<incompatible_host::Provided>,
}

impl Runner {
    /// A runner at `step` that declares each feature of [`FEATURES`]
    /// either offered or absent: a feature in neither list, or in both,
    /// is a failure (ADR-0073: the coverage map tells applicable, missing
    /// and unsupported features apart).
    fn new(step: usize, offered: &[&'static str], absent: &[&'static str]) -> Self {
        let offered: BTreeSet<&'static str> = offered.iter().copied().collect();
        let absent: BTreeSet<&'static str> = absent.iter().copied().collect();
        assert!(
            offered.is_disjoint(&absent),
            "a feature both offered and absent"
        );
        let declared: BTreeSet<&str> = offered.union(&absent).copied().collect();
        assert_eq!(
            declared,
            BTreeSet::from(FEATURES),
            "every feature is declared offered or absent"
        );
        Self {
            step,
            offered,
            absent,
            archive: None,
            incompatible: None,
        }
    }

    /// The reference runner: every step, and every feature but a TAI clock
    /// where the library has none (Linux only).
    fn reference() -> Self {
        let absent: &[&'static str] = if cfg!(target_os = "linux") {
            &["archive-replay", "incompatible-driver", "remote-driver"]
        } else {
            &[
                "archive-replay",
                "incompatible-driver",
                "remote-driver",
                "tai-clock",
            ]
        };
        let offered: Vec<&'static str> = FEATURES
            .into_iter()
            .filter(|feature| !absent.contains(feature))
            .collect();
        Self::new(STEPS.len() - 1, &offered, absent)
    }

    /// The reference runner with what `archive-replay` needs, on Linux,
    /// where it provisions karyosd (FORMAT.md, Archive replays); as
    /// [`Runner::reference`] elsewhere.
    fn reference_with_archive() -> Self {
        let mut runner = Self::reference();
        // The stubs first: building one may take long, and the karyosd
        // client must not wait unserved meanwhile (karyos#820).
        if let Some(provided) = incompatible_host::provide() {
            runner.absent.remove("incompatible-driver");
            runner.offered.insert("incompatible-driver");
            runner.incompatible = Some(provided);
        }
        if let Some(provided) = archive_host::provide() {
            // The same karyosd serves both (FORMAT.md, Remote driver).
            for feature in ["archive-replay", "remote-driver"] {
                runner.absent.remove(feature);
                runner.offered.insert(feature);
            }
            runner.archive = Some(provided);
        }
        runner
    }

    /// Serves the karyosd client it provides, so that its heartbeat
    /// advances between the scenarios that use it (FORMAT.md, Remote
    /// driver; karyos#820): a client's heartbeat advances only when it is
    /// polled, and karyosd releases a client silent for its liveness
    /// timeout.
    fn serve_provided(&self) {
        if let Some(provided) = &self.archive {
            let _ = abi::client_poll(provided.client);
        }
    }

    /// The line a run prints after its pinning line (FORMAT.md,
    /// Reporting): its step and its declared features.
    fn declaration(&self) -> String {
        let list = |features: &BTreeSet<&str>| {
            if features.is_empty() {
                "none".to_owned()
            } else {
                features.iter().copied().collect::<Vec<_>>().join(" ")
            }
        };
        format!(
            "step {} offers {} absent {}",
            STEPS[self.step],
            list(&self.offered),
            list(&self.absent)
        )
    }
}

/// A scenario's outcome when it did not fail (a failure panics, naming the
/// file and line of the step).
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Passed,
    /// Its ABI version does not run against the library's.
    Skipped,
    /// It needs a feature the runner does not offer.
    Unsupported(String),
    /// Its `since` step is after the runner's.
    Later,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passed => f.write_str("passed"),
            Self::Skipped => f.write_str("skipped"),
            Self::Unsupported(feature) => write!(f, "unsupported {feature}"),
            Self::Later => f.write_str("later"),
        }
    }
}

fn run(
    scenario: &Scenario,
    statuses: &BTreeMap<String, i32>,
    library: (u32, u32),
    runner: &Runner,
) -> Outcome {
    let name = scenario.file.display();
    if !runs(scenario.abi, library) {
        return Outcome::Skipped;
    }
    if scenario.since.is_some_and(|since| since > runner.step) {
        return Outcome::Later;
    }
    if let Some(missing) = scenario
        .features
        .iter()
        .find(|feature| !runner.offered.contains(feature.as_str()))
    {
        // Only a feature the runner declared absent is unsupported.
        assert!(
            runner.absent.contains(missing.as_str()),
            "{name}: `{missing}` is neither offered nor declared absent"
        );
        return Outcome::Unsupported(missing.clone());
    }
    let mut adapter = semantic::Adapter::new(statuses);
    let mut variables: BTreeMap<String, Value> = BTreeMap::new();
    let semantic = scenario
        .steps
        .first()
        .is_some_and(|step| step.layer == Layer::Semantic);
    if semantic && !scenario.features.contains("embedded-driver") {
        variables.insert("driver".to_owned(), adapter.provided_driver());
    }
    if scenario.features.contains("remote-driver") {
        let provided = runner
            .archive
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: remote-driver offered with nothing provided"));
        variables.insert(
            "remote_client".to_owned(),
            adapter.provided_client(provided.client),
        );
        variables.insert(
            "loopback_uri".to_owned(),
            Value::Text(provided.loopback_uri.clone()),
        );
    }
    if scenario.features.contains("incompatible-driver") {
        let provided = runner
            .incompatible
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: incompatible-driver offered with nothing provided"));
        variables.insert(
            "refusing_dir".to_owned(),
            Value::Text(provided.refusing.clone()),
        );
        variables.insert(
            "other_version_dir".to_owned(),
            Value::Text(provided.other_version.clone()),
        );
    }
    if scenario.features.contains("archive-replay") {
        let provided = runner
            .archive
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: archive-replay offered with nothing provided"));
        variables.insert(
            "archive_client".to_owned(),
            adapter.provided_client(provided.client),
        );
        variables.insert(
            "recording".to_owned(),
            Value::Integer(i128::from(provided.recording)),
        );
        variables.insert(
            "recording_end".to_owned(),
            Value::Integer(i128::from(provided.end)),
        );
    }
    for step in &scenario.steps {
        let at = format!("{name}:{}", step.line);
        // A step takes its variables' values.
        let mut bound = step.clone();
        for argument in bound.arguments.values_mut() {
            if let Value::Variable(variable) = argument {
                *argument = variables
                    .get(variable.as_str())
                    .unwrap_or_else(|| panic!("{at}: `${variable}` is unbound"))
                    .clone();
            }
        }
        let results = match step.layer {
            Layer::Abi => check_status(step, call(&bound, &at), statuses, &at),
            Layer::Semantic => match adapter.op(&step.function, &bound.arguments, &at) {
                semantic::Answer::Ok(results) => {
                    assert_eq!(
                        step.status.as_deref(),
                        Some("ok"),
                        "{at}: `ok`, expected {:?}",
                        step.status
                    );
                    results
                }
                semantic::Answer::Status(got) => {
                    assert_eq!(
                        step.status.as_deref(),
                        Some(got.as_str()),
                        "{at}: status={got}"
                    );
                    BTreeMap::new()
                }
                semantic::Answer::StatusWith(got, results) => {
                    assert_eq!(
                        step.status.as_deref(),
                        Some(got.as_str()),
                        "{at}: status={got} {results:?}"
                    );
                    results
                }
            },
        };
        for (result, expected) in &step.results {
            let got = results
                .get(result)
                .unwrap_or_else(|| panic!("{at}: `{result}` was not written"));
            let (Expected::Equal(value) | Expected::AtLeast(value)) = expected;
            let wanted = match value {
                Value::Variable(variable) => match variables.get(variable) {
                    Some(bound) => bound.clone(),
                    None => {
                        assert!(
                            matches!(expected, Expected::Equal(_)),
                            "{at}: `{result}>=` takes a bound variable"
                        );
                        variables.insert(variable.clone(), got.clone());
                        continue;
                    }
                },
                literal => literal.clone(),
            };
            match expected {
                Expected::Equal(_) => assert_eq!(*got, wanted, "{at}: `{result}`"),
                Expected::AtLeast(_) => match (got, &wanted) {
                    (Value::Integer(got), Value::Integer(floor)) => {
                        assert!(got >= floor, "{at}: `{result}` {got} below {floor}");
                    }
                    other => panic!("{at}: `{result}>=` compares integers, got {other:?}"),
                },
            }
        }
    }
    adapter.close_all();
    Outcome::Passed
}

/// Checks an ABI-layer call's status against its `expect`; its results.
fn check_status(
    step: &Step,
    returned: Returned,
    statuses: &BTreeMap<String, i32>,
    at: &str,
) -> BTreeMap<String, Value> {
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
    returned.results
}

/// The suite's files, by their path under `conformance/`, sorted: the
/// format, the index and the scenarios (FORMAT.md, Pinning).
fn suite_files() -> Vec<(String, PathBuf)> {
    let base = root().join("conformance");
    let mut files = vec![
        ("FORMAT.md".to_owned(), base.join("FORMAT.md")),
        ("index.txt".to_owned(), base.join("index.txt")),
    ];
    for entry in std::fs::read_dir(base.join("scenarios")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        files.push((format!("scenarios/{name}"), path));
    }
    files.sort();
    files
}

/// The suite's identity: SHA-256 over each file in path order, as its
/// path, a NUL, its length as 8 bytes big-endian and its bytes.
fn suite_identity(files: &[(String, Vec<u8>)]) -> String {
    let mut hash = sha256::Sha256::new();
    for (path, bytes) in files {
        hash.update(path.as_bytes());
        hash.update(&[0]);
        hash.update(&u64::try_from(bytes.len()).unwrap().to_be_bytes());
        hash.update(bytes);
    }
    hash.hex()
}

/// The line a run starts with (FORMAT.md, Pinning).
fn pinning(library: [u32; 3]) -> String {
    let files: Vec<(String, Vec<u8>)> = suite_files()
        .into_iter()
        .map(|(path, file)| (path, std::fs::read(file).unwrap()))
        .collect();
    let header = std::fs::read(root().join("include/karyos.h")).unwrap();
    format!(
        "suite {} header {} core {}.{}.{} karyos-ffi {}",
        suite_identity(&files),
        sha256::hex(&header),
        library[0],
        library[1],
        library[2],
        env!("CARGO_PKG_VERSION"),
    )
}

fn scenarios() -> Vec<Scenario> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(root().join("conformance/scenarios"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert!(
        files.len() <= MAX_SCENARIOS,
        "over {MAX_SCENARIOS} scenarios"
    );
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
type Index = BTreeMap<String, Option<Vec<String>>>;

/// Parses `index.txt` (FORMAT.md, Index).
fn parse_index(text: &str) -> Result<Index, String> {
    let mut rows = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let at = number + 1;
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (row, covered) = line
            .split_once(':')
            .ok_or_else(|| format!("index.txt:{at}: no `:`"))?;
        let (row, covered) = (row.trim(), covered.trim());
        if row.is_empty() {
            return Err(format!("index.txt:{at}: empty row name"));
        }
        let ids = match covered.strip_prefix("pending") {
            Some(batch) if batch.starts_with(char::is_whitespace) && !batch.trim().is_empty() => {
                None
            }
            _ if covered.is_empty() => {
                return Err(format!("index.txt:{at}: no ids and not pending"));
            }
            _ => Some(covered.split_whitespace().map(str::to_owned).collect()),
        };
        if rows.insert(row.to_owned(), ids).is_some() {
            return Err(format!("index.txt:{at}: row `{row}` repeated"));
        }
    }
    Ok(rows)
}

/// The two-way check of the index against the scenarios' `(id, covers)`
/// (FORMAT.md, Index): ids are unique; every id a row lists exists and
/// covers exactly that row; every scenario is listed by its row.
fn check_index(scenarios: &[(String, String)], index: &Index) -> Result<(), String> {
    let mut covers = BTreeMap::new();
    for (id, row) in scenarios {
        if covers.insert(id.as_str(), row.as_str()).is_some() {
            return Err(format!("id {id} repeated"));
        }
    }
    for (row, covered) in index {
        for id in covered.iter().flatten() {
            match covers.get(id.as_str()) {
                None => return Err(format!("row `{row}` lists unknown scenario {id}")),
                Some(own) if own != row => {
                    return Err(format!("row `{row}` lists {id}, which covers `{own}`"));
                }
                Some(_) => {}
            }
        }
    }
    for (id, row) in scenarios {
        let listed = index
            .get(row)
            .ok_or_else(|| format!("{id} covers `{row}`, which index.txt has no row for"))?;
        if !listed.iter().flatten().any(|listed| listed == id) {
            return Err(format!("{id} covers `{row}`, whose row does not list it"));
        }
    }
    Ok(())
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the suite's files, which Miri's isolation forbids"
)]
#[allow(
    clippy::print_stdout,
    reason = "the run's report: its pinning line and each outcome (FORMAT.md, Reporting)"
)]
fn every_scenario_passes_at_the_library_abi_version() {
    let statuses = statuses();
    let (status, [major, minor, patch]) = abi::abi_version_with([false; 3]);
    assert_eq!(status, statuses["KARYOS_OK"]);
    let (major, minor, patch) = (major.unwrap(), minor.unwrap(), patch.unwrap());
    assert!(
        suite_runs_on([major, minor, patch]),
        "ABI {major}.{minor}.{patch} is outside this suite's (FORMAT.md, Versions)"
    );
    // The run's identities come first (FORMAT.md, Pinning).
    println!("{}", pinning([major, minor, patch]));
    let runner = Runner::reference_with_archive();
    println!("{}", runner.declaration());
    let scenarios = scenarios();
    assert!(!scenarios.is_empty());
    for scenario in &scenarios {
        runner.serve_provided();
        let outcome = run(scenario, &statuses, (major, minor), &runner);
        println!("{} {outcome}", scenario.id);
        // Every scenario targets this library's ABI and a step the
        // reference runner covers, so none may be skipped here; only a TAI
        // clock may be missing, off Linux.
        match outcome {
            Outcome::Passed => {}
            // Off Linux, the TAI clock and the Archive replays are absent.
            Outcome::Unsupported(feature)
                if [
                    "tai-clock",
                    "archive-replay",
                    "incompatible-driver",
                    "remote-driver",
                ]
                .contains(&feature.as_str())
                    && !cfg!(target_os = "linux") => {}
            other => panic!("{}: {other}", scenario.id),
        }
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the suite's files, which Miri's isolation forbids"
)]
fn the_index_maps_every_scenario_and_every_id_exists() {
    let scenarios: Vec<(String, String)> = scenarios()
        .into_iter()
        .map(|scenario| (scenario.id, scenario.covers))
        .collect();
    let text = std::fs::read_to_string(root().join("conformance/index.txt")).unwrap();
    let index = parse_index(&text).unwrap();
    check_index(&scenarios, &index).unwrap();
}

#[test]
fn the_index_check_refuses_a_map_that_lies() {
    let scenarios = [
        ("a".to_owned(), "row a".to_owned()),
        ("b".to_owned(), "row b".to_owned()),
    ];
    let check = |text: &str| parse_index(text).and_then(|index| check_index(&scenarios, &index));
    assert_eq!(check("row a: a\nrow b: b\nrow c: pending F4\n"), Ok(()));
    for lie in [
        // A row listing a scenario that covers another row (the probe of
        // the #469 review).
        "row a: a\nrow b: b\nrow c: a\n",
        "row a: a b\nrow b: b\n",
        // A scenario its row does not list, or with no row at all.
        "row a: a\nrow b: pending F4\n",
        "row a: a\n",
        // An unknown id, a repeated row, a row with nothing after `:`,
        // `pending` with no batch, a line without `:`.
        "row a: a z\nrow b: b\n",
        "row a: a\nrow a: a\nrow b: b\n",
        "row a: a\nrow b: b\nrow c:\n",
        "row a: a\nrow b: b\nrow c: pending\n",
        "row a: a\nrow b: b\nrow c\n",
    ] {
        assert!(check(lie).is_err(), "accepted:\n{lie}");
    }
    let repeated = [
        ("a".to_owned(), "row a".to_owned()),
        ("a".to_owned(), "row a".to_owned()),
    ];
    let index = parse_index("row a: a\n").unwrap();
    assert!(check_index(&repeated, &index).is_err());
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
        value(r#""a \"b\" \\""#, 1, at),
        Value::Text(r#"a "b" \"#.to_owned())
    );
    assert_eq!(value("-1", 1, at), Value::Integer(-1));
    assert_eq!(value("$x", 1, at), Value::Variable("x".to_owned()));
    assert_eq!(value("null", 1, at), Value::Null);
    // Tabs separate tokens like spaces.
    assert_eq!(tokens("call\tf  x=1\t", at), ["call", "f", "x=1"]);
    let statuses = statuses();
    let file = Path::new("test.kcs");
    let parse = |text: &str| parse_text(text, file, &statuses);
    // Blank and comment lines may come before `format`.
    assert_eq!(
        parse("\n  # a comment\n\nformat 1\nid a\nabi 0.1\ncovers \"r\"\ncall f\nexpect\n").id,
        "a"
    );
    for broken in [
        "id x\nformat 1\n",
        "format 3\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\ncall f\ncall g\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\nexpect KARYOS_OK\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\ncall f\n",
        "format 1\nid a\nabi zero\ncovers \"r\"\ncall f\nexpect\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\ncall f x=1 x=2\nexpect\n",
        "format 1\nid a\nabi 0.1\ncovers \"r\"\nbogus\n",
    ] {
        let parsed = std::panic::catch_unwind(|| parse(broken));
        assert!(parsed.is_err(), "accepted:\n{broken}");
    }
}

/// Format 2 (FORMAT.md): full 64-bit values, `since` and `feature`, one
/// layer per scenario, the op table and its outcomes, and the bounds.
#[test]
#[cfg_attr(
    miri,
    ignore = "reads the suite's files, which Miri's isolation forbids"
)]
fn format_2_is_parsed_strictly_and_within_its_bounds() {
    let at = "test";
    // Format 1 is signed only; format 2 carries every u64 and i64.
    assert_eq!(
        value("18446744073709551615", 2, at),
        Value::Integer(i128::from(u64::MAX))
    );
    assert_eq!(
        value("-9223372036854775808", 2, at),
        Value::Integer(i128::from(i64::MIN))
    );
    for (token, format) in [
        ("9223372036854775808", 1),
        ("18446744073709551616", 2),
        ("-9223372036854775809", 2),
    ] {
        assert!(
            std::panic::catch_unwind(|| value(token, format, at)).is_err(),
            "accepted {token} in format {format}"
        );
    }
    let statuses = statuses();
    let file = Path::new("test.kcs");
    let parse = |text: &str| parse_text(text, file, &statuses);
    let head = "format 2\nid a\nabi 0.1\ncovers \"r\"\nsince B1\n";
    let ok = parse(&format!(
        "{head}feature embedded-driver\nop driver.create\nexpect ok driver=$d\n\
         op clock.now domain=\"monotonic\"\nexpect ok now=$n\n\
         op clock.now domain=\"monotonic\"\nexpect ok now>=$n\n\
         op driver.close driver=$d\nexpect status=busy\n"
    ));
    assert_eq!((ok.format, ok.since), (2, Some(1)));
    // An Archive's refusal may check its code.
    let refused = parse(&format!(
        "{head}feature archive-replay\nop archive.stop_replay archive=$a replay=1\n\
         expect status=refused code=3\n"
    ));
    assert_eq!(
        refused.steps[0].results["code"],
        Expected::Equal(Value::Integer(3))
    );
    assert_eq!(
        ok.steps[2].results["now"],
        Expected::AtLeast(Value::Variable("n".to_owned()))
    );
    // The ABI layer of format 2: a handle past the signed range.
    let abi = parse(&format!(
        "{head}call karyos_publication_close publication=18446744073709551615\n\
         expect KARYOS_E_INVALID_HANDLE\n"
    ));
    assert_eq!(abi.steps[0].layer, Layer::Abi);
    let many_steps = format!(
        "{head}{}",
        "op library.version\nexpect ok\n".repeat(MAX_STEPS + 1)
    );
    let long_line = format!(
        "{head}# {}\nop library.version\nexpect ok\n",
        "x".repeat(MAX_LINE_BYTES)
    );
    let many_tokens = format!(
        "{head}op library.version {}\nexpect ok\n",
        "a=1 ".repeat(MAX_TOKENS)
    );
    let big_file = format!(
        "{head}op library.version\nexpect ok\n{}",
        "#\n".repeat(MAX_FILE_BYTES)
    );
    let many_variables: String = (0..=MAX_VARIABLES)
        .map(|n| format!("op clock.now domain=\"monotonic\"\nexpect ok now=$v{n}\n"))
        .collect();
    for (broken, why) in [
        // `since` is required in format 2 and not allowed in format 1.
        (
            "format 2\nid a\nabi 0.1\ncovers \"r\"\nop library.version\nexpect ok\n".to_owned(),
            "needs `since`",
        ),
        (
            "format 1\nid a\nabi 0.1\ncovers \"r\"\nsince B1\ncall f\nexpect\n".to_owned(),
            "`since` is format 2",
        ),
        // An unknown step, feature, op, argument, result or status.
        (
            "format 2\nid a\nabi 0.1\ncovers \"r\"\nsince B0b\nop library.version\nexpect ok\n"
                .to_owned(),
            "unknown step",
        ),
        (
            format!("{head}feature wings\nop library.version\nexpect ok\n"),
            "unknown feature",
        ),
        (format!("{head}op library.fly\nexpect ok\n"), "unknown op"),
        (
            format!("{head}op library.version speed=1\nexpect ok\n"),
            "takes no argument",
        ),
        (
            format!("{head}op library.version\nexpect ok build=1\n"),
            "has no result",
        ),
        (
            format!("{head}op library.version\nexpect status=on_fire\n"),
            "no status of the header",
        ),
        // `invalid_handle` is no op outcome; a status takes no results;
        // an op expects `ok` or `status=`.
        (
            format!("{head}op library.version\nexpect status=invalid_handle\n"),
            "is no op outcome",
        ),
        (
            format!("{head}op library.version\nexpect status=closed major=0\n"),
            "expects no results",
        ),
        (
            format!("{head}op library.version\nexpect KARYOS_OK\n"),
            "`ok` or `status=<name>`",
        ),
        // An op without the feature it needs, an object passed as a
        // literal, a required argument left out.
        (
            format!("{head}op driver.create\nexpect ok\n"),
            "needs `feature embedded-driver`",
        ),
        (
            format!("{head}op clock.now domain=\"tai\"\nexpect ok\n"),
            "needs `feature tai-clock`",
        ),
        (
            format!("{head}op clock.now domain=\"wall\"\nexpect ok\n"),
            "`domain` is one of",
        ),
        // Only an Archive's refusal carries a result, and only `code`.
        (
            format!(
                "{head}feature archive-replay\nop archive.close archive=$a\nexpect status=refused code=2\n"
            ),
            "expects no results",
        ),
        (
            format!(
                "{head}feature archive-replay\nop archive.stop_replay archive=$a replay=1\n\
                 expect status=refused reason=2\n"
            ),
            "expects no results",
        ),
        (
            format!(
                "{head}feature archive-replay\nop archive.replay archive=$a recording=1 \
                 target_stream_id=1 rate=\"fast\"\nexpect ok\n"
            ),
            "`rate` is one of",
        ),
        (
            format!("{head}op archive.close archive=$a\nexpect ok\n"),
            "needs `feature archive-replay`",
        ),
        (
            format!(
                "{head}feature embedded-driver\nop driver.create\nexpect ok driver=$d\n\
                 op driver.start driver=$d idle_strategy=\"nap\"\nexpect ok\n"
            ),
            "`idle_strategy` is one of",
        ),
        (
            format!("{head}op client.poll client=1\nexpect ok\n"),
            "passed as a variable",
        ),
        (
            format!("{head}feature claim-retry\nop publication.claim publication=$p\nexpect ok\n"),
            "needs `length`",
        ),
        // `call` and `op` in one scenario; `op` and `>=` in format 1; a
        // feature after a step.
        (
            format!(
                "{head}op library.version\nexpect ok\ncall karyos_abi_version\nexpect KARYOS_OK\n"
            ),
            "`call` and `op` in one scenario",
        ),
        (
            "format 1\nid a\nabi 0.1\ncovers \"r\"\nop library.version\nexpect ok\n".to_owned(),
            "`op` is format 2",
        ),
        (
            "format 1\nid a\nabi 0.1\ncovers \"r\"\ncall f\nexpect x>=1\n".to_owned(),
            "`>=` is format 2",
        ),
        (
            format!("{head}op library.version\nexpect ok\nfeature conflation\n"),
            "`feature` after a step",
        ),
        // The bounds.
        (many_steps, "steps"),
        (long_line, "bytes"),
        (many_tokens, "tokens"),
        (big_file, "bytes"),
        (format!("{head}{many_variables}"), "variables"),
    ] {
        let parsed = std::panic::catch_unwind(|| parse(&broken));
        let message = parsed.err().map(|panic| match panic.downcast::<String>() {
            Ok(message) => *message,
            Err(panic) => panic
                .downcast::<&str>()
                .map(|m| (*m).to_owned())
                .unwrap_or_default(),
        });
        assert!(
            message
                .as_deref()
                .is_some_and(|message| message.contains(why)),
            "{why}: got {message:?} for\n{}",
            &broken[..broken.len().min(300)]
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "reads the suite's files, which Miri's isolation forbids"
)]
fn a_scenario_is_skipped_unsupported_or_later_but_never_passed_by_default() {
    let statuses = statuses();
    let step = Step {
        line: 1,
        layer: Layer::Abi,
        function: "karyos_abi_version".to_owned(),
        arguments: BTreeMap::new(),
        status: Some("KARYOS_OK".to_owned()),
        results: BTreeMap::new(),
    };
    let scenario = |abi, since, feature: Option<&str>| Scenario {
        file: PathBuf::from("test.kcs"),
        format: 2,
        id: "test".to_owned(),
        abi,
        covers: "abi version".to_owned(),
        since,
        features: feature.into_iter().map(str::to_owned).collect(),
        steps: vec![step.clone()],
    };
    let reference = Runner::reference();
    let run =
        |scenario: &Scenario, library, runner: &Runner| run(scenario, &statuses, library, runner);
    assert_eq!(
        run(&scenario((0, 1), None, None), (0, 1), &reference),
        Outcome::Passed
    );
    // Before 1.0 a minor may break: only the same `0.y` runs.
    assert_eq!(
        run(&scenario((0, 1), None, None), (0, 2), &reference),
        Outcome::Skipped
    );
    assert_eq!(
        run(&scenario((0, 2), None, None), (0, 1), &reference),
        Outcome::Skipped
    );
    assert_eq!(
        run(&scenario((1, 0), None, None), (0, 1), &reference),
        Outcome::Skipped
    );
    // From 1.0 minors add: an older one runs, a newer one does not.
    assert!(runs((1, 2), (1, 3)));
    assert!(runs((1, 3), (1, 3)));
    assert!(!runs((1, 4), (1, 3)));
    assert!(!runs((2, 0), (1, 3)));
    // The suite as a whole needs 0.1.3 or a later 0.1.z (the readiness
    // calls, karyos#794).
    assert!(!suite_runs_on([0, 1, 0]));
    assert!(!suite_runs_on([0, 1, 2]));
    assert!(suite_runs_on([0, 1, 3]));
    assert!(suite_runs_on([0, 1, 7]));
    assert!(!suite_runs_on([0, 2, 0]));
    assert!(!suite_runs_on([0, 0, 9]));
    assert!(!suite_runs_on([1, 1, 0]));
    // A binding at step B1 that offers only an embedded driver.
    let b1 = Runner::new(
        1,
        &["embedded-driver"],
        &[
            "archive-replay",
            "claim-retry",
            "concurrent-publication",
            "conflation",
            "guarded-publication",
            "incompatible-driver",
            "remote-driver",
            "tai-clock",
        ],
    );
    assert_eq!(
        b1.declaration(),
        "step B1 offers embedded-driver absent archive-replay claim-retry concurrent-publication \
         conflation guarded-publication incompatible-driver remote-driver tai-clock"
    );
    assert_eq!(
        run(&scenario((0, 1), Some(3), None), (0, 1), &b1),
        Outcome::Later
    );
    assert_eq!(
        run(&scenario((0, 1), Some(1), Some("claim-retry")), (0, 1), &b1),
        Outcome::Unsupported("claim-retry".to_owned())
    );
    assert_eq!(
        run(&scenario((0, 1), Some(1), None), (0, 1), &b1),
        Outcome::Passed
    );
    // A feature neither offered nor declared absent, or both, is refused.
    let undeclared = std::panic::catch_unwind(|| Runner::new(1, &["embedded-driver"], &[]));
    assert!(undeclared.is_err());
    let both = std::panic::catch_unwind(|| Runner::new(1, &FEATURES, &["tai-clock"]));
    assert!(both.is_err());
    // A runner whose lists were edited past `new` cannot pass an
    // undeclared feature off as unsupported.
    let mut edited = Runner::reference();
    edited.offered.remove("claim-retry");
    let run_edited = std::panic::catch_unwind(|| {
        run(
            &scenario((0, 1), Some(1), Some("claim-retry")),
            (0, 1),
            &edited,
        )
    });
    assert!(run_edited.is_err());
}

/// The identities a run pins (FORMAT.md, Pinning): SHA-256 matches its
/// FIPS 180-4 vectors, and the suite's framing tells a path from content.
#[test]
fn the_pinned_identities_are_sha_256_over_a_framed_suite() {
    assert_eq!(
        sha256::hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256::hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256::hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // The multi-block vector, natively: it holds no unsafe, and a million
    // interpreted bytes would take Miri most of an hour.
    if !cfg!(miri) {
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256::hex(&million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
    let suite = |files: &[(&str, &str)]| {
        let files: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|(path, text)| ((*path).to_owned(), text.as_bytes().to_vec()))
            .collect();
        suite_identity(&files)
    };
    assert_ne!(suite(&[("a", "bc")]), suite(&[("ab", "c")]));
    assert_ne!(suite(&[("a", "b"), ("c", "")]), suite(&[("a", "b\0c")]));
}

/// The sized struct checks see what they claim to (FORMAT.md, Sized
/// structs): an output left alone reports nothing written and its tail
/// intact; a field written is reported, and a byte written past the
/// header's size changes the tail.
#[test]
fn the_sized_struct_checks_see_writes() {
    let mut accepted = abi::accepted(40);
    assert_eq!(abi::accepted_fields(&accepted), None);
    assert!(accepted.tail_intact());
    // The lane and the position, as a library writes them.
    for offset in 4..16 {
        accepted.poke(offset, 0);
    }
    assert_eq!(abi::accepted_fields(&accepted), Some((0, 0)));
    assert!(accepted.tail_intact());
    // One byte past the 0.1.0 struct.
    accepted.poke(size_of::<abi::Accepted>(), 0);
    assert!(!accepted.tail_intact());
}

/// What a runner offering `incompatible-driver` provides (FORMAT.md,
/// Incompatible driver): two `karyos-admission-stub`s, one refusing every
/// client's version and one admitting it at `VERSION + 1`, and their
/// admission directories. Linux only, as the admission socket is.
mod incompatible_host {
    /// The two directories; dropping it stops both stubs.
    pub(crate) struct Provided {
        pub(crate) refusing: String,
        pub(crate) other_version: String,
        #[cfg(target_os = "linux")]
        _stubs: [linux::Stub; 2],
    }

    /// The provisioning, or `None` where `incompatible-driver` is absent.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn provide() -> Option<Provided> {
        None
    }

    /// The provisioning; a stub that does not start fails the run.
    #[cfg(target_os = "linux")]
    pub(crate) fn provide() -> Option<Provided> {
        let root = std::env::temp_dir().join(format!(
            "karyos-conformance-incompatible-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        // Each stub creates its own private directory inside.
        std::fs::create_dir_all(&root).unwrap();
        let refusing = linux::Stub::start(&root, "refuse");
        let other_version = linux::Stub::start(&root, "version");
        Some(Provided {
            refusing: refusing.dir(),
            other_version: other_version.dir(),
            _stubs: [refusing, other_version],
        })
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use std::path::{Path, PathBuf};
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        /// A running stub: killed and waited for when dropped.
        pub(crate) struct Stub {
            child: Child,
            dir: PathBuf,
        }

        /// The stub binary: `KARYOS_ADMISSION_STUB`, else the one this
        /// workspace built beside the test, else built now with cargo in
        /// the test's own profile, with the `test-hooks` feature it needs.
        fn binary() -> PathBuf {
            if let Ok(path) = std::env::var("KARYOS_ADMISSION_STUB") {
                return PathBuf::from(path);
            }
            let exe = std::env::current_exe().unwrap();
            let profile = exe.parent().unwrap().parent().unwrap().to_path_buf();
            let built = profile.join("karyos-admission-stub");
            if !built.exists() {
                // Cargo names the dev profile's directory `debug`.
                let name = match profile.file_name().and_then(|name| name.to_str()) {
                    Some("debug") | None => "dev",
                    Some(name) => name,
                };
                let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
                let status = Command::new(cargo)
                    .args([
                        "build",
                        "--locked",
                        "-p",
                        "karyos-tools",
                        "--features",
                        "test-hooks",
                        "--bin",
                        "karyos-admission-stub",
                        "--profile",
                        name,
                    ])
                    .env("CARGO_TARGET_DIR", profile.parent().unwrap())
                    .status()
                    .unwrap();
                assert!(status.success(), "karyos-admission-stub did not build");
            }
            built
        }

        impl Stub {
            pub(crate) fn start(root: &Path, mode: &str) -> Self {
                let dir = root.join(mode);
                let child = Command::new(binary())
                    .arg("--dir")
                    .arg(&dir)
                    .args(["--mode", mode])
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap();
                // Listening once its socket exists.
                let start = Instant::now();
                while !dir.join(karyos_sys::ipc::SOCKET_NAME).exists() {
                    assert!(
                        start.elapsed() < Duration::from_secs(10),
                        "karyos-admission-stub --mode {mode} did not listen"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Self { child, dir }
            }

            pub(crate) fn dir(&self) -> String {
                self.dir.to_str().unwrap().to_owned()
            }
        }

        impl Drop for Stub {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

/// What a runner offering `archive-replay` provides (FORMAT.md, Archive
/// replays): karyosd with an Archive, a client of it, and a recording of
/// "r0" to "r9" on stream 20. Linux only: the client attaches to karyosd
/// in another process, which only Linux's remote client does.
mod archive_host {
    /// The provided client, the recording and its end; dropping it closes
    /// the client and stops karyosd.
    pub(crate) struct Provided {
        pub(crate) client: u64,
        pub(crate) recording: u64,
        pub(crate) end: u64,
        /// A free loopback endpoint for a network subscription and the
        /// publication that sends to it (FORMAT.md, Remote driver).
        pub(crate) loopback_uri: String,
        #[cfg(target_os = "linux")]
        _karyosd: linux::Karyosd,
    }

    #[cfg(target_os = "linux")]
    impl Drop for Provided {
        fn drop(&mut self) {
            let _ = super::abi::client_close(self.client);
        }
    }

    /// The provisioning, or `None` where `archive-replay` is absent.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn provide() -> Option<Provided> {
        None
    }

    /// The provisioning (FORMAT.md, Archive replays); a step that fails
    /// fails the run, with karyosd's output.
    #[cfg(target_os = "linux")]
    pub(crate) fn provide() -> Option<Provided> {
        provide_with("archive", None)
    }

    /// As [`provide`], under `name`, with karyosd's client liveness
    /// timeout set to `liveness` when given.
    #[cfg(target_os = "linux")]
    pub(crate) fn provide_with(name: &str, liveness: Option<&str>) -> Option<Provided> {
        let karyosd = linux::Karyosd::start_with(name, liveness);
        let (client, recording, end) = karyosd.seed();
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        Some(Provided {
            client,
            recording,
            end,
            loopback_uri: format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            _karyosd: karyosd,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) mod linux {
        use std::ffi::CString;
        use std::path::PathBuf;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        use super::super::abi;

        /// The recorded stream and the Archive's control streams
        /// (FORMAT.md, Archive replays). The replay target's stream, 1041,
        /// is not configured: each replay opens its own target there.
        const RECORDED: i32 = 20;
        /// The remote driver's conflated stream (FORMAT.md, Remote driver).
        const CONFLATED: i32 = 22;
        /// The remote driver's guarded stream.
        const GUARDED: i32 = 23;
        /// The remote driver's plain stream, neither conflated nor guarded.
        pub(crate) const PLAIN: i32 = 24;
        /// The remote driver's timed network stream (`--timed-network`).
        const TIMED: i32 = 25;
        /// The remote driver's plain stream of the timed scenario.
        pub(crate) const UNTIMED: i32 = 26;
        const REQUESTS: i32 = 1030;
        const RESPONSES: i32 = 1031;

        /// A karyosd of the runner's: stopped with SIGTERM, a bounded
        /// wait, then SIGKILL, when dropped.
        pub(crate) struct Karyosd {
            child: Child,
            root: PathBuf,
            log: PathBuf,
        }

        /// The karyosd binary: `KARYOS_KARYOSD`, else the one this
        /// workspace built beside the test, else built now with cargo
        /// (FORMAT.md's fallback) in the test's own profile, so that it
        /// lands beside the test under `--release` too.
        fn binary() -> PathBuf {
            if let Ok(path) = std::env::var("KARYOS_KARYOSD") {
                return PathBuf::from(path);
            }
            let exe = std::env::current_exe().unwrap();
            let profile = exe.parent().unwrap().parent().unwrap().to_path_buf();
            let built = profile.join("karyosd");
            if !built.exists() {
                // Cargo names the dev profile's directory `debug`.
                let name = match profile.file_name().and_then(|name| name.to_str()) {
                    Some("debug") | None => "dev",
                    Some(name) => name,
                };
                let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
                let status = Command::new(cargo)
                    .args([
                        "build",
                        "--locked",
                        "-p",
                        "karyos-tools",
                        "--bin",
                        "karyosd",
                        "--profile",
                        name,
                    ])
                    .env("CARGO_TARGET_DIR", profile.parent().unwrap())
                    .status()
                    .unwrap();
                assert!(status.success(), "karyosd did not build");
            }
            built
        }

        impl Karyosd {
            /// A karyosd under `name` in the temporary directory, whose
            /// clients time out after `liveness` of silence when given,
            /// else after karyosd's default.
            pub(crate) fn start_with(name: &str, liveness: Option<&str>) -> Self {
                let root = std::env::temp_dir()
                    .join(format!("karyos-conformance-{name}-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&root);
                let (dir, archive) = (root.join("driver"), root.join("archive"));
                std::fs::create_dir_all(&archive).unwrap();
                std::fs::create_dir_all(&dir).unwrap();
                // A private directory, as karyosd's admission requires.
                std::process::Command::new("chmod")
                    .args(["700", dir.to_str().unwrap()])
                    .status()
                    .unwrap();
                let log = root.join("karyosd.log");
                let out = std::fs::File::create(&log).unwrap();
                let child = Command::new(binary())
                    .arg("--dir")
                    .arg(&dir)
                    .args(
                        liveness
                            .map(|timeout| vec!["--client-liveness-timeout", timeout])
                            .unwrap_or_default(),
                    )
                    .args(["--stream", &format!("{RECORDED}:1")])
                    // The remote driver's streams (FORMAT.md, Remote driver):
                    // a conflated one and a guarded one.
                    .args(["--stream", &format!("{CONFLATED}:1")])
                    .args(["--conflation", &format!("{CONFLATED}:1:4:64:4k")])
                    .args(["--stream", &format!("{GUARDED}:1:allow-unconnected")])
                    .args(["--guard", &format!("orders:{GUARDED}:1:4")])
                    .args(["--stream", &format!("{PLAIN}:1:allow-unconnected")])
                    // The timed lane's (FORMAT.md, Remote driver): timed
                    // network publications on TIMED, a plain stream beside.
                    .args(["--network", "on"])
                    .args(["--timed-network", &format!("{TIMED}:4")])
                    .args(["--stream", &format!("{UNTIMED}:1:allow-unconnected")])
                    .arg("--archive")
                    .arg(&archive)
                    .args(["--archive-control", &format!("{REQUESTS},{RESPONSES}")])
                    .args(["--record", &format!("{RECORDED}:1")])
                    .stdout(Stdio::from(out.try_clone().unwrap()))
                    .stderr(Stdio::from(out))
                    .spawn()
                    .unwrap();
                Self { child, root, log }
            }

            fn fail(&self, what: &str) -> ! {
                let log = std::fs::read_to_string(&self.log).unwrap_or_default();
                panic!("archive-replay provisioning: {what}\nkaryosd:\n{log}");
            }

            /// Connects the client and records "r0" to "r9" on the
            /// recorded stream: the client, the recording's id and its
            /// end.
            pub(crate) fn seed(&self) -> (u64, u64, u64) {
                let deadline = Duration::from_secs(20);
                let dir = CString::new(self.root.join("driver").to_str().unwrap()).unwrap();
                let start = Instant::now();
                let client = loop {
                    let (status, client, _) = abi::client_connect(&dir);
                    if status == 0 {
                        break client;
                    }
                    if start.elapsed() > deadline {
                        self.fail(&format!("no client of karyosd (status {status})"));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                };
                let (status, publication, _) =
                    abi::client_add_publication(client, c"karyos:ipc", RECORDED, 24);
                if status != 0 {
                    self.fail(&format!("no publication on stream {RECORDED} ({status})"));
                }
                let options = abi::ArchiveOptions {
                    size: u32::try_from(size_of::<abi::ArchiveOptions>()).unwrap(),
                    reserved: 0,
                    requests: REQUESTS,
                    responses: RESPONSES,
                    client_id: 1,
                    deadline_ns: 10_000_000_000,
                };
                let (status, archive) = abi::archive_connect(client, &options);
                if status != 0 {
                    self.fail(&format!("no Archive connection ({status})"));
                }
                // The recording once it is past `last`, the start of the
                // last message offered, which, one frame, is then recorded
                // whole: its id and position.
                let recorded_past = |last: u64| {
                    let start = Instant::now();
                    loop {
                        let (status, recordings) = abi::archive_recordings(archive, 0, 16);
                        if let Some(&(id, position)) = recordings.first()
                            && status == 0
                            && position > last
                        {
                            break (id, position);
                        }
                        if start.elapsed() > deadline {
                            self.fail(&format!("not recorded past {last}: {recordings:?}"));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                };
                let mut last = 0;
                for index in 0..10u8 {
                    // The second half only once the first is recorded, and
                    // 50 ms later. A recorder duty stamps one record time on
                    // everything it copies and ends at an empty source, so
                    // the first half's stamps are then taken, and the second
                    // half's are at least 50 ms later: a replay at a
                    // millionth of the recorded pace holds it
                    // (op.replay.stopped).
                    if index == 5 {
                        let _ = recorded_past(last);
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    let message = format!("r{index}");
                    let start = Instant::now();
                    last = loop {
                        let (status, accepted) =
                            abi::publication_offer_on(publication, 0, message.as_bytes(), 16);
                        if status == 0 {
                            break abi::accepted_fields(&accepted).unwrap().1;
                        }
                        if start.elapsed() > deadline {
                            self.fail(&format!("{message} not offered ({status})"));
                        }
                        let _ = abi::client_poll(client);
                        std::thread::sleep(Duration::from_millis(1));
                    };
                }
                let _ = abi::publication_close(publication);
                let (recording, end) = recorded_past(last);
                let _ = abi::archive_close(archive);
                (client, recording, end)
            }
        }

        impl Drop for Karyosd {
            fn drop(&mut self) {
                let _ = Command::new("kill")
                    .args(["-TERM", &self.child.id().to_string()])
                    .status();
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(10) {
                    if matches!(self.child.try_wait(), Ok(Some(_))) {
                        let _ = std::fs::remove_dir_all(&self.root);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                let _ = self.child.kill();
                let _ = self.child.wait();
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }
    }
}

/// karyos#820: a karyosd client's heartbeat advances only when it is
/// polled, and karyosd releases a client silent for its liveness timeout.
/// The runner serves its client before every scenario
/// (`Runner::serve_provided`), so scenarios that do not use it, as long as
/// twice the timeout in all, leave it usable; left unserved as long, it is
/// released and its next call answers `closed`, as `op.remote.conflated`
/// did after a slow provisioning. Without `serve_provided` the first half
/// fails. A 2 s timeout keeps the test short.
#[cfg(target_os = "linux")]
#[test]
fn the_runner_keeps_its_karyosd_client_served_between_scenarios() {
    use std::time::{Duration, Instant};
    let closed = statuses()["KARYOS_E_CLOSED"];
    let mut runner = Runner::reference();
    runner.archive = archive_host::provide_with("liveness", Some("2s"));
    let client = runner.archive.as_ref().unwrap().client;
    let gap = Duration::from_secs(4);
    let start = Instant::now();
    while start.elapsed() < gap {
        runner.serve_provided();
        // A scenario that does not use the client.
        std::thread::sleep(Duration::from_millis(500));
    }
    let (status, publication, _) =
        abi::client_add_publication(client, c"karyos:ipc", archive_host::linux::PLAIN, 24);
    assert_eq!(
        status, 0,
        "served between scenarios for {gap:?}, yet released"
    );
    let _ = abi::publication_close(publication);
    std::thread::sleep(gap);
    let (status, _, _) =
        abi::client_add_publication(client, c"karyos:ipc", archive_host::linux::UNTIMED, 24);
    assert_eq!(status, closed, "unserved for {gap:?}, yet kept");
}
