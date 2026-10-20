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

use std::collections::BTreeMap;
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

/// The handle argument `name`, the step's only one.
fn handle_argument(step: &Step, name: &str, at: &str) -> u64 {
    let value = integer_argument(step, name, at);
    u64::try_from(value).unwrap_or_else(|_| panic!("{at}: `{name}` is not a uint64_t"))
}

/// A handle as a scenario value.
fn handle_value(handle: u64, at: &str) -> Value {
    Value::Integer(
        i64::try_from(handle).unwrap_or_else(|_| panic!("{at}: a handle beyond 64-bit signed")),
    )
}

/// What a function that writes one handle returned.
fn with_handle(status: i32, name: &str, handle: u64, at: &str) -> Returned {
    Returned {
        status: Some(status),
        results: BTreeMap::from([(name.to_owned(), handle_value(handle, at))]),
    }
}

/// What a function that writes one count returned.
fn with_count(status: i32, name: &str, count: u32) -> Returned {
    Returned {
        status: Some(status),
        results: BTreeMap::from([(name.to_owned(), Value::Integer(i64::from(count)))]),
    }
}

fn integer_argument(step: &Step, name: &str, at: &str) -> i64 {
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

    fn integer(&self, name: &str) -> Option<i64> {
        match self.step.arguments.get(name) {
            None => None,
            Some(Value::Integer(value)) => Some(*value),
            Some(other) => panic!("{}: `{name}` must be an integer, got {other:?}", self.at),
        }
    }

    /// An integer argument that fits `T`, or `default`.
    fn narrow<T: TryFrom<i64>>(&self, name: &str, default: T) -> T {
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
        results.insert("lane".to_owned(), Value::Integer(i64::from(lane)));
        results.insert(
            "position".to_owned(),
            Value::Integer(i64::try_from(position).unwrap()),
        );
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
        "karyos_driver_create" => {
            let arguments = Arguments::new(step, &["size", "reserved"], at);
            let (status, mut options) = abi::driver_options();
            assert_eq!(status, 0, "{at}: karyos_driver_options_init");
            options.reserved = arguments.narrow("reserved", options.reserved);
            let size = size_argument::<abi::DriverOptions>(&arguments, "size");
            let (status, driver) = abi::driver_create_sized(&options, size);
            with_handle(status, "driver", driver, at)
        }
        "karyos_driver_start" => {
            let arguments = Arguments::new(step, &["driver", "idle_strategy", "idle_sleep_ns"], at);
            Returned {
                status: Some(abi::driver_start(
                    arguments.handle("driver"),
                    arguments.narrow("idle_strategy", 1),
                    arguments.narrow("idle_sleep_ns", 0),
                )),
                results: BTreeMap::new(),
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
        "karyos_client_add_publication" => {
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
            let (status, publication, detail) = abi::client_add_publication(
                arguments.handle("client"),
                &uri,
                stream_id,
                size_argument::<abi::Detail>(&arguments, "detail_size"),
            );
            let mut results =
                BTreeMap::from([("detail_tail".to_owned(), tail(detail.tail_intact()))]);
            if status == 0 {
                results.insert("publication".to_owned(), handle_value(publication, at));
            }
            let written = abi::detail_fields(&detail);
            results.insert(
                "detail_written".to_owned(),
                Value::Integer(i64::from(written.is_some())),
            );
            if let Some((code, value)) = written {
                results.insert(
                    "code".to_owned(),
                    Value::Integer(i64::try_from(code).unwrap()),
                );
                results.insert(
                    "value".to_owned(),
                    Value::Integer(i64::try_from(value).unwrap()),
                );
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
                .map(|now| {
                    let now = i64::try_from(now)
                        .unwrap_or_else(|_| panic!("{at}: `now` does not fit an integer"));
                    BTreeMap::from([("now".to_owned(), Value::Integer(now))])
                })
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
                with_handle(status, "claim", claim, at)
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
            let (status, subscription) = abi::client_add_subscription_with(
                arguments.handle("client"),
                &uri,
                stream_id,
                &options,
                size_argument::<abi::SubscriptionOptions>(&arguments, "size"),
            );
            if status == 0 {
                with_handle(status, "subscription", subscription, at)
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
            with_handle(status, "client", client, at)
        }
        "karyos_driver_do_work" => {
            let (status, work) = abi::driver_do_work(handle_argument(step, "driver", at));
            with_count(status, "work", work)
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

/// Runs a scenario; `false` when it was skipped for its ABI version.
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

fn run(scenario: &Scenario, statuses: &BTreeMap<String, i32>, library: (u32, u32)) -> bool {
    let name = scenario.file.display();
    if !runs(scenario.abi, library) {
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
        // A call takes its variables' values.
        let mut bound = step.clone();
        for argument in bound.arguments.values_mut() {
            if let Value::Variable(variable) = argument {
                *argument = variables[variable.as_str()].clone();
            }
        }
        let returned = call(&bound, &at);
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
        value(r#""a \"b\" \\""#, at),
        Value::Text(r#"a "b" \"#.to_owned())
    );
    assert_eq!(value("-1", at), Value::Integer(-1));
    assert_eq!(value("$x", at), Value::Variable("x".to_owned()));
    assert_eq!(value("null", at), Value::Null);
    // Tabs separate tokens like spaces.
    assert_eq!(tokens("call\tf  x=1\t", at), ["call", "f", "x=1"]);
    // Blank and comment lines may come before `format`.
    let dir = std::env::temp_dir().join(format!("karyos-ffi-kcs-ok-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("ok.kcs");
    std::fs::write(
        &file,
        "\n  # a comment\n\nformat 1\nid a\nabi 0.1\ncovers \"r\"\ncall f\nexpect\n",
    )
    .unwrap();
    assert_eq!(parse(&file).id, "a");
    let _ = std::fs::remove_dir_all(&dir);
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
fn a_scenario_of_another_abi_version_is_skipped() {
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
    // Before 1.0 a minor may break: only the same `0.y` runs.
    assert!(!run(&scenario((0, 1)), &statuses, (0, 2)));
    assert!(!run(&scenario((0, 2)), &statuses, (0, 1)));
    assert!(!run(&scenario((1, 0)), &statuses, (0, 1)));
    // From 1.0 minors add: an older one runs, a newer one does not.
    assert!(runs((1, 2), (1, 3)));
    assert!(runs((1, 3), (1, 3)));
    assert!(!runs((1, 4), (1, 3)));
    assert!(!runs((2, 0), (1, 3)));
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
