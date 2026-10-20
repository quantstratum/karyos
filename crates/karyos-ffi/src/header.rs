// SPDX-License-Identifier: Apache-2.0

//! The check of the hand-written `include/karyos.h` against the Rust
//! source (quantstratum-docs: karyos/design/ffi-gap-analysis.md §4.6),
//! until `cbindgen` generates the header: the same exported functions with
//! the same C types, the same status codes and the same ABI version.
//!
//! It reads both files as text and covers the constructs the ABI uses: one
//! `#define NAME VALUE` per constant, `typedef struct` declarations with one
//! field per statement, `typedef void (*name)(...)` callback types matched
//! with the `pub type Name = Option<unsafe extern "C" fn(...)>` aliases of
//! `abi.rs`, prototypes whose function pointer parameters use such a
//! typedef, and the `extern "C" fn` items and `pub struct` items of
//! `abi.rs` whose types the tables in [`c_type`] and [`c_struct`] know.
//! Anything else fails the test.

use std::collections::BTreeMap;

use crate::abi::{ABI_VERSION_MAJOR, ABI_VERSION_MINOR, ABI_VERSION_PATCH};
use crate::status::Status;

const HEADER: &str = include_str!("../include/karyos.h");
const ABI: &str = include_str!("abi.rs");

/// A function's C return type and parameter types.
type Signature = (String, Vec<String>);

/// A struct's fields: names and C types, in order.
type Fields = Vec<(String, String)>;

/// The C name of a struct of `abi.rs`.
fn c_struct(rust: &str) -> &'static str {
    match rust {
        "ClientOptions" => "karyos_client_options",
        "Detail" => "karyos_detail",
        "Accepted" => "karyos_accepted",
        "DriverOptions" => "karyos_driver_options",
        "StreamOptions" => "karyos_stream_options",
        "MessageInfo" => "karyos_message_info",
        "ImageChange" => "karyos_image_change",
        "Outcome" => "karyos_outcome",
        other => panic!("no C struct for the Rust struct `{other}`; extend the table"),
    }
}

/// The C type of a Rust type the boundary uses.
fn c_type(rust: &str) -> String {
    let c = match rust.trim() {
        "i32" => "int32_t",
        "u32" => "uint32_t",
        "u64" => "uint64_t",
        "usize" => "size_t",
        "*mut u32" => "uint32_t *",
        "*mut u64" => "uint64_t *",
        "*const u8" => "const uint8_t *",
        "*const c_char" => "const char *",
        "*const ClientOptions" => "const karyos_client_options *",
        "*mut ClientOptions" => "karyos_client_options *",
        "*mut Detail" => "karyos_detail *",
        "*mut Accepted" => "karyos_accepted *",
        "*mut *mut u8" => "uint8_t **",
        "*const DriverOptions" => "const karyos_driver_options *",
        "*mut DriverOptions" => "karyos_driver_options *",
        "*const StreamOptions" => "const karyos_stream_options *",
        "*mut StreamOptions" => "karyos_stream_options *",
        "i64" => "int64_t",
        "*mut c_void" => "void *",
        "*const MessageInfo" => "const karyos_message_info *",
        "*mut ImageChange" => "karyos_image_change *",
        "MessageHandler" => "karyos_message_handler",
        "*const Outcome" => "const karyos_outcome *",
        "OutcomeHandler" => "karyos_outcome_handler",
        other => panic!("no C type for the Rust type `{other}`; extend the table"),
    };
    c.to_owned()
}

/// A C type with one space before each `*` and single spaces elsewhere.
fn normalize(c: &str) -> String {
    c.replace('*', " * ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The header without comments.
fn header_code() -> String {
    let mut code = String::new();
    let mut rest = HEADER;
    while let Some(start) = rest.find("/*") {
        code.push_str(&rest[..start]);
        let end = rest[start..].find("*/").expect("an unterminated comment");
        rest = &rest[start + end + 2..];
    }
    code.push_str(rest);
    code
}

/// The header's `#define`s of `KARYOS_` names.
fn header_defines() -> BTreeMap<String, i64> {
    header_code()
        .lines()
        .filter_map(|line| line.trim().strip_prefix("#define "))
        .filter_map(|define| {
            let mut parts = define.split_whitespace();
            let name = parts.next()?;
            let value = parts.next()?;
            assert!(parts.next().is_none(), "`{define}` is not NAME VALUE");
            name.starts_with("KARYOS_").then(|| {
                let value = value.parse().unwrap_or_else(|_| panic!("`{define}`"));
                (name.to_owned(), value)
            })
        })
        .collect()
}

/// The header's code without comments and without its struct
/// declarations, and the structs it declares.
fn header_structs() -> (String, BTreeMap<String, Fields>) {
    let mut code = header_code();
    let mut structs = BTreeMap::new();
    while let Some(start) = code.find("typedef struct ") {
        let open = start + code[start..].find('{').expect("a struct body");
        let close = open + code[open..].find('}').expect("a struct body");
        let end = close + code[close..].find(';').expect("a typedef name");
        let name = code[close + 1..end].trim().to_owned();
        assert_eq!(
            code[start + "typedef struct ".len()..open].trim(),
            name,
            "the struct tag and the typedef name differ"
        );
        let fields = code[open + 1..close]
            .split(';')
            .map(str::trim)
            .filter(|field| !field.is_empty())
            .map(|field| {
                let (c, name) = split_name(field);
                (name, c)
            })
            .collect();
        structs.insert(name, fields);
        code.replace_range(start..=end, "");
    }
    (code, structs)
}

/// The `pub struct` items of `abi.rs`, with their C names and types.
fn rust_structs() -> BTreeMap<String, Fields> {
    let mut structs = BTreeMap::new();
    let mut rest = ABI;
    while let Some(at) = rest.find("\npub struct ") {
        rest = &rest[at + "\npub struct ".len()..];
        let open = rest.find('{').expect("a struct body");
        let close = rest.find("\n}").expect("a struct body");
        let name = c_struct(rest[..open].trim()).to_owned();
        let fields = rest[open + 1..close]
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix("pub "))
            .map(|field| {
                let (name, rust) = field
                    .trim_end_matches(',')
                    .split_once(':')
                    .expect("name: type");
                (name.trim().to_owned(), normalize(&c_type(rust)))
            })
            .collect();
        structs.insert(name, fields);
    }
    structs
}

/// The prefix of a callback type's typedef.
const HANDLER_TYPEDEF: &str = "typedef void (*";

/// The header's code without comments, structs and callback typedefs, and
/// the callback types it declares: each name with its parameter types.
fn header_handlers() -> (String, BTreeMap<String, Vec<String>>) {
    let mut code = header_structs().0;
    let mut handlers = BTreeMap::new();
    while let Some(start) = code.find(HANDLER_TYPEDEF) {
        let end = start + code[start..].find(';').expect("a typedef's end");
        let typedef = code[start + HANDLER_TYPEDEF.len()..end].to_owned();
        let (name, rest) = typedef.split_once(')').expect("the typedef's name");
        let parameters = rest
            .trim()
            .strip_prefix('(')
            .and_then(|rest| rest.strip_suffix(')'))
            .expect("the typedef's parameters")
            .split(',')
            .map(|parameter| split_name(parameter).0)
            .collect();
        handlers.insert(name.trim().to_owned(), parameters);
        code.replace_range(start..=end, "");
    }
    (code, handlers)
}

/// The `pub type` callback aliases of `abi.rs`: each C name with its
/// parameter types.
fn rust_handlers() -> BTreeMap<String, Vec<String>> {
    let mut handlers = BTreeMap::new();
    let mut rest = ABI;
    while let Some(at) = rest.find("\npub type ") {
        rest = &rest[at + "\npub type ".len()..];
        let end = rest.find(';').expect("an alias's end");
        let alias = rest[..end].split_whitespace().collect::<Vec<_>>().join(" ");
        let (name, target) = alias.split_once('=').expect("name = type");
        let parameters = target
            .trim()
            .strip_prefix("Option<unsafe extern \"C\" fn(")
            .and_then(|target| target.strip_suffix(")>"))
            .expect("a callback alias: Option<unsafe extern \"C\" fn(...)>")
            .split(',')
            .map(|parameter| normalize(&c_type(parameter)))
            .collect();
        handlers.insert(c_type(name), parameters);
    }
    handlers
}

/// The header's prototypes.
fn header_functions() -> BTreeMap<String, Signature> {
    let code: String = header_handlers()
        .0
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && *line != "extern \"C\" {" && *line != "}")
        .collect::<Vec<_>>()
        .join(" ");
    code.split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(|prototype| {
            let open = prototype.find('(').expect("a prototype");
            let close = prototype.rfind(')').expect("a prototype");
            let (head, name) = split_name(&prototype[..open]);
            let parameters = prototype[open + 1..close]
                .split(',')
                .map(|parameter| split_name(parameter).0)
                .collect();
            (name, (head, parameters))
        })
        .collect()
}

/// A declaration split into its normalized type and its trailing name.
fn split_name(declaration: &str) -> (String, String) {
    let declaration = declaration.trim();
    let at = declaration
        .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
        .map_or(0, |at| at + 1);
    (normalize(&declaration[..at]), declaration[at..].to_owned())
}

/// The `extern "C" fn` items of `abi.rs`, with their C types.
fn rust_functions() -> BTreeMap<String, Signature> {
    let mut functions = BTreeMap::new();
    let mut rest = ABI;
    while let Some(at) = rest.find("extern \"C\" fn ") {
        rest = &rest[at + "extern \"C\" fn ".len()..];
        let open = rest.find('(').expect("a parameter list");
        let close = rest.find(')').expect("a parameter list");
        let name = rest[..open].trim().to_owned();
        let parameters = rest[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|parameter| !parameter.is_empty())
            .map(|parameter| {
                let (_, rust) = parameter.split_once(':').expect("name: type");
                normalize(&c_type(rust))
            })
            .collect();
        let body = rest[close..].find('{').expect("a body");
        let returns = rest[close + 1..close + body]
            .trim()
            .strip_prefix("->")
            .map_or_else(|| "void".to_owned(), |rust| normalize(&c_type(rust)));
        functions.insert(name, (returns, parameters));
    }
    functions
}

#[test]
fn the_header_declares_every_exported_function_with_its_types() {
    let rust = rust_functions();
    assert!(rust.contains_key("karyos_abi_version"));
    assert_eq!(header_functions(), rust);
}

#[test]
fn the_header_declares_every_callback_type_with_its_parameters() {
    let rust = rust_handlers();
    assert!(rust.contains_key("karyos_message_handler"));
    assert_eq!(header_handlers().1, rust);
}

#[test]
fn the_header_declares_every_struct_with_its_fields() {
    let rust = rust_structs();
    assert!(rust.contains_key("karyos_detail"));
    assert_eq!(header_structs().1, rust);
}

#[test]
fn the_header_states_every_status_code() {
    let defines = header_defines();
    let statuses: BTreeMap<String, i64> = Status::ALL
        .iter()
        .map(|status| (status.name().to_owned(), i64::from(status.code())))
        .collect();
    let in_header: BTreeMap<String, i64> = defines
        .iter()
        .filter(|(name, _)| name.as_str() == "KARYOS_OK" || name.starts_with("KARYOS_E_"))
        .map(|(name, value)| (name.clone(), *value))
        .collect();
    assert_eq!(in_header, statuses);
}

#[test]
fn the_header_states_the_abi_version() {
    let defines = header_defines();
    assert_eq!(
        defines["KARYOS_ABI_VERSION_MAJOR"],
        i64::from(ABI_VERSION_MAJOR)
    );
    assert_eq!(
        defines["KARYOS_ABI_VERSION_MINOR"],
        i64::from(ABI_VERSION_MINOR)
    );
    assert_eq!(
        defines["KARYOS_ABI_VERSION_PATCH"],
        i64::from(ABI_VERSION_PATCH)
    );
    assert_eq!(defines["KARYOS_NULL_HANDLE"], 0);
    let version =
        format!("ABI version {ABI_VERSION_MAJOR}.{ABI_VERSION_MINOR}.{ABI_VERSION_PATCH}");
    assert!(
        HEADER.contains(&version),
        "the header's comment names {version}"
    );
}

#[test]
fn the_parsers_read_what_they_are_given() {
    assert_eq!(normalize("const  char*"), "const char *");
    assert_eq!(normalize("uint32_t *"), "uint32_t *");
    assert_eq!(
        split_name(" uint32_t *major"),
        ("uint32_t *".to_owned(), "major".to_owned())
    );
}

#[test]
fn the_header_states_the_client_constants() {
    use crate::api::client;
    let defines = header_defines();
    assert_eq!(
        defines["KARYOS_MAX_CLIENTS"],
        i64::from(client::MAX_CLIENTS)
    );
    assert_eq!(
        defines["KARYOS_IDLE_BUSY_SPIN"],
        i64::from(client::IDLE_BUSY_SPIN)
    );
    assert_eq!(defines["KARYOS_IDLE_YIELD"], i64::from(client::IDLE_YIELD));
    assert_eq!(defines["KARYOS_IDLE_SLEEP"], i64::from(client::IDLE_SLEEP));
}

#[test]
fn the_header_states_the_publication_constants() {
    use crate::api::publication;
    let defines = header_defines();
    assert_eq!(
        defines["KARYOS_MAX_PUBLICATIONS"],
        i64::from(publication::MAX_PUBLICATIONS)
    );
    assert_eq!(
        defines["KARYOS_MAX_CLAIMS"],
        i64::from(publication::MAX_CLAIMS)
    );
}

#[test]
fn the_header_states_the_driver_constants() {
    use crate::api::driver;
    let defines = header_defines();
    assert_eq!(
        defines["KARYOS_MAX_DRIVERS"],
        i64::from(driver::MAX_DRIVERS)
    );
    assert_eq!(
        defines["KARYOS_PROTOCOL_VERSION"],
        i64::try_from(driver::PROTOCOL_VERSION).unwrap()
    );
    assert_eq!(
        defines["KARYOS_PUBLICATION_EXCLUSIVE"],
        i64::from(driver::PUBLICATION_EXCLUSIVE)
    );
    assert_eq!(defines["KARYOS_LOSS_HOLD"], i64::from(driver::LOSS_HOLD));
    assert_eq!(
        defines["KARYOS_LOSS_CONTINUE"],
        i64::from(driver::LOSS_CONTINUE)
    );
    assert_eq!(defines["KARYOS_LOSS_ABORT"], i64::from(driver::LOSS_ABORT));
}

/// The clock domains match the client's codes (`ClockDomain::code`).
#[test]
fn the_header_states_the_clock_domains() {
    use karyos_client::schedule::ClockDomain;

    use crate::abi::{CLOCK_MONOTONIC, CLOCK_TAI};
    let defines = header_defines();
    assert_eq!(
        defines["KARYOS_CLOCK_MONOTONIC"],
        i64::from(CLOCK_MONOTONIC)
    );
    assert_eq!(defines["KARYOS_CLOCK_TAI"], i64::from(CLOCK_TAI));
    assert_eq!(u64::from(CLOCK_MONOTONIC), ClockDomain::Monotonic.code());
    assert_eq!(u64::from(CLOCK_TAI), ClockDomain::Tai.code());
}

#[test]
fn the_header_states_the_subscription_constants() {
    use crate::abi::{MESSAGE_END_OF_STREAM, MESSAGE_TRACED};
    use crate::api::subscription;
    let defines = header_defines();
    assert_eq!(
        defines["KARYOS_MAX_SUBSCRIPTIONS"],
        i64::from(subscription::MAX_SUBSCRIPTIONS)
    );
    assert_eq!(
        defines["KARYOS_MESSAGE_END_OF_STREAM"],
        i64::from(MESSAGE_END_OF_STREAM)
    );
    assert_eq!(defines["KARYOS_MESSAGE_TRACED"], i64::from(MESSAGE_TRACED));
}

#[test]
fn the_header_states_the_outcome_kinds() {
    use crate::abi::{
        OUTCOME_ABORTED, OUTCOME_CONFIRMED_CANCELLED, OUTCOME_ENDED, OUTCOME_INTERRUPTED,
        OUTCOME_OUTCOMES_LOST, OUTCOME_RANGE, OUTCOME_REJECTED, OUTCOME_SUBMITTED, OUTCOME_UNKNOWN,
    };
    let defines = header_defines();
    for (name, value) in [
        ("SUBMITTED", OUTCOME_SUBMITTED),
        ("CONFIRMED_CANCELLED", OUTCOME_CONFIRMED_CANCELLED),
        ("UNKNOWN", OUTCOME_UNKNOWN),
        ("REJECTED", OUTCOME_REJECTED),
        ("ABORTED", OUTCOME_ABORTED),
        ("RANGE", OUTCOME_RANGE),
        ("INTERRUPTED", OUTCOME_INTERRUPTED),
        ("ENDED", OUTCOME_ENDED),
        ("OUTCOMES_LOST", OUTCOME_OUTCOMES_LOST),
    ] {
        assert_eq!(
            defines[&format!("KARYOS_OUTCOME_{name}")],
            i64::from(value),
            "{name}"
        );
    }
}
