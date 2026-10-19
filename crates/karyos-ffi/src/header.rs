// SPDX-License-Identifier: Apache-2.0

//! The check of the hand-written `include/karyos.h` against the Rust
//! source (quantstratum-docs: karyos/design/ffi-gap-analysis.md §4.6),
//! until `cbindgen` generates the header: the same exported functions with
//! the same C types, the same status codes and the same ABI version.
//!
//! It reads both files as text and covers the constructs the ABI uses: one
//! `#define NAME VALUE` per constant, prototypes without function pointer
//! parameters, and `extern "C" fn` items in `abi.rs` whose parameter types
//! the table in [`c_type`] knows. Anything else fails the test.

use std::collections::BTreeMap;

use crate::abi::{ABI_VERSION_MAJOR, ABI_VERSION_MINOR, ABI_VERSION_PATCH};
use crate::status::Status;

const HEADER: &str = include_str!("../include/karyos.h");
const ABI: &str = include_str!("abi.rs");

/// A function's C return type and parameter types.
type Signature = (String, Vec<String>);

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

/// The header's prototypes.
fn header_functions() -> BTreeMap<String, Signature> {
    let code: String = header_code()
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
                c_type(rust)
            })
            .collect();
        let body = rest[close..].find('{').expect("a body");
        let returns = rest[close + 1..close + body]
            .trim()
            .strip_prefix("->")
            .map_or_else(|| "void".to_owned(), c_type);
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
