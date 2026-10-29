// SPDX-License-Identifier: Apache-2.0

//! The wire compatibility matrix (R-CORE-36, karyos#732;
//! `quantstratum-docs: karyos/design/versions.md`, "Compatibility"): which
//! builds interoperate, surface by surface, indexed by the full versions
//! tuple of `--versions` (R-CORE-33), never by the frame version alone.
//!
//! The matrix is `compat/matrix.toml`, embedded in this crate. Its columns
//! are the versions tuples of the releases it covers and of `main`; its
//! entries give, for an ordered pair of columns and one surface, the
//! outcome: `interoperate`, `refuse` with the typed reason a side answers,
//! or `not_covered` with why. A pair of the same column interoperates. A
//! surface that one side does not have is `absent`: that pair does not use
//! it.
//!
//! [`decide`] reads two `--versions` objects (or named columns), finds
//! each one's column by its whole tuple and decides every surface. A tuple
//! the matrix has no column for, or a field it does not know, is not
//! covered: the matrix judges only what it was written for.
//!
//! The objects are read by a strict, bounded reader of the
//! `karyos-versions` schema alone, not of arbitrary JSON: a fixed depth
//! and size, integers checked against overflow, and every failure a typed
//! [`CompatError`], never a panic.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use serde::Deserialize;

/// The matrix, as this build embeds it.
pub const MATRIX: &str = include_str!("../compat/matrix.toml");
/// The matrix file's schema name.
pub const SCHEMA: &str = "karyos-compat";
/// The matrix file's schema version.
pub const SCHEMA_VERSION: u32 = 1;
/// The deepest nesting a versions object may have.
pub const MAX_DEPTH: usize = 8;
/// The largest versions object read, in bytes.
pub const MAX_BYTES: usize = 16 * 1024;

/// Exit status: every surface the pair uses interoperates.
pub const EXIT_INTEROPERATE: u8 = 0;
/// Exit status: a surface refuses.
pub const EXIT_REFUSE: u8 = 1;
/// Exit status: no surface refuses, and one is not covered.
pub const EXIT_NOT_COVERED: u8 = 2;
/// Exit status: an input could not be read.
pub const EXIT_ERROR: u8 = 3;

/// The surfaces the matrix judges, each with the role of its two sides:
/// `from` is the first build of a pair, `to` the second.
pub const SURFACES: [(&str, &str); 9] = [
    ("admission", "a client (from) attaching to a driver (to)"),
    (
        "frame",
        "a driver sending (from) to a driver receiving (to)",
    ),
    (
        "c_abi",
        "a binding built on a header (from) loading a library (to)",
    ),
    (
        "archive_control",
        "a client (from) controlling an Archive (to)",
    ),
    (
        "cluster_log",
        "a Cluster member's log (from) read by another (to)",
    ),
    ("group_record", "group records written (from) and read (to)"),
    (
        "capture_contract",
        "a group journal captured (from) and read (to)",
    ),
    (
        "archive_durable",
        "a client (from) querying durability (to)",
    ),
    (
        "config",
        "a configuration file (from) read by a karyosd (to)",
    ),
];

/// Why an input could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompatError {
    /// The text ends inside a value.
    Truncated,
    /// A string escape that is not one of JSON's, or a lone surrogate.
    BadEscape,
    /// An object repeats a key.
    DuplicateKey(String),
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Longer than [`MAX_BYTES`].
    TooLarge,
    /// An integer above `u64::MAX`, or a number this reader does not take
    /// (negative, fractional or with an exponent).
    Number,
    /// Text after the value.
    Trailing,
    /// Anything else that is not JSON.
    Syntax(usize),
    /// Valid JSON that is not a `karyos-versions` object of a version this
    /// build reads.
    Schema(String),
    /// The matrix file is invalid.
    Matrix(String),
    /// A `column:` name the matrix does not have.
    UnknownColumn(String),
}

impl fmt::Display for CompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("the versions object is truncated"),
            Self::BadEscape => f.write_str("a string escape is invalid"),
            Self::DuplicateKey(key) => write!(f, "the key {key:?} is repeated"),
            Self::TooDeep => write!(f, "nested deeper than {MAX_DEPTH}"),
            Self::TooLarge => write!(f, "longer than {MAX_BYTES} bytes"),
            Self::Number => f.write_str("a number is not an unsigned 64-bit integer"),
            Self::Trailing => f.write_str("text follows the versions object"),
            Self::Syntax(at) => write!(f, "invalid JSON at byte {at}"),
            Self::Schema(what) => write!(f, "not a karyos-versions object: {what}"),
            Self::Matrix(what) => write!(f, "invalid matrix: {what}"),
            Self::UnknownColumn(name) => write!(f, "the matrix has no column {name:?}"),
        }
    }
}

impl std::error::Error for CompatError {}

/// A JSON value, as the reader takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// An object, its keys unique, in order.
    Object(Vec<(String, Json)>),
    /// An array.
    Array(Vec<Json>),
    /// A string.
    String(String),
    /// An unsigned integer.
    Integer(u64),
    /// A boolean.
    Bool(bool),
    /// `null`.
    Null,
}

impl Json {
    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find_map(|(name, value)| (name == key).then_some(value)),
            _ => None,
        }
    }
}

/// Reads one JSON value, the whole of `text`, within [`MAX_BYTES`] and
/// [`MAX_DEPTH`].
///
/// # Errors
///
/// A [`CompatError`] of the reader's classes.
pub fn parse(text: &str) -> Result<Json, CompatError> {
    if text.len() > MAX_BYTES {
        return Err(CompatError::TooLarge);
    }
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = reader.value(0)?;
    reader.space();
    if reader.at != reader.bytes.len() {
        return Err(CompatError::Trailing);
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn next(&mut self) -> Result<u8, CompatError> {
        let byte = self.peek().ok_or(CompatError::Truncated)?;
        self.at += 1;
        Ok(byte)
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, literal: &[u8]) -> Result<(), CompatError> {
        for expected in literal {
            if self.next()? != *expected {
                return Err(CompatError::Syntax(self.at - 1));
            }
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Json, CompatError> {
        if depth > MAX_DEPTH {
            return Err(CompatError::TooDeep);
        }
        self.space();
        match self.peek().ok_or(CompatError::Truncated)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Json::String),
            b't' => self.expect(b"true").map(|()| Json::Bool(true)),
            b'f' => self.expect(b"false").map(|()| Json::Bool(false)),
            b'n' => self.expect(b"null").map(|()| Json::Null),
            b'0'..=b'9' => self.integer().map(Json::Integer),
            b'-' => Err(CompatError::Number),
            _ => Err(CompatError::Syntax(self.at)),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, CompatError> {
        self.expect(b"{")?;
        let mut fields: Vec<(String, Json)> = Vec::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            self.space();
            if self.peek() != Some(b'"') {
                return Err(self
                    .peek()
                    .map_or(CompatError::Truncated, |_| CompatError::Syntax(self.at)));
            }
            let key = self.string()?;
            if fields.iter().any(|(name, _)| *name == key) {
                return Err(CompatError::DuplicateKey(key));
            }
            self.space();
            self.expect(b":")?;
            let value = self.value(depth + 1)?;
            fields.push((key, value));
            self.space();
            match self.next()? {
                b',' => {}
                b'}' => return Ok(Json::Object(fields)),
                _ => return Err(CompatError::Syntax(self.at - 1)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, CompatError> {
        self.expect(b"[")?;
        let mut items = Vec::new();
        self.space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.space();
            match self.next()? {
                b',' => {}
                b']' => return Ok(Json::Array(items)),
                _ => return Err(CompatError::Syntax(self.at - 1)),
            }
        }
    }

    fn string(&mut self) -> Result<String, CompatError> {
        self.expect(b"\"")?;
        let mut out = Vec::new();
        loop {
            match self.next()? {
                b'"' => return String::from_utf8(out).map_err(|_| CompatError::Syntax(self.at)),
                b'\\' => {
                    let escaped = match self.next()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let code = self.hex4()?;
                            // A high surrogate takes the low one of its
                            // pair from the next escape; either half alone
                            // is not a character.
                            let code = if (0xD800..0xDC00).contains(&code) {
                                self.expect(b"\\u").map_err(|_| CompatError::BadEscape)?;
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return Err(CompatError::BadEscape);
                                }
                                0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                            } else {
                                code
                            };
                            char::from_u32(code).ok_or(CompatError::BadEscape)?
                        }
                        _ => return Err(CompatError::BadEscape),
                    };
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(escaped.encode_utf8(&mut buffer).as_bytes());
                }
                byte if byte < 0x20 => return Err(CompatError::Syntax(self.at - 1)),
                byte => out.push(byte),
            }
        }
    }

    /// The four hex digits of a `\u` escape.
    fn hex4(&mut self) -> Result<u32, CompatError> {
        let mut code = 0u32;
        for _ in 0..4 {
            let digit = char::from(self.next()?)
                .to_digit(16)
                .ok_or(CompatError::BadEscape)?;
            code = code * 16 + digit;
        }
        Ok(code)
    }

    fn integer(&mut self) -> Result<u64, CompatError> {
        let start = self.at;
        let mut value = 0u64;
        while let Some(byte @ b'0'..=b'9') = self.peek() {
            self.at += 1;
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                .ok_or(CompatError::Number)?;
        }
        // A leading zero, a fraction or an exponent is not taken.
        if (self.at - start > 1 && self.bytes.get(start) == Some(&b'0'))
            || matches!(self.peek(), Some(b'.' | b'e' | b'E'))
        {
            return Err(CompatError::Number);
        }
        Ok(value)
    }
}

/// A build's versions tuple: the fields a column is matched on, `None`
/// where the build has no such surface.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tuple {
    /// The admission protocol version.
    pub admission: Option<u64>,
    /// The frame protocol version.
    pub frame: Option<u64>,
    /// The C ABI version, `major.minor.patch`.
    pub c_abi: Option<String>,
    /// The Archive control schema version.
    pub archive_control: Option<u64>,
    /// The Cluster log schema version.
    pub cluster_log: Option<u64>,
    /// The group record schema version.
    pub group_record: Option<u64>,
    /// The capture contract version.
    pub capture_contract: Option<u64>,
    /// The Archive durability schema version.
    pub archive_durable: Option<u64>,
    /// The configuration file schema version.
    pub config: Option<u64>,
}

impl Tuple {
    /// Whether the build has `surface`.
    fn has(&self, surface: &str) -> bool {
        match surface {
            "admission" => self.admission.is_some(),
            "frame" => self.frame.is_some(),
            "c_abi" => self.c_abi.is_some(),
            "archive_control" => self.archive_control.is_some(),
            "cluster_log" => self.cluster_log.is_some(),
            "group_record" => self.group_record.is_some(),
            "capture_contract" => self.capture_contract.is_some(),
            "archive_durable" => self.archive_durable.is_some(),
            "config" => self.config.is_some(),
            _ => false,
        }
    }
}

/// What the matrix says of one surface of a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It works.
    Interoperate,
    /// A side refuses, typed.
    Refuse,
    /// Not known: untested or out of the matrix's scope.
    NotCovered,
    /// One side does not have the surface: the pair does not use it.
    Absent,
}

impl Outcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Interoperate => "interoperate",
            Self::Refuse => "refuse",
            Self::NotCovered => "not_covered",
            Self::Absent => "absent",
        }
    }
}

/// One column: a release, or `main`, and its tuple.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Column {
    /// The column's name.
    pub name: String,
    /// Its versions (`[column.versions]`).
    #[serde(rename = "versions")]
    pub tuple: Tuple,
}

/// One entry: an ordered pair of columns and a surface.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The surface.
    pub surface: String,
    /// The first build's column.
    pub from: String,
    /// The second build's column.
    pub to: String,
    /// The outcome.
    pub outcome: Outcome,
    /// The typed reason of a refusal, or why it is not covered; how it was
    /// established for an interoperation.
    pub reason: String,
}

/// A case the matrix names as not covered.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Uncovered {
    /// The case.
    pub case: String,
    /// Why.
    pub reason: String,
}

/// The matrix file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matrix {
    /// [`SCHEMA`].
    pub schema: String,
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The columns.
    #[serde(rename = "column")]
    pub columns: Vec<Column>,
    /// The entries.
    #[serde(rename = "entry", default)]
    pub entries: Vec<Entry>,
    /// The cases not covered.
    #[serde(rename = "not_covered", default)]
    pub uncovered: Vec<Uncovered>,
}

impl Matrix {
    /// The matrix in `text`, checked: its schema, unique column names and
    /// tuples, and entries naming known columns and surfaces, once each.
    ///
    /// # Errors
    ///
    /// [`CompatError::Matrix`].
    pub fn read(text: &str) -> Result<Self, CompatError> {
        let matrix: Self =
            toml::from_str(text).map_err(|error| CompatError::Matrix(error.to_string()))?;
        if matrix.schema != SCHEMA || matrix.schema_version != SCHEMA_VERSION {
            return Err(CompatError::Matrix(format!(
                "schema {} {}",
                matrix.schema, matrix.schema_version
            )));
        }
        for (at, column) in matrix.columns.iter().enumerate() {
            let earlier = matrix.columns.iter().take(at);
            if earlier
                .clone()
                .any(|other| other.name == column.name || other.tuple == column.tuple)
            {
                return Err(CompatError::Matrix(format!(
                    "column {} repeats a name or a tuple",
                    column.name
                )));
            }
        }
        let known = |name: &str| matrix.columns.iter().any(|column| column.name == name);
        for (at, entry) in matrix.entries.iter().enumerate() {
            if !SURFACES
                .iter()
                .any(|(surface, _)| *surface == entry.surface)
                || !known(&entry.from)
                || !known(&entry.to)
                || entry.from == entry.to
            {
                return Err(CompatError::Matrix(format!(
                    "entry {} {} {} names an unknown surface or column, or one column twice",
                    entry.surface, entry.from, entry.to
                )));
            }
            if matrix.entries.iter().take(at).any(|other| {
                other.surface == entry.surface && other.from == entry.from && other.to == entry.to
            }) {
                return Err(CompatError::Matrix(format!(
                    "entry {} {} {} is repeated",
                    entry.surface, entry.from, entry.to
                )));
            }
        }
        Ok(matrix)
    }

    /// The column of `tuple`, if the matrix has one.
    #[must_use]
    pub fn column_of(&self, tuple: &Tuple) -> Option<&Column> {
        self.columns.iter().find(|column| column.tuple == *tuple)
    }

    /// The column named `name`.
    #[must_use]
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|column| column.name == name)
    }
}

/// The matrix this build embeds.
///
/// # Errors
///
/// [`CompatError::Matrix`] if the embedded file is invalid, which a test
/// excludes.
pub fn matrix() -> Result<Matrix, CompatError> {
    Matrix::read(MATRIX)
}

/// The top-level fields of a versions object the matrix knows.
const KNOWN: [&str; 9] = [
    "schema",
    "schema_version",
    "core",
    "protocol",
    "c_abi",
    "wire",
    "config",
    "backends",
    "features",
];

/// The objects of a versions object: each one's keys, and the id of the
/// rule its versions are compared under, which this matrix's entries
/// assume (`None` for an object without a rule).
const OBJECTS: [(&str, &[&str], Option<&str>); 5] = [
    ("core", &["release"], None),
    ("protocol", &["admission", "frame", "rule"], Some("exact")),
    ("c_abi", &["version", "rule"], Some("exact-0y-min-patch")),
    (
        "wire",
        &[
            "frame",
            "archive_control",
            "cluster_log",
            "group_record",
            "capture_contract",
            "archive_durable",
            "rule",
        ],
        Some("exact"),
    ),
    ("config", &["schema_version", "rule"], Some("exact")),
];

/// The keys of each entry of `backends`.
const BACKEND_KEYS: [&str; 2] = ["name", "compiled"];

/// One side of a pair: its tuple, and what in it the matrix does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Side {
    /// The versions tuple.
    pub tuple: Tuple,
    /// What the matrix does not know, by path: a field at any depth beyond
    /// the known ones (`protocol.new_surface`), a rule other than the one
    /// its entries assume (`c_abi.rule=semver`), a missing rule, or
    /// another schema version. Any of them makes the pair not covered:
    /// the decision fails closed, never interoperate by a guess.
    pub unknown: Vec<String>,
}

/// The side a `--versions` object describes.
///
/// # Errors
///
/// The reader's errors, and [`CompatError::Schema`] for another schema, a
/// missing field, a field of the wrong type, or a `wire.frame` other than
/// `protocol.frame`.
pub fn side(text: &str) -> Result<Side, CompatError> {
    let json = parse(text)?;
    let schema = |what: &str| CompatError::Schema(what.to_owned());
    let Json::Object(fields) = &json else {
        return Err(schema("not an object"));
    };
    if json.get("schema") != Some(&Json::String(crate::versions::SCHEMA.to_owned())) {
        return Err(schema("schema"));
    }
    match json.get("schema_version") {
        Some(Json::Integer(version)) if *version == u64::from(crate::versions::SCHEMA_VERSION) => {}
        // Another version of the schema: nothing in it is read by a guess.
        Some(Json::Integer(version)) => {
            return Ok(Side {
                tuple: Tuple::default(),
                unknown: vec![format!("schema_version={version}")],
            });
        }
        _ => return Err(schema("schema_version")),
    }
    let mut unknown: Vec<String> = fields
        .iter()
        .map(|(name, _)| name)
        .filter(|name| !KNOWN.contains(&name.as_str()))
        .cloned()
        .collect();
    for (name, keys, rule) in OBJECTS {
        let Some(object) = json.get(name) else {
            continue;
        };
        let Json::Object(members) = object else {
            return Err(schema(name));
        };
        unknown.extend(
            members
                .iter()
                .filter(|(key, _)| !keys.contains(&key.as_str()))
                .map(|(key, _)| format!("{name}.{key}")),
        );
        if let Some(expected) = rule {
            match object.get("rule") {
                Some(Json::String(id)) if id == expected => {}
                Some(Json::String(id)) => unknown.push(format!("{name}.rule={id}")),
                None => unknown.push(format!("{name}.rule missing")),
                Some(_) => return Err(schema(&format!("{name}.rule"))),
            }
        }
    }
    match json.get("backends") {
        None => {}
        Some(Json::Array(backends)) => {
            for (index, backend) in backends.iter().enumerate() {
                let Json::Object(members) = backend else {
                    return Err(schema("backends"));
                };
                unknown.extend(
                    members
                        .iter()
                        .filter(|(key, _)| !BACKEND_KEYS.contains(&key.as_str()))
                        .map(|(key, _)| format!("backends[{index}].{key}")),
                );
            }
        }
        Some(_) => return Err(schema("backends")),
    }
    let integer = |path: [&str; 2]| match json.get(path[0]).and_then(|object| object.get(path[1])) {
        Some(Json::Integer(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err(schema(&path.join("."))),
    };
    let c_abi = match json.get("c_abi").and_then(|object| object.get("version")) {
        Some(Json::String(version)) => Some(version.clone()),
        None => None,
        Some(_) => return Err(schema("c_abi.version")),
    };
    let frame = integer(["protocol", "frame"])?;
    // The wire object repeats the frame version: one value, or the object
    // contradicts itself.
    if let Some(wire_frame) = integer(["wire", "frame"])?
        && Some(wire_frame) != frame
    {
        return Err(schema("wire.frame differs from protocol.frame"));
    }
    let tuple = Tuple {
        admission: integer(["protocol", "admission"])?,
        frame,
        c_abi,
        archive_control: integer(["wire", "archive_control"])?,
        cluster_log: integer(["wire", "cluster_log"])?,
        group_record: integer(["wire", "group_record"])?,
        capture_contract: integer(["wire", "capture_contract"])?,
        archive_durable: integer(["wire", "archive_durable"])?,
        config: integer(["config", "schema_version"])?,
    };
    Ok(Side { tuple, unknown })
}

/// One surface's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceDecision {
    /// The surface.
    pub surface: &'static str,
    /// Its outcome.
    pub outcome: Outcome,
    /// Why.
    pub reason: String,
}

/// A pair's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The first build's column, if it has one.
    pub from: Option<String>,
    /// The second build's column, if it has one.
    pub to: Option<String>,
    /// Each surface, in [`SURFACES`] order.
    pub surfaces: Vec<SurfaceDecision>,
    /// The whole pair: `refuse` when a surface refuses, else `not_covered`
    /// when one is not covered, else `interoperate`.
    pub outcome: Outcome,
}

impl Decision {
    /// The exit status of the decision.
    #[must_use]
    pub const fn exit(&self) -> u8 {
        match self.outcome {
            Outcome::Refuse => EXIT_REFUSE,
            Outcome::NotCovered => EXIT_NOT_COVERED,
            Outcome::Interoperate | Outcome::Absent => EXIT_INTEROPERATE,
        }
    }

    /// The decision as one JSON object, with its newline.
    #[must_use]
    pub fn json(&self) -> String {
        let mut out = String::new();
        let name = |column: &Option<String>| {
            column
                .as_ref()
                .map_or_else(|| "null".to_owned(), |name| format!("\"{}\"", escape(name)))
        };
        let _ = write!(
            out,
            r#"{{"schema":"{SCHEMA}-decision","schema_version":{SCHEMA_VERSION},"from":{},"to":{},"outcome":"{}","surfaces":["#,
            name(&self.from),
            name(&self.to),
            self.outcome.name()
        );
        for (index, surface) in self.surfaces.iter().enumerate() {
            let separator = if index == 0 { "" } else { "," };
            let _ = write!(
                out,
                r#"{separator}{{"surface":"{}","outcome":"{}","reason":"{}"}}"#,
                surface.surface,
                surface.outcome.name(),
                escape(&surface.reason)
            );
        }
        out.push_str("]}\n");
        out
    }
}

/// `text` with JSON's string escapes.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Decides the pair `from` → `to` under `matrix`.
#[must_use]
pub fn decide(matrix: &Matrix, from: &Side, to: &Side) -> Decision {
    let from_column = matrix.column_of(&from.tuple);
    let to_column = matrix.column_of(&to.tuple);
    let unknown: Vec<&String> = from.unknown.iter().chain(&to.unknown).collect();
    let mut surfaces = Vec::with_capacity(SURFACES.len());
    for (surface, _) in SURFACES {
        let (outcome, reason) = match (from_column, to_column) {
            _ if !unknown.is_empty() => (
                Outcome::NotCovered,
                format!("fields the matrix does not know: {unknown:?}"),
            ),
            (Some(a), Some(b)) if !a.tuple.has(surface) || !b.tuple.has(surface) => (
                Outcome::Absent,
                format!("{} or {} does not have it", a.name, b.name),
            ),
            (Some(a), Some(b)) if a.name == b.name => {
                (Outcome::Interoperate, format!("the same build, {}", a.name))
            }
            (Some(a), Some(b)) => matrix
                .entries
                .iter()
                .find(|entry| {
                    entry.surface == surface && entry.from == a.name && entry.to == b.name
                })
                .map_or_else(
                    || {
                        (
                            Outcome::NotCovered,
                            format!("no entry for {} to {}", a.name, b.name),
                        )
                    },
                    |entry| (entry.outcome, entry.reason.clone()),
                ),
            _ => (
                Outcome::NotCovered,
                "a versions tuple the matrix has no column for".to_owned(),
            ),
        };
        surfaces.push(SurfaceDecision {
            surface,
            outcome,
            reason,
        });
    }
    let outcome = if surfaces.iter().any(|s| s.outcome == Outcome::Refuse) {
        Outcome::Refuse
    } else if surfaces.iter().any(|s| s.outcome == Outcome::NotCovered) {
        Outcome::NotCovered
    } else {
        Outcome::Interoperate
    };
    Decision {
        from: from_column.map(|column| column.name.clone()),
        to: to_column.map(|column| column.name.clone()),
        surfaces,
        outcome,
    }
}

/// The side named by `arg`: `column:<name>` for a column of the matrix,
/// else the path of a `--versions` object.
///
/// # Errors
///
/// [`CompatError::UnknownColumn`], [`CompatError::Schema`] for a file that
/// cannot be read, and the errors of [`side`].
pub fn side_of(matrix: &Matrix, arg: &str) -> Result<Side, CompatError> {
    if let Some(name) = arg.strip_prefix("column:") {
        let column = matrix
            .column(name)
            .ok_or_else(|| CompatError::UnknownColumn(name.to_owned()))?;
        return Ok(Side {
            tuple: column.tuple.clone(),
            unknown: Vec::new(),
        });
    }
    let file =
        std::fs::File::open(arg).map_err(|error| CompatError::Schema(format!("{arg}: {error}")))?;
    let mut text = String::new();
    // One byte past the bound tells a file that is too large.
    let limit = u64::try_from(MAX_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    std::io::Read::read_to_string(&mut std::io::Read::take(file, limit), &mut text)
        .map_err(|error| CompatError::Schema(format!("{arg}: {error}")))?;
    side(&text)
}

/// The tuple of this build, from its own versions.
#[must_use]
pub fn this_build() -> Tuple {
    let versions = crate::versions::current();
    let (major, minor, patch) = versions.c_abi;
    Tuple {
        admission: Some(versions.admission),
        frame: Some(u64::from(versions.frame)),
        c_abi: Some(format!("{major}.{minor}.{patch}")),
        archive_control: Some(u64::from(versions.archive_control)),
        cluster_log: Some(u64::from(versions.cluster_log)),
        group_record: Some(u64::from(versions.group_record)),
        capture_contract: Some(u64::from(versions.capture_contract)),
        archive_durable: Some(u64::from(versions.archive_durable)),
        config: Some(u64::from(versions.config)),
    }
}

/// The matrix's entries by surface, for documentation.
#[must_use]
pub fn by_surface(matrix: &Matrix) -> BTreeMap<&str, Vec<&Entry>> {
    let mut map: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
    for entry in &matrix.entries {
        map.entry(entry.surface.as_str()).or_default().push(entry);
    }
    map
}

/// `karyos-tools compat --help`.
pub const HELP: &str = "\
karyos-tools compat: decides whether two builds interoperate, surface by
surface, from the wire compatibility matrix this build embeds (R-CORE-36).

Usage: karyos-tools compat <FROM> <TO>

FROM and TO are each the path of a `--versions` object, or `column:<name>`
for a column of the matrix (such as column:0.1.0-alpha.2). FROM is the
client, sender, header or writer side of each surface and TO the driver,
receiver, library or reader side.

Prints one JSON object. Exit status: 0 interoperate, 1 a surface refuses,
2 not covered, 3 an input could not be read.
";

/// Runs `karyos-tools compat` with `args` (after the subcommand), writing
/// the decision to `out` and errors to `err`; returns the exit status.
pub fn run<I, S>(args: I, out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> u8
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let args: Vec<S> = args.into_iter().collect();
    let texts: Option<Vec<&str>> = args.iter().map(|arg| arg.as_ref().to_str()).collect();
    let fail = |err: &mut dyn std::io::Write, message: &dyn fmt::Display| {
        let _ = writeln!(err, "karyos-tools compat: {message}");
        EXIT_ERROR
    };
    let Some(texts) = texts else {
        return fail(err, &"an argument is not UTF-8");
    };
    match texts.as_slice() {
        ["-h" | "--help"] => {
            if out.write_all(HELP.as_bytes()).is_ok() {
                EXIT_INTEROPERATE
            } else {
                EXIT_ERROR
            }
        }
        [from, to] => {
            let decided = matrix().and_then(|matrix| {
                let from = side_of(&matrix, from)?;
                let to = side_of(&matrix, to)?;
                Ok(decide(&matrix, &from, &to))
            });
            match decided {
                Ok(decision) => {
                    if out
                        .write_all(decision.json().as_bytes())
                        .and_then(|()| out.flush())
                        .is_ok()
                    {
                        decision.exit()
                    } else {
                        EXIT_ERROR
                    }
                }
                Err(error) => fail(err, &error),
            }
        }
        _ => fail(err, &"expected <FROM> <TO> (karyos-tools compat --help)"),
    }
}

#[cfg(test)]
mod tests;
