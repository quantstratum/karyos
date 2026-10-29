// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::*;

fn this_side() -> Side {
    side(&crate::versions::current().json()).unwrap()
}

/// The embedded matrix is valid, and this build's tuple is its `main`
/// column: a version that changes without its column fails here.
#[test]
fn the_matrix_is_valid_and_main_is_this_build() {
    let matrix = matrix().unwrap();
    assert_eq!(
        matrix.column("main").map(|column| &column.tuple),
        Some(&this_build()),
        "update compat/matrix.toml's main column for this build's versions"
    );
}

/// A round trip of this build's own `--versions`: read back, its tuple is
/// this build's and nothing in it is unknown.
#[test]
fn this_builds_versions_read_back() {
    let side = this_side();
    assert_eq!(side.tuple, this_build());
    assert!(side.unknown.is_empty(), "{:?}", side.unknown);
}

/// Every entry of the matrix decides as written, and a pair of one column
/// interoperates on every surface both sides have.
#[test]
fn every_entry_decides_as_written() {
    let matrix = matrix().unwrap();
    let side_of_column = |name: &str| side_of(&matrix, &format!("column:{name}")).unwrap();
    for entry in &matrix.entries {
        let decision = decide(
            &matrix,
            &side_of_column(&entry.from),
            &side_of_column(&entry.to),
        );
        let surface = decision
            .surfaces
            .iter()
            .find(|surface| surface.surface == entry.surface)
            .unwrap();
        assert_eq!(
            (surface.outcome, surface.reason.as_str()),
            (entry.outcome, entry.reason.as_str()),
            "{entry:?}"
        );
    }
    for column in &matrix.columns {
        let side = side_of_column(&column.name);
        let decision = decide(&matrix, &side, &side);
        assert_eq!(decision.outcome, Outcome::Interoperate, "{}", column.name);
        assert_eq!(decision.exit(), EXIT_INTEROPERATE);
    }
}

/// The criterion of R-CORE-36: an equal frame version with another
/// admission version is in the matrix with its real outcome, a refusal.
#[test]
fn an_equal_frame_version_is_not_enough() {
    let matrix = matrix().unwrap();
    let main = side_of(&matrix, "column:main").unwrap();
    let alpha2 = side_of(&matrix, "column:0.1.0-alpha.2").unwrap();
    assert_eq!(main.tuple.frame, alpha2.tuple.frame);
    let decision = decide(&matrix, &main, &alpha2);
    assert_eq!(decision.outcome, Outcome::Refuse);
    assert_eq!(decision.exit(), EXIT_REFUSE);
    let admission = &decision.surfaces[0];
    assert_eq!(
        (admission.surface, admission.outcome),
        ("admission", Outcome::Refuse)
    );
    // A surface only main has is absent from the pair, not a refusal.
    let durable = decision
        .surfaces
        .iter()
        .find(|surface| surface.surface == "archive_durable")
        .unwrap();
    assert_eq!(durable.outcome, Outcome::Absent);
}

/// A tuple without a column, or a field the matrix does not know, is not
/// covered, never decided by a guess.
#[test]
fn an_unknown_tuple_or_field_is_not_covered() {
    let matrix = matrix().unwrap();
    let main = this_side();
    let mut future = main.clone();
    future.tuple.admission = Some(4);
    let decision = decide(&matrix, &future, &main);
    assert_eq!(decision.outcome, Outcome::NotCovered);
    assert_eq!(decision.exit(), EXIT_NOT_COVERED);
    assert_eq!(decision.from, None);

    let with_field = crate::versions::current().json().replacen(
        "\"features\"",
        "\"telemetry\":{\"v\":1},\"features\"",
        1,
    );
    let newer = side(&with_field).unwrap();
    assert_eq!(newer.unknown, vec!["telemetry".to_owned()]);
    assert_eq!(decide(&matrix, &newer, &main).outcome, Outcome::NotCovered);
}

/// The decision fails closed at every depth: a field inside an object, a
/// rule other than the one the matrix's entries assume, a missing rule,
/// a backend's new key or another schema version makes the pair not
/// covered (exit 2), and names what it did not know by path; this
/// build's own object has nothing unknown at any depth.
#[test]
fn an_unknown_nested_field_or_rule_is_not_covered() {
    let matrix = matrix().unwrap();
    let main = this_side();
    assert!(main.unknown.is_empty(), "{:?}", main.unknown);
    let own = crate::versions::current().json();
    let rows: [(&str, &str, &str); 7] = [
        (
            "\"protocol\":{",
            "\"protocol\":{\"new_surface\":1,",
            "protocol.new_surface",
        ),
        ("\"wire\":{", "\"wire\":{\"telemetry\":1,", "wire.telemetry"),
        (
            "\"config\":{",
            "\"config\":{\"profile\":\"x\",",
            "config.profile",
        ),
        ("\"core\":{", "\"core\":{\"build\":\"x\",", "core.build"),
        (
            "\"rule\":\"exact-0y-min-patch\"",
            "\"rule\":\"semver\"",
            "c_abi.rule=semver",
        ),
        (",\"rule\":\"exact-0y-min-patch\"", "", "c_abi.rule missing"),
        (
            "\"compiled\":true",
            "\"compiled\":true,\"queue\":2",
            "backends[0].queue",
        ),
    ];
    for (from, to, path) in rows {
        assert!(own.contains(from), "{from}");
        let changed = side(&own.replacen(from, to, 1)).unwrap();
        assert_eq!(changed.unknown, vec![path.to_owned()], "{path}");
        let decision = decide(&matrix, &changed, &main);
        assert_eq!(decision.outcome, Outcome::NotCovered, "{path}");
        assert_eq!(decision.exit(), EXIT_NOT_COVERED, "{path}");
        assert!(
            decision
                .surfaces
                .iter()
                .all(|surface| surface.outcome == Outcome::NotCovered),
            "{path}"
        );
    }
    // Another schema version is read no further.
    let next = side(&own.replacen("\"schema_version\":1", "\"schema_version\":2", 1)).unwrap();
    assert_eq!(next.unknown, vec!["schema_version=2".to_owned()]);
    assert_eq!(decide(&matrix, &main, &next).exit(), EXIT_NOT_COVERED);
}

/// The frame version appears twice, in `protocol` and in `wire`: an
/// object whose two disagree is refused as a schema error.
#[test]
fn a_wire_frame_other_than_the_protocol_frame_is_refused() {
    let own = crate::versions::current().json();
    let tuple = this_build();
    let frame = tuple.frame.unwrap();
    let from = format!("\"wire\":{{\"frame\":{frame}");
    assert!(own.contains(&from));
    let other = own.replacen(&from, &format!("\"wire\":{{\"frame\":{}", frame + 1), 1);
    assert!(matches!(side(&other), Err(CompatError::Schema(_))));
}

/// Each error class of the reader, typed.
#[test]
fn each_reader_error_is_typed() {
    let deep = format!(
        "{}1{}",
        "[".repeat(MAX_DEPTH + 1),
        "]".repeat(MAX_DEPTH + 1)
    );
    let large = format!("\"{}\"", "x".repeat(MAX_BYTES));
    let rows: [(&str, CompatError); 9] = [
        (r#"{"schema":"karyos-versions""#, CompatError::Truncated),
        (r#"{"a":"\q"}"#, CompatError::BadEscape),
        (r#"{"a":"\ud800"}"#, CompatError::BadEscape),
        (
            r#"{"a":1,"a":2}"#,
            CompatError::DuplicateKey("a".to_owned()),
        ),
        (&deep, CompatError::TooDeep),
        (&large, CompatError::TooLarge),
        (r#"{"a":18446744073709551616}"#, CompatError::Number),
        (r#"{"a":1} x"#, CompatError::Trailing),
        (r#"{"a":-1}"#, CompatError::Number),
    ];
    for (text, expected) in rows {
        assert_eq!(parse(text), Err(expected.clone()), "{text}");
    }
    // A surrogate pair is one character; a high half without its low
    // one, or before another high one, is not.
    assert_eq!(
        parse(r#"{"a":"\ud83d\ude00"}"#),
        Ok(Json::Object(vec![(
            "a".to_owned(),
            Json::String("\u{1F600}".to_owned())
        )]))
    );
    assert_eq!(
        parse(r#"{"a":"\ud83d\ud83d"}"#),
        Err(CompatError::BadEscape)
    );
    assert_eq!(parse(r#"{"a":"\ud83dx"}"#), Err(CompatError::BadEscape));
    assert_eq!(parse(r#"{"a":"\ude00"}"#), Err(CompatError::BadEscape));
    assert_eq!(parse(r#"{"a":1.5}"#), Err(CompatError::Number));
    assert_eq!(parse(r#"{"a":01}"#), Err(CompatError::Number));
    assert!(matches!(parse("{a:1}"), Err(CompatError::Syntax(_))));
    // At the depth limit, and the largest integer, are read.
    let at_limit = format!("{}1{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
    assert!(parse(&at_limit).is_ok());
    assert_eq!(
        parse(r#"{"a":18446744073709551615,"b":"é\n"}"#),
        Ok(Json::Object(vec![
            ("a".to_owned(), Json::Integer(u64::MAX)),
            ("b".to_owned(), Json::String("é\n".to_owned())),
        ]))
    );
}

/// Valid JSON that is not a karyos-versions object of this version is a
/// schema error.
#[test]
fn another_schema_is_refused() {
    for text in [
        "[]",
        r#"{"schema":"other","schema_version":1}"#,
        r#"{"schema":"karyos-versions","schema_version":"1"}"#,
        r#"{"schema":"karyos-versions","schema_version":1,"protocol":{"admission":"3","rule":"exact"}}"#,
        r#"{"schema":"karyos-versions","schema_version":1,"protocol":3}"#,
        r#"{"schema":"karyos-versions","schema_version":1,"protocol":{"rule":3}}"#,
        r#"{"schema":"karyos-versions","schema_version":1,"backends":[1]}"#,
    ] {
        assert!(matches!(side(text), Err(CompatError::Schema(_))), "{text}");
    }
}

/// Unknown fields in the matrix file are refused, as is a matrix that
/// names an unknown column or repeats an entry.
#[test]
fn an_invalid_matrix_is_refused() {
    let head = "schema = \"karyos-compat\"\nschema_version = 1\n";
    let column = "[[column]]\nname = \"a\"\n[column.versions]\nadmission = 1\n";
    for text in [
        format!("{head}{column}extra = 1\n"),
        format!("{head}[[column]]\nname = \"a\"\n[column.versions]\nadmission = 1\nbogus = 2\n"),
        format!(
            "{head}{column}[[entry]]\nsurface = \"admission\"\nfrom = \"a\"\nto = \"b\"\noutcome = \"refuse\"\nreason = \"r\"\n"
        ),
        format!(
            "{head}{column}{}",
            column.replace("admission = 1", "admission = 2")
        ),
        "schema = \"other\"\nschema_version = 1\n".to_owned(),
    ] {
        assert!(
            matches!(Matrix::read(&text), Err(CompatError::Matrix(_))),
            "{text}"
        );
    }
    assert!(matches!(
        side_of(&matrix().unwrap(), "column:nope"),
        Err(CompatError::UnknownColumn(_))
    ));
}

/// The decision object names its schema, both columns and every surface.
#[test]
fn the_decision_is_one_json_object() {
    let matrix = matrix().unwrap();
    let main = this_side();
    let json = decide(&matrix, &main, &main).json();
    assert!(
        json.starts_with(r#"{"schema":"karyos-compat-decision","schema_version":1,"from":"main","to":"main","outcome":"interoperate","#),
        "{json}"
    );
    assert_eq!(json.lines().count(), 1);
    // The decider's own output reads back as JSON.
    assert!(parse(&json).is_ok());
    for (surface, _) in SURFACES {
        assert!(
            json.contains(&format!("\"surface\":\"{surface}\"")),
            "{surface}"
        );
    }
}

/// The subcommand: a decision with its exit status, and a typed error
/// (status 3) for an input it cannot read.
#[test]
fn the_subcommand_exits_by_outcome() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = run(["column:main", "column:main"], &mut out, &mut err);
    assert_eq!(status, EXIT_INTEROPERATE);
    assert!(String::from_utf8_lossy(&out).contains("\"outcome\":\"interoperate\""));
    out.clear();
    assert_eq!(
        run(["column:main", "column:0.1.0-alpha.2"], &mut out, &mut err),
        EXIT_REFUSE
    );
    assert_eq!(run(["column:main"], &mut out, &mut err), EXIT_ERROR);
    assert_eq!(
        run(["column:main", "/nonexistent.json"], &mut out, &mut err),
        EXIT_ERROR
    );
    assert_eq!(
        run(["column:main", "column:nope"], &mut out, &mut err),
        EXIT_ERROR
    );
    assert!(String::from_utf8_lossy(&err).contains("no column"));
}

mod properties {
    use proptest::prelude::*;

    use super::super::{Json, MAX_DEPTH, escape, parse};

    /// A JSON value within the reader's depth, its object keys unique.
    fn value() -> impl Strategy<Value = Json> {
        let leaf = prop_oneof![
            Just(Json::Null),
            any::<bool>().prop_map(Json::Bool),
            any::<u64>().prop_map(Json::Integer),
            any::<String>().prop_map(Json::String),
        ];
        // One level for the outer object, the rest below it.
        leaf.prop_recursive(u32::try_from(MAX_DEPTH - 1).unwrap(), 64, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Json::Array),
                prop::collection::btree_map(any::<String>(), inner, 0..6)
                    .prop_map(|fields| Json::Object(fields.into_iter().collect())),
            ]
        })
    }

    /// `json` as text, written independently of the reader.
    fn text(json: &Json) -> String {
        match json {
            Json::Null => "null".to_owned(),
            Json::Bool(value) => value.to_string(),
            Json::Integer(value) => value.to_string(),
            Json::String(value) => format!("\"{}\"", escape(value)),
            Json::Array(items) => {
                format!("[{}]", items.iter().map(text).collect::<Vec<_>>().join(","))
            }
            Json::Object(fields) => format!(
                "{{{}}}",
                fields
                    .iter()
                    .map(|(key, value)| format!("\"{}\":{}", escape(key), text(value)))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }

    proptest! {
        /// Any bounded text, read as untrusted input, is a value or a
        /// typed error, never a panic.
        #[test]
        fn arbitrary_text_never_panics(input in "\\PC{0,4096}") {
            let _ = parse(&input);
        }

        /// Text made of JSON's own characters, which reaches deeper into
        /// the reader than arbitrary text does, never panics either.
        #[test]
        fn json_like_text_never_panics(input in r#"[\[\]{}",:0-9a-z\\ .eE+-]{0,2048}"#) {
            let _ = parse(&input);
        }

        /// A generated object within the bounds reads back as itself.
        #[test]
        fn a_generated_object_round_trips(
            fields in prop::collection::btree_map(any::<String>(), value(), 0..6)
        ) {
            let json = Json::Object(fields.into_iter().collect());
            let written = text(&json);
            prop_assume!(written.len() <= super::super::MAX_BYTES);
            prop_assert_eq!(parse(&written), Ok(json));
        }
    }
}
