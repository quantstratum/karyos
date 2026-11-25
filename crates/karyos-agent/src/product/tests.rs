// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

use super::*;

/// The contract's two requests parse into their fields; anything off the
/// form does not.
#[test]
fn appends_and_imports_take_the_contracts_form() {
    assert_eq!(
        parse(
            "request durable 7 market-ops halt-venue 00000000deadbeef log:4711 operator asked",
            false
        ),
        Some(ProductAppend {
            phase: Phase::Request,
            durable: true,
            operation: 7,
            service: "market-ops",
            command: "halt-venue",
            value: 0xdead_beef,
            correlation: "log:4711",
            reason: "operator asked",
            import: None,
        })
    );
    assert_eq!(
        parse("outcome ordinary 7 market-ops halt-venue 0 log:4712", false),
        Some(ProductAppend {
            phase: Phase::Outcome,
            durable: false,
            operation: 7,
            service: "market-ops",
            command: "halt-venue",
            value: 0,
            correlation: "log:4712",
            reason: "",
            import: None,
        })
    );
    assert_eq!(
        parse(
            "4096 1700000000 request 9 market-ops resume 0123456789abcdef l:1",
            true
        ),
        Some(ProductAppend {
            phase: Phase::Request,
            durable: true,
            operation: 9,
            service: "market-ops",
            command: "resume",
            value: 0x0123_4567_89ab_cdef,
            correlation: "l:1",
            reason: "",
            import: Some(Import {
                interval: 4096,
                time: 1_700_000_000
            }),
        })
    );
    let long = "n".repeat(MAX_NAME + 1);
    let far = "c".repeat(MAX_CORRELATION + 1);
    for (arguments, import) in [
        ("", false),
        ("request durable 7 svc cmd 00000000deadbeef", false),
        ("request maybe 7 svc cmd 00000000deadbeef l", false),
        ("request durable x svc cmd 00000000deadbeef l", false),
        ("request durable +7 svc cmd 00000000deadbeef l", false),
        ("request durable 7 svc cmd deadbeef l", false),
        ("request durable 7 s/v cmd 00000000deadbeef l", false),
        (
            &format!("request durable 7 {long} cmd 00000000deadbeef l"),
            false,
        ),
        (
            &format!("request durable 7 svc cmd 00000000deadbeef {far}"),
            false,
        ),
        ("outcome durable 7 svc cmd -1 l", false),
        ("question durable 7 svc cmd 0 l", false),
        ("request durable 7 svc  cmd 00000000deadbeef l", false),
        // An import takes no durability word, and needs its two numbers.
        ("4096 1 request durable 9 svc cmd 0123456789abcdef l", true),
        ("4096 request 9 svc cmd 0123456789abcdef l", true),
    ] {
        assert_eq!(parse(arguments, import), None, "{arguments}");
    }
}

/// Each append is its kind of record, with the requester and relay
/// apart, the value in a request's digest or an outcome's code, and an
/// import's interval and time.
#[test]
fn an_append_is_recorded_with_its_fields() {
    let append = parse(
        "request durable 7 market-ops halt-venue 00000000deadbeef log:4711 why",
        false,
    )
    .unwrap();
    let record = append.record(Requester::relayed(1001, 3), 55);
    assert_eq!(record.kind, Kind::ProductRequest);
    assert_eq!(
        (record.time, record.operation, record.operator, record.relay),
        (55, 7, 1001, 3)
    );
    assert_eq!((record.parameters, record.code), (0xdead_beef, 0));
    assert_eq!(
        (
            record.target.as_slice(),
            record.command.as_slice(),
            record.evidence.as_slice(),
            record.reason.as_slice()
        ),
        (
            b"market-ops".as_slice(),
            b"halt-venue".as_slice(),
            b"log:4711".as_slice(),
            b"why".as_slice()
        )
    );
    // It reads back as itself.
    assert_eq!(JournalRecord::decode(&record.encode()), Some(record));

    let outcome = parse(
        "outcome ordinary 7 market-ops halt-venue 12 log:4712",
        false,
    )
    .unwrap();
    let record = outcome.record(Requester::local(1001), 56);
    assert_eq!(record.kind, Kind::ProductOutcome);
    assert_eq!((record.parameters, record.code, record.relay), (0, 12, 0));
    assert!(!outcome.waits());

    let import = parse(
        "4096 1700 outcome 7 market-ops halt-venue 12 log:4712",
        true,
    )
    .unwrap();
    let record = import.record(Requester::local(1001), 57);
    assert_eq!(record.kind, Kind::ProductOutcomeImported);
    assert_eq!((record.expected, record.word), (4096, 1700));
    assert!(import.waits());
    assert_eq!(JournalRecord::decode(&record.encode()), Some(record));
}
