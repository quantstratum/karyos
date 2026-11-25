// SPDX-License-Identifier: Apache-2.0

//! R-CORE-42's acceptance criteria (karyos#773): a product service's
//! records in the operations journal, through the agent.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;

use super::*;
use crate::journal::{HISTORY_MAX, Kind};
use crate::product::{ProductAnswer, parse};
use crate::server::Role;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-agent-product-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn agent(dir: &std::path::Path) -> Agent {
    Agent::new(AgentConfig::new(Vec::new()).with_journal(dir.join("journal")))
}

fn append(agent: &mut Agent, line: &str) -> ProductAnswer {
    agent.journal_append(&parse(line, false).unwrap(), Requester::local(1001))
}

fn import(line: &str) -> crate::product::ProductAppend<'_> {
    parse(line, true).unwrap()
}

/// The product records in the journal's history, oldest first.
fn product_records(agent: &mut Agent) -> Vec<crate::journal::JournalRecord> {
    agent
        .journal_history(None, HISTORY_MAX)
        .unwrap()
        .records
        .into_iter()
        .filter_map(|record| record.record)
        .filter(|record| record.kind.is_product())
        .collect()
}

/// Only a service and an administrator may append a product's records.
#[test]
fn only_a_service_or_an_administrator_may_append() {
    for (role, may) in [
        ("viewer", false),
        ("operator", false),
        ("risk-officer", false),
        ("registrar", false),
        ("service", true),
        ("administrator", true),
    ] {
        assert_eq!(Role::parse(role).unwrap().may_append(), may, "{role}");
    }
    let agent = agent(&dir("capability"));
    let served = |append: bool| {
        agent
            .capabilities(false, false, false, false, append)
            .into_iter()
            .find(|capability| capability.name == "journal-append")
            .unwrap()
            .state
    };
    assert_eq!(served(true), crate::api::CapabilityState::Served);
    assert_eq!(
        served(false),
        crate::api::CapabilityState::Forbidden { reason: "role" }
    );
}

/// A service appends a request and its outcome under one operation id,
/// durably or not; the history serves both with their fields, and
/// nothing in them is interpreted.
#[test]
fn a_request_and_its_outcome_are_journalled_under_one_operation_id() {
    let dir = dir("append");
    let mut agent = agent(&dir);
    let ProductAnswer::Journalled {
        durable: true,
        position,
        ..
    } = append(
        &mut agent,
        "request durable 7 market-ops halt-venue 00000000deadbeef log:4711 risk up",
    )
    else {
        panic!("not journalled");
    };
    let outcome = append(
        &mut agent,
        "outcome ordinary 7 market-ops halt-venue 3 log:4712",
    );
    assert!(
        matches!(
            outcome,
            ProductAnswer::Journalled {
                durable: false,
                position: after,
                ..
            } if after > position
        ),
        "{outcome:?}"
    );
    // The history serves durable records: the ordinary outcome once the
    // journal is settled, as it is before every view.
    assert_eq!(product_records(&mut agent).len(), 1);
    agent.settle_journal();
    let records = product_records(&mut agent);
    assert_eq!(
        records.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [Kind::ProductRequest, Kind::ProductOutcome]
    );
    assert!(records.iter().all(|record| record.operation == 7
        && record.operator == 1001
        && record.target == b"market-ops"
        && record.command == b"halt-venue"));
    assert_eq!((records[0].parameters, records[1].code), (0xdead_beef, 3));
    assert_eq!(records[1].evidence, b"log:4712");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A durable append that cannot be made durable is refused and records
/// nothing, so a fail-closed command is never sent unrecorded; an
/// ordinary one is refused the same, and the product goes ahead.
#[test]
fn a_durable_append_that_cannot_be_durable_is_refused() {
    let dir = dir("refused");
    let mut agent = agent(&dir);
    agent.journal.as_mut().unwrap().break_recorder();
    assert_eq!(
        append(
            &mut agent,
            "request durable 8 market-ops widen-limits 00000000000000aa log:1"
        ),
        ProductAnswer::JournalUnavailable
    );
    assert_eq!(
        append(
            &mut agent,
            "request ordinary 9 market-ops halt 00000000000000bb log:2"
        ),
        ProductAnswer::JournalUnavailable
    );
    drop(agent);
    let mut agent = self::agent(&dir);
    assert!(product_records(&mut agent).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// After an outage the journal shows its unknown interval; the product
/// imports what it kept by operation id, naming the interval, which stays
/// visible until an administrator acknowledges it. An import that names
/// no unknown interval is refused.
#[test]
fn records_made_during_an_outage_are_imported_by_operation_id() {
    let dir = dir("import");
    let mut agent = agent(&dir);
    agent.journal.as_mut().unwrap().break_recorder();
    // A safety-reducing command goes ahead unrecorded.
    assert_eq!(
        append(
            &mut agent,
            "request ordinary 9 market-ops halt 00000000000000bb log:2"
        ),
        ProductAnswer::JournalUnavailable
    );
    drop(agent);
    let mut agent = self::agent(&dir);
    let gap = agent.view().journal.unwrap().gap.unwrap();
    // A position that is no unknown interval.
    let wrong = gap.position + 32;
    assert_eq!(
        agent.journal_append(
            &import(&format!(
                "{wrong} 1700 request 9 market-ops halt 00000000000000bb log:2"
            )),
            Requester::local(1001)
        ),
        ProductAnswer::NotAnInterval { position: wrong }
    );
    for line in [
        format!(
            "{} 1700 request 9 market-ops halt 00000000000000bb log:2",
            gap.position
        ),
        format!("{} 1701 outcome 9 market-ops halt 0 log:3", gap.position),
    ] {
        assert!(matches!(
            agent.journal_append(&import(&line), Requester::local(1001)),
            ProductAnswer::Journalled { durable: true, .. }
        ));
    }
    let records = product_records(&mut agent);
    assert_eq!(
        records.iter().map(|record| record.kind).collect::<Vec<_>>(),
        [Kind::ProductRequestImported, Kind::ProductOutcomeImported]
    );
    assert!(
        records
            .iter()
            .all(|record| record.operation == 9 && record.expected == gap.position)
    );
    assert_eq!((records[0].word, records[1].word), (1700, 1701));
    // The interval stays visible until an administrator acknowledges it.
    assert_eq!(agent.view().journal.unwrap().gap, Some(gap));
    let _ = agent
        .acknowledge_gap_for(gap.position, Requester::local(0))
        .unwrap();
    assert_eq!(agent.view().journal.unwrap().gap, None);
    let _ = std::fs::remove_dir_all(&dir);
}
