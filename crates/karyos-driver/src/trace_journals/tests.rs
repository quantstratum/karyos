// SPDX-License-Identifier: Apache-2.0

//! The trace journal region's tests that run in one process
//! (`quantstratum-docs: karyos/design/trace-journal-region.md`, Tests):
//! in-process clients get heap journals; the remote path, which needs
//! journal regions, is tested on Linux in `tests/trace_journals.rs`.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::BTreeSet;

use karyos_client::{ClientConductor, ClientJournal, ConductorError, Outcome};
use karyos_protocol::cnc::ErrorCode;
use karyos_sys::counters::CellRead;
use karyos_sys::record_journal::{Append, JournalLayout, Stamp};
use karyos_sys::trace_mirror::{EntryRead, JournalEntry, JournalState};

use super::journal_bytes;
use crate::{DriverConfig, DriverError, EmbeddedDriver};

const LAYOUT: JournalLayout = JournalLayout {
    capacity: 4,
    payload_words: 2,
    drop_ranges: 2,
};

fn driver(entries: usize, records: usize, budget: usize) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        max_trace_journals: entries,
        trace_mirror_records: records,
        trace_drain_budget: budget,
        ..DriverConfig::default()
    })
    .unwrap()
}

fn stamp(time: u64) -> Stamp {
    Stamp {
        time,
        clock: 1,
        epoch: 1,
    }
}

/// Submits `submit`, runs one duty cycle and returns the outcome.
fn complete(
    driver: &mut EmbeddedDriver,
    conductor: &mut ClientConductor,
    submit: impl FnOnce(&mut ClientConductor) -> Result<u64, ConductorError>,
) -> Outcome {
    let sequence = submit(conductor).unwrap();
    let _ = driver.do_work().unwrap();
    let mut outcome = None;
    let _ = conductor.poll(usize::MAX, |completion| {
        assert_eq!(completion.sequence, sequence);
        outcome = Some(completion.outcome);
    });
    outcome.unwrap()
}

fn request(
    driver: &mut EmbeddedDriver,
    conductor: &mut ClientConductor,
    layout: JournalLayout,
) -> Outcome {
    complete(driver, conductor, |conductor| {
        conductor.trace_journal(layout)
    })
}

fn journal(driver: &mut EmbeddedDriver, conductor: &mut ClientConductor) -> ClientJournal {
    match request(driver, conductor, LAYOUT) {
        Outcome::Journal(journal) => journal,
        other => panic!("expected a journal, got {other:?}"),
    }
}

fn refused(outcome: &Outcome) -> ErrorCode {
    match outcome {
        Outcome::Refused { code, .. } => *code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn append(journal: &mut ClientJournal, values: impl IntoIterator<Item = u64>) -> Vec<Append> {
    values
        .into_iter()
        .map(|value| journal.writer().append(&[value, 0], stamp(value)).unwrap())
        .collect()
}

/// The table as a tool reads it.
fn entries(driver: &EmbeddedDriver) -> Vec<JournalEntry> {
    let reader = driver.trace_mirror();
    (0..reader.entries())
        .filter_map(|index| match reader.entry(index) {
            EntryRead::Entry(entry) => Some(entry),
            EntryRead::Free => None,
            EntryRead::Busy => panic!("entry {index} busy"),
        })
        .collect()
}

fn entry(driver: &EmbeddedDriver, journal: u64) -> JournalEntry {
    entries(driver)
        .into_iter()
        .find(|entry| entry.journal == journal)
        .unwrap()
}

/// A mirrored record: ring sequence, journal, journal sequence, first
/// payload word.
type Mirrored = (u64, u64, u64, u64);

fn scan(driver: &EmbeddedDriver, cursor: &mut u64) -> (u64, Vec<Mirrored>) {
    let mut seen = Vec::new();
    let scan = driver.trace_mirror().scan(cursor, |record| {
        assert_eq!(record.payload.len(), 2);
        seen.push((
            record.seq,
            record.journal,
            record.sequence,
            record.payload[0],
        ));
    });
    assert_eq!(scan.stopped, None);
    (scan.overwritten, seen)
}

fn counter(driver: &EmbeddedDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

/// The writer appends, the driver drains and mirrors, and a reader sees
/// every stored record with its journal sequence and the drops of the full
/// journal as a gap, with the loss accounting in the table. The boundary of
/// `CloseJournal` reaches the table, and the entry becomes closed once the
/// closed journal is drained to its end.
#[test]
fn a_journal_is_drained_into_the_mirror_with_its_drops() {
    let mut driver = driver(4, 64, 64);
    let mut conductor = driver.connect().unwrap();
    let client = conductor.owner().client;
    let mut journal = journal(&mut driver, &mut conductor);
    let number = journal.journal();
    assert_eq!(number, 1, "the first trace number");
    let opened = entry(&driver, number);
    assert_eq!(
        (
            opened.client,
            opened.state,
            opened.payload_words,
            opened.capacity
        ),
        (client, JournalState::Open, 2, 4)
    );
    assert_eq!(counter(&driver, "trace journals open"), 1);
    // Four fit; two are dropped before the driver drains.
    let appended = append(&mut journal, 0..6);
    assert!(matches!(appended[4], Append::Dropped { sequence: 4 }));
    let _ = driver.do_work().unwrap();
    append(&mut journal, [9]);
    let _ = driver.do_work().unwrap();
    let mut cursor = 0;
    let (overwritten, seen) = scan(&driver, &mut cursor);
    assert_eq!(overwritten, 0);
    let sequences: Vec<(u64, u64, u64)> = seen
        .iter()
        .map(|&(_, journal, sequence, value)| (journal, sequence, value))
        .collect();
    assert_eq!(
        sequences,
        [(1, 0, 0), (1, 1, 1), (1, 2, 2), (1, 3, 3), (1, 6, 9)],
        "the gap 4..6 is the journal's own loss"
    );
    let drained = entry(&driver, number);
    assert_eq!(
        (drained.attempted, drained.stored, drained.mirrored),
        (7, 5, 5)
    );
    assert_eq!(drained.last_record, Some(4));
    assert_eq!(drained.ranges().len(), 1);
    assert_eq!(
        (drained.ranges()[0].first, drained.ranges()[0].last),
        (4, 5)
    );
    assert_eq!(counter(&driver, "trace records mirrored"), 5);

    // The boundary, then the close.
    let closed = complete(&mut driver, &mut conductor, |conductor| {
        conductor.close_journal(number, 4096)
    });
    assert!(matches!(closed, Outcome::Succeeded));
    let bounded = entry(&driver, number);
    assert_eq!(
        (bounded.state, bounded.boundary),
        (JournalState::Open, Some(4096))
    );
    append(&mut journal, [10]);
    drop(journal);
    let _ = driver.do_work().unwrap();
    let ended = entry(&driver, number);
    assert_eq!(
        (ended.state, ended.boundary, ended.mirrored),
        (JournalState::Closed, Some(4096), 6)
    );
    assert_eq!(counter(&driver, "trace journals open"), 0);
    let (_, seen) = scan(&driver, &mut cursor);
    assert_eq!(seen, [(5, 1, 7, 10)]);
}

/// A mirror overwrite is mirror loss, proven by the ring's boundary and
/// counted as such; the journal's own accounting shows no loss.
#[test]
fn a_mirror_overwrite_is_mirror_loss_never_journal_loss() {
    let mut driver = driver(2, 2, 64);
    let mut conductor = driver.connect().unwrap();
    let mut journal = journal(&mut driver, &mut conductor);
    append(&mut journal, 0..4);
    let _ = driver.do_work().unwrap();
    let (overwritten, seen) = scan(&driver, &mut 0);
    assert_eq!(overwritten, 2, "ring records 0 and 1 are mirror loss");
    assert_eq!(
        seen.iter().map(|record| record.2).collect::<Vec<_>>(),
        [2, 3]
    );
    let entry = entry(&driver, journal.journal());
    assert_eq!((entry.attempted, entry.stored, entry.mirrored), (4, 4, 4));
    assert!(entry.ranges().is_empty());
    assert_eq!(entry.lost_before, None);
    assert_eq!(counter(&driver, "trace mirror overwritten"), 2);
}

/// A reader that starts after the ring wrapped still finds every journal
/// in the table, with its state, although the ring retains none of the
/// first journal's records.
#[test]
fn a_reader_after_the_ring_wrapped_sees_every_journal() {
    let mut driver = driver(4, 2, 64);
    let mut conductor = driver.connect().unwrap();
    let mut first = journal(&mut driver, &mut conductor);
    let mut second = journal(&mut driver, &mut conductor);
    append(&mut first, 0..2);
    let _ = driver.do_work().unwrap();
    append(&mut second, 0..3);
    let _ = driver.do_work().unwrap();
    let (_, seen) = scan(&driver, &mut 0);
    assert!(seen.iter().all(|record| record.1 == second.journal()));
    let bounds = driver.trace_mirror().bounds().unwrap();
    let table = entries(&driver);
    assert_eq!(table.len(), 2);
    let old = table
        .iter()
        .find(|entry| entry.journal == first.journal())
        .unwrap();
    assert_eq!(old.state, JournalState::Open);
    assert!(old.last_record.unwrap() < bounds.first);
    assert_eq!(old.mirrored, 2);
}

/// Short-lived journals churn through a table of two entries with a
/// reader scanning throughout: an ended entry is reused only after the
/// ring dropped its last record, every retained record's journal is in the
/// table, and a request while every entry is still covered is refused with
/// `TraceJournalsExhausted` and creates nothing.
#[test]
fn ended_journals_churn_through_a_small_table() {
    let mut driver = driver(2, 4, 64);
    let mut conductor = driver.connect().unwrap();
    let mut cursor = 0;
    // The reader's check: each scanned record still retained has its
    // journal in the table it reads after the scan.
    let check = |driver: &EmbeddedDriver, cursor: &mut u64| {
        let (_, seen) = scan(driver, cursor);
        let first = driver.trace_mirror().bounds().unwrap().first;
        let table: BTreeSet<u64> = entries(driver).iter().map(|entry| entry.journal).collect();
        for record in seen.iter().filter(|record| record.0 >= first) {
            assert!(table.contains(&record.1), "{record:?} without its entry");
        }
    };
    let mut a = journal(&mut driver, &mut conductor);
    let mut b = journal(&mut driver, &mut conductor);
    assert_eq!(
        refused(&request(&mut driver, &mut conductor, LAYOUT)),
        ErrorCode::TraceJournalsExhausted
    );
    append(&mut a, [1]);
    let _ = driver.do_work().unwrap();
    check(&driver, &mut cursor);
    // Closed and drained, but the ring still holds its record.
    let a_number = a.journal();
    drop(a);
    let _ = driver.do_work().unwrap();
    assert_eq!(entry(&driver, a_number).state, JournalState::Closed);
    assert_eq!(
        refused(&request(&mut driver, &mut conductor, LAYOUT)),
        ErrorCode::TraceJournalsExhausted
    );
    check(&driver, &mut cursor);
    // Four more records push it out of the ring: its entry is free again.
    append(&mut b, 0..4);
    let _ = driver.do_work().unwrap();
    check(&driver, &mut cursor);
    let mut c = journal(&mut driver, &mut conductor);
    // Refusals assigned no trace number.
    assert_eq!(c.journal(), 3);
    let table: Vec<u64> = entries(&driver).iter().map(|entry| entry.journal).collect();
    assert_eq!(table.len(), 2);
    assert!(table.contains(&3) && table.contains(&b.journal()));
    append(&mut c, [7]);
    let _ = driver.do_work().unwrap();
    check(&driver, &mut cursor);
}

/// A hostile journal (a `head` past its capacity, an impossible sequence,
/// a changed record length) faults its client without a panic: a `client
/// protocol violation` keyed by the client and the journal, its entry
/// writer lost, and no more draining; the client's other journals keep
/// being drained.
#[test]
fn a_hostile_journal_faults_its_client_without_a_panic() {
    let mut driver = driver(8, 64, 64);
    let mut conductor = driver.connect().unwrap();
    let client = conductor.owner().client;
    let mut good = journal(&mut driver, &mut conductor);
    // Words of the block: geometry 0..16, head at 16; records at 96, three
    // words each, the sequence first.
    let corruptions: [(usize, u64); 3] = [(16, 99), (96, u64::MAX), (2, 5)];
    for (case, (index, value)) in corruptions.into_iter().enumerate() {
        let mut bad = journal(&mut driver, &mut conductor);
        append(&mut bad, [1, 2]);
        let words = driver
            .trace_journals
            .slots
            .iter()
            .flatten()
            .find(|held| held.entry.journal == bad.journal())
            .and_then(|held| held.drain.as_ref())
            .unwrap()
            .hostile_words();
        words[index].store(value, std::sync::atomic::Ordering::Release);
        append(&mut good, [case as u64]);
        let _ = driver.do_work().unwrap();
        let faulted = entry(&driver, bad.journal());
        assert_eq!(faulted.state, JournalState::WriterLost, "case {case}");
        assert_eq!(faulted.mirrored, 0, "case {case}");
        assert_eq!(counter(&driver, "trace journal faults"), case as u64 + 1);
        let mut found = false;
        let _ = driver.error_log().scan(&mut 0, |record| {
            found |= record.code == crate::diagnostics::ErrorCode::ClientProtocolViolation as u32
                && record.key == [client, bad.journal()];
        });
        assert!(found, "case {case}");
        // Nothing more is drained from it.
        append(&mut bad, [3]);
        let _ = driver.do_work().unwrap();
        assert_eq!(entry(&driver, bad.journal()).mirrored, 0);
    }
    assert_eq!(entry(&driver, good.journal()).mirrored, 3);
    assert_eq!(entry(&driver, good.journal()).state, JournalState::Open);
}

/// Flooding journals never exceed `trace_drain_budget` records per duty
/// cycle, and every journal is drained in turn.
#[test]
fn the_drain_budget_bounds_each_cycle_and_rotates() {
    let mut driver = driver(3, 64, 4);
    let mut conductor = driver.connect().unwrap();
    let mut journals: Vec<ClientJournal> = (0..3)
        .map(|_| journal(&mut driver, &mut conductor))
        .collect();
    for journal in &mut journals {
        append(journal, 0..4);
    }
    let mut cursor = 0;
    let mut drained = BTreeSet::new();
    for cycle in 1..=3u64 {
        let _ = driver.do_work().unwrap();
        assert_eq!(counter(&driver, "trace records mirrored"), 4 * cycle);
        let (_, seen) = scan(&driver, &mut cursor);
        let cycle_journals: BTreeSet<u64> = seen.iter().map(|record| record.1).collect();
        assert_eq!(cycle_journals.len(), 1, "one flooding journal per cycle");
        drained.extend(cycle_journals);
    }
    assert_eq!(drained.len(), 3, "every journal was drained in turn");
    // Refilled journals keep rotating: never more than the budget.
    for journal in &mut journals {
        append(journal, 4..8);
    }
    for _ in 0..3 {
        let before = counter(&driver, "trace records mirrored");
        let _ = driver.do_work().unwrap();
        assert!(counter(&driver, "trace records mirrored") - before <= 4);
    }
}

/// Sizes the mirror cannot hold and journals beyond the bytes budget are
/// refused, and nothing is created: no entry, no trace number.
#[test]
fn the_budget_and_the_sizes_refuse_without_creating() {
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        max_trace_journals: 4,
        max_trace_journal_bytes: journal_bytes(&LAYOUT).unwrap(),
        ..DriverConfig::default()
    })
    .unwrap();
    let mut conductor = driver.connect().unwrap();
    let held = journal(&mut driver, &mut conductor);
    for layout in [
        LAYOUT,
        JournalLayout {
            payload_words: 28,
            ..LAYOUT
        },
        JournalLayout {
            drop_ranges: 9,
            ..LAYOUT
        },
    ] {
        assert_eq!(
            refused(&request(&mut driver, &mut conductor, layout)),
            ErrorCode::ResourcesUnavailable,
            "{layout:?}"
        );
    }
    assert_eq!(entries(&driver).len(), 1);
    // The bytes come back once the journal ended.
    drop(held);
    let _ = driver.do_work().unwrap();
    let next = journal(&mut driver, &mut conductor);
    assert_eq!(next.journal(), 2);
    // Sizes the driver would refuse to decode are not even sent.
    assert_eq!(
        conductor.trace_journal(JournalLayout {
            capacity: 3,
            ..LAYOUT
        }),
        Err(ConductorError::InvalidJournal)
    );
    assert_eq!(
        conductor.close_journal(0, 1),
        Err(ConductorError::InvalidJournal)
    );
    for config in [
        DriverConfig {
            max_trace_journals: 0,
            ..DriverConfig::default()
        },
        DriverConfig {
            max_trace_journal_bytes: 0,
            ..DriverConfig::default()
        },
        DriverConfig {
            trace_drain_budget: 0,
            ..DriverConfig::default()
        },
        DriverConfig {
            trace_mirror_records: 0,
            ..DriverConfig::default()
        },
    ] {
        assert!(matches!(
            EmbeddedDriver::with_config(config),
            Err(DriverError::InvalidConfig)
        ));
    }
}

/// `CloseJournal` sets the boundary of the client's own open journal once;
/// another client's, a second one and an unknown journal are refused with
/// `UnknownRegistration` and change nothing.
#[test]
fn close_journal_sets_the_boundary_of_its_own_journal_once() {
    let mut driver = driver(4, 64, 64);
    let mut owner = driver.connect().unwrap();
    let mut other = driver.connect().unwrap();
    let journal = journal(&mut driver, &mut owner);
    let number = journal.journal();
    let close = |driver: &mut EmbeddedDriver,
                 conductor: &mut ClientConductor,
                 journal: u64,
                 boundary: u64| {
        complete(driver, conductor, |conductor| {
            conductor.close_journal(journal, boundary)
        })
    };
    assert_eq!(
        refused(&close(&mut driver, &mut other, number, 1)),
        ErrorCode::UnknownRegistration
    );
    assert_eq!(
        refused(&close(&mut driver, &mut owner, number + 7, 1)),
        ErrorCode::UnknownRegistration
    );
    assert!(matches!(
        close(&mut driver, &mut owner, number, 2),
        Outcome::Succeeded
    ));
    assert_eq!(
        refused(&close(&mut driver, &mut owner, number, 3)),
        ErrorCode::UnknownRegistration
    );
    assert_eq!(entry(&driver, number).boundary, Some(2));
}

/// J4: when a journal's writer is gone (a remote client's grant ended),
/// the driver drains what is committed and marks the entry writer lost,
/// without a boundary; a writer that had closed its journal ends it closed.
#[test]
fn a_gone_writer_is_drained_and_marked_writer_lost() {
    let mut driver = driver(4, 64, 64);
    let mut conductor = driver.connect().unwrap();
    let mut open = journal(&mut driver, &mut conductor);
    let mut closed = journal(&mut driver, &mut conductor);
    append(&mut open, 0..3);
    append(&mut closed, 0..2);
    closed.writer().close();
    for journal in [open.journal(), closed.journal()] {
        driver
            .trace_journals
            .writer_gone(journal, &mut driver.diagnostics, &mut driver.counters);
    }
    let lost = entry(&driver, open.journal());
    assert_eq!(
        (lost.state, lost.boundary, lost.mirrored),
        (JournalState::WriterLost, None, 3)
    );
    let ended = entry(&driver, closed.journal());
    assert_eq!((ended.state, ended.mirrored), (JournalState::Closed, 2));
    // The writer's later records are never drained.
    append(&mut open, [9]);
    let _ = driver.do_work().unwrap();
    assert_eq!(entry(&driver, open.journal()).mirrored, 3);
    assert_eq!(counter(&driver, "trace journals open"), 0);
}

/// A dropped client conductor drops the journal writers it never took:
/// their journals close and end closed.
#[test]
fn an_untaken_journal_ends_with_its_client() {
    let mut driver = driver(4, 64, 64);
    let mut conductor = driver.connect().unwrap();
    let _ = conductor.trace_journal(LAYOUT).unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(entries(&driver)[0].state, JournalState::Open);
    drop(conductor);
    let _ = driver.do_work().unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(entries(&driver)[0].state, JournalState::Closed);
}
