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
use karyos_sys::trace_mirror::{
    EntryRead, JournalEntry, JournalKind, JournalState, LogRead, MAX_RECYCLE_PAIRS, NotedPublisher,
    RecycledJournal, TimeNamespace,
};

use super::journal_bytes;
use crate::embedded::FIRST_INCARNATION;
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

/// The provenance word the tests send: opaque to the driver.
const PROVENANCE: u64 = 0xC10C;

fn request(
    driver: &mut EmbeddedDriver,
    conductor: &mut ClientConductor,
    layout: JournalLayout,
    registration: u64,
) -> Outcome {
    complete(driver, conductor, |conductor| {
        conductor.trace_journal(layout, registration, PROVENANCE)
    })
}

/// A journal observing `registration`, a live registration of
/// `conductor`'s client.
fn journal(
    driver: &mut EmbeddedDriver,
    conductor: &mut ClientConductor,
    registration: u64,
) -> ClientJournal {
    match request(driver, conductor, LAYOUT, registration) {
        Outcome::Journal(journal) => journal,
        other => panic!("expected a journal, got {other:?}"),
    }
}

/// A client with a live publication on a new test stream, whose
/// registration its publisher journals name: (conductor, publication
/// handle, registration).
fn publisher(
    driver: &mut EmbeddedDriver,
) -> (ClientConductor, karyos_client::ClientPublication, u64) {
    let _ = stream(driver);
    let mut conductor = driver.connect().unwrap();
    let (publication, registration) = publish(driver, &mut conductor);
    (conductor, publication, registration)
}

/// The exclusive publication of the test stream for `conductor`'s client,
/// with its registration.
fn publish(
    driver: &mut EmbeddedDriver,
    conductor: &mut ClientConductor,
) -> (karyos_client::ClientPublication, u64) {
    let outcome = complete(driver, conductor, |conductor| {
        conductor.add_publication(KEY, true)
    });
    let Outcome::Publication(publication) = outcome else {
        panic!("expected a publication, got {outcome:?}");
    };
    let registration = publication.origin().unwrap().registration();
    (publication, registration)
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
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let client = conductor.owner().client;
    let mut journal = journal(&mut driver, &mut conductor, publication);
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
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let mut journal = journal(&mut driver, &mut conductor, publication);
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
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let mut first = journal(&mut driver, &mut conductor, publication);
    let mut second = journal(&mut driver, &mut conductor, publication);
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
    let (mut conductor, _publication, publication) = publisher(&mut driver);
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
    let mut a = journal(&mut driver, &mut conductor, publication);
    let mut b = journal(&mut driver, &mut conductor, publication);
    assert_eq!(
        refused(&request(&mut driver, &mut conductor, LAYOUT, publication)),
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
        refused(&request(&mut driver, &mut conductor, LAYOUT, publication)),
        ErrorCode::TraceJournalsExhausted
    );
    check(&driver, &mut cursor);
    // Four more records push it out of the ring: its entry is free again.
    append(&mut b, 0..4);
    let _ = driver.do_work().unwrap();
    check(&driver, &mut cursor);
    let mut c = journal(&mut driver, &mut conductor, publication);
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
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let client = conductor.owner().client;
    let mut good = journal(&mut driver, &mut conductor, publication);
    // Words of the block: geometry 0..16, head at 16; records at 96, three
    // words each, the sequence first.
    let corruptions: [(usize, u64); 3] = [(16, 99), (96, u64::MAX), (2, 5)];
    for (case, (index, value)) in corruptions.into_iter().enumerate() {
        let mut bad = journal(&mut driver, &mut conductor, publication);
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
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let mut journals: Vec<ClientJournal> = (0..3)
        .map(|_| journal(&mut driver, &mut conductor, publication))
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
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let held = journal(&mut driver, &mut conductor, publication);
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
            refused(&request(&mut driver, &mut conductor, layout, publication)),
            ErrorCode::ResourcesUnavailable,
            "{layout:?}"
        );
    }
    assert_eq!(entries(&driver).len(), 1);
    // The bytes come back once the journal ended.
    drop(held);
    let _ = driver.do_work().unwrap();
    let next = journal(&mut driver, &mut conductor, publication);
    assert_eq!(next.journal(), 2);
    // Sizes the driver would refuse to decode are not even sent.
    assert_eq!(
        conductor.trace_journal(
            JournalLayout {
                capacity: 3,
                ..LAYOUT
            },
            publication,
            0
        ),
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
        DriverConfig {
            trace_recycle_log_entries: 0,
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
    let (mut owner, _publication, publication) = publisher(&mut driver);
    let mut other = driver.connect().unwrap();
    let journal = journal(&mut driver, &mut owner, publication);
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
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let mut open = journal(&mut driver, &mut conductor, publication);
    let mut closed = journal(&mut driver, &mut conductor, publication);
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

/// A drop the writer records after the driver's last read reaches the
/// entry: at the next cycle of an idle open journal (its attempted count
/// moved), and at the final visit of a gone writer (review of #135).
#[test]
fn a_drop_after_the_last_read_reaches_the_entry() {
    // A late drop: the writer raises the attempted count after the read,
    // with nothing pending. Words: geometry 0..16, then the control words,
    // the attempted count at control word 32.
    fn late_drop(driver: &EmbeddedDriver, journal: u64) {
        driver
            .trace_journals
            .slots
            .iter()
            .flatten()
            .find(|held| held.entry.journal == journal)
            .and_then(|held| held.drain.as_ref())
            .unwrap()
            .hostile_words()[16 + 32]
            .store(3, std::sync::atomic::Ordering::Release);
    }
    let mut driver = driver(4, 64, 64);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let mut idle = journal(&mut driver, &mut conductor, publication);
    let mut gone = journal(&mut driver, &mut conductor, publication);
    append(&mut idle, 0..2);
    append(&mut gone, 0..2);
    let _ = driver.do_work().unwrap();
    assert_eq!(entry(&driver, idle.journal()).attempted, 2);
    // An open idle journal shows it at the next cycle.
    late_drop(&driver, idle.journal());
    let _ = driver.do_work().unwrap();
    assert_eq!(entry(&driver, idle.journal()).attempted, 3);
    assert_eq!(entry(&driver, idle.journal()).state, JournalState::Open);
    // A gone writer's last drop, after the last cycle, reaches the final
    // entry through the final visit.
    assert_eq!(entry(&driver, gone.journal()).attempted, 2);
    late_drop(&driver, gone.journal());
    driver.trace_journals.writer_gone(
        gone.journal(),
        &mut driver.diagnostics,
        &mut driver.counters,
    );
    let lost = entry(&driver, gone.journal());
    assert_eq!((lost.state, lost.attempted), (JournalState::WriterLost, 3));
}

/// A dropped client conductor drops the journal writers it never took:
/// their journals close and end closed.
#[test]
fn an_untaken_journal_ends_with_its_client() {
    let mut driver = driver(4, 64, 64);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let _ = conductor.trace_journal(LAYOUT, publication, 0).unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(entries(&driver)[0].state, JournalState::Open);
    drop(conductor);
    let _ = driver.do_work().unwrap();
    let _ = driver.do_work().unwrap();
    assert_eq!(entries(&driver)[0].state, JournalState::Closed);
}

/// A stream that accepts offers without a subscriber, so that a later
/// subscription joins at a nonzero position.
fn stream(driver: &mut EmbeddedDriver) -> crate::StreamHandle {
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;
    driver
        .add_stream(crate::StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                // Room for the spare-slot credits of two optional readers.
                spare_slots: 8,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 5,
                claim_deadline: 100,
                publication: PublicationMode::Exclusive,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .unwrap()
}

const KEY: karyos_protocol::cnc::StreamKey = karyos_protocol::cnc::StreamKey {
    stream_id: 5,
    session_id: 1,
};

/// A subscription of `conductor`'s client on the test stream, with its
/// registration.
fn subscribe(
    driver: &mut EmbeddedDriver,
    conductor: &mut ClientConductor,
) -> (karyos_client::ClientSubscription, u64) {
    let outcome = complete(driver, conductor, |conductor| {
        conductor.add_subscription(KEY, karyos_protocol::cnc::SubscriberRole::Optional)
    });
    let Outcome::Subscription(subscription) = outcome else {
        panic!("expected a subscription, got {outcome:?}");
    };
    let registration = subscription.origin().unwrap().registration();
    (subscription, registration)
}

/// The time namespace word of an in-process client: the driver's own on
/// Linux, unknown elsewhere (T2).
fn own_namespace() -> TimeNamespace {
    if cfg!(target_os = "linux") {
        TimeNamespace::Same
    } else {
        TimeNamespace::Unknown
    }
}

/// T4: a journal derives its kind from the registration it names. One
/// naming the sender's live subscription is a subscriber journal with the
/// subscription, its stream, the incarnation and the join position the
/// driver recorded when it registered the subscription (here past
/// messages published before it joined); one naming the sender's live
/// publication is a publisher journal of the same publication without a
/// join, which a reader tells apart from a join at 0. Both carry the
/// provenance word as sent and the time namespace word.
#[test]
fn a_journal_derives_its_kind_from_the_named_registration() {
    let mut driver = driver(4, 64, 64);
    let handle = stream(&mut driver);
    let stream_registration = driver.trace_identity(handle).unwrap().registration;
    let mut conductor = driver.connect().unwrap();
    let (mut publication, publication_registration) = publish(&mut driver, &mut conductor);
    for _ in 0..3 {
        assert!(matches!(
            publication.offer(b"before the join").unwrap(),
            karyos_client::OfferOutcome::Accepted { .. }
        ));
    }
    let (subscription, registration) = subscribe(&mut driver, &mut conductor);
    let joined = subscription.position();
    assert!(joined > 0, "the subscription joined after three messages");
    // Messages after the join do not move the recorded join.
    let _ = publication.offer(b"after the join").unwrap();
    let observing = journal(&mut driver, &mut conductor, registration);
    let observed = entry(&driver, observing.journal());
    assert_eq!(
        (
            observed.kind,
            observed.registration,
            observed.stream,
            observed.incarnation,
            observed.join
        ),
        (
            JournalKind::Subscriber,
            registration,
            stream_registration,
            FIRST_INCARNATION,
            Some(joined)
        )
    );
    assert_eq!(
        (observed.provenance, observed.time_namespace),
        (PROVENANCE, own_namespace())
    );
    let publishing = journal(&mut driver, &mut conductor, publication_registration);
    let publisher = entry(&driver, publishing.journal());
    assert_eq!(
        (
            publisher.kind,
            publisher.registration,
            publisher.stream,
            publisher.incarnation,
            publisher.join
        ),
        (
            JournalKind::Publisher,
            publication_registration,
            stream_registration,
            FIRST_INCARNATION,
            None
        )
    );
    assert_eq!(
        (publisher.provenance, publisher.time_namespace),
        (PROVENANCE, own_namespace())
    );
    // Registration 0 names nothing: refused before it is sent.
    assert_eq!(
        conductor.trace_journal(LAYOUT, 0, PROVENANCE),
        Err(ConductorError::InvalidJournal)
    );
}

/// A journal naming another client's subscription or publication, an
/// ended subscription or publication, or a registration that never existed
/// is refused with `UnknownRegistration`, and nothing is created: no table
/// entry, no bytes charged, no trace number, no hand-over writer.
#[test]
fn a_journal_of_a_registration_that_is_not_the_senders_live_one_creates_nothing() {
    fn refused_unknown(
        driver: &mut EmbeddedDriver,
        requester: &mut ClientConductor,
        case: &str,
        registration: u64,
    ) {
        match request(driver, requester, LAYOUT, registration) {
            Outcome::Refused { code, detail } => {
                assert_eq!(
                    (code, detail),
                    (ErrorCode::UnknownRegistration, registration),
                    "{case}"
                );
            }
            other => panic!("{case}: expected a refusal, got {other:?}"),
        }
        assert!(entries(driver).is_empty(), "{case}");
        assert_eq!(driver.trace_journals.bytes, 0, "{case}");
        assert_eq!(driver.next_trace_number, 1, "{case}");
    }
    let mut driver = driver(4, 64, 64);
    let _ = stream(&mut driver);
    let mut owner = driver.connect().unwrap();
    let mut other = driver.connect().unwrap();
    // The publication first: subscribers are admitted once the stream has
    // its publication.
    let (publication, publication_registration) = publish(&mut driver, &mut other);
    let (_kept, foreign) = subscribe(&mut driver, &mut owner);
    let (ended, ended_registration) = subscribe(&mut driver, &mut other);
    drop(ended);
    let _ = driver.do_work().unwrap();
    for (case, by_owner, registration) in [
        ("another client's subscription", false, foreign),
        ("an ended subscription", false, ended_registration),
        (
            "another client's publication",
            true,
            publication_registration,
        ),
        ("a registration never issued", false, 999),
    ] {
        let requester = if by_owner { &mut owner } else { &mut other };
        refused_unknown(&mut driver, requester, case, registration);
    }
    drop(publication);
    let _ = driver.do_work().unwrap();
    refused_unknown(
        &mut driver,
        &mut other,
        "an ended publication",
        publication_registration,
    );
    // The next journal is the first one created.
    let created = journal(&mut driver, &mut owner, foreign);
    assert_eq!(created.journal(), 1);
    assert_eq!(entries(&driver).len(), 1);
}

fn driver_with_log(entries: usize, records: usize, log: usize) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        max_trace_journals: entries,
        trace_mirror_records: records,
        trace_recycle_log_entries: log,
        ..DriverConfig::default()
    })
    .unwrap()
}

/// The recycle log as a tool reads it.
fn logged(driver: &EmbeddedDriver) -> Vec<RecycledJournal> {
    let reader = driver.trace_mirror();
    (0..reader.log_entries())
        .filter_map(|index| match reader.log_entry(index) {
            LogRead::Entry(entry) => Some(entry),
            LogRead::Free => None,
            LogRead::Busy => panic!("log entry {index} busy"),
        })
        .collect()
}

/// Ends `journal` closed as a gone writer does, before the next drain.
fn end(driver: &mut EmbeddedDriver, journal: &mut ClientJournal) {
    journal.writer().close();
    driver.trace_journals.writer_gone(
        journal.journal(),
        &mut driver.diagnostics,
        &mut driver.counters,
    );
}

/// T5: a subscriber journal mirrored before a `Publish` it could be
/// expected for, ended while that `Publish` was still in its journal and
/// recycled while it is retained, leaves a recycle log entry with its
/// publication, boundary and the noted publisher journal; a publisher
/// journal created after it ended is not noted; the log entry is dropped
/// only once the ring no longer retains the noted journal's records below
/// its noted attempted count.
#[test]
fn recycling_a_subscriber_entry_logs_it_until_covered() {
    let mut driver = driver(3, 4, 64);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let (_subscription, subscription) = subscribe(&mut driver, &mut conductor);
    let mut publishing = journal(&mut driver, &mut conductor, publication);
    let mut observing = journal(&mut driver, &mut conductor, subscription);
    let observed = observing.journal();
    // Its record is mirrored first (ring 0), then its boundary is given.
    append(&mut observing, [1]);
    let _ = driver.do_work().unwrap();
    let closed = complete(&mut driver, &mut conductor, |conductor| {
        conductor.close_journal(observed, 4096)
    });
    assert!(matches!(closed, Outcome::Succeeded));
    // Two `Publish` records are attempted before it ends, and drained only
    // after it ended.
    append(&mut publishing, [10, 11]);
    end(&mut driver, &mut observing);
    assert_eq!(entry(&driver, observed).state, JournalState::Closed);
    // A publisher journal of the publication created after it ended.
    let mut late = journal(&mut driver, &mut conductor, publication);
    // The two `Publish` records reach ring 1 and 2; two later records push
    // the subscriber journal's own record out of the ring.
    let _ = driver.do_work().unwrap();
    append(&mut publishing, [12, 13]);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 1);
    assert!(logged(&driver).is_empty(), "nothing recycled yet");
    // The table is full: its entry is reused, and logged first.
    let _next = journal(&mut driver, &mut conductor, publication);
    assert!(
        entries(&driver)
            .iter()
            .all(|entry| entry.journal != observed)
    );
    let stream = entry(&driver, publishing.journal()).stream;
    let log = logged(&driver);
    assert_eq!(log.len(), 1);
    assert_eq!(
        (
            log[0].journal,
            log[0].stream,
            log[0].incarnation,
            log[0].state,
            log[0].boundary
        ),
        (
            observed,
            stream,
            FIRST_INCARNATION,
            JournalState::Closed,
            Some(4096)
        )
    );
    assert_eq!(
        log[0].pairs(),
        [NotedPublisher {
            journal: publishing.journal(),
            attempted: 2
        }],
        "the later publisher journal is not noted"
    );
    // The log entry keeps the recycled journal's mirror sequence (T7).
    assert_eq!(log[0].sequence, 2);
    // Ring 2, the last noted `Publish`, is still retained: kept.
    append(&mut late, [20]);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 2);
    assert_eq!(logged(&driver).len(), 1);
    // Once it is gone the entry is covered: dropped.
    append(&mut late, [21]);
    let _ = driver.do_work().unwrap();
    assert!(logged(&driver).is_empty());
}

/// Ends subscriber journals with two `Publish` records of `publishing`
/// still undrained, then pushes their own records out of a ring of four
/// while the noted `Publish` records stay retained.
fn end_before_publish(
    driver: &mut EmbeddedDriver,
    publishing: &mut ClientJournal,
    observing: &mut [ClientJournal],
) {
    for journal in observing.iter_mut() {
        append(journal, [1]);
    }
    let _ = driver.do_work().unwrap();
    append(publishing, [10, 11]);
    for journal in observing.iter_mut() {
        end(driver, journal);
    }
    let _ = driver.do_work().unwrap();
    append(publishing, [12, 13]);
    let _ = driver.do_work().unwrap();
}

/// T5: with the recycle log full, an entry that needs a log entry is not
/// reused, and a `TraceJournal` that finds no other free entry is refused
/// with `TraceJournalsExhausted` and creates nothing; once the logged
/// entry is covered the log entry is dropped and recycling resumes.
#[test]
fn a_full_recycle_log_stops_recycling() {
    let mut driver = driver_with_log(4, 4, 1);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let (_subscription, subscription) = subscribe(&mut driver, &mut conductor);
    let mut publishing = journal(&mut driver, &mut conductor, publication);
    let mut observing: Vec<ClientJournal> = (0..3)
        .map(|_| journal(&mut driver, &mut conductor, subscription))
        .collect();
    end_before_publish(&mut driver, &mut publishing, &mut observing);
    // Ring 3 and 4 hold the noted `Publish` records; ring 0 to 2, the
    // subscriber journals' records, are gone.
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 3);
    let _first = journal(&mut driver, &mut conductor, publication);
    assert_eq!(logged(&driver).len(), 1);
    let number = driver.next_trace_number;
    assert_eq!(
        refused(&request(&mut driver, &mut conductor, LAYOUT, publication)),
        ErrorCode::TraceJournalsExhausted
    );
    assert_eq!(driver.next_trace_number, number, "nothing created");
    assert_eq!(entries(&driver).len(), 4);
    assert_eq!(logged(&driver).len(), 1);
    // The noted records leave the ring: every ended entry is covered.
    append(&mut publishing, [14, 15]);
    let _ = driver.do_work().unwrap();
    assert!(logged(&driver).is_empty());
    let _second = journal(&mut driver, &mut conductor, publication);
    assert!(logged(&driver).is_empty(), "a covered entry needs no log");
}

/// T5: a subscriber journal whose publication had more publisher journals
/// in the table than a log entry holds is never logged: its entry is not
/// reused until it is covered, even with the log empty.
#[test]
fn too_many_noted_journals_wait_until_covered() {
    let mut driver = driver(MAX_RECYCLE_PAIRS + 2, 4, 64);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let (_subscription, subscription) = subscribe(&mut driver, &mut conductor);
    let mut publishers: Vec<ClientJournal> = (0..=MAX_RECYCLE_PAIRS)
        .map(|_| journal(&mut driver, &mut conductor, publication))
        .collect();
    let mut observing = [journal(&mut driver, &mut conductor, subscription)];
    end_before_publish(&mut driver, &mut publishers[0], &mut observing);
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 1);
    assert_eq!(
        refused(&request(&mut driver, &mut conductor, LAYOUT, publication)),
        ErrorCode::TraceJournalsExhausted
    );
    assert!(logged(&driver).is_empty());
    // Ring 2, the last noted `Publish`, leaves the ring: covered.
    append(&mut publishers[0], [14, 15]);
    let _ = driver.do_work().unwrap();
    let _reused = journal(&mut driver, &mut conductor, publication);
    assert!(
        entries(&driver)
            .iter()
            .all(|entry| entry.journal != observing[0].journal())
    );
    assert!(logged(&driver).is_empty());
}

/// T5: a noted publisher journal whose `Publish` records are still
/// undrained at the cycles after the subscriber journal ended (a drain
/// budget of one record) does not count as drained: the recycle log entry
/// stays until the drain released the noted stored count and the ring
/// dropped those records, and only then is dropped.
#[test]
fn an_undrained_noted_journal_keeps_the_log_entry() {
    let mut driver = driver(2, 2, 1);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let (_subscription, subscription) = subscribe(&mut driver, &mut conductor);
    let mut publishing = journal(&mut driver, &mut conductor, publication);
    let mut observing = journal(&mut driver, &mut conductor, subscription);
    let observed = observing.journal();
    append(&mut observing, [1]);
    let _ = driver.do_work().unwrap();
    assert_eq!(entry(&driver, observed).last_record, Some(0));
    // Four `Publish` records are stored when it ends, none drained.
    append(&mut publishing, 10..14);
    end(&mut driver, &mut observing);
    // One record per cycle: ring 1 and 2, which push out ring 0.
    for _ in 0..2 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(entry(&driver, publishing.journal()).mirrored, 2);
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 1);
    // Its entry is reused and logged; the cycle of the request drains
    // ring 3, and two noted records are still in the journal or retained.
    let mut late = journal(&mut driver, &mut conductor, publication);
    assert!(
        entries(&driver)
            .iter()
            .all(|entry| entry.journal != observed)
    );
    assert_eq!(entry(&driver, publishing.journal()).mirrored, 3);
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 2);
    assert_eq!(logged(&driver).len(), 1, "a noted record is undrained");
    // The last noted record reaches ring 4: drained, but retained.
    let _ = driver.do_work().unwrap();
    assert_eq!(entry(&driver, publishing.journal()).mirrored, 4);
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 3);
    assert_eq!(logged(&driver).len(), 1, "ring 4 is retained");
    append(&mut late, [20]);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 4);
    assert_eq!(logged(&driver).len(), 1, "ring 4 is retained");
    // Once ring 4 is gone the entry is covered: dropped.
    append(&mut late, [21]);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 5);
    assert!(logged(&driver).is_empty());
}

/// T5 refinement: a noted publisher journal that dropped records below
/// its noted attempted count (its journal full) counts as drained once the
/// drain released its noted stored count, while it stays open: the
/// subscriber journal becomes covered and its log entry is dropped.
#[test]
fn a_noted_journal_that_dropped_records_still_drains() {
    let mut driver = driver(2, 2, 64);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let (_subscription, subscription) = subscribe(&mut driver, &mut conductor);
    let mut publishing = journal(&mut driver, &mut conductor, publication);
    let mut observing = journal(&mut driver, &mut conductor, subscription);
    let observed = observing.journal();
    append(&mut observing, [1]);
    let _ = driver.do_work().unwrap();
    // Four fit; two are dropped: attempted 6, stored 4 when it ends.
    let appended = append(&mut publishing, 10..16);
    assert!(matches!(appended[4], Append::Dropped { .. }));
    end(&mut driver, &mut observing);
    // Ring 1 to 4; ring 3 and 4 retained.
    let _ = driver.do_work().unwrap();
    let noted = entry(&driver, publishing.journal());
    assert_eq!((noted.attempted, noted.stored, noted.mirrored), (6, 4, 4));
    assert_eq!(noted.state, JournalState::Open);
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 3);
    // Its entry is reused while ring 4 is retained: logged.
    let mut late = journal(&mut driver, &mut conductor, publication);
    assert!(
        entries(&driver)
            .iter()
            .all(|entry| entry.journal != observed)
    );
    assert_eq!(logged(&driver).len(), 1);
    // A later publisher journal, not noted, pushes ring 4 out; the noted
    // journal stays open and never reaches its attempted count.
    append(&mut late, [20, 21]);
    let _ = driver.do_work().unwrap();
    assert_eq!(driver.trace_mirror().bounds().unwrap().first, 5);
    assert_eq!(entry(&driver, publishing.journal()).mirrored, 4);
    assert!(
        logged(&driver).is_empty(),
        "covered once the stored count is released"
    );
}

/// T7 (ACS 13973): the mirror sequence numbers the journals the driver
/// created densely from 1. Trace numbers drawn by the application,
/// registrations and refused `TraceJournal` requests (an unknown
/// registration, sizes the mirror cannot hold, a full table) do not
/// advance it, though some of them advance the journal number.
#[test]
fn mirror_sequences_are_dense_over_created_journals() {
    let mut driver = driver(3, 64, 64);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    let first = journal(&mut driver, &mut conductor, publication);
    for _ in 0..3 {
        let _ = driver.next_trace_number().unwrap();
    }
    let (_subscription, subscription) = subscribe(&mut driver, &mut conductor);
    assert_eq!(
        refused(&request(
            &mut driver,
            &mut conductor,
            LAYOUT,
            subscription + 1000
        )),
        ErrorCode::UnknownRegistration
    );
    let oversized = JournalLayout {
        payload_words: karyos_sys::trace_mirror::MAX_MIRROR_PAYLOAD + 1,
        ..LAYOUT
    };
    assert_eq!(
        refused(&request(
            &mut driver,
            &mut conductor,
            oversized,
            publication
        )),
        ErrorCode::ResourcesUnavailable
    );
    // The header's high-water mark moved with the first journal only.
    assert_eq!(driver.trace_mirror().assigned_sequence(), 1);
    let second = journal(&mut driver, &mut conductor, subscription);
    let _ = driver.next_trace_number().unwrap();
    let third = journal(&mut driver, &mut conductor, publication);
    assert_eq!(
        refused(&request(&mut driver, &mut conductor, LAYOUT, publication)),
        ErrorCode::TraceJournalsExhausted
    );
    // The journal numbers skip the trace numbers drawn in between.
    assert!(second.journal() > first.journal() + 1);
    assert!(third.journal() > second.journal() + 1);
    let sequences: Vec<(u64, u64)> = [&first, &second, &third]
        .iter()
        .map(|journal| {
            (
                journal.journal(),
                entry(&driver, journal.journal()).sequence,
            )
        })
        .collect();
    assert_eq!(
        sequences
            .iter()
            .map(|(_, sequence)| *sequence)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(driver.trace_mirror().assigned_sequence(), 3);
}

/// The journal sequence is checked (SPEC.md §14): when the next one would
/// not fit, the journal is refused and nothing is created; the last
/// sequence is still handed out.
#[test]
fn an_exhausted_journal_sequence_refuses_without_creating() {
    let mut driver = driver(4, 64, 64);
    let (mut conductor, _publication, publication) = publisher(&mut driver);
    driver.trace_journals.next_sequence = u64::MAX;
    assert_eq!(
        refused(&request(&mut driver, &mut conductor, LAYOUT, publication)),
        ErrorCode::TraceJournalsExhausted
    );
    assert!(entries(&driver).is_empty());
    assert_eq!(driver.trace_journals.next_sequence, u64::MAX);
    assert_eq!(driver.trace_journals.bytes, 0);
    driver.trace_journals.next_sequence = u64::MAX - 1;
    let _journal = journal(&mut driver, &mut conductor, publication);
    assert_eq!(entries(&driver)[0].sequence, u64::MAX - 1);
    assert_eq!(driver.trace_journals.next_sequence, u64::MAX);
    assert_eq!(driver.trace_journals.bytes, journal_bytes(&LAYOUT).unwrap());
}

/// Releasing a journal's bytes is checked: a charge larger than what is
/// held goes to zero explicitly and counts one counter overflow.
#[test]
fn releasing_more_bytes_than_held_counts_an_overflow() {
    let driver = driver(4, 64, 64);
    let overflows = counter(&driver, "counter overflows");
    assert_eq!(super::release(5, 3, &driver.counters), 2);
    assert_eq!(counter(&driver, "counter overflows"), overflows);
    assert_eq!(super::release(2, 3, &driver.counters), 0);
    assert_eq!(counter(&driver, "counter overflows"), overflows + 1);
}

/// Journals of an aggregate carry their lane in the mirror (entry word 69,
/// `aggregate-ownership.md`): every lane names the aggregate's
/// registration, and a subscriber journal that ends notes only the
/// publisher journals of its own lane.
#[test]
fn journals_pair_within_their_lane() {
    use karyos_protocol::cnc::{StreamKey, SubscriberRole};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;
    let mut driver = driver(4, 64, 64);
    let key = StreamKey {
        stream_id: 6,
        session_id: 1,
    };
    let aggregate = driver
        .add_aggregate(crate::embedded::AggregateConfig {
            stream: crate::StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                    spare_slots: 8,
                    max_subscribers: 4,
                    mtu: DEFAULT_MTU,
                    max_reserved: MIN_TERM_LENGTH / 8,
                    initial_term_id: TermId::new(7),
                    lane: Lane::ZERO,
                    session_id: key.session_id,
                    stream_id: key.stream_id,
                    claim_deadline: 100,
                    publication: PublicationMode::Exclusive,
                },
                allow_unconnected: true,
                on_required_loss: LossPolicy::Hold,
                conflation: None,
            },
            quanta: vec![u64::from(DEFAULT_MTU.next_multiple_of(32)); 2],
        })
        .unwrap();
    let lane = |number| Lane::try_new(number).unwrap();
    let registration = driver
        .trace_identity(aggregate.lane(lane(0)).unwrap())
        .unwrap()
        .registration;
    let mut conductor = driver.connect().unwrap();
    let publication_on = |driver: &mut EmbeddedDriver, conductor: &mut ClientConductor, number| {
        let outcome = complete(driver, conductor, |conductor| {
            conductor.add_publication_on_lane(key, lane(number), true)
        });
        let Outcome::Publication(publication) = outcome else {
            panic!("expected a publication, got {outcome:?}");
        };
        let registration = publication.origin().unwrap().registration();
        (publication, registration)
    };
    let (_zero, publication_zero) = publication_on(&mut driver, &mut conductor, 0);
    let (_one, publication_one) = publication_on(&mut driver, &mut conductor, 1);
    let outcome = complete(&mut driver, &mut conductor, |conductor| {
        conductor.add_subscription_on_lane(key, lane(1), SubscriberRole::Optional)
    });
    let Outcome::Subscription(subscription) = outcome else {
        panic!("expected a subscription, got {outcome:?}");
    };
    let subscription_one = subscription.origin().unwrap().registration();
    let publishing_zero = journal(&mut driver, &mut conductor, publication_zero);
    let publishing_one = journal(&mut driver, &mut conductor, publication_one);
    let mut observing = journal(&mut driver, &mut conductor, subscription_one);
    for (journal, number) in [(&publishing_zero, 0), (&publishing_one, 1), (&observing, 1)] {
        let found = entry(&driver, journal.journal());
        assert_eq!((found.stream, found.lane), (registration, lane(number)));
    }
    let observed = observing.journal();
    end(&mut driver, &mut observing);
    let _ = driver.do_work().unwrap();
    let notes: Vec<u64> = driver
        .trace_journals
        .slots
        .iter()
        .flatten()
        .find(|held| held.entry.journal == observed)
        .and_then(|held| held.notes.as_ref())
        .unwrap()
        .iter()
        .map(|note| note.journal)
        .collect();
    assert_eq!(notes, [publishing_one.journal()]);
}
