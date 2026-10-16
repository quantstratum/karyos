// SPDX-License-Identifier: Apache-2.0

//! `karyos-trace` against a real driver (Linux; `quantstratum-docs:
//! karyos/design/trace-tool.md` and `trace-journal-region.md`, Tests). An
//! in-test IPC driver serves remote clients of this process (and, for the
//! clock test, of a child process) whose trace journals the driver drains
//! into its trace mirror; a tool attached through P7's tool attach reads
//! the mirror with `MirrorTool` and builds the report:
//!
//! - Batch C of #121: a journal overflows for real; the report reads its
//!   drop ranges from the table and a trace with an observation in a
//!   dropped range is final `Incomplete`;
//! - a mirror overwrite during the tool's life makes the traces it covers
//!   `Incomplete`; a tool attaching later reports them out of scope;
//! - a subscriber journal whose every record was overwritten still makes
//!   its traces `Incomplete`;
//! - a recycled subscriber journal never lets a message be `Complete`;
//! - two processes with host clocks get calibrated latencies, an opaque
//!   clock's are unavailable;
//! - the `karyos-trace` binary reports, follows until the driver exits,
//!   and exits 2 when it cannot attach.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use karyos_client::ipc::{RemoteClient, attach};
use karyos_client::{ClientJournal, Outcome};
use karyos_driver::{
    DriverConfig, EmbeddedDriver, IpcConfig, LossPolicy, StreamConfig, SystemClock,
};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_protocol::journal::{Append, Stamp};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::record_journal::JournalLayout;
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;
use karyos_sys::trace_mirror::{EntryRead, JournalEntry, JournalKind, JournalState};
use karyos_tools::trace::mirror::MirrorTool;
use karyos_trace::{
    ClockProvenance, HostMonotonicClock, ObserverId, Point, PublicationId, RECORD_WORDS,
    SubscriberId, TraceAnswer, TraceClock, TraceIds, TraceRecord, TraceReport, TraceWriter,
    Unavailable, Verdict, trace_writer,
};

/// The child of the clock test: the admission directory.
const CHILD: &str = "KARYOS_TRACE_TOOL_CHILD";
/// The child of the clock test: the publication as
/// `driver high:driver low:stream registration:incarnation`.
const IDENTITY: &str = "KARYOS_TRACE_TOOL_IDENTITY";

const KEY: StreamKey = StreamKey {
    stream_id: 5,
    session_id: 1,
};

const KEY_B: StreamKey = StreamKey {
    stream_id: 6,
    session_id: 1,
};

/// The driver of these tests: IPC mode.
type IpcDriver = EmbeddedDriver<SharedTerms>;

/// A message's length on the stream, for positions.
const STEP: u64 = 64;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-tt-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn stream(key: StreamKey) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            // Each optional subscription takes a spare-slot credit, and the
            // exclusive publication one, below `spare_slots` minus the
            // cleaning headroom: four spare slots admit the publication and
            // the two subscriptions of the clock test's child.
            spare_slots: 4,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: key.session_id,
            stream_id: key.stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: false,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// A driver on the system clock with streams `KEY` and `KEY_B`, its trace
/// mirror sized by `config`; returns it with both publications'
/// identities as records carry them.
fn driver(dir: &Path, config: DriverConfig) -> (IpcDriver, PublicationId, PublicationId) {
    let mut driver = EmbeddedDriver::with_ipc(
        config,
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 4,
            hello_timeout: 5_000_000_000,
            max_outbound_per_client: 16,
            fetch_deadline: 30_000_000_000,
            max_exports_per_client: 32,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap();
    let a = driver.add_stream(stream(KEY)).unwrap();
    let b = driver.add_stream(stream(KEY_B)).unwrap();
    let a = PublicationId::from(driver.trace_identity(a).unwrap());
    let b = PublicationId::from(driver.trace_identity(b).unwrap());
    (driver, a, b)
}

/// The defaults with a trace mirror of `records` ring records, `journals`
/// table entries and `log` recycle log entries.
fn mirror_config(records: usize, journals: usize, log: usize) -> DriverConfig {
    DriverConfig {
        trace_mirror_records: records,
        max_trace_journals: journals,
        trace_recycle_log_entries: log,
        ..DriverConfig::default()
    }
}

/// Serves the driver while `client` runs on another thread; returns its
/// result once it finished.
fn serve_while<R: Send>(driver: &mut IpcDriver, client: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(client);
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "client stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap()
    })
}

/// Duty cycles until `done` or a generous bound passes.
fn serve_until(driver: &mut IpcDriver, mut done: impl FnMut(&IpcDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(30), "timed out");
        let _ = driver.do_work().unwrap();
        std::thread::yield_now();
    }
}

/// The table entry of journal `number`, if the driver holds it.
fn entry(driver: &IpcDriver, number: u64) -> Option<JournalEntry> {
    let reader = driver.trace_mirror();
    (0..reader.entries()).find_map(|index| match reader.entry(index) {
        EntryRead::Entry(entry) if entry.journal == number => Some(entry),
        _ => None,
    })
}

/// Asserts that subscriber journal `number` joined at 0: no data was ever
/// offered on the stream, so every subscription joins at its start and is
/// expected for every message these tests trace before its boundary.
fn joined_at_start(driver: &IpcDriver, number: u64) {
    assert_eq!(entry(driver, number).and_then(|entry| entry.join), Some(0));
}

/// Serves until journal `number` mirrored `count` records.
fn mirrored(driver: &mut IpcDriver, number: u64, count: u64) {
    serve_until(driver, |driver| {
        entry(driver, number).is_some_and(|entry| entry.mirrored == count)
    });
}

/// Serves until journal `number` ended in `state`.
fn ended(driver: &mut IpcDriver, number: u64, state: JournalState) {
    serve_until(driver, |driver| {
        entry(driver, number).is_some_and(|entry| entry.state == state)
    });
}

/// Polls `client` until its next completion is a grant; returns the
/// registration.
fn registration(client: &mut RemoteClient) -> u64 {
    let mut found = None;
    let start = Instant::now();
    while found.is_none() {
        assert!(start.elapsed() < Duration::from_secs(10), "no grant");
        let _ = client.poll(usize::MAX, |completion| match completion.outcome {
            Outcome::Fetchable(grant) => found = Some(grant.registration),
            other => panic!("expected a grant, got {other:?}"),
        });
        std::thread::yield_now();
    }
    found.unwrap()
}

/// The registration of a new publication of `key`; its grant is never
/// fetched.
fn publication(client: &mut RemoteClient, key: StreamKey) -> u64 {
    let _ = client.add_publication(key, false).unwrap();
    registration(client)
}

/// The registration of a new optional subscription of `key`; its grant is
/// never fetched.
fn subscription(client: &mut RemoteClient, key: StreamKey) -> u64 {
    let _ = client
        .add_subscription(key, SubscriberRole::Optional)
        .unwrap();
    registration(client)
}

/// A trace journal of `capacity` records observing `registration`, with
/// the clock `provenance`.
fn journal(
    client: &mut RemoteClient,
    registration: u64,
    capacity: usize,
    provenance: ClockProvenance,
) -> ClientJournal {
    let layout = JournalLayout {
        capacity,
        payload_words: RECORD_WORDS,
        drop_ranges: 2,
    };
    let _ = client
        .trace_journal(layout, registration, provenance.word())
        .unwrap();
    let mut found = None;
    let start = Instant::now();
    while found.is_none() {
        assert!(start.elapsed() < Duration::from_secs(10), "no journal");
        let _ = client.poll(usize::MAX, |completion| match completion.outcome {
            Outcome::FetchableJournal(journal) => found = Some(journal),
            other => panic!("expected a fetchable journal, got {other:?}"),
        });
        std::thread::yield_now();
    }
    client.take_journal(&found.unwrap()).unwrap()
}

/// Gives the driver journal `number`'s final boundary and waits for it.
fn close_journal(client: &mut RemoteClient, number: u64, boundary: u64) {
    let _ = client.close_journal(number, boundary).unwrap();
    let mut done = false;
    let start = Instant::now();
    while !done {
        assert!(start.elapsed() < Duration::from_secs(10), "no answer");
        let _ = client.poll(usize::MAX, |completion| {
            assert!(
                matches!(completion.outcome, Outcome::Succeeded),
                "{:?}",
                completion.outcome
            );
            done = true;
        });
        std::thread::yield_now();
    }
}

/// A journal this process writes trace records to, stamped by the host
/// clock (domain 1, the collection clock).
struct Traced {
    number: u64,
    writer: TraceWriter,
    clock: HostMonotonicClock,
}

impl Traced {
    fn new(journal: ClientJournal, driver: [u64; 2]) -> Self {
        let (number, raw) = journal.into_parts();
        let observer = ObserverId {
            driver,
            journal: number,
        };
        Self {
            number,
            writer: trace_writer(raw, observer, 1).unwrap(),
            clock: HostMonotonicClock::new(1),
        }
    }

    /// Records `point` of the message of `publication` at `position` in
    /// trace `[trace, 1]`.
    fn record(
        &mut self,
        point: Point,
        publication: PublicationId,
        position: u64,
        trace: u64,
    ) -> Append {
        let observed = self.clock.now();
        let record = TraceRecord {
            point,
            publication,
            lane: 0,
            position,
            ids: TraceIds {
                trace_id: [trace, 1],
                span_id: 1,
                parent_span_id: 0,
                message_id: position,
            },
            observed,
            subscriber: (point == Point::SubscriberPoll).then_some(SubscriberId {
                driver: publication.driver,
                registration: 9,
                incarnation: 1,
            }),
            packet: None,
            // Every Publish of these tests starts its own trace.
            root: point == Point::Publish,
        };
        let collected = Stamp {
            time: observed.time,
            clock: observed.clock,
            epoch: observed.epoch,
        };
        self.writer.record(&record, collected).unwrap()
    }
}

fn attach_tool(driver: &mut IpcDriver, dir: &Path) -> karyos_client::tool::RemoteTool {
    serve_while(driver, || {
        karyos_client::tool::attach_tool(dir, Duration::from_secs(5))
    })
    .unwrap()
}

fn answer(report: &TraceReport, trace: u64) -> TraceAnswer {
    report.trace([trace, 1])
}

/// Batch C of #121: a publisher journal of four records overflows for
/// real while the driver does not drain it; the tool reads its drop range
/// from the table, and the traces whose Publish lies in it, like every
/// trace of the journal under `D = u64::MAX`, are final Incomplete.
#[test]
fn a_real_journal_overflow_makes_its_traces_incomplete() {
    let dir = dir("overflow");
    let (mut driver, identity, _) = driver(&dir, DriverConfig::default());
    let driver_id = driver.driver_id();
    let tool = attach_tool(&mut driver, &dir);
    let mut mirror = MirrorTool::new(tool.instance());
    let _ = mirror.scan(tool.trace_mirror());
    let mut client = serve_while(&mut driver, || attach(&dir, Duration::from_secs(5), 16)).unwrap();
    let (mut client, publisher, subscriber) = serve_while(&mut driver, move || {
        let p = publication(&mut client, KEY);
        let s = subscription(&mut client, KEY);
        let host = ClockProvenance::HostMonotonic;
        let publisher = journal(&mut client, p, 4, host);
        let subscriber = journal(&mut client, s, 16, host);
        (client, publisher, subscriber)
    });
    let mut publisher = Traced::new(publisher, driver_id);
    let mut subscriber = Traced::new(subscriber, driver_id);
    joined_at_start(&driver, subscriber.number);
    // The driver is not served: the publisher journal fills and drops.
    let mut dropped = Vec::new();
    for n in 0..8u64 {
        if let Append::Dropped { .. } = publisher.record(Point::Publish, identity, n * STEP, n) {
            dropped.push(n);
        }
        let _ = subscriber.record(Point::SubscriberPoll, identity, n * STEP, n);
    }
    assert_eq!(dropped, [4, 5, 6, 7]);
    let (p, s) = (publisher.number, subscriber.number);
    let client = serve_while(&mut driver, move || {
        close_journal(&mut client, p, 8 * STEP);
        close_journal(&mut client, s, 8 * STEP);
        drop(publisher);
        drop(subscriber);
        client
    });
    ended(&mut driver, p, JournalState::Closed);
    ended(&mut driver, s, JournalState::Closed);

    let _ = mirror.scan(tool.trace_mirror());
    let losses = mirror.losses(p).unwrap();
    assert_eq!((losses.attempted, losses.stored), (8, 4));
    assert_eq!(
        losses
            .ranges
            .iter()
            .map(|range| (range.first, range.last))
            .collect::<Vec<_>>(),
        [(4, 7)]
    );
    assert!(losses.mirror_ranges.is_empty(), "journal loss only");
    assert_eq!(mirror.overwritten(), 0);
    let report = mirror.report().unwrap();
    for n in 4..8 {
        assert_eq!(answer(&report, n), TraceAnswer::Final(Verdict::Incomplete));
    }
    for n in 0..8 {
        assert_ne!(answer(&report, n), TraceAnswer::Final(Verdict::Complete));
    }
    serve_while(&mut driver, move || drop(client));
}

/// A mirror overwrite during the tool's life: the subscriber's polls of
/// messages 4 to 11 are overwritten before the tool's next scan, which
/// reports them as mirror loss and the traces Incomplete. A tool that
/// attaches afterwards sees those messages' Publish records but none of
/// the subscriber journal's: they are out of its scope.
#[test]
fn a_mirror_overwrite_is_incomplete_and_a_later_tool_out_of_scope() {
    let dir = dir("overwrite");
    let (mut driver, identity, _) = driver(&dir, mirror_config(8, 8, 4));
    let driver_id = driver.driver_id();
    let early = attach_tool(&mut driver, &dir);
    let mut following = MirrorTool::new(early.instance());
    let _ = following.scan(early.trace_mirror());
    let mut client = serve_while(&mut driver, || attach(&dir, Duration::from_secs(5), 16)).unwrap();
    let (mut client, publisher, subscriber) = serve_while(&mut driver, move || {
        let p = publication(&mut client, KEY);
        let s = subscription(&mut client, KEY);
        let host = ClockProvenance::HostMonotonic;
        let publisher = journal(&mut client, p, 64, host);
        let subscriber = journal(&mut client, s, 64, host);
        (client, publisher, subscriber)
    });
    let mut publisher = Traced::new(publisher, driver_id);
    let mut subscriber = Traced::new(subscriber, driver_id);
    joined_at_start(&driver, subscriber.number);
    let (p, s) = (publisher.number, subscriber.number);
    for n in 0..4u64 {
        let _ = subscriber.record(Point::SubscriberPoll, identity, n * STEP, n);
    }
    mirrored(&mut driver, s, 4);
    for n in 0..4u64 {
        let _ = publisher.record(Point::Publish, identity, n * STEP, n);
    }
    mirrored(&mut driver, p, 4);
    let first = following.scan(early.trace_mirror());
    assert_eq!((first.delivered, first.overwritten), (8, 0));
    // Eight polls, then eight Publish records that overwrite them before
    // the tool scans again.
    for n in 4..12u64 {
        let _ = subscriber.record(Point::SubscriberPoll, identity, n * STEP, n);
    }
    mirrored(&mut driver, s, 12);
    for n in 4..12u64 {
        let _ = publisher.record(Point::Publish, identity, n * STEP, n);
    }
    mirrored(&mut driver, p, 12);
    let client = serve_while(&mut driver, move || {
        close_journal(&mut client, p, 12 * STEP);
        close_journal(&mut client, s, 12 * STEP);
        drop(publisher);
        drop(subscriber);
        client
    });
    ended(&mut driver, p, JournalState::Closed);
    ended(&mut driver, s, JournalState::Closed);

    let scan = following.scan(early.trace_mirror());
    assert_eq!(scan.overwritten, 8);
    let losses = following.losses(s).unwrap();
    assert!(losses.ranges.is_empty(), "never journal loss");
    assert_eq!(losses.mirror_ranges, [(4, 11)]);
    let report = following.report().unwrap();
    for n in 0..12 {
        assert_eq!(
            answer(&report, n),
            TraceAnswer::Final(Verdict::Incomplete),
            "trace {n}"
        );
    }

    let late = attach_tool(&mut driver, &dir);
    let mut later = MirrorTool::new(late.instance());
    let _ = later.scan(late.trace_mirror());
    let report = later.report().unwrap();
    for n in 4..12 {
        assert_eq!(answer(&report, n), TraceAnswer::OutOfScope, "trace {n}");
    }
    serve_while(&mut driver, move || drop(client));
}

/// A subscriber journal whose only record was overwritten before any scan
/// read it still makes the trace it was expected in Incomplete: its entry
/// names the publication, its join and its boundary.
#[test]
fn a_subscriber_journal_with_every_record_overwritten_still_counts() {
    let dir = dir("every");
    let (mut driver, identity, _) = driver(&dir, mirror_config(4, 8, 4));
    let driver_id = driver.driver_id();
    let tool = attach_tool(&mut driver, &dir);
    let mut mirror = MirrorTool::new(tool.instance());
    let _ = mirror.scan(tool.trace_mirror());
    let mut client = serve_while(&mut driver, || attach(&dir, Duration::from_secs(5), 16)).unwrap();
    let (mut client, publisher, subscriber) = serve_while(&mut driver, move || {
        let p = publication(&mut client, KEY);
        let s = subscription(&mut client, KEY);
        let host = ClockProvenance::HostMonotonic;
        let publisher = journal(&mut client, p, 16, host);
        let subscriber = journal(&mut client, s, 16, host);
        (client, publisher, subscriber)
    });
    let mut publisher = Traced::new(publisher, driver_id);
    let mut subscriber = Traced::new(subscriber, driver_id);
    joined_at_start(&driver, subscriber.number);
    let (p, s) = (publisher.number, subscriber.number);
    let _ = subscriber.record(Point::SubscriberPoll, identity, 0, 1);
    mirrored(&mut driver, s, 1);
    // Messages past the subscription's boundary push its poll, and only
    // it, out of the ring of four, then the Publish of the first message
    // is mirrored.
    for n in 2..5u64 {
        let _ = publisher.record(Point::Publish, identity, n * STEP, n);
    }
    let _ = publisher.record(Point::Publish, identity, 0, 1);
    mirrored(&mut driver, p, 4);
    let client = serve_while(&mut driver, move || {
        close_journal(&mut client, p, 5 * STEP);
        close_journal(&mut client, s, STEP);
        drop(publisher);
        drop(subscriber);
        client
    });
    ended(&mut driver, p, JournalState::Closed);
    ended(&mut driver, s, JournalState::Closed);
    let _ = mirror.scan(tool.trace_mirror());
    assert_eq!(mirror.losses(s).unwrap().mirror_ranges, [(0, 0)]);
    let report = mirror.report().unwrap();
    assert_eq!(answer(&report, 1), TraceAnswer::Final(Verdict::Incomplete));
    // The other messages had no subscription expected: Complete.
    assert_eq!(answer(&report, 2), TraceAnswer::Final(Verdict::Complete));
    serve_while(&mut driver, move || drop(client));
}

/// A subscriber journal mirrored before a message's Publish, ended and
/// recycled while that Publish is retained (a table of three entries, a
/// ring of four records): a tool attaching after the recycle, and one that
/// scanned before the journal existed and next after its table life, both
/// report the message out of scope, never Complete.
#[test]
fn a_recycled_subscriber_journal_never_lets_a_message_be_complete() {
    let dir = dir("recycle");
    let (mut driver, identity, other) = driver(&dir, mirror_config(4, 3, 2));
    let driver_id = driver.driver_id();
    let early = attach_tool(&mut driver, &dir);
    let mut following = MirrorTool::new(early.instance());
    let _ = following.scan(early.trace_mirror());
    let mut client = serve_while(&mut driver, || attach(&dir, Duration::from_secs(5), 16)).unwrap();
    let (mut client, publisher, subscriber, filler, f) = serve_while(&mut driver, move || {
        let p = publication(&mut client, KEY);
        let s = subscription(&mut client, KEY);
        let f = publication(&mut client, KEY_B);
        let host = ClockProvenance::HostMonotonic;
        let publisher = journal(&mut client, p, 16, host);
        let subscriber = journal(&mut client, s, 16, host);
        let filler = journal(&mut client, f, 16, host);
        (client, publisher, subscriber, filler, f)
    });
    let mut publisher = Traced::new(publisher, driver_id);
    let mut subscriber = Traced::new(subscriber, driver_id);
    joined_at_start(&driver, subscriber.number);
    let mut filler = Traced::new(filler, driver_id);
    let (p, s, fj) = (publisher.number, subscriber.number, filler.number);
    let _ = subscriber.record(Point::SubscriberPoll, identity, 0, 1);
    mirrored(&mut driver, s, 1);
    for n in 0..4u64 {
        let _ = filler.record(Point::Publish, other, n * STEP, 10 + n);
    }
    mirrored(&mut driver, fj, 4);
    let _ = publisher.record(Point::Publish, identity, 0, 1);
    mirrored(&mut driver, p, 1);
    // The subscription ends after the Publish was attempted.
    let mut client = serve_while(&mut driver, move || {
        close_journal(&mut client, s, STEP);
        drop(subscriber);
        client
    });
    ended(&mut driver, s, JournalState::Closed);
    // A fourth journal reuses the subscriber's entry, logging it.
    let (mut client, extra) = serve_while(&mut driver, move || {
        let extra = journal(&mut client, f, 16, ClockProvenance::HostMonotonic);
        (client, extra)
    });
    assert!(entry(&driver, s).is_none(), "the entry was reused");
    let e = extra.journal();
    let client = serve_while(&mut driver, move || {
        close_journal(&mut client, p, STEP);
        close_journal(&mut client, fj, 4 * STEP);
        close_journal(&mut client, e, 0);
        drop(publisher);
        drop(filler);
        drop(extra);
        client
    });
    for number in [p, fj, e] {
        ended(&mut driver, number, JournalState::Closed);
    }

    let late = attach_tool(&mut driver, &dir);
    let mut attached_late = MirrorTool::new(late.instance());
    let _ = attached_late.scan(late.trace_mirror());
    let _ = following.scan(early.trace_mirror());
    for tool in [&attached_late, &following] {
        let report = tool.report().unwrap();
        assert_eq!(answer(&report, 1), TraceAnswer::OutOfScope);
    }
    serve_while(&mut driver, move || drop(client));
}

/// Two processes with host clocks in the driver's time namespace get a
/// calibrated latency; the same poll in an opaque journal does not. The
/// subscriber journals are written by a child process.
#[test]
fn host_clocks_of_two_processes_are_calibrated() {
    let dir = dir("clocks");
    let (mut driver, identity, _) = driver(&dir, DriverConfig::default());
    let driver_id = driver.driver_id();
    let mut client = serve_while(&mut driver, || attach(&dir, Duration::from_secs(5), 16)).unwrap();
    let (mut client, publisher) = serve_while(&mut driver, move || {
        let p = publication(&mut client, KEY);
        let publisher = journal(&mut client, p, 16, ClockProvenance::HostMonotonic);
        (client, publisher)
    });
    let mut publisher = Traced::new(publisher, driver_id);
    let p = publisher.number;
    let _ = publisher.record(Point::Publish, identity, 0, 1);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_polls_and_exits", "--nocapture"])
        .env(CHILD, &dir)
        .env(
            IDENTITY,
            format!(
                "{}:{}:{}:{}",
                identity.driver[0], identity.driver[1], identity.registration, identity.incarnation
            ),
        )
        .spawn()
        .unwrap();
    serve_until_exit(&mut driver, &mut child);
    assert!(child.wait().unwrap().success());
    let client = serve_while(&mut driver, move || {
        close_journal(&mut client, p, STEP);
        drop(publisher);
        client
    });
    ended(&mut driver, p, JournalState::Closed);
    serve_until(&mut driver, |driver| {
        let reader = driver.trace_mirror();
        (0..reader.entries())
            .filter_map(|index| match reader.entry(index) {
                EntryRead::Entry(entry) => Some(entry),
                _ => None,
            })
            .all(|entry| entry.state != JournalState::Open)
    });
    let reader = driver.trace_mirror();
    let joins: Vec<Option<u64>> = (0..reader.entries())
        .filter_map(|index| match reader.entry(index) {
            EntryRead::Entry(entry) if entry.kind == JournalKind::Subscriber => Some(entry.join),
            _ => None,
        })
        .collect();
    assert_eq!(joins, [Some(0), Some(0)], "the child's two subscriptions");
    let tool = attach_tool(&mut driver, &dir);
    let mut mirror = MirrorTool::new(tool.instance());
    let _ = mirror.scan(tool.trace_mirror());
    let report = mirror.report().unwrap();
    assert_eq!(answer(&report, 1), TraceAnswer::Final(Verdict::Complete));
    let latencies = report.latencies().unwrap();
    let [(_, histogram)] = &latencies[..] else {
        panic!("one publication");
    };
    // Without time namespaces the driver cannot tell: unavailable.
    let shared = Path::new("/proc/self/ns/time").exists();
    assert_eq!(histogram.available(), u64::from(shared));
    assert_eq!(
        histogram.unavailable(Unavailable::NoCalibration),
        2 - u64::from(shared)
    );
    serve_while(&mut driver, move || drop(client));
}

/// Runs only as the child of `host_clocks_of_two_processes_are_calibrated`:
/// two subscriber journals, one with a host clock, one opaque, each poll
/// the first message of the publication the parent names, close with
/// their boundary and leave.
#[test]
fn child_polls_and_exits() {
    let Some(dir) = std::env::var_os(CHILD) else {
        return;
    };
    let words: Vec<u64> = std::env::var(IDENTITY)
        .unwrap()
        .split(':')
        .map(|word| word.parse().unwrap())
        .collect();
    let publication = PublicationId {
        driver: [words[0], words[1]],
        registration: words[2],
        stream_id: KEY.stream_id,
        session_id: KEY.session_id,
        incarnation: words[3],
    };
    let mut client = attach(Path::new(&dir), Duration::from_secs(5), 16).unwrap();
    let mut journals = Vec::new();
    for provenance in [ClockProvenance::HostMonotonic, ClockProvenance::Opaque] {
        let s = subscription(&mut client, KEY);
        journals.push(Traced::new(
            journal(&mut client, s, 16, provenance),
            publication.driver,
        ));
    }
    for traced in &mut journals {
        let _ = traced.record(Point::SubscriberPoll, publication, 0, 1);
    }
    for traced in journals {
        close_journal(&mut client, traced.number, STEP);
        drop(traced);
    }
    drop(client);
    std::process::exit(0);
}

/// Waits for `child` while serving `driver`, at most 30 s.
fn serve_until_exit(driver: &mut IpcDriver, child: &mut Child) {
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < Duration::from_secs(30), "child stuck");
        let _ = driver.do_work().unwrap();
        std::thread::sleep(Duration::from_micros(200));
    }
}

fn karyos_trace(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_karyos-trace"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The command: a one-shot report against a running driver exits 0 with
/// one section per publication; `--follow` prints the report, then keeps
/// following until the driver exits, and exits 0; a directory without a
/// driver exits 2.
#[test]
fn the_command_reports_follows_and_exits() {
    let dir = dir("command");
    let (mut driver, identity, _) = driver(&dir, DriverConfig::default());
    let driver_id = driver.driver_id();
    let mut client = serve_while(&mut driver, || attach(&dir, Duration::from_secs(5), 16)).unwrap();
    let (mut client, publisher, subscriber) = serve_while(&mut driver, move || {
        let p = publication(&mut client, KEY);
        let s = subscription(&mut client, KEY);
        let host = ClockProvenance::HostMonotonic;
        let publisher = journal(&mut client, p, 16, host);
        let subscriber = journal(&mut client, s, 16, host);
        (client, publisher, subscriber)
    });
    let mut publisher = Traced::new(publisher, driver_id);
    let mut subscriber = Traced::new(subscriber, driver_id);
    joined_at_start(&driver, subscriber.number);
    let (p, s) = (publisher.number, subscriber.number);
    let _ = publisher.record(Point::Publish, identity, 0, 1);
    let _ = subscriber.record(Point::SubscriberPoll, identity, 0, 1);
    let client = serve_while(&mut driver, move || {
        close_journal(&mut client, p, STEP);
        close_journal(&mut client, s, STEP);
        drop(publisher);
        drop(subscriber);
        client
    });
    ended(&mut driver, p, JournalState::Closed);
    ended(&mut driver, s, JournalState::Closed);
    let text = dir.to_str().unwrap();

    let mut once = karyos_trace(&["--dir", text]);
    serve_until_exit(&mut driver, &mut once);
    let output = once.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("publication "), "{stdout}");
    assert!(stdout.contains("  messages: 1"), "{stdout}");
    assert!(
        stdout.contains("traces: complete 1, incomplete 0, provisional 0, out of scope 0"),
        "{stdout}"
    );
    assert!(
        stdout.contains("latency Publish to SubscriberPoll: "),
        "{stdout}"
    );
    assert!(
        stdout
            .lines()
            .last()
            .unwrap()
            .starts_with("mirror loss: 0 ring records")
    );

    let mut follow = karyos_trace(&["--dir", text, "--follow", "--interval", "50"]);
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        assert!(
            follow.try_wait().unwrap().is_none(),
            "exited while following"
        );
        let _ = driver.do_work().unwrap();
        std::thread::sleep(Duration::from_micros(200));
    }
    serve_while(&mut driver, move || drop(client));
    // The driver exits: the tool sees its socket close.
    drop(driver);
    let start = Instant::now();
    while follow.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < Duration::from_secs(10), "still following");
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = follow.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("--- scan 1\n"), "{stdout}");
    assert!(stdout.contains("traces: complete 1"), "{stdout}");

    let missing = karyos_trace(&["--dir", text]).wait_with_output().unwrap();
    assert_eq!(missing.status.code(), Some(2), "{missing:?}");
    let stderr = String::from_utf8(missing.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("karyos-trace: "), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}
