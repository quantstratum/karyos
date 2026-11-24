// SPDX-License-Identifier: Apache-2.0

//! Trace journal regions across processes (Linux; `quantstratum-docs:
//! karyos/design/trace-journal-region.md`, Tests): a remote client asks
//! for a journal, fetches its region like a log buffer grant and appends
//! to it; the driver drains it into the trace mirror, which a tool reads
//! through a read-only mapping; a client cannot fetch another client's
//! journal; `CloseJournal` and the writer's `Detach` end the journal
//! closed; and a client that exits without closing leaves its journal
//! writer lost after a final drain. Each journal observes its client's
//! publication (a publisher journal, T4), and its entry records that the
//! client shares the driver's time namespace (T2). The exit test runs this
//! test binary again as a child process.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_client::ipc::{AttachError, RemoteClient, attach};
use karyos_client::{FetchableJournal, Outcome};
use karyos_driver::{
    DriverConfig, EmbeddedDriver, IpcConfig, LossPolicy, StreamConfig, SystemClock,
};
use karyos_protocol::admission::refusal;
use karyos_protocol::cnc::StreamKey;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
use karyos_sys::record_journal::{JournalLayout, Stamp};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;
use karyos_sys::trace_mirror::{
    EntryRead, JournalEntry, JournalKind, JournalState, TimeNamespace, TraceMirrorReader,
};

const CHILD: &str = "KARYOS_TRACE_JOURNAL_CHILD";

const LAYOUT: JournalLayout = JournalLayout {
    capacity: 8,
    payload_words: 2,
    drop_ranges: 2,
};

/// The provenance word the tests send: opaque to the driver.
const PROVENANCE: u64 = 7;

const KEY: StreamKey = StreamKey {
    stream_id: 5,
    session_id: 1,
};

/// The driver of these tests: IPC mode.
type IpcDriver = EmbeddedDriver<SharedTerms>;

/// The time namespace word of a client in the driver's namespace: the
/// same, or unknown on a kernel without time namespaces.
fn own_namespace() -> TimeNamespace {
    if Path::new("/proc/self/ns/time").exists() {
        TimeNamespace::Same
    } else {
        TimeNamespace::Unknown
    }
}

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-tj-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A driver on the system clock (nanoseconds) with timeouts of 5 s, and
/// the stream whose publication the journals observe.
fn driver(dir: &Path) -> IpcDriver {
    let mut driver = EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 2,
            hello_timeout: 5_000_000_000,
            max_outbound_per_client: 8,
            fetch_deadline: 5_000_000_000,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
            client_send_buffer: None,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap();
    let _ = driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: KEY.session_id,
                stream_id: KEY.stream_id,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: false,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .unwrap();
    driver
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

fn stamp(time: u64) -> Stamp {
    Stamp {
        time,
        clock: 1,
        epoch: 1,
    }
}

/// Requests the client's publication and returns its registration; its
/// grant is never fetched, and ends when the client goes.
fn publication(client: &mut RemoteClient) -> u64 {
    let _ = client.add_publication(KEY, false).unwrap();
    let mut registration = None;
    let start = Instant::now();
    while registration.is_none() {
        assert!(start.elapsed() < Duration::from_secs(5), "no publication");
        let _ = client.poll(usize::MAX, |completion| match completion.outcome {
            Outcome::Fetchable(grant) => registration = Some(grant.registration),
            other => panic!("expected a publication grant, got {other:?}"),
        });
    }
    registration.unwrap()
}

/// Requests a publisher journal of the client's publication and polls
/// until it completes as fetchable.
fn fetchable(client: &mut RemoteClient) -> FetchableJournal {
    let registration = publication(client);
    let _ = client
        .trace_journal(LAYOUT, registration, PROVENANCE)
        .unwrap();
    let mut found = None;
    let start = Instant::now();
    while found.is_none() {
        assert!(start.elapsed() < Duration::from_secs(5), "no journal");
        let _ = client.poll(usize::MAX, |completion| match completion.outcome {
            Outcome::FetchableJournal(journal) => found = Some(journal),
            other => panic!("expected a fetchable journal, got {other:?}"),
        });
    }
    found.unwrap()
}

fn entries(reader: &TraceMirrorReader) -> Vec<JournalEntry> {
    (0..reader.entries())
        .filter_map(|index| match reader.entry(index) {
            EntryRead::Entry(entry) => Some(entry),
            _ => None,
        })
        .collect()
}

/// A remote client's journal region is fetched, appended to and drained;
/// a tool reads the records with their journal sequences through its
/// read-only mapping of the mirror; another client cannot fetch it; the
/// boundary and the writer's drop end it closed.
#[test]
fn a_remote_journal_is_drained_and_read_by_a_tool() {
    let dir = dir("remote");
    let mut driver = driver(&dir);
    let mut client = serve_while(&mut driver, || attach(&dir, Duration::from_secs(5), 16)).unwrap();
    let other = serve_while(&mut driver, || attach(&dir, Duration::from_secs(5), 16)).unwrap();
    let client_id = client.client();
    let (client, mut journal, foreign) = serve_while(&mut driver, move || {
        let fetchable = fetchable(&mut client);
        let journal = client.take_journal(&fetchable).unwrap();
        // The key is the client's: another client's fetch of it is refused.
        let foreign = other.take_journal(&fetchable).err();
        drop(other);
        (client, journal, foreign)
    });
    assert_eq!(
        foreign,
        Some(AttachError::Refused {
            code: refusal::UNKNOWN_KEY
        })
    );
    let number = journal.journal();
    for value in 0..3u64 {
        let _ = journal.writer().append(&[value, 7], stamp(value)).unwrap();
    }
    serve_until(&mut driver, |driver| {
        entries(&driver.trace_mirror())
            .iter()
            .any(|entry| entry.journal == number && entry.mirrored == 3)
    });

    let tool = serve_while(&mut driver, || {
        karyos_client::tool::attach_tool(&dir, Duration::from_secs(5))
    })
    .unwrap();
    let mirror = tool.trace_mirror();
    let mut records = Vec::new();
    let _ = mirror.scan(&mut 0, |record| {
        records.push((record.journal, record.sequence, record.payload.to_vec()));
    });
    assert_eq!(
        records,
        [
            (number, 0, vec![0, 7]),
            (number, 1, vec![1, 7]),
            (number, 2, vec![2, 7])
        ]
    );
    let seen = entries(mirror);
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].client, seen[0].state, seen[0].stored),
        (client_id, JournalState::Open, 3)
    );
    // A publisher journal of its publication, in the driver's time
    // namespace (the client is this process).
    assert_eq!(
        (
            seen[0].kind,
            seen[0].join,
            seen[0].provenance,
            seen[0].time_namespace
        ),
        (JournalKind::Publisher, None, PROVENANCE, own_namespace())
    );
    assert_ne!(seen[0].registration, 0);
    assert_ne!(seen[0].stream, 0);

    // The boundary, then the writer's drop: closed, then detached.
    let client = serve_while(&mut driver, move || {
        let mut client = client;
        let _ = client.close_journal(number, 1234).unwrap();
        let mut done = false;
        let start = Instant::now();
        while !done {
            assert!(start.elapsed() < Duration::from_secs(5), "no answer");
            let _ = client.poll(usize::MAX, |completion| {
                assert!(matches!(completion.outcome, Outcome::Succeeded));
                done = true;
            });
        }
        client
    });
    serve_while(&mut driver, move || drop(journal));
    serve_until(&mut driver, |driver| {
        entries(&driver.trace_mirror())
            .iter()
            .any(|entry| entry.journal == number && entry.state == JournalState::Closed)
    });
    let ended = entries(tool.trace_mirror());
    assert_eq!(
        (ended[0].state, ended[0].boundary),
        (JournalState::Closed, Some(1234))
    );
    // Every export was detached: the client leaves.
    serve_while(&mut driver, move || drop(client));
    serve_until(&mut driver, |driver| driver.clients() == 0);
}

/// A client that exits without closing its journal: the driver drains
/// what was committed and marks the entry writer lost, without a boundary.
#[test]
fn an_exited_writer_leaves_its_journal_writer_lost() {
    let dir = dir("exit");
    let mut driver = driver(&dir);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_writes_and_exits", "--nocapture"])
        .env(CHILD, &dir)
        .spawn()
        .unwrap();
    serve_until(&mut driver, |driver| {
        entries(&driver.trace_mirror())
            .iter()
            .any(|entry| entry.state == JournalState::WriterLost)
    });
    let lost = entries(&driver.trace_mirror());
    assert_eq!(lost.len(), 1);
    assert_eq!(
        (lost[0].mirrored, lost[0].boundary),
        (4, None),
        "every committed record was drained first"
    );
    // Another process in the driver's time namespace, checked through its
    // pidfd when the journal was created.
    assert_eq!(
        (lost[0].kind, lost[0].time_namespace),
        (JournalKind::Publisher, own_namespace())
    );
    assert!(child.wait().unwrap().success());
}

/// Runs only as the child of `an_exited_writer_leaves_its_journal_writer_lost`.
#[test]
fn child_writes_and_exits() {
    let Some(dir) = std::env::var_os(CHILD) else {
        return;
    };
    let mut client = attach(Path::new(&dir), Duration::from_secs(5), 16).unwrap();
    let fetchable = fetchable(&mut client);
    let mut journal = client.take_journal(&fetchable).unwrap();
    for value in 0..4u64 {
        let _ = journal.writer().append(&[value, 0], stamp(value)).unwrap();
    }
    // Exit without closing, detaching or leaving.
    std::mem::forget(journal);
    std::mem::forget(client);
    std::process::exit(0);
}
