// SPDX-License-Identifier: Apache-2.0

//! A remote client's read-only view of a conflated stream's table, over
//! real sockets, descriptors and regions (Linux; `quantstratum-docs:
//! karyos/design/conflation-end-to-end.md`, Cross-process views): the
//! command, its answer with the table's configuration, the fetch of the
//! table's region reopened read-only, and the grant's end.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_client::ipc::{AttachError, ConflatedLimits, RemoteClient, attach};
use karyos_client::{ClientPublication, Completion, FetchableConflated, OfferOutcome, Outcome};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, StreamConfig, SystemClock};
use karyos_protocol::admission::{MAX_MESSAGE_LENGTH, Message, RegionKind, refusal};
use karyos_protocol::cnc::{ErrorCode, StreamKey};
use karyos_sys::conflation::{Budget, ConflationConfig, ConflationReader};
use karyos_sys::error::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::ipc::{self, ReadOnlyRegion, Recv, Region, RegionRecord, SealProfile, Sent};
use karyos_sys::log_buffer::{AppendOptions, LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

/// The driver of these tests: IPC mode, every stream in a shared region.
type IpcDriver = EmbeddedDriver<SharedTerms>;

const KEY: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

const TABLE: ConflationConfig = ConflationConfig {
    keys: 4,
    value_capacity: 8,
    journal_capacity: 1024,
};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-cview-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A driver on the system clock with timeouts of 5 s.
fn driver(dir: &Path) -> IpcDriver {
    driver_with(dir, |config| config)
}

/// As [`driver`], with the admission settings changed by `change`.
fn driver_with(dir: &Path, change: impl FnOnce(IpcConfig) -> IpcConfig) -> IpcDriver {
    let timeout = 5_000_000_000;
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        change(IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 2,
            hello_timeout: timeout,
            max_outbound_per_client: 8,
            fetch_deadline: timeout,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
        }),
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

fn stream_config(stream_id: i32, conflation: Option<ConflationConfig>) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
        },
        allow_unconnected: false,
        on_required_loss: LossPolicy::Hold,
        conflation,
    }
}

/// Attaches on another thread while this one runs duty cycles.
fn attach_serving(driver: &mut IpcDriver, dir: &Path) -> RemoteClient {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| attach(dir, Duration::from_secs(5), 16));
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap().unwrap()
    })
}

/// Asks for a view of `stream` and returns how the request ended.
fn request_view(driver: &mut IpcDriver, client: &mut RemoteClient, stream: StreamKey) -> Outcome {
    let _ = client.add_conflated_subscription(stream).unwrap();
    let mut done: Vec<Completion> = Vec::new();
    let start = Instant::now();
    while done.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5), "no completion");
        let _ = driver.do_work().unwrap();
        let _ = client.poll(usize::MAX, |completion| done.push(completion));
    }
    done.pop().unwrap().outcome
}

fn encode(message: &Message) -> Vec<u8> {
    let mut out = [0u8; MAX_MESSAGE_LENGTH];
    let length = message.encode(&mut out).unwrap();
    out[..length].to_vec()
}

/// The next message on `socket`, serving the driver while none is there.
fn next_message(driver: &mut IpcDriver, socket: BorrowedFd<'_>) -> (Message, Option<OwnedFd>) {
    let start = Instant::now();
    loop {
        let _ = driver.do_work().unwrap();
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        match ipc::recv(socket, &mut buffer).unwrap() {
            Recv::Message(received) => {
                return (
                    Message::decode(&buffer[..received.len]).unwrap(),
                    received.fd,
                );
            }
            Recv::WouldBlock => assert!(start.elapsed() < Duration::from_secs(5), "no message"),
            Recv::PeerClosed => panic!("the driver closed the socket"),
        }
    }
}

fn counter(driver: &IpcDriver, label: &str) -> u64 {
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            karyos_sys::counters::CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some(value),
            _ => None,
        })
        .unwrap()
}

fn serve_until(driver: &mut IpcDriver, mut done: impl FnMut(&IpcDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(30), "timed out");
        let _ = driver.do_work().unwrap();
        std::thread::yield_now();
    }
}

fn offer_keyed(
    driver: &mut IpcDriver,
    publication: &mut ClientPublication<SharedTerms>,
    key: i64,
    value: &[u8],
) {
    let options = AppendOptions {
        reserved_value: key,
        ..AppendOptions::default()
    };
    let start = Instant::now();
    while !matches!(
        publication.offer_with(value, options).unwrap(),
        OfferOutcome::Accepted { .. }
    ) {
        assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
        let _ = driver.do_work().unwrap();
    }
}

/// Every value the view delivers until it settles, latest per key.
fn latest(reader: &mut ConflationReader) -> Vec<(u32, Vec<u8>)> {
    let mut seen: Vec<(u32, Vec<u8>)> = Vec::new();
    for _ in 0..100 {
        let report = reader.poll_changed(
            Budget {
                keys: 16,
                retries: 4,
            },
            |key, _, value| {
                seen.retain(|(seen, _)| *seen != key);
                seen.push((key, value.to_vec()));
            },
        );
        if report.journal_drained && report.pending == 0 && !report.scanning {
            break;
        }
    }
    seen.sort();
    seen
}

/// A remote client's view: the answer carries the table's configuration,
/// the fetch one `ConflationTable` record and a descriptor that maps only
/// read-only, and the view reads the latest values the feeder writes and
/// sees the table close when the stream is removed. `Detach` ends the
/// grant.
#[test]
fn a_fetched_conflated_view_reads_the_table_read_only() {
    let dir = dir("view");
    let mut driver = driver(&dir);
    let stream = driver.add_stream(stream_config(2, Some(TABLE))).unwrap();
    let mut client = attach_serving(&mut driver, &dir);
    let Outcome::FetchableConflated(fetchable) = request_view(&mut driver, &mut client, KEY) else {
        panic!("expected a fetchable view");
    };
    assert_eq!(
        fetchable,
        FetchableConflated {
            key: fetchable.registration,
            registration: fetchable.registration,
            stream: KEY,
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
        }
    );
    assert_eq!(counter(&driver, "grants reserved"), 1);
    let socket = client.admission_socket().unwrap();
    let fetch = encode(&Message::Fetch {
        fetch: 1,
        key: fetchable.key,
    });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    let (manifest, none) = next_message(&mut driver, socket);
    assert!(none.is_none());
    let Message::Manifest {
        fetch: 1,
        registration,
        stream_registration,
        incarnation,
        records,
        ..
    } = manifest
    else {
        panic!("expected the manifest of fetch 1, got {manifest:?}");
    };
    assert_eq!(registration, fetchable.registration);
    let identity = driver.trace_identity(stream).unwrap();
    assert_eq!(
        (stream_registration, incarnation),
        (identity.registration, identity.incarnation)
    );
    let [record] = records[..] else {
        panic!("one record");
    };
    assert_eq!(record.kind, RegionKind::ConflationTable);
    assert_eq!((record.stream_id, record.session_id), (2, 1));
    assert_eq!(
        record.capability,
        karyos_protocol::admission::Capability::None
    );
    let (region, fd) = next_message(&mut driver, socket);
    assert_eq!(region, Message::Region { fetch: 1, index: 0 });
    assert_eq!(counter(&driver, "grants exported"), 1);
    let fd = fd.unwrap();
    let expected = RegionRecord {
        instance: driver.instance().unwrap(),
        region: record.region,
        kind: karyos_sys::ipc::RegionKind::ConflationTable,
        generation: record.generation,
        layout: u64::from(record.layout),
        structure_length: usize::try_from(record.structure_length).unwrap(),
    };
    // A1: the descriptor was reopened read-only (its access mode is
    // O_RDONLY), and a writable attach fails its seal check.
    assert_eq!(access_mode(fd.as_fd()), 0);
    assert!(matches!(
        Region::attach(fd.try_clone().unwrap(), expected),
        Err(SysError::SealMismatch { .. })
    ));
    let region = ReadOnlyRegion::attach(fd, expected, SealProfile::DriverOnly).unwrap();
    let mut view = ConflationReader::attach_read_only(region, TABLE).unwrap();

    let mut publication = driver.publication(stream).unwrap();
    offer_keyed(&mut driver, &mut publication, 1, b"first");
    offer_keyed(&mut driver, &mut publication, 2, b"second");
    offer_keyed(&mut driver, &mut publication, 1, b"third");
    // The feeder writes the table in later duty cycles; the view converges
    // on the latest value of each key.
    let expected = vec![(1, b"third".to_vec()), (2, b"second".to_vec())];
    let mut seen = Vec::new();
    let start = Instant::now();
    while seen != expected {
        assert!(start.elapsed() < Duration::from_secs(5), "saw {seen:?}");
        let _ = driver.do_work().unwrap();
        for (key, value) in latest(&mut view) {
            seen.retain(|(seen, _): &(u32, Vec<u8>)| *seen != key);
            seen.push((key, value));
        }
        seen.sort();
    }

    // The end of the stream closes the table for the view.
    drop(publication);
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    let report = view.poll_changed(
        Budget {
            keys: 16,
            retries: 4,
        },
        |_, _, _| {},
    );
    assert!(report.closed);
    // The view unmapped the table: then it detaches, which ends the grant.
    drop(view);
    let detach = encode(&Message::Detach {
        export: record.export,
    });
    assert_eq!(ipc::send(socket, &detach, None).unwrap(), Sent::Sent);
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 1
    });
    assert_eq!(counter(&driver, "grants ended"), 1);
}

/// The table outlives mapping generations: across a cutover the view
/// keeps reading, and its grant neither keeps the predecessor mapping
/// alive nor is moved or fenced.
#[test]
fn a_conflated_view_survives_a_cutover() {
    let dir = dir("cutover");
    let mut driver = driver(&dir);
    let stream = driver.add_stream(stream_config(2, Some(TABLE))).unwrap();
    let mut client = attach_serving(&mut driver, &dir);
    let Outcome::FetchableConflated(fetchable) = request_view(&mut driver, &mut client, KEY) else {
        panic!("expected a fetchable view");
    };
    let socket = client.admission_socket().unwrap();
    let fetch = encode(&Message::Fetch {
        fetch: 1,
        key: fetchable.key,
    });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    let (Message::Manifest { records, .. }, _) = next_message(&mut driver, socket) else {
        panic!("no manifest");
    };
    let (_, fd) = next_message(&mut driver, socket);
    let record = records[0];
    let expected = RegionRecord {
        instance: driver.instance().unwrap(),
        region: record.region,
        kind: karyos_sys::ipc::RegionKind::ConflationTable,
        generation: record.generation,
        layout: u64::from(record.layout),
        structure_length: usize::try_from(record.structure_length).unwrap(),
    };
    let region = ReadOnlyRegion::attach(fd.unwrap(), expected, SealProfile::DriverOnly).unwrap();
    let mut view = ConflationReader::attach_read_only(region, TABLE).unwrap();
    let mut publication = driver.publication(stream).unwrap();
    offer_keyed(&mut driver, &mut publication, 0, b"before");
    let _ = driver
        .reconfigure_stream(
            stream,
            karyos_driver::Reconfiguration {
                term_length: TermLength::try_new(MIN_TERM_LENGTH * 2).unwrap(),
                spare_slots: 5,
            },
        )
        .unwrap();
    offer_keyed(&mut driver, &mut publication, 0, b"after");
    // The predecessor is freed once its in-process members moved: the
    // view's grant charges no generation.
    serve_until(&mut driver, |driver| {
        driver.generations(stream).unwrap().len() == 1
    });
    assert_eq!(driver.generations(stream).unwrap()[0].generation.get(), 1);
    let mut seen = Vec::new();
    let start = Instant::now();
    while seen != vec![(0, b"after".to_vec())] {
        assert!(start.elapsed() < Duration::from_secs(5), "saw {seen:?}");
        let _ = driver.do_work().unwrap();
        let latest = latest(&mut view);
        if !latest.is_empty() {
            seen = latest;
        }
    }
    assert!(
        !view
            .poll_changed(
                Budget {
                    keys: 16,
                    retries: 4
                },
                |_, _, _| {}
            )
            .closed
    );
    assert_eq!(counter(&driver, "grants reserved"), 1);
}

/// A stream that is not conflated, or no stream, has no table to view:
/// the command is refused and nothing is reserved. A held grant whose
/// stream is removed before the fetch is refused at the fetch.
#[test]
fn a_view_needs_a_live_conflated_stream() {
    let dir = dir("refused");
    let mut driver = driver(&dir);
    let _plain = driver.add_stream(stream_config(2, None)).unwrap();
    let mut client = attach_serving(&mut driver, &dir);
    for stream in [
        KEY,
        StreamKey {
            stream_id: 9,
            session_id: 1,
        },
    ] {
        assert!(matches!(
            request_view(&mut driver, &mut client, stream),
            Outcome::Refused {
                code: ErrorCode::UnknownStream,
                ..
            }
        ));
    }
    assert_eq!(counter(&driver, "grants reserved"), 0);
    let stream = driver.add_stream(stream_config(3, Some(TABLE))).unwrap();
    let conflated = StreamKey {
        stream_id: 3,
        session_id: 1,
    };
    let Outcome::FetchableConflated(fetchable) = request_view(&mut driver, &mut client, conflated)
    else {
        panic!("expected a fetchable view");
    };
    driver.remove_stream(stream).unwrap();
    let _ = driver.do_work().unwrap();
    let socket = client.admission_socket().unwrap();
    let fetch = encode(&Message::Fetch {
        fetch: 1,
        key: fetchable.key,
    });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    assert_eq!(
        next_message(&mut driver, socket).0,
        Message::Refused {
            fetch: 1,
            code: refusal::RESOURCES
        }
    );
}

/// The access mode of `fd` (0 read-only, 1 write-only, 2 read-write), as
/// `/proc/self/fdinfo` reports its open flags in octal.
fn access_mode(fd: BorrowedFd<'_>) -> u32 {
    use std::os::fd::AsRawFd;
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .unwrap()
        .trim();
    u32::from_str_radix(flags, 8).unwrap() & 0o3
}

/// Every check comes before any effect: a view over the client's export
/// bound, or whose region no fetch could carry, is refused, and the
/// refusal consumes no registration or export id.
#[test]
fn a_refused_view_takes_no_identity() {
    let dir = dir("bounds");
    // One table fits the fetch byte bound, the other one does not.
    let mut driver = driver_with(&dir, |config| IpcConfig {
        max_exports_per_client: 2,
        max_fetch_bytes: 4096,
        ..config
    });
    let _small = driver.add_stream(stream_config(2, Some(TABLE))).unwrap();
    let _large = driver
        .add_stream(stream_config(
            3,
            Some(ConflationConfig { keys: 64, ..TABLE }),
        ))
        .unwrap();
    let mut client = attach_serving(&mut driver, &dir);
    let large = StreamKey {
        stream_id: 3,
        session_id: 1,
    };
    let view = |driver: &mut IpcDriver, client: &mut RemoteClient, stream| match request_view(
        driver, client, stream,
    ) {
        Outcome::FetchableConflated(fetchable) => Ok(fetchable.registration),
        Outcome::Refused { code, .. } => Err(code),
        other => panic!("{other:?}"),
    };
    let first = view(&mut driver, &mut client, KEY).unwrap();
    assert_eq!(
        view(&mut driver, &mut client, large),
        Err(ErrorCode::ResourcesUnavailable)
    );
    assert_eq!(view(&mut driver, &mut client, KEY), Ok(first + 1));
    // Two grants held: the export bound refuses a third.
    assert_eq!(
        view(&mut driver, &mut client, KEY),
        Err(ErrorCode::ResourcesUnavailable)
    );
    assert_eq!(counter(&driver, "grants reserved"), 2);
    // The client's exit ends both held grants.
    drop(client);
    serve_until(&mut driver, |driver| driver.clients() == 0);
    assert_eq!(counter(&driver, "grants ended"), 2);
}

/// The record of a view carries its stream's lane.
#[test]
fn a_view_record_carries_the_lane() {
    let dir = dir("lane");
    let mut driver = driver(&dir);
    let mut config = stream_config(2, Some(TABLE));
    config.buffer.lane = Lane::try_new(2).unwrap();
    let _stream = driver.add_stream(config).unwrap();
    let mut client = attach_serving(&mut driver, &dir);
    let Outcome::FetchableConflated(fetchable) = request_view(&mut driver, &mut client, KEY) else {
        panic!("expected a fetchable view");
    };
    let socket = client.admission_socket().unwrap();
    let fetch = encode(&Message::Fetch {
        fetch: 1,
        key: fetchable.key,
    });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    let (Message::Manifest { records, .. }, _) = next_message(&mut driver, socket) else {
        panic!("no manifest");
    };
    assert_eq!(records[0].lane, 2);
    let _ = next_message(&mut driver, socket);
}

/// `take_conflated` maps the table read-only and reads the latest values;
/// dropping the view unmaps it and sends its `Detach`, which ends the
/// grant.
#[test]
fn a_taken_view_reads_and_detaches_on_drop() {
    let dir = dir("take");
    let mut driver = driver(&dir);
    let stream = driver.add_stream(stream_config(2, Some(TABLE))).unwrap();
    let mut client = attach_serving(&mut driver, &dir);
    let Outcome::FetchableConflated(fetchable) = request_view(&mut driver, &mut client, KEY) else {
        panic!("expected a fetchable view");
    };
    let mut view = serve_while(&mut driver, || {
        client.take_conflated(&fetchable, BUDGET, ConflatedLimits::default())
    })
    .unwrap();
    let mut publication = driver.publication(stream).unwrap();
    offer_keyed(&mut driver, &mut publication, 3, b"latest");
    let mut seen = Vec::new();
    let start = Instant::now();
    while seen.is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "nothing delivered"
        );
        let _ = driver.do_work().unwrap();
        let _ = view.poll_changed(|key, value| seen.push((key, value.to_vec())));
    }
    assert_eq!(seen, vec![(3, b"latest".to_vec())]);
    assert_eq!(counter(&driver, "grants exported"), 1);
    drop(view);
    serve_until(&mut driver, |driver| {
        counter(driver, "grants detached") == 1
    });
    assert_eq!(counter(&driver, "grants ended"), 1);
}

/// A take that fails rolls back: a configuration over the view's limits,
/// a record of another stream, and a table whose configuration differs
/// from the answer each fail, and the grant is detached and ended.
#[test]
fn a_failed_take_is_rolled_back() {
    let dir = dir("rollback");
    let mut driver = driver(&dir);
    let _stream = driver.add_stream(stream_config(2, Some(TABLE))).unwrap();
    let mut client = attach_serving(&mut driver, &dir);
    let cases: [(Change, Expected); 3] = [
        (
            |_, limits| limits.max_keys = 3,
            |error| matches!(error, AttachError::TooLarge),
        ),
        (
            |fetchable, _| fetchable.stream.stream_id = 9,
            |error| matches!(error, AttachError::Protocol),
        ),
        (
            |fetchable, _| fetchable.keys = 3,
            |error| matches!(error, AttachError::Sys(SysError::InvalidRegion { .. })),
        ),
    ];
    for (case, (change, expected)) in cases.into_iter().enumerate() {
        let Outcome::FetchableConflated(mut fetchable) =
            request_view(&mut driver, &mut client, KEY)
        else {
            panic!("expected a fetchable view");
        };
        let mut limits = ConflatedLimits::default();
        change(&mut fetchable, &mut limits);
        let Err(error) = serve_while(&mut driver, || {
            client.take_conflated(&fetchable, BUDGET, limits)
        }) else {
            panic!("case {case}: the take succeeded");
        };
        assert!(expected(&error), "case {case}: {error:?}");
        let ended = case as u64 + 1;
        serve_until(&mut driver, |driver| {
            counter(driver, "grants detached") == ended
        });
        assert_eq!(counter(&driver, "grants ended"), ended);
    }
}

/// A change to a view's answer or limits before its take.
type Change = fn(&mut FetchableConflated, &mut ConflatedLimits);
/// What a failed take must report.
type Expected = fn(&AttachError) -> bool;

const BUDGET: Budget = Budget {
    keys: 16,
    retries: 4,
};

/// Runs `client` on another thread while this one runs duty cycles.
fn serve_while<R: Send>(driver: &mut IpcDriver, client: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(client);
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap()
    })
}
