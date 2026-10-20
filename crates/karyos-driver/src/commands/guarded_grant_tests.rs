// SPDX-License-Identifier: Apache-2.0

//! A guarded publication's grant over the control path (G-x2;
//! `quantstratum-docs: karyos/design/guards-and-abort.md`, "The binding
//! across processes"), over real sockets, descriptors and regions, read
//! below the client's binding (G-x3) to see what the driver grants.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_client::ipc::{RemoteClient, attach};
use karyos_client::{Completion, Outcome};
use karyos_protocol::admission::{Capability, MAX_MESSAGE_LENGTH, Message, RegionKind};
use karyos_protocol::cnc::{ErrorCode, StreamKey};
use karyos_sys::frame::Lane;
use karyos_sys::ipc::{self, ReadOnlyRegion, Recv, Region, RegionRecord, SealProfile, Sent};
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::outcome_ring::{Binding, Kind, OutcomeReader};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

use crate::IpcConfig;
use crate::embedded::{DriverConfig, EmbeddedDriver, StreamConfig, StreamHandle};
use crate::ledger::{BindingRegion, Participant};
use crate::{GuardHandle, SystemClock};

type IpcDriver = EmbeddedDriver<SharedTerms>;

const KEY: StreamKey = StreamKey {
    stream_id: 2,
    session_id: 1,
};

/// `C_m` of the tests' guarded stream.
const MESSAGES: u64 = 4;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-gx2-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// An IPC driver whose clients hold at most `exports` grants, with one
/// guarded stream whose guard is open at epoch 2.
fn guarded_driver(dir: &Path, exports: usize) -> (IpcDriver, GuardHandle, StreamHandle) {
    let timeout = 5_000_000_000;
    let mut driver = EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 2,
            hello_timeout: timeout,
            max_outbound_per_client: 16,
            fetch_deadline: timeout,
            max_exports_per_client: exports,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: crate::DEFAULT_MAX_TOOLS,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap();
    let stream = driver
        .add_stream(StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        })
        .unwrap();
    // A second guard first, so the stream's guard is not at index 0.
    let _ = driver.add_guard("other").unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver.guard_stream(stream, guard, MESSAGES, None).unwrap();
    assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
    (driver, guard, stream)
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

/// Asks for the stream's publication and returns how the request ended.
fn request(driver: &mut IpcDriver, client: &mut RemoteClient) -> Outcome {
    let _ = client.add_publication(KEY, true).unwrap();
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

fn serve_until(driver: &mut IpcDriver, mut done: impl FnMut(&IpcDriver) -> bool) {
    let start = Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(30), "timed out");
        let _ = driver.do_work().unwrap();
        std::thread::yield_now();
    }
}

/// The access mode of `fd` (0 read-only, 2 read-write), as
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

/// What the client expects of a record's region.
fn expected(driver: &IpcDriver, record: &karyos_protocol::admission::Record) -> RegionRecord {
    RegionRecord {
        instance: driver.instance().unwrap(),
        region: record.region,
        kind: record.kind.to_sys(),
        generation: record.generation,
        layout: u64::from(record.layout),
        structure_length: usize::try_from(record.structure_length).unwrap(),
    }
}

/// The fetched regions of a guarded grant: the manifest's records and the
/// four descriptors, in order.
struct Fetched {
    records: Vec<karyos_protocol::admission::Record>,
    fds: Vec<OwnedFd>,
}

fn fetch(driver: &mut IpcDriver, client: &RemoteClient, key: u64) -> Fetched {
    let socket = client.admission_socket().unwrap();
    let fetch = encode(&Message::Fetch { fetch: 1, key });
    assert_eq!(ipc::send(socket, &fetch, None).unwrap(), Sent::Sent);
    let (manifest, none) = next_message(driver, socket);
    assert!(none.is_none());
    let Message::Manifest {
        fetch: 1, records, ..
    } = manifest
    else {
        panic!("expected the manifest of fetch 1, got {manifest:?}");
    };
    let mut fds = Vec::new();
    for index in 0..u64::try_from(records.len()).unwrap() {
        let (region, fd) = next_message(driver, socket);
        assert_eq!(region, Message::Region { fetch: 1, index });
        fds.push(fd.unwrap());
    }
    Fetched { records, fds }
}

/// A guarded publication's grant carries its log buffer, then its outcome
/// ring and the guard words read-only and its consumed cell writable, each
/// its own export; the ring's header names the guard's index in the guard
/// words and the admission epoch. Detaching every export ends the grants.
#[test]
fn a_guarded_grant_carries_its_binding() {
    let dir = dir("grant");
    let (mut driver, _, _) = guarded_driver(&dir, 16);
    let mut client = attach_serving(&mut driver, &dir);
    let Outcome::Fetchable(fetchable) = request(&mut driver, &mut client) else {
        panic!("expected a fetchable publication");
    };
    let id = driver.clients.last().unwrap().id;
    let participants: Vec<Participant> = driver
        .ledger(id)
        .unwrap()
        .grants()
        .iter()
        .map(|grant| grant.participant)
        .collect();
    assert_eq!(
        participants,
        [
            Participant::Exclusive,
            Participant::Binding {
                region: BindingRegion::Outcomes
            },
            Participant::Binding {
                region: BindingRegion::Consumed
            },
            Participant::Binding {
                region: BindingRegion::Guards
            },
        ]
    );
    assert_eq!(driver.binding_exports.len(), 2);

    let Fetched { records, mut fds } = fetch(&mut driver, &client, fetchable.key);
    let kinds: Vec<RegionKind> = records.iter().map(|record| record.kind).collect();
    assert_eq!(
        kinds,
        [
            RegionKind::LogBuffer,
            RegionKind::OutcomeRing,
            RegionKind::ConsumedCell,
            RegionKind::GuardRegion,
        ]
    );
    for record in &records[1..] {
        assert_eq!(record.capability, Capability::None);
        assert_eq!(
            (record.stream_id, record.session_id, record.lane),
            (2, 1, 0)
        );
    }
    let guards = fds.pop().unwrap();
    let cell = fds.pop().unwrap();
    let ring = fds.pop().unwrap();
    // The ring and the guard words map only read-only (A1); the cell is
    // writable by this client.
    assert_eq!(access_mode(ring.as_fd()), 0);
    assert_eq!(access_mode(guards.as_fd()), 0);
    assert_eq!(access_mode(cell.as_fd()), 2);
    let guards = ReadOnlyRegion::attach(
        guards,
        expected(&driver, &records[3]),
        SealProfile::DriverOnly,
    )
    .unwrap();
    let ring = ReadOnlyRegion::attach(
        ring,
        expected(&driver, &records[1]),
        SealProfile::DriverOnly,
    )
    .unwrap();
    let _cell = Region::attach(cell, expected(&driver, &records[2])).unwrap();
    let words = guards.structure();
    let binding = karyos_sys::outcome_ring::binding(&ring.structure(), words.len()).unwrap();
    assert_eq!(
        binding,
        Binding {
            messages: MESSAGES,
            ranges: 1,
            guard_index: 1,
            epoch: 2,
        }
    );
    let state = karyos_sys::guard::load_in(&words, 1).unwrap();
    assert_eq!((state.epoch, state.open), (2, true));

    // The client unmapped them: each export detaches, which ends its grant.
    drop((guards, ring, _cell));
    let socket = client.admission_socket().unwrap();
    for record in &records {
        let detach = encode(&Message::Detach {
            export: record.export,
        });
        assert_eq!(ipc::send(socket, &detach, None).unwrap(), Sent::Sent);
    }
    serve_until(&mut driver, |driver| {
        driver
            .ledger(id)
            .is_some_and(|ledger| ledger.grants().is_empty())
    });
    assert!(driver.binding_exports.is_empty());
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A guarded grant past the client's export bound with its binding is
/// refused before anything is reserved: no grant, no region, and the
/// publication is still free.
#[test]
fn a_guarded_grant_past_the_export_bound_reserves_nothing() {
    let dir = dir("bound");
    let (mut driver, _, stream) = guarded_driver(&dir, 3);
    let mut client = attach_serving(&mut driver, &dir);
    let outcome = request(&mut driver, &mut client);
    assert!(
        matches!(
            outcome,
            Outcome::Refused {
                code: ErrorCode::ResourcesUnavailable,
                ..
            }
        ),
        "{outcome:?}"
    );
    let id = driver.clients.last().unwrap().id;
    assert!(driver.ledger(id).unwrap().grants().is_empty());
    assert!(driver.binding_exports.is_empty());
    assert!(driver.publication(stream).is_ok());
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The ring outlives the handle (ruling 5): a client that detached every
/// export before its last outcome record still has it written. The guard
/// closes after the detach, and the walker's bound writes the `Ended`
/// record into the ring the client mapped.
#[test]
fn a_detached_ring_still_gets_its_last_record() {
    let dir = dir("late");
    let (mut driver, guard, _) = guarded_driver(&dir, 16);
    let mut client = attach_serving(&mut driver, &dir);
    let Outcome::Fetchable(fetchable) = request(&mut driver, &mut client) else {
        panic!("expected a fetchable publication");
    };
    let Fetched { records, mut fds } = fetch(&mut driver, &client, fetchable.key);
    let _guards = fds.pop().unwrap();
    let cell = Region::attach(fds.pop().unwrap(), expected(&driver, &records[2])).unwrap();
    let ring = ReadOnlyRegion::attach(
        fds.pop().unwrap(),
        expected(&driver, &records[1]),
        SealProfile::DriverOnly,
    )
    .unwrap();
    let socket = client.admission_socket().unwrap();
    for record in &records {
        let detach = encode(&Message::Detach {
            export: record.export,
        });
        assert_eq!(ipc::send(socket, &detach, None).unwrap(), Sent::Sent);
    }
    let id = driver.clients.last().unwrap().id;
    serve_until(&mut driver, |driver| {
        driver
            .ledger(id)
            .is_some_and(|ledger| ledger.grants().is_empty())
    });
    assert!(driver.binding_exports.is_empty());
    let _ = driver.close_guard(guard, 2).unwrap();
    let mut reader = OutcomeReader::attach(&ring.structure(), 1).unwrap();
    let consumed = cell.structure().as_slice().first().unwrap();
    let mut seen = Vec::new();
    let start = Instant::now();
    while !seen.contains(&Kind::Ended) {
        assert!(start.elapsed() < Duration::from_secs(5), "saw {seen:?}");
        let _ = driver.do_work().unwrap();
        let _ = reader
            .poll(&ring.structure(), consumed, 16, |_, record| {
                seen.push(record.kind)
            })
            .unwrap();
    }
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
}
