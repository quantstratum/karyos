// SPDX-License-Identifier: Apache-2.0

//! An image read by a subscriber in another process (Linux;
//! `quantstratum-docs: karyos/design/receive-publication.md`, Tests,
//! "Shared terms (Linux)"): the concurrent reader, duplicate and fragment
//! tests over a shared region, with the reader in a second process.
//!
//! The parent creates the image in a shared region, registers the reader's
//! cell and passes the region's descriptor over a private socket, as the
//! driver passes a grant. The child, this test binary run again, attaches
//! the region as a participant does, adopts the cell and reads while the
//! parent's receive owner writes the fragments, in order, twice each, or
//! reversed within each message. Every message must arrive once, complete
//! and byte for byte as sent. A fourth scenario writes four terms in order,
//! each closed by a PAD: the image's window is two terms, so the owner can
//! write a third only after the reader in the other process left the first
//! and the conductor rotated; until then its frames are refused as `Ahead`
//! and sent again, so the writer and the reader run concurrently across
//! rotations and reclamation.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use karyos_sys::frame::{Flags, FrameType, Lane, Word0};
use karyos_sys::ipc::{
    Recv, Region, RegionKind, RegionRecord, Sent, accept, connect, listen, recv, send,
};
use karyos_sys::log_buffer::{
    DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig, PollOutcome, PublicationMode, ReceiveOwner,
    Received, Role, Subscription,
};
use karyos_sys::receive::{ImageParams, Item, ValidatedDatagram};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::{Generation, TermCount, TermId};
use karyos_sys::term_bytes::SharedTerms;

const SCENARIO: &str = "KARYOS_IMAGE_SCENARIO";
const DIR: &str = "KARYOS_IMAGE_DIR";
const RECORD: &str = "KARYOS_IMAGE_RECORD";
const COUNT: &str = "KARYOS_IMAGE_MESSAGES";

/// Messages of three 64-byte fragments, 192 bytes each, all in term 0.
const MESSAGES: u32 = 150;
/// Messages per term: 341 of 192 bytes, then a 64-byte PAD.
const PER_TERM: u32 = MIN_TERM_LENGTH / 192;
/// Terms of the rotation scenario.
const TERMS: u32 = 4;
/// The reader's export id.
const EXPORT: u64 = 41;
const INSTANCE: u128 = 1;
const REGION: u64 = 6;

fn config() -> LogBufferConfig {
    LogBufferConfig {
        term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        spare_slots: 5,
        max_subscribers: 3,
        mtu: DEFAULT_MTU,
        max_reserved: MIN_TERM_LENGTH / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 1,
        stream_id: 2,
        claim_deadline: DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Image {
            join: 0,
            local_gaps: false,
        },
    }
}

fn params() -> ImageParams {
    ImageParams::new(
        1,
        2,
        1,
        TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        DEFAULT_MTU,
    )
    .unwrap()
}

/// Datagram of fragment `f` of message `m`: [`PER_TERM`] messages fill
/// each term up to its PAD.
fn fragment(m: u32, f: u32) -> Vec<u8> {
    let count = TermCount::try_new(m / PER_TERM).unwrap();
    let offset = m % PER_TERM * 192 + f * 64;
    let flags = Flags::new(f == 0, f == 2, false, false, Lane::ZERO);
    let mut out = Vec::new();
    out.extend_from_slice(&Word0::new(57, flags, FrameType::Data).pack().to_le_bytes());
    out.extend_from_slice(&offset.cast_signed().to_le_bytes());
    out.extend_from_slice(&1i32.to_le_bytes());
    out.extend_from_slice(&2i32.to_le_bytes());
    out.extend_from_slice(&TermId::new(7).advanced_by(count).get().to_le_bytes());
    out.extend_from_slice(&0i64.to_le_bytes());
    out.extend((0..25).map(|i| (m * 3 + f) as u8 ^ i));
    out
}

/// The PAD that closes term `term` after its [`PER_TERM`] messages.
fn pad(term: u32) -> Vec<u8> {
    let offset = PER_TERM * 192;
    let extent = MIN_TERM_LENGTH - offset;
    let count = TermCount::try_new(term).unwrap();
    let flags = Flags::new(false, false, false, false, Lane::ZERO);
    let mut out = Vec::new();
    out.extend_from_slice(&Word0::new(32, flags, FrameType::Pad).pack().to_le_bytes());
    out.extend_from_slice(&offset.cast_signed().to_le_bytes());
    out.extend_from_slice(&1i32.to_le_bytes());
    out.extend_from_slice(&2i32.to_le_bytes());
    out.extend_from_slice(&TermId::new(7).advanced_by(count).get().to_le_bytes());
    out.extend_from_slice(&i64::from(extent).to_le_bytes());
    out
}

/// The message the reader must deliver for `m`: its fragments' payloads.
fn message(m: u32) -> Vec<u8> {
    (0..3).flat_map(|f| fragment(m, f)[32..].to_vec()).collect()
}

/// The order in which the owner receives the fragments of one message.
fn arrivals(scenario: &str) -> &'static [u32] {
    match scenario {
        "in-order" => &[0, 1, 2],
        "duplicates" => &[0, 0, 1, 1, 2, 2],
        "reversed" => &[2, 1, 0],
        "rotations" => &[0, 1, 2],
        other => panic!("no scenario {other}"),
    }
}

/// A child process, killed when the test ends however it ends.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-img-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// The reader's cell and the region record fields the child cannot
/// derive, as `cell:generation:layout:structure length`.
fn record_text(cell: usize, record: RegionRecord) -> String {
    format!(
        "{cell}:{}:{}:{}",
        record.generation, record.layout, record.structure_length
    )
}

/// How many messages `scenario` sends.
fn messages(scenario: &str) -> u32 {
    if scenario == "rotations" {
        TERMS * PER_TERM
    } else {
        MESSAGES
    }
}

/// Runs `scenario` with the reader in a child: returns once the child
/// reported every message read and exited successfully.
fn run(scenario: &str) {
    let total = messages(scenario);
    let dir = private_dir(scenario);
    let listener = listen(&dir, 1).unwrap();
    let creator = Arc::new(
        LogBuffer::<SharedTerms>::create_in(
            INSTANCE,
            REGION,
            config(),
            Generation::try_new(3).unwrap(),
        )
        .unwrap(),
    );
    let mut conductor = creator.conductor_owned().unwrap();
    let cell = conductor
        .register_subscriber(Role::Required, EXPORT)
        .unwrap();
    let region = creator.region().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child", "--nocapture", "--test-threads", "1"])
        .env(SCENARIO, scenario)
        .env(DIR, &dir)
        .env(RECORD, record_text(cell, region.record()))
        .env(COUNT, total.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let reports = lines(child.stdout.take().unwrap());
    let mut guard = Guard(child);

    // The child connects; the region's descriptor goes over the socket.
    let start = Instant::now();
    let socket = loop {
        if let Some(socket) = accept(listener.as_fd()).unwrap() {
            break socket;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "no connection");
        std::thread::sleep(Duration::from_millis(1));
    };
    loop {
        match send(socket.as_fd(), b"image", region.descriptor()).unwrap() {
            Sent::Sent => break,
            Sent::WouldBlock => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    wait_for(&reports, &mut conductor, "attached");

    let params = params();
    let mut owner = ReceiveOwner::new(params, vec![Arc::clone(&creator)]).unwrap();
    // Receives `bytes`; a frame beyond the window waits, with duty cycles,
    // for the reader to free a term.
    let receive = |owner: &mut ReceiveOwner<_>, conductor: &mut _, bytes: &[u8]| {
        let datagram = ValidatedDatagram::parse(bytes, &params).unwrap();
        let Some(Item::Frame(frame)) = datagram.items().next() else {
            panic!("no frame");
        };
        let start = Instant::now();
        loop {
            match owner.receive(&frame).unwrap() {
                Received::Ahead => {
                    assert!(start.elapsed() < Duration::from_secs(20), "never rotated");
                    let conductor: &mut karyos_sys::log_buffer::Conductor<
                        Arc<LogBuffer<SharedTerms>>,
                    > = conductor;
                    let _ = conductor.duty_cycle().unwrap();
                    while owner.duty() {}
                    std::thread::yield_now();
                }
                other => return other,
            }
        }
    };
    let mut pads = 0u32;
    for m in 0..total {
        for (index, f) in arrivals(scenario).iter().enumerate() {
            let received = receive(&mut owner, &mut conductor, &fragment(m, *f));
            // A repeated arrival is compared and dropped.
            let repeat = scenario == "duplicates" && index % 2 == 1;
            match received {
                Received::Committed { .. } => assert!(!repeat, "{m}/{f}: committed twice"),
                Received::Duplicate => assert!(repeat, "{m}/{f}: a first arrival dropped"),
                other => panic!("{m}/{f}: {other:?}"),
            }
        }
        if (m + 1) % PER_TERM == 0 {
            let closed = receive(&mut owner, &mut conductor, &pad(m / PER_TERM));
            assert!(matches!(closed, Received::Committed { .. }), "{closed:?}");
            pads += 1;
        }
        let _ = conductor.duty_cycle().unwrap();
        while owner.duty() {}
    }
    if scenario == "rotations" {
        assert_eq!(pads, TERMS, "every term closed by its PAD");
    }
    wait_for(&reports, &mut conductor, &format!("read {total}"));
    let status = guard.0.wait().unwrap();
    assert!(status.success(), "{status:?}");
    drop(socket);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The child's report lines on a channel.
fn lines(stdout: std::process::ChildStdout) -> Receiver<String> {
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // libtest may print `test child ... ` on the same line first.
            if let Some(at) = line.find("child: ") {
                let _ = sender.send(line[at + "child: ".len()..].to_string());
            }
        }
    });
    receiver
}

/// Runs duty cycles until the child reports `expected`, within a bound;
/// any other report is a failure.
fn wait_for(
    reports: &Receiver<String>,
    conductor: &mut karyos_sys::log_buffer::Conductor<Arc<LogBuffer<SharedTerms>>>,
    expected: &str,
) {
    let start = Instant::now();
    loop {
        match reports.recv_timeout(Duration::from_millis(1)) {
            Ok(line) if line == expected => return,
            Ok(line) => panic!("child reported {line:?}, expected {expected:?}"),
            Err(_) => {}
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no report {expected:?}"
        );
        let _ = conductor.duty_cycle().unwrap();
    }
}

#[test]
fn an_image_is_read_in_order_by_a_reader_in_another_process() {
    run("in-order");
}

#[test]
fn duplicates_reach_a_reader_in_another_process_once() {
    run("duplicates");
}

#[test]
fn reversed_fragments_reach_a_reader_in_another_process_complete() {
    run("reversed");
}

#[test]
fn a_reader_in_another_process_bounds_rotation_across_four_terms() {
    run("rotations");
}

fn report(line: &str) {
    // A newline first: libtest may have started a line without ending it.
    let mut stdout = std::io::stdout();
    writeln!(stdout, "\nchild: {line}").unwrap();
    stdout.flush().unwrap();
}

/// The reader process: attaches the region it receives, adopts its cell
/// and reads every message. Does nothing unless run by a test above.
#[test]
fn child() {
    let (Some(_scenario), Some(dir), Some(record), Some(total)) = (
        std::env::var_os(SCENARIO),
        std::env::var_os(DIR),
        std::env::var(RECORD).ok(),
        std::env::var(COUNT).ok(),
    ) else {
        return;
    };
    let total: u32 = total.parse().unwrap();
    let fields: Vec<u64> = record
        .split(':')
        .map(|field| field.parse().unwrap())
        .collect();
    let [cell, generation, layout, structure_length] = fields[..] else {
        panic!("bad record {record}");
    };
    let socket = connect(Path::new(&dir), Duration::from_secs(5)).unwrap();
    let mut buffer = [0u8; 8];
    let Recv::Message(received) = recv(socket.as_fd(), &mut buffer).unwrap() else {
        panic!("no region");
    };
    let region = Region::attach(
        received.fd.unwrap(),
        RegionRecord {
            instance: INSTANCE,
            region: REGION,
            kind: RegionKind::LogBuffer,
            generation,
            layout,
            structure_length: usize::try_from(structure_length).unwrap(),
        },
    )
    .unwrap();
    let image = Arc::new(LogBuffer::attach(region).unwrap());
    let mut reader = Subscription::adopt(
        Arc::clone(&image),
        usize::try_from(cell).unwrap(),
        Role::Required,
        EXPORT,
    )
    .unwrap();
    report("attached");
    let mut out = vec![0u8; 256];
    let mut seen = 0u32;
    let start = Instant::now();
    while seen < total {
        if start.elapsed() > Duration::from_secs(15) {
            report(&format!("stuck at {seen}"));
            std::process::exit(1);
        }
        match reader.poll(&mut out).unwrap() {
            PollOutcome::Message { length, .. } => {
                if out[..length as usize] != message(seen)[..] {
                    report(&format!("message {seen} differs"));
                    std::process::exit(1);
                }
                reader.acknowledge();
                seen += 1;
            }
            PollOutcome::Pending => std::thread::sleep(Duration::from_micros(50)),
            other => {
                report(&format!("message {seen}: {other:?}"));
                std::process::exit(1);
            }
        }
    }
    report(&format!("read {seen}"));
    drop(reader);
    drop(socket);
}
