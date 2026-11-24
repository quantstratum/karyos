// SPDX-License-Identifier: Apache-2.0

//! A remote client's guarded publication over the C ABI (Linux, F7a-2;
//! quantstratum-docs: karyos/design/ffi-gap-analysis.md §6): the client
//! connects to a driver in this process over its admission socket, takes
//! a guarded stream's publication through `karyos_client_add_publication`,
//! and reads its outcome records through `karyos_publication_poll_outcomes`
//! while the guard is open and after it closes. The native counterpart of
//! the in-process tests of `src/abi/tests/outcomes.rs`, which run under
//! Miri.

// The cross-process client: shared mappings, descriptors and real files
// are outside Miri (MIRI.md, "What Miri does not cover"; karyos#1117).
#![cfg(all(target_os = "linux", not(miri)))]
// Test helpers outside `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, StreamConfig, SystemClock};
use karyos_ffi as _;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::SharedTerms;

mod support {
    #[allow(dead_code, reason = "each test binary calls a part of the ABI")]
    pub mod abi;
}

use support::abi;

/// `KARYOS_E_GATED`.
const GATED: i32 = 5;
/// `KARYOS_E_INVALID_LANE`.
const INVALID_LANE: i32 = 104;
/// `KARYOS_OUTCOME_SUBMITTED`.
const SUBMITTED: u32 = 1;
/// `KARYOS_OUTCOME_ENDED`.
const ENDED: u32 = 18;
/// The guarded stream.
const STREAM: i32 = 2;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-ffi-out-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn stream_config() -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            // The guard's walker holds a spare-slot credit for the
            // stream's life.
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: STREAM,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// A driver serving `dir` on its own thread, with one guarded stream open
/// at epoch 2, until `stop`; it closes the guard when `close` receives.
fn serve(
    dir: &Path,
    stop: Arc<AtomicBool>,
    close: mpsc::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    let (ready, started) = mpsc::channel();
    let dir = dir.to_path_buf();
    let thread = std::thread::spawn(move || {
        let timeout = 5_000_000_000;
        let mut driver: EmbeddedDriver<SharedTerms> = EmbeddedDriver::with_ipc(
            DriverConfig::default(),
            IpcConfig {
                dir,
                max_pending_hellos: 4,
                hello_timeout: timeout,
                max_outbound_per_client: 16,
                fetch_deadline: timeout,
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
        let stream = driver.add_stream(stream_config()).unwrap();
        let guard = driver.add_guard("orders").unwrap();
        driver.guard_stream(stream, guard, 4, None).unwrap();
        assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
        // A subscriber connects the stream: the C ABI's offers need one.
        let _subscriber = driver.subscribe(stream, Role::Optional).unwrap();
        ready.send(()).unwrap();
        while !stop.load(Ordering::Relaxed) {
            if close.try_recv().is_ok() {
                let _ = driver.close_guard(guard, 2).unwrap();
            }
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(100));
        }
    });
    started.recv().unwrap();
    thread
}

/// A driver serving `dir` on its own thread with one guarded concurrent
/// stream (`H = 2`, `C_m = 4`) whose rate policy allows a burst of two
/// messages per handle, open at epoch 2, until `stop`; it closes the guard
/// when `close` receives (karyos#1102 (e), ADR-0092).
fn serve_concurrent(
    dir: &Path,
    stop: Arc<AtomicBool>,
    close: mpsc::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    let (ready, started) = mpsc::channel();
    let dir = dir.to_path_buf();
    let thread = std::thread::spawn(move || {
        let timeout = 5_000_000_000;
        let mut driver: EmbeddedDriver<SharedTerms> = EmbeddedDriver::with_ipc(
            DriverConfig::default(),
            IpcConfig {
                dir,
                max_pending_hellos: 4,
                hello_timeout: timeout,
                max_outbound_per_client: 16,
                fetch_deadline: timeout,
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
        let mut config = stream_config();
        config.buffer.max_reserved = MIN_TERM_LENGTH / 32;
        config.buffer.publication = PublicationMode::Concurrent {
            publishers: 2,
            allow_non_lse: true,
        };
        let stream = driver.add_stream(config).unwrap();
        let guard = driver.add_guard("orders").unwrap();
        // One message a second, a burst of two: each handle's copy admits
        // two at once, then refuses for now.
        let rate = karyos_driver::GuardRate::publication(karyos_sys::rate_limit::RatePolicy {
            messages: karyos_sys::rate_limit::Rate {
                per_second: 1,
                burst: 2,
            },
            bytes: None,
        });
        driver.guard_stream(stream, guard, 4, Some(rate)).unwrap();
        assert_eq!(driver.reopen_guard(guard, 1, 1), Ok(2));
        let _subscriber = driver.subscribe(stream, Role::Optional).unwrap();
        ready.send(()).unwrap();
        while !stop.load(Ordering::Relaxed) {
            if close.try_recv().is_ok() {
                let _ = driver.close_guard(guard, 2).unwrap();
            }
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(100));
        }
    });
    started.recv().unwrap();
    thread
}

/// How long one wait may take: generous, as a loaded runner can starve the
/// driver's thread (karyos #526); each wait ends when its condition holds.
const WAIT: Duration = Duration::from_secs(30);

/// Polls `publication`'s lane 0 until `done` holds of the records;
/// `phase` names the wait in a failure.
fn outcomes_until(
    publication: u64,
    phase: &str,
    mut done: impl FnMut(&[abi::Outcome]) -> bool,
) -> Vec<abi::Outcome> {
    let mut records = Vec::new();
    let start = Instant::now();
    while !done(&records) {
        assert!(
            start.elapsed() < WAIT,
            "{phase}: after {:?}, saw {records:?}",
            start.elapsed()
        );
        let (status, delivered, mut polled) = abi::publication_poll_outcomes(publication, 0, 64);
        assert_eq!(status, 0);
        assert_eq!(usize::try_from(delivered).unwrap(), polled.len());
        records.append(&mut polled);
        std::thread::sleep(Duration::from_micros(200));
    }
    records
}

#[test]
fn a_remote_guarded_publication_reads_its_outcomes_over_the_c_abi() {
    let dir = dir("e2e");
    let stop = Arc::new(AtomicBool::new(false));
    let (close, closing) = mpsc::channel();
    let driver = serve(&dir, Arc::clone(&stop), closing);
    let path = CString::new(dir.to_str().unwrap()).unwrap();
    let (status, client, _) = abi::client_connect(&path);
    assert_eq!(status, 0);
    let (status, publication) = abi::client_add_ipc_publication(client, STREAM);
    assert_eq!(status, 0);

    // Under the open guard: three messages, three `SUBMITTED` records in
    // sequence order, bound to epoch 2.
    for payload in [b"a", b"b", b"c"] {
        assert_eq!(abi::publication_offer(publication, payload), 0);
    }
    let records = outcomes_until(publication, "three SUBMITTED", |records| records.len() >= 3);
    assert_eq!(records.len(), 3, "{records:?}");
    for (record, sequence) in records.iter().zip(1..) {
        assert_eq!(record.size, 72);
        assert_eq!(record.kind, SUBMITTED);
        assert_eq!(record.sequence, sequence);
        assert_eq!(record.epoch, 2);
    }
    // A lane the stream does not configure.
    assert_eq!(
        abi::publication_poll_outcomes(publication, 1, 64).0,
        INVALID_LANE
    );

    // The guard closes: offers are gated, and the walker ends the
    // incarnation's records. An offer accepted before the driver applied
    // the close gets its own record first.
    close.send(()).unwrap();
    let start = Instant::now();
    let mut accepted = 0;
    loop {
        match abi::publication_offer(publication, b"late") {
            GATED => break,
            0 => accepted += 1,
            _ => {}
        }
        assert!(
            start.elapsed() < WAIT,
            "never gated: after {:?}, {accepted} accepted",
            start.elapsed()
        );
        std::thread::sleep(Duration::from_micros(200));
    }
    let records = outcomes_until(publication, "ENDED", |records| {
        records.iter().any(|record| record.kind == ENDED)
    });
    let submitted = records
        .iter()
        .filter(|record| record.kind == SUBMITTED)
        .count();
    assert_eq!(submitted, accepted, "{records:?}");
    assert_eq!(records.last().map(|record| record.kind), Some(ENDED));

    assert_eq!(abi::publication_close(publication), 0);
    assert_eq!(abi::client_close(client), 0);
    stop.store(true, Ordering::Relaxed);
    driver.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `KARYOS_E_RATE_LIMITED`.
const RATE_LIMITED: i32 = 6;

/// The accepted position of an offer of `data` on lane 0 of `publication`.
fn offered(publication: u64, data: &[u8]) -> u64 {
    let (status, accepted) = abi::publication_offer_on(publication, 0, data, 16);
    assert_eq!(status, 0);
    abi::accepted_fields(&accepted).unwrap().1
}

/// A staged claim of `data` on lane 0, committed: the commit's status.
fn claimed(publication: u64, data: &[u8]) -> i32 {
    let length = u32::try_from(data.len()).unwrap();
    // A concurrent handle stages the claim; its commit reserves, so the
    // commit reports the refusal.
    let (status, claim) = abi::publication_claim_filled(publication, 0, length, data);
    assert_eq!(status, 0);
    abi::claim_commit(claim, 16).0
}

/// karyos#1102 (e), review of #1161: two concurrent handles of a guarded
/// stream acquired through `karyos_client_add_concurrent_publication` from
/// a remote client each read exactly their own lane 0 `SUBMITTED` records.
/// Past its rate copy, an offer and a staged claim's commit are
/// `KARYOS_E_RATE_LIMITED`; once the guard closes, both are
/// `KARYOS_E_GATED`.
#[test]
fn remote_concurrent_guarded_handles_over_the_c_abi() {
    let dir = dir("concurrent");
    let stop = Arc::new(AtomicBool::new(false));
    let (close, closing) = mpsc::channel();
    let driver = serve_concurrent(&dir, Arc::clone(&stop), closing);
    let path = CString::new(dir.to_str().unwrap()).unwrap();
    let (status, client, _) = abi::client_connect(&path);
    assert_eq!(status, 0);
    let (status, a) = abi::client_add_ipc_concurrent_publication(client, STREAM);
    assert_eq!(status, 0);
    let (status, b) = abi::client_add_ipc_concurrent_publication(client, STREAM);
    assert_eq!(status, 0);

    let a1 = offered(a, b"a1");
    let b1 = offered(b, b"b1");
    let a2 = offered(a, b"a2");
    // A's copy of the burst is spent: an offer and a staged commit refuse
    // for now, and reserve nothing.
    assert_eq!(abi::publication_offer(a, b"a3"), RATE_LIMITED);
    assert_eq!(claimed(a, b"a4"), RATE_LIMITED);

    let starts = |records: &[abi::Outcome]| {
        records
            .iter()
            .map(|record| (record.kind, record.start))
            .collect::<Vec<_>>()
    };
    let seen_a = outcomes_until(a, "A's two SUBMITTED", |records| records.len() >= 2);
    assert_eq!(starts(&seen_a), [(SUBMITTED, a1), (SUBMITTED, a2)]);
    let seen_b = outcomes_until(b, "B's SUBMITTED", |records| !records.is_empty());
    assert_eq!(starts(&seen_b), [(SUBMITTED, b1)]);
    assert_eq!(abi::publication_poll_outcomes(b, 1, 64).0, INVALID_LANE);

    // The guard closes: B is gated, offer and staged commit.
    close.send(()).unwrap();
    let start = Instant::now();
    loop {
        match abi::publication_offer(b, b"late") {
            GATED => break,
            // Accepted, or rate limited, before the driver applied the
            // close.
            status => assert!(
                (status == 0 || status == RATE_LIMITED) && start.elapsed() < WAIT,
                "never gated: {status}"
            ),
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(claimed(b, b"later"), GATED);
    for publication in [a, b] {
        let _ = outcomes_until(publication, "ENDED", |records| {
            records.iter().any(|record| record.kind == ENDED)
        });
        assert_eq!(abi::publication_close(publication), 0);
    }
    assert_eq!(abi::client_close(client), 0);
    stop.store(true, Ordering::Relaxed);
    driver.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
