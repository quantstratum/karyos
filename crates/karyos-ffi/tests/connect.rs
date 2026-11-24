// SPDX-License-Identifier: Apache-2.0

//! `karyos_client_connect` against a driver in this process, over its
//! admission socket (Linux, F2): a real driver admits the client; a fake
//! one refuses its version or admits it at another, which the C ABI
//! reports as `KARYOS_E_INCOMPATIBLE_DRIVER` (SPEC.md §10.2, §13).

// The cross-process client: shared mappings, descriptors and real files
// are outside Miri (MIRI.md, "What Miri does not cover"; karyos#1117).
#![cfg(all(target_os = "linux", not(miri)))]
// Test helpers outside `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::ffi::CString;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_ffi as _;
use karyos_protocol::admission::{MAX_MESSAGE_LENGTH, Message, VERSION, refusal};
use karyos_sys::ipc::{self, Recv};
use karyos_sys::term_bytes::SharedTerms;

mod support {
    #[allow(dead_code, reason = "each test binary calls a part of the ABI")]
    pub mod abi;
}

use support::abi;

/// `KARYOS_E_INCOMPATIBLE_DRIVER`.
const INCOMPATIBLE_DRIVER: i32 = 400;
/// `KARYOS_E_CLOSED`.
const CLOSED: i32 = 200;

/// The tests share the process's descriptors and threads: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-ffi-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn c_path(dir: &Path) -> CString {
    CString::new(dir.to_str().unwrap()).unwrap()
}

/// Accepts one client on `dir`, reads its `Hello`, and answers `answer`.
fn fake_driver(dir: &Path, answer: &Message) -> (i32, u64, abi::Detail) {
    let listener = ipc::listen(dir, 4).unwrap();
    let path = c_path(dir);
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            let start = Instant::now();
            let socket = loop {
                assert!(start.elapsed() < Duration::from_secs(5), "no connection");
                if let Some(socket) = ipc::accept(listener.as_fd()).unwrap() {
                    break socket;
                }
                std::thread::sleep(Duration::from_micros(100));
            };
            let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
            loop {
                assert!(start.elapsed() < Duration::from_secs(5), "no Hello");
                match ipc::recv(socket.as_fd(), &mut buffer).unwrap() {
                    Recv::Message(received) => {
                        assert_eq!(
                            Message::decode(&buffer[..received.len]),
                            Ok(Message::Hello { version: VERSION })
                        );
                        break;
                    }
                    Recv::WouldBlock => std::thread::sleep(Duration::from_micros(100)),
                    Recv::PeerClosed => panic!("the client closed first"),
                }
            }
            let mut out = [0u8; MAX_MESSAGE_LENGTH];
            let length = answer.encode(&mut out).unwrap();
            let _ = ipc::send(socket.as_fd(), &out[..length], None);
            // Keep the connection until the client has read the answer.
            std::thread::sleep(Duration::from_millis(100));
        });
        let connected = abi::client_connect(&path);
        server.join().unwrap();
        connected
    })
}

#[test]
fn a_driver_that_refuses_the_version_is_incompatible() {
    let _serial = serial();
    let refused_dir = dir("refused");
    let refused = Message::Refused {
        fetch: 0,
        code: refusal::INCOMPATIBLE_VERSION,
    };
    let (status, client, detail) = fake_driver(&refused_dir, &refused);
    assert_eq!(status, INCOMPATIBLE_DRIVER);
    assert_eq!(client, 0);
    // A refusal that states no version (0.1.0-alpha.2 and earlier) names
    // none.
    assert_eq!((detail.code, detail.value), (0, 0));
    let _ = std::fs::remove_dir_all(&refused_dir);
    // One that states it (karyos#879) gives it in detail->value.
    let stating_dir = dir("refused-stating");
    let stating = Message::incompatible_version(core::num::NonZeroU64::new(9).unwrap());
    let (status, client, detail) = fake_driver(&stating_dir, &stating);
    assert_eq!(status, INCOMPATIBLE_DRIVER);
    assert_eq!(client, 0);
    assert_eq!((detail.code, detail.value), (0, 9));
    let _ = std::fs::remove_dir_all(&stating_dir);
}

#[test]
fn a_driver_that_admits_at_another_version_is_incompatible() {
    let _serial = serial();
    let dir = dir("other-version");
    let admitted = Message::Admitted {
        instance: 1,
        version: VERSION + 1,
        client: 1,
        records: Vec::new(),
    };
    let (status, client, detail) = fake_driver(&dir, &admitted);
    assert_eq!(status, INCOMPATIBLE_DRIVER);
    assert_eq!(client, 0);
    assert_eq!(detail.value, VERSION + 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// SPEC.md §13, C ABI boundary row (karyos#637): an alpha.2 driver speaks
/// admission version 2 and this client version 6 (3 until karyos#740, 4 until karyos#844, 5 until karyos#738), so the pair is
/// incompatible whichever way the driver answers: `Admitted` at version 2
/// here, and a `Refused` with `INCOMPATIBLE_VERSION` above.
#[test]
fn an_alpha2_driver_is_incompatible() {
    let _serial = serial();
    assert_eq!(VERSION, 6);
    let dir = dir("alpha2");
    let admitted = Message::Admitted {
        instance: 1,
        version: 2,
        client: 1,
        records: Vec::new(),
    };
    let (status, client, detail) = fake_driver(&dir, &admitted);
    assert_eq!(status, INCOMPATIBLE_DRIVER);
    assert_eq!(client, 0);
    assert_eq!(detail.value, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_driver_admits_the_client_until_it_is_closed() {
    let _serial = serial();
    let dir = dir("admitted");
    let config = IpcConfig {
        dir: dir.clone(),
        max_pending_hellos: 4,
        hello_timeout: 5_000_000_000,
        max_outbound_per_client: 8,
        fetch_deadline: 5_000_000_000,
        max_exports_per_client: 16,
        max_fetches_per_client: 4,
        max_regions_per_fetch: 4,
        max_fetch_bytes: 1 << 30,
        max_tools: 1,
    };
    let mut driver: EmbeddedDriver<SharedTerms> = EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        config,
        Box::new(SystemClock::new()),
    )
    .unwrap();
    let path = c_path(&dir);
    let (status, client, _) = std::thread::scope(|scope| {
        let connecting = scope.spawn(|| abi::client_connect(&path));
        let start = Instant::now();
        while !connecting.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        connecting.join().unwrap()
    });
    assert_eq!(status, 0);
    assert_ne!(client, 0);
    assert_eq!(abi::client_poll(client).0, 0);
    assert_eq!(abi::client_close(client), 0);
    assert_eq!(abi::client_close(client), CLOSED);
    assert_eq!(abi::client_poll(client), (CLOSED, u32::MAX));
    let _ = driver.do_work().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Runs the control call `call` on another thread while this one serves
/// `driver`.
fn serve(
    driver: &mut EmbeddedDriver<SharedTerms>,
    call: &(dyn Fn() -> (i32, u64) + Sync),
) -> (i32, u64) {
    std::thread::scope(|scope| {
        let calling = scope.spawn(call);
        let start = Instant::now();
        while !calling.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        calling.join().unwrap()
    })
}

/// F7b-2c: a remote client's conflated view over the C ABI reads the
/// table's latest values; it is the client's, so the client's close
/// closes it (its handle then answers `KARYOS_E_CLOSED`) and sends its
/// `Detach`, which ends the grant.
#[test]
fn a_remote_client_reads_a_conflated_view_until_its_close() {
    let _serial = serial();
    let dir = dir("conflated");
    let config = IpcConfig {
        dir: dir.clone(),
        max_pending_hellos: 4,
        hello_timeout: 5_000_000_000,
        max_outbound_per_client: 8,
        fetch_deadline: 5_000_000_000,
        max_exports_per_client: 16,
        max_fetches_per_client: 4,
        max_regions_per_fetch: 4,
        max_fetch_bytes: 1 << 30,
        max_tools: 1,
    };
    let mut driver: EmbeddedDriver<SharedTerms> = EmbeddedDriver::with_ipc(
        DriverConfig::default(),
        config,
        Box::new(SystemClock::new()),
    )
    .unwrap();
    let mut stream = karyos_driver::StreamConfig {
        buffer: karyos_sys::log_buffer::LogBufferConfig {
            term_length: karyos_sys::sizing::TermLength::try_new(
                karyos_sys::sizing::MIN_TERM_LENGTH,
            )
            .unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: karyos_sys::sizing::DEFAULT_MTU,
            max_reserved: karyos_sys::sizing::MIN_TERM_LENGTH / 8,
            initial_term_id: karyos_sys::term::TermId::new(7),
            lane: karyos_sys::frame::Lane::ZERO,
            session_id: 1,
            stream_id: 5,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: karyos_driver::LossPolicy::Hold,
        conflation: Some(karyos_sys::conflation::ConflationConfig {
            keys: 4,
            value_capacity: 8,
            journal_capacity: 1024,
            refresh: false,
        }),
    };
    let handle = driver.add_stream(stream).unwrap();
    stream.buffer.stream_id = 6;
    stream.conflation = None;
    let _ = driver.add_stream(stream).unwrap();
    let path = c_path(&dir);
    let (status, client) = serve(&mut driver, &|| {
        let (status, client, _) = abi::client_connect(&path);
        (status, client)
    });
    assert_eq!(status, 0);
    // A stream without a table is refused (KARYOS_E_REFUSED).
    let (status, _) = serve(&mut driver, &|| {
        abi::client_add_conflated_subscription(client, c"karyos:ipc", 6)
    });
    assert_eq!(status, 304);
    let (status, view) = serve(&mut driver, &|| {
        abi::client_add_conflated_subscription(client, c"karyos:ipc", 5)
    });
    assert_eq!(status, 0);
    let mut publication = driver.publication(handle).unwrap();
    let options = karyos_sys::log_buffer::AppendOptions {
        reserved_value: 2,
        ..karyos_sys::log_buffer::AppendOptions::default()
    };
    let start = Instant::now();
    while !matches!(
        publication.offer_with(b"two", options).unwrap(),
        karyos_client::OfferOutcome::Accepted { .. }
    ) {
        assert!(start.elapsed() < Duration::from_secs(5), "never accepted");
        let _ = driver.do_work().unwrap();
    }
    let mut delivered = 0;
    while delivered == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "nothing delivered"
        );
        let _ = driver.do_work().unwrap();
        let (status, count, counted) = abi::conflated_poll(view, 8);
        assert_eq!((status, count), (0, counted));
        delivered = count;
    }
    assert_eq!(delivered, 1);
    assert_eq!(abi::client_close(client), 0);
    assert_eq!(abi::conflated_poll(view, 8).0, CLOSED);
    assert_eq!(abi::conflated_close(view), CLOSED);
    let _ = driver.do_work().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
