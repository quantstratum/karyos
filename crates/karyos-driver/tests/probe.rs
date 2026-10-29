// SPDX-License-Identifier: Apache-2.0

//! R-CORE-35 over the admission socket (Linux): a probe reads the driver's
//! readiness with `ProbeHello`, receives no descriptor and holds no slot,
//! does not count against the client or tool bounds, and one step answers
//! at most `MAX_PROBES_PER_STEP` probes.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_client::probe::{ProbeError, ProbeReason, ProbeState, probe};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, MAX_PROBES_PER_STEP, SystemClock};
use karyos_protocol::admission::{MAX_MESSAGE_LENGTH, Message, VERSION, probe as wire, refusal};
use karyos_sys::ipc::{self, Recv, Sent};
use karyos_sys::term_bytes::SharedTerms;

type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-probe-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn driver(dir: &Path, max_clients: usize, max_tools: usize) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig {
            max_clients,
            ..DriverConfig::default()
        },
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 8,
            hello_timeout: 5_000_000_000,
            max_outbound_per_client: 8,
            fetch_deadline: 5_000_000_000,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Runs `work` on another thread while serving `driver` here.
fn serving<R: Send>(driver: &mut IpcDriver, work: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(work);
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
            std::thread::yield_now();
        }
        handle.join().unwrap()
    })
}

fn encode(message: &Message) -> Vec<u8> {
    let mut out = [0u8; MAX_MESSAGE_LENGTH];
    let length = message.encode(&mut out).unwrap();
    out[..length].to_vec()
}

/// A connection that sent `bytes` as its first datagram.
fn sent(dir: &Path, bytes: &[u8]) -> OwnedFd {
    let socket = ipc::connect(dir, Duration::from_millis(100)).unwrap();
    assert_eq!(ipc::send(socket.as_fd(), bytes, None).unwrap(), Sent::Sent);
    socket
}

/// The driver's answer on `socket` and its descriptor, serving until it
/// arrives.
fn answer(driver: &mut IpcDriver, socket: &OwnedFd) -> (Message, Option<OwnedFd>) {
    let start = Instant::now();
    loop {
        let _ = driver.do_work().unwrap();
        let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
        match ipc::recv(socket.as_fd(), &mut buffer) {
            Ok(Recv::Message(received)) => {
                return (
                    Message::decode(&buffer[..received.len]).unwrap(),
                    received.fd,
                );
            }
            Ok(Recv::PeerClosed) => panic!("closed without an answer"),
            Ok(Recv::WouldBlock) | Err(_) => {
                assert!(start.elapsed() < Duration::from_secs(5), "no answer");
            }
        }
    }
}

fn probe_hello() -> Vec<u8> {
    encode(&Message::ProbeHello { version: VERSION })
}

/// Starting, then ready once the host declares its startup complete; the
/// answer carries no descriptor and the connection closes after it; a
/// probe holds no client slot and no tool slot; a full driver is not
/// ready.
#[test]
fn a_probe_reads_the_state_without_a_descriptor_or_a_slot() {
    let dir = dir("state");
    let mut driver = driver(&dir, 1, 1);
    let socket = sent(&dir, &probe_hello());
    let (message, fd) = answer(&mut driver, &socket);
    assert!(fd.is_none(), "a probe received a descriptor");
    assert!(matches!(
        message,
        Message::ProbeState {
            state: wire::STARTING,
            reason: wire::NONE,
            ..
        }
    ));
    // The driver closes the connection after its answer.
    let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
    assert!(matches!(
        ipc::recv(socket.as_fd(), &mut buffer),
        Ok(Recv::PeerClosed)
    ));
    assert!(driver.startup_complete());
    let answer = serving(&mut driver, || probe(&dir, Duration::from_secs(5)).unwrap());
    assert_eq!(answer.state, ProbeState::Ready);
    assert!(answer.uptime_ns > 0);
    assert_eq!(driver.clients(), 0, "a probe holds a client slot");
    // The only tool slot is still free after the probes, and a probe is
    // still answered while it is taken.
    let tool = serving(&mut driver, || {
        karyos_client::tool::attach_tool(&dir, Duration::from_secs(5))
    })
    .unwrap();
    let answer = serving(&mut driver, || probe(&dir, Duration::from_secs(5)).unwrap());
    assert_eq!(answer.state, ProbeState::Ready);
    // The one client slot taken: not ready, full.
    let client = serving(&mut driver, || {
        karyos_client::ipc::attach(&dir, Duration::from_secs(5), 16)
    })
    .unwrap();
    let answer = serving(&mut driver, || probe(&dir, Duration::from_secs(5)).unwrap());
    assert_eq!(answer.state, ProbeState::NotReady(ProbeReason::Full));
    drop((tool, client));
}

/// One step answers `MAX_PROBES_PER_STEP` probes and refuses the next
/// with `LIMIT`; another version is refused as incompatible.
#[test]
fn a_step_answers_four_probes_and_refuses_the_fifth() {
    let dir = dir("bound");
    let mut driver = driver(&dir, 4, 1);
    assert_eq!(MAX_PROBES_PER_STEP, 4);
    let sockets: Vec<OwnedFd> = (0..=MAX_PROBES_PER_STEP)
        .map(|_| sent(&dir, &probe_hello()))
        .collect();
    let _ = driver.do_work().unwrap();
    let mut states = 0;
    let mut limits = 0;
    for socket in &sockets {
        match answer(&mut driver, socket).0 {
            Message::ProbeState { .. } => states += 1,
            Message::Refused {
                code: refusal::LIMIT,
                ..
            } => limits += 1,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!((states, limits), (MAX_PROBES_PER_STEP, 1));
    let socket = sent(
        &dir,
        &encode(&Message::ProbeHello {
            version: VERSION + 1,
        }),
    );
    // Refused, stating this driver's version (karyos#879).
    let refusal = answer(&mut driver, &socket).0;
    assert!(matches!(
        refusal,
        Message::Refused {
            code: refusal::INCOMPATIBLE_VERSION,
            ..
        }
    ));
    assert_eq!(
        refusal.refuser_version().map(core::num::NonZeroU64::get),
        Some(VERSION)
    );
}

/// A directory without a driver is unreachable, not ready.
#[test]
fn a_probe_of_no_driver_is_unreachable() {
    let dir = dir("none");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    assert!(matches!(
        probe(&dir, Duration::from_millis(50)),
        Err(ProbeError::Unreachable(_))
    ));
}

/// R-CORE-35, D5: a measurement, not a gate test (it is unstable on a
/// loaded host). A publisher offers 100 000 messages while the driver runs
/// on its own thread, once without probes and once with a probe every
/// 10 ms (500 times the documented 5 s interval); it prints the p50, p99
/// and p99.9 of `offer`. Run with `cargo test -p karyos-driver --test
/// probe -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement for the pull request, not a gate test"]
#[expect(
    clippy::print_stdout,
    reason = "the ignored measurement prints its quantiles"
)]
fn probes_do_not_move_the_offer_latency() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use karyos_driver::{LossPolicy, StreamConfig};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, TermLength};
    use karyos_sys::term::TermId;

    const MESSAGES: usize = 100_000;
    let run = |probing: bool| -> Vec<u64> {
        let dir = dir(if probing {
            "bench-probed"
        } else {
            "bench-plain"
        });
        let mut driver = driver(&dir, 4, 1);
        assert!(driver.startup_complete());
        let stream = driver
            .add_stream(StreamConfig {
                buffer: LogBufferConfig {
                    term_length: TermLength::try_new(1 << 20).unwrap(),
                    spare_slots: 3,
                    max_subscribers: 4,
                    mtu: DEFAULT_MTU,
                    max_reserved: (1 << 20) / 8,
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
        let mut publication = driver.publication(stream).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            let flag = Arc::clone(&stop);
            scope.spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    let _ = driver.do_work().unwrap();
                    std::thread::yield_now();
                }
            });
            if probing {
                let (flag, dir) = (Arc::clone(&stop), dir.clone());
                scope.spawn(move || {
                    while !flag.load(Ordering::Acquire) {
                        let _ = probe(&dir, Duration::from_secs(1));
                        std::thread::sleep(Duration::from_millis(10));
                    }
                });
            }
            let payload = [7u8; 64];
            let mut samples = Vec::with_capacity(MESSAGES);
            for _ in 0..MESSAGES {
                let start = Instant::now();
                let _ = publication.offer(&payload);
                samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX));
            }
            stop.store(true, Ordering::Release);
            samples.sort_unstable();
            samples
        })
    };
    let quantile = |samples: &[u64], q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
    for _ in 0..2 {
        for probing in [false, true] {
            let samples = run(probing);
            println!(
                "probing {probing}: p50 {} ns, p99 {} ns, p99.9 {} ns",
                quantile(&samples, 0.5),
                quantile(&samples, 0.99),
                quantile(&samples, 0.999)
            );
        }
    }
}
