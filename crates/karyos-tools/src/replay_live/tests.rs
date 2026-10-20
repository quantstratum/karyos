// SPDX-License-Identifier: Apache-2.0

//! `karyos-replay start` and `stop`: their arguments, and their requests
//! against an Archive served over real control streams of an embedded
//! driver, with a `DriverHost` on the server's thread.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use karyos_archive::agent::{AgentConfig, ArchiveHandle};
use karyos_archive::disk::StdDisk;
use karyos_archive::recorder::Mode;
use karyos_archive::segment::SyncPolicy;
use karyos_archive::server::{RequestSource, ResponseSink};
use karyos_client::{ClientPublication, ClientSubscription, Context, MessageLimit, OfferOutcome};
use karyos_driver::embedded::{DriverConfig, EmbeddedDriver, StreamConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;
use crate::archive::DriverHost;

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

#[test]
fn start_parses_its_arguments_and_defaults() {
    let parsed = parse_start(os(&[
        "--live",
        "/run/k=40,41",
        "--recording",
        "7",
        "--to-stream=50",
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(
        parsed,
        StartArgs {
            live: LiveArchive {
                dir: PathBuf::from("/run/k"),
                requests: 40,
                responses: 41,
            },
            recording: 7,
            from: 0,
            length: u64::MAX,
            stream: 50,
            channel: "karyos:ipc".to_owned(),
            timeout: DEFAULT_TIMEOUT,
        }
    );
    let parsed = parse_start(os(&[
        "--live=d=1,2",
        "--recording=3",
        "--to-stream=4",
        "--from=64",
        "--length=128",
        "--channel=karyos:ipc",
        "--timeout-ms=10",
    ]))
    .unwrap()
    .unwrap();
    assert_eq!(
        (parsed.from, parsed.length, parsed.timeout),
        (64, 128, Duration::from_millis(10))
    );
    assert_eq!(parse_start(os(&["--help"])).unwrap(), None);
}

#[test]
fn start_and_stop_refuse_what_they_cannot_send() {
    let refused = |args: &[&str]| parse_start(os(args)).unwrap_err();
    assert_eq!(
        refused(&["--recording=1", "--to-stream=2"]),
        ArgsError::Missing("--live")
    );
    assert_eq!(
        refused(&["--live=d=1,2", "--to-stream=2"]),
        ArgsError::Missing("--recording")
    );
    assert_eq!(
        refused(&["--live=d=1,2", "--recording=1"]),
        ArgsError::Missing("--to-stream")
    );
    assert!(matches!(
        refused(&["--live=d=1,2", "--recording=0", "--to-stream=2"]),
        ArgsError::InvalidValue {
            option: "--recording",
            ..
        }
    ));
    for live in ["d", "d=1", "=1,2", "d=x,2", "d=1,y"] {
        assert!(
            matches!(
                parse_live(live),
                Err(ArgsError::InvalidValue {
                    option: "--live",
                    ..
                })
            ),
            "{live}"
        );
    }
    assert!(matches!(
        refused(&["--live=d=1,2", "--recording=1", "--to-stream=2", "--bogus"]),
        ArgsError::UnknownOption(_)
    ));
    assert!(matches!(
        parse_stop(os(&["--live=d=1,2", "--replay=0"])),
        Err(ArgsError::InvalidValue {
            option: "--replay",
            ..
        })
    ));
    assert_eq!(
        parse_stop(os(&["--live=d=1,2"])).unwrap_err(),
        ArgsError::Missing("--replay")
    );
    // The binary's error status, for a parse error.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(
        run(
            "karyos-replay start",
            Command::Start,
            os(&["--recording=0"]),
            &mut out,
            &mut err
        ),
        EXIT_ERROR
    );
    assert!(String::from_utf8(err).unwrap().contains("--recording"));
}

const DATA: i32 = 10;
const REQUESTS: i32 = 40;
const RESPONSES: i32 = 41;
const TARGET: i32 = 50;

fn stream(stream_id: i32, publication: PublicationMode) -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// The server's request stream: one request per call.
struct Requests(ClientSubscription);

impl RequestSource for Requests {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut length = None;
        let _ = self.0.poll(
            |bytes, _| {
                if let Some(to) = out.get_mut(..bytes.len()) {
                    to.copy_from_slice(bytes);
                    length = Some(bytes.len());
                }
            },
            MessageLimit::new(1),
        );
        length
    }
}

/// The server's response stream.
struct Responses(ClientPublication);

impl ResponseSink for Responses {
    fn send(&mut self, message: &[u8]) -> bool {
        matches!(self.0.offer(message), Ok(OfferOutcome::Accepted { .. }))
    }
}

/// An Archive served on its own thread over the driver's control streams,
/// until dropped.
struct Served {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    dir: PathBuf,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A driver with the recorded stream and the Archive's control streams,
/// served on a thread; a client of it, and a publication of the data.
fn served(
    name: &str,
) -> (
    Served,
    Client<karyos_client::ClientConductor>,
    ClientPublication,
) {
    served_with(name, true)
}

/// As [`served`]; without `answering`, the driver runs but the Archive
/// never serves its control streams: requests are taken, never answered.
fn served_with(
    name: &str,
    answering: bool,
) -> (
    Served,
    Client<karyos_client::ClientConductor>,
    ClientPublication,
) {
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        client_liveness_timeout: 3_600_000_000_000,
        ..DriverConfig::default()
    })
    .unwrap();
    let data = driver
        .add_stream(stream(DATA, PublicationMode::Exclusive))
        .unwrap();
    let requests = driver
        .add_stream(stream(
            REQUESTS,
            PublicationMode::Concurrent {
                publishers: 4,
                allow_non_lse: true,
            },
        ))
        .unwrap();
    let responses = driver
        .add_stream(stream(RESPONSES, PublicationMode::Exclusive))
        .unwrap();
    let source = Requests(driver.subscribe(requests, Role::Required).unwrap());
    let sink = Responses(driver.publication(responses).unwrap());
    let publication = driver.publication(data).unwrap();
    let conductor = driver.connect().unwrap();
    let dir = std::env::temp_dir().join(format!("karyos-h6-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let mut server = karyos_archive::server::ControlServer::new(
            agent,
            DriverHost::new(driver),
            source,
            sink,
        );
        while !flag.load(Ordering::Acquire) {
            let _ = server.host_mut().driver_mut().do_work().unwrap();
            if answering {
                let _ = server.duty();
                let _ = server.host_mut().finish_ended();
            }
            std::thread::yield_now();
        }
        let (mut host, stopped) = server.shutdown_into_host();
        stopped.unwrap();
        let _ = host.finish_all_ended();
    });
    let client = Client::with_conductor(
        conductor,
        Context::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap(),
    );
    (
        Served {
            stop,
            thread: Some(thread),
            dir,
        },
        client,
        publication,
    )
}

fn live() -> LiveArchive {
    LiveArchive {
        dir: PathBuf::from("unused in process"),
        requests: REQUESTS,
        responses: RESPONSES,
    }
}

const TIMEOUT: Duration = Duration::from_secs(10);

/// A recording made and stopped through the control streams: its id.
fn recorded(
    client: &mut Client<karyos_client::ClientConductor>,
    publication: &mut ClientPublication,
) -> u64 {
    let streams = ControlStreams::new(REQUESTS, RESPONSES);
    let recording = request(
        client,
        streams,
        &ControlMessage::StartRecording(control::StartRecording {
            correlation_id: 11,
            stream_id: DATA,
            session_id: 1,
            mode: Mode::Required,
            sync_policy: SyncPolicy::PerSegment,
            segment_length: 0,
            channel: "karyos:ipc",
        }),
        11,
        TIMEOUT,
    )
    .unwrap();
    for index in 0..4u8 {
        while !matches!(
            publication.offer(&[index; 100]).unwrap(),
            OfferOutcome::Accepted { .. }
        ) {
            std::thread::yield_now();
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    request(
        client,
        streams,
        &ControlMessage::StopRecording(control::StopRecording {
            correlation_id: 12,
            recording_id: recording,
        }),
        12,
        TIMEOUT,
    )
    .unwrap();
    recording
}

/// `start` asks for a replay and answers its id and target session;
/// `stop` stops it; the Archive's refusals of an unknown recording or
/// replay come back as such.
#[test]
fn start_and_stop_a_replay_through_the_control_streams() {
    let (_served, mut client, mut publication) = served("start");
    let recording = recorded(&mut client, &mut publication);
    let args = StartArgs {
        live: live(),
        recording,
        from: 0,
        length: u64::MAX,
        stream: TARGET,
        channel: "karyos:ipc".to_owned(),
        timeout: TIMEOUT,
    };
    let (replay, session) = start(&mut client, &args).unwrap();
    assert_ne!(replay, 0);
    assert_eq!(session, replay_session_id(replay));
    stop(
        &mut client,
        &StopArgs {
            live: live(),
            replay,
            timeout: TIMEOUT,
        },
    )
    .unwrap();

    assert!(matches!(
        start(
            &mut client,
            &StartArgs {
                recording: 999,
                ..args.clone()
            }
        ),
        Err(LiveError::Refused {
            code: ResponseCode::UnknownRecording,
            ..
        })
    ));
    assert!(matches!(
        stop(
            &mut client,
            &StopArgs {
                live: live(),
                replay: 999,
                timeout: TIMEOUT,
            }
        ),
        Err(LiveError::Refused {
            code: ResponseCode::UnknownReplay,
            ..
        })
    ));
}

/// A request the Archive takes but never answers ends in `NoAnswer` once
/// its timeout passes, and not long after.
#[test]
fn an_archive_that_never_answers_ends_in_no_answer_within_the_timeout() {
    let (_served, mut client, _publication) = served_with("silent", false);
    let started = Instant::now();
    let answered = stop(
        &mut client,
        &StopArgs {
            live: live(),
            replay: 1,
            timeout: Duration::from_millis(200),
        },
    );
    assert!(matches!(answered, Err(LiveError::NoAnswer)), "{answered:?}");
    let took = started.elapsed();
    // The two streams' opens, each a control call, then the 200 ms wait.
    assert!(
        took >= Duration::from_millis(200) && took < Duration::from_secs(10),
        "{took:?}"
    );
}
