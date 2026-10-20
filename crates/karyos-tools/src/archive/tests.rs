// SPDX-License-Identifier: Apache-2.0

//! The Archive's control server over a [`DriverHost`]: a recording of a
//! driver's local stream, refused for a key the driver does not have, and
//! replayed into a target stream that a subscriber reads; on a heap driver
//! and, on Linux, on a shared-terms driver as `karyosd` runs.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use karyos_archive::agent::{AgentConfig, ArchiveHandle};
use karyos_archive::control::{
    self, ControlMessage, ControlResponse, RecordingSignal, ReplayRate, ResponseCode, Signal,
};
use karyos_archive::disk::StdDisk;
use karyos_archive::segment::SyncPolicy;
use karyos_archive::server::{
    ArchiveHost, ControlServer, MAX_REQUEST, RequestSource, ResponseSink,
};
use karyos_client::OfferOutcome;
use karyos_driver::embedded::StreamConfig;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;

/// The recorded stream's key.
const DATA: StreamKey = StreamKey {
    stream_id: 10,
    session_id: 3,
};
/// The replay's target stream id.
const TARGET: i32 = 20;
/// The hosts' replay linger: long enough to subscribe after the answer.
const LINGER: Duration = Duration::from_millis(500);
/// Messages published, and each one's length.
const MESSAGES: usize = 8;
const LENGTH: usize = 100;

fn stream() -> StreamConfig {
    StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 4,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: DATA.session_id,
            stream_id: DATA.stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    }
}

/// The request stream, fed by the test.
#[derive(Clone, Default)]
struct Requests(Arc<Mutex<VecDeque<Vec<u8>>>>);

impl RequestSource for Requests {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let request = self.0.lock().unwrap().pop_front()?;
        out[..request.len()].copy_from_slice(&request);
        Some(request.len())
    }
}

/// The response stream, every message kept.
#[derive(Clone, Default)]
struct Responses(Arc<Mutex<Vec<Vec<u8>>>>);

impl ResponseSink for Responses {
    fn send(&mut self, message: &[u8]) -> bool {
        self.0.lock().unwrap().push(message.to_vec());
        true
    }
}

/// A control server over a driver host, its two streams and its directory.
struct Rig<T: StreamTerms + 'static>
where
    DriverHost<T>: ArchiveHost,
{
    server: Option<ControlServer<DriverHost<T>, Requests, Responses>>,
    requests: Requests,
    responses: Responses,
    /// Messages sent and not taken by a wait yet.
    backlog: Vec<Vec<u8>>,
    dir: PathBuf,
}

impl<T: StreamTerms + 'static> Rig<T>
where
    DriverHost<T>: ArchiveHost,
{
    fn new(name: &str, driver: EmbeddedDriver<T>) -> Self {
        let dir = std::env::temp_dir().join(format!("karyos-h2-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let agent = ArchiveHandle::spawn(StdDisk, &dir, AgentConfig::default()).unwrap();
        let (requests, responses) = (Requests::default(), Responses::default());
        let server = ControlServer::new(
            agent,
            DriverHost::new(driver).with_replay_linger(LINGER),
            requests.clone(),
            responses.clone(),
        );
        Self {
            server: Some(server),
            requests,
            responses,
            backlog: Vec::new(),
            dir,
        }
    }

    fn server(&mut self) -> &mut ControlServer<DriverHost<T>, Requests, Responses> {
        self.server.as_mut().unwrap()
    }

    fn driver(&mut self) -> &mut EmbeddedDriver<T> {
        self.server().host_mut().driver_mut()
    }

    /// One cycle of the host's loop: the driver, the server, the replays
    /// that ended.
    fn cycle(&mut self) {
        self.driver().do_work().unwrap();
        let _ = self.server().duty();
        let _ = self.server().host_mut().finish_ended();
    }

    fn request(&self, message: &ControlMessage<'_>) {
        let mut out = vec![0u8; MAX_REQUEST];
        let length = message.encode(&mut out).unwrap();
        out.truncate(length);
        self.requests.0.lock().unwrap().push_back(out);
    }

    /// Cycles until a message `pick` accepts is sent, at most five seconds.
    fn until<R>(&mut self, mut pick: impl FnMut(ControlMessage<'_>) -> Option<R>) -> R {
        for _ in 0..5000 {
            self.cycle();
            let sent = std::mem::take(&mut *self.responses.0.lock().unwrap());
            self.backlog.extend(sent);
            // A message another wait did not take stays for the next one.
            let found = self.backlog.iter().enumerate().find_map(|(at, bytes)| {
                pick(ControlMessage::decode(bytes).unwrap()).map(|found| (at, found))
            });
            if let Some((at, found)) = found {
                let _ = self.backlog.remove(at);
                return found;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let seen: Vec<String> = self
            .backlog
            .iter()
            .map(|bytes| format!("{:?}", ControlMessage::decode(bytes).unwrap()))
            .collect();
        panic!("no such message within five seconds; saw {seen:#?}");
    }

    /// The response to `correlation_id`.
    fn response(&mut self, correlation_id: u64) -> (ResponseCode, u64) {
        self.until(|message| match message {
            ControlMessage::ControlResponse(ControlResponse {
                correlation_id: id,
                id: answer,
                code,
                ..
            }) if id == correlation_id => Some((code, answer)),
            _ => None,
        })
    }
}

impl<T: StreamTerms + 'static> Drop for Rig<T>
where
    DriverHost<T>: ArchiveHost,
{
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            let (mut host, stopped) = server.shutdown_into_host();
            stopped.unwrap();
            let _ = host.finish_all_ended();
            drop(host.into_driver());
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(correlation_id: u64, key: StreamKey) -> ControlMessage<'static> {
    ControlMessage::StartRecording(control::StartRecording {
        correlation_id,
        stream_id: key.stream_id,
        session_id: key.session_id,
        mode: Mode::Required,
        sync_policy: SyncPolicy::PerSegment,
        segment_length: 0,
        channel: "karyos:ipc",
    })
}

/// A recording of a local stream, refused for a key the driver does not
/// have, stopped where the publisher's messages end; then its replay
/// opens a target at the replay's key, which lingers past the replay's
/// end and then retires.
fn records_and_replays<T: StreamTerms + 'static>(mut rig: Rig<T>)
where
    DriverHost<T>: ArchiveHost,
{
    // A key the driver does not have is refused, and nothing records.
    rig.request(&start(
        1,
        StreamKey {
            stream_id: 99,
            session_id: 3,
        },
    ));
    assert_eq!(rig.response(1).0, ResponseCode::Error);

    let data = rig.driver().add_stream(stream()).unwrap();
    rig.request(&start(2, DATA));
    let (code, recording) = rig.response(2);
    assert_eq!(code, ResponseCode::Ok);
    let mut publication = rig.driver().publication(data).unwrap();
    let mut last = 0;
    for index in 0..MESSAGES {
        let payload = [u8::try_from(index).unwrap(); LENGTH];
        loop {
            match publication.offer(&payload).unwrap() {
                OfferOutcome::Accepted { position, .. } => {
                    last = position;
                    break;
                }
                _ => rig.cycle(),
            }
        }
    }
    // The recording reads on the agent's thread; give it time, then stop.
    for _ in 0..200 {
        rig.cycle();
        std::thread::sleep(Duration::from_millis(1));
    }
    rig.request(&ControlMessage::StopRecording(control::StopRecording {
        correlation_id: 3,
        recording_id: recording,
    }));
    assert_eq!(rig.response(3).0, ResponseCode::Ok);
    let stopped = rig.until(|message| match message {
        ControlMessage::RecordingSignal(RecordingSignal {
            recording_id,
            position,
            signal: Signal::Stopped { .. },
            ..
        }) if recording_id == recording => Some(position),
        _ => None,
    });
    assert!(stopped > last, "recorded past the last message's start");

    rig.request(&ControlMessage::Replay(control::Replay {
        correlation_id: 4,
        recording_id: recording,
        position: 0,
        length: stopped,
        rate: ReplayRate::Full,
        target_stream_id: TARGET,
        target_channel: "karyos:ipc",
    }));
    let (code, replay) = rig.response(4);
    assert_eq!(code, ResponseCode::Ok);
    // The target is an ordinary stream of the driver, at the replay's
    // session id, which a subscriber finds by its key.
    let target = StreamKey {
        stream_id: TARGET,
        session_id: replay_session_id(replay),
    };
    assert!(rig.driver().stream_handle(target).is_some(), "opened");
    // A replay of this size ends at once; its target lingers for the
    // host's replay linger, then is finished and retires. A subscriber
    // added after the answer reads it once the sink waits for one (H2b,
    // archive-host.md): until then this test reads nothing from it.
    let started = std::time::Instant::now();
    while started.elapsed() < LINGER / 2 {
        rig.cycle();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(rig.driver().stream_handle(target).is_some(), "lingering");
    while rig.driver().stream_handle(target).is_some() {
        assert!(started.elapsed() < LINGER * 10, "never retired");
        rig.cycle();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(rig.server().host().unfinished(), 0);
}

#[test]
fn a_heap_driver_records_and_replays_through_its_host() {
    records_and_replays(Rig::new("heap", EmbeddedDriver::new().unwrap()));
}

/// On a shared-terms driver, as `karyosd` runs: the recording reads the
/// stream's region, and the replay target is one too.
#[cfg(target_os = "linux")]
#[test]
fn a_shared_terms_driver_records_and_replays_through_its_host() {
    use karyos_driver::{DriverConfig, IpcConfig, SystemClock};
    use karyos_sys::term_bytes::SharedTerms;

    let dir = std::env::temp_dir().join(format!("karyos-h2-ipc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let timeout = 5_000_000_000;
    let driver = EmbeddedDriver::<SharedTerms>::with_ipc(
        DriverConfig::default(),
        IpcConfig {
            dir: dir.clone(),
            max_pending_hellos: 2,
            hello_timeout: timeout,
            max_outbound_per_client: 8,
            fetch_deadline: timeout,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools: karyos_driver::DEFAULT_MAX_TOOLS,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap();
    records_and_replays(Rig::new("shared", driver));
    let _ = std::fs::remove_dir_all(&dir);
}
