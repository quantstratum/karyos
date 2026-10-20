// SPDX-License-Identifier: Apache-2.0

//! `karyosd`'s Archive (`quantstratum-docs: karyos/design/archive-host.md`,
//! H3): the agent with its catalog in `--archive DIR`, its control server
//! on the request and response streams `--archive-control REQ,RESP`, and
//! the recordings `--record` starts at boot through that control path.
//!
//! - **Control streams.** The daemon adds REQ, concurrent, and RESP. Its
//!   server reads REQ with a required subscription and answers on RESP,
//!   which takes offers with no subscriber, so an answer nobody reads is
//!   not held.
//! - **Who may control it.** Under same-uid admission every admitted
//!   client runs as the daemon's own uid, and may control the Archive:
//!   the trust boundary is the daemon's uid. Per-client authorization
//!   comes with owner item 43. What is kept meanwhile is the audit trail
//!   (`tracing` target [`AUDIT`]): each grant on REQ and RESP (client,
//!   process, uid, role), each request (its correlation id, whose high 32
//!   bits a requester chooses and nobody authenticates, and its kind),
//!   and each answer (served or refused).
//! - **Disk.** A recording is refused while the free space of the
//!   archive's file system is below `--archive-min-free`; retention waits
//!   on ADR-0051 (owner item 14).
//! - **Boot recordings** go through the control path as a requester's
//!   `StartRecording`, with the correlation ids of [`DAEMON_REQUESTER`],
//!   and are audited alike. A shutdown stops them through the control
//!   path, then the agent, then hands the driver back.

use std::path::PathBuf;

use karyos_archive::agent::{AgentConfig, ArchiveHandle, ReplaySink};
use karyos_archive::catalog::Recording;
use karyos_archive::control::{
    self, ControlMessage, ControlResponse, ResponseCode, StartRecording, StopRecording,
};
use karyos_archive::disk::StdDisk;
use karyos_archive::recorder::Mode;
use karyos_archive::server::{
    ArchiveHost, ControlServer, HostRecording, HostRefusal, MAX_REQUEST, RequestSource,
    ResponseSink,
};
use karyos_client::{
    ClientConcurrentPublication, ClientPublication, ClientSubscription, ConcurrentOfferOutcome,
    MessageLimit, OfferOutcome,
};
use karyos_driver::embedded::{EmbeddedDriver, StreamHandle};
use karyos_driver::grant_audit::GrantAudit;
use karyos_driver::{DriverError, StreamConfig};
use karyos_sys::log_buffer::{PublicationMode, Role};
use karyos_sys::term_bytes::SharedTerms;

use crate::archive::DriverHost;
use crate::args::{ArchiveOptions, RecordOption, StreamOption, TermOptions};

/// The `tracing` target of the Archive's audit trail.
pub const AUDIT: &str = "karyos::archive::audit";

/// The high 32 bits of the correlation ids of the daemon's own requests:
/// its boot recordings and their stop.
pub const DAEMON_REQUESTER: u64 = 0xFFFF_FFFF << 32;

/// Concurrent handles on the request stream at once.
pub const REQUEST_PUBLISHERS: u8 = 8;

/// The most one message reserves on the request stream: the longest
/// request and its frame header, rounded up. A concurrent stream needs
/// `publishers × max_reserved` within half a term, which this keeps for
/// every term length from the smallest.
pub const REQUEST_MAX_RESERVED: u32 = 2048;

/// The request stream's spare slots: one per publisher, plus the cleaning
/// headroom.
pub const REQUEST_SPARE_SLOTS: u8 = REQUEST_PUBLISHERS + karyos_sys::log_buffer::CLEANING_HEADROOM;

/// Readers of the response stream at once. Every requester, the daemon's
/// own included, holds one handle on each control stream, so as many as
/// the request stream's publishers.
pub const RESPONSE_READERS: u8 = REQUEST_PUBLISHERS;

/// The response stream's spare slots. Each reader is optional
/// (`ArchiveConnection`, quantstratum-docs: karyos/design/ffi-archive.md),
/// so it takes a spare-slot credit, as the exclusive publication does;
/// plus the cleaning headroom.
pub const RESPONSE_SPARE_SLOTS: u8 =
    1 + RESPONSE_READERS + karyos_sys::log_buffer::CLEANING_HEADROOM;

const _: () = assert!(MAX_REQUEST + 32 <= REQUEST_MAX_RESERVED as usize);
const _: () = assert!(
    REQUEST_PUBLISHERS as u32 * REQUEST_MAX_RESERVED <= karyos_sys::sizing::MIN_TERM_LENGTH / 2
);

/// Why the Archive did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveStartError {
    /// A control stream was refused.
    Stream(DriverError),
    /// A handle of a control stream was refused.
    Handle(DriverError),
    /// The agent did not start: the catalog in the directory could not be
    /// opened or created.
    Agent(String),
}

impl std::fmt::Display for ArchiveStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(error) => write!(f, "archive control stream refused: {error}"),
            Self::Handle(error) => write!(f, "archive control handle refused: {error}"),
            Self::Agent(error) => write!(f, "archive agent did not start: {error}"),
        }
    }
}

impl std::error::Error for ArchiveStartError {}

/// The production host with the daemon's free-space floor in front of it.
#[derive(Debug)]
pub struct DaemonHost {
    inner: DriverHost<SharedTerms>,
    dir: PathBuf,
    min_free: u64,
}

impl DaemonHost {
    /// The driver.
    #[must_use]
    pub fn driver(&self) -> &EmbeddedDriver<SharedTerms> {
        self.inner.driver()
    }

    /// The driver, mutably.
    pub fn driver_mut(&mut self) -> &mut EmbeddedDriver<SharedTerms> {
        self.inner.driver_mut()
    }
}

impl ArchiveHost for DaemonHost {
    fn open_recording(
        &mut self,
        request: &StartRecording<'_>,
    ) -> Result<HostRecording, HostRefusal> {
        let free = karyos_sys::fs::free_bytes(&self.dir).map_err(|error| {
            HostRefusal(format!("free space of the archive unreadable: {error}"))
        })?;
        if free < self.min_free {
            tracing::warn!(
                target: AUDIT,
                correlation_id = request.correlation_id,
                stream_id = request.stream_id,
                session_id = request.session_id,
                free,
                min_free = self.min_free,
                "recording refused: the archive's file system is below its free-space floor"
            );
            return Err(HostRefusal(format!(
                "{free} bytes free, below the archive's floor of {}",
                self.min_free
            )));
        }
        self.inner.open_recording(request)
    }

    fn open_replay(
        &mut self,
        request: &control::Replay<'_>,
        recording: &Recording,
        replay_id: u64,
        from: u64,
        to: u64,
    ) -> Result<Box<dyn ReplaySink + Send>, HostRefusal> {
        self.inner
            .open_replay(request, recording, replay_id, from, to)
    }
}

/// The request stream as the server reads it, each request audited.
#[derive(Debug)]
pub struct Requests(ClientSubscription<SharedTerms>);

impl RequestSource for Requests {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut length = None;
        let _ = self.0.poll(
            |bytes, _| {
                // A request longer than `out` is dropped (the trait's
                // contract), and audited as such.
                match out.get_mut(..bytes.len()) {
                    Some(into) => {
                        into.copy_from_slice(bytes);
                        length = Some(bytes.len());
                    }
                    None => tracing::warn!(
                        target: AUDIT,
                        length = bytes.len(),
                        "request dropped: longer than any request"
                    ),
                }
            },
            MessageLimit::new(1),
        );
        if let Some(length) = length {
            audit_request(out.get(..length).unwrap_or_default());
        }
        length
    }
}

/// The response stream as the server writes it, each answer audited once
/// it is sent.
#[derive(Debug)]
pub struct Responses(ClientPublication<SharedTerms>);

impl ResponseSink for Responses {
    fn send(&mut self, message: &[u8]) -> bool {
        let sent = matches!(self.0.offer(message), Ok(OfferOutcome::Accepted { .. }));
        if sent
            && let Ok(ControlMessage::ControlResponse(response)) = ControlMessage::decode(message)
        {
            audit_response(&response);
        }
        sent
    }
}

/// Logs a request: its correlation id (requester half not authenticated)
/// and kind.
fn audit_request(bytes: &[u8]) {
    let (kind, correlation_id) = match ControlMessage::decode(bytes) {
        Ok(ControlMessage::StartRecording(request)) => ("start recording", request.correlation_id),
        Ok(ControlMessage::StopRecording(request)) => ("stop recording", request.correlation_id),
        Ok(ControlMessage::ListRecordings(request)) => ("list recordings", request.correlation_id),
        Ok(ControlMessage::Replay(request)) => ("replay", request.correlation_id),
        Ok(ControlMessage::StopReplay(request)) => ("stop replay", request.correlation_id),
        Ok(_) => ("not a request", 0),
        Err(_) => ("malformed", 0),
    };
    tracing::info!(
        target: AUDIT,
        kind,
        correlation_id,
        requester = correlation_id >> 32,
        "archive request (requester half unauthenticated)"
    );
}

/// Logs an answer: served or refused, with its correlation id.
fn audit_response(response: &ControlResponse<'_>) {
    if response.code == ResponseCode::Ok {
        tracing::info!(
            target: AUDIT,
            correlation_id = response.correlation_id,
            id = response.id,
            "archive request served"
        );
    } else {
        tracing::warn!(
            target: AUDIT,
            correlation_id = response.correlation_id,
            code = ?response.code,
            message = response.message,
            "archive request refused"
        );
    }
}

/// Logs a grant on a control stream.
fn audit_grant(audit: GrantAudit) {
    tracing::info!(
        target: AUDIT,
        client = audit.client,
        pid = ?audit.pid,
        uid = ?audit.uid,
        stream_id = audit.stream_id,
        session_id = audit.session_id,
        role = ?audit.role,
        registration = audit.registration,
        "archive control stream granted"
    );
}

/// A request of the daemon's own, and what it waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// A boot recording's start.
    Start(RecordOption),
    /// A started recording's stop.
    Stop(u64),
}

/// The daemon as a requester: its boot recordings, then their stop at
/// shutdown. It drops its handles when nothing waits, so an idle reader
/// never holds the response stream.
#[derive(Debug)]
struct Requester {
    requests: Option<ClientConcurrentPublication<SharedTerms>>,
    responses: Option<ClientSubscription<SharedTerms>>,
    /// Requests encoded and not offered yet, with their correlation id.
    queued: Vec<(u64, Vec<u8>)>,
    /// Requests offered and not answered yet.
    waiting: Vec<(u64, Asked)>,
    /// The recordings started, for their stop.
    started: Vec<u64>,
    next: u64,
}

impl Requester {
    fn ask(&mut self, asked: Asked, channel: &str) {
        // The low 32 bits number the daemon's requests: never wrapped, a
        // request past them is not sent.
        let (Some(next), true) = (self.next.checked_add(1), self.next <= u64::from(u32::MAX))
        else {
            tracing::error!(?asked, "archive request ids of the daemon exhausted");
            return;
        };
        let correlation_id = DAEMON_REQUESTER | self.next;
        self.next = next;
        let message = match asked {
            Asked::Start(record) => ControlMessage::StartRecording(StartRecording {
                correlation_id,
                stream_id: record.stream_id,
                session_id: record.session_id,
                mode: Mode::Required,
                sync_policy: record.sync,
                segment_length: 0,
                channel,
            }),
            Asked::Stop(recording_id) => ControlMessage::StopRecording(StopRecording {
                correlation_id,
                recording_id,
            }),
        };
        let mut out = vec![0u8; MAX_REQUEST];
        match message.encode(&mut out) {
            Ok(length) => {
                out.truncate(length);
                self.queued.push((correlation_id, out));
                self.waiting.push((correlation_id, asked));
            }
            Err(error) => tracing::error!(%error, ?asked, "archive request not encoded"),
        }
    }

    /// Offers what is queued and reads the answers; true while anything
    /// waits.
    fn serve(&mut self) -> bool {
        if let Some(requests) = &mut self.requests {
            while let Some((_, message)) = self.queued.first() {
                match requests.offer(message) {
                    Ok(ConcurrentOfferOutcome::Accepted { .. }) => {
                        let _ = self.queued.remove(0);
                    }
                    _ => break,
                }
            }
        }
        let mut answers = Vec::new();
        if let Some(responses) = &mut self.responses {
            let _ = responses.poll(
                |bytes, _| {
                    if let Ok(ControlMessage::ControlResponse(response)) =
                        ControlMessage::decode(bytes)
                        && response.correlation_id >> 32 == DAEMON_REQUESTER >> 32
                    {
                        answers.push((response.correlation_id, response.code, response.id));
                    }
                },
                MessageLimit::new(16),
            );
        }
        for (correlation_id, code, id) in answers {
            let Some(at) = self
                .waiting
                .iter()
                .position(|(waited, _)| *waited == correlation_id)
            else {
                continue;
            };
            let (_, asked) = self.waiting.swap_remove(at);
            match (asked, code) {
                (Asked::Start(record), ResponseCode::Ok) => {
                    tracing::info!(
                        recording = id,
                        stream_id = record.stream_id,
                        session_id = record.session_id,
                        "boot recording started"
                    );
                    self.started.push(id);
                }
                (Asked::Start(record), code) => tracing::error!(
                    ?code,
                    stream_id = record.stream_id,
                    session_id = record.session_id,
                    "boot recording refused"
                ),
                (Asked::Stop(recording), code) => {
                    tracing::info!(recording, ?code, "boot recording stopped");
                }
            }
        }
        !self.waiting.is_empty()
    }
}

/// The Archive of a running daemon: the control server over the daemon's
/// driver, and the daemon's own requests.
pub struct DaemonArchive {
    server: ControlServer<DaemonHost, Requests, Responses>,
    requester: Requester,
    /// The driver's dropped grant audits last seen: a growth is logged, so
    /// a hole in the audit trail is never silent.
    audits_dropped: u64,
}

impl std::fmt::Debug for DaemonArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonArchive").finish_non_exhaustive()
    }
}

impl DaemonArchive {
    /// Adds the control streams to `driver`, audits their grants, starts
    /// the agent in `options.dir`, and asks for the boot recordings.
    /// Returns the Archive and the control streams, which the daemon
    /// removes at shutdown.
    ///
    /// # Errors
    ///
    /// [`ArchiveStartError`]; the driver is dropped with what it holds.
    pub fn start(
        mut driver: EmbeddedDriver<SharedTerms>,
        terms: &TermOptions,
        options: &ArchiveOptions,
    ) -> Result<(Self, [StreamHandle; 2]), ArchiveStartError> {
        let control = |stream_id| StreamOption {
            stream_id,
            session_id: 0,
        };
        let mut requests_config = control_config(terms, control(options.requests))?;
        requests_config.buffer.max_reserved = REQUEST_MAX_RESERVED;
        // A concurrent stream holds a spare slot per publisher beyond the
        // cleaning headroom.
        requests_config.buffer.spare_slots = REQUEST_SPARE_SLOTS;
        requests_config.buffer.publication = PublicationMode::Concurrent {
            publishers: REQUEST_PUBLISHERS,
            // A control stream's few small requests: the lock-free
            // fallback's cost does not matter (ADR-0012).
            allow_non_lse: true,
        };
        let mut responses_config = control_config(terms, control(options.responses))?;
        // An answer nobody reads is not held.
        responses_config.allow_unconnected = true;
        responses_config.buffer.max_subscribers = RESPONSE_READERS;
        responses_config.buffer.spare_slots = RESPONSE_SPARE_SLOTS;
        let requests = driver
            .add_stream(requests_config)
            .map_err(ArchiveStartError::Stream)?;
        let responses = driver
            .add_stream(responses_config)
            .map_err(ArchiveStartError::Stream)?;
        for stream in [requests, responses] {
            driver
                .audit_grants(stream)
                .map_err(ArchiveStartError::Stream)?;
        }
        let handle = ArchiveStartError::Handle;
        let reading = Requests(driver.subscribe(requests, Role::Required).map_err(handle)?);
        let writing = Responses(driver.publication(responses).map_err(handle)?);
        let requester = Requester {
            requests: Some(driver.concurrent_publication(requests).map_err(handle)?),
            responses: Some(
                driver
                    .subscribe(responses, Role::Optional)
                    .map_err(handle)?,
            ),
            queued: Vec::new(),
            waiting: Vec::new(),
            started: Vec::new(),
            next: 1,
        };
        let agent = ArchiveHandle::spawn(StdDisk, &options.dir, AgentConfig::default())
            .map_err(|error| ArchiveStartError::Agent(format!("{error:?}")))?;
        let host = DaemonHost {
            inner: DriverHost::new(driver),
            dir: options.dir.clone(),
            min_free: options.min_free,
        };
        let mut archive = Self {
            server: ControlServer::new(agent, host, reading, writing),
            requester,
            audits_dropped: 0,
        };
        for record in &options.records {
            archive.requester.ask(Asked::Start(*record), "karyos:ipc");
        }
        archive.release_idle_requester();
        Ok((archive, [requests, responses]))
    }

    /// The driver.
    #[must_use]
    pub fn driver(&self) -> &EmbeddedDriver<SharedTerms> {
        self.server.host().driver()
    }

    /// The driver, mutably.
    pub fn driver_mut(&mut self) -> &mut EmbeddedDriver<SharedTerms> {
        self.server.host_mut().driver_mut()
    }

    /// One cycle: the driver's duty, the server's, the replays that ended,
    /// the daemon's own requests and the grants to audit.
    ///
    /// # Errors
    ///
    /// The driver's duty cycle error; the rest still runs.
    pub fn cycle(&mut self) -> Result<u32, DriverError> {
        let work = self.driver_mut().do_work();
        let served = self.server.duty();
        self.server.host_mut().inner.finish_ended();
        let _ = self.requester.serve();
        self.release_idle_requester();
        self.driver_mut().drain_grant_audits(audit_grant);
        // Drained every cycle, the queue should never overflow; if it does,
        // the audit has a hole, which is logged with the new total.
        let dropped = self.driver().grant_audits_dropped();
        if dropped > self.audits_dropped {
            tracing::warn!(
                target: AUDIT,
                dropped,
                before = self.audits_dropped,
                "grant audits dropped: the audit trail has a hole"
            );
            self.audits_dropped = dropped;
        }
        // A request served counts as work, so the idle strategy does not
        // back off while requests arrive.
        work.map(|work| if served { work.max(1) } else { work })
    }

    /// Asks the agent, through the control path, to stop the recordings
    /// the daemon started at boot; [`Self::stopping`] says while it waits.
    pub fn stop_recordings(&mut self) {
        // The requester keeps its handles while a recording of its own may
        // need a stop (`release_idle_requester`).
        for recording in std::mem::take(&mut self.requester.started) {
            self.requester.ask(Asked::Stop(recording), "karyos:ipc");
        }
    }

    /// Whether a request of the daemon's own waits for its answer.
    #[must_use]
    pub fn stopping(&self) -> bool {
        !self.requester.waiting.is_empty()
    }

    /// Stops the agent, finishes every replay that ended, and hands the
    /// driver back.
    #[must_use]
    pub fn shutdown(self) -> EmbeddedDriver<SharedTerms> {
        let (mut host, stopped) = self.server.shutdown_into_host();
        if let Err(error) = stopped {
            tracing::warn!(?error, "archive agent shutdown error");
        }
        // The replays that ended are finished now, past their linger or not.
        host.inner.finish_all_ended();
        host.inner.into_driver()
    }

    /// Drops the requester's handles while nothing of its own waits and no
    /// recording of its own may need a stop: an idle reader never holds
    /// the response stream.
    fn release_idle_requester(&mut self) {
        if self.requester.waiting.is_empty() && self.requester.started.is_empty() {
            self.requester.requests = None;
            self.requester.responses = None;
        }
    }
}

/// A control stream's configuration from the daemon's term settings.
fn control_config(
    terms: &TermOptions,
    stream: StreamOption,
) -> Result<StreamConfig, ArchiveStartError> {
    crate::daemon::stream_config(terms, stream)
        .map_err(|_| ArchiveStartError::Stream(DriverError::InvalidConfig))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    /// A host over an IPC driver whose admission socket is in `dir`.
    fn host(dir: &std::path::Path, archive: &std::path::Path, min_free: u64) -> DaemonHost {
        let mut options = crate::args::Options::new(dir.to_path_buf());
        options.terms.term_length = karyos_sys::sizing::MIN_TERM_LENGTH;
        let driver = EmbeddedDriver::with_ipc(
            options.driver,
            crate::daemon::ipc_config(&options.admission),
            Box::new(karyos_driver::SystemClock::new()),
        )
        .unwrap();
        DaemonHost {
            inner: DriverHost::new(driver),
            dir: archive.to_path_buf(),
            min_free,
        }
    }

    fn start(correlation_id: u64) -> StartRecording<'static> {
        StartRecording {
            correlation_id,
            stream_id: 7,
            session_id: 1,
            mode: Mode::Required,
            sync_policy: karyos_archive::segment::SyncPolicy::PerSegment,
            segment_length: 0,
            channel: "karyos:ipc",
        }
    }

    /// H3: a recording is refused while the archive's file system is below
    /// the floor, before the host opens anything; at or above it the
    /// request reaches the production host.
    #[test]
    fn a_recording_below_the_free_space_floor_is_refused() {
        let base = std::env::temp_dir();
        let dir = base.join(format!("karyosd-floor-{}", std::process::id()));
        let archive = base.join(format!("karyosd-floor-catalog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&archive).unwrap();
        let mut full = host(&dir, &archive, u64::MAX);
        let Err(HostRefusal(reason)) = full.open_recording(&start(1)) else {
            panic!("a recording opened below the floor");
        };
        assert!(reason.contains("below the archive's floor"), "{reason}");
        drop(full);
        let _ = std::fs::remove_dir_all(&dir);
        let mut room = host(&dir, &archive, 0);
        let refused = room.open_recording(&start(2)).err();
        assert!(
            refused.is_none_or(|HostRefusal(reason)| !reason.contains("floor")),
            "the floor refused a request with room"
        );
        drop(room);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&archive);
    }

    /// An unreadable archive directory refuses the recording, never
    /// assumes room.
    #[test]
    fn an_unreadable_archive_directory_refuses_the_recording() {
        let base = std::env::temp_dir();
        let dir = base.join(format!("karyosd-floor-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut host = host(&dir, &base.join("karyosd-no-such-archive/x"), 0);
        let Err(HostRefusal(reason)) = host.open_recording(&start(3)) else {
            panic!("a recording opened with no readable free space");
        };
        assert!(reason.contains("unreadable"), "{reason}");
        drop(host);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
