// SPDX-License-Identifier: Apache-2.0

//! The Archive catalog of a driver (SPEC §11; quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M11): the recordings
//! the agent lists over the Archive's control streams, off by default.
//!
//! - **Where.** A driver given an Archive (`--archive DIR=REQ,RESP[,STATE]`, the third the retention state stream of ADR-0101)
//!   names the two control streams its host configured
//!   (archive-control-codec.md §7a). The request stream is shared by every
//!   requester, so the host configures it concurrent; the agent takes a
//!   concurrent handle on it and subscribes the response stream.
//! - **Cost.** The agent becomes a full IPC client of that driver, beside
//!   its tool attach: one client slot, one concurrent publisher on the
//!   request stream and one subscriber on the response stream.
//! - **Off the refresh path.** A thread per such driver connects with a
//!   short bounded timeout, lists with
//!   [`karyos_archive::client::list::RecordingLister`] within a deadline,
//!   and lists again after an interval. A failure (the connection, a grant,
//!   a refusal, a listing past its deadline, the driver closing under the
//!   agent's attach) is counted in the view and retried after the
//!   interval, on a new connection unless the Archive refused. The view
//!   keeps the last complete listing.
//! - **Correlation.** The agent's correlation ids carry
//!   [`CATALOG_CLIENT_ID`] in their high 32 bits; a host's other
//!   requesters must not use it (§7a).

use std::time::Duration;

#[cfg(target_os = "linux")]
pub(crate) use watch::CatalogWatch;

/// The high 32 bits of the agent's correlation ids: "AGNT".
pub const CATALOG_CLIENT_ID: u32 = 0x4147_4E54;
/// The default wait for each message of the connection and the grants.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
/// The default bound on one listing.
pub const DEFAULT_LIST_DEADLINE: Duration = Duration::from_secs(5);
/// The default interval between listings, and before a retry.
pub const DEFAULT_LIST_EVERY: Duration = Duration::from_secs(10);

/// The Archive control streams of a driver's host (§7a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveStreams {
    /// The request stream id, configured concurrent.
    pub requests: i32,
    /// The response stream id.
    pub responses: i32,
    /// The stream the Archive answers retention state queries on
    /// (ADR-0101), when its host configures one.
    pub retention: Option<i32>,
}

impl ArchiveStreams {
    /// The streams `requests` and `responses`, with no retention state
    /// stream.
    #[must_use]
    pub fn new(requests: i32, responses: i32) -> Self {
        Self {
            requests,
            responses,
            retention: None,
        }
    }

    /// With `retention`, the retention state answer stream (ADR-0101).
    #[must_use]
    pub const fn with_retention(mut self, retention: i32) -> Self {
        self.retention = Some(retention);
        self
    }
}

/// How the agent lists one driver's catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CatalogConfig {
    /// The control streams.
    pub streams: ArchiveStreams,
    /// The wait for each message of the connection and the grants.
    pub connect_timeout: Duration,
    /// The bound on one listing.
    pub list_deadline: Duration,
    /// The interval between listings, and before a retry.
    pub every: Duration,
    /// The high 32 bits of the correlation ids.
    pub client_id: u32,
}

impl CatalogConfig {
    /// Listing over `streams` with the default timing.
    #[must_use]
    pub fn new(streams: ArchiveStreams) -> Self {
        Self {
            streams,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            list_deadline: DEFAULT_LIST_DEADLINE,
            every: DEFAULT_LIST_EVERY,
            client_id: CATALOG_CLIENT_ID,
        }
    }

    /// With `connect_timeout` per message, `list_deadline` per listing and
    /// `every` between listings.
    #[must_use]
    pub fn with_timing(
        mut self,
        connect_timeout: Duration,
        list_deadline: Duration,
        every: Duration,
    ) -> Self {
        self.connect_timeout = connect_timeout;
        self.list_deadline = list_deadline;
        self.every = every;
        self
    }
}

#[cfg(target_os = "linux")]
mod watch {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use karyos_archive::catalog::{FailKind, StopReason};
    use karyos_archive::client::connection::Responses;
    use karyos_archive::client::connection::{ArchiveConnection, ControlStreams};
    use karyos_archive::client::list::{
        ListPoll, ListedRecording, ListerConfig, Listing, RecordingLister,
    };
    use karyos_archive::client::retention_state::{RetentionStatePoll, RetentionStateRequester};
    use karyos_archive::control::{
        FREE_UNKNOWN, HoldState, MAX_LIST_COUNT, NO_EXPIRY, RecordingState, RetentionDescriptor,
    };
    use karyos_client::ipc::RemoteClient;
    use karyos_client::{Client, Context};
    use karyos_sys::host_clock::host_monotonic_ns;

    use super::CatalogConfig;
    use crate::api::{Catalog, CatalogRecording, RecordingRetention, RetentionView};

    /// The correlation ids' client id of the retention state queries:
    /// apart from the lister's and the retention operations'.
    const RETENTION_STATE_CLIENT_ID: u32 = 0x4b52_5354;
    /// The recordings the view keeps the retention of at most: the pages
    /// of one query, each [`MAX_LIST_COUNT`] long.
    const MAX_RETENTION_RECORDINGS: usize = 16 * 1000;
    /// What the view says of an Archive without version 2 (ADR-0101).
    pub(crate) const UNSUPPORTED: &str = "retention state unsupported by this Archive";

    /// How long the thread sleeps between polls of a listing.
    const TICK: Duration = Duration::from_millis(1);
    /// How long it sleeps between polls of the connection while it waits.
    const IDLE_TICK: Duration = Duration::from_millis(10);

    /// What the agent tells the thread.
    #[derive(Debug, Default)]
    struct Signals {
        /// Stop for good.
        stop: AtomicBool,
        /// The agent saw the driver close or become unavailable: the
        /// session ends now rather than at its deadline.
        gone: AtomicBool,
    }

    /// Why a wait ended.
    enum Wake {
        Elapsed,
        Stop,
        Gone,
    }

    /// The thread listing one driver's catalog, and what it last found.
    #[derive(Debug)]
    pub(crate) struct CatalogWatch {
        shared: Arc<Mutex<Catalog>>,
        signals: Arc<Signals>,
        thread: Option<JoinHandle<()>>,
    }

    impl CatalogWatch {
        /// Starts listing the catalog of the driver in `dir`.
        pub(crate) fn start(dir: PathBuf, config: CatalogConfig) -> Self {
            let shared = Arc::new(Mutex::new(Catalog::default()));
            let signals = Arc::new(Signals::default());
            let thread = {
                let (shared, signals) = (Arc::clone(&shared), Arc::clone(&signals));
                std::thread::Builder::new()
                    .name("karyos-agent-catalog".to_owned())
                    .spawn(move || run(&dir, config, &shared, &signals))
            };
            let thread = match thread {
                Ok(thread) => Some(thread),
                Err(error) => {
                    // No thread: the view says so, and nothing lists.
                    fail(&shared, &format!("no catalog thread: {error}"));
                    None
                }
            };
            Self {
                shared,
                signals,
                thread,
            }
        }

        /// What it last found.
        pub(crate) fn view(&self) -> Catalog {
            lock(&self.shared).clone()
        }

        /// The agent saw the driver close or become unavailable: the
        /// session ends at once, is counted as a failure, and a new one is
        /// tried after the interval (REVIEWER-02's P3-2 on #488).
        pub(crate) fn driver_gone(&self) {
            self.signals.gone.store(true, Ordering::Release);
        }
    }

    impl Drop for CatalogWatch {
        fn drop(&mut self) {
            self.signals.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn lock(shared: &Mutex<Catalog>) -> MutexGuard<'_, Catalog> {
        shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fail(shared: &Mutex<Catalog>, error: &str) {
        let mut catalog = lock(shared);
        catalog.failures = catalog.failures.checked_add(1).unwrap_or(catalog.failures);
        catalog.last_error = Some(error.to_owned());
    }

    fn listed(shared: &Mutex<Catalog>, listing: Listing) {
        // A state or stop reason a later Archive version decodes has no
        // name in this API: the listing fails, the last catalog stays
        // (owner item 41).
        let Some(recordings) = listing.recordings.iter().map(recording).collect() else {
            fail(
                shared,
                "a recording state or stop reason this agent does not know",
            );
            return;
        };
        let mut catalog = lock(shared);
        catalog.recordings = recordings;
        catalog.left_out = listing.left_out;
        catalog.listed_at = Some(host_monotonic_ns());
        catalog.listings = catalog.listings.checked_add(1).unwrap_or(catalog.listings);
        catalog.last_error = None;
    }

    /// Keeps a retention state answer, or the failure, in the view.
    fn retained(shared: &Mutex<Catalog>, read: Result<RetentionView, String>) {
        let mut catalog = lock(shared);
        match read {
            Ok(view) => catalog.retention = Some(view),
            Err(error) => {
                let mut view = catalog.retention.take().unwrap_or_default();
                view.last_error = Some(error);
                catalog.retention = Some(view);
            }
        }
    }

    /// The view of one descriptor.
    fn retention_of(descriptor: &RetentionDescriptor) -> RecordingRetention {
        let some = |value: u64| (value != 0).then_some(value);
        RecordingRetention {
            recording_id: descriptor.recording_id,
            hold: match descriptor.hold {
                HoldState::None => "none",
                HoldState::Held => "held",
                HoldState::Pending => "pending",
                _ => "unknown",
            },
            hold_since_ns: some(descriptor.hold_since_ns),
            close_time_ns: some(descriptor.close_time_ns),
            earliest_expiry_ns: (descriptor.earliest_expiry_ns != NO_EXPIRY)
                .then_some(descriptor.earliest_expiry_ns),
            policy: (descriptor.policy != 0)
                .then_some((descriptor.policy, descriptor.policy_version)),
        }
    }

    /// Reads the Archive's retention state on a connection of its own
    /// (ADR-0101): subscribes to its own answer stream `stream_id` first,
    /// then pages `RetentionState` queries from the first recording until
    /// a page comes back short, within `config.list_deadline` each. Read
    /// only. The connection is closed before it returns.
    fn retention_state(
        client: &mut Client<RemoteClient>,
        config: CatalogConfig,
        stream_id: i32,
        signals: &Signals,
    ) -> Result<RetentionView, String> {
        let own = Responses::open(client, stream_id)
            .map_err(|error| format!("retention state stream {stream_id}: {error}"))?;
        let (requests, shared) = match ArchiveConnection::open(
            client,
            ControlStreams::new(config.streams.requests, config.streams.responses),
        ) {
            Ok(connection) => connection.into_transports(),
            Err(error) => {
                own.close(client);
                return Err(error.to_string());
            }
        };
        let mut requester = RetentionStateRequester::new(
            RETENTION_STATE_CLIENT_ID,
            requests,
            shared,
            own,
            stream_id,
            "karyos:ipc",
        );
        let read = pages(client, &mut requester, config, signals);
        let (requests, shared, own) = requester.into_transports();
        requests.close(client);
        shared.close(client);
        own.close(client);
        read
    }

    fn pages(
        client: &mut Client<RemoteClient>,
        requester: &mut RetentionStateRequester<
            karyos_archive::client::connection::Requests<karyos_sys::term_bytes::SharedTerms>,
            Responses<karyos_sys::term_bytes::SharedTerms>,
            Responses<karyos_sys::term_bytes::SharedTerms>,
        >,
        config: CatalogConfig,
        signals: &Signals,
    ) -> Result<RetentionView, String> {
        let mut view = RetentionView::default();
        let mut from_id = 0u64;
        let page = usize::try_from(MAX_LIST_COUNT).unwrap_or(usize::MAX);
        loop {
            requester.start(from_id, MAX_LIST_COUNT);
            let start = Instant::now();
            let answered = loop {
                if signalled(signals).is_some() {
                    return Err("the driver closed".to_owned());
                }
                let _ = client.poll();
                match requester.poll() {
                    RetentionStatePoll::Answered {
                        descriptors,
                        summary,
                    } => break (descriptors, summary),
                    RetentionStatePoll::Unsupported => return Err(UNSUPPORTED.to_owned()),
                    RetentionStatePoll::Refused { code, message } => {
                        return Err(format!("refused ({code:?}): {message}"));
                    }
                    RetentionStatePoll::Invalid => {
                        return Err("the query does not encode".to_owned());
                    }
                    _ => {
                        if start.elapsed() >= config.list_deadline {
                            return Err("no retention state within its deadline".to_owned());
                        }
                        std::thread::sleep(TICK);
                    }
                }
            };
            let (descriptors, summary) = answered;
            let last = descriptors.last().map(|descriptor| descriptor.recording_id);
            for descriptor in &descriptors {
                if view.recordings.len() < MAX_RETENTION_RECORDINGS {
                    view.recordings.push(retention_of(descriptor));
                }
            }
            view.min_free_bytes = summary.min_free_bytes;
            view.free_bytes = (summary.free_bytes != FREE_UNKNOWN).then_some(summary.free_bytes);
            match last.and_then(|last| last.checked_add(1)) {
                Some(next)
                    if descriptors.len() >= page
                        && view.recordings.len() < MAX_RETENTION_RECORDINGS =>
                {
                    from_id = next;
                }
                _ => break,
            }
        }
        view.read_at = Some(host_monotonic_ns());
        Ok(view)
    }

    fn recording(listed: &ListedRecording) -> Option<CatalogRecording> {
        let (recording, position, stopped_ns, stop_reason, incomplete) = match listed.state {
            RecordingState::Recording {
                written,
                incomplete,
            } => (true, written, None, None, incomplete),
            RecordingState::Stopped(stop) => (
                false,
                stop.position,
                Some(stop.time_ns),
                Some(reason(stop.reason)?.to_owned()),
                stop.incomplete,
            ),
            _ => return None,
        };
        Some(CatalogRecording {
            recording_id: listed.recording_id,
            stream_id: listed.stream_id,
            session_id: listed.session_id,
            channel: listed.channel.clone(),
            start: listed.start,
            start_time_ns: listed.start_time_ns,
            recording,
            position,
            stopped_ns,
            stop_reason,
            incomplete,
        })
    }

    fn reason(reason: StopReason) -> Option<&'static str> {
        Some(match reason {
            StopReason::Normal => "normal",
            StopReason::Recovered => "recovered",
            StopReason::Empty => "empty",
            StopReason::Lapped => "lapped",
            StopReason::Stopped => "stopped",
            StopReason::Shutdown => "shutdown",
            StopReason::Failed(FailKind::Source) => "failed_source",
            StopReason::Failed(FailKind::RequiredLapped) => "failed_required_lapped",
            StopReason::Failed(FailKind::Invalid) => "failed_invalid",
            _ => return None,
        })
    }

    /// What the signals ask now, if anything.
    fn signalled(signals: &Signals) -> Option<Wake> {
        if signals.stop.load(Ordering::Acquire) {
            Some(Wake::Stop)
        } else if signals.gone.load(Ordering::Acquire) {
            Some(Wake::Gone)
        } else {
            None
        }
    }

    /// Sleeps `every`, unless signalled; polls `client` meanwhile, so its
    /// connection stays alive.
    fn wait(client: Option<&mut Client<RemoteClient>>, every: Duration, signals: &Signals) -> Wake {
        let start = Instant::now();
        let mut client = client;
        while start.elapsed() < every {
            if let Some(wake) = signalled(signals) {
                return wake;
            }
            if let Some(client) = client.as_mut() {
                let _ = client.poll();
            }
            std::thread::sleep(IDLE_TICK.min(every));
        }
        signalled(signals).unwrap_or(Wake::Elapsed)
    }

    fn run(dir: &Path, config: CatalogConfig, shared: &Mutex<Catalog>, signals: &Signals) {
        while !signals.stop.load(Ordering::Acquire) {
            if let Err(error) = session(dir, config, shared, signals) {
                fail(shared, &error);
            }
            // Between sessions only a stop matters: the signal that ended
            // the last one is spent, and the next connection finds out
            // whether the driver is back.
            signals.gone.store(false, Ordering::Release);
            while matches!(wait(None, config.every, signals), Wake::Gone) {
                signals.gone.store(false, Ordering::Release);
            }
            if signals.stop.load(Ordering::Acquire) {
                return;
            }
        }
    }

    /// One connection: lists until a failure that needs a new one, or
    /// until asked to stop (`Ok`).
    fn session(
        dir: &Path,
        config: CatalogConfig,
        shared: &Mutex<Catalog>,
        signals: &Signals,
    ) -> Result<(), String> {
        // A close seen before this connection is not this one's.
        signals.gone.store(false, Ordering::Release);
        let context = Context::builder()
            .dir(dir)
            .timeout(config.connect_timeout)
            .build()
            .map_err(|error| format!("context: {error}"))?;
        let mut client = Client::connect(context).map_err(|error| format!("connect: {error}"))?;
        let (requests, responses) = ArchiveConnection::open(
            &mut client,
            ControlStreams::new(config.streams.requests, config.streams.responses),
        )
        .map_err(|error| error.to_string())?
        .into_transports();
        let mut lister =
            RecordingLister::new(ListerConfig::new(config.client_id), requests, responses);
        loop {
            lister.start();
            let start = Instant::now();
            loop {
                match signalled(signals) {
                    Some(Wake::Stop) => return Ok(()),
                    Some(_) => return Err("the driver closed".to_owned()),
                    None => {}
                }
                let _ = client.poll();
                match lister.poll() {
                    ListPoll::Done(listing) => {
                        listed(shared, listing);
                        if let Some(stream_id) = config.streams.retention {
                            let read = retention_state(&mut client, config, stream_id, signals);
                            retained(shared, read);
                        }
                        break;
                    }
                    // The Archive answered: the connection stays.
                    ListPoll::Refused { code, message } => {
                        fail(shared, &format!("refused ({code:?}): {message}"));
                        break;
                    }
                    ListPoll::Idle => break,
                    _ => {
                        if start.elapsed() >= config.list_deadline {
                            return Err("no listing within its deadline".to_owned());
                        }
                        std::thread::sleep(TICK);
                    }
                }
            }
            match wait(Some(&mut client), config.every, signals) {
                Wake::Elapsed => {}
                Wake::Stop => return Ok(()),
                Wake::Gone => return Err("the driver closed".to_owned()),
            }
        }
    }
}
