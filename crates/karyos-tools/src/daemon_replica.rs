// SPDX-License-Identifier: Apache-2.0

//! `karyosd`'s replica side of recording replication (quantstratum-docs:
//! karyos/adr/0102-replication-pushed-from-the-source.md decisions 3 to 6,
//! 8 and 10; design archive-replication.md §4; karyos#1113).
//!
//! Each `--replica` is one replication this Archive's operator accepts:
//! the source's address, the recording, and the stream it arrives on, a
//! bind endpoint the network subscription listens at. The replica only
//! listens; it sends nothing back but the stream's own status messages.
//!
//! - **Authorization** is the triple (source address, recording id,
//!   destination stream). Only images of the stream from the source's
//!   address are read; a message naming another recording is dropped and
//!   counted.
//! - **The newest incarnation.** Each request of the source comes on a
//!   fresh incarnation (a new session). The replica follows the newest
//!   image of its source and retires an older one when a newer binds, so
//!   nothing an older incarnation still delivers gets through.
//! - **The start comes first.** Payload of a request is ignored until its
//!   `streaming` status arrived. When that status's `source_start` lies
//!   above the end of the replica's last verified range, the missing
//!   interval is committed to the copy catalog as a gap, durably, before
//!   the first range is taken, and the copy starts again at the source's
//!   start.
//! - **Bytes and seals** go to [`Receiver`]: stored bytes are compared,
//!   never overwritten; a seal counts its range only once it verifies on
//!   the replica's own bytes, recorded with its arrival profile. Bytes
//!   past the tail are dropped and counted as gaps, mismatches counted
//!   and reported apart.
//! - **Lag** is against the last `ReplicationStatus`, and unknown before
//!   any and after 3 s without one (decision 8).
//! - **An interrupted replication** raises the alarm: a warning and a
//!   counter.
//!
//! The replica's store, journal and copy catalog are its own, in
//! `<archive>/replicas/<recording>`: the agent's files are locked by the
//! agent.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_archive::control::{ControlMessage, ResponseCode};
use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::copies::{ArrivalProfile, CopyCatalog, CopyState, Enforcement};
use karyos_archive::integrity::journal::IntegrityJournal;
use karyos_archive::integrity::replication::{Replica, ReplicationLag, Verdict};
use karyos_archive::replication::transport::{ReceiveError, Receiver};
use karyos_archive::replication::{ReplicationMessage, ReplicationStatus, State};
use karyos_archive::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};
use karyos_client::{ClientSubscription, MessageLimit};
use karyos_driver::DriverError;
use karyos_driver::embedded::{AggregateHandle, EmbeddedDriver};
use karyos_driver::net::NetworkSubscription;
use karyos_protocol::channel::{Destination, Security, UdpConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::Role;
use karyos_sys::term_bytes::SharedTerms;

use crate::args::ReplicaOption;

/// How long without a status before the lag reads unknown: three status
/// intervals (ADR-0102 decision 8).
pub const LAG_STALE: Duration = Duration::from_secs(3);

/// Messages read per duty at most.
const MESSAGES_PER_DUTY: usize = 16;

/// The longest message a replication stream carries.
const MAX_MESSAGE: usize = karyos_archive::replication::RECORDING_BYTES.max_length as usize;

/// Why the replicas did not start.
#[derive(Debug)]
pub enum ReplicaStartError {
    /// A replica on a network nobody declared trusted (decision 10).
    Untrusted,
    /// Two replicas of one recording: they would share a directory.
    Duplicate(u64),
    /// A replica's directory, store, journal or catalog failed to open.
    Store(String),
    /// The network subscription was refused.
    Subscribe(DriverError),
}

impl std::fmt::Display for ReplicaStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Untrusted => write!(
                f,
                "replica refused: no --replication-trusted-network, and no authenticated \
                 profile is selected"
            ),
            Self::Duplicate(recording) => {
                write!(f, "recording {recording} is replicated here twice")
            }
            Self::Store(error) => write!(f, "replica store: {error}"),
            Self::Subscribe(error) => write!(f, "replica subscription refused: {error}"),
        }
    }
}

impl std::error::Error for ReplicaStartError {}

/// The replicas' counters, for the operator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplicaCounters {
    /// Ranges counted after their seal verified.
    pub counted: u64,
    /// Bytes or seals that differ from what the replica stores: refused,
    /// counted and reported apart from gaps.
    pub mismatches: u64,
    /// Bytes past the replica's tail, dropped (`replication_gaps`).
    pub replication_gaps: u64,
    /// Gap intervals committed to the copy catalog.
    pub gaps_recorded: u64,
    /// Messages dropped for not matching the configured triple.
    pub unauthorized: u64,
    /// Payload ignored: an older request's, or before its start marker.
    pub ignored: u64,
    /// Interrupted replications: the alarm.
    pub interrupted: u64,
    /// Incarnations followed.
    pub incarnations: u64,
    /// Store, journal or catalog failures.
    pub failures: u64,
}

/// One accepted replication.
struct ReplicaListener {
    option: ReplicaOption,
    subscription: NetworkSubscription,
    /// The followed incarnation: its session, aggregate and reader.
    image: Option<(i32, AggregateHandle, ClientSubscription<SharedTerms>)>,
    /// The registration of the newest incarnation ever followed: an older
    /// one still exposed after the newest retired is never followed again.
    newest: Option<u64>,
    /// The current request: its correlation id, once its `streaming`
    /// status was seen in this incarnation.
    started: Option<u64>,
    receiver: Receiver,
    replica: Replica,
    store: SegmentStore<StdDisk>,
    journal: IntegrityJournal<StdDisk>,
    copies: CopyCatalog<StdDisk>,
    /// The last status and when it arrived.
    status: Option<(ReplicationStatus, Instant)>,
    buf: Vec<u8>,
}

/// Every replica of a daemon.
pub struct Replicas {
    listeners: Vec<ReplicaListener>,
    counters: ReplicaCounters,
}

impl std::fmt::Debug for Replicas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replicas")
            .field("listeners", &self.listeners.len())
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

/// Whether an image of `registration` may be followed, the newest
/// followed so far being `newest`: never one older, a superseded
/// incarnation (ADR-0102 decision 3). Registrations grow with each image
/// the driver exposes.
const fn follows(newest: Option<u64>, registration: u64) -> bool {
    match newest {
        Some(newest) => registration >= newest,
        None => true,
    }
}

/// The listening channel at `bind`: reliable unicast UDP on the trusted
/// profile, as the source's forwarding channel.
#[must_use]
pub fn listen_channel(bind: SocketAddr) -> UdpConfig {
    UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        path_skew: None,
        destination: Destination::Unicast(bind),
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// The replica directory of `recording` under `archive`.
#[must_use]
pub fn replica_dir(archive: &Path, recording: u64) -> PathBuf {
    archive.join("replicas").join(recording.to_string())
}

/// The replica store's geometry: fixed, so a restart reopens what it
/// wrote.
fn geometry() -> Result<Geometry, SegmentError> {
    Geometry::with_default_length(karyos_sys::sizing::MIN_TERM_LENGTH)
}

/// What one replica holds, opened or created in `dir`.
type Opened = (
    SegmentStore<StdDisk>,
    IntegrityJournal<StdDisk>,
    CopyCatalog<StdDisk>,
);

fn open_replica(dir: &Path, recording: u64) -> Result<Opened, ReplicaStartError> {
    let failed = |error: String| ReplicaStartError::Store(format!("{}: {error}", dir.display()));
    std::fs::create_dir_all(dir).map_err(|error| failed(error.to_string()))?;
    let geometry = geometry().map_err(|error| failed(error.to_string()))?;
    let store =
        match SegmentStore::recover(StdDisk, dir, recording, geometry, SyncPolicy::PerSegment) {
            Ok(recovered) => recovered.store,
            Err(SegmentError::NotFound { .. }) => {
                SegmentStore::create(StdDisk, dir, recording, geometry, SyncPolicy::PerSegment, 0)
                    .map_err(|error| failed(error.to_string()))?
            }
            Err(error) => return Err(failed(error.to_string())),
        };
    let mut journal = IntegrityJournal::open(StdDisk, dir)
        .map_err(|error| failed(error.to_string()))?
        .journal;
    let copies =
        CopyCatalog::open(StdDisk, dir, &mut journal).map_err(|error| failed(error.to_string()))?;
    Ok((store, journal, copies))
}

impl Replicas {
    /// Opens each replica's store and subscribes its stream at its bind
    /// endpoint.
    ///
    /// # Errors
    ///
    /// [`ReplicaStartError`].
    pub fn start(
        driver: &mut EmbeddedDriver<SharedTerms>,
        archive: &Path,
        location: [u8; 32],
        options: &[ReplicaOption],
        trusted_network: bool,
    ) -> Result<Self, ReplicaStartError> {
        if !options.is_empty() && !trusted_network {
            return Err(ReplicaStartError::Untrusted);
        }
        // One replica per recording: two would open one directory twice.
        for (index, option) in options.iter().enumerate() {
            if options
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.recording_id == option.recording_id)
            {
                return Err(ReplicaStartError::Duplicate(option.recording_id));
            }
        }
        let mut listeners = Vec::with_capacity(options.len());
        for option in options {
            let (store, journal, copies) = open_replica(
                &replica_dir(archive, option.recording_id),
                option.recording_id,
            )?;
            let subscription = driver
                .add_network_subscription(option.stream_id, &listen_channel(option.bind))
                .map_err(ReplicaStartError::Subscribe)?;
            // Every copy here arrived over a trusted network: no
            // authenticated profile is selected yet (decision 10).
            let replica = Replica::new(location, 0, Enforcement::Unsupported)
                .with_profile(ArrivalProfile::Trusted);
            listeners.push(ReplicaListener {
                option: *option,
                subscription,
                image: None,
                newest: None,
                started: None,
                receiver: Receiver::new(option.recording_id, replica),
                replica,
                store,
                journal,
                copies,
                status: None,
                buf: vec![0; MAX_MESSAGE],
            });
        }
        Ok(Self {
            listeners,
            counters: ReplicaCounters::default(),
        })
    }

    /// The counters.
    #[must_use]
    pub const fn counters(&self) -> ReplicaCounters {
        self.counters
    }

    /// The lag of replica `index` now: `None`, unknown, before any status
    /// and while none arrived within [`LAG_STALE`].
    #[must_use]
    pub fn lag(&self, index: usize, now: Instant) -> Option<ReplicationLag> {
        self.listeners.get(index)?.lag(now)
    }

    /// One duty of every replica; returns whether anything moved.
    pub fn duty(&mut self, driver: &mut EmbeddedDriver<SharedTerms>) -> bool {
        let now = Instant::now();
        let mut worked = false;
        for listener in &mut self.listeners {
            worked |= listener.duty(driver, now, &mut self.counters);
        }
        worked
    }

    /// Drops every reader and subscription, and syncs every store.
    pub fn shutdown(self, driver: &mut EmbeddedDriver<SharedTerms>) {
        for mut listener in self.listeners {
            listener.image = None;
            if let Err(error) = listener.store.sync() {
                tracing::warn!(%error, "replica store not synced at shutdown");
            }
            let _ = driver.remove_network_subscription(listener.subscription);
        }
    }
}

impl ReplicaListener {
    fn lag(&self, now: Instant) -> Option<ReplicationLag> {
        let (status, at) = self.status?;
        if now.saturating_duration_since(at) > LAG_STALE {
            return None;
        }
        self.replica
            .lag(
                &self.copies,
                self.option.recording_id,
                status.source_start,
                status.sealed_end,
            )
            .ok()
    }

    fn duty(
        &mut self,
        driver: &mut EmbeddedDriver<SharedTerms>,
        now: Instant,
        counters: &mut ReplicaCounters,
    ) -> bool {
        let mut worked = self.follow(driver, counters);
        for _ in 0..MESSAGES_PER_DUTY {
            let Some((_, _, reader)) = self.image.as_mut() else {
                break;
            };
            let mut length = None;
            let buf = &mut self.buf;
            let _ = reader.poll(
                |bytes, _| {
                    if let Some(into) = buf.get_mut(..bytes.len()) {
                        into.copy_from_slice(bytes);
                        length = Some(bytes.len());
                    }
                },
                MessageLimit::new(1),
            );
            let Some(length) = length else {
                break;
            };
            worked = true;
            let buf = std::mem::take(&mut self.buf);
            self.take(buf.get(..length).unwrap_or_default(), now, counters);
            self.buf = buf;
        }
        worked
    }

    /// Follows the newest image of the stream from the source's address:
    /// a newer incarnation retires the one followed, and its request
    /// starts again at its start marker.
    fn follow(
        &mut self,
        driver: &mut EmbeddedDriver<SharedTerms>,
        counters: &mut ReplicaCounters,
    ) -> bool {
        // An image older than the newest followed is a superseded
        // incarnation: never followed again.
        let newest = driver
            .network_image_from(self.subscription, self.option.source)
            .filter(|(_, handle)| follows(self.newest, handle.registration()));
        let current = self
            .image
            .as_ref()
            .map(|(session, handle, _)| (*session, *handle));
        if newest == current {
            return false;
        }
        // The older image is retired: nothing it still delivers is read.
        self.image = None;
        self.started = None;
        let Some((session, handle)) = newest else {
            return true;
        };
        let Some(lane) = handle.lane(Lane::ZERO) else {
            return true;
        };
        match driver.subscribe(lane, Role::Required) {
            Ok(reader) => {
                counters.incarnations = counters.incarnations.saturating_add(1);
                tracing::info!(
                    recording_id = self.option.recording_id,
                    session,
                    source = %self.option.source,
                    "replica follows the source's newest incarnation"
                );
                self.newest = Some(handle.registration());
                self.image = Some((session, handle, reader));
            }
            Err(error) => {
                tracing::warn!(%error, "replica image not subscribed");
            }
        }
        true
    }

    /// Acts on one message of the followed incarnation.
    fn take(&mut self, message: &[u8], now: Instant, counters: &mut ReplicaCounters) {
        let recording_id = self.option.recording_id;
        if let Ok(ControlMessage::ControlResponse(response)) = ControlMessage::decode(message) {
            if response.code != ResponseCode::Ok {
                tracing::warn!(
                    recording_id,
                    code = ?response.code,
                    message = response.message,
                    "the source refused its replication request"
                );
            }
            return;
        }
        let Ok(decoded) = ReplicationMessage::decode(message) else {
            counters.unauthorized = counters.unauthorized.saturating_add(1);
            return;
        };
        match decoded {
            ReplicationMessage::ReplicationStatus(status) => {
                if status.recording_id != recording_id {
                    counters.unauthorized = counters.unauthorized.saturating_add(1);
                    return;
                }
                self.status(&status, now, counters);
            }
            ReplicationMessage::RecordingBytes(bytes) => {
                if bytes.recording_id != recording_id {
                    counters.unauthorized = counters.unauthorized.saturating_add(1);
                    return;
                }
                if self.started != Some(bytes.correlation_id) {
                    counters.ignored = counters.ignored.saturating_add(1);
                    return;
                }
                match self
                    .receiver
                    .bytes(recording_id, bytes.start, bytes.bytes, &mut self.store)
                {
                    Ok(_) => {}
                    Err(ReceiveError::PastTail { tail, start }) => {
                        counters.replication_gaps = counters.replication_gaps.saturating_add(1);
                        tracing::warn!(
                            recording_id,
                            tail,
                            start,
                            "replica bytes past its tail dropped"
                        );
                    }
                    Err(ReceiveError::Mismatch { start }) => {
                        counters.mismatches = counters.mismatches.saturating_add(1);
                        tracing::warn!(
                            recording_id,
                            start,
                            "replica bytes differ from the stored bytes: refused"
                        );
                    }
                    Err(error) => {
                        counters.failures = counters.failures.saturating_add(1);
                        tracing::warn!(recording_id, %error, "replica bytes not stored");
                    }
                }
            }
            ReplicationMessage::SourceSeal(seal) => {
                if self.started != Some(seal.correlation_id) {
                    counters.ignored = counters.ignored.saturating_add(1);
                    return;
                }
                // The bytes are durable before the range they hold counts.
                if let Err(error) = self.store.sync() {
                    counters.failures = counters.failures.saturating_add(1);
                    tracing::warn!(recording_id, %error, "replica store not synced");
                    return;
                }
                match self.receiver.seal(
                    &seal.seal,
                    &mut self.store,
                    &mut self.copies,
                    &mut self.journal,
                ) {
                    Ok(Verdict::Counted(_)) => {
                        counters.counted = counters.counted.saturating_add(1);
                    }
                    Ok(Verdict::Corrupt(_)) => {
                        counters.mismatches = counters.mismatches.saturating_add(1);
                        tracing::warn!(
                            recording_id,
                            start = seal.seal.start,
                            end = seal.seal.end,
                            "replica seal does not verify on its bytes: nothing counted"
                        );
                    }
                    Ok(_) => {}
                    Err(ReceiveError::SealOutOfRange { start, end, .. }) => {
                        counters.mismatches = counters.mismatches.saturating_add(1);
                        tracing::warn!(
                            recording_id,
                            start,
                            end,
                            "replica seal outside its stored bytes: refused"
                        );
                    }
                    Err(error) => {
                        counters.failures = counters.failures.saturating_add(1);
                        tracing::warn!(recording_id, %error, "replica seal not checked");
                    }
                }
            }
            _ => counters.unauthorized = counters.unauthorized.saturating_add(1),
        }
    }

    fn status(&mut self, status: &ReplicationStatus, now: Instant, counters: &mut ReplicaCounters) {
        let recording_id = self.option.recording_id;
        self.status = Some((*status, now));
        match status.state {
            State::Streaming => {
                // Started only once its start is set up; a failure is
                // tried again on the next status, at least once a second.
                if self.started != Some(status.correlation_id)
                    && self.start_at(status.source_start, counters)
                {
                    self.started = Some(status.correlation_id);
                }
            }
            State::Interrupted => {
                counters.interrupted = counters.interrupted.saturating_add(1);
                tracing::warn!(
                    recording_id,
                    source_start = status.source_start,
                    sealed_end = status.sealed_end,
                    "replication interrupted"
                );
            }
            state => tracing::info!(recording_id, ?state, "replication status"),
        }
    }

    /// A request starts at the source's `start`: above the replica's last
    /// verified end, the interval between is a gap of the copy, recorded
    /// before the first range, and the copy starts again at `start`.
    /// Returns whether the copy is ready for the request's first range.
    fn start_at(&mut self, start: u64, counters: &mut ReplicaCounters) -> bool {
        let recording_id = self.option.recording_id;
        let verified_end = match self.copies.current() {
            Ok(copies) => copies
                .into_iter()
                .filter(|copy| {
                    copy.location == self.replica.location()
                        && copy.recording == recording_id
                        && copy.state == CopyState::Verified
                })
                .map(|copy| copy.end)
                .max()
                .unwrap_or_else(|| self.store.start()),
            Err(error) => {
                counters.failures = counters.failures.saturating_add(1);
                tracing::warn!(recording_id, %error, "replica copy catalog unreadable");
                return false;
            }
        };
        if start <= verified_end {
            return true;
        }
        // Unverified bytes past the verified end are not part of the
        // boundary: they go, and the store resumes at the source's start.
        if self.store.written() > verified_end
            && let Err(error) = self.store.truncate(verified_end)
        {
            counters.failures = counters.failures.saturating_add(1);
            tracing::warn!(recording_id, %error, "replica unverified tail not cut");
            return false;
        }
        let tail = self.store.written();
        if tail < start
            && let Err(error) = self.store.append_gap(tail, start)
        {
            counters.failures = counters.failures.saturating_add(1);
            tracing::warn!(recording_id, %error, "replica gap not stored");
            return false;
        }
        // The store's gap is durable before the catalog commits it: a
        // crash never leaves a committed gap past the store's tail.
        if let Err(error) = self.store.sync() {
            counters.failures = counters.failures.saturating_add(1);
            tracing::warn!(recording_id, %error, "replica gap not synced");
            return false;
        }
        match self.replica.gap(
            &mut self.copies,
            &mut self.journal,
            recording_id,
            verified_end,
            start,
        ) {
            Ok(recorded) => {
                if recorded {
                    counters.gaps_recorded = counters.gaps_recorded.saturating_add(1);
                }
                tracing::warn!(
                    recording_id,
                    from = verified_end,
                    to = start,
                    "replica records a gap: the source no longer holds it"
                );
                true
            }
            Err(error) => {
                counters.failures = counters.failures.saturating_add(1);
                tracing::warn!(recording_id, %error, "replica gap not recorded");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    #[test]
    fn the_listening_channel_is_reliable_and_trusted() {
        let channel = listen_channel("0.0.0.0:4000".parse().unwrap());
        assert!(channel.reliable);
        assert_eq!(channel.security, Security::Trusted);
    }

    /// Codex P2 6: after the newest incarnation retires, an older image
    /// still exposed is not followed again.
    #[test]
    fn a_superseded_incarnation_is_never_followed_again() {
        assert!(follows(None, 3));
        assert!(follows(Some(5), 5));
        assert!(follows(Some(5), 9));
        assert!(!follows(Some(5), 4));
    }

    #[test]
    fn a_replica_lives_in_its_own_directory() {
        assert_eq!(
            replica_dir(Path::new("/var/archive"), 5),
            PathBuf::from("/var/archive/replicas/5")
        );
    }

    /// A replica reopens what it stored: its store, journal and catalog
    /// survive a restart.
    #[test]
    fn a_replica_reopens_its_store() {
        let dir = std::env::temp_dir().join(format!("karyosd-replica-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (mut store, _, _) = open_replica(&dir, 7).unwrap();
        store.append(0, &[1; 64]).unwrap();
        store.sync().unwrap();
        drop(store);
        let (store, _, copies) = open_replica(&dir, 7).unwrap();
        assert_eq!(store.written(), 64);
        assert!(copies.records().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
