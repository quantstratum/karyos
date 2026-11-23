// SPDX-License-Identifier: Apache-2.0

//! The Archive's agent thread (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md §4 and A4; SPEC §8.1).
//!
//! The agent owns an archive directory's [`Catalog`] and its
//! [`Recorder`]s, on its own thread beside the driver: disk writes and
//! syncs block there, never on the driver's duty cycle. The host wires it:
//! the driver hands out a lane's reader, the host passes it to
//! [`ArchiveHandle::start`] as a [`FrameSource`] (SPEC §14: the driver and
//! the Archive do not depend on each other).
//!
//! - **Start.** The opened catalog is settled first: recordings a crash
//!   left open are stopped at their recovered positions. A new recording's
//!   `Started` is durable, then its store is created, then it records.
//! - **Duty.** Each cycle serves the commands, then gives every recorder a
//!   duty. A recording that ends (the seal, or a lap with `OnLap::Stop`) is
//!   closed, then stopped in the catalog, and an event says so. A recorder
//!   that fails is dropped, its recording left for the next start's settle.
//! - **Replays.** After the recorders, the replays share one budget per
//!   cycle, each in turn, so recording keeps priority. A replay is first
//!   prepared, its range checked against the recording's index, and only
//!   then given its target's sink.
//! - **Groups.** Each group's job runs after the recorders, whose
//!   positions cover its payloads. A recording that stops or fails
//!   settles the groups' references to it: by its stop, or by its frames
//!   durable at the failure, which the agent keeps beside the failed
//!   recording for references drained later. A failed recording holds its
//!   slot under the recording cap until every running group has read its
//!   ring empty after the failure; a start that needs the slot then drops
//!   the entry. A reference that raced the failure and arrives after that
//!   covers nothing. A strict group that ended
//!   because its recording failed short comes back running after a
//!   restart when the recording recovers frames that cover the reference.
//!   Its journal holds every event up to the end; the events the Gateway
//!   sent before it learned of the end are not journaled. Stopping a group
//!   refuses its sender, then drains its ring into the journal, bounded by
//!   the ring, before it closes.
//! - **Caps.** Recordings, replays and groups at once are capped; a start
//!   beyond is refused and counted.
//! - **Idle.** A cycle with nothing to do waits for a command up to the
//!   idle interval, so an idle agent does not spin.
//!
//! A caller that must not block, such as the control server on the
//! driver's thread, posts its commands and takes their answers later
//! ([`Posted`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use karyos_sys::frame::Lane;

use crate::catalog::{Catalog, CatalogError, NewRecording, Recording, StopReason, StreamFormat};
use crate::disk::Disk;
use crate::durable::DurablePosition;
use crate::group::capture::{
    self, CaptureConfig, CaptureError, CaptureJob, CaptureSender, CaptureSetup, CheckpointStep,
    GroupState,
};
use crate::group::checkpoint::{
    CheckpointError, CheckpointInbox, CheckpointRequest, CheckpointStore, CheckpointWriter,
    handoff, recorded_end, store_dir,
};
use crate::group::gateway::live::RecordingWord;
use crate::group::journal::{GroupJournal, JournalConfig, JournalError};
use crate::group::prefix::{CheckpointHeld, Coverage};
use crate::group::record::{CONTRACT_VERSION, Capture, Clock, JournalHeader};
use crate::integrity::damage::shortened_below_seal;
use crate::integrity::journal::{IntegrityError, IntegrityJournal};
use crate::integrity::ledger::{Ledger, read_entries};
use crate::integrity::sealer::{self, SealSource, Sealer};
use crate::integrity::signing::{
    HeadSigner, HeadSigning, Offered, SignerUnavailable, SigningConfig,
};
use crate::integrity::trust::{
    ChainHead, HEADS_FILE, KEYS_FILE, KeyRegistry, REGISTRY_ENTRY_LENGTH, SIGNATURE_LENGTH,
    SIGNED_HEAD_LENGTH, TrustRoot,
};
use crate::recorder::{Ended, FrameSource, Mode, Recorder, RecorderError};
use crate::replay::{Rate, ReplayError, ReplaySource, Step};
use crate::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};
use crate::server::RetentionAnswer;

/// The agent's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentConfig {
    /// Commands queued at most. A blocking call waits for room; a posted
    /// command finds none as [`AgentError::Busy`].
    pub command_capacity: usize,
    /// Recording events queued at most, and replay ends apart; a full
    /// queue drops the newest, counted by [`ArchiveHandle::dropped_events`]
    /// and [`ArchiveHandle::dropped_replay_ends`].
    pub event_capacity: usize,
    /// The copy buffer of each recorder and replay: at least the largest
    /// frame.
    pub buffer: usize,
    /// Bytes one recorder records, or one replay replays, at most per
    /// cycle.
    pub budget: u64,
    /// Bytes all replays replay at most per cycle, after the recorders;
    /// each takes at most `budget` of it, in turn.
    pub replay_budget: u64,
    /// Recordings recorded at once at most.
    pub max_recordings: usize,
    /// Replays at once at most, prepared or running.
    pub max_replays: usize,
    /// How long a prepared replay waits for its sink. Past it the agent
    /// drops it, so a sink never attached, its post lost or its server
    /// gone, does not hold a replay's slot. Keep it above the time a host
    /// takes to open a target: 0 drops every prepared replay on the
    /// agent's next cycle, before any attach can find it.
    pub prepared_timeout: Duration,
    /// How long an attached replay waits for its target's first
    /// subscriber ([`ReplaySink::ready`]) before it ends unattended
    /// ([`ReplayOutcome::NoSubscriber`]), having written nothing
    /// (`quantstratum-docs: karyos/design/archive-host.md`, H2b).
    pub attach_deadline: Duration,
    /// How long an idle cycle waits for a command.
    pub idle: Duration,
    /// Recording groups captured at once at most (A7d).
    pub max_groups: usize,
    /// Events one group's journal takes at most per cycle.
    pub group_budget: usize,
    /// Checkpoint bytes one group writes at most per cycle: a large
    /// snapshot is written over several, so it never stalls the
    /// recorders and replays sharing the thread (A9-3).
    pub checkpoint_budget: usize,
    /// The `seal_interval` (A10; karyos#961): each durable byte of a
    /// recording is sealed in the integrity journal within it, its last
    /// range when the recording stops, and the catalog's changes are
    /// chained there too. `None` keeps no integrity journal.
    pub seal_interval: Option<Duration>,
    /// This Archive's location id in the copy catalog (karyos#1024): with
    /// it, each recording that closes sealed is recorded as a verified
    /// local copy, its segments made immutable where the file system and
    /// the process allow it, and the enforcement that applies recorded.
    /// `None` records no copy. Needs `seal_interval`.
    pub copy_location: Option<crate::integrity::Digest>,
    /// The retention policy purges are checked against (karyos#1093):
    /// with it, a `PurgeRecording` runs [`Retention::purge`] against the
    /// recording's store, the copy catalog of `copy_location` counting the
    /// verified copies elsewhere. `None` refuses every purge `no_policy`.
    /// Needs `copy_location`.
    ///
    /// [`Retention::purge`]: crate::integrity::retention::Retention::purge
    pub retention_policy: Option<crate::integrity::retention::RetentionPolicy>,
}

impl AgentConfig {
    /// This configuration with `retention_policy` set (karyos#1093).
    #[must_use]
    #[inline]
    pub const fn with_retention_policy(
        mut self,
        policy: Option<crate::integrity::retention::RetentionPolicy>,
    ) -> Self {
        self.retention_policy = policy;
        self
    }

    /// This configuration with `copy_location` set (karyos#1024).
    #[must_use]
    #[inline]
    pub const fn with_copy_location(
        mut self,
        copy_location: Option<crate::integrity::Digest>,
    ) -> Self {
        self.copy_location = copy_location;
        self
    }

    /// This configuration with `seal_interval` set (A10).
    #[must_use]
    #[inline]
    pub const fn with_seal_interval(mut self, seal_interval: Option<Duration>) -> Self {
        self.seal_interval = seal_interval;
        self
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            command_capacity: 64,
            event_capacity: 256,
            buffer: 64 * 1024,
            budget: 1 << 20,
            replay_budget: 1 << 20,
            max_recordings: 64,
            max_replays: 16,
            prepared_timeout: Duration::from_secs(5),
            attach_deadline: Duration::from_secs(5),
            idle: Duration::from_millis(1),
            max_groups: 16,
            group_budget: 64,
            checkpoint_budget: 256 * 1024,
            seal_interval: None,
            copy_location: None,
            retention_policy: None,
        }
    }
}

/// A recording group to capture (A7d; `quantstratum-docs:
/// karyos/design/recording-group-gateway.md` section 9): its journal, made
/// new or recovered, and its capture path. The agent serves the group's
/// job in its cycle, after the recorders.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StartGroup {
    /// The group, never 0.
    pub group_id: u64,
    /// The directory of group journals, which the host made: it holds
    /// group journals only.
    pub dir: PathBuf,
    /// A new group's journal header; `None` recovers the group's journal
    /// from `dir`, its prefixes recomputed over the recordings this Archive
    /// keeps.
    pub new: Option<NewGroup>,
    /// The journal's segments and sync policy.
    pub journal: JournalConfig,
    /// The capture path's ring and bounds.
    pub capture: CaptureConfig,
    /// The group's checkpoints (A9-3), or `None` for a group that keeps
    /// none.
    pub checkpoints: Option<GroupCheckpoints>,
    /// The capture session's declared event clock, for time evidence
    /// (ADR-0098; karyos#1137); `None` declares none, and the group gets
    /// no entries.
    pub time_evidence: Option<GroupTimeEvidence>,
}

/// A capture session's time evidence (ADR-0098 item 1): the declared
/// clock of the `logical_time`s the event loop passes, and how long a
/// sealed range waits for the calibration journal to reach it.
///
/// Entries are kept only when the Archive seals (an integrity journal) and
/// the host made `time-evidence/` in the group journal directory, as for
/// the Archive's own entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupTimeEvidence {
    /// The declared clock; the zero tuple is refused
    /// ([`AgentError::ZeroEventClock`]).
    pub clock: crate::integrity::time_producer::EventClock,
    /// The longest a sealed range waits for the calibration journal to
    /// publish past its largest timestamp; past it, its entries are
    /// `no_evidence`.
    pub calibration_wait: Duration,
    /// The identity of the group directory's store journal in the trust
    /// root, when the Archive signs heads: its entries' journal is signed
    /// and anchored by the Archive's signer under it, as the trust file's
    /// `time-journal` of the groups directory. Required when the Archive
    /// signs ([`AgentError::NoTimeEvidenceJournal`]), distinct from the
    /// Archive's own journals ([`AgentError::SharedJournalId`]), and the
    /// same for every group of one directory
    /// ([`AgentError::GroupStoreJournalId`]).
    pub journal_id: Option<u64>,
}

impl GroupTimeEvidence {
    /// The declaration of `clock`, waiting at most `calibration_wait`.
    #[must_use]
    pub const fn new(
        clock: crate::integrity::time_producer::EventClock,
        calibration_wait: Duration,
    ) -> Self {
        Self {
            clock,
            calibration_wait,
            journal_id: None,
        }
    }

    /// Names the group directory's store journal identity, for signing.
    #[must_use]
    pub const fn with_journal_id(mut self, journal_id: u64) -> Self {
        self.journal_id = Some(journal_id);
        self
    }
}

impl StartGroup {
    /// Starts group `group_id` from its journal in `dir`: a restart, with
    /// no checkpoints ([`StartGroup::with_new`] makes the group,
    /// [`StartGroup::with_checkpoints`] keeps checkpoints).
    #[must_use]
    pub const fn new(
        group_id: u64,
        dir: PathBuf,
        journal: JournalConfig,
        capture: CaptureConfig,
    ) -> Self {
        Self {
            group_id,
            dir,
            new: None,
            journal,
            capture,
            checkpoints: None,
            time_evidence: None,
        }
    }

    /// Makes the group, with this header.
    #[must_use]
    pub fn with_new(mut self, new: NewGroup) -> Self {
        self.new = Some(new);
        self
    }

    /// Keeps checkpoints.
    #[must_use]
    pub const fn with_checkpoints(mut self, checkpoints: GroupCheckpoints) -> Self {
        self.checkpoints = Some(checkpoints);
        self
    }

    /// Declares the capture session's event clock, for time evidence.
    #[must_use]
    pub const fn with_time_evidence(mut self, evidence: GroupTimeEvidence) -> Self {
        self.time_evidence = Some(evidence);
        self
    }
}

/// How a group's checkpoints are kept. Their store is in the journal
/// directory's `checkpoints` subdirectory
/// ([`store_dir`]), which the host
/// made, as it made the journal directory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupCheckpoints {
    /// The largest snapshot, at least 1 byte: the Gateway's buffer.
    pub max_checkpoint: usize,
    /// The events a reopening checkpoint's range keeps while it is written
    /// over several cycles: those expected to end during one checkpoint
    /// write, with the Gateway unbounded while stopped. `None` is four
    /// times the capture's `in_flight`. A best-effort group under traffic
    /// beyond it reopens at a later checkpoint, counted
    /// ([`PrefixTracker::failed_reopens`](crate::group::prefix::PrefixTracker::failed_reopens)).
    /// A hold below `in_flight` is taken as `in_flight`; one above
    /// [`MAX_REOPEN_HOLD`] is refused ([`AgentError::CheckpointConfig`]).
    /// It is fixed when the group is made and recorded in its journal's
    /// header, which recovery and the running tracker both take; the
    /// default is computed only then. A restart is refused when the
    /// effective window it names, `max(hold, in_flight)`, differs from
    /// the recorded one, when its `in_flight` is above it, or when it
    /// turns checkpoints on or off: they are fixed per group. Raising a
    /// group's hold would take a record of the raise in its journal; none
    /// exists yet.
    pub reopen_hold: Option<usize>,
}

impl GroupCheckpoints {
    /// Checkpoints of up to `max_checkpoint` bytes, the reopen hold the
    /// default ([`GroupCheckpoints::with_reopen_hold`] sets it).
    #[must_use]
    pub const fn new(max_checkpoint: usize) -> Self {
        Self {
            max_checkpoint,
            reopen_hold: None,
        }
    }

    /// The reopen hold, in events.
    #[must_use]
    pub const fn with_reopen_hold(mut self, hold: usize) -> Self {
        self.reopen_hold = Some(hold);
        self
    }
}

/// The largest reopening window a group takes, in events: its hold, or
/// its `in_flight` when larger. The window's three queues are allocated
/// to it when the group starts, about 216 bytes an event, about 14 MiB at
/// the cap. The journal header's bound
/// ([`crate::group::record::MAX_REOPEN_HOLD`]).
pub const MAX_REOPEN_HOLD: usize = 1 << 16;

// The agent's bound is the header's.
const _: () =
    assert!(MAX_REOPEN_HOLD == 1 << 16 && crate::group::record::MAX_REOPEN_HOLD == 1 << 16);

/// A new group's journal header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewGroup {
    /// The first event's `group_seq`, never 0.
    pub first_group_seq: u64,
    /// The payload size above which a `required` source's payload is
    /// stored by reference.
    pub inline_threshold: u32,
    /// Strict or best effort.
    pub capture: Capture,
    /// The caller's identity of what ran, 1 to 4096 bytes.
    pub manifest: Vec<u8>,
}

impl NewGroup {
    /// A new group's header: its first event, inline threshold, capture
    /// mode and manifest.
    #[must_use]
    pub const fn new(
        first_group_seq: u64,
        inline_threshold: u32,
        capture: Capture,
        manifest: Vec<u8>,
    ) -> Self {
        Self {
            first_group_seq,
            inline_threshold,
            capture,
            manifest,
        }
    }
}

/// What a recording reads, as its host knows it (karyos#490): a local
/// stream, the publication side of a stream this host publishes, or a
/// network image of one. A host recording its own `karyos:udp`
/// publication beside that publication's loopback image has two
/// recordings of one stream, session and lane, with the same channel and
/// source incarnation: only this tells them apart. It is not kept in the
/// catalog: it serves the live lookup of a recording's word only, and a
/// host restarting a recording hands it over again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RecordedFrom {
    /// A local stream: the stream itself, on its publication side.
    #[default]
    Local,
    /// A network image of the stream.
    Image,
}

/// A recording to start, with its source.
#[non_exhaustive]
pub struct StartRecording {
    /// The recorded stream.
    pub stream_id: i32,
    /// The recorded session.
    pub session_id: i32,
    /// The channel.
    pub channel: Vec<u8>,
    /// Its segment geometry.
    pub geometry: Geometry,
    /// Its sync policy.
    pub policy: SyncPolicy,
    /// Required or async.
    pub mode: Mode,
    /// The recorded stream's format, which a replay needs.
    pub format: StreamFormat,
    /// The lane's reader, positioned at the recording's start.
    pub source: Box<dyn FrameSource + Send>,
    /// What the source reads; a local stream unless the host says
    /// otherwise.
    pub origin: RecordedFrom,
}

impl StartRecording {
    /// Records stream `stream_id`, session `session_id`, on `channel`,
    /// from `source`.
    #[must_use]
    #[allow(clippy::too_many_arguments, reason = "every field is required")]
    pub fn new(
        stream_id: i32,
        session_id: i32,
        channel: Vec<u8>,
        geometry: Geometry,
        policy: SyncPolicy,
        mode: Mode,
        format: StreamFormat,
        source: Box<dyn FrameSource + Send>,
    ) -> Self {
        Self {
            stream_id,
            session_id,
            channel,
            geometry,
            policy,
            mode,
            format,
            source,
            origin: RecordedFrom::Local,
        }
    }

    /// The same, recording `origin` (karyos#490).
    #[must_use]
    pub fn with_origin(mut self, origin: RecordedFrom) -> Self {
        self.origin = origin;
        self
    }
}

impl core::fmt::Debug for StartRecording {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartRecording")
            .field("stream_id", &self.stream_id)
            .field("session_id", &self.session_id)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// What the agent reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A recording ended and is stopped in the catalog.
    Ended {
        /// The recording.
        id: u64,
        /// Where and why.
        ended: Ended,
    },
    /// A recording's store or catalog failed: the recording stays open in
    /// the catalog until the next start settles it, at what its segments
    /// recover. (A source that fails ends the recording instead, with
    /// [`StopReason::Failed`].)
    Failed {
        /// The recording.
        id: u64,
        /// What failed.
        failure: Failure,
        /// The position its store had written when it failed.
        position: u64,
    },
    /// At start, a recording a crash left open recovered below what its
    /// seals cover: media damage shortened its index, and the range
    /// `[written, sealed_end)` is lost (A10; karyos#671). The verifier
    /// reports it `inconsistent` with `shortened_index`.
    IndexShortened(crate::integrity::damage::ShortenedIndex),
}

/// A replay that ended by itself; its target was told with
/// [`ReplaySink::finish`]. (One stopped by command reports nothing.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReplayEnded {
    /// The replay.
    pub id: u64,
    /// Where it ended.
    pub position: u64,
    /// How.
    pub outcome: ReplayOutcome,
}

/// Where a replay delivers what it reads: the host's replay target, such
/// as a driver stream that keeps the recorded positions. Each call either
/// takes the step whole (`Ok(true)`) or has no room for it yet
/// (`Ok(false)`), in which case the same step comes again on a later duty.
pub trait ReplaySink {
    /// Whole frames at `position`, as the log held them.
    ///
    /// # Errors
    ///
    /// [`SinkClosed`] when the target is gone; the replay ends.
    fn frames(&mut self, position: u64, bytes: &[u8]) -> Result<bool, SinkClosed>;

    /// A padding or aborted block: its canonical record, covering `extent`
    /// bytes from `position`.
    ///
    /// # Errors
    ///
    /// As [`ReplaySink::frames`].
    fn fill(&mut self, position: u64, record: &[u8], extent: u32) -> Result<bool, SinkClosed>;

    /// A range the recording lost.
    ///
    /// # Errors
    ///
    /// As [`ReplaySink::frames`].
    fn gap(&mut self, from: u64, to: u64) -> Result<bool, SinkClosed>;

    /// The replay ended at `end`: `complete` when it reached its requested
    /// end, else it was stopped or failed.
    fn finish(&mut self, end: u64, complete: bool);

    /// Whether the target is ready for the replay's first step: a target
    /// that waits for its first reader answers `false` until it has one,
    /// so that reader reads the replay from its first position. Asked
    /// before every step until it first answers `true`; never again after.
    /// A replay that stays not ready past the agent's
    /// [`AgentConfig::attach_deadline`] ends
    /// [`ReplayOutcome::NoSubscriber`]. Ready at once by default.
    fn ready(&mut self) -> bool {
        true
    }
}

/// A replay target that is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the replay target is closed")]
pub struct SinkClosed;

/// A replay to start: a recording's range onto a host's target.
#[non_exhaustive]
pub struct StartReplay {
    /// The recording.
    pub recording_id: u64,
    /// The first position, a frame boundary.
    pub from: u64,
    /// The end, at most the recording's end ([`ArchiveHandle::describe`]).
    pub to: u64,
    /// The pace.
    pub rate: Rate,
    /// The target.
    pub sink: Box<dyn ReplaySink + Send>,
}

impl StartReplay {
    /// Replays `recording_id` over `[from, to)` at `rate` into `sink`.
    #[must_use]
    pub fn new(
        recording_id: u64,
        from: u64,
        to: u64,
        rate: Rate,
        sink: Box<dyn ReplaySink + Send>,
    ) -> Self {
        Self {
            recording_id,
            from,
            to,
            rate,
            sink,
        }
    }
}

impl core::fmt::Debug for StartReplay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartReplay")
            .field("recording_id", &self.recording_id)
            .field("from", &self.from)
            .field("to", &self.to)
            .field("rate", &self.rate)
            .finish_non_exhaustive()
    }
}

/// A replay to prepare: a recording's range, checked against its index
/// before any target exists ([`ArchiveHandle::post_prepare_replay`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrepareReplay {
    /// The recording.
    pub recording_id: u64,
    /// The first position: a frame boundary at or after the recording's
    /// start.
    pub position: u64,
    /// The bytes to replay; `u64::MAX` replays to the recording's end now.
    pub length: u64,
    /// The pace.
    pub rate: Rate,
}

impl PrepareReplay {
    /// A replay of `length` bytes of `recording_id` from `position`, at
    /// `rate`.
    #[must_use]
    pub const fn new(recording_id: u64, position: u64, length: u64, rate: Rate) -> Self {
        Self {
            recording_id,
            position,
            length,
            rate,
        }
    }
}

/// A prepared replay, waiting for its target's sink
/// ([`ArchiveHandle::post_attach_replay`]); it counts toward
/// [`AgentConfig::max_replays`] until it is attached or stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Prepared {
    /// The replay's id.
    pub replay_id: u64,
    /// The recording, as the catalog lists it.
    pub recording: Recording,
    /// The range: `[from, to)`.
    pub from: u64,
    /// Its end.
    pub to: u64,
}

/// How a replay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplayOutcome {
    /// It reached its requested end.
    Complete,
    /// Its recording could not be read, or its target closed.
    Failed,
    /// Its target had no reader within the attach deadline
    /// ([`ReplaySink::ready`]): it wrote nothing.
    NoSubscriber,
}

/// A recording as the catalog lists it, and where it ends now: its stop,
/// or the position written for one that still records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Described {
    /// The catalog's record.
    pub recording: Recording,
    /// Its end now.
    pub end: u64,
    /// Its durable position now: every byte below it, with its index, is
    /// on storage. Its stop once stopped, since the close syncs first.
    pub durable: u64,
    /// It lost ranges: its stop's, or so far for one that records.
    pub incomplete: bool,
}

/// What failed when a recording could not be stopped in the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// Its segment store, while recording.
    Store,
    /// Closing its store or appending its `Stopped` record.
    Stop,
}

/// The agent's errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// A group's declared event clock is the reserved all zero identity,
    /// which means "provenance unknown" (karyos#1137): declare none.
    #[error("the all zero clock identity is reserved: declare no clock instead")]
    ZeroEventClock,
    /// A group declares a store journal identity other than the one its
    /// directory's store is already signed under (karyos#1137): one store
    /// per directory has one identity.
    #[error("the group directory's store is signed as journal {signed}, not {declared}")]
    GroupStoreJournalId {
        /// The identity the directory's store is signed under.
        signed: u64,
        /// The group's.
        declared: u64,
    },
    /// A replication the source refuses (ADR-0091; karyos#1113): answered
    /// with its `ControlResponse` code.
    #[error("replication refused: {0:?}")]
    ReplicationRefused(crate::replication::transport::Refusal),
    /// The agent's count of failed recordings, or of recordings it holds,
    /// would pass its range: the start is refused.
    #[error("the agent's recording counts are exhausted")]
    Exhausted,
    /// The catalog failed.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// A store failed.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// A recorder failed.
    #[error(transparent)]
    Recorder(#[from] RecorderError),
    /// The integrity journal failed (A10).
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    /// No time evidence is kept: no integrity journal, or no
    /// `time-evidence/` directory the host made (karyos#1128).
    #[error("this Archive keeps no time evidence")]
    NoTimeEvidence,
    /// A time evidence entry for a range its recording's seals do not
    /// cover whole: an entry follows its range's seal (ADR-0095).
    #[error(
        "recording {recording} is sealed over [{first}, {sealed}), which does not hold the entry's [{start}, {end})"
    )]
    TimeEvidenceUnsealed {
        /// The recording.
        recording: u64,
        /// The entry's start.
        start: u64,
        /// The entry's end.
        end: u64,
        /// Where its seals start.
        first: u64,
        /// Where its seals end.
        sealed: u64,
    },
    /// A time evidence entry for a recording nothing of which is sealed,
    /// or that this Archive does not know (karyos#1128).
    #[error("recording {recording} has no sealed range")]
    TimeEvidenceNoSeal {
        /// The recording.
        recording: u64,
    },
    /// The entries could not be written.
    #[error(transparent)]
    TimeEvidence(#[from] crate::integrity::time_evidence::StoreError),
    /// The shared head signer's lock is poisoned: a thread panicked
    /// holding it, so the signer's state is unknown and no head is asked
    /// of it (karyos#1128).
    #[error("the head signer's lock is poisoned: no head is signed")]
    SignerPoisoned,
    /// Head signing configures no time evidence journal identity: an
    /// entry would have no journal to be signed as (karyos#1128).
    #[error("time evidence needs its own journal id: the trust file has no time-journal line")]
    NoTimeEvidenceJournal,
    /// The time evidence entries' journal was given the integrity
    /// journal's identity: each chain needs its own (karyos#1128).
    #[error("the time evidence journal needs a journal id of its own")]
    SharedJournalId,
    /// Head signing was asked for without a `seal_interval`: there would
    /// be no seals to sign.
    #[error("head signing needs a seal_interval")]
    SigningWithoutSealing,
    /// A retention policy was given without a `copy_location` and a
    /// `seal_interval`: a purge needs the copy catalog and the seals
    /// (karyos#1093).
    #[error("a retention policy needs a copy_location and a seal_interval")]
    PolicyWithoutCopies,
    /// No such recording records.
    #[error("recording {id} is not recording")]
    NotRecording {
        /// The id.
        id: u64,
    },
    /// No recording or replay has this id.
    #[error("no recording or replay {id}")]
    Unknown {
        /// The id.
        id: u64,
    },
    /// A replay's range is not readable.
    #[error(transparent)]
    Replay(#[from] ReplayError),
    /// The recording failed ([`Event::Failed`]); the next start settles it.
    #[error("recording {id} failed")]
    RecordingFailed {
        /// The id.
        id: u64,
    },
    /// As many recordings or replays as the configuration allows run
    /// already; counted by [`ArchiveHandle::refused`].
    #[error("at most {max} {what} at once")]
    Full {
        /// Recordings or replays.
        what: &'static str,
        /// The cap.
        max: usize,
    },
    /// Every replay id was used.
    #[error("replay ids are exhausted")]
    IdsExhausted,
    /// A posted command found the command queue full.
    #[error("the agent's command queue is full")]
    Busy,
    /// The agent's thread is gone.
    #[error("the agent stopped")]
    Gone,
    /// A recording group's journal could not be made, recovered or closed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A recording group's journal already holds network images of an
    /// earlier run, which this run's could repeat (ADR-0089): the group
    /// continues in a new journal.
    ///
    /// **What an operator sees.** After a restart of the host (or of the
    /// driver it records from), the restart of a group whose journal
    /// recorded any network image fails with this error, and nothing is
    /// written: the earlier journal stays as it was, complete and
    /// replayable. A group that recorded IPC streams only is not refused.
    /// The reason is that an image is named by its driver registration,
    /// which is unique within one driver incarnation only: a new run may
    /// reuse a registration of the earlier one, and replay would then
    /// merge two different images.
    ///
    /// **How to continue.** Start the group as new
    /// ([`StartGroup::with_new`]) in a journal of its own: one journal
    /// holds one group per directory, so either give it a new directory
    /// ([`StartGroup::dir`]), keeping the group id, or keep the directory
    /// and give it a new group id. To keep `group_seq` continuous for
    /// consumers, set [`NewGroup::first_group_seq`] to the earlier
    /// journal's `complete_recording_seq` plus one, as its replay reports
    /// it (`Stop::EndOfPrefix`). Keep the earlier journal while anything may
    /// still replay it; retention handles it like any other journal.
    #[error("the group journal holds network images of an earlier run")]
    ImagesOfAnEarlierRun,
    /// A recording group's capture settings cannot work.
    #[error(transparent)]
    Capture(#[from] CaptureError),
    /// A group's checkpoints are configured so they cannot work: their
    /// size, or the agent's budget per cycle, is 0, or the reopen hold is
    /// above [`MAX_REOPEN_HOLD`]. Nothing is made (A9-3).
    #[error("invalid checkpoint configuration")]
    CheckpointConfig,
    /// A restart of a group whose journal never got its header: nothing
    /// says how it was made. Start it as new (`StartGroup::new`), which
    /// writes the header into the empty journal.
    #[error("group {id}'s journal has no header: start it as new")]
    NoHeader {
        /// The group.
        id: u64,
    },
    /// With sealing on, a group journal in the Archive's own directory:
    /// that directory's integrity journal is the Archive's, held under its
    /// lock, so the group's journal could not be sealed (karyos#1112).
    /// Refused before the journal exists; put the group's journal in a
    /// directory of its own.
    #[error(
        "group journal directory {dir:?} is the Archive's own: its journal cannot be sealed there"
    )]
    GroupInArchiveDirectory {
        /// The directory.
        dir: PathBuf,
    },
    /// With sealing on, a group journal directory, or the Archive's own
    /// directory, that does not resolve to a directory on the host
    /// (`std::fs::canonicalize` failed): the two cannot be told apart, so
    /// the group is refused before its journal exists (karyos#1140,
    /// karyos#1149). `dir` names the one that did not resolve.
    #[error(
        "directory {dir:?} (the group journal's or the Archive's own) does not resolve: {kind}"
    )]
    GroupDirectoryUnresolved {
        /// The directory as given.
        dir: PathBuf,
        /// Why it did not resolve.
        kind: std::io::ErrorKind,
    },
    /// A journal whose recovery would cut it to nothing, dropping more
    /// than the header's own write: a damaged header that events
    /// followed, not one torn while it was written. Neither a restart nor
    /// a new start takes it, and nothing is cut, so the journal can be
    /// copied.
    #[error("group {id}'s journal lost its header: recovery cut it at {cut:?}")]
    HeaderCut {
        /// The group.
        id: u64,
        /// Where and why recovery cut it.
        cut: crate::segment::Cut,
    },
    /// A group's checkpoint writer could not start (A9-3).
    #[error(transparent)]
    Checkpoint(Box<CheckpointError>),
    /// A recording group of that id is already captured.
    #[error("group {id} is already captured")]
    GroupCaptured {
        /// The group.
        id: u64,
    },
    /// The thread could not be spawned.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Reply<T> = SyncSender<Result<T, AgentError>>;

enum Command {
    Start(Box<StartRecording>, Reply<u64>),
    Stop(u64, Reply<Ended>),
    List(Reply<Vec<Recording>>),
    Word {
        stream_id: i32,
        session_id: i32,
        lane: Lane,
        reply: Reply<Option<Arc<RecordingWord>>>,
    },
    Snapshot {
        from_id: u64,
        max: usize,
        reply: Reply<Vec<Described>>,
    },
    Describe(u64, Reply<Described>),
    Prepare(PrepareReplay, Reply<Prepared>),
    Attach {
        id: u64,
        from: u64,
        sink: Box<dyn ReplaySink + Send>,
        reply: Reply<u64>,
    },
    Replay(Box<StartReplay>, Reply<u64>),
    StopReplay(u64, Reply<u64>),
    StartGroup(Box<StartGroup>, Reply<CaptureSender>),
    StopGroup(u64, Reply<u64>),
    /// A hold, a release or a purge (ADR-0088).
    Retain(retention::Request, Reply<RetentionAnswer>),
    /// A seal verification (ADR-0088).
    Verify(u64, Reply<retention::Verified>),
    /// A retention state snapshot (ADR-0101).
    RetentionState {
        from_id: u64,
        max: usize,
        reply: Reply<Vec<crate::control::RetentionDescriptor>>,
    },
    /// A replica's request (ADR-0091; karyos#1113).
    Replicate(
        crate::replication::ReplicateRecording,
        usize,
        Reply<Receiver<crate::replication::transport::Outgoing>>,
    ),
    /// A replica's stop.
    StopReplication(crate::replication::StopReplication, Reply<()>),
    /// Whether a replication with this `correlation_id` is still active
    /// (ADR-0102 decision 3).
    ReplicationActive(u64, Reply<bool>),
    /// A time evidence entry to record (karyos#1128).
    TimeEvidence(Box<crate::integrity::time_evidence::Entry>, Reply<u64>),
    /// The calibration source for groups' time evidence (karyos#1137).
    CalibrationSource(
        Box<dyn crate::integrity::time_producer::CalibrationSource>,
        Reply<()>,
    ),
    Shutdown(Reply<()>),
}

impl Command {
    /// A command never served: a sink it carries is finished, incomplete,
    /// so its target does not wait for a replay that will not come.
    fn abandon(self) {
        match self {
            Self::Attach { from, mut sink, .. } => sink.finish(from, false),
            Self::Replay(mut start, _) => start.sink.finish(start.from, false),
            _ => {}
        }
    }
}

/// The host's handle on a running agent.
#[derive(Debug)]
pub struct ArchiveHandle {
    commands: SyncSender<Command>,
    events: Receiver<Event>,
    replay_ends: Receiver<ReplayEnded>,
    counts: Arc<Counts>,
    thread: Option<JoinHandle<()>>,
}

/// The agent's counters, each sticky at `u64::MAX` rather than wrapping.
#[derive(Debug, Default)]
struct Counts {
    dropped_events: AtomicU64,
    dropped_replay_ends: AtomicU64,
    refused: AtomicU64,
    fenced_recordings: AtomicU64,
    rejoined_recordings: AtomicU64,
    shortened_indexes: AtomicU64,
    /// Signing polls refused because the shared signer's lock is
    /// poisoned (karyos#1128).
    poisoned_signer: AtomicU64,
    /// Allocations and frees the replication duties made, counted on
    /// the agent's thread for the steady state test (karyos#1113).
    #[cfg(test)]
    replication_allocations: AtomicU64,
    /// The shortened indexes found at start, kept whole for
    /// [`ArchiveHandle::shortened_index_reports`]: the event queue may
    /// drop some before a caller can read it (karyos#671 review).
    shortened_reports: std::sync::Mutex<Vec<crate::integrity::damage::ShortenedIndex>>,
    /// The last signing status, once signing ran (karyos#1031).
    signing: std::sync::Mutex<Option<SigningLag>>,
}

/// The coverage lag of the running Archive's head signing, as its last
/// signing poll left it (SPEC.md §8.4; karyos#1031).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SigningLag {
    /// Records sealed past the last signed head.
    pub records: u64,
    /// How long the oldest uncovered record has waited, in ns.
    pub ns: u64,
    /// Whether records stay uncovered past `anchor_interval`.
    pub alarm: bool,
    /// Heads waiting for the signer.
    pub pending: u64,
}

/// Adds one to `counter`, sticky at `u64::MAX`.
fn count(counter: &AtomicU64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
    });
}

impl core::fmt::Debug for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Start(start, _) => f.debug_tuple("Start").field(start).finish(),
            Self::Stop(id, _) => f.debug_tuple("Stop").field(id).finish(),
            Self::List(_) => f.write_str("List"),
            Self::Word {
                stream_id,
                session_id,
                lane,
                ..
            } => f
                .debug_struct("Word")
                .field("stream_id", stream_id)
                .field("session_id", session_id)
                .field("lane", lane)
                .finish_non_exhaustive(),
            Self::Snapshot { from_id, max, .. } => f
                .debug_struct("Snapshot")
                .field("from_id", from_id)
                .field("max", max)
                .finish_non_exhaustive(),
            Self::Describe(id, _) => f.debug_tuple("Describe").field(id).finish(),
            Self::Prepare(prepare, _) => f.debug_tuple("Prepare").field(prepare).finish(),
            Self::Attach { id, from, .. } => f
                .debug_struct("Attach")
                .field("id", id)
                .field("from", from)
                .finish_non_exhaustive(),
            Self::Replay(start, _) => f.debug_tuple("Replay").field(start).finish(),
            Self::StopReplay(id, _) => f.debug_tuple("StopReplay").field(id).finish(),
            Self::StartGroup(start, _) => f.debug_tuple("StartGroup").field(start).finish(),
            Self::StopGroup(id, _) => f.debug_tuple("StopGroup").field(id).finish(),
            Self::Retain(request, _) => f.debug_tuple("Retain").field(request).finish(),
            Self::Verify(id, _) => f.debug_tuple("Verify").field(id).finish(),
            Self::RetentionState { from_id, max, .. } => f
                .debug_struct("RetentionState")
                .field("from_id", from_id)
                .field("max", max)
                .finish_non_exhaustive(),
            Self::Replicate(request, _, _) => f.debug_tuple("Replicate").field(request).finish(),
            Self::StopReplication(stop, _) => f.debug_tuple("StopReplication").field(stop).finish(),
            Self::ReplicationActive(correlation_id, _) => f
                .debug_tuple("ReplicationActive")
                .field(correlation_id)
                .finish(),
            Self::TimeEvidence(entry, _) => f.debug_tuple("TimeEvidence").field(entry).finish(),
            Self::CalibrationSource(source, _) => {
                f.debug_tuple("CalibrationSource").field(source).finish()
            }
            Self::Shutdown(_) => f.write_str("Shutdown"),
        }
    }
}

/// An answer the agent sends later, to a command posted without waiting.
#[derive(Debug)]
pub struct Posted<T> {
    answer: Receiver<Result<T, AgentError>>,
}

impl<T> Posted<T> {
    /// The answer, once the agent sent it; `None` until then. It is
    /// returned once: a later call finds [`AgentError::Gone`].
    #[must_use]
    pub fn try_answer(&self) -> Option<Result<T, AgentError>> {
        match self.answer.try_recv() {
            Ok(answer) => Some(answer),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(AgentError::Gone)),
        }
    }
}

impl ArchiveHandle {
    /// Spawns the agent of `dir` on `disk`. The catalog is opened and
    /// settled before this returns, on the agent's thread.
    ///
    /// # Errors
    ///
    /// The catalog's and the thread's errors.
    pub fn spawn<D>(disk: D, dir: &Path, config: AgentConfig) -> Result<Self, AgentError>
    where
        D: Disk + Clone + Send + 'static,
        D::File: Send,
    {
        Self::spawn_with(disk, dir, config, None)
    }

    /// As [`ArchiveHandle::spawn`], with the heads of the integrity journal
    /// signed on the agent's control path by `signing`'s signer and
    /// recorded in `heads.kyh` (A10; karyos#966). Needs
    /// [`AgentConfig::seal_interval`].
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::spawn`]; [`AgentError::SigningWithoutSealing`]
    /// without a `seal_interval`.
    pub fn spawn_signing<D>(
        disk: D,
        dir: &Path,
        config: AgentConfig,
        signing: ArchiveSigning,
    ) -> Result<Self, AgentError>
    where
        D: Disk + Clone + Send + 'static,
        D::File: Send,
    {
        Self::spawn_with(disk, dir, config, Some(signing))
    }

    fn spawn_with<D>(
        disk: D,
        dir: &Path,
        config: AgentConfig,
        signing: Option<ArchiveSigning>,
    ) -> Result<Self, AgentError>
    where
        D: Disk + Clone + Send + 'static,
        D::File: Send,
    {
        if signing.is_some() && config.seal_interval.is_none() {
            return Err(AgentError::SigningWithoutSealing);
        }
        if signing
            .as_ref()
            .is_some_and(|signing| signing.time_evidence_journal_id == Some(signing.journal_id))
        {
            return Err(AgentError::SharedJournalId);
        }
        if config.retention_policy.is_some()
            && (config.copy_location.is_none() || config.seal_interval.is_none())
        {
            return Err(AgentError::PolicyWithoutCopies);
        }
        let (commands, inbox) = mpsc::sync_channel(config.command_capacity);
        let (events_in, events) = mpsc::sync_channel(config.event_capacity);
        let (replay_ends_in, replay_ends) = mpsc::sync_channel(config.event_capacity);
        let (ready, started) = mpsc::sync_channel(1);
        let dir = dir.to_path_buf();
        let counts = Arc::new(Counts::default());
        let outbox = Outbox {
            events: events_in,
            replay_ends: replay_ends_in,
            counts: Arc::clone(&counts),
        };
        let thread = std::thread::Builder::new()
            .name("karyos-archive".to_owned())
            .spawn(move || run(disk, dir, config, signing, &inbox, &outbox, &ready))?;
        match started.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                events,
                replay_ends,
                counts,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(AgentError::Gone)
            }
        }
    }

    fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> Result<T, AgentError> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.commands
            .send(make(reply))
            .map_err(|_| AgentError::Gone)?;
        answer.recv().map_err(|_| AgentError::Gone)?
    }

    /// Posts a command without waiting for room or for its answer.
    fn post<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> Result<Posted<T>, AgentError> {
        let (reply, answer) = mpsc::sync_channel(1);
        match self.commands.try_send(make(reply)) {
            Ok(()) => Ok(Posted { answer }),
            Err(TrySendError::Full(command)) => {
                command.abandon();
                Err(AgentError::Busy)
            }
            Err(TrySendError::Disconnected(command)) => {
                command.abandon();
                Err(AgentError::Gone)
            }
        }
    }

    /// Starts a recording of `start.source` from its position; returns its
    /// id once its `Started` is durable and its store exists.
    ///
    /// # Errors
    ///
    /// [`AgentError::Full`], the catalog's and the store's errors, and
    /// [`AgentError::Gone`].
    pub fn start(&self, start: StartRecording) -> Result<u64, AgentError> {
        self.call(|reply| Command::Start(Box::new(start), reply))
    }

    /// [`ArchiveHandle::start`], posted.
    ///
    /// # Errors
    ///
    /// [`AgentError::Busy`] and [`AgentError::Gone`]; the answer carries
    /// the rest.
    pub fn post_start(&self, start: StartRecording) -> Result<Posted<u64>, AgentError> {
        self.post(|reply| Command::Start(Box::new(start), reply))
    }

    /// Stops recording `id` where it is: its store is closed with
    /// everything durable, then its `Stopped` (reason
    /// [`StopReason::Stopped`]) is durable.
    ///
    /// # Errors
    ///
    /// [`AgentError::NotRecording`], [`AgentError::RecordingFailed`], the
    /// store's and the catalog's errors, and [`AgentError::Gone`].
    pub fn stop(&self, id: u64) -> Result<Ended, AgentError> {
        self.call(|reply| Command::Stop(id, reply))
    }

    /// Applies a legal hold on `recording` through the Archive's retention
    /// engine (ADR-0088), posted: the hold inhibits purge at once and is
    /// answered [`RetentionAnswer::Done`] only with the operations
    /// journal's evidence.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_hold(&self, recording: u64) -> Result<Posted<RetentionAnswer>, AgentError> {
        self.post(|reply| Command::Retain(retention::Request::Hold(recording), reply))
    }

    /// Releases the legal hold on `recording` (ADR-0088), posted; a release
    /// without evidence is refused `no_evidence`.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_release(&self, recording: u64) -> Result<Posted<RetentionAnswer>, AgentError> {
        self.post(|reply| Command::Retain(retention::Request::Release(recording), reply))
    }

    /// Purges `recording` below `before` as purge `request_id` for
    /// `operator` (ADR-0088), posted. No purge policy is configured in the
    /// agent yet (karyos#1093): the purge is refused, `legal_hold` under a
    /// hold, else `no_policy`, and nothing is deleted.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_purge(
        &self,
        recording: u64,
        before: u64,
        request_id: u64,
        operator: u64,
    ) -> Result<Posted<RetentionAnswer>, AgentError> {
        self.post(|reply| {
            Command::Retain(
                retention::Request::Purge {
                    recording,
                    before,
                    request_id,
                    operator,
                },
                reply,
            )
        })
    }

    /// A replica's request to replicate a recording from this Archive
    /// (ADR-0091; karyos#1113), posted. The answer is the stream of
    /// messages the agent sends for it (its bytes, its seals, its status),
    /// or [`AgentError::ReplicationRefused`] with the code to answer.
    /// Each bytes message carries at most `chunk` bytes, so it fits the
    /// stream that carries it.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_replicate(
        &self,
        request: crate::replication::ReplicateRecording,
        chunk: usize,
    ) -> Result<Posted<Receiver<crate::replication::transport::Outgoing>>, AgentError> {
        self.post(|reply| Command::Replicate(request, chunk, reply))
    }

    /// A replica's stop of its replication (ADR-0091), posted: the
    /// replication's last status is `stopped`.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_stop_replication(
        &self,
        stop: crate::replication::StopReplication,
    ) -> Result<Posted<()>, AgentError> {
        self.post(|reply| Command::StopReplication(stop, reply))
    }

    /// Whether a replication with `correlation_id` is still active in the
    /// agent, posted: answered from the agent's own state whatever the
    /// response buffers hold, so a requester can confirm that a stopped
    /// request is gone before it starts a replacement (ADR-0102 decision
    /// 3).
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_replication_active(&self, correlation_id: u64) -> Result<Posted<bool>, AgentError> {
        self.post(|reply| Command::ReplicationActive(correlation_id, reply))
    }

    /// Verifies `recording`'s seals (ADR-0088), posted.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_verify(&self, recording: u64) -> Result<Posted<retention::Verified>, AgentError> {
        self.post(|reply| Command::Verify(recording, reply))
    }

    /// Records a time evidence entry (ADR-0095; karyos#1128), durable and
    /// sealed in `time-evidence/` on return. The host computes it for a
    /// range of a clock's timestamps; the Archive takes it only once that
    /// range is sealed, so an entry never names unsealed bytes. Returns the
    /// entry's position in the entries' store.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoTimeEvidence`], [`AgentError::NoTimeEvidenceJournal`],
    /// [`AgentError::TimeEvidenceNoSeal`],
    /// [`AgentError::TimeEvidenceUnsealed`], [`AgentError::TimeEvidence`]
    /// (a refused entry or a store failure), and [`AgentError::Gone`].
    pub fn record_time_evidence(
        &self,
        entry: crate::integrity::time_evidence::Entry,
    ) -> Result<u64, AgentError> {
        self.call(|reply| Command::TimeEvidence(Box::new(entry), reply))
    }

    /// Sets where the agent takes its calibration snapshots for groups'
    /// time evidence (ADR-0098; karyos#1137), replacing any earlier one.
    /// Without one, every snapshot is empty, so a group's ranges wait
    /// their `calibration_wait` and then get `no_evidence` entries.
    ///
    /// # Errors
    ///
    /// [`AgentError::Gone`].
    pub fn set_calibration_source(
        &self,
        source: Box<dyn crate::integrity::time_producer::CalibrationSource>,
    ) -> Result<(), AgentError> {
        self.call(|reply| Command::CalibrationSource(source, reply))
    }

    /// [`ArchiveHandle::stop`], posted.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_stop(&self, id: u64) -> Result<Posted<Ended>, AgentError> {
        self.post(|reply| Command::Stop(id, reply))
    }

    /// Starts capturing a recording group: its journal is made, or
    /// recovered, and its job served in the agent's cycle; returns the
    /// sender the event loop's Gateway writes through.
    ///
    /// # Errors
    ///
    /// [`AgentError::Full`], [`AgentError::GroupCaptured`],
    /// [`AgentError::Capture`], [`AgentError::Journal`] and
    /// [`AgentError::Gone`].
    pub fn start_group(&self, start: StartGroup) -> Result<CaptureSender, AgentError> {
        self.call(|reply| Command::StartGroup(Box::new(start), reply))
    }

    /// Stops capturing group `id`: its journal is closed, synced; returns
    /// the journal's durable position. The group's sender then refuses.
    ///
    /// # Errors
    ///
    /// [`AgentError::Unknown`], [`AgentError::Journal`] and
    /// [`AgentError::Gone`].
    pub fn stop_group(&self, id: u64) -> Result<u64, AgentError> {
        self.call(|reply| Command::StopGroup(id, reply))
    }

    /// The catalog's recordings, in id order.
    ///
    /// # Errors
    ///
    /// [`AgentError::Gone`].
    pub fn recordings(&self) -> Result<Vec<Recording>, AgentError> {
        self.call(Command::List)
    }

    /// The word of the `required` recording of stream `stream_id`, session
    /// `session_id`, lane `lane` this Archive records, if any: recordings
    /// are per lane, and a word for another lane would place references
    /// into the wrong frames. A recording of the local stream answers
    /// before one of an image of the same key ([`RecordedFrom`]). A recording group Gateway's source reads it
    /// to place payloads by reference. It names
    /// the recording and its start while it records, and is cleared when
    /// the recording stops, ends or fails. Configuration path only.
    ///
    /// # Errors
    ///
    /// [`AgentError::Gone`].
    pub fn recording_word(
        &self,
        stream_id: i32,
        session_id: i32,
        lane: Lane,
    ) -> Result<Option<Arc<RecordingWord>>, AgentError> {
        self.call(|reply| Command::Word {
            stream_id,
            session_id,
            lane,
            reply,
        })
    }

    /// Posts a snapshot of at most `max` recordings from id `from_id` on,
    /// in id order, each with where it ends now, as
    /// [`ArchiveHandle::describe`] tells it.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_list(
        &self,
        from_id: u64,
        max: usize,
    ) -> Result<Posted<Vec<Described>>, AgentError> {
        self.post(|reply| Command::Snapshot {
            from_id,
            max,
            reply,
        })
    }

    /// Posts the retention state of at most `max` recordings from id
    /// `from_id` on (inclusive), in id order (ADR-0101): each one's hold,
    /// close time and earliest policy expiry, their correlation ids 0.
    /// Read only.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_retention_state(
        &self,
        from_id: u64,
        max: usize,
    ) -> Result<Posted<Vec<crate::control::RetentionDescriptor>>, AgentError> {
        self.post(|reply| Command::RetentionState {
            from_id,
            max,
            reply,
        })
    }

    /// Recording `id` as the catalog lists it, and where it ends now.
    ///
    /// # Errors
    ///
    /// [`AgentError::Unknown`] and [`AgentError::Gone`].
    pub fn describe(&self, id: u64) -> Result<Described, AgentError> {
        self.call(|reply| Command::Describe(id, reply))
    }

    /// As [`ArchiveHandle::describe`], without waiting for room or for the
    /// answer.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_describe(&self, id: u64) -> Result<Posted<Described>, AgentError> {
        self.post(|reply| Command::Describe(id, reply))
    }

    /// Recording `id`'s durable position now (R-CORE-12): never ahead of
    /// the last successful sync of its store.
    ///
    /// # Errors
    ///
    /// [`AgentError::Unknown`] and [`AgentError::Gone`].
    pub fn durable_position(&self, id: u64) -> Result<DurablePosition, AgentError> {
        self.describe(id)
            .map(|described| DurablePosition::of(&described))
    }

    /// Starts a replay of a recording's range onto `start.sink`; returns
    /// its id. The recording is read, never changed; one that still
    /// records is read up to `start.to`.
    ///
    /// # Errors
    ///
    /// [`AgentError::Unknown`], [`AgentError::Replay`] for a range that
    /// cannot be read, [`AgentError::Full`] (its sink is then finished,
    /// incomplete), and [`AgentError::Gone`].
    pub fn replay(&self, start: StartReplay) -> Result<u64, AgentError> {
        self.call(|reply| Command::Replay(Box::new(start), reply))
    }

    /// Posts the preparation of a replay: its range is checked against
    /// the recording's index and its source opened, with no target yet.
    /// Attach its sink with [`ArchiveHandle::post_attach_replay`], or stop
    /// it with [`ArchiveHandle::post_stop_replay`].
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`]; the answer carries
    /// [`AgentError::Unknown`], [`AgentError::Replay`] and
    /// [`AgentError::Full`].
    pub fn post_prepare_replay(
        &self,
        prepare: PrepareReplay,
    ) -> Result<Posted<Prepared>, AgentError> {
        self.post(|reply| Command::Prepare(prepare, reply))
    }

    /// Posts the target's sink of prepared replay `id`, whose range starts
    /// at `from`: the replay runs. A sink the agent does not take is
    /// finished, incomplete.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`]; the answer carries
    /// [`AgentError::Unknown`].
    pub fn post_attach_replay(
        &self,
        id: u64,
        from: u64,
        sink: Box<dyn ReplaySink + Send>,
    ) -> Result<Posted<u64>, AgentError> {
        self.post(|reply| Command::Attach {
            id,
            from,
            sink,
            reply,
        })
    }

    /// Stops replay `id` where it is; returns that position. Its target is
    /// finished, incomplete. A prepared replay is dropped.
    ///
    /// # Errors
    ///
    /// [`AgentError::Unknown`] and [`AgentError::Gone`].
    pub fn stop_replay(&self, id: u64) -> Result<u64, AgentError> {
        self.call(|reply| Command::StopReplay(id, reply))
    }

    /// [`ArchiveHandle::stop_replay`], posted.
    ///
    /// # Errors
    ///
    /// As [`ArchiveHandle::post_start`].
    pub fn post_stop_replay(&self, id: u64) -> Result<Posted<u64>, AgentError> {
        self.post(|reply| Command::StopReplay(id, reply))
    }

    /// The next recording event, if any.
    #[must_use]
    pub fn try_event(&self) -> Option<Event> {
        self.events.try_recv().ok()
    }

    /// The next recording event, waiting up to `timeout`.
    #[must_use]
    pub fn event(&self, timeout: Duration) -> Option<Event> {
        self.events.recv_timeout(timeout).ok()
    }

    /// The next replay that ended by itself, if any.
    #[must_use]
    pub fn try_replay_ended(&self) -> Option<ReplayEnded> {
        self.replay_ends.try_recv().ok()
    }

    /// Recordings found at start with an index shortened below their seals
    /// (karyos#671).
    #[must_use]
    pub fn shortened_indexes(&self) -> u64 {
        self.counts.shortened_indexes.load(Ordering::Relaxed)
    }

    /// Allocations and frees the replication duties made so far.
    #[cfg(test)]
    pub(crate) fn replication_allocations(&self) -> u64 {
        self.counts.replication_allocations.load(Ordering::Acquire)
    }

    /// Every shortened index found at start, with its recording and lost
    /// range, whatever the event queue dropped (karyos#671 review).
    #[must_use]
    pub fn shortened_index_reports(&self) -> Vec<crate::integrity::damage::ShortenedIndex> {
        self.counts
            .shortened_reports
            .lock()
            .map(|reports| reports.clone())
            .unwrap_or_default()
    }

    /// Recording events dropped because their queue was full.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.counts.dropped_events.load(Ordering::Relaxed)
    }

    /// Replay ends dropped because their queue was full.
    #[must_use]
    pub fn dropped_replay_ends(&self) -> u64 {
        self.counts.dropped_replay_ends.load(Ordering::Relaxed)
    }

    /// The head signing's coverage lag as its last poll left it; `None`
    /// without signing, or before its first poll (karyos#1031).
    #[must_use]
    pub fn signing_lag(&self) -> Option<SigningLag> {
        self.counts.signing.lock().ok().and_then(|slot| *slot)
    }

    /// Signing polls refused with [`AgentError::SignerPoisoned`]: the
    /// shared signer's lock is poisoned, so no head is signed and
    /// coverage falls behind (karyos#1128).
    #[must_use]
    pub fn poisoned_signer(&self) -> u64 {
        self.counts.poisoned_signer.load(Ordering::Relaxed)
    }

    /// Starts and replays refused at a cap ([`AgentError::Full`]).
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.counts.refused.load(Ordering::Relaxed)
    }

    /// Duties that found a recording's source fenced at a mapping cutover
    /// (mapping-generations.md, "Recordings"): once per fence. A fenced
    /// recording ends there, or, `async` and resuming after a lap, rejoins
    /// the stream at its head ([`ArchiveHandle::rejoined_recordings`]). A
    /// duty that fails is not counted. It tells a cutover end from a lap,
    /// which share [`StopReason::Lapped`].
    #[must_use]
    pub fn fenced_recordings(&self) -> u64 {
        self.counts.fenced_recordings.load(Ordering::Relaxed)
    }

    /// Fenced recordings that rejoined their stream at its head, as a new
    /// optional member, and went on past a gap (mapping-generations.md,
    /// "Recordings"). A duty that fails is not counted.
    #[must_use]
    pub fn rejoined_recordings(&self) -> u64 {
        self.counts.rejoined_recordings.load(Ordering::Relaxed)
    }

    /// Stops every recording where it is (reason [`StopReason::Shutdown`])
    /// and ends the agent's thread.
    ///
    /// # Errors
    ///
    /// The first error a recording's stop met, and [`AgentError::Gone`].
    pub fn shutdown(mut self) -> Result<(), AgentError> {
        let result = self.call(Command::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        result
    }
}

impl Drop for ArchiveHandle {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let (reply, _answer) = mpsc::sync_channel(1);
            let _ = self.commands.send(Command::Shutdown(reply));
            let _ = thread.join();
        }
    }
}

/// The agent's side of the event queues: a full queue drops the event and
/// counts it.
struct Outbox {
    events: SyncSender<Event>,
    replay_ends: SyncSender<ReplayEnded>,
    counts: Arc<Counts>,
}

impl Outbox {
    fn send(&self, event: Event) {
        if self.events.try_send(event).is_err() {
            count(&self.counts.dropped_events);
        }
    }

    fn replay_ended(&self, ended: ReplayEnded) {
        if self.replay_ends.try_send(ended).is_err() {
            count(&self.counts.dropped_replay_ends);
        }
    }

    /// A recording's source fenced at a cutover.
    fn fenced(&self) {
        count(&self.counts.fenced_recordings);
    }

    /// A fenced recording's source rejoined its stream.
    fn rejoined(&self) {
        count(&self.counts.rejoined_recordings);
    }

    /// A start or replay refused at a cap.
    fn refused(&self, what: &'static str, max: usize) -> AgentError {
        count(&self.counts.refused);
        AgentError::Full { what, max }
    }
}

/// A recording the agent records.
struct Active<D: Disk> {
    id: u64,
    recorder: Recorder<D, Box<dyn FrameSource + Send>>,
    stream_id: i32,
    session_id: i32,
    /// The lane it records: a recording is per lane.
    lane: Lane,
    /// A `required` recording's word, which recording group Gateways read
    /// to place payloads by reference; cleared when the recording leaves
    /// the active set, however it stopped, ended or failed.
    word: Option<WordGuard>,
    /// What it reads: a recording of a local stream answers its key's
    /// word before one of an image of the same key.
    origin: RecordedFrom,
}

/// Clears a recording's word when the recording leaves the active set.
#[derive(Debug)]
struct WordGuard(Arc<RecordingWord>);

impl Drop for WordGuard {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl FrameSource for Box<dyn FrameSource + Send> {
    fn position(&self) -> u64 {
        (**self).position()
    }

    fn read(
        &mut self,
        out: &mut [u8],
    ) -> Result<crate::recorder::Frames, crate::recorder::SourceError> {
        (**self).read(out)
    }

    fn consumed(&mut self, position: u64) -> Result<(), crate::recorder::SourceError> {
        (**self).consumed(position)
    }

    fn resume(&mut self, to: u64) -> Result<u64, crate::recorder::SourceError> {
        (**self).resume(to)
    }
}

/// A replay the agent runs.
struct ActiveReplay<D: Disk> {
    id: u64,
    source: ReplaySource<D>,
    sink: Box<dyn ReplaySink + Send>,
    /// When its sink was attached, on the agent's clock.
    attached: u64,
    /// Its sink answered ready once; it is not asked again.
    started: bool,
    /// How it ended, once it did; it leaves the set at the cycle's end.
    ended: Option<ReplayOutcome>,
}

/// A replay prepared, waiting for its sink.
struct PreparedReplay<D: Disk> {
    id: u64,
    source: ReplaySource<D>,
    /// When it was prepared, on the agent's clock.
    at: u64,
}

/// The replays the agent runs or prepared, and the next id.
struct Replays<D: Disk> {
    active: Vec<ActiveReplay<D>>,
    prepared: Vec<PreparedReplay<D>>,
    next_id: u64,
    /// The replay whose turn comes first next cycle.
    turn: usize,
}

impl<D: Disk> Replays<D> {
    /// Whether a replay prepared or running reads `recording`.
    fn reads(&self, recording: u64) -> bool {
        self.active
            .iter()
            .map(|replay| &replay.source)
            .chain(self.prepared.iter().map(|replay| &replay.source))
            .any(|source| source.recording() == recording)
    }

    /// Replays prepared or running.
    fn len(&self) -> usize {
        self.active.len() + self.prepared.len()
    }

    /// Drops the prepared replays older than `timeout`.
    fn expire(&mut self, now: u64, timeout: Duration) {
        let timeout = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
        self.prepared
            .retain(|prepared| now.checked_sub(prepared.at).is_none_or(|age| age < timeout));
    }

    /// A new replay id.
    fn id(&mut self) -> Result<u64, AgentError> {
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(AgentError::IdsExhausted)?;
        Ok(id)
    }

    /// Runs the replays in turn, each up to `budget` bytes, all together up
    /// to `share`; returns whether any moved.
    fn duty(
        &mut self,
        now: u64,
        (budget, share, deadline): (u64, u64, Duration),
        outbox: &Outbox,
    ) -> bool {
        let deadline = u64::try_from(deadline.as_nanos()).unwrap_or(u64::MAX);
        let count = self.active.len();
        if count == 0 {
            return false;
        }
        let first = self.turn % count;
        self.turn = (first + 1) % count;
        let mut worked = false;
        let mut left = share;
        for offset in 0..count {
            if left == 0 {
                break;
            }
            let Some(replay) = self.active.get_mut((first + offset) % count) else {
                break;
            };
            let (moved, spent, ended) = run_replay(replay, now, budget.min(left), deadline);
            worked |= moved || ended.is_some();
            left -= spent.min(left);
            replay.ended = ended;
        }
        self.active.retain_mut(|replay| {
            let Some(outcome) = replay.ended else {
                return true;
            };
            let position = replay.source.position();
            replay
                .sink
                .finish(position, outcome == ReplayOutcome::Complete);
            outbox.replay_ended(ReplayEnded {
                id: replay.id,
                position,
                outcome,
            });
            false
        });
        worked
    }
}

/// One replay's duty: steps into its sink until it waits, has no room,
/// spends `budget` bytes or ends. Returns whether it moved, the bytes it
/// spent, and how it ended if it did.
fn run_replay<D: Disk>(
    replay: &mut ActiveReplay<D>,
    now: u64,
    budget: u64,
    deadline: u64,
) -> (bool, u64, Option<ReplayOutcome>) {
    // Nothing is written before the target is ready (its first reader
    // joined): past the deadline the replay ends unattended, having
    // written nothing, so a reader that joins the target later can only
    // find it empty and then retired, never part of the replay.
    if !replay.started {
        if replay.sink.ready() {
            replay.started = true;
        } else if now.saturating_sub(replay.attached) >= deadline {
            return (false, 0, Some(ReplayOutcome::NoSubscriber));
        } else {
            return (false, 0, None);
        }
    }
    let mut moved = false;
    let mut spent = 0u64;
    while spent < budget {
        let before = replay.source.position();
        let taken = match replay.source.poll(now) {
            Ok(Step::Frames { position, bytes }) => replay.sink.frames(position, bytes),
            Ok(Step::Fill {
                position,
                record,
                extent,
            }) => replay.sink.fill(position, record, extent),
            Ok(Step::Gap { from, to }) => replay.sink.gap(from, to),
            Ok(Step::Wait { .. }) => return (moved, spent, None),
            Ok(Step::End { .. }) => return (moved, spent, Some(ReplayOutcome::Complete)),
            Err(_) => return (moved, spent, Some(ReplayOutcome::Failed)),
        };
        match taken {
            Ok(true) => {
                moved = true;
                // A source only moves forward.
                let Some(step) = replay.source.position().checked_sub(before) else {
                    return (moved, spent, Some(ReplayOutcome::Failed));
                };
                // `spent` is below `budget` here.
                if step >= budget - spent {
                    return (moved, budget, None);
                }
                spent += step;
            }
            // No room: the same step comes again on a later duty.
            Ok(false) => {
                let outcome = replay.source.hold().err().map(|_| ReplayOutcome::Failed);
                return (moved, spent, outcome);
            }
            // Back to the step not taken, so the replay ends where its
            // target stopped taking.
            Err(SinkClosed) => {
                let _ = replay.source.hold();
                return (moved, spent, Some(ReplayOutcome::Failed));
            }
        }
    }
    (moved, spent, None)
}

/// The agent's thread.
fn run<D>(
    disk: D,
    dir: PathBuf,
    config: AgentConfig,
    signing: Option<ArchiveSigning>,
    inbox: &Receiver<Command>,
    outbox: &Outbox,
    ready: &SyncSender<Result<(), AgentError>>,
) where
    D: Disk + Clone + Send + 'static,
    D::File: Send,
{
    let epoch = Instant::now();
    let now = || u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let mut catalog = match Catalog::open(disk.clone(), &dir) {
        Ok(opened) => opened.catalog,
        Err(error) => {
            let _ = ready.send(Err(error.into()));
            return;
        }
    };
    let mut retention = match retention::open(&disk, &dir) {
        Ok(retention) => retention,
        Err(error) => {
            let _ = ready.send(Err(error.into()));
            return;
        }
    };
    // A purge releases the immutability the local copies' segments were
    // given (karyos#1024) right before it deletes them.
    #[cfg(target_os = "linux")]
    if config.retention_policy.is_some() {
        retention.set_immutability(Box::new(crate::integrity::copies::ImmutableAttribute));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = &mut retention;
    // Collected before the settle, so the stops recovery appends are
    // chained too, before the start is reported.
    let mut integrity = match config.seal_interval.map(|interval| {
        Integrity::open(
            disk.clone(),
            &dir,
            interval,
            &mut catalog,
            signing,
            &outbox.counts,
            config.copy_location,
        )
    }) {
        None => None,
        Some(Ok(integrity)) => Some(integrity),
        Some(Err(error)) => {
            let _ = ready.send(Err(error.into()));
            return;
        }
    };
    // An offload a crash cut short is finished before any recording is
    // scanned (ADR-0104, decision 4): its local copy stops counting, its
    // files are released and removed, and its start raised, so its segment
    // is never taken for a local one, nor purged.
    if let Some(integrity) = integrity.as_mut()
        && integrity.journal.tiered()
        && let Err(error) = reconcile_offloads(&disk, &dir, integrity, &catalog)
    {
        let _ = ready.send(Err(error));
        return;
    }
    // The configured retention policy is chained in the integrity journal
    // when its terms changed (SPEC.md 8.4; karyos#1123), but only after
    // the purges a crash cut short are reconciled: they are rechecked, and
    // their evidence chained, under the version in force when they were
    // asked, never under a newer one (karyos#1123 review).
    let mut config = config;
    let mut book = None;
    if let (Some(policy), Some(integrity)) = (config.retention_policy, integrity.as_mut()) {
        match crate::integrity::retention::PolicyBook::open(
            disk.clone(),
            &dir,
            &mut integrity.journal,
        ) {
            Ok(opened) => {
                if let Some(current) = opened.current(policy.policy) {
                    config.retention_policy = Some(current);
                }
                book = Some((opened, policy));
            }
            Err(error) => {
                let _ = ready.send(Err(error.into()));
                return;
            }
        }
    }
    // A recording a crash left open recovered at A2's rule; one whose
    // recovered end falls below its seals lost sealed bytes to media
    // damage, which the seal chain shows (karyos#671). The check runs
    // before each stop is written, so a seal read that fails ends the
    // start with that recording still open: a later start checks it again
    // (karyos#671 review). Candidates come from the sealed ends the
    // journal already keeps; the records are read once, only if one is
    // found.
    let mut found = Vec::new();
    let mut records: Option<Vec<crate::integrity::SealRecord>> = None;
    let settled = catalog.settle_checked(now(), |id, position, reason| {
        let Some(integrity) = integrity.as_mut() else {
            return Ok::<_, AgentError>(());
        };
        if reason != StopReason::Recovered
            || !integrity
                .journal
                .sealed_end(id)
                .is_some_and(|end| end > position)
        {
            return Ok(());
        }
        if records.is_none() {
            records = Some(integrity.journal.records()?);
        }
        if let Some(damage) = records
            .as_deref()
            .and_then(|records| shortened_below_seal(records, id, position))
        {
            found.push(damage);
        }
        Ok(())
    });
    drop(records);
    if let Err(error) = settled {
        let _ = ready.send(Err(error));
        return;
    }
    if let Ok(mut reports) = outbox.counts.shortened_reports.lock() {
        reports.extend(found.iter().copied());
    }
    for damage in found {
        count(&outbox.counts.shortened_indexes);
        outbox.send(Event::IndexShortened(damage));
    }
    if let Some(integrity) = integrity.as_mut() {
        for change in catalog.take_changes() {
            if let Err(error) = integrity.journal.record_catalog_change(
                change.recording,
                change.offset,
                &change.bytes,
            ) {
                let _ = ready.send(Err(error.into()));
                return;
            }
        }
    }
    let mut state = State {
        disk,
        dir,
        config,
        catalog,
        active: Vec::new(),
        failed: Vec::new(),
        failures: 0,
        replays: Replays {
            active: Vec::new(),
            prepared: Vec::new(),
            next_id: 1,
            turn: 0,
        },
        groups: Vec::new(),
        group_seals: std::collections::BTreeMap::new(),
        group_stores: std::collections::BTreeMap::new(),
        group_signings: std::collections::BTreeMap::new(),
        integrity,
        retention,
        verifying: Arc::default(),
        replications: Vec::new(),
        replication_records: Vec::with_capacity(REPLICATION_QUEUE),
        replication_out: Vec::with_capacity(REPLICATION_QUEUE),
        calibrations: None,
    };
    // Before the first command: a purge a crash cut short is completed or
    // cancelled before any retry reaches it (karyos#1121 review).
    state.reconcile_purges();
    if let Some((mut book, policy)) = book
        && let Some(integrity) = state.integrity.as_mut()
    {
        match book.record_configured(policy, &mut integrity.journal) {
            Ok(recorded) => state.config.retention_policy = Some(recorded),
            Err(error) => {
                let _ = ready.send(Err(error.into()));
                return;
            }
        }
    }
    if ready.send(Ok(())).is_err() {
        return;
    }
    loop {
        let mut worked = false;
        loop {
            let command = match inbox.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            };
            worked = true;
            if state.serve(command, outbox, now()) {
                return;
            }
        }
        // Right after the commands: an attach this cycle served still found
        // its replay.
        state.replays.expire(now(), config.prepared_timeout);
        worked |= state.duty(outbox, now());
        // After the recorders, whose positions cover the groups' payloads.
        worked |= state.group_duty(now());
        // Control path work, after the recorders: sealing reads what they
        // made durable.
        worked |= state.integrity_duty(now());
        // Sealed ranges to the replicas that asked (ADR-0091; karyos#1113).
        #[cfg(not(test))]
        {
            worked |= state.replication_duty(config.replay_budget, now());
        }
        #[cfg(test)]
        {
            let (replicated, allocations) = karyos_sys::alloc_count::count(|| {
                state.replication_duty(config.replay_budget, now())
            });
            outbox
                .counts
                .replication_allocations
                .fetch_add(allocations, Ordering::AcqRel);
            worked |= replicated;
        }
        // After the recorders: they keep priority.
        worked |= state.replays.duty(
            now(),
            (config.budget, config.replay_budget, config.attach_deadline),
            outbox,
        );
        if !worked {
            match inbox.recv_timeout(config.idle) {
                Ok(command) => {
                    if state.serve(command, outbox, now()) {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

/// What the agent's thread owns.
struct State<D: Disk> {
    /// Where groups' time evidence takes its calibration snapshots
    /// (karyos#1137).
    calibrations: Option<Box<dyn crate::integrity::time_producer::CalibrationSource>>,
    disk: D,
    dir: PathBuf,
    config: AgentConfig,
    catalog: Catalog<D>,
    active: Vec<Active<D>>,
    /// Recordings whose store failed: open in the catalog until the next
    /// start settles them.
    failed: Vec<Failed>,
    /// How many recordings failed: each failed entry's number.
    failures: u64,
    replays: Replays<D>,
    groups: Vec<ActiveGroup<D>>,
    integrity: Option<Integrity<D>>,
    /// The retention engine (ADR-0088; karyos#967).
    retention: retention::Engine<D>,
    /// The recording a verification reads on its worker (karyos#1111), 0
    /// for none: recording ids are never 0.
    verifying: Arc<AtomicU64>,
    /// The replications this Archive is the source of (karyos#1113).
    replications: Vec<Replication<D>>,
    /// The journal records a replication duty reads, reused so a steady
    /// duty allocates nothing (karyos#1113).
    replication_records: Vec<crate::integrity::SealRecord>,
    /// One replication's messages of a duty, reused likewise.
    replication_out: Vec<crate::replication::transport::Outgoing>,
    /// The integrity journal of each group journal directory, which seals
    /// its groups' journals (karyos#1088); a directory whose journal
    /// failed holds `None` and is not sealed again until restart.
    group_seals: std::collections::BTreeMap<PathBuf, Option<IntegrityJournal<D>>>,
    /// The `time-evidence/` store of each group journal directory, one
    /// writer per directory shared by its groups (karyos#1137); a store
    /// that failed holds `None` until restart.
    group_stores: GroupStores<D>,
    /// The signing of each group directory's store journal, under its
    /// identity, when the Archive signs (karyos#1137).
    group_signings: std::collections::BTreeMap<PathBuf, (u64, Signing<D>)>,
}

/// One `time-evidence/` store per group journal directory.
type GroupStores<D> =
    std::collections::BTreeMap<PathBuf, Option<crate::integrity::time_evidence::EntryStore<D>>>;

/// The integrity journal of a running Archive and its sealing schedule
/// (A10; karyos#961).
struct Integrity<D: Disk> {
    signing: Option<Signing<D>>,
    /// The time evidence entries and their journal's signing, when the
    /// host made `time-evidence/` (karyos#1128).
    evidence: Option<Evidence<D>>,
    /// Whether head signing configures no time evidence journal id, so
    /// entries are refused ([`AgentError::NoTimeEvidenceJournal`]).
    no_time_journal: bool,
    /// What a group store's signing shares with the Archive's (karyos#1137).
    group_signing: Option<GroupSigning>,
    /// The copy catalog and this Archive's location in it, when
    /// `copy_location` is set; dropped at its first failure.
    copies: Option<(
        crate::integrity::copies::CopyCatalog<D>,
        crate::integrity::Digest,
    )>,
    journal: IntegrityJournal<D>,
    sealer: Sealer,
    tracked: std::collections::BTreeSet<u64>,
    /// Set by the first failure: the journal is left as it is and nothing
    /// more is sealed, so the recorders never wait on it. The verifier
    /// then reports the unsealed tail.
    failed: bool,
}

impl<D: Disk> Integrity<D> {
    fn open(
        disk: D,
        dir: &Path,
        interval: Duration,
        catalog: &mut Catalog<D>,
        signing: Option<ArchiveSigning>,
        counts: &Arc<Counts>,
        location: Option<crate::integrity::Digest>,
    ) -> Result<Self, IntegrityError>
    where
        D: Clone,
    {
        let interval = u64::try_from(interval.as_nanos())
            .ok()
            .and_then(std::num::NonZeroU64::new)
            .ok_or(IntegrityError::Overflow)?;
        let mut journal = IntegrityJournal::open(disk.clone(), dir)?.journal;
        let (signing, shared, no_time_journal, group_signing) = match signing {
            Some(setup) => {
                let parts = setup
                    .time_evidence_journal_id
                    .map(|id| (setup.trust.clone(), id, setup.config));
                let taken = [Some(setup.journal_id), setup.time_evidence_journal_id];
                let (trust, config) = (setup.trust.clone(), setup.config);
                let signing =
                    Signing::open(disk.clone(), dir, setup, &mut journal, Arc::clone(counts))?;
                let signer = Arc::clone(&signing.signer);
                let no_time_journal = parts.is_none();
                let group_signing = GroupSigning {
                    trust,
                    config,
                    signer: Arc::clone(&signer),
                    taken,
                };
                (
                    Some(signing),
                    parts.map(|parts| (parts, signer)),
                    no_time_journal,
                    Some(group_signing),
                )
            }
            None => (None, None, false, None),
        };
        // Signed, but with no journal id for the entries: none are kept.
        let evidence = if no_time_journal {
            None
        } else {
            Self::open_evidence(disk.clone(), dir, shared)?
        };
        let copies = location
            .map(|location| {
                crate::integrity::copies::CopyCatalog::open(disk, dir, &mut journal)
                    .map(|copies| (copies, location))
            })
            .transpose()?;
        catalog.collect_changes();
        Ok(Self {
            signing,
            evidence,
            no_time_journal,
            group_signing,
            copies,
            journal,
            sealer: Sealer::new(interval),
            tracked: std::collections::BTreeSet::new(),
            failed: false,
        })
    }

    /// The time evidence entries in `dir`'s `time-evidence/`, when the host
    /// made it, signed by the Archive's signer when it has one.
    fn open_evidence(
        mut disk: D,
        dir: &Path,
        shared: Option<(
            (TrustRoot, u64, crate::integrity::signing::SigningConfig),
            SharedSigner,
        )>,
    ) -> Result<Option<Evidence<D>>, IntegrityError>
    where
        D: Clone,
    {
        use crate::integrity::time_evidence::{DIR, EntryStore, StoreError, entries_dir};
        if !disk.list(dir)?.iter().any(|name| name == DIR) {
            return Ok(None);
        }
        let mut store = EntryStore::open(disk.clone(), dir).map_err(|error| match error {
            StoreError::Integrity(error) => error,
            other => IntegrityError::Io(std::io::Error::other(other.to_string())),
        })?;
        let signing = shared
            .map(|(parts, signer)| {
                Signing::open_shared(
                    disk,
                    &entries_dir(dir),
                    parts,
                    signer,
                    store.journal_mut(),
                    Arc::default(),
                )
            })
            .transpose()?;
        Ok(Some(Evidence { store, signing }))
    }

    /// Reports `recording` durable to `durable`, tracking it first.
    fn written(&mut self, recording: u64, start: u64, durable: u64, now: u64) -> bool {
        if self.tracked.insert(recording) {
            let sealed = self.journal.sealed_end(recording).unwrap_or(start);
            if self
                .sealer
                .track(recording, SealSource::Segments, sealed)
                .is_err()
            {
                return false;
            }
        }
        self.sealer.written(recording, durable, now).is_ok()
    }

    /// Seals what is due, reading from `active`.
    /// Seals what is due, one recording at a time from its own store. A
    /// range its store cannot serve (a recorded gap, a failed store) stops
    /// that recording's sealing only, leaving its unsealed tail for the
    /// verifier; a failure of the journal itself returns false.
    fn seal(&mut self, active: &mut [Active<D>], now: u64) -> bool {
        let ids: Vec<u64> = self.tracked.iter().copied().collect();
        for id in ids {
            let mut unreadable = false;
            let sealed = sealer::run_recording(
                &mut self.sealer,
                &mut self.journal,
                now,
                id,
                |id, start, end| {
                    let read = read_range(active, id, start, end);
                    unreadable = read.is_err();
                    read
                },
            );
            match sealed {
                Ok(_) => {}
                Err(_) if unreadable => self.untrack(id),
                Err(_) => return false,
            }
        }
        true
    }

    /// Stops sealing `id`.
    fn untrack(&mut self, id: u64) {
        self.tracked.remove(&id);
        let _ = self.sealer.untrack(id);
    }
}

/// Head signing for a running Archive (A10; karyos#966): the operator's
/// trust root, the journal's identity in it, the signing configuration and
/// the signer, which runs off the Archive host (SPEC.md §8.4).
pub struct ArchiveSigning {
    /// The trust root the key registry is replayed under.
    pub trust: TrustRoot,
    /// The integrity journal's identity within the Archive.
    pub journal_id: u64,
    /// The identity of the time evidence entries' journal (karyos#1128),
    /// another than `journal_id`: a head of one chain never stands for the
    /// other's, and an anchor of one is refused for the other. `None`
    /// configures none, and time evidence is then refused
    /// ([`AgentError::NoTimeEvidenceJournal`]); no identity is guessed.
    pub time_evidence_journal_id: Option<u64>,
    /// The `anchor_interval` and backlog policy.
    pub config: SigningConfig,
    /// The signer. It is asked from the agent's control path and must not
    /// block: one that cannot answer now returns [`SignerUnavailable`].
    pub signer: Box<dyn HeadSigner + Send>,
}

impl std::fmt::Debug for ArchiveSigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveSigning")
            .field("journal_id", &self.journal_id)
            .field("time_evidence_journal_id", &self.time_evidence_journal_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// How often the agent offers a new head and asks the signer, at most.
const SIGNING_POLL: u64 = 1_000_000_000;

/// Messages a replication holds for the server at most.
const REPLICATION_QUEUE: usize = 64;

/// How often a replication sends a status at least, in nanoseconds.
const REPLICATION_STATUS: u64 = 1_000_000_000;

/// One replication this Archive is the source of (karyos#1113).
struct Replication<D: Disk> {
    sender: crate::replication::transport::Sender,
    out: SyncSender<crate::replication::transport::Outgoing>,
    /// Messages not handed to the server yet.
    queued: std::collections::VecDeque<crate::replication::transport::Outgoing>,
    /// A stopped recording's store, read only; `None` while it records.
    store: Option<SegmentStore<crate::disk::ReadOnly<D>>>,
    /// The recording's range seals read so far.
    seals: Vec<crate::integrity::SealRecord>,
    /// The integrity journal records read so far.
    read: u64,
    /// When its last status was produced, in agent nanoseconds.
    status_at: u64,
}

/// Drops the range seals sent whole, those ending at or below
/// `sent_end`, but the last: it keeps where the seals end. They are in
/// the journal's order, each range after the one before it, so a steady
/// replication holds a few seals in the storage it already has
/// (karyos#1113).
fn forget_sent(seals: &mut Vec<crate::integrity::SealRecord>, sent_end: u64) {
    let sent = seals
        .iter()
        .take_while(|seal| seal.end <= sent_end)
        .count()
        .min(seals.len().saturating_sub(1));
    seals.drain(..sent);
}

/// `records`' range seals of `recording`.
fn range_seals(
    records: &[crate::integrity::SealRecord],
    recording: u64,
) -> Vec<crate::integrity::SealRecord> {
    records
        .iter()
        .filter(|record| record.subject == recording && record.kind.is_range())
        .copied()
        .collect()
}

/// The running signing state.
struct Signing<D: Disk> {
    disk: D,
    dir: PathBuf,
    trust: TrustRoot,
    journal_id: u64,
    signing: HeadSigning,
    /// The one signer, shared with the time evidence journal's signing
    /// (karyos#1128).
    signer: SharedSigner,
    heads: Ledger<D, SIGNED_HEAD_LENGTH>,
    /// Whether the backlog coalesces: then a head waiting for the signer
    /// is kept until signed, and newer ones wait behind it.
    coalesce: bool,
    offered: Option<crate::integrity::Digest>,
    next_ns: u64,
    /// The journal's records from counter `base` on, the tail not yet
    /// covered by a signed head (and at least the last record): a poll
    /// reads only the new ones (karyos#1031), and drops the covered prefix
    /// (karyos#1095).
    records: Vec<crate::integrity::SealRecord>,
    /// The counter of `records`' first.
    base: u64,
    /// Every key registry record of the chain, all the registry replay
    /// reads: bounded by key changes, not by the journal.
    keys: Vec<crate::integrity::SealRecord>,
    /// The key registry as of `records`, replayed again only when a new
    /// key registry record is chained.
    registry: KeyRegistry,
    /// Where each poll publishes the status.
    counts: Arc<Counts>,
}

/// What a group store's signing shares with the Archive's (karyos#1137).
struct GroupSigning {
    trust: TrustRoot,
    config: crate::integrity::signing::SigningConfig,
    signer: SharedSigner,
    /// The Archive's journal identity and its entries' journal identity.
    taken: [Option<u64>; 2],
}

/// The time evidence entries of a running Archive (ADR-0095).
struct Evidence<D: Disk> {
    store: crate::integrity::time_evidence::EntryStore<D>,
    /// Signs and anchors the entries' journal with the Archive's signer,
    /// on the same schedule and trust root.
    signing: Option<Signing<D>>,
}

/// What a journal's signing is configured with, besides its signer.
struct SigningSetup {
    trust: TrustRoot,
    journal_id: u64,
    config: crate::integrity::signing::SigningConfig,
}

/// The Archive's signer, shared by the journals it signs.
type SharedSigner = Arc<std::sync::Mutex<SignerSlot>>;

/// The shared signer and the journal whose head it is asked for.
///
/// A signer may hold one request in flight and retire it when asked for
/// another head (the operator's signing program does): two journals
/// asking in turn would cancel each other's requests forever. So the
/// journal that asked keeps the signer until its pending heads are
/// signed or dropped, and the other journal waits (karyos#1138 review).
struct SignerSlot {
    signer: Box<dyn HeadSigner + Send>,
    /// The journal id holding the signer, while it has heads pending.
    holder: Option<u64>,
}

impl SignerSlot {
    /// A slot no journal holds yet.
    fn shared(signer: Box<dyn HeadSigner + Send>) -> SharedSigner {
        Arc::new(std::sync::Mutex::new(Self {
            signer,
            holder: None,
        }))
    }
}

/// A boxed signer, as the sized signer [`HeadSigning::poll`] takes.
struct Boxed<'a>(&'a mut (dyn HeadSigner + Send));

impl HeadSigner for Boxed<'_> {
    fn key_id(&self) -> crate::integrity::Digest {
        self.0.key_id()
    }

    fn custody(&self) -> crate::integrity::trust::Custody {
        self.0.custody()
    }

    fn sign(&mut self, head: &ChainHead) -> Result<[u8; SIGNATURE_LENGTH], SignerUnavailable> {
        self.0.sign(head)
    }
}

/// The key registry records of `records`: what [`KeyRegistry::replay`]
/// reads (karyos#1095).
fn key_records(records: &[crate::integrity::SealRecord]) -> Vec<crate::integrity::SealRecord> {
    records
        .iter()
        .filter(|record| record.kind == crate::integrity::SealKind::KeyRegistry)
        .copied()
        .collect()
}

impl<D: Disk + Clone> Signing<D> {
    fn open(
        disk: D,
        dir: &Path,
        setup: ArchiveSigning,
        journal: &mut IntegrityJournal<D>,
        counts: Arc<Counts>,
    ) -> Result<Self, IntegrityError> {
        let signer = SignerSlot::shared(setup.signer);
        Self::open_shared(
            disk,
            dir,
            (setup.trust, setup.journal_id, setup.config),
            signer,
            journal,
            counts,
        )
    }

    /// [`Signing::open`] of the journal in `dir` with a signer another
    /// journal's signing shares.
    fn open_shared(
        disk: D,
        dir: &Path,
        (trust, journal_id, config): (TrustRoot, u64, crate::integrity::signing::SigningConfig),
        signer: SharedSigner,
        journal: &mut IntegrityJournal<D>,
        counts: Arc<Counts>,
    ) -> Result<Self, IntegrityError> {
        let setup = SigningSetup {
            trust,
            journal_id,
            config,
        };
        let heads = Ledger::open(disk.clone(), dir, HEADS_FILE)?;
        let coalesce = matches!(
            setup.config.policy(),
            crate::integrity::signing::BacklogPolicy::Coalesce
        );
        let records = journal.records()?;
        let registry = Self::registry(&disk, dir, &setup.trust, &records)?;
        let signing = HeadSigning::resume(
            setup.config,
            0,
            heads.entries(),
            &registry,
            setup.journal_id,
            &records,
        );
        let keys = key_records(&records);
        let mut opened = Self {
            disk,
            dir: dir.to_path_buf(),
            trust: setup.trust,
            journal_id: setup.journal_id,
            signing,
            signer,
            heads,
            coalesce,
            offered: None,
            next_ns: 0,
            records,
            base: 0,
            keys,
            registry,
            counts,
        };
        opened.trim();
        Ok(opened)
    }

    /// The key registry as the journal chains it now.
    fn registry(
        disk: &D,
        dir: &Path,
        trust: &TrustRoot,
        records: &[crate::integrity::SealRecord],
    ) -> Result<KeyRegistry, IntegrityError> {
        let mut disk = disk.clone();
        let entries = read_entries::<D, REGISTRY_ENTRY_LENGTH>(&mut disk, dir, KEYS_FILE)?;
        Ok(KeyRegistry::replay(trust.clone(), records, &entries)?.0)
    }

    /// Offers the journal's head when it moved and asks the signer, at most
    /// every [`SIGNING_POLL`]. Failures leave heads pending.
    ///
    /// Under [`BacklogPolicy::Coalesce`](crate::integrity::signing::BacklogPolicy::Coalesce),
    /// a head already waiting for the signer is kept until it is signed:
    /// a newer head is offered only once nothing is pending, so a signer
    /// slower than the sealing still completes the head it was given, and
    /// the newer work waiting behind it coalesces into the latest head at
    /// that point (karyos#966 review). A head the backlog refuses is not
    /// marked offered, so it is offered again at the next duty.
    ///
    /// # Errors
    ///
    /// [`AgentError::SignerPoisoned`]: the shared signer's lock is
    /// poisoned, so nothing is offered or asked; the heads stay pending.
    fn duty(&mut self, journal: &mut IntegrityJournal<D>, now: u64) -> Result<(), AgentError> {
        if now < self.next_ns {
            return Ok(());
        }
        self.next_ns = now.saturating_add(SIGNING_POLL);
        if !self.refresh(journal) {
            return Ok(());
        }
        let records = &self.records;
        let registry = &self.registry;
        let sealed = u64::try_from(records.len())
            .ok()
            .and_then(|len| self.base.checked_add(len))
            .unwrap_or(u64::MAX);
        let busy = self.coalesce && self.signing.status(now, sealed, registry).pending > 0;
        let Ok(mut slot) = self.signer.lock() else {
            return Err(AgentError::SignerPoisoned);
        };
        if let Some(last) = records.last() {
            let digest = last.digest();
            // Only a head the configured key can validly sign is offered:
            // one before the key's effective counter (or under a key the
            // registry does not hold) would never be trusted, and under
            // either backlog policy it would pin the heads behind it
            // (karyos#966 review). Not offered, it is not marked, so the
            // first eligible head is offered as soon as it exists.
            let eligible = registry
                .key(&slot.signer.key_id())
                .is_some_and(|key| last.counter >= key.valid_from);
            if eligible && !busy && self.offered != Some(digest) {
                let offered = self.signing.offer(
                    ChainHead {
                        archive_id: self.trust.archive_id,
                        journal_id: self.journal_id,
                        counter: last.counter,
                        digest,
                    },
                    now,
                );
                if !matches!(offered, Offered::Refused) {
                    self.offered = Some(digest);
                }
            }
        }
        // Another journal's request is in flight: asking for this head
        // would retire it. This journal asks once that one is done.
        if slot.holder.is_none_or(|holder| holder == self.journal_id) {
            let _ = self.signing.poll_from(
                &mut Boxed(slot.signer.as_mut()),
                &mut self.heads,
                registry,
                self.base,
                records,
                now,
            );
            slot.holder =
                (self.signing.status(now, sealed, registry).pending > 0).then_some(self.journal_id);
        }
        drop(slot);
        let status = self.signing.status(now, sealed, registry);
        self.trim();
        if let Ok(mut slot) = self.counts.signing.lock() {
            *slot = Some(SigningLag {
                records: status.coverage_lag_records,
                ns: status.coverage_lag_ns,
                alarm: status.alarm,
                pending: status.pending,
            });
        }
        Ok(())
    }

    /// Drops the records signed heads cover from the cache (karyos#1095),
    /// keeping the last record, whose head a poll offers.
    fn trim(&mut self) {
        let covered = self.signing.covered();
        let last = self.records.len().saturating_sub(1);
        let drop = usize::try_from(covered.saturating_sub(self.base))
            .unwrap_or(usize::MAX)
            .min(last);
        if drop == 0 {
            return;
        }
        let _ = self.records.drain(..drop);
        self.base = self
            .base
            .saturating_add(u64::try_from(drop).unwrap_or(u64::MAX));
    }

    /// The cached records, from counter `base` on (tests).
    #[cfg(test)]
    fn cached(&self) -> (u64, usize) {
        (self.base, self.records.len())
    }

    /// Reads the records chained since the last poll, and replays the key
    /// registry only when one of them changes it. False when the journal
    /// cannot be read; the cache is then left as it was.
    fn refresh(&mut self, journal: &mut IntegrityJournal<D>) -> bool {
        let known = u64::try_from(self.records.len())
            .ok()
            .and_then(|len| self.base.checked_add(len))
            .unwrap_or(u64::MAX);
        let Ok(new) = journal.records_from(known) else {
            return false;
        };
        if new.is_empty() {
            return true;
        }
        let changes_registry = new
            .iter()
            .any(|record| record.kind == crate::integrity::SealKind::KeyRegistry);
        let added = key_records(&new);
        if self.records.try_reserve(new.len()).is_err()
            || self.keys.try_reserve(added.len()).is_err()
        {
            return false;
        }
        self.records.extend(new);
        self.keys.extend(added);
        if changes_registry {
            match Self::registry(&self.disk, &self.dir, &self.trust, &self.keys) {
                Ok(registry) => self.registry = registry,
                Err(_) => {
                    // Re-read the whole journal at the next poll.
                    self.records.clear();
                    self.keys.clear();
                    self.base = 0;
                    return false;
                }
            }
        }
        true
    }
}

/// Whether `entry` names only bytes its recording's seals cover:
/// `sealed`, the range `[first, end)` they cover whole, must exist and
/// hold the entry's `[start, end)` (karyos#1128). An unknown recording,
/// or one nothing of which is sealed, is refused, never read as sealed
/// to zero.
fn admit_time_evidence(
    sealed: Option<(u64, u64)>,
    entry: &crate::integrity::time_evidence::Entry,
) -> Result<(), AgentError> {
    let Some((first, end)) = sealed else {
        return Err(AgentError::TimeEvidenceNoSeal {
            recording: entry.recording,
        });
    };
    if entry.start < first || entry.start > entry.end || entry.end > end {
        return Err(AgentError::TimeEvidenceUnsealed {
            recording: entry.recording,
            start: entry.start,
            end: entry.end,
            first,
            sealed: end,
        });
    }
    Ok(())
}

/// The bytes `[start, end)` of active recording `id`.
fn read_range<D: Disk>(
    active: &mut [Active<D>],
    id: u64,
    start: u64,
    end: u64,
) -> std::io::Result<Vec<u8>> {
    let recording = active
        .iter_mut()
        .find(|recording| recording.id == id)
        .ok_or_else(|| std::io::Error::other("recording is not active"))?;
    read_store(recording.recorder.store_mut(), start, end)
}

/// The bytes `[start, end)` of `store`.
fn read_store<D: Disk>(
    store: &mut SegmentStore<D>,
    start: u64,
    end: u64,
) -> std::io::Result<Vec<u8>> {
    let length = end
        .checked_sub(start)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| std::io::Error::other("inverted range"))?;
    let mut bytes = vec![0u8; length];
    store
        .read(start, &mut bytes)
        .map_err(std::io::Error::other)?;
    Ok(bytes)
}

/// A recording that failed: no stop in the catalog, so the groups settle
/// their references to it by `durable`, its frames durable at the failure.
///
/// A Gateway stops naming a recording once its word is cleared, which
/// happens when it leaves the active set, so only references sent before
/// that can name it. An entry
/// is kept until every running group has read its ring empty in a duty
/// that began after the failure (`seq`), and is dropped then when a start
/// needs its slot. A failed recording
/// holds its slot under the recording cap until then, so the list is
/// bounded by the cap, and a start past it is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Failed {
    id: u64,
    durable: u64,
    /// The failure's number: the agent's count of failures with it.
    seq: u64,
}

/// The failure count after one more failure. The start checked that it
/// stays in range; were it not to, the count stays, so entries are kept
/// longer, never dropped early.
fn next_failure(failures: u64) -> u64 {
    failures.checked_add(1).unwrap_or(failures)
}

/// One group's checkpoint work this cycle: takes a request from the
/// Gateway, writes at most `budget` of its bytes, and gives the buffer back
/// once its write ended. Returns whether it worked.
fn checkpoint_duty<D: Disk>(
    job: &mut CaptureJob<D>,
    checkpoints: &mut GroupWriter<D>,
    budget: usize,
) -> bool {
    // A failed or ended group writes nothing more: what waits is
    // answered, and later requests refused.
    if job.state() != GroupState::Running {
        if let Some(request) = checkpoints.current.take() {
            checkpoints
                .inbox
                .give_back(request, Err(CheckpointError::Stopped));
        }
        checkpoints.inbox.close();
        return false;
    }
    if checkpoints.current.is_none() {
        checkpoints.current = checkpoints.inbox.take();
    }
    let Some(request) = checkpoints.current.as_ref() else {
        return false;
    };
    let result = match job.checkpoint(&mut checkpoints.writer, request, budget) {
        Ok(CheckpointStep::NotReady) => return false,
        Ok(CheckpointStep::Writing { .. }) => return true,
        Ok(CheckpointStep::Recorded(record)) => Ok(record),
        Err(error) => Err(error),
    };
    if let Some(request) = checkpoints.current.take() {
        checkpoints.inbox.give_back(request, result);
    }
    true
}

/// A recording group the agent captures.
#[derive(Debug)]
struct ActiveGroup<D: Disk> {
    id: u64,
    /// Its journal's directory.
    dir: PathBuf,
    job: CaptureJob<D>,
    /// Its checkpoints, when it keeps them.
    checkpoints: Option<GroupWriter<D>>,
    /// The failures whose references this group has all read: its last
    /// duty that read the ring empty began after them.
    cleared: u64,
    /// Its time evidence, when declared and kept (karyos#1137).
    evidence: Option<GroupEvidence>,
}

/// A group's time evidence production (ADR-0098).
#[derive(Debug)]
struct GroupEvidence {
    declared: GroupTimeEvidence,
    /// The journal position this capture session began at: earlier
    /// records are of another session, whose clock is not known.
    session_start: u64,
    /// The record boundary entries are produced from.
    next: u64,
    /// The timers created in this session and not cancelled.
    timers: std::collections::BTreeSet<u64>,
    /// The range waiting for the calibrations: its end, a record
    /// boundary pinned when it began waiting, and when that was. Records
    /// after it wait for the next batch.
    pending: Option<(u64, u64)>,
}

/// A group's checkpoint writer on the agent's thread (A9-3): the store,
/// the handoff from the Gateway, and the request being written.
#[derive(Debug)]
struct GroupWriter<D: Disk> {
    writer: CheckpointWriter<D>,
    inbox: CheckpointInbox,
    current: Option<CheckpointRequest>,
}

/// One group's coverage: the recordings, and its checkpoint store.
struct GroupCoverage<'a, D: Disk> {
    recorded: &'a Recorded<'a, D>,
    store: Option<&'a CheckpointStore<D>>,
}

impl<D: Disk> Coverage for GroupCoverage<'_, D> {
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        self.recorded.positions(recording_id)
    }

    fn ended(&self, recording_id: u64) -> Option<u64> {
        self.recorded.ended(recording_id)
    }

    fn checkpoint(&self, position: u64, end: u64) -> CheckpointHeld {
        self.store
            .map_or(CheckpointHeld::Missing, |store| store.holds(position, end))
    }
}

/// The recordings' frames as recording groups see them (A7d): an active
/// `required` recorder's written and durable positions, a stopped
/// `required` recording's end, which its close made durable, and a failed
/// `required` recording's frames durable at the failure. An `async`
/// recording, or one the catalog does not know as `required` (an entry
/// from before the mode was recorded), answers nothing.
struct Recorded<'a, D: Disk> {
    active: &'a [Active<D>],
    failed: &'a [Failed],
    catalog: &'a Catalog<D>,
}

impl<D: Disk> Recorded<'_, D> {
    /// A failed recording's durable end: it will never cover more.
    fn failed(&self, recording_id: u64) -> Option<u64> {
        self.failed
            .iter()
            .find(|failed| failed.id == recording_id)
            .map(|failed| failed.durable)
    }
}

impl<D: Disk> Coverage for Recorded<'_, D> {
    fn positions(&self, recording_id: u64) -> Option<(u64, u64)> {
        let recording = self.catalog.get(recording_id)?;
        if !recording.required {
            return None;
        }
        if let Some(active) = self.active.iter().find(|active| active.id == recording_id) {
            let store = active.recorder.store();
            return Some((store.written(), store.durable()));
        }
        let end = recording
            .stop
            .map(|stop| stop.position)
            .or_else(|| self.failed(recording_id))?;
        Some((end, end))
    }

    fn ended(&self, recording_id: u64) -> Option<u64> {
        // A recording the catalog does not know vouches for nothing.
        let Some(recording) = self.catalog.get(recording_id) else {
            return Some(0);
        };
        if let Some(end) = recording
            .stop
            .map(|stop| stop.position)
            .or_else(|| self.failed(recording_id))
        {
            return Some(if recording.required { end } else { 0 });
        }
        // Open in the catalog and not recording: it failed, and its entry
        // was dropped once the groups read past the failure. A reference
        // sent later raced the failure; it covers nothing, so it is never
        // over-vouched and never waits for good.
        if self.active.iter().any(|active| active.id == recording_id) {
            None
        } else {
            Some(0)
        }
    }
}

/// Records that recording `id` failed with its frames durable to
/// `durable` and no stop in the catalog, and settles every group's
/// references to it. A reference drained later is settled by the groups'
/// duty, through [`Coverage::ended`], as for a recording that stopped.
/// Only a `required` recording vouches for its frames: a reference to any
/// other covers nothing.
fn fail_recording<D: Disk>(
    groups: &mut [ActiveGroup<D>],
    active: &[Active<D>],
    (failed, failures): (&mut Vec<Failed>, &mut u64),
    catalog: &Catalog<D>,
    id: u64,
    durable: u64,
) {
    // A start is refused unless every recording it holds can fail with
    // the count in range ([`next_failure`]), so this always advances.
    *failures = next_failure(*failures);
    failed.push(Failed {
        id,
        durable,
        seq: *failures,
    });
    let required = catalog.get(id).is_some_and(|recording| recording.required);
    let durable = if required { durable } else { 0 };
    let recorded = Recorded {
        active,
        failed,
        catalog,
    };
    for group in groups {
        // A mark that cannot be written fails the group, which its sender
        // then reports; nothing else is to be done here.
        let _ = group.job.recording_ended(id, durable, &recorded);
    }
}

impl<D: Disk + Clone + Send + 'static> State<D>
where
    D::File: Send,
{
    /// Each recording's duty; those that end or fail leave the set.
    /// Returns whether any moved.
    /// Accepts a replica's request: the recording known, its seals read,
    /// [`Sender::accept`](crate::replication::transport::Sender::accept)'s
    /// boundaries checked (karyos#1113).
    fn replicate(
        &mut self,
        request: crate::replication::ReplicateRecording,
        chunk: usize,
    ) -> Result<Receiver<crate::replication::transport::Outgoing>, AgentError> {
        use crate::replication::transport::{Refusal, Sender};
        let id = request.recording_id;
        // Refused before the journal is read.
        let Some(start) = self
            .catalog
            .get(id)
            .filter(|_| self.integrity.is_some())
            .map(|recording| recording.start)
        else {
            return Err(AgentError::ReplicationRefused(Refusal::UnknownRecording));
        };
        let (seals, read) = match self.integrity.as_mut() {
            Some(integrity) => {
                let records = integrity.journal.records()?;
                let read = u64::try_from(records.len()).unwrap_or(u64::MAX);
                (range_seals(&records, id), read)
            }
            None => (Vec::new(), 0),
        };
        let sender = Sender::accept(request, true, start, &seals)
            .map_err(AgentError::ReplicationRefused)?
            .with_chunk(chunk);
        let store = if self.active.iter().any(|active| active.id == id) {
            None
        } else {
            self.stopped_store(id)?
        };
        let (out, answer) = mpsc::sync_channel(REPLICATION_QUEUE);
        // Room for a steady duty's messages and new seals up front.
        let mut seals = seals;
        seals.reserve(REPLICATION_QUEUE);
        self.replications.push(Replication {
            sender,
            out,
            queued: std::collections::VecDeque::with_capacity(REPLICATION_QUEUE),
            store,
            seals,
            read,
            status_at: 0,
        });
        Ok(answer)
    }

    /// A stopped recording's store, opened read only; `None` for an
    /// unknown recording.
    fn stopped_store(
        &self,
        id: u64,
    ) -> Result<Option<SegmentStore<crate::disk::ReadOnly<D>>>, AgentError> {
        let Some(recording) = self.catalog.get(id) else {
            return Ok(None);
        };
        Ok(Some(SegmentStore::open_verified(
            crate::disk::ReadOnly(self.disk.clone()),
            &self.dir,
            id,
            recording.geometry,
            SyncPolicy::None,
        )?))
    }

    /// Ends the replication `stop` names with a `stopped` status.
    fn stop_replication(&mut self, stop: crate::replication::StopReplication) {
        self.reopen();
        for replication in &mut self.replications {
            let request = replication.sender.request();
            if request.recording_id != stop.recording_id
                || request.correlation_id != stop.correlation_id
                || replication.sender.done().is_some()
            {
                continue;
            }
            let sealed = replication
                .seals
                .iter()
                .map(|seal| seal.end)
                .max()
                .unwrap_or(request.from);
            let status = match (
                replication.store.as_ref(),
                self.active
                    .iter()
                    .find(|active| active.id == stop.recording_id),
            ) {
                (Some(store), _) => replication.sender.stop(store, sealed),
                (None, Some(active)) => replication.sender.stop(active.recorder.store(), sealed),
                (None, None) => continue,
            };
            // The stop drops the replication's pending output (ADR-0102
            // decision 3): only the stopped status is left to hand over.
            replication.queued.clear();
            replication.queued.push_back(status);
        }
    }

    /// Opens the store of each replication whose recording stopped since
    /// it was accepted; one that cannot be opened is dropped, which ends
    /// its stream. Nothing is collected, so a duty with every recording
    /// still active allocates nothing.
    fn reopen(&mut self) {
        let mut index = 0;
        while let Some(replication) = self.replications.get(index) {
            let id = replication.sender.request().recording_id;
            if replication.store.is_some() || self.active.iter().any(|active| active.id == id) {
                index += 1;
                continue;
            }
            match self.stopped_store(id) {
                Ok(Some(store)) => {
                    if let Some(replication) = self.replications.get_mut(index) {
                        replication.store = Some(store);
                    }
                    index += 1;
                }
                _ => {
                    self.replications.swap_remove(index);
                }
            }
        }
    }

    /// Each replication: what is queued is handed over, then, once the
    /// queue is empty, the next sealed ranges, at most `budget` bytes for
    /// all of them in one duty, and a status when one is due.
    fn replication_duty(&mut self, budget: u64, now: u64) -> bool {
        self.reopen();
        let mut out = core::mem::take(&mut self.replication_out);
        let mut records = core::mem::take(&mut self.replication_records);
        let worked = self.replicate_each(budget, now, &mut out, &mut records);
        self.replication_out = out;
        self.replication_records = records;
        worked
    }

    /// [`State::replication_duty`]'s pass over the replications, with
    /// its reused buffers.
    fn replicate_each(
        &mut self,
        budget: u64,
        now: u64,
        out: &mut Vec<crate::replication::transport::Outgoing>,
        records: &mut Vec<crate::integrity::SealRecord>,
    ) -> bool {
        let mut budget = usize::try_from(budget).unwrap_or(usize::MAX).max(1);
        let mut worked = false;
        let mut index = 0;
        while let Some(replication) = self.replications.get_mut(index) {
            let mut gone = false;
            while let Some(message) = replication.queued.pop_front() {
                match replication.out.try_send(message) {
                    Ok(()) => worked = true,
                    Err(TrySendError::Full(message)) => {
                        replication.queued.push_front(message);
                        break;
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        gone = true;
                        break;
                    }
                }
            }
            let done = replication.sender.done().is_some() && replication.queued.is_empty();
            if gone || done {
                self.replications.swap_remove(index);
                continue;
            }
            if replication.queued.is_empty() && replication.sender.done().is_none() {
                let id = replication.sender.request().recording_id;
                records.clear();
                if let Some(integrity) = self.integrity.as_mut()
                    && integrity
                        .journal
                        .records_from_into(replication.read, records)
                        .is_ok()
                {
                    replication.read = replication
                        .read
                        .saturating_add(u64::try_from(records.len()).unwrap_or(u64::MAX));
                    replication.seals.extend(
                        records
                            .iter()
                            .filter(|record| record.subject == id && record.kind.is_range())
                            .copied(),
                    );
                }
                out.clear();
                let active = self.active.iter_mut().find(|active| active.id == id);
                let polled = match (replication.store.as_mut(), active) {
                    (Some(store), _) => {
                        replication
                            .sender
                            .poll(store, &replication.seals, true, budget, out)
                    }
                    (None, Some(active)) => replication.sender.poll(
                        active.recorder.store_mut(),
                        &replication.seals,
                        false,
                        budget,
                        out,
                    ),
                    // Reopened at the top of the next duty.
                    (None, None) => Ok(()),
                };
                let sent: usize = out
                    .iter()
                    .map(|message| match message {
                        crate::replication::transport::Outgoing::Bytes { bytes, .. } => bytes.len(),
                        _ => 0,
                    })
                    .sum();
                budget = budget.saturating_sub(sent);
                if polled.is_err() {
                    // Its chunks go with it: the shared buffer keeps its
                    // capacity for the next replication (Codex review).
                    out.clear();
                    self.replications.swap_remove(index);
                    continue;
                }
                // A status at least once a second (ADR-0091).
                let has_status = out.iter().any(|message| {
                    matches!(message, crate::replication::transport::Outgoing::Status(_))
                });
                if !has_status
                    && replication.sender.done().is_none()
                    && now.saturating_sub(replication.status_at) >= REPLICATION_STATUS
                {
                    let active = self.active.iter().find(|active| active.id == id);
                    if let Some(status) = match (replication.store.as_ref(), active) {
                        (Some(store), _) => {
                            Some(replication.sender.status(store, &replication.seals))
                        }
                        (None, Some(active)) => Some(
                            replication
                                .sender
                                .status(active.recorder.store(), &replication.seals),
                        ),
                        (None, None) => None,
                    } {
                        out.push(status);
                    }
                }
                if out.iter().any(|message| {
                    matches!(message, crate::replication::transport::Outgoing::Status(_))
                }) {
                    replication.status_at = now;
                }
                worked |= !out.is_empty();
                replication.queued.extend(out.drain(..));
                forget_sent(&mut replication.seals, replication.sender.sent_end());
            }
            index += 1;
        }
        worked
    }

    /// Chains the catalog's changes and seals what is due (A10). A
    /// failure stops the integrity work, never a recording.
    fn integrity_duty(&mut self, now: u64) -> bool {
        let changes = self.catalog.take_changes();
        let Some(integrity) = self
            .integrity
            .as_mut()
            .filter(|integrity| !integrity.failed)
        else {
            return false;
        };
        let mut ok = true;
        for change in &changes {
            ok &= integrity
                .journal
                .record_catalog_change(change.recording, change.offset, &change.bytes)
                .is_ok();
        }
        // A recording that left the active set without its last seal (its
        // store failed) is not read again.
        let active = &self.active;
        let gone: Vec<u64> = integrity
            .tracked
            .iter()
            .copied()
            .filter(|id| active.iter().all(|recording| recording.id != *id))
            .collect();
        for id in gone {
            integrity.untrack(id);
        }
        for recording in &self.active {
            let store = recording.recorder.store();
            ok &= integrity.written(recording.id, store.start(), store.durable(), now);
        }
        let before = integrity.journal.head();
        ok &= integrity.seal(&mut self.active, now);
        integrity.failed = !ok;
        // Signing never fails the integrity work: an unavailable signer
        // leaves heads pending, and anchoring falls behind. A poisoned
        // signer is refused and counted, never skipped silently. The
        // entries' journal is signed only with the Archive's signer, so
        // its signing's counts are the handle's.
        let counts = integrity
            .signing
            .as_ref()
            .map(|signing| Arc::clone(&signing.counts));
        let mut poisoned = 0u8;
        if let Some(signing) = integrity.signing.as_mut()
            && signing.duty(&mut integrity.journal, now).is_err()
        {
            poisoned = poisoned.saturating_add(1);
        }
        if let Some(evidence) = integrity.evidence.as_mut()
            && let Some(signing) = evidence.signing.as_mut()
            && signing.duty(evidence.store.journal_mut(), now).is_err()
        {
            poisoned = poisoned.saturating_add(1);
        }
        // Each group directory's store journal, on the same schedule
        // (karyos#1137).
        for (dir, (_, signing)) in &mut self.group_signings {
            if let Some(Some(store)) = self.group_stores.get_mut(dir)
                && signing.duty(store.journal_mut(), now).is_err()
            {
                poisoned = poisoned.saturating_add(1);
            }
        }
        if let Some(counts) = counts {
            for _ in 0..poisoned {
                count(&counts.poisoned_signer);
            }
        }
        !changes.is_empty() || integrity.journal.head() != before
    }

    fn duty(&mut self, outbox: &Outbox, now: u64) -> bool {
        let mut worked = false;
        let mut index = 0;
        while let Some(recording) = self.active.get_mut(index) {
            // What was durable before a close that may fail.
            let durable = recording.recorder.store().durable();
            let event = match recording.recorder.duty(now) {
                Ok(duty) => {
                    worked |= duty.recorded > 0;
                    if duty.fenced {
                        outbox.fenced();
                    }
                    if duty.rejoined {
                        outbox.rejoined();
                    }
                    if duty.ended.is_none() {
                        index += 1;
                        continue;
                    }
                    // The reason it ended for (the seal, a lap).
                    finish(
                        self.active.swap_remove(index),
                        &mut self.catalog,
                        self.integrity.as_mut(),
                        StopReason::Normal,
                        now,
                    )
                }
                Err(error) => {
                    worked = true;
                    let recording = self.active.swap_remove(index);
                    match error.fail_kind() {
                        // The store is whole: close it and stop the
                        // recording, typed.
                        Some(kind) => {
                            finish(
                                recording,
                                &mut self.catalog,
                                // The store is whole: its last range is
                                // sealed; one it cannot serve stays
                                // unsealed for the verifier.
                                self.integrity.as_mut(),
                                StopReason::Failed(kind),
                                now,
                            )
                        }
                        None => Event::Failed {
                            id: recording.id,
                            failure: Failure::Store,
                            position: recording.recorder.store().written(),
                        },
                    }
                }
            };
            // A recording that ended is settled by the groups' duty, from
            // its stop in the catalog; one that failed has none there.
            if let Event::Failed { id, .. } = event {
                fail_recording(
                    &mut self.groups,
                    &self.active,
                    (&mut self.failed, &mut self.failures),
                    &self.catalog,
                    id,
                    durable,
                );
            }
            outbox.send(event);
        }
        worked
    }

    /// Serves one command; `true` when it was the shutdown.
    fn serve(&mut self, command: Command, outbox: &Outbox, now: u64) -> bool {
        match command {
            Command::Start(start, reply) => {
                let _ = reply.send(self.start_recording(*start, outbox, now));
            }
            Command::Stop(id, reply) => {
                let result = match self.active.iter().position(|recording| recording.id == id) {
                    Some(index) => {
                        let recording = self.active.swap_remove(index);
                        let durable = recording.recorder.store().durable();
                        let result = stop(
                            recording,
                            &mut self.catalog,
                            self.integrity.as_mut(),
                            StopReason::Stopped,
                            now,
                        );
                        // A stop that failed leaves the recording to settle,
                        // with none in the catalog to settle the groups'
                        // references by.
                        if result.is_err() {
                            fail_recording(
                                &mut self.groups,
                                &self.active,
                                (&mut self.failed, &mut self.failures),
                                &self.catalog,
                                id,
                                durable,
                            );
                        }
                        result
                    }
                    None if self.failed.iter().any(|failed| failed.id == id) => {
                        Err(AgentError::RecordingFailed { id })
                    }
                    None => Err(AgentError::NotRecording { id }),
                };
                let _ = reply.send(result);
            }
            Command::List(reply) => {
                let _ = reply.send(Ok(self.catalog.recordings().to_vec()));
            }
            Command::Word {
                stream_id,
                session_id,
                lane,
                reply,
            } => {
                // A local stream's recording first: a host recording its own
                // network publication and that publication's loopback image
                // has both of one key (karyos#490); never a silent pick.
                let word_of = |from: RecordedFrom| {
                    self.active
                        .iter()
                        .filter(|active| {
                            active.stream_id == stream_id
                                && active.session_id == session_id
                                && active.lane == lane
                                && (active.origin == RecordedFrom::Local)
                                    == (from == RecordedFrom::Local)
                        })
                        .find_map(|active| active.word.as_ref().map(|guard| Arc::clone(&guard.0)))
                };
                let word = word_of(RecordedFrom::Local).or_else(|| word_of(RecordedFrom::Image));
                let _ = reply.send(Ok(word));
            }
            Command::Snapshot {
                from_id,
                max,
                reply,
            } => {
                let listed = self
                    .catalog
                    .recordings()
                    .iter()
                    .filter(|recording| recording.id >= from_id)
                    .take(max)
                    .map(|recording| described(recording, &self.active))
                    .collect();
                let _ = reply.send(Ok(listed));
            }
            Command::Describe(id, reply) => {
                let result = self
                    .catalog
                    .get(id)
                    .map(|recording| described(recording, &self.active))
                    .ok_or(AgentError::Unknown { id });
                let _ = reply.send(result);
            }
            Command::Prepare(prepare, reply) => {
                let _ = reply.send(self.prepare_replay(prepare, outbox, now));
            }
            Command::Attach {
                id,
                from,
                mut sink,
                reply,
            } => {
                let result = match self.replays.prepared.iter().position(|p| p.id == id) {
                    Some(index) => {
                        let prepared = self.replays.prepared.swap_remove(index);
                        self.replays.active.push(ActiveReplay {
                            id,
                            source: prepared.source,
                            sink,
                            attached: now,
                            started: false,
                            ended: None,
                        });
                        Ok(id)
                    }
                    None => {
                        sink.finish(from, false);
                        Err(AgentError::Unknown { id })
                    }
                };
                let _ = reply.send(result);
            }
            Command::Replay(start, reply) => {
                let _ = reply.send(self.start_replay(*start, outbox, now));
            }
            Command::StopReplay(id, reply) => {
                let replays = &mut self.replays;
                let result = if let Some(index) = replays.active.iter().position(|r| r.id == id) {
                    let mut replay = replays.active.swap_remove(index);
                    let position = replay.source.position();
                    replay.sink.finish(position, false);
                    Ok(position)
                } else if let Some(index) = replays.prepared.iter().position(|p| p.id == id) {
                    Ok(replays.prepared.swap_remove(index).source.position())
                } else {
                    Err(AgentError::Unknown { id })
                };
                let _ = reply.send(result);
            }
            Command::StartGroup(start, reply) => {
                let _ = reply.send(self.start_group(*start, outbox));
            }
            Command::StopGroup(id, reply) => {
                let result = match self.groups.iter().position(|group| group.id == id) {
                    Some(index) => {
                        let group = self.groups.swap_remove(index);
                        self.close_group(group, now)
                    }
                    None => Err(AgentError::Unknown { id }),
                };
                let _ = reply.send(result);
            }
            Command::Retain(request, reply) => {
                let _ = reply.send(Ok(self.retain(request)));
            }
            Command::Verify(id, reply) => self.verify(id, reply),
            Command::RetentionState {
                from_id,
                max,
                reply,
            } => {
                let _ = reply.send(Ok(self.retention_state(from_id, max)));
            }
            Command::Replicate(request, chunk, reply) => {
                let _ = reply.send(self.replicate(request, chunk));
            }
            Command::StopReplication(stop, reply) => {
                self.stop_replication(stop);
                let _ = reply.send(Ok(()));
            }
            Command::ReplicationActive(correlation_id, reply) => {
                let active = self.replications.iter().any(|replication| {
                    replication.sender.request().correlation_id == correlation_id
                });
                let _ = reply.send(Ok(active));
            }
            Command::TimeEvidence(entry, reply) => {
                let _ = reply.send(self.record_time_evidence(&entry));
            }
            Command::CalibrationSource(source, reply) => {
                self.calibrations = Some(source);
                let _ = reply.send(Ok(()));
            }
            Command::Shutdown(reply) => {
                let groups = std::mem::take(&mut self.groups);
                for group in groups {
                    let _ = self.close_group(group, now);
                }
                for mut replay in self.replays.active.drain(..) {
                    let position = replay.source.position();
                    replay.sink.finish(position, false);
                }
                self.replays.prepared.clear();
                let mut first = Ok(());
                for recording in self.active.drain(..) {
                    if let Err(error) = stop(
                        recording,
                        &mut self.catalog,
                        self.integrity.as_mut(),
                        StopReason::Shutdown,
                        now,
                    ) && first.is_ok()
                    {
                        first = Err(error);
                    }
                }
                // The stops' catalog records are chained before the reply.
                let _ = self.integrity_duty(now);
                let _ = reply.send(first);
                return true;
            }
        }
        false
    }

    /// Drains what the group's ring still holds into its journal, then
    /// closes it, synced: an event the sender wrote before the stop is
    /// recorded. The sender is refused first, and the drain is bounded by
    /// the ring, so a live sender cannot hold the agent here.
    fn close_group(&mut self, mut group: ActiveGroup<D>, now: u64) -> Result<u64, AgentError> {
        let recorded = Recorded {
            active: &self.active,
            failed: &self.failed,
            catalog: &self.catalog,
        };
        let coverage = GroupCoverage {
            recorded: &recorded,
            store: group.checkpoints.as_ref().map(|c| c.writer.store()),
        };
        // A job that fails reports it through its sender's state, and
        // closes all the same.
        let _ = group.job.drain_to_close(now, &coverage);
        // Its last records sealed and their time evidence produced, a
        // pending batch without waiting more (karyos#1137): the close never
        // leaves a sealed range without its entries.
        if self.integrity.is_some() {
            seal_group(&mut self.group_seals, &mut group, &self.disk);
            while group.evidence.is_some()
                && produce_evidence(
                    &self.group_seals,
                    &mut self.group_stores,
                    &mut group,
                    self.calibrations.as_mut(),
                    now,
                    true,
                )
            {}
        }
        // A checkpoint not recorded by the stop is not: its buffer goes
        // back, and its bytes stay unnamed.
        // Both close; the first error is reported.
        let mut stored = Ok(());
        if let Some(mut checkpoints) = group.checkpoints {
            if let Some(request) = checkpoints.current.take() {
                checkpoints
                    .inbox
                    .give_back(request, Err(CheckpointError::Stopped));
            }
            checkpoints.inbox.close();
            stored = checkpoints.writer.close().map(drop);
        }
        let closed = group.job.close().map_err(AgentError::from);
        stored?;
        closed
    }

    /// Checks a restart against the reopen hold its journal's header
    /// records (A9): the hold and checkpoints are fixed per group. Refused
    /// ([`AgentError::CheckpointConfig`]): checkpoints on a group made
    /// without them, or off for one made with them; an explicit hold whose
    /// effective window, `max(hold, in_flight)`, differs from the recorded
    /// one; and an `in_flight` above it (the clamp would raise the running
    /// window).
    fn check_hold(start: &StartGroup, recorded: u32) -> Result<(), AgentError> {
        let Some(checkpoints) = &start.checkpoints else {
            // Checkpoints off for a group made with them would take back
            // the durability its reopened ranges reported.
            return if recorded == 0 {
                Ok(())
            } else {
                Err(AgentError::CheckpointConfig)
            };
        };
        let recorded = usize::try_from(recorded).map_err(|_| AgentError::CheckpointConfig)?;
        let differs = checkpoints
            .reopen_hold
            .is_some_and(|hold| hold.max(start.capture.in_flight) != recorded);
        if recorded == 0 || differs || start.capture.in_flight > recorded {
            return Err(AgentError::CheckpointConfig);
        }
        Ok(())
    }

    /// Makes or recovers a group's journal and its capture path.
    fn start_group(
        &mut self,
        start: StartGroup,
        outbox: &Outbox,
    ) -> Result<CaptureSender, AgentError> {
        if self.groups.len() >= self.config.max_groups {
            return Err(outbox.refused("groups", self.config.max_groups));
        }
        let id = start.group_id;
        if self.groups.iter().any(|group| group.id == id) {
            return Err(AgentError::GroupCaptured { id });
        }
        // The declaration is checked before any file is made, sealing or
        // not (karyos#1137).
        if let Some(declared) = start.time_evidence.as_ref() {
            check_declared(
                declared,
                self.integrity
                    .as_ref()
                    .and_then(|integrity| integrity.group_signing.as_ref()),
            )?;
        }
        // Sealing on: the Archive's directory holds its own integrity
        // journal, which a group's cannot share (karyos#1112). Compared as
        // canonical paths, so a relative path, a `..` detour or a link to
        // the Archive's directory is the Archive's directory (karyos#1140);
        // the canonical path also keys the group's integrity journal.
        let sealed_dir = if self.integrity.is_some() {
            let resolve = |dir: &Path| {
                std::fs::canonicalize(dir).map_err(|error| AgentError::GroupDirectoryUnresolved {
                    dir: start.dir.clone(),
                    kind: error.kind(),
                })
            };
            // `std::fs::canonicalize` goes around the `Disk` abstraction,
            // which matters only if a disk other than the host's ever runs
            // a sealing Archive.
            let group = resolve(&start.dir)?;
            // The Archive's own directory not resolving (moved or removed
            // while the Archive runs) refuses the group: without it the
            // two cannot be told apart (karyos#1149).
            let own = std::fs::canonicalize(&self.dir).map_err(|error| {
                AgentError::GroupDirectoryUnresolved {
                    dir: self.dir.clone(),
                    kind: error.kind(),
                }
            })?;
            if own == group {
                return Err(AgentError::GroupInArchiveDirectory { dir: start.dir });
            }
            Some(group)
        } else {
            None
        };
        // One store per directory has one signed identity (karyos#1137).
        if let (Some(declared), Some(dir)) = (start.time_evidence.as_ref(), sealed_dir.as_ref())
            && let (Some(declared_id), Some((signed, _))) =
                (declared.journal_id, self.group_signings.get(dir))
            && declared_id != *signed
        {
            return Err(AgentError::GroupStoreJournalId {
                signed: *signed,
                declared: declared_id,
            });
        }
        // Checked before the journal exists, so a refused start leaves
        // none behind.
        capture::validate(start.capture, start.journal.policy).map_err(AgentError::Capture)?;
        if let Some(checkpoints) = &start.checkpoints
            && (checkpoints.max_checkpoint == 0 || self.config.checkpoint_budget == 0)
        {
            return Err(AgentError::CheckpointConfig);
        }
        // A new group's reopening window, recorded in its header (A9) and
        // checked here, before the journal exists: configured, or four
        // times `in_flight`, at least `in_flight`; 0 without checkpoints.
        let new_hold = match (&start.new, &start.checkpoints) {
            (None, _) | (Some(_), None) => 0,
            (Some(_), Some(checkpoints)) => {
                let hold = match checkpoints.reopen_hold {
                    Some(hold) => hold,
                    None => start
                        .capture
                        .in_flight
                        .checked_mul(4)
                        .ok_or(AgentError::CheckpointConfig)?,
                }
                .max(start.capture.in_flight);
                if hold > MAX_REOPEN_HOLD {
                    return Err(AgentError::CheckpointConfig);
                }
                u32::try_from(hold).map_err(|_| AgentError::CheckpointConfig)?
            }
        };
        let checkpoint_dir = store_dir(&start.dir);
        // Before a journal is recovered, its plan. A recovery that would
        // cut it to nothing, dropping more than the header's own write,
        // cuts away a header that events followed: nothing takes it, with
        // nothing written, on every start (the operator may copy the
        // journal). A crash while the header was written tears that one
        // write only, with nothing after it; that journal is taken over as
        // never written, since nothing of it was ever reported durable.
        let verified = |disk: &D| -> Result<(), AgentError> {
            let plan = GroupJournal::verify(disk.clone(), &start.dir, id, start.journal)?;
            let dropped = plan.kept.as_ref().map_or(0, |kept| kept.dropped_entries);
            match plan.cut {
                Some(cut) if cut.position == 0 && (dropped > 1 || !plan.dropped.is_empty()) => {
                    Err(AgentError::HeaderCut { id, cut })
                }
                _ => Ok(()),
            }
        };
        // The header a new group writes, once its store is open: a
        // refusal writes nothing.
        let mut pending_header = None;
        let journal = match &start.new {
            Some(new) => {
                let header = JournalHeader {
                    group_id: id,
                    first_group_seq: new.first_group_seq,
                    inline_threshold: new.inline_threshold,
                    contract_version: CONTRACT_VERSION,
                    clock: Clock::HostMonotonic,
                    capture: new.capture,
                    reopen_hold: new_hold,
                    manifest: &new.manifest,
                };
                match GroupJournal::create(self.disk.clone(), &start.dir, &header, start.journal) {
                    Ok(journal) => journal,
                    // A journal whose header was never written: the new
                    // group takes it over, its header written once its
                    // store is open. One with a header is the group's
                    // already.
                    Err(exists @ JournalError::Segment(SegmentError::Exists { .. })) => {
                        verified(&self.disk)?;
                        let mut journal = GroupJournal::recover(
                            self.disk.clone(),
                            &start.dir,
                            id,
                            start.journal,
                        )?
                        .journal;
                        if journal.reopen_hold()?.is_some() {
                            return Err(exists.into());
                        }
                        pending_header = Some(header);
                        journal
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            None => {
                verified(&self.disk)?;
                let mut journal =
                    GroupJournal::recover(self.disk.clone(), &start.dir, id, start.journal)?
                        .journal;
                if journal.reopen_hold()?.is_none() {
                    return Err(AgentError::NoHeader { id });
                }
                journal
            }
        };
        let mut journal = journal;
        // A restart takes the header's window as recorded, before the
        // store or the capture path is touched; the journal's own
        // recovery, which may cut a torn tail, has run. The hold is fixed
        // per group.
        if start.new.is_none() {
            let recorded = journal.reopen_hold()?.ok_or(AgentError::NoHeader { id })?;
            Self::check_hold(&start, recorded)?;
        }
        // The store beside the journal, made or recovered with it: a
        // recovered one is cut to what the journal's records name. A
        // journal taken over may have a store from the same crash: it is
        // opened as a restart's, cut to nothing. Without checkpoints, a
        // store left there is not read.
        let taken_over = pending_header.is_some();
        let store = match &start.checkpoints {
            None => None,
            Some(_) if start.new.is_some() && !taken_over => Some(CheckpointStore::create(
                self.disk.clone(),
                &checkpoint_dir,
                id,
                start.journal,
            )?),
            Some(_) => {
                let end = recorded_end(&mut journal)?;
                Some(
                    match CheckpointStore::recover(
                        self.disk.clone(),
                        &checkpoint_dir,
                        id,
                        start.journal,
                        end,
                    ) {
                        // A missing store: a group whose checkpoints were
                        // never kept, or one whose store is gone. The
                        // ranges its journal's records name are then lost
                        // (A9 section 2), and the group starts.
                        Err(SegmentError::NotFound { .. }) => {
                            let mut store = CheckpointStore::create(
                                self.disk.clone(),
                                &checkpoint_dir,
                                id,
                                start.journal,
                            )?;
                            store.mark_lost(end)?;
                            store
                        }
                        recovered => recovered?,
                    },
                )
            }
        };
        if let Some(header) = pending_header {
            let _ = journal.write_header(&header)?;
        }
        let recorded = Recorded {
            active: &self.active,
            failed: &self.failed,
            catalog: &self.catalog,
        };
        let coverage = GroupCoverage {
            recorded: &recorded,
            store: store.as_ref(),
        };
        let (mut sender, job) =
            capture::capture(start.capture, journal, &coverage).map_err(|error| match error {
                CaptureSetup::Config(error) => AgentError::Capture(error),
                CaptureSetup::Journal(error) => AgentError::Journal(error),
                CaptureSetup::ImagesOfAnEarlierRun => AgentError::ImagesOfAnEarlierRun,
            })?;
        let checkpoints = match (store, &start.checkpoints) {
            (Some(store), Some(config)) => {
                let writer = CheckpointWriter::new(store, job.journal())
                    .map_err(|error| AgentError::Checkpoint(Box::new(error)))?;
                let (handle, inbox) = handoff(config.max_checkpoint);
                sender.attach_checkpoints(handle);
                Some(GroupWriter {
                    writer,
                    inbox,
                    current: None,
                })
            }
            _ => None,
        };
        // A new ring holds no reference to a recording that failed.
        let dir = sealed_dir.unwrap_or_else(|| start.dir.clone());
        let evidence = match start.time_evidence {
            Some(declared) if self.integrity.is_some() => group_evidence(
                &self.disk,
                &mut self.group_stores,
                &dir,
                id,
                declared,
                job.journal().start(),
                job.journal().durable(),
            )?,
            _ => None,
        };
        if let (Some(declared), Some(integrity)) = (start.time_evidence, self.integrity.as_ref())
            && let (Some(shared), Some(journal_id)) =
                (integrity.group_signing.as_ref(), declared.journal_id)
            && !self.group_signings.contains_key(&dir)
            && let Some(Some(store)) = self.group_stores.get_mut(&dir)
        {
            let signing = Signing::open_shared(
                self.disk.clone(),
                &crate::integrity::time_evidence::entries_dir(&dir),
                (shared.trust.clone(), journal_id, shared.config),
                Arc::clone(&shared.signer),
                store.journal_mut(),
                Arc::default(),
            )?;
            self.group_signings
                .insert(dir.clone(), (journal_id, signing));
        }
        self.groups.push(ActiveGroup {
            id,
            dir,
            job,
            checkpoints,
            cleared: self.failures,
            evidence,
        });
        Ok(sender)
    }

    /// Records `entry` once its range is sealed (karyos#1128).
    fn record_time_evidence(
        &mut self,
        entry: &crate::integrity::time_evidence::Entry,
    ) -> Result<u64, AgentError> {
        let Some(integrity) = self.integrity.as_mut() else {
            return Err(AgentError::NoTimeEvidence);
        };
        if integrity.no_time_journal {
            return Err(AgentError::NoTimeEvidenceJournal);
        }
        let sealed = integrity.journal.sealed_range(entry.recording);
        let Some(evidence) = integrity.evidence.as_mut() else {
            return Err(AgentError::NoTimeEvidence);
        };
        admit_time_evidence(sealed, entry)?;
        Ok(evidence.store.append(entry)?)
    }

    /// Each group's job: drains its ring into its journal and advances its
    /// prefixes over the recordings. Returns whether any read.
    fn group_duty(&mut self, now: u64) -> bool {
        let recorded = Recorded {
            active: &self.active,
            failed: &self.failed,
            catalog: &self.catalog,
        };
        let failures = self.failures;
        let checkpoint_budget = self.config.checkpoint_budget;
        let mut worked = false;
        for group in &mut self.groups {
            let emptied = group.job.emptied();
            let coverage = GroupCoverage {
                recorded: &recorded,
                store: group.checkpoints.as_ref().map(|c| c.writer.store()),
            };
            // A job that fails reports it through its sender's state.
            worked |= group
                .job
                .duty(now, self.config.group_budget, &coverage)
                .unwrap_or(false);
            if let Some(checkpoints) = group.checkpoints.as_mut()
                && checkpoint_duty(&mut group.job, checkpoints, checkpoint_budget)
            {
                worked = true;
                // A checkpoint just recorded may open a range: now, not at
                // the next cycle.
                let coverage = GroupCoverage {
                    recorded: &recorded,
                    store: Some(checkpoints.writer.store()),
                };
                group.job.refresh(&coverage);
            }
            if self.integrity.is_some() {
                seal_group(&mut self.group_seals, group, &self.disk);
                worked |= produce_evidence(
                    &self.group_seals,
                    &mut self.group_stores,
                    group,
                    self.calibrations.as_mut(),
                    now,
                    false,
                );
            }
            // A group that read its ring empty, or that reads nothing
            // more, holds no reference to an earlier failure.
            if group.job.emptied() != emptied || group.job.state() != GroupState::Running {
                group.cleared = failures;
            }
        }
        worked
    }

    /// Drops the failed entries no group's ring can still name: every
    /// running group read its ring empty after the failure.
    fn reclaim_failed(&mut self) {
        let cleared = self
            .groups
            .iter()
            .map(|group| group.cleared)
            .min()
            .unwrap_or(self.failures);
        self.failed.retain(|failed| failed.seq > cleared);
    }

    fn start_recording(
        &mut self,
        start: StartRecording,
        outbox: &Outbox,
        now: u64,
    ) -> Result<u64, AgentError> {
        // A failed recording holds its slot until no group's ring can
        // still name it, which bounds the failed list by the cap. Its entry
        // is kept until a start needs the slot, so a late reference still
        // finds its durable end when nothing pressed for room.
        let held = |state: &Self| {
            state
                .active
                .len()
                .checked_add(state.failed.len())
                .ok_or(AgentError::Exhausted)
        };
        if held(self)? >= self.config.max_recordings {
            self.reclaim_failed();
        }
        if held(self)? >= self.config.max_recordings {
            return Err(outbox.refused("recordings", self.config.max_recordings));
        }
        // Every recording held, this one among them, can still fail with
        // the failure count in range.
        u64::try_from(self.config.max_recordings)
            .ok()
            .and_then(|max| self.failures.checked_add(max))
            .ok_or(AgentError::Exhausted)?;
        let position = start.source.position();
        let id = self.catalog.start(NewRecording {
            stream_id: start.stream_id,
            session_id: start.session_id,
            channel: &start.channel,
            start: position,
            start_time_ns: now,
            geometry: start.geometry,
            policy: start.policy,
            format: start.format,
            required: matches!(start.mode, Mode::Required),
        })?;
        let recorder = SegmentStore::create(
            self.disk.clone(),
            &self.dir,
            id,
            start.geometry,
            start.policy,
            position,
        )
        .map_err(AgentError::from)
        .and_then(|store| {
            Recorder::new(
                store,
                start.source,
                start.mode,
                self.config.buffer,
                self.config.budget,
            )
            .map_err(AgentError::from)
        });
        match recorder {
            Ok(recorder) => {
                let word = matches!(start.mode, Mode::Required).then(|| {
                    let word = Arc::new(RecordingWord::new());
                    word.set(id, position);
                    WordGuard(word)
                });
                self.active.push(Active {
                    id,
                    recorder,
                    stream_id: start.stream_id,
                    session_id: start.session_id,
                    lane: start.format.lane,
                    word,
                    origin: start.origin,
                });
                Ok(id)
            }
            Err(error) => {
                // `Started` is durable and nothing was recorded: the
                // recording stops empty, or is left for the next start to
                // settle when even that fails.
                if self
                    .catalog
                    .stop(id, position, now, StopReason::Empty, false)
                    .is_err()
                {
                    // Nothing was recorded, and no group refers to it yet.
                    self.failures = next_failure(self.failures);
                    self.failed.push(Failed {
                        id,
                        durable: position,
                        seq: self.failures,
                    });
                }
                Err(error)
            }
        }
    }

    /// Checks a replay's range and opens its source.
    fn prepare_replay(
        &mut self,
        prepare: PrepareReplay,
        outbox: &Outbox,
        now: u64,
    ) -> Result<Prepared, AgentError> {
        let id = prepare.recording_id;
        let recording = self.catalog.get(id).ok_or(AgentError::Unknown { id })?;
        let described = described(recording, &self.active);
        let from = prepare.position;
        let to = if prepare.length == u64::MAX {
            Some(described.end)
        } else {
            from.checked_add(prepare.length)
        };
        // The end is checked here, where the length is resolved; the
        // source's open checks the start against what the store holds and
        // that it is a frame boundary.
        let Some(to) = to.filter(|to| from < *to && *to <= described.end) else {
            return Err(AgentError::Replay(ReplayError::OutOfRange {
                from,
                to: to.unwrap_or(u64::MAX),
            }));
        };
        if self.replays.len() >= self.config.max_replays {
            return Err(outbox.refused("replays", self.config.max_replays));
        }
        let source = ReplaySource::open(
            self.disk.clone(),
            &self.dir,
            id,
            described.recording.geometry,
            from,
            to,
            prepare.rate,
            self.config.buffer,
        )?;
        let replay_id = self.replays.id()?;
        self.replays.prepared.push(PreparedReplay {
            id: replay_id,
            source,
            at: now,
        });
        Ok(Prepared {
            replay_id,
            recording: described.recording,
            from,
            to,
        })
    }

    /// Prepares a replay and runs it into its sink; a sink not taken is
    /// finished, incomplete.
    fn start_replay(
        &mut self,
        mut start: StartReplay,
        outbox: &Outbox,
        now: u64,
    ) -> Result<u64, AgentError> {
        let from = start.from;
        let prepared = start
            .to
            .checked_sub(from)
            .ok_or(AgentError::Replay(ReplayError::OutOfRange {
                from,
                to: start.to,
            }))
            .and_then(|length| {
                self.prepare_replay(
                    PrepareReplay {
                        recording_id: start.recording_id,
                        position: from,
                        length,
                        rate: start.rate,
                    },
                    outbox,
                    now,
                )
            });
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                start.sink.finish(from, false);
                return Err(error);
            }
        };
        let Some(index) = self
            .replays
            .prepared
            .iter()
            .position(|replay| replay.id == prepared.replay_id)
        else {
            start.sink.finish(from, false);
            return Err(AgentError::Unknown {
                id: prepared.replay_id,
            });
        };
        let source = self.replays.prepared.swap_remove(index).source;
        self.replays.active.push(ActiveReplay {
            id: prepared.replay_id,
            source,
            sink: start.sink,
            attached: now,
            started: false,
            ended: None,
        });
        Ok(prepared.replay_id)
    }
}

/// Closes a recording's store and stops it in the catalog, with the
/// reason it ended for or else `reason`.
fn finish<D: Disk>(
    recording: Active<D>,
    catalog: &mut Catalog<D>,
    integrity: Option<&mut Integrity<D>>,
    reason: StopReason,
    now: u64,
) -> Event {
    let id = recording.id;
    let position = recording.recorder.store().written();
    match stop(recording, catalog, integrity, reason, now) {
        Ok(ended) => Event::Ended { id, ended },
        Err(_) => Event::Failed {
            id,
            failure: Failure::Stop,
            position,
        },
    }
}

/// Closes the store with everything durable, then appends `Stopped` at
/// the durable position.
fn stop<D: Disk>(
    recording: Active<D>,
    catalog: &mut Catalog<D>,
    integrity: Option<&mut Integrity<D>>,
    reason: StopReason,
    now: u64,
) -> Result<Ended, AgentError> {
    let Active {
        id,
        mut recorder,
        word,
        ..
    } = recording;
    // Cleared first: a Gateway stops naming the recording before the close
    // and the catalog's stop, which take time.
    drop(word);
    let mut integrity = integrity.filter(|integrity| !integrity.failed);
    let mut sealed = false;
    if let Some(integrity) = integrity.as_deref_mut() {
        sealed = seal_last(integrity, id, &mut recorder, now);
        integrity.failed = !sealed;
    }
    let start = recorder.store().start();
    // A list that cannot be read is no file list: the copy then records
    // no enforcement (karyos#1024 review).
    let files = recorder.store().segment_files().unwrap_or_default();
    let ended = recorder.close(reason)?;
    catalog.stop(id, ended.position, now, ended.reason, ended.incomplete)?;
    if let Some(integrity) = integrity.filter(|_| sealed) {
        integrity.record_local_copy(id, start, ended.position, &files);
    }
    Ok(ended)
}

/// The enforcement a local copy of `files` records: the immutable
/// attribute only when the list is not empty and every file took it,
/// [`Enforcement::Unsupported`] otherwise, so an empty or unreadable file
/// list never records a protection that is not there (karyos#1024
/// review).
///
/// [`Enforcement::Unsupported`]: crate::integrity::copies::Enforcement::Unsupported
fn local_enforcement(
    backend: &mut impl crate::integrity::copies::ImmutabilityBackend,
    files: &[PathBuf],
) -> crate::integrity::copies::Enforcement {
    use crate::integrity::copies::Enforcement;
    if files.is_empty() {
        return Enforcement::Unsupported;
    }
    let mut enforcement = Enforcement::ImmutableAttribute;
    for file in files {
        if !matches!(
            backend.enforce(file, 0),
            Ok(Enforcement::ImmutableAttribute)
        ) {
            enforcement = Enforcement::Unsupported;
        }
    }
    enforcement
}

/// Finishes, at start, every offload of a tiered Archive a crash cut
/// short (ADR-0104, decision 4): each offloaded recording's data files
/// below its offloaded end are released from immutability first, then,
/// with a copy catalog, its store is recovered and
/// [`crate::integrity::tiering::Tiering::reconcile`] uncounts the local
/// copy, raises the start and removes the files; without one, only the
/// start is raised.
fn reconcile_offloads<D: Disk + Clone>(
    disk: &D,
    dir: &Path,
    integrity: &mut Integrity<D>,
    catalog: &Catalog<D>,
) -> Result<(), AgentError> {
    use crate::integrity::tiering::{Releasing, Tiering, offloaded, reconcile_floors};
    let tiering_error = |error: crate::integrity::tiering::TieringError| {
        AgentError::Io(std::io::Error::other(error.to_string()))
    };
    let records = integrity.journal.records()?;
    #[cfg(target_os = "linux")]
    let mut backend = crate::integrity::copies::ImmutableAttribute;
    #[cfg(not(target_os = "linux"))]
    let mut backend = crate::integrity::copies::NoImmutability;
    let names = disk.clone().list(dir)?;
    for (id, offloads) in offloaded(&records) {
        let Some(recording) = catalog.get(id) else {
            continue;
        };
        let end = offloads
            .iter()
            .map(|offload| offload.end)
            .max()
            .unwrap_or(0);
        let floor_base = recording.geometry.base_of(end);
        let prefix = format!("{id:016x}-");
        for name in &names {
            let below = name
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".seg"))
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .is_some_and(|base| base < floor_base);
            if below {
                crate::integrity::copies::ImmutabilityBackend::release(
                    &mut backend,
                    &dir.join(name),
                )?;
            }
        }
        if let Some((copies, local)) = integrity.copies.as_mut() {
            let mut store =
                SegmentStore::recover(disk.clone(), dir, id, recording.geometry, recording.policy)?
                    .store;
            // The destination plays no part after the offload record.
            Tiering {
                local: *local,
                remote: *local,
            }
            .reconcile(
                copies,
                &mut integrity.journal,
                &mut store,
                &mut Releasing(&mut backend),
            )
            .map_err(tiering_error)?;
        }
    }
    if integrity.copies.is_none() {
        let _ = reconcile_floors(&mut disk.clone(), dir, &records)?;
    }
    Ok(())
}

impl<D: Disk> Integrity<D> {
    /// Records recording `id`, closed and sealed over `[start, end)`, as a
    /// verified local copy: each segment file in `files` is made
    /// immutable through the platform's backend, and the copy records
    /// [`Enforcement::ImmutableAttribute`] only when every file took it,
    /// [`Enforcement::Unsupported`] otherwise (karyos#1024). Its digest is
    /// that of the range's seals, as a purge records them. A failure
    /// leaves the copy unrecorded and stops recording copies.
    fn record_local_copy(&mut self, id: u64, start: u64, end: u64, files: &[PathBuf]) {
        use crate::integrity::copies::{CopyRecord, CopyState};
        if end <= start {
            return;
        }
        let Some((copies, location)) = self.copies.as_mut() else {
            return;
        };
        #[cfg(target_os = "linux")]
        let mut backend = crate::integrity::copies::ImmutableAttribute;
        #[cfg(not(target_os = "linux"))]
        let mut backend = crate::integrity::copies::NoImmutability;
        let enforcement = local_enforcement(&mut backend, files);
        let recorded = self.journal.records().and_then(|records| {
            let digest = crate::integrity::retention::seals_digest(&records, id, start, end);
            copies.record(
                CopyRecord {
                    sequence: 0,
                    recording: id,
                    start,
                    end,
                    location: *location,
                    digest,
                    retain_until_ns: 0,
                    state: CopyState::Verified,
                    enforcement,
                    profile: crate::integrity::copies::ArrivalProfile::Local,
                },
                &mut self.journal,
            )
        });
        if recorded.is_err() {
            self.copies = None;
        }
    }
}

/// Seals `group`'s journal from where its seals end to its durable end,
/// in at most 1 MiB pieces, in the integrity journal of its directory,
/// opened at the first seal (A10; karyos#1088): `karyos-catalog verify` of
/// that directory then reports its ranges. A failure stops the sealing of
/// that directory until restart; the groups go on.
fn seal_group<D: Disk + Clone>(
    seals: &mut std::collections::BTreeMap<PathBuf, Option<IntegrityJournal<D>>>,
    group: &mut ActiveGroup<D>,
    disk: &D,
) {
    const CHUNK: u64 = 1 << 20;
    let entry = seals.entry(group.dir.clone()).or_insert_with(|| {
        IntegrityJournal::open(disk.clone(), &group.dir)
            .ok()
            .map(|opened| opened.journal)
    });
    let Some(integrity) = entry.as_mut() else {
        return;
    };
    let journal = group.job.journal_mut();
    let mut from = integrity.sealed_end(group.id).unwrap_or(journal.start());
    let end = journal.durable();
    let mut buf = Vec::new();
    let mut failed = false;
    while from < end {
        let to = end.min(from.saturating_add(CHUNK));
        let Ok(length) = usize::try_from(to.saturating_sub(from)) else {
            failed = true;
            break;
        };
        buf.resize(length, 0);
        if journal.read_bytes(from, &mut buf).is_err()
            || integrity.seal_segment(group.id, from, &buf, false).is_err()
        {
            failed = true;
            break;
        }
        from = to;
    }
    if failed {
        *entry = None;
    }
}

/// Checks a group's declaration before any file is made: not the reserved
/// zero tuple, and, for a signing Archive, a journal identity of its own,
/// never one of the Archive's journals'.
///
/// # Errors
///
/// [`AgentError::ZeroEventClock`], [`AgentError::NoTimeEvidenceJournal`]
/// and [`AgentError::SharedJournalId`].
fn check_declared(
    declared: &GroupTimeEvidence,
    shared: Option<&GroupSigning>,
) -> Result<(), AgentError> {
    if declared.clock.clock == [0; 5] {
        return Err(AgentError::ZeroEventClock);
    }
    let Some(shared) = shared else {
        return Ok(());
    };
    let id = declared
        .journal_id
        .ok_or(AgentError::NoTimeEvidenceJournal)?;
    if shared.taken.contains(&Some(id)) {
        return Err(AgentError::SharedJournalId);
    }
    Ok(())
}

/// A group's time evidence, when the host made `time-evidence/` in its
/// journal directory: the directory's store opened once and shared, the
/// session starting at `session_start`, production resuming after the
/// group's last entry in the store, or at the journal's `start`. Records
/// of an earlier session get the zero identity, never a skip.
///
/// # Errors
///
/// The store's errors.
fn group_evidence<D: Disk + Clone>(
    disk: &D,
    stores: &mut GroupStores<D>,
    dir: &Path,
    id: u64,
    declared: GroupTimeEvidence,
    start: u64,
    session_start: u64,
) -> Result<Option<GroupEvidence>, AgentError> {
    use crate::integrity::time_evidence::{DIR, EntryStore};
    if !stores.contains_key(dir) {
        if !disk.clone().list(dir)?.iter().any(|name| name == DIR) {
            return Ok(None);
        }
        stores.insert(
            dir.to_path_buf(),
            Some(EntryStore::open(disk.clone(), dir)?),
        );
    }
    let Some(Some(store)) = stores.get_mut(dir) else {
        return Ok(None);
    };
    let next = store
        .entries()?
        .iter()
        .filter(|entry| entry.recording == id)
        .map(|entry| entry.end)
        .max()
        .unwrap_or(start)
        .max(start);
    Ok(Some(GroupEvidence {
        declared,
        session_start,
        next,
        timers: std::collections::BTreeSet::new(),
        pending: None,
    }))
}

/// Produces `group`'s time evidence entries for what its integrity
/// journal sealed since the last (ADR-0098 item 3): the sealed records'
/// events, partitioned and bounded by [`produce`], appended to the
/// directory's store, sealed there. A batch's end is pinned at a record
/// boundary when it starts waiting for the calibrations, at most the
/// declared `calibration_wait` (with `finish`, no wait); later records
/// wait for the next batch. A walk or store failure stops the group's
/// production, never the capture or the seal: the rest stays without
/// entries (`no_evidence`). Returns whether any entry was appended.
///
/// [`produce`]: crate::integrity::time_producer::produce
fn produce_evidence<D: Disk + Clone>(
    seals: &std::collections::BTreeMap<PathBuf, Option<IntegrityJournal<D>>>,
    stores: &mut GroupStores<D>,
    group: &mut ActiveGroup<D>,
    calibrations: Option<&mut Box<dyn crate::integrity::time_producer::CalibrationSource>>,
    now: u64,
    finish: bool,
) -> bool {
    use crate::group::record::{GroupRecord, TimerAction};
    use crate::integrity::time_producer::{Event, Snapshot, produce};
    let ActiveGroup {
        id,
        dir,
        job,
        evidence: slot,
        ..
    } = group;
    let Some(evidence) = slot.as_mut() else {
        return false;
    };
    let Some(Some(store)) = stores.get_mut(dir) else {
        return false;
    };
    let Some(sealed) = seals
        .get(dir)
        .and_then(Option::as_ref)
        .and_then(|integrity| integrity.sealed_end(*id))
    else {
        return false;
    };
    // A pinned batch never grows: newer records wait for the next.
    let limit = evidence.pending.map_or(sealed, |(end, _)| end);
    if limit <= evidence.next {
        return false;
    }
    let session_start = evidence.session_start;
    let mut timers = evidence.timers.clone();
    let mut events: Vec<Event> = Vec::new();
    let mut stop = evidence.next;
    let walked = job.journal_mut().walk(evidence.next, |start, end, record| {
        if end > limit {
            return false;
        }
        stop = end;
        let in_session = start >= session_start;
        let time = match record {
            GroupRecord::Message(event) => Some(event.logical_time),
            GroupRecord::Conflated(event) => Some(event.logical_time),
            GroupRecord::Timer(event) => Some(event.logical_time),
            GroupRecord::Lifecycle(event) => Some(event.logical_time),
            GroupRecord::External(event) => Some(event.logical_time),
            GroupRecord::Loss(event) => Some(event.logical_time),
            GroupRecord::TimerOperation(operation) => {
                if in_session {
                    match operation.action {
                        TimerAction::Create => {
                            timers.insert(operation.timer_id);
                        }
                        TimerAction::Cancel => {
                            timers.remove(&operation.timer_id);
                        }
                    }
                }
                None
            }
            _ => None,
        };
        // A fired timer's deadline is proven only if this session
        // scheduled it.
        let proven = match record {
            GroupRecord::Timer(event) => timers.contains(&event.timer_id),
            _ => true,
        };
        match (time, events.last_mut()) {
            (Some(time), _) => events.push(Event {
                start,
                end,
                time,
                in_session: in_session && proven,
            }),
            (None, Some(last)) => last.end = end,
            (None, None) => {}
        }
        true
    });
    if walked.is_err() {
        *slot = None;
        return false;
    }
    if stop <= evidence.next {
        return false;
    }
    // The records before the first timed one belong to its entry, so the
    // entries tile from `next`.
    if let Some(first) = events.first_mut() {
        first.start = evidence.next;
    }
    let snapshot = calibrations.map_or_else(Snapshot::default, |source| source.snapshot());
    let wait = u64::try_from(evidence.declared.calibration_wait.as_nanos()).unwrap_or(u64::MAX);
    if !finish && !events.is_empty() && !snapshot.reaches(&evidence.declared.clock, &events) {
        let (_, since) = *evidence.pending.get_or_insert((stop, now));
        if now.saturating_sub(since) < wait {
            return false;
        }
    }
    let mut appended = false;
    for entry in produce(*id, &events, Some(&evidence.declared.clock), &snapshot) {
        if store.append(&entry).is_err() {
            *slot = None;
            return appended;
        }
        appended = true;
    }
    evidence.next = stop;
    evidence.timers = timers;
    evidence.pending = None;
    appended
}

/// Seals the last range of `id` before its store closes: everything
/// durable, the range marked closing. False on a failure.
fn seal_last<D: Disk>(
    integrity: &mut Integrity<D>,
    id: u64,
    recorder: &mut Recorder<D, Box<dyn FrameSource + Send>>,
    now: u64,
) -> bool {
    // Everything durable first, the segments rolled over unsynced
    // included, so the closing seal ends where the stop will.
    let durable = recorder
        .sync()
        .ok()
        .and_then(|_| recorder.store_mut().sync_all().ok());
    let Some(durable) = durable else {
        // The store's own failure, not the journal's: the range stays
        // unsealed and the close reports the failure.
        integrity.untrack(id);
        return true;
    };
    let start = recorder.store().start();
    if !integrity.written(id, start, durable, now)
        || integrity.sealer.close(id, durable, now).is_err()
    {
        return false;
    }
    let store = recorder.store_mut();
    let mut unreadable = false;
    let sealed = sealer::run_recording(
        &mut integrity.sealer,
        &mut integrity.journal,
        now,
        id,
        |_, start, end| {
            let read = read_store(store, start, end);
            unreadable = read.is_err();
            read
        },
    );
    integrity.untrack(id);
    sealed.is_ok() || unreadable
}

/// `recording` and where it ends now.
fn described<D: Disk>(recording: &Recording, active: &[Active<D>]) -> Described {
    let (end, durable, incomplete) = match recording.stop {
        // The close synced: the stop is durable.
        Some(stop) => (stop.position, stop.position, stop.incomplete),
        None => active
            .iter()
            .find(|active| active.id == recording.id)
            .map_or((recording.start, recording.start, false), |active| {
                let store = active.recorder.store();
                (
                    store.written(),
                    store.durable(),
                    active.recorder.incomplete(),
                )
            }),
    };
    Described {
        recording: recording.clone(),
        end,
        durable,
        incomplete,
    }
}

mod retention;

pub use retention::Verified;

#[cfg(test)]
mod tests;
