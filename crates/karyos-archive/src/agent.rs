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
//! - **Idle.** A cycle with nothing to do waits for a command up to the
//!   idle interval, so an idle agent does not spin.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::catalog::{Catalog, CatalogError, NewRecording, Recording, StopReason, StreamFormat};
use crate::disk::Disk;
use crate::recorder::{Ended, FrameSource, Mode, Recorder, RecorderError};
use crate::replay::{Rate, ReplayError, ReplaySource, Step};
use crate::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};

/// The agent's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentConfig {
    /// Commands queued at most. A handle waits for each command's reply
    /// before it sends another, so one is always enough; a send waits for
    /// room.
    pub command_capacity: usize,
    /// Events queued at most; a full queue drops the newest, counted by
    /// [`ArchiveHandle::dropped_events`].
    pub event_capacity: usize,
    /// The copy buffer of each recorder: at least the largest frame.
    pub buffer: usize,
    /// Bytes one recorder records at most per duty.
    pub budget: u64,
    /// How long an idle cycle waits for a command.
    pub idle: Duration,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            command_capacity: 64,
            event_capacity: 256,
            buffer: 64 * 1024,
            budget: 1 << 20,
            idle: Duration::from_millis(1),
        }
    }
}

/// A recording to start, with its source.
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
    },
    /// A replay ended by itself; its target was told with
    /// [`ReplaySink::finish`]. (One stopped by command reports nothing.)
    ReplayEnded {
        /// The replay.
        id: u64,
        /// Where it ended.
        position: u64,
        /// How.
        outcome: ReplayOutcome,
    },
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
}

/// A replay target that is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the replay target is closed")]
pub struct SinkClosed;

/// A replay to start: a recording's range onto a host's target.
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

/// How a replay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// It reached its requested end.
    Complete,
    /// Its recording could not be read, or its target closed.
    Failed,
}

/// A recording as the catalog lists it, and where it ends now: its stop,
/// or the position written for one that still records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Described {
    /// The catalog's record.
    pub recording: Recording,
    /// Its end now.
    pub end: u64,
    /// It lost ranges: its stop's, or so far for one that records.
    pub incomplete: bool,
}

/// What failed when a recording could not be stopped in the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Its segment store, while recording.
    Store,
    /// Closing its store or appending its `Stopped` record.
    Stop,
}

/// The agent's errors.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The catalog failed.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// A store failed.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// A recorder failed.
    #[error(transparent)]
    Recorder(#[from] RecorderError),
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
    /// The agent's thread is gone.
    #[error("the agent stopped")]
    Gone,
    /// The thread could not be spawned.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Reply<T> = SyncSender<Result<T, AgentError>>;

enum Command {
    Start(Box<StartRecording>, Reply<u64>),
    Stop(u64, Reply<Ended>),
    List(Reply<Vec<Recording>>),
    Describe(u64, Reply<Described>),
    Replay(Box<StartReplay>, Reply<u64>),
    StopReplay(u64, Reply<u64>),
    Shutdown(Reply<()>),
}

/// The host's handle on a running agent.
#[derive(Debug)]
pub struct ArchiveHandle {
    commands: SyncSender<Command>,
    events: Receiver<Event>,
    dropped: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Start(start, _) => f.debug_tuple("Start").field(start).finish(),
            Self::Stop(id, _) => f.debug_tuple("Stop").field(id).finish(),
            Self::List(_) => f.write_str("List"),
            Self::Describe(id, _) => f.debug_tuple("Describe").field(id).finish(),
            Self::Replay(start, _) => f.debug_tuple("Replay").field(start).finish(),
            Self::StopReplay(id, _) => f.debug_tuple("StopReplay").field(id).finish(),
            Self::Shutdown(_) => f.write_str("Shutdown"),
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
        let (commands, inbox) = mpsc::sync_channel(config.command_capacity);
        let (outbox, events) = mpsc::sync_channel(config.event_capacity);
        let (ready, started) = mpsc::sync_channel(1);
        let dir = dir.to_path_buf();
        let dropped = Arc::new(AtomicU64::new(0));
        let events_out = Outbox {
            sender: outbox,
            dropped: Arc::clone(&dropped),
        };
        let thread = std::thread::Builder::new()
            .name("karyos-archive".to_owned())
            .spawn(move || run(disk, dir, config, &inbox, &events_out, &ready))?;
        match started.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                events,
                dropped,
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

    /// Starts a recording of `start.source` from its position; returns its
    /// id once its `Started` is durable and its store exists.
    ///
    /// # Errors
    ///
    /// The catalog's and the store's errors, and [`AgentError::Gone`].
    pub fn start(&self, start: StartRecording) -> Result<u64, AgentError> {
        self.call(|reply| Command::Start(Box::new(start), reply))
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

    /// The catalog's recordings, in id order.
    ///
    /// # Errors
    ///
    /// [`AgentError::Gone`].
    pub fn recordings(&self) -> Result<Vec<Recording>, AgentError> {
        self.call(Command::List)
    }

    /// Recording `id` as the catalog lists it, and where it ends now.
    ///
    /// # Errors
    ///
    /// [`AgentError::Unknown`] and [`AgentError::Gone`].
    pub fn describe(&self, id: u64) -> Result<Described, AgentError> {
        self.call(|reply| Command::Describe(id, reply))
    }

    /// Starts a replay of a recording's range onto `start.sink`; returns
    /// its id. The recording is read, never changed; one that still
    /// records is read up to `start.to`.
    ///
    /// # Errors
    ///
    /// [`AgentError::Unknown`], [`AgentError::Replay`] for a range that
    /// cannot be read (its sink is then finished, incomplete), and
    /// [`AgentError::Gone`].
    pub fn replay(&self, start: StartReplay) -> Result<u64, AgentError> {
        self.call(|reply| Command::Replay(Box::new(start), reply))
    }

    /// Stops replay `id` where it is; returns that position. Its target is
    /// finished, incomplete.
    ///
    /// # Errors
    ///
    /// [`AgentError::Unknown`] and [`AgentError::Gone`].
    pub fn stop_replay(&self, id: u64) -> Result<u64, AgentError> {
        self.call(|reply| Command::StopReplay(id, reply))
    }

    /// The next event, if any.
    #[must_use]
    pub fn try_event(&self) -> Option<Event> {
        self.events.try_recv().ok()
    }

    /// Events dropped because the event queue was full.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The next event, waiting up to `timeout`.
    #[must_use]
    pub fn event(&self, timeout: Duration) -> Option<Event> {
        self.events.recv_timeout(timeout).ok()
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

/// The agent's side of the event queue: a full queue drops the event and
/// counts it.
struct Outbox {
    sender: SyncSender<Event>,
    dropped: Arc<AtomicU64>,
}

impl Outbox {
    fn send(&self, event: Event) {
        if self.sender.try_send(event).is_err() {
            // Sticky at u64::MAX rather than wrapping.
            let _ = self
                .dropped
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |dropped| {
                    dropped.checked_add(1)
                });
        }
    }
}

/// A recording the agent records.
struct Active<D: Disk> {
    id: u64,
    recorder: Recorder<D, Box<dyn FrameSource + Send>>,
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
}

/// The replays the agent runs, and the next id.
struct Replays<D: Disk> {
    active: Vec<ActiveReplay<D>>,
    next_id: u64,
}

impl<D: Disk> Replays<D> {
    /// Runs each replay up to `budget` bytes; returns whether any moved.
    fn duty(&mut self, now: u64, budget: u64, outbox: &Outbox) -> bool {
        let mut worked = false;
        for mut replay in std::mem::take(&mut self.active) {
            let (moved, ended) = run_replay(&mut replay, now, budget);
            worked |= moved;
            let Some(outcome) = ended else {
                self.active.push(replay);
                continue;
            };
            worked = true;
            let position = replay.source.position();
            replay
                .sink
                .finish(position, outcome == ReplayOutcome::Complete);
            outbox.send(Event::ReplayEnded {
                id: replay.id,
                position,
                outcome,
            });
        }
        worked
    }
}

/// One replay's duty: steps into its sink until it waits, has no room,
/// spends `budget` bytes or ends. Returns whether it moved, and how it
/// ended if it did.
fn run_replay<D: Disk>(
    replay: &mut ActiveReplay<D>,
    now: u64,
    budget: u64,
) -> (bool, Option<ReplayOutcome>) {
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
            Ok(Step::Wait { .. }) => return (moved, None),
            Ok(Step::End { .. }) => return (moved, Some(ReplayOutcome::Complete)),
            Err(_) => return (moved, Some(ReplayOutcome::Failed)),
        };
        match taken {
            Ok(true) => {
                moved = true;
                spent = spent.saturating_add(replay.source.position().saturating_sub(before));
            }
            // No room: the same step comes again on a later duty.
            Ok(false) => {
                let outcome = replay.source.hold().err().map(|_| ReplayOutcome::Failed);
                return (moved, outcome);
            }
            // Back to the step not taken, so the replay ends where its
            // target stopped taking.
            Err(SinkClosed) => {
                let _ = replay.source.hold();
                return (moved, Some(ReplayOutcome::Failed));
            }
        }
    }
    (moved, None)
}

/// The agent's thread.
fn run<D>(
    disk: D,
    dir: PathBuf,
    config: AgentConfig,
    inbox: &Receiver<Command>,
    outbox: &Outbox,
    ready: &SyncSender<Result<(), AgentError>>,
) where
    D: Disk + Clone,
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
    if let Err(error) = catalog.settle(now()) {
        let _ = ready.send(Err(error.into()));
        return;
    }
    if ready.send(Ok(())).is_err() {
        return;
    }
    let mut active: Vec<Active<D>> = Vec::new();
    // Recordings whose store failed: open in the catalog until the next
    // start settles them.
    let mut failed: Vec<u64> = Vec::new();
    let mut replays = Replays {
        active: Vec::new(),
        next_id: 1,
    };
    loop {
        let mut worked = false;
        loop {
            let command = match inbox.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            };
            worked = true;
            if serve(
                command,
                &disk,
                &dir,
                &config,
                &mut catalog,
                &mut active,
                &mut failed,
                &mut replays,
                now(),
            ) {
                return;
            }
        }
        // Each recording's duty; those that end or fail leave the set.
        for mut recording in std::mem::take(&mut active) {
            let event = match recording.recorder.duty(now()) {
                Ok(duty) => {
                    worked |= duty.recorded > 0;
                    if duty.ended.is_none() {
                        active.push(recording);
                        continue;
                    }
                    // The reason it ended for (the seal, a lap).
                    finish(recording, &mut catalog, StopReason::Normal, now())
                }
                Err(error) => {
                    worked = true;
                    match error.fail_kind() {
                        // The store is whole: close it and stop the
                        // recording, typed.
                        Some(kind) => {
                            finish(recording, &mut catalog, StopReason::Failed(kind), now())
                        }
                        None => Event::Failed {
                            id: recording.id,
                            failure: Failure::Store,
                        },
                    }
                }
            };
            if let Event::Failed { id, .. } = event {
                failed.push(id);
            }
            outbox.send(event);
        }
        worked |= replays.duty(now(), config.budget, outbox);
        if !worked {
            match inbox.recv_timeout(config.idle) {
                Ok(command) => {
                    if serve(
                        command,
                        &disk,
                        &dir,
                        &config,
                        &mut catalog,
                        &mut active,
                        &mut failed,
                        &mut replays,
                        now(),
                    ) {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

/// Closes a recording's store and stops it in the catalog, with the
/// reason it ended for or else `reason`.
fn finish<D: Disk>(
    recording: Active<D>,
    catalog: &mut Catalog<D>,
    reason: StopReason,
    now: u64,
) -> Event {
    let id = recording.id;
    match stop(recording, catalog, reason, now) {
        Ok(ended) => Event::Ended { id, ended },
        Err(_) => Event::Failed {
            id,
            failure: Failure::Stop,
        },
    }
}

/// Closes the store with everything durable, then appends `Stopped` at
/// the durable position.
fn stop<D: Disk>(
    recording: Active<D>,
    catalog: &mut Catalog<D>,
    reason: StopReason,
    now: u64,
) -> Result<Ended, AgentError> {
    let id = recording.id;
    let ended = recording.recorder.close(reason)?;
    catalog.stop(id, ended.position, now, ended.reason, ended.incomplete)?;
    Ok(ended)
}

/// Serves one command; `true` when it was the shutdown.
#[allow(
    clippy::too_many_arguments,
    reason = "one command against the agent's state: its disk, catalog and recordings"
)]
fn serve<D: Disk + Clone>(
    command: Command,
    disk: &D,
    dir: &Path,
    config: &AgentConfig,
    catalog: &mut Catalog<D>,
    active: &mut Vec<Active<D>>,
    failed: &mut Vec<u64>,
    replays: &mut Replays<D>,
    now: u64,
) -> bool {
    match command {
        Command::Start(start, reply) => {
            let result = start_recording(*start, disk, dir, config, catalog, active, now);
            let _ = reply.send(result);
            false
        }
        Command::Stop(id, reply) => {
            let result = match active.iter().position(|recording| recording.id == id) {
                Some(index) => {
                    let result = stop(active.swap_remove(index), catalog, StopReason::Stopped, now);
                    // A stop that failed leaves the recording to settle.
                    if result.is_err() {
                        failed.push(id);
                    }
                    result
                }
                None if failed.contains(&id) => Err(AgentError::RecordingFailed { id }),
                None => Err(AgentError::NotRecording { id }),
            };
            let _ = reply.send(result);
            false
        }
        Command::List(reply) => {
            let _ = reply.send(Ok(catalog.recordings().to_vec()));
            false
        }
        Command::Describe(id, reply) => {
            let _ = reply.send(describe(id, catalog, active));
            false
        }
        Command::Replay(start, reply) => {
            let _ = reply.send(start_replay(*start, disk, dir, config, catalog, replays));
            false
        }
        Command::StopReplay(id, reply) => {
            let result = match replays.active.iter().position(|replay| replay.id == id) {
                Some(index) => {
                    let mut replay = replays.active.swap_remove(index);
                    let position = replay.source.position();
                    replay.sink.finish(position, false);
                    Ok(position)
                }
                None => Err(AgentError::Unknown { id }),
            };
            let _ = reply.send(result);
            false
        }
        Command::Shutdown(reply) => {
            for mut replay in replays.active.drain(..) {
                let position = replay.source.position();
                replay.sink.finish(position, false);
            }
            let mut first = Ok(());
            for recording in active.drain(..) {
                if let Err(error) = stop(recording, catalog, StopReason::Shutdown, now)
                    && first.is_ok()
                {
                    first = Err(error);
                }
            }
            let _ = reply.send(first);
            true
        }
    }
}

#[cfg(test)]
mod tests;

fn start_recording<D: Disk + Clone>(
    start: StartRecording,
    disk: &D,
    dir: &Path,
    config: &AgentConfig,
    catalog: &mut Catalog<D>,
    active: &mut Vec<Active<D>>,
    now: u64,
) -> Result<u64, AgentError> {
    let position = start.source.position();
    let id = catalog.start(NewRecording {
        stream_id: start.stream_id,
        session_id: start.session_id,
        channel: &start.channel,
        start: position,
        start_time_ns: now,
        geometry: start.geometry,
        policy: start.policy,
        format: start.format,
    })?;
    let store = SegmentStore::create(
        disk.clone(),
        dir,
        id,
        start.geometry,
        start.policy,
        position,
    )?;
    let recorder = Recorder::new(
        store,
        start.source,
        start.mode,
        config.buffer,
        config.budget,
    )?;
    active.push(Active { id, recorder });
    Ok(id)
}

/// Recording `id` and where it ends now.
fn describe<D: Disk>(
    id: u64,
    catalog: &Catalog<D>,
    active: &[Active<D>],
) -> Result<Described, AgentError> {
    let recording = catalog.get(id).ok_or(AgentError::Unknown { id })?.clone();
    let (end, incomplete) = match recording.stop {
        Some(stop) => (stop.position, stop.incomplete),
        None => active.iter().find(|active| active.id == id).map_or(
            (recording.start, false),
            |active| {
                (
                    active.recorder.store().written(),
                    active.recorder.incomplete(),
                )
            },
        ),
    };
    Ok(Described {
        recording,
        end,
        incomplete,
    })
}

/// Opens a replay's source and adds it to the running replays.
fn start_replay<D: Disk + Clone>(
    mut start: StartReplay,
    disk: &D,
    dir: &Path,
    config: &AgentConfig,
    catalog: &Catalog<D>,
    replays: &mut Replays<D>,
) -> Result<u64, AgentError> {
    let opened = catalog
        .get(start.recording_id)
        .ok_or(AgentError::Unknown {
            id: start.recording_id,
        })
        .and_then(|recording| {
            ReplaySource::open(
                disk.clone(),
                dir,
                recording.id,
                recording.geometry,
                start.from,
                start.to,
                start.rate,
                config.buffer,
            )
            .map_err(AgentError::from)
        });
    let source = match opened {
        Ok(source) => source,
        Err(error) => {
            start.sink.finish(start.from, false);
            return Err(error);
        }
    };
    let id = replays.next_id;
    replays.next_id += 1;
    replays.active.push(ActiveReplay {
        id,
        source,
        sink: start.sink,
    });
    Ok(id)
}
