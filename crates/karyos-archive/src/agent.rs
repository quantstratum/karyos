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
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::catalog::{Catalog, CatalogError, NewRecording, Recording};
use crate::disk::Disk;
use crate::recorder::{Ended, FrameSource, Mode, Recorder, RecorderError};
use crate::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};

/// The agent's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentConfig {
    /// Commands queued at most.
    pub command_capacity: usize,
    /// Events queued at most; a full queue drops the newest, counted.
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
    /// A recording failed; it stays open in the catalog until the next
    /// start settles it.
    Failed {
        /// The recording.
        id: u64,
        /// What failed.
        error: String,
    },
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
    /// The command queue is full.
    #[error("the agent is busy")]
    Busy,
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
    Shutdown(Reply<()>),
}

/// The host's handle on a running agent.
#[derive(Debug)]
pub struct ArchiveHandle {
    commands: SyncSender<Command>,
    events: Receiver<Event>,
    thread: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Start(start, _) => f.debug_tuple("Start").field(start).finish(),
            Self::Stop(id, _) => f.debug_tuple("Stop").field(id).finish(),
            Self::List(_) => f.write_str("List"),
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
        let thread = std::thread::Builder::new()
            .name("karyos-archive".to_owned())
            .spawn(move || run(disk, dir, config, &inbox, &outbox, &ready))?;
        match started.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                events,
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
        match self.commands.try_send(make(reply)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(AgentError::Busy),
            Err(TrySendError::Disconnected(_)) => return Err(AgentError::Gone),
        }
        answer.recv().map_err(|_| AgentError::Gone)?
    }

    /// Starts a recording of `start.source` from its position; returns its
    /// id once its `Started` is durable and its store exists.
    ///
    /// # Errors
    ///
    /// The catalog's and the store's errors, [`AgentError::Busy`] and
    /// [`AgentError::Gone`].
    pub fn start(&self, start: StartRecording) -> Result<u64, AgentError> {
        self.call(|reply| Command::Start(Box::new(start), reply))
    }

    /// Stops recording `id` where it is: its store is closed, then its
    /// `Stopped` is durable.
    ///
    /// # Errors
    ///
    /// [`AgentError::NotRecording`], the store's and the catalog's errors,
    /// [`AgentError::Busy`] and [`AgentError::Gone`].
    pub fn stop(&self, id: u64) -> Result<Ended, AgentError> {
        self.call(|reply| Command::Stop(id, reply))
    }

    /// The catalog's recordings, in id order.
    ///
    /// # Errors
    ///
    /// [`AgentError::Busy`] and [`AgentError::Gone`].
    pub fn recordings(&self) -> Result<Vec<Recording>, AgentError> {
        self.call(Command::List)
    }

    /// The next event, if any.
    #[must_use]
    pub fn try_event(&self) -> Option<Event> {
        self.events.try_recv().ok()
    }

    /// The next event, waiting up to `timeout`.
    #[must_use]
    pub fn event(&self, timeout: Duration) -> Option<Event> {
        self.events.recv_timeout(timeout).ok()
    }

    /// Stops every recording where it is and ends the agent's thread.
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

/// The agent's thread.
fn run<D>(
    disk: D,
    dir: PathBuf,
    config: AgentConfig,
    inbox: &Receiver<Command>,
    outbox: &SyncSender<Event>,
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
                now(),
            ) {
                return;
            }
        }
        let mut index = 0;
        while let Some(recording) = active.get_mut(index) {
            match recording.recorder.duty(now()) {
                Ok(duty) => {
                    worked |= duty.recorded > 0;
                    if duty.ended.is_some() {
                        let recording = active.swap_remove(index);
                        let event = finish(recording, &mut catalog, now());
                        let _ = outbox.try_send(event);
                        continue;
                    }
                }
                Err(error) => {
                    let recording = active.swap_remove(index);
                    let _ = outbox.try_send(Event::Failed {
                        id: recording.id,
                        error: error.to_string(),
                    });
                    continue;
                }
            }
            index = index.saturating_add(1);
        }
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

/// Closes an ended recording's store and stops it in the catalog.
fn finish<D: Disk>(recording: Active<D>, catalog: &mut Catalog<D>, now: u64) -> Event {
    let id = recording.id;
    match stop(recording, catalog, now) {
        Ok(ended) => Event::Ended { id, ended },
        Err(error) => Event::Failed {
            id,
            error: error.to_string(),
        },
    }
}

fn stop<D: Disk>(
    recording: Active<D>,
    catalog: &mut Catalog<D>,
    now: u64,
) -> Result<Ended, AgentError> {
    let id = recording.id;
    let ended = recording.recorder.close()?;
    catalog.stop(id, ended.position, now, ended.reason, ended.incomplete)?;
    Ok(ended)
}

/// Serves one command; `true` when it was the shutdown.
fn serve<D: Disk + Clone>(
    command: Command,
    disk: &D,
    dir: &Path,
    config: &AgentConfig,
    catalog: &mut Catalog<D>,
    active: &mut Vec<Active<D>>,
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
                Some(index) => stop(active.swap_remove(index), catalog, now),
                None => Err(AgentError::NotRecording { id }),
            };
            let _ = reply.send(result);
            false
        }
        Command::List(reply) => {
            let _ = reply.send(Ok(catalog.recordings().to_vec()));
            false
        }
        Command::Shutdown(reply) => {
            let mut first = Ok(());
            for recording in active.drain(..) {
                if let Err(error) = stop(recording, catalog, now)
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
