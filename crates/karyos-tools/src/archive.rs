// SPDX-License-Identifier: Apache-2.0

//! The Archive's host over a driver (`quantstratum-docs:
//! karyos/design/archive-host.md`, H2): what touches the driver for the
//! Archive's control server, which karyos-archive may not do itself
//! (SPEC.md §14). [`DriverHost`] owns the driver, opens a recording
//! reader for each `StartRecording` and a replay target for each replay,
//! and finishes the replays that ended on the host's thread.
//!
//! A host's loop is the driver's duty, then the server's, then
//! [`DriverHost::finish_ended`]. A replay that ended keeps its target for
//! the host's replay linger before it is finished, which retires it. A
//! subscriber joins the target where it is when it attaches, so the sink
//! writes nothing until the target has its first reader (archive-host.md,
//! H2b): a requester that subscribes after the `Replay` answer attaches to
//! a target still empty and reads the replay from its first position. A
//! replay whose target has no reader by the agent's attach deadline ends
//! unattended, having written nothing, and its target retires at once.
//!
//! Any active local stream can be recorded, a replay target included: a
//! copy of a replay is legitimate. The recording's lease keeps the target
//! until the recording stops, and the replay's seal ends the recording, so
//! it never outlives the replay.
//!
//! At shutdown the server hands the host back
//! ([`ControlServer::shutdown_into_host`]), the host finishes what the
//! agent's stop ended ([`DriverHost::finish_all_ended`]), and
//! [`DriverHost::into_driver`] returns the driver for its own shutdown.
//!
//! [`ControlServer::shutdown_into_host`]: karyos_archive::server::ControlServer::shutdown_into_host

use std::num::NonZeroU32;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use karyos_archive::agent::{ReplaySink, SinkClosed};
use karyos_archive::catalog::{Recording, SourceIncarnation, StreamFormat};
use karyos_archive::control;
use karyos_archive::recorder::Mode;
use karyos_archive::server::{ArchiveHost, HostRecording, HostRefusal, replay_session_id};
use karyos_archive::source::Guarded;
use karyos_driver::embedded::{AggregateHandle, EmbeddedDriver, StreamTerms};
use karyos_driver::replay::{ReplayFeed, ReplayTargetConfig};
use karyos_protocol::cnc::StreamKey;
use karyos_sys::log_buffer::Role;

/// A replay that ended, for the host to finish on its thread.
struct Ended<T: StreamTerms> {
    handle: AggregateHandle,
    feed: ReplayFeed<T>,
    to: u64,
    /// The replay.
    id: u64,
    /// Its target had a reader and the replay wrote; one that never did
    /// is finished at once, without the linger.
    started: bool,
}

/// How long a replay that ended keeps its target by default: the
/// publication linger's interim value (owner item 16).
pub const DEFAULT_REPLAY_LINGER: Duration = Duration::from_secs(5);

/// The Archive's host over a driver: its recordings read the driver's
/// local streams, and its replays open targets on it.
pub struct DriverHost<T: StreamTerms> {
    driver: EmbeddedDriver<T>,
    ended: (Sender<Ended<T>>, Receiver<Ended<T>>),
    /// Replays that ended, each with when the host saw it, kept for the
    /// linger.
    lingering: Vec<(Ended<T>, Instant)>,
    linger: Duration,
    /// Replays that ended and whose finish the driver refused, counted.
    unfinished: u64,
}

impl<T: StreamTerms> core::fmt::Debug for DriverHost<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DriverHost")
            .field("unfinished", &self.unfinished)
            .finish_non_exhaustive()
    }
}

impl<T: StreamTerms> DriverHost<T> {
    /// A host over `driver`.
    #[must_use]
    pub fn new(driver: EmbeddedDriver<T>) -> Self {
        Self {
            driver,
            ended: channel(),
            lingering: Vec::new(),
            linger: DEFAULT_REPLAY_LINGER,
            unfinished: 0,
        }
    }

    /// The host with `linger` as its replay linger.
    #[must_use]
    pub const fn with_replay_linger(mut self, linger: Duration) -> Self {
        self.linger = linger;
        self
    }

    /// The driver.
    #[must_use]
    pub const fn driver(&self) -> &EmbeddedDriver<T> {
        &self.driver
    }

    /// The driver, to run its duty or add streams.
    pub const fn driver_mut(&mut self) -> &mut EmbeddedDriver<T> {
        &mut self.driver
    }

    /// Finishes the replays that ended at least the replay linger ago:
    /// each target seals at its replay's end, `EndOfStream` when it was
    /// written exactly up to it, else `ImageRetired` (a stopped replay),
    /// and retires. Returns how many it finished.
    pub fn finish_ended(&mut self) -> usize {
        self.finish_after(self.linger)
    }

    /// Finishes every replay that ended, at once: for a shutdown, after the
    /// server's agent stopped.
    pub fn finish_all_ended(&mut self) -> usize {
        self.finish_after(Duration::ZERO)
    }

    fn finish_after(&mut self, linger: Duration) -> usize {
        let now = Instant::now();
        while let Ok(ended) = self.ended.1.try_recv() {
            if ended.started {
                self.lingering.push((ended, now));
            } else {
                // Unattended: no reader by the attach deadline, nothing
                // written. Retired at once, so a reader racing the deadline
                // finds the target gone, or empty and retired, never part
                // of a replay (archive-host.md, H2b).
                tracing::warn!(
                    replay = ended.id,
                    "a replay's target had no reader by the attach deadline"
                );
                self.lingering
                    .push((ended, now.checked_sub(linger).unwrap_or(now)));
            }
        }
        let mut finished = 0usize;
        let mut kept = Vec::with_capacity(self.lingering.len());
        for (ended, since) in self.lingering.drain(..) {
            if now.saturating_duration_since(since) < linger {
                kept.push((ended, since));
                continue;
            }
            match self
                .driver
                .finish_replay(ended.handle, ended.feed, ended.to)
            {
                Ok(_) => finished = finished.saturating_add(1),
                Err(_) => self.unfinished = self.unfinished.saturating_add(1),
            }
        }
        self.lingering = kept;
        finished
    }

    /// Replays that ended and whose finish the driver refused (a handle it
    /// no longer knows, a feed past its end): a broken invariant, counted
    /// rather than panicking on the host's thread.
    #[must_use]
    pub const fn unfinished(&self) -> u64 {
        self.unfinished
    }

    /// The driver back, for its own shutdown, once the server is stopped
    /// and [`DriverHost::finish_all_ended`] has run.
    #[must_use]
    pub fn into_driver(self) -> EmbeddedDriver<T> {
        self.driver
    }
}

/// A refusal carrying `error`'s text.
fn refused(error: &impl core::fmt::Display) -> HostRefusal {
    HostRefusal(error.to_string())
}

impl<T: StreamTerms + 'static> ArchiveHost for DriverHost<T>
where
    karyos_driver::agents::data::LaneReader<T>: karyos_archive::recorder::FrameSource + Send,
    ReplayFeed<T>: Send,
{
    fn open_recording(
        &mut self,
        request: &control::StartRecording<'_>,
    ) -> Result<HostRecording, HostRefusal> {
        let stream = self
            .driver
            .stream_handle(StreamKey {
                stream_id: request.stream_id,
                session_id: request.session_id,
            })
            .ok_or_else(|| HostRefusal("no such stream".to_owned()))?;
        // The source's incarnation, from the driver's identity of the
        // stream recorded.
        let identity = self
            .driver
            .trace_identity(stream)
            .map_err(|e| refused(&e))?;
        // An async recording reads as an optional participant, which never
        // bounds the publisher.
        let role = match request.mode {
            Mode::Required => Role::Required,
            Mode::Async { .. } => Role::Optional,
        };
        let recording = self
            .driver
            .recording_reader(stream, role)
            .map_err(|e| refused(&e))?;
        let format = recording.format();
        let mtu =
            NonZeroU32::new(format.mtu).ok_or_else(|| HostRefusal("an mtu of 0".to_owned()))?;
        let (reader, lease) = recording.into_parts();
        Ok(HostRecording::new(
            Box::new(Guarded::new(reader, lease)),
            format.term_length,
            StreamFormat {
                lane: format.lane,
                initial_term_id: format.initial_term_id,
                mtu,
                source: SourceIncarnation {
                    driver: identity.driver,
                    registration: identity.registration,
                    incarnation: identity.incarnation,
                },
            },
        ))
    }

    fn open_replay(
        &mut self,
        request: &control::Replay<'_>,
        recording: &Recording,
        replay_id: u64,
        from: u64,
        to: u64,
    ) -> Result<Box<dyn ReplaySink + Send>, HostRefusal> {
        // The target is an ordinary stream of this driver, at the
        // requester's stream id and the replay's session id, which any
        // client then subscribes to (archive-control-codec.md section 4.1).
        let (handle, feed) = self
            .driver
            .replay_target(ReplayTargetConfig {
                stream_id: request.target_stream_id,
                session_id: replay_session_id(replay_id),
                term_length: recording.geometry.term_length(),
                initial_term_id: recording.format.initial_term_id,
                mtu: recording.format.mtu.get(),
                join: from,
                lane: recording.format.lane,
                source_stream_id: recording.stream_id,
                source_session_id: recording.session_id,
            })
            .map_err(|e| refused(&e))?;
        Ok(Box::new(Sink {
            feed: Some(feed),
            handle,
            to,
            id: replay_id,
            started: false,
            ended: self.ended.0.clone(),
        }))
    }
}

/// A replay's sink on the agent's thread: the target's feed, handed back
/// to the host at the end.
struct Sink<T: StreamTerms> {
    feed: Option<ReplayFeed<T>>,
    handle: AggregateHandle,
    to: u64,
    id: u64,
    /// The target had its first reader: the replay writes from then on.
    started: bool,
    ended: Sender<Ended<T>>,
}

impl<T: StreamTerms> Sink<T> {
    fn feed(&mut self) -> Result<&mut ReplayFeed<T>, SinkClosed> {
        self.feed.as_mut().ok_or(SinkClosed)
    }
}

impl<T: StreamTerms> ReplaySink for Sink<T>
where
    ReplayFeed<T>: Send,
{
    fn frames(&mut self, position: u64, bytes: &[u8]) -> Result<bool, SinkClosed> {
        self.feed()?.frames(position, bytes).map_err(|_| SinkClosed)
    }

    fn fill(&mut self, position: u64, record: &[u8], extent: u32) -> Result<bool, SinkClosed> {
        self.feed()?
            .fill(position, record, extent)
            .map_err(|_| SinkClosed)
    }

    fn gap(&mut self, from: u64, to: u64) -> Result<bool, SinkClosed> {
        self.feed()?.gap(from, to).map_err(|_| SinkClosed)
    }

    /// The feed goes back to the host, which finishes the replay at its
    /// requested end: a replay that stopped short seals `ImageRetired`, so
    /// its readers see it incomplete.
    fn finish(&mut self, _end: u64, _complete: bool) {
        if let Some(feed) = self.feed.take() {
            let _ = self.ended.send(Ended {
                handle: self.handle,
                feed,
                to: self.to,
                id: self.id,
                started: self.started,
            });
        }
    }

    /// Ready once the target has its first reader, which then joins at the
    /// replay's first position and reads it all; the agent holds the
    /// replay until then, up to its attach deadline (archive-host.md,
    /// H2b).
    fn ready(&mut self) -> bool {
        self.started = self.feed.as_ref().is_some_and(ReplayFeed::has_subscriber);
        self.started
    }
}

#[cfg(test)]
mod tests;
