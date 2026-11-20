// SPDX-License-Identifier: Apache-2.0

//! `ReplayGateway`, the replay implementation of [`GroupGateway`]
//! (`quantstratum-docs: karyos/design/recording-group-replay.md`
//! sections 3 and 7).
//!
//! It presents a recovered journal's complete prefix, event by event, to
//! the handler, through [`ReplayEffects`]. It holds no driver, client or
//! socket: an event comes from the journal, and each call the handler
//! makes is checked against its recorded observation and answered from
//! it (section 6).
//!
//! What it cannot present it refuses with
//! [`GatewayError::NotReproducible`]: a gap, a payload not captured or
//! unavailable, and a source the configuration lacks. An incomplete event
//! runs with its recorded observations, checked as usual (a call past
//! them gets a neutral answer, since the capture stopped there), and
//! replay stops after it, not reproducible.
//!
//! A payload by reference is read from its recording through
//! [`super::reference::read_message`] (A5's replay source), when the
//! Gateway has the Archive that holds it; a recording that no longer
//! holds the frames leaves the payload unavailable. The configuration
//! can opt in to present a message whose payload replay cannot give as
//! `MessagePayload::Unavailable`, with its recorded length and extent.
//!
//! With a [`CaptureJournal`] it writes what the handler did (section 9):
//! each presented event's records as the handler matched them, which are
//! the recorded ones; at a divergence or an incomplete event, the records
//! matched so far and an end that says incomplete, where replay stops.

use karyos_sys::frame::Lane;
use std::path::PathBuf;

use super::effects::{Divergence as StateDivergence, DivergenceKind, ReplayEffects};
use super::reference::{Frames, Recording, read_message};
use super::{
    CaptureJournal, ReplayCursor, ReplayError, ReplayEvent, Step, Stop, allocate, compare_state,
};
use crate::crc32c::crc32c;
use crate::disk::Disk;
use crate::group::gateway::{
    ConflatedId, Dispatched, Event, GatewayError, GroupGateway, Handler, MessagePayload,
    SubscriptionId, TimerId,
};
use crate::group::journal::JournalError;
use crate::group::record::{CheckpointRecord, EndOutcome, EventEnd, GroupRecord, Payload};
use crate::segment::Geometry;

#[cfg(test)]
mod tests;

/// What a replay is configured with: the same sources and publications as
/// the capture, each by the integer id the handler names, as
/// `(stream_id, session_id)`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct GatewayConfig<'a> {
    /// By publication id.
    pub publications: &'a [(i32, i32)],
    /// By subscription id: each source by its stream, session and lane,
    /// as the live Gateway added it; each triple is named once.
    pub subscriptions: &'a [(i32, i32, Lane)],
    /// The streams of `subscriptions` that are network subscriptions: the
    /// entry of such a stream takes every session and lane, as the live
    /// source took every image, which was then its stream's only source.
    /// Each is named once in `subscriptions`.
    pub network: &'a [i32],
    /// By conflated view id.
    pub conflated: &'a [(i32, i32)],
    /// The largest claim the handler makes, for the scratch claim.
    pub max_claim: usize,
    /// The largest payload by reference, for the buffer it is read into.
    pub max_payload: usize,
    /// Present a message whose payload replay cannot give (not captured,
    /// unavailable, or by reference) as `MessagePayload::Unavailable`,
    /// with its recorded length and extent, for a handler
    /// that only counts or routes such messages (section 7). Off, such a
    /// message is not reproducible.
    pub present_unavailable: bool,
}

impl<'a> GatewayConfig<'a> {
    /// No publication, subscription or view, no claim or payload room,
    /// unavailable payloads not presented: each `with_*` sets one.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            publications: &[],
            subscriptions: &[],
            network: &[],
            conflated: &[],
            max_claim: 0,
            max_payload: 0,
            present_unavailable: false,
        }
    }

    /// The publications, by id.
    #[must_use]
    pub const fn with_publications(mut self, publications: &'a [(i32, i32)]) -> Self {
        self.publications = publications;
        self
    }

    /// The subscriptions, by id.
    #[must_use]
    pub const fn with_subscriptions(mut self, subscriptions: &'a [(i32, i32, Lane)]) -> Self {
        self.subscriptions = subscriptions;
        self
    }

    /// The network subscriptions' streams.
    #[must_use]
    pub const fn with_network(mut self, network: &'a [i32]) -> Self {
        self.network = network;
        self
    }

    /// The conflated views, by id.
    #[must_use]
    pub const fn with_conflated(mut self, conflated: &'a [(i32, i32)]) -> Self {
        self.conflated = conflated;
        self
    }

    /// The largest claim the handler makes.
    #[must_use]
    pub const fn with_max_claim(mut self, max_claim: usize) -> Self {
        self.max_claim = max_claim;
        self
    }

    /// The largest payload by reference.
    #[must_use]
    pub const fn with_max_payload(mut self, max_payload: usize) -> Self {
        self.max_payload = max_payload;
        self
    }

    /// Presents a payload replay cannot give as empty.
    #[must_use]
    pub const fn with_present_unavailable(mut self, present: bool) -> Self {
        self.present_unavailable = present;
        self
    }
}

impl Default for GatewayConfig<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// The Archive that holds the recordings payloads by reference name.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Archive<D: Disk> {
    /// Its disk.
    pub disk: D,
    /// Its directory.
    pub dir: PathBuf,
    /// The recordings it holds, as `(recording_id, geometry)`.
    pub recordings: Vec<(u64, Geometry)>,
}

impl<D: Disk> Archive<D> {
    /// The Archive on `disk` in `dir`, holding `recordings`.
    #[must_use]
    pub const fn new(disk: D, dir: PathBuf, recordings: Vec<(u64, Geometry)>) -> Self {
        Self {
            disk,
            dir,
            recordings,
        }
    }
}

/// The replay Gateway.
#[derive(Debug)]
pub struct ReplayGateway<D: Disk> {
    cursor: ReplayCursor<D>,
    publications: Vec<(i32, i32)>,
    subscriptions: Vec<(i32, i32, Lane)>,
    /// The network subscriptions' streams.
    network: Vec<i32>,
    conflated: Vec<(i32, i32)>,
    scratch: Vec<u8>,
    archive: Option<Archive<D>>,
    /// A payload by reference, read back.
    payload: Vec<u8>,
    present_unavailable: bool,
    /// Where what the handler did is written.
    capture: Option<CaptureJournal<D>>,
    /// The handler's state at a checkpoint, written for the compare.
    state: Vec<u8>,
    /// The recorded observations of the event last dispatched: a state
    /// divergence's index.
    observations: u32,
    /// Where replay stopped, returned again by every later dispatch.
    stopped: Option<Result<Dispatched, GatewayError>>,
    /// A restore may still come: no dispatch and no restore yet.
    restorable: bool,
}

impl<D: Disk> ReplayGateway<D> {
    /// A Gateway over `cursor`, configured by `config`, reading payloads
    /// by reference from `archive`. It allocates here, and nothing per
    /// event but a payload by reference's read.
    ///
    /// # Errors
    ///
    /// [`ReplayError::InvalidConfig`] for a table that names one stream
    /// and session twice (an event would be its first id's, silently),
    /// or a buffer that cannot be allocated.
    pub fn new(
        cursor: ReplayCursor<D>,
        config: &GatewayConfig<'_>,
        archive: Option<Archive<D>>,
    ) -> Result<Self, ReplayError> {
        fn copied<K: Copy + PartialEq>(table: &[K]) -> Result<Vec<K>, ReplayError> {
            let twice = table.iter().enumerate().any(|(index, key)| {
                table
                    .get(..index)
                    .is_some_and(|before| before.contains(key))
            });
            if twice {
                return Err(ReplayError::InvalidConfig);
            }
            let mut copy = allocate(table.len())?;
            copy.extend_from_slice(table);
            Ok(copy)
        }
        let zeroed = |length: usize| -> Result<Vec<u8>, ReplayError> {
            let mut bytes = allocate(length)?;
            bytes.resize(length, 0);
            Ok(bytes)
        };
        Ok(Self {
            cursor,
            publications: copied(config.publications)?,
            subscriptions: copied(config.subscriptions)?,
            network: {
                // Each network stream is one entry of the table.
                let once = config.network.iter().all(|stream| {
                    config
                        .subscriptions
                        .iter()
                        .filter(|(entry, ..)| entry == stream)
                        .count()
                        == 1
                });
                if !once {
                    return Err(ReplayError::InvalidConfig);
                }
                let mut network = allocate(config.network.len())?;
                network.extend_from_slice(config.network);
                network
            },
            conflated: copied(config.conflated)?,
            scratch: zeroed(config.max_claim)?,
            archive,
            payload: zeroed(config.max_payload)?,
            present_unavailable: config.present_unavailable,
            capture: None,
            state: Vec::new(),
            observations: 0,
            stopped: None,
            restorable: true,
        })
    }

    /// Compares the handler's state at each recorded checkpoint (A9-2):
    /// it writes it into a buffer of `max_state` bytes, allocated here.
    /// A recorded snapshot larger than the buffer (empty without this
    /// call) stops the replay with [`GatewayError::StateBuffer`].
    ///
    /// # Errors
    ///
    /// [`ReplayError::InvalidConfig`] for a buffer that cannot be
    /// allocated.
    pub fn with_state(mut self, max_state: usize) -> Result<Self, ReplayError> {
        let mut state = allocate(max_state)?;
        state.resize(max_state, 0);
        self.state = state;
        Ok(self)
    }

    /// The handler's state at `recorded`, compared, and the capture's
    /// record written: a difference, or no state, is a divergence of kind
    /// `state checkpoint`.
    fn check_state(
        &mut self,
        recorded: &CheckpointRecord,
        handler: &mut dyn Handler,
    ) -> Result<(), GatewayError> {
        let diverged = |found| {
            GatewayError::Diverged(
                StateDivergence {
                    group_seq: recorded.group_seq,
                    index: self.observations,
                    kind: DivergenceKind::StateCheckpoint {
                        recorded: (recorded.length, recorded.crc32c),
                        found,
                    },
                }
                .into(),
            )
        };
        // A recorded snapshot larger than the buffer is the replay's
        // configuration, not the handler's state.
        if usize::try_from(recorded.length).map_or(true, |length| length > self.state.len()) {
            return Err(GatewayError::StateBuffer {
                group_seq: recorded.group_seq,
                length: recorded.length,
            });
        }
        let state = handler
            .checkpoint(&mut self.state)
            .and_then(|length| self.state.get(..length));
        let Some(state) = state else {
            return Err(diverged(None));
        };
        let capture = compare_state(recorded, state)
            .map_err(|divergence| diverged(Some((divergence.length, divergence.crc32c))))?;
        if let Some(journal) = self.capture.as_mut()
            && journal.append(&GroupRecord::Checkpoint(capture)).is_err()
        {
            return Err(GatewayError::Ended);
        }
        Ok(())
    }

    /// Hands checkpoint `record`'s snapshot to the handler's `restore`,
    /// once, before the first dispatch of a replay from it (A9-2,
    /// `recording-group-checkpoints.md` section 6, whose
    /// `from_checkpoint` is [`ReplayCursor::open_at_checkpoint`] then
    /// this): `record` is the checkpoint the cursor was opened at, and
    /// `snapshot` its bytes.
    ///
    /// # Errors
    ///
    /// Without calling the handler: the stop of a gateway already
    /// stopped by an error; [`GatewayError::RestoreOrder`] after a
    /// dispatch (the stop of one stopped at its end is kept), for a
    /// second restore, or for a checkpoint the cursor was not opened at;
    /// [`GatewayError::CheckpointCorrupt`] for a snapshot whose length or
    /// crc32c differs from `record`. [`GatewayError::NotReproducible`] at
    /// the checkpoint's `group_seq` when the handler refuses the bytes.
    /// Replay stops at each, and each later dispatch returns the same.
    /// A replay opened at a checkpoint restores before its first
    /// dispatch: one without it returns [`GatewayError::RestoreOrder`]
    /// and stops.
    pub fn restore(
        &mut self,
        record: &CheckpointRecord,
        snapshot: &[u8],
        handler: &mut dyn Handler,
    ) -> Result<(), GatewayError> {
        let group_seq = record.group_seq;
        match self.stopped {
            Some(Err(stopped)) => return Err(stopped),
            // Stopped at its end: refused, the stop kept.
            Some(Ok(_)) => return Err(GatewayError::RestoreOrder { group_seq }),
            None => {}
        }
        let refused = if !std::mem::replace(&mut self.restorable, false)
            || self.cursor.opened_at() != Some(group_seq)
        {
            GatewayError::RestoreOrder { group_seq }
        } else if u64::try_from(snapshot.len()).ok() != Some(record.length)
            || crc32c(snapshot) != record.crc32c
        {
            GatewayError::CheckpointCorrupt { group_seq }
        } else if handler.restore(snapshot) {
            return Ok(());
        } else {
            GatewayError::NotReproducible { group_seq }
        };
        self.stopped = Some(Err(refused));
        Err(refused)
    }

    /// Writes what the handler does to `capture` (section 9): a journal
    /// created with the recorded header and the replaying caller's
    /// manifest.
    #[must_use]
    pub fn with_capture(mut self, capture: CaptureJournal<D>) -> Self {
        self.capture = Some(capture);
        self
    }

    /// The cursor and the capture, given back.
    #[must_use]
    pub fn into_parts(self) -> (ReplayCursor<D>, Option<CaptureJournal<D>>) {
        (self.cursor, self.capture)
    }

    fn stop(
        &mut self,
        result: Result<Dispatched, GatewayError>,
    ) -> Result<Dispatched, GatewayError> {
        self.stopped = Some(result);
        result
    }
}

/// The id of `(stream_id, session_id)` in `table`.
/// A subscription's id: its stream, session and lane, or its stream
/// alone for a network subscription's.
fn subscription_of(
    table: &[(i32, i32, Lane)],
    network: &[i32],
    stream_id: i32,
    session_id: i32,
    lane: Lane,
) -> Option<u16> {
    let at = |index: usize| u16::try_from(index).ok();
    if network.contains(&stream_id) {
        return table
            .iter()
            .position(|&(stream, ..)| stream == stream_id)
            .and_then(at);
    }
    table
        .iter()
        .position(|&source| source == (stream_id, session_id, lane))
        .and_then(at)
}

fn id_of(table: &[(i32, i32)], stream_id: i32, session_id: i32) -> Option<u16> {
    table
        .iter()
        .position(|&source| source == (stream_id, session_id))
        .and_then(|index| u16::try_from(index).ok())
}

/// Writes `event` to `capture`: whole when the handler matched it all,
/// else its first record, its first `matched` observations and an end
/// that says incomplete.
fn capture_event<D: Disk>(
    capture: &mut CaptureJournal<D>,
    event: &ReplayEvent<'_>,
    matched: u32,
    whole: bool,
) -> Result<(), JournalError> {
    let kept = if whole {
        event.len()
    } else {
        usize::try_from(matched)
            .ok()
            .and_then(|matched| matched.checked_add(1))
            .ok_or(JournalError::InvalidConfig)?
    };
    for record in event.records().take(kept) {
        let _ = capture.append(&record?)?;
    }
    if !whole {
        let _ = capture.append(&GroupRecord::End(EventEnd {
            group_seq: event.group_seq(),
            observations: matched,
            outcome: EndOutcome::Incomplete,
        }))?;
    }
    Ok(())
}

/// Reads a payload by reference from `archive` into `out`.
fn by_reference<D: Disk + Clone>(
    archive: Option<&Archive<D>>,
    recording_id: u64,
    frames: Frames,
    out: &mut [u8],
) -> Option<usize> {
    let archive = archive?;
    let &(_, geometry) = archive
        .recordings
        .iter()
        .find(|(id, _)| *id == recording_id)?;
    let recording = Recording {
        dir: &archive.dir,
        recording_id,
        geometry,
    };
    read_message(archive.disk.clone(), &recording, frames, out)
}

impl<D: Disk + Clone> crate::group::gateway::sealed::Sealed for ReplayGateway<D> {}

impl<D: Disk + Clone> GroupGateway for ReplayGateway<D> {
    fn dispatch(&mut self, handler: &mut dyn Handler) -> Result<Dispatched, GatewayError> {
        if let Some(stopped) = self.stopped {
            return stopped;
        }
        // Opened at a checkpoint, replay starts from its restored state:
        // never from the handler's empty one.
        if std::mem::replace(&mut self.restorable, false)
            && let Some(group_seq) = self.cursor.opened_at()
        {
            return self.stop(Err(GatewayError::RestoreOrder { group_seq }));
        }
        let event = match self.cursor.step() {
            Ok(Step::Event(event)) => event,
            // Never: an event's checkpoints are compared in its own
            // dispatch, and one opened at a checkpoint gives none before
            // its first event.
            Ok(Step::Checkpoint(_) | Step::LateCheckpoint(_)) => {
                return self.stop(Err(GatewayError::Ended));
            }
            Ok(Step::Stop(Stop::EndOfPrefix { .. })) => return self.stop(Ok(Dispatched::End)),
            Ok(Step::Stop(Stop::Gap(gap))) => {
                return self.stop(Err(GatewayError::NotReproducible {
                    group_seq: gap.from_seq,
                }));
            }
            Ok(Step::Stop(Stop::Incomplete { group_seq })) => {
                return self.stop(Err(GatewayError::NotReproducible { group_seq }));
            }
            // An event larger than the buffer, or a journal that does not
            // read as the recovery said: replay cannot go on.
            Err(_) => return self.stop(Err(GatewayError::Ended)),
        };
        let group_seq = event.group_seq();
        let incomplete = event.incomplete();
        // Records 1 to len - 2: the observations.
        let Some(observations) = event
            .len()
            .checked_sub(2)
            .and_then(|observations| u32::try_from(observations).ok())
        else {
            return self.stop(Err(GatewayError::Ended));
        };
        let not_reproducible = Err(GatewayError::NotReproducible { group_seq });
        let Some(Ok(first)) = event.record(0) else {
            return self.stop(Err(GatewayError::Ended));
        };
        let presented = match first {
            GroupRecord::Message(message) => {
                let read = match message.payload {
                    Payload::Reference {
                        recording_id,
                        length,
                    } if !event.reference_unavailable() => by_reference(
                        self.archive.as_ref(),
                        recording_id,
                        Frames {
                            position: message.position,
                            extent: message.extent,
                            length,
                        },
                        &mut self.payload,
                    ),
                    _ => None,
                };
                let length = match message.payload {
                    Payload::Inline(bytes) => u32::try_from(bytes.len()).ok(),
                    Payload::Reference { length, .. } | Payload::Unavailable { length } => {
                        Some(length)
                    }
                };
                let payload = match (message.payload, read) {
                    // Inline bytes are in the record itself: replay always has
                    // them, whatever names the event.
                    (Payload::Inline(bytes), _) => Some(MessagePayload::Bytes(bytes)),
                    (Payload::Reference { .. }, Some(length)) => {
                        self.payload.get(..length).map(MessagePayload::Bytes)
                    }
                    _ if self.present_unavailable => Some(MessagePayload::Unavailable),
                    _ => None,
                };
                match (
                    payload,
                    length,
                    subscription_of(
                        &self.subscriptions,
                        &self.network,
                        message.stream_id,
                        message.session_id,
                        message.lane,
                    ),
                ) {
                    (Some(payload), Some(length), Some(source)) => Some(Event::Message {
                        source: SubscriptionId(source),
                        lane: message.lane,
                        position: message.position,
                        extent: message.extent,
                        length,
                        reserved_value: message.reserved_value,
                        end_of_stream: message.end_of_stream,
                        extension: message.extension,
                        payload,
                        image: message.image,
                    }),
                    _ => None,
                }
            }
            GroupRecord::Conflated(view) => id_of(&self.conflated, view.stream_id, view.session_id)
                .map(|source| Event::Conflated {
                    source: ConflatedId(source),
                    key: view.key,
                    version: view.version,
                    freshness: view.freshness,
                    value: view.value,
                }),
            GroupRecord::Timer(timer) => {
                u16::try_from(timer.timer_id)
                    .ok()
                    .map(|timer| Event::Timer {
                        timer: TimerId(timer),
                    })
            }
            GroupRecord::Lifecycle(lifecycle) => subscription_of(
                &self.subscriptions,
                &self.network,
                lifecycle.stream_id,
                lifecycle.session_id,
                lifecycle.lane,
            )
            .map(|source| Event::Lifecycle {
                source: SubscriptionId(source),
                kind: lifecycle.kind,
                image: lifecycle.image,
            }),
            GroupRecord::External(external) => Some(Event::External {
                kind: external.kind,
                value: external.value,
            }),
            GroupRecord::Loss(loss) => subscription_of(
                &self.subscriptions,
                &self.network,
                loss.stream_id,
                loss.session_id,
                loss.lane,
            )
            .map(|source| Event::Loss {
                source: SubscriptionId(source),
                loss: loss.loss,
                from: loss.from,
                lost_to: loss.lost_to,
                resume: loss.resume,
                image: loss.image,
            }),
            _ => None,
        };
        let Some(presented) = presented else {
            return self.stop(not_reproducible);
        };
        let Ok(mut effects) = ReplayEffects::new(event, &self.publications, &mut self.scratch)
        else {
            return self.stop(Err(GatewayError::Ended));
        };
        handler.on_event(&presented, &mut effects);
        let matched = effects.matched();
        let finished = effects.finish();
        if let Some(capture) = self.capture.as_mut()
            && capture_event(capture, &event, matched, finished.is_ok() && !incomplete).is_err()
        {
            return self.stop(Err(GatewayError::Ended));
        }
        if let Err(divergence) = finished {
            return self.stop(Err(GatewayError::Diverged(divergence.into())));
        }
        // An incomplete event ran with its recorded observations; replay
        // cannot claim what the handler did past them.
        if incomplete {
            return self.stop(not_reproducible);
        }
        // The checkpoints of this event, in its own dispatch.
        self.observations = observations;
        loop {
            match self.cursor.due_checkpoint() {
                Ok(None) => break,
                Ok(Some(recorded)) => {
                    if let Err(error) = self.check_state(&recorded, handler) {
                        return self.stop(Err(error));
                    }
                }
                Err(_) => return self.stop(Err(GatewayError::Ended)),
            }
        }
        Ok(Dispatched::Event { group_seq })
    }

    fn deliver_external(
        &mut self,
        _kind: u32,
        _value: &[u8],
        _handler: &mut dyn Handler,
    ) -> Result<Dispatched, GatewayError> {
        Err(GatewayError::ExternalInReplay)
    }
}
