// SPDX-License-Identifier: Apache-2.0

//! The target stream of an Archive replay (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A5b; SPEC §8.2).
//!
//! A replay writes a recording back at its recorded positions, so a
//! subscriber reads the replay as it would have read the recorded stream,
//! and the live merge (A6) can match the two by position. The target is an
//! image: one lane in [`PublicationMode::Image`] with local gaps, joined at
//! the replay's first position, whose [`ReceiveOwner`] the replay holds as
//! a [`ReplayFeed`]. It is exposed as an aggregate of lane streams exactly
//! as a network image is (network-shared-terms n3), so subscribers, in
//! process or remote on an IPC driver, read it as any image:
//!
//! - data frames and PAD or ABORTED records as the log held them;
//! - a range the recording lost as a local gap record
//!   ([`GapReason::RangeUnavailable`]): on a replay target a local gap
//!   means "unavailable in the recording", and a reader sees it as
//!   `Skipped { LocalGap }`;
//! - the end as a seal: [`SealReason::EndOfStream`] when the replay
//!   reached its end, [`SealReason::ImageRetired`] otherwise
//!   ([`EmbeddedDriver::finish_replay`]).
//!
//! The feed runs on the replay's thread (the Archive's agent), as the
//! receiver role runs a network image's owner on its own; it drives the
//! owner's bounded cleaning itself, before each write. The driver keeps the
//! targets it made in a registry of its own, apart from the network's image
//! table (no admission, budget or alias logic applies to a replay).
//!
//! The target is keyed by `(stream_id, session_id)` like any stream: a key
//! in use (a local stream, an image, another replay) is refused, so a
//! caller picks a distinct session id per replay. A replay goes onto a new
//! stream (SPEC §8.2) as a new session: each frame's session id and stream
//! id (header bytes 12 to 15 and 16 to 19) are written as the target's,
//! and nothing else of it changes. The recorded ids stay in the catalog.
//!
//! Limitation: only a recording of lane 0 is replayed. Recorded frames
//! name their lane and a target has one lane, so another lane is refused
//! when the target is made ([`DriverError::ReplayLane`]); multi-lane
//! replay is later work.

use std::sync::Arc;

use karyos_sys::frame::{FRAME_ALIGNMENT, Lane};
use karyos_sys::local_gap::GapReason;
use karyos_sys::log_buffer::{
    DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig, PublicationMode, ReceiveError,
    ReceiveOwner, Received,
};
use karyos_sys::receive::{ImageParams, Item, ValidatedDatagram};
use karyos_sys::sizing::TermLength;
use karyos_sys::term::TermId;

use crate::agents::images::ImageTemplate;
use crate::embedded::{AggregateHandle, EmbeddedDriver, StreamTerms, sealed};
use crate::error::DriverError;
use karyos_protocol::cnc::CloseReason;

use crate::SealReason;

#[cfg(test)]
mod tests;

/// A replay target to make: the recorded stream's geometry, and where the
/// replay starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayTargetConfig {
    /// The target's stream id.
    pub stream_id: i32,
    /// The target's session id: distinct from every stream of the driver.
    pub session_id: i32,
    /// The recording's term length.
    pub term_length: u32,
    /// The recorded stream's initial term id, so positions map to the
    /// recorded terms.
    pub initial_term_id: i32,
    /// The largest frame the recording holds, at most; frames are written
    /// one per datagram of this size.
    pub mtu: u32,
    /// The replay's first position: a frame boundary of the recording.
    pub join: u64,
    /// The recorded lane: only lane 0 is replayed in A5.
    pub lane: Lane,
}

/// Why a write into a replay target failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayFeedError {
    /// The bytes are not whole, valid frames of the target.
    #[error("invalid replay frames at {position}: {reason}")]
    Invalid {
        /// Where.
        position: u64,
        /// Why.
        reason: String,
    },
    /// The image refused them: they differ from what it holds, or its
    /// shared state is corrupt.
    #[error(transparent)]
    Receive(#[from] ReceiveError),
}

/// The writer of a replay target: the image's receive owner, its only
/// writer. The feed owns it and drives its bounded cleaning itself, before
/// each write, on whatever thread runs the replay; nothing else, the driver
/// included, may drive that owner. The driver keeps only the target's
/// registration, for [`EmbeddedDriver::finish_replay`].
#[derive(Debug)]
pub struct ReplayFeed<T: StreamTerms> {
    owner: ReceiveOwner<T>,
    params: ImageParams,
    term_length: u64,
    /// One frame, its ids rewritten: allocated once, of the mtu.
    scratch: Vec<u8>,
    registration: u64,
    finished: bool,
}

/// The session id's offset in a frame header; the stream id follows it.
const SESSION_OFFSET: usize = 12;
/// The end of the stream id in a frame header.
const STREAM_END: usize = 20;

/// Whether one frame or record was taken.
enum Taken {
    /// Written, or already there.
    Yes,
    /// Its term is not ready; offer it again later.
    NotYet,
}

impl<T: StreamTerms> ReplayFeed<T> {
    /// Where the target is written up to: the end of its contiguous
    /// prefix.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.owner.rebuild_position(Lane::ZERO).unwrap_or(0)
    }

    /// Writes whole frames at `position`, as the log held them. `Ok(false)`
    /// when a term is not ready: the same frames are offered again later,
    /// and those already written are taken as duplicates.
    ///
    /// # Errors
    ///
    /// [`ReplayFeedError`] for frames that are not whole and valid, or that
    /// the image refuses.
    pub fn frames(&mut self, position: u64, bytes: &[u8]) -> Result<bool, ReplayFeedError> {
        self.owner.duty();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let at = position
                .checked_add(offset as u64)
                .ok_or_else(|| invalid(position, "position overflow"))?;
            let length = frame_extent(bytes, offset).ok_or_else(|| invalid(at, "bad frame"))?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid(at, "position overflow"))?;
            // The last frame of a run may omit its alignment padding.
            let frame = bytes
                .get(offset..end.min(bytes.len()))
                .ok_or_else(|| invalid(at, "bad frame"))?;
            if let Taken::NotYet = self.write(at, frame)? {
                return Ok(false);
            }
            offset = end;
        }
        Ok(true)
    }

    /// Writes a PAD or ABORTED record at `position`: one frame, whose
    /// header states the extent it covers. As [`ReplayFeed::frames`].
    ///
    /// # Errors
    ///
    /// As [`ReplayFeed::frames`].
    pub fn fill(
        &mut self,
        position: u64,
        record: &[u8],
        _extent: u32,
    ) -> Result<bool, ReplayFeedError> {
        self.frames(position, record)
    }

    /// Seals `[from, to)`, a range the recording lost, as local gap
    /// records, one per term it crosses. As [`ReplayFeed::frames`].
    ///
    /// # Errors
    ///
    /// As [`ReplayFeed::frames`].
    pub fn gap(&mut self, from: u64, to: u64) -> Result<bool, ReplayFeedError> {
        self.owner.duty();
        let mut at = from.max(self.position());
        while at < to {
            let term_end = at
                .checked_div(self.term_length)
                .and_then(|term| term.checked_add(1))
                .and_then(|term| term.checked_mul(self.term_length))
                .ok_or_else(|| invalid(at, "position overflow"))?;
            let end = term_end.min(to);
            let extent =
                u32::try_from(end.saturating_sub(at)).map_err(|_| invalid(at, "gap extent"))?;
            match self
                .owner
                .seal_gap(Lane::ZERO, at, extent, GapReason::RangeUnavailable)?
            {
                Received::Committed { .. } | Received::Duplicate => at = end,
                Received::NotReady | Received::Ahead => return Ok(false),
                Received::Late | Received::LateAfterSkip => {
                    return Err(invalid(at, "the gap lies below the target's join"));
                }
            }
        }
        Ok(true)
    }

    fn write(&mut self, position: u64, frame: &[u8]) -> Result<Taken, ReplayFeedError> {
        let copy = self
            .scratch
            .get_mut(..frame.len())
            .ok_or_else(|| invalid(position, "a frame larger than the mtu"))?;
        copy.copy_from_slice(frame);
        let ids = copy
            .get_mut(SESSION_OFFSET..STREAM_END)
            .ok_or_else(|| invalid(position, "a frame shorter than its header"))?;
        let (session, stream) = ids.split_at_mut(4);
        session.copy_from_slice(&self.params.session_id().to_le_bytes());
        stream.copy_from_slice(&self.params.stream_id().to_le_bytes());
        let frame = &*copy;
        let datagram = ValidatedDatagram::parse(frame, &self.params)
            .map_err(|error| invalid(position, &error.to_string()))?;
        for item in datagram.items() {
            let Item::Frame(frame) = item else {
                // A header-only frame carries nothing to write.
                continue;
            };
            match self.owner.receive(&frame)? {
                Received::Committed { .. } | Received::Duplicate => {}
                Received::NotReady | Received::Ahead => return Ok(Taken::NotYet),
                Received::Late | Received::LateAfterSkip => {
                    return Err(invalid(position, "the frame lies below the target's join"));
                }
            }
        }
        Ok(Taken::Yes)
    }
}

impl<T: StreamTerms> Drop for ReplayFeed<T> {
    fn drop(&mut self) {
        debug_assert!(
            self.finished || std::thread::panicking(),
            "a replay feed must end with EmbeddedDriver::finish_replay"
        );
    }
}

fn invalid(position: u64, reason: &str) -> ReplayFeedError {
    ReplayFeedError::Invalid {
        position,
        reason: reason.to_owned(),
    }
}

/// The aligned extent of the frame at `offset` of `bytes`, from its length
/// word.
fn frame_extent(bytes: &[u8], offset: usize) -> Option<usize> {
    let word = bytes.get(offset..offset.checked_add(4)?)?;
    let length = i32::from_le_bytes(word.try_into().ok()?);
    let length = usize::try_from(length).ok().filter(|length| *length > 0)?;
    let alignment = usize::try_from(FRAME_ALIGNMENT).ok()?;
    length.checked_next_multiple_of(alignment)
}

/// The replay targets a driver made, by the registration of their
/// aggregate.
#[derive(Debug, Default)]
pub(crate) struct ReplayTargets {
    registrations: Vec<u64>,
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Makes a replay target: a one-lane image joined at `config.join`,
    /// exposed as an aggregate of lane streams, and the feed that writes
    /// it.
    ///
    /// # Errors
    ///
    /// [`DriverError::ReplayLane`] for a lane other than 0,
    /// [`DriverError::InvalidConfig`] for a geometry an image cannot have,
    /// [`DriverError::DuplicateStream`] when the key is in use or the
    /// stream table is full, and the backing's errors (a region on an IPC
    /// driver).
    pub fn replay_target(
        &mut self,
        config: ReplayTargetConfig,
    ) -> Result<(AggregateHandle, ReplayFeed<T>), DriverError> {
        if config.lane != Lane::ZERO {
            return Err(DriverError::ReplayLane {
                lane: config.lane.get(),
            });
        }
        let term_length =
            TermLength::try_new(config.term_length).map_err(|_| DriverError::InvalidConfig)?;
        let params = ImageParams::new(
            config.session_id,
            config.stream_id,
            1,
            term_length,
            config.mtu,
        )
        .map_err(|_| DriverError::InvalidConfig)?;
        let template = ImageTemplate::default();
        let buffer = LogBufferConfig {
            term_length,
            spare_slots: template.spare_slots,
            max_subscribers: template.max_subscribers,
            mtu: config.mtu,
            max_reserved: term_length.get() / 8,
            initial_term_id: TermId::new(config.initial_term_id.cast_unsigned()),
            lane: Lane::ZERO,
            session_id: config.session_id,
            stream_id: config.stream_id,
            publication: PublicationMode::Image {
                join: config.join,
                local_gaps: true,
            },
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            schedule_capacity: 0,
        };
        LogBuffer::<T>::validate(&buffer).map_err(|_| DriverError::InvalidConfig)?;
        let lane = Arc::new(self.replay_lane(buffer)?);
        let owner = ReceiveOwner::new(params, vec![Arc::clone(&lane)])?;
        let handle = <T as sealed::Create>::expose_image(self, &[lane]).ok_or(
            DriverError::DuplicateStream {
                stream_id: config.stream_id,
                session_id: config.session_id,
            },
        )?;
        self.replays.registrations.push(handle.registration());
        let feed = ReplayFeed {
            owner,
            params,
            term_length: u64::from(term_length.get()),
            scratch: vec![0; usize::try_from(config.mtu).map_err(|_| DriverError::InvalidConfig)?],
            registration: handle.registration(),
            finished: false,
        };
        Ok((handle, feed))
    }

    /// Ends a replay at `end`: its target is sealed and retired, with
    /// [`SealReason::EndOfStream`] when the feed wrote it up to `end`, else
    /// [`SealReason::ImageRetired`]. Returns whether it was complete.
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownStream`] for a target this driver did not
    /// make, and the retire's errors.
    pub fn finish_replay(
        &mut self,
        handle: AggregateHandle,
        mut feed: ReplayFeed<T>,
        end: u64,
    ) -> Result<bool, DriverError> {
        feed.finished = true;
        let registration = feed.registration;
        let index = self
            .replays
            .registrations
            .iter()
            .position(|known| *known == registration)
            .filter(|_| handle.registration() == registration)
            .ok_or(DriverError::UnknownStream {
                stream: registration,
            })?;
        self.replays.registrations.swap_remove(index);
        let complete = feed.position() == end;
        let (seal, close) = if complete {
            (SealReason::EndOfStream, CloseReason::EndOfStream)
        } else {
            (SealReason::ImageRetired, CloseReason::ImageRetired)
        };
        // The owner goes first: nothing is written after the seal.
        drop(feed);
        let streams: Vec<_> = handle.streams().collect();
        for stream in streams {
            self.retire_lane_with(stream, seal, close)?;
        }
        Ok(complete)
    }

    /// An image lane for a replay target, on the driver's backing.
    fn replay_lane(&mut self, config: LogBufferConfig) -> Result<LogBuffer<T>, DriverError> {
        #[cfg(target_os = "linux")]
        let mut source = crate::embedded::lane_source(self.admission.as_mut());
        #[cfg(not(target_os = "linux"))]
        let mut source = crate::agents::images::LaneSource::heap();
        <T as sealed::Create>::image_lane(&mut source, config)
    }
}
