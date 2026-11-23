// SPDX-License-Identifier: Apache-2.0

//! The two ends of a replication (ADR-0091; quantstratum-docs:
//! karyos/design/archive-replication.md section 4; quantstratum/karyos#1072):
//! [`Sender`], the source's state for one request, which turns the stored
//! bytes and the range seals into the messages it sends, in order; and
//! [`Receiver`], the replica's, which stores what arrives without counting
//! it, and counts a range only once its seal verifies on the replica's own
//! bytes (ADR-0102 decision 5).
//! Either end is driven by its host's control streams.

use std::sync::mpsc::{Receiver as Returned, SyncSender, TryRecvError, sync_channel};

use crate::control::ResponseCode;
use crate::disk::Disk;
use crate::integrity::copies::CopyCatalog;
use crate::integrity::journal::IntegrityJournal;
use crate::integrity::replication::{Replica, ReplicationError, Verdict};
use crate::integrity::{SealKind, SealRecord};
use crate::segment::{SegmentError, SegmentStore};

use super::{
    MAX_CHUNK, Mode, ReplicateRecording, ReplicationStatus, RequestRefusal, State, check_request,
    check_seal,
};

/// A message the source sends, owned until the host encodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outgoing {
    /// Stored bytes at `start`.
    Bytes {
        /// Their position.
        start: u64,
        /// At most [`MAX_CHUNK`] of them.
        bytes: Chunk,
    },
    /// A range's seal, sent once its bytes were.
    Seal(SealRecord),
    /// The source's status.
    Status(ReplicationStatus),
}

/// How many chunk buffers a [`Sender`] keeps for reuse: the stream's
/// queue and one poll's chunks in flight fit, so a steady replication
/// takes every buffer back and allocates none (karyos#1113).
pub const CHUNK_POOL: usize = 256;

/// The bytes of one [`Outgoing::Bytes`]. A chunk a [`Sender`] made goes
/// back to it once dropped, for its next poll to fill again: a steady
/// replication allocates no buffer per chunk (karyos#1113).
pub struct Chunk {
    bytes: Vec<u8>,
    /// Where the buffer goes back to; `None` for a chunk no sender owns.
    home: Option<SyncSender<Vec<u8>>>,
}

impl Chunk {
    /// The bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for Chunk {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes, home: None }
    }
}

impl core::ops::Deref for Chunk {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        if let Some(home) = self.home.take() {
            // A full pool or a gone sender: the buffer is freed.
            let _ = home.try_send(core::mem::take(&mut self.bytes));
        }
    }
}

impl Clone for Chunk {
    fn clone(&self) -> Self {
        Self::from(self.bytes.clone())
    }
}

impl PartialEq for Chunk {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Chunk {}

impl core::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Chunk").field(&self.bytes).finish()
    }
}

/// Why a source refuses a request: the `ControlResponse` code to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The source holds no such recording: code 2, unknown recording.
    UnknownRecording,
    /// The request is off a seal boundary or below the start: code 4.
    Invalid(RequestRefusal),
}

impl Refusal {
    /// The `ControlResponse` code that answers it.
    #[must_use]
    pub const fn code(self) -> ResponseCode {
        match self {
            Self::UnknownRecording => ResponseCode::UnknownRecording,
            Self::Invalid(_) => ResponseCode::InvalidRequest,
        }
    }
}

/// The source's state for one request.
#[derive(Debug)]
pub struct Sender {
    request: ReplicateRecording,
    /// The next position to send.
    next: u64,
    /// The end of the last range sent whole with its seal.
    sent_end: u64,
    /// Set once a final status was produced: nothing more is sent.
    done: Option<State>,
    /// The request's first status, its start marker, was produced: it
    /// comes before any bytes (ADR-0102 decision 6).
    started: bool,
    /// The most bytes one [`Outgoing::Bytes`] carries, 1 to [`MAX_CHUNK`].
    chunk: usize,
    /// Where dropped chunks return their buffers, and where they are
    /// taken from again.
    give: SyncSender<Vec<u8>>,
    pool: Returned<Vec<u8>>,
    /// Chunk buffers made so far, at most [`CHUNK_POOL`]: past it a poll
    /// waits for one to come back rather than allocate another.
    made: usize,
}

impl Sender {
    /// Accepts `request` for a store starting at `start`, whose range seals
    /// are `seals`, or refuses it.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownRecording`] when `known` is false, and
    /// [`Refusal::Invalid`] for a request off a seal boundary or below the
    /// start. In continuous mode an `until` the seals do not reach yet is
    /// refused too: the note asks for an existing seal boundary.
    pub fn accept(
        request: ReplicateRecording,
        known: bool,
        start: u64,
        seals: &[SealRecord],
    ) -> Result<Self, Refusal> {
        if !known {
            return Err(Refusal::UnknownRecording);
        }
        check_request(&request, start, seals).map_err(Refusal::Invalid)?;
        let (give, pool) = sync_channel(CHUNK_POOL);
        Ok(Self {
            request,
            next: request.from,
            sent_end: request.from,
            done: None,
            started: false,
            chunk: MAX_CHUNK,
            give,
            pool,
            made: 0,
        })
    }

    /// Caps each [`Outgoing::Bytes`] at `chunk` bytes, clamped to 1 to
    /// [`MAX_CHUNK`], so each fits the stream that carries it.
    #[must_use]
    pub fn with_chunk(mut self, chunk: usize) -> Self {
        self.chunk = chunk.clamp(1, MAX_CHUNK);
        self
    }

    /// The request.
    #[must_use]
    pub const fn request(&self) -> &ReplicateRecording {
        &self.request
    }

    /// The end of the last range sent whole with its seal: the seals at
    /// or below it are not needed again.
    #[must_use]
    pub const fn sent_end(&self) -> u64 {
        self.sent_end
    }

    /// The final state, once reached; nothing more is sent after it.
    #[must_use]
    pub const fn done(&self) -> Option<State> {
        self.done
    }

    /// Stops it, after the replica's `StopReplication`.
    pub fn stop(&mut self, store: &SegmentStore<impl Disk>, sealed_end: u64) -> Outgoing {
        self.finish(State::Stopped, store, sealed_end)
    }

    /// Sends what is due, at most `budget` bytes of recording per call
    /// (none when it is 0), each chunk at most the sender's chunk, so nothing is buffered without bound: for
    /// each range seal that follows what was sent, its bytes in chunks
    /// then the seal, up to `until`. A range cut by the budget goes on at
    /// the next call. On demand, then a [`State::CaughtUp`] status; when
    /// the recording `stopped` and everything to its end was sent,
    /// [`State::Ended`]; a purge past the next position or a gap,
    /// [`State::Interrupted`].
    ///
    /// # Errors
    ///
    /// The store's read error; nothing after the failed read is sent.
    pub fn poll<D: Disk>(
        &mut self,
        store: &mut SegmentStore<D>,
        seals: &[SealRecord],
        stopped: bool,
        budget: usize,
        out: &mut Vec<Outgoing>,
    ) -> Result<(), SegmentError> {
        if self.done.is_some() {
            return Ok(());
        }
        let recording = self.request.recording_id;
        let sealed_end = sealed_end(seals, recording, store.start());
        // A purge past the next position interrupts the request first:
        // a start marker would advertise the purged start as the request's,
        // which the source would then read as an interior gap.
        if store.start() > self.next {
            out.push(self.finish(State::Interrupted, store, sealed_end));
            return Ok(());
        }
        // The start comes first: a `streaming` status, whose
        // `source_start` is where the request starts, before any bytes
        // (ADR-0102 decision 6).
        if !self.started {
            self.started = true;
            out.push(Outgoing::Status(self.report(
                State::Streaming,
                store,
                sealed_end,
            )));
        }
        let mut left = budget;
        let wanted = |seal: &SealRecord, sent_end: u64, until: u64| {
            seal.subject == recording
                && matches!(seal.kind, SealKind::OpenSegment | SealKind::ClosedSegment)
                && seal.end > sent_end
                && seal.end <= until
        };
        // The journal holds a recording's range seals in position order,
        // so one pass in that order sends them all: no rescan per range.
        // A seal met out of that order ends the pass, and the range that
        // starts first past what was sent decides, as before, whether it
        // follows or is a gap.
        let mut at = 0;
        loop {
            let next = seals
                .get(at..)
                .unwrap_or_default()
                .iter()
                .position(|seal| wanted(seal, self.sent_end, self.request.until));
            let seal = match next.and_then(|offset| at.checked_add(offset)) {
                Some(index)
                    if seals
                        .get(index)
                        .is_some_and(|seal| seal.start == self.sent_end) =>
                {
                    at = index;
                    seals.get(index).copied()
                }
                _ => seals
                    .iter()
                    .filter(|seal| wanted(seal, self.sent_end, self.request.until))
                    .min_by_key(|seal| seal.start)
                    .copied(),
            };
            let Some(seal) = seal else { break };
            if seal.start != self.sent_end {
                // A range that does not follow what was sent: a gap.
                out.push(self.finish(State::Interrupted, store, sealed_end));
                return Ok(());
            }
            while self.next < seal.end {
                if left == 0 {
                    return Ok(());
                }
                let chunk = self.chunk.min(left) as u64;
                let to = seal.end.min(self.next.saturating_add(chunk));
                let length = usize::try_from(to.saturating_sub(self.next))
                    .map_err(|_| SegmentError::PositionOverflow)?;
                // Every buffer is out: wait for one to come back.
                let Some(mut bytes) = self.buffer() else {
                    return Ok(());
                };
                bytes.resize(length, 0);
                // Back to the pool on a failed read too.
                let mut bytes = Chunk {
                    bytes,
                    home: Some(self.give.clone()),
                };
                store.read(self.next, &mut bytes.bytes)?;
                out.push(Outgoing::Bytes {
                    start: self.next,
                    bytes,
                });
                left = left.saturating_sub(length);
                self.next = to;
            }
            out.push(Outgoing::Seal(seal));
            self.sent_end = seal.end;
        }
        if self.sent_end == self.request.until {
            out.push(self.finish(State::CaughtUp, store, sealed_end));
        } else if stopped && self.sent_end == sealed_end && sealed_end == store.written() {
            out.push(self.finish(State::Ended, store, sealed_end));
        } else if self.request.mode == Mode::OnDemand {
            out.push(self.finish(State::CaughtUp, store, sealed_end));
        }
        Ok(())
    }

    /// A buffer a dropped chunk gave back, or a new one that holds a
    /// whole chunk while fewer than [`CHUNK_POOL`] were made, so filling it
    /// never grows it; `None` while every buffer is out.
    fn buffer(&mut self) -> Option<Vec<u8>> {
        match self.pool.try_recv() {
            Ok(mut bytes) => {
                bytes.clear();
                Some(bytes)
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) if self.made < CHUNK_POOL => {
                self.made = self.made.saturating_add(1);
                Some(Vec::with_capacity(self.chunk))
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }

    /// A status of the recording as the store holds it now.
    #[must_use]
    pub fn status(&self, store: &SegmentStore<impl Disk>, seals: &[SealRecord]) -> Outgoing {
        let sealed_end = sealed_end(seals, self.request.recording_id, store.start());
        Outgoing::Status(self.report(State::Streaming, store, sealed_end))
    }

    fn finish(
        &mut self,
        state: State,
        store: &SegmentStore<impl Disk>,
        sealed_end: u64,
    ) -> Outgoing {
        self.done = Some(state);
        // An interrupted request names the last range sent whole.
        let end = if state == State::Interrupted {
            self.sent_end
        } else {
            sealed_end
        };
        Outgoing::Status(self.report(state, store, end))
    }

    fn report(
        &self,
        state: State,
        store: &SegmentStore<impl Disk>,
        sealed_end: u64,
    ) -> ReplicationStatus {
        // The store's start as it is: after a purge an interrupted
        // status names it above the last range sent (ADR-0094).
        let written = store.written().max(sealed_end);
        let source_start = if state == State::Interrupted {
            store.start().min(written)
        } else {
            store.start().min(sealed_end)
        };
        ReplicationStatus {
            correlation_id: self.request.correlation_id,
            recording_id: self.request.recording_id,
            source_start,
            sealed_end,
            written,
            state,
        }
    }
}

/// Where `recording`'s range seals end, from `start`.
fn sealed_end(seals: &[SealRecord], recording: u64, start: u64) -> u64 {
    seals
        .iter()
        .filter(|seal| seal.subject == recording && seal.kind.is_range())
        .map(|seal| seal.end)
        .max()
        .unwrap_or(start)
        .max(start)
}

/// The longest range a replica checks against one seal: a seal covers at
/// most a segment, and no segment is longer (`Geometry::new`).
pub const MAX_SEALED_RANGE: u64 = 0xFFFF_FFFF;

/// What a replica refuses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiveError {
    /// Bytes for another recording than the request's.
    #[error("bytes of recording {got}, replicating {expected}")]
    OtherRecording {
        /// The request's recording.
        expected: u64,
        /// The message's.
        got: u64,
    },
    /// A seal of another kind or subject.
    #[error("a seal that does not cover this recording")]
    ForeignSeal,
    /// Bytes past the replica's tail: they would leave a hole the source
    /// has not sent (ADR-0102 decision 6). Dropped and counted as a gap.
    #[error("bytes at {start} past the replica's tail {tail}")]
    PastTail {
        /// The replica's written end.
        tail: u64,
        /// The bytes' start.
        start: u64,
    },
    /// A seal whose range the replica's store does not hold whole, or
    /// longer than [`MAX_SEALED_RANGE`]: refused before anything is read
    /// or allocated.
    #[error("seal of [{start}, {end}) outside the stored [{floor}, {tail}) or too long")]
    SealOutOfRange {
        /// The seal's start.
        start: u64,
        /// Its end.
        end: u64,
        /// The store's start.
        floor: u64,
        /// The store's written end.
        tail: u64,
    },
    /// Bytes below the replica's start, which it cannot compare.
    #[error("bytes at {start} below the replica's start {floor}")]
    BelowStart {
        /// The replica store's start.
        floor: u64,
        /// The bytes' start.
        start: u64,
    },
    /// Bytes that differ from the bytes the replica already stores at
    /// their positions: refused, and never written over them (ADR-0102
    /// decision 5).
    #[error("bytes at {start} differ from the stored bytes")]
    Mismatch {
        /// The bytes' start.
        start: u64,
    },
    /// The replica's store refused the bytes, or failed.
    #[error(transparent)]
    Store(#[from] SegmentError),
    /// The copy catalog or the integrity journal failed.
    #[error(transparent)]
    Replication(#[from] ReplicationError),
}

/// What the replica did with bytes it accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Arrival {
    /// Stored at the tail (some of them may have been held already).
    Stored,
    /// Every byte was already stored, identical: nothing written.
    AlreadyStored,
}

/// The replica's state for one recording it replicates.
#[derive(Debug)]
pub struct Receiver {
    recording_id: u64,
    replica: Replica,
}

impl Receiver {
    /// Receives `recording_id` as `replica`.
    #[must_use]
    pub const fn new(recording_id: u64, replica: Replica) -> Self {
        Self {
            recording_id,
            replica,
        }
    }

    /// Takes bytes that arrived at `start` into `store`, the replica's
    /// copy of the recording. Nothing is recorded in the copy catalog:
    /// only a seal that verifies changes it (ADR-0102 decision 5). Bytes
    /// at positions already stored are compared, not written; the rest
    /// is appended at the tail.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::OtherRecording`], [`ReceiveError::PastTail`],
    /// [`ReceiveError::BelowStart`] and [`ReceiveError::Mismatch`], which
    /// change nothing; the store's errors.
    pub fn bytes<D: Disk>(
        &self,
        recording_id: u64,
        start: u64,
        bytes: &[u8],
        store: &mut SegmentStore<D>,
    ) -> Result<Arrival, ReceiveError> {
        if recording_id != self.recording_id {
            return Err(ReceiveError::OtherRecording {
                expected: self.recording_id,
                got: recording_id,
            });
        }
        let tail = store.written();
        if start > tail {
            return Err(ReceiveError::PastTail { tail, start });
        }
        if start < store.start() {
            return Err(ReceiveError::BelowStart {
                floor: store.start(),
                start,
            });
        }
        let held = usize::try_from(tail.saturating_sub(start))
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let (stored, fresh) = bytes.split_at_checked(held).unwrap_or((bytes, &[]));
        if !stored.is_empty() {
            let mut buf = [0u8; MAX_CHUNK];
            let mut position = start;
            for chunk in stored.chunks(MAX_CHUNK) {
                let read = buf
                    .get_mut(..chunk.len())
                    .ok_or(ReceiveError::Mismatch { start })?;
                store.read(position, read)?;
                if read != chunk {
                    return Err(ReceiveError::Mismatch { start });
                }
                position = position
                    .checked_add(
                        u64::try_from(chunk.len()).map_err(|_| SegmentError::PositionOverflow)?,
                    )
                    .ok_or(SegmentError::PositionOverflow)?;
            }
        }
        if fresh.is_empty() {
            return Ok(Arrival::AlreadyStored);
        }
        let _ = store.append(tail, fresh)?;
        Ok(Arrival::Stored)
    }

    /// Checks `seal` on the replica's own bytes in `store` before
    /// anything is recorded: only a match counts the range, once; a
    /// mismatch records nothing and never downgrades a verified copy.
    ///
    /// # Errors
    ///
    /// [`ReceiveError::ForeignSeal`], [`ReceiveError::SealOutOfRange`],
    /// the store's read error, and the replica's.
    pub fn seal<D: Disk>(
        &self,
        seal: &SealRecord,
        store: &mut SegmentStore<D>,
        copies: &mut CopyCatalog<D>,
        journal: &mut IntegrityJournal<D>,
    ) -> Result<Verdict, ReceiveError> {
        check_seal(seal, self.recording_id).map_err(|_| ReceiveError::ForeignSeal)?;
        // Checked before anything is read or allocated: the range must be
        // whole in the store, and bounded.
        let (floor, tail) = (store.start(), store.written());
        let out_of_range = ReceiveError::SealOutOfRange {
            start: seal.start,
            end: seal.end,
            floor,
            tail,
        };
        let span = seal.end.checked_sub(seal.start).ok_or(out_of_range)?;
        if seal.start < floor || seal.end > tail || span > MAX_SEALED_RANGE {
            return Err(ReceiveError::SealOutOfRange {
                start: seal.start,
                end: seal.end,
                floor,
                tail,
            });
        }
        let length = usize::try_from(span).map_err(|_| SegmentError::PositionOverflow)?;
        let mut bytes = vec![0u8; length];
        store.read(seal.start, &mut bytes)?;
        Ok(self.replica.verify(copies, journal, seal, &bytes)?)
    }

    /// The replica this receiver records as.
    #[must_use]
    pub const fn replica(&self) -> &Replica {
        &self.replica
    }
}
