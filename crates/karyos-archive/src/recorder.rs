// SPDX-License-Identifier: Apache-2.0

//! The recorder of one stream lane (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A4; SPEC §8.1, ADR-0023).
//!
//! A [`Recorder`] copies a lane's committed frames, as the log holds them,
//! from a [`FrameSource`] into its recording's [`SegmentStore`]: data as
//! data, a padding or aborted block as a fill, and a lost range as a gap.
//!
//! - **Required.** The source is a required participant of the
//!   publication: it bounds the publisher and is never lapped, so a disk
//!   that stalls the recorder throttles the publisher (SPEC §8.1). That is
//!   the mode's promise, not a fault.
//! - **Async.** The source is an optional participant: the publisher may
//!   lap it. The lost range is recorded as a gap, and the recording then
//!   stops there ([`OnLap::Stop`]) or resumes at the source's lowest
//!   retained position ([`OnLap::Resume`]), marked incomplete.
//! - **Consumption.** The recorder tells the source what it consumed once
//!   it is written to the store (not yet durable): durability follows the
//!   store's policy, a separate axis (ADR-0023).

#[cfg(test)]
mod tests;

use crate::catalog::{FailKind, StopReason};
use crate::disk::Disk;
use crate::segment::{FILL_RECORD, SegmentError, SegmentStore};

/// What a [`FrameSource`] read produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frames {
    /// Whole committed frames, `len` bytes from `position`, copied into
    /// the read's buffer; the next read starts at `next`.
    Copied {
        /// Where they start.
        position: u64,
        /// Their bytes.
        len: usize,
        /// The position after them.
        next: u64,
    },
    /// A padding or aborted block at `position`: its canonical record is
    /// the first [`FILL_RECORD`] bytes of the buffer, and the block ends at
    /// `next`.
    Fill {
        /// Where it starts.
        position: u64,
        /// Where it ends.
        next: u64,
    },
    /// Nothing is committed at the position yet.
    Pending,
    /// The publication is sealed at `at`: nothing follows.
    Sealed {
        /// The seal position.
        at: u64,
    },
    /// The source was lapped: `[from, to)` is lost, and `to` is the lowest
    /// position still retained.
    Lost {
        /// The first lost position, the source's.
        from: u64,
        /// The lowest retained position.
        to: u64,
    },
}

/// Why a source cannot read on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// The source's participant was revoked.
    #[error("the source was revoked")]
    Revoked,
    /// The log under the source is corrupt at `position`.
    #[error("the log is corrupt at {position}")]
    Faulted {
        /// Where.
        position: u64,
    },
    /// The source broke its contract (a consumption it did not return, a
    /// buffer too small for a frame).
    #[error("the source broke its contract")]
    Invariant,
    /// The source cannot resume now; a later duty tries again.
    #[error("the source is busy")]
    Busy,
}

/// A lane's committed frames, read in position order.
pub trait FrameSource {
    /// Where the next read starts.
    fn position(&self) -> u64;

    /// Reads at [`FrameSource::position`] into `out`.
    ///
    /// # Errors
    ///
    /// [`SourceError`] when the source cannot read on.
    fn read(&mut self, out: &mut [u8]) -> Result<Frames, SourceError>;

    /// Everything before `position`, a `next` a read returned, is
    /// consumed: for a required source, the publisher may move past it.
    ///
    /// # Errors
    ///
    /// [`SourceError`] when the source cannot take it.
    fn consumed(&mut self, position: u64) -> Result<(), SourceError>;

    /// After a [`Frames::Lost`], reads on from `to`, its lowest retained
    /// position, or from a later block boundary (the head, for a lapped
    /// reader): returns where it resumed. [`SourceError::Busy`] asks to try
    /// again on a later duty.
    ///
    /// # Errors
    ///
    /// [`SourceError`] when the source cannot resume.
    fn resume(&mut self, to: u64) -> Result<u64, SourceError>;
}

/// What an async recording does when it is lapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnLap {
    /// It records the gap and stops there.
    Stop,
    /// It records the gap up to where the source resumes (the head, for a
    /// lapped reader; see [`FrameSource::resume`]) and records on from
    /// there.
    Resume,
}

/// A recording's mode (SPEC §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A required participant: never lapped; it throttles the publisher.
    Required,
    /// An optional participant: lapped, it does as `on_lap` says.
    Async {
        /// What a lap does.
        on_lap: OnLap,
    },
}

/// The recorder's errors.
#[derive(Debug, thiserror::Error)]
pub enum RecorderError {
    /// The store failed.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// The source failed.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// A required source reported a loss, which its role excludes.
    #[error("a required recording was lapped at [{from}, {to})")]
    RequiredLapped {
        /// The first lost position.
        from: u64,
        /// The lowest retained one.
        to: u64,
    },
    /// The source and the store disagree on the position.
    #[error("the source is at {source_position}, the store at {store}")]
    Misaligned {
        /// The source's position.
        source_position: u64,
        /// The store's written position.
        store: u64,
    },
    /// The source returned what a source never may.
    #[error("the source returned {0:?}")]
    Invalid(Invalid),
}

/// What a source returned that it never may.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// A seal away from the written position.
    SealNotAtWritten {
        /// The seal.
        at: u64,
        /// The written position.
        written: u64,
    },
    /// A copy of no bytes.
    EmptyCopy {
        /// Where.
        position: u64,
    },
    /// A loss of no range.
    EmptyLoss {
        /// Its start.
        from: u64,
        /// Its end, not above its start.
        to: u64,
    },
}

impl RecorderError {
    /// Why the source failed, when the store is still whole: the recording
    /// can then be closed and stopped with that reason. `None` for a store
    /// error, after which the store must be recovered.
    #[must_use]
    pub const fn fail_kind(&self) -> Option<FailKind> {
        match self {
            Self::Segment(_) => None,
            Self::Source(_) => Some(FailKind::Source),
            Self::RequiredLapped { .. } => Some(FailKind::RequiredLapped),
            Self::Misaligned { .. } | Self::Invalid(_) => Some(FailKind::Invalid),
        }
    }
}

/// Why a recording ended, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ended {
    /// Its last position.
    pub position: u64,
    /// Why: the seal (normal), a lap with `OnLap::Stop`, or how it was
    /// closed (a command, the shutdown, a source failure).
    pub reason: StopReason,
    /// Whether it lost a range.
    pub incomplete: bool,
}

/// What one duty did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Duty {
    /// Bytes of the stream recorded (data, fills and gaps).
    pub recorded: u64,
    /// The recording ended in this duty.
    pub ended: Option<Ended>,
}

/// The recorder of one stream lane into one recording.
#[derive(Debug)]
pub struct Recorder<D: Disk, S> {
    store: SegmentStore<D>,
    source: S,
    mode: Mode,
    buffer: Vec<u8>,
    budget: u64,
    incomplete: bool,
    ended: Option<Ended>,
    /// A lap recorded up to this position, whose resume is still to do.
    resume: Option<u64>,
}

impl<D: Disk, S: FrameSource> Recorder<D, S> {
    /// A recorder of `source` into `store`, whose written position must be
    /// the source's; each duty copies through a buffer of `buffer` bytes
    /// (at least the largest frame) and records at most `budget` bytes.
    ///
    /// # Errors
    ///
    /// [`RecorderError::Misaligned`] when the positions differ.
    pub fn new(
        store: SegmentStore<D>,
        source: S,
        mode: Mode,
        buffer: usize,
        budget: u64,
    ) -> Result<Self, RecorderError> {
        if store.written() != source.position() {
            return Err(RecorderError::Misaligned {
                source_position: source.position(),
                store: store.written(),
            });
        }
        Ok(Self {
            store,
            source,
            mode,
            buffer: vec![0; buffer.max(FILL_RECORD)],
            budget,
            incomplete: false,
            ended: None,
            resume: None,
        })
    }

    /// The store.
    #[must_use]
    pub const fn store(&self) -> &SegmentStore<D> {
        &self.store
    }

    /// The store, to read it back (tests).
    #[cfg(test)]
    pub(crate) fn store_mut(&mut self) -> &mut SegmentStore<D> {
        &mut self.store
    }

    /// Whether the recording ended.
    #[must_use]
    pub const fn ended(&self) -> Option<Ended> {
        self.ended
    }

    /// Records what the source has, up to the budget, then lets the store's
    /// policy sync at `now_ns`.
    ///
    /// # Errors
    ///
    /// The store's and the source's errors, and a lap of a required
    /// recording; the recording must then be stopped and recovered.
    pub fn duty(&mut self, now_ns: u64) -> Result<Duty, RecorderError> {
        let mut duty = Duty::default();
        if self.ended.is_some() {
            return Ok(duty);
        }
        let start = self.store.written();
        if let Some(to) = self.resume
            && !self.resume_after_lap(to)?
        {
            self.store.tick(now_ns)?;
            return Ok(duty);
        }
        while self.recorded_since(start)? < self.budget {
            match self.source.read(&mut self.buffer)? {
                Frames::Copied {
                    position,
                    len,
                    next,
                } => {
                    if len == 0 {
                        return Err(RecorderError::Invalid(Invalid::EmptyCopy { position }));
                    }
                    let bytes = self.buffer.get(..len).ok_or(SourceError::Invariant)?;
                    self.store.append(position, bytes)?;
                    self.source.consumed(next)?;
                }
                Frames::Fill { position, next } => {
                    let record: &[u8; FILL_RECORD] = self
                        .buffer
                        .get(..FILL_RECORD)
                        .and_then(|record| record.try_into().ok())
                        .ok_or(SourceError::Invariant)?;
                    let extent = next
                        .checked_sub(position)
                        .and_then(|extent| u32::try_from(extent).ok())
                        .ok_or(SourceError::Invariant)?;
                    self.store.append_fill(position, record, extent)?;
                    self.source.consumed(next)?;
                }
                Frames::Pending => break,
                Frames::Sealed { at } => {
                    let written = self.store.written();
                    if at != written {
                        return Err(RecorderError::Invalid(Invalid::SealNotAtWritten {
                            at,
                            written,
                        }));
                    }
                    duty.ended = Some(self.end(at, StopReason::Normal));
                    break;
                }
                Frames::Lost { from, to } => {
                    if to <= from {
                        return Err(RecorderError::Invalid(Invalid::EmptyLoss { from, to }));
                    }
                    let Mode::Async { on_lap } = self.mode else {
                        return Err(RecorderError::RequiredLapped { from, to });
                    };
                    // A store holding its most gaps ends the recording here,
                    // lapped, rather than lose count of what it lost.
                    if !self.store.gap_fits() {
                        self.incomplete = true;
                        duty.ended = Some(self.end(from, StopReason::Lapped));
                        break;
                    }
                    self.store.append_gap(from, to)?;
                    self.incomplete = true;
                    match on_lap {
                        OnLap::Stop => {
                            duty.ended = Some(self.end(to, StopReason::Lapped));
                            break;
                        }
                        OnLap::Resume => {
                            if !self.resume_after_lap(to)? {
                                break;
                            }
                        }
                    }
                }
            }
        }
        // Data, fills and gaps alike: the written position's advance.
        duty.recorded = self.recorded_since(start)?;
        self.store.tick(now_ns)?;
        Ok(duty)
    }

    /// Resumes the source after a lap recorded up to `to`: the range up to
    /// where it resumes is lost too (a lapped reader rejoins at the head).
    /// `false` when the source is busy: a later duty tries again.
    fn resume_after_lap(&mut self, to: u64) -> Result<bool, RecorderError> {
        match self.source.resume(to) {
            Ok(resumed) => {
                self.resume = None;
                if resumed > to {
                    self.store.append_gap(to, resumed)?;
                }
                Ok(true)
            }
            Err(SourceError::Busy) => {
                self.resume = Some(to);
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// The written position's advance since `start`.
    fn recorded_since(&self, start: u64) -> Result<u64, RecorderError> {
        Ok(self
            .store
            .written()
            .checked_sub(start)
            .ok_or(SegmentError::PositionOverflow)?)
    }

    fn end(&mut self, position: u64, reason: StopReason) -> Ended {
        let ended = Ended {
            position,
            reason,
            incomplete: self.incomplete,
        };
        self.ended = Some(ended);
        ended
    }

    /// Closes the store with everything written durable, whatever its
    /// policy, and returns where the recording ends: its durable position,
    /// with the reason it ended for, or `reason` when it had not ended (a
    /// command, the shutdown, a source failure). The catalog's stop names
    /// that position, so the segments always hold what it says.
    ///
    /// # Errors
    ///
    /// The store's errors.
    pub fn close(self, reason: StopReason) -> Result<Ended, RecorderError> {
        let reason = self.ended.map_or(reason, |ended| ended.reason);
        let incomplete = self.incomplete;
        let position = self.store.close_synced()?;
        Ok(Ended {
            position,
            reason,
            incomplete,
        })
    }
}
