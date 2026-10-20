// SPDX-License-Identifier: Apache-2.0

//! The operations journal of the agent's guard operations (quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M10 and owner item 7,
//! interim): an Archive recording in the agent's journal directory, written
//! through the Archive's [`Recorder`] from a [`QueueSource`], and shown as
//! unsealed until A10 seals it.
//!
//! - **One recording.** The directory's catalog holds the journal as one
//!   `required` recording on channel [`CHANNEL`]. The agent resumes the open
//!   one at start (recovering its store), or starts one when there is none.
//! - **Records.** Each operation is a request record before it is sent and
//!   an outcome record after it ([`Kind`]); each is one DATA frame
//!   ([`JournalRecord::encode`]).
//! - **Failure.** An append that fails leaves the journal unavailable until
//!   the agent restarts, and counts in [`Journal::failed_appends`]. A close
//!   goes ahead without its record (failing toward safety); a reopen needs
//!   its request durable first ([`Journal::append_durable`]) and is refused
//!   otherwise (failing closed).
//! - **Unknown interval.** At start, a request with no outcome after it, or
//!   a tail recovery cut, means an operation may have taken effect without
//!   its record: the agent appends a [`Kind::UnknownInterval`] from the last
//!   record's time to now. The latest unknown interval stays open
//!   ([`Journal::gap`]), across restarts, until an administrator
//!   acknowledges it with a [`Kind::GapAcknowledged`] record naming it.

#[cfg(test)]
mod tests;

use std::path::Path;

use karyos_archive::catalog::{
    Catalog, CatalogError, NewRecording, SourceIncarnation, StreamFormat,
};
use karyos_archive::disk::StdDisk;
use karyos_archive::queue::{QueueConfig, QueueError, QueueSource};
use karyos_archive::recorder::{Mode, Recorder, RecorderError};
use karyos_archive::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};
use karyos_sys::frame::{FRAME_ALIGNMENT, FrameType, HEADER_LENGTH, Lane, Word0};

/// The journal recording's channel.
pub const CHANNEL: &[u8] = b"karyos:operations-journal";
/// The journal's term length: one record never comes near it.
const TERM_LENGTH: u32 = karyos_sys::sizing::MIN_TERM_LENGTH;
/// The longest reason a record keeps, in bytes.
pub const MAX_REASON: usize = 128;
/// The record layout's version.
const VERSION: u64 = 1;
/// The fixed words of a record before its reason.
const WORDS: usize = 11;
/// Bytes queued at most before the recorder takes them.
const MAX_QUEUED: u64 = 1 << 20;
/// The journal's largest frame: a term.
const MTU: core::num::NonZeroU32 = match core::num::NonZeroU32::new(TERM_LENGTH) {
    Some(mtu) => mtu,
    None => core::num::NonZeroU32::MIN,
};

/// What a record says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A guard close, before it is sent.
    CloseRequest,
    /// What the close did.
    CloseOutcome,
    /// A guard reopen, before it is sent.
    ReopenRequest,
    /// What the reopen did.
    ReopenOutcome,
    /// Operations may have taken effect without their records between
    /// `expected` (the last record's time) and `time`.
    UnknownInterval,
    /// An administrator acknowledged the unknown interval recorded at
    /// position `expected`.
    GapAcknowledged,
}

impl Kind {
    const fn code(self) -> u64 {
        match self {
            Self::CloseRequest => 1,
            Self::CloseOutcome => 2,
            Self::ReopenRequest => 3,
            Self::ReopenOutcome => 4,
            Self::UnknownInterval => 5,
            Self::GapAcknowledged => 6,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::CloseRequest,
            2 => Self::CloseOutcome,
            3 => Self::ReopenRequest,
            4 => Self::ReopenOutcome,
            5 => Self::UnknownInterval,
            6 => Self::GapAcknowledged,
            _ => return None,
        })
    }

    const fn is_request(self) -> bool {
        matches!(self, Self::CloseRequest | Self::ReopenRequest)
    }
}

/// One journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalRecord {
    /// What it says.
    pub kind: Kind,
    /// Host `CLOCK_MONOTONIC` nanoseconds.
    pub time: u64,
    /// The guard id; 0 for an unknown interval or an acknowledgement.
    pub guard: u64,
    /// The epoch a reopen expects; the interval's start for an unknown
    /// interval; the acknowledged interval's position for an
    /// acknowledgement; else 0.
    pub expected: u64,
    /// The operation id.
    pub operation: u64,
    /// The operator's uid (the administrator's, for an acknowledgement).
    pub operator: u64,
    /// The command's parameters digest.
    pub parameters: u64,
    /// An outcome's control error code, 0 when it succeeded or for a
    /// request.
    pub code: u64,
    /// An outcome's guard word after it, else 0.
    pub word: u64,
    /// The operator's reason, at most [`MAX_REASON`] bytes.
    pub reason: Vec<u8>,
}

impl JournalRecord {
    /// A record of `kind` at `time`, every other field zero.
    #[must_use]
    pub const fn new(kind: Kind, time: u64) -> Self {
        Self {
            kind,
            time,
            guard: 0,
            expected: 0,
            operation: 0,
            operator: 0,
            parameters: 0,
            code: 0,
            word: 0,
            reason: Vec::new(),
        }
    }

    /// The record's payload: [`WORDS`] little-endian words (the layout's
    /// version, the kind, then the fields in declaration order, then the
    /// reason's length) and the reason, cut to [`MAX_REASON`] bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let reason = self.reason.get(..MAX_REASON).unwrap_or(&self.reason);
        let words = [
            VERSION,
            self.kind.code(),
            self.time,
            self.guard,
            self.expected,
            self.operation,
            self.operator,
            self.parameters,
            self.code,
            self.word,
            u64::try_from(reason.len()).unwrap_or(0),
        ];
        let mut out: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        out.extend_from_slice(reason);
        out
    }

    /// The record of `payload`, if it is one of this layout.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let word = |index: usize| -> Option<u64> {
            let start = index.checked_mul(8)?;
            let bytes = payload.get(start..start.checked_add(8)?)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        };
        if word(0)? != VERSION {
            return None;
        }
        let length = usize::try_from(word(10)?).ok()?;
        let start = WORDS.checked_mul(8)?;
        let reason = payload.get(start..start.checked_add(length)?)?;
        Some(Self {
            kind: Kind::from_code(word(1)?)?,
            time: word(2)?,
            guard: word(3)?,
            expected: word(4)?,
            operation: word(5)?,
            operator: word(6)?,
            parameters: word(7)?,
            code: word(8)?,
            word: word(9)?,
            reason: reason.to_vec(),
        })
    }
}

/// An unknown interval no administrator has acknowledged yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Gap {
    /// Its record's position in the journal.
    pub position: u64,
    /// The interval's start: the last record's time before it, 0 when
    /// none was readable.
    pub from: u64,
    /// The interval's end: the start of the agent that recorded it.
    pub to: u64,
}

/// Why the journal could not open or append.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The catalog's error.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// The store's error.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// The recorder's error.
    #[error(transparent)]
    Recorder(#[from] RecorderError),
    /// The queue's refusal.
    #[error(transparent)]
    Queue(#[from] QueueError),
    /// An earlier append failed: the journal stays unavailable until the
    /// agent restarts.
    #[error("the journal is unavailable")]
    Unavailable,
    /// The record was written but did not become durable.
    #[error("the journal record is not durable")]
    NotDurable,
    /// No unknown interval is open, or another one is.
    #[error("no such unknown interval")]
    NoGap,
    /// The journal holds something that is not a frame at `position`.
    #[error("the journal is corrupt at {position}")]
    Corrupt {
        /// Where.
        position: u64,
    },
}

/// The operations journal (see the module).
#[derive(Debug)]
pub struct Journal {
    recorder: Option<Recorder<StdDisk, QueueSource>>,
    recording: u64,
    failed_appends: u64,
    gap: Option<Gap>,
}

impl Journal {
    /// Opens the journal in `dir` at host time `now`: resumes its open
    /// recording, or starts one, then records an unknown interval when the
    /// last run may have lost a record.
    ///
    /// # Errors
    ///
    /// [`JournalError`] when the directory's catalog or the recording
    /// cannot be opened, or the unknown interval cannot be recorded.
    pub fn open(dir: &Path, now: u64) -> Result<Self, JournalError> {
        let geometry = Geometry::with_default_length(TERM_LENGTH)?;
        let mut catalog = Catalog::open(StdDisk, dir)?.catalog;
        let open = catalog
            .recordings()
            .iter()
            .rev()
            .find(|recording| recording.channel == CHANNEL)
            .map(|recording| (recording.id, recording.stop.is_none(), recording.geometry));
        let (recording, store, cut, earlier) = match open {
            Some((id, true, geometry)) => {
                let recovered =
                    SegmentStore::recover(StdDisk, dir, id, geometry, SyncPolicy::PerSegment)?;
                (id, recovered.store, recovered.cut.is_some(), false)
            }
            // A stopped journal is not this agent's to resume: a new one
            // starts, and what happened between them is not known.
            stopped => {
                let id = catalog.start(new_recording(geometry, now))?;
                let store =
                    SegmentStore::create(StdDisk, dir, id, geometry, SyncPolicy::PerSegment, 0)?;
                (id, store, false, stopped.is_some())
            }
        };
        let mut store = store;
        let scan = scan(&mut store)?;
        let source = QueueSource::new(
            QueueConfig::new(store.geometry(), 0, 0, MAX_QUEUED),
            store.written(),
        )?;
        let buffer = usize::try_from(TERM_LENGTH).map_err(|_| QueueError::Exhausted)?;
        let recorder = Recorder::new(store, source, Mode::Required, buffer, MAX_QUEUED)?;
        let mut journal = Self {
            recorder: Some(recorder),
            recording,
            failed_appends: 0,
            gap: scan.gap,
        };
        let pending = scan
            .last
            .as_ref()
            .is_some_and(|last| last.kind.is_request());
        if cut || pending || earlier {
            let mut record = JournalRecord::new(Kind::UnknownInterval, now);
            record.expected = scan.last.map_or(0, |last| last.time);
            let position = journal.append_durable(&record, now)?;
            journal.gap = Some(Gap {
                position,
                from: record.expected,
                to: now,
            });
        }
        Ok(journal)
    }

    /// The journal recording's id in its directory's catalog.
    #[must_use]
    pub const fn recording(&self) -> u64 {
        self.recording
    }

    /// Appends that failed since the agent started.
    #[must_use]
    pub const fn failed_appends(&self) -> u64 {
        self.failed_appends
    }

    /// Whether an append failed: the journal then refuses every append.
    #[must_use]
    pub const fn unavailable(&self) -> bool {
        self.recorder.is_none()
    }

    /// The unknown interval not acknowledged yet, if any.
    #[must_use]
    pub const fn gap(&self) -> Option<Gap> {
        self.gap
    }

    /// Appends `record` at host time `now`, written to the store but not
    /// necessarily durable; returns its position.
    ///
    /// # Errors
    ///
    /// [`JournalError`]; the journal is then unavailable, and the failure
    /// counted.
    pub fn append(&mut self, record: &JournalRecord, now: u64) -> Result<u64, JournalError> {
        self.write(record, now, false)
    }

    /// Appends `record` at host time `now` and makes it durable before it
    /// returns its position.
    ///
    /// # Errors
    ///
    /// As [`Journal::append`], and [`JournalError::NotDurable`].
    pub fn append_durable(
        &mut self,
        record: &JournalRecord,
        now: u64,
    ) -> Result<u64, JournalError> {
        self.write(record, now, true)
    }

    /// Records administrator `uid`'s acknowledgement of the open unknown
    /// interval at `position`, durably, and closes it.
    ///
    /// # Errors
    ///
    /// [`JournalError::NoGap`] when that interval is not the open one, and
    /// as [`Journal::append_durable`].
    pub fn acknowledge_gap(
        &mut self,
        position: u64,
        uid: u64,
        now: u64,
    ) -> Result<(), JournalError> {
        if self.gap.map(|gap| gap.position) != Some(position) {
            return Err(JournalError::NoGap);
        }
        let mut record = JournalRecord::new(Kind::GapAcknowledged, now);
        record.expected = position;
        record.operator = uid;
        let _ = self.append_durable(&record, now)?;
        self.gap = None;
        Ok(())
    }

    fn write(
        &mut self,
        record: &JournalRecord,
        now: u64,
        durable: bool,
    ) -> Result<u64, JournalError> {
        let Some(recorder) = self.recorder.as_mut() else {
            self.count_failure();
            return Err(JournalError::Unavailable);
        };
        let result = (|| {
            let position = recorder.store().written();
            let end = recorder.source_mut().push(&record.encode())?;
            let _ = recorder.duty(now)?;
            if recorder.store().written() < end {
                return Err(JournalError::NotDurable);
            }
            if durable && recorder.sync()? < end {
                return Err(JournalError::NotDurable);
            }
            // A padding block may precede the frame: the record is where
            // its frame starts, the end less its aligned length.
            Ok(frame_start(end, record).unwrap_or(position))
        })();
        if result.is_err() {
            self.recorder = None;
            self.count_failure();
        }
        result
    }

    fn count_failure(&mut self) {
        // Checked: at its end the count keeps its value.
        if let Some(next) = self.failed_appends.checked_add(1) {
            self.failed_appends = next;
        }
    }
}

/// The catalog entry of a new journal recording.
fn new_recording(geometry: Geometry, now: u64) -> NewRecording<'static> {
    NewRecording {
        stream_id: 0,
        session_id: 0,
        channel: CHANNEL,
        start: 0,
        start_time_ns: now,
        geometry,
        policy: SyncPolicy::PerSegment,
        format: StreamFormat {
            lane: Lane::ZERO,
            initial_term_id: 0,
            mtu: MTU,
            source: SourceIncarnation {
                driver: [0, 0],
                registration: 0,
                incarnation: 0,
            },
        },
        required: true,
    }
}

/// Where the frame of `record` starts, given the position after it.
fn frame_start(end: u64, record: &JournalRecord) -> Option<u64> {
    let length = u64::try_from(record.encode().len())
        .ok()?
        .checked_add(u64::from(HEADER_LENGTH))?
        .checked_next_multiple_of(u64::from(FRAME_ALIGNMENT))?;
    end.checked_sub(length)
}

/// What a scan of the journal found.
#[derive(Debug, Default)]
struct Scan {
    /// The last record.
    last: Option<JournalRecord>,
    /// The latest unknown interval, unless an acknowledgement follows it.
    gap: Option<Gap>,
}

/// Reads every frame of `store`, oldest first.
fn scan(store: &mut SegmentStore<StdDisk>) -> Result<Scan, JournalError> {
    let mut found = Scan::default();
    let mut position = store.start();
    let mut header = [0u8; HEADER_LENGTH as usize];
    let mut payload = Vec::new();
    while position < store.written() {
        store.read(position, &mut header)?;
        let corrupt = JournalError::Corrupt { position };
        let word0 = header
            .get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .and_then(|raw| Word0::unpack(raw).ok())
            .ok_or(JournalError::Corrupt { position })?;
        let extent = if word0.frame_type_code() == FrameType::Pad.code() {
            header
                .get(24..32)
                .and_then(|bytes| bytes.try_into().ok())
                .map(i64::from_le_bytes)
                .and_then(|extent| u64::try_from(extent).ok())
                .ok_or(corrupt)?
        } else {
            let length = u32::try_from(word0.frame_length())
                .ok()
                .filter(|length| *length >= HEADER_LENGTH)
                .ok_or(JournalError::Corrupt { position })?;
            let body = usize::try_from(length.abs_diff(HEADER_LENGTH))
                .map_err(|_| JournalError::Corrupt { position })?;
            payload.resize(body, 0);
            let at = position
                .checked_add(u64::from(HEADER_LENGTH))
                .ok_or(JournalError::Corrupt { position })?;
            store.read(at, &mut payload)?;
            if let Some(record) = JournalRecord::decode(&payload) {
                match record.kind {
                    Kind::UnknownInterval => {
                        found.gap = Some(Gap {
                            position,
                            from: record.expected,
                            to: record.time,
                        });
                    }
                    Kind::GapAcknowledged
                        if found.gap.map(|gap| gap.position) == Some(record.expected) =>
                    {
                        found.gap = None;
                    }
                    _ => {}
                }
                found.last = Some(record);
            }
            u64::from(length)
                .checked_next_multiple_of(u64::from(FRAME_ALIGNMENT))
                .ok_or(JournalError::Corrupt { position })?
        };
        if extent == 0 {
            return Err(JournalError::Corrupt { position });
        }
        position = position
            .checked_add(extent)
            .ok_or(JournalError::Corrupt { position })?;
    }
    Ok(found)
}
