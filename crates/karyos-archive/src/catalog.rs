// SPDX-License-Identifier: Apache-2.0

//! The catalog of an archive directory (quantstratum-docs:
//! karyos/design/archive-gap-analysis.md, A3; SPEC §8.1, ADR-0023).
//!
//! - **Format.** `catalog.kyc` is a header, then an append-only log of
//!   records, each with its kind, length, payload and CRC-32C: a recording
//!   started, stopped or forgotten, and the id watermark.
//! - **Updates.** A record is durable (written, then synced) before the
//!   call returns; the caller acts after it: a recording's `Started` is
//!   durable before its segment store is created, and its store is closed
//!   before its `Stopped` is appended.
//! - **Ids.** The next id is the highest started plus one, never below the
//!   watermark a compaction writes (`NextId`), so an id is never reused,
//!   even once its recording is forgotten and compacted away.
//! - **Compaction.** The live records are written to `catalog.kyc.tmp`,
//!   synced, renamed over `catalog.kyc`, and the directory synced (Linux).
//!   A crash leaves the old catalog or the new one, never a mix: both hold
//!   the same recordings.
//! - **Recovery.** [`Catalog::open`] removes a leftover temporary file
//!   (its rename never happened), cuts the log at the first torn or
//!   inconsistent record and reports where. [`Catalog::settle`] then stops
//!   every recording a crash left open, at its recovered written position,
//!   with the reason recorded.

#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};

use crate::crc32c::crc32c;
use crate::disk::Disk;
use crate::segment::{Geometry, SegmentError, SegmentStore, SyncPolicy};

/// The catalog's file name in its directory.
pub const CATALOG: &str = "catalog.kyc";
/// A compaction's file, renamed over the catalog when it is complete.
const TEMPORARY: &str = "catalog.kyc.tmp";

/// "KYCT", the catalog magic.
const MAGIC: u32 = u32::from_le_bytes(*b"KYCT");
/// The catalog format version.
const VERSION: u32 = 1;
/// The header's length: magic, version, reserved, CRC.
const HEADER: usize = 16;
/// A record's head: kind and payload length.
const HEAD: usize = 4;
/// A record's tail: its CRC.
const TAIL: usize = 4;

/// The longest channel a recording names, in bytes.
pub const MAX_CHANNEL: usize = 1024;

const STARTED: u16 = 1;
const STOPPED: u16 = 2;
const NEXT_ID: u16 = 3;
const FORGOTTEN: u16 = 4;

/// Why a recording stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Its recorder stopped it.
    Normal,
    /// A crash left it open; recovery stopped it at its recovered written
    /// position.
    Recovered,
    /// A crash left it open before its segment store existed: it is empty.
    Empty,
}

impl StopReason {
    const fn code(self) -> u8 {
        match self {
            Self::Normal => 1,
            Self::Recovered => 2,
            Self::Empty => 3,
        }
    }

    const fn of(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Normal),
            2 => Some(Self::Recovered),
            3 => Some(Self::Empty),
            _ => None,
        }
    }
}

/// Where and when a recording stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stop {
    /// Its last position.
    pub position: u64,
    /// When, in nanoseconds of the caller's clock.
    pub time_ns: u64,
    /// Why.
    pub reason: StopReason,
}

/// A recording the catalog lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    /// Its id, never reused.
    pub id: u64,
    /// The recorded stream.
    pub stream_id: i32,
    /// The recorded session.
    pub session_id: i32,
    /// The channel, at most [`MAX_CHANNEL`] bytes.
    pub channel: Vec<u8>,
    /// Its first position.
    pub start: u64,
    /// When it started, in nanoseconds of the caller's clock.
    pub start_time_ns: u64,
    /// Its segment geometry.
    pub geometry: Geometry,
    /// Its sync policy.
    pub policy: SyncPolicy,
    /// Where it stopped; `None` while it records.
    pub stop: Option<Stop>,
}

/// A recording to start.
#[derive(Debug, Clone, Copy)]
pub struct NewRecording<'a> {
    /// The recorded stream.
    pub stream_id: i32,
    /// The recorded session.
    pub session_id: i32,
    /// The channel, at most [`MAX_CHANNEL`] bytes.
    pub channel: &'a [u8],
    /// Its first position.
    pub start: u64,
    /// When it starts.
    pub start_time_ns: u64,
    /// Its segment geometry.
    pub geometry: Geometry,
    /// Its sync policy.
    pub policy: SyncPolicy,
}

/// The catalog's errors.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// A channel longer than [`MAX_CHANNEL`].
    #[error("channel of {length} bytes, at most {MAX_CHANNEL}")]
    ChannelTooLong {
        /// Its length.
        length: usize,
    },
    /// No such recording.
    #[error("no recording {id}")]
    UnknownRecording {
        /// The id.
        id: u64,
    },
    /// The recording stopped already.
    #[error("recording {id} stopped already")]
    AlreadyStopped {
        /// The id.
        id: u64,
    },
    /// Only a stopped recording can be forgotten.
    #[error("recording {id} still records")]
    NotStopped {
        /// The id.
        id: u64,
    },
    /// No id is left.
    #[error("recording ids exhausted")]
    IdsExhausted,
    /// An earlier write failed: the catalog's state on disk is unknown
    /// until it is opened again.
    #[error("the catalog failed earlier and must be opened again")]
    Failed,
    /// A recording's segment store failed to recover.
    #[error(transparent)]
    Segment(#[from] SegmentError),
    /// The operating system's error.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// An opened catalog and what opening it repaired.
#[derive(Debug)]
pub struct Opened<D: Disk> {
    /// The catalog.
    pub catalog: Catalog<D>,
    /// The log offset where a torn or inconsistent record was cut.
    pub cut: Option<u64>,
    /// Whether a compaction's leftover file was removed.
    pub removed_temporary: bool,
}

/// A recording [`Catalog::settle`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settled {
    /// The recording.
    pub id: u64,
    /// Where it now stops.
    pub position: u64,
    /// Why: recovered, or empty.
    pub reason: StopReason,
}

/// The catalog of one archive directory.
#[derive(Debug)]
pub struct Catalog<D: Disk> {
    disk: D,
    dir: PathBuf,
    file: D::File,
    /// The log's end: where the next record goes.
    end: u64,
    recordings: Vec<Recording>,
    next_id: u64,
    failed: bool,
}

/// A decoded record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Record {
    Started(Recording),
    Stopped { id: u64, stop: Stop },
    NextId(u64),
    Forgotten(u64),
}

/// A little-endian writer.
#[derive(Debug, Default)]
struct Out(Vec<u8>);

impl Out {
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

/// A little-endian reader over a payload.
struct In<'a>(&'a [u8]);

impl In<'_> {
    fn take(&mut self, length: usize) -> Option<&[u8]> {
        let (head, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
}

fn policy_code(policy: SyncPolicy) -> (u8, u64) {
    match policy {
        SyncPolicy::None => (0, 0),
        SyncPolicy::PerSegment => (1, 0),
        SyncPolicy::Every { interval_ns } => (2, interval_ns),
    }
}

fn policy_of(code: u8, interval_ns: u64) -> Option<SyncPolicy> {
    match code {
        0 => Some(SyncPolicy::None),
        1 => Some(SyncPolicy::PerSegment),
        2 => Some(SyncPolicy::Every { interval_ns }),
        _ => None,
    }
}

impl Record {
    /// The record's bytes: kind, length, payload, CRC.
    fn encode(&self) -> Option<Vec<u8>> {
        let mut payload = Out::default();
        let kind = match self {
            Self::Started(recording) => {
                payload.bytes(&recording.id.to_le_bytes());
                payload.bytes(&recording.stream_id.to_le_bytes());
                payload.bytes(&recording.session_id.to_le_bytes());
                payload.bytes(&recording.start.to_le_bytes());
                payload.bytes(&recording.start_time_ns.to_le_bytes());
                payload.bytes(&recording.geometry.term_length().to_le_bytes());
                payload.bytes(&recording.geometry.segment_length().to_le_bytes());
                let (policy, interval) = policy_code(recording.policy);
                payload.bytes(&[policy]);
                payload.bytes(&interval.to_le_bytes());
                let channel = u16::try_from(recording.channel.len()).ok()?;
                payload.bytes(&channel.to_le_bytes());
                payload.bytes(&recording.channel);
                STARTED
            }
            Self::Stopped { id, stop } => {
                payload.bytes(&id.to_le_bytes());
                payload.bytes(&stop.position.to_le_bytes());
                payload.bytes(&stop.time_ns.to_le_bytes());
                payload.bytes(&[stop.reason.code()]);
                STOPPED
            }
            Self::NextId(next) => {
                payload.bytes(&next.to_le_bytes());
                NEXT_ID
            }
            Self::Forgotten(id) => {
                payload.bytes(&id.to_le_bytes());
                FORGOTTEN
            }
        };
        let length = u16::try_from(payload.0.len()).ok()?;
        let mut record = Out::default();
        record.bytes(&kind.to_le_bytes());
        record.bytes(&length.to_le_bytes());
        record.bytes(&payload.0);
        let crc = crc32c(&record.0);
        record.bytes(&crc.to_le_bytes());
        Some(record.0)
    }

    /// The record of `kind` in `payload`, if it decodes whole.
    fn decode(kind: u16, payload: &[u8]) -> Option<Self> {
        let mut input = In(payload);
        let record = match kind {
            STARTED => {
                let id = input.u64()?;
                let stream_id = input.i32()?;
                let session_id = input.i32()?;
                let start = input.u64()?;
                let start_time_ns = input.u64()?;
                let term_length = input.u32()?;
                let segment_length = input.u64()?;
                let policy = input.u8()?;
                let interval = input.u64()?;
                let channel = usize::from(input.u16()?);
                if channel > MAX_CHANNEL {
                    return None;
                }
                let channel = input.take(channel)?.to_vec();
                Self::Started(Recording {
                    id,
                    stream_id,
                    session_id,
                    channel,
                    start,
                    start_time_ns,
                    geometry: Geometry::new(term_length, segment_length).ok()?,
                    policy: policy_of(policy, interval)?,
                    stop: None,
                })
            }
            STOPPED => Self::Stopped {
                id: input.u64()?,
                stop: Stop {
                    position: input.u64()?,
                    time_ns: input.u64()?,
                    reason: StopReason::of(input.u8()?)?,
                },
            },
            NEXT_ID => Self::NextId(input.u64()?),
            FORGOTTEN => Self::Forgotten(input.u64()?),
            _ => return None,
        };
        input.0.is_empty().then_some(record)
    }
}

fn header() -> [u8; HEADER] {
    let mut bytes = [0u8; HEADER];
    if let Some(slot) = bytes.get_mut(0..4) {
        slot.copy_from_slice(&MAGIC.to_le_bytes());
    }
    if let Some(slot) = bytes.get_mut(4..8) {
        slot.copy_from_slice(&VERSION.to_le_bytes());
    }
    let crc = crc32c(bytes.get(..12).unwrap_or_default());
    if let Some(slot) = bytes.get_mut(12..16) {
        slot.copy_from_slice(&crc.to_le_bytes());
    }
    bytes
}

/// The catalog's logical state, built from its records in order.
#[derive(Debug, Default)]
struct State {
    recordings: Vec<Recording>,
    highest: Option<u64>,
    watermark: u64,
}

impl State {
    /// Applies `record`; `false` when it is inconsistent with the state.
    fn apply(&mut self, record: Record) -> bool {
        match record {
            Record::Started(recording) => {
                // Ids rise in log order; a compacted log lists its live
                // recordings after the watermark, below it.
                if self.highest.is_some_and(|highest| recording.id <= highest) {
                    return false;
                }
                self.highest = Some(recording.id);
                self.recordings.push(recording);
            }
            Record::Stopped { id, stop } => {
                match self
                    .recordings
                    .iter_mut()
                    .find(|recording| recording.id == id)
                {
                    Some(recording) if recording.stop.is_none() => recording.stop = Some(stop),
                    _ => return false,
                }
            }
            Record::NextId(next) => self.watermark = self.watermark.max(next),
            Record::Forgotten(id) => {
                let Some(index) = self
                    .recordings
                    .iter()
                    .position(|recording| recording.id == id && recording.stop.is_some())
                else {
                    return false;
                };
                self.recordings.remove(index);
            }
        }
        true
    }

    fn next_id(&self) -> Option<u64> {
        let after = match self.highest {
            Some(highest) => highest.checked_add(1)?,
            None => 1,
        };
        Some(after.max(self.watermark).max(1))
    }
}

impl<D: Disk> Catalog<D> {
    /// Opens the catalog of `dir`, creating it when there is none: removes
    /// a compaction's leftover file, and cuts the log at the first torn or
    /// inconsistent record.
    ///
    /// # Errors
    ///
    /// The operating system's errors.
    pub fn open(mut disk: D, dir: &Path) -> Result<Opened<D>, CatalogError> {
        let names = disk.list(dir)?;
        let path = dir.join(CATALOG);
        let mut removed_temporary = false;
        if names.iter().any(|name| name == TEMPORARY) {
            disk.remove(&dir.join(TEMPORARY))?;
            removed_temporary = true;
        }
        if !names.iter().any(|name| name == CATALOG) {
            let file = disk.create(&path)?;
            disk.write_at(&file, 0, &header())?;
            disk.sync(&file)?;
            disk.sync_dir(dir)?;
            let catalog = Self {
                disk,
                dir: dir.to_path_buf(),
                file,
                end: HEADER as u64,
                recordings: Vec::new(),
                next_id: 1,
                failed: false,
            };
            return Ok(Opened {
                catalog,
                cut: None,
                removed_temporary,
            });
        }
        let file = disk.open(&path)?;
        let length = usize::try_from(disk.len(&file)?).map_err(io::Error::other)?;
        let mut bytes = vec![0u8; length];
        disk.read_at(&file, 0, &mut bytes)?;
        let mut state = State::default();
        let mut offset = HEADER;
        let mut cut = None;
        if bytes.get(..HEADER) != Some(&header()[..]) {
            // A torn header: the catalog's creation did not complete, so no
            // record of it was ever reported.
            disk.truncate(&file, 0)?;
            disk.write_at(&file, 0, &header())?;
            cut = Some(0);
        } else {
            while offset < length {
                let Some(next) = parse(&bytes, offset) else {
                    cut = Some(offset as u64);
                    break;
                };
                let (record, end) = next;
                if !state.apply(record) {
                    cut = Some(offset as u64);
                    break;
                }
                offset = end;
            }
        }
        if let Some(at) = cut.filter(|at| *at > 0) {
            disk.truncate(&file, at)?;
        }
        disk.sync(&file)?;
        if removed_temporary || cut.is_some() {
            disk.sync_dir(dir)?;
        }
        let end = match cut {
            Some(0) => HEADER as u64,
            Some(at) => at,
            None => offset as u64,
        };
        let next_id = state.next_id().ok_or(CatalogError::IdsExhausted)?;
        Ok(Opened {
            catalog: Self {
                disk,
                dir: dir.to_path_buf(),
                file,
                end,
                recordings: state.recordings,
                next_id,
                failed: false,
            },
            cut,
            removed_temporary,
        })
    }

    /// The recordings, in id order.
    #[must_use]
    pub fn recordings(&self) -> &[Recording] {
        &self.recordings
    }

    /// The recording `id`.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&Recording> {
        self.recordings.iter().find(|recording| recording.id == id)
    }

    /// The id the next recording gets.
    #[must_use]
    pub const fn next_id(&self) -> u64 {
        self.next_id
    }

    /// The log's length in bytes, for a compaction policy.
    #[must_use]
    pub const fn log_length(&self) -> u64 {
        self.end
    }

    /// Appends `record` and syncs it; the store fails on an error.
    fn append(&mut self, record: &Record) -> Result<(), CatalogError> {
        if self.failed {
            return Err(CatalogError::Failed);
        }
        let bytes = record.encode().ok_or(CatalogError::IdsExhausted)?;
        let length = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        let end = self
            .end
            .checked_add(length)
            .ok_or(CatalogError::IdsExhausted)?;
        let written = self
            .disk
            .write_at(&self.file, self.end, &bytes)
            .and_then(|()| self.disk.sync(&self.file));
        if let Err(error) = written {
            self.failed = true;
            return Err(error.into());
        }
        self.end = end;
        Ok(())
    }

    /// Starts a recording: its `Started` record is durable on return, and
    /// the caller then creates its segment store.
    ///
    /// # Errors
    ///
    /// [`CatalogError::ChannelTooLong`] and [`CatalogError::IdsExhausted`],
    /// which change nothing; [`CatalogError::Failed`] after an earlier
    /// failure; the operating system's errors.
    pub fn start(&mut self, new: NewRecording<'_>) -> Result<u64, CatalogError> {
        if new.channel.len() > MAX_CHANNEL {
            return Err(CatalogError::ChannelTooLong {
                length: new.channel.len(),
            });
        }
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(CatalogError::IdsExhausted)?;
        let recording = Recording {
            id,
            stream_id: new.stream_id,
            session_id: new.session_id,
            channel: new.channel.to_vec(),
            start: new.start,
            start_time_ns: new.start_time_ns,
            geometry: new.geometry,
            policy: new.policy,
            stop: None,
        };
        self.append(&Record::Started(recording.clone()))?;
        self.next_id = next;
        self.recordings.push(recording);
        Ok(id)
    }

    /// Stops recording `id` at `position`: its `Stopped` record is durable
    /// on return. The caller closes its segment store first.
    ///
    /// # Errors
    ///
    /// [`CatalogError::UnknownRecording`] and
    /// [`CatalogError::AlreadyStopped`], which change nothing;
    /// [`CatalogError::Failed`]; the operating system's errors.
    pub fn stop(
        &mut self,
        id: u64,
        position: u64,
        time_ns: u64,
        reason: StopReason,
    ) -> Result<(), CatalogError> {
        let recording = self
            .recordings
            .iter()
            .find(|recording| recording.id == id)
            .ok_or(CatalogError::UnknownRecording { id })?;
        if recording.stop.is_some() {
            return Err(CatalogError::AlreadyStopped { id });
        }
        let stop = Stop {
            position,
            time_ns,
            reason,
        };
        self.append(&Record::Stopped { id, stop })?;
        if let Some(recording) = self
            .recordings
            .iter_mut()
            .find(|recording| recording.id == id)
        {
            recording.stop = Some(stop);
        }
        Ok(())
    }

    /// Forgets the stopped recording `id` (its files are the caller's):
    /// its `Forgotten` record is durable on return; its id stays used.
    ///
    /// # Errors
    ///
    /// [`CatalogError::UnknownRecording`] and [`CatalogError::NotStopped`],
    /// which change nothing; [`CatalogError::Failed`]; the operating
    /// system's errors.
    pub fn forget(&mut self, id: u64) -> Result<(), CatalogError> {
        let index = self
            .recordings
            .iter()
            .position(|recording| recording.id == id)
            .ok_or(CatalogError::UnknownRecording { id })?;
        if self
            .recordings
            .get(index)
            .is_some_and(|recording| recording.stop.is_none())
        {
            return Err(CatalogError::NotStopped { id });
        }
        self.append(&Record::Forgotten(id))?;
        self.recordings.remove(index);
        Ok(())
    }

    /// Rewrites the log with only the live records and the id watermark,
    /// through a temporary file renamed over the catalog.
    ///
    /// # Errors
    ///
    /// [`CatalogError::Failed`], and the operating system's errors, after
    /// which the catalog must be opened again.
    pub fn compact(&mut self) -> Result<(), CatalogError> {
        if self.failed {
            return Err(CatalogError::Failed);
        }
        let result = self.rewrite();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn rewrite(&mut self) -> Result<(), CatalogError> {
        let mut bytes = header().to_vec();
        let next = Record::NextId(self.next_id)
            .encode()
            .ok_or(CatalogError::IdsExhausted)?;
        bytes.extend_from_slice(&next);
        for recording in &self.recordings {
            let mut started = recording.clone();
            started.stop = None;
            let record = Record::Started(started)
                .encode()
                .ok_or(CatalogError::IdsExhausted)?;
            bytes.extend_from_slice(&record);
            if let Some(stop) = recording.stop {
                let record = Record::Stopped {
                    id: recording.id,
                    stop,
                }
                .encode()
                .ok_or(CatalogError::IdsExhausted)?;
                bytes.extend_from_slice(&record);
            }
        }
        let temporary = self.dir.join(TEMPORARY);
        let path = self.dir.join(CATALOG);
        let file = self.disk.create(&temporary)?;
        self.disk.write_at(&file, 0, &bytes)?;
        self.disk.sync(&file)?;
        self.disk.rename(&temporary, &path)?;
        self.disk.sync_dir(&self.dir)?;
        self.file = self.disk.open(&path)?;
        self.end = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        Ok(())
    }
}

impl<D: Disk + Clone> Catalog<D> {
    /// Stops every recording a crash left open: at its segment store's
    /// recovered written position, or at its start when its store never
    /// came to exist, with the reason recorded.
    ///
    /// # Errors
    ///
    /// A store's recovery error other than its absence, and the catalog's
    /// write errors.
    pub fn settle(&mut self, now_ns: u64) -> Result<Vec<Settled>, CatalogError> {
        let open: Vec<(u64, u64, Geometry, SyncPolicy)> = self
            .recordings
            .iter()
            .filter(|recording| recording.stop.is_none())
            .map(|recording| {
                (
                    recording.id,
                    recording.start,
                    recording.geometry,
                    recording.policy,
                )
            })
            .collect();
        let mut settled = Vec::with_capacity(open.len());
        for (id, start, geometry, policy) in open {
            let (position, reason) =
                match SegmentStore::recover(self.disk.clone(), &self.dir, id, geometry, policy) {
                    Ok(recovered) => (recovered.store.written(), StopReason::Recovered),
                    Err(SegmentError::NotFound { .. }) => (start, StopReason::Empty),
                    Err(error) => return Err(error.into()),
                };
            self.stop(id, position, now_ns, reason)?;
            settled.push(Settled {
                id,
                position,
                reason,
            });
        }
        Ok(settled)
    }
}

/// The record at `offset` of `bytes` and the offset after it, if it is
/// whole and its CRC holds.
fn parse(bytes: &[u8], offset: usize) -> Option<(Record, usize)> {
    let head = bytes.get(offset..offset.checked_add(HEAD)?)?;
    let kind = u16::from_le_bytes(head.get(0..2)?.try_into().ok()?);
    let length = usize::from(u16::from_le_bytes(head.get(2..4)?.try_into().ok()?));
    let body_end = offset.checked_add(HEAD)?.checked_add(length)?;
    let end = body_end.checked_add(TAIL)?;
    let checked = bytes.get(offset..body_end)?;
    let crc = u32::from_le_bytes(bytes.get(body_end..end)?.try_into().ok()?);
    if crc32c(checked) != crc {
        return None;
    }
    let payload = bytes.get(offset.checked_add(HEAD)?..body_end)?;
    Some((Record::decode(kind, payload)?, end))
}
