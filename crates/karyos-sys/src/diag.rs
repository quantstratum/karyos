// SPDX-License-Identifier: Apache-2.0

//! The error log and the loss report (`quantstratum-docs:
//! karyos/design/observability-and-tools.md`, "Error log" and "Loss
//! report"): typed records over the rings of [`crate::diag_ring`], on the
//! heap or in a shared region the driver alone writes (A2 seals), with
//! readers that also work over a read-only mapping.
//!
//! Only the driver conductor writes, on the control path. Formatting a
//! record never happens on the data path.

use std::collections::HashMap;
use std::sync::Arc;

use crate::atomic_view::{HeapWords, WORD_BYTES};
use crate::diag_ring::{Appended, FIELDS, RingReader, RingWriter, Scan, ring_words, scan};
use crate::error::SysError;
use crate::sync::{AtomicU64, Ordering};

/// Words per error record: two strides.
pub const ERROR_RECORD_WORDS: usize = 32;
/// Words per loss record: one stride.
pub const LOSS_RECORD_WORDS: usize = 16;
/// Words per guard audit record: one stride.
pub const GUARD_AUDIT_RECORD_WORDS: usize = 16;
/// Default guard audit capacity in records.
pub const DEFAULT_GUARD_AUDIT_RECORDS: usize = 256;
/// Bytes of an error record's message.
pub const MESSAGE_BYTES: usize = 192;
/// Default error log capacity in records.
pub const DEFAULT_ERROR_RECORDS: usize = 1024;
/// Default loss report capacity in records.
pub const DEFAULT_LOSS_RECORDS: usize = 256;
/// Layout version of both regions.
pub const LAYOUT_VERSION: u64 = 1;

/// Message words: from field 6 to the end of the record.
const MESSAGE_WORDS: usize = MESSAGE_BYTES / WORD_BYTES;

/// Where a ring lives.
#[derive(Debug)]
pub(crate) enum Store {
    /// A heap allocation of this process.
    Heap(HeapWords),
    /// A shared region the driver writes (Linux).
    #[cfg(target_os = "linux")]
    Mapped(crate::ipc::Region),
    /// The same region mapped read-only (Linux): readers only.
    #[cfg(target_os = "linux")]
    ReadOnly(crate::ipc::ReadOnlyRegion),
}

impl Store {
    /// The writable words; empty for a read-only store.
    pub(crate) fn words(&self) -> &[AtomicU64] {
        match self {
            Self::Heap(heap) => heap.words().as_slice(),
            #[cfg(target_os = "linux")]
            Self::Mapped(region) => region.structure().as_slice(),
            #[cfg(target_os = "linux")]
            Self::ReadOnly(_) => &[],
        }
    }

    /// Word `index` with a `Relaxed` load, valid over every store.
    pub(crate) fn load(&self, index: usize) -> Option<u64> {
        match self {
            #[cfg(target_os = "linux")]
            Self::ReadOnly(region) => region.structure().load(index),
            _ => self
                .words()
                .get(index)
                .map(|word| word.load(Ordering::Relaxed)),
        }
    }
}

/// Creates a ring store of `capacity` records on the heap.
fn heap_store(capacity: usize, record_words: usize) -> Result<(Store, usize), SysError> {
    let words = ring_words(capacity, record_words)
        .filter(|_| capacity > 0)
        .ok_or(SysError::InvalidRegion { address: 0, len: 0 })?;
    Ok((Store::Heap(HeapWords::zeroed(words)?), capacity))
}

/// Bytes of a diagnostic ring region's structure: `capacity` records of
/// `record_words` words and the ring's own words.
#[cfg(target_os = "linux")]
fn structure_length(capacity: usize, record_words: usize) -> Option<usize> {
    ring_words(capacity, record_words)
        .filter(|_| capacity > 0)
        .and_then(|words| words.checked_mul(WORD_BYTES))
}

/// Bytes of an error log region's structure for `capacity` records
/// (R-CORE-34): the size it is created with, after the region header.
#[cfg(target_os = "linux")]
#[must_use]
pub fn error_log_structure_length(capacity: usize) -> Option<usize> {
    structure_length(capacity, ERROR_RECORD_WORDS)
}

/// Bytes of a loss report region's structure for `capacity` records
/// (R-CORE-34).
#[cfg(target_os = "linux")]
#[must_use]
pub fn loss_report_structure_length(capacity: usize) -> Option<usize> {
    structure_length(capacity, LOSS_RECORD_WORDS)
}

/// Bytes of a guard audit region's structure for `capacity` records
/// (R-CORE-34).
#[cfg(target_os = "linux")]
#[must_use]
pub fn guard_audit_structure_length(capacity: usize) -> Option<usize> {
    structure_length(capacity, GUARD_AUDIT_RECORD_WORDS)
}

/// Creates a ring store in a new driver-only shared region.
#[cfg(target_os = "linux")]
fn region_store(
    instance: u128,
    region: u64,
    kind: crate::ipc::RegionKind,
    capacity: usize,
    record_words: usize,
) -> Result<Store, SysError> {
    let structure_length = structure_length(capacity, record_words)
        .ok_or(SysError::InvalidRegion { address: 0, len: 0 })?;
    // Only the driver writes these regions: A2 seal order (owner decision
    // Q7), so tools can map them only read-only.
    let mapped = crate::ipc::Region::create_driver_only(crate::ipc::RegionRecord {
        instance,
        region,
        kind,
        generation: 0,
        layout: LAYOUT_VERSION,
        structure_length,
    })?;
    Ok(Store::Mapped(mapped))
}

/// Checks a read-only region of `kind` and `record_words`-word records.
#[cfg(target_os = "linux")]
fn read_only_store(
    region: crate::ipc::ReadOnlyRegion,
    kind: crate::ipc::RegionKind,
    record_words: usize,
) -> Result<Store, SysError> {
    let record = region.record();
    let invalid = SysError::InvalidRegion {
        address: 0,
        len: record.structure_length,
    };
    if record.kind != kind || record.layout != LAYOUT_VERSION || record.generation != 0 {
        return Err(invalid);
    }
    let capacity = region
        .structure()
        .load_acquire(0)
        .and_then(|capacity| usize::try_from(capacity).ok())
        .ok_or(invalid)?;
    if structure_length(capacity, record_words) != Some(record.structure_length) {
        return Err(invalid);
    }
    Ok(Store::ReadOnly(region))
}

/// Packs a `u32`, a `u16` and a `u16` into one word.
const fn pack_code(code: u32, source: u16, length: u16) -> u64 {
    code as u64 | (source as u64) << 32 | (length as u64) << 48
}

/// The longest prefix of `message` of at most [`MESSAGE_BYTES`] bytes that
/// ends on a character boundary.
fn truncate(message: &str) -> &[u8] {
    let mut end = message.len().min(MESSAGE_BYTES);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.as_bytes().get(..end).unwrap_or(&[])
}

/// One error record as a reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorRecord {
    /// Its sequence.
    pub seq: u64,
    /// First and last time it occurred (`CLOCK_MONOTONIC` nanoseconds).
    pub first: u64,
    /// Last time it occurred.
    pub last: u64,
    /// Occurrences.
    pub occurrences: u64,
    /// The error code.
    pub code: u32,
    /// The agent that reported it.
    pub source: u16,
    /// The key: a stream or client registration, and a detail value.
    pub key: [u64; 2],
    /// The message, UTF-8, at most [`MESSAGE_BYTES`] bytes.
    pub message: String,
}

impl ErrorRecord {
    fn decode(seq: u64, fields: &[u64]) -> Self {
        let field = |index: usize| fields.get(index).copied().unwrap_or(0);
        let packed = field(3);
        let length = usize::from((packed >> 48) as u16).min(MESSAGE_BYTES);
        let mut bytes = Vec::with_capacity(MESSAGE_BYTES);
        for index in 0..MESSAGE_WORDS {
            bytes.extend_from_slice(&field(6 + index).to_le_bytes());
        }
        bytes.truncate(length);
        Self {
            seq,
            first: field(0),
            last: field(1),
            occurrences: field(2),
            code: packed as u32,
            source: (packed >> 32) as u16,
            key: [field(4), field(5)],
            message: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }
}

/// What reporting an error did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reported {
    /// A new record; `overwrote` when it displaced the oldest one.
    New {
        /// Its sequence.
        seq: u64,
        /// Whether the ring was full.
        overwrote: bool,
    },
    /// An existing record was updated in place.
    Updated {
        /// Its sequence.
        seq: u64,
    },
}

/// Identity of an error for deduplication.
type ErrorKey = (u32, [u64; 2]);

/// The error log's writer: the driver conductor's.
#[derive(Debug)]
pub struct ErrorLog {
    store: Arc<Store>,
    /// The `(code, key)` of the record each slot holds.
    slots: Vec<Option<ErrorKey>>,
    /// The record that last reported each `(code, key)`, at most one entry
    /// per retained record.
    index: HashMap<ErrorKey, u64>,
    window: u64,
}

impl ErrorLog {
    fn new(store: Store, capacity: usize, window: u64) -> Result<Self, SysError> {
        // Writes the header; each report resumes the writer.
        if RingWriter::create(store.words(), capacity, ERROR_RECORD_WORDS).is_none() {
            return Err(SysError::InvalidRegion { address: 0, len: 0 });
        }
        Ok(Self {
            store: Arc::new(store),
            slots: vec![None; capacity],
            index: HashMap::with_capacity(capacity.saturating_mul(2)),
            window,
        })
    }

    fn ring(&self) -> Option<RingWriter<'_>> {
        RingWriter::resume(self.store.words(), ERROR_RECORD_WORDS)
    }

    /// Reports an error at `now`. A repeat of the same `(code, key)` within
    /// the deduplication window of its last occurrence, while its record is
    /// retained, updates that record; otherwise a new record is written.
    /// `None` once the sequences are exhausted.
    pub fn report(
        &mut self,
        now: u64,
        code: u32,
        source: u16,
        key: [u64; 2],
        message: &str,
    ) -> Option<Reported> {
        let id = (code, key);
        if let Some(&seq) = self.index.get(&id)
            && let Some(updated) = self.repeat(seq, now)
        {
            return Some(updated);
        }
        let bytes = truncate(message);
        let mut fields = [0u64; ERROR_RECORD_WORDS - FIELDS];
        fields[0] = now;
        fields[1] = now;
        fields[2] = 1;
        fields[3] = pack_code(code, source, bytes.len() as u16);
        fields[4] = key[0];
        fields[5] = key[1];
        for (word, chunk) in fields[6..].iter_mut().zip(bytes.chunks(WORD_BYTES)) {
            let mut padded = [0u8; WORD_BYTES];
            for (byte, &value) in padded.iter_mut().zip(chunk) {
                *byte = value;
            }
            *word = u64::from_le_bytes(padded);
        }
        let capacity = self.slots.len() as u64;
        let mut ring = RingWriter::resume(self.store.words(), ERROR_RECORD_WORDS)?;
        let next = ring.bounds().next;
        let slot = usize::try_from(next % capacity).ok()?;
        // The overwritten record's index entry goes first, so the index
        // never outgrows the ring.
        if let Some(old) = self.slots.get_mut(slot).and_then(Option::take)
            && self
                .index
                .get(&old)
                .is_some_and(|&seq| seq + capacity == next)
        {
            self.index.remove(&old);
        }
        let Appended { seq, overwrote } = ring.append(&fields)?;
        *self.slots.get_mut(slot)? = Some(id);
        self.index.insert(id, seq);
        Some(Reported::New {
            seq,
            overwrote: overwrote.is_some(),
        })
    }

    /// Updates record `seq` for a repeat at `now`, if it is retained and
    /// its last occurrence is within the window.
    fn repeat(&mut self, seq: u64, now: u64) -> Option<Reported> {
        let mut ring = self.ring()?;
        if !ring.bounds().contains(seq) {
            return None;
        }
        let reader = RingReader::new(|index| self.store.load(index), ERROR_RECORD_WORDS)?;
        let mut fields = [0u64; ERROR_RECORD_WORDS - FIELDS];
        if reader.read(seq, &mut fields) != crate::diag_ring::SlotRead::Record {
            return None;
        }
        if now.saturating_sub(fields[1]) > self.window {
            return None;
        }
        fields[1] = now.max(fields[1]);
        fields[2] = fields[2].saturating_add(1);
        ring.update(seq, &fields)
            .then_some(Reported::Updated { seq })
    }

    /// Entries in the deduplication index; never above the capacity.
    #[must_use]
    pub fn indexed(&self) -> usize {
        self.index.len()
    }

    /// A reader of this log.
    #[must_use]
    pub fn reader(&self) -> ErrorLogReader {
        ErrorLogReader {
            store: Arc::clone(&self.store),
        }
    }

    /// The shared region, to pass its descriptor; `None` on the heap.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn region(&self) -> Option<&crate::ipc::Region> {
        match &*self.store {
            Store::Mapped(region) => Some(region),
            _ => None,
        }
    }
}

/// Creates an error log of `capacity` records on the heap, deduplicating
/// repeats within `window` nanoseconds.
///
/// # Errors
///
/// [`SysError::InvalidRegion`] for a zero or oversized capacity.
pub fn error_log(capacity: usize, window: u64) -> Result<ErrorLog, SysError> {
    let (store, capacity) = heap_store(capacity, ERROR_RECORD_WORDS)?;
    ErrorLog::new(store, capacity, window)
}

/// Creates an error log in a new driver-only shared region.
///
/// # Errors
///
/// As [`error_log`], and the errors of [`crate::ipc::Region::create_driver_only`].
#[cfg(target_os = "linux")]
pub fn error_log_in(
    instance: u128,
    region: u64,
    capacity: usize,
    window: u64,
) -> Result<ErrorLog, SysError> {
    let store = region_store(
        instance,
        region,
        crate::ipc::RegionKind::ErrorLog,
        capacity,
        ERROR_RECORD_WORDS,
    )?;
    ErrorLog::new(store, capacity, window)
}

/// A reader of an error log.
#[derive(Debug, Clone)]
pub struct ErrorLogReader {
    store: Arc<Store>,
}

impl ErrorLogReader {
    /// A reader of an error log region mapped read-only (a tool).
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidRegion`] for another kind, layout or size.
    #[cfg(target_os = "linux")]
    pub fn attach_read_only(region: crate::ipc::ReadOnlyRegion) -> Result<Self, SysError> {
        Ok(Self {
            store: Arc::new(read_only_store(
                region,
                crate::ipc::RegionKind::ErrorLog,
                ERROR_RECORD_WORDS,
            )?),
        })
    }

    /// Scans from `cursor` (see [`crate::diag_ring::scan`]), delivering
    /// each retained record in order.
    pub fn scan(&self, cursor: &mut u64, mut deliver: impl FnMut(ErrorRecord)) -> Scan {
        let Some(reader) = RingReader::new(|index| self.store.load(index), ERROR_RECORD_WORDS)
        else {
            return empty_scan();
        };
        let mut buffer = [0u64; ERROR_RECORD_WORDS - FIELDS];
        scan(&reader, cursor, &mut buffer, |seq, fields| {
            deliver(ErrorRecord::decode(seq, fields));
        })
    }
}

/// A scan of a ring whose header is not readable.
const fn empty_scan() -> Scan {
    Scan {
        overwritten: 0,
        delivered: 0,
        stopped: Some(crate::diag_ring::ScanStop::Busy),
    }
}

/// One loss record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LossRecord {
    /// Time (`CLOCK_MONOTONIC` nanoseconds).
    pub time: u64,
    /// The loss kind.
    pub kind: u16,
    /// Its reason.
    pub reason: u16,
    /// The lane.
    pub lane: u8,
    /// The configured rejoin policy.
    pub configured_policy: u8,
    /// The applied policy.
    pub applied_policy: u8,
    /// Flags; bit 0 unverified.
    pub flags: u8,
    /// The driver instance id of the publication's full identity.
    pub instance: u128,
    /// The stream registration id of the full identity.
    pub stream_registration: u64,
    /// The incarnation of the full identity.
    pub incarnation: u64,
    /// The stream id.
    pub stream_id: u64,
    /// The lost range: from (inclusive).
    pub from: u64,
    /// The lost range: to (exclusive).
    pub to: u64,
    /// The reporting participant's registration, 0 for the driver.
    pub participant: u64,
    /// The reporting client's registration, 0 for the driver.
    pub client: u64,
}

impl LossRecord {
    fn encode(&self) -> [u64; LOSS_RECORD_WORDS - FIELDS] {
        [
            self.time,
            u64::from(self.kind)
                | u64::from(self.reason) << 16
                | u64::from(self.lane) << 32
                | u64::from(self.configured_policy) << 40
                | u64::from(self.applied_policy) << 48
                | u64::from(self.flags) << 56,
            (self.instance >> 64) as u64,
            self.instance as u64,
            self.stream_registration,
            self.incarnation,
            self.stream_id,
            self.from,
            self.to,
            self.participant,
            self.client,
            0,
            0,
            0,
        ]
    }

    fn decode(fields: &[u64]) -> Self {
        let field = |index: usize| fields.get(index).copied().unwrap_or(0);
        let packed = field(1);
        Self {
            time: field(0),
            kind: packed as u16,
            reason: (packed >> 16) as u16,
            lane: (packed >> 32) as u8,
            configured_policy: (packed >> 40) as u8,
            applied_policy: (packed >> 48) as u8,
            flags: (packed >> 56) as u8,
            instance: u128::from(field(2)) << 64 | u128::from(field(3)),
            stream_registration: field(4),
            incarnation: field(5),
            stream_id: field(6),
            from: field(7),
            to: field(8),
            participant: field(9),
            client: field(10),
        }
    }
}

/// The loss report's writer: the driver conductor's.
#[derive(Debug)]
pub struct LossReport {
    store: Arc<Store>,
}

impl LossReport {
    fn new(store: Store, capacity: usize) -> Result<Self, SysError> {
        // Writes the header; each report resumes the writer.
        if RingWriter::create(store.words(), capacity, LOSS_RECORD_WORDS).is_none() {
            return Err(SysError::InvalidRegion { address: 0, len: 0 });
        }
        Ok(Self {
            store: Arc::new(store),
        })
    }

    /// Appends `record`; `None` once the sequences are exhausted.
    pub fn record(&mut self, record: &LossRecord) -> Option<Appended> {
        RingWriter::resume(self.store.words(), LOSS_RECORD_WORDS)?.append(&record.encode())
    }

    /// A reader of this report.
    #[must_use]
    pub fn reader(&self) -> LossReportReader {
        LossReportReader {
            store: Arc::clone(&self.store),
        }
    }

    /// The shared region, to pass its descriptor; `None` on the heap.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn region(&self) -> Option<&crate::ipc::Region> {
        match &*self.store {
            Store::Mapped(region) => Some(region),
            _ => None,
        }
    }
}

/// Creates a loss report of `capacity` records on the heap.
///
/// # Errors
///
/// [`SysError::InvalidRegion`] for a zero or oversized capacity.
pub fn loss_report(capacity: usize) -> Result<LossReport, SysError> {
    let (store, capacity) = heap_store(capacity, LOSS_RECORD_WORDS)?;
    LossReport::new(store, capacity)
}

/// Creates a loss report in a new driver-only shared region.
///
/// # Errors
///
/// As [`loss_report`], and the errors of [`crate::ipc::Region::create_driver_only`].
#[cfg(target_os = "linux")]
pub fn loss_report_in(
    instance: u128,
    region: u64,
    capacity: usize,
) -> Result<LossReport, SysError> {
    let store = region_store(
        instance,
        region,
        crate::ipc::RegionKind::LossReport,
        capacity,
        LOSS_RECORD_WORDS,
    )?;
    LossReport::new(store, capacity)
}

/// A reader of a loss report.
#[derive(Debug, Clone)]
pub struct LossReportReader {
    store: Arc<Store>,
}

impl LossReportReader {
    /// A reader of a loss report region mapped read-only (a tool).
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidRegion`] for another kind, layout or size.
    #[cfg(target_os = "linux")]
    pub fn attach_read_only(region: crate::ipc::ReadOnlyRegion) -> Result<Self, SysError> {
        Ok(Self {
            store: Arc::new(read_only_store(
                region,
                crate::ipc::RegionKind::LossReport,
                LOSS_RECORD_WORDS,
            )?),
        })
    }

    /// Scans from `cursor` (see [`crate::diag_ring::scan`]), delivering
    /// each retained record in order with its sequence.
    pub fn scan(&self, cursor: &mut u64, mut deliver: impl FnMut(u64, LossRecord)) -> Scan {
        let Some(reader) = RingReader::new(|index| self.store.load(index), LOSS_RECORD_WORDS)
        else {
            return empty_scan();
        };
        let mut buffer = [0u64; LOSS_RECORD_WORDS - FIELDS];
        scan(&reader, cursor, &mut buffer, |seq, fields| {
            deliver(seq, LossRecord::decode(fields));
        })
    }
}

/// One guard transition, refusals included (`quantstratum-docs:
/// karyos/design/management-agent-gap-analysis.md`, M4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuardAuditRecord {
    /// Host time (`CLOCK_MONOTONIC` nanoseconds), the tools' clock domain.
    pub time: u64,
    /// The driver clock's time, as the driver's own audit holds it.
    pub driver_time: u64,
    /// The guard id the requester named, known or not.
    pub guard: u64,
    /// The guard word before; 0 for an unknown guard.
    pub before: u64,
    /// The guard word after.
    pub after: u64,
    /// The requester's operation id.
    pub operation: u64,
    /// Who asked: 0 the in-process caller, 1 an admitted client, 2 an
    /// operator through an admitted client (M10).
    pub requester_kind: u8,
    /// The client id for a client or an operator's client, else 0.
    pub requester: u64,
    /// What happened: 1 closed, 2 already closed, 3 reopened, 4 refused,
    /// 5 a guarded stream's rate policy changed (R-CORE-21, `before` and
    /// `after` its versions, `parameters` 1 safety or 2 administrator),
    /// 6 a rate policy change that named the policy in force (unchanged,
    /// `before` equal to `after`).
    /// A reader passes any other value through as it is: an outcome a
    /// later driver adds reads as unknown, never as a corrupt record.
    pub outcome: u8,
    /// The control error code of a refusal, else 0.
    pub refusal: u16,
    /// The operator uid (`requester_kind` 2), else 0. Word 8, zero in
    /// records written before M10, so older records read as none.
    pub operator: u64,
    /// The command's parameters digest
    /// (`karyos_protocol::cnc::guard_parameters`), 0 when none was given.
    /// Word 9, likewise.
    pub parameters: u64,
}

impl GuardAuditRecord {
    fn encode(&self) -> [u64; GUARD_AUDIT_RECORD_WORDS - FIELDS] {
        [
            self.time,
            self.driver_time,
            self.guard,
            self.before,
            self.after,
            self.operation,
            u64::from(self.requester_kind)
                | u64::from(self.outcome) << 8
                | u64::from(self.refusal) << 16,
            self.requester,
            self.operator,
            self.parameters,
            0,
            0,
            0,
            0,
        ]
    }

    fn decode(fields: &[u64]) -> Self {
        let field = |index: usize| fields.get(index).copied().unwrap_or(0);
        let [requester_kind, outcome, refusal_low, refusal_high, ..] = field(6).to_le_bytes();
        Self {
            time: field(0),
            driver_time: field(1),
            guard: field(2),
            before: field(3),
            after: field(4),
            operation: field(5),
            requester_kind,
            outcome,
            refusal: u16::from_le_bytes([refusal_low, refusal_high]),
            requester: field(7),
            operator: field(8),
            parameters: field(9),
        }
    }
}

/// The guard audit ring's writer: the driver conductor's.
#[derive(Debug)]
pub struct GuardAudit {
    store: Arc<Store>,
}

impl GuardAudit {
    fn new(store: Store, capacity: usize) -> Result<Self, SysError> {
        if RingWriter::create(store.words(), capacity, GUARD_AUDIT_RECORD_WORDS).is_none() {
            return Err(SysError::InvalidRegion { address: 0, len: 0 });
        }
        Ok(Self {
            store: Arc::new(store),
        })
    }

    /// Appends `record`, overwriting the oldest when full; `None` once the
    /// sequences are exhausted.
    pub fn record(&mut self, record: &GuardAuditRecord) -> Option<Appended> {
        RingWriter::resume(self.store.words(), GUARD_AUDIT_RECORD_WORDS)?.append(&record.encode())
    }

    /// A reader of this ring.
    #[must_use]
    pub fn reader(&self) -> GuardAuditReader {
        GuardAuditReader {
            store: Arc::clone(&self.store),
        }
    }

    /// The shared region, to pass its descriptor; `None` on the heap.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn region(&self) -> Option<&crate::ipc::Region> {
        match &*self.store {
            Store::Mapped(region) => Some(region),
            _ => None,
        }
    }
}

/// Creates a guard audit ring of `capacity` records on the heap.
///
/// # Errors
///
/// [`SysError::InvalidRegion`] for a zero or oversized capacity.
pub fn guard_audit(capacity: usize) -> Result<GuardAudit, SysError> {
    let (store, capacity) = heap_store(capacity, GUARD_AUDIT_RECORD_WORDS)?;
    GuardAudit::new(store, capacity)
}

/// Creates a guard audit ring in a new driver-only shared region.
///
/// # Errors
///
/// As [`guard_audit`], and the errors of [`crate::ipc::Region::create_driver_only`].
#[cfg(target_os = "linux")]
pub fn guard_audit_in(
    instance: u128,
    region: u64,
    capacity: usize,
) -> Result<GuardAudit, SysError> {
    let store = region_store(
        instance,
        region,
        crate::ipc::RegionKind::GuardAudit,
        capacity,
        GUARD_AUDIT_RECORD_WORDS,
    )?;
    GuardAudit::new(store, capacity)
}

/// A reader of a guard audit ring.
#[derive(Debug, Clone)]
pub struct GuardAuditReader {
    store: Arc<Store>,
}

impl GuardAuditReader {
    /// A reader of a guard audit region mapped read-only (a tool).
    ///
    /// # Errors
    ///
    /// [`SysError::InvalidRegion`] for another kind, layout or size.
    #[cfg(target_os = "linux")]
    pub fn attach_read_only(region: crate::ipc::ReadOnlyRegion) -> Result<Self, SysError> {
        Ok(Self {
            store: Arc::new(read_only_store(
                region,
                crate::ipc::RegionKind::GuardAudit,
                GUARD_AUDIT_RECORD_WORDS,
            )?),
        })
    }

    /// Scans from `cursor` (see [`crate::diag_ring::scan`]), delivering
    /// each retained record in order with its sequence.
    pub fn scan(&self, cursor: &mut u64, mut deliver: impl FnMut(u64, GuardAuditRecord)) -> Scan {
        let Some(reader) =
            RingReader::new(|index| self.store.load(index), GUARD_AUDIT_RECORD_WORDS)
        else {
            return empty_scan();
        };
        let mut buffer = [0u64; GUARD_AUDIT_RECORD_WORDS - FIELDS];
        scan(&reader, cursor, &mut buffer, |seq, fields| {
            deliver(seq, GuardAuditRecord::decode(fields));
        })
    }
}

#[cfg(test)]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]
mod tests {
    use super::*;

    fn errors(log: &ErrorLog, cursor: &mut u64) -> (Scan, Vec<ErrorRecord>) {
        let mut records = Vec::new();
        let scan = log.reader().scan(cursor, |record| records.push(record));
        (scan, records)
    }

    /// A guard audit record reads back whole, oldest first, and a full ring
    /// overwrites its oldest record and reports it.
    #[test]
    fn guard_audit_records_round_trip_and_overwrite() {
        let mut ring = guard_audit(2).unwrap();
        let record = |guard| GuardAuditRecord {
            time: 10,
            driver_time: 20,
            guard,
            before: 1,
            after: 3,
            operation: 99,
            requester_kind: 2,
            requester: 7,
            outcome: 4,
            refusal: u16::MAX,
            operator: 1000,
            parameters: u64::MAX,
        };
        for guard in 1..=3 {
            assert!(ring.record(&record(guard)).is_some());
        }
        let mut cursor = 0;
        let mut read = Vec::new();
        let scan = ring
            .reader()
            .scan(&mut cursor, |seq, record| read.push((seq, record)));
        assert_eq!(read, [(1, record(2)), (2, record(3))]);
        assert_eq!(scan.overwritten, 1);
    }

    /// R-CORE-21: a rate change record (outcome 5) and an outcome no
    /// reader knows read back as written: the ring neither refuses nor
    /// reinterprets them.
    #[test]
    fn guard_audit_outcomes_read_back_as_written() {
        let mut ring = guard_audit(4).unwrap();
        let record = |outcome| GuardAuditRecord {
            time: 1,
            driver_time: 2,
            guard: 3,
            before: 1,
            after: 2,
            operation: 4,
            requester_kind: 0,
            requester: 0,
            outcome,
            refusal: 0,
            operator: 0,
            parameters: 1,
        };
        for outcome in [5, u8::MAX] {
            assert!(ring.record(&record(outcome)).is_some());
        }
        let mut cursor = 0;
        let mut read = Vec::new();
        let _ = ring
            .reader()
            .scan(&mut cursor, |_, record| read.push(record));
        assert_eq!(read, [record(5), record(u8::MAX)]);
    }

    #[test]
    fn a_repeat_within_the_window_updates_its_record() {
        let mut log = error_log(4, 100).unwrap();
        assert_eq!(
            log.report(10, 7, 1, [3, 4], "stream config rejected"),
            Some(Reported::New {
                seq: 0,
                overwrote: false
            })
        );
        assert_eq!(
            log.report(60, 7, 1, [3, 4], "again"),
            Some(Reported::Updated { seq: 0 })
        );
        // Another key is a new record.
        assert_eq!(
            log.report(70, 7, 1, [3, 5], "other"),
            Some(Reported::New {
                seq: 1,
                overwrote: false
            })
        );
        // Beyond the window of the last occurrence (60): a new record.
        assert_eq!(
            log.report(161, 7, 1, [3, 4], "late"),
            Some(Reported::New {
                seq: 2,
                overwrote: false
            })
        );
        let mut cursor = 0;
        let (scan, records) = errors(&log, &mut cursor);
        assert_eq!((scan.delivered, scan.overwritten, cursor), (3, 0, 3));
        let first = &records[0];
        assert_eq!((first.first, first.last, first.occurrences), (10, 60, 2));
        assert_eq!((first.code, first.source, first.key), (7, 1, [3, 4]));
        // The message stays the first occurrence's.
        assert_eq!(first.message, "stream config rejected");
        assert_eq!(records[2].message, "late");
        // The index points at the latest record of each key.
        assert_eq!(
            log.report(200, 7, 1, [3, 4], "x"),
            Some(Reported::Updated { seq: 2 })
        );
    }

    #[test]
    fn an_overwritten_record_leaves_the_index() {
        let mut log = error_log(2, u64::MAX).unwrap();
        for key in 0..2 {
            log.report(1, 1, 0, [key, 0], "m").unwrap();
        }
        // Key 2 overwrites key 0's record, whose repeat is then new.
        assert_eq!(
            log.report(2, 1, 0, [2, 0], "m"),
            Some(Reported::New {
                seq: 2,
                overwrote: true
            })
        );
        assert_eq!(log.indexed(), 2);
        assert_eq!(
            log.report(3, 1, 0, [0, 0], "m"),
            Some(Reported::New {
                seq: 3,
                overwrote: true
            })
        );
        // Key 1's record (seq 1) was overwritten too.
        assert!(matches!(
            log.report(4, 1, 0, [1, 0], "m"),
            Some(Reported::New { .. })
        ));
        assert!(log.indexed() <= 2);
        // Key 2 was displaced by key 1, key 0 is still retained.
        assert_eq!(
            log.report(5, 1, 0, [0, 0], "m"),
            Some(Reported::Updated { seq: 3 })
        );
        let mut cursor = 0;
        let (scan, records) = errors(&log, &mut cursor);
        assert_eq!(scan.overwritten, 3);
        assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), [3, 4]);
    }

    #[test]
    fn a_long_message_is_cut_on_a_char_boundary() {
        let mut log = error_log(1, 0).unwrap();
        // 191 ASCII bytes then a 2-byte character: byte 192 would split it.
        let message = format!("{}é tail", "a".repeat(MESSAGE_BYTES - 1));
        log.report(0, 1, 0, [0, 0], &message).unwrap();
        let (_, records) = errors(&log, &mut 0);
        assert_eq!(records[0].message, "a".repeat(MESSAGE_BYTES - 1));
        let exact = "b".repeat(MESSAGE_BYTES + 10);
        log.report(1, 2, 0, [0, 0], &exact).unwrap();
        let (_, records) = errors(&log, &mut 1);
        assert_eq!(records[0].message, "b".repeat(MESSAGE_BYTES));
    }

    #[test]
    fn loss_records_round_trip() {
        let mut report = loss_report(2).unwrap();
        let record = LossRecord {
            time: 9,
            kind: 2,
            reason: 3,
            lane: 1,
            configured_policy: 4,
            applied_policy: 5,
            flags: 1,
            instance: u128::MAX - 7,
            stream_registration: 11,
            incarnation: 12,
            stream_id: 13,
            from: 100,
            to: 200,
            participant: 14,
            client: 15,
        };
        for time in 0..3 {
            report.record(&LossRecord { time, ..record }).unwrap();
        }
        let mut seen = Vec::new();
        let mut cursor = 0;
        let scan = report
            .reader()
            .scan(&mut cursor, |seq, read| seen.push((seq, read)));
        assert_eq!((scan.overwritten, scan.delivered, cursor), (1, 2, 3));
        assert_eq!(
            seen,
            [
                (1, LossRecord { time: 1, ..record }),
                (2, LossRecord { time: 2, ..record })
            ]
        );
    }

    #[test]
    fn a_zero_capacity_is_refused() {
        assert!(error_log(0, 0).is_err());
        assert!(loss_report(0).is_err());
    }

    // Miri cannot execute memfd_create (karyos#924).
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn a_tool_reads_the_regions_read_only() {
        use crate::ipc::{ReadOnlyRegion, RegionKind, SealProfile};

        fn read_only(region: &crate::ipc::Region, kind: RegionKind) -> ReadOnlyRegion {
            let fd = region.descriptor().unwrap().try_clone_to_owned().unwrap();
            let mut record = region.record();
            record.kind = kind;
            ReadOnlyRegion::attach(fd, record, SealProfile::DriverOnly).unwrap()
        }

        let mut log = error_log_in(5, 1, 8, 10).unwrap();
        log.report(1, 3, 2, [1, 2], "hello").unwrap();
        let region = log.region().unwrap();
        let reader =
            ErrorLogReader::attach_read_only(read_only(region, RegionKind::ErrorLog)).unwrap();
        let mut records = Vec::new();
        reader.scan(&mut 0, |record| records.push(record));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "hello");
        // A writer's later record reaches the read-only mapping.
        log.report(2, 4, 2, [1, 2], "again").unwrap();
        let mut cursor = 1;
        let scan = reader.scan(&mut cursor, |_| {});
        assert_eq!((scan.delivered, cursor), (1, 2));

        let mut report = loss_report_in(5, 2, 4).unwrap();
        report
            .record(&LossRecord {
                time: 3,
                ..LossRecord::default()
            })
            .unwrap();
        let region = report.region().unwrap();
        // An error log reader refuses a loss report region.
        let ro = read_only(region, RegionKind::LossReport);
        assert!(ErrorLogReader::attach_read_only(ro).is_err());
        let reader =
            LossReportReader::attach_read_only(read_only(region, RegionKind::LossReport)).unwrap();
        let mut times = Vec::new();
        reader.scan(&mut 0, |_, record| times.push(record.time));
        assert_eq!(times, [3]);
    }
}
