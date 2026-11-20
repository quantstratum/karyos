// SPDX-License-Identifier: Apache-2.0

//! The raw trace export (R-CORE-13): pages of a driver's trace mirror
//! records, read straight from the mirror with a cursor the reader keeps.
//!
//! - **The cursor.** A mirror ring sequence: unique and increasing within
//!   one driver instance, so a page ends at `next` and the next page starts
//!   there, with no record delivered twice and none skipped that the mirror
//!   still holds. The agent keeps nothing per reader: a cursor survives the
//!   reader's restart and the agent's alike.
//! - **The epoch.** The driver instance the sequences belong to. A new
//!   instance starts its ring over, so a cursor of another instance is
//!   refused, typed, with the new epoch, and the reader starts again from
//!   0; a new instance is never a jump in one sequence. Unlike the trace
//!   buckets' epoch (R-CORE-23), which names the agent's window run because
//!   the buckets live in the agent, this one names the driver because the
//!   records live in the driver's mirror.
//! - **Loss, explicit.** A cursor behind the ring's retention is not
//!   refused: the page starts at the oldest record and states the lost
//!   sequences, typed `overwritten`. A record overwritten while the page is
//!   read is never delivered torn (the ring's seqlock): it is lost too, and
//!   the page ends before it. A malformed record (its length past the
//!   payload bound) is never delivered: it is lost, typed `malformed`, and
//!   the page goes on. Every loss is below `next` and stated once across
//!   pages.
//! - **Whole records.** A page holds whole records, at most `count` of
//!   them, within the reply's byte bound ([`crate::api::MAX_EXPORT_REPLY`]
//!   plus one record and one journal); the read alone decides where it
//!   ends, `next` naming the first record left out.
//! - **The table.** Each page names the journals its records come from, as
//!   the table showed them when the page was read: the entry (with the
//!   clock provenance, the time namespace and the drop ranges a record
//!   needs to be decoded and calibrated), the recycle log's entry for a
//!   journal recycled since, unknown (gone from both, every entry read),
//!   or unreadable: an entry still being written after its wait while the
//!   page's first record was its journal's, whose records in the page then
//!   all go out without calibration. Otherwise the page ends before a
//!   record whose journal was not read. The table is read, its busy
//!   entries waited for, before the log, as the driver writes a log entry
//!   before it reuses a table entry.
//! - **Bounds.** At most [`crate::api::EXPORT_MAX`] records per page, read
//!   in batches that stop where the page ends, and a pass over the table
//!   and one over the log, the busy entries of each retried for
//!   `BUSY_BUDGET` (1 ms), which each part may overrun by one yield and
//!   one more read of its busy entries.
//! - **The trade-off of a stuck entry.** When the entry of the page's
//!   first record's journal stays busy past its wait, every record of that
//!   journal in the page goes out uncalibrated, those the entry would have
//!   calibrated had it come free included. The agent keeps no memory of a
//!   stuck entry across requests (that needs the entry's version word in
//!   the reader API), so each request whose records name a journal not
//!   found while an entry is stuck waits for it again: about 1 ms for the
//!   table, then up to 1 ms for the log.

use std::collections::BTreeSet;

use karyos_sys::counters::{CellRead, CountersReader, TYPE_TRACE_POINT};
use karyos_sys::trace_mirror::{EntryRead, LogRead, TraceMirrorReader};

use crate::api::{
    ExportJournal, ExportLoss, ExportPage, ExportPoint, ExportRecord, ExportRefusal, LossReason,
};

/// Overwrites within one page retried at most before the page ends.
pub(crate) const OVERWRITE_RETRIES: usize = 4;
/// Overwritten ranges one page states at most: the cursor's own and one
/// per overwrite retry. Malformed records are counted in the byte bound,
/// one range each.
pub(crate) const MAX_LOST_RANGES: usize = OVERWRITE_RETRIES + 1;
/// The bytes one lost range takes in a reply at most.
pub(crate) const LOSS_BYTES: usize = 96;
/// Records one scan of a page reads at most, so a page that ends early
/// copies no more than this past its end.
const SCAN_BATCH: usize = 64;
#[cfg(test)]
thread_local! {
    /// Tests: run while busy table entries are waited for, to recycle a
    /// journal there.
    pub(crate) static DURING_TABLE_WAIT: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
    /// Tests: run while busy log entries are waited for, to release one
    /// there.
    pub(crate) static DURING_LOG_WAIT: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
    /// Tests: run between two batches of a page, to lap the ring there.
    pub(crate) static BETWEEN_BATCHES: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
}
/// The time a read of the table, and then one of the log, waits for
/// entries being written, yielding between attempts: a driver writes an entry in
/// a few stores, so a busy entry is a writer mid-write, which this waits
/// out unless it was preempted or stopped there; 1 ms is past any write
/// but a preempted one, and short enough not to hold the agent.
const BUSY_BUDGET: std::time::Duration = std::time::Duration::from_millis(1);
/// Reads of the ring's bounds retried while a publication is in progress.
const BUSY_RETRIES: usize = 16;

/// Up to `count` records (at most [`crate::api::EXPORT_MAX`]) of
/// `mirror`, with the application points they reference named from
/// `points` (the driver counters region, whose trace point cells the
/// driver writes; R-CORE-1, karyos#869), of driver instance
/// `epoch`, from sequence `from` on, in a
/// reply of at most `max_bytes` plus one record and one journal; `asked` is
/// the epoch of the reader's cursor, if it has one.
///
/// The read stops where the page must end: at the byte bound, before a
/// record overwritten under it, and before the first record whose journal
/// could not be read (busy: the reader retries), unless that journal is
/// the first record's, whose records all go out `unreadable`; `next` names
/// where. A malformed record is lost, with its sequence and reason, and
/// the page goes on.
///
/// # Errors
///
/// [`ExportRefusal::EpochChanged`] when `asked` is another instance;
/// [`ExportRefusal::Ahead`] for a cursor beyond the ring's next sequence;
/// [`ExportRefusal::Busy`] when the ring's bounds could not be read.
pub fn export(
    mirror: &TraceMirrorReader,
    points: Option<&CountersReader>,
    epoch: u128,
    from: u64,
    count: usize,
    asked: Option<u128>,
    max_bytes: usize,
) -> Result<ExportPage, ExportRefusal> {
    export_within(
        mirror,
        points,
        (epoch, asked),
        from,
        count,
        max_bytes,
        Waits {
            busy_budget: BUSY_BUDGET,
            max_lost_ranges: MAX_LOST_RANGES,
        },
    )
}

/// What one export waits for and states at most: the time busy entries are
/// waited for, in the table and then in the log, and the overwritten
/// ranges a page states.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Waits {
    pub(crate) busy_budget: std::time::Duration,
    pub(crate) max_lost_ranges: usize,
}

/// [`export`] with its [`Waits`]: `busy_budget` for table entries being
/// written, then as much for log entries, and `max_lost_ranges`
/// overwritten ranges.
pub(crate) fn export_within(
    mirror: &TraceMirrorReader,
    points: Option<&CountersReader>,
    (epoch, asked): (u128, Option<u128>),
    from: u64,
    count: usize,
    max_bytes: usize,
    Waits {
        busy_budget,
        max_lost_ranges,
    }: Waits,
) -> Result<ExportPage, ExportRefusal> {
    if asked.is_some_and(|asked| asked != epoch) {
        return Err(ExportRefusal::EpochChanged { epoch });
    }
    let bounds = (0..BUSY_RETRIES)
        .find_map(|_| mirror.bounds())
        .ok_or(ExportRefusal::Busy)?;
    // A cursor past what the ring has given: another instance's, or a
    // reader's error. Never served as caught up.
    if from > bounds.next {
        return Err(ExportRefusal::Ahead { next: bounds.next });
    }
    let count = count.min(crate::api::EXPORT_MAX);
    let mut cursor = from;
    let mut lost: Vec<ExportLoss> = Vec::new();
    let mut records: Vec<ExportRecord> = Vec::new();
    let mut named = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    let mut used = crate::json::EXPORT_REPLY_OVERHEAD;
    let mut stop = None;
    let note = |lost: &mut Vec<ExportLoss>, first: u64, last: u64, reason: LossReason| match lost
        .last_mut()
    {
        Some(previous) if previous.reason == reason && previous.last.saturating_add(1) == first => {
            previous.last = last;
        }
        _ => lost.push(ExportLoss {
            first,
            last,
            reason,
        }),
    };
    // In batches, so the read stops where the page ends instead of
    // copying the rest of the count.
    let mut scanned = 0usize;
    let mut retries = 0;
    let mut overwritten_ranges = 0usize;
    loop {
        let batch = count.saturating_sub(scanned).min(SCAN_BATCH);
        if batch == 0 {
            break;
        }
        let before = cursor;
        let (kept, lost_kept) = (records.len(), lost.len());
        let scan = mirror.scan_at_most(
            &mut cursor,
            u64::try_from(batch).unwrap_or(u64::MAX),
            |record| {
                if stop.is_some() {
                    return;
                }
                scanned += 1;
                // A malformed record is never delivered: it is lost, with
                // its sequence, counted in the bound, and the page goes on.
                if record.truncated {
                    if used.saturating_add(LOSS_BYTES) > max_bytes && !records.is_empty() {
                        stop = Some(record.seq);
                    } else {
                        used = used.saturating_add(LOSS_BYTES);
                        note(&mut lost, record.seq, record.seq, LossReason::Malformed);
                    }
                    return;
                }
                // Measured before it is copied: a record past the bound
                // costs no allocation.
                let journal = if named.contains(&record.journal) {
                    0
                } else {
                    crate::api::MAX_JOURNAL_REPLY
                };
                let point = application_point(record.payload);
                let point_bytes = match point {
                    Some(id) if !referenced.contains(&id) => crate::api::MAX_POINT_REPLY,
                    _ => 0,
                };
                let size = crate::json::export_record_len_of(
                    record.seq,
                    record.journal,
                    record.sequence,
                    record.payload,
                )
                .saturating_add(journal)
                .saturating_add(point_bytes);
                if !records.is_empty() && used.saturating_add(size) > max_bytes {
                    stop = Some(record.seq);
                    return;
                }
                used = used.saturating_add(size);
                let _ = named.insert(record.journal);
                if let Some(id) = point {
                    let _ = referenced.insert(id);
                }
                records.push(ExportRecord {
                    seq: record.seq,
                    journal: record.journal,
                    sequence: record.sequence,
                    payload: record.payload.to_vec(),
                });
            },
        );
        if scan.overwritten > 0 {
            if kept > 0 {
                // Lapped after this page's first records: the page ends
                // where it was, so its loss is never stated after them; the
                // next read states it first.
                records.truncate(kept);
                lost.truncate(lost_kept);
                stop = Some(before);
                break;
            }
            note(
                &mut lost,
                before,
                before + scan.overwritten - 1,
                LossReason::Overwritten,
            );
            overwritten_ranges += 1;
            // The reply's overhead holds MAX_LOST_RANGES of them: the
            // page ends at the last one it can state.
            if overwritten_ranges >= max_lost_ranges {
                break;
            }
        }
        if stop.is_some() {
            break;
        }
        match scan.stopped {
            // Overwritten under the reader: the next scan's boundary proves
            // it and states it as lost, in this page while it has no record
            // yet (the loss comes first), else in the next one.
            Some(karyos_sys::diag_ring::ScanStop::Overwritten) => {
                if !records.is_empty() || retries == OVERWRITE_RETRIES {
                    break;
                }
                retries += 1;
            }
            Some(karyos_sys::diag_ring::ScanStop::Busy) => break,
            // The end of what the ring holds.
            None if usize::try_from(scan.delivered).unwrap_or(usize::MAX) < batch => break,
            None => {}
        }
        #[cfg(test)]
        BETWEEN_BATCHES.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
    }
    let mut next = stop.unwrap_or(cursor);
    let refused_before = mirror.network_journals_refused();
    let (mut journals, unread) = journals(mirror, &records, busy_budget);
    let refused_after = mirror.network_journals_refused();
    // Records whose journal could not be read are not decodable: the page
    // ends before the first of them, and the reader retries. When that is
    // the page's first record, an entry stayed busy past the budget: the
    // agent keeps no state to tell a writer stopped mid-write from an
    // unlucky moment, so nothing is lost and the cursor never stalls: that
    // journal's records in the page all go out without calibration, its
    // journal `unreadable`, so a stuck entry costs one wait per page, not
    // one per run of its records. The page ends at the first record of
    // another journal left unread.
    let mut unreadable = None;
    if let Some(first) = records
        .first()
        .filter(|record| unread.contains(&record.journal))
        .map(|record| record.journal)
    {
        unreadable = Some(first);
        journals.push(ExportJournal::Unreadable { journal: first });
        journals.sort_by_key(journal_number);
    }
    if let Some(at) = records
        .iter()
        .position(|record| Some(record.journal) != unreadable && unread.contains(&record.journal))
    {
        next = records.get(at).map_or(next, |record| record.seq);
        records.truncate(at);
    }
    // Nothing is stated past where the page ends: a page cut before a
    // record drops what lies after it, and no range crosses the cut, as an
    // overwritten range precedes every record and a malformed one is one
    // sequence.
    lost.retain(|loss| loss.first < next);
    debug_assert!(
        lost.iter().all(|loss| loss.last < next),
        "{lost:?} past {next}"
    );
    // Kept in release too: a range past the end is never stated.
    for loss in &mut lost {
        loss.last = loss.last.min(next.saturating_sub(1));
    }
    lost.sort_by_key(|loss| loss.first);
    let kept: BTreeSet<u64> = records.iter().map(|record| record.journal).collect();
    let journals: Vec<ExportJournal> = journals
        .into_iter()
        .filter(|journal| kept.contains(&journal_number(journal)))
        .collect();
    // Records without calibration, by why: one pass.
    let (mut unknown_records, mut unreadable_records) = (0usize, 0usize);
    for record in &records {
        match journals
            .binary_search_by_key(&record.journal, journal_number)
            .ok()
            .and_then(|at| journals.get(at))
        {
            Some(ExportJournal::Unknown { .. }) => unknown_records += 1,
            Some(ExportJournal::Unreadable { .. }) => unreadable_records += 1,
            _ => {}
        }
    }
    let points = name_points(points, &records, &journals);
    // The head is the ring's, read again after the page, never the cursor.
    let head = (0..BUSY_RETRIES)
        .find_map(|_| mirror.bounds())
        .map_or(bounds.next, |now| now.next);
    Ok(ExportPage {
        epoch,
        from,
        lost,
        records,
        next,
        head,
        journals,
        points,
        unknown_records: u64::try_from(unknown_records).unwrap_or(u64::MAX),
        unreadable_records: u64::try_from(unreadable_records).unwrap_or(u64::MAX),
        network_journals_refused: crate::api::RefusedReads {
            attach: None,
            before: refused_before,
            after: refused_after,
        },
    })
}

/// The application point id of a karyos-trace record payload (layout
/// version 4, point code 9, the id in word 16's low 16 bits), if it is
/// one. Read without decoding the record: the export delivers payloads as
/// they are, and a malformed one only goes unnamed.
fn application_point(payload: &[u64]) -> Option<u16> {
    let head = *payload.first()?;
    let id = *payload.get(16)? as u16;
    (head & 0xFF == 4 && (head >> 8) & 0xFF == 9 && id != 0).then_some(id)
}

/// The application points `records` reference, by id, named from the
/// driver's own copy of each trace point in the driver counters region
/// (karyos#869), which clients never write: a client rewriting its own
/// cell's value changes no name. A point is named only by the single live
/// trace point cell holding its id, and only when every record
/// referencing the id is in a live journal of that cell's client. A record
/// in a recycled, unknown or unreadable journal has no client to check, so
/// its id goes unnamed; so does a point whose copy found no free cell.
fn name_points(
    points: Option<&CountersReader>,
    records: &[ExportRecord],
    journals: &[ExportJournal],
) -> Vec<ExportPoint> {
    // Each referenced id with the clients of the journals its records are
    // in; `None` once one of them is not a live journal.
    let mut referenced: std::collections::BTreeMap<u16, Option<BTreeSet<u64>>> = Default::default();
    for record in records {
        let Some(id) = application_point(&record.payload) else {
            continue;
        };
        let live = match journals
            .binary_search_by_key(&record.journal, journal_number)
            .ok()
            .and_then(|at| journals.get(at))
        {
            Some(ExportJournal::Live(entry)) => Some(entry.client),
            _ => None,
        };
        let clients = referenced
            .entry(id)
            .or_insert_with(|| Some(BTreeSet::new()));
        match (clients.as_mut(), live) {
            (Some(clients), Some(client)) => {
                let _ = clients.insert(client);
            }
            _ => *clients = None,
        }
    }
    if referenced.is_empty() {
        return Vec::new();
    }
    // The trace point cells holding a referenced id: label and client.
    let mut cells: std::collections::BTreeMap<u16, Vec<(String, u64)>> = Default::default();
    if let Some(reader) = points {
        for index in 0..reader.capacity() {
            let CellRead::Allocated {
                metadata, value, ..
            } = reader.read(index)
            else {
                continue;
            };
            let Ok(id) = u16::try_from(value) else {
                continue;
            };
            if metadata.type_id == TYPE_TRACE_POINT && referenced.contains_key(&id) {
                cells.entry(id).or_default().push((
                    String::from_utf8_lossy(metadata.label()).into_owned(),
                    metadata.keys.participant,
                ));
            }
        }
    }
    referenced
        .into_iter()
        .map(|(id, clients)| {
            let named = match cells.get(&id).map(Vec::as_slice) {
                Some([(label, client)])
                    if clients
                        .as_ref()
                        .is_some_and(|clients| clients.iter().all(|owner| owner == client)) =>
                {
                    Some((label.clone(), *client))
                }
                _ => None,
            };
            ExportPoint {
                id,
                label: named.as_ref().map(|(label, _)| label.clone()),
                client: named.map(|(_, client)| client),
            }
        })
        .collect()
}

/// The number of `journal`.
fn journal_number(journal: &ExportJournal) -> u64 {
    match journal {
        ExportJournal::Live(entry) => entry.journal,
        ExportJournal::Recycled(entry) => entry.journal,
        ExportJournal::Unknown { journal } | ExportJournal::Unreadable { journal } => *journal,
    }
}

/// The journals `records` name, from the table, then the recycle log, and
/// those that could not be read. An entry being written is retried, the
/// others read once: each part's busy entries again and again, yielding,
/// for `busy_budget` (1 ms) per part, so a writer preempted for a moment
/// mid-write is waited for. One still busy then may hold any journal, so a
/// journal found in neither part is unknown only when every entry was
/// read, and unread otherwise.
fn journals(
    mirror: &TraceMirrorReader,
    records: &[ExportRecord],
    busy_budget: std::time::Duration,
) -> (Vec<ExportJournal>, BTreeSet<u64>) {
    #[derive(Clone, Copy)]
    enum Slot {
        Table(usize),
        Log(usize),
    }
    let mut wanted: BTreeSet<u64> = records.iter().map(|record| record.journal).collect();
    let mut found = Vec::with_capacity(wanted.len());
    let take = |slot: Slot, found: &mut Vec<ExportJournal>, wanted: &mut BTreeSet<u64>| match slot {
        Slot::Table(index) => match mirror.entry(index) {
            EntryRead::Busy => false,
            EntryRead::Entry(entry) => {
                if wanted.remove(&entry.journal) {
                    found.push(ExportJournal::Live(Box::new(entry)));
                }
                true
            }
            EntryRead::Free => true,
        },
        Slot::Log(index) => match mirror.log_entry(index) {
            LogRead::Busy => false,
            LogRead::Entry(entry) => {
                if wanted.remove(&entry.journal) {
                    found.push(ExportJournal::Recycled(Box::new(entry)));
                }
                true
            }
            LogRead::Free => true,
        },
    };
    // One part: every slot read once, then its busy ones retried for the
    // budget, which each part has whole. Whether a busy entry was left.
    let part = |slots: &mut dyn Iterator<Item = Slot>,
                found: &mut Vec<ExportJournal>,
                wanted: &mut BTreeSet<u64>| {
        let mut busy = Vec::new();
        for slot in slots {
            if wanted.is_empty() {
                break;
            }
            if !take(slot, found, wanted) {
                busy.push(slot);
            }
        }
        // Each part retries its busy entries at least once, whatever the
        // clock says, so a thread preempted past the budget before its
        // first check still waits once.
        let start = std::time::Instant::now();
        let mut retried = false;
        while !busy.is_empty() && !wanted.is_empty() && (!retried || start.elapsed() < busy_budget)
        {
            retried = true;
            std::thread::yield_now();
            #[cfg(test)]
            {
                let during = match busy.first() {
                    Some(Slot::Table(_)) => &DURING_TABLE_WAIT,
                    _ => &DURING_LOG_WAIT,
                };
                during.with(|hook| {
                    if let Some(hook) = hook.borrow_mut().as_mut() {
                        hook();
                    }
                });
            }
            busy.retain(|slot| !take(*slot, found, wanted));
        }
        !busy.is_empty()
    };
    // The table first, its busy entries waited for, and only then the log:
    // the driver writes a log entry before it reuses a table entry, so a
    // journal recycled while the table is waited for is in the log read
    // after (trace-journal-region.md, "Recycling").
    let table_busy = part(
        &mut (0..mirror.entries()).map(Slot::Table),
        &mut found,
        &mut wanted,
    );
    let log_busy = part(
        &mut (0..mirror.log_entries()).map(Slot::Log),
        &mut found,
        &mut wanted,
    );
    let unread = if table_busy || log_busy {
        core::mem::take(&mut wanted)
    } else {
        BTreeSet::new()
    };
    found.extend(
        wanted
            .into_iter()
            .map(|journal| ExportJournal::Unknown { journal }),
    );
    found.sort_by_key(journal_number);
    (found, unread)
}

#[cfg(test)]
mod tests;
