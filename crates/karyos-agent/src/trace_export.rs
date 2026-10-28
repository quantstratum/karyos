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
//!   sequences first, typed, before any record. A record overwritten while
//!   the page is read is never delivered torn (the ring's seqlock): it is
//!   lost too, stated the same way, and the page ends before it, so a
//!   page's loss always precedes its records.
//! - **Whole records.** A page holds whole records, at most `count` of
//!   them; the reply's byte bound ([`crate::api::MAX_EXPORT_REPLY`]) leaves
//!   whole records out, named by `next`.
//! - **The table.** Each page names the journals its records come from, as
//!   the table showed them when the page was read: the entry (with the clock
//!   provenance, the time namespace and the drop ranges a record needs to be
//!   decoded and calibrated), the recycle log's entry for a journal recycled
//!   since, or unknown.
//! - **Bounds.** At most [`crate::api::EXPORT_MAX`] records per page, read
//!   in one bounded scan, and one pass over the table and the log.

use std::collections::BTreeSet;

use karyos_sys::trace_mirror::{EntryRead, LogRead, TraceMirrorReader};

use crate::api::{ExportJournal, ExportLoss, ExportPage, ExportRecord, ExportRefusal, LossReason};

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
/// Reads of the ring's bounds, or of a table or log entry, retried while
/// a publication is in progress.
const BUSY_RETRIES: usize = 16;

/// Up to `count` records (at most [`crate::api::EXPORT_MAX`]) of
/// `mirror`, of driver instance `epoch`, from sequence `from` on, in a
/// reply of at most `max_bytes` plus one record and one journal; `asked` is
/// the epoch of the reader's cursor, if it has one.
///
/// The read stops where the page must end: at the byte bound, before a
/// record overwritten under it, and before the first record whose
/// journal's table entry could not be read (busy: the reader retries);
/// `next` names where. A malformed record is lost, with its sequence and
/// reason, and the page goes on.
///
/// # Errors
///
/// [`ExportRefusal::EpochChanged`] when `asked` is another instance;
/// [`ExportRefusal::Ahead`] for a cursor beyond the ring's next sequence;
/// [`ExportRefusal::Busy`] when the ring's bounds could not be read.
pub fn export(
    mirror: &TraceMirrorReader,
    epoch: u128,
    from: u64,
    count: usize,
    asked: Option<u128>,
    max_bytes: usize,
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
                let exported = ExportRecord {
                    seq: record.seq,
                    journal: record.journal,
                    sequence: record.sequence,
                    payload: record.payload.to_vec(),
                };
                let journal = if named.contains(&record.journal) {
                    0
                } else {
                    crate::api::MAX_JOURNAL_REPLY
                };
                let size = crate::json::export_record_len(&exported).saturating_add(journal);
                if !records.is_empty() && used.saturating_add(size) > max_bytes {
                    stop = Some(record.seq);
                    return;
                }
                used = used.saturating_add(size);
                let _ = named.insert(record.journal);
                records.push(exported);
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
    }
    let mut next = stop.unwrap_or(cursor);
    let (journals, unread) = journals(mirror, &records);
    if records
        .first()
        .is_some_and(|record| unread.contains(&record.journal))
    {
        // An entry busy on every attempt from the page's first record on
        // (a writer stopped mid-write leaves it so): its records are lost,
        // stated as such, rather than stalling the cursor for good.
        for record in records
            .iter()
            .filter(|record| unread.contains(&record.journal))
        {
            note(
                &mut lost,
                record.seq,
                record.seq,
                LossReason::UnreadableJournal,
            );
        }
        records.retain(|record| !unread.contains(&record.journal));
    } else if let Some(at) = records
        .iter()
        .position(|record| unread.contains(&record.journal))
    {
        // A record whose journal could not be read would not be
        // decodable: the page ends before it, and the reader retries.
        next = records.get(at).map_or(next, |record| record.seq);
        records.truncate(at);
    }
    // Nothing is stated past where the page ends.
    lost.retain(|loss| loss.first < next);
    for loss in &mut lost {
        loss.last = loss.last.min(next.saturating_sub(1));
    }
    lost.sort_by_key(|loss| loss.first);
    let kept: BTreeSet<u64> = records.iter().map(|record| record.journal).collect();
    let journals: Vec<ExportJournal> = journals
        .into_iter()
        .filter(|journal| kept.contains(&journal_number(journal)))
        .collect();
    let unknown: BTreeSet<u64> = journals
        .iter()
        .filter_map(|journal| match journal {
            ExportJournal::Unknown { journal } => Some(*journal),
            _ => None,
        })
        .collect();
    let unknown_records = records
        .iter()
        .filter(|record| unknown.contains(&record.journal))
        .count();
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
        unknown_records: u64::try_from(unknown_records).unwrap_or(u64::MAX),
    })
}

/// The number of `journal`.
fn journal_number(journal: &ExportJournal) -> u64 {
    match journal {
        ExportJournal::Live(entry) => entry.journal,
        ExportJournal::Recycled(entry) => entry.journal,
        ExportJournal::Unknown { journal } => *journal,
    }
}

/// The journals `records` name, from the table, then the recycle log, and
/// those that could not be read: a table or log entry busy on every
/// attempt may have been any of them, so a journal found in neither is
/// unknown only when every entry was read.
fn journals(
    mirror: &TraceMirrorReader,
    records: &[ExportRecord],
) -> (Vec<ExportJournal>, BTreeSet<u64>) {
    let mut wanted: BTreeSet<u64> = records.iter().map(|record| record.journal).collect();
    let mut found = Vec::with_capacity(wanted.len());
    let mut busy = false;
    for index in 0..mirror.entries() {
        if wanted.is_empty() {
            break;
        }
        let read = (0..BUSY_RETRIES)
            .map(|_| mirror.entry(index))
            .find(|read| !matches!(read, EntryRead::Busy))
            .unwrap_or(EntryRead::Busy);
        match read {
            EntryRead::Entry(entry) if wanted.remove(&entry.journal) => {
                found.push(ExportJournal::Live(Box::new(entry)));
            }
            EntryRead::Busy => busy = true,
            _ => {}
        }
    }
    for index in 0..mirror.log_entries() {
        if wanted.is_empty() {
            break;
        }
        let read = (0..BUSY_RETRIES)
            .map(|_| mirror.log_entry(index))
            .find(|read| !matches!(read, LogRead::Busy))
            .unwrap_or(LogRead::Busy);
        match read {
            LogRead::Entry(entry) if wanted.remove(&entry.journal) => {
                found.push(ExportJournal::Recycled(Box::new(entry)));
            }
            LogRead::Busy => busy = true,
            _ => {}
        }
    }
    if busy {
        found.sort_by_key(journal_number);
        return (found, wanted);
    }
    found.extend(
        wanted
            .into_iter()
            .map(|journal| ExportJournal::Unknown { journal }),
    );
    found.sort_by_key(journal_number);
    (found, BTreeSet::new())
}

#[cfg(test)]
mod tests;
