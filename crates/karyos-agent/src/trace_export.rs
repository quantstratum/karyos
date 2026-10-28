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

use crate::api::{ExportJournal, ExportLoss, ExportPage, ExportRecord, ExportRefusal};

/// Overwrites within one page retried at most before the page ends.
const OVERWRITE_RETRIES: usize = 4;

/// Up to `count` records of `mirror`, of driver instance `epoch`, from
/// sequence `from` on; `asked` is the epoch of the reader's cursor, if it
/// has one.
///
/// # Errors
///
/// [`ExportRefusal::EpochChanged`] when `asked` is another instance.
pub fn export(
    mirror: &TraceMirrorReader,
    epoch: u128,
    from: u64,
    count: usize,
    asked: Option<u128>,
) -> Result<ExportPage, ExportRefusal> {
    if asked.is_some_and(|asked| asked != epoch) {
        return Err(ExportRefusal::EpochChanged { epoch });
    }
    let mut cursor = from;
    let mut lost = Vec::new();
    let mut records: Vec<ExportRecord> = Vec::new();
    let max = u64::try_from(count).unwrap_or(u64::MAX);
    for _ in 0..=OVERWRITE_RETRIES {
        let before = cursor;
        let left = max.saturating_sub(u64::try_from(records.len()).unwrap_or(u64::MAX));
        let scan = mirror.scan_at_most(&mut cursor, left, |record| {
            records.push(ExportRecord {
                seq: record.seq,
                journal: record.journal,
                sequence: record.sequence,
                payload: record.payload.to_vec(),
            });
        });
        if scan.overwritten > 0 {
            lost.push(ExportLoss {
                first: before,
                last: before + scan.overwritten - 1,
            });
        }
        // Overwritten under the reader: the next scan's boundary proves
        // it and states it as lost, in this page while it has no record
        // yet (the loss comes first), else in the next one.
        if scan.stopped != Some(karyos_sys::diag_ring::ScanStop::Overwritten) || !records.is_empty()
        {
            break;
        }
    }
    let head = mirror
        .bounds()
        .map_or(cursor, |bounds| bounds.next.max(cursor));
    Ok(ExportPage {
        epoch,
        from,
        lost,
        journals: journals(mirror, &records),
        records,
        next: cursor,
        head,
    })
}

/// The journals `records` name, from the table, then the recycle log.
fn journals(mirror: &TraceMirrorReader, records: &[ExportRecord]) -> Vec<ExportJournal> {
    let mut wanted: BTreeSet<u64> = records.iter().map(|record| record.journal).collect();
    let mut found = Vec::with_capacity(wanted.len());
    for index in 0..mirror.entries() {
        if wanted.is_empty() {
            break;
        }
        if let EntryRead::Entry(entry) = mirror.entry(index)
            && wanted.remove(&entry.journal)
        {
            found.push(ExportJournal::Live(Box::new(entry)));
        }
    }
    for index in 0..mirror.log_entries() {
        if wanted.is_empty() {
            break;
        }
        if let LogRead::Entry(entry) = mirror.log_entry(index)
            && wanted.remove(&entry.journal)
        {
            found.push(ExportJournal::Recycled(Box::new(entry)));
        }
    }
    found.extend(
        wanted
            .into_iter()
            .map(|journal| ExportJournal::Unknown { journal }),
    );
    found.sort_by_key(|journal| match journal {
        ExportJournal::Live(entry) => entry.journal,
        ExportJournal::Recycled(entry) => entry.journal,
        ExportJournal::Unknown { journal } => *journal,
    });
    found
}

#[cfg(test)]
mod tests;
