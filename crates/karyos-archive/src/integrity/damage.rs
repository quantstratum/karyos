// SPDX-License-Identifier: Apache-2.0

//! Detecting an index shortened by media damage (u5 of the review of
//! karyos#437; quantstratum-docs: karyos/SPEC.md §8.4; karyos#671).
//!
//! A2's recovery keeps every whole, checked write and cuts at the first
//! that is not, because the index is synced after the data: an unindexed
//! tail can be a write that was never acknowledged, and that rule stays.
//! The seal chain is the second source of truth. A range a seal covers
//! was durable when it was sealed, so a recovered store whose written end
//! falls below its recording's sealed end lost sealed bytes: that is
//! damage, never an unacknowledged write. An unindexed tail above the last
//! seal is still an unacknowledged write and is not reported.

use super::SealRecord;

/// A recording whose recovered store ends below what its seals cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortenedIndex {
    /// The recording.
    pub recording: u64,
    /// Where its recovered store ends.
    pub written: u64,
    /// Where its seals end.
    pub sealed_end: u64,
    /// The first seal record whose range the store no longer holds whole.
    pub counter: u64,
}

impl ShortenedIndex {
    /// The lost range, `[written, sealed_end)`.
    #[must_use]
    #[inline]
    pub const fn lost(&self) -> (u64, u64) {
        (self.written, self.sealed_end)
    }
}

/// The damage, if any, of `recording` recovered to `written` under the
/// chain `records`: `None` when its seals end at or below `written`.
#[must_use]
pub fn shortened_below_seal(
    records: &[SealRecord],
    recording: u64,
    written: u64,
) -> Option<ShortenedIndex> {
    let mut ranges = records
        .iter()
        .filter(|record| record.kind.is_range() && record.subject == recording);
    let sealed_end = ranges.clone().map(|record| record.end).max()?;
    if sealed_end <= written {
        return None;
    }
    let counter = ranges.find(|record| record.end > written)?.counter;
    Some(ShortenedIndex {
        recording,
        written,
        sealed_end,
        counter,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests, as ADR-0007 allows"
    )]

    use super::*;
    use crate::integrity::test_support::chain;

    #[test]
    fn a_store_ending_below_its_seals_is_damage_naming_the_first_lost_seal() {
        // Recording 3 sealed in eight-byte ranges to 32.
        let (_, records) = chain(4);
        let damage = shortened_below_seal(&records, 3, 12).unwrap();
        assert_eq!(damage.lost(), (12, 32));
        assert_eq!(damage.counter, records[1].counter);
        assert_eq!(
            shortened_below_seal(&records, 3, 0).unwrap().lost(),
            (0, 32)
        );
    }

    /// The damage injected on a `FaultDisk`: a synced, sealed store whose
    /// index the test shortens recovers below its seals, and the check
    /// names it; the recovery rule itself is unchanged.
    #[test]
    fn a_store_recovered_from_a_shortened_index_is_found_below_its_seals() {
        use std::path::Path;

        use crate::disk::Disk as _;
        use crate::fault::FaultDisk;
        use crate::integrity::journal::IntegrityJournal;
        use crate::segment::{Geometry, SegmentStore, SyncPolicy};

        let mut disk = FaultDisk::default();
        let dir = Path::new("/archive");
        let geometry = Geometry::new(64, 128).unwrap();
        let mut store =
            SegmentStore::create(disk.clone(), dir, 3, geometry, SyncPolicy::PerSegment, 0)
                .unwrap();
        let mut journal = IntegrityJournal::open(disk.clone(), dir).unwrap().journal;
        for (index, fill) in [1u8, 2].into_iter().enumerate() {
            let bytes = vec![fill; 32];
            let at = index as u64 * 32;
            store.append(at, &bytes).unwrap();
            journal.seal_segment(3, at, &bytes, false).unwrap();
        }
        store.sync().unwrap();
        drop(store);
        // The media damage: the index loses its last entry.
        let index = dir.join(format!("{:016x}-{:016x}.idx", 3, 0));
        let file = disk.open(&index).unwrap();
        let length = disk.len(&file).unwrap();
        disk.set_len(&file, length - 32).unwrap();
        let recovered =
            SegmentStore::recover(disk.clone(), dir, 3, geometry, SyncPolicy::PerSegment).unwrap();
        let written = recovered.store.written();
        assert_eq!(written, 32, "A2 keeps the indexed write only");
        let records = journal.records().unwrap();
        let damage = shortened_below_seal(&records, 3, written).unwrap();
        assert_eq!(damage.lost(), (32, 64));
    }

    #[test]
    fn a_tail_above_the_last_seal_or_an_unsealed_recording_is_not_damage() {
        let (_, records) = chain(4);
        assert_eq!(shortened_below_seal(&records, 3, 32), None);
        assert_eq!(shortened_below_seal(&records, 3, 40), None);
        assert_eq!(shortened_below_seal(&records, 9, 0), None);
    }
}
