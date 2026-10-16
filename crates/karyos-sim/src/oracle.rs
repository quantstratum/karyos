// SPDX-License-Identifier: Apache-2.0

//! The oracle: what publishers recorded, and the checks every reader's
//! observation must pass (`quantstratum-docs: karyos/design/simulator-and-bench.md`).
//!
//! The simulator is single-threaded, so a publisher records each outcome
//! before any reader can observe the block: a delivered message must
//! already be recorded `Accepted` at its position.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use karyos_sys::log_buffer::Role;

use crate::payload::{Stamp, decode};

/// What publishers recorded on one stream, by stream position.
#[derive(Debug, Default)]
pub struct StreamRecord {
    accepted: BTreeMap<u64, Stamp>,
    aborted: BTreeSet<u64>,
}

impl StreamRecord {
    /// A publisher's message was accepted at `position`.
    ///
    /// # Errors
    ///
    /// Returns a description when the position was already used.
    pub fn accepted(&mut self, position: u64, stamp: Stamp) -> Result<(), String> {
        if self.aborted.contains(&position) {
            return Err(format!("{position} accepted after it was aborted"));
        }
        match self.accepted.insert(position, stamp) {
            None => Ok(()),
            Some(earlier) => Err(format!(
                "{position} accepted twice: {earlier:?} then {stamp:?}"
            )),
        }
    }

    /// A block at `position` will never carry a message: an abort, a lost
    /// commit, or a dropped or forgotten claim.
    ///
    /// # Errors
    ///
    /// Returns a description when the position was accepted.
    pub fn aborted(&mut self, position: u64) -> Result<(), String> {
        if self.accepted.contains_key(&position) {
            return Err(format!("{position} aborted after it was accepted"));
        }
        let _ = self.aborted.insert(position);
        Ok(())
    }

    /// Accepted messages at or above `from` and below `to`.
    pub fn accepted_in(&self, from: u64, to: u64) -> impl Iterator<Item = (&u64, &Stamp)> {
        self.accepted.range(from..to)
    }

    /// Messages accepted in total.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }
}

/// The key of `stamp` on a conflated stream of `keys` keys: derived from
/// the stamp, so the oracle and the publisher agree without sharing state.
#[must_use]
pub fn key_of(stamp: Stamp, keys: u32) -> u32 {
    stamp.publisher.wrapping_add(stamp.sequence) % keys.max(1)
}

impl StreamRecord {
    /// The latest accepted stamp of every key, by stream position: what a
    /// conflated view must hold once the writers are quiescent.
    #[must_use]
    pub fn latest_by_key(&self, keys: u32) -> BTreeMap<u32, Stamp> {
        let mut latest = BTreeMap::new();
        for stamp in self.accepted.values() {
            let _ = latest.insert(key_of(*stamp, keys), *stamp);
        }
        latest
    }

    /// Whether `stamp` was accepted.
    #[must_use]
    pub fn was_accepted(&self, stamp: Stamp) -> bool {
        self.accepted.values().any(|accepted| *accepted == stamp)
    }
}

/// A conflated view's observations (SPEC.md §7.1): per key, the last
/// version and value delivered.
#[derive(Debug, Default)]
pub struct ConflatedView {
    keys: u32,
    seen: BTreeMap<u32, (u64, Stamp)>,
    delivered: usize,
}

impl ConflatedView {
    /// A view of a stream of `keys` keys.
    #[must_use]
    pub fn new(keys: u32) -> Self {
        Self {
            keys,
            ..Self::default()
        }
    }

    /// Values delivered so far.
    #[must_use]
    pub fn delivered(&self) -> usize {
        self.delivered
    }

    /// A delivered value of `key` at `version`.
    ///
    /// # Errors
    ///
    /// Returns a description when the value is not a valid payload, names
    /// another key, was never accepted, or its version does not move
    /// forward.
    pub fn value(
        &mut self,
        record: &StreamRecord,
        key: u32,
        version: u64,
        bytes: &[u8],
    ) -> Result<(), String> {
        let stamp = decode(bytes).map_err(|why| format!("key {key}: {why}"))?;
        if key_of(stamp, self.keys) != key {
            return Err(format!("key {key} holds {stamp:?} of another key"));
        }
        if !record.was_accepted(stamp) {
            return Err(format!("key {key} holds {stamp:?}, never accepted"));
        }
        if let Some((before, _)) = self.seen.get(&key)
            && version <= *before
        {
            return Err(format!("key {key}: version {version} after {before}"));
        }
        let _ = self.seen.insert(key, (version, stamp));
        self.delivered += 1;
        Ok(())
    }

    /// The end-of-run check, with the writers quiescent: every key holds
    /// its latest accepted value.
    ///
    /// # Errors
    ///
    /// Returns the first key whose value is not the latest.
    pub fn complete(&self, record: &StreamRecord) -> Result<(), String> {
        for (key, stamp) in record.latest_by_key(self.keys) {
            match self.seen.get(&key) {
                Some((_, held)) if *held == stamp => {}
                other => {
                    return Err(format!(
                        "key {key} holds {other:?}, the latest accepted is {stamp:?}"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// One reader's observations.
#[derive(Debug)]
pub struct ReaderView {
    role: Role,
    /// Where it joined: messages from here on are its due.
    attach: u64,
    /// Highest position delivered or skipped so far.
    last: Option<u64>,
    delivered: BTreeSet<u64>,
    /// Per publisher, the last sequence delivered.
    sequences: HashMap<u32, u32>,
    /// Ranges an overrun reported lost: `[from, resume)`.
    lost: Vec<(u64, u64)>,
    /// The seal position, once the reader reached an end with no
    /// successor (removal, or a fence at a cutover).
    closed: Option<u64>,
    /// The read position at which the reader was revoked, its client lost.
    revoked: Option<u64>,
}

impl ReaderView {
    /// A reader of `role` that joined at `attach`.
    #[must_use]
    pub fn new(role: Role, attach: u64) -> Self {
        Self {
            role,
            attach,
            last: None,
            delivered: BTreeSet::new(),
            sequences: HashMap::new(),
            lost: Vec::new(),
            closed: None,
            revoked: None,
        }
    }

    /// The reader's role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// Messages delivered so far.
    #[must_use]
    pub fn delivered(&self) -> usize {
        self.delivered.len()
    }

    /// The end the reader reached, if any.
    #[must_use]
    pub fn closed(&self) -> Option<u64> {
        self.closed
    }

    /// The read position at which the reader was revoked, if it was.
    #[must_use]
    pub fn revoked(&self) -> Option<u64> {
        self.revoked
    }

    fn advance(&mut self, position: u64) -> Result<(), String> {
        if let Some(revoked) = self.revoked {
            return Err(format!(
                "{position} observed after the revocation at {revoked}"
            ));
        }
        if let Some(closed) = self.closed {
            return Err(format!("{position} observed after the end at {closed}"));
        }
        match self.last {
            Some(last) if position <= last => Err(format!(
                "position {position} not after the last observed {last}"
            )),
            _ => {
                self.last = Some(position);
                Ok(())
            }
        }
    }

    /// A delivered message.
    ///
    /// # Errors
    ///
    /// Returns a description of the first violated check.
    pub fn message(
        &mut self,
        record: &StreamRecord,
        position: u64,
        bytes: &[u8],
    ) -> Result<(), String> {
        let stamp = decode(bytes).map_err(|why| format!("at {position}: {why}"))?;
        self.advance(position)?;
        match record.accepted.get(&position) {
            Some(recorded) if *recorded == stamp => {}
            Some(recorded) => {
                return Err(format!(
                    "{position} delivered {stamp:?}, recorded {recorded:?}"
                ));
            }
            None => return Err(format!("{position} delivered {stamp:?}, never accepted")),
        }
        if !self.delivered.insert(position) {
            return Err(format!("{position} delivered twice"));
        }
        let previous = self.sequences.insert(stamp.publisher, stamp.sequence);
        if previous.is_some_and(|previous| previous >= stamp.sequence) {
            return Err(format!(
                "publisher {} sequence {} after {previous:?}",
                stamp.publisher, stamp.sequence
            ));
        }
        Ok(())
    }

    /// An aborted block the reader skipped.
    ///
    /// # Errors
    ///
    /// Returns a description when the block was accepted.
    pub fn aborted(&mut self, record: &StreamRecord, position: u64) -> Result<(), String> {
        self.advance(position)?;
        if record.accepted.contains_key(&position) {
            return Err(format!("accepted {position} reported aborted"));
        }
        Ok(())
    }

    /// An overrun. Only an optional reader may be overrun.
    ///
    /// # Errors
    ///
    /// Returns a description of an inconsistent or forbidden report.
    pub fn overrun(&mut self, from: u64, lost_to: u64, resume: u64) -> Result<(), String> {
        if self.role != Role::Optional {
            return Err(format!("a {:?} reader overrun at {from}", self.role));
        }
        if !(from <= lost_to && lost_to <= resume) {
            return Err(format!("overrun {from}..{lost_to}..{resume} out of order"));
        }
        if self.last.is_some_and(|last| from <= last) {
            return Err(format!("overrun from {from} at or before {:?}", self.last));
        }
        self.lost.push((from, resume));
        // Nothing below `resume` can be delivered after this.
        if resume > 0 {
            self.last = Some(resume - 1);
        }
        Ok(())
    }

    /// The reader reached an end with no successor.
    ///
    /// # Errors
    ///
    /// Returns a description when the end is not past everything observed,
    /// or the end moved. (Messages may follow on a successor the reader was
    /// fenced from, so the record is not checked here.)
    pub fn closed_at(&mut self, position: u64) -> Result<(), String> {
        if let Some(earlier) = self.closed {
            return if earlier == position {
                Ok(())
            } else {
                Err(format!("end moved from {earlier} to {position}"))
            };
        }
        if self.last.is_some_and(|last| last >= position) {
            return Err(format!("end {position} at or before {:?}", self.last));
        }
        self.closed = Some(position);
        Ok(())
    }

    /// The reader was revoked at read position `position`: its client was
    /// lost (`quantstratum-docs: karyos/design/required-participant-loss.md`).
    ///
    /// # Errors
    ///
    /// Returns a description when the position is not past everything
    /// observed, or moved.
    pub fn revoked_at(&mut self, position: u64) -> Result<(), String> {
        if let Some(earlier) = self.revoked {
            return if earlier == position {
                Ok(())
            } else {
                Err(format!("revocation moved from {earlier} to {position}"))
            };
        }
        if self.last.is_some_and(|last| last >= position) {
            return Err(format!(
                "revoked at {position}, at or before {:?}",
                self.last
            ));
        }
        self.revoked = Some(position);
        Ok(())
    }

    /// The end-of-run check: a required reader received every message
    /// accepted from its attach position up to its end, or up to its
    /// revocation: while it bounded the publisher it missed nothing.
    ///
    /// # Errors
    ///
    /// Returns the first message it missed.
    pub fn complete(&self, record: &StreamRecord) -> Result<(), String> {
        if self.role != Role::Required {
            return Ok(());
        }
        let end = self
            .closed
            .unwrap_or(u64::MAX)
            .min(self.revoked.unwrap_or(u64::MAX));
        for (position, stamp) in record.accepted_in(self.attach, end) {
            if !self.delivered.contains(position) {
                return Err(format!(
                    "required reader missed {stamp:?} at {position} (attach {}, end {end})",
                    self.attach
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::encode;

    fn stamp(sequence: u32) -> Stamp {
        Stamp {
            publisher: 1,
            sequence,
        }
    }

    fn record() -> StreamRecord {
        let mut record = StreamRecord::default();
        record.accepted(0, stamp(0)).unwrap();
        record.accepted(64, stamp(1)).unwrap();
        record.aborted(128).unwrap();
        record.accepted(192, stamp(3)).unwrap();
        record
    }

    #[test]
    fn a_correct_history_passes() {
        let record = record();
        let mut reader = ReaderView::new(Role::Required, 0);
        reader.message(&record, 0, &encode(stamp(0), 40)).unwrap();
        reader.message(&record, 64, &encode(stamp(1), 40)).unwrap();
        reader.aborted(&record, 128).unwrap();
        reader.message(&record, 192, &encode(stamp(3), 40)).unwrap();
        reader.complete(&record).unwrap();
    }

    // Negative controls: each injected fault must be reported.

    #[test]
    fn a_duplicate_delivery_is_reported() {
        let record = record();
        let mut reader = ReaderView::new(Role::Required, 0);
        reader.message(&record, 0, &encode(stamp(0), 40)).unwrap();
        assert!(reader.message(&record, 0, &encode(stamp(0), 40)).is_err());
    }

    #[test]
    fn a_dropped_accepted_message_is_reported() {
        let record = record();
        let mut reader = ReaderView::new(Role::Required, 0);
        reader.message(&record, 0, &encode(stamp(0), 40)).unwrap();
        reader.message(&record, 192, &encode(stamp(3), 40)).unwrap();
        assert!(reader.complete(&record).is_err());
    }

    #[test]
    fn a_revoked_reader_owes_only_what_preceded_its_revocation() {
        let record = record();
        let mut reader = ReaderView::new(Role::Required, 0);
        reader.message(&record, 0, &encode(stamp(0), 40)).unwrap();
        reader.revoked_at(64).unwrap();
        reader.complete(&record).unwrap();
        // Negative control: a gap before the revocation is still missed.
        let mut gap = ReaderView::new(Role::Required, 0);
        gap.revoked_at(64).unwrap();
        assert!(gap.complete(&record).is_err());
    }

    #[test]
    fn a_reordered_sequence_is_reported() {
        let mut record = StreamRecord::default();
        record.accepted(0, stamp(5)).unwrap();
        record.accepted(64, stamp(4)).unwrap();
        let mut reader = ReaderView::new(Role::Optional, 0);
        reader.message(&record, 0, &encode(stamp(5), 40)).unwrap();
        assert!(reader.message(&record, 64, &encode(stamp(4), 40)).is_err());
    }

    #[test]
    fn forbidden_or_inconsistent_reports_are_found() {
        let record = record();
        let mut required = ReaderView::new(Role::Required, 0);
        assert!(required.overrun(0, 64, 128).is_err());
        let mut optional = ReaderView::new(Role::Optional, 0);
        assert!(optional.overrun(64, 0, 128).is_err());
        optional.overrun(0, 64, 128).unwrap();
        assert!(
            optional
                .message(&record, 64, &encode(stamp(1), 40))
                .is_err()
        );
        let mut reader = ReaderView::new(Role::Optional, 0);
        assert!(reader.message(&record, 64, &encode(stamp(9), 40)).is_err());
        assert!(reader.aborted(&record, 192).is_err());
        let mut revoked = ReaderView::new(Role::Required, 0);
        revoked.message(&record, 64, &encode(stamp(1), 40)).unwrap();
        assert!(revoked.revoked_at(64).is_err());
        revoked.revoked_at(128).unwrap();
        assert!(revoked.revoked_at(192).is_err());
        assert!(revoked.aborted(&record, 128).is_err());
        let mut ended = ReaderView::new(Role::Required, 0);
        ended.closed_at(256).unwrap();
        assert!(ended.closed_at(320).is_err());
        assert!(ended.message(&record, 0, &encode(stamp(0), 40)).is_err());
        let mut twice = StreamRecord::default();
        twice.accepted(0, stamp(0)).unwrap();
        assert!(twice.accepted(0, stamp(1)).is_err());
        assert!(twice.aborted(0).is_err());
    }
}

#[cfg(test)]
mod conflated_tests {
    use super::*;
    use crate::payload::encode;

    #[test]
    fn a_conflated_view_checks_keys_versions_and_the_latest_value() {
        let stamp = |sequence| Stamp {
            publisher: 0,
            sequence,
        };
        let mut record = StreamRecord::default();
        // Keys of 2: sequences 0 and 2 are key 0, 1 is key 1.
        for (position, sequence) in [(0, 0), (64, 1), (128, 2)] {
            record.accepted(position, stamp(sequence)).unwrap();
        }
        let mut view = ConflatedView::new(2);
        view.value(&record, 0, 2, &encode(stamp(0), 40)).unwrap();
        view.value(&record, 1, 2, &encode(stamp(1), 40)).unwrap();
        // Negative controls: not the latest yet, a version going back, a
        // value of another key, a value never accepted.
        assert!(view.complete(&record).is_err());
        assert!(view.value(&record, 0, 2, &encode(stamp(2), 40)).is_err());
        assert!(view.value(&record, 0, 4, &encode(stamp(1), 40)).is_err());
        assert!(view.value(&record, 0, 4, &encode(stamp(4), 40)).is_err());
        view.value(&record, 0, 4, &encode(stamp(2), 40)).unwrap();
        view.complete(&record).unwrap();
    }
}
