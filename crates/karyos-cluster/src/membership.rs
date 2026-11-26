// SPDX-License-Identifier: Apache-2.0

//! A Cluster's membership: its voters and learners (quantstratum-docs:
//! karyos/SPEC.md §9, "Voting members are added and removed through
//! configuration entries in the replicated log ... A new member joins first
//! as a learner and is promoted only after it has caught up to a configured
//! lag"; "Learners. Non-voting members replicate the committed log and
//! snapshots without affecting quorum"; karyos#711).
//!
//! - **Mechanism.** Single-server changes, the one the custom core
//!   (ADR-0105) provides: each change adds a learner, promotes one learner
//!   to a voter, or removes one member, so any two consecutive voter sets
//!   overlap in a majority of each. With Ongaro's published errata: a
//!   leader proposes a change only once it has committed an entry of its
//!   own term, and only while no earlier change is uncommitted
//!   ([`crate::consensus::ChangeError::InProgress`]).
//! - **Effect.** A configuration takes effect on a node as soon as its
//!   entry is in the node's log, committed or not (Raft's rule): the latest
//!   configuration entry a log holds is the membership the node acts
//!   under, and a truncation that removes it restores the one before.
//! - **Bounds.** At most [`MAX_VOTERS`] voters and [`MAX_LEARNERS`]
//!   learners; the core's state is fixed in size, so it allocates nothing.
//! - **Entry.** A configuration entry is a core entry
//!   ([`MembershipEntry`], schema 5 template 2 over the ADR-0036 envelope,
//!   beside [`crate::service::SessionBounds`]): the voters and the
//!   learners, ascending. The service container delivers nothing for it.

use karyos_codec::{CodecError, Decoder, ENVELOPE_LENGTH, Encoder, Template};

use crate::consensus::MAX_VOTERS;
use crate::service::{CORE_SCHEMA_ID, CORE_VERSION, CORE_VERSION_1};

/// The most learners a membership holds at once.
pub const MAX_LEARNERS: usize = 2;
/// The most members, voters and learners.
pub const MAX_MEMBERS: usize = MAX_VOTERS + MAX_LEARNERS;
/// The fewest voters a change may leave: a cluster bootstraps with 3 or 5
/// and passes through 4.
pub const MIN_VOTERS: usize = 3;

/// Why a membership is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipError {
    /// No voter, or more than [`MAX_VOTERS`].
    #[error("a membership holds 1 to {MAX_VOTERS} voters, not {0}")]
    Voters(usize),
    /// More than [`MAX_LEARNERS`] learners.
    #[error("a membership holds at most {MAX_LEARNERS} learners, not {0}")]
    Learners(usize),
    /// A member of id 0, or one listed twice.
    #[error("a member id is 0 or repeated")]
    BadMember,
}

/// One membership change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipChange {
    /// Adds a learner: a non-voting member.
    AddLearner(u64),
    /// Makes a learner a voter.
    Promote(u64),
    /// Removes a member, voter or learner.
    Remove(u64),
}

/// A membership: voters and learners, each ascending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Membership {
    voters: [u64; MAX_VOTERS],
    voter_count: usize,
    learners: [u64; MAX_LEARNERS],
    learner_count: usize,
}

impl Membership {
    /// No member: what a validated configuration never holds.
    pub(crate) const EMPTY: Self = Self {
        voters: [0; MAX_VOTERS],
        voter_count: 0,
        learners: [0; MAX_LEARNERS],
        learner_count: 0,
    };

    /// The membership of `voters` and `learners`, in any order.
    ///
    /// # Errors
    ///
    /// [`MembershipError`] for each rule it breaks.
    pub fn new(voters: &[u64], learners: &[u64]) -> Result<Self, MembershipError> {
        if voters.is_empty() || voters.len() > MAX_VOTERS {
            return Err(MembershipError::Voters(voters.len()));
        }
        if learners.len() > MAX_LEARNERS {
            return Err(MembershipError::Learners(learners.len()));
        }
        let all = voters.iter().chain(learners);
        for (at, &member) in all.clone().enumerate() {
            if member == 0 || all.clone().take(at).any(|&seen| seen == member) {
                return Err(MembershipError::BadMember);
            }
        }
        let mut membership = Self {
            voters: [0; MAX_VOTERS],
            voter_count: voters.len(),
            learners: [0; MAX_LEARNERS],
            learner_count: learners.len(),
        };
        for (slot, &voter) in membership.voters.iter_mut().zip(voters) {
            *slot = voter;
        }
        for (slot, &learner) in membership.learners.iter_mut().zip(learners) {
            *slot = learner;
        }
        if let Some(live) = membership.voters.get_mut(..voters.len()) {
            live.sort_unstable();
        }
        if let Some(live) = membership.learners.get_mut(..learners.len()) {
            live.sort_unstable();
        }
        Ok(membership)
    }

    /// The voters, ascending.
    pub fn voters(&self) -> impl Iterator<Item = u64> + '_ {
        self.voters.iter().copied().take(self.voter_count)
    }

    /// The learners, ascending.
    pub fn learners(&self) -> impl Iterator<Item = u64> + '_ {
        self.learners.iter().copied().take(self.learner_count)
    }

    /// Every member and whether it votes: the voters first.
    pub fn members(&self) -> impl Iterator<Item = (u64, bool)> + '_ {
        self.voters()
            .map(|id| (id, true))
            .chain(self.learners().map(|id| (id, false)))
    }

    /// The voter count.
    #[must_use]
    pub const fn voter_count(&self) -> usize {
        self.voter_count
    }

    /// Whether `id` votes.
    #[must_use]
    pub fn is_voter(&self, id: u64) -> bool {
        self.voters().any(|voter| voter == id)
    }

    /// Whether `id` is a member, voter or learner.
    #[must_use]
    pub fn contains(&self, id: u64) -> bool {
        self.members().any(|(member, _)| member == id)
    }

    /// A majority of the voters.
    #[must_use]
    pub const fn quorum(&self) -> usize {
        self.voter_count / 2 + 1
    }

    /// The membership after `change`; `None` when it does not apply: a
    /// member added again, a promotion of anyone but a learner, the removal
    /// of a stranger, of a voter leaving fewer than [`MIN_VOTERS`], or a
    /// bound passed.
    #[must_use]
    pub fn changed(&self, change: MembershipChange) -> Option<Self> {
        let mut voters = [0; MAX_VOTERS];
        let mut learners = [0; MAX_LEARNERS + 1];
        let (mut v, mut l) = (0, 0);
        let push = |set: &mut [u64], count: &mut usize, id: u64| -> Option<()> {
            *set.get_mut(*count)? = id;
            *count += 1;
            Some(())
        };
        match change {
            MembershipChange::AddLearner(id) => {
                if self.contains(id) {
                    return None;
                }
                for voter in self.voters() {
                    push(&mut voters, &mut v, voter)?;
                }
                for learner in self.learners().chain([id]) {
                    push(&mut learners, &mut l, learner)?;
                }
            }
            MembershipChange::Promote(id) => {
                if !self.learners().any(|learner| learner == id) {
                    return None;
                }
                for voter in self.voters().chain([id]) {
                    push(&mut voters, &mut v, voter)?;
                }
                for learner in self.learners().filter(|&learner| learner != id) {
                    push(&mut learners, &mut l, learner)?;
                }
            }
            MembershipChange::Remove(id) => {
                if !self.contains(id) || (self.is_voter(id) && self.voter_count <= MIN_VOTERS) {
                    return None;
                }
                for voter in self.voters().filter(|&voter| voter != id) {
                    push(&mut voters, &mut v, voter)?;
                }
                for learner in self.learners().filter(|&learner| learner != id) {
                    push(&mut learners, &mut l, learner)?;
                }
            }
        }
        Self::new(voters.get(..v)?, learners.get(..l)?).ok()
    }
}

/// `Membership`, template 2 of schema 5 (the core's own entries): voter and
/// learner counts (one byte each), then [`MAX_MEMBERS`] ids of eight bytes,
/// the voters, then the learners, then zeros.
pub const MEMBERSHIP: Template = Template {
    schema_id: CORE_SCHEMA_ID,
    template_id: 2,
    version: CORE_VERSION,
    block_length: BLOCK as u16,
    max_length: ENVELOPE_LENGTH as u32 + BLOCK as u32,
};

const BLOCK: usize = 2 + 8 * MAX_MEMBERS;

/// A configuration entry's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipEntry(pub Membership);

impl MembershipEntry {
    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] for a short `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let membership = &self.0;
        let mut encoder = Encoder::new(out, &MEMBERSHIP)?;
        // Both counts are at most MAX_MEMBERS.
        encoder.u8(0, u8::try_from(membership.voter_count).unwrap_or(u8::MAX))?;
        encoder.u8(1, u8::try_from(membership.learner_count).unwrap_or(u8::MAX))?;
        for (at, (id, _)) in membership.members().enumerate() {
            encoder.u64(2 + 8 * at, id)?;
        }
        encoder.finish()
    }

    /// The message's bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0; MEMBERSHIP.max_length as usize];
        let length = self.encode(&mut out).unwrap_or(0);
        out.truncate(length);
        out
    }

    /// Whether `bytes` are a configuration entry's, by their envelope
    /// alone.
    #[must_use]
    pub fn is_one(bytes: &[u8]) -> bool {
        karyos_codec::Envelope::read(bytes).is_ok_and(|envelope| {
            envelope.schema_id == CORE_SCHEMA_ID && envelope.template_id == MEMBERSHIP.template_id
        })
    }

    /// Decodes exactly one `Membership` message from `bytes`.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 5,
    /// template 2, [`CodecError::ValueOutOfRange`] for counts or ids a
    /// membership refuses, and every other [`CodecError`] the envelope can
    /// raise.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let envelope = karyos_codec::Envelope::read(bytes)?;
        if envelope.schema_id != CORE_SCHEMA_ID
            || envelope.template_id != MEMBERSHIP.template_id
            || !matches!(envelope.version, CORE_VERSION | CORE_VERSION_1)
        {
            return Err(CodecError::UnsupportedSchema {
                schema: envelope.schema_id,
                template: envelope.template_id,
                version: envelope.version,
            });
        }
        let template = Template {
            version: envelope.version,
            ..MEMBERSHIP
        };
        let (block, decoder) = Decoder::new(bytes, &template)?;
        let voters = usize::from(block.u8(0)?);
        let learners = usize::from(block.u8(1)?);
        let out_of_range = CodecError::ValueOutOfRange {
            field: "membership",
        };
        if voters.saturating_add(learners) > MAX_MEMBERS {
            return Err(out_of_range);
        }
        let mut ids = [0u64; MAX_MEMBERS];
        for (at, slot) in ids.iter_mut().enumerate() {
            *slot = block.u64(2 + 8 * at)?;
        }
        // Unused slots are zero: one encoding per membership.
        if ids.iter().skip(voters + learners).any(|&id| id != 0) {
            return Err(out_of_range);
        }
        decoder.finish()?;
        let (voter_ids, rest) = ids.split_at(voters);
        let learner_ids = rest.get(..learners).ok_or(out_of_range)?;
        // Each list ascending: an unsorted list is another encoding of the
        // same membership, and one encoding per membership is the rule.
        let ascending = |list: &[u64]| list.windows(2).all(|pair| matches!(pair, [low, high] if low < high));
        if !ascending(voter_ids) || !ascending(learner_ids) {
            return Err(out_of_range);
        }
        let membership = Membership::new(voter_ids, learner_ids).map_err(|_| out_of_range)?;
        Ok(Self(membership))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_membership_is_sorted_and_bounded() {
        let membership = Membership::new(&[3, 1, 2], &[7]).unwrap();
        assert_eq!(membership.voters().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(membership.learners().collect::<Vec<_>>(), vec![7]);
        assert_eq!(membership.quorum(), 2);
        assert!(membership.is_voter(2) && !membership.is_voter(7));
        assert!(membership.contains(7) && !membership.contains(4));
        assert_eq!(Membership::new(&[], &[]), Err(MembershipError::Voters(0)));
        assert_eq!(
            Membership::new(&[1, 2, 3, 4, 5, 6], &[]),
            Err(MembershipError::Voters(6))
        );
        assert_eq!(
            Membership::new(&[1], &[2, 3, 4]),
            Err(MembershipError::Learners(3))
        );
        assert_eq!(
            Membership::new(&[1, 2], &[2]),
            Err(MembershipError::BadMember)
        );
        assert_eq!(Membership::new(&[0], &[]), Err(MembershipError::BadMember));
    }

    #[test]
    fn each_change_applies_only_where_it_makes_sense() {
        let three = Membership::new(&[1, 2, 3], &[]).unwrap();
        let joined = three.changed(MembershipChange::AddLearner(4)).unwrap();
        assert_eq!(joined, Membership::new(&[1, 2, 3], &[4]).unwrap());
        let four = joined.changed(MembershipChange::Promote(4)).unwrap();
        assert_eq!(four, Membership::new(&[1, 2, 3, 4], &[]).unwrap());
        assert_eq!(four.quorum(), 3);
        let back = four.changed(MembershipChange::Remove(1)).unwrap();
        assert_eq!(back, Membership::new(&[2, 3, 4], &[]).unwrap());
        // Never below three voters; a learner leaves freely.
        assert_eq!(back.changed(MembershipChange::Remove(2)), None);
        assert_eq!(joined.changed(MembershipChange::Remove(4)), Some(three));
        assert_eq!(three.changed(MembershipChange::AddLearner(2)), None);
        assert_eq!(three.changed(MembershipChange::Promote(2)), None);
        assert_eq!(three.changed(MembershipChange::Promote(9)), None);
        assert_eq!(three.changed(MembershipChange::Remove(9)), None);
        let one = Membership::new(&[1], &[]).unwrap();
        assert_eq!(one.changed(MembershipChange::Remove(1)), None);
        let full = Membership::new(&[1], &[2, 3]).unwrap();
        assert_eq!(full.changed(MembershipChange::AddLearner(4)), None);
        let five = Membership::new(&[1, 2, 3, 4, 5], &[6]).unwrap();
        assert_eq!(five.changed(MembershipChange::Promote(6)), None);
    }

    #[test]
    fn a_configuration_entry_round_trips_and_refuses_what_is_not_one() {
        let membership = Membership::new(&[1, 2, 3], &[4]).unwrap();
        let bytes = MembershipEntry(membership).to_vec();
        assert!(MembershipEntry::is_one(&bytes));
        assert_eq!(
            MembershipEntry::decode(&bytes),
            Ok(MembershipEntry(membership))
        );
        assert!(MembershipEntry::decode(&bytes[..bytes.len() - 1]).is_err());
        // A nonzero unused slot, a repeated id.
        let mut slot = bytes.clone();
        let last = slot.len() - 1;
        slot[last] = 1;
        assert!(MembershipEntry::decode(&slot).is_err());
        let repeated = {
            let mut out = vec![0; MEMBERSHIP.max_length as usize];
            let mut encoder = Encoder::new(&mut out, &MEMBERSHIP).unwrap();
            encoder.u8(0, 2).unwrap();
            encoder.u8(1, 0).unwrap();
            encoder.u64(2, 5).unwrap();
            encoder.u64(10, 5).unwrap();
            let length = encoder.finish().unwrap();
            out.truncate(length);
            out
        };
        assert!(MembershipEntry::decode(&repeated).is_err());
        // Voters out of order (vector P-8): ids 1, 3, 2.
        let mut unsorted = bytes.clone();
        unsorted[ENVELOPE_LENGTH + 10] = 3;
        unsorted[ENVELOPE_LENGTH + 18] = 2;
        assert_eq!(
            MembershipEntry::decode(&unsorted),
            Err(CodecError::ValueOutOfRange {
                field: "membership"
            })
        );
        // Another core entry is not one.
        let bounds = crate::service::SessionBounds::new(crate::dedup::DedupConfig::default())
            .to_vec()
            .unwrap();
        assert!(!MembershipEntry::is_one(&bounds));
        assert!(MembershipEntry::decode(&bounds).is_err());
        assert!(!MembershipEntry::is_one(b"command"));
    }
}

/// Golden vectors P-1 to P-11 of design/cluster-service-container.md §4.1,
/// derived from the documents alone (ADR-0087, ADR-0121, #712).
#[cfg(test)]
mod golden {
    use super::*;

    /// A schema 5 template 2 message: the envelope, then the two counts and
    /// seven ids, little endian.
    fn message(version: u16, block_length: u16, voters: u8, learners: u8, ids: [u64; MAX_MEMBERS]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(70);
        for half in [5u16, 2, version, block_length] {
            bytes.extend_from_slice(&half.to_le_bytes());
        }
        bytes.extend_from_slice(&70u32.to_le_bytes());
        bytes.extend_from_slice(&[voters, learners]);
        for id in ids {
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes
    }

    fn hex(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .map(|pair| u8::from_str_radix(pair, 16).unwrap_or_default())
            .collect()
    }

    const P1: &str = "05 00 02 00 02 00 3a 00 46 00 00 00 03 00 01 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    const P2: &str = "05 00 02 00 02 00 3a 00 46 00 00 00 03 01 01 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";

    #[test]
    fn the_golden_memberships_encode_to_their_bytes_and_back() {
        let p1 = MembershipEntry(Membership::new(&[1, 2, 3], &[]).expect("P-1"));
        let p2 = MembershipEntry(Membership::new(&[1, 2, 3], &[4]).expect("P-2"));
        assert_eq!(p1.to_vec(), hex(P1), "P-1");
        assert_eq!(p2.to_vec(), hex(P2), "P-2");
        assert_eq!(message(2, 58, 3, 0, [1, 2, 3, 0, 0, 0, 0]), hex(P1));
        assert_eq!(MembershipEntry::decode(&hex(P1)), Ok(p1));
        assert_eq!(MembershipEntry::decode(&hex(P2)), Ok(p2));
    }

    #[test]
    fn the_golden_refusals_refuse_with_their_errors() {
        let out_of_range = Err(CodecError::ValueOutOfRange { field: "membership" });
        let cases: [(&str, Vec<u8>); 7] = [
            ("P-3", message(2, 58, 0, 0, [0; MAX_MEMBERS])),
            ("P-4", message(2, 58, 6, 0, [1, 2, 3, 4, 5, 6, 0])),
            ("P-5", message(2, 58, 3, 3, [1, 2, 3, 4, 5, 6, 0])),
            ("P-6", message(2, 58, 3, 0, [1, 0, 3, 0, 0, 0, 0])),
            ("P-7", message(2, 58, 3, 0, [1, 3, 3, 0, 0, 0, 0])),
            ("P-8", message(2, 58, 3, 0, [1, 3, 2, 0, 0, 0, 0])),
            ("P-9", message(2, 58, 3, 0, [1, 2, 3, 9, 0, 0, 0])),
        ];
        for (name, bytes) in cases {
            assert_eq!(MembershipEntry::decode(&bytes), out_of_range, "{name}");
        }
        let p10 = message(2, 57, 3, 0, [1, 2, 3, 0, 0, 0, 0]);
        assert_eq!(
            MembershipEntry::decode(&p10),
            Err(CodecError::UnsupportedSchema { schema: 5, template: 2, version: 2 }),
            "P-10"
        );
        let full = hex(P1);
        let p11 = full.get(..69).unwrap_or_default();
        assert_eq!(
            MembershipEntry::decode(p11),
            Err(CodecError::MessageLength { declared: 70, actual: 69 }),
            "P-11"
        );
    }

    #[test]
    fn the_pinned_readings_hold() {
        // Version 1 decodes the same membership (ADR-0121 decision 7).
        assert_eq!(
            MembershipEntry::decode(&message(1, 58, 3, 0, [1, 2, 3, 0, 0, 0, 0])),
            MembershipEntry::decode(&hex(P1))
        );
        // One voter decodes; the 3-voter floor is the core's, not the codec's.
        assert!(MembershipEntry::decode(&message(2, 58, 1, 0, [7, 0, 0, 0, 0, 0, 0])).is_ok());
        // Learners need not sort after voters.
        assert!(MembershipEntry::decode(&message(2, 58, 3, 1, [5, 6, 7, 1, 0, 0, 0])).is_ok());
        // A voter also named as a learner is refused.
        assert_eq!(
            MembershipEntry::decode(&message(2, 58, 3, 1, [1, 2, 3, 3, 0, 0, 0])),
            Err(CodecError::ValueOutOfRange { field: "membership" })
        );
        // An unused slot after the learners must be zero.
        assert_eq!(
            MembershipEntry::decode(&message(2, 58, 3, 1, [1, 2, 3, 4, 9, 0, 0])),
            Err(CodecError::ValueOutOfRange { field: "membership" })
        );
    }
}
