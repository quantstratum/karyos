// SPDX-License-Identifier: Apache-2.0

//! A standby cluster over the harness (quantstratum-docs:
//! karyos/design/phase-5-cluster-scenarios.md §3, H3 and H4; ADR-0054;
//! SPEC.md §9, Operability), batch P5-S2.
//!
//! - **The standby** is a second group of servers in the same run, with
//!   its own voters and disks. Its service applies the primary's
//!   committed log with external effects disabled: it takes no client
//!   request and sends no reply until it is promoted.
//! - **The feed** stands in for ADR-0051's recording replication until
//!   that exists. Every [`FEED_PERIOD`] ticks the primary's leader sends
//!   its committed entries after the standby's verified position, each a
//!   [`FeedEntry`] with a checksum over its index, term and payload, over
//!   C1 links. The standby's leader checks each range by log matching
//!   (each entry the next index, its predecessor's term the one it holds)
//!   and checksum, proposes what passes to its own log
//!   ([`wrap`]), and refuses the rest. Its *verified position* is the
//!   last primary index its service applied; it acknowledges it, so the
//!   feed resends from there. A [`FeedFault`] damages one send of one
//!   index.
//! - **Fencing** before a promotion is either an operator-confirmed stop
//!   of every primary server or an [`ExternalLease`] that the primary's
//!   leader renews while the arbiter is reachable and must hold to take a
//!   command or release a reply. The arbiter judges the lease on the base
//!   clock, with a margin for the servers' clock skew.
//! - **Promotion** raises the generation. The standby's leader reports a
//!   [`PromotionReport`]: its verified position, the last commit position
//!   it learnt from the primary, a lower bound on the unknown interval,
//!   and every request known to be in flight. Every reply carries its
//!   server's generation, and a client rejects a lower one once it has
//!   seen a higher one.

use super::workloads::{Action, Case, Progress};
use crate::net::NodeId;

/// The tag every wrapped feed entry's bytes start with in the standby's
/// log.
pub const FEED_MAGIC: [u8; 4] = *b"KS5\x01";

/// Ticks between two feed sends of the primary's leader.
pub const FEED_PERIOD: u64 = 4;

/// Frame bytes per feed send at most (at least one entry).
pub const FEED_BATCH_BYTES: u64 = 16 * 1024;

/// The first index of every log the harness creates, the primary's
/// among them: the first entry the standby expects.
pub const PRIMARY_FIRST_INDEX: u64 = 1;

/// The generation of every server before a promotion.
pub const FIRST_GENERATION: u64 = 1;

/// One primary entry on the feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEntry {
    /// The primary's index.
    pub index: u64,
    /// Its term.
    pub term: u64,
    /// [`checksum`] of the index, term and payload, as the primary holds
    /// them.
    pub checksum: u64,
    /// The payload.
    pub payload: Vec<u8>,
}

/// FNV-1a over an entry's index and term (little endian) and payload.
#[must_use]
pub fn checksum(index: u64, term: u64, payload: &[u8]) -> u64 {
    let mut digest = 0xCBF2_9CE4_8422_2325u64;
    for byte in index
        .to_le_bytes()
        .iter()
        .chain(&term.to_le_bytes())
        .chain(payload)
    {
        digest ^= u64::from(*byte);
        // FNV's multiplication wraps by the hash's definition.
        digest = digest.wrapping_mul(0x0000_0100_0000_01B3);
    }
    digest
}

/// A primary entry as the standby proposes it: [`FEED_MAGIC`], the
/// primary's index and term, then the payload.
#[must_use]
pub fn wrap(index: u64, term: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = FEED_MAGIC.to_vec();
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.extend_from_slice(&term.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// The primary's index, term and payload of a wrapped entry, if it is one.
#[must_use]
pub fn unwrap(bytes: &[u8]) -> Option<(u64, u64, &[u8])> {
    let rest = bytes.strip_prefix(&FEED_MAGIC)?;
    let (index, rest) = rest.split_first_chunk::<8>()?;
    let (term, payload) = rest.split_first_chunk::<8>()?;
    Some((
        u64::from_le_bytes(*index),
        u64::from_le_bytes(*term),
        payload,
    ))
}

/// A damage to one send of one index on the feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFault {
    /// The payload's first byte flipped; the checksum is the original's.
    Corrupt,
    /// The term raised by one; the checksum is the original's. The
    /// checksum covers the term, so the standby refuses it as
    /// [`FeedRefusal::Checksum`]; [`FeedRefusal::Term`] is for a sender
    /// whose own log diverged, which these scenarios do not build.
    Term,
    /// The entry left out of the send; the later ones still sent.
    Skip,
}

/// Why the standby refused a feed entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedRefusal {
    /// Not the next index after the last one proposed.
    Gap,
    /// Its predecessor's term is not the one the standby holds.
    Term,
    /// The checksum does not match the entry.
    Checksum,
}

/// The lease the primary's leader must hold to take a command or release
/// a reply (one of SPEC.md §9's two ways to fence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalLease {
    /// Its length, in ticks of the holder's clock.
    pub duration: u64,
    /// When the holder last renewed it, on its own clock; `None` before
    /// the first renewal.
    pub renewed_at: Option<u64>,
    /// Whether the holder still reaches the arbiter, so renewals land.
    pub renewing: bool,
}

impl ExternalLease {
    /// A lease of `duration` ticks, not yet renewed.
    #[must_use]
    pub const fn new(duration: u64) -> Self {
        Self {
            duration,
            renewed_at: None,
            renewing: true,
        }
    }

    /// Whether the holder may act at `now`, on its own clock: before
    /// [`ExternalLease::end`].
    #[must_use]
    pub fn held_at(&self, now: u64) -> bool {
        self.end().is_some_and(|until| now < until)
    }

    /// The end of the last renewal, on the holder's clock: the fencing
    /// point, from which the holder neither takes a command nor releases
    /// a reply.
    #[must_use]
    pub fn end(&self) -> Option<u64> {
        self.renewed_at.and_then(|at| at.checked_add(self.duration))
    }

    /// Whether the arbiter sees it expired at `now` on the base clock,
    /// `margin` ticks past its end for the clocks' skew.
    #[must_use]
    pub fn expired_at(&self, now: u64, margin: u64) -> bool {
        !self.renewing
            && self
                .renewed_at
                .and_then(|at| at.checked_add(self.duration))
                .and_then(|until| until.checked_add(margin))
                .is_some_and(|after| now > after)
    }
}

/// How the old primary was fenced before a promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fencing {
    /// The operator stopped every primary server and confirmed it.
    OperatorStop,
    /// The primary's lease expired, as the arbiter judges it.
    Lease,
}

/// What a promoted standby reports (SPEC.md §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionReport {
    /// The generation it raised.
    pub generation: u64,
    /// The last primary index its service applied: every entry up to it
    /// survives.
    pub verified: Option<u64>,
    /// The last commit position it learnt from the primary: the unknown
    /// interval is at least from `verified` to it.
    pub learnt_commit: Option<u64>,
    /// The requests known to be in flight, by client and sequence: their
    /// outcome is unknown. The harness stands in for the clients and
    /// gateways that would report them (SPEC.md §9) and hands the list to
    /// the standby, which echoes it; no check derives it.
    pub unknown: Vec<(NodeId, u64)>,
}

/// The servers of every standby scenario: three in the primary, ids 0 to
/// 2, three in the standby, ids 3 to 5.
pub const PRIMARY: [NodeId; 3] = [0, 1, 2];
/// The standby's servers; its leader is the first.
pub const STANDBY: [NodeId; 3] = [3, 4, 5];

/// A primary of three and a standby of three under load.
fn followed(name: &str, operations: usize) -> Case {
    let mut case = Case::healthy(name, PRIMARY.len(), 2, operations);
    case.standby = STANDBY.len();
    case.retry_after = 60;
    case.steps = 900;
    case
}

/// S1, follow: the standby applies the primary's committed log with its
/// effects disabled, and its verified position reaches the primary's
/// commit.
#[must_use]
pub fn s1() -> Case {
    followed("S1 follow", 8)
}

/// S2, promotion after an operator stop: the operator stops the primary
/// with commands in flight and the standby is promoted. Entries up to its
/// verified position survive; the rest is reported unknown.
#[must_use]
pub fn s2() -> Case {
    let mut case = followed("S2 promote after an operator stop", 12);
    case.schedule = vec![
        (30, Action::OperatorStop),
        (31, Action::Promote(Fencing::OperatorStop)),
    ];
    case
}

/// The lease of S3, in ticks: short, so the old primary's answers the
/// standby never saw stay few enough for C3 to check.
pub const LEASE: u64 = 12;
/// The arbiter's margin past a lease's end.
pub const LEASE_MARGIN: u64 = 4;
/// The step at which S3 cuts the primary from the standby and the
/// arbiter, once the feed has caught up.
pub const S3_CUT: u64 = 40;

/// S3, promotion after the lease expired, the old primary alive: the
/// primary is cut from the standby and the arbiter but keeps its quorum
/// and its clients. It stops taking commands at its lease's end on its
/// own clock; the standby is promoted after the arbiter sees it expired.
/// Client 1 stays on the old primary, which must never answer it again:
/// its progress stops.
#[must_use]
pub fn s3() -> Case {
    let mut case = followed("S3 promote after the lease expired", 16);
    // Slow answers, so requests are still pending when the lease ends.
    case.reply_delay = 6;
    case.lease = Some(LEASE);
    case.lease_margin = LEASE_MARGIN;
    case.stay_on_primary = vec![1];
    case.progress = Progress::MayStop;
    case.schedule = vec![
        (S3_CUT, Action::CutArbiter),
        (
            S3_CUT,
            Action::Split {
                left: PRIMARY.to_vec(),
                right: STANDBY.to_vec(),
            },
        ),
        (
            S3_CUT + LEASE + LEASE_MARGIN + 4,
            Action::Promote(Fencing::Lease),
        ),
    ];
    case
}

/// S4, promotion before fencing: a promotion while the lease is held, and
/// one before any operator stop, are refused; nothing changes.
#[must_use]
pub fn s4() -> Case {
    let mut case = followed("S4 promotion before fencing", 8);
    case.lease = Some(400);
    case.lease_margin = LEASE_MARGIN;
    case.schedule = vec![
        (20, Action::Promote(Fencing::Lease)),
        (21, Action::Promote(Fencing::OperatorStop)),
    ];
    case
}

/// The primary indices S6 damages on the feed.
pub const S6_FAULTS: [(u64, FeedFault); 3] = [
    (3, FeedFault::Corrupt),
    (5, FeedFault::Term),
    (7, FeedFault::Skip),
];

/// S6, a damaged feed: a corrupted payload, a changed term and a skipped
/// index are refused before they apply, and the verified position moves
/// past them only once the feed resends them intact.
#[must_use]
pub fn s6() -> Case {
    let mut case = followed("S6 damaged feed", 8);
    case.feed_faults = S6_FAULTS.to_vec();
    case
}

/// S7, standby restart: the standby's leader and a follower crash while it
/// follows and restart; it resumes from its verified position.
#[must_use]
pub fn s7() -> Case {
    let mut case = followed("S7 standby restart", 12);
    case.schedule = vec![
        (15, Action::Crash(STANDBY[0])),
        (15, Action::Crash(STANDBY[1])),
        (40, Action::Restart(STANDBY[0])),
        (40, Action::Restart(STANDBY[1])),
    ];
    case
}

/// S1 to S4, S6 and S7; S5, a client's generations, is a test of the
/// client node.
#[must_use]
pub fn cases() -> Vec<Case> {
    vec![s1(), s2(), s3(), s4(), s6(), s7()]
}
