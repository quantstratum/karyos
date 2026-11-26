// SPDX-License-Identifier: Apache-2.0

//! The standby cluster's follower of the primary's Cluster log
//! (quantstratum-docs: karyos/SPEC.md §9, "Standby cluster"; ADR-0120,
//! decisions 4 to 9; design/cluster-standby-replication.md; karyos#714).
//!
//! The primary's leading node replicates its Cluster log
//! ([`crate::log::LOG_RECORDING`]) over schema 6: its stored bytes from
//! [`crate::RaftLog::replication_start`] and its `ClusterLog` seals of
//! one epoch ([`crate::RaftLog::replication_seals`]). The standby's
//! leader feeds what arrives to a [`Standby`], transport neutral, which
//! holds:
//!
//! - **One copy per source.** A copy is one source node's bytes in one
//!   epoch (decision 4): positions and epochs are per node. Only one
//!   source is active (decision 5): another is refused
//!   ([`Refusal::Busy`]) until the active one ended or sent no status for
//!   [`StandbyConfig::status_interval`]. A new source, or a new start,
//!   starts a new copy and discards the old one.
//! - **Checks before apply** (decision 6). On each seal, in order: the
//!   seal verifies on the copy's own bytes ([`SealCheck`]); every frame of
//!   its range passes the log's frame check ([`crate::log::read_frame`]:
//!   magic, length, CRC-32C) and the range ends on a frame end; indices
//!   follow one another and terms never go down; and the copy is anchored
//!   at the standby's last position: frames up to it are skipped, the
//!   frame at it must carry its recorded term, a copy whose first frame is
//!   past it plus one is a gap, and a fresh standby starts only at
//!   [`StandbyConfig::primary_first_index`]. Anything that fails is
//!   refused whole: nothing is handed out and the verified position does
//!   not move. A copy cut short (a lost chunk) leaves the seal waiting
//!   ([`Sealed::Waiting`]); the sender resends from the copy's end.
//! - **The verified position `V`** (decision 7) is the highest primary
//!   index whose wrapped entry the standby group committed and its
//!   service applied ([`Standby::applied`]), with its primary term. After
//!   a restart or a standby leader change it is rebuilt from the
//!   standby's own log ([`verified_in`], [`Standby::rebuild`]) and the
//!   previous copy is discarded. Entries handed out ([`Sealed::Ready`])
//!   and not yet applied are the copy's *tail*: the anchor is the tail,
//!   so nothing is proposed twice from one copy.
//! - **A gap stops the follower** (decision 9): [`Refusal::Gap`], and
//!   every later call is [`Refusal::Stopped`] until a rebuild.
//!   Rebaselining from a snapshot is a later operation.
//! - **Reports** (decision 8): [`Standby::recovery_point`], never zero,
//!   and [`Standby::promote`]'s [`PromotionReport`].
//! - **Promotion is fenced** (SPEC §9, ADR-0054): refused until every old
//!   member's stop is operator-confirmed or the primary's external lease
//!   is seen expired ([`Fencing`]). It raises the generation; a client
//!   rejects a lower one once it saw a higher one
//!   ([`crate::client::ClusterClient`], karyos#720). External effects are
//!   enabled only after it ([`Standby::effects_enabled`]).
//!
//! **Later decisions, not here** (SPEC §9; owner decisions 2026-10-21,
//! item 44): automatic promotion, which needs an external arbiter, and a
//! synchronous standby profile, which would change ADR-0025's commit
//! rule. Promotion is manual and fenced, the standby asynchronous, and
//! unknown outcomes are reported as such.

use std::num::NonZeroU64;
use std::path::Path;

use karyos_archive::disk::Disk;
use karyos_archive::integrity::copies::{CopyCatalog, CopyRecord, CopyState, Enforcement};
use karyos_archive::integrity::journal::{IntegrityError, IntegrityJournal};
use karyos_archive::integrity::replication::{Replica, Verdict};
use karyos_archive::integrity::{Digest, SealKind, SealRecord, digest};
use karyos_archive::replication::SealScope;

use crate::log::{ChainProblem, LOG_RECORDING, read_frame};

/// The tag every wrapped primary entry starts with in the standby's log.
pub const WRAP_MAGIC: [u8; 4] = *b"KS5\x01";

/// A primary entry as the standby proposes it to its own log:
/// [`WRAP_MAGIC`], the primary's index and term (little endian), then the
/// payload.
#[must_use]
pub fn wrap(index: u64, term: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(payload.len().saturating_add(20));
    bytes.extend_from_slice(&WRAP_MAGIC);
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.extend_from_slice(&term.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// The primary's index, term and payload of a wrapped entry, if it is
/// one.
#[must_use]
pub fn unwrap(bytes: &[u8]) -> Option<(u64, u64, &[u8])> {
    let rest = bytes.strip_prefix(&WRAP_MAGIC)?;
    let (index, rest) = rest.split_first_chunk::<8>()?;
    let (term, payload) = rest.split_first_chunk::<8>()?;
    Some((
        u64::from_le_bytes(*index),
        u64::from_le_bytes(*term),
        payload,
    ))
}

/// A primary index and its term.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    /// The primary's index.
    pub index: u64,
    /// Its primary term.
    pub term: u64,
}

/// `V` from the standby's own committed log (ADR-0120 decision 7): the
/// highest primary index among the wrapped entries of `payloads`, the
/// committed and applied entries' payloads, with its term.
pub fn verified_in<'a>(payloads: impl IntoIterator<Item = &'a [u8]>) -> Option<Position> {
    payloads
        .into_iter()
        .filter_map(unwrap)
        .map(|(index, term, _)| Position { index, term })
        .max()
}

/// The seal check of a replicated range: the seam to schema 6's replica
/// verification (ADR-0102 decision 5).
///
/// [`Standby::seal`] calls it once the copy holds the seal's whole
/// range, with `bytes` the copy's own bytes of `[seal.start, seal.end)`
/// from `source`, after it checked the seal's kind (`ClusterLog`) and its
/// epoch. The implementation is [`ReplicaCheck`], schema 6's replica;
/// [`DigestCheck`] is a test double.
pub trait SealCheck {
    /// Whether `seal` of `source` verifies on `bytes`.
    ///
    /// # Errors
    ///
    /// Why it does not, for the report.
    fn verify(&mut self, source: u64, seal: &SealRecord, bytes: &[u8]) -> Result<(), String>;

    /// The standby discarded `source`'s copy of `epoch` from `from` on (a
    /// rebuild, a new source, a refused range): what was counted of it
    /// must no longer count, since its bytes are gone (karyos#714 review).
    fn discard(&mut self, source: u64, epoch: u64, from: u64) {
        let _ = (source, epoch, from);
    }
}

/// The schema 6 replica's verification of a Cluster log seal
/// (`Replica::verify_in` under `SealScope::cluster_log`, ADR-0102
/// decision 5, ADR-0120 decision 2): the range counts as a copy in the
/// standby's own copy catalog, recorded under [`LOG_RECORDING`], at a
/// location of its own per source node and epoch (decision 4).
#[derive(Debug)]
pub struct ReplicaCheck<D: Disk> {
    journal: IntegrityJournal<D>,
    copies: CopyCatalog<D>,
}

impl<D: Disk + Clone> ReplicaCheck<D> {
    /// The standby's integrity journal and copy catalog in `dir`.
    ///
    /// # Errors
    ///
    /// The journal's and the catalog's open errors.
    pub fn open(disk: D, dir: &Path) -> Result<Self, IntegrityError> {
        let mut journal = IntegrityJournal::open(disk.clone(), dir)?.journal;
        let copies = CopyCatalog::open(disk, dir, &mut journal)?;
        let mut check = Self { journal, copies };
        // The copies' bytes lived in the follower's memory, gone with the
        // process: nothing the catalog counts survives the reopen.
        check.remove(|_| true, 0)?;
        Ok(check)
    }

    /// Records as removed every verified copy under [`LOG_RECORDING`] at a
    /// location `at` admits that ends past `from`.
    fn remove(&mut self, at: impl Fn(&Digest) -> bool, from: u64) -> Result<(), IntegrityError> {
        let gone: Vec<CopyRecord> = self
            .copies
            .current()?
            .into_iter()
            .filter(|copy| {
                copy.recording == LOG_RECORDING
                    && copy.state == CopyState::Verified
                    && copy.end > from
                    && at(&copy.location)
            })
            .collect();
        for mut copy in gone {
            copy.state = CopyState::Removed;
            let _ = self.copies.record(copy, &mut self.journal)?;
        }
        Ok(())
    }

    /// The copies of `source`'s epoch `epoch` that verified, as the copy
    /// catalog counts them under [`LOG_RECORDING`] at their location.
    ///
    /// # Errors
    ///
    /// The catalog's read error.
    pub fn verified_copies(&self, source: u64, epoch: u64) -> Result<usize, IntegrityError> {
        let at = location(source, epoch);
        Ok(self
            .copies
            .current()?
            .into_iter()
            .filter(|copy| {
                copy.location == at
                    && copy.recording == LOG_RECORDING
                    && copy.state == CopyState::Verified
            })
            .count())
    }
}

/// The copy location of `source`'s epoch `epoch` (ADR-0120 decision 4).
#[must_use]
pub fn location(source: u64, epoch: u64) -> Digest {
    let mut bytes = b"karyos standby copy".to_vec();
    bytes.extend_from_slice(&source.to_le_bytes());
    bytes.extend_from_slice(&epoch.to_le_bytes());
    digest(&bytes)
}

impl<D: Disk + Clone> SealCheck for ReplicaCheck<D> {
    fn verify(&mut self, source: u64, seal: &SealRecord, bytes: &[u8]) -> Result<(), String> {
        let replica = Replica::new(location(source, seal.subject), 0, Enforcement::Unsupported);
        let scope = SealScope::cluster_log(LOG_RECORDING, seal.subject);
        match replica.verify_in(&mut self.copies, &mut self.journal, scope, seal, bytes) {
            Ok(Verdict::Counted(_) | Verdict::AlreadyCounted) => Ok(()),
            Ok(Verdict::Corrupt(inconsistency)) => Err(format!("{inconsistency:?}")),
            Err(error) => Err(format!("{error:?}")),
        }
    }

    fn discard(&mut self, source: u64, epoch: u64, from: u64) {
        let at = location(source, epoch);
        // A failure poisons the catalog: the next verify is refused.
        let _ = self.remove(|location| *location == at, from);
    }
}

/// A test double of the seam: the seal's content digest over the copy's
/// bytes, what a seal of kind 3 covers, with no catalog.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DigestCheck;

impl SealCheck for DigestCheck {
    fn verify(&mut self, _source: u64, seal: &SealRecord, bytes: &[u8]) -> Result<(), String> {
        let length = u64::try_from(bytes.len()).map_err(|_| "range too long".to_owned())?;
        if seal.end.checked_sub(seal.start) != Some(length) {
            return Err(format!(
                "{length} bytes for a seal of {}..{}",
                seal.start, seal.end
            ));
        }
        if digest(bytes) == seal.content {
            Ok(())
        } else {
            Err(format!(
                "content digest differs over {}..{}",
                seal.start, seal.end
            ))
        }
    }
}

/// How long the committed tail past the last seal may be (ADR-0120
/// decision 8): it is unknown, and bounded by one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailBound {
    /// The source's seal interval, in its clock's units, while its host
    /// runs the log's tick duty ([`crate::RaftLog::tick`]).
    Interval(u64),
    /// [`crate::log::SEAL_CHUNK`] bytes, when no tick duty runs.
    Bytes(u64),
}

/// A [`Standby`]'s settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandbyConfig {
    /// The primary's first log index: a fresh standby's copy must start
    /// with it (ADR-0120 decision 6).
    pub primary_first_index: u64,
    /// How long a source may go without a status before its copy is
    /// stale: another source may then take over, and the recovery point
    /// is [`RecoveryPoint::Unknown`]. In the caller's clock units.
    pub status_interval: u64,
    /// The bound on the unsealed tail.
    pub tail_bound: TailBound,
    /// The generation before a promotion.
    pub generation: u64,
}

/// Why the standby refused something (ADR-0120 decisions 5, 6 and 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Another source is active and fresh (decision 5).
    Busy {
        /// The active source.
        active: u64,
    },
    /// No copy of this source is active.
    NotActive {
        /// The source.
        source: u64,
    },
    /// The standby is promoted: it follows no one.
    Promoted,
    /// The standby stopped at a gap (decision 9).
    Stopped,
    /// The seal is not a `ClusterLog` seal.
    Kind(SealKind),
    /// The seal names another epoch than the copy's.
    Epoch {
        /// The copy's.
        copy: u64,
        /// The seal's.
        seal: u64,
    },
    /// The seal does not start where the copy's checked bytes end.
    Range {
        /// Where the checked bytes end.
        checked: u64,
        /// The seal's start.
        start: u64,
    },
    /// The seal does not verify on the copy's bytes.
    Seal(String),
    /// A frame fails the log's frame check, or the range ends inside one.
    Frame {
        /// The frame's position in the source's log.
        position: u64,
        /// What is wrong.
        problem: ChainProblem,
    },
    /// An index does not follow the previous one, or a term goes down.
    Chain {
        /// The frame's position.
        position: u64,
        /// What is wrong.
        problem: ChainProblem,
    },
    /// The frame at the anchor's index does not carry its recorded term,
    /// or the first frame past it has a lower term.
    Anchor {
        /// The anchor.
        anchor: Position,
        /// The frame's index.
        index: u64,
        /// The frame's term.
        term: u64,
    },
    /// The copy starts past the anchor plus one, or a fresh standby's copy
    /// does not start at the primary's first index: the log cannot fill
    /// it (decision 9). The standby stops.
    Gap {
        /// The anchor, `None` for a fresh standby.
        anchor: Option<Position>,
        /// The copy's first index.
        first: u64,
    },
}

/// What a seal gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sealed {
    /// Its range checked: the entries past the anchor, in order, to
    /// propose to the standby's log (each [`Ready::wrapped`]).
    Ready(Vec<Ready>),
    /// The copy does not hold its whole range yet: it waits, and the
    /// sender resends from [`CopyEnds::received`].
    Waiting,
}

/// One checked primary entry, ready to propose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    /// The primary's index and term.
    pub position: Position,
    /// The primary leader's event time.
    pub event_time: u64,
    /// Its [`wrap`]ped bytes.
    pub wrapped: Vec<u8>,
}

/// The active copy's ends, in the source's byte positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyEnds {
    /// The source node.
    pub source: u64,
    /// Its epoch, once a seal named it.
    pub epoch: Option<u64>,
    /// Where the copy starts.
    pub start: u64,
    /// The end of `V`'s frame in this copy; its start for a standby with
    /// no `V`; `None` while `V` is not yet mapped into this copy's
    /// positions (after a rebuild or a new source).
    pub verified: Option<u64>,
    /// Where its checked seals end.
    pub checked: u64,
    /// Where its received bytes end.
    pub received: u64,
    /// The source's sealed end, from its last status.
    pub sealed: Option<u64>,
}

/// The recovery point (ADR-0120 decision 8): reported continuously,
/// never as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPoint {
    /// Bytes sealed at the source and not verified here.
    Behind {
        /// How many: never zero.
        bytes: NonZeroU64,
    },
    /// Verified to the sealed end: the unsealed tail is unknown, within
    /// its bound.
    AtSealedEnd {
        /// The bound.
        bound: TailBound,
    },
    /// No status arrived within the status interval.
    Unknown,
}

/// The gap a promotion leaves (ADR-0120 decision 8): a lower bound,
/// never its exact size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// At least these bytes, sealed at the source and not verified here;
    /// `None` (unknown) while `V` is not mapped into the copy's positions,
    /// so applied entries are never counted as loss.
    pub sealed_unverified: Option<u64>,
    /// Plus the committed tail past the last seal, which is unknown.
    pub unsealed_tail: TailBound,
}

/// A request known to be in flight: its outcome is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InFlight {
    /// The client's identity.
    pub client: u64,
    /// The request's sequence.
    pub sequence: u64,
}

/// What fences the old primary before a promotion (SPEC §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fencing {
    /// The operator stopped old members and confirmed each stop.
    OperatorStop {
        /// Every member of the old primary.
        members: Vec<u64>,
        /// The members whose stop the operator confirmed.
        confirmed: Vec<u64>,
    },
    /// The primary's external lease, as the arbiter sees it.
    Lease {
        /// Whether the arbiter sees it expired.
        expired: bool,
    },
}

/// Why a promotion was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionRefused {
    /// Members of the old primary whose stop is not confirmed.
    Unconfirmed(Vec<u64>),
    /// The lease is still valid.
    LeaseValid,
    /// Already promoted.
    Promoted,
}

/// What a promotion reports (SPEC §9; ADR-0120 decision 8). The
/// primary's commit index is not learnt over schema 6, so it is not
/// reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionReport {
    /// The generation raised.
    pub generation: u64,
    /// `V` and its term: every entry up to it survives.
    pub verified: Option<Position>,
    /// The active copy's ends.
    pub copy: Option<CopyEnds>,
    /// The gap, a lower bound.
    pub gap: Gap,
    /// The requests in flight, outcomes unknown.
    pub unknown: Vec<InFlight>,
}

/// One copy: a source's bytes in one epoch.
#[derive(Debug, Clone)]
struct Copy {
    source: u64,
    epoch: Option<u64>,
    start: u64,
    /// The received bytes not yet checked, from `base`: a checked range
    /// is released once its seal passed (karyos#714 review).
    bytes: Vec<u8>,
    base: u64,
    checked: u64,
    verified: Option<u64>,
    sealed: Option<u64>,
    /// When its request first arrived: its grace until a status.
    begun: u64,
    /// When a status last arrived.
    status: Option<u64>,
    ended: bool,
    /// The last checked frame, for the chain.
    last: Option<Position>,
    /// The frames handed out and not yet applied: index and end.
    pending: Vec<(u64, u64)>,
}

impl Copy {
    fn received(&self) -> u64 {
        let length = u64::try_from(self.bytes.len()).unwrap_or(u64::MAX);
        self.base.saturating_add(length)
    }

    /// `fresh`: whether the standby has no `V`, so the copy's start is its
    /// verified end until a frame maps one.
    fn ends(&self, fresh: bool) -> CopyEnds {
        CopyEnds {
            source: self.source,
            epoch: self.epoch,
            start: self.start,
            verified: self.verified.or(fresh.then_some(self.start)),
            checked: self.checked,
            received: self.received(),
            sealed: self.sealed,
        }
    }

    /// Drops the unchecked bytes, so a resend replaces them.
    fn drop_unchecked(&mut self) {
        let keep = usize::try_from(self.checked.saturating_sub(self.base)).unwrap_or(usize::MAX);
        self.bytes.truncate(keep);
    }

    /// Releases the checked bytes: a checked seal is never verified again.
    fn release_checked(&mut self) {
        let done = usize::try_from(self.checked.saturating_sub(self.base)).unwrap_or(usize::MAX);
        let done = done.min(self.bytes.len());
        drop(self.bytes.drain(..done));
        self.base = self.checked.max(self.base);
    }
}

/// The standby's follower of the primary's Cluster log, on its leader.
#[derive(Debug)]
pub struct Standby<S> {
    config: StandbyConfig,
    check: S,
    verified: Option<Position>,
    /// The last entry handed out, at least `V`.
    tail: Option<Position>,
    copy: Option<Copy>,
    stopped: bool,
    promoted: bool,
    generation: u64,
}

impl<S: SealCheck> Standby<S> {
    /// A follower whose verified position is `verified`, rebuilt from the
    /// standby's own log ([`verified_in`]), `None` for a fresh standby.
    pub fn new(config: StandbyConfig, check: S, verified: Option<Position>) -> Self {
        Self {
            config,
            check,
            verified,
            tail: verified,
            copy: None,
            stopped: false,
            promoted: false,
            generation: config.generation,
        }
    }

    /// After a restart or a change of standby leader (ADR-0120 decision
    /// 7): `V` rebuilt from the standby's own log, the copy discarded, a
    /// stop at a gap forgotten (it is found again if it is still there).
    pub fn rebuild(&mut self, verified: Option<Position>) {
        self.verified = verified;
        self.tail = verified;
        self.discard_copy();
        self.stopped = false;
    }

    /// Drops the copy, and what the seal check counted of it.
    fn discard_copy(&mut self) {
        if let Some(copy) = self.copy.take()
            && let Some(epoch) = copy.epoch
        {
            self.check.discard(copy.source, epoch, 0);
        }
    }

    /// The seal check behind the seam.
    #[must_use]
    pub fn check(&self) -> &S {
        &self.check
    }

    /// The seal check, the follower dropped.
    #[must_use]
    pub fn into_check(self) -> S {
        self.check
    }

    /// The copy's received bytes still held: at most the unchecked ones.
    #[must_use]
    pub fn retained(&self) -> usize {
        self.copy.as_ref().map_or(0, |copy| copy.bytes.len())
    }

    /// `V`.
    #[must_use]
    pub fn verified(&self) -> Option<Position> {
        self.verified
    }

    /// The last entry handed out: `V` or past it.
    #[must_use]
    pub fn tail(&self) -> Option<Position> {
        self.tail
    }

    /// Whether it stopped at a gap (decision 9).
    #[must_use]
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// Its generation: raised by a promotion.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether its service may have external effects: only once promoted.
    #[must_use]
    pub fn effects_enabled(&self) -> bool {
        self.promoted
    }

    /// The active copy's ends.
    #[must_use]
    pub fn copy(&self) -> Option<CopyEnds> {
        let fresh = self.verified.is_none();
        self.copy.as_ref().map(|copy| copy.ends(fresh))
    }

    fn following(&self) -> Result<(), Refusal> {
        if self.promoted {
            Err(Refusal::Promoted)
        } else if self.stopped {
            Err(Refusal::Stopped)
        } else {
            Ok(())
        }
    }

    fn active(&mut self, source: u64) -> Result<&mut Copy, Refusal> {
        self.copy
            .as_mut()
            .filter(|copy| copy.source == source && !copy.ended)
            .ok_or(Refusal::NotActive { source })
    }

    /// A request from `source` starting at `start`, at `now` (decision
    /// 5): the same request again changes nothing; another source's is
    /// refused while the active copy is fresh; otherwise a new copy
    /// starts and the old one is discarded.
    ///
    /// # Errors
    ///
    /// [`Refusal::Busy`], [`Refusal::Promoted`], [`Refusal::Stopped`].
    pub fn begin(&mut self, source: u64, start: u64, now: u64) -> Result<(), Refusal> {
        self.following()?;
        if let Some(copy) = self.copy.as_mut()
            && !copy.ended
        {
            if copy.source == source && copy.start == start {
                // A retry: it changes nothing, its grace included.
                return Ok(());
            }
            let heard = copy.status.unwrap_or(copy.begun);
            let fresh = now.saturating_sub(heard) < self.config.status_interval;
            if copy.source != source && fresh {
                return Err(Refusal::Busy {
                    active: copy.source,
                });
            }
        }
        self.discard_copy();
        self.copy = Some(Copy {
            source,
            epoch: None,
            start,
            bytes: Vec::new(),
            base: start,
            checked: start,
            verified: None,
            sealed: None,
            begun: now,
            status: None,
            ended: false,
            last: None,
            pending: Vec::new(),
        });
        Ok(())
    }

    /// Bytes from `source` at `position`: appended when they reach the
    /// copy's end, their part past it kept; bytes past the end are
    /// dropped (a lost chunk before them). Returns the copy's received
    /// end.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotActive`], [`Refusal::Promoted`], [`Refusal::Stopped`].
    pub fn receive(&mut self, source: u64, position: u64, bytes: &[u8]) -> Result<u64, Refusal> {
        self.following()?;
        let copy = self.active(source)?;
        let end = copy.received();
        if position <= end {
            let skip = usize::try_from(end.saturating_sub(position)).unwrap_or(usize::MAX);
            if let Some(new) = bytes.get(skip..) {
                copy.bytes.extend_from_slice(new);
            }
        }
        Ok(copy.received())
    }

    /// A status from `source` at `now`: its sealed end.
    ///
    /// # Errors
    ///
    /// As [`Standby::receive`].
    pub fn status(&mut self, source: u64, sealed: u64, now: u64) -> Result<CopyEnds, Refusal> {
        self.following()?;
        let fresh = self.verified.is_none();
        let copy = self.active(source)?;
        copy.sealed = copy.sealed.max(Some(sealed));
        copy.status = Some(now);
        Ok(copy.ends(fresh))
    }

    /// The source ended its request (`state` 5): the copy stays for the
    /// reports, and another source may start.
    pub fn end(&mut self, source: u64) {
        if let Some(copy) = self.copy.as_mut().filter(|copy| copy.source == source) {
            copy.ended = true;
        }
    }

    /// A seal from `source` (decision 6): checked on the copy, and its
    /// entries past the anchor handed out to propose, or refused whole.
    ///
    /// # Errors
    ///
    /// [`Refusal`]: nothing is handed out and `V` does not move; the
    /// copy's unchecked bytes are dropped, so the sender resends them. A
    /// [`Refusal::Gap`] stops the follower.
    pub fn seal(&mut self, source: u64, seal: &SealRecord) -> Result<Sealed, Refusal> {
        self.following()?;
        let anchor = self.tail;
        let verified = self.verified;
        let first_index = self.config.primary_first_index;
        let copy = self
            .copy
            .as_mut()
            .filter(|copy| copy.source == source && !copy.ended)
            .ok_or(Refusal::NotActive { source })?;
        if seal.kind != SealKind::ClusterLog {
            return Err(Refusal::Kind(seal.kind));
        }
        if let Some(epoch) = copy.epoch.filter(|epoch| *epoch != seal.subject) {
            return Err(Refusal::Epoch {
                copy: epoch,
                seal: seal.subject,
            });
        }
        if seal.end <= copy.checked {
            return Ok(Sealed::Ready(Vec::new()));
        }
        if seal.start != copy.checked {
            return Err(Refusal::Range {
                checked: copy.checked,
                start: seal.start,
            });
        }
        if seal.end > copy.received() {
            return Ok(Sealed::Waiting);
        }
        let from = usize::try_from(seal.start.saturating_sub(copy.base)).unwrap_or(usize::MAX);
        let to = usize::try_from(seal.end.saturating_sub(copy.base)).unwrap_or(usize::MAX);
        let walked = match copy.bytes.get(from..to) {
            None => Err(Refusal::Range {
                checked: copy.checked,
                start: seal.start,
            }),
            Some(bytes) => self
                .check
                .verify(source, seal, bytes)
                .map_err(Refusal::Seal)
                .and_then(|()| {
                    walk(
                        bytes,
                        seal.start,
                        copy.last,
                        (verified, anchor),
                        first_index,
                    )
                }),
        };
        match walked {
            Ok(walk) => {
                copy.checked = seal.end;
                copy.epoch = Some(seal.subject);
                copy.last = walk.last.or(copy.last);
                copy.verified = copy.verified.max(walk.verified_end);
                copy.pending.extend(walk.pending);
                copy.release_checked();
                if let Some(last) = walk.ready.last() {
                    self.tail = Some(last.position);
                }
                Ok(Sealed::Ready(walk.ready))
            }
            Err(refusal) => {
                if matches!(refusal, Refusal::Gap { .. }) {
                    self.stopped = true;
                } else {
                    copy.drop_unchecked();
                }
                // The seal may have counted the range before its frames
                // failed: it no longer counts.
                self.check.discard(source, seal.subject, seal.start);
                Err(refusal)
            }
        }
    }

    /// The standby's service applied the wrapped entry of `position`: `V`
    /// moves to it, if it is past `V`.
    pub fn applied(&mut self, position: Position) {
        if self
            .verified
            .is_some_and(|verified| verified.index >= position.index)
        {
            return;
        }
        self.verified = Some(position);
        if self.tail.is_none_or(|tail| tail.index < position.index) {
            self.tail = Some(position);
        }
        if let Some(copy) = self.copy.as_mut() {
            let done = copy
                .pending
                .partition_point(|(index, _)| *index <= position.index);
            if let Some(&(_, end)) = done.checked_sub(1).and_then(|at| copy.pending.get(at)) {
                copy.verified = copy.verified.max(Some(end));
            }
            copy.pending.drain(..done);
        }
    }

    /// The recovery point at `now` (decision 8): never zero.
    #[must_use]
    pub fn recovery_point(&self, now: u64) -> RecoveryPoint {
        let Some(copy) = self.copy.as_ref() else {
            return RecoveryPoint::Unknown;
        };
        let fresh = copy
            .status
            .is_some_and(|at| now.saturating_sub(at) < self.config.status_interval);
        match copy.sealed {
            Some(sealed) if fresh && !copy.ended => {
                let Some(verified) = copy.ends(self.verified.is_none()).verified else {
                    return RecoveryPoint::Unknown;
                };
                match NonZeroU64::new(sealed.saturating_sub(verified)) {
                    Some(bytes) => RecoveryPoint::Behind { bytes },
                    None => RecoveryPoint::AtSealedEnd {
                        bound: self.config.tail_bound,
                    },
                }
            }
            _ => RecoveryPoint::Unknown,
        }
    }

    /// Promotes the standby once `fencing` is verified (SPEC §9): the
    /// generation raised, the follower stopped, external effects enabled,
    /// and the report, `unknown` listed as unknown outcomes.
    ///
    /// # Errors
    ///
    /// [`PromotionRefused`], changing nothing.
    pub fn promote(
        &mut self,
        fencing: &Fencing,
        mut unknown: Vec<InFlight>,
    ) -> Result<PromotionReport, PromotionRefused> {
        if self.promoted {
            return Err(PromotionRefused::Promoted);
        }
        match fencing {
            Fencing::OperatorStop { members, confirmed } => {
                let missing: Vec<u64> = members
                    .iter()
                    .copied()
                    .filter(|member| !confirmed.contains(member))
                    .collect();
                if !missing.is_empty() || members.is_empty() {
                    return Err(PromotionRefused::Unconfirmed(missing));
                }
            }
            Fencing::Lease { expired: false } => return Err(PromotionRefused::LeaseValid),
            Fencing::Lease { expired: true } => {}
        }
        self.promoted = true;
        self.generation = self.generation.saturating_add(1);
        let copy = self.copy();
        let sealed_unverified = match copy {
            None => self.verified.is_none().then_some(0),
            Some(ends) => ends.verified.map(|verified| {
                ends.sealed
                    .unwrap_or(ends.checked)
                    .max(ends.checked)
                    .saturating_sub(verified)
            }),
        };
        unknown.sort_unstable();
        unknown.dedup();
        Ok(PromotionReport {
            generation: self.generation,
            verified: self.verified,
            copy,
            gap: Gap {
                sealed_unverified,
                unsealed_tail: self.config.tail_bound,
            },
            unknown,
        })
    }
}

/// What a seal's range walk found.
struct Walk {
    ready: Vec<Ready>,
    /// Each frame past `V`, handed out now or before: its index and end.
    pending: Vec<(u64, u64)>,
    last: Option<Position>,
    /// The end of the last frame at or below `V`.
    verified_end: Option<u64>,
}

/// Walks the frames of `bytes`, at `position` in the source's log, after
/// the copy's `last` checked frame, against `V` and the `anchor`, the
/// last entry handed out (at least `V`).
fn walk(
    bytes: &[u8],
    position: u64,
    mut last: Option<Position>,
    (verified, anchor): (Option<Position>, Option<Position>),
    first_index: u64,
) -> Result<Walk, Refusal> {
    let mut walk = Walk {
        ready: Vec::new(),
        pending: Vec::new(),
        last: None,
        verified_end: None,
    };
    let mut offset = 0usize;
    let mut at = position;
    while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
        let frame = read_frame(rest).map_err(|problem| Refusal::Frame {
            position: at,
            problem,
        })?;
        let end = at.saturating_add(frame.span);
        let here = Position {
            index: frame.index,
            term: frame.term,
        };
        match last {
            Some(previous) => {
                if previous.index.checked_add(1) != Some(frame.index) {
                    return Err(Refusal::Chain {
                        position: at,
                        problem: ChainProblem::Index {
                            expected: previous.index.saturating_add(1),
                            got: frame.index,
                        },
                    });
                }
                if frame.term < previous.term {
                    return Err(Refusal::Chain {
                        position: at,
                        problem: ChainProblem::TermBack {
                            last: previous.term,
                            got: frame.term,
                        },
                    });
                }
            }
            // The copy's first frame: anchored, or the primary's first.
            None => match anchor {
                None if frame.index != first_index => {
                    return Err(Refusal::Gap {
                        anchor,
                        first: frame.index,
                    });
                }
                Some(anchor) if frame.index > anchor.index.saturating_add(1) => {
                    return Err(Refusal::Gap {
                        anchor: Some(anchor),
                        first: frame.index,
                    });
                }
                Some(anchor) if frame.index > anchor.index && frame.term < anchor.term => {
                    return Err(Refusal::Anchor {
                        anchor,
                        index: frame.index,
                        term: frame.term,
                    });
                }
                _ => {}
            },
        }
        if let Some(anchor) = anchor.filter(|anchor| anchor.index == frame.index)
            && frame.term != anchor.term
        {
            return Err(Refusal::Anchor {
                anchor,
                index: frame.index,
                term: frame.term,
            });
        }
        if verified.is_some_and(|verified| frame.index <= verified.index) {
            walk.verified_end = Some(end);
        } else {
            walk.pending.push((frame.index, end));
        }
        if anchor.is_none_or(|anchor| frame.index > anchor.index) {
            walk.ready.push(Ready {
                position: here,
                event_time: frame.event_time,
                wrapped: wrap(frame.index, frame.term, frame.payload),
            });
        }
        last = Some(here);
        walk.last = Some(here);
        let span = usize::try_from(frame.span).unwrap_or(usize::MAX);
        offset = offset.saturating_add(span);
        at = end;
    }
    Ok(walk)
}
