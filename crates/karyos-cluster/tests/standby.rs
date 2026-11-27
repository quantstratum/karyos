// SPDX-License-Identifier: Apache-2.0

//! The standby's follower of the primary's Cluster log (ADR-0120,
//! karyos#714), over a real log as the source and over hand-built
//! frames and seals:
//!
//! - the source: its replication start, its seals and stored bytes, and
//!   the conditions that end a request;
//! - a standby follows a primary's sealed log and applies nothing
//!   externally before a promotion;
//! - a damaged or forged range is refused before anything is handed out,
//!   and `V` does not move; a lost chunk leaves the seal waiting;
//! - the anchor at `V`, a gap that stops the follower, a fresh standby;
//! - one source at a time, `V` rebuilt from the standby's own log;
//! - the recovery point, never zero; fenced promotion and its report.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::path::PathBuf;

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::{GENESIS, SealKind, SealRecord, digest};
use karyos_archive::segment::Geometry;
use karyos_cluster::log::{ReplicationEnd, SEAL_CHUNK};
use karyos_cluster::standby::{
    self, DigestCheck, Fencing, InFlight, Position, PromotionRefused, RecoveryPoint, Refusal,
    ReplicaCheck, SealCheck, Sealed, Standby, StandbyConfig, TailBound,
};
use karyos_cluster::{ChainProblem, Entry, HardState, RaftLog};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("karyos-standby-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entry(index: u64, term: u64) -> Entry {
    Entry {
        index,
        term,
        event_time: index * 10,
        payload: format!("command {index}").into_bytes(),
    }
}

const STATUS: u64 = 20;
const BOUND: TailBound = TailBound::Interval(10);

fn config() -> StandbyConfig {
    StandbyConfig {
        primary_first_index: 1,
        status_interval: STATUS,
        tail_bound: BOUND,
        generation: 1,
    }
}

fn fresh() -> Standby<DigestCheck> {
    Standby::new(config(), DigestCheck, None)
}

/// A log of entries `1..=count`, term `term`, committed and sealed.
fn primary(dir: &TempDir, geometry: Geometry, count: u64, term: u64) -> RaftLog<StdDisk> {
    let mut log = RaftLog::create(StdDisk, &dir.0, geometry, 1).unwrap();
    for index in 1..=count {
        log.append(&[entry(index, term)]).unwrap();
    }
    log.sync().unwrap();
    log.save_hard_state(HardState {
        current_term: term,
        voted_for: None,
        commit: Some(count),
    })
    .unwrap();
    log.seal().unwrap();
    log
}

/// What a sender reads from `log`: its start, its epoch's seals, and its
/// bytes from the start to the last seal's end.
fn source(log: &mut RaftLog<StdDisk>) -> (u64, Vec<SealRecord>, Vec<u8>) {
    let start = log.replication_start().unwrap().unwrap();
    let (epoch, seals) = log.replication_seals().unwrap();
    assert!(seals.iter().all(|seal| seal.subject == epoch));
    let end = seals.last().unwrap().end;
    let mut bytes = vec![0; usize::try_from(end - start).unwrap()];
    log.read_stored(start, &mut bytes).unwrap();
    (start, seals, bytes)
}

/// Frames of `entries`, back to back.
fn frames(entries: &[(u64, u64)]) -> Vec<u8> {
    entries
        .iter()
        .flat_map(|&(index, term)| entry(index, term).frame().unwrap())
        .collect()
}

/// A kind 3 seal of `epoch` over `bytes` at `start`, as the source would
/// write it (forged when the bytes are not the source's).
fn seal_over(epoch: u64, start: u64, bytes: &[u8]) -> SealRecord {
    SealRecord {
        kind: SealKind::ClusterLog,
        counter: 0,
        subject: epoch,
        start,
        end: start + bytes.len() as u64,
        content: digest(bytes),
        previous: GENESIS,
    }
}

/// Feeds `standby` one source's copy and seals, applying what is ready
/// at once as the standby group would; returns the entries handed out.
fn feed<S: SealCheck>(
    standby: &mut Standby<S>,
    (start, seals, bytes): (u64, &[SealRecord], &[u8]),
) -> Result<Vec<Position>, Refusal> {
    standby.begin(0, start, 0)?;
    standby.receive(0, start, bytes)?;
    let mut handed = Vec::new();
    for seal in seals {
        match standby.seal(0, seal)? {
            Sealed::Ready(ready) => {
                for entry in ready {
                    let (index, term, _) = standby::unwrap(&entry.wrapped).unwrap();
                    assert_eq!(Position { index, term }, entry.position);
                    handed.push(entry.position);
                    standby.applied(entry.position);
                }
            }
            Sealed::Waiting => panic!("waiting on a whole copy"),
        }
    }
    Ok(handed)
}

fn at(index: u64, term: u64) -> Position {
    Position { index, term }
}

#[test]
fn the_source_starts_at_a_seal_boundary_and_its_seals_cover_its_bytes() {
    let dir = TempDir::new("source");
    let mut log = primary(&dir, Geometry::new(4096, 4096).unwrap(), 400, 1);
    let start = log.replication_start().unwrap().unwrap();
    assert_eq!(start, log.store_start());
    let (epoch, seals) = log.replication_seals().unwrap();
    assert_eq!(epoch, log.seal_epoch());
    assert_eq!(seals[0].start, start);
    for pair in seals.windows(2) {
        assert_eq!(pair[0].end, pair[1].start);
    }
    assert_eq!(seals.last().unwrap().end, log.written());
    // Its stored bytes are the frames, whole.
    let (_, _, bytes) = source(&mut log);
    let first = karyos_cluster::log::read_frame(&bytes).unwrap();
    assert_eq!((first.index, first.term), (1, 1));
    // The end conditions.
    assert_eq!(log.replication_end(epoch, start, true), None);
    assert_eq!(
        log.replication_end(epoch, start, false),
        Some(ReplicationEnd::NotLeading)
    );
    assert_eq!(
        log.replication_end(epoch + 1, start, true),
        Some(ReplicationEnd::NewEpoch { epoch })
    );
    // A purge moves the start past the old one: the request ends, and a new
    // one starts at the epoch's next seal boundary at or after the start.
    log.purge_prefix(300).unwrap();
    assert!(log.store_start() > start);
    assert_eq!(
        log.replication_end(epoch, start, true),
        Some(ReplicationEnd::PurgedPast {
            start: log.store_start()
        })
    );
    let restart = log.replication_start().unwrap().unwrap();
    assert!(restart >= log.store_start());
    let (_, seals) = log.replication_seals().unwrap();
    assert!(
        seals
            .iter()
            .any(|seal| seal.start == restart || seal.end == restart)
    );
}

#[test]
fn a_standby_follows_the_primarys_log_and_applies_nothing_externally_before_promotion() {
    let dir = TempDir::new("follow");
    let mut log = primary(&dir, Geometry::new(4096, 4096).unwrap(), 300, 2);
    let (start, seals, bytes) = source(&mut log);
    assert!(seals.len() > 1 || bytes.len() as u64 <= SEAL_CHUNK);
    let mut standby = fresh();
    let handed = feed(&mut standby, (start, &seals, &bytes)).unwrap();
    assert_eq!(
        handed,
        (1..=300).map(|index| at(index, 2)).collect::<Vec<_>>()
    );
    assert_eq!(standby.verified(), Some(at(300, 2)));
    assert!(!standby.effects_enabled());
    // Caught up with a fresh status: at the sealed end, the tail unknown.
    let sealed = seals.last().unwrap().end;
    standby.status(0, sealed, 1).unwrap();
    assert_eq!(
        standby.recovery_point(1),
        RecoveryPoint::AtSealedEnd { bound: BOUND }
    );
    // The same seals again hand nothing out twice.
    for seal in &seals {
        assert_eq!(standby.seal(0, seal), Ok(Sealed::Ready(Vec::new())));
    }
}

#[test]
fn a_damaged_range_is_refused_before_apply_and_v_does_not_move() {
    let dir = TempDir::new("damaged");
    let mut log = primary(&dir, Geometry::with_default_length(65_536).unwrap(), 6, 1);
    let (start, seals, bytes) = source(&mut log);
    assert_eq!(seals.len(), 1);
    let mut standby = Standby::new(config(), DigestCheck, Some(at(2, 1)));
    // A flipped payload byte fails the seal.
    let mut flipped = bytes.clone();
    *flipped.last_mut().unwrap() ^= 0xFF;
    assert!(matches!(
        feed(&mut standby, (start, &seals, &flipped)),
        Err(Refusal::Seal(_))
    ));
    assert_eq!(standby.verified(), Some(at(2, 1)));
    // A changed term (byte 16 of the first frame) fails the seal too.
    let mut termed = bytes.clone();
    termed[16] ^= 1;
    assert!(matches!(
        feed(&mut standby, (start, &seals, &termed)),
        Err(Refusal::Seal(_))
    ));
    assert_eq!(standby.verified(), Some(at(2, 1)));
    // The copy dropped the bad bytes: the intact resend goes through, from
    // past V.
    let handed = feed(&mut standby, (start, &seals, &bytes)).unwrap();
    assert_eq!(
        handed,
        (3..=6).map(|index| at(index, 1)).collect::<Vec<_>>()
    );
}

#[test]
fn a_forged_range_fails_the_frame_and_chain_checks_with_v_unchanged() {
    // Forged seals whose digest matches the forged bytes: the seal passes,
    // the frames do not.
    let mut good = frames(&[(1, 1), (2, 1)]);
    let mut crc = good.clone();
    let last = crc.len() - 1;
    crc[last] ^= 1;
    let mut standby = fresh();
    assert!(matches!(
        feed(&mut standby, (0, &[seal_over(0, 0, &crc)], &crc)),
        Err(Refusal::Frame {
            problem: ChainProblem::Checksum,
            ..
        })
    ));
    assert_eq!(standby.verified(), None);
    // A range ending inside a frame.
    let cut = &good[..good.len() - 3];
    let mut standby = fresh();
    assert!(matches!(
        feed(&mut standby, (0, &[seal_over(0, 0, cut)], cut)),
        Err(Refusal::Frame {
            problem: ChainProblem::PastEnd,
            ..
        })
    ));
    // A term going down, and an index skipped.
    for (bytes, problem) in [
        (
            frames(&[(1, 2), (2, 1)]),
            ChainProblem::TermBack { last: 2, got: 1 },
        ),
        (
            frames(&[(1, 1), (3, 1)]),
            ChainProblem::Index {
                expected: 2,
                got: 3,
            },
        ),
    ] {
        let mut standby = fresh();
        assert_eq!(
            feed(&mut standby, (0, &[seal_over(0, 0, &bytes)], &bytes)),
            Err(Refusal::Chain {
                position: entry(1, 1).encoded_len().unwrap(),
                problem
            })
        );
        assert_eq!(standby.verified(), None);
    }
    // A seal of another kind, or of another epoch than the copy's.
    let mut standby = fresh();
    let mut other = seal_over(0, 0, &good);
    other.kind = SealKind::OpenSegment;
    assert_eq!(
        feed(&mut standby, (0, &[other], &good)),
        Err(Refusal::Kind(SealKind::OpenSegment))
    );
    let more = frames(&[(3, 1)]);
    let at_end = good.len() as u64;
    good.extend_from_slice(&more);
    let mut standby = fresh();
    let seals = [
        seal_over(0, 0, &good[..at_end as usize]),
        seal_over(1, at_end, &more),
    ];
    assert_eq!(
        feed(&mut standby, (0, &seals, &good)),
        Err(Refusal::Epoch { copy: 0, seal: 1 })
    );
    assert_eq!(standby.verified(), Some(at(2, 1)));
}

#[test]
fn a_lost_chunk_leaves_the_seal_waiting_until_the_resend() {
    let bytes = frames(&[(1, 1), (2, 1), (3, 1)]);
    let one = entry(1, 1).encoded_len().unwrap() as usize;
    let seal = seal_over(0, 0, &bytes);
    let mut standby = fresh();
    standby.begin(7, 0, 0).unwrap();
    standby.receive(7, 0, &bytes[..one]).unwrap();
    // The second chunk is lost: the third lands past the copy's end.
    let two = 2 * one;
    assert_eq!(
        standby.receive(7, two as u64, &bytes[two..]),
        Ok(one as u64)
    );
    assert_eq!(standby.seal(7, &seal), Ok(Sealed::Waiting));
    assert_eq!(standby.copy().unwrap().received, one as u64);
    // The sender resends from the copy's received end.
    standby.receive(7, one as u64, &bytes[one..]).unwrap();
    let Ok(Sealed::Ready(ready)) = standby.seal(7, &seal) else {
        panic!("not ready");
    };
    assert_eq!(ready.len(), 3);
}

#[test]
fn the_copy_is_anchored_at_v() {
    let bytes = frames(&[(1, 1), (2, 1), (3, 2), (4, 2)]);
    let seals = [seal_over(0, 0, &bytes)];
    // Frames up to V are skipped; the frame at V carries its term.
    let mut standby = Standby::new(config(), DigestCheck, Some(at(3, 2)));
    assert_eq!(feed(&mut standby, (0, &seals, &bytes)), Ok(vec![at(4, 2)]));
    // The frame at V with another term is refused, V unchanged.
    let mut standby = Standby::new(config(), DigestCheck, Some(at(3, 1)));
    assert_eq!(
        feed(&mut standby, (0, &seals, &bytes)),
        Err(Refusal::Anchor {
            anchor: at(3, 1),
            index: 3,
            term: 2
        })
    );
    assert_eq!(standby.verified(), Some(at(3, 1)));
    // A copy starting at V + 1 continues the chain from V's term.
    let next = frames(&[(5, 1)]);
    let mut standby = Standby::new(config(), DigestCheck, Some(at(4, 2)));
    assert!(matches!(
        feed(&mut standby, (900, &[seal_over(0, 900, &next)], &next)),
        Err(Refusal::Anchor { index: 5, .. })
    ));
}

#[test]
fn a_gap_stops_the_follower_and_a_fresh_standby_starts_only_at_the_first_index() {
    let late = frames(&[(5, 1), (6, 1)]);
    let seals = [seal_over(0, 4000, &late)];
    let mut standby = Standby::new(config(), DigestCheck, Some(at(3, 1)));
    assert_eq!(
        feed(&mut standby, (4000, &seals, &late)),
        Err(Refusal::Gap {
            anchor: Some(at(3, 1)),
            first: 5
        })
    );
    assert!(standby.stopped());
    assert_eq!(standby.verified(), Some(at(3, 1)));
    assert_eq!(standby.begin(0, 4000, 1), Err(Refusal::Stopped));
    // A fresh standby: only from the primary's first index.
    let mut standby = fresh();
    assert_eq!(
        feed(&mut standby, (4000, &seals, &late)),
        Err(Refusal::Gap {
            anchor: None,
            first: 5
        })
    );
    // A rebuild forgets the stop; the gap is found again.
    standby.rebuild(None);
    assert!(!standby.stopped());
}

#[test]
fn one_source_is_active_at_a_time() {
    let mut standby = fresh();
    standby.begin(0, 0, 0).unwrap();
    // The same request again changes nothing.
    standby.begin(0, 0, 5).unwrap();
    assert_eq!(standby.begin(1, 0, 10), Err(Refusal::Busy { active: 0 }));
    assert_eq!(
        standby.receive(1, 0, b"x"),
        Err(Refusal::NotActive { source: 1 })
    );
    // A status keeps it fresh; silence past the status interval frees it.
    standby.status(0, 0, 15).unwrap();
    assert_eq!(
        standby.begin(1, 0, 15 + STATUS - 1),
        Err(Refusal::Busy { active: 0 })
    );
    standby.begin(1, 0, 15 + STATUS).unwrap();
    assert_eq!(standby.copy().unwrap().source, 1);
    // An ended request frees it at once.
    standby.end(1);
    standby.begin(2, 64, 40).unwrap();
    assert_eq!(standby.copy().unwrap().source, 2);
}

#[test]
fn v_is_rebuilt_from_the_standbys_own_log_and_the_copy_discarded() {
    let log = [
        standby::wrap(1, 1, b"a"),
        b"a configuration entry".to_vec(),
        standby::wrap(2, 1, b"b"),
        standby::wrap(3, 2, b"c"),
    ];
    let verified = standby::verified_in(log.iter().map(Vec::as_slice));
    assert_eq!(verified, Some(at(3, 2)));
    let mut standby = fresh();
    standby.begin(0, 0, 0).unwrap();
    standby.rebuild(verified);
    assert_eq!(standby.copy(), None);
    assert_eq!(standby.verified(), Some(at(3, 2)));
    // The next copy anchors at it.
    let bytes = frames(&[(3, 2), (4, 2)]);
    assert_eq!(
        feed(&mut standby, (0, &[seal_over(0, 0, &bytes)], &bytes)),
        Ok(vec![at(4, 2)])
    );
}

#[test]
fn the_recovery_point_is_never_zero_while_lagging() {
    let bytes = frames(&[(1, 1), (2, 1), (3, 1)]);
    let one = entry(1, 1).encoded_len().unwrap() as usize;
    let first = seal_over(0, 0, &bytes[..one]);
    let rest = seal_over(0, one as u64, &bytes[one..]);
    let mut standby = fresh();
    assert_eq!(standby.recovery_point(0), RecoveryPoint::Unknown);
    standby.begin(0, 0, 0).unwrap();
    // No status yet.
    assert_eq!(standby.recovery_point(0), RecoveryPoint::Unknown);
    standby.status(0, bytes.len() as u64, 1).unwrap();
    let behind = |standby: &Standby<DigestCheck>, now| match standby.recovery_point(now) {
        RecoveryPoint::Behind { bytes } => bytes.get(),
        other => panic!("{other:?}"),
    };
    assert_eq!(behind(&standby, 1), bytes.len() as u64);
    standby.receive(0, 0, &bytes).unwrap();
    let Ok(Sealed::Ready(ready)) = standby.seal(0, &first) else {
        panic!()
    };
    // Handed out, not yet applied: still behind.
    assert_eq!(behind(&standby, 2), bytes.len() as u64);
    standby.applied(ready[0].position);
    assert_eq!(behind(&standby, 2), (bytes.len() - one) as u64);
    let Ok(Sealed::Ready(ready)) = standby.seal(0, &rest) else {
        panic!()
    };
    for entry in ready {
        standby.applied(entry.position);
    }
    assert_eq!(
        standby.recovery_point(3),
        RecoveryPoint::AtSealedEnd { bound: BOUND }
    );
    // A stale status: unknown, never zero.
    assert_eq!(standby.recovery_point(1 + STATUS), RecoveryPoint::Unknown);
}

#[test]
fn promotion_is_refused_until_fenced_then_reports_v_the_gap_and_unknowns() {
    let bytes = frames(&[(1, 1), (2, 1), (3, 1)]);
    let one = entry(1, 1).encoded_len().unwrap() as usize;
    let mut standby = fresh();
    standby.begin(0, 0, 0).unwrap();
    standby.receive(0, 0, &bytes).unwrap();
    let Ok(Sealed::Ready(ready)) = standby.seal(0, &seal_over(0, 0, &bytes[..one])) else {
        panic!()
    };
    standby.applied(ready[0].position);
    standby.status(0, bytes.len() as u64, 1).unwrap();
    // Unfenced: refused, nothing changes.
    let unconfirmed = Fencing::OperatorStop {
        members: vec![0, 1, 2],
        confirmed: vec![0, 2],
    };
    assert_eq!(
        standby.promote(&unconfirmed, Vec::new()),
        Err(PromotionRefused::Unconfirmed(vec![1]))
    );
    assert_eq!(
        standby.promote(&Fencing::Lease { expired: false }, Vec::new()),
        Err(PromotionRefused::LeaseValid)
    );
    assert_eq!(standby.generation(), 1);
    assert!(!standby.effects_enabled());
    let fenced = Fencing::OperatorStop {
        members: vec![0, 1, 2],
        confirmed: vec![2, 1, 0],
    };
    let unknown = vec![
        InFlight {
            client: 9,
            sequence: 4,
        },
        InFlight {
            client: 8,
            sequence: 2,
        },
    ];
    let report = standby.promote(&fenced, unknown).unwrap();
    assert_eq!(report.generation, 2);
    assert_eq!(report.verified, Some(at(1, 1)));
    // At least the sealed bytes past V's frame; the unsealed tail unknown.
    assert_eq!(
        report.gap.sealed_unverified,
        Some((bytes.len() - one) as u64)
    );
    assert_eq!(report.gap.unsealed_tail, BOUND);
    assert_eq!(report.copy.unwrap().verified, Some(one as u64));
    assert_eq!(
        report.unknown,
        vec![
            InFlight {
                client: 8,
                sequence: 2
            },
            InFlight {
                client: 9,
                sequence: 4
            }
        ]
    );
    assert!(standby.effects_enabled());
    assert_eq!(standby.generation(), 2);
    // It follows no one any more, and keeps V.
    assert_eq!(
        standby.seal(0, &seal_over(0, one as u64, &bytes[one..])),
        Err(Refusal::Promoted)
    );
    assert_eq!(standby.verified(), Some(at(1, 1)));
    assert_eq!(
        standby.promote(&Fencing::Lease { expired: true }, Vec::new()),
        Err(PromotionRefused::Promoted)
    );
}

#[test]
fn an_expired_lease_fences_a_promotion() {
    let mut standby = fresh();
    let report = standby
        .promote(&Fencing::Lease { expired: true }, Vec::new())
        .unwrap();
    assert_eq!(report.generation, 2);
    assert_eq!(report.verified, None);
    assert_eq!(report.gap.sealed_unverified, Some(0));
}

/// The seam's test double: refuses every seal, so nothing reaches the
/// frame check.
struct Refusing;

impl SealCheck for Refusing {
    fn verify(&mut self, _: u64, _: &SealRecord, _: &[u8]) -> Result<(), String> {
        Err("refused by the replica".to_owned())
    }
}

#[test]
fn the_seal_check_is_a_seam_and_runs_before_the_frames() {
    let bytes = frames(&[(1, 1)]);
    let mut standby = Standby::new(config(), Refusing, None);
    assert_eq!(
        feed(&mut standby, (0, &[seal_over(0, 0, &bytes)], &bytes)),
        Err(Refusal::Seal("refused by the replica".to_owned()))
    );
    assert_eq!(standby.verified(), None);
}

/// The schema 6 replica behind the seam: a real log's seals verify and
/// count as copies of their source and epoch; a damaged range is refused
/// and counts nothing.
#[test]
fn the_schema_6_replica_verifies_the_seals_and_counts_the_copy() {
    let dir = TempDir::new("replica-source");
    let mut log = primary(&dir, Geometry::new(4096, 4096).unwrap(), 200, 1);
    let (start, seals, bytes) = source(&mut log);
    let epoch = log.seal_epoch();
    let standby_dir = TempDir::new("replica-standby");
    let check = ReplicaCheck::open(StdDisk, &standby_dir.0).unwrap();
    let mut standby = Standby::new(config(), check, None);
    let mut damaged = bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    // feed() takes source 0.
    let refused = feed(&mut standby, (start, &seals, &damaged));
    assert!(matches!(refused, Err(Refusal::Seal(_))), "{refused:?}");
    let handed = feed(&mut standby, (start, &seals, &bytes)).unwrap();
    assert_eq!(handed.len(), 200);
    assert_eq!(
        standby.check().verified_copies(0, epoch).unwrap(),
        seals.len()
    );
    assert_eq!(standby.check().verified_copies(1, epoch).unwrap(), 0);
}

/// Review finding 3 (karyos#714): the catalog never counts a copy the
/// standby discarded, nor one whose bytes died with the process.
#[test]
fn a_discarded_copy_no_longer_counts_and_a_reopen_counts_none() {
    let dir = TempDir::new("discard-source");
    let mut log = primary(&dir, Geometry::new(4096, 4096).unwrap(), 200, 1);
    let (start, seals, bytes) = source(&mut log);
    let epoch = log.seal_epoch();
    let standby_dir = TempDir::new("discard-standby");
    let check = ReplicaCheck::open(StdDisk, &standby_dir.0).unwrap();
    let mut standby = Standby::new(config(), check, None);
    feed(&mut standby, (start, &seals, &bytes)).unwrap();
    assert_eq!(
        standby.check().verified_copies(0, epoch).unwrap(),
        seals.len()
    );
    // A rebuild discards the copy: nothing of it counts.
    standby.rebuild(standby.verified());
    assert_eq!(standby.check().verified_copies(0, epoch).unwrap(), 0);
    // Counted again, then the process ends: a reopen counts none.
    let mut standby = Standby::new(config(), standby.into_check(), None);
    feed(&mut standby, (start, &seals, &bytes)).unwrap();
    assert_eq!(
        standby.check().verified_copies(0, epoch).unwrap(),
        seals.len()
    );
    drop(standby);
    let check = ReplicaCheck::open(StdDisk, &standby_dir.0).unwrap();
    assert_eq!(check.verified_copies(0, epoch).unwrap(), 0);
    // A new source discards the old one's copy too.
    let mut standby = Standby::new(config(), check, None);
    feed(&mut standby, (start, &seals, &bytes)).unwrap();
    standby.end(0);
    standby.begin(1, start, 1).unwrap();
    assert_eq!(standby.check().verified_copies(0, epoch).unwrap(), 0);
}

/// Review finding 2: the copy releases its checked bytes.
#[test]
fn the_bytes_retained_stay_bounded_over_many_seals() {
    let dir = TempDir::new("bounded");
    let mut log = primary(&dir, Geometry::new(4096, 4096).unwrap(), 300, 1);
    let (start, _, _) = source(&mut log);
    let mut standby = fresh();
    standby.begin(0, start, 0).unwrap();
    // One frame per seal, hand-built over the log's own frames.
    let mut position = start;
    let mut most = 0;
    for index in 1..=300 {
        let frame = entry(index, 1).frame().unwrap();
        standby.receive(0, position, &frame).unwrap();
        let seal = seal_over(0, position, &frame);
        let Ok(Sealed::Ready(ready)) = standby.seal(0, &seal) else {
            panic!("seal {index}")
        };
        for entry in ready {
            standby.applied(entry.position);
        }
        most = most.max(standby.retained());
        position += frame.len() as u64;
    }
    assert_eq!(standby.retained(), 0);
    assert_eq!(most, 0);
    assert_eq!(standby.verified(), Some(at(300, 1)));
}

/// Review finding 4: retried requests of the active source do not keep it
/// fresh; only its statuses do.
#[test]
fn a_retried_request_does_not_keep_another_source_busy() {
    let mut standby = fresh();
    standby.begin(0, 0, 0).unwrap();
    for now in 1..STATUS {
        standby.begin(0, 0, now).unwrap();
        assert_eq!(standby.begin(1, 0, now), Err(Refusal::Busy { active: 0 }));
    }
    // Its grace ran out at the status interval, retries or not.
    standby.begin(0, 0, STATUS).unwrap();
    standby.begin(1, 0, STATUS).unwrap();
    assert_eq!(standby.copy().unwrap().source, 1);
}

/// Review finding 5: V at 100, a new source sealed only through 50 bytes'
/// worth: the loss is unknown, not the sealed bytes counted from the new
/// copy's start.
#[test]
fn an_unmapped_v_reports_the_sealed_loss_unknown() {
    let mut standby = Standby::new(config(), DigestCheck, Some(at(100, 3)));
    standby.begin(5, 0, 0).unwrap();
    standby.status(5, 50, 1).unwrap();
    assert_eq!(standby.copy().unwrap().verified, None);
    assert_eq!(standby.recovery_point(1), RecoveryPoint::Unknown);
    let report = standby
        .promote(&Fencing::Lease { expired: true }, Vec::new())
        .unwrap();
    assert_eq!(report.verified, Some(at(100, 3)));
    assert_eq!(report.gap.sealed_unverified, None);
}

/// ADR-0123 decision 5: an isolated rebuild refuses every promotion, even
/// fenced, and its external effects stay off.
#[test]
fn an_isolated_standby_is_never_promoted() {
    let mut standby = fresh();
    standby.isolate();
    assert!(standby.isolated());
    for fencing in [
        Fencing::Lease { expired: true },
        Fencing::OperatorStop {
            members: vec![0],
            confirmed: vec![0],
        },
    ] {
        assert_eq!(
            standby.promote(&fencing, Vec::new()),
            Err(PromotionRefused::Isolated)
        );
    }
    assert!(!standby.effects_enabled());
    assert_eq!(standby.generation(), 1);
}
