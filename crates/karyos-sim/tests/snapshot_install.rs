// SPDX-License-Identifier: Apache-2.0

//! A follower's snapshot install, streamed, and compaction on the snapshot
//! store's own policy (karyos#682), over the harness's nodes:
//!
//! - a follower behind compaction receives the leader's snapshot in
//!   pieces of at most `WRITE_CHUNK`, in order from 0, each written into
//!   its store as it arrives, installs it and passes the case;
//! - a lost piece (dropped deterministically) breaks the transfer off,
//!   the leader asks again, and the follower still installs and passes;
//! - each compaction purges the log below the oldest kept snapshot, but
//!   the catch-up allowance (`SnapshotConfig::log_floor`), never more.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::BTreeMap;

use karyos_cluster::snapshot::WRITE_CHUNK;
use karyos_sim::harness::core::SnapshotBase;
use karyos_sim::harness::node::Observation;
use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::{self, Case, Outcome, W5};
use karyos_sim::net::NodeId;

fn behind(w5: &W5) -> Case {
    w5.cases()
        .unwrap()
        .into_iter()
        .find(|case| case.name.contains("follower behind the compaction point"))
        .unwrap()
}

/// Per server and snapshot base: the pieces written, as (offset, length,
/// total), in order.
type Pieces = BTreeMap<(NodeId, u64), Vec<(u64, u64, u64)>>;

/// The pieces each server wrote, per snapshot base, in order.
fn pieces(outcome: &Outcome) -> Pieces {
    let mut pieces = Pieces::new();
    for observation in &outcome.observations {
        if let Observation::SnapshotPiece {
            node,
            base,
            offset,
            length,
            total,
        } = observation
        {
            pieces
                .entry((*node, base.index))
                .or_default()
                .push((*offset, *length, *total));
        }
    }
    pieces
}

fn installed(outcome: &Outcome, node: NodeId) -> Vec<SnapshotBase> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Installed { node: at, base, .. } if *at == node => Some(*base),
            _ => None,
        })
        .collect()
}

/// W5's manifest follower behind compaction: its snapshot is larger than
/// one piece, so it arrives in several, in order from 0, the last ending
/// at the section's length; it installs and the case passes.
#[test]
fn a_follower_installs_a_snapshot_received_in_pieces() {
    let case = behind(&W5::manifest());
    for seed in [1] {
        let outcome = workloads::run::<Reference>(&case, seed).unwrap();
        assert_eq!(workloads::pass(&case, &outcome), Ok(None), "seed {seed}");
        let bases = installed(&outcome, W5::BEHIND);
        assert!(!bases.is_empty(), "seed {seed}: no install");
        let pieces = pieces(&outcome);
        let base = bases[0];
        let received = &pieces[&(W5::BEHIND, base.index)];
        assert!(received.len() > 1, "seed {seed}: one piece {received:?}");
        let total = received[0].2;
        assert!(total > u64::try_from(WRITE_CHUNK).unwrap());
        let mut at = 0;
        for &(offset, length, piece_total) in received {
            assert_eq!(piece_total, total);
            assert!(length <= u64::try_from(WRITE_CHUNK).unwrap());
            if offset == 0 {
                at = 0;
            }
            assert_eq!(offset, at, "seed {seed}: out of order {received:?}");
            at += length;
        }
        assert_eq!(at, total, "seed {seed}: the last piece does not end it");
    }
}

/// The second piece of the follower's first transfer is lost, every run
/// alike ([`Case::lose_snapshot_piece`]): the next piece no longer follows
/// what it holds, so the transfer is dropped; the leader asks again, the
/// second transfer starts again from 0, and the follower installs it and
/// passes.
#[test]
fn a_lost_piece_drops_the_transfer_and_a_retry_installs() {
    let mut case = behind(&W5::manifest());
    case.lose_snapshot_piece = Some(1);
    let outcome = workloads::run::<Reference>(&case, 1).unwrap();
    assert!(outcome.safety.is_ok());
    assert_eq!(workloads::pass(&case, &outcome), Ok(None));
    let lost: Vec<_> = outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::SnapshotPieceLost { node, offset, .. } => Some((*node, *offset)),
            _ => None,
        })
        .collect();
    assert_eq!(lost.len(), 1, "{lost:?}");
    let (node, offset) = lost[0];
    assert_eq!(node, W5::BEHIND);
    assert_eq!(
        offset,
        u64::try_from(WRITE_CHUNK).unwrap(),
        "the second piece"
    );
    let bases = installed(&outcome, W5::BEHIND);
    assert!(!bases.is_empty(), "no install");
    // The installed transfer restarted from 0 after the loss.
    let received = &pieces(&outcome)[&(W5::BEHIND, bases[0].index)];
    let starts = received.iter().filter(|(offset, ..)| *offset == 0).count();
    assert!(starts >= 2, "not started again: {received:?}");
}

/// Each compaction keeps the log from the oldest kept snapshot (the store
/// keeps two) less the allowance of `keep` entries: the first index after
/// a purge is never above the oldest kept base plus one, and never more
/// than `keep` entries below it while the log holds them.
#[test]
fn compaction_purges_below_the_oldest_kept_snapshot_but_the_allowance() {
    let w5 = W5::skeleton();
    let keep = w5.compaction.keep;
    let case = w5
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| case.name.contains("compaction under load"))
        .unwrap();
    let outcome = workloads::run::<Reference>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &outcome), Ok(None));
    let mut bases: BTreeMap<NodeId, Vec<u64>> = BTreeMap::new();
    let mut checked = 0;
    for observation in &outcome.observations {
        if let Observation::Compacted { node, base, first } = observation {
            let kept = bases.entry(*node).or_default();
            kept.push(base.index);
            // The store keeps the two newest.
            let oldest = kept[kept.len().saturating_sub(2)];
            assert!(
                *first <= oldest + 1,
                "node {node}: first {first} above {oldest}"
            );
            assert!(
                *first + keep > oldest || *first == 1,
                "node {node}: first {first} more than {keep} below {oldest}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 3, "only {checked} compactions");
}
