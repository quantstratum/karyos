// SPDX-License-Identifier: Apache-2.0

//! A follower's snapshot install, streamed, and compaction on the snapshot
//! store's own policy (karyos#682), over the harness's nodes:
//!
//! - a follower behind compaction receives the leader's snapshot in
//!   pieces, in order from 0, one transfer end to end, the leader never
//!   more than its window ahead of the follower, and installs it;
//! - a lost piece (dropped deterministically) breaks its transfer off as a
//!   gap; the leader's next transfer, a new one from 0, installs;
//! - each compaction purges the log below the oldest kept snapshot less
//!   the catch-up allowance (`SnapshotConfig::log_floor`), exactly that
//!   once the store has rolled over;
//! - the byte trigger alone drives compaction, never early, across a
//!   restart.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::BTreeMap;

use karyos_cluster::log::FRAME_HEADER_LEN;
use karyos_sim::harness::core::SnapshotBase;
use karyos_sim::harness::node::{Compaction, Observation, SNAPSHOT_WINDOW};
use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::{self, Action, Case, Outcome, W5, w5_frame};
use karyos_sim::net::NodeId;

fn behind(w5: &W5) -> Case {
    w5.cases()
        .unwrap()
        .into_iter()
        .find(|case| case.name.contains("follower behind the compaction point"))
        .unwrap()
}

/// One piece a follower wrote: transfer, offset, length, total.
type Written = (u64, u64, u64, u64);

/// The pieces `node` wrote, in order.
fn written(outcome: &Outcome, node: NodeId) -> Vec<Written> {
    outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::SnapshotPiece {
                node: at,
                transfer,
                offset,
                length,
                total,
                ..
            } if *at == node => Some((*transfer, *offset, *length, *total)),
            _ => None,
        })
        .collect()
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

/// The transfer whose pieces end the section: the one installed.
fn completed(pieces: &[Written]) -> u64 {
    pieces
        .iter()
        .find(|(_, offset, length, total)| offset + length == *total)
        .map(|(transfer, ..)| *transfer)
        .unwrap()
}

/// W5's manifest follower behind compaction: its snapshot takes several
/// pieces of one transfer, written in order from 0 to the section's end;
/// before the follower wrote its first piece, the leader had sent at most
/// its window; the follower installs and the case passes.
#[test]
fn a_follower_installs_a_snapshot_received_in_pieces() {
    let case = behind(&W5::manifest());
    let outcome = workloads::run::<Reference>(&case, 1).unwrap();
    assert_eq!(workloads::pass(&case, &outcome), Ok(None));
    assert!(!installed(&outcome, W5::BEHIND).is_empty(), "no install");
    let pieces = written(&outcome, W5::BEHIND);
    let transfer = completed(&pieces);
    let of: Vec<_> = pieces.iter().filter(|piece| piece.0 == transfer).collect();
    assert!(of.len() > 1, "one piece: {of:?}");
    // A transfer that moves goes on however often the core asks: each
    // snapshot base reaches the follower in one transfer, not one per
    // duty; a new transfer comes only with a newer snapshot.
    let mut per_base: BTreeMap<u64, std::collections::BTreeSet<u64>> = BTreeMap::new();
    for observation in &outcome.observations {
        if let Observation::SnapshotPiece {
            node,
            base,
            transfer,
            ..
        } = observation
            && *node == W5::BEHIND
        {
            per_base.entry(base.index).or_default().insert(*transfer);
        }
    }
    for (base, transfers) in &per_base {
        assert_eq!(transfers.len(), 1, "base {base}: transfers {transfers:?}");
    }
    let mut at = 0;
    for &&(_, offset, length, total) in &of {
        assert_eq!(offset, at, "out of order: {of:?}");
        at += length;
        assert!(at <= total);
    }
    assert_eq!(at, of[0].3);
    // The window: sends of that transfer before its first piece was written.
    let first_written = outcome
        .observations
        .iter()
        .position(|observation| {
            matches!(observation, Observation::SnapshotPiece { transfer: t, .. } if *t == transfer)
        })
        .unwrap();
    let sent_before = outcome.observations[..first_written]
        .iter()
        .filter(|observation| {
            matches!(observation, Observation::SnapshotSent { transfer: t, to, .. }
                if *t == transfer && *to == W5::BEHIND)
        })
        .count();
    assert!(
        (1..=usize::try_from(SNAPSHOT_WINDOW).unwrap()).contains(&sent_before),
        "{sent_before} pieces ahead of the follower"
    );
}

/// The second piece of the follower's first transfer is lost, every run
/// alike (`Case::lose_snapshot_piece`): that transfer is dropped as a gap,
/// and the one installed is a later transfer, written whole from 0.
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
            Observation::SnapshotPieceLost { node, transfer, .. } => Some((*node, *transfer)),
            _ => None,
        })
        .collect();
    assert_eq!(lost.len(), 1, "{lost:?}");
    let (node, broken) = lost[0];
    assert_eq!(node, W5::BEHIND);
    let abandoned: Vec<_> = outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::SnapshotAbandoned {
                node,
                transfer,
                reason,
                ..
            } if *node == W5::BEHIND => Some((*transfer, *reason)),
            _ => None,
        })
        .collect();
    assert!(abandoned.contains(&(broken, "gap")), "{abandoned:?}");
    assert!(!installed(&outcome, W5::BEHIND).is_empty(), "no install");
    let pieces = written(&outcome, W5::BEHIND);
    let done = completed(&pieces);
    assert_ne!(done, broken, "the broken transfer installed");
    assert_eq!(
        pieces
            .iter()
            .find(|piece| piece.0 == done)
            .map(|piece| piece.1),
        Some(0),
        "the retry does not start from 0"
    );
}

/// Each compaction keeps the log from the oldest kept snapshot less the
/// allowance: once node 0's store has rolled over (a third snapshot), its
/// first index after each purge lies at most the allowance's entries below
/// the oldest kept base plus one, at least `keep` of them, never more
/// than the empty entries among them besides.
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
    let mut rolled = 0;
    for observation in &outcome.observations {
        if let Observation::Compacted { node, base, first } = observation {
            let kept = bases.entry(*node).or_default();
            kept.push(base.index);
            if kept.len() < 3 {
                continue;
            }
            let oldest = kept[kept.len() - 2];
            let below = (oldest + 1)
                .checked_sub(*first)
                .unwrap_or_else(|| panic!("node {node}: first {first} above {oldest} + 1"));
            assert!(
                (keep..=keep + 4).contains(&below),
                "node {node}: {below} entries kept below {oldest}, keep {keep}"
            );
            rolled += 1;
        }
    }
    assert!(rolled > 0, "no store rolled over");
}

/// The byte trigger alone (no entry trigger): every compaction comes after
/// at least the trigger's bytes of entries since the last, each entry at
/// most one W5 frame, and so does the first after a restart, whose count
/// starts again from its snapshot.
#[test]
fn the_byte_trigger_alone_drives_compaction_across_a_restart() {
    let w5 = W5::skeleton();
    let frame = w5_frame(w5.payload_bytes);
    let trigger = 40 * frame;
    let mut case = w5
        .cases()
        .unwrap()
        .into_iter()
        .find(|case| case.name.contains("compaction under load"))
        .unwrap();
    // The byte trigger alone: the entry trigger out of reach.
    case.compaction = Some(Compaction {
        every: u64::MAX,
        every_bytes: Some(trigger),
        ..w5.compaction
    });
    // Early: the clients finish well before the run ends.
    let mid = case.steps / 8;
    case.schedule = vec![(mid, Action::Crash(1)), (mid + 40, Action::Restart(1))];
    let outcome = workloads::run::<Reference>(&case, 1).unwrap();
    assert!(outcome.safety.is_ok());
    let fewest = trigger.div_ceil(frame.max(FRAME_HEADER_LEN));
    // Node 1's count after its restart starts from the snapshot it stands
    // on, its last compaction's: the check spans the restart.
    let mut previous: BTreeMap<NodeId, u64> = BTreeMap::new();
    let mut compactions = 0;
    let mut crashed = false;
    let mut across = 0;
    for observation in &outcome.observations {
        match observation {
            Observation::Crashed { node: 1 } => crashed = true,
            Observation::Compacted { node, base, .. } => {
                if let Some(last) = previous.insert(*node, base.index) {
                    assert!(
                        base.index - last >= fewest,
                        "node {node}: compacted {} entries after {last}, fewer than {fewest}",
                        base.index - last
                    );
                    if *node == 1 && crashed {
                        across += 1;
                        crashed = false;
                    }
                }
                compactions += 1;
            }
            _ => {}
        }
    }
    let trace: Vec<String> = outcome
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Crashed { node: 1 } => Some("crash".to_owned()),
            Observation::Recovered { node: 1, .. } => Some("recovered".to_owned()),
            Observation::Compacted {
                node: 1,
                base,
                first,
            } => Some(format!("compacted {} first {first}", base.index)),
            Observation::Installed { node: 1, base, .. } => {
                Some(format!("installed {}", base.index))
            }
            Observation::SnapshotRefused {
                node: 1, reason, ..
            } => Some(format!("refused {reason}")),
            _ => None,
        })
        .collect();
    assert!(
        across > 0,
        "node 1 never compacted after its restart: {trace:?}"
    );
    assert!(compactions >= 4, "{compactions} compactions");
}
