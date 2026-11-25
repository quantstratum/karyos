// SPDX-License-Identifier: Apache-2.0

//! A follower's snapshot transfer piece by piece (karyos#682), driven by
//! hand: one follower `ServerNode` given crafted pieces from node 0, its
//! observations and acknowledgements read back.
//!
//! - a delayed piece of an older transfer neither cancels the newer one
//!   nor is written; an older base's first piece is ignored;
//! - a duplicate is acknowledged again and changes nothing;
//! - a piece whose metadata differs from its transfer's drops it;
//! - a snapshot whose digest is not its sender's, or whose service is not
//!   at its base, is refused and never installed;
//! - a transfer that stalls is dropped, and one a crash cuts short starts
//!   again from 0 after the restart.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use karyos_cluster::Entry;
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_sim::cluster::{Node, Outbox};
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::harness::core::SnapshotBase;
use karyos_sim::harness::node::{
    Command, Compaction, Observation, Op, Recorder, SERVICE_SECTION_VERSION, SNAPSHOT_STALL,
    ServerNode, Shared, TestService, Wire,
};
use karyos_sim::harness::reference::Reference;
use karyos_sim::harness::workloads::{geometry, w5_frame};
use karyos_sim::net::NodeId;

type Server = ServerNode<Reference>;
type Out = Outbox<Wire<<Reference as karyos_sim::harness::core::ConsensusCore>::Message>>;

const LEADER: NodeId = 0;
const PIECE: usize = 1000;

/// Follower 2 of three, compacting, its observations in `recorder`.
fn follower() -> (Server, Shared) {
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let server = Server::new(
        2,
        vec![0, 1, 2],
        SimDisk::new(),
        Survives::Synced,
        geometry().unwrap(),
        Rc::clone(&recorder),
    )
    .unwrap()
    .with_compaction(Compaction {
        every: 1_000_000,
        keep: 10,
        frame: w5_frame(256),
        every_bytes: None,
    });
    (server, recorder)
}

/// The service state after `index` appends of `payload` bytes each.
fn service(index: u64, payload: usize) -> Vec<u8> {
    let mut service = TestService::default();
    for at in 1..=index {
        let command = Command {
            client: 7,
            sequence: at,
            op: Op::Append(vec![u8::try_from(at % 251).unwrap(); payload]),
        };
        let _ = service.apply(&Entry {
            index: at,
            term: 1,
            event_time: 0,
            payload: command.encode(),
        });
    }
    service.encode().unwrap()
}

/// The digest a store gives a snapshot of `bytes` at `base`.
fn digest(base: SnapshotBase, bytes: &[u8]) -> u32 {
    let mut store = SnapshotStore::open(
        SimDisk::new(),
        Path::new("/d"),
        geometry().unwrap(),
        SnapshotConfig::default(),
    )
    .unwrap()
    .store;
    store
        .write(
            base.index,
            base.term,
            &[Section::new(
                SectionKind::Service,
                SERVICE_SECTION_VERSION,
                bytes,
            )],
        )
        .unwrap()
        .digest
}

/// A transfer's pieces of `PIECE` bytes.
fn pieces(base: SnapshotBase, transfer: u64, bytes: &[u8], digest: u32) -> Vec<Wire<Message>> {
    pieces_in(1, base, transfer, bytes, digest)
}

/// A transfer's pieces, its sender in `term`.
fn pieces_in(
    term: u64,
    base: SnapshotBase,
    transfer: u64,
    bytes: &[u8],
    digest: u32,
) -> Vec<Wire<Message>> {
    let length = u64::try_from(bytes.len()).unwrap();
    bytes
        .chunks(PIECE)
        .enumerate()
        .map(|(at, chunk)| Wire::Snapshot {
            base,
            term,
            transfer,
            digest,
            length,
            offset: u64::try_from(at * PIECE).unwrap(),
            bytes: chunk.to_vec(),
        })
        .collect()
}

type Message = <Reference as karyos_sim::harness::core::ConsensusCore>::Message;

fn deliver(server: &mut Server, message: Wire<Message>, now: u64) -> Out {
    let mut out = Out::new();
    server.deliver(LEADER, message, now, &mut out);
    out
}

fn acks(out: &Out) -> Vec<(u64, u64)> {
    out.iter()
        .filter_map(|(to, wire)| match wire {
            Wire::SnapshotAck { transfer, next, .. } if *to == LEADER => Some((*transfer, *next)),
            _ => None,
        })
        .collect()
}

/// The installed acknowledgements in `out`, by transfer.
fn installed(out: &Out) -> Vec<u64> {
    out.iter()
        .filter_map(|(to, wire)| match wire {
            Wire::SnapshotAck {
                transfer,
                installed: true,
                ..
            } if *to == LEADER => Some(*transfer),
            _ => None,
        })
        .collect()
}

fn abandoned(recorder: &Shared) -> Vec<(u64, &'static str)> {
    recorder
        .borrow()
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::SnapshotAbandoned {
                transfer, reason, ..
            } => Some((*transfer, *reason)),
            _ => None,
        })
        .collect()
}

fn installs(recorder: &Shared) -> Vec<SnapshotBase> {
    recorder
        .borrow()
        .observations
        .iter()
        .filter_map(|observation| match observation {
            Observation::Installed { base, .. } => Some(*base),
            _ => None,
        })
        .collect()
}

fn refusals(recorder: &Shared) -> usize {
    recorder
        .borrow()
        .observations
        .iter()
        .filter(|observation| matches!(observation, Observation::SnapshotRefused { .. }))
        .count()
}

fn at(index: u64) -> SnapshotBase {
    SnapshotBase { index, term: 1 }
}

#[test]
fn a_delayed_older_piece_neither_cancels_nor_writes() {
    let (mut server, recorder) = follower();
    let (old, new) = (service(50, 100), service(60, 100));
    let old_pieces = pieces(at(50), 1, &old, digest(at(50), &old));
    let new_pieces = pieces(at(60), 2, &new, digest(at(60), &new));
    let _ = deliver(&mut server, old_pieces[0].clone(), 1);
    let _ = deliver(&mut server, new_pieces[0].clone(), 2);
    assert_eq!(abandoned(&recorder), vec![(1, "superseded")]);
    // The older transfer's next piece, delayed: ignored, no ack.
    let out = deliver(&mut server, old_pieces[1].clone(), 3);
    assert!(acks(&out).is_empty());
    // An older base's first piece: ignored too.
    let out = deliver(&mut server, old_pieces[0].clone(), 4);
    assert!(acks(&out).is_empty());
    assert_eq!(abandoned(&recorder), vec![(1, "superseded")]);
    for piece in &new_pieces[1..] {
        let _ = deliver(&mut server, piece.clone(), 5);
    }
    assert_eq!(installs(&recorder), vec![at(60)]);
}

#[test]
fn a_duplicate_is_acknowledged_again_and_changes_nothing() {
    let (mut server, recorder) = follower();
    let bytes = service(40, 100);
    let all = pieces(at(40), 3, &bytes, digest(at(40), &bytes));
    let out = deliver(&mut server, all[0].clone(), 1);
    let first = u64::try_from(PIECE).unwrap();
    assert_eq!(acks(&out), vec![(3, first)]);
    let out = deliver(&mut server, all[0].clone(), 2);
    assert_eq!(
        acks(&out),
        vec![(3, first)],
        "the duplicate is acknowledged again"
    );
    assert!(abandoned(&recorder).is_empty());
    for piece in &all[1..] {
        let _ = deliver(&mut server, piece.clone(), 3);
    }
    assert_eq!(installs(&recorder), vec![at(40)]);
}

#[test]
fn a_piece_whose_metadata_differs_drops_the_transfer() {
    for change in 0..3 {
        let (mut server, recorder) = follower();
        let bytes = service(40, 100);
        let good = digest(at(40), &bytes);
        let all = pieces(at(40), 4, &bytes, good);
        let _ = deliver(&mut server, all[0].clone(), 1);
        let Wire::Snapshot {
            base,
            term,
            transfer,
            digest,
            length,
            offset,
            bytes,
        } = all[1].clone()
        else {
            unreachable!()
        };
        let altered = match change {
            0 => Wire::Snapshot {
                base,
                term,
                transfer,
                digest,
                length: length + 10,
                offset,
                bytes,
            },
            1 => Wire::Snapshot {
                base,
                term,
                transfer,
                digest: digest ^ 1,
                length,
                offset,
                bytes,
            },
            _ => Wire::Snapshot {
                base,
                term,
                transfer,
                digest,
                length,
                offset: offset + 1,
                bytes,
            },
        };
        let _ = deliver(&mut server, altered, 2);
        let reason = if change == 2 {
            "gap"
        } else {
            "metadata changed"
        };
        assert_eq!(abandoned(&recorder), vec![(4, reason)], "change {change}");
        assert!(installs(&recorder).is_empty());
    }
}

#[test]
fn a_snapshot_not_its_senders_or_not_at_its_base_is_refused() {
    // A wrong digest, then a service at another index than its base.
    let bytes = service(40, 100);
    let cases = [
        (at(40), bytes.clone(), digest(at(40), &bytes) ^ 0xFF),
        (at(45), bytes.clone(), digest(at(45), &bytes)),
    ];
    for (base, bytes, digest) in cases {
        let (mut server, recorder) = follower();
        // Every piece written, then the check fails: the sender is never
        // told it was installed, so its transfer is not taken for done.
        let mut last = Out::new();
        for piece in pieces(base, 5, &bytes, digest) {
            last = deliver(&mut server, piece, 1);
        }
        assert!(installs(&recorder).is_empty(), "{base:?}");
        assert_eq!(refusals(&recorder), 1, "{base:?}");
        assert!(
            last.is_empty(),
            "the last piece of a refused snapshot is not acknowledged"
        );
        // Refused, it was never published: a right one installs after it,
        // and only then is acknowledged installed.
        let right = service(base.index, 100);
        let all = pieces(base, 6, &right, self::digest(base, &right));
        let count = all.len();
        for (at, piece) in all.into_iter().enumerate() {
            let out = deliver(&mut server, piece, 2);
            let expected: Vec<u64> = if at + 1 == count { vec![6] } else { vec![] };
            assert_eq!(installed(&out), expected, "{base:?} piece {at}");
        }
        assert_eq!(installs(&recorder), vec![base]);
        // A piece of a base it stands on: acknowledged installed again, so
        // a sender whose acknowledgement was lost ends its transfer.
        let again = pieces(base, 7, &right, self::digest(base, &right));
        let out = deliver(&mut server, again[0].clone(), 3);
        assert_eq!(installed(&out), vec![7]);
        assert_eq!(installs(&recorder), vec![base]);
    }
}

#[test]
fn a_stalled_transfer_is_dropped_and_a_crashed_one_starts_again() {
    let (mut server, recorder) = follower();
    let bytes = service(40, 100);
    let all = pieces(at(40), 7, &bytes, digest(at(40), &bytes));
    let _ = deliver(&mut server, all[0].clone(), 1);
    let mut out = Out::new();
    server.tick(SNAPSHOT_STALL + 2, &mut out);
    assert_eq!(abandoned(&recorder), vec![(7, "stalled")]);
    // A crash mid-transfer: after the restart its next piece is stale, and
    // a new transfer from 0 installs.
    let _ = deliver(&mut server, all[0].clone(), SNAPSHOT_STALL + 3);
    server.crash();
    server.restart(SNAPSHOT_STALL + 4);
    let out = deliver(&mut server, all[1].clone(), SNAPSHOT_STALL + 5);
    assert!(
        acks(&out).is_empty(),
        "a piece of a transfer the crash ended"
    );
    for piece in pieces(at(40), 8, &bytes, digest(at(40), &bytes)) {
        let _ = deliver(&mut server, piece, SNAPSHOT_STALL + 6);
    }
    assert_eq!(installs(&recorder), vec![at(40)]);
}

/// Two starts at the same base, reordered: a retry's transfer is not
/// replaced by the earlier transfer's delayed first piece, and a later
/// sender's term at that base supersedes while an earlier one does not.
#[test]
fn a_delayed_start_at_the_same_base_does_not_replace_a_newer_transfer() {
    let (mut server, recorder) = follower();
    let bytes = service(40, 100);
    let good = digest(at(40), &bytes);
    let first = pieces_in(2, at(40), 1, &bytes, good);
    let retry = pieces_in(2, at(40), 2, &bytes, good);
    let _ = deliver(&mut server, first[0].clone(), 1);
    let _ = deliver(&mut server, retry[0].clone(), 2);
    assert_eq!(abandoned(&recorder), vec![(1, "superseded")]);
    // The first transfer's start, delayed: ignored.
    let out = deliver(&mut server, first[0].clone(), 3);
    assert!(out.is_empty());
    // A start of an earlier term at the same base: ignored too.
    let stale = pieces_in(1, at(40), 9, &bytes, good);
    assert!(deliver(&mut server, stale[0].clone(), 4).is_empty());
    assert_eq!(abandoned(&recorder), vec![(1, "superseded")]);
    // A later term's start at the same base supersedes the retry.
    let later = pieces_in(3, at(40), 1, &bytes, good);
    let _ = deliver(&mut server, later[0].clone(), 5);
    assert_eq!(
        abandoned(&recorder),
        vec![(1, "superseded"), (2, "superseded")]
    );
    let mut last = Out::new();
    for piece in &later[1..] {
        last = deliver(&mut server, piece.clone(), 6);
    }
    assert_eq!(installed(&last), vec![1]);
    assert_eq!(installs(&recorder), vec![at(40)]);
}
