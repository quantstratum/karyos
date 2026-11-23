// SPDX-License-Identifier: Apache-2.0

//! karyos#1113: a steady cycle of the source's recorder and replication
//! allocates nothing once warmed up. Each cycle the recorder appends a
//! frame to its segment store and syncs it, the integrity journal seals
//! the range, the replication reads the new seal records into a reused
//! buffer, and its sender reads the sealed bytes into pooled chunks the
//! consumer drops straight back, all over a counting global allocator and
//! the real disk. The agent's and the server's own steady tests
//! (`agent::tests::a_steady_continuous_replication_allocates_nothing`,
//! `server::tests::forwarding_a_steady_replication_allocates_nothing`)
//! count the replication duty and the forwarding; this one counts the
//! recorder's write path with them. Tiering's offload is offline
//! (ADR-0104) and never runs in this cycle.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::PathBuf;

use karyos_archive::disk::StdDisk;
use karyos_archive::integrity::SealRecord;
use karyos_archive::integrity::journal::IntegrityJournal;
use karyos_archive::replication::transport::{Outgoing, Sender};
use karyos_archive::replication::{Mode, ReplicateRecording};
use karyos_archive::segment::{Geometry, SegmentStore, SyncPolicy};
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const RECORDING: u64 = 5;
const FRAME: usize = 96;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-recorder-replication-alloc-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The source's state across cycles, every buffer reused.
struct Source {
    store: SegmentStore<StdDisk>,
    journal: IntegrityJournal<StdDisk>,
    sender: Sender,
    seals: Vec<SealRecord>,
    records: Vec<SealRecord>,
    read: u64,
    out: Vec<Outgoing>,
    frame: [u8; FRAME],
    at: u64,
    sent: u64,
}

impl Source {
    /// One cycle: record a frame, seal it, replicate it.
    fn cycle(&mut self) {
        let index = u8::try_from(self.at / FRAME as u64 % 200).unwrap();
        self.frame.fill(index);
        self.at = self.store.append(self.at, &self.frame).unwrap();
        let _ = self.store.sync().unwrap();
        let start = self.at - FRAME as u64;
        let _ = self
            .journal
            .seal_segment(RECORDING, start, &self.frame, false)
            .unwrap();
        self.records.clear();
        self.journal
            .records_from_into(self.read, &mut self.records)
            .unwrap();
        self.read += self.records.len() as u64;
        self.seals.extend(
            self.records
                .iter()
                .filter(|record| record.subject == RECORDING && record.kind.is_range())
                .copied(),
        );
        // The replication keeps only the seals it has not sent.
        let sent = self.sender.sent_end();
        self.seals.retain(|seal| seal.end > sent);
        self.out.clear();
        self.sender
            .poll(&mut self.store, &self.seals, false, 1 << 20, &mut self.out)
            .unwrap();
        for message in self.out.drain(..) {
            match message {
                Outgoing::Bytes { start, bytes } => {
                    assert_eq!(start, self.sent);
                    self.sent += bytes.as_slice().len() as u64;
                }
                Outgoing::Seal(seal) => assert_eq!(seal.end, self.sent),
                _ => {}
            }
        }
    }
}

#[test]
fn a_steady_recorder_and_replication_cycle_allocates_nothing() {
    let dir = dir("steady");
    // Segments far longer than the run: no roll opens a file in it.
    let geometry = Geometry::new(1 << 16, 1 << 26).unwrap();
    let store = SegmentStore::create(
        StdDisk,
        &dir,
        RECORDING,
        geometry,
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    let journal = IntegrityJournal::open(StdDisk, &dir).unwrap().journal;
    let sender = Sender::accept(
        ReplicateRecording {
            correlation_id: 1,
            recording_id: RECORDING,
            from: 0,
            until: u64::MAX,
            mode: Mode::Continuous,
        },
        true,
        0,
        &[],
    )
    .unwrap()
    .with_chunk(32);
    let mut source = Source {
        store,
        journal,
        sender,
        seals: Vec::with_capacity(64),
        records: Vec::with_capacity(64),
        read: 0,
        out: Vec::with_capacity(64),
        frame: [0; FRAME],
        at: 0,
        sent: 0,
    };
    // Warm up until every chunk buffer of a cycle exists and comes back.
    for _ in 0..64 {
        source.cycle();
    }
    let ((), allocations) = count(|| {
        for _ in 0..256 {
            source.cycle();
        }
    });
    assert_eq!(source.sent, source.at, "every recorded byte was replicated");
    assert_eq!(allocations, 0, "a steady cycle allocates nothing");
    let _ = std::fs::remove_dir_all(&dir);
}
