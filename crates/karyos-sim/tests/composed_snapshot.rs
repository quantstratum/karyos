// SPDX-License-Identifier: Apache-2.0

//! R-CORE-9 (karyos#746): a snapshot composed by a sequencer-shaped
//! service, through the public callback (`ClusteredService::snapshot` and
//! `ServiceContainer::snapshot`), over C2's crashing disk.
//!
//! A container applies a fixed log; at indices 10, 20 and 30 it composes a
//! snapshot (sessions, timers and three service parts: books, the
//! service's own sessions, reference data) and writes it with a consensus
//! section through C8a's store, keeping two. The run is repeated with the
//! disk crashing at each of its operations (the sections' appends and
//! syncs, the close, the manifest's replacement, the purge) and with each
//! flush failing, then reopened under every survival mode.
//!
//! At every crash point, the newest snapshot that survives:
//!
//! 1. is one that was published, or the one in flight, whole;
//! 2. restores into a new container, every part naming the same applied
//!    index as the snapshot, never parts of two moments;
//! 3. leaves the restored container equal to one that applied the log up
//!    to that index, and both apply the rest of the log alike.
//!
//! So a reader finds either the previous snapshot or the complete new one,
//! never a mixture.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_archive::segment::Geometry;
use karyos_cluster::dedup::{DedupConfig, Request};
use karyos_cluster::log::Entry;
use karyos_cluster::service::{
    ClusteredService, ContainerConfig, Context, Envelope, RestoreRefused, ServiceContainer,
    ServicePart, ServiceSnapshot, SnapshotFull,
};
use karyos_cluster::snapshot::{Section, SectionKind, SnapshotConfig, SnapshotStore};
use karyos_sim::disk::{SimDisk, Survives};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios;

const DIR: &str = "/snapshots";
const POINTS: [u64; 3] = [10, 20, 30];
const LAST: u64 = 40;

/// Books, the service's own sessions, reference data: each part starts
/// with the index it was written at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Sequencer {
    book: Vec<u64>,
    orders: Vec<u64>,
    price: u64,
    seen: u64,
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

fn words(seen: u64, values: &[u64]) -> Vec<u8> {
    let mut out = seen.to_le_bytes().to_vec();
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

impl ClusteredService for Sequencer {
    fn on_command(
        &mut self,
        context: &mut Context<'_>,
        _client: u64,
        command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize> {
        self.seen = context.index();
        let value = word(&command[1..]);
        match command[0] {
            0 => {
                self.book.push(value);
                self.orders.push(context.index());
            }
            _ => self.price = value,
        }
        reply
            .get_mut(..8)?
            .copy_from_slice(&self.seen.to_le_bytes());
        Some(8)
    }

    fn on_timer(&mut self, _context: &mut Context<'_>, _timer: u64) {}

    fn on_configuration(&mut self, _context: &mut Context<'_>, _configuration: &[u8]) {}

    fn snapshot(&self, parts: &mut ServiceSnapshot) -> Result<(), SnapshotFull> {
        parts.part(1, 1, &words(self.seen, &self.book))?;
        parts.part(2, 1, &words(self.seen, &self.orders))?;
        parts.part(3, 1, &words(self.seen, &[self.price]))
    }

    fn restore(&mut self, parts: &[ServicePart<'_>]) -> Result<(), RestoreRefused> {
        let [book, orders, reference] = parts else {
            return Err(RestoreRefused::MissingPart { id: 1 });
        };
        let seen = word(book.bytes);
        for part in parts {
            if word(part.bytes) != seen {
                return Err(RestoreRefused::Malformed { id: part.id });
            }
        }
        let tail = |part: &ServicePart<'_>| part.bytes[8..].chunks(8).map(word).collect();
        *self = Self {
            book: tail(book),
            orders: tail(orders),
            price: word(&reference.bytes[8..]),
            seen,
        };
        Ok(())
    }
}

fn config() -> ContainerConfig {
    ContainerConfig::default()
        .with_dedup(
            DedupConfig::default()
                .with_sessions(4)
                .with_window(4)
                .with_response_bytes(16)
                .with_ttl(1_000_000),
        )
        .with_timers(2)
}

fn container() -> ServiceContainer<Sequencer> {
    ServiceContainer::new(Sequencer::default(), config()).unwrap()
}

/// Applies entries `from..=to` of the fixed log: client 7 registers at 1,
/// then rests an order at every entry and sets a price at each fourth.
fn apply(container: &mut ServiceContainer<Sequencer>, from: u64, to: u64) {
    for index in from..=to {
        let envelope_bytes;
        let envelope = if index == 1 {
            Envelope::Register { client: 7 }
        } else {
            let sequence = index - 2;
            let mut command = vec![u8::from(index % 4 == 0)];
            command.extend_from_slice(&(index * 3).to_le_bytes());
            envelope_bytes = command;
            Envelope::Request {
                request: Request::new(7, 1, sequence, sequence),
                command: &envelope_bytes,
            }
        };
        let entry = Entry {
            index,
            term: 1,
            event_time: index,
            payload: envelope.to_vec().unwrap(),
        };
        container.apply(&entry).unwrap();
    }
}

fn geometry() -> Geometry {
    Geometry::new(4096, 4096).unwrap()
}

/// The sections of the snapshot composed at `index`, consensus first.
fn compose(container: &ServiceContainer<Sequencer>) -> (u64, Vec<(SectionKind, u64, Vec<u8>)>) {
    let mut parts = ServiceSnapshot::new(4096, 4);
    let composed = container.snapshot(&mut parts).unwrap();
    let mut sections = vec![(
        SectionKind::Consensus,
        1,
        composed.index.to_le_bytes().to_vec(),
    )];
    sections.extend(
        composed
            .sections()
            .iter()
            .map(|section| (section.kind, section.version, section.bytes.to_vec())),
    );
    (composed.index, sections)
}

#[derive(Debug, Default)]
struct Model {
    published: Vec<u64>,
    writing: Option<u64>,
    completed: bool,
}

fn run(disk: SimDisk) -> Model {
    let mut model = Model::default();
    let Ok(opened) =
        SnapshotStore::open(disk, Path::new(DIR), geometry(), SnapshotConfig::default())
    else {
        return model;
    };
    let mut store = opened.store;
    let mut node = container();
    let mut applied = 0;
    for point in POINTS {
        apply(&mut node, applied + 1, point);
        applied = point;
        let (index, held) = compose(&node);
        let sections: Vec<Section<'_>> = held
            .iter()
            .map(|(kind, version, bytes)| Section::new(*kind, *version, bytes))
            .collect();
        model.writing = Some(index);
        if store.write(index, 1, &sections).is_err() {
            return model;
        }
        model.writing = None;
        model.published.push(index);
    }
    model.completed = true;
    model
}

fn check(disk: &SimDisk, survives: Survives, model: &Model) -> Result<(), String> {
    let restarted = disk
        .after_crash(survives)
        .map_err(|error| error.to_string())?;
    let opened = SnapshotStore::open(
        restarted,
        Path::new(DIR),
        geometry(),
        SnapshotConfig::default(),
    )
    .map_err(|error| format!("open: {error}"))?;
    if !opened.damaged.is_empty() {
        return Err(format!("damaged: {:?}", opened.damaged));
    }
    let store = opened.store;
    let Some(latest) = store.latest() else {
        return if model.published.is_empty() {
            Ok(())
        } else {
            Err(format!("nothing survived of {:?}", model.published))
        };
    };
    let allowed: Vec<u64> = model
        .published
        .iter()
        .copied()
        .chain(model.writing)
        .collect();
    if !allowed.contains(&latest.index) {
        return Err(format!("snapshot {} was never written", latest.index));
    }
    if model
        .published
        .last()
        .is_some_and(|last| latest.index < *last)
    {
        return Err(format!(
            "{} survived, {:?} were published",
            latest.index, model.published
        ));
    }
    let sections = store
        .read(&latest)
        .map_err(|error| format!("read {}: {error}", latest.index))?;
    let mut restored = container();
    restored
        .restore(latest.index, &sections)
        .map_err(|error| format!("restore {}: {error}", latest.index))?;
    for section in sections
        .iter()
        .filter(|section| section.kind == SectionKind::Service)
    {
        if word(&section.bytes) != latest.index {
            return Err(format!(
                "a part of snapshot {} is from {}",
                latest.index,
                word(&section.bytes)
            ));
        }
    }
    let mut reference = container();
    apply(&mut reference, 1, latest.index);
    if restored.service() != reference.service()
        || restored.sessions().encode() != reference.sessions().encode()
    {
        return Err(format!("snapshot {} restores another state", latest.index));
    }
    apply(&mut restored, latest.index + 1, LAST);
    apply(&mut reference, latest.index + 1, LAST);
    if restored.service() != reference.service() {
        return Err(format!(
            "after snapshot {} the replicas diverge",
            latest.index
        ));
    }
    Ok(())
}

fn check_all(disk: &SimDisk, model: &Model, point: u64, label: &str, failures: &mut Vec<String>) {
    let mut modes = vec![Survives::Synced, Survives::Everything];
    for seed in scenarios::seeds() {
        let mixed = Rng::new(seed ^ point.rotate_left(32)).next_u64();
        modes.push(Survives::Subset { seed: mixed });
        modes.push(Survives::Torn { seed: mixed });
    }
    for survives in modes {
        if let Err(broken) = check(disk, survives, model) {
            failures.push(format!("{label} under {survives:?}: {broken}"));
        }
    }
}

#[test]
fn every_crash_point_leaves_the_previous_or_the_complete_new_composed_snapshot() {
    let whole = SimDisk::new();
    let model = run(whole.clone());
    assert!(model.completed);
    assert_eq!(model.published, POINTS);
    let operations = whole.used();
    let mut failures = Vec::new();
    for budget in 0..=operations {
        let disk = SimDisk::with_budget(budget);
        let model = run(disk.clone());
        check_all(
            &disk,
            &model,
            budget,
            &format!("crash at operation {}", budget + 1),
            &mut failures,
        );
    }
    let mut flush = 1;
    loop {
        let disk = SimDisk::new().with_failed_syncs([flush]);
        let model = run(disk.clone());
        if model.completed {
            break;
        }
        check_all(
            &disk,
            &model,
            flush,
            &format!("flush {flush} failing"),
            &mut failures,
        );
        flush += 1;
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
