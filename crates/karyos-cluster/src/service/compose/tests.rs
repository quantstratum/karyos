// SPDX-License-Identifier: Apache-2.0

//! R-CORE-9 (karyos#746): a composed snapshot of a sequencer-shaped
//! service, three parts and the container's sections, taken at one applied
//! position and restored whole.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use super::super::{
    Applied, ClusteredService, ContainerConfig, Context, Envelope, ServiceContainer,
};
use super::*;
use crate::dedup::{DedupConfig, Request};
use crate::log::Entry;
use crate::snapshot::SectionRead;

const BOOKS: u16 = 1;
const SESSIONS: u16 = 2;
const REFERENCE: u16 = 3;

/// A sequencer's shape: a book of resting quantities, its own per-client
/// order counts, and reference data. Command `[0, q..8]` rests `q`; `[1,
/// p..8]` sets the reference price. Each part records the index of the
/// last entry it saw, so a restore shows every part is from one position.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Sequencer {
    book: Vec<u64>,
    orders: Vec<(u64, u64)>,
    price: u64,
    /// The index each part last changed at, and the last applied.
    seen: u64,
    /// The newest version of each part this build reads.
    reads: u32,
    /// Refuse every restore (a service that cannot read its parts).
    refuse: bool,
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

impl Sequencer {
    fn new() -> Self {
        Self {
            reads: 1,
            ..Self::default()
        }
    }

    fn book_bytes(&self) -> Vec<u8> {
        let mut out = self.seen.to_le_bytes().to_vec();
        for q in &self.book {
            out.extend_from_slice(&q.to_le_bytes());
        }
        out
    }

    fn orders_bytes(&self) -> Vec<u8> {
        let mut out = self.seen.to_le_bytes().to_vec();
        for (client, count) in &self.orders {
            out.extend_from_slice(&client.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
        }
        out
    }

    fn reference_bytes(&self) -> Vec<u8> {
        let mut out = self.seen.to_le_bytes().to_vec();
        out.extend_from_slice(&self.price.to_le_bytes());
        out
    }
}

impl ClusteredService for Sequencer {
    fn on_command(
        &mut self,
        context: &mut Context<'_>,
        client: u64,
        command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize> {
        self.seen = context.index();
        match command[0] {
            0 => {
                self.book.push(word(&command[1..]));
                match self.orders.iter_mut().find(|(held, _)| *held == client) {
                    Some((_, count)) => *count += 1,
                    None => self.orders.push((client, 1)),
                }
            }
            _ => self.price = word(&command[1..]),
        }
        reply
            .get_mut(..8)?
            .copy_from_slice(&self.seen.to_le_bytes());
        Some(8)
    }

    fn on_timer(&mut self, _context: &mut Context<'_>, _timer: u64) {}

    fn on_configuration(&mut self, _context: &mut Context<'_>, _configuration: &[u8]) {}

    fn snapshot(&self, parts: &mut ServiceSnapshot) -> Result<(), SnapshotFull> {
        parts.part(BOOKS, 1, &self.book_bytes())?;
        parts.part(SESSIONS, 1, &self.orders_bytes())?;
        parts.part(REFERENCE, 1, &self.reference_bytes())
    }

    fn restore(&mut self, parts: &[ServicePart<'_>]) -> Result<(), RestoreRefused> {
        if self.refuse {
            return Err(RestoreRefused::Malformed { id: BOOKS });
        }
        // Checked whole first: a refusal changes nothing.
        for part in parts {
            if !matches!(part.id, BOOKS | SESSIONS | REFERENCE) {
                return Err(RestoreRefused::UnknownPart { id: part.id });
            }
            if part.version > self.reads {
                return Err(RestoreRefused::NewerVersion {
                    id: part.id,
                    version: part.version,
                });
            }
        }
        let find = |id| {
            parts
                .iter()
                .find(|part| part.id == id)
                .ok_or(RestoreRefused::MissingPart { id })
        };
        let (book, orders, reference) = (find(BOOKS)?, find(SESSIONS)?, find(REFERENCE)?);
        let seen = word(book.bytes);
        let mut restored = Self {
            seen,
            reads: self.reads,
            ..Self::default()
        };
        restored.book = book.bytes[8..].chunks(8).map(word).collect();
        restored.orders = orders.bytes[8..]
            .chunks(16)
            .map(|pair| (word(pair), word(&pair[8..])))
            .collect();
        restored.price = word(&reference.bytes[8..]);
        // Every part is from one position.
        for part in [orders, reference] {
            if word(part.bytes) != seen {
                return Err(RestoreRefused::Malformed { id: part.id });
            }
        }
        *self = restored;
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

fn entry(index: u64, event_time: u64, envelope: Envelope<'_>) -> Entry {
    Entry {
        index,
        term: 1,
        event_time,
        payload: envelope.to_vec().unwrap(),
    }
}

fn command(kind: u8, value: u64) -> Vec<u8> {
    let mut command = vec![kind];
    command.extend_from_slice(&value.to_le_bytes());
    command
}

/// Applies entries `from..=to` of a fixed log: registrations of clients 7
/// and 8 at 1 and 2, then their orders and a price each fifth entry.
fn apply_range(container: &mut ServiceContainer<Sequencer>, from: u64, to: u64) {
    for index in from..=to {
        let applied = match index {
            1 | 2 => container.apply(&entry(
                index,
                index,
                Envelope::Register { client: 6 + index },
            )),
            _ => {
                let client = 7 + index % 2;
                let epoch = client - 6;
                // Each client's sequences, counted from 0.
                let sequence = (index - 3) / 2;
                let body = if index % 5 == 0 {
                    command(1, index * 100)
                } else {
                    command(0, index)
                };
                container.apply(&entry(
                    index,
                    index,
                    Envelope::Request {
                        request: Request::new(client, epoch, sequence, sequence),
                        command: &body,
                    },
                ))
            }
        };
        assert!(applied.is_ok(), "entry {index}: {applied:?}");
    }
}

fn reads(composed: &ComposedSnapshot<'_>) -> Vec<SectionRead> {
    composed
        .sections()
        .iter()
        .map(|section| SectionRead {
            kind: section.kind,
            version: section.version,
            bytes: section.bytes.to_vec(),
        })
        .collect()
}

/// A composed snapshot of three service parts and the container's
/// sections, every one from the last applied index, restored into a new
/// container; both then apply the rest of the log alike.
#[test]
fn a_composed_snapshot_is_taken_at_one_position_and_restored_whole() {
    let mut original = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut original, 1, 20);
    let mut parts = ServiceSnapshot::new(4096, 8);
    let composed = original.snapshot(&mut parts).unwrap();
    assert_eq!(composed.index, 20);
    let sections = reads(&composed);
    let kinds: Vec<SectionKind> = sections.iter().map(|section| section.kind).collect();
    assert_eq!(
        kinds,
        [
            SectionKind::Sessions,
            SectionKind::Timers,
            SectionKind::Service,
            SectionKind::Service,
            SectionKind::Service,
        ]
    );
    // Each service part names the index it is from: all 20.
    for section in sections.iter().filter(|s| s.kind == SectionKind::Service) {
        assert_eq!(word(&section.bytes), 20);
    }
    let mut restored = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    restored.restore(composed.index, &sections).unwrap();
    assert_eq!(restored.service(), original.service());
    assert_eq!(restored.applied(), Some(20));
    assert_eq!(restored.sessions().encode(), original.sessions().encode());
    apply_range(&mut original, 21, 30);
    apply_range(&mut restored, 21, 30);
    assert_eq!(restored.service(), original.service());
    assert_eq!(restored.sessions().encode(), original.sessions().encode());
}

/// A retry after the restore gets its retained reply: the sessions section
/// carries the outcomes (R-CORE-6's durable sessions and snapshots).
#[test]
fn a_restored_container_answers_a_retry_from_its_window() {
    let mut original = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut original, 1, 6);
    let mut parts = ServiceSnapshot::new(4096, 8);
    let sections = reads(&original.snapshot(&mut parts).unwrap());
    let mut restored = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    restored.restore(6, &sections).unwrap();
    // Entry 6 was client 7's sequence 1; it is retried at 7.
    let body = command(0, 6);
    let retry = restored
        .apply(&entry(
            7,
            7,
            Envelope::Request {
                request: Request::new(7, 1, 1, 1),
                command: &body,
            },
        ))
        .unwrap();
    assert!(
        matches!(
            retry,
            Applied::Answered {
                outcome: crate::dedup::Outcome::Retained(reply),
                ..
            } if reply == 6u64.to_le_bytes()
        ),
        "{retry:?}"
    );
}

/// A refused restore changes nothing: a service part of a newer version,
/// an unknown part id, a service that cannot read its parts, a missing
/// container section, a timers section that does not decode.
#[test]
fn a_refused_restore_leaves_the_container_unchanged() {
    let mut source = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut source, 1, 12);
    let mut parts = ServiceSnapshot::new(4096, 8);
    let good = reads(&source.snapshot(&mut parts).unwrap());
    let mut target = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut target, 1, 4);
    let before = (
        target.service().clone(),
        target.applied(),
        target.sessions().encode(),
    );
    let mut newer = good.clone();
    let service = newer
        .iter_mut()
        .find(|section| section.kind == SectionKind::Service)
        .unwrap();
    service.version = ServicePart::new(BOOKS, 2, &[]).section_version();
    let mut unknown = good.clone();
    unknown.push(SectionRead {
        kind: SectionKind::Service,
        version: ServicePart::new(99, 1, &[]).section_version(),
        bytes: Vec::new(),
    });
    let no_timers: Vec<SectionRead> = good
        .iter()
        .filter(|section| section.kind != SectionKind::Timers)
        .cloned()
        .collect();
    let mut bad_timers = good.clone();
    for section in &mut bad_timers {
        if section.kind == SectionKind::Timers {
            section.bytes = vec![9, 0, 0, 0];
        }
    }
    let cases: Vec<(Vec<SectionRead>, RestoreError)> = vec![
        (
            newer,
            RestoreError::Service(RestoreRefused::NewerVersion {
                id: BOOKS,
                version: 2,
            }),
        ),
        (
            unknown,
            RestoreError::Service(RestoreRefused::UnknownPart { id: 99 }),
        ),
        (no_timers, RestoreError::Missing(SectionKind::Timers)),
        (bad_timers, RestoreError::Timers),
    ];
    for (sections, expected) in cases {
        assert_eq!(target.restore(12, &sections), Err(expected.clone()));
        let after = (
            target.service().clone(),
            target.applied(),
            target.sessions().encode(),
        );
        assert_eq!(after, before, "{expected:?}");
    }
    let mut refusing = ServiceContainer::new(
        Sequencer {
            refuse: true,
            ..Sequencer::new()
        },
        config(),
    )
    .unwrap();
    assert_eq!(
        refusing.restore(12, &good),
        Err(RestoreError::Service(RestoreRefused::Malformed {
            id: BOOKS
        }))
    );
    assert_eq!(refusing.applied(), None);
}

/// Session bounds other than the container's are refused.
#[test]
fn a_snapshot_of_other_session_bounds_is_refused() {
    let mut source = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut source, 1, 4);
    let mut parts = ServiceSnapshot::new(4096, 8);
    let sections = reads(&source.snapshot(&mut parts).unwrap());
    let other = ContainerConfig::default().with_dedup(
        DedupConfig::default()
            .with_sessions(8)
            .with_window(4)
            .with_response_bytes(16)
            .with_ttl(1_000_000),
    );
    let mut target = ServiceContainer::new(Sequencer::new(), other).unwrap();
    assert_eq!(
        target.restore(4, &sections),
        Err(RestoreError::SessionBounds)
    );
}

/// The sink's budget: bytes, slots and repeated ids are refused, typed,
/// and the snapshot is not taken; the reservation counts the metadata.
#[test]
fn the_parts_budget_is_typed_and_counts_its_metadata() {
    let mut parts = ServiceSnapshot::new(16, 2);
    assert_eq!(parts.part(1, 1, &[0; 10]), Ok(()));
    assert_eq!(
        parts.part(2, 1, &[0; 7]),
        Err(SnapshotFull::Bytes { budget: 16 })
    );
    assert_eq!(
        parts.part(1, 1, &[0; 1]),
        Err(SnapshotFull::Repeated { id: 1 })
    );
    assert_eq!(parts.part(2, 1, &[0; 6]), Ok(()));
    assert_eq!(parts.part(3, 1, &[]), Err(SnapshotFull::Parts { slots: 2 }));
    assert_eq!(parts.parts().count(), 2);
    assert_eq!(
        ServiceSnapshot::reserved_bytes(16, 2),
        Some(16 + 2 * PART_METADATA)
    );
    assert_eq!(PART_METADATA, 48);
    // A service whose parts do not fit: no snapshot.
    let mut container = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut container, 1, 10);
    let mut small = ServiceSnapshot::new(8, 8);
    assert!(matches!(
        container.snapshot(&mut small),
        Err(ComposeError::Full(SnapshotFull::Bytes { .. }))
    ));
    let empty = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    assert!(matches!(
        empty.snapshot(&mut small),
        Err(ComposeError::NothingApplied)
    ));
}

/// A part's id and version travel in the section's version, and a version
/// that does not hold them is refused.
#[test]
fn a_part_round_trips_through_its_section_version() {
    let part = ServicePart::new(513, 7, b"x");
    assert_eq!(
        ServicePart::of_section(part.section_version(), b"x"),
        Some(part)
    );
    assert_eq!(ServicePart::of_section(1 << 48, b""), None);
}

fn raw(index: u64, event_time: u64, payload: Vec<u8>) -> Entry {
    Entry {
        index,
        term: 1,
        event_time,
        payload,
    }
}

/// Codex review of #1270 (P1): a snapshot taken before the log's guard
/// bounds applied has no guards section and restores a fresh guard table,
/// not the target's guards of another position.
#[test]
fn a_snapshot_without_guards_restores_a_fresh_guard_table() {
    use crate::guards::GuardEntry;

    let mut source = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut source, 1, 6);
    let mut parts = ServiceSnapshot::new(4096, 8);
    let sections = reads(&source.snapshot(&mut parts).unwrap());
    assert!(
        sections
            .iter()
            .all(|section| section.kind != SectionKind::Guards)
    );
    let mut target = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    let bounds = target.guards().bounds();
    target
        .apply(&raw(1, 1, GuardEntry::Bounds(bounds).to_vec().unwrap()))
        .unwrap();
    assert!(target.guards().bounds_logged());
    target.restore(6, &sections).unwrap();
    assert!(!target.guards().bounds_logged(), "the snapshot's guards");
    assert!(target.guards().guards().is_empty());
}

/// Codex review of #1270 (P1): the session bootstrap state is restored
/// from the snapshot: one taken before the log's session bounds applied
/// leaves a restored leader proposing them, and one taken after does not.
#[test]
fn the_session_bootstrap_state_travels_in_the_snapshot() {
    use crate::service::SessionBounds;

    let mut before = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    // A leader's empty entry: applied, no bounds yet.
    before.apply(&raw(1, 1, Vec::new())).unwrap();
    let mut parts = ServiceSnapshot::new(4096, 8);
    let sections = reads(&before.snapshot(&mut parts).unwrap());
    let mut restored = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    restored.restore(1, &sections).unwrap();
    assert!(!restored.bounds_logged(), "the bounds are still to propose");
    let mut after = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    let bounds = SessionBounds::new(after.sessions().config());
    after.apply(&raw(1, 1, bounds.to_vec().unwrap())).unwrap();
    let sections = reads(&after.snapshot(&mut parts).unwrap());
    let mut restored = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    restored.restore(1, &sections).unwrap();
    assert!(restored.bounds_logged());
}

/// Codex review of #1270 (P1, P2): bounds the log carried, which a fresh
/// replica adopted, restore into a replica configured otherwise, as the
/// log's entry would; within the container's session budget, refused
/// before anything is allocated.
#[test]
fn logged_session_bounds_restore_within_the_budget() {
    use crate::service::SessionBounds;

    // Larger than the configured table, so a budget can hold one and not
    // the other.
    let logged = DedupConfig::default()
        .with_sessions(8)
        .with_window(8)
        .with_response_bytes(16)
        .with_ttl(1_000_000);
    let mut source = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    source
        .apply(&raw(1, 1, SessionBounds::new(logged).to_vec().unwrap()))
        .unwrap();
    assert_eq!(source.sessions().config(), logged);
    let mut parts = ServiceSnapshot::new(4096, 8);
    let sections = reads(&source.snapshot(&mut parts).unwrap());
    let mut target = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    target.restore(1, &sections).unwrap();
    assert_eq!(target.sessions().config(), logged);
    let asked = logged.reserved_bytes().unwrap();
    let mut tight =
        ServiceContainer::new(Sequencer::new(), config().with_session_budget(asked - 1));
    // A container whose own table fits the tight budget.
    if let Ok(tight) = tight.as_mut() {
        assert!(matches!(
            tight.restore(1, &sections),
            Err(RestoreError::Sessions(crate::dedup::DecodeError::Config(
                crate::dedup::ConfigError::OverBudget { .. }
            )))
        ));
        assert_eq!(tight.applied(), None);
    } else {
        panic!("the tight container does not hold its own table");
    }
}

/// karyos#1019: a snapshot taken after a registration, with a live
/// session, restores into a fresh container as no longer fresh, so a
/// `SessionBounds` entry that differs from the restored table stops the
/// container with `BoundsDiffer` and keeps the restored sessions; the same
/// entry on a container never restored rebuilds its table instead.
#[test]
fn different_bounds_after_a_restore_with_a_session_stop_the_container() {
    use crate::service::{ApplyError, SessionBounds};

    let mut source = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut source, 1, 1);
    assert_eq!(source.sessions().live_sessions(), 1);
    let mut parts = ServiceSnapshot::new(4096, 8);
    let sections = reads(&source.snapshot(&mut parts).unwrap());
    let mut restored = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    restored.restore(1, &sections).unwrap();
    assert_eq!(restored.sessions(), source.sessions());
    let table = restored.sessions().config();
    let logged = table.with_sessions(2).with_ttl(500);
    assert_ne!(logged, table);
    assert_eq!(
        restored.apply(&raw(2, 2, SessionBounds::new(logged).to_vec().unwrap())),
        Err(ApplyError::BoundsDiffer { logged, table })
    );
    assert_eq!(restored.sessions(), source.sessions(), "the sessions kept");
    // A container with nothing applied is fresh: the same bounds rebuild
    // its table.
    let mut fresh = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    fresh
        .apply(&raw(1, 1, SessionBounds::new(logged).to_vec().unwrap()))
        .unwrap();
    assert_eq!(fresh.sessions().config(), logged);
}

/// Different logged bounds after a snapshot install with a live session
/// are a typed stop, never a rebuild: the restored container is not fresh
/// (karyos#1019).
#[test]
fn different_bounds_after_a_restore_with_a_live_session_stop() {
    use crate::service::{ApplyError, SessionBounds};

    let mut source = ServiceContainer::new(Sequencer::new(), config()).unwrap();
    apply_range(&mut source, 1, 6);
    assert!(source.sessions().live_sessions() > 0);
    let mut parts = ServiceSnapshot::new(4096, 8);
    let sections = reads(&source.snapshot(&mut parts).unwrap());
    let other = DedupConfig::default()
        .with_sessions(8)
        .with_window(8)
        .with_response_bytes(16)
        .with_ttl(1_000_000);
    let bounds = SessionBounds::new(other).to_vec().unwrap();
    // As restored, and with the snapshot's fresh flag forced on: both stop.
    let mut forged = sections.clone();
    let timers = forged
        .iter_mut()
        .find(|section| section.kind == SectionKind::Timers)
        .unwrap();
    timers.bytes[0] |= FRESH;
    for sections in [sections, forged] {
        let mut restored = ServiceContainer::new(Sequencer::new(), config()).unwrap();
        restored.restore(6, &sections).unwrap();
        let before = restored.sessions().encode();
        let table = restored.sessions().config();
        let result = restored.apply(&raw(7, 7, bounds.clone())).map(|_| ());
        assert!(
            matches!(result, Err(ApplyError::BoundsDiffer { .. })),
            "{result:?}"
        );
        assert_eq!(restored.sessions().encode(), before);
        assert_eq!(restored.sessions().config(), table);
    }
}
