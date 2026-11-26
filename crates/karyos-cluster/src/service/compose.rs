// SPDX-License-Identifier: Apache-2.0

//! The service's snapshot callback and the composed snapshot (R-CORE-9,
//! karyos#746; quantstratum-docs:
//! karyos/design/cluster-dedup-and-snapshots.md §3).
//!
//! # The contract
//!
//! - **One applied position.** [`ServiceContainer::snapshot`] takes the
//!   container's own sections (sessions, timers, guards) and asks the
//!   service, through [`ClusteredService::snapshot`], for its parts, all
//!   between two applies: no entry applies while it runs (it borrows the
//!   container), so every section of the result is the state after the
//!   same last applied entry, [`ComposedSnapshot::index`]. A service whose
//!   state is several parts (a sequencer's books, its own session state,
//!   its reference data) writes each as a [`ServicePart`]; none can come
//!   from another moment of the log.
//! - **Published whole or not at all.** The composed sections go to the
//!   snapshot store ([`crate::snapshot::SnapshotStore::write`]) as one
//!   snapshot: every section is written and synced before the manifest is
//!   replaced, and recovery removes what no manifest names. At every
//!   crash point a reader finds the previous snapshot or the complete new
//!   one, never a mixture (karyos-sim `tests/composed_snapshot.rs`).
//! - **Restored whole or not at all.** [`ServiceContainer::restore`]
//!   decodes and checks every container section first, then hands the
//!   service its parts ([`ClusteredService::restore`]), and only when the
//!   service accepts them replaces its own tables. A service must leave
//!   its state unchanged when it refuses, so a refused restore changes
//!   nothing. Every container table is replaced from the snapshot's one
//!   position: a snapshot taken before the log's guard bounds applied has
//!   no guards section, and restores a fresh guard table; the session
//!   bootstrap state (whether the log's session bounds have applied, and
//!   whether a registration has) travels in the timers section, so a
//!   restored leader still proposes the bounds a snapshot was taken
//!   before. A snapshot whose logged session bounds differ from the
//!   container's configured ones restores them, as the log's bounds entry
//!   would, within the container's session budget; bounds the log never
//!   carried must match.
//! - **Versions.** A part carries its own id and version. A service meets
//!   a part id it does not know, or a version newer than it reads, with a
//!   typed refusal ([`RestoreRefused`]), never a guess; the snapshot is
//!   then not installed. A section kind the store does not know is
//!   [`crate::snapshot::SnapshotError::UnknownSection`] at read: a newer
//!   writer, told apart from damage.
//! - **Memory.** The service's parts go into a [`ServiceSnapshot`] whose
//!   bytes and part slots are allocated once, at [`ServiceSnapshot::new`]:
//!   [`ServiceSnapshot::reserved_bytes`] is that budget, metadata
//!   included (item 37 of the decisions of 2026-10-21). A part past the
//!   budget is refused ([`SnapshotFull`]) and the snapshot is not taken.
//! - **Not promised.** The store's checks are CRC-32C: they detect
//!   corruption and claim no tamper evidence (item 37; item 15). Nothing
//!   is promised about a part's internal consistency beyond what the
//!   service writes at one position; the core reads none of its bytes.

use crate::dedup::{DecodeError, SessionTable};
use crate::guards::{GuardTable, SectionError};
use crate::snapshot::{Section, SectionKind, SectionRead};

use super::{ClusteredService, ServiceContainer, Timers};

/// The parts a [`ServiceSnapshot`] holds at most, whatever its budget.
pub const MAX_SERVICE_PARTS: usize = 64;

/// The metadata one part costs in a [`ServiceSnapshot`] and on disk: its
/// slot (id, version, offset, length) and its section header.
pub const PART_METADATA: u64 = 24 + crate::snapshot::SECTION_HEADER as u64;

/// The version of the timers section: the container's session bootstrap
/// flags (bit 0: the log's session bounds applied; bit 1: no registration
/// applied yet), then the timers.
pub const TIMERS_VERSION: u64 = 1;
const BOUNDS_LOGGED: u8 = 1;
const FRESH: u8 = 2;
/// The version of the sessions section this build writes: 2 since
/// karyos#715, the log's version state (the active version, whether a
/// configuration has activated, any pending `Activation` and any logged
/// `CoordinatedStop`, ADR-0122 decision 5) ahead of the session table
/// ([`SessionTable::encode`]).
pub const SESSIONS_SECTION_VERSION: u64 = 2;
/// The sessions section earlier builds wrote: the session table alone,
/// restored as the state before any `Activation`.
pub const SESSIONS_SECTION_VERSION_1: u64 = 1;

/// One part of a service's state, as it writes or restores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServicePart<'a> {
    /// The service's own id for the part, unique within a snapshot.
    pub id: u16,
    /// The part's schema version, the service's.
    pub version: u32,
    /// Its bytes.
    pub bytes: &'a [u8],
}

impl<'a> ServicePart<'a> {
    /// Part `id` of `version` holding `bytes`.
    #[must_use]
    pub const fn new(id: u16, version: u32, bytes: &'a [u8]) -> Self {
        Self { id, version, bytes }
    }

    /// The version a `Service` section carries for this part: the id in
    /// bits 32 to 47, the part's version below.
    #[must_use]
    pub const fn section_version(&self) -> u64 {
        ((self.id as u64) << 32) | self.version as u64
    }

    /// The part a `Service` section of `version` holding `bytes` is.
    #[must_use]
    pub fn of_section(version: u64, bytes: &'a [u8]) -> Option<Self> {
        if version >> 48 != 0 {
            return None;
        }
        Some(Self {
            id: u16::try_from(version >> 32).ok()?,
            version: u32::try_from(version & 0xffff_ffff).ok()?,
            bytes,
        })
    }
}

/// A part did not fit the [`ServiceSnapshot`]'s budget, or its id repeats
/// one already written: the snapshot is not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SnapshotFull {
    /// The parts' bytes would pass the budget.
    #[error("the service's parts pass the snapshot budget of {budget} bytes")]
    Bytes {
        /// The budget.
        budget: usize,
    },
    /// More parts than the budget's slots.
    #[error("more than {slots} service parts")]
    Parts {
        /// The slots.
        slots: usize,
    },
    /// A part id written twice.
    #[error("service part {id} written twice")]
    Repeated {
        /// The id.
        id: u16,
    },
}

/// Why a service refused the parts of a snapshot: it is not installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RestoreRefused {
    /// A part id this service does not know: a newer writer.
    #[error("service part {id} is unknown to this service")]
    UnknownPart {
        /// The id.
        id: u16,
    },
    /// A part version newer than this service reads.
    #[error("service part {id} of version {version} is newer than this service reads")]
    NewerVersion {
        /// The id.
        id: u16,
        /// The version.
        version: u32,
    },
    /// A part this service needs is missing.
    #[error("service part {id} is missing")]
    MissingPart {
        /// The id.
        id: u16,
    },
    /// A part's bytes do not read as its version.
    #[error("service part {id} is malformed")]
    Malformed {
        /// The id.
        id: u16,
    },
}

/// The service's parts of one snapshot, in bytes and slots allocated once
/// ([`ServiceSnapshot::new`]); reused from one snapshot to the next.
#[derive(Debug, Clone)]
pub struct ServiceSnapshot {
    bytes: Vec<u8>,
    budget: usize,
    /// Id, version, start, length.
    parts: Vec<(u16, u32, usize, usize)>,
    slots: usize,
}

impl ServiceSnapshot {
    /// A sink for up to `slots` parts (at most [`MAX_SERVICE_PARTS`]) of
    /// `budget` bytes in all, allocated here only.
    #[must_use]
    pub fn new(budget: usize, slots: usize) -> Self {
        let slots = slots.min(MAX_SERVICE_PARTS);
        Self {
            bytes: Vec::with_capacity(budget),
            budget,
            parts: Vec::with_capacity(slots),
            slots,
        }
    }

    /// The memory and disk a snapshot of `budget` bytes in `slots` parts
    /// reserves, metadata included: the bytes, and [`PART_METADATA`] per
    /// part. `None` on overflow.
    #[must_use]
    pub fn reserved_bytes(budget: usize, slots: usize) -> Option<u64> {
        let slots = u64::try_from(slots.min(MAX_SERVICE_PARTS)).ok()?;
        u64::try_from(budget)
            .ok()?
            .checked_add(slots.checked_mul(PART_METADATA)?)
    }

    /// Writes part `id` of `version`: its bytes are copied once.
    ///
    /// # Errors
    ///
    /// [`SnapshotFull`]: nothing is written.
    pub fn part(&mut self, id: u16, version: u32, bytes: &[u8]) -> Result<(), SnapshotFull> {
        if self.parts.iter().any(|(held, ..)| *held == id) {
            return Err(SnapshotFull::Repeated { id });
        }
        if self.parts.len() >= self.slots {
            return Err(SnapshotFull::Parts { slots: self.slots });
        }
        let start = self.bytes.len();
        if start
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.budget)
        {
            return Err(SnapshotFull::Bytes {
                budget: self.budget,
            });
        }
        self.bytes.extend_from_slice(bytes);
        self.parts.push((id, version, start, bytes.len()));
        Ok(())
    }

    /// The parts written, in order.
    pub fn parts(&self) -> impl Iterator<Item = ServicePart<'_>> {
        self.parts
            .iter()
            .filter_map(|&(id, version, start, length)| {
                let bytes = self.bytes.get(start..start.checked_add(length)?)?;
                Some(ServicePart { id, version, bytes })
            })
    }

    /// Forgets every part, keeping the allocation.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.parts.clear();
    }
}

/// A snapshot composed at one applied position
/// ([`ServiceContainer::snapshot`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct ComposedSnapshot<'a> {
    /// The last applied index every section reflects.
    pub index: u64,
    /// The log time at that index.
    pub log_time: u64,
    sessions: Vec<u8>,
    /// The bootstrap flags and the timers.
    timers: Vec<u8>,
    guards: Option<Vec<u8>>,
    service: &'a ServiceSnapshot,
}

impl<'a> ComposedSnapshot<'a> {
    /// Every section, for [`crate::snapshot::SnapshotStore::write`] at
    /// [`Self::index`]: sessions, timers, guards (once the log's guard
    /// bounds applied), then the service's parts in the order written.
    /// The caller adds its own consensus section.
    #[must_use]
    pub fn sections(&self) -> Vec<Section<'_>> {
        let mut sections = Vec::with_capacity(3_usize.saturating_add(self.service.parts.len()));
        sections.push(Section::new(
            SectionKind::Sessions,
            SESSIONS_SECTION_VERSION,
            &self.sessions,
        ));
        sections.push(Section::new(
            SectionKind::Timers,
            TIMERS_VERSION,
            &self.timers,
        ));
        if let Some(guards) = &self.guards {
            sections.push(Section::new(
                SectionKind::Guards,
                crate::guards::SECTION_VERSION,
                guards,
            ));
        }
        for part in self.service.parts() {
            sections.push(Section::new(
                SectionKind::Service,
                part.section_version(),
                part.bytes,
            ));
        }
        sections
    }
}

/// Why a composed snapshot was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ComposeError {
    /// Nothing has applied yet.
    #[error("no entry has applied")]
    NothingApplied,
    /// The service's parts did not fit.
    #[error(transparent)]
    Full(#[from] SnapshotFull),
}

/// Why a snapshot's sections were not restored: the container and its
/// service are unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RestoreError {
    /// A container section is missing.
    #[error("the snapshot has no {0:?} section")]
    Missing(SectionKind),
    /// A section appears twice, or a service part id repeats.
    #[error("the snapshot repeats a {0:?} section")]
    Repeated(SectionKind),
    /// A section's version is not one this build reads.
    #[error("the {kind:?} section's version {version} is not one this build reads")]
    Version {
        /// The section.
        kind: SectionKind,
        /// Its version.
        version: u64,
    },
    /// The sessions section does not decode.
    #[error(transparent)]
    Sessions(#[from] DecodeError),
    /// The sessions section's version state (version 2) does not decode,
    /// or names an activation at or before the snapshot's index.
    #[error("the sessions section's version state is malformed")]
    Versions,
    /// The snapshot's active service version is above what this binary
    /// runs ([`super::ClusteredService::supported_version`]).
    #[error("the snapshot runs version {active}, this binary at most {supported}")]
    VersionUnsupported {
        /// The snapshot's active service version.
        active: u32,
        /// This binary's.
        supported: u32,
    },
    /// The sessions section's bounds are not this container's.
    #[error("the snapshot's session bounds are not this container's")]
    SessionBounds,
    /// The timers section does not decode, or holds more than the bound.
    #[error("the timers section is malformed")]
    Timers,
    /// The guards section does not restore.
    #[error(transparent)]
    Guards(#[from] SectionError),
    /// The service refused its parts.
    #[error(transparent)]
    Service(#[from] RestoreRefused),
}

impl Timers {
    /// The timers as a section's bytes: their count, then each id and
    /// deadline, sorted by id.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 16 * self.scheduled.len());
        out.extend_from_slice(
            &u32::try_from(self.scheduled.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for (id, deadline) in &self.scheduled {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&deadline.to_le_bytes());
        }
        out
    }

    /// Timers decoded from a section, within `bound`; `None` when the
    /// bytes are not what [`Self::encode`] writes, unsorted, or too many.
    fn decode(bytes: &[u8], bound: usize) -> Option<Self> {
        let (count, mut rest) = bytes.split_first_chunk::<4>()?;
        let count = usize::try_from(u32::from_le_bytes(*count)).ok()?;
        if count > bound || rest.len() != count.checked_mul(16)? {
            return None;
        }
        let mut scheduled = Vec::with_capacity(bound);
        for _ in 0..count {
            let (id, after) = rest.split_first_chunk::<8>()?;
            let (deadline, after) = after.split_first_chunk::<8>()?;
            rest = after;
            let id = u64::from_le_bytes(*id);
            if scheduled.last().is_some_and(|&(last, _)| last >= id) {
                return None;
            }
            scheduled.push((id, u64::from_le_bytes(*deadline)));
        }
        Some(Self { scheduled, bound })
    }
}

impl<S: ClusteredService> ServiceContainer<S> {
    /// The state after the last applied entry, composed at that one
    /// position (see the module's contract): the container's sessions,
    /// timers and guards, and the parts the service writes into `parts`,
    /// which is cleared first.
    ///
    /// # Errors
    ///
    /// [`ComposeError`]: no snapshot is taken.
    pub fn snapshot<'a>(
        &self,
        parts: &'a mut ServiceSnapshot,
    ) -> Result<ComposedSnapshot<'a>, ComposeError> {
        let index = self.applied.ok_or(ComposeError::NothingApplied)?;
        parts.clear();
        self.service.snapshot(parts)?;
        Ok(ComposedSnapshot {
            index,
            log_time: self.sessions.log_time(),
            sessions: {
                let mut out = Vec::new();
                self.versions.encode(&mut out);
                out.extend(self.sessions.encode());
                out
            },
            timers: {
                let mut flags = 0;
                if self.bounds_logged {
                    flags |= BOUNDS_LOGGED;
                }
                if self.fresh {
                    flags |= FRESH;
                }
                let mut out = vec![flags];
                out.extend(self.timers.encode());
                out
            },
            guards: self.guards.section(),
            service: parts,
        })
    }

    /// Restores the state a snapshot at `index` holds from its `sections`
    /// (its consensus section, if any, is the caller's and is skipped):
    /// every container section is checked first, then the service's
    /// parts go to [`ClusteredService::restore`], and only once it
    /// accepts them are the container's tables replaced. The next entry
    /// to apply is `index + 1`.
    ///
    /// # Errors
    ///
    /// [`RestoreError`]: the container and its service are unchanged.
    pub fn restore(&mut self, index: u64, sections: &[SectionRead]) -> Result<(), RestoreError> {
        let mut found: [Option<&SectionRead>; 3] = [None; 3];
        let mut parts: Vec<ServicePart<'_>> = Vec::with_capacity(sections.len());
        for section in sections {
            let slot = match section.kind {
                SectionKind::Sessions => 0,
                SectionKind::Timers => 1,
                SectionKind::Guards => 2,
                SectionKind::Service => {
                    let part = ServicePart::of_section(section.version, &section.bytes).ok_or(
                        RestoreError::Version {
                            kind: SectionKind::Service,
                            version: section.version,
                        },
                    )?;
                    if parts.iter().any(|held| held.id == part.id) {
                        return Err(RestoreError::Repeated(SectionKind::Service));
                    }
                    parts.push(part);
                    continue;
                }
                _ => continue,
            };
            let entry = found
                .get_mut(slot)
                .ok_or(RestoreError::Repeated(section.kind))?;
            if entry.replace(section).is_some() {
                return Err(RestoreError::Repeated(section.kind));
            }
        }
        let [sessions, timers, guards] = found;
        let sessions = sessions.ok_or(RestoreError::Missing(SectionKind::Sessions))?;
        let (versions, table_bytes) = match sessions.version {
            SESSIONS_SECTION_VERSION_1 => (
                super::upgrade::Versions::default(),
                sessions.bytes.as_slice(),
            ),
            SESSIONS_SECTION_VERSION => super::upgrade::Versions::decode(&sessions.bytes, index)
                .ok_or(RestoreError::Versions)?,
            version => {
                return Err(RestoreError::Version {
                    kind: SectionKind::Sessions,
                    version,
                });
            }
        };
        // A replica runs the semantics of the version the snapshot names
        // (ADR-0122 decision 5): a binary that cannot is refused here.
        let supported = self.service.supported_version();
        if versions.active.service > supported {
            return Err(RestoreError::VersionUnsupported {
                active: versions.active.service,
                supported,
            });
        }
        let timers = timers.ok_or(RestoreError::Missing(SectionKind::Timers))?;
        if timers.version != TIMERS_VERSION {
            return Err(RestoreError::Version {
                kind: SectionKind::Timers,
                version: timers.version,
            });
        }
        let (&flags, rest) = timers.bytes.split_first().ok_or(RestoreError::Timers)?;
        if flags & !(BOUNDS_LOGGED | FRESH) != 0 {
            return Err(RestoreError::Timers);
        }
        let (bounds_logged, fresh) = (flags & BOUNDS_LOGGED != 0, flags & FRESH != 0);
        let timers = Timers::decode(rest, self.timers.bound).ok_or(RestoreError::Timers)?;
        // Within this container's session budget, checked before the
        // table is allocated; logged bounds restore as the log's entry
        // would, unlogged ones must be this container's.
        let table = SessionTable::decode_within(table_bytes, self.session_budget)?;
        if table.config() != self.sessions.config() && !bounds_logged {
            return Err(RestoreError::SessionBounds);
        }
        // Every table from the snapshot's position: no guards section is
        // a fresh guard table, the log's guard bounds not applied yet.
        let guards = match guards {
            Some(section) => GuardTable::restore(
                section.version,
                &section.bytes,
                self.guards.bounds(),
                index,
                table.log_time(),
            )?,
            None => GuardTable::new(self.guards.bounds()),
        };
        // Every container section holds: the service's parts last, so a
        // refusal leaves everything as it was.
        self.service.restore(&parts)?;
        self.sessions = table;
        self.timers = timers;
        self.guards = guards;
        self.applied = Some(index);
        self.fresh = fresh;
        self.bounds_logged = bounds_logged;
        self.versions = versions;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
